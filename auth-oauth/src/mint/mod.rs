// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The self-minting styles' shared machinery: `jwt-bearer` (RFC 7523) and `oauth-client-credentials`
//! (RFC 6749 §4.4) each obtain a short-lived bearer from a token endpoint and present it as
//! `authorization: Bearer <token>`. They differ ONLY in the token request ([`jwt_bearer`],
//! [`oauth_client_credentials`]). This module owns everything else: the cached token, the
//! per-request read, and the refresh ahead of expiry.
//!
//! The cached token, the header built once at mint, the empty-token-is-a-failure rule and the
//! refresh schedule ([`next_refresh_secs`]) live here. The driver is a state machine advanced on
//! `tick` ([`Minted::tick`]) over the plugin's own need ([`Wire`], the host's connection table).
//! Nothing here blocks: an exchange whose reply is not ready yet is read again by the next `drive`
//! its wake brings, or the next `tick`.
//!
//! The expired-token rule: when the cached token has expired AND its
//! refresh has failed, the per-request call answers not-ready ([`Read::Wait`]) and the ticket is
//! woken when a mint lands; the host bounds the wait by the attempt's deadline.

pub(crate) mod host_wire;
pub(crate) mod jwt_bearer;
pub(crate) mod oauth_client_credentials;
pub(crate) mod token_exchange;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use busbar_contract::abi::sdk::cred::{FormBody, SealedWrite};
use busbar_contract::conn::{ConnError, ConnId, PieceKind};
use zeroize::{Zeroize, Zeroizing};

use crate::token_response::{default_expires_in, deserialize_expires_in, wiped_member};
use busbar_contract::abi::sdk::auth_kit::json_error;
use busbar_contract::header::{is_legal_header_value, token_value};

/// Refresh this many seconds BEFORE the token's stated expiry, so a request never races an expired
/// token across the refresh boundary.
const REFRESH_SKEW_SECS: u64 = 300;
/// Floor on the refresh sleep so a short-lived / already-near-expiry token can't spin the loop hot,
/// and the retry delay after a mint failure.
pub(crate) const MIN_SLEEP_SECS: u64 = 30;
/// The whole-mint deadline — send plus capped body read under ONE absolute instant, the
/// client-level 30s total.
pub(crate) const MINT_DEADLINE_SECS: u64 = 30;
/// The cap on a token response body when the binding's settings state none (`max_response_bytes`):
/// 256 KiB.
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// One read of a token response, in bytes.
const READ_BUF_BYTES: usize = 16 * 1024;
/// How long `tick` waits before reading an in-flight exchange again.
pub(crate) const IN_FLIGHT_POLL_NS: u64 = 5_000_000;

/// Nanoseconds in a second, on the tick clock.
pub(crate) const NS: u64 = 1_000_000_000;

/// The plugin's own needs, by their index in the Statement (`crate::NEEDS`): the token endpoint
/// each style POSTs to, its target the binding's own setting (egress class `provider`: a private
/// endpoint refused unless allowlisted).
pub(crate) mod need {
    /// `oauth-client-credentials`: `settings.token_url`.
    pub const TOKEN_URL: u32 = 0;
    /// `jwt-bearer`: `settings.token_uri`.
    pub const TOKEN_URI: u32 = 1;
}

/// One token request: POST `body` (a form) to `target`, over the need `need`.
pub(crate) struct TokenRequest {
    /// The need it goes out on ([`need`]).
    pub need: u32,
    /// The token endpoint.
    pub target: String,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, &'static str)>,
    /// The form body: its credential values are the chip's, encoded only as it is written.
    pub body: FormBody,
}

impl TokenRequest {
    /// A form POST of `body` to `target`, over the need `need`. Its fields are, in order,
    /// the form's `content-type`, then the client-default `accept: */*`, which the request carries
    /// itself (the http door writes no field the caller did not).
    pub(crate) fn form(need: u32, target: String, body: FormBody) -> Self {
        Self {
            need,
            target,
            fields: vec![
                ("content-type", "application/x-www-form-urlencoded"),
                ("accept", "*/*"),
            ],
            body,
        }
    }
}

/// A style that mints: how it builds its token request.
pub(crate) enum Minter {
    /// RFC 7523.
    JwtBearer(Box<jwt_bearer::Signer>),
    /// RFC 6749 §4.4.
    ClientCredentials(oauth_client_credentials::ClientCreds),
    /// RFC 8693, for one scope: minted ON DEMAND (a request that finds no usable token starts the
    /// exchange), never refreshed ahead of a request.
    TokenExchange(token_exchange::Scoped),
}

impl std::fmt::Debug for Read<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(_) => f.write_str("Header([REDACTED])"),
            Self::Nothing => f.write_str("Nothing"),
            Self::Refuse(why) => f.debug_tuple("Refuse").field(why).finish(),
            Self::Wait => f.write_str("Wait"),
        }
    }
}

impl Minter {
    pub(crate) fn request(&self, now: u64) -> Result<TokenRequest, String> {
        match self {
            Minter::JwtBearer(s) => s.request(now),
            Minter::ClientCredentials(c) => c.request(),
            Minter::TokenExchange(x) => x.request(),
        }
    }
}

/// A minted access token and the wall-clock epoch second it expires at.
pub(crate) struct CachedToken {
    /// The minted bearer, wiped on drop (no `Debug` of it: [`CachedToken`]'s own prints none).
    pub(crate) token: Zeroizing<String>,
    pub(crate) expires_at: u64,
    /// The `Bearer <token>` value, pre-built ONCE here (at mint time) rather than on every request.
    /// `None` when `token` is empty (the pre-first-mint sentinel) or contains bytes invalid for an
    /// header value — both cases mean "emit no auth header".
    header: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl CachedToken {
    /// Construct a `CachedToken`, building its header once here. The second value is whether the
    /// token was omitted for bytes invalid in a header value (the caller reports it). The token
    /// arrives already wiped on drop (a response's token is read into a wiped buffer and moved
    /// here, [`access_token`]).
    pub(crate) fn new(token: Zeroizing<String>, expires_at: u64) -> (Self, bool) {
        let (header, invalid) = if token.is_empty() {
            (None, false)
        } else {
            let mut v = token_value(&token);
            if is_legal_header_value(&v) {
                (Some(Zeroizing::new(v)), false)
            } else {
                v.zeroize();
                (None, true)
            }
        };
        (
            Self {
                token,
                expires_at,
                header,
            },
            invalid,
        )
    }

    /// The header value, when there is one to present.
    pub(crate) fn header(&self) -> Option<&str> {
        self.header.as_ref().map(|h| h.as_str())
    }
}

/// Seconds to sleep before the next re-mint, given a token that expires at `expires_at` (epoch secs).
///
/// Refresh `REFRESH_SKEW_SECS` BEFORE expiry for a normally-lived token so a request never races the
/// expiry boundary. But that skew cannot be honored for a SHORT-TTL token: the old
/// `(ttl - SKEW).max(MIN_SLEEP)` floored the sleep back up to `MIN_SLEEP_SECS` (30s) even for a token
/// that expired in, say, 10s — so `headers_for` served an EXPIRED bearer for ~20s and the upstream 401'd.
/// Instead:
///   - `ttl == 0` (already expired / garbage `expires_in ≈ 0`): back off `MIN_SLEEP_SECS` so the mint
///     loop cannot spin hot — nothing useful to serve, fail safe.
///   - `ttl <= REFRESH_SKEW_SECS` (too short to refresh a full skew early): re-mint at ~half the
///     remaining life, so the refresh always lands BEFORE expiry (never past `ttl`), and never below 1s.
///   - otherwise: the normal `ttl - REFRESH_SKEW_SECS`, with `MIN_SLEEP_SECS` as a hot-loop floor near
///     the skew boundary.
///
/// Guarantees: for any `ttl > 0` the next mint is scheduled strictly before expiry (no expired token is
/// served); for `ttl == 0` the loop is rate-limited to `MIN_SLEEP_SECS`.
pub(crate) fn next_refresh_secs(expires_at: u64, now: u64) -> u64 {
    let ttl = expires_at.saturating_sub(now);
    if ttl == 0 {
        MIN_SLEEP_SECS
    } else if ttl <= REFRESH_SKEW_SECS {
        (ttl / 2).max(1)
    } else {
        (ttl - REFRESH_SKEW_SECS).max(MIN_SLEEP_SECS)
    }
}

/// An OAuth token endpoint's success body (RFC 6749 section 5.1), as far as a minter reads it.
/// Deserialize-only. The decoder never decodes the access token: it unescapes a string that
/// carries an escape into a scratch buffer of its own that it frees unwiped, so the decode skips
/// the token's value (skipping copies nothing) and [`access_token`] reads it (auth
/// material is zeroised).
#[derive(serde::Deserialize)]
struct TokenResponse {
    /// Required, and skipped by the decoder; [`access_token`] reads it.
    #[serde(rename = "access_token")]
    _access_token: serde::de::IgnoredAny,
    #[serde(
        default = "default_expires_in",
        deserialize_with = "deserialize_expires_in"
    )]
    expires_in: u64,
}

/// THE ACCESS TOKEN of a token response `json` the decoder has already judged well-formed (with an
/// `access_token` member), its escapes resolved into ONE buffer sized to the escaped length and
/// wiped on drop.
///
/// # Errors
/// The response's `access_token` is not a string (the decode has already refused a missing one).
pub(crate) fn access_token(json: &str) -> Result<Zeroizing<String>, String> {
    wiped_member(json, b"access_token").ok_or_else(|| {
        "token response JSON invalid: a field is missing or has the wrong type (the decoder's \
         text is withheld)"
            .to_string()
    })
}

/// `body` as text, bytes that are not UTF-8 replaced as `String::from_utf8_lossy` does, built into
/// ONE wiped string sized exactly first, so it never reallocates and frees an unwiped copy.
fn lossy_wiped(b: &[u8]) -> Zeroizing<String> {
    let len: usize = b
        .utf8_chunks()
        .map(|c| c.valid().len() + if c.invalid().is_empty() { 0 } else { 3 })
        .sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for c in b.utf8_chunks() {
        out.push_str(c.valid());
        if !c.invalid().is_empty() {
            out.push('\u{FFFD}');
        }
    }
    out
}

/// The RFC 6749 section 5.2 `error` code of a JSON error body: a string member of at most 64 chars
/// from `%x20-21 / %x23-5B / %x5D-7E`; `None` for anything else (never other body text).
fn oauth_error_code(body: &str) -> Option<Zeroizing<String>> {
    // Well-formed only (`IgnoredAny` copies nothing); `wiped_member` answers none unless the
    // top level is an object holding a string `error`.
    serde_json::from_str::<serde::de::IgnoredAny>(body).ok()?;
    let code = crate::token_response::wiped_member(body, b"error")?;
    let ok = code.len() <= 64
        && code
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E));
    ok.then_some(code)
}

/// Parse a finished token response: a non-2xx status is the endpoint's refusal, named with its
/// status and error code only; otherwise the JSON token. Verbatim from the two mint bodies.
pub(crate) fn parse_response(
    status: u16,
    body: &[u8],
    now: u64,
) -> Result<(CachedToken, bool), String> {
    // The body carries the access token: a lossy copy (bytes that are not UTF-8) is wiped too.
    let body = lossy_wiped(body);
    if !(200..300).contains(&status) {
        // Never put body text in the error: a server may reflect the request (client secret,
        // assertion) and the error reaches the diag channel. Status plus the RFC 6749 section 5.2
        // `error` code, only when the body proves it is one.
        let status = http::StatusCode::from_u16(status)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| status.to_string());
        return Err(match oauth_error_code(&body) {
            Some(code) => format!("token endpoint returned {status}: {}", code.as_str()),
            None => format!("token endpoint returned {status}"),
        });
    }
    // A decode failure is described without the decoder's text, which can quote the token.
    let tok: TokenResponse =
        serde_json::from_str(&body).map_err(json_error("token response JSON invalid"))?;
    // The token's buffer moves into the held secret whole (no copy): the emptied wrapper drops.
    let mut read = access_token(&body)?;
    let token = Zeroizing::new(std::mem::take(&mut *read));
    Ok(CachedToken::new(
        token,
        // saturating_add: `expires_in` is attacker-influenced (comes off the token endpoint), so a
        // huge value must clamp to u64::MAX rather than wrap/panic.
        now.saturating_add(tok.expires_in),
    ))
}

/// One piece a need's connection delivered, as the exchange reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Got {
    /// What the piece carries.
    pub kind: PieceKind,
    /// How many bytes of the buffer it filled.
    pub len: usize,
    /// It ends its frame.
    pub end: bool,
    /// The status number, where the wire reports one.
    pub status: Option<u32>,
}

/// The plugin's own need, as the exchange uses it: the host's connection table
/// (`busbar_contract::abi::host::conn::HostConns`), or a test's double.
pub(crate) trait Wire: Send + Sync {
    /// Open a connection for the need, sending the request's head and `body` (its form, encoded
    /// by the chip).
    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
    ) -> Result<ConnId, ConnError>;
    /// Read one piece into `buf`; [`ConnError::Pending`] when nothing is ready.
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError>;
    /// Close the connection.
    fn close(&self, conn: ConnId);
    /// The host's clock (`clock.now`; one clock, which also drives every plugin's `tick`), one
    /// reading; `None` when the host could not answer it.
    fn clock(&self) -> Option<HostClock> {
        None
    }
}

/// One reading of the host's clock: the wall clock a token's `expires_in` and a JWT's `iat` are
/// read against, and the monotonic clock a `drive` measures the time since its `tick` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostClock {
    /// Wall time, whole seconds since the epoch (1970-01-01 UTC).
    pub wall_secs: u64,
    /// Monotonic time, nanoseconds since an origin fixed for the process's life.
    pub mono_ns: u64,
}

/// Where one binding's exchange stands.
enum Exchange {
    /// No exchange; the next is due at `due_ns` on the tick clock.
    Idle { due_ns: u64 },
    /// An exchange is in flight on `conn`.
    InFlight {
        conn: ConnId,
        started_ns: u64,
        status: Option<u32>,
        /// The response so far: it carries the access token, so it grows only through
        /// [`append_wiped`] (no growth leaves an unwiped copy) and is wiped on drop.
        body: Zeroizing<Vec<u8>>,
    },
}

/// What a finished tick of one cell reports for the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// A mint failed; it will retry (`EGRESS_OAUTH_MINT_FAILED`).
    MintFailed(String),
    /// The endpoint answered 200 with an empty token (`EGRESS_OAUTH_EMPTY_TOKEN`).
    EmptyToken,
    /// The minted token holds bytes invalid in a header value (`EGRESS_OAUTH_TOKEN_INVALID_BYTES`).
    TokenInvalidBytes,
    /// A token landed.
    Minted,
}

/// Why a call is refused when its binding has no token to present: never sent unauthenticated.
pub(crate) const NO_TOKEN: &str = "no OAuth token could be minted for this binding (see \
     diagnostics BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and \
     the mint retries on its schedule";

/// Why a call is refused when its token cannot be a header value.
pub(crate) const UNPRESENTABLE: &str = "the minted OAuth token holds bytes invalid in a header \
     value (see diagnostic BUSBAR-4014); the call is refused rather than sent unauthenticated";

/// The answer the per-request call reads. No `Debug`: it carries the bearer.
#[derive(PartialEq, Eq)]
pub(crate) enum Read<'a> {
    /// Present this header value (`Bearer <token>`).
    Header(&'a str),
    /// No header: the boot window before the first mint is attempted (READY with no fields, the
    /// contract's rule at this pin: `busbar-test-kit` outbound script, "fields before the first
    /// mint").
    Nothing,
    /// Nothing can be presented after a mint: the call is FAILED, saying why (never sent
    /// unauthenticated).
    Refuse(&'static str),
    /// Not ready: the token has expired and its refresh failed (Q-EXPIRED), or an on-demand
    /// exchange is due.
    Wait,
}

/// ONE BINDING'S TOKEN: keyed by (style, credential, settings) in the instance's cache, so it
/// survives `refresh` and re-opening (abi/auth: the outbound token cache outlives a handle).
pub(crate) struct Minted {
    minter: Minter,
    max_response_bytes: usize,
    token: RwLock<Arc<CachedToken>>,
    exchange: Mutex<Exchange>,
    refresh_failed: AtomicBool,
    /// Minted on demand ([`Minter::TokenExchange`]): no refresh ahead of a request, no retry on a
    /// schedule; a request that finds no usable token arms the next exchange.
    on_demand: bool,
    /// An on-demand cell's token is presented until this wall-clock epoch second: the instant a
    /// scheduled style would refresh it ([`next_refresh_secs`] from its mint).
    usable_until: AtomicU64,
    /// The last failed mint was an outage of the token endpoint ([`Minted::outage`]).
    outage: AtomicBool,
}

impl Minted {
    /// A cell that has minted nothing yet; its first exchange is due at once, on the next `tick` or
    /// `drive` that advances it.
    pub(crate) fn new(minter: Minter, max_response_bytes: usize) -> Self {
        Self {
            on_demand: matches!(minter, Minter::TokenExchange(_)),
            minter,
            max_response_bytes,
            token: RwLock::new(Arc::new(
                CachedToken::new(Zeroizing::new(String::new()), 0).0,
            )),
            exchange: Mutex::new(Exchange::Idle { due_ns: 0 }),
            refresh_failed: AtomicBool::new(false),
            usable_until: AtomicU64::new(0),
            outage: AtomicBool::new(false),
        }
    }

    /// Minted on demand (the token-exchange style's per-scope cell).
    pub(crate) fn on_demand(&self) -> bool {
        self.on_demand
    }

    /// The binding's exchange material, for a token-exchange cell; `None` for a scheduled one.
    pub(crate) fn exchange(&self) -> Option<&token_exchange::Exchange> {
        match &self.minter {
            Minter::TokenExchange(scoped) => Some(scoped.exchange()),
            _ => None,
        }
    }

    /// No exchange is in flight.
    pub(crate) fn idle(&self) -> bool {
        matches!(
            *self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Exchange::Idle { .. }
        )
    }

    /// An on-demand cell holds a token it presents at wall-clock `now`.
    pub(crate) fn usable(&self, now: u64) -> bool {
        self.is_ready() && now < self.usable_until.load(Ordering::Acquire)
    }

    fn current(&self) -> Arc<CachedToken> {
        self.token
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether the first mint has populated a non-empty token.
    pub(crate) fn is_ready(&self) -> bool {
        !self.current().token.is_empty()
    }

    /// THE `ready` FACT at wall-clock `now` (epoch seconds), by the rule [`Minted::read`] applies:
    /// a call would present a credential now. Not before the first mint, not for a token that
    /// yields no header (bytes invalid in a header value), and not once the token has expired and
    /// its refresh failed (contract `abi/auth/outbound.rs`: "`0` = not yet (before the first mint,
    /// or expired with a failed refresh)").
    pub(crate) fn presents(&self, now: u64) -> bool {
        if self.on_demand {
            return self.usable(now);
        }
        self.read(now, |r| matches!(r, Read::Header(_)))
    }

    /// Present the cached token for a request at wall-clock `now` (epoch seconds), through `f`
    /// (so the borrow of the cached value never escapes the read).
    pub(crate) fn read<T>(&self, now: u64, f: impl FnOnce(Read<'_>) -> T) -> T {
        // ON DEMAND: a token past its use is not presented; the request arms the next exchange
        // (due at once, when none is in flight) and waits for it.
        if self.on_demand && !self.usable(now) {
            if let Exchange::Idle { due_ns } = &mut *self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                *due_ns = 0;
            }
            return f(Read::Wait);
        }
        // The snapshot comes AFTER the usable check: `tick` stores the token before it stores
        // `usable_until`, so a read that finds the cell usable snapshots the stored token, never
        // an older (empty or expired) one an exchange landing in between has replaced.
        let tok = self.current();
        // Before the first mint is attempted a scheduled cell presents nothing (the contract's
        // boot window); once a mint has failed with no token held, the call is refused, saying
        // why, never sent unauthenticated.
        if tok.token.is_empty() {
            return if self.refresh_failed.load(Ordering::Acquire) {
                f(Read::Refuse(NO_TOKEN))
            } else {
                f(Read::Nothing)
            };
        }
        if now >= tok.expires_at && self.refresh_failed.load(Ordering::Acquire) {
            return f(Read::Wait);
        }
        match tok.header() {
            Some(h) => f(Read::Header(h)),
            None => f(Read::Refuse(UNPRESENTABLE)),
        }
    }

    /// Advance the exchange at tick-clock `now_ns` and the host's wall clock `wall` (epoch seconds):
    /// start one when due, read what arrived, finish it. Answers when the cell next wants a tick,
    /// and what happened.
    pub(crate) fn tick(
        &self,
        now_ns: u64,
        wall: u64,
        wire: Option<&dyn Wire>,
    ) -> (u64, Option<Report>) {
        let mut ex = self
            .exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Exchange::Idle { due_ns } = *ex {
            if now_ns < due_ns {
                return (due_ns, None);
            }
            let Some(wire) = wire else {
                // No need was granted: nothing can mint. Say so once per retry period.
                *ex = Exchange::Idle {
                    due_ns: now_ns.saturating_add(MIN_SLEEP_SECS * NS),
                };
                return self.failed(
                    &mut ex,
                    now_ns,
                    "token endpoint request failed: no connection was granted for the token endpoint"
                        .to_string(),
                    false,
                );
            };
            let req = match self.minter.request(wall) {
                Ok(r) => r,
                Err(e) => return self.failed(&mut ex, now_ns, e, false),
            };
            // The chip encodes the form (and signs a JWT-bearer assertion) as it is written.
            let mut body = match req.body.encoded() {
                Ok(b) => b,
                Err(r) => {
                    return self.failed(
                        &mut ex,
                        now_ns,
                        format!("the token request could not be built: {r}"),
                        false,
                    )
                }
            };
            match wire.open(&req, &mut body, MINT_DEADLINE_SECS * 1000) {
                Ok(conn) => {
                    *ex = Exchange::InFlight {
                        conn,
                        started_ns: now_ns,
                        status: None,
                        // Nothing reserved up front: the body grows to what arrives, bounded by
                        // the cap ([`append_wiped`]).
                        body: Zeroizing::new(Vec::new()),
                    }
                }
                Err(e) => {
                    return self.failed(
                        &mut ex,
                        now_ns,
                        format!("token endpoint request failed: {}", conn_cause(e)),
                        unreachable(e),
                    )
                }
            }
        }
        let Some(wire) = wire else {
            return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None);
        };
        let Exchange::InFlight {
            conn,
            started_ns,
            status,
            body,
        } = &mut *ex
        else {
            return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None);
        };
        let conn = *conn;
        let mut buf = Zeroizing::new([0_u8; READ_BUF_BYTES]);
        let finished = loop {
            if now_ns.saturating_sub(*started_ns) >= MINT_DEADLINE_SECS * NS {
                break Err((
                    "token endpoint response was not read before the mint deadline; refusing to \
                     parse a partial token response"
                        .to_string(),
                    true,
                ));
            }
            match wire.read(conn, &mut buf[..]) {
                Ok(got) => {
                    if got.status.is_some() {
                        *status = got.status;
                    }
                    if got.kind == PieceKind::Body {
                        if let Err(e) = append_wiped(body, &buf[..got.len], self.max_response_bytes)
                        {
                            break Err((e, false));
                        }
                        if body.len() > self.max_response_bytes {
                            break Err((
                                format!(
                                    "token endpoint response exceeded the {}-byte cap; refusing \
                                     to parse a truncated token response",
                                    self.max_response_bytes
                                ),
                                false,
                            ));
                        }
                    }
                    if got.kind == PieceKind::Completion || (got.kind == PieceKind::Body && got.end)
                    {
                        break Ok((status.unwrap_or(0), std::mem::take(body)));
                    }
                }
                Err(ConnError::Pending) => return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None),
                Err(ConnError::Closed) if status.is_some() && !body.is_empty() => {
                    break Ok((status.unwrap_or(0), std::mem::take(body)))
                }
                Err(ConnError::Closed) => {
                    break Err((
                        "token endpoint connection failed mid-response; refusing to parse \
                               a partial token response"
                            .to_string(),
                        true,
                    ))
                }
                Err(e) => {
                    break Err((
                        format!("token endpoint request failed: {}", conn_cause(e)),
                        unreachable(e),
                    ))
                }
            }
        };
        wire.close(conn);
        match finished.and_then(|(status, body)| {
            parse_response(u16::try_from(status).unwrap_or(0), &body, wall)
                .map_err(|e| (e, outage_status(status)))
        }) {
            // A 200 with an EMPTY access_token must be treated as a (retryable) failure, not stored:
            // an empty token collides with the pre-first-mint sentinel, so `ready` would stay false
            // forever AND the per-request call would emit no auth header — a permanent wedge with no
            // self-healing. Retry at MIN_SLEEP instead, exactly like a mint error.
            Ok((fresh, _)) if fresh.token.is_empty() => {
                self.refresh_failed.store(true, Ordering::Release);
                let due = if self.on_demand {
                    u64::MAX
                } else {
                    now_ns.saturating_add(MIN_SLEEP_SECS * NS)
                };
                *ex = Exchange::Idle { due_ns: due };
                (due, Some(Report::EmptyToken))
            }
            // A token that cannot be presented (bytes invalid in a header value) is a failed mint,
            // as an empty one is: it is not stored (a token held before keeps serving), and the
            // calls with nothing to present fail rather than go out unauthenticated.
            Ok((_, true)) => {
                self.refresh_failed.store(true, Ordering::Release);
                let due = if self.on_demand {
                    u64::MAX
                } else {
                    now_ns.saturating_add(MIN_SLEEP_SECS * NS)
                };
                *ex = Exchange::Idle { due_ns: due };
                (due, Some(Report::TokenInvalidBytes))
            }
            Ok((fresh, _)) => {
                let now = wall;
                let ahead = next_refresh_secs(fresh.expires_at, now);
                // An on-demand token is presented until a scheduled style would refresh it, and no
                // exchange is due until a request finds it past that.
                let due = if self.on_demand {
                    u64::MAX
                } else {
                    now_ns.saturating_add(ahead.saturating_mul(NS))
                };
                *self
                    .token
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(fresh);
                if self.on_demand {
                    self.usable_until
                        .store(now.saturating_add(ahead), Ordering::Release);
                }
                self.refresh_failed.store(false, Ordering::Release);
                *ex = Exchange::Idle { due_ns: due };
                (due, Some(Report::Minted))
            }
            Err((e, outage)) => self.failed(&mut ex, now_ns, e, outage),
        }
    }

    /// Whether this cell's last failed mint was an OUTAGE of its token endpoint (a 5xx or 429, a
    /// timeout, a connection lost), not a refusal of its credential or its configuration.
    pub(crate) fn outage(&self) -> bool {
        self.outage.load(Ordering::Acquire)
    }

    /// A failed mint: keep serving whatever token is current, and retry at `MIN_SLEEP_SECS` (an
    /// on-demand cell retries when a request next arms it).
    fn failed(
        &self,
        ex: &mut Exchange,
        now_ns: u64,
        e: String,
        outage: bool,
    ) -> (u64, Option<Report>) {
        self.refresh_failed.store(true, Ordering::Release);
        self.outage.store(outage, Ordering::Release);
        let due = if self.on_demand {
            u64::MAX
        } else {
            now_ns.saturating_add(MIN_SLEEP_SECS * NS)
        };
        *ex = Exchange::Idle { due_ns: due };
        (due, Some(Report::MintFailed(e)))
    }
}

/// APPEND `bytes` to the token response `body`, growing it to what has arrived (never reserving
/// the cap up front: a large cap costs nothing per mint) and at most one read past `cap` (the read
/// that trips it). A growth moves the bytes into a new buffer with a fallible reservation and wipes
/// the old one as it drops, so no unwiped copy of the access token is left behind.
fn append_wiped(body: &mut Zeroizing<Vec<u8>>, bytes: &[u8], cap: usize) -> Result<(), String> {
    let need = body.len().saturating_add(bytes.len());
    if need > body.capacity() {
        let want = need
            .max(body.capacity().saturating_mul(2))
            .max(READ_BUF_BYTES)
            .min(cap.saturating_add(READ_BUF_BYTES))
            .max(need);
        let mut grown = Vec::new();
        grown.try_reserve_exact(want).map_err(|_| {
            "token endpoint response could not be buffered; refusing to parse a partial token \
             response"
                .to_string()
        })?;
        grown.extend_from_slice(body);
        // The old buffer is wiped as it drops.
        *body = Zeroizing::new(grown);
    }
    body.extend_from_slice(bytes);
    Ok(())
}

/// Whether a token endpoint's reply `status` is an OUTAGE (S4): a 5xx or a 429, the endpoint down
/// or shedding load, never a refusal of the credential.
pub(crate) const fn outage_status(status: u32) -> bool {
    status == 429 || (status >= 500 && status <= 599)
}

/// Whether a connection error is the token endpoint being unreachable (an outage): a timeout, a
/// lost connection or a fault, never a refusal the host made by its own rules.
const fn unreachable(e: ConnError) -> bool {
    matches!(
        e,
        ConnError::Timeout | ConnError::Closed | ConnError::Fault | ConnError::Pending
    )
}

/// The cause a connection refusal names — never the URL (it can carry query/secret material).
fn conn_cause(e: ConnError) -> &'static str {
    match e {
        ConnError::Pending => "not ready",
        ConnError::Timeout => "timed out",
        ConnError::Closed => "connection closed",
        ConnError::NotOwner => "connection not owned",
        ConnError::UndeclaredNeed => "no need declared for the token endpoint",
        ConnError::Refused => "refused",
        ConnError::Fault => "fault",
        ConnError::Unarmed => "not armed",
        ConnError::CredentialUnavailable => "the request's credential is unavailable",
        // A cause this plugin predates is a failed connection. Busbar dev's `ConnError` names every
        // variant above (the arm is unreachable there); a contract that grows one lands here.
        #[allow(unreachable_patterns)]
        _ => "connection failed",
    }
}

#[cfg(test)]
#[path = "../tests/mint_tests.rs"]
pub(crate) mod tests;
