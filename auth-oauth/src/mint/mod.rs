// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The self-minting styles' shared machinery: `jwt-bearer` (RFC 7523) and `oauth-client-credentials`
//! (RFC 6749 §4.4) each obtain a short-lived bearer from a token endpoint on a schedule and present
//! it as `authorization: Bearer <token>`; `oauth-token-exchange` (RFC 8693) obtains one per scope,
//! on demand. They differ ONLY in the token request ([`jwt_bearer`], [`oauth_client_credentials`],
//! [`token_exchange`]). This module owns everything else: the cached token, the per-request read,
//! and the refresh ahead of expiry.
//!
//! The cached token, the empty-token-is-a-failure rule and the refresh schedule
//! ([`next_refresh_secs`], floored by [`MIN_MINT_INTERVAL_SECS`] for the scheduled styles) live
//! here. The driver is a state machine advanced on `tick` ([`Minted::tick`]) over the plugin's own
//! need ([`Wire`], the host's connection table). Nothing here blocks: an exchange whose reply is
//! not ready yet is read again by the next `drive` its wake brings, or the next `tick`.
//!
//! The expired-token rule (RFC 6750 §3.1, RFC 6749 §5.1): a token is never presented at or past
//! its expiry. When a scheduled style's cached token has expired before its refresh landed (the
//! host was suspended, say, so the tick clock did not move while the wall clock did), the call
//! answers not-ready ([`Read::Wait`]) and the refresh is brought forward, no sooner than
//! [`MIN_MINT_INTERVAL_SECS`] after the last mint; the call's ticket is woken when it settles.
//! When the refresh has failed and the cell is backing off (its retry stays [`MIN_SLEEP_SECS`]
//! on), the call fails closed ([`EXPIRED`]).

pub(crate) mod host_wire;
pub(crate) mod jwt_bearer;
pub(crate) mod oauth_client_credentials;
pub(crate) mod token_exchange;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use busbar_contract::abi::sdk::cred::{Cred, FormBody, SealedWrite};
use busbar_contract::conn::{ConnError, ConnId, PieceKind};
use zeroize::Zeroizing;

use crate::token_response::{default_expires_in, deserialize_expires_in, wiped_member};
use busbar_contract::abi::sdk::auth_kit::json_error;

/// Refresh this many seconds BEFORE the token's stated expiry, so a request never races an expired
/// token across the refresh boundary.
const REFRESH_SKEW_SECS: u64 = 300;
/// Floor on the refresh sleep so a short-lived / already-near-expiry token can't spin the loop hot,
/// and the retry delay after a mint failure.
pub(crate) const MIN_SLEEP_SECS: u64 = 30;
/// The longest a token is held before its refresh, whatever its `expires_in` (an endpoint's
/// untrusted number): a day, so a revoked token is not presented for the process's life.
pub(crate) const MAX_REFRESH_SECS: u64 = 24 * 60 * 60;
/// The whole-mint deadline — send plus capped body read under ONE absolute instant, the
/// client-level 30 s total of 1.5.5.
pub(crate) const MINT_DEADLINE_SECS: u64 = 30;
/// The cap on a token response body when the binding's settings state none (`max_response_bytes`):
/// 256 KiB.
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// One read of a token response, in bytes.
const READ_BUF_BYTES: usize = 16 * 1024;
/// How long a token-exchange scope whose exchange failed is not retried (its negative-cache
/// window) when the authorization server states no `Retry-After`: the other styles' retry interval.
pub(crate) const EXCHANGE_BACKOFF_SECS: u64 = MIN_SLEEP_SECS;
/// The longest window a `Retry-After` may set.
pub(crate) const MAX_BACKOFF_SECS: u64 = 300;
/// With no host clock to measure the read loop on, the most pieces one `tick` or `drive` reads
/// before it yields (the next judges the mint deadline anew).
const MAX_READS_PER_TICK: u32 = 1024;
/// How long `tick` waits before reading an in-flight exchange again.
pub(crate) const IN_FLIGHT_POLL_NS: u64 = 5_000_000;
/// The least time between a landed token and the next mint of its cell: an endpoint issuing tokens
/// that live a second or two is re-minted at most this often, not once a second as 1.5.5's
/// half-life schedule alone would (nor once per request, for a token exchange). A token that
/// expires sooner is not presented in between: the calls meanwhile wait for the next mint.
pub(crate) const MIN_MINT_INTERVAL_SECS: u64 = 5;
/// [`Minted`]'s landing instant before any token has landed.
const NEVER_LANDED: u64 = u64::MAX;

/// The fleet's sanity floor for the host's wall clock (2026-01-01T00:00:00Z, epoch seconds): no
/// token is minted at a wall clock before it (unknown, or decades off), since an assertion's `iat`
/// and a token's expiry are read against it.
pub(crate) const WALL_FLOOR_SECS: u64 = 1_767_225_600;
/// [`WALL_FLOOR_SECS`] as the refusal names it.
const WALL_FLOOR_DATE: &str = "2026-01-01";

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
            Self::Refuse(why) => f.debug_tuple("Refuse").field(why).finish(),
            Self::Wait => f.write_str("Wait"),
        }
    }
}

impl Minter {
    pub(crate) fn request(&self, now: u64) -> Result<TokenRequest, String> {
        match self {
            Minter::JwtBearer(s) => s.request(now),
            Minter::ClientCredentials(c) => Ok(c.request()),
            Minter::TokenExchange(x) => Ok(x.request()),
        }
    }
}

/// A minted access token and the wall-clock epoch second it expires at.
pub(crate) struct CachedToken {
    /// The minted bearer, wiped on drop (no `Debug` of it: [`CachedToken`]'s own prints none).
    pub(crate) token: Cred,
    pub(crate) expires_at: u64,
    /// Whether this token may be presented; the SDK builds its sealed Bearer field at delivery.
    presentable: bool,
    /// The reply's `token_type`, as it stated it (`None`: it stated none).
    pub(crate) token_type: Option<String>,
    /// An RFC 8693 reply's `issued_token_type` (`None`: it stated none).
    pub(crate) issued_token_type: Option<String>,
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
    /// Construct a `CachedToken`, capturing its credential without a plaintext header copy. The second value is whether the
    /// token holds bytes invalid in a header value, so it is never presented (the caller reports it). The token
    /// arrives already wiped on drop (a response's token is read into a wiped buffer and moved
    /// here, [`access_token`]).
    pub(crate) fn new(mut token: Zeroizing<String>, expires_at: u64) -> (Self, bool) {
        let token = Cred::captured(Zeroizing::new(std::mem::take(&mut *token).into_bytes()))
            .require_secure();
        let invalid = !token.is_field_value();
        let presentable = !token.is_empty() && !invalid;
        (
            Self {
                token,
                expires_at,
                presentable,
                token_type: None,
                issued_token_type: None,
            },
            invalid,
        )
    }

    /// Why this token is no bearer (its `token_type` is stated and is not `bearer`, in any case);
    /// `None` for a bearer or a reply that stated no type.
    pub(crate) fn not_bearer(&self) -> Option<String> {
        let t = self.token_type.as_deref()?;
        if t.eq_ignore_ascii_case("bearer") {
            return None;
        }
        if t == "N_A" {
            return Some(
                "token endpoint returned token_type N_A: the exchange issued no bearer token (RFC \
                 8693 §2.2.1); it is not presented"
                    .to_string(),
            );
        }
        Some(format!(
            "token endpoint returned token_type {}, not a bearer token (RFC 6749 §7.1); it is not \
             presented",
            shown(t)
        ))
    }

    /// Why an RFC 8693 exchange's token is not one to present: its `issued_token_type` is stated
    /// and is neither an access token nor a JWT (RFC 8693 §3); `None` otherwise.
    pub(crate) fn not_access_token(&self) -> Option<String> {
        let t = self.issued_token_type.as_deref()?;
        if t == token_exchange::ACCESS_TOKEN_TYPE || t == token_exchange::JWT_TOKEN_TYPE {
            return None;
        }
        Some(format!(
            "token endpoint returned issued_token_type {}, neither an access token nor a JWT (RFC \
             8693 §2.2.1); it is not presented",
            shown(t)
        ))
    }

    /// The sealed credential, when there is one to present.
    pub(crate) fn header(&self) -> Option<&Cred> {
        self.presentable.then_some(&self.token)
    }
}

/// A reply's type word as a refusal names it: quoted when it is a short token of plain characters,
/// else described (an endpoint's text is never echoed beyond that).
fn shown(t: &str) -> String {
    let plain = !t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/:".contains(&b));
    if plain {
        format!("`{t}`")
    } else {
        "an unrecognised value".to_string()
    }
}

/// Seconds to sleep before the next re-mint, given a token that expires at `expires_at` (epoch secs).
///
/// Refresh `REFRESH_SKEW_SECS` BEFORE expiry for a normally-lived token so a request never races the
/// expiry boundary. A SHORT-TTL token cannot take that skew (nor the `MIN_SLEEP_SECS` floor, which
/// would serve it past its expiry), so:
///   - `ttl == 0` (already expired / garbage `expires_in ≈ 0`): back off `MIN_SLEEP_SECS` so the mint
///     loop cannot spin hot — nothing useful to serve, fail safe.
///   - `ttl <= REFRESH_SKEW_SECS` (too short to refresh a full skew early): re-mint at ~half the
///     remaining life, so the refresh never lands past expiry, and never below 1s (1.5.5's rule).
///   - otherwise: the normal `ttl - REFRESH_SKEW_SECS`, with `MIN_SLEEP_SECS` as a hot-loop floor near
///     the skew boundary.
///
/// Guarantees: for any `ttl >= 2` the next mint is scheduled strictly before expiry, and for
/// `ttl == 1` at it; for `ttl == 0` the loop is rate-limited to `MIN_SLEEP_SECS`; and no refresh is
/// further off than [`MAX_REFRESH_SECS`].
pub(crate) fn next_refresh_secs(expires_at: u64, now: u64) -> u64 {
    let ttl = expires_at.saturating_sub(now);
    let secs = if ttl == 0 {
        MIN_SLEEP_SECS
    } else if ttl <= REFRESH_SKEW_SECS {
        (ttl / 2).max(1)
    } else {
        (ttl - REFRESH_SKEW_SECS).max(MIN_SLEEP_SECS)
    };
    secs.min(MAX_REFRESH_SECS)
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
    /// RFC 6749 §5.1 `token_type` (REQUIRED there; absent is tolerated).
    #[serde(default)]
    token_type: Option<String>,
    /// RFC 8693 §2.2.1 `issued_token_type` (a token exchange's reply).
    #[serde(default)]
    issued_token_type: Option<String>,
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
    let code = wiped_member(body, b"error")?;
    let ok = code.len() <= 64
        && code
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E));
    ok.then_some(code)
}

/// Parse a finished token response: a non-2xx status is the endpoint's refusal, named with its
/// status and error code only; otherwise the JSON token, with whether that token cannot be
/// presented (it holds bytes invalid in a header value, or a byte the lossy decode replaced).
pub(crate) fn parse_response(
    status: u16,
    body: &[u8],
    now: u64,
) -> Result<(CachedToken, bool), String> {
    let replaced = std::str::from_utf8(body).is_err();
    let body = lossy_wiped(body);
    if !(200..300).contains(&status) {
        let status = http::StatusCode::from_u16(status)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| status.to_string());
        return Err(match oauth_error_code(&body) {
            Some(code) => format!("token endpoint returned {status}: {}", code.as_str()),
            None => format!("token endpoint returned {status}"),
        });
    }

    let tok: TokenResponse =
        serde_json::from_str(&body).map_err(json_error("token response JSON invalid"))?;

    let mut read = access_token(&body)?;
    let token = Zeroizing::new(std::mem::take(&mut *read));
    let forged = replaced && token.contains('\u{FFFD}');
    let (mut cached, invalid) = CachedToken::new(token, now.saturating_add(tok.expires_in));
    cached.token_type = tok.token_type;
    cached.issued_token_type = tok.issued_token_type;
    Ok((cached, invalid || forged))
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
    /// The reply head's `Retry-After` (RFC 9110 §10.2.3), where it carries one.
    pub retry_after: Option<RetryAfter>,
}

/// A reply's `Retry-After`: a delay in seconds, or an instant (epoch seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryAfter {
    /// `delay-seconds`.
    Secs(u64),
    /// An `HTTP-date`, as epoch seconds.
    At(u64),
}

/// Seconds from a scheduled style's landed token to its next mint: 1.5.5's schedule
/// ([`next_refresh_secs`]), never sooner than [`MIN_MINT_INTERVAL_SECS`]. A token that lives at
/// least twice the floor keeps 1.5.5's schedule exactly.
pub(crate) fn scheduled_refresh_secs(expires_at: u64, now: u64) -> u64 {
    next_refresh_secs(expires_at, now).max(MIN_MINT_INTERVAL_SECS)
}

/// A `Retry-After` value (RFC 9110 §10.2.3): `delay-seconds`, or an `HTTP-date` in any of its three
/// formats, using the shared calendar and the fleet wall-clock floor.
pub(crate) fn retry_after(value: &[u8]) -> Option<RetryAfter> {
    let v = std::str::from_utf8(value).ok()?.trim();
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        return Some(RetryAfter::Secs(v.parse().unwrap_or(u64::MAX)));
    }
    busbar_contract::abi::auth::http_date_unix(v, WALL_FLOOR_SECS)
        .and_then(|at| u64::try_from(at).ok())
        .map(RetryAfter::At)
}

/// The negative-cache window of a failed exchange at wall-clock `wall`: the reply's `Retry-After`
/// when it carried one, else [`EXCHANGE_BACKOFF_SECS`]; never past [`MAX_BACKOFF_SECS`].
fn backoff_secs(retry: Option<RetryAfter>, wall: u64) -> u64 {
    match retry {
        None => EXCHANGE_BACKOFF_SECS,
        Some(RetryAfter::Secs(s)) => s,
        Some(RetryAfter::At(t)) => t.saturating_sub(wall),
    }
    .min(MAX_BACKOFF_SECS)
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
    /// Continue one opening without rebuilding its request or losing a pending host handle.
    fn advance_open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
        _state: &mut Option<Box<host_wire::Opening>>,
    ) -> Result<ConnId, ConnError> {
        self.open(req, body, timeout_ms)
    }
    /// Read one piece into `buf`; [`ConnError::Pending`] when nothing is ready.
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError>;
    /// Continue a pending reply read on its original completion handle.
    fn advance_read(
        &self,
        conn: ConnId,
        buf: &mut [u8],
        _state: &mut Option<Box<host_wire::PendingRead>>,
    ) -> Result<Got, ConnError> {
        self.read(conn, buf)
    }
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
enum Attempt {
    /// No exchange; the next is due at `due_ns` on the tick clock.
    Idle { due_ns: u64 },
    /// The request and its zeroizing encoding survive pending connection security checks.
    Opening {
        request: TokenRequest,
        sealed: SealedWrite,
        state: Option<Box<host_wire::Opening>>,
        started_ns: u64,
    },
    /// An exchange is in flight on `conn`.
    InFlight {
        conn: ConnId,
        connection: Option<Box<host_wire::Opening>>,
        pending_read: Option<Box<host_wire::PendingRead>>,
        started_ns: u64,
        status: Option<u32>,
        /// The reply head's `Retry-After`, when it carried one.
        retry_after: Option<RetryAfter>,
        /// The response so far: it carries the access token, so it grows only through
        /// [`append_wiped`] (no growth leaves an unwiped copy) and is wiped on drop.
        body: Zeroizing<Vec<u8>>,
    },
}

/// How a failed mint is judged, for its log line (S4, S5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The endpoint refused the credential, or the configuration cannot mint: INFO.
    Refused,
    /// The endpoint is down or shedding load (a 5xx or 429, a timeout, a lost connection): WARN.
    Outage,
    /// The endpoint answered, but what it issued cannot be used as this binding's bearer, or
    /// the host gave the mint nothing it can sign or date with: WARN, for the operator.
    Unusable,
}

impl Fail {
    /// An outage when `outage`, else a refusal.
    const fn of(outage: bool) -> Self {
        if outage {
            Self::Outage
        } else {
            Self::Refused
        }
    }
}

/// What a finished tick of one cell reports for the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// A mint failed; it will retry (BUSBAR-4016).
    MintFailed(String),
    /// The endpoint answered 200 with an empty token (BUSBAR-4015).
    EmptyToken,
    /// The minted token holds bytes invalid in a header value (BUSBAR-4014).
    TokenInvalidBytes,
    /// A token landed.
    Minted,
}

/// Why a call is refused when its binding has no token to present: never sent unauthenticated.
pub(crate) const NO_TOKEN: &str = "no OAuth token could be minted for this binding (see \
     diagnostics BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and \
     the mint retries on its schedule";

/// Why a call is refused when its binding's token has expired and its refresh failed: the
/// expired token is never presented (RFC 6750 §3.1), and the call is not held for the retry.
pub(crate) const EXPIRED: &str = "the minted OAuth token has expired and its refresh failed (see \
     diagnostics BUSBAR-4014/4015/4016); the call is refused rather than sent with an expired \
     token, and the mint retries on its schedule";

/// Why a call is refused when its token cannot be a header value.
pub(crate) const UNPRESENTABLE: &str = "the minted OAuth token holds bytes invalid in a header \
     value (see diagnostic BUSBAR-4014); the call is refused rather than sent unauthenticated";

/// The answer the per-request call reads. `Debug` redacts the bearer.
#[derive(PartialEq, Eq)]
pub(crate) enum Read<'a> {
    /// Present this credential through the SDK's sealed Bearer field recipe.
    Header(&'a Cred),
    /// Nothing can be presented after a mint: the call is FAILED, saying why (never sent
    /// unauthenticated).
    Refuse(&'static str),
    /// Not ready: a scheduled style's token has expired and its refresh is in flight or brought
    /// forward, or an on-demand exchange is due.
    Wait,
}

/// ONE BINDING'S TOKEN: keyed by (style, credential, settings) in the instance's cache, so it
/// survives `refresh` and re-opening (abi/auth: the outbound token cache outlives a handle).
pub(crate) struct Minted {
    minter: Minter,
    max_response_bytes: usize,
    token: RwLock<Arc<CachedToken>>,
    attempt: Mutex<Attempt>,
    refresh_failed: AtomicBool,
    /// The tick-clock instant (ns) the last token landed ([`NEVER_LANDED`]: none has): the cell's
    /// next mint, scheduled, brought forward or armed by a request, is never due before
    /// [`MIN_MINT_INTERVAL_SECS`] after it.
    landed_ns: AtomicU64,
    /// Keep an on-demand cell cached until its mint-rate floor elapses on the wall clock.
    retain_until: AtomicU64,
    /// Minted on demand ([`Minter::TokenExchange`]): no refresh ahead of a request, no retry on a
    /// schedule; a request that finds no usable token arms the next exchange.
    on_demand: bool,
    /// An on-demand cell's token is presented until this wall-clock epoch second: the instant a
    /// scheduled style would refresh it ([`next_refresh_secs`] from its mint), or, for a token
    /// too short-lived for that to reach [`MIN_MINT_INTERVAL_SECS`], that floor or its expiry,
    /// whichever comes first (never past the expiry).
    usable_until: AtomicU64,
    /// The last failed mint was an outage of the token endpoint ([`Minted::outage`]).
    outage: AtomicBool,
    /// The last failed mint's reply could not be used ([`Minted::unusable`]).
    unusable: AtomicBool,
    /// An absent `token_type` was logged for this cell (once per cell, O5).
    untyped_warned: AtomicBool,
    /// An on-demand cell whose exchange failed is not retried before this wall-clock epoch second
    /// (its negative-cache window: requests for its scope fail fast meanwhile); `0` = none.
    retry_at: AtomicU64,
    /// Why the on-demand cell's last exchange failed, answered to the requests in its window.
    failure: Mutex<Option<String>>,
    /// When a request last used this on-demand cell, as the instance's use count stamps it.
    last_used: AtomicU64,
    /// A point [`Minted::usable`] passes before it judges the cell, where a race test holds the
    /// thread (set only by the side-file tests; production sets none).
    pub(crate) before_usable: OnceLock<Pause>,
}

/// What a race test runs at a seam a call passes ([`Minted::before_usable`],
/// `Oauth::before_mint_park`): defined by the side-file tests; production holds none, so passing
/// the seam is one unset-cell read.
pub(crate) type Pause = Box<dyn Fn() + Send + Sync>;

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
            attempt: Mutex::new(Attempt::Idle { due_ns: 0 }),
            refresh_failed: AtomicBool::new(false),
            landed_ns: AtomicU64::new(NEVER_LANDED),
            retain_until: AtomicU64::new(0),
            usable_until: AtomicU64::new(0),
            outage: AtomicBool::new(false),
            unusable: AtomicBool::new(false),
            untyped_warned: AtomicBool::new(false),
            retry_at: AtomicU64::new(0),
            failure: Mutex::new(None),
            last_used: AtomicU64::new(0),
            before_usable: OnceLock::new(),
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
                .attempt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Attempt::Idle { .. }
        )
    }

    /// An on-demand cell holds a token it presents at wall-clock `now`.
    pub(crate) fn usable(&self, now: u64) -> bool {
        if let Some(pause) = self.before_usable.get() {
            pause();
        }
        self.is_ready() && now < self.usable_until.load(Ordering::Acquire)
    }

    /// A request used this cell at use count `at`.
    pub(crate) fn touch(&self, at: u64) {
        self.last_used.fetch_max(at, Ordering::AcqRel);
    }

    /// The use count a request last used this cell at.
    pub(crate) fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Acquire)
    }

    /// An on-demand cell whose exchange failed is inside its negative-cache window at wall-clock
    /// `now`: its scope is not exchanged again until the window ends.
    pub(crate) fn backing_off(&self, now: u64) -> bool {
        now < self.retry_at.load(Ordering::Acquire)
    }

    /// Evicting this cell now would discard its minimum interval between successful mints.
    pub(crate) fn cooling_down(&self, now: u64) -> bool {
        now < self.retain_until.load(Ordering::Acquire)
    }

    /// Why a request for this cell's scope fails at once at wall-clock `now`: the cached failure,
    /// while the cell backs off; `None` outside the window.
    pub(crate) fn backoff_reason(&self, now: u64) -> Option<String> {
        let (why, secs) = self.backoff(now)?;
        Some(format!(
            "the RFC 8693 token exchange for this call's scope failed ({why}); it is not tried \
             again for {secs} s, and the call is refused rather than made unauthenticated"
        ))
    }

    /// Why a call for a scope with no cell yet fails at once at wall-clock `now`, when this cell
    /// (another scope of the same binding) is backing off an OUTAGE of the token endpoint: a new
    /// scope would hit the same endpoint, so it is not tried before the window ends.
    pub(crate) fn outage_reason(&self, now: u64) -> Option<String> {
        if !self.outage() {
            return None;
        }
        let (why, secs) = self.backoff(now)?;
        Some(format!(
            "the RFC 8693 token endpoint is down (an exchange for another scope failed: {why}); \
             no new scope is exchanged for {secs} s, and the call is refused rather than made \
             unauthenticated"
        ))
    }

    /// The cached failure and the seconds its window has left at wall-clock `now`.
    fn backoff(&self, now: u64) -> Option<(String, u64)> {
        let until = self.retry_at.load(Ordering::Acquire);
        if now >= until {
            return None;
        }
        let why = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_default();
        Some((why, until - now))
    }

    /// An on-demand cell's exchange failed at wall-clock `wall` for `why`: its scope backs off for
    /// the window `retry` sets ([`backoff_secs`]). A scheduled cell retries on its own schedule.
    fn back_off(&self, wall: u64, retry: Option<RetryAfter>, why: &str) {
        if !self.on_demand {
            return;
        }
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(why.to_string());
        self.retry_at.store(
            wall.saturating_add(backoff_secs(retry, wall)),
            Ordering::Release,
        );
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
    /// yields no header (bytes invalid in a header value), and not once the token has expired,
    /// whether or not its refresh failed (contract `abi/auth/outbound.rs`: "`0` = not yet (before
    /// the first mint, or expired with a failed refresh)"; an expired token is never presented).
    /// It changes nothing: a probe does not bring a refresh forward.
    pub(crate) fn presents(&self, now: u64) -> bool {
        if self.on_demand {
            return self.usable(now);
        }
        let tok = self.current();
        !tok.token.is_empty() && now < tok.expires_at && tok.header().is_some()
    }

    /// Present the cached token for a request at wall-clock `now` (epoch seconds), through `f`
    /// (so the borrow of the cached value never escapes the read).
    pub(crate) fn read<T>(&self, now: u64, f: impl FnOnce(Read<'_>) -> T) -> T {
        if self.on_demand && !self.usable(now) {
            self.mint_now(now);
            return f(Read::Wait);
        }

        let mut tok = self.current();

        if tok.token.is_empty() {
            return f(Read::Refuse(NO_TOKEN));
        }
        if !self.on_demand && now >= tok.expires_at {
            let mut attempt = self
                .attempt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tok = self.current();
            if now >= tok.expires_at {
                let answer = self.expired(&mut attempt);
                drop(attempt);
                return f(answer);
            }
        }
        match tok.header() {
            Some(h) => f(Read::Header(h)),
            None => f(Read::Refuse(UNPRESENTABLE)),
        }
    }

    /// A scheduled cell's token has expired before its refresh landed, judged under the exchange's
    /// lock (`attempt`), which every mint lands and fails under: an exchange in flight is waited
    /// for; a refresh that failed is backing off, so the call fails closed ([`EXPIRED`]) and the
    /// retry stays on its schedule; otherwise the refresh is brought forward to
    /// [`MIN_MINT_INTERVAL_SECS`] after the last landed token (at once, after a host suspend) and
    /// waited for.
    fn expired(&self, attempt: &mut Attempt) -> Read<'static> {
        match attempt {
            Attempt::Opening { .. } | Attempt::InFlight { .. } => Read::Wait,
            Attempt::Idle { .. } if self.refresh_failed.load(Ordering::Acquire) => {
                Read::Refuse(EXPIRED)
            }
            Attempt::Idle { due_ns } => {
                *due_ns = (*due_ns).min(self.earliest_mint_ns());
                Read::Wait
            }
        }
    }

    /// An on-demand request wants a token this cell does not hold at wall-clock `now`: an idle
    /// cell's next exchange is due at once, unless it backs off a failure (judged under the
    /// exchange's lock, which every failure is recorded under, so a failure that lands meanwhile
    /// is seen).
    fn mint_now(&self, now: u64) {
        let mut attempt = self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Attempt::Idle { due_ns } = &mut *attempt {
            if !self.backing_off(now) {
                *due_ns = (*due_ns).min(self.earliest_mint_ns());
            }
        }
    }

    /// The earliest tick-clock instant (ns) the next mint may start: [`MIN_MINT_INTERVAL_SECS`]
    /// after the last token landed, or at once when none has.
    fn earliest_mint_ns(&self) -> u64 {
        match self.landed_ns.load(Ordering::Acquire) {
            NEVER_LANDED => 0,
            at => at.saturating_add(MIN_MINT_INTERVAL_SECS * NS),
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
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Attempt::Idle { due_ns } = *ex {
            if now_ns < due_ns {
                return (due_ns, None);
            }
            let Some(_) = wire else {
                return self.failed(
                    &mut ex,
                    now_ns,
                    wall,
                    "token endpoint request failed: no connection was granted for the token endpoint"
                        .to_string(),
                    Fail::Refused,
                    None,
                );
            };
            if wall < WALL_FLOOR_SECS {
                return self.failed(
                    &mut ex,
                    now_ns,
                    wall,
                    format!(
                        "no plausible wall clock: the host's reads {wall} s, before \
                         {WALL_FLOOR_DATE} (or none was read); no token is minted until it does"
                    ),
                    Fail::Unusable,
                    None,
                );
            }
            let req = match self.minter.request(wall) {
                Ok(r) => r,
                Err(e) => return self.failed(&mut ex, now_ns, wall, e, Fail::Refused, None),
            };

            let body = match req.body.encoded() {
                Ok(b) => b,
                Err(r) => {
                    return self.failed(
                        &mut ex,
                        now_ns,
                        wall,
                        format!("the token request could not be built: {r}"),
                        Fail::Refused,
                        None,
                    )
                }
            };
            *ex = Attempt::Opening {
                request: req,
                sealed: body,
                state: None,
                started_ns: now_ns,
            };
        }
        if let Attempt::Opening { started_ns, .. } = &*ex {
            if now_ns.saturating_sub(*started_ns) >= MINT_DEADLINE_SECS * NS {
                return self.failed(
                    &mut ex,
                    now_ns,
                    wall,
                    "token endpoint request did not open before the mint deadline".into(),
                    Fail::Outage,
                    None,
                );
            }
        }
        let Some(wire) = wire else {
            return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None);
        };
        if let Attempt::Opening {
            request,
            sealed,
            state,
            started_ns,
        } = &mut *ex
        {
            match wire.advance_open(request, sealed, MINT_DEADLINE_SECS * 1000, state) {
                Ok(conn) => {
                    *ex = Attempt::InFlight {
                        conn,
                        connection: state.take(),
                        pending_read: None,
                        started_ns: *started_ns,
                        status: None,
                        retry_after: None,
                        body: Zeroizing::new(Vec::new()),
                    };
                }
                Err(ConnError::Pending) => return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None),
                Err(e) => {
                    return self.failed(
                        &mut ex,
                        now_ns,
                        wall,
                        format!("token endpoint request failed: {}", conn_cause(e)),
                        Fail::of(endpoint_down(e)),
                        None,
                    )
                }
            }
        }
        let Attempt::InFlight {
            conn,
            connection,
            pending_read,
            started_ns,
            status,
            retry_after,
            body,
        } = &mut *ex
        else {
            return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None);
        };
        let conn = *conn;
        let mut buf = Zeroizing::new([0_u8; READ_BUF_BYTES]);

        let mono_at = wire.clock().map(|c| c.mono_ns);
        let mut reads = 0_u32;
        let finished = loop {
            let measured =
                mono_at.and_then(|at| wire.clock().map(|c| c.mono_ns.saturating_sub(at)));
            let elapsed = match measured {
                Some(elapsed) => elapsed,
                None => {
                    if reads >= MAX_READS_PER_TICK {
                        return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None);
                    }
                    reads += 1;
                    0
                }
            };
            if now_ns.saturating_add(elapsed).saturating_sub(*started_ns) >= MINT_DEADLINE_SECS * NS
            {
                break Err((
                    "token endpoint response was not read before the mint deadline; refusing to \
                     parse a partial token response"
                        .to_string(),
                    Fail::Outage,
                ));
            }
            match wire.advance_read(conn, &mut buf[..], pending_read) {
                Ok(got) => {
                    if got.status.is_some() {
                        *status = got.status;
                    }
                    if got.retry_after.is_some() {
                        *retry_after = got.retry_after;
                    }
                    if got.kind == PieceKind::Body {
                        if let Err(e) = append_wiped(body, &buf[..got.len], self.max_response_bytes)
                        {
                            break Err((e, Fail::Refused));
                        }
                        if body.len() > self.max_response_bytes {
                            break Err((
                                format!(
                                    "token endpoint response exceeded the {}-byte cap; refusing \
                                     to parse a truncated token response",
                                    self.max_response_bytes
                                ),
                                Fail::Refused,
                            ));
                        }
                    }
                    if got.kind == PieceKind::Completion || (got.kind == PieceKind::Body && got.end)
                    {
                        break match *status {
                            Some(status) => Ok((status, std::mem::take(body))),
                            None => Err((
                                "token endpoint response ended without a response head; refusing to parse a partial token response".to_string(),
                                Fail::Outage,
                            )),
                        };
                    }
                }
                Err(ConnError::Pending) => return (now_ns.saturating_add(IN_FLIGHT_POLL_NS), None),
                Err(ConnError::Closed) => {
                    break Err((
                        "token endpoint connection failed mid-response; refusing to parse \
                               a partial token response"
                            .to_string(),
                        Fail::Outage,
                    ))
                }
                Err(e) => {
                    break Err((
                        format!("token endpoint request failed: {}", conn_cause(e)),
                        Fail::of(endpoint_down(e)),
                    ))
                }
            }
        };
        let retry = *retry_after;
        if let Some(connection) = connection {
            connection.release();
        }
        wire.close(conn);
        match finished.and_then(|(status, body)| answered(status, &body, wall)) {
            Ok((fresh, _)) if !fresh.token.is_empty() && fresh.expires_at <= wall => self.failed(
                &mut ex,
                now_ns,
                wall,
                "token endpoint returned an access token that has already expired (expires_in 0); \
                 it is not presented"
                    .to_string(),
                Fail::Unusable,
                retry,
            ),

            // RFC 8693 uses access_token for arbitrary security tokens. Its required
            // type metadata must identify a usable bearer before it enters the cache.
            Ok((fresh, _))
                if self.on_demand
                    && (fresh.token_type.is_none() || fresh.issued_token_type.is_none()) =>
            {
                self.failed(
                    &mut ex,
                    now_ns,
                    wall,
                    "token exchange response requires token_type and issued_token_type; \
                     an untyped token is not presented"
                        .to_string(),
                    Fail::Unusable,
                    retry,
                )
            }

            Ok((fresh, _))
                if fresh.not_bearer().is_some()
                    || (self.on_demand && fresh.not_access_token().is_some()) =>
            {
                let e = fresh
                    .not_bearer()
                    .or_else(|| fresh.not_access_token())
                    .unwrap_or_default();
                self.failed(&mut ex, now_ns, wall, e, Fail::Unusable, retry)
            }

            Ok((fresh, _)) if fresh.token.is_empty() => {
                let due = self.retry_later(
                    &mut ex,
                    now_ns,
                    wall,
                    "the authorization server returned 200 with an empty access_token",
                    Fail::Unusable,
                    retry,
                );
                (due, Some(Report::EmptyToken))
            }

            Ok((_, true)) => {
                let due = self.retry_later(
                    &mut ex,
                    now_ns,
                    wall,
                    "the exchanged token holds bytes invalid in a header value",
                    Fail::Unusable,
                    retry,
                );
                (due, Some(Report::TokenInvalidBytes))
            }
            Ok((mut fresh, _)) => {
                if fresh.token_type.is_none() && !self.untyped_warned.swap(true, Ordering::AcqRel) {
                    tracing::warn!(
                        module = "oauth",
                        "the token endpoint's reply carries no token_type (RFC 6749 §5.1 requires \
                         it); its token is presented as a bearer"
                    );
                }
                fresh.token_type = None;
                fresh.issued_token_type = None;
                let now = wall;
                let fresh_expires_at = fresh.expires_at;
                let ahead = next_refresh_secs(fresh_expires_at, now);

                let due = if self.on_demand {
                    u64::MAX
                } else {
                    let floored = scheduled_refresh_secs(fresh.expires_at, now);
                    now_ns.saturating_add(floored.saturating_mul(NS))
                };
                *self
                    .token
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(fresh);
                if self.on_demand {
                    let ttl = fresh_expires_at.saturating_sub(now);
                    self.retain_until.store(
                        if ttl < 2 * MIN_MINT_INTERVAL_SECS {
                            now.saturating_add(MIN_MINT_INTERVAL_SECS)
                        } else {
                            0
                        },
                        Ordering::Release,
                    );
                    let usable = ahead.max(MIN_MINT_INTERVAL_SECS.min(ttl));
                    self.usable_until
                        .store(now.saturating_add(usable), Ordering::Release);
                    self.retry_at.store(0, Ordering::Release);
                }
                self.refresh_failed.store(false, Ordering::Release);
                self.landed_ns.store(now_ns, Ordering::Release);
                *ex = Attempt::Idle { due_ns: due };
                (due, Some(Report::Minted))
            }
            Err((e, kind)) => self.failed(&mut ex, now_ns, wall, e, kind, retry),
        }
    }

    /// Whether this cell's last failed mint was an OUTAGE of its token endpoint (a 5xx or 429, a
    /// timeout, a connection lost), not a refusal of its credential or its configuration.
    pub(crate) fn outage(&self) -> bool {
        self.outage.load(Ordering::Acquire)
    }

    /// Whether this cell's last failed mint got a reply it cannot use as a bearer, or had nothing
    /// to sign or date with: the operator's to see (WARN), though no outage.
    pub(crate) fn unusable(&self) -> bool {
        self.unusable.load(Ordering::Acquire)
    }

    /// A failed mint at tick-clock `now_ns` and wall-clock `wall`: keep serving the current token
    /// until it expires (never past it: [`Minted::read`]), and retry at `MIN_SLEEP_SECS` (an on-demand cell retries when a request next arms
    /// it, after its negative-cache window: `retry`, the reply's `Retry-After`, sets it).
    fn failed(
        &self,
        ex: &mut Attempt,
        now_ns: u64,
        wall: u64,
        e: String,
        kind: Fail,
        retry: Option<RetryAfter>,
    ) -> (u64, Option<Report>) {
        let due = self.retry_later(ex, now_ns, wall, &e, kind, retry);
        (due, Some(Report::MintFailed(e)))
    }

    /// THE ONE RETRY RULE of every failed mint, judged `kind`, at tick-clock `now_ns` and
    /// wall-clock `wall`: the refresh is failed, an on-demand cell backs off ([`Minted::back_off`]),
    /// and the next attempt is due a retry interval on (an on-demand cell's: on a request). The
    /// tick-clock instant it is due at.
    fn retry_later(
        &self,
        ex: &mut Attempt,
        now_ns: u64,
        wall: u64,
        why: &str,
        kind: Fail,
        retry: Option<RetryAfter>,
    ) -> u64 {
        self.refresh_failed.store(true, Ordering::Release);
        self.back_off(wall, retry, why);
        self.outage.store(kind == Fail::Outage, Ordering::Release);
        self.unusable
            .store(kind == Fail::Unusable, Ordering::Release);
        let due = if self.on_demand {
            u64::MAX
        } else {
            now_ns.saturating_add(MIN_SLEEP_SECS * NS)
        };
        *ex = Attempt::Idle { due_ns: due };
        due
    }
}

/// A finished reply at wall-clock `wall`, judged ([`parse_response`]): a status past 16 bits is no
/// HTTP status at all; a failure of a reply that answered 2xx is UNUSABLE, else an outage or a
/// refusal by its status.
fn answered(status: u32, body: &[u8], wall: u64) -> Result<(CachedToken, bool), (String, Fail)> {
    let Ok(code) = u16::try_from(status) else {
        return Err((
            format!("token endpoint returned status {status}, which is no HTTP status code"),
            Fail::Unusable,
        ));
    };
    parse_response(code, body, wall).map_err(|e| {
        let kind = if (200..300).contains(&status) {
            Fail::Unusable
        } else {
            Fail::of(outage_status(status))
        };
        (e, kind)
    })
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
const fn endpoint_down(e: ConnError) -> bool {
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

        #[allow(unreachable_patterns)]
        _ => "connection failed",
    }
}

#[cfg(test)]
#[path = "../tests/mint_tests.rs"]
pub(crate) mod tests;
