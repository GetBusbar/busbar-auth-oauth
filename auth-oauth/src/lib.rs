// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-oauth — the OAuth self-minting auth styles, one auth-kind plugin
//!
//! `jwt-bearer` (RFC 7523) and `oauth-client-credentials` (RFC 6749 §4.4) are ONE mechanism —
//! each obtains a short-lived bearer from a token endpoint and presents it as
//! `authorization: Bearer <token>`, differing only in the token request — and live in one plugin,
//! `busbar-auth-oauth`, loaded when some provider uses one of them. It speaks the auth kind's
//! memory ABI (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds one style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is called by the binding's transport at the style's auth point (`Head`): the auth fields for this request, staged into the SDK's
//!   writer, which the transport adds to the head before it encodes it.
//!   None of these styles serves the caller's credential — an OAuth token is always minted from the
//!   OPERATOR's own configured credential, never a per-request one — so none of these styles declares
//!   [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`].
//! * `outbound_ready` is the handle's `ready` fact for the health prober.
//! * `tick` refreshes minted tokens ahead of expiry.
//!
//! `oauth-token-exchange` (RFC 8693) is the same mechanism minted ON DEMAND: its credential is busbar's own subject token, its
//! settings `{token_url, resource, subject_token_type?}`, and the scope each exchange asks for is
//! the per-call down-scope the request states in `fields`' extensions blob
//! (`busbar_contract::abi::auth::EXT_SCOPE`). Each scope is its own exchange and its own cached token;
//! a request that finds none usable waits (PENDING on its ticket) while the exchange runs on the
//! instance's driver ticket, and fails (FAILED) when the exchange does.
//!
//! Each style mints through the plugin's own need and refreshes ahead of expiry on `tick`
//! (`mint`). The kernel holds no auth cache and does no per-plugin branching.
//!
//! The door is the SDK's safe outbound-auth kit (`busbar_contract::abi::sdk::auth_outbound`,
//! `auth_outbound_door!`): `Oauth` is its [`OutboundPlugin`], and the crate
//! holds no `unsafe` (`#![forbid(unsafe_code)]`). The inbound
//! operations (`verify`, the login pair) are not served and answer REFUSED (the tail declares only
//! the outbound capability).
//!
//! The needs ([`NEEDS`]; egress class `provider`: a token endpoint is a provider upstream's own URL
//! (security.md: provider upstreams, "their `base_url` and `token_url` included"), refused a
//! private, loopback or link-local address unless `advanced.allow_destinations` names it, the
//! provider's 1.5.5 metadata carve-outs read in it, and the target's own scheme kept, so 1.5.5's
//! plaintext to an allowlisted private token endpoint still mints): one
//! outbound need per token endpoint, over the http transport, its target the
//! binding's own setting (`target_from`), so the host declares it pinned to that endpoint when it
//! opens the instance with the binding's settings. The token exchange is ONE framed request and its
//! reply over that need, through the host's connector table (`mint::host_wire`), on the instance's
//! driver ticket: started on `tick`, or at once when a binding opens or a request waits on a token
//! (the driver ticket is woken and `drive` starts it), and carried on by the `drive`s its pending
//! reads wake.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod instance;
mod migrate;
mod mint;
mod style;
mod token_response;

#[cfg(test)]
#[path = "tests/support.rs"]
mod test_support;

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

use std::borrow::Cow;
use std::task::Poll;

use busbar_contract::abi::auth::{
    ranked, AuthPoints, AuthTail, StyleDecl, CANCEL_CONTINUES, FIELD_SENSITIVE,
    STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_PROVIDER, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::auth_outbound::{
    outbound_tail, style as style_decl, Diags, Driven, FieldsAnswer, FieldsView, FieldsWriter,
    Mode, OpenRefusal, OutboundPlugin,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::cred::{Cred, Parts};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::{self, Refusal};

use crate::instance::Oauth;
use crate::mint::Read;

/// The longest per-call scope a token exchange takes (O4): each distinct scope is its own cell,
/// so a request-stated scope is bounded.
const MAX_SCOPE_BYTES: usize = 1024;

/// Why a call whose scope's token exchange failed while it waited is refused.
const EXCHANGE_FAILED: &str = "the RFC 8693 token exchange for this call's scope failed; the call \
     is refused rather than made unauthenticated (see diagnostics BUSBAR-4014/4015/4016)";

/// The flags every field this plugin writes carries: [`FIELD_SENSITIVE`]. The field is the
/// bearer, so an h2/h3 encoder sends it never-indexed and no header table keeps it.
const FIELD_FLAGS: u32 = FIELD_SENSITIVE;

/// The styles this plugin serves, each at `Head` (a bearer token reads nothing past the head).
/// None carries [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`] (an OAuth token is always
/// minted from the operator's own credential). Each provider-entry grant STATES where its token
/// endpoint is, so the host judges it by the bit, never by the style's name:
/// `jwt-bearer` the service account's `token_uri` its credential names, read and judged by the
/// host and handed back as the `token_uri` setting; `oauth-client-credentials` the entry's
/// `token_url`. Both rank after the two header styles, so the host's list of the words a
/// provider's `auth:` may name keeps those as its prefix. The token exchange is a
/// plane need's style (its `resource` is no provider key): unranked, its endpoint judged as its
/// need's target.
const STYLES: &[StyleDecl] = &[
    style_decl(
        style::JWT_BEARER,
        STYLE_ENDPOINT_FROM_CREDENTIAL | ranked(3),
        AuthPoints::HEAD,
    ),
    style_decl(
        style::OAUTH_CLIENT_CREDENTIALS,
        STYLE_ENDPOINT_TOKEN_URL | ranked(4),
        AuthPoints::HEAD,
    ),
    style_decl(style::OAUTH_TOKEN_EXCHANGE, 0, AuthPoints::HEAD),
];

/// THE AUTH STATEMENT TAIL: outbound only, no login, no inbound carriers.
const TAIL: &AuthTail = &outbound_tail(0, STYLES);

/// Token endpoint response fields consumed by the mint's retry policy.
const KEPT_REPLY_FIELDS: &[AbiStr] = &[abi_str("retry-after")];

/// One token endpoint's need: outbound, `provider` (refused a private address unless
/// allowlisted, kept in its class though its config names the target; never
/// `operator-infrastructure`, which admits a private address with no entry), over the http
/// transport, its target the binding's setting `target_from` names. The mint reads the reply's
/// code and `retry-after`; the host keeps exactly that declared response field.
const fn token_need(target_from: &'static str) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_PROVIDER,
        transport: abi_str("http"),
        target_from: abi_str(target_from),
        keep_mode: KEEP_NAMED,
        ..Need::EMPTY
    }
    .with_keep_response_headers(KEPT_REPLY_FIELDS)
}

/// THE PLUGIN'S OWN NEEDS, in `mint::need` order: `oauth-client-credentials` and
/// `oauth-token-exchange` POST to the
/// binding's `token_url`, `jwt-bearer` to its `token_uri`.
const NEEDS: &[Need] = &[
    token_need("settings.token_url"),
    token_need("settings.token_uri"),
];

/// The diagnostic ids, in [`instance::diag`] order.
const DIAG_IDS: &[AbiStr] = &[
    abi_str("BUSBAR-4014"),
    abi_str("BUSBAR-4015"),
    abi_str("BUSBAR-4016"),
];

const SETTINGS_CHECK_KEY: &str = busbar_contract::abi::auth::EXT_OUTBOUND_SETTINGS_CHECK;
const SETTINGS_CHECK_EXTENSION: [u8; busbar_contract::abi::mechanism::extensions::entry_len(
    SETTINGS_CHECK_KEY,
    &[1],
)] = busbar_contract::abi::mechanism::extensions::entry(SETTINGS_CHECK_KEY, &[1]);

/// JSON Schema for the lifecycle settings document, embedded in the signed Statement.
const SETTINGS_SCHEMA: &[u8] = include_bytes!("../settings.schema.json");

/// The auth declaration, including pure settings-only validation support.
const STATEMENT: Statement = Statement {
    settings_schema: busbar_contract::abi::mechanism::call::Blob::json(SETTINGS_SCHEMA),
    extensions: busbar_contract::abi::mechanism::call::Blob::of(&SETTINGS_CHECK_EXTENSION),
    ..with_tail(
        statement("busbar-auth-oauth", env!("CARGO_PKG_VERSION"), 1024)
            .with_diag_ids(DIAG_IDS)
            .with_needs(NEEDS),
        TAIL,
    )
};

busbar_contract::auth_outbound_door!(Oauth, STATEMENT, migrate: busbar_contract::abi::sdk::migrate::Migrator<migrate::OauthMigration>);

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
/// `compiled_in::door::door`, the same [`door`] the dropped-in build exports (compiled-in =
/// dropped-in). busbar links this row in its default build, so a provider's `jwt-bearer` or
/// `oauth-client-credentials` credential binds here, the kernel's own copies deleted (P2 D1, the
/// auth split).
pub mod compiled_in {
    /// The door.
    pub mod door {
        pub use crate::door;
    }
}

/// The instance's own settings: the host opens it over a binding's settings, so a JSON object
/// holding only keys some style reads ([`style::instance_keys`]); every other key is refused by
/// name, one `settings: ` line each.
fn judged(settings: &[u8]) -> Result<(), Refusal> {
    let checked = life::settings_object(settings).and_then(|m| {
        style::instance_keys(&m).map_err(|refusals| {
            let lines: Vec<String> = refusals.iter().map(style::Refusal::line).collect();
            Refusal::failed(lines.join("\n"))
        })
    });
    if let Err(r) = &checked {
        tracing::info!(
            module = "oauth",
            reason = r.text().unwrap_or_default(),
            "instance settings refused"
        );
    }
    checked
}

/// ONE `fields` REQUEST, as the instance answers it (the SDK's view, read once).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ask<'a> {
    /// The handle `open_outbound` answered.
    pub handle: u64,
    /// The operator's own credential is asked for (never the caller's: no style passes it).
    pub own: bool,
    /// The per-call scope (`EXT_SCOPE`), for a token exchange.
    pub scope: Option<&'a [u8]>,
    /// The call's ticket ([`Ticket::NONE`] on the spot).
    pub ticket: Ticket,
    /// Wall-clock seconds the host read for the call; `0` = none.
    pub timestamp: u64,
}

/// What a read answers a call at once (`None`: it waits), the header handed to `present`.
fn ready_answer(r: Read<'_>, present: &mut dyn FnMut(&Cred)) -> Option<FieldsAnswer> {
    match r {
        Read::Header(h) => {
            present(h);
            Some(FieldsAnswer::Ready)
        }
        Read::Refuse(why) => Some(FieldsAnswer::Failed(Cow::Borrowed(why))),
        Read::Wait => None,
    }
}

impl Oauth {
    /// THE ANSWER TO ONE `fields`: the cached bearer, handed to `present` (READY with it); FAILED
    /// with an explanation before a scheduled style's first mint; PENDING on a ticket while the call
    /// waits for a token (a scheduled style's expired one whose refresh is in flight or brought
    /// forward, or a token exchange in flight), woken when the mint lands or fails; REFUSED for a
    /// passthrough or a handle this generation does not hold; FAILED, saying why, when there is no
    /// token to present after a mint (it failed, its token cannot be a header value, or it expired
    /// and its refresh failed) or the call's exchange failed. An expired token is never presented.
    ///
    /// NO LOST WAKE: a call that would wait parks its ticket and then reads the token again. A mint
    /// stores its token before it wakes the parked tickets, so the call either is parked in time to
    /// be woken, or reads the token the mint stored.
    pub(crate) fn answer(
        &self,
        ask: &Ask<'_>,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
        present: &mut dyn FnMut(&Cred),
    ) -> Poll<FieldsAnswer> {
        if !ask.own {
            return Poll::Ready(FieldsAnswer::Refused);
        }
        let Some(bound) = self.bound(ask.handle) else {
            return Poll::Ready(FieldsAnswer::Refused);
        };
        self.saw_wall(ask.timestamp);
        let now = self.wall_secs();
        let x = match bound {
            style::Binding::Minted(m) => return self.minted(&m, ask.ticket, now, host, present),
            style::Binding::Exchange(x) => x,
        };
        let ticket = ask.ticket;
        if !ticket.is_none() && self.exchange_failed(ticket) {
            return Poll::Ready(FieldsAnswer::Failed(Cow::Borrowed(EXCHANGE_FAILED)));
        }
        let scope = ask.scope.unwrap_or_default();
        if scope.len() > MAX_SCOPE_BYTES {
            return Poll::Ready(FieldsAnswer::Failed(Cow::Owned(format!(
                "the call's token-exchange scope is {} bytes; a scope is at most {MAX_SCOPE_BYTES} \
                 bytes, so the call is refused rather than made unauthenticated",
                scope.len()
            ))));
        }
        let Ok(scope_text) = std::str::from_utf8(scope) else {
            return Poll::Ready(FieldsAnswer::Failed(Cow::Borrowed(
                "the call's token-exchange scope is not UTF-8; the call is refused rather than exchanged with a changed scope",
            )));
        };
        let key = x.scope_key(scope);

        let cell = match self.exchange_cell(
            key,
            || x.minter(scope_text),
            ticket,
            |c| c.usable(now) || c.backing_off(now),
            |c| x.owns(c),
        ) {
            Ok(cell) => cell,
            Err(why) => return Poll::Ready(FieldsAnswer::Failed(why)),
        };
        if let Some(why) = cell.backoff_reason(now) {
            self.unpark_exchange(key, ticket);
            return Poll::Ready(FieldsAnswer::Failed(Cow::Owned(why)));
        }
        cell.read(now, |r| match r {
            Read::Header(h) => {
                self.unpark_exchange(key, ticket);
                present(h);
                Poll::Ready(FieldsAnswer::Ready)
            }
            Read::Refuse(why) => {
                self.unpark_exchange(key, ticket);
                Poll::Ready(FieldsAnswer::Failed(Cow::Borrowed(why)))
            }
            Read::Wait => match cell.backoff_reason(now) {
                Some(why) => {
                    self.unpark_exchange(key, ticket);
                    self.exchange_failed(ticket);
                    Poll::Ready(FieldsAnswer::Failed(Cow::Owned(why)))
                }
                None => {
                    self.mint_soon(host);
                    Poll::Pending
                }
            },
        })
    }

    /// A minted style's answer: the read, and on a wait the park and the second read.
    fn minted(
        &self,
        m: &mint::Minted,
        ticket: Ticket,
        now: u64,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
        present: &mut dyn FnMut(&Cred),
    ) -> Poll<FieldsAnswer> {
        if let Some(a) = m.read(now, |r| ready_answer(r, &mut *present)) {
            self.unpark_mint(ticket);
            return Poll::Ready(a);
        }
        if ticket.is_none() {
            self.mint_soon(host);
            return Poll::Pending;
        }
        if let Some(pause) = self.before_mint_park.get() {
            pause();
        }
        self.park(ticket);
        if let Some(a) = m.read(now, |r| ready_answer(r, &mut *present)) {
            self.unpark_mint(ticket);
            return Poll::Ready(a);
        }
        self.mint_soon(host);
        Poll::Pending
    }

    /// THE `ready` FACT of `handle`: whether `fields` would present a credential now.
    pub(crate) fn ready(&self, handle: u64) -> bool {
        match self.bound(handle) {
            Some(style::Binding::Minted(cell)) => cell.presents(self.wall_secs()),

            Some(style::Binding::Exchange(b)) => self.exchange_ready(&b),
            None => false,
        }
    }

    /// `open_outbound`'s body: bind a style; a refusal carries one `credential: …` /
    /// `settings: …` line per finding.
    pub(crate) fn bind(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
    ) -> Result<u64, OpenRefusal> {
        match style::open(style, credential, settings, self) {
            Ok(style::Binding::Minted(cell)) => {
                let fresh = !cell.is_ready();
                let handle = self.keep(cell);
                if fresh {
                    self.mint_soon(host);
                }
                Ok(handle)
            }

            Ok(binding) => Ok(self.keep_binding(binding)),
            Err(refusals) => {
                let all: Vec<String> = refusals.iter().map(style::Refusal::line).collect();
                tracing::info!(
                    module = "oauth",
                    style,
                    reason = all.join(" | "),
                    "outbound binding refused"
                );
                let mut lines = refusals.iter().map(style::Refusal::line);
                let first = lines.next().unwrap_or_default();
                Err(lines.fold(OpenRefusal::new(first), |r, l| r.and(l)))
            }
        }
    }
}

impl OutboundPlugin for Oauth {
    fn validate_outbound_settings(style: &str, settings: &[u8]) -> Result<(), Refusal> {
        style::check_settings(style, settings).map_err(|refusals| {
            Refusal::failed(
                refusals
                    .iter()
                    .map(style::Refusal::line)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        })
    }

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        judged(settings)
    }

    fn open(settings: &[u8], _secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        judged(settings)?;
        Oauth::opened(generation)
    }

    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
        _diags: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        self.bind(style, credential, settings, host)
    }

    fn fields(
        &self,
        request: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        op: &Op<'_, busbar_contract::plugin::markers::AuthKind>,
    ) -> Poll<FieldsAnswer> {
        let ask = Ask {
            handle: request.handle(),
            own: request.mode() == Mode::Own,
            scope: request.scope(),
            ticket: op.ticket(),
            timestamp: request.timestamp(),
        };
        let answer = self.answer(&ask, op.host(), &mut |h| {
            out.push_sealed(
                b"authorization",
                Parts::new().sealed(h.bearer()),
                FIELD_FLAGS,
            );
        });
        match &answer {
            Poll::Ready(FieldsAnswer::Refused) => tracing::info!(
                module = "oauth",
                reason =
                    "not the operator's own credential, or a handle this generation does not hold",
                "fields refused"
            ),
            Poll::Ready(FieldsAnswer::Failed(why)) => tracing::info!(
                module = "oauth",
                reason = why.as_ref(),
                "fields failed: no token to present"
            ),
            _ => {}
        }
        answer
    }

    fn outbound_ready(&self, handle: u64) -> bool {
        self.ready(handle)
    }

    /// The token cache survives a reload (abi/auth: keyed by style, credential and settings, never
    /// by handle).
    fn refresh(&self, settings: &[u8], _secrets: &[&[u8]], generation: u64) -> Result<(), Refusal> {
        judged(settings)?;
        self.set_generation(generation);
        Ok(())
    }

    /// The generation's handles go, and every token cell no live handle holds.
    fn retire(&self, generation: u64) {
        Oauth::retire(self, generation);
    }

    fn tick(
        &self,
        now_ns: u64,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
        driver: Ticket,
        diags: &mut Diags,
    ) -> u64 {
        Oauth::tick(self, now_ns, driver, host, diags)
    }

    /// The driver ticket was woken (a read of the token exchange that pended, or a mint wanted at
    /// once): the exchange goes on. PENDING with `wake_at_ns` at the instant a cell is next due, so
    /// a token minted between ticks is refreshed ahead of its expiry on the host's timer (every call
    /// is Ready or Pending(wake); no plugin timer, no plugin thread).
    fn drive(
        &self,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
        driver: Ticket,
        diags: &mut Diags,
    ) -> Driven {
        match Oauth::drive(self, driver, host, diags) {
            Some(at) => Driven::Pending { wake_at_ns: at },
            None => Driven::Ready,
        }
    }

    /// A waiting `fields` is dropped; the mint it waited on completes in the background and fills
    /// the cache.
    fn cancel(&self, ticket: Ticket) -> u32 {
        self.unpark(ticket);
        CANCEL_CONTINUES
    }
}

#[cfg(test)]
mod settings_schema_tests;
