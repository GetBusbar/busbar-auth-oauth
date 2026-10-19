// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-oauth — the OAuth self-minting auth styles, one auth-kind plugin
//!
//! BUSBAR-1.6.0.md THE DESIGN, §6 (OWNER-LOCKED 2026-09-27, split by mechanism per ARCHITECT ruling 2026-09-29):
//! `jwt-bearer` (RFC 7523) and `oauth-client-credentials` (RFC 6749 §4.4) are ONE mechanism —
//! each obtains a short-lived bearer from a token endpoint and presents it as
//! `authorization: Bearer <token>`, differing only in the token request — and live in one plugin,
//! `busbar-auth-oauth`, loaded when some provider uses one of them. It speaks the auth kind's
//! memory ABI (`busbar_contract::abi::auth`, v3):
//!
//! * `open_outbound` binds one style to its credential and settings and answers a handle
//!   (generation data). It never touches the network.
//! * `fields` is called by the binding's transport at the style's auth point (`Head`, THE DESIGN
//!   §6 "Auth points and guest lists"): the auth fields for this request, staged into the SDK's
//!   writer, which the transport adds to the head before it encodes it.
//!   Neither style serves the caller's credential — an OAuth token is always minted from the
//!   OPERATOR's own configured credential, never a per-request one — so neither style declares
//!   [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`] (ARCHITECT ruling 2026-09-29).
//! * `outbound_ready` is the handle's `ready` fact for the health prober.
//! * `tick` refreshes minted tokens ahead of expiry.
//!
//! `oauth-token-exchange` (RFC 8693; ARCHITECT round 5 Q-L3B-EXCHANGE (B), BUSBAR-1.6.0.md B.3 item
//! 12) is the same mechanism minted ON DEMAND: its credential is busbar's own subject token, its
//! settings `{token_url, resource, subject_token_type?}`, and the scope each exchange asks for is
//! the per-call down-scope the request states in `fields`' extensions blob
//! (`busbar_contract::abi::auth::EXT_SCOPE`). Each scope is its own exchange and its own cached token;
//! a request that finds none usable waits (PENDING on its ticket) while the exchange runs on the
//! instance's driver ticket, and fails (FAILED) when the exchange does.
//!
//! EACH STYLE MINTS THROUGH THE PLUGIN'S OWN NEED and refreshes ahead of expiry on `tick`
//! ([`mint`]). The kernel holds no auth cache and does no per-plugin branching.
//!
//! THE DOOR is the SDK's safe outbound-auth kit (`busbar_contract::abi::sdk::auth_outbound`,
//! `auth_outbound_door!`): [`Oauth`](instance::Oauth) is its [`OutboundPlugin`], and the crate
//! holds no `unsafe` (THE DESIGN §2: an auth plugin is `#![forbid(unsafe_code)]`). The inbound
//! operations (`verify`, the login pair) are not served and answer REFUSED (the tail declares only
//! the outbound capability).
//!
//! THE NEEDS ([`NEEDS`]; THE DESIGN §5, egress class `operator-infrastructure`, as ARCHITECT ruled
//! for D1 2026-10-05 (1.5.5 minted over plaintext to a private or loopback endpoint; the ONE
//! destination guard still applies on top): "auth mint endpoints (`token_url`,
//! `token_uri`)"): one outbound need per token endpoint, over the http transport, its target the
//! binding's own setting (`target_from`), so the host declares it pinned to that endpoint when it
//! opens the instance with the binding's settings. The token exchange is ONE framed request and its
//! reply over that need, through the host's connector table (`mint::host_wire`), on the instance's
//! driver ticket: started on `tick`, or at once when a binding opens or a request waits on a token
//! (the driver ticket is woken and `drive` starts it), and carried on by the `drive`s its pending
//! reads wake.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod held;
mod instance;
mod mint;
mod style;
mod token_response;

#[cfg(test)]
#[path = "tests/support.rs"]
mod test_support;

use std::borrow::Cow;
use std::ptr;
use std::task::Poll;

use busbar_contract::abi::auth::{AuthPoints, AuthTail, StyleDecl, CANCEL_CONTINUES};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::auth_outbound::{
    outbound_tail, style as style_decl, Diags, Driven, FieldsAnswer, FieldsView, FieldsWriter,
    Mode, OpenRefusal, OutboundPlugin,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::Refusal;

use crate::instance::Oauth;
use crate::mint::Read;

/// The flags every field this plugin writes carries: NONE. 1.5.5 sent its credential headers
/// indexable, and an h2 encoder that honoured `FIELD_SENSITIVE` would send them never-indexed —
/// different bytes (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win; TODO item 583's
/// sensitive marking is a behaviour change not taken without the owner).
const FIELD_FLAGS: u32 = 0;

/// The styles this plugin serves, each at `Head` (a bearer token reads nothing past the head).
/// None carries [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`] (an OAuth token is always
/// minted from the operator's own credential).
const STYLES: &[StyleDecl] = &[
    style_decl(style::JWT_BEARER, 0, AuthPoints::HEAD),
    style_decl(style::OAUTH_CLIENT_CREDENTIALS, 0, AuthPoints::HEAD),
    style_decl(style::OAUTH_TOKEN_EXCHANGE, 0, AuthPoints::HEAD),
];

/// THE AUTH STATEMENT TAIL: outbound only, no login, no inbound carriers.
const TAIL: &AuthTail = &outbound_tail(0, STYLES);

const NO_STR: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
    ..AbiStr::ZERO
};

/// One token endpoint's need: outbound, `operator-infrastructure`, over the http transport, its target the
/// binding's setting `target_from` names. It reads no response field beyond the reply's code.
const fn token_need(target_from: &'static str) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
        transport: abi_str("http"),
        auth: NO_STR,
        target_from: abi_str(target_from),
        trust_from: NO_STR,
        details: Blob {
            ptr: ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
            ..Blob::ZERO
        },
        keep_response_headers: ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: ptr::null(),
        deny_response_headers_len: 0,
        ..Need::ZERO
    }
}

/// THE PLUGIN'S OWN NEEDS, in [`mint::need`] order: `oauth-client-credentials` POSTs to the
/// binding's `token_url`, `jwt-bearer` to its `token_uri`.
pub const NEEDS: &[Need] = &[
    token_need("settings.token_url"),
    token_need("settings.token_uri"),
];

/// The diagnostic ids, in [`instance::diag`] order: 1.5.5's catalog codes where the line had one.
const DIAG_IDS: &[AbiStr] = &[
    abi_str("BUSBAR-4014"),
    abi_str("BUSBAR-4015"),
    abi_str("BUSBAR-4016"),
];

/// What the plugin states: its name, version, the concurrency it serves, its diagnostics, its own
/// needs and its outbound styles.
pub const STATEMENT: Statement = with_tail(
    Statement {
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        ..statement("busbar-auth-oauth", env!("CARGO_PKG_VERSION"), 1024)
    },
    TAIL,
);

busbar_contract::auth_outbound_door!(Oauth, STATEMENT);

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

/// The plugin's own settings: none are read; present settings must be a JSON object.
fn settings_ok(b: &[u8]) -> bool {
    b.is_empty()
        || matches!(
            serde_json::from_slice::<serde_json::Value>(b),
            Ok(serde_json::Value::Object(_))
        )
}

const SETTINGS_NOT_OBJECT: &str = "busbar-auth-oauth settings must be a JSON object";

fn judged(settings: &[u8]) -> Result<(), Refusal> {
    if settings_ok(settings) {
        Ok(())
    } else {
        Err(Refusal::refused(SETTINGS_NOT_OBJECT))
    }
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
fn ready_answer(r: Read<'_>, present: &mut dyn FnMut(&str)) -> Option<FieldsAnswer> {
    match r {
        Read::Header(h) => {
            present(h);
            Some(FieldsAnswer::Ready)
        }
        Read::Nothing => Some(FieldsAnswer::Ready),
        Read::Wait => None,
    }
}

impl Oauth {
    /// THE ANSWER TO ONE `fields`: the cached bearer, handed to `present` (READY with it); no field
    /// (READY with none, an un-encodable token); PENDING on a ticket while the call waits for a
    /// token (an expired one whose refresh failed, or a token exchange in flight), woken when one
    /// lands; REFUSED for a passthrough or a handle this generation does not hold; FAILED when the
    /// call's exchange failed.
    ///
    /// NO LOST WAKE: a call that would wait parks its ticket BEFORE it reads the token, and reads
    /// again once parked. A mint stores its token before it wakes the parked tickets, so the call
    /// either is parked in time to be woken, or reads the token the mint stored.
    pub(crate) fn answer(
        &self,
        ask: &Ask<'_>,
        host: Option<&Host>,
        present: &mut dyn FnMut(&str),
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
            return Poll::Ready(FieldsAnswer::Failed(Cow::Borrowed("")));
        }
        let scope = ask.scope.unwrap_or_default();
        let key = x.scope_key(scope);
        // The lookup and the park are one critical section with the cache (instance.rs).
        let cell = self.exchange_cell(key, || x.minter(scope), ticket, |c| c.usable(now));
        cell.read(now, |r| match r {
            Read::Header(h) => {
                self.unpark_exchange(key, ticket);
                present(h);
                Poll::Ready(FieldsAnswer::Ready)
            }
            Read::Nothing => {
                self.unpark_exchange(key, ticket);
                Poll::Ready(FieldsAnswer::Ready)
            }
            Read::Wait => {
                self.mint_soon(host);
                Poll::Pending
            }
        })
    }

    /// A minted style's answer: the read, and on a wait the park and the second read.
    fn minted(
        &self,
        m: &mint::Minted,
        ticket: Ticket,
        now: u64,
        host: Option<&Host>,
        present: &mut dyn FnMut(&str),
    ) -> Poll<FieldsAnswer> {
        if let Some(a) = m.read(now, |r| ready_answer(r, &mut *present)) {
            return Poll::Ready(a);
        }
        if ticket.is_none() {
            // On the spot the call cannot wait: the kit answers REFUSED and the host submits it on
            // a ticket.
            return Poll::Pending;
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
            // A token exchange is ready whenever asked: each request's exchange is its own.
            Some(style::Binding::Exchange(_)) => true,
            None => false,
        }
    }

    /// `open_outbound`'s body: bind a style; a refusal carries one `credential: …` /
    /// `settings: …` line per finding (ARCHITECT ruling 2026-09-28).
    pub(crate) fn bind(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        host: Option<&Host>,
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
            // A token exchange mints nothing at open: each request's scope is its own exchange.
            Ok(binding) => Ok(self.keep_binding(binding)),
            Err(refusals) => {
                let mut lines = refusals.iter().map(style::Refusal::line);
                let first = lines.next().unwrap_or_default();
                Err(lines.fold(OpenRefusal::new(first), |r, l| r.and(l)))
            }
        }
    }
}

impl OutboundPlugin for Oauth {
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        judged(settings)
    }

    fn open(settings: &[u8], _secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        judged(settings)?;
        Ok(Oauth::new(generation))
    }

    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        host: Option<&Host>,
        _diags: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        self.bind(style, credential, settings, host)
    }

    fn fields(
        &self,
        request: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        op: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        let ask = Ask {
            handle: request.handle(),
            own: request.mode() == Mode::Own,
            scope: request.scope(),
            ticket: op.ticket(),
            timestamp: request.timestamp(),
        };
        self.answer(&ask, op.host(), &mut |h| {
            out.push(b"authorization", h.as_bytes(), FIELD_FLAGS);
        })
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

    fn tick(&self, now_ns: u64, host: Option<&Host>, driver: Ticket, diags: &mut Diags) -> u64 {
        Oauth::tick(self, now_ns, driver, host, diags)
    }

    /// The driver ticket was woken (a read of the token exchange that pended, or a mint wanted at
    /// once): the exchange goes on. PENDING with `wake_at_ns` at the instant a cell is next due, so
    /// a token minted between ticks is refreshed ahead of its expiry on the host's timer (THE
    /// DESIGN §11: every call is Ready or Pending(wake); no plugin timer, no plugin thread).
    fn drive(&self, host: Option<&Host>, driver: Ticket, diags: &mut Diags) -> Driven {
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
