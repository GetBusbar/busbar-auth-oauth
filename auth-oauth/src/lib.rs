// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-oauth — the OAuth self-minting auth styles, one auth-kind plugin

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod instance;
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
const MAX_SCOPE_BYTES: usize = 1024;

/// Why a call whose scope's token exchange failed while it waited is refused.
const EXCHANGE_FAILED: &str = "the RFC 8693 token exchange for this call's scope failed; the call \
     is refused rather than made unauthenticated (see diagnostics BUSBAR-4014/4015/4016)";

/// The flags every field this plugin writes carries: [`FIELD_SENSITIVE`]. The field is the
const FIELD_FLAGS: u32 = FIELD_SENSITIVE;

/// The styles this plugin serves, each at `Head` (a bearer token reads nothing past the head).
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

/// One token endpoint's need: outbound, `provider` (refused a private address unless
const fn token_need(target_from: &'static str) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_PROVIDER,
        transport: abi_str("http"),
        target_from: abi_str(target_from),
        keep_mode: KEEP_NAMED,
        ..Need::EMPTY
    }
}

/// THE PLUGIN'S OWN NEEDS, in `mint::need` order: `oauth-client-credentials` and
pub const NEEDS: &[Need] = &[
    token_need("settings.token_url"),
    token_need("settings.token_uri"),
];

/// The diagnostic ids, in [`instance::diag`] order.
const DIAG_IDS: &[AbiStr] = &[
    abi_str("BUSBAR-4014"),
    abi_str("BUSBAR-4015"),
    abi_str("BUSBAR-4016"),
];

/// What the plugin states: its name, version, the concurrency it serves, its diagnostics, its own
pub const STATEMENT: Statement = with_tail(
    statement("busbar-auth-oauth", env!("CARGO_PKG_VERSION"), 1024)
        .with_diag_ids(DIAG_IDS)
        .with_needs(NEEDS),
    TAIL,
);

busbar_contract::auth_outbound_door!(Oauth, STATEMENT);

/// THE COMPILED-IN ENTRY a composition root's `auths` row names: the door at
pub mod compiled_in {
    /// The door.
    pub mod door {
        pub use crate::door;
    }
}

/// The instance's own settings: the host opens it over a binding's settings, so a JSON object
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
    pub(crate) fn answer(
        &self,
        ask: &Ask<'_>,
        host: Option<&Host>,
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
        host: Option<&Host>,
        present: &mut dyn FnMut(&Cred),
    ) -> Poll<FieldsAnswer> {
        if let Some(a) = m.read(now, |r| ready_answer(r, &mut *present)) {
            self.unpark_mint(ticket);
            return Poll::Ready(a);
        }
        if ticket.is_none() {
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
    fn drive(&self, host: Option<&Host>, driver: Ticket, diags: &mut Diags) -> Driven {
        match Oauth::drive(self, driver, host, diags) {
            Some(at) => Driven::Pending { wake_at_ns: at },
            None => Driven::Ready,
        }
    }

    /// A waiting `fields` is dropped; the mint it waited on completes in the background and fills
    fn cancel(&self, ticket: Ticket) -> u32 {
        self.unpark(ticket);
        CANCEL_CONTINUES
    }
}
