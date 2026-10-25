// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-token-exchange` (RFC 8693; ARCHITECT round 5 Q-L3B-EXCHANGE (B)) over a scripted need,
//! through the instance and the `fields` slot as the trampoline calls it: the exact token request
//! (the previous release's form, field for field), the per-call scope the call's extensions blob
//! states reaching that request, a cached token per scope (two scopes never share one), a failed
//! exchange failing exactly the calls that waited on it, and the binding's refusals.

use crate::held::Own;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_outbound::Diags;
use busbar_contract::conn::{ConnError, ConnId};

use super::*;
use crate::instance::Oauth;
use crate::mint::tests::{Scripted, Step};
use crate::mint::{Got, Wire};
use crate::style;
use crate::test_support::{self, TestHost};

/// The scripted need, shared so the test reads what was sent.
struct Shared(Arc<Scripted>);

impl Wire for Shared {
    fn open(&self, req: &TokenRequest, timeout_ms: u64) -> Result<ConnId, ConnError> {
        self.0.open(req, timeout_ms)
    }
    fn clock(&self) -> Option<crate::mint::HostClock> {
        self.0.clock()
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
}

const SETTINGS: &str =
    r#"{"token_url":"https://as.example/token","resource":"https://tools.example/rpc"}"#;
const SUBJECT: &str = "busbar-own-subject-token";

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

fn instance(wire: &Arc<Scripted>) -> Oauth {
    Oauth::with_wire(1, Some(Box::new(Shared(wire.clone()))))
}

fn open(o: &Oauth) -> u64 {
    let b = style::open(
        style::OAUTH_TOKEN_EXCHANGE,
        Some(SUBJECT.as_bytes()),
        Some(SETTINGS.as_bytes()),
        o,
    )
    .unwrap_or_else(|_| panic!("the binding opens"));
    o.keep_binding(b)
}

/// One `fields` call, its extensions stating `scope` (none: absent), as the kit's door answers it.
fn fields(
    o: &Oauth,
    host: &TestHost,
    handle: u64,
    ticket: Ticket,
    scope: Option<&str>,
) -> (Outcome, String) {
    test_support::fields(o, host, handle, ticket, scope)
}

/// The form a sent body decodes to, in order.
fn form(body: &str) -> Vec<(String, String)> {
    serde_urlencoded::from_str(body).expect("a form")
}

/// THE REQUEST, FIELD FOR FIELD: the previous release's RFC 8693 form in RFC order — the grant,
/// busbar's own subject token and its type, an access token requested back, the RFC 8707 resource,
/// and the scope (present and empty when the call states none) — POSTed as a form to `token_url`
/// over the need that names it.
#[test]
fn the_exchange_request_is_the_previous_releases_form_with_the_stated_scope() {
    let x = Arc::new(build(
        SUBJECT,
        "https://as.example/token",
        ACCESS_TOKEN_TYPE,
        "https://tools.example/rpc",
    ));
    let req = Scoped::new(Arc::clone(&x), "fs_read_file fs_write_file")
        .request()
        .expect("a request");
    assert_eq!(req.need, crate::mint::need::TOKEN_URL);
    assert_eq!(req.target, "https://as.example/token");
    assert_eq!(
        req.fields,
        [
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "*/*"),
        ]
    );
    let expected = |scope: &str| {
        vec![
            ("grant_type".to_string(), GRANT_TYPE.to_string()),
            ("subject_token".to_string(), SUBJECT.to_string()),
            (
                "subject_token_type".to_string(),
                ACCESS_TOKEN_TYPE.to_string(),
            ),
            (
                "requested_token_type".to_string(),
                ACCESS_TOKEN_TYPE.to_string(),
            ),
            (
                "resource".to_string(),
                "https://tools.example/rpc".to_string(),
            ),
            ("scope".to_string(), scope.to_string()),
        ]
    };
    assert_eq!(
        form(req.body.expose_own(&Own::here())),
        expected("fs_read_file fs_write_file")
    );
    let unscoped = Scoped::new(x, "").request().expect("a request");
    assert_eq!(form(unscoped.body.expose_own(&Own::here())), expected(""));
    assert!(
        format!("{req:?}").find(SUBJECT).is_none(),
        "the subject token never prints"
    );
}

/// THE PER-CALL SCOPE, CACHED PER SCOPE: a call stating a scope waits (PENDING on its ticket, a
/// ticket-less call REFUSED) while the exchange it arms asks for exactly that scope; the landed token
/// wakes it and is presented; a second scope is its own exchange and its own token; the first
/// scope's next call is answered from its cache with no exchange at all.
#[test]
fn each_scope_is_its_own_exchange_and_its_own_cached_token() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let (a, b) = (ticket(101), ticket(102));
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE, Some("fs_read_file")).0,
        Outcome::Refused,
        "ticket-less, nothing usable: REFUSED (the host submits it on a ticket)"
    );
    assert_eq!(
        fields(&o, &host, h, a, Some("fs_read_file")).0,
        Outcome::Pending
    );
    w.ok(r#"{"access_token":"tok-read","token_type":"Bearer","expires_in":3600}"#);
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![a], "the landed exchange wakes its call");
    assert_eq!(
        fields(&o, &host, h, a, Some("fs_read_file")),
        (Outcome::Ready, "authorization: Bearer tok-read".to_string())
    );

    assert_eq!(
        fields(&o, &host, h, b, Some("fs_read_file fs_write_file")).0,
        Outcome::Pending,
        "another scope never shares the first's token"
    );
    w.ok(r#"{"access_token":"tok-both","expires_in":3600}"#);
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![b]);
    assert_eq!(
        fields(&o, &host, h, b, Some("fs_read_file fs_write_file")).1,
        "authorization: Bearer tok-both"
    );
    // The first scope again, on the spot: its cached token, no exchange.
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE, Some("fs_read_file")).1,
        "authorization: Bearer tok-read"
    );
    o.tick(3_000, Ticket::NONE, Some(&host.host), &mut diags);
    let sent = w.sent.lock().unwrap();
    let scopes: Vec<String> = sent
        .iter()
        .map(|(_, _, body)| {
            form(body)
                .into_iter()
                .find(|(k, _)| k == "scope")
                .map(|(_, v)| v)
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(scopes, ["fs_read_file", "fs_read_file fs_write_file"]);
}

/// EVERY REFUSAL IS EXPLAINED: the call a failed exchange refuses carries non-empty text (the SDK
/// passes it as the attempt's failure text), not an empty string.
#[test]
fn a_call_refused_for_a_failed_exchange_carries_an_explanation() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let call = ticket(211);
    assert_eq!(fields(&o, &host, h, call, Some("s")).0, Outcome::Pending);
    w.push(vec![
        Step::Head(401),
        Step::Body(b"{\"error\":\"invalid_grant\"}".to_vec(), true),
    ]);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    let ask = crate::Ask {
        handle: h,
        own: true,
        scope: Some(b"s".as_slice()),
        ticket: call,
        timestamp: 0,
    };
    match o.answer(&ask, Some(&host.host), &mut |_| {}) {
        std::task::Poll::Ready(busbar_contract::abi::sdk::auth_outbound::FieldsAnswer::Failed(
            text,
        )) => assert!(!text.is_empty(), "the refusal is explained"),
        _ => panic!("the call is refused as failed"),
    }
}

/// TWO BINDINGS NEVER SHARE A SCOPE'S TOKEN: two bindings on ONE instance that differ only in the
/// subject token (the credential) each ask the same scope, and each gets its own exchange, carrying
/// its own subject token, and its own token. A shared cell would present one binding's token to
/// the other.
#[test]
fn two_bindings_on_one_instance_never_share_a_scopes_token() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h1 = open(&o);
    let b2 = style::open(
        style::OAUTH_TOKEN_EXCHANGE,
        Some(b"another-subject-token".as_slice()),
        Some(SETTINGS.as_bytes()),
        &o,
    )
    .unwrap_or_else(|_| panic!("the second binding opens"));
    let h2 = o.keep_binding(b2);
    let (a, b) = (ticket(201), ticket(202));
    let mut diags = Diags::default();

    assert_eq!(fields(&o, &host, h1, a, Some("s")).0, Outcome::Pending);
    w.ok(r#"{"access_token":"tok-one","expires_in":3600}"#);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![a]);
    assert_eq!(
        fields(&o, &host, h1, a, Some("s")).1,
        "authorization: Bearer tok-one"
    );

    assert_eq!(
        fields(&o, &host, h2, b, Some("s")).0,
        Outcome::Pending,
        "the other binding, same scope: its own exchange, not the first's cached token"
    );
    w.ok(r#"{"access_token":"tok-two","expires_in":3600}"#);
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![b]);
    assert_eq!(
        fields(&o, &host, h2, b, Some("s")).1,
        "authorization: Bearer tok-two"
    );
    assert_eq!(
        fields(&o, &host, h1, Ticket::NONE, Some("s")).1,
        "authorization: Bearer tok-one"
    );
    let subjects: Vec<String> = w
        .sent
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, body)| {
            form(body)
                .into_iter()
                .find(|(k, _)| k == "subject_token")
                .map(|(_, v)| v)
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(subjects, [SUBJECT, "another-subject-token"]);
}

/// A FAILED EXCHANGE FAILS ITS CALLS: the authorization server's refusal wakes every call that
/// waited on it, and each answers FAILED (the attempt fails; nothing unauthenticated is sent), the
/// instance's log naming why; the scope's next call arms a fresh exchange rather than inheriting
/// the failure.
#[test]
fn a_refused_exchange_fails_the_calls_that_waited_and_the_next_call_asks_again() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let (first, second, later) = (ticket(201), ticket(202), ticket(203));
    assert_eq!(fields(&o, &host, h, first, Some("s")).0, Outcome::Pending);
    assert_eq!(fields(&o, &host, h, second, Some("s")).0, Outcome::Pending);
    w.push(vec![
        Step::Head(401),
        Step::Body(b"{\"error\":\"invalid_grant\"}".to_vec(), true),
    ]);
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    let mut both = host.take();
    both.sort_by_key(|t| t.slot);
    assert_eq!(both, vec![first, second]);
    assert_eq!(fields(&o, &host, h, first, Some("s")).0, Outcome::Failed);
    assert_eq!(fields(&o, &host, h, second, Some("s")).0, Outcome::Failed);
    assert!(
        diags
            .iter()
            .any(|(id, _, _)| id == crate::instance::diag::OAUTH_MINT_FAILED),
        "the failure is logged"
    );
    // The next call is not failed by the last one: it arms a fresh exchange.
    assert_eq!(fields(&o, &host, h, later, Some("s")).0, Outcome::Pending);
    w.ok(r#"{"access_token":"tok-s","expires_in":3600}"#);
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![later]);
    assert_eq!(
        fields(&o, &host, h, later, Some("s")).1,
        "authorization: Bearer tok-s"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 2);
}

/// THE REFUSALS: busbar's own subject token is the credential (none, or a blank one, refuses),
/// `token_url` and the RFC 8707 `resource` are required; every finding is one `settings:` line.
#[test]
fn the_binding_refuses_without_its_subject_token_token_url_or_resource() {
    let o = Oauth::with_wire(1, None);
    let lines = |cred: Option<&str>, settings: &str| -> Vec<String> {
        match style::open(
            style::OAUTH_TOKEN_EXCHANGE,
            cred.map(str::as_bytes),
            Some(settings.as_bytes()),
            &o,
        ) {
            Ok(_) => panic!("the binding is refused"),
            Err(r) => r.iter().map(style::Refusal::line).collect(),
        }
    };
    assert_eq!(
        lines(None, "{}"),
        [
            "settings: uses auth: oauth-token-exchange but declares no credential; that grant \
             exchanges busbar's own subject token (the credential) for the upstream's, so there \
             is nothing to exchange",
            "settings: uses auth: oauth-token-exchange but has no `token_url` (the authorization \
             server's token endpoint busbar's subject token is exchanged at)",
            "settings: uses auth: oauth-token-exchange but has no `resource` — the RFC 8707 \
             resource indicator the exchanged token is audience-bound to. A token minted for one \
             upstream must not be spendable at another.",
        ]
    );
    assert_eq!(
        lines(Some("  "), SETTINGS).len(),
        1,
        "a blank subject token is none"
    );
    assert_eq!(
        lines(Some(SUBJECT), r#"{"token_url":"https://as.example/token"}"#).len(),
        1,
        "no resource"
    );
}

/// A RETIRE KEEPS AN EXCHANGE SOMEONE WAITS ON (contract `abi/auth`: the token cache outlives a
/// handle; THE DESIGN A.4.7, zero lost wakes). The generation that opened the binding retires while
/// a call is parked on its scope's exchange: the cell stays, the exchange lands on the next tick and
/// wakes that call. RED before the fix: `retire` dropped every cell no handle held, an on-demand
/// cell is held by none, so the waiter was never woken.
#[test]
fn a_retire_keeps_the_exchange_a_parked_call_waits_on() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let a = ticket(301);
    assert_eq!(
        fields(&o, &host, h, a, Some("fs_read_file")).0,
        Outcome::Pending
    );
    o.retire(1);
    w.ok(r#"{"access_token":"tok-kept","token_type":"Bearer","expires_in":3600}"#);
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(
        host.take(),
        vec![a],
        "the retired generation's parked call is woken when its exchange lands"
    );
}

/// AN UN-ENCODABLE EXCHANGED TOKEN FAILS ITS CALLS, as an empty one does (Q128 auth-oauth LOW): a
/// token with bytes invalid in a header value cannot be presented, and a call that waited on its
/// exchange must not go out unauthenticated. Each waiting call answers FAILED, the log names the
/// token, and the scope's next call arms a fresh exchange instead of being sent with no auth field.
/// RED before the fix: the calls answered READY with no field.
#[test]
fn an_exchanged_token_with_invalid_header_bytes_fails_the_calls_that_waited() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let (first, later) = (ticket(211), ticket(212));
    assert_eq!(fields(&o, &host, h, first, Some("s")).0, Outcome::Pending);
    w.ok("{\"access_token\":\"tok\\u0001bad\",\"expires_in\":3600}");
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![first]);
    assert_eq!(
        fields(&o, &host, h, first, Some("s")),
        (Outcome::Failed, String::new()),
        "the waiting call fails rather than going out with no auth"
    );
    assert!(
        diags
            .iter()
            .any(|(id, _, _)| id == crate::instance::diag::OAUTH_TOKEN_INVALID_BYTES),
        "the un-encodable token is logged"
    );
    assert_eq!(
        fields(&o, &host, h, later, Some("s")).0,
        Outcome::Pending,
        "the next call arms a fresh exchange; the un-encodable token is not served"
    );
}
