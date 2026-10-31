// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-token-exchange` (RFC 8693; ARCHITECT round 5 Q-L3B-EXCHANGE (B)) over a scripted need,
//! through the instance and the `fields` slot as the trampoline calls it: the exact token request
//! (the previous release's form, field for field), the per-call scope the call's extensions blob
//! states reaching that request, a cached token per scope (two scopes never share one), a failed
//! exchange failing exactly the calls that waited on it, and the binding's refusals.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_outbound::Diags;
use busbar_contract::conn::{ConnError, ConnId};

use super::*;
use crate::instance::Oauth;
use crate::mint::tests::{now_epoch, Scripted, Step};
use crate::mint::{Got, Wire};
use crate::style;
use crate::test_support::{self, TestHost};
use busbar_contract::abi::sdk::cred::SealedWrite;

/// The scripted need, shared so the test reads what was sent.
struct Shared(Arc<Scripted>);

impl Wire for Shared {
    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.0.open(req, body, timeout_ms)
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
/// and the scope (absent when the call states none, L6) — POSTed as a form to `token_url` over
/// the need that names it.
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
        let mut pairs = vec![
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
        ];
        if !scope.is_empty() {
            pairs.push(("scope".to_string(), scope.to_string()));
        }
        pairs
    };
    assert_eq!(
        form(&crate::test_support::form_text(&req.body)),
        expected("fs_read_file fs_write_file")
    );
    let unscoped = Scoped::new(x, "").request().expect("a request");
    assert_eq!(
        form(&crate::test_support::form_text(&unscoped.body)),
        expected("")
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
/// instance's log naming why; the scope's next call after the failure's back-off window (O3) arms
/// a fresh exchange rather than inheriting the failure.
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
    // The next call after the back-off window is not failed by the last one: it arms a fresh
    // exchange.
    assert_eq!(
        test_support::fields_at(&o, &host, h, later, Some("s"), now_epoch() + 31).0,
        Outcome::Pending
    );
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
        test_support::fields_at(&o, &host, h, later, Some("s"), now_epoch() + 31).0,
        Outcome::Pending,
        "the next call after the back-off window arms a fresh exchange; the un-encodable token \
         is not served"
    );
}

/// THE `ready` FACT FOLLOWS THE EXCHANGES (Q128 auth-oauth reader A, LOW; contract
/// `abi/auth/outbound.rs` `OutboundReadyOut::ready`: "`1` = `fields` would answer with a credential
/// now"): a token-exchange binding whose last settled exchange FAILED is not ready (its authorization
/// server is refusing, so `fields` would fail), and is ready again once an exchange lands. RED: the
/// binding read ready whatever its authorization server answered.
#[test]
fn a_token_exchange_binding_is_not_ready_while_its_last_exchange_failed() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    assert_eq!(
        fields(&o, &host, h, ticket(301), Some("s")).0,
        Outcome::Pending
    );
    w.push(vec![
        Step::Head(401),
        Step::Body(b"{\"error\":\"invalid_grant\"}".to_vec(), true),
    ]);
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(
        fields(&o, &host, h, ticket(301), Some("s")).0,
        Outcome::Failed,
        "positive control: the exchange failed"
    );
    assert!(!o.ready(h), "its last exchange failed: not ready");
    assert_eq!(
        test_support::fields_at(&o, &host, h, ticket(302), Some("s"), now_epoch() + 31).0,
        Outcome::Pending,
        "after the back-off window a request arms a fresh exchange"
    );
    w.ok(r#"{"access_token":"tok-s","expires_in":3600}"#);
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert!(o.ready(h), "an exchange landed: ready again");
}

/// A NEVER-USED EXCHANGE LANE IS TRIED ON ITS FIRST REQUEST: before any request the binding reads
/// ready, so the prober and the router try it, and that first request starts its first exchange.
/// A reading of "not ready until minted" would keep it untried forever (it mints only when asked).
#[test]
fn a_never_used_exchange_lane_is_tried_on_its_first_request() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    assert!(o.ready(h), "never used: ready, so it is tried");
    assert!(w.sent.lock().unwrap().is_empty(), "nothing minted yet");
    assert_eq!(
        fields(&o, &host, h, ticket(401), Some("s")).0,
        Outcome::Pending
    );
    w.ok(r#"{"access_token":"tok-first","expires_in":3600}"#);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        w.sent.lock().unwrap().len(),
        1,
        "the first request's exchange went out"
    );
    assert_eq!(
        fields(&o, &host, h, ticket(401), Some("s")).1,
        "authorization: Bearer tok-first"
    );
}

/// The scripted need on a host whose wall clock (epoch seconds) the test sets.
struct Clocked(Arc<Scripted>, Arc<std::sync::atomic::AtomicU64>);

impl Wire for Clocked {
    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.0.open(req, body, timeout_ms)
    }
    fn clock(&self) -> Option<crate::mint::HostClock> {
        Some(crate::mint::HostClock {
            wall_secs: self.1.load(std::sync::atomic::Ordering::Acquire),
            mono_ns: 0,
        })
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
}

/// A plausible host wall clock the clocked tests start at (2027-01-15).
const T0: u64 = 1_800_000_000;

/// A token-exchange binding on an instance whose host clock the test moves: the instance, the
/// handle, the scripted need and the clock.
struct ClockedBinding {
    o: Oauth,
    h: u64,
    w: Arc<Scripted>,
    wall: Arc<std::sync::atomic::AtomicU64>,
    host: TestHost,
}

impl ClockedBinding {
    fn new() -> Self {
        let w = Arc::new(Scripted::default());
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(T0));
        let o = Oauth::with_wire(1, Some(Box::new(Clocked(w.clone(), wall.clone()))));
        let h = open(&o);
        Self {
            o,
            h,
            w,
            wall,
            host: TestHost::new(),
        }
    }

    /// One `fields` for `scope` on `t` at host wall time `at` (the host's clock moved there too).
    fn call(&self, t: Ticket, scope: &str, at: u64) -> Outcome {
        self.wall.store(at, std::sync::atomic::Ordering::Release);
        test_support::fields_at(&self.o, &self.host, self.h, t, Some(scope), at).0
    }

    /// A tick at host wall time `at`.
    fn tick(&self, at: u64) {
        self.wall.store(at, std::sync::atomic::Ordering::Release);
        self.o.tick(
            at.saturating_mul(1_000_000_000),
            Ticket::NONE,
            Some(&self.host.host),
            &mut Diags::default(),
        );
    }

    /// How many token requests went out.
    fn sent(&self) -> usize {
        self.w.sent.lock().unwrap().len()
    }
}

/// O3, A FAILED EXCHANGE BACKS OFF (RFC 6585 §4, RFC 9110 §10.2.3): a scope whose exchange failed
/// keeps its cell for a negative-cache window, 30 s (the other styles' retry interval), and every
/// request for that scope in the window FAILS at once with the cached reason, sending nothing; the
/// first request after the window arms a fresh exchange. RED: the failed cell was dropped and the
/// next request re-hit the authorization server at request rate.
#[test]
fn a_failed_exchange_backs_off_for_its_window_and_fails_fast_meanwhile() {
    let b = ClockedBinding::new();
    assert_eq!(b.call(ticket(501), "s", T0), Outcome::Pending);
    b.w.push(vec![Step::Head(503), Step::Body(b"busy".to_vec(), true)]);
    b.tick(T0);
    assert_eq!(b.sent(), 1);
    assert_eq!(
        b.call(ticket(501), "s", T0),
        Outcome::Failed,
        "the waiter fails"
    );
    for at in [T0 + 1, T0 + 29] {
        assert_eq!(
            b.call(ticket(502), "s", at),
            Outcome::Failed,
            "inside the window the scope fails fast ({at})"
        );
        b.tick(at);
        assert_eq!(
            b.sent(),
            1,
            "nothing re-hits the authorization server ({at})"
        );
    }
    assert_eq!(
        b.call(ticket(503), "s", T0 + 31),
        Outcome::Pending,
        "after the window a request arms a fresh exchange"
    );
    b.w.ok(r#"{"access_token":"tok-s","expires_in":3600}"#);
    b.tick(T0 + 31);
    assert_eq!(b.sent(), 2);
    assert_eq!(
        test_support::fields_at(&b.o, &b.host, b.h, ticket(503), Some("s"), T0 + 31).1,
        "authorization: Bearer tok-s"
    );
}

/// O3, THE AUTHORIZATION SERVER'S `Retry-After` IS HONOURED, capped at 300 s: in seconds or as an
/// HTTP-date, it sets the window instead of the default 30 s. RED: no window at all.
#[test]
fn a_failed_exchange_honours_retry_after_capped_at_300_seconds() {
    // (retry-after, still failing at, retried at)
    let date = "Fri, 15 Jan 2027 08:03:20 GMT"; // T0 + 200
    for (value, failing_at, retried_at) in [
        ("120", T0 + 100, T0 + 121),
        ("100000", T0 + 299, T0 + 301),
        (date, T0 + 150, T0 + 201),
    ] {
        let b = ClockedBinding::new();
        assert_eq!(b.call(ticket(601), "s", T0), Outcome::Pending);
        b.w.push(vec![
            Step::HeadRetryAfter(429, value),
            Step::Body(b"slow down".to_vec(), true),
        ]);
        b.tick(T0);
        assert_eq!(
            b.call(ticket(602), "s", failing_at),
            Outcome::Failed,
            "retry-after {value}: still backing off at {failing_at}"
        );
        assert_eq!(
            b.call(ticket(603), "s", retried_at),
            Outcome::Pending,
            "retry-after {value}: retried at {retried_at}"
        );
    }
}

/// O2, THE `ready` FACT IS PER SCOPE: one scope's failure does not make a binding whose other
/// scope presents a token unready (no last-writer-wins across scopes), and a binding whose only
/// tried scope failed is ready again once that scope's back-off window ends, with no request in
/// between (exchanges start only on requests, so a latched `0` would never be tried again). RED:
/// one binding-wide flag, set by whichever scope settled last, cleared only by a landed exchange.
#[test]
fn a_token_exchange_binding_is_ready_unless_every_tried_scope_is_failing() {
    let b = ClockedBinding::new();
    assert_eq!(b.call(ticket(701), "good", T0), Outcome::Pending);
    b.w.ok(r#"{"access_token":"tok-good","expires_in":3600}"#);
    b.tick(T0);
    assert_eq!(b.call(ticket(702), "bad", T0), Outcome::Pending);
    b.w.push(vec![
        Step::Head(401),
        Step::Body(br#"{"error":"invalid_scope"}"#.to_vec(), true),
    ]);
    b.tick(T0);
    assert_eq!(
        b.call(ticket(702), "bad", T0),
        Outcome::Failed,
        "positive control: the second scope's exchange failed"
    );
    assert!(
        b.o.ready(b.h),
        "the first scope still presents its token: the binding is ready"
    );

    let b = ClockedBinding::new();
    assert_eq!(b.call(ticket(711), "s", T0), Outcome::Pending);
    b.w.push(vec![Step::Head(503), Step::Body(b"busy".to_vec(), true)]);
    b.tick(T0);
    assert!(
        !b.o.ready(b.h),
        "its only tried scope is failing: not ready"
    );
    b.tick(T0 + 31);
    assert!(
        b.o.ready(b.h),
        "the scope's back-off ended: ready again, so the lane is tried and a request retries"
    );
    assert_eq!(b.sent(), 1, "readiness came back without an exchange");
}

/// O6, THE ISSUED TOKEN TYPE IS CHECKED (RFC 8693 §2.2.1): an exchange whose `issued_token_type`
/// is stated and is neither an access token nor a JWT (`urn:ietf:params:oauth:token-type:
/// access_token` / `:jwt`), or whose `token_type` is `N_A` (no bearer at all), fails the calls
/// that waited on it, its diagnostic naming why; an access token or a JWT is presented. RED: the
/// reply's types were never read, so a refresh token was presented as a bearer.
#[test]
fn an_exchange_issuing_no_access_token_fails_its_calls() {
    for (body, presented, named) in [
        (
            r#"{"access_token":"t","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token"}"#,
            false,
            "issued_token_type",
        ),
        (
            r#"{"access_token":"t","token_type":"N_A","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}"#,
            false,
            "N_A",
        ),
        (
            r#"{"access_token":"t","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:jwt"}"#,
            true,
            "",
        ),
        (
            r#"{"access_token":"t","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}"#,
            true,
            "",
        ),
    ] {
        let host = TestHost::new();
        let w = Arc::new(Scripted::default());
        let o = instance(&w);
        let h = open(&o);
        assert_eq!(
            fields(&o, &host, h, ticket(801), Some("s")).0,
            Outcome::Pending
        );
        w.ok(body);
        let mut diags = Diags::default();
        o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
        let (outcome, written) = fields(&o, &host, h, ticket(801), Some("s"));
        if presented {
            assert_eq!(
                (outcome, written.as_str()),
                (Outcome::Ready, "authorization: Bearer t"),
                "{body}"
            );
        } else {
            assert_eq!(outcome, Outcome::Failed, "{body}");
            assert!(
                diags.iter().any(
                    |(id, _, text)| id == crate::instance::diag::OAUTH_MINT_FAILED
                        && text.contains(named)
                ),
                "{body}: the diagnostic names {named}"
            );
        }
    }
}

/// L2, A RELOAD KEEPS THE SCOPE TOKENS OF A BINDING THAT SURVIVES IT (contract `abi/auth`: the
/// token cache is keyed by style, credential and settings, never by handle): the new generation
/// re-opens the same binding, the old one retires, and the scope's cached token is presented with
/// no new exchange; the binding's readiness reads that scope too. RED: `retire` dropped every idle
/// scope cell, so each scope re-exchanged after every reload.
#[test]
fn a_reload_keeps_the_scope_tokens_of_a_binding_that_survives_it() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h1 = open(&o);
    assert_eq!(
        fields(&o, &host, h1, ticket(901), Some("s")).0,
        Outcome::Pending
    );
    w.ok(r#"{"access_token":"tok-kept","token_type":"Bearer","expires_in":3600}"#);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    o.set_generation(2);
    let h2 = open(&o);
    o.retire(1);
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        fields(&o, &host, h2, ticket(902), Some("s")),
        (Outcome::Ready, "authorization: Bearer tok-kept".to_string()),
        "the surviving binding's scope token is presented"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 1, "no new exchange");
    assert!(o.ready(h2));
}

/// L6: A CALL THAT STATES NO SCOPE SENDS NO `scope` (RFC 8693 §2.1: OPTIONAL; RFC 6749 §3.3: a
/// scope is at least one character, so `scope=` is malformed): the form ends at `resource`. RED:
/// `scope=` went out empty.
#[test]
fn an_unscoped_exchange_sends_no_scope_parameter() {
    let x = Arc::new(build(
        SUBJECT,
        "https://as.example/token",
        ACCESS_TOKEN_TYPE,
        "https://tools.example/rpc",
    ));
    let form = form(&crate::test_support::form_text(
        &Scoped::new(x, "").request().expect("a request").body,
    ));
    assert_eq!(
        form.last().map(|(k, _)| k.as_str()),
        Some("resource"),
        "{form:?}"
    );
    assert!(form.iter().all(|(k, _)| k != "scope"), "{form:?}");
}
