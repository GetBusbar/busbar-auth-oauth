// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MINT THROUGH THE INSTANCE AND THE `fields` SLOT (BUSBAR-1.6.0.md THE DESIGN, §6.5: jwt-bearer and
//! oauth-client-credentials "mint through the plugin's own `operator-infrastructure` need and refresh ahead of
//! expiry in the background on `tick`"), over a scripted need: the request the plugin sends, the
//! first mint on the first tick, the per-request call presenting the minted bearer, and THE
//! EXPIRED-TOKEN RULE end to end — an expired token whose refresh failed answers PENDING on a
//! ticket bounded by the attempt's deadline, the next landed mint WAKES that ticket, and the resumed
//! call presents the new token.
//!
//! The need is a [`Wire`] double, not the host's connector table (the twin's conformance test
//! mints over the loader and a connection table). With
//! `AUTH_OUT_CAPTURE_DIR` set, each request the plugin sent is written out for the 1.5.5 wire-bytes
//! comparison through the framer door (whose defaults, `accept: */*` included, are the framer's —
//! never this plugin's or the kernel's).

use super::*;
use crate::mint;
use crate::mint::tests::{Scripted, Step};
use crate::mint::TokenRequest;
use crate::style;
use crate::test_support::{self, TestHost};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::conn::{ConnError, ConnId};

/// The scripted need, shared so the test reads what was sent.
struct Shared(Arc<Scripted>);

impl Wire for Shared {
    fn open(&self, req: &TokenRequest, timeout_ms: u64) -> Result<ConnId, ConnError> {
        self.0.open(req, timeout_ms)
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<mint::Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
}

fn instance(wire: &Arc<Scripted>) -> Oauth {
    Oauth::with_wire(1, Some(Box::new(Shared(wire.clone()))))
}

fn open(o: &Oauth, style: &str, cred: &str, settings: &str) -> u64 {
    let cell = style::open_binding(style, Some(cred.as_bytes()), Some(settings.as_bytes()), o)
        .expect("the binding opens");
    o.keep(cell)
}

/// One `fields` call, as the kit's door answers it.
fn fields(o: &Oauth, host: &TestHost, handle: u64, ticket: Ticket) -> (Outcome, String) {
    test_support::fields(o, host, handle, ticket, None)
}

fn capture(name: &str, w: &Scripted) {
    let Some(dir) = std::env::var_os("AUTH_OUT_CAPTURE_DIR") else {
        return;
    };
    let sent = w.sent.lock().unwrap();
    let (target, head, body) = &sent[0];
    let v = serde_json::json!({ "target": target, "fields": head, "body": body });
    std::fs::write(std::path::Path::new(&dir).join(name), v.to_string()).expect("capture");
}

const NS: u64 = 1_000_000_000;

#[test]
fn oauth_client_credentials_mints_on_tick_and_honours_the_expired_token_rule() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        r#"{"token_url":"https://login.example.com/tenant/oauth2/v2.0/token","scope":"https://cognitiveservices.azure.com/.default"}"#,
    );
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE).0,
        Outcome::Refused,
        "before the first mint: not ready; ticket-less, REFUSED (the host re-submits on a ticket)"
    );
    let first = Ticket {
        slot: 2,
        generation: 1,
    };
    assert_eq!(
        fields(&o, &host, h, first).0,
        Outcome::Pending,
        "before the first mint: PENDING on a ticket until the first mint lands"
    );

    // THE FIRST MINT, on the first tick: a token that expires at once, so the rule can run on the
    // wall clock.
    w.ok(r#"{"access_token":"tok-1","expires_in":0}"#);
    let mut diags = Diags::default();
    let due = o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    {
        let sent = w.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].0,
            "https://login.example.com/tenant/oauth2/v2.0/token"
        );
        assert_eq!(
            sent[0].1,
            [
                (
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string()
                ),
                ("accept".to_string(), "*/*".to_string())
            ]
        );
        assert_eq!(
            sent[0].2,
            "grant_type=client_credentials&client_id=client-abc&client_secret=s3cr%26t&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
        );
    }
    capture("oauth-client-credentials.json", &w);
    assert_eq!(
        host.take(),
        vec![first],
        "the landed first mint wakes the waiting ticket"
    );
    assert_eq!(fields(&o, &host, h, first).1, "authorization: Bearer tok-1");
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE).1,
        "authorization: Bearer tok-1"
    );
    assert_eq!(
        due,
        1_000 + 30 * NS,
        "an expired-at-once token re-mints after MIN_SLEEP"
    );

    // THE REFRESH FAILS: the expired token answers PENDING on a ticket, bounded by the deadline;
    // a call that may not pend answers REFUSED (the host re-submits it on a ticket).
    w.push(vec![Step::Head(503), Step::Body(b"down".to_vec(), true)]);
    o.tick(due, Ticket::NONE, Some(&host.host), &mut diags);
    let ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    let (outcome, _) = fields(&o, &host, h, ticket);
    assert_eq!(
        outcome,
        Outcome::Pending,
        "bounded by the attempt's deadline (the host cancels it then)"
    );
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE),
        (Outcome::Refused, String::new())
    );

    // THE NEXT MINT LANDS: the waiting ticket is woken; the resumed call presents the new token.
    w.ok(r#"{"access_token":"tok-2","expires_in":3600}"#);
    o.tick(due + 30 * NS, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(host.take(), vec![ticket]);
    assert_eq!(
        fields(&o, &host, h, ticket).1,
        "authorization: Bearer tok-2"
    );
    assert_eq!(
        *w.closed.lock().unwrap(),
        3,
        "every exchange closed its connection"
    );
}

#[test]
fn jwt_bearer_mints_on_tick() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string();
    let h = open(&o, style::JWT_BEARER, &sa, "{}");
    w.ok(r#"{"access_token":"ya29.tok","expires_in":3599}"#);
    o.tick(1, Ticket::NONE, Some(&host.host), &mut Diags::default());
    {
        let sent = w.sent.lock().unwrap();
        assert_eq!(sent[0].0, "https://oauth2.googleapis.com/token");
        assert!(
            sent[0].2.starts_with(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
            ),
            "{}",
            sent[0].2
        );
    }
    capture("jwt-bearer.json", &w);
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE).1,
        "authorization: Bearer ya29.tok"
    );
}

const CC_SETTINGS: &str = r#"{"token_url":"https://login.example.com/tenant/oauth2/v2.0/token","scope":"https://cognitiveservices.azure.com/.default"}"#;

/// A client-credentials binding whose token has expired and whose refresh failed: `tok-1`,
/// expiring at once, then a 503.
fn expired_and_failed(w: &Arc<Scripted>, host: &TestHost) -> (Oauth, u64) {
    let o = instance(w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        CC_SETTINGS,
    );
    let mut diags = Diags::default();
    w.ok(r#"{"access_token":"tok-1","expires_in":0}"#);
    let due = o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    w.push(vec![Step::Head(503), Step::Body(b"down".to_vec(), true)]);
    o.tick(due, Ticket::NONE, Some(&host.host), &mut diags);
    (o, h)
}

/// THE `ready` FACT FOLLOWS THE READ (contract `abi/auth/outbound.rs`, `OutboundReadyOut::ready`:
/// "`1` = `fields` would answer with a credential now; `0` = not yet (before the first mint, or
/// expired with a failed refresh)"): a token that has expired and whose refresh failed is not
/// ready, though a token is held; nor is a minted token that yields no header.
#[test]
fn outbound_ready_is_false_for_an_expired_token_whose_refresh_failed() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let (o, h) = expired_and_failed(&w, &host);
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE).0,
        Outcome::Refused,
        "positive control: the read does not present the expired token"
    );
    assert!(
        !o.ready(h),
        "expired with a failed refresh: `fields` would not answer with a credential"
    );

    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        CC_SETTINGS,
    );
    w.ok("{\"access_token\":\"tok\\u0001bad\",\"expires_in\":3600}");
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE),
        (Outcome::Ready, String::new()),
        "positive control: a token with bytes invalid in a header is presented as no header"
    );
    assert!(
        !o.ready(h),
        "a token that yields no header presents no credential"
    );
}

/// NO LOST WAKE (THE DESIGN §6 item 5: the wait ends when a mint lands): a call that reads no
/// usable token while a mint lands, the mint's drain of the waiting tickets running before the call
/// has parked, still answers with the landed token instead of parking where nothing will wake it.
/// The test holds the instance's waiter list so the call stops at its park, lands the mint in that
/// window (the drain finds no one waiting), then lets the call go on.
#[test]
fn a_mint_landing_between_the_read_and_the_park_is_not_a_lost_wake() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let (o, h) = expired_and_failed(&w, &host);
    let Some(Binding::Minted(cell)) = o.bound(h) else {
        panic!("a minted binding")
    };
    let call = Ticket {
        slot: 7,
        generation: 1,
    };
    let answered = std::thread::scope(|s| {
        let held = o.waiters.lock().unwrap();
        let caller = s.spawn(|| fields(&o, &host, h, call));
        // The call reads the expired token and stops at its park.
        std::thread::sleep(std::time::Duration::from_millis(500));
        // THE MINT LANDS: its token is stored, and its drain finds no one parked.
        w.ok(r#"{"access_token":"tok-2","expires_in":3600}"#);
        let wire = Shared(Arc::clone(&w));
        let (_, report) = cell.tick(u64::MAX / 2, Some(&wire as &dyn Wire));
        assert_eq!(report, Some(Report::Minted), "the mint landed");
        assert!(held.is_empty(), "the drain finds no one parked yet");
        drop(held);
        caller.join().unwrap()
    });
    assert_eq!(
        answered,
        (Outcome::Ready, "authorization: Bearer tok-2".to_string()),
        "the call presents the landed token rather than park unwoken (woken: {:?})",
        host.take()
    );
}

/// NO LOST WAKE ON THE EXCHANGE PATH: a call that looks its scope's cell up while a tick settles
/// that cell (idle, unusable, waited on by no one, so dropped from the cache) parks on a cell the
/// tick still visits. The test holds the waiter list so the call stops between its lookup and its
/// park, and drops the cell from the cache in that window exactly as the settling tick would when
/// the cache lets it; the call's exchange then lands and wakes it.
#[test]
fn a_cell_settled_between_the_lookup_and_the_park_is_not_a_lost_wake() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = o.keep_binding(
        style::open(
            style::OAUTH_TOKEN_EXCHANGE,
            Some(b"busbar-own-subject-token".as_slice()),
            Some(br#"{"token_url":"https://as.example/token","resource":"https://tools.example/rpc"}"#.as_slice()),
            &o,
        )
        .unwrap_or_else(|_| panic!("the binding opens")),
    );
    let Some(Binding::Exchange(x)) = o.bound(h) else {
        panic!("an exchange binding")
    };
    let key = x.scope_key(b"s");
    let call = Ticket {
        slot: 301,
        generation: 1,
    };
    let first = std::thread::scope(|s| {
        let held = o.exchange_waiters.lock().unwrap();
        let caller = s.spawn(|| test_support::fields(&o, &host, h, call, Some("s")));
        std::thread::sleep(std::time::Duration::from_millis(500));
        // THE SETTLING TICK, where the cache lets it: the cell is idle, holds no usable token and
        // no one waits on it yet, so it is dropped.
        if let Ok(mut cache) = o.cache.try_lock() {
            cache.remove(&key);
        }
        drop(held);
        caller.join().unwrap()
    });
    assert_eq!(first.0, Outcome::Pending, "the call waits for its exchange");
    w.ok(r#"{"access_token":"tok-s","expires_in":3600}"#);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        host.take(),
        vec![call],
        "the exchange the call armed lands and wakes it"
    );
    assert_eq!(
        test_support::fields(&o, &host, h, call, Some("s")).1,
        "authorization: Bearer tok-s"
    );
}
