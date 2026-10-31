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
use crate::mint::tests::{now_epoch, Scripted, Step};
use crate::mint::TokenRequest;
use crate::style;
use crate::test_support::{self, TestHost};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::cred::SealedWrite;
use busbar_contract::conn::{ConnError, ConnId};

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
    fn clock(&self) -> Option<mint::HostClock> {
        self.0.clock()
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
    // BEFORE THE FIRST MINT: READY with zero fields, so the upstream answers 401, as 1.5.5 did
    // (THE DESIGN §11.11; App. A B.3; contract `abi/auth` `fields`). RED before the fix: the call
    // parked until the first mint landed.
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE),
        (Outcome::Ready, String::new()),
        "before the first mint, ticket-less: READY, no fields"
    );
    let first = Ticket {
        slot: 2,
        generation: 1,
    };
    assert_eq!(
        fields(&o, &host, h, first),
        (Outcome::Ready, String::new()),
        "before the first mint, on a ticket: READY, no fields, nothing parked"
    );

    // THE FIRST MINT, on the first tick: a ten-minute token, so the rule can run on the wall
    // clock once the host's clock passes it (a token expired as it lands is no token, L3).
    w.ok(r#"{"access_token":"tok-1","expires_in":600}"#);
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
        Vec::<Ticket>::new(),
        "nothing parked before the first mint, so the landed mint wakes nothing"
    );
    assert_eq!(fields(&o, &host, h, first).1, "authorization: Bearer tok-1");
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE).1,
        "authorization: Bearer tok-1"
    );
    assert_eq!(
        due,
        1_000 + 300 * NS,
        "a ten-minute token re-mints the skew (five minutes) ahead of its expiry"
    );

    // THE REFRESH FAILS, and the host's clock passes the token's expiry: the expired token
    // answers PENDING on a ticket, bounded by the deadline; a call that may not pend answers
    // REFUSED (the host re-submits it on a ticket).
    w.push(vec![Step::Head(503), Step::Body(b"down".to_vec(), true)]);
    o.tick(due, Ticket::NONE, Some(&host.host), &mut diags);
    o.saw_wall(now_epoch() + 3_600);
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

/// A BINDING'S SETTINGS REACH ITS ASSERTION: `jwt-bearer` opened with `scope` and `subject` settings
/// signs an assertion whose claims carry that scope and that `sub`.
#[test]
fn jwt_bearer_settings_reach_the_assertion_claims() {
    use base64::Engine as _;
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string();
    let _ = open(
        &o,
        style::JWT_BEARER,
        &sa,
        r#"{"scope":"s1","subject":"u@x"}"#,
    );
    w.ok(r#"{"access_token":"ya29.tok","expires_in":3599}"#);
    o.tick(1, Ticket::NONE, Some(&host.host), &mut Diags::default());
    let body = w.sent.lock().unwrap()[0].2.clone();
    let assertion = body.split("assertion=").nth(1).expect("an assertion");
    let claims = assertion.split('.').nth(1).expect("a claims part");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims"),
    )
    .expect("JSON claims");
    assert_eq!(claims["scope"], "s1", "{claims}");
    assert_eq!(claims["sub"], "u@x", "{claims}");
}

/// THE DRIVER TICKET IS WOKEN when a binding opens: after a `tick` on a real driver ticket, opening
/// a binding that wants a mint wakes that ticket on the host, so a `drive` starts the mint without
/// waiting for the next `tick`.
#[test]
fn opening_a_binding_wakes_the_driver_ticket() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let driver = Ticket {
        slot: 7,
        generation: 1,
    };
    o.tick(1, driver, Some(&host.host), &mut Diags::default());
    assert_eq!(
        host.take(),
        Vec::<Ticket>::new(),
        "nothing wanted a mint yet"
    );
    o.bind(
        style::OAUTH_CLIENT_CREDENTIALS,
        Some(b"client-abc:s3cr&t".as_slice()),
        Some(CC_SETTINGS.as_bytes()),
        Some(&host.host),
    )
    .unwrap_or_else(|_| panic!("the binding opens"));
    assert_eq!(host.take(), vec![driver], "the open woke the driver ticket");
}

/// The scripted need on a host whose clock reads `wall_secs` (and a monotonic `mono_ns`).
struct Pinned(Arc<Scripted>, u64);

impl Wire for Pinned {
    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.0.open(req, body, timeout_ms)
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<mint::Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
    fn clock(&self) -> Option<mint::HostClock> {
        Some(mint::HostClock {
            wall_secs: self.1,
            mono_ns: 0,
        })
    }
}

/// ONE CLOCK (THE DESIGN §1: "one clock, which also drives every plugin's `tick`"; §11.12
/// `clock.now`; Q128 auth-oauth LOW). The assertion's `iat` is the HOST's wall time, not a clock
/// the plugin reads for itself: a host pinned at 1_800_000_000 signs an assertion issued then (a
/// plausible clock: O8 mints at none before 2026-01-01). RED before the fix: the plugin read
/// `SystemTime::now()`.
#[test]
fn jwt_bearer_signs_at_the_hosts_wall_clock() {
    use base64::Engine as _;
    const HOST_WALL: u64 = 1_800_000_000;
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = Oauth::with_wire(1, Some(Box::new(Pinned(w.clone(), HOST_WALL))));
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string();
    let _ = open(&o, style::JWT_BEARER, &sa, "{}");
    w.ok(r#"{"access_token":"ya29.tok","expires_in":3599}"#);
    o.tick(1, Ticket::NONE, Some(&host.host), &mut Diags::default());
    let body = w.sent.lock().unwrap()[0].2.clone();
    let assertion = body.split("assertion=").nth(1).expect("an assertion");
    let claims = assertion.split('.').nth(1).expect("a claims part");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims"),
    )
    .expect("JSON claims");
    assert_eq!(claims["iat"], HOST_WALL, "{claims}");
    assert_eq!(claims["exp"], HOST_WALL + 3600, "{claims}");
}

const CC_SETTINGS: &str = r#"{"token_url":"https://login.example.com/tenant/oauth2/v2.0/token","scope":"https://cognitiveservices.azure.com/.default"}"#;

/// A client-credentials binding whose token has expired and whose refresh failed: `tok-1`, ten
/// minutes to live, a 503 on its refresh, then the host's clock past its expiry (a token expired
/// as it lands is no token, L3).
fn expired_and_failed(w: &Arc<Scripted>, host: &TestHost) -> (Oauth, u64) {
    let o = instance(w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        CC_SETTINGS,
    );
    let mut diags = Diags::default();
    w.ok(r#"{"access_token":"tok-1","expires_in":600}"#);
    let due = o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    w.push(vec![Step::Head(503), Step::Body(b"down".to_vec(), true)]);
    o.tick(due, Ticket::NONE, Some(&host.host), &mut diags);
    o.saw_wall(now_epoch() + 3_600);
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
        (Outcome::Failed, String::new()),
        "positive control: a token with bytes invalid in a header fails the call"
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
        let (_, report) = cell.tick(u64::MAX / 2, now_epoch(), Some(&wire as &dyn Wire));
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
        if let Ok(mut cache) = o.cache.try_write() {
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

/// A CANCELLED WAIT LEAVES NO ENTRY: forgetting the last ticket parked on an on-demand cell drops
/// the cell's waiter entry, so a scope whose cell the cache then drops does not leak an empty list.
#[test]
fn forgetting_the_last_waiter_drops_its_exchange_entry() {
    for via_cancel in [true, false] {
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
            slot: 401,
            generation: 1,
        };
        assert_eq!(
            test_support::fields(&o, &host, h, call, Some("s")).0,
            Outcome::Pending
        );
        assert!(o.exchange_waiters.lock().unwrap().contains_key(&key));
        if via_cancel {
            o.unpark(call);
        } else {
            o.unpark_exchange(key, call);
        }
        assert!(
            !o.exchange_waiters.lock().unwrap().contains_key(&key),
            "no empty entry remains (cancel: {via_cancel})"
        );
    }
}

/// The scripted need on a host whose clock the test sets: wall seconds from `wall`.
struct HostClocked(Arc<Scripted>, Arc<AtomicU64>);

impl Wire for HostClocked {
    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.0.open(req, body, timeout_ms)
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<mint::Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
    fn clock(&self) -> Option<mint::HostClock> {
        Some(mint::HostClock {
            wall_secs: self.1.load(Ordering::Acquire),
            mono_ns: 0,
        })
    }
}

/// One `fields` call stamped with the host's wall time `timestamp` (THE DESIGN abi/auth: "read once
/// by the host for this call"), on `ticket`, its scope `scope`.
fn fields_at(
    o: &Oauth,
    host: &TestHost,
    handle: u64,
    ticket: Ticket,
    scope: Option<&str>,
    timestamp: u64,
) -> (Outcome, String) {
    let mut written = Vec::new();
    let ask = crate::Ask {
        handle,
        own: true,
        scope: scope.map(str::as_bytes),
        ticket,
        timestamp,
    };
    let answer = o.answer(&ask, Some(&host.host), &mut |h| {
        written.push(format!("authorization: {h}"));
    });
    match answer {
        std::task::Poll::Ready(busbar_contract::abi::sdk::auth_outbound::FieldsAnswer::Ready) => {
            (Outcome::Ready, written.join(" ; "))
        }
        std::task::Poll::Pending => (Outcome::Pending, String::new()),
        std::task::Poll::Ready(_) => (Outcome::Refused, String::new()),
    }
}

/// ONE CLOCK, FOR EXPIRY AND CACHING (THE DESIGN §1 l.159: "one clock, which also drives every
/// plugin's tick"; §11.12: the clock family is "wall and monotonic time from the kernel's one
/// clock"; Q128 auth-oauth LOW, finding 3). A token's expiry and an on-demand token's cache life are
/// judged on the HOST's wall time, never the process's: the host's clock here sits at 2026-01-02
/// (the earliest plausible clock, O8), months behind the process clock, so a token minted on it is
/// FRESH on the host's time though the process clock calls it long expired; and a host clock moved far into the future sees the same cached
/// token as expired, though the process clock calls it fresh. The refresh timing is 1.5.5's,
/// relative to the clock the plugin is given.
#[test]
fn token_expiry_and_caching_are_judged_on_the_hosts_clock() {
    const HOST_WALL: u64 = 1_767_312_000;
    const FAR_FUTURE: u64 = 4_000_000_000;
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let wall = Arc::new(AtomicU64::new(HOST_WALL));
    let o = Oauth::with_wire(1, Some(Box::new(HostClocked(w.clone(), wall.clone()))));
    let mut diags = Diags::default();

    // A SCHEDULED STYLE: minted at the host's 2001, an hour to live, then its refresh fails.
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        CC_SETTINGS,
    );
    w.ok(r#"{"access_token":"tok-1","expires_in":3600}"#);
    let due = o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(
        due,
        1_000 + (3600 - 300) * NS,
        "the refresh is 1.5.5's: the skew ahead of expiry, on the clock the plugin is given"
    );
    w.push(vec![Step::Head(503), Step::Body(b"down".to_vec(), true)]);
    wall.store(HOST_WALL + 3300, Ordering::Release);
    o.tick(due, Ticket::NONE, Some(&host.host), &mut diags);
    let call = Ticket {
        slot: 11,
        generation: 1,
    };
    assert_eq!(
        fields_at(&o, &host, h, call, None, HOST_WALL + 3310),
        (Outcome::Ready, "authorization: Bearer tok-1".to_string()),
        "on the host's clock the token has not expired yet (the process clock says it has)"
    );
    assert!(o.ready(h), "ready on the host's clock");
    assert_eq!(
        fields_at(&o, &host, h, call, None, FAR_FUTURE).0,
        Outcome::Pending,
        "a host clock far in the future sees the cached token as expired"
    );
    assert!(!o.ready(h), "not ready on the host's far-future clock");
    o.unpark(call);

    // AN ON-DEMAND STYLE: a token exchange's cached token is presented on the host's clock (its own
    // instance, so the scheduled cell's retry above never takes the exchange's scripted reply).
    let w = Arc::new(Scripted::default());
    let wall = Arc::new(AtomicU64::new(HOST_WALL));
    let o = Oauth::with_wire(1, Some(Box::new(HostClocked(w.clone(), wall))));
    let x = style::open(
        style::OAUTH_TOKEN_EXCHANGE,
        Some(b"busbar-own-subject-token".as_slice()),
        Some(
            br#"{"token_url":"https://as.example/token","resource":"https://tools.example/rpc"}"#
                .as_slice(),
        ),
        &o,
    )
    .unwrap_or_else(|_| panic!("the binding opens"));
    let x = o.keep_binding(x);
    let first = Ticket {
        slot: 12,
        generation: 1,
    };
    assert_eq!(
        fields_at(&o, &host, x, first, Some("s"), HOST_WALL).0,
        Outcome::Pending,
        "no token for the scope yet: the call waits on its exchange"
    );
    w.ok(r#"{"access_token":"tok-x","expires_in":3600}"#);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    let sent = w.sent.lock().unwrap().len();
    assert_eq!(
        fields_at(&o, &host, x, first, Some("s"), HOST_WALL + 10),
        (Outcome::Ready, "authorization: Bearer tok-x".to_string()),
        "the cached exchange token is fresh on the host's clock (the process clock says stale)"
    );
    // A tick before the token's refresh is due: exchanges only start in a tick, so were the
    // fresh read to have armed one, it would start here and show in the count.
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(
        w.sent.lock().unwrap().len(),
        sent,
        "the cached token was served without a new exchange (a tick ran after the read)"
    );
    let later = Ticket {
        slot: 13,
        generation: 1,
    };
    assert_eq!(
        fields_at(&o, &host, x, later, Some("s"), FAR_FUTURE).0,
        Outcome::Pending,
        "a host clock far in the future sees the cached exchange token as expired: a new exchange"
    );
    assert_eq!(
        w.sent.lock().unwrap().len(),
        sent,
        "the cached token was served without a new exchange until the host's clock passed it"
    );
}

/// A TICK NEVER RESTARTS THE HANDLE COUNT (the oracle's egress.auth mint-refresh cells): the host
/// keeps a driver ticket's answers across a tick while anything is held or pending, so a count
/// reset at the tick reused a kept handle, and the refresh ahead of expiry never left (`fault`, or
/// a replayed reply read as status 0) — a 2 s token was never re-minted. RED before: 9 -> 0.
#[test]
fn a_tick_carries_the_handle_count_on() {
    let wire = Arc::new(Scripted::default());
    let o = instance(&wire);
    o.issued.store(9, Ordering::Release);
    o.tick(1, Ticket::NONE, None, &mut Diags::default());
    assert_eq!(o.issued.load(Ordering::Acquire), 9);
}

/// A SCHEDULED CELL NO HANDLE HOLDS LEAVES THE CACHE ONCE IDLE: `retire` keeps a cell whose mint is
/// in flight, and the tick that lands it drops the cell, so a provider a reload removed mid-mint is
/// never ticked again nor refreshed with its secret.
#[test]
fn a_retired_scheduled_cell_kept_for_its_mint_leaves_the_cache_when_it_lands() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let _h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        r#"{"token_url":"https://login.example.com/token","scope":"s"}"#,
    );
    w.push(vec![
        Step::Pending,
        Step::Head(200),
        Step::Body(
            br#"{"access_token":"tok-1","expires_in":3600}"#.to_vec(),
            true,
        ),
    ]);
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(w.sent.lock().unwrap().len(), 1, "the mint is in flight");
    o.retire(1);
    assert_eq!(
        o.cache.read().unwrap().len(),
        1,
        "kept: its mint is in flight"
    );
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    let sent = w.sent.lock().unwrap().len();
    o.tick(10_000 * NS, Ticket::NONE, Some(&host.host), &mut diags);
    assert!(o.cache.read().unwrap().is_empty(), "the idle orphan left");
    assert_eq!(
        w.sent.lock().unwrap().len(),
        sent,
        "no refresh exchange was opened for the removed provider"
    );
}

/// A cell a reload's new handle still holds stays through the old generation's `retire`.
#[test]
fn a_retired_generation_leaves_a_cell_the_new_generation_holds() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let (cred, settings) = (
        "client-abc:s3cr&t",
        r#"{"token_url":"https://login.example.com/token","scope":"s"}"#,
    );
    let _h1 = open(&o, style::OAUTH_CLIENT_CREDENTIALS, cred, settings);
    w.ok(r#"{"access_token":"tok-1","expires_in":3600}"#);
    let mut diags = Diags::default();
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut diags);
    o.set_generation(2);
    let h2 = open(&o, style::OAUTH_CLIENT_CREDENTIALS, cred, settings);
    o.retire(1);
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(
        fields(&o, &host, h2, Ticket::NONE).1,
        "authorization: Bearer tok-1"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 1, "no new exchange");
    assert_eq!(o.cache.read().unwrap().len(), 1, "one cell");
}

/// THE TOKEN CACHE KEY IS NO PLAIN DIGEST OF THE CREDENTIAL (S1, bank grade): a SHA-256 of
/// `style\0credential\0settings` held in memory lets anyone who reads it test guesses at a
/// low-entropy client secret offline. The key is a keyed derivation under the instance's own random
/// key, so two instances key one binding differently. RED: every cell was keyed by the plain digest.
#[test]
fn the_token_cache_key_is_keyed_per_instance_never_a_plain_digest() {
    use sha2::{Digest, Sha256};
    const CRED: &str = "id:secret";
    const SETTINGS: &str = r#"{"token_url":"https://t","scope":"s"}"#;
    let plain: [u8; 32] = {
        let mut h = Sha256::new();
        for (i, part) in [
            style::OAUTH_CLIENT_CREDENTIALS.as_bytes(),
            CRED.as_bytes(),
            SETTINGS.as_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            if i > 0 {
                h.update([0]);
            }
            h.update(part);
        }
        h.finalize().into()
    };
    let keys = |o: &Oauth| -> Vec<[u8; 32]> {
        open(o, style::OAUTH_CLIENT_CREDENTIALS, CRED, SETTINGS);
        o.cache.read().unwrap().keys().copied().collect()
    };
    let (a, b) = (keys(&Oauth::new(1)), keys(&Oauth::new(1)));
    assert_eq!((a.len(), b.len()), (1, 1));
    assert_ne!(
        a[0], plain,
        "the cache key is the plain digest of the credential"
    );
    assert_ne!(a[0], b[0], "two instances derive one binding's key alike");
}

/// ONE POLICY WITH THE TOKEN EXCHANGE (KIND-auth lead decision, 1.6.0): A FIRST MINT THAT FAILED
/// FAILS THE CALL, naming why: nothing goes out unauthenticated once a mint was attempted (the
/// token exchange's policy, and sigv4's refusal). The mint retries on its schedule; a call after a
/// token lands presents it. RED: READY with no field.
#[test]
fn a_failed_first_mint_fails_the_call_rather_than_send_it_unauthenticated() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "id:secret",
        r#"{"token_url":"https://idp.example/token","scope":"s"}"#,
    );
    let t = Ticket {
        slot: 2,
        generation: 1,
    };
    w.push(vec![
        Step::Head(401),
        Step::Body(br#"{"error":"invalid_client"}"#.to_vec(), true),
    ]);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    for ticket in [t, Ticket::NONE] {
        assert_eq!(
            fields(&o, &host, h, ticket),
            (Outcome::Failed, String::new())
        );
    }
    w.ok(r#"{"access_token":"tok-2","expires_in":3600}"#);
    o.tick(
        1_000 + 30 * NS,
        Ticket::NONE,
        Some(&host.host),
        &mut Diags::default(),
    );
    assert_eq!(fields(&o, &host, h, t).1, "authorization: Bearer tok-2");
}

/// A MINTED TOKEN THAT CANNOT BE A HEADER VALUE FAILS THE CALL (never READY with no field).
#[test]
fn a_token_that_cannot_be_presented_fails_the_call() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "id:secret",
        r#"{"token_url":"https://idp.example/token","scope":"s"}"#,
    );
    w.ok("{\"access_token\":\"bad\\u0001token\",\"expires_in\":3600}");
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        fields(&o, &host, h, Ticket::NONE),
        (Outcome::Failed, String::new())
    );
    assert!(!o.ready(h));
}

/// THE MINT LOGS ITS OUTCOME (S4, S5): a token endpoint that answers 5xx or 429, or cannot be
/// reached, is an OUTAGE, logged at WARN; one that refuses the credential (another 4xx) is logged
/// at INFO. Each event carries `module = "oauth"` and the reason, never a secret. RED: the mint
/// logged nothing (the diag channel only).
#[test]
fn a_failed_mint_is_logged_an_outage_at_warn_or_a_refusal_at_info() {
    use busbar_test_kit::warn_capture::WarnCapture;
    let mint_with = |cap: &WarnCapture, steps: Vec<Step>| {
        tracing::subscriber::with_default(cap.clone(), || {
            let host = TestHost::new();
            let w = Arc::new(Scripted::default());
            let o = instance(&w);
            open(
                &o,
                style::OAUTH_CLIENT_CREDENTIALS,
                "id:s3cr3t",
                r#"{"token_url":"https://idp.example/token","scope":"s"}"#,
            );
            w.push(steps);
            o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        });
        cap.messages()
    };
    for status in [503, 429] {
        let warn = WarnCapture::default();
        let m = mint_with(
            &warn,
            vec![Step::Head(status), Step::Body(b"busy".to_vec(), true)],
        );
        assert!(
            m.iter()
                .any(|l| l.contains("outage") && l.contains("module=oauth")),
            "{status} at WARN: {m:?}"
        );
    }
    let refused = || {
        vec![
            Step::Head(401),
            Step::Body(br#"{"error":"invalid_client"}"#.to_vec(), true),
        ]
    };
    let warn = WarnCapture::default();
    assert_eq!(
        mint_with(&warn, refused()),
        Vec::<String>::new(),
        "a refusal is no WARN"
    );
    drop(warn);
    let info = WarnCapture::capturing_debug();
    let m = mint_with(&info, refused());
    assert!(
        m.iter()
            .any(|l| l.contains("invalid_client") && l.contains("module=oauth")),
        "{m:?}"
    );
    assert!(
        m.iter()
            .all(|l| !l.contains("s3cr3t") && !l.contains("outage")),
        "{m:?}"
    );
}

/// A token-exchange binding on `o` (busbar's own subject token, the shared settings).
fn exchange_binding(o: &Oauth) -> u64 {
    o.keep_binding(
        style::open(
            style::OAUTH_TOKEN_EXCHANGE,
            Some(b"busbar-own-subject-token".as_slice()),
            Some(
                br#"{"token_url":"https://as.example/token","resource":"https://tools.example/rpc"}"#
                    .as_slice(),
            ),
            o,
        )
        .unwrap_or_else(|_| panic!("the binding opens")),
    )
}

/// O4, A REQUEST-STATED SCOPE IS BOUNDED: a scope longer than 1024 bytes is refused (FAILED,
/// saying why) before any cell is made for it; one of exactly 1024 bytes is exchanged. RED: every
/// scope, of any length, made its own cell and exchange.
#[test]
fn a_scope_longer_than_1024_bytes_is_refused() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = exchange_binding(&o);
    let long = "s".repeat(1025);
    let t = Ticket {
        slot: 801,
        generation: 1,
    };
    assert_eq!(
        test_support::fields(&o, &host, h, t, Some(&long)).0,
        Outcome::Failed
    );
    assert!(o.cache.read().unwrap().is_empty(), "no cell for it");
    assert_eq!(
        test_support::fields(&o, &host, h, t, Some(&long[..1024])).0,
        Outcome::Pending,
        "1024 bytes is a scope"
    );
}

/// O4, A BINDING HOLDS AT MOST 256 SCOPE CELLS: the 257th scope evicts the least recently used
/// IDLE cell no request waits on (a cell a request just read is not it). RED: one cell per
/// request-stated scope, unbounded.
#[test]
fn a_binding_holds_at_most_256_scope_cells_evicting_the_least_recently_used_idle_one() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = exchange_binding(&o);
    let Some(Binding::Exchange(x)) = o.bound(h) else {
        panic!("an exchange binding")
    };
    let call = |i: u32| Ticket {
        slot: 1_000 + i,
        generation: 1,
    };
    for i in 0..256_u32 {
        assert_eq!(
            test_support::fields(&o, &host, h, call(i), Some(&format!("s{i}"))).0,
            Outcome::Pending
        );
        w.ok(r#"{"access_token":"tok","expires_in":3600}"#);
    }
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(o.cache.read().unwrap().len(), 256, "256 scopes minted");
    // `s0` is read again: `s1` is now the least recently used.
    assert_eq!(
        test_support::fields(&o, &host, h, Ticket::NONE, Some("s0")).1,
        "authorization: Bearer tok"
    );
    assert_eq!(
        test_support::fields(&o, &host, h, call(256), Some("s256")).0,
        Outcome::Pending
    );
    let cache = o.cache.read().unwrap();
    assert_eq!(cache.len(), 256, "the cap holds");
    assert!(
        cache.contains_key(&x.scope_key(b"s0")),
        "the recently read cell stays"
    );
    assert!(
        !cache.contains_key(&x.scope_key(b"s1")),
        "the LRU idle cell left"
    );
    assert!(cache.contains_key(&x.scope_key(b"s256")));
}

/// O4: a cell some request waits on is never evicted; with every one of the 256 cells waited on,
/// a new scope is refused (FAILED, saying why) rather than grow the cache past its cap.
#[test]
fn a_scope_cell_with_waiters_is_never_evicted() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = exchange_binding(&o);
    let call = |i: u32| Ticket {
        slot: 2_000 + i,
        generation: 1,
    };
    for i in 0..256_u32 {
        assert_eq!(
            test_support::fields(&o, &host, h, call(i), Some(&format!("w{i}"))).0,
            Outcome::Pending
        );
    }
    assert_eq!(
        test_support::fields(&o, &host, h, call(256), Some("w256")).0,
        Outcome::Failed
    );
    assert_eq!(
        o.cache.read().unwrap().len(),
        256,
        "no waited cell was evicted"
    );
}

/// O5, THE TOKEN TYPE IS CHECKED (RFC 6749 §5.1, §7.1): a reply whose `token_type` is present and
/// not `bearer` (any case) fails the mint, at an operator-visible WARN, and nothing is presented
/// as a bearer; `Bearer` in any case mints; an absent `token_type` is accepted (many endpoints
/// omit it) with ONE WARN per cell. RED: `token_type` was never read.
#[test]
fn a_token_type_other_than_bearer_fails_the_mint_and_an_absent_one_warns_once() {
    use busbar_test_kit::warn_capture::WarnCapture;
    const SETTINGS: &str = r#"{"token_url":"https://idp.example/token","scope":"s"}"#;
    let host = TestHost::new();
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        let w = Arc::new(Scripted::default());
        let o = instance(&w);
        let h = open(&o, style::OAUTH_CLIENT_CREDENTIALS, "id:secret", SETTINGS);
        w.ok(r#"{"access_token":"tok","token_type":"mac","expires_in":3600}"#);
        o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        assert_eq!(
            fields(&o, &host, h, Ticket::NONE),
            (Outcome::Failed, String::new()),
            "a mac token is never presented as a bearer"
        );
    });
    let m = cap.messages();
    assert!(
        m.iter()
            .any(|l| l.contains("token_type") && l.contains("module=oauth")),
        "the refusal is a WARN: {m:?}"
    );
    for spelling in ["Bearer", "bearer", "BEARER"] {
        let w = Arc::new(Scripted::default());
        let o = instance(&w);
        let h = open(&o, style::OAUTH_CLIENT_CREDENTIALS, "id:secret", SETTINGS);
        w.ok(&format!(
            r#"{{"access_token":"tok","token_type":"{spelling}","expires_in":3600}}"#
        ));
        o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        assert_eq!(
            fields(&o, &host, h, Ticket::NONE).1,
            "authorization: Bearer tok",
            "{spelling}"
        );
    }
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        let w = Arc::new(Scripted::default());
        let o = instance(&w);
        let h = open(&o, style::OAUTH_CLIENT_CREDENTIALS, "id:secret", SETTINGS);
        w.ok(r#"{"access_token":"tok-1","expires_in":3600}"#);
        o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        assert_eq!(
            fields(&o, &host, h, Ticket::NONE).1,
            "authorization: Bearer tok-1"
        );
        w.ok(r#"{"access_token":"tok-2","expires_in":3600}"#);
        o.tick(
            1_000 + 3_300 * NS,
            Ticket::NONE,
            Some(&host.host),
            &mut Diags::default(),
        );
        assert_eq!(
            fields(&o, &host, h, Ticket::NONE).1,
            "authorization: Bearer tok-2"
        );
    });
    assert_eq!(
        cap.count("token_type"),
        1,
        "an absent token_type warns once per cell: {:?}",
        cap.messages()
    );
}

/// O8: a mint the host's wall clock cannot date fails the call (nothing is presented) and is
/// logged at WARN, `module = "oauth"`, naming the clock. RED: it minted at `iat` 0.
#[test]
fn a_mint_with_no_plausible_wall_clock_fails_at_warn() {
    use busbar_test_kit::warn_capture::WarnCapture;
    let host = TestHost::new();
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        let w = Arc::new(Scripted::default());
        let o = Oauth::with_wire(1, Some(Box::new(Pinned(w.clone(), 0))));
        let h = open(
            &o,
            style::OAUTH_CLIENT_CREDENTIALS,
            "id:secret",
            r#"{"token_url":"https://idp.example/token","scope":"s"}"#,
        );
        w.ok(r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#);
        o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        assert!(w.sent.lock().unwrap().is_empty(), "nothing was sent");
        assert_eq!(
            fields(&o, &host, h, Ticket::NONE),
            (Outcome::Failed, String::new())
        );
    });
    let m = cap.messages();
    assert!(
        m.iter()
            .any(|l| l.contains("wall clock") && l.contains("module=oauth")),
        "{m:?}"
    );
}

/// L1: THE WALL CLOCK NEVER MOVES BACKWARDS: an older reading (a call's own timestamp read before
/// a newer tick's, racing it) leaves the newest one in place. RED: the last writer won.
#[test]
fn an_older_wall_clock_reading_never_moves_the_clock_back() {
    let o = Oauth::new(1);
    o.saw_wall(1_800_000_100);
    o.saw_wall(1_800_000_000);
    assert_eq!(o.wall_secs(), 1_800_000_100);
    o.saw_wall(0);
    assert_eq!(o.wall_secs(), 1_800_000_100, "no reading is no reading");
}
