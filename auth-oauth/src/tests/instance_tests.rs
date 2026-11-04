// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises minting, bearer fields, refresh waits and wakeups over a scripted host connection.

use super::*;
use crate::mint;
use crate::mint::tests::{now_epoch, Scripted, Step};
use crate::mint::TokenRequest;
use crate::style;
use crate::test_support::{self, fields_at, TestHost};
use crate::Ask;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::auth_outbound::FieldsAnswer;
use busbar_contract::abi::sdk::cred::SealedWrite;
use busbar_contract::conn::{ConnError, ConnId};
use std::task::Poll;

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

/// The unit tests' instances: production opens one through [`Oauth::opened`] only.
impl Oauth {
    /// A test's instance at `generation`.
    pub(crate) fn new(generation: u64) -> Self {
        Self::with_wire(generation, None)
    }

    /// An instance over any [`Wire`] (the unit tests' double).
    pub(crate) fn with_wire(generation: u64, wire: Option<Box<dyn Wire>>) -> Self {
        Self::keyed(
            generation,
            wire,
            cache_secret().expect("the system random source"),
        )
    }
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
fn a_scheduled_binding_refuses_before_its_first_mint_without_presenting_or_parking() {
    let host = TestHost::new();
    let wire = Arc::new(Scripted::default());
    let oauth = instance(&wire);
    let handle = open(
        &oauth,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client:secret",
        r#"{"token_url":"https://issuer.example/token"}"#,
    );
    let mut reasons = Vec::new();
    for ticket in [
        Ticket::NONE,
        Ticket {
            slot: 7,
            generation: 1,
        },
    ] {
        let mut presented = 0;
        let answer = oauth.answer(
            &Ask {
                handle,
                own: true,
                scope: None,
                ticket,
                timestamp: now_epoch(),
            },
            Some(&host.host),
            &mut |_| presented += 1,
        );
        let Poll::Ready(FieldsAnswer::Failed(reason)) = answer else {
            panic!("an unminted binding must fail closed: {answer:?}");
        };
        assert_eq!(reason, crate::mint::NO_TOKEN, "the caller is told why");
        reasons.push(reason.into_owned());
        assert_eq!(
            presented, 0,
            "no anonymous or speculative credential presentation"
        );
        assert!(!oauth.ready(handle));
    }
    assert_eq!(
        reasons[0], reasons[1],
        "the first-mint refusal is stable on both call paths"
    );
    assert!(
        wire.sent.lock().unwrap().is_empty(),
        "requests do not start a scheduled mint"
    );
    assert!(host.take().is_empty(), "a refused call parks no ticket");
    wire.ok(r#"{"access_token":"minted","expires_in":600}"#);
    oauth.tick(1000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        fields(&oauth, &host, handle, Ticket::NONE),
        (Outcome::Ready, "authorization: Bearer minted".into())
    );
    assert_eq!(wire.sent.lock().unwrap().len(), 1);
}

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
        fields(&o, &host, h, Ticket::NONE),
        (Outcome::Failed, String::new()),
        "before the first mint, ticket-less: failed closed"
    );
    let first = Ticket {
        slot: 2,
        generation: 1,
    };
    assert_eq!(
        fields(&o, &host, h, first),
        (Outcome::Failed, String::new()),
        "before the first mint, on a ticket: failed closed, nothing parked"
    );

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
    let (pause, arrived, release) = test_support::pause_once();
    assert!(o.before_mint_park.set(pause).is_ok(), "the seam is unset");
    let answered = std::thread::scope(|threads| {
        let caller = threads.spawn(|| fields(&o, &host, h, call));
        arrived.recv().unwrap();
        w.ok(r#"{"access_token":"tok-2","expires_in":3600}"#);
        let wire = Shared(Arc::clone(&w));
        let report = cell.tick(u64::MAX / 2, now_epoch(), Some(&wire)).1;
        let unparked = o.waiters.lock().unwrap().is_empty();
        release.send(()).unwrap();
        assert_eq!(report, Some(Report::Minted));
        assert!(unparked, "the drain finds no one parked yet");
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

    let (entered, arrived) = std::sync::mpsc::sync_channel(0);
    let (release, resume) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|threads| {
        let oauth = &o;
        let binding = &x;
        let caller = threads.spawn(move || {
            oauth
                .exchange_cell(
                    key,
                    || binding.minter("s"),
                    call,
                    |_| {
                        entered.send(()).unwrap();
                        resume.recv().unwrap();
                        false
                    },
                    |cell| binding.owns(cell),
                )
                .unwrap_or_else(|_| panic!("room for one scope"))
        });
        arrived.recv().unwrap();

        let locked = o.cache.try_write().is_err();
        release.send(()).unwrap();
        assert!(
            locked,
            "the call holds the cache from its lookup to its park, so no settle can remove the \
             cell in between"
        );
        drop(caller.join().unwrap());
    });
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

#[test]
fn token_expiry_and_caching_are_judged_on_the_hosts_clock() {
    const HOST_WALL: u64 = 1_767_312_000;
    const FAR_FUTURE: u64 = 4_000_000_000;
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let wall = Arc::new(AtomicU64::new(HOST_WALL));
    let o = Oauth::with_wire(1, Some(Box::new(HostClocked(w.clone(), wall.clone()))));
    let mut diags = Diags::default();

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
        "a host clock far in the future sees the cached exchange token as expired: the call waits"
    );
    assert_eq!(
        w.sent.lock().unwrap().len(),
        sent,
        "the cached token was served without a new exchange until the host's clock passed it"
    );
    w.ok(r#"{"access_token":"tok-y","expires_in":3600}"#);
    o.tick(3_000, Ticket::NONE, Some(&host.host), &mut diags);
    assert_eq!(
        w.sent.lock().unwrap().len(),
        sent + 1,
        "the expired token armed a fresh exchange, which the next tick sends"
    );
}

/// A TICK NEVER RESTARTS THE HANDLE COUNT (the oracle's egress.auth mint-refresh cells): the host
#[test]
fn a_tick_carries_the_handle_count_on() {
    let wire = Arc::new(Scripted::default());
    let o = instance(&wire);
    o.issued.store(9, Ordering::Release);
    o.tick(1, Ticket::NONE, None, &mut Diags::default());
    assert_eq!(o.issued.load(Ordering::Acquire), 9);
}

/// A SCHEDULED CELL NO HANDLE HOLDS LEAVES THE CACHE ONCE IDLE: `retire` keeps a cell whose mint is
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
#[test]
fn a_failed_mint_is_logged_an_outage_at_warn_or_a_refusal_at_info() {
    use crate::test_support::OAuthEvents;
    let mint_with = |cap: &OAuthEvents, steps: Vec<Step>| {
        tracing::subscriber::with_default(cap.subscriber(), || {
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
    for status in [429, 500, 502, 503, 504, 599] {
        let warn = OAuthEvents::default();
        let m = mint_with(
            &warn,
            vec![Step::Head(status), Step::Body(b"busy".to_vec(), true)],
        );
        assert_eq!(
            m.iter()
                .filter(|l| l.contains("outage") && l.contains("module=\"oauth\""))
                .count(),
            1,
            "{status} at WARN exactly once: {m:?}"
        );
    }
    for status in [400, 499, 600] {
        let warn = OAuthEvents::default();
        assert!(mint_with(
            &warn,
            vec![Step::Head(status), Step::Body(b"refused".to_vec(), true)]
        )
        .is_empty());
    }
    for failure in [ConnError::Timeout, ConnError::Closed, ConnError::Fault] {
        let warn = OAuthEvents::default();
        let messages = mint_with(&warn, vec![Step::Fail(failure)]);
        assert_eq!(
            messages
                .iter()
                .filter(|line| line.contains("outage") && line.contains("module=\"oauth\""))
                .count(),
            1
        );
    }
    let refused = || {
        vec![
            Step::Head(401),
            Step::Body(br#"{"error":"invalid_client"}"#.to_vec(), true),
        ]
    };
    let warn = OAuthEvents::default();
    assert_eq!(
        mint_with(&warn, refused()),
        Vec::<String>::new(),
        "a refusal is no WARN"
    );
    drop(warn);
    let info = OAuthEvents::capturing_debug();
    let m = mint_with(&info, refused());
    assert!(
        m.iter()
            .any(|l| l.contains("invalid_client") && l.contains("module=\"oauth\"")),
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

/// A SCOPE BACKING OFF A FAILURE KEEPS ITS WINDOW: at the cap its cell is never the one evicted
/// (a fresh cell would forget the back-off and re-hit the token endpoint at once).
#[test]
fn a_scope_cell_backing_off_a_failure_is_never_evicted() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = exchange_binding(&o);
    let Some(Binding::Exchange(x)) = o.bound(h) else {
        panic!("an exchange binding")
    };
    let call = |i: u32| Ticket {
        slot: 3_000 + i,
        generation: 1,
    };
    assert_eq!(
        test_support::fields(&o, &host, h, call(0), Some("f0")).0,
        Outcome::Pending
    );
    w.push(vec![
        Step::Head(401),
        Step::Body(br#"{"error":"invalid_scope"}"#.to_vec(), true),
    ]);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        test_support::fields(&o, &host, h, call(0), Some("f0")).0,
        Outcome::Failed,
        "positive control: the first scope's exchange failed and backs off"
    );
    for i in 1..256_u32 {
        assert_eq!(
            test_support::fields(&o, &host, h, call(i), Some(&format!("s{i}"))).0,
            Outcome::Pending,
            "a refusal (4xx) of one scope does not hold the others back"
        );
        w.ok(r#"{"access_token":"tok","expires_in":3600}"#);
    }
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(o.cache.read().unwrap().len(), 256);
    assert_eq!(
        test_support::fields(&o, &host, h, call(256), Some("s256")).0,
        Outcome::Pending
    );
    let cache = o.cache.read().unwrap();
    assert!(
        cache.contains_key(&x.scope_key(b"f0")),
        "the least recently used cell is backing off: it stays, its window with it"
    );
    assert!(
        !cache.contains_key(&x.scope_key(b"s1")),
        "the least recently used cell not backing off left"
    );
}

/// AN OUTAGE BACKS OFF THE BINDING, NOT ONLY ITS SCOPE: while one scope's exchange backs off a
/// 5xx, a call stating a scope the binding holds no cell for fails at once rather than exchange
/// (caller-stated scopes cannot hammer a token endpoint that is down).
#[test]
fn a_new_scope_is_not_exchanged_while_the_binding_backs_off_an_outage() {
    let host = TestHost::new();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = exchange_binding(&o);
    let call = |i: u32| Ticket {
        slot: 4_000 + i,
        generation: 1,
    };
    assert_eq!(
        test_support::fields(&o, &host, h, call(0), Some("a")).0,
        Outcome::Pending
    );
    w.push(vec![Step::Head(503), Step::Body(b"busy".to_vec(), true)]);
    o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        test_support::fields(&o, &host, h, call(0), Some("a")).0,
        Outcome::Failed,
        "positive control: the exchange failed on an outage"
    );
    let ask = Ask {
        handle: h,
        own: true,
        scope: Some(b"b".as_slice()),
        ticket: call(1),
        timestamp: 0,
    };
    match o.answer(&ask, Some(&host.host), &mut |_| {}) {
        Poll::Ready(FieldsAnswer::Failed(why)) => assert!(
            why.starts_with(
                "the RFC 8693 token endpoint is down (an exchange for another scope failed: token \
                 endpoint returned 503 Service Unavailable); no new scope is exchanged for "
            ),
            "{why}"
        ),
        other => panic!("a new scope fails fast during the outage: {other:?}"),
    }
    o.tick(2_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
    assert_eq!(
        w.sent.lock().unwrap().len(),
        1,
        "nothing more reached the token endpoint"
    );
}

/// AN ON-DEMAND MINT THAT LANDS NOTHING USABLE IS LOGGED (module `oauth`, WARN), as a scheduled
/// one is: a 200 with an empty token, or one with bytes invalid in a header value.
#[test]
fn an_on_demand_exchange_landing_no_usable_token_is_logged_at_warn() {
    use crate::test_support::OAuthEvents;
    for (body, logged) in [
        (
            r#"{"access_token":"","expires_in":3600}"#,
            "empty access_token",
        ),
        (
            "{\"access_token\":\"tok\\u0001bad\",\"expires_in\":3600}",
            "bytes invalid in a header value",
        ),
    ] {
        let warn = OAuthEvents::default();
        tracing::subscriber::with_default(warn.subscriber(), || {
            let host = TestHost::new();
            let w = Arc::new(Scripted::default());
            let o = instance(&w);
            let h = exchange_binding(&o);
            let call = Ticket {
                slot: 5_000,
                generation: 1,
            };
            assert_eq!(
                test_support::fields(&o, &host, h, call, Some("s")).0,
                Outcome::Pending
            );
            w.ok(body);
            o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        });
        let m = warn.messages();
        assert_eq!(
            m.iter()
                .filter(|l| l.contains(logged) && l.contains("module=\"oauth\""))
                .count(),
            1,
            "{body}: {m:?}"
        );
    }
}

#[test]
fn a_token_type_other_than_bearer_fails_the_mint_and_an_absent_one_warns_once() {
    use crate::test_support::OAuthEvents;
    const SETTINGS: &str = r#"{"token_url":"https://idp.example/token","scope":"s"}"#;
    let host = TestHost::new();
    let cap = OAuthEvents::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
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
            .any(|l| l.contains("token_type") && l.contains("module=\"oauth\"")),
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
    let cap = OAuthEvents::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
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

#[test]
fn a_mint_with_no_plausible_wall_clock_fails_at_warn() {
    use crate::test_support::OAuthEvents;
    let host = TestHost::new();
    let cap = OAuthEvents::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
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
            .any(|l| l.contains("wall clock") && l.contains("module=\"oauth\"")),
        "{m:?}"
    );
}

#[test]
fn an_older_wall_clock_reading_never_moves_the_clock_back() {
    let o = Oauth::new(1);
    o.saw_wall(1_800_000_100);
    o.saw_wall(1_800_000_000);
    assert_eq!(o.wall_secs(), 1_800_000_100);
    o.saw_wall(0);
    assert_eq!(o.wall_secs(), 1_800_000_100, "no reading is no reading");
}

#[test]
fn an_empty_or_unpresentable_scheduled_token_is_logged_at_warn() {
    use crate::test_support::OAuthEvents;
    for (body, named) in [
        (r#"{"access_token":"","token_type":"Bearer"}"#, "empty"),
        (
            "{\"access_token\":\"bad\\u0001token\",\"token_type\":\"Bearer\"}",
            "header value",
        ),
    ] {
        let cap = OAuthEvents::default();
        tracing::subscriber::with_default(cap.subscriber(), || {
            let host = TestHost::new();
            let w = Arc::new(Scripted::default());
            let o = instance(&w);
            open(
                &o,
                style::OAUTH_CLIENT_CREDENTIALS,
                "id:secret",
                r#"{"token_url":"https://idp.example/token","scope":"s"}"#,
            );
            w.ok(body);
            o.tick(1_000, Ticket::NONE, Some(&host.host), &mut Diags::default());
        });
        let m = cap.messages();
        assert_eq!(cap.count("module=\"oauth\""), 1, "{body}: {m:?}");
        assert!(m[0].contains(named), "{body}: {m:?}");
    }
}

#[test]
fn a_resumed_mint_call_that_can_answer_forgets_its_parked_ticket() {
    let host = TestHost::new();
    let wire = Arc::new(Scripted::default());
    let (oauth, handle) = expired_and_failed(&wire, &host);
    let call = Ticket {
        slot: 1901,
        generation: 1,
    };
    assert_eq!(fields(&oauth, &host, handle, call).0, Outcome::Pending);
    let Some(Binding::Minted(cell)) = oauth.bound(handle) else {
        panic!("scheduled binding")
    };
    wire.ok(r#"{"access_token":"resumed","expires_in":3600}"#);

    assert_eq!(
        cell.tick(u64::MAX / 2, now_epoch(), Some(&Shared(wire.clone())))
            .1,
        Some(Report::Minted)
    );
    assert!(oauth.waiters.lock().unwrap().contains(&call));
    assert_eq!(
        fields(&oauth, &host, handle, call).1,
        "authorization: Bearer resumed"
    );
    assert!(
        !oauth.waiters.lock().unwrap().contains(&call),
        "an answered call no longer waits"
    );
}
