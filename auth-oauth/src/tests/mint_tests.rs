// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The self-minting machinery over a scripted need: the refresh schedule (ported from
//! `bearer_token_tests.rs`), the token response texts and cap (ported from the two mint bodies'
//! tests), and the tick-driven exchange with THE EXPIRED-TOKEN RULE.

use super::*;
use busbar_contract::abi::sdk::cred::SealedWrite;
use std::collections::VecDeque;

/// A read as the tests compare it: the header value shown (`Read`'s own `Debug` redacts it).
pub(crate) fn seen(r: Read<'_>) -> String {
    match r {
        Read::Header(h) => format!("Header({:?})", crate::test_support::bearer_text(h)),
        other => format!("{other:?}"),
    }
}

/// The unit tests' wall clock (epoch seconds): their doubles stand in for the host's `clock.now`.
/// The plugin itself reads no clock (THE DESIGN §1: "one clock"); see [`HostClock`].
pub(crate) fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One scripted read.
#[derive(Clone)]
pub(crate) enum Step {
    /// Nothing is ready yet.
    Pending,
    /// The response head, with this status.
    Head(u32),
    /// The response head, with this status and this `retry-after` value.
    HeadRetryAfter(u32, &'static str),
    /// Body bytes; `end` ends the frame.
    Body(Vec<u8>, bool),
    /// The exchange finished.
    Done,
    /// The connection failed.
    Fail(ConnError),
}

/// What one open sent: `(target, head, body)`.
type Sent = (String, Vec<(String, String)>, String);

/// A need whose every opened connection plays the next script, recording what it was asked to send.
#[derive(Default)]
pub(crate) struct Scripted {
    pub scripts: Mutex<VecDeque<Result<VecDeque<Step>, ConnError>>>,
    pub live: Mutex<Option<VecDeque<Step>>>,
    pub sent: Mutex<Vec<Sent>>,
    pub closed: Mutex<u32>,
}

impl Scripted {
    pub(crate) fn push(&self, steps: Vec<Step>) {
        self.scripts.lock().unwrap().push_back(Ok(steps.into()));
    }

    pub(crate) fn refuse(&self, e: ConnError) {
        self.scripts.lock().unwrap().push_back(Err(e));
    }

    /// A 200 carrying `body`, in one piece.
    pub(crate) fn ok(&self, body: &str) {
        self.push(vec![
            Step::Head(200),
            Step::Body(body.as_bytes().to_vec(), true),
        ]);
    }
}

impl Wire for Scripted {
    fn clock(&self) -> Option<HostClock> {
        Some(HostClock {
            wall_secs: now_epoch(),
            mono_ns: 0,
        })
    }

    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        _: u64,
    ) -> Result<ConnId, ConnError> {
        self.sent.lock().unwrap().push((
            req.target.clone(),
            req.fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            crate::test_support::sealed_text(body),
        ));
        let next = self
            .scripts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(ConnError::Refused))?;
        *self.live.lock().unwrap() = Some(next);
        Ok(ConnId(7))
    }

    fn read(&self, _: ConnId, buf: &mut [u8]) -> Result<Got, ConnError> {
        let mut live = self.live.lock().unwrap();
        let steps = live.as_mut().ok_or(ConnError::Closed)?;
        match steps.pop_front().ok_or(ConnError::Closed)? {
            Step::Pending => Err(ConnError::Pending),
            Step::Head(s) => Ok(Got {
                kind: PieceKind::Fields,
                len: 0,
                end: false,
                status: Some(s),
                retry_after: None,
            }),
            Step::HeadRetryAfter(s, value) => Ok(Got {
                kind: PieceKind::Fields,
                len: 0,
                end: false,
                status: Some(s),
                retry_after: retry_after(value.as_bytes()),
            }),
            Step::Body(b, end) => {
                buf[..b.len()].copy_from_slice(&b);
                Ok(Got {
                    kind: PieceKind::Body,
                    len: b.len(),
                    end,
                    status: None,
                    retry_after: None,
                })
            }
            Step::Done => Ok(Got {
                kind: PieceKind::Completion,
                len: 0,
                end: true,
                status: None,
                retry_after: None,
            }),
            Step::Fail(e) => Err(e),
        }
    }

    fn close(&self, _: ConnId) {
        *self.closed.lock().unwrap() += 1;
        *self.live.lock().unwrap() = None;
    }
}

pub(crate) fn client_credentials() -> Minter {
    Minter::ClientCredentials(
        oauth_client_credentials::build("id:secret", "https://idp.example/token", Some("s"))
            .unwrap(),
    )
}

const S: u64 = NS;

#[test]
fn next_refresh_never_sleeps_past_a_live_token_expiry() {
    let now = 1_000_000;

    assert_eq!(next_refresh_secs(now + 3600, now), 3600 - REFRESH_SKEW_SECS);

    for ttl in [1, 2, 10, 59, 299, 300] {
        let sleep = next_refresh_secs(now + ttl, now);
        assert_eq!(sleep, (ttl / 2).max(1), "ttl {ttl}");
    }

    assert_eq!(next_refresh_secs(now, now), MIN_SLEEP_SECS);
    assert_eq!(next_refresh_secs(now - 5, now), MIN_SLEEP_SECS);

    assert_eq!(next_refresh_secs(now + 301, now), 1.max(MIN_SLEEP_SECS));
}

#[test]
fn a_cached_token_is_redacted_in_debug() {
    let (t, invalid) = CachedToken::new(Zeroizing::new("super-secret-token".to_string()), 5);
    assert!(!invalid);
    assert!(!format!("{t:?}").contains("super-secret-token"));
}

#[test]
fn a_cached_token_omits_the_header_for_bytes_invalid_in_a_header_value() {
    let (t, invalid) = CachedToken::new(Zeroizing::new("tok\r\nen".to_string()), 5);
    assert!(invalid);
    assert!(t.header().is_none());
    let (t, invalid) = CachedToken::new(Zeroizing::new(String::new()), 0);
    assert!(
        !invalid,
        "the pre-first-mint sentinel is not a reportable token"
    );
    assert!(t.header().is_none());
}

/// The texts a failed exchange names: the status line plus, only when the body is JSON with an
/// RFC 6749 section 5.2 `error` code, that code; never other body text (a server may reflect the
/// request, client secret and assertion included, into the diag channel).
#[test]
fn a_refused_or_malformed_response_is_named_in_1_5_5_words() {
    let long = "x".repeat(500);
    let e = parse_response(401, long.as_bytes(), 0).unwrap_err();
    assert_eq!(e, "token endpoint returned 401 Unauthorized");
    let e = parse_response(400, br#"{"error":"invalid_client","x":"SECRETX"}"#, 0).unwrap_err();
    assert!(e.contains("invalid_client"), "{e}");
    assert!(!e.contains("SECRETX"), "{e}");
    let e = parse_response(400, b"SECRETY", 0).unwrap_err();
    assert!(!e.contains("SECRETY"), "{e}");

    for body in [
        r#"{"error":"bad \"SECRETZ\""}"#.to_string(),
        format!(r#"{{"error":"{}"}}"#, "SECRETZ".repeat(10)),
        r#"{"error":{"a":"SECRETZ"}}"#.to_string(),
    ] {
        let e = parse_response(400, body.as_bytes(), 0).unwrap_err();
        assert!(!e.contains("SECRETZ"), "{e}");
    }
    let e = parse_response(200, b"not json", 0).unwrap_err();
    assert!(e.starts_with("token response JSON invalid: "), "{e}");
    let (t, _) = parse_response(200, br#"{"access_token":"a","expires_in":"7200"}"#, 10).unwrap();
    assert_eq!(t.expires_at, 7210);
    assert_eq!(
        t.header().map(crate::test_support::bearer_text).as_deref(),
        Some("Bearer a")
    );
}

/// `expires_in` tolerates a number, a numeric string, a float, a decimal string and absence.
#[test]
fn token_response_tolerates_expires_in_as_number_string_or_absent() {
    for (body, want) in [
        (r#"{"access_token":"a","expires_in":3600}"#, 3600),
        (r#"{"access_token":"a","expires_in":"7200"}"#, 7200),
        (r#"{"access_token":"a"}"#, default_expires_in()),
        (r#"{"access_token":"a","expires_in":3600.0}"#, 3600),
        (r#"{"access_token":"a","expires_in":"3600.9"}"#, 3600),
    ] {
        let (t, _) = parse_response(200, body.as_bytes(), 0).unwrap();
        assert_eq!(t.expires_at, want, "{body}");
    }
}

/// `expires_in` that is not a non-negative finite number is a mint failure, never a token: a
/// negative number, a NaN or infinite string and a non-numeric string are each refused.
#[test]
fn token_response_refuses_an_expires_in_that_is_not_a_non_negative_number() {
    for body in [
        r#"{"access_token":"a","expires_in":-5}"#,
        r#"{"access_token":"a","expires_in":-1.5}"#,
        r#"{"access_token":"a","expires_in":"-5"}"#,
        r#"{"access_token":"a","expires_in":"NaN"}"#,
        r#"{"access_token":"a","expires_in":"inf"}"#,
        r#"{"access_token":"a","expires_in":"soon"}"#,
    ] {
        let e = parse_response(200, body.as_bytes(), 0)
            .err()
            .unwrap_or_else(|| panic!("{body} minted a token"));
        assert!(
            e.starts_with("token response JSON invalid: "),
            "{body}: {e}"
        );
    }
}

#[test]
fn an_escaped_access_token_is_read_into_one_wiped_buffer_never_by_the_decoder() {
    fn held_as<T>(_: &T) -> &'static str {
        std::any::type_name::<T>()
    }
    let body = r#"{"token_type":"Bearer","access_token":"ya29.a\/bAc","expires_in":60}"#;
    let tok: TokenResponse = serde_json::from_str(body).expect("a well-formed response");
    assert!(
        held_as(&tok._access_token).contains("IgnoredAny"),
        "the decoder skips the token, it never unescapes it: {}",
        held_as(&tok._access_token)
    );
    let read = access_token(body).expect("the token");
    assert!(held_as(&read).contains("Zeroizing"), "{}", held_as(&read));
    assert_eq!(read.as_str(), "ya29.a/bAc");
    assert!(
        read.capacity() <= body.len(),
        "sized once to the escaped length"
    );
    let (t, invalid) = parse_response(200, body.as_bytes(), 0).expect("a minted token");
    assert!(!invalid);
    assert_eq!(
        t.header().map(crate::test_support::bearer_text).as_deref(),
        Some("Bearer ya29.a/bAc")
    );
    assert_eq!(t.expires_at, 60);

    let nested = r#"{"x":{"access_token":"no"},"l":["access_token"],"access_token":"yes\n"}"#;
    assert_eq!(access_token(nested).expect("the token").as_str(), "yes\n");

    assert_eq!(
        parse_response(200, br#"{"access_token":1}"#, 0).unwrap_err(),
        "token response JSON invalid: a field is missing or has the wrong type (the decoder's \
         text is withheld)"
    );

    let e = parse_response(200, br#"{"expires_in":60}"#, 0).unwrap_err();
    assert!(e.contains("missing field `access_token`"), "{e}");
}

/// A token landed on the first tick: the header is presented, the cell is ready, and the next tick
/// is scheduled a skew ahead of expiry.
#[test]
fn the_first_tick_mints_and_the_request_path_presents_it() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"tok-1","expires_in":3600}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert!(!m.is_ready());
    assert_eq!(
        m.read(now_epoch(), seen),
        format!("Refuse({NO_TOKEN:?})"),
        "nothing minted yet: refuse locally rather than sending an anonymous request"
    );
    let (due, report) = m.tick(1_000, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted));
    assert!(m.is_ready());
    assert_eq!(m.read(now_epoch(), seen), "Header(\"Bearer tok-1\")");
    assert_eq!(due, 1_000 + (3600 - REFRESH_SKEW_SECS) * S);
    assert_eq!(*w.closed.lock().unwrap(), 1);
    let sent = w.sent.lock().unwrap();
    assert_eq!(sent[0].0, "https://idp.example/token");
    assert_eq!(
        sent[0].2,
        "grant_type=client_credentials&client_id=id&client_secret=secret&scope=s"
    );
}

/// A token endpoint's `expires_in` is untrusted: one so large that `ahead * NS` would overflow
/// u64 schedules the refresh a day on (L4), never a wrapped (arbitrary) instant.
#[test]
fn a_huge_expires_in_schedules_no_overflowed_refresh() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"tok","expires_in":100000000000}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, report) = m.tick(1_000, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted));
    assert_eq!(m.read(now_epoch(), seen), "Header(\"Bearer tok\")");
    assert_eq!(
        due,
        1_000 + MAX_REFRESH_SECS * S,
        "the refresh is a day on, not a wrapped instant"
    );
}

/// A read with nothing ready leaves the exchange in flight; the next tick finishes it.
#[test]
fn a_pending_read_is_finished_on_a_later_tick() {
    let w = Scripted::default();
    w.push(vec![
        Step::Pending,
        Step::Head(200),
        Step::Body(br#"{"access_token":"t"}"#.to_vec(), false),
        Step::Done,
    ]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(m.tick(0, now_epoch(), Some(&w)), (IN_FLIGHT_POLL_NS, None));
    let (_, report) = m.tick(IN_FLIGHT_POLL_NS, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted));
}

/// THE CAP: a body past the kernel's `max_response_bytes` is refused before any JSON parse, in
/// 1.5.5's words.
#[test]
fn a_response_body_over_the_cap_is_refused() {
    let w = Scripted::default();
    let body = serde_json::json!({ "access_token": "a".repeat(300 * 1024), "expires_in": 3600 })
        .to_string();
    let mut steps = vec![Step::Head(200)];
    for chunk in body.as_bytes().chunks(16 * 1024) {
        steps.push(Step::Body(chunk.to_vec(), false));
    }
    steps.push(Step::Done);
    w.push(steps);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (_, report) = m.tick(0, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint response exceeded the 262144-byte cap; refusing to parse a truncated \
             token response"
                .to_string()
        ))
    );
    assert!(!m.is_ready());
}

/// A connection dropped mid-response, and a refused open, are failures named as 1.5.5 named them.
#[test]
fn a_dropped_or_refused_exchange_is_a_failure() {
    let w = Scripted::default();
    w.push(vec![Step::Head(200), Step::Fail(ConnError::Closed)]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, report) = m.tick(0, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint connection failed mid-response; refusing to parse a partial token \
             response"
                .to_string()
        ))
    );
    assert_eq!(due, MIN_SLEEP_SECS * S, "a failure retries at MIN_SLEEP");
    w.refuse(ConnError::Refused);
    let (_, report) = m.tick(due, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint request failed: refused".to_string()
        ))
    );
}

/// A connection close before the protocol's terminal piece is an outage, even when the
/// partial response body happens to be complete JSON.
#[test]
fn a_close_before_the_terminal_piece_is_an_outage() {
    let w = Scripted::default();
    w.push(vec![
        Step::Head(200),
        Step::Body(
            br#"{"access_token":"closed-tok","expires_in":3600}"#.to_vec(),
            false,
        ),
        Step::Fail(ConnError::Closed),
    ]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (_, report) = m.tick(0, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint connection failed mid-response; refusing to parse a partial token response"
                .to_string()
        ))
    );
    assert!(!m.is_ready());
    assert!(m.outage());
    assert_eq!(*w.closed.lock().unwrap(), 1);
}

/// An exchange still unread at the mint deadline is abandoned in 1.5.5's words.
#[test]
fn an_exchange_past_the_mint_deadline_is_abandoned() {
    let w = Scripted::default();
    w.push(vec![Step::Pending, Step::Pending]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    m.tick(0, now_epoch(), Some(&w));
    let (_, report) = m.tick(MINT_DEADLINE_SECS * S, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint response was not read before the mint deadline; refusing to parse a \
             partial token response"
                .to_string()
        ))
    );
    assert_eq!(*w.closed.lock().unwrap(), 1, "the connection is closed");
}

/// A 200 with an empty token is a retryable failure, never stored (the permanent-wedge guard).
#[test]
fn an_empty_token_is_a_failure_not_a_token() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":""}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(
        m.tick(0, now_epoch(), Some(&w)),
        (MIN_SLEEP_SECS * S, Some(Report::EmptyToken))
    );
    assert!(!m.is_ready());
}

/// A SHORT-LIVED EXCHANGED TOKEN CANNOT DRIVE A TIGHT EXCHANGE LOOP: an on-demand cell whose token
/// lives a second is exchanged again no sooner than `MIN_MINT_INTERVAL_SECS` after it landed, however
/// many requests find it expired, and a token too short-lived for half its life to reach the floor
/// is presented up to its expiry, never past it. RED before the fix: the request one second on
/// armed an exchange due at once, and the 3 s token was not presented after its first second.
#[test]
fn a_short_lived_exchanged_token_is_not_exchanged_again_before_the_floor() {
    let scoped = |w: &Scripted, body: &str| {
        let exchange = Arc::new(token_exchange::build(
            "subject",
            "https://as.example/token",
            token_exchange::ACCESS_TOKEN_TYPE,
            "https://tools.example/rpc",
        ));
        w.ok(body);
        Minted::new(
            Minter::TokenExchange(token_exchange::Scoped::new(exchange, "s")),
            DEFAULT_MAX_RESPONSE_BYTES,
        )
    };
    let wall = now_epoch();
    let w = Scripted::default();
    let cell = scoped(
        &w,
        r#"{"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","access_token":"one","token_type":"Bearer","expires_in":1}"#,
    );
    assert_eq!(
        cell.read(wall, seen),
        "Wait",
        "no token yet: the exchange is armed"
    );
    assert_eq!(cell.tick(0, wall, Some(&w)).1, Some(Report::Minted));
    assert_eq!(cell.read(wall, seen), "Header(\"Bearer one\")");
    assert_eq!(
        cell.read(wall + 1, seen),
        "Wait",
        "expired: never presented"
    );
    assert_eq!(
        cell.tick(S, wall + 1, Some(&w)),
        (MIN_MINT_INTERVAL_SECS * S, None),
        "the request armed the next exchange no sooner than the floor"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 1);
    w.ok(r#"{"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","access_token":"two","token_type":"Bearer","expires_in":1}"#);
    assert_eq!(
        cell.tick(MIN_MINT_INTERVAL_SECS * S, wall + 5, Some(&w)).1,
        Some(Report::Minted)
    );
    assert_eq!(cell.read(wall + 5, seen), "Header(\"Bearer two\")");

    let w = Scripted::default();
    let cell = scoped(
        &w,
        r#"{"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","access_token":"three","token_type":"Bearer","expires_in":3}"#,
    );
    assert_eq!(cell.read(wall, seen), "Wait");
    assert_eq!(cell.tick(0, wall, Some(&w)).1, Some(Report::Minted));
    assert_eq!(
        cell.read(wall + 2, seen),
        "Header(\"Bearer three\")",
        "presented while it lives, since it cannot be exchanged again before the floor"
    );
    assert_eq!(cell.read(wall + 3, seen), "Wait", "never past its expiry");
}

/// AN EXPIRED TOKEN IS NEVER PRESENTED (RFC 6750 §3.1): a token past its expiry whose refresh has
/// not failed (the host was suspended: the wall clock moved, the tick clock did not) answers
/// `Wait` and brings its refresh forward; once that refresh has failed the call fails closed
/// (`EXPIRED`) and the retry keeps its back-off; a token not yet expired is still presented while
/// refreshes fail. RED before the fix: the first expired read presented `Bearer old`.
#[test]
fn an_expired_token_is_never_presented_and_a_failed_refresh_fails_the_call_closed() {
    let wall = now_epoch();
    let w = Scripted::default();
    w.ok(r#"{"access_token":"old","expires_in":60}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, _) = m.tick(0, wall, Some(&w));
    assert_eq!(
        due,
        30 * S,
        "1.5.5's half-life schedule for a one-minute token"
    );
    let later = wall + 3600;
    assert_eq!(
        m.read(later, seen),
        "Wait",
        "expired, refresh not failed: not presented, the refresh is waited for"
    );
    assert!(!m.presents(later), "an expired token is not ready");
    w.push(vec![Step::Head(500), Step::Body(b"down".to_vec(), true)]);
    let (due, report) = m.tick(MIN_MINT_INTERVAL_SECS * S, wall, Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint returned 500 Internal Server Error".to_string()
        )),
        "the refresh was brought forward to the floor after the last mint"
    );
    assert_eq!(due, (MIN_MINT_INTERVAL_SECS + MIN_SLEEP_SECS) * S);
    assert_eq!(m.read(later, seen), format!("Refuse({EXPIRED:?})"));
    assert_eq!(
        m.tick(due - 1, wall, Some(&w)),
        (due, None),
        "the failed refresh keeps its back-off: a refused call does not bring it forward"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 2);
    assert_eq!(
        m.read(wall, seen),
        "Header(\"Bearer old\")",
        "not yet expired: served even while refreshes fail"
    );
    w.ok(r#"{"access_token":"new","expires_in":3600}"#);
    assert_eq!(m.tick(due, wall, Some(&w)).1, Some(Report::Minted));
    assert_eq!(m.read(later - 1, seen), "Header(\"Bearer new\")");
}

/// A HOST SUSPEND DOES NOT PRESENT THE STALE BEARER: a one-hour token read two hours on (the tick
/// clock barely moved) waits, and the refresh it brings forward is due at once, on the next tick,
/// rather than at the old schedule. RED before the fix: the read presented `Bearer stale` and the
/// tick minted nothing until 3300 s on the tick clock.
#[test]
fn a_token_expired_across_a_host_suspend_is_refreshed_at_once_not_presented() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"stale","expires_in":3600}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let wall = now_epoch();
    let (due, _) = m.tick(0, wall, Some(&w));
    assert_eq!(due, (3600 - REFRESH_SKEW_SECS) * S);
    let resumed = wall + 7200;
    assert_eq!(m.read(resumed, seen), "Wait");
    w.ok(r#"{"access_token":"fresh","expires_in":3600}"#);
    let tick_clock = 60 * S;
    assert_eq!(
        m.tick(tick_clock, resumed, Some(&w)).1,
        Some(Report::Minted),
        "the brought-forward refresh is due at once"
    );
    assert_eq!(m.read(resumed, seen), "Header(\"Bearer fresh\")");
}

/// A PROVIDER ISSUING VERY SHORT TOKENS CANNOT DRIVE A TIGHT MINT LOOP: a scheduled token that
/// lives a second or two is re-minted no sooner than `MIN_MINT_INTERVAL_SECS` after it landed (1.5.5
/// re-minted it about once a second), while a token living at least twice the floor keeps 1.5.5's
/// schedule exactly. Such a provider still mints and its token is presented while it lives; a call
/// after its expiry waits for the next mint (it does not bring it before the floor). RED before the
/// fix: the 1 s and 2 s tokens were due again at 1 s.
#[test]
fn a_token_of_a_second_or_two_is_reminted_no_more_often_than_the_floor() {
    let now = 1_000_000;
    for (ttl, want) in [
        (1, 5),
        (2, 5),
        (9, 5),
        (10, 5),
        (11, 5),
        (20, 10),
        (60, 30),
        (3600, 3300),
    ] {
        assert_eq!(scheduled_refresh_secs(now + ttl, now), want, "ttl {ttl}");
        assert_eq!(
            scheduled_refresh_secs(now + ttl, now),
            next_refresh_secs(now + ttl, now).max(MIN_MINT_INTERVAL_SECS),
            "ttl {ttl}: 1.5.5's schedule, floored"
        );
    }

    let w = Scripted::default();
    w.ok(r#"{"access_token":"brief","token_type":"Bearer","expires_in":1}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let wall = now_epoch();
    let (due, report) = m.tick(0, wall, Some(&w));
    assert_eq!(report, Some(Report::Minted), "a 1 s token still mints");
    assert_eq!(due, MIN_MINT_INTERVAL_SECS * S, "not once a second");
    assert_eq!(
        m.read(wall, seen),
        "Header(\"Bearer brief\")",
        "presented while it lives"
    );
    assert_eq!(m.read(wall + 1, seen), "Wait", "expired: never presented");
    assert_eq!(
        m.tick(S, wall + 1, Some(&w)),
        (MIN_MINT_INTERVAL_SECS * S, None),
        "a call after expiry does not bring the mint before the floor"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 1);
    w.ok(r#"{"access_token":"next","token_type":"Bearer","expires_in":1}"#);
    assert_eq!(
        m.tick(MIN_MINT_INTERVAL_SECS * S, wall + 5, Some(&w)).1,
        Some(Report::Minted)
    );
    assert_eq!(m.read(wall + 5, seen), "Header(\"Bearer next\")");
}

/// A reply code too large for 16 bits is not read as another code: 65736 is 200 modulo 65536, but
/// it is no success, so its (valid-looking) body is not taken as a token.
#[test]
fn a_reply_code_past_sixteen_bits_is_a_failure_not_a_token() {
    let w = Scripted::default();
    w.push(vec![
        Step::Head(65736),
        Step::Body(br#"{"access_token":"t","expires_in":3600}"#.to_vec(), true),
    ]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (_, report) = m.tick(0, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint returned status 65736, which is no HTTP status code".to_string()
        )),
        "the code is named as the host reported it"
    );
}

/// THE LOSSY TEXT OF A TOKEN RESPONSE IS BUILT ONCE: a body with bytes that are not UTF-8 becomes
/// the text `from_utf8_lossy` gives, in a string sized exactly first, so it never grows (a growth
/// would free an unwiped copy of the access token).
#[test]
fn the_lossy_body_is_one_exactly_sized_string() {
    let raw: &[u8] = b"{\"access_token\":\"a\xffb\xc3\x28c\xe2\x82\",\"x\":\"\xf0\x90\"}";
    let got = lossy_wiped(raw);
    assert_eq!(got.as_str(), String::from_utf8_lossy(raw));
    assert_eq!(got.capacity(), got.len(), "sized once, no growth");
}

/// Without a granted need nothing mints, and the failure says so once per retry period.
#[test]
fn no_granted_need_mints_nothing() {
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, report) = m.tick(0, now_epoch(), None);
    assert!(matches!(report, Some(Report::MintFailed(_))));
    assert_eq!(due, MIN_SLEEP_SECS * S);
    assert_eq!(m.tick(1, now_epoch(), None), (due, None));
}

/// THE TOKEN ENDPOINT NEEDS ARE DECLARED IN THE `provider` EGRESS CLASS (commit 580ceb9): the
/// class the connector refuses a private address in unless `advanced.allow_destinations` names it,
/// each need pinned to its setting. The refusal itself is the host connector's.
#[test]
fn the_token_endpoint_needs_are_declared_in_the_provider_class() {
    use busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER;
    assert_eq!(crate::NEEDS.len(), 2, "token_url and token_uri");
    for (i, n) in crate::NEEDS.iter().enumerate() {
        assert_ne!(n.target_from.len, 0, "need {i} is pinned to its setting");
        assert_eq!(n.egress_class, EGRESS_PROVIDER, "need {i}");
    }
}

#[test]
fn a_redirecting_token_endpoint_fails_the_mint() {
    for (status, named) in [
        (301, "301 Moved Permanently"),
        (302, "302 Found"),
        (307, "307 Temporary Redirect"),
        (308, "308 Permanent Redirect"),
    ] {
        let w = Scripted::default();
        w.push(vec![
            Step::Head(status),
            Step::Body(b"{\"access_token\":\"from-a-redirect\"}".to_vec(), true),
        ]);
        w.ok(r#"{"access_token":"never-asked-for","expires_in":3600}"#);
        let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
        let (_, report) = m.tick(0, now_epoch(), Some(&w));
        assert_eq!(
            report,
            Some(Report::MintFailed(format!(
                "token endpoint returned {named}"
            ))),
            "{status}"
        );
        assert_eq!(w.sent.lock().unwrap().len(), 1, "{status}: never followed");
        assert!(!m.is_ready(), "{status}: no token");
    }
}

/// THE TOKEN REQUEST FORM IS THE CHIP'S (`cred::FormBody`): it carries the client secret, the
/// subject token or the signed assertion as sealed values, and is written byte for byte as
/// `serde_urlencoded` (reqwest's `.form()`) wrote it, for every byte.
#[test]
fn the_form_is_serde_urlencoded_byte_for_byte() {
    use busbar_contract::abi::sdk::test_support::chip::cred;
    let mut every: String = (0_u8..=0x7f).map(char::from).collect();
    every.push_str("\u{e9}\u{1F600} +&=%");
    let pairs = [
        ("grant_type", "client_credentials"),
        ("client_secret", every.as_str()),
        ("scope", "https://cognitiveservices.azure.com/.default a b"),
        ("empty", ""),
    ];
    let form = busbar_contract::abi::sdk::cred::FormBody::new()
        .public(pairs[0].0, pairs[0].1)
        .sealed(pairs[1].0, &cred(pairs[1].1))
        .public(pairs[2].0, pairs[2].1)
        .public(pairs[3].0, pairs[3].1);
    assert_eq!(
        crate::test_support::form_text(&form),
        serde_urlencoded::to_string(pairs).expect("a form")
    );
}

#[test]
fn an_exchange_in_flight_reserves_no_buffer_the_size_of_the_cap() {
    let w = Scripted::default();
    w.push(vec![
        Step::Head(200),
        Step::Body(br#"{"access_token":"#.to_vec(), false),
        Step::Pending,
        Step::Body(br#""t"}"#.to_vec(), true),
    ]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(m.tick(0, now_epoch(), Some(&w)), (IN_FLIGHT_POLL_NS, None));
    let held = match &*m.attempt.lock().unwrap() {
        Attempt::InFlight { body, .. } => body.capacity(),
        Attempt::Idle { .. } | Attempt::Opening { .. } => panic!("the exchange is in flight"),
    };
    assert!(
        held <= READ_BUF_BYTES,
        "an in-flight exchange holds {held} bytes for a {DEFAULT_MAX_RESPONSE_BYTES}-byte cap"
    );
    let (_, report) = m.tick(IN_FLIGHT_POLL_NS, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted), "the body still reads whole");

    let w = Scripted::default();
    w.ok(r#"{"access_token":"t","expires_in":3600}"#);
    let m = Minted::new(client_credentials(), usize::MAX);
    assert_eq!(m.tick(0, now_epoch(), Some(&w)).1, Some(Report::Minted));
}

/// AN ON-DEMAND READ NEVER PRESENTS A TOKEN SNAPSHOTTED BEFORE THE EXCHANGE LANDED: a read racing
/// the tick that stores the token either waits or presents the new token. It never answers
/// `Nothing` (an unauthenticated token-exchange call) for a cell whose exchange succeeds.
/// A test-only callback pins the usability judgement while the real mint publishes its token;
/// production sets no callback (passing the seam is one unset-cell read).
#[test]
fn an_on_demand_read_racing_the_exchange_never_presents_nothing() {
    let exchange = Arc::new(token_exchange::build(
        "subject",
        "https://as.example/token",
        token_exchange::ACCESS_TOKEN_TYPE,
        "https://tools.example/rpc",
    ));
    let wire = Scripted::default();
    wire.ok(r#"{"token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","access_token":"tok-x","expires_in":3600}"#);
    let cell = Minted::new(
        Minter::TokenExchange(token_exchange::Scoped::new(exchange, "s")),
        DEFAULT_MAX_RESPONSE_BYTES,
    );
    let (pause, arrived, release) = crate::test_support::pause_once();
    assert!(cell.before_usable.set(pause).is_ok(), "the seam is unset");
    let answer = std::thread::scope(|threads| {
        let reader = threads.spawn(|| cell.read(now_epoch(), seen));

        arrived.recv().unwrap();
        let report = cell.tick(1_000, now_epoch(), Some(&wire)).1;
        release.send(()).unwrap();
        assert_eq!(report, Some(Report::Minted));
        reader.join().unwrap()
    });
    assert_eq!(answer, "Header(\"Bearer tok-x\")");
}

#[test]
fn no_mint_without_a_plausible_wall_clock() {
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string();
    for wall in [0, 1_700_000_000, 1_767_225_599] {
        let w = Scripted::default();
        w.ok(r#"{"access_token":"t","token_type":"Bearer","expires_in":3600}"#);
        let m = Minted::new(
            Minter::JwtBearer(Box::new(
                jwt_bearer::build(&sa, None, None).expect("the service account builds"),
            )),
            DEFAULT_MAX_RESPONSE_BYTES,
        );
        let (due, report) = m.tick(0, wall, Some(&w));
        assert!(
            matches!(&report, Some(Report::MintFailed(e)) if e.contains("wall clock")),
            "{wall}: {report:?}"
        );
        assert!(
            w.sent.lock().unwrap().is_empty(),
            "{wall}: nothing was sent"
        );
        assert_eq!(due, MIN_SLEEP_SECS * S, "{wall}: it retries on schedule");
        let (_, report) = m.tick(due, 1_767_225_600, Some(&w));
        assert_eq!(
            report,
            Some(Report::Minted),
            "{wall}: a plausible clock mints"
        );
    }
}

#[test]
fn each_failed_exchange_arm_is_named_and_judged_outage_or_not() {
    let fail = |setup: &dyn Fn(&Scripted), later: Option<u64>| {
        let w = Scripted::default();
        setup(&w);
        let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
        let (_, mut report) = m.tick(0, now_epoch(), Some(&w));
        if let Some(at) = later {
            report = m.tick(at, now_epoch(), Some(&w)).1;
        }
        let Some(Report::MintFailed(e)) = report else {
            panic!("a failed mint: {report:?}")
        };
        assert!(!m.is_ready());
        (e, m.outage())
    };
    for (e, text) in [
        (ConnError::Timeout, "timed out"),
        (ConnError::Closed, "connection closed"),
        (ConnError::Fault, "fault"),
    ] {
        assert_eq!(
            fail(&|w| w.refuse(e), None),
            (format!("token endpoint request failed: {text}"), true),
            "open: {e:?}"
        );
        assert!(
            fail(&|w| w.push(vec![Step::Fail(e)]), None).1,
            "read: {e:?}"
        );
    }
    assert_eq!(
        fail(&|w| w.refuse(ConnError::Refused), None),
        ("token endpoint request failed: refused".to_string(), false),
        "a refusal by the host's own rules is no outage"
    );
    assert_eq!(
        fail(&|w| w.push(vec![Step::Fail(ConnError::Timeout)]), None).0,
        "token endpoint request failed: timed out"
    );
    let (e, outage) = fail(
        &|w| w.push(vec![Step::Head(200), Step::Fail(ConnError::Closed)]),
        None,
    );
    assert!(e.contains("mid-response"), "{e}");
    assert!(outage, "a connection lost mid-response is an outage");
    let (e, outage) = fail(
        &|w| w.push(vec![Step::Pending, Step::Pending]),
        Some(MINT_DEADLINE_SECS * S),
    );
    assert!(e.contains("mint deadline"), "{e}");
    assert!(outage, "the deadline is an outage");
}

#[test]
fn an_already_expired_token_is_a_failed_mint() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"stale","token_type":"Bearer","expires_in":0}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, report) = m.tick(0, now_epoch(), Some(&w));
    assert!(
        matches!(&report, Some(Report::MintFailed(e)) if e.contains("expires_in")),
        "{report:?}"
    );
    assert_eq!(due, MIN_SLEEP_SECS * S, "retried on schedule");
    assert!(!m.is_ready());
    assert_eq!(m.read(now_epoch(), seen), "Refuse(\"no OAuth token could be minted for this binding (see diagnostics BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and the mint retries on its schedule\")");
}

#[test]
fn a_huge_expires_in_refreshes_within_24_hours() {
    for expires_in in ["100000000000", "18446744073709551615", "31536000"] {
        let w = Scripted::default();
        w.ok(&format!(
            r#"{{"access_token":"tok","token_type":"Bearer","expires_in":{expires_in}}}"#
        ));
        let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
        let (due, report) = m.tick(1_000, now_epoch(), Some(&w));
        assert_eq!(report, Some(Report::Minted), "{expires_in}");
        assert_eq!(
            due,
            1_000 + 86_400 * S,
            "{expires_in}: refreshed within a day"
        );
    }
}

/// A need whose reply never ends: every read is another head piece, until a safety stop (a fault
/// after 100 000 reads, so a loop with no bound ends the test rather than hangs it). With
/// `clocked`, each clock reading is one second on the monotonic clock past the last.
#[derive(Default)]
struct Endless {
    clocked: bool,
    reads: std::sync::atomic::AtomicU64,
    readings: std::sync::atomic::AtomicU64,
}

impl Wire for Endless {
    fn open(&self, _: &TokenRequest, _: &mut SealedWrite, _: u64) -> Result<ConnId, ConnError> {
        Ok(ConnId(9))
    }
    fn read(&self, _: ConnId, _: &mut [u8]) -> Result<Got, ConnError> {
        if self.reads.fetch_add(1, Ordering::AcqRel) >= 100_000 {
            return Err(ConnError::Fault);
        }
        Ok(Got {
            kind: PieceKind::Fields,
            len: 0,
            end: false,
            status: Some(200),
            retry_after: None,
        })
    }
    fn close(&self, _: ConnId) {}
    fn clock(&self) -> Option<HostClock> {
        let n = self.readings.fetch_add(1, Ordering::AcqRel);
        self.clocked.then(|| HostClock {
            wall_secs: now_epoch(),
            mono_ns: n * S,
        })
    }
}

#[test]
fn a_reply_that_never_ends_is_bounded_in_one_tick() {
    let clocked = Endless {
        clocked: true,
        ..Endless::default()
    };
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (_, report) = m.tick(0, now_epoch(), Some(&clocked));
    assert!(
        matches!(&report, Some(Report::MintFailed(e)) if e.contains("mint deadline")),
        "{report:?}"
    );
    assert!(
        clocked.reads.load(Ordering::Acquire) <= 2 * MINT_DEADLINE_SECS,
        "abandoned at the deadline on the host's clock"
    );

    let bare = Endless::default();
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, report) = m.tick(0, now_epoch(), Some(&bare));
    assert_eq!((due, report), (IN_FLIGHT_POLL_NS, None), "it yields");
    assert!(
        bare.reads.load(Ordering::Acquire) <= 10_000,
        "a bounded number of reads: {}",
        bare.reads.load(Ordering::Acquire)
    );
    assert!(!m.idle(), "the exchange goes on at the next tick");
}

#[test]
fn escaped_member_names_mint_the_exact_token_and_keep_error_redaction() {
    let wire = Scripted::default();
    wire.ok(r#"{"access\u005ftoken":"a\/b\u00e9","expires_in":3600}"#);
    let cell = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(
        cell.tick(0, now_epoch(), Some(&wire)).1,
        Some(Report::Minted)
    );
    assert_eq!(cell.read(now_epoch(), seen), "Header(\"Bearer a/bé\")");
    assert_eq!(*wire.closed.lock().unwrap(), 1);
    let reason = parse_response(
        400,
        br#"{"err\u006fr":"invalid_client","error_description":"never-echo-me"}"#,
        0,
    )
    .unwrap_err();
    assert!(reason.contains("invalid_client"));
    assert!(!reason.contains("never-echo-me"));
}

#[test]
fn invalid_surrogate_pairs_never_become_a_different_minted_token() {
    for escaped in [
        r"\uD800\uE000",
        r"\uD800\uFFFF",
        r"\uDBFF\uE000",
        r"\uD800\u0041",
        r"\uD800",
        r"\uDC00",
    ] {
        let wire = Scripted::default();
        wire.ok(&format!(
            r#"{{"access_token":"{escaped}","expires_in":3600}}"#
        ));
        let cell = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
        assert!(
            matches!(
                cell.tick(0, now_epoch(), Some(&wire)).1,
                Some(Report::MintFailed(_))
            ),
            "invalid surrogate was minted: {escaped}"
        );
        assert!(!cell.is_ready());
        assert_eq!(*wire.closed.lock().unwrap(), 1);
    }
    for (escaped, expected) in [
        (r"\uD800\uDC00", "𐀀"),
        (r"\uDBFF\uDFFF", "\u{10ffff}"),
        (r"\uD83D\uDE00", "😀"),
    ] {
        let body = format!(r#"{{"access_token":"{escaped}","expires_in":3600}}"#);
        let (token, invalid) = parse_response(200, body.as_bytes(), 0).unwrap();
        assert!(!invalid);
        assert_eq!(
            seen(Read::Header(token.header().unwrap())),
            format!("Header({:?})", format!("Bearer {expected}"))
        );
    }
}

#[test]
fn response_cap_accepts_exact_length_and_refuses_the_next_byte_across_chunks() {
    const CAP: usize = 1024;
    for (size, accepted) in [(CAP - 1, true), (CAP, true), (CAP + 1, false)] {
        let wire = Scripted::default();
        let mut body = br#"{"access_token":"exact-cap","expires_in":3600}"#.to_vec();
        body.resize(size, b' ');
        let mut steps = vec![Step::Head(200)];
        for chunk in body.chunks(127) {
            steps.push(Step::Body(chunk.to_vec(), false));
        }
        steps.push(Step::Done);
        wire.push(steps);
        let cell = Minted::new(client_credentials(), CAP);
        let report = cell.tick(0, now_epoch(), Some(&wire)).1;
        if accepted {
            assert_eq!(report, Some(Report::Minted));
            assert_eq!(cell.read(now_epoch(), seen), "Header(\"Bearer exact-cap\")");
        } else {
            assert!(
                matches!(report, Some(Report::MintFailed(ref reason)) if reason.contains("1024-byte cap"))
            );
            assert!(!cell.is_ready());
        }
        assert_eq!(*wire.closed.lock().unwrap(), 1);
    }
}

#[test]
fn a_closed_token_response_needs_its_protocol_end_and_a_head() {
    for steps in [
        vec![
            Step::Head(200),
            Step::Body(
                br#"{"access_token":"complete-json-but-no-end","expires_in":3600}"#.to_vec(),
                false,
            ),
            Step::Fail(ConnError::Closed),
        ],
        vec![Step::Body(
            br#"{"access_token":"body-without-head","expires_in":3600}"#.to_vec(),
            true,
        )],
    ] {
        let wire = Scripted::default();
        wire.push(steps);
        let cell = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
        assert!(matches!(
            cell.tick(0, now_epoch(), Some(&wire)).1,
            Some(Report::MintFailed(_))
        ));
        assert!(!cell.is_ready());
        assert!(
            cell.outage(),
            "an incomplete protocol response is an outage"
        );
        assert_eq!(*wire.closed.lock().unwrap(), 1);
    }
    let wire = Scripted::default();
    wire.push(vec![
        Step::Head(200),
        Step::Body(
            br#"{"access_token":"ended","expires_in":3600}"#.to_vec(),
            false,
        ),
        Step::Done,
    ]);
    let cell = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(
        cell.tick(0, now_epoch(), Some(&wire)).1,
        Some(Report::Minted)
    );
    assert_eq!(cell.read(now_epoch(), seen), "Header(\"Bearer ended\")");
}

/// A BYTE THAT IS NOT UTF-8 NEVER BECOMES PART OF A MINTED TOKEN: the body is read lossily as
/// 1.5.5 read it, but an access token holding a replaced byte is one the endpoint never issued, so
/// it is not presented (as 1.5.5's header check refused it); a bad byte elsewhere in the body
/// leaves the token as issued, and an error body is still read for its status line.
#[test]
fn a_byte_that_is_not_utf8_never_becomes_part_of_a_minted_token() {
    let (_, invalid) =
        parse_response(200, b"{\"access_token\":\"a\xffb\",\"expires_in\":3600}", 0).unwrap();
    assert!(invalid, "a replaced byte in the token is not presented");
    let w = Scripted::default();
    w.push(vec![
        Step::Head(200),
        Step::Body(
            b"{\"access_token\":\"a\xffb\",\"expires_in\":3600}".to_vec(),
            true,
        ),
    ]);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(
        m.tick(0, now_epoch(), Some(&w)).1,
        Some(Report::TokenInvalidBytes)
    );
    assert!(!m.is_ready(), "nothing was stored");
    let (t, invalid) = parse_response(
        200,
        b"{\"access_token\":\"t\",\"note\":\"caf\xe9\",\"expires_in\":3600}",
        0,
    )
    .unwrap();
    assert!(!invalid, "a bad byte outside the token leaves it as issued");
    assert_eq!(
        seen(Read::Header(t.header().unwrap())),
        "Header(\"Bearer t\")"
    );
    let (t, invalid) = parse_response(
        200,
        "{\"access_token\":\"a\u{FFFD}b\",\"expires_in\":3600}".as_bytes(),
        0,
    )
    .unwrap();
    assert!(!invalid, "a U+FFFD the endpoint sent is its token");
    assert!(t.header().is_some());
    assert_eq!(
        parse_response(503, b"\xff", 0).err().as_deref(),
        Some("token endpoint returned 503 Service Unavailable")
    );
}

/// EVERY HTTP-DATE FORMAT IS READ (RFC 9110 §5.6.7: a recipient MUST accept all three): a
/// `Retry-After` in the obsolete RFC 850 or asctime form states the same instant as IMF-fixdate.
#[test]
fn retry_after_reads_every_http_date_format() {
    let at = Some(RetryAfter::At(784_111_777));
    for v in [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
    ] {
        assert_eq!(retry_after(v.as_bytes()), at, "{v}");
    }
    assert_eq!(
        retry_after(b"Friday, 15-Jan-27 08:03:20 GMT"),
        retry_after(b"Fri, 15 Jan 2027 08:03:20 GMT"),
        "a two-digit year near the clock floor is this century's"
    );
    assert_eq!(retry_after(b"120"), Some(RetryAfter::Secs(120)));
    for bad in [
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "Sun Nov 6 08:49:37",
        "Sunday, 06-Nov-1994 08:49:37 GMT",
        "soon",
    ] {
        assert_eq!(retry_after(bad.as_bytes()), None, "{bad}");
    }
}

/// A need whose clock answers once and then fails, and whose reply never ends: empty body pieces.
#[derive(Default)]
struct ClockFailsMidRead {
    clocks: std::sync::atomic::AtomicU32,
}

impl Wire for ClockFailsMidRead {
    fn open(&self, _: &TokenRequest, _: &mut SealedWrite, _: u64) -> Result<ConnId, ConnError> {
        Ok(ConnId(7))
    }
    fn read(&self, _: ConnId, _: &mut [u8]) -> Result<Got, ConnError> {
        Ok(Got {
            kind: PieceKind::Body,
            len: 0,
            end: false,
            status: None,
            retry_after: None,
        })
    }
    fn close(&self, _: ConnId) {}
    fn clock(&self) -> Option<HostClock> {
        (self.clocks.fetch_add(1, Ordering::AcqRel) == 0).then_some(HostClock {
            wall_secs: now_epoch(),
            mono_ns: 0,
        })
    }
}

/// THE READ LOOP IS BOUNDED WHEN THE CLOCK FAILS MID-READ: with no reading to judge the deadline
/// on, a tick yields after its bounded number of reads instead of reading on unbounded.
#[test]
fn a_clock_that_fails_mid_read_still_bounds_the_read_loop() {
    let w = ClockFailsMidRead::default();
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(
        m.tick(0, now_epoch(), Some(&w)),
        (IN_FLIGHT_POLL_NS, None),
        "the tick yields, the exchange still in flight"
    );
    assert!(!m.idle());
}

/// A 2XX THAT IS NO TOKEN RESPONSE IS UNUSABLE (WARN), not a refusal (INFO): the endpoint answered
/// success, but what it sent cannot be read; a 4xx with the same body stays a refusal.
#[test]
fn a_success_reply_that_is_no_token_response_is_unusable() {
    for (status, unusable) in [(200, true), (400, false)] {
        let w = Scripted::default();
        w.push(vec![
            Step::Head(status),
            Step::Body(b"<html>a proxy page</html>".to_vec(), true),
        ]);
        let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
        let (_, report) = m.tick(0, now_epoch(), Some(&w));
        assert!(matches!(report, Some(Report::MintFailed(_))), "{report:?}");
        assert_eq!((m.unusable(), m.outage()), (unusable, false), "{status}");
    }
}

/// A LANDED TOKEN KEEPS NONE OF THE REPLY'S TYPE WORDS: `token_type` and `issued_token_type` are
/// judged as the token lands and are not held for its life (an untrusted reply sizes them).
#[test]
fn a_landed_token_keeps_none_of_the_replys_type_words() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"t","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","expires_in":3600}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(m.tick(0, now_epoch(), Some(&w)).1, Some(Report::Minted));
    let held = m.current();
    assert_eq!(
        (
            held.token_type.as_deref(),
            held.issued_token_type.as_deref()
        ),
        (None, None)
    );
}

/// A READ RACING A FAILED EXCHANGE DOES NOT RE-ARM IT: a read that finds an on-demand cell
/// unusable while it backs off a failure leaves its next exchange unarmed (the check is made
/// under the exchange's lock, which the failure is recorded under); past the window it re-arms.
#[test]
fn an_on_demand_read_inside_the_back_off_does_not_rearm_the_exchange() {
    let exchange = Arc::new(token_exchange::build(
        "subject",
        "https://as.example/token",
        token_exchange::ACCESS_TOKEN_TYPE,
        "https://tools.example/rpc",
    ));
    let w = Scripted::default();
    w.push(vec![Step::Head(503), Step::Body(b"busy".to_vec(), true)]);
    let cell = Minted::new(
        Minter::TokenExchange(token_exchange::Scoped::new(exchange, "s")),
        DEFAULT_MAX_RESPONSE_BYTES,
    );
    let now = now_epoch();
    assert!(matches!(
        cell.tick(0, now, Some(&w)).1,
        Some(Report::MintFailed(_))
    ));
    assert!(
        cell.backing_off(now),
        "positive control: the scope backs off"
    );
    assert_eq!(cell.read(now, seen), "Wait");
    assert_eq!(
        cell.tick(1, now, Some(&w)),
        (u64::MAX, None),
        "no exchange is re-armed inside the window"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 1);
    assert_eq!(cell.read(now + MAX_BACKOFF_SECS, seen), "Wait");
    w.ok(r#"{"token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","access_token":"t","expires_in":3600}"#);
    assert_eq!(
        cell.tick(2, now, Some(&w)).1,
        Some(Report::Minted),
        "past the window a read re-arms the exchange"
    );
}

/// An expired token stays hidden while its refresh is waiting for the endpoint's reply.
#[test]
fn an_expired_token_waits_for_an_in_flight_refresh_without_starting_another() {
    let wall = now_epoch();
    let wire = Scripted::default();
    wire.ok(r#"{"access_token":"old","expires_in":60}"#);
    let cell = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, _) = cell.tick(0, wall, Some(&wire));
    wire.push(vec![
        Step::Pending,
        Step::Head(200),
        Step::Body(
            br#"{"access_token":"new","expires_in":3600}"#.to_vec(),
            true,
        ),
    ]);
    assert_eq!(cell.tick(due, wall + 60, Some(&wire)).1, None);
    assert_eq!(cell.read(wall + 60, seen), "Wait");
    assert!(!cell.presents(wall + 60));
    assert_eq!(wire.sent.lock().unwrap().len(), 2);
    assert_eq!(
        cell.tick(due + IN_FLIGHT_POLL_NS, wall + 60, Some(&wire)).1,
        Some(Report::Minted)
    );
    assert_eq!(cell.read(wall + 60, seen), "Header(\"Bearer new\")");
    assert_eq!(wire.sent.lock().unwrap().len(), 2);
}

#[test]
fn pending_opening_keeps_the_request_and_original_deadline() {
    let wire = Scripted::default();
    wire.refuse(ConnError::Pending);
    wire.ok(r#"{"access_token":"after-handshake","expires_in":3600}"#);
    let minted = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(minted.tick(7, now_epoch(), Some(&wire)).1, None);
    let (request, sealed) = match &*minted.attempt.lock().unwrap() {
        Attempt::Opening {
            request,
            sealed,
            started_ns,
            ..
        } => {
            assert_eq!(*started_ns, 7);
            (request as *const TokenRequest, sealed as *const SealedWrite)
        }
        _ => panic!("opening must remain pending"),
    };
    assert_eq!(minted.tick(8, now_epoch(), None).1, None);
    match &*minted.attempt.lock().unwrap() {
        Attempt::Opening {
            request: r,
            sealed: s,
            ..
        } => {
            assert_eq!(request, r as *const TokenRequest);
            assert_eq!(sealed, s as *const SealedWrite);
        }
        _ => panic!("opening must retain its request and sealed body"),
    }
    assert_eq!(
        minted.tick(9, now_epoch(), Some(&wire)).1,
        Some(Report::Minted)
    );
    assert_eq!(*wire.closed.lock().unwrap(), 1);

    let wire = Scripted::default();
    wire.refuse(ConnError::Pending);
    let minted = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(minted.tick(7, now_epoch(), Some(&wire)).1, None);
    let report = minted
        .tick(7 + MINT_DEADLINE_SECS * NS, now_epoch(), None)
        .1;
    assert!(matches!(report, Some(Report::MintFailed(_))));
    assert!(minted.outage());
    assert_eq!(
        wire.sent.lock().unwrap().len(),
        1,
        "deadline must not rebuild or retry the request"
    );
}
