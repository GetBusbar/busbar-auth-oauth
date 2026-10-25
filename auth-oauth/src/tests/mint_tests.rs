// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The self-minting machinery over a scripted need: the refresh schedule (ported from
//! `bearer_token_tests.rs`), the token response texts and cap (ported from the two mint bodies'
//! tests), and the tick-driven exchange with THE EXPIRED-TOKEN RULE.

use super::*;
use crate::held::Own;
use std::collections::VecDeque;

/// One scripted read.
#[derive(Clone)]
pub(crate) enum Step {
    /// Nothing is ready yet.
    Pending,
    /// The response head, with this status.
    Head(u32),
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

    fn open(&self, req: &TokenRequest, _: u64) -> Result<ConnId, ConnError> {
        self.sent.lock().unwrap().push((
            req.target.clone(),
            req.fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            req.body.expose_own(&Own::here()).clone(),
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
            }),
            Step::Body(b, end) => {
                buf[..b.len()].copy_from_slice(&b);
                Ok(Got {
                    kind: PieceKind::Body,
                    len: b.len(),
                    end,
                    status: None,
                })
            }
            Step::Done => Ok(Got {
                kind: PieceKind::Completion,
                len: 0,
                end: true,
                status: None,
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
        oauth_client_credentials::build("id:secret", "https://idp.example/token", "s").unwrap(),
    )
}

const S: u64 = NS;

#[test]
fn next_refresh_never_sleeps_past_a_live_token_expiry() {
    let now = 1_000_000;
    // A normally-lived token refreshes a full skew early.
    assert_eq!(next_refresh_secs(now + 3600, now), 3600 - REFRESH_SKEW_SECS);
    // A short-lived token refreshes at half its life, never past it.
    for ttl in [1, 2, 10, 59, 299, 300] {
        let sleep = next_refresh_secs(now + ttl, now);
        assert!(sleep < ttl || ttl == 1, "ttl {ttl}: slept {sleep}");
        assert!(sleep >= 1);
    }
    // An expired token backs off rather than spinning.
    assert_eq!(next_refresh_secs(now, now), MIN_SLEEP_SECS);
    assert_eq!(next_refresh_secs(now - 5, now), MIN_SLEEP_SECS);
    // Near the skew boundary the floor holds.
    assert_eq!(next_refresh_secs(now + 301, now), 1.max(MIN_SLEEP_SECS));
}

#[test]
fn a_cached_token_is_redacted_in_debug() {
    let (t, invalid) = CachedToken::new(Secret::held("super-secret-token".to_string()), 5);
    assert!(!invalid);
    assert!(!format!("{t:?}").contains("super-secret-token"));
}

#[test]
fn a_cached_token_omits_the_header_for_bytes_invalid_in_a_header_value() {
    let (t, invalid) = CachedToken::new(Secret::held("tok\r\nen".to_string()), 5);
    assert!(invalid);
    assert_eq!(t.header(), None);
    let (t, invalid) = CachedToken::new(Secret::held(String::new()), 0);
    assert!(
        !invalid,
        "the pre-first-mint sentinel is not a reportable token"
    );
    assert_eq!(t.header(), None);
}

/// The texts a failed exchange names, 1.5.5's words: the status line with a 200-char snippet, the
/// JSON error.
#[test]
fn a_refused_or_malformed_response_is_named_in_1_5_5_words() {
    let long = "x".repeat(500);
    let e = parse_response(401, long.as_bytes(), 0).unwrap_err();
    assert_eq!(
        e,
        format!(
            "token endpoint returned 401 Unauthorized: {}",
            "x".repeat(200)
        )
    );
    let e = parse_response(200, b"not json", 0).unwrap_err();
    assert!(e.starts_with("token response JSON invalid: "), "{e}");
    let (t, _) = parse_response(200, br#"{"access_token":"a","expires_in":"7200"}"#, 10).unwrap();
    assert_eq!(t.expires_at, 7210);
    assert_eq!(t.header(), Some("Bearer a"));
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

/// THE ACCESS TOKEN IS UNESCAPED BY THE PLUGIN, NEVER BY THE JSON DECODER (THE DESIGN §6: "auth
/// material is zeroised"): `serde_json` unescapes a string that carries an escape into a scratch
/// buffer of its own that it frees unwiped, so the decode skips the token (its field is
/// `IgnoredAny`: skipping copies nothing) and `access_token` reads the top-level member into one
/// buffer, sized once and wiped on drop, with every escape resolved as the decoder resolves it.
/// The crate forbids `unsafe`, so no test allocator can watch the freed bytes; what this holds is
/// that no decoded field can carry the token and that the one buffer that does is the wiping one.
#[test]
fn an_escaped_access_token_is_read_into_one_wiped_buffer_never_by_the_decoder() {
    fn held_as<T>(_: &T) -> &'static str {
        std::any::type_name::<T>()
    }
    let body = r#"{"token_type":"Bearer","access_token":"ya29.a\/bAc","expires_in":60}"#;
    let tok: TokenResponse = serde_json::from_str(body).expect("a well-formed response");
    assert!(
        held_as(&tok.access_token).contains("IgnoredAny"),
        "the decoder skips the token, it never unescapes it: {}",
        held_as(&tok.access_token)
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
    assert_eq!(t.header(), Some("Bearer ya29.a/bAc"));
    assert_eq!(t.expires_at, 60);
    // A nested `access_token` is not the response's.
    let nested = r#"{"x":{"access_token":"no"},"l":["access_token"],"access_token":"yes\n"}"#;
    assert_eq!(access_token(nested).expect("the token").as_str(), "yes\n");
    // A token that is not a string is refused without the decoder's text.
    assert_eq!(
        parse_response(200, br#"{"access_token":1}"#, 0).unwrap_err(),
        "token response JSON invalid: a field is missing or has the wrong type (the decoder's \
         text is withheld)"
    );
    // A missing one is still the decoder's own missing-field text.
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
        m.read(now_epoch(), |r| format!("{r:?}")),
        "Nothing",
        "nothing minted yet: READY with no fields (the upstream answers 401, as in 1.5.5)"
    );
    let (due, report) = m.tick(1_000, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted));
    assert!(m.is_ready());
    assert_eq!(
        m.read(now_epoch(), |r| format!("{r:?}")),
        "Header(\"Bearer tok-1\")"
    );
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
/// u64 schedules the refresh at the far end of the clock, never a wrapped (arbitrary) instant.
#[test]
fn a_huge_expires_in_schedules_no_overflowed_refresh() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"tok","expires_in":100000000000}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, report) = m.tick(1_000, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted));
    assert_eq!(
        m.read(now_epoch(), |r| format!("{r:?}")),
        "Header(\"Bearer tok\")"
    );
    assert_eq!(
        due,
        u64::MAX,
        "the refresh is effectively never, not a wrapped instant"
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

/// THE EXPIRED-TOKEN RULE (BUSBAR-1.6.0.md THE DESIGN, §6.5): an expired token whose refresh FAILED answers WAIT;
/// an expired token whose refresh has not failed is still presented (1.5.5 served the current token
/// until a refresh replaced it); a landed mint clears the wait.
#[test]
fn an_expired_token_whose_refresh_failed_answers_wait_until_a_mint_lands() {
    let w = Scripted::default();
    w.ok(r#"{"access_token":"old","expires_in":60}"#);
    let m = Minted::new(client_credentials(), DEFAULT_MAX_RESPONSE_BYTES);
    let (due, _) = m.tick(0, now_epoch(), Some(&w));
    let later = now_epoch() + 3600;
    assert_eq!(
        m.read(later, |r| format!("{r:?}")),
        "Header(\"Bearer old\")",
        "expired, refresh not failed: the current token"
    );
    w.push(vec![Step::Head(500), Step::Body(b"down".to_vec(), true)]);
    let (due, report) = m.tick(due, now_epoch(), Some(&w));
    assert_eq!(
        report,
        Some(Report::MintFailed(
            "token endpoint returned 500 Internal Server Error: down".to_string()
        ))
    );
    assert_eq!(m.read(later, |r| format!("{r:?}")), "Wait");
    assert_eq!(
        m.read(now_epoch(), |r| format!("{r:?}")),
        "Header(\"Bearer old\")",
        "not yet expired: served even while refreshes fail"
    );
    w.ok(r#"{"access_token":"new","expires_in":3600}"#);
    assert_eq!(m.tick(due, now_epoch(), Some(&w)).1, Some(Report::Minted));
    assert_eq!(
        m.read(later, |r| format!("{r:?}")),
        "Header(\"Bearer new\")"
    );
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

/// THE MINT ENDPOINTS ARE `operator-infrastructure` (ARCHITECT D1 2026-10-05, MINT CLASS (B),
/// re-measured against v1.5.5 2026-10-07): 1.5.5's config_validate/mod.rs:436-476 accepted a
/// `token_url` that is https, or http to a PRIVATE or LOOPBACK host, and refused http only to a
/// public host (plus the metadata denylist) — plaintext to a private token endpoint is the
/// operator-infrastructure class, not loopback-allowed. Every token need the Statement declares
/// states that class. RED on busbar-auth-oauth dev 44341ab, which declared them loopback-allowed.
#[test]
fn every_mint_need_is_declared_operator_infrastructure() {
    use busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE;
    assert_eq!(crate::NEEDS.len(), 2, "token_url and token_uri");
    for (i, n) in crate::NEEDS.iter().enumerate() {
        assert_eq!(
            n.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE,
            "need {i}: an auth mint endpoint is operator-infrastructure"
        );
    }
}

/// THE TOKEN REQUEST FORM IS BUILT ONCE AND HELD WIPED (THE DESIGN §6: "auth material is
/// zeroised"): it carries the client secret, the subject token or the signed assertion, so it is
/// written into one buffer sized to its exact length (no growth frees a partial copy) and held in
/// a `Secret<_, Own>` — byte for byte what `serde_urlencoded` (reqwest's `.form()`) wrote, for every byte.
#[test]
fn the_form_is_serde_urlencoded_byte_for_byte_and_built_once() {
    let mut every: String = (0_u8..=0x7f).map(char::from).collect();
    every.push_str("\u{e9}\u{1F600} +&=%");
    let pairs = [
        ("grant_type", "client_credentials"),
        ("client_secret", every.as_str()),
        ("scope", "https://cognitiveservices.azure.com/.default a b"),
        ("empty", ""),
    ];
    let held: Secret<String, Own> = form(&pairs);
    assert_eq!(
        held.expose_own(&Own::here()),
        &serde_urlencoded::to_string(pairs).expect("a form")
    );
    assert_eq!(
        held.expose_own(&Own::here()).capacity(),
        held.expose_own(&Own::here()).len(),
        "sized once"
    );
}

/// THE RESPONSE BUFFER GROWS TO WHAT ARRIVES, bounded by the cap (Q128 auth-oauth MEDIUM, the
/// per-mint reservation): an exchange in flight holds no reservation the size of the cap, so a
/// large `upstream_error_body_max_bytes` costs nothing per mint, and a cap near `usize::MAX` is a
/// bound, not an allocation. RED before the fix: each mint reserved `cap + READ_BUF_BYTES` at once.
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
    let held = match &*m.exchange.lock().unwrap() {
        Exchange::InFlight { body, .. } => body.capacity(),
        Exchange::Idle { .. } => panic!("the exchange is in flight"),
    };
    assert!(
        held <= READ_BUF_BYTES,
        "an in-flight exchange holds {held} bytes for a {DEFAULT_MAX_RESPONSE_BYTES}-byte cap"
    );
    let (_, report) = m.tick(IN_FLIGHT_POLL_NS, now_epoch(), Some(&w));
    assert_eq!(report, Some(Report::Minted), "the body still reads whole");

    // A cap near `usize::MAX` is a bound only.
    let w = Scripted::default();
    w.ok(r#"{"access_token":"t","expires_in":3600}"#);
    let m = Minted::new(client_credentials(), usize::MAX);
    assert_eq!(m.tick(0, now_epoch(), Some(&w)).1, Some(Report::Minted));
}
