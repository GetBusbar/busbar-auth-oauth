// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T1: THE PRODUCTION [`HostWire`], over the contract's fake host (its services written as safe
//! Rust): the clock's nanoseconds read as whole seconds, the request head's words and field
//! block, each host refusal's connection error, each reply piece as the exchange reads it, and a
//! whole jwt-bearer mint over it whose assertion's `iat` is the host's wall clock in SECONDS.

use std::collections::VecDeque;
use std::sync::Mutex;

use busbar_contract::abi::host::conn::connector::{
    EstablishIn, ReplyIn, ReplyPiece, RequestIn, StreamIn, REPLY_BODY, REPLY_END, REPLY_HEAD,
    REQUEST_HEAD,
};
use busbar_contract::abi::host::service::{ClockNowIn, ClockReading};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_outbound::Diags;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
use busbar_contract::abi::transport::FrameSpan;
use busbar_contract::conn::ConnError;

use super::*;
use crate::mint::{RetryAfter, TokenRequest};

/// The host's wall clock, in nanoseconds: 2027-01-15T08:00:00.999999999Z.
const WALL_NS: u64 = 1_800_000_000_999_999_999;

/// What the fake host's doubles were handed and will answer (one test drives them).
struct Script {
    /// `(target, need)` of each ESTABLISH.
    established: Vec<(String, u32)>,
    /// `(piece kind, bytes)` of each WRITE_REQUEST.
    written: Vec<(u32, Vec<u8>)>,
    /// The reply pieces READ_REPLY answers, in order.
    replies: VecDeque<(ReplyPiece, Vec<u8>)>,
    /// How many CLOSEs.
    closed: u32,
}

static SCRIPT: Mutex<Script> = Mutex::new(Script {
    established: Vec::new(),
    written: Vec::new(),
    replies: VecDeque::new(),
    closed: 0,
});

struct Clock;
impl FakeService for Clock {
    type In = ClockNowIn;
    fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
        call.put(
            |i| &i.reading,
            ClockReading {
                size: u32::try_from(std::mem::size_of::<ClockReading>()).unwrap(),
                _reserved: 0,
                wall_ns: WALL_NS,
                mono_ns: 42,
            },
        );
        Outcome::Ready
    }
}

struct Establish;
impl FakeService for Establish {
    type In = EstablishIn;
    fn serve(call: &mut ServiceCall<EstablishIn>) -> Outcome {
        let target = call.text(|i| &i.target).to_string();
        let need = call.input().need;
        SCRIPT.lock().unwrap().established.push((target, need));
        call.set_value(5);
        Outcome::Ready
    }
}

struct WriteRequest;
impl FakeService for WriteRequest {
    type In = RequestIn;
    fn serve(call: &mut ServiceCall<RequestIn>) -> Outcome {
        let kind = call.lent(|i| &i.piece)[0].kind;
        let bytes = call.lent(|i| &i.buf).to_vec();
        let n = bytes.len() as u64;
        SCRIPT.lock().unwrap().written.push((kind, bytes));
        call.set_len(n);
        Outcome::Ready
    }
}

struct ReadReply;
impl FakeService for ReadReply {
    type In = ReplyIn;
    fn serve(call: &mut ServiceCall<ReplyIn>) -> Outcome {
        let Some((piece, bytes)) = SCRIPT.lock().unwrap().replies.pop_front() else {
            return Outcome::Pending;
        };
        assert!(call.fill_lent(|i| &i.buf, &bytes), "the buffer holds it");
        call.put(|i| &i.piece, piece);
        Outcome::Ready
    }
}

struct Close;
impl FakeService for Close {
    type In = StreamIn;
    fn serve(_: &mut ServiceCall<StreamIn>) -> Outcome {
        SCRIPT.lock().unwrap().closed += 1;
        Outcome::Ready
    }
}

/// A fake host serving the clock and the framed connector.
fn fake_host() -> FakeHost {
    FakeHost::new()
        .serve(fake::host::CLOCK_NOW, Clock)
        .serve(fake::conn::ESTABLISH, Establish)
        .serve(fake::conn::WRITE_REQUEST, WriteRequest)
        .serve(fake::conn::READ_REPLY, ReadReply)
        .serve(fake::conn::CLOSE, Close)
}

const fn span(offset: u64, len: u64) -> FrameSpan {
    FrameSpan { offset, len }
}

/// THE CLOCK: the host's nanoseconds are whole seconds on the wall clock (never nanoseconds read
/// as seconds), and the monotonic reading passes through.
#[test]
fn the_host_clock_reads_whole_wall_seconds() {
    let host = FakeHost::new().serve(fake::host::CLOCK_NOW, Clock);
    let tables = host.lent();
    let h = Host::of(&tables);
    let issued = AtomicU32::new(0);
    let wire = HostWire::new(&h, Ticket::NONE, &issued);
    assert_eq!(
        wire.clock(),
        Some(HostClock {
            wall_secs: 1_800_000_000,
            mono_ns: 42,
        })
    );
    // A host with no clock answers none.
    let bare = FakeHost::new();
    let tables = bare.lent();
    let h = Host::of(&tables);
    assert_eq!(HostWire::new(&h, Ticket::NONE, &issued).clock(), None);
}

/// THE HEAD: `POST`, the target's path and query (never its fragment), then each field as
/// `name: value\r\n`; each span names its bytes.
#[test]
fn the_request_head_is_post_the_path_and_query_and_the_field_block() {
    let req = TokenRequest {
        need: 0,
        target: "https://idp.example/tenant/token?x=1#frag".to_string(),
        fields: vec![("content-type", "application/x-www-form-urlencoded")],
        body: busbar_contract::abi::sdk::cred::FormBody::new(),
    };
    let (bytes, piece) = head(&req, 30_000).expect("a head");
    let at = |s: FrameSpan| {
        let o = usize::try_from(s.offset).unwrap();
        String::from_utf8(bytes[o..o + usize::try_from(s.len).unwrap()].to_vec()).unwrap()
    };
    assert_eq!(piece.kind, REQUEST_HEAD);
    assert_eq!(at(piece.method), "POST");
    assert_eq!(at(piece.target), "/tenant/token?x=1");
    assert_eq!(
        at(piece.fields),
        "content-type: application/x-www-form-urlencoded\r\n"
    );
    assert_eq!(piece.timeout_ms, 30_000);
    let bad = TokenRequest {
        target: "not a url".to_string(),
        ..req
    };
    assert_eq!(head(&bad, 0).err(), Some(ConnError::Refused));
}

/// EACH HOST REFUSAL'S CONNECTION ERROR: the named failures map one to one; a failure or refusal
/// text is the table's own for the error it names, and an unknown text is a fault (failed) or a
/// refusal (refused).
#[test]
fn each_host_failure_maps_to_its_connection_error() {
    assert_eq!(error_of(&ConnFailure::Unarmed), ConnError::Unarmed);
    assert_eq!(error_of(&ConnFailure::NoTicket), ConnError::Pending);
    assert_eq!(error_of(&ConnFailure::Fault), ConnError::Fault);
    assert_eq!(
        error_of(&ConnFailure::CredentialUnavailable),
        ConnError::CredentialUnavailable
    );
    for e in [
        ConnError::Pending,
        ConnError::Timeout,
        ConnError::Closed,
        ConnError::NotOwner,
        ConnError::UndeclaredNeed,
        ConnError::Refused,
        ConnError::Fault,
        ConnError::Unarmed,
        ConnError::CredentialUnavailable,
    ] {
        assert_eq!(error_of(&ConnFailure::Failed(e.text().to_string())), e);
        assert_eq!(error_of(&ConnFailure::Refused(e.text().to_string())), e);
    }
    assert_eq!(
        error_of(&ConnFailure::Failed("something else".to_string())),
        ConnError::Fault
    );
    assert_eq!(
        error_of(&ConnFailure::Refused("something else".to_string())),
        ConnError::Refused
    );
}

/// A WHOLE MINT OVER THE PRODUCTION WIRE: the request goes out on the need its style names
/// (establish, head, body, end), each reply piece is read as the exchange reads it (the head's
/// code and its `retry-after`, the body's bytes, the end), the connection is closed, and the
/// assertion's `iat` is the host's wall clock in SECONDS. RED-proof: a wire that read the
/// nanoseconds as seconds signs `iat` 1_800_000_000_999_999_999.
#[test]
fn a_jwt_bearer_mint_runs_over_the_host_wire_at_the_hosts_wall_seconds() {
    use base64::Engine as _;
    let block = b"retry-after: 7\r\n".to_vec();
    let body = br#"{"access_token":"ya29.wire","token_type":"Bearer","expires_in":3600}"#.to_vec();
    {
        let mut s = SCRIPT.lock().unwrap();
        s.replies.push_back((
            ReplyPiece {
                kind: REPLY_HEAD,
                code: 200,
                reason: span(0, 0),
                fields: span(0, block.len() as u64),
            },
            block.clone(),
        ));
        s.replies.push_back((
            ReplyPiece {
                kind: REPLY_BODY,
                ..ReplyPiece::default()
            },
            body.clone(),
        ));
        s.replies.push_back((
            ReplyPiece {
                kind: REPLY_END,
                ..ReplyPiece::default()
            },
            Vec::new(),
        ));
    }
    let host = fake_host();
    let tables = host.lent();
    let h = Host::of(&tables);

    // The read mapping, piece by piece, through the wire itself.
    let issued = AtomicU32::new(0);
    let driver = Ticket {
        slot: 1,
        generation: 1,
    };
    let wire = HostWire::new(&h, driver, &issued);
    let mut buf = [0_u8; 1024];
    let got = wire.read(ConnId(5), &mut buf).expect("the head");
    assert_eq!(
        (got.kind, got.status, got.retry_after),
        (PieceKind::Fields, Some(200), Some(RetryAfter::Secs(7)))
    );
    let got = wire.read(ConnId(5), &mut buf).expect("the body");
    assert_eq!(
        (got.kind, got.len, got.end),
        (PieceKind::Body, body.len(), false)
    );
    assert_eq!(&buf[..got.len], &body[..]);
    let got = wire.read(ConnId(5), &mut buf).expect("the end");
    assert_eq!((got.kind, got.end), (PieceKind::Completion, true));
    assert_eq!(
        wire.read(ConnId(5), &mut buf).err(),
        Some(ConnError::Pending),
        "nothing more is ready"
    );

    // The whole mint, the same replies again.
    {
        let mut s = SCRIPT.lock().unwrap();
        s.replies.push_back((
            ReplyPiece {
                kind: REPLY_HEAD,
                code: 200,
                ..ReplyPiece::default()
            },
            Vec::new(),
        ));
        s.replies.push_back((
            ReplyPiece {
                kind: REPLY_BODY,
                ..ReplyPiece::default()
            },
            body,
        ));
        s.replies.push_back((
            ReplyPiece {
                kind: REPLY_END,
                ..ReplyPiece::default()
            },
            Vec::new(),
        ));
    }
    let o = crate::instance::Oauth::new(1);
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string();
    let cell = crate::style::open_binding(crate::style::JWT_BEARER, Some(sa.as_bytes()), None, &o)
        .expect("the binding opens");
    let handle = o.keep(cell);
    o.tick(1_000, driver, Some(&h), &mut Diags::default());
    let s = SCRIPT.lock().unwrap();
    assert_eq!(
        s.established,
        [("https://oauth2.googleapis.com/token".to_string(), 1)]
    );
    let kinds: Vec<u32> = s.written.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        [
            REQUEST_HEAD,
            busbar_contract::abi::host::conn::connector::REQUEST_BODY,
            busbar_contract::abi::host::conn::connector::REQUEST_END,
        ]
    );
    assert_eq!(s.closed, 1, "the connection is closed");
    let form = String::from_utf8(s.written[1].1.clone()).expect("a form");
    let assertion = form.split("assertion=").nth(1).expect("an assertion");
    let claims = assertion.split('.').nth(1).expect("a claims part");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims"),
    )
    .expect("JSON claims");
    assert_eq!(claims["iat"], 1_800_000_000_u64, "{claims}");
    assert_eq!(claims["exp"], 1_800_003_600_u64, "{claims}");
    drop(s);
    let mut written = Vec::new();
    let ask = crate::Ask {
        handle,
        own: true,
        scope: None,
        ticket: Ticket::NONE,
        timestamp: 0,
    };
    let answer = o.answer(&ask, Some(&h), &mut |v| written.push(v.to_string()));
    assert!(matches!(
        answer,
        std::task::Poll::Ready(busbar_contract::abi::sdk::auth_outbound::FieldsAnswer::Ready)
    ));
    assert_eq!(written, ["Bearer ya29.wire"]);
}
