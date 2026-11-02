// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises production `HostWire` over the loader's real host tables.

use std::collections::VecDeque;
use std::sync::Mutex;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_outbound::Diags;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::transport::FrameSpan;
use busbar_contract::conn::ConnError;

use super::*;
use crate::mint::{RetryAfter, TokenRequest};

/// The host's wall clock, in nanoseconds: 2027-01-15T08:00:00.999999999Z.
const WALL_NS: u64 = 1_800_000_000_999_999_999;

type OpenedRequest = (Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>, Vec<u8>);

/// What this host I/O script receives and answers (one test drives it).
struct Script {
    /// `(target, need)` of each ESTABLISH.
    established: Vec<(String, u32)>,
    deadlines: Vec<(u64, u64)>,
    /// `(piece kind, bytes)` of each WRITE_REQUEST.
    opened: Vec<OpenedRequest>,
    /// The reply pieces READ_REPLY answers, in order.
    replies: VecDeque<(ReplyPiece, Vec<u8>)>,
    /// How many CLOSEs.
    closed: u32,
}

static SCRIPT: Mutex<Script> = Mutex::new(Script {
    established: Vec::new(),
    deadlines: Vec::new(),
    opened: Vec::new(),
    replies: VecDeque::new(),
    closed: 0,
});

use busbar_contract::abi::auth::{OutboundReadyIn, OutboundReadyOut};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::sdk::auth_outbound::{Outbound, OutboundReadySlot};
use busbar_contract::abi::sdk::life::Held;
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::conn::{ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece};
use busbar_contract::ids::StreamId;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Snapshot,
    Stored, TrustKeyRef, UNSERVED,
};
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow,
    NoSink, Plugin,
};
use std::sync::Arc;

#[derive(Default)]
struct WireEndpoint {
    slab: ConnSlab<()>,
}
impl HostServices for WireEndpoint {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: WALL_NS,
            mono_ns: 42,
        }
    }

    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_decide(
        &self,
        _caller: &Caller,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_due(&self, _caller: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, _len: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn snapshot_read(&self, _caller: &Caller, _scope: u32) -> Snapshot {
        Snapshot::Refused(UNSERVED)
    }
}
impl DeclaredConns for WireEndpoint {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        // This local host-value script has no secure network connection. Preserve fail-closed
        // custody, while treating dial and request deadlines as the two distinct ABI values.
        if require_secure {
            return Err(ConnError::AuthRefused);
        }
        self.slab.check_need(owner, need)?;
        SCRIPT
            .lock()
            .unwrap()
            .deadlines
            .push((dial_timeout_ms, desc.timeout_ms));
        self.open(owner, need, desc)
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        scheme == "http"
    }
}
impl Conns for WireEndpoint {
    fn open(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(owner, need)?;
        let mut script = SCRIPT.lock().unwrap();
        script.established.push((desc.target.to_owned(), need.0));
        script.opened.push((
            desc.method.to_vec(),
            desc.head_target.to_vec(),
            desc.fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_vec()))
                .collect(),
            desc.body.to_vec(),
        ));
        self.slab.insert(owner, need, ())
    }
    fn write(
        &self,
        owner: InstanceId,
        id: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.slab.get(owner, id)?;
        Ok(bytes.len())
    }
    fn read(
        &self,
        owner: InstanceId,
        id: ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.slab.get(owner, id)?;
        let (p, bytes) = SCRIPT
            .lock()
            .unwrap()
            .replies
            .pop_front()
            .ok_or(ConnError::Pending)?;
        assert!(bytes.len() <= buf.len());
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(Piece {
            kind: match p.kind {
                REPLY_HEAD => PieceKind::Fields,
                REPLY_BODY => PieceKind::Body,
                REPLY_END => PieceKind::Completion,
                _ => panic!("unexpected reply"),
            },
            stream: StreamId(0),
            len: bytes.len(),
            end: p.kind == REPLY_END,
            status: None,
            status_code: if p.kind == REPLY_HEAD {
                Some(p.code)
            } else {
                None
            },
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, owner: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.slab.remove(owner, id)?;
        SCRIPT.lock().unwrap().closed += 1;
        Ok(())
    }
}
thread_local! { static CAPTURED: std::cell::RefCell<Option<Host>> = const { std::cell::RefCell::new(None) }; }
struct CaptureHost;
impl SafeSlot for CaptureHost {
    type In = OutboundReadyIn;
    type Out = OutboundReadyOut;
    type State = Held<Outbound<crate::instance::Oauth>>;
    fn call(
        instance: Instance<'_, Self::State>,
        input: Lent<'_, OutboundReadyIn>,
        out: Out<'_, OutboundReadyOut>,
    ) -> Outcome {
        CAPTURED.with(|slot| *slot.borrow_mut() = instance.get().unwrap().host().cloned());
        OutboundReadySlot::<crate::instance::Oauth>::call(instance, input, out)
    }
}
mod host_bridge {
    busbar_contract::plugin_door! { ops:busbar_contract::abi::auth::Ops, statement:crate::STATEMENT,
    lifecycle:life(busbar_contract::abi::sdk::auth_outbound::Outbound<crate::instance::Oauth>),
    kind_ops:{
        verify:busbar_contract::abi::sdk::Safe<busbar_contract::abi::sdk::auth_outbound::NotServed<busbar_contract::abi::sdk::auth_outbound::Outbound<crate::instance::Oauth>,busbar_contract::abi::auth::VerifyIn,busbar_contract::abi::auth::IdentifyOut>>,
        begin_login:busbar_contract::abi::sdk::Safe<busbar_contract::abi::sdk::auth_outbound::NotServed<busbar_contract::abi::sdk::auth_outbound::Outbound<crate::instance::Oauth>,busbar_contract::abi::auth::BeginLoginIn,busbar_contract::abi::auth::BeginLoginOut>>,
        complete_login:busbar_contract::abi::sdk::Safe<busbar_contract::abi::sdk::auth_outbound::NotServed<busbar_contract::abi::sdk::auth_outbound::Outbound<crate::instance::Oauth>,busbar_contract::abi::auth::CompleteLoginIn,busbar_contract::abi::auth::IdentifyOut>>,
        open_outbound:busbar_contract::abi::sdk::Safe<busbar_contract::abi::sdk::auth_outbound::OpenOutboundSlot<crate::instance::Oauth>>,
        outbound_ready:busbar_contract::abi::sdk::Safe<super::CaptureHost>,
        fields:busbar_contract::abi::sdk::Safe<busbar_contract::abi::sdk::auth_outbound::FieldsSlot<crate::instance::Oauth>>,
    }, }
}
struct HostedWire {
    host: Host,
    _plugin: Plugin<Auth>,
    _dispatcher: Dispatcher,
}
fn host_wire() -> HostedWire {
    use busbar_contract::abi::sdk::test_support::zeroed;
    let provider = Arc::new(WireEndpoint::default());
    let d = Dispatcher::with_services(DispatchConfig::default(), provider.clone());
    let p = load_linked::<Auth>(
        &LinkedRow::of_macro(host_bridge::MACRO_DOOR).unwrap(),
        Bind {
            instance: Arc::from("wire-test"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Host(provider),
        },
    )
    .unwrap();
    let mut open: Frame<
        busbar_contract::abi::mechanism::lifecycle::OpenIn,
        busbar_contract::abi::mechanism::lifecycle::OpenOut,
    > = Frame::new(zeroed(), zeroed());
    open.input.head = in_head();
    open.out.head = out_head();
    open.input.generation = 1;
    assert_eq!(
        p.call(
            busbar_contract::abi::mechanism::lifecycle::slot::OPEN,
            &mut open
        )
        .outcome,
        Outcome::Ready
    );
    let mut capture: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(zeroed(), zeroed());
    capture.input.head = in_head();
    capture.out.head = out_head();
    p.call(
        busbar_contract::abi::auth::slot::OUTBOUND_READY,
        &mut capture,
    );
    let host = CAPTURED.with(|slot| slot.borrow_mut().take()).unwrap();
    HostedWire {
        host,
        _plugin: p,
        _dispatcher: d,
    }
}

const fn span(offset: u64, len: u64) -> FrameSpan {
    FrameSpan { offset, len }
}

/// THE CLOCK: the host's nanoseconds are whole seconds on the wall clock (never nanoseconds read
#[test]
fn the_host_clock_reads_whole_wall_seconds() {
    let hosted = host_wire();
    let h = hosted.host;
    let issued = AtomicU32::new(0);
    let wire = HostWire::new(&h, Ticket::NONE, &issued);
    assert_eq!(
        wire.clock(),
        Some(HostClock {
            wall_secs: 1_800_000_000,
            mono_ns: 42,
        })
    );

    extern "C" fn wake(_: busbar_contract::abi::mechanism::ticket::HostCtx, _: Ticket) {}
    let h = Host::wake_only(busbar_contract::abi::mechanism::ticket::HostCtx::NONE, wake);
    assert_eq!(HostWire::new(&h, Ticket::NONE, &issued).clock(), None);
}

/// THE HEAD: `POST`, the target's path and query (never its fragment), then each field as
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
    let hosted = host_wire();
    let h = hosted.host;

    let issued = AtomicU32::new(0);
    let driver = hosted
        ._dispatcher
        .driver(&hosted._plugin, 0)
        .expect("the actual host mints this instance's driver ticket");
    let wire = HostWire::new(&h, driver, &issued);
    let mut connector = h.connector_from(driver, 0);
    let stream = match connector.establish(1, Some("https://oauth2.googleapis.com/token"), "") {
        std::task::Poll::Ready(Ok(id)) => id,
        other => panic!("declared stream: {other:?}"),
    };
    let req = TokenRequest {
        need: 1,
        target: "https://oauth2.googleapis.com/token".to_owned(),
        fields: vec![],
        body: busbar_contract::abi::sdk::cred::FormBody::new(),
    };
    let (bytes, piece) = head(&req, 0).unwrap();
    assert!(matches!(
        connector.write_request(stream, &piece, &bytes),
        std::task::Poll::Ready(Ok(_))
    ));
    for kind in [
        busbar_contract::abi::host::conn::connector::REQUEST_BODY,
        busbar_contract::abi::host::conn::connector::REQUEST_END,
    ] {
        assert!(matches!(
            connector.write_request(
                stream,
                &busbar_contract::abi::host::conn::connector::RequestPiece {
                    kind,
                    ..Default::default()
                },
                &[]
            ),
            std::task::Poll::Ready(Ok(_))
        ));
    }
    issued.store(connector.issued(), std::sync::atomic::Ordering::Release);
    let mut buf = [0_u8; 1024];
    let got = wire.read(ConnId(stream), &mut buf).expect("the head");
    assert_eq!(
        (got.kind, got.status, got.retry_after),
        (PieceKind::Fields, Some(200), Some(RetryAfter::Secs(7)))
    );
    let got = wire.read(ConnId(stream), &mut buf).expect("the body");
    assert_eq!(
        (got.kind, got.len, got.end),
        (PieceKind::Body, body.len(), false)
    );
    assert_eq!(&buf[..got.len], &body[..]);
    let terminal = SCRIPT
        .lock()
        .unwrap()
        .replies
        .pop_front()
        .expect("queued completion");
    assert_eq!(
        wire.read(ConnId(stream), &mut buf).err(),
        Some(ConnError::Pending),
        "nothing more is ready"
    );
    SCRIPT.lock().unwrap().replies.push_front(terminal);
    let got = wire.read(ConnId(stream), &mut buf).expect("the end");
    assert_eq!((got.kind, got.end), (PieceKind::Completion, true));

    wire.close(ConnId(stream));
    {
        let mut s = SCRIPT.lock().unwrap();
        assert_eq!(
            s.deadlines,
            [(0, 0)],
            "the probe keeps need-default dial and request deadlines distinct"
        );
        s.deadlines.clear();
        s.established.clear();
        s.opened.clear();
        s.closed = 0;
    }
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
    // This mint has its own issued-service sequence starting at zero. A fresh real ticket
    // prevents replay of the independent probe's already completed/closed service handles.
    let mint_driver = hosted
        ._dispatcher
        .driver(&hosted._plugin, 0)
        .expect("the actual host mints a distinct driver for the mint");
    assert_ne!(
        mint_driver, driver,
        "independent service sequences cannot share completion handles"
    );
    o.tick(1_000, mint_driver, Some(&h), &mut Diags::default());
    let s = SCRIPT.lock().unwrap();
    assert_eq!(
        s.established,
        [("https://oauth2.googleapis.com/token".to_string(), 1)]
    );
    assert_eq!(
        s.deadlines,
        [(0, 30_000)],
        "the actual OAuth need's default dial and mint request deadlines"
    );
    assert_eq!(s.opened.len(), 1);
    let (method, path, fields, body) = &s.opened[0];
    assert_eq!(method, b"POST");
    assert_eq!(path, b"/token");
    assert_eq!(
        fields,
        &[
            (
                "content-type".to_owned(),
                b"application/x-www-form-urlencoded".to_vec()
            ),
            ("accept".to_owned(), b"*/*".to_vec()),
        ]
    );
    assert_eq!(s.closed, 1, "the connection is closed");
    let form = String::from_utf8(body.clone()).expect("a form");
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
    let answer = o.answer(&ask, Some(&h), &mut |v| {
        written.push(crate::test_support::bearer_text(v))
    });
    assert!(matches!(
        answer,
        std::task::Poll::Ready(busbar_contract::abi::sdk::auth_outbound::FieldsAnswer::Ready)
    ));
    assert_eq!(written, ["Bearer ya29.wire"]);
}
