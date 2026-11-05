// SPDX-License-Identifier: Apache-2.0
//! Observe the actual OAuth door's private HostWire at its public raw host boundary.
//! The callbacks supply clock/connection values; all grant and request production is OAuth's.

use base64::Engine as _;
use busbar_contract::abi::{
    auth::{
        self, FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
        OutboundReadyOut,
    },
    host::{
        conn::connector::{
            self as conn, ConnectorSlots, EstablishIn, FactsIn, ReplyIn, ReplyPiece, RequestIn,
            RequestPiece, StreamFacts, StreamIn,
        },
        service::{self, ClockNowIn, ClockReading, HostSlots, ServiceOut},
    },
    mechanism::{
        call::{
            AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_OCTETS,
            BLOB_SECRET,
        },
        lifecycle::{self as life, OpenIn, OpenOut, TickIn, TickOut},
        ticket::{HostCtx, HostTables, Ticket},
    },
    transport::FrameSpan,
};
use busbar_plugin_loader::dispatch::{in_head, out_head};
use std::{collections::VecDeque, ffi::c_void, mem::size_of, sync::Mutex};

const CTX: HostCtx = HostCtx {
    handle: 0x6f61757468,
};
const DRIVER: Ticket = Ticket {
    slot: 1,
    generation: 1,
};
const WALL_NS: u64 = 1_800_000_000_999_999_999;
const SECOND_NS: u64 = 1_000_000_000;
static TEST_LOCK: Mutex<()> = Mutex::new(());
const BODY: &[u8] = br#"{"access_token":"ya29.wire","token_type":"Bearer","expires_in":3600}"#;

#[derive(Debug)]
enum Crossing {
    Establish(String, u32),
    Write(RequestPiece, Vec<u8>),
    Read(u32, Vec<u8>),
    Pending,
    Close,
}
struct Trace {
    calls: Vec<Crossing>,
    replies: VecDeque<(ReplyPiece, Vec<u8>)>,
    clocks: usize,
    wakes: Vec<Ticket>,
    errors: Vec<String>,
    wall_ns: u64,
    secure: bool,
    facts_reads: usize,
}
static TRACE: Mutex<Trace> = Mutex::new(Trace {
    calls: Vec::new(),
    replies: VecDeque::new(),
    clocks: 0,
    wakes: Vec::new(),
    errors: Vec::new(),
    wall_ns: WALL_NS,
    secure: false,
    facts_reads: 0,
});

// SAFETY: every callback below is installed only in its named host ABI slot. OAuth lends the
// typed input/output and pointed-to buffers for that crossing; copies remain owned by this test.
fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: usize) -> RawOutcome {
    let raw = RawOutcome::of(outcome);
    // SAFETY: every callback verifies a non-null live ServiceOut from the actual SDK call.
    if !out.is_null() {
        unsafe {
            *out = ServiceOut {
                size: size_of::<ServiceOut>() as u32,
                outcome: raw,
                value,
                len: len as u64,
                ..std::mem::zeroed()
            };
        }
    }
    raw
}
fn valid(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> bool {
    if ctx == CTX && !input.is_null() && !out.is_null() {
        return true;
    }
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .errors
        .push("invalid host context or null ABI frame".into());
    false
}
fn refused(out: *mut ServiceOut, reason: &str) -> RawOutcome {
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .errors
        .push(reason.into());
    answer(out, Outcome::Fault, 0, 0)
}
extern "C" fn clock(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if !valid(ctx, input, out) {
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: CLOCK_NOW lends its concrete input and writable ClockReading for this crossing.
    let reading = unsafe { (*input.cast::<ClockNowIn>()).reading };
    if reading.is_null() {
        return refused(out, "CLOCK_NOW missing reading buffer");
    }
    let mut trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
    // SAFETY: non-null writable reading belongs to the live input from this actual SDK call.
    unsafe {
        *reading = ClockReading {
            size: size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: trace.wall_ns,
            mono_ns: 42,
        };
    }
    trace.clocks += 1;
    answer(out, Outcome::Ready, 0, 0)
}
extern "C" fn establish(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if !valid(ctx, input, out) {
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: ESTABLISH lends this concrete input and its target bytes for this crossing.
    let i = unsafe { &*input.cast::<EstablishIn>() };
    let Ok(target) = (unsafe { i.target.as_str() }) else {
        return refused(out, "ESTABLISH target is not UTF-8");
    };
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .calls
        .push(Crossing::Establish(target.to_owned(), i.need));
    answer(out, Outcome::Ready, 5, 0)
}
extern "C" fn facts(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if !valid(ctx, input, out) {
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: FACTS lends its concrete input and writable StreamFacts for this crossing.
    let i = unsafe { &*input.cast::<FactsIn>() };
    if i.stream != 5 || i.facts.is_null() {
        return refused(out, "FACTS invalid stream or missing facts buffer");
    }
    let mut trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
    trace.facts_reads += 1;
    // This fixture explicitly models a completed handshake, independently of the target URL.
    // SAFETY: the checked non-null facts pointer is the SDK's live writable output loan.
    unsafe {
        *i.facts = StreamFacts {
            size: size_of::<StreamFacts>() as u32,
            secure: u32::from(trace.secure),
            ..zero()
        };
    }
    answer(out, Outcome::Ready, 0, 0)
}
extern "C" fn write_request(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    if !valid(ctx, input, out) {
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: WRITE_REQUEST lends this input, its descriptor and exactly len bytes.
    let i = unsafe { &*input.cast::<RequestIn>() };
    if i.stream != 5 || i.piece.is_null() || (i.len != 0 && i.buf.is_null()) {
        return refused(out, "WRITE_REQUEST invalid stream or lent buffer");
    }
    // SAFETY: the descriptor and nonempty buffer are live loans from the actual SDK crossing.
    let (piece, bytes) = unsafe {
        (
            *i.piece,
            if i.len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(i.buf, i.len).to_vec()
            },
        )
    };
    let len = bytes.len();
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .calls
        .push(Crossing::Write(piece, bytes));
    answer(out, Outcome::Ready, 0, len)
}
extern "C" fn read_reply(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if !valid(ctx, input, out) {
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: READ_REPLY lends this concrete input, writable descriptor and byte buffer.
    let i = unsafe { &*input.cast::<ReplyIn>() };
    if i.stream != 5 || i.piece.is_null() || (i.len != 0 && i.buf.is_null()) {
        return refused(out, "READ_REPLY invalid stream or lent buffer");
    }
    let mut trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
    let Some((piece, bytes)) = trace.replies.pop_front() else {
        trace.calls.push(Crossing::Pending);
        return answer(out, Outcome::Pending, 0, 0);
    };
    if bytes.len() > i.len {
        trace.errors.push("READ_REPLY buffer too short".into());
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: length checked against the live writable SDK buffer; descriptor is its live loan.
    unsafe {
        if !bytes.is_empty() {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.buf, bytes.len());
        }
        *i.piece = piece;
    }
    let len = bytes.len();
    trace.calls.push(Crossing::Read(piece.kind, bytes));
    answer(out, Outcome::Ready, 0, len)
}
extern "C" fn close(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if !valid(ctx, input, out) {
        return answer(out, Outcome::Fault, 0, 0);
    }
    // SAFETY: CLOSE lends this live StreamIn.
    if unsafe { (*input.cast::<StreamIn>()).stream } != 5 {
        return refused(out, "CLOSE wrong stream");
    }
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .calls
        .push(Crossing::Close);
    answer(out, Outcome::Ready, 0, 0)
}
extern "C" fn wake(ctx: HostCtx, ticket: Ticket) {
    let mut trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
    if ctx != CTX {
        trace.errors.push("WAKE wrong context".into());
        return;
    }
    trace.wakes.push(ticket);
}
fn ih<T>(op: u32, ticket: Ticket) -> InHead {
    let mut h = in_head();
    h.size = size_of::<T>() as u32;
    h.op = op;
    h.host = CTX;
    h.ticket = ticket;
    h
}
fn oh<T>() -> OutHead {
    let mut h = out_head();
    h.size = size_of::<T>() as u32;
    h
}
fn blob(bytes: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags,
    }
}
fn text(value: &str) -> AbiStr {
    AbiStr {
        ptr: value.as_ptr(),
        len: value.len(),
    }
}
fn zero<T>() -> T {
    // SAFETY: used only for zero-valid C ABI structs of numbers, raw pointers and Option<fn>.
    unsafe { std::mem::zeroed() }
}
fn call<I, O>(op: Op, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    // SAFETY: each call below selects the actual door's corresponding typed slot and lends the
    // matching live I/O frame. Instance comes from its successful OPEN and lives until CLOSE.
    unsafe {
        op(
            instance,
            std::ptr::from_ref(input).cast(),
            std::ptr::from_mut(out).cast(),
        )
        .outcome()
    }
}
fn span(bytes: &[u8], range: FrameSpan) -> &[u8] {
    &bytes[range.offset as usize..(range.offset + range.len) as usize]
}

#[test]
fn actual_jwt_door_emits_raw_host_wire_pieces_and_waits_for_completion() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    *TRACE.lock().unwrap_or_else(|p| p.into_inner()) = Trace {
        calls: Vec::new(),
        replies: VecDeque::new(),
        clocks: 0,
        wakes: Vec::new(),
        errors: Vec::new(),
        wall_ns: WALL_NS,
        secure: true,
        facts_reads: 0,
    };
    let services = HostSlots {
        size: size_of::<HostSlots>() as u32,
        slots: service::SERVICES,
        clock_now: Some(clock),
        ..zero()
    };
    let connector = ConnectorSlots {
        size: size_of::<ConnectorSlots>() as u32,
        slots: conn::SERVICES,
        establish: Some(establish),
        facts: Some(facts),
        write_request: Some(write_request),
        read_reply: Some(read_reply),
        close: Some(close),
        ..zero()
    };
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: CTX,
        wake: Some(wake),
        conns: &connector,
        services: &services,
        io: std::ptr::null(),
    };
    // SAFETY: the actual product's public door owns its static, complete auth Ops table.
    let ops = unsafe { &*busbar_auth_oauth::door().ops().cast::<auth::Ops>() };
    let open = OpenIn {
        head: ih::<OpenIn>(life::slot::OPEN, Ticket::NONE),
        host: &tables,
        settings: blob(b"{}", BLOB_JSON, 0),
        generation: 1,
        ..zero()
    };
    let mut opened = OpenOut {
        head: oh::<OpenOut>(),
        ..zero()
    };
    assert_eq!(
        call(
            ops.head.open.unwrap(),
            std::ptr::null_mut(),
            &open,
            &mut opened
        ),
        Outcome::Ready
    );
    assert!(!opened.instance.is_null());
    let credential=serde_json::json!({"client_email":"svc@proj.iam.gserviceaccount.com","private_key":include_str!("../../auth-oauth/src/tests/fixtures/test_sa_key.pem"),"token_uri":"https://oauth2.googleapis.com/token"}).to_string();
    let binding = OpenOutboundIn {
        head: ih::<OpenOutboundIn>(auth::slot::OPEN_OUTBOUND, Ticket::NONE),
        style: text("jwt-bearer"),
        credential: blob(credential.as_bytes(), BLOB_OCTETS, BLOB_SECRET),
        settings: blob(b"{}", BLOB_JSON, 0),
    };
    let mut bound = OpenOutboundOut {
        head: oh::<OpenOutboundOut>(),
        ..zero()
    };
    assert_eq!(
        call(
            ops.open_outbound.unwrap(),
            opened.instance,
            &binding,
            &mut bound
        ),
        Outcome::Ready
    );
    let block = b"retry-after: 7\r\n".to_vec();
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .replies
        .extend([
            (
                ReplyPiece {
                    kind: conn::REPLY_HEAD,
                    code: 200,
                    reason: FrameSpan { offset: 0, len: 0 },
                    fields: FrameSpan {
                        offset: 0,
                        len: block.len() as u64,
                    },
                },
                block,
            ),
            (
                ReplyPiece {
                    kind: conn::REPLY_BODY,
                    ..ReplyPiece::default()
                },
                BODY.to_vec(),
            ),
        ]);
    let tick = TickIn {
        head: ih::<TickIn>(life::slot::TICK, DRIVER),
        now_ns: 1_000,
    };
    let mut ticked = TickOut {
        head: oh::<TickOut>(),
        ..zero()
    };
    assert_eq!(
        call(ops.head.tick.unwrap(), opened.instance, &tick, &mut ticked),
        Outcome::Ready
    );
    // A complete JSON body alone is not completion: actual HostWire must map BODY to end=false,
    // then map an empty host reply queue to Pending instead of publishing a partial mint.
    let ready = OutboundReadyIn {
        head: ih::<OutboundReadyIn>(auth::slot::OUTBOUND_READY, Ticket::NONE),
        handle: bound.handle,
    };
    let mut readiness = OutboundReadyOut {
        head: oh::<OutboundReadyOut>(),
        ..zero()
    };
    assert_eq!(
        call(
            ops.outbound_ready.unwrap(),
            opened.instance,
            &ready,
            &mut readiness
        ),
        Outcome::Ready
    );
    assert_eq!(readiness.ready, 0);
    {
        let trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            trace.errors.is_empty(),
            "raw host callback observations: {:?}",
            trace.errors
        );
        assert!(matches!(trace.calls.last(), Some(Crossing::Pending)));
        assert!(trace.facts_reads > 0, "the mint checked observed security");
        assert!(!trace.calls.iter().any(|c| matches!(c, Crossing::Close)));
    }
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .replies
        .push_back((
            ReplyPiece {
                kind: conn::REPLY_END,
                ..ReplyPiece::default()
            },
            Vec::new(),
        ));
    let tick = TickIn {
        head: ih::<TickIn>(life::slot::TICK, DRIVER),
        now_ns: 1_001,
    };
    assert_eq!(
        call(ops.head.tick.unwrap(), opened.instance, &tick, &mut ticked),
        Outcome::Ready
    );
    assert_eq!(
        call(
            ops.outbound_ready.unwrap(),
            opened.instance,
            &ready,
            &mut readiness
        ),
        Outcome::Ready
    );
    assert_eq!(readiness.ready, 1);
    let mut bytes = [0u8; 256];
    let mut fields: [FieldSpan; 1] = [zero()];
    let mut ask = FieldsIn {
        head: ih::<FieldsIn>(auth::slot::FIELDS, Ticket::NONE),
        handle: bound.handle,
        mode: auth::MODE_OWN,
        point: auth::POINT_HEAD,
        field_buf: bytes.as_mut_ptr(),
        field_buf_cap: bytes.len(),
        fields: fields.as_mut_ptr(),
        fields_cap: 1,
        ..zero()
    };
    let mut answer = FieldsOut {
        head: oh::<FieldsOut>(),
        ..zero()
    };
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Refused
    );
    // Incoming BLOB_SECRET marks sensitivity, not a fabricated connection-security floor.
    // The actual returned bearer DOES require host custody of its secure-connection requirement.
    let error = unsafe { answer.head.error.as_str().unwrap() };
    assert_eq!(
        error,
        busbar_contract::abi::sdk::auth_outbound::SEALED_FIELDS_UNSUPPORTED
    );
    let custody = busbar_contract::abi::mechanism::extensions::encode(&[(
        busbar_contract::abi::sdk::auth_outbound::EXT_SEALED_FIELDS,
        busbar_contract::abi::sdk::auth_outbound::SEALED_FIELDS_V1,
    )]);
    ask.head.extensions = blob(&custody, BLOB_OCTETS, 0);
    let mut answer = FieldsOut {
        head: oh::<FieldsOut>(),
        ..zero()
    };
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Ready
    );
    // SAFETY: the successful actual FIELDS reply lends its extension for this call's result.
    let ext = unsafe {
        std::slice::from_raw_parts(answer.head.extensions.ptr, answer.head.extensions.len)
    };
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::get(
            ext,
            busbar_contract::abi::sdk::auth_outbound::EXT_SEALED_FIELDS
        ),
        Some(busbar_contract::abi::sdk::auth_outbound::SEALED_FIELDS_V1)
    );
    assert_eq!(answer.fields_len, 1);
    let field = fields[0];
    assert_eq!(
        &bytes[field.name.offset as usize..(field.name.offset + field.name.len) as usize],
        b"authorization"
    );
    assert_eq!(
        &bytes[field.value.offset as usize..(field.value.offset + field.value.len) as usize],
        b"Bearer ya29.wire"
    );
    assert_eq!(field.flags & auth::FIELD_SENSITIVE, auth::FIELD_SENSITIVE);
    let trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        trace.errors.is_empty(),
        "raw host callback observations: {:?}",
        trace.errors
    );
    assert!(
        trace.clocks > 0,
        "the actual JWT mint reads the host wall clock"
    );
    assert_eq!(
        trace.calls.len(),
        9,
        "establish, three writes, head/body/pending/end reads, one close: {:?}",
        trace.calls
    );
    assert!(
        matches!(&trace.calls[0],Crossing::Establish(url,1) if url=="https://oauth2.googleapis.com/token")
    );
    let writes: Vec<_> = trace
        .calls
        .iter()
        .filter_map(|c| {
            if let Crossing::Write(p, b) = c {
                Some((p, b))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        writes.iter().map(|(p, _)| p.kind).collect::<Vec<_>>(),
        [conn::REQUEST_HEAD, conn::REQUEST_BODY, conn::REQUEST_END]
    );
    assert_eq!(span(writes[0].1, writes[0].0.method), b"POST");
    assert_eq!(span(writes[0].1, writes[0].0.target), b"/token");
    assert_eq!(
        span(writes[0].1, writes[0].0.fields),
        b"content-type: application/x-www-form-urlencoded\r\naccept: */*\r\n"
    );
    assert_eq!(writes[0].0.timeout_ms, 30_000);
    assert!(writes[2].1.is_empty());
    let form = std::str::from_utf8(writes[1].1).unwrap();
    let assertion = form.split("assertion=").nth(1).unwrap();
    let claims = assertion.split('.').nth(1).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["iat"], 1_800_000_000_u64);
    assert_eq!(claims["exp"], 1_800_003_600_u64);
    assert!(
        matches!(&trace.calls[4],Crossing::Read(conn::REPLY_HEAD,b) if b==b"retry-after: 7\r\n")
    );
    assert!(matches!(&trace.calls[5],Crossing::Read(conn::REPLY_BODY,b) if b==BODY));
    assert!(matches!(trace.calls[6], Crossing::Pending));
    assert!(matches!(&trace.calls[7],Crossing::Read(conn::REPLY_END,b) if b.is_empty()));
    assert!(matches!(trace.calls[8], Crossing::Close));
    drop(trace);
    let close = ih::<InHead>(life::slot::CLOSE, Ticket::NONE);
    let mut closed = oh::<OutHead>();
    assert_eq!(
        call(
            ops.head.close.unwrap(),
            opened.instance,
            &close,
            &mut closed
        ),
        Outcome::Ready
    );
}

#[test]
fn actual_on_demand_door_obeys_the_raw_head_retry_after_seven_seconds() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    *TRACE.lock().unwrap_or_else(|p| p.into_inner()) = Trace {
        calls: Vec::new(),
        replies: VecDeque::new(),
        clocks: 0,
        wakes: Vec::new(),
        errors: Vec::new(),
        wall_ns: WALL_NS,
        secure: true,
        facts_reads: 0,
    };
    let services = HostSlots {
        size: size_of::<HostSlots>() as u32,
        slots: service::SERVICES,
        clock_now: Some(clock),
        ..zero()
    };
    let connector = ConnectorSlots {
        size: size_of::<ConnectorSlots>() as u32,
        slots: conn::SERVICES,
        establish: Some(establish),
        facts: Some(facts),
        write_request: Some(write_request),
        read_reply: Some(read_reply),
        close: Some(close),
        ..zero()
    };
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: CTX,
        wake: Some(wake),
        conns: &connector,
        services: &services,
        io: std::ptr::null(),
    };
    // SAFETY: the actual OAuth door owns this complete static auth Ops table.
    let ops = unsafe { &*busbar_auth_oauth::door().ops().cast::<auth::Ops>() };
    let open = OpenIn {
        head: ih::<OpenIn>(life::slot::OPEN, Ticket::NONE),
        host: &tables,
        settings: blob(b"{}", BLOB_JSON, 0),
        generation: 1,
        ..zero()
    };
    let mut opened = OpenOut {
        head: oh::<OpenOut>(),
        ..zero()
    };
    assert_eq!(
        call(
            ops.head.open.unwrap(),
            std::ptr::null_mut(),
            &open,
            &mut opened
        ),
        Outcome::Ready
    );
    let settings =
        br#"{"token_url":"https://oauth2.googleapis.com/token","resource":"https://api.example/"}"#;
    let binding = OpenOutboundIn {
        head: ih::<OpenOutboundIn>(auth::slot::OPEN_OUTBOUND, Ticket::NONE),
        style: text("oauth-token-exchange"),
        credential: blob(b"subject", BLOB_OCTETS, BLOB_SECRET),
        settings: blob(settings, BLOB_JSON, 0),
    };
    let mut bound = OpenOutboundOut {
        head: oh::<OpenOutboundOut>(),
        ..zero()
    };
    assert_eq!(
        call(
            ops.open_outbound.unwrap(),
            opened.instance,
            &binding,
            &mut bound
        ),
        Outcome::Ready
    );
    let tick = TickIn {
        head: ih::<TickIn>(life::slot::TICK, DRIVER),
        now_ns: 1_000,
    };
    let mut ticked = TickOut {
        head: oh::<TickOut>(),
        ..zero()
    };
    assert_eq!(
        call(ops.head.tick.unwrap(), opened.instance, &tick, &mut ticked),
        Outcome::Ready
    );
    assert!(
        TRACE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .calls
            .is_empty(),
        "on-demand does not mint before a request"
    );
    let mut bytes = [0u8; 256];
    let mut fields: [FieldSpan; 1] = [zero()];
    let scope = busbar_contract::abi::mechanism::extensions::encode(&[
        (auth::EXT_SCOPE, b"read:things".as_slice()),
        (
            busbar_contract::abi::sdk::auth_outbound::EXT_SEALED_FIELDS,
            busbar_contract::abi::sdk::auth_outbound::SEALED_FIELDS_V1,
        ),
    ]);
    let mut ask = FieldsIn {
        head: ih::<FieldsIn>(
            auth::slot::FIELDS,
            Ticket {
                slot: 2,
                generation: 1,
            },
        ),
        handle: bound.handle,
        mode: auth::MODE_OWN,
        point: auth::POINT_HEAD,
        field_buf: bytes.as_mut_ptr(),
        field_buf_cap: bytes.len(),
        fields: fields.as_mut_ptr(),
        fields_cap: 1,
        ..zero()
    };
    ask.head.extensions = blob(&scope, BLOB_OCTETS, 0);
    ask.request.timestamp = 1_800_000_000;
    let mut answer = FieldsOut {
        head: oh::<FieldsOut>(),
        ..zero()
    };
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Pending
    );
    let block = b"retry-after: 7\r\n".to_vec();
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .replies
        .extend([
            (
                ReplyPiece {
                    kind: conn::REPLY_HEAD,
                    code: 503,
                    reason: FrameSpan { offset: 0, len: 0 },
                    fields: FrameSpan {
                        offset: 0,
                        len: block.len() as u64,
                    },
                },
                block,
            ),
            (
                ReplyPiece {
                    kind: conn::REPLY_BODY,
                    ..ReplyPiece::default()
                },
                BODY.to_vec(),
            ),
            (
                ReplyPiece {
                    kind: conn::REPLY_END,
                    ..ReplyPiece::default()
                },
                Vec::new(),
            ),
        ]);
    assert_eq!(
        call(ops.head.tick.unwrap(), opened.instance, &tick, &mut ticked),
        Outcome::Ready
    );
    // The body is valid token JSON, so refusing it observes the actual HostWire's status mapping.
    ask.head.flags = busbar_contract::abi::mechanism::call::FLAG_RESUME;
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Failed
    );
    assert_eq!(
        TRACE
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| matches!(c, Crossing::Establish(..)))
            .count(),
        1
    );
    TRACE.lock().unwrap_or_else(|p| p.into_inner()).wall_ns = WALL_NS + 6 * SECOND_NS;
    ask.request.timestamp = 1_800_000_006;
    ask.head.ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    ask.head.flags = 0;
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Failed
    );
    let tick = TickIn {
        head: ih::<TickIn>(life::slot::TICK, DRIVER),
        now_ns: 6 * SECOND_NS + 1_000,
    };
    assert_eq!(
        call(ops.head.tick.unwrap(), opened.instance, &tick, &mut ticked),
        Outcome::Ready
    );
    assert_eq!(
        TRACE
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| matches!(c, Crossing::Establish(..)))
            .count(),
        1,
        "no retry at six seconds"
    );
    TRACE.lock().unwrap_or_else(|p| p.into_inner()).wall_ns = WALL_NS + 7 * SECOND_NS;
    ask.request.timestamp = 1_800_000_007;
    ask.head.ticket = Ticket {
        slot: 4,
        generation: 1,
    };
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Pending
    );
    TRACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .replies
        .extend([
            (
                ReplyPiece {
                    kind: conn::REPLY_HEAD,
                    code: 200,
                    ..ReplyPiece::default()
                },
                Vec::new(),
            ),
            (
                ReplyPiece {
                    kind: conn::REPLY_BODY,
                    ..ReplyPiece::default()
                },
                BODY.to_vec(),
            ),
            (
                ReplyPiece {
                    kind: conn::REPLY_END,
                    ..ReplyPiece::default()
                },
                Vec::new(),
            ),
        ]);
    let tick = TickIn {
        head: ih::<TickIn>(life::slot::TICK, DRIVER),
        now_ns: 7 * SECOND_NS + 1_000,
    };
    assert_eq!(
        call(ops.head.tick.unwrap(), opened.instance, &tick, &mut ticked),
        Outcome::Ready
    );
    ask.head.flags = busbar_contract::abi::mechanism::call::FLAG_RESUME;
    assert_eq!(
        call(ops.fields.unwrap(), opened.instance, &ask, &mut answer),
        Outcome::Ready
    );
    assert_eq!(answer.fields_len, 1);
    let value = fields[0].value;
    assert_eq!(
        &bytes[value.offset as usize..(value.offset + value.len) as usize],
        b"Bearer ya29.wire"
    );
    let trace = TRACE.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        trace.errors.is_empty(),
        "raw host callback observations: {:?}",
        trace.errors
    );
    assert_eq!(
        trace
            .calls
            .iter()
            .filter(|c| matches!(c, Crossing::Establish(..)))
            .count(),
        2,
        "exactly one retry at seven seconds"
    );
    assert_eq!(
        trace
            .calls
            .iter()
            .filter(|c| matches!(c, Crossing::Close))
            .count(),
        2
    );
    assert!(
        matches!(trace.calls.last(), Some(Crossing::Close)),
        "no reads after completion"
    );
    assert!(trace.facts_reads > 0, "the mint checked observed security");
    drop(trace);
    let close = ih::<InHead>(life::slot::CLOSE, Ticket::NONE);
    let mut closed = oh::<OutHead>();
    assert_eq!(
        call(
            ops.head.close.unwrap(),
            opened.instance,
            &close,
            &mut closed
        ),
        Outcome::Ready
    );
}
