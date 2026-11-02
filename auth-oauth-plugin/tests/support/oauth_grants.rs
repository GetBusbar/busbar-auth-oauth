// SPDX-License-Identifier: Apache-2.0
//! Actual OAuth grant cases over the product doors.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, FieldSpan, FieldsIn, FieldsOut, NamedValue, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, RequestFacts, MODE_OWN, POINT_HEAD_BODY,
    STYLE_NEEDS_HEADERS,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, RawOutcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, now_ns, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, Lent,
    LinkedRow, NoSink, Plugin, Reply,
};
/// The request one `fields` call signs.
#[derive(Clone)]
struct Head {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    timestamp: u64,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
    /// The call's extensions blob entries (`head.extensions`), in order.
    extensions: Vec<(String, String)>,
}

impl Head {
    /// This head with the extension `key` set to `value` (added when absent).
    fn with_extension(&self, key: &str, value: &str) -> Self {
        let mut h = self.clone();
        match h.extensions.iter_mut().find(|(k, _)| k == key) {
            Some(e) => value.clone_into(&mut e.1),
            None => h.extensions.push((key.to_string(), value.to_string())),
        }
        h
    }

    /// This head at another request instant.
    fn at(&self, timestamp: u64) -> Self {
        let mut h = self.clone();
        h.timestamp = timestamp;
        h
    }

    /// The encoded extensions blob.
    fn extensions_blob(&self) -> Vec<u8> {
        if self.extensions.is_empty() {
            return Vec::new();
        }
        let entries: Vec<(&str, &[u8])> = self
            .extensions
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes()))
            .collect();
        extensions::encode(&entries)
    }
}

/// What one token request must be.
struct ExpectRequest {
    method: String,
    target: String,
    fields_subset: Vec<(String, String)>,
    body: Option<String>,
    body_prefix: Option<String>,
}

/// One scripted exchange: the request it expects and the answer it gives.
struct Exchange {
    expect: ExpectRequest,
    status: u32,
    body: Vec<u8>,
}

/// A minting style's token endpoint script.
struct Minting {
    exchanges: Vec<Exchange>,
    expires_in: u64,
    /// Tick-driven: the refreshed token's fields. On demand: unused.
    refreshed: String,
    refusal: String,
    /// `"mint": "on_demand"`: minted per call, one cell per scope.
    on_demand: Option<OnDemand>,
}

/// An on-demand style's second scope and the fields its later exchanges write.
struct OnDemand {
    second_scope: String,
    second: String,
    expired: String,
}

/// One `auth.outbound` entry.
struct Style {
    style: String,
    credential: Option<Vec<u8>>,
    settings: Vec<u8>,
    head: Head,
    expect: String,
    minting: Option<Minting>,
}

fn str_of<'a>(v: &'a serde_json::Value, what: &str) -> &'a str {
    v.as_str()
        .unwrap_or_else(|| panic!("conformance.json: {what} must be a string"))
}

fn pairs(v: &serde_json::Value, what: &str) -> Vec<(String, String)> {
    match v {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(|p| {
                let p = p.as_array().unwrap_or_else(|| {
                    panic!("conformance.json: {what} holds [name, value] pairs")
                });
                (
                    str_of(&p[0], what).to_string(),
                    str_of(&p[1], what).to_string(),
                )
            })
            .collect(),
        _ => panic!("conformance.json: {what} is an array of [name, value] pairs"),
    }
}

/// The transcript's spelling of written fields: `name: value (flags=N)`, in order.
fn listing<'a>(fields: impl Iterator<Item = (&'a [u8], &'a [u8], u32)>) -> String {
    fields
        .map(|(n, v, f)| {
            format!(
                "{}: {} (flags={f})",
                String::from_utf8_lossy(n),
                String::from_utf8_lossy(v)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The answer a `fields` call writing exactly `v`'s fields reads as.
fn expected(v: &serde_json::Value, what: &str) -> String {
    let a = v.as_array().unwrap_or_else(|| {
        panic!("conformance.json: {what} is an array of [name, value(, flags)]")
    });
    let owned: Vec<(Vec<u8>, Vec<u8>, u32)> = a
        .iter()
        .map(|p| {
            let p = p
                .as_array()
                .unwrap_or_else(|| panic!("conformance.json: {what} holds [name, value(, flags)]"));
            (
                str_of(&p[0], what).as_bytes().to_vec(),
                str_of(&p[1], what).as_bytes().to_vec(),
                match p.get(2) {
                    // No third element: the field carries no flag.
                    None => 0,
                    Some(f) => f
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .unwrap_or_else(|| {
                            panic!("conformance.json: {what}'s flags must be a u32")
                        }),
                },
            )
        })
        .collect();
    // A style whose expectation is no field at all would pass a door that writes nothing: every
    // outbound style presents something (a header, a query parameter), so an empty list is refused
    // here rather than let the script compare nothing with nothing.
    assert!(
        !owned.is_empty(),
        "conformance.json: {what} is empty: an outbound style writes at least one field, and an \
         empty expectation would pass a door that writes none"
    );
    format!(
        "Ready fields=[{}]",
        listing(
            owned
                .iter()
                .map(|(n, v, f)| (n.as_slice(), v.as_slice(), *f))
        )
    )
}

fn settings_of(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::Null => b"{}".to_vec(),
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        other => other.to_string().into_bytes(),
    }
}

impl Style {
    fn parse(v: &serde_json::Value) -> Self {
        let style = str_of(&v["style"], "auth.outbound[].style").to_string();
        let h = &v["head"];
        assert!(
            h.is_object(),
            "conformance.json: style `{style}` has no `head`"
        );
        let target = str_of(&h["target"], "head.target");
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (target.to_string(), None),
        };
        let head = Head {
            method: str_of(&h["method"], "head.method").to_string(),
            authority: str_of(&h["authority"], "head.authority").to_string(),
            path,
            query,
            timestamp: h["timestamp"].as_u64().unwrap_or_else(|| {
                panic!("conformance.json: style `{style}`'s head.timestamp must be epoch seconds")
            }),
            fields: pairs(&h["fields"], "head.fields"),
            body: h["body"].as_str().unwrap_or("").as_bytes().to_vec(),
            extensions: match &h["extensions"] {
                serde_json::Value::Null => Vec::new(),
                serde_json::Value::Object(m) => m
                    .iter()
                    .map(|(k, v)| (k.clone(), str_of(v, "head.extensions").to_string()))
                    .collect(),
                _ => panic!("conformance.json: style `{style}`'s head.extensions is an object"),
            },
        };
        let on_demand = match v["mint"].as_str() {
            None => false,
            Some("on_demand") => true,
            Some(other) => panic!(
                "conformance.json: style `{style}` states mint `{other}`; the outbound script \
                 knows a tick-driven style (no `mint`) and `on_demand`"
            ),
        };
        let minting = match &v["token_endpoint"] {
            serde_json::Value::Null => None,
            serde_json::Value::Array(a) => {
                assert!(
                    !a.is_empty(),
                    "conformance.json: style `{style}`'s token_endpoint is empty"
                );
                let exchanges = a
                    .iter()
                    .map(|x| {
                        let e = &x["expect_request"];
                        let r = &x["respond"];
                        Exchange {
                            expect: ExpectRequest {
                                method: str_of(&e["method"], "expect_request.method").to_string(),
                                target: str_of(&e["target"], "expect_request.target").to_string(),
                                fields_subset: pairs(
                                    &e["fields_subset"],
                                    "expect_request.fields_subset",
                                ),
                                body: e["body"].as_str().map(String::from),
                                body_prefix: e["body_prefix"].as_str().map(String::from),
                            },
                            status: r["status"]
                                .as_u64()
                                .unwrap_or_else(|| panic!("conformance.json: respond.status"))
                                as u32,
                            body: str_of(&r["body"], "respond.body").as_bytes().to_vec(),
                        }
                    })
                    .collect();
                let on_demand = on_demand.then(|| {
                    assert!(
                        a.len() >= 3,
                        "conformance.json: on-demand style `{style}`'s token_endpoint scripts \
                         three exchanges (S, the second scope, S once expired)"
                    );
                    OnDemand {
                        second_scope: str_of(&v["second_scope"], "second_scope").to_string(),
                        second: expected(&v["second_scope_fields"], "second_scope_fields"),
                        expired: expected(&v["expired_fields"], "expired_fields"),
                    }
                });
                Some(Minting {
                    exchanges,
                    expires_in: v["expires_in"].as_u64().unwrap_or_else(|| {
                        panic!("conformance.json: minting style `{style}` states `expires_in`")
                    }),
                    refreshed: if on_demand.is_some() {
                        String::new()
                    } else {
                        expected(&v["refreshed_fields"], "refreshed_fields")
                    },
                    refusal: str_of(&v["refusal"], "refusal").to_string(),
                    on_demand,
                })
            }
            _ => panic!("conformance.json: style `{style}`'s token_endpoint is an array"),
        };
        assert!(
            !on_demand || minting.is_some(),
            "conformance.json: on-demand style `{style}` scripts its token_endpoint"
        );
        Style {
            credential: v["credential"].as_str().map(|c| c.as_bytes().to_vec()),
            settings: settings_of(&v["settings"]),
            head,
            expect: expected(&v["expect_fields"], "expect_fields"),
            minting,
            style,
        }
    }
}

// ---- the token endpoint: the host's connection table, scripted ----

/// One request the plugin sent over its need.
#[derive(Debug, Clone)]
struct Sent {
    target: String,
    method: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Each open connection's reply, piece by piece, with its bytes.
type Replies = HashMap<ConnId, VecDeque<(Piece, Vec<u8>)>>;

/// A connection table whose needs are framed: each open is ONE token request, recorded, and
/// answered by the script's next reply, one piece per read.
#[derive(Default)]
struct Endpoint {
    framed: bool,
    slab: ConnSlab<()>,
    answers: Vec<(u32, Vec<u8>)>,
    sent: Mutex<Vec<Sent>>,
    replies: Mutex<Replies>,
}

fn piece(kind: PieceKind, len: usize, status: Option<u32>) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: kind != PieceKind::Fields,
        status: None,
        status_code: status,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl Endpoint {
    fn new(answers: Vec<(u32, Vec<u8>)>) -> Self {
        Self {
            answers,
            framed: true,
            ..Self::default()
        }
    }

    fn count(&self) -> usize {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Every exchange so far, each judged against its expected request.
    fn report(&self, script: &[Exchange]) -> String {
        let sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        let judged: Vec<String> = sent
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let want = &script[i.min(script.len() - 1)].expect;
                let mut off = Vec::new();
                if s.method != want.method {
                    off.push("method");
                }
                if s.target != want.target {
                    off.push("target");
                }
                if !want
                    .fields_subset
                    .iter()
                    .all(|w| s.fields.iter().any(|f| f == w))
                {
                    off.push("fields");
                }
                if want.body.as_ref().is_some_and(|b| s.body != b.as_bytes()) {
                    off.push("body");
                }
                if want
                    .body_prefix
                    .as_ref()
                    .is_some_and(|b| !s.body.starts_with(b.as_bytes()))
                {
                    off.push("body_prefix");
                }
                if off.is_empty() {
                    "ok".to_string()
                } else {
                    format!("off({})", off.join(","))
                }
            })
            .collect();
        format!("exchanges={} [{}]", sent.len(), judged.join(", "))
    }
}

impl DeclaredConns for Endpoint {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _trust: Option<&str>,
    ) -> Result<(), ConnError> {
        // A `target_from` that resolved to nothing is refused, as the connector refuses it.
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.framed && self.slab.check_need(owner, need).is_ok()
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

impl Conns for Endpoint {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        let n = {
            let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
            sent.push(Sent {
                target: desc.target.to_owned(),
                method: String::from_utf8_lossy(desc.method).into_owned(),
                fields: desc
                    .fields
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), String::from_utf8_lossy(v).into_owned()))
                    .collect(),
                body: desc.body.to_vec(),
            });
            sent.len()
        };
        let (status, body) = self.answers[(n - 1).min(self.answers.len() - 1)].clone();
        let id = self.slab.insert(caller, need, ())?;
        self.replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id,
                VecDeque::from([
                    (piece(PieceKind::Fields, 0, Some(status)), Vec::new()),
                    (piece(PieceKind::Body, body.len(), None), body),
                    (piece(PieceKind::Completion, 0, None), Vec::new()),
                ]),
            );
        Ok(id)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Ok(b.len())
    }
    fn read(&self, c: InstanceId, id: ConnId, _: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let mut replies = self.replies.lock().unwrap_or_else(|e| e.into_inner());
        let queue = replies.get_mut(&id).ok_or(ConnError::Closed)?;
        let (p, bytes) = queue.pop_front().ok_or(ConnError::Closed)?;
        if bytes.len() > buf.len() {
            // The rest of a body larger than the reader's buffer is the next piece.
            let (now, later) = bytes.split_at(buf.len());
            buf.copy_from_slice(now);
            queue.push_front((piece(PieceKind::Body, later.len(), None), later.to_vec()));
            return Ok(Piece {
                len: now.len(),
                end: false,
                ..p
            });
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(p)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        self.slab.remove(c, id).map(|_| ())
    }
}

// ---- the calls ----

fn abi_str(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

const NO_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// `open_outbound` of `x`: its answer and the handle.
fn open_outbound(p: &Plugin<Auth>, x: &Style) -> (String, u64) {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(input(), output());
    f.input.style = abi_str(x.style.as_bytes());
    f.input.credential = x.credential.as_deref().map_or(Blob::ABSENT, secret);
    f.input.settings = json(&x.settings);
    let c = p.call(slot::OPEN_OUTBOUND, &mut f);
    (called(&c), f.out.handle)
}

/// `outbound_ready` of `handle`.
fn ready_fact(p: &Plugin<Auth>, handle: u64) -> String {
    let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(input(), output());
    f.input.handle = handle;
    let c = p.call(slot::OUTBOUND_READY, &mut f);
    format!("{} ready={}", called(&c), f.out.ready)
}

/// THE MEMORY ONE `fields` call lends the plugin: the host's field buffer and spans, the head's
/// lines, its body and its extensions blob. Lent whole to a call on a ticket (the dispatcher keeps
/// it alive until the op completes), so its pointers stay valid however the call ends.
struct Lend {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
    names: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
    lines: Vec<NamedValue>,
    request: [Vec<u8>; 4],
    body: Vec<u8>,
    ext: Vec<u8>,
}

// SAFETY: the raw pointers in `lines` point into `names` and `values`, owned by the same `Lend`;
// nothing mutates a `Lend` once its frame is built but the plugin's writes into `buf` and `spans`,
// which the host reads only after the op completes.
unsafe impl Send for Lend {}
// SAFETY: as above.
unsafe impl Sync for Lend {}

impl Lend {
    fn new(h: &Head) -> Box<Self> {
        let blank = FieldSpan {
            name: Span { offset: 0, len: 0 },
            value: Span { offset: 0, len: 0 },
            flags: 0,
            _reserved: 0,
        };
        let mut l = Box::new(Self {
            buf: vec![0_u8; auth::FIELDS_BUF_BYTES],
            spans: vec![blank; auth::FIELDS_MAX as usize],
            names: h
                .fields
                .iter()
                .map(|(n, _)| n.as_bytes().to_vec())
                .collect(),
            values: h
                .fields
                .iter()
                .map(|(_, v)| v.as_bytes().to_vec())
                .collect(),
            lines: Vec::new(),
            request: [
                h.method.as_bytes().to_vec(),
                h.authority.as_bytes().to_vec(),
                h.path.as_bytes().to_vec(),
                h.query.as_deref().unwrap_or("").as_bytes().to_vec(),
            ],
            body: h.body.clone(),
            ext: h.extensions_blob(),
        });
        l.lines = l
            .names
            .iter()
            .zip(&l.values)
            .map(|(n, v)| NamedValue {
                name: abi_str(n),
                value: Blob {
                    ptr: v.as_ptr(),
                    len: v.len(),
                    fmt: BLOB_OCTETS,
                    flags: 0,
                },
            })
            .collect();
        l
    }

    /// The `fields` input over this memory, at the style's one point.
    fn input(&mut self, handle: u64, h: &Head, flags: u32, point: u32) -> FieldsIn {
        let mut i: FieldsIn = input();
        i.handle = handle;
        i.mode = MODE_OWN;
        i.point = point;
        i.request = RequestFacts {
            method: abi_str(&self.request[0]),
            authority: abi_str(&self.request[1]),
            canonical_path: abi_str(&self.request[2]),
            query: if h.query.is_some() {
                abi_str(&self.request[3])
            } else {
                NO_STR
            },
            timestamp: h.timestamp,
        };
        i.field_buf = self.buf.as_mut_ptr();
        i.field_buf_cap = self.buf.len();
        i.fields = self.spans.as_mut_ptr();
        i.fields_cap = self.spans.len() as u32;
        if flags & STYLE_NEEDS_HEADERS != 0 {
            i.headers = self.lines.as_ptr();
            i.headers_len = self.lines.len();
        }
        if point == POINT_HEAD_BODY {
            i.body = Blob {
                ptr: self.body.as_ptr(),
                len: self.body.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
        if !self.ext.is_empty() {
            i.head.extensions = Blob {
                ptr: self.ext.as_ptr(),
                len: self.ext.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
        i
    }

    /// The transcript's line for an answer: on READY exactly what was written.
    fn answer(
        &self,
        outcome: Outcome,
        error: Option<&[u8]>,
        short: bool,
        out: &FieldsOut,
    ) -> String {
        if outcome != Outcome::Ready {
            let text = error.map(String::from_utf8_lossy).unwrap_or_default();
            let short = if short { " short" } else { "" };
            return format!("{outcome:?}{short} {text}");
        }
        let n = (out.fields_len as usize).min(self.spans.len());
        format!(
            "Ready fields=[{}]",
            listing(self.spans[..n].iter().map(|s| (
                at(&self.buf, s.name),
                at(&self.buf, s.value),
                s.flags
            )))
        )
    }
}

/// ONE `fields` call ("sign"): ticket-less, at the style's one point, over `h`, the host's
/// starting buffers. The answer, and on READY exactly what it wrote.
fn sign(p: &Plugin<Auth>, handle: u64, h: &Head, flags: u32, point: u32) -> String {
    let mut lend = Lend::new(h);
    let mut f: Frame<FieldsIn, FieldsOut> =
        Frame::new(lend.input(handle, h, flags, point), output());
    let c = p.call(slot::FIELDS, &mut f);
    lend.answer(c.outcome, c.error.as_deref(), c.recall.is_some(), &f.out)
}

/// ONE `fields` call ON A TICKET (as the host submits a call the plugin may make wait): minted on
/// the dispatcher, its memory lent to the op. Its reply, and the memory to read the answer from.
struct OnTicket {
    reply: Reply<FieldsIn, FieldsOut>,
    lend: Arc<Lend>,
    /// The answer, when it came before the suite asked whether the call waits.
    early: Option<String>,
}

/// How long a ticket's `fields` may wait before its deadline (well past every wait here).
const FIELDS_DEADLINE: Duration = Duration::from_secs(60);

fn submit_fields(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    handle: u64,
    h: &Head,
    flags: u32,
    point: u32,
) -> OnTicket {
    let ticket = d.mint(0).expect("a request ticket is minted");
    let mut lend = Lend::new(h);
    let input = lend.input(handle, h, flags, point);
    let lend: Arc<Lend> = Arc::from(lend);
    let deadline =
        now_ns().saturating_add(u64::try_from(FIELDS_DEADLINE.as_nanos()).unwrap_or(u64::MAX));
    let reply = d.submit_lent(
        p,
        ticket,
        slot::FIELDS,
        Frame::new(input, output()),
        DeadlineClass::Call,
        deadline,
        Arc::clone(&lend) as Lent,
    );
    OnTicket {
        reply,
        lend,
        early: None,
    }
}

impl OnTicket {
    /// Whether the call is still waiting (PENDING); an answer that already came is kept.
    fn waiting(&mut self) -> bool {
        match self.reply.wait(Duration::ZERO) {
            None => true,
            Some(done) => {
                self.early = Some(self.read(&done));
                false
            }
        }
    }

    fn read(&self, done: &busbar_plugin_loader::dispatch::Done<FieldsIn, FieldsOut>) -> String {
        match done.frame.as_ref() {
            Some(f) => self
                .lend
                .answer(done.outcome, done.error.as_deref(), done.short, &f.out),
            None => format!("{:?} (no frame)", done.outcome),
        }
    }

    /// The answer once the op completes (`no answer` past [`TICK_WAIT`]).
    fn answered(self) -> String {
        if let Some(a) = self.early {
            return a;
        }
        match self.reply.wait(TICK_WAIT) {
            None => {
                // The op runs on; its memory stays with it.
                self.reply.detach();
                "no answer".to_string()
            }
            Some(done) => self.read(&done),
        }
    }
}

/// The bytes `sp` names in the host's field buffer.
fn at(buf: &[u8], sp: Span) -> &[u8] {
    buf.get(sp.offset as usize..sp.offset as usize + sp.len as usize)
        .unwrap_or(&b"<out of the buffer>"[..])
}

/// `tick` at `now_ns` on the instance's driver ticket, awaited: its outcome and `next_tick_ns`.
fn tick_driver(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    clock: &Clock,
    driver: Ticket,
    now_ns: u64,
) -> (String, u64) {
    clock.advance(now_ns);
    let reply = d.tick(p, driver, now_ns);
    let Some(done) = reply.wait(TICK_WAIT) else {
        return ("no answer".to_string(), 0);
    };
    let next = done.frame.as_ref().map_or(0, |f| f.out.next_tick_ns);
    (format!("{:?}", done.outcome), next)
}

const T0: u64 = 1_000_000_000_000;
const NS: u64 = 1_000_000_000;
const TICK_WAIT: Duration = Duration::from_secs(10);
struct Clock {
    wall_origin: u64,
    elapsed: AtomicU64,
}
impl Clock {
    fn advance(&self, at: u64) {
        self.elapsed
            .fetch_max(at.saturating_sub(T0), Ordering::SeqCst);
    }
}
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, RecordsList, Snapshot, Stored,
    TrustKeyRef, UNSERVED,
};

impl HostServices for Clock {
    fn now(&self) -> busbar_contract::services::Reading {
        let elapsed =
            u64::try_from(self.elapsed.load(Ordering::SeqCst) as u128).expect("test clock fits");
        busbar_contract::services::Reading {
            wall_ns: self.wall_origin + elapsed,
            mono_ns: T0 + elapsed,
        }
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

use busbar_plugin_loader::dispatch::{in_head, out_head, Called, InFrame, OutFrame};
fn input<T: InFrame>() -> T {
    // SAFETY: ABI InFrame consists of zero-valid C data and begins with InHead.
    let mut value: T = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::addr_of_mut!(value).cast().write(in_head()) };
    value
}
fn output<T: OutFrame>() -> T {
    // SAFETY: ABI OutFrame consists of zero-valid C data and begins with OutHead.
    let mut value: T = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::addr_of_mut!(value).cast().write(out_head()) };
    value
}
fn json(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    }
}
fn secret(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: busbar_contract::abi::mechanism::call::BLOB_SECRET,
    }
}
fn called(c: &Called) -> String {
    format!(
        "{:?} lease={} {}",
        c.outcome,
        c.lease != 0,
        c.error
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default()
    )
}
fn clock_dispatcher(timestamp: u64) -> (Arc<Clock>, Arc<Dispatcher>) {
    let clock = Arc::new(Clock {
        wall_origin: timestamp.max(1_800_000_000) * NS,
        elapsed: AtomicU64::new(0),
    });
    (
        clock.clone(),
        Arc::new(Dispatcher::with_services(DispatchConfig::default(), clock)),
    )
}
fn counts(p: &Plugin<Auth>) -> u64 {
    p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst)
}
fn count<T>(p: &Plugin<Auth>, expected: u64, op: impl FnOnce() -> T) -> T {
    let before = counts(p);
    let result = op();
    assert_eq!(counts(p) - before, expected, "actual dispatcher crossings");
    result
}
fn product(
    dropped: bool,
    d: &Dispatcher,
    e: Arc<Endpoint>,
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Plugin<Auth> {
    let bind = Bind {
        instance: Arc::from("oauth-grant"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(e),
    };
    if dropped {
        load_dropped::<Auth>(
            &super::built_plugin_image(),
            &busbar_plugin_loader::dispatch::rendering_of(busbar_auth_oauth::door).unwrap(),
            bind,
        )
        .expect("actual OAuth cdylib loads")
    } else {
        load_linked::<Auth>(&LinkedRow::of(door).unwrap(), bind).unwrap()
    }
}
fn close(p: &Plugin<Auth>) {
    let mut f = Frame::new(in_head(), out_head());
    assert_eq!(
        count(p, 1, || p.call(
            busbar_contract::abi::mechanism::lifecycle::slot::CLOSE,
            &mut f
        ))
        .outcome,
        Outcome::Ready
    );
}
fn opened(p: &Plugin<Auth>, d: &Dispatcher, x: &Style) -> u64 {
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ValidateIn};
    let mut v = Frame::new(
        ValidateIn {
            settings: json(&x.settings),
            ..input()
        },
        out_head(),
    );
    assert_eq!(
        count(p, 1, || p.call(life::VALIDATE, &mut v)).outcome,
        Outcome::Ready
    );
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = json(&x.settings);
    assert_eq!(
        count(p, 1, || p.call(life::OPEN, &mut f)).outcome,
        Outcome::Ready
    );
    assert_eq!(
        count(p, u64::from(p.has_ready()), || p.ready(d, TICK_WAIT)),
        Ok(())
    );
    let (answer, h) = count(p, 1, || open_outbound(p, x));
    assert!(answer.starts_with("Ready "), "{answer}");
    h
}
fn flags(x: &Style) -> (u32, u32) {
    // SAFETY: the real product Statement owns the static auth tail and style declarations.
    unsafe {
        let t = &*busbar_auth_oauth::STATEMENT
            .kind_tail
            .cast::<auth::AuthTail>();
        let ds = std::slice::from_raw_parts(t.styles, t.styles_len);
        let decl = ds
            .iter()
            .find(|d| d.name.as_str().unwrap() == x.style)
            .expect("JSON style declared by real product");
        assert_eq!(decl.points.count_ones(), 1);
        (decl.flags, decl.points)
    }
}
fn fields_checked(p: &Plugin<Auth>, h: u64, x: &Style, head: &Head, expected: &str) {
    let (flags, point) = flags(x);
    assert_eq!(
        count(p, 1, || sign(p, h, head, flags, point)),
        expected,
        "expected actual minted fields"
    );
}

#[test]
fn oauth_client_credentials_actual_doors() {
    grant_case(0);
}
#[test]
fn jwt_bearer_actual_doors() {
    grant_case(1);
}
#[test]
fn token_exchange_actual_doors() {
    grant_case(2);
}

fn grant_case(index: usize) {
    grant_case_door(index, busbar_auth_oauth::door, true);
}
fn grant_case_door(index: usize, door: busbar_contract::abi::mechanism::door::DoorFn, both: bool) {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../conformance.json")).unwrap();
    let x = Style::parse(&cases["auth"]["outbound"][index]);
    let mut refusals = Vec::new();
    let mut before_mint = Vec::new();
    for dropped in [false, true].into_iter().filter(|d| both || !d) {
        let m = x.minting.as_ref().unwrap();
        let e = Arc::new(Endpoint::new(
            m.exchanges
                .iter()
                .map(|v| (v.status, v.body.clone()))
                .collect(),
        ));
        let (clock, d) = clock_dispatcher(x.head.timestamp);
        let p = product(dropped, &d, e.clone(), door);
        let h = opened(&p, &d, &x);
        let (flags, point) = flags(&x);
        let driver = d.driver(&p, 0).unwrap();
        if let Some(od) = &m.on_demand {
            let before = counts(&p);
            let mut a = submit_fields(&p, &d, h, &x.head, flags, point);
            let mut b = submit_fields(&p, &d, h, &x.head, flags, point);
            let until = std::time::Instant::now() + TICK_WAIT;
            while counts(&p) < before + 2 && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(counts(&p) - before, 2);
            assert!(a.waiting());
            assert!(b.waiting());
            assert_eq!(e.count(), 0);
            let (answer, _) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, T0));
            assert_eq!(answer, "Ready");
            assert_eq!(a.answered(), x.expect);
            assert_eq!(b.answered(), x.expect);
            assert_eq!(e.count(), 1, "exactly ONE token exchange");
            fields_checked(&p, h, &x, &x.head, &x.expect);
            fields_checked(&p, h, &x, &x.head, &x.expect);
            assert_eq!(
                count(&p, 1, || ready_fact(&p, h)),
                "Ready lease=false  ready=1"
            );
            assert_eq!(e.report(&m.exchanges), "exchanges=1 [ok]");
            count(&p, 1, || {
                tick_driver(&p, &d, &clock, driver, T0 + m.expires_in / 2 * NS)
            });
            assert_eq!(e.count(), 1, "on-demand token not refreshed before expiry");
            let second = x.head.with_extension(auth::EXT_SCOPE, &od.second_scope);
            assert_eq!(
                count(&p, 2, || submit_fields(&p, &d, h, &second, flags, point)
                    .answered()),
                od.second
            );
            assert_eq!(e.count(), 2);
            clock.advance(T0 + (m.expires_in + 1) * NS);
            let expired = x
                .head
                .at((clock.wall_origin + clock.elapsed.load(Ordering::SeqCst)) / NS);
            assert_eq!(
                count(&p, 2, || submit_fields(&p, &d, h, &expired, flags, point)
                    .answered()),
                od.expired
            );
            assert_eq!(e.report(&m.exchanges), "exchanges=3 [ok, ok, ok]");
        } else {
            let before = count(&p, 1, || sign(&p, h, &x.head, flags, point));
            assert!(before.starts_with("Failed ") || before.starts_with("Refused "));
            assert!(!before.split_once(' ').unwrap().1.is_empty());
            before_mint.push(before);
            let (answer, next) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, T0));
            assert_eq!(answer, "Ready");
            assert_eq!(e.count(), 1, "exactly ONE token exchange");
            fields_checked(&p, h, &x, &x.head, &x.expect);
            fields_checked(&p, h, &x, &x.head, &x.expect);
            assert_eq!(e.report(&m.exchanges), "exchanges=1 [ok]");
            assert_eq!(
                count(&p, 1, || ready_fact(&p, h)),
                "Ready lease=false  ready=1"
            );
            assert!(next > T0 && next <= T0 + m.expires_in * NS);
            let (answer, _) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, next));
            assert_eq!(answer, "Ready");
            fields_checked(&p, h, &x, &x.head, &m.refreshed);
            assert_eq!(e.report(&m.exchanges), "exchanges=2 [ok, ok]");
        }
        close(&p);
        assert!(!count(&p, 0, || sign(&p, h, &x.head, flags, point)).starts_with("Ready"));
        let failing = Arc::new(Endpoint::new(vec![(
            500,
            b"conformance: the token endpoint is down".to_vec(),
        )]));
        let (clock, d) = clock_dispatcher(x.head.timestamp);
        let p = product(dropped, &d, failing.clone(), door);
        let h = opened(&p, &d, &x);
        let driver = d.driver(&p, 0).unwrap();
        let (answer, _) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, T0));
        assert_eq!(answer, "Ready");
        let failure = if m.on_demand.is_some() {
            assert_eq!(failing.count(), 0);
            count(&p, 2, || {
                submit_fields(&p, &d, h, &x.head, flags, point).answered()
            })
        } else {
            assert_eq!(failing.count(), 1);
            count(&p, 1, || sign(&p, h, &x.head, flags, point))
        };
        assert!(failure.starts_with(&format!("{} ", m.refusal)), "{failure}");
        if m.on_demand.is_some() {
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(failing.count(), 1, "failed exchange does not retry");
        } else {
            assert!(!failure.split_once(' ').unwrap().1.is_empty());
            assert_eq!(
                count(&p, 1, || ready_fact(&p, h)),
                "Ready lease=false  ready=0"
            );
        }
        refusals.push(failure);
        close(&p);
    }
    if both {
        if !before_mint.is_empty() {
            assert_eq!(
                before_mint[0], before_mint[1],
                "actual linked and dropped pre-mint failure text"
            );
        }
        assert_eq!(
            refusals[0], refusals[1],
            "actual linked and dropped mint failure text"
        );
    }
}

fn real_ops() -> Option<auth::Ops> {
    // SAFETY: the actual static OAuth auth table.
    Some(unsafe { *busbar_auth_oauth::door().ops().cast::<auth::Ops>() })
}
/// `fields`, then ONE byte of the first value written flipped.
unsafe extern "C" fn fields_one_byte_off(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.fields) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = unsafe { real(instance, input, out) };
    if answered.outcome() == Outcome::Ready {
        // SAFETY: the host hands `fields` a `FieldsIn` and a `FieldsOut`; the plugin answered
        // READY, so its first span (when it wrote one) lies inside the host's field buffer.
        unsafe {
            let i = &*input.cast::<FieldsIn>();
            let o = &*out.cast::<FieldsOut>();
            if o.fields_len > 0 && !i.fields.is_null() && !i.field_buf.is_null() {
                let v = (*i.fields).value;
                if v.len > 0 && (v.offset as usize + v.len as usize) <= i.field_buf_cap {
                    *i.field_buf.add(v.offset as usize + v.len as usize - 1) ^= 1;
                }
            }
        }
    }
    answered
}

/// `fields`, then the fields it wrote taken back: READY with none written.
unsafe extern "C" fn fields_writing_nothing(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.fields) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = unsafe { real(instance, input, out) };
    if answered.outcome() == Outcome::Ready {
        // SAFETY: the host hands `fields` a `FieldsOut` it owns for the call.
        unsafe {
            (*out.cast::<FieldsOut>()).fields_len = 0;
        }
    }
    answered
}

/// `open_outbound`, then a SECOND binding over the same style and credential under settings one
/// byte longer: a second token cell, so the plugin's mint fetches the token twice.
unsafe extern "C" fn open_outbound_twice(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.open_outbound) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = unsafe { real(instance, input, out) };
    // SAFETY: the host hands `open_outbound` an `OpenOutboundIn`; its settings blob is the
    // host's for the call. The second call's `in` and `out` are this frame's own.
    unsafe {
        let mut again = *input.cast::<OpenOutboundIn>();
        let mut longer = if again.settings.ptr.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(again.settings.ptr, again.settings.len).to_vec()
        };
        longer.push(b' ');
        again.settings = json(&longer);
        let mut scratch: OpenOutboundOut = output();
        let _ = real(
            instance,
            std::ptr::addr_of!(again).cast(),
            std::ptr::addr_of_mut!(scratch).cast(),
        );
    }
    answered
}

/// `fields`, and when it WAITS (an on-demand cell armed) the same call again under the scope one
/// byte longer: a second cell armed for the same waiting request, so the waiting calls fetch twice.
unsafe extern "C" fn fields_arming_twice(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let Some(real) = real_ops().and_then(|o| o.fields) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let answered = unsafe { real(instance, input, out) };
    if answered.outcome() == Outcome::Pending {
        // SAFETY: the host hands `fields` a `FieldsIn`; its extensions blob is the host's for the
        // call. The second call's `in` and `out` are this frame's own.
        unsafe {
            let mut again = *input.cast::<FieldsIn>();
            let ext = again.head.extensions;
            let blob = if ext.ptr.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(ext.ptr, ext.len)
            };
            let mut scope = extensions::get(blob, auth::EXT_SCOPE)
                .unwrap_or_default()
                .to_vec();
            scope.push(b' ');
            let other = extensions::encode(&[(auth::EXT_SCOPE, &scope)]);
            again.head.extensions = Blob {
                ptr: other.as_ptr(),
                len: other.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            let mut scratch: FieldsOut = output();
            let _ = real(
                instance,
                std::ptr::addr_of!(again).cast(),
                std::ptr::addr_of_mut!(scratch).cast(),
            );
        }
    }
    answered
}

fn altered(
    fields: Option<busbar_contract::abi::mechanism::call::Op>,
    twice: bool,
) -> &'static Door {
    // SAFETY: immutable copied actual product operations; changed callbacks forward the real
    // product and perturb only the assertion's field or extra binding.
    let mut ops = real_ops().unwrap();
    ops.fields = fields;
    if twice {
        ops.open_outbound = Some(open_outbound_twice);
    }
    let ops = Box::leak(Box::new(ops));
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ops: std::ptr::from_ref(ops).cast(),
            ..busbar_auth_oauth::door().parts()
        })
    }))
}
extern "C" fn byte_door() -> &'static Door {
    altered(Some(fields_one_byte_off), false)
}
extern "C" fn nothing_door() -> &'static Door {
    altered(Some(fields_writing_nothing), false)
}
extern "C" fn twice_door() -> &'static Door {
    altered(Some(fields_arming_twice), true)
}
fn rejected(door: busbar_contract::abi::mechanism::door::DoorFn, count: bool) {
    let error = std::panic::catch_unwind(|| grant_case_door(0, door, false))
        .expect_err("altered real product must fail its assertions");
    let text = error
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        text.contains(if count {
            "exactly ONE token exchange"
        } else {
            "expected actual minted fields"
        }),
        "unexpected assertion: {text}"
    );
}
#[test]
fn wrong_actual_field_byte_is_rejected() {
    rejected(byte_door, false);
}
#[test]
fn missing_actual_fields_are_rejected() {
    rejected(nothing_door, false);
}
#[test]
fn extra_actual_token_exchange_is_rejected() {
    rejected(twice_door, true);
}

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, IoIn, StreamIn};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::ticket::CompletionHandle;
use busbar_plugin_loader::dispatch::conn_services::CONN_SLOTS;
use std::os::raw::c_void;
/// A head for connector service `op`, `size` bytes, on no ticket.
fn head(op: u32, size: usize) -> ServiceHead {
    ServiceHead {
        size: u32::try_from(size).unwrap_or(u32::MAX),
        op,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

/// An empty service `out`.
fn out() -> ServiceOut {
    // SAFETY: a plain repr(C) value of integers and a NULL/0 string: all-zero is valid.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    out
}

/// A host slot's answer: its outcome, scalar and text.
fn answered(raw: RawOutcome, o: &ServiceOut) -> (Outcome, u64, String) {
    let text = if o.error.ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the host's text, `'static` (interned) or held for the call.
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
            .into_owned()
    };
    (raw.outcome(), o.value, text)
}

/// `ESTABLISH` of `need` at `target`, on `p`'s own context, as the plugin calls it.
fn establish(p: &Plugin<Auth>, need: u32, target: &str) -> (Outcome, u64, String) {
    let none = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let i = EstablishIn {
        head: head(service::ESTABLISH, std::mem::size_of::<EstablishIn>()),
        need,
        timeout_ms: 5_000,
        target: AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        },
        within: none,
        member: none,
    };
    let mut o = out();
    let f = CONN_SLOTS.establish.expect("the host offers ESTABLISH");
    let raw = f(
        p.inner.ctx(),
        std::ptr::from_ref(&i).cast::<c_void>(),
        &mut o,
    );
    answered(raw, &o)
}

/// `WRITE` (`write`) or `READ` of `stream`, on `p`'s own context.
fn io(p: &Plugin<Auth>, stream: u64, write: bool) -> (Outcome, u64, String) {
    let mut buf = *b"x";
    let (op, f) = if write {
        (service::WRITE, CONN_SLOTS.write)
    } else {
        (service::READ, CONN_SLOTS.read)
    };
    let i = IoIn {
        head: head(op, std::mem::size_of::<IoIn>()),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    };
    let mut o = out();
    let raw = f.expect("the host offers READ and WRITE")(
        p.inner.ctx(),
        std::ptr::from_ref(&i).cast::<c_void>(),
        &mut o,
    );
    answered(raw, &o)
}

/// `CLOSE` of `stream`, on `p`'s own context.
fn close_stream(p: &Plugin<Auth>, stream: u64) -> (Outcome, u64, String) {
    let i = StreamIn {
        head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
        stream,
    };
    let mut o = out();
    let raw = CONN_SLOTS.close.expect("the host offers CLOSE")(
        p.inner.ctx(),
        std::ptr::from_ref(&i).cast::<c_void>(),
        &mut o,
    );
    answered(raw, &o)
}

#[test]
fn actual_oauth_host_connections_refuse_undeclared_need_and_other_owner() {
    let mut endpoint = Endpoint::new(vec![(200, b"{}".to_vec())]);
    endpoint.framed = false; // Exercise raw host connection custody on the actual auth context.
    let endpoint = Arc::new(endpoint);
    let d = Dispatcher::new(DispatchConfig::default());
    let owner = product(false, &d, endpoint.clone(), busbar_auth_oauth::door);
    let other = product(false, &d, endpoint, busbar_auth_oauth::door);
    let (outcome, conn, text) = establish(&owner, 0, "https://login.example/token");
    assert_eq!(outcome, Outcome::Ready, "{text}");
    assert_eq!(io(&owner, conn, true).0, Outcome::Ready);
    for need in [2, u32::MAX] {
        let (outcome, _, text) = establish(&owner, need, "https://login.example/token");
        assert_eq!(
            (outcome, text.as_str()),
            (Outcome::Refused, ConnError::UndeclaredNeed.text())
        );
    }
    for (outcome, _, text) in [
        io(&other, conn, true),
        io(&other, conn, false),
        close_stream(&other, conn),
    ] {
        assert_eq!(
            (outcome, text.as_str()),
            (Outcome::Refused, ConnError::NotOwner.text())
        );
    }
    assert_eq!(io(&owner, conn, true).0, Outcome::Ready);
    assert_eq!(close_stream(&owner, conn).0, Outcome::Ready);
}
