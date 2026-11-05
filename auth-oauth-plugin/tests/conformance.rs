// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises OAuth auth operations through the linked and dropped-in doors.

use std::ffi::c_void;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{
    self, slot, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, RequestFacts, VerifyIn, FIELD_SENSITIVE, MODE_OWN,
    MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Op, Outcome, RawOutcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &'static str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &'static str, fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

fn json(b: &'static str) -> Blob {
    blob(b, BLOB_JSON, 0)
}

fn secret(b: &'static str) -> Blob {
    blob(b, BLOB_OCTETS, BLOB_SECRET)
}

#[derive(Default)]
struct Folds(Mutex<Vec<String>>);

impl EnvelopeSink for Folds {
    fn metric(&self, m: Metric<'_>) {
        self.0.lock().unwrap().push(format!("metric {}", m.family));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!(
            "diag {} sev={} {}",
            d.id,
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn bind(folds: &Arc<Folds>, dispatcher: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("conformance"),
        max_inflight_cap: 64,
        sink: folds.clone(),
        dispatcher: dispatcher.adopter(),

        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    }
}

/// The compiled-in row `door` states: its Statement rendering and the door.
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("the door states its Statement")
}

fn linked(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(busbar_auth_oauth::door), bind(folds, d))
        .expect("the linked door loads")
}

fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    let path = built_plugin_image();
    let stated = rendering_of(busbar_auth_oauth::door).expect("the door renders its Statement");
    load_dropped::<Auth>(&path, &stated, bind(folds, d)).expect("the dropped door loads")
}

fn err(e: &Option<Vec<u8>>) -> String {
    e.as_deref()
        .map(|e| String::from_utf8_lossy(e).replace('\n', " | "))
        .unwrap_or_default()
}

struct Buffers {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
}

impl Buffers {
    fn new(bytes: usize, fields: usize) -> Self {
        Self {
            buf: vec![0; bytes],
            spans: vec![z(); fields],
        }
    }

    fn read(&self, n: u32) -> String {
        (0..n as usize)
            .map(|i| {
                let f = self.spans[i];
                let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                    String::from_utf8_lossy(
                        &self.buf[sp.offset as usize..sp.offset as usize + sp.len as usize],
                    )
                    .into_owned()
                };
                format!("{}: {} [flags={}]", at(f.name), at(f.value), f.flags)
            })
            .collect::<Vec<_>>()
            .join(" ; ")
    }
}

fn facts() -> RequestFacts {
    RequestFacts {
        method: s("POST"),
        authority: s("runtime.signer.example"),
        canonical_path: s("/model/m/converse"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 1_440_938_160,
    }
}

fn fields(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, cap: (usize, usize)) -> String {
    let mut b = Buffers::new(cap.0, cap.1);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = mode;
    f.input.request = facts();
    f.input.caller_credential = caller;
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = p.call(slot::FIELDS, &mut f);
    let mut line = format!("fields {:?} {}", c.outcome, err(&c.error));
    let mut outcome = c.outcome;
    if let Some(token) = c.recall {
        line.push_str(&format!(
            " short(needed_fields={} needed_bytes={})",
            f.out.needed_fields, f.out.needed_bytes
        ));
        b = Buffers::new(f.out.needed_bytes as usize, f.out.needed_fields as usize);
        (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
        (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
        f.out = z();
        f.out.head = out_head();
        let c = p.recall(token, slot::FIELDS, &mut f);
        line.push_str(&format!(" -> recall {:?}", c.outcome));
        outcome = c.outcome;
    }
    if outcome == Outcome::Ready {
        line.push_str(&format!(" {}", b.read(f.out.fields_len)));
    }
    line
}

fn open_outbound(
    p: &Plugin<Auth>,
    style: &'static str,
    credential: Option<&'static str>,
    settings: &'static str,
) -> (String, u64) {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.style = s(style);
    f.input.credential = credential.map_or(z(), secret);
    f.input.settings = json(settings);
    let c = p.call(slot::OPEN_OUTBOUND, &mut f);
    (
        format!("open_outbound {style} {:?} {}", c.outcome, err(&c.error)),
        f.out.handle,
    )
}

fn ready(p: &Plugin<Auth>, handle: u64) -> String {
    let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    let c = p.call(slot::OUTBOUND_READY, &mut f);
    format!("ready {:?} {}", c.outcome, f.out.ready)
}

const OAUTH: &str = r#"{"token_url":"https://idp.example/token","scope":"s"}"#;

fn script(p: &Plugin<Auth>) -> Vec<String> {
    let mut t = Vec::new();

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json("[1]"),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let c = p.call(life::VALIDATE, &mut v);
    t.push(format!("validate [1] {:?} {}", c.outcome, err(&c.error)));
    v.input.settings = json("{}");
    t.push(format!(
        "validate {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));

    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    t.push(format!("open {:?}", p.call(life::OPEN, &mut o).outcome));

    let (l, oauth) = open_outbound(p, "oauth-client-credentials", Some("id:secret"), OAUTH);
    t.push(l);
    t.push(
        open_outbound(
            p,
            "oauth-client-credentials",
            Some("unused"),
            r#"{"scope":"s"}"#,
        )
        .0,
    );
    t.push(open_outbound(p, "jwt-bearer", None, "{}").0);
    t.push(open_outbound(p, "bearer", Some("k"), "{}").0);
    t.push(open_outbound(p, "kerberos", Some("k"), "{}").0);

    t.push(fields(p, oauth, MODE_OWN, z(), (256, 4)));
    t.push(fields(
        p,
        oauth,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));
    t.push(fields(p, 999, MODE_OWN, z(), (256, 4)));

    t.push(ready(p, oauth));

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1_000,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut vf: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    vf.input.head = in_head();
    vf.out.head = out_head();
    t.push(format!(
        "verify {:?}",
        p.call(slot::VERIFY, &mut vf).outcome
    ));

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    x.input.head = in_head();
    x.out.head = out_head();
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} continues={}",
        c.outcome,
        x.out.disposition == busbar_contract::abi::auth::CANCEL_CONTINUES
    ));

    let mut r: Frame<RefreshIn, _> = Frame::new(z(), out_head());
    r.input.head = in_head();
    r.input.generation = 2;
    t.push(format!(
        "refresh {:?}",
        p.call(life::REFRESH, &mut r).outcome
    ));
    let (l, oauth2) = open_outbound(p, "oauth-client-credentials", Some("id:secret"), OAUTH);
    t.push(l);
    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!(
        "retire 1 {:?}",
        p.call(life::RETIRE, &mut g).outcome
    ));
    t.push(format!(
        "after retire {}",
        fields(p, oauth, MODE_OWN, z(), (256, 4))
    ));
    t.push(format!(
        "gen 2 {}",
        fields(p, oauth2, MODE_OWN, z(), (256, 4))
    ));

    let mut e = Frame::new(in_head(), out_head());
    t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
    t
}

const EXPECTED: &[&str] = &[
    "validate [1] Failed settings: must be a JSON object",
    "validate Ready",
    "open Ready",
    "open_outbound oauth-client-credentials Ready ",
    "open_outbound oauth-client-credentials Failed settings: uses auth: oauth-client-credentials \
     but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to) | \
     credential: oauth-client-credentials key must be `client_id:client_secret`",
    "open_outbound jwt-bearer Failed settings: uses auth: jwt-bearer but declares `api_key: none`; \
     that grant signs its assertion WITH the credential (the service-account JSON or key file), so \
     there is nothing to declare keyless",
    "open_outbound bearer Failed settings: outbound auth style `bearer` is not served by this \
     plugin",
    "open_outbound kerberos Failed settings: outbound auth style `kerberos` is not served by this \
     plugin",

    "fields Failed no OAuth token could be minted for this binding (see diagnostics \
     BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and the mint \
     retries on its schedule",
    "fields Refused the auth plugin refused the request's fields and gave no reason",
    "fields Refused the auth plugin refused the request's fields and gave no reason",
    "ready Ready 0",
    "tick Ready next=30000001000",
    "verify Refused",
    "cancel Ready continues=true",
    "refresh Ready",
    "open_outbound oauth-client-credentials Ready ",
    "retire 1 Ready",
    "after retire fields Refused the auth plugin refused the request's fields and gave no reason",
    "gen 2 fields Failed no OAuth token could be minted for this binding (see diagnostics \
     BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and the mint \
     retries on its schedule",
    "close Ready",
];

/// The folds: the declared diagnostic, and each `tracing` event the SDK captured into the
/// plugin's log (S5: every refusal logged once, `module = "oauth"`).
const EXPECTED_FOLDS: &[&str] = &[
    "diag 4294967295 sev=0 busbar_auth_oauth: instance settings refused module=\"oauth\" \
     reason=\"settings: must be a JSON object\"",
    "diag 4294967295 sev=0 busbar_auth_oauth: outbound binding refused module=\"oauth\" \
     style=\"oauth-client-credentials\" reason=\"settings: uses auth: oauth-client-credentials \
     but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to) | \
     credential: oauth-client-credentials key must be `client_id:client_secret`\"",
    "diag 4294967295 sev=0 busbar_auth_oauth: outbound binding refused module=\"oauth\" \
     style=\"jwt-bearer\" reason=\"settings: uses auth: jwt-bearer but declares `api_key: \
     none`; that grant signs its assertion WITH the credential (the service-account JSON or key \
     file), so there is nothing to declare keyless\"",
    "diag 4294967295 sev=0 busbar_auth_oauth: outbound binding refused module=\"oauth\" \
     style=\"bearer\" reason=\"settings: outbound auth style `bearer` is not served by this \
     plugin\"",
    "diag 4294967295 sev=0 busbar_auth_oauth: outbound binding refused module=\"oauth\" \
     style=\"kerberos\" reason=\"settings: outbound auth style `kerberos` is not served by this \
     plugin\"",
    "diag 4294967295 sev=0 busbar_auth_oauth: fields failed: no token to present \
     module=\"oauth\" reason=\"no OAuth token could be minted for this binding (see diagnostics \
     BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and the mint \
     retries on its schedule\"",
    FIELDS_REFUSED,
    FIELDS_REFUSED,
    "diag 2 sev=1 OAuth token mint failed; will retry error=token endpoint request failed: no \
     connection was granted for the token endpoint",
    "diag 4294967295 sev=0 busbar_auth_oauth::instance: the OAuth mint was refused and will retry \
     module=\"oauth\" reason=\"token endpoint request failed: no connection was granted for the \
     token endpoint\"",
    FIELDS_REFUSED,
    "diag 4294967295 sev=0 busbar_auth_oauth: fields failed: no token to present \
     module=\"oauth\" reason=\"no OAuth token could be minted for this binding (see diagnostics \
     BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and the mint \
     retries on its schedule\"",
];

const FIELDS_REFUSED: &str = "diag 4294967295 sev=0 busbar_auth_oauth: fields refused \
     module=\"oauth\" reason=\"not the operator's own credential, or a handle this generation \
     does not hold\"";

fn run(p: &Plugin<Auth>, folds: &Folds) -> (Vec<String>, Vec<String>) {
    let t = script(p);
    (t, std::mem::take(&mut *folds.0.lock().unwrap()))
}

#[test]
fn compiled_in_and_dropped_in_answer_every_op_identically() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let (linked_t, linked_f) = run(&linked(&folds, &d), &folds);
    assert_eq!(linked_t, EXPECTED, "the linked door");
    assert_eq!(linked_f, EXPECTED_FOLDS, "the linked door's folds");
    let folds = Arc::new(Folds::default());
    {
        let p = dropped(&folds, &d);
        let (dropped_t, dropped_f) = run(&p, &folds);
        assert_eq!(dropped_t, linked_t, "the dropped door");
        assert_eq!(dropped_f, linked_f, "the dropped door's folds");
        println!(
            "PROOF auth-oauth: linked and dropped answered {} ops and {} folds identically",
            linked_t.len(),
            linked_f.len()
        );
    }
}

fn door_with_fields(op: Op) -> &'static Door {
    // SAFETY: the plugin's `'static` door and its auth table.
    let (d, ops) = unsafe {
        let d = busbar_auth_oauth::door();
        (d, *d.ops().cast::<auth::Ops>())
    };
    let mut ops = ops;
    ops.fields = Some(op);
    let ops: &'static auth::Ops = Box::leak(Box::new(ops));
    // SAFETY: the plugin's own door parts, with `ops` at a `'static` auth table whose every slot is
    // the plugin's or one of this file's call-convention ops.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ops: std::ptr::from_ref(ops).cast(),
            ..d.parts()
        })
    }))
}

fn real_fields() -> Op {
    // SAFETY: the plugin's `'static` door and its auth table.
    unsafe {
        (*busbar_auth_oauth::door().ops().cast::<auth::Ops>())
            .fields
            .unwrap()
    }
}

// SAFETY CONTRACT: installed only in the typed auth fields slot; the dispatcher lends the real
// instance and live FieldsIn/FieldsOut buffers for this crossing.
unsafe extern "C" fn insensitive_fields(
    inst: *mut c_void,
    i: *const c_void,
    o: *mut c_void,
) -> RawOutcome {
    // SAFETY: this wrapper forwards the same live instance and typed fields-slot buffers.
    let r = unsafe { real_fields()(inst, i, o) };
    // SAFETY: the host's live `FieldsIn`/`FieldsOut` for this call.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &*o.cast::<FieldsOut>());
        if r.outcome() == Outcome::Ready {
            for k in 0..o.fields_len as usize {
                (*i.fields.add(k)).flags &= !FIELD_SENSITIVE;
            }
        }
    }
    r
}

extern "C" fn insensitive_door() -> &'static Door {
    door_with_fields(insensitive_fields)
}

/// THE DIAGNOSTIC TABLE: each `diag` index names its 1.5.5 catalog code (the indices are
/// `instance::diag`, pinned to 0, 1, 2 by the crate's own unit test).
#[test]
fn the_diag_indices_name_their_catalog_codes() {
    let ids: Vec<&str> = (0..busbar_auth_oauth::STATEMENT.diag_ids_len)
        .map(|i| {
            // SAFETY: the Statement's `diag_ids` is a program-lifetime static of `diag_ids_len` `AbiStr`s
            // whose bytes are program-lifetime string literals.
            unsafe {
                (*busbar_auth_oauth::STATEMENT.diag_ids.add(i))
                    .as_str()
                    .unwrap()
            }
        })
        .collect();
    assert_eq!(
        ids,
        ["BUSBAR-4014", "BUSBAR-4015", "BUSBAR-4016"],
        "OAUTH_TOKEN_INVALID_BYTES, OAUTH_EMPTY_TOKEN, OAUTH_MINT_FAILED"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn red_a_field_without_the_sensitive_flag() {
    mint_door::check_binding(insensitive_door, false).await;
}

// SAFETY CONTRACT: the dispatcher calls this only as the typed fields slot with live input/output.
unsafe extern "C" fn overrunning_fields(
    _: *mut c_void,
    i: *const c_void,
    o: *mut c_void,
) -> RawOutcome {
    // SAFETY: the host's live `FieldsOut` for this call; nothing is written past its `out`.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &mut *o.cast::<FieldsOut>());
        o.fields_len = i.fields_cap + 1;
        o.head.outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn overrunning_door() -> &'static Door {
    door_with_fields(overrunning_fields)
}

#[test]
fn red_a_writer_that_ignores_the_host_capacity_faults() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let red =
        load_linked::<Auth>(&row(overrunning_door), bind(&folds, &d)).expect("the door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    let (_, h) = open_outbound(&red, "oauth-client-credentials", Some("id:secret"), OAUTH);
    assert!(fields(&red, h, MODE_OWN, z(), (256, 4)).starts_with("fields Fault"));
}

mod mint_door {
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_PROVIDER};
    use busbar_contract::abi::mechanism::rendering::ReadNeed;
    use busbar_contract::auth_calls::{Fields, FieldsRequest, OutboundAuth};
    use busbar_contract::conn::{
        ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
        PieceKind,
    };
    use busbar_contract::ids::StreamId;
    use busbar_contract::transport::ConnFacts;
    use busbar_plugin_loader::dispatch::auth_outbound::OutboundInstance;
    use busbar_plugin_loader::dispatch::kinds::auth::Auth;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };

    const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
    const SCOPE: &str = "https://cognitiveservices.azure.com/.default";
    const CREDENTIAL: &str = "oracle-client-0001:oracle:secret:with:colons";
    static SEALED_REQUIRED: AtomicBool = AtomicBool::new(false);

    // SAFETY CONTRACT: installed only in the real auth fields slot and forwarded unchanged.
    unsafe extern "C" fn observed_fields(
        inst: *mut std::ffi::c_void,
        input: *const std::ffi::c_void,
        output: *mut std::ffi::c_void,
    ) -> busbar_contract::abi::mechanism::call::RawOutcome {
        // SAFETY: the typed fields-slot dispatcher owns these live buffers and instance.
        let result = unsafe { super::real_fields()(inst, input, output) };
        // SAFETY: this is the real OAuth door's live FieldsOut. The observation copies only its
        // small static protocol extension during the call, never a credential or a borrowed ptr.
        let out = unsafe { &*output.cast::<busbar_contract::abi::auth::FieldsOut>() };
        if result.outcome() == busbar_contract::abi::mechanism::call::Outcome::Ready
            && out.fields_len > 0
        {
            let ext = out.head.extensions;
            let secure = !ext.ptr.is_null() && ext.len <= 128 && {
                // SAFETY: the real door's extension bytes are live for this call.
                let bytes = unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) };
                busbar_contract::abi::mechanism::extensions::get(bytes, "auth.sealed_fields")
                    == Some(&[1][..])
            };
            SEALED_REQUIRED.store(secure, Ordering::SeqCst);
        }
        result
    }

    extern "C" fn observed_door() -> &'static busbar_contract::abi::mechanism::door::Door {
        super::door_with_fields(observed_fields)
    }

    struct Clock(Instant);

    use busbar_contract::services::{
        Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, RecordsList, Snapshot,
        Stored, TrustKeyRef, UNSERVED,
    };

    impl HostServices for Clock {
        fn now(&self) -> busbar_contract::services::Reading {
            let elapsed = u64::try_from(self.0.elapsed().as_nanos()).expect("test clock fits");
            busbar_contract::services::Reading {
                wall_ns: 1_798_761_600_000_000_000 + elapsed,
                mono_ns: elapsed,
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
        fn unit_nest(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _ask: NestAsk,
            _later: Later,
        ) -> Ran {
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
        fn verify_store(
            &self,
            _caller: &Caller,
            _key: &[u8],
            _entry: &[u8],
            _ttl_ms: u64,
        ) -> Stored {
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
        fn hook_call(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _ask: HookAsk,
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn snapshot_read(&self, _caller: &Caller, _scope: u32) -> Snapshot {
            Snapshot::Refused(UNSERVED)
        }
    }

    /// What one open carried: the need, the target, the method, the head target, the fields, the body.
    type Opened = (u32, String, String, String, Vec<(String, String)>, String);

    /// Each open's reply, piece by piece, with its bytes.
    type Replies = HashMap<ConnId, VecDeque<(Piece, Vec<u8>)>>;

    /// A connection table whose needs are framed: each open is recorded and answered by the token
    /// endpoint's next reply (`expires_in` 2, then 3600), one piece per read.
    #[derive(Default)]
    struct TokenEndpoint {
        slab: ConnSlab<()>,
        carrier_facts: Option<ConnFacts>,
        prepared: Mutex<HashMap<ConnId, (NeedId, u64)>>,
        declared: Mutex<Vec<(u32, ReadNeed, Option<String>)>>,
        opened: Mutex<Vec<Opened>>,
        replies: Mutex<Replies>,

        refresh_allowed: AtomicBool,
    }

    fn piece(kind: PieceKind, len: usize, status: Option<u32>) -> Piece {
        Piece {
            kind,
            stream: StreamId(0),
            len,
            end: kind != PieceKind::Fields,
            status: None,
            status_code: status,
            status_namespace: status.map(|_| "http".to_owned()),
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        }
    }

    impl DeclaredConns for TokenEndpoint {
        fn prepare_request(
            &self,
            caller: InstanceId,
            need: NeedId,
            desc: &OpenDesc<'_>,
            dial_timeout_ms: u64,
        ) -> Result<ConnId, ConnError> {
            self.slab.check_need(caller, need)?;
            assert!(desc.method.is_empty() && desc.fields.is_empty() && desc.body.is_empty());
            let id = self.slab.insert(caller, need, ())?;
            self.prepared
                .lock()
                .unwrap()
                .insert(id, (need, dial_timeout_ms));
            Ok(id)
        }
        fn commit_request(
            &self,
            caller: InstanceId,
            id: ConnId,
            desc: &OpenDesc<'_>,
            require_secure: bool,
        ) -> Result<(), ConnError> {
            self.slab.get(caller, id)?;
            if require_secure
                && !self
                    .carrier_facts
                    .as_ref()
                    .is_some_and(|facts| facts.peer_cert.is_some())
            {
                return Err(ConnError::AuthRefused);
            }
            let (_need, _dial_timeout_ms) = self
                .prepared
                .lock()
                .unwrap()
                .remove(&id)
                .ok_or(ConnError::Refused)?;
            let need = _need;
            let mut opened = self.opened.lock().unwrap();
            opened.push((
                need.0,
                desc.target.to_owned(),
                String::from_utf8_lossy(desc.method).into_owned(),
                String::from_utf8_lossy(desc.head_target).into_owned(),
                desc.fields
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), String::from_utf8_lossy(v).into_owned()))
                    .collect(),
                String::from_utf8_lossy(&desc.body).into_owned(),
            ));
            let n = opened.len();
            let body = format!(
                r#"{{"access_token":"oracle-minted-{n}","expires_in":{},"token_type":"Bearer"}}"#,
                if n == 1 { 2 } else { 3600 }
            );

            self.replies.lock().unwrap().insert(
                id,
                VecDeque::from([
                    (piece(PieceKind::Fields, 0, Some(200)), Vec::new()),
                    (piece(PieceKind::Body, body.len(), None), body.into_bytes()),
                    (piece(PieceKind::Completion, 0, None), Vec::new()),
                ]),
            );
            Ok(())
        }
        fn declare(
            &self,
            owner: InstanceId,
            need: NeedId,
            spec: &ReadNeed,
            target: Option<&str>,
            _trust: Option<&str>,
        ) -> Result<(), ConnError> {
            self.declared
                .lock()
                .unwrap()
                .push((need.0, spec.clone(), target.map(str::to_owned)));

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
            self.slab.check_need(owner, need).is_ok()
        }
        fn serves_scheme(&self, scheme: &str) -> bool {
            scheme == "http"
        }
    }

    #[test]
    fn scripted_carrier_requires_preparation_ownership_and_secure_commit() {
        let owner = InstanceId(71);
        let other = InstanceId(72);
        let need = NeedId(0);
        for carrier_facts in [
            None,
            Some(ConnFacts::default()),
            Some(super::oauth_grants::modeled_secure_facts()),
        ] {
            let secure = carrier_facts
                .as_ref()
                .is_some_and(|facts| facts.peer_cert.is_some());
            let available = carrier_facts.is_some();
            let endpoint = TokenEndpoint {
                carrier_facts,
                ..TokenEndpoint::default()
            };
            endpoint.slab.declare(owner, need);
            // URL spelling is deliberately identical for unavailable, insecure and secure carriers.
            let dial = OpenDesc {
                target: "https://scripted.invalid/token",
                ..OpenDesc::default()
            };
            let id = endpoint.prepare_request(owner, need, &dial, 0).unwrap();
            assert!(endpoint.opened.lock().unwrap().is_empty());
            assert!(endpoint.replies.lock().unwrap().is_empty());
            assert_eq!(endpoint.facts(owner, id).is_ok(), available);
            assert!(matches!(
                endpoint.facts(other, id),
                Err(ConnError::NotOwner)
            ));
            assert_eq!(
                endpoint.write(owner, id, b"CANARY", false, false),
                Err(ConnError::Refused)
            );
            let request = OpenDesc {
                method: b"POST",
                body: b"CANARY".to_vec().into(),
                timeout_ms: 30_000,
                ..dial
            };
            assert_eq!(
                endpoint.commit_request(other, id, &request, true),
                Err(ConnError::NotOwner)
            );
            assert_eq!(endpoint.close(other, id), Err(ConnError::NotOwner));
            let committed = endpoint.commit_request(owner, id, &request, true);
            if secure {
                assert_eq!(committed, Ok(()));
                assert_eq!(endpoint.opened.lock().unwrap().len(), 1);
                assert!(endpoint.replies.lock().unwrap().contains_key(&id));
                assert_eq!(
                    endpoint.commit_request(owner, id, &request, true),
                    Err(ConnError::Refused)
                );
            } else {
                assert_eq!(committed, Err(ConnError::AuthRefused));
                assert!(endpoint.opened.lock().unwrap().is_empty());
                assert!(endpoint.replies.lock().unwrap().is_empty());
            }
            endpoint.close(owner, id).unwrap();
            assert!(endpoint.prepared.lock().unwrap().is_empty());
            assert!(endpoint.facts(owner, id).is_err());
            assert!(endpoint.commit_request(owner, id, &request, true).is_err());
        }
    }

    impl Conns for TokenEndpoint {
        fn open(
            &self,
            caller: InstanceId,
            need: NeedId,
            desc: &OpenDesc<'_>,
        ) -> Result<ConnId, ConnError> {
            self.slab.check_need(caller, need)?;
            let id = self.slab.insert(caller, need, ())?;
            self.prepared.lock().unwrap().insert(id, (need, 0));
            self.commit_request(caller, id, desc, false)?;
            Ok(id)
        }
        fn write(
            &self,
            owner: InstanceId,
            id: ConnId,
            b: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            self.slab.get(owner, id)?;
            if self.prepared.lock().unwrap().contains_key(&id) {
                return Err(ConnError::Refused);
            }
            Ok(b.len())
        }
        fn read(
            &self,
            c: InstanceId,
            id: ConnId,
            _: u64,
            buf: &mut [u8],
        ) -> Result<Piece, ConnError> {
            self.slab.get(c, id)?;
            if self.opened.lock().unwrap().len() > 1 && !self.refresh_allowed.load(Ordering::SeqCst)
            {
                return Err(ConnError::Pending);
            }
            let (p, bytes) = self
                .replies
                .lock()
                .unwrap()
                .get_mut(&id)
                .and_then(VecDeque::pop_front)
                .ok_or(ConnError::Closed)?;
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(p)
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
            Err(ConnError::Pending)
        }
        fn facts(&self, owner: InstanceId, id: ConnId) -> Result<ConnFacts, ConnError> {
            self.slab.get(owner, id)?;
            self.carrier_facts.clone().ok_or(ConnError::Refused)
        }
        fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
            self.slab.get(c, id)?;
            self.prepared.lock().unwrap().remove(&id);
            self.replies.lock().unwrap().remove(&id);
            self.slab.remove(c, id).map(|_| ())
        }
    }

    /// Whether one `fields` answer presents exactly `expected` as its authorization: its first
    /// `authorization` field's value, compared with `expected`. The value is the contract's sealed
    /// secret (busbar #1021, Part 2 #54), which a plugin's test holds no seal to read, so it is
    /// compared through the type's own constant-time equality rather than read out. The comparison
    /// never names the type, so it holds against the contract before and after the seal.
    fn presents(answer: &Fields, expected: &str) -> bool {
        fn same<T: PartialEq>(value: &T, expected: T) -> bool {
            *value == expected
        }
        match answer {
            Fields::Ready(fields) => fields
                .iter()
                .find(|f| f.name == b"authorization")
                .is_some_and(|f| same(&f.value, expected.as_bytes().to_vec().into())),
            _ => false,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_presents_its_minted_bearer_then_the_refreshed_one() {
        check_binding(observed_door, true).await;
    }

    pub(super) async fn check_binding(
        door: busbar_contract::abi::mechanism::door::DoorFn,
        sensitive: bool,
    ) {
        if sensitive {
            SEALED_REQUIRED.store(false, Ordering::SeqCst);
        }
        let table = Arc::new(TokenEndpoint {
            carrier_facts: Some(super::oauth_grants::modeled_secure_facts()),
            ..TokenEndpoint::default()
        });
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(Clock(Instant::now())),
        ));
        let row = LinkedRow::of(door).expect("the door states its Statement");
        let plugin = load_linked::<Auth>(
            &row,
            Bind {
                instance: Arc::from("busbar-auth-oauth"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: busbar_plugin_loader::dispatch::ConnTable::Host(
                    Arc::clone(&table) as Arc<dyn DeclaredConns>
                ),
            },
        )
        .expect("the linked door binds on the connection table");
        assert!(
            plugin.targets_from_settings(),
            "its needs take their target from the binding's settings"
        );

        let settings = serde_json::json!({ "token_url": TOKEN_URL, "scope": SCOPE });
        let instance = Arc::new(
            OutboundInstance::open_with(
                plugin,
                Arc::clone(&dispatcher),
                0,
                &serde_json::to_vec(&settings).expect("json"),
            )
            .expect("the instance opens"),
        );
        {
            let declared = table.declared.lock().unwrap();
            let token_url = declared
                .iter()
                .find(|(need, _, _)| *need == 0)
                .expect("the token_url need is declared");
            assert_eq!(token_url.1.direction, DIRECTION_OUTBOUND);
            assert_eq!(token_url.1.egress_class, EGRESS_PROVIDER);
            assert_eq!(token_url.1.transport, "http");
            assert_eq!(token_url.1.target_from, "settings.token_url");
            assert_eq!(token_url.2.as_deref(), Some(TOKEN_URL), "pinned to it");
        }
        let handle = instance
            .open_outbound("oauth-client-credentials", CREDENTIAL.as_bytes(), &settings)
            .expect("the binding opens");

        let request = FieldsRequest::default();
        assert!(
            instance.fields_now(handle, &request).is_none(),
            "nothing minted yet: no cached credential is presented"
        );
        assert!(!instance.ready(handle), "nothing minted yet: not ready");
        let before_mint = tokio::time::timeout(
            Duration::from_secs(10),
            instance.fields(handle, FieldsRequest::default(), 0),
        )
        .await
        .expect("the pre-mint fields failure answers without a token exchange");
        assert_eq!(
            before_mint,
            Fields::Failed,
            "nothing minted yet: failed closed"
        );
        assert!(
            table.opened.lock().unwrap().is_empty(),
            "the pre-mint failure must not open a token endpoint connection"
        );

        tokio::spawn(Arc::clone(&instance).ticks());
        let first = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let answer = instance.fields(handle, FieldsRequest::default(), 0).await;
                if presents(&answer, "Bearer oracle-minted-1") {
                    break answer;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the first mint lands");
        if sensitive {
            assert!(
                SEALED_REQUIRED.load(Ordering::SeqCst),
                "the actual minted bearer must carry its secure-field requirement to the host"
            );
        }
        let Fields::Ready(ref fields) = first else {
            panic!("the minted bearer is ready");
        };
        let bearer = fields
            .iter()
            .find(|field| field.name == b"authorization")
            .expect("the actual mint writes an authorization field");
        assert_eq!(
            bearer.sensitive, sensitive,
            "the real field's flag distinguishes the altered door"
        );
        assert!(
            presents(&first, "Bearer oracle-minted-1"),
            "the first upstream request carries the first token: {first:?}"
        );
        assert!(
            presents(
                &instance
                    .fields_now(handle, &request)
                    .expect("ready on the spot"),
                "Bearer oracle-minted-1"
            ),
            "the cached bearer answers in place, one call"
        );

        table.refresh_allowed.store(true, Ordering::SeqCst);

        let refreshed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(answer) = instance.fields_now(handle, &request) {
                    if presents(&answer, "Bearer oracle-minted-2") {
                        return answer;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the refresh lands");
        assert!(
            presents(&refreshed, "Bearer oracle-minted-2"),
            "the refreshed bearer is presented: {refreshed:?}"
        );

        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
        let form = "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
                oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com\
                %2F.default";
        for sent in opened.iter() {
            assert_eq!(
                sent,
                &(
                    0,
                    TOKEN_URL.to_string(),
                    "POST".to_string(),
                    "/tenant/oauth2/v2.0/token".to_string(),
                    vec![
                        (
                            "content-type".to_string(),
                            "application/x-www-form-urlencoded".to_string()
                        ),
                        ("accept".to_string(), "*/*".to_string())
                    ],
                    form.to_string(),
                )
            );
        }
    }
}

fn built_plugin_image() -> std::path::PathBuf {
    let image = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let test_binary = std::env::current_exe().expect("test binary path");
            test_binary
                .parent()
                .and_then(std::path::Path::parent)
                .expect("target profile directory")
                .join(format!(
                    "{}busbar_auth_oauth_plugin{}",
                    std::env::consts::DLL_PREFIX,
                    std::env::consts::DLL_SUFFIX
                ))
        });
    assert!(
        image.is_absolute(),
        "BUSBAR_PLUGIN_CDYLIB must name an absolute actual product image"
    );
    assert!(
        image.is_file(),
        "build the actual dropped-in plugin before running this test: {}",
        image.display()
    );
    image
}

#[path = "support/oauth_grants.rs"]
mod oauth_grants;

static RESTATED: std::sync::atomic::AtomicPtr<Door> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
extern "C" fn restated_door() -> &'static Door {
    // SAFETY: admission_negative_cases installs a leaked immutable Door before entering it.
    unsafe { &*RESTATED.load(std::sync::atomic::Ordering::SeqCst) }
}
extern "C" fn restated_raw() -> *const Door {
    std::ptr::from_ref(restated_door())
}
fn restate(parts: DoorParts) {
    // SAFETY: callers retain the real product's static operations and Statement, except the
    // deliberately malformed admission field. Replacement Statements are leaked for the test.
    let door = Box::leak(Box::new(unsafe { Door::__from_parts(parts) }));
    RESTATED.store(door, std::sync::atomic::Ordering::SeqCst);
}
#[test]
fn actual_product_admission_negative_cases() {
    use busbar_contract::abi::mechanism::{rendering::RENDERING_MAGIC, KindCode};
    use busbar_plugin_loader::dispatch::{
        kinds::{
            export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
            transport::Transport,
        },
        LoadError,
    };
    let d = Dispatcher::new(DispatchConfig::default());
    let f = Arc::new(Folds::default());
    let actual = busbar_auth_oauth::door().parts();
    let stated = rendering_of(busbar_auth_oauth::door).unwrap();
    let path = built_plugin_image();
    linked(&f, &d);
    dropped(&f, &d);
    // Change only the actual product's version and render a fully valid, different Statement.
    // Flipping an arbitrary byte can corrupt rendering syntax and tests a different refusal.
    // SAFETY: the real static Statement is copied; all nested static data stays unchanged.
    let statement = unsafe { actual.statement.read_unaligned() };
    let other = Box::leak(Box::new(busbar_contract::abi::mechanism::door::Statement {
        version: s("99.0.0-conformance"),
        ..statement
    }));
    restate(DoorParts {
        statement: other,
        ..actual
    });
    let lie = rendering_of(restated_door).expect("the altered-version actual door renders");
    busbar_contract::abi::mechanism::rendering::read(&lie)
        .expect("the different Statement is valid rendering");
    assert_ne!(lie, stated);
    assert_eq!(
        load_linked::<Auth>(
            &LinkedRow {
                statement: lie.clone(),
                ..row(busbar_auth_oauth::door)
            },
            bind(&f, &d)
        )
        .err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&path, &lie, bind(&f, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_linked::<Auth>(
            &LinkedRow {
                statement: stated.clone(),
                door: restated_raw
            },
            bind(&f, &d)
        )
        .err(),
        Some(LoadError::StatementMismatch)
    );
    let host = KindCode::Auth.abi_version();
    for abi in [host + 1, host.wrapping_sub(1)] {
        restate(DoorParts {
            kind_abi: abi,
            ..actual
        });
        let want = LoadError::KindAbi {
            kind: KindCode::Auth,
            door: abi,
            host,
        };
        assert_eq!(rendering_of(restated_door).err(), Some(want.clone()));
        assert_eq!(
            LinkedRow::of(restated_door)
                .and_then(|r| load_linked::<Auth>(&r, bind(&f, &d)))
                .err(),
            Some(want)
        );
        let mut manifest = stated.clone();
        let at = RENDERING_MAGIC.len() + 8;
        manifest[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Auth>(&path, &manifest, bind(&f, &d)).err(),
            Some(LoadError::ManifestKindAbi { stated: abi, host })
        );
    }
    let host = KindCode::Auth.layout_fingerprint();
    assert_eq!(actual.layout, host);
    for layout in [host ^ 1, 0] {
        restate(DoorParts { layout, ..actual });
        let refused = rendering_of(restated_door).expect_err("different layout cannot be packed");
        assert!(
            matches!(&refused,LoadError::KindLayout{kind:KindCode::Auth,stated,host:read,..} if *stated==layout&&*read==host)
        );
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
        assert_eq!(
            load_linked::<Auth>(
                &LinkedRow {
                    statement: stated.clone(),
                    door: restated_raw
                },
                bind(&f, &d)
            )
            .err(),
            Some(refused.clone())
        );
        assert_eq!(
            LinkedRow::of(restated_door)
                .and_then(|r| load_linked::<Auth>(&r, bind(&f, &d)))
                .err(),
            Some(refused)
        );
    }
    macro_rules! wrong_kind {
        ($kind:ty,$code:expr) => {{
            let want = $code;
            let manifest_error = LoadError::ManifestKind {
                stated: KindCode::Auth,
                want,
            };
            assert_eq!(
                load_linked::<$kind>(&row(busbar_auth_oauth::door), bind(&f, &d)).err(),
                Some(manifest_error.clone())
            );
            assert_eq!(
                load_dropped::<$kind>(&path, &stated, bind(&f, &d)).err(),
                Some(manifest_error)
            );
            // A row claiming the requested kind reaches validation of the actual auth door.
            // Preserve the distinct door-kind refusal after the manifest precheck.
            let mut claiming = stated.clone();
            let kind_at = RENDERING_MAGIC.len() + 4;
            claiming[kind_at..kind_at + 4].copy_from_slice(&(want as u32).to_le_bytes());
            claiming[kind_at + 4..kind_at + 8].copy_from_slice(&want.abi_version().to_le_bytes());
            let door_error = LoadError::WrongKind {
                door: KindCode::Auth,
                want,
            };
            assert_eq!(
                load_linked::<$kind>(
                    &LinkedRow {
                        statement: claiming.clone(),
                        ..row(busbar_auth_oauth::door)
                    },
                    bind(&f, &d)
                )
                .err(),
                Some(door_error.clone())
            );
            assert_eq!(
                load_dropped::<$kind>(&path, &claiming, bind(&f, &d)).err(),
                Some(door_error)
            );
        }};
    }
    wrong_kind!(Store, KindCode::Store);
    wrong_kind!(Secret, KindCode::Secret);
    wrong_kind!(Hook, KindCode::Hook);
    wrong_kind!(Export, KindCode::Export);
    wrong_kind!(Plane, KindCode::Plane);
    wrong_kind!(Transport, KindCode::Transport);
}

static READY_INVOCATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
// SAFETY CONTRACT: this callback only receives the dispatcher's live lifecycle buffers.
unsafe extern "C" fn failing_ready(
    _: *mut c_void,
    _: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    READY_INVOCATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let failure = RawOutcome::of(Outcome::Failed);
    // SAFETY: ready's output begins with the host's writable OutHead.
    unsafe {
        let head = &mut *out.cast::<busbar_contract::abi::mechanism::call::OutHead>();
        head.outcome = failure;
        head.error = s("OAuth conformance ready failure");
    }
    failure
}
extern "C" fn ready_failure_door() -> &'static Door {
    // SAFETY: the real product operations and Statement remain static; only ready is perturbed.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ready: Some(failing_ready),
            ..busbar_auth_oauth::door().parts()
        })
    }))
}
#[test]
fn actual_oauth_ready_failure_refuses_boot_once() {
    READY_INVOCATIONS.store(0, std::sync::atomic::Ordering::SeqCst);
    let d = Dispatcher::new(DispatchConfig::default());
    let f = Arc::new(Folds::default());
    let p = load_linked::<Auth>(&row(ready_failure_door), bind(&f, &d)).unwrap();
    assert!(p.has_ready());
    let mut open: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    open.input.head = in_head();
    open.out.head = out_head();
    assert_eq!(p.call(life::OPEN, &mut open).outcome, Outcome::Ready);
    let before = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
        - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        p.ready(&d, std::time::Duration::from_secs(10)),
        Err(format!(
            "plugin '{}' ready failed: OAuth conformance ready failure",
            p.name()
        ))
    );
    assert_eq!(
        p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
            - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst)
            - before,
        1
    );
    assert_eq!(
        READY_INVOCATIONS.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}
#[test]
fn actual_oauth_serving_requires_connection_table_both_doors() {
    use busbar_plugin_loader::dispatch::{ConnTable, LoadError};
    let d = Dispatcher::new(DispatchConfig::default());
    let f = Arc::new(Folds::default());
    let b = || Bind {
        conns: ConnTable::NoNeeds,
        ..bind(&f, &d)
    };
    let want = LoadError::NoConnectionTable {
        plugin: "busbar-auth-oauth".into(),
        needs: busbar_auth_oauth::NEEDS.len(),
    };
    assert_eq!(
        load_linked::<Auth>(&row(busbar_auth_oauth::door), b()).err(),
        Some(want.clone())
    );
    assert_eq!(
        load_dropped::<Auth>(
            &built_plugin_image(),
            &rendering_of(busbar_auth_oauth::door).unwrap(),
            b()
        )
        .err(),
        Some(want)
    );
    linked(&f, &d); // An explicit probe continues to bind without a serving table.
}

#[test]
fn oauth_statement_needs_match_manifest() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../auth-oauth/declares.json")).unwrap();
    let mut declared: Vec<_> = manifest["needs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    declared.sort();
    declared.dedup();
    let bytes = rendering_of(busbar_auth_oauth::door).unwrap();
    let parsed = busbar_contract::abi::mechanism::rendering::read(&bytes).unwrap();
    let mut actual: Vec<_> = parsed
        .needs
        .iter()
        .map(|need| need.transport.clone())
        .collect();
    actual.sort();
    actual.dedup();
    assert_eq!(actual, declared);
}
#[test]
fn requested_release_profile_is_used() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE is set: run with --release"
    );
}
#[test]
fn actual_oauth_refuses_undeclared_inbound_and_login_operations() {
    use busbar_contract::abi::auth::{BeginLoginIn, BeginLoginOut, CompleteLoginIn};
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let mut answers = Vec::new();
    let stated = rendering_of(busbar_auth_oauth::door).unwrap();
    let facts = busbar_contract::abi::mechanism::rendering::read(&stated).unwrap();
    let tail =
        busbar_contract::abi::mechanism::rendering::read_auth_tail(&facts.kind_tail).unwrap();
    assert_eq!(tail.caps & auth::CAP_INBOUND, 0);
    assert_eq!(tail.login_kind, auth::LOGIN_KIND_NONE);
    // The loader refuses undeclared families before entering an operation: exactly zero crossings.
    for p in [linked(&folds, &d), dropped(&folds, &d)] {
        let mut verify: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
        verify.input.head = in_head();
        verify.out.head = out_head();
        let before = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
            - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst);
        let call = p.call(slot::VERIFY, &mut verify);
        assert_eq!(call.outcome, Outcome::Refused);
        answers.push(format!(
            "{:?} lease={} {:?}",
            call.outcome, call.lease, call.error
        ));
        assert_eq!(
            p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
                - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst)
                - before,
            0
        );
        let mut begin: Frame<BeginLoginIn, BeginLoginOut> = Frame::new(z(), z());
        begin.input.head = in_head();
        begin.out.head = out_head();
        let before = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
            - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst);
        let call = p.call(slot::BEGIN_LOGIN, &mut begin);
        assert_eq!(call.outcome, Outcome::Refused);
        answers.push(format!(
            "{:?} lease={} {:?}",
            call.outcome, call.lease, call.error
        ));
        assert_eq!(
            p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
                - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst)
                - before,
            0
        );
        let mut complete: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(z(), z());
        complete.input.head = in_head();
        complete.out.head = out_head();
        let before = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
            - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst);
        let call = p.call(slot::COMPLETE_LOGIN, &mut complete);
        assert_eq!(call.outcome, Outcome::Refused);
        answers.push(format!(
            "{:?} lease={} {:?}",
            call.outcome, call.lease, call.error
        ));
        assert_eq!(
            p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
                - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst)
                - before,
            0
        );
    }
    assert_eq!(
        &answers[..3],
        &answers[3..],
        "undeclared operation full called parity"
    );
}

#[test]
fn every_actual_outbound_style_has_a_grant_case() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    let mut cases: Vec<_> = cases["auth"]["outbound"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["style"].as_str().unwrap().to_owned())
        .collect();
    // SAFETY: the real product's static Statement owns its static auth tail and style names.
    let mut declared: Vec<_> = unsafe {
        let tail = &*busbar_auth_oauth::STATEMENT
            .kind_tail
            .cast::<auth::AuthTail>();
        std::slice::from_raw_parts(tail.styles, tail.styles_len)
            .iter()
            .map(|style| style.name.as_str().unwrap().to_owned())
            .collect()
    };
    declared.sort();
    cases.sort();
    assert_eq!(declared, cases);
}

#[test]
fn actual_oauth_images_and_loaded_facts_are_distinct_and_equal() {
    use busbar_contract::abi::mechanism::{rendering, KindCode};
    use busbar_plugin_loader::dispatch::load::{door_addresses_of_library, rendering_of_library};
    let path = built_plugin_image();
    let (door, ops) = door_addresses_of_library(&path)
        .unwrap()
        .expect("actual cdylib exports door");
    assert_ne!(door, std::ptr::from_ref(busbar_auth_oauth::door()) as usize);
    assert_ne!(ops, busbar_auth_oauth::door().ops() as usize);
    let linked_bytes = rendering_of(busbar_auth_oauth::door).unwrap();
    let dropped_bytes = rendering_of_library(&path)
        .unwrap()
        .expect("actual cdylib Statement");
    assert_eq!(linked_bytes, dropped_bytes);
    let linked = rendering::read(&linked_bytes).unwrap();
    let dropped = rendering::read(&dropped_bytes).unwrap();
    let a = rendering::read_auth_tail(&linked.kind_tail).unwrap();
    let b = rendering::read_auth_tail(&dropped.kind_tail).unwrap();
    assert_eq!(a.caps, b.caps);
    assert_eq!(a.caps, auth::CAP_OUTBOUND);
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    for p in [self::linked(&folds, &d), self::dropped(&folds, &d)] {
        let before = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
            - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(p.kind(), KindCode::from_raw(linked.kind).unwrap());
        assert_eq!(p.kind(), KindCode::Auth);
        assert_eq!(p.name(), linked.name);
        assert_eq!(
            p.max_inflight(),
            linked.max_inflight.clamp(1, 64),
            "the actual loaded cap obeys this test bind's max_inflight_cap"
        );
        assert_eq!(
            p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
                - p.inner.resumes.load(std::sync::atomic::Ordering::SeqCst)
                - before,
            0,
            "actual facts are metadata without an operation crossing"
        );
    }
}
