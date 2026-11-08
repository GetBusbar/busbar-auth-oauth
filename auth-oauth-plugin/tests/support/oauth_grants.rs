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
/// Explicit scripted carrier evidence, independent of request URL spelling.
pub(super) fn modeled_secure_facts() -> ConnFacts {
    ConnFacts {
        peer_cert: Some(busbar_contract::transport::wire::CertFacts {
            subject: "scripted carrier".into(),
            issuer: "fixture".into(),
            fingerprint: "ab".repeat(32),
        }),
        ..ConnFacts::default()
    }
}

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
        let mut entries: Vec<(&str, &[u8])> = self
            .extensions
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes()))
            .collect();
        entries.push((
            busbar_contract::abi::sdk::auth_outbound::EXT_SEALED_FIELDS,
            busbar_contract::abi::sdk::auth_outbound::SEALED_FIELDS_V1,
        ));
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

/// Fixed inputs for the three actual OAuth grants below.
struct OAuthGrant {
    style: String,
    credential: Option<Vec<u8>>,
    settings: Vec<u8>,
    head: Head,
    expect: String,
    minting: Option<Minting>,
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

fn client_credentials_case() -> OAuthGrant {
    OAuthGrant {
        style: "oauth-client-credentials".into(),
        credential: Some("conformance-client:conformance:secret".as_bytes().to_vec()),
        settings: concat!("{\"token_url\":\"https://login.conformance.invalid/oauth2/token\",\"scope\":",
        "\"https://api.conformance.invalid/.default\"}").as_bytes().to_vec(),
        head: Head {
            method: "POST".into(),
            authority: "runtime.signer.example".into(),
            path: "/model/m/converse".into(),
            query: None,
            timestamp: 1440938160,
            fields: vec![("content-type".into(),
            "application/json".into())],
            body: "{}".as_bytes().to_vec(),
            extensions: vec![]
        },
        expect: "Ready fields=[authorization: Bearer conformance-token-1 (flags=1)]".into(),
        minting: Some(Minting {
            exchanges: vec![Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://login.conformance.invalid/oauth2/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: Some(concat!("grant_type=client_credentials&client_id=conformance-client&client_secr",
                    "et=conformance%3Asecret&scope=https%3A%2F%2Fapi.conformance.invalid%2F",
                    ".default").into()),
                    body_prefix: None
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-1\", \"expires_in\": 3600, \"token_typ",
                "e\": \"Bearer\"}").as_bytes().to_vec()
            },
            Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://login.conformance.invalid/oauth2/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: Some(concat!("grant_type=client_credentials&client_id=conformance-client&client_secr",
                    "et=conformance%3Asecret&scope=https%3A%2F%2Fapi.conformance.invalid%2F",
                    ".default").into()),
                    body_prefix: None
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-2\", \"expires_in\": 3600, \"token_typ",
                "e\": \"Bearer\"}").as_bytes().to_vec()
            }
            ],
            expires_in: 3600,
            refreshed: "Ready fields=[authorization: Bearer conformance-token-2 (flags=1)]".into(),
            refusal: "Failed".into(),
            on_demand: None
        }
        )
    }
}
fn jwt_bearer_case() -> OAuthGrant {
    OAuthGrant {
        style: "jwt-bearer".into(),
        credential: Some(serde_json::from_str::<serde_json::Value>(include_str!("../conformance.json")).unwrap()["auth"]["outbound"][1]["credential"].as_str().unwrap().as_bytes().to_vec()),
        settings: concat!("{\"token_uri\":\"https://oauth2.conformance.invalid/token\",\"scope\":\"https",
        "://www.googleapis.com/auth/cloud-platform\"}").as_bytes().to_vec(),
        head: Head {
            method: "POST".into(),
            authority: "runtime.signer.example".into(),
            path: "/model/m/converse".into(),
            query: None,
            timestamp: 1440938160,
            fields: vec![("content-type".into(),
            "application/json".into())],
            body: "{}".as_bytes().to_vec(),
            extensions: vec![]
        },
        expect: "Ready fields=[authorization: Bearer conformance-token-1 (flags=1)]".into(),
        minting: Some(Minting {
            exchanges: vec![Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://oauth2.conformance.invalid/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: None,
                    body_prefix: Some("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=eyJ".into())
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-1\", \"expires_in\": 3600, \"token_typ",
                "e\": \"Bearer\"}").as_bytes().to_vec()
            },
            Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://oauth2.conformance.invalid/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: None,
                    body_prefix: Some("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=eyJ".into())
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-2\", \"expires_in\": 3600, \"token_typ",
                "e\": \"Bearer\"}").as_bytes().to_vec()
            }
            ],
            expires_in: 3600,
            refreshed: "Ready fields=[authorization: Bearer conformance-token-2 (flags=1)]".into(),
            refusal: "Failed".into(),
            on_demand: None
        }
        )
    }
}
fn token_exchange_case() -> OAuthGrant {
    OAuthGrant {
        style: "oauth-token-exchange".into(),
        credential: Some("conformance-subject-token".as_bytes().to_vec()),
        settings: concat!("{\"token_url\":\"https://sts.conformance.invalid/token\",\"resource\":\"https",
        "://api.conformance.invalid/\"}").as_bytes().to_vec(),
        head: Head {
            method: "POST".into(),
            authority: "runtime.signer.example".into(),
            path: "/model/m/converse".into(),
            query: None,
            timestamp: 1440938160,
            fields: vec![("content-type".into(),
            "application/json".into())],
            body: "{}".as_bytes().to_vec(),
            extensions: vec![("scope".into(),
            "read:things".into())]
        },
        expect: "Ready fields=[authorization: Bearer conformance-token-1 (flags=1)]".into(),
        minting: Some(Minting {
            exchanges: vec![Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://sts.conformance.invalid/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: Some(concat!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&s",
                    "ubject_token=conformance-subject-token&subject_token_type=urn%3Aietf%3",
                    "Aparams%3Aoauth%3Atoken-type%3Aaccess_token&requested_token_type=urn%3",
                    "Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource=https%3A%2",
                    "F%2Fapi.conformance.invalid%2F&scope=read%3Athings").into()),
                    body_prefix: None
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-1\", \"expires_in\": 3600, \"token_typ",
                "e\": \"Bearer\", \"issued_token_type\": \"urn:ietf:params:oauth:token-type:a",
                "ccess_token\"}").as_bytes().to_vec()
            },
            Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://sts.conformance.invalid/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: Some(concat!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&s",
                    "ubject_token=conformance-subject-token&subject_token_type=urn%3Aietf%3",
                    "Aparams%3Aoauth%3Atoken-type%3Aaccess_token&requested_token_type=urn%3",
                    "Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource=https%3A%2",
                    "F%2Fapi.conformance.invalid%2F&scope=read%3Athings+write%3Athings").into()),
                    body_prefix: None
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-2\", \"expires_in\": 3600, \"token_typ",
                "e\": \"Bearer\", \"issued_token_type\": \"urn:ietf:params:oauth:token-type:a",
                "ccess_token\"}").as_bytes().to_vec()
            },
            Exchange {
                expect: ExpectRequest {
                    method: "POST".into(),
                    target: "https://sts.conformance.invalid/token".into(),
                    fields_subset: vec![("content-type".into(),
                    "application/x-www-form-urlencoded".into())],
                    body: Some(concat!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&s",
                    "ubject_token=conformance-subject-token&subject_token_type=urn%3Aietf%3",
                    "Aparams%3Aoauth%3Atoken-type%3Aaccess_token&requested_token_type=urn%3",
                    "Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource=https%3A%2",
                    "F%2Fapi.conformance.invalid%2F&scope=read%3Athings").into()),
                    body_prefix: None
                },
                status: 200,
                body: concat!("{\"access_token\": \"conformance-token-3\", \"expires_in\": 7200, \"token_typ",
                "e\": \"Bearer\", \"issued_token_type\": \"urn:ietf:params:oauth:token-type:a",
                "ccess_token\"}").as_bytes().to_vec()
            }
            ],
            expires_in: 3600,
            refreshed: "".into(),
            refusal: "Failed".into(),
            on_demand: Some(OnDemand {
                second_scope: "read:things write:things".into(),
                second: "Ready fields=[authorization: Bearer conformance-token-2 (flags=1)]".into(),
                expired: "Ready fields=[authorization: Bearer conformance-token-3 (flags=1)]".into()
            }
            )
        }
        )
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
    declared_owners: Mutex<Vec<InstanceId>>,
    deadlines: Mutex<Vec<(u64, u64)>>,
    framed: bool,
    slab: ConnSlab<()>,
    carrier_facts: Option<ConnFacts>,
    prepared: Mutex<HashMap<ConnId, (NeedId, u64)>>,
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
        status_namespace: status.map(|_| "http".to_owned()),
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl Endpoint {
    fn new(answers: Vec<(u32, Vec<u8>)>, carrier_facts: Option<ConnFacts>) -> Self {
        Self {
            answers,
            carrier_facts,
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
        assert_eq!(*self.deadlines.lock().unwrap(),vec![(0,30_000);sent.len()],"the actual OAuth request retains distinct need-default dial and 30-second request deadlines");
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
        self.deadlines
            .lock()
            .unwrap()
            .push((_dial_timeout_ms, desc.timeout_ms));
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
        // A `target_from` that resolved to nothing is refused, as the connector refuses it.
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        self.declared_owners.lock().unwrap().push(owner);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.framed && self.slab.check_need(owner, need).is_ok()
    }
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(owner, need)?;
        let id = self.slab.insert(owner, need, ())?;
        self.prepared
            .lock()
            .unwrap()
            .insert(id, (need, dial_timeout_ms));
        if let Err(error) = self.commit_request(owner, id, desc, require_secure) {
            self.close(owner, id)?;
            return Err(error);
        }
        Ok(id)
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
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
        Some(modeled_secure_facts()),
    ] {
        let secure = carrier_facts
            .as_ref()
            .is_some_and(|facts| facts.peer_cert.is_some());
        let available = carrier_facts.is_some();
        let endpoint = Endpoint::new(vec![(200, b"{}".to_vec())], carrier_facts);
        endpoint.slab.declare(owner, need);
        // URL spelling is deliberately identical for unavailable, insecure and secure carriers.
        let dial = OpenDesc {
            target: "https://scripted.invalid/token",
            ..OpenDesc::default()
        };
        let id = endpoint.prepare_request(owner, need, &dial, 0).unwrap();
        assert!(endpoint.sent.lock().unwrap().is_empty());
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
            assert_eq!(endpoint.sent.lock().unwrap().len(), 1);
            assert!(endpoint.replies.lock().unwrap().contains_key(&id));
            assert_eq!(
                endpoint.commit_request(owner, id, &request, true),
                Err(ConnError::Refused)
            );
        } else {
            assert_eq!(committed, Err(ConnError::AuthRefused));
            assert!(endpoint.sent.lock().unwrap().is_empty());
            assert!(endpoint.replies.lock().unwrap().is_empty());
        }
        endpoint.close(owner, id).unwrap();
        assert!(endpoint.prepared.lock().unwrap().is_empty());
        assert!(endpoint.facts(owner, id).is_err());
        assert!(endpoint.commit_request(owner, id, &request, true).is_err());
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
    fn facts(&self, owner: InstanceId, id: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(owner, id)?;
        self.carrier_facts.clone().ok_or(ConnError::Refused)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.slab.get(c, id)?;
        self.prepared.lock().unwrap().remove(&id);
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
fn open_outbound(p: &Plugin<Auth>, x: &OAuthGrant) -> (String, u64) {
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
        // SAFETY: this completed actual FIELDS reply lends its extension until the next call.
        let ext = out.head.extensions;
        let bytes = if ext.len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }
        };
        assert_eq!(extensions::get(bytes,busbar_contract::abi::sdk::auth_outbound::EXT_SEALED_FIELDS),Some(busbar_contract::abi::sdk::auth_outbound::SEALED_FIELDS_V1),"the receiving host must preserve the actual credential's secure-connection requirement");
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
    (
        format!(
            "{:?} lease={} {}",
            done.outcome,
            done.frame.as_ref().is_some_and(|f| f.out.head.lease != 0),
            done.error
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
        ),
        next,
    )
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
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, RecordsList, Stored, TrustKeyRef,
    UNSERVED,
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
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_decide(
        &self,
        _caller: &Caller,
        _ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
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
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
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
    fn snapshot_read(&self, _caller: &Caller, _scope: u32, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
}

use busbar_plugin_loader::dispatch::{in_head, out_head, Called, InFrame, OutFrame};
fn input<T: InFrame>() -> T {
    // SAFETY: ABI InFrame consists of zero-valid C data and begins with InHead.
    let mut value: T = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::addr_of_mut!(value)
            .cast::<busbar_contract::abi::mechanism::call::InHead>()
            .write(in_head())
    };
    value
}
fn output<T: OutFrame>() -> T {
    // SAFETY: ABI OutFrame consists of zero-valid C data and begins with OutHead.
    let mut value: T = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::addr_of_mut!(value)
            .cast::<busbar_contract::abi::mechanism::call::OutHead>()
            .write(out_head())
    };
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
        Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            clock,
            busbar_contract::services::test_caller_binding(),
        )),
    )
}
fn counts(p: &Plugin<Auth>) -> u64 {
    p.test_invocations().0 - p.test_invocations().1
}
fn count<T>(p: &Plugin<Auth>, expected: u64, op: impl FnOnce() -> T) -> T {
    let before = counts(p);
    let result = op();
    assert_eq!(counts(p) - before, expected, "actual dispatcher crossings");
    result
}
fn product(dropped: bool, d: &Dispatcher, e: Arc<Endpoint>) -> Plugin<Auth> {
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
        load_linked::<Auth>(&LinkedRow::of(busbar_auth_oauth::door).unwrap(), bind).unwrap()
    }
}
fn close(p: &Plugin<Auth>) -> String {
    let mut frame = Frame::new(in_head(), out_head());
    let answer = count(p, 1, || {
        p.call(
            busbar_contract::abi::mechanism::lifecycle::slot::CLOSE,
            &mut frame,
        )
    });
    assert_eq!(answer.outcome, Outcome::Ready);
    called(&answer)
}
fn opened(p: &Plugin<Auth>, d: &Dispatcher, x: &OAuthGrant) -> (u64, Vec<String>) {
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ValidateIn};
    let mut steps = Vec::new();
    let mut validate = Frame::new(
        ValidateIn {
            settings: json(&x.settings),
            ..input()
        },
        out_head(),
    );
    let answer = count(p, 1, || p.call(life::VALIDATE, &mut validate));
    assert_eq!(answer.outcome, Outcome::Ready);
    steps.push(called(&answer));
    let mut open: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    open.input.settings = json(&x.settings);
    let answer = count(p, 1, || p.call(life::OPEN, &mut open));
    assert_eq!(answer.outcome, Outcome::Ready);
    steps.push(called(&answer));
    let answer = count(p, u64::from(p.has_ready()), || p.ready(d, TICK_WAIT));
    assert_eq!(answer, Ok(()));
    steps.push(format!("has_ready={} {answer:?}", p.has_ready()));
    let (answer, handle) = count(p, 1, || open_outbound(p, x));
    assert!(answer.starts_with("Ready "), "{answer}");
    steps.push(answer);
    (handle, steps)
}
fn flags(x: &OAuthGrant) -> (u32, u32) {
    // SAFETY: the real product Statement owns the static auth tail and style declarations.
    unsafe {
        let t = &*declared().kind_tail.cast::<auth::AuthTail>();
        let ds = std::slice::from_raw_parts(t.styles, t.styles_len);
        let decl = ds
            .iter()
            .find(|d| d.name.as_str().unwrap() == x.style)
            .expect("JSON style declared by real product");
        assert_eq!(decl.points.count_ones(), 1);
        (decl.flags, decl.points)
    }
}
fn fields_checked(p: &Plugin<Auth>, h: u64, x: &OAuthGrant, head: &Head, expected: &str) {
    let (flags, point) = flags(x);
    assert_eq!(
        count(p, 1, || sign(p, h, head, flags, point)),
        expected,
        "expected actual minted fields"
    );
}

#[test]
fn oauth_client_credentials_actual_doors() {
    grant_case(client_credentials_case());
}
#[test]
fn jwt_bearer_actual_doors() {
    grant_case(jwt_bearer_case());
}
#[test]
fn token_exchange_actual_doors() {
    grant_case(token_exchange_case());
}

/// What a call on a scheduled binding whose first mint failed is told.
const NO_TOKEN: &str = "no OAuth token could be minted for this binding (see diagnostics \
     BUSBAR-4014/4015/4016); the call is refused rather than sent unauthenticated, and the mint \
     retries on its schedule";

/// What a call that waited on a token exchange that failed is told.
const EXCHANGE_FAILED: &str = "the RFC 8693 token exchange for this call's scope failed; the call \
     is refused rather than made unauthenticated (see diagnostics BUSBAR-4014/4015/4016)";

/// How a call inside a failed exchange's back-off window is told, up to its window's length.
const BACKING_OFF: &str = "the RFC 8693 token exchange for this call's scope failed (token \
     endpoint returned 500 Internal Server Error); it is not tried again for ";

fn grant_case(x: OAuthGrant) {
    let mut refusals = Vec::new();
    let mut before_mint = Vec::new();
    let mut both_steps = Vec::new();
    for dropped in [false, true] {
        let m = x.minting.as_ref().unwrap();
        let e = Arc::new(Endpoint::new(
            m.exchanges
                .iter()
                .map(|v| (v.status, v.body.clone()))
                .collect(),
            Some(modeled_secure_facts()),
        ));
        let (clock, d) = clock_dispatcher(x.head.timestamp);
        let p = product(dropped, &d, e.clone());
        let (h, mut steps) = opened(&p, &d, &x);
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
            let (answer, tick_next) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, T0));
            assert!(answer.starts_with("Ready "));
            steps.push(format!("{answer} next={tick_next}"));
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
            let (answer, tick_next) = count(&p, 1, || {
                tick_driver(&p, &d, &clock, driver, T0 + m.expires_in / 2 * NS)
            });
            assert!(answer.starts_with("Ready "));
            steps.push(format!("{answer} next={tick_next}"));
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
            assert!(answer.starts_with("Ready "));
            steps.push(format!("{answer} next={next}"));
            assert_eq!(e.count(), 1, "exactly ONE token exchange");
            fields_checked(&p, h, &x, &x.head, &x.expect);
            fields_checked(&p, h, &x, &x.head, &x.expect);
            assert_eq!(e.report(&m.exchanges), "exchanges=1 [ok]");
            assert_eq!(
                count(&p, 1, || ready_fact(&p, h)),
                "Ready lease=false  ready=1"
            );
            assert!(next > T0 && next <= T0 + m.expires_in * NS);
            let (answer, tick_next) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, next));
            assert!(answer.starts_with("Ready "));
            steps.push(format!("{answer} next={tick_next}"));
            fields_checked(&p, h, &x, &x.head, &m.refreshed);
            assert_eq!(e.report(&m.exchanges), "exchanges=2 [ok, ok]");
        }
        steps.push(close(&p));
        let closed = count(&p, 0, || sign(&p, h, &x.head, flags, point));
        // The actual loader faults a closed instance before any product operation crossing.
        assert_eq!(closed, "Fault ", "a closed instance cannot produce fields");
        steps.push(closed);
        let failing = Arc::new(Endpoint::new(
            vec![(500, b"conformance: the token endpoint is down".to_vec())],
            Some(modeled_secure_facts()),
        ));
        let (clock, d) = clock_dispatcher(x.head.timestamp);
        let p = product(dropped, &d, failing.clone());
        let (h, failure_open) = opened(&p, &d, &x);
        steps.extend(failure_open);
        let driver = d.driver(&p, 0).unwrap();
        let (answer, tick_next) = count(&p, 1, || tick_driver(&p, &d, &clock, driver, T0));
        assert!(answer.starts_with("Ready "));
        steps.push(format!("{answer} next={tick_next}"));
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
            assert_eq!(
                failure,
                format!("{} {EXCHANGE_FAILED}", m.refusal),
                "the waiting call is told its exchange failed"
            );
            let again = count(&p, 1, || {
                submit_fields(&p, &d, h, &x.head, flags, point).answered()
            });
            assert!(
                again.starts_with(&format!("{} {BACKING_OFF}", m.refusal)),
                "a call inside the back-off window fails fast with the cached reason: {again}"
            );
            assert_eq!(failing.count(), 1, "failed exchange does not retry");
        } else {
            assert_eq!(
                failure,
                format!("{} {NO_TOKEN}", m.refusal),
                "the call is told no token could be minted"
            );
            assert_eq!(
                count(&p, 1, || ready_fact(&p, h)),
                "Ready lease=false  ready=0"
            );
        }
        refusals.push(failure);
        steps.push(close(&p));
        both_steps.push(steps);
    }
    assert_eq!(
        both_steps[0], both_steps[1],
        "actual per-step called/ready/tick/close parity"
    );
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
    // SAFETY: the real host slot receives this live correctly typed frame and
    // the actual loaded instance context; all lent memory remains live through the call.
    let raw = unsafe {
        f(
            p.test_host_context(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
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
    // SAFETY: the real host slot receives this live correctly typed frame and
    // the actual loaded instance context; all lent memory remains live through the call.
    let raw = unsafe {
        f.expect("the host offers READ and WRITE")(
            p.test_host_context(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

/// `CLOSE` of `stream`, on `p`'s own context.
fn close_stream(p: &Plugin<Auth>, stream: u64) -> (Outcome, u64, String) {
    let i = StreamIn {
        head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
        stream,
    };
    let mut o = out();
    // SAFETY: the real host slot receives this live correctly typed frame and
    // the actual loaded instance context; all lent memory remains live through the call.
    let raw = unsafe {
        CONN_SLOTS.close.expect("the host offers CLOSE")(
            p.test_host_context(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

#[test]
fn actual_oauth_host_connections_refuse_undeclared_need_and_other_owner() {
    let mut endpoint = Endpoint::new(vec![(200, b"{}".to_vec())], None);
    endpoint.framed = false; // Exercise raw host connection custody on the actual auth context.
    let endpoint = Arc::new(endpoint);
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let owner = product(false, &d, endpoint.clone());
    let other = product(false, &d, endpoint.clone());
    // These real needs take their targets from binding settings: actual lifecycle and binding
    // admission must declare them before a host connection can be used by either instance.
    let case = client_credentials_case();
    opened(&owner, &d, &case);
    opened(&other, &d, &case);
    let mut owners = endpoint.declared_owners.lock().unwrap().clone();
    owners.sort();
    owners.dedup();
    assert_eq!(
        owners.len(),
        2,
        "both actual loader instances declared their own need"
    );
    assert_ne!(owners[0], owners[1], "real connection owners are distinct");
    assert_ne!(
        owner.test_host_context(),
        other.test_host_context(),
        "the actual host contexts are distinct"
    );
    let target = "https://login.conformance.invalid/oauth2/token";
    let (outcome, conn, text) = establish(&owner, 0, target);
    assert_eq!(outcome, Outcome::Ready, "{text}");
    assert_eq!(
        *endpoint.deadlines.lock().unwrap(),
        [(5_000, 0)],
        "the raw custody probe explicitly supplies its separate dial timeout"
    );
    assert_eq!(io(&owner, conn, true).0, Outcome::Ready);
    for need in [2, u32::MAX] {
        let (outcome, _, text) = establish(&owner, need, target);
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
    close(&owner);
    close(&other);
}

#[test]
fn actual_oauth_does_not_send_credentials_without_secure_carrier_facts_both_doors() {
    for dropped in [false, true] {
        for carrier_facts in [None, Some(ConnFacts::default())] {
            let endpoint = Arc::new(Endpoint::new(vec![(200, b"{}".to_vec())], carrier_facts));
            let case = client_credentials_case();
            let (clock, dispatcher) = clock_dispatcher(case.head.timestamp);
            let plugin = product(dropped, &dispatcher, endpoint.clone());
            let (binding, _) = opened(&plugin, &dispatcher, &case);
            let driver = dispatcher.driver(&plugin, 0).unwrap();
            let _ = tick_driver(&plugin, &dispatcher, &clock, driver, T0);
            let (flags, point) = flags(&case);
            let result = sign(&plugin, binding, &case.head, flags, point);
            assert!(result.starts_with("Failed "), "{result}");
            assert_eq!(
                endpoint.count(),
                0,
                "HTTPS does not establish carrier security"
            );
            assert!(endpoint.deadlines.lock().unwrap().is_empty());
            assert!(endpoint.replies.lock().unwrap().is_empty());
            close(&plugin);
            assert!(endpoint.prepared.lock().unwrap().is_empty());
        }
    }
}

fn declared() -> &'static busbar_contract::abi::mechanism::door::Statement {
    // SAFETY: the linked entry owns a static immutable declaration.
    unsafe { &*busbar_auth_oauth::door().statement() }
}
