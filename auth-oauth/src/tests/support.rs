// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit tests' host: host tables whose wake records the ticket it was handed (each host its
//! own record, so tests running side by side never read each other's wakes), and one `fields`
//! call answered as the SDK kit's door answers it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::task::Poll;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::sdk::auth_outbound::FieldsAnswer;
use busbar_contract::abi::sdk::conn::Host;

use crate::instance::Oauth;
use crate::mint::Pause;
use crate::Ask;

static WOKEN: Mutex<Option<HashMap<u64, Vec<Ticket>>>> = Mutex::new(None);
static NEXT: AtomicU64 = AtomicU64::new(1);

extern "C" fn wake(ctx: HostCtx, t: Ticket) {
    WOKEN
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .entry(ctx.handle)
        .or_default()
        .push(t);
}

/// A host with a wake and no connector table.
pub(crate) struct TestHost {
    pub(crate) host: Host<busbar_contract::plugin::markers::AuthKind>,
    id: u64,
}

impl TestHost {
    pub(crate) fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let host = Host::wake_only(HostCtx { handle: id }, wake);
        Self { host, id }
    }

    /// The tickets this host woke since the last take, in order.
    pub(crate) fn take(&self) -> Vec<Ticket> {
        WOKEN
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .remove(&self.id)
            .unwrap_or_default()
    }
}

/// One `fields` (the operator's own credential) on `ticket`, its scope `scope`, answered as the
/// kit's door answers it: the outcome (a ticket-less PENDING is REFUSED) and the fields written,
/// `name: value` joined by ` ; `.
pub(crate) fn fields(
    o: &Oauth,
    host: &TestHost,
    handle: u64,
    ticket: Ticket,
    scope: Option<&str>,
) -> (Outcome, String) {
    fields_at(o, host, handle, ticket, scope, 0)
}

/// [`fields`] stamped with the host's wall time `timestamp` (epoch seconds; `0` = none).
pub(crate) fn fields_at(
    o: &Oauth,
    host: &TestHost,
    handle: u64,
    ticket: Ticket,
    scope: Option<&str>,
    timestamp: u64,
) -> (Outcome, String) {
    let mut written = Vec::new();
    let ask = Ask {
        handle,
        own: true,
        scope: scope.map(str::as_bytes),
        ticket,
        timestamp,
    };
    let answer = o.answer(&ask, Some(&host.host), &mut |h| {
        written.push(format!("authorization: {}", bearer_text(h)));
    });
    let outcome = match answer {
        Poll::Pending if ticket.is_none() => Outcome::Refused,
        Poll::Pending => Outcome::Pending,
        Poll::Ready(FieldsAnswer::Ready) => Outcome::Ready,
        Poll::Ready(FieldsAnswer::Refused | FieldsAnswer::RefusedBecause(_)) => Outcome::Refused,
        Poll::Ready(FieldsAnswer::Failed(_)) => Outcome::Failed,
    };
    if outcome != Outcome::Ready {
        written.clear();
    }
    (outcome, written.join(" ; "))
}

/// The bytes a sealed write carries, read back through the SDK's dev-only test support.
pub(crate) fn bearer_text(credential: &busbar_contract::abi::sdk::cred::Cred) -> String {
    sealed_text(&mut busbar_contract::abi::sdk::cred::SealedWrite::new(
        busbar_contract::abi::sdk::cred::Parts::new().sealed(credential.bearer()),
    ))
}

/// The bytes a sealed write carries, read back through the SDK's dev-only test support.
pub(crate) fn sealed_text(w: &mut busbar_contract::abi::sdk::cred::SealedWrite) -> String {
    let mut out = Vec::new();
    let done = busbar_contract::abi::sdk::test_support::chip::drive_sealed::<()>(w, |b| {
        out.extend_from_slice(b);
        std::task::Poll::Ready(Ok(b.len()))
    });
    assert!(done.is_ready(), "a test sink takes every byte");
    String::from_utf8(out).expect("a form is text")
}

/// A token request form as the wire carries it (the chip encodes it, signing what it signs).
pub(crate) fn form_text(body: &busbar_contract::abi::sdk::cred::FormBody) -> String {
    sealed_text(&mut body.encoded().expect("the form encodes"))
}

/// Records this plugin's refusal/outage events through the standard tracing formatter.
#[derive(Clone)]
pub(crate) struct OAuthEvents {
    bytes: std::sync::Arc<Mutex<Vec<u8>>>,
    level: tracing::Level,
}
impl Default for OAuthEvents {
    fn default() -> Self {
        Self {
            bytes: Default::default(),
            level: tracing::Level::WARN,
        }
    }
}
impl std::io::Write for OAuthEvents {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl OAuthEvents {
    pub(crate) fn capturing_debug() -> Self {
        Self {
            level: tracing::Level::DEBUG,
            ..Self::default()
        }
    }
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(self.level)
            .with_writer(move || writer.clone())
            .finish()
    }
    pub(crate) fn messages(&self) -> Vec<String> {
        String::from_utf8(self.bytes.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    pub(crate) fn count(&self, text: &str) -> usize {
        self.messages()
            .iter()
            .filter(|line| line.contains(text))
            .count()
    }
}

/// A ONE-SHOT PAUSE for a production seam ([`Pause`]): the first thread to pass it announces
/// itself on the returned receiver and is held there until the returned sender sends; every later
/// pass runs straight through.
pub(crate) fn pause_once() -> (Pause, Receiver<()>, SyncSender<()>) {
    let (entered, arrived) = sync_channel(0);
    let (release, resume) = sync_channel::<()>(0);
    let armed = AtomicBool::new(true);
    let resume = Mutex::new(resume);
    let pause: Pause = Box::new(move || {
        if armed.swap(false, Ordering::AcqRel) {
            entered.send(()).unwrap();
            resume.lock().unwrap().recv().unwrap();
        }
    });
    (pause, arrived, release)
}
