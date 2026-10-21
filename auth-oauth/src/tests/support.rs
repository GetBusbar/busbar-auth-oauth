// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit tests' host: host tables whose wake records the ticket it was handed (each host its
//! own record, so tests running side by side never read each other's wakes), and one `fields`
//! call answered as the SDK kit's door answers it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::task::Poll;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::sdk::auth_outbound::FieldsAnswer;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::fake::FakeHost;

use crate::instance::Oauth;
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

/// A host with a wake whose connector table is empty (a `FakeHost::new()` table: non-null, serving nothing). It owns its tables (a `FakeHost`); a test reads its
/// [`Host`] handle from it per call, never holding one past the borrow.
pub(crate) struct TestHost {
    fake: FakeHost,
    id: u64,
}

impl TestHost {
    pub(crate) fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        Self {
            fake: FakeHost::new().ctx(HostCtx { handle: id }).wake(wake),
            id,
        }
    }

    /// This host's handle, borrowed from its tables for as long as the host lives.
    #[allow(mismatched_lifetime_syntaxes)]
    pub(crate) fn host(&self) -> Host {
        let tables = self.fake.lent();
        Host::of(&tables)
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
    host: &Host,
    handle: u64,
    ticket: Ticket,
    scope: Option<&str>,
) -> (Outcome, String) {
    let mut written = Vec::new();
    let ask = Ask {
        handle,
        own: true,
        scope: scope.map(str::as_bytes),
        ticket,
        timestamp: 0,
    };
    let answer = o.answer(&ask, Some(host), &mut |h| {
        written.push(format!("authorization: {h}"));
    });
    let outcome = match answer {
        Poll::Pending if ticket.is_none() => Outcome::Refused,
        Poll::Pending => Outcome::Pending,
        Poll::Ready(FieldsAnswer::Ready) => Outcome::Ready,
        Poll::Ready(FieldsAnswer::Refused) => Outcome::Refused,
        Poll::Ready(FieldsAnswer::Failed(_)) => Outcome::Failed,
    };
    if outcome != Outcome::Ready {
        written.clear();
    }
    (outcome, written.join(" ; "))
}
