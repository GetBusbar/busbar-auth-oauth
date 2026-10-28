// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data), the token cache (outlives handles) and the
//! waiting tickets. The door is the SDK's safe outbound-auth kit (`lib.rs`), which keeps each
//! answer's envelope itself.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockWriteGuard};

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_outbound::Diags;
use busbar_contract::abi::sdk::conn::Host;

use crate::mint::host_wire::HostWire;
use crate::mint::{Minted, Minter, Report, Wire, MIN_SLEEP_SECS};
use crate::style::Binding;

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A minted token holds bytes invalid in a header value (1.5.5 `EGRESS_OAUTH_TOKEN_INVALID_BYTES`).
    pub const OAUTH_TOKEN_INVALID_BYTES: u32 = 0;
    /// A 200 with an empty access token (1.5.5 `EGRESS_OAUTH_EMPTY_TOKEN`).
    pub const OAUTH_EMPTY_TOKEN: u32 = 1;
    /// A mint failed (1.5.5 `EGRESS_OAUTH_MINT_FAILED`).
    pub const OAUTH_MINT_FAILED: u32 = 2;
}

const WARN: u8 = 1;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One plugin instance: the SDK kit's [`OutboundPlugin`](busbar_contract::abi::sdk::auth_outbound::OutboundPlugin).
pub struct Oauth {
    /// A test's need double; production reaches its need through the host tables each `tick` and
    /// `drive` is handed.
    wire: Option<Box<dyn Wire>>,
    /// The instance's driver ticket, as its first `tick` names it: a binding opened, or a request
    /// waiting on a token, wakes it so a `drive` starts the mint at once.
    driver: Mutex<Ticket>,
    /// The handle count of the driver ticket's cycle ([`HostWire`]): reset at each `tick`, carried
    /// on through each `drive`.
    issued: AtomicU32,
    /// The last `tick`'s clock (`TickIn::now_ns`) and the host's monotonic clock as it read then:
    /// a `drive` reads the tick clock from them (THE DESIGN §1: "one clock"; the plugin reads none
    /// of its own).
    clock: Mutex<Option<(u64, Option<u64>)>>,
    /// The host's wall clock (epoch seconds) as it last read (`clock.now` at a `tick` or `drive`,
    /// or a call's own timestamp); `0` before the first reading.
    wall: AtomicU64,
    generation: AtomicU64,
    next_handle: AtomicU64,
    handles: RwLock<HashMap<u64, (u64, Binding)>>,
    /// The token cells, by cache key: a call that finds its cell usable reads it under the read
    /// lock; every change (and every park) takes the write lock.
    cache: RwLock<HashMap<[u8; 32], Arc<Minted>>>,
    waiters: Mutex<Vec<Ticket>>,
    /// The tickets waiting on each on-demand cell's exchange (a token-exchange scope), by its cache
    /// key: woken when it lands, or failed when it fails. Taken after `cache` wherever both are.
    exchange_waiters: Mutex<HashMap<[u8; 32], Vec<Ticket>>>,
    /// The tickets whose exchange failed: their resumed call answers FAILED (the attempt fails, as
    /// the previous release failed the call whose exchange the authorization server refused).
    exchange_failed: Mutex<Vec<Ticket>>,
}

impl crate::style::TokenCache for Oauth {
    fn cell(&self, key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
        self.cache_mut()
            .entry(key)
            .or_insert_with(|| Arc::new(Minted::new(minter, max)))
            .clone()
    }
}

impl Oauth {
    /// The token cache, to change.
    fn cache_mut(&self) -> RwLockWriteGuard<'_, HashMap<[u8; 32], Arc<Minted>>> {
        self.cache.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// An instance at `generation`; its need is the host's, reached through the tables each
    /// `tick` and `drive` is handed (none: no need was granted, and a minted style reports that
    /// no connection was).
    pub(crate) fn new(generation: u64) -> Self {
        Self::with_wire(generation, None)
    }

    /// An instance over any [`Wire`] (the unit tests' double).
    pub(crate) fn with_wire(generation: u64, wire: Option<Box<dyn Wire>>) -> Self {
        Self {
            wire,
            driver: Mutex::new(Ticket::NONE),
            issued: AtomicU32::new(0),
            clock: Mutex::new(None),
            wall: AtomicU64::new(0),
            generation: AtomicU64::new(generation),
            next_handle: AtomicU64::new(1),
            handles: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
            waiters: Mutex::new(Vec::new()),
            exchange_waiters: Mutex::new(HashMap::new()),
            exchange_failed: Mutex::new(Vec::new()),
        }
    }

    /// `refresh`: the generation later handles belong to.
    pub(crate) fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    /// Keep `cell` under a new handle of the current generation.
    pub(crate) fn keep(&self, cell: Arc<Minted>) -> u64 {
        self.keep_binding(Binding::Minted(cell))
    }

    /// Keep `binding` under a new handle of the current generation.
    pub(crate) fn keep_binding(&self, binding: Binding) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.load(Ordering::Acquire);
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, binding));
        handle
    }

    /// The binding behind `handle`.
    pub(crate) fn bound(&self, handle: u64) -> Option<Binding> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b)| b.clone())
    }

    /// THE CELL OF AN ON-DEMAND SCOPE, looked up (or made) and, for a call on `ticket` that will
    /// wait, that ticket parked on it, in ONE critical section with the cache: a tick that settles
    /// the cell either ran before (and the call finds or makes the cell anew) or after (and finds
    /// the ticket waiting, so it keeps the cell). `usable` says whether the call would present the
    /// cell's token now; a ticket that would wait is parked BEFORE the token is read, so an
    /// exchange that lands meanwhile still finds it.
    pub(crate) fn exchange_cell(
        &self,
        key: [u8; 32],
        make: impl FnOnce() -> (Minter, usize),
        ticket: Ticket,
        usable: impl Fn(&Minted) -> bool,
    ) -> Arc<Minted> {
        // THE HIT: a cell that exists, for a call that will not park on it (no ticket, or a token
        // it presents now), under the read lock only.
        if let Some(cell) = self
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .filter(|c| ticket.is_none() || usable(c))
        {
            return Arc::clone(cell);
        }
        let mut cache = self.cache_mut();
        let cell = Arc::clone(cache.entry(key).or_insert_with(|| {
            let (minter, max) = make();
            Arc::new(Minted::new(minter, max))
        }));
        if !ticket.is_none() && !usable(&cell) {
            let mut w = lock(&self.exchange_waiters);
            let waiting = w.entry(key).or_default();
            if !waiting.contains(&ticket) {
                waiting.push(ticket);
            }
        }
        drop(cache);
        cell
    }

    /// Forget `ticket` as waiting on the on-demand cell `key` (its call answered after all).
    pub(crate) fn unpark_exchange(&self, key: [u8; 32], ticket: Ticket) {
        // A call on no ticket is never parked.
        if ticket.is_none() {
            return;
        }
        let mut w = lock(&self.exchange_waiters);
        if let Some(waiting) = w.get_mut(&key) {
            waiting.retain(|t| *t != ticket);
            if waiting.is_empty() {
                w.remove(&key);
            }
        }
    }

    /// Whether `ticket`'s exchange failed (forgotten once read: the call it serves answers FAILED).
    pub(crate) fn exchange_failed(&self, ticket: Ticket) -> bool {
        let mut failed = lock(&self.exchange_failed);
        let before = failed.len();
        failed.retain(|t| *t != ticket);
        failed.len() != before
    }

    /// `retire`: drop the handles opened at `generation`, then every token cell no handle holds AND
    /// nothing still needs. An on-demand exchange cell is held by no handle, so one with an exchange
    /// in flight (its connection open) or a ticket waiting on it stays: the cache outlives a handle
    /// (contract `abi/auth`), and a waiting ticket is woken when its exchange settles, never lost.
    /// Its tick drops it from the cache once it is idle and unwaited.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
        // The cache's lock first, then the waiters', as `exchange_cell` takes them.
        let mut cache = self.cache_mut();
        let waiting = lock(&self.exchange_waiters);
        cache.retain(|key, c| {
            Arc::strong_count(c) > 1 || !c.idle() || waiting.get(key).is_some_and(|w| !w.is_empty())
        });
    }

    /// Park `ticket` until a mint lands.
    pub(crate) fn park(&self, ticket: Ticket) {
        let mut w = lock(&self.waiters);
        if !w.contains(&ticket) {
            w.push(ticket);
        }
    }

    /// Forget `ticket` as waiting on a mint (its call answered after all).
    pub(crate) fn unpark_mint(&self, ticket: Ticket) {
        lock(&self.waiters).retain(|t| *t != ticket);
    }

    /// `cancel`: forget `ticket`.
    pub(crate) fn unpark(&self, ticket: Ticket) {
        lock(&self.waiters).retain(|t| *t != ticket);
        // An emptied list is dropped with its key: no entry outlives the waiters it served.
        lock(&self.exchange_waiters).retain(|_, waiting| {
            waiting.retain(|t| *t != ticket);
            !waiting.is_empty()
        });
        lock(&self.exchange_failed).retain(|t| *t != ticket);
    }

    /// A mint is wanted now (a binding opened; a request waits on a token): wake the driver
    /// ticket, so a `drive` starts it without waiting for the next `tick`. Before the first `tick`
    /// nothing is woken: that tick, made at once, starts it.
    pub(crate) fn mint_soon(&self, host: Option<&Host>) {
        let driver = *lock(&self.driver);
        if let (Some(h), false) = (host, driver.is_none()) {
            h.wake(driver);
        }
    }

    /// `tick` at tick-clock `now_ns` on the driver ticket `ticket`: a new cycle (its handle count
    /// carries on: the host may still keep the last cycle's answers), the refresh ahead of expiry,
    /// the wakes. Answers the next tick; an instance
    /// with no binding yet still asks for one ([`MIN_SLEEP_SECS`] on), never ending its schedule.
    pub(crate) fn tick(
        &self,
        now_ns: u64,
        ticket: Ticket,
        host: Option<&Host>,
        diags: &mut Diags,
    ) -> u64 {
        if !ticket.is_none() {
            *lock(&self.driver) = ticket;
        }
        self.advance(Some(now_ns), ticket, host, diags)
            .unwrap_or(now_ns.saturating_add(MIN_SLEEP_SECS * crate::mint::NS))
    }

    /// `drive` on the driver ticket `ticket` (a wake: a read that pended, [`Oauth::mint_soon`], or
    /// the timer the last `drive` set): the cycle goes on, at the tick clock as it now reads. Answers
    /// when the earliest cell is next due, the instant the `drive` asks to be resumed at (a mint
    /// landed between ticks schedules its own refresh: the tick schedule was set before it), or
    /// `None` (no cell, or no `tick` yet).
    pub(crate) fn drive(
        &self,
        ticket: Ticket,
        host: Option<&Host>,
        diags: &mut Diags,
    ) -> Option<u64> {
        self.advance(None, ticket, host, diags)
    }

    /// The host's wall clock (epoch seconds) as it last read; `0` before the first reading.
    pub(crate) fn wall_secs(&self) -> u64 {
        self.wall.load(Ordering::Acquire)
    }

    /// A call's own timestamp (the host's wall clock, epoch seconds) is the newest reading.
    pub(crate) fn saw_wall(&self, secs: u64) {
        if secs != 0 {
            self.wall.store(secs, Ordering::Release);
        }
    }

    /// Advance every token cell over the need on `ticket`, at the tick's `at` (a `tick`) or, on a
    /// `drive`, at the last tick's clock moved on by the host's monotonic time since it: when the
    /// next tick is wanted (`None`: no cell, or a `drive` before any `tick`).
    fn advance(
        &self,
        at: Option<u64>,
        ticket: Ticket,
        host: Option<&Host>,
        diags: &mut Diags,
    ) -> Option<u64> {
        let host_wire = host
            .filter(|h| h.lends_connector())
            .map(|h| HostWire::new(h, ticket, &self.issued));
        let wire: Option<&dyn Wire> = match (&self.wire, &host_wire) {
            (Some(w), _) => Some(w.as_ref()),
            (None, Some(h)) => Some(h),
            (None, None) => None,
        };
        let reading = wire.and_then(|w| w.clock());
        if let Some(r) = reading {
            self.saw_wall(r.wall_secs);
        }
        let now_ns = match at {
            Some(now_ns) => {
                *lock(&self.clock) = Some((now_ns, reading.map(|r| r.mono_ns)));
                now_ns
            }
            None => {
                let (at, mono_at) = (*lock(&self.clock))?;
                match (mono_at, reading) {
                    (Some(then), Some(r)) => at.saturating_add(r.mono_ns.saturating_sub(then)),
                    _ => at,
                }
            }
        };
        let wall = self.wall_secs();
        let cells: Vec<([u8; 32], Arc<Minted>)> = self
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(k, c)| (*k, Arc::clone(c)))
            .collect();
        let mut next = u64::MAX;
        let mut minted = false;
        for (key, cell) in cells {
            let (due, report) = cell.tick(now_ns, wall, wire);
            if cell.on_demand() {
                next = next.min(due);
                self.settle_exchange(key, &cell, report, host, diags);
                continue;
            }
            match report {
                Some(Report::Minted) => minted = true,
                Some(Report::TokenInvalidBytes) => {
                    minted = true;
                    diags.push(
                        diag::OAUTH_TOKEN_INVALID_BYTES,
                        WARN,
                        "minted an OAuth token with bytes invalid for an HTTP header value; \
                         omitting the auth header — upstream will reject with 401",
                    );
                }
                Some(Report::EmptyToken) => diags.push(
                    diag::OAUTH_EMPTY_TOKEN,
                    WARN,
                    "OAuth token endpoint returned a 200 with an empty access_token; treating as a \
                     mint failure and will retry",
                ),
                Some(Report::MintFailed(e)) => diags.push(
                    diag::OAUTH_MINT_FAILED,
                    WARN,
                    format!("OAuth token mint failed; will retry error={e}"),
                ),
                None => {}
            }
            if !self.reap(key, &cell) {
                next = next.min(due);
            }
        }
        if minted {
            // The token is stored before this drain: a call that parks after the drain reads it
            // (it parks before it reads), and one that parked before is woken here.
            let woken: Vec<Ticket> = std::mem::take(&mut *lock(&self.waiters));
            if let Some(h) = host {
                for t in woken {
                    h.wake(t);
                }
            }
        }
        (next != u64::MAX).then_some(next)
    }

    /// A scheduled cell no handle holds leaves the cache once it is idle (what `retire`'s doc
    /// promises of a cell it kept for its mint): the cache's Arc and the tick's own are the only
    /// two, judged under the cache's lock. Whether it was dropped.
    fn reap(&self, key: [u8; 32], cell: &Arc<Minted>) -> bool {
        let mut cache = self.cache_mut();
        let orphan = Arc::strong_count(cell) == 2
            && cell.idle()
            && cache.get(&key).is_some_and(|c| Arc::ptr_eq(c, cell));
        if orphan {
            cache.remove(&key);
        }
        orphan
    }

    /// AN ON-DEMAND CELL'S TICK, settled: a landed exchange wakes the tickets waiting on it; a
    /// failed one fails them (each is woken, and its resumed call answers FAILED), naming why in
    /// the instance's log; a cell no request waits on, with nothing in flight and no token it would
    /// present, is dropped from the cache (its scope's next request makes it again) — judged under
    /// the cache's lock, so a call looking the cell up and parking on it is never split from it.
    fn settle_exchange(
        &self,
        key: [u8; 32],
        cell: &Minted,
        report: Option<Report>,
        host: Option<&Host>,
        diags: &mut Diags,
    ) {
        let failure = match report {
            None => None,
            Some(Report::Minted) => Some(false),
            Some(Report::TokenInvalidBytes) => {
                diags.push(
                    diag::OAUTH_TOKEN_INVALID_BYTES,
                    WARN,
                    "the RFC 8693 exchange returned a token with bytes invalid for an HTTP header \
                     value; the call is refused rather than made unauthenticated",
                );
                Some(true)
            }
            Some(Report::EmptyToken) => {
                diags.push(
                    diag::OAUTH_EMPTY_TOKEN,
                    WARN,
                    "the RFC 8693 exchange returned 200 with no usable `access_token`; the call is \
                     refused rather than made unauthenticated",
                );
                Some(true)
            }
            Some(Report::MintFailed(e)) => {
                diags.push(
                    diag::OAUTH_MINT_FAILED,
                    WARN,
                    format!("the RFC 8693 exchange failed; the call is refused error={e}"),
                );
                Some(true)
            }
        };
        if let Some(failed) = failure {
            if let Some(exchange) = cell.exchange() {
                exchange.settled(failed);
            }
            let woken = lock(&self.exchange_waiters)
                .remove(&key)
                .unwrap_or_default();
            if failed {
                lock(&self.exchange_failed).extend(woken.iter().copied());
            }
            if let Some(h) = host {
                for t in woken {
                    h.wake(t);
                }
            }
        }
        let mut cache = self.cache_mut();
        let waited = lock(&self.exchange_waiters)
            .get(&key)
            .is_some_and(|w| !w.is_empty());
        if !waited && cell.idle() && !cell.usable(self.wall_secs()) {
            cache.remove(&key);
        }
    }
}

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
