// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin's own need, over the host's connector (the minting styles mint through the plugin's
//! own `provider`-class need): [`HostWire`] is the
//! [`Wire`] the token exchange runs over in production. The token request goes out on the framed
//! need its style names (`ESTABLISH`, then `WRITE_REQUEST` head, body, end: the framer writes its
//! own wire head and its client defaults), and the reply is read piece by piece (`READ_REPLY`: its
//! head's code, its body, its terminal piece).
//!
//! THE REPLAY RULE (`busbar_contract::abi::sdk::conn`): every service carries the next completion
//! handle of the op's ticket. The exchange runs on the instance's DRIVER ticket, inside `tick` and
//! the `drive`s between ticks. The host forgets a ticket's kept answers only at a tick that
//! starts with nothing held, so the handle count is the instance's for the ticket's life, never
//! reset: no service is ever answered from another's kept result.

use std::sync::atomic::{AtomicU32, Ordering};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{ConnFailure, Connector, Host};
use busbar_contract::abi::sdk::cred::SealedWrite;
use busbar_contract::abi::transport::{fields, FrameSpan};
use busbar_contract::conn::{ConnError, ConnId, PieceKind};

use super::{retry_after, Got, HostClock, TokenRequest, Wire, NS};

/// The connector for one entry of the driver ticket's cycle.
pub(crate) struct HostWire<'a> {
    host: &'a Host<busbar_contract::plugin::markers::AuthKind>,
    ticket: Ticket,
    issued: &'a AtomicU32,
}

impl<'a> HostWire<'a> {
    /// The need's services over `host`, on `ticket`, the cycle's handle count in `issued`.
    pub(crate) fn new(
        host: &'a Host<busbar_contract::plugin::markers::AuthKind>,
        ticket: Ticket,
        issued: &'a AtomicU32,
    ) -> Self {
        Self {
            host,
            ticket,
            issued,
        }
    }

    /// Run `f` over the connector, the cycle's handle count carried in and out.
    fn with<T>(
        &self,
        f: impl FnOnce(&mut Connector<'_, busbar_contract::plugin::markers::AuthKind>) -> T,
    ) -> T {
        let mut c = self
            .host
            .connector_from(self.ticket, self.issued.load(Ordering::Acquire));
        let answer = f(&mut c);
        self.issued.store(c.issued(), Ordering::Release);
        answer
    }
}

/// The connection error a host refusal names: its text is the table's own (`ConnError::text`).
fn error_of(f: &ConnFailure) -> ConnError {
    const ALL: [ConnError; 9] = [
        ConnError::Pending,
        ConnError::Timeout,
        ConnError::Closed,
        ConnError::NotOwner,
        ConnError::UndeclaredNeed,
        ConnError::Refused,
        ConnError::Fault,
        ConnError::Unarmed,
        ConnError::CredentialUnavailable,
    ];
    match f {
        ConnFailure::Unarmed => ConnError::Unarmed,
        ConnFailure::NoTicket => ConnError::Pending,
        ConnFailure::Fault => ConnError::Fault,
        ConnFailure::CredentialUnavailable => ConnError::CredentialUnavailable,
        ConnFailure::Failed(t) => ALL
            .into_iter()
            .find(|e| e.text() == t)
            .unwrap_or(ConnError::Fault),
        ConnFailure::Refused(t) => ALL
            .into_iter()
            .find(|e| e.text() == t)
            .unwrap_or(ConnError::Refused),
    }
}

/// Preserve pending as a resumable answer.
fn now<T>(a: Poll<Result<T, ConnFailure>>) -> Result<T, ConnError> {
    match a {
        Poll::Ready(Ok(v)) => Ok(v),
        Poll::Ready(Err(f)) => Err(error_of(&f)),
        Poll::Pending => Err(ConnError::Pending),
    }
}

const fn span(offset: usize, len: usize) -> FrameSpan {
    FrameSpan {
        offset: offset as u64,
        len: len as u64,
    }
}

/// The request's head words and field block, as `WRITE_REQUEST`'s head piece names them: the
/// method `POST`, the target's path and query (no fragment: a client never sends one), then each
/// field.
fn head(req: &TokenRequest, timeout_ms: u64) -> Result<(Vec<u8>, RequestPiece), ConnError> {
    let url = busbar_contract::net::parse_url(&req.target).map_err(|_| ConnError::Refused)?;
    let words = url.path.split('#').next().unwrap_or("/");
    let mut bytes = b"POST".to_vec();
    bytes.extend_from_slice(words.as_bytes());
    let block_at = bytes.len();
    for (name, value) in &req.fields {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(fields::SEPARATOR);
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(fields::LINE_END);
    }
    let piece = RequestPiece {
        kind: REQUEST_HEAD,
        _reserved: 0,
        method: span(0, 4),
        target: span(4, words.len()),
        fields: span(block_at, bytes.len() - block_at),
        timeout_ms,
    };
    Ok((bytes, piece))
}

/// The `retry-after` of a reply head whose field block the host wrote in the first
/// `written` bytes of `buf` at `block_span` (the only field this plugin reads beyond the code);
/// `None` when it
/// carries none, or the span lies outside what was written.
fn head_retry_after(
    buf: &[u8],
    written: usize,
    block_span: FrameSpan,
) -> Option<super::RetryAfter> {
    let at = usize::try_from(block_span.offset).ok()?;
    let len = usize::try_from(block_span.len).ok()?;
    let block = buf.get(..written)?.get(at..at.checked_add(len)?)?;
    fields::lines(block)
        .find(|(name, _)| name.eq_ignore_ascii_case(b"retry-after"))
        .and_then(|(_, value)| retry_after(value))
}

/// The stream and completion handle retained while an opening is pending. Dropping an
/// unfinished opening (deadline, cancellation, retirement) closes its stream on no ticket.
pub(crate) struct Opening {
    host: Host<busbar_contract::plugin::markers::AuthKind>,
    ticket: Ticket,
    stream: Option<u64>,
    stage: OpenStage,
    pending: Option<u32>,
}

impl Opening {
    /// The response owner has closed the stream, or an immediate caller takes custody.
    pub(crate) fn release(&mut self) {
        self.stream = None;
    }
}

/// A pending reply carries the complete ticket and sequence, and the original host snapshot.
pub(crate) struct PendingRead {
    host: Host<busbar_contract::plugin::markers::AuthKind>,
    ticket: Ticket,
    seq: u32,
}

#[derive(Clone, Copy)]
enum OpenStage {
    Establish,
    Head,
    Facts,
    Body,
    End,
}

impl Drop for Opening {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = self.host.connector(Ticket::NONE).close(stream);
        }
    }
}

impl Wire for HostWire<'_> {
    fn open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        let mut state = None;
        let result = self.advance_open(req, body, timeout_ms, &mut state);
        if result.is_ok() {
            if let Some(opening) = &mut state {
                opening.release();
            }
        }
        result
    }

    fn advance_open(
        &self,
        req: &TokenRequest,
        body: &mut SealedWrite,
        timeout_ms: u64,
        state: &mut Option<Box<Opening>>,
    ) -> Result<ConnId, ConnError> {
        let opening = state.get_or_insert_with(|| {
            Box::new(Opening {
                host: *self.host,
                ticket: self.ticket,
                stream: None,
                stage: OpenStage::Establish,
                pending: None,
            })
        });
        loop {
            // Reuse precisely the pending service's handle, while subsequent services allocate
            // beyond ALL services issued by this driver's other cells and clock reads.
            let seq = opening.pending.take().unwrap_or_else(|| {
                if matches!(opening.stage, OpenStage::Body) && body.secure_required() {
                    // SealedWrite may issue FACTS and BODY in one call. Reserve both
                    // before yielding so its continuation cannot reuse another call's ID.
                    self.issued.fetch_add(2, Ordering::AcqRel)
                } else {
                    self.issued.load(Ordering::Acquire)
                }
            });
            let mut c = opening.host.connector_from(opening.ticket, seq);
            let answer = match opening.stage {
                OpenStage::Establish => c.establish(req.need, Some(&req.target), ""),
                OpenStage::Head => {
                    let (bytes, piece) = head(req, timeout_ms)?;
                    c.write_request(opening.stream.unwrap(), &piece, &bytes)
                        .map(|r| {
                            r.and_then(|n| {
                                if n == bytes.len() {
                                    Ok(0)
                                } else {
                                    Err(ConnFailure::Fault)
                                }
                            })
                        })
                }
                OpenStage::Facts => c.facts(opening.stream.unwrap()).map(|r| {
                    r.and_then(|facts| {
                        if facts.is_some_and(|facts| facts.secure) {
                            Ok(0)
                        } else {
                            Err(ConnFailure::Refused(
                                busbar_contract::abi::sdk::cred::NOT_SECURE.into(),
                            ))
                        }
                    })
                }),
                OpenStage::Body => body
                    .request(
                        &mut c,
                        opening.stream.unwrap(),
                        &RequestPiece {
                            kind: REQUEST_BODY,
                            ..RequestPiece::default()
                        },
                    )
                    .map(|r| {
                        r.and_then(|n| {
                            if n == body.len() {
                                Ok(0)
                            } else {
                                Err(ConnFailure::Fault)
                            }
                        })
                    }),
                OpenStage::End => c
                    .write_request(
                        opening.stream.unwrap(),
                        &RequestPiece {
                            kind: REQUEST_END,
                            ..RequestPiece::default()
                        },
                        &[],
                    )
                    .map(|r| r.map(|_| 0)),
            };
            self.issued.fetch_max(c.issued(), Ordering::AcqRel);
            if answer.is_pending() {
                opening.pending = Some(c.issued().saturating_sub(1));
                return Err(ConnError::Pending);
            }
            // The sealed writer owns closing a stream whose security confirmation fails.
            if matches!(opening.stage, OpenStage::Body)
                && matches!(&answer, Poll::Ready(Err(ConnFailure::Refused(reason))) if reason == busbar_contract::abi::sdk::cred::NOT_SECURE)
            {
                opening.stream = None;
            }
            let value = now(answer)?;
            opening.stage = match opening.stage {
                OpenStage::Establish => {
                    opening.stream = Some(value);
                    OpenStage::Head
                }
                OpenStage::Head => {
                    if body.secure_required() {
                        OpenStage::Facts
                    } else {
                        OpenStage::Body
                    }
                }
                OpenStage::Facts => OpenStage::Body,
                OpenStage::Body => OpenStage::End,
                OpenStage::End => return Ok(ConnId(opening.stream.unwrap())),
            };
        }
    }

    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError> {
        self.advance_read(conn, buf, &mut None)
    }

    fn advance_read(
        &self,
        conn: ConnId,
        buf: &mut [u8],
        state: &mut Option<Box<PendingRead>>,
    ) -> Result<Got, ConnError> {
        let pending = state.get_or_insert_with(|| {
            Box::new(PendingRead {
                host: *self.host,
                ticket: self.ticket,
                seq: self.issued.load(Ordering::Acquire),
            })
        });
        let mut c = pending.host.connector_from(pending.ticket, pending.seq);
        let mut slot = ReplyPiece::default();
        let answer = c.read_reply(conn.0, buf, &mut slot);
        self.issued.fetch_max(c.issued(), Ordering::AcqRel);
        if !answer.is_pending() {
            *state = None;
        }
        match answer {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(f)) => Err(error_of(&f)),
            Poll::Ready(Ok(got)) => match got.piece.kind {
                REPLY_HEAD => Ok(Got {
                    kind: PieceKind::Fields,
                    len: 0,
                    end: false,
                    status: Some(got.piece.code),
                    retry_after: head_retry_after(buf, got.len, got.piece.fields),
                }),
                REPLY_BODY => Ok(Got {
                    kind: PieceKind::Body,
                    len: got.len,
                    end: false,
                    status: None,
                    retry_after: None,
                }),
                REPLY_END | REPLY_ACK => Ok(Got {
                    kind: PieceKind::Completion,
                    len: 0,
                    end: true,
                    status: None,
                    retry_after: None,
                }),
                _ => Err(ConnError::Fault),
            },
        }
    }

    fn close(&self, conn: ConnId) {
        let _ = self.with(|c| c.close(conn.0));
    }

    fn clock(&self) -> Option<HostClock> {
        match self.with(|c| c.clock_now()) {
            Poll::Ready(Ok(r)) => Some(HostClock {
                wall_secs: r.wall_ns / NS,
                mono_ns: r.mono_ns,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "../tests/host_wire_tests.rs"]
mod tests;
