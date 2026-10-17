// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Held`] — a credential THIS PLUGIN holds in its own memory: the `client_secret`, the
//! service-account private key, the RFC 8693 subject token, the minted access token, and the token
//! request body that carries one of them.
//!
//! These are the plugin's own material, not a value the kernel resolved and lent it, so they are not
//! the contract's sealed `Secret<T>` (busbar #1021, BUSBAR-1.6.0.md Part 2 #54 / #65: that type's
//! one raw accessor takes a kernel seal, which a plugin neither holds nor can obtain). `Held` keeps
//! exactly the hygiene the plugin relied on when it wrapped them in the contract's former redaction
//! wrapper:
//!
//! * **`Debug` / `Display` never reveal it.** Both print the literal `"[REDACTED]"`, byte for byte
//!   what the former wrapper printed, so a struct that embeds a `Held` field and derives `Debug`
//!   cannot leak it into a log line, a panic message or an error `{:?}`.
//! * **It does not serialize.** `Held` implements neither `Serialize` nor `Deserialize`; a secret
//!   field of a decoded document lands in one through
//!   [`deserialize_held`](crate::token_response::deserialize_held).
//! * **It zeroizes its backing memory on drop.**
//! * **Equality is constant-time** (the contract's `constant_time_eq` over the byte form), so a
//!   derived `PartialEq` on a struct that embeds one does not leak a common prefix through timing.
//!
//! The value is reached ONLY through [`Held::reveal`]: every call site is an audit point where the
//! plaintext escapes on purpose.

use core::fmt;

use zeroize::Zeroize;

/// A credential this plugin holds. `Debug`/`Display` print `"[REDACTED]"`; it never serializes; its
/// backing memory is zeroized on drop. See the module docs. `Default` is an EMPTY value (no
/// material), as the former wrapper's was.
#[derive(Default)]
pub(crate) struct Held<T: Zeroize>(T);

impl<T: Zeroize> Held<T> {
    /// Hold `secret`.
    pub(crate) fn new(secret: T) -> Self {
        Self(secret)
    }

    /// Borrow the held value. AUDIT POINT: the plaintext escapes redaction here.
    pub(crate) fn reveal(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Held<T> {
    fn from(secret: T) -> Self {
        Self(secret)
    }
}

/// `Debug` NEVER reveals the value.
impl<T: Zeroize> fmt::Debug for Held<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// `Display` NEVER reveals the value either.
impl<T: Zeroize> fmt::Display for Held<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Drop for Held<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Held<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Equality on two held values is CONSTANT-TIME (the contract's `constant_time_eq`), never a
/// byte-by-byte compare with a data-dependent early exit.
impl<T: Zeroize + AsRef<[u8]>> PartialEq for Held<T> {
    fn eq(&self, other: &Self) -> bool {
        busbar_contract::constant_time_eq(&self.0, &other.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Held<T> {}

#[cfg(test)]
#[path = "tests/held_tests.rs"]
mod tests;
