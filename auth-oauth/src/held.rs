// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Own`] and [`Secret`] — THIS PLUGIN'S OWN SEAL over the credentials it holds in its own memory:
//! the `client_secret`, the service-account private key, the RFC 8693 subject token, the minted
//! access token, and the token request body that carries one of them.
//!
//! They are held as `Secret<T, Own>`, wrapped with `Secret::held` and read with
//! `Secret::expose_own(&Own::here())`. No other crate can name or construct `Own` or this
//! `Secret`, so no other crate can read them. The hygiene is the contract `Secret`'s:
//! `Debug`/`Display` print `"[REDACTED]"`, nothing serializes or deserializes (a secret
//! member of a decoded document is read by [`wiped_member`](crate::token_response::wiped_member)
//! and moved into one), the backing memory is zeroized on drop, and equality is constant-time
//! (the contract's [`busbar_contract::constant_time_eq`]). Every `expose_own` call site is an
//! audit point where the plaintext escapes on purpose.
//!
//! The owner seal lives here, not in the contract: busbar dev's `busbar_contract::Secret` has no
//! owner parameter and no `own_seal!` (that contract change is not on busbar dev), so the plugin
//! keeps the same shape on its own type, as the fleet's other plugins hold their own credentials.

use core::fmt;
use core::marker::PhantomData;

use zeroize::Zeroize;

/// This crate's own seal over the secrets it holds: constructed only inside this crate.
pub(crate) struct Own(());

impl Own {
    /// The crate's seal: constructed only inside this crate.
    pub(crate) const fn here() -> Self {
        Self(())
    }
}

/// A secret this crate holds itself, readable only under its owner's seal `O`.
pub(crate) struct Secret<T: Zeroize, O = Own>(T, PhantomData<fn() -> O>);

impl<T: Zeroize, O> Secret<T, O> {
    /// Wrap a secret this crate holds itself.
    pub(crate) fn held(secret: T) -> Self {
        Self(secret, PhantomData)
    }

    /// Borrow the secret under its owner's seal. AUDIT POINT: the plaintext escapes here.
    pub(crate) fn expose_own(&self, _seal: &O) -> &T {
        &self.0
    }
}

/// `Debug` NEVER reveals the secret.
impl<T: Zeroize, O> fmt::Debug for Secret<T, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// `Display` NEVER reveals the secret either.
impl<T: Zeroize, O> fmt::Display for Secret<T, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize, O> Drop for Secret<T, O> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone, O> Clone for Secret<T, O> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

/// Constant-time over the held bytes (no early exit on the first differing byte).
impl<T: Zeroize + AsRef<[u8]>, O> PartialEq for Secret<T, O> {
    fn eq(&self, other: &Self) -> bool {
        busbar_contract::constant_time_eq(&self.0, &other.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>, O> Eq for Secret<T, O> {}

#[cfg(test)]
#[path = "tests/held_tests.rs"]
mod tests;
