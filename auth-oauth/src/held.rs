// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Own`] — THIS PLUGIN'S OWN SEAL over the credentials it holds in its own memory: the
//! `client_secret`, the service-account private key, the RFC 8693 subject token, the minted access
//! token, and the token request body that carries one of them.
//!
//! They are the contract's `Secret<T>` (BUSBAR-1.6.0.md Part 2 #54: "secret material is `Secret<T>`;
//! raw access only via the sealed accessor"), owned by this crate: `Secret<T, Own>`, wrapped with
//! `Secret::held` and read with `Secret::expose_own(&Own::here())`. No other crate can name or
//! construct `Own`, so no other crate can read them. The contract keeps the hygiene for every
//! owner: `Debug`/`Display` print `"[REDACTED]"`, nothing serializes (a secret field of a decoded
//! document lands in one through [`deserialize_held`](crate::token_response::deserialize_held)),
//! the backing memory is zeroized on drop, and equality is constant-time. Every `expose_own` call
//! site is an audit point where the plaintext escapes on purpose.

busbar_contract::own_seal!(Own);

#[cfg(test)]
#[path = "tests/held_tests.rs"]
mod tests;
