// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `held.rs`: a credential this plugin holds is the contract's `Secret`, owned by this
//! crate's seal — redacted, constant-time equal, and readable under `Own` only.

use super::Own;
use super::Secret;

#[test]
fn debug_and_display_print_only_the_redaction_marker() {
    let h: Secret<String, Own> = Secret::held(String::from("sk-live-plaintext"));
    assert_eq!(format!("{h:?}"), "[REDACTED]");
    assert_eq!(format!("{h}"), "[REDACTED]");
    assert_eq!(format!("{:?}", Some(&h)), "Some([REDACTED])");
    assert_eq!(h.expose_own(&Own::here()), "sk-live-plaintext");
}

#[test]
fn equality_compares_the_held_bytes() {
    let a: Secret<String, Own> = Secret::held(String::from("same"));
    assert_eq!(a, a.clone());
    assert_ne!(a, Secret::held(String::from("other")));
    assert_ne!(a, Secret::held(String::from("sam")));
}
