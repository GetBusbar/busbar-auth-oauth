// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `held.rs`: the redaction marker and the constant-time equality.

use super::Held;

#[test]
fn debug_and_display_print_only_the_redaction_marker() {
    let h = Held::new(String::from("sk-live-plaintext"));
    assert_eq!(format!("{h:?}"), "[REDACTED]");
    assert_eq!(format!("{h}"), "[REDACTED]");
    assert_eq!(format!("{:?}", Some(&h)), "Some([REDACTED])");
    assert_eq!(h.reveal(), "sk-live-plaintext");
}

#[test]
fn equality_compares_the_held_bytes() {
    let a = Held::new(String::from("same"));
    assert_eq!(a, a.clone());
    assert_ne!(a, Held::new(String::from("other")));
    assert_ne!(a, Held::new(String::from("sam")));
}
