// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate root's own constants: what the `fields` door writes, and the diagnostic table's
//! shape (its id strings are read by the plugin crate's conformance test, where reading an
//! `AbiStr`'s bytes is allowed).

use super::*;
use crate::instance::diag;

/// THE FIELD FLAGS ARE NONE (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win). The `fields`
/// door writes the authorization field with `FIELD_FLAGS`; 1.5.5 sent its credential headers
/// indexable, so a sensitive (never-indexed) marking is different bytes. The SDK's `FieldsWriter`
/// cannot be built outside its own door, so the constant the door passes is pinned directly.
#[test]
fn the_authorization_field_is_written_with_no_flags() {
    assert_eq!(
        FIELD_FLAGS, 0,
        "1.5.5 sent credential headers indexable: the flags stay 0 (ARCHITECT ruling Q4)"
    );
}

/// The diagnostic indices are the Statement's table positions, in `DIAG_IDS` order (the plugin
/// crate's conformance test pins which code each position holds).
#[test]
fn the_diag_indices_are_the_table_positions() {
    assert_eq!(DIAG_IDS.len(), 3);
    assert_eq!(diag::OAUTH_TOKEN_INVALID_BYTES, 0);
    assert_eq!(diag::OAUTH_EMPTY_TOKEN, 1);
    assert_eq!(diag::OAUTH_MINT_FAILED, 2);
}
