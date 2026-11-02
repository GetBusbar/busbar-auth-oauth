// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `oauth` auth as a droppable busbar plugin: the `cdylib` a signed tarball carries

#![deny(unsafe_code)]

pub use busbar_auth_oauth::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_oauth::door);
}
