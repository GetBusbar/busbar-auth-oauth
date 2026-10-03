// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `oauth` auth as a droppable busbar plugin: the `cdylib` a signed tarball carries
//! (`kind: auth`, key `oauth`). It re-exports the logic crate and exports that crate's door
//! as this image's ONE symbol, `busbar_plugin_door`, with `busbar_contract::export_door!` once the
//! door exists, so the library carries exactly the door a busbar build links.

#![deny(unsafe_code)]

pub use busbar_auth_oauth::*;
