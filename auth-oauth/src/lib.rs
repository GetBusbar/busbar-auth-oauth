// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `oauth` auth for busbar: its logic and its door.
//!
//! One door, two ways in: a busbar build that links this crate names the door here; the sibling
//! `busbar-auth-oauth-plugin` cdylib exports the same door as its image's one symbol (`export_door!`). This crate
//! exports nothing. Write the door with the `auth` kind's SDK in `busbar_contract::abi::sdk`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
