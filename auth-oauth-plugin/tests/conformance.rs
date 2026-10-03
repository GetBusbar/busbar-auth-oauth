// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOTH-WAYS CONFORMANCE of `busbar-auth-oauth`, owned by this repo and run by the fleet harness on every
//! push. It loads the LINKED door (the logic crate's) and the BUILT cdylib (`busbar-auth-oauth-plugin`) through
//! busbar's real plugin loader at the pin, drives both with one script and requires one transcript
//! (the test named `the_linked_and_the_dropped_in_*`). At least one more test in this target is a
//! RED arm: it proves the comparison can fail (a door asked for as another kind is refused both
//! ways, or a door that answered differently would be seen). The harness is red while either arm is
//! missing. busbar-transport-tcp's `transport-tcp-plugin/tests/conformance.rs` is the exemplar.
