// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn main() -> std::io::Result<()> {
    use std::path::PathBuf;
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .canonicalize()?;
    let source = manifest.join("tests/root/door_steps.rs");
    if source.canonicalize()? != source {
        return Err(std::io::Error::other(
            "test source must remain in its owner",
        ));
    }
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("output dir"));
    std::fs::write(output.join("context_test_source.rs"), format!(
        "#[doc(hidden)]\n#[macro_export]\nmacro_rules! __busbar_context_tests {{\n    (door_steps, \"busbar-auth-oauth\") => {{ include!({source:?}); }};\n}}\n"
    ))?;
    println!("cargo::rerun-if-changed={}", source.display());
    println!("cargo::rerun-if-changed=build.rs");
    Ok(())
}
