// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The same guarded credential migration over linked and loaded auth doors.
use busbar_contract::{abi::sdk::migrate::MigratedCredential, Secret};
use busbar_plugin_loader::dispatch::{
    load::raw,
    migrate::{migrate_credential_door, migrate_credential_library},
};

#[test]
fn linked_and_loaded_owners_keep_inline_json_and_verify_exact_filenames() {
    let image =
        std::fs::read(std::env::var_os("BUSBAR_PLUGIN_CDYLIB").expect("fresh plugin image"))
            .unwrap();
    let dir = std::env::temp_dir().join(format!("oauth-migration-door-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(" key.json ");
    let mut sources = busbar_contract::secret_ref::Sugars::default();
    use busbar_contract::abi::mechanism::door::{
        REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_PATH,
    };
    sources
        .declare(
            "artifact-owner",
            &[
                (REWRITE_SUGAR, "artifact".into(), "path".into()),
                (
                    REWRITE_SUGAR_ROLE,
                    "artifact".into(),
                    SUGAR_ROLE_PATH.into(),
                ),
            ],
        )
        .unwrap();
    for loaded in [false, true] {
        let convert = |value: &str| -> Result<MigratedCredential, String> {
            let credential = Secret::new(value.to_owned());
            if loaded {
                migrate_credential_library(
                    &image,
                    "oauth",
                    &credential,
                    "1.5.5",
                    &busbar_contract::plugin::TestKernelSeal,
                )
            } else {
                migrate_credential_door(
                    raw(busbar_auth_oauth::door),
                    &credential,
                    "1.5.5",
                    &busbar_contract::plugin::TestKernelSeal,
                )
            }
        };
        assert!(convert(" {\"key\":\"SYNTHETIC\"}")
            .unwrap()
            .into_reference(&sources)
            .unwrap()
            .is_none());
        std::fs::write(&file, br#"{"key":"SYNTHETIC"}"#).unwrap();
        assert_eq!(
            convert(file.to_str().unwrap())
                .unwrap()
                .into_reference(&sources)
                .unwrap()
                .unwrap(),
            sources
                .get("artifact")
                .unwrap()
                .reference(file.to_str().unwrap())
        );
        std::fs::write(&file, b"SYNTHETIC_NOT_JSON").unwrap();
        let error = convert(file.to_str().unwrap()).unwrap_err();
        assert_eq!(
            error,
            "credential owner could not migrate the original reference"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
