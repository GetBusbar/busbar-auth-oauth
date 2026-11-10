// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Released credential interpretation belongs to the OAuth owner alone.
use busbar_contract::abi::sdk::migrate::{
    CredentialMigration, CredentialRefusal, Migrate, Migrated, MigrationCredential,
};

pub(crate) struct OauthMigration;
impl Migrate for OauthMigration {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    fn migrate(settings: serde_json::Value, _: &str) -> Migrated {
        Migrated::unchanged(settings)
    }
    fn migrate_credential(
        credential: MigrationCredential<'_, Self::Kind>,
        from: &str,
    ) -> Result<CredentialMigration, CredentialRefusal> {
        if from != "1.5.5" {
            return Err(CredentialRefusal);
        }
        // The source resolver already applies historical outer CR/LF trimming.
        // Leading whitespace affects JSON detection only; filenames stay exact.
        if credential.text().trim_start().starts_with('{') {
            return Ok(CredentialMigration::unchanged());
        }
        if credential.text().is_empty() {
            return Err(CredentialRefusal);
        }
        let file = credential.read_file(credential.text())?;
        let text = std::str::from_utf8(file.bytes()).map_err(|_| CredentialRefusal)?;
        if !text.trim_start().starts_with('{')
            || serde_json::from_str::<serde::de::IgnoredAny>(text).is_err()
        {
            return Err(CredentialRefusal);
        }
        Ok(file.accept())
    }
}

#[cfg(test)]
mod tests {
    use busbar_contract::{abi::sdk::migrate::CredentialMigration, redacted::Secret};
    fn convert(value: &str) -> Result<CredentialMigration, String> {
        busbar_plugin_loader::dispatch::migrate::migrate_credential_door(
            busbar_plugin_loader::dispatch::load::raw(crate::door),
            &Secret::new(value.to_owned()),
            "1.5.5",
            &busbar_contract::plugin::TestKernelSeal,
        )
    }
    #[test]
    fn inline_json_keeps_the_original_reference() {
        assert!(convert(" \r\n{\"key\":\"SYNTHETIC\"}")
            .unwrap()
            .into_reference(&Default::default())
            .unwrap()
            .is_none());
    }
    #[test]
    fn verified_filename_preserves_exact_spaces_and_process_cwd() {
        let dir = std::env::temp_dir().join(format!("oauth-migration-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(" key.json ");
        std::fs::write(&file, br#"{"key":"SYNTHETIC"}"#).unwrap();
        // Spell the same file relative to process cwd without changing process-global cwd.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = std::path::PathBuf::new();
        for _ in cwd.components().skip(1) { relative.push(".."); }
        relative.push(file.strip_prefix("/").unwrap());
        let answer = convert(relative.to_str().unwrap()).unwrap();
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
        let reference = answer.into_reference(&sources).unwrap().unwrap();
        assert_eq!(
            reference,
            sources
                .get("artifact")
                .unwrap()
                .reference(file.to_str().unwrap())
        );
        std::fs::write(&file, b"SYNTHETIC_NOT_JSON").unwrap();
        let error = convert(file.to_str().unwrap()).unwrap_err();
        assert!(!error.contains("key.json") && !error.contains("SYNTHETIC"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn missing_files_empty_credentials_and_nonobject_json_refuse_without_values() {
        for value in ["", "SYNTHETIC_MISSING_FILE", "[1,2,3]"] {
            let error = convert(value).unwrap_err();
            assert_eq!(
                error,
                "credential owner could not migrate the original reference"
            );
        }
    }
}
