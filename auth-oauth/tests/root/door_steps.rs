// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// Compiled in the host door_steps test scope; this owner supplies the actual grant cases.
fn presented(answer: Option<&busbar_contract::auth_calls::Fields>) -> Option<String> {
    match answer? {
        busbar_contract::auth_calls::Fields::Ready(fields) => fields.iter().find_map(|f| {
            (f.name == b"authorization").then(|| {
                String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend())).into_owned()
            })
        }),
        _ => None,
    }
}

fn linked_mint_plugin(table: &std::sync::Arc<TokenEndpoint>) -> super::OutboundAuths {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::with_services(
        crate::root::loader::dispatch::DispatchConfig::default(),
        crate::root::serve::LateServices::new().served(),
        busbar_kernel::host_services::caller_binding(),
    ));
    assert!(
        dispatcher.host_services().is_some(),
        "the plugin's clock is the host's: a dispatcher serving no host services answers no \
         `clock.now`"
    );
    crate::root::connector::install_io(&dispatcher);

    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());

    let name = "busbar-auth-oauth";
    let linked: [busbar_kernel::preflight::LinkedAuth; 1] = [(name, name, busbar_auth_oauth::door)];
    super::OutboundAuths::new(
        dispatcher,
        &linked,
        None,
        crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(
            std::sync::Arc::clone(table)
                as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>,
        )),
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_an_oauth_grant_presents_its_minted_then_refreshed_bearer() {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_PROVIDER};
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
    let basic = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
        )
    };

    for written in [
        TOKEN_URL.to_string(),
        TOKEN_URL.replacen("://", "://svcuser:hunter2-P4ss@", 1),
    ] {
        let key_file =
            std::env::temp_dir().join(format!("busbar-door-steps-oauth-{}", std::process::id()));
        std::fs::write(&key_file, "oracle-client-0001:oracle:secret:with:colons").expect("key");
        let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
            "p".to_string(),
            super::ProviderRoute {
                base_url: "http://127.0.0.1:9".to_string(),
                userinfo: None,
                protocol: "d".to_string(),
                error_map: Default::default(),
                credential: source_path(key_file.display().to_string()),
                style: Some("oauth-client-credentials".to_string()),
                params: super::StyleParams {
                    token_url: Some(written.clone()),
                    scope: Some("https://cognitiveservices.azure.com/.default".to_string()),
                    ..super::StyleParams::default()
                },
                metadata: busbar_kernel::config_validate::MetadataPosture::default(),
            },
        )]
        .into();
        let table = std::sync::Arc::new(TokenEndpoint::secure());
        let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
            std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
        let reach = super::DoorReach {
            providers: &providers,
            secrets: std::sync::Arc::clone(&secrets),
            auths: std::sync::Arc::new(linked_mint_plugin(&table)),
            conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
            stream_ceiling_secs: 1,
            catalog: None,
            models: None,
            upgrades: Vec::new(),
        };
        let section: serde_yaml::Value =
            serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
        let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
            need_auths: vec![(DIRECTION_OUTBOUND, "oauth-client-credentials")],
            dialects: vec!["d"],
            ..Default::default()
        };
        let routes = super::member_routes(
            &section,
            &DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools"),
            &facts,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("the member resolves");
        let _ = std::fs::remove_file(&key_file);
        let binding = routes["m"].auth.clone().expect("its credential is bound");
        assert!(
            table.declared.lock().unwrap().contains(&(
                0,
                EGRESS_PROVIDER,
                Some(TOKEN_URL.to_string())
            )),
            "the plugin's provider-class need (security item 3, busbar-auth-oauth #43: a private \
             token endpoint refused unless allowlisted), pinned to the provider's token_url: {:?}",
            table.declared.lock().unwrap()
        );

        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);
        let first = tokio::time::timeout(HANG_GUARD, async {
            table.closed(1).await;
            loop {
                let now = binding
                    .auth
                    .fields_now(binding.handle, &FieldsRequest::default());
                match presented(now.as_ref()).as_deref() {
                    Some("Bearer oracle-minted-1") => return,
                    None => {}
                    other => panic!("only the first minted bearer, or none yet: {other:?}"),
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(first.is_ok(), "the first minted bearer is presented");

        let refreshed = tokio::time::timeout(HANG_GUARD, async {
            table.closed(2).await;
            loop {
                let now = binding
                    .auth
                    .fields_now(binding.handle, &FieldsRequest::default());
                if presented(now.as_ref()).as_deref() == Some("Bearer oracle-minted-2") {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(refreshed.is_ok(), "the refreshed bearer is presented");
        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
        assert!(opened.iter().all(|(need, target, words, _)| *need == 0
            && target == TOKEN_URL
            && words == b"/tenant/oauth2/v2.0/token"));
        assert_eq!(
            opened[1].3,
            "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
             oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
        );
        drop(opened);

        let fields = table.fields.lock().unwrap();
        assert_eq!(fields.len(), 2);
        for head in fields.iter() {
            let lead = head.first().map(|(n, v)| (n.as_str(), v.as_slice()));
            if written == TOKEN_URL {
                assert!(
                    !head
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case("authorization")),
                    "a plain endpoint's mint presents no authorization: {head:?}"
                );
            } else {
                assert_eq!(lead, Some(("authorization", basic.as_bytes())), "{head:?}");
            }
            assert!(
                head.iter()
                    .all(|(_, v)| !String::from_utf8_lossy(v).contains("hunter2")),
                "the userinfo rides only as its Basic value: {head:?}"
            );
        }
    }
}

const TEST_SA_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu2RTBghXyuvqd\n\
v/4AIq1NcPzdRUCr0wyjEH35avOM9vSW+fuira0UtCQcyTHJZswoJqgwcdO2SRav\n\
/QMZhnjB/sCzuvHrbILd/T0nK19Fdld/wKMQlQlqz94OpS5b0J/nEc7/IOTxszbq\n\
4B2geG7lJc5wm3dMjKwr7IPbnWs5fMEVyZFaFsctrejOTURx8duff8eM2L+Lf5No\n\
H2k0h+6blyDTq1Iu+9UM5/AfycgvdhPlcKCL1VZq9+YY5zW5GuXj997TnEWEeiam\n\
ZfaHklhdSX3zzSUkShqayzaxX6YRdlUvE6yEIkjq/AVRVrMZDynyD7J0nsyjykhx\n\
WVh79c5fAgMBAAECggEALHaz2onUPwfhl6AtXadz3s+u3i4wRgHDouwcvQK/sMdU\n\
Z9hmb3YvH6a30EIx0P+9RzCdcMRhjGeFx3dWBHW3282G/624u5+6n+04Ue+rqKRx\n\
l+FLFnpwDKOT2rGS2nJxV3el5iddUUG743rezeISgV9d4jEG44aaegkJdx3PGKz/\n\
E76BIyi9H4oUgiqIyPW2trPEeg5n/1oVMHLGDBhotuM7VPUCegh/J3e1jSxcYvi8\n\
0CutgOLynZAS1xSatbbp8nWrUSRHOUYrgE9OYbS7TSgGz1PjzdcmLEsHEGcor0wm\n\
cT4oePDjZmuxICFBSg96Ffb82t6UGXC7xLQbglsfQQKBgQDlBOBtVQafWVJiEj83\n\
fG2YfKTMx1neGO/6ftBMn7XUt4D/AbL0Kx0/Z5lfxm2cixlxcGWT6e96CmZmEsyA\n\
RFSyuG/bvbTF1c0vaKXcjghtPH5TaB6MjgP3VmjOHR5V5o3JMQX0Xayxf/kBP//f\n\
wfolsPUM5hcB7pMjVDQz0OZacQKBgQDDcm0i42UA1wrh4XUTNAbVHfacTm/zBhVB\n\
zvtEC3WGkBCRdU9JSwFAJitPmxrVS3+w2fxO47IiSngeQEyC2neew/H5FrWSNs+L\n\
xV9Jystubq6oTCulEGBP4gb99FkDY2RToNYOjVrEQDsmiijv3CeZyHnes0/8uMQq\n\
5ekEveH9zwKBgBZvR9zt+1wYz+0zhGXXFpVdgHde//q1zqxnR9h5vMI9x7EzZWht\n\
4MuZRnkPYyV2quNl801uGTuHUUimhsn556IqVyrbhp3qt9LxGW5lq4Wn62gYRwXV\n\
06WjHVkzmQkpMLKIzuCFXKl2s9nffx1YTzzp/Ndqos5ZpKhNU1/QEwDBAoGAfVvA\n\
WldFqmNDbJwCTp3ZIAqG6bx5m4O0ULBkg0FiUTvIFLQMdbMxCycwMnAGpvY04Yb/\n\
iM4MrGfdYXHWYTuk6+U8J4sETNLxDfI7awYysxM03Wd1uvqk+7e6ylpWWZD/gZAw\n\
m8bYh/W2usJ0/VvU3pMyb7/NNwh/chBjBBKSiAsCgYEAsTCMDD6CYdncyFWMtWpK\n\
vaTrTko3xPDigybk5520jK5UkEaZr0meRn1CFYFAnfUs0sKB4EbWkcmkZOayPPtQ\n\
su3l06s8o+WrP8Bp2GikIg+jVz9sdz9Vph0Vr0VOPwdBKbWUT4As0r6Muceq+sH6\n\
oy3z0wnL4GXkIelYmU1zCk0=\n\
-----END PRIVATE KEY-----\n";

fn jwt_bearer_routes(
    token_uri: &str,
    metadata: busbar_kernel::config_validate::MetadataPosture,
    table: &std::sync::Arc<TokenEndpoint>,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": TEST_SA_KEY_PEM,
        "token_uri": token_uri,
    });
    let key_file = std::env::temp_dir().join(format!(
        "busbar-door-steps-jwt-{}-{}",
        std::process::id(),
        token_uri.len()
    ));
    std::fs::write(&key_file, sa.to_string()).expect("key");
    let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
        "p".to_string(),
        super::ProviderRoute {
            base_url: "http://127.0.0.1:9".to_string(),
            userinfo: None,
            protocol: "d".to_string(),
            error_map: Default::default(),
            credential: source_path(key_file.display().to_string()),
            style: Some("jwt-bearer".to_string()),
            params: super::StyleParams::default(),
            metadata,
        },
    )]
    .into();
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
        auths: std::sync::Arc::new(linked_mint_plugin(table)),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let section: serde_yaml::Value =
        serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "jwt-bearer")],
        dialects: vec!["d"],
        ..Default::default()
    };
    let routes = super::member_routes(
        &section,
        &DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools"),
        &facts,
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    );
    let _ = std::fs::remove_file(&key_file);
    routes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_jwt_bearer_mints_at_its_service_accounts_token_uri() {
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URI: &str = "https://oauth2.example.com/token";
    let table = std::sync::Arc::new(TokenEndpoint::secure());
    let routes = jwt_bearer_routes(
        TOKEN_URI,
        busbar_kernel::config_validate::MetadataPosture::default(),
        &table,
    )
    .expect("the member resolves");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, target)| target.as_deref() == Some(TOKEN_URI)),
        "the plugin's mint need, pinned to the service account's token_uri: {:?}",
        table.declared.lock().unwrap()
    );

    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).is_some_and(|a| a.starts_with("Bearer oracle-minted-")) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        minted.is_ok(),
        "a bearer minted at the token_uri is presented"
    );
    let opened = table.opened.lock().unwrap();
    let (_, target, words, body) = &opened[0];
    assert_eq!(target, TOKEN_URI);
    assert_eq!(words, b"/token");
    assert!(
        body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ),
        "1.5.5's RFC 7523 form: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_account_token_uri_userinfo_rides_the_mint_as_1_5_5_sent_it() {
    use base64::Engine as _;
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URI: &str = "https://oauth2.example.com/token";
    let written = TOKEN_URI.replacen("://", "://svcuser:hunter2-P4ss@", 1);
    let table = std::sync::Arc::new(TokenEndpoint::secure());
    let routes = jwt_bearer_routes(
        &written,
        busbar_kernel::config_validate::MetadataPosture::default(),
        &table,
    )
    .expect("a token_uri spelling a userinfo seals, as 1.5.5 accepted it");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, target)| target.as_deref() == Some(TOKEN_URI)),
        "the mint need is pinned to the stripped endpoint: {:?}",
        table.declared.lock().unwrap()
    );
    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).is_some_and(|a| a.starts_with("Bearer oracle-minted-")) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(minted.is_ok(), "a bearer minted at the stripped endpoint");
    assert_eq!(table.opened.lock().unwrap()[0].1, TOKEN_URI);
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
    );
    let fields = table.fields.lock().unwrap();
    let head = &fields[0];
    assert_eq!(
        head.first().map(|(n, v)| (n.as_str(), v.as_slice())),
        Some(("authorization", basic.as_bytes())),
        "{head:?}"
    );
    assert!(
        head.iter()
            .all(|(_, v)| !String::from_utf8_lossy(v).contains("hunter2")),
        "{head:?}"
    );
    drop(fields);

    let route = &routes["m"];
    assert!(
        !route.base_url.contains("svcuser")
            && route
                .spelled
                .iter()
                .all(|(_, url)| !url.contains("svcuser")),
        "the member's route carries no userinfo"
    );
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, target)| !matches!(target, Some(t) if t.contains("svcuser"))),
        "no declared need carries the userinfo: {:?}",
        table.declared.lock().unwrap()
    );

    let body = table.opened.lock().unwrap()[0].3.clone();
    let assertion = body
        .split('&')
        .find_map(|pair| pair.strip_prefix("assertion="))
        .expect("the RFC 7523 form carries the assertion");
    let claims = assertion.split('.').nth(1).expect("a compact JWT");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims"),
    )
    .expect("JSON claims");
    assert_eq!(
        claims["aud"],
        written.as_str(),
        "the aud is the raw token_uri, as 1.5.5 signed it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_account_token_uri_is_judged_at_the_seal_in_1_5_5s_words() {
    use busbar_kernel::config_validate::MetadataPosture;
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let Err(plaintext) = jwt_bearer_routes(
        "http://oauth2.example.com/token",
        MetadataPosture::default(),
        &table,
    ) else {
        panic!("plaintext to a public host is refused");
    };
    assert_eq!(
        plaintext,
        "provider 'p' (jwt-bearer auth): service-account token_uri must use https for a public \
         host (got 'http://oauth2.example.com/token'); it receives the signed JWT assertion, so \
         plaintext http is permitted only for a private/loopback endpoint"
    );
    let Err(metadata) = jwt_bearer_routes(
        "https://169.254.169.254/token",
        MetadataPosture::default(),
        &table,
    ) else {
        panic!("a metadata host is refused");
    };
    assert!(
        metadata.starts_with(
            "provider 'p' (jwt-bearer auth): service-account token_uri \
             'https://169.254.169.254/token' targets a blocked cloud-metadata host"
        ),
        "{metadata}"
    );
    let allowed = MetadataPosture {
        allow_overrides: vec!["169.254.169.254".to_string()],
        ..MetadataPosture::default()
    };
    assert!(
        jwt_bearer_routes("https://169.254.169.254/token", allowed, &table).is_ok(),
        "the provider's allow-override carves the host back out"
    );
}

#[test]
fn oauth_settings_validate_before_open_with_no_credential_or_host_secrets() {
    use crate::root::loader::dispatch::{
        auth_outbound::check_settings, kinds::auth::Auth, load_linked, Bind, ConnTable,
        DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    );
    let row = LinkedRow::of(busbar_auth_oauth::door).expect("OAuth declaration");
    let plugin = load_linked::<Auth>(
        &row,
        Bind {
            instance: std::sync::Arc::from("pure-settings-check"),
            max_inflight_cap: 1,
            sink: std::sync::Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .expect("bind without OPEN");
    assert!(!plugin.is_open());
    check_settings(
        &plugin,
        "oauth-client-credentials",
        br#"{"token_url":"https://unreachable.invalid/token"}"#,
    )
    .expect("pure valid settings need no credential");
    let bad = check_settings(
        &plugin,
        "oauth-client-credentials",
        br#"{"token_url":"http://login.example.com/token"}"#,
    )
    .expect_err("known plaintext token endpoint is refused before resolving a credential");
    assert!(bad.contains("must use https"), "{bad}");
    let missing = check_settings(&plugin, "oauth-client-credentials", b"{}").unwrap_err();
    assert!(missing.contains("no `token_url`"), "{missing}");
    assert!(
        !plugin.is_open(),
        "validation never opens the auth instance"
    );
}
