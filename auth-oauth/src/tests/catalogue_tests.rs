//! The declared diagnostics against the core catalogue the crate is pinned to.

const DECLARES_JSON: &str = include_str!("../../declares.json");

/// NO DECLARED CODE IS ONE THE CORE'S CATALOGUE HOLDS: the core at `.busbar-ref` (`BUSBAR_CHECKOUT`,
/// `crates/busbar-kernel/src/diagnostics/catalog.toml`) refuses a plugin that declares a code its
/// catalogue already holds ("plugin '<name>' declares BUSBAR-NNNN: the catalogue already holds that
/// code"), identical or not, so a collision is a busbar that does not boot. An unset variable is a
/// failure, never a skip.
#[test]
fn no_declared_code_is_one_the_core_catalogue_holds() {
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the core catalogue is busbar's at .busbar-ref (plugin-ci exports it)",
    );
    let path =
        std::path::PathBuf::from(busbar).join("crates/busbar-kernel/src/diagnostics/catalog.toml");
    let catalog = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the core catalogue at {}: {e}", path.display()));
    let held: std::collections::BTreeSet<u64> = catalog
        .lines()
        .filter_map(|l| l.trim().strip_prefix("code"))
        .filter_map(|rest| rest.trim().strip_prefix('='))
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    assert!(
        !held.is_empty(),
        "no `code = N` row read from {}",
        path.display()
    );
    let declares: serde_json::Value = serde_json::from_str(DECLARES_JSON).unwrap();
    for d in declares["diagnostics"].as_array().unwrap() {
        let code = d["code"].as_u64().unwrap();
        assert!(
            !held.contains(&code),
            "BUSBAR-{code:04} ({}) is a code the core catalogue at {} already holds",
            d["slug"],
            path.display()
        );
    }
}

/// EVERY CODE THE PLUGIN RAISES IS DECLARED BY THE PLUGIN OR HELD BY THE CORE CATALOGUE. The
/// Statement's diagnostic ids (`abi_str("BUSBAR-NNNN")` in `src/lib.rs`) are resolved by the host
/// from the full catalogue (`by_code`: the core's entries plus the plugins' declared ones), so a
/// code in neither place would log without its slug, title and action.
#[test]
fn every_raised_code_is_declared_here_or_held_by_the_core_catalogue() {
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the core catalogue is busbar's at .busbar-ref (plugin-ci exports it)",
    );
    let path =
        std::path::PathBuf::from(busbar).join("crates/busbar-kernel/src/diagnostics/catalog.toml");
    let catalog = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the core catalogue at {}: {e}", path.display()));
    let held: std::collections::BTreeSet<u64> = catalog
        .lines()
        .filter_map(|l| l.trim().strip_prefix("code"))
        .filter_map(|rest| rest.trim().strip_prefix('='))
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    let declares: serde_json::Value = serde_json::from_str(DECLARES_JSON).unwrap();
    let declared: std::collections::BTreeSet<u64> = declares["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_u64().unwrap())
        .collect();
    let lib = include_str!("../lib.rs");
    let raised: Vec<u64> = lib
        .split("abi_str(\"BUSBAR-")
        .skip(1)
        .map(|rest| rest[..4].parse().unwrap())
        .collect();
    assert!(
        !raised.is_empty(),
        "no abi_str(\"BUSBAR-NNNN\") id read from src/lib.rs"
    );
    for code in raised {
        assert!(
            declared.contains(&code) || held.contains(&code),
            "BUSBAR-{code:04} is raised but neither declared by the plugin nor held by the core catalogue"
        );
    }
}
