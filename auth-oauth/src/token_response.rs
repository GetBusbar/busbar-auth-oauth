// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Provider-specific OAuth expiry decoding, and selected strings read by the shared SDK.

use zeroize::Zeroizing;

/// Read a selected top-level string through the SDK's guarded decoder. Duplicate selected
/// members are refused; unrelated values are validated without retaining their strings.
pub(crate) fn wiped_member(json: &str, name: &[u8]) -> Option<Zeroizing<String>> {
    let name = std::str::from_utf8(name).ok()?;
    let [value] =
        busbar_contract::abi::sdk::cred::json_text_members(json.as_bytes(), [name]).ok()?;
    value
}

/// Default token TTL when a token endpoint omits `expires_in` (RFC 6749 section 5.1 makes it
/// RECOMMENDED, not required): a conservative 1 h so the token still refreshes on schedule.
pub fn default_expires_in() -> u64 {
    3600
}

/// Deserialize an OAuth `expires_in` TOLERANTLY. RFC 6749 specifies a number of seconds, but real IdPs
/// vary — some emit it as a JSON STRING (`"3600"`), and some omit it (handled by
/// `#[serde(default = "default_expires_in")]` on the field). A strict `u64` field breaks token minting
/// for those providers, silently downing the lane. Accept an integer, a JSON float/decimal
/// (`3600.0` / `"3600.5"`, truncated toward zero — a fractional second on a token TTL is noise), or a
/// numeric string. A negative or non-finite value is rejected.
pub fn deserialize_expires_in<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    // `arbitrary_precision` represents JSON decimals using a private Serde map. An untagged
    // u64/f64/string enum therefore rejects decimals when another workspace dependency enables
    // that feature. Read the original JSON scalar instead; object lookalikes remain invalid.
    let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
    let string;
    let text = if raw.get().starts_with('"') {
        string = serde_json::from_str::<String>(raw.get()).map_err(serde::de::Error::custom)?;
        string.trim()
    } else {
        raw.get()
    };
    fn float_to_secs<E: serde::de::Error>(f: f64) -> Result<u64, E> {
        if f.is_finite() && f >= 0.0 {
            Ok(f as u64)
        } else {
            Err(E::custom(format!(
                "expires_in must be a non-negative number, got {f}"
            )))
        }
    }
    // Parse integers first so values above f64's exact-integer range keep every second.
    if let Ok(n) = text.parse::<u64>() {
        Ok(n)
    } else if let Ok(f) = text.parse::<f64>() {
        float_to_secs(f)
    } else {
        Err(serde::de::Error::custom(
            "expires_in must be a non-negative number or numeric string",
        ))
    }
}
