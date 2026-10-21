// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading an OAuth token endpoint's `expires_in`: the default a response that omits it gets, and
//! the tolerant parse the self-minting styles (JWT bearer, client credentials) read it with. MOVED
//! VERBATIM from the identity unit's `egress_auth/token_response.rs` in the kernel (KERNEL<>PLUGINS step
//! 22); the minting that reads it moved with it, into [`crate::mint`].
//!
//! Beside it, the two secret-hygiene (#53) helpers the minters decode with: [`wiped_member`]
//! reads a secret member of a decoded document (the access token, the service-account key) into a
//! buffer wiped on drop, and [`json_err`] describes a decode failure without the decoder's text,
//! which can quote the secret it was decoding.

use zeroize::Zeroizing;

/// THE TOP-LEVEL STRING MEMBER `name` of `json` (a document the decoder has already judged
/// well-formed), its escapes resolved into ONE buffer sized to the escaped length (unescaping only
/// shortens) and wiped on drop; `None` when that member is not a string.
///
/// A secret member is read here and never by the decoder: `serde_json` unescapes a string that
/// carries an escape into a scratch buffer of its own, which it frees unwiped. The decode names the
/// member `serde::de::IgnoredAny` (skipping copies nothing) and its value is read with this.
pub(crate) fn wiped_member(json: &str, name: &[u8]) -> Option<Zeroizing<String>> {
    unescape(top_level_string(json.as_bytes(), name)?)
}

/// The escaped bytes (between the quotes) of the top-level object member `name` of the
/// well-formed JSON document `json`, when that member is a string.
fn top_level_string<'a>(json: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    let mut depth = 0_usize;
    // At depth 1, whether the next string is a member name (after `{` or `,`).
    let mut expect_name = false;
    let mut want_value = false;
    while i < json.len() {
        match json[i] {
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < json.len() && json[j] != b'"' {
                    j += if json[j] == b'\\' { 2 } else { 1 };
                }
                let s = json.get(start..j)?;
                if depth == 1 && want_value {
                    return Some(s);
                }
                want_value = depth == 1 && expect_name && s == name;
                expect_name = false;
                i = j + 1;
                continue;
            }
            b'{' => {
                depth += 1;
                expect_name = depth == 1;
                want_value = false;
            }
            b'[' => {
                depth += 1;
                want_value = false;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' => {
                expect_name = depth == 1;
                want_value = false;
            }
            b':' => {}
            b if b.is_ascii_whitespace() => {}
            // A value that is no string ends a pending match.
            _ => want_value = false,
        }
        i += 1;
    }
    None
}

/// JSON string escapes resolved (RFC 8259 section 7), into a buffer sized once to the escaped
/// length; `None` for an escape the decoder would have refused.
fn unescape(raw: &[u8]) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(raw.len()));
    let mut i = 0;
    let hex4 = |at: usize| -> Option<u32> {
        let h = raw.get(at..at + 4)?;
        u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()
    };
    while i < raw.len() {
        if raw[i] != b'\\' {
            // Copy the run of plain bytes up to the next escape (UTF-8 as the decoder judged it).
            let end = raw[i..]
                .iter()
                .position(|b| *b == b'\\')
                .map_or(raw.len(), |p| i + p);
            out.push_str(std::str::from_utf8(&raw[i..end]).ok()?);
            i = end;
            continue;
        }
        let c = match *raw.get(i + 1)? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = hex4(i + 2)?;
                if (0xD800..0xDC00).contains(&hi) && raw.get(i + 6..i + 8) == Some(&b"\\u"[..]) {
                    let lo = hex4(i + 8)?;
                    i += 6;
                    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo.checked_sub(0xDC00)?))?
                } else {
                    char::from_u32(hi)?
                }
            }
            _ => return None,
        };
        i += if raw[i + 1] == b'u' { 6 } else { 2 };
        out.push(c);
    }
    Some(out)
}

/// The `map_err` for a `serde_json` decode whose INPUT may carry a secret: a service-account key or
/// a token response. `serde_json::Error`'s own `Display` is withheld: a data error quotes the
/// offending value (`invalid type: string "<the value>"`), which here can be the secret itself, and
/// these messages reach `--validate` output, read-scope admin callers and logs. What survives is
/// `what` failed, the CLASS of failure and WHERE (secret-hygiene #53, Check 3: redact at the format
/// site). The one decoder text kept verbatim is a MISSING FIELD: serde spells it from the type's own
/// schema (``missing field `private_key` ``), never from the input.
pub fn json_err(what: &'static str) -> impl FnOnce(serde_json::Error) -> String {
    move |e: serde_json::Error| {
        if e.is_data() && e.to_string().starts_with("missing field `") {
            return format!("{what}: {e}");
        }
        let class = match e.classify() {
            serde_json::error::Category::Io => "the input could not be read",
            serde_json::error::Category::Syntax => "it is not well-formed JSON",
            serde_json::error::Category::Data => "a field is missing or has the wrong type",
            serde_json::error::Category::Eof => "it ends before the JSON does",
        };
        let (line, column) = (e.line(), e.column());
        format!("{what}: {class} (line {line}, column {column}; the decoder's text is withheld)")
    }
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
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        // Order matters for `untagged`: an integer matches `Num` first; `Float` only catches a
        // non-integer JSON number; `Str` catches a quoted value.
        Num(u64),
        Float(f64),
        Str(String),
    }
    fn float_to_secs<E: serde::de::Error>(f: f64) -> Result<u64, E> {
        if f.is_finite() && f >= 0.0 {
            Ok(f as u64)
        } else {
            Err(E::custom(format!(
                "expires_in must be a non-negative number, got {f}"
            )))
        }
    }
    match NumOrStr::deserialize(d)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Float(f) => float_to_secs(f),
        NumOrStr::Str(s) => {
            let t = s.trim();
            if let Ok(n) = t.parse::<u64>() {
                Ok(n)
            } else if let Ok(f) = t.parse::<f64>() {
                float_to_secs(f)
            } else {
                Err(serde::de::Error::custom(format!(
                    "expires_in {s:?} is not a number"
                )))
            }
        }
    }
}
