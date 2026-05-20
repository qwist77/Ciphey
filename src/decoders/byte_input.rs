//! Helpers for decoders that need byte input in the string-only Rust pipeline.

use base64::{engine::general_purpose, Engine as _};

/// Parse common textual byte carriers into bytes.
pub fn parse_textual_bytes(text: &str) -> Option<Vec<u8>> {
    parse_hex_escape_bytes(text)
        .or_else(|| parse_hex_bytes(text))
        .or_else(|| parse_base64_bytes(text))
}

/// Parse `\xHH` byte escape strings.
pub fn parse_hex_escape_bytes(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut rest = text;
    while let Some(stripped) = rest.strip_prefix("\\x") {
        if stripped.len() < 2 {
            return None;
        }
        let (hex, remaining) = stripped.split_at(2);
        bytes.push(u8::from_str_radix(hex, 16).ok()?);
        rest = remaining;
    }
    if rest.is_empty() && !bytes.is_empty() {
        Some(bytes)
    } else {
        None
    }
}

/// Parse contiguous hexadecimal bytes after removing whitespace.
pub fn parse_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    if cleaned.is_empty()
        || cleaned.len() % 2 != 0
        || !cleaned.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }
    cleaned
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(hex, 16).ok()
        })
        .collect()
}

/// Parse standard or URL-safe Base64 bytes after removing whitespace.
pub fn parse_base64_bytes(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }

    let mut padded = cleaned.clone();
    let padding = padded.len() % 4;
    if padding == 1 {
        return None;
    }
    if padding != 0 {
        padded.extend(std::iter::repeat('=').take(4 - padding));
    }

    [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|engine| {
        engine
            .decode(cleaned.as_bytes())
            .or_else(|_| engine.decode(padded.as_bytes()))
            .ok()
    })
}
