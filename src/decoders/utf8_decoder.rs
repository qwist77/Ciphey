//! Decode UTF-8 bytes.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// UTF-8 decoder.
pub struct Utf8Decoder;

impl Crack for Decoder<Utf8Decoder> {
    fn new() -> Decoder<Utf8Decoder> {
        Decoder {
            name: "utf8",
            description: "UTF-8 is a variable-width Unicode character encoding.",
            link: "https://en.wikipedia.org/wiki/UTF-8",
            tags: vec!["utf8", "unicode", "decoder"],
            popularity: 0.9,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying UTF-8 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(bytes) = parse_hex_escape_bytes(text) else {
            debug!("UTF-8 decoder skipped string input without escaped bytes");
            return results;
        };
        let Some(decoded_text) = decode_utf8_bytes(&bytes) else {
            debug!("UTF-8 decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode utf8 because check_string_success returned false on string {}",
                decoded_text
            );
            return results;
        }

        let checker_result = checker.check(&decoded_text);
        results.unencrypted_text = Some(vec![decoded_text]);
        results.update_checker(&checker_result);
        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }

    fn get_name(&self) -> &str {
        self.name
    }

    fn get_popularity(&self) -> f32 {
        self.popularity
    }

    fn get_description(&self) -> &str {
        self.description
    }

    fn get_link(&self) -> &str {
        self.link
    }
}

fn decode_utf8_bytes(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

fn parse_hex_escape_bytes(text: &str) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf8_bytes() {
        assert_eq!(decode_utf8_bytes(b"Hello"), Some("Hello".to_string()));
    }

    #[test]
    fn rejects_invalid_utf8_bytes() {
        assert_eq!(decode_utf8_bytes(&[0xff]), None);
    }

    #[test]
    fn parses_hex_escape_input_for_string_pipeline() {
        assert_eq!(
            parse_hex_escape_bytes("\\x48\\x65\\x6c\\x6c\\x6f"),
            Some(b"Hello".to_vec())
        );
    }
}
