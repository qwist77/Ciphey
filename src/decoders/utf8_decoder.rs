//! Decode UTF-8 bytes.

use crate::checkers::CheckerTypes;
use crate::decoders::byte_input::{parse_hex_bytes, parse_hex_escape_bytes};
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
        let Some(bytes) = parse_hex_escape_bytes(text).or_else(|| parse_hex_bytes(text)) else {
            debug!("UTF-8 decoder skipped string input without a byte carrier");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::interface::Crack;

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

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

    #[test]
    fn crack_decodes_hex_byte_carrier() {
        let decoder = Decoder::<Utf8Decoder>::new();
        let result = decoder.crack("48656c6c6f", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "Hello");
    }

    #[test]
    fn does_not_duplicate_base64_string_path() {
        let decoder = Decoder::<Utf8Decoder>::new();
        let result = decoder.crack("aGVsbG8gd29ybGQK", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn decodes_rfc3629_four_byte_sequence() {
        assert_eq!(
            decode_utf8_bytes(&[0xf0, 0x90, 0x8d, 0x88]),
            Some("𐍈".to_string())
        );
    }

    #[test]
    fn decodes_utf8_scalar_upper_boundary() {
        assert_eq!(
            decode_utf8_bytes(&[0xf4, 0x8f, 0xbf, 0xbf]),
            Some("\u{10FFFF}".to_string())
        );
    }

    #[test]
    fn rejects_utf8_invalid_boundaries() {
        assert_eq!(decode_utf8_bytes(&[0xc0, 0xaf]), None);
        assert_eq!(decode_utf8_bytes(&[0xed, 0xa0, 0x80]), None);
        assert_eq!(decode_utf8_bytes(&[0xf4, 0x90, 0x80, 0x80]), None);
    }
}
