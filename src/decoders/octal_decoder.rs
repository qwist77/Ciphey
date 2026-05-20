//! Decode octal byte values into text.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Octal decoder.
pub struct OctalDecoder;

impl Crack for Decoder<OctalDecoder> {
    fn new() -> Decoder<OctalDecoder> {
        Decoder {
            name: "octal",
            description: "Octal byte encoding represents text as base-8 character code values.",
            link: "https://en.wikipedia.org/wiki/Octal",
            tags: vec!["octal", "ascii", "decoder"],
            popularity: 0.025,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying octal with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_octal(text) else {
            debug!("Octal decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode octal because check_string_success returned false on string {}",
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

fn decode_octal(text: &str) -> Option<String> {
    // Python returns bytes; the Rust search pipeline can only carry valid UTF-8 strings.
    String::from_utf8(decode_octal_bytes(text)?).ok()
}

fn decode_octal_bytes(text: &str) -> Option<Vec<u8>> {
    let tokens: Vec<&str> = if text.contains(' ') {
        text.split(' ').collect()
    } else {
        if !text.len().is_multiple_of(3) {
            return None;
        }
        text.as_bytes()
            .chunks(3)
            .map(std::str::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .ok()?
    };

    let mut bytes = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.is_empty() || token.len() > 3 {
            return None;
        }
        let value = u16::from_str_radix(token, 8).ok()?;
        if value > 255 {
            return None;
        }
        bytes.push(value as u8);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_concatenated_triplets() {
        assert_eq!(decode_octal("110145154154157"), Some("Hello".to_string()));
    }

    #[test]
    fn decodes_space_separated_values() {
        assert_eq!(
            decode_octal("110 145 154 154 157"),
            Some("Hello".to_string())
        );
    }

    #[test]
    fn rejects_values_outside_byte_range() {
        assert_eq!(decode_octal("777"), None);
    }

    #[test]
    fn keeps_python_byte_parity_for_high_bit_values() {
        assert_eq!(decode_octal_bytes("200"), Some(vec![0x80]));
        assert_eq!(decode_octal("200"), None);
    }

    #[test]
    fn decodes_variable_width_space_separated_octal_values() {
        assert_eq!(decode_octal("41 40 101 12"), Some("! A\n".to_string()));
    }

    #[test]
    fn decodes_utf8_and_rejects_invalid_octal_bytes() {
        assert_eq!(decode_octal("303 251"), Some("é".to_string()));
        assert_eq!(decode_octal("377"), None);
        assert_eq!(decode_octal("128"), None);
    }
}
