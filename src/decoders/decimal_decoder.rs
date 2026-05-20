//! Decode decimal byte values into text.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Decimal decoder.
pub struct DecimalDecoder;

impl Crack for Decoder<DecimalDecoder> {
    fn new() -> Decoder<DecimalDecoder> {
        Decoder {
            name: "decimal",
            description: "Decimal byte encoding represents text as base-10 character code values.",
            link: "https://en.wikipedia.org/wiki/ASCII",
            tags: vec!["decimal", "ascii", "decoder"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying decimal with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_decimal(text) else {
            debug!("Decimal decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode decimal because check_string_success returned false on string {}",
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

fn decode_decimal(text: &str) -> Option<String> {
    let digits_only: String = text
        .chars()
        .filter(|ch| !matches!(ch, ',' | ';' | ':' | '-' | '\n') && !ch.is_whitespace())
        .collect();
    if digits_only.is_empty() || !digits_only.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let mut decoded = String::new();
    for token in text.split(|ch| matches!(ch, ' ' | ',' | ';' | ':' | '-' | '\n')) {
        let value: u32 = token.parse().ok()?;
        if value > 255 {
            return None;
        }
        decoded.push(char::from_u32(value)?);
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_decimal_values() {
        assert_eq!(
            decode_decimal("72 101 108 108 111"),
            Some("Hello".to_string())
        );
    }

    #[test]
    fn rejects_out_of_byte_range() {
        assert_eq!(decode_decimal("256"), None);
    }

    #[test]
    fn rejects_consecutive_delimiters_like_python() {
        assert_eq!(decode_decimal("72,,101"), None);
    }
}
