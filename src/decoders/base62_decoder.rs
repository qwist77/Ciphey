//! Decode Base62 strings using the same alphabet as Python pybase62.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};
use num::{BigUint, ToPrimitive, Zero};

const BASE62_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Base62 decoder.
pub struct Base62Decoder;

impl Crack for Decoder<Base62Decoder> {
    fn new() -> Decoder<Base62Decoder> {
        Decoder {
            name: "Base62",
            description: "Base62 is a binary-to-text encoding that uses digits, uppercase letters, and lowercase letters.",
            link: "https://pypi.org/project/pybase62/",
            tags: vec!["base62", "decoder", "base"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Base62 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_base62(text) else {
            debug!("Base62 decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode base62 because check_string_success returned false on string {}",
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

fn decode_base62(text: &str) -> Option<String> {
    let mut encoded = text.trim();
    if encoded.is_empty() {
        return None;
    }

    let mut leading_nulls = Vec::new();
    while encoded.starts_with('0') && encoded.len() >= 2 {
        let count_char = encoded.chars().nth(1)?;
        let count = base62_value(count_char)? as usize;
        leading_nulls.extend(std::iter::repeat_n(0, count));
        encoded = &encoded[count_char.len_utf8() + 1..];
    }

    let mut value = BigUint::zero();
    for ch in encoded.chars() {
        value *= 62u8;
        value += base62_value(ch)?;
    }

    let mut decoded = leading_nulls;
    if !value.is_zero() {
        decoded.extend(value.to_bytes_be());
    }
    String::from_utf8(decoded).ok()
}

fn base62_value(ch: char) -> Option<u8> {
    BASE62_ALPHABET
        .chars()
        .position(|candidate| candidate == ch)
        .and_then(|value| value.to_u8())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_pybase62_vector() {
        assert_eq!(
            decode_base62("AAwf93rvy4aWQVw"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn preserves_pybase62_leading_null_marker() {
        assert_eq!(decode_base62("011"), Some("\0\x01".to_string()));
    }

    #[test]
    fn rejects_invalid_character() {
        assert_eq!(decode_base62("not base62!"), None);
    }
}
