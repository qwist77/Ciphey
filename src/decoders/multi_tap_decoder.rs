//! Decode multi-tap phone keypad text.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Multi-tap phone keypad decoder.
pub struct MultiTapDecoder;

impl Crack for Decoder<MultiTapDecoder> {
    fn new() -> Decoder<MultiTapDecoder> {
        Decoder {
            name: "multi_tap",
            description: "Multi-tap is a phone keypad text entry encoding.",
            link: "https://en.wikipedia.org/wiki/Multi-tap",
            tags: vec!["multi_tap", "phone", "decoder"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying multi-tap with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_multi_tap(text) else {
            debug!("Multi-tap decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode multi-tap because check_string_success returned false on string {}",
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

fn decode_multi_tap(text: &str) -> Option<String> {
    let mut result = String::new();
    for token in text.split_whitespace() {
        if token == "0" {
            result.push(' ');
        } else if !valid_code_part(token) {
            return None;
        } else {
            result.push(decode_num_to_char(token)?);
        }
    }
    Some(result)
}

fn valid_code_part(code: &str) -> bool {
    if code.is_empty() || !code.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let mut chars = code.chars();
    let first = chars.next().expect("checked non-empty");
    chars.all(|ch| ch == first) && ('2'..='9').contains(&first) && code.len() <= 4
}

fn decode_num_to_char(number: &str) -> Option<char> {
    let first_digit = number.chars().next()?.to_digit(10)? as usize;
    let mut index = if first_digit >= 8 { 1 } else { 0 };
    index += (first_digit - 2) * 3;
    index += number.len() - 1;
    char::from_u32(u32::from(b'A') + index as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_multi_tap() {
        assert_eq!(
            decode_multi_tap("44 33 555 555 666 0 9 666 777 555 3"),
            Some("HELLO WORLD".to_string())
        );
    }

    #[test]
    fn preserves_python_four_press_quirk() {
        assert_eq!(decode_multi_tap("2222 6666"), Some("DP".to_string()));
    }

    #[test]
    fn rejects_mixed_digit_token() {
        assert_eq!(decode_multi_tap("23"), None);
    }

    #[test]
    fn empty_input_matches_python_helper() {
        assert_eq!(decode_multi_tap(""), Some(String::new()));
    }
}
