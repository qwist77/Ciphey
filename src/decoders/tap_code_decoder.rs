//! Decode tap code coordinates.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Tap code decoder.
pub struct TapCodeDecoder;

impl Crack for Decoder<TapCodeDecoder> {
    fn new() -> Decoder<TapCodeDecoder> {
        Decoder {
            name: "tap_code",
            description: "Tap code is a 5 by 5 Polybius-square coordinate encoding.",
            link: "https://en.wikipedia.org/wiki/Tap_code",
            tags: vec!["tap_code", "polybius", "decoder"],
            popularity: 0.06,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying tap code with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        if text.is_empty() {
            return results;
        }
        let Some(decoded_text) = decode_tap_code(text) else {
            debug!("Tap code decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode tap code because check_string_success returned false on string {}",
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

fn decode_tap_code(text: &str) -> Option<String> {
    let mut result = String::new();
    for fragment in text.split(' ') {
        result.push_str(tap_code_fragment(fragment)?);
    }
    Some(result)
}

fn tap_code_fragment(fragment: &str) -> Option<&'static str> {
    match fragment {
        "1,1" => Some("A"),
        "1,2" => Some("B"),
        "1,3" => Some("C"),
        "1,4" => Some("D"),
        "1,5" => Some("E"),
        "2,1" => Some("F"),
        "2,2" => Some("G"),
        "2,3" => Some("H"),
        "2,4" => Some("I"),
        "2,5" => Some("J"),
        "3,1" => Some("L"),
        "3,2" => Some("M"),
        "3,3" => Some("N"),
        "3,4" => Some("O"),
        "3,5" => Some("P"),
        "4,1" => Some("Q"),
        "4,2" => Some("R"),
        "4,3" => Some("S"),
        "4,4" => Some("T"),
        "4,5" => Some("U"),
        "5,1" => Some("V"),
        "5,2" => Some("W"),
        "5,3" => Some("X"),
        "5,4" => Some("Y"),
        "5,5" => Some("Z"),
        "" => Some(" "),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        english::EnglishChecker,
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn decodes_tap_code() {
        assert_eq!(
            decode_tap_code("4,4 1,5 4,3 4,4  3,4 3,3 1,5"),
            Some("TEST ONE".to_string())
        );
    }

    #[test]
    fn rejects_unknown_fragment() {
        assert_eq!(decode_tap_code("1,1 9,9"), None);
    }

    #[test]
    fn empty_crack_input_returns_no_candidates() {
        let decoder = Decoder::<TapCodeDecoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn decodes_standard_help_me_phrase() {
        assert_eq!(
            decode_tap_code("2,3 1,5 3,1 3,5  3,2 1,5"),
            Some("HELP ME".to_string())
        );
    }
    #[test]
    fn crack_decodes_tap_code_public_path() {
        let checker = CheckerTypes::CheckEnglish(Checker::<EnglishChecker>::new());
        let decoder = Decoder::<TapCodeDecoder>::new();
        let result = decoder.crack("2,3 1,5 3,1 3,1 3,4", &checker);

        assert!(result.success);
        assert_eq!(result.unencrypted_text.as_ref().unwrap()[0], "HELLO");
    }
}
