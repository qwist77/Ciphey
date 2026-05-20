//! Decode a small leetspeak translation table.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

/// Leetspeak decoder.
pub struct LeetspeakDecoder;

impl Crack for Decoder<LeetspeakDecoder> {
    fn new() -> Decoder<LeetspeakDecoder> {
        Decoder {
            name: "leetspeak",
            description: "Leetspeak replaces letters with visually similar numbers or punctuation.",
            link: "https://en.wikipedia.org/wiki/Leet",
            tags: vec!["leetspeak", "substitution", "decoder"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying leetspeak with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let decoded_text = decode_leetspeak(text);

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode leetspeak because check_string_success returned false on string {}",
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

fn decode_leetspeak(text: &str) -> String {
    let replacements = [
        ("_", " "),
        ("0", "O"),
        ("1", "I"),
        ("2", "Z"),
        ("3", "E"),
        ("4", "A"),
        ("5", "S"),
        ("6", "G"),
        ("7", "T"),
        ("8", "B"),
        ("9", "G"),
        ("|>", "P"),
        ("|-|", "H"),
        ("\\/\\/", "W"),
    ];

    let mut decoded = text.to_string();
    for (src, dst) in replacements {
        decoded = decoded.replace(src, dst);
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_leetspeak_in_python_order() {
        assert_eq!(decode_leetspeak("|-|3ll0"), "HEllO");
    }

    #[test]
    fn decodes_underscore_as_space() {
        assert_eq!(decode_leetspeak("H3ll0_W0rld"), "HEllO WOrld");
    }

    #[test]
    fn decodes_multichar_leetspeak_tokens() {
        assert_eq!(decode_leetspeak("P4|>3R_\\/\\/1N5"), "PAPER WINS");
    }
}
