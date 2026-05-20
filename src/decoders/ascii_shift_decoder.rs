//! Crack full-ASCII Caesar shift text.

use crate::checkers::CheckerTypes;
use crate::decoders::english_scoring::score_english;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

/// ASCII shift cracker.
pub struct AsciiShiftDecoder;

impl Crack for Decoder<AsciiShiftDecoder> {
    fn new() -> Decoder<AsciiShiftDecoder> {
        Decoder {
            name: "ascii_shift",
            description: "ASCII shift is a Caesar cipher over the 7-bit ASCII alphabet.",
            link: "https://en.wikipedia.org/wiki/Caesar_cipher",
            tags: vec!["ascii_shift", "ascii", "cipher", "decryption"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying ASCII shift with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        if text.is_empty() {
            return results;
        }
        let mut candidates: Vec<(String, String, f32)> = (1..128)
            .map(|shift| {
                let decoded = ascii_shift(text, shift);
                let score = score_english(&decoded);
                (decoded, shift.to_string(), score)
            })
            .collect();
        candidates.sort_by(|left, right| right.2.total_cmp(&left.2));

        for (candidate, key, _) in &candidates {
            if !check_string_success(candidate, text) {
                info!("ASCII shift candidate did not modify input: {}", candidate);
                continue;
            }
            let checker_result = checker.check(candidate);
            if checker_result.is_identified {
                results.unencrypted_text = Some(vec![candidate.clone()]);
                results.key = Some(key.clone());
                results.update_checker(&checker_result);
                return results;
            }
        }

        results.unencrypted_text = Some(
            candidates
                .into_iter()
                .take(50)
                .map(|(candidate, _, _)| candidate)
                .collect(),
        );
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

fn ascii_shift(text: &str, shift: u8) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_ascii() {
                let shifted = (ch as u8).wrapping_add(shift) & 0x7f;
                shifted as char
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn shifts_full_ascii() {
        assert_eq!(ascii_shift("\"?FFI", 38), "Hello");
    }

    #[test]
    fn crack_orders_legacy_python_vector_first() {
        let decoder = Decoder::<AsciiShiftDecoder>::new();
        let result = decoder.crack(
            "\"?FFIzGSzH;G?zCMz<??z;H>z#zFCE?z>IAz;H>z;JJF?z;H>zNL??",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Hello my name is bee and I like dog and apple and tree"
        );
    }

    #[test]
    fn empty_input_returns_no_candidates() {
        let decoder = Decoder::<AsciiShiftDecoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn shift_wraps_at_7_bit_boundary() {
        assert_eq!(ascii_shift("~\x7f", 1), "\x7f\0");
    }
}
