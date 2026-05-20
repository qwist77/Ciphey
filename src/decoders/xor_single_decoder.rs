//! Crack single-byte XOR text.

use crate::checkers::CheckerTypes;
use crate::decoders::binary_signatures::binary_signature_score;
use crate::decoders::byte_input::parse_textual_bytes;
use crate::decoders::english_scoring::score_english;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

/// Single-byte XOR cracker.
pub struct XorSingleDecoder;

impl Crack for Decoder<XorSingleDecoder> {
    fn new() -> Decoder<XorSingleDecoder> {
        Decoder {
            name: "xor_single",
            description: "Single-byte XOR applies the same byte key to every byte of the input.",
            link: "https://en.wikipedia.org/wiki/XOR_cipher",
            tags: vec!["xor_single", "xor", "cipher", "decryption"],
            popularity: 0.2,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying single-byte XOR with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        if text.is_empty() {
            return results;
        }
        let bytes = parse_textual_bytes(text).unwrap_or_else(|| text.as_bytes().to_vec());
        let mut candidates = xor_single_candidates(&bytes);
        candidates.sort_by(|left, right| right.2.total_cmp(&left.2));

        for (candidate, key, _) in &candidates {
            if !check_string_success(candidate, text) {
                info!(
                    "Single-byte XOR candidate did not modify input: {}",
                    candidate
                );
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

fn xor_single_candidates(bytes: &[u8]) -> Vec<(String, String, f32)> {
    (0u8..=255)
        .map(|key| {
            let decoded = xor_single_decrypt(bytes, key);
            let (text, score) = bytes_to_candidate_text(decoded);
            (text, format!("0x{key:02x}"), score)
        })
        .collect()
}

fn bytes_to_candidate_text(decoded: Vec<u8>) -> (String, f32) {
    let signature_score = binary_signature_score(&decoded);
    match String::from_utf8(decoded) {
        Ok(text) => {
            let score = signature_score.unwrap_or_else(|| score_english(&text));
            (text, score)
        }
        Err(error) => {
            let bytes = error.into_bytes();
            let text = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            (text, signature_score.unwrap_or(-1000.0))
        }
    }
}

fn xor_single_decrypt(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ key).collect()
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
    fn decrypts_with_single_byte_key() {
        assert_eq!(xor_single_decrypt(b"\x03.''$", 0x4b), b"Hello");
    }

    #[test]
    fn crack_orders_hex_vector_first() {
        let decoder = Decoder::<XorSingleDecoder>::new();
        let result = decoder.crack("032e272724", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "Hello");
        assert_eq!(result.key.unwrap(), "0x4b");
    }

    #[test]
    fn preserves_non_utf8_output_as_hex_carrier() {
        let candidates = xor_single_candidates(&[0xff]);
        assert!(candidates
            .iter()
            .any(|(candidate, key, _)| candidate == "ff" && key == "0x00"));
    }

    #[test]
    fn crack_preserves_non_utf8_output_as_hex_carrier() {
        let encrypted = [0x1f, 0x8b, 0x08]
            .iter()
            .map(|byte| format!("{:02x}", byte ^ 0x42))
            .collect::<String>();
        let decoder = Decoder::<XorSingleDecoder>::new();
        let result = decoder.crack(&encrypted, &get_athena_checker());
        let texts = result.unencrypted_text.unwrap();
        assert_eq!(texts[0], "1f8b08");
    }

    #[test]
    fn empty_input_returns_no_candidates() {
        let decoder = Decoder::<XorSingleDecoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn finds_cryptopals_single_byte_xor_vector() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let bytes =
            crate::decoders::byte_input::parse_textual_bytes(input).expect("hex should parse");
        let candidates = xor_single_candidates(&bytes);
        assert!(candidates.iter().any(|(candidate, key, _)| {
            candidate == "Cooking MC's like a pound of bacon" && key == "0x58"
        }));
    }
}
