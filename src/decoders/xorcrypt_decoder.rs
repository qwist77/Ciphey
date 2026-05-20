//! Crack repeating-key XOR text with native Rust scoring.

use crate::checkers::CheckerTypes;
use crate::decoders::byte_input::parse_textual_bytes;
use crate::decoders::english_scoring::score_english;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

const MAX_KEY_SIZE: usize = 16;
const KEY_BYTE_BEAM: usize = 3;
const MAX_KEYS_PER_SIZE: usize = 32;

/// Repeating-key XOR cracker.
pub struct XorCryptDecoder;

impl Crack for Decoder<XorCryptDecoder> {
    fn new() -> Decoder<XorCryptDecoder> {
        Decoder {
            name: "xorcrypt",
            description: "Repeating-key XOR applies a repeating byte key across the input.",
            link: "https://en.wikipedia.org/wiki/XOR_cipher",
            tags: vec!["xorcrypt", "xor", "cipher", "decryption"],
            popularity: 0.2,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying repeating-key XOR with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        if text.is_empty() {
            return results;
        }
        let bytes = parse_textual_bytes(text).unwrap_or_else(|| text.as_bytes().to_vec());
        let mut candidates = xorcrypt_candidates(&bytes);
        candidates.sort_by(|left, right| right.2.total_cmp(&left.2));

        for (candidate, key, _) in &candidates {
            if !check_string_success(candidate, text) {
                info!(
                    "Repeating-key XOR candidate did not modify input: {}",
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

        if !candidates.is_empty() {
            results.unencrypted_text = Some(
                candidates
                    .into_iter()
                    .map(|(candidate, _, _)| candidate)
                    .collect(),
            );
        }
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

fn xorcrypt_candidates(bytes: &[u8]) -> Vec<(String, String, f32)> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    let max_key_size = MAX_KEY_SIZE.min(bytes.len());
    let mut candidates = Vec::new();
    for key_size in 2..=max_key_size {
        if key_size == bytes.len() {
            let key = vec![0; key_size];
            let decoded = xor_repeating(bytes, &key);
            let (text, base_score) = bytes_to_candidate_text(decoded);
            let key_info = format!(
                "0x{}",
                key.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            candidates.push((text, key_info, base_score - key_size as f32 * 0.2));
        }
        for key in derive_keys(bytes, key_size) {
            let decoded = xor_repeating(bytes, &key);
            let (text, base_score) = bytes_to_candidate_text(decoded);
            let score = base_score - key_size as f32 * 0.2;
            let key_info = format!(
                "0x{}",
                key.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            candidates.push((text, key_info, score));
        }
    }
    candidates
}

fn derive_keys(bytes: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    let top_keys_by_column: Vec<Vec<(u8, f32)>> = (0..key_size)
        .map(|offset| {
            let column: Vec<u8> = bytes
                .iter()
                .skip(offset)
                .step_by(key_size)
                .copied()
                .collect();
            top_single_byte_keys(&column)
        })
        .collect();

    let mut keys = vec![(Vec::new(), 0.0)];
    for column_keys in top_keys_by_column {
        let mut next_keys = Vec::new();
        for (prefix, prefix_score) in &keys {
            for (byte, byte_score) in &column_keys {
                let mut key = prefix.clone();
                key.push(*byte);
                next_keys.push((key, prefix_score + byte_score));
            }
        }
        next_keys.sort_by(|left, right| right.1.total_cmp(&left.1));
        next_keys.truncate(MAX_KEYS_PER_SIZE);
        keys = next_keys;
    }
    keys.into_iter().map(|(key, _)| key).collect()
}

fn top_single_byte_keys(bytes: &[u8]) -> Vec<(u8, f32)> {
    let mut keys: Vec<(u8, f32)> = (0u8..=255)
        .map(|key| (key, score_xor_column(bytes, key)))
        .collect();
    keys.sort_by(|left, right| right.1.total_cmp(&left.1));
    keys.truncate(KEY_BYTE_BEAM);
    keys
}

fn score_xor_column(bytes: &[u8], key: u8) -> f32 {
    let decoded: String = bytes.iter().map(|byte| (byte ^ key) as char).collect();
    score_english(&decoded)
}

fn xor_repeating(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect()
}

fn bytes_to_candidate_text(decoded: Vec<u8>) -> (String, f32) {
    match String::from_utf8(decoded) {
        Ok(text) => {
            let score = score_english(&text);
            (text, score)
        }
        Err(error) => {
            let bytes = error.into_bytes();
            let text = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            (text, -1000.0)
        }
    }
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
    fn repeating_xor_roundtrips() {
        let encrypted = xor_repeating(b"Hello", b"key");
        assert_eq!(xor_repeating(&encrypted, b"key"), b"Hello");
    }

    #[test]
    fn crack_orders_repeating_key_vector_first() {
        let plaintext = b"Hello my name is bee and I like dog and apple and tree";
        let encrypted = xor_repeating(plaintext, b"ice");
        let encoded = encrypted
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let decoder = Decoder::<XorCryptDecoder>::new();
        let result = decoder.crack(&encoded, &get_athena_checker());
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Hello my name is bee and I like dog and apple and tree"
        );
        assert_eq!(result.key.unwrap(), "0x696365");
    }

    #[test]
    fn preserves_non_utf8_output_as_hex_carrier() {
        let candidates = xorcrypt_candidates(&[0xff, 0x00]);
        assert!(candidates
            .iter()
            .any(|(candidate, key, _)| candidate == "ff00" && key == "0x0000"));
    }

    #[test]
    fn crack_preserves_non_utf8_output_as_hex_carrier() {
        let decoder = Decoder::<XorCryptDecoder>::new();
        let result = decoder.crack("ff00", &get_athena_checker());
        let texts = result.unencrypted_text.unwrap();
        assert!(texts.iter().any(|candidate| candidate == "ff00"));
    }

    #[test]
    fn empty_input_returns_no_candidates() {
        let decoder = Decoder::<XorCryptDecoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }
}
