//! Crack repeating-key XOR text with native Rust scoring.

use crate::checkers::CheckerTypes;
use crate::decoders::byte_input::parse_textual_bytes;
use crate::decoders::english_scoring::score_english;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

const MAX_KEY_SIZE: usize = 16;

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

fn xorcrypt_candidates(bytes: &[u8]) -> Vec<(String, String, f32)> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    let max_key_size = MAX_KEY_SIZE.min(bytes.len());
    let mut candidates = Vec::new();
    for key_size in 2..=max_key_size {
        let key = derive_key(bytes, key_size);
        let decoded = xor_repeating(bytes, &key);
        if let Ok(text) = String::from_utf8(decoded) {
            let score = score_english(&text) - key_size as f32 * 0.2;
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

fn derive_key(bytes: &[u8], key_size: usize) -> Vec<u8> {
    (0..key_size)
        .map(|offset| {
            let column: Vec<u8> = bytes
                .iter()
                .skip(offset)
                .step_by(key_size)
                .copied()
                .collect();
            best_single_byte_key(&column)
        })
        .collect()
}

fn best_single_byte_key(bytes: &[u8]) -> u8 {
    (0u8..=255)
        .max_by(|left, right| {
            score_xor_column(bytes, *left).total_cmp(&score_xor_column(bytes, *right))
        })
        .unwrap_or(0)
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
}
