//! Crack Affine cipher text by brute-forcing native Rust candidates.

use crate::checkers::CheckerTypes;
use crate::decoders::english_scoring::score_english;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

const ALPHABET_LEN: i32 = 26;

/// Affine cipher cracker.
pub struct AffineDecoder;

impl Crack for Decoder<AffineDecoder> {
    fn new() -> Decoder<AffineDecoder> {
        Decoder {
            name: "affine",
            description: "Affine cipher decrypts letters with D(x) = a^-1(x - b) mod m.",
            link: "https://en.wikipedia.org/wiki/Affine_cipher",
            tags: vec!["affine", "cipher", "classic", "decryption"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying affine cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        if text.is_empty() {
            return results;
        }
        let mut candidates = affine_candidates(text);
        candidates.sort_by(|left, right| right.2.total_cmp(&left.2));

        for (candidate, key, _) in &candidates {
            if !check_string_success(candidate, text) {
                info!("Affine candidate did not modify input: {}", candidate);
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
                    .take(50)
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

fn affine_candidates(text: &str) -> Vec<(String, String, f32)> {
    let mut candidates = Vec::new();
    for a in 1..ALPHABET_LEN {
        if gcd(a, ALPHABET_LEN) != 1 {
            continue;
        }
        let Some(a_inv) = mod_inv(a, ALPHABET_LEN) else {
            continue;
        };
        for b in 0..ALPHABET_LEN {
            let decoded = decrypt_affine(text, a_inv, b);
            let score = score_english(&decoded);
            candidates.push((decoded, format!("a={a}, b={b}"), score));
        }
    }
    candidates
}

fn decrypt_affine(text: &str, a_inv: i32, b: i32) -> String {
    text.chars()
        .map(|ch| {
            if !ch.is_ascii_alphabetic() {
                return ch;
            }
            let was_upper = ch.is_ascii_uppercase();
            let idx = ch.to_ascii_lowercase() as i32 - 'a' as i32;
            let decoded_idx = (a_inv * (idx - b)).rem_euclid(ALPHABET_LEN);
            let decoded = (b'a' + decoded_idx as u8) as char;
            if was_upper {
                decoded.to_ascii_uppercase()
            } else {
                decoded
            }
        })
        .collect()
}

fn gcd(mut a: i32, mut b: i32) -> i32 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a.abs()
}

fn mod_inv(a: i32, modulus: i32) -> Option<i32> {
    (1..modulus).find(|candidate| (a * candidate).rem_euclid(modulus) == 1)
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
    fn decrypts_known_affine_key() {
        assert_eq!(decrypt_affine("Ihhwvc Swfrcp!", 21, 8), "Affine Cipher!");
    }

    #[test]
    fn crack_orders_legacy_python_vector_first() {
        let decoder = Decoder::<AffineDecoder>::new();
        let result = decoder.crack(
            "Ihsst bf kxbh rd ghh xky R srjh ytz xky xccsh xky muhh",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Hello my name is bee and I like dog and apple and tree"
        );
    }

    #[test]
    fn empty_input_returns_no_candidates() {
        let decoder = Decoder::<AffineDecoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }
}
