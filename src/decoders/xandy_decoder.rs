//! Crack X-and-Y binary substitution text.

use crate::checkers::CheckerTypes;
use crate::decoders::english_scoring::score_english;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};
use num::{BigUint, Zero};
use std::collections::HashSet;

/// X-and-Y substitution cracker.
pub struct XandyDecoder;

impl Crack for Decoder<XandyDecoder> {
    fn new() -> Decoder<XandyDecoder> {
        Decoder {
            name: "xandy",
            description:
                "X-and-Y treats two symbols as binary 0 and 1, with an optional delimiter.",
            link: "https://en.wikipedia.org/wiki/Binary_code",
            tags: vec!["xandy", "binary", "substitution", "decryption"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying X-and-Y with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(mut candidates) = xandy_candidates(text) else {
            return results;
        };
        candidates.sort_by(|left, right| right.2.total_cmp(&left.2));

        for (candidate, key, _) in &candidates {
            if !check_string_success(candidate, text) {
                info!("X-and-Y candidate did not modify input: {}", candidate);
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

fn xandy_candidates(text: &str) -> Option<Vec<(String, String, f32)>> {
    let mut cleaned: String = text
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let mut unique = unique_chars(&cleaned);
    if !(2..=3).contains(&unique.len()) {
        return None;
    }
    if unique.len() == 3 {
        let delimiter = unique
            .iter()
            .min_by_key(|ch| cleaned.chars().filter(|candidate| candidate == *ch).count())?;
        cleaned = cleaned.replace(*delimiter, "");
        unique = unique_chars(&cleaned);
    }
    if unique.len() != 2 {
        return None;
    }

    let first = unique[0];
    let second = unique[1];
    let variants = [(first, '0', second, '1'), (first, '1', second, '0')];
    let mut candidates = Vec::new();
    for (left, left_bit, right, right_bit) in variants {
        let binary: String = cleaned
            .chars()
            .map(|ch| if ch == left { left_bit } else { right_bit })
            .collect();
        if let Some(decoded) = binary_to_utf8(&binary) {
            let decoded = decoded.trim_matches('\0').to_string();
            if !decoded.is_empty() {
                let score = score_english(&decoded);
                candidates.push((
                    decoded,
                    format!("{left} -> {left_bit} & {right} -> {right_bit}"),
                    score,
                ));
            }
        }
    }
    Some(candidates)
}

fn unique_chars(text: &str) -> Vec<char> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for ch in text.chars() {
        if seen.insert(ch) {
            unique.push(ch);
        }
    }
    unique
}

fn binary_to_utf8(binary: &str) -> Option<String> {
    if binary.is_empty() || !binary.chars().all(|ch| matches!(ch, '0' | '1')) {
        return None;
    }
    let number = BigUint::parse_bytes(binary.as_bytes(), 2)?;
    if number.is_zero() {
        return Some(String::new());
    }
    String::from_utf8(number.to_bytes_be()).ok()
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
    fn converts_binary_symbols_to_text() {
        let candidates = xandy_candidates("xDDxDxxx xDDxxDxD").expect("candidate");
        assert!(candidates.iter().any(|(candidate, _, _)| candidate == "he"));
    }

    #[test]
    fn crack_orders_legacy_python_vector_first() {
        let decoder = Decoder::<XandyDecoder>::new();
        let result = decoder.crack(
            "xDDxDxxx xDDxxDxD xDDxDDxx xDDxDDxx xDDxDDDD xxDxxxxx xDDxDDxD xDDDDxxD xxDxxxxx xDDxDDDx xDDxxxxD xDDxDDxD xDDxxDxD xxDxxxxx xDDxDxxD xDDDxxDD xxDxxxxx xDDxxxDx xDDxxDxD xDDxxDxD xxDxxxxx xDDxxxxD xDDxDDDx xDDxxDxx xxDxxxxx xDxxDxxD xxDxxxxx xDDxDDxx xDDxDxxD xDDxDxDD xDDxxDxD xxDxxxxx xDDxxDxx xDDxDDDD xDDxxDDD xxDxxxxx xDDxxxxD xDDxDDDx xDDxxDxx xxDxxxxx xDDxxxxD xDDDxxxx xDDDxxxx xDDxDDxx xDDxxDxD xxDxxxxx xDDxxxxD xDDxDDDx xDDxxDxx xxDxxxxx xDDDxDxx xDDDxxDx xDDxxDxD xDDxxDxD",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "hello my name is bee and I like dog and apple and tree"
        );
    }
}
