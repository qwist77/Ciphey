//! Crack Baconian cipher text.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};

const BACONIAN_CLASSIC: [(&str, char); 24] = [
    ("AAAAA", 'A'),
    ("AAAAB", 'B'),
    ("AAABA", 'C'),
    ("AAABB", 'D'),
    ("AABAA", 'E'),
    ("AABAB", 'F'),
    ("AABBA", 'G'),
    ("AABBB", 'H'),
    ("ABAAA", 'I'),
    ("ABAAB", 'K'),
    ("ABABA", 'L'),
    ("ABABB", 'M'),
    ("ABBAA", 'N'),
    ("ABBAB", 'O'),
    ("ABBBA", 'P'),
    ("ABBBB", 'Q'),
    ("BAAAA", 'R'),
    ("BAAAB", 'S'),
    ("BAABA", 'T'),
    ("BAABB", 'U'),
    ("BABAA", 'W'),
    ("BABAB", 'X'),
    ("BABBA", 'Y'),
    ("BABBB", 'Z'),
];

const BACONIAN_UNIQUE: [(&str, char); 26] = [
    ("AAAAA", 'A'),
    ("AAAAB", 'B'),
    ("AAABA", 'C'),
    ("AAABB", 'D'),
    ("AABAA", 'E'),
    ("AABAB", 'F'),
    ("AABBA", 'G'),
    ("AABBB", 'H'),
    ("ABAAA", 'I'),
    ("ABAAB", 'J'),
    ("ABABA", 'K'),
    ("ABABB", 'L'),
    ("ABBAA", 'M'),
    ("ABBAB", 'N'),
    ("ABBBA", 'O'),
    ("ABBBB", 'P'),
    ("BAAAA", 'Q'),
    ("BAAAB", 'R'),
    ("BAABA", 'S'),
    ("BAABB", 'T'),
    ("BABAA", 'U'),
    ("BABAB", 'V'),
    ("BABBA", 'W'),
    ("BABBB", 'X'),
    ("BBAAA", 'Y'),
    ("BBAAB", 'Z'),
];

/// Baconian cipher cracker.
pub struct BaconianDecoder;

impl Crack for Decoder<BaconianDecoder> {
    fn new() -> Decoder<BaconianDecoder> {
        Decoder {
            name: "baconian",
            description: "Baconian cipher encodes letters as five-character A/B groups.",
            link: "https://en.wikipedia.org/wiki/Bacon%27s_cipher",
            tags: vec!["baconian", "cipher", "classic", "decryption"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Baconian with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(candidates) = decode_baconian(text) else {
            return results;
        };

        for candidate in &candidates {
            if !check_string_success(candidate, text) {
                info!("Baconian candidate did not modify input: {}", candidate);
                continue;
            }
            let checker_result = checker.check(candidate);
            if checker_result.is_identified {
                results.unencrypted_text = Some(vec![candidate.clone()]);
                results.update_checker(&checker_result);
                return results;
            }
        }

        results.unencrypted_text = Some(candidates);
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

fn decode_baconian(text: &str) -> Option<Vec<String>> {
    let cleaned: String = text
        .chars()
        .filter(|ch| !matches!(ch, ',' | ';' | ':' | '-' | ' ' | '\n' | '\r' | '\t'))
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty()
        || !cleaned.len().is_multiple_of(5)
        || !cleaned.chars().all(|ch| matches!(ch, 'A' | 'B'))
    {
        return None;
    }

    let mut classic = String::new();
    let mut unique = String::new();
    for chunk in cleaned.as_bytes().chunks(5) {
        let key = std::str::from_utf8(chunk).ok()?;
        if let Some((_, letter)) = BACONIAN_CLASSIC
            .iter()
            .find(|(candidate, _)| *candidate == key)
        {
            classic.push(*letter);
        }
        if let Some((_, letter)) = BACONIAN_UNIQUE
            .iter()
            .find(|(candidate, _)| *candidate == key)
        {
            unique.push(*letter);
        }
    }

    let mut candidates = Vec::new();
    if !classic.is_empty() {
        candidates.push(classic);
    }
    if !unique.is_empty() {
        candidates.push(unique);
    }
    Some(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_baconian_variants() {
        assert_eq!(
            decode_baconian("AAAAA AAAAB AAABA"),
            Some(vec!["ABC".to_string(), "ABC".to_string()])
        );
    }

    #[test]
    fn unique_variant_handles_yz() {
        assert_eq!(decode_baconian("BBAAA BBAAB"), Some(vec!["YZ".to_string()]));
    }

    #[test]
    fn rejects_non_ab_input() {
        assert_eq!(decode_baconian("AACAA"), None);
    }
}
