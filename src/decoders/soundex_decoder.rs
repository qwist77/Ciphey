//! Crack Soundex code sequences using CipheyDists word data.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{info, trace};
use once_cell::sync::Lazy;
use std::collections::HashMap;

static SOUNDEX_DICT: Lazy<HashMap<String, Vec<String>>> = Lazy::new(|| {
    serde_json::from_str(include_str!("data/soundex.json"))
        .expect("bundled soundex dictionary should be valid JSON")
});

static FREQUENCY_RANKS: Lazy<HashMap<String, usize>> = Lazy::new(|| {
    let words: Vec<String> = serde_json::from_str(include_str!("data/english5000freq.json"))
        .expect("bundled English frequency list should be valid JSON");
    words
        .into_iter()
        .enumerate()
        .map(|(rank, word)| (word, rank))
        .collect()
});

/// Soundex cracker.
pub struct SoundexDecoder;

impl Crack for Decoder<SoundexDecoder> {
    fn new() -> Decoder<SoundexDecoder> {
        Decoder {
            name: "soundex",
            description: "Soundex encodes words by their English pronunciation.",
            link: "https://en.wikipedia.org/wiki/Soundex",
            tags: vec!["soundex", "phonetic", "decoder", "decryption"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Soundex with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(candidates) = soundex_candidates(text) else {
            return results;
        };

        for candidate in &candidates {
            if !check_string_success(candidate, text) {
                info!("Soundex candidate did not modify input: {}", candidate);
                continue;
            }
            let checker_result = checker.check(candidate);
            if checker_result.is_identified {
                results.unencrypted_text = Some(vec![candidate.clone()]);
                results.update_checker(&checker_result);
                return results;
            }
        }

        results.unencrypted_text = Some(candidates.into_iter().take(50).collect());
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

fn soundex_candidates(text: &str) -> Option<Vec<String>> {
    let cleaned: String = text
        .chars()
        .filter(|ch| !matches!(ch, ',' | ';' | ':' | '-' | ' ' | '\n' | '\r' | '\t'))
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty()
        || cleaned.len() % 4 != 0
        || !cleaned.chars().all(|ch| ch.is_ascii_alphanumeric())
    {
        return None;
    }

    let mut word_lists = Vec::new();
    for chunk in cleaned.as_bytes().chunks(4) {
        let code = std::str::from_utf8(chunk).ok()?;
        if let Some(words) = SOUNDEX_DICT.get(code) {
            word_lists.push(words.clone());
        }
    }
    if word_lists.is_empty() {
        return Some(Vec::new());
    }

    let mut sentences = Vec::new();
    build_sentences(&word_lists, 0, &mut Vec::new(), &mut sentences);
    sentences.sort_by_key(|sentence| sentence_rank(sentence));
    Some(sentences)
}

fn build_sentences(
    word_lists: &[Vec<String>],
    index: usize,
    current: &mut Vec<String>,
    sentences: &mut Vec<String>,
) {
    if index == word_lists.len() {
        sentences.push(current.join(" "));
        return;
    }

    for word in &word_lists[index] {
        current.push(word.clone());
        build_sentences(word_lists, index + 1, current, sentences);
        current.pop();
    }
}

fn sentence_rank(sentence: &str) -> usize {
    sentence
        .split_whitespace()
        .map(|word| FREQUENCY_RANKS.get(word).copied().unwrap_or(5000))
        .sum()
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
    fn decodes_legacy_python_soundex_vector() {
        let decoder = Decoder::<SoundexDecoder>::new();
        let result = decoder.crack("H236 I200 I500 T000 P230", &get_athena_checker());
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "history is in the past"
        );
    }

    #[test]
    fn rejects_invalid_soundex_chars() {
        assert_eq!(soundex_candidates("H236!"), None);
    }
}
