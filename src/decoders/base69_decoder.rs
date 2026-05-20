//! Decode Base69 strings using Ciphey's Python Base69 alphabet and chunking.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

const BASE69_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-*<>|";

/// Base69 decoder.
pub struct Base69Decoder;

impl Crack for Decoder<Base69Decoder> {
    fn new() -> Decoder<Base69Decoder> {
        Decoder {
            name: "Base69",
            description: "Base69 is a binary-to-text encoding that packs seven bytes into sixteen characters.",
            link: "https://github.com/pshihn/base69",
            tags: vec!["base69", "decoder", "base"],
            popularity: 0.2,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Base69 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_base69(text) else {
            debug!("Base69 decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode base69 because check_string_success returned false on string {}",
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

fn decode_base69(text: &str) -> Option<String> {
    let cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.is_ascii() {
        return None;
    }

    let chunk_count = cleaned.len().div_ceil(16);
    let mut result = Vec::with_capacity(chunk_count * 7);

    for chunk_index in 0..chunk_count {
        let start = chunk_index * 16;
        let end = ((chunk_index + 1) * 16).min(cleaned.len());
        let decoded = decode_base69_chunk(&cleaned[start..end])?;
        result.extend(decoded.into_iter().map(|byte| (byte % 256) as u8));
    }

    while result.last() == Some(&0) {
        result.pop();
    }

    String::from_utf8(result).ok()
}

fn decode_base69_chunk(chunk: &str) -> Option<Vec<u16>> {
    if chunk.len() != 16 {
        return None;
    }

    let mut decoded = [0u16; 8];
    let padded_bytes = chunk.ends_with('=');
    for (index, value) in decoded.iter_mut().enumerate() {
        let start = index * 2;
        if start >= chunk.len() {
            break;
        }
        if index == 7 && padded_bytes {
            *value = 0;
        } else {
            *value = chars_to_base69_byte(&chunk[start..start + 2])?;
        }
    }

    let mut result = Vec::with_capacity(7);
    for index in 0..7 {
        let left = decoded[index] << (index + 1);
        let right = decoded[index + 1] >> (7 - index - 1);
        result.push(left | right);
    }
    Some(result)
}

fn chars_to_base69_byte(pair: &str) -> Option<u16> {
    let mut chars = pair.chars();
    let first = chars.next()?;
    let second = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    let first_index = BASE69_CHARS.chars().position(|ch| ch == first)? as u16;
    let second_index = BASE69_CHARS.chars().position(|ch| ch == second)? as u16;
    Some(69 * second_index + first_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full_chunk() {
        assert_eq!(
            decode_base69("kAZAtABBeB8ATBgA"),
            Some("Hello, ".to_string())
        );
    }

    #[test]
    fn decodes_partial_chunk_with_padding() {
        assert_eq!(
            decode_base69("kAZAtABBeB8ATBgAtBuASApB8ARBYA1="),
            Some("Hello, 世界".to_string())
        );
    }

    #[test]
    fn rejects_unknown_character() {
        assert_eq!(decode_base69("not_base69"), None);
    }

    #[test]
    fn rejects_non_ascii_without_panicking() {
        assert_eq!(decode_base69("😀😀😀😀😀😀😀😀"), None);
    }
}
