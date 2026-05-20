//! Decode Git-style Base85 strings.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

const BASE85_ALPHABET: &str =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

/// Base85 decoder.
pub struct Base85Decoder;

impl Crack for Decoder<Base85Decoder> {
    fn new() -> Decoder<Base85Decoder> {
        Decoder {
            name: "Base85",
            description: "Base85 is a binary-to-text encoding that represents four bytes with five printable characters.",
            link: "https://docs.python.org/3/library/base64.html#base64.b85decode",
            tags: vec!["base85", "decoder", "base"],
            popularity: 0.01,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Base85 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_base85(text) else {
            debug!("Base85 decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode base85 because check_string_success returned false on string {}",
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

fn decode_base85(text: &str) -> Option<String> {
    let cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    decode_base85_bytes(&cleaned, BASE85_ALPHABET, false)
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

pub(crate) fn decode_base85_bytes(
    text: &str,
    alphabet: &str,
    ascii85_zero_shortcut: bool,
) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }

    let mut output = Vec::new();
    let mut chunk = Vec::with_capacity(5);

    for ch in text.chars() {
        if ascii85_zero_shortcut && ch == 'z' && chunk.is_empty() {
            output.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        let value = alphabet.chars().position(|candidate| candidate == ch)? as u32;
        chunk.push(value);
        if chunk.len() == 5 {
            output.extend_from_slice(&base85_chunk_to_bytes(&chunk, 4)?);
            chunk.clear();
        }
    }

    if !chunk.is_empty() {
        if chunk.len() == 1 {
            return None;
        }
        let output_len = chunk.len() - 1;
        while chunk.len() < 5 {
            chunk.push(84);
        }
        output.extend_from_slice(&base85_chunk_to_bytes(&chunk, output_len)?);
    }

    Some(output)
}

fn base85_chunk_to_bytes(chunk: &[u32], output_len: usize) -> Option<Vec<u8>> {
    let mut value = 0u32;
    for digit in chunk {
        value = value.checked_mul(85)?.checked_add(*digit)?;
    }
    let bytes = value.to_be_bytes();
    Some(bytes[..output_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_python_base85_vector() {
        assert_eq!(
            decode_base85("Xk~0{Zy<MXa%^M"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn decodes_whitespace_like_python_dispatch() {
        assert_eq!(
            decode_base85("Xk~0{ Zy<MX a%^M"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn rejects_invalid_single_digit_tail() {
        assert_eq!(decode_base85("X"), None);
    }
}
