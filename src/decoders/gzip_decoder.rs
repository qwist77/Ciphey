//! Decode gzip-compressed bytes.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use flate2::read::GzDecoder;
use log::{debug, info, trace};
use std::io::Read;

/// Gzip decoder.
pub struct GzipDecoder;

impl Crack for Decoder<GzipDecoder> {
    fn new() -> Decoder<GzipDecoder> {
        Decoder {
            name: "gzip",
            description:
                "Gzip is a compressed data format using DEFLATE with a gzip header and trailer.",
            link: "https://en.wikipedia.org/wiki/Gzip",
            tags: vec!["gzip", "compression", "decoder"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying gzip with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let input = parse_hex_bytes(text).unwrap_or_else(|| text.as_bytes().to_vec());
        let Some(decoded_text) = decode_gzip_bytes(&input) else {
            debug!("Gzip decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode gzip because check_string_success returned false on string {}",
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

fn decode_gzip_bytes(bytes: &[u8]) -> Option<String> {
    let mut decoder = GzDecoder::new(bytes);
    let mut output = String::new();
    decoder.read_to_string(&mut output).ok()?;
    Some(output)
}

fn parse_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    if cleaned.is_empty()
        || cleaned.len() % 2 != 0
        || !cleaned.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }
    cleaned
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(hex, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_gzip_hex_vector() {
        let gzip_hex = "1f8b08000000000002ffcb48cdc9c95728cf2fca49010085114a0d0b000000";
        let bytes = parse_hex_bytes(gzip_hex).expect("hex should parse");
        assert_eq!(decode_gzip_bytes(&bytes), Some("hello world".to_string()));
    }

    #[test]
    fn rejects_invalid_gzip() {
        assert_eq!(decode_gzip_bytes(b"not gzip"), None);
    }
}
