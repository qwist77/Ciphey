//! Decode gzip-compressed bytes.

use crate::checkers::CheckerTypes;
use crate::decoders::byte_input::parse_textual_bytes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use flate2::read::GzDecoder;
use log::{debug, info, trace};
use std::io::Read;

const MAX_GZIP_DECOMPRESSED_BYTES: u64 = 1024 * 1024;

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
        let input = parse_textual_bytes(text).unwrap_or_else(|| text.as_bytes().to_vec());
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
    let decoder = GzDecoder::new(bytes);
    let mut limited = decoder.take(MAX_GZIP_DECOMPRESSED_BYTES + 1);
    let mut output = Vec::new();
    limited.read_to_end(&mut output).ok()?;
    if output.len() as u64 > MAX_GZIP_DECOMPRESSED_BYTES {
        return None;
    }
    String::from_utf8(output).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::interface::Crack;
    use std::io::Write;

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn decodes_gzip_hex_vector() {
        let gzip_hex = "1f8b08000000000002ffcb48cdc9c95728cf2fca49010085114a0d0b000000";
        let bytes = parse_textual_bytes(gzip_hex).expect("hex should parse");
        assert_eq!(decode_gzip_bytes(&bytes), Some("hello world".to_string()));
    }

    #[test]
    fn crack_decodes_legacy_python_base64_gzip_vector() {
        let decoder = Decoder::<GzipDecoder>::new();
        let result = decoder.crack(
            "H4sIAAzul18A/yXJzQmAMBSEwVa+ckwZT7LIw80P6sXuA3ocZpM9aC89msibXSJ6peA8RR3Hx5jTfzyXtAAbQvCyNgAAAA==",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Hello my name is bee and I like dog and apple and tree"
        );
    }

    #[test]
    fn rejects_invalid_gzip() {
        assert_eq!(decode_gzip_bytes(b"not gzip"), None);
    }

    #[test]
    fn rejects_gzip_output_over_limit() {
        use flate2::{write::GzEncoder, Compression};

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![b'a'; MAX_GZIP_DECOMPRESSED_BYTES as usize + 1])
            .expect("write test gzip payload");
        let compressed = encoder.finish().expect("finish test gzip payload");

        assert_eq!(decode_gzip_bytes(&compressed), None);
    }

    #[test]
    fn decodes_gzip_with_original_filename_header() {
        let gzip_hex = "1f8b08080000000002ff68656c6c6f2e74787400cb48cdc9c9e7020020303a3606000000";
        let bytes = parse_textual_bytes(gzip_hex).expect("hex should parse");
        assert_eq!(decode_gzip_bytes(&bytes), Some("hello\n".to_string()));
    }
}
