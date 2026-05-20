//! Decode ASCII85 strings.

use crate::checkers::CheckerTypes;
use crate::decoders::base85_decoder::decode_base85_bytes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

const ASCII85_ALPHABET: &str =
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";

/// ASCII85 decoder.
pub struct Ascii85Decoder;

impl Crack for Decoder<Ascii85Decoder> {
    fn new() -> Decoder<Ascii85Decoder> {
        Decoder {
            name: "ascii85",
            description: "ASCII85 is a binary-to-text encoding that represents four bytes with five printable ASCII characters.",
            link: "https://docs.python.org/3/library/base64.html#base64.a85decode",
            tags: vec!["ascii85", "base85", "decoder", "base"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying ASCII85 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_ascii85(text) else {
            debug!("ASCII85 decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode ascii85 because check_string_success returned false on string {}",
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

fn decode_ascii85(text: &str) -> Option<String> {
    let mut cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    if cleaned.starts_with("<~") && cleaned.ends_with("~>") {
        cleaned = cleaned[2..cleaned.len() - 2].to_string();
    }
    decode_base85_bytes(&cleaned, ASCII85_ALPHABET, true)
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_python_ascii85_vector() {
        assert_eq!(
            decode_ascii85("BOu!rD]j7BEbo7"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn decodes_zero_shortcut() {
        assert_eq!(decode_ascii85("z"), Some("\0\0\0\0".to_string()));
    }

    #[test]
    fn accepts_adobe_markers() {
        assert_eq!(
            decode_ascii85("<~BOu!rD]j7BEbo7~>"),
            Some("hello world".to_string())
        );
    }
}
