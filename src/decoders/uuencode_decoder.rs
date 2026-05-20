//! Decode uuencoded text.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Uuencode decoder.
pub struct UuencodeDecoder;

impl Crack for Decoder<UuencodeDecoder> {
    fn new() -> Decoder<UuencodeDecoder> {
        Decoder {
            name: "uuencode",
            description:
                "Uuencode converts binary data to printable ASCII for transport over text channels.",
            link: "https://en.wikipedia.org/wiki/Uuencoding",
            tags: vec!["uuencode", "binary-to-text", "decoder"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying uuencode with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_uuencode(text) else {
            debug!("Uuencode decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode uuencode because check_string_success returned false on string {}",
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

fn decode_uuencode(text: &str) -> Option<String> {
    let stripped = text.trim();
    let lines: Vec<&str> = if stripped.starts_with("begin") && stripped.ends_with("end") {
        stripped
            .lines()
            .skip(1)
            .take_while(|line| line.trim() != "end")
            .filter(|line| !line.is_empty())
            .collect()
    } else {
        text.lines().filter(|line| !line.is_empty()).collect()
    };

    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend(decode_uu_line(line)?);
    }
    String::from_utf8(bytes).ok()
}

fn decode_uu_line(line: &str) -> Option<Vec<u8>> {
    let bytes = line.as_bytes();
    let (&length_char, encoded) = bytes.split_first()?;
    let expected_len = uu_value(length_char)? as usize;
    let mut decoded = Vec::new();

    for chunk in encoded.chunks(4) {
        let mut padded = [b'`'; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        let a = uu_value(padded[0])?;
        let b = uu_value(padded[1])?;
        let c = uu_value(padded[2])?;
        let d = uu_value(padded[3])?;
        decoded.push((a << 2) | (b >> 4));
        decoded.push((b << 4) | (c >> 2));
        decoded.push((c << 6) | d);
    }
    decoded.resize(expected_len, 0);
    if decoded[expected_len..].iter().any(|byte| *byte != 0) {
        return None;
    }
    decoded.truncate(expected_len);
    Some(decoded)
}

fn uu_value(byte: u8) -> Option<u8> {
    match byte {
        b' '..=b'_' => Some(byte - 32),
        b'`' => Some(0),
        _ => None,
    }
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

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn decodes_raw_uuencoded_line() {
        assert_eq!(
            decode_uuencode("+:&5L;&\\@=V]R;&0"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn decodes_begin_end_wrapper() {
        let encoded = "begin 644 hello.txt\n+:&5L;&\\@=V]R;&0\n`\nend";
        assert_eq!(decode_uuencode(encoded), Some("hello world".to_string()));
    }

    #[test]
    fn rejects_invalid_short_chunk() {
        assert_eq!(decode_uuencode("+abc"), None);
    }

    #[test]
    fn pads_missing_short_line_payload_like_python() {
        assert_eq!(
            decode_uu_line("+").expect("line should decode"),
            vec![0; 11]
        );
    }

    #[test]
    fn rejects_illegal_uuencode_character() {
        assert_eq!(decode_uuencode("+aaaa"), None);
    }

    #[test]
    fn crack_decodes_legacy_python_wrapper_vector() {
        let decoder = Decoder::<UuencodeDecoder>::new();
        let result = decoder.crack(
            "begin 644 /dev/stdout\nM2&5L;&\\@;7D@;F%M92!I<R!B964@86YD($D@;&EK92!D;V<@86YD(&%P<&QE\n)(&%N9\"!T<F5E\n`\nend\n",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Hello my name is bee and I like dog and apple and tree"
        );
    }
}
