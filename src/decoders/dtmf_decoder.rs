//! Decode DTMF frequency pairs.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// DTMF decoder.
pub struct DtmfDecoder;

impl Crack for Decoder<DtmfDecoder> {
    fn new() -> Decoder<DtmfDecoder> {
        Decoder {
            name: "dtmf",
            description:
                "DTMF encodes telephone keypad symbols as low and high audio frequency pairs.",
            link: "https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling",
            tags: vec!["dtmf", "phone", "decoder"],
            popularity: 0.2,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying DTMF with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_dtmf(text) else {
            debug!("DTMF decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode dtmf because check_string_success returned false on string {}",
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

fn decode_dtmf(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|ch| !matches!(ch, ',' | ';' | ':' | '-' | '/') && !ch.is_whitespace())
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(7) {
        return None;
    }

    let mut result = String::new();
    for chunk in cleaned.as_bytes().chunks(7) {
        result.push_str(dtmf_symbol(std::str::from_utf8(chunk).ok()?)?);
    }
    Some(result)
}

fn dtmf_symbol(chunk: &str) -> Option<&'static str> {
    match chunk {
        "1209697" | "6971209" => Some("1"),
        "1336697" | "6971336" => Some("2"),
        "1477697" | "6971477" => Some("3"),
        "1633697" | "6971633" => Some("A"),
        "1209770" | "7701209" => Some("4"),
        "1336770" | "7701336" => Some("5"),
        "1477770" | "7701477" => Some("6"),
        "1633770" | "7701633" => Some("B"),
        "1209852" | "8521209" => Some("7"),
        "1336852" | "8521336" => Some("8"),
        "1477852" | "8521477" => Some("9"),
        "1633852" | "8521633" => Some("C"),
        "1209941" | "9411209" => Some("*"),
        "1336941" | "9411336" => Some("0"),
        "1477941" | "9411477" => Some("#"),
        "1633941" | "9411633" => Some("D"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_dtmf_frequency_pairs() {
        assert_eq!(decode_dtmf("16336976971336"), Some("A2".to_string()));
    }

    #[test]
    fn decodes_delimited_pairs() {
        assert_eq!(decode_dtmf("1209/697,1336/697"), Some("12".to_string()));
    }

    #[test]
    fn rejects_incomplete_chunk() {
        assert_eq!(decode_dtmf("163369"), None);
    }

    #[test]
    fn decodes_full_dtmf_keypad_matrix() {
        assert_eq!(
            decode_dtmf("697/1209 697/1336 697/1477 697/1633 770/1209 770/1336 770/1477 770/1633 852/1209 852/1336 852/1477 852/1633 941/1209 941/1336 941/1477 941/1633"),
            Some("123A456B789C*0#D".to_string())
        );
    }
}
