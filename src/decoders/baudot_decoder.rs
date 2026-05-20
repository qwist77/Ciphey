//! Decode Baudot code.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Baudot decoder.
pub struct BaudotDecoder;

impl Crack for Decoder<BaudotDecoder> {
    fn new() -> Decoder<BaudotDecoder> {
        Decoder {
            name: "baudot",
            description: "Baudot code is a 5-bit teleprinter character encoding with letter and figure shift states.",
            link: "https://en.wikipedia.org/wiki/Baudot_code",
            tags: vec!["baudot", "teleprinter", "decoder"],
            popularity: 0.05,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Baudot with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_baudot(text) else {
            debug!("Baudot decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode baudot because check_string_success returned false on string {}",
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

fn decode_baudot(text: &str) -> Option<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.is_empty()
        || !tokens[0].chars().all(|ch| matches!(ch, '0' | '1'))
        || tokens[0].len() != 5
    {
        return None;
    }

    let mut figure_shift = false;
    let mut result = String::new();
    for token in tokens {
        if token.len() != 5 || !token.chars().all(|ch| matches!(ch, '0' | '1')) {
            return None;
        }
        if token == "11011" {
            figure_shift = true;
        }
        if token == "11111" {
            figure_shift = false;
        }
        result.push_str(baudot_symbol(token, figure_shift)?);
    }
    Some(result)
}

fn baudot_symbol(token: &str, figure_shift: bool) -> Option<&'static str> {
    match (figure_shift, token) {
        (_, "00000") | (_, "11011") | (_, "11111") => Some(""),
        (_, "00100") => Some(" "),
        (false, "00011") => Some("A"),
        (false, "11001") => Some("B"),
        (false, "01110") => Some("C"),
        (false, "01001") => Some("D"),
        (false, "00001") => Some("E"),
        (false, "01101") => Some("F"),
        (false, "11010") => Some("G"),
        (false, "10100") => Some("H"),
        (false, "00110") => Some("I"),
        (false, "01011") => Some("J"),
        (false, "01111") => Some("K"),
        (false, "10010") => Some("L"),
        (false, "11100") => Some("M"),
        (false, "01100") => Some("N"),
        (false, "11000") => Some("O"),
        (false, "10110") => Some("P"),
        (false, "10111") => Some("Q"),
        (false, "01010") => Some("R"),
        (false, "00101") => Some("S"),
        (false, "10000") => Some("T"),
        (false, "00111") => Some("U"),
        (false, "11110") => Some("V"),
        (false, "10011") => Some("W"),
        (false, "11101") => Some("X"),
        (false, "10101") => Some("Y"),
        (false, "10001") => Some("Z"),
        (true, "00011") => Some("-"),
        (true, "11001") => Some("?"),
        (true, "01110") => Some(":"),
        (true, "01001") => Some("$"),
        (true, "00001") => Some("3"),
        (true, "01101") => Some("!"),
        (true, "11010") => Some("&"),
        (true, "10100") => Some("#"),
        (true, "00110") => Some("8"),
        (true, "01011") => Some("\""),
        (true, "00101") => Some("BELL"),
        (true, "01111") => Some("("),
        (true, "10010") => Some(")"),
        (true, "11100") => Some("."),
        (true, "01100") => Some(","),
        (true, "11000") => Some("9"),
        (true, "10110") => Some("0"),
        (true, "10111") => Some("1"),
        (true, "01010") => Some("4"),
        (true, "10000") => Some("5"),
        (true, "00111") => Some("7"),
        (true, "11110") => Some(";"),
        (true, "10011") => Some("2"),
        (true, "11101") => Some("/"),
        (true, "10101") => Some("6"),
        (true, "10001") => Some("\""),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_letters() {
        assert_eq!(
            decode_baudot("10100 00001 10010 10010 11000"),
            Some("HELLO".to_string())
        );
    }

    #[test]
    fn decodes_figure_shift_state() {
        assert_eq!(
            decode_baudot("11011 00001 00110 11111 00011"),
            Some("38A".to_string())
        );
    }

    #[test]
    fn rejects_non_bit_token() {
        assert_eq!(decode_baudot("10100 hello"), None);
    }
}
