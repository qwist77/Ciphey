//! Decode the Standard Galactic Alphabet.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// Standard Galactic Alphabet decoder.
pub struct GalacticDecoder;

impl Crack for Decoder<GalacticDecoder> {
    fn new() -> Decoder<GalacticDecoder> {
        Decoder {
            name: "galactic",
            description: "The Standard Galactic Alphabet is the symbol set used by Minecraft enchanting-table text.",
            link: "https://minecraft.fandom.com/wiki/Enchanting_Table",
            tags: vec!["galactic", "minecraft", "decoder"],
            popularity: 0.01,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Standard Galactic Alphabet with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_galactic(text) else {
            debug!("Galactic decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode galactic because check_string_success returned false on string {}",
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

fn decode_galactic(text: &str) -> Option<String> {
    let galactic_matches = text
        .chars()
        .filter(|ch| *ch != '!' && *ch != '|')
        .filter(|ch| galactic_symbol(*ch).is_some())
        .count();
    if galactic_matches == 0 {
        return None;
    }

    let modified = text
        .replace("||", "|")
        .replace('/', "")
        .replace('\u{00a1}', "")
        .replace(" \u{0323} ", "")
        .replace('\u{0307}', "x");

    let mut result = String::new();
    for letter in modified.chars() {
        if let Some(decoded) = galactic_symbol(letter) {
            result.push_str(decoded);
        } else {
            result.push(letter);
        }
    }
    Some(result.replace("x ", "x"))
}

fn galactic_symbol(ch: char) -> Option<&'static str> {
    match ch {
        '\u{1511}' => Some("a"),
        '\u{0296}' => Some("b"),
        '\u{14f5}' => Some("c"),
        '\u{21b8}' => Some("d"),
        '\u{14b7}' => Some("e"),
        '\u{2393}' => Some("f"),
        '\u{22a3}' => Some("g"),
        '\u{2351}' => Some("h"),
        '\u{254e}' => Some("i"),
        '\u{22ee}' => Some("j"),
        '\u{a58c}' => Some("k"),
        '\u{a58e}' => Some("l"),
        '\u{14b2}' => Some("m"),
        '\u{30ea}' => Some("n"),
        '\u{1d679}' => Some("o"),
        '!' => Some("p"),
        '\u{1451}' => Some("q"),
        '\u{2237}' => Some("r"),
        '\u{14ed}' => Some("s"),
        '\u{2138}' => Some("t"),
        '\u{268d}' => Some("u"),
        '\u{234a}' => Some("v"),
        '\u{2234}' => Some("w"),
        '|' => Some("y"),
        '\u{2a05}' => Some("z"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_galactic_symbols() {
        assert_eq!(
            decode_galactic("\u{1511}\u{0296}\u{14f5}"),
            Some("abc".to_string())
        );
    }

    #[test]
    fn leaves_unknown_characters_in_place() {
        assert_eq!(decode_galactic("\u{1511} 123"), Some("a 123".to_string()));
    }

    #[test]
    fn ignores_only_common_ascii_symbols_for_detection() {
        assert_eq!(decode_galactic("!|"), None);
    }
}
