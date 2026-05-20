//! Decode DNA codons into amino-acid one-letter codes.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use log::{debug, info, trace};

/// DNA codon decoder.
pub struct DnaDecoder;

impl Crack for Decoder<DnaDecoder> {
    fn new() -> Decoder<DnaDecoder> {
        Decoder {
            name: "dna",
            description:
                "DNA codon encoding maps nucleotide triplets to amino-acid one-letter codes.",
            link: "https://en.wikipedia.org/wiki/DNA_codon_table",
            tags: vec!["dna", "biology", "decoder"],
            popularity: 0.2,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying DNA with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let Some(decoded_text) = decode_dna(text) else {
            debug!("DNA decode failed");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode dna because check_string_success returned false on string {}",
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

fn decode_dna(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|ch| !matches!(ch, ',' | ';' | ':' | '-') && !ch.is_whitespace())
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(3) {
        return None;
    }

    let mut result = String::new();
    for codon in cleaned.as_bytes().chunks(3) {
        result.push_str(dna_codon(std::str::from_utf8(codon).ok()?)?);
    }
    Some(result)
}

fn dna_codon(codon: &str) -> Option<&'static str> {
    match codon {
        "GCT" | "GCC" | "GCA" | "GCG" => Some("A"),
        "TGT" | "TGC" => Some("C"),
        "GAT" | "GAC" => Some("D"),
        "GAA" | "GAG" => Some("E"),
        "TTT" | "TTC" => Some("F"),
        "GGT" | "GGC" | "GGA" | "GGG" => Some("G"),
        "CAT" | "CAC" => Some("H"),
        "ATT" | "ATC" | "ATA" => Some("I"),
        "AAA" | "AAG" => Some("K"),
        "TTA" | "TTG" | "CTT" | "CTC" | "CTA" | "CTG" => Some("L"),
        "ATG" => Some("M"),
        "AAT" | "AAC" => Some("N"),
        "CCT" | "CCC" | "CCA" | "CCG" => Some("P"),
        "CAA" | "CAG" => Some("Q"),
        "CGT" | "CGC" | "CGA" | "CGG" | "AGA" | "AGG" => Some("R"),
        "TCT" | "TCC" | "TCA" | "TCG" | "AGT" | "AGC" => Some("S"),
        "ACT" | "ACC" | "ACA" | "ACG" => Some("T"),
        "GTT" | "GTC" | "GTA" | "GTG" => Some("V"),
        "TGG" => Some("W"),
        "TAT" | "TAC" => Some("Y"),
        "TAA" | "TAG" | "TGA" => Some("."),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_dna_codons() {
        assert_eq!(decode_dna("GCTTGTGATTAA"), Some("ACD.".to_string()));
    }

    #[test]
    fn rejects_rna_codons() {
        assert_eq!(decode_dna("GCU"), None);
    }

    #[test]
    fn rejects_incomplete_trailing_codon() {
        assert_eq!(decode_dna("GCTA"), None);
    }

    #[test]
    fn decodes_standard_codon_table_example() {
        assert_eq!(
            decode_dna("ATGGCCATTGTAATGGGCCGCTGAAAGGGTGCCCGATAG"),
            Some("MAIVMGR.KGAR.".to_string())
        );
    }
}
