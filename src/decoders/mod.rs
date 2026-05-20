//! This module contains all the code for decoders
//! Think of a decoder as a decryption method that doesn't require a key
//! The `interface.rs` defines what each decoder looks like.
//! Once you have made a decoder you need to add it to the filtration system's
//! mod.rs file
//! you will also need to make it a public module in this file.

/// The a1z26_decoder module decodes A1Z26
pub mod a1z26_decoder;
/// The ascii85_decoder module decodes ASCII85
pub mod ascii85_decoder;
/// The atbash_decoder module decodes atbash
pub mod atbash_decoder;
/// The base32_decoder module decodes base32
pub mod base32_decoder;
/// The base58_bitcoin_decoder module decodes base58 bitcoin
pub mod base58_bitcoin_decoder;
/// The base58_monero_decoder module decodes base58 monero
pub mod base58_monero_decoder;
/// The base62_decoder module decodes base62
pub mod base62_decoder;
/// The base69_decoder module decodes base69
pub mod base69_decoder;
/// The base85_decoder module decodes base85
pub mod base85_decoder;
/// The baudot_decoder module decodes Baudot code
pub mod baudot_decoder;
/// The binary_decoder module decodes binary
pub mod binary_decoder;
/// The hexadecimal_decoder module decodes hexadecimal
pub mod hexadecimal_decoder;

/// The base58_ripple_decoder module decodes base58 ripple
pub mod base58_ripple_decoder;

/// The base58_flickr decoder module decodes base58 flickr
pub mod base58_flickr_decoder;

/// The base64_decoder module decodes base64
/// It is public as we use it in some tests.
pub mod base64_decoder;
/// The base65536 module decodes base65536
pub mod base65536_decoder;
/// The base91_decoder module decodes base91
pub mod base91_decoder;
/// The citrix_ctx1_decoder module decodes citrix ctx1
pub mod citrix_ctx1_decoder;
/// The crack_results module defines the CrackResult
/// Each and every decoder return same CrackResult
pub mod crack_results;
/// The decimal_decoder module decodes decimal byte values
pub mod decimal_decoder;
/// The dna_decoder module decodes DNA codons
pub mod dna_decoder;
/// The dtmf_decoder module decodes DTMF frequency pairs
pub mod dtmf_decoder;
/// The galactic_decoder module decodes Standard Galactic Alphabet
pub mod galactic_decoder;
/// The leetspeak_decoder module decodes leetspeak
pub mod leetspeak_decoder;
/// The url_decoder module decodes url
pub mod url_decoder;

/// The interface module defines the interface for decoders
/// Each and every decoder has the same struct & traits
pub mod interface;

/// The reverse_decoder module decodes reverse text
/// Stac -> Cats
/// It is public as we use it in some tests.
pub mod reverse_decoder;

/// The morse_code module decodes morse code
/// It is public as we use it in some tests.
pub mod morse_code;
/// The multi_tap_decoder module decodes multi-tap phone keypad codes
pub mod multi_tap_decoder;
/// The octal_decoder module decodes octal byte values
pub mod octal_decoder;

/// For the caesar cipher decoder
pub mod caesar_decoder;

/// For the railfence cipher decoder
pub mod railfence_decoder;
/// For the rot47 decoder
pub mod rot47_decoder;

/// The tap_code_decoder module decodes tap code coordinates
pub mod tap_code_decoder;
/// For the z85 cipher decoder
pub mod z85_decoder;

/// For the braille decoder
pub mod braille_decoder;

/// The substitution_generic_decoder module handles generic substitution ciphers
pub mod substitution_generic_decoder;

/// A brainfuck interpreter
pub mod brainfuck_interpreter;

/// The vigenere_decoder module decodes Vigenère cipher text
pub mod vigenere_decoder;

use ascii85_decoder::Ascii85Decoder;
use atbash_decoder::AtbashDecoder;
use base32_decoder::Base32Decoder;
use base58_bitcoin_decoder::Base58BitcoinDecoder;
use base58_flickr_decoder::Base58FlickrDecoder;
use base58_monero_decoder::Base58MoneroDecoder;
use base58_ripple_decoder::Base58RippleDecoder;
use base62_decoder::Base62Decoder;
use base69_decoder::Base69Decoder;
use base85_decoder::Base85Decoder;
use baudot_decoder::BaudotDecoder;
use binary_decoder::BinaryDecoder;
use hexadecimal_decoder::HexadecimalDecoder;
use interface::{Crack, Decoder};

use a1z26_decoder::A1Z26Decoder;
use base64_decoder::Base64Decoder;
use base65536_decoder::Base65536Decoder;
use base91_decoder::Base91Decoder;
use braille_decoder::BrailleDecoder;
use caesar_decoder::CaesarDecoder;
use citrix_ctx1_decoder::CitrixCTX1Decoder;
use decimal_decoder::DecimalDecoder;
use dna_decoder::DnaDecoder;
use dtmf_decoder::DtmfDecoder;
use galactic_decoder::GalacticDecoder;
use leetspeak_decoder::LeetspeakDecoder;
use morse_code::MorseCodeDecoder;
use multi_tap_decoder::MultiTapDecoder;
use octal_decoder::OctalDecoder;
use railfence_decoder::RailfenceDecoder;
use reverse_decoder::ReverseDecoder;
use rot47_decoder::ROT47Decoder;
use substitution_generic_decoder::SubstitutionGenericDecoder;
use tap_code_decoder::TapCodeDecoder;
use url_decoder::URLDecoder;
use vigenere_decoder::VigenereDecoder;
use z85_decoder::Z85Decoder;

use brainfuck_interpreter::BrainfuckInterpreter;

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Enum for annotating Decoder types, specifically for retrieving decoders from
/// DECODER_MAP
pub enum DecoderType {
    /// default decoder
    DefaultDecoder(interface::DefaultDecoder),
    /// a1z26 decoder
    A1z26Decoder(a1z26_decoder::A1Z26Decoder),
    /// atbash decoder
    AtbashDecoder(atbash_decoder::AtbashDecoder),
    /// ascii85 decoder
    Ascii85Decoder(ascii85_decoder::Ascii85Decoder),
    /// baudot decoder
    BaudotDecoder(baudot_decoder::BaudotDecoder),
    /// base32 decoder
    Base32Decoder(base32_decoder::Base32Decoder),
    /// base62 decoder
    Base62Decoder(base62_decoder::Base62Decoder),
    /// base69 decoder
    Base69Decoder(base69_decoder::Base69Decoder),
    /// base85 decoder
    Base85Decoder(base85_decoder::Base85Decoder),
    /// base58 bitcoin decoder
    Base58BitcoinDecoder(base58_bitcoin_decoder::Base58BitcoinDecoder),
    /// base58 monero decoder
    Base58MoneroDecoder(base58_monero_decoder::Base58MoneroDecoder),
    /// binary decoder
    BinaryDecoder(binary_decoder::BinaryDecoder),
    /// hexadecimal decoder
    HexadecimalDecoder(hexadecimal_decoder::HexadecimalDecoder),
    /// base58 ripple decoder
    Base58RippleDecoder(base58_ripple_decoder::Base58RippleDecoder),
    /// base58 flickr decoder
    Base58FlickrDecoder(base58_flickr_decoder::Base58FlickrDecoder),
    /// base64 decoder
    Base64Decoder(base64_decoder::Base64Decoder),
    /// base65536 decoder
    Base65536Decoder(base65536_decoder::Base65536Decoder),
    /// base91 decoder
    Base91Decoder(base91_decoder::Base91Decoder),
    /// citrix ctx1 decoder
    CitrixCtx1Decoder(citrix_ctx1_decoder::CitrixCTX1Decoder),
    /// decimal decoder
    DecimalDecoder(decimal_decoder::DecimalDecoder),
    /// dna decoder
    DnaDecoder(dna_decoder::DnaDecoder),
    /// dtmf decoder
    DtmfDecoder(dtmf_decoder::DtmfDecoder),
    /// galactic decoder
    GalacticDecoder(galactic_decoder::GalacticDecoder),
    /// leetspeak decoder
    LeetspeakDecoder(leetspeak_decoder::LeetspeakDecoder),
    /// url decoder
    UrlDecoder(url_decoder::URLDecoder),
    /// reverse decoder
    ReverseDecoder(reverse_decoder::ReverseDecoder),
    /// morse decoder
    MorseCode(morse_code::MorseCodeDecoder),
    /// multi-tap decoder
    MultiTapDecoder(multi_tap_decoder::MultiTapDecoder),
    /// octal decoder
    OctalDecoder(octal_decoder::OctalDecoder),
    /// caesar decoder
    CaesarDecoder(caesar_decoder::CaesarDecoder),
    /// railfence decoder
    RailfenceDecoder(railfence_decoder::RailfenceDecoder),
    /// rot47 decoder
    Rot47Decoder(rot47_decoder::ROT47Decoder),
    /// z85 decoder
    Z85Decoder(z85_decoder::Z85Decoder),
    /// tap code decoder
    TapCodeDecoder(tap_code_decoder::TapCodeDecoder),
    /// braille decoder
    BrailleDecoder(braille_decoder::BrailleDecoder),
    /// substitution decoder
    SubstitutionGenericDecoder(substitution_generic_decoder::SubstitutionGenericDecoder),
    /// brainfuck interpreter
    BrainfuckInterpreter(brainfuck_interpreter::BrainfuckInterpreter),
    /// vigenere decoder
    VigenereDecoder(vigenere_decoder::VigenereDecoder),
}

/// Wrapper struct to hold Decoders for DECODER_MAP
pub struct DecoderBox {
    /// Wrapper box to hold Decoders for DECODER_MAP
    value: Box<dyn Crack + Sync + Send>,
}

impl DecoderBox {
    /// Constructor for DecoderBox. Takes in a Decoder and stores it as the
    /// internal value
    fn new<T: 'static + Crack + Sync + Send>(value: T) -> Self {
        Self {
            value: Box::new(value),
        }
    }

    /// Getter method for DecoderBox to return the internal Box
    pub fn get<T: 'static>(&self) -> &(dyn Crack + Sync + Send) {
        self.value.as_ref()
    }
}

/// Global hashmap for translating strings to Decoders
pub static DECODER_MAP: Lazy<HashMap<&str, DecoderBox>> = Lazy::new(|| {
    HashMap::from([
        (
            "Default decoder",
            DecoderBox::new(Decoder::<interface::DefaultDecoder>::new()),
        ),
        (
            "Vigenere",
            DecoderBox::new(Decoder::<VigenereDecoder>::new()),
        ),
        ("Binary", DecoderBox::new(Decoder::<BinaryDecoder>::new())),
        (
            "Hexadecimal",
            DecoderBox::new(Decoder::<HexadecimalDecoder>::new()),
        ),
        (
            "Base58 Bitcoin",
            DecoderBox::new(Decoder::<Base58BitcoinDecoder>::new()),
        ),
        (
            "Base58 Monero",
            DecoderBox::new(Decoder::<Base58MoneroDecoder>::new()),
        ),
        (
            "Base58 Ripple",
            DecoderBox::new(Decoder::<Base58RippleDecoder>::new()),
        ),
        (
            "Base58 Flickr",
            DecoderBox::new(Decoder::<Base58FlickrDecoder>::new()),
        ),
        ("Base64", DecoderBox::new(Decoder::<Base64Decoder>::new())),
        ("Base91", DecoderBox::new(Decoder::<Base91Decoder>::new())),
        (
            "Base65536",
            DecoderBox::new(Decoder::<Base65536Decoder>::new()),
        ),
        (
            "Citrix Ctx1",
            DecoderBox::new(Decoder::<CitrixCTX1Decoder>::new()),
        ),
        ("decimal", DecoderBox::new(Decoder::<DecimalDecoder>::new())),
        ("baudot", DecoderBox::new(Decoder::<BaudotDecoder>::new())),
        ("dna", DecoderBox::new(Decoder::<DnaDecoder>::new())),
        ("dtmf", DecoderBox::new(Decoder::<DtmfDecoder>::new())),
        (
            "galactic",
            DecoderBox::new(Decoder::<GalacticDecoder>::new()),
        ),
        (
            "leetspeak",
            DecoderBox::new(Decoder::<LeetspeakDecoder>::new()),
        ),
        ("URL", DecoderBox::new(Decoder::<URLDecoder>::new())),
        ("ascii85", DecoderBox::new(Decoder::<Ascii85Decoder>::new())),
        ("Base62", DecoderBox::new(Decoder::<Base62Decoder>::new())),
        ("Base69", DecoderBox::new(Decoder::<Base69Decoder>::new())),
        ("Base85", DecoderBox::new(Decoder::<Base85Decoder>::new())),
        ("Base32", DecoderBox::new(Decoder::<Base32Decoder>::new())),
        ("Reverse", DecoderBox::new(Decoder::<ReverseDecoder>::new())),
        (
            "Morse Code",
            DecoderBox::new(Decoder::<MorseCodeDecoder>::new()),
        ),
        (
            "multi_tap",
            DecoderBox::new(Decoder::<MultiTapDecoder>::new()),
        ),
        ("octal", DecoderBox::new(Decoder::<OctalDecoder>::new())),
        ("atbash", DecoderBox::new(Decoder::<AtbashDecoder>::new())),
        ("caesar", DecoderBox::new(Decoder::<CaesarDecoder>::new())),
        (
            "railfence",
            DecoderBox::new(Decoder::<RailfenceDecoder>::new()),
        ),
        ("rot47", DecoderBox::new(Decoder::<ROT47Decoder>::new())),
        ("Z85", DecoderBox::new(Decoder::<Z85Decoder>::new())),
        (
            "tap_code",
            DecoderBox::new(Decoder::<TapCodeDecoder>::new()),
        ),
        ("a1z26", DecoderBox::new(Decoder::<A1Z26Decoder>::new())),
        ("Braille", DecoderBox::new(Decoder::<BrailleDecoder>::new())),
        (
            "simplesubstitution",
            DecoderBox::new(Decoder::<SubstitutionGenericDecoder>::new()),
        ),
        (
            "Brainfuck",
            DecoderBox::new(Decoder::<BrainfuckInterpreter>::new()),
        ),
    ])
});
