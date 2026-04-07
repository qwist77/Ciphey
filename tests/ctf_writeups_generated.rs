#![cfg(feature = "ctf-corpus-tests")]
#![allow(dead_code, unused_imports)]

mod support;

use ciphey::decoders::{
    a1z26_decoder::A1Z26Decoder, atbash_decoder::AtbashDecoder, base32_decoder::Base32Decoder,
    base58_bitcoin_decoder::Base58BitcoinDecoder, base58_flickr_decoder::Base58FlickrDecoder,
    base58_monero_decoder::Base58MoneroDecoder, base58_ripple_decoder::Base58RippleDecoder,
    base64_decoder::Base64Decoder, base65536_decoder::Base65536Decoder,
    base91_decoder::Base91Decoder, binary_decoder::BinaryDecoder, braille_decoder::BrailleDecoder,
    brainfuck_interpreter::BrainfuckInterpreter, caesar_decoder::CaesarDecoder,
    hexadecimal_decoder::HexadecimalDecoder, morse_code::MorseCodeDecoder,
    reverse_decoder::ReverseDecoder, rot47_decoder::ROT47Decoder,
    substitution_generic_decoder::SubstitutionGenericDecoder, url_decoder::URLDecoder,
    vigenere_decoder::VigenereDecoder, z85_decoder::Z85Decoder,
};
use serial_test::serial;
use support::ctf_writeups::{
    assert_decoder_candidates_contain, assert_decoder_output, assert_perform_cracking_contains,
};

include!("generated/ctf_writeups_generated.inc.rs");
