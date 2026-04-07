use ciphey::checkers::{
    athena::Athena,
    checker_type::{Check, Checker},
    wordlist::WordlistChecker,
    CheckerTypes,
};
use ciphey::config::Config;
use ciphey::decoders::interface::{Crack, Decoder};
use ciphey::{perform_cracking, set_test_db_path, TestDatabase};

fn get_athena_checker() -> CheckerTypes {
    let athena_checker = Checker::<Athena>::new();
    CheckerTypes::CheckAthena(athena_checker)
}

pub fn assert_decoder_output<T>(encoded: &str, expected: &str)
where
    Decoder<T>: Crack,
{
    let result = Decoder::<T>::new().crack(encoded, &get_athena_checker());
    let decoded = result
        .unencrypted_text
        .unwrap_or_else(|| panic!("failed to decode CTF sample: {encoded}"));

    assert_eq!(decoded[0], expected);
}

pub fn assert_decoder_candidates_contain<T>(encoded: &str, expected: &str)
where
    Decoder<T>: Crack,
{
    let checker = CheckerTypes::CheckWordlist(Checker::<WordlistChecker>::new());
    let result = Decoder::<T>::new().crack(encoded, &checker);
    let decoded = result
        .unencrypted_text
        .unwrap_or_else(|| panic!("failed to decode CTF sample: {encoded}"));

    assert!(
        decoded.iter().any(|candidate| candidate == expected),
        "expected candidate not found for CTF sample: {encoded}",
    );
}

#[allow(dead_code)]
pub fn assert_perform_cracking_contains(encoded: &str, expected: &str) {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let config = Config::default();
    let result = perform_cracking(encoded, config)
        .unwrap_or_else(|| panic!("perform_cracking returned no result for CTF sample: {encoded}"));

    assert!(
        result.text.iter().any(|candidate| candidate == expected),
        "expected plaintext not found for CTF sample: {encoded}; got {:?}",
        result.text,
    );
}
