//! Binary file signatures used to keep byte carriers visible in crack output.

/// Score assigned to recovered byte carriers with known binary prefixes.
pub(crate) const BINARY_SIGNATURE_SCORE: f32 = 1000.0;

/// Known binary signatures that downstream decoders can validate.
pub(crate) const KNOWN_BINARY_SIGNATURES: [&[u8]; 8] = [
    b"\x1f\x8b\x08",
    b"PK\x03\x04",
    b"\x89PNG\r\n\x1a\n",
    b"%PDF-",
    b"\x7fELF",
    b"\xff\xd8\xff",
    b"BZh",
    b"\xfd7zXZ\x00",
];

/// Return a high score for byte output that starts with a known binary signature.
pub(crate) fn binary_signature_score(bytes: &[u8]) -> Option<f32> {
    KNOWN_BINARY_SIGNATURES
        .iter()
        .any(|signature| bytes.starts_with(signature))
        .then_some(BINARY_SIGNATURE_SCORE)
}
