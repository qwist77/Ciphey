//! Lightweight native English scoring for brute-force crackers.

const COMMON_WORDS: [&str; 24] = [
    "the", "and", "that", "have", "for", "not", "with", "you", "this", "but", "his", "from",
    "they", "say", "her", "she", "will", "one", "all", "would", "there", "their", "what", "about",
];

/// Score candidate plaintext for rough English-likeness.
pub fn score_english(text: &str) -> f32 {
    if text.is_empty() {
        return f32::MIN;
    }

    let mut score = 0.0;
    let mut letters = 0usize;
    let mut vowels = 0usize;
    let mut spaces = 0usize;
    let mut printable = 0usize;

    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            letters += 1;
            let lower = ch.to_ascii_lowercase();
            if matches!(lower, 'e' | 't' | 'a' | 'o' | 'i' | 'n' | 's' | 'h' | 'r') {
                score += 2.0;
            } else {
                score += 1.0;
            }
            if matches!(lower, 'a' | 'e' | 'i' | 'o' | 'u') {
                vowels += 1;
            }
        } else if ch == ' ' {
            spaces += 1;
            score += 1.5;
        } else if ch.is_ascii_punctuation() {
            score += 0.2;
        }

        if ch.is_ascii_graphic() || ch.is_ascii_whitespace() {
            printable += 1;
        } else {
            score -= 8.0;
        }
    }

    let len = text.chars().count().max(1) as f32;
    score += 12.0 * printable as f32 / len;

    if letters > 0 {
        let vowel_ratio = vowels as f32 / letters as f32;
        score -= (vowel_ratio - 0.38).abs() * 10.0;
    }

    let space_ratio = spaces as f32 / len;
    score -= (space_ratio - 0.16).abs() * 8.0;

    let lower = text.to_ascii_lowercase();
    for word in COMMON_WORDS {
        if lower
            .split_whitespace()
            .any(|candidate| candidate.trim_matches(|ch: char| ch.is_ascii_punctuation()) == word)
        {
            score += 7.0;
        }
    }

    score
}
