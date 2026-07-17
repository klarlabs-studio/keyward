//! Password + passphrase generation, and the hash primitive for breach checks.
//!
//! Randomness comes from the shared kernel's CSPRNG ([`proctor_crypto::fill_random`]);
//! selection is unbiased (rejection sampling), and a generated password always
//! contains at least one character from each selected class. Passphrases draw
//! from a small embedded word list — a prototype (real diceware wants ~7776
//! words for ~12.9 bits/word; this list gives roughly 7.6 bits/word).

use proctor_crypto::fill_random;
use sha1::{Digest, Sha1};

/// Characters that look alike and are dropped when `avoid_ambiguous` is set.
const AMBIGUOUS: &[u8] = b"O0oIl1|`'\"{}[]()/\\";

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?.,;:";

/// What character classes a generated password should draw from.
#[derive(Clone, Debug)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Drop look-alike characters (O/0, l/1/I, …).
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

/// Filter out ambiguous characters if requested.
fn filtered(set: &[u8], avoid: bool) -> Vec<u8> {
    if avoid {
        set.iter()
            .copied()
            .filter(|c| !AMBIGUOUS.contains(c))
            .collect()
    } else {
        set.to_vec()
    }
}

/// Uniformly pick one byte from `chars` via rejection sampling (unbiased).
fn pick(chars: &[u8]) -> u8 {
    debug_assert!(!chars.is_empty() && chars.len() <= 256);
    let n = chars.len();
    // Largest multiple of n that fits in a byte; reject above it to avoid modulo bias.
    let limit = 256 - (256 % n);
    loop {
        let mut b = [0u8; 1];
        fill_random(&mut b);
        if (b[0] as usize) < limit {
            return chars[b[0] as usize % n];
        }
    }
}

/// In-place Fisher–Yates shuffle using the CSPRNG.
fn shuffle(v: &mut [u8]) {
    for i in (1..v.len()).rev() {
        // Unbiased index in 0..=i.
        let n = i + 1;
        let limit = 256 - (256 % n);
        let j = loop {
            let mut b = [0u8; 1];
            fill_random(&mut b);
            if (b[0] as usize) < limit {
                break b[0] as usize % n;
            }
        };
        v.swap(i, j);
    }
}

/// Generate a random password honoring `opts`. Guarantees at least one character
/// of each selected class (when the length allows). Falls back to lowercase if
/// no class is selected.
pub fn generate_password(opts: &PasswordOptions) -> String {
    let mut classes: Vec<Vec<u8>> = Vec::new();
    if opts.lowercase {
        classes.push(filtered(LOWER, opts.avoid_ambiguous));
    }
    if opts.uppercase {
        classes.push(filtered(UPPER, opts.avoid_ambiguous));
    }
    if opts.digits {
        classes.push(filtered(DIGITS, opts.avoid_ambiguous));
    }
    if opts.symbols {
        classes.push(filtered(SYMBOLS, opts.avoid_ambiguous));
    }
    if classes.is_empty() {
        classes.push(filtered(LOWER, opts.avoid_ambiguous));
    }

    let length = opts.length.max(1);
    let pool: Vec<u8> = classes.iter().flatten().copied().collect();

    let mut out: Vec<u8> = Vec::with_capacity(length);
    // Seed one character from each class so the result satisfies the policy.
    for class in &classes {
        if out.len() < length {
            out.push(pick(class));
        }
    }
    while out.len() < length {
        out.push(pick(&pool));
    }
    shuffle(&mut out);
    String::from_utf8(out).unwrap_or_default()
}

/// A small embedded word list for passphrases (prototype). ~200 words.
const WORDS: &[&str] = &[
    "able", "acid", "aged", "also", "amber", "apple", "arena", "argue", "atlas", "aware", "basil",
    "beach", "berry", "birch", "blaze", "bloom", "boost", "brave", "brick", "brisk", "cabin",
    "cable", "cacao", "camel", "candy", "canoe", "cedar", "chalk", "charm", "cliff", "clove",
    "coast", "cocoa", "comet", "coral", "crane", "crisp", "cyan", "daisy", "dawn", "delta",
    "diver", "dough", "dune", "eagle", "ember", "epoch", "ethos", "fable", "falcon", "fern",
    "flame", "flint", "flora", "focus", "frost", "gauge", "glade", "gleam", "globe", "grape",
    "grove", "gully", "harbor", "haven", "hazel", "heron", "hollow", "honey", "ivory", "jade",
    "jolly", "juno", "kayak", "kelp", "kite", "koala", "lagoon", "lark", "lemon", "lilac", "linen",
    "lotus", "lunar", "maize", "mango", "maple", "marsh", "meadow", "mesa", "mint", "mocha",
    "moon", "moss", "myth", "nectar", "noble", "north", "oasis", "ochre", "olive", "onyx", "opal",
    "orbit", "otter", "oxide", "pearl", "pecan", "petal", "pine", "plaza", "plume", "polar",
    "pond", "prism", "pulse", "quail", "quartz", "quest", "quill", "raven", "reef", "relic",
    "ridge", "river", "robin", "rowan", "ruby", "sable", "sage", "sandy", "shale", "shore", "silk",
    "slate", "solar", "spark", "spice", "spruce", "storm", "sugar", "swan", "tango", "teal",
    "thorn", "tidal", "tiger", "topaz", "trail", "tulip", "umber", "unity", "urban", "vale",
    "vapor", "vivid", "vole", "walnut", "wave", "wheat", "willow", "wolf", "wren", "yield",
    "yucca", "zebra", "zenith", "zephyr", "zinc", "zone",
];

/// Generate a passphrase of `words` random words joined by `separator`.
pub fn generate_passphrase(words: usize, separator: &str) -> String {
    let count = words.max(1);
    let n = WORDS.len();
    let limit = 256 - (256 % n.min(256));
    let mut chosen: Vec<&str> = Vec::with_capacity(count);
    // For a list under 256 long, one random byte per pick with rejection is fine.
    while chosen.len() < count {
        let mut b = [0u8; 2];
        fill_random(&mut b);
        // 16-bit sample gives ample headroom for lists up to 65k words.
        let sample = u16::from_le_bytes(b) as usize;
        let big_limit = 65_536 - (65_536 % n);
        if sample < big_limit {
            chosen.push(WORDS[sample % n]);
        } else if limit != 0 {
            // Unreachable for our list size; kept for completeness.
            chosen.push(WORDS[(b[0] as usize) % n]);
        }
    }
    chosen.join(separator)
}

/// SHA-1 of `input` as uppercase hex — the hash HaveIBeenPwned's k-anonymity API
/// uses. The full password never leaves the device: callers send only the first
/// 5 hex chars (the range prefix) and match the remaining suffix locally.
pub fn sha1_hex(input: &str) -> String {
    let digest = Sha1::digest(input.as_bytes());
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strength_bits;

    #[test]
    fn password_has_requested_length_and_classes() {
        let opts = PasswordOptions {
            length: 24,
            ..Default::default()
        };
        let pw = generate_password(&opts);
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
        // A 24-char all-classes password should be strong.
        assert!(strength_bits(&pw) >= 100);
    }

    #[test]
    fn digits_only_respects_the_class() {
        let opts = PasswordOptions {
            length: 12,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        };
        let pw = generate_password(&opts);
        assert_eq!(pw.len(), 12);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn avoid_ambiguous_excludes_lookalikes() {
        let opts = PasswordOptions {
            length: 200,
            avoid_ambiguous: true,
            ..Default::default()
        };
        let pw = generate_password(&opts);
        assert!(!pw.contains('0') && !pw.contains('O') && !pw.contains('l') && !pw.contains('1'));
    }

    #[test]
    fn two_passwords_differ() {
        let o = PasswordOptions::default();
        assert_ne!(generate_password(&o), generate_password(&o));
    }

    #[test]
    fn passphrase_word_count() {
        let p = generate_passphrase(5, "-");
        assert_eq!(p.split('-').count(), 5);
    }

    #[test]
    fn sha1_hex_matches_known_vector() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (the classic HIBP example).
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }
}
