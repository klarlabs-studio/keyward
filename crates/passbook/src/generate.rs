//! Password + passphrase generation, and the hash primitive for breach checks.
//!
//! Randomness comes from the shared kernel's CSPRNG ([`keyward_crypto::fill_random`]);
//! selection is unbiased (rejection sampling), and a generated password always
//! contains at least one character from each selected class. Passphrases draw
//! from the EFF Long Wordlist (7772 entries after removing hyphenated words),
//! giving 12.924 bits per word.
//!
//! Entropy is reported from the GENERATION PARAMETERS ([`passphrase_bits`]),
//! never re-estimated from the rendered string. Estimating a passphrase's
//! strength by character space is not conservative, it is simply wrong: it
//! cannot tell 5 uniform word draws from a same-length string a human invented.

use keyward_crypto::fill_random;
use sha1::{Digest, Sha1};
use std::sync::LazyLock;

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
    // 16-bit sample for the same reason as `shuffle`: a byte-sized rejection
    // limit collapses to 0 once n exceeds 256, which would spin forever. Every
    // caller today passes a character-class pool well under 256, but that was
    // guarded only by a `debug_assert!` that is compiled out of release builds.
    loop {
        let mut b = [0u8; 2];
        fill_random(&mut b);
        let sample = u16::from_le_bytes(b) as usize;
        let limit = 65_536 - (65_536 % n.min(65_536));
        if sample < limit {
            return chars[sample % n];
        }
    }
}

/// In-place Fisher–Yates shuffle using the CSPRNG.
fn shuffle(v: &mut [u8]) {
    for i in (1..v.len()).rev() {
        // Unbiased index in 0..=i, drawn from a 16-bit sample.
        //
        // A single byte is NOT enough: with `n > 256`, `256 % n == 256`, so the
        // old `256 - (256 % n)` rejection limit evaluated to 0, no draw could
        // ever fall below it, and the loop spun forever. `generate_password`
        // clamps only the lower bound on length, and both the WASM export and
        // the CLI accept an unbounded length, so `keyward generate 300` hung.
        let n = i + 1;
        let j = loop {
            let mut b = [0u8; 2];
            fill_random(&mut b);
            let sample = u16::from_le_bytes(b) as usize;
            // Largest multiple of n within the 16-bit range; reject above it to
            // avoid modulo bias. n <= u16::MAX here because v is a password
            // buffer, but the saturating form keeps this total regardless.
            let limit = 65_536 - (65_536 % n.min(65_536));
            if sample < limit {
                break sample % n;
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

/// Passphrase word list: the **EFF Long Wordlist** (7776 entries), minus the
/// four hyphenated entries — see `wordlist.txt`. 7772 words = 12.924 bits/word.
///
/// This replaced a hand-written 170-word list. That list was not merely small,
/// it was silently misreported: its own comment claimed "~200 words" and
/// "roughly 7.6 bits/word", while the real figures were 170 words and 7.409
/// bits/word, and `strength_bits` then re-estimated the rendered string by
/// character space — reporting 82–275 bits for phrases carrying 22–59. No
/// generated passphrase could be flagged Weak at any setting, and a 22-bit
/// phrase was labelled "Excellent". See `passphrase_bits` below for the fix.
///
/// Attribution (CC BY 3.0 US): "EFF Long Wordlist" by the Electronic Frontier
/// Foundation, https://www.eff.org/dice — see `wordlist.txt` for the full
/// notice. Chosen over BIP-39 because it is designed for human-typed
/// passphrases: no offensive entries, unique 3-character prefixes, and words
/// selected for spelling and recall rather than for seed encoding.
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("wordlist.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

/// Shannon entropy, in bits, of a passphrase of `words` words drawn uniformly
/// from `WORDS`. This is the ONLY honest way to score a generated passphrase:
/// entropy is a property of how the string was produced, not of how the
/// resulting characters look. Re-deriving it from the rendered text — as the
/// old character-space estimator did — cannot distinguish 5 uniform draws from
/// a 29-character string a human chose.
pub fn passphrase_bits(words: usize) -> f64 {
    words as f64 * (WORDS.len() as f64).log2()
}

/// True if `s` is exactly `separator`-joined tokens drawn from `WORDS`, in
/// which case the number of tokens is returned.
///
/// Used by `strength_bits` to recognise passphrase STRUCTURE and score it by
/// word entropy instead of character space. The list contains no entry
/// containing the separator (the hyphenated EFF entries were removed for
/// exactly this reason), so the split is unambiguous.
pub fn passphrase_word_count(s: &str, separator: &str) -> Option<usize> {
    if separator.is_empty() {
        return None;
    }
    let tokens: Vec<&str> = s.split(separator).collect();
    if tokens.len() < 2 {
        return None;
    }
    tokens
        .iter()
        .all(|t| WORDS.binary_search(t).is_ok())
        .then_some(tokens.len())
}

/// Generate a passphrase of `words` random words joined by `separator`.
///
/// Strictly rejection-sampled: a draw at or above the largest multiple of
/// `WORDS.len()` inside the 16-bit range is DISCARDED and redrawn.
///
/// The previous implementation instead fell back to `WORDS[b[0] % n]` on such a
/// draw, which is biased — `b[0]` is a single byte, so that expression can only
/// ever select from the first 256 words. With the old 170-word list the fallback
/// fired for ~0.16% of draws; with 7772 words it fires for ~5.1% of them,
/// concentrating one draw in twenty onto 3.3% of the list. Growing the wordlist
/// without removing the fallback would have made the bias substantially worse.
pub fn generate_passphrase(words: usize, separator: &str) -> String {
    let count = words.max(1);
    let n = WORDS.len();
    // Largest multiple of n inside 0..65_536; anything at or above is rejected.
    let limit = 65_536 - (65_536 % n);
    let mut chosen: Vec<&str> = Vec::with_capacity(count);
    while chosen.len() < count {
        let mut b = [0u8; 2];
        fill_random(&mut b);
        let sample = u16::from_le_bytes(b) as usize;
        if sample < limit {
            chosen.push(WORDS[sample % n]);
        }
        // else: discard and redraw — no fallback, no bias.
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
    fn wordlist_is_sorted_deduped_and_separator_free() {
        // binary_search in passphrase_word_count REQUIRES sorted input; an
        // unsorted list would silently fail lookups and send real passphrases
        // down the character-space path — reintroducing the bug this fixes.
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]), "not sorted/deduped");
        // No word may contain a separator the generator emits, or splitting a
        // phrase back into words is ambiguous and the entropy score over-counts.
        for sep in ["-", " ", ".", "_"] {
            assert!(
                !WORDS.iter().any(|w| w.contains(sep)),
                "word contains separator {sep:?}"
            );
        }
        assert!(
            WORDS.len() >= 7000,
            "list unexpectedly small: {}",
            WORDS.len()
        );
    }

    #[test]
    fn reported_entropy_matches_generation_parameters() {
        // The regression that shipped: reported bits were derived from the
        // rendered characters, so they tracked phrase LENGTH rather than the
        // number of draws. Here the two must agree exactly.
        for words in [3usize, 5, 8] {
            let expected = passphrase_bits(words) as u32;
            for _ in 0..200 {
                let p = generate_passphrase(words, "-");
                assert_eq!(p.split('-').count(), words);
                assert_eq!(
                    crate::watchtower::strength_bits(&p),
                    expected,
                    "phrase {p:?} scored by character space, not word entropy"
                );
            }
        }
        // 5 words is the UI default and must clear the Weak threshold (60) on
        // its own merits — previously it carried 37 real bits while reporting
        // over 80, so it cleared the bar only because the bar was misread.
        assert!(
            passphrase_bits(5) > 60.0,
            "default is weak: {}",
            passphrase_bits(5)
        );
        assert!(passphrase_bits(3) < 60.0, "3 words should read as weak");
    }

    #[test]
    fn shuffle_and_pick_terminate_past_the_256_cliff() {
        // `keyward generate 300` used to hang forever: the byte-sized rejection
        // limit collapsed to 0 for n > 256. The pre-existing test used 200,
        // just under the cliff, so it passed throughout.
        let o = PasswordOptions {
            length: 300,
            ..PasswordOptions::default()
        };
        assert_eq!(generate_password(&o).chars().count(), 300);
    }

    #[test]
    fn passphrase_draws_cover_the_whole_list() {
        // Guards the removed biased fallback, which could only ever return one
        // of the first 256 words and fired on ~5% of draws at this list size.
        let mut max_index = 0usize;
        for _ in 0..20_000 {
            let w = generate_passphrase(1, "-");
            let idx = WORDS
                .binary_search(&w.as_str())
                .expect("generated word not in list");
            max_index = max_index.max(idx);
        }
        assert!(
            max_index > 256,
            "20k draws never exceeded index {max_index} — sampling is truncated"
        );
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
