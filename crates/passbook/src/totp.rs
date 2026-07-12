//! TOTP (RFC 6238) — generate the rolling 2FA codes a password manager shows
//! next to a login, so the user never juggles a separate authenticator app.

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// HOTP (RFC 4226): a `digits`-length code for a counter value.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    bin % 10u32.pow(digits)
}

/// TOTP code for a base32 secret at `unix_time`, with a `step` window and
/// `digits` length (defaults: 30s / 6 digits — see [`code_now`]).
pub fn code_at(secret_base32: &str, unix_time: u64, step: u64, digits: u32) -> Option<String> {
    let secret = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        secret_base32
            .trim()
            .replace(' ', "")
            .to_uppercase()
            .as_str(),
    )?;
    if secret.is_empty() {
        return None;
    }
    let counter = unix_time / step;
    let code = hotp(&secret, counter, digits);
    Some(format!("{code:0width$}", width = digits as usize))
}

/// The current 6-digit / 30-second code for a base32 secret.
pub fn code_now(secret_base32: &str, unix_time: u64) -> Option<String> {
    code_at(secret_base32, unix_time, 30, 6)
}

/// Seconds remaining in the current 30-second window (for the countdown ring).
pub fn seconds_remaining(unix_time: u64, step: u64) -> u64 {
    step - (unix_time % step)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vector: ASCII secret "12345678901234567890"
    // (base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") with SHA-1, 8 digits.
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_rfc6238_vector() {
        // At T = 59s the RFC expects 94287082 (8 digits, SHA-1).
        assert_eq!(code_at(RFC_SECRET_B32, 59, 30, 8).unwrap(), "94287082");
        // At T = 1111111109s the RFC expects 07081804.
        assert_eq!(
            code_at(RFC_SECRET_B32, 1_111_111_109, 30, 8).unwrap(),
            "07081804"
        );
    }

    #[test]
    fn six_digit_code_is_stable_within_a_window() {
        let a = code_now(RFC_SECRET_B32, 100).unwrap();
        let b = code_now(RFC_SECRET_B32, 115).unwrap(); // same 30s window
        assert_eq!(a.len(), 6);
        assert_eq!(a, b);
    }

    #[test]
    fn countdown_wraps() {
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(29, 30), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
    }

    #[test]
    fn junk_secret_is_none_not_panic() {
        assert!(code_now("not!base32!", 0).is_none());
    }
}
