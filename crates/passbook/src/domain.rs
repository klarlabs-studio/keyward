//! Domain model — the entities and value objects of the Passbook context.
//!
//! [`Entry`] is the entity (it has identity: `id`). [`Login`], [`Card`],
//! [`Identity`], [`Category`] and [`SecretKey`] are value objects — defined by
//! their attributes, not an identity. Secret-bearing fields zeroize on drop.

use crate::PassbookError;
use keyward_crypto::random_array;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The category of a vault entry (drives the icon + fields in the UI).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Login,
    SecureNote,
    Card,
    Identity,
}

/// A synced passkey (WebAuthn credential) held by a [`Login`].
///
/// This is the *data model* for a multi-device ("synced") passkey the vault
/// stores and syncs across a user's devices. The WebAuthn create/get ceremony
/// that actually generates `private_key` needs a browser and lives in a
/// separate slice — this value object only defines *where* that result lives.
/// `private_key` is secret key material, so it zeroizes on drop exactly like
/// [`Login::password`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// The WebAuthn credential id (base64url, unpadded).
    pub credential_id: String,
    /// The relying-party id — the origin/domain this passkey authenticates to.
    pub rp_id: String,
    /// The user handle the relying party knows this credential by (base64url).
    pub user_handle: String,
    /// Unix epoch seconds at which the credential was created.
    pub created_epoch: u64,
    /// Opaque private-key material produced by the ceremony slice (e.g. a
    /// PKCS#8/COSE key encoded base64url). Secret — zeroized on drop.
    pub private_key: String,
}

impl Drop for PasskeyCredential {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// A website/app login — the most common entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    /// TOTP shared secret (base32), if the account has 2FA.
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// Synced passkeys stored for this login (a login may have a password
    /// and/or one or more passkeys). `#[serde(default)]` so vaults sealed
    /// before this field existed — which lack the key entirely — still open,
    /// deserializing to an empty vec rather than failing.
    #[serde(default)]
    pub passkeys: Vec<PasskeyCredential>,
}

impl Drop for Login {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(s) = self.totp_secret.as_mut() {
            s.zeroize();
        }
        // Each PasskeyCredential zeroizes its own private_key on drop; the
        // `passkeys` vec is dropped automatically after this runs.
    }
}

/// A payment card.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Card {
    pub cardholder: String,
    pub number: String,
    pub expiry: String,
    pub cvv: String,
}

impl Drop for Card {
    fn drop(&mut self) {
        self.number.zeroize();
        self.cvv.zeroize();
    }
}

/// An identity (for form-fill).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Identity {
    pub full_name: String,
    pub email: String,
    pub phone: String,
    pub address: String,
}

/// The category-specific content of an entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Content {
    Login(Login),
    SecureNote(String),
    Card(Card),
    Identity(Identity),
}

impl Content {
    pub fn category(&self) -> Category {
        match self {
            Content::Login(_) => Category::Login,
            Content::SecureNote(_) => Category::SecureNote,
            Content::Card(_) => Category::Card,
            Content::Identity(_) => Category::Identity,
        }
    }
}

/// A vault entry: a titled, tagged, categorized credential. The aggregate's
/// entity — identified by `id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub updated_epoch: u64,
    pub content: Content,
}

impl Entry {
    pub fn login(id: &str, title: &str, username: &str, password: &str) -> Entry {
        Entry {
            id: id.into(),
            title: title.into(),
            tags: Vec::new(),
            favorite: false,
            updated_epoch: 0,
            content: Content::Login(Login {
                username: username.into(),
                password: password.into(),
                urls: Vec::new(),
                totp_secret: None,
                passkeys: Vec::new(),
            }),
        }
    }

    pub fn category(&self) -> Category {
        self.content.category()
    }
}

/// A 128-bit device-generated Secret Key (a value object). Combined with the
/// master password so a server breach yields data uncrackable without *both*
/// secrets (à la 1Password's two-secret key derivation).
#[derive(Clone)]
pub struct SecretKey([u8; 16]);

impl SecretKey {
    /// Generate a fresh random Secret Key.
    pub fn generate() -> Self {
        SecretKey(random_array::<16>())
    }

    /// Render as a grouped hex string for the Emergency Kit (e.g. `A3F1-9C..`).
    pub fn emergency_kit_format(&self) -> String {
        let hex: String = self.0.iter().map(|b| format!("{b:02X}")).collect();
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse an Emergency-Kit Secret Key (32 hex digits; grouping ignored).
    pub fn parse(s: &str) -> Result<Self, PassbookError> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if clean.len() != 32 {
            return Err(PassbookError::SecretKey);
        }
        let mut k = [0u8; 16];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                .map_err(|_| PassbookError::SecretKey)?;
        }
        Ok(SecretKey(k))
    }

    /// The raw key bytes — crate-internal, for the sealing service to fold into
    /// key derivation.
    pub(crate) fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_emergency_kit_roundtrips() {
        let sk = SecretKey::generate();
        let printed = sk.emergency_kit_format();
        assert!(printed.contains('-'));
        let parsed = SecretKey::parse(&printed).unwrap();
        assert_eq!(sk.bytes(), parsed.bytes());
    }

    #[test]
    fn category_follows_content() {
        assert_eq!(
            Content::SecureNote("x".into()).category(),
            Category::SecureNote
        );
        assert_eq!(Entry::login("i", "t", "u", "p").category(), Category::Login);
    }

    #[test]
    fn login_with_passkey_serde_roundtrips() {
        let login = Login {
            username: "octo".into(),
            password: "s3cr3t".into(),
            urls: Vec::new(),
            totp_secret: None,
            passkeys: vec![PasskeyCredential {
                credential_id: "Y3JlZC1pZA".into(),
                rp_id: "github.com".into(),
                user_handle: "dXNlci1oYW5kbGU".into(),
                created_epoch: 1_700_000_000,
                private_key: "cHJpdmF0ZS1rZXktYnl0ZXM".into(),
            }],
        };

        let json = serde_json::to_string(&login).unwrap();
        let back: Login = serde_json::from_str(&json).unwrap();

        assert_eq!(back.passkeys.len(), 1);
        let pk = &back.passkeys[0];
        assert_eq!(pk.credential_id, "Y3JlZC1pZA");
        assert_eq!(pk.rp_id, "github.com");
        assert_eq!(pk.user_handle, "dXNlci1oYW5kbGU");
        assert_eq!(pk.created_epoch, 1_700_000_000);
        assert_eq!(pk.private_key, "cHJpdmF0ZS1rZXktYnl0ZXM");
    }

    #[test]
    fn old_login_blob_without_passkeys_opens_to_empty_vec() {
        // A vault sealed before passkeys existed has no `passkeys` key. The
        // `#[serde(default)]` migration must let it deserialize to an empty vec
        // rather than failing — never break opening an existing sealed vault.
        let legacy = r#"{"username":"octo","password":"pw","urls":[],"totp_secret":null}"#;
        let login: Login = serde_json::from_str(legacy).unwrap();
        assert!(login.passkeys.is_empty());
    }
}
