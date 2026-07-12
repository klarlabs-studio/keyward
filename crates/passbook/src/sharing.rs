//! Family sharing — end-to-end encrypted vault-key distribution.
//!
//! A Passbook vault is protected by a single symmetric **vault key** (32 bytes).
//! To share the vault with a family member without ever revealing that key in the
//! clear, we wrap it *per-recipient* with a sealed-box scheme built on X25519 +
//! HKDF-SHA256 + XChaCha20-Poly1305:
//!
//! For each recipient we generate a fresh **ephemeral** X25519 keypair, compute
//! the Diffie-Hellman shared secret `X25519(ephemeral_priv, recipient_pub)`,
//! stretch it through HKDF-SHA256 into a 32-byte wrapping key, and use that key
//! (with a random 24-byte nonce) to XChaCha20-Poly1305 encrypt the vault key. We
//! store `{ ephemeral_pub, nonce, ciphertext }` for that recipient. Only the
//! holder of the matching X25519 private key can recompute the shared secret
//! (`X25519(recipient_priv, ephemeral_pub)`), re-derive the wrapping key, and
//! decrypt the vault key. Public keys are freely shareable; private keys never
//! leave the member's device.
//!
//! **Account recovery** falls out of the design: any current member can recover
//! the vault key (they can unwrap their own copy) and therefore re-wrap it to a
//! brand-new member's public key — no involvement from the original vault-key
//! holder is required. See [`SharedVault::grant_access`].
//!
//! SECURITY NOTE: prototype crypto of the *shape*. Needs a formal review before
//! real use — see the threat model.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Domain-separation label mixed into every wrapping-key derivation.
const HKDF_INFO: &[u8] = b"proctor-passbook family-share v1";

/// The length of a Passbook vault key, in bytes.
pub const VAULT_KEY_LEN: usize = 32;

/// Errors that can occur while sharing or unwrapping a vault key.
#[derive(Debug, thiserror::Error)]
pub enum SharingError {
    /// The supplied member is not a recipient of this shared vault.
    #[error("member is not a recipient of this shared vault")]
    NotAMember,
    /// A wrapped key failed to decrypt (tampered data or wrong member key).
    #[error("could not unwrap the vault key (tampered wrapped key or wrong member key)")]
    Unwrap,
    /// The HKDF expansion failed (should not happen for a 32-byte output).
    #[error("wrapping-key derivation failed")]
    KeyDerivation,
}

type Result<T> = std::result::Result<T, SharingError>;

/// A family member and their X25519 keypair.
///
/// This is the *private* half — it holds the member's X25519 secret and stays on
/// the member's device. Share [`Member::public`] with others; never the `Member`
/// itself. The wrapped secret is zeroized on drop (via `x25519-dalek`'s `zeroize`
/// feature), so `id`/`name` are the only fields that outlive a drop.
pub struct Member {
    /// Stable identifier for the member (e.g. a UUID or email).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    secret: StaticSecret,
}

impl Member {
    /// Generate a new member with a fresh random X25519 keypair.
    pub fn generate(id: &str, name: &str) -> Self {
        Member {
            id: id.to_owned(),
            name: name.to_owned(),
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// The shareable public half of this member's identity.
    pub fn public(&self) -> MemberPublic {
        MemberPublic {
            id: self.id.clone(),
            name: self.name.clone(),
            public_key: PublicKey::from(&self.secret).to_bytes(),
        }
    }
}

impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret key.
        f.debug_struct("Member")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The shareable, public half of a [`Member`]: identity plus X25519 public key.
///
/// Safe to distribute freely — it contains no secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPublic {
    /// Stable identifier, matching the owning [`Member::id`].
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// The member's X25519 public key.
    pub public_key: [u8; 32],
}

/// One recipient's wrapped copy of the vault key.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WrappedKey {
    /// The recipient member's id (matches [`MemberPublic::id`]).
    member_id: String,
    /// The ephemeral X25519 public key used for this wrap.
    ephemeral_public: [u8; 32],
    /// The XChaCha20-Poly1305 nonce.
    nonce: [u8; 24],
    /// The AEAD ciphertext of the 32-byte vault key.
    ciphertext: Vec<u8>,
}

/// A vault key shared to a set of members via per-recipient sealed boxes.
///
/// Serialize/deserialize this alongside the encrypted vault; it reveals nothing
/// about the vault key to anyone who is not a listed recipient.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SharedVault {
    wrapped: Vec<WrappedKey>,
}

impl SharedVault {
    /// Wrap `vault_key` to each of `members`, producing a shareable [`SharedVault`].
    pub fn share_to(vault_key: &[u8; VAULT_KEY_LEN], members: &[MemberPublic]) -> Result<Self> {
        let mut sv = SharedVault::default();
        for m in members {
            sv.wrap_to(vault_key, m)?;
        }
        Ok(sv)
    }

    /// Number of recipients this vault key is currently wrapped to.
    pub fn recipient_count(&self) -> usize {
        self.wrapped.len()
    }

    /// Whether the given member id is a recipient of this shared vault.
    pub fn has_recipient(&self, member_id: &str) -> bool {
        self.wrapped.iter().any(|w| w.member_id == member_id)
    }

    /// Wrap `vault_key` to a single member and append it to this vault.
    ///
    /// If the member is already a recipient, their existing wrap is replaced.
    fn wrap_to(&mut self, vault_key: &[u8; VAULT_KEY_LEN], member: &MemberPublic) -> Result<()> {
        // Fresh ephemeral keypair for this recipient (sealed-box style).
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let recipient_public = PublicKey::from(member.public_key);
        let shared = ephemeral_secret.diffie_hellman(&recipient_public);
        // `SharedSecret` zeroizes on drop; copy its bytes into a Zeroizing buffer.
        let wrapping_key = derive_wrapping_key(shared.as_bytes())?;

        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| SharingError::KeyDerivation)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), vault_key.as_slice())
            .map_err(|_| SharingError::Unwrap)?;

        let entry = WrappedKey {
            member_id: member.id.clone(),
            ephemeral_public: ephemeral_public.to_bytes(),
            nonce,
            ciphertext,
        };

        // Replace an existing wrap for the same member, else append.
        if let Some(existing) = self.wrapped.iter_mut().find(|w| w.member_id == member.id) {
            *existing = entry;
        } else {
            self.wrapped.push(entry);
        }
        Ok(())
    }

    /// Recover the 32-byte vault key for `member`.
    ///
    /// Returns [`SharingError::NotAMember`] if the member has no wrap here, or
    /// [`SharingError::Unwrap`] if their wrap fails to decrypt (tampering).
    pub fn unwrap_for(&self, member: &Member) -> Result<[u8; VAULT_KEY_LEN]> {
        let wrapped = self
            .wrapped
            .iter()
            .find(|w| w.member_id == member.id)
            .ok_or(SharingError::NotAMember)?;

        let ephemeral_public = PublicKey::from(wrapped.ephemeral_public);
        let shared = member.secret.diffie_hellman(&ephemeral_public);
        let wrapping_key = derive_wrapping_key(shared.as_bytes())?;

        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| SharingError::KeyDerivation)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&wrapped.nonce),
                    wrapped.ciphertext.as_ref(),
                )
                .map_err(|_| SharingError::Unwrap)?,
        );
        if plaintext.len() != VAULT_KEY_LEN {
            return Err(SharingError::Unwrap);
        }
        let mut vault_key = [0u8; VAULT_KEY_LEN];
        vault_key.copy_from_slice(&plaintext);
        Ok(vault_key)
    }

    /// **Account recovery / re-invite.** An existing member re-wraps the vault key
    /// to a brand-new member, without the original vault-key holder.
    ///
    /// `existing_member` must already be a recipient (they prove access by
    /// unwrapping their own copy); the recovered key is then wrapped to
    /// `new_member`.
    pub fn grant_access(
        &mut self,
        existing_member: &Member,
        new_member: &MemberPublic,
    ) -> Result<()> {
        let vault_key = Zeroizing::new(self.unwrap_for(existing_member)?);
        self.wrap_to(&vault_key, new_member)
    }

    /// Remove a member's wrapped copy of the vault key.
    ///
    /// Returns `true` if a wrap was removed. NOTE: this revokes *future* access to
    /// this `SharedVault` object only; it does not rotate the vault key, so a
    /// member who already read the key retains it. Rotate the key for true
    /// revocation.
    pub fn revoke(&mut self, member_id: &str) -> bool {
        let before = self.wrapped.len();
        self.wrapped.retain(|w| w.member_id != member_id);
        self.wrapped.len() != before
    }
}

/// HKDF-SHA256 expand an X25519 shared secret into a 32-byte wrapping key.
fn derive_wrapping_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .map_err(|_| SharingError::KeyDerivation)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vault_key() -> [u8; VAULT_KEY_LEN] {
        let mut k = [0u8; VAULT_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn member_can_unwrap_shared_vault_key() {
        let vault_key = sample_vault_key();
        let alice = Member::generate("alice", "Alice");
        let bob = Member::generate("bob", "Bob");

        let shared = SharedVault::share_to(&vault_key, &[alice.public(), bob.public()]).unwrap();
        assert_eq!(shared.recipient_count(), 2);

        // Each member recovers the exact original bytes.
        assert_eq!(shared.unwrap_for(&alice).unwrap(), vault_key);
        assert_eq!(shared.unwrap_for(&bob).unwrap(), vault_key);
    }

    #[test]
    fn non_member_cannot_unwrap() {
        let vault_key = sample_vault_key();
        let alice = Member::generate("alice", "Alice");
        let shared = SharedVault::share_to(&vault_key, &[alice.public()]).unwrap();

        // A completely different keypair/id is not a recipient.
        let mallory = Member::generate("mallory", "Mallory");
        assert!(matches!(
            shared.unwrap_for(&mallory),
            Err(SharingError::NotAMember)
        ));

        // Even someone who forges the *same id* but a different key cannot unwrap:
        // their DH shared secret won't match, so decryption fails.
        let impostor = Member::generate("alice", "Not Alice");
        assert!(matches!(
            shared.unwrap_for(&impostor),
            Err(SharingError::Unwrap)
        ));
    }

    #[test]
    fn recovery_existing_member_grants_new_member() {
        let vault_key = sample_vault_key();
        let alice = Member::generate("alice", "Alice");

        // Only Alice is initially a recipient.
        let mut shared = SharedVault::share_to(&vault_key, &[alice.public()]).unwrap();

        // A brand-new member joins; Alice (an existing member) grants access
        // WITHOUT the original vault-key holder being involved.
        let carol = Member::generate("carol", "Carol");
        assert!(!shared.has_recipient("carol"));
        shared.grant_access(&alice, &carol.public()).unwrap();
        assert!(shared.has_recipient("carol"));

        // Carol can now unwrap the exact original vault key.
        assert_eq!(shared.unwrap_for(&carol).unwrap(), vault_key);
        // Alice still can too.
        assert_eq!(shared.unwrap_for(&alice).unwrap(), vault_key);
    }

    #[test]
    fn revoke_removes_recipient() {
        let vault_key = sample_vault_key();
        let alice = Member::generate("alice", "Alice");
        let bob = Member::generate("bob", "Bob");
        let mut shared =
            SharedVault::share_to(&vault_key, &[alice.public(), bob.public()]).unwrap();

        assert!(shared.revoke("bob"));
        assert!(!shared.revoke("bob")); // idempotent
        assert!(matches!(
            shared.unwrap_for(&bob),
            Err(SharingError::NotAMember)
        ));
        // Alice is unaffected.
        assert_eq!(shared.unwrap_for(&alice).unwrap(), vault_key);
    }

    #[test]
    fn re_sharing_same_member_replaces_not_duplicates() {
        let vault_key = sample_vault_key();
        let alice = Member::generate("alice", "Alice");
        let mut shared = SharedVault::share_to(&vault_key, &[alice.public()]).unwrap();
        // Grant to the same id again — should replace, not duplicate.
        shared.wrap_to(&vault_key, &alice.public()).unwrap();
        assert_eq!(shared.recipient_count(), 1);
        assert_eq!(shared.unwrap_for(&alice).unwrap(), vault_key);
    }
}
