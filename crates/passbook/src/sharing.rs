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
use proctor_crypto::{aead_open, aead_seal, random_array, NONCE_LEN};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// The shared vault **content**, encrypted directly under the 32-byte vault key
/// that [`SharedVault`] distributes.
///
/// Unlike a personal [`crate::sealing::SealedVault`] (which derives its key from a
/// master password + Secret Key), a shared content blob is keyed *only* by the
/// vault key. Every member decrypts it with the vault key they unwrapped from
/// their own [`SharedVault`] entry — there is no per-account wrapping here, and
/// the personal-vault format is left completely untouched. The member's X25519
/// secret is what is stored (encrypted) in their personal vault; the shared
/// content lives separately, at the group relay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentBlob {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// Domain-separation label for the group safety number.
const SAFETY_NUMBER_INFO: &[u8] = b"proctor-passbook group-safety-number v1";

/// A short, human-comparable fingerprint of a group's **public** membership —
/// the mitigation for the key-substitution / directory-trust risk named in
/// ADR-0004.
///
/// The relay distributes each member's public key. A malicious or compromised
/// server could substitute a key it controls and be wrapped into the vault as a
/// silent extra recipient. Members cannot detect that from the ciphertext alone —
/// but they *can* compare this number **out of band** (in person, over a call). It
/// is derived only from the members' ids and public keys, so if the server showed
/// anyone a different directory, the numbers will not match.
///
/// Rendered as 8 groups of 5 digits, e.g. `01234 56789 …`. Order-independent
/// (members are sorted) and length-prefixed so two different directories can never
/// hash to the same bytes by concatenation ambiguity.
pub fn safety_number(members: &[MemberPublic]) -> String {
    let mut sorted: Vec<&MemberPublic> = members.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));

    let mut hasher = Sha256::new();
    hasher.update(SAFETY_NUMBER_INFO);
    for m in sorted {
        // Length-prefix the id so `("ab","c")` and `("a","bc")` differ.
        hasher.update((m.id.len() as u32).to_be_bytes());
        hasher.update(m.id.as_bytes());
        hasher.update(m.public_key);
    }
    let digest = hasher.finalize();

    digest
        .chunks(4)
        .map(|c| {
            let v = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) % 100_000;
            format!("{v:05}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Arbitrary bytes sealed to exactly ONE recipient's X25519 public key.
///
/// Same sealed-box construction as the per-recipient vault-key wrap (ephemeral
/// X25519 → HKDF-SHA256 → XChaCha20-Poly1305), but for a payload of any length.
/// Used for **recovery contacts**: a member seals their device Secret Key to a
/// family member, so if they lose their Emergency Kit that person can hand it
/// back. The contact still cannot open the vault — the Secret Key is only one of
/// the two 2SKD factors; the master password is never shared.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedBox {
    ephemeral_public: [u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Seal `plaintext` to a single recipient's public key.
pub fn seal_to(recipient: &MemberPublic, plaintext: &[u8]) -> Result<SealedBox> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(recipient.public_key));
    let wrapping_key = derive_wrapping_key(shared.as_bytes())?;

    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| SharingError::KeyDerivation)?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| SharingError::Unwrap)?;

    Ok(SealedBox {
        ephemeral_public: ephemeral_public.to_bytes(),
        nonce,
        ciphertext,
    })
}

/// Open a [`SealedBox`] addressed to `member`. Fails for any other member, or on
/// tampering.
pub fn open_sealed(sealed: &SealedBox, member: &Member) -> Result<Vec<u8>> {
    let shared = member
        .secret
        .diffie_hellman(&PublicKey::from(sealed.ephemeral_public));
    let wrapping_key = derive_wrapping_key(shared.as_bytes())?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| SharingError::KeyDerivation)?;
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            sealed.ciphertext.as_ref(),
        )
        .map_err(|_| SharingError::Unwrap)
}

/// Generate a fresh random 32-byte vault key (the key a [`SharedVault`] wraps).
pub fn new_vault_key() -> [u8; VAULT_KEY_LEN] {
    random_array::<VAULT_KEY_LEN>()
}

/// Seal opaque `plaintext` (e.g. serialized entries) under `vault_key`.
pub fn seal_content(vault_key: &[u8; VAULT_KEY_LEN], plaintext: &[u8]) -> Result<ContentBlob> {
    let nonce = random_array::<NONCE_LEN>();
    let ciphertext = aead_seal(vault_key, &nonce, plaintext).map_err(|_| SharingError::Unwrap)?;
    Ok(ContentBlob { nonce, ciphertext })
}

/// Open a [`ContentBlob`] with `vault_key`. Fails on a wrong key or any tampering.
pub fn open_content(blob: &ContentBlob, vault_key: &[u8; VAULT_KEY_LEN]) -> Result<Vec<u8>> {
    aead_open(vault_key, &blob.nonce, &blob.ciphertext).map_err(|_| SharingError::Unwrap)
}

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

    /// Reconstruct a member from a stored 32-byte X25519 secret. The inverse of
    /// [`Member::secret_bytes`]; the secret is kept encrypted-at-rest inside the
    /// member's *own* vault, so their sharing identity is stable across devices
    /// and master-password changes.
    pub fn from_secret(id: &str, name: &str, secret: [u8; 32]) -> Self {
        Member {
            id: id.to_owned(),
            name: name.to_owned(),
            secret: StaticSecret::from(secret),
        }
    }

    /// Export the raw X25519 secret for encrypted-at-rest storage in the member's
    /// own vault. Treat as secret material — it unwraps every vault shared to this
    /// member.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
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
    fn member_survives_a_secret_bytes_round_trip() {
        let vault_key = sample_vault_key();
        let alice = Member::generate("alice", "Alice");
        let shared = SharedVault::share_to(&vault_key, &[alice.public()]).unwrap();

        // Persist Alice's secret (as her vault would), then rebuild her from it.
        let stored = alice.secret_bytes();
        let restored = Member::from_secret("alice", "Alice", stored);

        // The rebuilt member has the same public key and can still unwrap.
        assert_eq!(restored.public().public_key, alice.public().public_key);
        assert_eq!(shared.unwrap_for(&restored).unwrap(), vault_key);
    }

    #[test]
    fn recovery_contact_can_return_a_secret_key_but_not_open_the_vault() {
        // Alice seals her device Secret Key to Bob as her recovery contact.
        let alice = Member::generate("alice", "Alice");
        let bob = Member::generate("bob", "Bob");
        let eve = Member::generate("eve", "Eve");
        let alice_secret_key = b"A1B2-C3D4-E5F6-7890"; // Emergency-Kit format

        let sealed = seal_to(&bob.public(), alice_secret_key).unwrap();

        // Only Bob can open it — not Eve, and not Alice's own member key.
        assert_eq!(open_sealed(&sealed, &bob).unwrap(), alice_secret_key);
        assert!(open_sealed(&sealed, &eve).is_err());
        assert!(open_sealed(&sealed, &alice).is_err());

        // Tampering is detected (AEAD).
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert!(open_sealed(&tampered, &bob).is_err());

        // The ciphertext does not leak the payload.
        assert!(!sealed
            .ciphertext
            .windows(alice_secret_key.len())
            .any(|w| w == alice_secret_key));

        // CRITICAL PROPERTY: holding the Secret Key is NOT enough to open Alice's
        // vault — the master password is the other 2SKD factor and is never shared.
        let recovered = open_sealed(&sealed, &bob).unwrap();
        let sk = crate::domain::SecretKey::generate();
        let entries = vec![crate::domain::Entry::login("e1", "Bank", "alice", "s3cret")];
        let vault = crate::sealing::seal(&entries, b"alice-master", Some(&sk)).unwrap();
        // Bob has a Secret Key but not Alice's master password.
        assert!(crate::sealing::open(&vault, b"bob-guesses", Some(&sk)).is_err());
        assert!(!recovered.is_empty());
    }

    #[test]
    fn safety_number_detects_a_substituted_key() {
        let alice = Member::generate("alice", "Alice");
        let bob = Member::generate("bob", "Bob");
        let members = vec![alice.public(), bob.public()];

        let number = safety_number(&members);
        // Shape: 8 groups of 5 digits.
        let groups: Vec<&str> = number.split(' ').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups
            .iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));

        // Order-independent: both members compute the SAME number regardless of
        // the order the directory happens to list them in.
        let reversed = vec![bob.public(), alice.public()];
        assert_eq!(number, safety_number(&reversed));

        // THE POINT: a malicious relay swapping Bob's public key for one it
        // controls changes the number, so an out-of-band comparison catches it.
        let attacker = Member::generate("bob", "Bob");
        let substituted = vec![alice.public(), attacker.public()];
        assert_ne!(number, safety_number(&substituted));

        // A silently added extra recipient also changes it.
        let eve = Member::generate("eve", "Eve");
        let mut with_eve = members.clone();
        with_eve.push(eve.public());
        assert_ne!(number, safety_number(&with_eve));

        // Length-prefixing: ids that would concatenate identically must differ.
        let make = |id: &str, m: &Member| MemberPublic {
            id: id.to_string(),
            name: String::new(),
            public_key: m.public().public_key,
        };
        assert_ne!(
            safety_number(&[make("ab", &alice), make("c", &bob)]),
            safety_number(&[make("a", &alice), make("bc", &bob)])
        );
    }

    #[test]
    fn content_seals_and_opens_under_the_vault_key() {
        let vault_key = new_vault_key();
        let plaintext = br#"[{"id":"e1","title":"GitHub"}]"#;

        let blob = seal_content(&vault_key, plaintext).unwrap();
        assert_eq!(open_content(&blob, &vault_key).unwrap(), plaintext);

        // A wrong vault key (what a non-member would have) cannot open it.
        let wrong = new_vault_key();
        assert!(open_content(&blob, &wrong).is_err());

        // Tampered ciphertext is rejected.
        let mut tampered = blob.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert!(open_content(&tampered, &vault_key).is_err());
    }

    #[test]
    fn end_to_end_member_reads_shared_content() {
        // Owner establishes a shared vault: fresh key, seal content, share to Bob.
        let vault_key = new_vault_key();
        let content = seal_content(&vault_key, b"secret entries").unwrap();
        let owner = Member::generate("owner", "Alice");
        let bob = Member::generate("bob", "Bob");
        let shared = SharedVault::share_to(&vault_key, &[owner.public(), bob.public()]).unwrap();

        // Bob, holding only his secret + the SharedVault + the content blob,
        // recovers the key and reads the content — the server saw none of it.
        let bob_key = shared.unwrap_for(&bob).unwrap();
        assert_eq!(open_content(&content, &bob_key).unwrap(), b"secret entries");
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
