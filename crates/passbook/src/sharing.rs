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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use proctor_crypto::{aead_open, aead_seal, random_array, NONCE_LEN};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Domain-separation label mixed into every vault-key wrapping derivation.
const HKDF_INFO: &[u8] = b"proctor-passbook family-share v1";

/// Separate label for the general-purpose [`SealedBox`] (recovery payloads). Two
/// protocols carrying different plaintext types must never share one derivation.
const SEALED_BOX_INFO: &[u8] = b"proctor-passbook sealed-box v1";

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
    /// The X25519 exchange was **non-contributory**: the peer's public key is a
    /// low-order point, so the shared secret degenerates to a publicly-computable
    /// constant. Since recipient public keys arrive from the (untrusted) relay,
    /// this must be rejected rather than silently producing a guessable key.
    #[error("rejected a weak (low-order) public key")]
    WeakKey,
    /// The wrapped-key set carries no signature, so its author cannot be
    /// established. Distinct from [`SharingError::BadSignature`]: this is a
    /// legacy or stripped blob rather than evidence of tampering.
    #[error("wrapped-key set is unsigned — cannot establish who produced it")]
    Unsigned,
    /// The wrapped-key set is signed, but the signature does not verify against
    /// the expected member's key: it was produced or altered by someone other
    /// than that member.
    #[error("wrapped-key set signature does not verify — produced by someone other than the expected member")]
    BadSignature,
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
/// Domain label for the wrapped-key-set signature. Distinct from every other
/// label here so a signature over this structure can never be replayed as a
/// signature over something else.
const WRAP_SIGNATURE_CONTEXT: &[u8] = b"proctor-passbook shared-vault-wraps v1";

/// Bumped to v2 when the safety number began covering signing keys. The label is
/// part of the digest, so v1 and v2 numbers differ for the same directory — which
/// is the point: a silently-changed derivation under the same label would look
/// like a substituted directory to every family at once.
const SAFETY_NUMBER_INFO: &[u8] = b"proctor-passbook group-safety-number v2";

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
        // Fixed 32 bytes, so no length prefix is needed. An absent key is
        // all-zero and still contributes: "this member has no signing key" is
        // itself a fact the family should be comparing.
        hasher.update(m.signing_key);
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
    let wrapping_key = derive_wrapping_key_with(checked_secret(&shared)?, SEALED_BOX_INFO)?;

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
    let wrapping_key = derive_wrapping_key_with(checked_secret(&shared)?, SEALED_BOX_INFO)?;
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
/// A fresh Ed25519 signing key from the shared CSPRNG.
///
/// Not `SigningKey::generate`: ed25519-dalek and x25519-dalek depend on
/// different `rand_core` versions, so the `OsRng` used for X25519 does not
/// satisfy the trait ed25519-dalek expects. Drawing 32 bytes from
/// `proctor_crypto::fill_random` keeps one entropy source across the crate
/// rather than introducing a second RNG stack to reason about.
fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    proctor_crypto::fill_random(&mut seed);
    SigningKey::from_bytes(&seed)
}

pub struct Member {
    /// Stable identifier for the member (e.g. a UUID or email).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    secret: StaticSecret,
    /// Ed25519 signing key, used to authenticate wrapped-key sets this member
    /// produces.
    ///
    /// Separate from the X25519 `secret` on purpose. The two could be derived
    /// from one seed — both are Curve25519 — but using a single key for both
    /// key agreement and signatures invites cross-protocol interactions, and
    /// the cost of a second 32-byte key is nil.
    signing: SigningKey,
}

impl Member {
    /// Generate a new member with a fresh random X25519 keypair.
    pub fn generate(id: &str, name: &str) -> Self {
        Member {
            id: id.to_owned(),
            name: name.to_owned(),
            secret: StaticSecret::random_from_rng(OsRng),
            signing: random_signing_key(),
        }
    }

    /// Reconstruct a member from a stored 32-byte X25519 secret. The inverse of
    /// [`Member::secret_bytes`]; the secret is kept encrypted-at-rest inside the
    /// member's *own* vault, so their sharing identity is stable across devices
    /// and master-password changes.
    pub fn from_secret(id: &str, name: &str, secret: [u8; 32]) -> Self {
        Self::from_secrets(id, name, secret, None)
    }

    /// Reconstruct a member from stored secrets, including the Ed25519 signing
    /// key when one exists.
    ///
    /// `signing` is optional because members created before wrapped-key sets
    /// were signed have no signing key stored. Such a member is generated a
    /// FRESH signing key here rather than being rejected: they can still read
    /// vaults shared to them (which needs only the X25519 secret), and the new
    /// public half is published on their next write. The consequence is that
    /// other devices see a new signing key for them and must accept it, which
    /// is the same trust decision as any re-enrolment.
    pub fn from_secrets(id: &str, name: &str, secret: [u8; 32], signing: Option<[u8; 32]>) -> Self {
        Member {
            id: id.to_owned(),
            name: name.to_owned(),
            secret: StaticSecret::from(secret),
            signing: match signing {
                Some(bytes) => SigningKey::from_bytes(&bytes),
                None => random_signing_key(),
            },
        }
    }

    /// Export the raw Ed25519 signing secret for encrypted-at-rest storage
    /// alongside [`Member::secret_bytes`]. Secret material.
    pub fn signing_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// This member's Ed25519 verifying key, published in the directory so other
    /// members can authenticate wrapped-key sets this member writes.
    pub fn signing_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
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
            signing_key: self.signing.verifying_key().to_bytes(),
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
    /// The member's Ed25519 verifying key, used to authenticate wrapped-key
    /// sets they write.
    ///
    /// `#[serde(default)]` so a directory entry published before signing
    /// existed still deserializes; an all-zero key is treated as "no signing
    /// key" and cannot verify anything.
    #[serde(default)]
    pub signing_key: [u8; 32],
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
    /// Monotonic version of this wrapped-key set.
    ///
    /// THIS IS WHAT CLOSES ROLLBACK. A signature proves WHO wrote a set, not
    /// WHICH set is current — so a relay that cannot forge one can still serve
    /// an older, perfectly valid set it captured earlier, reinstating a revoked
    /// member's wrap or reverting a key rotation. Every reader accepts it,
    /// because it really was signed by a real member.
    ///
    /// The epoch is inside the signed payload, so it cannot be edited without
    /// invalidating the signature. A client pins the highest epoch it has seen
    /// for a group and refuses anything lower.
    ///
    /// `#[serde(default)]` (0) for sets written before epochs existed.
    #[serde(default)]
    epoch: u64,
    /// The member id that produced this wrapped-key set, if it is signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer_id: Option<String>,
    /// Ed25519 signature over the canonical encoding of `wrapped`.
    ///
    /// THIS IS WHAT CLOSES THE SUBSTITUTION ATTACK. Producing a wrap requires
    /// only a recipient's PUBLIC key, so anyone — including the relay — can
    /// mint a vault key, wrap it correctly to every genuine member, and
    /// overwrite the blob. Every member then decrypts successfully, and the
    /// safety number is unchanged because it digests only member ids and public
    /// keys. A signature makes the set unforgeable by anyone who is not a
    /// member holding a signing key the reader has pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Vec<u8>>,
}

impl SharedVault {
    /// The bytes a signature covers: a canonical, unambiguous encoding of every
    /// wrap in the set.
    ///
    /// Entries are sorted by member id and every variable-length field is
    /// length-prefixed, so two different sets can never produce the same
    /// message — without that, an attacker could shuffle fields between wraps
    /// and keep a signature valid. The context label is included so this
    /// signature cannot be replayed as a signature over anything else.
    fn signing_payload(wrapped: &[WrappedKey], epoch: u64) -> Vec<u8> {
        let mut sorted: Vec<&WrappedKey> = wrapped.iter().collect();
        sorted.sort_by(|a, b| a.member_id.cmp(&b.member_id));

        let mut msg = Vec::with_capacity(WRAP_SIGNATURE_CONTEXT.len() + sorted.len() * 128);
        msg.extend_from_slice(WRAP_SIGNATURE_CONTEXT);
        msg.extend_from_slice(&epoch.to_be_bytes());
        msg.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
        for w in sorted {
            msg.extend_from_slice(&(w.member_id.len() as u32).to_be_bytes());
            msg.extend_from_slice(w.member_id.as_bytes());
            msg.extend_from_slice(&w.ephemeral_public);
            msg.extend_from_slice(&w.nonce);
            msg.extend_from_slice(&(w.ciphertext.len() as u32).to_be_bytes());
            msg.extend_from_slice(&w.ciphertext);
        }
        msg
    }

    /// Sign this wrapped-key set as `member`.
    ///
    /// Called after any mutation. A set is only trustworthy if the reader can
    /// tell WHO produced it: wraps require nothing but public keys, so an
    /// unsigned set proves only that somebody could read a directory.
    pub fn sign_as(&mut self, member: &Member) {
        let sig = member
            .signing
            .sign(&Self::signing_payload(&self.wrapped, self.epoch));
        self.signer_id = Some(member.id.clone());
        self.signature = Some(sig.to_bytes().to_vec());
    }

    /// The member id that signed this set, if any.
    pub fn signer(&self) -> Option<&str> {
        self.signer_id.as_deref()
    }

    /// Verify this set was signed by `signer`.
    ///
    /// The caller must pass a verifying key it TRUSTS — in practice one pinned
    /// locally for that member. Verifying against a key taken from the same
    /// relay that served the blob would prove nothing: an attacker able to
    /// replace the wraps can replace the key beside them.
    ///
    /// Returns [`SharingError::Unsigned`] when there is no signature at all,
    /// and [`SharingError::BadSignature`] when one is present but does not
    /// verify. The distinction matters to callers: the first is a legacy or
    /// stripped blob, the second is active tampering.
    pub fn verify_signed_by(&self, signer: &MemberPublic) -> Result<()> {
        let (Some(id), Some(sig_bytes)) = (self.signer_id.as_ref(), self.signature.as_ref()) else {
            return Err(SharingError::Unsigned);
        };
        if id != &signer.id {
            return Err(SharingError::BadSignature);
        }
        // An absent signing key is all-zero, which is not a valid Ed25519 point;
        // reject explicitly rather than relying on that.
        if signer.signing_key == [0u8; 32] {
            return Err(SharingError::Unsigned);
        }
        let vk = VerifyingKey::from_bytes(&signer.signing_key)
            .map_err(|_| SharingError::BadSignature)?;
        let sig = Signature::from_slice(sig_bytes).map_err(|_| SharingError::BadSignature)?;
        vk.verify(&Self::signing_payload(&self.wrapped, self.epoch), &sig)
            .map_err(|_| SharingError::BadSignature)
    }

    /// Wrap `vault_key` to each of `members`, producing a shareable [`SharedVault`].
    pub fn share_to(vault_key: &[u8; VAULT_KEY_LEN], members: &[MemberPublic]) -> Result<Self> {
        // Epoch 1, not 0: 0 is what a pre-epoch set deserializes to, and a fresh
        // set must outrank one so a captured legacy set cannot be replayed over it.
        let mut sv = SharedVault {
            epoch: 1,
            ..Default::default()
        };
        for m in members {
            sv.wrap_to(vault_key, m)?;
        }
        Ok(sv)
    }

    /// This set's monotonic epoch. A reader must refuse any set whose epoch is
    /// lower than the highest it has already accepted for the group.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Rotate to a NEW vault key at the next epoch after `previous`.
    ///
    /// Used for true revocation: dropping a wrap is not enough, since a removed
    /// member may already hold the key. Carrying `previous.epoch + 1` is what
    /// stops the relay answering the rotation by replaying the pre-rotation set
    /// and handing the removed member their access back.
    pub fn rotate_from(
        previous: &SharedVault,
        vault_key: &[u8; VAULT_KEY_LEN],
        members: &[MemberPublic],
    ) -> Result<Self> {
        let mut sv = SharedVault::share_to(vault_key, members)?;
        sv.epoch = previous.epoch.saturating_add(1);
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
        // The recipient key came from the relay — reject low-order points, which
        // would make the wrapping key a publicly computable constant.
        // `SharedSecret` zeroizes on drop; copy its bytes into a Zeroizing buffer.
        let wrapping_key = derive_wrapping_key(checked_secret(&shared)?)?;

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
        let wrapping_key = derive_wrapping_key(checked_secret(&shared)?)?;

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
        self.wrap_to(&vault_key, new_member)?;
        self.epoch = self.epoch.saturating_add(1);
        Ok(())
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
        let removed = self.wrapped.len() != before;
        if removed {
            self.epoch = self.epoch.saturating_add(1);
        }
        removed
    }
}

/// HKDF-SHA256 expand an X25519 shared secret into a 32-byte wrapping key, under
/// the caller's domain-separation label.
fn derive_wrapping_key_with(shared_secret: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| SharingError::KeyDerivation)?;
    Ok(okm)
}

/// The vault-key wrapping derivation (the family-share protocol).
fn derive_wrapping_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_wrapping_key_with(shared_secret, HKDF_INFO)
}

/// Reject a non-contributory exchange before deriving anything from it.
fn checked_secret(shared: &x25519_dalek::SharedSecret) -> Result<&[u8; 32]> {
    if !shared.was_contributory() {
        return Err(SharingError::WeakKey);
    }
    Ok(shared.as_bytes())
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
    fn low_order_public_keys_are_rejected() {
        // Recipient public keys arrive from the UNTRUSTED relay. A low-order point
        // makes X25519 non-contributory: the shared secret becomes an all-zero
        // constant, so the wrapping key is publicly computable and anyone could
        // unwrap the vault key. All four DH sites must refuse.
        //
        // The canonical small-order points of Curve25519.
        let low_order: [[u8; 32]; 3] = [
            [0u8; 32], // order 1
            {
                let mut p = [0u8; 32];
                p[0] = 1; // order 1
                p
            },
            [
                224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9,
                141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0,
            ], // order 8
        ];

        let victim = Member::generate("victim", "Victim");
        let vault_key = sample_vault_key();

        for point in low_order {
            let hostile = MemberPublic {
                id: "injected".into(),
                name: "Mom".into(),
                public_key: point,
                signing_key: [0u8; 32],
            };
            // Wrapping the vault key to a low-order "member" must fail, not
            // silently produce a guessable wrap.
            assert!(
                matches!(
                    SharedVault::share_to(&vault_key, std::slice::from_ref(&hostile)),
                    Err(SharingError::WeakKey)
                ),
                "share_to accepted a low-order key"
            );
            // The recovery sealed box must refuse it too.
            assert!(
                matches!(seal_to(&hostile, b"secret"), Err(SharingError::WeakKey)),
                "seal_to accepted a low-order key"
            );
        }

        // Honest keys still work.
        assert!(SharedVault::share_to(&vault_key, &[victim.public()]).is_ok());
    }

    #[test]
    fn recovery_and_vault_wrapping_use_separate_derivations() {
        // Two protocols must not share one HKDF label. A SealedBox and a vault-key
        // wrap built from the same DH must not produce interchangeable keys.
        let bob = Member::generate("bob", "Bob");
        let payload = b"A1B2-C3D4";
        let sealed = seal_to(&bob.public(), payload).unwrap();
        // Opening with the right member works...
        assert_eq!(open_sealed(&sealed, &bob).unwrap(), payload);
        // ...and the labels are genuinely distinct.
        assert_ne!(HKDF_INFO, SEALED_BOX_INFO);
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
    fn safety_number_detects_a_substituted_signing_key() {
        // The first-contact gap. A relay hostile from the very first sight of a
        // member can hand a newcomer a fabricated SIGNING key; that newcomer
        // then verifies the relay's forged wrapped-key sets as genuine. Before
        // the safety number covered signing keys, this was invisible -- the
        // number digested only the X25519 halves, so it matched everyone
        // else's exactly.
        let alice = Member::generate("alice", "Alice");
        let bob = Member::generate("bob", "Bob");
        let genuine = vec![alice.public(), bob.public()];

        // Same ids, same X25519 keys -- only Bob's signing key is swapped.
        let relay = Member::generate("bob", "Bob");
        let mut forged_bob = bob.public();
        forged_bob.signing_key = relay.signing_public();
        assert_eq!(forged_bob.public_key, bob.public().public_key);

        assert_ne!(
            safety_number(&genuine),
            safety_number(&[alice.public(), forged_bob])
        );
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
            signing_key: m.public().signing_key,
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

    // ---- F2: sender authentication -------------------------------------
    //
    // The attack these cover: producing a wrap needs only a recipient's PUBLIC
    // key, so a relay can mint its own vault key, wrap it correctly to every
    // genuine member, and overwrite the blob. Every member decrypts
    // successfully and the safety number is unchanged, because it digests only
    // member ids and public keys. Signing is what makes the set unforgeable.

    #[test]
    fn a_signed_wrap_set_verifies_against_its_author() {
        let alice = Member::generate("m-alice", "Alice");
        let bob = Member::generate("m-bob", "Bob");
        let key = new_vault_key();

        let mut sv = SharedVault::share_to(&key, &[alice.public(), bob.public()]).unwrap();
        sv.sign_as(&alice);

        assert_eq!(sv.signer(), Some("m-alice"));
        sv.verify_signed_by(&alice.public())
            .expect("author's signature must verify");
    }

    #[test]
    fn a_relay_substituted_wrap_set_is_rejected() {
        let alice = Member::generate("m-alice", "Alice");
        let bob = Member::generate("m-bob", "Bob");

        // The real set, signed by Alice.
        let real_key = new_vault_key();
        let mut real = SharedVault::share_to(&real_key, &[alice.public(), bob.public()]).unwrap();
        real.sign_as(&alice);

        // The relay mints its OWN key and wraps it correctly to both genuine
        // members. This is entirely possible — it needs only public keys — and
        // both members would decrypt it happily.
        let evil_key = new_vault_key();
        let evil = SharedVault::share_to(&evil_key, &[alice.public(), bob.public()]).unwrap();
        assert!(
            evil.unwrap_for(&bob).is_ok(),
            "the forged set does decrypt — that is the danger"
        );
        assert_ne!(
            evil.unwrap_for(&bob).unwrap(),
            real.unwrap_for(&bob).unwrap(),
            "and it yields a DIFFERENT vault key"
        );

        // But it cannot be signed as Alice, so Bob rejects it.
        assert!(matches!(
            evil.verify_signed_by(&alice.public()),
            Err(SharingError::Unsigned)
        ));
    }

    #[test]
    fn a_replayed_older_set_is_still_perfectly_signed() {
        // ROLLBACK, the attack signatures alone do NOT stop. Alice revokes Mallory
        // and rotates. The relay kept the pre-revocation set -- which Alice
        // genuinely signed -- and serves it back. Every signature check passes,
        // because nothing was forged. Only the epoch distinguishes them.
        let alice = Member::generate("alice", "Alice");
        let mallory = Member::generate("mallory", "Mallory");

        let key1 = new_vault_key();
        let mut before = SharedVault::share_to(&key1, &[alice.public(), mallory.public()]).unwrap();
        before.sign_as(&alice);

        let key2 = new_vault_key();
        let mut after = SharedVault::rotate_from(&before, &key2, &[alice.public()]).unwrap();
        after.sign_as(&alice);

        // The stale set verifies. That is the whole problem.
        assert!(before.verify_signed_by(&alice.public()).is_ok());
        assert!(after.verify_signed_by(&alice.public()).is_ok());
        // And replaying it hands Mallory her access back.
        assert!(before.unwrap_for(&mallory).is_ok());
        assert!(after.unwrap_for(&mallory).is_err());

        // The epoch is the only thing that tells them apart, and it is inside
        // the signature, so the relay cannot raise it.
        assert!(after.epoch() > before.epoch());
    }

    #[test]
    fn an_epoch_cannot_be_edited_without_breaking_the_signature() {
        let alice = Member::generate("alice", "Alice");
        let key = new_vault_key();
        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        sv.sign_as(&alice);
        assert!(sv.verify_signed_by(&alice.public()).is_ok());

        // A relay trying to make a stale set outrank a current one.
        sv.epoch = 99;
        assert!(matches!(
            sv.verify_signed_by(&alice.public()),
            Err(SharingError::BadSignature)
        ));
    }

    #[test]
    fn every_mutation_advances_the_epoch() {
        let alice = Member::generate("alice", "Alice");
        let bob = Member::generate("bob", "Bob");
        let key = new_vault_key();

        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        // Not 0: a pre-epoch set deserializes to 0, and a fresh set must outrank
        // one so a captured legacy set cannot be replayed over it.
        assert_eq!(sv.epoch(), 1);

        sv.grant_access(&alice, &bob.public()).unwrap();
        assert_eq!(sv.epoch(), 2);

        assert!(sv.revoke("bob"));
        assert_eq!(sv.epoch(), 3);

        // A no-op revoke must NOT advance it, or a relay could pump the epoch by
        // replaying harmless removals to outrank a genuine set.
        assert!(!sv.revoke("nobody"));
        assert_eq!(sv.epoch(), 3);
    }

    #[test]
    fn stripping_a_signature_is_not_the_same_as_never_having_one() {
        // A relay that cannot forge a signature can still DELETE one. The
        // primitive must report that as `Unsigned`, distinct from
        // `BadSignature`, so a client can apply the rule the primitive cannot:
        // a group seen signed once must never be accepted unsigned again.
        let alice = Member::generate("alice", "Alice");
        let key = new_vault_key();
        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        sv.sign_as(&alice);
        assert!(sv.verify_signed_by(&alice.public()).is_ok());

        let stripped: SharedVault =
            serde_json::from_str(&serde_json::to_string(&sv).unwrap()).unwrap();
        let mut stripped = stripped;
        stripped.signer_id = None;
        stripped.signature = None;

        assert!(matches!(
            stripped.verify_signed_by(&alice.public()),
            Err(SharingError::Unsigned)
        ));
        // And it still decrypts — which is exactly why the caller, not the
        // signature check, has to refuse it.
        assert_eq!(stripped.unwrap_for(&alice).unwrap(), key);
    }

    #[test]
    fn a_signature_from_the_wrong_member_is_rejected() {
        let alice = Member::generate("m-alice", "Alice");
        let mallory = Member::generate("m-mallory", "Mallory");
        let key = new_vault_key();

        // Mallory signs a set and claims nothing about Alice — verifying it
        // AGAINST Alice must fail, or a relay could pass off any member's
        // signature as any other's.
        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        sv.sign_as(&mallory);

        assert!(matches!(
            sv.verify_signed_by(&alice.public()),
            Err(SharingError::BadSignature)
        ));
        sv.verify_signed_by(&mallory.public())
            .expect("verifies against its real author");
    }

    #[test]
    fn tampering_with_a_signed_set_invalidates_it() {
        let alice = Member::generate("m-alice", "Alice");
        let bob = Member::generate("m-bob", "Bob");
        let key = new_vault_key();

        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        sv.sign_as(&alice);
        sv.verify_signed_by(&alice.public()).unwrap();

        // Appending a recipient after signing — the shape of "relay adds a
        // member it controls" — must break the signature.
        sv.wrap_to(&key, &bob.public()).unwrap();
        assert!(matches!(
            sv.verify_signed_by(&alice.public()),
            Err(SharingError::BadSignature)
        ));
    }

    #[test]
    fn a_member_without_a_signing_key_cannot_verify_anything() {
        let alice = Member::generate("m-alice", "Alice");
        let key = new_vault_key();
        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        sv.sign_as(&alice);

        // A directory entry published before signing existed carries an
        // all-zero key. That must fail closed rather than being treated as a
        // valid point.
        let legacy = MemberPublic {
            id: alice.public().id,
            name: alice.public().name,
            public_key: alice.public().public_key,
            signing_key: [0u8; 32],
        };
        assert!(matches!(
            sv.verify_signed_by(&legacy),
            Err(SharingError::Unsigned)
        ));
    }

    #[test]
    fn signing_identity_survives_a_round_trip() {
        let alice = Member::generate("m-alice", "Alice");
        let restored = Member::from_secrets(
            "m-alice",
            "Alice",
            alice.secret_bytes(),
            Some(alice.signing_bytes()),
        );
        assert_eq!(restored.signing_public(), alice.signing_public());

        let key = new_vault_key();
        let mut sv = SharedVault::share_to(&key, &[alice.public()]).unwrap();
        sv.sign_as(&restored);
        sv.verify_signed_by(&alice.public())
            .expect("a restored member signs as the same identity");
    }
}
