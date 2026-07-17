//! Share groups — the zero-knowledge relay for family sharing.
//!
//! A **share group** lets several accounts hold the *same* vault. The server
//! stores only public material: each member's display name + X25519 **public**
//! key, pending invites (as SHA-256 *hashes* of the invite code — never the code
//! itself), the opaque per-member **wrapped keys** (a serialized
//! `proctor_passbook::sharing::SharedVault`, i.e. ciphertext of the vault key to
//! each member), and the opaque shared **content** blob. It never sees the vault
//! key, any master password, or any Secret Key — the same zero-knowledge promise
//! as the personal-vault path in [`crate`], extended to multiple people.
//!
//! Policy that must be *atomic* (invite TTL + single-use, membership changes,
//! optimistic concurrency on the two versioned blobs) lives on the store so a
//! read-modify-write cannot interleave. Higher-level authorization (who may call
//! what) is enforced by the server against the [`ShareGroup::member_by_account`]
//! directory.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::{next_version, SyncError};

/// A fresh random 128-bit id as lowercase hex — used for group ids and invite
/// codes. Unrelated to any account or key material (zero-knowledge).
pub fn new_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// SHA-256 of an invite code, as 64-char lowercase hex. The server stores this,
/// never the code — a breached group registry yields no usable invite (the same
/// pattern as device-token hashing).
pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A member of a share group — public identity only.
///
/// Zero-knowledge: `public_key` is the member's X25519 **public** key (opaque
/// bytes to the server), `account_id` is which sync account authenticates as this
/// member. No secret material is ever stored here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMember {
    /// Stable member id (client-chosen; matches the `SharedVault` recipient id).
    pub member_id: String,
    /// The sync account this member authenticates as (for authorization checks).
    pub account_id: String,
    /// Human-readable display name (public).
    pub name: String,
    /// The member's X25519 public key, opaque to the server (base64/hex client-side).
    pub public_key: String,
    /// Whether this member owns the group (owner-only ops like revoke).
    pub is_owner: bool,
    /// When the member joined (unix seconds).
    pub added_epoch: u64,
}

/// A pending invite. The server stores only the SHA-256 **hash** of the code, so
/// a breached group registry leaks no usable invite.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInvite {
    /// SHA-256 hex of the invite code (the plaintext code lives only client-side).
    pub code_hash: String,
    /// When the invite was minted (unix seconds).
    pub created_epoch: u64,
    /// When it expires (unix seconds). A redeem at/after this is [`RedeemOutcome::Expired`].
    pub expires_epoch: u64,
    /// The member id that redeemed it, once used (invites are single-use).
    pub redeemed_by: Option<String>,
}

/// A share group: membership directory, invites, per-member wrapped keys, and the
/// shared content blob — each versioned for optimistic concurrency.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareGroup {
    /// Server-unique group id.
    pub group_id: String,
    /// Membership directory (owner first, by construction).
    pub members: Vec<GroupMember>,
    /// Pending + redeemed invites.
    pub invites: Vec<GroupInvite>,
    /// Opaque serialized `SharedVault` — per-member wrapped copies of the vault key.
    pub wrapped_keys: Vec<u8>,
    /// Version of `wrapped_keys` (optimistic concurrency).
    pub keys_version: u64,
    /// The shared vault content blob (opaque, same shape as a personal vault).
    pub content: Vec<u8>,
    /// Version of `content` (optimistic concurrency).
    pub content_version: u64,
}

impl ShareGroup {
    /// The member authenticating as `account_id`, if any.
    pub fn member_by_account(&self, account_id: &str) -> Option<&GroupMember> {
        self.members.iter().find(|m| m.account_id == account_id)
    }

    /// Whether `account_id` is a member of this group.
    pub fn is_member(&self, account_id: &str) -> bool {
        self.member_by_account(account_id).is_some()
    }

    /// Whether `account_id` owns this group.
    pub fn is_owner(&self, account_id: &str) -> bool {
        self.member_by_account(account_id)
            .map(|m| m.is_owner)
            .unwrap_or(false)
    }
}

/// The outcome of redeeming an invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemOutcome {
    /// The invite was valid; the new member was added to the group.
    Added,
    /// No group with that id exists.
    NoSuchGroup,
    /// The code hash matches no live invite, or the invite was already redeemed.
    InvalidOrUsed,
    /// The invite existed but has expired.
    Expired,
}

/// The driven port for share-group storage. Each mutating method is atomic under
/// the store's lock — no read-modify-write races.
pub trait ShareGroupStore {
    /// Create a new group owned by `owner`. Errors with [`SyncError::Conflict`]
    /// (server_version 0) if the id is already taken.
    fn create(&self, group_id: &str, owner: GroupMember) -> Result<ShareGroup, SyncError>;

    /// Fetch a group, or `None` if it does not exist.
    fn get(&self, group_id: &str) -> Result<Option<ShareGroup>, SyncError>;

    /// Append a pending invite to a group. Returns `false` if the group is gone.
    fn add_invite(&self, group_id: &str, invite: GroupInvite) -> Result<bool, SyncError>;

    /// Redeem an invite (atomic: checks existence, expiry, and single-use) and, on
    /// success, add `new_member`. `now_epoch` decides expiry.
    fn redeem_invite(
        &self,
        group_id: &str,
        code_hash: &str,
        new_member: GroupMember,
        now_epoch: u64,
    ) -> Result<RedeemOutcome, SyncError>;

    /// Remove a member. Returns `true` if a member was removed.
    fn remove_member(&self, group_id: &str, member_id: &str) -> Result<bool, SyncError>;

    /// Replace the per-member wrapped keys under optimistic concurrency. Returns
    /// the new `keys_version`, or [`SyncError::Conflict`]/[`SyncError::NotFound`].
    fn put_keys(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        wrapped_keys: Vec<u8>,
    ) -> Result<u64, SyncError>;

    /// Replace the shared content blob under optimistic concurrency. Returns the
    /// new `content_version`, or [`SyncError::Conflict`]/[`SyncError::NotFound`].
    fn put_content(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError>;

    /// Delete a group entirely. Idempotent.
    fn delete(&self, group_id: &str) -> Result<(), SyncError>;
}

/// Apply an invite redemption to an already-loaded group. Pure so both adapters
/// share the exact policy (existence handled by the caller).
fn apply_redeem(
    group: &mut ShareGroup,
    code_hash: &str,
    new_member: GroupMember,
    now_epoch: u64,
) -> RedeemOutcome {
    let Some(invite) = group.invites.iter_mut().find(|i| i.code_hash == code_hash) else {
        return RedeemOutcome::InvalidOrUsed;
    };
    if invite.redeemed_by.is_some() {
        return RedeemOutcome::InvalidOrUsed;
    }
    if now_epoch >= invite.expires_epoch {
        return RedeemOutcome::Expired;
    }
    invite.redeemed_by = Some(new_member.member_id.clone());
    // Replace an existing membership for the same account (re-join), else append.
    if let Some(existing) = group
        .members
        .iter_mut()
        .find(|m| m.account_id == new_member.account_id)
    {
        *existing = new_member;
    } else {
        group.members.push(new_member);
    }
    RedeemOutcome::Added
}

/// In-memory store (tests, and a stateless dev server).
#[derive(Default)]
pub struct MemoryShareGroupStore {
    inner: Mutex<HashMap<String, ShareGroup>>,
}

impl MemoryShareGroupStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ShareGroupStore for MemoryShareGroupStore {
    fn create(&self, group_id: &str, owner: GroupMember) -> Result<ShareGroup, SyncError> {
        let mut map = self.inner.lock().unwrap();
        if map.contains_key(group_id) {
            return Err(SyncError::Conflict { server_version: 0 });
        }
        let group = ShareGroup {
            group_id: group_id.to_string(),
            members: vec![owner],
            ..Default::default()
        };
        map.insert(group_id.to_string(), group.clone());
        Ok(group)
    }

    fn get(&self, group_id: &str) -> Result<Option<ShareGroup>, SyncError> {
        Ok(self.inner.lock().unwrap().get(group_id).cloned())
    }

    fn add_invite(&self, group_id: &str, invite: GroupInvite) -> Result<bool, SyncError> {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(group_id) {
            Some(g) => {
                g.invites.push(invite);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn redeem_invite(
        &self,
        group_id: &str,
        code_hash: &str,
        new_member: GroupMember,
        now_epoch: u64,
    ) -> Result<RedeemOutcome, SyncError> {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(group_id) {
            Some(g) => Ok(apply_redeem(g, code_hash, new_member, now_epoch)),
            None => Ok(RedeemOutcome::NoSuchGroup),
        }
    }

    fn remove_member(&self, group_id: &str, member_id: &str) -> Result<bool, SyncError> {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(group_id) {
            Some(g) => {
                let before = g.members.len();
                g.members.retain(|m| m.member_id != member_id);
                Ok(g.members.len() != before)
            }
            None => Ok(false),
        }
    }

    fn put_keys(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        wrapped_keys: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let mut map = self.inner.lock().unwrap();
        let g = map.get_mut(group_id).ok_or(SyncError::NotFound)?;
        let version = next_version(nonzero(g.keys_version), expected_version)?;
        g.keys_version = version;
        g.wrapped_keys = wrapped_keys;
        Ok(version)
    }

    fn put_content(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let mut map = self.inner.lock().unwrap();
        let g = map.get_mut(group_id).ok_or(SyncError::NotFound)?;
        let version = next_version(nonzero(g.content_version), expected_version)?;
        g.content_version = version;
        g.content = blob;
        Ok(version)
    }

    fn delete(&self, group_id: &str) -> Result<(), SyncError> {
        self.inner.lock().unwrap().remove(group_id);
        Ok(())
    }
}

/// Map a stored version of 0 ("never written") to `None`, matching the
/// `expected_version` convention used by [`next_version`].
fn nonzero(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}

/// Filesystem store: one JSON file per group under `dir`, serialized by a process
/// mutex so concurrent requests don't interleave a read-modify-write.
pub struct FileShareGroupStore {
    dir: PathBuf,
    guard: Mutex<()>,
}

impl FileShareGroupStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            guard: Mutex::new(()),
        }
    }

    /// Path of a group's file. The id is sanitized to a safe base name so it
    /// cannot escape the storage directory.
    fn path(&self, group_id: &str) -> PathBuf {
        let safe: String = group_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("group-{safe}.json"))
    }

    fn read(&self, group_id: &str) -> Result<Option<ShareGroup>, SyncError> {
        let path = self.path(group_id);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&std::fs::read(&path)?)?))
    }

    fn write(&self, group: &ShareGroup) -> Result<(), SyncError> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.path(&group.group_id), serde_json::to_vec(group)?)?;
        Ok(())
    }
}

impl ShareGroupStore for FileShareGroupStore {
    fn create(&self, group_id: &str, owner: GroupMember) -> Result<ShareGroup, SyncError> {
        let _lock = self.guard.lock().unwrap();
        if self.read(group_id)?.is_some() {
            return Err(SyncError::Conflict { server_version: 0 });
        }
        let group = ShareGroup {
            group_id: group_id.to_string(),
            members: vec![owner],
            ..Default::default()
        };
        self.write(&group)?;
        Ok(group)
    }

    fn get(&self, group_id: &str) -> Result<Option<ShareGroup>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        self.read(group_id)
    }

    fn add_invite(&self, group_id: &str, invite: GroupInvite) -> Result<bool, SyncError> {
        let _lock = self.guard.lock().unwrap();
        match self.read(group_id)? {
            Some(mut g) => {
                g.invites.push(invite);
                self.write(&g)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn redeem_invite(
        &self,
        group_id: &str,
        code_hash: &str,
        new_member: GroupMember,
        now_epoch: u64,
    ) -> Result<RedeemOutcome, SyncError> {
        let _lock = self.guard.lock().unwrap();
        match self.read(group_id)? {
            Some(mut g) => {
                let outcome = apply_redeem(&mut g, code_hash, new_member, now_epoch);
                if outcome == RedeemOutcome::Added {
                    self.write(&g)?;
                }
                Ok(outcome)
            }
            None => Ok(RedeemOutcome::NoSuchGroup),
        }
    }

    fn remove_member(&self, group_id: &str, member_id: &str) -> Result<bool, SyncError> {
        let _lock = self.guard.lock().unwrap();
        match self.read(group_id)? {
            Some(mut g) => {
                let before = g.members.len();
                g.members.retain(|m| m.member_id != member_id);
                let removed = g.members.len() != before;
                if removed {
                    self.write(&g)?;
                }
                Ok(removed)
            }
            None => Ok(false),
        }
    }

    fn put_keys(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        wrapped_keys: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut g = self.read(group_id)?.ok_or(SyncError::NotFound)?;
        let version = next_version(nonzero(g.keys_version), expected_version)?;
        g.keys_version = version;
        g.wrapped_keys = wrapped_keys;
        self.write(&g)?;
        Ok(version)
    }

    fn put_content(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut g = self.read(group_id)?.ok_or(SyncError::NotFound)?;
        let version = next_version(nonzero(g.content_version), expected_version)?;
        g.content_version = version;
        g.content = blob;
        self.write(&g)?;
        Ok(version)
    }

    fn delete(&self, group_id: &str) -> Result<(), SyncError> {
        let _lock = self.guard.lock().unwrap();
        match std::fs::remove_file(self.path(group_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> GroupMember {
        GroupMember {
            member_id: "m-owner".into(),
            account_id: "acct-owner".into(),
            name: "Alice".into(),
            public_key: "alice-pub".into(),
            is_owner: true,
            added_epoch: 100,
        }
    }

    fn invitee() -> GroupMember {
        GroupMember {
            member_id: "m-bob".into(),
            account_id: "acct-bob".into(),
            name: "Bob".into(),
            public_key: "bob-pub".into(),
            is_owner: false,
            added_epoch: 200,
        }
    }

    fn invite(code_hash: &str, expires: u64) -> GroupInvite {
        GroupInvite {
            code_hash: code_hash.into(),
            created_epoch: 100,
            expires_epoch: expires,
            redeemed_by: None,
        }
    }

    fn suite(store: &dyn ShareGroupStore) {
        // Create a group; owner is the sole member.
        let g = store.create("g1", owner()).unwrap();
        assert_eq!(g.members.len(), 1);
        assert!(g.is_owner("acct-owner"));
        assert!(!g.is_member("acct-bob"));

        // Duplicate id conflicts.
        assert!(matches!(
            store.create("g1", owner()).unwrap_err(),
            SyncError::Conflict { server_version: 0 }
        ));

        // Invite + redeem adds Bob.
        assert!(store.add_invite("g1", invite("hash-ok", 1_000)).unwrap());
        assert_eq!(
            store
                .redeem_invite("g1", "hash-ok", invitee(), 500)
                .unwrap(),
            RedeemOutcome::Added
        );
        let g = store.get("g1").unwrap().unwrap();
        assert!(g.is_member("acct-bob"));
        assert_eq!(g.member_by_account("acct-bob").unwrap().name, "Bob");

        // Single-use: the same code cannot be redeemed twice.
        assert_eq!(
            store
                .redeem_invite("g1", "hash-ok", invitee(), 500)
                .unwrap(),
            RedeemOutcome::InvalidOrUsed
        );

        // Unknown code / expired.
        assert_eq!(
            store.redeem_invite("g1", "nope", invitee(), 500).unwrap(),
            RedeemOutcome::InvalidOrUsed
        );
        assert!(store.add_invite("g1", invite("hash-old", 400)).unwrap());
        assert_eq!(
            store
                .redeem_invite("g1", "hash-old", invitee(), 500)
                .unwrap(),
            RedeemOutcome::Expired
        );

        // No such group.
        assert_eq!(
            store.redeem_invite("ghost", "x", invitee(), 500).unwrap(),
            RedeemOutcome::NoSuchGroup
        );

        // Wrapped-keys optimistic concurrency: first write expects None → v1.
        assert_eq!(store.put_keys("g1", None, b"wrap-1".to_vec()).unwrap(), 1);
        assert_eq!(
            store.put_keys("g1", Some(1), b"wrap-2".to_vec()).unwrap(),
            2
        );
        assert!(matches!(
            store
                .put_keys("g1", Some(1), b"stale".to_vec())
                .unwrap_err(),
            SyncError::Conflict { server_version: 2 }
        ));

        // Content optimistic concurrency is independent of keys.
        assert_eq!(
            store.put_content("g1", None, b"blob-1".to_vec()).unwrap(),
            1
        );
        let g = store.get("g1").unwrap().unwrap();
        assert_eq!(g.wrapped_keys, b"wrap-2");
        assert_eq!(g.content, b"blob-1");
        assert_eq!(g.keys_version, 2);
        assert_eq!(g.content_version, 1);

        // put on a missing group is NotFound.
        assert!(matches!(
            store.put_keys("ghost", None, b"x".to_vec()).unwrap_err(),
            SyncError::NotFound
        ));

        // Remove Bob; he is no longer a member.
        assert!(store.remove_member("g1", "m-bob").unwrap());
        assert!(!store.get("g1").unwrap().unwrap().is_member("acct-bob"));
        assert!(!store.remove_member("g1", "m-bob").unwrap());

        // Delete is idempotent.
        store.delete("g1").unwrap();
        assert!(store.get("g1").unwrap().is_none());
        store.delete("g1").unwrap();
    }

    #[test]
    fn memory_group_store() {
        suite(&MemoryShareGroupStore::new());
    }

    #[test]
    fn file_group_store() {
        let dir = std::env::temp_dir().join(format!("proctor-groups-test-{}", std::process::id()));
        let store = FileShareGroupStore::new(&dir);
        suite(&store);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn group_id_is_sanitized_to_a_safe_path() {
        let dir = std::env::temp_dir().join(format!("proctor-groups-safe-{}", std::process::id()));
        let store = FileShareGroupStore::new(&dir);
        store.create("../../etc/passwd", owner()).unwrap();
        assert!(!std::path::Path::new("/etc/passwd.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
