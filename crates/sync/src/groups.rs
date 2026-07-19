//! Share groups — the zero-knowledge relay for family sharing.
//!
//! A **share group** lets several accounts hold the *same* vault. The server
//! stores only public material: each member's display name + X25519 **public**
//! key, pending invites (as SHA-256 *hashes* of the invite code — never the code
//! itself), the opaque per-member **wrapped keys** (a serialized
//! `keyward_passbook::sharing::SharedVault`, i.e. ciphertext of the vault key to
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

/// A member's role in a group — the authorization model. A family vault uses just
/// Owner + Member; Teams (see ADR-0006) add Admin. Ordered by privilege, so
/// comparisons like `role >= Role::Admin` work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read and write shared content. Cannot invite or manage members.
    #[default]
    Member,
    /// Everything a Member can do, plus invite and remove members.
    Admin,
    /// Full control: everything an Admin can do, plus changing roles. Created with
    /// the group; an Owner cannot be removed by anyone else.
    Owner,
}

impl Role {
    /// The canonical lowercase name (stored in Postgres / group JSON).
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }

    /// Parse a stored role name; anything unrecognized falls back to `Member`
    /// (fail closed — an unknown role gets the fewest privileges).
    pub fn parse(s: &str) -> Role {
        match s.trim().to_ascii_lowercase().as_str() {
            "owner" => Role::Owner,
            "admin" => Role::Admin,
            _ => Role::Member,
        }
    }

    /// May invite new members and remove existing ones (Admin or Owner).
    pub fn can_manage_members(&self) -> bool {
        *self >= Role::Admin
    }

    /// May change other members' roles (Owner only).
    pub fn can_change_roles(&self) -> bool {
        *self == Role::Owner
    }
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
    /// The member's Ed25519 verifying key, opaque to the server, used by other
    /// members to authenticate wrapped-key sets this member writes.
    ///
    /// Published here only so members can DISCOVER it on first contact. It is
    /// not authoritative: a client pins the key locally on first sight and
    /// verifies against the pin thereafter. Trusting this field on every read
    /// would defeat the point, since the server serving it also serves the
    /// wrapped keys it is supposed to authenticate.
    ///
    /// `#[serde(default)]` (empty) keeps groups written before signing loadable;
    /// an empty key verifies nothing and fails closed.
    #[serde(default)]
    pub signing_key: String,
    /// This member's role. `#[serde(default)]` keeps pre-role group JSON loadable
    /// (those members load as `Member`; Postgres backfills Owner from the legacy
    /// `is_owner` column on migration).
    #[serde(default)]
    pub role: Role,
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
    /// Accounts that have been removed from this group and may not rejoin by
    /// redeeming an invite.
    ///
    /// Without this, removal was reversible by anyone holding an unredeemed
    /// code: removing a member did not invalidate outstanding invites, and
    /// `apply_redeem` had no notion of a removed account, so an Admin could mint
    /// an invite for themselves before being removed and simply redeem it
    /// afterwards. Removal also does not revoke the account's device token, so
    /// they could still reach the endpoint.
    ///
    /// Account ids only — no key material, nothing that is not already in
    /// `members`. `#[serde(default)]` keeps pre-existing group JSON loadable.
    #[serde(default)]
    pub removed_accounts: Vec<String>,
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

    /// The role `account_id` holds in this group, if they are a member.
    pub fn role_of(&self, account_id: &str) -> Option<Role> {
        self.member_by_account(account_id).map(|m| m.role)
    }

    /// Whether `account_id` owns this group.
    pub fn is_owner(&self, account_id: &str) -> bool {
        self.role_of(account_id) == Some(Role::Owner)
    }

    /// Whether `account_id` may invite/remove members (Admin or Owner).
    pub fn can_manage_members(&self, account_id: &str) -> bool {
        self.role_of(account_id)
            .is_some_and(|r| r.can_manage_members())
    }

    /// Whether `account_id` may change other members' roles (Owner only).
    pub fn can_change_roles(&self, account_id: &str) -> bool {
        self.role_of(account_id)
            .is_some_and(|r| r.can_change_roles())
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
    /// The account was removed from this group and may not rejoin by invite.
    /// An Owner must issue a fresh membership deliberately.
    AccountRemoved,
    /// The requested `member_id` is already in use by a different account.
    ///
    /// `member_id` is the key by which wraps are stored and looked up, so a
    /// collision is not cosmetic: a joiner claiming the Owner's `member_id`
    /// becomes unremovable and, at the next rotation, their wrap overwrites the
    /// Owner's — locking the Owner out with no removal path.
    MemberIdTaken,
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

    /// Change a member's role. Returns `true` if a matching member was updated.
    /// Authorization (who may call this) is enforced by the server, not the store.
    fn set_member_role(
        &self,
        group_id: &str,
        member_id: &str,
        role: Role,
    ) -> Result<bool, SyncError>;

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

    /// Erase every trace of `account_id` from every group in this store — the
    /// group half of account deletion (GDPR Art. 17). Applies
    /// [`apply_account_erasure`] to each group the account touches, deleting a
    /// group outright when the erasure empties it. Returns how many groups were
    /// changed or deleted.
    ///
    /// Must be atomic *per group*, like every other mutating method here.
    /// Idempotent: erasing an account that is in no group is `Ok(0)`.
    fn erase_account(&self, account_id: &str) -> Result<usize, SyncError>;
}

/// Apply an invite redemption to an already-loaded group. Pure so every adapter
/// shares the exact policy (existence handled by the caller).
///
/// Every invariant below belongs HERE rather than in a storage adapter. The
/// Postgres adapter happens to declare `PRIMARY KEY (group_id, member_id)`,
/// which incidentally rejected duplicate member ids on the managed instance
/// while the file and memory stores — the self-host defaults — accepted them.
/// An invariant enforced by one backend and not by the shared policy is a bug in
/// the policy, and the doc comment claiming adapters "share the exact policy"
/// was false while that was the case.
pub fn apply_redeem(
    group: &mut ShareGroup,
    code_hash: &str,
    new_member: GroupMember,
    now_epoch: u64,
) -> RedeemOutcome {
    // Removed accounts may not readmit themselves. Checked BEFORE the invite so
    // a stashed code cannot even probe validity.
    if group
        .removed_accounts
        .iter()
        .any(|a| a == &new_member.account_id)
    {
        return RedeemOutcome::AccountRemoved;
    }

    // `member_id` is the cryptographic identity key: wraps are stored and looked
    // up by it. It is client-chosen, so it must be checked for collision against
    // any OTHER account. (Matching one's own existing row is the re-join case.)
    if group
        .members
        .iter()
        .any(|m| m.member_id == new_member.member_id && m.account_id != new_member.account_id)
    {
        return RedeemOutcome::MemberIdTaken;
    }

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
        // PRESERVE THE EXISTING ROLE. A wholesale `*existing = new_member` let a
        // re-join silently rewrite it, and the join handler hardcodes
        // `Role::Member`. An Admin could therefore mint an invite, persuade the
        // Owner to redeem it ("rejoin from your phone"), and demote them to
        // Member. Since `can_change_roles` is strictly Owner-only, no one could
        // ever restore an Owner: the group became permanently unadministrable,
        // the "an owner cannot be removed" guard matched nobody, and there is no
        // delete-group route. Unrecoverable.
        let preserved_role = existing.role;
        *existing = GroupMember {
            role: preserved_role,
            ..new_member
        };
    } else {
        group.members.push(new_member);
    }
    RedeemOutcome::Added
}

/// Remove a member, and close the paths that made removal reversible. Pure, and
/// shared by every adapter for the same reason as [`apply_redeem`].
///
/// Returns whether a member was actually removed.
///
/// Refuses to remove the last Owner: with no Owner, `can_change_roles` (strictly
/// Owner-only) can never be satisfied again, so no role could be granted and the
/// group would be permanently stuck.
pub fn apply_remove(group: &mut ShareGroup, member_id: &str) -> bool {
    let Some(target) = group.members.iter().find(|m| m.member_id == member_id) else {
        return false;
    };
    if target.role == Role::Owner
        && group
            .members
            .iter()
            .filter(|m| m.role == Role::Owner)
            .count()
            <= 1
    {
        return false;
    }
    let account_id = target.account_id.clone();

    group.members.retain(|m| m.member_id != member_id);

    // Bar readmission by invite. Removal previously left `group.invites`
    // untouched, so any outstanding code was a standing readmission ticket —
    // and with auto-reconcile on the client, re-entry silently yielded the
    // CURRENT vault key, including content written after the eviction and the
    // rotation that followed it.
    if !group.removed_accounts.iter().any(|a| a == &account_id) {
        group.removed_accounts.push(account_id);
    }

    // Invalidate EVERY pending invite, not just one. An invite records only a
    // code hash — there is no intended recipient — so it is impossible to tell
    // which pending code the removed member is holding. Retaining redeemed
    // invites keeps their code hashes known, so a previously used code still
    // resolves to "already redeemed" rather than becoming unknown.
    //
    // The tradeoff is deliberate: an invite minted for someone else is also
    // cancelled and must be re-issued. Cancelling a legitimate invite is a
    // minor inconvenience; failing to cancel the attacker's is a full
    // compromise of the shared vault.
    group.invites.retain(|i| i.redeemed_by.is_some());

    true
}

/// What erasing an account did to one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountErasure {
    /// The account appears nowhere in this group; nothing was written.
    Untouched,
    /// The group still exists and was rewritten without the account.
    Updated,
    /// The account was the group's only remaining member. The caller must
    /// DELETE the group: keeping a memberless group would leave exactly the
    /// orphaned rows account deletion exists to remove, and nobody is left who
    /// could ever read it.
    Emptied,
}

/// Erase an account from a group as part of deleting that account. Pure, and
/// shared by every adapter for the same reason as [`apply_redeem`].
///
/// This is deliberately NOT [`apply_remove`], for three reasons:
///
/// 1. **It cannot refuse.** `apply_remove` protects the last Owner, because a
///    group with no Owner can never have a role granted again
///    (`can_change_roles` is Owner-only) and is permanently stuck. That guard is
///    right for "an Admin evicts someone" and wrong here: an Owner who deletes
///    their account must not be told "no", and leaving their membership row
///    behind would make erasure a lie. So when the departing account holds the
///    last Owner role and other members remain, the longest-standing remaining
///    member is **promoted to Owner** first. The group survives administrable,
///    which is the whole point of considering group membership at all — deleting
///    one member's account must not corrupt the group for everyone else.
///
/// 2. **It leaves no tombstone.** `apply_remove` records the account in
///    `removed_accounts` so a stashed invite cannot readmit it. Here that row
///    would be a retained identifier of an account that no longer exists — the
///    exact thing Art. 17 forbids — and it is pointless: account ids are random
///    128-bit values that are never re-issued, so there is no account left to
///    bar. Any pre-existing tombstone for this account is scrubbed too.
///
/// 3. **It removes what the account left in the invite log.** Invites the erased
///    member redeemed carry their `member_id` in `redeemed_by`, so those rows go.
///    Pending invites are cancelled wholesale, for the same reason as in
///    `apply_remove`: an invite names no recipient, so there is no way to tell
///    which pending code the departing member is holding. Other members' already-
///    redeemed invites are kept, so a reused code still resolves to "already
///    redeemed" rather than becoming unknown.
///
/// What this deliberately does NOT do is rewrite `wrapped_keys`. That blob is
/// opaque ciphertext the server must never interpret; the erased member's copy of
/// the wrapped vault key stays in it until the remaining members' clients rotate,
/// exactly as after an ordinary removal. The server cannot fix that without
/// giving up zero knowledge, and it would not help anyway: the departing user
/// already held the key.
pub fn apply_account_erasure(group: &mut ShareGroup, account_id: &str) -> AccountErasure {
    let member_id = group
        .member_by_account(account_id)
        .map(|m| m.member_id.clone());
    let has_tombstone = group.removed_accounts.iter().any(|a| a == account_id);
    if member_id.is_none() && !has_tombstone {
        return AccountErasure::Untouched;
    }

    // Reason 2: the account is going away, so no record of it may remain.
    group.removed_accounts.retain(|a| a != account_id);

    let Some(member_id) = member_id else {
        // Only a tombstone to scrub — membership is unaffected.
        return AccountErasure::Updated;
    };

    // Sole member: nothing left to preserve, so the group goes with the account.
    if group.members.iter().all(|m| m.account_id == account_id) {
        return AccountErasure::Emptied;
    }

    // Reason 1: never leave the group Ownerless. `added_epoch` order makes the
    // successor deterministic (longest-standing member) rather than dependent on
    // whatever order an adapter happens to load rows in.
    let loses_last_owner = group
        .members
        .iter()
        .filter(|m| m.role == Role::Owner)
        .all(|m| m.account_id == account_id);
    if loses_last_owner {
        if let Some(successor) = group
            .members
            .iter_mut()
            .filter(|m| m.account_id != account_id)
            .min_by_key(|m| (m.added_epoch, m.member_id.clone()))
        {
            successor.role = Role::Owner;
        }
    }

    group.members.retain(|m| m.account_id != account_id);

    // Reason 3.
    group
        .invites
        .retain(|i| i.redeemed_by.as_deref() != Some(member_id.as_str()));
    group.invites.retain(|i| i.redeemed_by.is_some());

    AccountErasure::Updated
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
            Some(g) => Ok(apply_remove(g, member_id)),
            None => Ok(false),
        }
    }

    fn set_member_role(
        &self,
        group_id: &str,
        member_id: &str,
        role: Role,
    ) -> Result<bool, SyncError> {
        let mut map = self.inner.lock().unwrap();
        match map
            .get_mut(group_id)
            .and_then(|g| g.members.iter_mut().find(|m| m.member_id == member_id))
        {
            Some(member) => {
                member.role = role;
                Ok(true)
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

    fn erase_account(&self, account_id: &str) -> Result<usize, SyncError> {
        let mut map = self.inner.lock().unwrap();
        let mut changed = 0;
        let mut emptied = Vec::new();
        for (group_id, group) in map.iter_mut() {
            match apply_account_erasure(group, account_id) {
                AccountErasure::Untouched => {}
                AccountErasure::Updated => changed += 1,
                AccountErasure::Emptied => emptied.push(group_id.clone()),
            }
        }
        for group_id in &emptied {
            map.remove(group_id);
        }
        Ok(changed + emptied.len())
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
                let removed = apply_remove(&mut g, member_id);
                if removed {
                    self.write(&g)?;
                }
                Ok(removed)
            }
            None => Ok(false),
        }
    }

    fn set_member_role(
        &self,
        group_id: &str,
        member_id: &str,
        role: Role,
    ) -> Result<bool, SyncError> {
        let _lock = self.guard.lock().unwrap();
        match self.read(group_id)? {
            Some(mut g) => {
                let Some(member) = g.members.iter_mut().find(|m| m.member_id == member_id) else {
                    return Ok(false);
                };
                member.role = role;
                self.write(&g)?;
                Ok(true)
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

    fn erase_account(&self, account_id: &str) -> Result<usize, SyncError> {
        let _lock = self.guard.lock().unwrap();
        // There is no index from account to group on disk, so every group file is
        // scanned. Self-host installs hold a handful of groups and this runs once
        // per account deletion, so a scan is the right trade against maintaining a
        // second on-disk index that could drift out of sync with the group files.
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            // No storage dir yet → no groups → nothing to erase.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let mut affected = 0;
        for entry in entries {
            let path = entry?.path();
            let is_group_file = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("group-") && n.ends_with(".json"));
            if !is_group_file {
                continue;
            }
            let mut group: ShareGroup = serde_json::from_slice(&std::fs::read(&path)?)?;
            match apply_account_erasure(&mut group, account_id) {
                AccountErasure::Untouched => {}
                AccountErasure::Updated => {
                    self.write(&group)?;
                    affected += 1;
                }
                AccountErasure::Emptied => {
                    // Remove the file we actually read, not a path re-derived from
                    // the id — they agree today, but erasure must not depend on that.
                    std::fs::remove_file(&path)?;
                    affected += 1;
                }
            }
        }
        Ok(affected)
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
            signing_key: String::new(),
            role: Role::Owner,
            added_epoch: 100,
        }
    }

    fn invitee() -> GroupMember {
        GroupMember {
            member_id: "m-bob".into(),
            account_id: "acct-bob".into(),
            name: "Bob".into(),
            public_key: "bob-pub".into(),
            signing_key: String::new(),
            role: Role::Member,
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
        let dir = std::env::temp_dir().join(format!("keyward-groups-test-{}", std::process::id()));
        let store = FileShareGroupStore::new(&dir);
        suite(&store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Erasing an account must remove every trace of it from the groups it
    /// touches, while leaving those groups usable for everyone else.
    fn erasure_suite(store: &dyn ShareGroupStore) {
        let member = |mid: &str, acct: &str, role: Role, epoch: u64| GroupMember {
            member_id: mid.into(),
            account_id: acct.into(),
            name: mid.into(),
            public_key: format!("{mid}-pub"),
            signing_key: String::new(),
            role,
            added_epoch: epoch,
        };
        let open = |h: &str| GroupInvite {
            code_hash: h.into(),
            created_epoch: 100,
            expires_epoch: u64::MAX,
            redeemed_by: None,
        };

        // A group with an owner and two members; the OWNER erases their account.
        store
            .create("eg", member("m-o", "acct-o", Role::Owner, 100))
            .unwrap();
        assert!(store.add_invite("eg", open("h-b")).unwrap());
        assert_eq!(
            store
                .redeem_invite("eg", "h-b", member("m-b", "acct-b", Role::Member, 300), 200)
                .unwrap(),
            RedeemOutcome::Added
        );
        assert!(store.add_invite("eg", open("h-c")).unwrap());
        assert_eq!(
            store
                .redeem_invite("eg", "h-c", member("m-c", "acct-c", Role::Member, 200), 200)
                .unwrap(),
            RedeemOutcome::Added
        );
        // Ordinary removal of the last owner is refused; erasure cannot be.
        assert!(!store.remove_member("eg", "m-o").unwrap());
        assert!(store.add_invite("eg", open("h-pending")).unwrap());

        assert_eq!(store.erase_account("acct-o").unwrap(), 1);
        let g = store.get("eg").unwrap().unwrap();
        assert!(!g.is_member("acct-o"));
        assert_eq!(g.members.len(), 2);
        // The longest-standing survivor is promoted, so the group stays administrable.
        assert!(g.is_owner("acct-c"));
        assert!(g.can_change_roles("acct-c"));
        // No tombstone for an account that no longer exists.
        assert!(g.removed_accounts.is_empty());
        // Pending invites are cancelled (no way to know which the leaver held).
        assert_eq!(
            store
                .redeem_invite(
                    "eg",
                    "h-pending",
                    member("m-d", "acct-d", Role::Member, 500),
                    200
                )
                .unwrap(),
            RedeemOutcome::InvalidOrUsed
        );

        // An account in no group is a no-op; erasure is idempotent.
        assert_eq!(store.erase_account("acct-o").unwrap(), 0);
        assert_eq!(store.erase_account("nobody").unwrap(), 0);

        // A group whose LAST member erases their account is deleted outright —
        // keeping a memberless group is the orphan this endpoint exists to avoid.
        store
            .create("eg-solo", member("m-s", "acct-s", Role::Owner, 100))
            .unwrap();
        assert_eq!(store.erase_account("acct-s").unwrap(), 1);
        assert!(store.get("eg-solo").unwrap().is_none());

        // A removed account's tombstone is scrubbed when that account is erased.
        store
            .create("eg-tomb", member("m-o2", "acct-o2", Role::Owner, 100))
            .unwrap();
        assert!(store.add_invite("eg-tomb", open("h-t")).unwrap());
        assert_eq!(
            store
                .redeem_invite(
                    "eg-tomb",
                    "h-t",
                    member("m-t", "acct-t", Role::Member, 200),
                    150
                )
                .unwrap(),
            RedeemOutcome::Added
        );
        assert!(store.remove_member("eg-tomb", "m-t").unwrap());
        assert!(store
            .get("eg-tomb")
            .unwrap()
            .unwrap()
            .removed_accounts
            .contains(&"acct-t".to_string()));
        assert_eq!(store.erase_account("acct-t").unwrap(), 1);
        let g = store.get("eg-tomb").unwrap().unwrap();
        assert!(g.removed_accounts.is_empty());
        assert!(g.is_owner("acct-o2"));

        store.delete("eg").unwrap();
        store.delete("eg-tomb").unwrap();
    }

    #[test]
    fn memory_group_store_erases_an_account() {
        erasure_suite(&MemoryShareGroupStore::new());
    }

    #[test]
    fn file_group_store_erases_an_account() {
        let dir = std::env::temp_dir().join(format!("keyward-erase-test-{}", std::process::id()));
        let store = FileShareGroupStore::new(&dir);
        erasure_suite(&store);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn erasure_of_an_unrelated_account_is_untouched() {
        let mut g = ShareGroup {
            group_id: "g".into(),
            members: vec![owner()],
            ..Default::default()
        };
        let before = g.clone();
        assert_eq!(
            apply_account_erasure(&mut g, "acct-stranger"),
            AccountErasure::Untouched
        );
        assert_eq!(g, before, "an unrelated erasure must not rewrite the group");
    }

    #[test]
    fn erasure_drops_invites_the_leaver_had_redeemed_but_keeps_others() {
        let mut g = ShareGroup {
            group_id: "g".into(),
            members: vec![owner(), invitee()],
            invites: vec![
                GroupInvite {
                    code_hash: "used-by-bob".into(),
                    created_epoch: 1,
                    expires_epoch: u64::MAX,
                    redeemed_by: Some("m-bob".into()),
                },
                GroupInvite {
                    code_hash: "used-by-owner".into(),
                    created_epoch: 1,
                    expires_epoch: u64::MAX,
                    redeemed_by: Some("m-owner".into()),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            apply_account_erasure(&mut g, "acct-bob"),
            AccountErasure::Updated
        );
        // Bob's redeemed invite carried his member_id — it goes with him. The
        // owner's stays, so a reused code still reads as "already redeemed"
        // rather than becoming an unknown one.
        let hashes: Vec<&str> = g.invites.iter().map(|i| i.code_hash.as_str()).collect();
        assert_eq!(hashes, vec!["used-by-owner"]);
    }

    #[test]
    fn group_id_is_sanitized_to_a_safe_path() {
        let dir = std::env::temp_dir().join(format!("keyward-groups-safe-{}", std::process::id()));
        let store = FileShareGroupStore::new(&dir);
        store.create("../../etc/passwd", owner()).unwrap();
        assert!(!std::path::Path::new("/etc/passwd.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
