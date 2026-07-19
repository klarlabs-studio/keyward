//! PostgreSQL adapters for the Sync ports — the **managed-cloud backend**.
//!
//! The file/memory adapters in [`keyward_sync`] are single-node. These implement
//! the same [`SyncStore`], [`AccountStore`], and [`ShareGroupStore`] ports over a
//! shared PostgreSQL database, so the HTTP API becomes **stateless and
//! horizontally scalable** (N replicas behind the ingress, all reading one
//! datastore). Vault blobs are small, so they live in Postgres `BYTEA` — object
//! storage is a later, at-scale optimization.
//!
//! **Zero-knowledge is preserved**: the database stores only opaque ciphertext
//! blobs, X25519 *public* keys, and SHA-256 *hashes* of device tokens and invite
//! codes — never a master password, Secret Key, or vault key. An `accounts.plan`
//! column is the seed of the entitlements plane (free / individual / family).
//!
//! The connection is synchronous (matching the blocking `tiny_http` server), so no
//! async runtime is needed; an r2d2 pool serves concurrent requests.

use postgres::NoTls;
use r2d2_postgres::PostgresConnectionManager;
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::io;

use keyward_sync::accounts::{Account, AccountStore, DeviceInfo, Plan, TokenIdentity};
use keyward_sync::groups::{
    apply_redeem, apply_remove, GroupInvite, GroupMember, RedeemOutcome, Role, ShareGroup,
    ShareGroupStore,
};
use keyward_sync::{SyncEnvelope, SyncError, SyncStore};

type Pool = r2d2::Pool<PostgresConnectionManager<NoTls>>;

/// The schema, applied idempotently by [`migrate`]. Intentionally FK-light: the
/// three ports are independent (a vault row need not have an account row), matching
/// the file/memory adapters. FKs exist only *within* the group aggregate so a group
/// delete cascades its members and invites.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    account_id    TEXT PRIMARY KEY,
    email         TEXT,
    plan          TEXT NOT NULL DEFAULT 'free',
    created_epoch  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL,
    label         TEXT NOT NULL,
    token_hash    TEXT NOT NULL,
    created_epoch  BIGINT NOT NULL,
    expires_epoch  BIGINT
);
CREATE INDEX IF NOT EXISTS devices_token_hash ON devices (token_hash);
CREATE INDEX IF NOT EXISTS devices_account ON devices (account_id);
CREATE TABLE IF NOT EXISTS vaults (
    account_id    TEXT PRIMARY KEY,
    version       BIGINT NOT NULL,
    blob          BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS share_groups (
    group_id        TEXT PRIMARY KEY,
    wrapped_keys    BYTEA NOT NULL DEFAULT ''::bytea,
    keys_version    BIGINT NOT NULL DEFAULT 0,
    content         BYTEA NOT NULL DEFAULT ''::bytea,
    content_version BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id      TEXT NOT NULL REFERENCES share_groups (group_id) ON DELETE CASCADE,
    member_id     TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    name          TEXT NOT NULL,
    public_key    TEXT NOT NULL,
    signing_key   TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'member',
    added_epoch    BIGINT NOT NULL,
    PRIMARY KEY (group_id, member_id)
);
-- Migrate databases created before roles existed: add the column, then relax the
-- legacy NOT NULL `is_owner` (so inserts may omit it) and backfill Owner from it.
-- A no-op on fresh databases, which never had `is_owner`.
ALTER TABLE group_members ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member';
-- Members enrolled before wrapped-key sets were signed have no verifying key.
-- Default empty rather than backfilling anything: a fabricated key would make
-- forged sets appear verified, which is the exact failure this column exists to
-- prevent. Empty means "cannot verify", and clients fail closed on it.
ALTER TABLE group_members ADD COLUMN IF NOT EXISTS signing_key TEXT NOT NULL DEFAULT '';
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'group_members' AND column_name = 'is_owner'
    ) THEN
        EXECUTE 'ALTER TABLE group_members ALTER COLUMN is_owner DROP NOT NULL';
        EXECUTE 'UPDATE group_members SET role = ''owner'' WHERE is_owner IS TRUE AND role = ''member''';
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS group_invites (
    group_id      TEXT NOT NULL REFERENCES share_groups (group_id) ON DELETE CASCADE,
    code_hash     TEXT NOT NULL,
    created_epoch  BIGINT NOT NULL,
    expires_epoch  BIGINT NOT NULL,
    redeemed_by   TEXT,
    PRIMARY KEY (group_id, code_hash)
);
-- Accounts removed from a group, which may not rejoin by redeeming an invite.
-- Removing a member did not previously invalidate outstanding invites, so any
-- unredeemed code was a standing readmission ticket; combined with client-side
-- auto-reconcile, re-entry silently handed back the post-rotation vault key.
-- Account ids only — no key material.
CREATE TABLE IF NOT EXISTS group_removed_accounts (
    group_id      TEXT NOT NULL REFERENCES share_groups (group_id) ON DELETE CASCADE,
    account_id    TEXT NOT NULL,
    removed_epoch BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, account_id)
);
"#;

/// Build a connection pool from a libpq connection string / URL and apply the
/// schema. Reused by all three stores (they can share one pool).
pub fn connect(url: &str, max_size: u32) -> Result<Pool, SyncError> {
    let config: postgres::Config = url.parse().map_err(db_err)?;
    let manager = PostgresConnectionManager::new(config, NoTls);
    let pool = r2d2::Pool::builder()
        .max_size(max_size)
        .build(manager)
        .map_err(db_err)?;
    migrate(&pool)?;
    Ok(pool)
}

/// Apply [`SCHEMA`] idempotently.
pub fn migrate(pool: &Pool) -> Result<(), SyncError> {
    let mut client = pool.get().map_err(db_err)?;
    client.batch_execute(SCHEMA).map_err(db_err)?;
    Ok(())
}

/// Map any DB/pool error into the port's error type (which has no DB variant).
fn db_err<E: Display>(e: E) -> SyncError {
    SyncError::Io(io::Error::other(e.to_string()))
}

/// The optimistic-concurrency rule (mirrors `keyward_sync`'s private helper): a
/// write is accepted only if the client's expected version matches the server's.
fn next_version(current: Option<u64>, expected: Option<u64>) -> Result<u64, SyncError> {
    if expected == current {
        Ok(current.unwrap_or(0) + 1)
    } else {
        Err(SyncError::Conflict {
            server_version: current.unwrap_or(0),
        })
    }
}

fn random_hex_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---- SyncStore -------------------------------------------------------------

/// Versioned opaque blob storage over Postgres.
pub struct PostgresSyncStore {
    pool: Pool,
}

impl PostgresSyncStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl SyncStore for PostgresSyncStore {
    fn get(&self, account: &str) -> Result<Option<SyncEnvelope>, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let row = c
            .query_opt(
                "SELECT version, blob FROM vaults WHERE account_id = $1",
                &[&account],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| SyncEnvelope {
            version: r.get::<_, i64>(0) as u64,
            blob: r.get::<_, Vec<u8>>(1),
        }))
    }

    fn put(
        &self,
        account: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;
        let current: Option<u64> = tx
            .query_opt(
                "SELECT version FROM vaults WHERE account_id = $1 FOR UPDATE",
                &[&account],
            )
            .map_err(db_err)?
            .map(|r| r.get::<_, i64>(0) as u64);
        let version = next_version(current, expected_version)?;
        let v = version as i64;
        if current.is_some() {
            tx.execute(
                "UPDATE vaults SET version = $1, blob = $2 WHERE account_id = $3",
                &[&v, &blob, &account],
            )
            .map_err(db_err)?;
        } else {
            tx.execute(
                "INSERT INTO vaults (account_id, version, blob) VALUES ($1, $2, $3)",
                &[&account, &v, &blob],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        Ok(version)
    }

    fn delete(&self, account: &str) -> Result<(), SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        c.execute("DELETE FROM vaults WHERE account_id = $1", &[&account])
            .map_err(db_err)?;
        Ok(())
    }
}

// ---- AccountStore ----------------------------------------------------------

/// Accounts + per-device tokens over Postgres. Tokens are stored only as SHA-256
/// hashes; the plaintext is returned once at register / add-device / rotate.
pub struct PostgresAccountStore {
    pool: Pool,
}

impl PostgresAccountStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl AccountStore for PostgresAccountStore {
    fn register(
        &self,
        email: Option<&str>,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Account, SyncError> {
        let account_id = random_hex_id();
        let device_id = random_hex_id();
        let device_token = random_hex_id();
        let expires: Option<i64> = ttl_seconds.map(|ttl| (now + ttl) as i64);
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO accounts (account_id, email, plan, created_epoch) VALUES ($1, $2, 'free', $3)",
            &[&account_id, &email, &(now as i64)],
        )
        .map_err(db_err)?;
        tx.execute(
            "INSERT INTO devices (device_id, account_id, label, token_hash, created_epoch, expires_epoch) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &device_id,
                &account_id,
                &label,
                &token_hash(&device_token),
                &(now as i64),
                &expires,
            ],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(Account {
            account_id,
            device_token,
            device_id,
        })
    }

    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Option<Account>, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let account_id: Option<String> = c
            .query_opt(
                "SELECT account_id FROM devices \
                 WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch > $2)",
                &[&token_hash(existing_token), &(now as i64)],
            )
            .map_err(db_err)?
            .map(|r| r.get(0));
        let Some(account_id) = account_id else {
            return Ok(None);
        };
        let device_id = random_hex_id();
        let device_token = random_hex_id();
        let expires: Option<i64> = ttl_seconds.map(|ttl| (now + ttl) as i64);
        c.execute(
            "INSERT INTO devices (device_id, account_id, label, token_hash, created_epoch, expires_epoch) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &device_id,
                &account_id,
                &label,
                &token_hash(&device_token),
                &(now as i64),
                &expires,
            ],
        )
        .map_err(db_err)?;
        Ok(Some(Account {
            account_id,
            device_token,
            device_id,
        }))
    }

    fn resolve_token(&self, token: &str, now: u64) -> Result<Option<TokenIdentity>, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let row = c
            .query_opt(
                "SELECT account_id, device_id FROM devices \
                 WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch > $2)",
                &[&token_hash(token), &(now as i64)],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| TokenIdentity {
            account_id: r.get(0),
            device_id: r.get(1),
        }))
    }

    fn rotate_token(&self, old_token: &str, now: u64) -> Result<Option<Account>, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;
        let row = tx
            .query_opt(
                "SELECT device_id, account_id FROM devices \
                 WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch > $2) FOR UPDATE",
                &[&token_hash(old_token), &(now as i64)],
            )
            .map_err(db_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let device_id: String = row.get(0);
        let account_id: String = row.get(1);
        let device_token = random_hex_id();
        tx.execute(
            "UPDATE devices SET token_hash = $1 WHERE device_id = $2",
            &[&token_hash(&device_token), &device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(Some(Account {
            account_id,
            device_token,
            device_id,
        }))
    }

    fn list_devices(&self, account_id: &str) -> Result<Vec<DeviceInfo>, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let rows = c
            .query(
                "SELECT device_id, label, created_epoch, expires_epoch FROM devices \
                 WHERE account_id = $1 ORDER BY created_epoch",
                &[&account_id],
            )
            .map_err(db_err)?;
        Ok(rows
            .iter()
            .map(|r| DeviceInfo {
                id: r.get(0),
                label: r.get(1),
                created_epoch: r.get::<_, i64>(2) as u64,
                expires_epoch: r.get::<_, Option<i64>>(3).map(|e| e as u64),
            })
            .collect())
    }

    fn revoke_device(&self, account_id: &str, device_id: &str) -> Result<bool, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let n = c
            .execute(
                "DELETE FROM devices WHERE account_id = $1 AND device_id = $2",
                &[&account_id, &device_id],
            )
            .map_err(db_err)?;
        Ok(n > 0)
    }

    fn get_plan(&self, account_id: &str) -> Result<Plan, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let plan: Option<String> = c
            .query_opt(
                "SELECT plan FROM accounts WHERE account_id = $1",
                &[&account_id],
            )
            .map_err(db_err)?
            .map(|r| r.get(0));
        Ok(plan.map(|p| Plan::parse(&p)).unwrap_or_default())
    }

    fn set_plan(&self, account_id: &str, plan: Plan) -> Result<bool, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let n = c
            .execute(
                "UPDATE accounts SET plan = $1 WHERE account_id = $2",
                &[&plan.as_str(), &account_id],
            )
            .map_err(db_err)?;
        Ok(n > 0)
    }
}

// ---- ShareGroupStore -------------------------------------------------------

/// Share groups (family sharing relay) over Postgres.
pub struct PostgresShareGroupStore {
    pool: Pool,
}

impl PostgresShareGroupStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

/// Load a full group (directory + invites + blobs) from an executor.
fn load_group(
    client: &mut impl postgres::GenericClient,
    group_id: &str,
) -> Result<Option<ShareGroup>, SyncError> {
    let head = client
        .query_opt(
            "SELECT wrapped_keys, keys_version, content, content_version \
             FROM share_groups WHERE group_id = $1",
            &[&group_id],
        )
        .map_err(db_err)?;
    let Some(head) = head else {
        return Ok(None);
    };
    let members = client
        .query(
            "SELECT member_id, account_id, name, public_key, signing_key, role, added_epoch \
             FROM group_members WHERE group_id = $1 ORDER BY added_epoch",
            &[&group_id],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| GroupMember {
            member_id: r.get(0),
            account_id: r.get(1),
            name: r.get(2),
            public_key: r.get(3),
            signing_key: r.get(4),
            role: Role::parse(&r.get::<_, String>(5)),
            added_epoch: r.get::<_, i64>(5) as u64,
        })
        .collect();
    let invites = client
        .query(
            "SELECT code_hash, created_epoch, expires_epoch, redeemed_by \
             FROM group_invites WHERE group_id = $1",
            &[&group_id],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| GroupInvite {
            code_hash: r.get(0),
            created_epoch: r.get::<_, i64>(1) as u64,
            expires_epoch: r.get::<_, i64>(2) as u64,
            redeemed_by: r.get(3),
        })
        .collect();
    let removed_accounts = client
        .query(
            "SELECT account_id FROM group_removed_accounts WHERE group_id = $1",
            &[&group_id],
        )
        .map_err(db_err)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    Ok(Some(ShareGroup {
        group_id: group_id.to_string(),
        members,
        invites,
        wrapped_keys: head.get::<_, Vec<u8>>(0),
        keys_version: head.get::<_, i64>(1) as u64,
        content: head.get::<_, Vec<u8>>(2),
        content_version: head.get::<_, i64>(3) as u64,
        removed_accounts,
    }))
}

/// Overwrite this group's membership, invites and removed-account rows to match
/// `g` exactly.
///
/// Used after applying a shared policy function (`apply_redeem` / `apply_remove`)
/// so the database is whatever the policy decided — no second, SQL-flavoured
/// implementation of the same rules that can drift from it.
///
/// This adapter previously expressed redemption and removal directly as SQL.
/// That is how the two backends diverged: the shared policy gained invariants
/// (member-id uniqueness, role preservation on re-join, invite invalidation,
/// last-Owner protection) that this adapter never applied — and this adapter is
/// the one the managed instance runs. Groups are family-sized, so replacing the
/// rows wholesale is cheap and removes a whole class of drift.
fn replace_group_rows(
    client: &mut impl postgres::GenericClient,
    g: &ShareGroup,
) -> Result<(), SyncError> {
    let gid = &g.group_id;
    client
        .execute("DELETE FROM group_members WHERE group_id = $1", &[gid])
        .map_err(db_err)?;
    for m in &g.members {
        insert_member(client, gid, m)?;
    }
    client
        .execute("DELETE FROM group_invites WHERE group_id = $1", &[gid])
        .map_err(db_err)?;
    for i in &g.invites {
        client
            .execute(
                "INSERT INTO group_invites \
                 (group_id, code_hash, created_epoch, expires_epoch, redeemed_by) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    gid,
                    &i.code_hash,
                    &(i.created_epoch as i64),
                    &(i.expires_epoch as i64),
                    &i.redeemed_by,
                ],
            )
            .map_err(db_err)?;
    }
    for account_id in &g.removed_accounts {
        client
            .execute(
                "INSERT INTO group_removed_accounts (group_id, account_id) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[gid, account_id],
            )
            .map_err(db_err)?;
    }
    Ok(())
}

fn insert_member(
    client: &mut impl postgres::GenericClient,
    group_id: &str,
    m: &GroupMember,
) -> Result<(), SyncError> {
    client
        .execute(
            "INSERT INTO group_members \
             (group_id, member_id, account_id, name, public_key, signing_key, role, added_epoch) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &group_id,
                &m.member_id,
                &m.account_id,
                &m.name,
                &m.public_key,
                &m.signing_key,
                &m.role.as_str(),
                &(m.added_epoch as i64),
            ],
        )
        .map_err(db_err)?;
    Ok(())
}

impl ShareGroupStore for PostgresShareGroupStore {
    fn create(&self, group_id: &str, owner: GroupMember) -> Result<ShareGroup, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;
        let n = tx
            .execute(
                "INSERT INTO share_groups (group_id) VALUES ($1) ON CONFLICT DO NOTHING",
                &[&group_id],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(SyncError::Conflict { server_version: 0 });
        }
        insert_member(&mut tx, group_id, &owner)?;
        tx.commit().map_err(db_err)?;
        Ok(ShareGroup {
            group_id: group_id.to_string(),
            members: vec![owner],
            ..Default::default()
        })
    }

    fn get(&self, group_id: &str) -> Result<Option<ShareGroup>, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        load_group(&mut *c, group_id)
    }

    fn add_invite(&self, group_id: &str, invite: GroupInvite) -> Result<bool, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let exists = c
            .query_opt(
                "SELECT 1 FROM share_groups WHERE group_id = $1",
                &[&group_id],
            )
            .map_err(db_err)?
            .is_some();
        if !exists {
            return Ok(false);
        }
        c.execute(
            "INSERT INTO group_invites (group_id, code_hash, created_epoch, expires_epoch, redeemed_by) \
             VALUES ($1, $2, $3, $4, NULL)",
            &[
                &group_id,
                &invite.code_hash,
                &(invite.created_epoch as i64),
                &(invite.expires_epoch as i64),
            ],
        )
        .map_err(db_err)?;
        Ok(true)
    }

    fn redeem_invite(
        &self,
        group_id: &str,
        code_hash: &str,
        new_member: GroupMember,
        now_epoch: u64,
    ) -> Result<RedeemOutcome, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;
        // Lock the group so the load-apply-persist below cannot interleave with
        // a concurrent redeem or removal.
        if tx
            .query_opt(
                "SELECT 1 FROM share_groups WHERE group_id = $1 FOR UPDATE",
                &[&group_id],
            )
            .map_err(db_err)?
            .is_none()
        {
            return Ok(RedeemOutcome::NoSuchGroup);
        }
        let Some(mut g) = load_group(&mut tx, group_id)? else {
            return Ok(RedeemOutcome::NoSuchGroup);
        };

        // Delegate the decision to the SHARED policy rather than restating it in
        // SQL. The previous SQL version accepted things the policy rejects: it
        // let a removed account rejoin with a stashed invite, ignored member-id
        // collisions (caught only incidentally by the PRIMARY KEY, as a 500),
        // and overwrote the existing row wholesale on re-join — which reset the
        // role, since the join handler hardcodes Member. That last one could
        // demote the Owner and leave the group permanently unadministrable.
        let outcome = apply_redeem(&mut g, code_hash, new_member, now_epoch);
        if outcome != RedeemOutcome::Added {
            return Ok(outcome);
        }

        replace_group_rows(&mut tx, &g)?;
        tx.commit().map_err(db_err)?;
        Ok(RedeemOutcome::Added)
    }

    /// Removal is a POLICY operation, not a `DELETE`.
    ///
    /// It previously was one bare statement, which meant this adapter silently
    /// skipped every invariant the shared policy enforces: it would remove the
    /// last Owner (leaving a group nobody can ever administer, since
    /// `can_change_roles` is Owner-only), it left outstanding invites live so
    /// the removed account could readmit itself, and it recorded nothing to stop
    /// that. Load, apply the shared `apply_remove`, persist the delta — inside
    /// one transaction so the read-modify-write cannot interleave.
    fn remove_member(&self, group_id: &str, member_id: &str) -> Result<bool, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;

        // Lock the group row so the load-apply-persist cannot interleave.
        if tx
            .query_opt(
                "SELECT 1 FROM share_groups WHERE group_id = $1 FOR UPDATE",
                &[&group_id],
            )
            .map_err(db_err)?
            .is_none()
        {
            return Ok(false);
        }
        let Some(mut g) = load_group(&mut tx, group_id)? else {
            return Ok(false);
        };

        if !apply_remove(&mut g, member_id) {
            return Ok(false);
        }

        replace_group_rows(&mut tx, &g)?;
        tx.commit().map_err(db_err)?;
        Ok(true)
    }

    fn set_member_role(
        &self,
        group_id: &str,
        member_id: &str,
        role: Role,
    ) -> Result<bool, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let n = c
            .execute(
                "UPDATE group_members SET role = $1 WHERE group_id = $2 AND member_id = $3",
                &[&role.as_str(), &group_id, &member_id],
            )
            .map_err(db_err)?;
        Ok(n > 0)
    }

    fn put_keys(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        wrapped_keys: Vec<u8>,
    ) -> Result<u64, SyncError> {
        self.put_versioned(
            group_id,
            expected_version,
            "keys_version",
            "wrapped_keys",
            wrapped_keys,
        )
    }

    fn put_content(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        self.put_versioned(
            group_id,
            expected_version,
            "content_version",
            "content",
            blob,
        )
    }

    fn delete(&self, group_id: &str) -> Result<(), SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        c.execute("DELETE FROM share_groups WHERE group_id = $1", &[&group_id])
            .map_err(db_err)?;
        Ok(())
    }
}

impl PostgresShareGroupStore {
    /// Shared optimistic-concurrency update for the two versioned group blobs.
    /// The column names are fixed internal literals (never user input).
    fn put_versioned(
        &self,
        group_id: &str,
        expected_version: Option<u64>,
        version_col: &str,
        blob_col: &str,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let mut c = self.pool.get().map_err(db_err)?;
        let mut tx = c.transaction().map_err(db_err)?;
        let current: Option<u64> = tx
            .query_opt(
                &format!("SELECT {version_col} FROM share_groups WHERE group_id = $1 FOR UPDATE"),
                &[&group_id],
            )
            .map_err(db_err)?
            .map(|r| r.get::<_, i64>(0) as u64);
        // A version of 0 means "never written" — treat as None for the concurrency rule.
        let current = current.filter(|&v| v != 0);
        let Some(_) = tx
            .query_opt(
                "SELECT 1 FROM share_groups WHERE group_id = $1",
                &[&group_id],
            )
            .map_err(db_err)?
        else {
            return Err(SyncError::NotFound);
        };
        let version = next_version(current, expected_version)?;
        tx.execute(
            &format!(
                "UPDATE share_groups SET {version_col} = $1, {blob_col} = $2 WHERE group_id = $3"
            ),
            &[&(version as i64), &blob, &group_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(version)
    }
}
