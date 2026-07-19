-- Keyward sync-server PostgreSQL schema.
--
-- Extracted from a `const SCHEMA: &str` in src/lib.rs on 2026-07-19. It is
-- still applied the same way, by `migrate()` via include_str! below, so this
-- change is textual only — no runtime behaviour differs.
--
-- WHY IT LIVES IN A .sql FILE NOW: query-checking tools (Cornucopia, sqlx)
-- prepare queries against a real schema, and they need one they can read. A
-- schema embedded in a Rust string literal cannot be handed to them. This is
-- the prerequisite for eliminating hand-written positional row access — the
-- construct that produced `r.get::<_, i64>(5)` reading a TEXT column as i64
-- and panicking on every group load (fixed in eb367b7).
--
-- NOTE ON MIGRATIONS: this is idempotent DDL, not a versioned migration set.
-- Every statement is CREATE ... IF NOT EXISTS / ALTER ... IF NOT EXISTS, so it
-- is safe to re-apply, but there is no version tracking, no ordering guarantee
-- beyond source order, and no down path. That ceiling is fine at one instance
-- and gets dangerous at several; a real runner (refinery) is the next step and
-- was deliberately NOT bundled with this extraction, so that a change to how
-- production applies its schema is its own reviewable decision.

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
