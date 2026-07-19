-- AccountStore queries — accounts and per-device bearer tokens.
--
-- WHY THESE ARE NOT HAND-WRITTEN `client.query(...)` CALLS ANYMORE: the previous
-- form paired a SQL string literal with POSITIONAL row access (`r.get::<_, i64>(5)`)
-- at the call site. Nothing tied the two together. Reorder a SELECT list, add a
-- column, and every index after it silently means a different column — and
-- because `postgres`'s FromSql is checked at RUNTIME, a type mismatch is not a
-- wrong value, it is a PANIC on the request path. That is exactly how
-- `load_group` came to read `added_epoch` from index 5, which is `role`, a TEXT
-- column, and take down family sharing on the only backend the managed instance
-- runs. Review does not reliably catch an off-by-one in an integer literal.
--
-- Cornucopia generates a typed struct with NAMED fields per query, and it does so
-- by PREPARING each statement against crates/sync-postgres/schema.sql. A column
-- that does not exist, a type that does not match, a parameter count that does not
-- line up — none of them reach a running server, they fail codegen with exit 1.
-- The index is gone as a concept; there is nothing left to miscount.
--
-- Parameter names here are `:name`; the `(name?)` annotation after a query name
-- marks NULLABLE parameters, and `: (col?)` marks nullable RESULT columns.
-- Getting those wrong is also a codegen error rather than a runtime surprise.

-- Registration inserts the account head row. `plan` is hardcoded 'free' rather
-- than parameterised: entitlement is granted by the billing plane, never by the
-- caller of register.
--! insert_account (email?)
INSERT INTO accounts (account_id, email, plan, created_epoch)
VALUES (:account_id, :email, 'free', :created_epoch);

-- Devices store only the SHA-256 HASH of the bearer token; the plaintext is
-- returned to the caller once and never persisted. `expires_epoch` is NULL for
-- non-expiring devices, which is why it carries the nullable annotation.
--! insert_device (expires_epoch?)
INSERT INTO devices (device_id, account_id, label, token_hash, created_epoch, expires_epoch)
VALUES (:device_id, :account_id, :label, :token_hash, :created_epoch, :expires_epoch);

-- Token lookup for add_device: resolves a presented token to its account.
-- The expiry predicate is part of the QUERY, not the caller — an expired token
-- must not authorise enrolling a new device, and leaving that check to Rust is
-- how it goes missing at one of the several call sites.
--! account_for_token
SELECT account_id FROM devices
WHERE token_hash = :token_hash
  AND (expires_epoch IS NULL OR expires_epoch > :now_epoch);

-- Full identity resolution for request authentication. Returns both ids as named
-- fields, replacing `r.get(0)` / `r.get(1)` — two positional reads whose meaning
-- depended entirely on the order of the SELECT list directly above them.
--! resolve_token
SELECT device_id, account_id FROM devices
WHERE token_hash = :token_hash
  AND (expires_epoch IS NULL OR expires_epoch > :now_epoch);

-- Same lookup as resolve_token, but takes the row lock for the rotate
-- read-modify-write so a concurrent rotation cannot issue two live tokens for
-- one device.
--! resolve_token_for_update
SELECT device_id, account_id FROM devices
WHERE token_hash = :token_hash
  AND (expires_epoch IS NULL OR expires_epoch > :now_epoch)
FOR UPDATE;

--! update_device_token
UPDATE devices SET token_hash = :token_hash WHERE device_id = :device_id;

-- Device listing for the account-management UI. Deliberately does NOT select
-- token_hash: nothing outside authentication has a reason to read it, and a
-- SELECT * here would have leaked it into a struct that gets serialised.
--! list_devices : (expires_epoch?)
SELECT device_id, label, created_epoch, expires_epoch FROM devices
WHERE account_id = :account_id
ORDER BY created_epoch;

-- Revocation is scoped by account_id as well as device_id so a caller cannot
-- revoke another account's device by guessing an id. The predicate is the
-- authorisation check; it must stay in the query.
--! revoke_device
DELETE FROM devices WHERE account_id = :account_id AND device_id = :device_id;

--! get_plan
SELECT plan FROM accounts WHERE account_id = :account_id;

--! set_plan
UPDATE accounts SET plan = :plan WHERE account_id = :account_id;

-- Account erasure. The schema is deliberately FK-light, so there is no
-- ON DELETE CASCADE to lean on — the cascade is these two statements, run in one
-- transaction, devices first. See delete_account in lib.rs for why the order and
-- the transaction both matter (a window with the account gone but its tokens
-- still resolving is a live bearer credential for a deleted account).
--! delete_devices_for_account
DELETE FROM devices WHERE account_id = :account_id;

--! delete_account
DELETE FROM accounts WHERE account_id = :account_id;
