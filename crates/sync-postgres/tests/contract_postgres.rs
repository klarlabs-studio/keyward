//! Runs the shared port contracts against a REAL PostgreSQL, proving the cloud
//! backend is behaviourally identical to the file/memory adapters.
//!
//! Gated on the `PROCTOR_TEST_PG` env var (a libpq URL); skipped otherwise, so the
//! normal `cargo test` never needs a database. Each test uses a unique key/group
//! suffix so runs don't collide and can execute in parallel.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use proctor_sync::contract::{
    account_store_contract, share_group_store_contract, sync_store_contract,
};
use proctor_sync_postgres::{
    connect, PostgresAccountStore, PostgresShareGroupStore, PostgresSyncStore,
};

type Pool = r2d2::Pool<r2d2_postgres::PostgresConnectionManager<postgres::NoTls>>;

/// One shared, migrated pool for all tests — so migration (concurrent DDL would
/// otherwise race) runs exactly once, and connections are reused.
fn pool_or_skip() -> Option<Pool> {
    static POOL: OnceLock<Option<Pool>> = OnceLock::new();
    POOL.get_or_init(|| match std::env::var("PROCTOR_TEST_PG") {
        Ok(url) if !url.is_empty() => Some(connect(&url, 6).expect("connect + migrate")),
        _ => {
            eprintln!("skipping: set PROCTOR_TEST_PG to a libpq URL to run the Postgres contract");
            None
        }
    })
    .clone()
}

fn unique() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos:x}{:x}", rand::random::<u32>())
}

#[test]
fn postgres_sync_store_contract() {
    let Some(pool) = pool_or_skip() else { return };
    sync_store_contract(&PostgresSyncStore::new(pool), &format!("pg-{}", unique()));
}

#[test]
fn postgres_account_store_contract() {
    let Some(pool) = pool_or_skip() else { return };
    account_store_contract(&PostgresAccountStore::new(pool));
}

#[test]
fn postgres_share_group_store_contract() {
    let Some(pool) = pool_or_skip() else { return };
    share_group_store_contract(
        &PostgresShareGroupStore::new(pool),
        &format!("g-{}", unique()),
    );
}
