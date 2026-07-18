//! Proves the reusable port contracts against the in-memory adapters (the
//! known-good reference), so the Postgres backend can trust the same suites.
//! Run with: `cargo test -p proctor-sync --features testkit`.
#![cfg(feature = "testkit")]

use proctor_sync::contract::{
    account_store_contract, share_group_store_contract, sync_store_contract,
};
use proctor_sync::{MemoryAccountStore, MemoryShareGroupStore, MemoryStore};

#[test]
fn memory_adapters_satisfy_the_contracts() {
    sync_store_contract(&MemoryStore::new(), "mem");
    account_store_contract(&MemoryAccountStore::new());
    share_group_store_contract(&MemoryShareGroupStore::new(), "mem-group");
}
