//! Reusable port-contract suites. Any adapter of [`SyncStore`], [`AccountStore`],
//! or [`ShareGroupStore`] must satisfy these — the file/memory adapters run them in
//! their own tests, and out-of-tree adapters (e.g. the Postgres cloud backend) run
//! the exact same suites so every backend is behaviourally identical.
//!
//! Enabled by the `testkit` feature so the assertions don't ship in normal builds.

use crate::groups::{GroupInvite, GroupMember, RedeemOutcome, Role, ShareGroupStore};
use crate::{AccountStore, Plan, SyncError, SyncStore};

/// Contract for a [`SyncStore`]: versioned blob get/put/delete with optimistic
/// concurrency. `key_prefix` lets a shared backend avoid key collisions between
/// concurrent contract runs.
pub fn sync_store_contract(store: &dyn SyncStore, key_prefix: &str) {
    let a = format!("{key_prefix}-alice");
    let b = format!("{key_prefix}-bob");

    assert!(store.get(&a).unwrap().is_none());

    let v1 = store.put(&a, None, b"ct-1".to_vec()).unwrap();
    assert_eq!(v1, 1);
    let got = store.get(&a).unwrap().unwrap();
    assert_eq!(got.version, 1);
    assert_eq!(got.blob, b"ct-1");

    let v2 = store.put(&a, Some(1), b"ct-2".to_vec()).unwrap();
    assert_eq!(v2, 2);

    let err = store.put(&a, Some(1), b"stale".to_vec()).unwrap_err();
    assert!(matches!(err, SyncError::Conflict { server_version: 2 }));
    assert_eq!(store.get(&a).unwrap().unwrap().blob, b"ct-2");

    assert_eq!(store.put(&b, None, b"bob-1".to_vec()).unwrap(), 1);

    store.delete(&a).unwrap();
    assert!(store.get(&a).unwrap().is_none());
    store.delete(&a).unwrap(); // idempotent
    assert_eq!(store.put(&a, None, b"fresh".to_vec()).unwrap(), 1);
    assert_eq!(store.get(&b).unwrap().unwrap().blob, b"bob-1");

    // A first push with a stale expectation conflicts at server=0.
    let c = format!("{key_prefix}-carol");
    let err = store.put(&c, Some(5), b"x".to_vec()).unwrap_err();
    assert!(matches!(err, SyncError::Conflict { server_version: 0 }));
}

/// Contract for an [`AccountStore`]: register, add/rotate/resolve/list/revoke, and
/// token expiry.
pub fn account_store_contract(store: &dyn AccountStore) {
    // Register → a device token that resolves to the account.
    let acct = store
        .register(Some("a@example.com"), "Laptop", 1_000, None)
        .unwrap();
    assert!(!acct.account_id.is_empty() && !acct.device_token.is_empty());
    let id = store
        .resolve_token(&acct.device_token, 1_001)
        .unwrap()
        .unwrap();
    assert_eq!(id.account_id, acct.account_id);
    assert_eq!(id.device_id, acct.device_id);

    // An unknown token resolves to nothing.
    assert!(store.resolve_token("nope", 1_001).unwrap().is_none());

    // Add a second device for the same account.
    let dev2 = store
        .add_device(&acct.device_token, "Phone", 2_000, None)
        .unwrap()
        .unwrap();
    assert_eq!(dev2.account_id, acct.account_id);
    assert_ne!(dev2.device_id, acct.device_id);
    assert!(store
        .resolve_token(&dev2.device_token, 2_001)
        .unwrap()
        .is_some());
    // add_device with an unknown token fails.
    assert!(store
        .add_device("nope", "X", 2_000, None)
        .unwrap()
        .is_none());

    // Two devices listed.
    let devices = store.list_devices(&acct.account_id).unwrap();
    assert_eq!(devices.len(), 2);

    // Rotate device 1: old token stops resolving, new one works, id unchanged.
    let rotated = store
        .rotate_token(&acct.device_token, 3_000)
        .unwrap()
        .unwrap();
    assert_eq!(rotated.device_id, acct.device_id);
    assert!(store
        .resolve_token(&acct.device_token, 3_001)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .resolve_token(&rotated.device_token, 3_001)
            .unwrap()
            .unwrap()
            .device_id,
        acct.device_id
    );
    assert!(store.rotate_token("nope", 3_000).unwrap().is_none());

    // Revoke device 2: its token no longer resolves.
    assert!(store
        .revoke_device(&acct.account_id, &dev2.device_id)
        .unwrap());
    assert!(store
        .resolve_token(&dev2.device_token, 4_000)
        .unwrap()
        .is_none());
    assert!(!store
        .revoke_device(&acct.account_id, &dev2.device_id)
        .unwrap());

    // TTL: a token with a lifetime stops resolving past expiry.
    let ttl = store.register(None, "Kiosk", 10_000, Some(60)).unwrap();
    assert!(store
        .resolve_token(&ttl.device_token, 10_030)
        .unwrap()
        .is_some());
    assert!(store
        .resolve_token(&ttl.device_token, 10_061)
        .unwrap()
        .is_none());

    // Entitlements: a new account is Free; set_plan updates it; unknown → false.
    assert_eq!(store.get_plan(&acct.account_id).unwrap(), Plan::Free);
    assert!(store.set_plan(&acct.account_id, Plan::Family).unwrap());
    assert_eq!(store.get_plan(&acct.account_id).unwrap(), Plan::Family);
    assert!(!store.set_plan("no-such-account", Plan::Individual).unwrap());
    assert_eq!(store.get_plan("no-such-account").unwrap(), Plan::Free);
}

/// Contract for a [`ShareGroupStore`]: membership directory, single-use TTL'd
/// invites, versioned wrapped-keys + content, and revocation.
pub fn share_group_store_contract(store: &dyn ShareGroupStore, group_id: &str) {
    let owner = GroupMember {
        member_id: "m-owner".into(),
        account_id: "acct-owner".into(),
        name: "Alice".into(),
        public_key: "alice-pub".into(),
        role: Role::Owner,
        added_epoch: 100,
    };
    let bob = GroupMember {
        member_id: "m-bob".into(),
        account_id: "acct-bob".into(),
        name: "Bob".into(),
        public_key: "bob-pub".into(),
        role: Role::Member,
        added_epoch: 200,
    };
    let invite = |h: &str, exp: u64| GroupInvite {
        code_hash: h.into(),
        created_epoch: 100,
        expires_epoch: exp,
        redeemed_by: None,
    };

    let g = store.create(group_id, owner).unwrap();
    assert_eq!(g.members.len(), 1);
    assert!(g.is_owner("acct-owner"));
    assert!(matches!(
        store.create(group_id, g.members[0].clone()).unwrap_err(),
        SyncError::Conflict { server_version: 0 }
    ));

    assert!(store
        .add_invite(group_id, invite("hash-ok", 1_000))
        .unwrap());
    assert_eq!(
        store
            .redeem_invite(group_id, "hash-ok", bob.clone(), 500)
            .unwrap(),
        RedeemOutcome::Added
    );
    let g = store.get(group_id).unwrap().unwrap();
    assert!(g.is_member("acct-bob"));

    // Single-use + unknown + expired + no-such-group.
    assert_eq!(
        store
            .redeem_invite(group_id, "hash-ok", bob.clone(), 500)
            .unwrap(),
        RedeemOutcome::InvalidOrUsed
    );
    assert_eq!(
        store
            .redeem_invite(group_id, "nope", bob.clone(), 500)
            .unwrap(),
        RedeemOutcome::InvalidOrUsed
    );
    assert!(store.add_invite(group_id, invite("hash-old", 400)).unwrap());
    assert_eq!(
        store
            .redeem_invite(group_id, "hash-old", bob.clone(), 500)
            .unwrap(),
        RedeemOutcome::Expired
    );
    assert_eq!(
        store
            .redeem_invite("ghost-group", "x", bob.clone(), 500)
            .unwrap(),
        RedeemOutcome::NoSuchGroup
    );

    // Versioned keys + content, independent optimistic concurrency.
    assert_eq!(
        store.put_keys(group_id, None, b"wrap-1".to_vec()).unwrap(),
        1
    );
    assert_eq!(
        store
            .put_keys(group_id, Some(1), b"wrap-2".to_vec())
            .unwrap(),
        2
    );
    assert!(matches!(
        store
            .put_keys(group_id, Some(1), b"stale".to_vec())
            .unwrap_err(),
        SyncError::Conflict { server_version: 2 }
    ));
    assert_eq!(
        store
            .put_content(group_id, None, b"blob-1".to_vec())
            .unwrap(),
        1
    );
    let g = store.get(group_id).unwrap().unwrap();
    assert_eq!(g.wrapped_keys, b"wrap-2");
    assert_eq!(g.content, b"blob-1");
    assert_eq!(g.keys_version, 2);
    assert_eq!(g.content_version, 1);
    assert!(matches!(
        store
            .put_keys("ghost-group", None, b"x".to_vec())
            .unwrap_err(),
        SyncError::NotFound
    ));

    // Roles: Bob joins as Member; promoting/demoting flows through the directory.
    let g = store.get(group_id).unwrap().unwrap();
    assert_eq!(g.role_of("acct-bob"), Some(Role::Member));
    assert!(g.is_owner("acct-owner"));
    assert!(g.can_manage_members("acct-owner"));
    assert!(!g.can_manage_members("acct-bob"));
    assert!(!g.can_change_roles("acct-bob"));

    assert!(store
        .set_member_role(group_id, "m-bob", Role::Admin)
        .unwrap());
    let g = store.get(group_id).unwrap().unwrap();
    assert_eq!(g.role_of("acct-bob"), Some(Role::Admin));
    // An Admin may manage members but may NOT change roles.
    assert!(g.can_manage_members("acct-bob"));
    assert!(!g.can_change_roles("acct-bob"));
    // Unknown member → false.
    assert!(!store
        .set_member_role(group_id, "no-such-member", Role::Admin)
        .unwrap());

    // ---- Membership invariants -------------------------------------------
    //
    // Every assertion below belongs in the CONTRACT, not in one adapter's
    // tests. These invariants previously lived only in whichever backend
    // happened to enforce them: Postgres rejected duplicate member ids via
    // `PRIMARY KEY (group_id, member_id)` (as a 500), while the file and memory
    // stores — the self-host defaults — accepted them, and Postgres expressed
    // redemption and removal as bespoke SQL that skipped the shared policy
    // entirely. Running these against all three adapters is what stops that
    // divergence recurring.

    // A member_id already held by ANOTHER account is refused. member_id is the
    // key wraps are stored under, so a collision lets a joiner take over
    // another member's key slot.
    let live = store.get(group_id).unwrap().unwrap();
    let taken_id = live.members[0].member_id.clone();
    let code_collide = "collide-code";
    assert!(store
        .add_invite(
            group_id,
            GroupInvite {
                code_hash: code_collide.into(),
                created_epoch: 100,
                expires_epoch: u64::MAX,
                redeemed_by: None,
            },
        )
        .unwrap());
    assert_eq!(
        store
            .redeem_invite(
                group_id,
                code_collide,
                GroupMember {
                    member_id: taken_id.clone(),
                    account_id: "acct-mallory".into(),
                    name: "Mallory".into(),
                    public_key: "mallory-pub".into(),
                    role: Role::Member,
                    added_epoch: 300,
                },
                200,
            )
            .unwrap(),
        RedeemOutcome::MemberIdTaken
    );

    // Re-joining preserves the existing ROLE. The join handler hardcodes
    // Member, so a wholesale row overwrite let an invite demote an Owner — and
    // since only an Owner may change roles, that left the group permanently
    // unadministrable with no recovery path.
    let owner_member_id = live
        .members
        .iter()
        .find(|m| m.role == Role::Owner)
        .map(|m| m.member_id.clone())
        .expect("group must have an owner");
    let code_rejoin = "rejoin-code";
    assert!(store
        .add_invite(
            group_id,
            GroupInvite {
                code_hash: code_rejoin.into(),
                created_epoch: 100,
                expires_epoch: u64::MAX,
                redeemed_by: None,
            },
        )
        .unwrap());
    assert_eq!(
        store
            .redeem_invite(
                group_id,
                code_rejoin,
                GroupMember {
                    member_id: owner_member_id.clone(),
                    account_id: "acct-owner".into(),
                    name: "Alice (new phone)".into(),
                    public_key: "alice-pub-2".into(),
                    role: Role::Member, // what the join handler always sends
                    added_epoch: 400,
                },
                200,
            )
            .unwrap(),
        RedeemOutcome::Added
    );
    let g = store.get(group_id).unwrap().unwrap();
    assert_eq!(
        g.role_of("acct-owner"),
        Some(Role::Owner),
        "re-join must not demote the owner"
    );
    // The rest of the row does update — this is a real re-join.
    assert_eq!(
        g.member_by_account("acct-owner").unwrap().public_key,
        "alice-pub-2"
    );

    // The last Owner cannot be removed: with none, `can_change_roles` (Owner
    // only) can never be satisfied again, so no role could ever be granted.
    assert!(
        !store.remove_member(group_id, &owner_member_id).unwrap(),
        "removing the last owner must be refused"
    );

    // Removing a member invalidates PENDING invites and bars that account from
    // rejoining. Previously removal touched only the member row, so any
    // outstanding code was a standing readmission ticket.
    let code_stashed = "stashed-code";
    assert!(store
        .add_invite(
            group_id,
            GroupInvite {
                code_hash: code_stashed.into(),
                created_epoch: 100,
                expires_epoch: u64::MAX,
                redeemed_by: None,
            },
        )
        .unwrap());
    assert!(store.remove_member(group_id, "m-bob").unwrap());
    assert!(!store.get(group_id).unwrap().unwrap().is_member("acct-bob"));

    // The stashed code is dead — proven with an UNRELATED account, so this
    // tests invite invalidation on its own rather than being masked by the
    // removed-account bar (which is checked first, and would answer
    // AccountRemoved for Bob whatever the code).
    assert_eq!(
        store
            .redeem_invite(
                group_id,
                code_stashed,
                GroupMember {
                    member_id: "m-carol".into(),
                    account_id: "acct-carol".into(),
                    name: "Carol".into(),
                    public_key: "carol-pub".into(),
                    role: Role::Member,
                    added_epoch: 500,
                },
                200,
            )
            .unwrap(),
        RedeemOutcome::InvalidOrUsed,
        "removal must invalidate every pending invite, not just the removed member's"
    );
    // ...and even a FRESH invite will not readmit a removed account.
    let code_fresh = "fresh-code";
    assert!(store
        .add_invite(
            group_id,
            GroupInvite {
                code_hash: code_fresh.into(),
                created_epoch: 100,
                expires_epoch: u64::MAX,
                redeemed_by: None,
            },
        )
        .unwrap());
    assert_eq!(
        store
            .redeem_invite(
                group_id,
                code_fresh,
                GroupMember {
                    member_id: "m-bob-3".into(),
                    account_id: "acct-bob".into(),
                    name: "Bob".into(),
                    public_key: "bob-pub".into(),
                    role: Role::Member,
                    added_epoch: 600,
                },
                200,
            )
            .unwrap(),
        RedeemOutcome::AccountRemoved
    );

    // Removal stays idempotent.
    assert!(!store.remove_member(group_id, "m-bob").unwrap());
    store.delete(group_id).unwrap();
    assert!(store.get(group_id).unwrap().is_none());
    store.delete(group_id).unwrap();
}
