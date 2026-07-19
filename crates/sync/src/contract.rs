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

    // ---- Account deletion (GDPR Art. 17) ---------------------------------
    //
    // Deleting an account must take EVERY device with it. A surviving device row
    // is a live bearer token for an account that no longer exists.
    let doomed = store
        .register(Some("bye@example.com"), "Laptop", 20_000, None)
        .unwrap();
    let doomed2 = store
        .add_device(&doomed.device_token, "Phone", 20_000, None)
        .unwrap()
        .unwrap();
    let survivor = store.register(None, "Laptop", 20_000, None).unwrap();
    assert_eq!(store.list_devices(&doomed.account_id).unwrap().len(), 2);

    assert!(store.delete_account(&doomed.account_id).unwrap());
    // Both tokens are dead, not just the one that asked.
    assert!(store
        .resolve_token(&doomed.device_token, 20_001)
        .unwrap()
        .is_none());
    assert!(store
        .resolve_token(&doomed2.device_token, 20_001)
        .unwrap()
        .is_none());
    assert!(store.list_devices(&doomed.account_id).unwrap().is_empty());
    // The account record is gone, not merely emptied: re-planning it fails.
    assert!(!store.set_plan(&doomed.account_id, Plan::Family).unwrap());
    assert_eq!(store.get_plan(&doomed.account_id).unwrap(), Plan::Free);
    // A dead token cannot mint a new device to climb back in.
    assert!(store
        .add_device(&doomed.device_token, "Sneaky", 20_002, None)
        .unwrap()
        .is_none());
    // Idempotent, and an unknown account is simply false.
    assert!(!store.delete_account(&doomed.account_id).unwrap());
    assert!(!store.delete_account("no-such-account").unwrap());

    // BLAST RADIUS: another account is completely untouched.
    assert!(store
        .resolve_token(&survivor.device_token, 20_002)
        .unwrap()
        .is_some());
    assert_eq!(store.list_devices(&survivor.account_id).unwrap().len(), 1);
}

/// Contract for a [`ShareGroupStore`]: membership directory, single-use TTL'd
/// invites, versioned wrapped-keys + content, and revocation.
pub fn share_group_store_contract(store: &dyn ShareGroupStore, group_id: &str) {
    let owner = GroupMember {
        member_id: "m-owner".into(),
        account_id: "acct-owner".into(),
        name: "Alice".into(),
        public_key: "alice-pub".into(),
        signing_key: String::new(),
        role: Role::Owner,
        added_epoch: 100,
    };
    let bob = GroupMember {
        member_id: "m-bob".into(),
        account_id: "acct-bob".into(),
        name: "Bob".into(),
        public_key: "bob-pub".into(),
        signing_key: String::new(),
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
                    signing_key: String::new(),
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
                    signing_key: String::new(),
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
                    signing_key: String::new(),
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
                    signing_key: String::new(),
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

    account_erasure_contract(store, group_id);
}

/// Contract for [`ShareGroupStore::erase_account`] — the group half of account
/// deletion. Split out only for length; it is part of the group contract and is
/// called at the end of [`share_group_store_contract`].
///
/// The through-line of every case: erasing one account must leave NOTHING of that
/// account behind, and must leave the group usable for everyone else.
fn account_erasure_contract(store: &dyn ShareGroupStore, group_id: &str) {
    let member = |mid: &str, acct: &str, role: Role, epoch: u64| GroupMember {
        member_id: mid.into(),
        account_id: acct.into(),
        name: mid.into(),
        public_key: format!("{mid}-pub"),
        signing_key: String::new(),
        role,
        added_epoch: epoch,
    };
    let open_invite = |h: &str| GroupInvite {
        code_hash: h.into(),
        created_epoch: 100,
        expires_epoch: u64::MAX,
        redeemed_by: None,
    };
    /// Add `m` to `g` via a fresh invite (the only path membership has).
    fn join(store: &dyn ShareGroupStore, gid: &str, code: &str, m: GroupMember) {
        assert!(store
            .add_invite(
                gid,
                GroupInvite {
                    code_hash: code.into(),
                    created_epoch: 100,
                    expires_epoch: u64::MAX,
                    redeemed_by: None,
                },
            )
            .unwrap());
        assert_eq!(
            store.redeem_invite(gid, code, m, 200).unwrap(),
            RedeemOutcome::Added
        );
    }

    // ---- Case 1: a plain Member erases themselves ------------------------
    // The group survives with its Owner intact.
    let g1 = format!("{group_id}-erase-member");
    store
        .create(&g1, member("m-o1", "acct-o1", Role::Owner, 100))
        .unwrap();
    join(
        store,
        &g1,
        "c1",
        member("m-b1", "acct-b1", Role::Member, 200),
    );
    assert_eq!(store.erase_account("acct-b1").unwrap(), 1);
    let g = store.get(&g1).unwrap().unwrap();
    assert!(
        !g.is_member("acct-b1"),
        "erased account must not remain a member"
    );
    assert!(
        g.is_owner("acct-o1"),
        "erasing a member must not disturb the owner"
    );
    assert_eq!(g.members.len(), 1);
    // No tombstone: `remove_member` records one, erasure must NOT — it would be a
    // retained identifier of an account that no longer exists.
    assert!(
        !g.removed_accounts.iter().any(|a| a == "acct-b1"),
        "erasure must leave no removed-account record"
    );
    // Idempotent, and an account in no group is a no-op.
    assert_eq!(store.erase_account("acct-b1").unwrap(), 0);
    assert_eq!(store.erase_account("nobody-at-all").unwrap(), 0);

    // ---- Case 2: the last OWNER erases themselves ------------------------
    // `remove_member` refuses this (it would leave the group unadministrable
    // forever). Erasure cannot refuse, so it promotes a successor instead.
    let g2 = format!("{group_id}-erase-owner");
    store
        .create(&g2, member("m-o2", "acct-o2", Role::Owner, 100))
        .unwrap();
    join(
        store,
        &g2,
        "c2a",
        member("m-b2", "acct-b2", Role::Member, 300),
    );
    join(
        store,
        &g2,
        "c2b",
        member("m-c2", "acct-c2", Role::Member, 200),
    );
    // Sanity: ordinary removal of the last owner is still refused.
    assert!(!store.remove_member(&g2, "m-o2").unwrap());

    assert_eq!(store.erase_account("acct-o2").unwrap(), 1);
    let g = store.get(&g2).unwrap().unwrap();
    assert!(!g.is_member("acct-o2"));
    assert_eq!(g.members.len(), 2);
    // The longest-standing remaining member (added_epoch 200) becomes Owner, so
    // roles can still be changed and members still managed.
    assert!(
        g.is_owner("acct-c2"),
        "erasing the last owner must promote a successor, not orphan the group"
    );
    assert!(g.can_change_roles("acct-c2"));
    assert_eq!(g.role_of("acct-b2"), Some(Role::Member));

    // ---- Case 3: the SOLE member erases themselves -----------------------
    // Nothing is left to preserve, so the group goes too — a memberless group is
    // exactly the orphaned row account deletion exists to remove.
    let g3 = format!("{group_id}-erase-sole");
    store
        .create(&g3, member("m-o3", "acct-o3", Role::Owner, 100))
        .unwrap();
    assert!(store.add_invite(&g3, open_invite("c3")).unwrap());
    assert_eq!(store.erase_account("acct-o3").unwrap(), 1);
    assert!(
        store.get(&g3).unwrap().is_none(),
        "a group whose last member erased their account must be deleted"
    );
    // Its invites went with it — the code cannot resurrect anything.
    assert_eq!(
        store
            .redeem_invite(&g3, "c3", member("m-x", "acct-x", Role::Member, 400), 200)
            .unwrap(),
        RedeemOutcome::NoSuchGroup
    );

    // ---- Case 4: a previously REMOVED account erases itself --------------
    // The removed-account tombstone carries the account id, so erasure has to
    // scrub it even though the account is no longer a member.
    let g4 = format!("{group_id}-erase-tombstone");
    store
        .create(&g4, member("m-o4", "acct-o4", Role::Owner, 100))
        .unwrap();
    join(
        store,
        &g4,
        "c4",
        member("m-b4", "acct-b4", Role::Member, 200),
    );
    assert!(store.remove_member(&g4, "m-b4").unwrap());
    assert!(
        store
            .get(&g4)
            .unwrap()
            .unwrap()
            .removed_accounts
            .iter()
            .any(|a| a == "acct-b4"),
        "removal is expected to leave a tombstone"
    );
    assert_eq!(store.erase_account("acct-b4").unwrap(), 1);
    let g = store.get(&g4).unwrap().unwrap();
    assert!(
        g.removed_accounts.is_empty(),
        "erasure must scrub the removed-account tombstone"
    );
    assert!(g.is_owner("acct-o4"), "the surviving owner is untouched");

    // ---- Case 5: pending invites are cancelled ---------------------------
    // Same reasoning as `apply_remove`: an invite names no recipient, so there is
    // no way to tell which pending code the departing member was holding.
    let g5 = format!("{group_id}-erase-invites");
    store
        .create(&g5, member("m-o5", "acct-o5", Role::Owner, 100))
        .unwrap();
    join(
        store,
        &g5,
        "c5",
        member("m-b5", "acct-b5", Role::Member, 200),
    );
    assert!(store.add_invite(&g5, open_invite("c5-pending")).unwrap());
    assert_eq!(store.erase_account("acct-b5").unwrap(), 1);
    assert_eq!(
        store
            .redeem_invite(
                &g5,
                "c5-pending",
                member("m-d5", "acct-d5", Role::Member, 500),
                200
            )
            .unwrap(),
        RedeemOutcome::InvalidOrUsed,
        "erasure must invalidate pending invites"
    );

    store.delete(&g1).unwrap();
    store.delete(&g2).unwrap();
    store.delete(&g4).unwrap();
    store.delete(&g5).unwrap();
}
