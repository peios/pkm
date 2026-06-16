use kacs_core::{
    apply_take_ownership_fallback, seed_access_check_privileges, AccessDecisionState,
    GenericMapping, TokenPrivileges, ACCESS_SYSTEM_SECURITY, BACKUP_INTENT, DELETE, GENERIC_READ,
    MAXIMUM_ALLOWED, READ_CONTROL, RESTORE_INTENT, SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE,
    SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE, WRITE_DAC,
    WRITE_OWNER,
};

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC,
        execute: 0,
        all: READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE,
    }
}

fn privileges(enabled: u64) -> TokenPrivileges {
    TokenPrivileges {
        present: enabled,
        enabled,
        enabled_by_default: 0,
        used: 0,
    }
}

#[test]
fn backup_and_restore_are_intent_gated() {
    let state = seed_access_check_privileges(
        &privileges(SE_BACKUP_PRIVILEGE | SE_RESTORE_PRIVILEGE),
        &mapping(),
        0,
    )
    .expect("privilege seeding should succeed");

    assert_eq!(state.effective_privileges, 0);
    assert_eq!(state.decided, ACCESS_SYSTEM_SECURITY);
    assert_eq!(state.granted, 0);
    assert_eq!(state.privilege_granted(), 0);
}

#[test]
fn privilege_constants_match_the_ratified_bit_positions() {
    assert_eq!(SE_SECURITY_PRIVILEGE, 0x0000_0000_0000_0100);
    assert_eq!(SE_TAKE_OWNERSHIP_PRIVILEGE, 0x0000_0000_0000_0200);
    assert_eq!(SE_BACKUP_PRIVILEGE, 0x0000_0000_0002_0000);
    assert_eq!(SE_RESTORE_PRIVILEGE, 0x0000_0000_0004_0000);
    assert_eq!(SE_RELABEL_PRIVILEGE, 0x0000_0001_0000_0000);
}

#[test]
fn access_system_security_is_always_decided_by_privilege_step() {
    let disabled = seed_access_check_privileges(&TokenPrivileges::default(), &mapping(), 0)
        .expect("privilege seeding should succeed");
    assert_eq!(disabled.decided, ACCESS_SYSTEM_SECURITY);
    assert_eq!(disabled.granted, 0);

    let enabled = seed_access_check_privileges(&privileges(SE_SECURITY_PRIVILEGE), &mapping(), 0)
        .expect("privilege seeding should succeed");

    assert_eq!(enabled.decided, ACCESS_SYSTEM_SECURITY);
    assert_eq!(enabled.granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(enabled.provenance.security_granted, ACCESS_SYSTEM_SECURITY);
}

#[test]
fn backup_grants_generic_read_bits_only_with_backup_intent() {
    let state =
        seed_access_check_privileges(&privileges(SE_BACKUP_PRIVILEGE), &mapping(), BACKUP_INTENT)
            .expect("privilege seeding should succeed");

    assert_eq!(state.effective_privileges, SE_BACKUP_PRIVILEGE);
    assert_eq!(state.decided, ACCESS_SYSTEM_SECURITY | READ_CONTROL);
    assert_eq!(state.granted, READ_CONTROL);
    assert_eq!(state.provenance.backup_granted, READ_CONTROL);
}

#[test]
fn restore_grants_write_and_metadata_bits_with_restore_intent() {
    let state = seed_access_check_privileges(
        &privileges(SE_RESTORE_PRIVILEGE),
        &mapping(),
        RESTORE_INTENT,
    )
    .expect("privilege seeding should succeed");

    let expected = WRITE_DAC | WRITE_OWNER | DELETE | ACCESS_SYSTEM_SECURITY;
    assert_eq!(state.effective_privileges, SE_RESTORE_PRIVILEGE);
    assert_eq!(state.decided, ACCESS_SYSTEM_SECURITY | expected);
    assert_eq!(state.granted, expected);
    assert_eq!(state.provenance.restore_granted, expected);
}

#[test]
fn enabled_bit_without_present_bit_is_ignored() {
    let state = seed_access_check_privileges(
        &TokenPrivileges {
            present: 0,
            enabled: SE_SECURITY_PRIVILEGE | SE_BACKUP_PRIVILEGE,
            enabled_by_default: 0,
            used: 0,
        },
        &mapping(),
        BACKUP_INTENT,
    )
    .expect("privilege seeding should succeed");

    assert_eq!(state.effective_privileges, 0);
    assert_eq!(state.granted, 0);
}

#[test]
fn overlapping_privilege_provenance_is_tracked_independently() {
    let state = seed_access_check_privileges(
        &privileges(SE_SECURITY_PRIVILEGE | SE_RESTORE_PRIVILEGE),
        &mapping(),
        RESTORE_INTENT,
    )
    .expect("privilege seeding should succeed");

    assert_eq!(state.provenance.security_granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(
        state.provenance.restore_granted & ACCESS_SYSTEM_SECURITY,
        ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(
        state.privilege_granted() & ACCESS_SYSTEM_SECURITY,
        ACCESS_SYSTEM_SECURITY
    );
}

#[test]
fn take_ownership_fallback_requires_privilege_and_request() {
    let normalized = mapping()
        .normalize_desired_access(WRITE_OWNER)
        .expect("desired access should normalize");
    let mut scalar = AccessDecisionState {
        decided: 0,
        granted: 0,
    };
    let mut provenance = Default::default();

    apply_take_ownership_fallback(&mut scalar, None, &normalized, 0, 0, &mut provenance);

    assert_eq!(scalar.granted, 0);
    assert_eq!(provenance.take_ownership_granted, 0);
}

#[test]
fn take_ownership_fallback_applies_for_maximum_allowed() {
    let normalized = mapping()
        .normalize_desired_access(MAXIMUM_ALLOWED | GENERIC_READ)
        .expect("desired access should normalize");
    let mut scalar = AccessDecisionState {
        decided: 0,
        granted: 0,
    };
    let mut provenance = Default::default();

    apply_take_ownership_fallback(
        &mut scalar,
        None,
        &normalized,
        SE_TAKE_OWNERSHIP_PRIVILEGE,
        0,
        &mut provenance,
    );

    assert_eq!(scalar.granted, WRITE_OWNER);
    assert_eq!(provenance.take_ownership_granted, WRITE_OWNER);
}

#[test]
fn take_ownership_fallback_respects_mandatory_decisions() {
    let normalized = mapping()
        .normalize_desired_access(WRITE_OWNER)
        .expect("desired access should normalize");
    let mut scalar = AccessDecisionState {
        decided: 0,
        granted: 0,
    };
    let mut provenance = Default::default();

    apply_take_ownership_fallback(
        &mut scalar,
        None,
        &normalized,
        SE_TAKE_OWNERSHIP_PRIVILEGE,
        WRITE_OWNER,
        &mut provenance,
    );

    assert_eq!(scalar.granted, 0);
    assert_eq!(provenance.take_ownership_granted, 0);
}

#[test]
fn take_ownership_fallback_updates_object_tree_nodes_missing_write_owner() {
    let normalized = mapping()
        .normalize_desired_access(WRITE_OWNER)
        .expect("desired access should normalize");
    let mut scalar = AccessDecisionState {
        decided: 0,
        granted: 0,
    };
    let mut object_states = [
        AccessDecisionState {
            decided: 0,
            granted: 0,
        },
        AccessDecisionState {
            decided: WRITE_OWNER,
            granted: WRITE_OWNER,
        },
        AccessDecisionState {
            decided: READ_CONTROL,
            granted: READ_CONTROL,
        },
    ];
    let mut provenance = Default::default();

    apply_take_ownership_fallback(
        &mut scalar,
        Some(&mut object_states),
        &normalized,
        SE_TAKE_OWNERSHIP_PRIVILEGE,
        0,
        &mut provenance,
    );

    assert_eq!(scalar.granted, WRITE_OWNER);
    assert_eq!(object_states[0].granted, WRITE_OWNER);
    assert_eq!(object_states[1].granted, WRITE_OWNER);
    assert_eq!(object_states[2].granted, READ_CONTROL | WRITE_OWNER);
}

#[test]
fn take_ownership_fallback_does_not_reseed_tree_when_root_already_has_write_owner() {
    let normalized = mapping()
        .normalize_desired_access(WRITE_OWNER)
        .expect("desired access should normalize");
    let mut scalar = AccessDecisionState {
        decided: WRITE_OWNER,
        granted: WRITE_OWNER,
    };
    let mut object_states = [
        AccessDecisionState {
            decided: 0,
            granted: 0,
        },
        AccessDecisionState {
            decided: 0,
            granted: 0,
        },
    ];
    let mut provenance = Default::default();

    apply_take_ownership_fallback(
        &mut scalar,
        Some(&mut object_states),
        &normalized,
        SE_TAKE_OWNERSHIP_PRIVILEGE,
        0,
        &mut provenance,
    );

    assert_eq!(provenance.take_ownership_granted, 0);
    assert_eq!(object_states[0].granted, 0);
    assert_eq!(object_states[1].granted, 0);
}
