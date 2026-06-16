mod common;
use common::{acl_bytes, basic_ace, mapping, sid_bytes};
use kacs_core::{
    apply_pip, resolve_process_trust_label, KacsError, PipContext,
    PipEnforcementState, ProcessTrustLabel, SecurityDescriptor, ACCESS_SYSTEM_SECURITY,
    GENERIC_WRITE, READ_CONTROL, SE_SACL_PRESENT, SE_SELF_RELATIVE, WRITE_DAC, WRITE_OWNER,
};

const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;
const INHERIT_ONLY_ACE: u8 = 0x08;




fn sd_with_sacl(owner: &[u8], sacl: Option<&[u8]>) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | if sacl.is_some() { SE_SACL_PRESENT } else { 0 };
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    let group_offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    if let Some(sacl) = sacl {
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl);
    }
    bytes
}


#[test]
fn missing_trust_label_is_a_noop() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sd_bytes = sd_with_sacl(&owner, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd).expect("trust label resolution should succeed");

    assert_eq!(label, None);
}

#[test]
fn first_trust_label_is_used() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let lower = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 1024]);
    let higher = sid_bytes([0, 0, 0, 0, 0, 19], &[1024, 8192]);
    let sacl = acl_bytes(&[
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, READ_CONTROL, &lower),
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, WRITE_DAC, &higher),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd)
        .expect("trust label resolution should succeed")
        .expect("first trust label should exist");

    assert_eq!(
        label,
        ProcessTrustLabel {
            pip_type: 512,
            pip_trust: 1024,
            mask: READ_CONTROL,
        }
    );
}

#[test]
fn inherit_only_trust_label_is_ignored() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let inherited = sid_bytes([0, 0, 0, 0, 0, 19], &[1024, 8192]);
    let effective = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 1024]);
    let sacl = acl_bytes(&[
        basic_ace(
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            INHERIT_ONLY_ACE,
            WRITE_DAC,
            &inherited,
        ),
        basic_ace(
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            0,
            READ_CONTROL,
            &effective,
        ),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd)
        .expect("trust label resolution should succeed")
        .expect("trust label should exist");

    assert_eq!(label.pip_type, 512);
    assert_eq!(label.pip_trust, 1024);
    assert_eq!(label.mask, READ_CONTROL);
}

#[test]
fn malformed_trust_label_shape_is_rejected() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let invalid = sid_bytes([0, 0, 0, 0, 0, 19], &[512]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL,
        &invalid,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let err = resolve_process_trust_label(&sd).expect_err("malformed trust label sid must fail");
    assert_eq!(err, KacsError::InvalidProcessTrustLabelSid);
}

#[test]
fn malformed_trust_label_sid_matrix_is_rejected() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let cases = [
        sid_bytes([0, 0, 0, 0, 0, 5], &[512, 4096]),
        sid_bytes([0, 0, 0, 0, 0, 19], &[512]),
        sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096, 8192]),
    ];

    for invalid in cases {
        let sacl = acl_bytes(&[basic_ace(
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            0,
            READ_CONTROL,
            &invalid,
        )]);
        let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
        let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

        let err =
            resolve_process_trust_label(&sd).expect_err("malformed trust label sid must fail");
        assert_eq!(err, KacsError::InvalidProcessTrustLabelSid);
    }
}

#[test]
fn first_applicable_valid_trust_label_ignores_later_malformed_labels() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let valid = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let malformed = sid_bytes([0, 0, 0, 0, 0, 19], &[1024]);
    let sacl = acl_bytes(&[
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, READ_CONTROL, &valid),
        basic_ace(
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            0,
            WRITE_DAC,
            &malformed,
        ),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd)
        .expect("later malformed labels must not be inspected")
        .expect("first label should exist");

    assert_eq!(
        label,
        ProcessTrustLabel {
            pip_type: 512,
            pip_trust: 4096,
            mask: READ_CONTROL,
        }
    );
}

#[test]
fn dominant_callers_receive_no_pip_predecisions() {
    let label = ProcessTrustLabel {
        pip_type: 512,
        pip_trust: 1024,
        mask: READ_CONTROL,
    };
    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC;
    let mut privilege_granted = ACCESS_SYSTEM_SECURITY;

    let pip = apply_pip(
        label,
        PipContext {
            pip_type: 1024,
            pip_trust: 8192,
        },
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(decided, 0);
    assert_eq!(granted, READ_CONTROL | WRITE_DAC);
    assert_eq!(privilege_granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(pip, PipEnforcementState::default());
}

#[test]
fn dominance_matrix_requires_both_pip_axes() {
    let label = ProcessTrustLabel {
        pip_type: 512,
        pip_trust: 4096,
        mask: READ_CONTROL,
    };
    let cases = [
        (
            PipContext {
                pip_type: 512,
                pip_trust: 4096,
            },
            true,
        ),
        (
            PipContext {
                pip_type: 1024,
                pip_trust: 8192,
            },
            true,
        ),
        (
            PipContext {
                pip_type: 1024,
                pip_trust: 1024,
            },
            false,
        ),
        (
            PipContext {
                pip_type: 256,
                pip_trust: 8192,
            },
            false,
        ),
    ];

    for (caller_pip, dominates) in cases {
        let mut decided = 0u32;
        let mut granted = READ_CONTROL | WRITE_DAC;
        let mut privilege_granted = WRITE_DAC;

        let pip = apply_pip(
            label,
            caller_pip,
            &mapping(),
            &mut decided,
            &mut granted,
            &mut privilege_granted,
        )
        .expect("pip should succeed");

        if dominates {
            assert_eq!(decided, 0);
            assert_eq!(granted, READ_CONTROL | WRITE_DAC);
            assert_eq!(privilege_granted, WRITE_DAC);
            assert_eq!(pip, PipEnforcementState::default());
        } else {
            assert_eq!(
                decided,
                WRITE_DAC | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY
            );
            assert_eq!(granted, READ_CONTROL);
            assert_eq!(privilege_granted, 0);
            assert_eq!(pip.mandatory_decided, decided);
        }
    }
}

#[test]
fn generic_trust_label_mask_is_mapped_before_denial() {
    let label = ProcessTrustLabel {
        pip_type: 512,
        pip_trust: 4096,
        mask: GENERIC_WRITE,
    };
    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY;
    let mut privilege_granted = WRITE_OWNER | ACCESS_SYSTEM_SECURITY;

    let pip = apply_pip(
        label,
        PipContext {
            pip_type: 512,
            pip_trust: 1024,
        },
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(
        decided,
        READ_CONTROL | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(granted, WRITE_DAC);
    assert_eq!(privilege_granted, 0);
    assert_eq!(pip.mandatory_decided, decided);
}

#[test]
fn non_dominant_pip_revokes_privilege_granted_bits() {
    let label = ProcessTrustLabel {
        pip_type: 512,
        pip_trust: 4096,
        mask: READ_CONTROL,
    };
    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
    let mut privilege_granted = WRITE_OWNER | ACCESS_SYSTEM_SECURITY;

    let pip = apply_pip(
        label,
        PipContext {
            pip_type: 512,
            pip_trust: 1024,
        },
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(
        decided,
        WRITE_DAC | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(granted, READ_CONTROL);
    assert_eq!(privilege_granted, 0);
    assert_eq!(pip.mandatory_decided, decided);
}

#[test]
fn nonstandard_numeric_type_values_are_valid() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let nonstandard = sid_bytes([0, 0, 0, 0, 0, 19], &[1536, 6000]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL | 0x0000_0020,
        &nonstandard,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd)
        .expect("trust label resolution should succeed")
        .expect("trust label should exist");

    assert_eq!(label.pip_type, 1536);
    assert_eq!(label.pip_trust, 6000);

    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC | 0x0000_0020;
    let mut privilege_granted = 0;
    let pip = apply_pip(
        label,
        PipContext {
            pip_type: 1024,
            pip_trust: 6000,
        },
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(granted, READ_CONTROL | 0x0000_0020);
    assert_eq!(decided, WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
    assert_eq!(pip.mandatory_decided, decided);
}
