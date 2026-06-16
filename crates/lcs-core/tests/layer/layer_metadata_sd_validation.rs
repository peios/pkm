use lcs_core::{
    LcsError, RsiMappedErrno, RsiSourceDataValidationFailure, plan_rsi_malformed_source_data,
    validate_layer_metadata_security_descriptor,
};

const SE_SELF_RELATIVE: u16 = 0x8000;

fn system_sid() -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1);
    sid.push(1);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    sid.extend_from_slice(&18u32.to_le_bytes());
    sid
}

fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn ownerless_sd() -> Vec<u8> {
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd
}

#[test]
fn layer_metadata_security_descriptor_validation_accepts_owner_bearing_sds() {
    validate_layer_metadata_security_descriptor(&owner_only_sd()).unwrap();
}

#[test]
fn layer_metadata_security_descriptor_validation_rejects_malformed_sds() {
    assert_eq!(
        validate_layer_metadata_security_descriptor(b"bad"),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "layer_metadata.sd",
        })
    );
}

#[test]
fn layer_metadata_security_descriptor_validation_rejects_ownerless_sds() {
    assert_eq!(
        validate_layer_metadata_security_descriptor(&ownerless_sd()),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "layer_metadata.sd",
        })
    );
}

#[test]
fn layer_metadata_security_descriptor_failures_retain_previous_cache_entry() {
    let plan = plan_rsi_malformed_source_data(
        RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor,
    );

    assert_eq!(plan.caller_errno, RsiMappedErrno::Eio);
    assert!(plan.emit_audit);
    assert!(plan.keep_source_alive);
    assert!(plan.retain_previous_layer_metadata_sd);
}
