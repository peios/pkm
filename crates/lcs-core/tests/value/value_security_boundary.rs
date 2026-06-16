use crate::common::{field};
use lcs_core::{
    BlanketTombstoneEntry, EnumeratedValue, KEY_QUERY_VALUE, KEY_SET_VALUE, QueryValueOutcome,
    QueryValueResult, REG_BINARY, REG_DWORD, REG_IOC_BLANKET_TOMBSTONE, REG_IOC_DELETE_VALUE,
    REG_IOC_ENUM_VALUES, REG_IOC_GET_SECURITY, REG_IOC_QUERY_VALUE, REG_IOC_QUERY_VALUES_BATCH,
    REG_IOC_SET_SECURITY, REG_IOC_SET_VALUE, RegistryIoctlAccessRequirement,
    RegistrySecurityOperation, RegistryValueType, ResolvedValueEntry,
    RsiDeleteValueEntryRequestPayload, RsiQueryValueResponseEntry,
    RsiQueryValuesBlanketResponseEntry, RsiQueryValuesRequestPayload,
    RsiSetBlanketTombstoneRequestPayload, RsiSetValueRequestPayload, RsiTrailingOptionalFieldsPlan,
    ValueEntry, ValueResolution, query_value_result_from_resolution,
    registry_ioctl_access_requirement, registry_ioctl_fixed_granted_mask_allows,
};

const KEY_GUID: [u8; 16] = [0x44; 16];


fn trailing() -> RsiTrailingOptionalFieldsPlan {
    RsiTrailingOptionalFieldsPlan {
        ignored_trailing_len: 0,
    }
}

#[test]
fn value_ioctls_are_gated_only_by_cached_key_fd_rights() {
    for ioctl in [
        REG_IOC_QUERY_VALUE,
        REG_IOC_QUERY_VALUES_BATCH,
        REG_IOC_ENUM_VALUES,
    ] {
        assert_eq!(
            registry_ioctl_access_requirement(ioctl),
            Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(
                KEY_QUERY_VALUE
            ))
        );
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(KEY_QUERY_VALUE, ioctl),
            Ok(Some(true))
        );
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(KEY_SET_VALUE, ioctl),
            Ok(Some(false))
        );
    }

    for ioctl in [
        REG_IOC_SET_VALUE,
        REG_IOC_DELETE_VALUE,
        REG_IOC_BLANKET_TOMBSTONE,
    ] {
        assert_eq!(
            registry_ioctl_access_requirement(ioctl),
            Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(
                KEY_SET_VALUE
            ))
        );
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(KEY_SET_VALUE, ioctl),
            Ok(Some(true))
        );
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(KEY_QUERY_VALUE, ioctl),
            Ok(Some(false))
        );
    }
}

#[test]
fn security_descriptor_ioctls_are_key_scoped_not_value_scoped() {
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_GET_SECURITY),
        Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(
            RegistrySecurityOperation::Get
        ))
    );
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_SET_SECURITY),
        Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(
            RegistrySecurityOperation::Set
        ))
    );
    assert_eq!(
        registry_ioctl_fixed_granted_mask_allows(u32::MAX, REG_IOC_GET_SECURITY),
        Ok(None)
    );
    assert_eq!(
        registry_ioctl_fixed_granted_mask_allows(u32::MAX, REG_IOC_SET_SECURITY),
        Ok(None)
    );
}

#[test]
fn value_resolution_and_query_shapes_carry_no_security_descriptor() {
    let data = [0xde, 0xad, 0xbe, 0xef];
    let raw = ValueEntry {
        layer: "base",
        sequence: 7,
        value_type: REG_DWORD,
        data: &data,
    };
    let blanket = BlanketTombstoneEntry {
        layer: "policy",
        sequence: 9,
    };
    let resolved = ResolvedValueEntry {
        value_type: RegistryValueType::Dword,
        data: raw.data,
        layer: raw.layer,
        precedence: 0,
        sequence: raw.sequence,
    };
    let enumerated = EnumeratedValue {
        name: "Setting",
        value: resolved,
    };
    let query = QueryValueResult {
        value_type: resolved.value_type,
        data: resolved.data,
        data_len: resolved.data.len(),
        sequence: resolved.sequence,
        layer: resolved.layer,
        layer_len: resolved.layer.len(),
    };

    assert_eq!(raw.value_type, REG_DWORD);
    assert_eq!(blanket.layer, "policy");
    assert_eq!(enumerated.name, "Setting");
    assert_eq!(
        query_value_result_from_resolution(ValueResolution::Found(resolved)),
        QueryValueOutcome::Found(query)
    );
}

#[test]
fn rsi_value_payload_shapes_are_key_guid_and_value_data_only() {
    let value_name = field(b"Setting");
    let layer_name = field(b"base");
    let data = field(&[1, 2, 3]);

    let query = RsiQueryValuesRequestPayload {
        guid: KEY_GUID,
        value_name,
        query_all: false,
        trailing: trailing(),
    };
    let response_entry = RsiQueryValueResponseEntry {
        value_name,
        layer_name,
        value_type: REG_BINARY,
        data,
        sequence: 11,
    };
    let blanket_entry = RsiQueryValuesBlanketResponseEntry {
        layer_name,
        sequence: 12,
    };
    let set = RsiSetValueRequestPayload {
        guid: KEY_GUID,
        value_name,
        layer_name,
        value_type: REG_BINARY,
        data,
        sequence: 13,
        expected_sequence: 0,
        trailing: trailing(),
    };
    let delete = RsiDeleteValueEntryRequestPayload {
        guid: KEY_GUID,
        value_name,
        layer_name,
        trailing: trailing(),
    };
    let blanket = RsiSetBlanketTombstoneRequestPayload {
        guid: KEY_GUID,
        layer_name,
        set: true,
        sequence: 14,
        trailing: trailing(),
    };

    assert_eq!(query.guid, KEY_GUID);
    assert_eq!(response_entry.value_name.data, b"Setting");
    assert_eq!(blanket_entry.sequence, 12);
    assert_eq!(set.data.data, &[1, 2, 3]);
    assert_eq!(delete.layer_name.data, b"base");
    assert!(blanket.set);
}
