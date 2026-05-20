use kacs_core::{ACCESS_ALLOWED_ACE_TYPE, SE_DACL_PRESENT, SE_SELF_RELATIVE, SecurityDescriptor};
use lcs_core::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, Guid, KEY_READ, LcsError,
    OWNER_SECURITY_INFORMATION, RSI_REQUEST_HEADER_LEN, RSI_WRITE_KEY,
    RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, RSI_WRITE_KEY_FIELD_SD, RsiLengthPrefixedField,
    parse_rsi_request_header, parse_rsi_write_key_request_payload, plan_registry_set_security,
    write_registry_set_security_rsi_write_key_request_frame,
};

const KEY_GUID: Guid = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
];

fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + subauths.len() * 4);
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

fn basic_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + sid.len());
    bytes.push(ACCESS_ALLOWED_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(8 + sid.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

fn sd(owner: Option<&[u8]>, group: Option<&[u8]>, dacl: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    let mut control = SE_SELF_RELATIVE;

    let owner_offset = append_optional_component(&mut bytes, owner);
    let group_offset = append_optional_component(&mut bytes, group);
    let dacl_offset = append_optional_component(&mut bytes, dacl);

    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
    }

    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
}

fn append_optional_component(bytes: &mut Vec<u8>, component: Option<&[u8]>) -> u32 {
    let Some(component) = component else {
        return 0;
    };
    let offset = bytes.len() as u32;
    bytes.extend_from_slice(component);
    offset
}

fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

#[test]
fn set_security_dispatch_writes_merged_sd_and_last_write_time() {
    let old_owner = sid(5, &[18]);
    let old_group = sid(5, &[32, 544]);
    let new_owner = sid(5, &[21, 2000]);
    let user = sid(5, &[21, 1000]);
    let old_dacl = acl(&[basic_ace(KEY_READ, &user)]);
    let existing = sd(Some(&old_owner), Some(&old_group), Some(&old_dacl));
    let input = sd(Some(&new_owner), None, None);
    let plan = plan_registry_set_security(&existing, &input, OWNER_SECURITY_INFORMATION)
        .expect("owner-only set-security merge");

    let mut frame = [0u8; 192];
    let built = write_registry_set_security_rsi_write_key_request_frame(
        &mut frame,
        2000,
        77,
        KEY_GUID,
        0x1122_3344_5566_7788,
        &plan,
    )
    .expect("set-security RSI frame");

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.request_id, 2000);
    assert_eq!(header.op_code, RSI_WRITE_KEY);
    assert_eq!(header.txn_id, 77);
    assert_eq!(built.retained.op_code, RSI_WRITE_KEY);

    let payload =
        parse_rsi_write_key_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(
        payload.field_mask,
        RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME
    );
    assert_eq!(payload.sd, Some(field(plan.merged_sd.as_slice())));
    assert_eq!(payload.last_write_time, Some(0x1122_3344_5566_7788));

    let merged = SecurityDescriptor::parse(payload.sd.unwrap().data).unwrap();
    assert_eq!(merged.owner().unwrap().as_bytes(), new_owner.as_slice());
    assert_eq!(merged.group().unwrap().as_bytes(), old_group.as_slice());
    assert_eq!(merged.dacl().unwrap().bytes(), old_dacl.as_slice());
}

#[test]
fn set_security_dispatch_preserves_null_group_replacement() {
    let owner = sid(5, &[18]);
    let old_group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(KEY_READ, &user)]);
    let existing = sd(Some(&owner), Some(&old_group), Some(&dacl));
    let input = sd(None, None, None);
    let plan = plan_registry_set_security(&existing, &input, GROUP_SECURITY_INFORMATION)
        .expect("null group replacement");

    let mut frame = [0u8; 192];
    let built = write_registry_set_security_rsi_write_key_request_frame(
        &mut frame, 2001, 0, KEY_GUID, 55, &plan,
    )
    .expect("set-security RSI frame");
    let payload =
        parse_rsi_write_key_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    let merged = SecurityDescriptor::parse(payload.sd.unwrap().data).unwrap();

    assert!(merged.group().is_none());
    assert_eq!(merged.owner().unwrap().as_bytes(), owner.as_slice());
    assert_eq!(payload.last_write_time, Some(55));
}

#[test]
fn set_security_dispatch_fails_closed_on_short_frame_buffer() {
    let owner = sid(5, &[18]);
    let existing = sd(Some(&owner), None, None);
    let input = sd(Some(&owner), None, None);
    let plan = plan_registry_set_security(
        &existing,
        &input,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )
    .expect("set-security merge");
    let required = RSI_REQUEST_HEADER_LEN + 16 + 4 + 4 + plan.merged_sd.len() + 8;
    let mut frame = vec![0xaa; required - 1];

    assert_eq!(
        write_registry_set_security_rsi_write_key_request_frame(
            &mut frame, 2002, 0, KEY_GUID, 99, &plan
        ),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
