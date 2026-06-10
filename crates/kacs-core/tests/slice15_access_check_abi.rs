use kacs_core::{
    execute_access_check_abi, execute_access_check_list_abi, parse_access_check_abi_request,
    AccessCheckAbiMemory, AccessCheckAbiResolved, AccessCheckAbiReturn, AccessCheckToken,
    ClaimAttribute, ClaimValue, ConfinementTokenContext, ImpersonationLevel, IntegrityLevel,
    PipContext, PkmVec, RestrictedTokenContext, Sid, TokenPrivileges, TokenType, TokenView,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, CLAIM_TYPE_BOOLEAN, KACS_ACCESS_CHECK_ARGS_V1_SIZE,
    READ_CONTROL, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, WRITE_DAC,
};
use std::collections::BTreeMap;

const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;

fn sid_bytes(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&authority);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

fn parse_sid(bytes: &[u8]) -> Sid<'_> {
    Sid::parse(bytes).expect("sid should parse")
}

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn callback_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8], app_data: &[u8]) -> Vec<u8> {
    let size = (8 + sid.len() + app_data.len() + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(app_data);
    bytes.resize(size, 0);
    bytes
}

fn resource_attribute_ace(application_data: &[u8]) -> Vec<u8> {
    let sid = sid_bytes([0, 0, 0, 0, 0, 1], &[0]);
    let size = (8 + sid.len() + application_data.len() + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&sid);
    bytes.extend_from_slice(application_data);
    bytes.resize(size, 0);
    bytes
}

fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(4);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

fn utf16_cstr(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn bool_claim_entry(name: &str, value: u64) -> Vec<u8> {
    let values_start = 20usize;
    let name_offset = 28usize;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_BOOLEAN.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(values_start as u32).to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn claim_array(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        bytes.extend_from_slice(entry);
    }
    bytes
}

fn expr(tokens: &[u8]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    bytes.extend_from_slice(tokens);
    bytes
}

fn string_literal(value: &str) -> Vec<u8> {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let mut bytes = Vec::new();
    bytes.push(0x10);
    bytes.extend_from_slice(&((utf16.len() * 2) as u32).to_le_bytes());
    for code_unit in utf16 {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes
}

fn attr_ref(opcode: u8, name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(opcode);
    bytes.extend_from_slice(&string_literal(name)[1..]);
    bytes
}

fn append_tokens(tokens: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for token in tokens {
        bytes.extend_from_slice(token);
    }
    bytes
}

fn sd_bytes(owner: &[u8], group: &[u8], dacl: &[u8]) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());

    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner);

    let group_offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes.extend_from_slice(group);

    let dacl_offset = bytes.len() as u32;
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes.extend_from_slice(dacl);

    bytes
}

fn sd_bytes_with_sacl(owner: &[u8], group: &[u8], sacl: &[u8], dacl: &[u8]) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT;
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());

    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner);

    let group_offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes.extend_from_slice(group);

    let sacl_offset = bytes.len() as u32;
    bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
    bytes.extend_from_slice(sacl);

    let dacl_offset = bytes.len() as u32;
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes.extend_from_slice(dacl);

    bytes
}

fn primary_token<'a>(user: Sid<'a>) -> AccessCheckToken<'a> {
    AccessCheckToken {
        subject: TokenView {
            user,
            user_deny_only: false,
            groups: &[],
        },
        token_type: TokenType::Primary,
        impersonation_level: ImpersonationLevel::Impersonation,
        audit_policy: 0,
        privileges: TokenPrivileges::default(),
        integrity_level: IntegrityLevel::Medium,
        mandatory_policy: 0x0000_0001,
        restricted: RestrictedTokenContext::default(),
        confinement: ConfinementTokenContext::default(),
    }
}

fn build_args(size: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; size as usize];
    bytes[0..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn object_tree_entry(level: u16, reserved: u16, guid: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(&level.to_le_bytes());
    bytes.extend_from_slice(&reserved.to_le_bytes());
    bytes.extend_from_slice(&guid);
    bytes
}

fn object_tree_bytes(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(entry);
    }
    bytes
}

#[derive(Default)]
struct TestMemory {
    regions: BTreeMap<u64, Vec<u8>>,
}

impl TestMemory {
    fn insert(&mut self, ptr: u64, bytes: Vec<u8>) {
        self.regions.insert(ptr, bytes);
    }
}

impl AccessCheckAbiMemory for TestMemory {
    fn read_bytes(&self, ptr: u64, len: usize) -> Option<PkmVec<u8>> {
        for (base, region) in &self.regions {
            if ptr < *base {
                continue;
            }
            let start = usize::try_from(ptr - *base).ok()?;
            let end = start.checked_add(len)?;
            if end <= region.len() {
                return Some(region[start..end].to_vec().into());
            }
        }
        None
    }
}

fn resolved<'a>(token: &'a AccessCheckToken<'a>) -> AccessCheckAbiResolved<'a> {
    AccessCheckAbiResolved {
        token,
        default_pip: PipContext {
            pip_type: 7,
            pip_trust: 9,
        },
        device_groups: &[],
        user_claims: &[],
        device_claims: &[],
        policies: &[],
    }
}

fn parse_request_with_object_tree(
    object_tree: Option<Vec<u8>>,
    object_tree_ptr: u64,
    object_tree_count: u32,
) -> kacs_core::KacsResult<kacs_core::AccessCheckAbiRequest> {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15100]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);
    if let Some(object_tree) = object_tree {
        memory.insert(object_tree_ptr, object_tree);
    }

    let mut args = build_args(72);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        20 + owner.len() as u32 + group.len() as u32 + dacl.len() as u32,
    );
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 56, object_tree_ptr);
    write_u32(&mut args, 64, object_tree_count);

    parse_access_check_abi_request(&args, &memory)
}

#[test]
fn short_v1_args_zero_default_later_fields_and_execute_scalar() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15000]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(KACS_ACCESS_CHECK_ARGS_V1_SIZE);
    write_i32(&mut args, 4, 7);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        20 + owner.len() as u32 + group.len() as u32 + dacl.len() as u32,
    );
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 32, 0);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    assert_eq!(request.token_fd, 7);
    assert!(request.self_sid_bytes.is_none());
    assert!(request.object_tree.is_none());
    assert!(request.local_claims.is_empty());
    assert!(request.audit_context.is_none());

    let token = primary_token(parse_sid(&user));
    let result = execute_access_check_abi(&request, &resolved(&token))
        .expect("scalar access check should execute");
    assert_eq!(
        result.disposition,
        AccessCheckAbiReturn::Granted(READ_CONTROL)
    );
    assert!(result.granted_out.is_none());
    assert!(result.node_results.is_none());
}

#[test]
fn nonzero_reserved_padding_is_rejected() {
    let mut args = build_args(72);
    write_u32(&mut args, 68, 1);

    let error = parse_access_check_abi_request(&args, &TestMemory::default())
        .expect_err("non-zero _pad0 should fail");
    assert_eq!(
        error,
        kacs_core::KacsError::NonZeroAbiReservedField("_pad0")
    );
}

#[test]
fn malformed_object_tree_shape_is_rejected_at_abi_boundary() {
    let bad_root = object_tree_bytes(&[object_tree_entry(1, 0, [1u8; 16])]);
    let error = parse_request_with_object_tree(Some(bad_root), 0x2000, 1)
        .expect_err("bad root level must fail");
    assert_eq!(error, kacs_core::KacsError::InvalidObjectTypeRootLevel(1));

    let duplicate_guid = object_tree_bytes(&[
        object_tree_entry(0, 0, [1u8; 16]),
        object_tree_entry(1, 0, [2u8; 16]),
        object_tree_entry(1, 0, [2u8; 16]),
    ]);
    let error = parse_request_with_object_tree(Some(duplicate_guid), 0x2000, 3)
        .expect_err("duplicate object tree GUID must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::DuplicateObjectTypeGuid([2u8; 16])
    );

    let level_gap = object_tree_bytes(&[
        object_tree_entry(0, 0, [1u8; 16]),
        object_tree_entry(2, 0, [2u8; 16]),
    ]);
    let error =
        parse_request_with_object_tree(Some(level_gap), 0x2000, 2).expect_err("gap must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::ObjectTypeLevelGap {
            previous: 0,
            current: 2,
        }
    );
}

#[test]
fn object_tree_reserved_field_is_rejected_at_abi_boundary() {
    let object_tree = object_tree_bytes(&[object_tree_entry(0, 1, [1u8; 16])]);

    let error = parse_request_with_object_tree(Some(object_tree), 0x2000, 1)
        .expect_err("non-zero object-tree reserved field must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::NonZeroAbiReservedField("kacs_object_type_entry._reserved")
    );
}

#[test]
fn object_tree_pointer_count_mismatch_is_rejected_at_abi_boundary() {
    let error = parse_request_with_object_tree(None, 0x2000, 0)
        .expect_err("object-tree pointer without count must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidAbiInput(
            "object_tree_ptr and object_tree_count must both be present"
        )
    );

    let error = parse_request_with_object_tree(None, 0, 1)
        .expect_err("object-tree count without pointer must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidAbiInput(
            "object_tree_ptr and object_tree_count must both be present"
        )
    );
}

#[test]
fn malformed_local_claims_fail_at_abi_boundary() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15001]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);
    memory.insert(0x2000, vec![1, 2, 3]);

    let mut args = build_args(88);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        20 + owner.len() as u32 + group.len() as u32 + dacl.len() as u32,
    );
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 72, 0x2000);
    write_u32(&mut args, 80, 3);

    let error = parse_access_check_abi_request(&args, &memory)
        .expect_err("invalid local claims should fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidClaimFormat("claim array entry length")
    );
}

#[test]
fn public_abi_conditions_see_all_claim_namespaces() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15006]);
    let local_claims = claim_array(&[bool_claim_entry("LocalGate", 1)]);
    let resource_claim_entry = bool_claim_entry("ResourceGate", 2);
    let condition = expr(&append_tokens(&[
        attr_ref(0xf8, "LocalGate"),
        vec![0x87],
        attr_ref(0xf9, "UserGate"),
        vec![0x87],
        vec![0xa0],
        attr_ref(0xfa, "ResourceGate"),
        vec![0x87],
        vec![0xa0],
        attr_ref(0xfb, "DeviceGate"),
        vec![0x87],
        vec![0xa0],
    ]));
    let sacl = acl_bytes(&[resource_attribute_ace(&resource_claim_entry)]);
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        READ_CONTROL,
        &user,
        &condition,
    )]);
    let sd = sd_bytes_with_sacl(&owner, &group, &sacl, &dacl);
    let sd_len = sd.len() as u32;

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);
    memory.insert(0x2000, local_claims);

    let mut args = build_args(88);
    write_u64(&mut args, 8, 0x1000);
    write_u32(&mut args, 16, sd_len);
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 72, 0x2000);
    write_u32(
        &mut args,
        80,
        4 + bool_claim_entry("LocalGate", 1).len() as u32,
    );

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let user_claims = [ClaimAttribute::new(
        "UserGate",
        0,
        vec![ClaimValue::Boolean(1)],
    )];
    let device_claims = [ClaimAttribute::new(
        "DeviceGate",
        0,
        vec![ClaimValue::Boolean(1)],
    )];
    let resolved = AccessCheckAbiResolved {
        token: &token,
        default_pip: PipContext {
            pip_type: 7,
            pip_trust: 9,
        },
        device_groups: &[],
        user_claims: &user_claims,
        device_claims: &device_claims,
        policies: &[],
    };
    let result =
        execute_access_check_abi(&request, &resolved).expect("all claim namespaces should execute");
    assert_eq!(
        result.disposition,
        AccessCheckAbiReturn::Granted(READ_CONTROL)
    );

    let without_device_claim = AccessCheckAbiResolved {
        device_claims: &[],
        ..resolved
    };
    let result = execute_access_check_abi(&request, &without_device_claim)
        .expect("missing claim should deny by skipping callback allow ACE");
    assert_eq!(result.disposition, AccessCheckAbiReturn::AccessDenied);
}

#[test]
fn malformed_resource_attribute_payload_fails_access_check_execution() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15007]);
    let sacl = acl_bytes(&[resource_attribute_ace(&[1, 2, 3, 4])]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes_with_sacl(&owner, &group, &sacl, &dacl);
    let sd_len = sd.len() as u32;

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(136);
    write_u64(&mut args, 8, 0x1000);
    write_u32(&mut args, 16, sd_len);
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let err = execute_access_check_abi(&request, &resolved(&token))
        .expect_err("malformed resource attribute must fail during execution");

    assert_eq!(
        err,
        kacs_core::KacsError::InvalidClaimFormat("claim entry header")
    );
}

#[test]
fn malformed_process_trust_label_fails_access_check_execution() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15005]);
    let invalid_trust = sid_bytes([0, 0, 0, 0, 0, 5], &[512, 4096]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL,
        &invalid_trust,
    )]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes_with_sacl(&owner, &group, &sacl, &dacl);
    let sd_len = sd.len() as u32;

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(136);
    write_u64(&mut args, 8, 0x1000);
    write_u32(&mut args, 16, sd_len);
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let error = execute_access_check_abi(&request, &resolved(&token))
        .expect_err("malformed process trust label must fail closed");

    assert_eq!(error, kacs_core::KacsError::InvalidProcessTrustLabelSid);
}

#[test]
fn denied_scalar_request_still_shapes_optional_outputs() {
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let object_owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9999]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15002]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&object_owner, &group, &dacl);

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(136);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        20 + object_owner.len() as u32 + group.len() as u32 + dacl.len() as u32,
    );
    write_u32(&mut args, 20, READ_CONTROL | WRITE_DAC);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 88, 0x3000);
    write_u64(&mut args, 120, 0x3004);
    write_u64(&mut args, 128, 0x3008);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let result = execute_access_check_abi(&request, &resolved(&token))
        .expect("denied scalar request should execute");

    assert_eq!(result.disposition, AccessCheckAbiReturn::AccessDenied);
    assert_eq!(result.granted_out.expect("granted_out").value, READ_CONTROL);
    assert_eq!(result.continuous_audit_out.expect("continuous").value, 0);
    assert_eq!(result.staging_mismatch_out.expect("staging").value, 0);
}

#[test]
fn list_mode_returns_root_granted_and_per_node_results() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15003]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);

    let mut object_tree = Vec::new();
    object_tree.extend_from_slice(&0u16.to_le_bytes());
    object_tree.extend_from_slice(&0u16.to_le_bytes());
    object_tree.extend_from_slice(&[1u8; 16]);
    object_tree.extend_from_slice(&1u16.to_le_bytes());
    object_tree.extend_from_slice(&0u16.to_le_bytes());
    object_tree.extend_from_slice(&[2u8; 16]);

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);
    memory.insert(0x2000, object_tree);

    let mut args = build_args(136);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        20 + owner.len() as u32 + group.len() as u32 + dacl.len() as u32,
    );
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 56, 0x2000);
    write_u32(&mut args, 64, 2);
    write_u64(&mut args, 88, 0x3000);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let result = execute_access_check_list_abi(&request, 2, &resolved(&token))
        .expect("result-list request should execute");

    assert_eq!(result.disposition, AccessCheckAbiReturn::Success);
    assert_eq!(result.granted_out.expect("granted_out").value, READ_CONTROL);
    let node_results = result.node_results.expect("node results");
    assert_eq!(node_results.len(), 2);
    assert_eq!(node_results[0].granted, READ_CONTROL);
    assert_eq!(node_results[0].status, 0);
    assert_eq!(node_results[1].granted, READ_CONTROL);
    assert_eq!(node_results[1].status, 0);
}

#[test]
fn caller_supplied_pip_overrides_psb_in_query() {
    // PSD-004 §10.7 "PIP source": the caller's args pip overrides the PSB pip
    // for the query (a broker / what-if capability, paralleling token_fd). The
    // SD carries a HIGH process-trust-label {1024,8192} whose mask is WRITE_DAC
    // (not READ_CONTROL). The PSB default {7,9} is NON-dominant and would strip
    // READ_CONTROL, but the caller supplies a DOMINANT pip {2048,16384}, so the
    // label imposes no restriction and READ_CONTROL is granted.
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15020]);
    let trust_label = sid_bytes([0, 0, 0, 0, 0, 19], &[1024, 8192]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        WRITE_DAC,
        &trust_label,
    )]);
    let sd = sd_bytes_with_sacl(&owner, &group, &sacl, &dacl);
    let sd_len = sd.len() as u32;

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(136);
    write_u64(&mut args, 8, 0x1000);
    write_u32(&mut args, 16, sd_len);
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    // Caller-supplied pip in args offsets 96/100 — dominant over the label.
    write_u32(&mut args, 96, 2048);
    write_u32(&mut args, 100, 16384);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let result = execute_access_check_abi(&request, &resolved(&token))
        .expect("scalar access check should execute");

    assert_eq!(
        result.disposition,
        AccessCheckAbiReturn::Granted(READ_CONTROL)
    );
}

#[test]
fn object_tree_count_over_cap_is_rejected_before_alloc() {
    // No object-tree region is inserted: the count cap must reject the request
    // before parse_object_tree ever allocates or reads the (huge) buffer.
    let count = kacs_core::KACS_ACCESS_CHECK_MAX_OBJECT_TYPE_COUNT + 1;
    let error = parse_request_with_object_tree(None, 0x2000, count)
        .expect_err("object_tree_count over cap must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidAbiInput("object_tree_count exceeds maximum")
    );
}

#[test]
fn oversized_sd_len_is_rejected_before_read() {
    // sd_ptr is non-zero but no region is mapped there; the size cap must fire
    // before read_memory so a multi-gigabyte sd_len cannot drive an allocation.
    let mut args = build_args(72);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        (kacs_core::MAX_SECURITY_DESCRIPTOR_BYTES + 1) as u32,
    );

    let error = parse_access_check_abi_request(&args, &TestMemory::default())
        .expect_err("oversized sd_len must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidAbiInput("sd_len exceeds maximum security descriptor size")
    );
}

#[test]
fn oversized_self_sid_len_is_rejected_before_read() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15010]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);
    let sd_len = sd.len() as u32;

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(72);
    write_u64(&mut args, 8, 0x1000);
    write_u32(&mut args, 16, sd_len);
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 40, 0x2000);
    write_u32(&mut args, 48, (Sid::MAX_SIZE + 1) as u32);

    let error = parse_access_check_abi_request(&args, &memory)
        .expect_err("oversized self_sid_len must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidAbiInput("self_sid_len exceeds maximum SID size")
    );
}

#[test]
fn oversized_local_claims_len_is_rejected_before_read() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15011]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);
    let sd_len = sd.len() as u32;

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);

    let mut args = build_args(88);
    write_u64(&mut args, 8, 0x1000);
    write_u32(&mut args, 16, sd_len);
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 72, 0x2000);
    write_u32(&mut args, 80, kacs_core::KACS_ACCESS_CHECK_MAX_LOCAL_CLAIMS_LEN + 1);

    let error = parse_access_check_abi_request(&args, &memory)
        .expect_err("oversized local_claims_len must fail");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidAbiInput("local_claims_len exceeds maximum")
    );
}

#[test]
fn list_mode_rejects_results_count_mismatch() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15004]);
    let dacl = acl_bytes(&[basic_ace(0x00, 0, READ_CONTROL, &user)]);
    let sd = sd_bytes(&owner, &group, &dacl);

    let mut object_tree = Vec::new();
    object_tree.extend_from_slice(&0u16.to_le_bytes());
    object_tree.extend_from_slice(&0u16.to_le_bytes());
    object_tree.extend_from_slice(&[1u8; 16]);

    let mut memory = TestMemory::default();
    memory.insert(0x1000, sd);
    memory.insert(0x2000, object_tree);

    let mut args = build_args(136);
    write_u64(&mut args, 8, 0x1000);
    write_u32(
        &mut args,
        16,
        20 + owner.len() as u32 + group.len() as u32 + dacl.len() as u32,
    );
    write_u32(&mut args, 20, READ_CONTROL);
    write_u32(&mut args, 24, READ_CONTROL);
    write_u32(&mut args, 28, WRITE_DAC);
    write_u32(&mut args, 36, READ_CONTROL | WRITE_DAC);
    write_u64(&mut args, 56, 0x2000);
    write_u32(&mut args, 64, 1);

    let request = parse_access_check_abi_request(&args, &memory).expect("request should parse");
    let token = primary_token(parse_sid(&user));
    let error = execute_access_check_list_abi(&request, 2, &resolved(&token))
        .expect_err("results_count mismatch should fail");
    assert_eq!(
        error,
        kacs_core::KacsError::AccessCheckListResultsCountMismatch {
            expected: 1,
            actual: 2,
        }
    );
}
