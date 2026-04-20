use kacs_core::{
    execute_access_check_abi, execute_access_check_list_abi, parse_access_check_abi_request,
    AccessCheckAbiMemory, AccessCheckAbiResolved, AccessCheckAbiReturn, AccessCheckToken,
    ConfinementTokenContext, ImpersonationLevel, IntegrityLevel, PipContext, PkmVec,
    RestrictedTokenContext, Sid, TokenPrivileges, TokenType, TokenView,
    KACS_ACCESS_CHECK_ARGS_V1_SIZE, READ_CONTROL, SE_DACL_PRESENT, SE_SELF_RELATIVE, WRITE_DAC,
};
use std::collections::BTreeMap;

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
