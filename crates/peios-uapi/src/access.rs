// KACS AccessCheck ABI — `kacs_access_check` (syscall 1023) and
// `kacs_access_check_list` (syscall 1024).
//
// The syscall takes a pointer to a `kacs_access_check_args` buffer
// whose first `u32` is the caller-provided size. The struct embeds
// pointers to four side buffers: the security descriptor, an optional
// `PRINCIPAL_SELF` substitution SID, an optional object-type tree, and
// an optional `@Local` claims array.
//
// This module carries the raw struct shadows + constants. The encoders
// (object-tree, claims array) and the safe request builder live in
// `libp-sd`.

/// Full fixed width of `kacs_access_check_args` (the size the kernel
/// copies). Newer kernels may grow this; the `caller_size` field lets
/// the kernel accept smaller v1 callers.
pub const KACS_ACCESS_CHECK_ARGS_SIZE: u32 = 136;

/// Minimum `caller_size` the kernel accepts for a v0.20 AccessCheck.
pub const KACS_ACCESS_CHECK_ARGS_V1_SIZE: u32 = 40;

/// Size of one flat object-type entry in the ABI array.
pub const KACS_OBJECT_TYPE_ENTRY_SIZE: usize = 20;

/// Maximum object-audit-context length the kernel accepts.
pub const KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN: u32 = 4096;

/// On-wire layout of `kacs_access_check_args` (136 bytes).
///
/// All pointer fields are `u64` holding userspace addresses; a zero
/// pointer with a zero length means "absent". `_pad0/1/2` must be zero
/// or the kernel rejects the call with `-EINVAL`.
#[repr(C)]
#[derive(Default)]
pub struct KacsAccessCheckArgs {
    /// Caller-provided size — set to `KACS_ACCESS_CHECK_ARGS_SIZE`.
    pub caller_size: u32,
    /// Token fd the check runs against.
    pub token_fd: i32,
    /// Pointer to the self-relative security descriptor bytes.
    pub sd_ptr: u64,
    /// Length of the security descriptor.
    pub sd_len: u32,
    /// Desired-access mask being checked.
    pub desired_access: u32,
    /// Generic mapping: read.
    pub mapping_read: u32,
    /// Generic mapping: write.
    pub mapping_write: u32,
    /// Generic mapping: execute.
    pub mapping_execute: u32,
    /// Generic mapping: all.
    pub mapping_all: u32,
    /// Optional `PRINCIPAL_SELF` substitution SID pointer (0 = none).
    pub self_sid_ptr: u64,
    /// Length of the self SID (0 = none).
    pub self_sid_len: u32,
    /// Privilege-intent flags used while seeding privileges.
    pub privilege_intent: u32,
    /// Optional object-type tree pointer (0 = none).
    pub object_tree_ptr: u64,
    /// Number of object-type entries.
    pub object_tree_count: u32,
    /// Reserved — must be zero.
    pub _pad0: u32,
    /// Optional `@Local` claims array pointer (0 = none).
    pub local_claims_ptr: u64,
    /// Length of the claims array in bytes.
    pub local_claims_len: u32,
    /// Reserved — must be zero.
    pub _pad1: u32,
    /// Optional scalar `granted` writeback pointer (0 = none).
    pub granted_out_ptr: u64,
    /// PSB-derived PIP type axis.
    pub pip_type: u32,
    /// PSB-derived PIP trust axis.
    pub pip_trust: u32,
    /// Optional object-audit-context pointer (0 = none).
    pub audit_context_ptr: u64,
    /// Length of the object-audit context.
    pub audit_context_len: u32,
    /// Reserved — must be zero.
    pub _pad2: u32,
    /// Optional continuous-audit writeback pointer (0 = none).
    pub continuous_audit_out_ptr: u64,
    /// Optional staging-mismatch writeback pointer (0 = none).
    pub staging_mismatch_out_ptr: u64,
}

/// On-wire layout of one object-type tree entry (20 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct KacsObjectTypeEntry {
    /// Depth in the object-type tree (0 = root).
    pub level: u16,
    /// Reserved — must be zero.
    pub _reserved: u16,
    /// 16-byte object-type GUID.
    pub guid: [u8; 16],
}

/// On-wire layout of one `kacs_node_result` — the per-node output of
/// `kacs_access_check_list`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct KacsNodeResult {
    /// Granted access mask for this node.
    pub granted: u32,
    /// NTSTATUS-style status for this node (0 = granted).
    pub status: i32,
}

// ---------------------------------------------------------------------------
// Claim-attribute constants (the `@Local` claims array). The claims
// array wire format is variable-length and encoded by libp-sd; these
// constants name the value-type discriminants and attribute flags.
// ---------------------------------------------------------------------------

pub const CLAIM_TYPE_INT64: u16 = 0x0001;
pub const CLAIM_TYPE_UINT64: u16 = 0x0002;
pub const CLAIM_TYPE_STRING: u16 = 0x0003;
pub const CLAIM_TYPE_SID: u16 = 0x0005;
pub const CLAIM_TYPE_BOOLEAN: u16 = 0x0006;
pub const CLAIM_TYPE_OCTET: u16 = 0x0010;

pub const CLAIM_SECURITY_ATTRIBUTE_CASE_SENSITIVE: u32 = 0x0002;
pub const CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY: u32 = 0x0004;
pub const CLAIM_SECURITY_ATTRIBUTE_DISABLED: u32 = 0x0010;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_struct_is_136_bytes() {
        // The kernel copies exactly this many bytes; a layout drift
        // would silently corrupt the ABI.
        assert_eq!(
            core::mem::size_of::<KacsAccessCheckArgs>(),
            KACS_ACCESS_CHECK_ARGS_SIZE as usize
        );
    }

    #[test]
    fn args_struct_offsets_match_psd_004() {
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, caller_size), 0);
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, token_fd), 4);
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, sd_ptr), 8);
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, sd_len), 16);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, desired_access),
            20
        );
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, mapping_read), 24);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, mapping_write),
            28
        );
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, mapping_execute),
            32
        );
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, mapping_all), 36);
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, self_sid_ptr), 40);
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, self_sid_len), 48);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, privilege_intent),
            52
        );
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, object_tree_ptr),
            56
        );
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, object_tree_count),
            64
        );
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, _pad0), 68);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, local_claims_ptr),
            72
        );
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, local_claims_len),
            80
        );
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, _pad1), 84);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, granted_out_ptr),
            88
        );
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, pip_type), 96);
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, pip_trust), 100);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, audit_context_ptr),
            104
        );
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, audit_context_len),
            112
        );
        assert_eq!(core::mem::offset_of!(KacsAccessCheckArgs, _pad2), 116);
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, continuous_audit_out_ptr),
            120
        );
        assert_eq!(
            core::mem::offset_of!(KacsAccessCheckArgs, staging_mismatch_out_ptr),
            128
        );
    }

    #[test]
    fn object_type_entry_is_20_bytes() {
        assert_eq!(
            core::mem::size_of::<KacsObjectTypeEntry>(),
            KACS_OBJECT_TYPE_ENTRY_SIZE
        );
    }

    #[test]
    fn object_type_entry_offsets_match_psd_004() {
        assert_eq!(core::mem::offset_of!(KacsObjectTypeEntry, level), 0);
        assert_eq!(core::mem::offset_of!(KacsObjectTypeEntry, _reserved), 2);
        assert_eq!(core::mem::offset_of!(KacsObjectTypeEntry, guid), 4);
    }

    #[test]
    fn node_result_is_8_bytes() {
        assert_eq!(core::mem::size_of::<KacsNodeResult>(), 8);
    }

    #[test]
    fn node_result_offsets_match_psd_004() {
        assert_eq!(core::mem::offset_of!(KacsNodeResult, granted), 0);
        assert_eq!(core::mem::offset_of!(KacsNodeResult, status), 4);
    }
}
