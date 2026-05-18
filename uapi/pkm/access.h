/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_ACCESS_H
#define _UAPI_PKM_ACCESS_H

#include <linux/types.h>

/*
 * KACS AccessCheck ABI — kacs_access_check (SYS_KACS_ACCESS_CHECK) and
 * kacs_access_check_list (SYS_KACS_ACCESS_CHECK_LIST).
 *
 * The syscall takes a pointer to a kacs_access_check_args buffer. Its
 * first field, caller_size, is set to the size the caller was compiled
 * against; the kernel uses it to accept callers built against an older,
 * shorter revision of the structure.
 */

/* Full size of kacs_access_check_args the current kernel copies. */
#define KACS_ACCESS_CHECK_ARGS_SIZE		136U

/* Minimum caller_size the kernel accepts (the v1 / v0.20 layout). */
#define KACS_ACCESS_CHECK_ARGS_V1_SIZE		40U

/* Byte size of one kacs_object_type_entry in the object-type tree array. */
#define KACS_OBJECT_TYPE_ENTRY_SIZE		20U

/* Largest object-audit-context buffer the kernel accepts. */
#define KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN	4096U

/*
 * AccessCheck request. Pointer fields hold userspace addresses; a zero
 * pointer paired with a zero length means "absent". The _pad fields must
 * be zero.
 */
struct kacs_access_check_args {
	__u32 caller_size;
	__s32 token_fd;
	__u64 sd_ptr;
	__u32 sd_len;
	__u32 desired_access;
	__u32 mapping_read;
	__u32 mapping_write;
	__u32 mapping_execute;
	__u32 mapping_all;
	__u64 self_sid_ptr;
	__u32 self_sid_len;
	__u32 privilege_intent;
	__u64 object_tree_ptr;
	__u32 object_tree_count;
	__u32 _pad0;
	__u64 local_claims_ptr;
	__u32 local_claims_len;
	__u32 _pad1;
	__u64 granted_out_ptr;
	__u32 pip_type;
	__u32 pip_trust;
	__u64 audit_context_ptr;
	__u32 audit_context_len;
	__u32 _pad2;
	__u64 continuous_audit_out_ptr;
	__u64 staging_mismatch_out_ptr;
};

/* One entry of the object-type tree (object_tree_ptr points at an array). */
struct kacs_object_type_entry {
	__u16 level;
	__u16 _reserved;
	__u8  guid[16];
};

/* Per-node result of kacs_access_check_list. */
struct kacs_node_result {
	__u32 granted;
	__s32 status;
};

/*
 * Claim value types — the discriminant of one attribute in the @Local
 * claims array (local_claims_ptr).
 */
#define KACS_CLAIM_TYPE_INT64		0x0001U
#define KACS_CLAIM_TYPE_UINT64		0x0002U
#define KACS_CLAIM_TYPE_STRING		0x0003U
#define KACS_CLAIM_TYPE_SID		0x0005U
#define KACS_CLAIM_TYPE_BOOLEAN		0x0006U
#define KACS_CLAIM_TYPE_OCTET		0x0010U

/* Claim attribute flags. */
#define KACS_CLAIM_ATTR_CASE_SENSITIVE		0x0002U
#define KACS_CLAIM_ATTR_USE_FOR_DENY_ONLY	0x0004U
#define KACS_CLAIM_ATTR_DISABLED		0x0010U

#endif /* _UAPI_PKM_ACCESS_H */
