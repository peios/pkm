/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_TOKEN_H
#define _UAPI_PKM_TOKEN_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include <pkm/sd.h>

/*
 * KACS token ABI — token-handle rights, the token-handle ioctl interface,
 * token information classes, and the privilege set.
 *
 * A token handle is an open file descriptor; per-handle rights are checked
 * against the token's security descriptor at open time, and the ioctls
 * below operate on the handle subject to those granted rights.
 */

/* kacs_open_self_token (SYS_KACS_OPEN_SELF_TOKEN) flags. */
#define KACS_TOKEN_OPEN_REAL		0x01U

/* Per-handle token rights (the low 16 bits of a token access mask). */
#define KACS_TOKEN_ASSIGN_PRIMARY	0x0001U
#define KACS_TOKEN_DUPLICATE		0x0002U
#define KACS_TOKEN_IMPERSONATE		0x0004U
#define KACS_TOKEN_QUERY		0x0008U
#define KACS_TOKEN_QUERY_SOURCE		0x0010U
#define KACS_TOKEN_ADJUST_PRIVS		0x0020U
#define KACS_TOKEN_ADJUST_GROUPS	0x0040U
#define KACS_TOKEN_ADJUST_DEFAULT	0x0080U
#define KACS_TOKEN_ADJUST_SESSIONID	0x0100U
#define KACS_TOKEN_ALL_ACCESS		0x000F01FFU

/* Token ioctl interface identifier. */
#define KACS_IOC_MAGIC			0x4BU

/* kacs_priv_entry.attributes bits. */
#define KACS_PRIVILEGE_ATTR_ENABLED	0x00000002U
#define KACS_PRIVILEGE_ATTR_REMOVED	0x00000004U

/* kacs_adjust_privs bulk-reset flag (not a per-entry attribute). */
#define KACS_PRIVILEGE_RESET_ALL_DEFAULTS	0x80000000U

/* kacs_restrict_args.flags bits. */
#define KACS_TOKEN_RESTRICT_WRITE_RESTRICTED	0x00000001U

/* Token type (KACS_TOKEN_CLASS_TYPE). */
#define KACS_TOKEN_TYPE_PRIMARY		0x01U
#define KACS_TOKEN_TYPE_IMPERSONATION	0x02U

/* Impersonation level (KACS_TOKEN_CLASS_IMPERSONATION_LEVEL). */
#define KACS_IMLEVEL_ANONYMOUS		0x00U
#define KACS_IMLEVEL_IDENTIFICATION	0x01U
#define KACS_IMLEVEL_IMPERSONATION	0x02U
#define KACS_IMLEVEL_DELEGATION		0x03U

/* Elevation type (KACS_TOKEN_CLASS_ELEVATION_TYPE). */
#define KACS_ELEVATION_DEFAULT		0x01U
#define KACS_ELEVATION_FULL		0x02U
#define KACS_ELEVATION_LIMITED		0x03U

/* Mandatory-policy bits (KACS_TOKEN_CLASS_MANDATORY_POLICY). */
#define KACS_TOKEN_MANDATORY_POLICY_NO_WRITE_UP		0x00000001U
#define KACS_TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN	0x00000002U

/* Logon type (KACS_TOKEN_CLASS_LOGON_TYPE). */
#define KACS_LOGON_TYPE_INTERACTIVE		2
#define KACS_LOGON_TYPE_NETWORK			3
#define KACS_LOGON_TYPE_BATCH			4
#define KACS_LOGON_TYPE_SERVICE			5
#define KACS_LOGON_TYPE_NETWORK_CLEARTEXT	8
#define KACS_LOGON_TYPE_NEW_CREDENTIALS		9

/* Maximum number of groups a token may carry. */
#define KACS_TOKEN_MAX_GROUPS		1024U

/* Number of 64-bit words in a group enabled-state bitmask (KACS_TOKEN_MAX_GROUPS / 64). */
#define KACS_TOKEN_GROUP_MASK_WORDS	16U

/* ioctl argument structures. */

struct kacs_query_args {
	__u32 token_class;
	__u32 buf_len;
	__u64 buf_ptr;
};

struct kacs_adjust_privs_args {
	__u32 count;
	__u32 _pad;
	__u64 data_ptr;
	__u64 previous_enabled;
};

struct kacs_priv_entry {
	__u32 luid;
	__u32 attributes;
};

struct kacs_adjust_groups_args {
	__u32 count;
	__u32 _pad;
	__u64 data_ptr;
	__u64 previous_state[16]; /* KACS_TOKEN_GROUP_MASK_WORDS */
};

struct kacs_duplicate_args {
	__u32 access_mask;
	__u32 token_type;
	__u32 impersonation_level;
	__s32 result_fd;
};

struct kacs_group_entry {
	__u32 index;
	__u32 enable;
};

struct kacs_adjust_default_args {
	__u64 dacl_ptr;
	__u32 dacl_len;
	__u16 owner_index;
	__u16 group_index;
};

struct kacs_restrict_args {
	__u64 privs_to_delete;
	__u32 num_deny_indices;
	__u32 num_restrict_sids;
	__u32 data_len;
	__u32 flags;
	__u64 data_ptr;
	__s32 result_fd;
	__u32 _pad;
};

struct kacs_link_tokens_args {
	__s32 elevated_fd;
	__s32 filtered_fd;
	__u64 session_id;
};

struct kacs_get_linked_token_args {
	__s32 result_fd;
};

/* Token-handle ioctls. */
#define KACS_IOC_QUERY		_IOWR(KACS_IOC_MAGIC, 0, struct kacs_query_args)
#define KACS_IOC_ADJUST_PRIVS	\
	_IOW(KACS_IOC_MAGIC, 1, struct kacs_adjust_privs_args)
#define KACS_IOC_DUPLICATE	\
	_IOWR(KACS_IOC_MAGIC, 2, struct kacs_duplicate_args)
#define KACS_IOC_INSTALL	_IO(KACS_IOC_MAGIC, 3)
#define KACS_IOC_RESTRICT	\
	_IOWR(KACS_IOC_MAGIC, 4, struct kacs_restrict_args)
#define KACS_IOC_LINK_TOKENS	\
	_IOW(KACS_IOC_MAGIC, 5, struct kacs_link_tokens_args)
#define KACS_IOC_GET_LINKED_TOKEN	\
	_IOWR(KACS_IOC_MAGIC, 6, struct kacs_get_linked_token_args)
#define KACS_IOC_ADJUST_GROUPS	\
	_IOW(KACS_IOC_MAGIC, 7, struct kacs_adjust_groups_args)
#define KACS_IOC_IMPERSONATE	_IO(KACS_IOC_MAGIC, 8)
#define KACS_IOC_ADJUST_DEFAULT	\
	_IOW(KACS_IOC_MAGIC, 9, struct kacs_adjust_default_args)
#define KACS_IOC_ADJUST_SESSIONID	_IOW(KACS_IOC_MAGIC, 10, __u32)

/* Token information classes (kacs_query_args.token_class). */
#define KACS_TOKEN_CLASS_USER			0x01U
#define KACS_TOKEN_CLASS_GROUPS			0x02U
#define KACS_TOKEN_CLASS_PRIVILEGES		0x03U
#define KACS_TOKEN_CLASS_TYPE			0x04U
#define KACS_TOKEN_CLASS_INTEGRITY_LEVEL	0x05U
#define KACS_TOKEN_CLASS_OWNER			0x06U
#define KACS_TOKEN_CLASS_PRIMARY_GROUP		0x07U
#define KACS_TOKEN_CLASS_SESSION_ID		0x08U
#define KACS_TOKEN_CLASS_RESTRICTED_SIDS	0x09U
#define KACS_TOKEN_CLASS_SOURCE			0x0AU
#define KACS_TOKEN_CLASS_STATISTICS		0x0BU
#define KACS_TOKEN_CLASS_ORIGIN			0x0CU
#define KACS_TOKEN_CLASS_ELEVATION_TYPE		0x0DU
#define KACS_TOKEN_CLASS_DEVICE_GROUPS		0x0EU
#define KACS_TOKEN_CLASS_APPCONTAINER_SID	0x0FU
#define KACS_TOKEN_CLASS_CAPABILITIES		0x10U
#define KACS_TOKEN_CLASS_MANDATORY_POLICY	0x11U
#define KACS_TOKEN_CLASS_LOGON_TYPE		0x12U
#define KACS_TOKEN_CLASS_LOGON_SID		0x13U
#define KACS_TOKEN_CLASS_DEFAULT_DACL		0x14U
#define KACS_TOKEN_CLASS_IMPERSONATION_LEVEL	0x15U
#define KACS_TOKEN_CLASS_USER_CLAIMS		0x16U
#define KACS_TOKEN_CLASS_DEVICE_CLAIMS		0x17U
#define KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS 0x18U

/*
 * Privileges, as single-bit masks within a token's 64-bit privilege word
 * (present / enabled / enabled-by-default / used are each one such word).
 * Named for the Windows privilege identifiers (SeTcbPrivilege, …).
 */
#define KACS_SE_CREATE_TOKEN_PRIVILEGE			(1ULL << 2)
#define KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE		(1ULL << 3)
#define KACS_SE_LOCK_MEMORY_PRIVILEGE			(1ULL << 4)
#define KACS_SE_INCREASE_QUOTA_PRIVILEGE		(1ULL << 5)
#define KACS_SE_TCB_PRIVILEGE				(1ULL << 7)
#define KACS_SE_SECURITY_PRIVILEGE			(1ULL << 8)
#define KACS_SE_LOAD_DRIVER_PRIVILEGE			(1ULL << 10)
#define KACS_SE_SYSTEMTIME_PRIVILEGE			(1ULL << 12)
#define KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE	(1ULL << 13)
#define KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE	(1ULL << 14)
#define KACS_SE_BACKUP_PRIVILEGE			(1ULL << 17)
#define KACS_SE_RESTORE_PRIVILEGE			(1ULL << 18)
#define KACS_SE_SHUTDOWN_PRIVILEGE			(1ULL << 19)
#define KACS_SE_DEBUG_PRIVILEGE				(1ULL << 20)
#define KACS_SE_AUDIT_PRIVILEGE				(1ULL << 21)
#define KACS_SE_CHANGE_NOTIFY_PRIVILEGE			(1ULL << 23)
#define KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE		(1ULL << 24)
#define KACS_SE_IMPERSONATE_PRIVILEGE			(1ULL << 29)
#define KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE		(1ULL << 35)
#define KACS_SE_BIND_PRIVILEGED_PORT_PRIVILEGE		(1ULL << 63)

#endif /* _UAPI_PKM_TOKEN_H */
