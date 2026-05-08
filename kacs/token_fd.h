/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TOKEN_FD_H
#define _SECURITY_PKM_KACS_TOKEN_FD_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* Syscall 1000 flags */
#define KACS_REAL_TOKEN 0x01U

/* Standard/generic access-mask bits used by token opens */
#define KACS_ACCESS_DELETE 0x00010000U
#define KACS_ACCESS_READ_CONTROL 0x00020000U
#define KACS_ACCESS_WRITE_DAC 0x00040000U
#define KACS_ACCESS_WRITE_OWNER 0x00080000U
#define KACS_ACCESS_ACCESS_SYSTEM_SECURITY 0x01000000U
#define KACS_ACCESS_MAXIMUM_ALLOWED 0x02000000U
#define KACS_ACCESS_GENERIC_ALL 0x10000000U
#define KACS_ACCESS_GENERIC_EXECUTE 0x20000000U
#define KACS_ACCESS_GENERIC_WRITE 0x40000000U
#define KACS_ACCESS_GENERIC_READ 0x80000000U

/* Per-handle token rights from Appendix A */
#define KACS_TOKEN_ASSIGN_PRIMARY 0x0001U
#define KACS_TOKEN_DUPLICATE 0x0002U
#define KACS_TOKEN_IMPERSONATE 0x0004U
#define KACS_TOKEN_QUERY 0x0008U
#define KACS_TOKEN_QUERY_SOURCE 0x0010U
#define KACS_TOKEN_ADJUST_PRIVS 0x0020U
#define KACS_TOKEN_ADJUST_GROUPS 0x0040U
#define KACS_TOKEN_ADJUST_DEFAULT 0x0080U
#define KACS_TOKEN_ADJUST_SESSIONID 0x0100U
#define KACS_TOKEN_ALL_ACCESS 0x000F01FFU

/* Token ioctl ABI from Appendix A */
#define KACS_IOC_MAGIC 0x4BU
#define SE_PRIVILEGE_ENABLED 0x00000002U
#define SE_PRIVILEGE_REMOVED 0x00000004U
#define KACS_PRIV_RESET_ALL_DEFAULTS 0x80000000U
#define KACS_RESTRICT_WRITE_RESTRICTED 0x00000001U
#define KACS_TOKEN_TYPE_PRIMARY 0x01U
#define KACS_TOKEN_TYPE_IMPERSONATION 0x02U
#define KACS_LEVEL_ANONYMOUS 0x00U
#define KACS_LEVEL_IDENTIFICATION 0x01U
#define KACS_LEVEL_IMPERSONATION 0x02U
#define KACS_LEVEL_DELEGATION 0x03U
#define KACS_ELEVATION_DEFAULT 0x01U
#define KACS_ELEVATION_FULL 0x02U
#define KACS_ELEVATION_LIMITED 0x03U

struct kacs_query_args {
	u32 token_class;
	u32 buf_len;
	u64 buf_ptr;
};

struct kacs_adjust_privs_args {
	u32 count;
	u32 _pad;
	u64 data_ptr;
	u64 previous_enabled;
};

struct kacs_priv_entry {
	u32 luid;
	u32 attributes;
};

struct kacs_adjust_groups_args {
	u32 count;
	u32 _pad;
	u64 data_ptr;
	u64 previous_state;
};

struct kacs_duplicate_args {
	u32 access_mask;
	u32 token_type;
	u32 impersonation_level;
	s32 result_fd;
};

struct kacs_group_entry {
	u32 index;
	u32 enable;
};

struct kacs_adjust_default_args {
	u64 dacl_ptr;
	u32 dacl_len;
	u16 owner_index;
	u16 group_index;
};

struct kacs_restrict_args {
	u64 privs_to_delete;
	u32 num_deny_indices;
	u32 num_restrict_sids;
	u32 data_len;
	u32 flags;
	u64 data_ptr;
	s32 result_fd;
};

struct kacs_link_tokens_args {
	s32 elevated_fd;
	s32 filtered_fd;
	u64 session_id;
};

struct kacs_get_linked_token_args {
	s32 result_fd;
};

#define KACS_IOC_QUERY _IOWR(KACS_IOC_MAGIC, 0, struct kacs_query_args)
#define KACS_IOC_ADJUST_PRIVS \
	_IOW(KACS_IOC_MAGIC, 1, struct kacs_adjust_privs_args)
#define KACS_IOC_DUPLICATE \
	_IOWR(KACS_IOC_MAGIC, 2, struct kacs_duplicate_args)
#define KACS_IOC_INSTALL _IO(KACS_IOC_MAGIC, 3)
#define KACS_IOC_RESTRICT \
	_IOWR(KACS_IOC_MAGIC, 4, struct kacs_restrict_args)
#define KACS_IOC_LINK_TOKENS \
	_IOW(KACS_IOC_MAGIC, 5, struct kacs_link_tokens_args)
#define KACS_IOC_GET_LINKED_TOKEN \
	_IOWR(KACS_IOC_MAGIC, 6, struct kacs_get_linked_token_args)
#define KACS_IOC_ADJUST_GROUPS \
	_IOW(KACS_IOC_MAGIC, 7, struct kacs_adjust_groups_args)
#define KACS_IOC_IMPERSONATE _IO(KACS_IOC_MAGIC, 8)
#define KACS_IOC_ADJUST_DEFAULT \
	_IOW(KACS_IOC_MAGIC, 9, struct kacs_adjust_default_args)
#define KACS_IOC_ADJUST_SESSIONID _IOW(KACS_IOC_MAGIC, 10, u32)

#define TOKEN_CLASS_USER 0x01U
#define TOKEN_CLASS_GROUPS 0x02U
#define TOKEN_CLASS_PRIVILEGES 0x03U
#define TOKEN_CLASS_TYPE 0x04U
#define TOKEN_CLASS_INTEGRITY_LEVEL 0x05U
#define TOKEN_CLASS_OWNER 0x06U
#define TOKEN_CLASS_PRIMARY_GROUP 0x07U
#define TOKEN_CLASS_SESSION_ID 0x08U
#define TOKEN_CLASS_RESTRICTED_SIDS 0x09U
#define TOKEN_CLASS_SOURCE 0x0AU
#define TOKEN_CLASS_STATISTICS 0x0BU
#define TOKEN_CLASS_ORIGIN 0x0CU
#define TOKEN_CLASS_ELEVATION_TYPE 0x0DU
#define TOKEN_CLASS_DEVICE_GROUPS 0x0EU
#define TOKEN_CLASS_APPCONTAINER_SID 0x0FU
#define TOKEN_CLASS_CAPABILITIES 0x10U
#define TOKEN_CLASS_MANDATORY_POLICY 0x11U
#define TOKEN_CLASS_LOGON_TYPE 0x12U
#define TOKEN_CLASS_LOGON_SID 0x13U
#define TOKEN_CLASS_DEFAULT_DACL 0x14U
#define TOKEN_CLASS_IMPERSONATION_LEVEL 0x15U
#define TOKEN_CLASS_USER_CLAIMS 0x16U
#define TOKEN_CLASS_DEVICE_CLAIMS 0x17U
#define TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS 0x18U

struct pkm_kacs_token_fd_view {
	const void *token;
	u32 access_mask;
};

int pkm_kacs_validate_token_open_access_mask(u32 access_mask);
long pkm_kacs_open_token_fd_for_subject_checked(const void *subject_token,
						const void *target_token,
						u32 access_mask);
long pkm_kacs_open_token_fd_with_fixed_access(const void *target_token,
					      u32 granted_access);
long pkm_kacs_impersonate_token_for_current(const void *client_token);
long pkm_kacs_open_self_token_internal(unsigned int flags, u32 access_mask);
long pkm_kacs_kunit_open_token_fd_for_subject(const void *subject_token,
					      const void *target_token,
					      u32 access_mask);
int pkm_kacs_token_fd_clone_token(int fd, const void **token_out,
				  u32 *access_mask_out);
int pkm_kacs_kunit_token_fd_snapshot(int fd,
				     struct pkm_kacs_token_fd_view *out);
long pkm_kacs_kunit_token_fd_query(int fd, struct kacs_query_args *args,
				   void *out_buf);
long pkm_kacs_kunit_token_fd_adjust_privs(int fd,
					  struct kacs_adjust_privs_args *args,
					  const struct kacs_priv_entry *entries);
long pkm_kacs_kunit_token_fd_duplicate(int fd,
				       const void *subject_token,
				       const void *creator_token,
				       struct kacs_duplicate_args *args);
long pkm_kacs_kunit_token_fd_install(int fd, const void *caller_primary_token);
long pkm_kacs_kunit_token_fd_impersonate(int fd, const void *server_token);
long pkm_kacs_kunit_token_fd_restrict(int fd, const void *subject_token,
				      const void *creator_token,
				      struct kacs_restrict_args *args,
				      const void *payload);
long pkm_kacs_kunit_token_fd_link(int fd, const void *caller_token,
				  struct kacs_link_tokens_args *args);
long pkm_kacs_kunit_token_fd_get_linked(
	int fd, const void *caller_token,
	struct kacs_get_linked_token_args *args);
long pkm_kacs_kunit_token_fd_adjust_groups(int fd,
					   struct kacs_adjust_groups_args *args,
					   const struct kacs_group_entry *entries);
long pkm_kacs_kunit_token_fd_adjust_default(int fd,
					    const struct kacs_adjust_default_args *args,
					    const void *dacl_bytes);
long pkm_kacs_kunit_token_fd_adjust_session_for_token(int fd,
						      const void *caller_token,
						      u32 session_id);

#endif /* _SECURITY_PKM_KACS_TOKEN_FD_H */
