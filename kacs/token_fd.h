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

struct kacs_query_args {
	u32 token_class;
	u32 buf_len;
	u64 buf_ptr;
};

#define KACS_IOC_QUERY _IOWR(KACS_IOC_MAGIC, 0, struct kacs_query_args)
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

struct pkm_kacs_token_fd_view {
	const void *token;
	u32 access_mask;
};

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
long pkm_kacs_kunit_token_fd_adjust_session_for_token(int fd,
						      const void *caller_token,
						      u32 session_id);

#endif /* _SECURITY_PKM_KACS_TOKEN_FD_H */
