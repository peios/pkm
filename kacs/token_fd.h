/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TOKEN_FD_H
#define _SECURITY_PKM_KACS_TOKEN_FD_H

#include <linux/types.h>

#include <pkm/token.h>

struct file;

struct pkm_kacs_token_fd_view {
	const void *token;
	u32 access_mask;
};

int pkm_kacs_validate_token_open_access_mask(u32 access_mask);
long pkm_kacs_open_token_fd_for_subject_checked(const void *subject_token,
						const void *target_token,
						u32 access_mask);
long pkm_kacs_open_token_fd_for_subject_checked_with_pip(
	const void *subject_token, const void *target_token, u32 access_mask,
	u32 pip_type, u32 pip_trust);
long pkm_kacs_open_token_fd_with_fixed_access(const void *target_token,
					      u32 granted_access);
int pkm_kacs_bind_query_token_file(struct file *file,
				   const void *target_token);
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
long pkm_kacs_kunit_token_fd_ioctl(int fd, unsigned int cmd,
				   unsigned long arg);

#endif /* _SECURITY_PKM_KACS_TOKEN_FD_H */
