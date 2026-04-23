/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TOKEN_RUNTIME_H
#define _SECURITY_PKM_KACS_TOKEN_RUNTIME_H

#include <linux/types.h>

#include "access_check.h"

struct pkm_kacs_boot_group_view {
	const u8 *sid_ptr;
	size_t sid_len;
	u32 attributes;
};

struct pkm_kacs_boot_snapshot {
	const void *token_ptr;
	u64 session_id;
	u64 auth_id;
	u64 token_id;
	u64 modified_id;
	u32 logon_type;
	const u8 *auth_pkg_ptr;
	size_t auth_pkg_len;
	const u8 *user_sid_ptr;
	size_t user_sid_len;
	const u8 *logon_sid_ptr;
	size_t logon_sid_len;
	const struct pkm_kacs_boot_group_view *groups_ptr;
	u32 group_count;
	u32 owner_sid_index;
	u32 primary_group_index;
	const u8 *default_dacl_ptr;
	size_t default_dacl_len;
	u64 privileges_present;
	u64 privileges_enabled;
	u64 privileges_enabled_by_default;
	u64 privileges_used;
	u32 integrity_level;
	u32 token_type;
	u32 impersonation_level;
	u32 mandatory_policy;
	u32 interactive_session_id;
	u32 projected_uid;
	u32 projected_gid;
	u32 audit_policy;
};

const void *pkm_kacs_current_effective_token_ptr(void);
const void *pkm_kacs_current_primary_token_ptr(void);
const void *pkm_kacs_boot_system_token_ptr(void);
void *pkm_kacs_zalloc(size_t size);
void pkm_kacs_free(void *ptr);

int pkm_kacs_resolve_ctx_from_token(const void *token,
				    struct pkm_kacs_resolved_ctx *out);
int pkm_kacs_resolve_current_effective_ctx(struct pkm_kacs_resolved_ctx *out);
int pkm_kacs_resolve_current_primary_ctx(struct pkm_kacs_resolved_ctx *out);

const void *kacs_rust_create_boot_system_token(void);
const void *kacs_rust_token_clone(const void *token);
const void *kacs_rust_token_deep_copy(const void *token);
void kacs_rust_token_drop(const void *token);
bool kacs_rust_token_has_enabled_privilege(const void *token, u64 privilege);
bool kacs_rust_token_mark_privileges_used(const void *token, u64 used_mask);
int kacs_rust_token_open_check(const void *subject_token, const void *target_token,
			       u32 desired_access, u32 *granted_out);
u32 kacs_rust_token_projected_uid(const void *token);
u32 kacs_rust_token_projected_gid(const void *token);
bool kacs_rust_kunit_token_snapshot(const void *token,
				    struct pkm_kacs_boot_snapshot *out);
bool kacs_rust_kunit_boot_snapshot(struct pkm_kacs_boot_snapshot *out);
const void *kacs_rust_kunit_create_query_only_token(void);
const void *kacs_rust_kunit_create_without_tcb_token(void);
int kacs_rust_token_query(const void *token, u32 token_class, u8 *out,
			  size_t out_len, size_t *required_out);
int kacs_rust_token_adjust_session_id(const void *token, u32 session_id);
int kacs_rust_token_adjust_default(const void *token, u32 owner_index,
				   u32 group_index, const u8 *dacl,
				   size_t dacl_len, u32 change_dacl);

#endif /* _SECURITY_PKM_KACS_TOKEN_RUNTIME_H */
