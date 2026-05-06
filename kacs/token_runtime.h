/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TOKEN_RUNTIME_H
#define _SECURITY_PKM_KACS_TOKEN_RUNTIME_H

#include <linux/types.h>

#include "access_check.h"

#define KACS_PROCESS_TERMINATE 0x0001U
#define KACS_PROCESS_SIGNAL 0x0002U
#define KACS_PROCESS_VM_READ 0x0010U
#define KACS_PROCESS_VM_WRITE 0x0020U
#define KACS_PROCESS_DUP_HANDLE 0x0040U
#define KACS_PROCESS_SET_INFORMATION 0x0200U
#define KACS_PROCESS_QUERY_INFORMATION 0x0400U
#define KACS_PROCESS_SUSPEND_RESUME 0x0800U
#define KACS_PROCESS_QUERY_LIMITED 0x1000U

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

struct pkm_kacs_group_adjust_entry {
	u32 index;
	u32 enable;
};

struct pkm_kacs_priv_adjust_entry {
	u32 luid;
	u32 attributes;
};

struct pkm_kacs_kunit_process_state_view {
	const void *state_ptr;
	const void *process_sd_ptr;
	size_t process_sd_len;
	const void *rate_bucket_ptr;
	u32 pip_type;
	u32 pip_trust;
};

struct pkm_kacs_kunit_process_token_open_args {
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 access_mask;
};

struct pkm_kacs_kunit_process_signal_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	int sig;
	u32 kernel_originated;
};

struct pkm_kacs_kunit_process_ptrace_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 mode;
};

struct pkm_kacs_kunit_process_setinfo_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 self_target;
};

struct pkm_kacs_kunit_process_prlimit_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 self_target;
	u32 flags;
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
int pkm_kacs_install_impersonation_token(const void *token);
int pkm_kacs_revert_impersonation(void);
int pkm_kmes_current_process_rate_reserve(u32 count);
void pkm_kmes_current_process_rate_refund(u32 count);

const void *kacs_rust_create_boot_system_token(void);
const void *kacs_rust_token_clone(const void *token);
const void *kacs_rust_token_deep_copy(const void *token);
void kacs_rust_token_drop(const void *token);
bool kacs_rust_token_has_enabled_privilege(const void *token, u64 privilege);
bool kacs_rust_token_mark_privileges_used(const void *token, u64 used_mask);
int kacs_rust_token_open_check(const void *subject_token, const void *target_token,
			       u32 desired_access, u32 *granted_out);
int kacs_rust_token_duplicate(const void *source_token,
			      const void *creator_token, u32 token_type,
			      u32 impersonation_level,
			      const void **out_token);
int kacs_rust_token_impersonation_gate(
	const void *server_token, const void *client_token,
	u32 *effective_level_out, u32 *used_impersonate_privilege_out);
int kacs_rust_token_clone_with_impersonation_level(
	const void *token, u32 impersonation_level, const void **out_token);
const u8 *kacs_rust_create_default_process_sd(const void *token_ptr,
					      size_t *len_out);
const u8 *kacs_rust_kunit_create_query_limited_process_sd(const void *token_ptr,
							  size_t *len_out);
const u8 *kacs_rust_kunit_create_query_information_process_sd(
	const void *token_ptr, size_t *len_out);
int kacs_rust_check_process_sd(const void *subject_token_ptr,
			       const u8 *sd_ptr, size_t sd_len, u32 desired,
			       u32 *granted_out);
u32 kacs_rust_token_projected_uid(const void *token);
u32 kacs_rust_token_projected_gid(const void *token);
bool kacs_rust_kunit_token_snapshot(const void *token,
				    struct pkm_kacs_boot_snapshot *out);
bool kacs_rust_kunit_boot_snapshot(struct pkm_kacs_boot_snapshot *out);
const void *kacs_rust_kunit_create_query_only_token(void);
const void *kacs_rust_kunit_create_without_tcb_token(void);
const void *kacs_rust_kunit_create_adjustable_groups_token(void);
const void *kacs_rust_kunit_create_adjustable_privileges_token(void);
const void *kacs_rust_kunit_create_privilege_audit_token(void);
const void *kacs_rust_kunit_create_impersonation_variant_token(
	u32 user_kind, u32 token_type, u32 impersonation_level,
	u32 integrity_level, u32 restricted, u64 enabled_privileges);
int kacs_rust_token_query(const void *token, u32 token_class, u8 *out,
			  size_t out_len, size_t *required_out);
int kacs_rust_token_adjust_privs(
	const void *token, const struct pkm_kacs_priv_adjust_entry *entries,
	u32 count, u64 *previous_enabled_out);
int kacs_rust_token_adjust_groups(
	const void *token, const struct pkm_kacs_group_adjust_entry *entries,
	u32 count, u64 *previous_state_out);
int kacs_rust_token_adjust_session_id(const void *token, u32 session_id);
int kacs_rust_token_adjust_default(const void *token, u32 owner_index,
				   u32 group_index, const u8 *dacl,
				   size_t dacl_len, u32 change_dacl);

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kmes_kunit_set_current_process_rate_tokens(u32 tokens);
int pkm_kmes_kunit_set_current_process_rate_refill_frozen(bool frozen);
int pkm_kmes_kunit_get_current_process_rate_tokens(u32 *tokens_out);
const void *pkm_kacs_kunit_current_process_state_ptr(void);
const void *pkm_kacs_kunit_inherit_current_process_state(u64 clone_flags);
void pkm_kacs_kunit_put_process_state(const void *state_ptr);
int pkm_kacs_kunit_process_state_snapshot(
	const void *state_ptr,
	struct pkm_kacs_kunit_process_state_view *out);
long pkm_kacs_kunit_open_process_token_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args);
long pkm_kacs_kunit_check_signal_for_subject(
	const struct pkm_kacs_kunit_process_signal_check_args *args);
long pkm_kacs_kunit_check_ptrace_for_subject(
	const struct pkm_kacs_kunit_process_ptrace_check_args *args);
long pkm_kacs_kunit_check_process_setinfo_for_subject(
	const struct pkm_kacs_kunit_process_setinfo_check_args *args);
long pkm_kacs_kunit_check_prlimit_for_subject(
	const struct pkm_kacs_kunit_process_prlimit_check_args *args);
long pkm_kacs_kunit_open_current_thread_token_for_subject(
	const void *subject_token, u32 access_mask);
#endif

#endif /* _SECURITY_PKM_KACS_TOKEN_RUNTIME_H */
