/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_ACCESS_CHECK_H
#define _SECURITY_PKM_KACS_ACCESS_CHECK_H

#include <linux/compiler_types.h>
#include <linux/types.h>

#define PKM_KACS_RESOLVED_CTX_KUNIT 0U
#define PKM_KACS_RESOLVED_CTX_TOKEN 1U

struct pkm_kacs_resolved_ctx {
	u32 kind;
	u32 _reserved;
	const void *token;
	const void *caap_cache;
	u32 default_pip_type;
	u32 default_pip_trust;
};

struct kacs_node_result {
	u32 granted;
	s32 status;
};

struct pkm_kacs_usercopy_ops {
	void *ctx;
	bool (*read_bytes)(void *ctx, u64 user_ptr, void *dst, size_t len);
	bool (*write_bytes)(void *ctx, u64 user_ptr, const void *src, size_t len);
};

struct pkm_kacs_audit_event_view {
	const u8 *ace_bytes_ptr;
	size_t ace_bytes_len;
	u32 requested;
	u32 granted;
	bool success;
	bool policy_forced;
	bool has_privilege;
	u64 privilege;
	const u8 *object_audit_context_ptr;
	size_t object_audit_context_len;
};

struct pkm_kacs_privilege_use_event_view {
	u64 privilege;
	u32 requested;
	u32 granted;
	u32 surviving_bits;
	bool success;
	const u8 *object_audit_context_ptr;
	size_t object_audit_context_len;
};

struct pkm_kacs_event_sink_ops {
	void *ctx;
	bool (*on_audit_event)(
		void *ctx,
		const struct pkm_kacs_audit_event_view *event);
	bool (*on_privilege_use_event)(
		void *ctx,
		const struct pkm_kacs_privilege_use_event_view *event);
};

struct pkm_kacs_privilege_state_view {
	u64 present;
	u64 enabled;
	u64 enabled_by_default;
	u64 used;
};

struct pkm_kacs_ingress_summary {
	struct pkm_kacs_privilege_state_view updated_privileges;
	u32 audit_event_count;
	u32 privilege_use_event_count;
};

long pkm_kacs_access_check_ingress_scalar(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_ingress_list(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_user_scalar(
	const void __user *uargs,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_user_list(
	const void __user *uargs,
	struct kacs_node_result __user *results,
	u32 results_count,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_ingress_scalar_with_token_fd(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_ingress_list_with_token_fd(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_user_scalar_with_token_fd(
	const void __user *uargs,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

long pkm_kacs_access_check_user_list_with_token_fd(
	const void __user *uargs,
	struct kacs_node_result __user *results,
	u32 results_count,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

int pkm_kacs_current_pip_context(u32 *pip_type, u32 *pip_trust);

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_kacs_kunit_set_current_pip_context(u32 pip_type, u32 pip_trust);
#endif

const struct pkm_kacs_resolved_ctx *kacs_rust_kunit_access_check_context(void);

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_access_check_syscall_scalar(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr);

long pkm_kacs_kunit_access_check_syscall_list(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count);
#endif

#endif /* _SECURITY_PKM_KACS_ACCESS_CHECK_H */
