// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_kunit_access_mask_constants_match_spec(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_DELETE, 0x00010000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_READ_CONTROL, 0x00020000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_WRITE_DAC, 0x00040000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_WRITE_OWNER, 0x00080000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_SYNCHRONIZE, 0x00100000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_ACCESS_SYSTEM_SECURITY, 0x01000000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_MAXIMUM_ALLOWED, 0x02000000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_GENERIC_ALL, 0x10000000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_GENERIC_EXECUTE, 0x20000000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_GENERIC_WRITE, 0x40000000U);
	KUNIT_EXPECT_EQ(test, KACS_ACCESS_GENERIC_READ, 0x80000000U);
}


static void pkm_kunit_scalar_denied_writebacks(struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_on_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00060000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, &sinks,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0x00020000U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}


static void pkm_kunit_access_check_emits_to_kmes_without_sink(
	struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	size_t written = 0;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4104, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00060000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, NULL,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0x00020000U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"access-audit",
				  sizeof("access-audit") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PROCESS_PATH) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"policy",
						 sizeof("policy") - 1));
}


static void pkm_kunit_access_check_failing_audit_sink_fails_closed(
	struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_fail_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00060000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, &sinks,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}


static void pkm_kunit_list_faults_on_results_write(struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_on_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x11, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x22, 16);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00020000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);
	pkm_kunit_write_u64(args, 88, 0x3000);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));
	mem.regions[4].fault_write = true;

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_list(&ops, 0x0100, 0x4000, 2, ctx,
						  &sinks, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0x00020000U);
}


static void pkm_kunit_allow_caps_survive_token_lifecycle(struct kunit *test)
{
	const void *old_primary_token;
	const void *new_primary_token = NULL;
	const void *client_token = NULL;
	long old_fd = -1;
	long install_fd = -1;
	long impersonation_fd = -1;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_cred_prepare_transfer_allow_caps(),
			0);
	pkm_kunit_expect_allow_caps_present(test, current_cred());
	pkm_kunit_expect_allow_caps_present(test, current_real_cred());

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE |
			PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);
	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_close;
	pkm_kunit_expect_allow_caps_present(test, current_cred());
	pkm_kunit_expect_allow_caps_present(test, current_real_cred());

	ret = pkm_kacs_kunit_token_fd_impersonate(
		(int)impersonation_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore_primary;
	pkm_kunit_expect_allow_caps_present(test, current_cred());
	pkm_kunit_expect_allow_caps_present(test, current_real_cred());

	ret = pkm_kacs_revert_impersonation();
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore_primary;
	pkm_kunit_expect_allow_caps_present(test, current_cred());
	pkm_kunit_expect_allow_caps_present(test, current_real_cred());

out_restore_primary:
	if (pkm_kacs_current_effective_token_ptr() !=
	    pkm_kacs_current_primary_token_ptr())
		KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!ret) {
		KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
				    old_primary_token);
		pkm_kunit_expect_allow_caps_present(test, current_cred());
		pkm_kunit_expect_allow_caps_present(test, current_real_cred());
	}

out_close:
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_required_build_config_enabled(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, IS_ENABLED(CONFIG_STRICT_DEVMEM));
	KUNIT_EXPECT_TRUE(test, IS_ENABLED(CONFIG_MODULE_SIG));
	KUNIT_EXPECT_TRUE(test, IS_ENABLED(CONFIG_MODULE_SIG_FORCE));
}


static void pkm_kunit_resolved_ctx_fails_closed_on_null_token(struct kunit *test)
{
	struct pkm_kacs_resolved_ctx ctx = {
		.kind = 99,
		._reserved = 99,
		.token = (void *)0x1,
		.caap_cache = (void *)0x2,
		.default_pip_type = 99,
		.default_pip_trust = 99,
	};
	long ret;

	ret = pkm_kacs_resolve_ctx_from_token(NULL, &ctx);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.kind, 99U);
	KUNIT_EXPECT_EQ(test, ctx._reserved, 99U);
	KUNIT_EXPECT_PTR_EQ(test, ctx.token, (void *)0x1);
	KUNIT_EXPECT_PTR_EQ(test, ctx.caap_cache, (void *)0x2);
	KUNIT_EXPECT_EQ(test, ctx.default_pip_type, 99U);
	KUNIT_EXPECT_EQ(test, ctx.default_pip_trust, 99U);
}


static void pkm_kunit_continuous_audit_msgpack_schema(struct kunit *test)
{
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	int ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4301, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	ret = pkm_kacs_kunit_check_file_permission_snapshot_audit(
		1, PKM_KUNIT_FILE_READ_DATA, PKM_KUNIT_FILE_READ_DATA, 0,
		MAY_READ);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_continuous_audit_schema(
				  test, &view, PKM_KUNIT_FILE_READ_DATA,
				  PKM_KUNIT_FILE_READ_DATA,
				  PKM_KUNIT_FILE_READ_DATA, true));
}


static void pkm_kunit_continuous_audit_append_records_matched_subset(
	struct kunit *test)
{
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	int ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

		pkm_kunit_reset_kmes();
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_set_process_override(
					4301, PKM_KUNIT_KMES_PROCESS_NAME,
					PKM_KUNIT_KMES_PROCESS_PATH),
				0);

	ret = pkm_kacs_kunit_check_file_permission_snapshot_audit(
		1, PKM_KUNIT_FILE_APPEND_DATA, PKM_KUNIT_FILE_APPEND_DATA,
		O_APPEND, MAY_WRITE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_continuous_audit_schema(
				  test, &view,
				  PKM_KUNIT_FILE_WRITE_DATA |
					  PKM_KUNIT_FILE_APPEND_DATA,
				  PKM_KUNIT_FILE_APPEND_DATA,
				  PKM_KUNIT_FILE_APPEND_DATA, true));
}


static void pkm_kunit_access_check_public_uses_restricted_device_groups(
	struct kunit *test)
{
	static const struct pkm_kunit_sid_attr_spec restricted_sids[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_match[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_mismatch[] = {
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kacs_token_fd_view matching = { };
	struct pkm_kacs_token_fd_view mismatching = { };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	const u8 *file_sd;
	size_t file_sd_len = 0;
	long matching_fd;
	long mismatching_fd;
	long ret;

	matching_fd = pkm_kunit_create_condition_token_ex(
		true, false, false, restricted_sids, ARRAY_SIZE(restricted_sids),
		restricted_match,
		ARRAY_SIZE(restricted_match), &matching);
	KUNIT_ASSERT_GE(test, matching_fd, 0L);
	mismatching_fd = pkm_kunit_create_condition_token_ex(
		true, false, false, restricted_sids, ARRAY_SIZE(restricted_sids),
		restricted_mismatch,
		ARRAY_SIZE(restricted_mismatch), &mismatching);
	KUNIT_ASSERT_GE(test, mismatching_fd, 0L);

	file_sd = kacs_rust_kunit_create_device_member_file_sd(
		matching.token, pkm_kunit_everyone_sid,
		sizeof(pkm_kunit_everyone_sid), PKM_KUNIT_FILE_READ_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, (u32)file_sd_len);
	pkm_kunit_write_u32(args, 20, PKM_KUNIT_FILE_READ_DATA);
	pkm_kunit_write_u32(args, 24,
			    PKM_KUNIT_FILE_READ_DATA |
				    PKM_KUNIT_FILE_READ_ATTRIBUTES |
				    KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28,
			    PKM_KUNIT_FILE_WRITE_DATA |
				    PKM_KUNIT_FILE_APPEND_DATA |
				    PKM_KUNIT_FILE_WRITE_EA |
				    PKM_KUNIT_FILE_WRITE_ATTRIBUTES |
				    KACS_ACCESS_WRITE_DAC |
				    KACS_ACCESS_WRITE_OWNER);
	pkm_kunit_write_u32(args, 32, PKM_KUNIT_FILE_EXECUTE);
	pkm_kunit_write_u32(args, 36, PKM_KUNIT_FILE_SD_ADMIN_MASK);
	pkm_kunit_write_u64(args, 88, 0x3000);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)file_sd, file_sd_len);
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	pkm_kunit_write_u32(args, 4, (u32)matching_fd);
	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_FILE_READ_DATA);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_FILE_READ_DATA);

	memset(granted_out, 0, sizeof(granted_out));
	pkm_kunit_write_u32(args, 4, (u32)mismatching_fd);
	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);

	pkm_kacs_free((void *)file_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mismatching_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)matching_fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_access_check_token_fd_current_effective(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long ret;

	pkm_kunit_build_read_control_args(args, -1);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}


static void pkm_kunit_access_check_audit_policy_follows_impersonation(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 'd', 'i', 't', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_IMPERSONATION,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.audit_policy =
			PKM_KUNIT_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct pkm_kacs_ingress_summary summary = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *primary_token;
	size_t session_spec_len;
	size_t token_spec_len;
	u64 session_id = 0;
	u32 granted = 0;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	pkm_kunit_reset_kmes();
	ret = pkm_kunit_run_read_control_with_token_fd_summary(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted, &summary);
	KUNIT_EXPECT_GE(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				primary_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(primary_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);

	memset(&summary, 0, sizeof(summary));
	granted = 0;
	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4107, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);
	ret = pkm_kunit_run_read_control_with_token_fd_summary(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kunit_reset_kmes();
}


static void pkm_kunit_access_check_mic_follows_impersonation(
	struct kunit *test)
{
	static const u8 high_label_everyone_write_sd[] = {
		1, 0, 20, 128, 20, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
		60, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		17, 0, 20, 0, 2, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 16, 0, 48, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		0, 0, 20, 0, 0, 0, 4, 0,
		1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	};
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)-1);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(high_label_everyone_write_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)high_label_everyone_write_sd,
			      sizeof(high_label_everyone_write_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_GE(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, (u32)ret, pkm_kunit_read_u32(granted_out, 0));
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u32(granted_out, 0) &
			KACS_ACCESS_WRITE_DAC, 0U);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_MEDIUM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_close;

	memset(granted_out, 0, sizeof(granted_out));
	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

out_close:
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_access_check_token_fd_explicit_handle(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long fd;
	long ret;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_read_control_args(args, (s32)fd);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_access_check_token_fd_rejects_linked_query_copy(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	u8 args[136];
	u8 granted_out[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	const void *caller_token;
	const void *caller_without_tcb;
	long ret;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked(
				(int)pair.filtered_fd, caller_without_tcb, &get),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)get.result_fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, get.result_fd,
						  KACS_TOKEN_CLASS_TYPE),
			KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, get.result_fd,
						  KACS_TOKEN_CLASS_IMPERSONATION_LEVEL),
			KACS_IMLEVEL_IDENTIFICATION);

	pkm_kunit_build_read_control_args(args, (s32)get.result_fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			0xaaaaaaaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)get.result_fd), 0);
	kacs_rust_token_drop(caller_without_tcb);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_access_check_token_fd_invalid_negative(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
}


static void pkm_kunit_access_check_token_fd_rejects_non_token_fd(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	int fd;
	long ret;

	fd = anon_inode_getfd("pkm-kunit-not-token",
			      &pkm_kunit_non_token_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_GE(test, fd, 0);

	pkm_kunit_build_read_control_args(args, fd);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_access_check_token_fd_bad_size_before_lookup(struct kunit *test)
{
	u8 args[136];
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	memset(args, 0, sizeof(args));
	pkm_kunit_write_u32(args, 0, 4);
	pkm_kunit_write_u32(args, 4, 123456U);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
}


static void pkm_kunit_access_check_token_fd_result_list(struct kunit *test)
{
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x33, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x44, 16);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));

	ret = pkm_kacs_access_check_ingress_list_with_token_fd(
		&ops, 0x0100, 0x4000, 2, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), 0U);
}


static void pkm_kunit_access_check_public_malformed_object_tree_fails_closed(
	struct kunit *test)
{
	u8 bad_root[20] = { 0 };
	u8 duplicate_guid[60] = { 0 };
	u8 level_gap[40] = { 0 };
	u8 reserved_field[20] = { 0 };
	u8 valid_root[20] = { 0 };

	pkm_kunit_write_u16(bad_root, 0, 1);
	pkm_kunit_write_u16(bad_root, 2, 0);
	memset(bad_root + 4, 0x11, 16);

	pkm_kunit_write_u16(duplicate_guid, 0, 0);
	pkm_kunit_write_u16(duplicate_guid, 2, 0);
	memset(duplicate_guid + 4, 0x21, 16);
	pkm_kunit_write_u16(duplicate_guid, 20, 1);
	pkm_kunit_write_u16(duplicate_guid, 22, 0);
	memset(duplicate_guid + 24, 0x22, 16);
	pkm_kunit_write_u16(duplicate_guid, 40, 1);
	pkm_kunit_write_u16(duplicate_guid, 42, 0);
	memset(duplicate_guid + 44, 0x22, 16);

	pkm_kunit_write_u16(level_gap, 0, 0);
	pkm_kunit_write_u16(level_gap, 2, 0);
	memset(level_gap + 4, 0x31, 16);
	pkm_kunit_write_u16(level_gap, 20, 2);
	pkm_kunit_write_u16(level_gap, 22, 0);
	memset(level_gap + 24, 0x32, 16);

	pkm_kunit_write_u16(reserved_field, 0, 0);
	pkm_kunit_write_u16(reserved_field, 2, 1);
	memset(reserved_field + 4, 0x41, 16);

	pkm_kunit_write_u16(valid_root, 0, 0);
	pkm_kunit_write_u16(valid_root, 2, 0);
	memset(valid_root + 4, 0x51, 16);

	pkm_kunit_expect_access_check_list_input_denied(
		test, bad_root, sizeof(bad_root), 0x2000, 1, 1);
	pkm_kunit_expect_access_check_list_input_denied(
		test, duplicate_guid, sizeof(duplicate_guid), 0x2000, 3, 3);
	pkm_kunit_expect_access_check_list_input_denied(
		test, level_gap, sizeof(level_gap), 0x2000, 2, 2);
	pkm_kunit_expect_access_check_list_input_denied(
		test, reserved_field, sizeof(reserved_field), 0x2000, 1, 1);
	pkm_kunit_expect_access_check_list_input_denied(
		test, NULL, 0, 0x2000, 0, 0);
	pkm_kunit_expect_access_check_list_input_denied(
		test, NULL, 0, 0, 1, 1);
	pkm_kunit_expect_access_check_list_input_denied(
		test, valid_root, sizeof(valid_root), 0x2000, 1, 2);
}


static void pkm_kunit_access_check_scalar_object_list_intersects_children(
	struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 96, 0, 2, 0, 0, 0,
		5, 0, 44, 0, 0, 0, 6, 0,
		1, 0, 0, 0,
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0,
		5, 0, 44, 0, 0, 0, 2, 0,
		1, 0, 0, 0,
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0,
	};
	u8 object_tree[60] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_on_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x01, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x02, 16);
	pkm_kunit_write_u16(object_tree, 40, 1);
	pkm_kunit_write_u16(object_tree, 42, 0);
	memset(object_tree + 44, 0x03, 16);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 3);
	pkm_kunit_write_u64(args, 88, 0x3000);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, &sinks,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);

	memset(&counts, 0, sizeof(counts));
	memset(granted_out, 0, sizeof(granted_out));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, &sinks,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}


static void pkm_kunit_access_check_owner_implicit_survives_later_deny(
	struct kunit *test)
{
	static const u8 owner_deny_sd[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		32, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		1, 0, 20, 0, 0, 0, 6, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(owner_deny_sd));

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)owner_deny_sd,
			      sizeof(owner_deny_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}


static void pkm_kunit_access_check_invalid_mandatory_label_sid_fails_closed(
	struct kunit *test)
{
	static const u8 invalid_label_sd[] = {
		1, 0, 20, 128, 20, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
		60, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		17, 0, 20, 0, 2, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 16, 57, 48, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		0, 0, 20, 0, 0, 0, 2, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	u8 args[136];
	u8 granted_out[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(invalid_label_sd));

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)invalid_label_sd,
			      sizeof(invalid_label_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0xaaaaaaaaU);
}


static void pkm_kunit_access_check_public_scalar_current_effective(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}


static void pkm_kunit_access_check_public_result_list(struct kunit *test)
{
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x55, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x66, 16);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));

	ret = pkm_kacs_kunit_access_check_syscall_list(&ops, 0x0100, 0x4000,
						       2);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), 0U);
}


static void pkm_kunit_access_check_public_confined_token_paths(
	struct kunit *test)
{
	static const u8 root_guid[16] = {
		0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
		0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
	};
	static const u8 child_grant_guid[16] = {
		0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
		0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
	};
	static const u8 child_deny_guid[16] = {
		0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
		0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kunit_read_ace_spec one_user_ace[] = {
		{
			.ace_type = 0,
			.sid = pkm_kunit_local_service_sid,
			.sid_len = sizeof(pkm_kunit_local_service_sid),
		},
	};
	struct pkm_kunit_read_ace_spec user_and_confinement_aces[] = {
		{
			.ace_type = 0,
			.sid = pkm_kunit_local_service_sid,
			.sid_len = sizeof(pkm_kunit_local_service_sid),
		},
		{
			.ace_type = 0,
			.sid = pkm_kunit_sample_confinement_sid,
			.sid_len = sizeof(pkm_kunit_sample_confinement_sid),
		},
	};
	u8 sd[160] = { };
	u8 object_tree[60] = { };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[24] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	size_t sd_len;
	u32 granted = 0;
	long fd;
	long ret;

	fd = pkm_kunit_create_confined_access_check_token(
		PKM_KUNIT_SE_SECURITY_PRIVILEGE, &view);
	KUNIT_ASSERT_GE(test, fd, 0L);

	sd_len = pkm_kunit_build_read_control_sd(
		sd, sizeof(sd), pkm_kunit_system_sid,
		sizeof(pkm_kunit_system_sid), one_user_ace,
		ARRAY_SIZE(one_user_ace));
	KUNIT_ASSERT_GT(test, (long)sd_len, 0L);
	ret = pkm_kunit_run_read_control_with_token_fd((int)fd, sd, sd_len,
						       NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	memset(sd, 0, sizeof(sd));
	sd_len = pkm_kunit_build_null_dacl_sd(
		sd, sizeof(sd), pkm_kunit_system_sid,
		sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)sd_len, 0L);
	ret = pkm_kunit_run_read_control_with_token_fd((int)fd, sd, sd_len,
						       &granted);
	KUNIT_EXPECT_EQ(test, ret,
			(long)(KACS_ACCESS_READ_CONTROL |
			       KACS_ACCESS_WRITE_DAC));
	KUNIT_EXPECT_EQ(test, granted,
			KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);

	memset(sd, 0, sizeof(sd));
	sd_len = pkm_kunit_build_read_control_sd(
		sd, sizeof(sd), pkm_kunit_system_sid,
		sizeof(pkm_kunit_system_sid), user_and_confinement_aces,
		ARRAY_SIZE(user_and_confinement_aces));
	KUNIT_ASSERT_GT(test, (long)sd_len, 0L);
	memset(args, 0, sizeof(args));
	memset(granted_out, 0, sizeof(granted_out));
	pkm_kunit_build_read_control_args(args, (s32)fd);
	pkm_kunit_write_u32(args, 16, sd_len);
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL |
				    KACS_ACCESS_ACCESS_SYSTEM_SECURITY);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, sd, sd_len);
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			KACS_ACCESS_READ_CONTROL);

	memset(sd, 0, sizeof(sd));
	sd_len = pkm_kunit_build_confinement_object_sd(
		sd, sizeof(sd), child_grant_guid);
	KUNIT_ASSERT_GT(test, (long)sd_len, 0L);
	memset(object_tree, 0, sizeof(object_tree));
	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memcpy(object_tree + 4, root_guid, sizeof(root_guid));
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memcpy(object_tree + 24, child_grant_guid, sizeof(child_grant_guid));
	pkm_kunit_write_u16(object_tree, 40, 1);
	pkm_kunit_write_u16(object_tree, 42, 0);
	memcpy(object_tree + 44, child_deny_guid, sizeof(child_deny_guid));

	memset(args, 0, sizeof(args));
	memset(granted_out, 0, sizeof(granted_out));
	memset(results, 0, sizeof(results));
	memset(&mem, 0, sizeof(mem));
	pkm_kunit_build_read_control_args(args, (s32)fd);
	pkm_kunit_write_u32(args, 16, sd_len);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 3);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, sd, sd_len);
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));
	ret = pkm_kacs_kunit_access_check_syscall_list(&ops, 0x0100, 0x4000,
						       3);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4),
			(u32)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 16), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 20),
			(u32)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_access_check_public_invalid_token_fd(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -2);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
}


static void pkm_kunit_access_check_public_emits_to_kmes(
	struct kunit *test)
{
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)-1);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)pkm_kunit_system_read_audit_sd,
			      sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"access-audit",
				  sizeof("access-audit") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PROCESS_PATH) - 1));
}


static void pkm_kunit_access_check_privilege_use_emits_to_kmes(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const void *subject_token;
	const void *target_token;
	size_t written = 0;
	long fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4206, PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
				PKM_KUNIT_KMES_PRIV_PROCESS_PATH),
			0);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"privilege-use",
				  sizeof("privilege-use") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"SeSecurityPrivilege",
						 sizeof("SeSecurityPrivilege") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PRIV_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PRIV_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PRIV_PROCESS_PATH) - 1));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_access_check_privilege_use_precedes_access_audit_kmes(
	struct kunit *test)
{
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	struct pkm_kunit_kmes_event_view second = { };
	const void *subject_token;
	const void *target_token;
	size_t written = 0;
	long fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4206, PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
				PKM_KUNIT_KMES_PRIV_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)fd);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL |
				    KACS_ACCESS_ACCESS_SYSTEM_SECURITY);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC |
				    KACS_ACCESS_ACCESS_SYSTEM_SECURITY);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)pkm_kunit_system_read_audit_sd,
			      sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &first));
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(
				  buffer + first.event_size,
				  written - first.event_size, &second));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 2ULL);
	KUNIT_EXPECT_TRUE(test, pkm_kunit_expect_kmes_event_type(
					test, &first, "privilege-use"));
	KUNIT_EXPECT_TRUE(test, pkm_kunit_expect_kmes_event_type(
					test, &second, "access-audit"));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_access_audit_msgpack_schema(struct kunit *test)
{
	static const u8 expected_ace[] = {
		2, 64, 20, 0, 0, 0, 2, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)-1);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)pkm_kunit_system_read_audit_sd,
			      sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_access_audit_schema(
				  test, &view, KACS_ACCESS_READ_CONTROL,
				  PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT, true,
				  "sacl", expected_ace,
				  sizeof(expected_ace)));
}


static void pkm_kunit_access_audit_policy_msgpack_schema(struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 'd', 'S', 'c', 'h', 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_IMPERSONATION,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.audit_policy =
			PKM_KUNIT_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
		.source_name = source_name,
		.user_sid = pkm_kunit_system_sid,
		.user_sid_len = sizeof(pkm_kunit_system_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct pkm_kacs_ingress_summary summary = { };
	u8 *buffer;
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const void *primary_token;
	size_t session_spec_len;
	size_t token_spec_len;
	size_t written = 0;
	u64 session_id = 0;
	u32 granted = 0;
	long fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				primary_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(primary_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	ret = pkm_kunit_run_read_control_with_token_fd_summary(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted, &summary);
	KUNIT_EXPECT_EQ(test, ret,
			(long)(KACS_ACCESS_READ_CONTROL |
			       KACS_ACCESS_WRITE_DAC));
	KUNIT_EXPECT_EQ(test, granted,
			KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_access_audit_schema(
				  test, &view, KACS_ACCESS_READ_CONTROL,
				  KACS_ACCESS_READ_CONTROL |
					  KACS_ACCESS_WRITE_DAC,
				  true, "policy", NULL, 0));

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kunit_reset_kmes();
}


static void pkm_kunit_access_audit_subject_group_sids_msgpack_schema(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 'd', 'G', 'r', 'p', 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_administrators_sid,
			.sid_len = sizeof(pkm_kunit_administrators_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_IMPERSONATION,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.audit_policy =
			PKM_KUNIT_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
		.source_name = source_name,
		.user_sid = pkm_kunit_system_sid,
		.user_sid_len = sizeof(pkm_kunit_system_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct pkm_kunit_sid_attr_spec expected_groups[ARRAY_SIZE(groups) + 1];
	struct pkm_kacs_ingress_summary summary = { };
	u8 *buffer;
	u8 logon_sid[20] = { };
	u8 session_spec[64] = { };
	u8 token_spec[320] = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const void *primary_token;
	size_t session_spec_len;
	size_t token_spec_len;
	size_t written = 0;
	u64 session_id = 0;
	u32 granted = 0;
	long fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				primary_token, session_spec, session_spec_len,
				&session_id),
			0L);
	memcpy(expected_groups, groups, sizeof(groups));
	pkm_kunit_build_logon_sid(session_id, logon_sid);
	expected_groups[ARRAY_SIZE(groups)].sid = logon_sid;
	expected_groups[ARRAY_SIZE(groups)].sid_len = sizeof(logon_sid);
	expected_groups[ARRAY_SIZE(groups)].attributes =
		PKM_KUNIT_SE_GROUP_MANDATORY |
		PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
		PKM_KUNIT_SE_GROUP_ENABLED |
		PKM_KUNIT_SE_GROUP_LOGON_ID;

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(primary_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	ret = pkm_kunit_run_read_control_with_token_fd_summary(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted, &summary);
	KUNIT_EXPECT_EQ(test, ret,
			(long)(KACS_ACCESS_READ_CONTROL |
			       KACS_ACCESS_WRITE_DAC));
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_access_audit_subject_group_sids(
				  test, &view, expected_groups,
				  ARRAY_SIZE(expected_groups)));

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kunit_reset_kmes();
}


static void pkm_kunit_access_audit_object_context_msgpack_schema(
	struct kunit *test)
{
	static const u8 object_context[] = {
		0xde, 0xad, 0xbe, 0xef, 0x01,
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)-1);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 104, 0x2000);
	pkm_kunit_write_u32(args, 112, sizeof(object_context));
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)pkm_kunit_system_read_audit_sd,
			      sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_add_region(&mem, 0x2000, (u8 *)object_context,
			      sizeof(object_context));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_access_audit_object_context(
				  test, &view, object_context,
				  sizeof(object_context)));

	pkm_kunit_reset_kmes();
}


static void pkm_kunit_access_audit_invalid_process_name_is_sanitized(
	struct kunit *test)
{
	static const char invalid_name[] = {
		'k', 'a', 'c', 's', (char)0xff, 0,
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 buffer[PKM_KUNIT_KMES_CAPTURE_BYTES];
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view process = { };
	size_t written = 0;
	long ret;

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, invalid_name, PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)-1);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)pkm_kunit_system_read_audit_sd,
			      sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	/*
	 * KC-22: a non-UTF-8 process name (here "kacs\xff") is sanitized to
	 * U+FFFD instead of failing the audited access check closed. The check
	 * must proceed normally and the audit event must still be emitted
	 * (audit output is unsuppressible by a bad process name) — carrying the
	 * sanitized name "kacs\xEF\xBF\xBD".
	 */
	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_msgpack_parse_payload_root(test, &view,
							       &root, 7));
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_msgpack_require_key(test, &root, "process",
							PKM_KUNIT_MSGPACK_MAP,
							&process));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_msgpack_expect_process_map(
				  test, &process, 4105, "kacs\xEF\xBF\xBD",
				  PKM_KUNIT_KMES_PROCESS_PATH));

	pkm_kunit_reset_kmes();
}


static void pkm_kunit_access_check_public_uses_psb_pip_default(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	u32 old_type = 0;
	u32 old_trust = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_pip_sd,
			      sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}


static void pkm_kunit_access_check_public_uses_caap_cache(struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_caap_object_sd));
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_caap_object_sd,
			      sizeof(pkm_kunit_caap_object_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_CAAP_PRIVILEGE_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_access_check_token_ctx_requires_caap_cache(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_resolved_ctx ctx = { };
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_resolve_current_effective_ctx(&ctx), 0L);
	KUNIT_ASSERT_EQ(test, ctx.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_PTR_EQ(test, ctx.caap_cache, NULL);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, &ctx, NULL,
						    NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
}


static void pkm_kunit_access_check_psb_pip_default_none_denies(
	struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(0, 0);

	ret = pkm_kunit_run_pip_labeled_access_check(0, 0, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);
}


static void pkm_kunit_access_check_no_pip_label_ignores_psb_pip(
	struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	ret = pkm_kunit_run_pip_labeled_sd_access_check(
		pkm_kunit_system_read_sd, sizeof(pkm_kunit_system_read_sd),
		0, 0, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}


static void pkm_kunit_access_check_uses_psb_pip_default(struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	ret = pkm_kunit_run_pip_labeled_access_check(0, 0, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}


static void pkm_kunit_access_check_psb_pip_unchanged_by_impersonation(
	struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	const void *primary_token;
	const void *client_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	ret = pkm_kunit_run_pip_labeled_sd_access_check(
		pkm_kunit_everyone_pip_sd, sizeof(pkm_kunit_everyone_pip_sd),
		0, 0, &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore;
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() != primary_token);

	granted = 0;
	ret = pkm_kunit_run_pip_labeled_sd_access_check(
		pkm_kunit_everyone_pip_sd, sizeof(pkm_kunit_everyone_pip_sd),
		0, 0, &granted);
	KUNIT_EXPECT_EQ(test, ret,
			(long)(KACS_ACCESS_READ_CONTROL |
			       KACS_ACCESS_WRITE_DAC));
	KUNIT_EXPECT_EQ(test, granted,
			KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);

	pkm_kacs_kunit_set_current_pip_context(0, 0);
	granted = 0;
	ret = pkm_kunit_run_pip_labeled_sd_access_check(
		pkm_kunit_everyone_pip_sd, sizeof(pkm_kunit_everyone_pip_sd),
		0, 0, &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

out_restore:
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_access_check_explicit_pip_overrides_psb(
	struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	/*
	 * The caller-supplied args pip overrides the PSB pip for this query
	 * (PSD-004 §10.7 "PIP source"): a non-dominant caller pip (1,1) narrows
	 * the grant even though the process PSB context is dominant.
	 */
	ret = pkm_kunit_run_pip_labeled_access_check(1, 1, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);
}


static void pkm_kunit_access_check_result_list_pip_default_and_override(
	struct kunit *test)
{
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	u32 old_type = 0;
	u32 old_trust = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x77, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x88, 16);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_pip_sd,
			      sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));

	ret = pkm_kacs_kunit_access_check_syscall_list(&ops, 0x0100, 0x4000,
						       2);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), 0U);

	memset(granted_out, 0, sizeof(granted_out));
	memset(results, 0, sizeof(results));
	pkm_kunit_write_u32(args, 96, 1);
	pkm_kunit_write_u32(args, 100, 1);
	ret = pkm_kacs_kunit_access_check_syscall_list(&ops, 0x0100, 0x4000,
						       2);
	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);

	/*
	 * The caller-supplied args pip (1,1) overrides the dominant PSB context
	 * for this query, narrowing every node's grant (PSD-004 §10.7).
	 */
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0),
			KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), (u32)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), (u32)-EACCES);
}


static void pkm_kunit_access_check_malformed_process_trust_label_fails_closed(
	struct kunit *test)
{
	static const u8 invalid_pip_label_sd[] = {
		1, 0, 20, 128, 20, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
		64, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		2, 0, 32, 0, 1, 0, 0, 0,
		20, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 0, 2, 0, 0, 5, 0, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		0, 0, 20, 0, 0, 0, 2, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	u8 args[136];
	u8 granted_out[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(invalid_pip_label_sd));

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)invalid_pip_label_sd,
			      sizeof(invalid_pip_label_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0xaaaaaaaaU);
}


static void pkm_kunit_access_check_marks_live_privilege_used(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, before.privileges_used, 0ULL);
	KUNIT_EXPECT_NE(test,
			summary.updated_privileges.used &
				PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_NE(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_access_check_copyout_fault_still_marks_used(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	mem.regions[2].fault_write = true;

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_NE(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_access_check_malformed_input_does_not_mark_used(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_write_u32(args, 68, 1);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_caap_cache_installed_policy_restricts(struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	ret = pkm_kunit_run_caap_access_check(&granted);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_PRIVILEGE_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_caap_cache_replace_changes_future_decisions(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_ASSERT_EQ(test, ret, (long)-EACCES);
	KUNIT_ASSERT_EQ(test, granted, PKM_KUNIT_CAAP_PRIVILEGE_GRANT);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	granted = 0xffffffffU;
	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_access_check_caap_staging_mismatch_emits_kmes(
	struct kunit *test)
{
	u8 spec[96];
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t spec_len;
	size_t written = 0;
	u32 granted = 0xffffffffU;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4307, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec_with_staged_dacl(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl),
		pkm_kunit_caap_empty_dacl, sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	ret = pkm_kunit_run_caap_access_check(&granted);

	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"caap-policy-diagnostic",
				  sizeof("caap-policy-diagnostic") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"staging-mismatch",
						 sizeof("staging-mismatch") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"effective-staged-delta",
						 sizeof("effective-staged-delta") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PROCESS_PATH) - 1));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_caap_policy_diagnostic_msgpack_schema(struct kunit *test)
{
	u8 spec[96];
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t spec_len;
	size_t written = 0;
	u32 granted = 0xffffffffU;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4307, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec_with_staged_dacl(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl),
		pkm_kunit_caap_empty_dacl, sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	ret = pkm_kunit_run_caap_access_check(&granted);

	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_caap_diagnostic_schema(
				  test, &view, PKM_KUNIT_CAAP_READ_GRANT,
				  KACS_ACCESS_ACCESS_SYSTEM_SECURITY));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_caap_cache_remove_uses_recovery_policy(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)0);

	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
}


static void pkm_kunit_caap_cache_malformed_replace_keeps_old_policy(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	spec_len = pkm_kunit_build_caap_spec(spec, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static struct kunit_case pkm_kunit_access_cases[] = {
	KUNIT_CASE(pkm_kunit_access_mask_constants_match_spec),
	KUNIT_CASE(pkm_kunit_scalar_denied_writebacks),
	KUNIT_CASE(pkm_kunit_access_check_emits_to_kmes_without_sink),
	KUNIT_CASE(pkm_kunit_access_check_failing_audit_sink_fails_closed),
	KUNIT_CASE(pkm_kunit_list_faults_on_results_write),
	KUNIT_CASE(pkm_kunit_allow_caps_survive_token_lifecycle),
	KUNIT_CASE(pkm_kunit_required_build_config_enabled),
	KUNIT_CASE(pkm_kunit_resolved_ctx_fails_closed_on_null_token),
	KUNIT_CASE(pkm_kunit_continuous_audit_msgpack_schema),
	KUNIT_CASE(pkm_kunit_continuous_audit_append_records_matched_subset),
	KUNIT_CASE(pkm_kunit_access_check_public_uses_restricted_device_groups),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_current_effective),
	KUNIT_CASE(pkm_kunit_access_check_audit_policy_follows_impersonation),
	KUNIT_CASE(pkm_kunit_access_check_mic_follows_impersonation),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_explicit_handle),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_rejects_linked_query_copy),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_invalid_negative),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_rejects_non_token_fd),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_bad_size_before_lookup),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_result_list),
	KUNIT_CASE(pkm_kunit_access_check_public_malformed_object_tree_fails_closed),
	KUNIT_CASE(pkm_kunit_access_check_scalar_object_list_intersects_children),
	KUNIT_CASE(pkm_kunit_access_check_owner_implicit_survives_later_deny),
	KUNIT_CASE(pkm_kunit_access_check_invalid_mandatory_label_sid_fails_closed),
	KUNIT_CASE(pkm_kunit_access_check_public_scalar_current_effective),
	KUNIT_CASE(pkm_kunit_access_check_public_result_list),
	KUNIT_CASE(pkm_kunit_access_check_public_confined_token_paths),
	KUNIT_CASE(pkm_kunit_access_check_public_invalid_token_fd),
	KUNIT_CASE(pkm_kunit_access_check_public_emits_to_kmes),
	KUNIT_CASE(pkm_kunit_access_check_privilege_use_emits_to_kmes),
	KUNIT_CASE(pkm_kunit_access_check_privilege_use_precedes_access_audit_kmes),
	KUNIT_CASE(pkm_kunit_access_audit_msgpack_schema),
	KUNIT_CASE(pkm_kunit_access_audit_policy_msgpack_schema),
	KUNIT_CASE(pkm_kunit_access_audit_subject_group_sids_msgpack_schema),
	KUNIT_CASE(pkm_kunit_access_audit_object_context_msgpack_schema),
	KUNIT_CASE(pkm_kunit_access_audit_invalid_process_name_is_sanitized),
	KUNIT_CASE(pkm_kunit_access_check_public_uses_psb_pip_default),
	KUNIT_CASE(pkm_kunit_access_check_public_uses_caap_cache),
	KUNIT_CASE(pkm_kunit_access_check_token_ctx_requires_caap_cache),
	KUNIT_CASE(pkm_kunit_access_check_psb_pip_default_none_denies),
	KUNIT_CASE(pkm_kunit_access_check_no_pip_label_ignores_psb_pip),
	KUNIT_CASE(pkm_kunit_access_check_uses_psb_pip_default),
	KUNIT_CASE(pkm_kunit_access_check_psb_pip_unchanged_by_impersonation),
	KUNIT_CASE(pkm_kunit_access_check_explicit_pip_overrides_psb),
	KUNIT_CASE(pkm_kunit_access_check_result_list_pip_default_and_override),
	KUNIT_CASE(pkm_kunit_access_check_malformed_process_trust_label_fails_closed),
	KUNIT_CASE(pkm_kunit_access_check_marks_live_privilege_used),
	KUNIT_CASE(pkm_kunit_access_check_copyout_fault_still_marks_used),
	KUNIT_CASE(pkm_kunit_access_check_malformed_input_does_not_mark_used),
	KUNIT_CASE(pkm_kunit_caap_cache_installed_policy_restricts),
	KUNIT_CASE(pkm_kunit_caap_cache_replace_changes_future_decisions),
	KUNIT_CASE(pkm_kunit_access_check_caap_staging_mismatch_emits_kmes),
	KUNIT_CASE(pkm_kunit_caap_policy_diagnostic_msgpack_schema),
	KUNIT_CASE(pkm_kunit_caap_cache_remove_uses_recovery_policy),
	KUNIT_CASE(pkm_kunit_caap_cache_malformed_replace_keeps_old_policy),
	{}
};

static struct kunit_suite pkm_kunit_access_suite = {
	.name = "pkm_kunit_access",
	.test_cases = pkm_kunit_access_cases,
};

kunit_test_suite(pkm_kunit_access_suite);
