// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_absolute_path_route_uses_first_component_and_errno(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	const char machine_path[] = "Machine\\Software\\App";
	const char missing_path[] = "Users\\Default";
	const char invalid_path[] = "Machine\\";
	const char unterminated_path[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_hive_route_result route = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				machine_path, sizeof(machine_path), false, NULL,
				0, NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				missing_path, sizeof(missing_path), false, NULL,
				0, NULL, 0, &route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				invalid_path, sizeof(invalid_path), false, NULL,
				0, NULL, 0, &route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				unterminated_path, strlen(unterminated_path),
				false, NULL, 0, NULL, 0, &route),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_absolute_path_route_uses_dynamic_hives(
	struct kunit *test)
{
	const char name_src[] = "CustomHive";
	const char custom_path[] = "CustomHive\\Software";
	const char machine_path[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_hive_route_result route = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 42, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				machine_path, sizeof(machine_path), false, NULL,
				0, NULL, 0, &route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				custom_path, sizeof(custom_path), false, NULL,
				0, NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 42U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_absolute_path_current_user_rewrite_routes_users(
	struct kunit *test)
{
	const char name_src[] = "Users";
	const char current_user_path[] = "CurrentUser\\Software";
	const char user_sid_component[] = "S-1-5-18";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_hive_route_result route = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				current_user_path, sizeof(current_user_path),
				false, NULL, 0, NULL, 0, &route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				current_user_path, sizeof(current_user_path),
				true, user_sid_component,
				strlen(user_sid_component), NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_absolute_path_current_user_uses_token_sid(
	struct kunit *test)
{
	const char name_src[] = "Users";
	const char current_user_path[] = "CurrentUser\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_hive_route_result route = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path_for_token(
				token, current_user_path,
				sizeof(current_user_path), true, NULL, 0,
				&route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	memset(&route, 0, sizeof(route));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path_for_token(
				NULL, current_user_path,
				sizeof(current_user_path), true, NULL, 0,
				&route),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_syscall_path_copy_bounds_and_faults(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_syscall_path_copy copy = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, copy.path);
	KUNIT_EXPECT_EQ(test, copy.path_len, (u32)sizeof(path_src));
	KUNIT_EXPECT_STREQ(test, copy.path, path_src);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	pkm_lcs_syscall_path_copy_destroy(&copy);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, NULL, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);

	ctx.unterminated_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
	ctx.unterminated_src = NULL;

	ctx.fault_strlen_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
	ctx.fault_strlen_src = NULL;

	ctx.fault_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
}


static void pkm_lcs_kunit_syscall_path_copy_fault_zeroes_output(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)"stale",
		.path_len = 99,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, NULL, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
	KUNIT_EXPECT_EQ(test, copy.path_len, 0U);

	copy.path = (char *)"stale";
	copy.path_len = 99;
	ctx.fault_strlen_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
	KUNIT_EXPECT_EQ(test, copy.path_len, 0U);
}


static void pkm_lcs_kunit_open_preflight_accepts_valid_masks(
	struct kunit *test)
{
	struct pkm_lcs_open_preflight_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(KEY_QUERY_VALUE, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(GENERIC_READ, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access, GENERIC_READ);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(MAXIMUM_ALLOWED |
						       KEY_QUERY_VALUE,
					       REG_OPEN_LINK, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access,
			MAXIMUM_ALLOWED | KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);
}


static void pkm_lcs_kunit_open_preflight_rejects_fail_closed(
	struct kunit *test)
{
	struct pkm_lcs_open_preflight_plan plan = {
		.requested_access = 0xffffffffU,
		.mapped_desired_access = 0xffffffffU,
		.maximum_allowed = 1,
		.path_resolution_allowed = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(KEY_QUERY_VALUE, 0, NULL),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_open_preflight(0, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.requested_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	plan.path_resolution_allowed = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(0x00100000U, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	plan.path_resolution_allowed = 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_open_preflight(0x00000040U, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	plan.path_resolution_allowed = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(KEY_QUERY_VALUE,
					       REG_OPEN_LINK | 0x80U, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);
}


static void pkm_lcs_kunit_create_preflight_accepts_valid_flags(
	struct kunit *test)
{
	struct pkm_lcs_create_preflight_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(KEY_CREATE_SUB_KEY, 0,
						 &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.access.requested_access,
			KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.access.mapped_desired_access,
			KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.access.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 0U);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(
				MAXIMUM_ALLOWED | KEY_READ,
				REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.access.requested_access,
			MAXIMUM_ALLOWED | KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.access.mapped_desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.access.maximum_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 1U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 1U);
}


static void pkm_lcs_kunit_create_preflight_rejects_fail_closed(
	struct kunit *test)
{
	struct pkm_lcs_create_preflight_plan plan = {
		.access = {
			.requested_access = 0xffffffffU,
			.mapped_desired_access = 0xffffffffU,
			.maximum_allowed = 1,
			.path_resolution_allowed = 1,
		},
		.options = {
			.volatile_key = 1,
			.symlink = 1,
		},
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(KEY_CREATE_SUB_KEY, 0,
						 NULL),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(0, REG_OPTION_VOLATILE,
						 &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.access.requested_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.mapped_desired_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 0U);

	plan.access.path_resolution_allowed = 1;
	plan.options.volatile_key = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(KEY_CREATE_SUB_KEY,
						 REG_OPTION_VOLATILE | 0x04U,
						 &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 0U);
}


static void pkm_lcs_kunit_create_layer_target_null_uses_base(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, NULL, NULL, 0, &target, &plan),
			0L);
	KUNIT_EXPECT_STREQ(test, target.name, "base");
	KUNIT_EXPECT_EQ(test, target.name_len, 4U);
	KUNIT_EXPECT_EQ(test, target.implicit_base, 1U);
	KUNIT_EXPECT_PTR_EQ(test, target.owned_name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	pkm_lcs_create_layer_target_destroy(&target);
}


static void pkm_lcs_kunit_create_layer_target_explicit_layer_admitted(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "Policy", .name_len = 6, .precedence = 25,
		  .enabled = 1 },
	};
	const char layer_src[] = "Policy";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, layers,
				ARRAY_SIZE(layers), &target, &plan),
			0L);
	KUNIT_EXPECT_STREQ(test, target.name, "Policy");
	KUNIT_EXPECT_EQ(test, target.name_len, 6U);
	KUNIT_EXPECT_EQ(test, target.implicit_base, 0U);
	KUNIT_EXPECT_NOT_NULL(test, target.owned_name);
	KUNIT_EXPECT_EQ(test, plan.precedence, 25U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_lcs_create_layer_target_destroy(&target);
}


static void pkm_lcs_kunit_create_layer_target_uses_runtime_limits(
	struct kunit *test)
{
	static const bool widened_cases[] = { false, true };
	enum { LONG_NAME_LEN = 300 };
	char layer_src[LONG_NAME_LEN + 1];
	size_t i;

	memset(layer_src, 'P', LONG_NAME_LEN);
	layer_src[LONG_NAME_LEN] = '\0';
	for (i = 0; i < ARRAY_SIZE(widened_cases); i++) {
		struct pkm_lcs_rsi_layer_view layers[] = {
			{ .name = "base", .name_len = 4, .precedence = 0,
			  .enabled = 1 },
			{ .name = layer_src, .name_len = LONG_NAME_LEN,
			  .precedence = 25, .enabled = 1 },
		};
		struct pkm_lcs_kunit_usercopy_ctx ctx = { };
		struct pkm_lcs_usercopy_ops ops =
			pkm_lcs_kunit_usercopy_ops(&ctx);
		struct pkm_lcs_create_layer_target target = { };
		struct pkm_lcs_layer_target_admission_plan plan = { };
		struct pkm_lcs_runtime_limits limits = { };
		long ret;

		KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits),
				0L);
		if (widened_cases[i])
			limits.max_path_component_length = LONG_NAME_LEN;

		ret = pkm_lcs_create_layer_target_prepare_with_limits(
			&ops, (const char __user *)layer_src, layers,
			ARRAY_SIZE(layers), &limits, &target, &plan);
		KUNIT_EXPECT_EQ(test, ret,
				widened_cases[i] ? 0L : (long)-ENAMETOOLONG);
		if (widened_cases[i]) {
			KUNIT_EXPECT_EQ(test, target.name_len,
					(u32)LONG_NAME_LEN);
			KUNIT_EXPECT_NOT_NULL(test, target.owned_name);
			KUNIT_EXPECT_EQ(test, plan.precedence, 25U);
			KUNIT_EXPECT_EQ(test, plan.enabled, 1U);
		} else {
			KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
			KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
			KUNIT_EXPECT_EQ(test, plan.enabled, 0U);
		}
		KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
		KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

		pkm_lcs_create_layer_target_destroy(&target);
	}
}


static void pkm_lcs_kunit_create_layer_target_absent_returns_enoent(
	struct kunit *test)
{
	const char layer_src[] = "Policy";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = {
		.precedence = 99,
		.enabled = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-ENOENT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, target.owned_name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}


static void pkm_lcs_kunit_create_layer_target_bad_name_fails_closed(
	struct kunit *test)
{
	const char layer_src[] = "bad/layer";
	const char invalid_utf8_layer[] = { 'b', (char)0xff, 'd', '\0' };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = {
		.precedence = 99,
		.enabled = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	memset(&ctx, 0, sizeof(ctx));
	plan.precedence = 99;
	plan.enabled = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)invalid_utf8_layer,
				NULL, 0, &target, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}


static void pkm_lcs_kunit_create_layer_target_copy_faults_fail_closed(
	struct kunit *test)
{
	const char layer_src[] = "base";
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = layer_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.fault_strlen_src = NULL;
	ctx.fault_src = layer_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.fault_src = NULL;
	ctx.unterminated_src = layer_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 3U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}


static void pkm_lcs_kunit_create_layer_target_copy_zeroes_stale_state(
	struct kunit *test)
{
	const char layer_src[] = "base";
	struct pkm_lcs_create_layer_target target = {
		.name = "stale",
		.owned_name = (char *)"stale",
		.name_len = 99,
		.implicit_base = 0,
		._pad = { 0xff, 0xff, 0xff },
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_copy_from_user(
				&ops, NULL, &target),
			0L);
	KUNIT_EXPECT_STREQ(test, target.name, "base");
	KUNIT_EXPECT_PTR_EQ(test, target.owned_name, NULL);
	KUNIT_EXPECT_EQ(test, target.name_len, 4U);
	KUNIT_EXPECT_EQ(test, target.implicit_base, 1U);
	KUNIT_EXPECT_EQ(test, target._pad[0], 0U);
	KUNIT_EXPECT_EQ(test, target._pad[1], 0U);
	KUNIT_EXPECT_EQ(test, target._pad[2], 0U);

	target.name = "stale";
	target.owned_name = (char *)"stale";
	target.name_len = 99;
	target.implicit_base = 1;
	target._pad[0] = 0xff;
	target._pad[1] = 0xff;
	target._pad[2] = 0xff;
	ctx.fault_src = layer_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_copy_from_user(
				&ops, (const char __user *)layer_src, &target),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, target.owned_name, NULL);
	KUNIT_EXPECT_EQ(test, target.name_len, 0U);
	KUNIT_EXPECT_EQ(test, target.implicit_base, 0U);
	KUNIT_EXPECT_EQ(test, target._pad[0], 0U);
	KUNIT_EXPECT_EQ(test, target._pad[1], 0U);
	KUNIT_EXPECT_EQ(test, target._pad[2], 0U);
}


static void pkm_lcs_kunit_open_preflight_route_success(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_open_preflight_plan plan = { };
	struct pkm_lcs_hive_route_result route = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				token, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, REG_OPEN_LINK, false, NULL, 0,
				&plan, &route),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_preflight_route_stops_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_open_preflight_plan plan = { };
	struct pkm_lcs_hive_route_result route = {
		.source_id = 99,
		.root_guid = { 88 },
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src, 0, 0,
				false, NULL, 0, &plan, &route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, REG_OPEN_LINK | 0x80U, false,
				NULL, 0, &plan, &route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, false, NULL, 0, NULL,
				&route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}


static void pkm_lcs_kunit_open_preflight_route_copy_fault_keeps_route_empty(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = path_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_open_preflight_plan plan = { };
	struct pkm_lcs_hive_route_result route = {
		.source_id = 99,
		.root_guid = { 88 },
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, false, NULL, 0, &plan,
				&route),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}


static void pkm_lcs_kunit_open_path_components_absolute_success(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software\\App";
	struct pkm_lcs_materialized_path path = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, path_src, sizeof(path_src), false, &path),
			0L);
	KUNIT_EXPECT_EQ(test, path.component_count, 3U);
	KUNIT_ASSERT_NOT_NULL(test, path.components);
	KUNIT_ASSERT_NOT_NULL(test, path.strings);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 0,
						    "Machine");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 1,
						    "Software");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 2, "App");
	KUNIT_EXPECT_EQ(test, path.string_bytes,
			(u32)(strlen("Machine") + strlen("Software") +
			      strlen("App")));

	pkm_lcs_materialized_path_destroy(&path);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
}


static void pkm_lcs_kunit_open_path_components_normalizes_forward_slashes(
	struct kunit *test)
{
	const char path_src[] = "Machine/Software/App";
	struct pkm_lcs_materialized_path path = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, path_src, sizeof(path_src), false, &path),
			0L);
	KUNIT_EXPECT_EQ(test, path.component_count, 3U);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 0,
						    "Machine");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 1,
						    "Software");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 2, "App");

	pkm_lcs_materialized_path_destroy(&path);
}


static void pkm_lcs_kunit_open_path_components_rewrites_current_user(
	struct kunit *test)
{
	const char path_src[] = "CurrentUser\\App";
	struct pkm_lcs_materialized_path path = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				token, path_src, sizeof(path_src), true, &path),
			0L);
	KUNIT_EXPECT_EQ(test, path.component_count, 3U);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 0, "Users");
	KUNIT_ASSERT_NOT_NULL(test, path.components[1].name);
	KUNIT_ASSERT_GT(test, path.components[1].name_len, 2U);
	KUNIT_EXPECT_EQ(test, memcmp(path.components[1].name, "S-", 2), 0);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 2, "App");

	pkm_lcs_materialized_path_destroy(&path);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_path_components_rejects_fail_closed(
	struct kunit *test)
{
	const char malformed_path[] = "Machine\\";
	const char current_user_path[] = "CurrentUser\\App";
	struct pkm_lcs_materialized_path path = {
		.component_count = 99,
		.string_bytes = 99,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, malformed_path, sizeof(malformed_path),
				false, &path),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
	KUNIT_EXPECT_EQ(test, path.component_count, 0U);
	KUNIT_EXPECT_EQ(test, path.string_bytes, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, current_user_path,
				sizeof(current_user_path), true, &path),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
}


static void pkm_lcs_kunit_open_absolute_composes_success(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
	};
	const char path_src[] = "Machine\\Software\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[2] = {
		{ .expected_child = "Software", .guid = software_guid },
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[1].sd = sd;
	steps[1].sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-abs");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, layers, ARRAY_SIZE(layers), NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, snapshot.first_ancestor_guid[0], 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, app_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_uses_implicit_base_layer(
	struct kunit *test)
{
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44,
	};
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-base");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_final_symlink_open_link(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
	};
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "Link", .guid = link_guid,
		  .symlink = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ,
		REG_OPEN_LINK, NULL, 0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Link");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, link_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, link_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_final_symlink_follows_target(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
		0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
		0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_symlink_follow_source_script script = {
		.link_step = {
			.expected_child = "Link",
			.guid = link_guid,
			.symlink = true,
		},
		.target_step = {
			.expected_child = "Target",
			.guid = target_guid,
		},
		.target_data = target_path,
		.target_data_len = sizeof(target_path) - 1,
		.target_value_type = REG_LINK,
		.expect_target_lookup = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.target_step.sd = sd;
	script.target_step.sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_follow_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-link-follow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_final_symlink_bad_target_einval(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
		0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
	};
	static const u8 bad_target_path[] = "Machine\\\\Target";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_symlink_follow_source_script script = {
		.link_step = {
			.expected_child = "Link",
			.guid = link_guid,
			.symlink = true,
		},
		.target_data = bad_target_path,
		.target_data_len = sizeof(bad_target_path) - 1,
		.target_value_type = REG_LINK,
		.expect_target_lookup = false,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_follow_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-link-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_intermediate_symlink_follows_suffix(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
		0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
		0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
	};
	static const u8 leaf_guid[RSI_GUID_SIZE] = {
		0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine\\Link\\Leaf";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_walk_source_step leaf_step = {
		.expected_child = "Leaf",
		.guid = leaf_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &leaf_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	leaf_step.sd = sd;
	leaf_step.sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-abs-link-mid");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Leaf");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, leaf_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, leaf_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_recursive_symlink_follows_target(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
		0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
	};
	static const u8 mid_guid[RSI_GUID_SIZE] = {
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
		0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
	};
	static const u8 mid_path[] = "Machine\\Mid";
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step mid_step = {
		.expected_child = "Mid",
		.guid = mid_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = mid_path,
		  .query_data_len = sizeof(mid_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &mid_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = mid_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	target_step.sd = sd;
	target_step.sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-abs-link-rec");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_symlink_depth_limit_eloop(
	struct kunit *test)
{
	static const u8 loop_guid[RSI_GUID_SIZE] = {
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
		0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
	};
	static const u8 loop_path[] = "Machine\\Loop";
	const char path_src[] = "Machine\\Loop";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step loop_step = {
		.expected_child = "Loop",
		.guid = loop_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_symlink_sequence_op
		sequence[PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT * 2U + 1U];
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 i;
	long ret;
	int thread_ret;

	for (i = 0; i < PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT; i++) {
		sequence[i * 2U] =
			(struct pkm_lcs_kunit_symlink_sequence_op) {
				.op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
				.lookup_step = &loop_step,
			};
		sequence[i * 2U + 1U] =
			(struct pkm_lcs_kunit_symlink_sequence_op) {
				.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
				.query_guid = loop_guid,
				.query_data = loop_path,
				.query_data_len = sizeof(loop_path) - 1,
				.query_value_type = REG_LINK,
			};
	}
	sequence[ARRAY_SIZE(sequence) - 1U] =
		(struct pkm_lcs_kunit_symlink_sequence_op) {
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
			.lookup_step = &loop_step,
		};

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-abs-link-eloop");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ELOOP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads,
			PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT * 2U + 1U);
	KUNIT_EXPECT_EQ(test, script.writes,
			PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT * 2U + 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_runtime_symlink_depth_limit_eloop(
	struct kunit *test)
{
	static const u8 loop_guid[RSI_GUID_SIZE] = {
		0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
		0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
	};
	static const u8 loop_path[] = "Machine\\Loop";
	const char path_src[] = "Machine\\Loop";
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step loop_step = {
		.expected_child = "Loop",
		.guid = loop_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[5];
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 i;
	long ret;
	int thread_ret;

	for (i = 0; i < 2U; i++) {
		sequence[i * 2U] =
			(struct pkm_lcs_kunit_symlink_sequence_op) {
				.op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
				.lookup_step = &loop_step,
			};
		sequence[i * 2U + 1U] =
			(struct pkm_lcs_kunit_symlink_sequence_op) {
				.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
				.query_guid = loop_guid,
				.query_data = loop_path,
				.query_data_len = sizeof(loop_path) - 1,
				.query_value_type = REG_LINK,
			};
	}
	sequence[ARRAY_SIZE(sequence) - 1U] =
		(struct pkm_lcs_kunit_symlink_sequence_op) {
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
			.lookup_step = &loop_step,
		};

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_symlink_sequence_source_thread, &script,
		"pkm-lcs-kunit-open-runtime-link-eloop");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.symlink_depth_limit = 2U;
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ELOOP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_root_uses_read_key(struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Machine");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_syscall_dispatches_absolute(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-reg-open-abs");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_open_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Machine");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_uses_dynamic_hive(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 42 };
	const char name_src[] = "CustomHive";
	const char path_src[] = "CustomHive";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "CustomHive",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src,
					  root_guid[0], 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &script,
		"pkm-lcs-kunit-reg-open-dyn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_open_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "CustomHive");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "CustomHive");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_uses_empty_private_credential_view(
	struct kunit *test)
{
	static const u8 global_root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 private_root_guid[RSI_GUID_SIZE] = { 2 };
	const char name_src[] = "Machine";
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry global_hive;
	struct reg_src_register_args global_args;
	struct reg_src_hive_entry private_hive;
	struct reg_src_register_args private_args;
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script global_script = {
		.expected_guid = global_root_guid,
		.name = "Machine",
	};
	struct pkm_lcs_kunit_read_key_source_script private_script = {
		.expected_guid = private_root_guid,
		.name = "Machine",
	};
	struct task_struct *global_task;
	struct task_struct *private_task;
	struct file global_file = { };
	struct file private_file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int global_thread_ret;
	int private_thread_ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &global_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &private_file),
			0L);

	pkm_lcs_kunit_build_register_args(&global_args, &global_hive,
					  name_src, global_root_guid[0], 0);
	pkm_lcs_kunit_build_private_register_args(
		&private_args, &private_hive, name_src, private_root_guid[0],
		0x42);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &global_file, &ops,
				(const void __user *)&global_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &private_file, &ops,
				(const void __user *)&private_args),
			0L);

	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	global_script.file = &global_file;
	global_script.sd = sd;
	global_script.sd_len = sd_len;
	private_script.file = &private_file;
	private_script.sd = sd;
	private_script.sd_len = sd_len;

	global_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &global_script,
		"pkm-lcs-kunit-reg-open-global");
	KUNIT_ASSERT_FALSE(test, IS_ERR(global_task));
	private_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &private_script,
		"pkm-lcs-kunit-reg-open-private");
	KUNIT_ASSERT_FALSE(test, IS_ERR(private_task));

	fd = pkm_lcs_reg_open_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0);
	global_thread_ret = pkm_lcs_kunit_kthread_stop(global_task);
	private_thread_ret = pkm_lcs_kunit_kthread_stop(private_task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, global_thread_ret, 0);
	KUNIT_EXPECT_EQ(test, global_script.result, 0);
	KUNIT_EXPECT_EQ(test, global_script.reads, 1U);
	KUNIT_EXPECT_EQ(test, global_script.writes, 1U);
	KUNIT_EXPECT_EQ(test, private_thread_ret, -EINTR);
	KUNIT_EXPECT_EQ(test, private_script.result, -EINTR);
	KUNIT_EXPECT_EQ(test, private_script.reads, 0U);
	KUNIT_EXPECT_EQ(test, private_script.writes, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, global_root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Machine");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&global_file),
			0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&private_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_uses_kacs_private_scope(
	struct kunit *test)
{
	static const u8 global_root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 private_root_guid[RSI_GUID_SIZE] = { 2 };
	static const u8 scopes[1][KACS_LCS_SCOPE_GUID_BYTES] = { { 0x42 } };
	const char name_src[] = "Machine";
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry global_hive;
	struct reg_src_register_args global_args;
	struct reg_src_hive_entry private_hive;
	struct reg_src_register_args private_args;
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script global_script = {
		.expected_guid = global_root_guid,
		.name = "Machine",
	};
	struct pkm_lcs_kunit_read_key_source_script private_script = {
		.expected_guid = private_root_guid,
		.name = "Machine",
	};
	struct task_struct *global_task;
	struct task_struct *private_task;
	struct file global_file = { };
	struct file private_file = { };
	const void *source_token;
	const void *caller_token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int global_thread_ret;
	int private_thread_ret;

	pkm_lcs_kunit_reset_source_table();
	source_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	caller_token = kacs_rust_kunit_create_lcs_private_credential_token(
		scopes, ARRAY_SIZE(scopes), NULL, 0);
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(source_token,
								  &global_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(source_token,
								  &private_file),
			0L);

	pkm_lcs_kunit_build_register_args(&global_args, &global_hive,
					  name_src, global_root_guid[0], 0);
	pkm_lcs_kunit_build_private_register_args(
		&private_args, &private_hive, name_src, private_root_guid[0],
		0x42);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				source_token, &global_file, &ops,
				(const void __user *)&global_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				source_token, &private_file, &ops,
				(const void __user *)&private_args),
			0L);

	sd = kacs_rust_kunit_create_file_sd(caller_token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	global_script.file = &global_file;
	global_script.sd = sd;
	global_script.sd_len = sd_len;
	private_script.file = &private_file;
	private_script.sd = sd;
	private_script.sd_len = sd_len;

	global_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &global_script,
		"pkm-lcs-kunit-reg-open-global-skip");
	KUNIT_ASSERT_FALSE(test, IS_ERR(global_task));
	private_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &private_script,
		"pkm-lcs-kunit-reg-open-private-hit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(private_task));

	fd = pkm_lcs_reg_open_key_for_token(caller_token, &ops, -1,
					    (const char __user *)path_src,
					    KEY_READ, 0);
	global_thread_ret = pkm_lcs_kunit_kthread_stop(global_task);
	private_thread_ret = pkm_lcs_kunit_kthread_stop(private_task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, global_thread_ret, -EINTR);
	KUNIT_EXPECT_EQ(test, global_script.result, -EINTR);
	KUNIT_EXPECT_EQ(test, global_script.reads, 0U);
	KUNIT_EXPECT_EQ(test, global_script.writes, 0U);
	KUNIT_EXPECT_EQ(test, private_thread_ret, 0);
	KUNIT_EXPECT_EQ(test, private_script.result, 0);
	KUNIT_EXPECT_EQ(test, private_script.reads, 1U);
	KUNIT_EXPECT_EQ(test, private_script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 2U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, private_root_guid,
				    RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&global_file),
			0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&private_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(caller_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_reg_open_key_uses_live_layer_table(
	struct kunit *test)
{
	static const u8 base_guid[RSI_GUID_SIZE] = { 0x35 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0x36 };
	static const u8 policy_layer_guid[RSI_GUID_SIZE] = { 0x37 };
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{
			.expected_child = "App",
			.guid = base_guid,
			.layer_name = "base",
			.second_guid = policy_guid,
			.second_layer_name = "policy",
			.include_second_entry = true,
		},
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *base_sd;
	const u8 *policy_sd;
	const u8 *layer_sd;
	size_t base_sd_len = 0;
	size_t policy_sd_len = 0;
	size_t layer_sd_len = 0;
	u64 base_sequence;
	u64 policy_sequence;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
						  &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, layer_sd, layer_sd_len,
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	base_sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
						 &base_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, base_sd);
	policy_sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
						   &policy_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, policy_sd);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	steps[0].sd = base_sd;
	steps[0].sd_len = base_sd_len;
	steps[0].sequence = base_sequence;
	steps[0].second_sd = policy_sd;
	steps[0].second_sd_len = policy_sd_len;
	steps[0].second_sequence = policy_sequence;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_source_thread, &script,
		"pkm-lcs-kunit-reg-open-live-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_open_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, policy_guid, RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	pkm_kacs_free((void *)policy_sd);
	pkm_kacs_free((void *)base_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_policy_hidden_masks_base(
	struct kunit *test)
{
	static const u8 base_guid[RSI_GUID_SIZE] = { 0x38 };
	static const u8 policy_layer_guid[RSI_GUID_SIZE] = { 0x39 };
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{
			.expected_child = "App",
			.guid = base_guid,
			.layer_name = "base",
			.second_layer_name = "policy",
			.include_second_entry = true,
			.second_hidden = true,
		},
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *base_sd;
	const u8 *layer_sd;
	size_t base_sd_len = 0;
	size_t layer_sd_len = 0;
	u64 base_sequence;
	u64 policy_sequence;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
						  &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, layer_sd, layer_sd_len,
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	base_sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
						 &base_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, base_sd);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	steps[0].sd = base_sd;
	steps[0].sd_len = base_sd_len;
	steps[0].sequence = base_sequence;
	steps[0].second_sequence = policy_sequence;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_source_thread, &script,
		"pkm-lcs-kunit-reg-open-hidden-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_open_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, fd, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_kacs_free((void *)layer_sd);
	pkm_kacs_free((void *)base_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_syscall_dispatches_relative(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_open_key_for_token(
				token, &ops, -2, (const char __user *)path_src,
				KEY_READ, 0),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_open_key_syscall_rejects_null_token(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_open_key_for_token(
				NULL, &ops, -1, (const char __user *)path_src,
				KEY_READ, 0),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}


static void pkm_lcs_kunit_create_existing_absolute_sets_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_accepts_null_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-null-disp");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0,
		NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_finish_copies_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-finish");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_finish_null_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-finish-null");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0,
		NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_finish_faults_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;
	ctx.fault_dst = &disposition;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-finish-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_existing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_copied_finish_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)path_src,
		.path_len = sizeof(path_src),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-copied");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_copied_path_finish_for_token(
		token, &ops, -1, &copy, KEY_READ,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_copied_finish_fault_closes_fd(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)path_src,
		.path_len = sizeof(path_src),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;
	ctx.fault_dst = &disposition;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-copied-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_existing_copied_path_finish_for_token(
		token, &ops, -1, &copy, KEY_READ, 0,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, 0U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_copied_rejects_bad_copy(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_syscall_path_copy bad_copy = {
		.path = (char *)path_src,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = 0xaaaaaaaaU;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_existing_copied_path_finish_for_token(
				token, &ops, -1, &bad_copy, KEY_READ, 0,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_disposition_copyout_success(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, (u32 __user *)&disposition,
				REG_CREATED_NEW),
			0L);
	KUNIT_EXPECT_EQ(test, disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
}


static void pkm_lcs_kunit_create_disposition_copyout_null_is_noop(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, NULL, REG_OPENED_EXISTING),
			0L);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_create_disposition_copyout_faults(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaa55aa55U;

	ctx.fault_dst = &disposition;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, (u32 __user *)&disposition,
				REG_CREATED_NEW),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
}


static void pkm_lcs_kunit_create_disposition_copyout_bad_ops(
	struct kunit *test)
{
	struct pkm_lcs_usercopy_ops ops = { };
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, (u32 __user *)&disposition,
				REG_CREATED_NEW),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
}


static void pkm_lcs_kunit_create_finish_success_returns_fd(struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long fd;
	long ret;

	fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		&ops, (u32 __user *)&disposition, fd, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, ret, fd);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_create_finish_success_null_disposition(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	long fd;
	long ret;

	fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		&ops, NULL, fd, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, ret, fd);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_create_finish_fault_closes_fd(struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long fd;

	fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	ctx.fault_dst = &disposition;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_finish_success_to_user(
				&ops, (u32 __user *)&disposition, fd,
				REG_CREATED_NEW),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			(long)-EBADF);
}


static void pkm_lcs_kunit_create_finish_rejects_invalid_fd(struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_finish_success_to_user(
				&ops, (u32 __user *)&disposition, -1,
				REG_CREATED_NEW),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_create_missing_created_finish_success(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long ret;

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);

	ret = pkm_lcs_create_missing_created_result_finish_to_user(
		&ops, (u32 __user *)&disposition, &result);
	KUNIT_EXPECT_TRUE(test, ret >= 0);
	KUNIT_EXPECT_EQ(test, disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot((int)ret, &snapshot),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)ret), 0);
}


static void pkm_lcs_kunit_create_missing_created_finish_null_disposition(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	long ret;

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);

	ret = pkm_lcs_create_missing_created_result_finish_to_user(
		&ops, NULL, &result);
	KUNIT_EXPECT_TRUE(test, ret >= 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)ret), 0);
}


static void pkm_lcs_kunit_create_missing_created_finish_fault_closes_fd(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long fd;

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	fd = result.fd;
	ctx.fault_dst = &disposition;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			(long)-EBADF);
}


static void pkm_lcs_kunit_create_missing_created_finish_rejects_retry(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.fd = -1,
		.disposition = REG_OPENED_EXISTING,
		.retry_open_existing = true,
	};
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_create_missing_created_finish_rejects_malformed(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.fd = -1,
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	result.disposition = REG_OPENED_EXISTING;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)result.fd), 0);
}


static void pkm_lcs_kunit_create_missing_retry_open_success(struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, "App"),
			0L);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-retry-open");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_READ, NULL, 0, NULL, 0, NULL, 0,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	if (fd >= 0) {
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
				0L);
		KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
		KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
		KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
		KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
		KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
		KUNIT_EXPECT_EQ(test,
				memcmp(snapshot.key_guid, app_guid,
				       sizeof(snapshot.key_guid)),
				0);
		KUNIT_EXPECT_EQ(test,
				memcmp(snapshot.last_ancestor_guid, app_guid,
				       sizeof(snapshot.last_ancestor_guid)),
				0);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_retry_open_retains_limits(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = { 0xb2 };
	enum { LONG_NAME_LEN = 300 };
	char child_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = child_name, .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	memset(child_name, 'R', LONG_NAME_LEN);
	child_name[LONG_NAME_LEN] = '\0';
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, child_name),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_runtime_limits_defaults(&resolution.limits),
			0L);
	resolution.limits.max_path_component_length = LONG_NAME_LEN;
	resolution.limits_present = true;

	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_source_thread, &script,
		"pkm-lcs-kunit-create-retry-retains-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_READ, NULL, 0, NULL, 0, NULL, 0,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	if (fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_retry_open_fault_closes(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = { 0xb1 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0xaa55aa55U;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, "App"),
			0L);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	ctx.fault_dst = &disposition;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-retry-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_READ, NULL, 0, NULL, 0, NULL, 0,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_retry_open_denied_no_copyout(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = { 0xc1 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0xaa55aa55U;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, "App"),
			0L);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-retry-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_SET_VALUE, NULL, 0, NULL, 0,
		NULL, 0, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_retry_open_bad_resolution(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.parent.component_count = 1,
		.child_name = "App",
		.child_name_len = 3,
		.child_depth = 2,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaa55aa55U;

	memcpy(resolution.parent.key_guid, root_guid, RSI_GUID_SIZE);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_retry_open_existing_for_token(
				NULL, &ops, &resolution, KEY_READ, NULL, 0,
				NULL, 0, NULL, 0,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);
}


static void pkm_lcs_kunit_create_existing_rejects_flags_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = REG_OPENED_EXISTING;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_existing_user_path_for_token(
				token, &ops, -1, (const char __user *)path_src,
				KEY_READ, 0x04U, &disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_existing_dispatches_relative_parent(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = REG_OPENED_EXISTING;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_existing_user_path_for_token(
				token, &ops, -2, (const char __user *)path_src,
				KEY_READ, 0, &disposition),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_root_denied_publishes_no_fd(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src,
		KEY_QUERY_VALUE | KEY_SET_VALUE, 0, NULL, 0, NULL, 0, NULL,
		0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_root_malformed_sd_fails_closed(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
		.sd = bad_sd,
		.sd_len = sizeof(bad_sd),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root-bad-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_root_symlink_open_link(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
		.symlink = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root-link-self");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ,
		REG_OPEN_LINK, NULL, 0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Machine");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, root_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_root_symlink_follows_target(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
		0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script root_read = {
		.expected_guid = root_guid,
		.name = "Machine",
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
		  .read_key = &root_read },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = root_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	target_step.sd = sd;
	target_step.sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-root-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_symlink_target_hive_root(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 users_root_guid[RSI_GUID_SIZE] = { 2 };
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
		0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
	};
	static const u8 target_path[] = "Users";
	const char machine_name[] = "Machine";
	const char users_name[] = "Users";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hives[2] = { };
	struct reg_src_register_args args = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_read_key_source_script users_read = {
		.expected_guid = users_root_guid,
		.name = "Users",
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
		  .read_key = &users_read },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	hives[0].name_len = strlen(machine_name);
	hives[0].name_ptr = (u64)(unsigned long)machine_name;
	memcpy(hives[0].root_guid, machine_root_guid, RSI_GUID_SIZE);
	hives[1].name_len = strlen(users_name);
	hives[1].name_ptr = (u64)(unsigned long)users_name;
	memcpy(hives[1].root_guid, users_root_guid, RSI_GUID_SIZE);
	args.hive_count = ARRAY_SIZE(hives);
	args.hives_ptr = (u64)(unsigned long)hives;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	users_read.sd = sd;
	users_read.sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-link-root-target");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Users");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Users");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, users_root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, users_root_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_denied_publishes_no_fd(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src,
		KEY_QUERY_VALUE | KEY_SET_VALUE, 0, NULL, 0, layers,
		ARRAY_SIZE(layers), NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_malformed_sd_fails_closed(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid,
		  .sd = bad_sd, .sd_len = sizeof(bad_sd) },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-bad-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, layers, ARRAY_SIZE(layers), NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_absolute_preflight_stops_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_for_token(
				token, &ops, (const char __user *)path_src, 0,
				0, NULL, 0, NULL, 0, NULL, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_composes_success(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const u8 leaf_guid[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	const char * const parent_path[] = { "Machine", "Software" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App/Leaf";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[2] = {
		{ .expected_child = "App", .guid = app_guid },
		{ .expected_child = "Leaf", .guid = leaf_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[1].sd = sd;
	steps[1].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], software_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, software_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, layers, ARRAY_SIZE(layers), NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 4U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Leaf");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, leaf_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, snapshot.first_ancestor_guid[0], 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, leaf_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_uses_implicit_base_layer(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
		0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
		0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
	};
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-base");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_final_symlink_open_link(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
		0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
		0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
	};
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "Link", .guid = link_guid,
		  .symlink = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, REG_OPEN_LINK, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Link");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, link_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, link_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_final_symlink_follows_target(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
		0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
		0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec,
		0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_symlink_follow_source_script script = {
		.link_step = {
			.expected_child = "Link",
			.guid = link_guid,
			.symlink = true,
		},
		.target_step = {
			.expected_child = "Target",
			.guid = target_guid,
		},
		.target_data = target_path,
		.target_data_len = sizeof(target_path) - 1,
		.target_value_type = REG_LINK,
		.expect_target_lookup = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.target_step.sd = sd;
	script.target_step.sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_follow_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-link-follow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_symlink_target_hive_root(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 users_root_guid[RSI_GUID_SIZE] = { 2 };
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	static const u8 target_path[] = "Users";
	const char machine_name[] = "Machine";
	const char users_name[] = "Users";
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hives[2] = { };
	struct reg_src_register_args args = { };
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_read_key_source_script users_read = {
		.expected_guid = users_root_guid,
		.name = "Users",
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
		  .read_key = &users_read },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	hives[0].name_len = strlen(machine_name);
	hives[0].name_ptr = (u64)(unsigned long)machine_name;
	memcpy(hives[0].root_guid, machine_root_guid, RSI_GUID_SIZE);
	hives[1].name_len = strlen(users_name);
	hives[1].name_ptr = (u64)(unsigned long)users_name;
	memcpy(hives[1].root_guid, users_root_guid, RSI_GUID_SIZE);
	args.hive_count = ARRAY_SIZE(hives);
	args.hives_ptr = (u64)(unsigned long)hives;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	users_read.sd = sd;
	users_read.sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-rel-link-root-target");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Users");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Users");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, users_root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, users_root_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_intermediate_symlink_follows_suffix(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
		0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
		0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
	};
	static const u8 leaf_guid[RSI_GUID_SIZE] = {
		0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
		0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link\\Leaf";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_walk_source_step leaf_step = {
		.expected_child = "Leaf",
		.guid = leaf_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &leaf_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	leaf_step.sd = sd;
	leaf_step.sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-rel-link-mid");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Leaf");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, leaf_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, leaf_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_denied_publishes_no_fd(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
		0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
	};
	const char * const parent_path[] = { "Machine", "Software" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], software_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, software_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_QUERY_VALUE | KEY_SET_VALUE, 0, layers,
		ARRAY_SIZE(layers), NULL, 0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_preflight_stops_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_for_token(
				token, &ops, -1, (const char __user *)path_src,
				0, 0, NULL, 0, NULL, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_relative_orphan_parent_fails_closed(
	struct kunit *test)
{
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
		0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x01,
	};
	const char * const parent_path[] = { "Machine", "Software" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	const void *token;
	long parent_fd;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	memcpy(parent_ancestors[1], software_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, software_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)parent_fd,
							  true),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_for_token(
				token, &ops, (int)parent_fd,
				(const char __user *)path_src, KEY_READ, 0,
				NULL, 0, NULL, 0),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_relative_open_runtime_max_key_depth(
	struct kunit *test)
{
	static const char path_src[] = "Child";
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_key_depth = 32U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	fd = pkm_lcs_kunit_publish_key_fd_with_depth(32U);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)path_src,
				KEY_READ, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.parent.parent_depth, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_create_missing_runtime_max_key_depth(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	u32 child_depth = 0;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_key_depth = 32U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_create_missing_child_depth(32U,
								 &child_depth),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, child_depth, 0U);

	limits.max_key_depth = 33U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_create_missing_child_depth(32U,
								 &child_depth),
			0L);
	KUNIT_EXPECT_EQ(test, child_depth, 33U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_relative_open_preflight_success(struct kunit *test)
{
	const char path_src[] = "Child/Sub";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)path_src,
				KEY_QUERY_VALUE, REG_OPEN_LINK, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.access.requested_access,
			KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, result.access.mapped_desired_access,
			KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, result.access.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 2U);
	KUNIT_EXPECT_TRUE(test, result.path.used_forward_separator);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 11U);
	KUNIT_EXPECT_EQ(test, result.parent.parent_depth, 2U);
	KUNIT_EXPECT_FALSE(test, result.parent.orphaned);
	KUNIT_EXPECT_EQ(test, result.parent.key_guid[0], 0x52U);
	KUNIT_EXPECT_EQ(test, result.parent.root_guid[0], 0x51U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_relative_open_preflight_stops_bad_scalars(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = {
		.access = {
			.requested_access = 0xffffffffU,
			.path_resolution_allowed = 1,
		},
		.path = {
			.component_count = 99,
			.used_forward_separator = true,
		},
		.parent = {
			.source_id = 88,
		},
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src, 0, 0,
				&result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.access.requested_access, 0U);
	KUNIT_EXPECT_EQ(test, result.access.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 0U);
	KUNIT_EXPECT_FALSE(test, result.path.used_forward_separator);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}


static void
pkm_lcs_kunit_relative_open_preflight_validates_path_before_parent(
	struct kunit *test)
{
	const char path_src[] = "Child\\";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.access.requested_access,
			KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 0U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}


static void pkm_lcs_kunit_relative_open_preflight_rejects_bad_parent_fd(
	struct kunit *test)
{
	const char path_src[] = "Child\\Sub";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	int fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 2U);
	KUNIT_EXPECT_FALSE(test, result.path.used_forward_separator);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	memset(&result, 0, sizeof(result));
	fd = anon_inode_getfd("lcs-not-key", &pkm_lcs_kunit_non_key_fops,
			      NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, fd, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_relative_open_preflight_rejects_orphan_parent(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 1U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_relative_open_preflight_checks_combined_depth(
	struct kunit *test)
{
	const char exact_path[] = "Child";
	const char over_path[] = "Child\\Sub";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_depth(511);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)exact_path,
				KEY_QUERY_VALUE, 0, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.parent.parent_depth, 511U);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 1U);

	memset(&result, 0, sizeof(result));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)over_path,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 2U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_create_missing_absolute_resolves_parent_only(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Software", .guid = software_guid },
	};
	const char path_src[] = "Machine\\Software\\NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-parent");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_absolute_parent_for_token(
		token, &ops, (const char __user *)path_src, NULL, 0,
		layers, ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_STREQ(test, result.child_name, "NewKey");
	KUNIT_EXPECT_EQ(test, result.child_name_len, 6U);
	KUNIT_EXPECT_EQ(test, result.child_depth, 3U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 1U);
	KUNIT_EXPECT_EQ(test, result.parent.component_count, 2U);
	KUNIT_EXPECT_STREQ(test, result.parent.resolved_path[0], "Machine");
	KUNIT_EXPECT_STREQ(test, result.parent.resolved_path[1], "Software");
	KUNIT_EXPECT_EQ(test,
			memcmp(result.parent.ancestor_guids[0], root_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.parent.key_guid, software_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_GT(test, result.parent.final_sd_len, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_absolute_missing_parent_enoent(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Missing", .empty = true },
	};
	const char path_src[] = "Machine\\Missing\\NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-missing-parent");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_absolute_parent_for_token(
		token, &ops, (const char __user *)path_src, NULL, 0,
		layers, ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_PTR_EQ(test, result.child_name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.final_frame.data, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_absolute_root_path_rejected(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_absolute_parent_for_token(
				token, &ops, (const char __user *)path_src,
				NULL, 0, NULL, 0, NULL, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.child_name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.resolved_path, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_relative_direct_parent_reads_sd(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x52 };
	const char path_src[] = "NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = parent_guid,
		.name = "Software",
		.parent_guid = root_guid,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_for_source(
		1, root_guid, parent_guid,
		KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-parent-read");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_relative_parent(
		&ops, (int)fd, (const char __user *)path_src, NULL, 0,
		NULL, 0, NULL, 0, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_STREQ(test, result.child_name, "NewKey");
	KUNIT_EXPECT_EQ(test, result.child_depth, 3U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 1U);
	KUNIT_EXPECT_EQ(test, result.parent.component_count, 2U);
	KUNIT_EXPECT_STREQ(test, result.parent.resolved_path[1], "Software");
	KUNIT_EXPECT_EQ(test,
			memcmp(result.parent.key_guid, parent_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_GT(test, result.parent.final_sd_len, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_relative_checks_child_depth(
	struct kunit *test)
{
	const char path_src[] = "NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_depth(512);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_relative_parent(
				&ops, (int)fd, (const char __user *)path_src,
				NULL, 0, NULL, 0, NULL, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.child_name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.resolved_path, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_create_missing_parent_access_allows_create_subkey(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_SUB_KEY, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_CREATE_SUB_KEY);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_parent_access_denies_without_right(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_parent_access_malformed_sd_eio(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_CREATE_SUB_KEY,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	result.parent.final_frame.data = kmalloc(4U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, result.parent.final_frame.data);
	memset(result.parent.final_frame.data, 0, 4U);
	result.parent.final_frame.len = 4U;
	result.parent.final_sd_offset = 3U;
	result.parent.final_sd_len = 4U;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_parent_access_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_SUB_KEY, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				NULL, &result, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, NULL, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, NULL),
			(long)-EINVAL);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_volatile_parent_rejects_nonvolatile(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	result.parent.final_volatile = true;
	KUNIT_ASSERT_EQ(test, pkm_lcs_create_preflight(KEY_READ, 0, &plan),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_create_missing_volatile_parent_allows_volatile(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	result.parent.final_volatile = true;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_create_preflight(KEY_READ, REG_OPTION_VOLATILE,
						 &plan),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			0L);
}


static void pkm_lcs_kunit_create_missing_volatile_parent_allows_nonvolatile_parent(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_create_preflight(KEY_READ, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			0L);

	memset(&plan, 0, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_create_preflight(KEY_READ, REG_OPTION_VOLATILE,
						 &plan),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			0L);
}


static void pkm_lcs_kunit_create_missing_volatile_parent_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_create_preflight(KEY_READ, 0, &plan),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(NULL,
								     &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_create_initial_sd_inherits_registry_mapping(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
		test, &result, pkm_lcs_kunit_parent_sd_ci_generic_read,
		sizeof(pkm_lcs_kunit_parent_sd_ci_generic_read));

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, &result, &created),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	KUNIT_EXPECT_GT(test, created.sd_len, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_sd_bytes(created.sd, created.sd_len),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, created.sd, created.sd_len, KEY_READ,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_READ);

	pkm_lcs_created_key_sd_destroy(&created);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);
	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_initial_sd_malformed_parent_eio(
	struct kunit *test)
{
	static const u8 bad_sd[] = { 0x00, 0x01, 0x02, 0x03 };
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_created_key_sd created = {
		.sd = (const u8 *)1UL,
		.sd_len = 7,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
		test, &result, bad_sd, sizeof(bad_sd));

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, &result, &created),
			(long)-EIO);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_initial_sd_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
		test, &result, pkm_lcs_kunit_parent_sd_ci_generic_read,
		sizeof(pkm_lcs_kunit_parent_sd_ci_generic_read));

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, &result, NULL),
			(long)-EINVAL);
	created.sd = (const u8 *)1UL;
	created.sd_len = 7;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				NULL, &result, &created),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);
	created.sd = (const u8 *)1UL;
	created.sd_len = 7;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, NULL, &created),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_explicit_folded_match(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "Policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_layer_metadata_sd_view metadata[2] = {
		{ .name = "other", .name_len = 5 },
		{ .name = "policy", .name_len = 6 },
	};
	const void *token;
	const u8 *other_sd;
	const u8 *policy_sd;
	size_t other_sd_len = 0;
	size_t policy_sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	other_sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE,
						  0, 0, 0, &other_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, other_sd);
	policy_sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE,
						   0, 0, 0, &policy_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, policy_sd);
	metadata[0].sd = other_sd;
	metadata[0].sd_len = other_sd_len;
	metadata[1].sd = policy_sd;
	metadata[1].sd_len = policy_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, metadata,
				ARRAY_SIZE(metadata), &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)policy_sd);
	pkm_kacs_free((void *)other_sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_uses_runtime_limits(
	struct kunit *test)
{
	char long_name[301];
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_metadata_sd_view metadata = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_runtime_limits limits = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	memset(long_name, 'p', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	target.name = long_name;
	target.name_len = sizeof(long_name) - 1;
	metadata.name = long_name;
	metadata.name_len = sizeof(long_name) - 1;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	metadata.sd = sd;
	metadata.sd_len = sd_len;

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token_with_limits(
				token, &target, false, NULL, 0, &metadata, 1,
				&limits, &plan),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	limits.max_path_component_length = target.name_len;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token_with_limits(
				token, &target, false, NULL, 0, &metadata, 1,
				&limits, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_explicit_denied(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_layer_metadata_sd_view metadata = {
		.name = "policy",
		.name_len = 6,
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	metadata.sd = sd;
	metadata.sd_len = sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, &metadata, 1,
				&plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_missing_metadata_eio(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	struct pkm_lcs_layer_metadata_sd_view metadata = {
		.name = "other",
		.name_len = 5,
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	metadata.sd = sd;
	metadata.sd_len = sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, &metadata, 1,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_malformed_metadata_eio(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_layer_metadata_sd_view missing_sd = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_layer_metadata_sd_view duplicate[2] = {
		{ .name = "Policy", .name_len = 6 },
		{ .name = "policy", .name_len = 6 },
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	duplicate[0].sd = sd;
	duplicate[0].sd_len = sd_len;
	duplicate[1].sd = sd;
	duplicate[1].sd_len = sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, &missing_sd, 1,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, duplicate,
				ARRAY_SIZE(duplicate), &plan),
			(long)-EIO);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_implicit_base_delegates(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = 4,
		.implicit_base = 1,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_explicit_base_delegates(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = 4,
		.implicit_base = 0,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	/*
	 * An explicitly-named "base" layer (implicit_base = 0) must be
	 * authorized through the base-layer path, identically to an omitted
	 * layer -- routing it through the metadata-SD lookup would fail EIO
	 * because the hardcoded base layer has no metadata-table row.
	 */
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_layer_write_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_create_layer_target bad_target = { };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, NULL, false, NULL, 0, NULL, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &bad_target, false, NULL, 0, NULL, 0,
				&plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 1,
				&plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0, NULL),
			(long)-EINVAL);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_symlink_authority_non_link_noop(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan link_plan = {
		.allowed = 1,
		.fd_granted_access = KEY_CREATE_LINK,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				NULL, NULL, REG_OPTION_VOLATILE, &link_plan),
			0L);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, 0U);
}


static void pkm_lcs_kunit_create_symlink_authority_tcb_marks_used(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_LINK, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_EXPECT_EQ(test, before.privileges_used & KACS_SE_TCB_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			0L);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, KEY_CREATE_LINK);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			KACS_SE_TCB_PRIVILEGE);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_symlink_authority_admin_without_tcb(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_has_enabled_administrators(token));
	KUNIT_ASSERT_FALSE(test,
			   kacs_rust_token_has_enabled_privilege(
				   token, KACS_SE_TCB_PRIVILEGE));
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_LINK, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			0L);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, KEY_CREATE_LINK);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_symlink_authority_denies_missing_link_right(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_SUB_KEY, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, 0U);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			0ULL);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_symlink_authority_denies_missing_identity(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_FALSE(test,
			   kacs_rust_token_has_enabled_administrators(token));
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_LINK, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, KEY_CREATE_LINK);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_symlink_authority_unknown_flags_einval(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = {
		.allowed = 1,
		.fd_granted_access = KEY_CREATE_LINK,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK | 0x80U,
				&link_plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_source_status_policy(struct kunit *test)
{
	struct pkm_lcs_reg_create_source_response_plan plan = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_OK, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action,
			PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	memset(&plan, 0xff, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_ALREADY_EXISTS, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action,
			PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING);
	KUNIT_EXPECT_EQ(test, plan.disposition, REG_OPENED_EXISTING);

	memset(&plan, 0xff, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_KEY, RSI_OK, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action,
			PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, plan.disposition, REG_CREATED_NEW);
}


static void pkm_lcs_kunit_reg_create_source_status_fails_closed(
	struct kunit *test)
{
	struct pkm_lcs_reg_create_source_response_plan plan = {
		.action = 99,
		.disposition = 88,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_KEY, RSI_ALREADY_EXISTS, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	plan.action = 99;
	plan.disposition = 88;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_NOT_FOUND, &plan),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	plan.action = 99;
	plan.disposition = 88;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, 0xffffffffU, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	plan.action = 99;
	plan.disposition = 88;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_LOOKUP, RSI_OK, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_OK, NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_create_missing_source_records_created_new(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80, 0x30, 0x00 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Created",
		.child_name_len = strlen("Created"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "Created",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
		.volatile_key = true,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-create-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, true, false,
		&result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_source_records_runtime_limits(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x9a };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x9b };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	enum { LONG_NAME_LEN = 300 };
	char child_name[LONG_NAME_LEN + 1];
	char layer_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = child_name,
		.child_name_len = LONG_NAME_LEN,
		.limits_present = true,
	};
	struct pkm_lcs_create_layer_target target = {
		.name = layer_name,
		.name_len = LONG_NAME_LEN,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = child_name,
		.layer_name = layer_name,
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memset(child_name, 'C', LONG_NAME_LEN);
	child_name[LONG_NAME_LEN] = '\0';
	memset(layer_name, 'L', LONG_NAME_LEN);
	layer_name[LONG_NAME_LEN] = '\0';
	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_runtime_limits_defaults(&resolution.limits),
			0L);
	resolution.limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread,
					 &script,
					 "pkm-lcs-kunit-create-src-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, false, false,
		&result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_source_entry_race_retries(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x41 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x42 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Race",
		.child_name_len = strlen("Race"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "Race",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_ALREADY_EXISTS,
		.expect_key_request = false,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-create-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, false, false,
		&result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_TRUE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_source_key_duplicate_eio(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x51 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x52 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Duplicate",
		.child_name_len = strlen("Duplicate"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = {
		.sequence = 99,
		.disposition = 88,
		.created_new = true,
		.retry_open_existing = true,
	};
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "Duplicate",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_ALREADY_EXISTS,
		.expect_key_request = true,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-create-dup");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, false, false,
		&result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, 0U);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_source_bad_inputs(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x61 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Bad",
		.child_name_len = strlen("Bad"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = {
		.sequence = 99,
		.disposition = 88,
		.created_new = true,
		.retry_open_existing = true,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_source_records(
				NULL, &target, child_guid, &created_sd, false,
				false, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, result.disposition, 0U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_source_records(
				&resolution, &target, child_guid, &created_sd,
				false, false, NULL),
			(long)-EINVAL);

	result.sequence = 99;
	result.disposition = 88;
	result.created_new = true;
	result.retry_open_existing = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_source_records(
				&resolution, &target, child_guid, &created_sd,
				false, false, &result),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, result.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, result.disposition, 0U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
}


static void pkm_lcs_kunit_create_missing_publish_created_success(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x33 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;
	long fd;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	fd = pkm_lcs_create_missing_publish_created_key_for_token(
		token, &resolution, child_guid, &created, KEY_READ);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_guid,
			       sizeof(snapshot.key_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, child_guid,
			       sizeof(snapshot.last_ancestor_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_publish_created_retains_limits(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x34 };
	enum { LONG_NAME_LEN = 300 };
	char child_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;
	long fd;

	memset(child_name, 'C', LONG_NAME_LEN);
	child_name[LONG_NAME_LEN] = '\0';
	pkm_lcs_runtime_limits_reset_defaults();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	kfree(resolution.child_name);
	resolution.child_name = kstrdup(child_name, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, resolution.child_name);
	resolution.child_name_len = LONG_NAME_LEN;
	resolution.child_depth = resolution.parent.component_count + 1U;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_runtime_limits_defaults(&resolution.limits),
			0L);
	resolution.limits.max_path_component_length = LONG_NAME_LEN;
	resolution.limits_present = true;

	fd = pkm_lcs_create_missing_publish_created_key_for_token(
		token, &resolution, child_guid, &created, KEY_READ);
	KUNIT_EXPECT_TRUE(test, fd >= 0);
	if (fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_publish_created_denied(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x44 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_QUERY_VALUE, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, &created,
				KEY_SET_VALUE),
			(long)-EACCES);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_publish_created_malformed_sd(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x55 };
	static const u8 bad_sd[] = { 0x00, 0x01, 0x02, 0x03 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = {
		.sd = bad_sd,
		.sd_len = sizeof(bad_sd),
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, &created,
				KEY_READ),
			(long)-EIO);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_publish_created_bad_inputs(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x66 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				NULL, &resolution, child_guid, &created,
				KEY_READ),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, NULL, child_guid, &created, KEY_READ),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, NULL, &created, KEY_READ),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, NULL, KEY_READ),
			(long)-EINVAL);
	resolution.child_depth = 4;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, &created,
				KEY_READ),
			(long)-EINVAL);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_prepared_created_new_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x77 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	script.sd = created.sd;
	script.sd_len = created.sd_len;
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-create");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created, KEY_READ,
		false, false, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)result.fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_guid,
			       sizeof(snapshot.key_guid)),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)result.fd), 0);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_prepared_gen_overflow(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x7a };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
	};
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_set(
				1, root_guid, U64_MAX),
			0L);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	script.sd = created.sd;
	script.sd_len = created.sd_len;
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-create-gen-overflow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created, KEY_READ,
		false, false, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_prepared_layer_refreshes(
	struct kunit *test)
{
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0xa8, 0x13 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xa8, 0x14 };
	static const char * const watch_path[] = { "Machine", "Software" };
	static const u8 watch_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa8, 0x15 },
	};
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_create_layer_refresh_source_script script = {
		.create = {
			.parent_guid = layers_guid,
			.child_guid = policy_guid,
			.child_name = "Policy",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
			.expect_key_request = true,
		},
		.refresh = {
			.expected_guid = policy_guid,
			.name = "Policy",
			.precedence_present = false,
			.enabled_present = false,
		},
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	u8 event[16] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *expected_owner_sid = NULL;
	u8 *owner_sid = NULL;
	size_t expected_owner_sid_len = 0;
	size_t owner_sid_len = 0;
	u32 count = 0;
	bool owner_present = false;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long ret;
	long watch_fd;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	script.create.sd = created.sd;
	script.create.sd_len = created.sd_len;
	script.refresh.sd = created.sd;
	script.refresh.sd_len = created.sd_len;
	script.file = &file;
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, watch_path, watch_ancestors,
		ARRAY_SIZE(watch_ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, watch_ancestors[0], &generation_before),
			0L);
	pkm_lcs_kunit_create_missing_set_layer_metadata_child_path(test,
								  &resolution);
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_create_layer_refresh_source_thread, &script,
		"pkm-lcs-kunit-create-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, policy_guid, &created, KEY_READ,
		false, false, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_EQ(test, script.refresh.result, 0);
	KUNIT_EXPECT_EQ(test, script.refresh.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.refresh.writes, 4U);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)result.fd, &snapshot), 0L);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Policy");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, policy_guid,
			       sizeof(snapshot.key_guid)),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 0U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_user_sid(token, &expected_owner_sid,
						 &expected_owner_sid_len),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_owner_snapshot(
				"Policy", strlen("Policy"), &owner_sid,
				&owner_sid_len, &owner_present),
			0L);
	KUNIT_ASSERT_TRUE(test, owner_present);
	KUNIT_ASSERT_EQ(test, owner_sid_len, expected_owner_sid_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(owner_sid, expected_owner_sid, owner_sid_len),
			0);
	kfree(owner_sid);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, watch_ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)result.fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_prepared_entry_race_retries(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x78 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_ALREADY_EXISTS,
		.expect_key_request = false,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created, KEY_READ,
		false, false, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_TRUE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_prepared_denies_after_source(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x79 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_QUERY_VALUE, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	script.sd = created.sd;
	script.sd_len = created.sd_len;
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created,
		KEY_SET_VALUE, false, false, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_prepared_bad_inputs(struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = {
		.fd = 123,
		.sequence = 99,
		.disposition = 88,
		.created_new = true,
		.retry_open_existing = true,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_prepared_key_for_token(
				token, &resolution, &target, child_guid, &created,
				KEY_READ, false, false, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_prepared_key_for_token(
				token, NULL, &target, child_guid, &created,
				KEY_READ, false, false, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_EXPECT_EQ(test, result.sequence, 0ULL);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_branch_created_new_success(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x91 } };
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_read_then_create_source_script script = {
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
			.expect_key_request = true,
			.allow_any_sd = true,
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_then_create_source_thread,
			   &script, "pkm-lcs-kunit-create-full");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_candidates[0],
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_branch_volatile_parent_denies(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\Blocked";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
		.volatile_key = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *parent_sd;
	size_t parent_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	parent_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_CREATE_SUB_KEY, 0, 0, 0, &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);

	script.file = &file;
	script.sd = parent_sd;
	script.sd_len = parent_sd_len;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-vol");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, NULL, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_kacs_free((void *)parent_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_branch_rejects_bad_snapshots(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_create_missing_runtime_inputs bad_inputs = {
		.scope_count = 1,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_user_path_finish_for_token(
				NULL, &ops, -1, (const char __user *)path_src,
				KEY_READ, NULL, 0, &bad_inputs,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_create_missing_copied_path_success(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x92 } };
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)path_src,
		.path_len = sizeof(path_src),
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_read_then_create_source_script script = {
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
			.expect_key_request = true,
			.allow_any_sd = true,
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_then_create_source_thread,
			   &script, "pkm-lcs-kunit-create-copy-full");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_copied_path_finish_for_token(
		token, &ops, -1, &copy, KEY_READ, NULL, 0, &inputs,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_candidates[0],
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_create_missing_copied_path_rejects_bad_copy(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_syscall_path_copy bad_copy = {
		.path = (char *)path_src,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = 0xaaaaaaaaU;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_copied_path_finish_for_token(
				token, &ops, -1, &bad_copy, KEY_READ, NULL,
				0, NULL, (u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_existing_ignores_layer(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	const char layer_src[] = "should-not-be-read";
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = layer_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-reg-create-existing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		(const char __user *)layer_src,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_existing_uses_live_layer_table(
	struct kunit *test)
{
	static const u8 base_guid[RSI_GUID_SIZE] = { 0x41 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0x42 };
	static const u8 policy_layer_guid[RSI_GUID_SIZE] = { 0x43 };
	const char path_src[] = "Machine\\App";
	const char layer_src[] = "should-not-be-read";
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = layer_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{
			.expected_child = "App",
			.guid = base_guid,
			.layer_name = "base",
			.second_guid = policy_guid,
			.second_layer_name = "policy",
			.include_second_entry = true,
		},
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *base_sd;
	const u8 *policy_sd;
	const u8 *layer_sd;
	size_t base_sd_len = 0;
	size_t policy_sd_len = 0;
	size_t layer_sd_len = 0;
	u64 base_sequence;
	u64 policy_sequence;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
						  &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, layer_sd, layer_sd_len,
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	base_sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
						 &base_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, base_sd);
	policy_sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
						   &policy_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, policy_sd);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	steps[0].sd = base_sd;
	steps[0].sd_len = base_sd_len;
	steps[0].sequence = base_sequence;
	steps[0].second_sd = policy_sd;
	steps[0].second_sd_len = policy_sd_len;
	steps[0].second_sequence = policy_sequence;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_source_thread, &script,
		"pkm-lcs-kunit-create-existing-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		(const char __user *)layer_src, 0, NULL,
		(u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, policy_guid, RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)policy_sd);
	pkm_kacs_free((void *)base_sd);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_missing_fallback_success(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x93 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_walk_then_read_create_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.create = {
			.read_key = {
				.expected_guid = root_guid,
				.name = "Machine",
			},
			.create = {
				.parent_guid = root_guid,
				.child_guid = child_candidates[0],
				.child_name = "App",
				.layer_name = "base",
				.expected_sequence = 1,
				.entry_status = RSI_OK,
				.key_status = RSI_OK,
				.expect_key_request = true,
				.allow_any_sd = true,
			},
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.create.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.create.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_then_read_create_source_thread,
			   &script, "pkm-lcs-kunit-reg-create-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_key_duplicate_eio(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\Duplicate";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x99 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "Duplicate",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_walk_then_read_create_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.create = {
			.read_key = {
				.expected_guid = root_guid,
				.name = "Machine",
			},
			.create = {
				.parent_guid = root_guid,
				.child_guid = child_candidates[0],
				.child_name = "Duplicate",
				.layer_name = "base",
				.expected_sequence = 1,
				.entry_status = RSI_OK,
				.key_status = RSI_ALREADY_EXISTS,
				.expect_key_request = true,
				.allow_any_sd = true,
			},
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.create.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.create.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_read_create_source_thread,
		&script, "pkm-lcs-kunit-reg-create-key-dup");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_entry_race_retries_open(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\Race";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x9a } };
	static const u8 existing_guid[RSI_GUID_SIZE] = { 0x9b };
	static const struct pkm_lcs_kunit_walk_source_step missing_steps[] = {
		{
			.expected_child = "Race",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_walk_source_step retry_steps[] = {
		{
			.expected_child = "Race",
			.guid = existing_guid,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = missing_steps,
			.step_count = ARRAY_SIZE(missing_steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "Race",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_ALREADY_EXISTS,
			.expect_key_request = false,
			.allow_any_sd = true,
		},
		.retry_walk = {
			.steps = retry_steps,
			.step_count = ARRAY_SIZE(retry_steps),
		},
		.expect_create = true,
		.expect_retry_walk = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	const u8 *existing_sd;
	size_t layer_sd_len = 0;
	size_t existing_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	existing_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &existing_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, existing_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	retry_steps[0].sd = existing_sd;
	retry_steps[0].sd_len = existing_sd_len;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_txn_create_flow_source_thread,
		&script, "pkm-lcs-kunit-create-entry-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, existing_guid,
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)existing_sd);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_missing_uses_live_layer_table(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const char layer_src[] = "policy";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 policy_layer_guid[RSI_GUID_SIZE] = { 0x39 };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_walk_then_read_create_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.create = {
			.read_key = {
				.expected_guid = root_guid,
				.name = "Machine",
			},
			.create = {
				.parent_guid = root_guid,
				.child_name = "App",
				.layer_name = layer_src,
				.expected_sequence = 1,
				.entry_status = RSI_OK,
				.key_status = RSI_OK,
				.expect_key_request = true,
				.allow_any_sd = true,
				.allow_any_child_guid = true,
			},
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.layer_ptr = (u64)(unsigned long)layer_src,
		.txn_fd = -1,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	args.disposition_ptr = (u64)(unsigned long)&disposition;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				layer_src, strlen(layer_src), 10, 1,
				policy_layer_guid, layer_sd, layer_sd_len,
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	script.file = &file;
	script.create.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.create.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_read_create_source_thread,
		&script, "pkm-lcs-kunit-create-live-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid,
			       script.create.create.captured_child_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_missing_uses_live_base_metadata(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 base_metadata_guid[RSI_GUID_SIZE] = { 0x43, 0x6b };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_walk_then_read_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	const void *service_token;
	const u8 *base_sd;
	const u8 *parent_sd;
	size_t base_sd_len = 0;
	size_t parent_sd_len = 0;
	u32 disposition = 0xccccccccU;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	service_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, 0);
	KUNIT_ASSERT_NOT_NULL(test, service_token);
	base_sd = kacs_rust_kunit_create_file_sd(service_token,
						 KEY_QUERY_VALUE, 0, 0, 0,
						 &base_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, base_sd);
	parent_sd = kacs_rust_kunit_create_file_sd(
		admin_token, KEY_CREATE_SUB_KEY | KEY_READ, 0, 0, 0,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_base_layer_metadata_publish(
				base_metadata_guid, base_sd, base_sd_len),
			0L);

	script.file = &file;
	script.read_key.sd = parent_sd;
	script.read_key.sd_len = parent_sd_len;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_read_source_thread, &script,
		"pkm-lcs-kunit-create-live-base");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_reg_create_key_for_token(
		admin_token, &ops, -1, (const char __user *)path_src,
		KEY_READ, NULL, 0, NULL, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, disposition, 0xccccccccU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)base_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(service_token);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_reg_create_key_missing_dispatches_watch(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\Parent\\App";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 root_ancestors[1][PKM_LCS_GUID_BYTES] = { { 1 } };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x61 },
	};
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x96 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "Parent",
			.guid = parent_ancestors[1],
			.sd = pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read,
			.sd_len =
				sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read),
		},
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const struct pkm_lcs_kunit_walk_source_step parent_steps[] = {
		{
			.expected_child = "Parent",
			.guid = parent_ancestors[1],
			.sd = pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read,
			.sd_len =
				sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read),
		},
	};
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_walk_then_read_create_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.parent_walk = {
			.steps = parent_steps,
			.step_count = ARRAY_SIZE(parent_steps),
		},
		.create = {
			.skip_read_key = true,
			.create = {
				.parent_guid = parent_ancestors[1],
				.child_guid = child_candidates[0],
				.child_name = "App",
				.layer_name = "base",
				.expected_sequence = 1,
				.entry_status = RSI_OK,
				.key_status = RSI_OK,
				.expect_key_request = true,
				.allow_any_sd = true,
			},
		},
		.wait_for_stop_after_completion = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u8 direct[32] = { };
	u8 subtree[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long root_fd;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_then_read_create_source_thread,
			   &script, "pkm-lcs-kunit-create-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)11);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 11U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 3U);
	KUNIT_EXPECT_EQ(test, memcmp(direct + 8, "App", 3), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)21);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 21U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 3U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 8, "App", 3), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 11), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 13), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 15, "Parent", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_bad_flags_before_usercopy(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_for_token(
				NULL, &ops, -1, (const char __user *)path_src,
				KEY_READ, NULL, 0x80000000U, NULL,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_reg_create_key_args_copy_success_and_fault(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_create_key_args src = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
	};
	struct reg_create_key_args dst = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, (const void __user *)&src, &dst),
			0L);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, dst.parent_fd, -1);
	KUNIT_EXPECT_EQ(test, dst.path_ptr, src.path_ptr);
	KUNIT_EXPECT_EQ(test, dst.desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, dst.txn_fd, -1);

	ctx.fault_src = &src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, (const void __user *)&src, &dst),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, NULL, &dst),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);
}


static void pkm_lcs_kunit_reg_create_key_args_copy_fault_zeroes_output(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_create_key_args src = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
	};
	struct reg_create_key_args dst = {
		.parent_fd = 123,
		._pad0 = 0xffffffffU,
		.path_ptr = 0xffffffffffffffffULL,
		.desired_access = 0xffffffffU,
		.layer_ptr = 0xffffffffffffffffULL,
		.flags = 0xffffffffU,
		.txn_fd = 123,
		._pad1 = 0xffffffffU,
		.disposition_ptr = 0xffffffffffffffffULL,
	};

	ctx.fault_src = &src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, (const void __user *)&src, &dst),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, dst.parent_fd, 0);
	KUNIT_EXPECT_EQ(test, dst._pad0, 0U);
	KUNIT_EXPECT_EQ(test, dst.path_ptr, 0ULL);
	KUNIT_EXPECT_EQ(test, dst.desired_access, 0U);
	KUNIT_EXPECT_EQ(test, dst.layer_ptr, 0ULL);
	KUNIT_EXPECT_EQ(test, dst.flags, 0U);
	KUNIT_EXPECT_EQ(test, dst.txn_fd, 0);
	KUNIT_EXPECT_EQ(test, dst._pad1, 0U);
	KUNIT_EXPECT_EQ(test, dst.disposition_ptr, 0ULL);
}


static void pkm_lcs_kunit_reg_create_key_args_rejects_padding(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		._pad0 = 1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(NULL, &ops, &args,
							      NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	args._pad0 = 0;
	args._pad1 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(NULL, &ops, &args,
							      NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_reg_create_key_args_existing_txn_reads(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const char path_src[] = "Machine";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	args.txn_fd = (int)txn_fd;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-txn-unbound");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_guid = root_guid;
	script.name = "Machine";
	script.sd = sd;
	script.sd_len = sd_len;
	script.expected_txn_id = txn_snapshot.transaction_id;
	disposition = 0;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-txn-bound");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_existing_txn_symlink_reads(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
	};
	static const char path_src[] = "Machine\\Link";
	static const u8 target_path[] = "Machine\\Target";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	target_step.sd = sd;
	target_step.sd_len = sd_len;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	args.txn_fd = (int)txn_fd;
	for (i = 0; i < ARRAY_SIZE(sequence); i++)
		sequence[i].expected_txn_id = txn_snapshot.transaction_id;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-create-txn-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_txn_failures(
	struct kunit *test)
{
	static const u8 other_root_guid[RSI_GUID_SIZE] = { 2 };
	static const char path_src[] = "Machine";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct file file = { };
	const void *token;
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	int not_txn_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				other_root_guid),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)txn_fd, REG_TXN_COMMITTED, 0),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);

	not_txn_fd = anon_inode_getfd("lcs-not-create-txn",
				     &pkm_lcs_kunit_non_key_fops, NULL,
				     O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_txn_fd >= 0);
	args.txn_fd = not_txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_txn_fd), 0);

	args.txn_fd = INT_MAX;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EBADF);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_txn_missing_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x94 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_header_txn_id = 0,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
			.expect_key_request = true,
			.allow_any_sd = true,
		},
		.expect_begin = true,
		.expect_create = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.create.expected_txn_id = txn_snapshot.transaction_id;
	args.txn_fd = (int)txn_fd;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_txn_create_flow_source_thread, &script,
			   "pkm-lcs-kunit-create-txn-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						   &inputs);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 1ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "App");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, key_snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, key_snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(key_snapshot.key_guid, child_candidates[0],
			       sizeof(key_snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_txn_missing_full_log(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x95 } };
	static const u8 warmup_guid[RSI_GUID_SIZE] = { 0x96 };
	static const char * const parent_path[] = { "Machine" };
	static const u8 parent_ancestors[1][RSI_GUID_SIZE] = { { 1 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input log_input = {
		.parent_guid = root_guid,
		.target_guid = warmup_guid,
		.child_name = "Warmup",
		.child_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 1,
		.sequence = 77,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_log_capacity(
				(int)txn_fd, 1),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)txn_fd, 1, root_guid, &log_input,
				&handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	script.walk.expected_txn_id = txn_snapshot.transaction_id;
	script.read_key.expected_txn_id = txn_snapshot.transaction_id;
	args.txn_fd = (int)txn_fd;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_txn_create_flow_source_thread,
			   &script, "pkm-lcs-kunit-create-txn-full-log");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						    &inputs);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-ENOMEM);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 77ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_txn_missing_entry_race(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x97 } };
	static const u8 existing_guid[RSI_GUID_SIZE] = { 0x98 };
	static const struct pkm_lcs_kunit_walk_source_step missing_steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_walk_source_step retry_steps[] = {
		{
			.expected_child = "App",
			.guid = existing_guid,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = missing_steps,
			.step_count = ARRAY_SIZE(missing_steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_header_txn_id = 0,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_ALREADY_EXISTS,
			.expect_key_request = false,
			.allow_any_sd = true,
		},
		.retry_walk = {
			.steps = retry_steps,
			.step_count = ARRAY_SIZE(retry_steps),
		},
		.expect_begin = true,
		.expect_create = true,
		.expect_retry_walk = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	const u8 *existing_sd;
	size_t layer_sd_len = 0;
	size_t existing_sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	existing_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &existing_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, existing_sd);
	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	retry_steps[0].sd = existing_sd;
	retry_steps[0].sd_len = existing_sd_len;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.create.expected_txn_id = txn_snapshot.transaction_id;
	script.retry_walk.expected_txn_id = txn_snapshot.transaction_id;
	args.txn_fd = (int)txn_fd;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_txn_create_flow_source_thread,
			   &script, "pkm-lcs-kunit-create-txn-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						   &inputs);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, key_snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test,
			memcmp(key_snapshot.key_guid, existing_guid,
			       sizeof(key_snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)existing_sd);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_bad_flags_before_txn(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.flags = 0x80000000U,
		.txn_fd = 0,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(NULL, &ops, &args,
							      NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}


static void pkm_lcs_kunit_reg_create_key_args_existing_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	const char layer_src[] = "ignored-for-existing";
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = layer_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.flags = REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
		.layer_ptr = (u64)(unsigned long)layer_src,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-reg-create-args");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_missing_entry_race(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\ArgsRace";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x9c } };
	static const u8 existing_guid[RSI_GUID_SIZE] = { 0x9d };
	static const struct pkm_lcs_kunit_walk_source_step missing_steps[] = {
		{
			.expected_child = "ArgsRace",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_walk_source_step retry_steps[] = {
		{
			.expected_child = "ArgsRace",
			.guid = existing_guid,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = missing_steps,
			.step_count = ARRAY_SIZE(missing_steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "ArgsRace",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_ALREADY_EXISTS,
			.expect_key_request = false,
			.allow_any_sd = true,
		},
		.retry_walk = {
			.steps = retry_steps,
			.step_count = ARRAY_SIZE(retry_steps),
		},
		.expect_create = true,
		.expect_retry_walk = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	const u8 *existing_sd;
	size_t layer_sd_len = 0;
	size_t existing_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	existing_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &existing_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, existing_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	retry_steps[0].sd = existing_sd;
	retry_steps[0].sd_len = existing_sd_len;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_txn_create_flow_source_thread,
		&script, "pkm-lcs-kunit-create-args-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						   &inputs);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, existing_guid,
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)existing_sd);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_reg_create_key_args_key_duplicate_eio(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\ArgsDuplicate";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x9e } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "ArgsDuplicate",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_walk_then_read_create_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.create = {
			.read_key = {
				.expected_guid = root_guid,
				.name = "Machine",
			},
			.create = {
				.parent_guid = root_guid,
				.child_guid = child_candidates[0],
				.child_name = "ArgsDuplicate",
				.layer_name = "base",
				.expected_sequence = 1,
				.entry_status = RSI_OK,
				.key_status = RSI_ALREADY_EXISTS,
				.expect_key_request = true,
				.allow_any_sd = true,
			},
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.create.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.create.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_read_create_source_thread,
		&script, "pkm-lcs-kunit-create-args-dup");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						    &inputs);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_lookup_response_bridge_accepts_valid_and_empty(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 801,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 801, 21, NULL, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.path_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.metadata_count, 1U);
	KUNIT_EXPECT_FALSE(test, summary.child_absent);

	memset(&summary, 0xaa, sizeof(summary));
	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 802,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     0);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     0);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 802, 21, NULL, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.path_entry_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.metadata_count, 0U);
	KUNIT_EXPECT_TRUE(test, summary.child_absent);
}


static void pkm_lcs_kunit_lookup_response_bridge_maps_source_errors(
	struct kunit *test)
{
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[RSI_MIN_RESPONSE_SIZE];
	size_t frame_len;

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 811,
					    RSI_LOOKUP, RSI_NOT_FOUND,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 811, 1, NULL, &summary),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, summary.path_entry_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.metadata_count, 0U);

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 812,
					    RSI_LOOKUP, RSI_STORAGE_ERROR,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 812, 1, NULL, &summary),
			(long)-EIO);
}


static void pkm_lcs_kunit_lookup_response_bridge_rejects_common_mismatches(
	struct kunit *test)
{
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[RSI_MIN_RESPONSE_SIZE];
	size_t frame_len;

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 821,
					    RSI_LOOKUP, RSI_NOT_FOUND,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 822, 1, NULL, &summary),
			(long)-EINVAL);

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 823,
					    RSI_QUERY_VALUES, RSI_NOT_FOUND,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 823, 1, NULL, &summary),
			(long)-EINVAL);

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 824,
					    RSI_LOOKUP, RSI_NOT_FOUND,
					    &frame_len);
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE + 1U,
			   frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 824, 1, NULL, &summary),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_lookup_response_bridge_rejects_malformed_data(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 831,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     0);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 831, 21, NULL, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 832,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 21);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 832, 21, NULL, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 833,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "bad/layer",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 833, 21, NULL, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 834,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid, bad_sd,
		sizeof(bad_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 834, 21, NULL, &summary),
			(long)-EIO);
}


static void pkm_lcs_kunit_lookup_materializes_visible_child(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	struct pkm_lcs_rsi_lookup_child_result result = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 901,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 0);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata_ex(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd), 1, 1, 4242);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_lookup_child(
				frame, frame_len, 901, 1, "Child",
				strlen("Child"), layers, ARRAY_SIZE(layers),
				NULL, 0, NULL, &result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_path_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(result.key_guid, guid, RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, result.selected_precedence, 0U);
	KUNIT_EXPECT_EQ(test, result.selected_sequence, 0ULL);
	KUNIT_EXPECT_TRUE(test, result.volatile_key);
	KUNIT_EXPECT_TRUE(test, result.symlink);
	KUNIT_EXPECT_EQ(test, result.last_write_time, 4242ULL);
	KUNIT_EXPECT_EQ(test, result.sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_ASSERT_LE(test,
			(size_t)result.sd_offset +
				(size_t)result.sd_len,
			frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + result.sd_offset,
			       pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);
}


static void pkm_lcs_kunit_lookup_materializes_hidden_as_not_found(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	struct pkm_lcs_rsi_lookup_child_result result = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 902,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "overlay",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_lookup_child(
				frame, frame_len, 902, 3, "Child",
				strlen("Child"), layers, ARRAY_SIZE(layers),
				NULL, 0, NULL, &result),
			0L);
	KUNIT_EXPECT_FALSE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_path_entry_count, 2U);
	KUNIT_EXPECT_EQ(test, result.sd_len, 0U);
}


static void pkm_lcs_kunit_lookup_materialize_rejects_duplicate_tie(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "layerA", .name_len = 6, .precedence = 10,
		  .enabled = 1 },
		{ .name = "layerB", .name_len = 6, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 guid_a[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	static const u8 guid_b[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	struct pkm_lcs_rsi_lookup_child_result result = { };
	u8 frame[384];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 903,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "layerA",
		RSI_PATH_TARGET_GUID, guid_a, 5);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "layerB",
		RSI_PATH_TARGET_GUID, guid_b, 5);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid_a,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid_b,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_lookup_child(
				frame, frame_len, 903, 6, "Child",
				strlen("Child"), layers, ARRAY_SIZE(layers),
				NULL, 0, NULL, &result),
			(long)-EIO);
	KUNIT_EXPECT_FALSE(test, result.found);
}


static void pkm_lcs_kunit_open_component_walk_collects_ancestors(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "Software", .name_len = 8 },
		{ .name = "App", .name_len = 3 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Software", .guid = software_guid },
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_resolved_key_path result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-walk");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_walk_absolute_components(
		1, 0, root_guid, components, ARRAY_SIZE(components), layers,
		ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, result.source_id, 1U);
	KUNIT_EXPECT_EQ(test, result.component_count, 3U);
	KUNIT_EXPECT_STREQ(test, result.resolved_path[0], "Machine");
	KUNIT_EXPECT_STREQ(test, result.resolved_path[1], "Software");
	KUNIT_EXPECT_STREQ(test, result.resolved_path[2], "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(result.ancestor_guids[0], root_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.ancestor_guids[1], software_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.ancestor_guids[2], app_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test, memcmp(result.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, result.final_sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_ASSERT_NOT_NULL(test, result.final_frame.data);
	KUNIT_ASSERT_LE(test,
			(size_t)result.final_sd_offset +
				(size_t)result.final_sd_len,
			result.final_frame.len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.final_frame.data + result.final_sd_offset,
			       pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);
	KUNIT_EXPECT_FALSE(test, result.final_symlink);
	KUNIT_EXPECT_FALSE(test, result.final_volatile);
	KUNIT_EXPECT_EQ(test, result.final_last_write_time, 1001ULL);

	pkm_lcs_resolved_key_path_destroy(&result);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_component_walk_empty_child_enoent(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "Missing", .name_len = 7 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Missing", .empty = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_resolved_key_path result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-walk-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_walk_absolute_components(
		1, 0, root_guid, components, ARRAY_SIZE(components), layers,
		ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_PTR_EQ(test, result.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.ancestor_guids, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.final_frame.data, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_open_component_walk_rejects_bad_private_layers(
	struct kunit *test)
{
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "App", .name_len = 3 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	struct pkm_lcs_resolved_key_path result = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_walk_absolute_components(
				1, 0, root_guid, components,
				ARRAY_SIZE(components), NULL, 0, NULL, 1,
				&result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.ancestor_guids, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.final_frame.data, NULL);
}


static void pkm_lcs_kunit_open_component_walk_symlink_fails_closed(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "Link", .name_len = 4 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Link", .guid = link_guid,
		  .symlink = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_resolved_key_path result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-walk-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_walk_absolute_components(
		1, 0, root_guid, components, ARRAY_SIZE(components), layers,
		ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_PTR_EQ(test, result.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.ancestor_guids, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.final_frame.data, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_open_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_absolute_path_route_uses_first_component_and_errno),
	KUNIT_CASE(pkm_lcs_kunit_absolute_path_route_uses_dynamic_hives),
	KUNIT_CASE(pkm_lcs_kunit_absolute_path_current_user_rewrite_routes_users),
	KUNIT_CASE(pkm_lcs_kunit_absolute_path_current_user_uses_token_sid),
	KUNIT_CASE(pkm_lcs_kunit_syscall_path_copy_bounds_and_faults),
	KUNIT_CASE(pkm_lcs_kunit_syscall_path_copy_fault_zeroes_output),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_accepts_valid_masks),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_rejects_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_create_preflight_accepts_valid_flags),
	KUNIT_CASE(pkm_lcs_kunit_create_preflight_rejects_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_null_uses_base),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_explicit_layer_admitted),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_absent_returns_enoent),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_bad_name_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_copy_faults_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_copy_zeroes_stale_state),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_success),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_stops_before_usercopy),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_copy_fault_keeps_route_empty),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_absolute_success),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_normalizes_forward_slashes),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_rewrites_current_user),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_rejects_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_composes_success),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_uses_implicit_base_layer),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_final_symlink_open_link),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_final_symlink_follows_target),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_final_symlink_bad_target_einval),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_intermediate_symlink_follows_suffix),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_recursive_symlink_follows_target),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_symlink_depth_limit_eloop),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_runtime_symlink_depth_limit_eloop),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_uses_read_key),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_syscall_dispatches_absolute),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_uses_dynamic_hive),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_uses_empty_private_credential_view),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_uses_kacs_private_scope),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_uses_live_layer_table),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_policy_hidden_masks_base),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_syscall_dispatches_relative),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_syscall_rejects_null_token),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_absolute_sets_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_accepts_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_finish_copies_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_finish_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_finish_faults_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_copied_finish_success),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_copied_finish_fault_closes_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_copied_rejects_bad_copy),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_success),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_null_is_noop),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_faults),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_bad_ops),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_success_returns_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_success_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_fault_closes_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_rejects_invalid_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_fault_closes_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_rejects_retry),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_rejects_malformed),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_retains_limits),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_fault_closes),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_denied_no_copyout),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_bad_resolution),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_rejects_flags_before_usercopy),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_dispatches_relative_parent),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_denied_publishes_no_fd),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_malformed_sd_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_symlink_open_link),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_symlink_follows_target),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_symlink_target_hive_root),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_denied_publishes_no_fd),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_malformed_sd_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_preflight_stops_before_usercopy),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_composes_success),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_uses_implicit_base_layer),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_final_symlink_open_link),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_final_symlink_follows_target),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_symlink_target_hive_root),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_intermediate_symlink_follows_suffix),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_denied_publishes_no_fd),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_preflight_stops_before_usercopy),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_orphan_parent_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_runtime_max_key_depth),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_runtime_max_key_depth),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_success),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_stops_bad_scalars),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_validates_path_before_parent),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_rejects_bad_parent_fd),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_rejects_orphan_parent),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_checks_combined_depth),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_absolute_resolves_parent_only),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_absolute_missing_parent_enoent),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_absolute_root_path_rejected),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_relative_direct_parent_reads_sd),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_relative_checks_child_depth),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_parent_access_allows_create_subkey),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_parent_access_denies_without_right),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_parent_access_malformed_sd_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_parent_access_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_volatile_parent_rejects_nonvolatile),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_volatile_parent_allows_volatile),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_volatile_parent_allows_nonvolatile_parent),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_volatile_parent_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_initial_sd_inherits_registry_mapping),
	KUNIT_CASE(pkm_lcs_kunit_create_initial_sd_malformed_parent_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_initial_sd_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_explicit_folded_match),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_explicit_denied),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_missing_metadata_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_malformed_metadata_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_implicit_base_delegates),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_explicit_base_delegates),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_non_link_noop),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_tcb_marks_used),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_admin_without_tcb),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_denies_missing_link_right),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_denies_missing_identity),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_unknown_flags_einval),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_source_status_policy),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_source_status_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_source_records_created_new),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_source_records_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_source_entry_race_retries),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_source_key_duplicate_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_source_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_publish_created_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_publish_created_retains_limits),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_publish_created_denied),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_publish_created_malformed_sd),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_publish_created_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_created_new_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_gen_overflow),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_layer_refreshes),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_entry_race_retries),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_denies_after_source),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_branch_created_new_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_branch_volatile_parent_denies),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_branch_rejects_bad_snapshots),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_copied_path_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_copied_path_rejects_bad_copy),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_existing_ignores_layer),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_existing_uses_live_layer_table),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_missing_fallback_success),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_key_duplicate_eio),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_entry_race_retries_open),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_missing_uses_live_layer_table),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_missing_uses_live_base_metadata),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_missing_dispatches_watch),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_bad_flags_before_usercopy),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_copy_success_and_fault),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_copy_fault_zeroes_output),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_rejects_padding),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_existing_txn_reads),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_existing_txn_symlink_reads),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_txn_failures),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_txn_missing_success),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_txn_missing_full_log),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_txn_missing_entry_race),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_bad_flags_before_txn),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_existing_success),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_missing_entry_race),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_key_duplicate_eio),
	KUNIT_CASE(pkm_lcs_kunit_lookup_response_bridge_accepts_valid_and_empty),
	KUNIT_CASE(pkm_lcs_kunit_lookup_response_bridge_maps_source_errors),
	KUNIT_CASE(pkm_lcs_kunit_lookup_response_bridge_rejects_common_mismatches),
	KUNIT_CASE(pkm_lcs_kunit_lookup_response_bridge_rejects_malformed_data),
	KUNIT_CASE(pkm_lcs_kunit_lookup_materializes_visible_child),
	KUNIT_CASE(pkm_lcs_kunit_lookup_materializes_hidden_as_not_found),
	KUNIT_CASE(pkm_lcs_kunit_lookup_materialize_rejects_duplicate_tie),
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_collects_ancestors),
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_empty_child_enoent),
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_rejects_bad_private_layers),
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_symlink_fails_closed),
	{}
};

static struct kunit_suite pkm_lcs_kunit_open_suite = {
	.name = "pkm_lcs_kunit_open",
	.test_cases = pkm_lcs_kunit_open_cases,
};

kunit_test_suite(pkm_lcs_kunit_open_suite);
