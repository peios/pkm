// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_rust_probe_links_lcs_core(struct kunit *test)
{
	KUNIT_ASSERT_GT(test, lcs_rust_kunit_probe(), (size_t)0);
}


static void pkm_lcs_kunit_private_hive_route_uses_scope_order_live(
	struct kunit *test)
{
	static const char name_a[] = "Machine";
	static const char name_b[] = "machine";
	const u8 scope_ab[2][16] = { { 0x42 }, { 0x43 } };
	const u8 scope_ba[2][16] = { { 0x43 }, { 0x42 } };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hives[2] = {
		{
			.name_len = sizeof(name_a) - 1,
			.name_ptr = (u64)(unsigned long)name_a,
			.root_guid = { 2 },
			.flags = RSI_HIVE_PRIVATE,
			.scope_guid = { 0x42 },
		},
		{
			.name_len = sizeof(name_b) - 1,
			.name_ptr = (u64)(unsigned long)name_b,
			.root_guid = { 3 },
			.flags = RSI_HIVE_PRIVATE,
			.scope_guid = { 0x43 },
		},
	};
	struct reg_src_register_args args = {
		.hive_count = ARRAY_SIZE(hives),
		.hives_ptr = (u64)(unsigned long)hives,
	};
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_a, strlen(name_a),
						scope_ba, ARRAY_SIZE(scope_ba),
						&route),
			0L);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 3U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_a, strlen(name_a),
						scope_ab, ARRAY_SIZE(scope_ab),
						&route),
			0L);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 4U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_self_watch_arm_targeted_and_fallback(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0xa2 };
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0xa3 };
	static const u8 replacement_root_guid[RSI_GUID_SIZE] = { 0xa4 };
	struct pkm_lcs_internal_self_watch_arm_result result = { };
	struct pkm_lcs_internal_self_watch_snapshot snapshot = { };

	pkm_lcs_internal_self_watch_disarm();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				7, machine_root_guid, true, registry_guid, true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				&result),
			0L);
	KUNIT_EXPECT_EQ(test, result.source_id, 7U);
	KUNIT_EXPECT_EQ(test, result.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_TARGETED);
	KUNIT_EXPECT_EQ(test, result.watch_count, 3U);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.registry_guid, registry_guid,
			       sizeof(registry_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.layers_guid, layers_guid,
			       sizeof(layers_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.kmes_guid,
			       pkm_lcs_kunit_kmes_watch_guid,
			       sizeof(pkm_lcs_kunit_kmes_watch_guid)),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				7, machine_root_guid, true, registry_guid, true,
				layers_guid, false, NULL, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.source_id, 7U);
	KUNIT_EXPECT_EQ(test, result.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_MIXED);
	KUNIT_EXPECT_EQ(test, result.watch_count, 3U);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.registry_guid, registry_guid,
			       sizeof(registry_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.layers_guid, layers_guid,
			       sizeof(layers_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.fallback_guid, machine_root_guid,
			       sizeof(machine_root_guid)),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				8, replacement_root_guid, false, NULL,
				false, NULL, false, NULL, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.source_id, 8U);
	KUNIT_EXPECT_EQ(test, result.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_MACHINE_ROOT_FALLBACK);
	KUNIT_EXPECT_EQ(test, result.watch_count, 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.fallback_guid, replacement_root_guid,
			       sizeof(replacement_root_guid)),
			0);
	KUNIT_EXPECT_FALSE(test,
			   memchr_inv(result.registry_guid, 0,
				      sizeof(result.registry_guid)));
	KUNIT_EXPECT_FALSE(test,
			   memchr_inv(result.layers_guid, 0,
				      sizeof(result.layers_guid)));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(&snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 8U);
	KUNIT_EXPECT_EQ(test, snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_MACHINE_ROOT_FALLBACK);
	KUNIT_EXPECT_EQ(test, snapshot.watch_count, 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.fallback_guid, replacement_root_guid,
			       sizeof(replacement_root_guid)),
			0);
	pkm_lcs_internal_self_watch_disarm();
}


static void pkm_lcs_kunit_internal_self_watch_bad_inputs_fail_closed(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0xb1 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0xb2 };
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0xb3 };
	static const u8 nil_guid[RSI_GUID_SIZE] = { 0 };
	struct pkm_lcs_internal_self_watch_snapshot snapshot = { };

	pkm_lcs_internal_self_watch_disarm();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				9, machine_root_guid, true, registry_guid, true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				0, machine_root_guid, true, registry_guid, true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				9, nil_guid, true, registry_guid, true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				9, machine_root_guid, true, nil_guid, true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				9, machine_root_guid, true, registry_guid, true,
				nil_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				9, machine_root_guid, true, registry_guid, true,
				layers_guid, true, nil_guid, NULL),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(&snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 9U);
	KUNIT_EXPECT_EQ(test, snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_TARGETED);
	KUNIT_EXPECT_EQ(test, snapshot.watch_count, 3U);
	pkm_lcs_internal_self_watch_disarm();
}


static void pkm_lcs_kunit_internal_self_watch_value_event_refreshes_config(
	struct kunit *test)
{
	static const char * const registry_path[] = {
		"Machine", "System", "Registry",
	};
	static const u8 ancestors[3][RSI_GUID_SIZE] = {
		{ 0xc1 }, { 0xc2 }, { 0xc3 },
	};
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0xc4 };
	static const char value_name[] = "RequestTimeoutMs";
	u8 data[sizeof(u32)];
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[2],
		.ancestor_guids = ancestors,
		.resolved_path = registry_path,
		.path_component_count = ARRAY_SIZE(registry_path),
		.event_type = REG_WATCH_VALUE_SET,
		.name = (const u8 *)value_name,
		.name_len = sizeof(value_name) - 1U,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[2],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_DWORD,
		.query_all = true,
	};
	struct pkm_lcs_runtime_limits snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	put_unaligned_le32(1000U, data);
	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-watch-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 1000U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_kmes_watch_value_event_refreshes_config(
	struct kunit *test)
{
	static const char * const kmes_path[] = {
		"Machine", "System", "KMES",
	};
	static const u8 ancestors[3][RSI_GUID_SIZE] = {
		{ 0xca }, { 0xcb }, { 0xcc },
	};
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0xcd };
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0xce };
	static const char value_name[] = "MaxNestingDepth";
	u8 data[sizeof(u32)];
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[2],
		.ancestor_guids = ancestors,
		.resolved_path = kmes_path,
		.path_component_count = ARRAY_SIZE(kmes_path),
		.event_type = REG_WATCH_VALUE_SET,
		.name = (const u8 *)value_name,
		.name_len = sizeof(value_name) - 1U,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[2],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_DWORD,
		.query_all = true,
	};
	struct pkm_kmes_runtime_config snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	put_unaligned_le32(64U, data);
	pkm_kmes_kunit_reset_all();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, registry_guid, true,
				layers_guid, true, ancestors[2], NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-kmes-watch-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_runtime_config_snapshot(&snapshot), 0);
	KUNIT_EXPECT_EQ(test, snapshot.max_nesting_depth, 64U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_kmes_kunit_reset_all();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_self_watch_non_value_event_noop(
	struct kunit *test)
{
	static const char * const registry_path[] = {
		"Machine", "System", "Registry",
	};
	static const u8 ancestors[3][RSI_GUID_SIZE] = {
		{ 0xd1 }, { 0xd2 }, { 0xd3 },
	};
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0xd4 };
	static const char value_name[] = "RequestTimeoutMs";
	u8 data[sizeof(u32)];
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[2],
		.ancestor_guids = ancestors,
		.resolved_path = registry_path,
		.path_component_count = ARRAY_SIZE(registry_path),
		.event_type = REG_WATCH_SD_CHANGED,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[2],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_DWORD,
		.query_all = true,
	};
	struct pkm_lcs_runtime_limits snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	put_unaligned_le32(1000U, data);
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				layers_guid, true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-watch-noop");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, -EINTR);
	KUNIT_EXPECT_EQ(test, script.reads, 0U);
	KUNIT_EXPECT_EQ(test, script.writes, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_self_watch_fallback_create_rearms_targeted(
	struct kunit *test)
{
	static const char * const machine_path[] = { "Machine" };
	static const u8 ancestors[1][RSI_GUID_SIZE] = { { 1 } };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0xd5 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0xd6 };
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0xd7 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xd8 };
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0xd9 };
	static const char subkey_name[] = "System";
	static const char value_name[] = "RequestTimeoutMs";
	static const char kmes_value_name[] = "MaxNestingDepth";
	static const struct pkm_lcs_kunit_walk_source_step self_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
	};
	static const struct pkm_lcs_kunit_walk_source_step kmes_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "KMES", .guid = kmes_guid },
	};
	static const struct pkm_lcs_kunit_walk_source_step layer_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
		{ .expected_child = "Layers", .guid = layers_root_guid },
	};
	u8 data[sizeof(u32)];
	u8 kmes_data[sizeof(u32)];
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[0],
		.ancestor_guids = ancestors,
		.resolved_path = machine_path,
		.path_component_count = ARRAY_SIZE(machine_path),
		.event_type = REG_WATCH_SUBKEY_CREATED,
		.name = (const u8 *)subkey_name,
		.name_len = sizeof(subkey_name) - 1U,
	};
	struct pkm_lcs_kunit_source_bootstrap_source_script script = {
		.self_config_walk = {
			.steps = self_steps,
			.step_count = ARRAY_SIZE(self_steps),
		},
		.self_config_query = {
			.expected_guid = registry_guid,
			.expected_value_name = "",
			.response_value_name = value_name,
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.kmes_walk = {
			.steps = kmes_steps,
			.step_count = ARRAY_SIZE(kmes_steps),
		},
		.kmes_query = {
			.expected_guid = kmes_guid,
			.expected_value_name = "",
			.response_value_name = kmes_value_name,
			.layer_name = "base",
			.data = kmes_data,
			.data_len = sizeof(kmes_data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.layers_walk = {
			.steps = layer_steps,
			.step_count = ARRAY_SIZE(layer_steps),
		},
		.layers_refresh = {
			.enum_children = {
				.expected_parent_guid = layers_root_guid,
				.child_name = "Policy",
				.layer_name = "base",
				.child_guid = policy_guid,
			},
			.refresh = {
				.expected_guid = policy_guid,
				.name = "Policy",
				.sd = pkm_lcs_kunit_owner_only_sd,
				.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
				.precedence = 5,
				.enabled = 1,
				.precedence_present = true,
				.enabled_present = true,
			},
			.expect_refresh = true,
		},
		.expect_kmes_query = true,
		.expect_layers_refresh = true,
	};
	struct pkm_lcs_internal_self_watch_snapshot watch_snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_kmes_runtime_config kmes_snapshot = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	put_unaligned_le32(1000U, data);
	put_unaligned_le32(128U, kmes_data);
	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], false, NULL, false, NULL,
				false, NULL, NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_source_bootstrap_source_thread, &script,
		"pkm-lcs-kunit-fallback-rearm");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 14U);
	KUNIT_EXPECT_EQ(test, script.writes, 14U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(
				&watch_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, watch_snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, watch_snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_TARGETED);
	KUNIT_EXPECT_EQ(test, watch_snapshot.watch_count, 3U);
	KUNIT_EXPECT_EQ(test,
			memcmp(watch_snapshot.registry_guid, registry_guid,
			       sizeof(registry_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(watch_snapshot.layers_guid, layers_root_guid,
			       sizeof(layers_root_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(watch_snapshot.kmes_guid, kmes_guid,
			       sizeof(kmes_guid)),
			0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&limits), 0L);
	KUNIT_EXPECT_EQ(test, limits.request_timeout_ms, 1000U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_runtime_config_snapshot(&kmes_snapshot), 0);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.max_nesting_depth, 128U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 5U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_self_watch_fallback_non_create_noop(
	struct kunit *test)
{
	static const char * const machine_path[] = { "Machine" };
	static const u8 ancestors[1][RSI_GUID_SIZE] = { { 1 } };
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[0],
		.ancestor_guids = ancestors,
		.resolved_path = machine_path,
		.path_component_count = ARRAY_SIZE(machine_path),
		.event_type = REG_WATCH_SD_CHANGED,
	};
	struct pkm_lcs_source_fd_snapshot fd_snapshot = { };
	struct pkm_lcs_internal_self_watch_snapshot watch_snapshot = { };
	struct file file = { };
	const void *token;

	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], false, NULL, false, NULL,
				false, NULL, NULL),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	pkm_lcs_kunit_source_fd_snapshot(&file, &fd_snapshot);
	KUNIT_EXPECT_EQ(test, fd_snapshot.queued_request_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(
				&watch_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, watch_snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_MACHINE_ROOT_FALLBACK);
	KUNIT_EXPECT_EQ(test, watch_snapshot.watch_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_internal_layer_watch_value_event_refreshes_metadata(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 ancestors[5][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe4, 0x10 }, { 0xe4, 0x11 },
		{ 0xe4, 0x12 }, { 0xe4 },
	};
	static const char value_name[] = "Enabled";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[4],
		.ancestor_guids = ancestors,
		.resolved_path = metadata_path,
		.path_component_count = ARRAY_SIZE(metadata_path),
		.event_type = REG_WATCH_VALUE_SET,
		.name = (const u8 *)value_name,
		.name_len = sizeof(value_name) - 1U,
	};
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = ancestors[4],
		.name = "Policy",
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 11,
		.enabled = 1,
		.precedence_present = true,
		.enabled_present = true,
	};
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-watch-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 11U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_layer_watch_lifecycle_event_noop(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 ancestors[5][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe5, 0x10 }, { 0xe5, 0x11 },
		{ 0xe5, 0x12 }, { 0xe5 },
	};
	static const char value_name[] = "Child";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[4],
		.ancestor_guids = ancestors,
		.resolved_path = metadata_path,
		.path_component_count = ARRAY_SIZE(metadata_path),
		.event_type = REG_WATCH_SUBKEY_CREATED,
		.name = (const u8 *)value_name,
		.name_len = sizeof(value_name) - 1U,
	};
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = ancestors[4],
		.name = "Policy",
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 11,
		.enabled = 1,
		.precedence_present = true,
		.enabled_present = true,
	};
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	char names[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-watch-noop");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, -EINTR);
	KUNIT_EXPECT_EQ(test, script.reads, 0U);
	KUNIT_EXPECT_EQ(test, script.writes, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_layer_watch_descendant_event_noop(
	struct kunit *test)
{
	static const char * const descendant_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy", "Child"
	};
	static const u8 ancestors[6][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe5, 0x20 }, { 0xe5, 0x21 },
		{ 0xe5, 0x22 }, { 0xe5, 0x23 }, { 0xe5, 0x24 },
	};
	static const char value_name[] = "Enabled";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[5],
		.ancestor_guids = ancestors,
		.resolved_path = descendant_path,
		.path_component_count = ARRAY_SIZE(descendant_path),
		.event_type = REG_WATCH_VALUE_SET,
		.name = (const u8 *)value_name,
		.name_len = sizeof(value_name) - 1U,
	};
	struct pkm_lcs_source_fd_snapshot fd_snapshot = { };
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	char names[32] = { };
	struct file file = { };
	const void *token;
	u32 count = 0;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	pkm_lcs_kunit_source_fd_snapshot(&file, &fd_snapshot);
	KUNIT_EXPECT_EQ(test, fd_snapshot.queued_request_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_internal_layer_watch_create_event_refreshes_metadata(
	struct kunit *test)
{
	static const char * const layers_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 ancestors[4][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe6, 0x10 }, { 0xe6, 0x11 }, { 0xe6, 0x12 },
	};
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xe6, 0x13 };
	static const char layer_name[] = "Policy";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[3],
		.ancestor_guids = ancestors,
		.resolved_path = layers_path,
		.path_component_count = ARRAY_SIZE(layers_path),
		.event_type = REG_WATCH_SUBKEY_CREATED,
		.name = (const u8 *)layer_name,
		.name_len = sizeof(layer_name) - 1U,
	};
	struct pkm_lcs_kunit_walk_source_step lookup_step = {
		.expected_child = layer_name,
		.guid = policy_guid,
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.sequence = 0,
	};
	struct pkm_lcs_kunit_layer_create_watch_source_script script = {
		.lookup = {
			.steps = &lookup_step,
			.step_count = 1,
		},
		.refresh = {
			.expected_guid = policy_guid,
			.name = layer_name,
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.precedence = 17,
			.enabled = 1,
			.precedence_present = true,
			.enabled_present = true,
		},
		.expect_refresh = true,
	};
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.lookup.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_create_watch_source_thread, &script,
		"pkm-lcs-kunit-layer-watch-create");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.lookup.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.lookup.writes, 1U);
	KUNIT_EXPECT_EQ(test, script.refresh.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.refresh.writes, 4U);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 17U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_internal_layer_watch_create_missing_child_noop(
	struct kunit *test)
{
	static const char * const layers_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 ancestors[4][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe7, 0x10 }, { 0xe7, 0x11 }, { 0xe7, 0x12 },
	};
	static const char layer_name[] = "Policy";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[3],
		.ancestor_guids = ancestors,
		.resolved_path = layers_path,
		.path_component_count = ARRAY_SIZE(layers_path),
		.event_type = REG_WATCH_SUBKEY_CREATED,
		.name = (const u8 *)layer_name,
		.name_len = sizeof(layer_name) - 1U,
	};
	struct pkm_lcs_kunit_walk_source_step lookup_step = {
		.expected_child = layer_name,
		.empty = true,
	};
	struct pkm_lcs_kunit_layer_create_watch_source_script script = {
		.lookup = {
			.steps = &lookup_step,
			.step_count = 1,
		},
	};
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	char names[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.lookup.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_create_watch_source_thread, &script,
		"pkm-lcs-kunit-layer-watch-create-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.lookup.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.lookup.writes, 1U);
	KUNIT_EXPECT_EQ(test, script.refresh.reads, 0U);
	KUNIT_EXPECT_EQ(test, script.refresh.writes, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_internal_layer_watch_create_retains_runtime_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const char * const layers_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 ancestors[4][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe6, 0x20 }, { 0xe6, 0x21 }, { 0xe6, 0x22 },
	};
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xe6, 0x23 };
	char layer_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[3],
		.ancestor_guids = ancestors,
		.resolved_path = layers_path,
		.path_component_count = ARRAY_SIZE(layers_path),
		.event_type = REG_WATCH_SUBKEY_CREATED,
		.name = (const u8 *)layer_name,
		.name_len = LONG_NAME_LEN,
	};
	struct pkm_lcs_kunit_walk_source_step lookup_step = {
		.expected_child = layer_name,
		.guid = policy_guid,
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.sequence = 0,
	};
	struct pkm_lcs_kunit_layer_create_watch_source_script script = {
		.lookup = {
			.steps = &lookup_step,
			.step_count = 1,
			.reset_runtime_limits_before_response = true,
		},
		.refresh = {
			.expected_guid = policy_guid,
			.name = layer_name,
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.precedence = 29,
			.enabled = 1,
			.precedence_present = true,
			.enabled_present = true,
		},
		.expect_refresh = true,
	};
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_runtime_limits limits = { };
	char names[512] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	memset(layer_name, 'L', LONG_NAME_LEN);
	layer_name[LONG_NAME_LEN] = '\0';
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.lookup.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_create_watch_source_thread, &script,
		"pkm-lcs-kunit-layer-watch-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.lookup.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.lookup.writes, 1U);
	KUNIT_EXPECT_EQ(test, script.refresh.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.refresh.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test, layers[1].name_len, (u32)LONG_NAME_LEN);
	KUNIT_EXPECT_EQ(test,
			memcmp(layers[1].name, layer_name, LONG_NAME_LEN),
			0);
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 29U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_internal_layer_watch_delete_event_orchestrates(
	struct kunit *test)
{
	static const char * const layers_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 ancestors[4][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe8, 0x10 }, { 0xe8, 0x11 }, { 0xe8, 0x12 },
	};
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xe8, 0x13 };
	static const char layer_name[] = "Policy";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[3],
		.ancestor_guids = ancestors,
		.resolved_path = layers_path,
		.path_component_count = ARRAY_SIZE(layers_path),
		.event_type = REG_WATCH_SUBKEY_DELETED,
		.name = (const u8 *)layer_name,
		.name_len = sizeof(layer_name) - 1U,
	};
	struct pkm_lcs_kunit_delete_layer_source_script script = {
		.expected_layer_name = layer_name,
		.status = RSI_OK,
	};
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	char names[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 effects = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				layer_name, sizeof(layer_name) - 1U, 17, 1,
				policy_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-layer-watch-delete");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_key_fd_dispatch_watch_event_context_effects(&context,
								  &effects);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_TRUE(test,
			  !!(effects &
			     PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 1U);
	KUNIT_EXPECT_STREQ(test, layers[0].name, "base");

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_internal_layer_watch_delete_base_noop(
	struct kunit *test)
{
	static const char * const layers_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 ancestors[4][RSI_GUID_SIZE] = {
		{ 1 }, { 0xe9, 0x10 }, { 0xe9, 0x11 }, { 0xe9, 0x12 },
	};
	static const char layer_name[] = "base";
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[3],
		.ancestor_guids = ancestors,
		.resolved_path = layers_path,
		.path_component_count = ARRAY_SIZE(layers_path),
		.event_type = REG_WATCH_SUBKEY_DELETED,
		.name = (const u8 *)layer_name,
		.name_len = sizeof(layer_name) - 1U,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	char names[32] = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 effects = 0;
	long ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm(
				1, ancestors[0], true, ancestors[2], true,
				ancestors[3], true, pkm_lcs_kunit_kmes_watch_guid,
				NULL),
			0L);

	ret = pkm_lcs_key_fd_dispatch_watch_event_context_effects(&context,
								  &effects);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, effects, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 1U);
	KUNIT_EXPECT_STREQ(test, layers[0].name, "base");

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_user_absolute_path_copy_routes_current_user(
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
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, (const char __user *)current_user_path,
				true, NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 4U);

	ctx.fault_src = current_user_path;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, (const char __user *)current_user_path,
				true, NULL, 0, &route),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	ctx.fault_src = NULL;

	ctx.unterminated_src = current_user_path;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, (const char __user *)current_user_path,
				true, NULL, 0, &route),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	ctx.unterminated_src = NULL;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, NULL, true, NULL, 0, &route),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_orphan_watch_observes_guid_local_sd_change(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa4 },
	};
	static const u8 existing_sd[] = {
		/* SECURITY_DESCRIPTOR_RELATIVE */
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		/* Owner: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* Group: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* DACL: one CONTAINER_INHERIT allow ACE for Everyone. */
		0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 input_empty_dacl_sd[] = {
		/* SECURITY_DESCRIPTOR_RELATIVE with an empty DACL only. */
		0x01, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const u8 expected_merged_sd[] = {
		/* Existing owner/group with the replacement empty DACL. */
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		/* Owner: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* Group: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* DACL: empty ACL. */
		0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_SD,
	};
	struct reg_set_security_args set_args = {
		.security_info = DACL_SECURITY_INFORMATION,
		.sd_len = sizeof(input_empty_dacl_sd),
		.sd_ptr = (u64)(unsigned long)input_empty_dacl_sd,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_set_security_source_script script = {
		.expected_guid = ancestors[1],
		.existing_sd = existing_sd,
		.existing_sd_len = sizeof(existing_sd),
		.expected_merged_sd = expected_merged_sd,
		.expected_merged_sd_len = sizeof(expected_merged_sd),
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 record[16] = { };
	u32 marked = U32_MAX;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY | WRITE_DAC, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
				1, ancestors[1], &marked),
			0L);
	KUNIT_EXPECT_EQ(test, marked, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);
	KUNIT_EXPECT_TRUE(test, snapshot.watch_armed);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, record,
							sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_security_source_thread, &script,
		"pkm-lcs-kunit-orphan-set-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)fd, &ops, &set_args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, record,
							sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[1]);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_misc_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_rust_probe_links_lcs_core),
	KUNIT_CASE(pkm_lcs_kunit_private_hive_route_uses_scope_order_live),
	KUNIT_CASE(pkm_lcs_kunit_internal_self_watch_arm_targeted_and_fallback),
	KUNIT_CASE(pkm_lcs_kunit_internal_self_watch_bad_inputs_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_internal_self_watch_value_event_refreshes_config),
	KUNIT_CASE(pkm_lcs_kunit_internal_kmes_watch_value_event_refreshes_config),
	KUNIT_CASE(pkm_lcs_kunit_internal_self_watch_non_value_event_noop),
	KUNIT_CASE(pkm_lcs_kunit_internal_self_watch_fallback_create_rearms_targeted),
	KUNIT_CASE(pkm_lcs_kunit_internal_self_watch_fallback_non_create_noop),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_value_event_refreshes_metadata),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_lifecycle_event_noop),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_descendant_event_noop),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_create_event_refreshes_metadata),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_create_missing_child_noop),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_create_retains_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_delete_event_orchestrates),
	KUNIT_CASE(pkm_lcs_kunit_internal_layer_watch_delete_base_noop),
	KUNIT_CASE(pkm_lcs_kunit_user_absolute_path_copy_routes_current_user),
	KUNIT_CASE(pkm_lcs_kunit_orphan_watch_observes_guid_local_sd_change),
	{}
};

static struct kunit_suite pkm_lcs_kunit_misc_suite = {
	.name = "pkm_lcs_kunit_misc",
	.test_cases = pkm_lcs_kunit_misc_cases,
};

kunit_test_suite(pkm_lcs_kunit_misc_suite);
