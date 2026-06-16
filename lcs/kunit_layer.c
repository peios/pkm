// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_layer_metadata_root_discovers_layers(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x68 };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x69 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x6a };
	static const u8 layers_guid[RSI_GUID_SIZE] = { 0x6b };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
		{ .expected_child = "Layers", .guid = layers_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	u8 discovered_guid[RSI_GUID_SIZE];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	bool present = false;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread,
					 &script,
					 "pkm-lcs-kunit-layers-root");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_layer_metadata_root_discover_from_machine_hive(
		1, machine_root_guid, &present, discovered_guid);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_TRUE(test, present);
	KUNIT_EXPECT_EQ(test,
			memcmp(discovered_guid, layers_guid, RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_root_missing_retains_fallback(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x6c };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x6d };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x6e };
	static const u8 zero_guid[RSI_GUID_SIZE];
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
		{ .expected_child = "Layers", .empty = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	u8 discovered_guid[RSI_GUID_SIZE];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	bool present = true;
	long ret;
	int thread_ret;

	memset(discovered_guid, 0xee, sizeof(discovered_guid));
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread,
					 &script,
					 "pkm-lcs-kunit-layers-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_layer_metadata_root_discover_from_machine_hive(
		1, machine_root_guid, &present, discovered_guid);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_FALSE(test, present);
	KUNIT_EXPECT_EQ(test,
			memcmp(discovered_guid, zero_guid, RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_root_bad_inputs_fail_closed(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x6f };
	static const u8 zero_guid[RSI_GUID_SIZE];
	u8 discovered_guid[RSI_GUID_SIZE];
	bool present = true;

	memset(discovered_guid, 0xee, sizeof(discovered_guid));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_root_discover_from_machine_hive(
				0, machine_root_guid, &present,
				discovered_guid),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, present);
	KUNIT_EXPECT_EQ(test,
			memcmp(discovered_guid, zero_guid, RSI_GUID_SIZE), 0);

	present = true;
	memset(discovered_guid, 0xee, sizeof(discovered_guid));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_root_discover_from_machine_hive(
				1, NULL, &present, discovered_guid),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, present);
	KUNIT_EXPECT_EQ(test,
			memcmp(discovered_guid, zero_guid, RSI_GUID_SIZE), 0);
}


static void pkm_lcs_kunit_layer_metadata_children_enumerates_visible(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x70 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0x71 };
	struct pkm_lcs_kunit_enum_children_source_script script = {
		.expected_parent_guid = layers_root_guid,
		.child_name = "Policy",
		.layer_name = "base",
		.child_guid = policy_guid,
		.sequence = 0,
	};
	struct pkm_lcs_layer_metadata_child_list list = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_enum_children_source_thread, &script,
		"pkm-lcs-kunit-layers-enum");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_layer_metadata_children_enumerate_from_root(
		1, layers_root_guid, &list);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, list.child_count, 1U);
	KUNIT_ASSERT_NOT_NULL(test, list.children);
	KUNIT_EXPECT_EQ(test, list.children[0].name_len, 6U);
	KUNIT_EXPECT_STREQ(test, list.children[0].name, "Policy");
	KUNIT_EXPECT_EQ(test,
			memcmp(list.children[0].guid, policy_guid,
			       RSI_GUID_SIZE),
			0);

	pkm_lcs_layer_metadata_child_list_destroy(&list);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_children_empty_effective_set(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x72 };
	struct pkm_lcs_kunit_enum_children_source_script script = {
		.expected_parent_guid = layers_root_guid,
		.child_name = "HiddenPolicy",
		.layer_name = "base",
		.sequence = 0,
		.hidden = true,
	};
	struct pkm_lcs_layer_metadata_child_list list = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_enum_children_source_thread, &script,
		"pkm-lcs-kunit-layers-enum-empty");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_layer_metadata_children_enumerate_from_root(
		1, layers_root_guid, &list);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, list.child_count, 0U);
	KUNIT_EXPECT_NULL(test, list.children);

	pkm_lcs_layer_metadata_child_list_destroy(&list);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_children_respects_total_layer_cap(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x74 };
	struct pkm_lcs_kunit_enum_children_source_script script = {
		.expected_parent_guid = layers_root_guid,
		.layer_name = "base",
		.sequence = 0,
		.repeated_child_count = 17U,
	};
	struct pkm_lcs_layer_metadata_child_list list = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_total_layers = 16U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_enum_children_source_thread, &script,
		"pkm-lcs-kunit-layers-enum-cap");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_layer_metadata_children_enumerate_from_root(
		1, layers_root_guid, &list);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, list.child_count, 0U);
	KUNIT_EXPECT_NULL(test, list.children);

	pkm_lcs_layer_metadata_child_list_destroy(&list);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_layer_metadata_children_bad_inputs_fail_closed(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x73 };
	struct pkm_lcs_layer_metadata_child_list list = {
		.child_count = 99U,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_children_enumerate_from_root(
				0, layers_root_guid, &list),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, list.child_count, 0U);
	KUNIT_EXPECT_NULL(test, list.children);

	list.child_count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_children_enumerate_from_root(
				1, NULL, &list),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, list.child_count, 0U);
	KUNIT_EXPECT_NULL(test, list.children);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_children_enumerate_from_root(
				1, layers_root_guid, NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_layer_metadata_refresh_all_publishes_children(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x75 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0x76 };
	static const u8 owner_only_sd[] = {
		0x01, 0x00, 0x00, 0x80,
		0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_layer_metadata_refresh_all_result result = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_all_source_script script = {
		.enum_children = {
			.expected_parent_guid = layers_root_guid,
			.child_name = "Policy",
			.layer_name = "base",
			.child_guid = policy_guid,
		},
		.refresh = {
			.expected_guid = policy_guid,
			.name = "Policy",
			.sd = owner_only_sd,
			.sd_len = sizeof(owner_only_sd),
			.precedence = 7,
			.enabled = 1,
			.precedence_present = true,
			.enabled_present = true,
		},
		.expect_refresh = true,
	};
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_all_source_thread,
		&script, "pkm-lcs-kunit-layers-refresh-all");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_layer_metadata_refresh_all_from_root(
		1, layers_root_guid, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, result.enumerated_child_count, 1U);
	KUNIT_EXPECT_EQ(test, result.refreshed_child_count, 1U);
	KUNIT_EXPECT_EQ(test, result.effective_changed_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 7U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_refresh_all_empty_noops(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x77 };
	struct pkm_lcs_layer_metadata_refresh_all_result result = { };
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_all_source_script script = {
		.enum_children = {
			.expected_parent_guid = layers_root_guid,
			.child_name = "HiddenPolicy",
			.layer_name = "base",
			.hidden = true,
		},
	};
	char names[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_all_source_thread,
		&script, "pkm-lcs-kunit-layers-refresh-empty");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_layer_metadata_refresh_all_from_root(
		1, layers_root_guid, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.enumerated_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.refreshed_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.effective_changed_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_refresh_all_respects_total_layer_cap(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x78 };
	struct pkm_lcs_layer_metadata_refresh_all_result result = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_all_source_script script = {
		.enum_children = {
			.expected_parent_guid = layers_root_guid,
			.layer_name = "base",
			.repeated_child_count = 16U,
		},
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_total_layers = 16U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_all_source_thread,
		&script, "pkm-lcs-kunit-layers-refresh-cap");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_layer_metadata_refresh_all_from_root(
		1, layers_root_guid, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, script.refresh.reads, 0U);
	KUNIT_EXPECT_EQ(test, script.refresh.writes, 0U);
	KUNIT_EXPECT_EQ(test, result.enumerated_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.refreshed_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.effective_changed_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_layer_metadata_refresh_all_bad_inputs_fail_closed(
	struct kunit *test)
{
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x79 };
	struct pkm_lcs_layer_metadata_refresh_all_result result = {
		.enumerated_child_count = 99U,
		.refreshed_child_count = 99U,
		.effective_changed_count = 99U,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_refresh_all_from_root(
				0, layers_root_guid, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.enumerated_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.refreshed_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.effective_changed_count, 0U);

	result.enumerated_child_count = 99U;
	result.refreshed_child_count = 99U;
	result.effective_changed_count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_refresh_all_from_root(
				1, NULL, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.enumerated_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.refreshed_child_count, 0U);
	KUNIT_EXPECT_EQ(test, result.effective_changed_count, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_metadata_refresh_all_from_root(
				1, layers_root_guid, NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_layer_write_access_allows_key_set_value(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_write_access_denies_without_right(
	struct kunit *test)
{
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

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_write_access_malformed_sd_eio(
	struct kunit *test)
{
	static const u8 malformed_sd[] = { 0x01, 0x00, 0x00, 0x00 };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, malformed_sd, sizeof(malformed_sd),
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access_check_granted, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_write_access_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				NULL, sd, sd_len, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, NULL, sd_len, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, 0, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_base_layer_default_sd_allows_system_and_admin(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan system_plan = { };
	struct pkm_lcs_key_open_access_plan admin_plan = { };
	const void *system_token = pkm_kacs_boot_system_token_ptr();
	const void *admin_token;
	const u8 *sd;
	size_t sd_len = 0;

	KUNIT_ASSERT_NOT_NULL(test, system_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	sd = kacs_rust_create_lcs_base_layer_default_sd(&sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, sd_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				system_token, sd, sd_len, &system_plan),
			0L);
	KUNIT_EXPECT_EQ(test, system_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, system_plan.fd_granted_access, KEY_SET_VALUE);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				admin_token, sd, sd_len, &admin_plan),
			0L);
	KUNIT_EXPECT_EQ(test, admin_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, admin_plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(admin_token);
}


static void pkm_lcs_kunit_base_layer_default_sd_denies_service(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_create_lcs_base_layer_default_sd(&sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, sd_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_base_layer_write_present_sd_overrides_default(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, sd, sd_len, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_base_layer_write_absent_uses_default(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, false, NULL, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_base_layer_write_absent_denies_service(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, false, NULL, 0, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_base_layer_write_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
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

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, NULL, sd_len, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, sd, 0, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, sd, sd_len, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_table_publish_snapshot_remove(struct kunit *test)
{
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 replacement_guid[RSI_GUID_SIZE] = { 0xb2 };
	static const u8 nil_guid[RSI_GUID_SIZE] = { 0 };
	struct pkm_lcs_layer_table_publish_result publish = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	char names[64] = { };
	bool removed = true;
	u32 count = 0;

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_STREQ(test, layers[0].name, "base");
	KUNIT_EXPECT_EQ(test, layers[0].precedence, 0U);
	KUNIT_EXPECT_EQ(test, layers[0].enabled, 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish_with_result(
				"Policy", strlen("Policy"), 7, 1, policy_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid), &publish),
			0L);
	KUNIT_EXPECT_FALSE(test, publish.existed_before);
	KUNIT_EXPECT_TRUE(test, publish.effective_changed);
	KUNIT_EXPECT_EQ(test, publish.new_precedence, 7U);
	KUNIT_EXPECT_EQ(test, publish.new_enabled, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish_with_result(
				"policy", strlen("policy"), 11, 0,
				replacement_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_everyone_sid,
				sizeof(pkm_lcs_kunit_everyone_sid), &publish),
			0L);
	KUNIT_EXPECT_TRUE(test, publish.existed_before);
	KUNIT_EXPECT_TRUE(test, publish.effective_changed);
	KUNIT_EXPECT_EQ(test, publish.previous_precedence, 7U);
	KUNIT_EXPECT_EQ(test, publish.new_precedence, 11U);
	KUNIT_EXPECT_EQ(test, publish.previous_enabled, 1U);
	KUNIT_EXPECT_EQ(test, publish.new_enabled, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish_with_result(
				"policy", strlen("policy"), 12, 0,
				replacement_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid), &publish),
			0L);
	KUNIT_EXPECT_TRUE(test, publish.existed_before);
	KUNIT_EXPECT_FALSE(test, publish.effective_changed);
	memset(layers, 0, sizeof(layers));
	memset(names, 0, sizeof(names));
	count = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 12U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_remove("POLICY", strlen("POLICY"),
						   &removed),
			0L);
	KUNIT_EXPECT_TRUE(test, removed);
	memset(layers, 0, sizeof(layers));
	memset(names, 0, sizeof(names));
	count = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_STREQ(test, layers[0].name, "base");

	removed = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_remove("base", strlen("base"),
						   &removed),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, removed);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish(
				"base", strlen("base"), 0, 1, policy_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish(
				"bad/layer", strlen("bad/layer"), 0, 1,
				policy_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Other", strlen("Other"), 0, 1, nil_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish("Other", strlen("Other"),
						    0, 1, policy_guid,
						    (const u8 *)"bad", 3,
						    pkm_lcs_kunit_system_sid,
						    sizeof(pkm_lcs_kunit_system_sid)),
			(long)-EIO);

	pkm_lcs_kunit_reset_layer_table();
}


static void pkm_lcs_kunit_layer_table_publish_uses_runtime_limits(
	struct kunit *test)
{
	static const u8 layer_guid[RSI_GUID_SIZE] = { 0xc5 };
	struct pkm_lcs_layer_table_publish_result publish = { };
	struct pkm_lcs_runtime_limits limits = { };
	char long_name[301];
	bool removed = false;

	memset(long_name, 'l', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish_with_result_with_limits(
				long_name, sizeof(long_name) - 1, 4, 1,
				layer_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid), &limits,
				&publish),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_FALSE(test, publish.existed_before);
	KUNIT_EXPECT_FALSE(test, publish.effective_changed);

	limits.max_path_component_length = sizeof(long_name) - 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish_with_result_with_limits(
				long_name, sizeof(long_name) - 1, 4, 1,
				layer_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid), &limits,
				&publish),
			0L);
	KUNIT_EXPECT_FALSE(test, publish.existed_before);
	KUNIT_EXPECT_TRUE(test, publish.effective_changed);
	KUNIT_EXPECT_EQ(test, publish.new_precedence, 4U);
	KUNIT_EXPECT_EQ(test, publish.new_enabled, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_remove_with_limits(
				long_name, sizeof(long_name) - 1, &limits,
				&removed),
			0L);
	KUNIT_EXPECT_TRUE(test, removed);

	pkm_lcs_kunit_reset_layer_table();
}


static void pkm_lcs_kunit_layer_metadata_refresh_uses_runtime_limits(
	struct kunit *test)
{
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xf1, 0x20 },
		{ 0xf1, 0x21 },
		{ 0xf1, 0x22 },
		{ 0xf1, 0x23 },
	};
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = metadata_ancestors[4],
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 19,
		.enabled = 1,
		.precedence_present = true,
		.enabled_present = true,
	};
	char long_layer[301];
	const char *metadata_path[] = {
		"Machine", "System", "Registry", "Layers", long_layer
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(long_layer, 'R', sizeof(long_layer) - 1);
	long_layer[sizeof(long_layer) - 1] = '\0';
	script.name = long_layer;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = sizeof(long_layer) - 1;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-long-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_layer_snapshot_acquire(&snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.layer_count, 2U);
	if (snapshot.layer_count > 1) {
		KUNIT_EXPECT_EQ(test, snapshot.layers[1].name_len,
				(u32)(sizeof(long_layer) - 1));
		KUNIT_EXPECT_EQ(test,
				memcmp(snapshot.layers[1].name, long_layer,
				       sizeof(long_layer) - 1),
				0);
		KUNIT_EXPECT_EQ(test, snapshot.layers[1].precedence, 19U);
	}
	pkm_lcs_source_layer_snapshot_release(&snapshot);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_path_refresh_uses_supplied_limits(
	struct kunit *test)
{
	static const u8 metadata_guid[PKM_LCS_GUID_BYTES] = { 0xf2, 0x23 };
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = metadata_guid,
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 21,
		.enabled = 1,
		.precedence_present = true,
		.enabled_present = true,
	};
	char long_layer[301];
	const char *metadata_path[] = {
		"Machine", "System", "Registry", "Layers", long_layer
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	bool effective_changed = false;
	long ret;
	int thread_ret;

	memset(long_layer, 'S', sizeof(long_layer) - 1);
	long_layer[sizeof(long_layer) - 1] = '\0';
	script.name = long_layer;

	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = sizeof(long_layer) - 1;
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-path-refresh-retains-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
		1, metadata_guid, metadata_path, ARRAY_SIZE(metadata_path),
		pkm_lcs_kunit_system_sid, sizeof(pkm_lcs_kunit_system_sid),
		true, &limits, &effective_changed);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, effective_changed);
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_layer_snapshot_acquire(&snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.layer_count, 2U);
	if (snapshot.layer_count > 1) {
		KUNIT_EXPECT_EQ(test, snapshot.layers[1].name_len,
				(u32)(sizeof(long_layer) - 1));
		KUNIT_EXPECT_EQ(test,
				memcmp(snapshot.layers[1].name, long_layer,
				       sizeof(long_layer) - 1),
				0);
		KUNIT_EXPECT_EQ(test, snapshot.layers[1].precedence, 21U);
	}
	pkm_lcs_source_layer_snapshot_release(&snapshot);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_refresh_publishes_and_retains(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xf1, 0x10 },
		{ 0xf1, 0x11 },
		{ 0xf1, 0x12 },
		{ 0xf1 },
	};
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = metadata_ancestors[4],
		.name = "Policy",
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 9,
		.enabled = 0,
		.precedence_present = true,
		.enabled_present = true,
	};
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 *owner_sid = NULL;
	size_t owner_sid_len = 0;
	u32 count = 0;
	bool owner_present = false;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
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
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 9U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_owner_snapshot(
				"policy", strlen("policy"), &owner_sid,
				&owner_sid_len, &owner_present),
			0L);
	KUNIT_ASSERT_TRUE(test, owner_present);
	KUNIT_ASSERT_EQ(test, owner_sid_len,
			sizeof(pkm_lcs_kunit_system_sid));
	KUNIT_EXPECT_EQ(test,
			memcmp(owner_sid, pkm_lcs_kunit_system_sid,
			       owner_sid_len),
			0);
	kfree(owner_sid);
	owner_sid = NULL;
	owner_sid_len = 0;
	owner_present = false;

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_guid = metadata_ancestors[4];
	script.name = "Policy";
	script.sd = pkm_lcs_kunit_owner_only_sd;
	script.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd);
	script.precedence = 13;
	script.enabled = 1;
	script.owner_sid = pkm_lcs_kunit_everyone_sid;
	script.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid);
	script.precedence_present = true;
	script.enabled_present = true;
	script.owner_present = true;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-refresh-owner");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_owner_snapshot(
				"POLICY", strlen("POLICY"), &owner_sid,
				&owner_sid_len, &owner_present),
			0L);
	KUNIT_ASSERT_TRUE(test, owner_present);
	KUNIT_ASSERT_EQ(test, owner_sid_len,
			sizeof(pkm_lcs_kunit_everyone_sid));
	KUNIT_EXPECT_EQ(test,
			memcmp(owner_sid, pkm_lcs_kunit_everyone_sid,
			       owner_sid_len),
			0);
	kfree(owner_sid);
	owner_sid = NULL;
	owner_sid_len = 0;
	owner_present = false;

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_guid = metadata_ancestors[4];
	script.name = "Policy";
	script.sd = pkm_lcs_kunit_owner_only_sd;
	script.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd);
	script.precedence = 15;
	script.enabled = 0;
	script.precedence_present = true;
	script.enabled_present = true;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-refresh-owner-retain");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	memset(layers, 0, sizeof(layers));
	memset(names, 0, sizeof(names));
	count = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 15U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_owner_snapshot(
				"policy", strlen("policy"), &owner_sid,
				&owner_sid_len, &owner_present),
			0L);
	KUNIT_ASSERT_TRUE(test, owner_present);
	KUNIT_ASSERT_EQ(test, owner_sid_len,
			sizeof(pkm_lcs_kunit_everyone_sid));
	KUNIT_EXPECT_EQ(test,
			memcmp(owner_sid, pkm_lcs_kunit_everyone_sid,
			       owner_sid_len),
			0);
	kfree(owner_sid);
	owner_sid = NULL;
	owner_sid_len = 0;
	owner_present = false;

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_guid = metadata_ancestors[4];
	script.name = "Policy";
	script.sd = pkm_lcs_kunit_owner_only_sd;
	script.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd);
	script.precedence = 16;
	script.enabled = 1;
	script.owner_sid = (const u8 *)"bad";
	script.owner_sid_len = 3;
	script.precedence_present = true;
	script.enabled_present = true;
	script.owner_present = true;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-refresh-owner-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_guid = metadata_ancestors[4];
	script.name = "Policy";
	script.sd = pkm_lcs_kunit_owner_only_sd;
	script.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd);
	script.precedence = 12;
	script.enabled = 2;
	script.precedence_present = true;
	script.enabled_present = true;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-refresh-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	memset(layers, 0, sizeof(layers));
	memset(names, 0, sizeof(names));
	count = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 15U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_owner_snapshot(
				"Policy", strlen("Policy"), &owner_sid,
				&owner_sid_len, &owner_present),
			0L);
	KUNIT_ASSERT_TRUE(test, owner_present);
	KUNIT_ASSERT_EQ(test, owner_sid_len,
			sizeof(pkm_lcs_kunit_everyone_sid));
	KUNIT_EXPECT_EQ(test,
			memcmp(owner_sid, pkm_lcs_kunit_everyone_sid,
			       owner_sid_len),
			0);
	kfree(owner_sid);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_base_layer_metadata_refresh_caches_sd(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "base"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xb6, 0x10 },
		{ 0xb6, 0x11 },
		{ 0xb6, 0x12 },
		{ 0xb6 },
	};
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = metadata_ancestors[4],
		.name = "base",
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.stop_after_read_key = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	bool present = false;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-base-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_ASSERT_EQ(test, pkm_lcs_source_layer_snapshot_acquire(&snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.layer_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.metadata_count, 0U);
	KUNIT_ASSERT_TRUE(test, snapshot.base_metadata_present);
	KUNIT_ASSERT_EQ(test, snapshot.base_metadata_sd_len,
			sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.base_metadata_sd,
			       pkm_lcs_kunit_owner_only_sd,
			       snapshot.base_metadata_sd_len),
			0);
	pkm_lcs_source_layer_snapshot_release(&snapshot);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_metadata_key_guid_present(
				metadata_ancestors[4], &present),
			0L);
	KUNIT_EXPECT_TRUE(test, present);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_refresh_malformed_sd_audits(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] =
		"malformed_layer_metadata_security_descriptor";
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xf5, 0x10 },
		{ 0xf5, 0x11 },
		{ 0xf5, 0x12 },
		{ 0xf5 },
	};
	static const u8 malformed_sd[] = { 0x01, 0x02, 0x03 };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script script = {
		.expected_guid = metadata_ancestors[4],
		.name = "Policy",
		.sd = malformed_sd,
		.sd_len = sizeof(malformed_sd),
		.stop_after_read_key = true,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 *buffer;
	size_t written = 0;
	u32 header_size;
	u32 count = 0;
	u16 type_len;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	buffer = kzalloc(2048, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 9, 1,
				metadata_ancestors[4],
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_layer_metadata_refresh_source_thread, &script,
		"pkm-lcs-kunit-layer-refresh-sd-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_refresh_layer_metadata((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_LCS, event_type,
				sizeof(event_type) - 1, buffer, 2048,
				&written, &snapshot),
			0);
	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)(sizeof(event_type) - 1));
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_EXPECT_EQ(test, buffer[header_size], 0x86);
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains(
				  buffer, written, validation_class));
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains_bytes(
				  buffer, written, metadata_ancestors[4],
				  sizeof(metadata_ancestors[4])));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 9U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kfree(buffer);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_metadata_set_security_refreshes_sd(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xf6, 0x10 },
		{ 0xf6, 0x11 },
		{ 0xf6, 0x12 },
		{ 0xf6 },
	};
	static const u8 old_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	static const u8 new_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = sizeof(new_sd),
		.sd_ptr = (u64)(unsigned long)new_sd,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_set_security_layer_refresh_source_script script = {
		.set_security = {
			.expected_guid = metadata_ancestors[4],
			.existing_sd = old_sd,
			.existing_sd_len = sizeof(old_sd),
			.expected_merged_sd = new_sd,
			.expected_merged_sd_len = sizeof(new_sd),
		},
		.refresh = {
			.expected_guid = metadata_ancestors[4],
			.name = "Policy",
			.sd = new_sd,
			.sd_len = sizeof(new_sd),
			.precedence = 17,
			.enabled = 0,
			.precedence_present = true,
			.enabled_present = true,
		},
	};
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 9, 1,
				metadata_ancestors[4], old_sd, sizeof(old_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, WRITE_OWNER, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_security_layer_refresh_source_thread,
		&script, "pkm-lcs-kunit-set-sd-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_set_security((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_NE(test,
			script.set_security.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_acquire(&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test, snapshot.layer_count, 2U);
	KUNIT_ASSERT_EQ(test, snapshot.metadata_count, 1U);
	KUNIT_EXPECT_STREQ(test, snapshot.layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, snapshot.layers[1].precedence, 17U);
	KUNIT_EXPECT_EQ(test, snapshot.layers[1].enabled, 0U);
	KUNIT_EXPECT_STREQ(test, snapshot.metadata[0].name, "Policy");
	KUNIT_EXPECT_EQ(test, snapshot.metadata[0].sd_len, sizeof(new_sd));
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.metadata[0].sd, new_sd, sizeof(new_sd)),
			0);
	pkm_lcs_source_layer_snapshot_release(&snapshot);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_delete_aborts_matching_bound_transactions(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_layer_abort_result result = { };
	struct pkm_lcs_transaction_fd_snapshot policy_snapshot = { };
	struct pkm_lcs_transaction_fd_snapshot other_snapshot = { };
	struct pkm_lcs_transaction_fd_snapshot unbound_snapshot = { };
	struct pkm_lcs_transaction_read_plan read_plan = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct reg_txn_status_args status = { };
	u8 abort_frame[RSI_REQUEST_HEADER_SIZE + sizeof(u64)];
	struct file file = { };
	const void *token;
	ssize_t read_len;
	u32 count = 0;
	long policy_fd;
	long other_fd;
	long unbound_fd;

	flush_delayed_fput();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	policy_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, policy_fd >= 0);
	other_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, other_fd >= 0);
	unbound_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, unbound_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)policy_fd,
							&policy_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)other_fd,
							&other_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)policy_fd, policy_snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)other_fd, other_snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_set_value_log_for_layer(
		test, (int)policy_fd, root_guid, "Policy", 42);
	pkm_lcs_kunit_append_set_value_log_for_layer(
		test, (int)other_fd, root_guid, "Other", 43);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_abort_layer_writers(
				"bad/layer", strlen("bad/layer"), &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_abort_layer_writers(
				"base", strlen("base"), &result),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)policy_fd,
							&policy_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, policy_snapshot.state, REG_TXN_ACTIVE_BOUND);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_abort_layer_writers(
				"policy", strlen("policy"), &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.inspected_transaction_count, 3U);
	KUNIT_EXPECT_EQ(test, result.affected_bound_transaction_count, 1U);
	KUNIT_EXPECT_EQ(test, result.abort_dispatched_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)policy_fd,
							&policy_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, policy_snapshot.state, REG_TXN_ABORTED);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)policy_fd, &status),
			0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ABORTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)policy_fd),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)policy_fd, 1, root_guid, &read_plan),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)other_fd,
							&other_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, other_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)unbound_fd,
							&unbound_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, unbound_snapshot.state, REG_TXN_ACTIVE_UNBOUND);

	read_len = pkm_lcs_kunit_source_device_read_file(&file, abort_frame,
							 sizeof(abort_frame),
							 true);
	KUNIT_ASSERT_EQ(test, read_len, (ssize_t)sizeof(abort_frame));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(abort_frame +
					   RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(abort_frame +
					   RSI_REQUEST_TXN_ID_OFFSET),
			policy_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(abort_frame + RSI_REQUEST_HEADER_SIZE),
			policy_snapshot.transaction_id);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)unbound_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)other_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)policy_fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_layer_delete_abort_uses_runtime_limits(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_layer_abort_result result = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 abort_frame[RSI_REQUEST_HEADER_SIZE + sizeof(u64)];
	struct file file = { };
	const void *token;
	char long_layer[301];
	ssize_t read_len;
	u32 count = 0;
	long fd;

	memset(long_layer, 'T', sizeof(long_layer) - 1);
	long_layer[sizeof(long_layer) - 1] = '\0';

	flush_delayed_fput();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = sizeof(long_layer) - 1;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1, root_guid),
			0L);

	pkm_lcs_kunit_append_set_value_log_for_layer(
		test, (int)fd, root_guid, long_layer, 77);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_abort_layer_writers(
				long_layer, sizeof(long_layer) - 1, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.inspected_transaction_count, 1U);
	KUNIT_EXPECT_EQ(test, result.affected_bound_transaction_count, 1U);
	KUNIT_EXPECT_EQ(test, result.abort_dispatched_count, 1U);

	read_len = pkm_lcs_kunit_source_device_read_file(&file, abort_frame,
							 sizeof(abort_frame),
							 true);
	KUNIT_ASSERT_EQ(test, read_len, (ssize_t)sizeof(abort_frame));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(abort_frame +
					   RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_layer_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_root_discovers_layers),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_root_missing_retains_fallback),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_root_bad_inputs_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_children_enumerates_visible),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_children_empty_effective_set),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_children_respects_total_layer_cap),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_children_bad_inputs_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_all_publishes_children),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_all_empty_noops),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_all_respects_total_layer_cap),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_all_bad_inputs_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_allows_key_set_value),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_denies_without_right),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_malformed_sd_eio),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_default_sd_allows_system_and_admin),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_default_sd_denies_service),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_present_sd_overrides_default),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_absent_uses_default),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_absent_denies_service),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_layer_table_publish_snapshot_remove),
	KUNIT_CASE(pkm_lcs_kunit_layer_table_publish_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_layer_path_refresh_uses_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_publishes_and_retains),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_metadata_refresh_caches_sd),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_refresh_malformed_sd_audits),
	KUNIT_CASE(pkm_lcs_kunit_layer_metadata_set_security_refreshes_sd),
	KUNIT_CASE(pkm_lcs_kunit_layer_delete_aborts_matching_bound_transactions),
	KUNIT_CASE(pkm_lcs_kunit_layer_delete_abort_uses_runtime_limits),
	{}
};

static struct kunit_suite pkm_lcs_kunit_layer_suite = {
	.name = "pkm_lcs_kunit_layer",
	.test_cases = pkm_lcs_kunit_layer_cases,
};

kunit_test_suite(pkm_lcs_kunit_layer_suite);
