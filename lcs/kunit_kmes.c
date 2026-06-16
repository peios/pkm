// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_kmes_config_apply_ignores_unknown_and_retains_invalid(
	struct kunit *test)
{
	static const char buffer_capacity_name[] = "BufferCapacity";
	static const char nesting_name[] = "MaxNestingDepth";
	static const char unknown_name[] = "Mystery";
	struct pkm_kmes_self_config_entry entries[] = {
		{
			.name = buffer_capacity_name,
			.name_len = sizeof(buffer_capacity_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_QWORD,
			.value_type = REG_QWORD,
			.value_u64 = 65537ULL,
		},
		{
			.name = nesting_name,
			.name_len = sizeof(nesting_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_DWORD,
			.value_type = REG_DWORD,
			.value_u32 = 64U,
		},
		{
			.name = unknown_name,
			.name_len = sizeof(unknown_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_DWORD,
			.value_type = REG_DWORD,
			.value_u32 = 123U,
		},
	};
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kmes_kunit_reset_all();

	KUNIT_EXPECT_EQ(test,
			pkm_kmes_runtime_config_apply_self_config(
				entries, ARRAY_SIZE(entries), &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count, 2U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.ignored_unknown_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 3U);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity,
			4ULL * 1024ULL * 1024ULL);
	KUNIT_EXPECT_EQ(test, snapshot.max_nesting_depth, 64U);

	pkm_kmes_kunit_reset_all();
}


static void pkm_lcs_kunit_kmes_config_invalid_emits_kmes_event(
	struct kunit *test)
{
	static const char buffer_capacity_name[] = "BufferCapacity";
	static const char max_event_name[] = "MaxEventSize";
	static const char nesting_name[] = "MaxNestingDepth";
	static const char rate_name[] = "MaxEmitRatePerProcess";
	struct pkm_kmes_self_config_entry entries[] = {
		{
			.name = buffer_capacity_name,
			.name_len = sizeof(buffer_capacity_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_QWORD,
			.value_type = REG_QWORD,
			.value_u64 = 65537ULL,
		},
		{
			.name = max_event_name,
			.name_len = sizeof(max_event_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_DWORD,
			.value_type = REG_DWORD,
			.value_u32 = 2048U,
		},
		{
			.name = nesting_name,
			.name_len = sizeof(nesting_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_DWORD,
			.value_type = REG_DWORD,
			.value_u32 = 64U,
		},
		{
			.name = rate_name,
			.name_len = sizeof(rate_name) - 1,
			.value_kind = PKM_KMES_SELF_CONFIG_VALUE_DWORD,
			.value_type = REG_DWORD,
			.value_u32 = 200U,
		},
	};
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kmes_kunit_reset_all();

	KUNIT_EXPECT_EQ(test,
			pkm_kmes_runtime_config_apply_self_config(
				entries, ARRAY_SIZE(entries), &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 3U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 1U);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity,
			4ULL * 1024ULL * 1024ULL);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 2048U);
	pkm_lcs_kunit_expect_latest_kmes_origin_event(
		test, "KMES_SELF_CONFIG_INVALID", 0x89,
		"Machine\\System\\KMES", "u64_out_of_range");
	pkm_lcs_kunit_expect_latest_kmes_origin_event(
		test, "KMES_SELF_CONFIG_INVALID", 0x89, "BufferCapacity",
		"retained_value");

	pkm_kmes_kunit_reset_all();
}


static void pkm_lcs_kunit_kmes_config_swap_failure_emits_kmes_event(
	struct kunit *test)
{
	struct pkm_kmes_runtime_config config = {
		.buffer_capacity = 65536ULL,
		.max_event_size = 65536U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kmes_kunit_reset_all();
	pkm_kmes_kunit_fail_next_swap_alloc();

	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-ENOMEM);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity,
			4ULL * 1024ULL * 1024ULL);
	pkm_lcs_kunit_expect_latest_kmes_origin_event(
		test, "KMES_BUFFER_SWAP_FAILED", 0x83, "requested_capacity",
		"retained_capacity");

	pkm_kmes_kunit_reset_all();
}


static void pkm_lcs_kunit_kmes_config_refresh_from_source_hot_swaps(
	struct kunit *test)
{
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0x91 };
	static const char value_name[] = "BufferCapacity";
	u8 data[sizeof(u64)];
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = kmes_guid,
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_QWORD,
		.query_all = true,
	};
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	put_unaligned_le64(65536ULL, data);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-kmes-config-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_kmes_runtime_config_refresh_from_key(1, kmes_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count, 3U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 3U);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity, 65536ULL);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 65536U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_kmes_kunit_reset_all();
}


static void pkm_lcs_kunit_kmes_config_refresh_wrong_type_retains(
	struct kunit *test)
{
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0x92 };
	static const char value_name[] = "MaxEventSize";
	static const u8 data[] = { 0x01 };
	struct pkm_kmes_runtime_config active = {
		.buffer_capacity = 4ULL * 1024ULL * 1024ULL,
		.max_event_size = 2048U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = kmes_guid,
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&active), 0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-kmes-config-wrong");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_kmes_runtime_config_refresh_from_key(1, kmes_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count, 3U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 4U);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 2048U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_kmes_kunit_reset_all();
}


static void pkm_lcs_kunit_kmes_config_refresh_malformed_source_retains(
	struct kunit *test)
{
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0x93 };
	static const char value_name[] = "MaxEventSize";
	static const u8 data[] = { 0x01 };
	struct pkm_kmes_runtime_config active = {
		.buffer_capacity = 4ULL * 1024ULL * 1024ULL,
		.max_event_size = 2048U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = kmes_guid,
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = 0xffffffffU,
		.query_all = true,
	};
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&active), 0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-kmes-config-malformed");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_kmes_runtime_config_refresh_from_key(1, kmes_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 2048U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_kmes_kunit_reset_all();
}


static void pkm_lcs_kunit_kmes_config_machine_hive_missing_retains_defaults(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x94 };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x95 };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "KMES", .empty = true },
	};
	struct pkm_lcs_kunit_walk_then_query_values_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
	};
	struct pkm_kmes_self_config_apply_plan plan = {
		.applied_count = 99U,
	};
	struct pkm_kmes_runtime_config snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_query_values_source_thread, &script,
		"pkm-lcs-kunit-kmes-config-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_kmes_runtime_config_refresh_from_machine_hive(
		1, machine_root_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity,
			4ULL * 1024ULL * 1024ULL);
	KUNIT_EXPECT_EQ(test, snapshot.max_emit_rate_per_process, 10000U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_kmes_kunit_reset_all();
}

static struct kunit_case pkm_lcs_kunit_kmes_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_apply_ignores_unknown_and_retains_invalid),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_invalid_emits_kmes_event),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_swap_failure_emits_kmes_event),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_refresh_from_source_hot_swaps),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_refresh_wrong_type_retains),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_refresh_malformed_source_retains),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_machine_hive_missing_retains_defaults),
	{}
};

static struct kunit_suite pkm_lcs_kunit_kmes_suite = {
	.name = "pkm_lcs_kunit_kmes",
	.test_cases = pkm_lcs_kunit_kmes_cases,
};

kunit_test_suite(pkm_lcs_kunit_kmes_suite);
