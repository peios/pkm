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

static void pkm_lcs_kunit_kmes_fill_missing_audit(
	struct pkm_kmes_self_config_audit_intent *audit, const char *name,
	u64 retained_value)
{
	memset(audit, 0, sizeof(*audit));
	audit->configuration_name_len = (u32)strlen(name);
	memcpy(audit->configuration_name, name, audit->configuration_name_len);
	audit->received_kind = PKM_KMES_SELF_CONFIG_RECEIVED_MISSING;
	audit->retained_value = retained_value;
}

/* Count the events of one type and origin in the single active ring. */
static u32 pkm_lcs_kunit_kmes_count_origin_events(struct kunit *test,
						   const char *event_type)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };
	size_t event_type_len = strlen(event_type);
	size_t written = 0;
	size_t pos = 0;
	u32 count = 0;
	u8 *buffer;
	int ret;

	buffer = kunit_kzalloc(test, 16384, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	ret = pkm_kmes_kunit_copy_single_buffer(buffer, 16384, &written,
						&snapshot);
	if (ret == -ENOENT)
		return 0;
	KUNIT_ASSERT_EQ(test, ret, 0);

	while (pos + KMES_EVENT_HEADER_BASE_SIZE <= written) {
		u32 event_size = get_unaligned_le32(buffer + pos +
						    KMES_EVENT_SIZE_OFFSET);
		u16 type_len = get_unaligned_le16(buffer + pos +
						  KMES_EVENT_TYPE_LEN_OFFSET);

		KUNIT_ASSERT_GE(test, event_size, (u32)KMES_EVENT_HEADER_BASE_SIZE);
		KUNIT_ASSERT_LE(test, (size_t)event_size, written - pos);
		if (buffer[pos + KMES_EVENT_ORIGIN_CLASS_OFFSET] ==
			    KMES_ORIGIN_KMES &&
		    type_len == event_type_len &&
		    !memcmp(buffer + pos + KMES_EVENT_HEADER_BASE_SIZE,
			    event_type, event_type_len))
			count++;
		pos += event_size;
	}
	KUNIT_EXPECT_EQ(test, pos, written);
	return count;
}


/*
 * PKM *config.at-most-four-reports and the four-events half of
 * *config.empty-key-emits-four. One read reports at most four
 * KMES_SELF_CONFIG_INVALID events -- the number of keys. A plan needing
 * a fifth is refused before anything is applied or emitted; a plan with
 * exactly four emits all four and applies.
 */
static void pkm_lcs_kunit_kmes_publish_caps_reports_at_four(struct kunit *test)
{
	static const char invalid_type[] = "KMES_SELF_CONFIG_INVALID";
	static const char * const names[] = {
		"BufferCapacity", "MaxEventSize", "MaxNestingDepth",
		"MaxEmitRatePerProcess",
	};
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_self_config_apply_plan result = { };
	struct pkm_kmes_runtime_config snapshot = { };
	u32 i;

	pkm_kmes_kunit_reset_all();

	plan.config = (struct pkm_kmes_runtime_config) {
		.buffer_capacity = 4ULL * 1024ULL * 1024ULL,
		.max_event_size = 2048U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	for (i = 0; i < PKM_KMES_SELF_CONFIG_MAX_AUDITS; i++)
		pkm_lcs_kunit_kmes_fill_missing_audit(&plan.audits[i], names[i],
						      1ULL);
	plan.retained_missing_count = PKM_KMES_SELF_CONFIG_MAX_AUDITS;

	/* Five: the whole read is abandoned, nothing applied, nothing said. */
	plan.audit_count = PKM_KMES_SELF_CONFIG_MAX_AUDITS + 1U;
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_publish_self_config_plan(&plan, &result),
			(long)-EIO);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 65536U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(test, invalid_type),
			0U);
	KUNIT_EXPECT_EQ(test, result.audit_count, 0U);

	/* Four: every report emitted, then the configuration applied. */
	plan.audit_count = PKM_KMES_SELF_CONFIG_MAX_AUDITS;
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_publish_self_config_plan(&plan, &result),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 2048U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(test, invalid_type),
			(u32)PKM_KMES_SELF_CONFIG_MAX_AUDITS);
	KUNIT_EXPECT_EQ(test, result.audit_count,
			(u32)PKM_KMES_SELF_CONFIG_MAX_AUDITS);
	pkm_lcs_kunit_expect_latest_kmes_origin_event(
		test, invalid_type, 0x89, "MaxEmitRatePerProcess", "missing");

	pkm_kmes_kunit_reset_all();
}


/*
 * PKM *config.validated-twice. The planner is the first gate; the C apply
 * is the second. A plan whose configuration is out of range at the second
 * gate fails the whole application with -EINVAL and changes nothing.
 */
static void pkm_lcs_kunit_kmes_publish_second_gate_rejects_out_of_range(
	struct kunit *test)
{
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kmes_kunit_reset_all();

	plan.config = (struct pkm_kmes_runtime_config) {
		.buffer_capacity = 4ULL * 1024ULL * 1024ULL,
		.max_event_size = 2048U,
		.max_nesting_depth = 257U,
		.max_emit_rate_per_process = 10000U,
	};
	plan.applied_count = 2U;
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_publish_self_config_plan(&plan, NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 65536U);
	KUNIT_EXPECT_EQ(test, snapshot.max_nesting_depth, 32U);

	pkm_kmes_kunit_reset_all();
}


/*
 * PKM *config.self-events-best-effort. Self-events are emitted before the
 * configuration is applied and their result is discarded: an audit the
 * event builder refuses does not roll back a valid application, and an
 * event that does emit does not activate an invalid configuration.
 */
static void pkm_lcs_kunit_kmes_publish_self_events_are_best_effort(
	struct kunit *test)
{
	static const char invalid_type[] = "KMES_SELF_CONFIG_INVALID";
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kmes_kunit_reset_all();

	/* An audit naming no known key cannot be rendered; the apply still lands. */
	plan.config = (struct pkm_kmes_runtime_config) {
		.buffer_capacity = 4ULL * 1024ULL * 1024ULL,
		.max_event_size = 4096U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	pkm_lcs_kunit_kmes_fill_missing_audit(&plan.audits[0], "Mystery", 1ULL);
	plan.audit_count = 1U;
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_publish_self_config_plan(&plan, NULL),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 4096U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(test, invalid_type),
			0U);

	/* A renderable audit beside an invalid config: event out, config not in. */
	pkm_kmes_kunit_reset_all();
	plan.config.max_event_size = 4096U;
	plan.config.max_nesting_depth = 257U;
	pkm_lcs_kunit_kmes_fill_missing_audit(&plan.audits[0], "MaxEventSize",
					      65536ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_publish_self_config_plan(&plan, NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 65536U);
	KUNIT_EXPECT_EQ(test, snapshot.max_nesting_depth, 32U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(test, invalid_type),
			1U);
	pkm_lcs_kunit_expect_latest_kmes_origin_event(
		test, invalid_type, 0x89, "MaxEventSize", "missing");

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
	KUNIT_CASE(pkm_lcs_kunit_kmes_publish_caps_reports_at_four),
	KUNIT_CASE(pkm_lcs_kunit_kmes_publish_second_gate_rejects_out_of_range),
	KUNIT_CASE(pkm_lcs_kunit_kmes_publish_self_events_are_best_effort),
	{}
};

static struct kunit_suite pkm_lcs_kunit_kmes_suite = {
	.name = "pkm_lcs_kunit_kmes",
	.test_cases = pkm_lcs_kunit_kmes_cases,
};

kunit_test_suite(pkm_lcs_kunit_kmes_suite);
