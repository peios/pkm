// SPDX-License-Identifier: GPL-2.0-only

/* The generated trie, for driving and checking the emission-policy walk. */
#define PKM_KMES_EVENT_TYPES_WANT_TABLES
#include "../kmes/event_policy.h"

#include "kunit_common.h"

#define PKM_LCS_KUNIT_KMES_CONFIG_REJECTED "kmes.config.value.rejected"
#define PKM_LCS_KUNIT_KMES_SWAP_FAILED "kmes.buffer.swap.failed"

/*
 * The msgpack every kmes.config.value.rejected payload opens with:
 * {config: {key: {path: "Machine\System\KMES"}, ...}} -- one top-level key,
 * five under config. Literal pieces are split so no hex escape runs on into
 * the text after it.
 */
#define PKM_LCS_KUNIT_KMES_CONFIG_PREFIX \
	"\x81" "\xa6" "config" "\x85" \
	"\xa3" "key" "\x81" "\xa4" "path" "\xb3" "Machine\\System\\KMES"

/*
 * Match the latest KMES-origin event of @event_type against @expected, the
 * whole payload byte for byte. Its fields are nested maps, one per path
 * segment, so an exact payload is what pins every map's size and every
 * field's path; a substring search could not.
 */
static void pkm_lcs_kunit_kmes_expect_latest_payload(
	struct kunit *test, const char *event_type, const u8 *expected,
	size_t expected_len)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };
	size_t written = 0;
	u32 header_size;
	u8 *buffer;

	buffer = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_KMES, event_type, strlen(event_type),
				buffer, 1024, &written, &snapshot),
			0);
	KUNIT_ASSERT_GT(test, written, (size_t)KMES_EVENT_HEADER_BASE_SIZE);
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_KMES);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_LE(test, (size_t)header_size, written);
	KUNIT_ASSERT_EQ(test, written - header_size, expected_len);
	KUNIT_EXPECT_MEMEQ(test, buffer + header_size, expected, expected_len);
}


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
	/*
	 * 65537 is in range but not a power of two: out-of-range, with what
	 * was received and the 4 MiB default retained.
	 */
	static const u8 expected[] =
		PKM_LCS_KUNIT_KMES_CONFIG_PREFIX
		"\xa4" "name" "\xae" "BufferCapacity"
		"\xa8" "expected" "\x83"
		"\xa4" "type" "\x0b"
		"\xa3" "min" "\xce\x00\x01\x00\x00"
		"\xa3" "max" "\xce\x10\x00\x00\x00"
		"\xa8" "received" "\x82"
		"\xa4" "kind" "\xac" "out-of-range"
		"\xa5" "value" "\xce\x00\x01\x00\x01"
		"\xa5" "value" "\xce\x00\x40\x00\x00";
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
	pkm_lcs_kunit_kmes_expect_latest_payload(
		test, PKM_LCS_KUNIT_KMES_CONFIG_REJECTED, expected,
		sizeof(expected) - 1);

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
	/* 64 KiB asked for, the 4 MiB default kept, and -ENOMEM signed. */
	static const u8 expected[] =
		"\x82" "\xa6" "buffer" "\x82"
		"\xb2" "capacity-requested" "\xce\x00\x01\x00\x00"
		"\xa8" "capacity" "\xce\x00\x40\x00\x00"
		"\xa7" "outcome" "\x81" "\xa5" "errno" "\xf4";
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kmes_kunit_reset_all();
	pkm_kmes_kunit_fail_next_swap_alloc();

	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-ENOMEM);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity,
			4ULL * 1024ULL * 1024ULL);
	pkm_lcs_kunit_kmes_expect_latest_payload(
		test, PKM_LCS_KUNIT_KMES_SWAP_FAILED, expected,
		sizeof(expected) - 1);

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
 * kmes.config.value.rejected events -- the number of keys. A plan needing
 * a fifth is refused before anything is applied or emitted; a plan with
 * exactly four emits all four and applies.
 */
static void pkm_lcs_kunit_kmes_publish_caps_reports_at_four(struct kunit *test)
{
	static const char invalid_type[] = PKM_LCS_KUNIT_KMES_CONFIG_REJECTED;
	/* The last of the four: missing, so received carries the kind alone. */
	static const u8 expected[] =
		PKM_LCS_KUNIT_KMES_CONFIG_PREFIX
		"\xa4" "name" "\xb5" "MaxEmitRatePerProcess"
		"\xa8" "expected" "\x83"
		"\xa4" "type" "\x04"
		"\xa3" "min" "\x64"
		"\xa3" "max" "\xce\x00\x0f\x42\x40"
		"\xa8" "received" "\x81"
		"\xa4" "kind" "\xa7" "missing"
		"\xa5" "value" "\x01";
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
	pkm_lcs_kunit_kmes_expect_latest_payload(test, invalid_type, expected,
						 sizeof(expected) - 1);

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
	static const char invalid_type[] = PKM_LCS_KUNIT_KMES_CONFIG_REJECTED;
	static const u8 expected[] =
		PKM_LCS_KUNIT_KMES_CONFIG_PREFIX
		"\xa4" "name" "\xac" "MaxEventSize"
		"\xa8" "expected" "\x83"
		"\xa4" "type" "\x04"
		"\xa3" "min" "\xcd\x04\x00"
		"\xa3" "max" "\xce\x00\x40\x00\x00"
		"\xa8" "received" "\x81"
		"\xa4" "kind" "\xa7" "missing"
		"\xa5" "value" "\xce\x00\x01\x00\x00";
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
	pkm_lcs_kunit_kmes_expect_latest_payload(test, invalid_type, expected,
						 sizeof(expected) - 1);

	pkm_kmes_kunit_reset_all();
}

/* --- kmes.config.applied and kmes.config.refresh.failed ---------------- */

/*
 * PKM *config.applied-event. A read that reaches the commit is recorded with
 * its four counts and the capacity and rate in force afterwards.
 */
static void pkm_lcs_kunit_kmes_config_applied_reports_counts(
	struct kunit *test)
{
	static const char applied_type[] = "kmes.config.applied";
	static const char buffer_capacity_name[] = "BufferCapacity";
	static const char nesting_name[] = "MaxNestingDepth";
	static const char unknown_name[] = "Mystery";
	/* 1 applied, 2 missing, 1 invalid, 1 unknown; 4 MiB and 10 000 kept. */
	static const u8 expected[] =
		"\x83"
		"\xa6" "config" "\x82"
		"\xa3" "key" "\x81" "\xa4" "path" "\xb3" "Machine\\System\\KMES"
		"\xa6" "counts" "\x84"
		"\xa7" "applied" "\x01"
		"\xb0" "retained-missing" "\x02"
		"\xb0" "retained-invalid" "\x01"
		"\xaf" "ignored-unknown" "\x01"
		"\xa6" "buffer" "\x81" "\xa8" "capacity" "\xce\x00\x40\x00\x00"
		"\xa8" "emission" "\x81" "\xaa" "rate-limit" "\xcd\x27\x10";
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

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_runtime_config_apply_self_config(
				entries, ARRAY_SIZE(entries), &plan),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(test, applied_type),
			1U);
	pkm_lcs_kunit_kmes_expect_latest_payload(test, applied_type, expected,
						 sizeof(expected) - 1);
	pkm_kmes_kunit_reset_all();
}

/*
 * PKM *config.applied-after-failed-swap. A capacity swap that fails still
 * leaves the read recorded as applied -- the other settings committed --
 * with the capacity kept, beside the swap's own record.
 */
static void pkm_lcs_kunit_kmes_config_applied_after_failed_swap(
	struct kunit *test)
{
	static const char applied_type[] = "kmes.config.applied";
	static const u8 capacity_kept[] =
		"\xa6" "buffer" "\x81" "\xa8" "capacity" "\xce\x00\x40\x00\x00";
	struct pkm_kmes_self_config_apply_plan plan = { };
	struct pkm_kmes_runtime_config snapshot = { };
	u8 *buffer;
	size_t written = 0;
	u32 header_size;
	size_t i;
	bool found = false;

	buffer = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	pkm_kmes_kunit_reset_all();
	plan.config = (struct pkm_kmes_runtime_config) {
		.buffer_capacity = 65536ULL,
		.max_event_size = 2048U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	plan.applied_count = 2U;
	pkm_kmes_kunit_fail_next_swap_alloc();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_publish_self_config_plan(&plan, NULL),
			(long)-ENOMEM);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 2048U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(
				test, PKM_LCS_KUNIT_KMES_SWAP_FAILED),
			1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_KMES, applied_type,
				sizeof(applied_type) - 1, buffer, 1024, &written,
				NULL),
			0);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_LE(test, (size_t)header_size, written);
	for (i = header_size; i + sizeof(capacity_kept) - 1 <= written; i++) {
		if (!memcmp(buffer + i, capacity_kept,
			    sizeof(capacity_kept) - 1)) {
			found = true;
			break;
		}
	}
	KUNIT_EXPECT_TRUE(test, found);
	pkm_kmes_kunit_reset_all();
}

/*
 * {config: {key: {path}}, outcome: {errno}} for an errno in -128..-1: a
 * negative fixint down to -32, an int 8 below it, as KMES writes them.
 */
static size_t pkm_lcs_kunit_refresh_failed_payload(u8 *out, size_t out_len,
						   const char *path, long error)
{
	static const u8 head[] = "\x82" "\xa6" "config" "\x81" "\xa3" "key"
				 "\x81" "\xa4" "path";
	static const u8 tail[] = "\xa7" "outcome" "\x81" "\xa5" "errno";
	size_t path_len = strlen(path);
	size_t len = 0;

	if (path_len > 31 || error < -128 || error >= 0 ||
	    out_len < sizeof(head) + path_len + sizeof(tail) + 3)
		return 0;
	memcpy(out, head, sizeof(head) - 1);
	len = sizeof(head) - 1;
	out[len++] = (u8)(0xa0 | path_len);
	memcpy(out + len, path, path_len);
	len += path_len;
	memcpy(out + len, tail, sizeof(tail) - 1);
	len += sizeof(tail) - 1;
	if (error < -32)
		out[len++] = 0xd0;
	out[len++] = (u8)(s8)error;
	return len;
}

/*
 * PKM *config.refresh-failed-event. A re-read of Machine\System\KMES that
 * fails -- here because no source is registered to answer it -- keeps the
 * configuration in force and is recorded with the key and the errno.
 */
static void pkm_lcs_kunit_kmes_config_refresh_failure_is_recorded(
	struct kunit *test)
{
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0x9a };
	static const char failed_type[] = "kmes.config.refresh.failed";
	struct pkm_kmes_runtime_config active = {
		.buffer_capacity = 4ULL * 1024ULL * 1024ULL,
		.max_event_size = 2048U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = 10000U,
	};
	struct pkm_kmes_runtime_config snapshot = { };
	u8 expected[64];
	size_t expected_len;
	long ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_kunit_reset_source_table();
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&active), 0L);

	/* No registered source: the round trip fails, typically -EIO. */
	ret = pkm_kmes_runtime_config_refresh_on_change(7, kmes_guid);
	KUNIT_EXPECT_LT(test, ret, 0L);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_snapshot(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 2048U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_kmes_count_origin_events(test, failed_type),
			1U);
	expected_len = pkm_lcs_kunit_refresh_failed_payload(
		expected, sizeof(expected), "Machine\\System\\KMES", ret);
	KUNIT_ASSERT_GT(test, expected_len, (size_t)0);
	pkm_lcs_kunit_kmes_expect_latest_payload(test, failed_type, expected,
						 expected_len);
	pkm_kmes_kunit_reset_all();
}

/* --- the emission policy ------------------------------------------------ */

/* The trie node a dotted @path names, or -1. */
static int pkm_lcs_kunit_event_node(const char *path)
{
	const char *seg = path;
	int parent = -1;

	while (*seg) {
		const char *dot = strchrnul(seg, '.');
		size_t len = dot - seg;
		int found = -1;
		u32 i;

		for (i = 0; i < PKM_KMES_EV_NODE_COUNT; i++) {
			const struct pkm_kmes_event_node *node =
				&pkm_kmes_event_nodes[i];

			if (node->parent == parent && node->segment_len == len &&
			    !memcmp(node->segment, seg, len)) {
				found = (int)i;
				break;
			}
		}
		if (found < 0)
			return -1;
		parent = found;
		seg = *dot ? dot + 1 : dot;
	}
	return parent;
}

/* Whether the type @name is @prefix or beneath it. */
static bool pkm_lcs_kunit_event_under(const char *name, const char *prefix)
{
	size_t len = strlen(prefix);

	return !strncmp(name, prefix, len) &&
	       (name[len] == '\0' || name[len] == '.');
}

static void pkm_lcs_kunit_event_nodes_clear(
	struct pkm_kmes_event_policy_node_state *nodes)
{
	u32 i;

	for (i = 0; i < PKM_KMES_EV_NODE_COUNT; i++) {
		nodes[i].present = false;
		nodes[i].setting = PKM_KMES_EVENT_SETTING_ABSENT;
	}
}

static bool pkm_lcs_kunit_event_essential(u32 id)
{
	return pkm_kmes_event_tier((enum pkm_kmes_event_id)id) ==
	       PKM_KMES_EV_TIER_ESSENTIAL;
}

static bool pkm_lcs_kunit_event_tier_default(u32 id)
{
	enum pkm_kmes_event_tier tier =
		pkm_kmes_event_tier((enum pkm_kmes_event_id)id);

	return tier == PKM_KMES_EV_TIER_ESSENTIAL ||
	       tier == PKM_KMES_EV_TIER_STANDARD;
}

/*
 * PKM *policy.resolution. PGSS §6.9's procedure, checked for every kernel
 * type at once: the deepest Enabled on a type's path wins, a value on Events
 * covers what the keys beneath do not decide, a key whose parent does not
 * exist decides nothing, and with nothing set the tier decides. The cases
 * are §6.9's own example tree and its variants.
 */
static void pkm_lcs_kunit_kmes_event_policy_resolution_table(
	struct kunit *test)
{
	struct pkm_kmes_event_policy_node_state *nodes;
	int kacs = pkm_lcs_kunit_event_node("kacs");
	int audit = pkm_lcs_kunit_event_node("kacs.audit");
	int caap = pkm_lcs_kunit_event_node("kacs.caap");
	int staging = pkm_lcs_kunit_event_node("kacs.caap.staging");
	int diverged = pkm_lcs_kunit_event_node("kacs.caap.staging.diverged");
	u64 expected;
	u64 mask;
	u32 i;

	KUNIT_ASSERT_GE(test, kacs, 0);
	KUNIT_ASSERT_GE(test, audit, 0);
	KUNIT_ASSERT_GE(test, caap, 0);
	KUNIT_ASSERT_GE(test, staging, 0);
	KUNIT_ASSERT_GE(test, diverged, 0);
	nodes = kunit_kcalloc(test, PKM_KMES_EV_NODE_COUNT, sizeof(*nodes),
			      GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, nodes);

	/* Nothing anywhere: the tier decides, which is the default mask. */
	pkm_lcs_kunit_event_nodes_clear(nodes);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_resolve(
				PKM_KMES_EVENT_SETTING_ABSENT, nodes,
				PKM_KMES_EV_NODE_COUNT),
			PKM_KMES_EV_DEFAULT_MASK);

	/* §6.9's example: nothing on Events, kacs = 0, kacs\audit = 1. */
	nodes[kacs] = (struct pkm_kmes_event_policy_node_state){
		true, PKM_KMES_EVENT_SETTING_OFF };
	nodes[audit] = (struct pkm_kmes_event_policy_node_state){
		true, PKM_KMES_EVENT_SETTING_ON };
	mask = pkm_kmes_event_policy_resolve(PKM_KMES_EVENT_SETTING_ABSENT,
					     nodes, PKM_KMES_EV_NODE_COUNT);
	expected = 0;
	for (i = 0; i < PKM_KMES_EV_COUNT; i++) {
		const char *name = pkm_kmes_event_names[i];
		bool on;

		if (pkm_lcs_kunit_event_essential(i) ||
		    pkm_lcs_kunit_event_under(name, "kacs.audit"))
			on = true;
		else if (pkm_lcs_kunit_event_under(name, "kacs"))
			on = false;
		else
			on = pkm_lcs_kunit_event_tier_default(i);
		if (on)
			expected |= BIT_ULL(i);
	}
	KUNIT_EXPECT_EQ(test, mask, expected);

	/* The same with Enabled = 0 on Events: only kacs\audit stays on. */
	mask = pkm_kmes_event_policy_resolve(PKM_KMES_EVENT_SETTING_OFF, nodes,
					     PKM_KMES_EV_NODE_COUNT);
	expected = 0;
	for (i = 0; i < PKM_KMES_EV_COUNT; i++) {
		if (pkm_lcs_kunit_event_essential(i) ||
		    pkm_lcs_kunit_event_under(pkm_kmes_event_names[i],
					      "kacs.audit"))
			expected |= BIT_ULL(i);
	}
	KUNIT_EXPECT_EQ(test, mask, expected);

	/* The type's own key counts, and beats kacs = 0 above it. */
	nodes[caap] = (struct pkm_kmes_event_policy_node_state){
		true, PKM_KMES_EVENT_SETTING_ABSENT };
	nodes[staging] = (struct pkm_kmes_event_policy_node_state){
		true, PKM_KMES_EVENT_SETTING_ABSENT };
	nodes[diverged] = (struct pkm_kmes_event_policy_node_state){
		true, PKM_KMES_EVENT_SETTING_ON };
	mask = pkm_kmes_event_policy_resolve(PKM_KMES_EVENT_SETTING_OFF, nodes,
					     PKM_KMES_EV_NODE_COUNT);
	KUNIT_EXPECT_TRUE(test,
			  mask & BIT_ULL(PKM_KMES_EV_KACS_CAAP_STAGING_DIVERGED));
	KUNIT_EXPECT_EQ(test,
			mask & ~BIT_ULL(PKM_KMES_EV_KACS_CAAP_STAGING_DIVERGED),
			expected &
				~BIT_ULL(PKM_KMES_EV_KACS_CAAP_STAGING_DIVERGED));

	/*
	 * A missing key ends the walk: with kacs\caap absent, what a
	 * descendant claims is ignored and kacs = 0 decides.
	 */
	nodes[caap].present = false;
	nodes[diverged] = (struct pkm_kmes_event_policy_node_state){
		true, PKM_KMES_EVENT_SETTING_ON };
	mask = pkm_kmes_event_policy_resolve(PKM_KMES_EVENT_SETTING_ABSENT,
					     nodes, PKM_KMES_EV_NODE_COUNT);
	KUNIT_EXPECT_EQ(test,
			!!(mask & BIT_ULL(PKM_KMES_EV_KACS_CAAP_STAGING_DIVERGED)),
			pkm_lcs_kunit_event_essential(
				PKM_KMES_EV_KACS_CAAP_STAGING_DIVERGED));

	/* A table of the wrong shape publishes nothing but the defaults. */
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_resolve(
				PKM_KMES_EVENT_SETTING_OFF, nodes,
				PKM_KMES_EV_NODE_COUNT - 1),
			PKM_KMES_EV_DEFAULT_MASK);
}

/*
 * PKM *policy.enabled-dword-only. Only a REG_DWORD of 0 or 1 is a setting;
 * any other number, type or length is ignored as though absent.
 */
static void pkm_lcs_kunit_kmes_event_policy_enabled_values(struct kunit *test)
{
	static const s8 absent = PKM_KMES_EVENT_SETTING_ABSENT;
	u8 dword[4];
	u8 qword[8];

	put_unaligned_le32(0, dword);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(REG_DWORD, dword, 4,
							   absent),
			(s8)PKM_KMES_EVENT_SETTING_OFF);
	put_unaligned_le32(1, dword);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(REG_DWORD, dword, 4,
							   absent),
			(s8)PKM_KMES_EVENT_SETTING_ON);
	/* Ignored values keep what was found above. */
	put_unaligned_le32(2, dword);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(
				REG_DWORD, dword, 4, PKM_KMES_EVENT_SETTING_OFF),
			(s8)PKM_KMES_EVENT_SETTING_OFF);
	put_unaligned_le32(1, dword);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(REG_DWORD, dword, 3,
							   absent),
			absent);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(
				REG_DWORD_BIG_ENDIAN, dword, 4, absent),
			absent);
	put_unaligned_le64(1, qword);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(REG_QWORD, qword, 8,
							   absent),
			absent);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_event_policy_read_enabled(REG_SZ,
							   (const u8 *)"1", 2,
							   absent),
			absent);
}

/*
 * PKM *policy.early-boot-tier-defaults. Before any walk the mask is the
 * tier defaults -- every essential and standard type on, every verbose and
 * debug type off -- and resetting the policy returns to them.
 */
static void pkm_lcs_kunit_kmes_event_policy_early_boot_defaults(
	struct kunit *test)
{
	u32 i;

	for (i = 0; i < PKM_KMES_EV_COUNT; i++)
		KUNIT_EXPECT_EQ(test,
				!!(PKM_KMES_EV_DEFAULT_MASK & BIT_ULL(i)),
				pkm_lcs_kunit_event_tier_default(i));
	KUNIT_EXPECT_EQ(test, PKM_KMES_EV_DEFAULT_MASK >> PKM_KMES_EV_COUNT,
			0ULL);

	pkm_kmes_event_policy_kunit_publish(0);
	pkm_kmes_event_policy_kunit_reset();
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_mask(),
			PKM_KMES_EV_DEFAULT_MASK);
	for (i = 0; i < PKM_KMES_EV_COUNT; i++)
		KUNIT_EXPECT_EQ(test, pkm_kmes_event_enabled_ffi(i),
				pkm_lcs_kunit_event_tier_default(i));
}

/*
 * PKM *policy.essential-never-consults. With every bit of the mask clear,
 * an essential type is still on -- the check folds to true for it -- and
 * every other type is off. An id outside the table is never hidden.
 */
static void pkm_lcs_kunit_kmes_event_policy_essential_fold(struct kunit *test)
{
	u32 i;

	pkm_kmes_event_policy_kunit_publish(0);
	KUNIT_EXPECT_TRUE(test, pkm_kmes_event_enabled(
					PKM_KMES_EV_KACS_AUDIT_ACCESS_CHECKED));
	KUNIT_EXPECT_TRUE(test, pkm_kmes_event_enabled(
					PKM_KMES_EV_KMES_CONFIG_REFRESH_FAILED));
	KUNIT_EXPECT_FALSE(test, pkm_kmes_event_enabled(
					 PKM_KMES_EV_KMES_CONFIG_APPLIED));
	for (i = 0; i < PKM_KMES_EV_COUNT; i++)
		KUNIT_EXPECT_EQ(test, pkm_kmes_event_enabled_ffi(i),
				pkm_lcs_kunit_event_essential(i));
	KUNIT_EXPECT_TRUE(test, pkm_kmes_event_enabled_ffi(PKM_KMES_EV_COUNT));

	pkm_kmes_event_policy_kunit_publish(~0ULL);
	for (i = 0; i < PKM_KMES_EV_COUNT; i++)
		KUNIT_EXPECT_TRUE(test, pkm_kmes_event_enabled_ffi(i));
	pkm_kmes_event_policy_kunit_reset();
}

/*
 * The source side of a policy walk: Events holds Enabled = 1, kacs exists
 * with Enabled = 0, and nothing else exists. The lookups are served in the
 * order the walk makes them, read from the generated trie, so the script
 * follows the table when types are added.
 */
struct pkm_lcs_kunit_event_policy_script {
	struct file *file;
	const u8 *events_guid;
	const u8 *kacs_guid;
	int kacs_node;
	u8 root_data[4];
	u8 kacs_data[4];
	u32 lookups;
	u32 reads;
	u32 writes;
	int result;
};

static int pkm_lcs_kunit_event_policy_serve_query(
	struct pkm_lcs_kunit_event_policy_script *script, const u8 *guid,
	const u8 *data)
{
	struct pkm_lcs_kunit_query_values_source_script query = {
		.file = script->file,
		.expected_guid = guid,
		.expected_value_name = "",
		.response_value_name = "Enabled",
		.layer_name = "base",
		.data = data,
		.data_len = 4,
		.value_type = REG_DWORD,
		.query_all = true,
	};
	int ret;

	ret = pkm_lcs_kunit_query_values_source_thread(&query);
	script->reads += query.reads;
	script->writes += query.writes;
	return ret;
}

static int pkm_lcs_kunit_event_policy_source_thread(void *raw)
{
	struct pkm_lcs_kunit_event_policy_script *script = raw;
	int ret;
	u32 i;

	ret = pkm_lcs_kunit_event_policy_serve_query(
		script, script->events_guid, script->root_data);
	if (ret)
		goto out;

	for (i = 0; i < PKM_KMES_EV_NODE_COUNT; i++) {
		const struct pkm_kmes_event_node *node =
			&pkm_kmes_event_nodes[i];
		struct pkm_lcs_kunit_walk_source_step step = {
			.expected_child = node->segment,
		};
		struct pkm_lcs_kunit_walk_source_script walk = {
			.file = script->file,
			.steps = &step,
			.step_count = 1,
		};

		/* Only the roots and kacs's children are looked up. */
		if (node->parent != -1 && node->parent != script->kacs_node)
			continue;
		if ((int)i == script->kacs_node)
			step.guid = script->kacs_guid;
		else
			step.empty = true;
		ret = pkm_lcs_kunit_walk_source_thread(&walk);
		script->reads += walk.reads;
		script->writes += walk.writes;
		script->lookups++;
		if (ret)
			goto out;
		if ((int)i == script->kacs_node) {
			ret = pkm_lcs_kunit_event_policy_serve_query(
				script, script->kacs_guid, script->kacs_data);
			if (ret)
				goto out;
		}
	}
out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}

/*
 * PKM *policy.walk-publishes and *policy.missing-key-ends-walk. One walk
 * reads Events, looks up each root, and descends only into the root that
 * exists: kacs, whose Enabled = 0 switches its non-essential types off
 * while Events' Enabled = 1 switches every other type on, verbose and debug
 * included. Nothing beneath a missing root is asked for.
 */
static void pkm_lcs_kunit_kmes_event_policy_walk_publishes(struct kunit *test)
{
	static const u8 events_guid[RSI_GUID_SIZE] = { 0xe1, 0x01 };
	static const u8 kacs_guid[RSI_GUID_SIZE] = { 0xe1, 0x02 };
	struct pkm_lcs_kunit_event_policy_script script = {
		.events_guid = events_guid,
		.kacs_guid = kacs_guid,
		.kacs_node = pkm_lcs_kunit_event_node("kacs"),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 expected_lookups = 0;
	u64 expected = 0;
	long ret;
	int thread_ret;
	u32 i;

	KUNIT_ASSERT_GE(test, script.kacs_node, 0);
	for (i = 0; i < PKM_KMES_EV_NODE_COUNT; i++) {
		s16 parent = pkm_kmes_event_nodes[i].parent;

		if (parent == -1 || parent == script.kacs_node)
			expected_lookups++;
	}
	for (i = 0; i < PKM_KMES_EV_COUNT; i++) {
		if (pkm_lcs_kunit_event_essential(i) ||
		    !pkm_lcs_kunit_event_under(pkm_kmes_event_names[i], "kacs"))
			expected |= BIT_ULL(i);
	}
	put_unaligned_le32(1, script.root_data);
	put_unaligned_le32(0, script.kacs_data);

	pkm_kmes_kunit_reset_all();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_event_policy_source_thread, &script,
		"pkm-lcs-kunit-event-policy-walk");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_kmes_event_policy_refresh_from_key(1, events_guid);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.lookups, expected_lookups);
	/* Two queries (Events, kacs) and one round trip per lookup. */
	KUNIT_EXPECT_EQ(test, script.reads, expected_lookups + 2U);
	KUNIT_EXPECT_EQ(test, script.writes, expected_lookups + 2U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_mask(), expected);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_kmes_kunit_reset_all();
}

/*
 * PKM *policy.failed-walk-keeps-mask. A walk the source cannot answer
 * publishes nothing: the mask in force stays, and the failure is recorded
 * as kmes.config.refresh.failed naming Machine\Generic\Events.
 */
static void pkm_lcs_kunit_kmes_event_policy_failed_walk_keeps_mask(
	struct kunit *test)
{
	static const u8 events_guid[RSI_GUID_SIZE] = { 0xe1, 0x03 };
	static const char failed_type[] = "kmes.config.refresh.failed";
	u64 kept = PKM_KMES_EV_DEFAULT_MASK &
		   ~BIT_ULL(PKM_KMES_EV_KMES_CONFIG_APPLIED);
	u8 expected[64];
	size_t expected_len;
	long ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_kunit_reset_source_table();
	pkm_kmes_event_policy_kunit_publish(kept);

	/* No registered source: the first round trip fails, typically -EIO. */
	ret = pkm_kmes_event_policy_refresh_from_key(7, events_guid);
	KUNIT_EXPECT_LT(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_mask(), kept);
	expected_len = pkm_lcs_kunit_refresh_failed_payload(
		expected, sizeof(expected), PKM_KMES_EVENT_POLICY_KEY_PATH, ret);
	KUNIT_ASSERT_GT(test, expected_len, (size_t)0);
	pkm_lcs_kunit_kmes_expect_latest_payload(test, failed_type, expected,
						 expected_len);
	pkm_kmes_kunit_reset_all();
}

/*
 * PKM *policy.watch-filtered-to-kernel-roots. The internal watch on Events
 * queues a re-walk for a change to Enabled on Events itself or beneath a
 * kernel root, and for a kernel root appearing; a vendor key under
 * Events\org, or a value that is not Enabled, queues nothing.
 */
static void pkm_lcs_kunit_kmes_event_policy_watch_filter(struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0xe2, 0x01 };
	static const char * const vendor_path[] = {
		"Machine", "Generic", "Events", "org",
	};
	static const char * const kacs_path[] = {
		"Machine", "Generic", "Events", "kacs",
	};
	static const char * const events_path[] = {
		"Machine", "Generic", "Events",
	};
	static const u8 ancestors[4][RSI_GUID_SIZE] = {
		{ 0xe2, 0x01 }, { 0xe2, 0x02 }, { 0xe2, 0x03 }, { 0xe2, 0x04 },
	};
	/* Registry, Layers, KMES, port reservations and Network: elsewhere. */
	static const u8 other_keys[5][RSI_GUID_SIZE] = {
		{ 0xe3, 0x01 }, { 0xe3, 0x02 }, { 0xe3, 0x03 }, { 0xe3, 0x04 },
		{ 0xe3, 0x05 },
	};
	static const char enabled[] = "Enabled";
	static const char other[] = "Comment";
	static const char vendor[] = "org";
	static const char root[] = "NTFE";
	struct pkm_lcs_watch_dispatch_context context = {
		.ancestor_guids = ancestors,
		.event_type = REG_WATCH_VALUE_SET,
	};
	u64 noted;

	pkm_kmes_event_policy_kunit_reset();
	pkm_lcs_internal_self_watch_disarm();
	/*
	 * Every key present, so no machine-root fallback is armed: it would
	 * fire on the subkey creations below and re-run the bootstrap.
	 */
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_internal_self_watch_arm_full(
				1, machine_root_guid, true, other_keys[0], true,
				other_keys[1], true, other_keys[2], true,
				other_keys[3], true, other_keys[4], true,
				ancestors[2], NULL),
			0L);

	/*
	 * What the watch passes on is counted as it is noted, before the
	 * debounced walk (which finds no source here and fails harmlessly);
	 * the count does not depend on when that walk runs.
	 */
	noted = pkm_kmes_event_policy_kunit_changes_noted();

	/* Enabled under a vendor root: dropped. */
	context.changed_key_guid = ancestors[3];
	context.resolved_path = vendor_path;
	context.path_component_count = ARRAY_SIZE(vendor_path);
	context.name = (const u8 *)enabled;
	context.name_len = sizeof(enabled) - 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_kunit_changes_noted(), noted);

	/* Another value under a kernel root: dropped. */
	context.resolved_path = kacs_path;
	context.name = (const u8 *)other;
	context.name_len = sizeof(other) - 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_kunit_changes_noted(), noted);

	/* A vendor key appearing under Events: dropped. */
	context.changed_key_guid = ancestors[2];
	context.resolved_path = events_path;
	context.path_component_count = ARRAY_SIZE(events_path);
	context.event_type = REG_WATCH_SUBKEY_CREATED;
	context.name = (const u8 *)vendor;
	context.name_len = sizeof(vendor) - 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_kunit_changes_noted(), noted);

	/* A kernel root appearing, in any case: passed on. */
	context.name = (const u8 *)root;
	context.name_len = sizeof(root) - 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_kunit_changes_noted(),
			noted + 1);

	/* Enabled under a kernel root: passed on. */
	context.changed_key_guid = ancestors[3];
	context.resolved_path = kacs_path;
	context.path_component_count = ARRAY_SIZE(kacs_path);
	context.event_type = REG_WATCH_VALUE_SET;
	context.name = (const u8 *)enabled;
	context.name_len = sizeof(enabled) - 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_kunit_changes_noted(),
			noted + 2);

	/* Enabled on Events itself: passed on. */
	context.changed_key_guid = ancestors[2];
	context.resolved_path = events_path;
	context.path_component_count = ARRAY_SIZE(events_path);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kmes_event_policy_kunit_changes_noted(),
			noted + 3);

	pkm_lcs_internal_self_watch_disarm();
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
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_applied_reports_counts),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_applied_after_failed_swap),
	KUNIT_CASE(pkm_lcs_kunit_kmes_config_refresh_failure_is_recorded),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_resolution_table),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_enabled_values),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_early_boot_defaults),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_essential_fold),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_walk_publishes),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_failed_walk_keeps_mask),
	KUNIT_CASE(pkm_lcs_kunit_kmes_event_policy_watch_filter),
	{}
};

static struct kunit_suite pkm_lcs_kunit_kmes_suite = {
	.name = "pkm_lcs_kunit_kmes",
	.test_cases = pkm_lcs_kunit_kmes_cases,
};

kunit_test_suite(pkm_lcs_kunit_kmes_suite);
