// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_symlink_target_materializes_literal_current_user(
	struct kunit *test)
{
	static const char target[] = "CurrentUser\\Software";
	struct pkm_lcs_materialized_path path = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_materialize_symlink_target_components(
				target, sizeof(target) - 1, &path),
			0L);
	KUNIT_ASSERT_EQ(test, path.component_count, 2U);
	KUNIT_ASSERT_NOT_NULL(test, path.components);
	KUNIT_EXPECT_EQ(test, path.components[0].name_len, 11U);
	KUNIT_EXPECT_EQ(test,
			memcmp(path.components[0].name, "CurrentUser", 11),
			0);
	KUNIT_EXPECT_EQ(test, path.components[1].name_len, 8U);
	KUNIT_EXPECT_EQ(test,
			memcmp(path.components[1].name, "Software", 8),
			0);

	pkm_lcs_materialized_path_destroy(&path);
}


static void pkm_lcs_kunit_symlink_target_resolution_success(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = link_guid,
		.expected_value_name = "",
		.value_type = REG_LINK,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_symlink_target_resolution resolution = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-symlink-target");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_resolve_symlink_target_for_key(
		1, 0, link_guid, NULL, 0, layers, ARRAY_SIZE(layers), NULL,
		0, NULL, &resolution);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, resolution.route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, resolution.route.root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, resolution.value_type, (u32)REG_LINK);
	KUNIT_EXPECT_EQ(test, resolution.selected_precedence, 0U);
	KUNIT_EXPECT_EQ(test, resolution.selected_sequence, 0ULL);
	KUNIT_ASSERT_EQ(test, resolution.components.component_count, 2U);
	KUNIT_EXPECT_EQ(test, resolution.components.components[0].name_len, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(resolution.components.components[0].name,
			       "Machine", 7),
			0);
	KUNIT_EXPECT_EQ(test, resolution.components.components[1].name_len, 6U);
	KUNIT_EXPECT_EQ(test,
			memcmp(resolution.components.components[1].name,
			       "Target", 6),
			0);

	pkm_lcs_symlink_target_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_symlink_target_resolution_non_link_einval(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = link_guid,
		.expected_value_name = "",
		.value_type = REG_SZ,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_symlink_target_resolution resolution = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-symlink-nonlink");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_resolve_symlink_target_for_key(
		1, 0, link_guid, NULL, 0, layers, ARRAY_SIZE(layers), NULL,
		0, NULL, &resolution);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_PTR_EQ(test, resolution.components.components, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_symlink_target_resolution_bad_target_einval(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 target[] = "Machine\\\\Target";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = link_guid,
		.expected_value_name = "",
		.value_type = REG_LINK,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_symlink_target_resolution resolution = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-symlink-badtarget");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_resolve_symlink_target_for_key(
		1, 0, link_guid, NULL, 0, layers, ARRAY_SIZE(layers), NULL,
		0, NULL, &resolution);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_PTR_EQ(test, resolution.components.components, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_symlink_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_materializes_literal_current_user),
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_resolution_success),
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_resolution_non_link_einval),
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_resolution_bad_target_einval),
	{}
};

static struct kunit_suite pkm_lcs_kunit_symlink_suite = {
	.name = "pkm_lcs_kunit_symlink",
	.test_cases = pkm_lcs_kunit_symlink_cases,
};

kunit_test_suite(pkm_lcs_kunit_symlink_suite);
