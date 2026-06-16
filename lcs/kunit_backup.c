// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_backup_audit_payload_abi_rejects_bad_state(
	struct kunit *test)
{
	static const u8 malformed_sid[] = { 0x01, 0x01 };
	static const u8 key_guid[16] = {
		0x45, 0x45, 0x03, 0x03, 0x45, 0x45, 0x03, 0x03,
		0x45, 0x45, 0x03, 0x03, 0x45, 0x45, 0x03, 0x03,
	};
	struct pkm_lcs_kunit_audit_caller_summary caller = {
		.effective_token_guid = { 1 },
		.true_token_guid = { 2 },
		.process_guid = { 3 },
		.user_sid = malformed_sid,
		.user_sid_len = sizeof(malformed_sid),
		.authentication_id = 10,
		.token_id = 11,
		.token_type = 1,
		.impersonation_level = 0,
		.integrity_level = 8192,
	};
	size_t written = 0;

	KUNIT_EXPECT_EQ(test,
			lcs_rust_backup_start_audit_payload(
				&caller, key_guid, 7, NULL, 0, &written),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			lcs_rust_backup_complete_audit_payload(
				&caller, key_guid, EOPNOTSUPP, NULL, 0,
				&written),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			lcs_rust_restore_start_audit_payload(
				&caller, key_guid, 7, NULL, 0, &written),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			lcs_rust_restore_complete_audit_payload(
				&caller, key_guid, EOPNOTSUPP, NULL, 0,
				&written),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
}


static void pkm_lcs_kunit_backup_layer_manifest_base_default_owner(
	struct kunit *test)
{
	u8 *frame = NULL;
	size_t frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame(
				"base", strlen("base"), 0, 1, false, NULL, 0,
				&frame, &frame_len),
			0L);
	pkm_lcs_kunit_expect_layer_manifest_record(
		test, frame, frame_len, "base", 0, 1, pkm_lcs_kunit_system_sid,
		sizeof(pkm_lcs_kunit_system_sid));
	kfree(frame);
}


static void pkm_lcs_kunit_backup_layer_manifest_base_cached_owner(
	struct kunit *test)
{
	static const u8 base_owner_everyone_sd[] = {
		0x01, 0x00, 0x00, 0x80,
		0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	u8 *frame = NULL;
	size_t frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame(
				"base", strlen("base"), 0, 1, true,
				base_owner_everyone_sd,
				sizeof(base_owner_everyone_sd), &frame,
				&frame_len),
			0L);
	pkm_lcs_kunit_expect_layer_manifest_record(
		test, frame, frame_len, "base", 0, 1,
		pkm_lcs_kunit_everyone_sid,
		sizeof(pkm_lcs_kunit_everyone_sid));
	kfree(frame);
}


static void pkm_lcs_kunit_backup_layer_manifest_non_base_cached_owner(
	struct kunit *test)
{
	static const u8 metadata_guid[PKM_LCS_GUID_BYTES] = { 0x9a };
	u8 *frame = NULL;
	size_t frame_len = 0;

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 42, 1,
				metadata_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_everyone_sid,
				sizeof(pkm_lcs_kunit_everyone_sid)),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame(
				"Policy", strlen("Policy"), 42, 1, false, NULL,
				0, &frame, &frame_len),
			0L);
	pkm_lcs_kunit_expect_layer_manifest_record(
		test, frame, frame_len, "Policy", 42, 1,
		pkm_lcs_kunit_everyone_sid,
		sizeof(pkm_lcs_kunit_everyone_sid));
	kfree(frame);
	pkm_lcs_kunit_reset_layer_table();
}


static void pkm_lcs_kunit_backup_layer_manifest_fails_closed(
	struct kunit *test)
{
	static const u8 malformed_sd[] = { 0x01, 0x02, 0x03 };
	u8 *frame = NULL;
	size_t frame_len = 0;

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame(
				"Policy", strlen("Policy"), 42, 1, false, NULL,
				0, &frame, &frame_len),
			(long)-ENOENT);
	KUNIT_EXPECT_PTR_EQ(test, frame, NULL);
	KUNIT_EXPECT_EQ(test, frame_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame(
				"base", strlen("base"), 0, 1, true,
				malformed_sd, sizeof(malformed_sd), &frame,
				&frame_len),
			(long)-EIO);
	KUNIT_EXPECT_PTR_EQ(test, frame, NULL);
	KUNIT_EXPECT_EQ(test, frame_len, (size_t)0);
}


static void pkm_lcs_kunit_backup_layer_manifest_frame_set_order(
	struct kunit *test)
{
	static const u8 metadata_guid[PKM_LCS_GUID_BYTES] = { 0xaa };
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "Policy", .name_len = 6, .precedence = 42,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_backup_layer_ref_view refs[] = {
		{ .layer_index = 0 },
		{ .layer_index = 1 },
	};
	struct pkm_lcs_backup_manifest_frame_summary summary = { };

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 42, 1,
				metadata_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_everyone_sid,
				sizeof(pkm_lcs_kunit_everyone_sid)),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame_set(
				layers, ARRAY_SIZE(layers), refs,
				ARRAY_SIZE(refs), false, NULL, 0, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.frame_count, 2U);
	KUNIT_EXPECT_GT(test, summary.total_len, (size_t)0);
	pkm_lcs_kunit_reset_layer_table();
}


static void pkm_lcs_kunit_backup_layer_manifest_frame_set_fail_closed(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "Policy", .name_len = 6, .precedence = 42,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_backup_layer_ref_view missing_owner[] = {
		{ .layer_index = 0 },
	};
	static const struct pkm_lcs_backup_layer_ref_view bad_index[] = {
		{ .layer_index = 1 },
	};
	struct pkm_lcs_backup_manifest_frame_summary summary = { };

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame_set(
				layers, ARRAY_SIZE(layers), missing_owner,
				ARRAY_SIZE(missing_owner), false, NULL, 0,
				&summary),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, summary.frame_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.total_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_layer_manifest_frame_set(
				layers, ARRAY_SIZE(layers), bad_index,
				ARRAY_SIZE(bad_index), false, NULL, 0,
				&summary),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, summary.frame_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.total_len, (size_t)0);
}


static void pkm_lcs_kunit_backup_path_entry_frames(struct kunit *test)
{
	static const u8 parent_guid[PKM_LCS_GUID_BYTES] = { 0x21 };
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x22 };
	static const u8 hidden_guid[PKM_LCS_GUID_BYTES] = { };
	u8 *frame = NULL;
	size_t frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_path_entry_frame(
				parent_guid, "Child", strlen("Child"),
				child_guid, false, "base", strlen("base"), 77,
				&frame, &frame_len),
			0L);
	pkm_lcs_kunit_expect_path_entry_record(
		test, frame, frame_len, parent_guid, "Child", child_guid,
		"base", 77);
	kfree(frame);
	frame = NULL;
	frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_path_entry_frame(
				parent_guid, "Masked", strlen("Masked"), NULL,
				true, "Overlay", strlen("Overlay"), 88, &frame,
				&frame_len),
			0L);
	pkm_lcs_kunit_expect_path_entry_record(
		test, frame, frame_len, parent_guid, "Masked", hidden_guid,
		"Overlay", 88);
	kfree(frame);
}


static void pkm_lcs_kunit_backup_value_frames(struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x31 };
	static const u8 value_data[] = { 0xde, 0xad, 0xbe, 0xef };
	u8 *frame = NULL;
	size_t frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_value_frame(
				key_guid, "Answer", strlen("Answer"), REG_BINARY,
				value_data, sizeof(value_data), "base",
				strlen("base"), 99, &frame, &frame_len),
			0L);
	pkm_lcs_kunit_expect_value_record(
		test, frame, frame_len, key_guid, "Answer", REG_BINARY,
		value_data, sizeof(value_data), "base", 99);
	kfree(frame);
	frame = NULL;
	frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_value_frame(
				key_guid, "", 0, REG_TOMBSTONE, NULL, 0,
				"Overlay", strlen("Overlay"), 100, &frame,
				&frame_len),
			0L);
	pkm_lcs_kunit_expect_value_record(
		test, frame, frame_len, key_guid, "", REG_TOMBSTONE, NULL, 0,
		"Overlay", 100);
	kfree(frame);
}


static void pkm_lcs_kunit_backup_blanket_tombstone_record(struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x41 };
	u8 *frame = NULL;
	size_t frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_blanket_tombstone_frame(
				key_guid, "Overlay", strlen("Overlay"), 101,
				&frame, &frame_len),
			0L);
	pkm_lcs_kunit_expect_blanket_tombstone_record(
		test, frame, frame_len, key_guid, "Overlay", 101);
	kfree(frame);
}


static void pkm_lcs_kunit_backup_data_frames_fail_closed(struct kunit *test)
{
	static const u8 nil_guid[PKM_LCS_GUID_BYTES] = { };
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x51 };
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u8 tombstone_data[] = { 0x01 };
	u8 *frame = NULL;
	size_t frame_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_path_entry_frame(
				nil_guid, "Child", strlen("Child"), child_guid,
				false, "base", strlen("base"), 1, &frame,
				&frame_len),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, frame, NULL);
	KUNIT_EXPECT_EQ(test, frame_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_value_frame(
				key_guid, "", 0, REG_TOMBSTONE, tombstone_data,
				sizeof(tombstone_data), "base", strlen("base"),
				1, &frame, &frame_len),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, frame, NULL);
	KUNIT_EXPECT_EQ(test, frame_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_blanket_tombstone_frame(
				key_guid, "bad/name", strlen("bad/name"), 1,
				&frame, &frame_len),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, frame, NULL);
	KUNIT_EXPECT_EQ(test, frame_len, (size_t)0);
}


static void pkm_lcs_kunit_backup_query_values_entries_materialize(
	struct kunit *test)
{
	static const u8 data[] = { 0xde, 0xad };
	struct pkm_lcs_backup_value_entry_view values[2] = { };
	struct pkm_lcs_backup_blanket_entry_view blankets[1] = { };
	u8 response[256];
	size_t offset;
	size_t response_len;
	u32 value_count = 0;
	u32 blanket_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 520, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "Alpha", "base",
		REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "", "Overlay",
		REG_TOMBSTONE, NULL, 0, 2);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_blanket(
		test, response, sizeof(response), &offset, "Overlay", 3);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_query_values_entries(
				response, response_len, 520, 4, values,
				ARRAY_SIZE(values), blankets,
				ARRAY_SIZE(blankets), &value_count,
				&blanket_count),
			0L);
	KUNIT_EXPECT_EQ(test, value_count, 2U);
	KUNIT_EXPECT_EQ(test, blanket_count, 1U);

	KUNIT_ASSERT_LE(test,
			(size_t)values[0].name_offset + values[0].name_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)values[0].data_offset + values[0].data_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)values[0].layer_offset + values[0].layer_len,
			response_len);
	KUNIT_EXPECT_EQ(test, values[0].name_len, 5U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + values[0].name_offset, "Alpha", 5),
			0);
	KUNIT_EXPECT_EQ(test, values[0].data_len, (u32)sizeof(data));
	KUNIT_EXPECT_EQ(test,
			memcmp(response + values[0].data_offset, data,
			       sizeof(data)),
			0);
	KUNIT_EXPECT_EQ(test, values[0].layer_len, 4U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + values[0].layer_offset, "base", 4),
			0);
	KUNIT_EXPECT_EQ(test, values[0].value_type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, values[0].sequence, 1ULL);

	KUNIT_ASSERT_LE(test,
			(size_t)values[1].name_offset + values[1].name_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)values[1].data_offset + values[1].data_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)values[1].layer_offset + values[1].layer_len,
			response_len);
	KUNIT_EXPECT_EQ(test, values[1].name_len, 0U);
	KUNIT_EXPECT_EQ(test, values[1].data_len, 0U);
	KUNIT_EXPECT_EQ(test, values[1].layer_len, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + values[1].layer_offset, "Overlay",
			       7),
			0);
	KUNIT_EXPECT_EQ(test, values[1].value_type, (u32)REG_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, values[1].sequence, 2ULL);

	KUNIT_ASSERT_LE(test,
			(size_t)blankets[0].layer_offset +
				blankets[0].layer_len,
			response_len);
	KUNIT_EXPECT_EQ(test, blankets[0].layer_len, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + blankets[0].layer_offset, "Overlay",
			       7),
			0);
	KUNIT_EXPECT_EQ(test, blankets[0].sequence, 3ULL);
}


static void pkm_lcs_kunit_backup_query_values_entries_short_arrays(
	struct kunit *test)
{
	static const u8 data[] = { 0x7a };
	struct pkm_lcs_backup_value_entry_view values[1] = { };
	struct pkm_lcs_backup_blanket_entry_view blankets[1] = { };
	u8 response[256];
	size_t offset;
	size_t response_len;
	u32 value_count = 0;
	u32 blanket_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 521, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "One", "base",
		REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_blanket(
		test, response, sizeof(response), &offset, "base", 2);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_query_values_entries(
				response, response_len, 521, 3, values, 0,
				blankets, ARRAY_SIZE(blankets), &value_count,
				&blanket_count),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, value_count, 1U);
	KUNIT_EXPECT_EQ(test, blanket_count, 1U);
}


static void pkm_lcs_kunit_backup_query_values_entries_malformed(
	struct kunit *test)
{
	static const u8 data[] = { 0x11 };
	struct pkm_lcs_backup_value_entry_view values[1] = { };
	struct pkm_lcs_backup_blanket_entry_view blankets[1] = { };
	u8 response[256];
	size_t offset;
	size_t response_len;
	u32 value_count = 0;
	u32 blanket_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 522, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "Future", "base",
		REG_BINARY, data, sizeof(data), 10);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_query_values_entries(
				response, response_len, 522, 10, values,
				ARRAY_SIZE(values), blankets,
				ARRAY_SIZE(blankets), &value_count,
				&blanket_count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, value_count, 0U);
	KUNIT_EXPECT_EQ(test, blanket_count, 0U);
}


static void pkm_lcs_kunit_backup_enum_children_path_entries_materialize(
	struct kunit *test)
{
	static const u8 alpha_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	struct pkm_lcs_backup_path_entry_view entries[2] = { };
	u8 response[512];
	size_t offset;
	size_t response_len;
	u32 entry_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 523, RSI_ENUM_CHILDREN_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "Alpha", 5);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, alpha_guid, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "Masked", 6);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "Overlay",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, alpha_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_enum_children_path_entries(
				response, response_len, 523, 3, entries,
				ARRAY_SIZE(entries), &entry_count),
			0L);
	KUNIT_EXPECT_EQ(test, entry_count, 2U);

	KUNIT_ASSERT_LE(test,
			(size_t)entries[0].child_name_offset +
				entries[0].child_name_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)entries[0].layer_offset + entries[0].layer_len,
			response_len);
	KUNIT_EXPECT_EQ(test, entries[0].child_name_len, 5U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + entries[0].child_name_offset,
			       "Alpha", 5),
			0);
	KUNIT_EXPECT_EQ(test, entries[0].layer_len, 4U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + entries[0].layer_offset, "base", 4),
			0);
	KUNIT_EXPECT_EQ(test, memcmp(entries[0].child_guid, alpha_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, entries[0].hidden, 0U);
	KUNIT_EXPECT_EQ(test, entries[0].sequence, 1ULL);

	KUNIT_ASSERT_LE(test,
			(size_t)entries[1].child_name_offset +
				entries[1].child_name_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)entries[1].layer_offset + entries[1].layer_len,
			response_len);
	KUNIT_EXPECT_EQ(test, entries[1].child_name_len, 6U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + entries[1].child_name_offset,
			       "Masked", 6),
			0);
	KUNIT_EXPECT_EQ(test, entries[1].layer_len, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + entries[1].layer_offset, "Overlay",
			       7),
			0);
	KUNIT_EXPECT_EQ(test, memcmp(entries[1].child_guid, hidden_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, entries[1].hidden, 1U);
	KUNIT_EXPECT_EQ(test, entries[1].sequence, 2ULL);
}


static void pkm_lcs_kunit_backup_enum_children_path_entries_short_array(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xc1 };
	struct pkm_lcs_backup_path_entry_view entries[1] = { };
	u8 response[256];
	size_t offset;
	size_t response_len;
	u32 entry_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 524, RSI_ENUM_CHILDREN_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "Child", 5);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_enum_children_path_entries(
				response, response_len, 524, 2, entries, 0,
				&entry_count),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, entry_count, 1U);
}


static void pkm_lcs_kunit_backup_enum_children_path_entries_malformed(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xd1 };
	struct pkm_lcs_backup_path_entry_view entries[1] = { };
	u8 response[256];
	size_t offset;
	size_t response_len;
	u32 entry_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 525, RSI_ENUM_CHILDREN_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "Future", 6);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 10);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_enum_children_path_entries(
				response, response_len, 525, 10, entries,
				ARRAY_SIZE(entries), &entry_count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, entry_count, 0U);
}


static void pkm_lcs_kunit_backup_collect_referenced_layers_dedupe(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "Overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
		{ .name = "Audit", .name_len = 5, .precedence = 20,
		  .enabled = 1 },
	};
	static const u8 alpha_guid[RSI_GUID_SIZE] = { 0xe1 };
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	static const u8 value_data[] = { 0x42 };
	struct pkm_lcs_backup_layer_ref_view refs[3] = { };
	u8 enum_response[512];
	u8 values_response[256];
	size_t offset;
	size_t enum_response_len;
	size_t values_response_len;
	u32 ref_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, enum_response,
					 sizeof(enum_response), 526,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 2);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Alpha",
		5);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset, "base",
		RSI_PATH_TARGET_GUID, alpha_guid, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Masked",
		6);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset,
		"Overlay", RSI_PATH_TARGET_HIDDEN, hidden_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, enum_response, sizeof(enum_response), &offset,
		alpha_guid, pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, enum_response, offset,
					  &enum_response_len);

	pkm_lcs_kunit_rsi_response_begin(test, values_response,
					 sizeof(values_response), 527,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, values_response, sizeof(values_response), &offset,
		"Value", "overlay", REG_BINARY, value_data,
		sizeof(value_data), 3);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_query_blanket(
		test, values_response, sizeof(values_response), &offset,
		"Audit", 4);
	pkm_lcs_kunit_rsi_finish_response(test, values_response, offset,
					  &values_response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_collect_referenced_layers(
				layers, ARRAY_SIZE(layers), enum_response,
				enum_response_len, 526, values_response,
				values_response_len, 527, 5, refs,
				ARRAY_SIZE(refs), &ref_count),
			0L);
	KUNIT_EXPECT_EQ(test, ref_count, 3U);
	KUNIT_EXPECT_EQ(test, refs[0].layer_index, 0U);
	KUNIT_EXPECT_EQ(test, refs[1].layer_index, 1U);
	KUNIT_EXPECT_EQ(test, refs[2].layer_index, 2U);
}


static void pkm_lcs_kunit_backup_collect_referenced_layers_short_output(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "Overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xf1 };
	struct pkm_lcs_backup_layer_ref_view refs[1] = { };
	u8 enum_response[256];
	u8 values_response[128];
	size_t offset;
	size_t enum_response_len;
	size_t values_response_len;
	u32 ref_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, enum_response,
					 sizeof(enum_response), 528,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Child",
		5);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset,
		"Overlay", RSI_PATH_TARGET_GUID, child_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, enum_response, sizeof(enum_response), &offset,
		child_guid, pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, enum_response, offset,
					  &enum_response_len);

	pkm_lcs_kunit_rsi_response_begin(test, values_response,
					 sizeof(values_response), 529,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, values_response, offset,
					  &values_response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_collect_referenced_layers(
				layers, ARRAY_SIZE(layers), enum_response,
				enum_response_len, 528, values_response,
				values_response_len, 529, 3, refs,
				ARRAY_SIZE(refs), &ref_count),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, ref_count, 2U);
}


static void pkm_lcs_kunit_backup_collect_referenced_layers_unknown(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 value_data[] = { 0x9a };
	struct pkm_lcs_backup_layer_ref_view refs[1] = { };
	u8 enum_response[128];
	u8 values_response[256];
	size_t offset;
	size_t enum_response_len;
	size_t values_response_len;
	u32 ref_count = 0;

	pkm_lcs_kunit_rsi_response_begin(test, enum_response,
					 sizeof(enum_response), 530,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 0);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, enum_response, offset,
					  &enum_response_len);

	pkm_lcs_kunit_rsi_response_begin(test, values_response,
					 sizeof(values_response), 531,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, values_response, sizeof(values_response), &offset,
		"Value", "Missing", REG_BINARY, value_data,
		sizeof(value_data), 1);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, values_response, offset,
					  &values_response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_collect_referenced_layers(
				layers, ARRAY_SIZE(layers), enum_response,
				enum_response_len, 530, values_response,
				values_response_len, 531, 2, refs,
				ARRAY_SIZE(refs), &ref_count),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, ref_count, 0U);
}


static void pkm_lcs_kunit_backup_root_section_frames_materialize(
	struct kunit *test)
{
	static const u8 key_guid[RSI_GUID_SIZE] = { 0x61 };
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	static const u8 value_data[] = { 0x6a, 0x6b };
	struct pkm_lcs_backup_root_section_frame_summary summary = { };
	u8 enum_response[256];
	u8 values_response[256];
	size_t offset;
	size_t enum_response_len;
	size_t values_response_len;

	pkm_lcs_kunit_rsi_response_begin(test, enum_response,
					 sizeof(enum_response), 532,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Masked",
		6);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset, "base",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 1);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, enum_response, offset,
					  &enum_response_len);

	pkm_lcs_kunit_rsi_response_begin(test, values_response,
					 sizeof(values_response), 533,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, values_response, sizeof(values_response), &offset,
		"Answer", "base", REG_BINARY, value_data,
		sizeof(value_data), 2);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_query_blanket(
		test, values_response, sizeof(values_response), &offset,
		"base", 3);
	pkm_lcs_kunit_rsi_finish_response(test, values_response, offset,
					  &values_response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_root_section_frames(
				key_guid, enum_response, enum_response_len, 532,
				values_response, values_response_len, 533, 4,
				&summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.needs_child_traversal, 0U);
	KUNIT_EXPECT_EQ(test, summary.hidden_path_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.value_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.blanket_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.frame_count, 3U);
	KUNIT_EXPECT_GT(test, summary.total_len, (size_t)0);
}


static void pkm_lcs_kunit_backup_root_section_frames_visible_child_blocks(
	struct kunit *test)
{
	static const u8 key_guid[RSI_GUID_SIZE] = { 0x62 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x63 };
	struct pkm_lcs_backup_root_section_frame_summary summary = { };
	u8 enum_response[256];
	u8 values_response[128];
	size_t offset;
	size_t enum_response_len;
	size_t values_response_len;

	pkm_lcs_kunit_rsi_response_begin(test, enum_response,
					 sizeof(enum_response), 534,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Child",
		5);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 1);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, enum_response, sizeof(enum_response), &offset,
		child_guid, pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, enum_response, offset,
					  &enum_response_len);

	pkm_lcs_kunit_rsi_response_begin(test, values_response,
					 sizeof(values_response), 535,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, values_response, offset,
					  &values_response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_root_section_frames(
				key_guid, enum_response, enum_response_len, 534,
				values_response, values_response_len, 535, 2,
				&summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.needs_child_traversal, 1U);
	KUNIT_EXPECT_EQ(test, summary.hidden_path_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.value_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.frame_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.total_len, (size_t)0);
}


static void pkm_lcs_kunit_backup_root_section_keeps_hidden_with_child(
	struct kunit *test)
{
	static const u8 key_guid[RSI_GUID_SIZE] = { 0x64 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x65 };
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	struct pkm_lcs_backup_root_section_frame_summary summary = { };
	u8 enum_response[384];
	u8 values_response[128];
	size_t offset;
	size_t enum_response_len;
	size_t values_response_len;

	pkm_lcs_kunit_rsi_response_begin(test, enum_response,
					 sizeof(enum_response), 536,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 2);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Child",
		5);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, enum_response, sizeof(enum_response), &offset, "Masked",
		6);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, enum_response, sizeof(enum_response), &offset, "base",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 1);
	pkm_lcs_kunit_rsi_append_u32(test, enum_response,
				     sizeof(enum_response), &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, enum_response, sizeof(enum_response), &offset,
		child_guid, pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, enum_response, offset,
					  &enum_response_len);

	pkm_lcs_kunit_rsi_response_begin(test, values_response,
					 sizeof(values_response), 537,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_append_u32(test, values_response,
				     sizeof(values_response), &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, values_response, offset,
					  &values_response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_backup_root_section_frames(
				key_guid, enum_response, enum_response_len, 536,
				values_response, values_response_len, 537, 2,
				&summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.needs_child_traversal, 1U);
	KUNIT_EXPECT_EQ(test, summary.hidden_path_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.value_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.frame_count, 1U);
	KUNIT_EXPECT_GT(test, summary.total_len, (size_t)0);
}


static void pkm_lcs_kunit_restore_sequence_gate_advances_terminal(
	struct kunit *test)
{
	struct pkm_lcs_restore_sequence_gate gate = { };
	struct pkm_lcs_source_table_snapshot snapshot = { };
	u64 sequence = 0;

	pkm_lcs_kunit_set_sequence_state(true, 10);

	KUNIT_ASSERT_EQ(test, pkm_lcs_restore_sequence_gate_acquire(&gate),
			0L);
	KUNIT_EXPECT_TRUE(test, gate.held);
	KUNIT_EXPECT_EQ(test, gate.restore_sequence_offset, 10ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_restore_sequence_gate_record_dispatched(
				&gate, 3, &sequence),
			0L);
	KUNIT_EXPECT_EQ(test, sequence, 13ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_restore_sequence_gate_record_dispatched(
				&gate, 1, &sequence),
			0L);
	KUNIT_EXPECT_EQ(test, sequence, 11ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_restore_sequence_gate_release_terminal(&gate),
			0L);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 14ULL);

	pkm_lcs_kunit_reset_source_table();
}


static void pkm_lcs_kunit_restore_sequence_gate_validate_no_advance(
	struct kunit *test)
{
	struct pkm_lcs_restore_sequence_gate gate = { };
	struct pkm_lcs_source_table_snapshot snapshot = { };
	u64 sequence = 0;

	pkm_lcs_kunit_set_sequence_state(true, 20);

	KUNIT_ASSERT_EQ(test, pkm_lcs_restore_sequence_gate_acquire(&gate),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_restore_sequence_gate_validate(&gate, 7,
							      &sequence),
			0L);
	KUNIT_EXPECT_EQ(test, sequence, 27ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_restore_sequence_gate_release_terminal(&gate),
			0L);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 20ULL);

	pkm_lcs_kunit_reset_source_table();
}


static void pkm_lcs_kunit_restore_sequence_gate_overflow(
	struct kunit *test)
{
	struct pkm_lcs_restore_sequence_gate gate = { };
	struct pkm_lcs_source_table_snapshot snapshot = { };
	u64 sequence = 123;

	pkm_lcs_kunit_set_sequence_state(true, U64_MAX);

	KUNIT_ASSERT_EQ(test, pkm_lcs_restore_sequence_gate_acquire(&gate),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_restore_sequence_gate_validate(&gate, 0,
							      &sequence),
			(long)-EOVERFLOW);
	KUNIT_EXPECT_EQ(test, sequence, 0ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_restore_sequence_gate_release_terminal(&gate),
			0L);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, U64_MAX);

	pkm_lcs_kunit_reset_source_table();
}

static struct kunit_case pkm_lcs_kunit_backup_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_backup_audit_payload_abi_rejects_bad_state),
	KUNIT_CASE(pkm_lcs_kunit_backup_layer_manifest_base_default_owner),
	KUNIT_CASE(pkm_lcs_kunit_backup_layer_manifest_base_cached_owner),
	KUNIT_CASE(pkm_lcs_kunit_backup_layer_manifest_non_base_cached_owner),
	KUNIT_CASE(pkm_lcs_kunit_backup_layer_manifest_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_backup_layer_manifest_frame_set_order),
	KUNIT_CASE(pkm_lcs_kunit_backup_layer_manifest_frame_set_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_backup_path_entry_frames),
	KUNIT_CASE(pkm_lcs_kunit_backup_value_frames),
	KUNIT_CASE(pkm_lcs_kunit_backup_blanket_tombstone_record),
	KUNIT_CASE(pkm_lcs_kunit_backup_data_frames_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_backup_query_values_entries_materialize),
	KUNIT_CASE(pkm_lcs_kunit_backup_query_values_entries_short_arrays),
	KUNIT_CASE(pkm_lcs_kunit_backup_query_values_entries_malformed),
	KUNIT_CASE(pkm_lcs_kunit_backup_enum_children_path_entries_materialize),
	KUNIT_CASE(pkm_lcs_kunit_backup_enum_children_path_entries_short_array),
	KUNIT_CASE(pkm_lcs_kunit_backup_enum_children_path_entries_malformed),
	KUNIT_CASE(pkm_lcs_kunit_backup_collect_referenced_layers_dedupe),
	KUNIT_CASE(pkm_lcs_kunit_backup_collect_referenced_layers_short_output),
	KUNIT_CASE(pkm_lcs_kunit_backup_collect_referenced_layers_unknown),
	KUNIT_CASE(pkm_lcs_kunit_backup_root_section_frames_materialize),
	KUNIT_CASE(pkm_lcs_kunit_backup_root_section_frames_visible_child_blocks),
	KUNIT_CASE(pkm_lcs_kunit_backup_root_section_keeps_hidden_with_child),
	KUNIT_CASE(pkm_lcs_kunit_restore_sequence_gate_advances_terminal),
	KUNIT_CASE(pkm_lcs_kunit_restore_sequence_gate_validate_no_advance),
	KUNIT_CASE(pkm_lcs_kunit_restore_sequence_gate_overflow),
	{}
};

static struct kunit_suite pkm_lcs_kunit_backup_suite = {
	.name = "pkm_lcs_kunit_backup",
	.test_cases = pkm_lcs_kunit_backup_cases,
};

kunit_test_suite(pkm_lcs_kunit_backup_suite);
