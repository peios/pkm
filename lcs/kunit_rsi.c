// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_rsi_lookup_request_frame_success(struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const char child_name[] = "Child";
	u8 frame[96];
	struct pkm_lcs_rsi_built_request built = { };
	size_t payload_offset;
	size_t child_offset;
	size_t expected_len;
	size_t i;

	memset(frame, 0xcc, sizeof(frame));
	expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
		       RSI_LENGTH_PREFIX_SIZE + strlen(child_name);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 0x1112131415161718ULL, 99,
				parent_guid, child_name, strlen(child_name),
				NULL, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_LOOKUP);

	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			99ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test, memcmp(frame + payload_offset, parent_guid,
				     sizeof(parent_guid)),
			0);
	child_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + child_offset),
			(u32)strlen(child_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + child_offset + RSI_LENGTH_PREFIX_SIZE,
			       child_name, strlen(child_name)),
			0);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xccU);
}


static void pkm_lcs_kunit_rsi_lookup_request_frame_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x21 };
	static const char child_name[] = "Child";
	u8 frame[96];
	struct pkm_lcs_rsi_built_request built = {
		.len = 77,
		.request_id = 88,
		.op_code = 99,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				NULL, sizeof(frame), 1, 0, parent_guid,
				child_name, strlen(child_name), NULL, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);

	built.len = 77;
	built.request_id = 88;
	built.op_code = 99;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 1, 0, NULL, child_name,
				strlen(child_name), NULL, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);

	built.len = 77;
	built.request_id = 88;
	built.op_code = 99;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 1, 0, parent_guid, NULL,
				strlen(child_name), NULL, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 1, 0, parent_guid,
				child_name, strlen(child_name), NULL, NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_rsi_lookup_request_frame_validates_child(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x31 };
	static const char bad_separator[] = "Bad\\Name";
	char too_long[256];
	u8 frame[96];
	struct pkm_lcs_rsi_built_request built = {
		.len = 55,
		.request_id = 66,
		.op_code = 77,
	};

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 2, 0, parent_guid,
				bad_separator, strlen(bad_separator), NULL,
				&built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	KUNIT_EXPECT_EQ(test, frame[0], 0xaaU);

	memset(too_long, 'A', sizeof(too_long));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 2, 0, parent_guid,
				too_long, sizeof(too_long), NULL, &built),
			(long)-ENAMETOOLONG);
}


static void pkm_lcs_kunit_rsi_lookup_request_frame_rejects_short_buffer(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x41 };
	static const char child_name[] = "Child";
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
		 RSI_LENGTH_PREFIX_SIZE + 4];
	struct pkm_lcs_rsi_built_request built = {
		.len = 11,
		.request_id = 22,
		.op_code = 33,
	};
	size_t i;

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 3, 0, parent_guid,
				child_name, strlen(child_name), NULL, &built),
			(long)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xaaU);
}


static void pkm_lcs_kunit_rsi_begin_transaction_request_frame_success(
	struct kunit *test)
{
	u8 frame[64];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + sizeof(u64) +
			      sizeof(u32);
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(frame, 0xcc, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				frame, sizeof(frame), 0x2122232425262728ULL, 0,
				0x0102030405060708ULL, RSI_TXN_READ_WRITE,
				&built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_BEGIN_TRANSACTION);

	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(frame + payload_offset),
			0x0102030405060708ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_WRITE);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xccU);
}


static void pkm_lcs_kunit_rsi_commit_abort_transaction_request_frames(
	struct kunit *test)
{
	u8 commit[64];
	u8 abort[64];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + sizeof(u64);
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(commit, 0xcc, sizeof(commit));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_commit_transaction_request(
				commit, sizeof(commit), 0x3132333435363738ULL,
				77, 77, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x3132333435363738ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 77ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(commit +
					   RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(commit +
					   RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(commit + RSI_REQUEST_TXN_ID_OFFSET),
			77ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(commit + payload_offset), 77ULL);
	for (i = expected_len; i < sizeof(commit); i++)
		KUNIT_EXPECT_EQ(test, commit[i], 0xccU);

	memset(&built, 0, sizeof(built));
	memset(abort, 0xdd, sizeof(abort));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_abort_transaction_request(
				abort, sizeof(abort), 0x4142434445464748ULL,
				88, 88, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x4142434445464748ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 88ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(abort + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(abort + RSI_REQUEST_TXN_ID_OFFSET),
			88ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(abort + payload_offset),
			88ULL);
	for (i = expected_len; i < sizeof(abort); i++)
		KUNIT_EXPECT_EQ(test, abort[i], 0xddU);
}


static void pkm_lcs_kunit_rsi_flush_request_frame_success(struct kunit *test)
{
	static const char hive_name[] = "Machine";
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE +
		 sizeof(hive_name) - 1 + 8];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE +
			      sizeof(hive_name) - 1;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(frame, 0xee, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_flush_request(
				frame, sizeof(frame), 0x5152535455565758ULL, 0,
				hive_name, strlen(hive_name), &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x5152535455565758ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x5152535455565758ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + payload_offset),
			(u32)strlen(hive_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + payload_offset + RSI_LENGTH_PREFIX_SIZE,
			       hive_name, strlen(hive_name)),
			0);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xeeU);
}


static void pkm_lcs_kunit_rsi_drop_key_request_frame_success(struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE + 8];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_drop_key_request(
				frame, sizeof(frame), 0x4142434445464748ULL,
				0x1011121314151617ULL, guid, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x4142434445464748ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0x1011121314151617ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x4142434445464748ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			0x1011121314151617ULL);
	KUNIT_EXPECT_EQ(test, memcmp(frame + payload_offset, guid,
				    RSI_GUID_SIZE), 0);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xaaU);
}


static void pkm_lcs_kunit_rsi_delete_layer_request_frame_success(
	struct kunit *test)
{
	static const char layer_name[] = "role-alpha";
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE +
		 sizeof(layer_name) - 1 + 8];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE +
			      sizeof(layer_name) - 1;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(frame, 0xbb, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_delete_layer_request(
				frame, sizeof(frame), 0x6162636465666768ULL, 0,
				layer_name, strlen(layer_name), &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x6162636465666768ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x6162636465666768ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + payload_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + payload_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xbbU);
}


static void pkm_lcs_kunit_rsi_delete_layer_request_uses_runtime_limits(
	struct kunit *test)
{
	char long_name[301];
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE + 301];
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits limits = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE +
			      sizeof(long_name) - 1;

	memset(long_name, 'd', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	memset(frame, 0xdd, sizeof(frame));

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_delete_layer_request_with_limits(
				frame, sizeof(frame), 1, 0, long_name,
				sizeof(long_name) - 1, &limits, &built),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);

	limits.max_path_component_length = sizeof(long_name) - 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_delete_layer_request_with_limits(
				frame, sizeof(frame), 1, 0, long_name,
				sizeof(long_name) - 1, &limits, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_HEADER_SIZE),
			(u32)(sizeof(long_name) - 1));
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + RSI_REQUEST_HEADER_SIZE +
				       RSI_LENGTH_PREFIX_SIZE,
			       long_name, sizeof(long_name) - 1),
			0);
}


static void pkm_lcs_kunit_rsi_transaction_request_frames_reject_bad_inputs(
	struct kunit *test)
{
	u8 frame[64];
	struct pkm_lcs_rsi_built_request built = {
		.len = 11,
		.request_id = 22,
		.txn_id = 33,
		.op_code = 44,
	};
	size_t i;

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				NULL, sizeof(frame), 1, 0, 2,
				RSI_TXN_READ_WRITE, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);

	built.len = 11;
	built.request_id = 22;
	built.txn_id = 33;
	built.op_code = 44;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				frame, sizeof(frame), 1, 0, 2, 0x80, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xaaU);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_commit_transaction_request(
				frame, sizeof(frame), 1, 1, 1, NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_rsi_transaction_request_frames_reject_short_buffer(
	struct kunit *test)
{
	u8 begin[RSI_REQUEST_HEADER_SIZE + sizeof(u64) + sizeof(u32) - 1];
	u8 commit[RSI_REQUEST_HEADER_SIZE + sizeof(u64) - 1];
	struct pkm_lcs_rsi_built_request built = {
		.len = 11,
		.request_id = 22,
		.txn_id = 33,
		.op_code = 44,
	};
	size_t i;

	memset(begin, 0xaa, sizeof(begin));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				begin, sizeof(begin), 1, 0, 2,
				RSI_TXN_READ_ONLY, &built),
			(long)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(begin); i++)
		KUNIT_EXPECT_EQ(test, begin[i], 0xaaU);

	built.len = 11;
	built.request_id = 22;
	built.txn_id = 33;
	built.op_code = 44;
	memset(commit, 0xbb, sizeof(commit));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_commit_transaction_request(
				commit, sizeof(commit), 1, 1, 1, &built),
			(long)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(commit); i++)
		KUNIT_EXPECT_EQ(test, commit[i], 0xbbU);
}


static void pkm_lcs_kunit_rsi_read_key_bridge_accepts_valid(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = guid,
		.name = "Machine",
	};
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_rsi_read_key_result result = { };
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE];
	u8 response[256];
	size_t response_len = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_read_key_request(
				request, sizeof(request), 42, 0, guid, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, sizeof(request));
	KUNIT_EXPECT_EQ(test, built.request_id, 42ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_READ_KEY);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_read_key_source_build_response(
				&script, built.request_id, response,
				sizeof(response), &response_len),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_read_key_response(
				response, response_len, built.request_id,
				&result),
			0L);
	KUNIT_EXPECT_EQ(test, result.name_len, 7U);
	KUNIT_EXPECT_EQ(test,
			result.sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_EXPECT_EQ(test, result.last_write_time, 2000ULL);
	KUNIT_EXPECT_EQ(test, result.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, result.symlink, 0U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + result.sd_offset,
			       pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);
}


static void pkm_lcs_kunit_rsi_read_key_bridge_uses_runtime_limits(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	char long_name[301];
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = guid,
		.name = long_name,
	};
	struct pkm_lcs_rsi_read_key_result result = { };
	struct pkm_lcs_runtime_limits limits = { };
	u8 response[512];
	size_t response_len = 0;

	memset(long_name, 'r', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_read_key_source_build_response(
				&script, 9, response, sizeof(response),
				&response_len),
			0);

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_read_key_response_with_limits(
				response, response_len, 9, &limits, &result),
			(long)-EIO);
	KUNIT_EXPECT_TRUE(test, result.source_validation_failure_present);

	limits.max_path_component_length = sizeof(long_name) - 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_read_key_response_with_limits(
				response, response_len, 9, &limits, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.name_len, (u32)(sizeof(long_name) - 1));
	KUNIT_EXPECT_EQ(test,
			result.sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
}


static void pkm_lcs_kunit_rsi_query_values_bridge_materializes_default_reg_link(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE + sizeof(u32) +
		   sizeof(u8)];
	u8 response[256];
	size_t offset;
	size_t response_len;

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_query_values_request(
				request, sizeof(request), 43, 0, guid, "", 0,
				false, &limits, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, sizeof(request));
	KUNIT_EXPECT_EQ(test, built.request_id, 43ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_QUERY_VALUES);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request + RSI_REQUEST_HEADER_SIZE +
					   RSI_GUID_SIZE),
			0U);
	KUNIT_EXPECT_EQ(test, request[sizeof(request) - 1], 0U);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 built.request_id,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "", "base",
		REG_LINK, target, sizeof(target) - 1, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
				pkm_lcs_rsi_materialize_query_value_response(
					response, response_len, built.request_id, 1,
					"", 0, layers, ARRAY_SIZE(layers), NULL, 0,
					NULL, &result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, result.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, result.value_type, (u32)REG_LINK);
	KUNIT_EXPECT_EQ(test, result.selected_precedence, 0U);
	KUNIT_EXPECT_EQ(test, result.selected_sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, result.layer_len, 4U);
	KUNIT_ASSERT_NOT_NULL(test, result.layer);
	KUNIT_EXPECT_EQ(test, memcmp(result.layer, "base", 4), 0);
	KUNIT_EXPECT_EQ(test, result.data_len, (u32)(sizeof(target) - 1));
	KUNIT_ASSERT_LE(test,
			(size_t)result.data_offset +
				(size_t)result.data_len,
			response_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + result.data_offset, target,
			       sizeof(target) - 1),
			0);
}


static void pkm_lcs_kunit_rsi_query_value_response_uses_runtime_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	char value_name[LONG_NAME_LEN + 1];
	char layer_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_rsi_layer_view layers[2];
	static const u8 data[] = { 0x42 };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 response[1024];
	size_t offset;
	size_t response_len;

	memset(value_name, 'v', LONG_NAME_LEN);
	value_name[LONG_NAME_LEN] = '\0';
	memset(layer_name, 'l', LONG_NAME_LEN);
	layer_name[LONG_NAME_LEN] = '\0';
	layers[0] = (struct pkm_lcs_rsi_layer_view){
		.name = "base",
		.name_len = 4,
		.precedence = 0,
		.enabled = 1,
	};
	layers[1] = (struct pkm_lcs_rsi_layer_view){
		.name = layer_name,
		.name_len = LONG_NAME_LEN,
		.precedence = 10,
		.enabled = 1,
	};
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 495, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, value_name,
		layer_name, REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_value_response(
				response, response_len, 495, 2, value_name,
				LONG_NAME_LEN, layers, ARRAY_SIZE(layers), NULL,
				0, &limits, &result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, result.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, result.layer_len, (u32)LONG_NAME_LEN);
	KUNIT_ASSERT_NOT_NULL(test, result.layer);
	KUNIT_EXPECT_EQ(test, memcmp(result.layer, layer_name, LONG_NAME_LEN),
			0);
	KUNIT_EXPECT_EQ(test, result.data_len, (u32)sizeof(data));
	KUNIT_ASSERT_LE(test,
			(size_t)result.data_offset +
				(size_t)result.data_len,
			response_len);
	KUNIT_EXPECT_EQ(test, memcmp(response + result.data_offset, data,
				    sizeof(data)), 0);
}


static void pkm_lcs_kunit_rsi_query_values_bridge_blanket_not_found(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 44, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "", "base",
		REG_LINK, target, sizeof(target) - 1, 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_blanket(
		test, response, sizeof(response), &offset, "overlay", 2);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
				pkm_lcs_rsi_materialize_query_value_response(
					response, response_len, 44, 3, "", 0, layers,
					ARRAY_SIZE(layers), NULL, 0, NULL, &result),
			0L);
	KUNIT_EXPECT_FALSE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, result.source_blanket_count, 1U);
}


static void pkm_lcs_kunit_rsi_query_values_bridge_rejects_wrong_value(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 45, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "Other", "base",
		REG_LINK, target, sizeof(target) - 1, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
				pkm_lcs_rsi_materialize_query_value_response(
					response, response_len, 45, 1, "", 0, layers,
					ARRAY_SIZE(layers), NULL, 0, NULL, &result),
			(long)-EIO);
}


static void pkm_lcs_kunit_rsi_enum_children_info_summary(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 alpha_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 beta_guid[RSI_GUID_SIZE] = { 0xb1 };
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xc1 };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_rsi_built_request built = { };
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE];
	u8 response[512];
	size_t offset;
	size_t response_len;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_enum_children_request(
				request, sizeof(request), 51, 0, parent_guid,
				&built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, sizeof(request));
	KUNIT_EXPECT_EQ(test, built.request_id, 51ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_ENUM_CHILDREN);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, parent_guid,
			       RSI_GUID_SIZE),
			0);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 built.request_id,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
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
		test, response, sizeof(response), &offset, "BetaLong", 8);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, beta_guid, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "overlay",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, alpha_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, beta_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_enum_children_info_summary(
				response, response_len, built.request_id, 3,
				layers, ARRAY_SIZE(layers), NULL, 0,
				NULL, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.source_path_entry_count, 3U);
	KUNIT_EXPECT_EQ(test, summary.subkey_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.max_subkey_name_len, 5U);
}


static void pkm_lcs_kunit_rsi_query_values_info_summary(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 data[] = { 1, 2, 3 };
	static const u8 bigger_data[] = { 1, 2, 3, 4, 5, 6 };
	static const u8 tombstone_data = 0;
	struct pkm_lcs_rsi_query_values_info_summary summary = { };
	u8 response[512];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 52, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 3);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "One", "base",
		REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "SecondLong",
		"base", REG_BINARY, bigger_data, sizeof(bigger_data), 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "SecondLong",
		"overlay", REG_TOMBSTONE, &tombstone_data, 0, 2);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_info_summary(
				response, response_len, 52, 3, layers,
				ARRAY_SIZE(layers), NULL, 0, NULL, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.source_value_entry_count, 3U);
	KUNIT_EXPECT_EQ(test, summary.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.value_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.max_value_name_len, 3U);
	KUNIT_EXPECT_EQ(test, summary.max_value_data_size, (u32)sizeof(data));
}


static void pkm_lcs_kunit_rsi_query_values_batch_uses_runtime_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300, RESPONSE_LEN = 2048, OUTPUT_LEN = 512 };
	char *value_name;
	char *layer_name;
	struct pkm_lcs_rsi_layer_view layers[2];
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_rsi_query_values_info_summary summary = { };
	struct pkm_lcs_rsi_query_values_batch_result result = { };
	static const u8 data[] = { 0x7b };
	u8 *response;
	u8 *output;
	size_t offset;
	size_t response_len;

	value_name = kunit_kzalloc(test, LONG_NAME_LEN + 1, GFP_KERNEL);
	layer_name = kunit_kzalloc(test, LONG_NAME_LEN + 1, GFP_KERNEL);
	response = kunit_kzalloc(test, RESPONSE_LEN, GFP_KERNEL);
	output = kunit_kzalloc(test, OUTPUT_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, value_name);
	KUNIT_ASSERT_NOT_NULL(test, layer_name);
	KUNIT_ASSERT_NOT_NULL(test, response);
	KUNIT_ASSERT_NOT_NULL(test, output);

	memset(value_name, 'q', LONG_NAME_LEN);
	value_name[LONG_NAME_LEN] = '\0';
	memset(layer_name, 'r', LONG_NAME_LEN);
	layer_name[LONG_NAME_LEN] = '\0';
	layers[0] = (struct pkm_lcs_rsi_layer_view){
		.name = "base",
		.name_len = 4,
		.precedence = 0,
		.enabled = 1,
	};
	layers[1] = (struct pkm_lcs_rsi_layer_view){
		.name = layer_name,
		.name_len = LONG_NAME_LEN,
		.precedence = 10,
		.enabled = 1,
	};
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_rsi_response_begin(test, response, RESPONSE_LEN,
					 496, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, RESPONSE_LEN,
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, RESPONSE_LEN, &offset, value_name,
		layer_name, REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, RESPONSE_LEN,
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_info_summary(
				response, response_len, 496, 2, layers,
				ARRAY_SIZE(layers), NULL, 0, NULL, &summary),
			(long)-EIO);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_info_summary(
				response, response_len, 496, 2, layers,
				ARRAY_SIZE(layers), NULL, 0, &limits,
				&summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.value_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.max_value_name_len, (u32)LONG_NAME_LEN);
	KUNIT_EXPECT_EQ(test, summary.max_value_data_size, (u32)sizeof(data));

	memset(output, 0xaa, OUTPUT_LEN);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_batch_response(
				response, response_len, 496, 2, layers,
				ARRAY_SIZE(layers), NULL, 0, &limits, output,
				OUTPUT_LEN, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.count, 1U);
	KUNIT_EXPECT_EQ(test, result.required_len,
			(u32)(12 + LONG_NAME_LEN + sizeof(data)));
	KUNIT_EXPECT_EQ(test, result.written_len, result.required_len);
	KUNIT_ASSERT_LE(test, (size_t)result.written_len,
			(size_t)OUTPUT_LEN);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(output), (u32)LONG_NAME_LEN);
	KUNIT_EXPECT_EQ(test, memcmp(output + sizeof(u32), value_name,
				    LONG_NAME_LEN), 0);
}


static void pkm_lcs_kunit_rsi_enum_value_uses_runtime_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300, RESPONSE_LEN = 2048 };
	char *value_name;
	char *layer_name;
	struct pkm_lcs_rsi_layer_view layers[2];
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_rsi_enum_value_result result = { };
	static const u8 data[] = { 0x45, 0x46 };
	u8 *response;
	size_t offset;
	size_t response_len;

	value_name = kunit_kzalloc(test, LONG_NAME_LEN + 1, GFP_KERNEL);
	layer_name = kunit_kzalloc(test, LONG_NAME_LEN + 1, GFP_KERNEL);
	response = kunit_kzalloc(test, RESPONSE_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, value_name);
	KUNIT_ASSERT_NOT_NULL(test, layer_name);
	KUNIT_ASSERT_NOT_NULL(test, response);

	memset(value_name, 'e', LONG_NAME_LEN);
	value_name[LONG_NAME_LEN] = '\0';
	memset(layer_name, 'v', LONG_NAME_LEN);
	layer_name[LONG_NAME_LEN] = '\0';
	layers[0] = (struct pkm_lcs_rsi_layer_view){
		.name = "base",
		.name_len = 4,
		.precedence = 0,
		.enabled = 1,
	};
	layers[1] = (struct pkm_lcs_rsi_layer_view){
		.name = layer_name,
		.name_len = LONG_NAME_LEN,
		.precedence = 10,
		.enabled = 1,
	};
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_rsi_response_begin(test, response, RESPONSE_LEN,
					 497, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, RESPONSE_LEN,
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, RESPONSE_LEN, &offset, value_name,
		layer_name, REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, RESPONSE_LEN,
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_enum_value_response(
				response, response_len, 497, 2, 0, layers,
				ARRAY_SIZE(layers), NULL, 0, NULL, &result),
			(long)-EIO);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_enum_value_response(
				response, response_len, 497, 2, 0, layers,
				ARRAY_SIZE(layers), NULL, 0, &limits,
				&result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, result.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, result.name_len, (u32)LONG_NAME_LEN);
	KUNIT_EXPECT_EQ(test, result.data_len, (u32)sizeof(data));
	KUNIT_ASSERT_LE(test,
			(size_t)result.name_offset +
				(size_t)result.name_len,
			response_len);
	KUNIT_ASSERT_LE(test,
			(size_t)result.data_offset +
				(size_t)result.data_len,
			response_len);
	KUNIT_EXPECT_EQ(test, memcmp(response + result.name_offset,
				    value_name, LONG_NAME_LEN), 0);
	KUNIT_EXPECT_EQ(test, memcmp(response + result.data_offset, data,
				    sizeof(data)), 0);
}


static void pkm_lcs_kunit_rsi_value_watch_uses_runtime_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300, RESPONSE_LEN = 2048, OUTPUT_LEN = 512 };
	char *value_name;
	char *layer_name;
	struct pkm_lcs_rsi_layer_view layers[2];
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_rsi_value_watch_events_result result = { };
	static const u8 data[] = { 0x90 };
	u8 *before;
	u8 *after;
	u8 *output;
	size_t offset;
	size_t before_len;
	size_t after_len;

	value_name = kunit_kzalloc(test, LONG_NAME_LEN + 1, GFP_KERNEL);
	layer_name = kunit_kzalloc(test, LONG_NAME_LEN + 1, GFP_KERNEL);
	before = kunit_kzalloc(test, RESPONSE_LEN, GFP_KERNEL);
	after = kunit_kzalloc(test, RESPONSE_LEN, GFP_KERNEL);
	output = kunit_kzalloc(test, OUTPUT_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, value_name);
	KUNIT_ASSERT_NOT_NULL(test, layer_name);
	KUNIT_ASSERT_NOT_NULL(test, before);
	KUNIT_ASSERT_NOT_NULL(test, after);
	KUNIT_ASSERT_NOT_NULL(test, output);

	memset(value_name, 'w', LONG_NAME_LEN);
	value_name[LONG_NAME_LEN] = '\0';
	memset(layer_name, 'l', LONG_NAME_LEN);
	layer_name[LONG_NAME_LEN] = '\0';
	layers[0] = (struct pkm_lcs_rsi_layer_view){
		.name = "base",
		.name_len = 4,
		.precedence = 0,
		.enabled = 1,
	};
	layers[1] = (struct pkm_lcs_rsi_layer_view){
		.name = layer_name,
		.name_len = LONG_NAME_LEN,
		.precedence = 10,
		.enabled = 1,
	};
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_rsi_response_begin(test, before, RESPONSE_LEN, 498,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, before, RESPONSE_LEN, &offset, 0);
	pkm_lcs_kunit_rsi_append_u32(test, before, RESPONSE_LEN, &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, before, offset, &before_len);

	pkm_lcs_kunit_rsi_response_begin(test, after, RESPONSE_LEN, 499,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, after, RESPONSE_LEN, &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, after, RESPONSE_LEN, &offset, value_name, layer_name,
		REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_u32(test, after, RESPONSE_LEN, &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, after, offset, &after_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_watch_events(
				before, before_len, 498, after, after_len, 499,
				2, layers, ARRAY_SIZE(layers), NULL, 0, NULL,
				NULL, 0, &result),
			(long)-EIO);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_watch_events(
				before, before_len, 498, after, after_len, 499,
				2, layers, ARRAY_SIZE(layers), NULL, 0,
				&limits, output, OUTPUT_LEN, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.count, 1U);
	KUNIT_EXPECT_EQ(test, result.required_len, (u32)(8 + LONG_NAME_LEN));
	KUNIT_EXPECT_EQ(test, result.written_len, result.required_len);
	KUNIT_ASSERT_LE(test, (size_t)result.written_len,
			(size_t)OUTPUT_LEN);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(output),
			(u32)REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(output + sizeof(u32)),
			(u32)LONG_NAME_LEN);
	KUNIT_EXPECT_EQ(test, memcmp(output + 2 * sizeof(u32), value_name,
				    LONG_NAME_LEN), 0);
}


static void pkm_lcs_kunit_rsi_enum_children_info_rejects_bad_metadata(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xd1 };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 53, RSI_ENUM_CHILDREN_RESPONSE,
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
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_enum_children_info_summary(
				response, response_len, 53, 2, layers,
				ARRAY_SIZE(layers), NULL, 0, NULL, &summary),
			(long)-EIO);
}


static void pkm_lcs_kunit_rsi_delete_layer_response_validation(
	struct kunit *test)
{
	static const u8 guid_a[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 guid_b[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const u8 nil_guid[RSI_GUID_SIZE];
	struct pkm_lcs_rsi_delete_layer_response_summary summary = { };
	u8 frame[RSI_MIN_RESPONSE_SIZE + sizeof(u32) +
		 2U * RSI_GUID_SIZE];
	size_t frame_len;
	size_t offset;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 861,
					 RSI_DELETE_LAYER_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, sizeof(frame), &offset,
				       guid_a, RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, sizeof(frame), &offset,
				       guid_b, RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_delete_layer_response(
				frame, frame_len, 861, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.orphaned_guid_count, 2U);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 862,
					 RSI_DELETE_LAYER_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, sizeof(frame), &offset,
				       nil_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_delete_layer_response(
				frame, frame_len, 862, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 863,
					 RSI_DELETE_LAYER_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, sizeof(frame), &offset,
				       guid_a, RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, sizeof(frame), &offset,
				       guid_a, RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_delete_layer_response(
				frame, frame_len, 863, &summary),
			(long)-EIO);
}

static struct kunit_case pkm_lcs_kunit_rsi_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_success),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_validates_child),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_rejects_short_buffer),
	KUNIT_CASE(pkm_lcs_kunit_rsi_begin_transaction_request_frame_success),
	KUNIT_CASE(pkm_lcs_kunit_rsi_commit_abort_transaction_request_frames),
	KUNIT_CASE(pkm_lcs_kunit_rsi_flush_request_frame_success),
	KUNIT_CASE(pkm_lcs_kunit_rsi_drop_key_request_frame_success),
	KUNIT_CASE(pkm_lcs_kunit_rsi_delete_layer_request_frame_success),
	KUNIT_CASE(pkm_lcs_kunit_rsi_delete_layer_request_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_rsi_transaction_request_frames_reject_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_rsi_transaction_request_frames_reject_short_buffer),
	KUNIT_CASE(pkm_lcs_kunit_rsi_read_key_bridge_accepts_valid),
	KUNIT_CASE(pkm_lcs_kunit_rsi_read_key_bridge_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_values_bridge_materializes_default_reg_link),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_value_response_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_values_bridge_blanket_not_found),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_values_bridge_rejects_wrong_value),
	KUNIT_CASE(pkm_lcs_kunit_rsi_enum_children_info_summary),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_values_info_summary),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_values_batch_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_rsi_enum_value_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_rsi_value_watch_uses_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_rsi_enum_children_info_rejects_bad_metadata),
	KUNIT_CASE(pkm_lcs_kunit_rsi_delete_layer_response_validation),
	{}
};

static struct kunit_suite pkm_lcs_kunit_rsi_suite = {
	.name = "pkm_lcs_kunit_rsi",
	.test_cases = pkm_lcs_kunit_rsi_cases,
};

kunit_test_suite(pkm_lcs_kunit_rsi_suite);
