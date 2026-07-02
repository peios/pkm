// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source dispatch and round-trip API wrappers.
 */

#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include "rsi.h"
#include "source_device.h"
#include "source_internal.h"

#include <trace/events/lcs.h>

long pkm_lcs_source_dispatch_lookup_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_lookup_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_lookup_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_lookup_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		NULL, waiter, result);
}

long pkm_lcs_source_dispatch_lookup_waitable_request_retaining_frame(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_enqueue_result *result)
{
	long ret;

	if (!waiter || !frame)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	ret = pkm_lcs_source_response_waiter_retain_frame(waiter, frame);
	if (ret)
		return ret;
	return pkm_lcs_source_dispatch_lookup_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		NULL, waiter, result);
}

long pkm_lcs_source_lookup_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_LOOKUP, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_lookup_request_with_waiter(
			source_id, txn_id, parent_guid, child_name,
			child_name_len, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_lookup_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_lookup_round_trip_timeout_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		NULL, timeout_ms, response, enqueue);
}

long pkm_lcs_source_lookup_round_trip(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_lookup_round_trip_timeout_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		&limits, limits.request_timeout_ms, response, enqueue);
}

long pkm_lcs_source_dispatch_create_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_create_entry_request_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, child_guid, sequence, NULL, result);
}

long pkm_lcs_source_dispatch_create_entry_request_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_create_entry_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, child_guid, sequence, limits, NULL,
		result);
}

long pkm_lcs_source_dispatch_create_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_create_entry_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, child_guid, sequence, NULL, waiter,
		result);
}

long pkm_lcs_source_dispatch_hide_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
		source_id, txn_id, true, parent_guid, child_name,
		child_name_len, layer_name, layer_name_len, sequence, NULL, NULL,
		result);
}

long pkm_lcs_source_dispatch_hide_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
		source_id, txn_id, true, parent_guid, child_name,
		child_name_len, layer_name, layer_name_len, sequence, NULL, waiter,
		result);
}

long pkm_lcs_source_dispatch_delete_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
		source_id, txn_id, false, parent_guid, child_name,
		child_name_len, layer_name, layer_name_len, 0, NULL, NULL,
		result);
}

long pkm_lcs_source_dispatch_delete_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
		source_id, txn_id, false, parent_guid, child_name,
		child_name_len, layer_name, layer_name_len, 0, NULL, waiter,
		result);
}

long pkm_lcs_source_create_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_create_entry_round_trip_timeout_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, child_guid, sequence, NULL,
		timeout_ms, response, enqueue);
}

long pkm_lcs_source_create_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_CREATE_ENTRY, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_create_entry_request_with_waiter(
			source_id, txn_id, parent_guid, child_name,
			child_name_len, layer_name, layer_name_len,
			child_guid, sequence, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_hide_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_HIDE_ENTRY, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
			source_id, txn_id, true, parent_guid, child_name,
			child_name_len, layer_name, layer_name_len, sequence,
			limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_hide_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_hide_entry_round_trip_timeout_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, sequence, NULL, timeout_ms,
		response, enqueue);
}

long pkm_lcs_source_delete_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_DELETE_ENTRY, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
			source_id, txn_id, false, parent_guid, child_name,
			child_name_len, layer_name, layer_name_len, 0, limits,
			&waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_delete_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_delete_entry_round_trip_timeout_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, NULL, timeout_ms, response, enqueue);
}

long pkm_lcs_source_dispatch_create_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_create_key_request_with_limits(
		source_id, txn_id, guid, name, name_len, parent_guid, sd,
		sd_len, volatile_key, symlink, NULL, result);
}

long pkm_lcs_source_dispatch_create_key_request_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_create_key_request_with_waiter(
		source_id, txn_id, guid, name, name_len, parent_guid, sd,
		sd_len, volatile_key, symlink, limits, NULL, result);
}

long pkm_lcs_source_dispatch_create_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_create_key_request_with_waiter(
		source_id, txn_id, guid, name, name_len, parent_guid, sd,
		sd_len, volatile_key, symlink, NULL, waiter, result);
}

long pkm_lcs_source_dispatch_write_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_write_key_request_with_waiter(
		source_id, txn_id, guid, sd, sd_len, last_write_time, NULL,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_write_key_request_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_write_key_request_with_waiter(
		source_id, txn_id, guid, sd, sd_len, last_write_time, limits,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_write_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_write_key_request_with_waiter(
		source_id, txn_id, guid, sd, sd_len, last_write_time, NULL,
		NULL, waiter, result);
}

long pkm_lcs_source_dispatch_set_value_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_set_value_request_with_waiter(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, value_type, data, data_len,
		sequence, expected_sequence, NULL, NULL, NULL, result);
}

long pkm_lcs_source_dispatch_set_value_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_set_value_request_with_waiter(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, value_type, data, data_len,
		sequence, expected_sequence, NULL, NULL, waiter, result);
}

long pkm_lcs_source_dispatch_delete_value_entry_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_delete_value_entry_request_with_waiter(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, NULL, NULL, result);
}

long pkm_lcs_source_dispatch_delete_value_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_delete_value_entry_request_with_waiter(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, NULL, waiter, result);
}

long pkm_lcs_source_dispatch_set_blanket_tombstone_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_set_blanket_tombstone_request_with_waiter(
		source_id, txn_id, guid, layer_name, layer_name_len, set,
		sequence, NULL, NULL, result);
}

long pkm_lcs_source_dispatch_set_blanket_tombstone_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_set_blanket_tombstone_request_with_waiter(
		source_id, txn_id, guid, layer_name, layer_name_len, set,
		sequence, NULL, waiter, result);
}

long pkm_lcs_source_dispatch_drop_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_drop_key_request_with_waiter(
		source_id, txn_id, guid, NULL, NULL, result);
}

long pkm_lcs_source_dispatch_drop_key_request_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_drop_key_request_with_waiter(
		source_id, txn_id, guid, limits, NULL, result);
}

long pkm_lcs_source_dispatch_drop_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_drop_key_request_with_waiter(
		source_id, txn_id, guid, NULL, waiter, result);
}

long pkm_lcs_source_dispatch_begin_transaction_request(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_BEGIN_TRANSACTION, transaction_id, mode, NULL,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_begin_transaction_waitable_request(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_BEGIN_TRANSACTION, transaction_id, mode,
		NULL, NULL, waiter, result);
}

long pkm_lcs_source_dispatch_commit_transaction_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0, NULL,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_commit_transaction_waitable_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0, NULL,
		NULL, waiter, result);
}

long pkm_lcs_source_dispatch_abort_transaction_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0, NULL,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_abort_transaction_request_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0, limits,
		NULL, NULL, result);
}

long pkm_lcs_source_dispatch_abort_transaction_waitable_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0, NULL,
		NULL, waiter, result);
}

long pkm_lcs_source_dispatch_delete_layer_request(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_dispatch_delete_layer_request_with_waiter(
		source_id, layer_name, layer_name_len, &limits, NULL, result);
}

long pkm_lcs_source_dispatch_delete_layer_waitable_request(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_dispatch_delete_layer_request_with_waiter(
		source_id, layer_name, layer_name_len, &limits, waiter,
		result);
}

long pkm_lcs_source_dispatch_flush_request(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_flush_request_with_waiter(
		source_id, hive_name, hive_name_len, NULL, NULL, result);
}

long pkm_lcs_source_dispatch_flush_waitable_request(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	if (!waiter)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_flush_request_with_waiter(
		source_id, hive_name, hive_name_len, NULL, waiter, result);
}

static long pkm_lcs_source_transaction_round_trip_timeout_with_limits(
	u32 source_id, u16 op_code, u64 transaction_id, u32 mode,
	const struct pkm_lcs_runtime_limits *limits,
	u32 timeout_ms,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id,
				      op_code == RSI_BEGIN_TRANSACTION ?
					      LCS_OP_TXN_BEGIN :
				      op_code == RSI_COMMIT_TRANSACTION ?
					      LCS_OP_TXN_COMMIT : LCS_OP_TXN_ABORT,
				      transaction_id, timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));
	if (!limits)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_transaction_request_with_waiter(
			source_id, op_code, transaction_id, mode, limits,
			late_effect,
			&waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_begin_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 mode, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_BEGIN_TRANSACTION, transaction_id, mode,
		&limits, timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_begin_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id, u32 mode,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_BEGIN_TRANSACTION, transaction_id, mode,
		limits, timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_begin_transaction_round_trip(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_begin_transaction_round_trip_timeout_with_limits(
		source_id, transaction_id, mode, &limits,
		limits.request_timeout_ms, response, enqueue);
}

long pkm_lcs_source_commit_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0,
		&limits, timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_commit_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0,
		limits, timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_restore_commit_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0,
		limits, timeout_ms, late_effect, response, enqueue);
}

long pkm_lcs_source_commit_transaction_round_trip(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_commit_transaction_round_trip_timeout_with_limits(
		source_id, transaction_id, &limits, limits.request_timeout_ms,
		response, enqueue);
}

long pkm_lcs_source_abort_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0,
		&limits, timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_abort_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout_with_limits(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0,
		limits, timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_abort_transaction_round_trip(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_abort_transaction_round_trip_timeout_with_limits(
		source_id, transaction_id, &limits, limits.request_timeout_ms,
		response, enqueue);
}

long pkm_lcs_source_drop_key_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_DROP_KEY, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));
	if (!limits)
		return -EINVAL;

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_drop_key_request_with_waiter(
			source_id, txn_id, guid, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_drop_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_drop_key_round_trip_timeout_with_limits(
		source_id, txn_id, guid, &limits, timeout_ms, response,
		enqueue);
}

long pkm_lcs_source_drop_key_round_trip(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_drop_key_round_trip_timeout_with_limits(
		source_id, txn_id, guid, &limits, limits.request_timeout_ms,
		response, enqueue);
}

long pkm_lcs_source_create_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_create_key_round_trip_timeout_with_limits(
		source_id, txn_id, guid, name, name_len, parent_guid, sd,
		sd_len, volatile_key, symlink, NULL, timeout_ms, response,
		enqueue);
}

long pkm_lcs_source_create_key_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_CREATE_KEY, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_create_key_request_with_waiter(
			source_id, txn_id, guid, name, name_len,
			parent_guid, sd, sd_len, volatile_key, symlink,
			limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_write_key_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_write_key_round_trip_timeout_late_effect_with_limits(
		source_id, txn_id, guid, sd, sd_len, last_write_time, limits,
		timeout_ms, NULL, response, enqueue);
}

long pkm_lcs_source_write_key_round_trip_timeout_late_effect_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_WRITE_KEY, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_write_key_request_with_waiter(
			source_id, txn_id, guid, sd, sd_len, last_write_time,
			limits, late_effect, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_write_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_write_key_round_trip_timeout_with_limits(
		source_id, txn_id, guid, sd, sd_len, last_write_time, NULL,
		timeout_ms, response, enqueue);
}

long pkm_lcs_source_set_value_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_set_value_round_trip_timeout_late_effect_with_limits(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, value_type, data, data_len,
		sequence, expected_sequence, limits, timeout_ms, NULL,
		response, enqueue);
}

long pkm_lcs_source_set_value_round_trip_timeout_late_effect_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_SET_VALUE, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_set_value_request_with_waiter(
			source_id, txn_id, guid, value_name, value_name_len,
			layer_name, layer_name_len, value_type, data, data_len,
			sequence, expected_sequence, limits, late_effect, &waiter,
			enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_set_value_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_set_value_round_trip_timeout_with_limits(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, value_type, data, data_len,
		sequence, expected_sequence, NULL, timeout_ms, response,
		enqueue);
}

long pkm_lcs_source_delete_value_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_DELETE_VALUE, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_delete_value_entry_request_with_waiter(
			source_id, txn_id, guid, value_name, value_name_len,
			layer_name, layer_name_len, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_delete_value_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_delete_value_entry_round_trip_timeout_with_limits(
		source_id, txn_id, guid, value_name, value_name_len,
		layer_name, layer_name_len, NULL, timeout_ms, response, enqueue);
}

long pkm_lcs_source_set_blanket_tombstone_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_BLANKET_TOMBSTONE, txn_id,
				      timeout_ms, false, false, 0);

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_set_blanket_tombstone_request_with_waiter(
			source_id, txn_id, guid, layer_name, layer_name_len,
			set, sequence, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	return pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							 response);
}

long pkm_lcs_source_set_blanket_tombstone_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_set_blanket_tombstone_round_trip_timeout_with_limits(
		source_id, txn_id, guid, layer_name, layer_name_len, set,
		sequence, NULL, timeout_ms, response, enqueue);
}

long pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_LOOKUP, txn_id,
				      timeout_ms, false, false, 0);

	if (!frame)
		return -EINVAL;
	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	pkm_lcs_source_response_frame_init(frame);
	ret = pkm_lcs_source_response_waiter_retain_frame(&waiter, frame);
	if (ret)
		return ret;
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_lookup_request_with_waiter(
			source_id, txn_id, parent_guid, child_name,
			child_name_len, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	ret = pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							response);
	if (ret)
		pkm_lcs_source_response_frame_destroy(frame);
	return ret;
}

long pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		NULL, timeout_ms, frame, response, enqueue);
}

long
pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_ENUM_CHILDREN, txn_id,
				      timeout_ms, false, false, 0);

	if (!frame)
		return -EINVAL;
	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	pkm_lcs_source_response_frame_init(frame);
	ret = pkm_lcs_source_response_waiter_retain_frame(&waiter, frame);
	if (ret)
		return ret;
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_enum_children_request_with_waiter(
			source_id, txn_id, parent_guid, limits, &waiter,
			enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	ret = pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							response);
	if (ret)
		pkm_lcs_source_response_frame_destroy(frame);
	return ret;
}

long pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		source_id, txn_id, parent_guid, NULL, timeout_ms, frame,
		response, enqueue);
}

long pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_READ_KEY, txn_id,
				      timeout_ms, false, false, 0);

	if (!frame)
		return -EINVAL;
	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	pkm_lcs_source_response_frame_init(frame);
	ret = pkm_lcs_source_response_waiter_retain_frame(&waiter, frame);
	if (ret)
		return ret;
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_read_key_request_with_waiter(
			source_id, txn_id, guid, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	ret = pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							response);
	if (ret)
		pkm_lcs_source_response_frame_destroy(frame);
	return ret;
}

long pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		source_id, txn_id, guid, NULL, timeout_ms, frame, response,
		enqueue);
}

long pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	trace_lcs_rsi_roundtrip_begin(source_id, LCS_OP_QUERY_VALUES, txn_id,
				      timeout_ms, false, false, 0);

	if (!frame)
		return -EINVAL;
	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	pkm_lcs_source_response_frame_init(frame);
	ret = pkm_lcs_source_response_waiter_retain_frame(&waiter, frame);
	if (ret)
		return ret;
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, limits, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_query_values_request_with_waiter(
			source_id, txn_id, guid, value_name, value_name_len,
			query_all, limits, &waiter, enqueue);
		if (ret != -EAGAIN)
			break;
		if (!pkm_lcs_source_deadline_remaining(deadline))
			return -ETIMEDOUT;
	}
	if (ret)
		return ret;

	ret = pkm_lcs_source_response_waiter_wait_until(&waiter, deadline,
							response);
	if (ret)
		pkm_lcs_source_response_frame_destroy(frame);
	return ret;
}

long pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		source_id, txn_id, guid, value_name, value_name_len,
		query_all, NULL, timeout_ms, frame, response, enqueue);
}
