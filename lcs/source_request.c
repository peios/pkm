// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source RSI request builders and queue admission.
 */

#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "rsi.h"
#include "source_device.h"
#include "source_internal.h"

#include <trace/events/lcs.h>

long pkm_lcs_source_dispatch_lookup_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!parent_guid || !child_name)
		return -EINVAL;
	if (child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)child_name_len, &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_lookup_request(
		request->frame, frame_len, request_id, txn_id, parent_guid,
		child_name, child_name_len, limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		parent_guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_LOOKUP, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}
long pkm_lcs_source_dispatch_read_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid)
		return -EINVAL;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_read_key_request(
		request->frame, frame_len, request_id, txn_id, guid, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_READ_KEY, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_enum_children_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!parent_guid)
		return -EINVAL;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_enum_children_request(
		request->frame, frame_len, request_id, txn_id, parent_guid,
		&built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		parent_guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_ENUM_CHILDREN, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_query_values_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || (value_name_len && !value_name))
		return -EINVAL;
	if (value_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)value_name_len, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u8), &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_query_values_request(
		request->frame, frame_len, request_id, txn_id, guid,
		value_name, value_name_len, query_all, limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_QUERY_VALUES, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_set_value_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || (value_name_len && !value_name) || !layer_name ||
	    (data_len && !data))
		return -EINVAL;
	if (value_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
	    layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (data_len > U32_MAX)
		return -EOVERFLOW;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)value_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)layer_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, data_len, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u64), &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u64), &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_set_value_request(
		request->frame, frame_len, request_id, txn_id, guid,
		value_name, value_name_len, layer_name, layer_name_len,
		value_type, data, data_len, sequence, expected_sequence,
		limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;
	ret = pkm_lcs_source_in_flight_set_key_late_effect_locked(
		source_fd, built.request_id, late_effect);
	if (ret) {
		struct pkm_lcs_source_in_flight_request *record;

		record = pkm_lcs_source_in_flight_find_locked(
			source_fd, built.request_id);
		if (record)
			pkm_lcs_source_in_flight_release_locked(source_fd,
								record);
		goto out_unlock_queue;
	}

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_SET_VALUE, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_delete_value_entry_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || (value_name_len && !value_name) || !layer_name)
		return -EINVAL;
	if (value_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
	    layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)value_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)layer_name_len,
			       &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_delete_value_entry_request(
		request->frame, frame_len, request_id, txn_id, guid,
		value_name, value_name_len, layer_name, layer_name_len,
		limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_DELETE_VALUE, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_set_blanket_tombstone_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || !layer_name)
		return -EINVAL;
	if (layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)layer_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u8), &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u64), &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_set_blanket_tombstone_request(
		request->frame, frame_len, request_id, txn_id, guid,
		layer_name, layer_name_len, set, sequence, limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_BLANKET_TOMBSTONE, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_drop_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || !memchr_inv(guid, 0, RSI_GUID_SIZE))
		return -EINVAL;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_drop_key_request(
		request->frame, frame_len, request_id, txn_id, guid, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_DROP_KEY, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_create_entry_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!parent_guid || !child_name || !layer_name || !child_guid)
		return -EINVAL;
	if (child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
	    layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)child_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)layer_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, (size_t)RSI_GUID_SIZE,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u64), &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_create_entry_request(
		request->frame, frame_len, request_id, txn_id, parent_guid,
		child_name, child_name_len, layer_name, layer_name_len,
		child_guid, sequence, limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		child_guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_CREATE_ENTRY, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
	u32 source_id, u64 txn_id, bool hide,
	const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!parent_guid || !child_name || !layer_name)
		return -EINVAL;
	if (child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
	    layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)child_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)layer_name_len,
			       &frame_len) ||
	    (hide && check_add_overflow(frame_len, sizeof(u64),
					&frame_len)))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	if (hide)
		ret = pkm_lcs_rsi_build_hide_entry_request(
			request->frame, frame_len, request_id, txn_id,
			parent_guid, child_name, child_name_len, layer_name,
			layer_name_len, sequence, limits, &built);
	else
		ret = pkm_lcs_rsi_build_delete_entry_request(
			request->frame, frame_len, request_id, txn_id,
			parent_guid, child_name, child_name_len, layer_name,
			layer_name_len, limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		parent_guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id,
			      hide ? LCS_OP_HIDE_ENTRY : LCS_OP_DELETE_ENTRY,
			      txn_id, result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_create_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || !name || !parent_guid || !sd || !sd_len)
		return -EINVAL;
	if (name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;
	if (sd_len > U32_MAX)
		return -EOVERFLOW;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)name_len, &frame_len) ||
	    check_add_overflow(frame_len, (size_t)RSI_GUID_SIZE,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, sd_len, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u8), &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u8), &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_create_key_request(
		request->frame, frame_len, request_id, txn_id, guid, name,
		name_len, parent_guid, sd, sd_len, volatile_key, symlink,
		limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_CREATE_KEY, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_write_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || (sd_len && !sd) || (!sd_len && sd))
		return -EINVAL;
	if (sd_len > U32_MAX)
		return -EOVERFLOW;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len))
		return -EOVERFLOW;
	if (sd_len &&
	    (check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	     check_add_overflow(frame_len, sd_len, &frame_len)))
		return -EOVERFLOW;
	if (check_add_overflow(frame_len, sizeof(u64), &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_write_key_request(
		request->frame, frame_len, request_id, txn_id, guid, sd,
		sd_len, last_write_time, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		guid, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;
	ret = pkm_lcs_source_in_flight_set_key_late_effect_locked(
		source_fd, built.request_id, late_effect);
	if (ret) {
		struct pkm_lcs_source_in_flight_request *record;

		record = pkm_lcs_source_in_flight_find_locked(
			source_fd, built.request_id);
		if (record)
			pkm_lcs_source_in_flight_release_locked(source_fd,
								record);
		goto out_unlock_queue;
	}

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_WRITE_KEY, txn_id,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_transaction_request_with_waiter(
	u32 source_id, u16 op_code, u64 transaction_id, u32 mode,
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len = RSI_REQUEST_HEADER_SIZE + sizeof(u64);
	u64 header_txn_id;
	u64 retained_txn_id;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}

	switch (op_code) {
	case RSI_BEGIN_TRANSACTION:
		if (mode != RSI_TXN_READ_WRITE && mode != RSI_TXN_READ_ONLY)
			return -EINVAL;
		if (check_add_overflow(frame_len, sizeof(u32), &frame_len))
			return -EOVERFLOW;
		header_txn_id = 0;
		retained_txn_id = transaction_id;
		break;
	case RSI_COMMIT_TRANSACTION:
	case RSI_ABORT_TRANSACTION:
		header_txn_id = transaction_id;
		retained_txn_id = transaction_id;
		break;
	default:
		return -EINVAL;
	}

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	switch (op_code) {
	case RSI_BEGIN_TRANSACTION:
		ret = pkm_lcs_rsi_build_begin_transaction_request(
			request->frame, frame_len, request_id, header_txn_id,
			transaction_id, mode, &built);
		break;
	case RSI_COMMIT_TRANSACTION:
		ret = pkm_lcs_rsi_build_commit_transaction_request(
			request->frame, frame_len, request_id, header_txn_id,
			transaction_id, &built);
		break;
	case RSI_ABORT_TRANSACTION:
		ret = pkm_lcs_rsi_build_abort_transaction_request(
			request->frame, frame_len, request_id, header_txn_id,
			transaction_id, &built);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, retained_txn_id, built.op_code,
		NULL, limits, late_effect, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id,
			      op_code == RSI_BEGIN_TRANSACTION ?
				      LCS_OP_TXN_BEGIN :
			      op_code == RSI_COMMIT_TRANSACTION ?
				      LCS_OP_TXN_COMMIT : LCS_OP_TXN_ABORT,
			      transaction_id, result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_flush_request_with_waiter(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!hive_name || !hive_name_len)
		return -EINVAL;
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	if (hive_name_len > PKM_LCS_MAX_HIVE_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)hive_name_len, &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_flush_request(
		request->frame, frame_len, request_id, 0, hive_name,
		hive_name_len, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		NULL, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_FLUSH, 0,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}

long pkm_lcs_source_dispatch_delete_layer_request_with_waiter(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len;
	u64 request_id;
	u64 next_request_id;
	bool names_base_layer = false;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!layer_name || !layer_name_len || !limits)
		return -EINVAL;
	ret = pkm_lcs_layer_name_casefold_is_base_with_limits(
		layer_name, layer_name_len, limits, &names_base_layer);
	if (ret)
		return ret;
	if (names_base_layer)
		return -EINVAL;
	if (layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)layer_name_len, &frame_len))
		return -EOVERFLOW;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmalloc(frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&request->link);

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd) {
		ret = -EIO;
		goto out_unlock_table;
	}

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
		goto out_unlock_queue;
	}
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd, limits)) {
		ret = -EAGAIN;
		goto out_unlock_queue;
	}

	request_id = source_fd->next_request_id;
	ret = pkm_lcs_source_request_id_successor(request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_rsi_build_delete_layer_request_with_limits(
		request->frame, frame_len, request_id, 0, layer_name,
		layer_name_len, limits, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		NULL, limits, NULL, waiter);
	if (ret)
		goto out_unlock_queue;

	request->len = built.len;
	request->request_id = built.request_id;
	request->txn_id = built.txn_id;
	request->op_code = built.op_code;
	list_add_tail(&request->link, &source_fd->request_queue);
	source_fd->queued_request_count++;
	source_fd->next_request_id = next_request_id;
	pkm_lcs_source_enqueue_result_fill_locked(result, request, source_fd);
	request = NULL;
	ret = 0;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
	if (!ret)
		wake_up_interruptible(&source_fd->read_wait);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_queued_request_free(request);
	trace_lcs_rsi_request(source_id, LCS_OP_DELETE_LAYER, 0,
			      result ? result->request_id : 0,
			      result ? result->queue_depth : 0,
			      result ? result->in_flight_count : 0, ret);
	return ret;
}
