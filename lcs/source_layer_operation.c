// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source layer-operation orchestration.
 */

#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"
#include "source_internal.h"
#include "transaction_fd.h"

#include <trace/events/lcs.h>

static bool pkm_lcs_source_generation_skip_matches(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE], u32 skip_source_id,
	const u8 skip_root_guid[RSI_GUID_SIZE])
{
	return skip_source_id && skip_root_guid && source_id == skip_source_id &&
	       !memcmp(root_guid, skip_root_guid, RSI_GUID_SIZE);
}

static long pkm_lcs_source_preflight_layer_operation_generations(
	const u32 *source_ids, u32 source_count, u32 skip_source_id,
	const u8 skip_root_guid[RSI_GUID_SIZE])
{
	u32 i;
	long ret = 0;

	if (source_count && !source_ids)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	for (i = 0; i < source_count; i++) {
		struct pkm_lcs_source_slot *slot;
		u32 j;

		slot = pkm_lcs_source_slot_find_locked(source_ids[i]);
		if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
			ret = -EIO;
			goto out_unlock;
		}

		for (j = 0; j < slot->hive_count; j++) {
			struct pkm_lcs_source_registration_hive_copy *hive =
				&slot->hives[j];

			if (pkm_lcs_source_generation_skip_matches(
				    slot->source_id, hive->root_guid,
				    skip_source_id, skip_root_guid))
				continue;
			if (hive->hive_generation == U64_MAX) {
				ret = -EOVERFLOW;
				goto out_unlock;
			}
		}
	}

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

static long pkm_lcs_source_record_layer_operation_generations(
	u32 source_id, u32 skip_source_id,
	const u8 skip_root_guid[RSI_GUID_SIZE], u32 *hive_count_out)
{
	struct pkm_lcs_source_slot *slot;
	u32 hive_count = 0;
	u32 i;
	long ret = 0;

	if (hive_count_out)
		*hive_count_out = 0;
	if (!source_id || !hive_count_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
		ret = -EIO;
		goto out_unlock;
	}

	for (i = 0; i < slot->hive_count; i++) {
		struct pkm_lcs_source_registration_hive_copy *hive =
			&slot->hives[i];

		if (pkm_lcs_source_generation_skip_matches(
			    slot->source_id, hive->root_guid, skip_source_id,
			    skip_root_guid))
			continue;
		if (hive->hive_generation == U64_MAX) {
			ret = -EOVERFLOW;
			goto out_unlock;
		}
	}

	for (i = 0; i < slot->hive_count; i++) {
		struct pkm_lcs_source_registration_hive_copy *hive =
			&slot->hives[i];

		if (pkm_lcs_source_generation_skip_matches(
			    slot->source_id, hive->root_guid, skip_source_id,
			    skip_root_guid))
			continue;
		hive->hive_generation++;
		hive_count++;
	}
	*hive_count_out = hive_count;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_delete_layer_round_trip_timeout_with_limits(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

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

		ret = pkm_lcs_source_dispatch_delete_layer_request_with_waiter(
			source_id, layer_name, layer_name_len, limits, &waiter,
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

long pkm_lcs_source_delete_layer_round_trip_timeout(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_round_trip_timeout_with_limits(
		source_id, layer_name, layer_name_len, &limits, timeout_ms,
		response, enqueue);
}

static long pkm_lcs_source_delete_layer_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	if (!frame)
		return -EINVAL;
	if (!limits)
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

		ret = pkm_lcs_source_dispatch_delete_layer_request_with_waiter(
			source_id, layer_name, layer_name_len, limits, &waiter,
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

static long pkm_lcs_source_apply_delete_layer_orphan_response_with_limits(
	u32 source_id, const struct pkm_lcs_source_response_frame *frame,
	u64 request_id,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_delete_layer_orphan_apply_result *result)
{
	struct pkm_lcs_rsi_delete_layer_response_summary summary = { };
	u32 immediate_drop_count = 0;
	u32 marked_fd_count = 0;
	size_t guid_offset;
	u8 guid[RSI_GUID_SIZE];
	u32 i;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!source_id || !frame || !frame->data || !limits)
		return -EINVAL;

	ret = pkm_lcs_rsi_validate_delete_layer_response(
		frame->data, frame->len, request_id, &summary);
	if (ret)
		return ret;

	guid_offset = RSI_MIN_RESPONSE_SIZE + sizeof(u32);
	for (i = 0; i < summary.orphaned_guid_count; i++) {
		u32 marked = 0;
		u32 live_refs = 0;

		if (guid_offset > frame->len ||
		    frame->len - guid_offset < RSI_GUID_SIZE)
			return -EIO;
		memcpy(guid, frame->data + guid_offset, sizeof(guid));
		guid_offset += RSI_GUID_SIZE;

		ret = pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted_with_refs_limits(
			source_id, guid, limits, &marked, &live_refs);
		if (ret)
			return ret;
		if (check_add_overflow(marked_fd_count, marked,
				       &marked_fd_count))
			return -EOVERFLOW;
		if (!live_refs) {
			ret = pkm_lcs_source_dispatch_drop_key_request_with_limits(
				source_id, 0, guid, limits, NULL);
			if (!ret)
				immediate_drop_count++;
		}
	}

	if (result) {
		result->orphaned_guid_count = summary.orphaned_guid_count;
		result->marked_fd_count = marked_fd_count;
		result->immediate_drop_count = immediate_drop_count;
	}
	return 0;
}

long pkm_lcs_source_apply_delete_layer_orphan_response(
	u32 source_id, const struct pkm_lcs_source_response_frame *frame,
	u64 request_id,
	struct pkm_lcs_delete_layer_orphan_apply_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_apply_delete_layer_orphan_response_with_limits(
		source_id, frame, request_id, &limits, result);
}

static long pkm_lcs_source_delete_layer_validate_request(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits)
{
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_LENGTH_PREFIX_SIZE +
		   PKM_LCS_MAX_LAYER_NAME_BYTES_HARD];
	struct pkm_lcs_rsi_built_request built;

	return pkm_lcs_rsi_build_delete_layer_request_with_limits(
		request, sizeof(request), 0, 0, layer_name, layer_name_len,
		limits, &built);
}

static long pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout_with_limits(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_delete_layer_orphan_apply_result *orphan_result,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_result local_response = { };
	struct pkm_lcs_source_response_frame frame;
	long ret;

	if (!response)
		response = &local_response;
	if (!limits)
		return -EINVAL;

	ret = pkm_lcs_source_delete_layer_round_trip_retaining_frame_timeout_with_limits(
		source_id, layer_name, layer_name_len, limits, timeout_ms,
		&frame, response, enqueue);
	if (ret) {
		pkm_lcs_source_response_frame_destroy(&frame);
		return ret;
	}

	ret = pkm_lcs_source_apply_delete_layer_orphan_response_with_limits(
		source_id, &frame, response->request_id, limits,
		orphan_result);
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

long pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	u32 timeout_ms,
	struct pkm_lcs_delete_layer_orphan_apply_result *orphan_result,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout_with_limits(
		source_id, layer_name, layer_name_len, &limits, timeout_ms,
		orphan_result, response, enqueue);
}

static long pkm_lcs_source_pending_layer_delete_peek(
	u32 source_id, char **layer_name_out, u32 *layer_name_len_out)
{
	struct pkm_lcs_pending_layer_delete *entry;
	struct pkm_lcs_source_slot *slot;
	char *layer_name = NULL;
	u32 layer_name_len = 0;
	long ret = 0;

	if (layer_name_out)
		*layer_name_out = NULL;
	if (layer_name_len_out)
		*layer_name_len_out = 0;
	if (!source_id || !layer_name_out || !layer_name_len_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
		ret = -EIO;
		goto out_unlock;
	}
	if (list_empty(&slot->pending_layer_deletes))
		goto out_unlock;

	entry = list_first_entry(&slot->pending_layer_deletes,
				 struct pkm_lcs_pending_layer_delete, link);
	layer_name = kmemdup_nul(entry->name, entry->name_len, GFP_KERNEL);
	if (!layer_name) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	layer_name_len = entry->name_len;

out_unlock:
	pkm_lcs_source_table_unlock();
	if (ret) {
		kfree(layer_name);
		return ret;
	}

	*layer_name_out = layer_name;
	*layer_name_len_out = layer_name_len;
	return 0;
}

static long pkm_lcs_source_pending_layer_delete_remove(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_pending_layer_delete *entry;
	struct pkm_lcs_pending_layer_delete *tmp;
	struct pkm_lcs_source_slot *slot;
	bool equal = false;
	long ret = -ENOENT;

	if (!source_id || !layer_name || !layer_name_len || !limits)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
		ret = -EIO;
		goto out_unlock;
	}

	list_for_each_entry_safe(entry, tmp, &slot->pending_layer_deletes,
				 link) {
		ret = pkm_lcs_layer_name_casefold_equal_with_limits(
			entry->name, entry->name_len, layer_name, layer_name_len,
			limits, &equal);
		if (ret)
			goto out_unlock;
		if (!equal) {
			ret = -ENOENT;
			continue;
		}

		list_del(&entry->link);
		kfree(entry);
		slot->pending_layer_delete_count--;
		ret = 0;
		goto out_unlock;
	}

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_replay_pending_layer_deletes_with_limits(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits)
{
	char *layer_name = NULL;
	u32 layer_name_len = 0;
	long ret;

	if (!source_id || !limits)
		return -EINVAL;

	for (;;) {
		u32 generation_hive_count = 0;
		u32 watch_overflow_count = 0;

		ret = pkm_lcs_source_pending_layer_delete_peek(
			source_id, &layer_name, &layer_name_len);
		if (ret)
			return ret;
		if (!layer_name) {
			trace_lcs_layer_replay(source_id, 0, 0, 0, 0, 0, 0);
			return 0;
		}

		ret = pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout_with_limits(
			source_id, layer_name, layer_name_len, limits,
			limits->request_timeout_ms, NULL, NULL, NULL);
		if (ret)
			goto out_free;

		ret = pkm_lcs_source_record_layer_operation_generations(
			source_id, 0, NULL, &generation_hive_count);
		if (ret) {
			ret = -EIO;
			goto out_free;
		}

		ret = pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
			source_id, limits, &watch_overflow_count);
		if (ret) {
			ret = -EIO;
			goto out_free;
		}

		ret = pkm_lcs_source_pending_layer_delete_remove(
			source_id, layer_name, layer_name_len, limits);
		kfree(layer_name);
		layer_name = NULL;
		if (ret)
			return ret;
	}

out_free:
	trace_lcs_layer_replay(source_id, layer_name_len,
			       layer_name ? jhash(layer_name, layer_name_len, 0) :
					    0,
			       0, 0, 0, ret);
	kfree(layer_name);
	return ret;
}

static long
pkm_lcs_source_delete_layer_broadcast_apply_orphans_skip_generation_timeout_with_limits(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	u32 skip_source_id, const u8 skip_root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_delete_layer_broadcast_result *result)
{
	u32 *source_ids;
	u32 source_count = 0;
	u32 i;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));

	if (!limits)
		return -EINVAL;

	/*
	 * Up to PKM_LCS_MAX_REGISTERED_SOURCES_HARD (256) source ids — too
	 * large to snapshot on the kernel stack, so allocate the scratch array.
	 */
	source_ids = kmalloc_array(PKM_LCS_MAX_REGISTERED_SOURCES_HARD,
				   sizeof(*source_ids), GFP_KERNEL);
	if (!source_ids)
		return -ENOMEM;

	ret = pkm_lcs_source_delete_layer_validate_request(layer_name,
							   layer_name_len,
							   limits);
	if (ret)
		goto out;

	pkm_lcs_source_table_lock();
	ret = pkm_lcs_source_record_down_layer_delete_locked(
		layer_name, layer_name_len, limits, NULL);
	pkm_lcs_source_table_unlock();
	if (ret)
		goto out;

	ret = pkm_lcs_source_active_ids_snapshot(
		source_ids, PKM_LCS_MAX_REGISTERED_SOURCES_HARD, &source_count);
	if (ret)
		goto out;

	ret = pkm_lcs_source_preflight_layer_operation_generations(
		source_ids, source_count, skip_source_id, skip_root_guid);
	if (ret)
		goto out;

	if (result)
		result->active_source_count = source_count;

	for (i = 0; i < source_count; i++) {
		struct pkm_lcs_delete_layer_orphan_apply_result apply = { };
		u32 generation_hive_count = 0;
		u32 watch_overflow_count = 0;

		ret = pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout_with_limits(
			source_ids[i], layer_name, layer_name_len, limits,
			timeout_ms, &apply, NULL, NULL);
		if (ret)
			goto out;

		ret = pkm_lcs_source_record_layer_operation_generations(
			source_ids[i], skip_source_id, skip_root_guid,
			&generation_hive_count);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(source_ids[i]);
			ret = -EIO;
			goto out;
		}

		ret = pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
			source_ids[i], limits, &watch_overflow_count);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(source_ids[i]);
			ret = -EIO;
			goto out;
		}

		if (result) {
			result->completed_source_count++;
			if (check_add_overflow(result->orphaned_guid_count,
					       apply.orphaned_guid_count,
					       &result->orphaned_guid_count)) {
				ret = -EOVERFLOW;
				goto out;
			}
			if (check_add_overflow(result->marked_fd_count,
					       apply.marked_fd_count,
					       &result->marked_fd_count)) {
				ret = -EOVERFLOW;
				goto out;
			}
			if (check_add_overflow(result->immediate_drop_count,
					       apply.immediate_drop_count,
					       &result->immediate_drop_count)) {
				ret = -EOVERFLOW;
				goto out;
			}
			if (check_add_overflow(result->generation_hive_count,
					       generation_hive_count,
					       &result->generation_hive_count)) {
				ret = -EOVERFLOW;
				goto out;
			}
			if (check_add_overflow(result->watch_overflow_count,
					       watch_overflow_count,
					       &result->watch_overflow_count)) {
				ret = -EOVERFLOW;
				goto out;
			}
		}
	}

	ret = 0;
out:
	trace_lcs_layer_broadcast(
		skip_source_id, layer_name_len,
		layer_name ? jhash(layer_name, layer_name_len, 0) : 0, 0, 0,
		result ? (result->completed_source_count ? 1 : 0) : 0, ret);
	kfree(source_ids);
	return ret;
}

static long
pkm_lcs_source_delete_layer_broadcast_apply_orphans_skip_generation_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	u32 skip_source_id, const u8 skip_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_delete_layer_broadcast_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_broadcast_apply_orphans_skip_generation_timeout_with_limits(
		layer_name, layer_name_len, timeout_ms, skip_source_id,
		skip_root_guid, &limits, result);
}

long pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_delete_layer_broadcast_result *result)
{
	return pkm_lcs_source_delete_layer_broadcast_apply_orphans_skip_generation_timeout(
		layer_name, layer_name_len, timeout_ms, 0, NULL, result);
}

static void pkm_lcs_source_mark_ids_down(const u32 *source_ids,
					 u32 source_count)
{
	u32 i;

	if (!source_ids)
		return;

	for (i = 0; i < source_count; i++)
		pkm_lcs_source_mark_down_by_id(source_ids[i]);
}

long pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
	u32 skip_source_id, const u8 skip_root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_operation_recovery_result *result)
{
	u32 source_ids[PKM_LCS_MAX_REGISTERED_SOURCES_HARD];
	u32 source_count = 0;
	u32 i;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (skip_source_id && !skip_root_guid)
		return -EINVAL;

	ret = pkm_lcs_source_active_ids_snapshot(
		source_ids, ARRAY_SIZE(source_ids), &source_count);
	if (ret)
		return ret;

	ret = pkm_lcs_source_preflight_layer_operation_generations(
		source_ids, source_count, skip_source_id, skip_root_guid);
	if (ret) {
		pkm_lcs_source_mark_ids_down(source_ids, source_count);
		return -EIO;
	}

	if (result)
		result->active_source_count = source_count;

	for (i = 0; i < source_count; i++) {
		u32 generation_hive_count = 0;
		u32 watch_overflow_count = 0;

		ret = pkm_lcs_source_record_layer_operation_generations(
			source_ids[i], skip_source_id, skip_root_guid,
			&generation_hive_count);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(source_ids[i]);
			return -EIO;
		}

		ret = pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
			source_ids[i], limits, &watch_overflow_count);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(source_ids[i]);
			return -EIO;
		}

		if (result) {
			result->completed_source_count++;
			if (check_add_overflow(result->generation_hive_count,
					       generation_hive_count,
					       &result->generation_hive_count))
				return -EOVERFLOW;
			if (check_add_overflow(result->watch_overflow_count,
					       watch_overflow_count,
					       &result->watch_overflow_count))
				return -EOVERFLOW;
		}
	}

	return 0;
}

long pkm_lcs_source_layer_operation_recover_skip_generation(
	u32 skip_source_id, const u8 skip_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_layer_operation_recovery_result *result)
{
	return pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
		skip_source_id, skip_root_guid, NULL, result);
}

long pkm_lcs_source_layer_operation_recover(
	struct pkm_lcs_layer_operation_recovery_result *result)
{
	return pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
		0, NULL, NULL, result);
}

long pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	u32 skip_source_id, const u8 skip_root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_delete_layer_orchestration_result *result)
{
	struct pkm_lcs_transaction_layer_abort_result abort_result = { };
	struct pkm_lcs_delete_layer_broadcast_result broadcast_result = { };
	bool removed = false;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!limits)
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_abort_layer_writers_with_limits(
		layer_name, layer_name_len, limits, &abort_result);
	if (result) {
		result->inspected_transaction_count =
			abort_result.inspected_transaction_count;
		result->affected_bound_transaction_count =
			abort_result.affected_bound_transaction_count;
		result->abort_dispatched_count =
			abort_result.abort_dispatched_count;
	}
	if (ret)
		return ret;

	ret = pkm_lcs_layer_table_remove_with_limits(layer_name, layer_name_len,
						     limits, &removed);
	if (result)
		result->layer_table_entry_removed = removed ? 1U : 0U;
	if (ret)
		return ret;

	ret = pkm_lcs_source_delete_layer_broadcast_apply_orphans_skip_generation_timeout_with_limits(
		layer_name, layer_name_len, timeout_ms, skip_source_id,
		skip_root_guid, limits, &broadcast_result);
	if (result) {
		result->active_source_count = broadcast_result.active_source_count;
		result->completed_source_count =
			broadcast_result.completed_source_count;
		result->orphaned_guid_count =
			broadcast_result.orphaned_guid_count;
		result->marked_fd_count = broadcast_result.marked_fd_count;
		result->immediate_drop_count =
			broadcast_result.immediate_drop_count;
		result->generation_hive_count =
			broadcast_result.generation_hive_count;
		result->watch_overflow_count =
			broadcast_result.watch_overflow_count;
	}
	trace_lcs_layer_delete_orchestrate(
		skip_source_id, layer_name_len,
		layer_name ? jhash(layer_name, layer_name_len, 0) : 0, 0, 0,
		(result && result->layer_table_entry_removed) ? 1 : 0, ret);
	return ret;
}

long pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	u32 skip_source_id, const u8 skip_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_delete_layer_orchestration_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
		layer_name, layer_name_len, timeout_ms, skip_source_id,
		skip_root_guid, &limits, result);
}

long pkm_lcs_source_delete_layer_orchestrate_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_delete_layer_orchestration_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
		layer_name, layer_name_len, timeout_ms, 0, NULL, &limits,
		result);
}

long pkm_lcs_source_delete_layer_round_trip(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_round_trip_timeout_with_limits(
		source_id, layer_name, layer_name_len, &limits,
		limits.request_timeout_ms, response, enqueue);
}

long pkm_lcs_source_flush_round_trip_timeout_with_limits(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

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

		ret = pkm_lcs_source_dispatch_flush_request_with_waiter(
			source_id, hive_name, hive_name_len, limits, &waiter,
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

long pkm_lcs_source_flush_round_trip_timeout(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_flush_round_trip_timeout_with_limits(
		source_id, hive_name, hive_name_len, &limits, timeout_ms,
		response, enqueue);
}

long pkm_lcs_source_delete_layer_round_trip_retaining_frame_timeout(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_delete_layer_round_trip_retaining_frame_timeout_with_limits(
		source_id, layer_name, layer_name_len, &limits, timeout_ms,
		frame, response, enqueue);
}

long pkm_lcs_source_flush_round_trip(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_flush_round_trip_timeout_with_limits(
		source_id, hive_name, hive_name_len, &limits,
		limits.request_timeout_ms, response, enqueue);
}
