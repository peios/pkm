// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source table and global source sequence state.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>

#include <trace/events/lcs.h>

#include "source_internal.h"

static DEFINE_MUTEX(pkm_lcs_source_table_mutex);
static DEFINE_MUTEX(pkm_lcs_sequence_allocation_gate_mutex);
static struct pkm_lcs_source_slot
	pkm_lcs_source_slots[PKM_LCS_MAX_REGISTERED_SOURCES_HARD];
static bool pkm_lcs_sequence_initialized;
static u64 pkm_lcs_next_sequence;
static DECLARE_WAIT_QUEUE_HEAD(pkm_lcs_source_slot_wait);
static atomic64_t pkm_lcs_source_slot_epoch = ATOMIC64_INIT(0);

void pkm_lcs_source_table_lock(void)
{
	mutex_lock(&pkm_lcs_source_table_mutex);
}

void pkm_lcs_source_table_unlock(void)
{
	mutex_unlock(&pkm_lcs_source_table_mutex);
}

void pkm_lcs_source_table_assert_locked(void)
{
	lockdep_assert_held(&pkm_lcs_source_table_mutex);
}

void pkm_lcs_source_sequence_gate_lock(void)
{
	mutex_lock(&pkm_lcs_sequence_allocation_gate_mutex);
}

void pkm_lcs_source_sequence_gate_unlock(void)
{
	mutex_unlock(&pkm_lcs_sequence_allocation_gate_mutex);
}

void pkm_lcs_source_slot_waiters_wake(void)
{
	atomic64_inc(&pkm_lcs_source_slot_epoch);
	wake_up_interruptible(&pkm_lcs_source_slot_wait);
}

s64 pkm_lcs_source_slot_wait_epoch_snapshot(void)
{
	return atomic64_read(&pkm_lcs_source_slot_epoch);
}

long pkm_lcs_source_slot_wait_epoch_change_interruptible_timeout(
	s64 epoch, long timeout)
{
	return wait_event_interruptible_timeout(
		pkm_lcs_source_slot_wait,
		atomic64_read(&pkm_lcs_source_slot_epoch) != epoch, timeout);
}

void pkm_lcs_source_table_sequence_snapshot_locked(bool *initialized,
						   u64 *next_sequence)
{
	pkm_lcs_source_table_assert_locked();

	if (initialized)
		*initialized = pkm_lcs_sequence_initialized;
	if (next_sequence)
		*next_sequence = pkm_lcs_next_sequence;
}

void pkm_lcs_source_table_sequence_set_locked(bool initialized,
					      u64 next_sequence)
{
	pkm_lcs_source_table_assert_locked();

	pkm_lcs_sequence_initialized = initialized;
	pkm_lcs_next_sequence = next_sequence;
}

void pkm_lcs_source_slot_pending_layer_deletes_destroy(
	struct pkm_lcs_source_slot *slot)
{
	struct pkm_lcs_pending_layer_delete *entry;
	struct pkm_lcs_pending_layer_delete *tmp;

	if (!slot || !slot->occupied)
		return;

	list_for_each_entry_safe(entry, tmp, &slot->pending_layer_deletes,
				 link) {
		list_del(&entry->link);
		kfree(entry);
	}
	slot->pending_layer_delete_count = 0;
}

void pkm_lcs_source_slot_view_buffer_init(
	struct pkm_lcs_source_slot_view_buffer *buffer)
{
	buffer->views = buffer->stack;
	buffer->capacity = ARRAY_SIZE(buffer->stack);
}

void pkm_lcs_source_slot_view_buffer_destroy(
	struct pkm_lcs_source_slot_view_buffer *buffer)
{
	if (buffer->views != buffer->stack)
		kfree(buffer->views);
	memset(buffer, 0, sizeof(*buffer));
}

static u32 pkm_lcs_source_table_occupied_count_locked(void)
{
	u32 count = 0;
	u32 i;

	pkm_lcs_source_table_assert_locked();

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		if (pkm_lcs_source_slots[i].occupied)
			count++;
	}
	return count;
}

static u32 pkm_lcs_source_table_views_locked(
	struct pkm_lcs_source_slot_view_copy *views)
{
	u32 count = 0;
	u32 i;

	pkm_lcs_source_table_assert_locked();

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		struct pkm_lcs_source_slot *slot = &pkm_lcs_source_slots[i];

		if (!slot->occupied)
			continue;

		views[count].source_id = slot->source_id;
		views[count].status = slot->status;
		views[count].hive_count = slot->hive_count;
		views[count]._pad = 0;
		views[count].hives = slot->hives;
		count++;
	}
	return count;
}

long pkm_lcs_source_slot_view_buffer_prepare_locked(
	struct pkm_lcs_source_slot_view_buffer *buffer, u32 *count_out)
{
	struct pkm_lcs_source_slot_view_copy *views;
	u32 occupied;

	pkm_lcs_source_table_assert_locked();

	if (!buffer || !count_out)
		return -EINVAL;

	occupied = pkm_lcs_source_table_occupied_count_locked();
	if (occupied > buffer->capacity) {
		views = kcalloc(occupied, sizeof(*views), GFP_KERNEL);
		if (!views)
			return -ENOMEM;
		buffer->views = views;
		buffer->capacity = occupied;
	}

	*count_out = pkm_lcs_source_table_views_locked(buffer->views);
	return 0;
}

struct pkm_lcs_source_slot *pkm_lcs_source_slot_find_locked(u32 source_id)
{
	u32 i;

	pkm_lcs_source_table_assert_locked();

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		if (pkm_lcs_source_slots[i].occupied &&
		    pkm_lcs_source_slots[i].source_id == source_id)
			return &pkm_lcs_source_slots[i];
	}
	return NULL;
}

struct pkm_lcs_source_slot *pkm_lcs_source_slot_free_locked(void)
{
	u32 i;

	pkm_lcs_source_table_assert_locked();

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		if (!pkm_lcs_source_slots[i].occupied)
			return &pkm_lcs_source_slots[i];
	}
	return NULL;
}

u32 pkm_lcs_source_slot_id(const struct pkm_lcs_source_slot *slot)
{
	return (u32)(slot - pkm_lcs_source_slots) + 1U;
}

static long pkm_lcs_source_slot_pending_layer_delete_find_locked(
	struct pkm_lcs_source_slot *slot, const char *layer_name,
	u32 layer_name_len, const struct pkm_lcs_runtime_limits *limits,
	bool *found)
{
	struct pkm_lcs_pending_layer_delete *entry;
	long ret;

	pkm_lcs_source_table_assert_locked();

	if (!slot || !layer_name || !limits || !found)
		return -EINVAL;

	*found = false;
	list_for_each_entry(entry, &slot->pending_layer_deletes, link) {
		ret = pkm_lcs_layer_name_casefold_equal_with_limits(
			entry->name, entry->name_len, layer_name, layer_name_len,
			limits, found);
		if (ret)
			return ret;
		if (*found)
			return 0;
	}
	return 0;
}

static long pkm_lcs_source_slot_pending_layer_delete_add_locked(
	struct pkm_lcs_source_slot *slot, const char *layer_name,
	u32 layer_name_len, const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_pending_layer_delete *entry;
	bool found = false;
	long ret;

	pkm_lcs_source_table_assert_locked();

	if (!slot || !slot->occupied || !layer_name || !layer_name_len ||
	    !limits)
		return -EINVAL;
	if (layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;

	ret = pkm_lcs_source_slot_pending_layer_delete_find_locked(
		slot, layer_name, layer_name_len, limits, &found);
	if (ret || found)
		return ret;
	if (slot->pending_layer_delete_count >= limits->max_total_layers)
		return -ENOSPC;

	entry = kmalloc(struct_size(entry, name, (size_t)layer_name_len + 1),
			GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->name_len = layer_name_len;
	memcpy(entry->name, layer_name, layer_name_len);
	entry->name[layer_name_len] = '\0';

	list_add_tail(&entry->link, &slot->pending_layer_deletes);
	slot->pending_layer_delete_count++;
	return 0;
}

long pkm_lcs_source_record_down_layer_delete_locked(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 *pending_count_out)
{
	u32 pending_count = 0;
	u32 i;
	long ret;

	pkm_lcs_source_table_assert_locked();

	if (pending_count_out)
		*pending_count_out = 0;
	if (!layer_name || !layer_name_len || !limits)
		return -EINVAL;

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		struct pkm_lcs_source_slot *slot = &pkm_lcs_source_slots[i];

		if (!slot->occupied ||
		    slot->status != PKM_LCS_SOURCE_SLOT_STATUS_DOWN)
			continue;

		ret = pkm_lcs_source_slot_pending_layer_delete_add_locked(
			slot, layer_name, layer_name_len, limits);
		if (ret)
			return ret;
		pending_count++;
	}

	if (pending_count_out)
		*pending_count_out = pending_count;
	return 0;
}

struct pkm_lcs_source_registration_hive_copy *
pkm_lcs_source_slot_hive_find_locked(struct pkm_lcs_source_slot *slot,
				     const u8 root_guid[RSI_GUID_SIZE])
{
	u32 i;

	pkm_lcs_source_table_assert_locked();

	if (!slot || !root_guid || !slot->hives)
		return NULL;

	for (i = 0; i < slot->hive_count; i++) {
		if (!memcmp(slot->hives[i].root_guid, root_guid,
			    sizeof(slot->hives[i].root_guid)))
			return &slot->hives[i];
	}
	return NULL;
}

long pkm_lcs_source_record_transaction_generation(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 *generation_out)
{
	struct pkm_lcs_source_registration_hive_copy *hive;
	struct pkm_lcs_source_slot *slot;
	long ret = -EIO;

	if (generation_out)
		*generation_out = 0;
	if (!source_id || !root_guid || !generation_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
		goto out_unlock;

	hive = pkm_lcs_source_slot_hive_find_locked(slot, root_guid);
	if (!hive)
		goto out_unlock;
	if (hive->hive_generation == U64_MAX) {
		ret = -EOVERFLOW;
		trace_lcs_record_generation(source_id, 0, hive->hive_generation,
					    ret);
		goto out_unlock;
	}

	hive->hive_generation++;
	*generation_out = hive->hive_generation;
	ret = 0;
	trace_lcs_record_generation(source_id, 0, hive->hive_generation, ret);

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_hive_generation_snapshot(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 *generation_out)
{
	struct pkm_lcs_source_registration_hive_copy *hive;
	struct pkm_lcs_source_slot *slot;
	long ret = -EIO;

	if (generation_out)
		*generation_out = 0;
	if (!source_id || !root_guid || !generation_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
		goto out_unlock;
	hive = pkm_lcs_source_slot_hive_find_locked(slot, root_guid);
	if (!hive)
		goto out_unlock;

	*generation_out = hive->hive_generation;
	ret = 0;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_bound_transaction_acquire(u32 source_id, u32 *count_out)
{
	struct pkm_lcs_source_slot *slot;
	u32 cap = pkm_lcs_runtime_max_bound_transactions_per_source();
	long ret = 0;

	if (count_out)
		*count_out = 0;
	if (!source_id || !count_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
		ret = -EIO;
		goto out_unlock;
	}
	if (slot->bound_transaction_count >= cap) {
		ret = -EBUSY;
		trace_lcs_bound_txn_acquire(source_id,
					    slot->bound_transaction_count, cap,
					    ret);
		goto out_unlock;
	}

	slot->bound_transaction_count++;
	*count_out = slot->bound_transaction_count;
	trace_lcs_bound_txn_acquire(source_id, slot->bound_transaction_count,
				    cap, ret);

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_bound_transaction_release(u32 source_id, u32 *count_out)
{
	struct pkm_lcs_source_slot *slot;
	long ret = 0;

	if (count_out)
		*count_out = 0;
	if (!source_id || !count_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || !slot->occupied || !slot->bound_transaction_count) {
		ret = -EIO;
		goto out_unlock;
	}

	slot->bound_transaction_count--;
	*count_out = slot->bound_transaction_count;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_read_only_transaction_acquire_with_limits(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits,
	u32 *count_out)
{
	struct pkm_lcs_source_slot *slot;
	long ret = 0;

	if (count_out)
		*count_out = 0;
	if (!source_id || !limits || !count_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
		ret = -EIO;
		goto out_unlock;
	}
	if (slot->read_only_transaction_count >=
	    limits->max_read_only_transactions_per_source) {
		ret = -EBUSY;
		trace_lcs_readonly_txn_acquire(
			source_id, slot->read_only_transaction_count,
			limits->max_read_only_transactions_per_source, ret);
		goto out_unlock;
	}

	slot->read_only_transaction_count++;
	*count_out = slot->read_only_transaction_count;
	trace_lcs_readonly_txn_acquire(
		source_id, slot->read_only_transaction_count,
		limits->max_read_only_transactions_per_source, ret);

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_read_only_transaction_acquire(u32 source_id,
						  u32 *count_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_read_only_transaction_acquire_with_limits(
		source_id, &limits, count_out);
}

long pkm_lcs_source_read_only_transaction_release(u32 source_id,
						 u32 *count_out)
{
	struct pkm_lcs_source_slot *slot;
	long ret = 0;

	if (count_out)
		*count_out = 0;
	if (!source_id || !count_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || !slot->occupied ||
	    !slot->read_only_transaction_count) {
		ret = -EIO;
		goto out_unlock;
	}

	slot->read_only_transaction_count--;
	*count_out = slot->read_only_transaction_count;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_active_ids_snapshot(u32 *source_ids, u32 max_source_ids,
					u32 *count_out)
{
	u32 active_count = 0;
	u32 written = 0;
	u32 i;
	long ret = 0;

	if (count_out)
		*count_out = 0;
	if (!source_ids || !max_source_ids || !count_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		struct pkm_lcs_source_slot *slot = &pkm_lcs_source_slots[i];

		if (!slot->occupied ||
		    slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
			continue;
		if (!slot->active_fd) {
			ret = -EIO;
			goto out_unlock;
		}
		active_count++;
	}

	*count_out = active_count;
	if (active_count > max_source_ids) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		struct pkm_lcs_source_slot *slot = &pkm_lcs_source_slots[i];

		if (!slot->occupied ||
		    slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
			continue;
		source_ids[written++] = slot->source_id;
	}

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_restart_generation_snapshot(u32 source_id,
						u64 *generation_out)
{
	struct pkm_lcs_source_slot *slot;
	long ret = 0;

	if (generation_out)
		*generation_out = 0;
	if (!source_id || !generation_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || !slot->occupied) {
		ret = -ENOENT;
		goto out_unlock;
	}

	*generation_out = slot->restart_generation;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_next_sequence_snapshot(u64 *next_sequence)
{
	if (!next_sequence)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	if (!pkm_lcs_sequence_initialized) {
		pkm_lcs_source_table_unlock();
		return -EIO;
	}

	*next_sequence = pkm_lcs_next_sequence;
	pkm_lcs_source_table_unlock();
	return 0;
}

long pkm_lcs_allocate_sequence(u64 *sequence)
{
	if (!sequence)
		return -EINVAL;

	*sequence = 0;
	pkm_lcs_source_sequence_gate_lock();
	pkm_lcs_source_table_lock();
	if (!pkm_lcs_sequence_initialized) {
		pkm_lcs_source_table_unlock();
		pkm_lcs_source_sequence_gate_unlock();
		return -EIO;
	}
	if (pkm_lcs_next_sequence == U64_MAX) {
		pkm_lcs_source_table_unlock();
		pkm_lcs_source_sequence_gate_unlock();
		trace_lcs_allocate_sequence(0, 0, pkm_lcs_next_sequence,
					    -EOVERFLOW);
		return -EOVERFLOW;
	}

	*sequence = pkm_lcs_next_sequence;
	pkm_lcs_next_sequence++;
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_sequence_gate_unlock();
	trace_lcs_allocate_sequence(0, 0, *sequence, 0);
	return 0;
}

long pkm_lcs_restore_sequence_gate_acquire(
	struct pkm_lcs_restore_sequence_gate *gate)
{
	if (!gate)
		return -EINVAL;

	memset(gate, 0, sizeof(*gate));
	pkm_lcs_source_sequence_gate_lock();
	pkm_lcs_source_table_lock();
	if (!pkm_lcs_sequence_initialized) {
		pkm_lcs_source_table_unlock();
		pkm_lcs_source_sequence_gate_unlock();
		return -EIO;
	}

	gate->restore_sequence_offset = pkm_lcs_next_sequence;
	gate->held = true;
	pkm_lcs_source_table_unlock();
	return 0;
}

long pkm_lcs_restore_sequence_gate_validate(
	const struct pkm_lcs_restore_sequence_gate *gate,
	u64 backup_sequence, u64 *new_sequence)
{
	u64 mapped;

	if (!gate || !gate->held || !new_sequence)
		return -EINVAL;
	*new_sequence = 0;
	if (check_add_overflow(gate->restore_sequence_offset,
			       backup_sequence, &mapped))
		return -EOVERFLOW;
	if (mapped == U64_MAX)
		return -EOVERFLOW;

	*new_sequence = mapped;
	return 0;
}

long pkm_lcs_restore_sequence_gate_record_dispatched(
	struct pkm_lcs_restore_sequence_gate *gate,
	u64 backup_sequence, u64 *new_sequence)
{
	long ret;

	ret = pkm_lcs_restore_sequence_gate_validate(gate, backup_sequence,
						    new_sequence);
	if (ret)
		return ret;

	if (!gate->max_dispatched_valid ||
	    *new_sequence > gate->max_dispatched_sequence) {
		gate->max_dispatched_sequence = *new_sequence;
		gate->max_dispatched_valid = true;
	}
	return 0;
}

long pkm_lcs_restore_sequence_gate_release_terminal(
	struct pkm_lcs_restore_sequence_gate *gate)
{
	u64 required_next;
	long ret = 0;

	if (!gate)
		return -EINVAL;
	if (!gate->held)
		return 0;

	if (gate->max_dispatched_valid) {
		if (check_add_overflow(gate->max_dispatched_sequence, 1ULL,
				       &required_next)) {
			ret = -EOVERFLOW;
			trace_lcs_restore_sequence(0, 0,
						   gate->max_dispatched_sequence,
						   ret);
			goto out_release;
		}

		pkm_lcs_source_table_lock();
		if (!pkm_lcs_sequence_initialized) {
			ret = -EIO;
		} else if (pkm_lcs_next_sequence < required_next) {
			pkm_lcs_next_sequence = required_next;
		}
		pkm_lcs_source_table_unlock();
		trace_lcs_restore_sequence(0, 0, required_next, ret);
	}

out_release:
	memset(gate, 0, sizeof(*gate));
	pkm_lcs_source_sequence_gate_unlock();
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_lcs_kunit_reset_source_table(void)
{
	u32 i;

	pkm_lcs_source_table_lock();
	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		pkm_lcs_source_slot_pending_layer_deletes_destroy(
			&pkm_lcs_source_slots[i]);
		pkm_lcs_source_hives_destroy(pkm_lcs_source_slots[i].hives,
					     pkm_lcs_source_slots[i].hive_count);
		memset(&pkm_lcs_source_slots[i], 0,
		       sizeof(pkm_lcs_source_slots[i]));
	}
	pkm_lcs_sequence_initialized = false;
	pkm_lcs_next_sequence = 0;
	pkm_lcs_source_table_unlock();
}

void pkm_lcs_kunit_set_sequence_state(bool initialized, u64 next_sequence)
{
	pkm_lcs_source_table_lock();
	pkm_lcs_sequence_initialized = initialized;
	pkm_lcs_next_sequence = next_sequence;
	pkm_lcs_source_table_unlock();
}

void pkm_lcs_kunit_source_table_snapshot(
	struct pkm_lcs_source_table_snapshot *snapshot)
{
	u32 i;

	if (!snapshot)
		return;

	memset(snapshot, 0, sizeof(*snapshot));
	pkm_lcs_source_table_lock();
	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_HARD; i++) {
		struct pkm_lcs_source_slot *slot = &pkm_lcs_source_slots[i];

		if (!slot->occupied)
			continue;
		snapshot->occupied_count++;
		if (slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
			snapshot->active_count++;
		if (slot->status == PKM_LCS_SOURCE_SLOT_STATUS_DOWN)
			snapshot->down_count++;
		snapshot->pending_layer_delete_count +=
			slot->pending_layer_delete_count;
	}
	snapshot->sequence_initialized = pkm_lcs_sequence_initialized;
	snapshot->next_sequence = pkm_lcs_next_sequence;
	pkm_lcs_source_table_unlock();
}

long pkm_lcs_kunit_source_hive_generation_snapshot(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 *generation_out)
{
	struct pkm_lcs_source_registration_hive_copy *hive;
	struct pkm_lcs_source_slot *slot;
	long ret = -EIO;

	if (generation_out)
		*generation_out = 0;
	if (!source_id || !root_guid || !generation_out)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
		goto out_unlock;
	hive = pkm_lcs_source_slot_hive_find_locked(slot, root_guid);
	if (!hive)
		goto out_unlock;

	*generation_out = hive->hive_generation;
	ret = 0;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_kunit_source_hive_generation_set(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE], u64 generation)
{
	struct pkm_lcs_source_registration_hive_copy *hive;
	struct pkm_lcs_source_slot *slot;
	long ret = -EIO;

	if (!source_id || !root_guid)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
		goto out_unlock;
	hive = pkm_lcs_source_slot_hive_find_locked(slot, root_guid);
	if (!hive)
		goto out_unlock;

	hive->hive_generation = generation;
	ret = 0;

out_unlock:
	pkm_lcs_source_table_unlock();
	return ret;
}
#endif
