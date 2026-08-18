// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source-device entrypoint.
 *
 * PSD-005 requires sources to obtain RSI fds through /dev/pkm_registry and
 * requires the open path to be gated by SeTcbPrivilege before any source fd is
 * issued.
 */

#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "../kmes/kmes.h"
#include "rsi.h"
#include "source_device.h"
#include "source_internal.h"
#include "transaction_fd.h"

#include <trace/events/lcs.h>

extern int lcs_rust_validate_rsi_queued_request_frame(
	const u8 *frame, size_t frame_len,
	struct pkm_lcs_rsi_built_request *retained);

static void pkm_lcs_source_fd_init(struct pkm_lcs_source_fd *source_fd)
{
	source_fd->state = PKM_LCS_SOURCE_FD_UNREGISTERED;
	source_fd->source_id = 0;
	mutex_init(&source_fd->queue_lock);
	init_waitqueue_head(&source_fd->read_wait);
	INIT_LIST_HEAD(&source_fd->request_queue);
	source_fd->queued_request_count = 0;
	source_fd->in_flight_request_count = 0;
	source_fd->next_request_id = 0;
	INIT_LIST_HEAD(&source_fd->in_flight_requests);
	source_fd->closing = false;
}

void pkm_lcs_source_queued_request_free(
	struct pkm_lcs_source_queued_request *request)
{
	if (!request)
		return;

	kfree(request->frame);
	kfree(request);
}

static void pkm_lcs_source_queue_destroy_locked(
	struct pkm_lcs_source_fd *source_fd)
{
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_queued_request *next;

	lockdep_assert_held(&source_fd->queue_lock);

	list_for_each_entry_safe(request, next, &source_fd->request_queue,
				 link) {
		list_del(&request->link);
		pkm_lcs_source_queued_request_free(request);
	}
	source_fd->queued_request_count = 0;
}

static void pkm_lcs_source_in_flight_destroy_locked(
	struct pkm_lcs_source_fd *source_fd)
{
	bool had_in_flight;
	struct pkm_lcs_source_in_flight_request *record;
	struct pkm_lcs_source_in_flight_request *next;

	lockdep_assert_held(&source_fd->queue_lock);

	had_in_flight = source_fd->in_flight_request_count != 0;
	list_for_each_entry_safe(record, next, &source_fd->in_flight_requests,
				 link) {
		if (record->occupied && record->waiter) {
			struct pkm_lcs_source_response_result result = {
				.request_id = record->request_id,
				.txn_id = record->txn_id,
				.request_op_code = record->op_code,
				.status = RSI_STORAGE_ERROR,
				.malformed_source_data = false,
				.caller_waiter_attached = true,
			};

			pkm_lcs_source_response_waiter_complete(record->waiter,
								-EIO,
								&result);
		}
		list_del(&record->link);
		pkm_lcs_source_late_effect_destroy(&record->late_effect);
		kfree(record);
	}
	source_fd->in_flight_request_count = 0;
	if (had_in_flight)
		pkm_lcs_source_slot_waiters_wake();
}

static u32 pkm_lcs_source_in_flight_limit(
	const struct pkm_lcs_runtime_limits *limits)
{
	if (limits)
		return limits->max_concurrent_rsi_requests;
	return pkm_lcs_runtime_max_concurrent_rsi_requests();
}

bool pkm_lcs_source_in_flight_at_limit_locked(
	const struct pkm_lcs_source_fd *source_fd,
	const struct pkm_lcs_runtime_limits *limits)
{
	lockdep_assert_held(&source_fd->queue_lock);

	return source_fd->in_flight_request_count >=
	       pkm_lcs_source_in_flight_limit(limits);
}

long pkm_lcs_source_request_id_successor(u64 request_id, u64 *next)
{
	if (!next)
		return -EINVAL;
	if (request_id == ~0ULL)
		return -EOVERFLOW;

	*next = request_id + 1;
	return 0;
}

static long pkm_lcs_source_slot_admission_state(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	long ret = -EIO;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    !slot->active_fd)
		goto out_unlock_table;

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE ||
	    source_fd->source_id != source_id) {
		ret = -EIO;
	} else if (pkm_lcs_source_in_flight_at_limit_locked(source_fd,
							    limits)) {
		ret = -EAGAIN;
	} else {
		ret = 0;
	}
	mutex_unlock(&source_fd->queue_lock);

out_unlock_table:
	pkm_lcs_source_table_unlock();
	return ret;
}

long pkm_lcs_source_wait_for_slot(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits,
	unsigned long deadline)
{
	long ret;

	for (;;) {
		s64 epoch = pkm_lcs_source_slot_wait_epoch_snapshot();
		long remaining;
		long wait_ret;

		ret = pkm_lcs_source_slot_admission_state(source_id, limits);
		if (ret != -EAGAIN)
			break;

		remaining = pkm_lcs_source_deadline_remaining(deadline);
		if (!remaining) {
			ret = -ETIMEDOUT;
			break;
		}

		wait_ret =
			pkm_lcs_source_slot_wait_epoch_change_interruptible_timeout(
				epoch, remaining);
		if (wait_ret < 0) {
			ret = wait_ret;
			break;
		}
		if (!wait_ret) {
			ret = -ETIMEDOUT;
			break;
		}
	}

	/*
	 * A source's round trip cannot proceed until it holds an admission slot;
	 * emit the slot-wait leg of the round trip only when it terminates
	 * without one (op/txn are unknown at this shared sink -> 0).
	 */
	if (ret)
		trace_lcs_rsi_roundtrip_complete(source_id, 0, 0, 0, false,
						 ret == -ETIMEDOUT, ret);
	return ret;
}

long pkm_lcs_source_in_flight_insert_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id, u64 txn_id,
	u16 op_code, const u8 key_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter)
{
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_in_flight_request *record;
	long ret;

	lockdep_assert_held(&source_fd->queue_lock);

	if (limits)
		effective_limits = *limits;
	else
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
	if (pkm_lcs_source_in_flight_at_limit_locked(source_fd,
						    &effective_limits))
		return -EAGAIN;

	list_for_each_entry(record, &source_fd->in_flight_requests, link) {
		if (record->occupied && record->request_id == request_id)
			return -EINVAL;
	}

	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return -ENOMEM;

	INIT_LIST_HEAD(&record->link);
	record->occupied = true;
	record->delivered = false;
	record->response_accepted = false;
	record->request_id = request_id;
	record->txn_id = txn_id;
	record->op_code = op_code;
	record->key_guid_present = key_guid != NULL;
	if (key_guid)
		memcpy(record->key_guid, key_guid, sizeof(record->key_guid));
	record->limits = effective_limits;
	if (late_effect) {
		ret = pkm_lcs_source_late_effect_copy_restore(
			&record->late_effect, late_effect);
		if (ret) {
			pkm_lcs_source_late_effect_destroy(
				&record->late_effect);
			kfree(record);
			return ret;
		}
	}
	record->waiter = waiter;
	record->waiter_was_attached = waiter != NULL;
	if (waiter) {
		waiter->source_id = source_fd->source_id;
		waiter->request_id = request_id;
		WRITE_ONCE(waiter->attached, true);
		WRITE_ONCE(waiter->detached, false);
	}
	list_add_tail(&record->link, &source_fd->in_flight_requests);
	source_fd->in_flight_request_count++;
	trace_lcs_in_flight(source_fd->source_id, request_id,
			    source_fd->in_flight_request_count, LCS_IF_INSERT,
			    0);
	return 0;
}

struct pkm_lcs_source_in_flight_request *
pkm_lcs_source_in_flight_find_locked(struct pkm_lcs_source_fd *source_fd,
				     u64 request_id)
{
	struct pkm_lcs_source_in_flight_request *record;

	lockdep_assert_held(&source_fd->queue_lock);

	list_for_each_entry(record, &source_fd->in_flight_requests, link) {
		if (record->occupied && record->request_id == request_id)
			return record;
	}

	return NULL;
}

long pkm_lcs_source_in_flight_set_key_late_effect_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect)
{
	struct pkm_lcs_source_in_flight_request *record;
	long ret;

	lockdep_assert_held(&source_fd->queue_lock);

	if (!late_effect)
		return 0;
	record = pkm_lcs_source_in_flight_find_locked(source_fd, request_id);
	if (!record)
		return -EIO;
	if (record->late_effect.kind != PKM_LCS_SOURCE_LATE_EFFECT_NONE)
		return -EINVAL;

	ret = pkm_lcs_source_late_effect_copy_key_mutation(
		&record->late_effect, late_effect);
	if (ret)
		pkm_lcs_source_late_effect_destroy(&record->late_effect);
	return ret;
}

long pkm_lcs_source_in_flight_set_delivered_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id, bool delivered)
{
	struct pkm_lcs_source_in_flight_request *record;

	lockdep_assert_held(&source_fd->queue_lock);

	record = pkm_lcs_source_in_flight_find_locked(source_fd, request_id);
	if (!record)
		return -EIO;

	record->delivered = delivered;
	if (delivered)
		trace_lcs_in_flight(source_fd->source_id, request_id,
				    source_fd->in_flight_request_count,
				    LCS_IF_DELIVERED, 0);
	return 0;
}

void pkm_lcs_source_in_flight_release_locked(
	struct pkm_lcs_source_fd *source_fd,
	struct pkm_lcs_source_in_flight_request *record)
{
	lockdep_assert_held(&source_fd->queue_lock);

	if (!record || !record->occupied)
		return;

	list_del(&record->link);
	pkm_lcs_source_late_effect_destroy(&record->late_effect);
	{
		u64 released_request_id = record->request_id;

		kfree(record);
		if (source_fd->in_flight_request_count) {
			source_fd->in_flight_request_count--;
			pkm_lcs_source_slot_waiters_wake();
		}
		trace_lcs_in_flight(source_fd->source_id, released_request_id,
				    source_fd->in_flight_request_count,
				    LCS_IF_RELEASE, 0);
	}
}

void pkm_lcs_source_enqueue_result_fill_locked(
	struct pkm_lcs_source_enqueue_result *result,
	const struct pkm_lcs_source_queued_request *request,
	const struct pkm_lcs_source_fd *source_fd)
{
	lockdep_assert_held(&source_fd->queue_lock);

	if (!result)
		return;

	result->len = request->len;
	result->request_id = request->request_id;
	result->txn_id = request->txn_id;
	result->op_code = request->op_code;
	result->queue_depth = source_fd->queued_request_count;
	result->in_flight_count = source_fd->in_flight_request_count;
	result->next_request_id = source_fd->next_request_id;
}

bool pkm_lcs_source_read_ready(struct pkm_lcs_source_fd *source_fd)
{
	return READ_ONCE(source_fd->queued_request_count) > 0 ||
	       READ_ONCE(source_fd->closing);
}

long pkm_lcs_source_device_open_for_token(const void *token)
{
	long ret;

	ret = pkm_lcs_source_device_check_tcb(token);
	if (ret)
		return ret;

	return pkm_lcs_source_device_mark_tcb_used(token);
}

long pkm_lcs_source_device_open_file_for_token(const void *token,
					       struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;
	long ret;

	/*
	 * Linux misc_open() stores the struct miscdevice * in
	 * file->private_data before invoking this .open handler, so a fresh
	 * open of /dev/pkm_registry always arrives with private_data already
	 * non-NULL. We do not use that pointer; the success path below
	 * overwrites it with our per-fd state. Rejecting a non-NULL
	 * private_data here would fail every real open with EINVAL (the
	 * misc framework never hands us a NULL one).
	 */
	if (!file)
		return -EINVAL;

	ret = pkm_lcs_source_device_check_tcb(token);
	if (ret)
		return ret;

	source_fd = kzalloc(sizeof(*source_fd), GFP_KERNEL);
	if (!source_fd)
		return -ENOMEM;
	pkm_lcs_source_fd_init(source_fd);

	ret = pkm_lcs_source_device_mark_tcb_used(token);
	if (ret) {
		kfree(source_fd);
		return ret;
	}

	file->private_data = source_fd;
	trace_lcs_source_fd(0, source_fd->state, 0, 0, LCS_SRC_OPEN, 0);
	return 0;
}

static u32 pkm_lcs_source_fd_mark_down_locked(
	struct pkm_lcs_source_fd *source_fd)
{
	struct pkm_lcs_source_slot *slot;
	u32 source_down_id = 0;

	pkm_lcs_source_table_assert_locked();
	lockdep_assert_held(&source_fd->queue_lock);

	source_fd->closing = true;
	pkm_lcs_source_queue_destroy_locked(source_fd);
	pkm_lcs_source_in_flight_destroy_locked(source_fd);

	if (source_fd->state == PKM_LCS_SOURCE_FD_ACTIVE) {
		slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
		if (slot && slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE &&
		    slot->active_fd == source_fd) {
			slot->status = PKM_LCS_SOURCE_SLOT_STATUS_DOWN;
			slot->active_fd = NULL;
			slot->bound_transaction_count = 0;
			slot->read_only_transaction_count = 0;
			source_down_id = source_fd->source_id;
		}
	}

	return source_down_id;
}

void pkm_lcs_source_device_mark_down_file(struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;
	u32 source_down_id;

	if (!file)
		return;

	source_fd = file->private_data;
	if (!source_fd)
		return;

	pkm_lcs_source_table_lock();
	mutex_lock(&source_fd->queue_lock);
	source_down_id = pkm_lcs_source_fd_mark_down_locked(source_fd);
	mutex_unlock(&source_fd->queue_lock);
	wake_up_interruptible(&source_fd->read_wait);
	pkm_lcs_source_table_unlock();

	trace_lcs_source_fd(source_fd->source_id, source_fd->state, 0,
			    source_down_id, LCS_SRC_EXPLICIT, 0);
	if (source_down_id)
		(void)pkm_lcs_transaction_fd_mark_source_down(source_down_id,
							      NULL);
}

void pkm_lcs_source_device_mark_malformed_protocol_file(
	struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;
	struct pkm_lcs_source_slot *slot;
	u32 source_down_id = 0;

	if (!file)
		return;

	source_fd = file->private_data;
	if (!source_fd)
		return;

	pkm_lcs_source_table_lock();
	mutex_lock(&source_fd->queue_lock);
	if (source_fd->state == PKM_LCS_SOURCE_FD_ACTIVE) {
		slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
		if (slot && slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE &&
		    slot->active_fd == source_fd)
			source_down_id =
				pkm_lcs_source_fd_mark_down_locked(source_fd);
	}
	mutex_unlock(&source_fd->queue_lock);
	if (source_down_id)
		wake_up_interruptible(&source_fd->read_wait);
	pkm_lcs_source_table_unlock();

	trace_lcs_source_fd(source_fd->source_id, source_fd->state, 0,
			    source_down_id, LCS_SRC_MALFORMED, 0);
	if (source_down_id)
		(void)pkm_lcs_transaction_fd_mark_source_down(source_down_id,
							      NULL);
}

void pkm_lcs_source_mark_down_by_id(u32 source_id)
{
	struct pkm_lcs_source_fd *source_fd = NULL;
	struct pkm_lcs_source_slot *slot;
	u32 source_down_id = 0;

	if (!source_id)
		return;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (slot && slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE &&
	    slot->active_fd) {
		source_fd = slot->active_fd;
		mutex_lock(&source_fd->queue_lock);
		source_down_id = pkm_lcs_source_fd_mark_down_locked(source_fd);
		mutex_unlock(&source_fd->queue_lock);
		wake_up_interruptible(&source_fd->read_wait);
	}
	pkm_lcs_source_table_unlock();

	trace_lcs_source_fd(source_id, source_fd ? source_fd->state : 0, 0,
			    source_down_id, LCS_SRC_MARK_BY_ID, 0);
	if (source_down_id)
		(void)pkm_lcs_transaction_fd_mark_source_down(source_down_id,
							      NULL);
}

int pkm_lcs_source_device_release_file(struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;
	u32 source_down_id = 0;

	if (!file)
		return 0;

	source_fd = file->private_data;
	file->private_data = NULL;
	if (!source_fd)
		return 0;

	pkm_lcs_source_table_lock();
	mutex_lock(&source_fd->queue_lock);
	source_down_id = pkm_lcs_source_fd_mark_down_locked(source_fd);
	mutex_unlock(&source_fd->queue_lock);
	wake_up_interruptible(&source_fd->read_wait);
	pkm_lcs_source_table_unlock();

	trace_lcs_source_fd(source_fd->source_id, source_fd->state, 0,
			    source_down_id, LCS_SRC_RELEASE, 0);
	if (source_down_id)
		(void)pkm_lcs_transaction_fd_mark_source_down(source_down_id,
							      NULL);

	kfree(source_fd);
	return 0;
}

long pkm_lcs_source_enqueue_request(
	u32 source_id, const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request retained = { };
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!frame)
		return -EINVAL;

	ret = lcs_rust_validate_rsi_queued_request_frame(frame, frame_len,
							 &retained);
	if (ret)
		return ret;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;
	request->frame = kmemdup(frame, frame_len, GFP_KERNEL);
	if (!request->frame) {
		kfree(request);
		return -ENOMEM;
	}
	request->len = frame_len;
	request->request_id = retained.request_id;
	request->txn_id = retained.txn_id;
	request->op_code = retained.op_code;
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
	if (retained.request_id < source_fd->next_request_id) {
		ret = -EINVAL;
		goto out_unlock_queue;
	}
	ret = pkm_lcs_source_request_id_successor(retained.request_id,
						  &next_request_id);
	if (ret)
		goto out_unlock_queue;
	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, retained.request_id, retained.txn_id,
		retained.op_code, NULL, NULL, NULL, NULL);
	if (ret)
		goto out_unlock_queue;

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
	return ret;
}

static int pkm_lcs_source_device_open(struct inode *inode, struct file *file)
{
	return pkm_lcs_source_device_open_file_for_token(
		pkm_kacs_current_effective_token_ptr(), file);
}

static ssize_t pkm_lcs_source_device_read(struct file *file, char __user *buf,
					  size_t count, loff_t *ppos)
{
	(void)ppos;

	return pkm_lcs_source_device_read_user(file, buf, count);
}

static ssize_t pkm_lcs_source_device_write(struct file *file,
					   const char __user *buf,
					   size_t count, loff_t *ppos)
{
	(void)ppos;

	return pkm_lcs_source_device_write_user(file, buf, count, NULL);
}

static __poll_t pkm_lcs_source_device_poll(struct file *file,
					   struct poll_table_struct *wait)
{
	struct pkm_lcs_source_fd *source_fd;
	struct pkm_lcs_source_slot *slot;
	__poll_t mask = 0;
	bool active = false;

	if (!file)
		return EPOLLERR | EPOLLHUP;

	source_fd = file->private_data;
	if (!source_fd)
		return EPOLLERR | EPOLLHUP;

	poll_wait(file, &source_fd->read_wait, wait);

	pkm_lcs_source_table_lock();
	mutex_lock(&source_fd->queue_lock);

	if (source_fd->closing) {
		mask = EPOLLERR | EPOLLHUP;
		goto out_unlock;
	}

	if (source_fd->state == PKM_LCS_SOURCE_FD_ACTIVE) {
		slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
		active = slot &&
			 slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE &&
			 slot->active_fd == source_fd;
	}

	if (!active) {
		if (source_fd->state == PKM_LCS_SOURCE_FD_ACTIVE)
			mask = EPOLLERR | EPOLLHUP;
		goto out_unlock;
	}

	if (source_fd->queued_request_count)
		mask |= EPOLLIN;
	mask |= EPOLLOUT;

out_unlock:
	mutex_unlock(&source_fd->queue_lock);
	pkm_lcs_source_table_unlock();
	return mask;
}

static long pkm_lcs_source_device_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	switch (cmd) {
	case REG_SRC_REGISTER:
		return pkm_lcs_source_register_file_for_token_with_bootstrap(
			pkm_kacs_current_effective_token_ptr(), file, NULL,
			(struct reg_src_register_args __user *)arg);
	default:
		return -ENOTTY;
	}
}

static int pkm_lcs_source_device_release(struct inode *inode, struct file *file)
{
	return pkm_lcs_source_device_release_file(file);
}

static const struct file_operations pkm_lcs_source_device_fops = {
	.owner = THIS_MODULE,
	.open = pkm_lcs_source_device_open,
	.read = pkm_lcs_source_device_read,
	.write = pkm_lcs_source_device_write,
	.poll = pkm_lcs_source_device_poll,
	.unlocked_ioctl = pkm_lcs_source_device_ioctl,
	.release = pkm_lcs_source_device_release,
	.llseek = noop_llseek,
};

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_source_register_file_for_token_with_bootstrap(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs)
{
	return pkm_lcs_source_register_file_for_token_with_bootstrap(
		token, file, ops, uargs);
}

long pkm_lcs_kunit_source_device_raw_ioctl(struct file *file, unsigned int cmd,
					   unsigned long arg)
{
	return pkm_lcs_source_device_ioctl(file, cmd, arg);
}

void pkm_lcs_kunit_flush_source_bootstrap_work(void)
{
	pkm_lcs_source_bootstrap_workqueue_flush();
}

void pkm_lcs_kunit_source_fd_snapshot(
	struct file *file, struct pkm_lcs_source_fd_snapshot *snapshot)
{
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;

	if (!snapshot)
		return;

	memset(snapshot, 0, sizeof(*snapshot));
	if (!file)
		return;

	source_fd = file->private_data;
	if (!source_fd)
		return;

	pkm_lcs_source_table_lock();
	mutex_lock(&source_fd->queue_lock);
	snapshot->state = source_fd->state;
	snapshot->source_id = source_fd->source_id;
	snapshot->queued_request_count = source_fd->queued_request_count;
	snapshot->in_flight_request_count =
		source_fd->in_flight_request_count;
	snapshot->next_request_id = source_fd->next_request_id;
	snapshot->closing = source_fd->closing;
	slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
	if (slot && slot->occupied) {
		snapshot->bound_transaction_count =
			slot->bound_transaction_count;
		snapshot->read_only_transaction_count =
			slot->read_only_transaction_count;
	}
	mutex_unlock(&source_fd->queue_lock);
	pkm_lcs_source_table_unlock();
}

long pkm_lcs_kunit_source_slot_admission_state(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits)
{
	return pkm_lcs_source_slot_admission_state(source_id, limits);
}

__poll_t pkm_lcs_kunit_source_device_poll_file(struct file *file)
{
	return pkm_lcs_source_device_fops.poll(file, NULL);
}

__poll_t pkm_lcs_kunit_source_device_poll_file_with_table(
	struct file *file, struct poll_table_struct *wait)
{
	return pkm_lcs_source_device_fops.poll(file, wait);
}

long pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	pkm_lcs_source_response_waiter_init(waiter);
	return pkm_lcs_source_dispatch_enum_children_request_with_waiter(
		source_id, txn_id, parent_guid, NULL, waiter, result);
}
#endif

static struct miscdevice pkm_lcs_source_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pkm_registry",
	.fops = &pkm_lcs_source_device_fops,
};

static int __init pkm_lcs_source_device_init(void)
{
	int ret;

	ret = pkm_lcs_source_bootstrap_workqueue_init();
	if (ret)
		return ret;

	ret = misc_register(&pkm_lcs_source_device);
	if (ret) {
		pr_err("pkm: /dev/pkm_registry registration failed (%d)\n",
		       ret);
		pkm_lcs_source_bootstrap_workqueue_destroy();
	}

	return ret;
}
late_initcall(pkm_lcs_source_device_init);
