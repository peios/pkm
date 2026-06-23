// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source read/write protocol handling for /dev/pkm_registry.
 */

#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/wait.h>

#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"
#include "source_internal.h"
#include "transaction_fd.h"

#define PKM_LCS_RSI_READ_ACTION_COPY 0U
#define PKM_LCS_RSI_READ_ACTION_WAIT 1U
#define PKM_LCS_RSI_READ_ACTION_EAGAIN 2U
#define PKM_LCS_RSI_READ_ACTION_EMSGSIZE 3U
#define PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE 4U

struct pkm_lcs_rsi_read_plan_copy {
	u32 action;
	u32 _pad;
	size_t request_len;
	size_t required_len;
};

struct pkm_lcs_source_copyout_ops {
	bool (*write)(void *ctx, void __user *dst, const void *src, size_t len);
	void *ctx;
};

struct pkm_lcs_source_copyin_ops {
	bool (*read)(void *ctx, void *dst, const void __user *src, size_t len);
	void *ctx;
};

static bool pkm_lcs_default_copy_from_user(void *ctx, void *dst,
					   const void __user *src, size_t len)
{
	(void)ctx;

	return copy_from_user(dst, src, len) == 0;
}

static const struct pkm_lcs_source_copyin_ops pkm_lcs_default_copyin_ops = {
	.read = pkm_lcs_default_copy_from_user,
};

static bool pkm_lcs_default_copy_to_user(void *ctx, void __user *dst,
					 const void *src, size_t len)
{
	(void)ctx;

	return copy_to_user(dst, src, len) == 0;
}

static const struct pkm_lcs_source_copyout_ops pkm_lcs_default_copyout_ops = {
	.write = pkm_lcs_default_copy_to_user,
};

extern int lcs_rust_plan_rsi_source_read(
	bool has_next_request, size_t next_request_len, size_t caller_buffer_len,
	bool nonblocking, bool fd_closing,
	struct pkm_lcs_rsi_read_plan_copy *plan);

static ssize_t pkm_lcs_source_device_read_file_with_ops(
	struct file *file, char __user *buf, size_t count, bool nonblocking,
	const struct pkm_lcs_source_copyout_ops *ops)
{
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_rsi_read_plan_copy plan;
	struct pkm_lcs_source_fd *source_fd;
	long ret;

	if (!file || !ops || !ops->write)
		return -EINVAL;
	source_fd = file->private_data;
	if (!source_fd)
		return -EINVAL;

	for (;;) {
		mutex_lock(&source_fd->queue_lock);
		request = list_first_entry_or_null(
			&source_fd->request_queue,
			struct pkm_lcs_source_queued_request, link);
		memset(&plan, 0, sizeof(plan));
		ret = lcs_rust_plan_rsi_source_read(
			request != NULL, request ? request->len : 0, count,
			nonblocking, source_fd->closing, &plan);
		if (ret) {
			mutex_unlock(&source_fd->queue_lock);
			return ret;
		}

		switch (plan.action) {
		case PKM_LCS_RSI_READ_ACTION_COPY:
			if (!request || plan.request_len != request->len) {
				mutex_unlock(&source_fd->queue_lock);
				return -EINVAL;
			}
			ret = pkm_lcs_source_in_flight_set_delivered_locked(
				source_fd, request->request_id, true);
			if (ret) {
				mutex_unlock(&source_fd->queue_lock);
				return ret;
			}
			if (!ops->write(ops->ctx, buf, request->frame,
					request->len)) {
				pkm_lcs_source_in_flight_set_delivered_locked(
					source_fd, request->request_id, false);
				mutex_unlock(&source_fd->queue_lock);
				return -EFAULT;
			}

			list_del(&request->link);
			source_fd->queued_request_count--;
			mutex_unlock(&source_fd->queue_lock);
			ret = (ssize_t)request->len;
			pkm_lcs_source_queued_request_free(request);
			return ret;
		case PKM_LCS_RSI_READ_ACTION_EAGAIN:
			mutex_unlock(&source_fd->queue_lock);
			return -EAGAIN;
		case PKM_LCS_RSI_READ_ACTION_EMSGSIZE:
			mutex_unlock(&source_fd->queue_lock);
			return -EMSGSIZE;
		case PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE:
			mutex_unlock(&source_fd->queue_lock);
			return 0;
		case PKM_LCS_RSI_READ_ACTION_WAIT:
			mutex_unlock(&source_fd->queue_lock);
			ret = wait_event_interruptible(
				source_fd->read_wait,
				pkm_lcs_source_read_ready(source_fd));
			if (ret)
				return ret;
			break;
		default:
			mutex_unlock(&source_fd->queue_lock);
			return -EINVAL;
		}
	}
}

long pkm_lcs_source_accept_response_file(
	struct file *file, const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_response_result *result)
{
	struct pkm_lcs_source_in_flight_request *record;
	struct pkm_lcs_source_fd *source_fd;
	struct pkm_lcs_source_slot *slot;
	u16 response_op_code;
	u16 expected_op_code;
	u64 request_id;
	u32 total_len;
	u32 status;
	long ret = 0;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!file || !frame)
		return -EINVAL;
	if (frame_len < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;

	total_len = get_unaligned_le32(frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	if ((size_t)total_len != frame_len)
		return -EINVAL;

	request_id = get_unaligned_le64(frame + RSI_RESPONSE_ID_OFFSET);
	response_op_code =
		get_unaligned_le16(frame + RSI_RESPONSE_OP_CODE_OFFSET);
	status = get_unaligned_le32(frame + RSI_RESPONSE_STATUS_OFFSET);

	pkm_lcs_source_table_lock();
	source_fd = file->private_data;
	if (!source_fd) {
		ret = -EINVAL;
		goto out_unlock_table;
	}

	mutex_lock(&source_fd->queue_lock);
	if (source_fd->closing ||
	    source_fd->state != PKM_LCS_SOURCE_FD_ACTIVE) {
		ret = -EINVAL;
		goto out_unlock_queue;
	}

	slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE ||
	    slot->active_fd != source_fd) {
		ret = -EINVAL;
		goto out_unlock_queue;
	}

	record = pkm_lcs_source_in_flight_find_locked(source_fd, request_id);
	if (!record || !record->delivered || record->response_accepted) {
		ret = -EINVAL;
		goto out_unlock_queue;
	}

	expected_op_code = record->op_code | RSI_RESPONSE_BIT;
	if (response_op_code != expected_op_code) {
		ret = -EINVAL;
		goto out_unlock_queue;
	}

	if (result) {
		bool status_known = pkm_lcs_rsi_status_known(status);

		result->len = frame_len;
		result->request_id = record->request_id;
		result->txn_id = record->txn_id;
		result->source_id = source_fd->source_id;
		result->request_op_code = record->op_code;
		result->response_op_code = response_op_code;
		result->status = status;
		result->limits = record->limits;
		result->key_guid_present = record->key_guid_present;
		if (record->key_guid_present)
			memcpy(result->key_guid, record->key_guid,
			       sizeof(result->key_guid));
		if (!record->waiter)
			pkm_lcs_source_late_effect_move(
				&result->late_effect, &record->late_effect);
		result->source_validation_failure = 0;
		result->malformed_source_data = !status_known;
		result->source_validation_failure_present = !status_known;
		if (!status_known)
			result->source_validation_failure =
				PKM_LCS_SOURCE_VALIDATION_UNKNOWN_RSI_STATUS_CODE;
		result->caller_waiter_attached = record->waiter != NULL;
	}

	record->response_accepted = true;
	if (!record->waiter)
		pkm_lcs_source_in_flight_release_locked(source_fd, record);
	if (result)
		result->in_flight_count = source_fd->in_flight_request_count;

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	return ret;
}

static void pkm_lcs_source_emit_validation_failure_for_result(
	const struct pkm_lcs_source_response_result *result)
{
	if (!result || !result->malformed_source_data ||
	    !result->source_validation_failure_present)
		return;

	pkm_lcs_emit_source_validation_failure_audit(
		result->source_id, NULL, 0, false, result->request_id, true,
		result->request_op_code, true,
		result->key_guid_present ? result->key_guid : NULL,
		result->key_guid_present,
		result->source_validation_failure);
}

static bool pkm_lcs_source_late_success_requires_mutation_effects(u16 op_code)
{
	switch (op_code) {
	case RSI_CREATE_ENTRY:
	case RSI_HIDE_ENTRY:
	case RSI_DELETE_ENTRY:
	case RSI_CREATE_KEY:
	case RSI_WRITE_KEY:
	case RSI_DROP_KEY:
	case RSI_SET_VALUE:
	case RSI_DELETE_VALUE_ENTRY:
	case RSI_SET_BLANKET_TOMBSTONE:
	case RSI_DELETE_LAYER:
		return true;
	default:
		return false;
	}
}

static long pkm_lcs_source_handle_late_response_effects_file(
	struct file *file, const struct pkm_lcs_source_response_result *result)
{
	long ret;

	if (!file || !result)
		return -EINVAL;
	if (result->caller_waiter_attached)
		return 0;
	if (result->malformed_source_data) {
		if (result->request_op_code == RSI_COMMIT_TRANSACTION) {
			pkm_lcs_source_device_mark_down_file(file);
			return -EIO;
		}
		return 0;
	}

	switch (result->request_op_code) {
	case RSI_BEGIN_TRANSACTION:
		if (result->status != RSI_OK)
			return 0;
		if (!result->source_id || !result->txn_id) {
			pkm_lcs_source_device_mark_down_file(file);
			return -EIO;
		}

		ret = pkm_lcs_source_dispatch_abort_transaction_request_with_limits(
			result->source_id, result->txn_id, &result->limits,
			NULL);
		if (ret) {
			pkm_lcs_source_device_mark_down_file(file);
			return ret;
		}
		return 0;
	case RSI_COMMIT_TRANSACTION:
		if (result->late_effect.kind ==
		    PKM_LCS_SOURCE_LATE_EFFECT_RESTORE_COMMIT) {
			if (result->status != RSI_OK)
				return 0;
			ret = pkm_lcs_key_fd_publish_restore_commit_effects(
				result->source_id, result->late_effect.key_guid,
				(const u8 (*)[PKM_LCS_GUID_BYTES])
					result->late_effect.ancestor_guids,
				(const char * const *)
					result->late_effect.resolved_path,
				result->late_effect.path_component_count,
				&result->limits);
			if (ret) {
				pkm_lcs_source_device_mark_down_file(file);
				return ret;
			}
			return 0;
		}
		ret = pkm_lcs_transaction_fd_handle_late_commit_response(
			result->source_id, result->txn_id, result->status,
			&result->limits);
		if (ret) {
			pkm_lcs_source_device_mark_down_file(file);
			return ret;
		}
		return 0;
	default:
		if (result->status != RSI_OK)
			return 0;
		if (!pkm_lcs_source_late_success_requires_mutation_effects(
			    result->request_op_code))
			return 0;
		if (result->late_effect.kind !=
		    PKM_LCS_SOURCE_LATE_EFFECT_KEY_MUTATION) {
			pkm_lcs_source_device_mark_down_file(file);
			return -EIO;
		}
		ret = pkm_lcs_key_fd_publish_late_mutation_effects(
			result->source_id, &result->late_effect,
			&result->limits);
		if (ret) {
			pkm_lcs_source_device_mark_down_file(file);
			return -EIO;
		}
		return 0;
	}
}

static long pkm_lcs_source_validate_accepted_response_payload(
	const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_response_result *result, long *caller_errno)
{
	struct pkm_lcs_rsi_lookup_response_summary lookup = { };
	struct pkm_lcs_rsi_query_values_response_summary query_values = { };
	struct pkm_lcs_rsi_enum_children_info_summary enum_children = { };
	struct pkm_lcs_rsi_delete_layer_response_summary delete_layer = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	u64 next_sequence;
	long ret;

	if (!frame || !result || !caller_errno)
		return -EINVAL;
	*caller_errno = pkm_lcs_rsi_status_errno(result->status);
	if (result->malformed_source_data)
		return 0;
	if (*caller_errno)
		return 0;

	switch (result->request_op_code) {
	case RSI_LOOKUP:
		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			return ret;
		ret = pkm_lcs_rsi_validate_lookup_response(
			frame, frame_len, result->request_id, next_sequence,
			&result->limits, &lookup);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			if (lookup.source_validation_failure_present) {
				result->source_validation_failure =
					lookup.source_validation_failure;
				result->source_validation_failure_present = true;
			}
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	case RSI_QUERY_VALUES:
		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			return ret;
		ret = pkm_lcs_rsi_validate_query_values_response(
			frame, frame_len, result->request_id, next_sequence,
			&result->limits, &query_values);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			if (query_values.source_validation_failure_present) {
				result->source_validation_failure =
					query_values.source_validation_failure;
				result->source_validation_failure_present = true;
			}
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	case RSI_ENUM_CHILDREN:
		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			return ret;
		ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
		if (ret)
			return ret;
		ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
			frame, frame_len, result->request_id, next_sequence,
			layer_snapshot.layers, layer_snapshot.layer_count, NULL,
			0, &result->limits, &enum_children);
		pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			if (enum_children.source_validation_failure_present) {
				result->source_validation_failure =
					enum_children.source_validation_failure;
				result->source_validation_failure_present = true;
			}
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	case RSI_READ_KEY:
		ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
			frame, frame_len, result->request_id, &result->limits,
			&read_key);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			if (read_key.source_validation_failure_present) {
				result->source_validation_failure =
					read_key.source_validation_failure;
				result->source_validation_failure_present = true;
			}
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	case RSI_HIDE_ENTRY:
	case RSI_DELETE_ENTRY:
	case RSI_CREATE_ENTRY:
	case RSI_CREATE_KEY:
	case RSI_WRITE_KEY:
	case RSI_SET_VALUE:
	case RSI_DELETE_VALUE_ENTRY:
	case RSI_SET_BLANKET_TOMBSTONE:
	case RSI_BEGIN_TRANSACTION:
	case RSI_COMMIT_TRANSACTION:
	case RSI_ABORT_TRANSACTION:
	case RSI_FLUSH:
	case RSI_DROP_KEY:
		ret = pkm_lcs_rsi_validate_status_only_response(
			frame, frame_len, result->request_id,
			result->request_op_code);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			result->source_validation_failure =
				PKM_LCS_SOURCE_VALIDATION_MALFORMED_RESPONSE_PAYLOAD;
			result->source_validation_failure_present = true;
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	case RSI_DELETE_LAYER:
		ret = pkm_lcs_rsi_validate_delete_layer_response(
			frame, frame_len, result->request_id, &delete_layer);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			if (delete_layer.source_validation_failure_present) {
				result->source_validation_failure =
					delete_layer.source_validation_failure;
				result->source_validation_failure_present = true;
			}
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	default:
		*caller_errno = 0;
		return 0;
	}
}

static long pkm_lcs_source_complete_waiter_file(
	struct file *file, u64 request_id, long caller_errno,
	struct pkm_lcs_source_response_result *result,
	const u8 *frame, size_t frame_len)
{
	struct pkm_lcs_source_in_flight_request *record;
	struct pkm_lcs_source_response_waiter *waiter;
	struct pkm_lcs_source_fd *source_fd;
	long ret = 0;

	if (!file || !result)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	source_fd = file->private_data;
	if (!source_fd) {
		ret = -EINVAL;
		goto out_unlock_table;
	}

	mutex_lock(&source_fd->queue_lock);
	record = pkm_lcs_source_in_flight_find_locked(source_fd, request_id);
	if (!record || !record->response_accepted) {
		ret = -EINVAL;
		goto out_unlock_queue;
	}

	waiter = record->waiter;
	record->waiter = NULL;
	pkm_lcs_source_in_flight_release_locked(source_fd, record);
	result->in_flight_count = source_fd->in_flight_request_count;
	if (waiter) {
		pkm_lcs_source_response_waiter_complete_with_frame(
			waiter, caller_errno, result, frame, frame_len);
	}

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	return ret;
}

static ssize_t pkm_lcs_source_device_write_file_with_ops(
	struct file *file, const char __user *buf, size_t count,
	const struct pkm_lcs_source_copyin_ops *ops,
	struct pkm_lcs_source_response_result *result)
{
	struct pkm_lcs_source_response_result local_result = { };
	u8 header[RSI_MIN_RESPONSE_SIZE];
	u32 total_len;
	u8 *frame;
	long caller_errno = 0;
	long ret;

	if (!file || !ops || !ops->read)
		return -EINVAL;
	if (result)
		memset(result, 0, sizeof(*result));
	else
		result = &local_result;

	if (count < RSI_MIN_RESPONSE_SIZE) {
		pkm_lcs_source_device_mark_malformed_protocol_file(file);
		return -EINVAL;
	}
	if (!buf)
		return -EFAULT;
	if (!ops->read(ops->ctx, header, buf, sizeof(header)))
		return -EFAULT;

	total_len = get_unaligned_le32(header + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	if ((size_t)total_len != count) {
		pkm_lcs_source_device_mark_malformed_protocol_file(file);
		return -EINVAL;
	}

	frame = kmalloc(count, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	if (!ops->read(ops->ctx, frame, buf, count)) {
		ret = -EFAULT;
		goto out_free;
	}

	ret = pkm_lcs_source_accept_response_file(file, frame, count, result);
	if (ret) {
		if (ret == -EINVAL)
			pkm_lcs_source_device_mark_malformed_protocol_file(file);
		goto out_free;
	}

	ret = pkm_lcs_source_validate_accepted_response_payload(
		frame, count, result, &caller_errno);
	if (!ret)
		pkm_lcs_source_emit_validation_failure_for_result(result);
	if (ret && result->caller_waiter_attached)
		pkm_lcs_source_complete_waiter_file(file, result->request_id,
						    -EIO, result, NULL, 0);
	if (!ret && result->caller_waiter_attached)
		ret = pkm_lcs_source_complete_waiter_file(
			file, result->request_id, caller_errno, result,
			frame, count);
	if (!ret)
		ret = pkm_lcs_source_handle_late_response_effects_file(file,
								       result);
	if (!ret)
		ret = (ssize_t)count;

out_free:
	pkm_lcs_source_late_effect_destroy(&result->late_effect);
	kfree(frame);
	return ret;
}

ssize_t pkm_lcs_source_device_read_user(struct file *file, char __user *buf,
					size_t count)
{
	bool nonblocking;

	if (!file)
		return -EINVAL;

	nonblocking = (file->f_flags & O_NONBLOCK) != 0;
	return pkm_lcs_source_device_read_file_with_ops(
		file, buf, count, nonblocking, &pkm_lcs_default_copyout_ops);
}

ssize_t pkm_lcs_source_device_write_user(
	struct file *file, const char __user *buf, size_t count,
	struct pkm_lcs_source_response_result *result)
{
	return pkm_lcs_source_device_write_file_with_ops(
		file, buf, count, &pkm_lcs_default_copyin_ops, result);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static bool pkm_lcs_kunit_copy_to_kernel(void *ctx, void __user *dst,
					 const void *src, size_t len)
{
	(void)ctx;

	if (!dst)
		return false;
	memcpy((void *)(unsigned long)dst, src, len);
	return true;
}

static bool pkm_lcs_kunit_copy_from_kernel(void *ctx, void *dst,
					   const void __user *src, size_t len)
{
	const void *ksrc = (const void *)(unsigned long)src;
	bool fault = ctx ? *(bool *)ctx : false;

	if (!ksrc || fault)
		return false;
	memcpy(dst, ksrc, len);
	return true;
}

ssize_t pkm_lcs_kunit_source_device_read_file(
	struct file *file, void *buf, size_t count, bool nonblocking)
{
	static const struct pkm_lcs_source_copyout_ops ops = {
		.write = pkm_lcs_kunit_copy_to_kernel,
	};

	return pkm_lcs_source_device_read_file_with_ops(
		file, (char __user *)buf, count, nonblocking, &ops);
}

ssize_t pkm_lcs_kunit_source_device_write_file(
	struct file *file, const void *buf, size_t count, bool fault,
	struct pkm_lcs_source_response_result *result)
{
	struct pkm_lcs_source_copyin_ops ops = {
		.read = pkm_lcs_kunit_copy_from_kernel,
		.ctx = &fault,
	};

	return pkm_lcs_source_device_write_file_with_ops(
		file, (const char __user *)buf, count, &ops, result);
}
#endif
