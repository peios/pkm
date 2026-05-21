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
#include <linux/jiffies.h>
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
#include <linux/uaccess.h>
#include <linux/unaligned.h>

#include <pkm/token.h>

#include "../kacs/access_check.h"
#include "../kacs/caap_cache.h"
#include "../kacs/token_runtime.h"
#include "../kmes/kmes.h"
#include "rsi.h"
#include "source_device.h"

#define PKM_LCS_MAX_HIVE_NAME_BYTES_HARD 1024U
#define PKM_LCS_MAX_LAYER_NAME_BYTES_HARD 1024U
#define PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD 65535U
#define PKM_LCS_MAX_SYSCALL_PATH_BYTES_HARD \
	(PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD + 1U)
#define PKM_LCS_MAX_SYSCALL_LAYER_BYTES_HARD \
	(PKM_LCS_MAX_LAYER_NAME_BYTES_HARD + 1U)
#define PKM_LCS_MAX_KEY_DEPTH_HARD 4096U
#define PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT 32U
#define PKM_LCS_MAX_HIVES_PER_SOURCE_DEFAULT 64U
#define PKM_LCS_MAX_BOUND_TRANSACTIONS_PER_SOURCE_DEFAULT 16U

#define PKM_LCS_RSI_READ_ACTION_COPY 0U
#define PKM_LCS_RSI_READ_ACTION_WAIT 1U
#define PKM_LCS_RSI_READ_ACTION_EAGAIN 2U
#define PKM_LCS_RSI_READ_ACTION_EMSGSIZE 3U
#define PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE 4U
#define PKM_LCS_SACL_MATCH_SUCCESS 0x1U
#define PKM_LCS_SACL_MATCH_FAILURE 0x2U

static const char pkm_lcs_key_open_audit_event_type[] =
	"LCS_KEY_OPEN_AUDIT";

struct pkm_lcs_rsi_read_plan_copy {
	u32 action;
	u32 _pad;
	size_t request_len;
	size_t required_len;
};

struct pkm_lcs_source_queued_request {
	struct list_head link;
	u8 *frame;
	size_t len;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
};

struct pkm_lcs_symlink_follow_components {
	struct pkm_lcs_path_component_view *components;
	u32 component_count;
};

struct pkm_lcs_owned_path_components {
	struct pkm_lcs_path_component_view *components;
	u32 component_count;
};

struct pkm_lcs_source_copyout_ops {
	bool (*write)(void *ctx, void __user *dst, const void *src, size_t len);
	void *ctx;
};

struct pkm_lcs_source_copyin_ops {
	bool (*read)(void *ctx, void *dst, const void __user *src, size_t len);
	void *ctx;
};

struct pkm_lcs_source_slot {
	bool occupied;
	u32 status;
	u32 source_id;
	u32 hive_count;
	struct pkm_lcs_source_registration_hive_copy *hives;
	struct pkm_lcs_source_fd *active_fd;
	u64 source_next_sequence;
	u32 bound_transaction_count;
};

static DEFINE_MUTEX(pkm_lcs_source_table_lock);
static struct pkm_lcs_source_slot
	pkm_lcs_source_slots[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
static bool pkm_lcs_sequence_initialized;
static u64 pkm_lcs_next_sequence;
static DECLARE_WAIT_QUEUE_HEAD(pkm_lcs_source_slot_wait);
static atomic64_t pkm_lcs_source_slot_epoch = ATOMIC64_INIT(0);
static const char pkm_lcs_base_layer_name[] = "base";
static const struct pkm_lcs_rsi_layer_view pkm_lcs_base_layer_snapshot[] = {
	{
		.name = pkm_lcs_base_layer_name,
		.name_len = sizeof(pkm_lcs_base_layer_name) - 1,
		.precedence = 0,
		.enabled = 1,
	},
};

static void pkm_lcs_source_slot_waiters_wake(void)
{
	atomic64_inc(&pkm_lcs_source_slot_epoch);
	wake_up_interruptible(&pkm_lcs_source_slot_wait);
}

static long pkm_lcs_normalize_layer_inputs(
	const struct pkm_lcs_rsi_layer_view **layers, u32 *layer_count,
	const struct pkm_lcs_rsi_private_layer_view **private_layers,
	u32 *private_layer_count)
{
	if (!layers || !layer_count || !private_layers || !private_layer_count)
		return -EINVAL;
	if (*layer_count && !*layers)
		return -EINVAL;
	if (*private_layer_count && !*private_layers)
		return -EINVAL;
	if (!*layer_count) {
		*layers = pkm_lcs_base_layer_snapshot;
		*layer_count = ARRAY_SIZE(pkm_lcs_base_layer_snapshot);
	}
	return 0;
}

static bool pkm_lcs_default_copy_from_user(void *ctx, void *dst,
					   const void __user *src, size_t len)
{
	(void)ctx;

	return copy_from_user(dst, src, len) == 0;
}

static size_t pkm_lcs_default_strnlen_user(void *ctx,
					   const char __user *src, size_t max)
{
	(void)ctx;

	return strnlen_user(src, max);
}

static bool pkm_lcs_default_copy_to_user(void *ctx, void __user *dst,
					 const void *src, size_t len);

static const struct pkm_lcs_usercopy_ops pkm_lcs_default_usercopy_ops = {
	.read = pkm_lcs_default_copy_from_user,
	.write = pkm_lcs_default_copy_to_user,
	.strnlen = pkm_lcs_default_strnlen_user,
};

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

struct pkm_lcs_audit_caller_summary {
	u8 effective_token_guid[16];
	u8 true_token_guid[16];
	u8 process_guid[16];
	const u8 *user_sid;
	size_t user_sid_len;
	u64 authentication_id;
	u64 token_id;
	u32 token_type;
	u32 impersonation_level;
	u32 integrity_level;
};

extern int lcs_rust_validate_source_registration_empty(
	const struct pkm_lcs_source_registration_hive_copy *hives,
	size_t hive_count, u64 max_sequence, bool caller_has_tcb,
	struct pkm_lcs_source_registration_plan_copy *plan);
extern int lcs_rust_validate_source_registration(
	const struct pkm_lcs_source_registration_hive_copy *hives,
	size_t hive_count, u64 max_sequence, bool caller_has_tcb,
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	bool current_next_sequence_valid, u64 current_next_sequence,
	struct pkm_lcs_source_registration_plan_copy *plan);
extern int lcs_rust_route_hive_from_source_slots(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *hive_name, u32 hive_name_len,
	const u8 (*scope_guids)[16], size_t scope_count,
	struct pkm_lcs_hive_route_result *result);
extern int lcs_rust_route_absolute_path_from_source_slots(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *path, u32 path_len, bool rewrite_current_user,
	const u8 *current_user_sid_component,
	u32 current_user_sid_component_len, const u8 (*scope_guids)[16],
	size_t scope_count, struct pkm_lcs_hive_route_result *result);
extern int lcs_rust_route_absolute_path_from_source_slots_with_token_sid(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *path, u32 path_len, bool rewrite_current_user,
	const u8 *current_user_sid, size_t current_user_sid_len,
	const u8 (*scope_guids)[16], size_t scope_count,
	struct pkm_lcs_hive_route_result *result);
extern int lcs_rust_route_symlink_target_from_source_slots(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *target, u32 target_len, const u8 (*scope_guids)[16],
	size_t scope_count, struct pkm_lcs_hive_route_result *result);
extern int lcs_rust_materialize_absolute_path_components_with_token_sid(
	const u8 *path, u32 path_len, bool rewrite_current_user,
	const u8 *current_user_sid, size_t current_user_sid_len,
	struct pkm_lcs_path_component_view *components,
	size_t component_capacity, u8 *string_buf, size_t string_capacity,
	struct pkm_lcs_path_component_materialization *result);
extern int lcs_rust_materialize_symlink_target_components(
	const u8 *target, u32 target_len,
	struct pkm_lcs_path_component_view *components,
	size_t component_capacity, u8 *string_buf, size_t string_capacity,
	struct pkm_lcs_path_component_materialization *result);
extern int lcs_rust_materialize_relative_path_components(
	const u8 *path, u32 path_len,
	struct pkm_lcs_path_component_view *components,
	size_t component_capacity, u8 *string_buf, size_t string_capacity,
	struct pkm_lcs_path_component_materialization *result);
extern int lcs_rust_open_preflight(
	u32 desired_access, u32 flags,
	struct pkm_lcs_open_preflight_plan *plan);
extern int lcs_rust_validate_key_create_flags(
	u32 flags, struct pkm_lcs_key_create_options *options);
extern int lcs_rust_plan_key_guid_assignment(
	const u8 candidate_guid[16], const u8 (*active_key_guids)[16],
	size_t active_key_guid_count, const u8 (*retired_key_guids)[16],
	size_t retired_key_guid_count,
	struct pkm_lcs_key_guid_assignment_plan *plan);
extern int lcs_rust_admit_layer_target(
	const u8 *layer_name, u32 layer_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	struct pkm_lcs_layer_target_admission_plan *plan);
extern int lcs_rust_select_layer_metadata_sd(
	const u8 *layer_name, u32 layer_name_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	size_t metadata_count,
	struct pkm_lcs_layer_metadata_sd_selection *selection);
extern int lcs_rust_key_open_access_plan(
	const void *subject_token, const u8 *sd_ptr, size_t sd_len,
	u32 desired_access, u32 pip_type, u32 pip_trust,
	const void *caap_cache,
	struct pkm_lcs_key_open_access_plan *plan);
extern int lcs_rust_key_open_audit_payload(
	const struct pkm_lcs_audit_caller_summary *caller,
	const u8 key_guid[16], u32 requested_access, u32 granted_access,
	u8 allowed, u32 sacl_match_flags, u8 *output, size_t output_len,
	size_t *written_out);
extern int lcs_rust_validate_syscall_relative_path(
	const u8 *path, u32 path_len,
	struct pkm_lcs_path_validation_result *result);
extern int lcs_rust_validate_relative_open_depth(
	u32 parent_depth, u32 relative_component_count);
extern int lcs_rust_validate_rsi_queued_request_frame(
	const u8 *frame, size_t frame_len,
	struct pkm_lcs_rsi_built_request *retained);
extern int lcs_rust_plan_rsi_source_read(
	bool has_next_request, size_t next_request_len, size_t caller_buffer_len,
	bool nonblocking, bool fd_closing,
	struct pkm_lcs_rsi_read_plan_copy *plan);

static void pkm_lcs_source_response_waiter_complete(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result);
static void pkm_lcs_source_response_waiter_complete_with_frame(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result,
	const u8 *frame, size_t frame_len);

static long pkm_lcs_source_device_check_tcb(const void *token)
{
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE))
		return -EPERM;
	return 0;
}

static long pkm_lcs_source_device_mark_tcb_used(const void *token)
{
	if (!kacs_rust_token_mark_privileges_used(token,
						 KACS_SE_TCB_PRIVILEGE))
		return -EPERM;

	return 0;
}

static bool pkm_lcs_token_has_tcb_or_admin_authority(const void *token)
{
	if (!token)
		return false;
	if (kacs_rust_token_has_enabled_privilege(token, KACS_SE_TCB_PRIVILEGE))
		return pkm_lcs_source_device_mark_tcb_used(token) == 0;

	return kacs_rust_token_has_enabled_administrators(token);
}

static void pkm_lcs_source_hives_destroy(
	struct pkm_lcs_source_registration_hive_copy *hives, u32 hive_count)
{
	u32 i;

	if (!hives)
		return;

	for (i = 0; i < hive_count; i++)
		kfree(hives[i].name);
	kfree(hives);
}

static u32 pkm_lcs_source_table_views_locked(
	struct pkm_lcs_source_slot_view_copy *views)
{
	u32 count = 0;
	u32 i;

	lockdep_assert_held(&pkm_lcs_source_table_lock);

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT; i++) {
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

static struct pkm_lcs_source_slot *
pkm_lcs_source_slot_find_locked(u32 source_id)
{
	u32 i;

	lockdep_assert_held(&pkm_lcs_source_table_lock);

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT; i++) {
		if (pkm_lcs_source_slots[i].occupied &&
		    pkm_lcs_source_slots[i].source_id == source_id)
			return &pkm_lcs_source_slots[i];
	}
	return NULL;
}

long pkm_lcs_source_bound_transaction_acquire(u32 source_id, u32 *count_out)
{
	struct pkm_lcs_source_slot *slot;
	long ret = 0;

	if (count_out)
		*count_out = 0;
	if (!source_id || !count_out)
		return -EINVAL;

	mutex_lock(&pkm_lcs_source_table_lock);
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE) {
		ret = -EIO;
		goto out_unlock;
	}
	if (slot->bound_transaction_count >=
	    PKM_LCS_MAX_BOUND_TRANSACTIONS_PER_SOURCE_DEFAULT) {
		ret = -EBUSY;
		goto out_unlock;
	}

	slot->bound_transaction_count++;
	*count_out = slot->bound_transaction_count;

out_unlock:
	mutex_unlock(&pkm_lcs_source_table_lock);
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

	mutex_lock(&pkm_lcs_source_table_lock);
	slot = pkm_lcs_source_slot_find_locked(source_id);
	if (!slot || !slot->occupied || !slot->bound_transaction_count) {
		ret = -EIO;
		goto out_unlock;
	}

	slot->bound_transaction_count--;
	*count_out = slot->bound_transaction_count;

out_unlock:
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

static struct pkm_lcs_source_slot *pkm_lcs_source_slot_free_locked(void)
{
	u32 i;

	lockdep_assert_held(&pkm_lcs_source_table_lock);

	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT; i++) {
		if (!pkm_lcs_source_slots[i].occupied)
			return &pkm_lcs_source_slots[i];
	}
	return NULL;
}

static u32 pkm_lcs_source_slot_id(const struct pkm_lcs_source_slot *slot)
{
	return (u32)(slot - pkm_lcs_source_slots) + 1U;
}

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
	source_fd->closing = false;
}

static void pkm_lcs_source_queued_request_free(
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
	u32 i;

	lockdep_assert_held(&source_fd->queue_lock);

	had_in_flight = source_fd->in_flight_request_count != 0;
	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		struct pkm_lcs_source_in_flight_request *record =
			&source_fd->in_flight_requests[i];

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
		memset(record, 0, sizeof(*record));
	}
	source_fd->in_flight_request_count = 0;
	if (had_in_flight)
		pkm_lcs_source_slot_waiters_wake();
}

static long pkm_lcs_source_request_id_successor(u64 request_id, u64 *next)
{
	if (!next)
		return -EINVAL;
	if (request_id == ~0ULL)
		return -EOVERFLOW;

	*next = request_id + 1;
	return 0;
}

static unsigned long pkm_lcs_source_deadline_from_timeout_ms(u32 timeout_ms)
{
	unsigned long delta = msecs_to_jiffies(timeout_ms);

	if (timeout_ms && !delta)
		delta = 1;
	return jiffies + delta;
}

static long pkm_lcs_source_deadline_remaining(unsigned long deadline)
{
	unsigned long now = jiffies;

	if (time_after_eq(now, deadline))
		return 0;
	return (long)(deadline - now);
}

static long pkm_lcs_source_slot_admission_state(u32 source_id)
{
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	long ret = -EIO;

	mutex_lock(&pkm_lcs_source_table_lock);
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
	} else if (source_fd->in_flight_request_count >=
		   PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
		ret = -EAGAIN;
	} else {
		ret = 0;
	}
	mutex_unlock(&source_fd->queue_lock);

out_unlock_table:
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

static long pkm_lcs_source_wait_for_slot(u32 source_id,
					 unsigned long deadline)
{
	for (;;) {
		s64 epoch = atomic64_read(&pkm_lcs_source_slot_epoch);
		long remaining;
		long wait_ret;
		long ret;

		ret = pkm_lcs_source_slot_admission_state(source_id);
		if (ret != -EAGAIN)
			return ret;

		remaining = pkm_lcs_source_deadline_remaining(deadline);
		if (!remaining)
			return -ETIMEDOUT;

		wait_ret = wait_event_interruptible_timeout(
			pkm_lcs_source_slot_wait,
			atomic64_read(&pkm_lcs_source_slot_epoch) != epoch,
			remaining);
		if (wait_ret < 0)
			return wait_ret;
		if (!wait_ret)
			return -ETIMEDOUT;
	}
}

static long pkm_lcs_source_in_flight_insert_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id, u64 txn_id,
	u16 op_code, struct pkm_lcs_source_response_waiter *waiter)
{
	u32 i;

	lockdep_assert_held(&source_fd->queue_lock);

	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT)
		return -EAGAIN;

	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		struct pkm_lcs_source_in_flight_request *record =
			&source_fd->in_flight_requests[i];

		if (record->occupied && record->request_id == request_id)
			return -EINVAL;
	}

	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		struct pkm_lcs_source_in_flight_request *record =
			&source_fd->in_flight_requests[i];

		if (record->occupied)
			continue;
		record->occupied = true;
		record->delivered = false;
		record->response_accepted = false;
		record->request_id = request_id;
		record->txn_id = txn_id;
		record->op_code = op_code;
		record->waiter = waiter;
		if (waiter) {
			waiter->source_id = source_fd->source_id;
			waiter->request_id = request_id;
			WRITE_ONCE(waiter->attached, true);
			WRITE_ONCE(waiter->detached, false);
		}
		source_fd->in_flight_request_count++;
		return 0;
	}

	return -EIO;
}

static struct pkm_lcs_source_in_flight_request *
pkm_lcs_source_in_flight_find_locked(struct pkm_lcs_source_fd *source_fd,
				     u64 request_id)
{
	u32 i;

	lockdep_assert_held(&source_fd->queue_lock);

	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		struct pkm_lcs_source_in_flight_request *record =
			&source_fd->in_flight_requests[i];

		if (record->occupied && record->request_id == request_id)
			return record;
	}

	return NULL;
}

static long pkm_lcs_source_in_flight_set_delivered_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id, bool delivered)
{
	struct pkm_lcs_source_in_flight_request *record;

	lockdep_assert_held(&source_fd->queue_lock);

	record = pkm_lcs_source_in_flight_find_locked(source_fd, request_id);
	if (!record)
		return -EIO;

	record->delivered = delivered;
	return 0;
}

static void pkm_lcs_source_in_flight_release_locked(
	struct pkm_lcs_source_fd *source_fd,
	struct pkm_lcs_source_in_flight_request *record)
{
	lockdep_assert_held(&source_fd->queue_lock);

	if (!record || !record->occupied)
		return;

	memset(record, 0, sizeof(*record));
	if (source_fd->in_flight_request_count) {
		source_fd->in_flight_request_count--;
		pkm_lcs_source_slot_waiters_wake();
	}
}

static void pkm_lcs_source_enqueue_result_fill_locked(
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

static bool pkm_lcs_rsi_status_known(u32 status)
{
	switch (status) {
	case RSI_OK:
	case RSI_NOT_FOUND:
	case RSI_ALREADY_EXISTS:
	case RSI_STORAGE_ERROR:
	case RSI_NOT_EMPTY:
	case RSI_TOO_LARGE:
	case RSI_TXN_BUSY:
	case RSI_INVALID:
	case RSI_CAS_FAILED:
	case RSI_TXN_NOT_SUPPORTED:
		return true;
	default:
		return false;
	}
}

static long pkm_lcs_rsi_status_errno(u32 status)
{
	switch (status) {
	case RSI_OK:
		return 0;
	case RSI_NOT_FOUND:
		return -ENOENT;
	case RSI_ALREADY_EXISTS:
		return -EEXIST;
	case RSI_STORAGE_ERROR:
		return -EIO;
	case RSI_NOT_EMPTY:
		return -ENOTEMPTY;
	case RSI_TOO_LARGE:
		return -ENOSPC;
	case RSI_TXN_BUSY:
		return -EBUSY;
	case RSI_INVALID:
		return -EINVAL;
	case RSI_CAS_FAILED:
		return -EAGAIN;
	case RSI_TXN_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	default:
		return -EIO;
	}
}

long pkm_lcs_reg_create_key_source_response_plan(
	u16 request_op_code, u32 status,
	struct pkm_lcs_reg_create_source_response_plan *plan)
{
	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!pkm_lcs_rsi_status_known(status))
		return -EIO;

	switch (request_op_code) {
	case RSI_CREATE_ENTRY:
		if (status == RSI_OK) {
			plan->action = PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY;
			return 0;
		}
		if (status == RSI_ALREADY_EXISTS) {
			plan->action =
				PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING;
			plan->disposition = REG_OPENED_EXISTING;
			return 0;
		}
		return pkm_lcs_rsi_status_errno(status);

	case RSI_CREATE_KEY:
		if (status == RSI_OK) {
			plan->action =
				PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW;
			plan->disposition = REG_CREATED_NEW;
			return 0;
		}
		if (status == RSI_ALREADY_EXISTS)
			return -EIO;
		return pkm_lcs_rsi_status_errno(status);

	default:
		return -EINVAL;
	}
}

void pkm_lcs_source_response_waiter_init(
	struct pkm_lcs_source_response_waiter *waiter)
{
	if (!waiter)
		return;

	memset(waiter, 0, sizeof(*waiter));
	init_waitqueue_head(&waiter->wait);
}

void pkm_lcs_source_response_frame_init(
	struct pkm_lcs_source_response_frame *frame)
{
	if (!frame)
		return;

	memset(frame, 0, sizeof(*frame));
}

void pkm_lcs_source_response_frame_destroy(
	struct pkm_lcs_source_response_frame *frame)
{
	if (!frame)
		return;

	kfree(frame->data);
	memset(frame, 0, sizeof(*frame));
}

static long pkm_lcs_source_response_waiter_retain_frame(
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_frame *frame)
{
	if (!waiter || !frame)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(frame);
	waiter->retained_frame = frame;
	return 0;
}

static void pkm_lcs_source_response_waiter_complete_with_frame(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result,
	const u8 *frame, size_t frame_len)
{
	struct pkm_lcs_source_response_frame *retained_frame;

	if (!waiter)
		return;

	retained_frame = waiter->retained_frame;
	if (!response_errno && retained_frame) {
		pkm_lcs_source_response_frame_destroy(retained_frame);
		if (!frame || !frame_len) {
			response_errno = -EIO;
		} else {
			retained_frame->data = kmemdup(frame, frame_len,
						       GFP_KERNEL);
			if (!retained_frame->data)
				response_errno = -ENOMEM;
			else
				retained_frame->len = frame_len;
		}
	}

	if (result)
		waiter->response = *result;
	else
		memset(&waiter->response, 0, sizeof(waiter->response));
	waiter->response_errno = response_errno;
	WRITE_ONCE(waiter->attached, false);
	WRITE_ONCE(waiter->completed, true);
	wake_up_interruptible(&waiter->wait);
}

static void pkm_lcs_source_response_waiter_complete(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result)
{
	pkm_lcs_source_response_waiter_complete_with_frame(
		waiter, response_errno, result, NULL, 0);
}

static bool pkm_lcs_source_response_waiter_detach(
	struct pkm_lcs_source_response_waiter *waiter)
{
	struct pkm_lcs_source_in_flight_request *record;
	struct pkm_lcs_source_fd *source_fd;
	struct pkm_lcs_source_slot *slot;
	bool detached = false;

	if (!waiter || READ_ONCE(waiter->completed) ||
	    !READ_ONCE(waiter->attached))
		return false;

	mutex_lock(&pkm_lcs_source_table_lock);
	slot = pkm_lcs_source_slot_find_locked(waiter->source_id);
	if (!slot || !slot->active_fd)
		goto out_unlock_table;

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (READ_ONCE(waiter->completed))
		goto out_unlock_queue;

	record = pkm_lcs_source_in_flight_find_locked(source_fd,
						      waiter->request_id);
	if (record && record->waiter == waiter) {
		record->waiter = NULL;
		WRITE_ONCE(waiter->attached, false);
		WRITE_ONCE(waiter->detached, true);
		detached = true;
	}

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
out_unlock_table:
	mutex_unlock(&pkm_lcs_source_table_lock);
	return detached;
}

static long pkm_lcs_source_response_waiter_wait_until(
	struct pkm_lcs_source_response_waiter *waiter, unsigned long deadline,
	struct pkm_lcs_source_response_result *result)
{
	long ret;

	if (!waiter)
		return -EINVAL;

	for (;;) {
		long remaining;

		if (READ_ONCE(waiter->completed)) {
			if (result)
				*result = waiter->response;
			return waiter->response_errno;
		}

		remaining = pkm_lcs_source_deadline_remaining(deadline);
		if (!remaining)
			break;

		ret = wait_event_interruptible_timeout(
			waiter->wait, READ_ONCE(waiter->completed),
			remaining);
		if (ret < 0) {
			pkm_lcs_source_response_waiter_detach(waiter);
			return ret;
		}
		if (!ret)
			break;
	}

	if (READ_ONCE(waiter->completed)) {
		if (result)
			*result = waiter->response;
		return waiter->response_errno;
	}

	pkm_lcs_source_response_waiter_detach(waiter);
	if (READ_ONCE(waiter->completed)) {
		if (result)
			*result = waiter->response;
		return waiter->response_errno;
	}
	return -ETIMEDOUT;
}

long pkm_lcs_source_response_waiter_wait(
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_result *result)
{
	if (!waiter)
		return -EINVAL;

	wait_event(waiter->wait, READ_ONCE(waiter->completed));
	if (result)
		*result = waiter->response;
	return waiter->response_errno;
}

static bool pkm_lcs_source_read_ready(struct pkm_lcs_source_fd *source_fd)
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

	if (!file || file->private_data)
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
	return 0;
}

int pkm_lcs_source_device_release_file(struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;
	struct pkm_lcs_source_slot *slot;

	if (!file)
		return 0;

	source_fd = file->private_data;
	file->private_data = NULL;
	if (!source_fd)
		return 0;

	mutex_lock(&pkm_lcs_source_table_lock);
	mutex_lock(&source_fd->queue_lock);
	source_fd->closing = true;
	pkm_lcs_source_queue_destroy_locked(source_fd);
	pkm_lcs_source_in_flight_destroy_locked(source_fd);
	mutex_unlock(&source_fd->queue_lock);
	wake_up_interruptible(&source_fd->read_wait);

	if (source_fd->state == PKM_LCS_SOURCE_FD_ACTIVE) {
		slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
		if (slot && slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE &&
		    slot->active_fd == source_fd) {
			slot->status = PKM_LCS_SOURCE_SLOT_STATUS_DOWN;
			slot->active_fd = NULL;
			slot->bound_transaction_count = 0;
		}
	}
	mutex_unlock(&pkm_lcs_source_table_lock);

	kfree(source_fd);
	return 0;
}

void pkm_lcs_source_registration_copy_destroy(
	struct pkm_lcs_source_registration_copy *registration)
{
	if (!registration)
		return;

	pkm_lcs_source_hives_destroy(registration->hives,
				     registration->hive_count);
	memset(registration, 0, sizeof(*registration));
}

void pkm_lcs_syscall_path_copy_destroy(struct pkm_lcs_syscall_path_copy *copy)
{
	if (!copy)
		return;

	kfree(copy->path);
	memset(copy, 0, sizeof(*copy));
}

long pkm_lcs_syscall_path_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *upath,
	struct pkm_lcs_syscall_path_copy *out)
{
	char *path;
	size_t path_len;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (!ops)
		ops = &pkm_lcs_default_usercopy_ops;
	if (!ops->read || !ops->strnlen)
		return -EINVAL;
	if (!upath)
		return -EFAULT;

	path_len = ops->strnlen(ops->ctx, upath,
				PKM_LCS_MAX_SYSCALL_PATH_BYTES_HARD);
	if (!path_len)
		return -EFAULT;
	if (path_len > PKM_LCS_MAX_SYSCALL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	path = kmalloc(path_len, GFP_KERNEL);
	if (!path)
		return -ENOMEM;
	if (!ops->read(ops->ctx, path, upath, path_len)) {
		kfree(path);
		return -EFAULT;
	}

	out->path = path;
	out->path_len = (u32)path_len;
	return 0;
}

void pkm_lcs_create_layer_target_destroy(
	struct pkm_lcs_create_layer_target *target)
{
	if (!target)
		return;

	kfree(target->owned_name);
	memset(target, 0, sizeof(*target));
}

long pkm_lcs_create_layer_target_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	struct pkm_lcs_create_layer_target *target)
{
	char *layer;
	size_t user_len;

	if (!target)
		return -EINVAL;
	memset(target, 0, sizeof(*target));

	if (!ulayer) {
		target->name = pkm_lcs_base_layer_name;
		target->name_len = sizeof(pkm_lcs_base_layer_name) - 1;
		target->implicit_base = 1;
		return 0;
	}

	if (!ops)
		ops = &pkm_lcs_default_usercopy_ops;
	if (!ops->read || !ops->strnlen)
		return -EINVAL;

	user_len = ops->strnlen(ops->ctx, ulayer,
				PKM_LCS_MAX_SYSCALL_LAYER_BYTES_HARD);
	if (!user_len)
		return -EFAULT;
	if (user_len > PKM_LCS_MAX_SYSCALL_LAYER_BYTES_HARD)
		return -ENAMETOOLONG;

	layer = kmalloc(user_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer, ulayer, user_len)) {
		kfree(layer);
		return -EFAULT;
	}
	if (layer[user_len - 1] != '\0') {
		kfree(layer);
		return -EFAULT;
	}

	target->owned_name = layer;
	target->name = layer;
	target->name_len = (u32)user_len - 1U;
	return 0;
}

long pkm_lcs_create_layer_target_admit(
	const struct pkm_lcs_create_layer_target *target,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_layer_target_admission_plan *plan)
{
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *private_layers = NULL;
	u32 active_layer_count = layer_count;
	u32 private_layer_count = 0;
	long ret;

	if (!target || !target->name || !plan)
		return -EINVAL;
	memset(plan, 0, sizeof(*plan));

	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &private_layers,
		&private_layer_count);
	if (ret)
		return ret;

	return lcs_rust_admit_layer_target(
		(const u8 *)target->name, target->name_len, active_layers,
		active_layer_count, plan);
}

long pkm_lcs_create_layer_target_prepare(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_layer_target_admission_plan *plan)
{
	long ret;

	if (!target || !plan)
		return -EINVAL;

	ret = pkm_lcs_create_layer_target_copy_from_user(ops, ulayer, target);
	if (ret)
		return ret;

	ret = pkm_lcs_create_layer_target_admit(target, layers, layer_count,
						plan);
	if (ret) {
		pkm_lcs_create_layer_target_destroy(target);
		memset(plan, 0, sizeof(*plan));
	}
	return ret;
}

static long pkm_lcs_source_registration_copy_hive_name(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_hive_entry *wire_hive,
	struct pkm_lcs_source_registration_hive_copy *hive)
{
	const void __user *name_ptr;
	char *name;

	if (!wire_hive->name_len)
		return -EINVAL;
	if (wire_hive->name_len > PKM_LCS_MAX_HIVE_NAME_BYTES_HARD)
		return -EINVAL;

	name_ptr = (const void __user *)(unsigned long)wire_hive->name_ptr;
	if (!name_ptr)
		return -EFAULT;

	name = kmalloc((size_t)wire_hive->name_len + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	if (!ops->read(ops->ctx, name, name_ptr, wire_hive->name_len)) {
		kfree(name);
		return -EFAULT;
	}
	name[wire_hive->name_len] = '\0';

	hive->name = name;
	hive->name_len = wire_hive->name_len;
	return 0;
}

long pkm_lcs_source_registration_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs, u32 max_hives,
	struct pkm_lcs_source_registration_copy *out)
{
	struct reg_src_register_args args;
	struct reg_src_hive_entry *wire_hives;
	const void __user *hives_ptr;
	size_t hives_bytes;
	u32 i;
	long ret = 0;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (!ops)
		ops = &pkm_lcs_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;
	if (!uargs)
		return -EFAULT;
	if (!ops->read(ops->ctx, &args, uargs, sizeof(args)))
		return -EFAULT;

	if (args._pad)
		return -EINVAL;
	if (!args.hive_count)
		return -EINVAL;
	if (max_hives && args.hive_count > max_hives)
		return -ENOSPC;
	if (check_mul_overflow((size_t)args.hive_count,
			       sizeof(struct reg_src_hive_entry),
			       &hives_bytes))
		return -EOVERFLOW;

	hives_ptr = (const void __user *)(unsigned long)args.hives_ptr;
	if (!hives_ptr)
		return -EFAULT;

	wire_hives = kcalloc(args.hive_count, sizeof(*wire_hives), GFP_KERNEL);
	if (!wire_hives)
		return -ENOMEM;
	out->hives = kcalloc(args.hive_count, sizeof(*out->hives), GFP_KERNEL);
	if (!out->hives) {
		ret = -ENOMEM;
		goto out_free_wire;
	}
	out->hive_count = args.hive_count;
	out->max_sequence = args.max_sequence;

	if (!ops->read(ops->ctx, wire_hives, hives_ptr, hives_bytes)) {
		ret = -EFAULT;
		goto out_destroy;
	}

	for (i = 0; i < args.hive_count; i++) {
		if (wire_hives[i]._pad0 || wire_hives[i]._pad1) {
			ret = -EINVAL;
			goto out_destroy;
		}

		memcpy(out->hives[i].root_guid, wire_hives[i].root_guid,
		       sizeof(out->hives[i].root_guid));
		out->hives[i].flags = wire_hives[i].flags;
		memcpy(out->hives[i].scope_guid, wire_hives[i].scope_guid,
		       sizeof(out->hives[i].scope_guid));

		ret = pkm_lcs_source_registration_copy_hive_name(
			ops, &wire_hives[i], &out->hives[i]);
		if (ret)
			goto out_destroy;
	}

	kfree(wire_hives);
	return 0;

out_destroy:
	pkm_lcs_source_registration_copy_destroy(out);
out_free_wire:
	kfree(wire_hives);
	return ret;
}

long pkm_lcs_source_registration_validate_copied(
	const struct pkm_lcs_source_registration_copy *registration,
	bool caller_has_tcb,
	struct pkm_lcs_source_registration_plan_copy *plan)
{
	if (!registration || !plan)
		return -EINVAL;
	if (registration->hive_count && !registration->hives)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	return lcs_rust_validate_source_registration_empty(
		registration->hives, registration->hive_count,
		registration->max_sequence, caller_has_tcb, plan);
}

static long pkm_lcs_source_registration_publish_locked(
	struct pkm_lcs_source_fd *source_fd,
	struct pkm_lcs_source_registration_copy *registration)
{
	struct pkm_lcs_source_slot_view_copy
		views[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
	struct pkm_lcs_source_registration_plan_copy plan = { };
	struct pkm_lcs_source_slot *slot;
	u32 slot_count;
	long ret;

	lockdep_assert_held(&pkm_lcs_source_table_lock);

	if (!source_fd || !registration)
		return -EINVAL;
	if (source_fd->state != PKM_LCS_SOURCE_FD_UNREGISTERED)
		return -EINVAL;

	slot_count = pkm_lcs_source_table_views_locked(views);
	ret = lcs_rust_validate_source_registration(
		registration->hives, registration->hive_count,
		registration->max_sequence, true, views, slot_count,
		pkm_lcs_sequence_initialized, pkm_lcs_next_sequence, &plan);
	if (ret)
		return ret;

	switch (plan.decision) {
	case PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW:
		slot = pkm_lcs_source_slot_free_locked();
		if (!slot)
			return -ENOSPC;

		slot->occupied = true;
		slot->status = PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE;
		slot->source_id = pkm_lcs_source_slot_id(slot);
		slot->hive_count = registration->hive_count;
		slot->hives = registration->hives;
		slot->active_fd = source_fd;
		slot->source_next_sequence = plan.source_next_sequence;
		registration->hives = NULL;
		registration->hive_count = 0;
		break;
	case PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN:
		slot = pkm_lcs_source_slot_find_locked(plan.source_id);
		if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_DOWN)
			return -EINVAL;

		slot->status = PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE;
		slot->active_fd = source_fd;
		slot->source_next_sequence = plan.source_next_sequence;
		break;
	default:
		return -EINVAL;
	}

	source_fd->state = PKM_LCS_SOURCE_FD_ACTIVE;
	source_fd->source_id = slot->source_id;
	pkm_lcs_next_sequence = plan.effective_next_sequence;
	pkm_lcs_sequence_initialized = true;
	wake_up_interruptible(&source_fd->read_wait);
	return 0;
}

long pkm_lcs_source_register_file_for_token(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs)
{
	struct pkm_lcs_source_registration_copy registration = { };
	struct pkm_lcs_source_fd *source_fd;
	long ret;

	if (!file)
		return -EINVAL;
	source_fd = file->private_data;
	if (!source_fd)
		return -EINVAL;

	mutex_lock(&pkm_lcs_source_table_lock);
	if (source_fd->state != PKM_LCS_SOURCE_FD_UNREGISTERED) {
		mutex_unlock(&pkm_lcs_source_table_lock);
		return -EINVAL;
	}
	mutex_unlock(&pkm_lcs_source_table_lock);

	ret = pkm_lcs_source_device_check_tcb(token);
	if (ret)
		return ret;
	ret = pkm_lcs_source_device_mark_tcb_used(token);
	if (ret)
		return ret;

	ret = pkm_lcs_source_registration_copy_from_user(
		ops, uargs, PKM_LCS_MAX_HIVES_PER_SOURCE_DEFAULT,
		&registration);
	if (ret)
		return ret;

	mutex_lock(&pkm_lcs_source_table_lock);
	ret = pkm_lcs_source_registration_publish_locked(source_fd,
							&registration);
	mutex_unlock(&pkm_lcs_source_table_lock);

	pkm_lcs_source_registration_copy_destroy(&registration);
	return ret;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
		retained.op_code, NULL);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

static long pkm_lcs_source_dispatch_lookup_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
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
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!parent_guid || !child_name)
		return -EINVAL;
	if (child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
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
		child_name, child_name_len, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		waiter);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

static long pkm_lcs_source_dispatch_read_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
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
	if (!guid)
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
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
		waiter);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

static long pkm_lcs_source_dispatch_query_values_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
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
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || (value_name_len && !value_name))
		return -EINVAL;
	if (value_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
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
		value_name, value_name_len, query_all, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		waiter);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

static long pkm_lcs_source_dispatch_create_entry_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
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
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!parent_guid || !child_name || !layer_name || !child_guid)
		return -EINVAL;
	if (child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
	    layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
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
		child_guid, sequence, &built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		waiter);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

static long pkm_lcs_source_dispatch_create_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
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
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!guid || !name || !parent_guid || !sd || !sd_len)
		return -EINVAL;
	if (name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;
	if (sd_len > U32_MAX)
		return -EOVERFLOW;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
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
		&built);
	if (ret)
		goto out_unlock_queue;

	ret = pkm_lcs_source_in_flight_insert_locked(
		source_fd, built.request_id, built.txn_id, built.op_code,
		waiter);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

static long pkm_lcs_source_dispatch_transaction_request_with_waiter(
	u32 source_id, u16 op_code, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result)
{
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_source_queued_request *request;
	struct pkm_lcs_source_slot *slot;
	struct pkm_lcs_source_fd *source_fd;
	size_t frame_len = RSI_REQUEST_HEADER_SIZE + sizeof(u64);
	u64 header_txn_id;
	u64 request_id;
	u64 next_request_id;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));

	switch (op_code) {
	case RSI_BEGIN_TRANSACTION:
		if (mode != RSI_TXN_READ_WRITE && mode != RSI_TXN_READ_ONLY)
			return -EINVAL;
		if (check_add_overflow(frame_len, sizeof(u32), &frame_len))
			return -EOVERFLOW;
		header_txn_id = 0;
		break;
	case RSI_COMMIT_TRANSACTION:
	case RSI_ABORT_TRANSACTION:
		header_txn_id = transaction_id;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	if (source_fd->in_flight_request_count >=
	    PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT) {
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
		source_fd, built.request_id, built.txn_id, built.op_code,
		waiter);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	pkm_lcs_source_queued_request_free(request);
	return ret;
}

long pkm_lcs_source_dispatch_lookup_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_lookup_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		NULL, result);
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
		waiter, result);
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
		waiter, result);
}

long pkm_lcs_source_lookup_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
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

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_lookup_request_with_waiter(
			source_id, txn_id, parent_guid, child_name,
			child_name_len, &waiter, enqueue);
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

long pkm_lcs_source_lookup_round_trip(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_lookup_round_trip_timeout(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, response, enqueue);
}

long pkm_lcs_source_dispatch_create_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_create_entry_request_with_waiter(
		source_id, txn_id, parent_guid, child_name, child_name_len,
		layer_name, layer_name_len, child_guid, sequence, NULL,
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
		layer_name, layer_name_len, child_guid, sequence, waiter,
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
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_create_entry_request_with_waiter(
			source_id, txn_id, parent_guid, child_name,
			child_name_len, layer_name, layer_name_len,
			child_guid, sequence, &waiter, enqueue);
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

long pkm_lcs_source_dispatch_create_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_create_key_request_with_waiter(
		source_id, txn_id, guid, name, name_len, parent_guid, sd,
		sd_len, volatile_key, symlink, NULL, result);
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
		sd_len, volatile_key, symlink, waiter, result);
}

long pkm_lcs_source_dispatch_begin_transaction_request(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_BEGIN_TRANSACTION, transaction_id, mode, NULL,
		result);
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
		waiter, result);
}

long pkm_lcs_source_dispatch_commit_transaction_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0, NULL,
		result);
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
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0, waiter,
		result);
}

long pkm_lcs_source_dispatch_abort_transaction_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_enqueue_result *result)
{
	return pkm_lcs_source_dispatch_transaction_request_with_waiter(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0, NULL,
		result);
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
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0, waiter,
		result);
}

static long pkm_lcs_source_transaction_round_trip_timeout(
	u32 source_id, u16 op_code, u64 transaction_id, u32 mode,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_transaction_request_with_waiter(
			source_id, op_code, transaction_id, mode, &waiter,
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

long pkm_lcs_source_begin_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 mode, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout(
		source_id, RSI_BEGIN_TRANSACTION, transaction_id, mode,
		timeout_ms, response, enqueue);
}

long pkm_lcs_source_begin_transaction_round_trip(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_begin_transaction_round_trip_timeout(
		source_id, transaction_id, mode,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, response, enqueue);
}

long pkm_lcs_source_commit_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout(
		source_id, RSI_COMMIT_TRANSACTION, transaction_id, 0,
		timeout_ms, response, enqueue);
}

long pkm_lcs_source_commit_transaction_round_trip(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_commit_transaction_round_trip_timeout(
		source_id, transaction_id, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
		response, enqueue);
}

long pkm_lcs_source_abort_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_transaction_round_trip_timeout(
		source_id, RSI_ABORT_TRANSACTION, transaction_id, 0,
		timeout_ms, response, enqueue);
}

long pkm_lcs_source_abort_transaction_round_trip(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_abort_transaction_round_trip_timeout(
		source_id, transaction_id, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
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
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_create_key_request_with_waiter(
			source_id, txn_id, guid, name, name_len,
			parent_guid, sd, sd_len, volatile_key, symlink,
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

long pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

	if (!frame)
		return -EINVAL;
	if (response)
		memset(response, 0, sizeof(*response));
	if (enqueue)
		memset(enqueue, 0, sizeof(*enqueue));

	pkm_lcs_source_response_waiter_init(&waiter);
	pkm_lcs_source_response_frame_init(frame);
	deadline = pkm_lcs_source_deadline_from_timeout_ms(timeout_ms);

	for (;;) {
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_lookup_waitable_request_retaining_frame(
			source_id, txn_id, parent_guid, child_name,
			child_name_len, &waiter, frame, enqueue);
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
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

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
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_read_key_request_with_waiter(
			source_id, txn_id, guid, &waiter, enqueue);
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
	struct pkm_lcs_source_response_waiter waiter;
	unsigned long deadline;
	long ret;

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
		ret = pkm_lcs_source_wait_for_slot(source_id, deadline);
		if (ret)
			return ret;

		ret = pkm_lcs_source_dispatch_query_values_request_with_waiter(
			source_id, txn_id, guid, value_name, value_name_len,
			query_all, &waiter, enqueue);
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
		result->len = frame_len;
		result->request_id = record->request_id;
		result->txn_id = record->txn_id;
		result->request_op_code = record->op_code;
		result->response_op_code = response_op_code;
		result->status = status;
		result->malformed_source_data =
			!pkm_lcs_rsi_status_known(status);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

static long pkm_lcs_source_next_sequence_snapshot(u64 *next_sequence)
{
	if (!next_sequence)
		return -EINVAL;

	mutex_lock(&pkm_lcs_source_table_lock);
	if (!pkm_lcs_sequence_initialized) {
		mutex_unlock(&pkm_lcs_source_table_lock);
		return -EIO;
	}

	*next_sequence = pkm_lcs_next_sequence;
	mutex_unlock(&pkm_lcs_source_table_lock);
	return 0;
}

long pkm_lcs_allocate_sequence(u64 *sequence)
{
	if (!sequence)
		return -EINVAL;

	*sequence = 0;
	mutex_lock(&pkm_lcs_source_table_lock);
	if (!pkm_lcs_sequence_initialized) {
		mutex_unlock(&pkm_lcs_source_table_lock);
		return -EIO;
	}
	if (pkm_lcs_next_sequence == U64_MAX) {
		mutex_unlock(&pkm_lcs_source_table_lock);
		return -EOVERFLOW;
	}

	*sequence = pkm_lcs_next_sequence;
	pkm_lcs_next_sequence++;
	mutex_unlock(&pkm_lcs_source_table_lock);
	return 0;
}

static long pkm_lcs_source_validate_accepted_response_payload(
	const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_response_result *result, long *caller_errno)
{
	struct pkm_lcs_rsi_lookup_response_summary lookup = { };
	struct pkm_lcs_rsi_query_values_response_summary query_values = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
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
			&lookup);
		if (ret == -EIO) {
			result->malformed_source_data = true;
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
			&query_values);
		if (ret == -EIO) {
			result->malformed_source_data = true;
			*caller_errno = -EIO;
			return 0;
		}
		if (ret)
			return ret;
		*caller_errno = 0;
		return 0;
	case RSI_READ_KEY:
		ret = pkm_lcs_rsi_materialize_read_key_response(
			frame, frame_len, result->request_id, &read_key);
		if (ret == -EIO) {
			result->malformed_source_data = true;
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
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

	if (count < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;
	if (!buf)
		return -EFAULT;
	if (!ops->read(ops->ctx, header, buf, sizeof(header)))
		return -EFAULT;

	total_len = get_unaligned_le32(header + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	if ((size_t)total_len != count)
		return -EINVAL;

	frame = kmalloc(count, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	if (!ops->read(ops->ctx, frame, buf, count)) {
		ret = -EFAULT;
		goto out_free;
	}

	ret = pkm_lcs_source_accept_response_file(file, frame, count, result);
	if (ret)
		goto out_free;

	ret = pkm_lcs_source_validate_accepted_response_payload(
		frame, count, result, &caller_errno);
	if (ret && result->caller_waiter_attached)
		pkm_lcs_source_complete_waiter_file(file, result->request_id,
						    -EIO, result, NULL, 0);
	if (!ret && result->caller_waiter_attached)
		ret = pkm_lcs_source_complete_waiter_file(
			file, result->request_id, caller_errno, result,
			frame, count);
	if (!ret)
		ret = (ssize_t)count;

out_free:
	kfree(frame);
	return ret;
}

long pkm_lcs_route_hive_name(const char *hive_name, u32 hive_name_len,
			     const u8 (*scope_guids)[16], u32 scope_count,
			     struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_copy
		views[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
	u32 slot_count;
	long ret;

	if (!hive_name || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	mutex_lock(&pkm_lcs_source_table_lock);
	slot_count = pkm_lcs_source_table_views_locked(views);
	ret = lcs_rust_route_hive_from_source_slots(
		views, slot_count, hive_name, hive_name_len, scope_guids,
		scope_count, result);
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

long pkm_lcs_route_absolute_path(const char *path, u32 path_len,
				 bool rewrite_current_user,
				 const char *current_user_sid_component,
				 u32 current_user_sid_component_len,
				 const u8 (*scope_guids)[16], u32 scope_count,
				 struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_copy
		views[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
	u32 slot_count;
	long ret;

	if (!path || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	mutex_lock(&pkm_lcs_source_table_lock);
	slot_count = pkm_lcs_source_table_views_locked(views);
	ret = lcs_rust_route_absolute_path_from_source_slots(
		views, slot_count, path, path_len, rewrite_current_user,
		current_user_sid_component, current_user_sid_component_len,
		scope_guids, scope_count, result);
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

long pkm_lcs_route_absolute_path_for_token(const void *token, const char *path,
					   u32 path_len,
					   bool rewrite_current_user,
					   const u8 (*scope_guids)[16],
					   u32 scope_count,
					   struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_copy
		views[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
	const u8 *current_user_sid = NULL;
	size_t current_user_sid_len = 0;
	u32 slot_count;
	long ret;

	if (!path || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (rewrite_current_user) {
		ret = kacs_rust_token_user_sid(token, &current_user_sid,
					       &current_user_sid_len);
		if (ret)
			return ret;
	}

	mutex_lock(&pkm_lcs_source_table_lock);
	slot_count = pkm_lcs_source_table_views_locked(views);
	ret = lcs_rust_route_absolute_path_from_source_slots_with_token_sid(
		views, slot_count, path, path_len, rewrite_current_user,
		current_user_sid, current_user_sid_len, scope_guids, scope_count,
		result);
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

long pkm_lcs_route_current_absolute_path(const char *path, u32 path_len,
					 bool rewrite_current_user,
					 const u8 (*scope_guids)[16],
					 u32 scope_count,
					 struct pkm_lcs_hive_route_result *result)
{
	return pkm_lcs_route_absolute_path_for_token(
		pkm_kacs_current_effective_token_ptr(), path, path_len,
		rewrite_current_user, scope_guids, scope_count, result);
}

long pkm_lcs_route_user_absolute_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, bool rewrite_current_user,
	const u8 (*scope_guids)[16], u32 scope_count,
	struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_syscall_path_copy copy = { };
	long ret;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_route_absolute_path_for_token(
		token, copy.path, copy.path_len, rewrite_current_user,
		scope_guids, scope_count, result);
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_open_preflight(u32 desired_access, u32 flags,
			    struct pkm_lcs_open_preflight_plan *plan)
{
	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	return lcs_rust_open_preflight(desired_access, flags, plan);
}

long pkm_lcs_create_preflight(u32 desired_access, u32 flags,
			      struct pkm_lcs_create_preflight_plan *plan)
{
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	ret = pkm_lcs_open_preflight(desired_access, 0, &plan->access);
	if (ret) {
		memset(plan, 0, sizeof(*plan));
		return ret;
	}

	ret = lcs_rust_validate_key_create_flags(flags, &plan->options);
	if (ret)
		memset(plan, 0, sizeof(*plan));
	return ret;
}

long pkm_lcs_key_open_access_check_for_token(
	const void *token, const u8 *sd, size_t sd_len, u32 desired_access,
	struct pkm_lcs_key_open_access_plan *plan)
{
	const void *caap_cache = NULL;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!token)
		return -EACCES;
	if (!sd || !sd_len || !desired_access)
		return -EINVAL;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret)
		return ret;
	ret = lcs_rust_key_open_access_plan(token, sd, sd_len, desired_access,
					    pip_type, pip_trust, caap_cache,
					    plan);
	pkm_kacs_caap_cache_unlock();
	return ret;
}

static long pkm_lcs_build_audit_caller_summary(
	const void *token, struct pkm_lcs_audit_caller_summary *caller)
{
	struct pkm_kacs_token_audit_summary token_summary = { };
	kacs_uuid_t true_token_guid;
	kacs_uuid_t process_guid;
	int ret;

	if (!token || !caller)
		return -EIO;

	memset(caller, 0, sizeof(*caller));
	ret = kacs_rust_token_audit_summary(token, &token_summary);
	if (ret)
		return -EIO;

	true_token_guid = kacs_primary_token_guid();
	process_guid = kacs_process_guid();

	memcpy(caller->effective_token_guid, token_summary.token_guid,
	       sizeof(caller->effective_token_guid));
	memcpy(caller->true_token_guid, true_token_guid.bytes,
	       sizeof(caller->true_token_guid));
	memcpy(caller->process_guid, process_guid.bytes,
	       sizeof(caller->process_guid));
	caller->user_sid = token_summary.user_sid_ptr;
	caller->user_sid_len = token_summary.user_sid_len;
	caller->authentication_id = token_summary.auth_id;
	caller->token_id = token_summary.token_id;
	caller->token_type = token_summary.token_type;
	caller->impersonation_level = token_summary.impersonation_level;
	caller->integrity_level = token_summary.integrity_level;
	return 0;
}

long pkm_lcs_emit_key_open_audit_for_token(
	const void *token, const u8 key_guid[16],
	const struct pkm_lcs_key_open_access_plan *plan)
{
	struct pkm_lcs_audit_caller_summary caller = { };
	size_t payload_len = 0;
	size_t written = 0;
	u32 sacl_match_flags;
	u32 requested_access;
	u32 granted_access;
	u8 *payload;
	long ret;

	if (!token || !key_guid || !plan)
		return -EINVAL;
	if (!plan->key_open_sacl_audit_required)
		return 0;

	ret = pkm_lcs_build_audit_caller_summary(token, &caller);
	if (ret)
		return ret;

	sacl_match_flags = plan->allowed ? PKM_LCS_SACL_MATCH_SUCCESS :
					   PKM_LCS_SACL_MATCH_FAILURE;
	requested_access = plan->mapped_desired_access;
	if (plan->maximum_allowed)
		requested_access |= MAXIMUM_ALLOWED;
	granted_access = plan->allowed ? plan->fd_granted_access : 0U;

	ret = lcs_rust_key_open_audit_payload(
		&caller, key_guid, requested_access, granted_access,
		plan->allowed ? 1U : 0U, sacl_match_flags, NULL, 0,
		&payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_key_open_audit_payload(
		&caller, key_guid, requested_access, granted_access,
		plan->allowed ? 1U : 0U, sacl_match_flags, payload,
		payload_len, &written);
	if (ret || written != payload_len) {
		kfree(payload);
		return -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS, pkm_lcs_key_open_audit_event_type,
			     sizeof(pkm_lcs_key_open_audit_event_type) - 1,
			     payload, written);
	kfree(payload);
	return 0;
}

static long pkm_lcs_publish_open_key_for_token(
	const void *token, u32 source_id, const u8 key_guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u32 desired_access,
	const char * const *resolved_path,
	const u8 (*ancestor_guids)[RSI_GUID_SIZE], u32 path_component_count)
{
	struct pkm_lcs_key_fd_publish_input publish = { };
	struct pkm_lcs_key_open_access_plan access = { };
	long audit_ret;
	long ret;

	ret = pkm_lcs_key_open_access_check_for_token(
		token, sd, sd_len, desired_access, &access);
	if (ret) {
		if (ret == -EACCES && access.key_open_sacl_audit_required) {
			audit_ret = pkm_lcs_emit_key_open_audit_for_token(
				token, key_guid, &access);
			if (audit_ret)
				ret = audit_ret;
		}
		return ret;
	}

	ret = pkm_lcs_emit_key_open_audit_for_token(token, key_guid, &access);
	if (ret)
		return ret;

	publish.source_id = source_id;
	memcpy(publish.key_guid, key_guid, sizeof(publish.key_guid));
	publish.granted_access = access.fd_granted_access;
	publish.resolved_path = resolved_path;
	publish.ancestor_guids = ancestor_guids;
	publish.path_component_count = path_component_count;
	return pkm_lcs_key_fd_publish(&publish);
}

long pkm_lcs_validate_syscall_relative_path(
	const char *path, u32 path_len,
	struct pkm_lcs_path_validation_result *result)
{
	if (!path || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	return lcs_rust_validate_syscall_relative_path((const u8 *)path,
						      path_len, result);
}

static long pkm_lcs_validate_relative_open_depth(
	const struct pkm_lcs_relative_open_preflight *result)
{
	if (!result)
		return -EINVAL;

	return lcs_rust_validate_relative_open_depth(
		result->parent.parent_depth, result->path.component_count);
}

static long pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_hive_route_result route = { };
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	ret = pkm_lcs_route_absolute_path_for_token(
		token, copy->path, copy->path_len, true, scope_guids,
		scope_count, &route);
	if (ret)
		return ret;

	ret = pkm_lcs_materialize_absolute_path_components_for_token(
		token, copy->path, copy->path_len, true, &components);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components_for_open(
		route.source_id, 0, route.root_guid, components.components,
		components.component_count, (flags & REG_OPEN_LINK) != 0,
		scope_guids, scope_count, layers, layer_count, private_layers,
		private_layer_count, &resolved);
	if (ret)
		goto out_components;

	if (!resolved.final_frame.data || !resolved.final_sd_len ||
	    (size_t)resolved.final_sd_offset > resolved.final_frame.len ||
	    (size_t)resolved.final_sd_len >
		    resolved.final_frame.len -
			    (size_t)resolved.final_sd_offset) {
		ret = -EIO;
		goto out_resolved;
	}

	final_sd = resolved.final_frame.data + resolved.final_sd_offset;
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
	return ret;
}

static long pkm_lcs_open_copied_relative_path_after_preflight(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	ret = pkm_lcs_validate_syscall_relative_path(copy->path,
						     copy->path_len, &path);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_parent_snapshot(parent_fd, &parent);
	if (ret)
		return ret;

	ret = lcs_rust_validate_relative_open_depth(
		parent.path_component_count, path.component_count);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_materialize_relative_path_components(
		copy->path, copy->path_len, &components);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_walk_relative_components_for_open(
		&parent, 0, components.components, components.component_count,
		(flags & REG_OPEN_LINK) != 0, NULL, 0, layers, layer_count,
		private_layers, private_layer_count, &resolved);
	if (ret)
		goto out_components;

	if (!resolved.final_frame.data || !resolved.final_sd_len ||
	    (size_t)resolved.final_sd_offset > resolved.final_frame.len ||
	    (size_t)resolved.final_sd_len >
		    resolved.final_frame.len -
			    (size_t)resolved.final_sd_offset) {
		ret = -EIO;
		goto out_resolved;
	}

	final_sd = resolved.final_frame.data + resolved.final_sd_offset;
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	return ret;
}

long pkm_lcs_open_copied_absolute_path_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_open_preflight_plan preflight = { };
	long ret;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	return pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
		token, copy, desired_access, flags, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count);
}

long pkm_lcs_open_copied_relative_path_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_open_preflight_plan preflight = { };
	long ret;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	return pkm_lcs_open_copied_relative_path_after_preflight(
		token, parent_fd, copy, desired_access, flags, layers,
		layer_count, private_layers, private_layer_count);
}

long pkm_lcs_open_user_absolute_path_preflight_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	bool rewrite_current_user, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_open_preflight_plan *plan,
	struct pkm_lcs_hive_route_result *route)
{
	long ret;

	if (!plan || !route)
		return -EINVAL;

	memset(route, 0, sizeof(*route));
	ret = pkm_lcs_open_preflight(desired_access, flags, plan);
	if (ret)
		return ret;

	return pkm_lcs_route_user_absolute_path_for_token(
		token, ops, upath, rewrite_current_user, scope_guids,
		scope_count, route);
}

long pkm_lcs_open_user_relative_path_preflight(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, u32 desired_access, u32 flags,
	struct pkm_lcs_relative_open_preflight *result)
{
	struct pkm_lcs_syscall_path_copy copy = { };
	long ret;

	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_open_preflight(desired_access, flags, &result->access);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_validate_syscall_relative_path(copy.path, copy.path_len,
						     &result->path);
	if (ret)
		goto out_destroy_copy;

	ret = pkm_lcs_key_fd_relative_base(parent_fd, &result->parent);
	if (ret)
		goto out_destroy_copy;

	ret = pkm_lcs_validate_relative_open_depth(result);
	if (ret)
		memset(&result->parent, 0, sizeof(result->parent));

out_destroy_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

void pkm_lcs_materialized_path_destroy(struct pkm_lcs_materialized_path *path)
{
	if (!path)
		return;

	kfree(path->components);
	kfree(path->strings);
	memset(path, 0, sizeof(*path));
}

long pkm_lcs_materialize_absolute_path_components_for_token(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, struct pkm_lcs_materialized_path *result)
{
	const u8 *current_user_sid = NULL;
	size_t current_user_sid_len = 0;
	struct pkm_lcs_path_component_materialization shape = { };
	struct pkm_lcs_path_component_materialization filled = { };
	struct pkm_lcs_path_component_view *components;
	char *strings;
	long ret;

	if (!path || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (rewrite_current_user) {
		ret = kacs_rust_token_user_sid(token, &current_user_sid,
					       &current_user_sid_len);
		if (ret)
			return ret;
	}

	ret = lcs_rust_materialize_absolute_path_components_with_token_sid(
		(const u8 *)path, path_len, rewrite_current_user,
		current_user_sid, current_user_sid_len, NULL, 0, NULL, 0,
		&shape);
	if (ret)
		return ret;
	if (!shape.component_count || !shape.string_bytes)
		return -EINVAL;

	components = kcalloc(shape.component_count, sizeof(*components),
			     GFP_KERNEL);
	if (!components)
		return -ENOMEM;
	strings = kmalloc(shape.string_bytes, GFP_KERNEL);
	if (!strings) {
		kfree(components);
		return -ENOMEM;
	}

	ret = lcs_rust_materialize_absolute_path_components_with_token_sid(
		(const u8 *)path, path_len, rewrite_current_user,
		current_user_sid, current_user_sid_len, components,
		shape.component_count, (u8 *)strings, shape.string_bytes,
		&filled);
	if (ret)
		goto out_free;
	if (filled.component_count != shape.component_count ||
	    filled.string_bytes != shape.string_bytes) {
		ret = -EIO;
		goto out_free;
	}

	result->components = components;
	result->strings = strings;
	result->component_count = filled.component_count;
	result->string_bytes = filled.string_bytes;
	return 0;

out_free:
	kfree(components);
	kfree(strings);
	return ret;
}

long pkm_lcs_materialize_relative_path_components(
	const char *path, u32 path_len,
	struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_path_component_materialization shape = { };
	struct pkm_lcs_path_component_materialization filled = { };
	struct pkm_lcs_path_component_view *components;
	char *strings;
	long ret;

	if (!path || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	ret = lcs_rust_materialize_relative_path_components(
		(const u8 *)path, path_len, NULL, 0, NULL, 0, &shape);
	if (ret)
		return ret;
	if (!shape.component_count || !shape.string_bytes)
		return -EINVAL;

	components = kcalloc(shape.component_count, sizeof(*components),
			     GFP_KERNEL);
	if (!components)
		return -ENOMEM;
	strings = kmalloc(shape.string_bytes, GFP_KERNEL);
	if (!strings) {
		kfree(components);
		return -ENOMEM;
	}

	ret = lcs_rust_materialize_relative_path_components(
		(const u8 *)path, path_len, components, shape.component_count,
		(u8 *)strings, shape.string_bytes, &filled);
	if (ret)
		goto out_free;
	if (filled.component_count != shape.component_count ||
	    filled.string_bytes != shape.string_bytes) {
		ret = -EIO;
		goto out_free;
	}

	result->components = components;
	result->strings = strings;
	result->component_count = filled.component_count;
	result->string_bytes = filled.string_bytes;
	return 0;

out_free:
	kfree(components);
	kfree(strings);
	return ret;
}

long pkm_lcs_route_symlink_target(
	const char *target, u32 target_len, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_copy
		views[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
	u32 slot_count;
	long ret;

	if (!target || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	mutex_lock(&pkm_lcs_source_table_lock);
	slot_count = pkm_lcs_source_table_views_locked(views);
	ret = lcs_rust_route_symlink_target_from_source_slots(
		views, slot_count, (const u8 *)target, target_len,
		scope_guids, scope_count, result);
	mutex_unlock(&pkm_lcs_source_table_lock);
	return ret;
}

long pkm_lcs_materialize_symlink_target_components(
	const char *target, u32 target_len,
	struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_path_component_materialization shape = { };
	struct pkm_lcs_path_component_materialization filled = { };
	struct pkm_lcs_path_component_view *components;
	char *strings;
	long ret;

	if (!target || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	ret = lcs_rust_materialize_symlink_target_components(
		(const u8 *)target, target_len, NULL, 0, NULL, 0, &shape);
	if (ret)
		return ret;
	if (!shape.component_count || !shape.string_bytes)
		return -EINVAL;

	components = kcalloc(shape.component_count, sizeof(*components),
			     GFP_KERNEL);
	if (!components)
		return -ENOMEM;
	strings = kmalloc(shape.string_bytes, GFP_KERNEL);
	if (!strings) {
		kfree(components);
		return -ENOMEM;
	}

	ret = lcs_rust_materialize_symlink_target_components(
		(const u8 *)target, target_len, components,
		shape.component_count, (u8 *)strings, shape.string_bytes,
		&filled);
	if (ret)
		goto out_free;
	if (filled.component_count != shape.component_count ||
	    filled.string_bytes != shape.string_bytes) {
		ret = -EIO;
		goto out_free;
	}

	result->components = components;
	result->strings = strings;
	result->component_count = filled.component_count;
	result->string_bytes = filled.string_bytes;
	return 0;

out_free:
	kfree(components);
	kfree(strings);
	return ret;
}

void pkm_lcs_symlink_target_resolution_destroy(
	struct pkm_lcs_symlink_target_resolution *resolution)
{
	if (!resolution)
		return;

	pkm_lcs_materialized_path_destroy(&resolution->components);
	memset(resolution, 0, sizeof(*resolution));
}

long pkm_lcs_resolve_symlink_target_for_key(
	u32 source_id, u64 txn_id, const u8 key_guid[RSI_GUID_SIZE],
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_symlink_target_resolution *result)
{
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_query_value_result value = { };
	struct pkm_lcs_source_response_frame frame;
	const char *target;
	u64 next_sequence;
	long ret;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;

	if (!source_id || !key_guid || !result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	pkm_lcs_source_response_frame_init(&frame);

	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
		source_id, txn_id, key_guid, "", 0, false,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
		&enqueue);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_rsi_materialize_query_value_response(
		frame.data, frame.len, response.request_id, next_sequence,
		"", 0, active_layers, active_layer_count,
		active_private_layers, active_private_layer_count, &value);
	if (ret)
		goto out_destroy;
	if (!value.found || value.value_type != REG_LINK) {
		ret = -EINVAL;
		goto out_destroy;
	}
	if ((size_t)value.data_offset > frame.len ||
	    (size_t)value.data_len > frame.len - (size_t)value.data_offset) {
		ret = -EIO;
		goto out_destroy;
	}

	target = (const char *)(frame.data + value.data_offset);
	ret = pkm_lcs_route_symlink_target(
		target, value.data_len, scope_guids, scope_count,
		&result->route);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_materialize_symlink_target_components(
		target, value.data_len, &result->components);
	if (ret)
		goto out_destroy;

	result->value_type = value.value_type;
	result->selected_precedence = value.selected_precedence;
	result->selected_sequence = value.selected_sequence;
	pkm_lcs_source_response_frame_destroy(&frame);
	return 0;

out_destroy:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_symlink_target_resolution_destroy(result);
	return ret;
}

long pkm_lcs_open_user_absolute_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_open_preflight_plan preflight = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_syscall_path_copy copy = { };
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_route_absolute_path_for_token(
		token, copy.path, copy.path_len, true, scope_guids,
		scope_count, &route);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_materialize_absolute_path_components_for_token(
		token, copy.path, copy.path_len, true, &components);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_walk_absolute_components_for_open(
		route.source_id, 0, route.root_guid, components.components,
		components.component_count, (flags & REG_OPEN_LINK) != 0,
		scope_guids, scope_count, layers, layer_count,
		private_layers, private_layer_count, &resolved);
	if (ret)
		goto out_components;

	if (!resolved.final_frame.data || !resolved.final_sd_len ||
	    (size_t)resolved.final_sd_offset > resolved.final_frame.len ||
	    (size_t)resolved.final_sd_len >
		    resolved.final_frame.len -
			    (size_t)resolved.final_sd_offset) {
		ret = -EIO;
		goto out_resolved;
	}

	final_sd = resolved.final_frame.data + resolved.final_sd_offset;
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_open_user_relative_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_open_preflight_plan preflight = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_syscall_path_copy copy = { };
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_validate_syscall_relative_path(copy.path, copy.path_len,
						     &path);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_key_fd_parent_snapshot(parent_fd, &parent);
	if (ret)
		goto out_copy;

	ret = lcs_rust_validate_relative_open_depth(
		parent.path_component_count, path.component_count);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_materialize_relative_path_components(
		copy.path, copy.path_len, &components);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_walk_relative_components_for_open(
		&parent, 0, components.components, components.component_count,
		(flags & REG_OPEN_LINK) != 0, NULL, 0, layers, layer_count,
		private_layers, private_layer_count,
		&resolved);
	if (ret)
		goto out_components;

	if (!resolved.final_frame.data || !resolved.final_sd_len ||
	    (size_t)resolved.final_sd_offset > resolved.final_frame.len ||
	    (size_t)resolved.final_sd_len >
		    resolved.final_frame.len -
			    (size_t)resolved.final_sd_offset) {
		ret = -EIO;
		goto out_resolved;
	}

	final_sd = resolved.final_frame.data + resolved.final_sd_offset;
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_reg_open_key_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags)
{
	if (parent_fd == -1)
		return pkm_lcs_open_user_absolute_path_for_token(
			token, ops, upath, desired_access, flags, NULL, 0, NULL, 0,
			NULL, 0);

	return pkm_lcs_open_user_relative_path_for_token(
		token, ops, parent_fd, upath, desired_access, flags, NULL, 0,
		NULL, 0);
}

SYSCALL_DEFINE4(reg_open_key, int, parent_fd, const char __user *, path,
		u32, desired_access, u32, flags)
{
	return pkm_lcs_reg_open_key_for_token(
		pkm_kacs_current_effective_token_ptr(), NULL, parent_fd, path,
		desired_access, flags);
}

long pkm_lcs_create_existing_user_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	u32 *disposition)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	long ret;

	if (disposition)
		*disposition = 0;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	if (parent_fd == -1)
		ret = pkm_lcs_open_user_absolute_path_for_token(
			token, ops, upath, desired_access, 0, NULL, 0, NULL, 0,
			NULL, 0);
	else
		ret = pkm_lcs_open_user_relative_path_for_token(
			token, ops, parent_fd, upath, desired_access, 0, NULL, 0,
			NULL, 0);

	if (ret >= 0 && disposition)
		*disposition = REG_OPENED_EXISTING;
	return ret;
}

long pkm_lcs_create_existing_copied_path_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, u32 *disposition)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	long ret;

	if (disposition)
		*disposition = 0;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	if (parent_fd == -1)
		ret = pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
			token, copy, desired_access, 0, NULL, 0, NULL, 0,
			NULL, 0);
	else
		ret = pkm_lcs_open_copied_relative_path_after_preflight(
			token, parent_fd, copy, desired_access, 0, NULL, 0,
			NULL, 0);

	if (ret >= 0 && disposition)
		*disposition = REG_OPENED_EXISTING;
	return ret;
}

long pkm_lcs_reg_create_key_copy_disposition_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	u32 disposition)
{
	if (!udisposition)
		return 0;
	if (!ops)
		ops = &pkm_lcs_default_usercopy_ops;
	if (!ops->write)
		return -EINVAL;

	if (!ops->write(ops->ctx, udisposition, &disposition,
			sizeof(disposition)))
		return -EFAULT;
	return 0;
}

long pkm_lcs_reg_create_key_finish_success_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	long fd, u32 disposition)
{
	long ret;

	if (fd < 0 || fd > INT_MAX)
		return -EINVAL;

	ret = pkm_lcs_reg_create_key_copy_disposition_to_user(
		ops, udisposition, disposition);
	if (ret) {
		close_fd((unsigned int)fd);
		return ret;
	}

	return fd;
}

long pkm_lcs_create_existing_user_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	u32 __user *udisposition)
{
	long fd;

	fd = pkm_lcs_create_existing_user_path_for_token(
		token, ops, parent_fd, upath, desired_access, flags, NULL);
	if (fd < 0)
		return fd;

	return pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);
}

long pkm_lcs_create_existing_copied_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, u32 __user *udisposition)
{
	long fd;

	fd = pkm_lcs_create_existing_copied_path_for_token(
		token, parent_fd, copy, desired_access, flags, NULL);
	if (fd < 0)
		return fd;

	return pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);
}

void pkm_lcs_resolved_key_path_destroy(struct pkm_lcs_resolved_key_path *path)
{
	u32 i;

	if (!path)
		return;

	if (path->resolved_path) {
		for (i = 0; i < path->component_count; i++)
			kfree(path->resolved_path[i]);
		kfree(path->resolved_path);
	}
	kfree(path->ancestor_guids);
	pkm_lcs_source_response_frame_destroy(&path->final_frame);
	memset(path, 0, sizeof(*path));
}

void pkm_lcs_create_missing_parent_resolution_destroy(
	struct pkm_lcs_create_missing_parent_resolution *resolution)
{
	if (!resolution)
		return;

	pkm_lcs_resolved_key_path_destroy(&resolution->parent);
	kfree(resolution->child_name);
	memset(resolution, 0, sizeof(*resolution));
}

static long pkm_lcs_create_missing_parent_copy_child(
	const struct pkm_lcs_path_component_view *component,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	char *name;

	if (!component || !component->name || !component->name_len || !result)
		return -EINVAL;
	if (component->name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	name = kmemdup_nul(component->name, component->name_len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	kfree(result->child_name);
	result->child_name = name;
	result->child_name_len = component->name_len;
	return 0;
}

static long pkm_lcs_create_missing_validate_child_depth(
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	long ret;

	if (!result || !result->parent.component_count)
		return -EINVAL;

	ret = lcs_rust_validate_relative_open_depth(
		result->parent.component_count, 1);
	if (ret)
		return ret;

	result->child_depth = result->parent.component_count + 1U;
	return 0;
}

static long pkm_lcs_resolved_parent_from_snapshot_prepare(
	const struct pkm_lcs_key_fd_parent_snapshot *parent,
	struct pkm_lcs_resolved_key_path *result)
{
	size_t guid_bytes;
	u32 i;

	if (!parent || !result || !parent->source_id ||
	    !parent->path_component_count || !parent->resolved_path ||
	    !parent->ancestor_guids)
		return -EINVAL;
	if (parent->orphaned)
		return -ENOENT;
	if (parent->path_component_count > PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->source_id = parent->source_id;
	result->component_count = parent->path_component_count;
	memcpy(result->key_guid, parent->key_guid, sizeof(result->key_guid));
	pkm_lcs_source_response_frame_init(&result->final_frame);

	result->resolved_path = kcalloc(parent->path_component_count,
					sizeof(*result->resolved_path),
					GFP_KERNEL);
	if (!result->resolved_path)
		return -ENOMEM;

	if (check_mul_overflow((size_t)parent->path_component_count,
			       sizeof(*result->ancestor_guids), &guid_bytes)) {
		pkm_lcs_resolved_key_path_destroy(result);
		return -EINVAL;
	}
	result->ancestor_guids = kmemdup(parent->ancestor_guids, guid_bytes,
					GFP_KERNEL);
	if (!result->ancestor_guids) {
		pkm_lcs_resolved_key_path_destroy(result);
		return -ENOMEM;
	}

	for (i = 0; i < parent->path_component_count; i++) {
		if (!parent->resolved_path[i]) {
			pkm_lcs_resolved_key_path_destroy(result);
			return -EINVAL;
		}
		result->resolved_path[i] = kstrdup(parent->resolved_path[i],
						   GFP_KERNEL);
		if (!result->resolved_path[i]) {
			pkm_lcs_resolved_key_path_destroy(result);
			return -ENOMEM;
		}
	}

	return 0;
}

static long pkm_lcs_create_missing_read_parent_key(
	u32 source_id, u64 txn_id, const u8 key_guid[RSI_GUID_SIZE],
	struct pkm_lcs_resolved_key_path *parent)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_source_response_frame frame;
	long ret;

	if (!source_id || !key_guid || !parent)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
		source_id, txn_id, key_guid, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
		&frame, &response, &enqueue);
	if (ret)
		goto out_destroy_frame;

	ret = pkm_lcs_rsi_materialize_read_key_response(
		frame.data, frame.len, response.request_id, &read_key);
	if (ret)
		goto out_destroy_frame;
	if (!read_key.sd_len ||
	    (size_t)read_key.sd_offset > frame.len ||
	    (size_t)read_key.sd_len >
		    frame.len - (size_t)read_key.sd_offset) {
		ret = -EIO;
		goto out_destroy_frame;
	}

	parent->final_sd_offset = read_key.sd_offset;
	parent->final_sd_len = read_key.sd_len;
	parent->final_volatile = read_key.volatile_key != 0;
	parent->final_symlink = read_key.symlink != 0;
	parent->final_last_write_time = read_key.last_write_time;
	parent->final_frame = frame;
	pkm_lcs_source_response_frame_init(&frame);

out_destroy_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

long pkm_lcs_create_missing_absolute_parent_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_syscall_path_copy copy = { };
	u32 parent_component_count;
	long ret;

	if (!token || !result)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_route_absolute_path_for_token(
		token, copy.path, copy.path_len, true, scope_guids,
		scope_count, &route);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_materialize_absolute_path_components_for_token(
		token, copy.path, copy.path_len, true, &components);
	if (ret)
		goto out_copy;
	if (components.component_count < 2U) {
		ret = -EINVAL;
		goto out_components;
	}

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	parent_component_count = components.component_count - 1U;
	ret = pkm_lcs_walk_absolute_components_for_open(
		route.source_id, 0, route.root_guid, components.components,
		parent_component_count, false, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		&result->parent);
	if (ret)
		goto out_result;

	ret = pkm_lcs_create_missing_validate_child_depth(result);
	if (ret)
		goto out_result;

	pkm_lcs_materialized_path_destroy(&components);
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_create_missing_relative_parent(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_syscall_path_copy copy = { };
	long ret;

	if (!result)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_validate_syscall_relative_path(copy.path, copy.path_len,
						     &path);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_key_fd_parent_snapshot(parent_fd, &parent);
	if (ret)
		goto out_copy;

	ret = lcs_rust_validate_relative_open_depth(
		parent.path_component_count, path.component_count);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_materialize_relative_path_components(
		copy.path, copy.path_len, &components);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	if (components.component_count == 1U) {
		ret = pkm_lcs_resolved_parent_from_snapshot_prepare(
			&parent, &result->parent);
		if (ret)
			goto out_result;
		ret = pkm_lcs_create_missing_read_parent_key(
			parent.source_id, 0, parent.key_guid, &result->parent);
	} else {
		ret = pkm_lcs_walk_relative_components_for_open(
			&parent, 0, components.components,
			components.component_count - 1U, false, scope_guids,
			scope_count, layers, layer_count, private_layers,
			private_layer_count, &result->parent);
	}
	if (ret)
		goto out_result;

	ret = pkm_lcs_create_missing_validate_child_depth(result);
	if (ret)
		goto out_result;

	pkm_lcs_materialized_path_destroy(&components);
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_create_missing_copied_absolute_parent_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_hive_route_result route = { };
	u32 parent_component_count;
	long ret;

	if (!token || !result)
		return -EINVAL;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_route_absolute_path_for_token(
		token, copy->path, copy->path_len, true, scope_guids,
		scope_count, &route);
	if (ret)
		return ret;

	ret = pkm_lcs_materialize_absolute_path_components_for_token(
		token, copy->path, copy->path_len, true, &components);
	if (ret)
		return ret;
	if (components.component_count < 2U) {
		ret = -EINVAL;
		goto out_components;
	}

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	parent_component_count = components.component_count - 1U;
	ret = pkm_lcs_walk_absolute_components_for_open(
		route.source_id, 0, route.root_guid, components.components,
		parent_component_count, false, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		&result->parent);
	if (ret)
		goto out_result;

	ret = pkm_lcs_create_missing_validate_child_depth(result);
	if (ret)
		goto out_result;

	pkm_lcs_materialized_path_destroy(&components);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
	return ret;
}

long pkm_lcs_create_missing_copied_relative_parent(
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_path_validation_result path = { };
	long ret;

	if (!result)
		return -EINVAL;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_validate_syscall_relative_path(copy->path,
						     copy->path_len, &path);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_parent_snapshot(parent_fd, &parent);
	if (ret)
		return ret;

	ret = lcs_rust_validate_relative_open_depth(
		parent.path_component_count, path.component_count);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_materialize_relative_path_components(
		copy->path, copy->path_len, &components);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	if (components.component_count == 1U) {
		ret = pkm_lcs_resolved_parent_from_snapshot_prepare(
			&parent, &result->parent);
		if (ret)
			goto out_result;
		ret = pkm_lcs_create_missing_read_parent_key(
			parent.source_id, 0, parent.key_guid, &result->parent);
	} else {
		ret = pkm_lcs_walk_relative_components_for_open(
			&parent, 0, components.components,
			components.component_count - 1U, false, scope_guids,
			scope_count, layers, layer_count, private_layers,
			private_layer_count, &result->parent);
	}
	if (ret)
		goto out_result;

	ret = pkm_lcs_create_missing_validate_child_depth(result);
	if (ret)
		goto out_result;

	pkm_lcs_materialized_path_destroy(&components);
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	return ret;
}

long pkm_lcs_create_missing_copied_parent_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	if (parent_fd == -1)
		return pkm_lcs_create_missing_copied_absolute_parent_for_token(
			token, copy, scope_guids, scope_count, layers,
			layer_count, private_layers, private_layer_count,
			result);

	return pkm_lcs_create_missing_copied_relative_parent(
		parent_fd, copy, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, result);
}

long pkm_lcs_create_missing_parent_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	if (parent_fd == -1)
		return pkm_lcs_create_missing_absolute_parent_for_token(
			token, ops, upath, scope_guids, scope_count, layers,
			layer_count, private_layers, private_layer_count,
			result);

	return pkm_lcs_create_missing_relative_parent(
		ops, parent_fd, upath, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, result);
}

static long pkm_lcs_create_missing_parent_sd_view(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 **sd, size_t *sd_len)
{
	const struct pkm_lcs_resolved_key_path *parent;
	size_t sd_offset;
	size_t local_sd_len;

	if (!resolution || !sd || !sd_len)
		return -EINVAL;

	*sd = NULL;
	*sd_len = 0;
	parent = &resolution->parent;
	sd_offset = parent->final_sd_offset;
	local_sd_len = parent->final_sd_len;
	if (!parent->final_frame.data || !parent->final_frame.len ||
	    !local_sd_len || sd_offset > parent->final_frame.len ||
	    local_sd_len > parent->final_frame.len - sd_offset)
		return -EIO;

	*sd = parent->final_frame.data + sd_offset;
	*sd_len = local_sd_len;
	return 0;
}

long pkm_lcs_create_missing_parent_access_check_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_key_open_access_plan *plan)
{
	const u8 *sd;
	size_t sd_len;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	ret = pkm_lcs_create_missing_parent_sd_view(resolution, &sd, &sd_len);
	if (ret)
		return ret;

	return pkm_lcs_key_open_access_check_for_token(
		token, sd, sd_len, KEY_CREATE_SUB_KEY, plan);
}

long pkm_lcs_create_missing_volatile_parent_check(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_preflight_plan *preflight)
{
	if (!resolution || !preflight)
		return -EINVAL;

	if (resolution->parent.final_volatile &&
	    !preflight->options.volatile_key)
		return -EINVAL;

	return 0;
}

void pkm_lcs_created_key_sd_destroy(struct pkm_lcs_created_key_sd *created)
{
	if (!created)
		return;

	pkm_kacs_free((void *)created->sd);
	memset(created, 0, sizeof(*created));
}

long pkm_lcs_create_missing_initial_sd_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_created_key_sd *created)
{
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len;
	size_t child_sd_len = 0;
	long ret;

	if (!created)
		return -EINVAL;

	memset(created, 0, sizeof(*created));
	if (!token)
		return -EACCES;

	ret = pkm_lcs_create_missing_parent_sd_view(resolution, &parent_sd,
						    &parent_sd_len);
	if (ret)
		return ret;

	ret = kacs_rust_build_created_container_sd(
		token, parent_sd, parent_sd_len, KEY_READ, KEY_WRITE, 0,
		KEY_ALL_ACCESS, REG_VALID_MAPPED_ACCESS_MASK, &child_sd,
		&child_sd_len);
	if (ret == -EINVAL || ret == -ERANGE)
		return -EIO;
	if (ret)
		return ret;
	if (!child_sd || !child_sd_len) {
		pkm_kacs_free((void *)child_sd);
		return -EIO;
	}

	created->sd = child_sd;
	created->sd_len = child_sd_len;
	return 0;
}

long pkm_lcs_layer_write_access_check_for_token(
	const void *token, const u8 *metadata_sd, size_t metadata_sd_len,
	struct pkm_lcs_key_open_access_plan *plan)
{
	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!metadata_sd || !metadata_sd_len)
		return -EIO;

	return pkm_lcs_key_open_access_check_for_token(
		token, metadata_sd, metadata_sd_len, KEY_SET_VALUE, plan);
}

long pkm_lcs_base_layer_write_access_check_for_token(
	const void *token, bool base_metadata_present,
	const u8 *base_metadata_sd, size_t base_metadata_sd_len,
	struct pkm_lcs_key_open_access_plan *plan)
{
	const u8 *default_sd;
	size_t default_sd_len = 0;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (base_metadata_present)
		return pkm_lcs_layer_write_access_check_for_token(
			token, base_metadata_sd, base_metadata_sd_len, plan);

	default_sd = kacs_rust_create_lcs_base_layer_default_sd(
		&default_sd_len);
	if (!default_sd || !default_sd_len)
		return -ENOMEM;

	ret = pkm_lcs_layer_write_access_check_for_token(
		token, default_sd, default_sd_len, plan);
	pkm_kacs_free((void *)default_sd);
	return ret;
}

long pkm_lcs_create_layer_write_access_check_for_token(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	u32 metadata_count, struct pkm_lcs_key_open_access_plan *plan)
{
	struct pkm_lcs_layer_metadata_sd_selection selection = { };
	const struct pkm_lcs_layer_metadata_sd_view *selected;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!target || !target->name)
		return -EINVAL;

	if (target->implicit_base)
		return pkm_lcs_base_layer_write_access_check_for_token(
			token, base_metadata_present, base_metadata_sd,
			base_metadata_sd_len, plan);

	if (metadata_count && !metadata)
		return -EINVAL;

	ret = lcs_rust_select_layer_metadata_sd(
		(const u8 *)target->name, target->name_len, metadata,
		metadata_count, &selection);
	if (ret)
		return ret;
	if (selection.index >= metadata_count)
		return -EIO;

	selected = &metadata[selection.index];
	return pkm_lcs_layer_write_access_check_for_token(
		token, selected->sd, selected->sd_len, plan);
}

static void pkm_lcs_default_key_guid_generate(void *ctx, u8 guid[16])
{
	(void)ctx;

	pkm_kacs_fill_uuid_v4(guid);
}

long pkm_lcs_assign_new_key_guid(
	const u8 (*active_key_guids)[16], u32 active_key_guid_count,
	const u8 (*retired_key_guids)[16], u32 retired_key_guid_count,
	const struct pkm_lcs_key_guid_generator *generator,
	struct pkm_lcs_key_guid_assignment_plan *plan)
{
	pkm_lcs_key_guid_generator_fn generate =
		pkm_lcs_default_key_guid_generate;
	void *generate_ctx = NULL;
	u8 candidate[16];
	u32 attempt;
	int ret = -EIO;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if ((active_key_guid_count && !active_key_guids) ||
	    (retired_key_guid_count && !retired_key_guids))
		return -EINVAL;
	if (generator) {
		if (!generator->generate)
			return -EINVAL;
		generate = generator->generate;
		generate_ctx = generator->ctx;
	}

	BUILD_BUG_ON(sizeof(candidate) != KACS_UUID_BYTES);

	for (attempt = 0; attempt < PKM_LCS_KEY_GUID_ASSIGNMENT_MAX_ATTEMPTS;
	     attempt++) {
		memset(candidate, 0, sizeof(candidate));
		generate(generate_ctx, candidate);
		ret = lcs_rust_plan_key_guid_assignment(
			candidate, active_key_guids, active_key_guid_count,
			retired_key_guids, retired_key_guid_count, plan);
		if (!ret)
			return 0;
		if (ret != -EIO)
			return ret;
	}

	memset(plan, 0, sizeof(*plan));
	return -EIO;
}

long pkm_lcs_create_missing_symlink_authority_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 flags, struct pkm_lcs_key_open_access_plan *link_plan)
{
	const u32 known_flags = REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK;
	const u8 *sd;
	size_t sd_len;
	long ret;

	if (!link_plan)
		return -EINVAL;

	memset(link_plan, 0, sizeof(*link_plan));
	if (flags & ~known_flags)
		return -EINVAL;
	if (!(flags & REG_OPTION_CREATE_LINK))
		return 0;

	ret = pkm_lcs_create_missing_parent_sd_view(resolution, &sd, &sd_len);
	if (ret)
		return ret;

	ret = pkm_lcs_key_open_access_check_for_token(
		token, sd, sd_len, KEY_CREATE_LINK, link_plan);
	if (ret)
		return ret;

	if (!pkm_lcs_token_has_tcb_or_admin_authority(token))
		return -EPERM;

	return 0;
}

static long pkm_lcs_create_missing_source_response_plan(
	long round_trip_ret,
	const struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_reg_create_source_response_plan *plan)
{
	if (!response || !plan)
		return -EINVAL;
	if (!response->len)
		return round_trip_ret ? round_trip_ret : -EIO;

	return pkm_lcs_reg_create_key_source_response_plan(
		response->request_op_code, response->status, plan);
}

long pkm_lcs_create_missing_source_records(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd,
	bool volatile_key, bool symlink,
	struct pkm_lcs_create_missing_source_records_result *result)
{
	struct pkm_lcs_source_response_result entry_response = { };
	struct pkm_lcs_source_response_result key_response = { };
	struct pkm_lcs_reg_create_source_response_plan plan = { };
	u64 sequence = 0;
	long ret;

	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (!resolution || !target || !target->name || !child_guid ||
	    !created_sd || !created_sd->sd || !created_sd->sd_len ||
	    !resolution->parent.source_id || !resolution->child_name ||
	    !resolution->child_name_len)
		return -EINVAL;

	ret = pkm_lcs_allocate_sequence(&sequence);
	if (ret)
		return ret;

	ret = pkm_lcs_source_create_entry_round_trip_timeout(
		resolution->parent.source_id, 0, resolution->parent.key_guid,
		resolution->child_name, resolution->child_name_len,
		target->name, target->name_len, child_guid, sequence,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &entry_response, NULL);
	ret = pkm_lcs_create_missing_source_response_plan(ret, &entry_response,
							  &plan);
	if (ret)
		return ret;

	result->sequence = sequence;
	if (plan.action ==
	    PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING) {
		result->disposition = plan.disposition;
		result->retry_open_existing = true;
		return 0;
	}
	if (plan.action != PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY)
		return -EIO;

	ret = pkm_lcs_source_create_key_round_trip_timeout(
		resolution->parent.source_id, 0, child_guid,
		resolution->child_name, resolution->child_name_len,
		resolution->parent.key_guid, created_sd->sd, created_sd->sd_len,
		volatile_key, symlink, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
		&key_response, NULL);
	ret = pkm_lcs_create_missing_source_response_plan(ret, &key_response,
							  &plan);
	if (ret)
		return ret;
	if (plan.action !=
	    PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW)
		return -EIO;

	result->disposition = plan.disposition;
	result->created_new = true;
	return 0;
}

static long pkm_lcs_create_missing_child_path_prepare(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 child_guid[RSI_GUID_SIZE],
	struct pkm_lcs_resolved_key_path *child)
{
	size_t guid_bytes;
	u32 parent_count;
	u32 child_index;
	u32 i;
	long ret;

	if (!child)
		return -EINVAL;

	memset(child, 0, sizeof(*child));
	if (!resolution || !child_guid || !resolution->parent.source_id ||
	    !resolution->parent.component_count ||
	    !resolution->parent.resolved_path ||
	    !resolution->parent.ancestor_guids ||
	    !resolution->child_name || !resolution->child_name_len)
		return -EINVAL;

	parent_count = resolution->parent.component_count;
	if (parent_count >= PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;
	if (resolution->child_depth != parent_count + 1U)
		return -EINVAL;
	if (resolution->child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	child->source_id = resolution->parent.source_id;
	child->component_count = resolution->child_depth;
	pkm_lcs_source_response_frame_init(&child->final_frame);
	memcpy(child->key_guid, child_guid, sizeof(child->key_guid));

	child->resolved_path = kcalloc(child->component_count,
				       sizeof(*child->resolved_path),
				       GFP_KERNEL);
	if (!child->resolved_path)
		return -ENOMEM;
	child->ancestor_guids = kcalloc(child->component_count,
					sizeof(*child->ancestor_guids),
					GFP_KERNEL);
	if (!child->ancestor_guids)
		goto out_nomem;

	if (check_mul_overflow((size_t)parent_count,
			       sizeof(*child->ancestor_guids), &guid_bytes)) {
		ret = -EINVAL;
		goto out_error;
	}
	memcpy(child->ancestor_guids, resolution->parent.ancestor_guids,
	       guid_bytes);

	for (i = 0; i < parent_count; i++) {
		if (!resolution->parent.resolved_path[i]) {
			ret = -EINVAL;
			goto out_error;
		}
		child->resolved_path[i] =
			kstrdup(resolution->parent.resolved_path[i],
				GFP_KERNEL);
		if (!child->resolved_path[i])
			goto out_nomem;
	}

	child_index = parent_count;
	child->resolved_path[child_index] =
		kmemdup_nul(resolution->child_name,
			    resolution->child_name_len, GFP_KERNEL);
	if (!child->resolved_path[child_index])
		goto out_nomem;
	memcpy(child->ancestor_guids[child_index], child_guid, RSI_GUID_SIZE);
	return 0;

out_nomem:
	pkm_lcs_resolved_key_path_destroy(child);
	return -ENOMEM;
out_error:
	pkm_lcs_resolved_key_path_destroy(child);
	return ret;
}

long pkm_lcs_create_missing_publish_created_key_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd, u32 desired_access)
{
	struct pkm_lcs_resolved_key_path child = { };
	long ret;

	if (!created_sd || !created_sd->sd || !created_sd->sd_len)
		return -EINVAL;

	ret = pkm_lcs_create_missing_child_path_prepare(resolution, child_guid,
						       &child);
	if (ret)
		return ret;

	ret = pkm_lcs_publish_open_key_for_token(
		token, child.source_id, child.key_guid, created_sd->sd,
		created_sd->sd_len, desired_access,
		(const char * const *)child.resolved_path,
		child.ancestor_guids, child.component_count);
	pkm_lcs_resolved_key_path_destroy(&child);
	return ret;
}

long pkm_lcs_create_missing_prepared_key_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd, u32 desired_access,
	bool volatile_key, bool symlink,
	struct pkm_lcs_create_missing_prepared_result *result)
{
	struct pkm_lcs_create_missing_source_records_result source = { };
	long fd;
	long ret;

	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->fd = -1;

	ret = pkm_lcs_create_missing_source_records(
		resolution, target, child_guid, created_sd, volatile_key,
		symlink, &source);
	if (ret)
		return ret;

	result->sequence = source.sequence;
	result->disposition = source.disposition;
	result->created_new = source.created_new;
	result->retry_open_existing = source.retry_open_existing;
	if (source.retry_open_existing)
		return 0;
	if (!source.created_new)
		return -EIO;

	fd = pkm_lcs_create_missing_publish_created_key_for_token(
		token, resolution, child_guid, created_sd, desired_access);
	if (fd < 0)
		return fd;

	result->fd = fd;
	return 0;
}

long pkm_lcs_create_missing_created_result_finish_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	struct pkm_lcs_create_missing_prepared_result *result)
{
	long fd;
	long ret;

	if (!result || !result->created_new || result->retry_open_existing ||
	    result->disposition != REG_CREATED_NEW || result->fd < 0 ||
	    result->fd > INT_MAX)
		return -EINVAL;

	fd = result->fd;
	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_CREATED_NEW);
	result->fd = -1;
	return ret;
}

static void pkm_lcs_retry_open_components_destroy(
	struct pkm_lcs_path_component_view *components)
{
	kfree(components);
}

static long pkm_lcs_retry_open_components_prepare(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_path_component_view **components_out, u32 *count_out)
{
	struct pkm_lcs_path_component_view *components;
	u32 parent_count;
	u32 component_count;
	u32 i;

	if (!components_out || !count_out)
		return -EINVAL;
	*components_out = NULL;
	*count_out = 0;

	if (!resolution || !resolution->parent.source_id ||
	    !resolution->parent.component_count ||
	    !resolution->parent.resolved_path ||
	    !resolution->parent.ancestor_guids ||
	    !resolution->child_name || !resolution->child_name_len)
		return -EINVAL;

	parent_count = resolution->parent.component_count;
	if (parent_count >= PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;
	component_count = parent_count + 1U;
	if (resolution->child_depth != component_count)
		return -EINVAL;
	if (resolution->child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	components = kcalloc(component_count, sizeof(*components), GFP_KERNEL);
	if (!components)
		return -ENOMEM;

	for (i = 0; i < parent_count; i++) {
		size_t len;

		if (!resolution->parent.resolved_path[i]) {
			pkm_lcs_retry_open_components_destroy(components);
			return -EINVAL;
		}
		len = strlen(resolution->parent.resolved_path[i]);
		if (!len || len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
		    len > U32_MAX) {
			pkm_lcs_retry_open_components_destroy(components);
			return -EINVAL;
		}
		components[i].name = resolution->parent.resolved_path[i];
		components[i].name_len = (u32)len;
	}

	components[parent_count].name = resolution->child_name;
	components[parent_count].name_len = resolution->child_name_len;
	*components_out = components;
	*count_out = component_count;
	return 0;
}

long pkm_lcs_create_missing_retry_open_existing_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 desired_access, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, u32 __user *udisposition)
{
	struct pkm_lcs_path_component_view *components = NULL;
	struct pkm_lcs_resolved_key_path resolved = { };
	const u8 *final_sd;
	u32 component_count = 0;
	long fd;
	long ret;

	ret = pkm_lcs_retry_open_components_prepare(
		resolution, &components, &component_count);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components_for_open(
		resolution->parent.source_id, 0,
		resolution->parent.ancestor_guids[0], components,
		component_count, false, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, &resolved);
	if (ret)
		goto out_components;

	if (!resolved.final_frame.data || !resolved.final_sd_len ||
	    (size_t)resolved.final_sd_offset > resolved.final_frame.len ||
	    (size_t)resolved.final_sd_len >
		    resolved.final_frame.len -
			    (size_t)resolved.final_sd_offset) {
		ret = -EIO;
		goto out_resolved;
	}

	final_sd = resolved.final_frame.data + resolved.final_sd_offset;
	fd = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count);
	if (fd < 0) {
		ret = fd;
		goto out_resolved;
	}

	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_retry_open_components_destroy(components);
	return ret;
}

static long pkm_lcs_create_missing_runtime_inputs_validate(
	const struct pkm_lcs_create_missing_runtime_inputs *inputs)
{
	if (!inputs)
		return 0;
	if ((inputs->scope_count && !inputs->scope_guids) ||
	    (inputs->layer_count && !inputs->layers) ||
	    (inputs->private_layer_count && !inputs->private_layers) ||
	    (inputs->metadata_count && !inputs->metadata) ||
	    (inputs->active_key_guid_count && !inputs->active_key_guids) ||
	    (inputs->retired_key_guid_count && !inputs->retired_key_guids))
		return -EINVAL;
	if (inputs->base_metadata_present &&
	    (!inputs->base_metadata_sd || !inputs->base_metadata_sd_len))
		return -EIO;
	return 0;
}

long pkm_lcs_create_missing_user_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition)
{
	static const struct pkm_lcs_create_missing_runtime_inputs empty_inputs;
	struct pkm_lcs_create_preflight_plan preflight = { };
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan target_plan = { };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_key_open_access_plan parent_plan = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_lcs_key_open_access_plan layer_plan = { };
	struct pkm_lcs_key_guid_assignment_plan guid_plan = { };
	struct pkm_lcs_created_key_sd created_sd = { };
	struct pkm_lcs_create_missing_prepared_result prepared = { };
	long ret;

	prepared.fd = -1;
	if (!inputs)
		inputs = &empty_inputs;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;
	ret = pkm_lcs_create_missing_runtime_inputs_validate(inputs);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_parent_for_token(
		token, ops, parent_fd, upath, inputs->scope_guids,
		inputs->scope_count, inputs->layers, inputs->layer_count,
		inputs->private_layers, inputs->private_layer_count,
		&resolution);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_parent_access_check_for_token(
		token, &resolution, &parent_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_volatile_parent_check(&resolution,
							   &preflight);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_symlink_authority_for_token(
		token, &resolution, flags, &link_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_target_prepare(
		ops, ulayer, inputs->layers, inputs->layer_count, &target,
		&target_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_write_access_check_for_token(
		token, &target, inputs->base_metadata_present,
		inputs->base_metadata_sd, inputs->base_metadata_sd_len,
		inputs->metadata, inputs->metadata_count, &layer_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_assign_new_key_guid(
		inputs->active_key_guids, inputs->active_key_guid_count,
		inputs->retired_key_guids, inputs->retired_key_guid_count,
		inputs->generator, &guid_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_create_missing_initial_sd_for_token(
		token, &resolution, &created_sd);
	if (ret)
		goto out_target;

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, guid_plan.guid, &created_sd,
		desired_access, preflight.options.volatile_key,
		preflight.options.symlink, &prepared);
	if (ret)
		goto out_created_sd;

	if (prepared.retry_open_existing) {
		ret = pkm_lcs_create_missing_retry_open_existing_for_token(
			token, ops, &resolution, desired_access,
			inputs->scope_guids, inputs->scope_count,
			inputs->layers, inputs->layer_count,
			inputs->private_layers, inputs->private_layer_count,
			udisposition);
	} else {
		ret = pkm_lcs_create_missing_created_result_finish_to_user(
			ops, udisposition, &prepared);
	}

out_created_sd:
	if (ret && prepared.fd >= 0) {
		close_fd((unsigned int)prepared.fd);
		prepared.fd = -1;
	}
	pkm_lcs_created_key_sd_destroy(&created_sd);
out_target:
	pkm_lcs_create_layer_target_destroy(&target);
out_resolution:
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	return ret;
}

long pkm_lcs_create_missing_copied_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition)
{
	static const struct pkm_lcs_create_missing_runtime_inputs empty_inputs;
	struct pkm_lcs_create_preflight_plan preflight = { };
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan target_plan = { };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_key_open_access_plan parent_plan = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_lcs_key_open_access_plan layer_plan = { };
	struct pkm_lcs_key_guid_assignment_plan guid_plan = { };
	struct pkm_lcs_created_key_sd created_sd = { };
	struct pkm_lcs_create_missing_prepared_result prepared = { };
	long ret;

	prepared.fd = -1;
	if (!inputs)
		inputs = &empty_inputs;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;
	ret = pkm_lcs_create_missing_runtime_inputs_validate(inputs);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_copied_parent_for_token(
		token, parent_fd, copy, inputs->scope_guids,
		inputs->scope_count, inputs->layers, inputs->layer_count,
		inputs->private_layers, inputs->private_layer_count,
		&resolution);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_parent_access_check_for_token(
		token, &resolution, &parent_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_volatile_parent_check(&resolution,
							   &preflight);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_symlink_authority_for_token(
		token, &resolution, flags, &link_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_target_prepare(
		ops, ulayer, inputs->layers, inputs->layer_count, &target,
		&target_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_write_access_check_for_token(
		token, &target, inputs->base_metadata_present,
		inputs->base_metadata_sd, inputs->base_metadata_sd_len,
		inputs->metadata, inputs->metadata_count, &layer_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_assign_new_key_guid(
		inputs->active_key_guids, inputs->active_key_guid_count,
		inputs->retired_key_guids, inputs->retired_key_guid_count,
		inputs->generator, &guid_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_create_missing_initial_sd_for_token(
		token, &resolution, &created_sd);
	if (ret)
		goto out_target;

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, guid_plan.guid, &created_sd,
		desired_access, preflight.options.volatile_key,
		preflight.options.symlink, &prepared);
	if (ret)
		goto out_created_sd;

	if (prepared.retry_open_existing) {
		ret = pkm_lcs_create_missing_retry_open_existing_for_token(
			token, ops, &resolution, desired_access,
			inputs->scope_guids, inputs->scope_count,
			inputs->layers, inputs->layer_count,
			inputs->private_layers, inputs->private_layer_count,
			udisposition);
	} else {
		ret = pkm_lcs_create_missing_created_result_finish_to_user(
			ops, udisposition, &prepared);
	}

out_created_sd:
	if (ret && prepared.fd >= 0) {
		close_fd((unsigned int)prepared.fd);
		prepared.fd = -1;
	}
	pkm_lcs_created_key_sd_destroy(&created_sd);
out_target:
	pkm_lcs_create_layer_target_destroy(&target);
out_resolution:
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	return ret;
}

long pkm_lcs_reg_create_key_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	struct pkm_lcs_syscall_path_copy copy = { };
	long ret;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	ret = pkm_lcs_create_existing_copied_path_finish_for_token(
		token, ops, parent_fd, &copy, desired_access, flags,
		udisposition);
	if (ret == -ENOENT)
		ret = pkm_lcs_create_missing_copied_path_finish_for_token(
			token, ops, parent_fd, &copy, desired_access, ulayer,
			flags, inputs, udisposition);

	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

SYSCALL_DEFINE6(reg_create_key, int, parent_fd, const char __user *, path,
		u32, desired_access, const char __user *, layer, u32, flags,
		u32 __user *, disposition)
{
	return pkm_lcs_reg_create_key_for_token(
		pkm_kacs_current_effective_token_ptr(), NULL, parent_fd, path,
		desired_access, layer, flags, NULL, disposition);
}

static long pkm_lcs_resolved_key_path_prepare(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, struct pkm_lcs_resolved_key_path *result)
{
	u32 i;

	if (!source_id || !root_guid || !components || !result)
		return -EINVAL;
	if (!component_count)
		return -EINVAL;
	if (component_count > PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;

	result->resolved_path = kcalloc(component_count,
					sizeof(*result->resolved_path),
					GFP_KERNEL);
	if (!result->resolved_path)
		return -ENOMEM;
	result->ancestor_guids = kcalloc(component_count,
					 sizeof(*result->ancestor_guids),
					 GFP_KERNEL);
	if (!result->ancestor_guids)
		return -ENOMEM;

	for (i = 0; i < component_count; i++) {
		if (!components[i].name || !components[i].name_len)
			return -EINVAL;
		if (components[i].name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
			return -ENAMETOOLONG;
		result->resolved_path[i] =
			kmemdup_nul(components[i].name,
				    components[i].name_len, GFP_KERNEL);
		if (!result->resolved_path[i])
			return -ENOMEM;
	}

	result->source_id = source_id;
	result->component_count = component_count;
	memcpy(result->ancestor_guids[0], root_guid, RSI_GUID_SIZE);
	pkm_lcs_source_response_frame_init(&result->final_frame);
	return 0;
}

static long pkm_lcs_walk_absolute_components_impl(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link, bool follow_symlinks,
	u32 symlink_depth, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result);

static long pkm_lcs_walk_absolute_components_at_symlink_limit(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_source_response_frame frame;
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;
	u8 current_guid[RSI_GUID_SIZE];
	u64 next_sequence;
	u32 i;
	long ret;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;

	ret = pkm_lcs_resolved_key_path_prepare(source_id, root_guid,
						components, component_count,
						result);
	if (ret)
		goto out_destroy;

	if (component_count == 1) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
			source_id, txn_id, root_guid,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		if (ret)
			goto out_root_frame;

		ret = pkm_lcs_rsi_materialize_read_key_response(
			frame.data, frame.len, response.request_id, &read_key);
		if (ret)
			goto out_root_frame;
		if (!read_key.sd_len ||
		    (size_t)read_key.sd_offset > frame.len ||
		    (size_t)read_key.sd_len >
			    frame.len - (size_t)read_key.sd_offset) {
			ret = -EIO;
			goto out_root_frame;
		}
		if (read_key.symlink && !open_final_link) {
			ret = -ELOOP;
			goto out_root_frame;
		}

		memcpy(result->key_guid, root_guid, sizeof(result->key_guid));
		result->final_sd_offset = read_key.sd_offset;
		result->final_sd_len = read_key.sd_len;
		result->final_volatile = read_key.volatile_key != 0;
		result->final_symlink = read_key.symlink != 0;
		result->final_last_write_time = read_key.last_write_time;
		result->final_frame = frame;
		pkm_lcs_source_response_frame_init(&frame);
		pkm_lcs_source_response_frame_destroy(&frame);
		return 0;
	}

	memcpy(current_guid, root_guid, sizeof(current_guid));
	for (i = 1; i < component_count; i++) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
			source_id, txn_id, current_guid, components[i].name,
			components[i].name_len,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id,
			next_sequence, components[i].name,
			components[i].name_len, active_layers,
			active_layer_count, active_private_layers,
			active_private_layer_count, &child);
		if (ret)
			goto out_destroy_frame;
		if (!child.found) {
			ret = -ENOENT;
			goto out_destroy_frame;
		}
		if (child.symlink && !(open_final_link &&
				       i == component_count - 1U)) {
			ret = -ELOOP;
			goto out_destroy_frame;
		}

		memcpy(result->ancestor_guids[i], child.key_guid,
		       RSI_GUID_SIZE);
		memcpy(current_guid, child.key_guid, sizeof(current_guid));
		if (i == component_count - 1U) {
			memcpy(result->key_guid, child.key_guid,
			       sizeof(result->key_guid));
			result->final_sd_offset = child.sd_offset;
			result->final_sd_len = child.sd_len;
			result->final_volatile = child.volatile_key != 0;
			result->final_symlink = child.symlink != 0;
			result->final_last_write_time = child.last_write_time;
			result->final_frame = frame;
			pkm_lcs_source_response_frame_init(&frame);
		}
out_destroy_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_root_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
out_destroy:
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

static void pkm_lcs_symlink_follow_components_destroy(
	struct pkm_lcs_symlink_follow_components *components)
{
	if (!components)
		return;

	kfree(components->components);
	memset(components, 0, sizeof(*components));
}

static long pkm_lcs_symlink_follow_components_prepare(
	const struct pkm_lcs_materialized_path *target,
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	struct pkm_lcs_symlink_follow_components *result)
{
	size_t total_count;

	if (!target || !target->components || !target->component_count ||
	    !result || (suffix_count && !suffix))
		return -EINVAL;
	if (check_add_overflow((size_t)target->component_count,
			       (size_t)suffix_count, &total_count))
		return -EINVAL;
	if (!total_count || total_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    total_count > U32_MAX)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->components = kcalloc(total_count, sizeof(*result->components),
				     GFP_KERNEL);
	if (!result->components)
		return -ENOMEM;

	memcpy(result->components, target->components,
	       target->component_count * sizeof(*result->components));
	if (suffix_count) {
		memcpy(&result->components[target->component_count], suffix,
		       suffix_count * sizeof(*result->components));
	}
	result->component_count = (u32)total_count;
	return 0;
}

static void
pkm_lcs_owned_path_components_destroy(struct pkm_lcs_owned_path_components *path)
{
	u32 i;

	if (!path)
		return;
	if (path->components) {
		for (i = 0; i < path->component_count; i++)
			kfree(path->components[i].name);
		kfree(path->components);
	}
	memset(path, 0, sizeof(*path));
}

static long pkm_lcs_owned_path_component_copy(
	struct pkm_lcs_path_component_view *dst,
	const struct pkm_lcs_path_component_view *src)
{
	char *name;

	if (!dst || !src || !src->name || !src->name_len)
		return -EINVAL;
	if (src->name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	name = kmemdup_nul(src->name, src->name_len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	dst->name = name;
	dst->name_len = src->name_len;
	return 0;
}

static long pkm_lcs_prepare_owned_symlink_follow_components(
	const struct pkm_lcs_materialized_path *target,
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	struct pkm_lcs_owned_path_components *result)
{
	size_t total_count;
	u32 i;
	long ret;

	if (!target || !target->components || !target->component_count ||
	    !result || (suffix_count && !suffix))
		return -EINVAL;
	if (check_add_overflow((size_t)target->component_count,
			       (size_t)suffix_count, &total_count))
		return -EINVAL;
	if (!total_count || total_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    total_count > U32_MAX)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->components = kcalloc(total_count, sizeof(*result->components),
				     GFP_KERNEL);
	if (!result->components)
		return -ENOMEM;
	result->component_count = (u32)total_count;

	for (i = 0; i < target->component_count; i++) {
		ret = pkm_lcs_owned_path_component_copy(
			&result->components[i], &target->components[i]);
		if (ret)
			goto out_destroy;
	}
	for (i = 0; i < suffix_count; i++) {
		ret = pkm_lcs_owned_path_component_copy(
			&result->components[target->component_count + i],
			&suffix[i]);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_destroy:
	pkm_lcs_owned_path_components_destroy(result);
	return ret;
}

static long pkm_lcs_prepare_absolute_symlink_restart(
	u32 source_id, u64 txn_id, const u8 link_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, u32 *next_source_id,
	u8 next_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_owned_path_components *next_components)
{
	struct pkm_lcs_symlink_target_resolution target = { };
	long ret;

	if (!next_source_id || !next_root_guid || !next_components)
		return -EINVAL;

	ret = pkm_lcs_resolve_symlink_target_for_key(
		source_id, txn_id, link_guid, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		&target);
	if (ret)
		return ret;

	ret = pkm_lcs_prepare_owned_symlink_follow_components(
		&target.components, suffix, suffix_count, next_components);
	if (!ret) {
		*next_source_id = target.route.source_id;
		memcpy(next_root_guid, target.route.root_guid, RSI_GUID_SIZE);
	}

	pkm_lcs_symlink_target_resolution_destroy(&target);
	return ret;
}

static long pkm_lcs_walk_symlink_target(
	u32 source_id, u64 txn_id, const u8 link_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	bool open_final_link, u32 symlink_depth,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_symlink_target_resolution target = { };
	struct pkm_lcs_symlink_follow_components walk = { };
	long ret;

	if (symlink_depth >= PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT)
		return -ELOOP;

	ret = pkm_lcs_resolve_symlink_target_for_key(
		source_id, txn_id, link_guid, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		&target);
	if (ret)
		return ret;

	ret = pkm_lcs_symlink_follow_components_prepare(
		&target.components, suffix, suffix_count, &walk);
	if (ret)
		goto out_destroy_target;

	pkm_lcs_resolved_key_path_destroy(result);
	if (symlink_depth + 1U >= PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT) {
		ret = pkm_lcs_walk_absolute_components_at_symlink_limit(
			target.route.source_id, txn_id, target.route.root_guid,
			walk.components, walk.component_count, open_final_link,
			layers, layer_count, private_layers, private_layer_count,
			result);
	} else {
		ret = pkm_lcs_walk_absolute_components_impl(
			target.route.source_id, txn_id, target.route.root_guid,
			walk.components, walk.component_count, open_final_link,
			true, symlink_depth + 1U, scope_guids, scope_count,
			layers, layer_count, private_layers, private_layer_count,
			result);
	}

	pkm_lcs_symlink_follow_components_destroy(&walk);
out_destroy_target:
	pkm_lcs_symlink_target_resolution_destroy(&target);
	return ret;
}

static long pkm_lcs_walk_absolute_components_impl(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link, bool follow_symlinks,
	u32 symlink_depth, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_owned_path_components owned_components = { };
	struct pkm_lcs_source_response_frame frame;
	const struct pkm_lcs_path_component_view *walk_components = components;
	u8 walk_root_guid[RSI_GUID_SIZE];
	u8 current_guid[RSI_GUID_SIZE];
	u64 next_sequence;
	u32 walk_source_id = source_id;
	u32 walk_component_count = component_count;
	u32 walk_symlink_depth = symlink_depth;
	u32 i;
	long ret;
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;
	memcpy(walk_root_guid, root_guid, RSI_GUID_SIZE);

restart:
	ret = pkm_lcs_resolved_key_path_prepare(walk_source_id, walk_root_guid,
						walk_components,
						walk_component_count,
						result);
	if (ret)
		goto out_destroy;
	if (walk_component_count == 1) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
			walk_source_id, txn_id, walk_root_guid,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		if (ret)
			goto out_root_frame;

		ret = pkm_lcs_rsi_materialize_read_key_response(
			frame.data, frame.len, response.request_id, &read_key);
		if (ret)
			goto out_root_frame;
		if (!read_key.sd_len ||
		    (size_t)read_key.sd_offset > frame.len ||
		    (size_t)read_key.sd_len >
			    frame.len - (size_t)read_key.sd_offset) {
			ret = -EIO;
			goto out_root_frame;
		}
		if (read_key.symlink) {
			if (open_final_link) {
				/* Open the root link key itself. */
			} else if (follow_symlinks) {
				struct pkm_lcs_owned_path_components replacement =
					{ };
				u8 next_root_guid[RSI_GUID_SIZE];
				u32 next_source_id = 0;

				if (walk_symlink_depth >=
				    PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT) {
					ret = -ELOOP;
					goto out_root_frame;
				}
				ret = pkm_lcs_prepare_absolute_symlink_restart(
					walk_source_id, txn_id, walk_root_guid,
					NULL, 0, scope_guids, scope_count,
					active_layers, active_layer_count,
					active_private_layers,
					active_private_layer_count, &next_source_id,
					next_root_guid, &replacement);
				pkm_lcs_source_response_frame_destroy(&frame);
				if (ret)
					goto out_destroy;
				pkm_lcs_resolved_key_path_destroy(result);
				pkm_lcs_owned_path_components_destroy(
					&owned_components);
				owned_components = replacement;
				walk_source_id = next_source_id;
				memcpy(walk_root_guid, next_root_guid,
				       RSI_GUID_SIZE);
				walk_components = owned_components.components;
				walk_component_count =
					owned_components.component_count;
				walk_symlink_depth++;
				goto restart;
			} else {
				ret = -EOPNOTSUPP;
				goto out_root_frame;
			}
		}

		memcpy(result->key_guid, walk_root_guid,
		       sizeof(result->key_guid));
		result->final_sd_offset = read_key.sd_offset;
		result->final_sd_len = read_key.sd_len;
		result->final_volatile = read_key.volatile_key != 0;
		result->final_symlink = read_key.symlink != 0;
		result->final_last_write_time = read_key.last_write_time;
		result->final_frame = frame;
		pkm_lcs_source_response_frame_init(&frame);
		pkm_lcs_source_response_frame_destroy(&frame);
		pkm_lcs_owned_path_components_destroy(&owned_components);
		return 0;
	}

	memcpy(current_guid, walk_root_guid, sizeof(current_guid));
	for (i = 1; i < walk_component_count; i++) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
			walk_source_id, txn_id, current_guid,
			walk_components[i].name, walk_components[i].name_len,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id,
			next_sequence, walk_components[i].name,
			walk_components[i].name_len, active_layers,
			active_layer_count, active_private_layers,
			active_private_layer_count, &child);
		if (ret)
			goto out_destroy_frame;
		if (!child.found) {
			ret = -ENOENT;
			goto out_destroy_frame;
		}
		if (child.symlink) {
			if (open_final_link && i == walk_component_count - 1U) {
				/* Open the link key itself. */
			} else if (follow_symlinks) {
				const struct pkm_lcs_path_component_view *suffix =
					NULL;
				u32 suffix_count = 0;
				struct pkm_lcs_owned_path_components replacement =
					{ };
				u8 next_root_guid[RSI_GUID_SIZE];
				u32 next_source_id = 0;

				if (walk_symlink_depth >=
				    PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT) {
					ret = -ELOOP;
					goto out_destroy_frame;
				}
				if (i + 1U < walk_component_count) {
					suffix = &walk_components[i + 1U];
					suffix_count = walk_component_count - i - 1U;
				}
				ret = pkm_lcs_prepare_absolute_symlink_restart(
					walk_source_id, txn_id, child.key_guid,
					suffix, suffix_count, scope_guids,
					scope_count, active_layers, active_layer_count,
					active_private_layers,
					active_private_layer_count, &next_source_id,
					next_root_guid, &replacement);
				pkm_lcs_source_response_frame_destroy(&frame);
				if (ret)
					goto out_destroy;
				pkm_lcs_resolved_key_path_destroy(result);
				pkm_lcs_owned_path_components_destroy(
					&owned_components);
				owned_components = replacement;
				walk_source_id = next_source_id;
				memcpy(walk_root_guid, next_root_guid,
				       RSI_GUID_SIZE);
				walk_components = owned_components.components;
				walk_component_count =
					owned_components.component_count;
				walk_symlink_depth++;
				goto restart;
			} else {
				ret = -EOPNOTSUPP;
				goto out_destroy_frame;
			}
		}

		memcpy(result->ancestor_guids[i], child.key_guid,
		       RSI_GUID_SIZE);
		memcpy(current_guid, child.key_guid, sizeof(current_guid));
		if (i == walk_component_count - 1U) {
			memcpy(result->key_guid, child.key_guid,
			       sizeof(result->key_guid));
			result->final_sd_offset = child.sd_offset;
			result->final_sd_len = child.sd_len;
			result->final_volatile = child.volatile_key != 0;
			result->final_symlink = child.symlink != 0;
			result->final_last_write_time = child.last_write_time;
			result->final_frame = frame;
			pkm_lcs_source_response_frame_init(&frame);
		}
out_destroy_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		if (ret)
			goto out_destroy;
	}

	pkm_lcs_owned_path_components_destroy(&owned_components);
	return 0;

out_root_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
out_destroy:
	pkm_lcs_owned_path_components_destroy(&owned_components);
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

long pkm_lcs_walk_absolute_components_for_open(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	return pkm_lcs_walk_absolute_components_impl(
		source_id, txn_id, root_guid, components, component_count,
		open_final_link, true, 0, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, result);
}

long pkm_lcs_walk_absolute_components(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	return pkm_lcs_walk_absolute_components_impl(
		source_id, txn_id, root_guid, components, component_count,
		false, false, 0, NULL, 0, layers, layer_count, private_layers,
		private_layer_count, result);
}

static long pkm_lcs_resolved_key_path_prepare_relative(
	const struct pkm_lcs_key_fd_parent_snapshot *parent,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, struct pkm_lcs_resolved_key_path *result)
{
	size_t total_count;
	size_t guid_bytes;
	u32 parent_count;
	u32 i;
	long ret;

	if (!parent || !components || !result || !parent->source_id ||
	    !parent->path_component_count || !parent->resolved_path ||
	    !parent->ancestor_guids || !component_count)
		return -EINVAL;
	if (parent->orphaned)
		return -ENOENT;
	if (check_add_overflow((size_t)parent->path_component_count,
			       (size_t)component_count, &total_count))
		return -EINVAL;
	if (!total_count || total_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    total_count > U32_MAX)
		return -EINVAL;

	parent_count = parent->path_component_count;
	result->source_id = parent->source_id;
	result->component_count = (u32)total_count;
	pkm_lcs_source_response_frame_init(&result->final_frame);

	result->resolved_path = kcalloc(total_count,
					sizeof(*result->resolved_path),
					GFP_KERNEL);
	if (!result->resolved_path)
		return -ENOMEM;
	result->ancestor_guids = kcalloc(total_count,
					 sizeof(*result->ancestor_guids),
					 GFP_KERNEL);
	if (!result->ancestor_guids)
		goto out_nomem;

	if (check_mul_overflow((size_t)parent_count,
			       sizeof(*result->ancestor_guids), &guid_bytes)) {
		ret = -EINVAL;
		goto out_error;
	}
	memcpy(result->ancestor_guids, parent->ancestor_guids, guid_bytes);

	for (i = 0; i < parent_count; i++) {
		if (!parent->resolved_path[i]) {
			ret = -EINVAL;
			goto out_error;
		}
		result->resolved_path[i] =
			kstrdup(parent->resolved_path[i], GFP_KERNEL);
		if (!result->resolved_path[i])
			goto out_nomem;
	}

	for (i = 0; i < component_count; i++) {
		u32 path_index = parent_count + i;

		if (!components[i].name || !components[i].name_len) {
			ret = -EINVAL;
			goto out_error;
		}
		if (components[i].name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD) {
			ret = -ENAMETOOLONG;
			goto out_error;
		}
		result->resolved_path[path_index] =
			kmemdup_nul(components[i].name,
				    components[i].name_len, GFP_KERNEL);
		if (!result->resolved_path[path_index])
			goto out_nomem;
	}

	return 0;

out_nomem:
	pkm_lcs_resolved_key_path_destroy(result);
	return -ENOMEM;
out_error:
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

static long pkm_lcs_walk_relative_components_impl(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link, bool follow_symlinks,
	u32 symlink_depth, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_source_response_frame frame;
	u8 current_guid[RSI_GUID_SIZE];
	u64 next_sequence;
	u32 parent_count;
	u32 i;
	long ret;
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;

	ret = pkm_lcs_resolved_key_path_prepare_relative(
		parent, components, component_count, result);
	if (ret)
		goto out_destroy;

	parent_count = parent->path_component_count;
	memcpy(current_guid, parent->key_guid, sizeof(current_guid));
	for (i = 0; i < component_count; i++) {
		u32 path_index = parent_count + i;

		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
			parent->source_id, txn_id, current_guid,
			components[i].name, components[i].name_len,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id,
			next_sequence, components[i].name,
			components[i].name_len, active_layers,
			active_layer_count, active_private_layers,
			active_private_layer_count, &child);
		if (ret)
			goto out_destroy_frame;
		if (!child.found) {
			ret = -ENOENT;
			goto out_destroy_frame;
		}
		if (child.symlink) {
			if (open_final_link && i == component_count - 1U) {
				/* Open the link key itself. */
			} else if (follow_symlinks) {
				const struct pkm_lcs_path_component_view *suffix =
					NULL;
				u32 suffix_count = 0;

				if (i + 1U < component_count) {
					suffix = &components[i + 1U];
					suffix_count = component_count - i - 1U;
				}
				ret = pkm_lcs_walk_symlink_target(
					parent->source_id, txn_id, child.key_guid,
					suffix, suffix_count, open_final_link,
					symlink_depth, scope_guids, scope_count,
					active_layers, active_layer_count,
					active_private_layers,
					active_private_layer_count, result);
				pkm_lcs_source_response_frame_destroy(&frame);
				if (ret)
					goto out_destroy;
				return 0;
			} else {
				ret = -EOPNOTSUPP;
				goto out_destroy_frame;
			}
		}

		memcpy(result->ancestor_guids[path_index], child.key_guid,
		       RSI_GUID_SIZE);
		memcpy(current_guid, child.key_guid, sizeof(current_guid));
		if (i == component_count - 1U) {
			memcpy(result->key_guid, child.key_guid,
			       sizeof(result->key_guid));
			result->final_sd_offset = child.sd_offset;
			result->final_sd_len = child.sd_len;
			result->final_volatile = child.volatile_key != 0;
			result->final_symlink = child.symlink != 0;
			result->final_last_write_time = child.last_write_time;
			result->final_frame = frame;
			pkm_lcs_source_response_frame_init(&frame);
		}
out_destroy_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_destroy:
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

long pkm_lcs_walk_relative_components_for_open(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	return pkm_lcs_walk_relative_components_impl(
		parent, txn_id, components, component_count, open_final_link,
		true, 0, scope_guids, scope_count, layers, layer_count,
		private_layers, private_layer_count, result);
}

long pkm_lcs_walk_relative_components(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	return pkm_lcs_walk_relative_components_impl(
		parent, txn_id, components, component_count, false, false, 0, NULL,
		0, layers, layer_count, private_layers, private_layer_count,
		result);
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

	return pkm_lcs_source_device_read_file_with_ops(
		file, buf, count, (file->f_flags & O_NONBLOCK) != 0,
		&pkm_lcs_default_copyout_ops);
}

static ssize_t pkm_lcs_source_device_write(struct file *file,
					   const char __user *buf,
					   size_t count, loff_t *ppos)
{
	(void)ppos;

	return pkm_lcs_source_device_write_file_with_ops(
		file, buf, count, &pkm_lcs_default_copyin_ops, NULL);
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

	mutex_lock(&pkm_lcs_source_table_lock);
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
	mutex_unlock(&pkm_lcs_source_table_lock);
	return mask;
}

static long pkm_lcs_source_device_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	switch (cmd) {
	case REG_SRC_REGISTER:
		return pkm_lcs_source_register_file_for_token(
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
void pkm_lcs_kunit_reset_source_table(void)
{
	u32 i;

	mutex_lock(&pkm_lcs_source_table_lock);
	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT; i++) {
		pkm_lcs_source_hives_destroy(pkm_lcs_source_slots[i].hives,
					     pkm_lcs_source_slots[i].hive_count);
		memset(&pkm_lcs_source_slots[i], 0,
		       sizeof(pkm_lcs_source_slots[i]));
	}
	pkm_lcs_sequence_initialized = false;
	pkm_lcs_next_sequence = 0;
	mutex_unlock(&pkm_lcs_source_table_lock);
}

void pkm_lcs_kunit_set_sequence_state(bool initialized, u64 next_sequence)
{
	mutex_lock(&pkm_lcs_source_table_lock);
	pkm_lcs_sequence_initialized = initialized;
	pkm_lcs_next_sequence = next_sequence;
	mutex_unlock(&pkm_lcs_source_table_lock);
}

void pkm_lcs_kunit_source_table_snapshot(
	struct pkm_lcs_source_table_snapshot *snapshot)
{
	u32 i;

	if (!snapshot)
		return;

	memset(snapshot, 0, sizeof(*snapshot));
	mutex_lock(&pkm_lcs_source_table_lock);
	for (i = 0; i < PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT; i++) {
		struct pkm_lcs_source_slot *slot = &pkm_lcs_source_slots[i];

		if (!slot->occupied)
			continue;
		snapshot->occupied_count++;
		if (slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE)
			snapshot->active_count++;
		if (slot->status == PKM_LCS_SOURCE_SLOT_STATUS_DOWN)
			snapshot->down_count++;
	}
	snapshot->sequence_initialized = pkm_lcs_sequence_initialized;
	snapshot->next_sequence = pkm_lcs_next_sequence;
	mutex_unlock(&pkm_lcs_source_table_lock);
}

void pkm_lcs_kunit_source_fd_snapshot(
	struct file *file, struct pkm_lcs_source_fd_snapshot *snapshot)
{
	struct pkm_lcs_source_fd *source_fd;

	if (!snapshot)
		return;

	memset(snapshot, 0, sizeof(*snapshot));
	if (!file)
		return;

	source_fd = file->private_data;
	if (!source_fd)
		return;

	mutex_lock(&source_fd->queue_lock);
	snapshot->state = source_fd->state;
	snapshot->source_id = source_fd->source_id;
	snapshot->queued_request_count = source_fd->queued_request_count;
	snapshot->in_flight_request_count =
		source_fd->in_flight_request_count;
	snapshot->next_request_id = source_fd->next_request_id;
	snapshot->closing = source_fd->closing;
	mutex_unlock(&source_fd->queue_lock);
}

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

__poll_t pkm_lcs_kunit_source_device_poll_file(struct file *file)
{
	return pkm_lcs_source_device_poll(file, NULL);
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

	ret = misc_register(&pkm_lcs_source_device);
	if (ret)
		pr_err("pkm: /dev/pkm_registry registration failed (%d)\n",
		       ret);

	return ret;
}
late_initcall(pkm_lcs_source_device_init);
