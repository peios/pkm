// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source registration input ownership and validation.
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "key_fd.h"
#include "source_device.h"
#include "source_internal.h"

struct pkm_lcs_source_registration_result {
	u32 source_id;
	u32 resumed_source_id;
};

struct pkm_lcs_source_bootstrap_work {
	struct work_struct work;
	u32 source_id;
	u8 machine_root_guid[RSI_GUID_SIZE];
};

/*
 * Dedicated workqueue for source bootstrap refresh. Using our own queue lets
 * KUnit flush exactly this work instead of the shared system-wide queue
 * (which flush_scheduled_work() discourages). Allocated at init on this
 * built-in subsystem and never torn down on the success path (there is no
 * module unload path).
 */
static struct workqueue_struct *pkm_lcs_bootstrap_wq;

extern int lcs_rust_validate_source_registration(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_registration_hive_copy *hives,
	size_t hive_count, u64 max_sequence, bool caller_has_tcb,
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	bool current_next_sequence_valid, u64 current_next_sequence,
	struct pkm_lcs_source_registration_plan_copy *plan);
extern int lcs_rust_validate_source_registration_empty(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_registration_hive_copy *hives,
	size_t hive_count, u64 max_sequence, bool caller_has_tcb,
	struct pkm_lcs_source_registration_plan_copy *plan);

void pkm_lcs_source_hives_destroy(
	struct pkm_lcs_source_registration_hive_copy *hives, u32 hive_count)
{
	u32 i;

	if (!hives)
		return;

	for (i = 0; i < hive_count; i++)
		kfree(hives[i].name);
	kfree(hives);
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
		ops = pkm_lcs_default_usercopy_ops();
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
	struct pkm_lcs_runtime_limits limits;

	if (!registration || !plan)
		return -EINVAL;
	if (registration->hive_count && !registration->hives)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return lcs_rust_validate_source_registration_empty(
		&limits, registration->hives, registration->hive_count,
		registration->max_sequence, caller_has_tcb, plan);
}

static long pkm_lcs_source_registration_publish_locked(
	struct pkm_lcs_source_fd *source_fd,
	struct pkm_lcs_source_registration_copy *registration,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_registration_result *result)
{
	struct pkm_lcs_source_slot_view_buffer view_buffer;
	struct pkm_lcs_source_registration_plan_copy plan = { };
	struct pkm_lcs_source_slot *slot;
	bool sequence_initialized;
	u64 next_sequence;
	u32 slot_count;
	u32 i;
	long ret;

	pkm_lcs_source_table_assert_locked();

	if (!source_fd || !registration || !limits)
		return -EINVAL;
	if (source_fd->state != PKM_LCS_SOURCE_FD_UNREGISTERED)
		return -EINVAL;
	if (result)
		memset(result, 0, sizeof(*result));

	pkm_lcs_source_slot_view_buffer_init(&view_buffer);
	ret = pkm_lcs_source_slot_view_buffer_prepare_locked(&view_buffer,
							     &slot_count);
	if (ret)
		return ret;
	pkm_lcs_source_table_sequence_snapshot_locked(&sequence_initialized,
						      &next_sequence);
	ret = lcs_rust_validate_source_registration(
		limits, registration->hives, registration->hive_count,
		registration->max_sequence, true, view_buffer.views, slot_count,
		sequence_initialized, next_sequence, &plan);
	if (ret)
		goto out_views;

	switch (plan.decision) {
	case PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW:
		slot = pkm_lcs_source_slot_free_locked();
		if (!slot) {
			ret = -ENOSPC;
			goto out_views;
		}

		for (i = 0; i < registration->hive_count; i++)
			registration->hives[i].hive_generation =
				registration->max_sequence;

		slot->occupied = true;
		slot->status = PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE;
		slot->source_id = pkm_lcs_source_slot_id(slot);
		slot->hive_count = registration->hive_count;
		slot->hives = registration->hives;
		slot->active_fd = source_fd;
		INIT_LIST_HEAD(&slot->pending_layer_deletes);
		slot->source_next_sequence = plan.source_next_sequence;
		slot->restart_generation = 0;
		slot->pending_layer_delete_count = 0;
		registration->hives = NULL;
		registration->hive_count = 0;
		break;
	case PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN:
		slot = pkm_lcs_source_slot_find_locked(plan.source_id);
		if (!slot || slot->status != PKM_LCS_SOURCE_SLOT_STATUS_DOWN) {
			ret = -EINVAL;
			goto out_views;
		}
		if (slot->restart_generation == U64_MAX) {
			ret = -EOVERFLOW;
			goto out_views;
		}

		slot->status = PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE;
		slot->active_fd = source_fd;
		slot->source_next_sequence = plan.source_next_sequence;
		slot->restart_generation++;
		if (result)
			result->resumed_source_id = slot->source_id;
		break;
	default:
		ret = -EINVAL;
		goto out_views;
	}

	source_fd->state = PKM_LCS_SOURCE_FD_ACTIVE;
	source_fd->source_id = slot->source_id;
	if (result)
		result->source_id = slot->source_id;
	pkm_lcs_source_table_sequence_set_locked(true,
						 plan.effective_next_sequence);
	wake_up_interruptible(&source_fd->read_wait);
	ret = 0;

out_views:
	pkm_lcs_source_slot_view_buffer_destroy(&view_buffer);
	return ret;
}

static bool pkm_lcs_source_registration_hive_is_global_machine(
	const struct pkm_lcs_source_registration_hive_copy *hive)
{
	static const char machine_name[] = "Machine";

	if (!hive || !hive->name)
		return false;
	if (hive->flags)
		return false;
	if (hive->name_len != sizeof(machine_name) - 1)
		return false;

	return !strncasecmp(hive->name, machine_name, sizeof(machine_name) - 1);
}

static const struct pkm_lcs_source_registration_hive_copy *
pkm_lcs_source_registration_find_global_machine(
	const struct pkm_lcs_source_registration_copy *registration)
{
	u32 i;

	if (!registration || !registration->hives)
		return NULL;

	for (i = 0; i < registration->hive_count; i++) {
		if (pkm_lcs_source_registration_hive_is_global_machine(
			    &registration->hives[i]))
			return &registration->hives[i];
	}
	return NULL;
}

static void pkm_lcs_source_bootstrap_workfn(struct work_struct *work)
{
	struct pkm_lcs_source_bootstrap_work *bootstrap_work =
		container_of(work, struct pkm_lcs_source_bootstrap_work, work);
	struct pkm_lcs_source_bootstrap_refresh_result *result;

	/*
	 * The refresh result is unused here, but the call requires it. Keep it
	 * off the stack (the struct is ~2 KB); on allocation failure skip this
	 * best-effort background refresh rather than overflow the stack.
	 */
	result = kzalloc(sizeof(*result), GFP_KERNEL);
	if (result) {
		(void)pkm_lcs_source_bootstrap_refresh_machine_hive(
			bootstrap_work->source_id,
			bootstrap_work->machine_root_guid, result);
		kfree(result);
	}
	kfree(bootstrap_work);
}

static long pkm_lcs_source_bootstrap_work_prepare(
	const struct pkm_lcs_source_registration_copy *registration,
	struct pkm_lcs_source_bootstrap_work **work_out)
{
	const struct pkm_lcs_source_registration_hive_copy *machine;
	struct pkm_lcs_source_bootstrap_work *work;

	if (!work_out)
		return -EINVAL;
	*work_out = NULL;

	machine = pkm_lcs_source_registration_find_global_machine(registration);
	if (!machine)
		return 0;

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;
	memcpy(work->machine_root_guid, machine->root_guid,
	       sizeof(work->machine_root_guid));
	work->source_id = 0;
	*work_out = work;
	return 0;
}

static long pkm_lcs_source_register_file_for_token_core(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs, bool queue_bootstrap)
{
	struct pkm_lcs_source_registration_copy registration = { };
	struct pkm_lcs_source_registration_result publish = { };
	struct pkm_lcs_source_bootstrap_work *bootstrap_work = NULL;
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_source_fd *source_fd;
	long ret;

	if (!file)
		return -EINVAL;
	source_fd = file->private_data;
	if (!source_fd)
		return -EINVAL;

	pkm_lcs_source_table_lock();
	if (source_fd->state != PKM_LCS_SOURCE_FD_UNREGISTERED) {
		pkm_lcs_source_table_unlock();
		return -EINVAL;
	}
	pkm_lcs_source_table_unlock();

	ret = pkm_lcs_source_device_check_tcb(token);
	if (ret)
		return ret;
	ret = pkm_lcs_source_device_mark_tcb_used(token);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_source_registration_copy_from_user(
		ops, uargs, limits.max_hives_per_source, &registration);
	if (ret)
		return ret;

	if (queue_bootstrap) {
		ret = pkm_lcs_source_bootstrap_work_prepare(&registration,
							    &bootstrap_work);
		if (ret)
			goto out_registration;
	}

	pkm_lcs_source_sequence_gate_lock();
	pkm_lcs_source_table_lock();
	ret = pkm_lcs_source_registration_publish_locked(source_fd,
							&registration, &limits,
							&publish);
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_sequence_gate_unlock();
	if (ret)
		goto out_bootstrap;

	if (publish.resumed_source_id) {
		u32 watch_count = 0;

		ret = pkm_lcs_source_replay_pending_layer_deletes_with_limits(
			publish.resumed_source_id, &limits);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(publish.resumed_source_id);
			ret = -EIO;
			goto out_bootstrap;
		}

		ret = pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
			publish.resumed_source_id, &limits, &watch_count);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(publish.resumed_source_id);
			ret = -EIO;
			goto out_bootstrap;
		}
	}

	if (bootstrap_work) {
		bootstrap_work->source_id = publish.source_id;
		INIT_WORK(&bootstrap_work->work, pkm_lcs_source_bootstrap_workfn);
		queue_work(pkm_lcs_bootstrap_wq, &bootstrap_work->work);
		bootstrap_work = NULL;
	}

out_bootstrap:
	kfree(bootstrap_work);
out_registration:
	pkm_lcs_source_registration_copy_destroy(&registration);
	return ret;
}

long pkm_lcs_source_register_file_for_token(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs)
{
	return pkm_lcs_source_register_file_for_token_core(token, file, ops,
							   uargs, false);
}

long pkm_lcs_source_register_file_for_token_with_bootstrap(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs)
{
	return pkm_lcs_source_register_file_for_token_core(token, file, ops,
							   uargs, true);
}

long pkm_lcs_source_bootstrap_workqueue_init(void)
{
	pkm_lcs_bootstrap_wq = alloc_workqueue("pkm_lcs_bootstrap", 0, 0);
	if (!pkm_lcs_bootstrap_wq)
		return -ENOMEM;
	return 0;
}

void pkm_lcs_source_bootstrap_workqueue_destroy(void)
{
	destroy_workqueue(pkm_lcs_bootstrap_wq);
	pkm_lcs_bootstrap_wq = NULL;
}

void pkm_lcs_source_bootstrap_workqueue_flush(void)
{
	flush_workqueue(pkm_lcs_bootstrap_wq);
}
