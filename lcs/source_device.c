// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source-device entrypoint.
 *
 * PSD-005 requires sources to obtain RSI fds through /dev/pkm_registry and
 * requires the open path to be gated by SeTcbPrivilege before any source fd is
 * issued.
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/lockdep.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "source_device.h"

#define PKM_LCS_MAX_HIVE_NAME_BYTES_HARD 1024U
#define PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT 32U
#define PKM_LCS_MAX_HIVES_PER_SOURCE_DEFAULT 64U

struct pkm_lcs_source_slot {
	bool occupied;
	u32 status;
	u32 source_id;
	u32 hive_count;
	struct pkm_lcs_source_registration_hive_copy *hives;
	struct pkm_lcs_source_fd *active_fd;
	u64 source_next_sequence;
};

static DEFINE_MUTEX(pkm_lcs_source_table_lock);
static struct pkm_lcs_source_slot
	pkm_lcs_source_slots[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
static bool pkm_lcs_sequence_initialized;
static u64 pkm_lcs_next_sequence;

static bool pkm_lcs_default_copy_from_user(void *ctx, void *dst,
					   const void __user *src, size_t len)
{
	(void)ctx;

	return copy_from_user(dst, src, len) == 0;
}

static const struct pkm_lcs_usercopy_ops pkm_lcs_default_usercopy_ops = {
	.read = pkm_lcs_default_copy_from_user,
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
	source_fd->state = PKM_LCS_SOURCE_FD_UNREGISTERED;
	source_fd->source_id = 0;

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
	if (source_fd->state == PKM_LCS_SOURCE_FD_ACTIVE) {
		slot = pkm_lcs_source_slot_find_locked(source_fd->source_id);
		if (slot && slot->status == PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE &&
		    slot->active_fd == source_fd) {
			slot->status = PKM_LCS_SOURCE_SLOT_STATUS_DOWN;
			slot->active_fd = NULL;
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

static int pkm_lcs_source_device_open(struct inode *inode, struct file *file)
{
	return pkm_lcs_source_device_open_file_for_token(
		pkm_kacs_current_effective_token_ptr(), file);
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
