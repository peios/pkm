// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS transaction-fd carrier.
 *
 * reg_begin_transaction() is source-agnostic: the fd holds a monotonic
 * transaction ID and remains unbound until a later mutating operation.
 */

#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <pkm/lcs.h>

#include "key_fd.h"
#include "rsi.h"
#include "transaction_fd.h"
#include "source_device.h"

struct pkm_lcs_transaction_fd {
	u64 transaction_id;
	u64 next_operation_index;
	u32 state;
	u32 bound_source_id;
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	spinlock_t lock;
	struct mutex bind_lock;
	wait_queue_head_t wait;
	struct timer_list timeout_timer;
	struct work_struct timeout_work;
	struct list_head registry_link;
	struct list_head mutation_log;
	u32 mutation_log_entries;
	u32 mutation_log_capacity;
	bool commit_in_flight;
	bool timeout_abort_pending;
	bool registry_linked;
	bool fd_released;
};

struct pkm_lcs_transaction_key_create_log {
	u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u8 target_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u64 sequence;
	char *child_name;
	char *layer;
	char **parent_path;
	u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 child_name_len;
	u32 layer_len;
	u32 parent_depth;
};

struct pkm_lcs_transaction_set_security_log {
	u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	char **path;
	u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 depth;
};

struct pkm_lcs_transaction_set_value_log {
	u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u64 sequence;
	char *value_name;
	char *layer;
	char **path;
	u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 value_name_len;
	u32 layer_len;
	u32 depth;
};

struct pkm_lcs_transaction_delete_value_log {
	u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 event_type;
	char *value_name;
	char *layer;
	char **path;
	u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 value_name_len;
	u32 layer_len;
	u32 depth;
};

struct pkm_lcs_transaction_delete_key_log {
	u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	char *child_name;
	char *layer;
	char **parent_path;
	u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 child_name_len;
	u32 layer_len;
	u32 parent_depth;
};

struct pkm_lcs_transaction_hide_key_log {
	u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u64 sequence;
	char *child_name;
	char *layer;
	char **parent_path;
	u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 child_name_len;
	u32 layer_len;
	u32 parent_depth;
};

struct pkm_lcs_transaction_log_entry {
	struct list_head link;
	u64 operation_index;
	u32 kind;
	union {
		struct pkm_lcs_transaction_key_create_log create_key;
		struct pkm_lcs_transaction_set_security_log set_security;
		struct pkm_lcs_transaction_set_value_log set_value;
		struct pkm_lcs_transaction_delete_value_log delete_value;
		struct pkm_lcs_transaction_delete_key_log delete_key;
		struct pkm_lcs_transaction_hide_key_log hide_key;
	};
};

static DEFINE_MUTEX(pkm_lcs_transaction_id_lock);
static u64 pkm_lcs_next_transaction_id = 1;
static DEFINE_MUTEX(pkm_lcs_transaction_registry_lock);
static LIST_HEAD(pkm_lcs_transaction_registry);

static const struct file_operations pkm_lcs_transaction_fd_fops;
static long pkm_lcs_transaction_fd_complete_first_bind_from_state(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES]);

static unsigned long pkm_lcs_transaction_deadline_from_timeout_ms(
	u32 timeout_ms)
{
	unsigned long delta = msecs_to_jiffies(timeout_ms);

	if (timeout_ms && !delta)
		delta = 1;
	return jiffies + delta;
}

static bool pkm_lcs_transaction_state_active(u32 state)
{
	return state == REG_TXN_ACTIVE_UNBOUND ||
	       state == REG_TXN_ACTIVE_BOUND;
}

static long pkm_lcs_transaction_terminal_errno(u32 state, s32 *errno_out)
{
	if (!errno_out)
		return -EINVAL;

	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
	case REG_TXN_ACTIVE_BOUND:
	case REG_TXN_COMMITTED:
		*errno_out = 0;
		return 0;
	case REG_TXN_ABORTED:
		*errno_out = EINVAL;
		return 0;
	case REG_TXN_TIMED_OUT:
		*errno_out = ETIMEDOUT;
		return 0;
	case REG_TXN_SOURCE_DOWN:
		*errno_out = EIO;
		return 0;
	default:
		*errno_out = 0;
		return -EIO;
	}
}

static long pkm_lcs_transaction_id_allocate(u64 *transaction_id)
{
	long ret = 0;

	if (!transaction_id)
		return -EINVAL;
	*transaction_id = 0;

	mutex_lock(&pkm_lcs_transaction_id_lock);
	if (!pkm_lcs_next_transaction_id ||
	    pkm_lcs_next_transaction_id == U64_MAX) {
		ret = -EOVERFLOW;
		goto out_unlock;
	}

	*transaction_id = pkm_lcs_next_transaction_id++;

out_unlock:
	mutex_unlock(&pkm_lcs_transaction_id_lock);
	return ret;
}

static bool pkm_lcs_transaction_root_guid_valid(
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	u32 i;

	if (!root_guid)
		return false;

	for (i = 0; i < PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES; i++) {
		if (root_guid[i])
			return true;
	}
	return false;
}

static void
pkm_lcs_transaction_fd_registry_add(struct pkm_lcs_transaction_fd *txn)
{
	if (!txn)
		return;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	if (!txn->registry_linked) {
		list_add_tail(&txn->registry_link, &pkm_lcs_transaction_registry);
		txn->registry_linked = true;
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);
}

static void
pkm_lcs_transaction_fd_registry_remove(struct pkm_lcs_transaction_fd *txn)
{
	if (!txn)
		return;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	if (txn->registry_linked) {
		list_del_init(&txn->registry_link);
		txn->registry_linked = false;
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);
}

static bool pkm_lcs_transaction_name_len_valid(size_t len)
{
	return len && len <= U16_MAX;
}

static bool pkm_lcs_transaction_value_name_len_valid(size_t len)
{
	return len <= U16_MAX;
}

static void pkm_lcs_transaction_key_create_log_destroy(
	struct pkm_lcs_transaction_key_create_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->child_name);
	kfree(entry->layer);
	if (entry->parent_path) {
		for (i = 0; i < entry->parent_depth; i++)
			kfree(entry->parent_path[i]);
		kfree(entry->parent_path);
	}
	kfree(entry->parent_ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_set_security_log_destroy(
	struct pkm_lcs_transaction_set_security_log *entry)
{
	u32 i;

	if (!entry)
		return;

	if (entry->path) {
		for (i = 0; i < entry->depth; i++)
			kfree(entry->path[i]);
		kfree(entry->path);
	}
	kfree(entry->ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_set_value_log_destroy(
	struct pkm_lcs_transaction_set_value_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->value_name);
	kfree(entry->layer);
	if (entry->path) {
		for (i = 0; i < entry->depth; i++)
			kfree(entry->path[i]);
		kfree(entry->path);
	}
	kfree(entry->ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_delete_value_log_destroy(
	struct pkm_lcs_transaction_delete_value_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->value_name);
	kfree(entry->layer);
	if (entry->path) {
		for (i = 0; i < entry->depth; i++)
			kfree(entry->path[i]);
		kfree(entry->path);
	}
	kfree(entry->ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_delete_key_log_destroy(
	struct pkm_lcs_transaction_delete_key_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->child_name);
	kfree(entry->layer);
	if (entry->parent_path) {
		for (i = 0; i < entry->parent_depth; i++)
			kfree(entry->parent_path[i]);
		kfree(entry->parent_path);
	}
	kfree(entry->parent_ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_hide_key_log_destroy(
	struct pkm_lcs_transaction_hide_key_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->child_name);
	kfree(entry->layer);
	if (entry->parent_path) {
		for (i = 0; i < entry->parent_depth; i++)
			kfree(entry->parent_path[i]);
		kfree(entry->parent_path);
	}
	kfree(entry->parent_ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_log_entry_destroy(
	struct pkm_lcs_transaction_log_entry *entry)
{
	if (!entry)
		return;

	switch (entry->kind) {
	case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		pkm_lcs_transaction_key_create_log_destroy(
			&entry->create_key);
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		pkm_lcs_transaction_set_security_log_destroy(
			&entry->set_security);
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
		pkm_lcs_transaction_set_value_log_destroy(&entry->set_value);
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
		pkm_lcs_transaction_delete_value_log_destroy(
			&entry->delete_value);
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
		pkm_lcs_transaction_delete_key_log_destroy(
			&entry->delete_key);
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
		pkm_lcs_transaction_hide_key_log_destroy(&entry->hide_key);
		break;
	default:
		break;
	}
	kfree(entry);
}

static void pkm_lcs_transaction_log_clear(
	struct pkm_lcs_transaction_fd *txn)
{
	struct pkm_lcs_transaction_log_entry *entry;
	struct pkm_lcs_transaction_log_entry *tmp;

	if (!txn)
		return;

	list_for_each_entry_safe(entry, tmp, &txn->mutation_log, link) {
		list_del(&entry->link);
		pkm_lcs_transaction_log_entry_destroy(entry);
	}
	txn->mutation_log_entries = 0;
}

static void pkm_lcs_transaction_fd_destroy(
	struct pkm_lcs_transaction_fd *txn)
{
	if (!txn)
		return;

	pkm_lcs_transaction_log_clear(txn);
	kfree(txn);
}

static long pkm_lcs_transaction_dup_path_components(
	const char * const *src, u32 count, char ***out)
{
	char **copy;
	u32 i;

	if (!out || !count || !src)
		return -EINVAL;
	*out = NULL;

	copy = kcalloc(count, sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		size_t len;

		if (!src[i])
			goto out_inval;
		len = strnlen(src[i], U16_MAX + 1UL);
		if (!pkm_lcs_transaction_name_len_valid(len))
			goto out_inval;
		copy[i] = kstrndup(src[i], len, GFP_KERNEL);
		if (!copy[i])
			goto out_nomem;
	}

	*out = copy;
	return 0;

out_nomem:
	for (i = 0; i < count; i++)
		kfree(copy[i]);
	kfree(copy);
	return -ENOMEM;
out_inval:
	for (i = 0; i < count; i++)
		kfree(copy[i]);
	kfree(copy);
	return -EINVAL;
}

static long pkm_lcs_transaction_key_create_log_alloc(
	const struct pkm_lcs_transaction_key_create_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->parent_guid || !input->target_guid ||
	    !input->child_name || !input->layer || !input->parent_path ||
	    !input->parent_ancestor_guids || !input->parent_depth ||
	    !input->sequence ||
	    !pkm_lcs_transaction_name_len_valid(input->child_name_len) ||
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (input->parent_depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY;
	memcpy(entry->create_key.parent_guid, input->parent_guid,
	       sizeof(entry->create_key.parent_guid));
	memcpy(entry->create_key.target_guid, input->target_guid,
	       sizeof(entry->create_key.target_guid));
	entry->create_key.sequence = input->sequence;
	entry->create_key.parent_depth = input->parent_depth;
	entry->create_key.child_name_len = (u32)input->child_name_len;
	entry->create_key.layer_len = (u32)input->layer_len;

	entry->create_key.child_name =
		kmemdup_nul(input->child_name, input->child_name_len,
			    GFP_KERNEL);
	if (!entry->create_key.child_name) {
		ret = -ENOMEM;
		goto out_free;
	}
	entry->create_key.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->create_key.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->parent_path, input->parent_depth,
		&entry->create_key.parent_path);
	if (ret)
		goto out_free;

	if (check_mul_overflow((size_t)input->parent_depth,
			       sizeof(*entry->create_key.parent_ancestor_guids),
			       &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->create_key.parent_ancestor_guids =
		kmemdup(input->parent_ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->create_key.parent_ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->create_key.parent_ancestor_guids[input->parent_depth - 1],
		   entry->create_key.parent_guid,
		   sizeof(entry->create_key.parent_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static long pkm_lcs_transaction_set_security_log_alloc(
	const struct pkm_lcs_transaction_set_security_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->key_guid || !input->path ||
	    !input->ancestor_guids || !input->depth)
		return -EINVAL;
	if (input->depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY;
	memcpy(entry->set_security.key_guid, input->key_guid,
	       sizeof(entry->set_security.key_guid));
	entry->set_security.depth = input->depth;

	ret = pkm_lcs_transaction_dup_path_components(
		input->path, input->depth, &entry->set_security.path);
	if (ret)
		goto out_free;

	if (check_mul_overflow((size_t)input->depth,
			       sizeof(*entry->set_security.ancestor_guids),
			       &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->set_security.ancestor_guids =
		kmemdup(input->ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->set_security.ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->set_security.ancestor_guids[input->depth - 1],
		   entry->set_security.key_guid,
		   sizeof(entry->set_security.key_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static long pkm_lcs_transaction_set_value_log_alloc(
	const struct pkm_lcs_transaction_set_value_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->key_guid || !input->layer || !input->path ||
	    !input->ancestor_guids || !input->depth || !input->sequence ||
	    (input->value_name_len && !input->value_name) ||
	    !pkm_lcs_transaction_value_name_len_valid(
		    input->value_name_len) ||
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (input->depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE;
	memcpy(entry->set_value.key_guid, input->key_guid,
	       sizeof(entry->set_value.key_guid));
	entry->set_value.sequence = input->sequence;
	entry->set_value.value_name_len = (u32)input->value_name_len;
	entry->set_value.layer_len = (u32)input->layer_len;
	entry->set_value.depth = input->depth;

	if (input->value_name_len)
		entry->set_value.value_name =
			kmemdup_nul(input->value_name, input->value_name_len,
				    GFP_KERNEL);
	else
		entry->set_value.value_name = kstrdup("", GFP_KERNEL);
	if (!entry->set_value.value_name) {
		ret = -ENOMEM;
		goto out_free;
	}

	entry->set_value.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->set_value.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->path, input->depth, &entry->set_value.path);
	if (ret)
		goto out_free;

	if (check_mul_overflow((size_t)input->depth,
			       sizeof(*entry->set_value.ancestor_guids),
			       &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->set_value.ancestor_guids =
		kmemdup(input->ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->set_value.ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->set_value.ancestor_guids[input->depth - 1],
		   entry->set_value.key_guid,
		   sizeof(entry->set_value.key_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static bool pkm_lcs_transaction_delete_value_event_valid(u32 event_type)
{
	return event_type == 0 || event_type == REG_WATCH_VALUE_SET ||
	       event_type == REG_WATCH_VALUE_DELETED;
}

static long pkm_lcs_transaction_delete_value_log_alloc(
	const struct pkm_lcs_transaction_delete_value_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->key_guid || !input->layer || !input->path ||
	    !input->ancestor_guids || !input->depth ||
	    (input->value_name_len && !input->value_name) ||
	    !pkm_lcs_transaction_value_name_len_valid(
		    input->value_name_len) ||
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (input->depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE;
	memcpy(entry->delete_value.key_guid, input->key_guid,
	       sizeof(entry->delete_value.key_guid));
	entry->delete_value.value_name_len = (u32)input->value_name_len;
	entry->delete_value.layer_len = (u32)input->layer_len;
	entry->delete_value.depth = input->depth;

	if (input->value_name_len)
		entry->delete_value.value_name =
			kmemdup_nul(input->value_name,
				    input->value_name_len, GFP_KERNEL);
	else
		entry->delete_value.value_name = kstrdup("", GFP_KERNEL);
	if (!entry->delete_value.value_name) {
		ret = -ENOMEM;
		goto out_free;
	}

	entry->delete_value.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->delete_value.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->path, input->depth, &entry->delete_value.path);
	if (ret)
		goto out_free;

	if (check_mul_overflow((size_t)input->depth,
			       sizeof(*entry->delete_value.ancestor_guids),
			       &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->delete_value.ancestor_guids =
		kmemdup(input->ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->delete_value.ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->delete_value.ancestor_guids[input->depth - 1],
		   entry->delete_value.key_guid,
		   sizeof(entry->delete_value.key_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static long pkm_lcs_transaction_delete_key_log_alloc(
	const struct pkm_lcs_transaction_delete_key_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->key_guid || !input->parent_guid ||
	    !input->child_name ||
	    !input->layer || !input->parent_path ||
	    !input->parent_ancestor_guids || !input->parent_depth ||
	    !pkm_lcs_transaction_name_len_valid(input->child_name_len) ||
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (!memchr_inv(input->key_guid, 0,
			PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES))
		return -EINVAL;
	if (input->parent_depth >
	    PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY;
	memcpy(entry->delete_key.key_guid, input->key_guid,
	       sizeof(entry->delete_key.key_guid));
	memcpy(entry->delete_key.parent_guid, input->parent_guid,
	       sizeof(entry->delete_key.parent_guid));
	entry->delete_key.child_name_len = (u32)input->child_name_len;
	entry->delete_key.layer_len = (u32)input->layer_len;
	entry->delete_key.parent_depth = input->parent_depth;

	entry->delete_key.child_name =
		kmemdup_nul(input->child_name, input->child_name_len,
			    GFP_KERNEL);
	if (!entry->delete_key.child_name) {
		ret = -ENOMEM;
		goto out_free;
	}
	entry->delete_key.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->delete_key.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->parent_path, input->parent_depth,
		&entry->delete_key.parent_path);
	if (ret)
		goto out_free;

	if (check_mul_overflow(
		    (size_t)input->parent_depth,
		    sizeof(*entry->delete_key.parent_ancestor_guids),
		    &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->delete_key.parent_ancestor_guids =
		kmemdup(input->parent_ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->delete_key.parent_ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->delete_key.parent_ancestor_guids[
			   input->parent_depth - 1],
		   entry->delete_key.parent_guid,
		   sizeof(entry->delete_key.parent_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static long pkm_lcs_transaction_hide_key_log_alloc(
	const struct pkm_lcs_transaction_hide_key_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->key_guid || !input->parent_guid ||
	    !input->child_name ||
	    !input->layer || !input->parent_path ||
	    !input->parent_ancestor_guids || !input->parent_depth ||
	    !input->sequence ||
	    !pkm_lcs_transaction_name_len_valid(input->child_name_len) ||
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (!memchr_inv(input->key_guid, 0,
			PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES))
		return -EINVAL;
	if (input->parent_depth >
	    PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY;
	memcpy(entry->hide_key.key_guid, input->key_guid,
	       sizeof(entry->hide_key.key_guid));
	memcpy(entry->hide_key.parent_guid, input->parent_guid,
	       sizeof(entry->hide_key.parent_guid));
	entry->hide_key.sequence = input->sequence;
	entry->hide_key.child_name_len = (u32)input->child_name_len;
	entry->hide_key.layer_len = (u32)input->layer_len;
	entry->hide_key.parent_depth = input->parent_depth;

	entry->hide_key.child_name =
		kmemdup_nul(input->child_name, input->child_name_len,
			    GFP_KERNEL);
	if (!entry->hide_key.child_name) {
		ret = -ENOMEM;
		goto out_free;
	}
	entry->hide_key.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->hide_key.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->parent_path, input->parent_depth,
		&entry->hide_key.parent_path);
	if (ret)
		goto out_free;

	if (check_mul_overflow(
		    (size_t)input->parent_depth,
		    sizeof(*entry->hide_key.parent_ancestor_guids),
		    &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->hide_key.parent_ancestor_guids =
		kmemdup(input->parent_ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->hide_key.parent_ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->hide_key.parent_ancestor_guids[
			   input->parent_depth - 1],
		   entry->hide_key.parent_guid,
		   sizeof(entry->hide_key.parent_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static void pkm_lcs_transaction_fd_timeout(struct timer_list *timer)
{
	struct pkm_lcs_transaction_fd *txn =
		container_of(timer, struct pkm_lcs_transaction_fd,
			     timeout_timer);
	bool schedule_cleanup = false;
	bool terminal = false;

	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_ACTIVE_BOUND) {
		if (!txn->commit_in_flight) {
			txn->timeout_abort_pending = true;
			schedule_cleanup = true;
		}
		txn->state = REG_TXN_TIMED_OUT;
		terminal = true;
	} else if (txn->state == REG_TXN_ACTIVE_UNBOUND) {
		txn->state = REG_TXN_TIMED_OUT;
		terminal = true;
	}
	spin_unlock(&txn->lock);

	if (terminal)
		wake_up_all(&txn->wait);
	if (schedule_cleanup)
		schedule_work(&txn->timeout_work);
}

static void pkm_lcs_transaction_fd_timeout_work(struct work_struct *work)
{
	struct pkm_lcs_transaction_fd *txn =
		container_of(work, struct pkm_lcs_transaction_fd,
			     timeout_work);
	u64 transaction_id = 0;
	u32 source_id = 0;
	u32 count = 0;
	bool cleanup = false;

	mutex_lock(&txn->bind_lock);
	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_TIMED_OUT && txn->timeout_abort_pending) {
		transaction_id = txn->transaction_id;
		source_id = txn->bound_source_id;
		txn->timeout_abort_pending = false;
		cleanup = transaction_id && source_id;
	}
	spin_unlock(&txn->lock);

	if (cleanup) {
		(void)pkm_lcs_source_dispatch_abort_transaction_request(
			source_id, transaction_id, NULL);
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
		pkm_lcs_transaction_log_clear(txn);
	}
	mutex_unlock(&txn->bind_lock);
}

static int pkm_lcs_transaction_fd_release(struct inode *inode,
					  struct file *file)
{
	struct pkm_lcs_transaction_fd *txn = file->private_data;
	u64 transaction_id = 0;
	u32 source_id = 0;
	u32 count = 0;
	bool dispatch_abort = false;
	bool release_counter = false;
	bool retain_detached_commit = false;
	bool wake = false;

	file->private_data = NULL;
	if (!txn)
		return 0;

	timer_delete_sync(&txn->timeout_timer);
	cancel_work_sync(&txn->timeout_work);

	spin_lock(&txn->lock);
	txn->fd_released = true;
	if (txn->state == REG_TXN_ACTIVE_BOUND) {
		transaction_id = txn->transaction_id;
		source_id = txn->bound_source_id;
		txn->state = REG_TXN_ABORTED;
		dispatch_abort = transaction_id && source_id;
		release_counter = source_id != 0;
		wake = true;
	} else if (txn->state == REG_TXN_ACTIVE_UNBOUND) {
		txn->state = REG_TXN_ABORTED;
		wake = true;
	} else if (txn->state == REG_TXN_TIMED_OUT &&
		   txn->timeout_abort_pending) {
		transaction_id = txn->transaction_id;
		source_id = txn->bound_source_id;
		txn->timeout_abort_pending = false;
		dispatch_abort = transaction_id && source_id;
		release_counter = source_id != 0;
	} else if (txn->state == REG_TXN_TIMED_OUT &&
		   txn->commit_in_flight) {
		retain_detached_commit = true;
	}
	spin_unlock(&txn->lock);

	if (retain_detached_commit)
		return 0;

	pkm_lcs_transaction_fd_registry_remove(txn);
	if (dispatch_abort)
		(void)pkm_lcs_source_dispatch_abort_transaction_request(
			source_id, transaction_id, NULL);
	if (release_counter)
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
	if (wake)
		wake_up_all(&txn->wait);
	pkm_lcs_transaction_fd_destroy(txn);
	return 0;
}

static long pkm_lcs_transaction_fd_status_from_state(
	struct pkm_lcs_transaction_fd *txn, struct reg_txn_status_args *out)
{
	u32 state;
	long ret;

	if (!txn || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	spin_lock(&txn->lock);
	state = txn->state;
	spin_unlock(&txn->lock);

	ret = pkm_lcs_transaction_terminal_errno(state, &out->terminal_errno);
	if (ret) {
		memset(out, 0, sizeof(*out));
		return ret;
	}
	out->state = state;
	return 0;
}

static long pkm_lcs_transaction_log_requires_generation(
	const struct pkm_lcs_transaction_fd *txn, bool *requires_generation)
{
	struct pkm_lcs_transaction_log_entry *entry;
	bool required = false;

	if (!txn || !requires_generation)
		return -EINVAL;

	list_for_each_entry(entry, &txn->mutation_log, link) {
		switch (entry->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			required = true;
			break;
		default:
			return -EIO;
		}
	}

	*requires_generation = required;
	return 0;
}

static long pkm_lcs_transaction_fd_apply_success_generation_under_bind(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id)
{
	u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	bool requires_generation = false;
	u64 generation = 0;
	u32 state;
	long ret;

	if (!txn || !transaction_id || !source_id)
		return -EINVAL;

	spin_lock(&txn->lock);
	if (txn->transaction_id != transaction_id ||
	    txn->bound_source_id != source_id || !txn->commit_in_flight) {
		ret = -ENOENT;
		goto out_unlock;
	}

	state = txn->state;
	if (state != REG_TXN_ACTIVE_BOUND && state != REG_TXN_TIMED_OUT) {
		ret = state == REG_TXN_SOURCE_DOWN ? -EIO : -EINVAL;
		goto out_unlock;
	}
	memcpy(root_guid, txn->bound_root_guid, sizeof(root_guid));
	ret = 0;

out_unlock:
	spin_unlock(&txn->lock);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_log_requires_generation(
		txn, &requires_generation);
	if (ret)
		return ret;
	if (!requires_generation)
		return 0;

	ret = pkm_lcs_source_record_transaction_generation(
		source_id, root_guid, &generation);
	if (ret)
		return -EIO;
	return 0;
}

static long pkm_lcs_transaction_dispatch_key_path_overflow(
	const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	char **parent_path,
	u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	u32 parent_depth, const char *child_name)
{
	struct pkm_lcs_watch_dispatch_context parent_context = { };
	struct pkm_lcs_watch_dispatch_context child_context = { };
	u8 (*child_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	const char **child_path;
	u32 child_depth;
	size_t child_ancestor_bytes;
	size_t child_path_bytes;
	long ret;

	if (!key_guid || !parent_guid || !parent_path ||
	    !parent_ancestor_guids || !parent_depth || !child_name)
		return -EINVAL;
	if (check_add_overflow(parent_depth, 1U, &child_depth))
		return -EOVERFLOW;
	if (check_mul_overflow((size_t)child_depth, sizeof(*child_path),
			       &child_path_bytes) ||
	    check_mul_overflow((size_t)child_depth,
			       sizeof(*child_ancestor_guids),
			       &child_ancestor_bytes))
		return -EOVERFLOW;

	child_path = kzalloc(child_path_bytes, GFP_KERNEL);
	if (!child_path)
		return -ENOMEM;
	child_ancestor_guids = kzalloc(child_ancestor_bytes, GFP_KERNEL);
	if (!child_ancestor_guids) {
		kfree(child_path);
		return -ENOMEM;
	}

	memcpy(child_path, parent_path, (size_t)parent_depth * sizeof(*child_path));
	child_path[parent_depth] = child_name;
	memcpy(child_ancestor_guids, parent_ancestor_guids,
	       (size_t)parent_depth * sizeof(*child_ancestor_guids));
	memcpy(child_ancestor_guids[parent_depth], key_guid,
	       sizeof(child_ancestor_guids[parent_depth]));

	parent_context.changed_key_guid = parent_guid;
	parent_context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])parent_ancestor_guids;
	parent_context.resolved_path = (const char * const *)parent_path;
	parent_context.path_component_count = parent_depth;
	ret = pkm_lcs_key_fd_dispatch_overflow_context(&parent_context);
	if (ret)
		goto out_free;

	child_context.changed_key_guid = key_guid;
	child_context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])child_ancestor_guids;
	child_context.resolved_path = (const char * const *)child_path;
	child_context.path_component_count = child_depth;
	ret = pkm_lcs_key_fd_dispatch_overflow_context(&child_context);

out_free:
	kfree(child_ancestor_guids);
	kfree(child_path);
	return ret;
}

static long pkm_lcs_transaction_delete_key_still_named(
	u32 source_id,
	const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const char *child_name, u32 child_name_len, bool *still_named)
{
	struct pkm_lcs_rsi_lookup_guid_entry_result result = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u64 next_sequence = 0;
	long ret;

	if (!source_id || !key_guid || !parent_guid || !child_name ||
	    !child_name_len || !still_named)
		return -EINVAL;
	*still_named = false;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
		source_id, 0, parent_guid, child_name, child_name_len,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_lookup_guid_entry(
		frame.data, frame.len, response.request_id, next_sequence,
		child_name, child_name_len, key_guid, &result);
	if (ret)
		goto out_frame;

	*still_named = result.present != 0;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

static long pkm_lcs_transaction_apply_delete_key_orphan_effects(
	u32 source_id, const struct pkm_lcs_transaction_delete_key_log *entry)
{
	bool still_named = false;
	u32 live_refs = 0;
	u32 marked = 0;
	long ret;

	if (!source_id || !entry)
		return -EINVAL;

	ret = pkm_lcs_transaction_delete_key_still_named(
		source_id, entry->key_guid, entry->parent_guid,
		entry->child_name, entry->child_name_len, &still_named);
	if (ret)
		return ret;
	if (still_named)
		return 0;

	ret = pkm_lcs_key_fd_mark_orphaned_no_watch(
		source_id, entry->key_guid, &marked, &live_refs);
	if (ret)
		return ret;

	if (!live_refs)
		(void)pkm_lcs_source_dispatch_drop_key_request(
			source_id, 0, entry->key_guid, NULL);
	return 0;
}

static long pkm_lcs_transaction_log_apply_orphan_effects(
	struct pkm_lcs_transaction_fd *txn, u32 source_id)
{
	struct pkm_lcs_transaction_log_entry *entry;
	long ret;

	if (!txn || !source_id)
		return -EINVAL;

	list_for_each_entry(entry, &txn->mutation_log, link) {
		switch (entry->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
			ret = pkm_lcs_transaction_apply_delete_key_orphan_effects(
				source_id, &entry->delete_key);
			if (ret)
				return ret;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			break;
		default:
			return -EIO;
		}
	}
	return 0;
}

static long pkm_lcs_transaction_log_dispatch_watch_batch(
	struct pkm_lcs_transaction_fd *txn)
{
	struct pkm_lcs_watch_dispatch_context *contexts;
	struct pkm_lcs_transaction_log_entry *entry;
	u32 index = 0;
	long ret;

	if (!txn)
		return -EINVAL;
	if (!txn->mutation_log_entries)
		return 0;

	contexts = kcalloc(txn->mutation_log_entries, sizeof(*contexts),
			   GFP_KERNEL);
	if (!contexts)
		return -ENOMEM;

	list_for_each_entry(entry, &txn->mutation_log, link) {
		switch (entry->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
			contexts[index].changed_key_guid =
				entry->create_key.parent_guid;
			contexts[index].ancestor_guids =
				entry->create_key.parent_ancestor_guids;
			contexts[index].resolved_path =
				(const char * const *)entry->create_key.parent_path;
			contexts[index].path_component_count =
				entry->create_key.parent_depth;
			contexts[index].event_type = REG_WATCH_SUBKEY_CREATED;
			contexts[index].name =
				(const u8 *)entry->create_key.child_name;
			contexts[index].name_len =
				entry->create_key.child_name_len;
			index++;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
			contexts[index].changed_key_guid =
				entry->set_security.key_guid;
			contexts[index].ancestor_guids =
				entry->set_security.ancestor_guids;
			contexts[index].resolved_path =
				(const char * const *)entry->set_security.path;
			contexts[index].path_component_count =
				entry->set_security.depth;
			contexts[index].event_type = REG_WATCH_SD_CHANGED;
			contexts[index].name = NULL;
			contexts[index].name_len = 0;
			index++;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
			contexts[index].changed_key_guid =
				entry->set_value.key_guid;
			contexts[index].ancestor_guids =
				entry->set_value.ancestor_guids;
			contexts[index].resolved_path =
				(const char * const *)entry->set_value.path;
			contexts[index].path_component_count =
				entry->set_value.depth;
			contexts[index].event_type = REG_WATCH_VALUE_SET;
			contexts[index].name =
				(const u8 *)entry->set_value.value_name;
			contexts[index].name_len =
				entry->set_value.value_name_len;
			index++;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
			if (!entry->delete_value.event_type)
				break;
			contexts[index].changed_key_guid =
				entry->delete_value.key_guid;
			contexts[index].ancestor_guids =
				entry->delete_value.ancestor_guids;
			contexts[index].resolved_path =
				(const char * const *)entry->delete_value.path;
			contexts[index].path_component_count =
				entry->delete_value.depth;
			contexts[index].event_type =
				entry->delete_value.event_type;
			contexts[index].name =
				(const u8 *)entry->delete_value.value_name;
			contexts[index].name_len =
				entry->delete_value.value_name_len;
			index++;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
			if (index) {
				ret = pkm_lcs_key_fd_dispatch_watch_event_context_batch(
					contexts, index);
				if (ret)
					goto out_free;
				index = 0;
			}
			ret = pkm_lcs_transaction_dispatch_key_path_overflow(
				entry->delete_key.key_guid,
				entry->delete_key.parent_guid,
				entry->delete_key.parent_path,
				entry->delete_key.parent_ancestor_guids,
				entry->delete_key.parent_depth,
				entry->delete_key.child_name);
			if (ret)
				goto out_free;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			if (index) {
				ret = pkm_lcs_key_fd_dispatch_watch_event_context_batch(
					contexts, index);
				if (ret)
					goto out_free;
				index = 0;
			}
			ret = pkm_lcs_transaction_dispatch_key_path_overflow(
				entry->hide_key.key_guid,
				entry->hide_key.parent_guid,
				entry->hide_key.parent_path,
				entry->hide_key.parent_ancestor_guids,
				entry->hide_key.parent_depth,
				entry->hide_key.child_name);
			if (ret)
				goto out_free;
			break;
		default:
			ret = -EIO;
			goto out_free;
		}
	}

	ret = pkm_lcs_key_fd_dispatch_watch_event_context_batch(contexts,
							       index);

out_free:
	kfree(contexts);
	return ret;
}

static long pkm_lcs_transaction_fd_apply_commit_response_under_bind(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id,
	u32 status, bool detached, u32 *final_state_out,
	bool *release_counter_out, bool *source_down_required_out)
{
	bool release_counter = false;
	bool clear_log = false;
	bool stop_timer = false;
	bool wake = false;
	u32 final_state = 0;
	long ret = 0;

	if (!txn || !transaction_id || !source_id || !final_state_out ||
	    !release_counter_out || !source_down_required_out)
		return -EINVAL;
	*final_state_out = 0;
	*release_counter_out = false;
	*source_down_required_out = false;

	if (status == RSI_OK) {
		ret = pkm_lcs_transaction_fd_apply_success_generation_under_bind(
			txn, transaction_id, source_id);
		if (ret) {
			*source_down_required_out = true;
			return -EIO;
		}
		ret = pkm_lcs_transaction_log_apply_orphan_effects(
			txn, source_id);
		if (ret) {
			*source_down_required_out = true;
			return -EIO;
		}
		(void)pkm_lcs_transaction_log_dispatch_watch_batch(txn);
	}

	spin_lock(&txn->lock);
	if (txn->transaction_id != transaction_id ||
	    txn->bound_source_id != source_id || !txn->commit_in_flight) {
		ret = -ENOENT;
		goto out_unlock;
	}

	switch (txn->state) {
	case REG_TXN_ACTIVE_BOUND:
		txn->commit_in_flight = false;
		txn->timeout_abort_pending = false;
		if (status == RSI_OK) {
			txn->state = REG_TXN_COMMITTED;
			release_counter = true;
			clear_log = true;
			stop_timer = true;
			wake = true;
		} else if (detached) {
			txn->state = REG_TXN_TIMED_OUT;
			release_counter = true;
			clear_log = true;
			stop_timer = true;
			wake = true;
		}
		final_state = txn->state;
		break;
	case REG_TXN_TIMED_OUT:
		txn->commit_in_flight = false;
		txn->timeout_abort_pending = false;
		release_counter = true;
		clear_log = true;
		stop_timer = true;
		final_state = txn->state;
		break;
	case REG_TXN_SOURCE_DOWN:
		ret = -EIO;
		break;
	default:
		ret = -EINVAL;
		break;
	}

out_unlock:
	spin_unlock(&txn->lock);
	if (ret)
		return ret;

	if (stop_timer)
		timer_delete_sync(&txn->timeout_timer);
	if (clear_log)
		pkm_lcs_transaction_log_clear(txn);
	if (wake)
		wake_up_all(&txn->wait);

	*final_state_out = final_state;
	*release_counter_out = release_counter;
	return 0;
}

static long pkm_lcs_transaction_fd_mark_commit_request_timeout(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id)
{
	bool stop_timer = false;
	bool wake = false;
	long ret = 0;

	if (!txn || !transaction_id || !source_id)
		return -EINVAL;

	spin_lock(&txn->lock);
	if (txn->transaction_id != transaction_id ||
	    txn->bound_source_id != source_id || !txn->commit_in_flight) {
		ret = -ENOENT;
	} else if (txn->state == REG_TXN_ACTIVE_BOUND) {
		txn->state = REG_TXN_TIMED_OUT;
		txn->timeout_abort_pending = false;
		stop_timer = true;
		wake = true;
	} else if (txn->state == REG_TXN_TIMED_OUT) {
		txn->timeout_abort_pending = false;
		stop_timer = true;
	} else if (txn->state == REG_TXN_SOURCE_DOWN) {
		ret = -EIO;
	} else {
		ret = -EINVAL;
	}
	spin_unlock(&txn->lock);
	if (ret)
		return ret;

	if (stop_timer)
		timer_delete_sync(&txn->timeout_timer);
	if (wake)
		wake_up_all(&txn->wait);
	return 0;
}

static long pkm_lcs_transaction_fd_commit_from_state_timeout(
	struct pkm_lcs_transaction_fd *txn, u32 timeout_ms)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u64 transaction_id;
	u32 source_id;
	u32 state;
	u32 final_state = 0;
	long ret;
	u32 count;
	bool release_counter = false;
	bool mark_source_down = false;
	bool source_down_required = false;
	u32 mark_source_down_id = 0;

	if (!txn)
		return -EINVAL;

	mutex_lock(&txn->bind_lock);

	spin_lock(&txn->lock);
	state = txn->state;
	transaction_id = txn->transaction_id;
	source_id = txn->bound_source_id;
	spin_unlock(&txn->lock);

	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		ret = -EINVAL;
		goto out_unlock;
	case REG_TXN_TIMED_OUT:
		ret = -ETIMEDOUT;
		goto out_unlock;
	case REG_TXN_SOURCE_DOWN:
		ret = -EIO;
		goto out_unlock;
	case REG_TXN_ACTIVE_BOUND:
		if (!transaction_id || !source_id) {
			ret = -EIO;
			goto out_unlock;
		}
		break;
	default:
		ret = -EIO;
		goto out_unlock;
	}

	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_ACTIVE_BOUND &&
	    txn->transaction_id == transaction_id &&
	    txn->bound_source_id == source_id) {
		txn->commit_in_flight = true;
		ret = 0;
	} else if (txn->state == REG_TXN_TIMED_OUT) {
		ret = -ETIMEDOUT;
	} else if (txn->state == REG_TXN_SOURCE_DOWN) {
		ret = -EIO;
	} else {
		ret = -EINVAL;
	}
	spin_unlock(&txn->lock);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_source_commit_transaction_round_trip_timeout(
		source_id, transaction_id, timeout_ms, &response, &enqueue);
	if (ret) {
		if (ret == -ETIMEDOUT && enqueue.len) {
			(void)pkm_lcs_transaction_fd_mark_commit_request_timeout(
				txn, transaction_id, source_id);
			goto out_unlock;
		}

		if (response.len) {
			long apply_ret;

			source_down_required = false;
			apply_ret =
				pkm_lcs_transaction_fd_apply_commit_response_under_bind(
					txn, transaction_id, source_id,
					response.status, false, &final_state,
					&release_counter,
					&source_down_required);
			if (!apply_ret) {
				if (release_counter)
					(void)pkm_lcs_source_bound_transaction_release(
						source_id, &count);
				if (final_state != REG_TXN_ACTIVE_BOUND)
					ret = -ETIMEDOUT;
				goto out_unlock;
			}
			if (source_down_required) {
				mark_source_down = true;
				mark_source_down_id = source_id;
				ret = -EIO;
				goto out_unlock;
			}
		}

		spin_lock(&txn->lock);
		txn->commit_in_flight = false;
		spin_unlock(&txn->lock);
		goto out_unlock;
	}

	source_down_required = false;
	ret = pkm_lcs_transaction_fd_apply_commit_response_under_bind(
		txn, transaction_id, source_id, RSI_OK, false, &final_state,
		&release_counter, &source_down_required);
	if (ret) {
		if (source_down_required) {
			mark_source_down = true;
			mark_source_down_id = source_id;
			ret = -EIO;
		}
		goto out_unlock;
	}

	if (release_counter)
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
	if (final_state == REG_TXN_COMMITTED)
		ret = 0;
	else
		ret = -ETIMEDOUT;

out_unlock:
	mutex_unlock(&txn->bind_lock);
	if (mark_source_down)
		pkm_lcs_source_mark_down_by_id(mark_source_down_id);
	return ret;
}

static long pkm_lcs_transaction_fd_commit_from_state(
	struct pkm_lcs_transaction_fd *txn)
{
	return pkm_lcs_transaction_fd_commit_from_state_timeout(
		txn, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT);
}

static __poll_t pkm_lcs_transaction_fd_poll(struct file *file,
					    struct poll_table_struct *wait)
{
	struct pkm_lcs_transaction_fd *txn;
	__poll_t mask = 0;
	u32 state;

	if (!file)
		return EPOLLERR | EPOLLHUP;

	txn = file->private_data;
	if (!txn)
		return EPOLLERR | EPOLLHUP;

	poll_wait(file, &txn->wait, wait);

	spin_lock(&txn->lock);
	state = txn->state;
	spin_unlock(&txn->lock);

	if (!pkm_lcs_transaction_state_active(state))
		mask = EPOLLERR | EPOLLHUP;
	return mask;
}

static long pkm_lcs_transaction_fd_ioctl(struct file *file, unsigned int cmd,
					 unsigned long arg)
{
	struct pkm_lcs_transaction_fd *txn;
	struct reg_txn_status_args status;
	long ret;

	if (!file)
		return -EBADF;

	txn = file->private_data;
	if (!txn)
		return -EINVAL;

	switch (cmd) {
	case REG_IOC_COMMIT:
		return pkm_lcs_transaction_fd_commit_from_state(txn);
	case REG_IOC_TXN_STATUS:
		if (!arg)
			return -EFAULT;
		ret = pkm_lcs_transaction_fd_status_from_state(txn, &status);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations pkm_lcs_transaction_fd_fops = {
	.owner = THIS_MODULE,
	.release = pkm_lcs_transaction_fd_release,
	.poll = pkm_lcs_transaction_fd_poll,
	.unlocked_ioctl = pkm_lcs_transaction_fd_ioctl,
	.llseek = noop_llseek,
};

long pkm_lcs_transaction_fd_publish(u32 timeout_ms)
{
	struct pkm_lcs_transaction_fd *txn;
	long ret;
	int fd;

	if (!timeout_ms)
		return -EINVAL;

	txn = kzalloc(sizeof(*txn), GFP_KERNEL);
	if (!txn)
		return -ENOMEM;

	ret = pkm_lcs_transaction_id_allocate(&txn->transaction_id);
	if (ret)
		goto out_free;

	txn->state = REG_TXN_ACTIVE_UNBOUND;
	txn->next_operation_index = 1;
	txn->mutation_log_capacity =
		PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT;
	spin_lock_init(&txn->lock);
	mutex_init(&txn->bind_lock);
	init_waitqueue_head(&txn->wait);
	INIT_LIST_HEAD(&txn->registry_link);
	INIT_LIST_HEAD(&txn->mutation_log);
	timer_setup(&txn->timeout_timer, pkm_lcs_transaction_fd_timeout, 0);
	INIT_WORK(&txn->timeout_work, pkm_lcs_transaction_fd_timeout_work);
	pkm_lcs_transaction_fd_registry_add(txn);

	fd = anon_inode_getfd("lcs-transaction", &pkm_lcs_transaction_fd_fops,
			      txn, O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_unregister;
	}

	mod_timer(&txn->timeout_timer,
		  pkm_lcs_transaction_deadline_from_timeout_ms(timeout_ms));
	return fd;

out_unregister:
	pkm_lcs_transaction_fd_registry_remove(txn);
out_free:
	kfree(txn);
	return ret;
}

static long pkm_lcs_transaction_fd_get(
	int fd, struct fd *held, struct pkm_lcs_transaction_fd **txn_out)
{
	struct file *file;

	if (!held || !txn_out)
		return -EINVAL;
	*txn_out = NULL;

	*held = fdget(fd);
	file = fd_file(*held);
	if (!file)
		return -EBADF;

	if (file->f_op != &pkm_lcs_transaction_fd_fops) {
		fdput(*held);
		return -EINVAL;
	}

	*txn_out = file->private_data;
	if (!*txn_out) {
		fdput(*held);
		return -EINVAL;
	}

	return 0;
}

static void pkm_lcs_transaction_mutation_handle_release(
	struct pkm_lcs_transaction_mutation_handle *handle)
{
	if (!handle || !handle->active)
		return;

	mutex_unlock(&handle->txn->bind_lock);
	fdput(handle->held);
	memset(handle, 0, sizeof(*handle));
}

static long pkm_lcs_transaction_log_capacity_check(
	const struct pkm_lcs_transaction_fd *txn)
{
	if (!txn || !txn->mutation_log_capacity)
		return -EINVAL;
	if (txn->mutation_log_entries >= txn->mutation_log_capacity)
		return -ENOMEM;
	if (!txn->next_operation_index ||
	    txn->next_operation_index == U64_MAX)
		return -EOVERFLOW;
	return 0;
}

long pkm_lcs_transaction_fd_snapshot(
	int fd, struct pkm_lcs_transaction_fd_snapshot *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	spin_lock(&txn->lock);
	out->transaction_id = txn->transaction_id;
	out->state = txn->state;
	out->bound_source_id = txn->bound_source_id;
	memcpy(out->bound_root_guid, txn->bound_root_guid,
	       sizeof(out->bound_root_guid));
	out->timer_pending = timer_pending(&txn->timeout_timer);
	spin_unlock(&txn->lock);

	fdput(held);
	return 0;
}

long pkm_lcs_transaction_fd_log_snapshot(
	int fd, struct pkm_lcs_transaction_mutation_log_snapshot *out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	struct pkm_lcs_transaction_log_entry *last = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);
	out->next_operation_index = txn->next_operation_index;
	out->entry_count = txn->mutation_log_entries;
	out->capacity = txn->mutation_log_capacity;
	list_for_each_entry(entry, &txn->mutation_log, link)
		last = entry;

	if (last) {
		out->last_operation_index = last->operation_index;
		out->last_kind = last->kind;
		switch (last->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
			out->last_sequence = last->create_key.sequence;
			out->last_parent_depth = last->create_key.parent_depth;
			strscpy(out->last_child_name,
				last->create_key.child_name,
				sizeof(out->last_child_name));
			strscpy(out->last_layer, last->create_key.layer,
				sizeof(out->last_layer));
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
			out->last_parent_depth = last->set_security.depth;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
			out->last_sequence = last->set_value.sequence;
			out->last_parent_depth = last->set_value.depth;
			strscpy(out->last_child_name,
				last->set_value.value_name,
				sizeof(out->last_child_name));
			strscpy(out->last_layer, last->set_value.layer,
				sizeof(out->last_layer));
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
			out->last_parent_depth = last->delete_value.depth;
			strscpy(out->last_child_name,
				last->delete_value.value_name,
				sizeof(out->last_child_name));
			strscpy(out->last_layer, last->delete_value.layer,
				sizeof(out->last_layer));
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
			out->last_parent_depth = last->delete_key.parent_depth;
			memcpy(out->last_key_guid, last->delete_key.key_guid,
			       sizeof(out->last_key_guid));
			strscpy(out->last_child_name,
				last->delete_key.child_name,
				sizeof(out->last_child_name));
			strscpy(out->last_layer, last->delete_key.layer,
				sizeof(out->last_layer));
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			out->last_sequence = last->hide_key.sequence;
			out->last_parent_depth = last->hide_key.parent_depth;
			memcpy(out->last_key_guid, last->hide_key.key_guid,
			       sizeof(out->last_key_guid));
			strscpy(out->last_child_name, last->hide_key.child_name,
				sizeof(out->last_child_name));
			strscpy(out->last_layer, last->hide_key.layer,
				sizeof(out->last_layer));
			break;
		default:
			ret = -EIO;
			goto out_unlock;
		}
	}

	ret = 0;

out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	if (ret)
		memset(out, 0, sizeof(*out));
	return ret;
}

long pkm_lcs_transaction_fd_status(int fd, struct reg_txn_status_args *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_status_from_state(txn, out);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_commit(int fd)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_commit_from_state(txn);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_mark_source_down(u32 source_id, u32 *marked_out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct pkm_lcs_transaction_fd *tmp;
	u32 marked = 0;

	if (marked_out)
		*marked_out = 0;
	if (!source_id)
		return -EINVAL;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	list_for_each_entry_safe(txn, tmp, &pkm_lcs_transaction_registry,
				 registry_link) {
		bool destroy_detached = false;
		bool stop_timer = false;
		bool clear_log = false;
		bool wake = false;

		mutex_lock(&txn->bind_lock);
		spin_lock(&txn->lock);
		if (txn->state == REG_TXN_ACTIVE_BOUND &&
		    txn->bound_source_id == source_id) {
			txn->state = REG_TXN_SOURCE_DOWN;
			txn->commit_in_flight = false;
			txn->timeout_abort_pending = false;
			stop_timer = true;
			clear_log = true;
			wake = true;
			marked++;
		} else if (txn->state == REG_TXN_TIMED_OUT &&
			   txn->commit_in_flight &&
			   txn->bound_source_id == source_id) {
			txn->commit_in_flight = false;
			txn->timeout_abort_pending = false;
			clear_log = true;
			destroy_detached = txn->fd_released;
			marked++;
		}
		spin_unlock(&txn->lock);

		if (stop_timer)
			timer_delete_sync(&txn->timeout_timer);
		if (clear_log)
			pkm_lcs_transaction_log_clear(txn);
		if (destroy_detached) {
			list_del_init(&txn->registry_link);
			txn->registry_linked = false;
		}
		mutex_unlock(&txn->bind_lock);

		if (wake)
			wake_up_all(&txn->wait);
		if (destroy_detached)
			pkm_lcs_transaction_fd_destroy(txn);
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);

	if (marked_out)
		*marked_out = marked;
	return 0;
}

long pkm_lcs_transaction_fd_handle_late_commit_response(
	u32 source_id, u64 transaction_id, u32 status)
{
	struct pkm_lcs_transaction_fd *txn;
	struct pkm_lcs_transaction_fd *destroy_txn = NULL;
	bool release_counter = false;
	bool source_down_required = false;
	u32 final_state = 0;
	u32 count = 0;
	long ret = -ENOENT;

	if (!source_id || !transaction_id)
		return -EINVAL;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	list_for_each_entry(txn, &pkm_lcs_transaction_registry,
			    registry_link) {
		bool match;

		mutex_lock(&txn->bind_lock);
		spin_lock(&txn->lock);
		match = txn->transaction_id == transaction_id &&
			txn->bound_source_id == source_id;
		spin_unlock(&txn->lock);
		if (!match) {
			mutex_unlock(&txn->bind_lock);
			continue;
		}

		ret = pkm_lcs_transaction_fd_apply_commit_response_under_bind(
			txn, transaction_id, source_id, status, true,
			&final_state, &release_counter,
			&source_down_required);
		if (!ret) {
			bool destroy_detached;

			spin_lock(&txn->lock);
			destroy_detached = txn->fd_released &&
					   !txn->commit_in_flight;
			spin_unlock(&txn->lock);
			if (destroy_detached) {
				list_del_init(&txn->registry_link);
				txn->registry_linked = false;
				destroy_txn = txn;
			}
		}
		mutex_unlock(&txn->bind_lock);
		break;
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);

	if (!ret && release_counter)
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
	if (destroy_txn)
		pkm_lcs_transaction_fd_destroy(destroy_txn);
	return ret;
}

static long pkm_lcs_transaction_fd_prepare_read_context_from_state(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_read_plan *out)
{
	u32 state;
	long ret;

	if (!txn || !out || !source_id ||
	    !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	spin_lock(&txn->lock);
	state = txn->state;
	out->state = state;
	out->bound_source_id = txn->bound_source_id;
	memcpy(out->bound_root_guid, txn->bound_root_guid,
	       sizeof(out->bound_root_guid));
	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
		out->txn_id = 0;
		out->use_transaction = false;
		ret = 0;
		break;
	case REG_TXN_ACTIVE_BOUND:
		if (txn->bound_source_id == source_id &&
		    !memcmp(txn->bound_root_guid, root_guid,
			    sizeof(txn->bound_root_guid))) {
			out->txn_id = txn->transaction_id;
			out->use_transaction = true;
			ret = 0;
		} else {
			memset(out, 0, sizeof(*out));
			ret = -EXDEV;
		}
		break;
	case REG_TXN_TIMED_OUT:
		memset(out, 0, sizeof(*out));
		ret = -ETIMEDOUT;
		break;
	case REG_TXN_SOURCE_DOWN:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		memset(out, 0, sizeof(*out));
		ret = -EINVAL;
		break;
	default:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	}
	spin_unlock(&txn->lock);
	return ret;
}

long pkm_lcs_transaction_fd_prepare_read_context(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_read_plan *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_prepare_read_context_from_state(
		txn, source_id, root_guid, out);
	fdput(held);
	return ret;
}

static long pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out)
{
	u32 state;
	long ret;

	if (!txn || !out || !source_id ||
	    !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	spin_lock(&txn->lock);
	state = txn->state;
	out->transaction_id = txn->transaction_id;
	out->state = state;
	out->bound_source_id = txn->bound_source_id;
	memcpy(out->bound_root_guid, txn->bound_root_guid,
	       sizeof(out->bound_root_guid));
	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
		out->action = PKM_LCS_TRANSACTION_BIND_NEW;
		ret = 0;
		break;
	case REG_TXN_ACTIVE_BOUND:
		if (txn->bound_source_id == source_id &&
		    !memcmp(txn->bound_root_guid, root_guid,
			    sizeof(txn->bound_root_guid))) {
			out->action = PKM_LCS_TRANSACTION_BIND_REUSE;
			ret = 0;
		} else {
			memset(out, 0, sizeof(*out));
			ret = -EXDEV;
		}
		break;
	case REG_TXN_TIMED_OUT:
		memset(out, 0, sizeof(*out));
		ret = -ETIMEDOUT;
		break;
	case REG_TXN_SOURCE_DOWN:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		memset(out, 0, sizeof(*out));
		ret = -EINVAL;
		break;
	default:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	}
	spin_unlock(&txn->lock);
	return ret;
}

long pkm_lcs_transaction_fd_prepare_mutation_binding(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, out);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_begin_key_create_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_key_create_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_key_create_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
		if (ret)
			goto out_release_counter;

		ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
			txn, plan.transaction_id, source_id, root_guid);
		if (ret) {
			(void)pkm_lcs_source_dispatch_abort_transaction_request(
				source_id, plan.transaction_id, NULL);
			goto out_release_counter;
		}

		plan.state = REG_TXN_ACTIVE_BOUND;
		plan.bound_source_id = source_id;
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_begin_set_security_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_set_security_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_set_security_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
		if (ret)
			goto out_release_counter;

		ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
			txn, plan.transaction_id, source_id, root_guid);
		if (ret) {
			(void)pkm_lcs_source_dispatch_abort_transaction_request(
				source_id, plan.transaction_id, NULL);
			goto out_release_counter;
		}

		plan.state = REG_TXN_ACTIVE_BOUND;
		plan.bound_source_id = source_id;
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_begin_set_value_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_set_value_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_set_value_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
		if (ret)
			goto out_release_counter;

		ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
			txn, plan.transaction_id, source_id, root_guid);
		if (ret) {
			(void)pkm_lcs_source_dispatch_abort_transaction_request(
				source_id, plan.transaction_id, NULL);
			goto out_release_counter;
		}

		plan.state = REG_TXN_ACTIVE_BOUND;
		plan.bound_source_id = source_id;
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_begin_delete_value_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_delete_value_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_delete_value_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
		if (ret)
			goto out_release_counter;

		ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
			txn, plan.transaction_id, source_id, root_guid);
		if (ret) {
			(void)pkm_lcs_source_dispatch_abort_transaction_request(
				source_id, plan.transaction_id, NULL);
			goto out_release_counter;
		}

		plan.state = REG_TXN_ACTIVE_BOUND;
		plan.bound_source_id = source_id;
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_begin_delete_key_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_delete_key_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_delete_key_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
		if (ret)
			goto out_release_counter;

		ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
			txn, plan.transaction_id, source_id, root_guid);
		if (ret) {
			(void)pkm_lcs_source_dispatch_abort_transaction_request(
				source_id, plan.transaction_id, NULL);
			goto out_release_counter;
		}

		plan.state = REG_TXN_ACTIVE_BOUND;
		plan.bound_source_id = source_id;
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_begin_hide_key_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_hide_key_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_hide_key_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
		if (ret)
			goto out_release_counter;

		ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
			txn, plan.transaction_id, source_id, root_guid);
		if (ret) {
			(void)pkm_lcs_source_dispatch_abort_transaction_request(
				source_id, plan.transaction_id, NULL);
			goto out_release_counter;
		}

		plan.state = REG_TXN_ACTIVE_BOUND;
		plan.bound_source_id = source_id;
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_set_delete_value_event(
	struct pkm_lcs_transaction_mutation_handle *handle, u32 event_type)
{
	if (!handle || !handle->active || !handle->entry)
		return -EINVAL;
	if (handle->entry->kind != PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE)
		return -EINVAL;
	if (!pkm_lcs_transaction_delete_value_event_valid(event_type))
		return -EINVAL;

	handle->entry->delete_value.event_type = event_type;
	return 0;
}

long pkm_lcs_transaction_fd_commit_mutation(
	struct pkm_lcs_transaction_mutation_handle *handle)
{
	struct pkm_lcs_transaction_log_entry *entry;
	struct pkm_lcs_transaction_fd *txn;
	long ret;

	if (!handle || !handle->active || !handle->txn || !handle->entry)
		return -EINVAL;

	txn = handle->txn;
	entry = handle->entry;
	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		return -EIO;

	entry->operation_index = txn->next_operation_index++;
	list_add_tail(&entry->link, &txn->mutation_log);
	txn->mutation_log_entries++;
	handle->entry = NULL;
	pkm_lcs_transaction_mutation_handle_release(handle);
	return 0;
}

void pkm_lcs_transaction_fd_cancel_mutation(
	struct pkm_lcs_transaction_mutation_handle *handle)
{
	if (!handle || !handle->active)
		return;

	pkm_lcs_transaction_log_entry_destroy(handle->entry);
	handle->entry = NULL;
	pkm_lcs_transaction_mutation_handle_release(handle);
}

static long pkm_lcs_transaction_fd_complete_first_bind_from_state(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	long ret = 0;

	if (!txn || !transaction_id || !source_id ||
	    !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	spin_lock(&txn->lock);
	switch (txn->state) {
	case REG_TXN_ACTIVE_UNBOUND:
		if (txn->transaction_id != transaction_id) {
			ret = -EINVAL;
			break;
		}
		txn->state = REG_TXN_ACTIVE_BOUND;
		txn->bound_source_id = source_id;
		memcpy(txn->bound_root_guid, root_guid,
		       sizeof(txn->bound_root_guid));
		ret = 0;
		break;
	case REG_TXN_TIMED_OUT:
		ret = -ETIMEDOUT;
		break;
	case REG_TXN_SOURCE_DOWN:
		ret = -EIO;
		break;
	case REG_TXN_ACTIVE_BOUND:
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		ret = -EINVAL;
		break;
	default:
		ret = -EIO;
		break;
	}
	spin_unlock(&txn->lock);

	return ret;
}

long pkm_lcs_transaction_fd_complete_first_bind(
	int fd, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
		txn, transaction_id, source_id, root_guid);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_bind_for_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_REUSE) {
		*out = plan;
		goto out_unlock;
	}

	ret = pkm_lcs_source_bound_transaction_acquire(source_id, &count);
	if (ret)
		goto out_clear;

	ret = pkm_lcs_source_begin_transaction_round_trip(
		source_id, plan.transaction_id, RSI_TXN_READ_WRITE, NULL, NULL);
	if (ret)
		goto out_release_counter;

	ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
		txn, plan.transaction_id, source_id, root_guid);
	if (ret) {
		(void)pkm_lcs_source_dispatch_abort_transaction_request(
			source_id, plan.transaction_id, NULL);
		goto out_release_counter;
	}

	plan.state = REG_TXN_ACTIVE_BOUND;
	plan.bound_source_id = source_id;
	memcpy(plan.bound_root_guid, root_guid, sizeof(plan.bound_root_guid));
	*out = plan;
	goto out_unlock;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_clear:
	memset(out, 0, sizeof(*out));
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static bool pkm_lcs_transaction_state_known(u32 state)
{
	return state == REG_TXN_ACTIVE_UNBOUND ||
	       state == REG_TXN_ACTIVE_BOUND ||
	       state == REG_TXN_COMMITTED ||
	       state == REG_TXN_ABORTED ||
	       state == REG_TXN_TIMED_OUT ||
	       state == REG_TXN_SOURCE_DOWN;
}

long pkm_lcs_kunit_transaction_fd_set_state(int fd, u32 state,
					    u32 bound_source_id)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!pkm_lcs_transaction_state_known(state))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	spin_lock(&txn->lock);
	txn->state = state;
	txn->bound_source_id = bound_source_id;
	memset(txn->bound_root_guid, 0, sizeof(txn->bound_root_guid));
	spin_unlock(&txn->lock);

	if (!pkm_lcs_transaction_state_active(state))
		wake_up_all(&txn->wait);

	fdput(held);
	return 0;
}

long pkm_lcs_kunit_transaction_fd_set_log_capacity(int fd, u32 capacity)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);
	if (!capacity || capacity < txn->mutation_log_entries) {
		ret = -EINVAL;
		goto out_unlock;
	}
	txn->mutation_log_capacity = capacity;
	ret = 0;

out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_transaction_fd_set_commit_in_flight(int fd,
						       bool in_flight)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	spin_lock(&txn->lock);
	txn->commit_in_flight = in_flight;
	spin_unlock(&txn->lock);

	fdput(held);
	return 0;
}

long pkm_lcs_kunit_transaction_fd_flush_timeout_work(int fd)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	flush_work(&txn->timeout_work);
	fdput(held);
	return 0;
}

long pkm_lcs_kunit_transaction_fd_commit_timeout(int fd, u32 timeout_ms)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_commit_from_state_timeout(txn,
							      timeout_ms);
	fdput(held);
	return ret;
}

u32 pkm_lcs_kunit_transaction_fd_retained_commit_count(void)
{
	struct pkm_lcs_transaction_fd *txn;
	u32 count = 0;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	list_for_each_entry(txn, &pkm_lcs_transaction_registry,
			    registry_link) {
		spin_lock(&txn->lock);
		if (txn->fd_released && txn->commit_in_flight)
			count++;
		spin_unlock(&txn->lock);
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);
	return count;
}
#endif

long pkm_lcs_reg_begin_transaction(void)
{
	return pkm_lcs_transaction_fd_publish(
		PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT);
}

SYSCALL_DEFINE0(reg_begin_transaction)
{
	return pkm_lcs_reg_begin_transaction();
}
