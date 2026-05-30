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
#include <linux/unaligned.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <pkm/lcs.h>

#include "key_fd.h"
#include "rsi.h"
#include "transaction_fd.h"
#include "source_device.h"

extern int lcs_rust_layer_name_casefold_eq(const u8 *left, u32 left_len,
					   const u8 *right, u32 right_len,
					   const struct pkm_lcs_runtime_limits *limits,
					   u8 *equal_out);

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
	u8 *creator_sid;
	size_t creator_sid_len;
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

struct pkm_lcs_transaction_blanket_tombstone_log {
	u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u64 sequence;
	char *layer;
	char **path;
	u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u8 *events;
	size_t events_len;
	u32 event_count;
	u32 layer_len;
	u32 depth;
	bool set;
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
	bool post_lookup_valid;
	bool target_still_named;
	bool replacement_visible;
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
	bool post_lookup_valid;
	bool target_still_visible;
	bool replacement_visible;
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
		struct pkm_lcs_transaction_blanket_tombstone_log blanket_tombstone;
		struct pkm_lcs_transaction_delete_key_log delete_key;
		struct pkm_lcs_transaction_hide_key_log hide_key;
	};
};

struct pkm_lcs_transaction_watch_context_owner {
	struct list_head link;
	const char **path;
	u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

struct pkm_lcs_transaction_layer_delete_effect {
	struct list_head link;
	char *layer_name;
	u32 layer_name_len;
	u32 skip_generation_source_id;
	u8 skip_generation_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

static DEFINE_MUTEX(pkm_lcs_transaction_id_lock);
static u64 pkm_lcs_next_transaction_id = 1;
static DEFINE_MUTEX(pkm_lcs_transaction_registry_lock);
static LIST_HEAD(pkm_lcs_transaction_registry);
static const char pkm_lcs_transaction_base_layer_name[] = "base";
static const char * const pkm_lcs_transaction_layer_metadata_prefix[] = {
	"Machine", "System", "Registry", "Layers"
};

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

long pkm_lcs_transaction_id_allocate(u64 *transaction_id)
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

static void pkm_lcs_transaction_runtime_limits_snapshot_or_default(
	struct pkm_lcs_runtime_limits *limits)
{
	if (!limits)
		return;
	if (pkm_lcs_runtime_limits_snapshot(limits) &&
	    pkm_lcs_runtime_limits_defaults(limits))
		memset(limits, 0, sizeof(*limits));
}

static long pkm_lcs_transaction_layer_name_casefold_eq_with_limits(
	const char *left, u32 left_len, const char *right, u32 right_len,
	const struct pkm_lcs_runtime_limits *limits, bool *equal)
{
	u8 raw_equal = 0;
	int ret;

	if (!equal)
		return -EINVAL;
	*equal = false;
	if (!left || !right || !limits)
		return -EINVAL;

	ret = lcs_rust_layer_name_casefold_eq((const u8 *)left, left_len,
					      (const u8 *)right, right_len,
					      limits, &raw_equal);
	if (ret)
		return ret;

	*equal = raw_equal != 0;
	return 0;
}

static long pkm_lcs_transaction_layer_name_casefold_eq(
	const char *left, u32 left_len, const char *right, u32 right_len,
	bool *equal)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_transaction_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_transaction_layer_name_casefold_eq_with_limits(
		left, left_len, right, right_len, &limits, equal);
}

static long pkm_lcs_transaction_layer_name_validate(
	const char *layer_name, u32 layer_name_len)
{
	bool equal;

	return pkm_lcs_transaction_layer_name_casefold_eq(
		layer_name, layer_name_len, layer_name, layer_name_len, &equal);
}

static long pkm_lcs_transaction_path_component_casefold_eq(
	const char *component, const char *expected, bool *equal)
{
	size_t component_len;
	size_t expected_len;

	if (!component || !expected || !equal)
		return -EINVAL;
	component_len = strlen(component);
	expected_len = strlen(expected);
	if (component_len > U32_MAX || expected_len > U32_MAX)
		return -EOVERFLOW;
	return pkm_lcs_transaction_layer_name_casefold_eq(
		component, (u32)component_len, expected, (u32)expected_len,
		equal);
}

static long pkm_lcs_transaction_layer_metadata_prefix_matches(
	char **path, u32 depth, bool *matches_out)
{
	u32 i;

	if (!matches_out)
		return -EINVAL;
	*matches_out = false;
	if (!path)
		return -EINVAL;
	if (depth < ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix))
		return 0;

	for (i = 0; i < ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix);
	     i++) {
		bool equal = false;
		long ret;

		ret = pkm_lcs_transaction_path_component_casefold_eq(
			path[i], pkm_lcs_transaction_layer_metadata_prefix[i],
			&equal);
		if (ret)
			return ret;
		if (!equal)
			return 0;
	}

	*matches_out = true;
	return 0;
}

static long pkm_lcs_transaction_layer_metadata_path(
	char **path, u32 depth, const char **layer_name_out,
	u32 *layer_name_len_out, bool *matches_out)
{
	const char *layer_name;
	bool prefix_matches = false;
	long ret;

	if (!layer_name_out || !layer_name_len_out || !matches_out)
		return -EINVAL;
	*layer_name_out = NULL;
	*layer_name_len_out = 0;
	*matches_out = false;
	if (depth != ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix) + 1U)
		return 0;

	ret = pkm_lcs_transaction_layer_metadata_prefix_matches(
		path, depth, &prefix_matches);
	if (ret || !prefix_matches)
		return ret;

	layer_name = path[ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix)];
	if (!layer_name)
		return -EINVAL;
	if (strlen(layer_name) > U32_MAX)
		return -EOVERFLOW;

	*layer_name_out = layer_name;
	*layer_name_len_out = (u32)strlen(layer_name);
	*matches_out = true;
	return 0;
}

static long pkm_lcs_transaction_layer_name_is_base(
	const char *layer_name, u32 layer_name_len, bool *is_base)
{
	return pkm_lcs_transaction_layer_name_casefold_eq(
		layer_name, layer_name_len, pkm_lcs_transaction_base_layer_name,
		sizeof(pkm_lcs_transaction_base_layer_name) - 1, is_base);
}

static void pkm_lcs_transaction_layer_delete_effects_destroy(
	struct list_head *effects)
{
	struct pkm_lcs_transaction_layer_delete_effect *effect;
	struct pkm_lcs_transaction_layer_delete_effect *tmp;

	if (!effects)
		return;
	list_for_each_entry_safe(effect, tmp, effects, link) {
		list_del(&effect->link);
		kfree(effect->layer_name);
		kfree(effect);
	}
}

static long pkm_lcs_transaction_layer_delete_effect_append(
	struct list_head *effects, const char *layer_name, u32 layer_name_len,
	u32 skip_generation_source_id,
	const u8 skip_generation_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	struct pkm_lcs_transaction_layer_delete_effect *effect;

	if (!effects || !layer_name || !layer_name_len ||
	    !skip_generation_source_id || !skip_generation_root_guid)
		return -EINVAL;

	list_for_each_entry(effect, effects, link) {
		bool equal = false;
		long ret;

		ret = pkm_lcs_transaction_layer_name_casefold_eq(
			effect->layer_name, effect->layer_name_len,
			layer_name, layer_name_len, &equal);
		if (ret)
			return ret;
		if (equal)
			return 0;
	}

	effect = kzalloc(sizeof(*effect), GFP_KERNEL);
	if (!effect)
		return -ENOMEM;
	INIT_LIST_HEAD(&effect->link);
	effect->layer_name = kmemdup_nul(layer_name, layer_name_len,
					 GFP_KERNEL);
	if (!effect->layer_name) {
		kfree(effect);
		return -ENOMEM;
	}
	effect->layer_name_len = layer_name_len;
	effect->skip_generation_source_id = skip_generation_source_id;
	memcpy(effect->skip_generation_root_guid, skip_generation_root_guid,
	       sizeof(effect->skip_generation_root_guid));
	list_add_tail(&effect->link, effects);
	return 0;
}

static long pkm_lcs_transaction_layer_delete_effects_apply(
	struct list_head *effects, const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_transaction_layer_delete_effect *effect;

	if (!effects || !limits)
		return -EINVAL;

	list_for_each_entry(effect, effects, link) {
		long ret;

		ret = pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
			effect->layer_name, effect->layer_name_len,
			limits->request_timeout_ms,
			effect->skip_generation_source_id,
			effect->skip_generation_root_guid, limits, NULL);
		if (ret)
			return ret;
	}

	return 0;
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
	kfree(entry->creator_sid);
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

static void pkm_lcs_transaction_blanket_tombstone_log_destroy(
	struct pkm_lcs_transaction_blanket_tombstone_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->layer);
	if (entry->path) {
		for (i = 0; i < entry->depth; i++)
			kfree(entry->path[i]);
		kfree(entry->path);
	}
	kfree(entry->ancestor_guids);
	kfree(entry->events);
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
	case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE:
		pkm_lcs_transaction_blanket_tombstone_log_destroy(
			&entry->blanket_tombstone);
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
	if (input->creator_sid_len && !input->creator_sid)
		return -EINVAL;
	if (input->parent_depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;
	ret = pkm_lcs_transaction_layer_name_validate(
		input->layer, (u32)input->layer_len);
	if (ret)
		return ret;

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
	entry->create_key.creator_sid_len = input->creator_sid_len;

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
	if (input->creator_sid_len) {
		entry->create_key.creator_sid =
			kmemdup(input->creator_sid, input->creator_sid_len,
				GFP_KERNEL);
		if (!entry->create_key.creator_sid) {
			ret = -ENOMEM;
			goto out_free;
		}
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
	ret = pkm_lcs_transaction_layer_name_validate(
		input->layer, (u32)input->layer_len);
	if (ret)
		return ret;

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

static bool pkm_lcs_transaction_value_event_valid(u32 event_type)
{
	return event_type == REG_WATCH_VALUE_SET ||
	       event_type == REG_WATCH_VALUE_DELETED;
}

static long pkm_lcs_transaction_value_event_bytes_validate(
	const u8 *events, size_t events_len, u32 event_count)
{
	size_t offset = 0;
	u32 i;

	if (!event_count)
		return events || events_len ? -EINVAL : 0;
	if (!events || !events_len)
		return -EINVAL;

	for (i = 0; i < event_count; i++) {
		u32 event_type;
		u32 name_len;

		if (offset > events_len || events_len - offset < 8U)
			return -EINVAL;
		event_type = get_unaligned_le32(events + offset);
		name_len = get_unaligned_le32(events + offset + 4U);
		offset += 8U;
		if (!pkm_lcs_transaction_value_event_valid(event_type) ||
		    !pkm_lcs_transaction_value_name_len_valid(name_len) ||
		    offset > events_len || name_len > events_len - offset)
			return -EINVAL;
		offset += name_len;
	}
	return offset == events_len ? 0 : -EINVAL;
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
	ret = pkm_lcs_transaction_layer_name_validate(
		input->layer, (u32)input->layer_len);
	if (ret)
		return ret;

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

static long pkm_lcs_transaction_blanket_tombstone_log_alloc(
	const struct pkm_lcs_transaction_blanket_tombstone_log_input *input,
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
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (!input->set && input->sequence)
		return -EINVAL;
	if (input->set && !input->sequence)
		return -EINVAL;
	if (input->depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE;
	memcpy(entry->blanket_tombstone.key_guid, input->key_guid,
	       sizeof(entry->blanket_tombstone.key_guid));
	entry->blanket_tombstone.sequence = input->sequence;
	entry->blanket_tombstone.layer_len = (u32)input->layer_len;
	entry->blanket_tombstone.depth = input->depth;
	entry->blanket_tombstone.set = input->set;

	entry->blanket_tombstone.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->blanket_tombstone.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->path, input->depth, &entry->blanket_tombstone.path);
	if (ret)
		goto out_free;

	if (check_mul_overflow((size_t)input->depth,
			       sizeof(*entry->blanket_tombstone.ancestor_guids),
			       &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->blanket_tombstone.ancestor_guids =
		kmemdup(input->ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->blanket_tombstone.ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->blanket_tombstone.ancestor_guids[input->depth - 1],
		   entry->blanket_tombstone.key_guid,
		   sizeof(entry->blanket_tombstone.key_guid))) {
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
	ret = pkm_lcs_transaction_layer_name_validate(
		input->layer, (u32)input->layer_len);
	if (ret)
		return ret;

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
	ret = pkm_lcs_transaction_layer_name_validate(
		input->layer, (u32)input->layer_len);
	if (ret)
		return ret;

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
		case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE:
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

static void pkm_lcs_transaction_watch_context_owners_free(
	struct list_head *owners)
{
	struct pkm_lcs_transaction_watch_context_owner *owner;
	struct pkm_lcs_transaction_watch_context_owner *tmp;

	if (!owners)
		return;
	list_for_each_entry_safe(owner, tmp, owners, link) {
		list_del(&owner->link);
		kfree(owner->ancestor_guids);
		kfree(owner->path);
		kfree(owner);
	}
}

static long pkm_lcs_transaction_append_key_path_invisible_exact(
	struct pkm_lcs_watch_dispatch_context *contexts, u32 context_capacity,
	u32 *index, struct list_head *owners,
	const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	char **parent_path,
	u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	u32 parent_depth, const char *child_name, u32 child_name_len,
	bool replacement_visible)
{
	struct pkm_lcs_transaction_watch_context_owner *owner;
	u8 (*child_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	const char **child_path;
	u32 child_depth;
	u32 required_contexts = replacement_visible ? 3U : 2U;
	size_t child_ancestor_bytes;
	size_t child_path_bytes;

	if (!contexts || !index || !owners || !key_guid || !parent_guid ||
	    !parent_path ||
	    !parent_ancestor_guids || !parent_depth || !child_name ||
	    !child_name_len)
		return -EINVAL;
	if (*index > context_capacity ||
	    context_capacity - *index < required_contexts)
		return -EOVERFLOW;
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
	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner) {
		kfree(child_ancestor_guids);
		kfree(child_path);
		return -ENOMEM;
	}

	memcpy(child_path, parent_path, (size_t)parent_depth * sizeof(*child_path));
	child_path[parent_depth] = child_name;
	memcpy(child_ancestor_guids, parent_ancestor_guids,
	       (size_t)parent_depth * sizeof(*child_ancestor_guids));
	memcpy(child_ancestor_guids[parent_depth], key_guid,
	       sizeof(child_ancestor_guids[parent_depth]));
	INIT_LIST_HEAD(&owner->link);
	owner->path = child_path;
	owner->ancestor_guids = child_ancestor_guids;
	list_add_tail(&owner->link, owners);

	contexts[*index].changed_key_guid = parent_guid;
	contexts[*index].ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])parent_ancestor_guids;
	contexts[*index].resolved_path = (const char * const *)parent_path;
	contexts[*index].path_component_count = parent_depth;
	contexts[*index].event_type = REG_WATCH_SUBKEY_DELETED;
	contexts[*index].name = (const u8 *)child_name;
	contexts[*index].name_len = child_name_len;
	(*index)++;

	if (replacement_visible) {
		contexts[*index] = contexts[*index - 1U];
		contexts[*index].event_type = REG_WATCH_SUBKEY_CREATED;
		(*index)++;
	}

	contexts[*index].changed_key_guid = key_guid;
	contexts[*index].ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])child_ancestor_guids;
	contexts[*index].resolved_path = (const char * const *)child_path;
	contexts[*index].path_component_count = child_depth;
	contexts[*index].event_type = REG_WATCH_KEY_DELETED;
	(*index)++;
	return 0;
}

static long pkm_lcs_transaction_delete_key_post_lookup(
	u32 source_id, struct pkm_lcs_transaction_delete_key_log *entry,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_rsi_lookup_guid_entry_result result = { };
	struct pkm_lcs_rsi_lookup_child_result effective = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u64 next_sequence = 0;
	long ret;

	if (!source_id || !entry || !limits)
		return -EINVAL;
	if (entry->post_lookup_valid)
		return 0;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
		source_id, 0, entry->parent_guid, entry->child_name,
		entry->child_name_len, limits, limits->request_timeout_ms,
		&frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_lookup_guid_entry(
		frame.data, frame.len, response.request_id, next_sequence,
		entry->child_name, entry->child_name_len, entry->key_guid,
		&response.limits, &result);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_lookup_child(
		frame.data, frame.len, response.request_id, next_sequence,
		entry->child_name, entry->child_name_len, layer_snapshot.layers,
		layer_snapshot.layer_count, NULL, 0, &response.limits,
		&effective);
	if (ret)
		goto out_frame;

	entry->target_still_named = result.present != 0;
	entry->replacement_visible =
		effective.found &&
		memcmp(effective.key_guid, entry->key_guid,
		       sizeof(entry->key_guid)) != 0;
	entry->post_lookup_valid = true;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_transaction_apply_delete_key_orphan_effects(
	u32 source_id, struct pkm_lcs_transaction_delete_key_log *entry,
	const struct pkm_lcs_runtime_limits *limits)
{
	u32 live_refs = 0;
	u32 marked = 0;
	long ret;

	if (!source_id || !entry || !limits)
		return -EINVAL;

	ret = pkm_lcs_transaction_delete_key_post_lookup(source_id, entry,
							limits);
	if (ret)
		return ret;
	if (entry->target_still_named)
		return 0;

	ret = pkm_lcs_key_fd_mark_orphaned_no_watch(
		source_id, entry->key_guid, &marked, &live_refs);
	if (ret)
		return ret;

	if (!live_refs)
		(void)pkm_lcs_source_dispatch_drop_key_request_with_limits(
			source_id, 0, entry->key_guid, limits, NULL);
	return 0;
}

static long pkm_lcs_transaction_log_apply_orphan_effects(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_transaction_log_entry *entry;
	long ret;

	if (!txn || !source_id || !limits)
		return -EINVAL;

	list_for_each_entry(entry, &txn->mutation_log, link) {
		switch (entry->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
			ret = pkm_lcs_transaction_apply_delete_key_orphan_effects(
				source_id, &entry->delete_key, limits);
			if (ret)
				return ret;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
		case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE:
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			break;
		default:
			return -EIO;
		}
	}
	return 0;
}

static long pkm_lcs_transaction_entry_layer_metadata_path(
	const struct pkm_lcs_transaction_log_entry *entry,
	const u8 **key_guid_out, char ***path_out, u32 *depth_out,
	const char **layer_name_out, u32 *layer_name_len_out,
	bool *matches_path_out)
{
	const u8 *key_guid = NULL;
	char **path = NULL;
	u32 depth = 0;
	long ret;

	if (!layer_name_out || !layer_name_len_out || !matches_path_out)
		return -EINVAL;
	if (key_guid_out)
		*key_guid_out = NULL;
	if (path_out)
		*path_out = NULL;
	if (depth_out)
		*depth_out = 0;

	switch (entry->kind) {
	case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		if (entry->create_key.parent_depth !=
		    ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix)) {
			*matches_path_out = false;
			return 0;
		}
		ret = pkm_lcs_transaction_layer_metadata_prefix_matches(
			entry->create_key.parent_path,
			entry->create_key.parent_depth, matches_path_out);
		if (ret || !*matches_path_out)
			return ret;
		if (!entry->create_key.child_name ||
		    !entry->create_key.child_name_len)
			return -EIO;
		key_guid = entry->create_key.target_guid;
		path = entry->create_key.parent_path;
		depth = entry->create_key.parent_depth;
		*layer_name_out = entry->create_key.child_name;
		*layer_name_len_out = entry->create_key.child_name_len;
		if (key_guid_out)
			*key_guid_out = key_guid;
		if (path_out)
			*path_out = path;
		if (depth_out)
			*depth_out = depth;
		return 0;
	case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		key_guid = entry->set_security.key_guid;
		path = entry->set_security.path;
		depth = entry->set_security.depth;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
		key_guid = entry->set_value.key_guid;
		path = entry->set_value.path;
		depth = entry->set_value.depth;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
		if (entry->delete_key.parent_depth !=
		    ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix)) {
			*matches_path_out = false;
			return 0;
		}
		ret = pkm_lcs_transaction_layer_metadata_prefix_matches(
			entry->delete_key.parent_path,
			entry->delete_key.parent_depth, matches_path_out);
		if (ret || !*matches_path_out)
			return ret;
		if (!entry->delete_key.child_name ||
		    !entry->delete_key.child_name_len)
			return -EIO;
		key_guid = entry->delete_key.key_guid;
		path = entry->delete_key.parent_path;
		depth = entry->delete_key.parent_depth;
		*layer_name_out = entry->delete_key.child_name;
		*layer_name_len_out = entry->delete_key.child_name_len;
		if (key_guid_out)
			*key_guid_out = key_guid;
		if (path_out)
			*path_out = path;
		if (depth_out)
			*depth_out = depth;
		return 0;
	default:
		*matches_path_out = false;
		return 0;
	}

	ret = pkm_lcs_transaction_layer_metadata_path(
		path, depth, layer_name_out, layer_name_len_out,
		matches_path_out);
	if (ret || !*matches_path_out)
		return ret;

	if (key_guid_out)
		*key_guid_out = key_guid;
	if (path_out)
		*path_out = path;
	if (depth_out)
		*depth_out = depth;
	return 0;
}

static long pkm_lcs_transaction_layer_metadata_seen_after(
	struct pkm_lcs_transaction_fd *txn,
	const struct pkm_lcs_transaction_log_entry *current_entry,
	const char *layer_name, u32 layer_name_len, bool *seen_out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	bool after_current = false;

	if (!txn || !current_entry || !layer_name || !seen_out)
		return -EINVAL;
	*seen_out = false;

	list_for_each_entry(entry, &txn->mutation_log, link) {
		const char *entry_layer = NULL;
		u32 entry_layer_len = 0;
		bool matches_path = false;
		bool matches_layer = false;
		long ret;

		if (entry == current_entry) {
			after_current = true;
			continue;
		}
		if (!after_current)
			continue;

		ret = pkm_lcs_transaction_entry_layer_metadata_path(
			entry, NULL, NULL, NULL, &entry_layer, &entry_layer_len,
			&matches_path);
		if (ret)
			return ret;
		if (!matches_path)
			continue;

		ret = pkm_lcs_transaction_layer_name_casefold_eq(
			entry_layer, entry_layer_len, layer_name,
			layer_name_len, &matches_layer);
		if (ret)
			return ret;
		if (matches_layer) {
			*seen_out = true;
			return 0;
		}
	}

	return after_current ? 0 : -EIO;
}

static long pkm_lcs_transaction_log_apply_layer_metadata_effects(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	struct list_head *layer_delete_effects,
	const struct pkm_lcs_runtime_limits *limits,
	bool *layer_recovery_required_out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];

	if (!txn || !source_id || !layer_delete_effects ||
	    !limits || !layer_recovery_required_out)
		return -EINVAL;
	*layer_recovery_required_out = false;

	spin_lock(&txn->lock);
	if (txn->bound_source_id != source_id) {
		spin_unlock(&txn->lock);
		return -EIO;
	}
	memcpy(root_guid, txn->bound_root_guid, sizeof(root_guid));
	spin_unlock(&txn->lock);

	list_for_each_entry(entry, &txn->mutation_log, link) {
		const u8 *key_guid = NULL;
		char **path = NULL;
		const char *layer_name = NULL;
		u32 layer_name_len = 0;
		u32 depth = 0;
		bool matches_path = false;
		bool seen_after = false;
		long ret;

		ret = pkm_lcs_transaction_entry_layer_metadata_path(
			entry, &key_guid, &path, &depth, &layer_name,
			&layer_name_len, &matches_path);
		if (ret)
			return ret;
		if (!matches_path)
			continue;

		ret = pkm_lcs_transaction_layer_metadata_seen_after(
			txn, entry, layer_name, layer_name_len, &seen_after);
		if (ret)
			return ret;
		if (seen_after)
			continue;

		switch (entry->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY: {
			const char *created_path[
				ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix) +
				1U];
			bool effective_changed = false;
			u32 i;

			if (depth !=
			    ARRAY_SIZE(pkm_lcs_transaction_layer_metadata_prefix))
				return -EIO;
			for (i = 0; i < depth; i++)
				created_path[i] = path[i];
			created_path[depth] = layer_name;
			ret = pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
				source_id, key_guid, created_path, depth + 1U,
				entry->create_key.creator_sid,
				entry->create_key.creator_sid_len, true, limits,
				&effective_changed);
			if (!ret && effective_changed)
				*layer_recovery_required_out = true;
			break;
		}
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
			ret = pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
				source_id, key_guid,
				(const char * const *)path, depth, NULL, 0,
				false, limits, NULL);
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE: {
			bool effective_changed = false;

			ret = pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
				source_id, key_guid,
				(const char * const *)path, depth, NULL, 0,
				false, limits,
				&effective_changed);
			if (!ret && effective_changed)
				*layer_recovery_required_out = true;
			break;
		}
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY: {
			bool is_base = false;

			ret = pkm_lcs_transaction_layer_name_is_base(
				layer_name, layer_name_len, &is_base);
			if (ret)
				return ret;
			if (is_base)
				break;
			ret = pkm_lcs_transaction_layer_delete_effect_append(
				layer_delete_effects, layer_name, layer_name_len,
				source_id, root_guid);
			break;
		}
		default:
			ret = -EIO;
			break;
		}
		if (ret)
			return ret;
	}

	return 0;
}

static long pkm_lcs_transaction_append_delete_key_exact(
	u32 source_id, struct pkm_lcs_transaction_delete_key_log *entry,
	struct pkm_lcs_watch_dispatch_context *contexts, u32 context_capacity,
	u32 *index, struct list_head *owners,
	const struct pkm_lcs_runtime_limits *limits)
{
	long ret;

	if (!source_id || !entry || !limits)
		return -EINVAL;

	ret = pkm_lcs_transaction_delete_key_post_lookup(source_id, entry,
							limits);
	if (ret)
		return ret;
	if (entry->target_still_named)
		return 0;

	return pkm_lcs_transaction_append_key_path_invisible_exact(
		contexts, context_capacity, index, owners,
		entry->key_guid, entry->parent_guid, entry->parent_path,
		entry->parent_ancestor_guids, entry->parent_depth,
		entry->child_name, entry->child_name_len,
		entry->replacement_visible);
}

static long pkm_lcs_transaction_append_hide_key_exact(
	u32 source_id, struct pkm_lcs_transaction_hide_key_log *entry,
	struct pkm_lcs_watch_dispatch_context *contexts, u32 context_capacity,
	u32 *index, struct list_head *owners,
	const struct pkm_lcs_runtime_limits *limits)
{
	long ret;

	if (!source_id || !entry || !limits)
		return -EINVAL;

	if (!entry->post_lookup_valid) {
		struct pkm_lcs_layer_snapshot layer_snapshot = { };
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_rsi_lookup_child_result effective = { };
		u64 next_sequence = 0;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			return ret;
		ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
		if (ret)
			return ret;

		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
			source_id, 0, entry->parent_guid, entry->child_name,
			entry->child_name_len, limits, limits->request_timeout_ms,
			&frame, &response, NULL);
		if (ret)
			goto out_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id, next_sequence,
			entry->child_name, entry->child_name_len,
			layer_snapshot.layers, layer_snapshot.layer_count, NULL,
			0, &response.limits, &effective);
		if (ret)
			goto out_frame;

		if (effective.found) {
			if (!memcmp(effective.key_guid, entry->key_guid,
				    sizeof(entry->key_guid)))
				entry->target_still_visible = true;
			else
				entry->replacement_visible = true;
		}
		entry->post_lookup_valid = true;

out_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
		if (ret)
			return ret;
	}
	if (entry->target_still_visible)
		return 0;

	return pkm_lcs_transaction_append_key_path_invisible_exact(
		contexts, context_capacity, index, owners,
		entry->key_guid, entry->parent_guid, entry->parent_path,
		entry->parent_ancestor_guids, entry->parent_depth,
		entry->child_name, entry->child_name_len,
		entry->replacement_visible);
}

static long pkm_lcs_transaction_log_dispatch_watch_batch(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	const struct pkm_lcs_runtime_limits *limits,
	u32 *internal_watch_effects_out)
{
	struct pkm_lcs_watch_dispatch_context *contexts;
	struct pkm_lcs_transaction_log_entry *entry;
	LIST_HEAD(context_owners);
	size_t context_capacity_size;
	u32 context_capacity;
	u32 index = 0;
	u32 i;
	long ret;

	if (internal_watch_effects_out)
		*internal_watch_effects_out = 0;
	if (!txn || !limits)
		return -EINVAL;
	if (!txn->mutation_log_entries)
		return 0;

	context_capacity_size = 0;
	list_for_each_entry(entry, &txn->mutation_log, link) {
		size_t additional;

		switch (entry->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
			additional = 1;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
			additional = entry->delete_value.event_type ? 1 : 0;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE:
			additional = entry->blanket_tombstone.event_count;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			additional = 3;
			break;
		default:
			return -EIO;
		}
		if (check_add_overflow(context_capacity_size, additional,
				       &context_capacity_size) ||
		    context_capacity_size > U32_MAX)
			return -EOVERFLOW;
	}
	if (!context_capacity_size)
		return 0;
	context_capacity = (u32)context_capacity_size;
	contexts = kcalloc(context_capacity, sizeof(*contexts), GFP_KERNEL);
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
		case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE: {
			size_t offset = 0;
			u32 i;

			for (i = 0; i < entry->blanket_tombstone.event_count;
			     i++) {
				u32 event_type;
				u32 name_len;

				if (index >= context_capacity ||
				    offset > entry->blanket_tombstone.events_len ||
				    entry->blanket_tombstone.events_len - offset <
					    8U) {
					ret = -EIO;
					goto out_free;
				}
				event_type = get_unaligned_le32(
					entry->blanket_tombstone.events + offset);
				name_len = get_unaligned_le32(
					entry->blanket_tombstone.events + offset +
					4U);
				offset += 8U;
				if (!pkm_lcs_transaction_value_event_valid(
					    event_type) ||
				    offset >
					    entry->blanket_tombstone.events_len ||
				    name_len >
					    entry->blanket_tombstone.events_len -
						    offset) {
					ret = -EIO;
					goto out_free;
				}

				contexts[index].changed_key_guid =
					entry->blanket_tombstone.key_guid;
				contexts[index].ancestor_guids =
					entry->blanket_tombstone.ancestor_guids;
				contexts[index].resolved_path =
					(const char * const *)
						entry->blanket_tombstone.path;
				contexts[index].path_component_count =
					entry->blanket_tombstone.depth;
				contexts[index].event_type = event_type;
				contexts[index].name =
					entry->blanket_tombstone.events + offset;
				contexts[index].name_len = name_len;
				offset += name_len;
				index++;
			}
			if (offset != entry->blanket_tombstone.events_len) {
				ret = -EIO;
				goto out_free;
			}
			break;
		}
		case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
			ret = pkm_lcs_transaction_append_hide_key_exact(
				source_id, &entry->hide_key, contexts,
				context_capacity, &index, &context_owners,
				limits);
			if (ret)
				goto out_free;
			break;
		case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
			ret = pkm_lcs_transaction_append_delete_key_exact(
				source_id, &entry->delete_key, contexts,
				context_capacity, &index, &context_owners,
				limits);
			if (ret)
				goto out_free;
			break;
		default:
			ret = -EIO;
			goto out_free;
		}
	}
	for (i = 0; i < index; i++)
		contexts[i].limits = limits;

	ret = pkm_lcs_key_fd_dispatch_watch_event_context_batch_effects(
		contexts, index, internal_watch_effects_out);

out_free:
	pkm_lcs_transaction_watch_context_owners_free(&context_owners);
	kfree(contexts);
	return ret;
}

static long pkm_lcs_transaction_fd_apply_commit_response_under_bind(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id,
	u32 status, bool detached, u32 *final_state_out,
	bool *release_counter_out, bool *source_down_required_out,
	struct list_head *layer_delete_effects,
	const struct pkm_lcs_runtime_limits *limits,
	u32 *internal_watch_effects_out)
{
	bool release_counter = false;
	bool clear_log = false;
	bool stop_timer = false;
	bool wake = false;
	bool layer_recovery_required = false;
	u32 final_state = 0;
	u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = { };
	long ret = 0;

	if (!txn || !transaction_id || !source_id || !final_state_out ||
	    !release_counter_out || !source_down_required_out ||
	    !layer_delete_effects || !limits)
		return -EINVAL;
	*final_state_out = 0;
	*release_counter_out = false;
	*source_down_required_out = false;
	if (internal_watch_effects_out)
		*internal_watch_effects_out = 0;

	if (status == RSI_OK) {
		spin_lock(&txn->lock);
		if (txn->bound_source_id != source_id) {
			spin_unlock(&txn->lock);
			*source_down_required_out = true;
			return -EIO;
		}
		memcpy(root_guid, txn->bound_root_guid, sizeof(root_guid));
		spin_unlock(&txn->lock);

		ret = pkm_lcs_transaction_log_apply_layer_metadata_effects(
			txn, source_id, layer_delete_effects, limits,
			&layer_recovery_required);
		if (ret) {
			*source_down_required_out = true;
			return -EIO;
		}
		ret = pkm_lcs_transaction_fd_apply_success_generation_under_bind(
			txn, transaction_id, source_id);
		if (ret) {
			*source_down_required_out = true;
			return -EIO;
		}
		if (layer_recovery_required) {
			struct pkm_lcs_layer_operation_recovery_result recovery = { };

			ret = pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
				source_id, root_guid, limits, &recovery);
			if (ret) {
				*source_down_required_out = true;
				return -EIO;
			}
		}
		ret = pkm_lcs_transaction_log_apply_orphan_effects(
			txn, source_id, limits);
		if (ret) {
			*source_down_required_out = true;
			return -EIO;
		}
		(void)pkm_lcs_transaction_log_dispatch_watch_batch(
			txn, source_id, limits, internal_watch_effects_out);
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

static long pkm_lcs_transaction_fd_commit_from_state_timeout_with_limits(
	struct pkm_lcs_transaction_fd *txn,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms);

static long pkm_lcs_transaction_fd_commit_from_state_timeout(
	struct pkm_lcs_transaction_fd *txn, u32 timeout_ms)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_transaction_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_transaction_fd_commit_from_state_timeout_with_limits(
		txn, &limits, timeout_ms);
}

static long pkm_lcs_transaction_fd_commit_from_state_timeout_with_limits(
	struct pkm_lcs_transaction_fd *txn,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	LIST_HEAD(layer_delete_effects);
	u64 transaction_id;
	u32 source_id;
	u32 state;
	u32 final_state = 0;
	u32 internal_watch_effects = 0;
	long ret;
	u32 count;
	bool release_counter = false;
	bool apply_layer_delete_effects = false;
	bool mark_source_down = false;
	bool source_down_required = false;
	u32 mark_source_down_id = 0;

	if (!txn || !limits)
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

	ret = pkm_lcs_source_commit_transaction_round_trip_timeout_with_limits(
		source_id, transaction_id, limits, timeout_ms, &response,
		&enqueue);
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
					&source_down_required,
					&layer_delete_effects,
					limits,
					&internal_watch_effects);
			if (!apply_ret) {
				apply_layer_delete_effects = true;
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
		&release_counter, &source_down_required, &layer_delete_effects,
		limits,
		&internal_watch_effects);
	if (ret) {
		if (source_down_required) {
			mark_source_down = true;
			mark_source_down_id = source_id;
			ret = -EIO;
		}
		goto out_unlock;
	}
	apply_layer_delete_effects = true;

	if (release_counter)
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
	if (final_state == REG_TXN_COMMITTED)
		ret = 0;
	else
		ret = -ETIMEDOUT;

out_unlock:
	mutex_unlock(&txn->bind_lock);
	if (apply_layer_delete_effects &&
	    !(internal_watch_effects &
	      PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE)) {
		long effects_ret;

		effects_ret = pkm_lcs_transaction_layer_delete_effects_apply(
			&layer_delete_effects, limits);
		if (effects_ret) {
			mark_source_down = true;
			mark_source_down_id = source_id;
			ret = -EIO;
		}
	}
	if (mark_source_down)
		pkm_lcs_source_mark_down_by_id(mark_source_down_id);
	pkm_lcs_transaction_layer_delete_effects_destroy(
		&layer_delete_effects);
	return ret;
}

static long pkm_lcs_transaction_fd_commit_from_state(
	struct pkm_lcs_transaction_fd *txn)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_transaction_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_transaction_fd_commit_from_state_timeout_with_limits(
		txn, &limits, limits.request_timeout_ms);
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
		case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE:
			out->last_sequence =
				last->blanket_tombstone.sequence;
			out->last_parent_depth =
				last->blanket_tombstone.depth;
			memcpy(out->last_key_guid,
			       last->blanket_tombstone.key_guid,
			       sizeof(out->last_key_guid));
			strscpy(out->last_layer,
				last->blanket_tombstone.layer,
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

static long pkm_lcs_transaction_log_entry_layer_matches_with_limits(
	const struct pkm_lcs_transaction_log_entry *entry,
	const char *target_layer, u32 target_layer_len,
	const struct pkm_lcs_runtime_limits *limits, bool *matches)
{
	const char *entry_layer = NULL;
	u32 entry_layer_len = 0;

	if (!entry || !target_layer || !limits || !matches)
		return -EINVAL;
	*matches = false;

	switch (entry->kind) {
	case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		entry_layer = entry->create_key.layer;
		entry_layer_len = entry->create_key.layer_len;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY:
		return 0;
	case PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE:
		entry_layer = entry->set_value.layer;
		entry_layer_len = entry->set_value.layer_len;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE:
		entry_layer = entry->delete_value.layer;
		entry_layer_len = entry->delete_value.layer_len;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE:
		entry_layer = entry->blanket_tombstone.layer;
		entry_layer_len = entry->blanket_tombstone.layer_len;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY:
		entry_layer = entry->delete_key.layer;
		entry_layer_len = entry->delete_key.layer_len;
		break;
	case PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY:
		entry_layer = entry->hide_key.layer;
		entry_layer_len = entry->hide_key.layer_len;
		break;
	default:
		return -EIO;
	}

	return pkm_lcs_transaction_layer_name_casefold_eq_with_limits(
		entry_layer, entry_layer_len, target_layer, target_layer_len,
		limits, matches);
}

static long pkm_lcs_transaction_log_touches_layer_with_limits(
	const struct pkm_lcs_transaction_fd *txn, const char *layer_name,
	u32 layer_name_len, const struct pkm_lcs_runtime_limits *limits,
	bool *touches)
{
	struct pkm_lcs_transaction_log_entry *entry;
	bool found = false;
	long ret;

	if (!txn || !layer_name || !limits || !touches)
		return -EINVAL;
	*touches = false;

	list_for_each_entry(entry, &txn->mutation_log, link) {
		bool matches = false;

		ret = pkm_lcs_transaction_log_entry_layer_matches_with_limits(
			entry, layer_name, layer_name_len, limits, &matches);
		if (ret)
			return ret;
		if (matches)
			found = true;
	}

	*touches = found;
	return 0;
}

long pkm_lcs_transaction_fd_abort_layer_writers_with_limits(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_transaction_layer_abort_result *result)
{
	struct pkm_lcs_transaction_layer_abort_result local = { };
	struct pkm_lcs_transaction_fd *txn;
	bool is_base = false;
	long ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!layer_name || !layer_name_len || !limits)
		return -EINVAL;

	ret = pkm_lcs_transaction_layer_name_casefold_eq_with_limits(
		layer_name, layer_name_len, pkm_lcs_transaction_base_layer_name,
		sizeof(pkm_lcs_transaction_base_layer_name) - 1, limits,
		&is_base);
	if (ret)
		return ret;
	if (is_base)
		return -EINVAL;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	list_for_each_entry(txn, &pkm_lcs_transaction_registry, registry_link) {
		bool release_counter = false;
		bool dispatch_abort = false;
		bool clear_log = false;
		bool stop_timer = false;
		bool wake = false;
		u64 transaction_id = 0;
		u32 source_id = 0;
		u32 count = 0;

		if (local.inspected_transaction_count == U32_MAX) {
			ret = -EOVERFLOW;
			break;
		}
		local.inspected_transaction_count++;

		mutex_lock(&txn->bind_lock);
		spin_lock(&txn->lock);
		if (txn->state == REG_TXN_ACTIVE_BOUND) {
			transaction_id = txn->transaction_id;
			source_id = txn->bound_source_id;
		}
		spin_unlock(&txn->lock);

		if (transaction_id && source_id) {
			bool touches = false;

			ret = pkm_lcs_transaction_log_touches_layer_with_limits(
				txn, layer_name, layer_name_len, limits,
				&touches);
			if (ret) {
				mutex_unlock(&txn->bind_lock);
				break;
			}

			if (touches) {
				spin_lock(&txn->lock);
				if (txn->state == REG_TXN_ACTIVE_BOUND &&
				    txn->transaction_id == transaction_id &&
				    txn->bound_source_id == source_id) {
					txn->state = REG_TXN_ABORTED;
					txn->commit_in_flight = false;
					txn->timeout_abort_pending = false;
					stop_timer = true;
					clear_log = true;
					wake = true;
					release_counter = true;
					dispatch_abort = true;
				}
				spin_unlock(&txn->lock);
			}
		}

		if (stop_timer)
			timer_delete_sync(&txn->timeout_timer);
		if (clear_log)
			pkm_lcs_transaction_log_clear(txn);
		mutex_unlock(&txn->bind_lock);

		if (dispatch_abort) {
			long dispatch_ret;

			if (local.affected_bound_transaction_count == U32_MAX) {
				ret = -EOVERFLOW;
				break;
			}
			local.affected_bound_transaction_count++;
			dispatch_ret =
				pkm_lcs_source_dispatch_abort_transaction_request(
					source_id, transaction_id, NULL);
			if (!dispatch_ret)
				local.abort_dispatched_count++;
			else if (!ret)
				ret = dispatch_ret;
		}
		if (release_counter) {
			long release_ret;

			release_ret = pkm_lcs_source_bound_transaction_release(
				source_id, &count);
			if (release_ret && !ret)
				ret = release_ret;
		}
		if (wake)
			wake_up_all(&txn->wait);
		if (ret)
			break;
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);

	if (result)
		*result = local;
	return ret;
}

long pkm_lcs_transaction_fd_abort_layer_writers(
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_transaction_layer_abort_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_transaction_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_transaction_fd_abort_layer_writers_with_limits(
		layer_name, layer_name_len, &limits, result);
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
	u32 source_id, u64 transaction_id, u32 status,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_transaction_fd *txn;
	struct pkm_lcs_transaction_fd *destroy_txn = NULL;
	LIST_HEAD(layer_delete_effects);
	bool release_counter = false;
	bool source_down_required = false;
	bool apply_layer_delete_effects = false;
	u32 final_state = 0;
	u32 internal_watch_effects = 0;
	u32 count = 0;
	long ret = -ENOENT;

	if (!source_id || !transaction_id || !limits)
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
			&final_state, &release_counter, &source_down_required,
			&layer_delete_effects, limits, &internal_watch_effects);
		if (!ret) {
			bool destroy_detached;

			apply_layer_delete_effects = true;
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
	if (apply_layer_delete_effects &&
	    !(internal_watch_effects &
	      PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE)) {
		long effects_ret;

		effects_ret = pkm_lcs_transaction_layer_delete_effects_apply(
			&layer_delete_effects, limits);
		if (effects_ret && !ret)
			ret = effects_ret;
	}
	pkm_lcs_transaction_layer_delete_effects_destroy(
		&layer_delete_effects);
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

long pkm_lcs_transaction_fd_begin_blanket_tombstone_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_blanket_tombstone_log_input *input,
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

	ret = pkm_lcs_transaction_blanket_tombstone_log_alloc(input, &entry);
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

long pkm_lcs_transaction_fd_set_blanket_tombstone_events(
	struct pkm_lcs_transaction_mutation_handle *handle,
	const u8 *events, size_t events_len, u32 event_count)
{
	u8 *copy = NULL;
	long ret;

	if (!handle || !handle->active || !handle->entry)
		return -EINVAL;
	if (handle->entry->kind !=
	    PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE)
		return -EINVAL;
	if (handle->entry->blanket_tombstone.events)
		return -EINVAL;

	ret = pkm_lcs_transaction_value_event_bytes_validate(
		events, events_len, event_count);
	if (ret)
		return ret;

	if (events_len) {
		copy = kmemdup(events, events_len, GFP_KERNEL);
		if (!copy)
			return -ENOMEM;
	}

	handle->entry->blanket_tombstone.events = copy;
	handle->entry->blanket_tombstone.events_len = events_len;
	handle->entry->blanket_tombstone.event_count = event_count;
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

u32 pkm_lcs_kunit_transaction_fd_poll_mask(int fd)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 mask;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return (u32)(EPOLLERR | EPOLLHUP);

	mask = (u32)pkm_lcs_transaction_fd_poll(fd_file(held), NULL);
	fdput(held);
	return mask;
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
		pkm_lcs_runtime_transaction_timeout_ms());
}

SYSCALL_DEFINE0(reg_begin_transaction)
{
	return pkm_lcs_reg_begin_transaction();
}
