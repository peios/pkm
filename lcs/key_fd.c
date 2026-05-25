// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS key-fd carrier.
 *
 * PSD-005 key fds are capabilities: open-time AccessCheck grants are captured
 * once on an anonymous fd and later operations consult that stored mask.
 */

#include <crypto/sha2.h>
#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/wait.h>

#include <pkm/lcs.h>
#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"
#include "transaction_fd.h"

#define PKM_LCS_MAX_SD_BYTES 65535U
#define PKM_LCS_BACKUP_FORMAT_VERSION 21U
#define PKM_LCS_BACKUP_MIN_READER_VERSION 21U
#define PKM_LCS_BACKUP_TRAILER_PREFIX_LEN 14U
#define PKM_LCS_WATCH_NOTIFY_ACTION_ARM 1U
#define PKM_LCS_WATCH_NOTIFY_ACTION_DISARM 2U
#define PKM_LCS_WATCH_REGISTRY_BITS 8U
#define PKM_LCS_KEY_REF_BITS 8U
#define PKM_LCS_BACKUP_RESTORE_FD_OP_BACKUP_OUTPUT 0U
#define PKM_LCS_BACKUP_RESTORE_FD_OP_RESTORE_INPUT 1U

struct pkm_lcs_key_fd_string_view {
	const u8 *bytes;
	u32 len;
};

struct pkm_lcs_key_fd_transaction_burst_entry {
	struct list_head link;
	struct pkm_lcs_key_fd *watcher;
	u32 event_count;
	bool overflow;
};

struct pkm_lcs_key_fd_copyout_ops {
	bool (*write)(void *ctx, void __user *dst, const void *src, size_t len);
	void *ctx;
};

struct pkm_lcs_watch_notify_plan_copy {
	u32 action;
	u32 filter;
	u8 subtree;
	u8 replaces_existing;
	u8 discard_pending_events;
	u8 _pad;
};

struct pkm_lcs_key_fd_watch_event {
	struct list_head link;
	u32 event_type;
	u32 total_len;
	u8 bytes[];
};

struct pkm_lcs_subtree_watch_entry {
	struct hlist_node link;
	u8 guid[PKM_LCS_GUID_BYTES];
	u32 refcount;
};

struct pkm_lcs_key_fd;
struct pkm_lcs_internal_watch;

enum pkm_lcs_watch_registry_entry_kind {
	PKM_LCS_WATCH_REGISTRY_KEY_FD = 1,
	PKM_LCS_WATCH_REGISTRY_INTERNAL = 2,
};

struct pkm_lcs_watch_registry_entry {
	struct hlist_node link;
	u8 guid[PKM_LCS_GUID_BYTES];
	u32 source_id;
	enum pkm_lcs_watch_registry_entry_kind kind;
	bool subtree;
	bool linked;
	union {
		struct pkm_lcs_key_fd *key_fd;
		struct pkm_lcs_internal_watch *internal;
	} owner;
};

struct pkm_lcs_internal_watch {
	struct pkm_lcs_watch_registry_entry registry;
	enum pkm_lcs_internal_watch_target target;
};

struct pkm_lcs_internal_watch_event {
	struct list_head link;
	u8 guid[PKM_LCS_GUID_BYTES];
	u8 root_guid[PKM_LCS_GUID_BYTES];
	char **resolved_path;
	char *name;
	u32 source_id;
	u32 event_type;
	u32 path_component_count;
	u32 name_len;
	enum pkm_lcs_internal_watch_target target;
};

struct pkm_lcs_internal_self_watch_state {
	struct pkm_lcs_internal_watch registry;
	struct pkm_lcs_internal_watch layers;
	struct pkm_lcs_internal_watch fallback;
	u32 source_id;
	enum pkm_lcs_internal_self_watch_mode mode;
	u32 watch_count;
};

struct pkm_lcs_key_ref_entry {
	struct hlist_node link;
	struct list_head fds;
	u32 source_id;
	u32 refcount;
	bool orphaned;
	u8 guid[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_key_fd {
	u32 source_id;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u32 granted_access;
	u64 source_restart_generation_seen;
	u32 path_component_count;
	char **resolved_path;
	u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	struct mutex watch_lock;
	wait_queue_head_t watch_wait;
	struct list_head watch_events;
	struct list_head key_ref_node;
	struct pkm_lcs_watch_registry_entry watch_registry_entry;
	struct pkm_lcs_key_ref_entry *key_ref;
	u32 watch_filter;
	u32 watch_pending_events;
	bool watch_has_overflow;
	bool watch_subtree;
	bool watch_registry_linked;
	bool watch_subtree_registered;
	bool orphaned;
	bool watch_armed;
	bool key_ref_linked;
	bool source_restart_generation_tracked;
	bool published;
};

struct pkm_lcs_get_security_result {
	u8 *sd;
	size_t sd_len;
};

struct pkm_lcs_set_value_input {
	char *value_name;
	u8 *data;
	struct pkm_lcs_create_layer_target target;
	struct pkm_lcs_runtime_limits limits;
};

struct pkm_lcs_delete_value_input {
	char *value_name;
	struct pkm_lcs_create_layer_target target;
	struct pkm_lcs_runtime_limits limits;
};

struct pkm_lcs_blanket_tombstone_input {
	struct pkm_lcs_create_layer_target target;
	struct pkm_lcs_runtime_limits limits;
	bool set;
};

struct pkm_lcs_hide_key_input {
	struct pkm_lcs_create_layer_target target;
	struct pkm_lcs_runtime_limits limits;
};

struct pkm_lcs_delete_key_input {
	struct pkm_lcs_create_layer_target target;
	struct pkm_lcs_runtime_limits limits;
};

struct pkm_lcs_effective_value_snapshot {
	struct pkm_lcs_source_response_frame frame;
	struct pkm_lcs_rsi_query_value_result result;
};

struct pkm_lcs_value_watch_event_bytes {
	u8 *data;
	u32 len;
	u32 count;
};

struct pkm_lcs_delete_key_post_lookup {
	bool target_still_named;
	bool replacement_visible;
};

static void pkm_lcs_value_watch_event_bytes_destroy(
	struct pkm_lcs_value_watch_event_bytes *events);
static void pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
	struct pkm_lcs_runtime_limits *limits);

static const struct file_operations pkm_lcs_key_fd_fops;
static DEFINE_MUTEX(pkm_lcs_watch_registry_lock);
static DEFINE_HASHTABLE(pkm_lcs_watch_map, PKM_LCS_WATCH_REGISTRY_BITS);
static DEFINE_HASHTABLE(pkm_lcs_subtree_watch_set,
			PKM_LCS_WATCH_REGISTRY_BITS);
static DEFINE_MUTEX(pkm_lcs_key_ref_lock);
static DEFINE_HASHTABLE(pkm_lcs_key_ref_map, PKM_LCS_KEY_REF_BITS);
static struct pkm_lcs_internal_self_watch_state pkm_lcs_internal_self_watch;

extern int lcs_rust_validate_key_fd_open_view(
	const u8 *key_guid, u32 granted_access,
	const struct pkm_lcs_key_fd_string_view *path_components,
	size_t path_component_count,
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES], size_t ancestor_count,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_key_fd_fixed_ioctl_access_gate(u32 granted_access,
						   u32 ioctl_number);
extern int lcs_rust_key_fd_security_ioctl_access_gate(u32 granted_access,
						      u32 ioctl_number,
						      u32 security_info);
extern int lcs_rust_backup_restore_fd_mode_gate(u32 operation,
						u8 fd_readable,
						u8 fd_writable);
extern int lcs_rust_write_backup_header_record_frame(
	u8 *dst, size_t dst_len, const struct pkm_lcs_runtime_limits *limits,
	u32 format_version, u32 min_reader_version, s64 timestamp_ns,
	const u8 *root_guid, const u8 *hive_name, size_t hive_name_len,
	size_t *written_out);
extern int lcs_rust_write_backup_layer_manifest_record_frame(
	u8 *dst, size_t dst_len, const struct pkm_lcs_runtime_limits *limits,
	const u8 *name, size_t name_len, u32 precedence, u8 enabled,
	const u8 *owner_sid, size_t owner_sid_len, size_t *written_out);
extern int lcs_rust_write_backup_path_entry_record_frame(
	u8 *dst, size_t dst_len, const struct pkm_lcs_runtime_limits *limits,
	const u8 *parent_guid, const u8 *child_name, size_t child_name_len,
	const u8 *child_guid, u8 hidden, const u8 *layer_name,
	size_t layer_name_len, u64 sequence, size_t *written_out);
extern int lcs_rust_write_backup_value_record_frame(
	u8 *dst, size_t dst_len, const struct pkm_lcs_runtime_limits *limits,
	const u8 *key_guid, const u8 *name, size_t name_len, u32 value_type,
	const u8 *data, size_t data_len, const u8 *layer_name,
	size_t layer_name_len, u64 sequence, size_t *written_out);
extern int lcs_rust_write_backup_blanket_tombstone_record_frame(
	u8 *dst, size_t dst_len, const struct pkm_lcs_runtime_limits *limits,
	const u8 *key_guid, const u8 *layer_name, size_t layer_name_len,
	u64 sequence, size_t *written_out);
extern int lcs_rust_write_backup_key_record_frame(
	u8 *dst, size_t dst_len, const u8 *guid, u8 volatile_key, u8 symlink,
	const u8 *security_descriptor, size_t security_descriptor_len,
	s64 last_write_time_ns, size_t *written_out);
extern int lcs_rust_write_backup_trailer_record_frame(
	u8 *dst, size_t dst_len, u64 record_count, const u8 *checksum,
	size_t *written_out);
extern int lcs_rust_security_descriptor_owner_sid(
	const u8 *security_descriptor, size_t security_descriptor_len,
	const u8 **owner_sid_out, size_t *owner_sid_len_out);
extern int lcs_rust_materialize_rsi_query_values_backup_entries(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_backup_value_entry_view *values, size_t value_capacity,
	struct pkm_lcs_backup_blanket_entry_view *blankets,
	size_t blanket_capacity, u32 *value_count_out,
	u32 *blanket_count_out);
extern int lcs_rust_materialize_rsi_enum_children_backup_path_entries(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_backup_path_entry_view *entries, size_t entry_capacity,
	u32 *entry_count_out);
extern int lcs_rust_plan_registry_get_security(
	const u8 *existing_sd, size_t existing_sd_len, u32 security_info,
	u8 *output, size_t output_len, size_t *written_out);
extern int lcs_rust_plan_registry_set_security(
	const u8 *existing_sd, size_t existing_sd_len, const u8 *input_sd,
	size_t input_sd_len, u32 security_info, u8 *output,
	size_t output_len, size_t *written_out);
extern int lcs_rust_plan_key_fd_watch_notify(
	u8 armed, u8 orphaned, u32 filter, u8 subtree, const u8 *reserved,
	struct pkm_lcs_watch_notify_plan_copy *plan_out);
extern int lcs_rust_write_watch_event_record(
	u32 event_type, const u8 *name, size_t name_len, u8 subtree,
	const struct pkm_lcs_key_fd_string_view *path_components,
	size_t path_component_count, u8 *output, size_t output_len,
	u32 *written_out, u8 *overflow_out);
extern int lcs_rust_value_name_casefold_eq(
	const u8 *left, u32 left_len, const u8 *right, u32 right_len,
	const struct pkm_lcs_runtime_limits *limits, u8 *equal_out);
extern int lcs_rust_layer_name_casefold_eq(
	const u8 *left, u32 left_len, const u8 *right, u32 right_len,
	const struct pkm_lcs_runtime_limits *limits, u8 *equal_out);

static void pkm_lcs_get_security_result_destroy(
	struct pkm_lcs_get_security_result *result);
static long pkm_lcs_key_fd_plan_get_security(
	const u8 *existing_sd, size_t existing_sd_len, u32 security_info,
	struct pkm_lcs_get_security_result *out);
static long pkm_lcs_key_fd_mark_orphaned_internal(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out,
	u32 *live_refs_out, bool dispatch_direct_deleted,
	const struct pkm_lcs_runtime_limits *limits);

static u32 pkm_lcs_guid_hash(const u8 guid[PKM_LCS_GUID_BYTES])
{
	return jhash(guid, PKM_LCS_GUID_BYTES, 0);
}

static bool pkm_lcs_guid_equal(const u8 lhs[PKM_LCS_GUID_BYTES],
			       const u8 rhs[PKM_LCS_GUID_BYTES])
{
	return memcmp(lhs, rhs, PKM_LCS_GUID_BYTES) == 0;
}

static bool pkm_lcs_guid_is_nil(const u8 guid[PKM_LCS_GUID_BYTES])
{
	static const u8 nil[PKM_LCS_GUID_BYTES];

	return !guid || pkm_lcs_guid_equal(guid, nil);
}

static u32 pkm_lcs_key_ref_hash(u32 source_id,
				const u8 guid[PKM_LCS_GUID_BYTES])
{
	return jhash_2words(source_id, pkm_lcs_guid_hash(guid), 0);
}

static struct pkm_lcs_key_ref_entry *pkm_lcs_key_ref_find_locked(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES])
{
	struct pkm_lcs_key_ref_entry *entry;

	hash_for_each_possible(pkm_lcs_key_ref_map, entry, link,
			       pkm_lcs_key_ref_hash(source_id, guid)) {
		if (entry->source_id == source_id &&
		    pkm_lcs_guid_equal(entry->guid, guid))
			return entry;
	}
	return NULL;
}

static long pkm_lcs_key_ref_attach(struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_key_ref_entry *entry;
	u32 source_id;

	if (!key_fd || !key_fd->source_id)
		return -EINVAL;
	source_id = key_fd->source_id;

retry:
	mutex_lock(&pkm_lcs_key_ref_lock);
	entry = pkm_lcs_key_ref_find_locked(source_id, key_fd->key_guid);
	if (entry) {
		if (entry->refcount == U32_MAX) {
			mutex_unlock(&pkm_lcs_key_ref_lock);
			return -EOVERFLOW;
		}
		entry->refcount++;
		key_fd->key_ref = entry;
		key_fd->key_ref_linked = true;
		list_add_tail(&key_fd->key_ref_node, &entry->fds);
		mutex_unlock(&pkm_lcs_key_ref_lock);
		return 0;
	}
	mutex_unlock(&pkm_lcs_key_ref_lock);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_HLIST_NODE(&entry->link);
	INIT_LIST_HEAD(&entry->fds);
	entry->source_id = source_id;
	entry->refcount = 1;
	memcpy(entry->guid, key_fd->key_guid, sizeof(entry->guid));

	mutex_lock(&pkm_lcs_key_ref_lock);
	if (pkm_lcs_key_ref_find_locked(source_id, key_fd->key_guid)) {
		mutex_unlock(&pkm_lcs_key_ref_lock);
		kfree(entry);
		goto retry;
	}
	hash_add(pkm_lcs_key_ref_map, &entry->link,
		 pkm_lcs_key_ref_hash(source_id, key_fd->key_guid));
	key_fd->key_ref = entry;
	key_fd->key_ref_linked = true;
	list_add_tail(&key_fd->key_ref_node, &entry->fds);
	mutex_unlock(&pkm_lcs_key_ref_lock);
	return 0;
}

static void pkm_lcs_key_ref_put_for_key_fd(struct pkm_lcs_key_fd *key_fd,
					   bool allow_drop_dispatch)
{
	struct pkm_lcs_key_ref_entry *entry;
	u8 guid[PKM_LCS_GUID_BYTES];
	u32 source_id;

	if (!key_fd || !key_fd->key_ref)
		return;

	mutex_lock(&pkm_lcs_key_ref_lock);
	entry = key_fd->key_ref;
	key_fd->key_ref = NULL;
	if (key_fd->key_ref_linked) {
		list_del_init(&key_fd->key_ref_node);
		key_fd->key_ref_linked = false;
	}
	if (!entry->refcount) {
		mutex_unlock(&pkm_lcs_key_ref_lock);
		return;
	}

	if (allow_drop_dispatch && key_fd->published &&
	    entry->refcount == 1 && (entry->orphaned || key_fd->orphaned)) {
		source_id = entry->source_id;
		memcpy(guid, entry->guid, sizeof(guid));
		(void)pkm_lcs_source_dispatch_drop_key_request(
			source_id, 0, guid, NULL);
	}

	entry->refcount--;
	if (!entry->refcount) {
		hash_del(&entry->link);
		kfree(entry);
	}
	mutex_unlock(&pkm_lcs_key_ref_lock);
}

static struct pkm_lcs_subtree_watch_entry *
pkm_lcs_subtree_watch_find_locked(const u8 guid[PKM_LCS_GUID_BYTES])
{
	struct pkm_lcs_subtree_watch_entry *entry;

	hash_for_each_possible(pkm_lcs_subtree_watch_set, entry, link,
			       pkm_lcs_guid_hash(guid)) {
		if (pkm_lcs_guid_equal(entry->guid, guid))
			return entry;
	}
	return NULL;
}

static long pkm_lcs_subtree_watch_get_locked(
	const u8 guid[PKM_LCS_GUID_BYTES])
{
	struct pkm_lcs_subtree_watch_entry *entry;

	entry = pkm_lcs_subtree_watch_find_locked(guid);
	if (entry) {
		if (entry->refcount == U32_MAX)
			return -EOVERFLOW;
		entry->refcount++;
		return 0;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	memcpy(entry->guid, guid, sizeof(entry->guid));
	entry->refcount = 1;
	hash_add(pkm_lcs_subtree_watch_set, &entry->link,
		 pkm_lcs_guid_hash(guid));
	return 0;
}

static void pkm_lcs_subtree_watch_put_locked(
	const u8 guid[PKM_LCS_GUID_BYTES])
{
	struct pkm_lcs_subtree_watch_entry *entry;

	entry = pkm_lcs_subtree_watch_find_locked(guid);
	if (!entry)
		return;

	entry->refcount--;
	if (entry->refcount)
		return;

	hash_del(&entry->link);
	kfree(entry);
}

static void pkm_lcs_watch_registry_entry_init_key_fd(
	struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_watch_registry_entry *entry;

	entry = &key_fd->watch_registry_entry;
	INIT_HLIST_NODE(&entry->link);
	memcpy(entry->guid, key_fd->key_guid, sizeof(entry->guid));
	entry->source_id = key_fd->source_id;
	entry->kind = PKM_LCS_WATCH_REGISTRY_KEY_FD;
	entry->subtree = key_fd->watch_subtree;
	entry->linked = false;
	entry->owner.key_fd = key_fd;
}

static void pkm_lcs_watch_registry_entry_init_internal(
	struct pkm_lcs_internal_watch *watch, u32 source_id,
	const u8 guid[PKM_LCS_GUID_BYTES],
	enum pkm_lcs_internal_watch_target target)
{
	struct pkm_lcs_watch_registry_entry *entry;

	entry = &watch->registry;
	INIT_HLIST_NODE(&entry->link);
	memcpy(entry->guid, guid, sizeof(entry->guid));
	entry->source_id = source_id;
	entry->kind = PKM_LCS_WATCH_REGISTRY_INTERNAL;
	entry->subtree = true;
	entry->linked = false;
	entry->owner.internal = watch;
	watch->target = target;
}

static void pkm_lcs_watch_registry_entry_link_locked(
	struct pkm_lcs_watch_registry_entry *entry)
{
	if (entry->linked)
		return;

	hash_add(pkm_lcs_watch_map, &entry->link,
		 pkm_lcs_guid_hash(entry->guid));
	entry->linked = true;
}

static void pkm_lcs_watch_registry_entry_unlink_locked(
	struct pkm_lcs_watch_registry_entry *entry)
{
	if (!entry->linked)
		return;

	hash_del(&entry->link);
	INIT_HLIST_NODE(&entry->link);
	entry->linked = false;
}

static void pkm_lcs_key_fd_watch_map_link_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	if (key_fd->watch_registry_linked)
		return;

	pkm_lcs_watch_registry_entry_init_key_fd(key_fd);
	pkm_lcs_watch_registry_entry_link_locked(&key_fd->watch_registry_entry);
	key_fd->watch_registry_linked = true;
}

static void pkm_lcs_key_fd_watch_map_unlink_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	if (!key_fd->watch_registry_linked)
		return;

	pkm_lcs_watch_registry_entry_unlink_locked(&key_fd->watch_registry_entry);
	key_fd->watch_registry_linked = false;
}

static void pkm_lcs_key_fd_watch_registry_remove_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	pkm_lcs_key_fd_watch_map_unlink_locked(key_fd);
	if (key_fd->watch_subtree_registered) {
		pkm_lcs_subtree_watch_put_locked(key_fd->key_guid);
		key_fd->watch_subtree_registered = false;
	}
}

static bool pkm_lcs_key_fd_default_copyout_write(void *ctx, void __user *dst,
						 const void *src, size_t len)
{
	(void)ctx;

	if (!dst)
		return false;
	return copy_to_user(dst, src, len) == 0;
}

static const struct pkm_lcs_key_fd_copyout_ops
	pkm_lcs_key_fd_default_copyout_ops = {
		.write = pkm_lcs_key_fd_default_copyout_write,
};

static bool pkm_lcs_key_fd_default_usercopy_read(void *ctx, void *dst,
						 const void __user *src,
						 size_t len)
{
	(void)ctx;

	return copy_from_user(dst, src, len) == 0;
}

static bool pkm_lcs_key_fd_default_usercopy_write(void *ctx, void __user *dst,
						  const void *src, size_t len)
{
	(void)ctx;

	if (!dst)
		return false;
	return copy_to_user(dst, src, len) == 0;
}

static const struct pkm_lcs_usercopy_ops
	pkm_lcs_key_fd_default_usercopy_ops = {
		.read = pkm_lcs_key_fd_default_usercopy_read,
		.write = pkm_lcs_key_fd_default_usercopy_write,
};

static void pkm_lcs_key_fd_watch_event_free(
	struct pkm_lcs_key_fd_watch_event *event)
{
	kfree(event);
}

static void pkm_lcs_key_fd_watch_queue_clear_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_key_fd_watch_event *event;
	struct pkm_lcs_key_fd_watch_event *tmp;

	list_for_each_entry_safe(event, tmp, &key_fd->watch_events, link) {
		list_del(&event->link);
		pkm_lcs_key_fd_watch_event_free(event);
	}
	key_fd->watch_pending_events = 0;
	key_fd->watch_has_overflow = false;
}

static void pkm_lcs_key_fd_drop_watch_event_locked(
	struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_key_fd_watch_event *event)
{
	if (event->event_type == REG_WATCH_OVERFLOW)
		key_fd->watch_has_overflow = false;
	list_del(&event->link);
	key_fd->watch_pending_events--;
	pkm_lcs_key_fd_watch_event_free(event);
}

static void pkm_lcs_key_fd_drop_oldest_watch_event_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_key_fd_watch_event *event;

	if (!key_fd->watch_pending_events)
		return;
	event = list_first_entry(&key_fd->watch_events,
				 struct pkm_lcs_key_fd_watch_event, link);
	pkm_lcs_key_fd_drop_watch_event_locked(key_fd, event);
}

static void pkm_lcs_key_fd_drop_oldest_preserving_overflow_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_key_fd_watch_event *event;

	if (!key_fd->watch_pending_events)
		return;

	event = list_first_entry(&key_fd->watch_events,
				 struct pkm_lcs_key_fd_watch_event, link);
	if (event->event_type == REG_WATCH_OVERFLOW &&
	    key_fd->watch_pending_events > 1)
		event = list_next_entry(event, link);
	pkm_lcs_key_fd_drop_watch_event_locked(key_fd, event);
}

static long pkm_lcs_key_fd_watch_event_matches_filter(u32 event_type,
						      u32 filter,
						      bool *matches_out)
{
	if (!matches_out)
		return -EINVAL;
	*matches_out = false;

	switch (event_type) {
	case REG_WATCH_VALUE_SET:
	case REG_WATCH_VALUE_DELETED:
		*matches_out = (filter & REG_NOTIFY_VALUE) != 0;
		return 0;
	case REG_WATCH_SUBKEY_CREATED:
	case REG_WATCH_SUBKEY_DELETED:
		*matches_out = (filter & REG_NOTIFY_SUBKEY) != 0;
		return 0;
	case REG_WATCH_SD_CHANGED:
		*matches_out = (filter & REG_NOTIFY_SD) != 0;
		return 0;
	case REG_WATCH_KEY_DELETED:
	case REG_WATCH_OVERFLOW:
		*matches_out = true;
		return 0;
	default:
		return -EINVAL;
	}
}

static struct pkm_lcs_key_fd_watch_event *
pkm_lcs_key_fd_watch_event_alloc(u32 event_type, const u8 *record,
				 u32 record_len)
{
	struct pkm_lcs_key_fd_watch_event *event;
	size_t alloc_len;

	if (!record || record_len < REG_WATCH_EVENT_MIN_SIZE)
		return ERR_PTR(-EINVAL);
	if (get_unaligned_le32(record + REG_WATCH_EVENT_TOTAL_LEN_OFFSET) !=
		    record_len ||
	    get_unaligned_le16(record + REG_WATCH_EVENT_TYPE_OFFSET) !=
		    event_type)
		return ERR_PTR(-EINVAL);

	if (check_add_overflow(sizeof(*event), (size_t)record_len, &alloc_len))
		return ERR_PTR(-EOVERFLOW);
	event = kzalloc(alloc_len, GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&event->link);
	event->event_type = event_type;
	event->total_len = record_len;
	memcpy(event->bytes, record, record_len);
	return event;
}

static struct pkm_lcs_key_fd_watch_event *
pkm_lcs_key_fd_overflow_event_alloc(void)
{
	u8 record[REG_WATCH_EVENT_MIN_SIZE] = { };

	put_unaligned_le32(REG_WATCH_EVENT_MIN_SIZE,
			   record + REG_WATCH_EVENT_TOTAL_LEN_OFFSET);
	put_unaligned_le16(REG_WATCH_OVERFLOW,
			   record + REG_WATCH_EVENT_TYPE_OFFSET);
	put_unaligned_le16(0, record + REG_WATCH_EVENT_NAME_LEN_OFFSET);
	return pkm_lcs_key_fd_watch_event_alloc(REG_WATCH_OVERFLOW, record,
						sizeof(record));
}

static struct pkm_lcs_key_fd_watch_event *
pkm_lcs_key_fd_build_watch_event(u32 event_type, const u8 *name, u32 name_len,
				 bool subtree,
				 const struct pkm_lcs_key_fd_string_view *path,
				 u32 path_count)
{
	struct pkm_lcs_key_fd_watch_event *event;
	u32 record_len = 0;
	u32 written = 0;
	u8 overflow = 0;
	int ret;

	if (name_len && !name)
		return ERR_PTR(-EINVAL);
	if (path_count && !path)
		return ERR_PTR(-EINVAL);

	ret = lcs_rust_write_watch_event_record(
		event_type, name, name_len, subtree ? 1 : 0, path, path_count,
		NULL, 0, &record_len, &overflow);
	if (ret)
		return ERR_PTR(ret);
	if (overflow)
		return pkm_lcs_key_fd_overflow_event_alloc();
	if (record_len < REG_WATCH_EVENT_MIN_SIZE)
		return ERR_PTR(-EINVAL);

	event = kzalloc(sizeof(*event) + record_len, GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&event->link);

	ret = lcs_rust_write_watch_event_record(
		event_type, name, name_len, subtree ? 1 : 0, path, path_count,
		event->bytes, record_len, &written, &overflow);
	if (ret) {
		pkm_lcs_key_fd_watch_event_free(event);
		return ERR_PTR(ret);
	}
	if (overflow || written != record_len) {
		pkm_lcs_key_fd_watch_event_free(event);
		return ERR_PTR(-EINVAL);
	}

	event->event_type = event_type;
	event->total_len = record_len;
	return event;
}

static bool pkm_lcs_key_fd_subtree_depth_suppressed(u32 path_count,
						    u32 max_depth)
{
	return max_depth != 0 && path_count > max_depth;
}

static long pkm_lcs_key_fd_queue_watch_event_locked(
	struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_key_fd_watch_event *event, u32 queue_limit)
{
	struct pkm_lcs_key_fd_watch_event *queued_event = event;

	if (!key_fd || !event)
		return -EINVAL;
	if (!queue_limit)
		return -EINVAL;

	if (event->event_type == REG_WATCH_OVERFLOW &&
	    key_fd->watch_has_overflow) {
		pkm_lcs_key_fd_watch_event_free(event);
		return 0;
	}

	if (key_fd->watch_pending_events >= queue_limit) {
		if (key_fd->watch_has_overflow) {
			pkm_lcs_key_fd_drop_oldest_preserving_overflow_locked(
				key_fd);
		} else {
			pkm_lcs_key_fd_drop_oldest_watch_event_locked(key_fd);
			if (event->event_type != REG_WATCH_OVERFLOW) {
				pkm_lcs_key_fd_watch_event_free(event);
				queued_event =
					pkm_lcs_key_fd_overflow_event_alloc();
				if (IS_ERR(queued_event))
					return PTR_ERR(queued_event);
			}
		}
	}

	list_add_tail(&queued_event->link, &key_fd->watch_events);
	key_fd->watch_pending_events++;
	if (queued_event->event_type == REG_WATCH_OVERFLOW)
		key_fd->watch_has_overflow = true;
	return 0;
}

static void pkm_lcs_key_fd_free(struct pkm_lcs_key_fd *key_fd)
{
	u32 i;

	if (!key_fd)
		return;

	if (key_fd->resolved_path) {
		for (i = 0; i < key_fd->path_component_count; i++)
			kfree(key_fd->resolved_path[i]);
		kfree(key_fd->resolved_path);
	}
	pkm_lcs_key_ref_put_for_key_fd(key_fd, false);
	pkm_lcs_key_fd_watch_queue_clear_locked(key_fd);
	kfree(key_fd->ancestor_guids);
	kfree(key_fd);
}

static int pkm_lcs_key_fd_release(struct inode *inode, struct file *file)
{
	struct pkm_lcs_key_fd *key_fd = file->private_data;

	file->private_data = NULL;
	if (key_fd) {
		mutex_lock(&pkm_lcs_watch_registry_lock);
		mutex_lock(&key_fd->watch_lock);
		pkm_lcs_key_fd_watch_registry_remove_locked(key_fd);
		key_fd->watch_armed = false;
		key_fd->watch_filter = 0;
		key_fd->watch_subtree = false;
		pkm_lcs_key_fd_watch_queue_clear_locked(key_fd);
		mutex_unlock(&key_fd->watch_lock);
		mutex_unlock(&pkm_lcs_watch_registry_lock);
	}
	pkm_lcs_key_ref_put_for_key_fd(key_fd, true);
	pkm_lcs_key_fd_free(key_fd);
	return 0;
}

static ssize_t pkm_lcs_key_fd_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos);
static __poll_t pkm_lcs_key_fd_poll(struct file *file,
				    struct poll_table_struct *wait);
static long pkm_lcs_key_fd_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg);

static const struct file_operations pkm_lcs_key_fd_fops = {
	.owner = THIS_MODULE,
	.read = pkm_lcs_key_fd_read,
	.poll = pkm_lcs_key_fd_poll,
	.unlocked_ioctl = pkm_lcs_key_fd_ioctl,
	.release = pkm_lcs_key_fd_release,
	.llseek = noop_llseek,
};

static long pkm_lcs_key_fd_validate_input(
	const struct pkm_lcs_key_fd_publish_input *input,
	struct pkm_lcs_key_fd_string_view **views_out)
{
	struct pkm_lcs_key_fd_string_view *views = NULL;
	struct pkm_lcs_runtime_limits effective_limits;
	const struct pkm_lcs_runtime_limits *limits;
	size_t len;
	u32 i;
	long ret = -ENOMEM;

	if (!views_out)
		return -EINVAL;
	*views_out = NULL;

	if (!input || !input->source_id || !input->path_component_count ||
	    !input->resolved_path || !input->ancestor_guids)
		return -EINVAL;
	limits = input->limits;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&effective_limits);
		limits = &effective_limits;
	}

	views = kcalloc(input->path_component_count, sizeof(*views),
			GFP_KERNEL);
	if (!views)
		return -ENOMEM;

	for (i = 0; i < input->path_component_count; i++) {
		if (!input->resolved_path[i]) {
			ret = -EINVAL;
			goto out_free;
		}
		len = strlen(input->resolved_path[i]);
		if (len > U32_MAX) {
			ret = -EINVAL;
			goto out_free;
		}
		views[i].bytes = input->resolved_path[i];
		views[i].len = (u32)len;
	}

	ret = lcs_rust_validate_key_fd_open_view(
		input->key_guid, input->granted_access, views,
		input->path_component_count, input->ancestor_guids,
		input->path_component_count, limits);
	if (ret)
		goto out_free;

	*views_out = views;
	return 0;

out_free:
	kfree(views);
	return ret;
}

static long pkm_lcs_key_fd_copy_input(
	const struct pkm_lcs_key_fd_publish_input *input,
	const struct pkm_lcs_key_fd_string_view *views,
	struct pkm_lcs_key_fd **key_fd_out)
{
	struct pkm_lcs_key_fd *key_fd;
	size_t guid_bytes;
	long ret = -ENOMEM;
	u32 i;

	if (!input || !views || !key_fd_out)
		return -EINVAL;
	*key_fd_out = NULL;

	key_fd = kzalloc(sizeof(*key_fd), GFP_KERNEL);
	if (!key_fd)
		return -ENOMEM;
	mutex_init(&key_fd->watch_lock);
	init_waitqueue_head(&key_fd->watch_wait);
	INIT_LIST_HEAD(&key_fd->watch_events);
	INIT_LIST_HEAD(&key_fd->key_ref_node);
	INIT_HLIST_NODE(&key_fd->watch_registry_entry.link);

	key_fd->resolved_path = kcalloc(input->path_component_count,
					sizeof(*key_fd->resolved_path),
					GFP_KERNEL);
	if (!key_fd->resolved_path)
		goto out_nomem;

	if (check_mul_overflow((size_t)input->path_component_count,
			       sizeof(*key_fd->ancestor_guids),
			       &guid_bytes))
		goto out_nomem;
	key_fd->ancestor_guids = kmemdup(input->ancestor_guids, guid_bytes,
					 GFP_KERNEL);
	if (!key_fd->ancestor_guids)
		goto out_nomem;

	for (i = 0; i < input->path_component_count; i++) {
		key_fd->resolved_path[i] = kstrndup(input->resolved_path[i],
						    views[i].len, GFP_KERNEL);
		if (!key_fd->resolved_path[i])
			goto out_nomem;
	}

	key_fd->source_id = input->source_id;
	memcpy(key_fd->key_guid, input->key_guid, sizeof(key_fd->key_guid));
	ret = pkm_lcs_key_ref_attach(key_fd);
	if (ret)
		goto out_nomem;
	key_fd->granted_access = input->granted_access;
	key_fd->path_component_count = input->path_component_count;
	key_fd->orphaned = false;
	key_fd->watch_armed = false;

	*key_fd_out = key_fd;
	return 0;

out_nomem:
	pkm_lcs_key_fd_free(key_fd);
	return ret ?: -ENOMEM;
}

static void pkm_lcs_key_fd_capture_source_restart_generation(
	struct pkm_lcs_key_fd *key_fd)
{
	u64 generation;

	if (!key_fd)
		return;
	if (pkm_lcs_source_restart_generation_snapshot(
		    key_fd->source_id, &generation))
		return;

	key_fd->source_restart_generation_seen = generation;
	key_fd->source_restart_generation_tracked = true;
}

static long pkm_lcs_key_fd_revalidate_after_source_restart(
	struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_runtime_limits effective_limits;
	u64 generation;
	long ret;

	if (!key_fd)
		return -EINVAL;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&effective_limits);
		limits = &effective_limits;
	}
	if (!READ_ONCE(key_fd->source_restart_generation_tracked))
		return 0;

	ret = pkm_lcs_source_restart_generation_snapshot(key_fd->source_id,
							 &generation);
	if (ret)
		return 0;
	if (generation == READ_ONCE(key_fd->source_restart_generation_seen))
		return 0;
	if (READ_ONCE(key_fd->orphaned))
		return -ENOENT;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, 0, key_fd->key_guid, limits,
		limits->request_timeout_ms, &frame, &response, NULL);
	if (ret == -ENOENT) {
		u32 marked = 0;

		pkm_lcs_source_response_frame_destroy(&frame);
		(void)pkm_lcs_key_fd_mark_orphaned_no_watch(
			key_fd->source_id, key_fd->key_guid, &marked, NULL);
		return -ENOENT;
	}
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
		frame.data, frame.len, response.request_id, &response.limits,
		&read_key);
	if (ret)
		goto out_frame;
	if (!read_key.sd_len || (size_t)read_key.sd_offset > frame.len ||
	    (size_t)read_key.sd_len >
		    frame.len - (size_t)read_key.sd_offset) {
		ret = -EIO;
		goto out_frame;
	}

	WRITE_ONCE(key_fd->source_restart_generation_seen, generation);

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

long pkm_lcs_key_fd_publish(const struct pkm_lcs_key_fd_publish_input *input)
{
	struct pkm_lcs_key_fd_string_view *views = NULL;
	struct pkm_lcs_key_fd *key_fd = NULL;
	long ret;
	int fd;

	ret = pkm_lcs_key_fd_validate_input(input, &views);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_input(input, views, &key_fd);
	kfree(views);
	if (ret)
		return ret;
	pkm_lcs_key_fd_capture_source_restart_generation(key_fd);

	fd = anon_inode_getfd("lcs-key", &pkm_lcs_key_fd_fops, key_fd,
			      O_CLOEXEC);
	if (fd < 0) {
		pkm_lcs_key_fd_free(key_fd);
		return fd;
	}

	key_fd->published = true;
	return fd;
}

static long pkm_lcs_key_fd_notify_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct reg_notify_args *args)
{
	struct pkm_lcs_watch_notify_plan_copy plan;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;

	ret = pkm_lcs_key_fd_revalidate_after_source_restart(key_fd, NULL);
	if (ret)
		return ret;

	mutex_lock(&pkm_lcs_watch_registry_lock);
	mutex_lock(&key_fd->watch_lock);
	ret = lcs_rust_plan_key_fd_watch_notify(
		key_fd->watch_armed ? 1 : 0, key_fd->orphaned ? 1 : 0,
		args->filter, args->subtree, args->_pad, &plan);
	if (ret)
		goto out_unlock;

	switch (plan.action) {
	case PKM_LCS_WATCH_NOTIFY_ACTION_ARM:
		if (plan.subtree && !key_fd->watch_subtree_registered) {
			ret = pkm_lcs_subtree_watch_get_locked(
				key_fd->key_guid);
			if (ret)
				goto out_unlock;
			key_fd->watch_subtree_registered = true;
		} else if (!plan.subtree &&
			   key_fd->watch_subtree_registered) {
			pkm_lcs_subtree_watch_put_locked(key_fd->key_guid);
			key_fd->watch_subtree_registered = false;
		}
		pkm_lcs_key_fd_watch_map_link_locked(key_fd);
		key_fd->watch_filter = plan.filter;
		key_fd->watch_subtree = plan.subtree != 0;
		key_fd->watch_armed = true;
		break;
	case PKM_LCS_WATCH_NOTIFY_ACTION_DISARM:
		pkm_lcs_key_fd_watch_registry_remove_locked(key_fd);
		key_fd->watch_filter = 0;
		key_fd->watch_subtree = false;
		key_fd->watch_armed = false;
		if (plan.discard_pending_events)
			pkm_lcs_key_fd_watch_queue_clear_locked(key_fd);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out_unlock:
	mutex_unlock(&key_fd->watch_lock);
	mutex_unlock(&pkm_lcs_watch_registry_lock);

	wake_up_interruptible(&key_fd->watch_wait);
	return ret;
}

static long pkm_lcs_key_fd_queue_watch_record(
	struct pkm_lcs_key_fd *key_fd, u32 event_type, const u8 *record,
	u32 record_len)
{
	struct pkm_lcs_key_fd_watch_event *event;
	struct pkm_lcs_runtime_limits limits;
	bool matches;
	long ret;

	if (!key_fd)
		return -EINVAL;

	event = pkm_lcs_key_fd_watch_event_alloc(event_type, record,
						record_len);
	if (IS_ERR(event))
		return PTR_ERR(event);

	mutex_lock(&key_fd->watch_lock);
	if (!key_fd->watch_armed) {
		pkm_lcs_key_fd_watch_event_free(event);
		mutex_unlock(&key_fd->watch_lock);
		return 0;
	}
	ret = pkm_lcs_key_fd_watch_event_matches_filter(
		event_type, key_fd->watch_filter, &matches);
	if (ret || !matches) {
		pkm_lcs_key_fd_watch_event_free(event);
		mutex_unlock(&key_fd->watch_lock);
		return ret;
	}
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_key_fd_queue_watch_event_locked(
		key_fd, event, limits.notification_queue_size);
	mutex_unlock(&key_fd->watch_lock);

	if (!ret)
		wake_up_interruptible(&key_fd->watch_wait);
	return ret;
}

static ssize_t pkm_lcs_key_fd_read_file_with_ops(
	struct file *file, char __user *buf, size_t count, bool nonblocking,
	const struct pkm_lcs_key_fd_copyout_ops *ops)
{
	struct pkm_lcs_key_fd_watch_event *event;
	struct pkm_lcs_key_fd *key_fd;
	size_t bytes;
	u32 event_count;
	long ret;

	if (!file)
		return -EBADF;
	key_fd = file->private_data;
	if (!key_fd)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_copyout_ops;
	if (!ops->write)
		return -EINVAL;

	for (;;) {
		mutex_lock(&key_fd->watch_lock);
		if (key_fd->watch_pending_events)
			break;
		mutex_unlock(&key_fd->watch_lock);

		if (nonblocking)
			return -EAGAIN;
		ret = wait_event_interruptible(
			key_fd->watch_wait,
			READ_ONCE(key_fd->watch_pending_events) != 0);
		if (ret)
			return ret;
	}

	event = list_first_entry(&key_fd->watch_events,
				 struct pkm_lcs_key_fd_watch_event, link);
	if (count < event->total_len) {
		mutex_unlock(&key_fd->watch_lock);
		return -EINVAL;
	}

	bytes = 0;
	event_count = 0;
	list_for_each_entry(event, &key_fd->watch_events, link) {
		if (event->total_len > count - bytes)
			break;
		if (!ops->write(ops->ctx, buf + bytes, event->bytes,
				event->total_len)) {
			mutex_unlock(&key_fd->watch_lock);
			return -EFAULT;
		}
		bytes += event->total_len;
		event_count++;
	}

	while (event_count--) {
		event = list_first_entry(&key_fd->watch_events,
					 struct pkm_lcs_key_fd_watch_event,
					 link);
		pkm_lcs_key_fd_drop_watch_event_locked(key_fd, event);
	}
	mutex_unlock(&key_fd->watch_lock);

	return bytes;
}

static ssize_t pkm_lcs_key_fd_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos)
{
	(void)ppos;

	return pkm_lcs_key_fd_read_file_with_ops(
		file, buf, count, (file->f_flags & O_NONBLOCK) != 0,
		&pkm_lcs_key_fd_default_copyout_ops);
}

static __poll_t pkm_lcs_key_fd_poll(struct file *file,
				    struct poll_table_struct *wait)
{
	struct pkm_lcs_key_fd *key_fd;
	__poll_t mask = 0;

	if (!file)
		return EPOLLERR | EPOLLHUP;
	key_fd = file->private_data;
	if (!key_fd)
		return EPOLLERR | EPOLLHUP;

	poll_wait(file, &key_fd->watch_wait, wait);
	mutex_lock(&key_fd->watch_lock);
	if (key_fd->watch_pending_events)
		mask |= EPOLLIN;
	mutex_unlock(&key_fd->watch_lock);
	return mask;
}

static long pkm_lcs_key_fd_copy_set_security_sd(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_security_args *args, u8 **sd_out,
	size_t *sd_len_out)
{
	u8 *sd;

	if (!sd_out || !sd_len_out)
		return -EINVAL;
	*sd_out = NULL;
	*sd_len_out = 0;

	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read || !args)
		return -EINVAL;
	if (!args->sd_ptr || !args->sd_len ||
	    args->sd_len > PKM_LCS_MAX_SD_BYTES)
		return -EINVAL;

	sd = kmalloc(args->sd_len, GFP_KERNEL);
	if (!sd)
		return -ENOMEM;
	if (!ops->read(ops->ctx, sd,
		       (const void __user *)(unsigned long)args->sd_ptr,
		       args->sd_len)) {
		kfree(sd);
		return -EFAULT;
	}

	*sd_out = sd;
	*sd_len_out = args->sd_len;
	return 0;
}

static long pkm_lcs_key_fd_read_existing_sd(
	const struct pkm_lcs_key_fd *key_fd, u64 txn_id,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_frame *frame, const u8 **sd_out,
	size_t *sd_len_out, struct pkm_lcs_source_response_result *response_out)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_runtime_limits effective_limits;
	long ret;

	if (!key_fd || !frame || !sd_out || !sd_len_out)
		return -EINVAL;
	*sd_out = NULL;
	*sd_len_out = 0;
	if (response_out)
		memset(response_out, 0, sizeof(*response_out));

	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&effective_limits);
		limits = &effective_limits;
	}
	pkm_lcs_source_response_frame_init(frame);
	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, limits,
		limits->request_timeout_ms, frame, &response, NULL);
	if (response_out)
		*response_out = response;
	if (ret)
		return ret;

	ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
		frame->data, frame->len, response.request_id, limits,
		&read_key);
	if (ret)
		return ret;
	if (!read_key.sd_len || (size_t)read_key.sd_offset > frame->len ||
	    (size_t)read_key.sd_len >
		    frame->len - (size_t)read_key.sd_offset)
		return -EIO;

	*sd_out = frame->data + read_key.sd_offset;
	*sd_len_out = read_key.sd_len;
	return 0;
}

static void pkm_lcs_key_fd_publish_set_security_effects(
	struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_watch_dispatch_context context = { };

	context.changed_key_guid = key_fd->key_guid;
	context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])key_fd->ancestor_guids;
	context.resolved_path = (const char * const *)key_fd->resolved_path;
	context.limits = limits;
	context.path_component_count = key_fd->path_component_count;
	context.event_type = REG_WATCH_SD_CHANGED;

	(void)pkm_lcs_key_fd_dispatch_watch_event_context(&context);
}

static void pkm_lcs_key_fd_publish_value_effects(
	struct pkm_lcs_key_fd *key_fd, u32 event_type,
	const char *value_name, u32 value_name_len,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_watch_dispatch_context context = { };

	context.changed_key_guid = key_fd->key_guid;
	context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])key_fd->ancestor_guids;
	context.resolved_path = (const char * const *)key_fd->resolved_path;
	context.limits = limits;
	context.path_component_count = key_fd->path_component_count;
	context.event_type = event_type;
	context.name = (const u8 *)value_name;
	context.name_len = value_name_len;

	(void)pkm_lcs_key_fd_dispatch_watch_event_context(&context);
}

static u32 pkm_lcs_key_fd_publish_parent_subkey_event(
	struct pkm_lcs_key_fd *key_fd, const u8 *parent_guid,
	const char *child_name, u32 child_name_len, u32 event_type,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_watch_dispatch_context context = { };
	u32 internal_effects = 0;

	if (!key_fd || !parent_guid || !child_name || !child_name_len ||
	    key_fd->path_component_count < 2)
		return 0;

	context.changed_key_guid = parent_guid;
	context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])key_fd->ancestor_guids;
	context.resolved_path = (const char * const *)key_fd->resolved_path;
	context.limits = limits;
	context.path_component_count = key_fd->path_component_count - 1U;
	context.event_type = event_type;
	context.name = (const u8 *)child_name;
	context.name_len = child_name_len;

	(void)pkm_lcs_key_fd_dispatch_watch_event_context_effects(
		&context, &internal_effects);
	return internal_effects;
}

static u32 pkm_lcs_key_fd_publish_parent_subkey_deleted(
	struct pkm_lcs_key_fd *key_fd, const u8 *parent_guid,
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits)
{
	return pkm_lcs_key_fd_publish_parent_subkey_event(
		key_fd, parent_guid, child_name, child_name_len,
		REG_WATCH_SUBKEY_DELETED, limits);
}

static u32 pkm_lcs_key_fd_publish_parent_subkey_created(
	struct pkm_lcs_key_fd *key_fd, const u8 *parent_guid,
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits)
{
	return pkm_lcs_key_fd_publish_parent_subkey_event(
		key_fd, parent_guid, child_name, child_name_len,
		REG_WATCH_SUBKEY_CREATED, limits);
}

static void pkm_lcs_key_fd_publish_key_deleted_context(
	struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_watch_dispatch_context context = { };

	if (!key_fd)
		return;

	context.changed_key_guid = key_fd->key_guid;
	context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])key_fd->ancestor_guids;
	context.resolved_path = (const char * const *)key_fd->resolved_path;
	context.limits = limits;
	context.path_component_count = key_fd->path_component_count;
	context.event_type = REG_WATCH_KEY_DELETED;

	(void)pkm_lcs_key_fd_dispatch_watch_event_context(&context);
}

static void pkm_lcs_key_fd_publish_set_value_effects(
	struct pkm_lcs_key_fd *key_fd, const char *value_name,
	u32 value_name_len, const struct pkm_lcs_runtime_limits *limits)
{
	pkm_lcs_key_fd_publish_value_effects(
		key_fd, REG_WATCH_VALUE_SET, value_name, value_name_len,
		limits);
}

static void pkm_lcs_effective_value_snapshot_destroy(
	struct pkm_lcs_effective_value_snapshot *snapshot)
{
	if (!snapshot)
		return;

	pkm_lcs_source_response_frame_destroy(&snapshot->frame);
	memset(snapshot, 0, sizeof(*snapshot));
}

static long pkm_lcs_effective_value_snapshot_validate(
	const struct pkm_lcs_effective_value_snapshot *snapshot)
{
	const struct pkm_lcs_rsi_query_value_result *result;

	if (!snapshot)
		return -EINVAL;
	result = &snapshot->result;
	if (!result->found)
		return 0;
	if ((size_t)result->data_offset > snapshot->frame.len ||
	    (size_t)result->data_len >
		    snapshot->frame.len - (size_t)result->data_offset ||
	    (result->layer_len && !result->layer))
		return -EIO;
	return 0;
}

static long pkm_lcs_key_fd_query_effective_value_snapshot_with_limits(
	const struct pkm_lcs_key_fd *key_fd, u64 txn_id,
	const char *value_name, u32 value_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_effective_value_snapshot *snapshot)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_runtime_limits effective_limits;
	u64 next_sequence = 0;
	long ret;

	if (!key_fd || (value_name_len && !value_name) || !snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));
	pkm_lcs_source_response_frame_init(&snapshot->frame);
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, value_name,
		value_name_len, false, limits, limits->request_timeout_ms,
		&snapshot->frame, &response, NULL);
	if (ret)
		goto out_layer_snapshot;

	ret = pkm_lcs_rsi_materialize_query_value_response(
		snapshot->frame.data, snapshot->frame.len,
		response.request_id, next_sequence, value_name, value_name_len,
		layer_snapshot.layers, layer_snapshot.layer_count, NULL, 0,
		limits, &snapshot->result);
	if (ret)
		goto out_layer_snapshot;
	ret = pkm_lcs_effective_value_snapshot_validate(snapshot);

out_layer_snapshot:
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_query_effective_value_snapshot(
	const struct pkm_lcs_key_fd *key_fd, u64 txn_id,
	const char *value_name, u32 value_name_len,
	struct pkm_lcs_effective_value_snapshot *snapshot)
{
	return pkm_lcs_key_fd_query_effective_value_snapshot_with_limits(
		key_fd, txn_id, value_name, value_name_len, NULL, snapshot);
}

static bool pkm_lcs_effective_value_snapshots_same(
	const struct pkm_lcs_effective_value_snapshot *before,
	const struct pkm_lcs_effective_value_snapshot *after)
{
	const u8 *before_data;
	const u8 *after_data;

	if (!before || !after || !before->result.found || !after->result.found)
		return false;
	if (before->result.value_type != after->result.value_type ||
	    before->result.data_len != after->result.data_len ||
	    before->result.layer_len != after->result.layer_len ||
	    before->result.selected_sequence != after->result.selected_sequence)
		return false;
	before_data = before->frame.data + before->result.data_offset;
	after_data = after->frame.data + after->result.data_offset;
	if (before->result.data_len &&
	    memcmp(before_data, after_data, before->result.data_len))
		return false;
	if (before->result.layer_len &&
	    memcmp(before->result.layer, after->result.layer,
		   before->result.layer_len))
		return false;
	return true;
}

static long pkm_lcs_key_fd_delete_value_watch_event_type(
	const struct pkm_lcs_effective_value_snapshot *before,
	const struct pkm_lcs_effective_value_snapshot *after, u32 *event_type)
{
	if (!before || !after || !event_type)
		return -EINVAL;

	*event_type = 0;
	if (before->result.found && !after->result.found) {
		*event_type = REG_WATCH_VALUE_DELETED;
		return 0;
	}
	if (!before->result.found && after->result.found) {
		*event_type = REG_WATCH_VALUE_SET;
		return 0;
	}
	if (before->result.found && after->result.found &&
	    !pkm_lcs_effective_value_snapshots_same(before, after))
		*event_type = REG_WATCH_VALUE_SET;
	return 0;
}

static long pkm_lcs_key_fd_query_effective_values_frame(
	const struct pkm_lcs_key_fd *key_fd, u64 txn_id,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response)
{
	if (!key_fd || !limits || !frame || !response)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(frame);
	return pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, "", 0, true,
		limits, limits->request_timeout_ms, frame, response, NULL);
}

static long pkm_lcs_key_fd_materialize_value_watch_events(
	const struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_source_response_frame *before_frame,
	const struct pkm_lcs_source_response_result *before_response,
	const struct pkm_lcs_source_response_frame *after_frame,
	const struct pkm_lcs_source_response_result *after_response,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_value_watch_event_bytes *events)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_rsi_value_watch_events_result result = { };
	struct pkm_lcs_rsi_value_watch_events_result written = { };
	u64 next_sequence = 0;
	long ret;

	if (!key_fd || !before_frame || !before_response || !after_frame ||
	    !after_response || !limits || !events)
		return -EINVAL;
	memset(events, 0, sizeof(*events));

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	ret = pkm_lcs_rsi_materialize_query_values_watch_events(
		before_frame->data, before_frame->len,
		before_response->request_id, after_frame->data, after_frame->len,
		after_response->request_id, next_sequence, layer_snapshot.layers,
		layer_snapshot.layer_count, NULL, 0, limits, NULL, 0, &result);
	if (ret)
		goto out_layer_snapshot;
	if (!result.required_len) {
		events->count = result.count;
		ret = result.count ? -EIO : 0;
		goto out_layer_snapshot;
	}

	events->data = kmalloc(result.required_len, GFP_KERNEL);
	if (!events->data) {
		ret = -ENOMEM;
		goto out_layer_snapshot;
	}
	ret = pkm_lcs_rsi_materialize_query_values_watch_events(
		before_frame->data, before_frame->len,
		before_response->request_id, after_frame->data, after_frame->len,
		after_response->request_id, next_sequence, layer_snapshot.layers,
		layer_snapshot.layer_count, NULL, 0, limits, events->data,
		result.required_len, &written);
	if (ret)
		goto out_events;
	if (written.required_len != result.required_len ||
	    written.written_len != result.required_len ||
	    written.count != result.count) {
		ret = -EIO;
		goto out_events;
	}

	events->len = written.written_len;
	events->count = written.count;
	ret = 0;
	goto out_layer_snapshot;

out_events:
	pkm_lcs_value_watch_event_bytes_destroy(events);
out_layer_snapshot:
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_publish_value_watch_event_bytes(
	struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_value_watch_event_bytes *events,
	const struct pkm_lcs_runtime_limits *limits)
{
	size_t offset = 0;
	u32 i;

	if (!key_fd || !events)
		return -EINVAL;
	if (!events->count)
		return events->data || events->len ? -EINVAL : 0;
	if (!events->data || !events->len)
		return -EINVAL;

	for (i = 0; i < events->count; i++) {
		u32 event_type;
		u32 name_len;

		if (offset > events->len || events->len - offset < 8U)
			return -EIO;
		event_type = get_unaligned_le32(events->data + offset);
		name_len = get_unaligned_le32(events->data + offset + 4U);
		offset += 8U;
		if ((event_type != REG_WATCH_VALUE_SET &&
		     event_type != REG_WATCH_VALUE_DELETED) ||
		    offset > events->len || name_len > events->len - offset)
			return -EIO;
		pkm_lcs_key_fd_publish_value_effects(
			key_fd, event_type, (const char *)events->data + offset,
			name_len, limits);
		offset += name_len;
	}
	return offset == events->len ? 0 : -EIO;
}

static long pkm_lcs_key_fd_get_security_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_get_security_args *args)
{
	struct pkm_lcs_get_security_result result = { };
	struct pkm_lcs_source_response_frame existing_frame = { };
	const u8 *existing_sd = NULL;
	size_t existing_sd_len = 0;
	size_t provided_len;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->write)
		return -EINVAL;

	ret = lcs_rust_key_fd_security_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_GET_SECURITY_NR,
		args->security_info);
	if (ret)
		return ret;

	provided_len = args->sd_len;
	if (provided_len && !args->sd_ptr)
		return -EFAULT;

	ret = pkm_lcs_key_fd_read_existing_sd(key_fd, 0, NULL, &existing_frame,
					      &existing_sd, &existing_sd_len,
					      NULL);
	if (ret)
		goto out_existing;

	ret = pkm_lcs_key_fd_plan_get_security(existing_sd, existing_sd_len,
					       args->security_info, &result);
	if (ret)
		goto out_existing;
	if (result.sd_len > U32_MAX) {
		ret = -EOVERFLOW;
		goto out_result;
	}

	args->sd_len = (u32)result.sd_len;
	if (provided_len < result.sd_len) {
		ret = -ERANGE;
		goto out_result;
	}

	if (result.sd_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)args->sd_ptr,
			result.sd, result.sd_len))
		ret = -EFAULT;

out_result:
	pkm_lcs_get_security_result_destroy(&result);
out_existing:
	pkm_lcs_source_response_frame_destroy(&existing_frame);
	return ret;
}

static const char *pkm_lcs_key_fd_leaf_name(const struct pkm_lcs_key_fd *key_fd,
					    size_t *name_len)
{
	const char *name;

	if (name_len)
		*name_len = 0;
	if (!key_fd || !key_fd->resolved_path || !key_fd->path_component_count)
		return NULL;

	name = key_fd->resolved_path[key_fd->path_component_count - 1U];
	if (!name)
		return NULL;
	if (name_len)
		*name_len = strlen(name);
	return name;
}

static long pkm_lcs_key_fd_query_key_info_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_key_info_args *args)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame read_frame = { };
	struct pkm_lcs_source_response_frame enum_frame = { };
	struct pkm_lcs_source_response_frame values_frame = { };
	struct pkm_lcs_source_response_result read_response = { };
	struct pkm_lcs_source_response_result enum_response = { };
	struct pkm_lcs_source_response_result values_response = { };
	struct pkm_lcs_rsi_enum_children_info_summary enum_summary = { };
	struct pkm_lcs_rsi_query_values_info_summary values_summary = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_runtime_limits limits;
	const char *key_name;
	size_t key_name_len;
	u64 hive_generation = 0;
	u64 next_sequence = 0;
	u64 name_ptr;
	u32 provided_len;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->write)
		return -EINVAL;

	provided_len = args->name_len;
	name_ptr = args->name_ptr;
	if (args->_pad0)
		return -EINVAL;
	if (provided_len && !name_ptr)
		return -EFAULT;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_QUERY_KEY_INFO_NR);
	if (ret)
		return ret;

	key_name = pkm_lcs_key_fd_leaf_name(key_fd, &key_name_len);
	if (!key_name || key_name_len > U32_MAX)
		return -EIO;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&read_frame);
	pkm_lcs_source_response_frame_init(&enum_frame);
	pkm_lcs_source_response_frame_init(&values_frame);

	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, 0, key_fd->key_guid, &limits,
		limits.request_timeout_ms, &read_frame,
		&read_response, NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
		read_frame.data, read_frame.len, read_response.request_id,
		&limits, &read_key);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, 0, key_fd->key_guid, &limits,
		limits.request_timeout_ms, &enum_frame,
		&enum_response, NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		enum_frame.data, enum_frame.len, enum_response.request_id,
		next_sequence, layer_snapshot.layers, layer_snapshot.layer_count,
		NULL, 0, &enum_response.limits, &enum_summary);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, 0, key_fd->key_guid, "", 0, true,
		&limits, limits.request_timeout_ms, &values_frame,
		&values_response, NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_query_values_info_summary(
		values_frame.data, values_frame.len, values_response.request_id,
		next_sequence, layer_snapshot.layers, layer_snapshot.layer_count,
		NULL, 0, &values_response.limits, &values_summary);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_source_hive_generation_snapshot(
		key_fd->source_id, key_fd->ancestor_guids[0], &hive_generation);
	if (ret)
		goto out_frames;

	if (provided_len < key_name_len) {
		memset(args, 0, sizeof(*args));
		args->name_len = (u32)key_name_len;
		args->name_ptr = name_ptr;
		ret = -ERANGE;
		goto out_frames;
	}

	memset(args, 0, sizeof(*args));
	args->name_len = (u32)key_name_len;
	args->name_ptr = name_ptr;
	args->last_write_time = read_key.last_write_time;
	args->subkey_count = enum_summary.subkey_count;
	args->value_count = values_summary.value_count;
	args->max_subkey_name_len = enum_summary.max_subkey_name_len;
	args->max_value_name_len = values_summary.max_value_name_len;
	args->max_value_data_size = values_summary.max_value_data_size;
	args->sd_size = read_key.sd_len;
	args->volatile_key = read_key.volatile_key ? 1 : 0;
	args->symlink = read_key.symlink ? 1 : 0;
	args->hive_generation = hive_generation;

	if (key_name_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)name_ptr,
			key_name, key_name_len))
		ret = -EFAULT;

out_frames:
	pkm_lcs_source_response_frame_destroy(&values_frame);
	pkm_lcs_source_response_frame_destroy(&enum_frame);
	pkm_lcs_source_response_frame_destroy(&read_frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_copy_query_value_name(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_query_value_args *args, char **name_out)
{
	char *name;
	size_t alloc_len;

	if (!name_out)
		return -EINVAL;
	*name_out = NULL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read || !args)
		return -EINVAL;
	if (args->name_len && !args->name_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->name_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	name = kzalloc(alloc_len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	if (args->name_len &&
	    !ops->read(ops->ctx, name,
		       (const void __user *)(unsigned long)args->name_ptr,
		       args->name_len)) {
		kfree(name);
		return -EFAULT;
	}

	*name_out = name;
	return 0;
}

static long pkm_lcs_key_fd_query_value_prepare_read_context(
	const struct pkm_lcs_key_fd *key_fd, int txn_fd, u64 *txn_id_out)
{
	struct pkm_lcs_transaction_read_plan read = { };
	long ret;

	if (!key_fd || !txn_id_out)
		return -EINVAL;
	*txn_id_out = 0;

	if (txn_fd == -1)
		return 0;
	if (txn_fd < -1)
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_prepare_read_context(
		txn_fd, key_fd->source_id, key_fd->ancestor_guids[0], &read);
	if (ret)
		return ret;
	if (read.use_transaction)
		*txn_id_out = read.txn_id;
	return 0;
}

static void pkm_lcs_key_fd_query_value_reset_args(
	struct reg_query_value_args *args, u32 name_len, u64 name_ptr,
	u32 layer_buf_len, u64 data_ptr, u64 layer_ptr, s32 txn_fd)
{
	memset(args, 0, sizeof(*args));
	args->name_len = name_len;
	args->name_ptr = name_ptr;
	args->layer_buf_len = layer_buf_len;
	args->data_ptr = data_ptr;
	args->layer_ptr = layer_ptr;
	args->txn_fd = txn_fd;
}

static long pkm_lcs_key_fd_query_value_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_value_args *args)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_query_value_result result = { };
	struct pkm_lcs_runtime_limits limits;
	char *value_name = NULL;
	const u8 *data;
	const u8 *layer;
	u64 next_sequence = 0;
	u64 txn_id = 0;
	u64 name_ptr;
	u64 data_ptr;
	u64 layer_ptr;
	u32 name_len;
	u32 data_buf_len;
	u32 layer_buf_len;
	s32 txn_fd;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read || !ops->write)
		return -EINVAL;

	name_len = args->name_len;
	name_ptr = args->name_ptr;
	data_buf_len = args->data_len;
	data_ptr = args->data_ptr;
	layer_buf_len = args->layer_buf_len;
	layer_ptr = args->layer_ptr;
	txn_fd = args->txn_fd;

	if (args->_pad0)
		return -EINVAL;
	if (data_buf_len && !data_ptr)
		return -EFAULT;
	if (layer_buf_len && !layer_ptr)
		return -EFAULT;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_QUERY_VALUE_NR);
	if (ret)
		return ret;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	ret = pkm_lcs_key_fd_query_value_prepare_read_context(key_fd, txn_fd,
							      &txn_id);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_query_value_name(ops, args, &value_name);
	if (ret)
		return ret;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		goto out_name;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		goto out_name;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, value_name,
		name_len, false, &limits, limits.request_timeout_ms, &frame,
		&response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_query_value_response(
		frame.data, frame.len, response.request_id, next_sequence,
		value_name, name_len, layer_snapshot.layers,
		layer_snapshot.layer_count, NULL, 0, &limits, &result);
	if (ret)
		goto out_frame;
	if (!result.found) {
		ret = -ENOENT;
		goto out_frame;
	}
	if ((size_t)result.data_offset > frame.len ||
	    (size_t)result.data_len >
		    frame.len - (size_t)result.data_offset ||
	    (result.layer_len && !result.layer)) {
		ret = -EIO;
		goto out_frame;
	}

	if (data_buf_len < result.data_len ||
	    layer_buf_len < result.layer_len) {
		pkm_lcs_key_fd_query_value_reset_args(args, name_len,
						      name_ptr, layer_buf_len,
						      data_ptr, layer_ptr,
						      txn_fd);
		args->data_len = result.data_len;
		args->layer_len = result.layer_len;
		ret = -ERANGE;
		goto out_frame;
	}

	data = frame.data + result.data_offset;
	layer = result.layer;
	if (result.data_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)data_ptr,
			data, result.data_len)) {
		ret = -EFAULT;
		goto out_frame;
	}
	if (result.layer_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)layer_ptr,
			layer, result.layer_len)) {
		ret = -EFAULT;
		goto out_frame;
	}

	pkm_lcs_key_fd_query_value_reset_args(args, name_len, name_ptr,
					      layer_buf_len, data_ptr,
					      layer_ptr, txn_fd);
	args->type = result.value_type;
	args->data_len = result.data_len;
	args->sequence = result.selected_sequence;
	args->layer_len = result.layer_len;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
out_name:
	kfree(value_name);
	return ret;
}

static void pkm_lcs_key_fd_query_values_batch_reset_args(
	struct reg_query_values_batch_args *args, u32 buf_len, u64 buf_ptr,
	s32 txn_fd)
{
	memset(args, 0, sizeof(*args));
	args->buf_len = buf_len;
	args->buf_ptr = buf_ptr;
	args->txn_fd = txn_fd;
}

static void pkm_lcs_set_value_input_destroy(
	struct pkm_lcs_set_value_input *input)
{
	if (!input)
		return;

	kfree(input->value_name);
	kfree(input->data);
	pkm_lcs_create_layer_target_destroy(&input->target);
	memset(input, 0, sizeof(*input));
}

static void pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
	struct pkm_lcs_runtime_limits *limits)
{
	if (!limits)
		return;
	if (pkm_lcs_runtime_limits_snapshot(limits) &&
	    pkm_lcs_runtime_limits_defaults(limits))
		memset(limits, 0, sizeof(*limits));
}

static void pkm_lcs_delete_value_input_destroy(
	struct pkm_lcs_delete_value_input *input)
{
	if (!input)
		return;

	kfree(input->value_name);
	pkm_lcs_create_layer_target_destroy(&input->target);
	memset(input, 0, sizeof(*input));
}

static void pkm_lcs_blanket_tombstone_input_destroy(
	struct pkm_lcs_blanket_tombstone_input *input)
{
	if (!input)
		return;

	pkm_lcs_create_layer_target_destroy(&input->target);
	memset(input, 0, sizeof(*input));
}

static void pkm_lcs_value_watch_event_bytes_destroy(
	struct pkm_lcs_value_watch_event_bytes *events)
{
	if (!events)
		return;

	kfree(events->data);
	memset(events, 0, sizeof(*events));
}

static void pkm_lcs_hide_key_input_destroy(struct pkm_lcs_hide_key_input *input)
{
	if (!input)
		return;

	pkm_lcs_create_layer_target_destroy(&input->target);
	memset(input, 0, sizeof(*input));
}

static void pkm_lcs_delete_key_input_destroy(
	struct pkm_lcs_delete_key_input *input)
{
	if (!input)
		return;

	pkm_lcs_create_layer_target_destroy(&input->target);
	memset(input, 0, sizeof(*input));
}

static long pkm_lcs_key_fd_copy_set_value_value_name(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args,
	struct pkm_lcs_set_value_input *input)
{
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;
	if (args->name_len && !args->name_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->name_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	input->value_name = kzalloc(alloc_len, GFP_KERNEL);
	if (!input->value_name)
		return -ENOMEM;
	if (args->name_len &&
	    !ops->read(ops->ctx, input->value_name,
		       (const void __user *)(unsigned long)args->name_ptr,
		       args->name_len))
		return -EFAULT;
	return 0;
}

static long pkm_lcs_key_fd_copy_delete_value_name(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args,
	struct pkm_lcs_delete_value_input *input)
{
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;
	if (args->name_len && !args->name_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->name_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	input->value_name = kzalloc(alloc_len, GFP_KERNEL);
	if (!input->value_name)
		return -ENOMEM;
	if (args->name_len &&
	    !ops->read(ops->ctx, input->value_name,
		       (const void __user *)(unsigned long)args->name_ptr,
		       args->name_len))
		return -EFAULT;
	return 0;
}

static long pkm_lcs_key_fd_copy_set_value_layer(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args,
	struct pkm_lcs_set_value_input *input)
{
	char *layer;
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;

	if (!args->layer_len) {
		if (args->layer_ptr)
			return -EINVAL;
		input->target.name = "base";
		input->target.name_len = 4;
		input->target.implicit_base = 1;
		return 0;
	}

	if (!args->layer_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->layer_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	layer = kzalloc(alloc_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer,
		       (const void __user *)(unsigned long)args->layer_ptr,
		       args->layer_len)) {
		kfree(layer);
		return -EFAULT;
	}

	input->target.owned_name = layer;
	input->target.name = layer;
	input->target.name_len = args->layer_len;
	return 0;
}

static long pkm_lcs_key_fd_copy_delete_value_layer(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args,
	struct pkm_lcs_delete_value_input *input)
{
	char *layer;
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;

	if (!args->layer_len) {
		if (args->layer_ptr)
			return -EINVAL;
		input->target.name = "base";
		input->target.name_len = 4;
		input->target.implicit_base = 1;
		return 0;
	}

	if (!args->layer_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->layer_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	layer = kzalloc(alloc_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer,
		       (const void __user *)(unsigned long)args->layer_ptr,
		       args->layer_len)) {
		kfree(layer);
		return -EFAULT;
	}

	input->target.owned_name = layer;
	input->target.name = layer;
	input->target.name_len = args->layer_len;
	return 0;
}

static long pkm_lcs_key_fd_copy_blanket_tombstone_layer(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_blanket_tombstone_args *args,
	struct pkm_lcs_blanket_tombstone_input *input)
{
	char *layer;
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;

	if (!args->layer_len) {
		if (args->layer_ptr)
			return -EINVAL;
		input->target.name = "base";
		input->target.name_len = 4;
		input->target.implicit_base = 1;
		return 0;
	}

	if (!args->layer_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->layer_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	layer = kzalloc(alloc_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer,
		       (const void __user *)(unsigned long)args->layer_ptr,
		       args->layer_len)) {
		kfree(layer);
		return -EFAULT;
	}

	input->target.owned_name = layer;
	input->target.name = layer;
	input->target.name_len = args->layer_len;
	return 0;
}

static long pkm_lcs_key_fd_copy_hide_key_layer(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_hide_key_args *args,
	struct pkm_lcs_hide_key_input *input)
{
	char *layer;
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;

	if (!args->layer_len) {
		if (args->layer_ptr)
			return -EINVAL;
		input->target.name = "base";
		input->target.name_len = 4;
		input->target.implicit_base = 1;
		return 0;
	}

	if (!args->layer_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->layer_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	layer = kzalloc(alloc_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer,
		       (const void __user *)(unsigned long)args->layer_ptr,
		       args->layer_len)) {
		kfree(layer);
		return -EFAULT;
	}

	input->target.owned_name = layer;
	input->target.name = layer;
	input->target.name_len = args->layer_len;
	return 0;
}

static long pkm_lcs_key_fd_copy_delete_key_layer(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_key_args *args,
	struct pkm_lcs_delete_key_input *input)
{
	char *layer;
	size_t alloc_len;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;

	if (!args->layer_len) {
		if (args->layer_ptr)
			return -EINVAL;
		input->target.name = "base";
		input->target.name_len = 4;
		input->target.implicit_base = 1;
		return 0;
	}

	if (!args->layer_ptr)
		return -EFAULT;
	if (check_add_overflow((size_t)args->layer_len, (size_t)1,
			       &alloc_len))
		return -EOVERFLOW;

	layer = kzalloc(alloc_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer,
		       (const void __user *)(unsigned long)args->layer_ptr,
		       args->layer_len)) {
		kfree(layer);
		return -EFAULT;
	}

	input->target.owned_name = layer;
	input->target.name = layer;
	input->target.name_len = args->layer_len;
	return 0;
}

static long pkm_lcs_key_fd_copy_set_value_data(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args,
	struct pkm_lcs_set_value_input *input)
{
	u8 *data;

	if (!ops || !ops->read || !args || !input)
		return -EINVAL;
	if (!args->data_len)
		return 0;
	if (!args->data_ptr)
		return -EFAULT;

	data = kmalloc(args->data_len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	if (!ops->read(ops->ctx, data,
		       (const void __user *)(unsigned long)args->data_ptr,
		       args->data_len)) {
		kfree(data);
		return -EFAULT;
	}

	input->data = data;
	return 0;
}

static long pkm_lcs_key_fd_copy_set_value_input(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args,
	const struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_set_value_input *input)
{
	long ret;

	if (!ops || !ops->read || !args || !key_fd || !input)
		return -EINVAL;
	memset(input, 0, sizeof(*input));
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&input->limits);

	ret = pkm_lcs_key_fd_copy_set_value_value_name(ops, args, input);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_copy_set_value_layer(ops, args, input);
	if (ret)
		return ret;
	ret = pkm_lcs_rsi_validate_set_value_user_shape(
		key_fd->key_guid, input->value_name, args->name_len,
		input->target.name, input->target.name_len, args->type,
		args->data_len, &input->limits);
	if (ret)
		return ret;
	return 0;
}

static long pkm_lcs_key_fd_copy_delete_value_input(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args,
	const struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_delete_value_input *input)
{
	long ret;

	if (!ops || !ops->read || !args || !key_fd || !input)
		return -EINVAL;
	memset(input, 0, sizeof(*input));
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&input->limits);

	ret = pkm_lcs_key_fd_copy_delete_value_name(ops, args, input);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_copy_delete_value_layer(ops, args, input);
	if (ret)
		return ret;
	return pkm_lcs_rsi_validate_delete_value_user_shape(
		key_fd->key_guid, input->value_name, args->name_len,
		input->target.name, input->target.name_len, &input->limits);
}

static long pkm_lcs_key_fd_copy_blanket_tombstone_input(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_blanket_tombstone_args *args,
	const struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_blanket_tombstone_input *input)
{
	struct pkm_lcs_rsi_built_request built = { };
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE + sizeof(u32) +
		 1024U + sizeof(u8) + sizeof(u64)];
	long ret;

	if (!ops || !ops->read || !args || !key_fd || !input)
		return -EINVAL;
	memset(input, 0, sizeof(*input));
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&input->limits);
	if (args->set != 0 && args->set != 1)
		return -EINVAL;

	ret = pkm_lcs_key_fd_copy_blanket_tombstone_layer(ops, args, input);
	if (ret)
		return ret;
	input->set = args->set != 0;

	return pkm_lcs_rsi_build_set_blanket_tombstone_request(
		frame, sizeof(frame), 1, 0, key_fd->key_guid,
		input->target.name, input->target.name_len, input->set,
		input->set ? 1ULL : 0ULL, &input->limits, &built);
}

static long pkm_lcs_key_fd_copy_hide_key_input(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_hide_key_args *args,
	struct pkm_lcs_hide_key_input *input)
{
	if (!ops || !ops->read || !args || !input)
		return -EINVAL;
	memset(input, 0, sizeof(*input));
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&input->limits);

	return pkm_lcs_key_fd_copy_hide_key_layer(ops, args, input);
}

static long pkm_lcs_key_fd_copy_delete_key_input(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_key_args *args,
	struct pkm_lcs_delete_key_input *input)
{
	if (!ops || !ops->read || !args || !input)
		return -EINVAL;
	memset(input, 0, sizeof(*input));
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&input->limits);

	return pkm_lcs_key_fd_copy_delete_key_layer(ops, args, input);
}

static long pkm_lcs_key_fd_authorize_value_layer_target(
	const struct pkm_lcs_create_layer_target *target, const void *token)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_layer_target_admission_plan target_plan = { };
	struct pkm_lcs_key_open_access_plan layer_plan = { };
	long ret;

	if (!target)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;
	ret = pkm_lcs_create_layer_target_admit(
		target, layer_snapshot.layers, layer_snapshot.layer_count,
		&target_plan);
	if (ret)
		goto out_snapshot;
	ret = pkm_lcs_create_layer_write_access_check_for_token(
		token, target, layer_snapshot.base_metadata_present,
		layer_snapshot.base_metadata_sd,
		layer_snapshot.base_metadata_sd_len, layer_snapshot.metadata,
		layer_snapshot.metadata_count, &layer_plan);

out_snapshot:
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_set_value_authorize_layer(
	const struct pkm_lcs_set_value_input *input, const void *token)
{
	if (!input)
		return -EINVAL;

	return pkm_lcs_key_fd_authorize_value_layer_target(&input->target,
							   token);
}

static long pkm_lcs_key_fd_delete_value_authorize_layer(
	const struct pkm_lcs_delete_value_input *input, const void *token)
{
	if (!input)
		return -EINVAL;

	return pkm_lcs_key_fd_authorize_value_layer_target(&input->target,
							   token);
}

static long pkm_lcs_key_fd_blanket_tombstone_authorize_layer(
	const struct pkm_lcs_blanket_tombstone_input *input,
	const void *token)
{
	if (!input)
		return -EINVAL;

	return pkm_lcs_key_fd_authorize_value_layer_target(&input->target,
							   token);
}

static long pkm_lcs_key_fd_hide_key_authorize_layer(
	const struct pkm_lcs_hide_key_input *input, const void *token)
{
	if (!input)
		return -EINVAL;

	return pkm_lcs_key_fd_authorize_value_layer_target(&input->target,
							   token);
}

static long pkm_lcs_key_fd_delete_key_authorize_layer(
	const struct pkm_lcs_delete_key_input *input, const void *token)
{
	if (!input)
		return -EINVAL;

	return pkm_lcs_key_fd_authorize_value_layer_target(&input->target,
							   token);
}

static long pkm_lcs_key_fd_path_entry_target(
	const struct pkm_lcs_key_fd *key_fd,
	const u8 **parent_guid_out, const char **child_name_out,
	u32 *child_name_len_out)
{
	const char *child_name;
	size_t child_name_len;
	u32 parent_index;

	if (!key_fd || !parent_guid_out || !child_name_out ||
	    !child_name_len_out)
		return -EINVAL;
	*parent_guid_out = NULL;
	*child_name_out = NULL;
	*child_name_len_out = 0;

	if (key_fd->orphaned)
		return -ENOENT;
	if (key_fd->path_component_count < 2)
		return -EINVAL;
	if (!key_fd->resolved_path || !key_fd->ancestor_guids)
		return -EIO;

	parent_index = key_fd->path_component_count - 2U;
	if (pkm_lcs_guid_is_nil(key_fd->ancestor_guids[parent_index]))
		return -EIO;

	child_name = key_fd->resolved_path[key_fd->path_component_count - 1U];
	if (!child_name)
		return -EIO;
	child_name_len = strlen(child_name);
	if (child_name_len > U32_MAX)
		return -EIO;

	*parent_guid_out = key_fd->ancestor_guids[parent_index];
	*child_name_out = child_name;
	*child_name_len_out = (u32)child_name_len;
	return 0;
}

static long pkm_lcs_key_fd_validate_hide_key_request_shape(
	const u8 parent_guid[PKM_LCS_GUID_BYTES], const char *child_name,
	u32 child_name_len, const struct pkm_lcs_hide_key_input *input)
{
	struct pkm_lcs_rsi_built_request built = { };
	size_t frame_len;
	u8 *frame;
	long ret;

	if (!parent_guid || !child_name || !input)
		return -EINVAL;
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)child_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)input->target.name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u64), &frame_len))
		return -EOVERFLOW;

	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = pkm_lcs_rsi_build_hide_entry_request(
		frame, frame_len, 1, 0, parent_guid, child_name,
		child_name_len, input->target.name, input->target.name_len, 1,
		&input->limits, &built);
	kfree(frame);
	return ret;
}

static long pkm_lcs_key_fd_validate_delete_key_request_shape(
	const u8 parent_guid[PKM_LCS_GUID_BYTES], const char *child_name,
	u32 child_name_len, const struct pkm_lcs_delete_key_input *input)
{
	struct pkm_lcs_rsi_built_request built = { };
	size_t frame_len;
	u8 *frame;
	long ret;

	if (!parent_guid || !child_name || !input)
		return -EINVAL;
	if (check_add_overflow((size_t)RSI_REQUEST_HEADER_SIZE,
			       (size_t)RSI_GUID_SIZE, &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)child_name_len,
			       &frame_len) ||
	    check_add_overflow(frame_len, sizeof(u32), &frame_len) ||
	    check_add_overflow(frame_len, (size_t)input->target.name_len,
			       &frame_len))
		return -EOVERFLOW;

	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = pkm_lcs_rsi_build_delete_entry_request(
		frame, frame_len, 1, 0, parent_guid, child_name,
		child_name_len, input->target.name, input->target.name_len,
		&input->limits, &built);
	kfree(frame);
	return ret;
}

static long pkm_lcs_key_fd_delete_key_visible_child_gate(
	const struct pkm_lcs_key_fd *key_fd, u64 txn_id,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	u64 next_sequence = 0;
	long ret;

	if (!key_fd || !limits)
		return -EINVAL;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid,
		limits, limits->request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		frame.data, frame.len, response.request_id, next_sequence,
		layer_snapshot.layers, layer_snapshot.layer_count, NULL, 0,
		&response.limits, &summary);
	if (ret)
		goto out_frame;
	if (summary.subkey_count)
		ret = -ENOTEMPTY;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_delete_key_post_lookup(
	const struct pkm_lcs_key_fd *key_fd,
	const u8 parent_guid[PKM_LCS_GUID_BYTES], const char *child_name,
	u32 child_name_len, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_delete_key_post_lookup *out)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_lookup_guid_entry_result target = { };
	struct pkm_lcs_rsi_lookup_child_result effective = { };
	u64 next_sequence = 0;
	long ret;

	if (!key_fd || !parent_guid || !child_name || !limits || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, 0, parent_guid, child_name, child_name_len,
		limits, limits->request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_lookup_guid_entry(
		frame.data, frame.len, response.request_id, next_sequence,
		child_name, child_name_len, key_fd->key_guid,
		&response.limits, &target);
	if (ret)
		goto out_frame;
	out->target_still_named = target.present != 0;

	ret = pkm_lcs_rsi_materialize_lookup_child(
		frame.data, frame.len, response.request_id, next_sequence,
		child_name, child_name_len, layer_snapshot.layers,
		layer_snapshot.layer_count, NULL, 0, &response.limits,
		&effective);
	if (ret)
		goto out_frame;

	if (effective.found &&
	    !pkm_lcs_guid_equal(effective.key_guid, key_fd->key_guid))
		out->replacement_visible = true;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_set_value_layer_cap_check(
	const struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_set_value_input *input, u64 txn_id)
{
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_value_layer_admission_result result = { };
	u64 next_sequence = 0;
	long ret;

	if (!key_fd || !input)
		return -EINVAL;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, input->value_name,
		(input->value_name ? (u32)strlen(input->value_name) : 0),
		false, &input->limits, input->limits.request_timeout_ms, &frame,
		&response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_plan_set_value_layer_admission(
		frame.data, frame.len, response.request_id, next_sequence,
		input->value_name,
		(input->value_name ? (u32)strlen(input->value_name) : 0),
		input->target.name, input->target.name_len, &input->limits,
		&result);

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

static long pkm_lcs_key_fd_value_name_casefold_equal_with_limits(
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

	ret = lcs_rust_value_name_casefold_eq((const u8 *)left, left_len,
					      (const u8 *)right, right_len,
					      limits, &raw_equal);
	if (ret)
		return ret;
	*equal = raw_equal != 0;
	return 0;
}

static bool pkm_lcs_set_value_data_is_positive_dword(
	const struct pkm_lcs_set_value_input *input,
	const struct reg_set_value_args *args)
{
	if (!input || !args)
		return false;
	if (args->type != REG_DWORD || args->data_len != sizeof(u32) ||
	    !input->data)
		return false;

	return get_unaligned_le32(input->data) > 0;
}

static long pkm_lcs_key_fd_set_value_precedence_tcb_gate(
	const struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct pkm_lcs_set_value_input *input,
	const struct reg_set_value_args *args)
{
	static const char precedence_name[] = "Precedence";
	bool is_layer_metadata_key = false;
	bool is_precedence = false;
	long ret;

	if (!key_fd || !input || !args)
		return -EINVAL;
	if (!pkm_lcs_set_value_data_is_positive_dword(input, args))
		return 0;

	ret = pkm_lcs_layer_table_metadata_key_guid_present(
		key_fd->key_guid, &is_layer_metadata_key);
	if (ret)
		return ret;
	if (!is_layer_metadata_key)
		return 0;

	ret = pkm_lcs_key_fd_value_name_casefold_equal_with_limits(
		input->value_name, args->name_len, precedence_name,
		sizeof(precedence_name) - 1, &input->limits, &is_precedence);
	if (ret)
		return ret;
	if (!is_precedence)
		return 0;

	if (!token ||
	    !kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE))
		return -EPERM;
	return 0;
}

static long pkm_lcs_key_fd_layer_name_casefold_equal_with_limits(
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

static long pkm_lcs_key_fd_layer_name_casefold_equal(
	const char *left, u32 left_len, const char *right, u32 right_len,
	bool *equal)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_key_fd_layer_name_casefold_equal_with_limits(
		left, left_len, right, right_len, &limits, equal);
}

static long pkm_lcs_key_fd_path_component_casefold_equal_with_limits(
	const char *component, const char *expected,
	const struct pkm_lcs_runtime_limits *limits, bool *equal)
{
	size_t component_len;
	size_t expected_len;

	if (!component || !expected || !limits || !equal)
		return -EINVAL;
	component_len = strlen(component);
	expected_len = strlen(expected);
	if (component_len > U32_MAX || expected_len > U32_MAX)
		return -EOVERFLOW;
	return pkm_lcs_key_fd_value_name_casefold_equal_with_limits(
		component, (u32)component_len, expected, (u32)expected_len,
		limits, equal);
}

static long pkm_lcs_key_fd_layer_metadata_path_with_limits(
	const struct pkm_lcs_key_fd *key_fd, const char **layer_name_out,
	u32 *layer_name_len_out, const struct pkm_lcs_runtime_limits *limits,
	bool *matches_out)
{
	static const char * const prefix[] = {
		"Machine", "System", "Registry", "Layers"
	};
	const char *layer_name;
	u32 i;

	if (!layer_name_out || !layer_name_len_out || !matches_out)
		return -EINVAL;
	*layer_name_out = NULL;
	*layer_name_len_out = 0;
	*matches_out = false;
	if (!key_fd || !key_fd->resolved_path || !limits)
		return -EINVAL;
	if (key_fd->path_component_count != ARRAY_SIZE(prefix) + 1U)
		return 0;

	for (i = 0; i < ARRAY_SIZE(prefix); i++) {
		bool equal = false;
		long ret;

		if (!key_fd->resolved_path[i])
			return -EINVAL;
		ret = pkm_lcs_key_fd_path_component_casefold_equal_with_limits(
			key_fd->resolved_path[i], prefix[i], limits, &equal);
		if (ret)
			return ret;
		if (!equal)
			return 0;
	}

	layer_name = key_fd->resolved_path[ARRAY_SIZE(prefix)];
	if (!layer_name)
		return -EINVAL;
	if (strlen(layer_name) > U32_MAX)
		return -EOVERFLOW;

	*layer_name_out = layer_name;
	*layer_name_len_out = (u32)strlen(layer_name);
	*matches_out = true;
	return 0;
}

static long pkm_lcs_key_fd_query_layer_metadata_dword_with_limits(
	const struct pkm_lcs_key_fd *key_fd, const char *value_name,
	u32 value_name_len, const struct pkm_lcs_runtime_limits *limits,
	bool *found_out, u32 *value_out)
{
	struct pkm_lcs_effective_value_snapshot snapshot = { };
	const u8 *data;
	long ret;

	if (!limits || !found_out || !value_out)
		return -EINVAL;
	*found_out = false;
	*value_out = 0;

	ret = pkm_lcs_key_fd_query_effective_value_snapshot_with_limits(
		key_fd, 0, value_name, value_name_len, limits, &snapshot);
	if (ret)
		return ret;
	if (!snapshot.result.found)
		goto out;
	if (snapshot.result.value_type != REG_DWORD ||
	    snapshot.result.data_len != sizeof(u32)) {
		ret = -EIO;
		goto out;
	}
	data = snapshot.frame.data + snapshot.result.data_offset;
	*found_out = true;
	*value_out = get_unaligned_le32(data);

out:
	pkm_lcs_effective_value_snapshot_destroy(&snapshot);
	return ret;
}

static long pkm_lcs_key_fd_query_layer_metadata_owner_with_limits(
	const struct pkm_lcs_key_fd *key_fd, const char *value_name,
	u32 value_name_len, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_effective_value_snapshot *snapshot,
	bool *found_out, const u8 **owner_sid_out, size_t *owner_sid_len_out)
{
	long ret;

	if (!limits || !snapshot || !found_out || !owner_sid_out ||
	    !owner_sid_len_out)
		return -EINVAL;
	*found_out = false;
	*owner_sid_out = NULL;
	*owner_sid_len_out = 0;

	ret = pkm_lcs_key_fd_query_effective_value_snapshot_with_limits(
		key_fd, 0, value_name, value_name_len, limits, snapshot);
	if (ret) {
		pkm_lcs_effective_value_snapshot_destroy(snapshot);
		return ret;
	}
	if (!snapshot->result.found)
		return 0;
	if (snapshot->result.value_type != REG_BINARY ||
	    !snapshot->result.data_len) {
		ret = -EIO;
		goto out;
	}
	if ((size_t)snapshot->result.data_offset > snapshot->frame.len ||
	    (size_t)snapshot->result.data_len >
		    snapshot->frame.len - (size_t)snapshot->result.data_offset) {
		ret = -EIO;
		goto out;
	}

	*found_out = true;
	*owner_sid_out = snapshot->frame.data + snapshot->result.data_offset;
	*owner_sid_len_out = snapshot->result.data_len;
	return 0;

out:
	pkm_lcs_effective_value_snapshot_destroy(snapshot);
	return ret;
}

static void pkm_lcs_key_fd_emit_layer_metadata_sd_validation_failure(
	const struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_source_response_result *response)
{
	u64 request_id = 0;
	u16 op_code = RSI_READ_KEY;
	bool request_id_present = false;

	if (!key_fd)
		return;
	if (response) {
		if (response->request_op_code) {
			request_id = response->request_id;
			request_id_present = true;
			op_code = response->request_op_code;
		}
	}

	(void)pkm_lcs_emit_source_validation_failure_audit(
		key_fd->source_id, NULL, 0, false, request_id,
		request_id_present, op_code, true, key_fd->key_guid, true,
		PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_METADATA_SD);
}

static long pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context_limits(
	const struct pkm_lcs_key_fd *key_fd, const u8 *creator_sid,
	size_t creator_sid_len, bool is_new_layer,
	const struct pkm_lcs_runtime_limits *limits,
	bool *effective_changed_out)
{
	static const char precedence_name[] = "Precedence";
	static const char enabled_name[] = "Enabled";
	static const char owner_name[] = "Owner";
	static const char base_name[] = "base";
	struct pkm_lcs_layer_table_publish_result publish_result = { };
	struct pkm_lcs_source_response_frame read_frame = { };
	struct pkm_lcs_source_response_result read_response = { };
	struct pkm_lcs_effective_value_snapshot owner_snapshot = { };
	const char *layer_name = NULL;
	const u8 *sd = NULL;
	const u8 *owner_sid = NULL;
	u8 *selected_owner_sid = NULL;
	u8 *previous_owner_sid = NULL;
	size_t sd_len = 0;
	size_t owner_sid_len = 0;
	size_t selected_owner_sid_len = 0;
	size_t previous_owner_sid_len = 0;
	u32 owner_source = 0;
	u32 layer_name_len = 0;
	u32 precedence = 0;
	u32 enabled_raw = 1;
	bool matches = false;
	bool is_base = false;
	bool found = false;
	bool owner_found = false;
	bool previous_owner_present = false;
	u8 enabled = 1;
	long ret;

	if (effective_changed_out)
		*effective_changed_out = false;
	if (!limits)
		return -EINVAL;

	ret = pkm_lcs_key_fd_layer_metadata_path_with_limits(
		key_fd, &layer_name, &layer_name_len, limits, &matches);
	if (ret || !matches)
		return ret;

	ret = pkm_lcs_key_fd_layer_name_casefold_equal_with_limits(
		layer_name, layer_name_len, base_name, sizeof(base_name) - 1,
		limits, &is_base);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_read_existing_sd(key_fd, 0, limits, &read_frame,
					      &sd, &sd_len, &read_response);
	if (ret) {
		if (ret == -EIO && read_response.request_op_code &&
		    read_response.status == RSI_OK)
			pkm_lcs_key_fd_emit_layer_metadata_sd_validation_failure(
				key_fd, &read_response);
		goto out_read_frame;
	}
	if (is_base) {
		ret = pkm_lcs_base_layer_metadata_publish(key_fd->key_guid,
							  sd, sd_len);
		if (ret == -EIO)
			pkm_lcs_key_fd_emit_layer_metadata_sd_validation_failure(
				key_fd, &read_response);
		goto out_read_frame;
	}

	ret = pkm_lcs_key_fd_query_layer_metadata_dword_with_limits(
		key_fd, precedence_name, sizeof(precedence_name) - 1, limits,
		&found, &precedence);
	if (ret)
		goto out_read_frame;
	if (!found)
		precedence = 0;

	ret = pkm_lcs_key_fd_query_layer_metadata_dword_with_limits(
		key_fd, enabled_name, sizeof(enabled_name) - 1, limits,
		&found, &enabled_raw);
	if (ret)
		goto out_read_frame;
	if (!found) {
		enabled = 1;
	} else if (enabled_raw <= 1) {
		enabled = (u8)enabled_raw;
	} else {
		ret = -EIO;
		goto out_read_frame;
	}

	ret = pkm_lcs_key_fd_query_layer_metadata_owner_with_limits(
		key_fd, owner_name, sizeof(owner_name) - 1, limits,
		&owner_snapshot, &owner_found, &owner_sid, &owner_sid_len);
	if (ret)
		goto out_read_frame;

	ret = pkm_lcs_layer_table_owner_snapshot(
		layer_name, layer_name_len, &previous_owner_sid,
		&previous_owner_sid_len, &previous_owner_present);
	if (ret)
		goto out_owner_snapshot;

	ret = pkm_lcs_layer_owner_select_copy(
		owner_sid, owner_sid_len, owner_found, creator_sid,
		creator_sid_len, creator_sid && creator_sid_len,
		previous_owner_sid, previous_owner_sid_len,
		previous_owner_present, sd, sd_len, true, is_new_layer,
		&selected_owner_sid, &selected_owner_sid_len, &owner_source);
	if (ret)
		goto out_previous_owner;

	ret = pkm_lcs_layer_table_publish_with_result_with_limits(
		layer_name, layer_name_len, precedence, enabled,
		key_fd->key_guid, sd, sd_len, selected_owner_sid,
		selected_owner_sid_len, limits, &publish_result);
	if (ret == -EIO)
		pkm_lcs_key_fd_emit_layer_metadata_sd_validation_failure(
			key_fd, &read_response);
	if (!ret && effective_changed_out)
		*effective_changed_out = publish_result.effective_changed;

out_previous_owner:
	kfree(previous_owner_sid);
out_owner_snapshot:
	kfree(selected_owner_sid);
	pkm_lcs_effective_value_snapshot_destroy(&owner_snapshot);
out_read_frame:
	pkm_lcs_source_response_frame_destroy(&read_frame);
	return ret;
}

static long pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context(
	const struct pkm_lcs_key_fd *key_fd, const u8 *creator_sid,
	size_t creator_sid_len, bool is_new_layer, bool *effective_changed_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context_limits(
		key_fd, creator_sid, creator_sid_len, is_new_layer, &limits,
		effective_changed_out);
}

static long pkm_lcs_key_fd_orchestrate_deleted_layer_metadata_key(
	const struct pkm_lcs_key_fd *key_fd, bool *orchestrated_out)
{
	static const char base_name[] = "base";
	struct pkm_lcs_runtime_limits limits;
	const char *layer_name = NULL;
	u32 layer_name_len = 0;
	bool matches = false;
	bool is_base = false;
	long ret;

	if (orchestrated_out)
		*orchestrated_out = false;
	if (!orchestrated_out)
		return -EINVAL;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	ret = pkm_lcs_key_fd_layer_metadata_path_with_limits(
		key_fd, &layer_name, &layer_name_len, &limits, &matches);
	if (ret || !matches)
		return ret;

	ret = pkm_lcs_key_fd_layer_name_casefold_equal_with_limits(
		layer_name, layer_name_len, base_name, sizeof(base_name) - 1,
		&limits, &is_base);
	if (ret)
		return ret;
	if (is_base)
		return 0;

	ret = pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
		layer_name, layer_name_len, limits.request_timeout_ms, 0, NULL,
		&limits, NULL);
	if (!ret)
		*orchestrated_out = true;
	return ret;
}

static long pkm_lcs_key_fd_refresh_layer_metadata(
	const struct pkm_lcs_key_fd *key_fd)
{
	return pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context(
		key_fd, NULL, 0, false, NULL);
}

static long pkm_lcs_key_fd_refresh_layer_metadata_result(
	const struct pkm_lcs_key_fd *key_fd, bool *effective_changed_out)
{
	return pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context(
		key_fd, NULL, 0, false, effective_changed_out);
}

long pkm_lcs_key_path_refresh_layer_metadata(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count)
{
	return pkm_lcs_key_path_refresh_layer_metadata_with_owner_context(
		source_id, key_guid, resolved_path, path_component_count, NULL,
		0, false);
}

long pkm_lcs_key_path_refresh_layer_metadata_result(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	bool *effective_changed_out)
{
	return pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result(
		source_id, key_guid, resolved_path, path_component_count, NULL,
		0, false, effective_changed_out);
}

long pkm_lcs_key_path_refresh_layer_metadata_with_owner_context(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	const u8 *creator_sid, size_t creator_sid_len, bool is_new_layer)
{
	return pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result(
		source_id, key_guid, resolved_path, path_component_count,
		creator_sid, creator_sid_len, is_new_layer, NULL);
}

long pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	const u8 *creator_sid, size_t creator_sid_len, bool is_new_layer,
	bool *effective_changed_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
		source_id, key_guid, resolved_path, path_component_count,
		creator_sid, creator_sid_len, is_new_layer, &limits,
		effective_changed_out);
}

long pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	const u8 *creator_sid, size_t creator_sid_len, bool is_new_layer,
	const struct pkm_lcs_runtime_limits *limits,
	bool *effective_changed_out)
{
	struct pkm_lcs_key_fd key_fd = { };

	if (!source_id || !key_guid || !resolved_path || !path_component_count ||
	    !limits)
		return -EINVAL;

	key_fd.source_id = source_id;
	memcpy(key_fd.key_guid, key_guid, sizeof(key_fd.key_guid));
	key_fd.resolved_path = (char **)resolved_path;
	key_fd.path_component_count = path_component_count;
	return pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context_limits(
		&key_fd, creator_sid, creator_sid_len, is_new_layer, limits,
		effective_changed_out);
}

static long pkm_lcs_key_fd_query_values_batch_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_values_batch_args *args)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_query_values_batch_result result = { };
	struct pkm_lcs_rsi_query_values_batch_result written = { };
	struct pkm_lcs_runtime_limits limits;
	u64 next_sequence = 0;
	u64 txn_id = 0;
	u64 buf_ptr;
	u32 buf_len;
	s32 txn_fd;
	u8 *output = NULL;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->write)
		return -EINVAL;

	buf_len = args->buf_len;
	buf_ptr = args->buf_ptr;
	txn_fd = args->txn_fd;

	if (args->_pad)
		return -EINVAL;
	if (buf_len && !buf_ptr)
		return -EFAULT;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_QUERY_VALUES_BATCH_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_query_value_prepare_read_context(key_fd, txn_fd,
							      &txn_id);
	if (ret)
		return ret;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, "", 0, true,
		&limits, limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_query_values_batch_response(
		frame.data, frame.len, response.request_id, next_sequence,
		layer_snapshot.layers, layer_snapshot.layer_count, NULL, 0,
		&response.limits, NULL, 0, &result);
	if (ret)
		goto out_frame;

	if (buf_len < result.required_len) {
		pkm_lcs_key_fd_query_values_batch_reset_args(
			args, buf_len, buf_ptr, txn_fd);
		args->buf_len = result.required_len;
		ret = -ERANGE;
		goto out_frame;
	}

	if (result.required_len) {
		output = kmalloc(result.required_len, GFP_KERNEL);
		if (!output) {
			ret = -ENOMEM;
			goto out_frame;
		}
		ret = pkm_lcs_rsi_materialize_query_values_batch_response(
			frame.data, frame.len, response.request_id,
			next_sequence, layer_snapshot.layers,
			layer_snapshot.layer_count, NULL, 0, &response.limits,
			output, result.required_len, &written);
		if (ret)
			goto out_output;
		if (written.required_len != result.required_len ||
		    written.written_len != result.required_len ||
		    written.count != result.count) {
			ret = -EIO;
			goto out_output;
		}
		if (!ops->write(ops->ctx, (void __user *)(unsigned long)buf_ptr,
				output, result.required_len)) {
			ret = -EFAULT;
			goto out_output;
		}
	}

	pkm_lcs_key_fd_query_values_batch_reset_args(args, buf_len, buf_ptr,
						     txn_fd);
	args->buf_len = result.required_len;
	args->count = result.count;
	ret = 0;

out_output:
	kfree(output);
out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static void pkm_lcs_key_fd_enum_value_reset_args(
	struct reg_enum_value_args *args, u32 index, u32 name_len,
	u64 name_ptr, u32 data_len, u64 data_ptr, s32 txn_fd)
{
	memset(args, 0, sizeof(*args));
	args->index = index;
	args->name_len = name_len;
	args->name_ptr = name_ptr;
	args->data_len = data_len;
	args->data_ptr = data_ptr;
	args->txn_fd = txn_fd;
}

static long pkm_lcs_key_fd_enum_value_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_enum_value_args *args)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_enum_value_result result = { };
	struct pkm_lcs_runtime_limits limits;
	const u8 *name;
	const u8 *data;
	u64 next_sequence = 0;
	u64 txn_id = 0;
	u64 name_ptr;
	u64 data_ptr;
	u32 index;
	u32 name_buf_len;
	u32 data_buf_len;
	s32 txn_fd;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->write)
		return -EINVAL;

	index = args->index;
	name_buf_len = args->name_len;
	name_ptr = args->name_ptr;
	data_buf_len = args->data_len;
	data_ptr = args->data_ptr;
	txn_fd = args->txn_fd;

	if (args->_pad)
		return -EINVAL;
	if (name_buf_len && !name_ptr)
		return -EFAULT;
	if (data_buf_len && !data_ptr)
		return -EFAULT;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_ENUM_VALUES_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_query_value_prepare_read_context(key_fd, txn_fd,
							      &txn_id);
	if (ret)
		return ret;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, "", 0, true,
		&limits, limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_enum_value_response(
		frame.data, frame.len, response.request_id, next_sequence,
		index, layer_snapshot.layers, layer_snapshot.layer_count, NULL,
		0, &response.limits, &result);
	if (ret)
		goto out_frame;
	if (!result.found) {
		ret = -ENOENT;
		goto out_frame;
	}
	if ((size_t)result.name_offset > frame.len ||
	    (size_t)result.name_len >
		    frame.len - (size_t)result.name_offset ||
	    (size_t)result.data_offset > frame.len ||
	    (size_t)result.data_len >
		    frame.len - (size_t)result.data_offset) {
		ret = -EIO;
		goto out_frame;
	}

	if (name_buf_len < result.name_len ||
	    data_buf_len < result.data_len) {
		pkm_lcs_key_fd_enum_value_reset_args(args, index, name_buf_len,
						     name_ptr, data_buf_len,
						     data_ptr, txn_fd);
		args->name_len = result.name_len;
		args->data_len = result.data_len;
		ret = -ERANGE;
		goto out_frame;
	}

	name = frame.data + result.name_offset;
	data = frame.data + result.data_offset;
	if (result.name_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)name_ptr,
			name, result.name_len)) {
		ret = -EFAULT;
		goto out_frame;
	}
	if (result.data_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)data_ptr,
			data, result.data_len)) {
		ret = -EFAULT;
		goto out_frame;
	}

	pkm_lcs_key_fd_enum_value_reset_args(args, index, name_buf_len,
					     name_ptr, data_buf_len, data_ptr,
					     txn_fd);
	args->type = result.value_type;
	args->name_len = result.name_len;
	args->data_len = result.data_len;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static void pkm_lcs_key_fd_enum_subkey_reset_args(
	struct reg_enum_subkey_args *args, u32 index, u32 name_len,
	u64 name_ptr, s32 txn_fd)
{
	memset(args, 0, sizeof(*args));
	args->index = index;
	args->name_len = name_len;
	args->name_ptr = name_ptr;
	args->txn_fd = txn_fd;
}

static long pkm_lcs_key_fd_enum_subkey_read_metadata(
	struct pkm_lcs_key_fd *key_fd, u64 txn_id, u64 next_sequence,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	const u8 child_guid[RSI_GUID_SIZE],
	struct reg_enum_subkey_args *args)
{
	struct pkm_lcs_source_response_frame read_frame = { };
	struct pkm_lcs_source_response_frame enum_frame = { };
	struct pkm_lcs_source_response_frame values_frame = { };
	struct pkm_lcs_source_response_result read_response = { };
	struct pkm_lcs_source_response_result enum_response = { };
	struct pkm_lcs_source_response_result values_response = { };
	struct pkm_lcs_rsi_enum_children_info_summary enum_summary = { };
	struct pkm_lcs_rsi_query_values_info_summary values_summary = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	long ret;

	if (!limits)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(&read_frame);
	pkm_lcs_source_response_frame_init(&enum_frame);
	pkm_lcs_source_response_frame_init(&values_frame);

	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, child_guid, limits,
		limits->request_timeout_ms, &read_frame,
		&read_response, NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
		read_frame.data, read_frame.len, read_response.request_id,
		limits, &read_key);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, child_guid, limits,
		limits->request_timeout_ms, &enum_frame,
		&enum_response, NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		enum_frame.data, enum_frame.len, enum_response.request_id,
		next_sequence, layers, layer_count, NULL, 0,
		&enum_response.limits, &enum_summary);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, child_guid, "", 0, true,
		limits, limits->request_timeout_ms, &values_frame,
		&values_response, NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_query_values_info_summary(
		values_frame.data, values_frame.len, values_response.request_id,
		next_sequence, layers, layer_count, NULL, 0,
		&values_response.limits, &values_summary);
	if (ret)
		goto out_frames;

	args->last_write_time = read_key.last_write_time;
	args->subkey_count = enum_summary.subkey_count;
	args->value_count = values_summary.value_count;
	ret = 0;

out_frames:
	pkm_lcs_source_response_frame_destroy(&values_frame);
	pkm_lcs_source_response_frame_destroy(&enum_frame);
	pkm_lcs_source_response_frame_destroy(&read_frame);
	return ret;
}

static long pkm_lcs_key_fd_enum_subkey_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_enum_subkey_args *args)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_enum_subkey_result result = { };
	struct pkm_lcs_runtime_limits limits;
	const u8 *name;
	u64 next_sequence = 0;
	u64 txn_id = 0;
	u64 name_ptr;
	u32 index;
	u32 name_buf_len;
	s32 txn_fd;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->write)
		return -EINVAL;

	index = args->index;
	name_buf_len = args->name_len;
	name_ptr = args->name_ptr;
	txn_fd = args->txn_fd;

	if (args->_pad)
		return -EINVAL;
	if (name_buf_len && !name_ptr)
		return -EFAULT;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_ENUM_SUBKEYS_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_query_value_prepare_read_context(key_fd, txn_fd,
							      &txn_id);
	if (ret)
		return ret;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, &limits,
		limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_enum_subkey_response(
		frame.data, frame.len, response.request_id, next_sequence,
		index, layer_snapshot.layers, layer_snapshot.layer_count, NULL,
		0, &response.limits, &result);
	if (ret)
		goto out_frame;
	if (!result.found) {
		ret = -ENOENT;
		goto out_frame;
	}
	if ((size_t)result.name_offset > frame.len ||
	    (size_t)result.name_len >
		    frame.len - (size_t)result.name_offset) {
		ret = -EIO;
		goto out_frame;
	}

	if (name_buf_len < result.name_len) {
		pkm_lcs_key_fd_enum_subkey_reset_args(
			args, index, name_buf_len, name_ptr, txn_fd);
		args->name_len = result.name_len;
		ret = -ERANGE;
		goto out_frame;
	}

	pkm_lcs_key_fd_enum_subkey_reset_args(args, index, name_buf_len,
					      name_ptr, txn_fd);
	args->name_len = result.name_len;
	ret = pkm_lcs_key_fd_enum_subkey_read_metadata(
		key_fd, txn_id, next_sequence, layer_snapshot.layers,
		layer_snapshot.layer_count, &limits, result.child_guid, args);
	if (ret)
		goto out_frame;

	name = frame.data + result.name_offset;
	if (result.name_len &&
	    !ops->write(ops->ctx, (void __user *)(unsigned long)name_ptr,
			name, result.name_len))
		ret = -EFAULT;

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_set_security_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_security_args *args)
{
	struct pkm_lcs_set_security_merge_result merge = { };
	struct pkm_lcs_source_response_frame existing_frame = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_set_security_log_input log_input = { };
	struct pkm_lcs_runtime_limits limits = { };
	const u8 *existing_sd = NULL;
	size_t existing_sd_len = 0;
	u8 *input_sd = NULL;
	size_t input_sd_len = 0;
	u64 generation = 0;
	u64 last_write_time;
	u64 txn_id = 0;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (args->_pad)
		return -EINVAL;

	ret = lcs_rust_key_fd_security_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_SET_SECURITY_NR,
		args->security_info);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_set_security_sd(ops, args, &input_sd,
						  &input_sd_len);
	if (ret)
		return ret;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	if (args->txn_fd >= 0) {
		log_input.key_guid = key_fd->key_guid;
		log_input.path = (const char * const *)key_fd->resolved_path;
		log_input.ancestor_guids =
			(const u8 (*)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
				key_fd->ancestor_guids;
		log_input.depth = key_fd->path_component_count;

		ret = pkm_lcs_transaction_fd_begin_set_security_mutation(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&log_input, &mutation, &binding);
		if (ret)
			goto out_input;
		txn_id = binding.transaction_id;
	} else if (args->txn_fd != -1) {
		ret = -EINVAL;
		goto out_input;
	}

	ret = pkm_lcs_key_fd_read_existing_sd(key_fd, txn_id, &limits,
					      &existing_frame, &existing_sd,
					      &existing_sd_len, NULL);
	if (ret)
		goto out_cancel_mutation;

	ret = pkm_lcs_key_fd_plan_set_security_merge(
		existing_sd, existing_sd_len, input_sd, input_sd_len,
		args->security_info, &merge);
	if (ret)
		goto out_cancel_mutation;

	last_write_time = (u64)ktime_get_real_ns();
	ret = pkm_lcs_source_write_key_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, merge.merged_sd,
		merge.merged_sd_len, last_write_time, &limits,
		limits.request_timeout_ms, NULL, NULL);
	if (ret)
		goto out_cancel_merge;

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		goto out_merge;
	}

	ret = pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context_limits(
		key_fd, NULL, 0, false, &limits, NULL);
	if (ret)
		goto out_merge;

	ret = pkm_lcs_source_record_transaction_generation(
		key_fd->source_id, key_fd->ancestor_guids[0], &generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_merge;
	}

	pkm_lcs_key_fd_publish_set_security_effects(key_fd, &limits);

out_cancel_merge:
	if (ret && mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_merge:
	pkm_lcs_set_security_merge_result_destroy(&merge);
	goto out_existing;
out_cancel_mutation:
	if (mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_existing:
	pkm_lcs_source_response_frame_destroy(&existing_frame);
out_input:
	kfree(input_sd);
	return ret;
}

static long pkm_lcs_key_fd_set_value_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args)
{
	struct pkm_lcs_set_value_input input = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding_probe = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_set_value_log_input log_input = { };
	u64 generation = 0;
	u64 last_write_time;
	u64 sequence = 0;
	u64 cap_txn_id = 0;
	u64 txn_id = 0;
	bool layer_effective_changed = false;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!key_fd->path_component_count || !key_fd->ancestor_guids)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;

	if (args->_pad0 || args->_pad1 || args->_pad2)
		return -EINVAL;
	if (args->txn_fd < -1)
		return -EINVAL;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_SET_VALUE_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_set_value_input(ops, args, key_fd, &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_set_value_authorize_layer(&input, token);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_copy_set_value_data(ops, args, &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_set_value_precedence_tcb_gate(key_fd, token,
							   &input, args);
	if (ret)
		goto out_input;

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_prepare_mutation_binding(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&binding_probe);
		if (ret)
			goto out_input;
		if (binding_probe.action == PKM_LCS_TRANSACTION_BIND_REUSE)
			cap_txn_id = binding_probe.transaction_id;
	}

	ret = pkm_lcs_key_fd_set_value_layer_cap_check(key_fd, &input,
						       cap_txn_id);
	if (ret)
		goto out_input;

	ret = pkm_lcs_allocate_sequence(&sequence);
	if (ret)
		goto out_input;

	if (args->txn_fd >= 0) {
		log_input.key_guid = key_fd->key_guid;
		log_input.value_name = input.value_name;
		log_input.value_name_len = args->name_len;
		log_input.layer = input.target.name;
		log_input.layer_len = input.target.name_len;
		log_input.path = (const char * const *)key_fd->resolved_path;
		log_input.ancestor_guids =
			(const u8 (*)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
				key_fd->ancestor_guids;
		log_input.depth = key_fd->path_component_count;
		log_input.sequence = sequence;

		ret = pkm_lcs_transaction_fd_begin_set_value_mutation(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&log_input, &mutation, &binding);
		if (ret)
			goto out_input;
		txn_id = binding.transaction_id;
	}

	ret = pkm_lcs_source_set_value_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, input.value_name,
		args->name_len, input.target.name, input.target.name_len,
		args->type, input.data, args->data_len, sequence,
		args->expected_seq, &input.limits,
		input.limits.request_timeout_ms, &response, NULL);
	if (ret)
		goto out_cancel_mutation;

	last_write_time = (u64)ktime_get_real_ns();
	ret = pkm_lcs_source_write_key_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, NULL, 0,
		last_write_time, &input.limits, input.limits.request_timeout_ms,
		NULL, NULL);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_cancel_mutation;
	}

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		if (ret)
			goto out_cancel_mutation;
		goto out_input;
	}

	ret = pkm_lcs_key_fd_refresh_layer_metadata_with_owner_context_limits(
		key_fd, NULL, 0, false, &input.limits,
		&layer_effective_changed);
	if (ret)
		goto out_input;

	ret = pkm_lcs_source_record_transaction_generation(
		key_fd->source_id, key_fd->ancestor_guids[0], &generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_input;
	}

	if (layer_effective_changed) {
		struct pkm_lcs_layer_operation_recovery_result recovery = { };

		ret = pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
			key_fd->source_id, key_fd->ancestor_guids[0],
			&input.limits, &recovery);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(key_fd->source_id);
			ret = -EIO;
			goto out_input;
		}
	}

	pkm_lcs_key_fd_publish_set_value_effects(key_fd, input.value_name,
						 args->name_len, &input.limits);
	ret = 0;

out_cancel_mutation:
	if (ret && mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_input:
	pkm_lcs_set_value_input_destroy(&input);
	return ret;
}

static long pkm_lcs_key_fd_set_value_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args)
{
	return pkm_lcs_key_fd_set_value_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), ops, args);
}

static long pkm_lcs_key_fd_delete_value_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args)
{
	struct pkm_lcs_delete_value_input input = { };
	struct pkm_lcs_effective_value_snapshot before = { };
	struct pkm_lcs_effective_value_snapshot after = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_delete_value_log_input log_input = { };
	u64 generation = 0;
	u64 last_write_time;
	u64 txn_id = 0;
	u32 event_type = 0;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!key_fd->path_component_count || !key_fd->ancestor_guids)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;

	if (args->_pad0 || args->_pad1 || args->_pad2)
		return -EINVAL;
	if (args->txn_fd < -1)
		return -EINVAL;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_DELETE_VALUE_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_delete_value_input(ops, args, key_fd,
						     &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_delete_value_authorize_layer(&input, token);
	if (ret)
		goto out_input;

	if (args->txn_fd >= 0) {
		log_input.key_guid = key_fd->key_guid;
		log_input.value_name = input.value_name;
		log_input.value_name_len = args->name_len;
		log_input.layer = input.target.name;
		log_input.layer_len = input.target.name_len;
		log_input.path = (const char * const *)key_fd->resolved_path;
		log_input.ancestor_guids =
			(const u8 (*)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
				key_fd->ancestor_guids;
		log_input.depth = key_fd->path_component_count;

		ret = pkm_lcs_transaction_fd_begin_delete_value_mutation(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&log_input, &mutation, &binding);
		if (ret)
			goto out_input;
		txn_id = binding.transaction_id;
	}

	ret = pkm_lcs_key_fd_query_effective_value_snapshot_with_limits(
		key_fd, txn_id, input.value_name, args->name_len,
		&input.limits, &before);
	if (ret)
		goto out_cancel_mutation;

	ret = pkm_lcs_source_delete_value_entry_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, input.value_name,
		args->name_len, input.target.name, input.target.name_len,
		&input.limits, input.limits.request_timeout_ms, &response, NULL);
	if (ret)
		goto out_before;

	ret = pkm_lcs_key_fd_query_effective_value_snapshot_with_limits(
		key_fd, txn_id, input.value_name, args->name_len,
		&input.limits, &after);
	if (ret)
		goto out_before;

	last_write_time = (u64)ktime_get_real_ns();
	ret = pkm_lcs_source_write_key_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, NULL, 0,
		last_write_time, &input.limits, input.limits.request_timeout_ms,
		NULL, NULL);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_after;
	}

	ret = pkm_lcs_key_fd_delete_value_watch_event_type(&before, &after,
							   &event_type);
	if (ret)
		goto out_after;
	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_set_delete_value_event(
			&mutation, event_type);
		if (ret)
			goto out_after;
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		if (ret)
			goto out_after;
		goto out_after;
	}

	ret = pkm_lcs_source_record_transaction_generation(
		key_fd->source_id, key_fd->ancestor_guids[0], &generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_after;
	}

	if (event_type)
		pkm_lcs_key_fd_publish_value_effects(
			key_fd, event_type, input.value_name, args->name_len,
			&input.limits);
	ret = 0;

out_after:
	pkm_lcs_effective_value_snapshot_destroy(&after);
out_before:
	pkm_lcs_effective_value_snapshot_destroy(&before);
out_cancel_mutation:
	if (ret && mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_input:
	pkm_lcs_delete_value_input_destroy(&input);
	return ret;
}

static long pkm_lcs_key_fd_delete_value_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args)
{
	return pkm_lcs_key_fd_delete_value_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), ops, args);
}

static long pkm_lcs_key_fd_blanket_tombstone_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_blanket_tombstone_args *args)
{
	struct pkm_lcs_blanket_tombstone_input input = { };
	struct pkm_lcs_source_response_frame before_frame = { };
	struct pkm_lcs_source_response_frame after_frame = { };
	struct pkm_lcs_source_response_result before_response = { };
	struct pkm_lcs_source_response_result after_response = { };
	struct pkm_lcs_source_response_result mutation_response = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_blanket_tombstone_log_input log_input = { };
	struct pkm_lcs_value_watch_event_bytes events = { };
	u64 generation = 0;
	u64 last_write_time;
	u64 sequence = 0;
	u64 txn_id = 0;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!key_fd->path_component_count || !key_fd->ancestor_guids)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;

	if (args->_pad0 || memchr_inv(args->_pad1, 0, sizeof(args->_pad1)))
		return -EINVAL;
	if (args->txn_fd < -1)
		return -EINVAL;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_BLANKET_TOMBSTONE_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_blanket_tombstone_input(ops, args, key_fd,
							  &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_blanket_tombstone_authorize_layer(&input, token);
	if (ret)
		goto out_input;

	if (input.set) {
		ret = pkm_lcs_allocate_sequence(&sequence);
		if (ret)
			goto out_input;
	}

	if (args->txn_fd >= 0) {
		log_input.key_guid = key_fd->key_guid;
		log_input.layer = input.target.name;
		log_input.layer_len = input.target.name_len;
		log_input.path = (const char * const *)key_fd->resolved_path;
		log_input.ancestor_guids =
			(const u8 (*)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
				key_fd->ancestor_guids;
		log_input.depth = key_fd->path_component_count;
		log_input.sequence = sequence;
		log_input.set = input.set;

		ret = pkm_lcs_transaction_fd_begin_blanket_tombstone_mutation(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&log_input, &mutation, &binding);
		if (ret)
			goto out_input;
		txn_id = binding.transaction_id;
	}

	ret = pkm_lcs_key_fd_query_effective_values_frame(
		key_fd, txn_id, &input.limits, &before_frame, &before_response);
	if (ret)
		goto out_cancel_mutation;

	ret = pkm_lcs_source_set_blanket_tombstone_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid,
		input.target.name, input.target.name_len, input.set, sequence,
		&input.limits, input.limits.request_timeout_ms, &mutation_response,
		NULL);
	if (ret)
		goto out_before;

	ret = pkm_lcs_key_fd_query_effective_values_frame(
		key_fd, txn_id, &input.limits, &after_frame, &after_response);
	if (ret)
		goto out_before;

	last_write_time = (u64)ktime_get_real_ns();
	ret = pkm_lcs_source_write_key_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, key_fd->key_guid, NULL, 0,
		last_write_time, &input.limits, input.limits.request_timeout_ms,
		NULL, NULL);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_after;
	}

	ret = pkm_lcs_key_fd_materialize_value_watch_events(
		key_fd, &before_frame, &before_response, &after_frame,
		&after_response, &input.limits, &events);
	if (ret)
		goto out_after;

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_set_blanket_tombstone_events(
			&mutation, events.data, events.len, events.count);
		if (ret)
			goto out_events;
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		goto out_events;
	}

	ret = pkm_lcs_source_record_transaction_generation(
		key_fd->source_id, key_fd->ancestor_guids[0], &generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_events;
	}

	ret = pkm_lcs_key_fd_publish_value_watch_event_bytes(key_fd, &events,
							    &input.limits);

out_events:
	pkm_lcs_value_watch_event_bytes_destroy(&events);
out_after:
	pkm_lcs_source_response_frame_destroy(&after_frame);
out_before:
	pkm_lcs_source_response_frame_destroy(&before_frame);
out_cancel_mutation:
	if (ret && mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_input:
	pkm_lcs_blanket_tombstone_input_destroy(&input);
	return ret;
}

static long pkm_lcs_key_fd_blanket_tombstone_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_blanket_tombstone_args *args)
{
	return pkm_lcs_key_fd_blanket_tombstone_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), ops, args);
}

static long pkm_lcs_key_fd_delete_key_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_key_args *args)
{
	struct pkm_lcs_delete_key_input input = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_delete_key_log_input log_input = { };
	struct pkm_lcs_delete_key_post_lookup post_lookup = { };
	const u8 *parent_guid = NULL;
	const char *child_name = NULL;
	u64 generation = 0;
	u64 last_write_time;
	u64 txn_id = 0;
	u32 child_name_len = 0;
	u32 parent_depth = 0;
	u32 internal_watch_effects = 0;
	bool layer_delete_orchestrated = false;
	bool publish_deleted = false;
	bool publish_created = false;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;

	if (args->_pad0 || args->_pad1)
		return -EINVAL;
	if (args->txn_fd < -1)
		return -EINVAL;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_DELETE_KEY_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_delete_key_input(ops, args, &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_path_entry_target(key_fd, &parent_guid,
					       &child_name, &child_name_len);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_validate_delete_key_request_shape(
		parent_guid, child_name, child_name_len, &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_delete_key_authorize_layer(&input, token);
	if (ret)
		goto out_input;

	if (args->txn_fd >= 0) {
		parent_depth = key_fd->path_component_count - 1;
		log_input.key_guid = key_fd->key_guid;
		log_input.parent_guid = parent_guid;
		log_input.child_name = child_name;
		log_input.child_name_len = child_name_len;
		log_input.layer = input.target.name;
		log_input.layer_len = input.target.name_len;
		log_input.parent_path =
			(const char * const *)key_fd->resolved_path;
		log_input.parent_ancestor_guids =
			(const u8 (*)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
				key_fd->ancestor_guids;
		log_input.parent_depth = parent_depth;

		ret = pkm_lcs_transaction_fd_begin_delete_key_mutation(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&log_input, &mutation, &binding);
		if (ret)
			goto out_input;
		txn_id = binding.transaction_id;
	}

	ret = pkm_lcs_key_fd_delete_key_visible_child_gate(key_fd, txn_id,
							   &input.limits);
	if (ret)
		goto out_cancel_mutation;

	ret = pkm_lcs_source_delete_entry_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, parent_guid, child_name,
		child_name_len, input.target.name, input.target.name_len,
		&input.limits, input.limits.request_timeout_ms, &response, NULL);
	if (ret)
		goto out_cancel_mutation;

	if (args->txn_fd < 0) {
		ret = pkm_lcs_key_fd_delete_key_post_lookup(
			key_fd, parent_guid, child_name, child_name_len,
			&input.limits, &post_lookup);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(key_fd->source_id);
			ret = -EIO;
			goto out_cancel_mutation;
		}
		if (!post_lookup.target_still_named) {
			publish_deleted = true;
			publish_created = post_lookup.replacement_visible;
			ret = pkm_lcs_key_fd_mark_orphaned_internal(
				key_fd->source_id, key_fd->key_guid, NULL,
				NULL, false, &input.limits);
			if (ret) {
				pkm_lcs_source_mark_down_by_id(key_fd->source_id);
				ret = -EIO;
				goto out_cancel_mutation;
			}
		}
	}

	last_write_time = (u64)ktime_get_real_ns();
	ret = pkm_lcs_source_write_key_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, parent_guid, NULL, 0, last_write_time,
		&input.limits, input.limits.request_timeout_ms, NULL, NULL);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_cancel_mutation;
	}

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		if (ret)
			goto out_cancel_mutation;
		goto out_input;
	}

	if (publish_deleted) {
		internal_watch_effects =
			pkm_lcs_key_fd_publish_parent_subkey_deleted(
				key_fd, parent_guid, child_name, child_name_len,
				&input.limits);
		if (publish_created)
			internal_watch_effects |=
				pkm_lcs_key_fd_publish_parent_subkey_created(
					key_fd, parent_guid, child_name,
					child_name_len, &input.limits);
		pkm_lcs_key_fd_publish_key_deleted_context(key_fd,
							   &input.limits);
	}

	if (!(internal_watch_effects &
	      PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE)) {
		ret = pkm_lcs_key_fd_orchestrate_deleted_layer_metadata_key(
			key_fd, &layer_delete_orchestrated);
		if (ret)
			goto out_cancel_mutation;
	}
	if (layer_delete_orchestrated ||
	    (internal_watch_effects &
	     PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE))
		goto out_cancel_mutation;

	ret = pkm_lcs_source_record_transaction_generation(
		key_fd->source_id, key_fd->ancestor_guids[0], &generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_cancel_mutation;
	}
	ret = 0;

out_cancel_mutation:
	if (ret && mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_input:
	pkm_lcs_delete_key_input_destroy(&input);
	return ret;
}

static long pkm_lcs_key_fd_delete_key_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_key_args *args)
{
	return pkm_lcs_key_fd_delete_key_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), ops, args);
}

static long pkm_lcs_key_fd_hide_key_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_hide_key_args *args)
{
	struct pkm_lcs_hide_key_input input = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding_probe = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_hide_key_log_input log_input = { };
	const u8 *parent_guid = NULL;
	const char *child_name = NULL;
	u64 generation = 0;
	u64 sequence = 0;
	u64 txn_id = 0;
	u32 child_name_len = 0;
	u32 internal_watch_effects = 0;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;
	if (!ops)
		ops = &pkm_lcs_key_fd_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;

	if (args->_pad0 || args->_pad1)
		return -EINVAL;
	if (args->txn_fd < -1)
		return -EINVAL;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_HIDE_KEY_NR);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_hide_key_input(ops, args, &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_path_entry_target(key_fd, &parent_guid,
					       &child_name, &child_name_len);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_validate_hide_key_request_shape(
		parent_guid, child_name, child_name_len, &input);
	if (ret)
		goto out_input;

	ret = pkm_lcs_key_fd_hide_key_authorize_layer(&input, token);
	if (ret)
		goto out_input;

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_prepare_mutation_binding(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&binding_probe);
		if (ret)
			goto out_input;
	}

	ret = pkm_lcs_allocate_sequence(&sequence);
	if (ret)
		goto out_input;

	if (args->txn_fd >= 0) {
		log_input.key_guid = key_fd->key_guid;
		log_input.parent_guid = parent_guid;
		log_input.child_name = child_name;
		log_input.child_name_len = child_name_len;
		log_input.layer = input.target.name;
		log_input.layer_len = input.target.name_len;
		log_input.parent_path =
			(const char * const *)key_fd->resolved_path;
		log_input.parent_ancestor_guids =
			(const u8 (*)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
				key_fd->ancestor_guids;
		log_input.parent_depth = key_fd->path_component_count - 1;
		log_input.sequence = sequence;

		ret = pkm_lcs_transaction_fd_begin_hide_key_mutation(
			args->txn_fd, key_fd->source_id, key_fd->ancestor_guids[0],
			&log_input, &mutation, &binding);
		if (ret)
			goto out_input;
		txn_id = binding.transaction_id;
	}

	ret = pkm_lcs_source_hide_entry_round_trip_timeout_with_limits(
		key_fd->source_id, txn_id, parent_guid, child_name, child_name_len,
		input.target.name, input.target.name_len, sequence,
		&input.limits, input.limits.request_timeout_ms, &response, NULL);
	if (ret)
		goto out_cancel_mutation;

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		if (ret)
			goto out_cancel_mutation;
		ret = 0;
		goto out_input;
	}

	internal_watch_effects = pkm_lcs_key_fd_publish_parent_subkey_deleted(
		key_fd, parent_guid, child_name, child_name_len,
		&input.limits);
	pkm_lcs_key_fd_publish_key_deleted_context(key_fd, &input.limits);

	if (!(internal_watch_effects &
	      PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE)) {
		ret = pkm_lcs_source_record_transaction_generation(
			key_fd->source_id, key_fd->ancestor_guids[0],
			&generation);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(key_fd->source_id);
			ret = -EIO;
			goto out_input;
		}
	}
	ret = 0;

out_cancel_mutation:
	if (ret && mutation.active)
		pkm_lcs_transaction_fd_cancel_mutation(&mutation);
out_input:
	pkm_lcs_hide_key_input_destroy(&input);
	return ret;
}

static long pkm_lcs_key_fd_hide_key_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_hide_key_args *args)
{
	return pkm_lcs_key_fd_hide_key_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), ops, args);
}

static long pkm_lcs_key_fd_require_privilege(const void *token, u64 privilege)
{
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(token, privilege))
		return -EPERM;
	return 0;
}

static long pkm_lcs_key_fd_mark_privilege_used(const void *token, u64 privilege)
{
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_mark_privileges_used(token, privilege))
		return -EPERM;
	return 0;
}

static long pkm_lcs_key_fd_external_fd_get_mode_checked(int fd, u32 operation,
							struct fd *held,
							struct file **file_out)
{
	struct file *file;
	u8 readable;
	u8 writable;
	long ret;

	if (!held || !file_out)
		return -EINVAL;
	*held = fdget_pos(fd);
	file = fd_file(*held);
	if (!file)
		return -EBADF;

	readable = (file->f_mode & FMODE_READ) ? 1 : 0;
	writable = (file->f_mode & FMODE_WRITE) ? 1 : 0;
	ret = lcs_rust_backup_restore_fd_mode_gate(operation, readable,
						   writable);
	if (ret) {
		fdput_pos(*held);
		*held = (struct fd) { };
		return ret;
	}

	*file_out = file;
	return 0;
}

static long pkm_lcs_key_fd_external_fd_mode_gate(int fd, u32 operation)
{
	struct file *file = NULL;
	struct fd held = { };
	long ret;

	ret = pkm_lcs_key_fd_external_fd_get_mode_checked(fd, operation,
							  &held, &file);
	if (!ret)
		fdput_pos(held);
	return ret;
}

static long pkm_lcs_key_fd_backup_begin_read_only_snapshot(
	struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_runtime_limits *limits, u64 *transaction_id_out)
{
	u64 transaction_id = 0;
	u32 count = 0;
	long release_ret;
	long ret;

	if (transaction_id_out)
		*transaction_id_out = 0;
	if (!key_fd || !limits || !transaction_id_out)
		return -EINVAL;

	ret = pkm_lcs_source_read_only_transaction_acquire_with_limits(
		key_fd->source_id, limits, &count);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_id_allocate(&transaction_id);
	if (ret)
		goto out_release_counter;

	ret = pkm_lcs_source_begin_transaction_round_trip_timeout_with_limits(
		key_fd->source_id, transaction_id, RSI_TXN_READ_ONLY, limits,
		limits->request_timeout_ms, NULL, NULL);
	if (ret)
		goto out_release_counter;

	*transaction_id_out = transaction_id;
	return 0;

out_release_counter:
	release_ret = pkm_lcs_source_read_only_transaction_release(
		key_fd->source_id, &count);
	if (!ret)
		ret = release_ret;
	return ret;
}

static long pkm_lcs_key_fd_backup_release_read_only_snapshot(
	struct pkm_lcs_key_fd *key_fd,
	const struct pkm_lcs_runtime_limits *limits, u64 transaction_id)
{
	u32 count = 0;
	long release_ret;
	long ret;

	if (!key_fd || !limits || !transaction_id)
		return -EINVAL;

	ret = pkm_lcs_source_abort_transaction_round_trip_timeout_with_limits(
		key_fd->source_id, transaction_id, limits,
		limits->request_timeout_ms, NULL, NULL);
	release_ret = pkm_lcs_source_read_only_transaction_release(
		key_fd->source_id, &count);
	if (!ret)
		ret = release_ret;
	return ret;
}

static u32 pkm_lcs_key_fd_audit_result_errno(long ret)
{
	if (ret < 0)
		return (u32)-ret;
	return (u32)ret;
}

struct pkm_lcs_backup_output {
	struct file *file;
	struct sha256_ctx checksum;
	loff_t pos;
	u64 record_count;
	bool positional;
};

struct pkm_lcs_backup_referenced_layers {
	const struct pkm_lcs_rsi_layer_view **layers;
	u32 count;
};

struct pkm_lcs_backup_layer_manifest_frames {
	u8 **frames;
	size_t *frame_lens;
	u32 count;
};

struct pkm_lcs_backup_record_frames {
	u8 **frames;
	size_t *frame_lens;
	u32 count;
	u32 capacity;
};

struct pkm_lcs_backup_root_section_summary {
	u32 hidden_path_count;
	u32 value_count;
	u32 blanket_count;
	bool needs_child_traversal;
};

static void pkm_lcs_backup_output_init(struct pkm_lcs_backup_output *output,
				       struct file *file)
{
	memset(output, 0, sizeof(*output));
	output->file = file;
	output->positional = !(file->f_mode & FMODE_STREAM);
	if (output->positional)
		output->pos = file->f_pos;
	sha256_init(&output->checksum);
}

static void pkm_lcs_backup_output_finish(struct pkm_lcs_backup_output *output)
{
	if (output && output->file && output->positional)
		output->file->f_pos = output->pos;
}

static long pkm_lcs_backup_write_all(struct pkm_lcs_backup_output *output,
				     const u8 *buf, size_t len)
{
	const u8 *cursor = buf;
	size_t remaining = len;

	if (!output || !output->file || (!buf && len))
		return -EINVAL;

	while (remaining) {
		loff_t *ppos = output->positional ? &output->pos : NULL;
		ssize_t written = kernel_write(output->file, cursor, remaining,
					       ppos);

		if (written < 0)
			return written;
		if (!written)
			return -EIO;
		cursor += written;
		remaining -= written;
	}
	return 0;
}

static long pkm_lcs_backup_write_hashed_record(
	struct pkm_lcs_backup_output *output, const u8 *frame, size_t frame_len)
{
	long ret;

	ret = pkm_lcs_backup_write_all(output, frame, frame_len);
	if (ret)
		return ret;
	sha256_update(&output->checksum, frame, frame_len);
	output->record_count++;
	return 0;
}

static long pkm_lcs_backup_alloc_header_frame(
	const struct pkm_lcs_runtime_limits *limits, const u8 root_guid[16],
	const char *hive_name, size_t hive_name_len, s64 timestamp_ns,
	u8 **frame_out, size_t *frame_len_out)
{
	size_t frame_len = 0;
	size_t written = 0;
	u8 *frame;
	long ret;

	if (!limits || !root_guid || !hive_name || !frame_out ||
	    !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;

	ret = lcs_rust_write_backup_header_record_frame(
		NULL, 0, limits, PKM_LCS_BACKUP_FORMAT_VERSION,
		PKM_LCS_BACKUP_MIN_READER_VERSION, timestamp_ns, root_guid,
		(const u8 *)hive_name, hive_name_len, &frame_len);
	if (ret != -ERANGE || !frame_len)
		return ret ? ret : -EIO;
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = lcs_rust_write_backup_header_record_frame(
		frame, frame_len, limits, PKM_LCS_BACKUP_FORMAT_VERSION,
		PKM_LCS_BACKUP_MIN_READER_VERSION, timestamp_ns, root_guid,
		(const u8 *)hive_name, hive_name_len, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	return 0;

out_free:
	kfree(frame);
	return ret;
}

static long pkm_lcs_backup_sd_owner_sid_copy(const u8 *sd, size_t sd_len,
					     u8 **owner_sid_out,
					     size_t *owner_sid_len_out)
{
	const u8 *owner_sid = NULL;
	size_t owner_sid_len = 0;
	u8 *copy;
	long ret;

	if (!sd || !sd_len || !owner_sid_out || !owner_sid_len_out)
		return -EINVAL;
	*owner_sid_out = NULL;
	*owner_sid_len_out = 0;

	ret = lcs_rust_security_descriptor_owner_sid(
		sd, sd_len, &owner_sid, &owner_sid_len);
	if (ret)
		return ret;
	if (!owner_sid || !owner_sid_len)
		return -EIO;

	copy = kmemdup(owner_sid, owner_sid_len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	*owner_sid_out = copy;
	*owner_sid_len_out = owner_sid_len;
	return 0;
}

static long pkm_lcs_backup_base_layer_owner_snapshot(
	const struct pkm_lcs_layer_snapshot *snapshot, u8 **owner_sid_out,
	size_t *owner_sid_len_out)
{
	const u8 *default_sd;
	size_t default_sd_len = 0;
	long ret;

	if (!snapshot || !owner_sid_out || !owner_sid_len_out)
		return -EINVAL;

	if (snapshot->base_metadata_present) {
		if (!snapshot->base_metadata_sd ||
		    !snapshot->base_metadata_sd_len)
			return -EIO;
		ret = pkm_lcs_backup_sd_owner_sid_copy(
			snapshot->base_metadata_sd,
			snapshot->base_metadata_sd_len, owner_sid_out,
			owner_sid_len_out);
		return ret == -EINVAL ? -EIO : ret;
	}

	default_sd = kacs_rust_create_lcs_base_layer_default_sd(
		&default_sd_len);
	if (!default_sd || !default_sd_len)
		return -ENOMEM;
	ret = pkm_lcs_backup_sd_owner_sid_copy(
		default_sd, default_sd_len, owner_sid_out, owner_sid_len_out);
	pkm_kacs_free((void *)default_sd);
	return ret == -EINVAL ? -EIO : ret;
}

static long pkm_lcs_backup_layer_owner_snapshot(
	const struct pkm_lcs_layer_snapshot *snapshot,
	const struct pkm_lcs_runtime_limits *limits, const char *layer_name,
	u32 layer_name_len, u8 **owner_sid_out, size_t *owner_sid_len_out)
{
	static const char base_name[] = "base";
	bool owner_present = false;
	bool is_base = false;
	long ret;

	if (!snapshot || !limits || !layer_name || !layer_name_len ||
	    !owner_sid_out || !owner_sid_len_out)
		return -EINVAL;
	*owner_sid_out = NULL;
	*owner_sid_len_out = 0;

	ret = pkm_lcs_key_fd_layer_name_casefold_equal_with_limits(
		layer_name, layer_name_len, base_name, sizeof(base_name) - 1,
		limits, &is_base);
	if (ret)
		return ret;
	if (is_base)
		return pkm_lcs_backup_base_layer_owner_snapshot(
			snapshot, owner_sid_out, owner_sid_len_out);

	ret = pkm_lcs_layer_table_owner_snapshot(
		layer_name, layer_name_len, owner_sid_out, owner_sid_len_out,
		&owner_present);
	if (ret)
		return ret;
	if (!owner_present)
		return -ENOENT;
	return 0;
}

static long pkm_lcs_backup_alloc_layer_manifest_frame(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot,
	const struct pkm_lcs_rsi_layer_view *layer, u8 **frame_out,
	size_t *frame_len_out)
{
	u8 *owner_sid = NULL;
	size_t owner_sid_len = 0;
	size_t frame_len = 0;
	size_t written = 0;
	u8 *frame;
	long ret;

	if (!limits || !snapshot || !layer || !layer->name ||
	    !layer->name_len || !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;

	ret = pkm_lcs_backup_layer_owner_snapshot(
		snapshot, limits, layer->name, layer->name_len, &owner_sid,
		&owner_sid_len);
	if (ret)
		return ret;

	ret = lcs_rust_write_backup_layer_manifest_record_frame(
		NULL, 0, limits, (const u8 *)layer->name, layer->name_len,
		layer->precedence, layer->enabled, owner_sid, owner_sid_len,
		&frame_len);
	if (ret != -ERANGE || !frame_len) {
		ret = ret ? ret : -EIO;
		goto out_owner;
	}
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame) {
		ret = -ENOMEM;
		goto out_owner;
	}
	ret = lcs_rust_write_backup_layer_manifest_record_frame(
		frame, frame_len, limits, (const u8 *)layer->name,
		layer->name_len, layer->precedence, layer->enabled,
		owner_sid, owner_sid_len, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	kfree(owner_sid);
	return 0;

out_free:
	kfree(frame);
out_owner:
	kfree(owner_sid);
	return ret;
}

static void pkm_lcs_backup_referenced_layers_destroy(
	struct pkm_lcs_backup_referenced_layers *refs)
{
	if (!refs)
		return;
	kfree(refs->layers);
	refs->layers = NULL;
	refs->count = 0;
}

static long pkm_lcs_backup_referenced_layers_init(
	const struct pkm_lcs_layer_snapshot *snapshot,
	struct pkm_lcs_backup_referenced_layers *refs)
{
	if (!snapshot || !refs)
		return -EINVAL;
	memset(refs, 0, sizeof(*refs));
	if (!snapshot->layers || !snapshot->layer_count)
		return -EIO;

	refs->layers = kcalloc(snapshot->layer_count, sizeof(*refs->layers),
			       GFP_KERNEL);
	if (!refs->layers)
		return -ENOMEM;
	return 0;
}

static long pkm_lcs_backup_frame_field(const u8 *frame, size_t frame_len,
				       u32 offset, u32 len,
				       const char **field_out,
				       u32 *field_len_out)
{
	if (!frame || !field_out || !field_len_out)
		return -EINVAL;
	if ((size_t)offset > frame_len ||
	    (size_t)len > frame_len - (size_t)offset)
		return -EIO;

	*field_out = (const char *)frame + offset;
	*field_len_out = len;
	return 0;
}

static long pkm_lcs_backup_find_snapshot_layer(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot, const char *name,
	u32 name_len, const struct pkm_lcs_rsi_layer_view **layer_out)
{
	u32 i;

	if (!limits || !snapshot || !snapshot->layers || !name || !name_len ||
	    !layer_out)
		return -EINVAL;
	*layer_out = NULL;

	for (i = 0; i < snapshot->layer_count; i++) {
		const struct pkm_lcs_rsi_layer_view *layer =
			&snapshot->layers[i];
		bool equal = false;
		long ret;

		if (!layer->name || !layer->name_len)
			return -EIO;
		ret = pkm_lcs_key_fd_layer_name_casefold_equal_with_limits(
			name, name_len, layer->name, layer->name_len, limits,
			&equal);
		if (ret)
			return ret;
		if (equal) {
			*layer_out = layer;
			return 0;
		}
	}

	return -ENOENT;
}

static long pkm_lcs_backup_referenced_layers_add(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot,
	struct pkm_lcs_backup_referenced_layers *refs, const char *name,
	u32 name_len)
{
	const struct pkm_lcs_rsi_layer_view *layer = NULL;
	u32 i;
	long ret;

	if (!refs || !refs->layers)
		return -EINVAL;

	ret = pkm_lcs_backup_find_snapshot_layer(limits, snapshot, name,
						 name_len, &layer);
	if (ret)
		return ret;

	for (i = 0; i < refs->count; i++) {
		if (refs->layers[i] == layer)
			return 0;
	}
	if (refs->count >= snapshot->layer_count)
		return -EOVERFLOW;

	refs->layers[refs->count++] = layer;
	return 0;
}

static long pkm_lcs_backup_collect_enum_child_layers(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot,
	struct pkm_lcs_backup_referenced_layers *refs, const u8 *frame,
	size_t frame_len, u64 request_id, u64 next_sequence)
{
	struct pkm_lcs_backup_path_entry_view *entries = NULL;
	u32 entry_count = 0;
	u32 actual_count = 0;
	u32 i;
	long ret;

	ret = lcs_rust_materialize_rsi_enum_children_backup_path_entries(
		frame, frame_len, request_id, next_sequence, limits, NULL, 0,
		&entry_count);
	if (ret && ret != -ERANGE)
		return ret;
	if (!entry_count)
		return 0;

	entries = kcalloc(entry_count, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	actual_count = entry_count;
	ret = lcs_rust_materialize_rsi_enum_children_backup_path_entries(
		frame, frame_len, request_id, next_sequence, limits, entries,
		entry_count, &actual_count);
	if (ret)
		goto out;
	if (actual_count != entry_count) {
		ret = -EIO;
		goto out;
	}

	for (i = 0; i < entry_count; i++) {
		const char *layer_name = NULL;
		u32 layer_name_len = 0;

		ret = pkm_lcs_backup_frame_field(
			frame, frame_len, entries[i].layer_offset,
			entries[i].layer_len, &layer_name, &layer_name_len);
		if (ret)
			goto out;
		ret = pkm_lcs_backup_referenced_layers_add(
			limits, snapshot, refs, layer_name, layer_name_len);
		if (ret)
			goto out;
	}

out:
	kfree(entries);
	return ret;
}

static long pkm_lcs_backup_collect_query_value_layers(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot,
	struct pkm_lcs_backup_referenced_layers *refs, const u8 *frame,
	size_t frame_len, u64 request_id, u64 next_sequence)
{
	struct pkm_lcs_backup_value_entry_view *values = NULL;
	struct pkm_lcs_backup_blanket_entry_view *blankets = NULL;
	u32 value_count = 0;
	u32 blanket_count = 0;
	u32 actual_value_count = 0;
	u32 actual_blanket_count = 0;
	u32 i;
	long ret;

	ret = lcs_rust_materialize_rsi_query_values_backup_entries(
		frame, frame_len, request_id, next_sequence, limits, NULL, 0,
		NULL, 0, &value_count, &blanket_count);
	if (ret && ret != -ERANGE)
		return ret;
	if (!value_count && !blanket_count)
		return 0;

	if (value_count) {
		values = kcalloc(value_count, sizeof(*values), GFP_KERNEL);
		if (!values)
			return -ENOMEM;
	}
	if (blanket_count) {
		blankets = kcalloc(blanket_count, sizeof(*blankets),
				   GFP_KERNEL);
		if (!blankets) {
			ret = -ENOMEM;
			goto out;
		}
	}

	actual_value_count = value_count;
	actual_blanket_count = blanket_count;
	ret = lcs_rust_materialize_rsi_query_values_backup_entries(
		frame, frame_len, request_id, next_sequence, limits, values,
		value_count, blankets, blanket_count, &actual_value_count,
		&actual_blanket_count);
	if (ret)
		goto out;
	if (actual_value_count != value_count ||
	    actual_blanket_count != blanket_count) {
		ret = -EIO;
		goto out;
	}

	for (i = 0; i < value_count; i++) {
		const char *layer_name = NULL;
		u32 layer_name_len = 0;

		ret = pkm_lcs_backup_frame_field(
			frame, frame_len, values[i].layer_offset,
			values[i].layer_len, &layer_name, &layer_name_len);
		if (ret)
			goto out;
		ret = pkm_lcs_backup_referenced_layers_add(
			limits, snapshot, refs, layer_name, layer_name_len);
		if (ret)
			goto out;
	}

	for (i = 0; i < blanket_count; i++) {
		const char *layer_name = NULL;
		u32 layer_name_len = 0;

		ret = pkm_lcs_backup_frame_field(
			frame, frame_len, blankets[i].layer_offset,
			blankets[i].layer_len, &layer_name, &layer_name_len);
		if (ret)
			goto out;
		ret = pkm_lcs_backup_referenced_layers_add(
			limits, snapshot, refs, layer_name, layer_name_len);
		if (ret)
			goto out;
	}

out:
	kfree(blankets);
	kfree(values);
	return ret;
}

static long pkm_lcs_backup_collect_referenced_layers(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot, const u8 *enum_frame,
	size_t enum_frame_len, u64 enum_request_id, const u8 *values_frame,
	size_t values_frame_len, u64 values_request_id, u64 next_sequence,
	struct pkm_lcs_backup_referenced_layers *refs)
{
	long ret;

	if (!limits || !snapshot || !refs)
		return -EINVAL;

	ret = pkm_lcs_backup_referenced_layers_init(snapshot, refs);
	if (ret)
		return ret;

	ret = pkm_lcs_backup_collect_enum_child_layers(
		limits, snapshot, refs, enum_frame, enum_frame_len,
		enum_request_id, next_sequence);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_backup_collect_query_value_layers(
		limits, snapshot, refs, values_frame, values_frame_len,
		values_request_id, next_sequence);
	if (ret)
		goto out_destroy;

	return 0;

out_destroy:
	pkm_lcs_backup_referenced_layers_destroy(refs);
	return ret;
}

static void pkm_lcs_backup_layer_manifest_frames_destroy(
	struct pkm_lcs_backup_layer_manifest_frames *frames)
{
	u32 i;

	if (!frames)
		return;
	if (frames->frames) {
		for (i = 0; i < frames->count; i++)
			kfree(frames->frames[i]);
	}
	kfree(frames->frame_lens);
	kfree(frames->frames);
	frames->frames = NULL;
	frames->frame_lens = NULL;
	frames->count = 0;
}

static long pkm_lcs_backup_alloc_layer_manifest_frames(
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_layer_snapshot *snapshot,
	const struct pkm_lcs_backup_referenced_layers *refs,
	struct pkm_lcs_backup_layer_manifest_frames *frames)
{
	u32 i;
	long ret;

	if (!limits || !snapshot || !refs || !frames)
		return -EINVAL;
	memset(frames, 0, sizeof(*frames));
	if (!refs->count)
		return 0;
	if (!refs->layers)
		return -EINVAL;

	frames->frames = kcalloc(refs->count, sizeof(*frames->frames),
				 GFP_KERNEL);
	if (!frames->frames)
		return -ENOMEM;
	frames->frame_lens = kcalloc(refs->count, sizeof(*frames->frame_lens),
				     GFP_KERNEL);
	if (!frames->frame_lens) {
		ret = -ENOMEM;
		goto out_destroy;
	}

	for (i = 0; i < refs->count; i++) {
		if (!refs->layers[i]) {
			ret = -EINVAL;
			goto out_destroy;
		}
		ret = pkm_lcs_backup_alloc_layer_manifest_frame(
			limits, snapshot, refs->layers[i],
			&frames->frames[i], &frames->frame_lens[i]);
		if (ret)
			goto out_destroy;
		frames->count++;
	}

	return 0;

out_destroy:
	pkm_lcs_backup_layer_manifest_frames_destroy(frames);
	return ret;
}

static long pkm_lcs_backup_manifest_frame_matches_layer(
	const u8 *frame, size_t frame_len,
	const struct pkm_lcs_rsi_layer_view *layer)
{
	size_t offset = 6;
	u32 record_len;
	u32 name_len;

	if (!frame || !layer || !layer->name || !layer->name_len)
		return -EINVAL;
	if (frame_len < 6)
		return -EIO;
	if (get_unaligned_le16(frame) != REG_BACKUP_LAYER)
		return -EIO;
	record_len = get_unaligned_le32(frame + 2);
	if ((size_t)record_len != frame_len)
		return -EIO;

	if (offset > frame_len || sizeof(u32) > frame_len - offset)
		return -EIO;
	name_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	if (name_len != layer->name_len)
		return -EIO;
	if (offset > frame_len || name_len > frame_len - offset)
		return -EIO;
	if (memcmp(frame + offset, layer->name, name_len))
		return -EIO;
	offset += name_len;
	if (offset > frame_len || sizeof(u32) > frame_len - offset)
		return -EIO;
	if (get_unaligned_le32(frame + offset) != layer->precedence)
		return -EIO;
	offset += sizeof(u32);
	if (offset >= frame_len)
		return -EIO;
	if (frame[offset] != layer->enabled)
		return -EIO;
	return 0;
}

static void pkm_lcs_backup_record_frames_destroy(
	struct pkm_lcs_backup_record_frames *frames)
{
	u32 i;

	if (!frames)
		return;
	if (frames->frames) {
		for (i = 0; i < frames->count; i++)
			kfree(frames->frames[i]);
	}
	kfree(frames->frame_lens);
	kfree(frames->frames);
	frames->frames = NULL;
	frames->frame_lens = NULL;
	frames->count = 0;
	frames->capacity = 0;
}

static long pkm_lcs_backup_record_frames_init(
	struct pkm_lcs_backup_record_frames *frames, u32 capacity)
{
	if (!frames)
		return -EINVAL;
	memset(frames, 0, sizeof(*frames));
	if (!capacity)
		return 0;

	frames->frames = kcalloc(capacity, sizeof(*frames->frames),
				 GFP_KERNEL);
	if (!frames->frames)
		return -ENOMEM;
	frames->frame_lens = kcalloc(capacity, sizeof(*frames->frame_lens),
				     GFP_KERNEL);
	if (!frames->frame_lens) {
		pkm_lcs_backup_record_frames_destroy(frames);
		return -ENOMEM;
	}
	frames->capacity = capacity;
	return 0;
}

static long pkm_lcs_backup_record_frames_append(
	struct pkm_lcs_backup_record_frames *frames, u8 **frame,
	size_t frame_len)
{
	if (!frames || !frame || !*frame || !frame_len)
		return -EINVAL;
	if (frames->count >= frames->capacity)
		return -EOVERFLOW;

	frames->frames[frames->count] = *frame;
	frames->frame_lens[frames->count] = frame_len;
	frames->count++;
	*frame = NULL;
	return 0;
}

static long pkm_lcs_backup_alloc_path_entry_frame(
	const struct pkm_lcs_runtime_limits *limits,
	const u8 parent_guid[PKM_LCS_GUID_BYTES], const char *child_name,
	size_t child_name_len, const u8 child_guid[PKM_LCS_GUID_BYTES],
	bool hidden, const char *layer_name, size_t layer_name_len,
	u64 sequence, u8 **frame_out, size_t *frame_len_out)
{
	size_t frame_len = 0;
	size_t written = 0;
	u8 *frame;
	long ret;

	if (!limits || !parent_guid || !child_name || !child_name_len ||
	    (!hidden && !child_guid) || !layer_name || !layer_name_len ||
	    !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;

	ret = lcs_rust_write_backup_path_entry_record_frame(
		NULL, 0, limits, parent_guid, (const u8 *)child_name,
		child_name_len, child_guid, hidden ? 1 : 0,
		(const u8 *)layer_name, layer_name_len, sequence, &frame_len);
	if (ret != -ERANGE || !frame_len)
		return ret ? ret : -EIO;
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = lcs_rust_write_backup_path_entry_record_frame(
		frame, frame_len, limits, parent_guid, (const u8 *)child_name,
		child_name_len, child_guid, hidden ? 1 : 0,
		(const u8 *)layer_name, layer_name_len, sequence, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	return 0;

out_free:
	kfree(frame);
	return ret;
}

static long pkm_lcs_backup_alloc_value_frame(
	const struct pkm_lcs_runtime_limits *limits,
	const u8 key_guid[PKM_LCS_GUID_BYTES], const char *name,
	size_t name_len, u32 value_type, const u8 *data, size_t data_len,
	const char *layer_name, size_t layer_name_len, u64 sequence,
	u8 **frame_out, size_t *frame_len_out)
{
	size_t frame_len = 0;
	size_t written = 0;
	u8 *frame;
	long ret;

	if (!limits || !key_guid || (name_len && !name) ||
	    (data_len && !data) || !layer_name || !layer_name_len ||
	    !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;

	ret = lcs_rust_write_backup_value_record_frame(
		NULL, 0, limits, key_guid, (const u8 *)name, name_len,
		value_type, data, data_len, (const u8 *)layer_name,
		layer_name_len, sequence, &frame_len);
	if (ret != -ERANGE || !frame_len)
		return ret ? ret : -EIO;
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = lcs_rust_write_backup_value_record_frame(
		frame, frame_len, limits, key_guid, (const u8 *)name,
		name_len, value_type, data, data_len,
		(const u8 *)layer_name, layer_name_len, sequence, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	return 0;

out_free:
	kfree(frame);
	return ret;
}

static long pkm_lcs_backup_alloc_blanket_tombstone_frame(
	const struct pkm_lcs_runtime_limits *limits,
	const u8 key_guid[PKM_LCS_GUID_BYTES], const char *layer_name,
	size_t layer_name_len, u64 sequence, u8 **frame_out,
	size_t *frame_len_out)
{
	size_t frame_len = 0;
	size_t written = 0;
	u8 *frame;
	long ret;

	if (!limits || !key_guid || !layer_name || !layer_name_len ||
	    !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;

	ret = lcs_rust_write_backup_blanket_tombstone_record_frame(
		NULL, 0, limits, key_guid, (const u8 *)layer_name,
		layer_name_len, sequence, &frame_len);
	if (ret != -ERANGE || !frame_len)
		return ret ? ret : -EIO;
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = lcs_rust_write_backup_blanket_tombstone_record_frame(
		frame, frame_len, limits, key_guid, (const u8 *)layer_name,
		layer_name_len, sequence, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	return 0;

out_free:
	kfree(frame);
	return ret;
}

static long pkm_lcs_backup_materialize_path_entries(
	const struct pkm_lcs_runtime_limits *limits, const u8 *frame,
	size_t frame_len, u64 request_id, u64 next_sequence,
	struct pkm_lcs_backup_path_entry_view **entries_out,
	u32 *entry_count_out)
{
	struct pkm_lcs_backup_path_entry_view *entries = NULL;
	u32 entry_count = 0;
	u32 actual_count = 0;
	long ret;

	if (!limits || !entries_out || !entry_count_out)
		return -EINVAL;
	*entries_out = NULL;
	*entry_count_out = 0;

	ret = lcs_rust_materialize_rsi_enum_children_backup_path_entries(
		frame, frame_len, request_id, next_sequence, limits, NULL, 0,
		&entry_count);
	if (ret && ret != -ERANGE)
		return ret;
	if (!entry_count)
		return 0;

	entries = kcalloc(entry_count, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	actual_count = entry_count;
	ret = lcs_rust_materialize_rsi_enum_children_backup_path_entries(
		frame, frame_len, request_id, next_sequence, limits, entries,
		entry_count, &actual_count);
	if (ret)
		goto out_free;
	if (actual_count != entry_count) {
		ret = -EIO;
		goto out_free;
	}

	*entries_out = entries;
	*entry_count_out = entry_count;
	return 0;

out_free:
	kfree(entries);
	return ret;
}

static long pkm_lcs_backup_materialize_value_entries(
	const struct pkm_lcs_runtime_limits *limits, const u8 *frame,
	size_t frame_len, u64 request_id, u64 next_sequence,
	struct pkm_lcs_backup_value_entry_view **values_out,
	u32 *value_count_out,
	struct pkm_lcs_backup_blanket_entry_view **blankets_out,
	u32 *blanket_count_out)
{
	struct pkm_lcs_backup_value_entry_view *values = NULL;
	struct pkm_lcs_backup_blanket_entry_view *blankets = NULL;
	u32 value_count = 0;
	u32 blanket_count = 0;
	u32 actual_value_count = 0;
	u32 actual_blanket_count = 0;
	long ret;

	if (!limits || !values_out || !value_count_out || !blankets_out ||
	    !blanket_count_out)
		return -EINVAL;
	*values_out = NULL;
	*value_count_out = 0;
	*blankets_out = NULL;
	*blanket_count_out = 0;

	ret = lcs_rust_materialize_rsi_query_values_backup_entries(
		frame, frame_len, request_id, next_sequence, limits, NULL, 0,
		NULL, 0, &value_count, &blanket_count);
	if (ret && ret != -ERANGE)
		return ret;
	if (value_count) {
		values = kcalloc(value_count, sizeof(*values), GFP_KERNEL);
		if (!values)
			return -ENOMEM;
	}
	if (blanket_count) {
		blankets = kcalloc(blanket_count, sizeof(*blankets),
				   GFP_KERNEL);
		if (!blankets) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	actual_value_count = value_count;
	actual_blanket_count = blanket_count;
	ret = lcs_rust_materialize_rsi_query_values_backup_entries(
		frame, frame_len, request_id, next_sequence, limits, values,
		value_count, blankets, blanket_count, &actual_value_count,
		&actual_blanket_count);
	if (ret)
		goto out_free;
	if (actual_value_count != value_count ||
	    actual_blanket_count != blanket_count) {
		ret = -EIO;
		goto out_free;
	}

	*values_out = values;
	*value_count_out = value_count;
	*blankets_out = blankets;
	*blanket_count_out = blanket_count;
	return 0;

out_free:
	kfree(blankets);
	kfree(values);
	return ret;
}

static long pkm_lcs_backup_alloc_root_section_frames(
	const struct pkm_lcs_runtime_limits *limits,
	const u8 key_guid[PKM_LCS_GUID_BYTES], const u8 *enum_frame,
	size_t enum_frame_len, u64 enum_request_id, const u8 *values_frame,
	size_t values_frame_len, u64 values_request_id, u64 next_sequence,
	struct pkm_lcs_backup_record_frames *frames,
	struct pkm_lcs_backup_root_section_summary *summary)
{
	struct pkm_lcs_backup_path_entry_view *entries = NULL;
	struct pkm_lcs_backup_value_entry_view *values = NULL;
	struct pkm_lcs_backup_blanket_entry_view *blankets = NULL;
	u32 entry_count = 0;
	u32 value_count = 0;
	u32 blanket_count = 0;
	u32 capacity = 0;
	u32 i;
	long ret;

	if (!limits || !key_guid || !frames || !summary)
		return -EINVAL;
	memset(summary, 0, sizeof(*summary));

	ret = pkm_lcs_backup_materialize_path_entries(
		limits, enum_frame, enum_frame_len, enum_request_id,
		next_sequence, &entries, &entry_count);
	if (ret)
		return ret;
	ret = pkm_lcs_backup_materialize_value_entries(
		limits, values_frame, values_frame_len, values_request_id,
		next_sequence, &values, &value_count, &blankets,
		&blanket_count);
	if (ret)
		goto out_free_views;

	for (i = 0; i < entry_count; i++) {
		if (entries[i].hidden)
			summary->hidden_path_count++;
		else
			summary->needs_child_traversal = true;
	}
	summary->value_count = value_count;
	summary->blanket_count = blanket_count;

	if (summary->needs_child_traversal) {
		ret = pkm_lcs_backup_record_frames_init(frames, 0);
		goto out_free_views;
	}

	if (check_add_overflow(summary->hidden_path_count, value_count,
			       &capacity) ||
	    check_add_overflow(capacity, blanket_count, &capacity)) {
		ret = -EOVERFLOW;
		goto out_free_views;
	}
	ret = pkm_lcs_backup_record_frames_init(frames, capacity);
	if (ret)
		goto out_free_views;

	for (i = 0; i < entry_count; i++) {
		const char *child_name = NULL;
		const char *layer_name = NULL;
		u32 child_name_len = 0;
		u32 layer_name_len = 0;
		size_t frame_len = 0;
		u8 *frame = NULL;

		if (!entries[i].hidden)
			continue;
		ret = pkm_lcs_backup_frame_field(
			enum_frame, enum_frame_len, entries[i].child_name_offset,
			entries[i].child_name_len, &child_name,
			&child_name_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_frame_field(
			enum_frame, enum_frame_len, entries[i].layer_offset,
			entries[i].layer_len, &layer_name, &layer_name_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_alloc_path_entry_frame(
			limits, key_guid, child_name, child_name_len, NULL,
			true, layer_name, layer_name_len, entries[i].sequence,
			&frame, &frame_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_record_frames_append(frames, &frame,
							  frame_len);
		if (ret) {
			kfree(frame);
			goto out_destroy_frames;
		}
	}

	for (i = 0; i < value_count; i++) {
		const char *name = NULL;
		const char *data = NULL;
		const char *layer_name = NULL;
		u32 name_len = 0;
		u32 data_len = 0;
		u32 layer_name_len = 0;
		size_t frame_len = 0;
		u8 *frame = NULL;

		ret = pkm_lcs_backup_frame_field(
			values_frame, values_frame_len, values[i].name_offset,
			values[i].name_len, &name, &name_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_frame_field(
			values_frame, values_frame_len, values[i].data_offset,
			values[i].data_len, &data, &data_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_frame_field(
			values_frame, values_frame_len, values[i].layer_offset,
			values[i].layer_len, &layer_name, &layer_name_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_alloc_value_frame(
			limits, key_guid, name, name_len,
			values[i].value_type, (const u8 *)data, data_len,
			layer_name, layer_name_len, values[i].sequence, &frame,
			&frame_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_record_frames_append(frames, &frame,
							  frame_len);
		if (ret) {
			kfree(frame);
			goto out_destroy_frames;
		}
	}

	for (i = 0; i < blanket_count; i++) {
		const char *layer_name = NULL;
		u32 layer_name_len = 0;
		size_t frame_len = 0;
		u8 *frame = NULL;

		ret = pkm_lcs_backup_frame_field(
			values_frame, values_frame_len, blankets[i].layer_offset,
			blankets[i].layer_len, &layer_name, &layer_name_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_alloc_blanket_tombstone_frame(
			limits, key_guid, layer_name, layer_name_len,
			blankets[i].sequence, &frame, &frame_len);
		if (ret)
			goto out_destroy_frames;
		ret = pkm_lcs_backup_record_frames_append(frames, &frame,
							  frame_len);
		if (ret) {
			kfree(frame);
			goto out_destroy_frames;
		}
	}

out_free_views:
	kfree(blankets);
	kfree(values);
	kfree(entries);
	return ret;

out_destroy_frames:
	pkm_lcs_backup_record_frames_destroy(frames);
	memset(summary, 0, sizeof(*summary));
	goto out_free_views;
}

static long pkm_lcs_backup_alloc_key_frame(
	const u8 guid[16], bool volatile_key, bool symlink, const u8 *sd,
	size_t sd_len, s64 last_write_time_ns, u8 **frame_out,
	size_t *frame_len_out)
{
	size_t frame_len = 0;
	size_t written = 0;
	u8 *frame;
	long ret;

	if (!guid || !sd || !sd_len || !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;

	ret = lcs_rust_write_backup_key_record_frame(
		NULL, 0, guid, volatile_key ? 1 : 0, symlink ? 1 : 0, sd,
		sd_len, last_write_time_ns, &frame_len);
	if (ret != -ERANGE || !frame_len)
		return ret ? ret : -EIO;
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = lcs_rust_write_backup_key_record_frame(
		frame, frame_len, guid, volatile_key ? 1 : 0,
		symlink ? 1 : 0, sd, sd_len, last_write_time_ns, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	return 0;

out_free:
	kfree(frame);
	return ret;
}

static long pkm_lcs_backup_alloc_trailer_frame(
	struct pkm_lcs_backup_output *output, u8 **frame_out,
	size_t *frame_len_out)
{
	u8 zero_checksum[SHA256_DIGEST_SIZE] = { };
	u8 checksum[SHA256_DIGEST_SIZE];
	size_t frame_len = 0;
	size_t written = 0;
	u64 record_count;
	u8 *frame;
	long ret;

	if (!output || !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;
	if (check_add_overflow(output->record_count, 1ULL, &record_count))
		return -EOVERFLOW;

	ret = lcs_rust_write_backup_trailer_record_frame(
		NULL, 0, record_count, zero_checksum, &frame_len);
	if (ret != -ERANGE || !frame_len)
		return ret ? ret : -EIO;
	if (frame_len < PKM_LCS_BACKUP_TRAILER_PREFIX_LEN)
		return -EIO;
	frame = kmalloc(frame_len, GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	ret = lcs_rust_write_backup_trailer_record_frame(
		frame, frame_len, record_count, zero_checksum, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	sha256_update(&output->checksum, frame,
		      PKM_LCS_BACKUP_TRAILER_PREFIX_LEN);
	sha256_final(&output->checksum, checksum);
	ret = lcs_rust_write_backup_trailer_record_frame(
		frame, frame_len, record_count, checksum, &written);
	if (ret)
		goto out_free;
	if (written != frame_len) {
		ret = -EIO;
		goto out_free;
	}

	*frame_out = frame;
	*frame_len_out = frame_len;
	return 0;

out_free:
	kfree(frame);
	return ret;
}

static long pkm_lcs_key_fd_backup_export_empty_subtree(
	struct pkm_lcs_key_fd *key_fd, struct file *output_file,
	const struct pkm_lcs_runtime_limits *limits, u64 transaction_id)
{
	struct pkm_lcs_layer_snapshot layer_snapshot = { };
	struct pkm_lcs_source_response_frame read_frame = { };
	struct pkm_lcs_source_response_frame enum_frame = { };
	struct pkm_lcs_source_response_frame values_frame = { };
	struct pkm_lcs_source_response_result read_response = { };
	struct pkm_lcs_source_response_result enum_response = { };
	struct pkm_lcs_source_response_result values_response = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_backup_referenced_layers referenced_layers = { };
	struct pkm_lcs_backup_layer_manifest_frames layer_manifests = { };
	struct pkm_lcs_backup_record_frames root_section_frames = { };
	struct pkm_lcs_backup_root_section_summary root_section = { };
	struct pkm_lcs_backup_output output;
	const char *hive_name;
	u8 *header_frame = NULL;
	u8 *key_frame = NULL;
	u8 *trailer_frame = NULL;
	size_t header_frame_len = 0;
	size_t key_frame_len = 0;
	size_t trailer_frame_len = 0;
	u64 next_sequence = 0;
	const u8 *sd;
	u32 i;
	long ret;

	if (!key_fd || !output_file || !limits || !transaction_id)
		return -EINVAL;
	if (!key_fd->resolved_path || !key_fd->path_component_count ||
	    !key_fd->resolved_path[0])
		return -EIO;
	hive_name = key_fd->resolved_path[0];

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layer_snapshot);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&read_frame);
	pkm_lcs_source_response_frame_init(&enum_frame);
	pkm_lcs_source_response_frame_init(&values_frame);

	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, transaction_id, key_fd->key_guid, limits,
		limits->request_timeout_ms, &read_frame, &read_response,
		NULL);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
		read_frame.data, read_frame.len, read_response.request_id,
		&read_response.limits, &read_key);
	if (ret)
		goto out_frames;
	if (!read_key.sd_len || (size_t)read_key.sd_offset > read_frame.len ||
	    (size_t)read_key.sd_len >
		    read_frame.len - (size_t)read_key.sd_offset) {
		ret = -EIO;
		goto out_frames;
	}
	sd = read_frame.data + read_key.sd_offset;

	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, transaction_id, key_fd->key_guid, limits,
		limits->request_timeout_ms, &enum_frame, &enum_response,
		NULL);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		key_fd->source_id, transaction_id, key_fd->key_guid, "", 0,
		true, limits, limits->request_timeout_ms, &values_frame,
		&values_response, NULL);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_backup_collect_referenced_layers(
		limits, &layer_snapshot, enum_frame.data, enum_frame.len,
		enum_response.request_id, values_frame.data, values_frame.len,
		values_response.request_id, next_sequence, &referenced_layers);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_backup_alloc_layer_manifest_frames(
		limits, &layer_snapshot, &referenced_layers,
		&layer_manifests);
	if (ret)
		goto out_frames;

	ret = pkm_lcs_backup_alloc_root_section_frames(
		limits, key_fd->key_guid, enum_frame.data, enum_frame.len,
		enum_response.request_id, values_frame.data, values_frame.len,
		values_response.request_id, next_sequence, &root_section_frames,
		&root_section);
	if (ret)
		goto out_frames;

	if (root_section.needs_child_traversal) {
		ret = -EOPNOTSUPP;
		goto out_frames;
	}

	ret = pkm_lcs_backup_alloc_header_frame(
		limits, key_fd->key_guid, hive_name, strlen(hive_name),
		ktime_get_real_ns(), &header_frame, &header_frame_len);
	if (ret)
		goto out_frames;
	ret = pkm_lcs_backup_alloc_key_frame(
		key_fd->key_guid, read_key.volatile_key != 0,
		read_key.symlink != 0, sd, read_key.sd_len,
		(s64)read_key.last_write_time, &key_frame, &key_frame_len);
	if (ret)
		goto out_frames;

	pkm_lcs_backup_output_init(&output, output_file);
	ret = pkm_lcs_backup_write_hashed_record(&output, header_frame,
						 header_frame_len);
	if (ret)
		goto out_output;
	for (i = 0; i < layer_manifests.count; i++) {
		ret = pkm_lcs_backup_write_hashed_record(
			&output, layer_manifests.frames[i],
			layer_manifests.frame_lens[i]);
		if (ret)
			goto out_output;
	}
	ret = pkm_lcs_backup_write_hashed_record(&output, key_frame,
						 key_frame_len);
	if (ret)
		goto out_output;
	for (i = 0; i < root_section_frames.count; i++) {
		ret = pkm_lcs_backup_write_hashed_record(
			&output, root_section_frames.frames[i],
			root_section_frames.frame_lens[i]);
		if (ret)
			goto out_output;
	}
	ret = pkm_lcs_backup_alloc_trailer_frame(&output, &trailer_frame,
						 &trailer_frame_len);
	if (ret)
		goto out_output;
	ret = pkm_lcs_backup_write_all(&output, trailer_frame,
				       trailer_frame_len);

out_output:
	pkm_lcs_backup_output_finish(&output);
out_frames:
	pkm_lcs_backup_record_frames_destroy(&root_section_frames);
	pkm_lcs_backup_layer_manifest_frames_destroy(&layer_manifests);
	pkm_lcs_backup_referenced_layers_destroy(&referenced_layers);
	kfree(trailer_frame);
	kfree(key_frame);
	kfree(header_frame);
	pkm_lcs_source_response_frame_destroy(&values_frame);
	pkm_lcs_source_response_frame_destroy(&enum_frame);
	pkm_lcs_source_response_frame_destroy(&read_frame);
	pkm_lcs_source_layer_snapshot_release(&layer_snapshot);
	return ret;
}

static long pkm_lcs_key_fd_backup_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct reg_backup_args *args)
{
	struct pkm_lcs_runtime_limits limits;
	struct file *output_file = NULL;
	struct fd output_held = { };
	u64 transaction_id = 0;
	bool backup_started = false;
	bool start_audit_failed = false;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;

	ret = pkm_lcs_key_fd_require_privilege(token,
					       KACS_SE_BACKUP_PRIVILEGE);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_external_fd_get_mode_checked(
		args->output_fd, PKM_LCS_BACKUP_RESTORE_FD_OP_BACKUP_OUTPUT,
		&output_held, &output_file);
	if (ret)
		return ret;

	if (READ_ONCE(key_fd->orphaned)) {
		ret = -ENOENT;
		goto out_output_fd;
	}

	ret = pkm_lcs_runtime_limits_snapshot(&limits);
	if (ret)
		goto out_output_fd;

	ret = pkm_lcs_key_fd_backup_begin_read_only_snapshot(
		key_fd, &limits, &transaction_id);
	if (ret)
		goto out_output_fd;

	ret = pkm_lcs_emit_backup_start_audit_for_token(
		token, key_fd->key_guid, args->output_fd);
	if (ret) {
		start_audit_failed = true;
		ret = -EIO;
		goto out_release_snapshot;
	}
	backup_started = true;

	ret = pkm_lcs_key_fd_mark_privilege_used(token,
						 KACS_SE_BACKUP_PRIVILEGE);
	if (ret)
		goto out_release_snapshot;

	ret = pkm_lcs_key_fd_backup_export_empty_subtree(
		key_fd, output_file, &limits, transaction_id);

out_release_snapshot:
	{
		long release_ret;

		release_ret = pkm_lcs_key_fd_backup_release_read_only_snapshot(
			key_fd, &limits, transaction_id);
		if (release_ret && !start_audit_failed)
			ret = release_ret;
	}
	if (backup_started)
		(void)pkm_lcs_emit_backup_complete_audit_for_token(
			token, key_fd->key_guid,
			pkm_lcs_key_fd_audit_result_errno(ret));
out_output_fd:
	fdput_pos(output_held);
	return ret;
}

static long pkm_lcs_key_fd_backup_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct reg_backup_args *args)
{
	return pkm_lcs_key_fd_backup_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), args);
}

static long pkm_lcs_key_fd_restore_from_args_for_token(
	struct pkm_lcs_key_fd *key_fd, const void *token,
	const struct reg_restore_args *args)
{
	long ret;

	if (!key_fd || !args)
		return -EINVAL;

	ret = pkm_lcs_key_fd_require_privilege(token,
					       KACS_SE_RESTORE_PRIVILEGE);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_external_fd_mode_gate(
		args->input_fd, PKM_LCS_BACKUP_RESTORE_FD_OP_RESTORE_INPUT);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_mark_privilege_used(token,
						 KACS_SE_RESTORE_PRIVILEGE);
	if (ret)
		return ret;

	return -EOPNOTSUPP;
}

static long pkm_lcs_key_fd_restore_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct reg_restore_args *args)
{
	return pkm_lcs_key_fd_restore_from_args_for_token(
		key_fd, pkm_kacs_current_effective_token_ptr(), args);
}

static long pkm_lcs_key_fd_flush(struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_runtime_limits limits;
	const char *hive_name;
	size_t hive_name_len;
	long ret;

	if (!key_fd)
		return -EINVAL;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_FLUSH_NR);
	if (ret)
		return ret;

	if (!key_fd->source_id || !key_fd->path_component_count ||
	    !key_fd->resolved_path)
		return -EIO;

	hive_name = key_fd->resolved_path[0];
	if (!hive_name)
		return -EIO;
	hive_name_len = strlen(hive_name);
	if (!hive_name_len || hive_name_len > U32_MAX)
		return -EIO;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_source_flush_round_trip_timeout_with_limits(
		key_fd->source_id, hive_name, (u32)hive_name_len, &limits,
		limits.request_timeout_ms, &response, NULL);
}

static bool pkm_lcs_key_fd_ioctl_revalidates_restart(unsigned int cmd)
{
	switch (cmd) {
	case REG_IOC_SET_VALUE:
	case REG_IOC_DELETE_VALUE:
	case REG_IOC_BLANKET_TOMBSTONE:
	case REG_IOC_DELETE_KEY:
	case REG_IOC_HIDE_KEY:
	case REG_IOC_QUERY_VALUE:
	case REG_IOC_QUERY_VALUES_BATCH:
	case REG_IOC_ENUM_VALUES:
	case REG_IOC_ENUM_SUBKEYS:
	case REG_IOC_QUERY_KEY_INFO:
	case REG_IOC_GET_SECURITY:
	case REG_IOC_SET_SECURITY:
	case REG_IOC_FLUSH:
	case REG_IOC_BACKUP:
	case REG_IOC_RESTORE:
	case REG_IOC_NOTIFY:
		return true;
	default:
		return false;
	}
}

static long pkm_lcs_key_fd_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct pkm_lcs_key_fd *key_fd;
	struct reg_notify_args notify_args;
	struct reg_get_security_args get_security_args;
	struct reg_enum_subkey_args enum_subkey_args;
	struct reg_enum_value_args enum_value_args;
	struct reg_query_values_batch_args query_values_batch_args;
	struct reg_query_key_info_args query_key_info_args;
	struct reg_query_value_args query_value_args;
	struct reg_backup_args backup_args;
	struct reg_restore_args restore_args;
	struct reg_set_security_args set_security_args;
	struct reg_set_value_args set_value_args;
	struct reg_delete_value_args delete_value_args;
	struct reg_blanket_tombstone_args blanket_tombstone_args;
	struct reg_delete_key_args delete_key_args;
	struct reg_hide_key_args hide_key_args;
	struct pkm_lcs_runtime_limits restart_limits;
	long ret;

	if (!file)
		return -EBADF;
	key_fd = file->private_data;
	if (!key_fd)
		return -EINVAL;

	if (pkm_lcs_key_fd_ioctl_revalidates_restart(cmd)) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&restart_limits);
		ret = pkm_lcs_key_fd_revalidate_after_source_restart(
			key_fd, &restart_limits);
		if (ret)
			return ret;
	}

	switch (cmd) {
	case REG_IOC_SET_VALUE:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&set_value_args, (void __user *)arg,
				   sizeof(set_value_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_set_value_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&set_value_args);
	case REG_IOC_DELETE_VALUE:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&delete_value_args, (void __user *)arg,
				   sizeof(delete_value_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_delete_value_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&delete_value_args);
	case REG_IOC_BLANKET_TOMBSTONE:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&blanket_tombstone_args, (void __user *)arg,
				   sizeof(blanket_tombstone_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_blanket_tombstone_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&blanket_tombstone_args);
	case REG_IOC_DELETE_KEY:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&delete_key_args, (void __user *)arg,
				   sizeof(delete_key_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_delete_key_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&delete_key_args);
	case REG_IOC_HIDE_KEY:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&hide_key_args, (void __user *)arg,
				   sizeof(hide_key_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_hide_key_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&hide_key_args);
	case REG_IOC_QUERY_VALUE:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&query_value_args, (void __user *)arg,
				   sizeof(query_value_args)))
			return -EFAULT;
		ret = pkm_lcs_key_fd_query_value_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&query_value_args);
		if ((ret == 0 || ret == -ERANGE) &&
		    copy_to_user((void __user *)arg, &query_value_args,
				 sizeof(query_value_args)))
			return -EFAULT;
		return ret;
	case REG_IOC_QUERY_VALUES_BATCH:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&query_values_batch_args, (void __user *)arg,
				   sizeof(query_values_batch_args)))
			return -EFAULT;
		ret = pkm_lcs_key_fd_query_values_batch_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&query_values_batch_args);
		if ((ret == 0 || ret == -ERANGE) &&
		    copy_to_user((void __user *)arg, &query_values_batch_args,
				 sizeof(query_values_batch_args)))
			return -EFAULT;
		return ret;
	case REG_IOC_ENUM_VALUES:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&enum_value_args, (void __user *)arg,
				   sizeof(enum_value_args)))
			return -EFAULT;
		ret = pkm_lcs_key_fd_enum_value_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&enum_value_args);
		if ((ret == 0 || ret == -ERANGE) &&
		    copy_to_user((void __user *)arg, &enum_value_args,
				 sizeof(enum_value_args)))
			return -EFAULT;
		return ret;
	case REG_IOC_ENUM_SUBKEYS:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&enum_subkey_args, (void __user *)arg,
				   sizeof(enum_subkey_args)))
			return -EFAULT;
		ret = pkm_lcs_key_fd_enum_subkey_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&enum_subkey_args);
		if ((ret == 0 || ret == -ERANGE) &&
		    copy_to_user((void __user *)arg, &enum_subkey_args,
				 sizeof(enum_subkey_args)))
			return -EFAULT;
		return ret;
	case REG_IOC_QUERY_KEY_INFO:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&query_key_info_args, (void __user *)arg,
				   sizeof(query_key_info_args)))
			return -EFAULT;
		ret = pkm_lcs_key_fd_query_key_info_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&query_key_info_args);
		if ((ret == 0 || ret == -ERANGE) &&
		    copy_to_user((void __user *)arg, &query_key_info_args,
				 sizeof(query_key_info_args)))
			return -EFAULT;
		return ret;
	case REG_IOC_GET_SECURITY:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&get_security_args, (void __user *)arg,
				   sizeof(get_security_args)))
			return -EFAULT;
		ret = pkm_lcs_key_fd_get_security_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&get_security_args);
		if ((ret == 0 || ret == -ERANGE) &&
		    copy_to_user((void __user *)arg, &get_security_args,
				 sizeof(get_security_args)))
			return -EFAULT;
		return ret;
	case REG_IOC_SET_SECURITY:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&set_security_args, (void __user *)arg,
				   sizeof(set_security_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_set_security_from_args(
			key_fd, &pkm_lcs_key_fd_default_usercopy_ops,
			&set_security_args);
	case REG_IOC_FLUSH:
		return pkm_lcs_key_fd_flush(key_fd);
	case REG_IOC_BACKUP:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&backup_args, (void __user *)arg,
				   sizeof(backup_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_backup_from_args(key_fd, &backup_args);
	case REG_IOC_RESTORE:
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&restore_args, (void __user *)arg,
				   sizeof(restore_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_restore_from_args(key_fd, &restore_args);
	case REG_IOC_NOTIFY:
		ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
			key_fd->granted_access, _IOC_NR(cmd));
		if (ret)
			return ret;
		if (!arg)
			return -EFAULT;
		if (copy_from_user(&notify_args, (void __user *)arg,
				   sizeof(notify_args)))
			return -EFAULT;
		return pkm_lcs_key_fd_notify_from_args(key_fd, &notify_args);
	default:
		return -ENOTTY;
	}
}

static long pkm_lcs_key_fd_get(int fd, struct fd *held,
			       struct pkm_lcs_key_fd **key_fd_out)
{
	struct file *file;

	if (!held || !key_fd_out)
		return -EINVAL;
	*key_fd_out = NULL;

	*held = fdget(fd);
	file = fd_file(*held);
	if (!file)
		return -EBADF;

	if (file->f_op != &pkm_lcs_key_fd_fops) {
		fdput(*held);
		return -EINVAL;
	}

	*key_fd_out = file->private_data;
	if (!*key_fd_out) {
		fdput(*held);
		return -EINVAL;
	}

	return 0;
}

static void pkm_lcs_key_fd_path_views_free(
	struct pkm_lcs_key_fd_string_view *views)
{
	kfree(views);
}

static long pkm_lcs_key_fd_path_views_from_components(
	const char * const *resolved_path, u32 component_count, u32 start,
	u32 count,
	struct pkm_lcs_key_fd_string_view **views_out)
{
	struct pkm_lcs_key_fd_string_view *views;
	size_t len;
	u32 i;

	if (!views_out)
		return -EINVAL;
	*views_out = NULL;
	if (!count)
		return 0;
	if (!resolved_path || start > component_count ||
	    count > component_count - start)
		return -EINVAL;

	views = kcalloc(count, sizeof(*views), GFP_KERNEL);
	if (!views)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		if (!resolved_path[start + i]) {
			pkm_lcs_key_fd_path_views_free(views);
			return -EINVAL;
		}
		len = strlen(resolved_path[start + i]);
		if (len > U32_MAX) {
			pkm_lcs_key_fd_path_views_free(views);
			return -EINVAL;
		}
		views[i].bytes = resolved_path[start + i];
		views[i].len = (u32)len;
	}

	*views_out = views;
	return 0;
}

static long pkm_lcs_key_fd_queue_dispatch_event_locked(
	struct pkm_lcs_key_fd *watcher, u32 event_type, const u8 *name,
	u32 name_len, bool subtree_record,
	const struct pkm_lcs_key_fd_string_view *path_components,
	u32 path_component_count, u32 queue_limit, bool *queued_out)
{
	struct pkm_lcs_key_fd_watch_event *event;
	bool matches = false;
	long ret;

	if (!watcher || !queued_out)
		return -EINVAL;
	*queued_out = false;

	mutex_lock(&watcher->watch_lock);
	if (!watcher->watch_armed || !watcher->watch_registry_linked) {
		mutex_unlock(&watcher->watch_lock);
		return -EIO;
	}
	ret = pkm_lcs_key_fd_watch_event_matches_filter(
		event_type, watcher->watch_filter, &matches);
	if (ret || !matches) {
		mutex_unlock(&watcher->watch_lock);
		return ret;
	}

	event = pkm_lcs_key_fd_build_watch_event(
		event_type, name, name_len, subtree_record, path_components,
		path_component_count);
	if (IS_ERR(event)) {
		mutex_unlock(&watcher->watch_lock);
		return PTR_ERR(event);
	}

	ret = pkm_lcs_key_fd_queue_watch_event_locked(watcher, event,
						      queue_limit);
	if (!ret)
		*queued_out = true;
	mutex_unlock(&watcher->watch_lock);
	return ret;
}

static long pkm_lcs_key_fd_dispatch_to_watcher_locked(
	struct pkm_lcs_key_fd *watcher, u32 event_type, const u8 *name,
	u32 name_len, bool subtree_record,
	const struct pkm_lcs_key_fd_string_view *path_components,
	u32 path_component_count, u32 queue_limit)
{
	bool queued = false;
	long ret;

	ret = pkm_lcs_key_fd_queue_dispatch_event_locked(
		watcher, event_type, name, name_len, subtree_record,
		path_components, path_component_count, queue_limit, &queued);
	if (queued)
		wake_up_interruptible(&watcher->watch_wait);
	return ret;
}

static long pkm_lcs_key_fd_validate_dispatch_input(
	const struct pkm_lcs_watch_dispatch_input *input)
{
	u32 written = 0;
	u8 overflow = 0;
	bool matches;
	int ret;

	if (!input)
		return -EINVAL;
	if (input->name_len && !input->name)
		return -EINVAL;
	ret = pkm_lcs_key_fd_watch_event_matches_filter(
		input->event_type, REG_NOTIFY_ALL, &matches);
	if (ret)
		return ret;
	return lcs_rust_write_watch_event_record(
		input->event_type, input->name, input->name_len, 0, NULL, 0,
		NULL, 0, &written, &overflow);
}

static long pkm_lcs_key_fd_validate_dispatch_context(
	const struct pkm_lcs_watch_dispatch_context *context)
{
	size_t len;
	u32 changed_index;
	u32 i;

	if (!context || !context->changed_key_guid ||
	    !context->path_component_count || !context->ancestor_guids ||
	    !context->resolved_path)
		return -EINVAL;
	if (context->name_len && !context->name)
		return -EINVAL;
	changed_index = context->path_component_count - 1U;
	if (!pkm_lcs_guid_equal(context->ancestor_guids[changed_index],
				context->changed_key_guid))
		return -EINVAL;
	for (i = 0; i < context->path_component_count; i++) {
		if (!context->resolved_path[i])
			return -EINVAL;
		len = strlen(context->resolved_path[i]);
		if (!len || len > U32_MAX)
			return -EINVAL;
	}
	return pkm_lcs_key_fd_validate_dispatch_input(
		&(struct pkm_lcs_watch_dispatch_input) {
			.mutation_fd = -1,
			.event_type = context->event_type,
			.name = context->name,
			.name_len = context->name_len,
		});
}

static void pkm_lcs_key_fd_transaction_burst_counts_free(
	struct list_head *counts)
{
	struct pkm_lcs_key_fd_transaction_burst_entry *entry;
	struct pkm_lcs_key_fd_transaction_burst_entry *tmp;

	if (!counts)
		return;
	list_for_each_entry_safe(entry, tmp, counts, link) {
		list_del(&entry->link);
		kfree(entry);
	}
}

static struct pkm_lcs_key_fd_transaction_burst_entry *
pkm_lcs_key_fd_transaction_burst_find(
	struct list_head *counts, const struct pkm_lcs_key_fd *watcher)
{
	struct pkm_lcs_key_fd_transaction_burst_entry *entry;

	if (!counts || !watcher)
		return NULL;
	list_for_each_entry(entry, counts, link) {
		if (entry->watcher == watcher)
			return entry;
	}
	return NULL;
}

static long pkm_lcs_key_fd_transaction_burst_count_watcher(
	struct list_head *counts, struct pkm_lcs_key_fd *watcher,
	u32 event_type, u32 limit)
{
	struct pkm_lcs_key_fd_transaction_burst_entry *entry;
	bool matches = false;
	long ret;

	if (!counts || !watcher || !limit)
		return -EINVAL;

	ret = pkm_lcs_key_fd_watch_event_matches_filter(
		event_type, watcher->watch_filter, &matches);
	if (ret || !matches)
		return ret;

	entry = pkm_lcs_key_fd_transaction_burst_find(counts, watcher);
	if (!entry) {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;
		INIT_LIST_HEAD(&entry->link);
		entry->watcher = watcher;
		list_add_tail(&entry->link, counts);
	}

	if (entry->event_count == U32_MAX)
		return -EOVERFLOW;
	entry->event_count++;
	if (entry->event_count > limit)
		entry->overflow = true;
	return 0;
}

static void pkm_lcs_internal_watch_event_path_destroy(
	struct pkm_lcs_internal_watch_event *event)
{
	u32 i;

	if (!event || !event->resolved_path)
		return;

	for (i = 0; i < event->path_component_count; i++)
		kfree(event->resolved_path[i]);
	kfree(event->resolved_path);
	event->resolved_path = NULL;
	event->path_component_count = 0;
}

static void pkm_lcs_internal_watch_event_name_destroy(
	struct pkm_lcs_internal_watch_event *event)
{
	if (!event)
		return;

	kfree(event->name);
	event->name = NULL;
	event->name_len = 0;
}

static long pkm_lcs_internal_watch_event_name_copy(
	struct pkm_lcs_internal_watch_event *event,
	const struct pkm_lcs_watch_dispatch_context *context)
{
	if (!event || !context || !context->name || !context->name_len)
		return -EINVAL;

	event->name = kmemdup_nul(context->name, context->name_len,
				  GFP_KERNEL);
	if (!event->name)
		return -ENOMEM;
	event->name_len = context->name_len;
	return 0;
}

static long pkm_lcs_internal_watch_event_path_copy(
	struct pkm_lcs_internal_watch_event *event,
	const struct pkm_lcs_watch_dispatch_context *context)
{
	size_t len;
	u32 i;

	if (!event || !context || !context->resolved_path ||
	    !context->path_component_count)
		return -EINVAL;

	event->resolved_path = kcalloc(context->path_component_count,
				       sizeof(*event->resolved_path),
				       GFP_KERNEL);
	if (!event->resolved_path)
		return -ENOMEM;

	for (i = 0; i < context->path_component_count; i++) {
		if (!context->resolved_path[i]) {
			pkm_lcs_internal_watch_event_path_destroy(event);
			return -EINVAL;
		}
		len = strlen(context->resolved_path[i]);
		if (!len || len > U32_MAX) {
			pkm_lcs_internal_watch_event_path_destroy(event);
			return -EINVAL;
		}
		event->resolved_path[i] = kstrdup(context->resolved_path[i],
						  GFP_KERNEL);
		if (!event->resolved_path[i]) {
			pkm_lcs_internal_watch_event_path_destroy(event);
			return -ENOMEM;
		}
	}

	event->path_component_count = context->path_component_count;
	return 0;
}

static bool pkm_lcs_internal_watch_event_deliverable(
	const struct pkm_lcs_internal_watch *watch, u32 event_type,
	u32 relative_path_count)
{
	if (!watch)
		return false;

	switch (watch->target) {
	case PKM_LCS_INTERNAL_WATCH_SELF_CONFIGURATION:
		return relative_path_count == 0 &&
		       (event_type == REG_WATCH_VALUE_SET ||
			event_type == REG_WATCH_VALUE_DELETED);
	case PKM_LCS_INTERNAL_WATCH_LAYER_METADATA:
		if (relative_path_count == 0)
			return event_type == REG_WATCH_SUBKEY_CREATED ||
			       event_type == REG_WATCH_SUBKEY_DELETED;
		return relative_path_count == 1 &&
		       (event_type == REG_WATCH_VALUE_SET ||
			event_type == REG_WATCH_VALUE_DELETED ||
			event_type == REG_WATCH_SD_CHANGED);
	case PKM_LCS_INTERNAL_WATCH_MACHINE_ROOT_FALLBACK:
		return event_type == REG_WATCH_SUBKEY_CREATED;
	default:
		return false;
	}
}

static long pkm_lcs_internal_watch_collect_locked(
	struct list_head *events, const struct pkm_lcs_internal_watch *watch,
	const struct pkm_lcs_watch_dispatch_context *context,
	u32 watched_path_index)
{
	struct pkm_lcs_internal_watch_event *event;
	u32 changed_index;
	u32 relative_path_count;
	long ret;

	if (!events || !watch || !watch->registry.linked || !context ||
	    !context->path_component_count ||
	    watched_path_index >= context->path_component_count)
		return -EINVAL;

	changed_index = context->path_component_count - 1U;
	if (watched_path_index > changed_index)
		return -EINVAL;
	relative_path_count = changed_index - watched_path_index;
	if (!pkm_lcs_internal_watch_event_deliverable(
		    watch, context->event_type, relative_path_count))
		return 0;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	INIT_LIST_HEAD(&event->link);
	event->source_id = watch->registry.source_id;
	event->target = watch->target;
	event->event_type = context->event_type;
	if (event->target == PKM_LCS_INTERNAL_WATCH_LAYER_METADATA) {
		memcpy(event->root_guid, context->ancestor_guids[0],
		       sizeof(event->root_guid));
		if (relative_path_count == 0) {
			if (!context->name || !context->name_len) {
				kfree(event);
				return 0;
			}
			memcpy(event->guid, watch->registry.guid,
			       sizeof(event->guid));
			ret = pkm_lcs_internal_watch_event_name_copy(event,
								     context);
			if (ret) {
				kfree(event);
				return ret;
			}
		} else {
			memcpy(event->guid, context->changed_key_guid,
			       sizeof(event->guid));
			ret = pkm_lcs_internal_watch_event_path_copy(event,
								     context);
			if (ret) {
				kfree(event);
				return ret;
			}
		}
	} else {
		memcpy(event->guid, watch->registry.guid,
		       sizeof(event->guid));
	}
	list_add_tail(&event->link, events);
	return 0;
}

static void pkm_lcs_internal_watch_recover_layer_change(
	const struct pkm_lcs_internal_watch_event *event)
{
	struct pkm_lcs_layer_operation_recovery_result recovery = { };

	if (!event)
		return;

	/*
	 * The watched source mutation already committed; recovery failures
	 * retain the last known-good local state or mark faulty sources down in
	 * the recovery helper.
	 */
	pkm_lcs_source_layer_operation_recover_skip_generation(
		event->source_id, event->root_guid, &recovery);
}

static void pkm_lcs_internal_watch_deliver_layer_metadata_refresh(
	const struct pkm_lcs_internal_watch_event *event)
{
	struct pkm_lcs_runtime_limits limits;
	bool effective_changed = false;

	if (!event)
		return;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	if (!pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
		    event->source_id, event->guid,
		    (const char * const *)event->resolved_path,
		    event->path_component_count, NULL, 0, false, &limits,
		    &effective_changed) &&
	    effective_changed)
		pkm_lcs_internal_watch_recover_layer_change(event);
}

static void pkm_lcs_internal_watch_deliver_layer_create(
	const struct pkm_lcs_internal_watch_event *event)
{
	static const char * const path_prefix[] = {
		"Machine", "System", "Registry", "Layers",
	};
	const char *resolved_path[ARRAY_SIZE(path_prefix) + 1];
	struct pkm_lcs_runtime_limits limits;
	u8 child_guid[PKM_LCS_GUID_BYTES];
	bool effective_changed = false;
	bool present = false;

	if (!event || !event->name || !event->name_len)
		return;

	memcpy(resolved_path, path_prefix, sizeof(path_prefix));
	resolved_path[ARRAY_SIZE(path_prefix)] = event->name;
	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);

	if (pkm_lcs_layer_metadata_child_lookup_from_root_with_limits(
		    event->source_id, event->guid, event->name,
		    event->name_len, &limits, child_guid, &present) ||
	    !present)
		return;

	if (!pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
		    event->source_id, child_guid, resolved_path,
		    ARRAY_SIZE(resolved_path), NULL, 0, false, &limits,
		    &effective_changed) &&
	    effective_changed)
		pkm_lcs_internal_watch_recover_layer_change(event);
}

static void pkm_lcs_internal_watch_deliver_layer_delete(
	const struct pkm_lcs_internal_watch_event *event,
	u32 *internal_effects)
{
	static const char base_name[] = "base";
	struct pkm_lcs_runtime_limits limits;
	bool is_base = false;
	long ret;

	if (!event || !event->name || !event->name_len)
		return;

	ret = pkm_lcs_key_fd_layer_name_casefold_equal(
		event->name, event->name_len, base_name,
		sizeof(base_name) - 1, &is_base);
	if (ret || is_base)
		return;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
		event->name, event->name_len, limits.request_timeout_ms, 0,
		NULL, &limits, NULL);
	if (!ret && internal_effects)
		*internal_effects |= PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE;
}

static void pkm_lcs_internal_watch_deliver_layer_event(
	const struct pkm_lcs_internal_watch_event *event,
	u32 *internal_effects)
{
	if (!event)
		return;

	switch (event->event_type) {
	case REG_WATCH_VALUE_SET:
	case REG_WATCH_VALUE_DELETED:
	case REG_WATCH_SD_CHANGED:
		pkm_lcs_internal_watch_deliver_layer_metadata_refresh(event);
		break;
	case REG_WATCH_SUBKEY_CREATED:
		pkm_lcs_internal_watch_deliver_layer_create(event);
		break;
	case REG_WATCH_SUBKEY_DELETED:
		pkm_lcs_internal_watch_deliver_layer_delete(
			event, internal_effects);
		break;
	default:
		break;
	}
}

static void pkm_lcs_internal_watch_deliver_machine_root_fallback(
	const struct pkm_lcs_internal_watch_event *event)
{
	struct pkm_lcs_source_bootstrap_refresh_result result = { };

	if (!event)
		return;

	/*
	 * The fallback watch exists only while Registry or Layers is missing.
	 * Reusing the bootstrap refresh path keeps first-source and seed-restore
	 * re-arm policy identical.
	 */
	pkm_lcs_source_bootstrap_refresh_machine_hive(event->source_id,
						     event->guid, &result);
}

static void pkm_lcs_internal_watch_events_deliver(struct list_head *events,
						  u32 *internal_effects)
{
	struct pkm_lcs_internal_watch_event *event;
	struct pkm_lcs_internal_watch_event *tmp;

	if (!events)
		return;

	list_for_each_entry_safe(event, tmp, events, link) {
		if (event->target ==
		    PKM_LCS_INTERNAL_WATCH_SELF_CONFIGURATION) {
			/*
			 * The source mutation has already committed. A failed
			 * re-read retains the previous known-good snapshot.
			 */
			pkm_lcs_runtime_limits_refresh_self_config_from_key(
				event->source_id, event->guid, NULL);
		} else if (event->target ==
			   PKM_LCS_INTERNAL_WATCH_LAYER_METADATA) {
			pkm_lcs_internal_watch_deliver_layer_event(
				event, internal_effects);
		} else if (event->target ==
			   PKM_LCS_INTERNAL_WATCH_MACHINE_ROOT_FALLBACK) {
			pkm_lcs_internal_watch_deliver_machine_root_fallback(
				event);
		}
		list_del(&event->link);
		pkm_lcs_internal_watch_event_path_destroy(event);
		pkm_lcs_internal_watch_event_name_destroy(event);
		kfree(event);
	}
}

static long pkm_lcs_key_fd_transaction_burst_count_context_locked(
	const struct pkm_lcs_watch_dispatch_context *context,
	struct list_head *counts, u32 limit, u32 max_subtree_depth)
{
	struct pkm_lcs_subtree_watch_entry *subtree;
	struct pkm_lcs_watch_registry_entry *entry;
	struct pkm_lcs_key_fd *watcher;
	u32 changed_index;
	u32 hash;
	u32 i;
	long ret;

	hash = pkm_lcs_guid_hash(context->changed_key_guid);
	hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
		if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
		    !pkm_lcs_guid_equal(entry->guid,
					context->changed_key_guid))
			continue;
		watcher = entry->owner.key_fd;
		ret = pkm_lcs_key_fd_transaction_burst_count_watcher(
			counts, watcher, context->event_type, limit);
		if (ret)
			return ret;
	}

	changed_index = context->path_component_count - 1U;
	for (i = changed_index; i > 0; i--) {
		const u8 *ancestor_guid = context->ancestor_guids[i - 1U];
		u32 path_count = changed_index - (i - 1U);

		if (pkm_lcs_guid_equal(ancestor_guid, context->changed_key_guid))
			continue;
		subtree = pkm_lcs_subtree_watch_find_locked(ancestor_guid);
		if (!subtree)
			continue;
		if (pkm_lcs_key_fd_subtree_depth_suppressed(
			    path_count, max_subtree_depth))
			continue;

		hash = pkm_lcs_guid_hash(ancestor_guid);
		hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
			if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
			    !pkm_lcs_guid_equal(entry->guid, ancestor_guid))
				continue;
			watcher = entry->owner.key_fd;
			if (!watcher->watch_subtree)
				continue;
			ret = pkm_lcs_key_fd_transaction_burst_count_watcher(
				counts, watcher, context->event_type, limit);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static bool pkm_lcs_key_fd_transaction_burst_suppresses_watcher(
	struct list_head *counts, const struct pkm_lcs_key_fd *watcher)
{
	struct pkm_lcs_key_fd_transaction_burst_entry *entry;

	entry = pkm_lcs_key_fd_transaction_burst_find(counts, watcher);
	return entry && entry->overflow;
}

static long pkm_lcs_key_fd_transaction_burst_dispatch_overflows_locked(
	struct list_head *counts, u32 queue_limit)
{
	struct pkm_lcs_key_fd_transaction_burst_entry *entry;
	long ret;

	if (!counts)
		return 0;
	list_for_each_entry(entry, counts, link) {
		if (!entry->overflow)
			continue;
		ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
			entry->watcher, REG_WATCH_OVERFLOW, NULL, 0, false,
			NULL, 0, queue_limit);
		if (ret)
			return ret;
	}
	return 0;
}

static long pkm_lcs_key_fd_dispatch_watch_event_context_locked(
	const struct pkm_lcs_watch_dispatch_context *context,
	struct list_head *transaction_burst_counts,
	struct list_head *internal_events, u32 max_subtree_depth,
	u32 queue_limit)
{
	struct pkm_lcs_key_fd_string_view *path_views = NULL;
	struct pkm_lcs_subtree_watch_entry *subtree;
	struct pkm_lcs_watch_registry_entry *entry;
	struct pkm_lcs_key_fd *watcher;
	long ret = 0;
	u32 changed_index;
	u32 hash;
	u32 i;

	hash = pkm_lcs_guid_hash(context->changed_key_guid);
	hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
		if (entry->kind != PKM_LCS_WATCH_REGISTRY_INTERNAL ||
		    !pkm_lcs_guid_equal(entry->guid, context->changed_key_guid))
			continue;
		ret = pkm_lcs_internal_watch_collect_locked(
			internal_events, entry->owner.internal, context,
			context->path_component_count - 1U);
		if (ret)
			goto out_unlock;
	}

	hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
		if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
		    !pkm_lcs_guid_equal(entry->guid, context->changed_key_guid))
			continue;
		watcher = entry->owner.key_fd;
		if (pkm_lcs_key_fd_transaction_burst_suppresses_watcher(
			    transaction_burst_counts, watcher))
			continue;
		ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
			watcher, context->event_type, context->name,
			context->name_len, watcher->watch_subtree, NULL, 0,
			queue_limit);
		if (ret)
			goto out_unlock;
	}

	changed_index = context->path_component_count - 1U;
	for (i = changed_index; i > 0; i--) {
		const u8 *ancestor_guid = context->ancestor_guids[i - 1U];
		u32 watched_index = i - 1U;
		u32 path_count;

		if (pkm_lcs_guid_equal(ancestor_guid, context->changed_key_guid))
			continue;
		subtree = pkm_lcs_subtree_watch_find_locked(ancestor_guid);
		if (!subtree)
			continue;

		path_count = changed_index - watched_index;
		hash = pkm_lcs_guid_hash(ancestor_guid);
		hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
			if (entry->kind != PKM_LCS_WATCH_REGISTRY_INTERNAL ||
			    !pkm_lcs_guid_equal(entry->guid, ancestor_guid))
				continue;
			if (!entry->subtree)
				continue;
			ret = pkm_lcs_internal_watch_collect_locked(
				internal_events, entry->owner.internal, context,
				watched_index);
			if (ret)
				goto out_unlock;
		}

		if (pkm_lcs_key_fd_subtree_depth_suppressed(
			    path_count, max_subtree_depth))
			continue;

		ret = pkm_lcs_key_fd_path_views_from_components(
			context->resolved_path, context->path_component_count, i,
			path_count, &path_views);
		if (ret)
			goto out_unlock;

		hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
			if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
			    !pkm_lcs_guid_equal(entry->guid, ancestor_guid))
				continue;
			watcher = entry->owner.key_fd;
			if (!watcher->watch_subtree)
				continue;
			if (pkm_lcs_key_fd_transaction_burst_suppresses_watcher(
				    transaction_burst_counts, watcher))
				continue;
			ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
				watcher, context->event_type, context->name,
				context->name_len, true, path_views, path_count,
				queue_limit);
			if (ret)
				goto out_unlock;
		}

		pkm_lcs_key_fd_path_views_free(path_views);
		path_views = NULL;
	}

out_unlock:
	pkm_lcs_key_fd_path_views_free(path_views);
	return ret;
}

long pkm_lcs_key_fd_dispatch_watch_event_context_effects(
	const struct pkm_lcs_watch_dispatch_context *context,
	u32 *internal_effects_out)
{
	LIST_HEAD(internal_events);
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	long ret;

	if (internal_effects_out)
		*internal_effects_out = 0;
	ret = pkm_lcs_key_fd_validate_dispatch_context(context);
	if (ret)
		return ret;
	limits = context->limits;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&fallback_limits);
		limits = &fallback_limits;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	ret = pkm_lcs_key_fd_dispatch_watch_event_context_locked(context,
								NULL,
								&internal_events,
								limits->max_subtree_watch_depth,
								limits->notification_queue_size);
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	pkm_lcs_internal_watch_events_deliver(&internal_events,
					      internal_effects_out);
	return ret;
}

long pkm_lcs_key_fd_dispatch_watch_event_context(
	const struct pkm_lcs_watch_dispatch_context *context)
{
	return pkm_lcs_key_fd_dispatch_watch_event_context_effects(context,
								  NULL);
}

long pkm_lcs_key_fd_dispatch_watch_event_context_batch_effects(
	const struct pkm_lcs_watch_dispatch_context *contexts, u32 context_count,
	u32 *internal_effects_out)
{
	LIST_HEAD(internal_events);
	LIST_HEAD(transaction_burst_counts);
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	long ret = 0;
	u32 i;

	if (internal_effects_out)
		*internal_effects_out = 0;
	if (!context_count)
		return 0;
	if (!contexts)
		return -EINVAL;

	for (i = 0; i < context_count; i++) {
		ret = pkm_lcs_key_fd_validate_dispatch_context(&contexts[i]);
		if (ret)
			return ret;
	}
	limits = contexts[0].limits;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&fallback_limits);
		limits = &fallback_limits;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	for (i = 0; i < context_count; i++) {
		ret = pkm_lcs_key_fd_transaction_burst_count_context_locked(
			&contexts[i], &transaction_burst_counts,
			limits->max_transaction_watch_event_burst,
			limits->max_subtree_watch_depth);
		if (ret)
			goto out_unlock;
	}
	ret = pkm_lcs_key_fd_transaction_burst_dispatch_overflows_locked(
		&transaction_burst_counts, limits->notification_queue_size);
	if (ret)
		goto out_unlock;
	for (i = 0; i < context_count; i++) {
		ret = pkm_lcs_key_fd_dispatch_watch_event_context_locked(
			&contexts[i], &transaction_burst_counts,
			&internal_events, limits->max_subtree_watch_depth,
			limits->notification_queue_size);
		if (ret)
			break;
	}
out_unlock:
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	pkm_lcs_key_fd_transaction_burst_counts_free(
		&transaction_burst_counts);
	pkm_lcs_internal_watch_events_deliver(&internal_events,
					      internal_effects_out);
	return ret;
}

long pkm_lcs_key_fd_dispatch_watch_event_context_batch(
	const struct pkm_lcs_watch_dispatch_context *contexts, u32 context_count)
{
	return pkm_lcs_key_fd_dispatch_watch_event_context_batch_effects(
		contexts, context_count, NULL);
}

static long pkm_lcs_key_fd_dispatch_overflow_context_locked(
	const struct pkm_lcs_watch_dispatch_context *context,
	u32 max_subtree_depth, u32 queue_limit)
{
	struct pkm_lcs_subtree_watch_entry *subtree;
	struct pkm_lcs_watch_registry_entry *entry;
	struct pkm_lcs_key_fd *watcher;
	u32 changed_index;
	u32 hash;
	u32 i;
	long ret = 0;

	hash = pkm_lcs_guid_hash(context->changed_key_guid);
	hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
		if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
		    !pkm_lcs_guid_equal(entry->guid,
					context->changed_key_guid))
			continue;
		watcher = entry->owner.key_fd;
		ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
			watcher, REG_WATCH_OVERFLOW, NULL, 0, false, NULL, 0,
			queue_limit);
		if (ret)
			return ret;
	}

	changed_index = context->path_component_count - 1U;
	for (i = changed_index; i > 0; i--) {
		const u8 *ancestor_guid = context->ancestor_guids[i - 1U];
		u32 path_count = changed_index - (i - 1U);

		if (pkm_lcs_guid_equal(ancestor_guid, context->changed_key_guid))
			continue;
		subtree = pkm_lcs_subtree_watch_find_locked(ancestor_guid);
		if (!subtree)
			continue;
		if (pkm_lcs_key_fd_subtree_depth_suppressed(
			    path_count, max_subtree_depth))
			continue;

		hash = pkm_lcs_guid_hash(ancestor_guid);
		hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
			if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
			    !pkm_lcs_guid_equal(entry->guid, ancestor_guid))
				continue;
			watcher = entry->owner.key_fd;
			if (!watcher->watch_subtree)
				continue;
			ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
				watcher, REG_WATCH_OVERFLOW, NULL, 0, false,
				NULL, 0, queue_limit);
			if (ret)
				return ret;
		}
	}

	return 0;
}

long pkm_lcs_key_fd_dispatch_overflow_context(
	const struct pkm_lcs_watch_dispatch_context *context)
{
	struct pkm_lcs_watch_dispatch_context overflow_context;
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	long ret;

	if (!context)
		return -EINVAL;

	overflow_context = *context;
	overflow_context.event_type = REG_WATCH_OVERFLOW;
	overflow_context.name = NULL;
	overflow_context.name_len = 0;
	ret = pkm_lcs_key_fd_validate_dispatch_context(&overflow_context);
	if (ret)
		return ret;
	limits = overflow_context.limits;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&fallback_limits);
		limits = &fallback_limits;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	ret = pkm_lcs_key_fd_dispatch_overflow_context_locked(
		&overflow_context, limits->max_subtree_watch_depth,
		limits->notification_queue_size);
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return ret;
}

long pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits,
	u32 *watch_count_out)
{
	struct pkm_lcs_watch_registry_entry *entry;
	struct pkm_lcs_key_fd *watcher;
	struct pkm_lcs_runtime_limits fallback_limits;
	u32 queued = 0;
	int bucket;
	long ret = 0;

	if (watch_count_out)
		*watch_count_out = 0;
	if (!source_id || !watch_count_out)
		return -EINVAL;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&fallback_limits);
		limits = &fallback_limits;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	hash_for_each(pkm_lcs_watch_map, bucket, entry, link) {
		if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
		    entry->source_id != source_id)
			continue;
		watcher = entry->owner.key_fd;
		ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
			watcher, REG_WATCH_OVERFLOW, NULL, 0, false, NULL, 0,
			limits->notification_queue_size);
		if (ret)
			break;
		if (queued == U32_MAX) {
			ret = -EOVERFLOW;
			break;
		}
		queued++;
	}
	mutex_unlock(&pkm_lcs_watch_registry_lock);

	if (ret)
		return ret;
	*watch_count_out = queued;
	return 0;
}

long pkm_lcs_key_fd_dispatch_source_overflow(u32 source_id,
					     u32 *watch_count_out)
{
	return pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
		source_id, NULL, watch_count_out);
}

static long pkm_lcs_key_fd_dispatch_key_deleted_direct(
	const u8 guid[PKM_LCS_GUID_BYTES],
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_watch_registry_entry *entry;
	struct pkm_lcs_runtime_limits fallback_limits;
	struct pkm_lcs_key_fd *watcher;
	u32 hash;
	long ret = 0;

	if (!guid)
		return -EINVAL;
	if (!limits) {
		pkm_lcs_key_fd_runtime_limits_snapshot_or_default(
			&fallback_limits);
		limits = &fallback_limits;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	hash = pkm_lcs_guid_hash(guid);
	hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
		if (entry->kind != PKM_LCS_WATCH_REGISTRY_KEY_FD ||
		    !pkm_lcs_guid_equal(entry->guid, guid))
			continue;
		watcher = entry->owner.key_fd;
		ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
			watcher, REG_WATCH_KEY_DELETED, NULL, 0,
			watcher->watch_subtree, NULL, 0,
			limits->notification_queue_size);
		if (ret)
			break;
	}
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return ret;
}

static long pkm_lcs_key_fd_mark_orphaned_internal(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out,
	u32 *live_refs_out, bool dispatch_direct_deleted,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_key_ref_entry *entry;
	struct pkm_lcs_key_fd *key_fd;
	bool already_orphaned;
	u32 live_refs = 0;
	u32 marked = 0;

	if (marked_out)
		*marked_out = 0;
	if (live_refs_out)
		*live_refs_out = 0;
	if (!source_id || !guid || !memchr_inv(guid, 0, PKM_LCS_GUID_BYTES))
		return -EINVAL;

	mutex_lock(&pkm_lcs_key_ref_lock);
	entry = pkm_lcs_key_ref_find_locked(source_id, guid);
	if (!entry) {
		mutex_unlock(&pkm_lcs_key_ref_lock);
		return 0;
	}

	live_refs = entry->refcount;
	already_orphaned = entry->orphaned;
	if (!already_orphaned) {
		entry->orphaned = true;
		list_for_each_entry(key_fd, &entry->fds, key_ref_node) {
			mutex_lock(&key_fd->watch_lock);
			if (!key_fd->orphaned) {
				key_fd->orphaned = true;
				marked++;
			}
			mutex_unlock(&key_fd->watch_lock);
		}
	}
	mutex_unlock(&pkm_lcs_key_ref_lock);

	if (!already_orphaned && dispatch_direct_deleted)
		(void)pkm_lcs_key_fd_dispatch_key_deleted_direct(guid,
								 limits);
	if (marked_out)
		*marked_out = marked;
	if (live_refs_out)
		*live_refs_out = live_refs;
	return 0;
}

long pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out)
{
	return pkm_lcs_key_fd_mark_orphaned_internal(source_id, guid,
						    marked_out, NULL, true,
						    NULL);
}

long pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted_with_refs(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out,
	u32 *live_refs_out)
{
	return pkm_lcs_key_fd_mark_orphaned_internal(source_id, guid,
						    marked_out, live_refs_out,
						    true, NULL);
}

long pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted_with_refs_limits(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES],
	const struct pkm_lcs_runtime_limits *limits, u32 *marked_out,
	u32 *live_refs_out)
{
	return pkm_lcs_key_fd_mark_orphaned_internal(source_id, guid,
						    marked_out, live_refs_out,
						    true, limits);
}

long pkm_lcs_key_fd_mark_orphaned_no_watch(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out,
	u32 *live_refs_out)
{
	return pkm_lcs_key_fd_mark_orphaned_internal(source_id, guid,
						    marked_out, live_refs_out,
						    false, NULL);
}

long pkm_lcs_key_fd_dispatch_watch_event(
	const struct pkm_lcs_watch_dispatch_input *input)
{
	struct pkm_lcs_watch_dispatch_context context = { };
	struct pkm_lcs_key_fd *mutation_key;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_validate_dispatch_input(input);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_get(input->mutation_fd, &held, &mutation_key);
	if (ret)
		return ret;
	if (!mutation_key->path_component_count ||
	    !mutation_key->ancestor_guids || !mutation_key->resolved_path) {
		fdput(held);
		return -EINVAL;
	}

	context.changed_key_guid = mutation_key->key_guid;
	context.ancestor_guids = mutation_key->ancestor_guids;
	context.resolved_path = (const char * const *)mutation_key->resolved_path;
	context.path_component_count = mutation_key->path_component_count;
	context.event_type = input->event_type;
	context.name = input->name;
	context.name_len = input->name_len;
	ret = pkm_lcs_key_fd_dispatch_watch_event_context(&context);
	fdput(held);
	return ret;
}

static bool pkm_lcs_internal_watch_guid_valid(
	const u8 guid[PKM_LCS_GUID_BYTES])
{
	return guid && memchr_inv(guid, 0, PKM_LCS_GUID_BYTES);
}

static void pkm_lcs_internal_watch_remove_locked(
	struct pkm_lcs_internal_watch *watch)
{
	if (!watch->registry.linked)
		return;

	pkm_lcs_watch_registry_entry_unlink_locked(&watch->registry);
	if (watch->registry.subtree)
		pkm_lcs_subtree_watch_put_locked(watch->registry.guid);
	memset(watch, 0, sizeof(*watch));
}

static void pkm_lcs_internal_self_watch_disarm_locked(void)
{
	pkm_lcs_internal_watch_remove_locked(
		&pkm_lcs_internal_self_watch.registry);
	pkm_lcs_internal_watch_remove_locked(&pkm_lcs_internal_self_watch.layers);
	pkm_lcs_internal_watch_remove_locked(
		&pkm_lcs_internal_self_watch.fallback);
	pkm_lcs_internal_self_watch.source_id = 0;
	pkm_lcs_internal_self_watch.mode =
		PKM_LCS_INTERNAL_SELF_WATCH_DISARMED;
	pkm_lcs_internal_self_watch.watch_count = 0;
}

static long pkm_lcs_internal_watch_add_locked(
	struct pkm_lcs_internal_watch *watch, u32 source_id,
	const u8 guid[PKM_LCS_GUID_BYTES],
	enum pkm_lcs_internal_watch_target target)
{
	long ret;

	ret = pkm_lcs_subtree_watch_get_locked(guid);
	if (ret)
		return ret;
	pkm_lcs_watch_registry_entry_init_internal(watch, source_id, guid,
						   target);
	pkm_lcs_watch_registry_entry_link_locked(&watch->registry);
	return 0;
}

static void pkm_lcs_internal_self_watch_fill_result_locked(
	struct pkm_lcs_internal_self_watch_arm_result *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->source_id = pkm_lcs_internal_self_watch.source_id;
	out->watch_count = pkm_lcs_internal_self_watch.watch_count;
	out->mode = pkm_lcs_internal_self_watch.mode;
	if (pkm_lcs_internal_self_watch.registry.registry.linked)
		memcpy(out->registry_guid,
		       pkm_lcs_internal_self_watch.registry.registry.guid,
		       sizeof(out->registry_guid));
	if (pkm_lcs_internal_self_watch.layers.registry.linked)
		memcpy(out->layers_guid,
		       pkm_lcs_internal_self_watch.layers.registry.guid,
		       sizeof(out->layers_guid));
	if (pkm_lcs_internal_self_watch.fallback.registry.linked)
		memcpy(out->fallback_guid,
		       pkm_lcs_internal_self_watch.fallback.registry.guid,
		       sizeof(out->fallback_guid));
}

long pkm_lcs_internal_self_watch_arm(
	u32 source_id, const u8 machine_root_guid[PKM_LCS_GUID_BYTES],
	bool registry_present,
	const u8 registry_guid[PKM_LCS_GUID_BYTES],
	bool layers_present, const u8 layers_guid[PKM_LCS_GUID_BYTES],
	struct pkm_lcs_internal_self_watch_arm_result *result_out)
{
	long ret;

	if (result_out)
		memset(result_out, 0, sizeof(*result_out));
	if (!source_id || !pkm_lcs_internal_watch_guid_valid(machine_root_guid))
		return -EINVAL;
	if (registry_present &&
	    !pkm_lcs_internal_watch_guid_valid(registry_guid))
		return -EINVAL;
	if (layers_present && !pkm_lcs_internal_watch_guid_valid(layers_guid))
		return -EINVAL;

	mutex_lock(&pkm_lcs_watch_registry_lock);
	pkm_lcs_internal_self_watch_disarm_locked();

	if (registry_present && layers_present) {
		ret = pkm_lcs_internal_watch_add_locked(
			&pkm_lcs_internal_self_watch.registry, source_id,
			registry_guid,
			PKM_LCS_INTERNAL_WATCH_SELF_CONFIGURATION);
		if (ret)
			goto out_rollback;
		ret = pkm_lcs_internal_watch_add_locked(
			&pkm_lcs_internal_self_watch.layers, source_id,
			layers_guid, PKM_LCS_INTERNAL_WATCH_LAYER_METADATA);
		if (ret)
			goto out_rollback;
		pkm_lcs_internal_self_watch.mode =
			PKM_LCS_INTERNAL_SELF_WATCH_TARGETED;
		pkm_lcs_internal_self_watch.watch_count = 2;
	} else {
		ret = pkm_lcs_internal_watch_add_locked(
			&pkm_lcs_internal_self_watch.fallback, source_id,
			machine_root_guid,
			PKM_LCS_INTERNAL_WATCH_MACHINE_ROOT_FALLBACK);
		if (ret)
			goto out_rollback;
		pkm_lcs_internal_self_watch.mode =
			PKM_LCS_INTERNAL_SELF_WATCH_MACHINE_ROOT_FALLBACK;
		pkm_lcs_internal_self_watch.watch_count = 1;
	}

	pkm_lcs_internal_self_watch.source_id = source_id;
	pkm_lcs_internal_self_watch_fill_result_locked(result_out);
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return 0;

out_rollback:
	pkm_lcs_internal_self_watch_disarm_locked();
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return ret;
}

void pkm_lcs_internal_self_watch_disarm(void)
{
	mutex_lock(&pkm_lcs_watch_registry_lock);
	pkm_lcs_internal_self_watch_disarm_locked();
	mutex_unlock(&pkm_lcs_watch_registry_lock);
}

static long pkm_lcs_key_fd_check_ioctl_common(
	int fd, unsigned int cmd,
	int (*gate)(u32 granted_access, u32 ioctl_number),
	u32 security_info, bool has_security_info)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	if (_IOC_TYPE(cmd) != REG_IOC_TYPE)
		return -EINVAL;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	if (has_security_info)
		ret = lcs_rust_key_fd_security_ioctl_access_gate(
			key_fd->granted_access, _IOC_NR(cmd), security_info);
	else
		ret = gate(key_fd->granted_access, _IOC_NR(cmd));

	fdput(held);
	return ret;
}

long pkm_lcs_key_fd_check_fixed_ioctl_access(int fd, unsigned int cmd)
{
	return pkm_lcs_key_fd_check_ioctl_common(
		fd, cmd, lcs_rust_key_fd_fixed_ioctl_access_gate, 0, false);
}

long pkm_lcs_key_fd_check_security_ioctl_access(int fd, unsigned int cmd,
						u32 security_info)
{
	return pkm_lcs_key_fd_check_ioctl_common(
		fd, cmd, NULL, security_info, true);
}

void pkm_lcs_set_security_merge_result_destroy(
	struct pkm_lcs_set_security_merge_result *result)
{
	if (!result)
		return;
	kfree(result->merged_sd);
	result->merged_sd = NULL;
	result->merged_sd_len = 0;
}

long pkm_lcs_key_fd_plan_set_security_merge(
	const u8 *existing_sd, size_t existing_sd_len,
	const u8 *input_sd, size_t input_sd_len, u32 security_info,
	struct pkm_lcs_set_security_merge_result *out)
{
	size_t required_len = 0;
	size_t written = 0;
	u8 *merged_sd;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (!existing_sd || !input_sd)
		return -EINVAL;

	ret = lcs_rust_plan_registry_set_security(
		existing_sd, existing_sd_len, input_sd, input_sd_len,
		security_info, NULL, 0, &required_len);
	if (ret)
		return ret;
	if (!required_len || required_len > U32_MAX)
		return -EOVERFLOW;

	merged_sd = kmalloc(required_len, GFP_KERNEL);
	if (!merged_sd)
		return -ENOMEM;

	ret = lcs_rust_plan_registry_set_security(
		existing_sd, existing_sd_len, input_sd, input_sd_len,
		security_info, merged_sd, required_len, &written);
	if (ret) {
		kfree(merged_sd);
		return ret;
	}
	if (written != required_len) {
		kfree(merged_sd);
		return -EIO;
	}

	out->merged_sd = merged_sd;
	out->merged_sd_len = written;
	return 0;
}

static void pkm_lcs_get_security_result_destroy(
	struct pkm_lcs_get_security_result *result)
{
	if (!result)
		return;
	kfree(result->sd);
	result->sd = NULL;
	result->sd_len = 0;
}

static long pkm_lcs_key_fd_plan_get_security(
	const u8 *existing_sd, size_t existing_sd_len, u32 security_info,
	struct pkm_lcs_get_security_result *out)
{
	size_t required_len = 0;
	size_t written = 0;
	u8 *sd;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (!existing_sd)
		return -EINVAL;

	ret = lcs_rust_plan_registry_get_security(existing_sd, existing_sd_len,
						  security_info, NULL, 0,
						  &required_len);
	if (ret)
		return ret;
	if (!required_len || required_len > U32_MAX)
		return -EOVERFLOW;

	sd = kmalloc(required_len, GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	ret = lcs_rust_plan_registry_get_security(existing_sd, existing_sd_len,
						  security_info, sd,
						  required_len, &written);
	if (ret) {
		kfree(sd);
		return ret;
	}
	if (written != required_len) {
		kfree(sd);
		return -EIO;
	}

	out->sd = sd;
	out->sd_len = written;
	return 0;
}

long pkm_lcs_key_fd_relative_base(int fd,
				  struct pkm_lcs_key_fd_relative_base *out)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret) {
		if (ret == -EINVAL)
			return -EBADF;
		return ret;
	}

	if (key_fd->orphaned) {
		fdput(held);
		return -ENOENT;
	}

	ret = pkm_lcs_key_fd_revalidate_after_source_restart(key_fd, NULL);
	if (ret) {
		fdput(held);
		return ret;
	}

	out->source_id = key_fd->source_id;
	out->parent_depth = key_fd->path_component_count;
	out->orphaned = key_fd->orphaned;
	memcpy(out->key_guid, key_fd->key_guid, sizeof(out->key_guid));
	memcpy(out->root_guid, key_fd->ancestor_guids[0], sizeof(out->root_guid));

	fdput(held);
	return 0;
}

void pkm_lcs_key_fd_parent_snapshot_destroy(
	struct pkm_lcs_key_fd_parent_snapshot *snapshot)
{
	u32 i;

	if (!snapshot)
		return;

	if (snapshot->resolved_path) {
		for (i = 0; i < snapshot->path_component_count; i++)
			kfree(snapshot->resolved_path[i]);
		kfree(snapshot->resolved_path);
	}
	kfree(snapshot->ancestor_guids);
	memset(snapshot, 0, sizeof(*snapshot));
}

static long pkm_lcs_key_fd_copy_parent_snapshot(
	const struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_key_fd_parent_snapshot *out)
{
	size_t guid_bytes;
	u32 i;

	if (!key_fd || !out || !key_fd->source_id ||
	    !key_fd->path_component_count || !key_fd->resolved_path ||
	    !key_fd->ancestor_guids)
		return -EINVAL;

	out->source_id = key_fd->source_id;
	out->path_component_count = key_fd->path_component_count;
	out->orphaned = key_fd->orphaned;
	memcpy(out->key_guid, key_fd->key_guid, sizeof(out->key_guid));

	out->resolved_path = kcalloc(key_fd->path_component_count,
				     sizeof(*out->resolved_path),
				     GFP_KERNEL);
	if (!out->resolved_path)
		return -ENOMEM;

	if (check_mul_overflow((size_t)key_fd->path_component_count,
			       sizeof(*out->ancestor_guids), &guid_bytes)) {
		pkm_lcs_key_fd_parent_snapshot_destroy(out);
		return -EINVAL;
	}
	out->ancestor_guids = kmemdup(key_fd->ancestor_guids, guid_bytes,
				      GFP_KERNEL);
	if (!out->ancestor_guids) {
		pkm_lcs_key_fd_parent_snapshot_destroy(out);
		return -ENOMEM;
	}

	for (i = 0; i < key_fd->path_component_count; i++) {
		if (!key_fd->resolved_path[i]) {
			pkm_lcs_key_fd_parent_snapshot_destroy(out);
			return -EINVAL;
		}
		out->resolved_path[i] = kstrdup(key_fd->resolved_path[i],
						GFP_KERNEL);
		if (!out->resolved_path[i]) {
			pkm_lcs_key_fd_parent_snapshot_destroy(out);
			return -ENOMEM;
		}
	}

	return 0;
}

long pkm_lcs_key_fd_parent_snapshot(int fd,
				    struct pkm_lcs_key_fd_parent_snapshot *out)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret) {
		if (ret == -EINVAL)
			return -EBADF;
		return ret;
	}

	if (key_fd->orphaned) {
		fdput(held);
		return -ENOENT;
	}

	ret = pkm_lcs_key_fd_revalidate_after_source_restart(key_fd, NULL);
	if (ret) {
		fdput(held);
		return ret;
	}

	ret = pkm_lcs_key_fd_copy_parent_snapshot(key_fd, out);
	fdput(held);
	if (ret)
		pkm_lcs_key_fd_parent_snapshot_destroy(out);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_key_fd_set_orphaned(int fd, bool orphaned)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	mutex_lock(&pkm_lcs_key_ref_lock);
	if (key_fd->key_ref)
		key_fd->key_ref->orphaned = orphaned;
	mutex_unlock(&pkm_lcs_key_ref_lock);
	mutex_lock(&key_fd->watch_lock);
	key_fd->orphaned = orphaned;
	mutex_unlock(&key_fd->watch_lock);
	fdput(held);
	return 0;
}

long pkm_lcs_kunit_key_fd_get_security(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_get_security_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_get_security_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_query_value(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_value_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_query_value_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_query_values_batch(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_values_batch_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_query_values_batch_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_enum_value(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_enum_value_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_enum_value_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_enum_subkey(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_enum_subkey_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_enum_subkey_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_query_key_info(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_key_info_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_query_key_info_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_set_security(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_security_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_set_security_from_args(key_fd, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_set_value_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_set_value_from_args_for_token(key_fd, token, ops,
							    args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_refresh_layer_metadata(int fd)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_refresh_layer_metadata(key_fd);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_delete_value_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_delete_value_from_args_for_token(
		key_fd, token, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_blanket_tombstone_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_blanket_tombstone_from_args_for_token(
		key_fd, token, ops, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_delete_key_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_key_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_delete_key_from_args_for_token(key_fd, token, ops,
							    args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_hide_key_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_hide_key_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_hide_key_from_args_for_token(key_fd, token, ops,
							  args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_backup_for_token(
	int fd, const void *token, const struct reg_backup_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_backup_from_args_for_token(key_fd, token, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_backup_layer_manifest_frame(
	const char *layer_name, u32 layer_name_len, u32 precedence, u8 enabled,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len, u8 **frame_out, size_t *frame_len_out)
{
	struct pkm_lcs_layer_snapshot snapshot = {
		.base_metadata_present = base_metadata_present,
		.base_metadata_sd = base_metadata_sd,
		.base_metadata_sd_len = base_metadata_sd_len,
	};
	struct pkm_lcs_rsi_layer_view layer = {
		.name = layer_name,
		.name_len = layer_name_len,
		.precedence = precedence,
		.enabled = enabled,
	};
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_backup_alloc_layer_manifest_frame(
		&limits, &snapshot, &layer, frame_out, frame_len_out);
}

long pkm_lcs_kunit_backup_path_entry_frame(
	const u8 parent_guid[PKM_LCS_GUID_BYTES], const char *child_name,
	size_t child_name_len, const u8 child_guid[PKM_LCS_GUID_BYTES],
	bool hidden, const char *layer_name, size_t layer_name_len,
	u64 sequence, u8 **frame_out, size_t *frame_len_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_backup_alloc_path_entry_frame(
		&limits, parent_guid, child_name, child_name_len, child_guid,
		hidden, layer_name, layer_name_len, sequence, frame_out,
		frame_len_out);
}

long pkm_lcs_kunit_backup_value_frame(
	const u8 key_guid[PKM_LCS_GUID_BYTES], const char *name,
	size_t name_len, u32 value_type, const u8 *data, size_t data_len,
	const char *layer_name, size_t layer_name_len, u64 sequence,
	u8 **frame_out, size_t *frame_len_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_backup_alloc_value_frame(
		&limits, key_guid, name, name_len, value_type, data, data_len,
		layer_name, layer_name_len, sequence, frame_out,
		frame_len_out);
}

long pkm_lcs_kunit_backup_blanket_tombstone_frame(
	const u8 key_guid[PKM_LCS_GUID_BYTES], const char *layer_name,
	size_t layer_name_len, u64 sequence, u8 **frame_out,
	size_t *frame_len_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_backup_alloc_blanket_tombstone_frame(
		&limits, key_guid, layer_name, layer_name_len, sequence,
		frame_out, frame_len_out);
}

long pkm_lcs_kunit_backup_query_values_entries(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	struct pkm_lcs_backup_value_entry_view *values, size_t value_capacity,
	struct pkm_lcs_backup_blanket_entry_view *blankets,
	size_t blanket_capacity, u32 *value_count_out,
	u32 *blanket_count_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return lcs_rust_materialize_rsi_query_values_backup_entries(
		frame, frame_len, request_id, next_sequence, &limits, values,
		value_capacity, blankets, blanket_capacity, value_count_out,
		blanket_count_out);
}

long pkm_lcs_kunit_backup_enum_children_path_entries(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	struct pkm_lcs_backup_path_entry_view *entries, size_t entry_capacity,
	u32 *entry_count_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	return lcs_rust_materialize_rsi_enum_children_backup_path_entries(
		frame, frame_len, request_id, next_sequence, &limits, entries,
		entry_capacity, entry_count_out);
}

long pkm_lcs_kunit_backup_collect_referenced_layers(
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const u8 *enum_frame, size_t enum_frame_len, u64 enum_request_id,
	const u8 *values_frame, size_t values_frame_len,
	u64 values_request_id, u64 next_sequence,
	struct pkm_lcs_backup_layer_ref_view *refs, size_t ref_capacity,
	u32 *ref_count_out)
{
	struct pkm_lcs_layer_snapshot snapshot = {
		.layers = layers,
		.layer_count = layer_count,
	};
	struct pkm_lcs_backup_referenced_layers collected = { };
	struct pkm_lcs_runtime_limits limits;
	u32 i;
	long ret;

	if (!ref_count_out || (ref_capacity && !refs))
		return -EINVAL;
	*ref_count_out = 0;

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_backup_collect_referenced_layers(
		&limits, &snapshot, enum_frame, enum_frame_len,
		enum_request_id, values_frame, values_frame_len,
		values_request_id, next_sequence, &collected);
	if (ret)
		return ret;

	*ref_count_out = collected.count;
	if (ref_capacity < collected.count) {
		ret = -ERANGE;
		goto out;
	}

	for (i = 0; i < collected.count; i++) {
		u32 j;
		bool found = false;

		for (j = 0; j < layer_count; j++) {
			if (collected.layers[i] != &layers[j])
				continue;
			refs[i].layer_index = j;
			refs[i]._pad = 0;
			found = true;
			break;
		}
		if (!found) {
			ret = -EIO;
			goto out;
		}
	}

out:
	pkm_lcs_backup_referenced_layers_destroy(&collected);
	return ret;
}

long pkm_lcs_kunit_backup_layer_manifest_frame_set(
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_backup_layer_ref_view *refs, size_t ref_count,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len,
	struct pkm_lcs_backup_manifest_frame_summary *summary_out)
{
	struct pkm_lcs_layer_snapshot snapshot = {
		.layers = layers,
		.layer_count = layer_count,
		.base_metadata_present = base_metadata_present,
		.base_metadata_sd = base_metadata_sd,
		.base_metadata_sd_len = base_metadata_sd_len,
	};
	struct pkm_lcs_backup_referenced_layers referenced = { };
	struct pkm_lcs_backup_layer_manifest_frames frames = { };
	struct pkm_lcs_runtime_limits limits;
	size_t total_len = 0;
	u32 i;
	long ret = 0;

	if (!summary_out || (ref_count && (!layers || !refs)))
		return -EINVAL;
	memset(summary_out, 0, sizeof(*summary_out));
	if (ref_count > U32_MAX)
		return -EOVERFLOW;

	if (ref_count) {
		referenced.layers = kcalloc(ref_count,
					    sizeof(*referenced.layers),
					    GFP_KERNEL);
		if (!referenced.layers)
			return -ENOMEM;
		referenced.count = (u32)ref_count;
	}
	for (i = 0; i < ref_count; i++) {
		if (refs[i].layer_index >= layer_count) {
			ret = -EINVAL;
			goto out;
		}
		referenced.layers[i] = &layers[refs[i].layer_index];
	}

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_backup_alloc_layer_manifest_frames(
		&limits, &snapshot, &referenced, &frames);
	if (ret)
		goto out;

	for (i = 0; i < frames.count; i++) {
		ret = pkm_lcs_backup_manifest_frame_matches_layer(
			frames.frames[i], frames.frame_lens[i],
			referenced.layers[i]);
		if (ret)
			goto out;
		if (check_add_overflow(total_len, frames.frame_lens[i],
				       &total_len)) {
			ret = -EOVERFLOW;
			goto out;
		}
	}

	summary_out->frame_count = frames.count;
	summary_out->total_len = total_len;

out:
	pkm_lcs_backup_layer_manifest_frames_destroy(&frames);
	kfree(referenced.layers);
	return ret;
}

long pkm_lcs_kunit_backup_root_section_frames(
	const u8 key_guid[PKM_LCS_GUID_BYTES], const u8 *enum_frame,
	size_t enum_frame_len, u64 enum_request_id, const u8 *values_frame,
	size_t values_frame_len, u64 values_request_id, u64 next_sequence,
	struct pkm_lcs_backup_root_section_frame_summary *summary_out)
{
	struct pkm_lcs_backup_record_frames frames = { };
	struct pkm_lcs_backup_root_section_summary summary = { };
	struct pkm_lcs_runtime_limits limits;
	size_t total_len = 0;
	u32 i;
	long ret;

	if (!summary_out)
		return -EINVAL;
	memset(summary_out, 0, sizeof(*summary_out));

	pkm_lcs_key_fd_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_backup_alloc_root_section_frames(
		&limits, key_guid, enum_frame, enum_frame_len,
		enum_request_id, values_frame, values_frame_len,
		values_request_id, next_sequence, &frames, &summary);
	if (ret)
		return ret;

	for (i = 0; i < frames.count; i++) {
		if (check_add_overflow(total_len, frames.frame_lens[i],
				       &total_len)) {
			ret = -EOVERFLOW;
			goto out;
		}
	}

	summary_out->frame_count = frames.count;
	summary_out->hidden_path_count = summary.hidden_path_count;
	summary_out->value_count = summary.value_count;
	summary_out->blanket_count = summary.blanket_count;
	summary_out->needs_child_traversal = summary.needs_child_traversal ? 1 :
									  0;
	summary_out->total_len = total_len;

out:
	pkm_lcs_backup_record_frames_destroy(&frames);
	if (ret)
		memset(summary_out, 0, sizeof(*summary_out));
	return ret;
}

long pkm_lcs_kunit_key_fd_restore_for_token(
	int fd, const void *token, const struct reg_restore_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_restore_from_args_for_token(key_fd, token, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_flush(int fd)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_flush(key_fd);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_notify(int fd, const struct reg_notify_args *args)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	ret = lcs_rust_key_fd_fixed_ioctl_access_gate(
		key_fd->granted_access, REG_IOC_NOTIFY_NR);
	if (!ret)
		ret = pkm_lcs_key_fd_notify_from_args(key_fd, args);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_queue_watch_event(int fd, u32 event_type,
					    const u8 *record, u32 record_len)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;
	ret = pkm_lcs_key_fd_queue_watch_record(key_fd, event_type, record,
					       record_len);
	fdput(held);
	return ret;
}

static bool pkm_lcs_kunit_key_fd_copyout_write(void *ctx, void __user *dst,
					       const void *src, size_t len)
{
	(void)ctx;

	if (!dst)
		return false;
	memcpy((void *)(unsigned long)dst, src, len);
	return true;
}

ssize_t pkm_lcs_kunit_key_fd_read(int fd, u8 *buf, size_t count,
				  bool nonblocking)
{
	static const struct pkm_lcs_key_fd_copyout_ops ops = {
		.write = pkm_lcs_kunit_key_fd_copyout_write,
	};
	struct file *file;
	struct fd held;
	ssize_t ret;

	held = fdget(fd);
	file = fd_file(held);
	if (!file)
		return -EBADF;
	if (file->f_op != &pkm_lcs_key_fd_fops) {
		fdput(held);
		return -EINVAL;
	}

	ret = pkm_lcs_key_fd_read_file_with_ops(
		file, (char __user *)(unsigned long)buf, count, nonblocking,
		&ops);
	fdput(held);
	return ret;
}

__poll_t pkm_lcs_kunit_key_fd_poll(int fd)
{
	struct file *file;
	struct fd held;
	__poll_t ret;

	held = fdget(fd);
	file = fd_file(held);
	if (!file)
		return EPOLLERR | EPOLLHUP;
	if (file->f_op != &pkm_lcs_key_fd_fops) {
		fdput(held);
		return EPOLLERR | EPOLLHUP;
	}

	ret = pkm_lcs_key_fd_poll(file, NULL);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_key_fd_watch_registry_snapshot(
	int fd, struct pkm_lcs_key_fd_watch_registry_snapshot *out)
{
	struct pkm_lcs_subtree_watch_entry *subtree;
	struct pkm_lcs_watch_registry_entry *entry;
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	u32 hash;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	held = fdget(fd);
	if (!fd_file(held))
		return -EBADF;
	if (fd_file(held)->f_op != &pkm_lcs_key_fd_fops) {
		fdput(held);
		return -EINVAL;
	}
	key_fd = fd_file(held)->private_data;
	if (!key_fd) {
		fdput(held);
		return -EINVAL;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	hash = pkm_lcs_guid_hash(key_fd->key_guid);
	hash_for_each_possible(pkm_lcs_watch_map, entry, link, hash) {
		if (entry->kind == PKM_LCS_WATCH_REGISTRY_KEY_FD &&
		    pkm_lcs_guid_equal(entry->guid, key_fd->key_guid))
			out->direct_watchers++;
	}
	subtree = pkm_lcs_subtree_watch_find_locked(key_fd->key_guid);
	if (subtree)
		out->subtree_watchers = subtree->refcount;
	mutex_unlock(&pkm_lcs_watch_registry_lock);

	fdput(held);
	return 0;
}

long pkm_lcs_kunit_internal_self_watch_snapshot(
	struct pkm_lcs_internal_self_watch_snapshot *out)
{
	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	mutex_lock(&pkm_lcs_watch_registry_lock);
	out->source_id = pkm_lcs_internal_self_watch.source_id;
	out->watch_count = pkm_lcs_internal_self_watch.watch_count;
	out->mode = pkm_lcs_internal_self_watch.mode;
	if (pkm_lcs_internal_self_watch.registry.registry.linked)
		memcpy(out->registry_guid,
		       pkm_lcs_internal_self_watch.registry.registry.guid,
		       sizeof(out->registry_guid));
	if (pkm_lcs_internal_self_watch.layers.registry.linked)
		memcpy(out->layers_guid,
		       pkm_lcs_internal_self_watch.layers.registry.guid,
		       sizeof(out->layers_guid));
	if (pkm_lcs_internal_self_watch.fallback.registry.linked)
		memcpy(out->fallback_guid,
		       pkm_lcs_internal_self_watch.fallback.registry.guid,
		       sizeof(out->fallback_guid));
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return 0;
}
#endif

static void pkm_lcs_key_fd_copy_component_snapshot(char *dst, u32 *len_out,
						   const char *src)
{
	size_t len = strlen(src);
	size_t copy_len;

	if (len_out)
		*len_out = len > U32_MAX ? U32_MAX : (u32)len;

	copy_len = min_t(size_t, len,
			 PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES - 1U);
	memcpy(dst, src, copy_len);
	dst[copy_len] = '\0';
}

long pkm_lcs_key_fd_snapshot(int fd, struct pkm_lcs_key_fd_snapshot *out)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	u32 last;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	held = fdget(fd);
	if (!fd_file(held))
		return -EBADF;
	if (fd_file(held)->f_op != &pkm_lcs_key_fd_fops) {
		fdput(held);
		return -EINVAL;
	}

	key_fd = fd_file(held)->private_data;
	if (!key_fd || !key_fd->path_component_count) {
		fdput(held);
		return -EINVAL;
	}

	last = key_fd->path_component_count - 1U;
	out->source_id = key_fd->source_id;
	out->granted_access = key_fd->granted_access;
	out->path_component_count = key_fd->path_component_count;
	memcpy(out->key_guid, key_fd->key_guid, sizeof(out->key_guid));
	memcpy(out->first_ancestor_guid, key_fd->ancestor_guids[0],
	       sizeof(out->first_ancestor_guid));
	memcpy(out->last_ancestor_guid, key_fd->ancestor_guids[last],
	       sizeof(out->last_ancestor_guid));
	pkm_lcs_key_fd_copy_component_snapshot(out->first_component,
					       &out->first_component_len,
					       key_fd->resolved_path[0]);
	pkm_lcs_key_fd_copy_component_snapshot(out->last_component,
					       &out->last_component_len,
					       key_fd->resolved_path[last]);
	mutex_lock(&key_fd->watch_lock);
	out->orphaned = key_fd->orphaned;
	out->watch_armed = key_fd->watch_armed;
	out->watch_filter = key_fd->watch_filter;
	out->watch_pending_events = key_fd->watch_pending_events;
	out->watch_subtree = key_fd->watch_subtree;
	mutex_unlock(&key_fd->watch_lock);

	fdput(held);
	return 0;
}
