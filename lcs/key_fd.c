// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS key-fd carrier.
 *
 * PSD-005 key fds are capabilities: open-time AccessCheck grants are captured
 * once on an anonymous fd and later operations consult that stored mask.
 */

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

#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"
#include "transaction_fd.h"

#define PKM_LCS_MAX_SD_BYTES 65535U
#define PKM_LCS_WATCH_NOTIFY_ACTION_ARM 1U
#define PKM_LCS_WATCH_NOTIFY_ACTION_DISARM 2U
#define PKM_LCS_WATCH_EVENT_HEADER_LEN 8U
#define PKM_LCS_WATCH_REGISTRY_BITS 8U

struct pkm_lcs_key_fd_string_view {
	const u8 *bytes;
	u32 len;
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

struct pkm_lcs_key_fd {
	u32 source_id;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u32 granted_access;
	u32 path_component_count;
	char **resolved_path;
	u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	struct mutex watch_lock;
	wait_queue_head_t watch_wait;
	struct list_head watch_events;
	struct hlist_node watch_registry_node;
	u32 watch_filter;
	u32 watch_pending_events;
	bool watch_has_overflow;
	bool watch_subtree;
	bool watch_registry_linked;
	bool watch_subtree_registered;
	bool orphaned;
	bool watch_armed;
};

struct pkm_lcs_get_security_result {
	u8 *sd;
	size_t sd_len;
};

static const struct file_operations pkm_lcs_key_fd_fops;
static DEFINE_MUTEX(pkm_lcs_watch_registry_lock);
static DEFINE_HASHTABLE(pkm_lcs_watch_map, PKM_LCS_WATCH_REGISTRY_BITS);
static DEFINE_HASHTABLE(pkm_lcs_subtree_watch_set,
			PKM_LCS_WATCH_REGISTRY_BITS);

extern int lcs_rust_validate_key_fd_open_view(
	const u8 *key_guid, u32 granted_access,
	const struct pkm_lcs_key_fd_string_view *path_components,
	size_t path_component_count,
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES], size_t ancestor_count);
extern int lcs_rust_key_fd_fixed_ioctl_access_gate(u32 granted_access,
						   u32 ioctl_number);
extern int lcs_rust_key_fd_security_ioctl_access_gate(u32 granted_access,
						      u32 ioctl_number,
						      u32 security_info);
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

static void pkm_lcs_get_security_result_destroy(
	struct pkm_lcs_get_security_result *result);
static long pkm_lcs_key_fd_plan_get_security(
	const u8 *existing_sd, size_t existing_sd_len, u32 security_info,
	struct pkm_lcs_get_security_result *out);

static u32 pkm_lcs_guid_hash(const u8 guid[PKM_LCS_GUID_BYTES])
{
	return jhash(guid, PKM_LCS_GUID_BYTES, 0);
}

static bool pkm_lcs_guid_equal(const u8 lhs[PKM_LCS_GUID_BYTES],
			       const u8 rhs[PKM_LCS_GUID_BYTES])
{
	return memcmp(lhs, rhs, PKM_LCS_GUID_BYTES) == 0;
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

static void pkm_lcs_key_fd_watch_map_link_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	if (key_fd->watch_registry_linked)
		return;

	hash_add(pkm_lcs_watch_map, &key_fd->watch_registry_node,
		 pkm_lcs_guid_hash(key_fd->key_guid));
	key_fd->watch_registry_linked = true;
}

static void pkm_lcs_key_fd_watch_map_unlink_locked(
	struct pkm_lcs_key_fd *key_fd)
{
	if (!key_fd->watch_registry_linked)
		return;

	hash_del(&key_fd->watch_registry_node);
	INIT_HLIST_NODE(&key_fd->watch_registry_node);
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

	if (!record || record_len < PKM_LCS_WATCH_EVENT_HEADER_LEN)
		return ERR_PTR(-EINVAL);
	if (get_unaligned_le32(record) != record_len ||
	    get_unaligned_le16(record + 4) != event_type)
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
	u8 record[PKM_LCS_WATCH_EVENT_HEADER_LEN] = { };

	put_unaligned_le32(PKM_LCS_WATCH_EVENT_HEADER_LEN, record);
	put_unaligned_le16(REG_WATCH_OVERFLOW, record + 4);
	put_unaligned_le16(0, record + 6);
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
	if (record_len < PKM_LCS_WATCH_EVENT_HEADER_LEN)
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

static long pkm_lcs_key_fd_queue_watch_event_locked(
	struct pkm_lcs_key_fd *key_fd,
	struct pkm_lcs_key_fd_watch_event *event)
{
	struct pkm_lcs_key_fd_watch_event *queued_event = event;

	if (!key_fd || !event)
		return -EINVAL;

	if (event->event_type == REG_WATCH_OVERFLOW &&
	    key_fd->watch_has_overflow) {
		pkm_lcs_key_fd_watch_event_free(event);
		return 0;
	}

	if (key_fd->watch_pending_events >= PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT) {
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
	size_t len;
	u32 i;
	long ret;

	if (!views_out)
		return -EINVAL;
	*views_out = NULL;

	if (!input || !input->source_id || !input->path_component_count ||
	    !input->resolved_path || !input->ancestor_guids)
		return -EINVAL;

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
		input->path_component_count);
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
	INIT_HLIST_NODE(&key_fd->watch_registry_node);

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
	key_fd->granted_access = input->granted_access;
	key_fd->path_component_count = input->path_component_count;
	key_fd->orphaned = false;
	key_fd->watch_armed = false;

	*key_fd_out = key_fd;
	return 0;

out_nomem:
	pkm_lcs_key_fd_free(key_fd);
	return -ENOMEM;
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

	fd = anon_inode_getfd("lcs-key", &pkm_lcs_key_fd_fops, key_fd,
			      O_CLOEXEC);
	if (fd < 0) {
		pkm_lcs_key_fd_free(key_fd);
		return fd;
	}

	return fd;
}

static long pkm_lcs_key_fd_notify_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct reg_notify_args *args)
{
	struct pkm_lcs_watch_notify_plan_copy plan;
	long ret;

	if (!key_fd || !args)
		return -EINVAL;

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
	ret = pkm_lcs_key_fd_queue_watch_event_locked(key_fd, event);
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
	struct pkm_lcs_source_response_frame *frame, const u8 **sd_out,
	size_t *sd_len_out)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	long ret;

	if (!key_fd || !frame || !sd_out || !sd_len_out)
		return -EINVAL;
	*sd_out = NULL;
	*sd_len_out = 0;

	pkm_lcs_source_response_frame_init(frame);
	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
		key_fd->source_id, txn_id, key_fd->key_guid,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, frame, &response, NULL);
	if (ret)
		return ret;

	ret = pkm_lcs_rsi_materialize_read_key_response(
		frame->data, frame->len, response.request_id, &read_key);
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
	struct pkm_lcs_key_fd *key_fd)
{
	struct pkm_lcs_watch_dispatch_context context = { };

	context.changed_key_guid = key_fd->key_guid;
	context.ancestor_guids =
		(const u8 (*)[PKM_LCS_GUID_BYTES])key_fd->ancestor_guids;
	context.resolved_path = (const char * const *)key_fd->resolved_path;
	context.path_component_count = key_fd->path_component_count;
	context.event_type = REG_WATCH_SD_CHANGED;

	(void)pkm_lcs_key_fd_dispatch_watch_event_context(&context);
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

	ret = pkm_lcs_key_fd_read_existing_sd(key_fd, 0, &existing_frame,
					      &existing_sd, &existing_sd_len);
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

static long pkm_lcs_key_fd_set_security_from_args(
	struct pkm_lcs_key_fd *key_fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_security_args *args)
{
	struct pkm_lcs_set_security_merge_result merge = { };
	struct pkm_lcs_source_response_frame existing_frame = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_set_security_log_input log_input = { };
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

	ret = pkm_lcs_key_fd_read_existing_sd(key_fd, txn_id, &existing_frame,
					      &existing_sd, &existing_sd_len);
	if (ret)
		goto out_cancel_mutation;

	ret = pkm_lcs_key_fd_plan_set_security_merge(
		existing_sd, existing_sd_len, input_sd, input_sd_len,
		args->security_info, &merge);
	if (ret)
		goto out_cancel_mutation;

	last_write_time = (u64)ktime_get_real_ns();
	ret = pkm_lcs_source_write_key_round_trip_timeout(
		key_fd->source_id, txn_id, key_fd->key_guid, merge.merged_sd,
		merge.merged_sd_len, last_write_time,
		PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, NULL, NULL);
	if (ret)
		goto out_cancel_merge;

	if (args->txn_fd >= 0) {
		ret = pkm_lcs_transaction_fd_commit_mutation(&mutation);
		goto out_merge;
	}

	ret = pkm_lcs_source_record_transaction_generation(
		key_fd->source_id, key_fd->ancestor_guids[0], &generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(key_fd->source_id);
		ret = -EIO;
		goto out_merge;
	}

	pkm_lcs_key_fd_publish_set_security_effects(key_fd);

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

static long pkm_lcs_key_fd_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct pkm_lcs_key_fd *key_fd;
	struct reg_notify_args notify_args;
	struct reg_get_security_args get_security_args;
	struct reg_set_security_args set_security_args;
	long ret;

	if (!file)
		return -EBADF;
	key_fd = file->private_data;
	if (!key_fd)
		return -EINVAL;

	switch (cmd) {
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
	u32 path_component_count, bool *queued_out)
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

	ret = pkm_lcs_key_fd_queue_watch_event_locked(watcher, event);
	if (!ret)
		*queued_out = true;
	mutex_unlock(&watcher->watch_lock);
	return ret;
}

static long pkm_lcs_key_fd_dispatch_to_watcher_locked(
	struct pkm_lcs_key_fd *watcher, u32 event_type, const u8 *name,
	u32 name_len, bool subtree_record,
	const struct pkm_lcs_key_fd_string_view *path_components,
	u32 path_component_count)
{
	bool queued = false;
	long ret;

	ret = pkm_lcs_key_fd_queue_dispatch_event_locked(
		watcher, event_type, name, name_len, subtree_record,
		path_components, path_component_count, &queued);
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

static long pkm_lcs_key_fd_dispatch_watch_event_context_locked(
	const struct pkm_lcs_watch_dispatch_context *context)
{
	struct pkm_lcs_key_fd_string_view *path_views = NULL;
	struct pkm_lcs_subtree_watch_entry *subtree;
	struct pkm_lcs_key_fd *watcher;
	long ret = 0;
	u32 changed_index;
	u32 hash;
	u32 i;

	hash = pkm_lcs_guid_hash(context->changed_key_guid);
	hash_for_each_possible(pkm_lcs_watch_map, watcher,
			       watch_registry_node, hash) {
		if (!pkm_lcs_guid_equal(watcher->key_guid,
					context->changed_key_guid))
			continue;
		ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
			watcher, context->event_type, context->name,
			context->name_len, watcher->watch_subtree, NULL, 0);
		if (ret)
			goto out_unlock;
	}

	changed_index = context->path_component_count - 1U;
	for (i = changed_index; i > 0; i--) {
		const u8 *ancestor_guid = context->ancestor_guids[i - 1U];
		u32 path_count;

		if (pkm_lcs_guid_equal(ancestor_guid, context->changed_key_guid))
			continue;
		subtree = pkm_lcs_subtree_watch_find_locked(ancestor_guid);
		if (!subtree)
			continue;

		path_count = changed_index - (i - 1U);
		ret = pkm_lcs_key_fd_path_views_from_components(
			context->resolved_path, context->path_component_count, i,
			path_count, &path_views);
		if (ret)
			goto out_unlock;

		hash = pkm_lcs_guid_hash(ancestor_guid);
		hash_for_each_possible(pkm_lcs_watch_map, watcher,
				       watch_registry_node, hash) {
			if (!pkm_lcs_guid_equal(watcher->key_guid,
						ancestor_guid) ||
			    !watcher->watch_subtree)
				continue;
			ret = pkm_lcs_key_fd_dispatch_to_watcher_locked(
				watcher, context->event_type, context->name,
				context->name_len, true, path_views, path_count);
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

long pkm_lcs_key_fd_dispatch_watch_event_context(
	const struct pkm_lcs_watch_dispatch_context *context)
{
	long ret;

	ret = pkm_lcs_key_fd_validate_dispatch_context(context);
	if (ret)
		return ret;

	mutex_lock(&pkm_lcs_watch_registry_lock);
	ret = pkm_lcs_key_fd_dispatch_watch_event_context_locked(context);
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return ret;
}

long pkm_lcs_key_fd_dispatch_watch_event_context_batch(
	const struct pkm_lcs_watch_dispatch_context *contexts, u32 context_count)
{
	long ret = 0;
	u32 i;

	if (!context_count)
		return 0;
	if (!contexts)
		return -EINVAL;

	for (i = 0; i < context_count; i++) {
		ret = pkm_lcs_key_fd_validate_dispatch_context(&contexts[i]);
		if (ret)
			return ret;
	}

	mutex_lock(&pkm_lcs_watch_registry_lock);
	for (i = 0; i < context_count; i++) {
		ret = pkm_lcs_key_fd_dispatch_watch_event_context_locked(
			&contexts[i]);
		if (ret)
			break;
	}
	mutex_unlock(&pkm_lcs_watch_registry_lock);
	return ret;
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
	struct pkm_lcs_key_fd *cursor;
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
	hash_for_each_possible(pkm_lcs_watch_map, cursor,
			       watch_registry_node, hash) {
		if (pkm_lcs_guid_equal(cursor->key_guid, key_fd->key_guid))
			out->direct_watchers++;
	}
	subtree = pkm_lcs_subtree_watch_find_locked(key_fd->key_guid);
	if (subtree)
		out->subtree_watchers = subtree->refcount;
	mutex_unlock(&pkm_lcs_watch_registry_lock);

	fdput(held);
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
