/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_KEY_FD_H
#define _SECURITY_PKM_LCS_KEY_FD_H

#include <linux/poll.h>
#include <linux/types.h>

#include <pkm/lcs.h>

#define PKM_LCS_GUID_BYTES 16U
#define PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES 32U
#define PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT 256U

struct pkm_lcs_usercopy_ops;

struct pkm_lcs_key_fd_publish_input {
	u32 source_id;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u32 granted_access;
	const char * const *resolved_path;
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	u32 path_component_count;
};

struct pkm_lcs_key_fd_snapshot {
	u32 source_id;
	u32 granted_access;
	u32 path_component_count;
	u32 first_component_len;
	u32 last_component_len;
	u32 watch_filter;
	u32 watch_pending_events;
	bool orphaned;
	bool watch_armed;
	bool watch_subtree;
	u8 _pad;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u8 first_ancestor_guid[PKM_LCS_GUID_BYTES];
	u8 last_ancestor_guid[PKM_LCS_GUID_BYTES];
	char first_component[PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES];
	char last_component[PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES];
};

struct pkm_lcs_key_fd_relative_base {
	u32 source_id;
	u32 parent_depth;
	bool orphaned;
	u8 _pad[3];
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u8 root_guid[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_key_fd_parent_snapshot {
	u32 source_id;
	u32 path_component_count;
	bool orphaned;
	u8 _pad[3];
	u8 key_guid[PKM_LCS_GUID_BYTES];
	char **resolved_path;
	u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_key_fd_watch_registry_snapshot {
	u32 direct_watchers;
	u32 subtree_watchers;
};

struct pkm_lcs_watch_dispatch_input {
	int mutation_fd;
	u32 event_type;
	const u8 *name;
	u32 name_len;
};

struct pkm_lcs_watch_dispatch_context {
	const u8 *changed_key_guid;
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	const char * const *resolved_path;
	u32 path_component_count;
	u32 event_type;
	const u8 *name;
	u32 name_len;
};

struct pkm_lcs_set_security_merge_result {
	u8 *merged_sd;
	size_t merged_sd_len;
};

long pkm_lcs_key_fd_publish(const struct pkm_lcs_key_fd_publish_input *input);
long pkm_lcs_key_fd_snapshot(int fd, struct pkm_lcs_key_fd_snapshot *out);
long pkm_lcs_key_fd_check_fixed_ioctl_access(int fd, unsigned int cmd);
long pkm_lcs_key_fd_check_security_ioctl_access(int fd, unsigned int cmd,
						u32 security_info);
long pkm_lcs_key_fd_plan_set_security_merge(
	const u8 *existing_sd, size_t existing_sd_len,
	const u8 *input_sd, size_t input_sd_len, u32 security_info,
	struct pkm_lcs_set_security_merge_result *out);
void pkm_lcs_set_security_merge_result_destroy(
	struct pkm_lcs_set_security_merge_result *result);
long pkm_lcs_key_fd_relative_base(int fd,
				  struct pkm_lcs_key_fd_relative_base *out);
long pkm_lcs_key_fd_parent_snapshot(int fd,
				    struct pkm_lcs_key_fd_parent_snapshot *out);
void pkm_lcs_key_fd_parent_snapshot_destroy(
	struct pkm_lcs_key_fd_parent_snapshot *snapshot);
long pkm_lcs_key_fd_dispatch_watch_event_context(
	const struct pkm_lcs_watch_dispatch_context *context);
long pkm_lcs_key_fd_dispatch_watch_event_context_batch(
	const struct pkm_lcs_watch_dispatch_context *contexts,
	u32 context_count);
long pkm_lcs_key_fd_dispatch_watch_event(
	const struct pkm_lcs_watch_dispatch_input *input);

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_key_fd_set_orphaned(int fd, bool orphaned);
long pkm_lcs_kunit_key_fd_get_security(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_get_security_args *args);
long pkm_lcs_kunit_key_fd_set_security(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_security_args *args);
long pkm_lcs_kunit_key_fd_notify(int fd, const struct reg_notify_args *args);
long pkm_lcs_kunit_key_fd_queue_watch_event(int fd, u32 event_type,
					    const u8 *record, u32 record_len);
ssize_t pkm_lcs_kunit_key_fd_read(int fd, u8 *buf, size_t count,
				  bool nonblocking);
__poll_t pkm_lcs_kunit_key_fd_poll(int fd);
long pkm_lcs_kunit_key_fd_watch_registry_snapshot(
	int fd, struct pkm_lcs_key_fd_watch_registry_snapshot *out);
#endif

#endif /* _SECURITY_PKM_LCS_KEY_FD_H */
