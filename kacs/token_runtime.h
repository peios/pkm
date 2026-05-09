/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TOKEN_RUNTIME_H
#define _SECURITY_PKM_KACS_TOKEN_RUNTIME_H

#include <linux/types.h>

#include "access_check.h"

struct file;
struct path;
struct task_struct;

int pkm_kacs_open_by_handle_at(void);

#define KACS_PROCESS_TERMINATE 0x0001U
#define KACS_PROCESS_SIGNAL 0x0002U
#define KACS_PROCESS_VM_READ 0x0010U
#define KACS_PROCESS_VM_WRITE 0x0020U
#define KACS_PROCESS_DUP_HANDLE 0x0040U
#define KACS_PROCESS_SET_INFORMATION 0x0200U
#define KACS_PROCESS_QUERY_INFORMATION 0x0400U
#define KACS_PROCESS_SUSPEND_RESUME 0x0800U
#define KACS_PROCESS_QUERY_LIMITED 0x1000U

#define KACS_BACKUP_INTENT 0x00000001U
#define KACS_RESTORE_INTENT 0x00000002U

#define PKM_KACS_MOUNT_POLICY_UNMANAGED 1U
#define PKM_KACS_MOUNT_POLICY_DENY_MISSING 2U
#define PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL 3U
#define PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT 4U

#define KACS_FILE_SUPERSEDE 0U
#define KACS_FILE_OPEN 1U
#define KACS_FILE_CREATE 2U
#define KACS_FILE_OPEN_IF 3U
#define KACS_FILE_OVERWRITE 4U
#define KACS_FILE_OVERWRITE_IF 5U

#define KACS_CREATE_OPT_DIRECTORY 0x0001U
#define KACS_CREATE_OPT_DELETE_ON_CLOSE 0x0002U

#define PKM_KACS_KUNIT_FILE_METADATA_GETATTR 1U
#define PKM_KACS_KUNIT_FILE_METADATA_STATFS 2U
#define PKM_KACS_KUNIT_FILE_METADATA_CHMOD 3U
#define PKM_KACS_KUNIT_FILE_METADATA_CHOWN 4U
#define PKM_KACS_KUNIT_FILE_METADATA_UTIMENS 5U
#define PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_GET 6U
#define PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_SET 7U
#define PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET 8U
#define PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET 9U
#define PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE 10U
#define PKM_KACS_KUNIT_FILE_METADATA_XATTR_LIST 11U
#define PKM_KACS_KUNIT_PATH_METADATA_GETATTR 12U
#define PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHMOD 13U
#define PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHOWN 14U
#define PKM_KACS_KUNIT_PATH_METADATA_SETATTR_UTIMENS 15U
#define PKM_KACS_KUNIT_PATH_METADATA_SETATTR_TRUNCATE 16U
#define PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_GET 17U
#define PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_SET 18U
#define PKM_KACS_KUNIT_PATH_METADATA_XATTR_GET 19U
#define PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET 20U
#define PKM_KACS_KUNIT_PATH_METADATA_XATTR_REMOVE 21U
#define PKM_KACS_KUNIT_PATH_METADATA_XATTR_LIST 22U
#define PKM_KACS_KUNIT_PATH_METADATA_ACCESS 23U

#define PKM_KACS_KUNIT_NAMESPACE_CREATE_FILE 1U
#define PKM_KACS_KUNIT_NAMESPACE_MKDIR 2U
#define PKM_KACS_KUNIT_NAMESPACE_MKNOD 3U
#define PKM_KACS_KUNIT_NAMESPACE_SYMLINK 4U
#define PKM_KACS_KUNIT_NAMESPACE_LINK 5U
#define PKM_KACS_KUNIT_NAMESPACE_UNLINK 6U
#define PKM_KACS_KUNIT_NAMESPACE_RMDIR 7U
#define PKM_KACS_KUNIT_NAMESPACE_RENAME 8U
#define PKM_KACS_KUNIT_NAMESPACE_READLINK 9U

#define KACS_STATUS_OPENED 1U
#define KACS_STATUS_CREATED 2U
#define KACS_STATUS_OVERWRITTEN 3U
#define KACS_STATUS_SUPERSEDED 4U

#define KACS_MIT_WXP 0x001U
#define KACS_MIT_TLP 0x002U
#define KACS_MIT_LSV 0x004U
#define KACS_MIT_CFI 0x008U
#define KACS_MIT_UI_ACCESS 0x010U
#define KACS_MIT_NO_CHILD 0x020U
#define KACS_MIT_CFIF 0x040U
#define KACS_MIT_CFIB 0x080U
#define KACS_MIT_PIE 0x100U
#define KACS_MIT_SML 0x200U
#define KACS_MIT_ALL 0x3FFU
#define PKM_KACS_KUNIT_SIGNING_SOURCE_NONE 0U
#define PKM_KACS_KUNIT_SIGNING_SOURCE_ELF 1U
#define PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR 2U

struct pkm_kacs_boot_group_view {
	const u8 *sid_ptr;
	size_t sid_len;
	u32 attributes;
};

struct pkm_kacs_boot_snapshot {
	const void *token_ptr;
	const void *session_ptr;
	u64 session_id;
	u64 auth_id;
	u64 token_id;
	u64 modified_id;
	u32 logon_type;
	const u8 *auth_pkg_ptr;
	size_t auth_pkg_len;
	const u8 *user_sid_ptr;
	size_t user_sid_len;
	const u8 *logon_sid_ptr;
	size_t logon_sid_len;
	const struct pkm_kacs_boot_group_view *groups_ptr;
	u32 group_count;
	u32 owner_sid_index;
	u32 primary_group_index;
	const u8 *default_dacl_ptr;
	size_t default_dacl_len;
	u64 privileges_present;
	u64 privileges_enabled;
	u64 privileges_enabled_by_default;
	u64 privileges_used;
	u32 integrity_level;
	u32 token_type;
	u32 impersonation_level;
	u32 mandatory_policy;
	u32 interactive_session_id;
	u32 projected_uid;
	u32 projected_gid;
	u32 audit_policy;
	u32 elevation_type;
};

struct pkm_kacs_session_snapshot {
	const void *session_ptr;
	u64 session_id;
	u64 created_at;
	u32 logon_type;
	const u8 *auth_pkg_ptr;
	size_t auth_pkg_len;
	const u8 *user_sid_ptr;
	size_t user_sid_len;
	const u8 *logon_sid_ptr;
	size_t logon_sid_len;
};

struct pkm_kacs_group_adjust_entry {
	u32 index;
	u32 enable;
};

struct pkm_kacs_priv_adjust_entry {
	u32 luid;
	u32 attributes;
};

struct kacs_open_how {
	u32 desired_access;
	u32 create_disposition;
	u32 create_options;
	u32 flags;
	u64 sd_ptr;
	u32 sd_len;
	u32 __pad;
};

struct pkm_kacs_kunit_process_state_view {
	const void *state_ptr;
	const void *process_sd_ptr;
	size_t process_sd_len;
	const void *rate_bucket_ptr;
	u32 pip_type;
	u32 pip_trust;
	u32 mitigation_bits;
};

struct pkm_kacs_kunit_signing_probe {
	u32 source;
	u8 signature[64];
	u8 hash[32];
};

struct pkm_kacs_kunit_signing_reader_args {
	const u8 *file_bytes;
	size_t file_len;
	const u8 *xattr_sig;
	size_t xattr_sig_len;
	size_t final_file_len;
	u32 use_final_file_len;
	u32 fail_reads;
	u32 fail_xattr;
};

struct pkm_kacs_kunit_signing_key_entry {
	u8 public_key[32];
	u32 pip_type;
	u32 pip_trust;
};

struct pkm_kacs_kunit_signing_verify_out {
	u32 verified;
	u32 pip_type;
	u32 pip_trust;
};

struct pkm_kacs_kunit_process_token_open_args {
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 access_mask;
	u32 self_target;
};

struct pkm_kacs_kunit_process_signal_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	int sig;
	u32 kernel_originated;
};

struct pkm_kacs_kunit_process_ptrace_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 mode;
};

struct pkm_kacs_kunit_process_setinfo_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 self_target;
};

struct pkm_kacs_kunit_process_affinity_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 same_process;
};

struct pkm_kacs_kunit_process_prlimit_check_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 self_target;
	u32 flags;
};

struct pkm_kacs_kunit_process_sd_get_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 self_target;
	u32 security_info;
};

struct pkm_kacs_kunit_process_sd_set_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	const u8 *input_sd_ptr;
	size_t input_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 self_target;
	u32 security_info;
};

#define PKM_KACS_KUNIT_FILE_SD_VALID 1U
#define PKM_KACS_KUNIT_FILE_SD_MISSING 2U
#define PKM_KACS_KUNIT_FILE_SD_CORRUPT 3U

struct pkm_kacs_kunit_file_sd_get_args {
	const void *subject_token;
	const u8 *target_file_sd_ptr;
	size_t target_file_sd_len;
	u32 target_file_sd_state;
	u32 security_info;
	u32 cached_granted_access;
	u32 file_mode;
	u32 file_flags;
	u32 mount_policy_override;
	u64 mount_magic;
	u16 inode_mode;
	u16 _reserved;
};

struct pkm_kacs_kunit_file_sd_set_args {
	const void *subject_token;
	const u8 *target_file_sd_ptr;
	size_t target_file_sd_len;
	u32 target_file_sd_state;
	const u8 *input_sd_ptr;
	size_t input_sd_len;
	u32 security_info;
	u32 cached_granted_access;
	u32 file_mode;
	u32 file_flags;
	u32 mount_policy_override;
	u64 mount_magic;
	u16 inode_mode;
	u16 _reserved;
};

struct pkm_kacs_kunit_file_open_args {
	const void *subject_token;
	const u8 *target_file_sd_ptr;
	size_t target_file_sd_len;
	u32 target_file_sd_state;
	u32 file_mode;
	u32 file_flags;
	u32 mount_policy_override;
	u64 mount_magic;
	u16 inode_mode;
	u16 _reserved;
};

struct pkm_kacs_kunit_native_open_args {
	const void *subject_token;
	const u8 *target_file_sd_ptr;
	size_t target_file_sd_len;
	u32 target_file_sd_state;
	const u8 *parent_file_sd_ptr;
	size_t parent_file_sd_len;
	u32 parent_file_sd_state;
	const u8 *input_sd_ptr;
	size_t input_sd_len;
	u32 desired_access;
	u32 create_disposition;
	u32 create_options;
	u32 flags;
	u32 mount_policy_override;
	u64 mount_magic;
	u16 inode_mode;
	u16 _reserved;
};

struct pkm_kacs_kunit_native_create_args {
	const void *subject_token;
	const u8 *parent_file_sd_ptr;
	size_t parent_file_sd_len;
	u32 parent_file_sd_state;
	const u8 *creator_sd_ptr;
	size_t creator_sd_len;
	u32 desired_access;
	u32 create_disposition;
	u32 create_options;
	u32 flags;
	u32 mount_policy_override;
	u64 mount_magic;
};

struct pkm_kacs_kunit_namespace_args {
	const void *subject_token;
	const u8 *source_sd_ptr;
	size_t source_sd_len;
	u32 source_sd_state;
	const u8 *old_parent_sd_ptr;
	size_t old_parent_sd_len;
	u32 old_parent_sd_state;
	const u8 *new_parent_sd_ptr;
	size_t new_parent_sd_len;
	u32 new_parent_sd_state;
	const u8 *target_sd_ptr;
	size_t target_sd_len;
	u32 target_sd_state;
	u32 op;
	u32 mount_policy_override;
	u64 mount_magic;
	u16 source_mode;
	u16 target_mode;
	u32 target_mode_set;
};

struct pkm_kacs_kunit_delete_on_close_result {
	u32 granted_access;
	u32 status;
	long reopen_result;
	u32 pending_before_release;
	u32 pending_after_release;
	u32 unlink_calls;
};

struct pkm_kacs_kunit_missing_file_sd_query_args {
	const void *subject_token;
	const u8 *template_sd_ptr;
	size_t template_sd_len;
	u32 mount_policy;
	u32 security_info;
	u16 mode;
};

struct pkm_kacs_kunit_exec_setid_view {
	u32 uid;
	u32 euid;
	u32 suid;
	u32 fsuid;
	u32 gid;
	u32 egid;
	u32 sgid;
	u32 fsgid;
	u32 projected_fsuid;
	u32 projected_fsgid;
};

struct pkm_kacs_kunit_exec_new_process_min_args {
	const void *subject_token;
	const void *primary_token;
	const u8 *target_file_sd_ptr;
	size_t target_file_sd_len;
	u32 target_file_sd_state;
	u32 mount_policy_override;
	u64 mount_magic;
};

struct pkm_kacs_kunit_set_psb_args {
	const void *subject_token;
	const u8 *target_process_sd_ptr;
	size_t target_process_sd_len;
	u32 caller_pip_type;
	u32 caller_pip_trust;
	u32 target_pip_type;
	u32 target_pip_trust;
	u32 initial_mitigation_bits;
	u32 requested_mitigations;
	u32 self_target;
	u32 ibt_supported;
	u32 shstk_supported;
};

struct pkm_kacs_kunit_socket_view {
	const void *peer_token;
	const void *socket_sd_ptr;
	size_t socket_sd_len;
	u32 max_impersonation;
};

const void *pkm_kacs_current_effective_token_ptr(void);
const void *pkm_kacs_current_primary_token_ptr(void);
const void *pkm_kacs_boot_system_token_ptr(void);
void *pkm_kacs_zalloc(size_t size);
void pkm_kacs_free(void *ptr);

int pkm_kacs_resolve_ctx_from_token(const void *token,
				    struct pkm_kacs_resolved_ctx *out);
int pkm_kacs_resolve_current_effective_ctx(struct pkm_kacs_resolved_ctx *out);
int pkm_kacs_resolve_current_primary_ctx(struct pkm_kacs_resolved_ctx *out);
int pkm_kacs_install_impersonation_token(const void *token);
int pkm_kacs_revert_impersonation(void);
int pkm_kacs_install_current_primary_token(const void *token);
int pkm_kmes_current_process_rate_reserve(u32 count);
void pkm_kmes_current_process_rate_refund(u32 count);

const void *kacs_rust_create_boot_system_token(void);
int kacs_rust_create_token(const void *creator_token, const u8 *spec,
			   size_t spec_len, u64 created_at,
			   const void **out_token);
int kacs_rust_create_session(const u8 *spec, size_t spec_len, u64 created_at,
			     u64 *session_id_out);
const void *kacs_rust_token_clone(const void *token);
const void *kacs_rust_token_deep_copy(const void *token);
void kacs_rust_token_drop(const void *token);
bool kacs_rust_token_is_primary(const void *token);
bool kacs_rust_token_same_user_sid(const void *lhs, const void *rhs);
bool kacs_rust_token_has_enabled_privilege(const void *token, u64 privilege);
bool kacs_rust_token_has_new_process_min(const void *token);
bool kacs_rust_token_mark_privileges_used(const void *token, u64 used_mask);
int kacs_rust_token_open_check(const void *subject_token, const void *target_token,
			       u32 desired_access, u32 *granted_out);
int kacs_rust_token_duplicate(const void *source_token,
			      const void *creator_token, u32 token_type,
			      u32 impersonation_level,
			      const void **out_token);
int kacs_rust_token_new_process_min_exec(const void *source_token,
					 u32 file_integrity_level,
					 const void **out_token);
int kacs_rust_token_link_tokens(const void *elevated_token,
				const void *filtered_token, u64 session_id);
int kacs_rust_token_get_linked_actual(const void *token,
				      const void **out_token);
int kacs_rust_token_get_linked_query_copy(const void *token,
					  const void **out_token);
int kacs_rust_token_impersonation_gate(
	const void *server_token, const void *client_token,
	u32 *effective_level_out, u32 *used_impersonate_privilege_out);
int kacs_rust_token_clone_with_impersonation_level(
	const void *token, u32 impersonation_level, const void **out_token);
int kacs_rust_create_anonymous_impersonation_token(const void **out_token);
int kacs_rust_create_peer_impersonation_token(const void *token,
					      u32 impersonation_level,
					      const void **out_token);
const u8 *kacs_rust_create_default_process_sd(const void *token_ptr,
					      size_t *len_out);
const u8 *kacs_rust_create_default_socket_sd(const void *token_ptr,
					     size_t *len_out);
const u8 *kacs_rust_kunit_create_query_limited_process_sd(const void *token_ptr,
							  size_t *len_out);
const u8 *kacs_rust_kunit_create_query_information_process_sd(
	const void *token_ptr, size_t *len_out);
const u8 *kacs_rust_kunit_create_read_only_socket_sd(const void *token_ptr,
						      size_t *len_out);
const u8 *kacs_rust_kunit_create_file_sd(const void *token_ptr, u32 self_mask,
					 u32 admin_mask, u32 system_mask,
					 u32 everyone_mask, size_t *len_out);
const u8 *kacs_rust_kunit_create_file_sd_with_mandatory_resource_attr(
	const void *token_ptr, u32 self_mask, u32 admin_mask, u32 system_mask,
	u32 everyone_mask, size_t *len_out);
const u8 *kacs_rust_kunit_create_label_sd_subset(u32 integrity_level,
						 size_t *len_out);
const u8 *kacs_rust_kunit_create_process_sd_with_mandatory_resource_attr(
	const void *token_ptr, size_t *len_out);
const u8 *kacs_rust_kunit_create_query_only_token_sd(size_t *len_out);
int kacs_rust_check_process_sd(const void *subject_token_ptr,
			       const u8 *sd_ptr, size_t sd_len, u32 desired,
			       u32 *granted_out);
int kacs_rust_check_process_sd_with_intent(const void *subject_token_ptr,
					   const u8 *sd_ptr, size_t sd_len,
					   u32 desired, u32 privilege_intent,
					   u32 *granted_out);
int kacs_rust_check_file_sd_with_intent(const void *subject_token_ptr,
					const u8 *sd_ptr, size_t sd_len,
					u32 desired, u32 privilege_intent,
					u32 *granted_out);
int kacs_rust_check_file_sd_with_intent_audit(const void *subject_token_ptr,
					      const u8 *sd_ptr, size_t sd_len,
					      u32 desired, u32 privilege_intent,
					      u32 *granted_out,
					      u32 *continuous_audit_out);
int kacs_rust_file_sd_integrity_label(const u8 *sd_ptr, size_t sd_len,
				      u32 *integrity_level_out);
int kacs_rust_granted_file_sd_with_intent(const void *subject_token_ptr,
					  const u8 *sd_ptr, size_t sd_len,
					  u32 desired, u32 privilege_intent,
					  u32 *granted_out);
int kacs_rust_granted_file_sd_with_intent_audit(const void *subject_token_ptr,
						const u8 *sd_ptr,
						size_t sd_len, u32 desired,
						u32 privilege_intent,
						u32 *granted_out,
						u32 *continuous_audit_out);
int kacs_rust_emit_file_continuous_audit(const void *subject_token_ptr,
					 const u8 *operation_ptr,
					 size_t operation_len,
					 u32 requested_access,
					 u32 matched_access,
					 u32 granted_access, u8 success);
int kacs_rust_check_token_sd_with_intent(const void *subject_token_ptr,
					 const void *target_token_ptr,
					 u32 desired, u32 privilege_intent,
					 u32 *granted_out);
int kacs_rust_validate_sd_bytes(const u8 *sd_ptr, size_t sd_len);
int kacs_rust_query_process_sd_subset(const u8 *sd_ptr, size_t sd_len,
				      u32 security_info,
				      const u8 **out_sd_ptr,
				      size_t *out_sd_len);
int kacs_rust_query_file_sd_subset(const u8 *sd_ptr, size_t sd_len,
				   u32 security_info,
				   const u8 **out_sd_ptr,
				   size_t *out_sd_len);
int kacs_rust_query_token_sd_subset(const void *token_ptr, u32 security_info,
				    const u8 **out_sd_ptr,
				    size_t *out_sd_len);
int kacs_rust_merge_file_sd(const void *subject_token_ptr,
			    const u8 *current_sd_ptr,
			    size_t current_sd_len, u32 security_info,
			    const u8 *input_sd_ptr, size_t input_sd_len,
			    const u8 **out_sd_ptr,
			    size_t *out_sd_len);
int kacs_rust_merge_process_sd(const void *subject_token_ptr,
			       const u8 *current_sd_ptr,
			       size_t current_sd_len, u32 security_info,
			       const u8 *input_sd_ptr, size_t input_sd_len,
			       const u8 **out_sd_ptr,
			       size_t *out_sd_len);
int kacs_rust_build_replacement_file_sd(const void *subject_token_ptr,
					u32 security_info,
					const u8 *input_sd_ptr,
					size_t input_sd_len,
					const u8 **out_sd_ptr,
					size_t *out_sd_len);
int kacs_rust_build_created_file_sd(const void *subject_token_ptr,
				    const u8 *parent_sd_ptr,
				    size_t parent_sd_len,
				    const u8 *creator_sd_ptr,
				    size_t creator_sd_len,
				    u32 child_is_directory,
				    const u8 **out_sd_ptr,
				    size_t *out_sd_len);
int kacs_rust_synthesize_file_sd(const u8 *parent_sd_ptr, size_t parent_sd_len,
				 const u8 *template_sd_ptr,
				 size_t template_sd_len,
				 u32 child_is_directory,
				 const u8 **out_sd_ptr,
				 size_t *out_sd_len);
int kacs_rust_set_token_sd(const void *subject_token_ptr,
			   const void *target_token_ptr, u32 security_info,
			   const u8 *input_sd_ptr, size_t input_sd_len);
int kacs_rust_check_socket_sd(const void *subject_token_ptr,
			      const u8 *sd_ptr, size_t sd_len, u32 desired,
			      u32 *granted_out);
int kacs_rust_check_securityfs_sessions_read(const void *subject_token_ptr);
int kacs_rust_securityfs_sessions_listing(u8 *out, size_t out_len,
					  size_t *required_out);
u32 kacs_rust_token_projected_uid(const void *token);
u32 kacs_rust_token_projected_gid(const void *token);
bool kacs_rust_kunit_token_snapshot(const void *token,
				    struct pkm_kacs_boot_snapshot *out);
bool kacs_rust_kunit_boot_snapshot(struct pkm_kacs_boot_snapshot *out);
int kacs_rust_kunit_session_snapshot(
	u64 session_id, struct pkm_kacs_session_snapshot *out);
const void *kacs_rust_kunit_create_query_only_token(void);
const void *kacs_rust_kunit_create_without_tcb_token(void);
const void *kacs_rust_kunit_create_adjustable_groups_token(void);
const void *kacs_rust_kunit_create_adjustable_privileges_token(void);
const void *kacs_rust_kunit_create_privilege_audit_token(void);
const void *kacs_rust_kunit_create_impersonation_variant_token(
	u32 user_kind, u32 token_type, u32 impersonation_level,
	u32 integrity_level, u32 restricted, u64 enabled_privileges);
int kacs_rust_token_query(const void *token, u32 token_class, u8 *out,
			  size_t out_len, size_t *required_out);
int kacs_rust_token_adjust_privs(
	const void *token, const struct pkm_kacs_priv_adjust_entry *entries,
	u32 count, u64 *previous_enabled_out);
int kacs_rust_token_adjust_groups(
	const void *token, const struct pkm_kacs_group_adjust_entry *entries,
	u32 count, u64 *previous_state_out);
int kacs_rust_token_adjust_session_id(const void *token, u32 session_id);
int kacs_rust_token_adjust_default(const void *token, u32 owner_index,
				   u32 group_index, const u8 *dacl,
				   size_t dacl_len, u32 change_dacl);
int kacs_rust_token_restrict(const void *source_token,
			     const void *creator_token, u64 privs_to_delete,
			     u32 flags, const u8 *payload, size_t payload_len,
			     u32 num_deny_indices, u32 num_restrict_sids,
			     const void **out_token);
int pkm_kacs_proc_open_process_token_file(struct file *file,
					  struct task_struct *task);
int pkm_kacs_proc_open_thread_token_file(struct file *file,
					 struct task_struct *task);
int pkm_kacs_securityfs_open_self_token_file(struct file *file);
int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,
				     bool positioned);
void pkm_kacs_file_end_write_intent(struct file *file);
int pkm_kacs_file_fallocate(struct file *file, int mode);

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kmes_kunit_set_current_process_rate_tokens(u32 tokens);
int pkm_kmes_kunit_set_current_process_rate_refill_frozen(bool frozen);
int pkm_kmes_kunit_get_current_process_rate_tokens(u32 *tokens_out);
int pkm_kacs_kunit_set_current_process_mitigation_bits(u32 mitigation_bits);
const void *pkm_kacs_kunit_current_process_state_ptr(void);
const void *pkm_kacs_kunit_inherit_current_process_state(u64 clone_flags);
void pkm_kacs_kunit_put_process_state(const void *state_ptr);
int pkm_kacs_kunit_process_state_snapshot(
	const void *state_ptr,
	struct pkm_kacs_kunit_process_state_view *out);
long pkm_kacs_kunit_open_process_token_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args);
long pkm_kacs_kunit_open_process_token_inspection_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args);
long pkm_kacs_kunit_open_thread_token_inspection_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args);
long pkm_kacs_kunit_open_self_token_inspection_for_subject(void);
long pkm_kacs_kunit_read_securityfs_sessions_for_subject(
	const void *subject_token, u8 *buf, size_t buf_len,
	size_t *required_out);
long pkm_kacs_kunit_check_signal_for_subject(
	const struct pkm_kacs_kunit_process_signal_check_args *args);
long pkm_kacs_kunit_check_ptrace_for_subject(
	const struct pkm_kacs_kunit_process_ptrace_check_args *args);
long pkm_kacs_kunit_check_process_setinfo_for_subject(
	const struct pkm_kacs_kunit_process_setinfo_check_args *args);
long pkm_kacs_kunit_check_process_affinity_for_subject(
	const struct pkm_kacs_kunit_process_affinity_check_args *args);
long pkm_kacs_kunit_check_prlimit_for_subject(
	const struct pkm_kacs_kunit_process_prlimit_check_args *args);
long pkm_kacs_kunit_create_session_for_subject(const void *subject_token,
					       const u8 *spec, size_t spec_len,
					       u64 *session_id_out);
long pkm_kacs_kunit_create_token_for_subject(const void *subject_token,
					     const u8 *spec, size_t spec_len);
long pkm_kacs_kunit_get_process_sd_for_subject(
	const struct pkm_kacs_kunit_process_sd_get_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_set_process_sd_for_subject(
	const struct pkm_kacs_kunit_process_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_get_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_set_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_open_file_for_subject(
	const struct pkm_kacs_kunit_file_open_args *args,
	u32 *granted_access_out);
long pkm_kacs_kunit_open_file_for_subject_audit(
	const struct pkm_kacs_kunit_file_open_args *args,
	u32 *granted_access_out, u32 *continuous_audit_out);
long pkm_kacs_kunit_native_open_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	u32 *granted_access_out, u32 *status_out, u32 *file_mode_out);
long pkm_kacs_kunit_native_create_for_subject(
	const struct pkm_kacs_kunit_native_create_args *args,
	const u8 **created_sd_out, size_t *created_sd_len_out,
	u32 *granted_access_out, u32 *status_out);
long pkm_kacs_kunit_delete_on_close_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	struct pkm_kacs_kunit_delete_on_close_result *out);
long pkm_kacs_kunit_get_cached_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_set_cached_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len);
u32 pkm_kacs_kunit_classify_file_sd_bytes(const u8 *sd_ptr, size_t sd_len);
u32 pkm_kacs_kunit_mount_policy_for_magic(u64 magic);
long pkm_kacs_kunit_missing_file_sd_result_for_magic(u64 magic);
long pkm_kacs_kunit_get_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args, u64 magic,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_set_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args, u64 magic);
long pkm_kacs_kunit_get_path_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args, u64 magic, u32 flags,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_set_path_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args, u64 magic, u32 flags);
long pkm_kacs_kunit_query_missing_file_sd_on_policy_mount(
	const struct pkm_kacs_kunit_missing_file_sd_query_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len,
	u32 *xattr_written_out);
int pkm_kacs_kunit_inode_sd_xattr_get(const char *name, u32 ntfs);
int pkm_kacs_kunit_inode_sd_xattr_set(const char *name, u32 ntfs);
int pkm_kacs_kunit_inode_sd_xattr_remove(const char *name, u32 ntfs);
int pkm_kacs_kunit_file_sd_xattr_get(const char *name, u32 ntfs);
int pkm_kacs_kunit_file_sd_xattr_set(const char *name, u32 ntfs);
int pkm_kacs_kunit_file_sd_xattr_remove(const char *name, u32 ntfs);
long pkm_kacs_kunit_get_token_sd_for_subject(
	int token_fd, const void *subject_token, u32 security_info,
	const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_kunit_set_token_sd_for_subject(
	int token_fd, const void *subject_token, u32 security_info,
	const u8 *input_sd_ptr, size_t input_sd_len, const u8 **out_sd_ptr,
	size_t *out_sd_len);
long pkm_kacs_kunit_open_current_thread_token_for_subject(
	const void *subject_token, u32 access_mask);
long pkm_kacs_kunit_set_current_psb(u32 requested_mitigations);
long pkm_kacs_kunit_set_psb_for_subject(
	const struct pkm_kacs_kunit_set_psb_args *args,
	u32 *result_mitigation_bits_out);
long pkm_kacs_kunit_bind_abstract_socket_for_subject(
	const void *subject_token,
	struct pkm_kacs_kunit_socket_view *first_out,
	struct pkm_kacs_kunit_socket_view *second_out);
long pkm_kacs_kunit_set_socket_impersonation_level(
	u32 socket_type, u32 connected, u32 level,
	struct pkm_kacs_kunit_socket_view *out);
long pkm_kacs_kunit_capture_peer_socket_for_subject(
	const void *client_token, u32 socket_type, u32 max_impersonation,
	u32 abstract_socket, u32 allow_write,
	const void **captured_token_out,
	struct pkm_kacs_kunit_socket_view *listener_out,
	struct pkm_kacs_kunit_socket_view *accepted_out);
long pkm_kacs_kunit_unix_dgram_send_for_subject(
	const void *subject_token, u32 abstract_socket, u32 allow_write,
	struct pkm_kacs_kunit_socket_view *sender_out,
	struct pkm_kacs_kunit_socket_view *target_out);
long pkm_kacs_kunit_open_peer_token_for_socket_type(u32 socket_type,
						    u32 connected,
						    const void *peer_token);
long pkm_kacs_kunit_open_peer_token_for_socket(u32 connected,
					       const void *peer_token);
long pkm_kacs_kunit_impersonate_peer_for_socket_type(u32 socket_type,
						     u32 connected,
						     const void *peer_token);
long pkm_kacs_kunit_impersonate_peer_for_socket(u32 connected,
						const void *peer_token);
int pkm_kacs_kunit_check_no_child_process(u32 mitigation_bits,
					  u64 clone_flags);
int pkm_kacs_kunit_check_wxp_mmap(u32 mitigation_bits, unsigned long prot);
int pkm_kacs_kunit_check_wxp_mprotect(u32 mitigation_bits,
				      unsigned long vm_flags,
				      unsigned long prot);
long pkm_kacs_kunit_replace_tlp_prefixes(const char * const *prefixes,
					 const size_t *prefix_lens,
					 u32 count);
void pkm_kacs_kunit_clear_tlp_prefixes(void);
int pkm_kacs_kunit_check_tlp_mmap_path(u32 mitigation_bits,
				       unsigned long prot,
				       const char *path,
				       u32 file_backed);
int pkm_kacs_kunit_check_tlp_mprotect_path(u32 mitigation_bits,
					   unsigned long vm_flags,
					   unsigned long prot,
					   const char *path,
					   u32 file_backed);
int pkm_kacs_kunit_probe_signing_material(
	const u8 *file_bytes, size_t file_len, const u8 *xattr_sig,
	size_t xattr_sig_len, struct pkm_kacs_kunit_signing_probe *out);
int pkm_kacs_kunit_probe_signing_reader(
	const struct pkm_kacs_kunit_signing_reader_args *args,
	struct pkm_kacs_kunit_signing_probe *out);
int pkm_kacs_kunit_verify_signing_material(
	const struct pkm_kacs_kunit_signing_probe *material,
	const struct pkm_kacs_kunit_signing_key_entry *keys, size_t key_count,
	u32 match_key_index, u32 match_enabled,
	struct pkm_kacs_kunit_signing_verify_out *out);
int pkm_kacs_kunit_check_mmap_snapshot(u32 managed, u32 granted_access,
				       unsigned long prot,
				       unsigned long flags);
int pkm_kacs_kunit_check_mprotect_snapshot(u32 managed, u32 granted_access,
					   unsigned long vm_flags,
					   unsigned long prot);
int pkm_kacs_kunit_check_file_permission_snapshot(u32 managed,
						  u32 granted_access,
						  int file_flags,
						  int mask);
int pkm_kacs_kunit_check_file_permission_snapshot_audit(u32 managed,
							u32 granted_access,
							u32 continuous_audit,
							int file_flags,
							int mask);
int pkm_kacs_kunit_check_file_write_intent_snapshot(u32 managed,
						    u32 granted_access,
						    int file_flags,
						    u32 rwf_flags,
						    bool positioned);
int pkm_kacs_kunit_check_file_permission_write_intent(
	u32 managed, u32 granted_access, int file_flags, u32 rwf_flags,
	bool positioned);
int pkm_kacs_kunit_check_file_permission_write_intent_mismatch(void);
int pkm_kacs_kunit_check_file_metadata_snapshot(u32 managed,
						u32 granted_access, u32 op,
						const char *name);
int pkm_kacs_kunit_check_file_metadata_null(u32 op, const char *name);
int pkm_kacs_kunit_check_path_metadata_live(const u8 *target_file_sd_ptr,
					    size_t target_file_sd_len,
					    u32 target_file_sd_state, u32 op,
					    u32 mode, const char *name);
int pkm_kacs_kunit_check_inode_permission_live(
	const u8 *target_file_sd_ptr, size_t target_file_sd_len,
	u32 target_file_sd_state, u32 mount_policy,
	const void *subject_token, int mask);
int pkm_kacs_kunit_check_open_by_handle_for_subject(
	const void *subject_token);
int pkm_kacs_kunit_check_namespace_live(
	const struct pkm_kacs_kunit_namespace_args *args,
	const u8 **created_sd_out, size_t *created_sd_len_out);
int pkm_kacs_kunit_check_namespace_rename_flags(
	const struct pkm_kacs_kunit_namespace_args *args, unsigned int flags);
int pkm_kacs_kunit_check_file_ioctl_snapshot(u32 managed, u32 granted_access,
					     umode_t mode, unsigned int cmd,
					     bool compat);
int pkm_kacs_kunit_check_file_ioctl_null(void);
int pkm_kacs_kunit_check_file_lock_snapshot(u32 managed, u32 granted_access,
					    unsigned int cmd);
int pkm_kacs_kunit_check_file_fcntl_snapshot(u32 managed, u32 granted_access,
					     int file_flags,
					     unsigned int cmd,
					     unsigned long arg);
int pkm_kacs_kunit_check_file_fcntl_null(void);
int pkm_kacs_kunit_check_file_truncate_snapshot(u32 managed,
						u32 granted_access);
int pkm_kacs_kunit_check_file_truncate_null(void);
int pkm_kacs_kunit_check_file_fallocate_snapshot(u32 managed,
						 u32 granted_access,
						 int mode);
int pkm_kacs_kunit_check_file_fallocate_null(void);
int pkm_kacs_kunit_check_task_prctl_mitigations(
	u32 mitigation_bits, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5);
int pkm_kacs_kunit_check_pie_bprm(u32 mitigation_bits, const u8 *buf,
				  size_t len);
u64 pkm_kacs_kunit_allow_cap_mask(void);
long pkm_kacs_kunit_check_capability_for_subject(const void *subject_token,
						 int cap);
long pkm_kacs_kunit_check_capset_for_subject(const void *subject_token,
					     u64 effective_mask,
					     u64 inheritable_mask,
					     u64 permitted_mask);
long pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
	const void *subject_token, u64 ambient_mask, int option,
	unsigned long arg2, unsigned long arg3, unsigned long arg4,
	unsigned long arg5);
int pkm_kacs_kunit_reproject_exec_caps(
	u64 effective_mask, u64 inheritable_mask, u64 permitted_mask,
	u64 ambient_mask, u64 *effective_out, u64 *inheritable_out,
	u64 *permitted_out, u64 *ambient_out);
long pkm_kacs_kunit_check_setuid_fixup_for_subject(const void *subject_token,
						   int flags);
long pkm_kacs_kunit_check_setgid_fixup_for_subject(const void *subject_token,
						   int flags);
long pkm_kacs_kunit_check_setgroups_fixup_for_subject(
	const void *subject_token);
long pkm_kacs_kunit_check_exec_setid_compat_for_subject(
	const void *subject_token, u32 exec_mask,
	struct pkm_kacs_kunit_exec_setid_view *out);
long pkm_kacs_kunit_check_exec_new_process_min(
	const struct pkm_kacs_kunit_exec_new_process_min_args *args,
	struct pkm_kacs_boot_snapshot *snapshot_out, u32 *changed_out);
int pkm_kacs_kunit_projected_fsids_for_subject(const void *subject_token,
					       u32 raw_fsuid, u32 raw_fsgid,
					       u32 *fsuid_out,
					       u32 *fsgid_out);
#endif

#endif /* _SECURITY_PKM_KACS_TOKEN_RUNTIME_H */
