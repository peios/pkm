// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_kunit_open_self_token_effective_query(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	const void *effective_token;
	long fd;

	effective_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, effective_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_open_self_token_real_generic_read(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	const void *primary_token;
	long fd;

	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
					       KACS_ACCESS_GENERIC_READ);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, primary_token);
	KUNIT_EXPECT_EQ(test, view.access_mask,
			KACS_TOKEN_QUERY | KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_open_token_denied_by_own_sd(struct kunit *test)
{
	const void *subject_token;
	const void *target_token;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	ret = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						       KACS_TOKEN_DUPLICATE);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_open_self_token_generic_mapping_matrix(
	struct kunit *test)
{
	static const struct {
		u32 requested;
		u32 expected;
	} cases[] = {
		{
			.requested = KACS_ACCESS_GENERIC_READ,
			.expected = KACS_TOKEN_QUERY | KACS_ACCESS_READ_CONTROL,
		},
		{
			.requested = KACS_ACCESS_GENERIC_WRITE,
			.expected = KACS_TOKEN_ADJUST_PRIVS |
				    KACS_TOKEN_ADJUST_GROUPS |
				    KACS_TOKEN_ADJUST_DEFAULT |
				    KACS_ACCESS_WRITE_DAC,
		},
		{
			.requested = KACS_ACCESS_GENERIC_EXECUTE,
			.expected = KACS_TOKEN_IMPERSONATE,
		},
		{
			.requested = KACS_ACCESS_GENERIC_ALL,
			.expected = KACS_TOKEN_ALL_ACCESS,
		},
		{
			.requested = KACS_ACCESS_GENERIC_READ |
				     KACS_ACCESS_GENERIC_EXECUTE,
			.expected = KACS_TOKEN_QUERY |
				    KACS_ACCESS_READ_CONTROL |
				    KACS_TOKEN_IMPERSONATE,
		},
	};
	struct pkm_kacs_token_fd_view view = { };
	unsigned int i;
	long fd;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fd = pkm_kacs_open_self_token_internal(0, cases[i].requested);
		KUNIT_ASSERT_GE(test, fd, 0L);
		KUNIT_ASSERT_EQ(test,
				pkm_kacs_kunit_token_fd_snapshot((int)fd,
								 &view),
				0);
		KUNIT_EXPECT_EQ(test, view.access_mask, cases[i].expected);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}
}


static void pkm_kunit_open_self_token_maximum_allowed(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	const void *effective_token;
	long fd;

	effective_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);

	fd = pkm_kacs_open_self_token_internal(0, KACS_ACCESS_MAXIMUM_ALLOWED);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, effective_token);
	KUNIT_EXPECT_EQ(test, view.access_mask,
			KACS_TOKEN_ALL_ACCESS | KACS_ACCESS_ACCESS_SYSTEM_SECURITY);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_open_self_token_invalid_flags(struct kunit *test)
{
	long ret;

	ret = pkm_kacs_open_self_token_internal(0x2, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
}


static void pkm_kunit_file_mmap_snapshot_read_and_private_write(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, PROT_READ,
				MAP_PRIVATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, 0, PROT_READ, MAP_PRIVATE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, PROT_WRITE,
				MAP_PRIVATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, PROT_WRITE,
				MAP_PRIVATE),
			-EACCES);
}


static void pkm_kunit_file_mmap_snapshot_shared_write(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, PROT_WRITE,
				MAP_SHARED),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, PROT_WRITE,
				MAP_SHARED),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1,
				PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_WRITE_DATA,
				PROT_READ | PROT_WRITE, MAP_SHARED),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				PROT_READ | PROT_WRITE, MAP_SHARED),
			-EACCES);
}


static void pkm_kunit_file_mmap_snapshot_exec(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_EXECUTE, PROT_EXEC,
				MAP_PRIVATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, PROT_EXEC,
				MAP_PRIVATE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1,
				PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_EXECUTE,
				PROT_READ | PROT_EXEC, MAP_PRIVATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, PKM_KUNIT_FILE_EXECUTE,
				PROT_READ | PROT_EXEC, MAP_PRIVATE),
			-EACCES);
}


static void pkm_kunit_file_mprotect_snapshot_uses_vma_shape(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, 0, PROT_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, 0, PROT_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, VM_SHARED,
				PROT_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, VM_SHARED,
				PROT_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				1,
				PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_EXECUTE,
				0, PROT_READ | PROT_EXEC),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, 0, PROT_EXEC),
			-EACCES);
}


static void pkm_kunit_file_mapping_snapshot_unmanaged_bypasses_facs(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				0, 0, PROT_READ | PROT_EXEC, MAP_PRIVATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				0, 0, PROT_WRITE, MAP_SHARED),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mprotect_snapshot(
				0, 0, VM_SHARED, PROT_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_snapshot(
				1, 0, PROT_NONE, MAP_PRIVATE),
			0);
}


static void pkm_kunit_file_mmap_opath_denied(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_opath(PROT_READ,
							MAP_PRIVATE),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_opath(PROT_READ |
								PROT_WRITE,
							MAP_SHARED),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_mmap_opath(PROT_EXEC,
							MAP_PRIVATE),
			-EBADF);
}


static void pkm_kunit_file_permission_snapshot_read_and_unmanaged(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, 0, MAY_READ),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, 0, 0, MAY_READ),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				0, 0, 0, MAY_READ | MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, 0, 0, 0),
			0);
}


static void pkm_kunit_file_permission_sysfs_write_uses_live_gate(
	struct kunit *test)
{
	const void *system_token;
	const void *admin_token;
	const void *local_token;

	system_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	local_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, system_token);
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	KUNIT_ASSERT_NOT_NULL(test, local_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot_for_subject(
				local_token, SYSFS_MAGIC, 0, 0, 0, MAY_READ),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot_for_subject(
				system_token, SYSFS_MAGIC, 0, 0, 0, MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot_for_subject(
				admin_token, SYSFS_MAGIC, 0, 0, 0, MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot_for_subject(
				local_token, SYSFS_MAGIC, 0, 0, 0, MAY_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot_for_subject(
				admin_token, SYSFS_MAGIC, 0, 0, 0, 0, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot_for_subject(
				local_token, SYSFS_MAGIC, 0, 0, 0, 0, true),
			-EACCES);

	kacs_rust_token_drop(system_token);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(local_token);
}


static void pkm_kunit_file_permission_snapshot_write_and_append(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, 0, MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0, MAY_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, O_APPEND,
				MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, O_APPEND,
				MAY_WRITE),
			-EACCES);
}


static void pkm_kunit_file_permission_snapshot_combined_masks(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1,
				PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_APPEND_DATA,
				O_APPEND, MAY_READ | MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				MAY_READ | MAY_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				MAY_WRITE | MAY_APPEND),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_EXECUTE, 0,
				MAY_EXEC | MAY_CHDIR),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, 0,
				MAY_EXEC | MAY_CHDIR),
			-EACCES);
}


static void pkm_kunit_file_fd_dup_preserves_cached_grant(
	struct kunit *test)
{
	const u32 expected = PKM_KUNIT_FILE_READ_DATA |
			     PKM_KUNIT_FILE_READ_ATTRIBUTES;
	struct pkm_kacs_kunit_file_fd_view original = { };
	struct pkm_kacs_kunit_file_fd_view duplicate = { };
	int fd = -1;
	int duplicate_fd = -1;

	fd = anon_inode_getfd("pkm-kunit-file-transfer",
			      &pkm_kunit_file_fd_transfer_fops, NULL,
			      O_CLOEXEC);
	KUNIT_ASSERT_GE(test, fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_fd_snapshot(fd, 1, expected, 0),
			0L);

	duplicate_fd = pkm_kunit_dup_fd_same_file(fd);
	KUNIT_ASSERT_GE(test, duplicate_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_file_fd_snapshot(fd, &original), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_file_fd_snapshot(duplicate_fd,
							&duplicate),
			0L);

	KUNIT_EXPECT_EQ(test, duplicate.file_cookie, original.file_cookie);
	KUNIT_EXPECT_EQ(test, original.managed, 1U);
	KUNIT_EXPECT_EQ(test, duplicate.managed, 1U);
	KUNIT_EXPECT_EQ(test, original.granted_access, expected);
	KUNIT_EXPECT_EQ(test, duplicate.granted_access, expected);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_fd(fd, MAY_READ),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_fd(
				duplicate_fd, MAY_READ),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_fd(
				duplicate_fd, MAY_EXEC | MAY_CHDIR),
			(long)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)duplicate_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_file_continuous_audit_read_emits_kmes(
	struct kunit *test)
{
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	int ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4301, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	ret = pkm_kacs_kunit_check_file_permission_snapshot_audit(
		1, PKM_KUNIT_FILE_READ_DATA, PKM_KUNIT_FILE_READ_DATA, 0,
		MAY_READ);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"continuous-audit",
				  sizeof("continuous-audit") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"file.permission",
						 sizeof("file.permission") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PROCESS_PATH) - 1));
}


static void pkm_kunit_file_continuous_audit_unmatched_mask_no_event(
	struct kunit *test)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };
	int ret;

	pkm_kunit_reset_kmes();
	ret = pkm_kacs_kunit_check_file_permission_snapshot_audit(
		1, PKM_KUNIT_FILE_READ_DATA, PKM_KUNIT_FILE_WRITE_DATA, 0,
		MAY_READ);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
}


static void pkm_kunit_file_continuous_audit_denial_emits_failure(
	struct kunit *test)
{
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	int ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4302, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	ret = pkm_kacs_kunit_check_file_permission_snapshot_audit(
		1, 0, PKM_KUNIT_FILE_READ_DATA, 0, MAY_READ);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"continuous-audit",
				  sizeof("continuous-audit") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"file.permission",
						 sizeof("file.permission") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8[]){ 0xc2 },
						 1));
}


static void pkm_kunit_file_continuous_audit_emit_malformed_fails_closed(
	struct kunit *test)
{
	const void *subject_token = pkm_kacs_current_effective_token_ptr();

	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_emit_file_continuous_audit(
				subject_token, 0U, 0U,
				(const u8 *)"file.permission",
				sizeof("file.permission") - 1,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KUNIT_FILE_READ_DATA, 1),
			-EINVAL);
}


static void pkm_kunit_file_continuous_audit_operation_matrix(
	struct kunit *test)
{
	static const struct pkm_kunit_continuous_audit_op_case cases[] = {
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_ACCESS,
			.operation = "file.access",
			.granted = PKM_KUNIT_FILE_READ_DATA,
			.continuous_audit = PKM_KUNIT_FILE_READ_DATA,
			.arg0 = PKM_KUNIT_FILE_READ_DATA,
			.requested = PKM_KUNIT_FILE_READ_DATA,
			.matched = PKM_KUNIT_FILE_READ_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_MMAP,
			.operation = "file.mmap",
			.granted = PKM_KUNIT_FILE_READ_DATA,
			.continuous_audit = PKM_KUNIT_FILE_READ_DATA,
			.arg0 = PROT_READ,
			.arg1 = MAP_PRIVATE,
			.requested = PKM_KUNIT_FILE_READ_DATA,
			.matched = PKM_KUNIT_FILE_READ_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_MPROTECT,
			.operation = "file.mprotect",
			.granted = PKM_KUNIT_FILE_WRITE_DATA,
			.continuous_audit = PKM_KUNIT_FILE_WRITE_DATA,
			.arg0 = VM_SHARED,
			.arg1 = PROT_WRITE,
			.requested = PKM_KUNIT_FILE_WRITE_DATA,
			.matched = PKM_KUNIT_FILE_WRITE_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_PERMISSION,
			.operation = "file.permission",
			.granted = PKM_KUNIT_FILE_READ_DATA,
			.continuous_audit = PKM_KUNIT_FILE_READ_DATA,
			.arg0 = MAY_READ,
			.requested = PKM_KUNIT_FILE_READ_DATA,
			.matched = PKM_KUNIT_FILE_READ_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_WRITE,
			.operation = "file.write",
			.granted = PKM_KUNIT_FILE_WRITE_DATA,
			.continuous_audit = PKM_KUNIT_FILE_WRITE_DATA,
			.arg1 = 1,
			.requested = PKM_KUNIT_FILE_WRITE_DATA,
			.matched = PKM_KUNIT_FILE_WRITE_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_IOCTL,
			.operation = "file.ioctl",
			.granted = PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.continuous_audit = PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.arg0 = FS_IOC_GETFLAGS,
			.requested = PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.matched = PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_LOCK,
			.operation = "file.lock",
			.granted = PKM_KUNIT_FILE_WRITE_DATA,
			.continuous_audit = PKM_KUNIT_FILE_WRITE_DATA,
			.arg0 = F_WRLCK,
			.requested = PKM_KUNIT_FILE_WRITE_DATA |
				     PKM_KUNIT_FILE_APPEND_DATA,
			.matched = PKM_KUNIT_FILE_WRITE_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_FCNTL,
			.operation = "file.fcntl",
			.granted = PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
			.continuous_audit = PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
			.arg0 = F_SETPIPE_SZ,
			.requested = PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
			.matched = PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_TRUNCATE,
			.operation = "file.truncate",
			.granted = PKM_KUNIT_FILE_WRITE_DATA,
			.continuous_audit = PKM_KUNIT_FILE_WRITE_DATA,
			.requested = PKM_KUNIT_FILE_WRITE_DATA,
			.matched = PKM_KUNIT_FILE_WRITE_DATA,
			.success = true,
			.expected_ret = 0,
		},
		{
			.op = PKM_KACS_KUNIT_CONT_AUDIT_OP_FALLOCATE,
			.operation = "file.fallocate",
			.granted = PKM_KUNIT_FILE_APPEND_DATA,
			.continuous_audit = PKM_KUNIT_FILE_APPEND_DATA,
			.arg0 = FALLOC_FL_ALLOCATE_RANGE,
			.requested = PKM_KUNIT_FILE_WRITE_DATA |
				     PKM_KUNIT_FILE_APPEND_DATA,
			.matched = PKM_KUNIT_FILE_APPEND_DATA,
			.success = true,
			.expected_ret = 0,
		},
	};
	u8 *buffer;
	u32 i;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_kmes_kunit_snapshot snapshot = { };
		struct pkm_kunit_kmes_event_view view = { };
		size_t written = 0;
		u64 pid = 4400ULL + i;
		int ret;

		pkm_kunit_reset_kmes();
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_set_process_override(
					pid, PKM_KUNIT_KMES_PROCESS_NAME,
					PKM_KUNIT_KMES_PROCESS_PATH),
				0);

		ret = pkm_kacs_kunit_check_file_continuous_audit_op(
			cases[i].op, 1, cases[i].granted,
			cases[i].continuous_audit, cases[i].file_flags,
			cases[i].arg0, cases[i].arg1);
		KUNIT_EXPECT_EQ(test, ret, cases[i].expected_ret);
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_single_buffer(
					buffer, PKM_KUNIT_KMES_CAPTURE_BYTES,
					&written, &snapshot),
				0);
		KUNIT_ASSERT_TRUE(
			test, pkm_kunit_parse_kmes_event(buffer, written, &view));
		KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
		KUNIT_EXPECT_TRUE(
			test, pkm_kunit_expect_continuous_audit_schema_op(
				      test, &view, cases[i].operation,
				      cases[i].requested, cases[i].matched,
				      cases[i].granted, cases[i].success, 0U,
				      0U, pid));
	}
}


static void pkm_kunit_file_continuous_audit_records_current_pip(
	struct kunit *test)
{
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	u32 old_type = 0;
	u32 old_trust = 0;
	int copy_ret;
	int ret;
	bool parsed = false;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust),
			0);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4417, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	ret = pkm_kacs_kunit_check_file_continuous_audit_op(
		PKM_KACS_KUNIT_CONT_AUDIT_OP_PERMISSION, 1,
		PKM_KUNIT_FILE_READ_DATA, PKM_KUNIT_FILE_READ_DATA, 0,
		MAY_READ, 0);
	copy_ret = pkm_kmes_kunit_copy_single_buffer(
		buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written, &snapshot);
	if (!copy_ret)
		parsed = pkm_kunit_parse_kmes_event(buffer, written, &view);
	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);

	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, copy_ret, 0);
	KUNIT_ASSERT_TRUE(test, parsed);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_continuous_audit_schema_op(
				  test, &view, "file.permission",
				  PKM_KUNIT_FILE_READ_DATA,
				  PKM_KUNIT_FILE_READ_DATA,
				  PKM_KUNIT_FILE_READ_DATA, true,
				  PKM_KUNIT_PIP_TYPE_PROTECTED,
				  PKM_KUNIT_PIP_TRUST_TEST, 4417));
}


static void pkm_kunit_fchdir_snapshot_requires_traverse(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_TRAVERSE, 0,
				MAY_EXEC | MAY_CHDIR),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, 0,
				MAY_EXEC | MAY_CHDIR),
			-EACCES);
}


static void pkm_kunit_file_write_intent_append_and_positioned(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0, 0, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND, 0,
				false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				(u32)RWF_APPEND, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0, 0, true),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND, 0,
				true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				(u32)RWF_APPEND, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, 0, 0, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				0, 0, 0, 0, true),
			0);
}


static void pkm_kunit_file_write_intent_noappend_fails_closed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				(u32)RWF_NOAPPEND, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, O_APPEND,
				(u32)RWF_NOAPPEND, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_write_intent_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				(u32)RWF_APPEND | (u32)RWF_NOAPPEND, false),
			-EACCES);
}


static void pkm_kunit_file_write_intent_marker_drives_permission(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_write_intent(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				(u32)RWF_APPEND, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_write_intent(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				(u32)RWF_NOAPPEND, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_write_intent(
				1, PKM_KUNIT_FILE_WRITE_DATA, 0, 0, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_write_intent_mismatch(),
			-EACCES);
}


static void pkm_kunit_file_metadata_getattr_snapshot(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_GETATTR, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_FILE_METADATA_GETATTR, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_STATFS, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_GET,
				NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				0, 0, PKM_KACS_KUNIT_FILE_METADATA_GETATTR,
				NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_null(
				PKM_KACS_KUNIT_FILE_METADATA_GETATTR, NULL),
			-EACCES);
}


static void pkm_kunit_file_metadata_setattr_snapshot(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, KACS_ACCESS_WRITE_DAC,
				PKM_KACS_KUNIT_FILE_METADATA_CHMOD, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_CHMOD, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, KACS_ACCESS_WRITE_OWNER,
				PKM_KACS_KUNIT_FILE_METADATA_CHOWN, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, KACS_ACCESS_WRITE_DAC,
				PKM_KACS_KUNIT_FILE_METADATA_CHOWN, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_UTIMENS, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_UTIMENS, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_SET,
				NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				0, 0, PKM_KACS_KUNIT_FILE_METADATA_CHOWN,
				NULL),
			0);
}


static void pkm_kunit_file_metadata_marker_clears_after_dentry_hook(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_marker_clears(),
			0);
}


static void pkm_kunit_file_metadata_xattr_snapshot(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				"user.test"),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				"user.test"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET,
				"user.test"),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET,
				"user.test"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE,
				"user.test"),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET,
				XATTR_NAME_CAPS),
			-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE,
				XATTR_NAME_CAPS),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE,
				XATTR_NAME_CAPS),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, 0,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_LIST,
				NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				0, 0,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				"user.test"),
			0);
}


static void pkm_kunit_file_metadata_xattr_protected_names(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_SD_ADMIN_MASK,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				"security.peios.sd"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_SD_ADMIN_MASK,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET,
				"security.peios.sd"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_SD_ADMIN_MASK,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE,
				"security.peios.sd"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				XATTR_NAME_POSIX_ACL_ACCESS),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET,
				XATTR_NAME_POSIX_ACL_ACCESS),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_snapshot(
				1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE,
				XATTR_NAME_POSIX_ACL_DEFAULT),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_null(
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				"user.test"),
			-EACCES);
}


static void pkm_kunit_file_metadata_opath_semantics(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_GETATTR, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_STATFS, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_CHMOD, NULL),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_CHOWN, NULL),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_GET,
				NULL),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_SET,
				NULL),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET,
				"user.test"),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET,
				"user.test"),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_metadata_opath(
				PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE,
				"user.test"),
			-EBADF);
}


static void pkm_kunit_path_metadata_getattr_live(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_GETATTR, 0,
				NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_GET,
				0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_PATH_METADATA_GETATTR, 0,
				NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_path_metadata_live(
				NULL, 0, PKM_KACS_KUNIT_FILE_SD_MISSING,
				PKM_KACS_KUNIT_PATH_METADATA_GETATTR, 0,
				NULL),
			-EACCES);
}


static void pkm_kunit_path_metadata_setattr_live(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				KACS_ACCESS_WRITE_DAC,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHMOD,
				0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHMOD,
				0, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				KACS_ACCESS_WRITE_OWNER,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHOWN,
				0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_path_metadata_live(
				NULL, 0, PKM_KACS_KUNIT_FILE_SD_MISSING,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHOWN,
				0, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_UTIMENS,
				0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_TRUNCATE,
				0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_SETATTR_TRUNCATE,
				0, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_SET,
				0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
				PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_SET,
				0, NULL),
			-EACCES);
}


static void pkm_kunit_path_metadata_xattr_live(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_GET, 0,
				"user.test"),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_GET, 0,
				"user.test"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET, 0,
				"user.test"),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET, 0,
				"user.test"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_REMOVE, 0,
				"user.test"),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET, 0,
				XATTR_NAME_CAPS),
			-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_REMOVE, 0,
				XATTR_NAME_CAPS),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_REMOVE, 0,
				XATTR_NAME_CAPS),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				0, PKM_KACS_KUNIT_PATH_METADATA_XATTR_LIST,
				0, NULL),
			0);
}


static void pkm_kunit_path_metadata_xattr_protected_names(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_SD_ADMIN_MASK,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_GET, 0,
				"security.peios.sd"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_SD_ADMIN_MASK,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET, 0,
				"security.peios.sd"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_SD_ADMIN_MASK,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_REMOVE, 0,
				"security.peios.sd"),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_GET, 0,
				XATTR_NAME_POSIX_ACL_ACCESS),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET, 0,
				XATTR_NAME_POSIX_ACL_ACCESS),
			-EACCES);
}


static void pkm_kunit_path_metadata_access_live(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_PATH_METADATA_ACCESS, 0,
				NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_PATH_METADATA_ACCESS,
				MAY_READ, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PATH_METADATA_ACCESS,
				MAY_WRITE, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_EXECUTE,
				PKM_KACS_KUNIT_PATH_METADATA_ACCESS,
				MAY_EXEC, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_path_metadata_with_mask(
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_PATH_METADATA_ACCESS,
				MAY_READ | MAY_EXEC, NULL),
			-EACCES);
}


static void pkm_kunit_inode_permission_traverse_live(struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_TRAVERSE,
				MAY_EXEC),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				MAY_EXEC),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_TRAVERSE,
				MAY_READ),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				MAY_EXEC | MAY_OPEN),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				MAY_EXEC | MAY_ACCESS),
			0);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_inode_permission_pathname_socket_write(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mode(
				subject_token, PKM_KUNIT_FILE_WRITE_DATA,
				S_IFSOCK, MAY_WRITE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mode(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				S_IFSOCK, MAY_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mode(
				subject_token, PKM_KUNIT_FILE_WRITE_DATA,
				S_IFSOCK, MAY_WRITE | MAY_NOT_BLOCK),
			-ECHILD);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_inode_permission_change_notify_bypass(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_inode_permission_live(
				NULL, 0, PKM_KACS_KUNIT_FILE_SD_MISSING,
				KACS_MOUNT_POLICY_DENY_MISSING,
				subject_token, MAY_EXEC),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_CHANGE_NOTIFY_PRIVILEGE);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_inode_permission_chdir_requires_traverse(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				MAY_EXEC | MAY_CHDIR),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_TRAVERSE,
				MAY_EXEC | MAY_CHDIR),
			0);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_inode_permission_nonblocking_retries(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_TRAVERSE,
				MAY_EXEC | MAY_NOT_BLOCK),
			-ECHILD);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_check_inode_permission_with_mask(
				subject_token, PKM_KUNIT_FILE_TRAVERSE,
				MAY_EXEC),
			0);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_inode_permission_unmanaged_skips(struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_inode_permission_live(
				NULL, 0, PKM_KACS_KUNIT_FILE_SD_MISSING,
				KACS_MOUNT_POLICY_UNMANAGED,
				subject_token, MAY_EXEC),
			0);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_open_by_handle_requires_change_notify(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *privileged_token;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_open_by_handle_for_subject(
				subject_token),
			-EPERM);
	kacs_rust_token_drop(subject_token);

	privileged_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, privileged_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(privileged_token,
							 &before));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_open_by_handle_for_subject(
				privileged_token),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(privileged_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_CHANGE_NOTIFY_PRIVILEGE);
	kacs_rust_token_drop(privileged_token);
}


static void pkm_kunit_namespace_create_rights_and_sd(struct kunit *test)
{
	const void *subject_token;
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_ASSERT_EQ(test,
			pkm_kunit_namespace_parent_op(
				subject_token, PKM_KUNIT_FILE_ADD_FILE,
				PKM_KACS_KUNIT_NAMESPACE_CREATE_FILE,
				&created_sd, &created_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, created_sd);
	KUNIT_EXPECT_GT(test, created_sd_len, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_sd_bytes(created_sd, created_sd_len),
			0);
	pkm_kacs_free((void *)created_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_parent_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_NAMESPACE_CREATE_FILE, NULL,
				NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_parent_op(
				subject_token, PKM_KUNIT_FILE_ADD_SUBDIRECTORY,
				PKM_KACS_KUNIT_NAMESPACE_MKDIR, NULL, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_parent_op(
				subject_token, PKM_KUNIT_FILE_ADD_FILE,
				PKM_KACS_KUNIT_NAMESPACE_MKDIR, NULL, NULL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_parent_op(
				subject_token, PKM_KUNIT_FILE_ADD_FILE,
				PKM_KACS_KUNIT_NAMESPACE_MKNOD, NULL, NULL),
			0);
}


static void pkm_kunit_namespace_mknod_special_modes_fail_closed(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;
	static const umode_t supported_modes[] = {
		S_IFIFO,
		S_IFSOCK,
		S_IFCHR,
		S_IFBLK,
	};
	static const umode_t unsupported_modes[] = {
		0,
		S_IFREG,
		S_IFDIR,
		S_IFLNK,
		S_IFMT,
	};
	size_t i;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(supported_modes); i++) {
		KUNIT_EXPECT_EQ(test,
				pkm_kunit_namespace_mknod_mode_op(
					subject_token, PKM_KUNIT_FILE_ADD_FILE,
					supported_modes[i],
					i == 0 ? &created_sd : NULL,
					i == 0 ? &created_sd_len : NULL),
				0);
	}
	KUNIT_ASSERT_NOT_NULL(test, created_sd);
	KUNIT_EXPECT_GT(test, created_sd_len, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_sd_bytes(created_sd, created_sd_len),
			0);
	pkm_kacs_free((void *)created_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_mknod_mode_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				S_IFIFO, NULL, NULL),
			-EACCES);

	for (i = 0; i < ARRAY_SIZE(unsupported_modes); i++) {
		KUNIT_EXPECT_EQ(test,
				pkm_kunit_namespace_mknod_mode_op(
					subject_token, PKM_KUNIT_FILE_ADD_FILE,
					unsupported_modes[i], NULL, NULL),
				-EOPNOTSUPP);
	}
}


static void pkm_kunit_namespace_symlink_requires_privilege(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *privileged_token;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_parent_op(
				subject_token, PKM_KUNIT_FILE_ADD_FILE,
				PKM_KACS_KUNIT_NAMESPACE_SYMLINK, NULL,
				NULL),
			-EPERM);
	kacs_rust_token_drop(subject_token);

	privileged_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, privileged_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(privileged_token,
							 &before));
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_parent_op(
				privileged_token, PKM_KUNIT_FILE_ADD_FILE,
				PKM_KACS_KUNIT_NAMESPACE_SYMLINK, NULL,
				NULL),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(privileged_token,
							 &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used &
				PKM_KUNIT_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE,
			PKM_KUNIT_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE);
	KUNIT_EXPECT_EQ(test,
			before.privileges_used &
				PKM_KUNIT_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE,
			0ULL);
	kacs_rust_token_drop(privileged_token);
}


static void pkm_kunit_namespace_link_requires_parent_and_source(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_link_op(
				subject_token,
				PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KUNIT_FILE_ADD_FILE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_link_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_ADD_FILE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_link_op(
				subject_token,
				PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
				PKM_KUNIT_FILE_READ_DATA),
			-EACCES);
}


static void pkm_kunit_namespace_unlink_delete_duality(struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_delete_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_NAMESPACE_UNLINK, S_IFREG),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_delete_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_DELETE_CHILD,
				PKM_KACS_KUNIT_NAMESPACE_UNLINK, S_IFREG),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_delete_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_READ_ATTRIBUTES,
				PKM_KACS_KUNIT_NAMESPACE_UNLINK, S_IFREG),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_delete_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KACS_KUNIT_NAMESPACE_RMDIR, S_IFDIR),
			0);
}


static void pkm_kunit_namespace_rename_checks_required_edges(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_ADD_FILE, 0, false, S_IFREG),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_DELETE_CHILD,
				PKM_KUNIT_FILE_ADD_FILE, 0, false, S_IFREG),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_READ_DATA, 0, false, S_IFREG),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_ADD_FILE, PKM_KUNIT_FILE_READ_DATA,
				true, S_IFREG),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_ADD_FILE, KACS_ACCESS_DELETE,
				true, S_IFREG),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_ADD_FILE, 0, false, S_IFDIR),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_op(
				subject_token, KACS_ACCESS_DELETE,
				PKM_KUNIT_FILE_READ_DATA,
				PKM_KUNIT_FILE_ADD_SUBDIRECTORY, 0, false,
				S_IFDIR),
			0);
}


static void pkm_kunit_namespace_readlink_requires_read_data(struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_readlink_op(
				subject_token, PKM_KUNIT_FILE_READ_DATA),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_readlink_op(
				subject_token, PKM_KUNIT_FILE_READ_ATTRIBUTES),
			-EACCES);
}


static void pkm_kunit_namespace_whiteout_flags_native(struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	/* A non-whiteout rename short-circuits to 0 in this hook. */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_flags_op(
				subject_token, KACS_MOUNT_POLICY_DENY_MISSING,
				PKM_KUNIT_FILE_SD_ADMIN_MASK, 0),
			0);

	/*
	 * Managed RENAME_WHITEOUT is authorized natively (no longer refused):
	 * FILE_ADD_FILE on the source parent grants the whiteout sentinel.
	 */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_flags_op(
				subject_token, KACS_MOUNT_POLICY_DENY_MISSING,
				PKM_KUNIT_FILE_ADD_FILE, RENAME_WHITEOUT),
			0);

	/*
	 * Fail closed: without FILE_ADD_FILE on the source parent the whole
	 * rename is denied before any inode is created.
	 */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_flags_op(
				subject_token, KACS_MOUNT_POLICY_DENY_MISSING,
				PKM_KUNIT_FILE_READ_DATA, RENAME_WHITEOUT),
			-EACCES);

	/* Unmanaged mounts remain outside FACS. */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_namespace_rename_flags_op(
				subject_token, KACS_MOUNT_POLICY_UNMANAGED,
				PKM_KUNIT_FILE_READ_DATA, RENAME_WHITEOUT),
			0);
}


static void pkm_kunit_file_ioctl_snapshot_read_classified(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, S_IFREG,
				FS_IOC_FIEMAP, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				FS_IOC_FIEMAP, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, S_IFREG,
				FIBMAP, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFREG,
				FIONREAD, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, S_IFREG,
				FS_IOC_GETFLAGS, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, S_IFREG,
				FIGETBSZ, false),
			-EACCES);
}


static void pkm_kunit_file_ioctl_snapshot_write_classified(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, S_IFREG,
				FS_IOC_SETFLAGS, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, S_IFREG,
				FS_IOC_SETFLAGS, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFREG,
				FICLONE, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				FICLONE, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				FS_IOC_RESVSP, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				FS_IOC_ZERO_RANGE, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, S_IFREG,
				FITRIM, false),
			0);
}


static void pkm_kunit_file_ioctl_snapshot_fdlocal_fallback_unmanaged(
	struct kunit *test)
{
	const unsigned int unclassified = 0x5a5a5a5aU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, 0, S_IFREG, FIONBIO, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				unclassified, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, S_IFREG,
				unclassified, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFIFO,
				FIONREAD, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, 0, S_IFCHR, unclassified, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				0, 0, S_IFREG, unclassified, false),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_file_ioctl_null(),
			-EACCES);
}


static void pkm_kunit_file_ioctl_snapshot_compat_aliases(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, S_IFREG,
				FS_IOC32_GETFLAGS, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, S_IFREG,
				FS_IOC32_GETFLAGS, true),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, S_IFREG,
				FS_IOC32_SETFLAGS, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, S_IFREG,
				FS_IOC32_SETFLAGS, false),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, S_IFREG,
				FS_IOC32_SETFLAGS, false),
			0);
#if defined(CONFIG_X86_64)
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				FS_IOC_RESVSP_32, true),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, S_IFREG,
				FS_IOC_ZERO_RANGE_32, true),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFREG,
				FS_IOC_ZERO_RANGE_32, true),
			0);
#endif
}


static void pkm_kunit_file_ioctl_snapshot_full_classification(
	struct kunit *test)
{
	static const struct pkm_kunit_ioctl_expectation none_rights[] = {
		{ FIOCLEX, S_IFREG, 0, 0, false },
		{ FIONCLEX, S_IFREG, 0, 0, false },
		{ FIONBIO, S_IFREG, 0, 0, false },
		{ FIOASYNC, S_IFREG, 0, 0, false },
	};
	static const struct pkm_kunit_ioctl_expectation read_data[] = {
		{ FIBMAP, S_IFREG, PKM_KUNIT_FILE_READ_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FS_IOC_FIEMAP, S_IFREG, PKM_KUNIT_FILE_READ_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FIONREAD, S_IFREG, PKM_KUNIT_FILE_READ_DATA,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
	};
	static const struct pkm_kunit_ioctl_expectation any_data[] = {
		{ FIONREAD, S_IFIFO, PKM_KUNIT_FILE_APPEND_DATA,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, false },
	};
	static const struct pkm_kunit_ioctl_expectation read_attrs[] = {
		{ FIGETBSZ, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FIOQSIZE, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GETFLAGS, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GETVERSION, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_FSGETXATTR, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GETFSLABEL, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GETFSUUID, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GETFSSYSFSPATH, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GETLBMD_CAP, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_GET_ENCRYPTION_PWSALT, S_IFREG,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, PKM_KUNIT_FILE_READ_DATA,
		  false },
		{ FS_IOC_GET_ENCRYPTION_POLICY, S_IFREG,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, PKM_KUNIT_FILE_READ_DATA,
		  false },
		{ FS_IOC_GET_ENCRYPTION_POLICY_EX, S_IFREG,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, PKM_KUNIT_FILE_READ_DATA,
		  false },
		{ FS_IOC_GET_ENCRYPTION_KEY_STATUS, S_IFREG,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, PKM_KUNIT_FILE_READ_DATA,
		  false },
		{ BLKGETSIZE64, S_IFREG, PKM_KUNIT_FILE_READ_ATTRIBUTES,
		  PKM_KUNIT_FILE_READ_DATA, false },
	};
	static const struct pkm_kunit_ioctl_expectation write_attrs[] = {
		{ FS_IOC_SETFLAGS, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
		{ FS_IOC_SETVERSION, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
		{ FS_IOC_FSSETXATTR, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
		{ FS_IOC_SETFSLABEL, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
		{ FS_IOC_SET_ENCRYPTION_POLICY, S_IFREG,
		  PKM_KUNIT_FILE_WRITE_ATTRIBUTES, PKM_KUNIT_FILE_WRITE_DATA,
		  false },
		{ FS_IOC_ADD_ENCRYPTION_KEY, S_IFREG,
		  PKM_KUNIT_FILE_WRITE_ATTRIBUTES, PKM_KUNIT_FILE_WRITE_DATA,
		  false },
		{ FS_IOC_REMOVE_ENCRYPTION_KEY, S_IFREG,
		  PKM_KUNIT_FILE_WRITE_ATTRIBUTES, PKM_KUNIT_FILE_WRITE_DATA,
		  false },
		{ FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS, S_IFREG,
		  PKM_KUNIT_FILE_WRITE_ATTRIBUTES, PKM_KUNIT_FILE_WRITE_DATA,
		  false },
		{ FIFREEZE, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
		{ FITHAW, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
		{ FITRIM, S_IFREG, PKM_KUNIT_FILE_WRITE_ATTRIBUTES,
		  PKM_KUNIT_FILE_WRITE_DATA, false },
	};
	static const struct pkm_kunit_ioctl_expectation append_or_write[] = {
		{ FS_IOC_RESVSP, S_IFREG, PKM_KUNIT_FILE_APPEND_DATA,
		  PKM_KUNIT_FILE_READ_DATA, false },
		{ FS_IOC_RESVSP64, S_IFREG, PKM_KUNIT_FILE_APPEND_DATA,
		  PKM_KUNIT_FILE_READ_DATA, false },
	};
	static const struct pkm_kunit_ioctl_expectation write_data[] = {
		{ FS_IOC_UNRESVSP, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FS_IOC_UNRESVSP64, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FS_IOC_ZERO_RANGE, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FICLONE, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FICLONERANGE, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ FIDEDUPERANGE, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
		{ BLKFLSBUF, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, false },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(none_rights); i++)
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_file_ioctl_snapshot(
					1, none_rights[i].allowed_access,
					none_rights[i].mode, none_rights[i].cmd,
					none_rights[i].compat),
				0);
	for (i = 0; i < ARRAY_SIZE(read_data); i++)
		pkm_kunit_expect_ioctl_access(test, &read_data[i]);
	for (i = 0; i < ARRAY_SIZE(any_data); i++)
		pkm_kunit_expect_ioctl_access(test, &any_data[i]);
	for (i = 0; i < ARRAY_SIZE(read_attrs); i++)
		pkm_kunit_expect_ioctl_access(test, &read_attrs[i]);
	for (i = 0; i < ARRAY_SIZE(write_attrs); i++)
		pkm_kunit_expect_ioctl_access(test, &write_attrs[i]);
	for (i = 0; i < ARRAY_SIZE(append_or_write); i++)
		pkm_kunit_expect_ioctl_access(test, &append_or_write[i]);
	for (i = 0; i < ARRAY_SIZE(write_data); i++)
		pkm_kunit_expect_ioctl_access(test, &write_data[i]);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFREG,
				FS_IOC_RESVSP, false),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFREG,
				FS_IOC_RESVSP64, false),
			0);
}


static void pkm_kunit_file_ioctl_snapshot_compat_alias_matrix(
	struct kunit *test)
{
	static const struct pkm_kunit_ioctl_expectation aliases[] = {
		{ FS_IOC32_GETFLAGS, S_IFREG,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, PKM_KUNIT_FILE_READ_DATA,
		  true },
		{ FS_IOC32_GETVERSION, S_IFREG,
		  PKM_KUNIT_FILE_READ_ATTRIBUTES, PKM_KUNIT_FILE_READ_DATA,
		  true },
		{ FS_IOC32_SETFLAGS, S_IFREG,
		  PKM_KUNIT_FILE_WRITE_ATTRIBUTES, PKM_KUNIT_FILE_WRITE_DATA,
		  true },
		{ FS_IOC32_SETVERSION, S_IFREG,
		  PKM_KUNIT_FILE_WRITE_ATTRIBUTES, PKM_KUNIT_FILE_WRITE_DATA,
		  true },
#if defined(CONFIG_X86_64)
		{ FS_IOC_RESVSP_32, S_IFREG, PKM_KUNIT_FILE_APPEND_DATA,
		  PKM_KUNIT_FILE_READ_DATA, true },
		{ FS_IOC_RESVSP64_32, S_IFREG, PKM_KUNIT_FILE_APPEND_DATA,
		  PKM_KUNIT_FILE_READ_DATA, true },
		{ FS_IOC_UNRESVSP_32, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, true },
		{ FS_IOC_UNRESVSP64_32, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, true },
		{ FS_IOC_ZERO_RANGE_32, S_IFREG, PKM_KUNIT_FILE_WRITE_DATA,
		  PKM_KUNIT_FILE_APPEND_DATA, true },
#endif
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(aliases); i++)
		pkm_kunit_expect_ioctl_access(test, &aliases[i]);

#if defined(CONFIG_X86_64)
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, S_IFREG,
				FS_IOC_RESVSP64_32, true),
			0);
#endif
}


static void pkm_kunit_file_ioctl_opath_denied(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_opath(FIONBIO, false),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_opath(FS_IOC_FIEMAP,
							      false),
			-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_opath(FS_IOC_SETFLAGS,
							      false),
			-EBADF);
#if defined(CONFIG_X86_64)
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_opath(
				FS_IOC32_GETFLAGS, true),
			-EBADF);
#endif
}


static void pkm_kunit_file_fcntl_snapshot_append_transitions(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				F_SETFL, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1,
				PKM_KUNIT_FILE_APPEND_DATA |
					PKM_KUNIT_FILE_WRITE_DATA,
				O_APPEND, F_SETFL, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, O_APPEND,
				F_SETFL, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				F_SETFL, O_APPEND),
			0);
}


static void pkm_kunit_file_fcntl_snapshot_noatime_transitions(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, 0,
				F_SETFL, O_NOATIME),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, 0,
				F_SETFL, O_NOATIME),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, O_NOATIME, F_SETFL, 0),
			0);
}


static void pkm_kunit_file_fcntl_snapshot_non_right_flags_and_unmanaged(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETFL,
				O_NONBLOCK | O_NDELAY | O_DIRECT),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				F_SETFL, O_APPEND | O_NONBLOCK | O_DIRECT),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				0, 0, O_APPEND, F_SETFL, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, O_APPEND,
				F_GETFL, 0),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_file_fcntl_null(),
			-EACCES);
}


static void pkm_kunit_file_fcntl_snapshot_tail_no_right_commands(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_CREATED_QUERY, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_DUPFD_CLOEXEC, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETFD, FD_CLOEXEC),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETOWN, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETSIG, 0),
			0);
}


static void pkm_kunit_file_fcntl_snapshot_tail_lock_commands(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETLK, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETLKW64, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETLEASE, F_WRLCK),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_SETDELEG, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_GETLK, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, 0, F_GETLK, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, 0,
				F_OFD_GETLK, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, 0,
				F_GETLK64, 0),
			0);
}


static void pkm_kunit_file_fcntl_snapshot_tail_attr_commands(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_GETLEASE, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, 0,
				F_GETLEASE, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_READ_ATTRIBUTES, 0,
				F_GET_SEALS, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, 0,
				F_SETPIPE_SZ, 4096),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, 0,
				F_SETPIPE_SZ, 4096),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_WRITE_ATTRIBUTES, 0,
				F_ADD_SEALS, F_SEAL_WRITE),
			0);
}


static void pkm_kunit_file_fcntl_snapshot_tail_notify_and_unknown(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_NOTIFY, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_NOTIFY, DN_MULTISHOT),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, 0, 0, F_NOTIFY, DN_CREATE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_LIST_DIRECTORY, 0,
				F_NOTIFY, DN_CREATE | DN_RENAME),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_LIST_DIRECTORY, 0,
				F_NOTIFY, 0x40000000UL),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				1, PKM_KUNIT_FILE_SD_ADMIN_MASK, 0,
				0xffffffffU, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fcntl_snapshot(
				0, 0, 0, 0xffffffffU, 0),
			0);
}


static void pkm_kunit_file_receive_scm_rights_allows_existing_fd(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_file_receive(), 0);
}


static void pkm_kunit_file_lock_snapshot_shared_and_exclusive(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, F_RDLCK),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, F_WRLCK),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA, F_WRLCK),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(1, 0,
								F_UNLCK),
			0);
}


static void pkm_kunit_file_lock_snapshot_denials_and_unmanaged(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA, F_RDLCK),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA, F_WRLCK),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(1, 0,
								0xffffU),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_lock_snapshot(0, 0,
								F_WRLCK),
			0);
}


static void pkm_kunit_file_truncate_snapshot_requires_write_data(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_truncate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_truncate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_truncate_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_truncate_snapshot(
				0, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_truncate_null(),
			-EACCES);
}


static void pkm_kunit_file_fallocate_snapshot_extend_modes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_ALLOCATE_RANGE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA,
				FALLOC_FL_ALLOCATE_RANGE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA,
				FALLOC_FL_KEEP_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_READ_DATA,
				FALLOC_FL_ALLOCATE_RANGE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				0, 0, FALLOC_FL_WRITE_ZEROES),
			0);
}


static void pkm_kunit_file_fallocate_snapshot_mutation_modes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_ZERO_RANGE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_COLLAPSE_RANGE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_INSERT_RANGE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_UNSHARE_RANGE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_KEEP_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_WRITE_ZEROES),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA,
				FALLOC_FL_ZERO_RANGE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA,
				FALLOC_FL_UNSHARE_RANGE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_APPEND_DATA,
				FALLOC_FL_WRITE_ZEROES),
			-EACCES);
}


static void pkm_kunit_file_fallocate_snapshot_unsupported_fail_closed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_WRITE_ZEROES | FALLOC_FL_KEEP_SIZE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_ZERO_RANGE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_snapshot(
				1, PKM_KUNIT_FILE_WRITE_DATA,
				FALLOC_FL_PUNCH_HOLE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_fallocate_null(),
			-EACCES);
}


static void pkm_kunit_open_process_token_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.access_mask = KACS_TOKEN_QUERY;

	fd = pkm_kacs_kunit_open_process_token_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_open_process_token_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.access_mask = KACS_TOKEN_QUERY;

	ret = pkm_kacs_kunit_open_process_token_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_open_process_token_denied_by_target_token_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(subject_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.access_mask = KACS_TOKEN_DUPLICATE;

	ret = pkm_kacs_kunit_open_process_token_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_open_process_token_denied_by_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.access_mask = KACS_TOKEN_QUERY;

	ret = pkm_kacs_kunit_open_process_token_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_open_process_token_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long fd;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.access_mask = KACS_TOKEN_QUERY;

	fd = pkm_kacs_kunit_open_process_token_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_open_process_token_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.access_mask = KACS_TOKEN_QUERY;

	ret = pkm_kacs_kunit_open_process_token_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_securityfs_self_token_inspection_query_only(
	struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = 19U,
		.attributes = KACS_PRIVILEGE_ATTR_ENABLED,
	};
	const void *effective_token;
	long fd;

	effective_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);

	fd = pkm_kacs_kunit_open_self_token_inspection_for_subject();
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, effective_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							     &entry),
			(long)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_securityfs_sessions_listing_success(struct kunit *test)
{
	static const u8 local_service_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0,
	};
	static const char auth_pkg[] = "Kerberos";
	u8 spec[64] = {};
	char expected[192];
	const void *subject_token;
	u8 *buf;
	u64 session_id = 0;
	size_t spec_len;
	size_t required = 0;
	size_t second_required = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec, 2, auth_pkg,
						local_service_sid,
						sizeof(local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, NULL, 0, &required),
			0L);
	KUNIT_ASSERT_GT(test, required, 0UL);

	buf = kunit_kzalloc(test, required + 1, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, buf, required, &second_required),
			0L);
	KUNIT_EXPECT_GT(test, second_required, 0UL);
	KUNIT_EXPECT_LE(test, second_required, required);

	snprintf(expected, sizeof(expected),
		 "session_id=%llu user_sid=010100000000000513000000 "
		 "logon_type=2 auth_package=4b65726265726f73 created_at=",
		 (unsigned long long)session_id);
	KUNIT_EXPECT_NOT_NULL(test,
			      strnstr((const char *)buf, expected,
				      second_required));
}


static void pkm_kunit_securityfs_sessions_listing_exact_lines(
	struct kunit *test)
{
	static const u8 local_service_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0,
	};
	static const char empty_auth_pkg[] = "";
	static const char utf8_auth_pkg[] = "P\303\251";
	u8 empty_spec[64] = {};
	u8 utf8_spec[64] = {};
	struct pkm_kacs_session_snapshot empty_snapshot = {};
	struct pkm_kacs_session_snapshot utf8_snapshot = {};
	char expected_empty[192];
	char expected_utf8[192];
	const void *subject_token;
	u64 empty_session_id = 0;
	u64 utf8_session_id = 0;
	size_t empty_spec_len;
	size_t utf8_spec_len;
	size_t required = 0;
	size_t written = 0;
	u8 *buf;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	empty_spec_len = pkm_kunit_build_session_spec(empty_spec, 3,
						      empty_auth_pkg,
						      local_service_sid,
						      sizeof(local_service_sid));
	KUNIT_ASSERT_GT(test, (long)empty_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, empty_spec, empty_spec_len,
				&empty_session_id),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(empty_session_id,
							 &empty_snapshot),
			0);

	utf8_spec_len = pkm_kunit_build_session_spec(utf8_spec, 8,
						     utf8_auth_pkg,
						     local_service_sid,
						     sizeof(local_service_sid));
	KUNIT_ASSERT_GT(test, (long)utf8_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, utf8_spec, utf8_spec_len,
				&utf8_session_id),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(utf8_session_id,
							 &utf8_snapshot),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, NULL, 0, &required),
			0L);
	KUNIT_ASSERT_GT(test, required, 0UL);

	buf = kunit_kzalloc(test, required, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, buf, required, &written),
			0L);
	KUNIT_ASSERT_LE(test, written, required);

	snprintf(expected_empty, sizeof(expected_empty),
		 "session_id=%llu user_sid=010100000000000513000000 "
		 "logon_type=3 auth_package= created_at=%llu\n",
		 (unsigned long long)empty_session_id,
		 (unsigned long long)empty_snapshot.created_at);
	snprintf(expected_utf8, sizeof(expected_utf8),
		 "session_id=%llu user_sid=010100000000000513000000 "
		 "logon_type=8 auth_package=50c3a9 created_at=%llu\n",
		 (unsigned long long)utf8_session_id,
		 (unsigned long long)utf8_snapshot.created_at);

	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(
				  buf, written, (const u8 *)expected_empty,
				  strlen(expected_empty)));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(
				  buf, written, (const u8 *)expected_utf8,
				  strlen(expected_utf8)));
}


static void pkm_kunit_securityfs_sessions_short_buffer(struct kunit *test)
{
	const void *subject_token;
	size_t required = 0;
	size_t second_required = 0;
	u8 *buf;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, NULL, 0, &required),
			0L);
	KUNIT_ASSERT_GT(test, required, 0UL);

	buf = kunit_kzalloc(test, required, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, buf, required - 1,
				&second_required),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, second_required, required);
}


static void pkm_kunit_securityfs_sessions_denies_anonymous(
	struct kunit *test)
{
	const void *anonymous_token = NULL;
	size_t required = 0;

	KUNIT_ASSERT_EQ(test,
			kacs_rust_create_anonymous_impersonation_token(
				&anonymous_token),
			0);
	KUNIT_ASSERT_NOT_NULL(test, anonymous_token);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				anonymous_token, NULL, 0, &required),
			(long)-EACCES);
	kacs_rust_token_drop(anonymous_token);
}


static void pkm_kunit_securityfs_sessions_denies_non_admin_user(
	struct kunit *test)
{
	const void *local_service_token;
	size_t required = 0;

	local_service_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, local_service_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				local_service_token, NULL, 0, &required),
			(long)-EACCES);
	kacs_rust_token_drop(local_service_token);
}


static void pkm_kunit_securityfs_sessions_null_required_fails_closed(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_read_securityfs_sessions_for_subject(
				subject_token, NULL, 0, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_file_sd_cache_population_from_valid_xattr(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_classify_file_sd_bytes(file_sd,
							      file_sd_len),
			PKM_KACS_KUNIT_FILE_SD_VALID);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_sd_cache_population_cas_loser_frees_copy(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	size_t live_len = 0;
	u32 first_installed = 0;
	u32 second_installed = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_file_sd_cache_cas_loser(
				file_sd, file_sd_len, &first_installed,
				&second_installed, &live_len),
			0);
	KUNIT_EXPECT_EQ(test, first_installed, 1U);
	KUNIT_EXPECT_EQ(test, second_installed, 0U);
	KUNIT_EXPECT_EQ(test, live_len, file_sd_len);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_sd_cache_population_corrupt_fails_closed(
	struct kunit *test)
{
	static const u8 invalid_sd[] = { 1, 0, 0, 0 };

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_classify_file_sd_bytes(
				invalid_sd, sizeof(invalid_sd)),
			PKM_KACS_KUNIT_FILE_SD_CORRUPT);
}


static void pkm_kunit_file_sd_cache_population_corrupt_emits_once(
	struct kunit *test)
{
	static const u8 invalid_sd[] = { 1, 0, 0, 0 };
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	long first_ret = 0;
	long second_ret = 0;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_corrupt_file_sd_population_twice(
				invalid_sd, sizeof(invalid_sd), &first_ret,
				&second_ret),
			0L);
	KUNIT_EXPECT_EQ(test, first_ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, second_ret, (long)-EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_kmes_event_type(test, &view,
							   "corrupt-sd"));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						   view.payload_len,
						   (const u8 *)"corrupt-sd",
						   sizeof("corrupt-sd") - 1));
}


static void pkm_kunit_stored_sd_validation_requires_owner(struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_make_sd_ownerless((u8 *)file_sd);

	KUNIT_EXPECT_EQ(test, kacs_rust_validate_sd_bytes(file_sd, file_sd_len),
			0);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_stored_sd_bytes(file_sd,
							   file_sd_len),
			-EINVAL);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_stored_sd_validation_accepts_null_group(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_make_sd_groupless((u8 *)file_sd);

	KUNIT_EXPECT_EQ(test, kacs_rust_validate_sd_bytes(file_sd, file_sd_len),
			0);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_stored_sd_bytes(file_sd,
							   file_sd_len),
			0);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_acl_builder_u16_boundary(struct kunit *test)
{
	size_t acl_len = 0;

	KUNIT_EXPECT_EQ(test,
			kacs_rust_kunit_build_single_opaque_acl_len(65524,
								    &acl_len),
			0);
	KUNIT_EXPECT_EQ(test, acl_len, (size_t)65532);

	acl_len = 123;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_kunit_build_single_opaque_acl_len(65528,
								    &acl_len),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, acl_len, (size_t)0);
}


static void pkm_kunit_file_sd_cache_population_ownerless_fails_closed(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_make_sd_ownerless((u8 *)file_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_classify_file_sd_bytes(file_sd,
							      file_sd_len),
			PKM_KACS_KUNIT_FILE_SD_CORRUPT);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_inode_raw_sd_xattr_hooks_deny_canonical_names(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_get(
				"security.peios.sd", 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_set(
				"security.peios.sd", 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_remove(
				"security.peios.sd", 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_get(
				"system.ntfs_security", 1),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_get(
				"system.ntfs_security", 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_get("user.other", 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_set(XATTR_NAME_CAPS,
							  0),
			-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_remove(XATTR_NAME_CAPS,
							     0),
			0);
}


static void pkm_kunit_inode_filecap_nonempty_set_denied_remove_allowed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_set_sized(
				XATTR_NAME_CAPS, 4, 0),
			-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_set_sized("user.other",
								4, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_sd_xattr_remove(XATTR_NAME_CAPS,
							     0),
			0);
}


static void pkm_kunit_inode_xattr_skipcap_defers_to_kacs(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_xattr_skipcap("security.peios.sd"),
			1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_xattr_skipcap(
				"security.capability"),
			1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_xattr_skipcap("security.other"),
			1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_inode_xattr_skipcap("user.other"),
			1);
}


static void pkm_kunit_inode_xattr_skipcap_null_fails_closed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_inode_xattr_skipcap(NULL), 0);
}


static void pkm_kunit_inode_misc_hooks_match_matrix(struct kunit *test)
{
	u8 result[256] = {};
	size_t written = 0;

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_inode_follow_link(), 0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_inode_set_acl(), -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_inode_remove_acl(),
			-EOPNOTSUPP);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_inode_getsecurity_sd(
				pkm_kunit_everyone_read_sd,
				sizeof(pkm_kunit_everyone_read_sd),
				"peios.sd", result, sizeof(result), &written),
			0);
	KUNIT_EXPECT_EQ(test, written, sizeof(pkm_kunit_everyone_read_sd));
	pkm_kunit_expect_bytes_eq(test, result, written,
				  pkm_kunit_everyone_read_sd,
				  sizeof(pkm_kunit_everyone_read_sd));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_inode_getsecurity_sd(
				pkm_kunit_everyone_read_sd,
				sizeof(pkm_kunit_everyone_read_sd),
				"selinux", result, sizeof(result), &written),
			-EOPNOTSUPP);
}


static void pkm_kunit_file_open_read_stamps_granted_subset(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 expected;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	expected = PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_READ_ATTRIBUTES |
		   PKM_KUNIT_FILE_READ_EA | KACS_ACCESS_READ_CONTROL |
		   KACS_ACCESS_WRITE_DAC;
	file_sd = pkm_kunit_create_precise_file_sd(subject_token, expected,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, expected);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_read_accepts_null_group_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 expected;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	expected = PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_READ_ATTRIBUTES |
		   PKM_KUNIT_FILE_READ_EA | KACS_ACCESS_READ_CONTROL |
		   KACS_ACCESS_WRITE_DAC;
	file_sd = pkm_kunit_create_precise_file_sd(subject_token, expected,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_make_sd_groupless((u8 *)file_sd);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, expected);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_sacl_audit_emits_kmes(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_ptr = pkm_kunit_system_file_read_audit_sd,
		.target_file_sd_len = sizeof(pkm_kunit_system_file_read_audit_sd),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	u32 granted = 0;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4303, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_NE(test, granted, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_KACS, "access-audit",
				sizeof("access-audit") - 1, buffer,
				PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"access-audit",
				  sizeof("access-audit") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PROCESS_PATH) - 1));
}


static void pkm_kunit_file_open_caap_replace_preserves_cached_grant(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_ptr = pkm_kunit_caap_file_read_sd,
		.target_file_sd_len = sizeof(pkm_kunit_caap_file_read_sd),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	u8 spec[64];
	size_t spec_len;
	u32 cached_grant = 0;
	long ret;

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_file_read_dacl,
		sizeof(pkm_kunit_caap_file_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	ret = pkm_kacs_kunit_open_file_for_subject(&args, &cached_grant);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test,
			cached_grant &
				(PKM_KUNIT_FILE_READ_DATA |
				 PKM_KUNIT_FILE_READ_ATTRIBUTES),
			PKM_KUNIT_FILE_READ_DATA |
				PKM_KUNIT_FILE_READ_ATTRIBUTES);

	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_permission_snapshot(
				1, cached_grant, 0, MAY_READ),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_file_open_caap_replace_narrows_future_open(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_ptr = pkm_kunit_caap_file_read_sd,
		.target_file_sd_len = sizeof(pkm_kunit_caap_file_read_sd),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0;

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_file_read_dacl,
		sizeof(pkm_kunit_caap_file_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_NE(test, granted, 0U);

	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_file_open_cached_grant_survives_sd_change(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.file_mode = FMODE_READ,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.mount_policy_override = KACS_MOUNT_POLICY_DENY_MISSING,
	};
	const void *subject_token;
	const u8 *initial_sd;
	const u8 *replacement_sd;
	size_t initial_sd_len = 0;
	size_t replacement_sd_len = 0;
	u32 cached_grant = 0;
	u32 new_open_grant = 0;
	long new_open_ret = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	initial_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_READ_ATTRIBUTES |
			PKM_KUNIT_FILE_READ_EA | KACS_ACCESS_READ_CONTROL |
			KACS_ACCESS_WRITE_DAC,
		&initial_sd_len);
	replacement_sd = pkm_kunit_create_precise_file_sd(
		subject_token, 0, &replacement_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, initial_sd);
	KUNIT_ASSERT_NOT_NULL(test, replacement_sd);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = initial_sd;
	args.target_file_sd_len = initial_sd_len;
	args.input_sd_ptr = replacement_sd;
	args.input_sd_len = replacement_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_open_then_change_sd_for_subject(
				&args, &cached_grant, &new_open_ret,
				&new_open_grant),
			0L);
	KUNIT_EXPECT_TRUE(test,
			  (cached_grant & PKM_KUNIT_FILE_READ_DATA) != 0);
	KUNIT_EXPECT_EQ(test, new_open_ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, new_open_grant, 0U);

	pkm_kacs_free((void *)replacement_sd);
	pkm_kacs_free((void *)initial_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_uses_current_psb_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_ptr = pkm_kunit_everyone_file_read_pip_sd,
		.target_file_sd_len = sizeof(pkm_kunit_everyone_file_read_pip_sd),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust),
			0);

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted,
			PKM_KUNIT_FILE_READ_DATA |
				PKM_KUNIT_FILE_READ_ATTRIBUTES |
				PKM_KUNIT_FILE_READ_EA |
				KACS_ACCESS_READ_CONTROL |
				KACS_ACCESS_WRITE_DAC |
				KACS_ACCESS_WRITE_OWNER);

	pkm_kacs_kunit_set_current_pip_context(0, 0);
	granted = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			(long)-EACCES);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
}


static void pkm_kunit_file_open_append_trunc_stamps_expected_core(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_WRITE,
		.file_flags = O_APPEND | O_TRUNC,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 expected;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	expected = PKM_KUNIT_FILE_APPEND_DATA | PKM_KUNIT_FILE_WRITE_DATA |
		   PKM_KUNIT_FILE_READ_ATTRIBUTES |
		   KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC;
	file_sd = pkm_kunit_create_precise_file_sd(subject_token, expected,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, expected);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_append_modifier_core_matrix(
	struct kunit *test)
{
	static const struct {
		u32 file_mode;
		u32 file_flags;
		u32 granted_mask;
	} cases[] = {
		{
			.file_mode = FMODE_READ,
			.file_flags = O_APPEND,
			.granted_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
		{
			.file_mode = FMODE_WRITE,
			.file_flags = O_APPEND,
			.granted_mask = PKM_KUNIT_FILE_APPEND_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
		{
			.file_mode = FMODE_READ | FMODE_WRITE,
			.file_flags = O_APPEND,
			.granted_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_APPEND_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
		{
			.file_mode = FMODE_WRITE,
			.file_flags = O_APPEND | O_TRUNC,
			.granted_mask = PKM_KUNIT_FILE_APPEND_DATA |
					PKM_KUNIT_FILE_WRITE_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
	};
	const void *subject_token;
	size_t i;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_kacs_kunit_file_open_args args = {
			.subject_token = subject_token,
			.file_mode = cases[i].file_mode,
			.file_flags = cases[i].file_flags,
			.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		};
		const u8 *file_sd;
		size_t file_sd_len = 0;
		u32 granted = 0;
		u32 expected;

		file_sd = pkm_kunit_create_precise_file_sd(
			subject_token, cases[i].granted_mask, &file_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, file_sd);
		args.target_file_sd_ptr = file_sd;
		args.target_file_sd_len = file_sd_len;

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_open_file_for_subject(
					&args, &granted),
				0L);
		expected = cases[i].granted_mask | KACS_ACCESS_READ_CONTROL |
			   KACS_ACCESS_WRITE_DAC;
		KUNIT_EXPECT_EQ(test, granted, expected);
		if ((cases[i].file_flags & O_APPEND) != 0 &&
		    (cases[i].file_mode & FMODE_WRITE) == 0)
			KUNIT_EXPECT_EQ(test,
					granted & PKM_KUNIT_FILE_APPEND_DATA,
					0U);

		pkm_kacs_free((void *)file_sd);
	}

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_core_mode_matrix(struct kunit *test)
{
	static const struct {
		u32 file_mode;
		u32 file_flags;
		u32 grant_mask;
	} cases[] = {
		{
			.file_mode = FMODE_WRITE,
			.grant_mask = PKM_KUNIT_FILE_WRITE_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
		{
			.file_mode = FMODE_READ | FMODE_WRITE,
			.grant_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_WRITE_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
		{
			.file_mode = FMODE_READ,
			.file_flags = O_TRUNC,
			.grant_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_WRITE_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
		},
	};
	const void *subject_token;
	size_t i;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_kacs_kunit_file_open_args args = {
			.subject_token = subject_token,
			.file_mode = cases[i].file_mode,
			.file_flags = cases[i].file_flags,
			.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		};
		const u8 *file_sd;
		size_t file_sd_len = 0;
		u32 granted = 0;
		u32 expected;

		file_sd = pkm_kunit_create_precise_file_sd(
			subject_token, cases[i].grant_mask, &file_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, file_sd);
		args.target_file_sd_ptr = file_sd;
		args.target_file_sd_len = file_sd_len;

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_open_file_for_subject(
					&args, &granted),
				0L);
		expected = cases[i].grant_mask | KACS_ACCESS_READ_CONTROL |
			   KACS_ACCESS_WRITE_DAC;
		KUNIT_EXPECT_EQ(test, granted, expected);

		pkm_kacs_free((void *)file_sd);
	}

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_data_without_attributes_denies(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_READ_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_compat_subset_matrix(struct kunit *test)
{
	const u32 core = PKM_KUNIT_FILE_READ_DATA |
			 PKM_KUNIT_FILE_READ_ATTRIBUTES;
	const u32 optional_compat = PKM_KUNIT_FILE_READ_EA |
				    PKM_KUNIT_FILE_WRITE_ATTRIBUTES |
				    PKM_KUNIT_FILE_WRITE_EA |
				    KACS_ACCESS_WRITE_OWNER |
				    KACS_ACCESS_SYNCHRONIZE |
				    PKM_KUNIT_FILE_EXECUTE;
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	args.subject_token = subject_token;

	file_sd = pkm_kunit_create_precise_file_sd(subject_token, core,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted,
			core | KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	KUNIT_EXPECT_EQ(test, granted & optional_compat, 0U);
	pkm_kacs_free((void *)file_sd);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, core | optional_compat, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	granted = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted,
			core | optional_compat | KACS_ACCESS_READ_CONTROL |
				KACS_ACCESS_WRITE_DAC);
	pkm_kacs_free((void *)file_sd);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_special_node_core_matrix(struct kunit *test)
{
	static const struct {
		umode_t inode_mode;
		u32 file_mode;
		u32 grant_mask;
		u32 denied_compat_mask;
	} cases[] = {
		{
			.inode_mode = S_IFCHR,
			.file_mode = FMODE_READ,
			.grant_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.denied_compat_mask = PKM_KUNIT_FILE_EXECUTE,
		},
		{
			.inode_mode = S_IFBLK,
			.file_mode = FMODE_WRITE,
			.grant_mask = PKM_KUNIT_FILE_WRITE_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.denied_compat_mask = PKM_KUNIT_FILE_EXECUTE,
		},
		{
			.inode_mode = S_IFIFO,
			.file_mode = FMODE_READ | FMODE_WRITE,
			.grant_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_WRITE_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.denied_compat_mask = PKM_KUNIT_FILE_EXECUTE,
		},
		{
			.inode_mode = S_IFSOCK,
			.file_mode = FMODE_READ,
			.grant_mask = PKM_KUNIT_FILE_READ_DATA |
					PKM_KUNIT_FILE_READ_ATTRIBUTES,
			.denied_compat_mask = PKM_KUNIT_FILE_EXECUTE,
		},
	};
	const void *subject_token;
	size_t i;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_kacs_kunit_file_open_args args = {
			.subject_token = subject_token,
			.file_mode = cases[i].file_mode,
			.inode_mode = cases[i].inode_mode,
			.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		};
		const u8 *file_sd;
		size_t file_sd_len = 0;
		u32 granted = 0;
		u32 expected;

		file_sd = pkm_kunit_create_precise_file_sd(
			subject_token,
			cases[i].grant_mask | cases[i].denied_compat_mask,
			&file_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, file_sd);
		args.target_file_sd_ptr = file_sd;
		args.target_file_sd_len = file_sd_len;

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_open_file_for_subject(
					&args, &granted),
				0L);
		expected = cases[i].grant_mask | KACS_ACCESS_READ_CONTROL |
			   KACS_ACCESS_WRITE_DAC;
		KUNIT_EXPECT_EQ(test, granted, expected);
		KUNIT_EXPECT_EQ(test, granted & cases[i].denied_compat_mask,
				0U);

		pkm_kacs_free((void *)file_sd);
	}

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_special_node_read_core_matrix(
	struct kunit *test)
{
	static const umode_t inode_modes[] = {
		S_IFCHR,
		S_IFBLK,
		S_IFIFO,
		S_IFSOCK,
	};
	const u32 core = PKM_KUNIT_FILE_READ_DATA |
			 PKM_KUNIT_FILE_READ_ATTRIBUTES;
	const void *subject_token;
	size_t i;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(inode_modes); i++) {
		struct pkm_kacs_kunit_file_open_args args = {
			.subject_token = subject_token,
			.file_mode = FMODE_READ,
			.inode_mode = inode_modes[i],
			.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		};
		const u8 *file_sd;
		size_t file_sd_len = 0;
		u32 granted = 0;

		file_sd = pkm_kunit_create_precise_file_sd(
			subject_token, core, &file_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, file_sd);
		args.target_file_sd_ptr = file_sd;
		args.target_file_sd_len = file_sd_len;

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_open_file_for_subject(
					&args, &granted),
				0L);
		KUNIT_EXPECT_EQ(test, granted,
				core | KACS_ACCESS_READ_CONTROL |
					KACS_ACCESS_WRITE_DAC);

		pkm_kacs_free((void *)file_sd);
	}

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_opath_leaves_no_grant(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_PATH,
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 managed = 1U;
	u32 granted = 1234U;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_opath_for_subject(
				&args, &managed, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, managed, 0U);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_open_stamps_continuous_audit_mask(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_ptr = pkm_kunit_system_file_read_alarm_sd,
		.target_file_sd_len = sizeof(pkm_kunit_system_file_read_alarm_sd),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	u32 continuous_audit = 0;
	u32 granted = 0;

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject_audit(
				&args, &granted, &continuous_audit),
			0L);
	KUNIT_EXPECT_EQ(test, granted,
			PKM_KUNIT_FILE_READ_DATA |
				PKM_KUNIT_FILE_READ_ATTRIBUTES |
				PKM_KUNIT_FILE_READ_EA |
				KACS_ACCESS_READ_CONTROL |
				KACS_ACCESS_WRITE_DAC |
				KACS_ACCESS_WRITE_OWNER);
	KUNIT_EXPECT_EQ(test, continuous_audit, PKM_KUNIT_FILE_READ_DATA);
}


static void pkm_kunit_file_open_directory_read_stamps_expected_subset(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.inode_mode = S_IFDIR,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 expected;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	expected = PKM_KUNIT_FILE_READ_ATTRIBUTES |
		   PKM_KUNIT_FILE_EXECUTE |
		   PKM_KUNIT_FILE_READ_DATA |
		   KACS_ACCESS_READ_CONTROL |
		   KACS_ACCESS_WRITE_DAC;
	file_sd = pkm_kunit_create_precise_file_sd(subject_token, expected,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, expected);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_core_denial_fails_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   KACS_ACCESS_READ_CONTROL,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_open_directory_write_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_WRITE,
		.inode_mode = S_IFDIR,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_open_unmanaged_mount_leaves_no_grant(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_READ,
		.mount_policy_override = KACS_MOUNT_POLICY_UNMANAGED,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 1234U;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_open_sysfs_write_uses_live_gate(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.file_mode = FMODE_WRITE,
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.mount_magic = SYSFS_MAGIC,
	};
	const void *system_token;
	const void *admin_token;
	const void *local_token;
	u32 granted = 1234U;

	system_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	local_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, system_token);
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	KUNIT_ASSERT_NOT_NULL(test, local_token);

	args.subject_token = system_token;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	granted = 1234U;
	args.subject_token = admin_token;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	granted = 1234U;
	args.subject_token = local_token;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	args.file_mode = FMODE_READ;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_file_for_subject(&args, &granted),
			0L);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	kacs_rust_token_drop(system_token);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(local_token);
}


static void pkm_kunit_native_open_read_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;
	u32 file_mode = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, &file_mode),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_READ, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_WRITE, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_EXEC, 0U);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_append_only_sets_write_mode(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_APPEND_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;
	u32 file_mode = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, &file_mode),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_READ, 0U);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_WRITE, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_EXEC, 0U);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_caches_exact_requested_mask(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;
	u32 file_mode = 0;
	u32 broad_grant;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	broad_grant = PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA |
		      PKM_KUNIT_FILE_READ_ATTRIBUTES |
		      KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC;
	file_sd = pkm_kunit_create_precise_file_sd(subject_token, broad_grant,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, &file_mode),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_READ, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_WRITE, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_EXEC, 0U);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_maximum_allowed_with_read_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = KACS_ACCESS_MAXIMUM_ALLOWED |
				  PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;
	u32 file_mode = 0;
	u32 expected;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	expected = PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA |
		   PKM_KUNIT_FILE_READ_ATTRIBUTES | KACS_ACCESS_READ_CONTROL |
		   KACS_ACCESS_WRITE_DAC;
	file_sd = pkm_kunit_create_precise_file_sd(subject_token, expected,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, &file_mode),
			0L);
	KUNIT_EXPECT_EQ(test, granted, expected);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_READ, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_WRITE, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_EXEC, 0U);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_maximum_allowed_requires_mode_bit(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = KACS_ACCESS_MAXIMUM_ALLOWED,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_native_open_maximum_allowed_mode_bit_denied(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = KACS_ACCESS_MAXIMUM_ALLOWED |
				  PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_WRITE_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_execute_only_sets_exec_mode(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_EXECUTE,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;
	u32 file_mode = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, &file_mode),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_READ, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_WRITE, 0U);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_EXEC, 0U);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_directory_read_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_EXECUTE,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.inode_mode = S_IFDIR,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;
	u32 file_mode = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, &file_mode),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_READ, 0U);
	KUNIT_EXPECT_EQ(test, file_mode & FMODE_WRITE, 0U);
	KUNIT_EXPECT_NE(test, file_mode & FMODE_EXEC, 0U);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_special_nodes_use_file_rights(
	struct kunit *test)
{
	static const struct {
		umode_t mode;
		u32 desired_access;
		u32 expected_mode;
	} cases[] = {
		{ S_IFIFO, PKM_KUNIT_FILE_READ_DATA, FMODE_READ },
		{ S_IFCHR, PKM_KUNIT_FILE_WRITE_DATA, FMODE_WRITE },
		{ S_IFSOCK,
		  PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA,
		  FMODE_READ | FMODE_WRITE },
		{ S_IFBLK, PKM_KUNIT_FILE_APPEND_DATA, FMODE_WRITE },
	};
	const void *subject_token;
	size_t i;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_kacs_kunit_native_open_args args = {
			.desired_access = cases[i].desired_access,
			.create_disposition = KACS_DISPOSITION_OPEN,
			.inode_mode = cases[i].mode,
		};
		const u8 *file_sd;
		size_t file_sd_len = 0;
		u32 granted = 0;
		u32 status = 0;
		u32 file_mode = 0;

		file_sd = pkm_kunit_create_precise_file_sd(
			subject_token, args.desired_access, &file_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, file_sd);

		args.subject_token = subject_token;
		args.target_file_sd_ptr = file_sd;
		args.target_file_sd_len = file_sd_len;
		args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_native_open_for_subject(
					&args, &granted, &status, &file_mode),
				0L);
		KUNIT_EXPECT_EQ(test, granted, args.desired_access);
		KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);
		KUNIT_EXPECT_EQ(test,
				file_mode & (FMODE_READ | FMODE_WRITE),
				cases[i].expected_mode);
		KUNIT_EXPECT_EQ(test, file_mode & FMODE_EXEC, 0U);

		pkm_kacs_free((void *)file_sd);
	}

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_special_nodes_fail_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.inode_mode = S_IFIFO,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_READ_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);
	pkm_kacs_free((void *)file_sd);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_EXECUTE, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.desired_access = PKM_KUNIT_FILE_EXECUTE;
	args.inode_mode = S_IFCHR;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);
	pkm_kacs_free((void *)file_sd);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.desired_access = PKM_KUNIT_FILE_READ_DATA |
			      PKM_KUNIT_FILE_WRITE_DATA;
	args.create_disposition = KACS_DISPOSITION_OVERWRITE;
	args.inode_mode = S_IFSOCK;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EOPNOTSUPP);
	pkm_kacs_free((void *)file_sd);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_READ_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.desired_access = PKM_KUNIT_FILE_READ_DATA;
	args.create_disposition = KACS_DISPOSITION_OPEN;
	args.inode_mode = S_IFMT;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);
	pkm_kacs_free((void *)file_sd);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_partial_denial_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_READ_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_requires_data_or_execute(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = KACS_ACCESS_READ_CONTROL,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_native_open_invalid_disposition_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE_IF + 1U,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_native_open_reserved_create_options_fail_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args open_args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = 0x80000000U,
	};
	struct pkm_kacs_kunit_native_open_args flag_args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.flags = 0x80000000U,
	};
	struct pkm_kacs_kunit_native_create_args create_args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
		.create_options = 0x80000000U,
	};
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&open_args, NULL, NULL, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&flag_args, NULL, NULL, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&create_args, &created_sd, &created_sd_len,
				NULL, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_NULL(test, created_sd);
	KUNIT_EXPECT_EQ(test, created_sd_len, (size_t)0);
}


static void pkm_kunit_native_open_bad_padding_fails_closed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_prepare_open_with_padding(1U),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_prepare_open_with_padding(~0U),
			(long)-EINVAL);
}


static void pkm_kunit_native_open_missing_noncreate_dispositions_fail(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_missing_existing_result(
				KACS_DISPOSITION_OPEN),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_missing_existing_result(
				KACS_DISPOSITION_OVERWRITE),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_missing_existing_result(
				KACS_DISPOSITION_OPEN_IF),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_missing_existing_result(
				KACS_DISPOSITION_OVERWRITE_IF),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_missing_existing_result(
				KACS_DISPOSITION_SUPERSEDE),
			0L);
}


static void pkm_kunit_native_open_delete_on_close_existing_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA |
							   KACS_ACCESS_DELETE,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_EQ(test, result.reopen_result, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, result.pending_before_release, 1U);
	KUNIT_EXPECT_EQ(test, result.pending_after_release, 0U);
	KUNIT_EXPECT_EQ(test, result.unlink_calls, 1U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_delete_on_close_parent_fallback_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *parent_sd;
	size_t file_sd_len = 0;
	size_t parent_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_DELETE_CHILD, &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_EQ(test, result.reopen_result, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, result.unlink_calls, 1U);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_delete_on_close_dup_lineage_final_close(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA |
							   KACS_ACCESS_DELETE,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_dup_lineage_for_subject(
				&args, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_EQ(test, result.pending_before_release, 1U);
	KUNIT_EXPECT_EQ(test, result.pending_after_duplicate_close, 1U);
	KUNIT_EXPECT_EQ(test, result.unlink_calls_after_duplicate_close, 0U);
	KUNIT_EXPECT_EQ(test, result.pending_after_release, 0U);
	KUNIT_EXPECT_EQ(test, result.unlink_calls, 1U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_if_delete_on_close_existing_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN_IF,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA |
							   KACS_ACCESS_DELETE,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_OPENED);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_EQ(test, result.reopen_result, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, result.pending_before_release, 1U);
	KUNIT_EXPECT_EQ(test, result.pending_after_release, 0U);
	KUNIT_EXPECT_EQ(test, result.unlink_calls, 1U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_overwrite_delete_on_close_existing_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_WRITE_DATA |
							   KACS_ACCESS_DELETE,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_OVERWRITTEN);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_EQ(test, result.reopen_result, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, result.pending_before_release, 1U);
	KUNIT_EXPECT_EQ(test, result.pending_after_release, 0U);
	KUNIT_EXPECT_EQ(test, result.unlink_calls, 1U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_create_delete_on_close_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *parent_sd;
	size_t parent_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_DELETE_CHILD,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_CREATED);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_EQ(test, result.reopen_result, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, result.pending_before_release, 1U);
	KUNIT_EXPECT_EQ(test, result.pending_after_release, 0U);
	KUNIT_EXPECT_EQ(test, result.unlink_calls, 1U);

	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_open_delete_on_close_without_delete_denies(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *parent_sd;
	size_t file_sd_len = 0;
	size_t parent_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     KACS_ACCESS_READ_CONTROL,
						     &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			(long)-EACCES);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_delete_on_close_directory_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_EXECUTE,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = KACS_CREATE_OPT_DELETE_ON_CLOSE,
		.inode_mode = S_IFDIR,
	};
	struct pkm_kacs_kunit_delete_on_close_result result = {};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access |
							   KACS_ACCESS_DELETE,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_delete_on_close_for_subject(&args,
								   &result),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_delete_child_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_DELETE_CHILD,
		.create_disposition = KACS_DISPOSITION_OPEN,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EOPNOTSUPP);
}


static void pkm_kunit_native_open_directory_required_non_dir_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.create_options = KACS_CREATE_OPT_DIRECTORY,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-ENOTDIR);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_directory_mutation_rights_fail_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.inode_mode = S_IFDIR,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_WRITE_DATA,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_unmanaged_mount_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.mount_policy_override = KACS_MOUNT_POLICY_UNMANAGED,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_nofollow_symlink_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.flags = AT_SYMLINK_NOFOLLOW,
		.inode_mode = S_IFLNK,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   PKM_KUNIT_FILE_READ_DATA,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-ELOOP);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_open_if_existing_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN_IF,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, NULL),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OPENED);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_if_existing_with_creator_sd_invalid(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN_IF,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *input_sd;
	size_t file_sd_len = 0;
	size_t input_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_overwrite_existing_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, NULL),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OVERWRITTEN);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_overwrite_preserves_identity_and_truncates(
	struct kunit *test)
{
	pkm_kunit_expect_native_overwrite_identity(test, KACS_DISPOSITION_OVERWRITE);
}


static void pkm_kunit_native_overwrite_if_preserves_identity_and_truncates(
	struct kunit *test)
{
	pkm_kunit_expect_native_overwrite_identity(test, KACS_DISPOSITION_OVERWRITE_IF);
}


static void pkm_kunit_native_overwrite_if_existing_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE_IF,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, NULL),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_OVERWRITTEN);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_overwrite_without_write_data_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_native_overwrite_existing_with_creator_sd_invalid(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *input_sd;
	size_t file_sd_len = 0;
	size_t input_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_overwrite_if_existing_with_creator_sd_invalid(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE_IF,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *input_sd;
	size_t file_sd_len = 0;
	size_t input_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_supersede_existing_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_SUPERSEDE,
	};
	const void *subject_token;
	const u8 *target_sd = NULL;
	const u8 *parent_sd = NULL;
	size_t target_sd_len = 0;
	size_t parent_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     PKM_KUNIT_FILE_READ_DATA,
						     &target_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_DELETE_CHILD |
			PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_sd;
	args.target_file_sd_len = target_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, &granted, &status, NULL),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_SUPERSEDED);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)target_sd);
}


static void pkm_kunit_native_supersede_replaces_target_preserves_old_lineage(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_SUPERSEDE,
	};
	struct pkm_kacs_kunit_native_identity_result result = {};
	const void *subject_token;
	const u8 *target_sd;
	const u8 *parent_sd;
	size_t target_sd_len = 0;
	size_t parent_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_ATTRIBUTES |
			KACS_ACCESS_DELETE | KACS_ACCESS_READ_CONTROL,
		&target_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA |
			PKM_KUNIT_FILE_DELETE_CHILD | KACS_ACCESS_DELETE |
			KACS_ACCESS_READ_CONTROL,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_sd;
	args.target_file_sd_len = target_sd_len;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;

	ret = pkm_kacs_kunit_native_supersede_identity_for_subject(
		&args, &result);
	KUNIT_ASSERT_EQ_MSG(test, ret, 0L, "failure_step=%u",
			    result.failure_step);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_SUPERSEDED);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_GT(test, result.size_before, 0ULL);
	KUNIT_EXPECT_EQ(test, result.size_after, 0ULL);
	KUNIT_EXPECT_EQ(test, result.old_fd_size_after, result.size_before);
	KUNIT_EXPECT_EQ(test, result.same_inode_after, 0U);
	KUNIT_EXPECT_NE(test, result.target_inode_after, result.old_inode);
	KUNIT_EXPECT_EQ(test, result.hardlink_preserved, 1U);
	KUNIT_EXPECT_EQ(test, result.old_fd_preserved, 1U);
	KUNIT_EXPECT_EQ(test, result.sd_preserved, 1U);
	KUNIT_EXPECT_EQ(test, result.sd_recomputed, 1U);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)target_sd);
}


static void pkm_kunit_native_supersede_without_delete_denies(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_SUPERSEDE,
	};
	const void *subject_token;
	const u8 *target_sd = NULL;
	const u8 *parent_sd = NULL;
	size_t target_sd_len = 0;
	size_t parent_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     PKM_KUNIT_FILE_READ_DATA,
						     &target_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_sd;
	args.target_file_sd_len = target_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)target_sd);
}


static void pkm_kunit_native_supersede_without_add_file_denies(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_SUPERSEDE,
	};
	const void *subject_token;
	const u8 *target_sd = NULL;
	const u8 *parent_sd = NULL;
	size_t target_sd_len = 0;
	size_t parent_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | KACS_ACCESS_DELETE,
		&target_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_DELETE_CHILD | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_sd;
	args.target_file_sd_len = target_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)target_sd);
}


static void pkm_kunit_native_destructive_directory_target_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE,
		.inode_mode = S_IFDIR,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_create_existing_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   args.desired_access,
						   &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_open_for_subject(
				&args, NULL, NULL, NULL),
			(long)-EEXIST);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_native_create_regular_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, &granted,
				&status),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_CREATED);
	KUNIT_ASSERT_NOT_NULL(test, created_sd);
	KUNIT_EXPECT_GT(test, created_sd_len, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u16(created_sd, 2) &
				PKM_KUNIT_SE_OWNER_DEFAULTED,
			PKM_KUNIT_SE_OWNER_DEFAULTED);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u16(created_sd, 2) &
				PKM_KUNIT_SE_GROUP_DEFAULTED,
			PKM_KUNIT_SE_GROUP_DEFAULTED);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u16(created_sd, 2) &
				PKM_KUNIT_SE_DACL_DEFAULTED,
			0U);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u16(created_sd, 2) &
				PKM_KUNIT_SE_DACL_AUTO_INHERITED,
			PKM_KUNIT_SE_DACL_AUTO_INHERITED);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_defaulted_control_flags(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;
	u16 control;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, created_sd);

	control = pkm_kunit_read_u16(created_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_OWNER_DEFAULTED,
			PKM_KUNIT_SE_OWNER_DEFAULTED);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_GROUP_DEFAULTED,
			PKM_KUNIT_SE_GROUP_DEFAULTED);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_DEFAULTED,
			PKM_KUNIT_SE_DACL_DEFAULTED);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_AUTO_INHERITED, 0U);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_PRESENT,
			PKM_KUNIT_SE_DACL_PRESENT);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_directory_success(struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_EXECUTE,
		.create_disposition = KACS_DISPOSITION_CREATE,
		.create_options = KACS_CREATE_OPT_DIRECTORY,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_APPEND_DATA | PKM_KUNIT_FILE_READ_DATA |
			PKM_KUNIT_FILE_EXECUTE,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, &granted,
				&status),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_CREATED);
	KUNIT_ASSERT_NOT_NULL(test, created_sd);
	KUNIT_EXPECT_GT(test, created_sd_len, (size_t)0);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_fixed_modes(struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args regular_args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	struct pkm_kacs_kunit_native_create_args directory_args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_EXECUTE,
		.create_disposition = KACS_DISPOSITION_CREATE,
		.create_options = KACS_CREATE_OPT_DIRECTORY,
	};
	const void *subject_token;
	const u8 *regular_parent_sd = NULL;
	const u8 *directory_parent_sd = NULL;
	size_t regular_parent_sd_len = 0;
	size_t directory_parent_sd_len = 0;
	u32 mode = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	regular_parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&regular_parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, regular_parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)regular_parent_sd,
						  0x03);
	regular_args.subject_token = subject_token;
	regular_args.parent_file_sd_ptr = regular_parent_sd;
	regular_args.parent_file_sd_len = regular_parent_sd_len;
	regular_args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_mode_for_subject(
				&regular_args, &mode),
			0L);
	KUNIT_EXPECT_EQ(test, mode & S_IFMT, S_IFREG);
	KUNIT_EXPECT_EQ(test, mode & 0777, 0600U);

	directory_parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_APPEND_DATA | PKM_KUNIT_FILE_READ_DATA |
			PKM_KUNIT_FILE_EXECUTE,
		&directory_parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, directory_parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)directory_parent_sd,
						  0x03);
	directory_args.subject_token = subject_token;
	directory_args.parent_file_sd_ptr = directory_parent_sd;
	directory_args.parent_file_sd_len = directory_parent_sd_len;
	directory_args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	mode = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_mode_for_subject(
				&directory_args, &mode),
			0L);
	KUNIT_EXPECT_EQ(test, mode & S_IFMT, S_IFDIR);
	KUNIT_EXPECT_EQ(test, mode & 0777, 0700U);

	pkm_kacs_free((void *)directory_parent_sd);
	pkm_kacs_free((void *)regular_parent_sd);
}


static void pkm_kunit_native_create_owner_self_success(struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	pkm_kunit_expect_native_create_owner_success(
		test, subject_token, pkm_kunit_local_service_sid,
		sizeof(pkm_kunit_local_service_sid));

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_create_owner_group_success(struct kunit *test)
{
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	pkm_kunit_expect_native_create_owner_success(
		test, subject_token, pkm_kunit_administrators_sid,
		sizeof(pkm_kunit_administrators_sid));

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_create_owner_restore_privilege_success(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;

	subject_token =
		kacs_rust_kunit_create_impersonation_variant_token_with_privileges(
			PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			KACS_TOKEN_TYPE_PRIMARY, KACS_IMLEVEL_ANONYMOUS,
			PKM_KUNIT_IL_SYSTEM, 0,
			PKM_KUNIT_SE_RESTORE_PRIVILEGE,
			PKM_KUNIT_SE_RESTORE_PRIVILEGE,
			PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));

	pkm_kunit_expect_native_create_owner_success(
		test, subject_token, pkm_kunit_system_sid,
		sizeof(pkm_kunit_system_sid));

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_open_if_missing_creates_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN_IF,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, &granted,
				&status),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_CREATED);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_overwrite_if_missing_creates_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OVERWRITE_IF,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, &granted,
				&status),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_CREATED);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_supersede_missing_creates_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_SUPERSEDE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, &granted,
				&status),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_CREATED);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_parent_right_denied(struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     PKM_KUNIT_FILE_READ_DATA,
						     &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_unmanaged_mount_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
		.mount_policy_override = KACS_MOUNT_POLICY_UNMANAGED,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_invalid_owner_denies(struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const void *foreign_token;
	const u8 *parent_sd = NULL;
	const u8 *creator_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	foreign_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, foreign_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);
	creator_sd = pkm_kunit_create_default_file_sd(foreign_token,
						      &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.creator_sd_ptr = creator_sd;
	args.creator_sd_len = creator_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(foreign_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_create_sacl_without_security_denies(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *creator_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);
	creator_sd = kacs_rust_kunit_create_file_sd_with_mandatory_resource_attr(
		subject_token, PKM_KUNIT_FILE_READ_DATA, 0, 0, 0,
		&creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.creator_sd_ptr = creator_sd;
	args.creator_sd_len = creator_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_create_server_security_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *creator_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);
	creator_sd = pkm_kunit_create_default_file_sd(subject_token,
						      &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_write_u16((u8 *)creator_sd, 2,
			    pkm_kunit_read_u16(creator_sd, 2) |
				    PKM_KUNIT_SE_SERVER_SECURITY);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.creator_sd_ptr = creator_sd;
	args.creator_sd_len = creator_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_native_create_label_requires_relabel(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *creator_sd = NULL;
	const u8 *created_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);
	creator_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							    &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.creator_sd_ptr = creator_sd;
	args.creator_sd_len = creator_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			(long)-EACCES);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_native_create_creator_label_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *creator_sd = NULL;
	const u8 *built_sd = NULL;
	const u8 *created_sd = NULL;
	const u8 *actual_subset = NULL;
	const u8 *expected_subset = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t built_sd_len = 0;
	size_t created_sd_len = 0;
	size_t actual_subset_len = 0;
	size_t expected_subset_len = 0;
	u32 actual_sacl_offset = 0;
	u32 expected_sacl_offset = 0;
	u32 built_granted = 0;
	u32 granted = 0;
	u32 status = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE | PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);
	creator_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							    &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.creator_sd_ptr = creator_sd;
	args.creator_sd_len = creator_sd_len;

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(
				subject_token, parent_sd, parent_sd_len,
				creator_sd, creator_sd_len, 0, &built_sd,
				&built_sd_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				subject_token, built_sd, built_sd_len,
				args.desired_access, 0, 0, 0, &built_granted),
			0);
	KUNIT_EXPECT_EQ(test, built_granted, args.desired_access);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, &granted,
				&status),
			0L);
	KUNIT_EXPECT_EQ(test, granted, args.desired_access);
	KUNIT_EXPECT_EQ(test, status, KACS_STATUS_CREATED);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				created_sd, created_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				creator_sd, creator_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	actual_sacl_offset = pkm_kunit_read_u32(actual_subset, 12);
	expected_sacl_offset = pkm_kunit_read_u32(expected_subset, 12);
	KUNIT_ASSERT_NE(test, actual_sacl_offset, 0U);
	KUNIT_ASSERT_NE(test, expected_sacl_offset, 0U);
	KUNIT_EXPECT_EQ(test, actual_subset_len - actual_sacl_offset,
			expected_subset_len - expected_sacl_offset);
	KUNIT_EXPECT_EQ(
		test,
		memcmp(actual_subset + actual_sacl_offset,
		       expected_subset + expected_sacl_offset,
		       actual_subset_len - actual_sacl_offset),
		0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)built_sd);
	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_fd_raw_sd_xattr_hooks_deny_canonical_names(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_get(
				"security.peios.sd", 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_set(
				"security.peios.sd", 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_remove(
				"security.peios.sd", 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_get(
				"system.ntfs_security", 1),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_get(
				"system.ntfs_security", 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_get("user.other", 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_set(XATTR_NAME_CAPS, 0),
			-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_file_sd_xattr_remove(XATTR_NAME_CAPS,
							    0),
			0);
}


static void pkm_kunit_get_file_sd_cached_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_READ_CONTROL,
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_cached_file_sd_for_subject(
				&args, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test, memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_file_sd_cached_denied_without_read_control(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.cached_granted_access = 0,
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	const u8 *subset = NULL;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_cached_file_sd_for_subject(
				&args, &subset, &subset_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_file_sd_cached_unmanaged_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_READ_CONTROL,
		.file_mode = FMODE_READ,
		.mount_policy_override = KACS_MOUNT_POLICY_UNMANAGED,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_cached_file_sd_for_subject(
				&args, &subset, &subset_len),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_file_sd_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_file_sd_for_subject(
				&args, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test, memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_sd_syscall_filefd_probe_and_copyout(
	struct kunit *test)
{
	struct pkm_kacs_kunit_live_file_fd live = {
		.fd = -1,
	};
	const void *subject_token;
	const u8 *expected = NULL;
	size_t expected_len = 0;
	u32 security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
			    PKM_KUNIT_GROUP_SECURITY_INFORMATION |
			    PKM_KUNIT_DACL_SECURITY_INFORMATION;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_live_file_fd_for_get_sd(
				subject_token, security_info, &live, &expected,
				&expected_len),
			0L);
	pkm_kunit_expect_get_sd_syscall_copyout(
		test, live.fd, expected, expected_len, security_info);

	pkm_kacs_kunit_cleanup_live_file_fd(&live);
	pkm_kacs_free((void *)expected);
}


static void pkm_kunit_get_path_file_sd_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_path_file_sd_on_mount_for_subject(
				&args, TMPFS_MAGIC, 0, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test, memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_path_file_sd_nofollow_accepts_symlink(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.inode_mode = S_IFLNK,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_path_file_sd_on_mount_for_subject(
				&args, TMPFS_MAGIC, AT_SYMLINK_NOFOLLOW,
				&subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test, memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_path_file_sd_empty_path_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_path_file_sd_on_mount_for_subject(
				&args, TMPFS_MAGIC, AT_EMPTY_PATH, &subset,
				&subset_len),
			(long)-EOPNOTSUPP);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_mount_policy_classifies_unmanaged_special_fs(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mount_policy_for_magic(
				       PROC_SUPER_MAGIC),
			KACS_MOUNT_POLICY_UNMANAGED);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mount_policy_for_magic(SYSFS_MAGIC),
			KACS_MOUNT_POLICY_UNMANAGED);
}


static void pkm_kunit_file_mount_policy_classifies_synthesize_ephemeral_fs(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mount_policy_for_magic(
				       NFS_SUPER_MAGIC),
			KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mount_policy_for_magic(
				       MSDOS_SUPER_MAGIC),
			KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mount_policy_for_magic(
				       EXFAT_SUPER_MAGIC),
			KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
}


static void pkm_kunit_file_mount_policy_defaults_to_deny_missing(
	struct kunit *test)
{
	kunit_skip(test,
		   "tmpfs/rootfs default mount policy needs initramfs design");

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_mount_policy_for_magic(EXT4_SUPER_MAGIC),
			KACS_MOUNT_POLICY_DENY_MISSING);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_mount_policy_for_magic(TMPFS_MAGIC),
			KACS_MOUNT_POLICY_DENY_MISSING);
}


static void pkm_kunit_mount_policy_set_persistent_template_success(
	struct kunit *test)
{
	struct kacs_mount_policy_args args = {
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT,
	};
	const void *subject_token;
	const u8 *template_sd;
	size_t template_sd_len = 0;
	u32 policy = 0;
	u32 generation = 0;
	u32 template_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	args.template_sd_ptr = (u64)(unsigned long)template_sd;
	args.template_sd_len = (u32)template_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			0L);
	KUNIT_EXPECT_EQ(test, policy,
			KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT);
	KUNIT_EXPECT_EQ(test, generation, 1U);
	KUNIT_EXPECT_EQ(test, template_len, (u32)template_sd_len);

	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_mount_policy_same_superblock_views_share_policy(
	struct kunit *test)
{
	struct kacs_mount_policy_args args = {
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT,
	};
	const void *subject_token;
	const u8 *template_sd;
	size_t template_sd_len = 0;
	u32 first_policy = 0;
	u32 second_policy = 0;
	u32 first_generation = 0;
	u32 second_generation = 0;
	u32 first_template_len = 0;
	u32 second_template_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	args.template_sd_ptr = (u64)(unsigned long)template_sd;
	args.template_sd_len = (u32)template_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_same_superblock_mount_policy_for_subject(
				subject_token, &args, &first_policy,
				&second_policy, &first_generation,
				&second_generation, &first_template_len,
				&second_template_len),
			0L);
	KUNIT_EXPECT_EQ(test, first_policy,
			KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT);
	KUNIT_EXPECT_EQ(test, second_policy, first_policy);
	KUNIT_EXPECT_EQ(test, second_generation, first_generation);
	KUNIT_EXPECT_EQ(test, first_generation, 1U);
	KUNIT_EXPECT_EQ(test, first_template_len, (u32)template_sd_len);
	KUNIT_EXPECT_EQ(test, second_template_len, first_template_len);

	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_mount_policy_set_requires_tcb(struct kunit *test)
{
	struct kacs_mount_policy_args args = {
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
	};
	const void *subject_token;
	u32 policy = 0;
	u32 generation = 0;
	u32 template_len = 0;

	subject_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EPERM);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_mount_policy_rejects_unmanaged_and_hard_unmanaged(
	struct kunit *test)
{
	struct kacs_mount_policy_args args = {
		.policy = KACS_MOUNT_POLICY_UNMANAGED,
	};
	const void *subject_token;
	u32 policy = 0;
	u32 generation = 0;
	u32 template_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args.policy = KACS_MOUNT_POLICY_DENY_MISSING;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, PROC_SUPER_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EOPNOTSUPP);
}


static void pkm_kunit_mount_policy_rejects_invalid_templates(
	struct kunit *test)
{
	static const u8 malformed_sd[4] = { 0 };
	struct kacs_mount_policy_args args = {
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_ptr = (u64)(unsigned long)malformed_sd,
		.template_sd_len = sizeof(malformed_sd),
	};
	const void *subject_token;
	const u8 *template_sd;
	size_t template_sd_len = 0;
	u32 policy = 0;
	u32 generation = 0;
	u32 template_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	args.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	args.template_sd_ptr = (u64)(unsigned long)template_sd;
	args.template_sd_len = (u32)template_sd_len;
	pkm_kunit_make_sd_ownerless((u8 *)template_sd);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args.policy = KACS_MOUNT_POLICY_DENY_MISSING;
	args.template_sd_ptr = (u64)(unsigned long)template_sd;
	args.template_sd_len = (u32)template_sd_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	args.template_sd_ptr = (u64)(unsigned long)template_sd;
	args.template_sd_len = PKM_KUNIT_MAX_SECURITY_DESCRIPTOR_BYTES + 1;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_mount_policy_rejects_malformed_abi_args(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *template_sd;
	size_t template_sd_len = 0;
	u32 policy = 0;
	u32 generation = 0;
	u32 template_len = 0;
	struct kacs_mount_policy_args args = {
		.policy = 0xffffffffU,
	};

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.flags = 1,
	};
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.generation = 1,
	};
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.__pad0 = 1,
	};
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.__pad1 = 1,
	};
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_ptr = (u64)(unsigned long)template_sd,
	};
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_len = (u32)template_sd_len,
	};
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_mount_policy_for_subject(
				subject_token, TMPFS_MAGIC, &args, &policy,
				&generation, &template_len),
			(long)-EINVAL);

	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_mount_policy_failures_preserve_existing_state(
	struct kunit *test)
{
	static const u8 malformed_sd[4] = { 0 };
	const void *subject_token;
	const u8 *template_sd;
	const u8 *ownerless_sd;
	size_t template_sd_len = 0;
	size_t ownerless_sd_len = 0;
	struct kacs_mount_policy_args initial_args = {
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT,
	};
	struct kacs_mount_policy_args failure_args = {
		.policy = 0xffffffffU,
	};

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	ownerless_sd = pkm_kunit_create_default_file_sd(subject_token,
							&ownerless_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, ownerless_sd);
	pkm_kunit_make_sd_ownerless((u8 *)ownerless_sd);

	initial_args.template_sd_ptr = (u64)(unsigned long)template_sd;
	initial_args.template_sd_len = (u32)template_sd_len;

	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_UNMANAGED,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.flags = 1,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.generation = 1,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.__pad0 = 1,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.__pad1 = 1,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_ptr = (u64)(unsigned long)template_sd,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_len = (u32)template_sd_len,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_ptr = (u64)(unsigned long)template_sd,
		.template_sd_len = PKM_KUNIT_MAX_SECURITY_DESCRIPTOR_BYTES + 1,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_DENY_MISSING,
		.template_sd_ptr = (u64)(unsigned long)template_sd,
		.template_sd_len = (u32)template_sd_len,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_ptr = (u64)(unsigned long)malformed_sd,
		.template_sd_len = sizeof(malformed_sd),
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	failure_args = (struct kacs_mount_policy_args){
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.template_sd_ptr = (u64)(unsigned long)ownerless_sd,
		.template_sd_len = (u32)ownerless_sd_len,
	};
	pkm_kunit_expect_mount_policy_failure_preserves_state(
		test, subject_token, &initial_args, &failure_args, -EINVAL,
		(u32)template_sd_len);

	pkm_kacs_free((void *)ownerless_sd);
	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_mount_policy_opath_fd_names_superblock(
	struct kunit *test)
{
	u32 policy = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_mount_policy_opath_fd_resolves_superblock(
				&policy),
			0L);
	KUNIT_EXPECT_TRUE(test,
			  policy == KACS_MOUNT_POLICY_DENY_MISSING ||
				  policy ==
					  KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL ||
				  policy ==
					  KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT ||
				  policy == KACS_MOUNT_POLICY_UNMANAGED);
}


static void pkm_kunit_mount_policy_generation_wrap_skips_zero(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_next_mount_policy_generation(0),
			1U);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_next_mount_policy_generation(U32_MAX),
			1U);
}


static void pkm_kunit_mount_policy_adoption_invalidates_missing_cache(
	struct kunit *test)
{
	struct kacs_mount_policy_args args = {
		.policy = KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT,
	};
	const void *subject_token;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	u32 xattr_written = 0;
	long first_query_ret = 0;

	kunit_skip(test,
		   "tmpfs/rootfs default mount policy needs initramfs design");

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_adopt_missing_mount_for_subject(
				subject_token, &args, &subset, &subset_len,
				&xattr_written, &first_query_ret),
			0L);
	KUNIT_EXPECT_EQ(test, first_query_ret, (long)-EACCES);
	KUNIT_EXPECT_NOT_NULL(test, subset);
	KUNIT_EXPECT_NE(test, subset_len, (size_t)0);
	KUNIT_EXPECT_EQ(test, xattr_written, 1U);

	pkm_kacs_free((void *)subset);
}


static void pkm_kunit_file_missing_sd_deny_mount_returns_missing_state(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_missing_file_sd_result_for_magic(
				EXT4_SUPER_MAGIC),
			(long)PKM_KACS_KUNIT_FILE_SD_MISSING);
}


static void pkm_kunit_file_missing_sd_synthesize_mount_fails_closed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_missing_file_sd_result_for_magic(
				NFS_SUPER_MAGIC),
			(long)PKM_KACS_KUNIT_FILE_SD_MISSING);
}


static void pkm_kunit_get_file_sd_synthesize_mount_valid_cache_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_file_sd_on_mount_for_subject(
				&args, NFS_SUPER_MAGIC, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_synthesize_file_sd_parent_inheritance_success(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd;
	const u8 *parent_subset = NULL;
	const u8 *child_subset = NULL;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	size_t parent_subset_len = 0;
	size_t child_subset_len = 0;
	u32 child_dacl_offset;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_set_sd_dacl_reserved_fields((u8 *)parent_sd, 0x5d, 0x1234);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x01);

	child_sd = pkm_kunit_synthesize_file_sd(parent_sd, parent_sd_len,
						NULL, 0, 0, &child_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				parent_sd, parent_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&parent_subset, &parent_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				child_sd, child_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&child_subset, &child_subset_len),
			0);

	KUNIT_ASSERT_EQ(test, child_subset_len, parent_subset_len);
	child_dacl_offset = pkm_kunit_read_u32(child_subset, 16);
	KUNIT_ASSERT_NE(test, child_dacl_offset, 0U);
	KUNIT_EXPECT_EQ(test, child_subset[child_dacl_offset + 8 + 1], 0x11);
	pkm_kunit_expect_sd_dacl_reserved_fields(test, child_sd, 0x5d,
						 0x1234);

	pkm_kacs_free((void *)child_subset);
	pkm_kacs_free((void *)parent_subset);
	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_synthesize_file_sd_parent_without_inheritance_falls_back(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd;
	const u8 *fallback_sd;
	const u8 *child_subset = NULL;
	const u8 *fallback_subset = NULL;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	size_t fallback_sd_len = 0;
	size_t child_subset_len = 0;
	size_t fallback_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	child_sd = pkm_kunit_synthesize_file_sd(parent_sd, parent_sd_len,
						NULL, 0, 0, &child_sd_len);
	fallback_sd = pkm_kunit_synthesize_file_sd(NULL, 0, NULL, 0, 0,
						   &fallback_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	KUNIT_ASSERT_NOT_NULL(test, fallback_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				child_sd, child_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&child_subset, &child_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				fallback_sd, fallback_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&fallback_subset, &fallback_subset_len),
			0);
	pkm_kunit_expect_bytes_eq(test, child_subset, child_subset_len,
				  fallback_subset, fallback_subset_len);

	pkm_kacs_free((void *)fallback_subset);
	pkm_kacs_free((void *)child_subset);
	pkm_kacs_free((void *)fallback_sd);
	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_synthesize_file_sd_ownerless_template_fails_closed(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *template_sd;
	const u8 *child_sd = NULL;
	size_t template_sd_len = 0;
	size_t child_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	pkm_kunit_make_sd_ownerless((u8 *)template_sd);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_synthesize_file_sd(NULL, 0, template_sd,
						     template_sd_len, 0,
						     &child_sd, &child_sd_len),
			-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, child_sd, NULL);
	KUNIT_EXPECT_EQ(test, child_sd_len, (size_t)0);

	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_synthesize_file_sd_null_group_template_inherits(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *template_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t template_sd_len = 0;
	size_t child_sd_len = 0;
	const u8 *ace;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x01);
	pkm_kunit_make_sd_groupless((u8 *)template_sd);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_synthesize_file_sd(parent_sd, parent_sd_len,
						     template_sd,
						     template_sd_len, 0,
						     &child_sd, &child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(child_sd, 8), 0U);
	ace = pkm_kunit_first_inherited_dacl_ace_const(child_sd);
	KUNIT_ASSERT_NOT_NULL(test, ace);
	KUNIT_EXPECT_EQ(test, ace[1],
			PKM_KUNIT_OBJECT_INHERIT_ACE |
				PKM_KUNIT_INHERITED_ACE);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)template_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_synthesize_file_sd_creator_group_without_group_denies(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *template_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t template_sd_len = 0;
	size_t child_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x01);
	pkm_kunit_make_first_file_ace_sid(
		(u8 *)parent_sd, pkm_kunit_creator_group_sid,
		sizeof(pkm_kunit_creator_group_sid));
	pkm_kunit_make_sd_groupless((u8 *)template_sd);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_synthesize_file_sd(parent_sd, parent_sd_len,
						     template_sd,
						     template_sd_len, 0,
						     &child_sd, &child_sd_len),
			-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, child_sd, NULL);
	KUNIT_EXPECT_EQ(test, child_sd_len, (size_t)0);

	pkm_kacs_free((void *)template_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_inheritance_flag_matrix(
	struct kunit *test)
{
	static const struct pkm_kunit_inheritance_flags_case cases[] = {
		{
			.parent_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
					PKM_KUNIT_OBJECT_INHERIT_ACE,
			.file_inherits = true,
			.file_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
				      PKM_KUNIT_OBJECT_INHERIT_ACE |
				      PKM_KUNIT_INHERITED_ACE,
			.dir_inherits = true,
			.dir_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
				     PKM_KUNIT_OBJECT_INHERIT_ACE |
				     PKM_KUNIT_INHERITED_ACE,
		},
		{
			.parent_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE,
			.file_inherits = false,
			.dir_inherits = true,
			.dir_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
				     PKM_KUNIT_INHERITED_ACE,
		},
		{
			.parent_flags = PKM_KUNIT_OBJECT_INHERIT_ACE,
			.file_inherits = true,
			.file_flags = PKM_KUNIT_OBJECT_INHERIT_ACE |
				      PKM_KUNIT_INHERITED_ACE,
			.dir_inherits = true,
			.dir_flags = PKM_KUNIT_OBJECT_INHERIT_ACE |
				     PKM_KUNIT_INHERIT_ONLY_ACE |
				     PKM_KUNIT_INHERITED_ACE,
		},
		{
			.parent_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
					PKM_KUNIT_OBJECT_INHERIT_ACE |
					PKM_KUNIT_INHERIT_ONLY_ACE,
			.file_inherits = true,
			.file_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
				      PKM_KUNIT_OBJECT_INHERIT_ACE |
				      PKM_KUNIT_INHERITED_ACE,
			.dir_inherits = true,
			.dir_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
				     PKM_KUNIT_OBJECT_INHERIT_ACE |
				     PKM_KUNIT_INHERITED_ACE,
		},
		{
			.parent_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
					PKM_KUNIT_OBJECT_INHERIT_ACE |
					PKM_KUNIT_NO_PROPAGATE_INHERIT_ACE,
			.file_inherits = true,
			.file_flags = PKM_KUNIT_NO_PROPAGATE_INHERIT_ACE |
				      PKM_KUNIT_INHERITED_ACE,
			.dir_inherits = true,
			.dir_flags = PKM_KUNIT_NO_PROPAGATE_INHERIT_ACE |
				     PKM_KUNIT_INHERITED_ACE,
		},
		{
			.parent_flags = PKM_KUNIT_CONTAINER_INHERIT_ACE |
					PKM_KUNIT_NO_PROPAGATE_INHERIT_ACE,
			.file_inherits = false,
			.dir_inherits = true,
			.dir_flags = PKM_KUNIT_NO_PROPAGATE_INHERIT_ACE |
				     PKM_KUNIT_INHERITED_ACE,
		},
		{
			.parent_flags = 0,
			.file_inherits = false,
			.dir_inherits = false,
		},
	};
	const void *subject_token;
	size_t i;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const u8 *parent_sd;
		const u8 *file_sd;
		const u8 *dir_sd;
		size_t parent_sd_len = 0;
		size_t file_sd_len = 0;
		size_t dir_sd_len = 0;

		parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
								&parent_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, parent_sd);
		pkm_kunit_make_first_file_ace_inheritable(
			(u8 *)parent_sd, cases[i].parent_flags);

		file_sd = pkm_kunit_synthesize_file_sd(parent_sd, parent_sd_len,
						       NULL, 0, 0,
						       &file_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, file_sd);
		pkm_kunit_expect_inherited_ace_flags(
			test, file_sd, cases[i].file_inherits,
			cases[i].file_flags);

		dir_sd = pkm_kunit_synthesize_file_sd(parent_sd, parent_sd_len,
						      NULL, 0, 1,
						      &dir_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, dir_sd);
		pkm_kunit_expect_inherited_ace_flags(
			test, dir_sd, cases[i].dir_inherits,
			cases[i].dir_flags);

		pkm_kacs_free((void *)dir_sd);
		pkm_kacs_free((void *)file_sd);
		pkm_kacs_free((void *)parent_sd);
	}
}


static void pkm_kunit_build_created_file_sd_maps_generic_ace_masks(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	const u8 *explicit_ace;
	const u8 *inherited_ace;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u32 expected_read;
	u32 expected_write;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	creator_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							 &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);

	pkm_kunit_make_first_file_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);
	pkm_kunit_make_first_file_ace_mask((u8 *)parent_sd,
					   KACS_ACCESS_GENERIC_READ);
	pkm_kunit_make_first_file_ace_mask((u8 *)creator_sd,
					   KACS_ACCESS_GENERIC_WRITE);
	pkm_kunit_write_u16((u8 *)creator_sd, 2,
			    pkm_kunit_read_u16(creator_sd, 2) |
				    PKM_KUNIT_SE_DACL_AUTO_INHERIT_REQ);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);

	expected_read = PKM_KUNIT_FILE_READ_DATA |
			PKM_KUNIT_FILE_READ_ATTRIBUTES |
			PKM_KUNIT_FILE_READ_EA | KACS_ACCESS_READ_CONTROL |
			KACS_ACCESS_SYNCHRONIZE;
	expected_write = PKM_KUNIT_FILE_WRITE_DATA |
			 PKM_KUNIT_FILE_APPEND_DATA |
			 PKM_KUNIT_FILE_WRITE_ATTRIBUTES |
			 PKM_KUNIT_FILE_WRITE_EA | KACS_ACCESS_READ_CONTROL |
			 KACS_ACCESS_SYNCHRONIZE;

	explicit_ace = pkm_kunit_first_dacl_ace_const(child_sd);
	inherited_ace = pkm_kunit_first_inherited_dacl_ace_const(child_sd);
	KUNIT_ASSERT_NOT_NULL(test, explicit_ace);
	KUNIT_ASSERT_NOT_NULL(test, inherited_ace);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(explicit_ace, 4),
			expected_write);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(inherited_ace, 4),
			expected_read);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(explicit_ace, 4) &
			      (KACS_ACCESS_GENERIC_READ |
			       KACS_ACCESS_GENERIC_WRITE |
			       KACS_ACCESS_GENERIC_EXECUTE |
			       KACS_ACCESS_GENERIC_ALL),
			0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(inherited_ace, 4) &
			      (KACS_ACCESS_GENERIC_READ |
			       KACS_ACCESS_GENERIC_WRITE |
			       KACS_ACCESS_GENERIC_EXECUTE |
			       KACS_ACCESS_GENERIC_ALL),
			0U);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_preserves_dacl_source_order(
	struct kunit *test)
{
	const u32 creator_allow_mask = PKM_KUNIT_FILE_READ_DATA;
	const u32 creator_deny_mask = PKM_KUNIT_FILE_WRITE_DATA;
	const u32 parent_allow_mask = PKM_KUNIT_FILE_APPEND_DATA;
	const u32 parent_deny_mask = PKM_KUNIT_FILE_READ_ATTRIBUTES;
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u32 dacl_offset;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = kacs_rust_kunit_create_file_sd(
		subject_token, parent_allow_mask, parent_deny_mask, 0, 0,
		&parent_sd_len);
	creator_sd = kacs_rust_kunit_create_file_sd(
		subject_token, creator_allow_mask, creator_deny_mask, 0, 0,
		&creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);

	pkm_kunit_set_dacl_ace_header(
		(u8 *)creator_sd, creator_sd_len, 0,
		PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE, 0, creator_allow_mask);
	pkm_kunit_set_dacl_ace_header(
		(u8 *)creator_sd, creator_sd_len, 1,
		PKM_KUNIT_ACCESS_DENIED_ACE_TYPE, 0, creator_deny_mask);
	pkm_kunit_set_dacl_ace_header(
		(u8 *)parent_sd, parent_sd_len, 0,
		PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE, parent_allow_mask);
	pkm_kunit_set_dacl_ace_header(
		(u8 *)parent_sd, parent_sd_len, 1,
		PKM_KUNIT_ACCESS_DENIED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE, parent_deny_mask);
	pkm_kunit_write_u16((u8 *)creator_sd, 2,
			    pkm_kunit_read_u16(creator_sd, 2) |
				    PKM_KUNIT_SE_DACL_AUTO_INHERIT_REQ);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);

	dacl_offset = pkm_kunit_read_u32(child_sd, 16);
	KUNIT_ASSERT_NE(test, dacl_offset, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u16(child_sd, dacl_offset + 4),
			4U);
	pkm_kunit_expect_dacl_ace_header(
		test, child_sd, child_sd_len, 0, PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		0, creator_allow_mask);
	pkm_kunit_expect_dacl_ace_header(
		test, child_sd, child_sd_len, 1, PKM_KUNIT_ACCESS_DENIED_ACE_TYPE,
		0, creator_deny_mask);
	pkm_kunit_expect_dacl_ace_header(
		test, child_sd, child_sd_len, 2, PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE,
		parent_allow_mask);
	pkm_kunit_expect_dacl_ace_header(
		test, child_sd, child_sd_len, 3, PKM_KUNIT_ACCESS_DENIED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE,
		parent_deny_mask);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_creator_dacl_preserves_acl_reserved(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	creator_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							 &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_set_sd_dacl_reserved_fields((u8 *)creator_sd, 0x6e,
					      0x5678);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	pkm_kunit_expect_sd_dacl_reserved_fields(test, child_sd, 0x6e,
						 0x5678);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_creator_dacl_preserves_opaque_ace(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	const u8 *source_ace;
	const u8 *actual_ace;
	u8 *expected_ace;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u16 source_ace_len;
	u16 actual_ace_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	creator_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							 &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_make_first_file_ace_opaque(
		(u8 *)creator_sd,
		PKM_KUNIT_CONTAINER_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE);

	source_ace = pkm_kunit_first_dacl_ace_const(creator_sd);
	KUNIT_ASSERT_NOT_NULL(test, source_ace);
	source_ace_len = pkm_kunit_read_u16(source_ace, 2);
	expected_ace = kunit_kzalloc(test, source_ace_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, expected_ace);
	memcpy(expected_ace, source_ace, source_ace_len);
	expected_ace[1] = PKM_KUNIT_CONTAINER_INHERIT_ACE;

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	actual_ace = pkm_kunit_first_dacl_ace_const(child_sd);
	KUNIT_ASSERT_NOT_NULL(test, actual_ace);
	actual_ace_len = pkm_kunit_read_u16(actual_ace, 2);
	pkm_kunit_expect_bytes_eq(test, actual_ace, actual_ace_len,
				  expected_ace, source_ace_len);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_parent_preserves_opaque_ace(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	const u8 *source_ace;
	const u8 *actual_ace;
	u8 *expected_ace;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	u16 source_ace_len;
	u16 actual_ace_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_opaque(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);

	source_ace = pkm_kunit_first_dacl_ace_const(parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, source_ace);
	source_ace_len = pkm_kunit_read_u16(source_ace, 2);
	expected_ace = kunit_kzalloc(test, source_ace_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, expected_ace);
	memcpy(expected_ace, source_ace, source_ace_len);
	expected_ace[1] = PKM_KUNIT_OBJECT_INHERIT_ACE |
			  PKM_KUNIT_INHERITED_ACE;

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &child_sd,
							&child_sd_len),
			0);
	actual_ace = pkm_kunit_first_dacl_ace_const(child_sd);
	KUNIT_ASSERT_NOT_NULL(test, actual_ace);
	actual_ace_len = pkm_kunit_read_u16(actual_ace, 2);
	pkm_kunit_expect_bytes_eq(test, actual_ace, actual_ace_len,
				  expected_ace, source_ace_len);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_creator_dacl_no_auto_blocks_parent(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	creator_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							 &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_make_first_file_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	pkm_kunit_expect_inherited_ace_flags(test, child_sd, false, 0);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_protected_creator_dacl_blocks_parent(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	creator_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							 &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_make_first_file_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);
	pkm_kunit_write_u16((u8 *)creator_sd, 2,
			    pkm_kunit_read_u16(creator_sd, 2) |
				    PKM_KUNIT_SE_DACL_AUTO_INHERIT_REQ |
				    PKM_KUNIT_SE_DACL_PROTECTED);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	pkm_kunit_expect_inherited_ace_flags(test, child_sd, false, 0);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_inherits_parent_sacl(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_file_sd_with_mandatory_resource_attr(
		subject_token, &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_sacl_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &child_sd,
							&child_sd_len),
			0);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_PRESENT,
			PKM_KUNIT_SE_SACL_PRESENT);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_AUTO_INHERITED,
			PKM_KUNIT_SE_SACL_AUTO_INHERITED);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_DEFAULTED, 0U);
	pkm_kunit_expect_inherited_sacl_ace_flags(
		test, child_sd, true,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_without_parent_sacl_has_no_sacl(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &child_sd,
							&child_sd_len),
			0);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_PRESENT, 0U);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_DEFAULTED, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(child_sd, 12), 0U);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_creator_sacl_no_auto_blocks_parent(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_file_sd_with_mandatory_resource_attr(
		subject_token, &parent_sd_len);
	creator_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							    &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_make_first_sacl_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_PRESENT,
			PKM_KUNIT_SE_SACL_PRESENT);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_AUTO_INHERITED, 0U);
	pkm_kunit_expect_inherited_sacl_ace_flags(test, child_sd, false, 0);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_protected_creator_sacl_blocks_parent(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *creator_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_file_sd_with_mandatory_resource_attr(
		subject_token, &parent_sd_len);
	creator_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							    &creator_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_NOT_NULL(test, creator_sd);
	pkm_kunit_make_first_sacl_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);
	pkm_kunit_write_u16((u8 *)creator_sd, 2,
			    pkm_kunit_read_u16(creator_sd, 2) |
				    PKM_KUNIT_SE_SACL_AUTO_INHERIT_REQ |
				    PKM_KUNIT_SE_SACL_PROTECTED);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_PRESENT,
			PKM_KUNIT_SE_SACL_PRESENT);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_SACL_AUTO_INHERITED, 0U);
	pkm_kunit_expect_inherited_sacl_ace_flags(test, child_sd, false, 0);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)creator_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_substitutes_creator_sids(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	const u8 *owner_ace;
	const u8 *group_ace;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = kacs_rust_kunit_create_file_sd(
		subject_token, PKM_KUNIT_FILE_READ_DATA, 0,
		PKM_KUNIT_FILE_WRITE_DATA, 0, &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_set_dacl_ace_header(
		(u8 *)parent_sd, parent_sd_len, 0,
		PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE, PKM_KUNIT_FILE_READ_DATA);
	pkm_kunit_set_dacl_ace_header(
		(u8 *)parent_sd, parent_sd_len, 1,
		PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE, PKM_KUNIT_FILE_WRITE_DATA);
	pkm_kunit_set_dacl_ace_sid(
		test, (u8 *)parent_sd, parent_sd_len, 0,
		pkm_kunit_creator_owner_sid,
		sizeof(pkm_kunit_creator_owner_sid));
	pkm_kunit_set_dacl_ace_sid(
		test, (u8 *)parent_sd, parent_sd_len, 1,
		pkm_kunit_creator_group_sid,
		sizeof(pkm_kunit_creator_group_sid));

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &child_sd,
							&child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_AUTO_INHERITED,
			PKM_KUNIT_SE_DACL_AUTO_INHERITED);
	pkm_kunit_expect_sd_sid_component(test, child_sd, child_sd_len, 4,
					  pkm_kunit_local_service_sid,
					  sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_expect_sd_sid_component(test, child_sd, child_sd_len, 8,
					  pkm_kunit_administrators_sid,
					  sizeof(pkm_kunit_administrators_sid));

	pkm_kunit_expect_dacl_ace_header(
		test, child_sd, child_sd_len, 0,
		PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE,
		PKM_KUNIT_FILE_READ_DATA);
	pkm_kunit_expect_dacl_ace_header(
		test, child_sd, child_sd_len, 1,
		PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE,
		PKM_KUNIT_FILE_WRITE_DATA);
	owner_ace = pkm_kunit_dacl_ace_const(child_sd, child_sd_len, 0);
	group_ace = pkm_kunit_dacl_ace_const(child_sd, child_sd_len, 1);
	KUNIT_ASSERT_NOT_NULL(test, owner_ace);
	KUNIT_ASSERT_NOT_NULL(test, group_ace);
	pkm_kunit_expect_bytes_eq(test, owner_ace + 8,
				  sizeof(pkm_kunit_local_service_sid),
				  pkm_kunit_local_service_sid,
				  sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_expect_bytes_eq(test, group_ace + 8,
				  sizeof(pkm_kunit_administrators_sid),
				  pkm_kunit_administrators_sid,
				  sizeof(pkm_kunit_administrators_sid));

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_build_created_file_sd_creator_without_dacl_inherits_parent(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	u8 creator_sd[64] = { };
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable(
		(u8 *)parent_sd, PKM_KUNIT_OBJECT_INHERIT_ACE);
	creator_sd_len = pkm_kunit_build_owner_subset_sd(
		creator_sd, sizeof(creator_sd), pkm_kunit_system_sid,
		sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)creator_sd_len, 0L);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_PRESENT,
			PKM_KUNIT_SE_DACL_PRESENT);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_AUTO_INHERITED,
			PKM_KUNIT_SE_DACL_AUTO_INHERITED);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_DEFAULTED, 0U);
	pkm_kunit_expect_inherited_ace_flags(
		test, child_sd, true,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_creator_without_dacl_uses_default(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	u8 creator_sd[64] = { };
	size_t parent_sd_len = 0;
	size_t creator_sd_len = 0;
	size_t child_sd_len = 0;
	u32 dacl_offset;
	u16 control;
	u16 dacl_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	creator_sd_len = pkm_kunit_build_owner_subset_sd(
		creator_sd, sizeof(creator_sd), pkm_kunit_system_sid,
		sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)creator_sd_len, 0L);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len,
							creator_sd,
							creator_sd_len, 0,
							&child_sd,
							&child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_PRESENT,
			PKM_KUNIT_SE_DACL_PRESENT);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_DEFAULTED,
			PKM_KUNIT_SE_DACL_DEFAULTED);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_AUTO_INHERITED, 0U);

	dacl_offset = pkm_kunit_read_u32(child_sd, 16);
	KUNIT_ASSERT_NE(test, dacl_offset, 0U);
	dacl_len = pkm_kunit_read_u16(child_sd, dacl_offset + 2);
	KUNIT_EXPECT_EQ(test, dacl_len,
			(u16)sizeof(pkm_kunit_system_default_dacl));
	pkm_kunit_expect_bytes_eq(test, child_sd + dacl_offset, dacl_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
}


static void pkm_kunit_build_created_file_sd_without_default_dacl_gets_null_dacl(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	u16 control;

	subject_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_default(subject_token,
						       PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
						       PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
						       NULL,
						       0, 1U),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &child_sd,
							&child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_validate_sd_bytes(child_sd, child_sd_len),
			0);

	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_PRESENT, 0U);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_DEFAULTED, 0U);
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u32(child_sd, 4), 0U);
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u32(child_sd, 8), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(child_sd, 16), 0U);

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_build_created_file_sd_uses_adjusted_default_dacl(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t child_sd_len = 0;
	u32 dacl_offset;
	u16 control;
	u16 dacl_len;

	subject_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_default(
				subject_token, PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
				PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
				pkm_kunit_replacement_default_dacl,
				sizeof(pkm_kunit_replacement_default_dacl), 1U),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &child_sd,
							&child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_validate_sd_bytes(child_sd, child_sd_len),
			0);

	control = pkm_kunit_read_u16(child_sd, 2);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_PRESENT,
			PKM_KUNIT_SE_DACL_PRESENT);
	KUNIT_EXPECT_EQ(test, control & PKM_KUNIT_SE_DACL_DEFAULTED,
			PKM_KUNIT_SE_DACL_DEFAULTED);

	dacl_offset = pkm_kunit_read_u32(child_sd, 16);
	KUNIT_ASSERT_NE(test, dacl_offset, 0U);
	dacl_len = pkm_kunit_read_u16(child_sd, dacl_offset + 2);
	KUNIT_EXPECT_EQ(test, dacl_len,
			(u16)sizeof(pkm_kunit_replacement_default_dacl));
	pkm_kunit_expect_bytes_eq(test, child_sd + dacl_offset, dacl_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	pkm_kacs_free((void *)child_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_build_created_file_sd_adjust_default_future_only(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd;
	const u8 *existing_child_sd = NULL;
	const u8 *future_child_sd = NULL;
	size_t parent_sd_len = 0;
	size_t existing_child_sd_len = 0;
	size_t future_child_sd_len = 0;
	u32 existing_dacl_offset;
	u32 future_dacl_offset;
	u16 existing_control;
	u16 future_control;
	u16 existing_dacl_len;
	u16 future_dacl_len;

	subject_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0,
							&existing_child_sd,
							&existing_child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, existing_child_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_validate_sd_bytes(existing_child_sd,
						    existing_child_sd_len),
			0);

	existing_control = pkm_kunit_read_u16(existing_child_sd, 2);
	KUNIT_EXPECT_EQ(test,
			existing_control & PKM_KUNIT_SE_DACL_PRESENT,
			PKM_KUNIT_SE_DACL_PRESENT);
	KUNIT_EXPECT_EQ(test,
			existing_control & PKM_KUNIT_SE_DACL_DEFAULTED,
			PKM_KUNIT_SE_DACL_DEFAULTED);
	existing_dacl_offset = pkm_kunit_read_u32(existing_child_sd, 16);
	KUNIT_ASSERT_NE(test, existing_dacl_offset, 0U);
	existing_dacl_len = pkm_kunit_read_u16(
		existing_child_sd, existing_dacl_offset + 2);
	KUNIT_EXPECT_EQ(test, existing_dacl_len,
			(u16)sizeof(pkm_kunit_system_default_dacl));
	pkm_kunit_expect_bytes_eq(test,
				  existing_child_sd + existing_dacl_offset,
				  existing_dacl_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));

	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_default(
				subject_token, PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
				PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
				pkm_kunit_replacement_default_dacl,
				sizeof(pkm_kunit_replacement_default_dacl), 1U),
			0);

	existing_dacl_len = pkm_kunit_read_u16(
		existing_child_sd, existing_dacl_offset + 2);
	KUNIT_EXPECT_EQ(test, existing_dacl_len,
			(u16)sizeof(pkm_kunit_system_default_dacl));
	pkm_kunit_expect_bytes_eq(test,
				  existing_child_sd + existing_dacl_offset,
				  existing_dacl_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));

	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0,
							&future_child_sd,
							&future_child_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, future_child_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_validate_sd_bytes(future_child_sd,
						    future_child_sd_len),
			0);

	future_control = pkm_kunit_read_u16(future_child_sd, 2);
	KUNIT_EXPECT_EQ(test, future_control & PKM_KUNIT_SE_DACL_PRESENT,
			PKM_KUNIT_SE_DACL_PRESENT);
	KUNIT_EXPECT_EQ(test, future_control & PKM_KUNIT_SE_DACL_DEFAULTED,
			PKM_KUNIT_SE_DACL_DEFAULTED);
	future_dacl_offset = pkm_kunit_read_u32(future_child_sd, 16);
	KUNIT_ASSERT_NE(test, future_dacl_offset, 0U);
	future_dacl_len = pkm_kunit_read_u16(future_child_sd,
					     future_dacl_offset + 2);
	KUNIT_EXPECT_EQ(test, future_dacl_len,
			(u16)sizeof(pkm_kunit_replacement_default_dacl));
	pkm_kunit_expect_bytes_eq(test, future_child_sd + future_dacl_offset,
				  future_dacl_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	pkm_kacs_free((void *)future_child_sd);
	pkm_kacs_free((void *)existing_child_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_file_missing_sd_synthesize_ephemeral_root_query_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_missing_file_sd_query_args args = {
		.mount_policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.mode = S_IFREG,
	};
	const void *subject_token;
	const u8 *subset = NULL;
	const u8 *expected_sd;
	const u8 *expected_subset = NULL;
	size_t subset_len = 0;
	size_t expected_sd_len = 0;
	size_t expected_subset_len = 0;
	u32 xattr_written = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	args.subject_token = subject_token;

	expected_sd = pkm_kunit_synthesize_file_sd(NULL, 0, NULL, 0, 0,
						   &expected_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, expected_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_query_missing_file_sd_on_policy_mount(
				&args, &subset, &subset_len,
				&xattr_written),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				expected_sd, expected_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	pkm_kunit_expect_bytes_eq(test, subset, subset_len, expected_subset,
				  expected_subset_len);
	KUNIT_EXPECT_EQ(test, xattr_written, 0U);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)expected_sd);
	pkm_kacs_free((void *)subset);
}


static void pkm_kunit_file_missing_sd_synthesize_persistent_root_defers_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_missing_file_sd_query_args args = {
		.mount_policy = KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.mode = S_IFREG,
	};
	const void *subject_token;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	u32 xattr_written = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	args.subject_token = subject_token;

	/*
	 * Synthesis yields a usable SD immediately, but the write-back to the
	 * xattr is deferred to a task_work (it cannot run inline under
	 * sec->lock / a held i_rwsem). The xattr is therefore NOT written by
	 * the query itself.
	 */
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_query_missing_file_sd_on_policy_mount(
				&args, &subset, &subset_len,
				&xattr_written),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_EXPECT_NE(test, subset_len, (size_t)0);
	KUNIT_EXPECT_EQ(test, xattr_written, 0U);

	pkm_kacs_free((void *)subset);
}


static void pkm_kunit_file_missing_sd_persistent_deferred_persist_writes_xattr(
	struct kunit *test)
{
	const void *subject_token;
	u32 inline_written = 1;
	u32 persisted_written = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	/*
	 * The deferred task_work, once it runs, writes the synthesized SD to
	 * the xattr: not written immediately after the query, written after the
	 * persist fires.
	 */
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_persistent_synthesis_deferred_persist(
				subject_token, &inline_written,
				&persisted_written),
			0L);
	KUNIT_EXPECT_EQ(test, inline_written, 0U);
	KUNIT_EXPECT_EQ(test, persisted_written, 1U);
}


static void pkm_kunit_file_missing_sd_persistent_synthesizes_once(
	struct kunit *test)
{
	const void *subject_token;
	long first_ret = 0;
	long second_ret = 0;
	u32 xattr_written = 1;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	/*
	 * The first query synthesizes and caches a SYNTHETIC_PENDING SD; the
	 * second query is served from that cache without re-synthesizing
	 * (both succeed). The synthesized SD is not written to the xattr by the
	 * query path -- the write-back is deferred to a task_work.
	 */
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_persistent_synthesis_second_query_uses_cache(
				subject_token, &first_ret, &second_ret,
				&xattr_written),
			0L);
	KUNIT_EXPECT_EQ(test, first_ret, 0L);
	KUNIT_EXPECT_EQ(test, second_ret, 0L);
	KUNIT_EXPECT_EQ(test, xattr_written, 0U);
}


static void pkm_kunit_file_sd_generation_currentness_by_source(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 missing_current = 1;
	u32 synthetic_current = 1;
	u32 xattr_current = 0;
	u32 corrupt_current = 0;
	u32 synthetic_pending_current = 1;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	/*
	 * Generation-tagged sources (missing, synthetic, and the deferred
	 * synthetic-pending) go stale when the policy generation advances;
	 * xattr-backed and corrupt entries do not.
	 */
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_cache_generation_currentness(
				file_sd, file_sd_len, &missing_current,
				&synthetic_current, &xattr_current,
				&corrupt_current, &synthetic_pending_current),
			0);
	KUNIT_EXPECT_EQ(test, missing_current, 0U);
	KUNIT_EXPECT_EQ(test, synthetic_current, 0U);
	KUNIT_EXPECT_EQ(test, xattr_current, 1U);
	KUNIT_EXPECT_EQ(test, corrupt_current, 1U);
	KUNIT_EXPECT_EQ(test, synthetic_pending_current, 0U);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_missing_sd_synthesize_root_template_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_missing_file_sd_query_args args = {
		.mount_policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.mode = S_IFREG,
	};
	const void *subject_token;
	const u8 *template_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t template_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;
	u32 xattr_written = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	template_sd = pkm_kunit_create_default_file_sd(subject_token,
						       &template_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, template_sd);
	args.subject_token = subject_token;
	args.template_sd_ptr = template_sd;
	args.template_sd_len = template_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_query_missing_file_sd_on_policy_mount(
				&args, &subset, &subset_len,
				&xattr_written),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				template_sd, template_sd_len,
				args.security_info, &expected_subset,
				&expected_subset_len),
			0);
	pkm_kunit_expect_bytes_eq(test, subset, subset_len, expected_subset,
				  expected_subset_len);
	KUNIT_EXPECT_EQ(test, xattr_written, 0U);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)template_sd);
}


static void pkm_kunit_get_file_sd_unmanaged_mount_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_file_sd_on_mount_for_subject(
				&args, PROC_SUPER_MAGIC, &subset,
				&subset_len),
			(long)-EOPNOTSUPP);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_file_sd_label_on_unlabeled_returns_empty_subset(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_file_sd_for_subject(
				&args, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)20);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(subset, 12), 0U);

	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_sd_subset_preserves_rm_control_byte(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_set_sd_rm_control((u8 *)file_sd, 0x5a);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, &subset,
				&subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	pkm_kunit_expect_sd_rm_control(test, subset, 0x5a);

	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_sd_subset_preserves_dacl_trusted_metadata(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_write_u16((u8 *)file_sd, 2,
			    pkm_kunit_read_u16(file_sd, 2) |
				    PKM_KUNIT_SE_DACL_TRUSTED);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, &subset,
				&subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u16(subset, 2) &
				PKM_KUNIT_SE_DACL_TRUSTED,
			PKM_KUNIT_SE_DACL_TRUSTED);

	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_file_sd_subset_preserves_opaque_dacl_ace(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	const u8 *source_ace;
	const u8 *actual_ace;
	size_t file_sd_len = 0;
	size_t subset_len = 0;
	u16 source_ace_len;
	u16 actual_ace_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	pkm_kunit_make_first_file_ace_opaque(
		(u8 *)file_sd,
		PKM_KUNIT_OBJECT_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				file_sd, file_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, &subset,
				&subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);

	source_ace = pkm_kunit_first_dacl_ace_const(file_sd);
	actual_ace = pkm_kunit_first_dacl_ace_const(subset);
	KUNIT_ASSERT_NOT_NULL(test, source_ace);
	KUNIT_ASSERT_NOT_NULL(test, actual_ace);
	source_ace_len = pkm_kunit_read_u16(source_ace, 2);
	actual_ace_len = pkm_kunit_read_u16(actual_ace, 2);
	pkm_kunit_expect_bytes_eq(test, actual_ace, actual_ace_len,
				  source_ace, source_ace_len);

	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)file_sd);
}


static void pkm_kunit_get_file_sd_missing_denies(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *subset = NULL;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	args.subject_token = subject_token;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_file_sd_for_subject(
				&args, &subset, &subset_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);
}


static void pkm_kunit_get_file_sd_denied_without_read_control(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_get_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *file_sd;
	const u8 *subset = NULL;
	size_t file_sd_len = 0;
	size_t subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	file_sd = pkm_kunit_create_write_only_file_sd(target_token,
						      &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_file_sd_for_subject(
				&args, &subset, &subset_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_get_process_sd_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_get_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *process_sd;
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	size_t process_sd_len = 0;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	process_sd = kacs_rust_create_default_process_sd(subject_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_process_sd_for_subject(
				&args, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				process_sd, process_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test, memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_default_process_sd_golden_shape(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot snapshot = { };
	const void *token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &snapshot));

	process_sd = kacs_rust_create_default_process_sd(token, &process_sd_len);
	pkm_kunit_expect_default_process_sd_shape(test, process_sd,
						  process_sd_len, &snapshot);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_stored_object_sd_forms_have_owner(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot token_snapshot = { };
	struct pkm_kacs_session_snapshot session_snapshot = { };
	const void *subject_token;
	const u8 *process_sd = NULL;
	const u8 *socket_sd = NULL;
	const u8 *file_sd = NULL;
	const u8 *synthesized_sd = NULL;
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t process_sd_len = 0;
	size_t socket_sd_len = 0;
	size_t file_sd_len = 0;
	size_t synthesized_sd_len = 0;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &token_snapshot));
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(0, &session_snapshot),
			0);

	pkm_kunit_expect_stored_sd_has_owner(
		test, token_snapshot.own_sd_ptr, token_snapshot.own_sd_len);
	pkm_kunit_expect_stored_sd_has_owner(
		test, session_snapshot.own_sd_ptr, session_snapshot.own_sd_len);

	process_sd = kacs_rust_create_default_process_sd(subject_token,
							 &process_sd_len);
	socket_sd = kacs_rust_create_default_socket_sd(subject_token,
						       &socket_sd_len);
	file_sd = pkm_kunit_create_default_file_sd(subject_token, &file_sd_len);
	synthesized_sd = pkm_kunit_synthesize_file_sd(NULL, 0, NULL, 0, 0,
						      &synthesized_sd_len);
	parent_sd = pkm_kunit_create_query_only_file_sd(subject_token,
							&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	KUNIT_ASSERT_NOT_NULL(test, socket_sd);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	KUNIT_ASSERT_NOT_NULL(test, synthesized_sd);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_build_created_file_sd(subject_token,
							parent_sd,
							parent_sd_len, NULL,
							0, 0, &created_sd,
							&created_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, created_sd);

	pkm_kunit_expect_stored_sd_has_owner(test, process_sd, process_sd_len);
	pkm_kunit_expect_stored_sd_has_owner(test, socket_sd, socket_sd_len);
	pkm_kunit_expect_stored_sd_has_owner(test, file_sd, file_sd_len);
	pkm_kunit_expect_stored_sd_has_owner(test, synthesized_sd,
					     synthesized_sd_len);
	pkm_kunit_expect_stored_sd_has_owner(test, created_sd, created_sd_len);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)synthesized_sd);
	pkm_kacs_free((void *)file_sd);
	pkm_kacs_free((void *)socket_sd);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_get_process_sd_label_on_unlabeled_returns_empty_subset(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_get_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *process_sd;
	const u8 *subset = NULL;
	size_t process_sd_len = 0;
	size_t subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	process_sd = kacs_rust_create_default_process_sd(subject_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_process_sd_for_subject(
				&args, &subset, &subset_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)20);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(subset, 12), 0U);

	pkm_kacs_free((void *)subset);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_get_process_sd_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_get_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	const u8 *subset = NULL;
	size_t process_sd_len = 0;
	size_t subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_process_sd_for_subject(
				&args, &subset, &subset_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_get_process_sd_debug_does_not_bypass(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_get_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	const u8 *subset = NULL;
	size_t process_sd_len = 0;
	size_t subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_process_sd_for_subject(
				&args, &subset, &subset_len),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_get_token_sd_success(struct kunit *test)
{
	const u8 *subset = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t subset_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION |
					PKM_KUNIT_GROUP_SECURITY_INFORMATION |
					PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&subset, &subset_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_token_sd_subset(
				target_token,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION |
					PKM_KUNIT_GROUP_SECURITY_INFORMATION |
					PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test, memcmp(subset, expected_subset, subset_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)subset);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_get_sd_syscall_tokenfd_probe_and_copyout(
	struct kunit *test)
{
	const u8 *expected = NULL;
	const void *subject_token;
	const void *target_token;
	size_t expected_len = 0;
	long token_fd;
	u32 security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
			    PKM_KUNIT_GROUP_SECURITY_INFORMATION |
			    PKM_KUNIT_DACL_SECURITY_INFORMATION;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_token_sd_subset(
				target_token, security_info, &expected,
				&expected_len),
			0);

	pkm_kunit_expect_get_sd_syscall_copyout(
		test, (int)token_fd, expected, expected_len, security_info);

	pkm_kacs_free((void *)expected);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_get_token_sd_label_on_unlabeled_returns_empty_subset(
	struct kunit *test)
{
	const u8 *subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t subset_len = 0;
	long token_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&subset, &subset_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, subset);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)20);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(subset, 12), 0U);

	pkm_kacs_free((void *)subset);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_get_token_sd_denied_by_token_sd(struct kunit *test)
{
	const u8 *subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t subset_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&subset, &subset_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_get_token_sd_debug_does_not_bypass(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const u8 *subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t subset_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&subset, &subset_len),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	KUNIT_EXPECT_PTR_EQ(test, subset, NULL);
	KUNIT_EXPECT_EQ(test, subset_len, (size_t)0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_open_current_thread_token_observes_effective_token_and_revert(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *client_token;
	const void *primary_token;
	long impersonation_fd;
	long open_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)impersonation_fd,
						 primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_IMPERSONATION);

	open_fd = pkm_kacs_kunit_open_current_thread_token_for_subject(
		primary_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, open_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)open_fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token,
			    pkm_kacs_current_effective_token_ptr());

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)open_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	kacs_rust_token_drop(client_token);
}

static struct kunit_case pkm_kunit_file_cases[] = {
	KUNIT_CASE(pkm_kunit_open_self_token_effective_query),
	KUNIT_CASE(pkm_kunit_open_self_token_real_generic_read),
	KUNIT_CASE(pkm_kunit_open_token_denied_by_own_sd),
	KUNIT_CASE(pkm_kunit_open_self_token_generic_mapping_matrix),
	KUNIT_CASE(pkm_kunit_open_self_token_maximum_allowed),
	KUNIT_CASE(pkm_kunit_open_self_token_invalid_flags),
	KUNIT_CASE(pkm_kunit_file_mmap_snapshot_read_and_private_write),
	KUNIT_CASE(pkm_kunit_file_mmap_snapshot_shared_write),
	KUNIT_CASE(pkm_kunit_file_mmap_snapshot_exec),
	KUNIT_CASE(pkm_kunit_file_mprotect_snapshot_uses_vma_shape),
	KUNIT_CASE(pkm_kunit_file_mapping_snapshot_unmanaged_bypasses_facs),
	KUNIT_CASE(pkm_kunit_file_mmap_opath_denied),
	KUNIT_CASE(pkm_kunit_file_permission_snapshot_read_and_unmanaged),
	KUNIT_CASE(pkm_kunit_file_permission_sysfs_write_uses_live_gate),
	KUNIT_CASE(pkm_kunit_file_permission_snapshot_write_and_append),
	KUNIT_CASE(pkm_kunit_file_permission_snapshot_combined_masks),
	KUNIT_CASE(pkm_kunit_file_fd_dup_preserves_cached_grant),
	KUNIT_CASE(pkm_kunit_file_continuous_audit_read_emits_kmes),
	KUNIT_CASE(pkm_kunit_file_continuous_audit_unmatched_mask_no_event),
	KUNIT_CASE(pkm_kunit_file_continuous_audit_denial_emits_failure),
	KUNIT_CASE(pkm_kunit_file_continuous_audit_emit_malformed_fails_closed),
	KUNIT_CASE(pkm_kunit_file_continuous_audit_operation_matrix),
	KUNIT_CASE(pkm_kunit_file_continuous_audit_records_current_pip),
	KUNIT_CASE(pkm_kunit_fchdir_snapshot_requires_traverse),
	KUNIT_CASE(pkm_kunit_file_write_intent_append_and_positioned),
	KUNIT_CASE(pkm_kunit_file_write_intent_noappend_fails_closed),
	KUNIT_CASE(pkm_kunit_file_write_intent_marker_drives_permission),
	KUNIT_CASE(pkm_kunit_file_metadata_getattr_snapshot),
	KUNIT_CASE(pkm_kunit_file_metadata_setattr_snapshot),
	KUNIT_CASE(pkm_kunit_file_metadata_marker_clears_after_dentry_hook),
	KUNIT_CASE(pkm_kunit_file_metadata_xattr_snapshot),
	KUNIT_CASE(pkm_kunit_file_metadata_xattr_protected_names),
	KUNIT_CASE(pkm_kunit_file_metadata_opath_semantics),
	KUNIT_CASE(pkm_kunit_path_metadata_getattr_live),
	KUNIT_CASE(pkm_kunit_path_metadata_setattr_live),
	KUNIT_CASE(pkm_kunit_path_metadata_xattr_live),
	KUNIT_CASE(pkm_kunit_path_metadata_xattr_protected_names),
	KUNIT_CASE(pkm_kunit_path_metadata_access_live),
	KUNIT_CASE(pkm_kunit_inode_permission_traverse_live),
	KUNIT_CASE(pkm_kunit_inode_permission_pathname_socket_write),
	KUNIT_CASE(pkm_kunit_inode_permission_change_notify_bypass),
	KUNIT_CASE(pkm_kunit_inode_permission_chdir_requires_traverse),
	KUNIT_CASE(pkm_kunit_inode_permission_nonblocking_retries),
	KUNIT_CASE(pkm_kunit_inode_permission_unmanaged_skips),
	KUNIT_CASE(pkm_kunit_open_by_handle_requires_change_notify),
	KUNIT_CASE(pkm_kunit_namespace_create_rights_and_sd),
	KUNIT_CASE(pkm_kunit_namespace_mknod_special_modes_fail_closed),
	KUNIT_CASE(pkm_kunit_namespace_symlink_requires_privilege),
	KUNIT_CASE(pkm_kunit_namespace_link_requires_parent_and_source),
	KUNIT_CASE(pkm_kunit_namespace_unlink_delete_duality),
	KUNIT_CASE(pkm_kunit_namespace_rename_checks_required_edges),
	KUNIT_CASE(pkm_kunit_namespace_readlink_requires_read_data),
	KUNIT_CASE(pkm_kunit_namespace_whiteout_flags_native),
	KUNIT_CASE(pkm_kunit_file_ioctl_snapshot_read_classified),
	KUNIT_CASE(pkm_kunit_file_ioctl_snapshot_write_classified),
	KUNIT_CASE(pkm_kunit_file_ioctl_snapshot_fdlocal_fallback_unmanaged),
	KUNIT_CASE(pkm_kunit_file_ioctl_snapshot_compat_aliases),
	KUNIT_CASE(pkm_kunit_file_ioctl_snapshot_full_classification),
	KUNIT_CASE(pkm_kunit_file_ioctl_snapshot_compat_alias_matrix),
	KUNIT_CASE(pkm_kunit_file_ioctl_opath_denied),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_append_transitions),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_noatime_transitions),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_non_right_flags_and_unmanaged),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_tail_no_right_commands),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_tail_lock_commands),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_tail_attr_commands),
	KUNIT_CASE(pkm_kunit_file_fcntl_snapshot_tail_notify_and_unknown),
	KUNIT_CASE(pkm_kunit_file_receive_scm_rights_allows_existing_fd),
	KUNIT_CASE(pkm_kunit_file_lock_snapshot_shared_and_exclusive),
	KUNIT_CASE(pkm_kunit_file_lock_snapshot_denials_and_unmanaged),
	KUNIT_CASE(pkm_kunit_file_truncate_snapshot_requires_write_data),
	KUNIT_CASE(pkm_kunit_file_fallocate_snapshot_extend_modes),
	KUNIT_CASE(pkm_kunit_file_fallocate_snapshot_mutation_modes),
	KUNIT_CASE(pkm_kunit_file_fallocate_snapshot_unsupported_fail_closed),
	KUNIT_CASE(pkm_kunit_open_process_token_success),
	KUNIT_CASE(pkm_kunit_open_process_token_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_open_process_token_denied_by_target_token_sd),
	KUNIT_CASE(pkm_kunit_open_process_token_denied_by_pip),
	KUNIT_CASE(pkm_kunit_open_process_token_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_open_process_token_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_securityfs_self_token_inspection_query_only),
	KUNIT_CASE(pkm_kunit_securityfs_sessions_listing_success),
	KUNIT_CASE(pkm_kunit_securityfs_sessions_listing_exact_lines),
	KUNIT_CASE(pkm_kunit_securityfs_sessions_short_buffer),
	KUNIT_CASE(pkm_kunit_securityfs_sessions_denies_anonymous),
	KUNIT_CASE(pkm_kunit_securityfs_sessions_denies_non_admin_user),
	KUNIT_CASE(pkm_kunit_securityfs_sessions_null_required_fails_closed),
	KUNIT_CASE(pkm_kunit_file_sd_cache_population_from_valid_xattr),
	KUNIT_CASE(pkm_kunit_file_sd_cache_population_cas_loser_frees_copy),
	KUNIT_CASE(pkm_kunit_file_sd_cache_population_corrupt_fails_closed),
	KUNIT_CASE(pkm_kunit_file_sd_cache_population_corrupt_emits_once),
	KUNIT_CASE(pkm_kunit_stored_sd_validation_requires_owner),
	KUNIT_CASE(pkm_kunit_stored_sd_validation_accepts_null_group),
	KUNIT_CASE(pkm_kunit_acl_builder_u16_boundary),
	KUNIT_CASE(pkm_kunit_file_sd_cache_population_ownerless_fails_closed),
	KUNIT_CASE(pkm_kunit_inode_raw_sd_xattr_hooks_deny_canonical_names),
	KUNIT_CASE(pkm_kunit_inode_filecap_nonempty_set_denied_remove_allowed),
	KUNIT_CASE(pkm_kunit_inode_xattr_skipcap_defers_to_kacs),
	KUNIT_CASE(pkm_kunit_inode_xattr_skipcap_null_fails_closed),
	KUNIT_CASE(pkm_kunit_inode_misc_hooks_match_matrix),
	KUNIT_CASE(pkm_kunit_file_open_read_stamps_granted_subset),
	KUNIT_CASE(pkm_kunit_file_open_read_accepts_null_group_sd),
	KUNIT_CASE(pkm_kunit_file_open_sacl_audit_emits_kmes),
	KUNIT_CASE(pkm_kunit_file_open_caap_replace_preserves_cached_grant),
	KUNIT_CASE(pkm_kunit_file_open_caap_replace_narrows_future_open),
	KUNIT_CASE(pkm_kunit_file_open_cached_grant_survives_sd_change),
	KUNIT_CASE(pkm_kunit_file_open_uses_current_psb_pip),
	KUNIT_CASE(pkm_kunit_file_open_append_trunc_stamps_expected_core),
	KUNIT_CASE(pkm_kunit_file_open_append_modifier_core_matrix),
	KUNIT_CASE(pkm_kunit_file_open_core_mode_matrix),
	KUNIT_CASE(pkm_kunit_file_open_data_without_attributes_denies),
	KUNIT_CASE(pkm_kunit_file_open_compat_subset_matrix),
	KUNIT_CASE(pkm_kunit_file_open_special_node_core_matrix),
	KUNIT_CASE(pkm_kunit_file_open_special_node_read_core_matrix),
	KUNIT_CASE(pkm_kunit_file_open_opath_leaves_no_grant),
	KUNIT_CASE(pkm_kunit_file_open_stamps_continuous_audit_mask),
	KUNIT_CASE(pkm_kunit_file_open_directory_read_stamps_expected_subset),
	KUNIT_CASE(pkm_kunit_file_open_core_denial_fails_closed),
	KUNIT_CASE(pkm_kunit_file_open_directory_write_fails_closed),
	KUNIT_CASE(pkm_kunit_file_open_unmanaged_mount_leaves_no_grant),
	KUNIT_CASE(pkm_kunit_file_open_sysfs_write_uses_live_gate),
	KUNIT_CASE(pkm_kunit_native_open_read_success),
	KUNIT_CASE(pkm_kunit_native_open_append_only_sets_write_mode),
	KUNIT_CASE(pkm_kunit_native_open_caches_exact_requested_mask),
	KUNIT_CASE(pkm_kunit_native_open_maximum_allowed_with_read_success),
	KUNIT_CASE(pkm_kunit_native_open_maximum_allowed_requires_mode_bit),
	KUNIT_CASE(pkm_kunit_native_open_maximum_allowed_mode_bit_denied),
	KUNIT_CASE(pkm_kunit_native_open_execute_only_sets_exec_mode),
	KUNIT_CASE(pkm_kunit_native_open_directory_read_success),
	KUNIT_CASE(pkm_kunit_native_open_special_nodes_use_file_rights),
	KUNIT_CASE(pkm_kunit_native_open_special_nodes_fail_closed),
	KUNIT_CASE(pkm_kunit_native_open_partial_denial_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_requires_data_or_execute),
	KUNIT_CASE(pkm_kunit_native_open_invalid_disposition_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_reserved_create_options_fail_closed),
	KUNIT_CASE(pkm_kunit_native_open_bad_padding_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_missing_noncreate_dispositions_fail),
	KUNIT_CASE(pkm_kunit_native_open_delete_on_close_existing_success),
	KUNIT_CASE(pkm_kunit_native_open_delete_on_close_parent_fallback_succeeds),
	KUNIT_CASE(pkm_kunit_native_open_delete_on_close_dup_lineage_final_close),
	KUNIT_CASE(pkm_kunit_native_open_if_delete_on_close_existing_success),
	KUNIT_CASE(pkm_kunit_native_overwrite_delete_on_close_existing_success),
	KUNIT_CASE(pkm_kunit_native_create_delete_on_close_success),
	KUNIT_CASE(pkm_kunit_native_open_delete_on_close_without_delete_denies),
	KUNIT_CASE(pkm_kunit_native_open_delete_on_close_directory_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_delete_child_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_directory_required_non_dir_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_directory_mutation_rights_fail_closed),
	KUNIT_CASE(pkm_kunit_native_open_unmanaged_mount_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_nofollow_symlink_fails_closed),
	KUNIT_CASE(pkm_kunit_native_open_if_existing_success),
	KUNIT_CASE(pkm_kunit_native_open_if_existing_with_creator_sd_invalid),
	KUNIT_CASE(pkm_kunit_native_overwrite_existing_success),
	KUNIT_CASE(pkm_kunit_native_overwrite_preserves_identity_and_truncates),
	KUNIT_CASE(pkm_kunit_native_overwrite_if_preserves_identity_and_truncates),
	KUNIT_CASE(pkm_kunit_native_overwrite_if_existing_success),
	KUNIT_CASE(pkm_kunit_native_overwrite_without_write_data_fails_closed),
	KUNIT_CASE(pkm_kunit_native_overwrite_existing_with_creator_sd_invalid),
	KUNIT_CASE(pkm_kunit_native_overwrite_if_existing_with_creator_sd_invalid),
	KUNIT_CASE(pkm_kunit_native_supersede_existing_success),
	KUNIT_CASE(pkm_kunit_native_supersede_replaces_target_preserves_old_lineage),
	KUNIT_CASE(pkm_kunit_native_supersede_without_delete_denies),
	KUNIT_CASE(pkm_kunit_native_supersede_without_add_file_denies),
	KUNIT_CASE(pkm_kunit_native_destructive_directory_target_fails_closed),
	KUNIT_CASE(pkm_kunit_native_create_existing_fails_closed),
	KUNIT_CASE(pkm_kunit_native_create_regular_success),
	KUNIT_CASE(pkm_kunit_native_create_defaulted_control_flags),
	KUNIT_CASE(pkm_kunit_native_create_directory_success),
	KUNIT_CASE(pkm_kunit_native_create_fixed_modes),
	KUNIT_CASE(pkm_kunit_native_create_owner_self_success),
	KUNIT_CASE(pkm_kunit_native_create_owner_group_success),
	KUNIT_CASE(pkm_kunit_native_create_owner_restore_privilege_success),
	KUNIT_CASE(pkm_kunit_native_open_if_missing_creates_success),
	KUNIT_CASE(pkm_kunit_native_overwrite_if_missing_creates_success),
	KUNIT_CASE(pkm_kunit_native_supersede_missing_creates_success),
	KUNIT_CASE(pkm_kunit_native_create_parent_right_denied),
	KUNIT_CASE(pkm_kunit_native_create_unmanaged_mount_fails_closed),
	KUNIT_CASE(pkm_kunit_native_create_invalid_owner_denies),
	KUNIT_CASE(pkm_kunit_native_create_sacl_without_security_denies),
	KUNIT_CASE(pkm_kunit_native_create_server_security_fails_closed),
	KUNIT_CASE(pkm_kunit_native_create_label_requires_relabel),
	KUNIT_CASE(pkm_kunit_native_create_creator_label_success),
	KUNIT_CASE(pkm_kunit_file_fd_raw_sd_xattr_hooks_deny_canonical_names),
	KUNIT_CASE(pkm_kunit_get_file_sd_cached_success),
	KUNIT_CASE(pkm_kunit_get_file_sd_cached_denied_without_read_control),
	KUNIT_CASE(pkm_kunit_get_file_sd_cached_unmanaged_fails_closed),
	KUNIT_CASE(pkm_kunit_get_file_sd_success),
	KUNIT_CASE(pkm_kunit_get_sd_syscall_filefd_probe_and_copyout),
	KUNIT_CASE(pkm_kunit_get_path_file_sd_success),
	KUNIT_CASE(pkm_kunit_get_path_file_sd_nofollow_accepts_symlink),
	KUNIT_CASE(pkm_kunit_get_path_file_sd_empty_path_fails_closed),
	KUNIT_CASE(pkm_kunit_file_mount_policy_classifies_unmanaged_special_fs),
	KUNIT_CASE(pkm_kunit_file_mount_policy_classifies_synthesize_ephemeral_fs),
	KUNIT_CASE(pkm_kunit_file_mount_policy_defaults_to_deny_missing),
	KUNIT_CASE(pkm_kunit_mount_policy_set_persistent_template_success),
	KUNIT_CASE(pkm_kunit_mount_policy_same_superblock_views_share_policy),
	KUNIT_CASE(pkm_kunit_mount_policy_set_requires_tcb),
	KUNIT_CASE(pkm_kunit_mount_policy_rejects_unmanaged_and_hard_unmanaged),
	KUNIT_CASE(pkm_kunit_mount_policy_rejects_invalid_templates),
	KUNIT_CASE(pkm_kunit_mount_policy_rejects_malformed_abi_args),
	KUNIT_CASE(pkm_kunit_mount_policy_failures_preserve_existing_state),
	KUNIT_CASE(pkm_kunit_mount_policy_opath_fd_names_superblock),
	KUNIT_CASE(pkm_kunit_mount_policy_generation_wrap_skips_zero),
	KUNIT_CASE(pkm_kunit_mount_policy_adoption_invalidates_missing_cache),
	KUNIT_CASE(pkm_kunit_file_missing_sd_deny_mount_returns_missing_state),
	KUNIT_CASE(pkm_kunit_file_missing_sd_synthesize_mount_fails_closed),
	KUNIT_CASE(pkm_kunit_get_file_sd_synthesize_mount_valid_cache_success),
	KUNIT_CASE(pkm_kunit_synthesize_file_sd_parent_inheritance_success),
	KUNIT_CASE(pkm_kunit_synthesize_file_sd_parent_without_inheritance_falls_back),
	KUNIT_CASE(pkm_kunit_synthesize_file_sd_ownerless_template_fails_closed),
	KUNIT_CASE(pkm_kunit_synthesize_file_sd_null_group_template_inherits),
	KUNIT_CASE(pkm_kunit_synthesize_file_sd_creator_group_without_group_denies),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_inheritance_flag_matrix),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_maps_generic_ace_masks),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_preserves_dacl_source_order),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_creator_dacl_preserves_acl_reserved),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_creator_dacl_preserves_opaque_ace),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_parent_preserves_opaque_ace),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_creator_dacl_no_auto_blocks_parent),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_protected_creator_dacl_blocks_parent),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_inherits_parent_sacl),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_without_parent_sacl_has_no_sacl),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_creator_sacl_no_auto_blocks_parent),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_protected_creator_sacl_blocks_parent),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_substitutes_creator_sids),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_creator_without_dacl_inherits_parent),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_creator_without_dacl_uses_default),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_without_default_dacl_gets_null_dacl),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_uses_adjusted_default_dacl),
	KUNIT_CASE(pkm_kunit_build_created_file_sd_adjust_default_future_only),
	KUNIT_CASE(pkm_kunit_file_missing_sd_synthesize_ephemeral_root_query_success),
	KUNIT_CASE(pkm_kunit_file_missing_sd_synthesize_persistent_root_defers_xattr),
	KUNIT_CASE(pkm_kunit_file_missing_sd_persistent_deferred_persist_writes_xattr),
	KUNIT_CASE(pkm_kunit_file_missing_sd_persistent_synthesizes_once),
	KUNIT_CASE(pkm_kunit_file_sd_generation_currentness_by_source),
	KUNIT_CASE(pkm_kunit_file_missing_sd_synthesize_root_template_success),
	KUNIT_CASE(pkm_kunit_get_file_sd_unmanaged_mount_fails_closed),
	KUNIT_CASE(pkm_kunit_get_file_sd_label_on_unlabeled_returns_empty_subset),
	KUNIT_CASE(pkm_kunit_file_sd_subset_preserves_rm_control_byte),
	KUNIT_CASE(pkm_kunit_file_sd_subset_preserves_dacl_trusted_metadata),
	KUNIT_CASE(pkm_kunit_file_sd_subset_preserves_opaque_dacl_ace),
	KUNIT_CASE(pkm_kunit_get_file_sd_missing_denies),
	KUNIT_CASE(pkm_kunit_get_file_sd_denied_without_read_control),
	KUNIT_CASE(pkm_kunit_get_process_sd_success),
	KUNIT_CASE(pkm_kunit_default_process_sd_golden_shape),
	KUNIT_CASE(pkm_kunit_stored_object_sd_forms_have_owner),
	KUNIT_CASE(pkm_kunit_get_process_sd_label_on_unlabeled_returns_empty_subset),
	KUNIT_CASE(pkm_kunit_get_process_sd_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_get_process_sd_debug_does_not_bypass),
	KUNIT_CASE(pkm_kunit_get_token_sd_success),
	KUNIT_CASE(pkm_kunit_get_sd_syscall_tokenfd_probe_and_copyout),
	KUNIT_CASE(pkm_kunit_get_token_sd_label_on_unlabeled_returns_empty_subset),
	KUNIT_CASE(pkm_kunit_get_token_sd_denied_by_token_sd),
	KUNIT_CASE(pkm_kunit_get_token_sd_debug_does_not_bypass),
	KUNIT_CASE(pkm_kunit_open_current_thread_token_observes_effective_token_and_revert),
	{}
};

static struct kunit_suite pkm_kunit_file_suite = {
	.name = "pkm_kunit_file",
	.test_cases = pkm_kunit_file_cases,
};

kunit_test_suite(pkm_kunit_file_suite);
