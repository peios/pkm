// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_hive_route_reflects_active_and_down_slots(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_hive_route_result route = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src), NULL,
						0, &route),
			(long)-ENOENT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src), NULL,
						0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src), NULL,
						0, &route),
			(long)-EIO);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_hive_route_private_scope_shadows_global(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	const u8 matching_scope[1][16] = { { 9 } };
	const u8 other_scope[1][16] = { { 7 } };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry global_hive;
	struct reg_src_register_args global_args;
	struct reg_src_hive_entry private_hive;
	struct reg_src_register_args private_args;
	struct pkm_lcs_hive_route_result route = { };
	struct file global_file = { };
	struct file private_file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &global_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &private_file),
			0L);

	pkm_lcs_kunit_build_register_args(&global_args, &global_hive, name_src,
					  1, 0);
	pkm_lcs_kunit_build_private_register_args(
		&private_args, &private_hive, name_src, 2, 9);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &global_file, &ops,
				(const void __user *)&global_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &private_file, &ops,
				(const void __user *)&private_args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src), NULL,
						0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src),
						other_scope, 1, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src),
						matching_scope, 1, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 2U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 2U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&global_file),
			0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&private_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_access_bridge_allows_registry_rights(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, sd, sd_len, KEY_READ, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.access_check_granted, KEY_READ | WRITE_DAC);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.key_open_sacl_audit_required, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_access_bridge_denies_partial_grants(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 desired = KEY_QUERY_VALUE | KEY_SET_VALUE;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, sd, sd_len, desired, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, desired);
	KUNIT_EXPECT_EQ(test, plan.access_check_granted,
			KEY_QUERY_VALUE | READ_CONTROL | WRITE_DAC);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_access_bridge_maximum_allowed(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 granted = KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL;
	u32 maximum_allowed = granted | WRITE_DAC;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, granted, 0, 0, 0, &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, sd, sd_len, MAXIMUM_ALLOWED, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access_check_granted, maximum_allowed);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, maximum_allowed);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_access_bridge_malformed_sd_eio(
	struct kunit *test)
{
	static const u8 malformed_sd[] = { 0x01, 0x00, 0x00, 0x00 };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_READ,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, malformed_sd, sizeof(malformed_sd),
				KEY_READ, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access_check_granted, 0U);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_audit_not_required_no_event(
	struct kunit *test)
{
	static const u8 key_guid[16] = {
		0x30, 0x30, 0x03, 0x03, 0x30, 0x30, 0x03, 0x03,
		0x30, 0x30, 0x03, 0x03, 0x30, 0x30, 0x03, 0x03,
	};
	struct pkm_lcs_key_open_access_plan plan = {
		.mapped_desired_access = KEY_READ,
		.fd_granted_access = KEY_READ,
		.allowed = 1,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[256];
	size_t written = 0;
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_emit_key_open_audit_for_token(token, key_guid,
							      &plan),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &snapshot),
			-ENOENT);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_audit_emits_lcs_kmes_event(
	struct kunit *test)
{
	static const char event_type[] = "LCS_KEY_OPEN_AUDIT";
	static const u8 key_guid[16] = {
		0x30, 0x30, 0x03, 0x03, 0x30, 0x30, 0x03, 0x03,
		0x30, 0x30, 0x03, 0x03, 0x30, 0x30, 0x03, 0x03,
	};
	struct pkm_lcs_key_open_access_plan plan = {
		.requested_access = KEY_READ,
		.mapped_desired_access = KEY_READ,
		.fd_granted_access = KEY_READ,
		.allowed = 1,
		.key_open_sacl_audit_required = 1,
		.audit_payload_failure_blocks_completion = 1,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[2048];
	size_t written = 0;
	u32 header_size;
	u16 type_len;
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_emit_key_open_audit_for_token(token, key_guid,
							      &plan),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &snapshot),
			0);
	KUNIT_ASSERT_GT(test, written, (size_t)KMES_EVENT_HEADER_BASE_SIZE);

	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)(sizeof(event_type) - 1));
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_LCS);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_EXPECT_EQ(test, buffer[header_size], 0x86);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_open_audit_payload_abi_rejects_bad_state(
	struct kunit *test)
{
	static const u8 malformed_sid[] = { 0x01, 0x01 };
	static const u8 key_guid[16] = {
		0x30, 0x30, 0x03, 0x03, 0x30, 0x30, 0x03, 0x03,
		0x30, 0x30, 0x03, 0x03, 0x30, 0x30, 0x03, 0x03,
	};
	struct pkm_lcs_kunit_audit_caller_summary caller = {
		.effective_token_guid = { 1 },
		.true_token_guid = { 2 },
		.process_guid = { 3 },
		.user_sid = malformed_sid,
		.user_sid_len = sizeof(malformed_sid),
		.authentication_id = 10,
		.token_id = 11,
		.token_type = 1,
		.impersonation_level = 0,
		.integrity_level = 8192,
	};
	size_t written = 0;

	KUNIT_EXPECT_EQ(test,
			lcs_rust_key_open_audit_payload(
				&caller, key_guid, KEY_READ, KEY_READ, 1, 1,
				NULL, 0, &written),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
}


static void pkm_lcs_kunit_key_fd_publish_snapshot_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x11 },
		{ 0x22, 0x23 },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 7,
		.granted_access = KEY_READ,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	long fd;

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));

	fd = pkm_lcs_key_fd_publish(&input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);

	KUNIT_EXPECT_EQ(test, snapshot.source_id, 7U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);
	KUNIT_EXPECT_FALSE(test, snapshot.watch_armed);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, ancestors[1],
			       sizeof(snapshot.key_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.first_ancestor_guid, ancestors[0],
			       sizeof(snapshot.first_ancestor_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, ancestors[1],
			       sizeof(snapshot.last_ancestor_guid)),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.first_component_len, 7U);
	KUNIT_EXPECT_EQ(test, snapshot.last_component_len, 8U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Software");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_publish_deep_copies_input(struct kunit *test)
{
	char machine[] = "Machine";
	char software[] = "Software";
	const char *path[] = { machine, software };
	u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x41 },
		{ 0x42 },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 5,
		.granted_access = KEY_QUERY_VALUE,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	long fd;

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));

	fd = pkm_lcs_key_fd_publish(&input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	machine[0] = 'X';
	software[0] = 'Y';
	ancestors[0][0] = 0xff;
	ancestors[1][0] = 0xee;
	input.key_guid[0] = 0xdd;
	input.granted_access = KEY_SET_VALUE;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, snapshot.key_guid[0], 0x42U);
	KUNIT_EXPECT_EQ(test, snapshot.first_ancestor_guid[0], 0x41U);
	KUNIT_EXPECT_EQ(test, snapshot.last_ancestor_guid[0], 0x42U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Software");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_publish_rejects_malformed_state(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const char * const bad_path[] = { "Machine", NULL };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x31 },
		{ 0x32 },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 3,
		.granted_access = KEY_QUERY_VALUE,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};

	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_publish(NULL), (long)-EINVAL);

	input.source_id = 0;
	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_publish(&input), (long)-EINVAL);

	input.source_id = 3;
	memset(input.key_guid, 0, sizeof(input.key_guid));
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_publish(&input), (long)-EINVAL);

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));
	input.granted_access = GENERIC_READ;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_publish(&input), (long)-EINVAL);

	input.granted_access = KEY_QUERY_VALUE;
	input.key_guid[0] = 0x99;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_publish(&input), (long)-EINVAL);

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));
	input.resolved_path = bad_path;
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_publish(&input), (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_snapshot_rejects_non_key_fd(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_snapshot snapshot = {
		.source_id = 99,
	};
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot(-1, &snapshot),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot(-1, NULL),
			(long)-EINVAL);

	fd = anon_inode_getfd("lcs-not-key", &pkm_lcs_kunit_non_key_fops,
			      NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot(fd, &snapshot),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_fixed_ioctl_access_gates(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_fixed_ioctl_access(
				(int)fd, REG_IOC_QUERY_VALUE),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_fixed_ioctl_access(
				(int)fd, REG_IOC_SET_VALUE),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_fixed_ioctl_access(
				(int)fd, REG_IOC_GET_SECURITY),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_fixed_ioctl_access(
				(int)fd,
				_IO('X', REG_IOC_QUERY_VALUE_NR)),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_fixed_ioctl_access_matrix(
	struct kunit *test)
{
	static const struct {
		unsigned int cmd;
		u32 required;
	} cases[] = {
		{ REG_IOC_QUERY_VALUE, KEY_QUERY_VALUE },
		{ REG_IOC_SET_VALUE, KEY_SET_VALUE },
		{ REG_IOC_DELETE_VALUE, KEY_SET_VALUE },
		{ REG_IOC_BLANKET_TOMBSTONE, KEY_SET_VALUE },
		{ REG_IOC_QUERY_VALUES_BATCH, KEY_QUERY_VALUE },
		{ REG_IOC_ENUM_VALUES, KEY_QUERY_VALUE },
		{ REG_IOC_ENUM_SUBKEYS, KEY_ENUMERATE_SUB_KEYS },
		{ REG_IOC_QUERY_KEY_INFO, READ_CONTROL },
		{ REG_IOC_DELETE_KEY, DELETE },
		{ REG_IOC_HIDE_KEY, DELETE },
		{ REG_IOC_NOTIFY, KEY_NOTIFY },
		{ REG_IOC_FLUSH, KEY_SET_VALUE },
	};
	static const unsigned int non_fixed_cmds[] = {
		REG_IOC_GET_SECURITY,
		REG_IOC_SET_SECURITY,
		REG_IOC_BACKUP,
		REG_IOC_RESTORE,
		REG_IOC_COMMIT,
		REG_IOC_TXN_STATUS,
	};
	long fd;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fd = pkm_lcs_kunit_publish_key_fd_with_access(cases[i].required);
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_check_fixed_ioctl_access(
					(int)fd, cases[i].cmd),
				0L);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

		fd = pkm_lcs_kunit_publish_key_fd_with_access(0);
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_check_fixed_ioctl_access(
					(int)fd, cases[i].cmd),
				(long)-EACCES);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_ALL_ACCESS |
						     ACCESS_SYSTEM_SECURITY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	for (i = 0; i < ARRAY_SIZE(non_fixed_cmds); i++)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_check_fixed_ioctl_access(
					(int)fd, non_fixed_cmds[i]),
				(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_security_ioctl_access_gates(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(READ_CONTROL |
						     ACCESS_SYSTEM_SECURITY |
						     WRITE_DAC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				(int)fd, REG_IOC_GET_SECURITY,
				DACL_SECURITY_INFORMATION |
					SACL_SECURITY_INFORMATION),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				(int)fd, REG_IOC_SET_SECURITY,
				DACL_SECURITY_INFORMATION),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				(int)fd, REG_IOC_SET_SECURITY,
				OWNER_SECURITY_INFORMATION),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				(int)fd, REG_IOC_GET_SECURITY, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				(int)fd, REG_IOC_GET_SECURITY, 0x80U),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				(int)fd, REG_IOC_QUERY_VALUE,
				DACL_SECURITY_INFORMATION),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_security_ioctl_access_matrix(
	struct kunit *test)
{
	static const struct {
		unsigned int cmd;
		u32 security_info;
		u32 required;
	} cases[] = {
		{
			REG_IOC_GET_SECURITY,
			OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION,
			READ_CONTROL,
		},
		{
			REG_IOC_GET_SECURITY,
			SACL_SECURITY_INFORMATION,
			ACCESS_SYSTEM_SECURITY,
		},
		{
			REG_IOC_GET_SECURITY,
			OWNER_SECURITY_INFORMATION |
				SACL_SECURITY_INFORMATION,
			READ_CONTROL | ACCESS_SYSTEM_SECURITY,
		},
		{
			REG_IOC_SET_SECURITY,
			OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION,
			WRITE_OWNER,
		},
		{
			REG_IOC_SET_SECURITY,
			DACL_SECURITY_INFORMATION,
			WRITE_DAC,
		},
		{
			REG_IOC_SET_SECURITY,
			SACL_SECURITY_INFORMATION,
			ACCESS_SYSTEM_SECURITY,
		},
		{
			REG_IOC_SET_SECURITY,
			OWNER_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION |
				SACL_SECURITY_INFORMATION,
			WRITE_OWNER | WRITE_DAC | ACCESS_SYSTEM_SECURITY,
		},
	};
	long fd;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fd = pkm_lcs_kunit_publish_key_fd_with_access(cases[i].required);
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_check_security_ioctl_access(
					(int)fd, cases[i].cmd,
					cases[i].security_info),
				0L);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

		fd = pkm_lcs_kunit_publish_key_fd_with_access(0);
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_check_security_ioctl_access(
					(int)fd, cases[i].cmd,
					cases[i].security_info),
				(long)-EACCES);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}
}


static void pkm_lcs_kunit_key_fd_raw_ioctl_null_args_fail_closed(
	struct kunit *test)
{
	static const unsigned int null_arg_cmds[] = {
		REG_IOC_SET_VALUE,
		REG_IOC_DELETE_VALUE,
		REG_IOC_BLANKET_TOMBSTONE,
		REG_IOC_DELETE_KEY,
		REG_IOC_HIDE_KEY,
		REG_IOC_QUERY_VALUE,
		REG_IOC_QUERY_VALUES_BATCH,
		REG_IOC_ENUM_VALUES,
		REG_IOC_ENUM_SUBKEYS,
		REG_IOC_QUERY_KEY_INFO,
		REG_IOC_GET_SECURITY,
		REG_IOC_SET_SECURITY,
		REG_IOC_BACKUP,
		REG_IOC_RESTORE,
		REG_IOC_NOTIFY,
	};
	u32 access = KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY;
	long fd;
	size_t i;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(access);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	for (i = 0; i < ARRAY_SIZE(null_arg_cmds); i++)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_raw_ioctl(
					(int)fd, null_arg_cmds[i], 0),
				(long)-EFAULT);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				(int)fd, _IO(REG_IOC_TYPE, 0xff), 0),
			(long)-ENOTTY);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				(int)fd, _IO('X', REG_IOC_QUERY_VALUE_NR), 0),
			(long)-ENOTTY);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_raw_ioctl_copyin_fault_matrix(
	struct kunit *test)
{
	static const unsigned int arg_cmds[] = {
		REG_IOC_SET_VALUE,
		REG_IOC_DELETE_VALUE,
		REG_IOC_BLANKET_TOMBSTONE,
		REG_IOC_DELETE_KEY,
		REG_IOC_HIDE_KEY,
		REG_IOC_QUERY_VALUE,
		REG_IOC_QUERY_VALUES_BATCH,
		REG_IOC_ENUM_VALUES,
		REG_IOC_ENUM_SUBKEYS,
		REG_IOC_QUERY_KEY_INFO,
		REG_IOC_GET_SECURITY,
		REG_IOC_SET_SECURITY,
		REG_IOC_BACKUP,
		REG_IOC_RESTORE,
		REG_IOC_NOTIFY,
	};
	u32 access = KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY;
	long fd;
	size_t i;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(access);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	for (i = 0; i < ARRAY_SIZE(arg_cmds); i++)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_raw_ioctl(
					(int)fd, arg_cmds[i], 1UL),
				(long)-EFAULT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_raw_ioctl_rejects_bad_fds(
	struct kunit *test)
{
	struct reg_query_key_info_args args = { };
	int not_key_fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				-1, REG_IOC_FLUSH, 0),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				-1, REG_IOC_QUERY_KEY_INFO,
				(unsigned long)&args),
			(long)-EBADF);

	not_key_fd = anon_inode_getfd("lcs-not-key-raw-ioctl",
				      &pkm_lcs_kunit_non_key_fops, NULL,
				      O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_key_fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				not_key_fd, REG_IOC_FLUSH, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				not_key_fd, REG_IOC_QUERY_KEY_INFO,
				(unsigned long)&args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_key_fd), 0);
}


static void pkm_lcs_kunit_key_fd_raw_ioctl_flush_no_arg_access_gate(
	struct kunit *test)
{
	long denied_fd;
	long allowed_fd;

	pkm_lcs_kunit_reset_source_table();
	denied_fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_SET_VALUE);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				(int)denied_fd, REG_IOC_FLUSH, 0),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl(
				(int)allowed_fd, REG_IOC_FLUSH, 0),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
}


static void pkm_lcs_kunit_key_fd_get_security_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x55 },
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_get_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = 64,
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = ancestors[1],
		.name = "Software",
		.sd = existing_owner_system_sd,
		.sd_len = sizeof(existing_owner_system_sd),
	};
	u8 output[64];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(output, 0xaa, sizeof(output));
	args.sd_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.sd_len,
			(u32)sizeof(existing_owner_system_sd));
	KUNIT_EXPECT_EQ(test,
			memcmp(output, existing_owner_system_sd,
			       sizeof(existing_owner_system_sd)),
			0);
	KUNIT_EXPECT_EQ(test, output[sizeof(existing_owner_system_sd)], 0xaa);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_get_security_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x56 },
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_get_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = 16,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	u8 output[16] = { };
	long allowed_fd;
	long denied_fd;

	args.sd_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args.security_info = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_get_security((int)allowed_fd,
							  &ops, &args),
			(long)-EINVAL);

	args.security_info = OWNER_SECURITY_INFORMATION | 0x80U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_get_security((int)allowed_fd,
							  &ops, &args),
			(long)-EINVAL);

	args.security_info = OWNER_SECURITY_INFORMATION;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_get_security((int)denied_fd,
							  &ops, &args),
			(long)-EACCES);

	args.security_info = SACL_SECURITY_INFORMATION;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_get_security((int)allowed_fd,
							  &ops, &args),
			(long)-EACCES);

	args.security_info = OWNER_SECURITY_INFORMATION;
	args.sd_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_get_security((int)allowed_fd,
							  &ops, &args),
			(long)-EFAULT);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_get_security_erange_probe(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x57 },
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_get_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = 0,
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = ancestors[1],
		.name = "Software",
		.sd = existing_owner_system_sd,
		.sd_len = sizeof(existing_owner_system_sd),
	};
	u8 output[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.sd_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, args.sd_len,
			(u32)sizeof(existing_owner_system_sd));
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, output[0], 0xaa);

	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_get_security_args) {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = 0,
		.sd_ptr = 0,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-null-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.sd_len,
			(u32)sizeof(existing_owner_system_sd));
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.sd_ptr, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_get_security_copyout_fault(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x58 },
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_get_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = 64,
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = ancestors[1],
		.name = "Software",
		.sd = existing_owner_system_sd,
		.sd_len = sizeof(existing_owner_system_sd),
	};
	u8 output[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.sd_ptr = (u64)(unsigned long)output;
	ctx.fault_dst = output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, args.sd_len,
			(u32)sizeof(existing_owner_system_sd));
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, output[0], 0x00);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_get_security_malformed_source_sd(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x59 },
	};
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_get_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = 64,
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = ancestors[1],
		.name = "Software",
		.sd = bad_sd,
		.sd_len = sizeof(bad_sd),
	};
	u8 output[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.sd_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x62 },
	};
	static const char value_name[] = "Answer";
	static const char value_name_input[] = {
		'A', 'n', 's', 'w', 'e', 'r', '!'
	};
	static const u8 value_data[] = { 4, 3, 2, 1 };
	static const u8 default_data[] = { 0x5a };
	static const char separator_value_name[] = "A/B\\C";
	static const u8 separator_data[] = { 0x77, 0x88 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name_input,
		.data_len = 16,
		.layer_buf_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
	};
	u8 data[16];
	u8 layer[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(data, 0xaa, sizeof(data));
	memset(layer, 0xaa, sizeof(layer));
	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 2U);
	KUNIT_EXPECT_EQ(test, args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, args.layer_len, 4U);
	KUNIT_EXPECT_EQ(test, args._pad1, 0U);
	KUNIT_EXPECT_EQ(test, memcmp(data, value_data, sizeof(value_data)), 0);
	KUNIT_EXPECT_EQ(test, data[sizeof(value_data)], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(layer, "base", 4), 0);
	KUNIT_EXPECT_EQ(test, layer[4], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	memset(data, 0xaa, sizeof(data));
	memset(layer, 0xaa, sizeof(layer));
	script.expected_value_name = "";
	script.data = default_data;
	script.data_len = sizeof(default_data);
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_value_args) {
		.name_len = 0,
		.name_ptr = 0,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.layer_buf_len = sizeof(layer),
		.layer_ptr = (u64)(unsigned long)layer,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-query-default-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 2U);
	KUNIT_EXPECT_EQ(test, args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(default_data));
	KUNIT_EXPECT_EQ(test, args.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, args.layer_len, 4U);
	KUNIT_EXPECT_EQ(test, memcmp(data, default_data,
				     sizeof(default_data)), 0);
	KUNIT_EXPECT_EQ(test, data[sizeof(default_data)], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(layer, "base", 4), 0);
	KUNIT_EXPECT_EQ(test, layer[4], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	memset(data, 0xaa, sizeof(data));
	memset(layer, 0xaa, sizeof(layer));
	script.expected_value_name = separator_value_name;
	script.data = separator_data;
	script.data_len = sizeof(separator_data);
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_value_args) {
		.name_len = strlen(separator_value_name),
		.name_ptr = (u64)(unsigned long)separator_value_name,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.layer_buf_len = sizeof(layer),
		.layer_ptr = (u64)(unsigned long)layer,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-query-separator-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 2U);
	KUNIT_EXPECT_EQ(test, args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(separator_data));
	KUNIT_EXPECT_EQ(test, args.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, args.layer_len, 4U);
	KUNIT_EXPECT_EQ(test, memcmp(data, separator_data,
				     sizeof(separator_data)), 0);
	KUNIT_EXPECT_EQ(test, data[sizeof(separator_data)], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(layer, "base", 4), 0);
	KUNIT_EXPECT_EQ(test, layer[4], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_value_reads_resolve_policy_layer(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xaa, 0x01 },
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xaa, 0x02
	};
	static const char value_name[] = "Answer";
	static const char policy_layer_name[] = "policy";
	static const u8 base_data[] = { 0x11 };
	static const u8 policy_data[] = { 0x2a };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args query_args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 16,
		.layer_buf_len = 16,
		.txn_fd = -1,
	};
	struct reg_query_values_batch_args batch_args = {
		.buf_len = 64,
		.txn_fd = -1,
	};
	struct reg_enum_value_args enum_args = {
		.index = 0,
		.name_len = 16,
		.data_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.response_value_name = value_name,
		.layer_name = "base",
		.data = base_data,
		.data_len = sizeof(base_data),
		.value_type = REG_BINARY,
		.include_second_value = true,
		.second_response_value_name = value_name,
		.second_layer_name = policy_layer_name,
		.second_data = policy_data,
		.second_data_len = sizeof(policy_data),
		.second_value_type = REG_BINARY,
	};
	u8 query_data[16];
	u8 query_layer[16];
	u8 batch_output[64];
	u8 enum_name[16];
	u8 enum_data[16];
	size_t offset = 0;
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 policy_sequence;
	u64 base_sequence;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	script.sequence = base_sequence;
	script.second_sequence = policy_sequence;
	script.file = &file;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				policy_layer_name, strlen(policy_layer_name),
				10, 1, policy_layer_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	memset(query_data, 0xaa, sizeof(query_data));
	memset(query_layer, 0xaa, sizeof(query_layer));
	query_args.data_ptr = (u64)(unsigned long)query_data;
	query_args.layer_ptr = (u64)(unsigned long)query_layer;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-query-policy-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &query_args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, query_args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, query_args.data_len, (u32)sizeof(policy_data));
	KUNIT_EXPECT_EQ(test, query_args.sequence, policy_sequence);
	KUNIT_EXPECT_EQ(test, query_args.layer_len,
			(u32)strlen(policy_layer_name));
	KUNIT_EXPECT_EQ(test, memcmp(query_data, policy_data,
				     sizeof(policy_data)), 0);
	KUNIT_EXPECT_EQ(test, query_data[sizeof(policy_data)], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(query_layer, policy_layer_name,
				     strlen(policy_layer_name)), 0);
	KUNIT_EXPECT_EQ(test, query_layer[strlen(policy_layer_name)], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	memset(batch_output, 0xaa, sizeof(batch_output));
	script.expected_value_name = "";
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	script.query_all = true;
	batch_args.buf_ptr = (u64)(unsigned long)batch_output;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-batch-policy-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops,
						      &batch_args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, batch_args.count, 1U);
	KUNIT_EXPECT_EQ(test, batch_args.buf_len,
			(u32)(12 + strlen(value_name) + sizeof(policy_data)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(batch_output + offset),
			(u32)strlen(value_name));
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, memcmp(batch_output + offset, value_name,
				     strlen(value_name)), 0);
	offset += strlen(value_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(batch_output + offset),
			(u32)REG_BINARY);
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(batch_output + offset),
			(u32)sizeof(policy_data));
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, memcmp(batch_output + offset, policy_data,
				     sizeof(policy_data)), 0);
	offset += sizeof(policy_data);
	KUNIT_EXPECT_EQ(test, batch_output[offset], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	memset(enum_name, 0xaa, sizeof(enum_name));
	memset(enum_data, 0xaa, sizeof(enum_data));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	enum_args.name_ptr = (u64)(unsigned long)enum_name;
	enum_args.data_ptr = (u64)(unsigned long)enum_data;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-enum-policy-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &enum_args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, enum_args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, enum_args.name_len, (u32)strlen(value_name));
	KUNIT_EXPECT_EQ(test, enum_args.data_len, (u32)sizeof(policy_data));
	KUNIT_EXPECT_EQ(test, memcmp(enum_name, value_name,
				     strlen(value_name)), 0);
	KUNIT_EXPECT_EQ(test, enum_name[strlen(value_name)], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(enum_data, policy_data,
				     sizeof(policy_data)), 0);
	KUNIT_EXPECT_EQ(test, enum_data[sizeof(policy_data)], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_erange_all_or_none(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x63 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1, 2, 3, 4 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 2,
		.layer_buf_len = 2,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
	};
	u8 data[2] = { 0xaa, 0xaa };
	u8 layer[2] = { 0xaa, 0xaa };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.layer_len, 4U);
	KUNIT_EXPECT_EQ(test, args.type, 0U);
	KUNIT_EXPECT_EQ(test, data[0], 0xaaU);
	KUNIT_EXPECT_EQ(test, layer[0], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_value_args) {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 0,
		.data_ptr = 0,
		.layer_buf_len = 0,
		.layer_ptr = 0,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-query-value-null-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.layer_len, 4U);
	KUNIT_EXPECT_EQ(test, args.type, 0U);
	KUNIT_EXPECT_EQ(test, args.data_ptr, 0ULL);
	KUNIT_EXPECT_EQ(test, args.layer_ptr, 0ULL);

	memset(&ctx, 0, sizeof(ctx));
	memset(data, 0xaa, sizeof(data));
	memset(layer, 0xaa, sizeof(layer));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_value_args) {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 0,
		.data_ptr = (u64)(unsigned long)data,
		.layer_buf_len = 0,
		.layer_ptr = (u64)(unsigned long)layer,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-query-value-nonnull-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.layer_len, 4U);
	KUNIT_EXPECT_EQ(test, args.type, 0U);
	KUNIT_EXPECT_EQ(test, data[0], 0xaaU);
	KUNIT_EXPECT_EQ(test, layer[0], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_blanket_enoent(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x64 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 8,
		.layer_buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.include_blanket = true,
		.blanket_layer_name = "base",
	};
	u8 data[8] = { };
	u8 layer[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 value_sequence;
	u64 blanket_sequence;
	long fd;
	long ret;
	int thread_ret;

	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&value_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&blanket_sequence), 0L);
	script.sequence = value_sequence;
	script.blanket_sequence = blanket_sequence;
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_transaction_context(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x65 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 9 };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 8,
		.layer_buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
	};
	u8 data[8] = { };
	u8 layer[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long txn_fd;
	long fd;
	long ret;
	int thread_ret;

	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				ancestors[0]),
			0L);
	args.txn_fd = (int)txn_fd;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 2U);
	KUNIT_EXPECT_EQ(test, args.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, memcmp(data, value_data, sizeof(value_data)), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x66 },
	};
	static const char value_name[] = "Answer";
	static const char bad_value_name[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_value_name[] = { 'b', 0xff, 'd' };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 8,
		.layer_buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 data[8] = { };
	u8 layer[8] = { };
	struct file file = { };
	const void *token;
	long allowed_fd;
	long denied_fd;
	long txn_fd;

	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;

	args._pad1 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EINVAL);
	args._pad1 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	args.data_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EFAULT);
	args.data_ptr = (u64)(unsigned long)data;

	args.name_len = sizeof(bad_value_name);
	args.name_ptr = (u64)(unsigned long)bad_value_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EINVAL);
	args.name_len = sizeof(value_name) - 1;
	args.name_ptr = (u64)(unsigned long)value_name;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	ctx.reads = 0;

	args.name_len = sizeof(invalid_utf8_value_name);
	args.name_ptr = (u64)(unsigned long)invalid_utf8_value_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EINVAL);
	args.name_len = sizeof(value_name) - 1;
	args.name_ptr = (u64)(unsigned long)value_name;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	ctx.reads = 0;

	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EFAULT);
	args.layer_ptr = (u64)(unsigned long)layer;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)denied_fd,
							 &ops, &args),
			(long)-EACCES);

	args.name_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EFAULT);
	args.name_ptr = (u64)(unsigned long)value_name;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				(u8[RSI_GUID_SIZE]){ 2 }),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	args.txn_fd = -1;

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_copyout_fault(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x67 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1, 2 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 8,
		.layer_buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
	};
	u8 data[8] = { };
	u8 layer[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;
	ctx.fault_dst = data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_value_malformed_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x68 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 8,
		.layer_buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.response_value_name = "Other",
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
	};
	u8 data[8] = { };
	u8 layer[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x90 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 4, 3, 2 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 64,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 output[64];
	size_t offset = 0;
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(output, 0xaa, sizeof(output));
	args.buf_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)(12 + sizeof(value_name) - 1 +
			      sizeof(value_data)));
	KUNIT_EXPECT_EQ(test, args.count, 1U);
	KUNIT_EXPECT_EQ(test, args._pad, 0U);

	KUNIT_EXPECT_EQ(test, get_unaligned_le32(output + offset),
			(u32)sizeof(value_name) - 1);
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, memcmp(output + offset, value_name,
				     sizeof(value_name) - 1), 0);
	offset += sizeof(value_name) - 1;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(output + offset),
			(u32)REG_BINARY);
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(output + offset),
			(u32)sizeof(value_data));
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, memcmp(output + offset, value_data,
				     sizeof(value_data)), 0);
	offset += sizeof(value_data);
	KUNIT_EXPECT_EQ(test, output[offset], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_empty_effective_set(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x91 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
		.include_blanket = true,
		.blanket_layer_name = "base",
	};
	u8 output[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 value_sequence;
	u64 blanket_sequence;
	long fd;
	long ret;
	int thread_ret;

	memset(output, 0xaa, sizeof(output));
	args.buf_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&value_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&blanket_sequence), 0L);
	script.sequence = value_sequence;
	script.blanket_sequence = blanket_sequence;
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-empty");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);
	KUNIT_EXPECT_EQ(test, args.count, 0U);
	KUNIT_EXPECT_EQ(test, output[0], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_erange_all_or_none(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x92 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1, 2, 3, 4 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 output[8] = { [0 ... 7] = 0xaa };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.buf_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)(12 + sizeof(value_name) - 1 +
			      sizeof(value_data)));
	KUNIT_EXPECT_EQ(test, args.count, 0U);
	KUNIT_EXPECT_EQ(test, output[0], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_values_batch_args) {
		.buf_len = 0,
		.buf_ptr = 0,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-value-batch-null-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)(12 + sizeof(value_name) - 1 +
			      sizeof(value_data)));
	KUNIT_EXPECT_EQ(test, args.count, 0U);
	KUNIT_EXPECT_EQ(test, args.buf_ptr, 0ULL);

	memset(&ctx, 0, sizeof(ctx));
	memset(output, 0xaa, sizeof(output));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_values_batch_args) {
		.buf_len = 0,
		.buf_ptr = (u64)(unsigned long)output,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-value-batch-nonnull-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)(12 + sizeof(value_name) - 1 +
			      sizeof(value_data)));
	KUNIT_EXPECT_EQ(test, args.count, 0U);
	KUNIT_EXPECT_EQ(test, output[0], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_transaction_context(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x93 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 9 };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 32,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 output[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long txn_fd;
	long fd;
	long ret;
	int thread_ret;

	args.buf_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				ancestors[0]),
			0L);
	args.txn_fd = (int)txn_fd;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(output + sizeof(u32), value_name,
				     sizeof(value_name) - 1), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x94 },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 output[8] = { };
	struct file file = { };
	const void *token;
	long allowed_fd;
	long denied_fd;
	long txn_fd;

	args.buf_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args._pad = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_values_batch(
				(int)allowed_fd, &ops, &args),
			(long)-EINVAL);
	args._pad = 0;

	args.buf_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_values_batch(
				(int)allowed_fd, &ops, &args),
			(long)-EFAULT);
	args.buf_ptr = (u64)(unsigned long)output;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_values_batch(
				(int)denied_fd, &ops, &args),
			(long)-EACCES);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_values_batch(
				(int)allowed_fd, &ops, &args),
			(long)-EINVAL);
	args.txn_fd = -1;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				(u8[RSI_GUID_SIZE]){ 2 }),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_values_batch(
				(int)allowed_fd, &ops, &args),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	args.txn_fd = -1;

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_copyout_fault(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x95 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1, 2 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 32,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 output[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.buf_ptr = (u64)(unsigned long)output;
	ctx.fault_dst = output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, output[0], 0x00);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_values_batch_malformed_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x96 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_values_batch_args args = {
		.buf_len = 32,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
		.sequence = U64_MAX,
	};
	u8 output[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.buf_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x69 },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 4, 3, 2, 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 0,
		.name_len = 16,
		.data_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 name[16];
	u8 data[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(name, 0xaa, sizeof(name));
	memset(data, 0xaa, sizeof(data));
	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 2U);
	KUNIT_EXPECT_EQ(test, args.index, 0U);
	KUNIT_EXPECT_EQ(test, args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, args.name_len, (u32)sizeof(value_name) - 1);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args._pad, 0U);
	KUNIT_EXPECT_EQ(test, memcmp(name, value_name, sizeof(value_name) - 1), 0);
	KUNIT_EXPECT_EQ(test, name[sizeof(value_name) - 1], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(data, value_data, sizeof(value_data)), 0);
	KUNIT_EXPECT_EQ(test, data[sizeof(value_data)], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_erange_all_or_none(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x6a },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1, 2, 3, 4 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 0,
		.name_len = 2,
		.data_len = 2,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 name[2] = { 0xaa, 0xaa };
	u8 data[2] = { 0xaa, 0xaa };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, (u32)sizeof(value_name) - 1);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.type, 0U);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);
	KUNIT_EXPECT_EQ(test, data[0], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_enum_value_args) {
		.index = 0,
		.name_len = 0,
		.name_ptr = 0,
		.data_len = 0,
		.data_ptr = 0,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-enum-value-null-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, (u32)sizeof(value_name) - 1);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.type, 0U);
	KUNIT_EXPECT_EQ(test, args.name_ptr, 0ULL);
	KUNIT_EXPECT_EQ(test, args.data_ptr, 0ULL);

	memset(&ctx, 0, sizeof(ctx));
	memset(name, 0xaa, sizeof(name));
	memset(data, 0xaa, sizeof(data));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_enum_value_args) {
		.index = 0,
		.name_len = 0,
		.name_ptr = (u64)(unsigned long)name,
		.data_len = 0,
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread,
			   &script, "pkm-lcs-kunit-enum-value-nonnull-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, (u32)sizeof(value_name) - 1);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.type, 0U);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);
	KUNIT_EXPECT_EQ(test, data[0], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_index_past_end(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x6b },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 1,
		.name_len = 8,
		.data_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 name[8] = { };
	u8 data[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_transaction_context(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x6c },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 9 };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 0,
		.name_len = 8,
		.data_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 name[8] = { };
	u8 data[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long txn_fd;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				ancestors[0]),
			0L);
	args.txn_fd = (int)txn_fd;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 2U);
	KUNIT_EXPECT_EQ(test, memcmp(name, value_name, sizeof(value_name) - 1), 0);
	KUNIT_EXPECT_EQ(test, memcmp(data, value_data, sizeof(value_data)), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x6d },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 0,
		.name_len = 8,
		.data_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 name[8] = { };
	u8 data[8] = { };
	struct file file = { };
	const void *token;
	long allowed_fd;
	long denied_fd;
	long txn_fd;

	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args._pad = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_value((int)allowed_fd,
							&ops, &args),
			(long)-EINVAL);
	args._pad = 0;

	args.name_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_value((int)allowed_fd,
							&ops, &args),
			(long)-EFAULT);
	args.name_ptr = (u64)(unsigned long)name;

	args.data_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_value((int)allowed_fd,
							&ops, &args),
			(long)-EFAULT);
	args.data_ptr = (u64)(unsigned long)data;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_value((int)denied_fd,
							&ops, &args),
			(long)-EACCES);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_value((int)allowed_fd,
							&ops, &args),
			(long)-EINVAL);
	args.txn_fd = -1;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				(u8[RSI_GUID_SIZE]){ 2 }),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_value((int)allowed_fd,
							&ops, &args),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	args.txn_fd = -1;

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_copyout_fault(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x6e },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1, 2 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 0,
		.name_len = 8,
		.data_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	u8 name[8] = { };
	u8 data[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;
	ctx.fault_dst = name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_value_malformed_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x6f },
	};
	static const char value_name[] = "Answer";
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_value_args args = {
		.index = 0,
		.name_len = 8,
		.data_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = value_data,
		.data_len = sizeof(value_data),
		.value_type = REG_BINARY,
		.query_all = true,
		.sequence = U64_MAX,
	};
	u8 name[8] = { };
	u8 data[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	args.data_ptr = (u64)(unsigned long)data;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x70 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x71 };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x72 };
	static const u8 value_data[] = { 7 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_read_key_source_script child_read = {
		.expected_guid = child_guid,
		.name = "Child",
	};
	struct pkm_lcs_kunit_enum_children_source_script child_enum = {
		.expected_parent_guid = child_guid,
		.child_name = "Grandchild",
		.child_guid = grandchild_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &child_read,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &child_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = child_guid,
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(name, 0xaa, sizeof(name));
	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.index, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 5U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 2000ULL);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 1U);
	KUNIT_EXPECT_EQ(test, args.value_count, 1U);
	KUNIT_EXPECT_EQ(test, args._pad, 0U);
	KUNIT_EXPECT_EQ(test, memcmp(name, "Child", 5), 0);
	KUNIT_EXPECT_EQ(test, name[5], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_resolves_policy_layer(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xab, 0x01 },
	};
	static const u8 base_child_guid[PKM_LCS_GUID_BYTES] = {
		0xab, 0x02
	};
	static const u8 policy_child_guid[PKM_LCS_GUID_BYTES] = {
		0xab, 0x03
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xab, 0x04
	};
	static const u8 value_data[] = { 0x2a };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.layer_name = "base",
		.child_guid = base_child_guid,
		.include_second_entry = true,
		.second_child_name = "Child",
		.second_layer_name = "policy",
		.second_child_guid = policy_child_guid,
	};
	struct pkm_lcs_kunit_read_key_source_script child_read = {
		.expected_guid = policy_child_guid,
		.name = "Child",
	};
	struct pkm_lcs_kunit_enum_children_source_script child_enum = {
		.expected_parent_guid = policy_child_guid,
		.empty = true,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &child_read,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &child_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = policy_child_guid,
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 policy_sequence;
	u64 base_sequence;
	long fd;
	long ret;
	int thread_ret;

	memset(name, 0xaa, sizeof(name));
	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	parent_enum.sequence = base_sequence;
	parent_enum.second_sequence = policy_sequence;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_symlink_sequence_source_thread, &script,
		"pkm-lcs-kunit-enum-subkey-policy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.index, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 5U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 2000ULL);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 0U);
	KUNIT_EXPECT_EQ(test, args.value_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(name, "Child", 5), 0);
	KUNIT_EXPECT_EQ(test, name[5], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_policy_hidden_masks_base(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xac, 0x01 },
	};
	static const u8 base_child_guid[PKM_LCS_GUID_BYTES] = {
		0xac, 0x02
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xac, 0x04
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.layer_name = "base",
		.child_guid = base_child_guid,
		.include_second_entry = true,
		.second_child_name = "Child",
		.second_layer_name = "policy",
		.second_hidden = true,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 policy_sequence;
	u64 base_sequence;
	long fd;
	long ret;
	int thread_ret;

	memset(name, 0xaa, sizeof(name));
	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	parent_enum.sequence = base_sequence;
	parent_enum.second_sequence = policy_sequence;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_symlink_sequence_source_thread, &script,
		"pkm-lcs-kunit-enum-hidden-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 16U);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_erange_all_or_none(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x73 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x74 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 2,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[2] = { 0xaa, 0xaa };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 5U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 0U);
	KUNIT_EXPECT_EQ(test, args.value_count, 0U);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_enum_subkey_args) {
		.index = 0,
		.name_len = 0,
		.name_ptr = 0,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-null-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 5U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 0U);
	KUNIT_EXPECT_EQ(test, args.value_count, 0U);
	KUNIT_EXPECT_EQ(test, args.name_ptr, 0ULL);

	memset(&ctx, 0, sizeof(ctx));
	memset(name, 0xaa, sizeof(name));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_enum_subkey_args) {
		.index = 0,
		.name_len = 0,
		.name_ptr = (u64)(unsigned long)name,
		.txn_fd = -1,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-nonnull-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 5U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 0U);
	KUNIT_EXPECT_EQ(test, args.value_count, 0U);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_index_past_end(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x75 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x76 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 1,
		.name_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[8] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_transaction_context(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x77 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x78 };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x79 };
	static const u8 value_data[] = { 8 };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_read_key_source_script child_read = {
		.expected_guid = child_guid,
		.name = "Child",
	};
	struct pkm_lcs_kunit_enum_children_source_script child_enum = {
		.expected_parent_guid = child_guid,
		.child_name = "Grandchild",
		.child_guid = grandchild_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &child_read,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &child_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = child_guid,
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long txn_fd;
	long fd;
	long ret;
	int thread_ret;
	u32 i;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				ancestors[0]),
			0L);
	args.txn_fd = (int)txn_fd;
	for (i = 0; i < ARRAY_SIZE(ops_seq); i++)
		ops_seq[i].expected_txn_id = txn_snapshot.transaction_id;
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(name, "Child", 5), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7a },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 8,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 name[8] = { };
	struct file file = { };
	const void *token;
	long allowed_fd;
	long denied_fd;
	long txn_fd;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args._pad = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_subkey((int)allowed_fd,
							 &ops, &args),
			(long)-EINVAL);
	args._pad = 0;

	args.name_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_subkey((int)allowed_fd,
							 &ops, &args),
			(long)-EFAULT);
	args.name_ptr = (u64)(unsigned long)name;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_subkey((int)denied_fd,
							 &ops, &args),
			(long)-EACCES);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_subkey((int)allowed_fd,
							 &ops, &args),
			(long)-EINVAL);
	args.txn_fd = -1;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				(u8[RSI_GUID_SIZE]){ 2 }),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_enum_subkey((int)allowed_fd,
							 &ops, &args),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	args.txn_fd = -1;

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_read_ioctls_terminal_txns_fail_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7b },
	};
	static const char value_name[] = "Answer";
	static const struct {
		u32 state;
		u32 bound_source_id;
		long expected_errno;
	} cases[] = {
		{ REG_TXN_COMMITTED, 0, -EINVAL },
		{ REG_TXN_ABORTED, 0, -EINVAL },
		{ REG_TXN_TIMED_OUT, 0, -ETIMEDOUT },
		{ REG_TXN_SOURCE_DOWN, 1, -EIO },
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args query_value = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 8,
		.layer_buf_len = 8,
		.txn_fd = -1,
	};
	struct reg_query_values_batch_args query_batch = {
		.buf_len = 32,
		.txn_fd = -1,
	};
	struct reg_enum_value_args enum_value = {
		.index = 0,
		.name_len = 8,
		.data_len = 8,
		.txn_fd = -1,
	};
	struct reg_enum_subkey_args enum_subkey = {
		.index = 0,
		.name_len = 8,
		.txn_fd = -1,
	};
	u8 data[8] = { };
	u8 layer[8] = { };
	u8 batch[32] = { };
	u8 name[8] = { };
	struct file file = { };
	const void *token;
	long txn_fd;
	long fd;
	u32 i;

	query_value.data_ptr = (u64)(unsigned long)data;
	query_value.layer_ptr = (u64)(unsigned long)layer;
	query_batch.buf_ptr = (u64)(unsigned long)batch;
	enum_value.name_ptr = (u64)(unsigned long)name;
	enum_value.data_ptr = (u64)(unsigned long)data;
	enum_subkey.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, path,
		ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_transaction_fd_set_state(
					(int)txn_fd, cases[i].state,
					cases[i].bound_source_id),
				0L);

		query_value.txn_fd = (int)txn_fd;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_query_value((int)fd,
								 &ops,
								 &query_value),
				cases[i].expected_errno);

		query_batch.txn_fd = (int)txn_fd;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_query_values_batch(
					(int)fd, &ops, &query_batch),
				cases[i].expected_errno);

		enum_value.txn_fd = (int)txn_fd;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_enum_value((int)fd,
								&ops,
								&enum_value),
				cases[i].expected_errno);

		enum_subkey.txn_fd = (int)txn_fd;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_enum_subkey((int)fd,
								 &ops,
								 &enum_subkey),
				cases[i].expected_errno);
	}

	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_copyout_fault(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7b },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x7c };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x7d };
	static const u8 value_data[] = { 9 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_read_key_source_script child_read = {
		.expected_guid = child_guid,
		.name = "Child",
	};
	struct pkm_lcs_kunit_enum_children_source_script child_enum = {
		.expected_parent_guid = child_guid,
		.child_name = "Grandchild",
		.child_guid = grandchild_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &child_read,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &child_enum,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = child_guid,
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	ctx.fault_dst = name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_enum_subkey_malformed_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7e },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x7f };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_enum_subkey_args args = {
		.index = 0,
		.name_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_enum_children_source_script parent_enum = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Future",
		.child_guid = child_guid,
		.sequence = U64_MAX,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &parent_enum,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_ENUMERATE_SUB_KEYS, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x5a },
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x5b };
	static const u8 value_data[] = { 1, 2, 3, 4 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 32,
	};
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = ancestors[1],
		.name = "SourceName",
		.sd = existing_owner_system_sd,
		.sd_len = sizeof(existing_owner_system_sd),
		.volatile_key = true,
		.symlink = true,
	};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
		.sequence = 0,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &read_key,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &enum_children,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = ancestors[1],
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[32];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(name, 0xaa, sizeof(name));
	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_set(
				1, ancestors[0], 77),
			0L);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.name_len, 8U);
	KUNIT_EXPECT_EQ(test, memcmp(name, "Software", 8), 0);
	KUNIT_EXPECT_EQ(test, name[8], 0xaaU);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 2000ULL);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 1U);
	KUNIT_EXPECT_EQ(test, args.value_count, 1U);
	KUNIT_EXPECT_EQ(test, args.max_subkey_name_len, 5U);
	KUNIT_EXPECT_EQ(test, args.max_value_name_len, 0U);
	KUNIT_EXPECT_EQ(test, args.max_value_data_size,
			(u32)sizeof(value_data));
	KUNIT_EXPECT_EQ(test, args.sd_size,
			(u32)sizeof(existing_owner_system_sd));
	KUNIT_EXPECT_EQ(test, args.volatile_key, 1U);
	KUNIT_EXPECT_EQ(test, args.symlink, 1U);
	KUNIT_EXPECT_EQ(test, args.hive_generation, 77ULL);
	KUNIT_EXPECT_EQ(test, memcmp(args._pad1, (u8[6]){},
				     sizeof(args._pad1)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_resolves_policy_layers(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xad, 0x01 },
	};
	static const u8 base_child_guid[PKM_LCS_GUID_BYTES] = {
		0xad, 0x02
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xad, 0x03
	};
	static const u8 base_value_data[] = { 1, 2, 3, 4, 5, 6 };
	static const u8 policy_value_data[] = { 9, 10 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 32,
	};
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = ancestors[1],
		.name = "SourceName",
	};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.layer_name = "base",
		.child_guid = base_child_guid,
		.include_second_entry = true,
		.second_child_name = "Child",
		.second_layer_name = "policy",
		.second_hidden = true,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &read_key,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &enum_children,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = ancestors[1],
			.query_layer_name = "base",
			.query_data = base_value_data,
			.query_data_len = sizeof(base_value_data),
			.query_value_type = REG_BINARY,
			.include_second_query_value = true,
			.second_query_layer_name = "policy",
			.second_query_data = policy_value_data,
			.second_query_data_len = sizeof(policy_value_data),
			.second_query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[32];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 policy_sequence;
	u64 base_sequence;
	long fd;
	long ret;
	int thread_ret;

	memset(name, 0xaa, sizeof(name));
	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	enum_children.sequence = base_sequence;
	enum_children.second_sequence = policy_sequence;
	ops_seq[2].query_sequence = base_sequence;
	ops_seq[2].second_query_sequence = policy_sequence;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_symlink_sequence_source_thread, &script,
		"pkm-lcs-kunit-query-info-policy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.name_len, 8U);
	KUNIT_EXPECT_EQ(test, memcmp(name, "Software", 8), 0);
	KUNIT_EXPECT_EQ(test, args.subkey_count, 0U);
	KUNIT_EXPECT_EQ(test, args.value_count, 1U);
	KUNIT_EXPECT_EQ(test, args.max_subkey_name_len, 0U);
	KUNIT_EXPECT_EQ(test, args.max_value_name_len, 0U);
	KUNIT_EXPECT_EQ(test, args.max_value_data_size,
			(u32)sizeof(policy_value_data));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_retains_runtime_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x63 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	static const u8 value_data[] = { 1 };
	char child_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 32,
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = ancestors[1],
		.name = "SourceName",
	};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = ancestors[1],
		.child_name = child_name,
		.child_guid = child_guid,
		.sequence = 0,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &read_key,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &enum_children,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = ancestors[1],
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
		.reset_limits_after_write = true,
		.reset_limits_after_write_index = 0,
	};
	u8 name[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	memset(child_name, 'C', LONG_NAME_LEN);
	child_name[LONG_NAME_LEN] = '\0';
	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.max_subkey_name_len, (u32)LONG_NAME_LEN);
	KUNIT_EXPECT_EQ(test, args.value_count, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_erange_probe(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x5c },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x5d };
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 0,
	};
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = ancestors[1],
		.name = "SourceName",
	};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
		.sequence = 0,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &read_key,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &enum_children,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = ancestors[1],
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 8U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);

	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_query_key_info_args) {
		.name_len = 0,
		.name_ptr = 0,
	};
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-null-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 8U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, args.name_ptr, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x5e },
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 8,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 name[8] = { };
	struct file file = { };
	const void *token;
	long allowed_fd;
	long denied_fd;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_key_info((int)allowed_fd,
							    &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;

	args._pad1[3] = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_key_info((int)allowed_fd,
							    &ops, &args),
			(long)-EINVAL);
	args._pad1[3] = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_key_info((int)denied_fd,
							    &ops, &args),
			(long)-EACCES);

	args.name_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_key_info((int)allowed_fd,
							    &ops, &args),
			(long)-EFAULT);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_copyout_fault(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x5f },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x60 };
	static const u8 value_data[] = { 1 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 32,
	};
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = ancestors[1],
		.name = "SourceName",
	};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Child",
		.child_guid = child_guid,
		.sequence = 0,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &read_key,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &enum_children,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
			.query_guid = ancestors[1],
			.query_data = value_data,
			.query_data_len = sizeof(value_data),
			.query_value_type = REG_BINARY,
			.query_all = true,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;
	ctx.fault_dst = name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.name_len, 8U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_query_key_info_malformed_enum(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x61 },
	};
	static const u8 future_guid[PKM_LCS_GUID_BYTES] = { 0x62 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_key_info_args args = {
		.name_len = 32,
	};
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = ancestors[1],
		.name = "SourceName",
	};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = ancestors[1],
		.child_name = "Future",
		.child_guid = future_guid,
		.sequence = U64_MAX,
	};
	struct pkm_lcs_kunit_symlink_sequence_op ops_seq[] = {
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
			.read_key = &read_key,
		},
		{
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN,
			.enum_children = &enum_children,
		},
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = ops_seq,
		.op_count = ARRAY_SIZE(ops_seq),
	};
	u8 name[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	args.name_ptr = (u64)(unsigned long)name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_set_security_merge_bridge_preserves_components(
	struct kunit *test)
{
	static const u8 existing_sd[] = {
		/* SECURITY_DESCRIPTOR_RELATIVE */
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		/* Owner: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* Group: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* DACL: one CONTAINER_INHERIT allow ACE for Everyone. */
		0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 input_owner_everyone_sd[] = {
		/* SECURITY_DESCRIPTOR_RELATIVE with owner S-1-1-0. */
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 expected[] = {
		/* Header: owner, preserved group, no SACL, preserved DACL. */
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		/* Owner: S-1-1-0. */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		/* Group: preserved S-1-5-18. */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* DACL: preserved from the existing SD. */
		0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_set_security_merge_result result = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_plan_set_security_merge(
				existing_sd, sizeof(existing_sd),
				input_owner_everyone_sd,
				sizeof(input_owner_everyone_sd),
				OWNER_SECURITY_INFORMATION, &result),
			0L);
	KUNIT_ASSERT_EQ(test, result.merged_sd_len, sizeof(expected));
	KUNIT_EXPECT_EQ(test,
			memcmp(result.merged_sd, expected, sizeof(expected)),
			0);

	pkm_lcs_set_security_merge_result_destroy(&result);
	KUNIT_EXPECT_PTR_EQ(test, result.merged_sd, NULL);
	KUNIT_EXPECT_EQ(test, result.merged_sd_len, (size_t)0);
}


static void pkm_lcs_kunit_set_security_merge_bridge_fails_closed(
	struct kunit *test)
{
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	static const u8 existing_sd[] = {
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 input_owner_everyone_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_set_security_merge_result result = {
		.merged_sd = (u8 *)1UL,
		.merged_sd_len = 7,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_plan_set_security_merge(
				bad_sd, sizeof(bad_sd),
				input_owner_everyone_sd,
				sizeof(input_owner_everyone_sd),
				OWNER_SECURITY_INFORMATION, &result),
			(long)-EIO);
	KUNIT_EXPECT_PTR_EQ(test, result.merged_sd, NULL);
	KUNIT_EXPECT_EQ(test, result.merged_sd_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_plan_set_security_merge(
				existing_sd, sizeof(existing_sd),
				bad_sd, sizeof(bad_sd),
				OWNER_SECURITY_INFORMATION, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.merged_sd, NULL);
	KUNIT_EXPECT_EQ(test, result.merged_sd_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_plan_set_security_merge(
				existing_sd, sizeof(existing_sd),
				input_owner_everyone_sd,
				sizeof(input_owner_everyone_sd), 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.merged_sd, NULL);
	KUNIT_EXPECT_EQ(test, result.merged_sd_len, (size_t)0);
}


static void pkm_lcs_kunit_key_fd_set_security_nontransactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x52 },
	};
	static const u8 input_owner_everyone_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = sizeof(input_owner_everyone_sd),
		.sd_ptr = (u64)(unsigned long)input_owner_everyone_sd,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_kunit_set_security_source_script script = {
		.expected_guid = ancestors[1],
		.existing_sd = existing_owner_system_sd,
		.existing_sd_len = sizeof(existing_owner_system_sd),
		.expected_merged_sd = input_owner_everyone_sd,
		.expected_merged_sd_len = sizeof(input_owner_everyone_sd),
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct file file = { };
	const void *token;
	struct task_struct *task;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, WRITE_OWNER, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_security_source_thread, &script,
			   "pkm-lcs-kunit-set-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)mutation_fd, &ops,
						&args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, (u32)WRITE_OWNER);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_cached_grant_survives_sd_change(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x59 },
	};
	static const u8 existing_readable_sd[] = {
		/* SECURITY_DESCRIPTOR_RELATIVE */
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		/* Owner: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* Group: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* DACL: one CONTAINER_INHERIT allow ACE for Everyone. */
		0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 input_empty_dacl_sd[] = {
		/* SECURITY_DESCRIPTOR_RELATIVE with an empty DACL only. */
		0x01, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const u8 expected_merged_sd[] = {
		/* Existing owner/group with the replacement empty DACL. */
		0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00,
		/* Owner: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* Group: S-1-5-18 */
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
		/* DACL: empty ACL. */
		0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args set_args = {
		.security_info = DACL_SECURITY_INFORMATION,
		.sd_len = sizeof(input_empty_dacl_sd),
		.sd_ptr = (u64)(unsigned long)input_empty_dacl_sd,
		.txn_fd = -1,
	};
	struct reg_get_security_args get_args = {
		.security_info = DACL_SECURITY_INFORMATION,
		.sd_len = 64,
	};
	struct pkm_lcs_kunit_set_security_source_script set_script = {
		.expected_guid = ancestors[1],
		.existing_sd = existing_readable_sd,
		.existing_sd_len = sizeof(existing_readable_sd),
		.expected_merged_sd = expected_merged_sd,
		.expected_merged_sd_len = sizeof(expected_merged_sd),
	};
	struct pkm_lcs_kunit_read_key_source_script get_script = {
		.expected_guid = ancestors[1],
		.name = "Software",
		.sd = expected_merged_sd,
		.sd_len = sizeof(expected_merged_sd),
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 output[64];
	long read_fd;
	long write_fd;
	long ret;
	int thread_ret;

	memset(output, 0xaa, sizeof(output));
	get_args.sd_ptr = (u64)(unsigned long)output;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	set_script.file = &file;
	get_script.file = &file;

	read_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, read_fd >= 0);
	write_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, WRITE_DAC, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, write_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_security_source_thread, &set_script,
		"pkm-lcs-kunit-retain-grant-set-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)write_fd, &ops,
						&set_args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, set_script.result, 0);
	KUNIT_EXPECT_EQ(test, set_script.reads, 2U);
	KUNIT_EXPECT_EQ(test, set_script.writes, 2U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)read_fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, (u32)READ_CONTROL);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &get_script,
		"pkm-lcs-kunit-retain-grant-get-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)read_fd, &ops,
						&get_args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, get_script.result, 0);
	KUNIT_EXPECT_EQ(test, get_script.reads, 1U);
	KUNIT_EXPECT_EQ(test, get_script.writes, 1U);
	KUNIT_EXPECT_EQ(test, get_args.sd_len,
			(u32)sizeof(input_empty_dacl_sd));
	KUNIT_EXPECT_EQ(test,
			memcmp(output, input_empty_dacl_sd,
			       sizeof(input_empty_dacl_sd)),
			0);
	KUNIT_EXPECT_EQ(test, output[sizeof(input_empty_dacl_sd)], 0xaa);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)write_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)read_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_set_security_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x54 },
	};
	static const u8 input_owner_everyone_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = sizeof(input_owner_everyone_sd),
		.sd_ptr = (u64)(unsigned long)input_owner_everyone_sd,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_kunit_set_security_source_script script = {
		.expected_guid = ancestors[1],
		.existing_sd = existing_owner_system_sd,
		.existing_sd_len = sizeof(existing_owner_system_sd),
		.expected_merged_sd = input_owner_everyone_sd,
		.expected_merged_sd_len = sizeof(input_owner_everyone_sd),
		.expect_begin = true,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, WRITE_OWNER, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_security_source_thread, &script,
			   "pkm-lcs-kunit-set-sd-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)mutation_fd, &ops,
						&args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-set-sd-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_set_security_transactional_abort_no_effects(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x55 },
	};
	static const u8 input_owner_everyone_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	static const u8 existing_owner_system_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = sizeof(input_owner_everyone_sd),
		.sd_ptr = (u64)(unsigned long)input_owner_everyone_sd,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_kunit_set_security_source_script script = {
		.expected_guid = ancestors[1],
		.existing_sd = existing_owner_system_sd,
		.existing_sd_len = sizeof(existing_owner_system_sd),
		.expected_merged_sd = input_owner_everyone_sd,
		.expected_merged_sd_len = sizeof(input_owner_everyone_sd),
		.expect_begin = true,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 event[16] = { };
	u8 request[64] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	ssize_t read_len;
	u32 count = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, WRITE_OWNER, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_security_source_thread, &script,
		"pkm-lcs-kunit-set-sd-abort");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)mutation_fd, &ops,
						&args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	flush_delayed_fput();

	read_len = pkm_lcs_kunit_source_device_read_file(&file, request,
							 sizeof(request), true);
	KUNIT_ASSERT_EQ(test, read_len,
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)read_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(request + payload_offset),
			txn_snapshot.transaction_id);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_set_security_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x53 },
	};
	static const u8 input_owner_everyone_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args args = {
		.security_info = OWNER_SECURITY_INFORMATION,
		.sd_len = sizeof(input_owner_everyone_sd),
		.sd_ptr = (u64)(unsigned long)input_owner_everyone_sd,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	long allowed_fd;
	long denied_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, WRITE_OWNER, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, READ_CONTROL, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	args._pad = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security((int)allowed_fd,
							  &ops, &args),
			(long)-EINVAL);
	args._pad = 0;

	args.security_info = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security((int)allowed_fd,
							  &ops, &args),
			(long)-EINVAL);
	args.security_info = OWNER_SECURITY_INFORMATION;

	args.txn_fd = INT_MAX;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security((int)allowed_fd,
							  &ops, &args),
			(long)-EBADF);
	args.txn_fd = -1;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security((int)denied_fd,
							  &ops, &args),
			(long)-EACCES);

	ctx.fault_src = input_owner_everyone_sd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security((int)allowed_fd,
							  &ops, &args),
			(long)-EFAULT);
	ctx.fault_src = NULL;

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_set_value_nontransactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x73 },
	};
	static const char value_name[] = "Answer";
	static const char value_name_input[] = {
		'A', 'n', 's', 'w', 'e', 'r', '!'
	};
	static const u8 data[] = { 0x2a, 0x00, 0x00, 0x00 };
	static const u8 default_data[] = { 0x51 };
	static const char separator_value_name[] = "A/B\\C";
	static const u8 separator_data[] = { 0x61, 0x62 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name_input,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
		.expected_seq = 0x123456789abcdef0ULL,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.expected_data = data,
		.expected_data_len = sizeof(data),
		.expected_value_type = REG_BINARY,
		.expected_expected_sequence = 0x123456789abcdef0ULL,
		.set_value_status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-ioctl");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	memset(&ctx, 0, sizeof(ctx));
	memset(event, 0, sizeof(event));
	script.expected_value_name = "";
	script.expected_data = default_data;
	script.expected_data_len = sizeof(default_data);
	script.expected_expected_sequence = 0;
	script.observed_last_write_time = 0;
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_set_value_args) {
		.name_len = 0,
		.name_ptr = 0,
		.type = REG_BINARY,
		.data_len = sizeof(default_data),
		.data_ptr = (u64)(unsigned long)default_data,
		.txn_fd = -1,
		.expected_seq = 0,
	};
	generation_before = generation_after;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-set-default-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	memset(&ctx, 0, sizeof(ctx));
	memset(event, 0, sizeof(event));
	script.expected_value_name = separator_value_name;
	script.expected_data = separator_data;
	script.expected_data_len = sizeof(separator_data);
	script.expected_expected_sequence = 0;
	script.observed_last_write_time = 0;
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_set_value_args) {
		.name_len = strlen(separator_value_name),
		.name_ptr = (u64)(unsigned long)separator_value_name,
		.type = REG_BINARY,
		.data_len = sizeof(separator_data),
		.data_ptr = (u64)(unsigned long)separator_data,
		.txn_fd = -1,
		.expected_seq = 0,
	};
	generation_before = generation_after;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-set-separator-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(separator_value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(separator_value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(separator_value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, separator_value_name,
				     strlen(separator_value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x78 },
	};
	static const char value_name[] = "Answer";
	static const u8 data[] = { 0x2a, 0x00, 0x00, 0x00 };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
		.expected_seq = 0x1020304050607080ULL,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.expected_data = data,
		.expected_data_len = sizeof(data),
		.expected_value_type = REG_BINARY,
		.expected_expected_sequence = 0x1020304050607080ULL,
		.set_value_status = RSI_OK,
		.expect_begin = true,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE);
	KUNIT_EXPECT_EQ(test, log.last_sequence, sequence_before);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, value_name);
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-set-value-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_cas_failure_no_effects(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x74 },
	};
	static const char value_name[] = "Answer";
	static const u8 data[] = { 0x11, 0x22 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
		.expected_seq = 55,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.expected_data = data,
		.expected_data_len = sizeof(data),
		.expected_value_type = REG_BINARY,
		.expected_expected_sequence = 55,
		.set_value_status = RSI_CAS_FAILED,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-cas");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EAGAIN);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x75 },
	};
	static const char value_name[] = "Answer";
	static const char bad_value_name[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_value_name[] = { 'b', 0xff, 'd' };
	static const char bad_layer[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_layer[] = { 'b', 0xff, 'd' };
	static const char overlay_name[] = "overlay";
	static const char overlay_input[] = {
		'o', 'v', 'e', 'r', 'l', 'a', 'y', '!'
	};
	static const u8 data[] = { 0x01 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long allowed_fd;
	long denied_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)denied_fd, admin_token, &ops, &args),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad1 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad1 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad2 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad2 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.txn_fd = -1;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.reads = 0;
	args.type = 0xffffffffU;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.type = REG_BINARY;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.type = REG_TOMBSTONE;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.type = REG_BINARY;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.data_len = 1024U * 1024U + 1U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOSPC);
	args.data_len = sizeof(data);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.name_len = sizeof(bad_value_name);
	args.name_ptr = (u64)(unsigned long)bad_value_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.name_len = strlen(value_name);
	args.name_ptr = (u64)(unsigned long)value_name;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.name_len = sizeof(invalid_utf8_value_name);
	args.name_ptr = (u64)(unsigned long)invalid_utf8_value_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.name_len = strlen(value_name);
	args.name_ptr = (u64)(unsigned long)value_name;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = sizeof(bad_layer);
	args.layer_ptr = (u64)(unsigned long)bad_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	ctx.reads = 0;
	args.layer_len = sizeof(invalid_utf8_layer);
	args.layer_ptr = (u64)(unsigned long)invalid_utf8_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	ctx.reads = 0;
	args.layer_len = strlen(overlay_name);
	args.layer_ptr = (u64)(unsigned long)overlay_input;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_runtime_limits_fail_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7e },
	};
	static const char value_name[] = "Answer";
	static const char overlong_name[] =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	static const char overlong_layer[] =
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	static const u8 data[] = { 0x01 };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 64U;
	limits.max_value_size = 4096U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	args.name_len = sizeof(overlong_name) - 1;
	args.name_ptr = (u64)(unsigned long)overlong_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)fd, admin_token, &ops, &args),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.name_len = strlen(value_name);
	args.name_ptr = (u64)(unsigned long)value_name;
	args.data_len = 4097U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)fd, admin_token, &ops, &args),
			(long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.data_len = sizeof(data);
	args.layer_len = sizeof(overlong_layer) - 1;
	args.layer_ptr = (u64)(unsigned long)overlong_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)fd, admin_token, &ops, &args),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_runtime_limits_source_frames(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7f },
	};
	static const u8 data[] = { 0x42 };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	char value_name[301];
	long fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 300U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	memset(value_name, 'v', sizeof(value_name) - 1);
	value_name[sizeof(value_name) - 1] = '\0';
	args.name_len = sizeof(value_name) - 1;
	args.name_ptr = (u64)(unsigned long)value_name;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	pkm_lcs_kunit_expect_set_value_success(
		test, &file, (int)fd, admin_token, &ops, &args,
		ancestors[1], value_name, data, sizeof(data), REG_BINARY);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_precedence_tcb_gate(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xe1, 0x10 },
		{ 0xe1, 0x11 },
		{ 0xe1, 0x12 },
		{ 0xe1 },
	};
	static const char * const ordinary_path[] = { "Machine", "Software" };
	static const u8 ordinary_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xe2 },
	};
	static const char precedence_name[] = "pReCeDeNcE";
	static const u8 one_data[] = { 1, 0, 0, 0 };
	static const u8 zero_data[] = { 0, 0, 0, 0 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(precedence_name),
		.name_ptr = (u64)(unsigned long)precedence_name,
		.type = REG_DWORD,
		.data_len = sizeof(one_data),
		.data_ptr = (u64)(unsigned long)one_data,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	const void *tcb_token;
	const u8 *layer_sd;
	char names[64] = { };
	u32 count = 0;
	size_t layer_sd_len = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long metadata_fd;
	long ordinary_fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	tcb_token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, tcb_token);
	layer_sd = kacs_rust_kunit_create_file_sd(admin_token, KEY_SET_VALUE,
						  0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	metadata_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, metadata_fd >= 0);
	ordinary_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, ordinary_path, ordinary_ancestors,
		ARRAY_SIZE(ordinary_ancestors));
	KUNIT_ASSERT_TRUE(test, ordinary_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 0, 1,
				metadata_ancestors[ARRAY_SIZE(metadata_ancestors) - 1],
				layer_sd, layer_sd_len,
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_value_for_token(
				(int)metadata_fd, admin_token, &ops, &args),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	args.data_ptr = (u64)(unsigned long)zero_data;
	pkm_lcs_kunit_expect_set_value_layer_refresh_success(
		test, &file, (int)metadata_fd, admin_token, &ops, &args,
		metadata_ancestors[ARRAY_SIZE(metadata_ancestors) - 1],
		precedence_name, zero_data, sizeof(zero_data), REG_DWORD,
		"Policy", layer_sd, layer_sd_len, 0, 1);

	args.data_ptr = (u64)(unsigned long)one_data;
	pkm_lcs_kunit_expect_set_value_success(
		test, &file, (int)ordinary_fd, admin_token, &ops, &args,
		ordinary_ancestors[ARRAY_SIZE(ordinary_ancestors) - 1],
		precedence_name, one_data, sizeof(one_data), REG_DWORD);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(tcb_token,
							       &before));
	pkm_lcs_kunit_expect_set_value_layer_refresh_success(
		test, &file, (int)metadata_fd, tcb_token, &ops, &args,
		metadata_ancestors[ARRAY_SIZE(metadata_ancestors) - 1],
		precedence_name, one_data, sizeof(one_data), REG_DWORD,
		"Policy", layer_sd, layer_sd_len, 1, 1);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(tcb_token,
							       &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			before.privileges_used & KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 1U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)metadata_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)ordinary_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_kacs_free((void *)layer_sd);
	kacs_rust_token_drop(tcb_token);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_layer_precedence_overflows_watches(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xe3, 0x10 },
		{ 0xe3, 0x11 },
		{ 0xe3, 0x12 },
		{ 0xe3 },
	};
	static const char * const watch_path[] = { "Machine", "Software" };
	static const u8 watch_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xe4 },
	};
	static const char precedence_name[] = "Precedence";
	static const u8 one_data[] = { 1, 0, 0, 0 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(precedence_name),
		.name_ptr = (u64)(unsigned long)precedence_name,
		.type = REG_DWORD,
		.data_len = sizeof(one_data),
		.data_ptr = (u64)(unsigned long)one_data,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	const void *tcb_token;
	const u8 *layer_sd;
	u8 event[16] = { };
	size_t layer_sd_len = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long metadata_fd;
	long watch_fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	tcb_token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, tcb_token);
	layer_sd = kacs_rust_kunit_create_file_sd(admin_token, KEY_SET_VALUE,
						  0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	metadata_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, metadata_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, watch_path, watch_ancestors,
		ARRAY_SIZE(watch_ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 0, 1,
				metadata_ancestors[ARRAY_SIZE(metadata_ancestors) - 1],
				layer_sd, layer_sd_len,
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_ancestors[0], &generation_before),
			0L);

	pkm_lcs_kunit_expect_set_value_layer_refresh_success(
		test, &file, (int)metadata_fd, tcb_token, &ops, &args,
		metadata_ancestors[ARRAY_SIZE(metadata_ancestors) - 1],
		precedence_name, one_data, sizeof(one_data), REG_DWORD,
		"Policy", layer_sd, layer_sd_len, 1, 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)metadata_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_kacs_free((void *)layer_sd);
	kacs_rust_token_drop(tcb_token);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_value_nontransactional_deletes_effective(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x79 },
	};
	static const char value_name[] = "Answer";
	static const char value_name_input[] = {
		'A', 'n', 's', 'w', 'e', 'r', '!'
	};
	static const u8 before_data[] = { 0x2a };
	static const u8 default_before_data[] = { 0x5d };
	static const char separator_value_name[] = "A/B\\C";
	static const u8 separator_before_data[] = { 0x6d };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name_input,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_delete_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_found = true,
		.before_data = before_data,
		.before_data_len = sizeof(before_data),
		.before_layer_name = "base",
		.before_value_type = REG_BINARY,
		.after_found = false,
		.delete_status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 next_sequence = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&next_sequence),
			0L);
	KUNIT_ASSERT_GT(test, next_sequence, 0ULL);
	script.before_sequence = next_sequence - 1;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-delete-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	memset(&ctx, 0, sizeof(ctx));
	memset(event, 0, sizeof(event));
	script.expected_value_name = "";
	script.before_data = default_before_data;
	script.before_data_len = sizeof(default_before_data);
	script.observed_last_write_time = 0;
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_delete_value_args) {
		.name_len = 0,
		.name_ptr = 0,
		.txn_fd = -1,
	};
	generation_before = generation_after;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&next_sequence),
			0L);
	KUNIT_ASSERT_GT(test, next_sequence, 0ULL);
	script.before_sequence = next_sequence - 1;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-default-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	memset(&ctx, 0, sizeof(ctx));
	memset(event, 0, sizeof(event));
	script.expected_value_name = separator_value_name;
	script.before_data = separator_before_data;
	script.before_data_len = sizeof(separator_before_data);
	script.observed_last_write_time = 0;
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	args = (struct reg_delete_value_args) {
		.name_len = strlen(separator_value_name),
		.name_ptr = (u64)(unsigned long)separator_value_name,
		.txn_fd = -1,
	};
	generation_before = generation_after;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&next_sequence),
			0L);
	KUNIT_ASSERT_GT(test, next_sequence, 0ULL);
	script.before_sequence = next_sequence - 1;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-separator-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(separator_value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(separator_value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(separator_value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, separator_value_name,
				     strlen(separator_value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_value_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7c },
	};
	static const char value_name[] = "Answer";
	static const u8 before_data[] = { 0x2a };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_delete_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_found = true,
		.before_data = before_data,
		.before_data_len = sizeof(before_data),
		.before_layer_name = "base",
		.before_value_type = REG_BINARY,
		.after_found = false,
		.delete_status = RSI_OK,
		.expect_begin = true,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 next_sequence = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_before_query_txn_id = txn_snapshot.transaction_id;
	script.expected_after_query_txn_id = txn_snapshot.transaction_id;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&next_sequence),
			0L);
	KUNIT_ASSERT_GT(test, next_sequence, 0ULL);
	script.before_sequence = next_sequence - 1;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-delete-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, value_name);
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-delete-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_delete_value_transactional_idempotent_no_event(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7d },
	};
	static const char value_name[] = "Missing";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_delete_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_found = false,
		.after_found = false,
		.delete_status = RSI_OK,
		.expect_begin = true,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_before_query_txn_id = txn_snapshot.transaction_id;
	script.expected_after_query_txn_id = txn_snapshot.transaction_id;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-delete-txn-idem");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, value_name);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-delete-idem-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_value_idempotent_no_value_event(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7a },
	};
	static const char value_name[] = "Missing";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_delete_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_found = false,
		.after_found = false,
		.delete_status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-delete-idem");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_value_runtime_limits_source_frames(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7d },
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_layer_name = "base",
		.before_found = false,
		.after_found = false,
		.delete_status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	char value_name[301];
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 300U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	memset(value_name, 'd', sizeof(value_name) - 1);
	value_name[sizeof(value_name) - 1] = '\0';
	args.name_len = sizeof(value_name) - 1;
	args.name_ptr = (u64)(unsigned long)value_name;
	script.expected_value_name = value_name;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_value_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7b },
	};
	static const char value_name[] = "Answer";
	static const char bad_value_name[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_value_name[] = { 'b', 0xff, 'd' };
	static const char bad_layer[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_layer[] = { 'b', 0xff, 'd' };
	static const char overlay_name[] = "overlay";
	static const char overlay_input[] = {
		'o', 'v', 'e', 'r', 'l', 'a', 'y', '!'
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	long allowed_fd;
	long denied_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)denied_fd, admin_token, &ops, &args),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad1 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad1 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad2 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad2 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.txn_fd = -1;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.reads = 0;
	args.name_len = sizeof(bad_value_name);
	args.name_ptr = (u64)(unsigned long)bad_value_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.name_len = strlen(value_name);
	args.name_ptr = (u64)(unsigned long)value_name;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.name_len = sizeof(invalid_utf8_value_name);
	args.name_ptr = (u64)(unsigned long)invalid_utf8_value_name;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.name_len = strlen(value_name);
	args.name_ptr = (u64)(unsigned long)value_name;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = sizeof(bad_layer);
	args.layer_ptr = (u64)(unsigned long)bad_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	ctx.reads = 0;
	args.layer_len = sizeof(invalid_utf8_layer);
	args.layer_ptr = (u64)(unsigned long)invalid_utf8_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	ctx.reads = 0;
	args.layer_len = strlen(overlay_name);
	args.layer_ptr = (u64)(unsigned long)overlay_input;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_value_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_blanket_tombstone_set_deletes_effective_values(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x92 },
	};
	static const char value_name[] = "Alpha";
	static const u8 before_data[] = { 0x01, 0x00, 0x00, 0x00 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.set = 1,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_value_found = true,
		.before_data = before_data,
		.before_data_len = sizeof(before_data),
		.before_value_layer_name = "base",
		.before_value_type = REG_DWORD,
		.after_value_found = true,
		.after_data = before_data,
		.after_data_len = sizeof(before_data),
		.after_value_layer_name = "base",
		.after_value_type = REG_DWORD,
		.after_blanket_found = true,
		.blanket_status = RSI_OK,
		.expected_set = true,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	KUNIT_ASSERT_GT(test, sequence_before, 0ULL);
	script.before_value_sequence = sequence_before - 1;
	script.after_value_sequence = sequence_before - 1;
	script.after_blanket_sequence = sequence_before;
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread,
		&script, "pkm-lcs-kunit-blanket-set");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_set_value_policy_layer_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa9, 0x01 },
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xa9, 0x02
	};
	static const char value_name[] = "PolicyAnswer";
	static const char policy_layer_name[] = "policy";
	static const u8 data[] = { 0x2a };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.layer_len = strlen(policy_layer_name),
		.layer_ptr = (u64)(unsigned long)policy_layer_name,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = policy_layer_name,
		.expected_data = data,
		.expected_data_len = sizeof(data),
		.expected_value_type = REG_BINARY,
		.set_value_status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	const u8 *layer_sd;
	struct task_struct *task;
	u8 event[32] = { };
	size_t layer_sd_len = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	layer_sd = kacs_rust_kunit_create_file_sd(admin_token, KEY_SET_VALUE,
						  0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	script.file = &file;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				policy_layer_name, strlen(policy_layer_name),
				10, 1, policy_layer_guid, layer_sd,
				layer_sd_len, pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-set-value-policy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(event + 8, value_name, strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_kacs_free((void *)layer_sd);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_value_policy_reveals_base(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa9, 0x03 },
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xa9, 0x04
	};
	static const char value_name[] = "PolicyAnswer";
	static const char policy_layer_name[] = "policy";
	static const u8 before_data[] = { 0x2a };
	static const u8 after_data[] = { 0x11 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
		.layer_len = strlen(policy_layer_name),
		.layer_ptr = (u64)(unsigned long)policy_layer_name,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_delete_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = policy_layer_name,
		.before_found = true,
		.before_data = before_data,
		.before_data_len = sizeof(before_data),
		.before_layer_name = policy_layer_name,
		.before_value_type = REG_BINARY,
		.after_found = true,
		.after_data = after_data,
		.after_data_len = sizeof(after_data),
		.after_layer_name = "base",
		.after_value_type = REG_BINARY,
		.delete_status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	const u8 *layer_sd;
	struct task_struct *task;
	u8 event[32] = { };
	size_t layer_sd_len = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 next_sequence = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	layer_sd = kacs_rust_kunit_create_file_sd(admin_token, KEY_SET_VALUE,
						  0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	script.file = &file;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				policy_layer_name, strlen(policy_layer_name),
				10, 1, policy_layer_guid, layer_sd,
				layer_sd_len, pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&next_sequence),
			0L);
	KUNIT_ASSERT_GT(test, next_sequence, 0ULL);
	script.before_sequence = next_sequence - 1;
	script.after_sequence = next_sequence - 1;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-value-policy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(event + 8, value_name, strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_kacs_free((void *)layer_sd);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_blanket_tombstone_policy_masks_base(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa9, 0x05 },
	};
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = {
		0xa9, 0x06
	};
	static const char value_name[] = "Alpha";
	static const char policy_layer_name[] = "policy";
	static const u8 before_data[] = { 0x01, 0x00, 0x00, 0x00 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.layer_len = strlen(policy_layer_name),
		.layer_ptr = (u64)(unsigned long)policy_layer_name,
		.set = 1,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = policy_layer_name,
		.before_value_found = true,
		.before_data = before_data,
		.before_data_len = sizeof(before_data),
		.before_value_layer_name = "base",
		.before_value_type = REG_DWORD,
		.after_value_found = true,
		.after_data = before_data,
		.after_data_len = sizeof(before_data),
		.after_value_layer_name = "base",
		.after_value_type = REG_DWORD,
		.after_blanket_found = true,
		.blanket_status = RSI_OK,
		.expected_set = true,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	const u8 *layer_sd;
	struct task_struct *task;
	u8 event[32] = { };
	size_t layer_sd_len = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	layer_sd = kacs_rust_kunit_create_file_sd(admin_token, KEY_SET_VALUE,
						  0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	script.file = &file;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				policy_layer_name, strlen(policy_layer_name),
				10, 1, policy_layer_guid, layer_sd,
				layer_sd_len, pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	KUNIT_ASSERT_GT(test, sequence_before, 0ULL);
	script.before_value_sequence = sequence_before - 1;
	script.after_value_sequence = sequence_before - 1;
	script.after_blanket_sequence = sequence_before;
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread,
		&script, "pkm-lcs-kunit-blanket-policy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(event + 8, value_name, strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_kacs_free((void *)layer_sd);
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_blanket_tombstone_remove_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x93 },
	};
	static const char value_name[] = "Alpha";
	static const u8 after_data[] = { 0x2a };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.set = 0,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_blanket_found = true,
		.after_value_found = true,
		.after_data = after_data,
		.after_data_len = sizeof(after_data),
		.after_value_layer_name = "base",
		.after_value_type = REG_BINARY,
		.blanket_status = RSI_OK,
		.expected_set = false,
		.expect_begin = true,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 next_sequence = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.expected_before_query_txn_id = txn_snapshot.transaction_id;
	script.expected_after_query_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&next_sequence),
			0L);
	KUNIT_ASSERT_GT(test, next_sequence, 0ULL);
	script.before_blanket_sequence = next_sequence - 1;
	script.after_value_sequence = next_sequence - 1;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread,
		&script, "pkm-lcs-kunit-blanket-remove-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-blanket-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_blanket_tombstone_set_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x95 },
	};
	static const char value_name[] = "Alpha";
	static const u8 before_data[] = { 0x2b };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.set = 1,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_value_found = true,
		.before_data = before_data,
		.before_data_len = sizeof(before_data),
		.before_value_layer_name = "base",
		.before_value_type = REG_BINARY,
		.after_value_found = true,
		.after_data = before_data,
		.after_data_len = sizeof(before_data),
		.after_value_layer_name = "base",
		.after_value_type = REG_BINARY,
		.after_blanket_found = true,
		.blanket_status = RSI_OK,
		.expected_set = true,
		.expect_begin = true,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[32] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.expected_before_query_txn_id = txn_snapshot.transaction_id;
	script.expected_after_query_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	KUNIT_ASSERT_GT(test, sequence_before, 0ULL);
	script.before_value_sequence = sequence_before - 1;
	script.after_value_sequence = sequence_before - 1;
	script.after_blanket_sequence = sequence_before;
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread,
		&script, "pkm-lcs-kunit-blanket-set-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, log.last_sequence, sequence_before);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-blanket-set-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event),
			(u32)(8U + strlen(value_name)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)strlen(value_name));
	KUNIT_EXPECT_EQ(test, memcmp(event + 8, value_name,
				     strlen(value_name)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_blanket_tombstone_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x94 },
	};
	static const char bad_layer[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_layer[] = { 'b', 0xff, 'd' };
	static const char overlay_name[] = "overlay";
	static const char overlay_input[] = {
		'o', 'v', 'e', 'r', 'l', 'a', 'y', '!'
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.set = 1,
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long allowed_fd;
	long denied_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)denied_fd, admin_token, &ops, &args),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad1[0] = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad1[0] = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args.set = 2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.set = 1;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.txn_fd = -1;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.reads = 0;
	args.layer_len = sizeof(bad_layer);
	args.layer_ptr = (u64)(unsigned long)bad_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = sizeof(invalid_utf8_layer);
	args.layer_ptr = (u64)(unsigned long)invalid_utf8_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = strlen(overlay_name);
	args.layer_ptr = (u64)(unsigned long)overlay_input;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_blanket_tombstone_source_error_no_effects(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x95 },
	};
	static const char value_name[] = "Alpha";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.set = 1,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_value_found = true,
		.before_value_layer_name = "base",
		.before_value_type = REG_BINARY,
		.blanket_status = RSI_STORAGE_ERROR,
		.expected_set = true,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	KUNIT_ASSERT_GT(test, sequence_before, 0ULL);
	script.before_value_sequence = sequence_before - 1;
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread,
		&script, "pkm-lcs-kunit-blanket-error");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, script.observed_last_write_time, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_blanket_tombstone_transactional_source_error(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x96 },
	};
	static const char value_name[] = "Alpha";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_blanket_tombstone_args args = {
		.set = 1,
		.txn_fd = -1,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.before_value_found = true,
		.before_value_layer_name = "base",
		.before_value_type = REG_BINARY,
		.blanket_status = RSI_STORAGE_ERROR,
		.expected_set = true,
		.expect_begin = true,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u8 event[16] = { };
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long watch_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.expected_before_query_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.begin.expected_mode = RSI_TXN_READ_WRITE;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.begin.status = RSI_OK;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	KUNIT_ASSERT_GT(test, sequence_before, 0ULL);
	script.before_value_sequence = sequence_before - 1;
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread,
		&script, "pkm-lcs-kunit-blanket-txn-error");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, script.observed_last_write_time, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_nontransactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7e },
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_walk_source_step post_lookup_step = {
		.expected_child = "Software",
		.empty = true,
	};
	struct pkm_lcs_kunit_hide_key_ioctl_source_script script = {
		.hide = {
			.expected_parent_guid = ancestors[0],
			.expected_child_name = "Software",
			.expected_layer_name = "base",
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
		.post_lookup = {
			.steps = &post_lookup_step,
			.step_count = 1,
		},
		.expect_post_lookup = true,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.hide.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_hide_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-hide-key");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_hide_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_runtime_limits_source_frame(
	struct kunit *test)
{
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7e, 0x01 },
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_walk_source_step post_lookup_step = {
		.empty = true,
	};
	struct pkm_lcs_kunit_hide_key_ioctl_source_script script = {
		.hide = {
			.expected_parent_guid = ancestors[0],
			.expected_layer_name = "base",
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
		.post_lookup = {
			.steps = &post_lookup_step,
			.step_count = 1,
		},
		.expect_post_lookup = true,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	char child_name[301];
	const char *path[2] = { "Machine", child_name };
	u64 sequence_before = 0;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 300U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	memset(child_name, 'h', sizeof(child_name) - 1);
	child_name[sizeof(child_name) - 1] = '\0';
	script.hide.expected_child_name = child_name;
	post_lookup_step.expected_child = child_name;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, ARRAY_SIZE(ancestors));
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.hide.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_hide_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-hide-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_hide_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_dispatches_visibility_watches(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const path[] = { "Machine", "Parent", "Child" };
	static const u8 root_ancestors[1][PKM_LCS_GUID_BYTES] = { { 1 } };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa1 },
	};
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa1 },
		{ 0xa2 },
	};
	struct reg_notify_args subkey_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct reg_notify_args value_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_walk_source_step post_lookup_step = {
		.expected_child = "Child",
		.empty = true,
	};
	struct pkm_lcs_kunit_hide_key_ioctl_source_script script = {
		.hide = {
			.expected_parent_guid = ancestors[1],
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
		.post_lookup = {
			.steps = &post_lookup_step,
			.step_count = 1,
		},
		.expect_post_lookup = true,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u8 parent_record[16] = { };
	u8 root_record[32] = { };
	u8 child_record[8] = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 sequence_before = 0;
	long root_fd;
	long parent_fd;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE | KEY_NOTIFY, path, ancestors, 3);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &subkey_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)mutation_fd,
						    &value_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.hide.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_hide_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-hide-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_hide_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)13);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 13U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, "Child", 5), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, root_record,
						  23, true),
			(ssize_t)23);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(root_record), 23U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 6), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(root_record + 8, "Child", 5), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 13), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 15), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(root_record + 17, "Parent", 6), 0);
	memset(root_record, 0, sizeof(root_record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, root_record,
						  25, true),
			(ssize_t)25);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(root_record), 25U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 6), 0U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 8), 2U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 10), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(root_record + 12, "Parent", 6), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(root_record + 18), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(root_record + 20, "Child", 5), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)mutation_fd,
						  child_record,
						  sizeof(child_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(child_record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 6), 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_lower_layer_no_visibility_watch(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const path[] = { "Machine", "Parent", "Child" };
	static const u8 root_ancestors[1][PKM_LCS_GUID_BYTES] = { { 1 } };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xb1 },
	};
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xb1 },
		{ 0xb2 },
	};
	static const u8 policy_guid[PKM_LCS_GUID_BYTES] = { 0xb3 };
	struct reg_notify_args subkey_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct reg_notify_args value_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_walk_source_step post_lookup_step = {
		.expected_child = "Child",
		.layer_name = "policy",
		.guid = ancestors[2],
	};
	struct pkm_lcs_kunit_hide_key_ioctl_source_script script = {
		.hide = {
			.expected_parent_guid = ancestors[1],
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
		.post_lookup = {
			.steps = &post_lookup_step,
			.step_count = 1,
		},
		.expect_post_lookup = true,
	};
	u8 record[32] = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	long root_fd;
	long parent_fd;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1, policy_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE | KEY_NOTIFY, path, ancestors, 3);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &subkey_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)mutation_fd,
						    &value_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.hide.expected_sequence = sequence_before;
	post_lookup_step.sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_hide_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-hide-no-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_hide_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)mutation_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x86 },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_hide_key_ioctl_source_script script = {
		.expect_begin = true,
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
		.hide = {
			.expected_parent_guid = ancestors[0],
			.expected_child_name = "Software",
			.expected_layer_name = "base",
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
	};
	struct pkm_lcs_kunit_walk_source_step lookup_step = {
		.expected_child = "Software",
		.empty = true,
	};
	struct pkm_lcs_kunit_walk_source_script lookup = {
		.steps = &lookup_step,
		.step_count = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.hide.expected_txn_id = txn_snapshot.transaction_id;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.hide.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_hide_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-hide-key-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_hide_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY);
	KUNIT_EXPECT_EQ(test, log.last_sequence, sequence_before);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 1U);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Software");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before + 1);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	commit_script.hide_key_lookup_after = &lookup;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-hide-key-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);
	KUNIT_EXPECT_EQ(test, lookup.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_transactional_source_failure(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x87 },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_hide_key_ioctl_source_script script = {
		.expect_begin = true,
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
		.hide = {
			.expected_parent_guid = ancestors[0],
			.expected_child_name = "Software",
			.expected_layer_name = "base",
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_INVALID,
		},
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	long mutation_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.hide.expected_txn_id = txn_snapshot.transaction_id;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.hide.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_hide_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-hide-key-txn-fail");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_hide_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_nontransactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x80 },
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.remaining_path_found = true,
		.remaining_guid = ancestors[1],
		.delete_status = RSI_OK,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_GT(test, script.observed_parent_last_write_time, 0ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_delete_layer_metadata_key_orchestrates(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xd7, 0x10 },
		{ 0xd7, 0x11 },
		{ 0xd7, 0x12 },
		{ 0xd7 },
	};
	static const u8 policy_sd[] = {
		0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
	};
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	char names[32] = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = metadata_ancestors[3],
		.expected_key_guid = metadata_ancestors[4],
		.expected_child_name = "Policy",
		.expected_layer_name = "base",
		.remaining_path_found = false,
		.delete_status = RSI_OK,
		.expect_delete_layer = true,
		.delete_layer = {
			.expected_layer_name = "Policy",
			.status = RSI_OK,
		},
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u32 layer_count = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 9, 1,
				metadata_ancestors[4], policy_sd,
				sizeof(policy_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&layer_count),
			0L);
	KUNIT_ASSERT_EQ(test, layer_count, 2U);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-del-layer-key");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_GT(test, script.observed_parent_last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	memset(layers, 0, sizeof(layers));
	memset(names, 0, sizeof(names));
	layer_count = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&layer_count),
			0L);
	KUNIT_ASSERT_EQ(test, layer_count, 1U);
	KUNIT_EXPECT_STREQ(test, layers[0].name, "base");
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file,
					      metadata_ancestors[4]);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_orphans_missing_guid(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x81 },
	};
	static const u8 replacement_guid[PKM_LCS_GUID_BYTES] = { 0x82 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct reg_notify_args notify_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.remaining_path_found = true,
		.remaining_guid = replacement_guid,
		.delete_status = RSI_OK,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u8 record[16] = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE | KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)mutation_fd,
						    &notify_args),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-orphan");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)mutation_fd, record,
						  sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_KEY_DELETED);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[1]);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_dispatches_visibility_watches(
	struct kunit *test)
{
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const path[] = { "Machine", "Parent", "Child" };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa3 },
	};
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa3 },
		{ 0xa4 },
	};
	struct reg_notify_args subkey_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args value_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[1],
		.expected_key_guid = ancestors[2],
		.expected_child_name = "Child",
		.expected_layer_name = "base",
		.remaining_path_found = false,
		.delete_status = RSI_OK,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u8 parent_record[16] = { };
	u8 child_record[8] = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	long parent_fd;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE | KEY_NOTIFY, path, ancestors, 3);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &subkey_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)mutation_fd,
						    &value_args),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)13);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 13U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, "Child", 5), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)mutation_fd,
						  child_record,
						  sizeof(child_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(child_record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 6), 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[2]);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_replacement_dispatches_create(
	struct kunit *test)
{
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const path[] = { "Machine", "Parent", "Child" };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa5 },
	};
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xa5 },
		{ 0xa6 },
	};
	static const u8 replacement_guid[PKM_LCS_GUID_BYTES] = { 0xa7 };
	struct reg_notify_args subkey_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args value_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[1],
		.expected_key_guid = ancestors[2],
		.expected_child_name = "Child",
		.expected_layer_name = "base",
		.remaining_path_found = true,
		.remaining_guid = replacement_guid,
		.delete_status = RSI_OK,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u8 parent_record[16] = { };
	u8 child_record[8] = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	long parent_fd;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE | KEY_NOTIFY, path, ancestors, 3);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &subkey_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)mutation_fd,
						    &value_args),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-replace");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record, 13, true),
			(ssize_t)13);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 13U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, "Child", 5), 0);
	memset(parent_record, 0, sizeof(parent_record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record, 13, true),
			(ssize_t)13);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 13U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, "Child", 5), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)mutation_fd,
						  child_record,
						  sizeof(child_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(child_record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[2]);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_visible_child_denied(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x83 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x84 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.visible_child_guid = child_guid,
		.visible_child_name = "Child",
		.delete_status = RSI_OK,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-child");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOTEMPTY);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, script.observed_parent_last_write_time, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_visible_policy_child_denied(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x84 },
	};
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x85 };
	static const u8 policy_layer_guid[PKM_LCS_GUID_BYTES] = { 0x86 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.visible_child_guid = child_guid,
		.visible_child_name = "Child",
		.visible_child_layer_name = "policy",
		.delete_status = RSI_OK,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1,
				policy_layer_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-policy-child");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOTEMPTY);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, script.observed_parent_last_write_time, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_transactional_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x88 },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.delete_status = RSI_OK,
		.expect_begin = true,
		.skip_orphan_lookup = true,
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
	};
	struct pkm_lcs_kunit_transaction_source_script commit_script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script commit_lookup = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.remaining_path_found = true,
		.remaining_guid = ancestors[1],
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long mutation_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_GT(test, script.observed_parent_last_write_time, 0ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 1U);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Software");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	commit_script.file = &file;
	commit_script.expected_header_txn_id = txn_snapshot.transaction_id;
	commit_script.expected_payload_txn_id = txn_snapshot.transaction_id;
	commit_script.delete_key_lookup_after = &commit_lookup;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
					 &commit_script,
					 "pkm-lcs-kunit-delete-key-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, commit_script.result, 0);
	KUNIT_EXPECT_EQ(test, commit_script.reads, 2U);
	KUNIT_EXPECT_EQ(test, commit_script.writes, 2U);
	KUNIT_EXPECT_EQ(test, commit_lookup.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)mutation_fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_runtime_limits_source_frame(
	struct kunit *test)
{
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x88, 0x01 },
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_layer_name = "base",
		.delete_status = RSI_OK,
		.expect_begin = true,
		.skip_orphan_lookup = true,
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	char child_name[301];
	const char *path[2] = { "Machine", child_name };
	long mutation_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 300U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	memset(child_name, 'd', sizeof(child_name) - 1);
	child_name[sizeof(child_name) - 1] = '\0';
	script.expected_child_name = child_name;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, ARRAY_SIZE(ancestors));
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_GT(test, script.observed_parent_last_write_time, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_transactional_source_failure(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x89 },
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_delete_key_ioctl_source_script script = {
		.expected_parent_guid = ancestors[0],
		.expected_key_guid = ancestors[1],
		.expected_child_name = "Software",
		.expected_layer_name = "base",
		.delete_status = RSI_INVALID,
		.expect_begin = true,
		.skip_orphan_lookup = true,
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
	};
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long mutation_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);

	mutation_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, mutation_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	args.txn_fd = (int)txn_fd;
	script.file = &file;
	script.expected_txn_id = txn_snapshot.transaction_id;
	script.begin.expected_header_txn_id = 0;
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_key_ioctl_source_thread, &script,
		"pkm-lcs-kunit-delete-key-txn-fail");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_delete_key_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, script.observed_parent_last_write_time, 0ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mutation_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_hide_key_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const char * const root_path[] = { "Machine" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7f },
	};
	static const u8 root_ancestor[1][PKM_LCS_GUID_BYTES] = { { 1 } };
	static const char bad_layer[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_layer[] = { 'b', 0xff, 'd' };
	static const char overlay_name[] = "overlay";
	static const char overlay_input[] = {
		'o', 'v', 'e', 'r', 'l', 'a', 'y', '!'
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_hide_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long allowed_fd;
	long denied_fd;
	long root_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);
	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, root_path, root_ancestor, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)denied_fd, admin_token, &ops, &args),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad1 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad1 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.txn_fd = 123;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EBADF);
	args.txn_fd = -1;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)root_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)allowed_fd,
							  true),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)allowed_fd,
							  false),
			0L);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.reads = 0;
	args.layer_len = sizeof(bad_layer);
	args.layer_ptr = (u64)(unsigned long)bad_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = sizeof(invalid_utf8_layer);
	args.layer_ptr = (u64)(unsigned long)invalid_utf8_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = strlen(overlay_name);
	args.layer_ptr = (u64)(unsigned long)overlay_input;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_hide_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_delete_key_fails_before_source(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const char * const root_path[] = { "Machine" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x85 },
	};
	static const u8 root_ancestor[1][PKM_LCS_GUID_BYTES] = { { 1 } };
	static const char bad_layer[] = { 'b', '\0', 'd' };
	static const u8 invalid_utf8_layer[] = { 'b', 0xff, 'd' };
	static const char overlay_name[] = "overlay";
	static const char overlay_input[] = {
		'o', 'v', 'e', 'r', 'l', 'a', 'y', '!'
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_delete_key_args args = {
		.txn_fd = -1,
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	u64 sequence_before = 0;
	u64 sequence_after = 0;
	long allowed_fd;
	long denied_fd;
	long root_fd;
	long txn_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);
	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);
	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, DELETE, root_path, root_ancestor, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)denied_fd, admin_token, &ops, &args),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args._pad0 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad0 = 0;
	args._pad1 = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args._pad1 = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	args.txn_fd = -2;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	args.txn_fd = 123;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EBADF);
	args.txn_fd = -1;
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)root_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)root_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	args.txn_fd = -1;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)allowed_fd,
							  true),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)allowed_fd,
							  false),
			0L);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.reads = 0;
	args.layer_len = sizeof(bad_layer);
	args.layer_ptr = (u64)(unsigned long)bad_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = sizeof(invalid_utf8_layer);
	args.layer_ptr = (u64)(unsigned long)invalid_utf8_layer;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args.layer_len = strlen(overlay_name);
	args.layer_ptr = (u64)(unsigned long)overlay_input;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_delete_key_for_token(
				(int)allowed_fd, admin_token, &ops, &args),
			(long)-ENOENT);
	args.layer_len = 0;
	args.layer_ptr = 0;
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, sequence_before);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_flush_success(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7c },
	};
	struct pkm_lcs_kunit_flush_source_script script = {
		.expected_hive_name = "Machine",
		.status = RSI_OK,
	};
	struct file file = { };
	struct task_struct *task;
	const void *source_token;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_flush_source_thread, &script,
			   "pkm-lcs-kunit-key-flush");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_flush((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_flush_orphaned_guid_local_success(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7e },
	};
	struct pkm_lcs_kunit_flush_source_script script = {
		.expected_hive_name = "Machine",
		.status = RSI_OK,
	};
	struct file file = { };
	struct task_struct *task;
	const void *source_token;
	int thread_ret;
	long fd;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_flush_source_thread,
					 &script,
					 "pkm-lcs-kunit-orphan-flush");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_flush((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)fd, false),
			0L);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_flush_fails_before_source(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7d },
	};
	struct file file = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	const void *source_token;
	long denied_fd;
	long allowed_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);

	denied_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, denied_fd >= 0);
	allowed_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_SET_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, allowed_fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_flush((int)denied_fd),
			(long)-EACCES);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_flush((int)allowed_fd),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)denied_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)allowed_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_ioctl_access_rejects_bad_fds(
	struct kunit *test)
{
	int fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_fixed_ioctl_access(
				-1, REG_IOC_QUERY_VALUE),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				-1, REG_IOC_GET_SECURITY,
				DACL_SECURITY_INFORMATION),
			(long)-EBADF);

	fd = anon_inode_getfd("lcs-not-key", &pkm_lcs_kunit_non_key_fops,
			      NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_fixed_ioctl_access(
				fd, REG_IOC_QUERY_VALUE),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_check_security_ioctl_access(
				fd, REG_IOC_GET_SECURITY,
				DACL_SECURITY_INFORMATION),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_backup_admission(struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_export_reads = true,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_EXPECT_EQ(test, before.privileges_used & KACS_SE_BACKUP_PRIVILEGE,
			0ULL);
	script.file = &file;
	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	pkm_lcs_kunit_expect_empty_backup_stream(test, &output, key_guid);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_BACKUP_PRIVILEGE,
			KACS_SE_BACKUP_PRIVILEGE);
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_BACKUP_START", "fd");
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_BACKUP_COMPLETE", "result_errno");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_cycle_fails_closed(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53 };
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_export_reads = true,
		.expect_child_export_reads = true,
		.nonempty_child_response = true,
		.cycle_child_response = true,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-cycle");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			(long)-EIO);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 8U);
	KUNIT_EXPECT_EQ(test, script.writes, 8U);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	KUNIT_EXPECT_EQ(test, output.len, (size_t)0);
	pkm_lcs_kunit_expect_source_validation_audit(
		test, "malformed_key_metadata", child_guid);
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_BACKUP_COMPLETE", "result_errno");
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_FALSE(test, source_snapshot.closing);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_root_records_success(
	struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u16 expected_types[] = {
		REG_BACKUP_HEADER,
		REG_BACKUP_LAYER,
		REG_BACKUP_KEY,
		REG_BACKUP_PATH_ENTRY,
		REG_BACKUP_VALUE,
		REG_BACKUP_BLANKET_TOMBSTONE,
		REG_BACKUP_TRAILER,
	};
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_export_reads = true,
		.hidden_child_response = true,
		.root_value_response = true,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-root");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	pkm_lcs_kunit_expect_backup_stream_record_types(
		test, &output, expected_types, ARRAY_SIZE(expected_types),
		key_guid);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_root_payloads(struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u8 hidden_guid[PKM_LCS_GUID_BYTES] = { };
	static const u8 root_value_data[] = { 0xde, 0xad, 0xbe, 0xef };
	static const u16 expected_types[] = {
		REG_BACKUP_HEADER,
		REG_BACKUP_LAYER,
		REG_BACKUP_KEY,
		REG_BACKUP_PATH_ENTRY,
		REG_BACKUP_VALUE,
		REG_BACKUP_BLANKET_TOMBSTONE,
		REG_BACKUP_TRAILER,
	};
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_export_reads = true,
		.hidden_child_response = true,
		.root_value_response = true,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	const u8 *frame = NULL;
	struct task_struct *task;
	size_t frame_len = 0;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-payloads");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	pkm_lcs_kunit_expect_backup_stream_record_types(
		test, &output, expected_types, ARRAY_SIZE(expected_types),
		key_guid);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 1, REG_BACKUP_LAYER, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_layer_manifest_record(
		test, frame, frame_len, "base", 0, 1,
		pkm_lcs_kunit_system_sid, sizeof(pkm_lcs_kunit_system_sid));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 3, REG_BACKUP_PATH_ENTRY, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_path_entry_record(test, frame, frame_len,
					       key_guid, "Child", hidden_guid,
					       "base", 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 4, REG_BACKUP_VALUE, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_value_record(test, frame, frame_len, key_guid,
					  "RootValue", REG_BINARY,
					  root_value_data,
					  sizeof(root_value_data), "base", 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 5, REG_BACKUP_BLANKET_TOMBSTONE,
				&frame, &frame_len),
			0);
	pkm_lcs_kunit_expect_blanket_tombstone_record(
		test, frame, frame_len, key_guid, "base", 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_leaf_child_success(
	struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53 };
	static const u8 child_value_data[] = { 0xc0, 0xff, 0xee };
	static const u16 expected_types[] = {
		REG_BACKUP_HEADER,
		REG_BACKUP_LAYER,
		REG_BACKUP_KEY,
		REG_BACKUP_KEY,
		REG_BACKUP_PATH_ENTRY,
		REG_BACKUP_VALUE,
		REG_BACKUP_BLANKET_TOMBSTONE,
		REG_BACKUP_TRAILER,
	};
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_export_reads = true,
		.expect_child_export_reads = true,
		.nonempty_child_response = true,
		.child_value_response = true,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	const u8 *frame = NULL;
	struct task_struct *task;
	size_t frame_len = 0;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-leaf");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 8U);
	KUNIT_EXPECT_EQ(test, script.writes, 8U);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	pkm_lcs_kunit_expect_backup_stream_record_types(
		test, &output, expected_types, ARRAY_SIZE(expected_types),
		key_guid);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 3, REG_BACKUP_KEY, &frame, &frame_len),
			0);
	pkm_lcs_kunit_expect_key_record(
		test, frame, frame_len, child_guid, 0,
		pkm_lcs_kunit_owner_only_sd, sizeof(pkm_lcs_kunit_owner_only_sd),
		5678);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 4, REG_BACKUP_PATH_ENTRY, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_path_entry_record(test, frame, frame_len, key_guid,
					       "Child", child_guid, "base", 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 5, REG_BACKUP_VALUE, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_value_record(test, frame, frame_len, child_guid,
					  "ChildValue", REG_BINARY,
					  child_value_data,
					  sizeof(child_value_data), "base", 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 6, REG_BACKUP_BLANKET_TOMBSTONE,
				&frame, &frame_len),
			0);
	pkm_lcs_kunit_expect_blanket_tombstone_record(
		test, frame, frame_len, child_guid, "base", 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_grandchild_success(
	struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53 };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x54 };
	static const u8 grandchild_value_data[] = { 0x5a, 0x5b };
	static const u16 expected_types[] = {
		REG_BACKUP_HEADER,
		REG_BACKUP_LAYER,
		REG_BACKUP_KEY,
		REG_BACKUP_KEY,
		REG_BACKUP_PATH_ENTRY,
		REG_BACKUP_VALUE,
		REG_BACKUP_BLANKET_TOMBSTONE,
		REG_BACKUP_KEY,
		REG_BACKUP_PATH_ENTRY,
		REG_BACKUP_VALUE,
		REG_BACKUP_BLANKET_TOMBSTONE,
		REG_BACKUP_TRAILER,
	};
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_export_reads = true,
		.expect_child_export_reads = true,
		.expect_grandchild_export_reads = true,
		.nonempty_child_response = true,
		.child_value_response = true,
		.grandchild_response = true,
		.grandchild_value_response = true,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	const u8 *frame = NULL;
	struct task_struct *task;
	size_t frame_len = 0;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-grandchild");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 11U);
	KUNIT_EXPECT_EQ(test, script.writes, 11U);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	pkm_lcs_kunit_expect_backup_stream_record_types(
		test, &output, expected_types, ARRAY_SIZE(expected_types),
		key_guid);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 7, REG_BACKUP_KEY, &frame, &frame_len),
			0);
	pkm_lcs_kunit_expect_key_record(
		test, frame, frame_len, grandchild_guid, 0,
		pkm_lcs_kunit_owner_only_sd, sizeof(pkm_lcs_kunit_owner_only_sd),
		5678);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 8, REG_BACKUP_PATH_ENTRY, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_path_entry_record(test, frame, frame_len,
					       child_guid, "Grandchild",
					       grandchild_guid, "base", 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 9, REG_BACKUP_VALUE, &frame,
				&frame_len),
			0);
	pkm_lcs_kunit_expect_value_record(
		test, frame, frame_len, grandchild_guid, "GrandchildValue",
		REG_BINARY, grandchild_value_data, sizeof(grandchild_value_data),
		"base", 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_stream_record_at(
				&output, 10, REG_BACKUP_BLANKET_TOMBSTONE,
				&frame, &frame_len),
			0);
	pkm_lcs_kunit_expect_blanket_tombstone_record(
		test, frame, frame_len, grandchild_guid, "base", 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_read_only_unsupported(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct reg_backup_args args = { };
	struct pkm_lcs_kunit_backup_snapshot_source_script script = {
		.begin_status = RSI_TXN_NOT_SUPPORTED,
		.abort_status = RSI_OK,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *source_token;
	const void *token;
	long key_fd;
	int output_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_external_fd(O_WRONLY);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_backup_snapshot_source_thread, &script,
		"pkm-lcs-kunit-backup-unsupported");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			(long)-EOPNOTSUPP);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_BACKUP_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_read_only_cap_fail_before_source(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct reg_backup_args args = { };
	struct file file = { };
	const void *source_token;
	const void *token;
	long key_fd;
	u32 count = 0;
	int output_fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_read_only_transactions_per_source = 1U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_read_only_transaction_acquire(1,
								    &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_external_fd(O_WRONLY);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			(long)-EBUSY);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 1U);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_BACKUP_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_read_only_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_read_timeout_late_success_discard(
	struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	struct pkm_lcs_kunit_backup_snapshot_source_script source_script = {
		.file = NULL,
	};
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = key_guid,
		.name = "Software",
		.last_write_time = 2000ULL,
	};
	struct pkm_lcs_source_response_result late_read_response = { };
	struct pkm_lcs_source_response_result begin_response = { };
	struct pkm_lcs_source_response_result abort_response = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_backup_output_file *output;
	struct pkm_lcs_kunit_backup_call_script backup = { };
	struct pkm_kacs_boot_snapshot token_snapshot = { };
	u8 *read_key_response;
	u8 status_response[RSI_MIN_RESPONSE_SIZE];
	u8 request[128];
	struct task_struct *task;
	struct file file = { };
	const void *source_token;
	const void *token;
	size_t response_len = 0;
	const size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	long key_fd;
	u64 begin_request_id;
	u64 read_request_id;
	u64 abort_request_id;
	u64 transaction_id;
	u16 op_code;
	int output_fd;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	output = kzalloc(sizeof(*output), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, output);
	read_key_response = kmalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, read_key_response);

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	source_script.file = &file;
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	backup.key_fd = key_fd;
	backup.token = token;
	backup.args.output_fd = output_fd;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_backup_call_thread,
					 &backup,
					 "pkm-lcs-kunit-backup-read-timeout");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_snapshot_read_source_request(
				&source_script, request, sizeof(request)),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64) +
				  sizeof(u32)));
	begin_request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	transaction_id = get_unaligned_le64(request + payload_offset);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_NE(test, transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_ONLY);

	pkm_lcs_kunit_build_status_response(
		test, status_response, sizeof(status_response),
		begin_request_id, RSI_BEGIN_TRANSACTION, RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, status_response, response_len, false,
				&begin_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_TRUE(test, begin_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, begin_response.status, (u32)RSI_OK);

	memset(request, 0, sizeof(request));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_snapshot_read_source_request(
				&source_script, request, sizeof(request)),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE));
	read_request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	op_code = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	KUNIT_EXPECT_EQ(test, op_code, (u16)RSI_READ_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			transaction_id);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, key_guid,
			       RSI_GUID_SIZE),
			0);

	memset(request, 0, sizeof(request));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_backup_snapshot_read_source_request(
				&source_script, request, sizeof(request)),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	abort_request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(request + payload_offset),
			transaction_id);

	pkm_lcs_kunit_build_status_response(
		test, status_response, sizeof(status_response),
		abort_request_id, RSI_ABORT_TRANSACTION, RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, status_response, response_len, false,
				&abort_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_TRUE(test, abort_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, abort_response.status, (u32)RSI_OK);

	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, -ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, backup.result, (long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, output->len, (size_t)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &token_snapshot));
	KUNIT_EXPECT_EQ(test,
			token_snapshot.privileges_used & KACS_SE_BACKUP_PRIVILEGE,
			KACS_SE_BACKUP_PRIVILEGE);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);

	read_key.expected_txn_id = transaction_id;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_read_key_source_build_response(
				&read_key, read_request_id, read_key_response,
				1024, &response_len),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, read_key_response, response_len, false,
				&late_read_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, late_read_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, late_read_response.request_id, read_request_id);
	KUNIT_EXPECT_EQ(test, late_read_response.txn_id, transaction_id);
	KUNIT_EXPECT_EQ(test, late_read_response.request_op_code,
			(u16)RSI_READ_KEY);
	KUNIT_EXPECT_EQ(test, late_read_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_EQ(test, late_read_response.in_flight_count, 0U);
	KUNIT_EXPECT_EQ(test, output->len, (size_t)0);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
	kfree(read_key_response);
	kfree(output);
}


static void pkm_lcs_kunit_key_fd_backup_read_only_begin_timeout_cleanup(
	struct kunit *test)
{
	struct pkm_lcs_source_response_result begin_response = { };
	struct pkm_lcs_source_response_result abort_response = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_backup_output_file output = { };
	struct pkm_kacs_boot_snapshot token_snapshot = { };
	struct reg_backup_args args = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[128];
	struct file file = { };
	const void *source_token;
	const void *token;
	size_t response_len;
	const size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	long key_fd;
	u64 request_id;
	u64 transaction_id;
	int output_fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token((int)key_fd,
							      token, &args),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, output.len, (size_t)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &token_snapshot));
	KUNIT_EXPECT_EQ(test,
			token_snapshot.privileges_used & KACS_SE_BACKUP_PRIVILEGE,
			0ULL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64) +
				  sizeof(u32)));
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	transaction_id = get_unaligned_le64(request + payload_offset);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_NE(test, transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_ONLY);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_BEGIN_TRANSACTION,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&begin_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, begin_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, begin_response.request_id, request_id);
	KUNIT_EXPECT_EQ(test, begin_response.txn_id, transaction_id);
	KUNIT_EXPECT_EQ(test, begin_response.status, (u32)RSI_OK);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);

	memset(request, 0, sizeof(request));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(request + payload_offset),
			transaction_id);

	pkm_lcs_kunit_build_status_response(
		test, response, sizeof(response),
		get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET),
		RSI_ABORT_TRANSACTION, RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&abort_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, abort_response.txn_id, transaction_id);
	KUNIT_EXPECT_EQ(test, abort_response.request_op_code,
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, abort_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, abort_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, abort_response.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.read_only_transaction_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_backup_pre_start_failure_does_not_audit(
	struct kunit *test)
{
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct reg_backup_args args = { };
	u8 buffer[256];
	const void *token;
	size_t written = 0;
	long key_fd;
	int read_fd;

	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	read_fd = pkm_lcs_kunit_external_fd(O_RDONLY);
	KUNIT_ASSERT_TRUE(test, read_fd >= 0);
	args.output_fd = read_fd;

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, token, &args),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &kmes_snapshot),
			-ENOENT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)read_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_backup_restart_missing_guid_enoent(
	struct kunit *test)
{
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = pkm_lcs_kunit_restore_target_guid,
		.status = RSI_NOT_FOUND,
	};
	struct pkm_lcs_kunit_backup_output_file output = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct pkm_kacs_boot_snapshot token_snapshot = { };
	struct reg_backup_args args = { };
	struct task_struct *task;
	struct file file = { };
	const void *source_token;
	const void *backup_token;
	long key_fd;
	int output_fd;
	int thread_ret;

	key_fd = pkm_lcs_kunit_publish_restarted_missing_backup_restore_fd(
		&file, &source_token);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	backup_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, backup_token);
	output_fd = pkm_lcs_kunit_backup_output_fd(&output);
	KUNIT_ASSERT_TRUE(test, output_fd >= 0);
	args.output_fd = output_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &script,
		"pkm-lcs-kunit-backup-reval-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, backup_token, &args),
			(long)-ENOENT);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, output.len, (size_t)0);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)key_fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, key_snapshot.orphaned);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(backup_token,
							 &token_snapshot));
	KUNIT_EXPECT_EQ(test, token_snapshot.privileges_used &
				      KACS_SE_BACKUP_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)output_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(backup_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_admission(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x52 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct reg_restore_args args = { };
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u8 event[8] = { };
	long key_fd;
	long watch_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, ARRAY_SIZE(ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_EXPECT_EQ(test, before.privileges_used & KACS_SE_RESTORE_PRIVILEGE,
			0ULL);
	script.file = &file;
	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used &
				      KACS_SE_RESTORE_PRIVILEGE,
			KACS_SE_RESTORE_PRIVILEGE);
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_RESTORE_START", "fd");
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_RESTORE_COMPLETE", "result_errno");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_restore_root_path_teardown_dispatches(struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53, 0x07 };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.child_name = "Child",
			.layer_name = "base",
			.child_guid = child_guid,
		},
		.expect_root_path_delete = true,
		.delete_entry = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_op_code = RSI_DELETE_ENTRY,
			.status = RSI_OK,
		},
		.expect_child_teardown = true,
		.child_enum_children = {
			.expected_parent_guid = child_guid,
			.empty = true,
		},
		.child_query_values = {
			.expected_guid = child_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.drop_key = {
			.expected_guid = child_guid,
			.status = RSI_OK,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-root-paths");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 10U);
	KUNIT_EXPECT_EQ(test, script.writes, 10U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_deep_teardown_dispatches(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53, 0xd1 };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x53, 0xd2 };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.child_name = "Child",
			.layer_name = "base",
			.child_guid = child_guid,
		},
		.expect_root_path_delete = true,
		.delete_entry = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_op_code = RSI_DELETE_ENTRY,
			.status = RSI_OK,
		},
		.expect_child_teardown = true,
		.child_enum_children = {
			.expected_parent_guid = child_guid,
			.child_name = "Grandchild",
			.layer_name = "base",
			.child_guid = grandchild_guid,
		},
		.expect_child_path_delete = true,
		.child_delete_entry = {
			.expected_parent_guid = child_guid,
			.expected_child_name = "Grandchild",
			.expected_layer_name = "base",
			.expected_op_code = RSI_DELETE_ENTRY,
			.status = RSI_OK,
		},
		.expect_grandchild_teardown = true,
		.grandchild_enum_children = {
			.expected_parent_guid = grandchild_guid,
			.empty = true,
		},
		.grandchild_query_values = {
			.expected_guid = grandchild_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.grandchild_drop_key = {
			.expected_guid = grandchild_guid,
			.status = RSI_OK,
		},
		.child_query_values = {
			.expected_guid = child_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.drop_key = {
			.expected_guid = child_guid,
			.status = RSI_OK,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-deep");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 14U);
	KUNIT_EXPECT_EQ(test, script.writes, 14U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_restore_teardown_cycle_aborts(struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53, 0xc7 };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.child_name = "Child",
			.layer_name = "base",
			.child_guid = child_guid,
		},
		.expect_root_path_delete = true,
		.delete_entry = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_op_code = RSI_DELETE_ENTRY,
			.status = RSI_OK,
		},
		.expect_child_teardown = true,
		.expect_child_teardown_abort_after_enum = true,
		.child_enum_children = {
			.expected_parent_guid = child_guid,
			.child_name = "RootAlias",
			.layer_name = "base",
			.child_guid = pkm_lcs_kunit_restore_target_guid,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-cycle");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EOPNOTSUPP);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_FALSE(test, script.saw_commit);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_restore_teardown_alias_aborts(struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53, 0xa1 };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.child_name = "Child",
			.layer_name = "base",
			.child_guid = child_guid,
		},
		.expect_root_path_delete = true,
		.delete_entry = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_op_code = RSI_DELETE_ENTRY,
			.status = RSI_OK,
		},
		.expect_child_teardown = true,
		.expect_child_teardown_abort_after_enum = true,
		.child_enum_children = {
			.expected_parent_guid = child_guid,
			.child_name = "SelfAlias",
			.layer_name = "base",
			.child_guid = child_guid,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-alias");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EOPNOTSUPP);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_FALSE(test, script.saw_commit);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_restore_root_value_teardown_dispatches(struct kunit *test)
{
	static const u8 value_data[] = { 0x01, 0x02, 0x03 };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.response_value_name = "RootValue",
			.layer_name = "base",
			.data = value_data,
			.data_len = sizeof(value_data),
			.value_type = REG_BINARY,
			.query_all = true,
			.include_blanket = true,
			.blanket_layer_name = "base",
		},
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.expect_root_value_delete = true,
		.delete_value = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "RootValue",
			.expected_layer_name = "base",
			.status = RSI_OK,
		},
		.expect_root_blanket_delete = true,
		.blanket_tombstone = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_layer_name = "base",
			.status = RSI_OK,
			.expected_set = false,
			.expected_sequence = 0,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-root-values");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 8U);
	KUNIT_EXPECT_EQ(test, script.writes, 8U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_root_section_replays(struct kunit *test)
{
	static const u8 restored_data[] = { 0x2a };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record records[] = {
		{
			.record_type = REG_BACKUP_PATH_ENTRY,
			.layer_name = "base",
			.child_name = "Hidden",
			.hidden = true,
		},
		{
			.record_type = REG_BACKUP_VALUE,
			.layer_name = "base",
			.value_name = "Answer",
		},
		{
			.record_type = REG_BACKUP_BLANKET_TOMBSTONE,
			.layer_name = "base",
		},
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_root_hidden_path = true,
		.replay_root_hidden_path = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.expected_child_name = "Hidden",
			.expected_layer_name = "base",
			.expected_sequence = 101,
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
		.expect_replay_root_value = true,
		.replay_root_value = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "Answer",
			.expected_layer_name = "base",
			.expected_data = restored_data,
			.expected_data_len = sizeof(restored_data),
			.expected_value_type = REG_BINARY,
			.expected_sequence = 102,
			.expected_expected_sequence = 0,
			.status = RSI_OK,
		},
		.expect_replay_root_blanket = true,
		.replay_root_blanket = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_layer_name = "base",
			.expected_sequence = 103,
			.status = RSI_OK,
			.expected_set = true,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u64 sequence_after = 0;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, records, ARRAY_SIZE(records)),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-root-replay");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 9U);
	KUNIT_EXPECT_EQ(test, script.writes, 9U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_next_sequence_snapshot(
				     &sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, 104ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_non_root_key_replays(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x74, 0x01 };
	static const u8 restored_data[] = { 0x2a };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = child_guid,
		.child_name = "Child",
	};
	static const struct pkm_lcs_kunit_restore_data_record value = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.key_guid = child_guid,
		.value_name = "Answer",
	};
	static const struct pkm_lcs_kunit_restore_data_record blanket = {
		.record_type = REG_BACKUP_BLANKET_TOMBSTONE,
		.layer_name = "base",
		.key_guid = child_guid,
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_non_root_key = true,
		.expect_replay_non_root_path = true,
		.replay_non_root_create = {
			.parent_guid = pkm_lcs_kunit_restore_target_guid,
			.child_guid = child_guid,
			.child_name = "Child",
			.layer_name = "base",
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.expected_sequence = 101,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
		},
		.expect_replay_non_root_value = true,
		.replay_non_root_value = {
			.expected_guid = child_guid,
			.expected_value_name = "Answer",
			.expected_layer_name = "base",
			.expected_data = restored_data,
			.expected_data_len = sizeof(restored_data),
			.expected_value_type = REG_BINARY,
			.expected_sequence = 102,
			.expected_expected_sequence = 0,
			.status = RSI_OK,
		},
		.expect_replay_non_root_blanket = true,
		.replay_non_root_blanket = {
			.expected_guid = child_guid,
			.expected_layer_name = "base",
			.expected_sequence = 103,
			.status = RSI_OK,
			.expected_set = true,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u64 sequence_after = 0;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &value, 2),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &blanket, 3),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 8),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-nonroot");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 11U);
	KUNIT_EXPECT_EQ(test, script.writes, 11U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_next_sequence_snapshot(
				     &sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, 104ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_non_root_guid_collision_aborts(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x74, 0xe1 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = child_guid,
		.child_name = "Child",
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_non_root_key = true,
		.replay_non_root_create = {
			.parent_guid = pkm_lcs_kunit_restore_target_guid,
			.child_guid = child_guid,
			.child_name = "Child",
			.layer_name = "base",
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.expected_sequence = 101,
			.key_status = RSI_ALREADY_EXISTS,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u64 sequence_after = 0;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 6),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-guid-collision");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EEXIST);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 7U);
	KUNIT_EXPECT_EQ(test, script.writes, 7U);
	KUNIT_EXPECT_FALSE(test, script.saw_commit);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_after),
			0L);
	KUNIT_EXPECT_EQ(test, sequence_after, 100ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_generation_overflow_downs_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_GUID_BYTES] = { 1 };
	struct pkm_lcs_source_table_snapshot source_snapshot = { };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_set(
				1, root_guid, U64_MAX),
			0L);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-generation");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EIO);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	pkm_lcs_kunit_source_table_snapshot(&source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.down_count, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_overflow_reaches_descendant_watch(
	struct kunit *test)
{
	static const char * const restore_path[] = { "Machine", "Software" };
	static const char * const descendant_path[] = {
		"Machine", "Software", "Child"
	};
	static const u8 restore_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x52 },
	};
	static const u8 descendant_ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x52 },
		{ 0x53 },
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u8 event[8] = { };
	long descendant_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	descendant_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, descendant_path, descendant_ancestors,
		ARRAY_SIZE(descendant_ancestors));
	KUNIT_ASSERT_TRUE(test, descendant_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)descendant_fd,
						    &notify),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, restore_ancestors[0], &generation_before),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_publish_restore_commit_effects(
				1, restore_ancestors[1], restore_ancestors,
				restore_path, ARRAY_SIZE(restore_ancestors),
				&limits),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, restore_ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)descendant_fd, event,
						  sizeof(event), true),
			(ssize_t)sizeof(event));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)descendant_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_restore_commit_failure_no_effects(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x52 },
	};
	struct reg_restore_args args = { };
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.commit_status = RSI_STORAGE_ERROR,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u8 event[8] = { };
	long key_fd;
	long watch_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, ARRAY_SIZE(ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-commit-fail");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EIO);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_RESTORE_COMPLETE", "result_errno");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_readwrite_unsupported(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_TXN_NOT_SUPPORTED,
		.abort_status = RSI_OK,
	};
	struct task_struct *task;
	struct file file = { };
	u8 buffer[256];
	const void *token;
	const void *source_token;
	size_t written = 0;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	input_fd = pkm_lcs_kunit_external_fd(O_RDONLY);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-nosupport");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EOPNOTSUPP);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_RESTORE_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &kmes_snapshot),
			-ENOENT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_readwrite_begin_timeout_cleanup(
	struct kunit *test)
{
	struct pkm_lcs_source_response_result begin_response = { };
	struct pkm_lcs_source_response_result abort_response = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_kacs_boot_snapshot token_snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct reg_restore_args args = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[128];
	u8 buffer[256];
	struct file file = { };
	const void *source_token;
	const void *token;
	size_t response_len;
	size_t written = 0;
	const size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	long key_fd;
	u64 request_id;
	u64 transaction_id;
	int input_fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	input_fd = pkm_lcs_kunit_external_fd(O_RDONLY);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token((int)key_fd,
							       token, &args),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &token_snapshot));
	KUNIT_EXPECT_EQ(test,
			token_snapshot.privileges_used & KACS_SE_RESTORE_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &kmes_snapshot),
			-ENOENT);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64) +
				  sizeof(u32)));
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	transaction_id = get_unaligned_le64(request + payload_offset);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_NE(test, transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_WRITE);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_BEGIN_TRANSACTION,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&begin_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, begin_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, begin_response.request_id, request_id);
	KUNIT_EXPECT_EQ(test, begin_response.txn_id, transaction_id);
	KUNIT_EXPECT_EQ(test, begin_response.status, (u32)RSI_OK);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);

	memset(request, 0, sizeof(request));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(request + payload_offset),
			transaction_id);

	pkm_lcs_kunit_build_status_response(
		test, response, sizeof(response),
		get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET),
		RSI_ABORT_TRANSACTION, RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&abort_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, abort_response.txn_id, transaction_id);
	KUNIT_EXPECT_EQ(test, abort_response.request_op_code,
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, abort_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, abort_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, abort_response.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void
pkm_lcs_kunit_key_fd_restore_commit_timeout_late_success_effects(
	struct kunit *test)
{
	pkm_lcs_kunit_key_fd_restore_commit_timeout_late_response(
		test, RSI_OK, true);
}


static void
pkm_lcs_kunit_key_fd_restore_commit_timeout_late_error_no_effects(
	struct kunit *test)
{
	pkm_lcs_kunit_key_fd_restore_commit_timeout_late_response(
		test, RSI_STORAGE_ERROR, false);
}


static void pkm_lcs_kunit_key_fd_restore_stream_bad_magic(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input.data[6] ^= 0x01;
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_stream_min_reader_denied(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	put_unaligned_le32(22U, input.data + 6 + 8 + 4);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_stream_checksum_mismatch(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };
	u32 header_len;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	header_len = get_unaligned_le32(input.data + 2);
	KUNIT_ASSERT_LT(test, (size_t)header_len + 6, input.len);
	input.data[header_len + 6] ^= 0x01;
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_stream_after_trailer_denied(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_record_header(
				&input, 0x9002U, 6),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_stream_missing_root_key(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_root_keys(
				&input, true, 0, false, false),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_stream_duplicate_root_key(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_root_keys(
				&input, true, 2, false, false),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_root_key_retains_mutable(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_stream_summary summary = { };
	struct pkm_lcs_kunit_restore_input_file input = { };
	u8 root_sd[sizeof(pkm_lcs_kunit_owner_only_sd)];
	int input_fd;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_restore_validate_stream_summary(
				input_fd, pkm_lcs_kunit_restore_target_guid,
				&summary, root_sd, sizeof(root_sd)),
			0L);
	KUNIT_EXPECT_EQ(test, summary.root_key_seen, 1);
	KUNIT_EXPECT_EQ(test, summary.root_volatile, 0);
	KUNIT_EXPECT_EQ(test, summary.root_symlink, 0);
	KUNIT_EXPECT_EQ(test, summary.root_sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_EXPECT_EQ(test, summary.root_last_write_time_ns, (s64)5678);
	KUNIT_EXPECT_EQ(test,
			memcmp(root_sd, pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
}


static void pkm_lcs_kunit_key_fd_restore_root_key_sd_short_buffer(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_stream_summary summary = { };
	struct pkm_lcs_kunit_restore_input_file input = { };
	u8 root_sd[sizeof(pkm_lcs_kunit_owner_only_sd) - 1];
	int input_fd;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	memset(root_sd, 0xaa, sizeof(root_sd));
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_restore_validate_stream_summary(
				input_fd, pkm_lcs_kunit_restore_target_guid,
				&summary, root_sd, sizeof(root_sd)),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, summary.root_key_seen, 1);
	KUNIT_EXPECT_EQ(test, summary.root_sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_EXPECT_EQ(test, root_sd[0], 0xaa);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
}


static void pkm_lcs_kunit_key_fd_restore_stream_root_flags_conflict(
	struct kunit *test)
{
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_root_keys(
				&input, true, 1, true, false),
			0);
	pkm_lcs_kunit_expect_restore_root_flag_result(
		test, &input, (long)-EINVAL, false, false);
}


static void pkm_lcs_kunit_key_fd_restore_layer_duplicate_manifest(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layers[] = {
		{ .name = "Policy", .precedence = 0, .enabled = 1,
		  .owner_sid = pkm_lcs_kunit_everyone_sid,
		  .owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid) },
		{ .name = "policy", .precedence = 0, .enabled = 1,
		  .owner_sid = pkm_lcs_kunit_everyone_sid,
		  .owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid) },
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_layers(
				&input, layers, ARRAY_SIZE(layers), false),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_layer_after_key_denied(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "Policy",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_layers(
				&input, &layer, 1, true),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_layer_high_precedence_requires_tcb(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "Policy",
		.precedence = 42,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_layers(
				&input, &layer, 1, false),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EPERM);
}


static void pkm_lcs_kunit_key_fd_restore_layer_existing_high_requires_tcb(
	struct kunit *test)
{
	static const u8 metadata_guid[PKM_LCS_GUID_BYTES] = { 0x71 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "policy",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 7, 1,
				metadata_guid, pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_everyone_sid,
				sizeof(pkm_lcs_kunit_everyone_sid)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_layers(
				&input, &layer, 1, false),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EPERM);
	pkm_lcs_kunit_reset_layer_table();
}


static void pkm_lcs_kunit_key_fd_restore_layer_tcb_marks_used(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "Policy",
		.precedence = 42,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	struct pkm_kacs_boot_snapshot after = { };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE,
		KACS_SE_RESTORE_PRIVILEGE | KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_layers(
				&input, &layer, 1, false),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-layer-tcb");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 6U);
	KUNIT_EXPECT_EQ(test, script.writes, 6U);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used &
				      KACS_SE_RESTORE_PRIVILEGE,
			KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			KACS_SE_TCB_PRIVILEGE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_metadata_precedence_requires_tcb(
	struct kunit *test)
{
	static const char * const path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 policy_guid[PKM_LCS_GUID_BYTES] = { 0x91 };
	static const u8 one_data[] = { 1, 0, 0, 0 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = policy_guid,
		.child_name = "Policy",
	};
	static const struct pkm_lcs_kunit_restore_data_record value = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.key_guid = policy_guid,
		.value_name = "Precedence",
		.value_data = one_data,
		.value_data_len = sizeof(one_data),
		.value_type = REG_DWORD,
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Layers",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_non_root_key = true,
		.expect_replay_non_root_path = true,
		.replay_non_root_create = {
			.parent_guid = pkm_lcs_kunit_restore_target_guid,
			.child_guid = policy_guid,
			.child_name = "Policy",
			.layer_name = "base",
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.expected_sequence = 101,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u8 ancestors[4][PKM_LCS_GUID_BYTES];
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_restore_precedence_publish_layers_root(
		test, path, ancestors);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, policy_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &value, 2),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 7),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-precedence-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			(long)-EPERM);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	KUNIT_EXPECT_FALSE(test, script.saw_commit);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_metadata_precedence_tcb_allows(
	struct kunit *test)
{
	static const char * const path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 policy_guid[PKM_LCS_GUID_BYTES] = { 0x92 };
	static const u8 one_data[] = { 1, 0, 0, 0 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = policy_guid,
		.child_name = "Policy",
	};
	static const struct pkm_lcs_kunit_restore_data_record value = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.key_guid = policy_guid,
		.value_name = "Precedence",
		.value_data = one_data,
		.value_data_len = sizeof(one_data),
		.value_type = REG_DWORD,
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Layers",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_non_root_key = true,
		.expect_replay_non_root_path = true,
		.replay_non_root_create = {
			.parent_guid = pkm_lcs_kunit_restore_target_guid,
			.child_guid = policy_guid,
			.child_name = "Policy",
			.layer_name = "base",
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.expected_sequence = 101,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
		},
		.expect_replay_non_root_value = true,
		.replay_non_root_value = {
			.expected_guid = policy_guid,
			.expected_value_name = "Precedence",
			.expected_layer_name = "base",
			.expected_data = one_data,
			.expected_data_len = sizeof(one_data),
			.expected_value_type = REG_DWORD,
			.expected_sequence = 102,
			.expected_expected_sequence = 0,
			.status = RSI_OK,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u8 ancestors[4][PKM_LCS_GUID_BYTES];
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE,
		KACS_SE_RESTORE_PRIVILEGE | KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_restore_precedence_publish_layers_root(
		test, path, ancestors);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, policy_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &value, 2),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 7),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-precedence-allow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_metadata_precedence_zero_allows(
	struct kunit *test)
{
	static const char * const path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 policy_guid[PKM_LCS_GUID_BYTES] = { 0x93 };
	static const u8 zero_data[] = { 0, 0, 0, 0 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = policy_guid,
		.child_name = "Policy",
	};
	static const struct pkm_lcs_kunit_restore_data_record value = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.key_guid = policy_guid,
		.value_name = "Precedence",
		.value_data = zero_data,
		.value_data_len = sizeof(zero_data),
		.value_type = REG_DWORD,
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Layers",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_non_root_key = true,
		.expect_replay_non_root_path = true,
		.replay_non_root_create = {
			.parent_guid = pkm_lcs_kunit_restore_target_guid,
			.child_guid = policy_guid,
			.child_name = "Policy",
			.layer_name = "base",
			.sd = pkm_lcs_kunit_owner_only_sd,
			.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
			.expected_sequence = 101,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
		},
		.expect_replay_non_root_value = true,
		.replay_non_root_value = {
			.expected_guid = policy_guid,
			.expected_value_name = "Precedence",
			.expected_layer_name = "base",
			.expected_data = zero_data,
			.expected_data_len = sizeof(zero_data),
			.expected_value_type = REG_DWORD,
			.expected_sequence = 102,
			.expected_expected_sequence = 0,
			.status = RSI_OK,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	u8 ancestors[4][PKM_LCS_GUID_BYTES];
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_restore_precedence_publish_layers_root(
		test, path, ancestors);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, policy_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &value, 2),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 7),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-precedence-zero");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_precedence_non_metadata_allows(
	struct kunit *test)
{
	static const u8 one_data[] = { 1, 0, 0, 0 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record value = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.value_name = "Precedence",
		.value_data = one_data,
		.value_data_len = sizeof(one_data),
		.value_type = REG_DWORD,
	};
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
		.expect_replay_root_value = true,
		.replay_root_value = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "Precedence",
			.expected_layer_name = "base",
			.expected_data = one_data,
			.expected_data_len = sizeof(one_data),
			.expected_value_type = REG_DWORD,
			.expected_sequence = 101,
			.expected_expected_sequence = 0,
			.status = RSI_OK,
		},
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	pkm_lcs_kunit_set_sequence_state(true, 100);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, &value, 1),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-precedence-ordinary");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_restore_data_records_accept_manifest(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record records[] = {
		{ .record_type = REG_BACKUP_PATH_ENTRY, .layer_name = "base",
		  .child_guid = pkm_lcs_kunit_restore_header_root_guid },
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, records,
				ARRAY_SIZE(records)),
			0);
	pkm_lcs_kunit_expect_restore_root_flag_result(
		test, &input, 0L, false, false);
}


static void pkm_lcs_kunit_key_fd_restore_data_records_require_manifest(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_data_record records[] = {
		{ .record_type = REG_BACKUP_PATH_ENTRY, .layer_name = "base",
		  .hidden = true },
		{ .record_type = REG_BACKUP_VALUE, .layer_name = "base" },
		{ .record_type = REG_BACKUP_BLANKET_TOMBSTONE,
		  .layer_name = "base" },
	};
	u32 i;

	for (i = 0; i < ARRAY_SIZE(records); i++) {
		struct pkm_lcs_kunit_restore_input_file input = { };

		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_restore_stream_build_with_data_records(
					&input, NULL, 0, &records[i], 1),
				0);
		pkm_lcs_kunit_expect_restore_stream_result(test, &input,
							   (long)-EINVAL);
	}
}


static void pkm_lcs_kunit_key_fd_restore_data_before_key_denied(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record record = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.before_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, &record, 1),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_data_path_after_value_denied(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record records[] = {
		{ .record_type = REG_BACKUP_VALUE, .layer_name = "base" },
		{ .record_type = REG_BACKUP_PATH_ENTRY, .layer_name = "base" },
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, records,
				ARRAY_SIZE(records)),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_data_value_after_blanket_denied(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record records[] = {
		{ .record_type = REG_BACKUP_BLANKET_TOMBSTONE,
		  .layer_name = "base" },
		{ .record_type = REG_BACKUP_VALUE, .layer_name = "base" },
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, records,
				ARRAY_SIZE(records)),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_topology_first_key_must_be_root(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 3),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_topology_duplicate_non_root_guid(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &anchor, 2),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 7),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_topology_non_root_requires_anchor(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 4),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_topology_non_root_anchor_target(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	static const u8 other_guid[PKM_LCS_GUID_BYTES] = { 0x65 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record wrong_anchor = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = other_guid,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &wrong_anchor, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 5),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_topology_parent_must_precede_child(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	static const u8 outside_parent_guid[PKM_LCS_GUID_BYTES] = { 0x66 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record bad_parent = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.parent_guid = outside_parent_guid,
		.child_guid = child_guid,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, child_guid, false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &bad_parent, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 5),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_topology_value_scoped_to_section(
	struct kunit *test)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x64 };
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record bad_value = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
		.key_guid = child_guid,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_restore_stream_append_header(&input),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_layer_record(
				&input, &layer),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_key_record(
				&input, pkm_lcs_kunit_restore_header_root_guid,
				false, false),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_data_record(
				&input, &bad_value, 1),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_append_trailer(&input, 5),
			0);
	pkm_lcs_kunit_expect_restore_stream_result(test, &input,
						   (long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_restore_sequence_root_replay_advances(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record record = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.hidden = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	u64 sequence_after = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, &record, 1),
			0);
	pkm_lcs_kunit_expect_restore_root_flag_result_with_sequence(
		test, &input, 0L, false, false, true, 100,
		true, &sequence_after);
	KUNIT_EXPECT_EQ(test, sequence_after, 102ULL);
}


static void pkm_lcs_kunit_key_fd_restore_sequence_overflow_denied(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record record = {
		.record_type = REG_BACKUP_VALUE,
		.layer_name = "base",
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	u64 sequence_after = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, &record, 1),
			0);
	pkm_lcs_kunit_expect_restore_root_flag_result_with_sequence(
		test, &input, (long)-EOVERFLOW, false, false, true, U64_MAX,
		false, &sequence_after);
	KUNIT_EXPECT_EQ(test, sequence_after, U64_MAX);
}


static void pkm_lcs_kunit_key_fd_restore_sequence_skipped_root_path(
	struct kunit *test)
{
	static const struct pkm_lcs_kunit_restore_layer_record layer = {
		.name = "base",
		.precedence = 0,
		.enabled = 1,
		.owner_sid = pkm_lcs_kunit_everyone_sid,
		.owner_sid_len = sizeof(pkm_lcs_kunit_everyone_sid),
	};
	static const struct pkm_lcs_kunit_restore_data_record record = {
		.record_type = REG_BACKUP_PATH_ENTRY,
		.layer_name = "base",
		.child_guid = pkm_lcs_kunit_restore_header_root_guid,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	u64 sequence_after = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_with_data_records(
				&input, &layer, 1, &record, 1),
			0);
	pkm_lcs_kunit_expect_restore_root_flag_result_with_sequence(
		test, &input, 0L, false, false, true, U64_MAX,
		false, &sequence_after);
	KUNIT_EXPECT_EQ(test, sequence_after, U64_MAX);
}


static void pkm_lcs_kunit_key_fd_backup_restore_fail_before_stream(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct reg_backup_args backup_args = { .output_fd = -1 };
	struct reg_restore_args restore_args = { .input_fd = -1 };
	const void *backup_token;
	const void *restore_token;
	const void *plain_token;
	long key_fd;
	int read_fd;
	int write_fd;

	plain_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, 0);
	KUNIT_ASSERT_NOT_NULL(test, plain_token);
	backup_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_BACKUP_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, backup_token);
	restore_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, restore_token);
	key_fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	read_fd = pkm_lcs_kunit_external_fd(O_RDONLY);
	KUNIT_ASSERT_TRUE(test, read_fd >= 0);
	write_fd = pkm_lcs_kunit_external_fd(O_WRONLY);
	KUNIT_ASSERT_TRUE(test, write_fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, plain_token, &backup_args),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, plain_token, &restore_args),
			(long)-EPERM);

	backup_args.output_fd = read_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, backup_token, &backup_args),
			(long)-EBADF);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(backup_token,
							 &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_BACKUP_PRIVILEGE,
			0ULL);

	restore_args.input_fd = write_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, restore_token, &restore_args),
			(long)-EBADF);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(restore_token,
							 &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_RESTORE_PRIVILEGE,
			0ULL);

	backup_args.output_fd = write_fd;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)key_fd, true),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_backup_for_token(
				(int)key_fd, backup_token, &backup_args),
			(long)-ENOENT);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(backup_token,
							 &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_BACKUP_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)read_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)write_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	kacs_rust_token_drop(plain_token);
	kacs_rust_token_drop(backup_token);
	kacs_rust_token_drop(restore_token);
}


static void pkm_lcs_kunit_key_fd_restore_restart_missing_guid_enoent(
	struct kunit *test)
{
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = pkm_lcs_kunit_restore_target_guid,
		.status = RSI_NOT_FOUND,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct pkm_kacs_boot_snapshot token_snapshot = { };
	struct reg_restore_args args = { };
	struct task_struct *task;
	struct file file = { };
	const void *source_token;
	const void *restore_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	key_fd = pkm_lcs_kunit_publish_restarted_missing_backup_restore_fd(
		&file, &source_token);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	restore_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, restore_token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &script,
		"pkm-lcs-kunit-restore-reval-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, restore_token, &args),
			(long)-ENOENT);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)key_fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, key_snapshot.orphaned);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(restore_token,
							 &token_snapshot));
	KUNIT_EXPECT_EQ(test, token_snapshot.privileges_used &
				      KACS_SE_RESTORE_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(restore_token);
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_notify_arm_replace_disarm(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
		.subtree = 0,
	};
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.watch_armed);
	KUNIT_EXPECT_FALSE(test, snapshot.watch_subtree);
	KUNIT_EXPECT_EQ(test, snapshot.watch_filter, REG_NOTIFY_VALUE);

	args.filter = REG_NOTIFY_SUBKEY | REG_NOTIFY_SD;
	args.subtree = 1;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.watch_armed);
	KUNIT_EXPECT_TRUE(test, snapshot.watch_subtree);
	KUNIT_EXPECT_EQ(test, snapshot.watch_filter,
			REG_NOTIFY_SUBKEY | REG_NOTIFY_SD);

	args.filter = 0;
	args.subtree = 0;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.watch_armed);
	KUNIT_EXPECT_FALSE(test, snapshot.watch_subtree);
	KUNIT_EXPECT_EQ(test, snapshot.watch_filter, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_notify_fails_closed(struct kunit *test)
{
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	args.filter = REG_NOTIFY_VALUE | 0x80U;
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			(long)-EINVAL);
	args.filter = REG_NOTIFY_VALUE;
	args.subtree = 2;
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			(long)-EINVAL);
	args.subtree = 0;
	args._pad[1] = 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			(long)-EINVAL);
	args._pad[1] = 0;

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			(long)-ENOENT);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.watch_armed);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);
	args.filter = REG_NOTIFY_SD;
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.watch_armed);
	KUNIT_EXPECT_EQ(test, snapshot.watch_filter, REG_NOTIFY_SD);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_notify_restart_missing_guid_enoent(
	struct kunit *test)
{
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = pkm_lcs_kunit_restore_target_guid,
		.status = RSI_NOT_FOUND,
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct task_struct *task;
	struct file file = { };
	const void *source_token;
	long key_fd;
	int thread_ret;

	key_fd = pkm_lcs_kunit_publish_restarted_missing_key_fd(
		&file, &source_token, KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	KUNIT_ASSERT_NOT_NULL(test, source_token);

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &script,
		"pkm-lcs-kunit-notify-reval-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)key_fd, &args),
			(long)-ENOENT);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)key_fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, key_snapshot.orphaned);
	KUNIT_EXPECT_FALSE(test, key_snapshot.watch_armed);
	KUNIT_EXPECT_EQ(test, key_snapshot.watch_filter, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(source_token);
}


static void pkm_lcs_kunit_key_fd_orphan_last_close_sends_drop(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x91 },
		{ 0x92 },
	};
	struct file file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(1, KEY_QUERY_VALUE, path,
						    ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[1]);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_orphan_nonfinal_close_defers_drop(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x93 },
		{ 0x94 },
	};
	u8 request[128];
	struct file file = { };
	const void *token;
	long fd1;
	long fd2;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd1 = pkm_lcs_kunit_publish_key_fd_from_path(1, KEY_QUERY_VALUE, path,
						     ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd1 >= 0);
	fd2 = pkm_lcs_kunit_publish_key_fd_from_path(1, KEY_QUERY_VALUE, path,
						     ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd2 >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)fd1, true),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd1), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd2), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[1]);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_orphan_close_down_source_no_error(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x95 },
		{ 0x96 },
	};
	struct file file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(1, KEY_QUERY_VALUE, path,
						    ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_key_fd_orphan_transition_marks_and_notifies(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0xa1 },
		{ 0xa2 },
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	u8 record[16] = { };
	u32 marked = U32_MAX;
	long fd1;
	long fd2;
	long fd_other_source;

	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd1 = pkm_lcs_kunit_publish_key_fd_from_path(31, KEY_NOTIFY, path,
						     ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd1 >= 0);
	fd2 = pkm_lcs_kunit_publish_key_fd_from_path(31, KEY_NOTIFY, path,
						     ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd2 >= 0);
	fd_other_source = pkm_lcs_kunit_publish_key_fd_from_path(
		32, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd_other_source >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd1, &args),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
				31, ancestors[1], &marked),
			0L);
	KUNIT_EXPECT_EQ(test, marked, 2U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd1, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd2, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd_other_source,
						&snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd1, record,
							sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd2, &args),
			(long)-ENOENT);

	marked = U32_MAX;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
				31, ancestors[1], &marked),
			0L);
	KUNIT_EXPECT_EQ(test, marked, 0U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd1, record,
							sizeof(record), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd1), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd2), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd_other_source), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}


static void pkm_lcs_kunit_key_fd_orphan_transition_no_live_refs_noops(
	struct kunit *test)
{
	static const u8 guid[PKM_LCS_GUID_BYTES] = { 0xb1 };
	static const u8 nil_guid[PKM_LCS_GUID_BYTES] = { };
	u32 marked = U32_MAX;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
				44, guid, &marked),
			0L);
	KUNIT_EXPECT_EQ(test, marked, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
				44, nil_guid, &marked),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_watch_read_poll_drains_records(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	u8 record[16] = { };
	u8 out[32] = { };
	u32 record_len;
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							sizeof(out), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd), 0U);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	record_len = pkm_lcs_kunit_write_direct_watch_event(
		record, sizeof(record), REG_WATCH_VALUE_SET, "abc");
	KUNIT_ASSERT_EQ(test, record_len, 11U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_queue_watch_event(
				(int)fd, REG_WATCH_VALUE_SET, record,
				record_len),
			0L);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd),
			(u32)EPOLLIN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out, 8, true),
			(ssize_t)-EINVAL);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd),
			(u32)EPOLLIN);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, NULL,
							sizeof(out), true),
			(ssize_t)-EFAULT);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd),
			(u32)EPOLLIN);

	memset(out, 0, sizeof(out));
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							sizeof(out), true),
			(ssize_t)record_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, record, record_len), 0);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd), 0U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							sizeof(out), true),
			(ssize_t)-EAGAIN);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.watch_pending_events, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_watch_filter_disarm_and_overflow(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	const size_t out_len = PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT * 8U;
	u8 record[8] = { };
	u8 *out;
	u32 record_len;
	u32 last_type;
	long fd;
	u32 i;

	out = kunit_kzalloc(test, out_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);

	record_len = pkm_lcs_kunit_write_direct_watch_event(
		record, sizeof(record), REG_WATCH_SD_CHANGED, NULL);
	KUNIT_ASSERT_EQ(test, record_len, 8U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_queue_watch_event(
				(int)fd, REG_WATCH_SD_CHANGED, record,
				record_len),
			0L);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd), 0U);

	record_len = pkm_lcs_kunit_write_direct_watch_event(
		record, sizeof(record), REG_WATCH_KEY_DELETED, NULL);
	KUNIT_ASSERT_EQ(test, record_len, 8U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_queue_watch_event(
				(int)fd, REG_WATCH_KEY_DELETED, record,
				record_len),
			0L);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd),
			(u32)EPOLLIN);

	args.filter = 0;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_EXPECT_EQ(test, (u32)pkm_lcs_kunit_key_fd_poll((int)fd), 0U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							out_len, true),
			(ssize_t)-EAGAIN);

	args.filter = REG_NOTIFY_VALUE;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	record_len = pkm_lcs_kunit_write_direct_watch_event(
		record, sizeof(record), REG_WATCH_VALUE_SET, NULL);
	KUNIT_ASSERT_EQ(test, record_len, 8U);
	for (i = 0; i < PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT + 1U; i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_key_fd_queue_watch_event(
					(int)fd, REG_WATCH_VALUE_SET, record,
					record_len),
				0L);
	}

	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.watch_pending_events,
			PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							out_len, true),
			(ssize_t)out_len);
	last_type = get_unaligned_le16(out + out_len - 4U);
	KUNIT_EXPECT_EQ(test, last_type, REG_WATCH_OVERFLOW);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_key_fd_watch_runtime_queue_limit(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	const size_t low_out_len = 16U * 8U;
	const size_t high_out_len =
		(PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT + 1U) * 8U;
	u8 record[8] = { };
	u8 *out;
	u32 record_len;
	u32 last_type;
	long fd;
	u32 i;

	out = kunit_kzalloc(test, high_out_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.notification_queue_size = 16U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);

	record_len = pkm_lcs_kunit_write_direct_watch_event(
		record, sizeof(record), REG_WATCH_VALUE_SET, NULL);
	KUNIT_ASSERT_EQ(test, record_len, 8U);
	for (i = 0; i < 17U; i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_key_fd_queue_watch_event(
					(int)fd, REG_WATCH_VALUE_SET, record,
					record_len),
				0L);
	}

	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.watch_pending_events, 16U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							low_out_len, true),
			(ssize_t)low_out_len);
	last_type = get_unaligned_le16(out + low_out_len - 4U);
	KUNIT_EXPECT_EQ(test, last_type, REG_WATCH_OVERFLOW);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.notification_queue_size =
		PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT + 44U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);

	for (i = 0; i < PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT + 1U; i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_key_fd_queue_watch_event(
					(int)fd, REG_WATCH_VALUE_SET, record,
					record_len),
				0L);
	}
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.watch_pending_events,
			PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT + 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, out,
							high_out_len, true),
			(ssize_t)high_out_len);
	last_type = get_unaligned_le16(out + high_out_len - 4U);
	KUNIT_EXPECT_EQ(test, last_type, REG_WATCH_VALUE_SET);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_key_fd_watch_runtime_subtree_depth(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const child_path[] = { "Machine", "Parent", "Child" };
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 0xa1 },
		{ 0xa2 },
		{ 0xa3 },
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_SD,
		.subtree = 1,
	};
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[2],
		.ancestor_guids = ancestors,
		.resolved_path = child_path,
		.path_component_count = 3,
		.event_type = REG_WATCH_SD_CHANGED,
	};
	u8 record[32] = { };
	long root_fd;
	long parent_fd;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_subtree_watch_depth = 1U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		25, KEY_NOTIFY, root_path, ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		25, KEY_NOTIFY, parent_path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)root_fd,
							  &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)parent_fd,
							  &args),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)root_fd, record,
							sizeof(record), true),
			(ssize_t)-EAGAIN);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, record,
						  sizeof(record), true),
			(ssize_t)17);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 8), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 10), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(record + 12, "Child", 5), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_key_fd_watch_context_retains_queue_limit(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "RetainedQueue" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0xb1 },
		{ 0xb2 },
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits retained = { };
	struct pkm_lcs_runtime_limits live = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[1],
		.ancestor_guids = ancestors,
		.resolved_path = path,
		.limits = &retained,
		.path_component_count = 2,
		.event_type = REG_WATCH_SD_CHANGED,
	};
	long fd;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&retained), 0L);
	retained.notification_queue_size = 20U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&retained), 0L);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		26, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&live), 0L);
	live.notification_queue_size = 16U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&live), 0L);

	for (i = 0; i < 17U; i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_key_fd_dispatch_watch_event_context(
					&context),
				0L);
	}
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.watch_pending_events, 17U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_key_fd_watch_context_retains_subtree_depth(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const child_path[] = { "Machine", "Parent", "Child" };
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 0xc1 },
		{ 0xc2 },
		{ 0xc3 },
	};
	struct pkm_lcs_runtime_limits retained = { };
	struct pkm_lcs_runtime_limits live = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_SD,
		.subtree = 1,
	};
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = ancestors[2],
		.ancestor_guids = ancestors,
		.resolved_path = child_path,
		.limits = &retained,
		.path_component_count = 3,
		.event_type = REG_WATCH_SD_CHANGED,
	};
	u8 record[32] = { };
	long root_fd;
	ssize_t read_len;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&retained), 0L);
	retained.max_subtree_watch_depth = 0U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&retained), 0L);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		27, KEY_NOTIFY, root_path, ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)root_fd,
							  &args),
			0L);

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&live), 0L);
	live.max_subtree_watch_depth = 1U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&live), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);
	read_len = pkm_lcs_kunit_key_fd_read((int)root_fd, record,
					    sizeof(record), true);
	KUNIT_ASSERT_TRUE(test, read_len > 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 8), 2U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_key_fd_watch_registry_arm_replace_disarm(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_watch_registry_snapshot registry = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
	};
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 0U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 0U);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 1U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 0U);

	args.filter = REG_NOTIFY_SUBKEY;
	args.subtree = 1;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 1U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 1U);

	args.filter = REG_NOTIFY_SD;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 1U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 1U);

	args.filter = REG_NOTIFY_VALUE;
	args.subtree = 0;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 1U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 0U);

	args.filter = 0;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 0U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}


static void pkm_lcs_kunit_key_fd_watch_registry_refcounts_close(
	struct kunit *test)
{
	struct pkm_lcs_key_fd_watch_registry_snapshot registry = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_VALUE,
		.subtree = 1,
	};
	long fd1;
	long fd2;

	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd1 = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd1 >= 0);
	fd2 = pkm_lcs_kunit_publish_key_fd_with_access(KEY_NOTIFY);
	KUNIT_ASSERT_TRUE(test, fd2 >= 0);

	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd1, &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd2, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd1, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 2U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 2U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd2), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd1, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 1U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 1U);

	args.filter = 0;
	args.subtree = 0;
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd1, &args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_watch_registry_snapshot(
				(int)fd1, &registry),
			0L);
	KUNIT_EXPECT_EQ(test, registry.direct_watchers, 0U);
	KUNIT_EXPECT_EQ(test, registry.subtree_watchers, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd1), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}


static void pkm_lcs_kunit_key_fd_live_dispatch_direct_and_subtree(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software", "App" };
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 0x61 },
		{ 0x62 },
		{ 0x63 },
	};
	static const u8 setting[] = "Setting";
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_VALUE,
		.subtree = 1,
	};
	struct pkm_lcs_watch_dispatch_input dispatch = {
		.event_type = REG_WATCH_VALUE_SET,
		.name = setting,
		.name_len = sizeof(setting) - 1U,
	};
	u8 direct[32] = { };
	u8 subtree[64] = { };
	long direct_fd;
	long subtree_fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();

	subtree_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		21, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, subtree_fd >= 0);
	direct_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		21, KEY_NOTIFY, path, ancestors, 3);
	KUNIT_ASSERT_TRUE(test, direct_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)direct_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)subtree_fd,
						    &subtree_args),
			0L);

	dispatch.mutation_fd = (int)direct_fd;
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event(&dispatch),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)direct_fd, direct,
						  sizeof(direct), true),
			(ssize_t)15);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 15U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 7U);
	KUNIT_EXPECT_EQ(test, memcmp(direct + 8, setting, sizeof(setting) - 1U),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)subtree_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)22);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 22U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(subtree + 8, setting, sizeof(setting) - 1U),
			0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 15), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 17), 3U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 19, "App", 3), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)direct_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)subtree_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}


static void pkm_lcs_kunit_key_fd_live_dispatch_filter_bypass_and_zero_depth(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x71 },
		{ 0x72 },
	};
	static const u8 setting[] = "Setting";
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_SD,
		.subtree = 1,
	};
	struct pkm_lcs_watch_dispatch_input dispatch = {
		.name = setting,
		.name_len = sizeof(setting) - 1U,
	};
	u8 record[32] = { };
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		22, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);

	dispatch.mutation_fd = (int)fd;
	dispatch.event_type = REG_WATCH_VALUE_SET;
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event(&dispatch),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, record,
							sizeof(record), true),
			(ssize_t)-EAGAIN);

	dispatch.event_type = REG_WATCH_SD_CHANGED;
	dispatch.name = NULL;
	dispatch.name_len = 0;
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event(&dispatch),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, record,
							sizeof(record), true),
			(ssize_t)10);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 8), 0U);

	dispatch.event_type = REG_WATCH_KEY_DELETED;
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_dispatch_watch_event(&dispatch),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, record,
							sizeof(record), true),
			(ssize_t)10);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 8), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}


static void pkm_lcs_kunit_key_fd_live_dispatch_context_subkey_created(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const malformed_path[] = { "Machine", NULL };
	static const u8 root_ancestors[1][PKM_LCS_GUID_BYTES] = { { 0x81 } };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x81 },
		{ 0x82 },
	};
	static const u8 child[] = "Child";
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_watch_dispatch_context context = {
		.changed_key_guid = parent_ancestors[1],
		.ancestor_guids = parent_ancestors,
		.resolved_path = parent_path,
		.path_component_count = 2,
		.event_type = REG_WATCH_SUBKEY_CREATED,
		.name = child,
		.name_len = sizeof(child) - 1U,
	};
	struct pkm_lcs_watch_dispatch_context bad_context;
	u8 direct[32] = { };
	u8 subtree[64] = { };
	long root_fd;
	long parent_fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		23, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		23, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	bad_context = context;
	bad_context.changed_key_guid = root_ancestors[0];
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(
				&bad_context),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)-EAGAIN);

	bad_context = context;
	bad_context.resolved_path = malformed_path;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(
				&bad_context),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)-EAGAIN);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context(&context),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)13);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 13U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 5U);
	KUNIT_EXPECT_EQ(test, memcmp(direct + 8, child, sizeof(child) - 1U),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)23);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 23U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 5U);
	KUNIT_EXPECT_EQ(test,
			memcmp(subtree + 8, child, sizeof(child) - 1U), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 13), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 15), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 17, "Parent", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}


static void pkm_lcs_kunit_key_guid_assignment_fresh_succeeds(
	struct kunit *test)
{
	static const u8 candidates[1][16] = { { 0x40 } };
	static const u8 active[2][16] = { { 0x41 }, { 0x42 } };
	struct pkm_lcs_key_guid_assignment_plan plan = { };
	struct pkm_lcs_kunit_guid_sequence sequence = {
		.guids = candidates,
		.count = ARRAY_SIZE(candidates),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				active, ARRAY_SIZE(active), &generator, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(plan.guid, candidates[0], 16), 0);
	KUNIT_EXPECT_EQ(test, plan.assigned_by_lcs, 1U);
	KUNIT_EXPECT_EQ(test, plan.persist_in_key_record, 1U);
}


static void pkm_lcs_kunit_key_guid_assignment_retries_bad_candidates(
	struct kunit *test)
{
	static const u8 nil_then_fresh[2][16] = { { 0 }, { 0x61 } };
	static const u8 active_then_fresh[2][16] = { { 0x71 }, { 0x72 } };
	static const u8 active[1][16] = { { 0x71 } };
	struct pkm_lcs_key_guid_assignment_plan plan = { };
	struct pkm_lcs_kunit_guid_sequence nil_sequence = {
		.guids = nil_then_fresh,
		.count = ARRAY_SIZE(nil_then_fresh),
	};
	struct pkm_lcs_kunit_guid_sequence active_sequence = {
		.guids = active_then_fresh,
		.count = ARRAY_SIZE(active_then_fresh),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&nil_sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 0, &generator,
						    &plan),
			0L);
	KUNIT_EXPECT_EQ(test, nil_sequence.calls, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(plan.guid, nil_then_fresh[1], 16),
			0);

	generator = pkm_lcs_kunit_guid_generator(&active_sequence);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				active, ARRAY_SIZE(active), &generator, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, active_sequence.calls, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(plan.guid, active_then_fresh[1], 16),
			0);
}


static void pkm_lcs_kunit_key_guid_assignment_exhaustion_fails_closed(
	struct kunit *test)
{
	static const u8 active[1][16] = { { 0x91 } };
	struct pkm_lcs_key_guid_assignment_plan plan = {
		.guid = { 0xff },
		.assigned_by_lcs = 1,
		.persist_in_key_record = 1,
	};
	struct pkm_lcs_kunit_guid_sequence sequence = {
		.guids = active,
		.count = ARRAY_SIZE(active),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				active, ARRAY_SIZE(active), &generator, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, sequence.calls,
			PKM_LCS_KEY_GUID_ASSIGNMENT_MAX_ATTEMPTS);
	KUNIT_EXPECT_EQ(test, plan.assigned_by_lcs, 0U);
	KUNIT_EXPECT_EQ(test, plan.persist_in_key_record, 0U);
	KUNIT_EXPECT_FALSE(test, memcmp(plan.guid, active[0], 16) == 0);
}


static void pkm_lcs_kunit_key_guid_assignment_bad_tracker_eio(
	struct kunit *test)
{
	static const u8 candidate[1][16] = { { 0x93 } };
	static const u8 bad_active[1][16] = { { 0 } };
	struct pkm_lcs_key_guid_assignment_plan plan = { };
	struct pkm_lcs_kunit_guid_sequence sequence = {
		.guids = candidate,
		.count = ARRAY_SIZE(candidate),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				bad_active, ARRAY_SIZE(bad_active), &generator,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, sequence.calls,
			PKM_LCS_KEY_GUID_ASSIGNMENT_MAX_ATTEMPTS);
	KUNIT_EXPECT_EQ(test, plan.assigned_by_lcs, 0U);
}


static void pkm_lcs_kunit_key_guid_assignment_bad_inputs(struct kunit *test)
{
	static const u8 candidate[1][16] = { { 0xa1 } };
	struct pkm_lcs_key_guid_assignment_plan plan = { };
	struct pkm_lcs_key_guid_generator bad_generator = { };
	struct pkm_lcs_kunit_guid_sequence sequence = {
		.guids = candidate,
		.count = ARRAY_SIZE(candidate),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 0, &generator,
						    NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 1, &generator,
						    &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 0, &bad_generator,
						    &plan),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_key_fd_query_value_uses_live_layer_table(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x41 },
	};
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0xd4 };
	static const char value_name[] = "Answer";
	static const u8 base_data[] = { 1 };
	static const u8 policy_data[] = { 9 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_query_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.data_len = 16,
		.layer_buf_len = 16,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.response_value_name = value_name,
		.layer_name = "base",
		.data = base_data,
		.data_len = sizeof(base_data),
		.value_type = REG_BINARY,
		.second_response_value_name = value_name,
		.second_layer_name = "policy",
		.second_data = policy_data,
		.second_data_len = sizeof(policy_data),
		.second_value_type = REG_BINARY,
		.include_second_value = true,
	};
	u8 data[16];
	u8 layer[16];
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 base_sequence;
	u64 policy_sequence;
	long fd;
	long ret;
	int thread_ret;

	memset(data, 0xaa, sizeof(data));
	memset(layer, 0xaa, sizeof(layer));
	args.data_ptr = (u64)(unsigned long)data;
	args.layer_ptr = (u64)(unsigned long)layer;

	pkm_lcs_kunit_reset_layer_table();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1, policy_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&base_sequence), 0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&policy_sequence), 0L);
	script.sequence = base_sequence;
	script.second_sequence = policy_sequence;
	script.file = &file;

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-query-value-live-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, args.type, (u32)REG_BINARY);
	KUNIT_EXPECT_EQ(test, args.data_len, (u32)sizeof(policy_data));
	KUNIT_EXPECT_EQ(test, args.sequence, policy_sequence);
	KUNIT_EXPECT_EQ(test, args.layer_len, 6U);
	KUNIT_EXPECT_EQ(test, memcmp(data, policy_data, sizeof(policy_data)), 0);
	KUNIT_EXPECT_EQ(test, data[sizeof(policy_data)], 0xaaU);
	KUNIT_EXPECT_EQ(test, memcmp(layer, "policy", 6), 0);
	KUNIT_EXPECT_EQ(test, layer[6], 0xaaU);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_set_value_layer_cap_uses_runtime_limit(
	struct kunit *test)
{
	static const char value_name[] = "Answer";
	static const char base_layer[] = "base";
	static const char overlay_layer[] = "overlay";
	static const u8 data[] = { 0x01 };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_value_layer_admission_result result = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_layers_per_value = 1U;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 470, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, value_name,
		base_layer, REG_BINARY, data, sizeof(data), 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_plan_set_value_layer_admission(
				response, response_len, 470, 1, value_name,
				strlen(value_name), overlay_layer,
				strlen(overlay_layer), &limits, &result),
			(long)-ENOSPC);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_plan_set_value_layer_admission(
				response, response_len, 470, 1, value_name,
				strlen(value_name), base_layer,
				strlen(base_layer), &limits, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.current_distinct_layers, 1U);
	KUNIT_EXPECT_EQ(test, result.replacing_existing_layer_entry, 1U);
}


static void pkm_lcs_kunit_delete_layer_orchestration_aborts_before_broadcast(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 layer_guid[RSI_GUID_SIZE] = { 0xc3 };
	struct pkm_lcs_delete_layer_orchestration_result result = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_kunit_delete_layer_source_script script = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long txn_fd;
	long ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 9, 1, layer_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_set_value_log_for_layer(test, (int)txn_fd,
						     root_guid, "Policy",
						     77);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_delete_layer_orchestrate_timeout(
				"base", strlen("base"), 1000, &result),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_BOUND);

	script.file = &file;
	script.expected_layer_name = "policy";
	script.expected_abort_txn_id = txn_snapshot.transaction_id;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-layer-orch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	memset(&result, 0, sizeof(result));
	ret = pkm_lcs_source_delete_layer_orchestrate_timeout(
		"policy", strlen("policy"), 1000, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.abort_before_delete_observed);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, result.inspected_transaction_count, 1U);
	KUNIT_EXPECT_EQ(test, result.affected_bound_transaction_count, 1U);
	KUNIT_EXPECT_EQ(test, result.abort_dispatched_count, 1U);
	KUNIT_EXPECT_EQ(test, result.layer_table_entry_removed, 1U);
	KUNIT_EXPECT_EQ(test, result.active_source_count, 1U);
	KUNIT_EXPECT_EQ(test, result.completed_source_count, 1U);
	KUNIT_EXPECT_EQ(test, result.orphaned_guid_count, 0U);
	KUNIT_EXPECT_EQ(test, result.marked_fd_count, 0U);
	KUNIT_EXPECT_EQ(test, result.immediate_drop_count, 0U);
	KUNIT_EXPECT_EQ(test, result.generation_hive_count, 1U);
	KUNIT_EXPECT_EQ(test, result.watch_overflow_count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)txn_fd, &status),
			0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ABORTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_delete_layer_orchestration_overflows_watches(
	struct kunit *test)
{
	static const char layer_name[] = "policy";
	static const u8 layer_guid[RSI_GUID_SIZE] = { 0xc4 };
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xc4, 0x01 },
	};
	struct pkm_lcs_delete_layer_orchestration_result result = { };
	struct pkm_lcs_kunit_delete_layer_source_script script = {
		.expected_layer_name = layer_name,
		.status = RSI_OK,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	u8 record[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"Policy", strlen("Policy"), 9, 1, layer_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, ARRAY_SIZE(ancestors));
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-layer-overflow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_orchestrate_timeout(
		layer_name, strlen(layer_name), 1000, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, result.layer_table_entry_removed, 1U);
	KUNIT_EXPECT_EQ(test, result.active_source_count, 1U);
	KUNIT_EXPECT_EQ(test, result.completed_source_count, 1U);
	KUNIT_EXPECT_EQ(test, result.generation_hive_count, 1U);
	KUNIT_EXPECT_EQ(test, result.watch_overflow_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)fd, record,
						  sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_sequence_allocation_advances_global_counter(
	struct kunit *test)
{
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct file file = { };
	const void *token;
	u64 first = 0;
	u64 second = 0;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 1ULL);

	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&first), 0L);
	KUNIT_EXPECT_EQ(test, first, 1ULL);
	KUNIT_ASSERT_EQ(test, pkm_lcs_allocate_sequence(&second), 0L);
	KUNIT_EXPECT_EQ(test, second, 2ULL);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 3ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_sequence_allocation_fails_closed(struct kunit *test)
{
	struct pkm_lcs_source_table_snapshot snapshot = { };
	u64 sequence = 1234;

	pkm_lcs_kunit_reset_source_table();

	KUNIT_EXPECT_EQ(test, pkm_lcs_allocate_sequence(NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_allocate_sequence(&sequence),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, sequence, 0ULL);

	pkm_lcs_kunit_set_sequence_state(true, U64_MAX);
	sequence = 1234;
	KUNIT_EXPECT_EQ(test, pkm_lcs_allocate_sequence(&sequence),
			(long)-EOVERFLOW);
	KUNIT_EXPECT_EQ(test, sequence, 0ULL);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, U64_MAX);

	pkm_lcs_kunit_reset_source_table();
}

static struct kunit_case pkm_lcs_kunit_key_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_hive_route_reflects_active_and_down_slots),
	KUNIT_CASE(pkm_lcs_kunit_hive_route_private_scope_shadows_global),
	KUNIT_CASE(pkm_lcs_kunit_key_open_access_bridge_allows_registry_rights),
	KUNIT_CASE(pkm_lcs_kunit_key_open_access_bridge_denies_partial_grants),
	KUNIT_CASE(pkm_lcs_kunit_key_open_access_bridge_maximum_allowed),
	KUNIT_CASE(pkm_lcs_kunit_key_open_access_bridge_malformed_sd_eio),
	KUNIT_CASE(pkm_lcs_kunit_key_open_audit_not_required_no_event),
	KUNIT_CASE(pkm_lcs_kunit_key_open_audit_emits_lcs_kmes_event),
	KUNIT_CASE(pkm_lcs_kunit_key_open_audit_payload_abi_rejects_bad_state),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_publish_snapshot_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_publish_deep_copies_input),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_publish_rejects_malformed_state),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_snapshot_rejects_non_key_fd),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_fixed_ioctl_access_gates),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_fixed_ioctl_access_matrix),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_security_ioctl_access_gates),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_security_ioctl_access_matrix),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_raw_ioctl_null_args_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_raw_ioctl_copyin_fault_matrix),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_raw_ioctl_rejects_bad_fds),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_raw_ioctl_flush_no_arg_access_gate),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_erange_probe),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_malformed_source_sd),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_value_reads_resolve_policy_layer),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_erange_all_or_none),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_blanket_enoent),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_transaction_context),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_malformed_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_empty_effective_set),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_erange_all_or_none),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_transaction_context),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_values_batch_malformed_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_erange_all_or_none),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_index_past_end),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_transaction_context),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_value_malformed_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_resolves_policy_layer),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_policy_hidden_masks_base),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_erange_all_or_none),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_index_past_end),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_transaction_context),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_read_ioctls_terminal_txns_fail_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_malformed_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_resolves_policy_layers),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_retains_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_erange_probe),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_malformed_enum),
	KUNIT_CASE(pkm_lcs_kunit_set_security_merge_bridge_preserves_components),
	KUNIT_CASE(pkm_lcs_kunit_set_security_merge_bridge_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_security_nontransactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_cached_grant_survives_sd_change),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_security_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_security_transactional_abort_no_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_security_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_nontransactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_cas_failure_no_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_runtime_limits_fail_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_runtime_limits_source_frames),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_precedence_tcb_gate),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_layer_precedence_overflows_watches),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_nontransactional_deletes_effective),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_transactional_idempotent_no_event),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_idempotent_no_value_event),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_runtime_limits_source_frames),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_set_deletes_effective_values),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_policy_layer_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_value_policy_reveals_base),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_policy_masks_base),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_remove_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_set_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_source_error_no_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_blanket_tombstone_transactional_source_error),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_nontransactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_runtime_limits_source_frame),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_dispatches_visibility_watches),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_lower_layer_no_visibility_watch),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_transactional_source_failure),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_nontransactional_success),
	KUNIT_CASE(pkm_lcs_kunit_delete_layer_metadata_key_orchestrates),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_orphans_missing_guid),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_dispatches_visibility_watches),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_replacement_dispatches_create),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_visible_child_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_visible_policy_child_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_runtime_limits_source_frame),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_transactional_source_failure),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_hide_key_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_delete_key_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_flush_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_flush_orphaned_guid_local_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_flush_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_ioctl_access_rejects_bad_fds),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_admission),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_cycle_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_root_records_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_root_payloads),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_leaf_child_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_grandchild_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_read_only_unsupported),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_read_only_cap_fail_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_read_timeout_late_success_discard),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_read_only_begin_timeout_cleanup),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_pre_start_failure_does_not_audit),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_restart_missing_guid_enoent),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_admission),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_root_path_teardown_dispatches),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_deep_teardown_dispatches),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_teardown_cycle_aborts),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_teardown_alias_aborts),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_root_value_teardown_dispatches),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_root_section_replays),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_non_root_key_replays),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_non_root_guid_collision_aborts),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_generation_overflow_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_overflow_reaches_descendant_watch),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_commit_failure_no_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_readwrite_unsupported),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_readwrite_begin_timeout_cleanup),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_commit_timeout_late_success_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_commit_timeout_late_error_no_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_bad_magic),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_min_reader_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_checksum_mismatch),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_after_trailer_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_missing_root_key),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_duplicate_root_key),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_root_key_retains_mutable),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_root_key_sd_short_buffer),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_stream_root_flags_conflict),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_layer_duplicate_manifest),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_layer_after_key_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_layer_high_precedence_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_layer_existing_high_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_layer_tcb_marks_used),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_metadata_precedence_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_metadata_precedence_tcb_allows),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_metadata_precedence_zero_allows),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_precedence_non_metadata_allows),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_data_records_accept_manifest),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_data_records_require_manifest),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_data_before_key_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_data_path_after_value_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_data_value_after_blanket_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_topology_first_key_must_be_root),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_topology_duplicate_non_root_guid),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_topology_non_root_requires_anchor),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_topology_non_root_anchor_target),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_topology_parent_must_precede_child),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_topology_value_scoped_to_section),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_sequence_root_replay_advances),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_sequence_overflow_denied),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_sequence_skipped_root_path),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_backup_restore_fail_before_stream),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_restore_restart_missing_guid_enoent),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_notify_arm_replace_disarm),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_notify_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_notify_restart_missing_guid_enoent),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_orphan_last_close_sends_drop),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_orphan_nonfinal_close_defers_drop),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_orphan_close_down_source_no_error),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_orphan_transition_marks_and_notifies),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_orphan_transition_no_live_refs_noops),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_read_poll_drains_records),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_filter_disarm_and_overflow),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_runtime_queue_limit),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_runtime_subtree_depth),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_context_retains_queue_limit),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_context_retains_subtree_depth),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_registry_arm_replace_disarm),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_registry_refcounts_close),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_live_dispatch_direct_and_subtree),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_live_dispatch_filter_bypass_and_zero_depth),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_live_dispatch_context_subkey_created),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_fresh_succeeds),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_retries_bad_candidates),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_exhaustion_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_bad_tracker_eio),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_uses_live_layer_table),
	KUNIT_CASE(pkm_lcs_kunit_set_value_layer_cap_uses_runtime_limit),
	KUNIT_CASE(pkm_lcs_kunit_delete_layer_orchestration_aborts_before_broadcast),
	KUNIT_CASE(pkm_lcs_kunit_delete_layer_orchestration_overflows_watches),
	KUNIT_CASE(pkm_lcs_kunit_sequence_allocation_advances_global_counter),
	KUNIT_CASE(pkm_lcs_kunit_sequence_allocation_fails_closed),
	{}
};

static struct kunit_suite pkm_lcs_kunit_key_suite = {
	.name = "pkm_lcs_kunit_key",
	.test_cases = pkm_lcs_kunit_key_cases,
};

kunit_test_suite(pkm_lcs_kunit_key_suite);
