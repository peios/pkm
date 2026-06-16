// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_source_device_open_rejects_null_token(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_open_for_token(NULL),
			(long)-EPERM);
}


static void pkm_lcs_kunit_source_device_open_requires_tcb(struct kunit *test)
{
	struct file file = { };
	const void *token;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_open_for_token(token),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_open_file_for_token(token,
									&file),
			(long)-EPERM);
	KUNIT_EXPECT_PTR_EQ(test, file.private_data, NULL);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_device_open_marks_tcb_used(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_EXPECT_EQ(test, before.privileges_used & KACS_SE_TCB_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_open_for_token(token), 0L);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			KACS_SE_TCB_PRIVILEGE);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_device_open_attaches_private_state(
	struct kunit *test)
{
	struct pkm_lcs_source_fd *source_fd;
	struct file file = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, file.private_data);
	source_fd = file.private_data;
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_PTR_EQ(test, file.private_data, NULL);

	kacs_rust_token_drop(token);
}


/*
 * Regression: Linux misc_open() sets file->private_data to the struct
 * miscdevice * before calling the driver .open, so every real open of
 * /dev/pkm_registry arrives with a non-NULL private_data. The open path must
 * tolerate and overwrite it, not reject it as EINVAL (which previously broke
 * every userspace open while the KUnit suite -- using a zeroed struct file --
 * stayed green).
 */
static void pkm_lcs_kunit_source_device_open_overwrites_misc_private_data(
	struct kunit *test)
{
	struct pkm_lcs_source_fd *source_fd;
	int miscdevice_sentinel = 0;
	struct file file = { };
	const void *token;

	/* Stand in for the struct miscdevice * that misc_open() stashes. */
	file.private_data = &miscdevice_sentinel;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, file.private_data);
	KUNIT_EXPECT_PTR_NE(test, file.private_data,
			    (void *)&miscdevice_sentinel);
	source_fd = file.private_data;
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_PTR_EQ(test, file.private_data, NULL);

	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_copy_success(struct kunit *test)
{
	const char name_src[] = { 'M', 'a', 'c', 'h', 'i', 'n', 'e', '!' };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1, 2, 3 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.max_sequence = 41,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			0L);
	KUNIT_EXPECT_EQ(test, copy.hive_count, 1U);
	KUNIT_EXPECT_EQ(test, copy.max_sequence, 41ULL);
	KUNIT_ASSERT_NOT_NULL(test, copy.hives);
	KUNIT_ASSERT_NOT_NULL(test, copy.hives[0].name);
	KUNIT_EXPECT_EQ(test, copy.hives[0].name_len, 7U);
	KUNIT_EXPECT_STREQ(test, copy.hives[0].name, "Machine");
	KUNIT_EXPECT_EQ(test, copy.hives[0].name[7], '\0');
	KUNIT_EXPECT_EQ(test, copy.hives[0].root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 3U);

	pkm_lcs_source_registration_copy_destroy(&copy);
}


static void pkm_lcs_kunit_source_registration_copy_rejects_padding(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
		._pad1 = 1,
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };

	args._pad = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.reads = 0;
	args._pad = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);
	KUNIT_EXPECT_PTR_EQ(test, copy.hives, NULL);
}


static void pkm_lcs_kunit_source_registration_copy_fails_closed_on_faults(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, NULL, 64, &copy),
			(long)-EFAULT);

	ctx.fault_src = name_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, ctx.reads, 3U);
	KUNIT_EXPECT_PTR_EQ(test, copy.hives, NULL);
}


static void pkm_lcs_kunit_source_registration_copy_fault_zeroes_output(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = 1,
	};
	struct pkm_lcs_source_registration_hive_copy stale_hive = {
		.name = (char *)"stale",
		.name_len = 5,
		.flags = RSI_HIVE_PRIVATE,
		.hive_generation = 99,
	};
	struct pkm_lcs_source_registration_copy copy = {
		.hive_count = 7,
		.max_sequence = 1234,
		.hives = &stale_hive,
	};

	ctx.fault_src = &args;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, copy.hive_count, 0U);
	KUNIT_EXPECT_EQ(test, copy.max_sequence, 0ULL);
	KUNIT_EXPECT_PTR_EQ(test, copy.hives, NULL);
}


static void pkm_lcs_kunit_source_registration_entrypoint_fault_unpublished(
	struct kunit *test)
{
	static const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = sizeof(name_src) - 1,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	ctx.fault_src = &args;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.bound_transaction_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.read_only_transaction_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_device_raw_ioctl_entrypoints_fail_closed(
	struct kunit *test)
{
	struct file file = { };
	const void *token;
	long ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	ret = pkm_lcs_kunit_source_device_raw_ioctl(&file, REG_SRC_REGISTER, 0);
	KUNIT_EXPECT_TRUE(test, ret == -EFAULT || ret == -EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_raw_ioctl(
				&file, _IO(REG_IOC_TYPE, 0xfe), 0),
			(long)-ENOTTY);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_raw_ioctl(
				&file, _IO('X', REG_SRC_REGISTER_NR), 0),
			(long)-ENOTTY);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_copy_bounds_hive_count(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_register_args args = {
		.hive_count = 65,
		.hives_ptr = 0,
	};
	struct pkm_lcs_source_registration_copy copy = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			(long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_PTR_EQ(test, copy.hives, NULL);
}


static void pkm_lcs_kunit_source_registration_runtime_hive_limit(
	struct kunit *test)
{
	const char machine_name[] = "Machine";
	const char users_name[] = "Users";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_runtime_limits limits = { };
	struct reg_src_hive_entry hives[2] = { };
	struct reg_src_register_args args = {
		.hive_count = ARRAY_SIZE(hives),
		.hives_ptr = (u64)(unsigned long)hives,
	};
	struct pkm_lcs_source_fd *source_fd;
	struct file file = { };
	const void *token;

	hives[0].name_len = strlen(machine_name);
	hives[0].name_ptr = (u64)(unsigned long)machine_name;
	hives[0].root_guid[0] = 1U;
	hives[1].name_len = strlen(users_name);
	hives[1].name_ptr = (u64)(unsigned long)users_name;
	hives[1].root_guid[0] = 2U;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_hives_per_source = 1U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_max_hives_per_source(), 1U);

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			(long)-ENOSPC);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_runtime_raised_hive_limit(
	struct kunit *test)
{
	enum { HIVE_COUNT = 65 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct reg_src_hive_entry *hives;
	struct reg_src_register_args args = {
		.hive_count = HIVE_COUNT,
	};
	char (*names)[8];
	struct file file = { };
	const void *token = NULL;
	bool file_opened = false;
	long ret;
	u32 i;

	hives = kcalloc(HIVE_COUNT, sizeof(*hives), GFP_KERNEL);
	names = kcalloc(HIVE_COUNT, sizeof(*names), GFP_KERNEL);
	if (!hives || !names) {
		KUNIT_FAIL(test, "failed to allocate raised hive test arrays");
		goto out_free;
	}

	args.hives_ptr = (u64)(unsigned long)hives;
	for (i = 0; i < HIVE_COUNT; i++) {
		snprintf(names[i], sizeof(names[i]), "Hive%03u", i);
		hives[i].name_len = strlen(names[i]);
		hives[i].name_ptr = (u64)(unsigned long)names[i];
		hives[i].root_guid[0] = (u8)(i + 1U);
	}

	pkm_lcs_runtime_limits_reset_defaults();
	ret = pkm_lcs_runtime_limits_defaults(&limits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_reset_limits;
	limits.max_hives_per_source = HIVE_COUNT;
	ret = pkm_lcs_runtime_limits_publish(&limits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_reset_limits;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	if (!token) {
		KUNIT_FAIL(test, "failed to allocate TCB token");
		goto out_cleanup;
	}
	ret = pkm_lcs_source_device_open_file_for_token(token, &file);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_cleanup;
	file_opened = true;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);

out_cleanup:
	if (file_opened)
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
	pkm_lcs_kunit_reset_source_table();
	if (token)
		kacs_rust_token_drop(token);
out_reset_limits:
	pkm_lcs_runtime_limits_reset_defaults();
out_free:
	kfree(names);
	kfree(hives);
}


static void pkm_lcs_kunit_source_registration_runtime_source_limit(
	struct kunit *test)
{
	const char machine_name[] = "Machine";
	const char users_name[] = "Users";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_runtime_limits limits = { };
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_registered_sources = 1U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_max_registered_sources(), 1U);

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive,
					  machine_name, 1U, 0);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive,
					  users_name, 2U, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			(long)-ENOSPC);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_runtime_raised_source_limit(
	struct kunit *test)
{
	enum { SOURCE_COUNT = 33 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct file *files;
	struct reg_src_hive_entry *hives;
	struct reg_src_register_args *args;
	char (*names)[8];
	struct file extra_file = { };
	struct reg_src_hive_entry extra_hive;
	struct reg_src_register_args extra_args;
	struct pkm_lcs_hive_route_result route = { };
	const char extra_name[] = "Extra";
	const void *token = NULL;
	u32 opened_count = 0;
	bool extra_opened = false;
	long ret;
	u32 i;

	files = kcalloc(SOURCE_COUNT, sizeof(*files), GFP_KERNEL);
	hives = kcalloc(SOURCE_COUNT, sizeof(*hives), GFP_KERNEL);
	args = kcalloc(SOURCE_COUNT, sizeof(*args), GFP_KERNEL);
	names = kcalloc(SOURCE_COUNT, sizeof(*names), GFP_KERNEL);
	if (!files || !hives || !args || !names) {
		KUNIT_FAIL(test, "failed to allocate source registration arrays");
		goto out_free;
	}

	pkm_lcs_runtime_limits_reset_defaults();
	ret = pkm_lcs_runtime_limits_defaults(&limits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_free;
	limits.max_registered_sources = SOURCE_COUNT;
	ret = pkm_lcs_runtime_limits_publish(&limits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_reset_limits;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	if (!token) {
		KUNIT_FAIL(test, "failed to allocate TCB token");
		goto out_cleanup;
	}
	for (i = 0; i < SOURCE_COUNT; i++) {
		snprintf(names[i], sizeof(names[i]), "Src%03u", i);
		pkm_lcs_kunit_build_register_args(&args[i], &hives[i],
						  names[i], (u8)(i + 1U), 0);
		ret = pkm_lcs_source_device_open_file_for_token(token,
								&files[i]);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_cleanup;
		opened_count++;

		ret = pkm_lcs_source_register_file_for_token(
			token, &files[i], &ops, (const void __user *)&args[i]);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_cleanup;
	}

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, (u32)SOURCE_COUNT);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, (u32)SOURCE_COUNT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(names[SOURCE_COUNT - 1],
						strlen(names[SOURCE_COUNT - 1]),
						NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, (u32)SOURCE_COUNT);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], (u8)SOURCE_COUNT);

	pkm_lcs_kunit_build_register_args(&extra_args, &extra_hive, extra_name,
					  200U, 0);
	ret = pkm_lcs_source_device_open_file_for_token(token, &extra_file);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_cleanup;
	extra_opened = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &extra_file, &ops,
				(const void __user *)&extra_args),
			(long)-ENOSPC);

out_cleanup:
	for (i = 0; i < opened_count; i++)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_device_release_file(&files[i]),
				0);
	if (extra_opened)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_device_release_file(&extra_file),
				0);
	pkm_lcs_kunit_reset_source_table();
	if (token)
		kacs_rust_token_drop(token);
out_reset_limits:
	pkm_lcs_runtime_limits_reset_defaults();
out_free:
	kfree(names);
	kfree(args);
	kfree(hives);
	kfree(files);
}


static void pkm_lcs_kunit_source_registration_semantic_accepts_valid(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.max_sequence = 41,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };
	struct pkm_lcs_source_registration_plan_copy plan = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_validate_copied(&copy, true,
								    &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.hive_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.source_next_sequence, 42ULL);

	pkm_lcs_source_registration_copy_destroy(&copy);
}


static void pkm_lcs_kunit_source_registration_semantic_requires_tcb(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };
	struct pkm_lcs_source_registration_plan_copy plan = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_validate_copied(&copy, false,
								    &plan),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, plan.hive_count, 0U);

	pkm_lcs_source_registration_copy_destroy(&copy);
}


static void pkm_lcs_kunit_source_registration_semantic_rejects_bad_hive(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
		.flags = 0x2,
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };
	struct pkm_lcs_source_registration_plan_copy plan = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_validate_copied(&copy, true,
								    &plan),
			(long)-EINVAL);

	pkm_lcs_source_registration_copy_destroy(&copy);
}


static void pkm_lcs_kunit_source_registration_semantic_rejects_sequence_overflow(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = 7,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.max_sequence = ~0ULL,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct pkm_lcs_source_registration_copy copy = { };
	struct pkm_lcs_source_registration_plan_copy plan = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_registration_copy_from_user(
				&ops, (const void __user *)&args, 64, &copy),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_registration_validate_copied(&copy, true,
								    &plan),
			(long)-EOVERFLOW);

	pkm_lcs_source_registration_copy_destroy(&copy);
}


static void pkm_lcs_kunit_source_registration_rejects_sequence_overflow_live(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = sizeof(name_src) - 1,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.max_sequence = ~0ULL,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct file file = { };
	struct pkm_lcs_source_fd *source_fd;
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);

	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			(long)-EOVERFLOW);
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test, ctx.reads, 3U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_rejects_reserved_fields_live(
	struct kunit *test)
{
	static const char name_src[] = "Machine";
	static const struct {
		u32 args_pad;
		u32 hive_pad0;
		u32 hive_pad1;
		unsigned int expected_reads;
	} cases[] = {
		{ 1, 0, 0, 1 },
		{ 0, 1, 0, 2 },
		{ 0, 0, 1, 2 },
	};
	struct file file = { };
	const void *token;
	size_t i;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_kunit_usercopy_ctx ctx = { };
		struct pkm_lcs_usercopy_ops ops =
			pkm_lcs_kunit_usercopy_ops(&ctx);
		struct reg_src_hive_entry hive = {
			.name_len = sizeof(name_src) - 1,
			._pad0 = cases[i].hive_pad0,
			.name_ptr = (u64)(unsigned long)name_src,
			.root_guid = { 1 },
			._pad1 = cases[i].hive_pad1,
		};
		struct reg_src_register_args args = {
			.hive_count = 1,
			._pad = cases[i].args_pad,
			.hives_ptr = (u64)(unsigned long)&hive,
		};
		struct pkm_lcs_source_fd *source_fd = file.private_data;

		KUNIT_ASSERT_NOT_NULL(test, source_fd);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_register_file_for_token(
					token, &file, &ops,
					(const void __user *)&args),
				(long)-EINVAL);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test, ctx.reads, cases[i].expected_reads);
	}

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_rejects_zero_hive_count_live(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_register_args args = { };
	struct file file = { };
	struct pkm_lcs_source_fd *source_fd;
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);

	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_rechecks_tcb_live(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive = {
		.name_len = sizeof(name_src) - 1,
		.name_ptr = (u64)(unsigned long)name_src,
		.root_guid = { 1 },
	};
	struct reg_src_register_args args = {
		.hive_count = 1,
		.hives_ptr = (u64)(unsigned long)&hive,
	};
	struct file file = { };
	struct pkm_lcs_source_fd *source_fd;
	const void *open_token;
	const void *register_token;

	pkm_lcs_kunit_reset_source_table();
	open_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	register_token =
		kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, open_token);
	KUNIT_ASSERT_NOT_NULL(test, register_token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(open_token,
								  &file),
			0L);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);

	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				register_token, &file, &ops,
				(const void __user *)&args),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(register_token);
	kacs_rust_token_drop(open_token);
}


static void pkm_lcs_kunit_source_registration_rejects_malformed_hive_names(
	struct kunit *test)
{
	static const u8 invalid_utf8_name[] = { 'B', 0xff, 'd' };
	static const u8 null_containing_name[] = {
		'B', 'a', 'd', '\0', 'N', 'a', 'm', 'e'
	};
	static const char current_user_name[] = "CurrentUser";
	static const struct {
		const void *name;
		u32 name_len;
	} cases[] = {
		{ invalid_utf8_name, sizeof(invalid_utf8_name) },
		{ null_containing_name, sizeof(null_containing_name) },
		{ current_user_name, sizeof(current_user_name) - 1 },
	};
	struct file file = { };
	const void *token;
	size_t i;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_kunit_usercopy_ctx ctx = { };
		struct pkm_lcs_usercopy_ops ops =
			pkm_lcs_kunit_usercopy_ops(&ctx);
		struct reg_src_hive_entry hive = {
			.name_len = cases[i].name_len,
			.name_ptr = (u64)(unsigned long)cases[i].name,
			.root_guid = { 1 },
		};
		struct reg_src_register_args args = {
			.hive_count = 1,
			.hives_ptr = (u64)(unsigned long)&hive,
		};
		struct pkm_lcs_source_fd *source_fd = file.private_data;

		KUNIT_ASSERT_NOT_NULL(test, source_fd);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_register_file_for_token(
					token, &file, &ops,
					(const void __user *)&args),
				(long)-EINVAL);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test, ctx.reads, 3U);
	}

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_rejects_bad_hive_flags_scope(
	struct kunit *test)
{
	static const char name_src[] = "Machine";
	static const struct {
		u32 flags;
		u8 scope_first;
	} cases[] = {
		{ RSI_HIVE_PRIVATE | 0x04U, 0x42 },
		{ 0, 0x42 },
	};
	struct file file = { };
	const void *token;
	size_t i;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_kunit_usercopy_ctx ctx = { };
		struct pkm_lcs_usercopy_ops ops =
			pkm_lcs_kunit_usercopy_ops(&ctx);
		struct reg_src_hive_entry hive = {
			.name_len = sizeof(name_src) - 1,
			.name_ptr = (u64)(unsigned long)name_src,
			.root_guid = { 1 },
			.flags = cases[i].flags,
			.scope_guid = { cases[i].scope_first },
		};
		struct reg_src_register_args args = {
			.hive_count = 1,
			.hives_ptr = (u64)(unsigned long)&hive,
		};
		struct pkm_lcs_source_fd *source_fd = file.private_data;

		KUNIT_ASSERT_NOT_NULL(test, source_fd);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_register_file_for_token(
					token, &file, &ops,
					(const void __user *)&args),
				(long)-EINVAL);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test, ctx.reads, 3U);
	}

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_rejects_duplicate_routes_live(
	struct kunit *test)
{
	static const char name_a[] = "Machine";
	static const char name_b[] = "machine";
	static const struct {
		bool private_scope;
		u8 root_a;
		u8 root_b;
	} cases[] = {
		{ false, 1, 2 },
		{ true, 3, 4 },
	};
	struct file file = { };
	const void *token;
	size_t i;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_kunit_usercopy_ctx ctx = { };
		struct pkm_lcs_usercopy_ops ops =
			pkm_lcs_kunit_usercopy_ops(&ctx);
		struct reg_src_hive_entry hives[2] = {
			{
				.name_len = sizeof(name_a) - 1,
				.name_ptr = (u64)(unsigned long)name_a,
				.root_guid = { cases[i].root_a },
			},
			{
				.name_len = sizeof(name_b) - 1,
				.name_ptr = (u64)(unsigned long)name_b,
				.root_guid = { cases[i].root_b },
			},
		};
		struct reg_src_register_args args = {
			.hive_count = ARRAY_SIZE(hives),
			.hives_ptr = (u64)(unsigned long)hives,
		};
		struct pkm_lcs_source_fd *source_fd = file.private_data;

		if (cases[i].private_scope) {
			hives[0].flags = RSI_HIVE_PRIVATE;
			hives[0].scope_guid[0] = 0x42;
			hives[1].flags = RSI_HIVE_PRIVATE;
			hives[1].scope_guid[0] = 0x42;
		}

		KUNIT_ASSERT_NOT_NULL(test, source_fd);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_register_file_for_token(
					token, &file, &ops,
					(const void __user *)&args),
				(long)-EINVAL);
		KUNIT_EXPECT_EQ(test, source_fd->state,
				PKM_LCS_SOURCE_FD_UNREGISTERED);
		KUNIT_EXPECT_EQ(test, ctx.reads, 4U);
	}

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_accepts_private_shadow_live(
	struct kunit *test)
{
	static const char global_name[] = "Machine";
	static const char private_name[] = "machine";
	const u8 matching_scope[1][16] = { { 0x42 } };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hives[2] = {
		{
			.name_len = sizeof(global_name) - 1,
			.name_ptr = (u64)(unsigned long)global_name,
			.root_guid = { 1 },
		},
		{
			.name_len = sizeof(private_name) - 1,
			.name_ptr = (u64)(unsigned long)private_name,
			.root_guid = { 2 },
			.flags = RSI_HIVE_PRIVATE,
			.scope_guid = { 0x42 },
		},
	};
	struct reg_src_register_args args = {
		.hive_count = ARRAY_SIZE(hives),
		.hives_ptr = (u64)(unsigned long)hives,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_source_fd *source_fd;
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	KUNIT_EXPECT_EQ(test, source_fd->state, PKM_LCS_SOURCE_FD_ACTIVE);
	KUNIT_EXPECT_EQ(test, ctx.reads, 4U);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(global_name, strlen(global_name),
						NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(global_name, strlen(global_name),
						matching_scope, 1, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 2U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_registration_accepts_distinct_private_scopes_live(
	struct kunit *test)
{
	static const char name_a[] = "Machine";
	static const char name_b[] = "machine";
	const u8 scope_a[1][16] = { { 0x42 } };
	const u8 scope_b[1][16] = { { 0x43 } };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hives[2] = {
		{
			.name_len = sizeof(name_a) - 1,
			.name_ptr = (u64)(unsigned long)name_a,
			.root_guid = { 2 },
			.flags = RSI_HIVE_PRIVATE,
			.scope_guid = { 0x42 },
		},
		{
			.name_len = sizeof(name_b) - 1,
			.name_ptr = (u64)(unsigned long)name_b,
			.root_guid = { 3 },
			.flags = RSI_HIVE_PRIVATE,
			.scope_guid = { 0x43 },
		},
	};
	struct reg_src_register_args args = {
		.hive_count = ARRAY_SIZE(hives),
		.hives_ptr = (u64)(unsigned long)hives,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_source_fd *source_fd;
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	KUNIT_EXPECT_EQ(test, source_fd->state, PKM_LCS_SOURCE_FD_ACTIVE);
	KUNIT_EXPECT_EQ(test, ctx.reads, 4U);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_a, strlen(name_a), NULL, 0,
						&route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_a, strlen(name_a),
						scope_a, 1, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 2U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_a, strlen(name_a),
						scope_b, 1, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 3U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_ioctl_publishes_active_slot(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct pkm_lcs_source_fd *source_fd;
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 41);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	KUNIT_EXPECT_EQ(test, source_fd->state, PKM_LCS_SOURCE_FD_ACTIVE);
	KUNIT_EXPECT_EQ(test, source_fd->source_id, 1U);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.down_count, 0U);
	KUNIT_EXPECT_TRUE(test, snapshot.sequence_initialized);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 42ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.down_count, 1U);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_active_ids_snapshot_filters_down(
	struct kunit *test)
{
	const char first_name[] = "Machine";
	const char second_name[] = "Users";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct file first_file = { };
	struct file second_file = { };
	u32 ids[2] = { };
	u32 count = 123;
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(
				ids, ARRAY_SIZE(ids), &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(
				NULL, ARRAY_SIZE(ids), &count),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(ids, 0, &count),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(
				ids, ARRAY_SIZE(ids), NULL),
			(long)-EINVAL);

	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive,
					  first_name, 1, 0);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive,
					  second_name, 2, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	memset(ids, 0, sizeof(ids));
	count = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(
				ids, ARRAY_SIZE(ids), &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test, ids[0], 1U);
	KUNIT_EXPECT_EQ(test, ids[1], 2U);

	ids[0] = 99;
	count = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(ids, 1, &count),
			(long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test, ids[0], 99U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);
	memset(ids, 0, sizeof(ids));
	count = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_active_ids_snapshot(
				ids, ARRAY_SIZE(ids), &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test, ids[0], 2U);
	KUNIT_EXPECT_EQ(test, ids[1], 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_ioctl_rejects_active_collision(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct pkm_lcs_source_fd *second_fd;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  2, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			(long)-EEXIST);
	second_fd = second_file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, second_fd);
	KUNIT_EXPECT_EQ(test, second_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.down_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_ioctl_resumes_down_slot(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct pkm_lcs_source_fd *source_fd;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);
	source_fd = second_file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	KUNIT_EXPECT_EQ(test, source_fd->state, PKM_LCS_SOURCE_FD_ACTIVE);
	KUNIT_EXPECT_EQ(test, source_fd->source_id, 1U);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.down_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 8ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_resume_dispatches_overflow(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x44 },
	};
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input watch_input = {
		.source_id = 1,
		.granted_access = KEY_NOTIFY,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = ARRAY_SIZE(path),
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct file first_file = { };
	struct file second_file = { };
	const void *token;
	u8 event[8] = { };
	long watch_fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);

	memcpy(watch_input.key_guid, ancestors[1], sizeof(watch_input.key_guid));
	watch_fd = pkm_lcs_key_fd_publish(&watch_input);
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.down_count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)sizeof(event));
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_resume_revalidates_key_fd(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x55 },
	};
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input key_input = {
		.source_id = 1,
		.granted_access = KEY_NOTIFY,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = ARRAY_SIZE(path),
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.file = NULL,
		.expected_guid = ancestors[1],
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);

	memcpy(key_input.key_guid, ancestors[1], sizeof(key_input.key_guid));
	fd = pkm_lcs_key_fd_publish(&key_input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	script.file = &second_file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread,
					 &script,
					 "pkm-lcs-kunit-revalidate-ok");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_kthread_stop(task), 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);

	notify.filter = 0;
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_registration_denied_ioctl_skips_revalidation(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x56 },
	};
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input key_input = {
		.source_id = 1,
		.granted_access = 0,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = ARRAY_SIZE(path),
	};
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file first_file = { };
	struct file second_file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);

	memcpy(key_input.key_guid, ancestors[1], sizeof(key_input.key_guid));
	fd = pkm_lcs_key_fd_publish(&key_input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_raw_ioctl((int)fd,
						       REG_IOC_NOTIFY, 0),
			(long)-EACCES);
	pkm_lcs_kunit_source_fd_snapshot(&second_file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_registration_resume_revalidate_retains_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x57 },
	};
	char source_name[LONG_NAME_LEN + 1];
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input key_input = {
		.source_id = 1,
		.granted_access = KEY_NOTIFY,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = ARRAY_SIZE(path),
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.file = NULL,
		.expected_guid = ancestors[1],
		.name = source_name,
		.reset_runtime_limits_before_response = true,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;
	long fd;

	memset(source_name, 'R', LONG_NAME_LEN);
	source_name[LONG_NAME_LEN] = '\0';
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);

	memcpy(key_input.key_guid, ancestors[1], sizeof(key_input.key_guid));
	fd = pkm_lcs_key_fd_publish(&key_input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	script.file = &second_file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread,
					 &script,
					 "pkm-lcs-kunit-revalidate-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_kthread_stop(task), 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, snapshot.orphaned);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_resume_missing_guid_enoent(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x66 },
	};
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input key_input = {
		.source_id = 1,
		.granted_access = KEY_NOTIFY,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = ARRAY_SIZE(path),
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.file = NULL,
		.expected_guid = ancestors[1],
		.status = RSI_NOT_FOUND,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;
	u8 event[8] = { };
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);

	memcpy(key_input.key_guid, ancestors[1], sizeof(key_input.key_guid));
	fd = pkm_lcs_key_fd_publish(&key_input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	script.file = &second_file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread,
					 &script,
					 "pkm-lcs-kunit-revalidate-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_kthread_stop(task), 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, event,
							sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_registration_flush_revalidate_missing_guid_enoent(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x67 },
	};
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input key_input = {
		.source_id = 1,
		.granted_access = KEY_SET_VALUE,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = ARRAY_SIZE(path),
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.file = NULL,
		.expected_guid = ancestors[1],
		.status = RSI_NOT_FOUND,
	};
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct task_struct *task;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);

	memcpy(key_input.key_guid, ancestors[1], sizeof(key_input.key_guid));
	fd = pkm_lcs_key_fd_publish(&key_input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  1, 7);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	script.file = &second_file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_read_key_source_thread,
					 &script,
					 "pkm-lcs-kunit-flush-reval-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_key_fd_flush((int)fd),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_kthread_stop(task), 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&second_file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 1ULL);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &key_snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, key_snapshot.orphaned);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_ioctl_rejects_stale_resume(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct pkm_lcs_source_fd *source_fd;
	struct file first_file = { };
	struct file second_file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive, name_src, 1,
					  0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive, name_src,
					  2, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			(long)-ESTALE);
	source_fd = second_file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	KUNIT_EXPECT_EQ(test, source_fd->state,
			PKM_LCS_SOURCE_FD_UNREGISTERED);

	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.down_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_ioctl_rejects_repeat_register(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_bootstrap_refresh_machine_hive_success(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x81 };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x82 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x83 };
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x84 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0x85 };
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0x86 };
	static const char value_name[] = "RequestTimeoutMs";
	static const char kmes_value_name[] = "MaxNestingDepth";
	static const struct pkm_lcs_kunit_walk_source_step self_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
	};
	static const struct pkm_lcs_kunit_walk_source_step kmes_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "KMES", .guid = kmes_guid },
	};
	static const struct pkm_lcs_kunit_walk_source_step layer_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
		{ .expected_child = "Layers", .guid = layers_root_guid },
	};
	static const u8 owner_only_sd[] = {
		0x01, 0x00, 0x00, 0x80,
		0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	u8 data[sizeof(u32)];
	u8 kmes_data[sizeof(u32)];
	struct pkm_lcs_kunit_source_bootstrap_source_script script = {
		.self_config_walk = {
			.steps = self_steps,
			.step_count = ARRAY_SIZE(self_steps),
		},
		.self_config_query = {
			.expected_guid = registry_guid,
			.expected_value_name = "",
			.response_value_name = value_name,
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.kmes_walk = {
			.steps = kmes_steps,
			.step_count = ARRAY_SIZE(kmes_steps),
		},
		.kmes_query = {
			.expected_guid = kmes_guid,
			.expected_value_name = "",
			.response_value_name = kmes_value_name,
			.layer_name = "base",
			.data = kmes_data,
			.data_len = sizeof(kmes_data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.layers_walk = {
			.steps = layer_steps,
			.step_count = ARRAY_SIZE(layer_steps),
		},
		.layers_refresh = {
			.enum_children = {
				.expected_parent_guid = layers_root_guid,
				.child_name = "Policy",
				.layer_name = "base",
				.child_guid = policy_guid,
			},
			.refresh = {
				.expected_guid = policy_guid,
				.name = "Policy",
				.sd = owner_only_sd,
				.sd_len = sizeof(owner_only_sd),
				.precedence = 7,
				.enabled = 1,
				.precedence_present = true,
				.enabled_present = true,
			},
			.expect_refresh = true,
		},
		.expect_kmes_query = true,
		.expect_layers_refresh = true,
	};
	struct pkm_lcs_source_bootstrap_refresh_result result = { };
	struct pkm_lcs_internal_self_watch_snapshot watch_snapshot = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct pkm_kmes_runtime_config kmes_snapshot = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	put_unaligned_le32(1000U, data);
	put_unaligned_le32(64U, kmes_data);
	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_source_bootstrap_source_thread, &script,
		"pkm-lcs-kunit-bootstrap-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_source_bootstrap_refresh_machine_hive(
		1, machine_root_guid, &result);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 14U);
	KUNIT_EXPECT_EQ(test, script.writes, 14U);
	KUNIT_EXPECT_TRUE(test, result.registry_root_present);
	KUNIT_EXPECT_EQ(test, result.self_config.applied_count, 1U);
	KUNIT_EXPECT_TRUE(test, result.kmes_root_present);
	KUNIT_EXPECT_EQ(test, result.kmes_config.applied_count, 1U);
	KUNIT_EXPECT_TRUE(test, result.layers_root_present);
	KUNIT_EXPECT_EQ(test, result.layers.enumerated_child_count, 1U);
	KUNIT_EXPECT_EQ(test, result.layers.refreshed_child_count, 1U);
	KUNIT_EXPECT_EQ(test, result.layers.effective_changed_count, 1U);
	KUNIT_EXPECT_EQ(test, result.self_watch.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_TARGETED);
	KUNIT_EXPECT_EQ(test, result.self_watch.watch_count, 3U);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.self_watch.registry_guid, registry_guid,
			       sizeof(registry_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.self_watch.layers_guid, layers_root_guid,
			       sizeof(layers_root_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.self_watch.kmes_guid, kmes_guid,
			       sizeof(kmes_guid)),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(
				&watch_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, watch_snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_TARGETED);
	KUNIT_EXPECT_EQ(test, watch_snapshot.watch_count, 3U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 1000U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_runtime_config_snapshot(&kmes_snapshot), 0);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.max_nesting_depth, 64U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 7U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_bootstrap_queues_after_publish(
	struct kunit *test)
{
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x87 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x88 };
	static const u8 layers_root_guid[RSI_GUID_SIZE] = { 0x89 };
	static const u8 policy_guid[RSI_GUID_SIZE] = { 0x8a };
	static const u8 kmes_guid[RSI_GUID_SIZE] = { 0x8b };
	static const char name_src[] = "Machine";
	static const char value_name[] = "RequestTimeoutMs";
	static const char kmes_value_name[] = "MaxNestingDepth";
	static const struct pkm_lcs_kunit_walk_source_step self_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
	};
	static const struct pkm_lcs_kunit_walk_source_step kmes_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "KMES", .guid = kmes_guid },
	};
	static const struct pkm_lcs_kunit_walk_source_step layer_steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
		{ .expected_child = "Layers", .guid = layers_root_guid },
	};
	static const u8 owner_only_sd[] = {
		0x01, 0x00, 0x00, 0x80,
		0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x05,
		0x12, 0x00, 0x00, 0x00,
	};
	u8 data[sizeof(u32)];
	u8 kmes_data[sizeof(u32)];
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_kunit_source_bootstrap_source_script script = {
		.self_config_walk = {
			.steps = self_steps,
			.step_count = ARRAY_SIZE(self_steps),
		},
		.self_config_query = {
			.expected_guid = registry_guid,
			.expected_value_name = "",
			.response_value_name = value_name,
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.kmes_walk = {
			.steps = kmes_steps,
			.step_count = ARRAY_SIZE(kmes_steps),
		},
		.kmes_query = {
			.expected_guid = kmes_guid,
			.expected_value_name = "",
			.response_value_name = kmes_value_name,
			.layer_name = "base",
			.data = kmes_data,
			.data_len = sizeof(kmes_data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.layers_walk = {
			.steps = layer_steps,
			.step_count = ARRAY_SIZE(layer_steps),
		},
		.layers_refresh = {
			.enum_children = {
				.expected_parent_guid = layers_root_guid,
				.child_name = "Policy",
				.layer_name = "base",
				.child_guid = policy_guid,
			},
			.refresh = {
				.expected_guid = policy_guid,
				.name = "Policy",
				.sd = owner_only_sd,
				.sd_len = sizeof(owner_only_sd),
				.precedence = 9,
				.enabled = 1,
				.precedence_present = true,
				.enabled_present = true,
			},
			.expect_refresh = true,
		},
		.expect_kmes_query = true,
		.expect_layers_refresh = true,
	};
	struct pkm_lcs_runtime_limits snapshot = { };
	struct pkm_kmes_runtime_config kmes_snapshot = { };
	struct pkm_lcs_internal_self_watch_snapshot watch_snapshot = { };
	struct pkm_lcs_source_table_snapshot table = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long ret;
	int thread_ret;

	put_unaligned_le32(1000U, data);
	put_unaligned_le32(96U, kmes_data);
	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_source_bootstrap_source_thread, &script,
		"pkm-lcs-kunit-register-bootstrap");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 0x86, 0);
	ret = pkm_lcs_kunit_source_register_file_for_token_with_bootstrap(
		token, &file, &ops, (const void __user *)&args);
	pkm_lcs_kunit_flush_source_bootstrap_work();
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 14U);
	KUNIT_EXPECT_EQ(test, script.writes, 14U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 1000U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_runtime_config_snapshot(&kmes_snapshot), 0);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.max_nesting_depth, 96U);
	pkm_lcs_kunit_source_table_snapshot(&table);
	KUNIT_EXPECT_EQ(test, table.occupied_count, 1U);
	KUNIT_EXPECT_EQ(test, table.active_count, 1U);
	KUNIT_EXPECT_TRUE(test, table.sequence_initialized);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(
				&watch_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, watch_snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, watch_snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_TARGETED);
	KUNIT_EXPECT_EQ(test, watch_snapshot.watch_count, 3U);
	KUNIT_EXPECT_EQ(test,
			memcmp(watch_snapshot.registry_guid, registry_guid,
			       sizeof(registry_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(watch_snapshot.layers_guid, layers_root_guid,
			       sizeof(layers_root_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(watch_snapshot.kmes_guid, kmes_guid,
			       sizeof(kmes_guid)),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 9U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_registration_bootstrap_ignores_non_machine(
	struct kunit *test)
{
	static const char name_src[] = "Users";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_source_fd_snapshot fd_snapshot = { };
	struct pkm_lcs_internal_self_watch_snapshot watch_snapshot = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct file file = { };
	const void *token;

	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 0x91, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_register_file_for_token_with_bootstrap(
				token, &file, &ops, (const void __user *)&args),
			0L);
	pkm_lcs_kunit_flush_source_bootstrap_work();

	pkm_lcs_kunit_source_fd_snapshot(&file, &fd_snapshot);
	KUNIT_EXPECT_EQ(test, fd_snapshot.state, PKM_LCS_SOURCE_FD_ACTIVE);
	KUNIT_EXPECT_EQ(test, fd_snapshot.queued_request_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_internal_self_watch_snapshot(
				&watch_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, watch_snapshot.mode,
			(u32)PKM_LCS_INTERNAL_SELF_WATCH_DISARMED);
	KUNIT_EXPECT_EQ(test, watch_snapshot.watch_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_internal_self_watch_disarm();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_bootstrap_refresh_bad_inputs_fail_closed(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x92 };
	struct pkm_lcs_source_bootstrap_refresh_result result = {
		.layers_root_present = true,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bootstrap_refresh_machine_hive(
				0, machine_root_guid, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, result.layers_root_present);

	result.layers_root_present = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bootstrap_refresh_machine_hive(
				1, NULL, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, result.layers_root_present);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bootstrap_refresh_machine_hive(
				1, machine_root_guid, NULL),
			(long)-EINVAL);
}


static void pkm_lcs_kunit_source_bound_transaction_counter_limits(
	struct kunit *test)
{
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	for (i = 0; i < 16U; i++) {
		count = 0;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_bound_transaction_acquire(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i + 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, count, 0U);

	for (i = 16U; i > 0U; i--) {
		count = 99U;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_bound_transaction_release(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i - 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_bound_transaction_counter_runtime_limit(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_bound_transactions_per_source = 2U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_max_bound_transactions_per_source(),
			2U);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < 2U; i++) {
		count = 0;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_bound_transaction_acquire(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i + 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, count, 0U);

	for (i = 2U; i > 0U; i--) {
		count = 99U;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_bound_transaction_release(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i - 1U);
	}

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_bound_transaction_counter_raised_runtime_limit(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_bound_transactions_per_source = 20U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < 20U; i++) {
		count = 0;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_bound_transaction_acquire(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i + 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, count, 0U);

	for (i = 20U; i > 0U; i--)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_bound_transaction_release(
					1, &count),
				0L);

	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_bound_transaction_counter_source_down(
	struct kunit *test)
{
	struct file file = { };
	const void *token;
	u32 count = 0;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, count, 0U);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_bound_transaction_counter_bad_inputs(
	struct kunit *test)
{
	u32 count = 99U;

	pkm_lcs_kunit_reset_source_table();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(0, &count),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(0, &count),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, NULL),
			(long)-EINVAL);

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, count, 0U);
}


static void pkm_lcs_kunit_source_read_only_transaction_counter_limits(
	struct kunit *test)
{
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	for (i = 0; i < 16U; i++) {
		count = 0;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_read_only_transaction_acquire(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i + 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_read_only_transaction_acquire(1,
								    &count),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, count, 0U);

	for (i = 16U; i > 0U; i--) {
		count = 99U;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_read_only_transaction_release(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i - 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_read_only_transaction_release(1,
								    &count),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_read_only_transaction_counter_runtime_limit(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_read_only_transactions_per_source = 2U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_max_read_only_transactions_per_source(),
			2U);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < 2U; i++) {
		count = 0;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_read_only_transaction_acquire(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i + 1U);
	}

	count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_read_only_transaction_acquire(1,
								    &count),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, count, 0U);

	for (i = 2U; i > 0U; i--) {
		count = 99U;
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_read_only_transaction_release(
					1, &count),
				0L);
		KUNIT_EXPECT_EQ(test, count, i - 1U);
	}

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_route_runtime_reduced_scope_limit(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	const char target[] = "Machine\\Target";
	const u8 scopes[2][16] = { { 1 }, { 2 } };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_hive_route_result route = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_scope_guids_per_token = 1U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src),
						scopes, ARRAY_SIZE(scopes),
						&route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_symlink_target(
				target, strlen(target), scopes,
				ARRAY_SIZE(scopes), &route),
			(long)-EINVAL);

	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_route_runtime_raised_scope_limit(
	struct kunit *test)
{
	enum { SCOPE_COUNT = 9 };
	const char name_src[] = "Machine";
	const char target[] = "Machine\\Target";
	u8 scopes[SCOPE_COUNT][16] = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_hive_route_result route = { };
	u32 i;

	for (i = 0; i < SCOPE_COUNT; i++)
		scopes[i][0] = (u8)(i + 1U);

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_scope_guids_per_token = SCOPE_COUNT;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_hive_name(name_src, strlen(name_src),
						scopes, ARRAY_SIZE(scopes),
						&route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_symlink_target(
				target, strlen(target), scopes,
				ARRAY_SIZE(scopes), &route),
			(long)-ENOENT);

	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_source_validation_audit_emits_lcs_kmes_event(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const u8 key_guid[16] = {
		0x45, 0x25, 0x04, 0x25, 0x45, 0x25, 0x04, 0x25,
		0x45, 0x25, 0x04, 0x25, 0x45, 0x25, 0x04, 0x25,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[512];
	size_t written = 0;
	u32 header_size;
	u16 type_len;

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_emit_source_validation_failure_audit(
				7, NULL, 0, false, 44, true, RSI_READ_KEY,
				true, key_guid, true,
				PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_METADATA_SD),
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
}


static void pkm_lcs_kunit_self_config_invalid_audit_emits_lcs_kmes_event(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SELF_CONFIG_INVALID";
	static const char config_parent[] = "Machine\\System\\Registry";
	static const char config_name[] = "RequestTimeoutMs";
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[512];
	size_t written = 0;
	u32 header_size;
	u16 type_len;

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_emit_self_config_invalid_audit(
				config_name, sizeof(config_name) - 1,
				PKM_LCS_SELF_CONFIG_RECEIVED_WRONG_TYPE,
				REG_SZ, 0, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT),
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
	KUNIT_EXPECT_EQ(test, buffer[header_size], 0x89);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, config_parent));
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, config_name));
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, "wrong_type"));
}


static void pkm_lcs_kunit_self_config_invalid_audit_rejects_bad_shape(
	struct kunit *test)
{
	static const char config_name[] = "RequestTimeoutMs";
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[256];
	size_t written = 0;

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_emit_self_config_invalid_audit(
				config_name, sizeof(config_name) - 1, 99,
				0, 0, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &snapshot),
			-ENOENT);
}


static void pkm_lcs_kunit_runtime_limits_default_snapshot(struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_snapshot(&limits), 0L);
	pkm_lcs_kunit_expect_runtime_limits_defaults(test, &limits);
}


static void pkm_lcs_kunit_runtime_limits_publish_valid_snapshot(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_runtime_limits snapshot = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 600000U;
	limits.transaction_timeout_ms = 1000U;
	limits.notification_queue_size = 65536U;
	limits.symlink_depth_limit = 64U;
	limits.max_value_size = 67108864U;
	limits.max_key_depth = 4096U;
	limits.max_path_component_length = 1024U;
	limits.max_total_path_length = 65535U;
	limits.max_layers_per_value = 1024U;
	limits.max_bound_transactions_per_source = 256U;
	limits.max_read_only_transactions_per_source = 256U;
	limits.max_total_layers = 65536U;
	limits.max_registered_sources = 256U;
	limits.max_hives_per_source = 1024U;
	limits.max_concurrent_rsi_requests = 4096U;
	limits.max_scope_guids_per_token = 256U;
	limits.max_private_layers_per_token = 256U;
	limits.max_subtree_watch_depth = 4096U;
	limits.max_transaction_watch_event_burst = 65536U;

	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_validate(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, memcmp(&snapshot, &limits, sizeof(limits)), 0);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_runtime_limits_invalid_retains_previous(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_runtime_limits invalid = { };
	struct pkm_lcs_runtime_limits snapshot = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 45000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	invalid = limits;
	invalid.max_value_size = 4095U;
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_publish(&invalid),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, memcmp(&snapshot, &limits, sizeof(limits)), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_defaults(NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_validate(NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_snapshot(NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_limits_publish(NULL),
			(long)-EINVAL);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_apply_hot_swaps_valid_snapshot(
	struct kunit *test)
{
	static const char unknown_name[] = "UnknownFutureTunable";
	struct pkm_lcs_self_config_entry
		entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults) + 1] = {
			{ }
		};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits snapshot = { };

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_fill_self_config_defaults(entries);
	entries[0].value_u32 = 1000U;
	entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)].name =
		unknown_name;
	entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)].name_len =
		sizeof(unknown_name) - 1;
	entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)].value_kind =
		PKM_LCS_SELF_CONFIG_VALUE_DWORD;
	entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)].value_type =
		REG_DWORD;
	entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)].value_u32 =
		123U;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_apply_self_config(
				entries, ARRAY_SIZE(entries), &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.applied_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults));
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.ignored_unknown_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 1000U);
	KUNIT_EXPECT_EQ(test, snapshot.max_value_size, 1048576U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_apply_invalid_retains_and_audits(
	struct kunit *test)
{
	struct pkm_lcs_self_config_entry
		entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)] = {
			{ }
		};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits active_limits = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	u8 buffer[2048];
	size_t written = 0;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&active_limits), 0L);
	active_limits.transaction_timeout_ms = 45000U;
	active_limits.max_value_size = 8192U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&active_limits), 0L);

	pkm_lcs_kunit_fill_self_config_defaults(entries);
	entries[1].value_kind = PKM_LCS_SELF_CONFIG_VALUE_WRONG_TYPE;
	entries[1].value_type = REG_SZ;
	entries[1].value_u32 = 0U;
	entries[4].value_u32 = 4095U;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_apply_self_config(
				entries, ARRAY_SIZE(entries), &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.applied_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults) -
				2U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 2U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 2U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.transaction_timeout_ms, 45000U);
	KUNIT_EXPECT_EQ(test, snapshot.max_value_size, 8192U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &kmes_snapshot),
			0);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, "TransactionTimeoutMs"));
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, "MaxValueSize"));
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, "wrong_type"));
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
				      buffer, written, "dword_out_of_range"));
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_apply_missing_retains_and_audits(
	struct kunit *test)
{
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits snapshot = { };

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_apply_self_config(NULL, 0,
								 &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults));
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults));
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	pkm_lcs_kunit_expect_runtime_limits_defaults(test, &snapshot);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_apply_malformed_input_fails_closed(
	struct kunit *test)
{
	struct pkm_lcs_self_config_entry
		entries[ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults)] = {
			{ }
		};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits active_limits = { };
	struct pkm_lcs_runtime_limits snapshot = { };

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&active_limits), 0L);
	active_limits.request_timeout_ms = 45000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&active_limits), 0L);

	pkm_lcs_kunit_fill_self_config_defaults(entries);
	entries[0].value_kind = PKM_LCS_SELF_CONFIG_VALUE_DWORD;
	entries[0].value_type = REG_SZ;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_apply_self_config(
				entries, ARRAY_SIZE(entries), &plan),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 45000U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_apply_self_config(entries, 1,
								 NULL),
			(long)-EINVAL);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_refresh_from_source_hot_swaps(
	struct kunit *test)
{
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x52 };
	static const char value_name[] = "RequestTimeoutMs";
	u8 data[sizeof(u32)];
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = registry_guid,
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_DWORD,
		.query_all = true,
	};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	put_unaligned_le32(1000U, data);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-config-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_runtime_limits_refresh_self_config_from_key(
		1, registry_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults) -
				1U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults) -
				1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 1000U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_refresh_from_source_wrong_type_retains(
	struct kunit *test)
{
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x53 };
	static const char value_name[] = "RequestTimeoutMs";
	static const u8 data[] = { 0x01 };
	struct pkm_lcs_runtime_limits active_limits = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = registry_guid,
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = REG_BINARY,
		.query_all = true,
	};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&active_limits),
			0L);
	active_limits.request_timeout_ms = 45000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&active_limits),
			0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-config-wrong");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_runtime_limits_refresh_self_config_from_key(
		1, registry_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults) -
				1U);
	KUNIT_EXPECT_EQ(test, plan.retained_invalid_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.audit_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults));
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 45000U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_refresh_malformed_source_retains(
	struct kunit *test)
{
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x54 };
	static const char value_name[] = "RequestTimeoutMs";
	static const u8 data[] = { 0x01 };
	struct pkm_lcs_runtime_limits active_limits = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = registry_guid,
		.expected_value_name = "",
		.response_value_name = value_name,
		.layer_name = "base",
		.data = data,
		.data_len = sizeof(data),
		.value_type = 0xffffffffU,
		.query_all = true,
	};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&active_limits),
			0L);
	active_limits.request_timeout_ms = 45000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&active_limits),
			0L);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-config-malformed");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_runtime_limits_refresh_self_config_from_key(
		1, registry_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 45000U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_machine_hive_discovers_registry(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x61 };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x62 };
	static const u8 registry_guid[RSI_GUID_SIZE] = { 0x63 };
	static const char value_name[] = "RequestTimeoutMs";
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .guid = registry_guid },
	};
	u8 data[sizeof(u32)];
	struct pkm_lcs_kunit_walk_then_query_values_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.query = {
			.expected_guid = registry_guid,
			.expected_value_name = "",
			.response_value_name = value_name,
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = REG_DWORD,
			.query_all = true,
		},
		.expect_query = true,
	};
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	put_unaligned_le32(1000U, data);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-config-discover");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
		1, machine_root_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 1U);
	KUNIT_EXPECT_EQ(test, plan.retained_missing_count,
			(u32)ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults) -
				1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms, 1000U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_missing_registry_retains_defaults(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x64 };
	static const u8 system_guid[RSI_GUID_SIZE] = { 0x65 };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "System", .guid = system_guid },
		{ .expected_child = "Registry", .empty = true },
	};
	struct pkm_lcs_kunit_walk_then_query_values_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
	};
	struct pkm_lcs_self_config_apply_plan plan = {
		.applied_count = 99U,
	};
	struct pkm_lcs_runtime_limits snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-config-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
		1, machine_root_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_missing_system_retains_defaults(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x67 };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "System", .empty = true },
	};
	struct pkm_lcs_kunit_walk_then_query_values_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
	};
	struct pkm_lcs_self_config_apply_plan plan = {
		.applied_count = 99U,
	};
	struct pkm_lcs_runtime_limits snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_kmes_kunit_reset_all();
	pkm_lcs_runtime_limits_reset_defaults();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_walk_then_query_values_source_thread, &script,
		"pkm-lcs-kunit-self-config-no-system");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
		1, machine_root_guid, &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	KUNIT_EXPECT_EQ(test, plan.audit_count, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_snapshot(&snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.request_timeout_ms,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_self_config_machine_hive_bad_inputs_fail_closed(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 0x66 };
	struct pkm_lcs_self_config_apply_plan plan = {
		.applied_count = 99U,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
				0, machine_root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
	plan.applied_count = 99U;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
				1, NULL, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.applied_count, 0U);
}


static void pkm_lcs_kunit_runtime_request_timeout_uses_snapshot(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_request_timeout_ms(), 30000U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 12345U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_request_timeout_ms(), 12345U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_runtime_transaction_timeout_uses_snapshot(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_transaction_timeout_ms(), 30000U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.transaction_timeout_ms = 54321U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_transaction_timeout_ms(), 54321U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_runtime_symlink_depth_uses_snapshot(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_symlink_depth_limit(), 16U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.symlink_depth_limit = 7U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_symlink_depth_limit(), 7U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_runtime_max_key_depth_uses_snapshot(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_max_key_depth(), 512U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_key_depth = 33U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_max_key_depth(), 33U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_runtime_path_component_limit_relative(
	struct kunit *test)
{
	static const char path_src[] =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 64U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 0U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_runtime_total_path_limit_absolute(
	struct kunit *test)
{
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_materialized_path path = { };
	char path_src[1026];
	size_t offset;

	memcpy(path_src, "Machine", sizeof("Machine") - 1);
	offset = sizeof("Machine") - 1;
	while (offset < sizeof(path_src) - 1) {
		path_src[offset++] = '\\';
		if (offset < sizeof(path_src) - 1)
			path_src[offset++] = 'a';
	}
	path_src[sizeof(path_src) - 1] = '\0';

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_total_path_length = 1024U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, path_src, sizeof(path_src), false, &path),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
	KUNIT_EXPECT_EQ(test, path.component_count, 0U);
	KUNIT_EXPECT_EQ(test, path.string_bytes, 0U);
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_source_down_marks_bound_transaction(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x78
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_table_snapshot source_snapshot = { };
	struct pkm_lcs_transaction_read_plan read_plan = { };
	struct reg_txn_status_args status = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_transaction_fd_publish(30000);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_source_table_snapshot(&source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.down_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_SOURCE_DOWN);
	KUNIT_EXPECT_FALSE(test, txn_snapshot.timer_pending);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status),
			0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_SOURCE_DOWN);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EIO);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd), -EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, root_guid, &read_plan),
			-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_down_ignores_unbound_transaction(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct file file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_transaction_fd_publish(30000);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_TRUE(test, txn_snapshot.timer_pending);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_live_base_layer_write_uses_cached_sd(
	struct kunit *test)
{
	static const u8 base_metadata_guid[RSI_GUID_SIZE] = { 0x4b, 0x36 };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = 4,
		.implicit_base = 1,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *admin_token;
	const void *service_token;
	const u8 *sd;
	size_t sd_len = 0;

	pkm_lcs_kunit_reset_layer_table();
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	service_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, 0);
	KUNIT_ASSERT_NOT_NULL(test, service_token);
	sd = kacs_rust_kunit_create_file_sd(service_token, KEY_QUERY_VALUE, 0,
					    0, 0, &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_base_layer_metadata_publish(
				base_metadata_guid, sd, sd_len),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_live_layer_write_access_check_for_token(
				admin_token, &target, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);

	pkm_lcs_kunit_reset_layer_table();
	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_live_layer_write_access_check_for_token(
				admin_token, &target, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(service_token);
	kacs_rust_token_drop(admin_token);
	pkm_lcs_kunit_reset_layer_table();
}


static void pkm_lcs_kunit_source_enum_children_round_trip_retains_frame(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xe1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xe2 };
	struct pkm_lcs_kunit_enum_children_source_script script = {
		.expected_parent_guid = parent_guid,
		.child_name = "Child",
		.child_guid = child_guid,
		.sequence = 0,
	};
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_enum_children_source_thread,
			   &script, "pkm-lcs-kunit-enum-children");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout(
				1, 0, parent_guid,
				PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame,
				&response, &enqueue),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_ENUM_CHILDREN);
	KUNIT_ASSERT_NOT_NULL(test, frame.data);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_enum_children_info_summary(
				frame.data, frame.len, response.request_id, 1,
				layers, ARRAY_SIZE(layers), NULL, 0,
				&response.limits, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.source_path_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.subkey_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.max_subkey_name_len, 5U);

	pkm_lcs_source_response_frame_destroy(&frame);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_query_values_round_trip_retains_frame(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	static const u8 target[] = "Machine\\RoundTrip";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = guid,
		.expected_value_name = "",
		.value_type = REG_LINK,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_query_value_result result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-values");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
				1, 0, guid, "", 0, false,
				PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame,
				&response, &enqueue),
			0L);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_QUERY_VALUES);
	KUNIT_ASSERT_NOT_NULL(test, frame.data);
	KUNIT_ASSERT_EQ(test,
				pkm_lcs_rsi_materialize_query_value_response(
					frame.data, frame.len, response.request_id, 1,
					"", 0, layers, ARRAY_SIZE(layers), NULL, 0,
					NULL, &result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.value_type, (u32)REG_LINK);
	KUNIT_EXPECT_EQ(test, result.layer_len, 4U);
	KUNIT_ASSERT_NOT_NULL(test, result.layer);
	KUNIT_EXPECT_EQ(test, memcmp(result.layer, "base", 4), 0);
	KUNIT_EXPECT_EQ(test, result.data_len, (u32)(sizeof(target) - 1));
	KUNIT_EXPECT_EQ(test,
			memcmp(frame.data + result.data_offset, target,
			       sizeof(target) - 1),
			0);

	pkm_lcs_source_response_frame_destroy(&frame);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_read_returns_complete_frame(
	struct kunit *test)
{
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 frame[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 101,
					 "Child", &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.len, frame_len);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 101ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);

	memset(out, 0xaa, sizeof(out));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, frame, frame_len), 0);
	KUNIT_EXPECT_EQ(test, out[frame_len], 0xaaU);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_read_preserves_fifo_order(
	struct kunit *test)
{
	u8 frame1[96];
	u8 frame2[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame1_len;
	size_t frame2_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_build_lookup_frame(test, frame1, sizeof(frame1), 201,
					 "First", &frame1_len);
	pkm_lcs_kunit_build_lookup_frame(test, frame2, sizeof(frame2), 202,
					 "Second", &frame2_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame1, frame1_len,
						       NULL),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame2, frame2_len,
						       NULL),
			0L);

	memset(out, 0, sizeof(out));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame1_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, frame1, frame1_len), 0);

	memset(out, 0, sizeof(out));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame2_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, frame2, frame2_len), 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_read_short_buffer_preserves_queue(
	struct kunit *test)
{
	u8 frame[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 301,
					 "Child", &frame_len);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			0L);

	memset(out, 0xaa, sizeof(out));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      frame_len - 1,
							      true),
			(ssize_t)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, out[0], 0xaaU);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, frame, frame_len), 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_read_fault_preserves_queue(
	struct kunit *test)
{
	u8 frame[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 401,
					 "Child", &frame_len);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, NULL,
							      sizeof(out),
							      true),
			(ssize_t)-EFAULT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, frame, frame_len), 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_blocking_read_wakes_on_enqueue(
	struct kunit *test)
{
	struct pkm_lcs_kunit_blocking_source_read_script script = { };
	struct task_struct *task;
	struct pkm_lcs_source_fd *source_fd;
	u8 frame[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame_len;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);

	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 451,
					 "Blocked", &frame_len);
	memset(out, 0xaa, sizeof(out));
	init_completion(&script.started);
	init_completion(&script.done);
	script.file = &file;
	script.buf = out;
	script.buf_len = sizeof(out);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blocking_source_read_thread, &script,
		"pkm-lcs-blocking-source-read");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start blocking source-read worker");
		goto out_release_source;
	}
	if (!wait_for_completion_timeout(&script.started, HZ)) {
		pkm_lcs_kunit_source_fd_force_closing(source_fd);
		KUNIT_FAIL(test, "blocking source-read worker did not start");
		goto out_stop_task;
	}
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&script.done,
						    msecs_to_jiffies(20)),
			0UL);

	ret = pkm_lcs_source_enqueue_request(1, frame, frame_len, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret) {
		pkm_lcs_kunit_source_fd_force_closing(source_fd);
		goto out_stop_task;
	}
	if (!wait_for_completion_timeout(&script.done, HZ)) {
		pkm_lcs_kunit_source_fd_force_closing(source_fd);
		KUNIT_FAIL(test, "blocking source read did not wake on enqueue");
	}

out_stop_task:
	ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!completion_done(&script.done))
		goto out_release_source;

	KUNIT_EXPECT_EQ(test, script.ret, (ssize_t)frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(out, frame, frame_len), 0);
	KUNIT_EXPECT_EQ(test, out[frame_len], 0xaaU);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)-EAGAIN);

out_release_source:
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_blocking_read_wakes_on_closing(
	struct kunit *test)
{
	struct pkm_lcs_kunit_blocking_source_read_script script = { };
	struct task_struct *task;
	struct pkm_lcs_source_fd *source_fd;
	u8 out[128];
	struct file file = { };
	const void *token;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);

	memset(out, 0xaa, sizeof(out));
	init_completion(&script.started);
	init_completion(&script.done);
	script.file = &file;
	script.buf = out;
	script.buf_len = sizeof(out);

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blocking_source_read_thread, &script,
		"pkm-lcs-closing-source-read");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start closing source-read worker");
		goto out_release_source;
	}
	if (!wait_for_completion_timeout(&script.started, HZ)) {
		pkm_lcs_kunit_source_fd_force_closing(source_fd);
		KUNIT_FAIL(test, "closing source-read worker did not start");
		goto out_stop_task;
	}
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&script.done,
						    msecs_to_jiffies(20)),
			0UL);

	pkm_lcs_kunit_source_fd_force_closing(source_fd);
	if (!wait_for_completion_timeout(&script.done, HZ))
		KUNIT_FAIL(test, "blocking source read did not wake on close");

out_stop_task:
	ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!completion_done(&script.done))
		goto out_release_source;

	KUNIT_EXPECT_EQ(test, script.ret, (ssize_t)0);
	KUNIT_EXPECT_EQ(test, out[0], 0xaaU);

out_release_source:
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_request_enqueue_rejects_bad_state(
	struct kunit *test)
{
	u8 frame[96];
	u8 short_frame[4] = { };
	struct pkm_lcs_source_enqueue_result enqueue = {
		.len = 1,
		.request_id = 2,
		.op_code = 3,
		.queue_depth = 4,
	};
	struct file file = { };
	const void *token;
	size_t frame_len;

	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 501,
					 "Child", &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       &enqueue),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, enqueue.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 0U);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, short_frame,
						       sizeof(short_frame),
						       &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, enqueue.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       &enqueue),
			(long)-EIO);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_lookup_allocates_monotonic_ids(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x61 };
	struct pkm_lcs_source_enqueue_result first = { };
	struct pkm_lcs_source_enqueue_result second = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x4445464748494a4bULL, parent_guid,
				"First", strlen("First"), &first),
			0L);
	KUNIT_EXPECT_EQ(test, first.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, first.txn_id, 0x4445464748494a4bULL);
	KUNIT_EXPECT_EQ(test, first.op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, first.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, first.in_flight_count, 1U);
	KUNIT_EXPECT_EQ(test, first.next_request_id, 1ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x55565758595a5b5cULL, parent_guid,
				"Second", strlen("Second"), &second),
			0L);
	KUNIT_EXPECT_EQ(test, second.request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, second.txn_id, 0x55565758595a5b5cULL);
	KUNIT_EXPECT_EQ(test, second.op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, second.queue_depth, 2U);
	KUNIT_EXPECT_EQ(test, second.in_flight_count, 2U);
	KUNIT_EXPECT_EQ(test, second.next_request_id, 2ULL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 2U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 2U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)first.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x4445464748494a4bULL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 2U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_create_entry_frame(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const char child_name[] = "Created";
	static const char layer_name[] = "base";
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	size_t payload_offset;
	size_t child_offset;
	size_t layer_offset;
	size_t guid_offset;
	size_t sequence_offset;
	u8 out[160];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_create_entry_request(
				1, 0x6162636465666768ULL, parent_guid,
				child_name, strlen(child_name), layer_name,
				strlen(layer_name), child_guid,
				0x0102030405060708ULL, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0x6162636465666768ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_CREATE_ENTRY);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.next_request_id, 1ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_CREATE_ENTRY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x6162636465666768ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, parent_guid,
			       RSI_GUID_SIZE),
			0);
	child_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + child_offset),
			(u32)strlen(child_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + child_offset + RSI_LENGTH_PREFIX_SIZE,
			       child_name, strlen(child_name)),
			0);
	layer_offset = child_offset + RSI_LENGTH_PREFIX_SIZE +
		       strlen(child_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	guid_offset = layer_offset + RSI_LENGTH_PREFIX_SIZE +
		      strlen(layer_name);
	KUNIT_EXPECT_EQ(test,
			memcmp(out + guid_offset, child_guid, RSI_GUID_SIZE),
			0);
	sequence_offset = guid_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + sequence_offset),
			0x0102030405060708ULL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_hide_delete_entry_frames(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
	};
	static const char hide_name[] = "Hidden";
	static const char delete_name[] = "Deleted";
	static const char layer_name[] = "base";
	struct pkm_lcs_source_enqueue_result hide = { };
	struct pkm_lcs_source_enqueue_result del = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	size_t payload_offset;
	size_t child_offset;
	size_t layer_offset;
	size_t sequence_offset;
	u8 out[160];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_hide_entry_request(
				1, 0x1112131415161718ULL, parent_guid,
				hide_name, strlen(hide_name), layer_name,
				strlen(layer_name), 0x2122232425262728ULL,
				&hide),
			0L);
	KUNIT_EXPECT_EQ(test, hide.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, hide.txn_id, 0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test, hide.op_code, (u16)RSI_HIDE_ENTRY);
	KUNIT_EXPECT_EQ(test, hide.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, hide.in_flight_count, 1U);
	KUNIT_EXPECT_EQ(test, hide.next_request_id, 1ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)hide.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)hide.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_HIDE_ENTRY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x1112131415161718ULL);
	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, parent_guid,
			       RSI_GUID_SIZE),
			0);
	child_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + child_offset),
			(u32)strlen(hide_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + child_offset + RSI_LENGTH_PREFIX_SIZE,
			       hide_name, strlen(hide_name)),
			0);
	layer_offset = child_offset + RSI_LENGTH_PREFIX_SIZE +
		       strlen(hide_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	sequence_offset = layer_offset + RSI_LENGTH_PREFIX_SIZE +
			  strlen(layer_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + sequence_offset),
			0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test, sequence_offset + sizeof(u64), hide.len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_delete_entry_request(
				1, 0x3132333435363738ULL, parent_guid,
				delete_name, strlen(delete_name), layer_name,
				strlen(layer_name), &del),
			0L);
	KUNIT_EXPECT_EQ(test, del.request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, del.txn_id, 0x3132333435363738ULL);
	KUNIT_EXPECT_EQ(test, del.op_code, (u16)RSI_DELETE_ENTRY);
	KUNIT_EXPECT_EQ(test, del.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, del.in_flight_count, 2U);
	KUNIT_EXPECT_EQ(test, del.next_request_id, 2ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)del.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DELETE_ENTRY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x3132333435363738ULL);
	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, parent_guid,
			       RSI_GUID_SIZE),
			0);
	child_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + child_offset),
			(u32)strlen(delete_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + child_offset + RSI_LENGTH_PREFIX_SIZE,
			       delete_name, strlen(delete_name)),
			0);
	layer_offset = child_offset + RSI_LENGTH_PREFIX_SIZE +
		       strlen(delete_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	KUNIT_EXPECT_EQ(test,
			layer_offset + RSI_LENGTH_PREFIX_SIZE +
				strlen(layer_name),
			del.len);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 2U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_hide_delete_entry_round_trip_statuses(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
	};
	static const char child_name[] = "Child";
	static const char layer_name[] = "base";
	struct pkm_lcs_kunit_path_entry_source_script script = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_parent_guid = parent_guid;
	script.expected_child_name = child_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x1111111111111111ULL;
	script.expected_sequence = 0x2222222222222222ULL;
	script.expected_op_code = RSI_HIDE_ENTRY;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_path_entry_source_thread,
					 &script, "pkm-lcs-kunit-hide-entry");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_hide_entry_round_trip_timeout(
		1, script.expected_txn_id, parent_guid, child_name,
		strlen(child_name), layer_name, strlen(layer_name),
		script.expected_sequence, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_HIDE_ENTRY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_parent_guid = parent_guid;
	script.expected_child_name = child_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x3333333333333333ULL;
	script.expected_op_code = RSI_DELETE_ENTRY;
	script.status = RSI_NOT_FOUND;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_path_entry_source_thread,
					 &script, "pkm-lcs-kunit-delete-entry");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_entry_round_trip_timeout(
		1, script.expected_txn_id, parent_guid, child_name,
		strlen(child_name), layer_name, strlen(layer_name), 1000,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_ENTRY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_NOT_FOUND);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_parent_guid = parent_guid;
	script.expected_child_name = child_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x4444444444444444ULL;
	script.expected_sequence = 0x5555555555555555ULL;
	script.expected_op_code = RSI_HIDE_ENTRY;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_path_entry_source_thread,
					 &script,
					 "pkm-lcs-kunit-hide-entry-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_hide_entry_round_trip_timeout(
		1, script.expected_txn_id, parent_guid, child_name,
		strlen(child_name), layer_name, strlen(layer_name),
		script.expected_sequence, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_HIDE_ENTRY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_create_key_frame(struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const char name[] = "Created";
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80, 0x30, 0x00 };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset;
	size_t name_offset;
	size_t parent_offset;
	size_t sd_offset;
	size_t flags_offset;
	u8 out[160];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_create_key_request(
				1, 0x7172737475767778ULL, guid, name,
				strlen(name), parent_guid, sd, sizeof(sd),
				true, false, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0x7172737475767778ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_CREATE_KEY);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_CREATE_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x7172737475767778ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, guid, RSI_GUID_SIZE),
			0);
	name_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + name_offset),
			(u32)strlen(name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + name_offset + RSI_LENGTH_PREFIX_SIZE,
			       name, strlen(name)),
			0);
	parent_offset = name_offset + RSI_LENGTH_PREFIX_SIZE + strlen(name);
	KUNIT_EXPECT_EQ(test,
			memcmp(out + parent_offset, parent_guid,
			       RSI_GUID_SIZE),
			0);
	sd_offset = parent_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + sd_offset),
			(u32)sizeof(sd));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + sd_offset + RSI_LENGTH_PREFIX_SIZE, sd,
			       sizeof(sd)),
			0);
	flags_offset = sd_offset + RSI_LENGTH_PREFIX_SIZE + sizeof(sd);
	KUNIT_EXPECT_EQ(test, out[flags_offset], 1U);
	KUNIT_EXPECT_EQ(test, out[flags_offset + 1], 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_create_frames_use_runtime_limits(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x5a };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x5b };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	enum { LONG_NAME_LEN = 300 };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_rsi_built_request built = { };
	char long_child[LONG_NAME_LEN + 1];
	char long_layer[LONG_NAME_LEN + 1];
	u8 frame[1024];

	memset(long_child, 'C', LONG_NAME_LEN);
	long_child[LONG_NAME_LEN] = '\0';
	memset(long_layer, 'L', LONG_NAME_LEN);
	long_layer[LONG_NAME_LEN] = '\0';

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_create_entry_request(
				frame, sizeof(frame), 1, 0, parent_guid,
				long_child, LONG_NAME_LEN, "base",
				strlen("base"), child_guid, 7, &limits, &built),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_create_entry_request(
				frame, sizeof(frame), 1, 0, parent_guid,
				"Child", strlen("Child"), long_layer,
				LONG_NAME_LEN, child_guid, 7, &limits, &built),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_create_key_request(
				frame, sizeof(frame), 2, 0, child_guid,
				long_child, LONG_NAME_LEN, parent_guid, sd,
				sizeof(sd), false, false, &limits, &built),
			(long)-ENAMETOOLONG);

	limits.max_path_component_length = LONG_NAME_LEN;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_create_entry_request(
				frame, sizeof(frame), 3, 0, parent_guid,
				long_child, LONG_NAME_LEN, long_layer,
				LONG_NAME_LEN, child_guid, 9, &limits, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.request_id, 3ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_CREATE_ENTRY);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_create_key_request(
				frame, sizeof(frame), 4, 0, child_guid,
				long_child, LONG_NAME_LEN, parent_guid, sd,
				sizeof(sd), true, false, &limits, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.request_id, 4ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_CREATE_KEY);
}


static void pkm_lcs_kunit_source_dispatch_write_key_frame(struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 sd[] = {
		0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00,
		0x11, 0x22, 0x33, 0x44,
	};
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset;
	size_t field_mask_offset;
	size_t sd_offset;
	size_t last_write_offset;
	u8 out[160];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_write_key_request(
				1, 0x8182838485868788ULL, guid, sd,
				sizeof(sd), 0x1122334455667788ULL, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0x8182838485868788ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_WRITE_KEY);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_WRITE_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x8182838485868788ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, guid, RSI_GUID_SIZE),
			0);
	field_mask_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + field_mask_offset),
			(u32)(RSI_WRITE_KEY_FIELD_SD |
			      RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME));
	sd_offset = field_mask_offset + sizeof(u32);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + sd_offset),
			(u32)sizeof(sd));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + sd_offset + RSI_LENGTH_PREFIX_SIZE, sd,
			       sizeof(sd)),
			0);
	last_write_offset = sd_offset + RSI_LENGTH_PREFIX_SIZE + sizeof(sd);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + last_write_offset),
			0x1122334455667788ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_set_value_frame(struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	static const char value_name[] = "Value";
	static const char layer_name[] = "base";
	static const u8 data[] = { 0xde, 0xad, 0xbe, 0xef };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset;
	size_t value_offset;
	size_t layer_offset;
	size_t type_offset;
	size_t data_offset;
	size_t sequence_offset;
	size_t expected_sequence_offset;
	u8 out[160];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0x9192939495969798ULL, guid, value_name,
				strlen(value_name), layer_name,
				strlen(layer_name), REG_BINARY, data,
				sizeof(data), 0x0102030405060708ULL,
				0x1112131415161718ULL, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0x9192939495969798ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_SET_VALUE);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_SET_VALUE);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x9192939495969798ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, guid, RSI_GUID_SIZE),
			0);
	value_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + value_offset),
			(u32)strlen(value_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + value_offset + RSI_LENGTH_PREFIX_SIZE,
			       value_name, strlen(value_name)),
			0);
	layer_offset = value_offset + RSI_LENGTH_PREFIX_SIZE +
		       strlen(value_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	type_offset = layer_offset + RSI_LENGTH_PREFIX_SIZE +
		      strlen(layer_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + type_offset),
			(u32)REG_BINARY);
	data_offset = type_offset + sizeof(u32);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + data_offset),
			(u32)sizeof(data));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + data_offset + RSI_LENGTH_PREFIX_SIZE,
			       data, sizeof(data)),
			0);
	sequence_offset = data_offset + RSI_LENGTH_PREFIX_SIZE +
			  sizeof(data);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + sequence_offset),
			0x0102030405060708ULL);
	expected_sequence_offset = sequence_offset + sizeof(u64);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + expected_sequence_offset),
			0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test,
			expected_sequence_offset + sizeof(u64), enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_set_value_round_trip_statuses(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0x51 };
	static const char value_name[] = "Value";
	static const char layer_name[] = "base";
	static const u8 data[] = { 0x01, 0x02, 0x03 };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_set_value_source_script script = { };
	struct file file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_guid = guid;
	script.expected_value_name = value_name;
	script.expected_layer_name = layer_name;
	script.expected_data = data;
	script.expected_data_len = sizeof(data);
	script.expected_value_type = REG_BINARY;
	script.expected_txn_id = 0xa1a2a3a4a5a6a7a8ULL;
	script.expected_sequence = 0xb1b2b3b4b5b6b7b8ULL;
	script.expected_expected_sequence = 0xc1c2c3c4c5c6c7c8ULL;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_source_thread, &script,
			   "pkm-lcs-kunit-set-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_value_round_trip_timeout(
		1, script.expected_txn_id, guid, value_name,
		strlen(value_name), layer_name, strlen(layer_name),
		REG_BINARY, data, sizeof(data), script.expected_sequence,
		script.expected_expected_sequence, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_SET_VALUE);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_value_name = value_name;
	script.expected_layer_name = layer_name;
	script.expected_data = data;
	script.expected_data_len = sizeof(data);
	script.expected_value_type = REG_BINARY;
	script.expected_txn_id = 0xd1d2d3d4d5d6d7d8ULL;
	script.expected_sequence = 0xe1e2e3e4e5e6e7e8ULL;
	script.expected_expected_sequence = 0xf1f2f3f4f5f6f7f8ULL;
	script.status = RSI_CAS_FAILED;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_source_thread, &script,
			   "pkm-lcs-kunit-set-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_value_round_trip_timeout(
		1, script.expected_txn_id, guid, value_name,
		strlen(value_name), layer_name, strlen(layer_name),
		REG_BINARY, data, sizeof(data), script.expected_sequence,
		script.expected_expected_sequence, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EAGAIN);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_SET_VALUE);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_CAS_FAILED);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_value_name = "";
	script.expected_layer_name = layer_name;
	script.expected_value_type = REG_TOMBSTONE;
	script.expected_txn_id = 0x0101010101010101ULL;
	script.expected_sequence = 0x0202020202020202ULL;
	script.expected_expected_sequence = 0x0303030303030303ULL;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_source_thread, &script,
			   "pkm-lcs-kunit-set-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_value_round_trip_timeout(
		1, script.expected_txn_id, guid, "", 0, layer_name,
		strlen(layer_name), REG_TOMBSTONE, NULL, 0,
		script.expected_sequence, script.expected_expected_sequence,
		1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_SET_VALUE);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_delete_value_entry_frame(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	static const char value_name[] = "Value";
	static const char layer_name[] = "base";
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset;
	size_t value_offset;
	size_t layer_offset;
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_delete_value_entry_request(
				1, 0xa9a8a7a6a5a4a3a2ULL, guid,
				value_name, strlen(value_name), layer_name,
				strlen(layer_name), &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0xa9a8a7a6a5a4a3a2ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code,
			(u16)RSI_DELETE_VALUE_ENTRY);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DELETE_VALUE_ENTRY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0xa9a8a7a6a5a4a3a2ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, guid, RSI_GUID_SIZE),
			0);
	value_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + value_offset),
			(u32)strlen(value_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + value_offset + RSI_LENGTH_PREFIX_SIZE,
			       value_name, strlen(value_name)),
			0);
	layer_offset = value_offset + RSI_LENGTH_PREFIX_SIZE +
		       strlen(value_name);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	KUNIT_EXPECT_EQ(test,
			layer_offset + RSI_LENGTH_PREFIX_SIZE +
				strlen(layer_name),
			enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_delete_value_entry_round_trip_statuses(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0x61 };
	static const char value_name[] = "Value";
	static const char layer_name[] = "base";
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_delete_value_source_script script = { };
	struct file file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_guid = guid;
	script.expected_value_name = value_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0xb1b2b3b4b5b6b7b8ULL;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_source_thread,
			   &script, "pkm-lcs-kunit-del-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_value_entry_round_trip_timeout(
		1, script.expected_txn_id, guid, value_name,
		strlen(value_name), layer_name, strlen(layer_name), 1000,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_VALUE_ENTRY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_value_name = value_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0xc1c2c3c4c5c6c7c8ULL;
	script.status = RSI_STORAGE_ERROR;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_source_thread,
			   &script, "pkm-lcs-kunit-del-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_value_entry_round_trip_timeout(
		1, script.expected_txn_id, guid, value_name,
		strlen(value_name), layer_name, strlen(layer_name), 1000,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_VALUE_ENTRY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_STORAGE_ERROR);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_value_name = "";
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0xd1d2d3d4d5d6d7d8ULL;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_delete_value_source_thread,
			   &script, "pkm-lcs-kunit-del-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_value_entry_round_trip_timeout(
		1, script.expected_txn_id, guid, "", 0, layer_name,
		strlen(layer_name), 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_VALUE_ENTRY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_set_blanket_tombstone_frame(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
	};
	static const char layer_name[] = "policy";
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset;
	size_t layer_offset;
	size_t set_offset;
	size_t sequence_offset;
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_set_blanket_tombstone_request(
				1, 0xb9b8b7b6b5b4b3b2ULL, guid,
				layer_name, strlen(layer_name), true,
				0x0102030405060708ULL, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0xb9b8b7b6b5b4b3b2ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code,
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0xb9b8b7b6b5b4b3b2ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, guid, RSI_GUID_SIZE),
			0);
	layer_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	set_offset = layer_offset + RSI_LENGTH_PREFIX_SIZE +
		     strlen(layer_name);
	KUNIT_EXPECT_EQ(test, out[set_offset], (u8)1);
	sequence_offset = set_offset + sizeof(u8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + sequence_offset),
			0x0102030405060708ULL);
	KUNIT_EXPECT_EQ(test, sequence_offset + sizeof(u64), enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_dispatch_set_blanket_tombstone_runtime_limits_frame(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81,
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset;
	size_t layer_offset;
	size_t set_offset;
	size_t sequence_offset;
	struct file file = { };
	const void *token;
	char layer_name[301];
	u8 out[512];

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 300U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	memset(layer_name, 'l', sizeof(layer_name) - 1);
	layer_name[sizeof(layer_name) - 1] = '\0';

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_set_blanket_tombstone_request(
				1, 0xb9b8b7b6b5b4b3b3ULL, guid,
				layer_name, sizeof(layer_name) - 1, true,
				0x0102030405060709ULL, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0xb9b8b7b6b5b4b3b3ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code,
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0xb9b8b7b6b5b4b3b3ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset, guid, RSI_GUID_SIZE),
			0);
	layer_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + layer_offset),
			(u32)(sizeof(layer_name) - 1));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + layer_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, sizeof(layer_name) - 1),
			0);
	set_offset = layer_offset + RSI_LENGTH_PREFIX_SIZE +
		     sizeof(layer_name) - 1;
	KUNIT_EXPECT_EQ(test, out[set_offset], (u8)1);
	sequence_offset = set_offset + sizeof(u8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + sequence_offset),
			0x0102030405060709ULL);
	KUNIT_EXPECT_EQ(test, sequence_offset + sizeof(u64), enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_set_blanket_tombstone_round_trip_statuses(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0x81 };
	static const char layer_name[] = "base";
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_blanket_tombstone_source_script script = { };
	struct file file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_guid = guid;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0xe1e2e3e4e5e6e7e8ULL;
	script.expected_set = true;
	script.expected_sequence = 0xf1f2f3f4f5f6f7f8ULL;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_source_thread, &script,
		"pkm-lcs-kunit-blanket-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_blanket_tombstone_round_trip_timeout(
		1, script.expected_txn_id, guid, layer_name,
		strlen(layer_name), true, script.expected_sequence, 1000,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x1112131415161718ULL;
	script.expected_set = false;
	script.expected_sequence = 0;
	script.status = RSI_STORAGE_ERROR;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_source_thread, &script,
		"pkm-lcs-kunit-blanket-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_blanket_tombstone_round_trip_timeout(
		1, script.expected_txn_id, guid, layer_name,
		strlen(layer_name), false, 0, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_STORAGE_ERROR);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x2122232425262728ULL;
	script.expected_set = true;
	script.expected_sequence = 0x3132333435363738ULL;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_blanket_tombstone_source_thread, &script,
		"pkm-lcs-kunit-blanket-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_blanket_tombstone_round_trip_timeout(
		1, script.expected_txn_id, guid, layer_name,
		strlen(layer_name), true, script.expected_sequence, 1000,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_SET_BLANKET_TOMBSTONE);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_dispatch_set_blanket_tombstone_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0x91 };
	static const char bad_layer_name[] = { 'b', '\\', 'd' };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_blanket_tombstone_request(
				1, 0, NULL, "base", strlen("base"), true, 1,
				&enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_blanket_tombstone_request(
				1, 0, guid, NULL, strlen("base"), true, 1,
				&enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_blanket_tombstone_request(
				1, 0, guid, bad_layer_name,
				sizeof(bad_layer_name), true, 1, &enqueue),
			(long)-EINVAL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_flush_frame(struct kunit *test)
{
	static const char hive_name[] = "Machine";
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_flush_request(
				1, hive_name, strlen(hive_name), &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + payload_offset),
			(u32)strlen(hive_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset + RSI_LENGTH_PREFIX_SIZE,
			       hive_name, strlen(hive_name)),
			0);
	KUNIT_EXPECT_EQ(test,
			payload_offset + RSI_LENGTH_PREFIX_SIZE +
				strlen(hive_name),
			enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_flush_round_trip_statuses(struct kunit *test)
{
	static const char hive_name[] = "Machine";
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_flush_source_script script = { };
	struct file file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_hive_name = hive_name;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_flush_source_thread, &script,
			   "pkm-lcs-kunit-flush-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_flush_round_trip_timeout(
		1, hive_name, strlen(hive_name), 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_hive_name = hive_name;
	script.status = RSI_STORAGE_ERROR;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_flush_source_thread, &script,
			   "pkm-lcs-kunit-flush-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_flush_round_trip_timeout(
		1, hive_name, strlen(hive_name), 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_STORAGE_ERROR);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_hive_name = hive_name;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_flush_source_thread, &script,
			   "pkm-lcs-kunit-flush-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_flush_round_trip_timeout(
		1, hive_name, strlen(hive_name), 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_drop_key_frame(struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_drop_key_request(
				1, 0x3132333435363738ULL, guid, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0x3132333435363738ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x3132333435363738ULL);
	KUNIT_EXPECT_EQ(test, memcmp(out + payload_offset, guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, payload_offset + RSI_GUID_SIZE, enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_drop_key_round_trip_statuses(struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_drop_key_source_script script = { };
	struct file file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_guid = guid;
	script.expected_txn_id = 0;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_drop_key_source_thread, &script,
			   "pkm-lcs-kunit-drop-key-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_drop_key_round_trip_timeout(
		1, 0, guid, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.expected_txn_id = 0x7172737475767778ULL;
	script.status = RSI_STORAGE_ERROR;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_drop_key_source_thread, &script,
			   "pkm-lcs-kunit-drop-key-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_drop_key_round_trip_timeout(
		1, 0x7172737475767778ULL, guid, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_STORAGE_ERROR);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_guid = guid;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_drop_key_source_thread, &script,
			   "pkm-lcs-kunit-drop-key-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_drop_key_round_trip_timeout(
		1, 0, guid, 1000, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_delete_layer_frame(struct kunit *test)
{
	static const char layer_name[] = "role-alpha";
	static const char bad_layer_name[] = { 'b', '\\', 'd' };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_layer_request(
				1, "base", strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_layer_request(
				1, bad_layer_name, sizeof(bad_layer_name),
				&enqueue),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_delete_layer_request(
				1, layer_name, strlen(layer_name), &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out + payload_offset),
			(u32)strlen(layer_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(out + payload_offset + RSI_LENGTH_PREFIX_SIZE,
			       layer_name, strlen(layer_name)),
			0);
	KUNIT_EXPECT_EQ(test,
			payload_offset + RSI_LENGTH_PREFIX_SIZE +
				strlen(layer_name),
			enqueue.len);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_delete_layer_round_trip_statuses(
	struct kunit *test)
{
	static const char layer_name[] = "role-alpha";
	static const u8 guid_a[RSI_GUID_SIZE] = {
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
	};
	static const u8 guid_b[RSI_GUID_SIZE] = {
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
	};
	static const u8 nil_guid[RSI_GUID_SIZE];
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_delete_layer_source_script script = { };
	struct file file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_layer_name = layer_name;
	script.status = RSI_OK;
	script.orphaned_guid_count = 2;
	script.orphaned_guid_a = guid_a;
	script.orphaned_guid_b = guid_b;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_round_trip_timeout(
		1, layer_name, strlen(layer_name), 1000, &response,
		&enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_layer_name = layer_name;
	script.status = RSI_STORAGE_ERROR;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_round_trip_timeout(
		1, layer_name, strlen(layer_name), 1000, &response,
		&enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_STORAGE_ERROR);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_layer_name = layer_name;
	script.status = RSI_OK;
	script.extra_response_payload = true;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_round_trip_timeout(
		1, layer_name, strlen(layer_name), 1000, &response,
		&enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	script.file = &file;
	script.expected_layer_name = layer_name;
	script.status = RSI_OK;
	script.orphaned_guid_count = 1;
	script.orphaned_guid_a = nil_guid;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_round_trip_timeout(
		1, layer_name, strlen(layer_name), 1000, &response,
		&enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_delete_layer_applies_orphans(
	struct kunit *test)
{
	static const char layer_name[] = "role-beta";
	static const char * const path[] = { "Machine", "RoleKey" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x61 },
		{
			0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
			0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
		},
	};
	static const u8 no_live_guid[PKM_LCS_GUID_BYTES] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	struct pkm_lcs_delete_layer_orphan_apply_result apply = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_delete_layer_source_script script = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	u8 record[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long fd;
	long ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_from_path(1, KEY_NOTIFY, path,
						    ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &notify),
			0L);

	script.file = &file;
	script.expected_layer_name = layer_name;
	script.status = RSI_OK;
	script.orphaned_guid_count = 2;
	script.orphaned_guid_a = ancestors[1];
	script.orphaned_guid_b = no_live_guid;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout(
		1, layer_name, strlen(layer_name), 1000, &apply, &response,
		&enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, apply.orphaned_guid_count, 2U);
	KUNIT_EXPECT_EQ(test, apply.marked_fd_count, 1U);
	KUNIT_EXPECT_EQ(test, apply.immediate_drop_count, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);

	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, snapshot.orphaned);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_read((int)fd, record,
							sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);

	pkm_lcs_kunit_expect_drop_key_request(test, &file, no_live_guid);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, ancestors[1]);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_delete_layer_broadcast_active_sources(
	struct kunit *test)
{
	static const char layer_name[] = "role-broadcast";
	static const char first_name[] = "Machine";
	static const char second_name[] = "Users";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct pkm_lcs_delete_layer_broadcast_result result = { };
	struct pkm_lcs_source_fd_snapshot first_snapshot = { };
	struct pkm_lcs_source_fd_snapshot second_snapshot = { };
	struct pkm_lcs_kunit_delete_layer_source_script first_script = { };
	struct pkm_lcs_kunit_delete_layer_source_script second_script = { };
	struct file first_file = { };
	struct file second_file = { };
	struct task_struct *first_task;
	struct task_struct *second_task;
	const void *token;
	int first_thread_ret;
	int second_thread_ret;
	long ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &first_file),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &second_file),
			0L);
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive,
					  first_name, 1, 0);
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive,
					  second_name, 2, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &first_file, &ops,
				(const void __user *)&first_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &second_file, &ops,
				(const void __user *)&second_args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
				"base", strlen("base"), 1000, &result),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&first_file, &first_snapshot);
	pkm_lcs_kunit_source_fd_snapshot(&second_file, &second_snapshot);
	KUNIT_EXPECT_EQ(test, first_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, first_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, second_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, second_snapshot.in_flight_request_count, 0U);

	first_script.file = &first_file;
	first_script.expected_layer_name = layer_name;
	first_script.status = RSI_OK;
	second_script.file = &second_file;
	second_script.expected_layer_name = layer_name;
	second_script.status = RSI_OK;
	first_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &first_script,
		"pkm-lcs-kunit-del-layer-src1");
	KUNIT_ASSERT_FALSE(test, IS_ERR(first_task));
	second_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &second_script,
		"pkm-lcs-kunit-del-layer-src2");
	KUNIT_ASSERT_FALSE(test, IS_ERR(second_task));
	memset(&result, 0, sizeof(result));
	ret = pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
		layer_name, strlen(layer_name), 1000, &result);
	first_thread_ret = pkm_lcs_kunit_kthread_stop(first_task);
	second_thread_ret = pkm_lcs_kunit_kthread_stop(second_task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, first_thread_ret, 0);
	KUNIT_EXPECT_EQ(test, second_thread_ret, 0);
	KUNIT_EXPECT_EQ(test, first_script.result, 0);
	KUNIT_EXPECT_EQ(test, second_script.result, 0);
	KUNIT_EXPECT_EQ(test, first_script.reads, 1U);
	KUNIT_EXPECT_EQ(test, first_script.writes, 1U);
	KUNIT_EXPECT_EQ(test, second_script.reads, 1U);
	KUNIT_EXPECT_EQ(test, second_script.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.active_source_count, 2U);
	KUNIT_EXPECT_EQ(test, result.completed_source_count, 2U);
	KUNIT_EXPECT_EQ(test, result.orphaned_guid_count, 0U);
	KUNIT_EXPECT_EQ(test, result.marked_fd_count, 0U);
	KUNIT_EXPECT_EQ(test, result.immediate_drop_count, 0U);
	KUNIT_EXPECT_EQ(test, result.generation_hive_count, 2U);
	KUNIT_EXPECT_EQ(test, result.watch_overflow_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&first_file),
			0);
	memset(&second_script, 0, sizeof(second_script));
	second_script.file = &second_file;
	second_script.expected_layer_name = layer_name;
	second_script.status = RSI_OK;
	second_task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &second_script,
		"pkm-lcs-kunit-del-layer-src2");
	KUNIT_ASSERT_FALSE(test, IS_ERR(second_task));
	memset(&result, 0, sizeof(result));
	ret = pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
		layer_name, strlen(layer_name), 1000, &result);
	second_thread_ret = pkm_lcs_kunit_kthread_stop(second_task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, second_thread_ret, 0);
	KUNIT_EXPECT_EQ(test, second_script.result, 0);
	KUNIT_EXPECT_EQ(test, second_script.reads, 1U);
	KUNIT_EXPECT_EQ(test, second_script.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.active_source_count, 1U);
	KUNIT_EXPECT_EQ(test, result.completed_source_count, 1U);
	KUNIT_EXPECT_EQ(test, result.generation_hive_count, 1U);
	KUNIT_EXPECT_EQ(test, result.watch_overflow_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&second_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_delete_layer_replays_registered_down_source(
	struct kunit *test)
{
	static const char layer_name[] = "role-down";
	static const char hive_name[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_delete_layer_broadcast_result result = { };
	struct pkm_lcs_source_table_snapshot table = { };
	struct pkm_lcs_kunit_delete_layer_source_script script = { };
	struct file file = { };
	struct file resume_file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, hive_name, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);

	ret = pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
		layer_name, strlen(layer_name), 1000, &result);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, result.active_source_count, 0U);
	KUNIT_EXPECT_EQ(test, result.completed_source_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table);
	KUNIT_EXPECT_EQ(test, table.down_count, 1U);
	KUNIT_EXPECT_EQ(test, table.pending_layer_delete_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &resume_file),
			0L);
	script.file = &resume_file;
	script.expected_layer_name = layer_name;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-resume");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_register_file_for_token(
		token, &resume_file, &ops, (const void __user *)&args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	pkm_lcs_kunit_source_table_snapshot(&table);
	KUNIT_EXPECT_EQ(test, table.active_count, 1U);
	KUNIT_EXPECT_EQ(test, table.down_count, 0U);
	KUNIT_EXPECT_EQ(test, table.pending_layer_delete_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&resume_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_delete_layer_resume_replay_failure_stays_down(
	struct kunit *test)
{
	static const char layer_name[] = "role-down-fail";
	static const char duplicate_name[] = "ROLE-DOWN-FAIL";
	static const char hive_name[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_source_table_snapshot table = { };
	struct pkm_lcs_kunit_delete_layer_source_script script = { };
	struct file file = { };
	struct file resume_file = { };
	struct task_struct *task;
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, hive_name, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
				layer_name, strlen(layer_name), 1000, NULL),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
				duplicate_name, strlen(duplicate_name), 1000,
				NULL),
			0L);
	pkm_lcs_kunit_source_table_snapshot(&table);
	KUNIT_EXPECT_EQ(test, table.pending_layer_delete_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token,
								  &resume_file),
			0L);
	script.file = &resume_file;
	script.expected_layer_name = layer_name;
	script.status = RSI_STORAGE_ERROR;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &script,
		"pkm-lcs-kunit-del-layer-resume-fail");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_register_file_for_token(
		token, &resume_file, &ops, (const void __user *)&args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	pkm_lcs_kunit_source_table_snapshot(&table);
	KUNIT_EXPECT_EQ(test, table.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table.down_count, 1U);
	KUNIT_EXPECT_EQ(test, table.pending_layer_delete_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&resume_file),
			0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_transaction_control_frames(
	struct kunit *test)
{
	struct pkm_lcs_source_enqueue_result begin = { };
	struct pkm_lcs_source_enqueue_result commit = { };
	struct pkm_lcs_source_enqueue_result abort = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[64];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_begin_transaction_request(
				1, 0x0102030405060708ULL,
				RSI_TXN_READ_WRITE, &begin),
			0L);
	KUNIT_EXPECT_EQ(test, begin.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, begin.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, begin.op_code, (u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, begin.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, begin.in_flight_count, 1U);
	KUNIT_EXPECT_EQ(test, begin.next_request_id, 1ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_commit_transaction_request(
				1, 0x1112131415161718ULL, &commit),
			0L);
	KUNIT_EXPECT_EQ(test, commit.request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, commit.txn_id, 0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test, commit.op_code, (u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, commit.queue_depth, 2U);
	KUNIT_EXPECT_EQ(test, commit.in_flight_count, 2U);
	KUNIT_EXPECT_EQ(test, commit.next_request_id, 2ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_abort_transaction_request(
				1, 0x2122232425262728ULL, &abort),
			0L);
	KUNIT_EXPECT_EQ(test, abort.request_id, 2ULL);
	KUNIT_EXPECT_EQ(test, abort.txn_id, 0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test, abort.op_code, (u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, abort.queue_depth, 3U);
	KUNIT_EXPECT_EQ(test, abort.in_flight_count, 3U);
	KUNIT_EXPECT_EQ(test, abort.next_request_id, 3ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)begin.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)(RSI_REQUEST_HEADER_SIZE + sizeof(u64) +
			      sizeof(u32)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			0x0102030405060708ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_WRITE);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)commit.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 1ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			0x1112131415161718ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)abort.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 2ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			0x2122232425262728ULL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 3U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 3ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_abort_response_releases_no_wait_record(
	struct kunit *test)
{
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result abort = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_abort_transaction_request(
				1, 0x3132333435363738ULL, &abort),
			0L);
	KUNIT_EXPECT_EQ(test, abort.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, abort.txn_id, 0x3132333435363738ULL);
	KUNIT_EXPECT_EQ(test, abort.op_code, (u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, abort.in_flight_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)abort.len);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    abort.request_id, abort.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, abort.request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id, abort.txn_id);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response_result.response_op_code,
			(u16)RSI_ABORT_TRANSACTION_RESPONSE);
	KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_transaction_rejects_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_source_enqueue_result enqueue = {
		.len = 1,
		.request_id = 2,
		.txn_id = 3,
		.op_code = 4,
		.queue_depth = 5,
	};
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct file file = { };
	const void *token;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_begin_transaction_request(
				1, 1, RSI_TXN_READ_WRITE, &enqueue),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, enqueue.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 0U);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_begin_transaction_request(
				1, 1, 0x80, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_commit_transaction_waitable_request(
				1, 1, NULL, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_abort_transaction_waitable_request(
				1, 1, &waiter, &enqueue),
			0L);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 1ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_transaction_round_trip_statuses(
	struct kunit *test)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = 0x0102030405060708ULL;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_OK;
	pkm_lcs_kunit_run_transaction_source_round_trip(
		test, &script, pkm_lcs_kunit_begin_readwrite_round_trip_default,
		script.expected_payload_txn_id, 0L, &response, &enqueue);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = 0x1112131415161718ULL;
	script.expected_payload_txn_id = script.expected_header_txn_id;
	script.status = RSI_TXN_BUSY;
	pkm_lcs_kunit_run_transaction_source_round_trip(
		test, &script, pkm_lcs_kunit_commit_round_trip_default,
		script.expected_payload_txn_id, (long)-EBUSY, &response,
		&enqueue);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_TXN_BUSY);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_op_code = RSI_ABORT_TRANSACTION;
	script.expected_header_txn_id = 0x2122232425262728ULL;
	script.expected_payload_txn_id = script.expected_header_txn_id;
	script.status = RSI_TXN_NOT_SUPPORTED;
	pkm_lcs_kunit_run_transaction_source_round_trip(
		test, &script, pkm_lcs_kunit_abort_round_trip_default,
		script.expected_payload_txn_id, (long)-EOPNOTSUPP,
		&response, &enqueue);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_TXN_NOT_SUPPORTED);
	KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_transaction_round_trip_failures(
	struct kunit *test)
{
	struct pkm_lcs_source_response_result timeout_response = { };
	struct pkm_lcs_source_response_result late_response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_reset_source_table();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_commit_transaction_round_trip_timeout(
				1, 0x3132333435363738ULL, 1,
				&timeout_response, &enqueue),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, enqueue.len, (size_t)0);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_begin_transaction_round_trip_timeout(
				1, 0x4142434445464748ULL, 0x80, 1,
				&timeout_response, &enqueue),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_begin_transaction_round_trip_timeout(
				1, 0x5152535455565758ULL,
				RSI_TXN_READ_WRITE, 1, &timeout_response,
				&enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);
	KUNIT_EXPECT_EQ(test, timeout_response.len, (size_t)0);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&late_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, late_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, late_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_EQ(test, late_response.in_flight_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_create_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0xc1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xc2 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_create_entry_request(
				1, 0, NULL, "Child", strlen("Child"),
				"base", strlen("base"), guid, 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_create_entry_request(
				1, 0, parent_guid, "", 0, "base",
				strlen("base"), guid, 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_create_entry_request(
				1, 0, parent_guid, "Child", strlen("Child"),
				"bad/layer", strlen("bad/layer"), guid, 1,
				&enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_create_key_request(
				1, 0, guid, "", 0, parent_guid, sd,
				sizeof(sd), false, false, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_create_key_request(
				1, 0, guid, "Child", strlen("Child"),
				parent_guid, NULL, sizeof(sd), false, false,
				&enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_write_key_request(
				1, 0, NULL, sd, sizeof(sd), 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_write_key_request(
				1, 0, guid, NULL, sizeof(sd), 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_write_key_request(
				1, 0, guid, sd, 0, 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_write_key_request(
				1, 0, guid, sd, (size_t)U32_MAX + 1, 1,
				&enqueue),
			(long)-EOVERFLOW);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_set_value_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0xc3 };
	static const char bad_value_name[] = { 'b', '\0', 'd' };
	static const u8 data[] = { 0x01, 0x02 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0, NULL, "Value", strlen("Value"),
				"base", strlen("base"), REG_BINARY, data,
				sizeof(data), 1, 0, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0, guid, "Value", strlen("Value"), NULL,
				strlen("base"), REG_BINARY, data, sizeof(data),
				1, 0, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0, guid, bad_value_name,
				sizeof(bad_value_name),
				"base", strlen("base"), REG_BINARY, data,
				sizeof(data), 1, 0, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0, guid, "Value", strlen("Value"),
				"base", strlen("base"), REG_BINARY, NULL,
				sizeof(data), 1, 0, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0, guid, "Value", strlen("Value"),
				"base", strlen("base"), 0xffffffffU, data,
				sizeof(data), 1, 0, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_set_value_request(
				1, 0, guid, "Value", strlen("Value"),
				"base", strlen("base"), REG_BINARY, data,
				(size_t)U32_MAX + 1, 1, 0, &enqueue),
			(long)-EOVERFLOW);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void
pkm_lcs_kunit_source_dispatch_delete_value_entry_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0xd3 };
	static const char bad_value_name[] = { 'b', '\0', 'd' };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_value_entry_request(
				1, 0, NULL, "Value", strlen("Value"),
				"base", strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_value_entry_request(
				1, 0, guid, NULL, strlen("Value"),
				"base", strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_value_entry_request(
				1, 0, guid, "Value", strlen("Value"),
				NULL, strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_value_entry_request(
				1, 0, guid, bad_value_name,
				sizeof(bad_value_name), "base",
				strlen("base"), &enqueue),
			(long)-EINVAL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_dispatch_path_entry_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xd4 };
	static const char bad_child_name[] = { 'b', '\0', 'd' };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_hide_entry_request(
				1, 0, NULL, "Child", strlen("Child"),
				"base", strlen("base"), 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_hide_entry_request(
				1, 0, parent_guid, NULL, strlen("Child"),
				"base", strlen("base"), 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_hide_entry_request(
				1, 0, parent_guid, "Child", strlen("Child"),
				NULL, strlen("base"), 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_hide_entry_request(
				1, 0, parent_guid, bad_child_name,
				sizeof(bad_child_name), "base",
				strlen("base"), 1, &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_entry_request(
				1, 0, NULL, "Child", strlen("Child"),
				"base", strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_entry_request(
				1, 0, parent_guid, NULL, strlen("Child"),
				"base", strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_entry_request(
				1, 0, parent_guid, "Child", strlen("Child"),
				NULL, strlen("base"), &enqueue),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_dispatch_delete_entry_request(
				1, 0, parent_guid, bad_child_name,
				sizeof(bad_child_name), "base",
				strlen("base"), &enqueue),
			(long)-EINVAL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_read_retains_in_flight_until_release(
	struct kunit *test)
{
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 frame[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 601,
					 "Child", &frame_len);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			0L);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 602ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame_len);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 602ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_enqueue_rejects_reused_request_id(
	struct kunit *test)
{
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 frame[96];
	u8 duplicate[96];
	struct file file = { };
	const void *token;
	size_t frame_len;
	size_t duplicate_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), 701,
					 "Child", &frame_len);
	pkm_lcs_kunit_build_lookup_frame(test, duplicate, sizeof(duplicate),
					 701, "Other", &duplicate_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, duplicate,
						       duplicate_len, NULL),
			(long)-EINVAL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 702ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_in_flight_full_blocks_after_read(
	struct kunit *test)
{
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 frame[96];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t frame_len;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame),
						 i, "Child", &frame_len);
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_enqueue_request(1, frame,
							       frame_len,
							       NULL),
				0L);
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)frame_len);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT - 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);

	pkm_lcs_kunit_build_lookup_frame(
		test, frame, sizeof(frame),
		PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT, "Next",
		&frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			(long)-EAGAIN);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT - 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_in_flight_uses_runtime_limit(
	struct kunit *test)
{
	const u32 limit = 8U;
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	u8 frame[96];
	struct file file = { };
	const void *token;
	size_t frame_len;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_concurrent_rsi_requests = limit;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_runtime_max_concurrent_rsi_requests(),
			limit);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < limit; i++) {
		pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame),
						 i, "Child", &frame_len);
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_enqueue_request(1, frame,
							       frame_len,
							       NULL),
				0L);
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, limit);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, limit);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, (u64)limit);

	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), limit,
					 "Next", &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			(long)-EAGAIN);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, limit);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, limit);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, (u64)limit);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_in_flight_raised_runtime_limit(
	struct kunit *test)
{
	const u32 limit = PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT + 4U;
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	u8 frame[96];
	struct file file = { };
	const void *token;
	size_t frame_len;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_concurrent_rsi_requests = limit;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < limit; i++) {
		pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame),
						 i, "Child", &frame_len);
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_enqueue_request(1, frame,
							       frame_len,
							       NULL),
				0L);
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, limit);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, limit);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, (u64)limit);

	pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame), limit,
					 "Next", &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_enqueue_request(1, frame, frame_len,
						       NULL),
			(long)-EAGAIN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_slot_admission_uses_supplied_limits(
	struct kunit *test)
{
	const u32 live_limit = 8U;
	const u32 supplied_limit = live_limit + 1U;
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xd0 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xd1 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_runtime_limits supplied = { };
	struct file file = { };
	const void *token;
	size_t frame_len;
	u8 frame[96];
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_concurrent_rsi_requests = live_limit;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	supplied = limits;
	supplied.max_concurrent_rsi_requests = supplied_limit;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < live_limit; i++) {
		pkm_lcs_kunit_build_lookup_frame(test, frame, sizeof(frame),
						 i, "Child", &frame_len);
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_enqueue_request(1, frame,
							       frame_len,
							       NULL),
				0L);
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, live_limit);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, live_limit);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_slot_admission_state(1, NULL),
			(long)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_slot_admission_state(1, &supplied),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_create_entry_request_with_limits(
				1, 0, parent_guid, "Next", strlen("Next"),
				"base", strlen("base"), child_guid, 101,
				&supplied, &enqueue),
			0L);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, (u64)live_limit);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, supplied_limit);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_slot_admission_state(1, &supplied),
			(long)-EAGAIN);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, supplied_limit);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			supplied_limit);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, (u64)supplied_limit);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_response_rejects_before_read(struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x72 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x1112131415161718ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len,
				&response_result),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_response_releases_after_read(struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x73 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x2122232425262728ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len,
				&response_result),
			0L);
	KUNIT_EXPECT_EQ(test, response_result.len, response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, enqueue.request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id, enqueue.txn_id);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, response_result.response_op_code,
			(u16)RSI_LOOKUP_RESPONSE);
	KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_response_rejects_common_mismatches(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x74 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE + 1];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x3132333435363738ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, RSI_MIN_RESPONSE_SIZE - 1U,
				NULL),
			(long)-EINVAL);

	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE + 1U,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, RSI_MIN_RESPONSE_SIZE, NULL),
			(long)-EINVAL);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id + 1U,
					    enqueue.op_code, RSI_OK,
					    &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len, NULL),
			(long)-EINVAL);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id,
					    RSI_CREATE_KEY, RSI_OK,
					    &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len, NULL),
			(long)-EINVAL);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_response_unknown_status_releases(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x75 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x4142434445464748ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    0xffffffffU, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len,
				&response_result),
			0L);
	KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response_result.status, 0xffffffffU);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_unknown_status_audits(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] = "unknown_rsi_status_code";
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
		0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
	};
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_response_result waiter_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_fd_snapshot fd_snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	u8 buffer[512];
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t written = 0;
	u32 header_size;
	u16 type_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request(
				1, 0x4142434445464750ULL, parent_guid,
				"Child", strlen("Child"), &waiter,
				&enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    0xffffffffU, &response_len);

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_TRUE(test,
			  response_result.source_validation_failure_present);
	KUNIT_EXPECT_EQ(
		test, response_result.source_validation_failure,
		(u32)PKM_LCS_SOURCE_VALIDATION_UNKNOWN_RSI_STATUS_CODE);
	KUNIT_EXPECT_TRUE(test, response_result.key_guid_present);
	KUNIT_EXPECT_EQ(test,
			memcmp(response_result.key_guid, parent_guid,
			       sizeof(parent_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &waiter_result),
			(long)-EIO);
	KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
	KUNIT_EXPECT_TRUE(test,
			  waiter_result.source_validation_failure_present);
	KUNIT_EXPECT_EQ(
		test, waiter_result.source_validation_failure,
		(u32)PKM_LCS_SOURCE_VALIDATION_UNKNOWN_RSI_STATUS_CODE);
	KUNIT_EXPECT_TRUE(test, waiter_result.key_guid_present);
	KUNIT_EXPECT_EQ(test,
			memcmp(waiter_result.key_guid, parent_guid,
			       sizeof(parent_guid)),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written,
				&kmes_snapshot),
			0);
	KUNIT_ASSERT_GT(test, written, (size_t)KMES_EVENT_HEADER_BASE_SIZE);
	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)(sizeof(event_type) - 1));
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_LCS);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_EQ(test, buffer[header_size], 0x86);
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains(
				  buffer, written, validation_class));
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains_bytes(
				  buffer, written, parent_guid,
				  sizeof(parent_guid)));

	pkm_lcs_kunit_source_fd_snapshot(&file, &fd_snapshot);
	KUNIT_EXPECT_EQ(test, fd_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_FALSE(test, fd_snapshot.closing);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_response_duplicate_after_release_rejected(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x76 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x5152535455565758ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len, NULL),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len, NULL),
			(long)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_status_only_payload_exactness(
	struct kunit *test)
{
	static const u16 op_codes[] = {
		RSI_CREATE_ENTRY,
		RSI_HIDE_ENTRY,
		RSI_DELETE_ENTRY,
		RSI_CREATE_KEY,
		RSI_WRITE_KEY,
		RSI_DROP_KEY,
		RSI_SET_VALUE,
		RSI_DELETE_VALUE_ENTRY,
		RSI_SET_BLANKET_TOMBSTONE,
		RSI_BEGIN_TRANSACTION,
		RSI_COMMIT_TRANSACTION,
		RSI_ABORT_TRANSACTION,
		RSI_FLUSH,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(op_codes); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		u8 response[RSI_MIN_RESPONSE_SIZE + 1];
		u8 out[256];
		struct file file = { };
		const void *token;
		size_t response_len;
		ssize_t count;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		ret = pkm_lcs_kunit_dispatch_status_only_waitable_request(
			op_codes[i], &waiter, &enqueue);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		pkm_lcs_kunit_build_status_response(test, response,
						    sizeof(response),
						    enqueue.request_id,
						    enqueue.op_code, RSI_OK,
						    &response_len);
		response[response_len] = 0xee;
		response_len++;
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false, &response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				op_codes[i]);
		KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
		KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_EQ(test, waiter_result.request_op_code, op_codes[i]);
		KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_enum_children_payload_validation(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xb1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xb2 };
	static const bool malformed_cases[] = { false, true };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(malformed_cases); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		u8 response[256];
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t offset;
		ssize_t count;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		ret = pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
			1, 0xb3b4b5b6b7b8b9baULL + i, parent_guid,
			&waiter, &enqueue);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		pkm_lcs_kunit_rsi_response_begin(
			test, response, sizeof(response), enqueue.request_id,
			RSI_ENUM_CHILDREN_RESPONSE, RSI_OK, &offset);
		if (malformed_cases[i]) {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
			pkm_lcs_kunit_rsi_append_len_prefixed(
				test, response, sizeof(response), &offset,
				"Child", strlen("Child"));
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
			pkm_lcs_kunit_rsi_append_lookup_path_entry(
				test, response, sizeof(response), &offset,
				"base", RSI_PATH_TARGET_GUID, child_guid, 0);
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 0);
		} else {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 0);
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 0);
		}
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false, &response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				(u16)RSI_ENUM_CHILDREN);
		KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
		KUNIT_EXPECT_EQ(test,
				response_result.malformed_source_data,
				malformed_cases[i]);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret,
				malformed_cases[i] ? (long)-EIO : 0L);
		KUNIT_EXPECT_EQ(test, waiter_result.request_op_code,
				(u16)RSI_ENUM_CHILDREN);
		KUNIT_EXPECT_EQ(test,
				waiter_result.malformed_source_data,
				malformed_cases[i]);

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_lookup_runtime_limits_path_names(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xc1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xc2 };
	static const bool widened_cases[] = { false, true };
	char layer_name[301];
	size_t i;

	pkm_lcs_kunit_fill_name(layer_name, 300, 'L');
	for (i = 0; i < ARRAY_SIZE(widened_cases); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct pkm_lcs_runtime_limits limits = { };
		u8 *response;
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t offset;
		ssize_t count;
		long ret;

		response = kzalloc(PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, response);

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		pkm_lcs_runtime_limits_reset_defaults();
		if (widened_cases[i]) {
			KUNIT_ASSERT_EQ(test,
					pkm_lcs_runtime_limits_defaults(&limits),
					0L);
			limits.max_path_component_length = 300;
			KUNIT_ASSERT_EQ(test,
					pkm_lcs_runtime_limits_publish(&limits),
					0L);
		}

		ret = pkm_lcs_source_dispatch_lookup_waitable_request(
			1, 0xc3c4c5c6c7c8c9caULL + i, parent_guid, "Child",
			strlen("Child"), &waiter, &enqueue);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		if (widened_cases[i])
			pkm_lcs_runtime_limits_reset_defaults();

		pkm_lcs_kunit_rsi_response_begin(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			enqueue.request_id,
			RSI_LOOKUP_RESPONSE, RSI_OK, &offset);
		pkm_lcs_kunit_rsi_append_u32(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_path_entry(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, layer_name,
			RSI_PATH_TARGET_GUID, child_guid, 0);
		pkm_lcs_kunit_rsi_append_u32(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_metadata(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, child_guid,
			pkm_lcs_kunit_owner_only_sd,
			sizeof(pkm_lcs_kunit_owner_only_sd));
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false, &response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				(u16)RSI_LOOKUP);
		KUNIT_EXPECT_EQ(test, response_result.malformed_source_data,
				!widened_cases[i]);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret,
				widened_cases[i] ? 0L : (long)-EIO);
		KUNIT_EXPECT_EQ(test, waiter_result.malformed_source_data,
				!widened_cases[i]);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		pkm_lcs_runtime_limits_reset_defaults();
		kacs_rust_token_drop(token);
		kfree(response);
	}
}


static void pkm_lcs_kunit_source_write_enum_children_runtime_limits_child_names(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xd1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xd2 };
	static const bool widened_cases[] = { false, true };
	char child_name[301];
	size_t i;

	pkm_lcs_kunit_fill_name(child_name, 300, 'C');
	for (i = 0; i < ARRAY_SIZE(widened_cases); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct pkm_lcs_runtime_limits limits = { };
		u8 *response;
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t offset;
		ssize_t count;
		long ret;

		response = kzalloc(PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, response);

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		pkm_lcs_runtime_limits_reset_defaults();
		if (widened_cases[i]) {
			KUNIT_ASSERT_EQ(test,
					pkm_lcs_runtime_limits_defaults(&limits),
					0L);
			limits.max_path_component_length = 300;
			KUNIT_ASSERT_EQ(test,
					pkm_lcs_runtime_limits_publish(&limits),
					0L);
		}

		ret = pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
			1, 0xd3d4d5d6d7d8d9daULL + i, parent_guid, &waiter,
			&enqueue);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		if (widened_cases[i])
			pkm_lcs_runtime_limits_reset_defaults();

		pkm_lcs_kunit_rsi_response_begin(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			enqueue.request_id,
			RSI_ENUM_CHILDREN_RESPONSE, RSI_OK, &offset);
		pkm_lcs_kunit_rsi_append_u32(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, 1);
		pkm_lcs_kunit_rsi_append_len_prefixed(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, child_name, strlen(child_name));
		pkm_lcs_kunit_rsi_append_u32(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_path_entry(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, "base",
			RSI_PATH_TARGET_GUID, child_guid, 0);
		pkm_lcs_kunit_rsi_append_u32(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_metadata(
			test, response, PKM_LCS_KUNIT_RUNTIME_RESPONSE_SIZE,
			&offset, child_guid,
			pkm_lcs_kunit_owner_only_sd,
			sizeof(pkm_lcs_kunit_owner_only_sd));
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false, &response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				(u16)RSI_ENUM_CHILDREN);
		KUNIT_EXPECT_EQ(test, response_result.malformed_source_data,
				!widened_cases[i]);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret,
				widened_cases[i] ? 0L : (long)-EIO);
		KUNIT_EXPECT_EQ(test, waiter_result.malformed_source_data,
				!widened_cases[i]);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		pkm_lcs_runtime_limits_reset_defaults();
		kacs_rust_token_drop(token);
		kfree(response);
	}
}


static void pkm_lcs_kunit_source_write_query_values_runtime_limits_names(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = { 0xe1 };
	static const bool widened_cases[] = { false, true };
	enum { LONG_NAME_LEN = 300 };
	char value_name[LONG_NAME_LEN + 1];
	char layer_name[LONG_NAME_LEN + 1];
	size_t field;
	size_t i;

	pkm_lcs_kunit_fill_name(value_name, LONG_NAME_LEN, 'V');
	pkm_lcs_kunit_fill_name(layer_name, LONG_NAME_LEN, 'L');
	for (field = 0; field < 2; field++) {
		for (i = 0; i < ARRAY_SIZE(widened_cases); i++) {
			struct pkm_lcs_kunit_query_values_source_script script = {
				.expected_guid = guid,
				.expected_value_name = "Value",
				.response_value_name = field == 0 ?
						       value_name :
						       "Value",
				.layer_name = field == 1 ? layer_name : "base",
				.data = (const u8 *)"x",
				.data_len = 1,
				.value_type = REG_BINARY,
			};
			struct pkm_lcs_source_response_frame frame = { };
			struct pkm_lcs_source_response_result response = { };
			struct pkm_lcs_source_enqueue_result enqueue = { };
			struct pkm_lcs_runtime_limits limits = { };
			const struct pkm_lcs_runtime_limits *limits_ptr = NULL;
			struct task_struct *task;
			struct file file = { };
			const void *token;
			int thread_ret;
			long ret;

			if (widened_cases[i]) {
				KUNIT_ASSERT_EQ(
					test,
					pkm_lcs_runtime_limits_defaults(&limits),
					0L);
				limits.max_path_component_length = LONG_NAME_LEN;
				limits_ptr = &limits;
			}

			pkm_lcs_kunit_setup_registered_source(test, &file,
							      &token);
			script.file = &file;
			task = pkm_lcs_kunit_kthread_run(
				pkm_lcs_kunit_query_values_source_thread,
				&script, "pkm-lcs-kunit-query-runtime");
			if (IS_ERR(task)) {
				KUNIT_FAIL(test,
					   "failed to start query-values source");
				goto out_release_source;
			}

			pkm_kmes_kunit_reset_all();
			ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
				1, 0, guid, "Value", strlen("Value"), false,
				limits_ptr, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
				&frame, &response, &enqueue);
			thread_ret = pkm_lcs_kunit_kthread_stop(task);
			KUNIT_EXPECT_EQ(test, thread_ret, 0);
			KUNIT_EXPECT_EQ(test, script.result, 0);
			KUNIT_EXPECT_EQ(test, script.reads, 1U);
			KUNIT_EXPECT_EQ(test, script.writes, 1U);
			KUNIT_EXPECT_EQ(test, ret,
					widened_cases[i] ? 0L : (long)-EIO);
			KUNIT_EXPECT_EQ(test, response.malformed_source_data,
					!widened_cases[i]);
			if (!widened_cases[i]) {
				KUNIT_EXPECT_TRUE(
					test,
					response.source_validation_failure_present);
				KUNIT_EXPECT_EQ(
					test,
					response.source_validation_failure,
					field == 0 ?
					(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_VALUE_NAME :
					(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME);
			}
			pkm_lcs_source_response_frame_destroy(&frame);

out_release_source:
			KUNIT_EXPECT_EQ(
				test,
				pkm_lcs_source_device_release_file(&file), 0);
			pkm_lcs_kunit_reset_source_table();
			kacs_rust_token_drop(token);
		}
	}
}


static void pkm_lcs_kunit_source_lookup_round_trip_supplied_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xa2 };
	char layer_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_kunit_walk_source_step step = {
		.expected_child = "Child",
		.layer_name = layer_name,
		.guid = child_guid,
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = &step,
		.step_count = 1,
		.reset_runtime_limits_before_response = true,
	};
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_fill_name(layer_name, LONG_NAME_LEN, 'L');
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread,
					 &script,
					 "pkm-lcs-kunit-lookup-supplied");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
		1, 0, parent_guid, "Child", strlen("Child"), &limits,
		limits.request_timeout_ms, &frame, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	pkm_lcs_source_response_frame_destroy(&frame);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_lookup_plain_retains_supplied_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xa3 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xa4 };
	char child_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_kunit_walk_source_step step = {
		.expected_child = child_name,
		.guid = child_guid,
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = &step,
		.step_count = 1,
		.reset_runtime_limits_before_response = true,
	};
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_fill_name(child_name, LONG_NAME_LEN, 'P');
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_walk_source_thread,
					 &script,
					 "pkm-lcs-kunit-lookup-plain-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_source_lookup_round_trip_timeout_with_limits(
		1, 0, parent_guid, child_name, strlen(child_name), &limits,
		limits.request_timeout_ms, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_enum_children_round_trip_supplied_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xb1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xb2 };
	char child_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_kunit_enum_children_source_script script = {
		.expected_parent_guid = parent_guid,
		.child_name = child_name,
		.layer_name = "base",
		.child_guid = child_guid,
	};
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_fill_name(child_name, LONG_NAME_LEN, 'C');
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_enum_children_source_thread, &script,
		"pkm-lcs-kunit-enum-supplied");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		1, 0, parent_guid, &limits, limits.request_timeout_ms, &frame,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_ENUM_CHILDREN);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	pkm_lcs_source_response_frame_destroy(&frame);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_read_key_round_trip_supplied_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const u8 guid[RSI_GUID_SIZE] = { 0xc1 };
	char key_name[LONG_NAME_LEN + 1];
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = guid,
		.name = key_name,
	};
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_kunit_fill_name(key_name, LONG_NAME_LEN, 'K');
	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_read_key_source_thread, &script,
		"pkm-lcs-kunit-read-key-supplied");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		1, 0, guid, &limits, limits.request_timeout_ms, &frame,
		&response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_READ_KEY);
	KUNIT_EXPECT_FALSE(test, response.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	pkm_lcs_source_response_frame_destroy(&frame);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_key_retains_supplied_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const u8 guid[RSI_GUID_SIZE] = { 0xd1 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_write_key_request_with_limits(
				1, 0x8182838485868788ULL, guid, sd,
				sizeof(sd), 0x1122334455667788ULL, &limits,
				&enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)enqueue.len);
	pkm_lcs_runtime_limits_reset_defaults();

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_accept_response_file(
				&file, response, response_len,
				&response_result),
			0L);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_WRITE_KEY);
	KUNIT_EXPECT_FALSE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response_result.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_control_retains_supplied_limits(
	struct kunit *test)
{
	enum { LONG_NAME_LEN = 300 };
	static const char hive_name[] = "Machine";
	static const char layer_name[] = "role-alpha";
	static const u8 guid[RSI_GUID_SIZE] = { 0xe1 };
	struct pkm_lcs_kunit_transaction_source_script txn_script = { };
	struct pkm_lcs_kunit_flush_source_script flush_script = { };
	struct pkm_lcs_kunit_drop_key_source_script drop_script = { };
	struct pkm_lcs_kunit_delete_layer_source_script layer_script = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = LONG_NAME_LEN;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	txn_script.file = &file;
	txn_script.expected_op_code = RSI_BEGIN_TRANSACTION;
	txn_script.expected_header_txn_id = 0;
	txn_script.expected_payload_txn_id = 0x0102030405060708ULL;
	txn_script.expected_mode = RSI_TXN_READ_WRITE;
	txn_script.status = RSI_OK;
	txn_script.reset_runtime_limits_before_response = true;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &txn_script,
		"pkm-lcs-kunit-txn-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_begin_transaction_round_trip_timeout_with_limits(
		1, txn_script.expected_payload_txn_id, RSI_TXN_READ_WRITE,
		&limits, limits.request_timeout_ms, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, txn_script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	flush_script.file = &file;
	flush_script.expected_hive_name = hive_name;
	flush_script.status = RSI_OK;
	flush_script.reset_runtime_limits_before_response = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_flush_source_thread,
					 &flush_script,
					 "pkm-lcs-kunit-flush-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_flush_round_trip_timeout_with_limits(
		1, hive_name, strlen(hive_name), &limits,
		limits.request_timeout_ms, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, flush_script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_FLUSH);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	drop_script.file = &file;
	drop_script.expected_guid = guid;
	drop_script.expected_txn_id = 0x1112131415161718ULL;
	drop_script.status = RSI_OK;
	drop_script.reset_runtime_limits_before_response = true;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_drop_key_source_thread,
					 &drop_script,
					 "pkm-lcs-kunit-drop-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_drop_key_round_trip_timeout_with_limits(
		1, drop_script.expected_txn_id, guid, &limits,
		limits.request_timeout_ms, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, drop_script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	memset(&response, 0, sizeof(response));
	memset(&enqueue, 0, sizeof(enqueue));
	layer_script.file = &file;
	layer_script.expected_layer_name = layer_name;
	layer_script.status = RSI_OK;
	layer_script.reset_runtime_limits_before_response = true;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_delete_layer_source_thread, &layer_script,
		"pkm-lcs-kunit-layer-limit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_layer_round_trip_timeout_with_limits(
		1, layer_name, strlen(layer_name), &limits,
		limits.request_timeout_ms, &response, &enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, layer_script.result, 0);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_LAYER);
	KUNIT_EXPECT_EQ(test, response.limits.max_path_component_length,
			(u32)LONG_NAME_LEN);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_malformed_path_name_audits(
	struct kunit *test)
{
	static const char invalid_child_name[] = { 'C', (char)0xff, 'd', '\0' };
	static const char invalid_layer_name[] = { 'L', (char)0xff, 'r', '\0' };
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	};
	static const struct {
		u16 request_op;
		u16 response_op;
		u64 txn_id;
		const char *child_name;
		const char *layer_name;
		const char *validation_class;
		u32 validation_failure;
	} cases[] = {
		{ RSI_LOOKUP, RSI_LOOKUP_RESPONSE, 0xa1a2a3a4a5a6a7a8ULL,
		  "Child", "bad/layer", "malformed_layer_name",
		  PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME },
		{ RSI_ENUM_CHILDREN, RSI_ENUM_CHILDREN_RESPONSE,
		  0xb1b2b3b4b5b6b7b8ULL, "Bad/Child", "base",
		  "malformed_key_name",
		  PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_NAME },
		{ RSI_ENUM_CHILDREN, RSI_ENUM_CHILDREN_RESPONSE,
		  0xc1c2c3c4c5c6c7c8ULL, "Child", "bad/layer",
		  "malformed_layer_name",
		  PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME },
		{ RSI_LOOKUP, RSI_LOOKUP_RESPONSE, 0xd1d2d3d4d5d6d7d8ULL,
		  "Child", invalid_layer_name, "malformed_layer_name",
		  PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME },
		{ RSI_ENUM_CHILDREN, RSI_ENUM_CHILDREN_RESPONSE,
		  0xe1e2e3e4e5e6e7e8ULL, invalid_child_name, "base",
		  "malformed_key_name",
		  PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_NAME },
		{ RSI_ENUM_CHILDREN, RSI_ENUM_CHILDREN_RESPONSE,
		  0xf1f2f3f4f5f6f7f8ULL, "Child", invalid_layer_name,
		  "malformed_layer_name",
		  PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		u8 response[256];
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t offset;
		ssize_t count;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		if (cases[i].request_op == RSI_LOOKUP) {
			ret = pkm_lcs_source_dispatch_lookup_waitable_request(
				1, cases[i].txn_id, parent_guid, "Child",
				strlen("Child"), &waiter, &enqueue);
		} else {
			ret = pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
				1, cases[i].txn_id, parent_guid, &waiter,
				&enqueue);
		}
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		pkm_lcs_kunit_rsi_response_begin(
			test, response, sizeof(response), enqueue.request_id,
			cases[i].response_op, RSI_OK, &offset);
		if (cases[i].request_op == RSI_LOOKUP) {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
		} else {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
			pkm_lcs_kunit_rsi_append_len_prefixed(
				test, response, sizeof(response), &offset,
				cases[i].child_name,
				strlen(cases[i].child_name));
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
		}
		pkm_lcs_kunit_rsi_append_lookup_path_entry(
			test, response, sizeof(response), &offset,
			cases[i].layer_name, RSI_PATH_TARGET_GUID, child_guid,
			0);
		pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
					     &offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_metadata(
			test, response, sizeof(response), &offset, child_guid,
			pkm_lcs_kunit_owner_only_sd,
			sizeof(pkm_lcs_kunit_owner_only_sd));
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		pkm_kmes_kunit_reset_all();
		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false,
			&response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				cases[i].request_op);
		KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
		KUNIT_EXPECT_TRUE(test,
				  response_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(test, response_result.source_validation_failure,
				cases[i].validation_failure);
		KUNIT_EXPECT_TRUE(test, response_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response_result.key_guid, parent_guid,
				       sizeof(parent_guid)),
				0);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			waiter_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(test, waiter_result.source_validation_failure,
				cases[i].validation_failure);
		KUNIT_EXPECT_TRUE(test, waiter_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(waiter_result.key_guid, parent_guid,
				       sizeof(parent_guid)),
				0);

		pkm_lcs_kunit_expect_source_validation_audit(
			test, cases[i].validation_class, parent_guid);

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_key_value_name_audits(
	struct kunit *test)
{
	static const char long_value_name[] =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	static const u8 guid[RSI_GUID_SIZE] = {
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	};
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	};
	static const u8 data[] = { 0x10, 0x20, 0x30 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	{
		struct pkm_lcs_kunit_read_key_source_script script = {
			.file = &file,
			.expected_guid = guid,
			.name = "Bad/Key",
			.parent_guid = parent_guid,
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct task_struct *task;
		int thread_ret;
		long ret;

		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_read_key_source_thread, &script,
			"pkm-lcs-kunit-read-key-name");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start read-key source");
			goto out_release_source;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
			1, 0, guid, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
			&frame, &response, &enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);
		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, script.reads, 1U);
		KUNIT_EXPECT_EQ(test, script.writes, 1U);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
		KUNIT_EXPECT_EQ(test, frame.len, (size_t)0);
		KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_NAME);
		KUNIT_EXPECT_TRUE(test, response.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response.key_guid, guid, sizeof(guid)),
				0);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_key_name", guid);
		pkm_lcs_source_response_frame_destroy(&frame);
	}

	{
		struct pkm_lcs_kunit_query_values_source_script script = {
			.file = &file,
			.expected_guid = guid,
			.expected_value_name = "Value",
			.response_value_name = long_value_name,
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = REG_BINARY,
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct task_struct *task;
		int thread_ret;
		long ret;

		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_query_values_source_thread, &script,
			"pkm-lcs-kunit-query-value-name");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start query-values source");
			goto out_release_source;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
			1, 0, guid, "Value", strlen("Value"), false,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);
		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, script.reads, 1U);
		KUNIT_EXPECT_EQ(test, script.writes, 1U);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
		KUNIT_EXPECT_EQ(test, frame.len, (size_t)0);
		KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_VALUE_NAME);
		KUNIT_EXPECT_TRUE(test, response.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response.key_guid, guid, sizeof(guid)),
				0);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_value_name", guid);
		pkm_lcs_source_response_frame_destroy(&frame);
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_invalid_utf8_name_audits(
	struct kunit *test)
{
	static const char invalid_key_name[] = { 'K', (char)0xff, 'y', '\0' };
	static const char invalid_value_name[] = { 'V', (char)0xff, 'l', '\0' };
	static const char invalid_layer_name[] = { 'L', (char)0xff, 'r', '\0' };
	static const u8 guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 data[] = { 0x42 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	{
		struct pkm_lcs_kunit_read_key_source_script script = {
			.file = &file,
			.expected_guid = guid,
			.name = invalid_key_name,
			.parent_guid = parent_guid,
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct task_struct *task;
		int thread_ret;
		long ret;

		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_read_key_source_thread, &script,
			"pkm-lcs-kunit-read-key-invalid-utf8");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start read-key source");
			goto out_release_source;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
			1, 0, guid, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
			&frame, &response, &enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);
		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, script.reads, 1U);
		KUNIT_EXPECT_EQ(test, script.writes, 1U);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
		KUNIT_EXPECT_EQ(test, frame.len, (size_t)0);
		KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test, response.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_NAME);
		KUNIT_EXPECT_TRUE(test, response.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response.key_guid, guid, sizeof(guid)),
				0);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_key_name", guid);
		pkm_lcs_source_response_frame_destroy(&frame);
	}

	{
		const struct {
			const char *response_value_name;
			const char *layer_name;
			const char *validation_class;
			u32 validation_failure;
		} cases[] = {
			{
				.response_value_name = invalid_value_name,
				.layer_name = "base",
				.validation_class = "malformed_value_name",
				.validation_failure =
					PKM_LCS_SOURCE_VALIDATION_MALFORMED_VALUE_NAME,
			},
			{
				.response_value_name = "Value",
				.layer_name = invalid_layer_name,
				.validation_class = "malformed_layer_name",
				.validation_failure =
					PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME,
			},
		};
		size_t i;

		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			struct pkm_lcs_kunit_query_values_source_script script = {
				.file = &file,
				.expected_guid = guid,
				.expected_value_name = "Value",
				.response_value_name =
					cases[i].response_value_name,
				.layer_name = cases[i].layer_name,
				.data = data,
				.data_len = sizeof(data),
				.value_type = REG_BINARY,
			};
			struct pkm_lcs_source_response_frame frame = { };
			struct pkm_lcs_source_response_result response = { };
			struct pkm_lcs_source_enqueue_result enqueue = { };
			struct task_struct *task;
			int thread_ret;
			long ret;

			task = pkm_lcs_kunit_kthread_run(
				pkm_lcs_kunit_query_values_source_thread,
				&script,
				"pkm-lcs-kunit-query-invalid-utf8");
			if (IS_ERR(task)) {
				KUNIT_FAIL(
					test,
					"failed to start query-values source");
				goto out_release_source;
			}

			pkm_kmes_kunit_reset_all();
			ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
				1, 0, guid, "Value", strlen("Value"), false,
				PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame,
				&response, &enqueue);
			thread_ret = pkm_lcs_kunit_kthread_stop(task);
			KUNIT_EXPECT_EQ(test, thread_ret, 0);
			KUNIT_EXPECT_EQ(test, script.result, 0);
			KUNIT_EXPECT_EQ(test, script.reads, 1U);
			KUNIT_EXPECT_EQ(test, script.writes, 1U);
			KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
			KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
			KUNIT_EXPECT_EQ(test, frame.len, (size_t)0);
			KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
			KUNIT_EXPECT_TRUE(
				test,
				response.source_validation_failure_present);
			KUNIT_EXPECT_EQ(test, response.source_validation_failure,
					cases[i].validation_failure);
			KUNIT_EXPECT_TRUE(test, response.key_guid_present);
			KUNIT_EXPECT_EQ(test,
					memcmp(response.key_guid, guid,
					       sizeof(guid)),
					0);
			pkm_lcs_kunit_expect_source_validation_audit(
				test, cases[i].validation_class, guid);
			pkm_lcs_source_response_frame_destroy(&frame);
		}
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_remaining_validation_class_audits(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	};
	static const u8 key_guid[RSI_GUID_SIZE] = { 0xa3 };
	static const u8 value_guid[RSI_GUID_SIZE] = {
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	};
	static const u8 orphan_guid[RSI_GUID_SIZE] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	};
	static const u8 data[] = { 0x10, 0x20, 0x30 };

	{
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		u8 response[RSI_MIN_RESPONSE_SIZE + 1];
		u8 out[256];
		struct file file = { };
		const void *token;
		size_t response_len;
		ssize_t count;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		ret = pkm_lcs_kunit_dispatch_status_only_waitable_request(
			RSI_SET_VALUE, &waiter, &enqueue);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_status;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_status;

		pkm_lcs_kunit_build_status_response(test, response,
						    sizeof(response),
						    enqueue.request_id,
						    enqueue.op_code, RSI_OK,
						    &response_len);
		response[response_len++] = 0xee;
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

		pkm_kmes_kunit_reset_all();
		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false, &response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_status;
		KUNIT_EXPECT_TRUE(test,
				  response_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_RESPONSE_PAYLOAD);
		KUNIT_EXPECT_TRUE(test, response_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response_result.key_guid, key_guid,
				       sizeof(key_guid)),
				0);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			waiter_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, waiter_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_RESPONSE_PAYLOAD);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_response_payload", key_guid);

out_release_status:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}

	{
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		u8 response[256];
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t offset;
		ssize_t count;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		ret = pkm_lcs_source_dispatch_lookup_waitable_request(
			1, 0x9192939495969798ULL, parent_guid, "Child",
			strlen("Child"), &waiter, &enqueue);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_lookup;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_lookup;

		pkm_lcs_kunit_rsi_response_begin(
			test, response, sizeof(response), enqueue.request_id,
			RSI_LOOKUP_RESPONSE, RSI_OK, &offset);
		pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
					     &offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_path_entry(
			test, response, sizeof(response), &offset, "base",
			RSI_PATH_TARGET_GUID, child_guid, 0);
		pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
					     &offset, 0);
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		pkm_kmes_kunit_reset_all();
		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false,
			&response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_lookup;
		KUNIT_EXPECT_TRUE(test,
				  response_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_METADATA);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
		KUNIT_EXPECT_EQ(
			test, waiter_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_METADATA);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_key_metadata", parent_guid);

out_release_lookup:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}

	{
		struct pkm_lcs_kunit_query_values_source_script script = {
			.expected_guid = value_guid,
			.expected_value_name = "Value",
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = 0xffffffffU,
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct task_struct *task;
		struct file file = { };
		const void *token;
		int thread_ret;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		script.file = &file;
		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_query_values_source_thread, &script,
			"pkm-lcs-kunit-value-payload");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start query-values source");
			goto out_release_query;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
			1, 0, value_guid, "Value", strlen("Value"), false,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);
		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
		KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_VALUE_PAYLOAD);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_value_payload", value_guid);
		pkm_lcs_source_response_frame_destroy(&frame);

out_release_query:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}

	{
		struct pkm_lcs_kunit_delete_layer_source_script script = {
			.file = NULL,
			.expected_layer_name = "policy",
			.orphaned_guid_a = orphan_guid,
			.orphaned_guid_b = orphan_guid,
			.status = RSI_OK,
			.orphaned_guid_count = 2,
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct task_struct *task;
		struct file file = { };
		const void *token;
		int thread_ret;
		long ret;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		script.file = &file;
		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_delete_layer_source_thread, &script,
			"pkm-lcs-kunit-delete-layer-orphans");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start delete-layer source");
			goto out_release_delete_layer;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_delete_layer_round_trip_retaining_frame_timeout(
			1, "policy", strlen("policy"),
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);
		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
		KUNIT_EXPECT_TRUE(test, response.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_DELETE_LAYER_ORPHAN_LIST);
		KUNIT_EXPECT_FALSE(test, response.key_guid_present);
		pkm_lcs_kunit_expect_source_validation_audit(
			test, "malformed_delete_layer_orphan_list", NULL);
		pkm_lcs_source_response_frame_destroy(&frame);

out_release_delete_layer:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_path_future_sequence_audits(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] = "future_sequence_number";
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
		0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
		0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x01,
	};
	static const struct {
		u16 request_op;
		u16 response_op;
		u64 txn_id;
	} cases[] = {
		{ RSI_LOOKUP, RSI_LOOKUP_RESPONSE, 0xc1c2c3c4c5c6c7c8ULL },
		{ RSI_ENUM_CHILDREN, RSI_ENUM_CHILDREN_RESPONSE,
		  0xc9cacbcccdcecfd0ULL },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
		u8 response[256];
		u8 buffer[512];
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t written = 0;
		size_t offset;
		ssize_t count;
		u32 header_size;
		long ret;
		u16 type_len;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		if (cases[i].request_op == RSI_LOOKUP) {
			ret = pkm_lcs_source_dispatch_lookup_waitable_request(
				1, cases[i].txn_id, parent_guid, "Child",
				strlen("Child"), &waiter, &enqueue);
		} else {
			ret = pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
				1, cases[i].txn_id, parent_guid, &waiter,
				&enqueue);
		}
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		pkm_lcs_kunit_rsi_response_begin(
			test, response, sizeof(response), enqueue.request_id,
			cases[i].response_op, RSI_OK, &offset);
		if (cases[i].request_op == RSI_LOOKUP) {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
		} else {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
			pkm_lcs_kunit_rsi_append_len_prefixed(
				test, response, sizeof(response), &offset,
				"Child", strlen("Child"));
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
		}
		pkm_lcs_kunit_rsi_append_lookup_path_entry(
			test, response, sizeof(response), &offset, "base",
			RSI_PATH_TARGET_GUID, child_guid, 1);
		pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
					     &offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_metadata(
			test, response, sizeof(response), &offset, child_guid,
			pkm_lcs_kunit_owner_only_sd,
			sizeof(pkm_lcs_kunit_owner_only_sd));
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		pkm_kmes_kunit_reset_all();
		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false,
			&response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				cases[i].request_op);
		KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
		KUNIT_EXPECT_TRUE(test,
				  response_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_FUTURE_SEQUENCE_NUMBER);
		KUNIT_EXPECT_TRUE(test, response_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response_result.key_guid, parent_guid,
				       sizeof(parent_guid)),
				0);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_EQ(test, waiter_result.request_op_code,
				cases[i].request_op);
		KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			waiter_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, waiter_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_FUTURE_SEQUENCE_NUMBER);
		KUNIT_EXPECT_TRUE(test, waiter_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(waiter_result.key_guid, parent_guid,
				       sizeof(parent_guid)),
				0);

		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_single_buffer(
					buffer, sizeof(buffer), &written,
					&kmes_snapshot),
				0);
		type_len = get_unaligned_le16(
			buffer + KMES_EVENT_TYPE_LEN_OFFSET);
		header_size = get_unaligned_le32(
			buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
		KUNIT_ASSERT_EQ(test, type_len,
				(u16)(sizeof(event_type) - 1));
		KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
				(u8)KMES_ORIGIN_LCS);
		KUNIT_EXPECT_EQ(
			test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE,
			       event_type, type_len),
			0);
		KUNIT_ASSERT_TRUE(test, written > header_size);
		KUNIT_EXPECT_TRUE(test,
				  pkm_lcs_kunit_buffer_contains(
					  buffer, written, validation_class));
		KUNIT_EXPECT_TRUE(
			test,
			pkm_lcs_kunit_buffer_contains_bytes(
				buffer, written, parent_guid,
				sizeof(parent_guid)));

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_path_metadata_sd_audits(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] = "malformed_security_descriptor";
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
		0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
		0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
	};
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	static const struct {
		u16 request_op;
		u16 response_op;
		u64 txn_id;
	} cases[] = {
		{ RSI_LOOKUP, RSI_LOOKUP_RESPONSE, 0xd1d2d3d4d5d6d7d8ULL },
		{ RSI_ENUM_CHILDREN, RSI_ENUM_CHILDREN_RESPONSE,
		  0xd9dadbdcdddedfe0ULL },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_lcs_source_response_result response_result = { };
		struct pkm_lcs_source_response_result waiter_result = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_lcs_source_response_waiter waiter;
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
		u8 response[256];
		u8 buffer[512];
		u8 out[128];
		struct file file = { };
		const void *token;
		size_t response_len;
		size_t written = 0;
		size_t offset;
		ssize_t count;
		u32 header_size;
		long ret;
		u16 type_len;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		if (cases[i].request_op == RSI_LOOKUP) {
			ret = pkm_lcs_source_dispatch_lookup_waitable_request(
				1, cases[i].txn_id, parent_guid, "Child",
				strlen("Child"), &waiter, &enqueue);
		} else {
			ret = pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
				1, cases[i].txn_id, parent_guid, &waiter,
				&enqueue);
		}
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (ret)
			goto out_release_source;

		count = pkm_lcs_kunit_source_device_read_file(
			&file, out, sizeof(out), true);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
		if (count != (ssize_t)enqueue.len)
			goto out_release_source;

		pkm_lcs_kunit_rsi_response_begin(
			test, response, sizeof(response), enqueue.request_id,
			cases[i].response_op, RSI_OK, &offset);
		if (cases[i].request_op == RSI_LOOKUP) {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
		} else {
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
			pkm_lcs_kunit_rsi_append_len_prefixed(
				test, response, sizeof(response), &offset,
				"Child", strlen("Child"));
			pkm_lcs_kunit_rsi_append_u32(test, response,
						     sizeof(response),
						     &offset, 1);
		}
		pkm_lcs_kunit_rsi_append_lookup_path_entry(
			test, response, sizeof(response), &offset, "base",
			RSI_PATH_TARGET_GUID, child_guid, 0);
		pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
					     &offset, 1);
		pkm_lcs_kunit_rsi_append_lookup_metadata(
			test, response, sizeof(response), &offset, child_guid,
			bad_sd, sizeof(bad_sd));
		pkm_lcs_kunit_rsi_finish_response(test, response, offset,
						  &response_len);

		pkm_kmes_kunit_reset_all();
		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false,
			&response_result);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_release_source;
		KUNIT_EXPECT_EQ(test, response_result.request_op_code,
				cases[i].request_op);
		KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
		KUNIT_EXPECT_TRUE(test,
				  response_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			response_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, response_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_SECURITY_DESCRIPTOR);
		KUNIT_EXPECT_TRUE(test, response_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(response_result.key_guid, parent_guid,
				       sizeof(parent_guid)),
				0);

		ret = pkm_lcs_source_response_waiter_wait(&waiter,
							  &waiter_result);
		KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
		KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
		KUNIT_EXPECT_TRUE(
			test,
			waiter_result.source_validation_failure_present);
		KUNIT_EXPECT_EQ(
			test, waiter_result.source_validation_failure,
			(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_SECURITY_DESCRIPTOR);
		KUNIT_EXPECT_TRUE(test, waiter_result.key_guid_present);
		KUNIT_EXPECT_EQ(test,
				memcmp(waiter_result.key_guid, parent_guid,
				       sizeof(parent_guid)),
				0);

		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_single_buffer(
					buffer, sizeof(buffer), &written,
					&kmes_snapshot),
				0);
		type_len = get_unaligned_le16(
			buffer + KMES_EVENT_TYPE_LEN_OFFSET);
		header_size = get_unaligned_le32(
			buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
		KUNIT_ASSERT_EQ(test, type_len,
				(u16)(sizeof(event_type) - 1));
		KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
				(u8)KMES_ORIGIN_LCS);
		KUNIT_EXPECT_EQ(
			test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE,
			       event_type, type_len),
			0);
		KUNIT_ASSERT_TRUE(test, written > header_size);
		KUNIT_EXPECT_TRUE(test,
				  pkm_lcs_kunit_buffer_contains(
					  buffer, written, validation_class));
		KUNIT_EXPECT_TRUE(
			test,
			pkm_lcs_kunit_buffer_contains_bytes(
				buffer, written, parent_guid,
				sizeof(parent_guid)));

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_enum_duplicate_tie_audits(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] = "duplicate_winning_sequence_tie";
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	static const u8 child_guid_a[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 child_guid_b[RSI_GUID_SIZE] = {
		0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
		0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
	};
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_response_result waiter_result = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	u8 response[384];
	u8 buffer[512];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t written = 0;
	size_t offset;
	ssize_t count;
	u32 header_size;
	long ret;
	u16 type_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	ret = pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
		1, 0xe1e2e3e4e5e6e7e8ULL, parent_guid, &waiter, &enqueue);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_release_source;

	count = pkm_lcs_kunit_source_device_read_file(
		&file, out, sizeof(out), true);
	KUNIT_EXPECT_EQ(test, count, (ssize_t)enqueue.len);
	if (count != (ssize_t)enqueue.len)
		goto out_release_source;

	pkm_lcs_kunit_rsi_response_begin(
		test, response, sizeof(response), enqueue.request_id,
		RSI_ENUM_CHILDREN_RESPONSE, RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, response,
					      sizeof(response), &offset,
					      "Child", strlen("Child"));
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid_a, 0);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid_b, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid_a,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid_b,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	pkm_kmes_kunit_reset_all();
	count = pkm_lcs_kunit_source_device_write_file(
		&file, response, response_len, false, &response_result);
	KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
	if (count != (ssize_t)response_len)
		goto out_release_source;
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_ENUM_CHILDREN);
	KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
	KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_TRUE(test,
			  response_result.source_validation_failure_present);
	KUNIT_EXPECT_EQ(
		test, response_result.source_validation_failure,
		(u32)PKM_LCS_SOURCE_VALIDATION_DUPLICATE_WINNING_SEQUENCE_TIE);
	KUNIT_EXPECT_TRUE(test, response_result.key_guid_present);
	KUNIT_EXPECT_EQ(test,
			memcmp(response_result.key_guid, parent_guid,
			       sizeof(parent_guid)),
			0);

	ret = pkm_lcs_source_response_waiter_wait(&waiter, &waiter_result);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_TRUE(test, waiter_result.malformed_source_data);
	KUNIT_EXPECT_TRUE(test,
			  waiter_result.source_validation_failure_present);
	KUNIT_EXPECT_EQ(
		test, waiter_result.source_validation_failure,
		(u32)PKM_LCS_SOURCE_VALIDATION_DUPLICATE_WINNING_SEQUENCE_TIE);
	KUNIT_EXPECT_TRUE(test, waiter_result.key_guid_present);
	KUNIT_EXPECT_EQ(test,
			memcmp(waiter_result.key_guid, parent_guid,
			       sizeof(parent_guid)),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, sizeof(buffer), &written, &kmes_snapshot),
			0);
	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)(sizeof(event_type) - 1));
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_LCS);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains(
				  buffer, written, validation_class));
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains_bytes(
				  buffer, written, parent_guid,
				  sizeof(parent_guid)));

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_FALSE(test, snapshot.closing);

out_release_source:
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_read_key_payload_validation(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] = "malformed_security_descriptor";
	static const u8 guid[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xd1 };
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	static const bool malformed_cases[] = { false, true };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(malformed_cases); i++) {
		struct pkm_lcs_kunit_read_key_source_script script = {
			.expected_guid = guid,
			.name = "Machine",
			.parent_guid = parent_guid,
			.sd = malformed_cases[i] ? bad_sd :
						 pkm_lcs_kunit_owner_only_sd,
			.sd_len = malformed_cases[i] ? sizeof(bad_sd) :
							 sizeof(pkm_lcs_kunit_owner_only_sd),
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
		struct pkm_lcs_rsi_read_key_result read_key = { };
		struct task_struct *task;
		u8 buffer[512];
		struct file file = { };
		const void *token;
		size_t written = 0;
		int thread_ret;
		u32 header_size;
		long ret;
		u16 type_len;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		script.file = &file;
		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_read_key_source_thread, &script,
			"pkm-lcs-kunit-read-key-write");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start read-key source");
			goto out_release_source;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
			1, 0, guid, PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT,
			&frame, &response, &enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);

		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, script.reads, 1U);
		KUNIT_EXPECT_EQ(test, script.writes, 1U);
		KUNIT_EXPECT_EQ(test, response.request_op_code,
				(u16)RSI_READ_KEY);
		KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
		KUNIT_EXPECT_EQ(test, response.malformed_source_data,
				malformed_cases[i]);
		KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);
		KUNIT_EXPECT_EQ(test, ret,
				malformed_cases[i] ? (long)-EIO : 0L);
		if (malformed_cases[i]) {
			KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
			KUNIT_EXPECT_EQ(test, frame.len, (size_t)0);
			KUNIT_EXPECT_TRUE(
				test,
				response.source_validation_failure_present);
			KUNIT_EXPECT_EQ(
				test, response.source_validation_failure,
				(u32)PKM_LCS_SOURCE_VALIDATION_MALFORMED_SECURITY_DESCRIPTOR);
			KUNIT_EXPECT_TRUE(test, response.key_guid_present);
			KUNIT_EXPECT_EQ(test,
					memcmp(response.key_guid, guid,
					       sizeof(guid)),
					0);
			KUNIT_ASSERT_EQ(test,
					pkm_kmes_kunit_copy_single_buffer(
						buffer, sizeof(buffer), &written,
						&kmes_snapshot),
					0);
			type_len = get_unaligned_le16(
				buffer + KMES_EVENT_TYPE_LEN_OFFSET);
			header_size = get_unaligned_le32(
				buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
			KUNIT_ASSERT_EQ(test, type_len,
					(u16)(sizeof(event_type) - 1));
			KUNIT_EXPECT_EQ(test,
					buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
					(u8)KMES_ORIGIN_LCS);
			KUNIT_EXPECT_EQ(
				test,
				memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE,
				       event_type, type_len),
				0);
			KUNIT_ASSERT_TRUE(test, written > header_size);
			KUNIT_EXPECT_TRUE(
				test,
				pkm_lcs_kunit_buffer_contains(
					buffer, written, validation_class));
			KUNIT_EXPECT_TRUE(
				test,
				pkm_lcs_kunit_buffer_contains_bytes(
					buffer, written, guid, sizeof(guid)));
		} else {
			KUNIT_ASSERT_NOT_NULL(test, frame.data);
			KUNIT_EXPECT_EQ(test,
					pkm_lcs_rsi_materialize_read_key_response(
						frame.data, frame.len,
						response.request_id, &read_key),
					0L);
			KUNIT_EXPECT_EQ(test, read_key.sd_len,
					(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
			KUNIT_EXPECT_EQ(test, read_key.name_len,
					(u32)strlen("Machine"));
		}

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);
		pkm_lcs_source_response_frame_destroy(&frame);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_query_values_payload_validation(
	struct kunit *test)
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	static const char validation_class[] = "future_sequence_number";
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 data[] = { 0x10, 0x20, 0x30 };
	static const bool malformed_cases[] = { false, true };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(malformed_cases); i++) {
		struct pkm_lcs_kunit_query_values_source_script script = {
			.expected_guid = guid,
			.expected_value_name = "Value",
			.layer_name = "base",
			.data = data,
			.data_len = sizeof(data),
			.value_type = REG_BINARY,
			.sequence = malformed_cases[i] ? 1 : 0,
		};
		struct pkm_lcs_source_response_frame frame = { };
		struct pkm_lcs_source_response_result response = { };
		struct pkm_lcs_source_enqueue_result enqueue = { };
		struct pkm_lcs_source_fd_snapshot snapshot = { };
		struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
		struct pkm_lcs_rsi_query_value_result value = { };
		struct task_struct *task;
		u8 buffer[512];
		struct file file = { };
		const void *token;
		size_t written = 0;
		int thread_ret;
		u32 header_size;
		long ret;
		u16 type_len;

		pkm_lcs_kunit_setup_registered_source(test, &file, &token);
		script.file = &file;
		task = pkm_lcs_kunit_kthread_run(
			pkm_lcs_kunit_query_values_source_thread, &script,
			"pkm-lcs-kunit-query-write");
		if (IS_ERR(task)) {
			KUNIT_FAIL(test, "failed to start query-values source");
			goto out_release_source;
		}

		pkm_kmes_kunit_reset_all();
		ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
			1, 0, guid, "Value", strlen("Value"), false,
			PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame, &response,
			&enqueue);
		thread_ret = pkm_lcs_kunit_kthread_stop(task);

		KUNIT_EXPECT_EQ(test, thread_ret, 0);
		KUNIT_EXPECT_EQ(test, script.result, 0);
		KUNIT_EXPECT_EQ(test, script.reads, 1U);
		KUNIT_EXPECT_EQ(test, script.writes, 1U);
		KUNIT_EXPECT_EQ(test, response.request_op_code,
				(u16)RSI_QUERY_VALUES);
		KUNIT_EXPECT_EQ(test, response.status, (u32)RSI_OK);
		KUNIT_EXPECT_EQ(test, response.malformed_source_data,
				malformed_cases[i]);
		KUNIT_EXPECT_EQ(test, response.in_flight_count, 0U);
		KUNIT_EXPECT_EQ(test, ret,
				malformed_cases[i] ? (long)-EIO : 0L);
		if (malformed_cases[i]) {
			KUNIT_EXPECT_PTR_EQ(test, frame.data, NULL);
			KUNIT_EXPECT_EQ(test, frame.len, (size_t)0);
			KUNIT_EXPECT_TRUE(
				test,
				response.source_validation_failure_present);
			KUNIT_EXPECT_EQ(
				test, response.source_validation_failure,
				(u32)PKM_LCS_SOURCE_VALIDATION_FUTURE_SEQUENCE_NUMBER);
			KUNIT_EXPECT_TRUE(test, response.key_guid_present);
			KUNIT_EXPECT_EQ(test,
					memcmp(response.key_guid, guid,
					       sizeof(guid)),
					0);
			KUNIT_ASSERT_EQ(test,
					pkm_kmes_kunit_copy_single_buffer(
						buffer, sizeof(buffer), &written,
						&kmes_snapshot),
					0);
			type_len = get_unaligned_le16(
				buffer + KMES_EVENT_TYPE_LEN_OFFSET);
			header_size = get_unaligned_le32(
				buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
			KUNIT_ASSERT_EQ(test, type_len,
					(u16)(sizeof(event_type) - 1));
			KUNIT_EXPECT_EQ(test,
					buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
					(u8)KMES_ORIGIN_LCS);
			KUNIT_EXPECT_EQ(
				test,
				memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE,
				       event_type, type_len),
				0);
			KUNIT_ASSERT_TRUE(test, written > header_size);
			KUNIT_EXPECT_TRUE(
				test,
				pkm_lcs_kunit_buffer_contains(
					buffer, written, validation_class));
			KUNIT_EXPECT_TRUE(
				test,
				pkm_lcs_kunit_buffer_contains_bytes(
					buffer, written, guid, sizeof(guid)));
		} else {
			KUNIT_ASSERT_NOT_NULL(test, frame.data);
			KUNIT_EXPECT_EQ(test,
						pkm_lcs_rsi_materialize_query_value_response(
							frame.data, frame.len,
							response.request_id, 1,
							"Value", strlen("Value"),
							layers, ARRAY_SIZE(layers),
							NULL, 0, NULL, &value),
					0L);
			KUNIT_EXPECT_TRUE(test, value.found);
			KUNIT_EXPECT_EQ(test, value.value_type, (u32)REG_BINARY);
			KUNIT_EXPECT_EQ(test, value.data_len, (u32)sizeof(data));
		}

		pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
		KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
		KUNIT_EXPECT_FALSE(test, snapshot.closing);
		pkm_lcs_source_response_frame_destroy(&frame);

out_release_source:
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		pkm_lcs_kunit_reset_source_table();
		kacs_rust_token_drop(token);
	}
}


static void pkm_lcs_kunit_source_write_accepts_complete_lookup_response(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x77 };
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[256];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t offset;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x6162636465666768ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 enqueue.request_id,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, enqueue.request_id);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, response_result.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_malformed_framing_downs_source(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x78 };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE + 1];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x7172737475767778ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, RSI_MIN_RESPONSE_SIZE - 1U,
				false, NULL),
			(ssize_t)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.closing);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&table_snapshot, 0, sizeof(table_snapshot));
	memset(&enqueue, 0, sizeof(enqueue));
	memset(&file, 0, sizeof(file));

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x7172737475767779ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE + 1U,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.closing);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_unknown_id_downs_source(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x78 };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x7172737475767780ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id + 1U,
					    enqueue.op_code, RSI_NOT_FOUND,
					    &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.closing);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_malformed_protocol_waiter_eio(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x78 };
	struct pkm_lcs_source_response_result wait_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request(
				1, 0x7172737475767781ULL, parent_guid,
				"Child", strlen("Child"), &waiter,
				&enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id + 1U,
					    enqueue.op_code, RSI_NOT_FOUND,
					    &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)-EINVAL);
	KUNIT_ASSERT_TRUE(test, waiter.completed);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &wait_result),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, wait_result.request_id, enqueue.request_id);
	KUNIT_EXPECT_EQ(test, wait_result.request_op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, wait_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.closing);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_opcode_mismatch_downs_source(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x78 };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x7172737475767782ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, RSI_CREATE_KEY,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.closing);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_duplicate_after_release_downs_source(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x78 };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x7172737475767783ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_TRUE(test, snapshot.closing);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_fault_preserves_record(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x79 };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x8182838485868788ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, true, NULL),
			(ssize_t)-EFAULT);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_malformed_lookup_data_succeeds(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x7a };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x42 };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[256];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t offset;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0x9192939495969798ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 enqueue.request_id,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_poll_registers_read_wait_queue(
	struct kunit *test)
{
	struct pkm_lcs_kunit_poll_capture capture = { };
	struct pkm_lcs_source_fd *source_fd;
	struct file file = { };
	const void *token;
	__poll_t mask;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);

	init_poll_funcptr(&capture.table,
			  pkm_lcs_kunit_poll_capture_queue);
	mask = pkm_lcs_kunit_source_device_poll_file_with_table(
		&file, &capture.table);

	KUNIT_EXPECT_EQ(test, (u32)mask, (u32)EPOLLOUT);
	KUNIT_EXPECT_EQ(test, capture.calls, 1U);
	KUNIT_EXPECT_PTR_EQ(test, capture.file, &file);
	KUNIT_EXPECT_PTR_EQ(test, capture.wait_address,
			    &source_fd->read_wait);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_poll_reports_active_readiness(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x7b };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 out[128];
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)EPOLLOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_request(
				1, 0xa1a2a3a4a5a6a7a8ULL, parent_guid,
				"Child", strlen("Child"), &enqueue),
			0L);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)(EPOLLIN | EPOLLOUT));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)EPOLLOUT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_poll_reports_unregistered_and_closing(
	struct kunit *test)
{
	struct file file = { };
	struct pkm_lcs_source_fd *source_fd;
	const void *token;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file), 0U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	kacs_rust_token_drop(token);

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	source_fd = file.private_data;
	KUNIT_ASSERT_NOT_NULL(test, source_fd);
	mutex_lock(&source_fd->queue_lock);
	source_fd->closing = true;
	mutex_unlock(&source_fd->queue_lock);
	KUNIT_EXPECT_EQ(
		test, (u32)pkm_lcs_kunit_source_device_poll_file(&file),
		(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_completes_waiting_lookup(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x7c };
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	};
	struct pkm_lcs_source_response_result write_result = { };
	struct pkm_lcs_source_response_result wait_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[256];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t offset;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request(
				1, 0xa9aaabacadaeafb0ULL, parent_guid,
				"Child", strlen("Child"), &waiter,
				&enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 enqueue.request_id,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&write_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_TRUE(test, write_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, write_result.in_flight_count, 0U);
	KUNIT_EXPECT_TRUE(test, waiter.completed);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &wait_result),
			0L);
	KUNIT_EXPECT_EQ(test, wait_result.request_id, enqueue.request_id);
	KUNIT_EXPECT_EQ(test, wait_result.request_op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, wait_result.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, wait_result.malformed_source_data);
	KUNIT_EXPECT_EQ(test, wait_result.in_flight_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_write_maps_status_to_waiter_errno(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x7d };
	struct pkm_lcs_source_response_result wait_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request(
				1, 0xb1b2b3b4b5b6b7b8ULL, parent_guid,
				"Missing", strlen("Missing"), &waiter,
				&enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)response_len);
	KUNIT_EXPECT_TRUE(test, waiter.completed);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &wait_result),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, wait_result.status, (u32)RSI_NOT_FOUND);
	KUNIT_EXPECT_FALSE(test, wait_result.malformed_source_data);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_waiter_retains_lookup_response_frame(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x73 };
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	struct pkm_lcs_source_response_result wait_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_response_frame retained;
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 expected[256];
	u8 response[256];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t offset;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request_retaining_frame(
				1, 0xf1f2f3f4f5f6f7f8ULL, parent_guid,
				"Child", strlen("Child"), &waiter,
				&retained, &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 enqueue.request_id,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, child_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);
	memcpy(expected, response, response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)response_len);
	memset(response, 0xcc, response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &wait_result),
			0L);
	KUNIT_EXPECT_EQ(test, retained.len, response_len);
	KUNIT_ASSERT_NOT_NULL(test, retained.data);
	KUNIT_EXPECT_EQ(test,
			memcmp(retained.data, expected, response_len), 0);
	KUNIT_EXPECT_EQ(test, wait_result.request_id, enqueue.request_id);
	KUNIT_EXPECT_EQ(test, wait_result.status, (u32)RSI_OK);

	pkm_lcs_source_response_frame_destroy(&retained);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_waiter_does_not_retain_error_frame(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x74 };
	struct pkm_lcs_source_response_result wait_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_response_frame retained;
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request_retaining_frame(
				1, 0xf9fafbfcfdfeff01ULL, parent_guid,
				"Missing", strlen("Missing"), &waiter,
				&retained, &enqueue),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &wait_result),
			(long)-ENOENT);
	KUNIT_EXPECT_PTR_EQ(test, retained.data, NULL);
	KUNIT_EXPECT_EQ(test, retained.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, wait_result.status, (u32)RSI_NOT_FOUND);

	pkm_lcs_source_response_frame_destroy(&retained);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_release_completes_waiter_with_eio(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x7e };
	struct pkm_lcs_source_response_result wait_result = { };
	struct pkm_lcs_source_response_waiter waiter;
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_dispatch_lookup_waitable_request(
				1, 0xc1c2c3c4c5c6c7c8ULL, parent_guid,
				"Child", strlen("Child"), &waiter,
				&enqueue),
			0L);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_TRUE(test, waiter.completed);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_response_waiter_wait(&waiter,
							    &wait_result),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, wait_result.request_id, enqueue.request_id);
	KUNIT_EXPECT_EQ(test, wait_result.request_op_code, (u16)RSI_LOOKUP);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_slot_wait_wakes_on_response(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x82 };
	struct pkm_lcs_kunit_slot_wait_round_trip_script script = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	struct task_struct *task;
	u8 request[128];
	struct file file = { };
	const void *token;
	size_t response_len;
	u64 request_id = 0;
	u16 op_code = 0;
	ssize_t count;
	bool released = false;
	long ret;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_dispatch_lookup_request(
					1, i, parent_guid, "Held",
					strlen("Held"), NULL),
				0L);
	}

	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		count = pkm_lcs_kunit_source_device_read_file(
			&file, request, sizeof(request), true);
		KUNIT_ASSERT_GE(test, count,
				(ssize_t)RSI_REQUEST_HEADER_SIZE);
		if (!i) {
			request_id = get_unaligned_le64(
				request + RSI_REQUEST_ID_OFFSET);
			op_code = get_unaligned_le16(
				request + RSI_REQUEST_OP_CODE_OFFSET);
		}
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);

	init_completion(&script.started);
	init_completion(&script.done);
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_slot_wait_round_trip_thread, &script,
		"pkm-lcs-slot-wait");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start source slot-wait worker");
		goto out_release_source;
	}
	if (!wait_for_completion_timeout(&script.started, HZ)) {
		KUNIT_FAIL(test, "source slot-wait worker did not start");
		goto out_stop_task;
	}
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&script.done,
						    msecs_to_jiffies(20)),
			0UL);
	KUNIT_EXPECT_EQ(test, script.enqueue.len, (size_t)0);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, op_code, RSI_NOT_FOUND,
					    &response_len);
	count = pkm_lcs_kunit_source_device_write_file(
		&file, response, response_len, false, NULL);
	KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
	if (count != (ssize_t)response_len)
		goto out_stop_task;

	for (i = 0; i < 100 && !completion_done(&script.done); i++) {
		count = pkm_lcs_kunit_source_device_read_file(
			&file, request, sizeof(request), true);
		if (count == -EAGAIN) {
			msleep(1);
			continue;
		}
		KUNIT_EXPECT_GE(test, count,
				(ssize_t)RSI_REQUEST_HEADER_SIZE);
		if (count < (ssize_t)RSI_REQUEST_HEADER_SIZE)
			goto out_stop_task;
		request_id = get_unaligned_le64(
			request + RSI_REQUEST_ID_OFFSET);
		op_code = get_unaligned_le16(
			request + RSI_REQUEST_OP_CODE_OFFSET);
		pkm_lcs_kunit_build_status_response(test, response,
						    sizeof(response),
						    request_id, op_code,
						    RSI_NOT_FOUND,
						    &response_len);
		count = pkm_lcs_kunit_source_device_write_file(
			&file, response, response_len, false, NULL);
		KUNIT_EXPECT_EQ(test, count, (ssize_t)response_len);
		if (count != (ssize_t)response_len)
			goto out_stop_task;
	}
	if (!wait_for_completion_timeout(&script.done, HZ))
		KUNIT_FAIL(test, "source slot waiter did not complete");

out_stop_task:
	if (!completion_done(&script.done) && !released) {
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
		released = true;
		wait_for_completion_timeout(&script.done, HZ);
	}
	ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!completion_done(&script.done))
		goto out_release_source;
	if (released)
		goto out_release_source;

	KUNIT_EXPECT_EQ(test, script.ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, script.enqueue.request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, script.enqueue.op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, script.enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, script.enqueue.in_flight_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, script.response.status, (u32)RSI_NOT_FOUND);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT - 1);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT + 1);

out_release_source:
	if (!released)
		KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file),
				0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_slot_timeout_sends_no_request(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x7f };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct file file = { };
	const void *token;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT; i++) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_dispatch_lookup_request(
					1, i, parent_guid, "Child",
					strlen("Child"), NULL),
				0L);
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_lookup_round_trip_timeout(
				1, 0xd1d2d3d4d5d6d7d8ULL, parent_guid,
				"Next", strlen("Next"), 1, &response,
				&enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, response.len, (size_t)0);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count,
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id,
			(u64)PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_response_timeout_retains_late_record(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x80 };
	struct pkm_lcs_source_response_result timeout_response = { };
	struct pkm_lcs_source_response_result write_result = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_lookup_round_trip_timeout(
				1, 0xe1e2e3e4e5e6e7e8ULL, parent_guid,
				"Late", strlen("Late"), 1,
				&timeout_response, &enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test, enqueue.queue_depth, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.in_flight_count, 1U);
	KUNIT_EXPECT_EQ(test, enqueue.next_request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, timeout_response.len, (size_t)0);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 1ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(&file, out,
							      sizeof(out),
							      true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET),
			enqueue.request_id);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_NOT_FOUND, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&write_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, write_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, write_result.status, (u32)RSI_NOT_FOUND);
	KUNIT_EXPECT_EQ(test, write_result.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 1ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_source_hide_delete_entry_runtime_limits_layer_frame(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x61,
	};
	static const char child_name[] = "Child";
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_path_entry_source_script script = { };
	struct pkm_lcs_source_response_result response = { };
	struct file file = { };
	const void *token;
	struct task_struct *task;
	char layer_name[301];
	int thread_ret;
	long ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_path_component_length = 300U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	memset(layer_name, 'l', sizeof(layer_name) - 1);
	layer_name[sizeof(layer_name) - 1] = '\0';

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	script.file = &file;
	script.expected_parent_guid = parent_guid;
	script.expected_child_name = child_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x5152535455565758ULL;
	script.expected_sequence = 0x6162636465666768ULL;
	script.expected_op_code = RSI_HIDE_ENTRY;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_path_entry_source_thread,
					 &script,
					 "pkm-lcs-kunit-hide-layer-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_hide_entry_round_trip_timeout(
		1, script.expected_txn_id, parent_guid, child_name,
		strlen(child_name), layer_name, sizeof(layer_name) - 1,
		script.expected_sequence, 1000, &response, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code, (u16)RSI_HIDE_ENTRY);

	memset(&script, 0, sizeof(script));
	memset(&response, 0, sizeof(response));
	script.file = &file;
	script.expected_parent_guid = parent_guid;
	script.expected_child_name = child_name;
	script.expected_layer_name = layer_name;
	script.expected_txn_id = 0x7172737475767778ULL;
	script.expected_op_code = RSI_DELETE_ENTRY;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_path_entry_source_thread,
					 &script,
					 "pkm-lcs-kunit-delete-layer-limits");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_delete_entry_round_trip_timeout(
		1, script.expected_txn_id, parent_guid, child_name,
		strlen(child_name), layer_name, sizeof(layer_name) - 1, 1000,
		&response, NULL);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_DELETE_ENTRY);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_source_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_rejects_null_token),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_marks_tcb_used),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_attaches_private_state),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_overwrites_misc_private_data),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_success),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_rejects_padding),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_fails_closed_on_faults),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_fault_zeroes_output),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_entrypoint_fault_unpublished),
	KUNIT_CASE(pkm_lcs_kunit_source_device_raw_ioctl_entrypoints_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_bounds_hive_count),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_runtime_hive_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_runtime_raised_hive_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_runtime_source_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_runtime_raised_source_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_accepts_valid),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_rejects_bad_hive),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_rejects_sequence_overflow),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rejects_sequence_overflow_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rejects_reserved_fields_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rejects_zero_hive_count_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rechecks_tcb_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rejects_malformed_hive_names),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rejects_bad_hive_flags_scope),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_rejects_duplicate_routes_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_accepts_private_shadow_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_accepts_distinct_private_scopes_live),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_publishes_active_slot),
	KUNIT_CASE(pkm_lcs_kunit_source_active_ids_snapshot_filters_down),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_rejects_active_collision),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_resumes_down_slot),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_resume_dispatches_overflow),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_resume_revalidates_key_fd),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_denied_ioctl_skips_revalidation),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_resume_revalidate_retains_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_resume_missing_guid_enoent),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_flush_revalidate_missing_guid_enoent),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_rejects_stale_resume),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_rejects_repeat_register),
	KUNIT_CASE(pkm_lcs_kunit_source_bootstrap_refresh_machine_hive_success),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_bootstrap_queues_after_publish),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_bootstrap_ignores_non_machine),
	KUNIT_CASE(pkm_lcs_kunit_source_bootstrap_refresh_bad_inputs_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_runtime_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_raised_runtime_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_source_down),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_read_only_transaction_counter_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_read_only_transaction_counter_runtime_limit),
	KUNIT_CASE(pkm_lcs_kunit_route_runtime_reduced_scope_limit),
	KUNIT_CASE(pkm_lcs_kunit_route_runtime_raised_scope_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_validation_audit_emits_lcs_kmes_event),
	KUNIT_CASE(pkm_lcs_kunit_self_config_invalid_audit_emits_lcs_kmes_event),
	KUNIT_CASE(pkm_lcs_kunit_self_config_invalid_audit_rejects_bad_shape),
	KUNIT_CASE(pkm_lcs_kunit_runtime_limits_default_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_runtime_limits_publish_valid_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_runtime_limits_invalid_retains_previous),
	KUNIT_CASE(pkm_lcs_kunit_self_config_apply_hot_swaps_valid_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_self_config_apply_invalid_retains_and_audits),
	KUNIT_CASE(pkm_lcs_kunit_self_config_apply_missing_retains_and_audits),
	KUNIT_CASE(pkm_lcs_kunit_self_config_apply_malformed_input_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_self_config_refresh_from_source_hot_swaps),
	KUNIT_CASE(pkm_lcs_kunit_self_config_refresh_from_source_wrong_type_retains),
	KUNIT_CASE(pkm_lcs_kunit_self_config_refresh_malformed_source_retains),
	KUNIT_CASE(pkm_lcs_kunit_self_config_machine_hive_discovers_registry),
	KUNIT_CASE(pkm_lcs_kunit_self_config_missing_registry_retains_defaults),
	KUNIT_CASE(pkm_lcs_kunit_self_config_missing_system_retains_defaults),
	KUNIT_CASE(pkm_lcs_kunit_self_config_machine_hive_bad_inputs_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_runtime_request_timeout_uses_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_runtime_transaction_timeout_uses_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_runtime_symlink_depth_uses_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_runtime_max_key_depth_uses_snapshot),
	KUNIT_CASE(pkm_lcs_kunit_runtime_path_component_limit_relative),
	KUNIT_CASE(pkm_lcs_kunit_runtime_total_path_limit_absolute),
	KUNIT_CASE(pkm_lcs_kunit_source_down_marks_bound_transaction),
	KUNIT_CASE(pkm_lcs_kunit_source_down_ignores_unbound_transaction),
	KUNIT_CASE(pkm_lcs_kunit_live_base_layer_write_uses_cached_sd),
	KUNIT_CASE(pkm_lcs_kunit_source_enum_children_round_trip_retains_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_query_values_round_trip_retains_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_returns_complete_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_preserves_fifo_order),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_short_buffer_preserves_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_fault_preserves_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_blocking_read_wakes_on_enqueue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_blocking_read_wakes_on_closing),
	KUNIT_CASE(pkm_lcs_kunit_source_request_enqueue_rejects_bad_state),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_lookup_allocates_monotonic_ids),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_create_entry_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_hide_delete_entry_frames),
	KUNIT_CASE(pkm_lcs_kunit_source_hide_delete_entry_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_create_key_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_create_frames_use_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_write_key_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_set_value_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_set_value_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_delete_value_entry_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_delete_value_entry_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_set_blanket_tombstone_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_set_blanket_tombstone_runtime_limits_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_set_blanket_tombstone_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_set_blanket_tombstone_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_flush_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_flush_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_drop_key_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_drop_key_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_delete_layer_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_delete_layer_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_delete_layer_applies_orphans),
	KUNIT_CASE(pkm_lcs_kunit_source_delete_layer_broadcast_active_sources),
	KUNIT_CASE(pkm_lcs_kunit_source_delete_layer_replays_registered_down_source),
	KUNIT_CASE(pkm_lcs_kunit_source_delete_layer_resume_replay_failure_stays_down),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_transaction_control_frames),
	KUNIT_CASE(pkm_lcs_kunit_source_abort_response_releases_no_wait_record),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_transaction_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_transaction_round_trip_statuses),
	KUNIT_CASE(pkm_lcs_kunit_source_transaction_round_trip_failures),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_create_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_set_value_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_delete_value_entry_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_path_entry_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_source_read_retains_in_flight_until_release),
	KUNIT_CASE(pkm_lcs_kunit_source_enqueue_rejects_reused_request_id),
	KUNIT_CASE(pkm_lcs_kunit_source_in_flight_full_blocks_after_read),
	KUNIT_CASE(pkm_lcs_kunit_source_in_flight_uses_runtime_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_in_flight_raised_runtime_limit),
	KUNIT_CASE(pkm_lcs_kunit_source_slot_admission_uses_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_response_rejects_before_read),
	KUNIT_CASE(pkm_lcs_kunit_source_response_releases_after_read),
	KUNIT_CASE(pkm_lcs_kunit_source_response_rejects_common_mismatches),
	KUNIT_CASE(pkm_lcs_kunit_source_response_unknown_status_releases),
	KUNIT_CASE(pkm_lcs_kunit_source_write_unknown_status_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_response_duplicate_after_release_rejected),
	KUNIT_CASE(pkm_lcs_kunit_source_write_status_only_payload_exactness),
	KUNIT_CASE(pkm_lcs_kunit_source_write_enum_children_payload_validation),
	KUNIT_CASE(pkm_lcs_kunit_source_write_lookup_runtime_limits_path_names),
	KUNIT_CASE(pkm_lcs_kunit_source_write_enum_children_runtime_limits_child_names),
	KUNIT_CASE(pkm_lcs_kunit_source_write_query_values_runtime_limits_names),
	KUNIT_CASE(pkm_lcs_kunit_source_lookup_round_trip_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_lookup_plain_retains_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_enum_children_round_trip_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_read_key_round_trip_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_key_retains_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_control_retains_supplied_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_malformed_path_name_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_key_value_name_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_invalid_utf8_name_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_remaining_validation_class_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_path_future_sequence_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_path_metadata_sd_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_enum_duplicate_tie_audits),
	KUNIT_CASE(pkm_lcs_kunit_source_write_read_key_payload_validation),
	KUNIT_CASE(pkm_lcs_kunit_source_write_query_values_payload_validation),
	KUNIT_CASE(pkm_lcs_kunit_source_write_accepts_complete_lookup_response),
	KUNIT_CASE(pkm_lcs_kunit_source_write_malformed_framing_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_source_write_unknown_id_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_source_write_malformed_protocol_waiter_eio),
	KUNIT_CASE(pkm_lcs_kunit_source_write_opcode_mismatch_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_source_write_duplicate_after_release_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_source_write_fault_preserves_record),
	KUNIT_CASE(pkm_lcs_kunit_source_write_malformed_lookup_data_succeeds),
	KUNIT_CASE(pkm_lcs_kunit_source_poll_registers_read_wait_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_poll_reports_active_readiness),
	KUNIT_CASE(pkm_lcs_kunit_source_poll_reports_unregistered_and_closing),
	KUNIT_CASE(pkm_lcs_kunit_source_write_completes_waiting_lookup),
	KUNIT_CASE(pkm_lcs_kunit_source_write_maps_status_to_waiter_errno),
	KUNIT_CASE(pkm_lcs_kunit_source_waiter_retains_lookup_response_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_waiter_does_not_retain_error_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_release_completes_waiter_with_eio),
	KUNIT_CASE(pkm_lcs_kunit_source_slot_wait_wakes_on_response),
	KUNIT_CASE(pkm_lcs_kunit_source_slot_timeout_sends_no_request),
	KUNIT_CASE(pkm_lcs_kunit_source_response_timeout_retains_late_record),
	KUNIT_CASE(pkm_lcs_kunit_source_hide_delete_entry_runtime_limits_layer_frame),
	{}
};

static struct kunit_suite pkm_lcs_kunit_source_suite = {
	.name = "pkm_lcs_kunit_source",
	.test_cases = pkm_lcs_kunit_source_cases,
};

kunit_test_suite(pkm_lcs_kunit_source_suite);
