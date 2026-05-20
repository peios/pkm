// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/string.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "source_device.h"

extern size_t lcs_rust_kunit_probe(void);

struct pkm_lcs_kunit_usercopy_ctx {
	const void *fault_src;
	unsigned int reads;
};

static bool pkm_lcs_kunit_usercopy_read(void *raw_ctx, void *dst,
					const void __user *src, size_t len)
{
	struct pkm_lcs_kunit_usercopy_ctx *ctx = raw_ctx;
	const void *ksrc = (const void *)(unsigned long)src;

	ctx->reads++;
	if (!ksrc || ksrc == ctx->fault_src)
		return false;

	memcpy(dst, ksrc, len);
	return true;
}

static struct pkm_lcs_usercopy_ops pkm_lcs_kunit_usercopy_ops(
	struct pkm_lcs_kunit_usercopy_ctx *ctx)
{
	return (struct pkm_lcs_usercopy_ops) {
		.read = pkm_lcs_kunit_usercopy_read,
		.ctx = ctx,
	};
}

static void pkm_lcs_kunit_rust_probe_links_lcs_core(struct kunit *test)
{
	KUNIT_ASSERT_GT(test, lcs_rust_kunit_probe(), (size_t)0);
}

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

static void pkm_lcs_kunit_build_register_args(
	struct reg_src_register_args *args, struct reg_src_hive_entry *hive,
	const char *name, u8 root_guid_first, u64 max_sequence)
{
	memset(args, 0, sizeof(*args));
	memset(hive, 0, sizeof(*hive));
	hive->name_len = strlen(name);
	hive->name_ptr = (u64)(unsigned long)name;
	hive->root_guid[0] = root_guid_first;
	args->hive_count = 1;
	args->max_sequence = max_sequence;
	args->hives_ptr = (u64)(unsigned long)hive;
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

static struct kunit_case pkm_lcs_kunit_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_rust_probe_links_lcs_core),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_rejects_null_token),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_marks_tcb_used),
	KUNIT_CASE(pkm_lcs_kunit_source_device_open_attaches_private_state),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_success),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_rejects_padding),
	KUNIT_CASE(
		pkm_lcs_kunit_source_registration_copy_fails_closed_on_faults),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_copy_bounds_hive_count),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_accepts_valid),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_requires_tcb),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_semantic_rejects_bad_hive),
	KUNIT_CASE(
		pkm_lcs_kunit_source_registration_semantic_rejects_sequence_overflow),
	KUNIT_CASE(
		pkm_lcs_kunit_source_registration_ioctl_publishes_active_slot),
	KUNIT_CASE(
		pkm_lcs_kunit_source_registration_ioctl_rejects_active_collision),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_resumes_down_slot),
	KUNIT_CASE(pkm_lcs_kunit_source_registration_ioctl_rejects_stale_resume),
	KUNIT_CASE(
		pkm_lcs_kunit_source_registration_ioctl_rejects_repeat_register),
	{ }
};

static struct kunit_suite pkm_lcs_kunit_suite = {
	.name = "pkm_lcs_kunit_scaffold",
	.test_cases = pkm_lcs_kunit_cases,
};

kunit_test_suite(pkm_lcs_kunit_suite);
