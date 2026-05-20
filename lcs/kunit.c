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
	const void *fault_strlen_src;
	const void *unterminated_src;
	unsigned int reads;
	unsigned int strnlens;
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

static size_t pkm_lcs_kunit_usercopy_strnlen(void *raw_ctx,
					     const char __user *src,
					     size_t max)
{
	struct pkm_lcs_kunit_usercopy_ctx *ctx = raw_ctx;
	const char *ksrc = (const char *)(unsigned long)src;
	size_t i;

	ctx->strnlens++;
	if (!ksrc || ksrc == ctx->fault_strlen_src)
		return 0;
	if (ksrc == ctx->unterminated_src)
		return max + 1;

	for (i = 0; i < max; i++) {
		if (ksrc[i] == '\0')
			return i + 1;
	}
	return max + 1;
}

static struct pkm_lcs_usercopy_ops pkm_lcs_kunit_usercopy_ops(
	struct pkm_lcs_kunit_usercopy_ctx *ctx)
{
	return (struct pkm_lcs_usercopy_ops) {
		.read = pkm_lcs_kunit_usercopy_read,
		.strnlen = pkm_lcs_kunit_usercopy_strnlen,
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

static void pkm_lcs_kunit_build_private_register_args(
	struct reg_src_register_args *args, struct reg_src_hive_entry *hive,
	const char *name, u8 root_guid_first, u8 scope_guid_first)
{
	pkm_lcs_kunit_build_register_args(args, hive, name, root_guid_first, 0);
	hive->flags = RSI_HIVE_PRIVATE;
	hive->scope_guid[0] = scope_guid_first;
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

static void pkm_lcs_kunit_absolute_path_route_uses_first_component_and_errno(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	const char machine_path[] = "Machine\\Software\\App";
	const char missing_path[] = "Users\\Default";
	const char invalid_path[] = "Machine\\";
	const char unterminated_path[] = "Machine\\Software";
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				machine_path, sizeof(machine_path), false, NULL,
				0, NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				missing_path, sizeof(missing_path), false, NULL,
				0, NULL, 0, &route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				invalid_path, sizeof(invalid_path), false, NULL,
				0, NULL, 0, &route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				unterminated_path, strlen(unterminated_path),
				false, NULL, 0, NULL, 0, &route),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_absolute_path_current_user_rewrite_routes_users(
	struct kunit *test)
{
	const char name_src[] = "Users";
	const char current_user_path[] = "CurrentUser\\Software";
	const char user_sid_component[] = "S-1-5-18";
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				current_user_path, sizeof(current_user_path),
				false, NULL, 0, NULL, 0, &route),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path(
				current_user_path, sizeof(current_user_path),
				true, user_sid_component,
				strlen(user_sid_component), NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_absolute_path_current_user_uses_token_sid(
	struct kunit *test)
{
	const char name_src[] = "Users";
	const char current_user_path[] = "CurrentUser\\Software";
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path_for_token(
				token, current_user_path,
				sizeof(current_user_path), true, NULL, 0,
				&route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);

	memset(&route, 0, sizeof(route));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_absolute_path_for_token(
				NULL, current_user_path,
				sizeof(current_user_path), true, NULL, 0,
				&route),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_syscall_path_copy_bounds_and_faults(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_syscall_path_copy copy = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, copy.path);
	KUNIT_EXPECT_EQ(test, copy.path_len, (u32)sizeof(path_src));
	KUNIT_EXPECT_STREQ(test, copy.path, path_src);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	pkm_lcs_syscall_path_copy_destroy(&copy);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, NULL, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);

	ctx.unterminated_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
	ctx.unterminated_src = NULL;

	ctx.fault_strlen_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
	ctx.fault_strlen_src = NULL;

	ctx.fault_src = path_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_syscall_path_copy_from_user(
				&ops, (const char __user *)path_src, &copy),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, copy.path, NULL);
}

static void pkm_lcs_kunit_user_absolute_path_copy_routes_current_user(
	struct kunit *test)
{
	const char name_src[] = "Users";
	const char current_user_path[] = "CurrentUser\\Software";
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, (const char __user *)current_user_path,
				true, NULL, 0, &route),
			0L);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 4U);

	ctx.fault_src = current_user_path;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, (const char __user *)current_user_path,
				true, NULL, 0, &route),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	ctx.fault_src = NULL;

	ctx.unterminated_src = current_user_path;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, (const char __user *)current_user_path,
				true, NULL, 0, &route),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	ctx.unterminated_src = NULL;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_route_user_absolute_path_for_token(
				token, &ops, NULL, true, NULL, 0, &route),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_preflight_accepts_valid_masks(
	struct kunit *test)
{
	struct pkm_lcs_open_preflight_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(KEY_QUERY_VALUE, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(GENERIC_READ, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access, GENERIC_READ);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(MAXIMUM_ALLOWED |
						       KEY_QUERY_VALUE,
					       REG_OPEN_LINK, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access,
			MAXIMUM_ALLOWED | KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);
}

static void pkm_lcs_kunit_open_preflight_rejects_fail_closed(
	struct kunit *test)
{
	struct pkm_lcs_open_preflight_plan plan = {
		.requested_access = 0xffffffffU,
		.mapped_desired_access = 0xffffffffU,
		.maximum_allowed = 1,
		.path_resolution_allowed = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(KEY_QUERY_VALUE, 0, NULL),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_open_preflight(0, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.requested_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	plan.path_resolution_allowed = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(0x00100000U, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	plan.path_resolution_allowed = 1;
	KUNIT_EXPECT_EQ(test, pkm_lcs_open_preflight(0x00000040U, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	plan.path_resolution_allowed = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_preflight(KEY_QUERY_VALUE,
					       REG_OPEN_LINK | 0x80U, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);
}

static void pkm_lcs_kunit_open_preflight_route_success(
	struct kunit *test)
{
	const char name_src[] = "Machine";
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	struct pkm_lcs_open_preflight_plan plan = { };
	struct pkm_lcs_hive_route_result route = { };
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
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				token, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, REG_OPEN_LINK, false, NULL, 0,
				&plan, &route),
			0L);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_preflight_route_stops_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_open_preflight_plan plan = { };
	struct pkm_lcs_hive_route_result route = {
		.source_id = 99,
		.root_guid = { 88 },
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src, 0, 0,
				false, NULL, 0, &plan, &route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, REG_OPEN_LINK | 0x80U, false,
				NULL, 0, &plan, &route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, false, NULL, 0, NULL,
				&route),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}

static void pkm_lcs_kunit_open_preflight_route_copy_fault_keeps_route_empty(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software";
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = path_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_open_preflight_plan plan = { };
	struct pkm_lcs_hive_route_result route = {
		.source_id = 99,
		.root_guid = { 88 },
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_preflight_for_token(
				NULL, &ops, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, false, NULL, 0, &plan,
				&route),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, plan.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, route.source_id, 0U);
	KUNIT_EXPECT_EQ(test, route.root_guid[0], 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
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
	KUNIT_CASE(pkm_lcs_kunit_hive_route_reflects_active_and_down_slots),
	KUNIT_CASE(pkm_lcs_kunit_hive_route_private_scope_shadows_global),
	KUNIT_CASE(
		pkm_lcs_kunit_absolute_path_route_uses_first_component_and_errno),
	KUNIT_CASE(
		pkm_lcs_kunit_absolute_path_current_user_rewrite_routes_users),
	KUNIT_CASE(
		pkm_lcs_kunit_absolute_path_current_user_uses_token_sid),
	KUNIT_CASE(pkm_lcs_kunit_syscall_path_copy_bounds_and_faults),
	KUNIT_CASE(
		pkm_lcs_kunit_user_absolute_path_copy_routes_current_user),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_accepts_valid_masks),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_rejects_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_success),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_stops_before_usercopy),
	KUNIT_CASE(
		pkm_lcs_kunit_open_preflight_route_copy_fault_keeps_route_empty),
	{ }
};

static struct kunit_suite pkm_lcs_kunit_suite = {
	.name = "pkm_lcs_kunit_scaffold",
	.test_cases = pkm_lcs_kunit_cases,
};

kunit_test_suite(pkm_lcs_kunit_suite);
