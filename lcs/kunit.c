// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "key_fd.h"
#include "rsi.h"
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

static const struct file_operations pkm_lcs_kunit_non_key_fops = { };

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

static long pkm_lcs_kunit_publish_key_fd_with_access(u32 granted_access)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x51 },
		{ 0x52 },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 11,
		.granted_access = granted_access,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}

static long pkm_lcs_kunit_publish_key_fd_with_depth(u32 depth)
{
	const char **path;
	u8 (*ancestors)[PKM_LCS_GUID_BYTES];
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 12,
		.granted_access = KEY_QUERY_VALUE,
		.path_component_count = depth,
	};
	long fd;
	u32 i;

	if (!depth)
		return -EINVAL;

	path = kcalloc(depth, sizeof(*path), GFP_KERNEL);
	if (!path)
		return -ENOMEM;
	ancestors = kcalloc(depth, sizeof(*ancestors), GFP_KERNEL);
	if (!ancestors) {
		kfree(path);
		return -ENOMEM;
	}

	for (i = 0; i < depth; i++) {
		path[i] = "A";
		ancestors[i][0] = 0x70;
		ancestors[i][14] = (u8)(i >> 8);
		ancestors[i][15] = (u8)i;
	}

	input.resolved_path = path;
	input.ancestor_guids = ancestors;
	memcpy(input.key_guid, ancestors[depth - 1U], sizeof(input.key_guid));
	fd = pkm_lcs_key_fd_publish(&input);

	kfree(ancestors);
	kfree(path);
	return fd;
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

static void pkm_lcs_kunit_relative_open_preflight_success(struct kunit *test)
{
	const char path_src[] = "Child/Sub";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)path_src,
				KEY_QUERY_VALUE, REG_OPEN_LINK, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.access.requested_access,
			KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, result.access.mapped_desired_access,
			KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, result.access.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 2U);
	KUNIT_EXPECT_TRUE(test, result.path.used_forward_separator);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 11U);
	KUNIT_EXPECT_EQ(test, result.parent.parent_depth, 2U);
	KUNIT_EXPECT_FALSE(test, result.parent.orphaned);
	KUNIT_EXPECT_EQ(test, result.parent.key_guid[0], 0x52U);
	KUNIT_EXPECT_EQ(test, result.parent.root_guid[0], 0x51U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_relative_open_preflight_stops_bad_scalars(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = {
		.access = {
			.requested_access = 0xffffffffU,
			.path_resolution_allowed = 1,
		},
		.path = {
			.component_count = 99,
			.used_forward_separator = true,
		},
		.parent = {
			.source_id = 88,
		},
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src, 0, 0,
				&result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.access.requested_access, 0U);
	KUNIT_EXPECT_EQ(test, result.access.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 0U);
	KUNIT_EXPECT_FALSE(test, result.path.used_forward_separator);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}

static void
pkm_lcs_kunit_relative_open_preflight_validates_path_before_parent(
	struct kunit *test)
{
	const char path_src[] = "Child\\";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.access.requested_access,
			KEY_QUERY_VALUE);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 0U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}

static void pkm_lcs_kunit_relative_open_preflight_rejects_bad_parent_fd(
	struct kunit *test)
{
	const char path_src[] = "Child\\Sub";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	int fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, -1, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 2U);
	KUNIT_EXPECT_FALSE(test, result.path.used_forward_separator);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	memset(&result, 0, sizeof(result));
	fd = anon_inode_getfd("lcs-not-key", &pkm_lcs_kunit_non_key_fops,
			      NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, fd, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_relative_open_preflight_rejects_orphan_parent(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_access(KEY_QUERY_VALUE);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_set_orphaned((int)fd, true),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)path_src,
				KEY_QUERY_VALUE, 0, &result),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 1U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_relative_open_preflight_checks_combined_depth(
	struct kunit *test)
{
	const char exact_path[] = "Child";
	const char over_path[] = "Child\\Sub";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_relative_open_preflight result = { };
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_depth(511);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)exact_path,
				KEY_QUERY_VALUE, 0, &result),
			0L);
	KUNIT_EXPECT_EQ(test, result.parent.parent_depth, 511U);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 1U);

	memset(&result, 0, sizeof(result));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_preflight(
				&ops, (int)fd, (const char __user *)over_path,
				KEY_QUERY_VALUE, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.path.component_count, 2U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_rsi_lookup_request_frame_success(struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const char child_name[] = "Child";
	u8 frame[96];
	struct pkm_lcs_rsi_built_request built = { };
	size_t payload_offset;
	size_t child_offset;
	size_t expected_len;
	size_t i;

	memset(frame, 0xcc, sizeof(frame));
	expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
		       RSI_LENGTH_PREFIX_SIZE + strlen(child_name);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 0x1112131415161718ULL, 99,
				parent_guid, child_name, strlen(child_name),
				&built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_LOOKUP);

	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x1112131415161718ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_LOOKUP);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			99ULL);

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	KUNIT_EXPECT_EQ(test, memcmp(frame + payload_offset, parent_guid,
				     sizeof(parent_guid)),
			0);
	child_offset = payload_offset + RSI_GUID_SIZE;
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + child_offset),
			(u32)strlen(child_name));
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + child_offset + RSI_LENGTH_PREFIX_SIZE,
			       child_name, strlen(child_name)),
			0);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xccU);
}

static void pkm_lcs_kunit_rsi_lookup_request_frame_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x21 };
	static const char child_name[] = "Child";
	u8 frame[96];
	struct pkm_lcs_rsi_built_request built = {
		.len = 77,
		.request_id = 88,
		.op_code = 99,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				NULL, sizeof(frame), 1, 0, parent_guid,
				child_name, strlen(child_name), &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);

	built.len = 77;
	built.request_id = 88;
	built.op_code = 99;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 1, 0, NULL, child_name,
				strlen(child_name), &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);

	built.len = 77;
	built.request_id = 88;
	built.op_code = 99;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 1, 0, parent_guid, NULL,
				strlen(child_name), &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 1, 0, parent_guid,
				child_name, strlen(child_name), NULL),
			(long)-EINVAL);
}

static void pkm_lcs_kunit_rsi_lookup_request_frame_validates_child(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x31 };
	static const char bad_separator[] = "Bad\\Name";
	char too_long[256];
	u8 frame[96];
	struct pkm_lcs_rsi_built_request built = {
		.len = 55,
		.request_id = 66,
		.op_code = 77,
	};

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 2, 0, parent_guid,
				bad_separator, strlen(bad_separator), &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	KUNIT_EXPECT_EQ(test, frame[0], 0xaaU);

	memset(too_long, 'A', sizeof(too_long));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 2, 0, parent_guid,
				too_long, sizeof(too_long), &built),
			(long)-ENAMETOOLONG);
}

static void pkm_lcs_kunit_rsi_lookup_request_frame_rejects_short_buffer(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x41 };
	static const char child_name[] = "Child";
	u8 frame[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
		 RSI_LENGTH_PREFIX_SIZE + 4];
	struct pkm_lcs_rsi_built_request built = {
		.len = 11,
		.request_id = 22,
		.op_code = 33,
	};
	size_t i;

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, sizeof(frame), 3, 0, parent_guid,
				child_name, strlen(child_name), &built),
			(long)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xaaU);
}

static void pkm_lcs_kunit_setup_registered_source(struct kunit *test,
						  struct file *file,
						  const void **token_out)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	const void *token;

	KUNIT_ASSERT_NOT_NULL(test, token_out);
	*token_out = NULL;
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	*token_out = token;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, file, &ops, (const void __user *)&args),
			0L);
}

static void pkm_lcs_kunit_build_lookup_frame(struct kunit *test, u8 *frame,
					     size_t frame_len, u64 request_id,
					     const char *child_name,
					     size_t *built_len)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x51 };
	struct pkm_lcs_rsi_built_request built = { };

	KUNIT_ASSERT_NOT_NULL(test, built_len);
	*built_len = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, frame_len, request_id, 0, parent_guid,
				child_name, strlen(child_name), &built),
			0L);
	*built_len = built.len;
}

static void pkm_lcs_kunit_build_status_response(struct kunit *test, u8 *frame,
						size_t frame_len,
						u64 request_id, u16 request_op,
						u32 status, size_t *built_len)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, built_len);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)RSI_MIN_RESPONSE_SIZE);

	memset(frame, 0, frame_len);
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, frame + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   frame + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, frame + RSI_RESPONSE_STATUS_OFFSET);
	*built_len = RSI_MIN_RESPONSE_SIZE;
}

static const u8 pkm_lcs_kunit_owner_only_sd[] = {
	0x01, 0x00, 0x00, 0x80,
	0x14, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05,
	0x12, 0x00, 0x00, 0x00,
};

static void pkm_lcs_kunit_rsi_append_bytes(struct kunit *test, u8 *frame,
					   size_t frame_len, size_t *offset,
					   const void *bytes, size_t len)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_TRUE(test, len == 0 || bytes);
	KUNIT_ASSERT_LE(test, len, frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - len);

	memcpy(frame + *offset, bytes, len);
	*offset += len;
}

static void pkm_lcs_kunit_rsi_append_u8(struct kunit *test, u8 *frame,
					size_t frame_len, size_t *offset,
					u8 value)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_LE(test, (size_t)1, frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - 1U);

	frame[*offset] = value;
	*offset += 1U;
}

static void pkm_lcs_kunit_rsi_append_u32(struct kunit *test, u8 *frame,
					 size_t frame_len, size_t *offset,
					 u32 value)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_LE(test, (size_t)sizeof(value), frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - sizeof(value));

	put_unaligned_le32(value, frame + *offset);
	*offset += sizeof(value);
}

static void pkm_lcs_kunit_rsi_append_u64(struct kunit *test, u8 *frame,
					 size_t frame_len, size_t *offset,
					 u64 value)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_LE(test, (size_t)sizeof(value), frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - sizeof(value));

	put_unaligned_le64(value, frame + *offset);
	*offset += sizeof(value);
}

static void pkm_lcs_kunit_rsi_append_len_prefixed(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const void *bytes, size_t len)
{
	KUNIT_ASSERT_LE(test, len, (size_t)U32_MAX);

	pkm_lcs_kunit_rsi_append_u32(test, frame, frame_len, offset,
				     (u32)len);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset,
				       bytes, len);
}

static void pkm_lcs_kunit_rsi_response_begin(struct kunit *test, u8 *frame,
					     size_t frame_len, u64 request_id,
					     u16 response_op, u32 status,
					     size_t *offset)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)RSI_MIN_RESPONSE_SIZE);

	memset(frame, 0, frame_len);
	put_unaligned_le64(request_id, frame + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, frame + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, frame + RSI_RESPONSE_STATUS_OFFSET);
	*offset = RSI_MIN_RESPONSE_SIZE;
}

static void pkm_lcs_kunit_rsi_finish_response(struct kunit *test, u8 *frame,
					      size_t offset,
					      size_t *built_len)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, built_len);
	KUNIT_ASSERT_LE(test, offset, (size_t)U32_MAX);

	put_unaligned_le32((u32)offset, frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
}

static void pkm_lcs_kunit_rsi_append_lookup_path_entry(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const char *layer_name, u8 target_type, const u8 guid[RSI_GUID_SIZE],
	u64 sequence)
{
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, layer_name,
		strlen(layer_name));
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset,
				    target_type);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset, guid,
				       RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     sequence);
}

static void pkm_lcs_kunit_rsi_append_lookup_metadata(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const u8 guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len)
{
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset, guid,
				       RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, frame, frame_len,
					      offset, sd, sd_len);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset, 0);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset, 0);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset, 1000);
}

static void pkm_lcs_kunit_rsi_append_lookup_metadata_ex(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const u8 guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	u8 volatile_key, u8 symlink, u64 last_write_time)
{
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset, guid,
				       RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, frame, frame_len,
					      offset, sd, sd_len);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset,
				    volatile_key);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset, symlink);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     last_write_time);
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

static void pkm_lcs_kunit_source_write_rejects_bad_framing_without_release(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x78 };
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

	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE + 1U,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false, NULL),
			(ssize_t)-EINVAL);
	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);

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

static void pkm_lcs_kunit_lookup_response_bridge_accepts_valid_and_empty(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 801,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 801, 21, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.path_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.metadata_count, 1U);
	KUNIT_EXPECT_FALSE(test, summary.child_absent);

	memset(&summary, 0xaa, sizeof(summary));
	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 802,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     0);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     0);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 802, 21, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.path_entry_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.metadata_count, 0U);
	KUNIT_EXPECT_TRUE(test, summary.child_absent);
}

static void pkm_lcs_kunit_lookup_response_bridge_maps_source_errors(
	struct kunit *test)
{
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[RSI_MIN_RESPONSE_SIZE];
	size_t frame_len;

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 811,
					    RSI_LOOKUP, RSI_NOT_FOUND,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 811, 1, &summary),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, summary.path_entry_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.metadata_count, 0U);

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 812,
					    RSI_LOOKUP, RSI_STORAGE_ERROR,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 812, 1, &summary),
			(long)-EIO);
}

static void pkm_lcs_kunit_lookup_response_bridge_rejects_common_mismatches(
	struct kunit *test)
{
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[RSI_MIN_RESPONSE_SIZE];
	size_t frame_len;

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 821,
					    RSI_LOOKUP, RSI_NOT_FOUND,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 822, 1, &summary),
			(long)-EINVAL);

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 823,
					    RSI_QUERY_VALUES, RSI_NOT_FOUND,
					    &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 823, 1, &summary),
			(long)-EINVAL);

	pkm_lcs_kunit_build_status_response(test, frame, sizeof(frame), 824,
					    RSI_LOOKUP, RSI_NOT_FOUND,
					    &frame_len);
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE + 1U,
			   frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 824, 1, &summary),
			(long)-EINVAL);
}

static void pkm_lcs_kunit_lookup_response_bridge_rejects_malformed_data(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	struct pkm_lcs_rsi_lookup_response_summary summary = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 831,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     0);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 831, 21, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 832,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 21);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 832, 21, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 833,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "bad/layer",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 833, 21, &summary),
			(long)-EIO);

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 834,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 20);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid, bad_sd,
		sizeof(bad_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_validate_lookup_response(
				frame, frame_len, 834, 21, &summary),
			(long)-EIO);
}

static void pkm_lcs_kunit_lookup_materializes_visible_child(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	struct pkm_lcs_rsi_lookup_child_result result = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 901,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 0);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata_ex(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd), 1, 1, 4242);
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_lookup_child(
				frame, frame_len, 901, 1, "Child",
				strlen("Child"), layers, ARRAY_SIZE(layers),
				NULL, 0, &result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_path_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(result.key_guid, guid, RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, result.selected_precedence, 0U);
	KUNIT_EXPECT_EQ(test, result.selected_sequence, 0ULL);
	KUNIT_EXPECT_TRUE(test, result.volatile_key);
	KUNIT_EXPECT_TRUE(test, result.symlink);
	KUNIT_EXPECT_EQ(test, result.last_write_time, 4242ULL);
	KUNIT_EXPECT_EQ(test, result.sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_ASSERT_LE(test,
			(size_t)result.sd_offset +
				(size_t)result.sd_len,
			frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + result.sd_offset,
			       pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);
}

static void pkm_lcs_kunit_lookup_materializes_hidden_as_not_found(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	struct pkm_lcs_rsi_lookup_child_result result = { };
	u8 frame[256];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 902,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "base",
		RSI_PATH_TARGET_GUID, guid, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "overlay",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     1);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_lookup_child(
				frame, frame_len, 902, 3, "Child",
				strlen("Child"), layers, ARRAY_SIZE(layers),
				NULL, 0, &result),
			0L);
	KUNIT_EXPECT_FALSE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_path_entry_count, 2U);
	KUNIT_EXPECT_EQ(test, result.sd_len, 0U);
}

static void pkm_lcs_kunit_lookup_materialize_rejects_duplicate_tie(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "layerA", .name_len = 6, .precedence = 10,
		  .enabled = 1 },
		{ .name = "layerB", .name_len = 6, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 guid_a[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	static const u8 guid_b[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	struct pkm_lcs_rsi_lookup_child_result result = { };
	u8 frame[384];
	size_t offset;
	size_t frame_len;

	pkm_lcs_kunit_rsi_response_begin(test, frame, sizeof(frame), 903,
					 RSI_LOOKUP_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "layerA",
		RSI_PATH_TARGET_GUID, guid_a, 5);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, frame, sizeof(frame), &offset, "layerB",
		RSI_PATH_TARGET_GUID, guid_b, 5);
	pkm_lcs_kunit_rsi_append_u32(test, frame, sizeof(frame), &offset,
				     2);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid_a,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, frame, sizeof(frame), &offset, guid_b,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, frame, offset, &frame_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_lookup_child(
				frame, frame_len, 903, 6, "Child",
				strlen("Child"), layers, ARRAY_SIZE(layers),
				NULL, 0, &result),
			(long)-EIO);
	KUNIT_EXPECT_FALSE(test, result.found);
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
	KUNIT_CASE(pkm_lcs_kunit_key_fd_publish_snapshot_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_publish_deep_copies_input),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_publish_rejects_malformed_state),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_snapshot_rejects_non_key_fd),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_fixed_ioctl_access_gates),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_security_ioctl_access_gates),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_ioctl_access_rejects_bad_fds),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_success),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_stops_bad_scalars),
	KUNIT_CASE(
		pkm_lcs_kunit_relative_open_preflight_validates_path_before_parent),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_rejects_bad_parent_fd),
	KUNIT_CASE(pkm_lcs_kunit_relative_open_preflight_rejects_orphan_parent),
	KUNIT_CASE(
		pkm_lcs_kunit_relative_open_preflight_checks_combined_depth),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_success),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_validates_child),
	KUNIT_CASE(pkm_lcs_kunit_rsi_lookup_request_frame_rejects_short_buffer),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_returns_complete_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_preserves_fifo_order),
	KUNIT_CASE(
		pkm_lcs_kunit_source_request_read_short_buffer_preserves_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_fault_preserves_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_enqueue_rejects_bad_state),
	KUNIT_CASE(
		pkm_lcs_kunit_source_dispatch_lookup_allocates_monotonic_ids),
	KUNIT_CASE(
		pkm_lcs_kunit_source_read_retains_in_flight_until_release),
	KUNIT_CASE(pkm_lcs_kunit_source_enqueue_rejects_reused_request_id),
	KUNIT_CASE(pkm_lcs_kunit_source_in_flight_full_blocks_after_read),
	KUNIT_CASE(pkm_lcs_kunit_source_response_rejects_before_read),
	KUNIT_CASE(pkm_lcs_kunit_source_response_releases_after_read),
	KUNIT_CASE(
		pkm_lcs_kunit_source_response_rejects_common_mismatches),
	KUNIT_CASE(pkm_lcs_kunit_source_response_unknown_status_releases),
	KUNIT_CASE(
		pkm_lcs_kunit_source_response_duplicate_after_release_rejected),
	KUNIT_CASE(
		pkm_lcs_kunit_source_write_accepts_complete_lookup_response),
	KUNIT_CASE(
		pkm_lcs_kunit_source_write_rejects_bad_framing_without_release),
	KUNIT_CASE(pkm_lcs_kunit_source_write_fault_preserves_record),
	KUNIT_CASE(
		pkm_lcs_kunit_source_write_malformed_lookup_data_succeeds),
	KUNIT_CASE(pkm_lcs_kunit_source_poll_reports_active_readiness),
	KUNIT_CASE(
		pkm_lcs_kunit_source_poll_reports_unregistered_and_closing),
	KUNIT_CASE(pkm_lcs_kunit_source_write_completes_waiting_lookup),
	KUNIT_CASE(
		pkm_lcs_kunit_source_write_maps_status_to_waiter_errno),
	KUNIT_CASE(
		pkm_lcs_kunit_source_waiter_retains_lookup_response_frame),
	KUNIT_CASE(
		pkm_lcs_kunit_source_waiter_does_not_retain_error_frame),
	KUNIT_CASE(
		pkm_lcs_kunit_source_release_completes_waiter_with_eio),
	KUNIT_CASE(
		pkm_lcs_kunit_source_slot_timeout_sends_no_request),
	KUNIT_CASE(
		pkm_lcs_kunit_source_response_timeout_retains_late_record),
	KUNIT_CASE(
		pkm_lcs_kunit_lookup_response_bridge_accepts_valid_and_empty),
	KUNIT_CASE(
		pkm_lcs_kunit_lookup_response_bridge_maps_source_errors),
	KUNIT_CASE(
		pkm_lcs_kunit_lookup_response_bridge_rejects_common_mismatches),
	KUNIT_CASE(
		pkm_lcs_kunit_lookup_response_bridge_rejects_malformed_data),
	KUNIT_CASE(pkm_lcs_kunit_lookup_materializes_visible_child),
	KUNIT_CASE(pkm_lcs_kunit_lookup_materializes_hidden_as_not_found),
	KUNIT_CASE(pkm_lcs_kunit_lookup_materialize_rejects_duplicate_tie),
	{ }
};

static struct kunit_suite pkm_lcs_kunit_suite = {
	.name = "pkm_lcs_kunit_scaffold",
	.test_cases = pkm_lcs_kunit_cases,
};

kunit_test_suite(pkm_lcs_kunit_suite);
