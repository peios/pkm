// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/anon_inodes.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "../kmes/kmes.h"
#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"

extern size_t lcs_rust_kunit_probe(void);

struct pkm_lcs_kunit_audit_caller_summary {
	u8 effective_token_guid[16];
	u8 true_token_guid[16];
	u8 process_guid[16];
	const u8 *user_sid;
	size_t user_sid_len;
	u64 authentication_id;
	u64 token_id;
	u32 token_type;
	u32 impersonation_level;
	u32 integrity_level;
};

extern int lcs_rust_key_open_audit_payload(
	const struct pkm_lcs_kunit_audit_caller_summary *caller,
	const u8 key_guid[16], u32 requested_access, u32 granted_access,
	u8 allowed, u32 sacl_match_flags, u8 *output, size_t output_len,
	size_t *written_out);

struct pkm_lcs_kunit_usercopy_ctx {
	const void *fault_src;
	const void *fault_dst;
	const void *fault_strlen_src;
	const void *unterminated_src;
	unsigned int reads;
	unsigned int writes;
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

static bool pkm_lcs_kunit_usercopy_write(void *raw_ctx, void __user *dst,
					 const void *src, size_t len)
{
	struct pkm_lcs_kunit_usercopy_ctx *ctx = raw_ctx;
	void *kdst = (void *)(unsigned long)dst;

	ctx->writes++;
	if (!kdst || kdst == ctx->fault_dst)
		return false;

	memcpy(kdst, src, len);
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
		.write = pkm_lcs_kunit_usercopy_write,
		.strnlen = pkm_lcs_kunit_usercopy_strnlen,
		.ctx = ctx,
	};
}

struct pkm_lcs_kunit_walk_source_step {
	const char *expected_child;
	const u8 *guid;
	const u8 *sd;
	size_t sd_len;
	bool empty;
	bool symlink;
};

struct pkm_lcs_kunit_walk_source_script {
	struct file *file;
	const struct pkm_lcs_kunit_walk_source_step *steps;
	u32 step_count;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_read_key_source_script {
	struct file *file;
	const u8 *expected_guid;
	const char *name;
	const u8 *parent_guid;
	const u8 *sd;
	size_t sd_len;
	bool volatile_key;
	bool symlink;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_query_values_source_script {
	struct file *file;
	const u8 *expected_guid;
	const char *expected_value_name;
	const char *response_value_name;
	const char *layer_name;
	const u8 *data;
	size_t data_len;
	u32 value_type;
	u64 sequence;
	bool query_all;
	bool include_blanket;
	const char *blanket_layer_name;
	u64 blanket_sequence;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_symlink_follow_source_script {
	struct file *file;
	struct pkm_lcs_kunit_walk_source_step link_step;
	struct pkm_lcs_kunit_walk_source_step target_step;
	const u8 *target_data;
	size_t target_data_len;
	u32 target_value_type;
	bool expect_target_lookup;
	u32 reads;
	u32 writes;
	int result;
};

enum pkm_lcs_kunit_symlink_sequence_op_code {
	PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP = 1,
	PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT = 2,
	PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY = 3,
};

struct pkm_lcs_kunit_symlink_sequence_op {
	enum pkm_lcs_kunit_symlink_sequence_op_code op;
	const struct pkm_lcs_kunit_walk_source_step *lookup_step;
	const struct pkm_lcs_kunit_read_key_source_script *read_key;
	const u8 *query_guid;
	const u8 *query_data;
	size_t query_data_len;
	u32 query_value_type;
};

struct pkm_lcs_kunit_symlink_sequence_source_script {
	struct file *file;
	const struct pkm_lcs_kunit_symlink_sequence_op *ops;
	u32 op_count;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_create_source_script {
	struct file *file;
	const u8 *parent_guid;
	const u8 *child_guid;
	const char *child_name;
	const char *layer_name;
	const u8 *sd;
	size_t sd_len;
	u64 expected_sequence;
	u32 entry_status;
	u32 key_status;
	bool expect_key_request;
	bool volatile_key;
	bool symlink;
	bool allow_any_sd;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_read_then_create_source_script {
	struct file *file;
	struct pkm_lcs_kunit_read_key_source_script read_key;
	struct pkm_lcs_kunit_create_source_script create;
	u32 reads;
	u32 writes;
	int result;
};

static void pkm_lcs_kunit_setup_registered_source(struct kunit *test,
						  struct file *file,
						  const void **token_out);
static int pkm_lcs_kunit_walk_source_thread(void *raw_script);
static int pkm_lcs_kunit_read_key_source_thread(void *raw_script);
static int pkm_lcs_kunit_query_values_source_thread(void *raw_script);
static int pkm_lcs_kunit_symlink_follow_source_thread(void *raw_script);
static int pkm_lcs_kunit_symlink_sequence_source_thread(void *raw_script);
static int pkm_lcs_kunit_create_source_thread(void *raw_script);

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

static void pkm_lcs_kunit_create_preflight_accepts_valid_flags(
	struct kunit *test)
{
	struct pkm_lcs_create_preflight_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(KEY_CREATE_SUB_KEY, 0,
						 &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.access.requested_access,
			KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.access.mapped_desired_access,
			KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.access.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 0U);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(
				MAXIMUM_ALLOWED | KEY_READ,
				REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.access.requested_access,
			MAXIMUM_ALLOWED | KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.access.mapped_desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, plan.access.maximum_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 1U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 1U);
}

static void pkm_lcs_kunit_create_preflight_rejects_fail_closed(
	struct kunit *test)
{
	struct pkm_lcs_create_preflight_plan plan = {
		.access = {
			.requested_access = 0xffffffffU,
			.mapped_desired_access = 0xffffffffU,
			.maximum_allowed = 1,
			.path_resolution_allowed = 1,
		},
		.options = {
			.volatile_key = 1,
			.symlink = 1,
		},
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(KEY_CREATE_SUB_KEY, 0,
						 NULL),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(0, REG_OPTION_VOLATILE,
						 &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.access.requested_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.mapped_desired_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.maximum_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 0U);

	plan.access.path_resolution_allowed = 1;
	plan.options.volatile_key = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_preflight(KEY_CREATE_SUB_KEY,
						 REG_OPTION_VOLATILE | 0x04U,
						 &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.access.path_resolution_allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, plan.options.symlink, 0U);
}

static void pkm_lcs_kunit_create_layer_target_null_uses_base(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, NULL, NULL, 0, &target, &plan),
			0L);
	KUNIT_EXPECT_STREQ(test, target.name, "base");
	KUNIT_EXPECT_EQ(test, target.name_len, 4U);
	KUNIT_EXPECT_EQ(test, target.implicit_base, 1U);
	KUNIT_EXPECT_PTR_EQ(test, target.owned_name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	pkm_lcs_create_layer_target_destroy(&target);
}

static void pkm_lcs_kunit_create_layer_target_explicit_layer_admitted(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "Policy", .name_len = 6, .precedence = 25,
		  .enabled = 1 },
	};
	const char layer_src[] = "Policy";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, layers,
				ARRAY_SIZE(layers), &target, &plan),
			0L);
	KUNIT_EXPECT_STREQ(test, target.name, "Policy");
	KUNIT_EXPECT_EQ(test, target.name_len, 6U);
	KUNIT_EXPECT_EQ(test, target.implicit_base, 0U);
	KUNIT_EXPECT_NOT_NULL(test, target.owned_name);
	KUNIT_EXPECT_EQ(test, plan.precedence, 25U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	pkm_lcs_create_layer_target_destroy(&target);
}

static void pkm_lcs_kunit_create_layer_target_absent_returns_enoent(
	struct kunit *test)
{
	const char layer_src[] = "Policy";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = {
		.precedence = 99,
		.enabled = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-ENOENT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, target.owned_name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}

static void pkm_lcs_kunit_create_layer_target_bad_name_fails_closed(
	struct kunit *test)
{
	const char layer_src[] = "bad/layer";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = {
		.precedence = 99,
		.enabled = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, plan.precedence, 0U);
	KUNIT_EXPECT_EQ(test, plan.enabled, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
}

static void pkm_lcs_kunit_create_layer_target_copy_faults_fail_closed(
	struct kunit *test)
{
	const char layer_src[] = "base";
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan plan = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = layer_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	ctx.fault_strlen_src = NULL;
	ctx.fault_src = layer_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-EFAULT);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 2U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	ctx.fault_src = NULL;
	ctx.unterminated_src = layer_src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_target_prepare(
				&ops, (const char __user *)layer_src, NULL, 0,
				&target, &plan),
			(long)-ENAMETOOLONG);
	KUNIT_EXPECT_PTR_EQ(test, target.name, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 3U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
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

static void pkm_lcs_kunit_expect_materialized_component(
	struct kunit *test, const struct pkm_lcs_materialized_path *path,
	u32 index, const char *expected)
{
	size_t expected_len = strlen(expected);

	KUNIT_ASSERT_NOT_NULL(test, path);
	KUNIT_ASSERT_TRUE(test, index < path->component_count);
	KUNIT_ASSERT_NOT_NULL(test, path->components[index].name);
	KUNIT_ASSERT_EQ(test, path->components[index].name_len,
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(path->components[index].name, expected,
			       expected_len),
			0);
}

static void pkm_lcs_kunit_open_path_components_absolute_success(
	struct kunit *test)
{
	const char path_src[] = "Machine\\Software\\App";
	struct pkm_lcs_materialized_path path = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, path_src, sizeof(path_src), false, &path),
			0L);
	KUNIT_EXPECT_EQ(test, path.component_count, 3U);
	KUNIT_ASSERT_NOT_NULL(test, path.components);
	KUNIT_ASSERT_NOT_NULL(test, path.strings);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 0,
						    "Machine");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 1,
						    "Software");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 2, "App");
	KUNIT_EXPECT_EQ(test, path.string_bytes,
			(u32)(strlen("Machine") + strlen("Software") +
			      strlen("App")));

	pkm_lcs_materialized_path_destroy(&path);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
}

static void pkm_lcs_kunit_open_path_components_normalizes_forward_slashes(
	struct kunit *test)
{
	const char path_src[] = "Machine/Software/App";
	struct pkm_lcs_materialized_path path = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, path_src, sizeof(path_src), false, &path),
			0L);
	KUNIT_EXPECT_EQ(test, path.component_count, 3U);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 0,
						    "Machine");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 1,
						    "Software");
	pkm_lcs_kunit_expect_materialized_component(test, &path, 2, "App");

	pkm_lcs_materialized_path_destroy(&path);
}

static void pkm_lcs_kunit_open_path_components_rewrites_current_user(
	struct kunit *test)
{
	const char path_src[] = "CurrentUser\\App";
	struct pkm_lcs_materialized_path path = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				token, path_src, sizeof(path_src), true, &path),
			0L);
	KUNIT_EXPECT_EQ(test, path.component_count, 3U);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 0, "Users");
	KUNIT_ASSERT_NOT_NULL(test, path.components[1].name);
	KUNIT_ASSERT_GT(test, path.components[1].name_len, 2U);
	KUNIT_EXPECT_EQ(test, memcmp(path.components[1].name, "S-", 2), 0);
	pkm_lcs_kunit_expect_materialized_component(test, &path, 2, "App");

	pkm_lcs_materialized_path_destroy(&path);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_path_components_rejects_fail_closed(
	struct kunit *test)
{
	const char malformed_path[] = "Machine\\";
	const char current_user_path[] = "CurrentUser\\App";
	struct pkm_lcs_materialized_path path = {
		.component_count = 99,
		.string_bytes = 99,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, malformed_path, sizeof(malformed_path),
				false, &path),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
	KUNIT_EXPECT_EQ(test, path.component_count, 0U);
	KUNIT_EXPECT_EQ(test, path.string_bytes, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_materialize_absolute_path_components_for_token(
				NULL, current_user_path,
				sizeof(current_user_path), true, &path),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, path.components, NULL);
	KUNIT_EXPECT_PTR_EQ(test, path.strings, NULL);
}

static void pkm_lcs_kunit_open_absolute_composes_success(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
	};
	const char path_src[] = "Machine\\Software\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[2] = {
		{ .expected_child = "Software", .guid = software_guid },
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[1].sd = sd;
	steps[1].sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-abs");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, layers, ARRAY_SIZE(layers), NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, snapshot.first_ancestor_guid[0], 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, app_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_uses_implicit_base_layer(
	struct kunit *test)
{
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44,
	};
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-base");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_final_symlink_open_link(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
	};
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "Link", .guid = link_guid,
		  .symlink = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ,
		REG_OPEN_LINK, NULL, 0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Link");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, link_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, link_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_final_symlink_follows_target(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
		0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
		0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_symlink_follow_source_script script = {
		.link_step = {
			.expected_child = "Link",
			.guid = link_guid,
			.symlink = true,
		},
		.target_step = {
			.expected_child = "Target",
			.guid = target_guid,
		},
		.target_data = target_path,
		.target_data_len = sizeof(target_path) - 1,
		.target_value_type = REG_LINK,
		.expect_target_lookup = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.target_step.sd = sd;
	script.target_step.sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_symlink_follow_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-link-follow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_final_symlink_bad_target_einval(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
		0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
	};
	static const u8 bad_target_path[] = "Machine\\\\Target";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_symlink_follow_source_script script = {
		.link_step = {
			.expected_child = "Link",
			.guid = link_guid,
			.symlink = true,
		},
		.target_data = bad_target_path,
		.target_data_len = sizeof(bad_target_path) - 1,
		.target_value_type = REG_LINK,
		.expect_target_lookup = false,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_symlink_follow_source_thread, &script,
			   "pkm-lcs-kunit-open-abs-link-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_intermediate_symlink_follows_suffix(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
		0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
		0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
	};
	static const u8 leaf_guid[RSI_GUID_SIZE] = {
		0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine\\Link\\Leaf";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_walk_source_step leaf_step = {
		.expected_child = "Leaf",
		.guid = leaf_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &leaf_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	leaf_step.sd = sd;
	leaf_step.sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-abs-link-mid");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Leaf");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, leaf_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, leaf_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_recursive_symlink_follows_target(
	struct kunit *test)
{
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
		0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
	};
	static const u8 mid_guid[RSI_GUID_SIZE] = {
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
		0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
		0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
	};
	static const u8 mid_path[] = "Machine\\Mid";
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step mid_step = {
		.expected_child = "Mid",
		.guid = mid_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = mid_path,
		  .query_data_len = sizeof(mid_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &mid_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = mid_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	target_step.sd = sd;
	target_step.sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-abs-link-rec");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_symlink_depth_limit_eloop(
	struct kunit *test)
{
	static const u8 loop_guid[RSI_GUID_SIZE] = {
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
		0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
	};
	static const u8 loop_path[] = "Machine\\Loop";
	const char path_src[] = "Machine\\Loop";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step loop_step = {
		.expected_child = "Loop",
		.guid = loop_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_symlink_sequence_op
		sequence[PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT * 2U + 1U];
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 i;
	long ret;
	int thread_ret;

	for (i = 0; i < PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT; i++) {
		sequence[i * 2U] =
			(struct pkm_lcs_kunit_symlink_sequence_op) {
				.op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
				.lookup_step = &loop_step,
			};
		sequence[i * 2U + 1U] =
			(struct pkm_lcs_kunit_symlink_sequence_op) {
				.op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
				.query_guid = loop_guid,
				.query_data = loop_path,
				.query_data_len = sizeof(loop_path) - 1,
				.query_value_type = REG_LINK,
			};
	}
	sequence[ARRAY_SIZE(sequence) - 1U] =
		(struct pkm_lcs_kunit_symlink_sequence_op) {
			.op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
			.lookup_step = &loop_step,
		};

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-abs-link-eloop");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ELOOP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads,
			PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT * 2U + 1U);
	KUNIT_EXPECT_EQ(test, script.writes,
			PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT * 2U + 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_root_uses_read_key(struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Machine");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_open_key_syscall_dispatches_absolute(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-reg-open-abs");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_open_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Machine");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_open_key_syscall_dispatches_relative(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_open_key_for_token(
				token, &ops, -2, (const char __user *)path_src,
				KEY_READ, 0),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_open_key_syscall_rejects_null_token(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_open_key_for_token(
				NULL, &ops, -1, (const char __user *)path_src,
				KEY_READ, 0),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
}

static void pkm_lcs_kunit_create_existing_absolute_sets_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, root_guid,
				    RSI_GUID_SIZE), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_accepts_null_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-null-disp");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0,
		NULL);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_finish_copies_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-finish");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_finish_null_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-finish-null");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0,
		NULL);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_finish_faults_disposition(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;
	ctx.fault_dst = &disposition;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-existing-finish-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_existing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ, 0,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_copied_finish_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)path_src,
		.path_len = sizeof(path_src),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-copied");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_existing_copied_path_finish_for_token(
		token, &ops, -1, &copy, KEY_READ,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_copied_finish_fault_closes_fd(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)path_src,
		.path_len = sizeof(path_src),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;
	ctx.fault_dst = &disposition;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-copied-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_existing_copied_path_finish_for_token(
		token, &ops, -1, &copy, KEY_READ, 0,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, 0U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_copied_rejects_bad_copy(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_syscall_path_copy bad_copy = {
		.path = (char *)path_src,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = 0xaaaaaaaaU;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_existing_copied_path_finish_for_token(
				token, &ops, -1, &bad_copy, KEY_READ, 0,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_disposition_copyout_success(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, (u32 __user *)&disposition,
				REG_CREATED_NEW),
			0L);
	KUNIT_EXPECT_EQ(test, disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
}

static void pkm_lcs_kunit_create_disposition_copyout_null_is_noop(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, NULL, REG_OPENED_EXISTING),
			0L);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}

static void pkm_lcs_kunit_create_disposition_copyout_faults(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaa55aa55U;

	ctx.fault_dst = &disposition;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, (u32 __user *)&disposition,
				REG_CREATED_NEW),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
}

static void pkm_lcs_kunit_create_disposition_copyout_bad_ops(
	struct kunit *test)
{
	struct pkm_lcs_usercopy_ops ops = { };
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_copy_disposition_to_user(
				&ops, (u32 __user *)&disposition,
				REG_CREATED_NEW),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
}

static long pkm_lcs_kunit_publish_create_finish_fd(void)
{
	static const char * const path[] = { "Machine" };
	static const u8 ancestors[1][PKM_LCS_GUID_BYTES] = {
		{ 0x8a },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 1,
		.granted_access = KEY_READ,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 1,
	};

	memcpy(input.key_guid, ancestors[0], sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}

static void pkm_lcs_kunit_create_finish_success_returns_fd(struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long fd;
	long ret;

	fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		&ops, (u32 __user *)&disposition, fd, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, ret, fd);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_create_finish_success_null_disposition(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	long fd;
	long ret;

	fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		&ops, NULL, fd, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, ret, fd);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_create_finish_fault_closes_fd(struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long fd;

	fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	ctx.fault_dst = &disposition;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_finish_success_to_user(
				&ops, (u32 __user *)&disposition, fd,
				REG_CREATED_NEW),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			(long)-EBADF);
}

static void pkm_lcs_kunit_create_finish_rejects_invalid_fd(struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_finish_success_to_user(
				&ops, (u32 __user *)&disposition, -1,
				REG_CREATED_NEW),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}

static void pkm_lcs_kunit_create_missing_created_finish_success(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long ret;

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);

	ret = pkm_lcs_create_missing_created_result_finish_to_user(
		&ops, (u32 __user *)&disposition, &result);
	KUNIT_EXPECT_TRUE(test, ret >= 0);
	KUNIT_EXPECT_EQ(test, disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot((int)ret, &snapshot),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)ret), 0);
}

static void pkm_lcs_kunit_create_missing_created_finish_null_disposition(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	long ret;

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);

	ret = pkm_lcs_create_missing_created_result_finish_to_user(
		&ops, NULL, &result);
	KUNIT_EXPECT_TRUE(test, ret >= 0);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)ret), 0);
}

static void pkm_lcs_kunit_create_missing_created_finish_fault_closes_fd(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	u32 disposition = 0;
	long fd;

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	fd = result.fd;
	ctx.fault_dst = &disposition;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			(long)-EBADF);
}

static void pkm_lcs_kunit_create_missing_created_finish_rejects_retry(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.fd = -1,
		.disposition = REG_OPENED_EXISTING,
		.retry_open_existing = true,
	};
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}

static void pkm_lcs_kunit_create_missing_created_finish_rejects_malformed(
	struct kunit *test)
{
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_create_missing_prepared_result result = {
		.fd = -1,
		.disposition = REG_CREATED_NEW,
		.created_new = true,
	};
	u32 disposition = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	result.fd = pkm_lcs_kunit_publish_create_finish_fd();
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	result.disposition = REG_OPENED_EXISTING;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_created_result_finish_to_user(
				&ops, (u32 __user *)&disposition, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)result.fd), 0);
}

static long pkm_lcs_kunit_retry_open_resolution_prepare(
	struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 root_guid[RSI_GUID_SIZE], const char *child_name)
{
	if (!resolution || !root_guid || !child_name)
		return -EINVAL;

	memset(resolution, 0, sizeof(*resolution));
	resolution->parent.resolved_path =
		kcalloc(1, sizeof(*resolution->parent.resolved_path),
			GFP_KERNEL);
	if (!resolution->parent.resolved_path)
		return -ENOMEM;
	resolution->parent.ancestor_guids =
		kcalloc(1, sizeof(*resolution->parent.ancestor_guids),
			GFP_KERNEL);
	if (!resolution->parent.ancestor_guids)
		goto out_nomem;
	resolution->parent.resolved_path[0] = kstrdup("Machine", GFP_KERNEL);
	if (!resolution->parent.resolved_path[0])
		goto out_nomem;
	resolution->child_name = kstrdup(child_name, GFP_KERNEL);
	if (!resolution->child_name)
		goto out_nomem;

	resolution->parent.source_id = 1;
	resolution->parent.component_count = 1;
	memcpy(resolution->parent.key_guid, root_guid, RSI_GUID_SIZE);
	memcpy(resolution->parent.ancestor_guids[0], root_guid, RSI_GUID_SIZE);
	resolution->child_name_len = strlen(child_name);
	resolution->child_depth = 2;
	return 0;

out_nomem:
	pkm_lcs_create_missing_parent_resolution_destroy(resolution);
	return -ENOMEM;
}

static void pkm_lcs_kunit_create_missing_retry_open_success(struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, "App"),
			0L);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-retry-open");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_READ, NULL, 0, NULL, 0, NULL, 0,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, REG_OPENED_EXISTING);
	if (fd >= 0) {
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
				0L);
		KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
		KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
		KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
		KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
		KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
		KUNIT_EXPECT_EQ(test,
				memcmp(snapshot.key_guid, app_guid,
				       sizeof(snapshot.key_guid)),
				0);
		KUNIT_EXPECT_EQ(test,
				memcmp(snapshot.last_ancestor_guid, app_guid,
				       sizeof(snapshot.last_ancestor_guid)),
				0);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_retry_open_fault_closes(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = { 0xb1 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0xaa55aa55U;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, "App"),
			0L);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	ctx.fault_dst = &disposition;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-retry-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_READ, NULL, 0, NULL, 0, NULL, 0,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_retry_open_denied_no_copyout(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 app_guid[RSI_GUID_SIZE] = { 0xc1 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0xaa55aa55U;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_retry_open_resolution_prepare(
				&resolution, root_guid, "App"),
			0L);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-retry-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_retry_open_existing_for_token(
		token, &ops, &resolution, KEY_SET_VALUE, NULL, 0, NULL, 0,
		NULL, 0, (u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);

	pkm_kacs_free((void *)sd);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_retry_open_bad_resolution(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.parent.component_count = 1,
		.child_name = "App",
		.child_name_len = 3,
		.child_depth = 2,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaa55aa55U;

	memcpy(resolution.parent.key_guid, root_guid, RSI_GUID_SIZE);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_retry_open_existing_for_token(
				NULL, &ops, &resolution, KEY_READ, NULL, 0,
				NULL, 0, NULL, 0,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, disposition, 0xaa55aa55U);
}

static void pkm_lcs_kunit_create_existing_rejects_flags_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = REG_OPENED_EXISTING;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_existing_user_path_for_token(
				token, &ops, -1, (const char __user *)path_src,
				KEY_READ, 0x04U, &disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_existing_dispatches_relative_parent(
	struct kunit *test)
{
	const char path_src[] = "Child";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = REG_OPENED_EXISTING;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_existing_user_path_for_token(
				token, &ops, -2, (const char __user *)path_src,
				KEY_READ, 0, &disposition),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, disposition, 0U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_root_denied_publishes_no_fd(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src,
		KEY_QUERY_VALUE | KEY_SET_VALUE, 0, NULL, 0, NULL, 0, NULL,
		0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_root_malformed_sd_fails_closed(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
		.sd = bad_sd,
		.sd_len = sizeof(bad_sd),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-open-root-bad-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_root_symlink_follows_target(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
		0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script root_read = {
		.expected_guid = root_guid,
		.name = "Machine",
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
		  .read_key = &root_read },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = root_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	target_step.sd = sd;
	target_step.sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-root-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_symlink_target_hive_root(
	struct kunit *test)
{
	static const u8 machine_root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 users_root_guid[RSI_GUID_SIZE] = { 2 };
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
		0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
	};
	static const u8 target_path[] = "Users";
	const char machine_name[] = "Machine";
	const char users_name[] = "Users";
	const char path_src[] = "Machine\\Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hives[2] = { };
	struct reg_src_register_args args = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_read_key_source_script users_read = {
		.expected_guid = users_root_guid,
		.name = "Users",
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY,
		  .read_key = &users_read },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, &file),
			0L);

	hives[0].name_len = strlen(machine_name);
	hives[0].name_ptr = (u64)(unsigned long)machine_name;
	memcpy(hives[0].root_guid, machine_root_guid, RSI_GUID_SIZE);
	hives[1].name_len = strlen(users_name);
	hives[1].name_ptr = (u64)(unsigned long)users_name;
	memcpy(hives[1].root_guid, users_root_guid, RSI_GUID_SIZE);
	args.hive_count = ARRAY_SIZE(hives);
	args.hives_ptr = (u64)(unsigned long)hives;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, &file, &ops, (const void __user *)&args),
			0L);

	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	users_read.sd = sd;
	users_read.sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-link-root-target");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 1U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Users");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Users");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, users_root_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, users_root_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_denied_publishes_no_fd(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src,
		KEY_QUERY_VALUE | KEY_SET_VALUE, 0, NULL, 0, layers,
		ARRAY_SIZE(layers), NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_malformed_sd_fails_closed(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 bad_sd[] = { 0x01, 0x02, 0x03 };
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid,
		  .sd = bad_sd, .sd_len = sizeof(bad_sd) },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-bad-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_absolute_path_for_token(
		token, &ops, (const char __user *)path_src, KEY_READ, 0, NULL,
		0, layers, ARRAY_SIZE(layers), NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_absolute_preflight_stops_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_absolute_path_for_token(
				token, &ops, (const char __user *)path_src, 0,
				0, NULL, 0, NULL, 0, NULL, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_composes_success(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const u8 leaf_guid[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	const char * const parent_path[] = { "Machine", "Software" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App/Leaf";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[2] = {
		{ .expected_child = "App", .guid = app_guid },
		{ .expected_child = "Leaf", .guid = leaf_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[1].sd = sd;
	steps[1].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], software_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, software_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, layers, ARRAY_SIZE(layers), NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 4U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Leaf");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, leaf_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, snapshot.first_ancestor_guid[0], 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, leaf_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_uses_implicit_base_layer(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
		0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
		0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
	};
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-base");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_final_symlink_open_link(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
		0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
		0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
	};
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "Link", .guid = link_guid,
		  .symlink = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, REG_OPEN_LINK, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Link");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, link_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, link_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_final_symlink_follows_target(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
		0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
		0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec,
		0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_symlink_follow_source_script script = {
		.link_step = {
			.expected_child = "Link",
			.guid = link_guid,
			.symlink = true,
		},
		.target_step = {
			.expected_child = "Target",
			.guid = target_guid,
		},
		.target_data = target_path,
		.target_data_len = sizeof(target_path) - 1,
		.target_value_type = REG_LINK,
		.expect_target_lookup = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.target_step.sd = sd;
	script.target_step.sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = kthread_run(pkm_lcs_kunit_symlink_follow_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-link-follow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 2U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Target");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, target_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, target_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_intermediate_symlink_follows_suffix(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
		0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
		0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
	};
	static const u8 target_guid[RSI_GUID_SIZE] = {
		0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
	};
	static const u8 leaf_guid[RSI_GUID_SIZE] = {
		0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
		0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
	};
	static const u8 target_path[] = "Machine\\Target";
	const char * const parent_path[] = { "Machine", "Parent" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "Link\\Leaf";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_walk_source_step link_step = {
		.expected_child = "Link",
		.guid = link_guid,
		.symlink = true,
	};
	struct pkm_lcs_kunit_walk_source_step target_step = {
		.expected_child = "Target",
		.guid = target_guid,
	};
	struct pkm_lcs_kunit_walk_source_step leaf_step = {
		.expected_child = "Leaf",
		.guid = leaf_guid,
	};
	struct pkm_lcs_kunit_symlink_sequence_op sequence[] = {
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &link_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT,
		  .query_guid = link_guid, .query_data = target_path,
		  .query_data_len = sizeof(target_path) - 1,
		  .query_value_type = REG_LINK },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &target_step },
		{ .op = PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP,
		  .lookup_step = &leaf_step },
	};
	struct pkm_lcs_kunit_symlink_sequence_source_script script = {
		.ops = sequence,
		.op_count = ARRAY_SIZE(sequence),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	leaf_step.sd = sd;
	leaf_step.sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], parent_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, parent_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-open-rel-link-mid");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_READ, 0, NULL, 0, NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "Leaf");
	KUNIT_EXPECT_EQ(test, memcmp(snapshot.key_guid, leaf_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, leaf_guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_denied_publishes_no_fd(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
		0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
	};
	const char * const parent_path[] = { "Machine", "Software" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	struct pkm_lcs_kunit_walk_source_step steps[1] = {
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	long parent_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	steps[0].sd = sd;
	steps[0].sd_len = sd_len;
	script.file = &file;

	memcpy(parent_ancestors[1], software_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, software_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);

	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-open-rel-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_open_user_relative_path_for_token(
		token, &ops, (int)parent_fd, (const char __user *)path_src,
		KEY_QUERY_VALUE | KEY_SET_VALUE, 0, layers,
		ARRAY_SIZE(layers), NULL, 0);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_preflight_stops_before_usercopy(
	struct kunit *test)
{
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_for_token(
				token, &ops, -1, (const char __user *)path_src,
				0, 0, NULL, 0, NULL, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_relative_orphan_parent_fails_closed(
	struct kunit *test)
{
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
		0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x01,
	};
	const char * const parent_path[] = { "Machine", "Software" };
	u8 parent_ancestors[2][RSI_GUID_SIZE] = { { 1 } };
	const char path_src[] = "App";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_publish_input parent_publish = { };
	const void *token;
	long parent_fd;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	memcpy(parent_ancestors[1], software_guid, RSI_GUID_SIZE);
	parent_publish.source_id = 1;
	memcpy(parent_publish.key_guid, software_guid,
	       sizeof(parent_publish.key_guid));
	parent_publish.granted_access = KEY_READ;
	parent_publish.resolved_path = parent_path;
	parent_publish.ancestor_guids = parent_ancestors;
	parent_publish.path_component_count = ARRAY_SIZE(parent_path);
	parent_fd = pkm_lcs_key_fd_publish(&parent_publish);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_set_orphaned((int)parent_fd,
							  true),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_open_user_relative_path_for_token(
				token, &ops, (int)parent_fd,
				(const char __user *)path_src, KEY_READ, 0,
				NULL, 0, NULL, 0),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
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

static long pkm_lcs_kunit_publish_key_fd_for_source(
	u32 source_id, const u8 root_guid[PKM_LCS_GUID_BYTES],
	const u8 key_guid[PKM_LCS_GUID_BYTES])
{
	static const char * const path[] = { "Machine", "Software" };
	u8 ancestors[2][PKM_LCS_GUID_BYTES];
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = source_id,
		.granted_access = KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};

	memset(ancestors, 0, sizeof(ancestors));
	memcpy(ancestors[0], root_guid, sizeof(ancestors[0]));
	memcpy(ancestors[1], key_guid, sizeof(ancestors[1]));
	memcpy(input.key_guid, key_guid, sizeof(input.key_guid));
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

static void pkm_lcs_kunit_create_missing_absolute_resolves_parent_only(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Software", .guid = software_guid },
	};
	const char path_src[] = "Machine\\Software\\NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-parent");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_absolute_parent_for_token(
		token, &ops, (const char __user *)path_src, NULL, 0,
		layers, ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_STREQ(test, result.child_name, "NewKey");
	KUNIT_EXPECT_EQ(test, result.child_name_len, 6U);
	KUNIT_EXPECT_EQ(test, result.child_depth, 3U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 1U);
	KUNIT_EXPECT_EQ(test, result.parent.component_count, 2U);
	KUNIT_EXPECT_STREQ(test, result.parent.resolved_path[0], "Machine");
	KUNIT_EXPECT_STREQ(test, result.parent.resolved_path[1], "Software");
	KUNIT_EXPECT_EQ(test,
			memcmp(result.parent.ancestor_guids[0], root_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.parent.key_guid, software_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_GT(test, result.parent.final_sd_len, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_absolute_missing_parent_enoent(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Missing", .empty = true },
	};
	const char path_src[] = "Machine\\Missing\\NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-create-missing-parent");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_absolute_parent_for_token(
		token, &ops, (const char __user *)path_src, NULL, 0,
		layers, ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_PTR_EQ(test, result.child_name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.final_frame.data, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_absolute_root_path_rejected(
	struct kunit *test)
{
	const char path_src[] = "Machine";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct file file = { };
	const void *token;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_absolute_parent_for_token(
				token, &ops, (const char __user *)path_src,
				NULL, 0, NULL, 0, NULL, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.child_name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.resolved_path, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_relative_direct_parent_reads_sd(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x52 };
	const char path_src[] = "NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = parent_guid,
		.name = "Software",
		.parent_guid = root_guid,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	fd = pkm_lcs_kunit_publish_key_fd_for_source(1, root_guid,
						     parent_guid);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-parent-read");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_relative_parent(
		&ops, (int)fd, (const char __user *)path_src, NULL, 0,
		NULL, 0, NULL, 0, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_STREQ(test, result.child_name, "NewKey");
	KUNIT_EXPECT_EQ(test, result.child_depth, 3U);
	KUNIT_EXPECT_EQ(test, result.parent.source_id, 1U);
	KUNIT_EXPECT_EQ(test, result.parent.component_count, 2U);
	KUNIT_EXPECT_STREQ(test, result.parent.resolved_path[1], "Software");
	KUNIT_EXPECT_EQ(test,
			memcmp(result.parent.key_guid, parent_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_GT(test, result.parent.final_sd_len, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_relative_checks_child_depth(
	struct kunit *test)
{
	const char path_src[] = "NewKey";
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	long fd;

	fd = pkm_lcs_kunit_publish_key_fd_with_depth(512);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_relative_parent(
				&ops, (int)fd, (const char __user *)path_src,
				NULL, 0, NULL, 0, NULL, 0, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.child_name, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.parent.resolved_path, NULL);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
	struct kunit *test, struct pkm_lcs_create_missing_parent_resolution *result,
	const u8 *sd, size_t sd_len)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x61 };
	u8 *frame;

	KUNIT_ASSERT_NOT_NULL(test, result);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, sd_len, (size_t)0);

	frame = kmalloc(sd_len + 3U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, frame);
	memset(frame, 0xa5, 3U);
	memcpy(frame + 3U, sd, sd_len);

	memcpy(result->parent.key_guid, parent_guid,
	       sizeof(result->parent.key_guid));
	result->parent.source_id = 1;
	result->parent.component_count = 2;
	result->parent.final_frame.data = frame;
	result->parent.final_frame.len = sd_len + 3U;
	result->parent.final_sd_offset = 3U;
	result->parent.final_sd_len = sd_len;
}

static void pkm_lcs_kunit_create_missing_parent_access_allows_create_subkey(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_SUB_KEY, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_CREATE_SUB_KEY);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_parent_access_denies_without_right(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_CREATE_SUB_KEY);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_parent_access_malformed_sd_eio(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_CREATE_SUB_KEY,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	result.parent.final_frame.data = kmalloc(4U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, result.parent.final_frame.data);
	memset(result.parent.final_frame.data, 0, 4U);
	result.parent.final_frame.len = 4U;
	result.parent.final_sd_offset = 3U;
	result.parent.final_sd_len = 4U;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_parent_access_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_SUB_KEY, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				NULL, &result, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, NULL, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_parent_access_check_for_token(
				token, &result, NULL),
			(long)-EINVAL);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_volatile_parent_rejects_nonvolatile(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	result.parent.final_volatile = true;
	KUNIT_ASSERT_EQ(test, pkm_lcs_create_preflight(KEY_READ, 0, &plan),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			(long)-EINVAL);
}

static void pkm_lcs_kunit_create_missing_volatile_parent_allows_volatile(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	result.parent.final_volatile = true;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_create_preflight(KEY_READ, REG_OPTION_VOLATILE,
						 &plan),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			0L);
}

static void pkm_lcs_kunit_create_missing_volatile_parent_allows_nonvolatile_parent(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_create_preflight(KEY_READ, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			0L);

	memset(&plan, 0, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_create_preflight(KEY_READ, REG_OPTION_VOLATILE,
						 &plan),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     &plan),
			0L);
}

static void pkm_lcs_kunit_create_missing_volatile_parent_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_create_preflight_plan plan = { };

	KUNIT_ASSERT_EQ(test, pkm_lcs_create_preflight(KEY_READ, 0, &plan),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(NULL,
								     &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_volatile_parent_check(&result,
								     NULL),
			(long)-EINVAL);
}

static const u8 pkm_lcs_kunit_parent_sd_ci_generic_read[] = {
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
	/* DACL: one CONTAINER_INHERIT allow ACE for Everyone GENERIC_READ. */
	0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
};

static const u8 pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read[] = {
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
	/* DACL: explicit create-subkey plus inheritable generic-read. */
	0x02, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
};

static void pkm_lcs_kunit_create_initial_sd_inherits_registry_mapping(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
		test, &result, pkm_lcs_kunit_parent_sd_ci_generic_read,
		sizeof(pkm_lcs_kunit_parent_sd_ci_generic_read));

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, &result, &created),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	KUNIT_EXPECT_GT(test, created.sd_len, (size_t)0);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_sd_bytes(created.sd, created.sd_len),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, created.sd, created.sd_len, KEY_READ,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_READ);

	pkm_lcs_created_key_sd_destroy(&created);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);
	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_initial_sd_malformed_parent_eio(
	struct kunit *test)
{
	static const u8 bad_sd[] = { 0x00, 0x01, 0x02, 0x03 };
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_created_key_sd created = {
		.sd = (const u8 *)1UL,
		.sd_len = 7,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
		test, &result, bad_sd, sizeof(bad_sd));

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, &result, &created),
			(long)-EIO);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_initial_sd_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
		test, &result, pkm_lcs_kunit_parent_sd_ci_generic_read,
		sizeof(pkm_lcs_kunit_parent_sd_ci_generic_read));

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, &result, NULL),
			(long)-EINVAL);
	created.sd = (const u8 *)1UL;
	created.sd_len = 7;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				NULL, &result, &created),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);
	created.sd = (const u8 *)1UL;
	created.sd_len = 7;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_initial_sd_for_token(
				token, NULL, &created),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, created.sd, NULL);
	KUNIT_EXPECT_EQ(test, created.sd_len, (size_t)0);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_layer_write_access_allows_key_set_value(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_layer_write_access_denies_without_right(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.mapped_desired_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_layer_write_access_malformed_sd_eio(
	struct kunit *test)
{
	static const u8 malformed_sd[] = { 0x01, 0x00, 0x00, 0x00 };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, malformed_sd, sizeof(malformed_sd),
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);
	KUNIT_EXPECT_EQ(test, plan.access_check_granted, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_layer_write_access_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				NULL, sd, sd_len, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, NULL, sd_len, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, 0, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_base_layer_default_sd_allows_system_and_admin(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan system_plan = { };
	struct pkm_lcs_key_open_access_plan admin_plan = { };
	const void *system_token = pkm_kacs_boot_system_token_ptr();
	const void *admin_token;
	const u8 *sd;
	size_t sd_len = 0;

	KUNIT_ASSERT_NOT_NULL(test, system_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	sd = kacs_rust_create_lcs_base_layer_default_sd(&sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, sd_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				system_token, sd, sd_len, &system_plan),
			0L);
	KUNIT_EXPECT_EQ(test, system_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, system_plan.fd_granted_access, KEY_SET_VALUE);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				admin_token, sd, sd_len, &admin_plan),
			0L);
	KUNIT_EXPECT_EQ(test, admin_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, admin_plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(admin_token);
}

static void pkm_lcs_kunit_base_layer_default_sd_denies_service(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_create_lcs_base_layer_default_sd(&sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, sd_len, (size_t)0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_layer_write_access_check_for_token(
				token, sd, sd_len, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_base_layer_write_present_sd_overrides_default(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, sd, sd_len, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_base_layer_write_absent_uses_default(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, false, NULL, 0, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_base_layer_write_absent_denies_service(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, false, NULL, 0, &plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_base_layer_write_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, NULL, sd_len, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, sd, 0, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_base_layer_write_access_check_for_token(
				token, true, sd, sd_len, NULL),
			(long)-EINVAL);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_layer_write_explicit_folded_match(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "Policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_layer_metadata_sd_view metadata[2] = {
		{ .name = "other", .name_len = 5 },
		{ .name = "policy", .name_len = 6 },
	};
	const void *token;
	const u8 *other_sd;
	const u8 *policy_sd;
	size_t other_sd_len = 0;
	size_t policy_sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	other_sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE,
						  0, 0, 0, &other_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, other_sd);
	policy_sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE,
						   0, 0, 0, &policy_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, policy_sd);
	metadata[0].sd = other_sd;
	metadata[0].sd_len = other_sd_len;
	metadata[1].sd = policy_sd;
	metadata[1].sd_len = policy_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, metadata,
				ARRAY_SIZE(metadata), &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	pkm_kacs_free((void *)policy_sd);
	pkm_kacs_free((void *)other_sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_layer_write_explicit_denied(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_layer_metadata_sd_view metadata = {
		.name = "policy",
		.name_len = 6,
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_QUERY_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	metadata.sd = sd;
	metadata.sd_len = sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, &metadata, 1,
				&plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_layer_write_missing_metadata_eio(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	struct pkm_lcs_layer_metadata_sd_view metadata = {
		.name = "other",
		.name_len = 5,
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	metadata.sd = sd;
	metadata.sd_len = sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, &metadata, 1,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, 0U);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_layer_write_malformed_metadata_eio(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_layer_metadata_sd_view missing_sd = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_layer_metadata_sd_view duplicate[2] = {
		{ .name = "Policy", .name_len = 6 },
		{ .name = "policy", .name_len = 6 },
	};
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_SET_VALUE, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	duplicate[0].sd = sd;
	duplicate[0].sd_len = sd_len;
	duplicate[1].sd = sd;
	duplicate[1].sd_len = sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, &missing_sd, 1,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, duplicate,
				ARRAY_SIZE(duplicate), &plan),
			(long)-EIO);

	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_layer_write_implicit_base_delegates(
	struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = 4,
		.implicit_base = 1,
	};
	struct pkm_lcs_key_open_access_plan plan = { };
	const void *token;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.requested_access, KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.fd_granted_access, KEY_SET_VALUE);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_layer_write_bad_inputs(struct kunit *test)
{
	struct pkm_lcs_create_layer_target target = {
		.name = "policy",
		.name_len = 6,
	};
	struct pkm_lcs_create_layer_target bad_target = { };
	struct pkm_lcs_key_open_access_plan plan = {
		.allowed = 1,
		.fd_granted_access = KEY_SET_VALUE,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, NULL, false, NULL, 0, NULL, 0, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &bad_target, false, NULL, 0, NULL, 0,
				&plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 1,
				&plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0,
				&plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_layer_write_access_check_for_token(
				token, &target, false, NULL, 0, NULL, 0, NULL),
			(long)-EINVAL);

	kacs_rust_token_drop(token);
}

struct pkm_lcs_kunit_guid_sequence {
	const u8 (*guids)[16];
	u32 count;
	u32 calls;
};

static void pkm_lcs_kunit_guid_sequence_generate(void *raw_ctx, u8 guid[16])
{
	struct pkm_lcs_kunit_guid_sequence *ctx = raw_ctx;
	u32 index;

	if (!ctx || !ctx->guids || !ctx->count) {
		memset(guid, 0, 16);
		return;
	}

	index = ctx->calls < ctx->count ? ctx->calls : ctx->count - 1;
	memcpy(guid, ctx->guids[index], 16);
	ctx->calls++;
}

static struct pkm_lcs_key_guid_generator
pkm_lcs_kunit_guid_generator(struct pkm_lcs_kunit_guid_sequence *sequence)
{
	return (struct pkm_lcs_key_guid_generator) {
		.generate = pkm_lcs_kunit_guid_sequence_generate,
		.ctx = sequence,
	};
}

static void pkm_lcs_kunit_key_guid_assignment_fresh_succeeds(
	struct kunit *test)
{
	static const u8 candidates[1][16] = { { 0x40 } };
	static const u8 active[2][16] = { { 0x41 }, { 0x42 } };
	static const u8 retired[1][16] = { { 0x50 } };
	struct pkm_lcs_key_guid_assignment_plan plan = { };
	struct pkm_lcs_kunit_guid_sequence sequence = {
		.guids = candidates,
		.count = ARRAY_SIZE(candidates),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				active, ARRAY_SIZE(active), retired,
				ARRAY_SIZE(retired), &generator, &plan),
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
	static const u8 retired_then_fresh[2][16] = { { 0x81 }, { 0x82 } };
	static const u8 active[1][16] = { { 0x71 } };
	static const u8 retired[1][16] = { { 0x81 } };
	struct pkm_lcs_key_guid_assignment_plan plan = { };
	struct pkm_lcs_kunit_guid_sequence nil_sequence = {
		.guids = nil_then_fresh,
		.count = ARRAY_SIZE(nil_then_fresh),
	};
	struct pkm_lcs_kunit_guid_sequence active_sequence = {
		.guids = active_then_fresh,
		.count = ARRAY_SIZE(active_then_fresh),
	};
	struct pkm_lcs_kunit_guid_sequence retired_sequence = {
		.guids = retired_then_fresh,
		.count = ARRAY_SIZE(retired_then_fresh),
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&nil_sequence);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 0, NULL, 0,
						    &generator, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, nil_sequence.calls, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(plan.guid, nil_then_fresh[1], 16),
			0);

	generator = pkm_lcs_kunit_guid_generator(&active_sequence);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				active, ARRAY_SIZE(active), NULL, 0,
				&generator, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, active_sequence.calls, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(plan.guid, active_then_fresh[1], 16),
			0);

	generator = pkm_lcs_kunit_guid_generator(&retired_sequence);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(
				NULL, 0, retired, ARRAY_SIZE(retired),
				&generator, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, retired_sequence.calls, 2U);
	KUNIT_EXPECT_EQ(test,
			memcmp(plan.guid, retired_then_fresh[1], 16),
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
				active, ARRAY_SIZE(active), NULL, 0,
				&generator, &plan),
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
				bad_active, ARRAY_SIZE(bad_active), NULL, 0,
				&generator, &plan),
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
			pkm_lcs_assign_new_key_guid(NULL, 0, NULL, 0,
						    &generator, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 1, NULL, 0,
						    &generator, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 0, NULL, 1,
						    &generator, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_assign_new_key_guid(NULL, 0, NULL, 0,
						    &bad_generator, &plan),
			(long)-EINVAL);
}

static void pkm_lcs_kunit_create_symlink_authority_non_link_noop(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan link_plan = {
		.allowed = 1,
		.fd_granted_access = KEY_CREATE_LINK,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				NULL, NULL, REG_OPTION_VOLATILE, &link_plan),
			0L);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, 0U);
}

static void pkm_lcs_kunit_create_symlink_authority_tcb_marks_used(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_LINK, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_EXPECT_EQ(test, before.privileges_used & KACS_SE_TCB_PRIVILEGE,
			0ULL);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			0L);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, KEY_CREATE_LINK);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			KACS_SE_TCB_PRIVILEGE);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_symlink_authority_admin_without_tcb(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_has_enabled_administrators(token));
	KUNIT_ASSERT_FALSE(test,
			   kacs_rust_token_has_enabled_privilege(
				   token, KACS_SE_TCB_PRIVILEGE));
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_LINK, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			0L);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, KEY_CREATE_LINK);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_symlink_authority_denies_missing_link_right(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_SUB_KEY, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, 0U);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & KACS_SE_TCB_PRIVILEGE,
			0ULL);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_symlink_authority_denies_missing_identity(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_FALSE(test,
			   kacs_rust_token_has_enabled_administrators(token));
	sd = kacs_rust_kunit_create_file_sd(token, KEY_CREATE_LINK, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	pkm_lcs_kunit_create_missing_parent_resolution_set_sd(test, &result, sd,
							      sd_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK,
				&link_plan),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, KEY_CREATE_LINK);

	pkm_lcs_create_missing_parent_resolution_destroy(&result);
	pkm_kacs_free((void *)sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_symlink_authority_unknown_flags_einval(
	struct kunit *test)
{
	struct pkm_lcs_create_missing_parent_resolution result = { };
	struct pkm_lcs_key_open_access_plan link_plan = {
		.allowed = 1,
		.fd_granted_access = KEY_CREATE_LINK,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_symlink_authority_for_token(
				token, &result, REG_OPTION_CREATE_LINK | 0x80U,
				&link_plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, link_plan.allowed, 0U);
	KUNIT_EXPECT_EQ(test, link_plan.fd_granted_access, 0U);

	kacs_rust_token_drop(token);
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

static int pkm_lcs_kunit_create_source_read_request(
	struct pkm_lcs_kunit_create_source_script *script, u8 *request,
	size_t request_len, ssize_t *count)
{
	for (;;) {
		*count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (*count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (*count < 0) {
		script->result = (int)*count;
		return script->result;
	}
	script->reads++;
	return 0;
}

static int pkm_lcs_kunit_create_source_expect_bytes(
	const u8 *request, size_t request_len, size_t *offset,
	const void *expected, size_t expected_len)
{
	if (!request || !offset || !expected)
		return -EINVAL;
	if (*offset > request_len || expected_len > request_len - *offset)
		return -EINVAL;
	if (memcmp(request + *offset, expected, expected_len))
		return -EINVAL;
	*offset += expected_len;
	return 0;
}

static int pkm_lcs_kunit_create_source_expect_string(
	const u8 *request, size_t request_len, size_t *offset,
	const char *expected)
{
	u32 actual_len;
	u32 expected_len;

	if (!request || !offset || !expected)
		return -EINVAL;
	if (*offset > request_len ||
	    sizeof(actual_len) > request_len - *offset)
		return -EINVAL;
	actual_len = get_unaligned_le32(request + *offset);
	*offset += sizeof(actual_len);

	expected_len = (u32)strlen(expected);
	if (actual_len != expected_len)
		return -EINVAL;
	return pkm_lcs_kunit_create_source_expect_bytes(
		request, request_len, offset, expected, expected_len);
}

static int pkm_lcs_kunit_create_source_expect_entry_request(
	struct pkm_lcs_kunit_create_source_script *script, const u8 *request,
	size_t request_len, u64 *request_id)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;

	if (!script || !request || !request_id ||
	    request_len < RSI_REQUEST_HEADER_SIZE)
		return -EINVAL;
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_CREATE_ENTRY)
		return -EINVAL;

	*request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, script->parent_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, request_len, &offset, script->child_name))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, request_len, &offset, script->layer_name))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, script->child_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (offset > request_len || sizeof(u64) > request_len - offset)
		return -EINVAL;
	if (get_unaligned_le64(request + offset) != script->expected_sequence)
		return -EINVAL;
	offset += sizeof(u64);
	return offset == request_len ? 0 : -EINVAL;
}

static int pkm_lcs_kunit_create_source_expect_key_request(
	struct pkm_lcs_kunit_create_source_script *script, const u8 *request,
	size_t request_len, u64 *request_id)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u32 sd_len;

	if (!script || !request || !request_id ||
	    request_len < RSI_REQUEST_HEADER_SIZE)
		return -EINVAL;
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_CREATE_KEY)
		return -EINVAL;

	*request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, script->child_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, request_len, &offset, script->child_name))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, script->parent_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (offset > request_len || sizeof(sd_len) > request_len - offset)
		return -EINVAL;
	sd_len = get_unaligned_le32(request + offset);
	offset += sizeof(sd_len);
	if (script->allow_any_sd) {
		if (!sd_len || sd_len > request_len - offset)
			return -EINVAL;
		offset += sd_len;
	} else {
		if (sd_len != script->sd_len)
			return -EINVAL;
		if (pkm_lcs_kunit_create_source_expect_bytes(
			    request, request_len, &offset, script->sd,
			    script->sd_len))
			return -EINVAL;
	}
	if (offset > request_len || 2U > request_len - offset)
		return -EINVAL;
	if (request[offset] != (script->volatile_key ? 1U : 0U) ||
	    request[offset + 1U] != (script->symlink ? 1U : 0U))
		return -EINVAL;
	offset += 2U;
	return offset == request_len ? 0 : -EINVAL;
}

static int pkm_lcs_kunit_create_source_write_status(
	struct pkm_lcs_kunit_create_source_script *script, u64 request_id,
	u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response)) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	return 0;
}

static int pkm_lcs_kunit_create_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_create_source_script *script = raw_script;
	u8 request[256];
	ssize_t count = 0;
	u64 request_id = 0;
	int ret;

	if (!script || !script->file || !script->parent_guid ||
	    !script->child_guid || !script->child_name ||
	    !script->layer_name || (!script->sd && !script->allow_any_sd)) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_create_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_create_source_expect_entry_request(
		script, request, count, &request_id);
	if (ret) {
		script->result = ret;
		return ret;
	}
	ret = pkm_lcs_kunit_create_source_write_status(
		script, request_id, RSI_CREATE_ENTRY, script->entry_status);
	if (ret || !script->expect_key_request) {
		if (!ret)
			script->result = 0;
		return ret;
	}

	ret = pkm_lcs_kunit_create_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_create_source_expect_key_request(
		script, request, count, &request_id);
	if (ret) {
		script->result = ret;
		return ret;
	}
	ret = pkm_lcs_kunit_create_source_write_status(
		script, request_id, RSI_CREATE_KEY, script->key_status);
	if (ret)
		return ret;

	script->result = 0;
	return 0;
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

static void pkm_lcs_kunit_rsi_append_query_value_entry(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const char *value_name, const char *layer_name, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence)
{
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, value_name,
		strlen(value_name));
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, layer_name,
		strlen(layer_name));
	pkm_lcs_kunit_rsi_append_u32(test, frame, frame_len, offset,
				     value_type);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, frame, frame_len,
					      offset, data, data_len);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     sequence);
}

static void pkm_lcs_kunit_rsi_append_query_blanket(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const char *layer_name, u64 sequence)
{
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, layer_name,
		strlen(layer_name));
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     sequence);
}

static int pkm_lcs_kunit_walk_source_append(void *dst, size_t dst_len,
					    size_t *offset, const void *src,
					    size_t src_len)
{
	if (!dst || !offset || (!src && src_len))
		return -EINVAL;
	if (*offset > dst_len || src_len > dst_len - *offset)
		return -EMSGSIZE;

	memcpy((u8 *)dst + *offset, src, src_len);
	*offset += src_len;
	return 0;
}

static int pkm_lcs_kunit_walk_source_append_u8(u8 *dst, size_t dst_len,
					       size_t *offset, u8 value)
{
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, &value,
						sizeof(value));
}

static int pkm_lcs_kunit_walk_source_append_u32(u8 *dst, size_t dst_len,
						size_t *offset, u32 value)
{
	u8 encoded[sizeof(value)];

	put_unaligned_le32(value, encoded);
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, encoded,
						sizeof(encoded));
}

static int pkm_lcs_kunit_walk_source_append_u64(u8 *dst, size_t dst_len,
						size_t *offset, u64 value)
{
	u8 encoded[sizeof(value)];

	put_unaligned_le64(value, encoded);
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, encoded,
						sizeof(encoded));
}

static int pkm_lcs_kunit_walk_source_append_len_prefixed(
	u8 *dst, size_t dst_len, size_t *offset, const void *src,
	size_t src_len)
{
	int ret;

	if (src_len > U32_MAX)
		return -EOVERFLOW;
	ret = pkm_lcs_kunit_walk_source_append_u32(dst, dst_len, offset,
						   (u32)src_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, src,
						src_len);
}

static int pkm_lcs_kunit_walk_source_build_response(
	const struct pkm_lcs_kunit_walk_source_step *step, u64 request_id,
	u16 request_op, u32 index, u8 *response, size_t response_len,
	size_t *built_len)
{
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = request_op | RSI_RESPONSE_BIT;
	u32 path_count;
	u32 metadata_count;
	int ret;

	if (!step || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	path_count = step->empty ? 0U : 1U;
	metadata_count = step->empty ? 0U : 1U;
	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						   &offset, path_count);
	if (ret)
		return ret;
	if (!step->empty) {
		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, "base", strlen("base"));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(
			response, response_len, &offset, RSI_PATH_TARGET_GUID);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append(
			response, response_len, &offset, step->guid,
			RSI_GUID_SIZE);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset, 0);
		if (ret)
			return ret;
	}

	ret = pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						   &offset, metadata_count);
	if (ret)
		return ret;
	if (!step->empty) {
		const u8 *sd = step->sd ? step->sd :
					 pkm_lcs_kunit_owner_only_sd;
		size_t sd_len = step->sd ? step->sd_len :
					    sizeof(pkm_lcs_kunit_owner_only_sd);

		ret = pkm_lcs_kunit_walk_source_append(
			response, response_len, &offset, step->guid,
			RSI_GUID_SIZE);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, sd, sd_len);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(response,
							  response_len,
							  &offset, 0);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(
			response, response_len, &offset, step->symlink ? 1 : 0);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset, 1000ULL + index);
		if (ret)
			return ret;
	}

	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}

static int pkm_lcs_kunit_walk_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_walk_source_script *script = raw_script;
	u8 request[128];
	u8 response[256];
	u32 i;

	if (!script || !script->file || !script->steps) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (i = 0; i < script->step_count; i++) {
		const struct pkm_lcs_kunit_walk_source_step *step =
			&script->steps[i];
		size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
		u64 request_id;
		u16 request_op;
		u32 child_len;
		size_t response_len = 0;
		ssize_t count;
		int ret;

		for (;;) {
			count = pkm_lcs_kunit_source_device_read_file(
				script->file, request, sizeof(request), true);
			if (count != -EAGAIN)
				break;
			if (kthread_should_stop()) {
				script->result = -EINTR;
				return script->result;
			}
			msleep(1);
		}
		if (count < 0) {
			script->result = (int)count;
			return script->result;
		}
		script->reads++;
		if ((size_t)count < child_offset + sizeof(u32)) {
			script->result = -EINVAL;
			return script->result;
		}

		request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
		request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
		if (request_op != RSI_LOOKUP) {
			script->result = -EINVAL;
			return script->result;
		}
		child_len = get_unaligned_le32(request + child_offset);
		child_offset += sizeof(u32);
		if (child_offset > (size_t)count ||
		    child_len > (size_t)count - child_offset ||
		    child_len != strlen(step->expected_child) ||
		    memcmp(request + child_offset, step->expected_child,
			   child_len)) {
			script->result = -EINVAL;
			return script->result;
		}

		ret = pkm_lcs_kunit_walk_source_build_response(
			step, request_id, request_op, i, response,
			sizeof(response), &response_len);
		if (ret) {
			script->result = ret;
			return script->result;
		}
		count = pkm_lcs_kunit_source_device_write_file(
			script->file, response, response_len, false, NULL);
		if (count != (ssize_t)response_len) {
			script->result = count < 0 ? (int)count : -EIO;
			return script->result;
		}
		script->writes++;
	}

	script->result = 0;
	return 0;
}

static int pkm_lcs_kunit_read_key_source_build_response(
	const struct pkm_lcs_kunit_read_key_source_script *script,
	u64 request_id, u8 *response, size_t response_len, size_t *built_len)
{
	static const u8 nil_guid[RSI_GUID_SIZE];
	const char *name;
	const u8 *parent_guid;
	const u8 *sd;
	size_t sd_len;
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = RSI_READ_KEY | RSI_RESPONSE_BIT;
	int ret;

	if (!script || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	name = script->name ? script->name : "Machine";
	parent_guid = script->parent_guid ? script->parent_guid : nil_guid;
	sd = script->sd ? script->sd : pkm_lcs_kunit_owner_only_sd;
	sd_len = script->sd ? script->sd_len :
			      sizeof(pkm_lcs_kunit_owner_only_sd);

	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, name, strlen(name));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append(response, response_len, &offset,
					       parent_guid, RSI_GUID_SIZE);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, sd, sd_len);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u8(
		response, response_len, &offset, script->volatile_key ? 1 : 0);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u8(
		response, response_len, &offset, script->symlink ? 1 : 0);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u64(response, response_len,
						   &offset, 2000ULL);
	if (ret)
		return ret;

	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}

static int pkm_lcs_kunit_read_key_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_read_key_source_script *script = raw_script;
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u8 request[64];
	u8 response[256];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!script || !script->file || !script->expected_guid) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count != expected_len) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_read_key_source_build_response(
		script, request_id, response, sizeof(response), &response_len);
	if (ret) {
		script->result = ret;
		return script->result;
	}
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}

static int pkm_lcs_kunit_read_then_create_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_read_then_create_source_script *script = raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->read_key.file = script->file;
	script->create.file = script->file;

	ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
	script->reads = script->read_key.reads;
	script->writes = script->read_key.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	ret = pkm_lcs_kunit_create_source_thread(&script->create);
	script->reads += script->create.reads;
	script->writes += script->create.writes;
	script->result = ret ? ret : script->create.result;
	return script->result;
}

struct pkm_lcs_kunit_walk_then_read_create_source_script {
	struct file *file;
	struct pkm_lcs_kunit_walk_source_script walk;
	struct pkm_lcs_kunit_read_then_create_source_script create;
	u32 reads;
	u32 writes;
	int result;
};

static int pkm_lcs_kunit_walk_then_read_create_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_walk_then_read_create_source_script *script =
		raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->walk);
	script->reads = script->walk.reads;
	script->writes = script->walk.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	script->create.file = script->file;
	ret = pkm_lcs_kunit_read_then_create_source_thread(&script->create);
	script->reads += script->create.reads;
	script->writes += script->create.writes;
	script->result = ret ? ret : script->create.result;
	return script->result;
}

static int pkm_lcs_kunit_query_values_source_build_response(
	const struct pkm_lcs_kunit_query_values_source_script *script,
	u64 request_id, u8 *response, size_t response_len, size_t *built_len)
{
	const char *value_name;
	const char *layer_name;
	const u8 *data;
	size_t data_len;
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = RSI_QUERY_VALUES | RSI_RESPONSE_BIT;
	int ret;

	if (!script || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	value_name = script->response_value_name ?
			     script->response_value_name :
			     script->expected_value_name;
	layer_name = script->layer_name ? script->layer_name : "base";
	data = script->data ? script->data : (const u8 *)"Machine\\Target";
	data_len = script->data ? script->data_len :
				  strlen("Machine\\Target");

	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						   &offset, 1);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, value_name,
		strlen(value_name));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, layer_name,
		strlen(layer_name));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, response_len, &offset, script->value_type);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, data, data_len);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u64(
		response, response_len, &offset, script->sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, response_len, &offset,
		script->include_blanket ? 1U : 0U);
	if (ret)
		return ret;
	if (script->include_blanket) {
		const char *blanket_layer = script->blanket_layer_name ?
						    script->blanket_layer_name :
						    "overlay";

		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, blanket_layer,
			strlen(blanket_layer));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset,
			script->blanket_sequence);
		if (ret)
			return ret;
	}

	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}

static int pkm_lcs_kunit_query_values_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_query_values_source_script *script = raw_script;
	size_t value_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u8 request[128];
	u8 response[256];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_value_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count < value_offset + sizeof(u32) + sizeof(u8)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset ||
	    value_len != strlen(script->expected_value_name) ||
	    memcmp(request + value_offset, script->expected_value_name,
		   value_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	value_offset += value_len;
	if (value_offset >= (size_t)count ||
	    request[value_offset] != (script->query_all ? 1 : 0)) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_query_values_source_build_response(
		script, request_id, response, sizeof(response), &response_len);
	if (ret) {
		script->result = ret;
		return script->result;
	}
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}

static ssize_t pkm_lcs_kunit_symlink_follow_read_request(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}

static int pkm_lcs_kunit_symlink_follow_write_response(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	const u8 *response, size_t response_len)
{
	ssize_t count;

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}

static int pkm_lcs_kunit_symlink_follow_handle_lookup(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	const struct pkm_lcs_kunit_walk_source_step *step, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 child_len;
	int ret;

	count = pkm_lcs_kunit_symlink_follow_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < child_offset + sizeof(u32))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_LOOKUP)
		return -EINVAL;
	child_len = get_unaligned_le32(request + child_offset);
	child_offset += sizeof(u32);
	if (child_offset > (size_t)count ||
	    child_len > (size_t)count - child_offset ||
	    child_len != strlen(step->expected_child) ||
	    memcmp(request + child_offset, step->expected_child,
		   child_len))
		return -EINVAL;

	ret = pkm_lcs_kunit_walk_source_build_response(
		step, request_id, request_op, script->reads - 1U, response,
		response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_follow_write_response(
		script, response, built_len);
}

static int pkm_lcs_kunit_symlink_follow_handle_query(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	u8 *request, size_t request_len, u8 *response, size_t response_len)
{
	struct pkm_lcs_kunit_query_values_source_script query = {
		.expected_guid = script->link_step.guid,
		.expected_value_name = "",
		.value_type = script->target_value_type,
		.data = script->target_data,
		.data_len = script->target_data_len,
	};
	size_t value_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	count = pkm_lcs_kunit_symlink_follow_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < value_offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->link_step.guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset || value_len)
		return -EINVAL;
	value_offset += value_len;
	if (value_offset >= (size_t)count || request[value_offset])
		return -EINVAL;

	ret = pkm_lcs_kunit_query_values_source_build_response(
		&query, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_follow_write_response(
		script, response, built_len);
}

static int pkm_lcs_kunit_symlink_follow_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_symlink_follow_source_script *script = raw_script;
	u8 request[128];
	u8 response[256];
	int ret;

	if (!script || !script->file || !script->link_step.expected_child ||
	    !script->link_step.guid || !script->target_data) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_symlink_follow_handle_lookup(
		script, &script->link_step, request, sizeof(request),
		response, sizeof(response));
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_symlink_follow_handle_query(
		script, request, sizeof(request), response, sizeof(response));
	if (ret || !script->expect_target_lookup)
		goto out;
	ret = pkm_lcs_kunit_symlink_follow_handle_lookup(
		script, &script->target_step, request, sizeof(request),
		response, sizeof(response));

out:
	script->result = ret;
	return ret;
}

static ssize_t pkm_lcs_kunit_symlink_sequence_read_request(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}

static int pkm_lcs_kunit_symlink_sequence_write_response(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const u8 *response, size_t response_len)
{
	ssize_t count;

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}

static int pkm_lcs_kunit_symlink_sequence_handle_lookup(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len, u32 index)
{
	const struct pkm_lcs_kunit_walk_source_step *step = op->lookup_step;
	size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 child_len;
	int ret;

	if (!step || !step->expected_child)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < child_offset + sizeof(u32))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_LOOKUP)
		return -EINVAL;
	child_len = get_unaligned_le32(request + child_offset);
	child_offset += sizeof(u32);
	if (child_offset > (size_t)count ||
	    child_len > (size_t)count - child_offset ||
	    child_len != strlen(step->expected_child) ||
	    memcmp(request + child_offset, step->expected_child, child_len))
		return -EINVAL;

	ret = pkm_lcs_kunit_walk_source_build_response(
		step, request_id, request_op, index, response, response_len,
		&built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}

static int pkm_lcs_kunit_symlink_sequence_handle_query(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	struct pkm_lcs_kunit_query_values_source_script query = {
		.expected_guid = op->query_guid,
		.expected_value_name = "",
		.value_type = op->query_value_type,
		.data = op->query_data,
		.data_len = op->query_data_len,
	};
	size_t value_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	if (!op->query_guid || !op->query_data)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < value_offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, op->query_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset || value_len)
		return -EINVAL;
	value_offset += value_len;
	if (value_offset >= (size_t)count || request[value_offset])
		return -EINVAL;

	ret = pkm_lcs_kunit_query_values_source_build_response(
		&query, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}

static int pkm_lcs_kunit_symlink_sequence_handle_read_key(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	const struct pkm_lcs_kunit_read_key_source_script *read_key =
		op->read_key;
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!read_key || !read_key->expected_guid)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != expected_len)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, read_key->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	ret = pkm_lcs_kunit_read_key_source_build_response(
		read_key, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}

static int pkm_lcs_kunit_symlink_sequence_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_symlink_sequence_source_script *script =
		raw_script;
	u8 request[128];
	u8 response[256];
	u32 i;
	int ret = 0;

	if (!script || !script->file || !script->ops || !script->op_count) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (i = 0; i < script->op_count; i++) {
		const struct pkm_lcs_kunit_symlink_sequence_op *op =
			&script->ops[i];

		switch (op->op) {
		case PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP:
			ret = pkm_lcs_kunit_symlink_sequence_handle_lookup(
				script, op, request, sizeof(request), response,
				sizeof(response), i);
			break;
		case PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT:
			ret = pkm_lcs_kunit_symlink_sequence_handle_query(
				script, op, request, sizeof(request), response,
				sizeof(response));
			break;
		case PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY:
			ret = pkm_lcs_kunit_symlink_sequence_handle_read_key(
				script, op, request, sizeof(request), response,
				sizeof(response));
			break;
		default:
			ret = -EINVAL;
			break;
		}
		if (ret)
			break;
	}

	script->result = ret;
	return ret;
}

static void pkm_lcs_kunit_rsi_read_key_bridge_accepts_valid(
	struct kunit *test)
{
	static const u8 guid[RSI_GUID_SIZE] = {
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	};
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = guid,
		.name = "Machine",
	};
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_rsi_read_key_result result = { };
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE];
	u8 response[256];
	size_t response_len = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_read_key_request(
				request, sizeof(request), 42, 0, guid, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, sizeof(request));
	KUNIT_EXPECT_EQ(test, built.request_id, 42ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_READ_KEY);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, guid,
			       RSI_GUID_SIZE),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_read_key_source_build_response(
				&script, built.request_id, response,
				sizeof(response), &response_len),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_read_key_response(
				response, response_len, built.request_id,
				&result),
			0L);
	KUNIT_EXPECT_EQ(test, result.name_len, 7U);
	KUNIT_EXPECT_EQ(test,
			result.sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_EXPECT_EQ(test, result.last_write_time, 2000ULL);
	KUNIT_EXPECT_EQ(test, result.volatile_key, 0U);
	KUNIT_EXPECT_EQ(test, result.symlink, 0U);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + result.sd_offset,
			       pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);
}

static void pkm_lcs_kunit_rsi_query_values_bridge_materializes_default_reg_link(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_rsi_built_request built = { };
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE + sizeof(u32) +
		   sizeof(u8)];
	u8 response[256];
	size_t offset;
	size_t response_len;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_query_values_request(
				request, sizeof(request), 43, 0, guid, "", 0,
				false, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, sizeof(request));
	KUNIT_EXPECT_EQ(test, built.request_id, 43ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_QUERY_VALUES);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request + RSI_REQUEST_HEADER_SIZE +
					   RSI_GUID_SIZE),
			0U);
	KUNIT_EXPECT_EQ(test, request[sizeof(request) - 1], 0U);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 built.request_id,
					 RSI_QUERY_VALUES_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "", "base",
		REG_LINK, target, sizeof(target) - 1, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_value_response(
				response, response_len, built.request_id, 1,
				"", 0, layers, ARRAY_SIZE(layers), NULL, 0,
				&result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, result.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, result.value_type, (u32)REG_LINK);
	KUNIT_EXPECT_EQ(test, result.selected_precedence, 0U);
	KUNIT_EXPECT_EQ(test, result.selected_sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, result.data_len, (u32)(sizeof(target) - 1));
	KUNIT_ASSERT_LE(test,
			(size_t)result.data_offset +
				(size_t)result.data_len,
			response_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(response + result.data_offset, target,
			       sizeof(target) - 1),
			0);
}

static void pkm_lcs_kunit_rsi_query_values_bridge_blanket_not_found(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 44, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "", "base",
		REG_LINK, target, sizeof(target) - 1, 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_blanket(
		test, response, sizeof(response), &offset, "overlay", 2);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_query_value_response(
				response, response_len, 44, 3, "", 0, layers,
				ARRAY_SIZE(layers), NULL, 0, &result),
			0L);
	KUNIT_EXPECT_FALSE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.source_value_entry_count, 1U);
	KUNIT_EXPECT_EQ(test, result.source_blanket_count, 1U);
}

static void pkm_lcs_kunit_rsi_query_values_bridge_rejects_wrong_value(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_rsi_query_value_result result = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 45, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "Other", "base",
		REG_LINK, target, sizeof(target) - 1, 0);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_query_value_response(
				response, response_len, 45, 1, "", 0, layers,
				ARRAY_SIZE(layers), NULL, 0, &result),
			(long)-EIO);
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
	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-values");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
				1, 0, guid, "", 0, false,
				PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame,
				&response, &enqueue),
			0L);
	thread_ret = kthread_stop(task);

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
				&result),
			0L);
	KUNIT_EXPECT_TRUE(test, result.found);
	KUNIT_EXPECT_EQ(test, result.value_type, (u32)REG_LINK);
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

static void pkm_lcs_kunit_symlink_target_materializes_literal_current_user(
	struct kunit *test)
{
	static const char target[] = "CurrentUser\\Software";
	struct pkm_lcs_materialized_path path = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_materialize_symlink_target_components(
				target, sizeof(target) - 1, &path),
			0L);
	KUNIT_ASSERT_EQ(test, path.component_count, 2U);
	KUNIT_ASSERT_NOT_NULL(test, path.components);
	KUNIT_EXPECT_EQ(test, path.components[0].name_len, 11U);
	KUNIT_EXPECT_EQ(test,
			memcmp(path.components[0].name, "CurrentUser", 11),
			0);
	KUNIT_EXPECT_EQ(test, path.components[1].name_len, 8U);
	KUNIT_EXPECT_EQ(test,
			memcmp(path.components[1].name, "Software", 8),
			0);

	pkm_lcs_materialized_path_destroy(&path);
}

static void pkm_lcs_kunit_symlink_target_resolution_success(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = link_guid,
		.expected_value_name = "",
		.value_type = REG_LINK,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_symlink_target_resolution resolution = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-symlink-target");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_resolve_symlink_target_for_key(
		1, 0, link_guid, NULL, 0, layers, ARRAY_SIZE(layers), NULL,
		0, &resolution);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, resolution.route.source_id, 1U);
	KUNIT_EXPECT_EQ(test, resolution.route.root_guid[0], 1U);
	KUNIT_EXPECT_EQ(test, resolution.value_type, (u32)REG_LINK);
	KUNIT_EXPECT_EQ(test, resolution.selected_precedence, 0U);
	KUNIT_EXPECT_EQ(test, resolution.selected_sequence, 0ULL);
	KUNIT_ASSERT_EQ(test, resolution.components.component_count, 2U);
	KUNIT_EXPECT_EQ(test, resolution.components.components[0].name_len, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(resolution.components.components[0].name,
			       "Machine", 7),
			0);
	KUNIT_EXPECT_EQ(test, resolution.components.components[1].name_len, 6U);
	KUNIT_EXPECT_EQ(test,
			memcmp(resolution.components.components[1].name,
			       "Target", 6),
			0);

	pkm_lcs_symlink_target_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_symlink_target_resolution_non_link_einval(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	};
	static const u8 target[] = "Machine\\Target";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = link_guid,
		.expected_value_name = "",
		.value_type = REG_SZ,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_symlink_target_resolution resolution = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-symlink-nonlink");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_resolve_symlink_target_for_key(
		1, 0, link_guid, NULL, 0, layers, ARRAY_SIZE(layers), NULL,
		0, &resolution);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_PTR_EQ(test, resolution.components.components, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_symlink_target_resolution_bad_target_einval(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
		0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	};
	static const u8 target[] = "Machine\\\\Target";
	struct pkm_lcs_kunit_query_values_source_script script = {
		.expected_guid = link_guid,
		.expected_value_name = "",
		.value_type = REG_LINK,
		.data = target,
		.data_len = sizeof(target) - 1,
	};
	struct pkm_lcs_symlink_target_resolution resolution = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-symlink-badtarget");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_resolve_symlink_target_for_key(
		1, 0, link_guid, NULL, 0, layers, ARRAY_SIZE(layers), NULL,
		0, &resolution);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_PTR_EQ(test, resolution.components.components, NULL);

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

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_source_status_policy(struct kunit *test)
{
	struct pkm_lcs_reg_create_source_response_plan plan = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_OK, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action,
			PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	memset(&plan, 0xff, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_ALREADY_EXISTS, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action,
			PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING);
	KUNIT_EXPECT_EQ(test, plan.disposition, REG_OPENED_EXISTING);

	memset(&plan, 0xff, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_KEY, RSI_OK, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action,
			PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, plan.disposition, REG_CREATED_NEW);
}

static void pkm_lcs_kunit_reg_create_source_status_fails_closed(
	struct kunit *test)
{
	struct pkm_lcs_reg_create_source_response_plan plan = {
		.action = 99,
		.disposition = 88,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_KEY, RSI_ALREADY_EXISTS, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	plan.action = 99;
	plan.disposition = 88;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_NOT_FOUND, &plan),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	plan.action = 99;
	plan.disposition = 88;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, 0xffffffffU, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	plan.action = 99;
	plan.disposition = 88;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_LOOKUP, RSI_OK, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test, plan.disposition, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_source_response_plan(
				RSI_CREATE_ENTRY, RSI_OK, NULL),
			(long)-EINVAL);
}

static void pkm_lcs_kunit_create_missing_source_records_created_new(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	};
	static const u8 child_guid[RSI_GUID_SIZE] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80, 0x30, 0x00 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Created",
		.child_name_len = strlen("Created"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "Created",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
		.volatile_key = true,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-create-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, true, false,
		&result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_source_entry_race_retries(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x41 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x42 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Race",
		.child_name_len = strlen("Race"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "Race",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_ALREADY_EXISTS,
		.expect_key_request = false,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-create-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, false, false,
		&result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_TRUE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_source_key_duplicate_eio(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x51 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x52 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Duplicate",
		.child_name_len = strlen("Duplicate"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = {
		.sequence = 99,
		.disposition = 88,
		.created_new = true,
		.retry_open_existing = true,
	};
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "Duplicate",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_ALREADY_EXISTS,
		.expect_key_request = true,
	};
	struct pkm_lcs_source_table_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	memcpy(resolution.parent.key_guid, parent_guid, RSI_GUID_SIZE);
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-create-dup");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_source_records(
		&resolution, &target, child_guid, &created_sd, false, false,
		&result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, 0U);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	pkm_lcs_kunit_source_table_snapshot(&snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.next_sequence, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_source_bad_inputs(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x61 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = {
		.parent.source_id = 1,
		.child_name = "Bad",
		.child_name_len = strlen("Bad"),
	};
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
	};
	struct pkm_lcs_created_key_sd created_sd = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_source_records_result result = {
		.sequence = 99,
		.disposition = 88,
		.created_new = true,
		.retry_open_existing = true,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_source_records(
				NULL, &target, child_guid, &created_sd, false,
				false, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, result.disposition, 0U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_source_records(
				&resolution, &target, child_guid, &created_sd,
				false, false, NULL),
			(long)-EINVAL);

	result.sequence = 99;
	result.disposition = 88;
	result.created_new = true;
	result.retry_open_existing = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_source_records(
				&resolution, &target, child_guid, &created_sd,
				false, false, &result),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test, result.sequence, 0ULL);
	KUNIT_EXPECT_EQ(test, result.disposition, 0U);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
}

static void pkm_lcs_kunit_create_missing_set_child_path(
	struct kunit *test, struct pkm_lcs_create_missing_parent_resolution *res)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 0x21 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };

	KUNIT_ASSERT_NOT_NULL(test, res);

	res->parent.resolved_path = kcalloc(2, sizeof(*res->parent.resolved_path),
					   GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path);
	res->parent.ancestor_guids = kcalloc(2, sizeof(*res->parent.ancestor_guids),
					     GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.ancestor_guids);
	res->parent.resolved_path[0] = kstrdup("Machine", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path[0]);
	res->parent.resolved_path[1] = kstrdup("Software", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path[1]);
	res->child_name = kstrdup("App", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->child_name);

	res->parent.source_id = 1;
	res->parent.component_count = 2;
	memcpy(res->parent.key_guid, parent_guid, sizeof(res->parent.key_guid));
	memcpy(res->parent.ancestor_guids[0], root_guid, RSI_GUID_SIZE);
	memcpy(res->parent.ancestor_guids[1], parent_guid, RSI_GUID_SIZE);
	res->child_name_len = 3;
	res->child_depth = 3;
}

static void pkm_lcs_kunit_create_missing_publish_created_success(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x33 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;
	long fd;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	fd = pkm_lcs_create_missing_publish_created_key_for_token(
		token, &resolution, child_guid, &created, KEY_READ);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, snapshot.path_component_count, 3U);
	KUNIT_EXPECT_STREQ(test, snapshot.first_component, "Machine");
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_guid,
			       sizeof(snapshot.key_guid)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.last_ancestor_guid, child_guid,
			       sizeof(snapshot.last_ancestor_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_publish_created_denied(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x44 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_QUERY_VALUE, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, &created,
				KEY_SET_VALUE),
			(long)-EACCES);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_publish_created_malformed_sd(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x55 };
	static const u8 bad_sd[] = { 0x00, 0x01, 0x02, 0x03 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = {
		.sd = bad_sd,
		.sd_len = sizeof(bad_sd),
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, &created,
				KEY_READ),
			(long)-EIO);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_publish_created_bad_inputs(
	struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x66 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_created_key_sd created = { };
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				NULL, &resolution, child_guid, &created,
				KEY_READ),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, NULL, child_guid, &created, KEY_READ),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, NULL, &created, KEY_READ),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, NULL, KEY_READ),
			(long)-EINVAL);
	resolution.child_depth = 4;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, child_guid, &created,
				KEY_READ),
			(long)-EINVAL);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_prepared_created_new_success(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x77 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	script.sd = created.sd;
	script.sd_len = created.sd_len;
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	task = kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-create");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created, KEY_READ,
		false, false, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_ASSERT_TRUE(test, result.fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)result.fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_guid,
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)result.fd), 0);
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_prepared_entry_race_retries(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x78 };
	static const u8 sd[] = { 0x01, 0x00, 0x04, 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = {
		.sd = sd,
		.sd_len = sizeof(sd),
	};
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.sd = sd,
		.sd_len = sizeof(sd),
		.expected_sequence = 1,
		.entry_status = RSI_ALREADY_EXISTS,
		.expect_key_request = false,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	task = kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created, KEY_READ,
		false, false, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_TRUE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_prepared_denies_after_source(
	struct kunit *test)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x79 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = { };
	struct pkm_lcs_kunit_create_source_script script = {
		.parent_guid = parent_guid,
		.child_guid = child_guid,
		.child_name = "App",
		.layer_name = "base",
		.expected_sequence = 1,
		.entry_status = RSI_OK,
		.key_status = RSI_OK,
		.expect_key_request = true,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_QUERY_VALUE, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	script.sd = created.sd;
	script.sd_len = created.sd_len;
	script.file = &file;
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);
	task = kthread_run(pkm_lcs_kunit_create_source_thread, &script,
			   "pkm-lcs-kunit-prepared-deny");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, child_guid, &created,
		KEY_SET_VALUE, false, false, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);
	KUNIT_EXPECT_EQ(test, result.disposition, REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, result.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_prepared_bad_inputs(struct kunit *test)
{
	static const u8 child_guid[RSI_GUID_SIZE] = { 0x80 };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_create_layer_target target = {
		.name = "base",
		.name_len = strlen("base"),
		.implicit_base = 1,
	};
	struct pkm_lcs_created_key_sd created = { };
	struct pkm_lcs_create_missing_prepared_result result = {
		.fd = 123,
		.sequence = 99,
		.disposition = 88,
		.created_new = true,
		.retry_open_existing = true,
	};
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);
	created.sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &created.sd_len);
	KUNIT_ASSERT_NOT_NULL(test, created.sd);
	pkm_lcs_kunit_create_missing_set_child_path(test, &resolution);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_prepared_key_for_token(
				token, &resolution, &target, child_guid, &created,
				KEY_READ, false, false, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_prepared_key_for_token(
				token, NULL, &target, child_guid, &created,
				KEY_READ, false, false, &result),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, result.fd, -1L);
	KUNIT_EXPECT_EQ(test, result.sequence, 0ULL);
	KUNIT_EXPECT_FALSE(test, result.created_new);
	KUNIT_EXPECT_FALSE(test, result.retry_open_existing);

	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	pkm_kacs_free((void *)created.sd);
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_branch_created_new_success(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x91 } };
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_read_then_create_source_script script = {
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
			.expect_key_request = true,
			.allow_any_sd = true,
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	task = kthread_run(pkm_lcs_kunit_read_then_create_source_thread,
			   &script, "pkm-lcs-kunit-create-full");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_candidates[0],
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_branch_volatile_parent_denies(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\Blocked";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
		.volatile_key = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *parent_sd;
	size_t parent_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	parent_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_CREATE_SUB_KEY, 0, 0, 0, &parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);

	script.file = &file;
	script.sd = parent_sd;
	script.sd_len = parent_sd_len;
	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-vol");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_create_missing_user_path_finish_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, NULL, (u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);

	pkm_kacs_free((void *)parent_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_branch_rejects_bad_snapshots(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_create_missing_runtime_inputs bad_inputs = {
		.scope_count = 1,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_user_path_finish_for_token(
				NULL, &ops, -1, (const char __user *)path_src,
				KEY_READ, NULL, 0, &bad_inputs,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}

static void pkm_lcs_kunit_create_missing_copied_path_success(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x92 } };
	struct pkm_lcs_syscall_path_copy copy = {
		.path = (char *)path_src,
		.path_len = sizeof(path_src),
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_read_then_create_source_script script = {
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_OK,
			.key_status = RSI_OK,
			.expect_key_request = true,
			.allow_any_sd = true,
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	task = kthread_run(pkm_lcs_kunit_read_then_create_source_thread,
			   &script, "pkm-lcs-kunit-create-copy-full");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_create_missing_copied_path_finish_for_token(
		token, &ops, -1, &copy, KEY_READ, NULL, 0, &inputs,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.key_guid, child_candidates[0],
			       sizeof(snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_create_missing_copied_path_rejects_bad_copy(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_syscall_path_copy bad_copy = {
		.path = (char *)path_src,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	const void *token;
	u32 disposition = 0xaaaaaaaaU;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_create_missing_copied_path_finish_for_token(
				token, &ops, -1, &bad_copy, KEY_READ, NULL,
				0, NULL, (u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);

	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_existing_ignores_layer(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	const char layer_src[] = "should-not-be-read";
	struct pkm_lcs_kunit_usercopy_ctx ctx = {
		.fault_strlen_src = layer_src,
	};
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_read_key_source_script script = {
		.expected_guid = root_guid,
		.name = "Machine",
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *sd;
	size_t sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-reg-create-existing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		(const char __user *)layer_src,
		REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL,
		(u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_missing_fallback_success(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\App";
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x93 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	struct pkm_lcs_kunit_guid_sequence guid_sequence = {
		.guids = child_candidates,
		.count = 1,
	};
	struct pkm_lcs_key_guid_generator generator =
		pkm_lcs_kunit_guid_generator(&guid_sequence);
	struct pkm_lcs_create_missing_runtime_inputs inputs = {
		.base_metadata_present = true,
		.generator = &generator,
	};
	struct pkm_lcs_kunit_walk_then_read_create_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.create = {
			.read_key = {
				.expected_guid = root_guid,
				.name = "Machine",
			},
			.create = {
				.parent_guid = root_guid,
				.child_guid = child_candidates[0],
				.child_name = "App",
				.layer_name = "base",
				.expected_sequence = 1,
				.entry_status = RSI_OK,
				.key_status = RSI_OK,
				.expect_key_request = true,
				.allow_any_sd = true,
			},
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;
	script.create.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.create.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	task = kthread_run(pkm_lcs_kunit_walk_then_read_create_source_thread,
			   &script, "pkm-lcs-kunit-reg-create-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 4U);
	KUNIT_EXPECT_EQ(test, script.writes, 4U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, snapshot.last_component, "App");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_bad_flags_before_usercopy(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_for_token(
				NULL, &ops, -1, (const char __user *)path_src,
				KEY_READ, NULL, 0x80000000U, NULL,
				(u32 __user *)&disposition),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
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

static void pkm_lcs_kunit_open_component_walk_collects_ancestors(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "Software", .name_len = 8 },
		{ .name = "App", .name_len = 3 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 software_guid[RSI_GUID_SIZE] = {
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	};
	static const u8 app_guid[RSI_GUID_SIZE] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Software", .guid = software_guid },
		{ .expected_child = "App", .guid = app_guid },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_resolved_key_path result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-walk");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_walk_absolute_components(
		1, 0, root_guid, components, ARRAY_SIZE(components), layers,
		ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, result.source_id, 1U);
	KUNIT_EXPECT_EQ(test, result.component_count, 3U);
	KUNIT_EXPECT_STREQ(test, result.resolved_path[0], "Machine");
	KUNIT_EXPECT_STREQ(test, result.resolved_path[1], "Software");
	KUNIT_EXPECT_STREQ(test, result.resolved_path[2], "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(result.ancestor_guids[0], root_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.ancestor_guids[1], software_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.ancestor_guids[2], app_guid,
			       RSI_GUID_SIZE),
			0);
	KUNIT_EXPECT_EQ(test, memcmp(result.key_guid, app_guid,
				    RSI_GUID_SIZE), 0);
	KUNIT_EXPECT_EQ(test, result.final_sd_len,
			(u32)sizeof(pkm_lcs_kunit_owner_only_sd));
	KUNIT_ASSERT_NOT_NULL(test, result.final_frame.data);
	KUNIT_ASSERT_LE(test,
			(size_t)result.final_sd_offset +
				(size_t)result.final_sd_len,
			result.final_frame.len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result.final_frame.data + result.final_sd_offset,
			       pkm_lcs_kunit_owner_only_sd,
			       sizeof(pkm_lcs_kunit_owner_only_sd)),
			0);
	KUNIT_EXPECT_FALSE(test, result.final_symlink);
	KUNIT_EXPECT_FALSE(test, result.final_volatile);
	KUNIT_EXPECT_EQ(test, result.final_last_write_time, 1001ULL);

	pkm_lcs_resolved_key_path_destroy(&result);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_component_walk_empty_child_enoent(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "Missing", .name_len = 7 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Missing", .empty = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_resolved_key_path result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-walk-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_walk_absolute_components(
		1, 0, root_guid, components, ARRAY_SIZE(components), layers,
		ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ENOENT);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_PTR_EQ(test, result.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.ancestor_guids, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.final_frame.data, NULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_open_component_walk_rejects_bad_private_layers(
	struct kunit *test)
{
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "App", .name_len = 3 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	struct pkm_lcs_resolved_key_path result = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_walk_absolute_components(
				1, 0, root_guid, components,
				ARRAY_SIZE(components), NULL, 0, NULL, 1,
				&result),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.ancestor_guids, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.final_frame.data, NULL);
}

static void pkm_lcs_kunit_open_component_walk_symlink_fails_closed(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const struct pkm_lcs_path_component_view components[] = {
		{ .name = "Machine", .name_len = 7 },
		{ .name = "Link", .name_len = 4 },
	};
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 link_guid[RSI_GUID_SIZE] = {
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	};
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{ .expected_child = "Link", .guid = link_guid,
		  .symlink = true },
	};
	struct pkm_lcs_kunit_walk_source_script script = {
		.steps = steps,
		.step_count = ARRAY_SIZE(steps),
	};
	struct pkm_lcs_resolved_key_path result = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	script.file = &file;
	task = kthread_run(pkm_lcs_kunit_walk_source_thread, &script,
			   "pkm-lcs-kunit-walk-link");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_walk_absolute_components(
		1, 0, root_guid, components, ARRAY_SIZE(components), layers,
		ARRAY_SIZE(layers), NULL, 0, &result);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_PTR_EQ(test, result.resolved_path, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.ancestor_guids, NULL);
	KUNIT_EXPECT_PTR_EQ(test, result.final_frame.data, NULL);

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
	KUNIT_CASE(pkm_lcs_kunit_create_preflight_accepts_valid_flags),
	KUNIT_CASE(pkm_lcs_kunit_create_preflight_rejects_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_target_null_uses_base),
	KUNIT_CASE(
		pkm_lcs_kunit_create_layer_target_explicit_layer_admitted),
	KUNIT_CASE(
		pkm_lcs_kunit_create_layer_target_absent_returns_enoent),
	KUNIT_CASE(
		pkm_lcs_kunit_create_layer_target_bad_name_fails_closed),
	KUNIT_CASE(
		pkm_lcs_kunit_create_layer_target_copy_faults_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_success),
	KUNIT_CASE(pkm_lcs_kunit_open_preflight_route_stops_before_usercopy),
	KUNIT_CASE(
		pkm_lcs_kunit_open_preflight_route_copy_fault_keeps_route_empty),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_absolute_success),
	KUNIT_CASE(
		pkm_lcs_kunit_open_path_components_normalizes_forward_slashes),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_rewrites_current_user),
	KUNIT_CASE(pkm_lcs_kunit_open_path_components_rejects_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_composes_success),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_uses_implicit_base_layer),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_final_symlink_open_link),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_final_symlink_follows_target),
	KUNIT_CASE(
		pkm_lcs_kunit_open_absolute_final_symlink_bad_target_einval),
	KUNIT_CASE(
		pkm_lcs_kunit_open_absolute_intermediate_symlink_follows_suffix),
	KUNIT_CASE(
		pkm_lcs_kunit_open_absolute_recursive_symlink_follows_target),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_symlink_depth_limit_eloop),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_uses_read_key),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_syscall_dispatches_absolute),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_syscall_dispatches_relative),
	KUNIT_CASE(pkm_lcs_kunit_reg_open_key_syscall_rejects_null_token),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_absolute_sets_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_accepts_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_finish_copies_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_finish_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_finish_faults_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_copied_finish_success),
	KUNIT_CASE(
		pkm_lcs_kunit_create_existing_copied_finish_fault_closes_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_existing_copied_rejects_bad_copy),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_success),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_null_is_noop),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_faults),
	KUNIT_CASE(pkm_lcs_kunit_create_disposition_copyout_bad_ops),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_success_returns_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_success_null_disposition),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_fault_closes_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_finish_rejects_invalid_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_success),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_created_finish_null_disposition),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_created_finish_fault_closes_fd),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_created_finish_rejects_retry),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_created_finish_rejects_malformed),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_success),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_fault_closes),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_retry_open_denied_no_copyout),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_retry_open_bad_resolution),
	KUNIT_CASE(
		pkm_lcs_kunit_create_existing_rejects_flags_before_usercopy),
	KUNIT_CASE(
		pkm_lcs_kunit_create_existing_dispatches_relative_parent),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_absolute_resolves_parent_only),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_absolute_missing_parent_enoent),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_absolute_root_path_rejected),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_relative_direct_parent_reads_sd),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_relative_checks_child_depth),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_parent_access_allows_create_subkey),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_parent_access_denies_without_right),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_parent_access_malformed_sd_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_parent_access_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_volatile_parent_rejects_nonvolatile),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_volatile_parent_allows_volatile),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_volatile_parent_allows_nonvolatile_parent),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_volatile_parent_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_create_initial_sd_inherits_registry_mapping),
	KUNIT_CASE(pkm_lcs_kunit_create_initial_sd_malformed_parent_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_initial_sd_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_allows_key_set_value),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_denies_without_right),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_malformed_sd_eio),
	KUNIT_CASE(pkm_lcs_kunit_layer_write_access_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_base_layer_default_sd_allows_system_and_admin),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_default_sd_denies_service),
	KUNIT_CASE(
		pkm_lcs_kunit_base_layer_write_present_sd_overrides_default),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_absent_uses_default),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_absent_denies_service),
	KUNIT_CASE(pkm_lcs_kunit_base_layer_write_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_explicit_folded_match),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_explicit_denied),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_missing_metadata_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_malformed_metadata_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_implicit_base_delegates),
	KUNIT_CASE(pkm_lcs_kunit_create_layer_write_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_fresh_succeeds),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_retries_bad_candidates),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_exhaustion_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_bad_tracker_eio),
	KUNIT_CASE(pkm_lcs_kunit_key_guid_assignment_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_non_link_noop),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_tcb_marks_used),
	KUNIT_CASE(pkm_lcs_kunit_create_symlink_authority_admin_without_tcb),
	KUNIT_CASE(
		pkm_lcs_kunit_create_symlink_authority_denies_missing_link_right),
	KUNIT_CASE(
		pkm_lcs_kunit_create_symlink_authority_denies_missing_identity),
	KUNIT_CASE(
		pkm_lcs_kunit_create_symlink_authority_unknown_flags_einval),
	KUNIT_CASE(
		pkm_lcs_kunit_open_absolute_root_denied_publishes_no_fd),
	KUNIT_CASE(
		pkm_lcs_kunit_open_absolute_root_malformed_sd_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_root_symlink_follows_target),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_symlink_target_hive_root),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_denied_publishes_no_fd),
	KUNIT_CASE(pkm_lcs_kunit_open_absolute_malformed_sd_fails_closed),
	KUNIT_CASE(
		pkm_lcs_kunit_open_absolute_preflight_stops_before_usercopy),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_composes_success),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_uses_implicit_base_layer),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_final_symlink_open_link),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_final_symlink_follows_target),
	KUNIT_CASE(
		pkm_lcs_kunit_open_relative_intermediate_symlink_follows_suffix),
	KUNIT_CASE(pkm_lcs_kunit_open_relative_denied_publishes_no_fd),
	KUNIT_CASE(
		pkm_lcs_kunit_open_relative_preflight_stops_before_usercopy),
	KUNIT_CASE(
		pkm_lcs_kunit_open_relative_orphan_parent_fails_closed),
	KUNIT_CASE(
		pkm_lcs_kunit_key_open_access_bridge_allows_registry_rights),
	KUNIT_CASE(
		pkm_lcs_kunit_key_open_access_bridge_denies_partial_grants),
	KUNIT_CASE(pkm_lcs_kunit_key_open_access_bridge_maximum_allowed),
	KUNIT_CASE(pkm_lcs_kunit_key_open_access_bridge_malformed_sd_eio),
	KUNIT_CASE(pkm_lcs_kunit_key_open_audit_not_required_no_event),
	KUNIT_CASE(pkm_lcs_kunit_key_open_audit_emits_lcs_kmes_event),
	KUNIT_CASE(
		pkm_lcs_kunit_key_open_audit_payload_abi_rejects_bad_state),
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
	KUNIT_CASE(pkm_lcs_kunit_rsi_read_key_bridge_accepts_valid),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_query_values_bridge_materializes_default_reg_link),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_query_values_bridge_blanket_not_found),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_query_values_bridge_rejects_wrong_value),
	KUNIT_CASE(
		pkm_lcs_kunit_source_query_values_round_trip_retains_frame),
	KUNIT_CASE(
		pkm_lcs_kunit_symlink_target_materializes_literal_current_user),
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_resolution_success),
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_resolution_non_link_einval),
	KUNIT_CASE(pkm_lcs_kunit_symlink_target_resolution_bad_target_einval),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_returns_complete_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_preserves_fifo_order),
	KUNIT_CASE(
		pkm_lcs_kunit_source_request_read_short_buffer_preserves_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_read_fault_preserves_queue),
	KUNIT_CASE(pkm_lcs_kunit_source_request_enqueue_rejects_bad_state),
	KUNIT_CASE(
		pkm_lcs_kunit_source_dispatch_lookup_allocates_monotonic_ids),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_create_entry_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_create_key_frame),
	KUNIT_CASE(
		pkm_lcs_kunit_source_dispatch_create_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_source_status_policy),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_source_status_fails_closed),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_source_records_created_new),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_source_entry_race_retries),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_source_key_duplicate_eio),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_source_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_publish_created_success),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_publish_created_denied),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_publish_created_malformed_sd),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_publish_created_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_prepared_created_new_success),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_prepared_entry_race_retries),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_prepared_denies_after_source),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_prepared_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_branch_created_new_success),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_branch_volatile_parent_denies),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_branch_rejects_bad_snapshots),
	KUNIT_CASE(pkm_lcs_kunit_create_missing_copied_path_success),
	KUNIT_CASE(
		pkm_lcs_kunit_create_missing_copied_path_rejects_bad_copy),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_existing_ignores_layer),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_missing_fallback_success),
	KUNIT_CASE(
		pkm_lcs_kunit_reg_create_key_bad_flags_before_usercopy),
	KUNIT_CASE(
		pkm_lcs_kunit_sequence_allocation_advances_global_counter),
	KUNIT_CASE(pkm_lcs_kunit_sequence_allocation_fails_closed),
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
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_collects_ancestors),
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_empty_child_enoent),
	KUNIT_CASE(
		pkm_lcs_kunit_open_component_walk_rejects_bad_private_layers),
	KUNIT_CASE(pkm_lcs_kunit_open_component_walk_symlink_fails_closed),
	{ }
};

static struct kunit_suite pkm_lcs_kunit_suite = {
	.name = "pkm_lcs_kunit_scaffold",
	.test_cases = pkm_lcs_kunit_cases,
};

kunit_test_suite(pkm_lcs_kunit_suite);
