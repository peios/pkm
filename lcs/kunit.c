// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/anon_inodes.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/unaligned.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "../kmes/kmes.h"
#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"
#include "transaction_fd.h"

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
	u64 expected_txn_id;
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
	u64 expected_txn_id;
	bool volatile_key;
	bool symlink;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_transaction_source_script {
	struct file *file;
	u16 expected_op_code;
	u32 expected_mode;
	u32 status;
	u64 expected_header_txn_id;
	u64 expected_payload_txn_id;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_set_security_source_script {
	struct file *file;
	struct pkm_lcs_kunit_transaction_source_script begin;
	const u8 *expected_guid;
	const u8 *existing_sd;
	size_t existing_sd_len;
	const u8 *expected_merged_sd;
	size_t expected_merged_sd_len;
	u64 expected_txn_id;
	u64 observed_last_write_time;
	u32 reads;
	u32 writes;
	bool expect_begin;
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
	u64 expected_txn_id;
	bool query_all;
	bool include_blanket;
	const char *blanket_layer_name;
	u64 blanket_sequence;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_set_value_source_script {
	struct file *file;
	const u8 *expected_guid;
	const char *expected_value_name;
	const char *expected_layer_name;
	const u8 *expected_data;
	size_t expected_data_len;
	u32 expected_value_type;
	u64 expected_txn_id;
	u64 expected_sequence;
	u64 expected_expected_sequence;
	u32 status;
	bool extra_response_payload;
	u32 reads;
	u32 writes;
	int result;
};

struct pkm_lcs_kunit_set_value_ioctl_source_script {
	struct file *file;
	struct pkm_lcs_kunit_transaction_source_script begin;
	const u8 *expected_guid;
	const char *expected_value_name;
	const char *expected_layer_name;
	const u8 *expected_data;
	size_t expected_data_len;
	u64 expected_query_txn_id;
	u64 expected_txn_id;
	u32 expected_value_type;
	u64 expected_sequence;
	u64 expected_expected_sequence;
	u32 set_value_status;
	u64 observed_last_write_time;
	u32 reads;
	u32 writes;
	bool expect_begin;
	int result;
};

struct pkm_lcs_kunit_enum_children_source_script {
	struct file *file;
	const u8 *expected_parent_guid;
	const char *child_name;
	const char *layer_name;
	const u8 *child_guid;
	u64 sequence;
	bool hidden;
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
	PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN = 4,
};

struct pkm_lcs_kunit_symlink_sequence_op {
	enum pkm_lcs_kunit_symlink_sequence_op_code op;
	const struct pkm_lcs_kunit_walk_source_step *lookup_step;
	const struct pkm_lcs_kunit_read_key_source_script *read_key;
	const struct pkm_lcs_kunit_enum_children_source_script *enum_children;
	const u8 *query_guid;
	const u8 *query_data;
	size_t query_data_len;
	u32 query_value_type;
	u64 expected_txn_id;
	bool query_all;
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
	u64 expected_txn_id;
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
	bool skip_read_key;
	int result;
};

static void pkm_lcs_kunit_setup_registered_source(struct kunit *test,
						  struct file *file,
						  const void **token_out);
static int pkm_lcs_kunit_walk_source_thread(void *raw_script);
static int pkm_lcs_kunit_read_key_source_thread(void *raw_script);
static int pkm_lcs_kunit_set_security_source_thread(void *raw_script);
static int pkm_lcs_kunit_query_values_source_thread(void *raw_script);
static int pkm_lcs_kunit_set_value_source_thread(void *raw_script);
static int pkm_lcs_kunit_set_value_ioctl_source_thread(void *raw_script);
static int pkm_lcs_kunit_enum_children_source_thread(void *raw_script);
static int pkm_lcs_kunit_symlink_follow_source_thread(void *raw_script);
static int pkm_lcs_kunit_symlink_sequence_source_thread(void *raw_script);
static int pkm_lcs_kunit_create_source_thread(void *raw_script);
static int pkm_lcs_kunit_transaction_source_thread(void *data);

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

static void pkm_lcs_kunit_flush_deferred_key_fd_release(void)
{
	/*
	 * KUnit closes fds through close_fd(), which uses deferred fput in
	 * kernel context. Flush it before tests assert release-time watch
	 * registry effects.
	 */
	task_work_run();
	flush_delayed_fput();
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

static long pkm_lcs_kunit_publish_key_fd_from_path(
	u32 source_id, u32 granted_access, const char * const *path,
	const u8 (*ancestors)[PKM_LCS_GUID_BYTES], u32 depth)
{
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = source_id,
		.granted_access = granted_access,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = depth,
	};

	if (!depth)
		return -EINVAL;
	memcpy(input.key_guid, ancestors[depth - 1U], sizeof(input.key_guid));
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

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, args.sd_len,
			(u32)sizeof(existing_owner_system_sd));
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, output[0], 0xaa);

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

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-get-sd-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_get_security((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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
	static const u8 value_data[] = { 4, 3, 2, 1 };
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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	args.data_ptr = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_query_value((int)allowed_fd,
							 &ops, &args),
			(long)-EFAULT);
	args.data_ptr = (u64)(unsigned long)data;

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-query-value-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-empty");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-value-batch-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_values_batch((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_query_values_source_thread, &script,
			   "pkm-lcs-kunit-enum-value-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_value((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-enum-subkey-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_enum_subkey((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-erange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, args.name_len, 8U);
	KUNIT_EXPECT_EQ(test, args.last_write_time, 0ULL);
	KUNIT_EXPECT_EQ(test, name[0], 0xaaU);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-fault");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_symlink_sequence_source_thread,
			   &script, "pkm-lcs-kunit-query-info-bad");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_query_key_info((int)fd, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_set_security_source_thread, &script,
			   "pkm-lcs-kunit-set-sd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)mutation_fd, &ops,
						&args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_set_security_source_thread, &script,
			   "pkm-lcs-kunit-set-sd-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_security((int)mutation_fd, &ops,
						&args);
	thread_ret = kthread_stop(task);

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
	task = kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-set-sd-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = kthread_stop(task);

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
	static const u8 data[] = { 0x2a, 0x00, 0x00, 0x00 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = strlen(value_name),
		.name_ptr = (u64)(unsigned long)value_name,
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

	task = kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-ioctl");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-txn");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = kthread_stop(task);

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
	task = kthread_run(pkm_lcs_kunit_transaction_source_thread,
			   &commit_script, "pkm-lcs-kunit-set-value-commit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = kthread_stop(task);

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

	task = kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-cas");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(
		(int)mutation_fd, admin_token, &ops, &args);
	thread_ret = kthread_stop(task);

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
	static const char overlay_name[] = "overlay";
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
	args.layer_len = strlen(overlay_name);
	args.layer_ptr = (u64)(unsigned long)overlay_name;
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

static u32 pkm_lcs_kunit_write_direct_watch_event(u8 *dst, size_t dst_len,
						  u32 event_type,
						  const char *name)
{
	size_t name_len = name ? strlen(name) : 0;
	u32 total_len;

	if (!dst || dst_len < 8 || name_len > U16_MAX ||
	    name_len + 8 > dst_len)
		return 0;

	total_len = (u32)(8 + name_len);
	put_unaligned_le32(total_len, dst);
	put_unaligned_le16((u16)event_type, dst + 4);
	put_unaligned_le16((u16)name_len, dst + 6);
	if (name_len)
		memcpy(dst + 8, name, name_len);
	return total_len;
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

static void pkm_lcs_kunit_begin_transaction_publishes_active_unbound(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_table_snapshot source_snapshot = { };
	long fd;

	pkm_lcs_kunit_reset_source_table();

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_NE(test, txn_snapshot.transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 0U);
	KUNIT_EXPECT_TRUE(test, txn_snapshot.timer_pending);

	pkm_lcs_kunit_source_table_snapshot(&source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.occupied_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.down_count, 0U);
	KUNIT_EXPECT_FALSE(test, source_snapshot.sequence_initialized);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_reset_source_table();
}

static void pkm_lcs_kunit_begin_transaction_ids_are_monotonic(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot first = { };
	struct pkm_lcs_transaction_fd_snapshot second = { };
	long first_fd;
	long second_fd;

	first_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, first_fd >= 0);
	second_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, second_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)first_fd, &first),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)second_fd,
							&second),
			0L);
	KUNIT_EXPECT_LT(test, first.transaction_id, second.transaction_id);
	KUNIT_EXPECT_EQ(test, first.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, second.state, REG_TXN_ACTIVE_UNBOUND);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first_fd), 0);
}

static void pkm_lcs_kunit_transaction_timeout_marks_timed_out(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	msleep(20);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_FALSE(test, snapshot.timer_pending);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_timeout_bound_aborts_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x76
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[64];
	struct file file = { };
	const void *token;
	ssize_t read_len;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	msleep(20);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_flush_timeout_work(
				(int)fd),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_FALSE(test, txn_snapshot.timer_pending);

	read_len = pkm_lcs_kunit_source_device_read_file(&file, out,
							 sizeof(out), true);
	KUNIT_ASSERT_EQ(test, read_len,
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
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

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_timeout_commit_in_flight_no_abort(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x77
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_transaction_fd_publish(1);
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_commit_in_flight(
				(int)fd, true),
			0L);

	msleep(20);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_flush_timeout_work(
				(int)fd),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_commit_in_flight(
				(int)fd, false),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
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

static void pkm_lcs_kunit_transaction_fd_rejects_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot snapshot = {
		.transaction_id = 99,
	};
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_publish(0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_snapshot(-1, &snapshot),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, snapshot.transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_snapshot(-1, NULL),
			(long)-EINVAL);

	fd = anon_inode_getfd("lcs-not-transaction",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_snapshot(fd, &snapshot),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_status_reports_active_state(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_status_reports_timeout_errno(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	msleep(20);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, ETIMEDOUT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_status_maps_terminal_errno(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ACTIVE_BOUND, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ABORTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_SOURCE_DOWN);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EIO);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, U32_MAX, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_status_rejects_bad_inputs(
	struct kunit *test)
{
	struct reg_txn_status_args status = {
		.state = 99,
		.terminal_errno = 99,
	};
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_status(-1, &status),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, status.state, 0U);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_status(-1, NULL),
			(long)-EINVAL);

	fd = anon_inode_getfd("lcs-not-transaction-status",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_status(fd, &status),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_commit_precheck_unbound_terminal(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_commit_precheck_timeout_source_down(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	msleep(20);

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_commit_active_bound_no_source_eio(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x71
	};
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 11,
				root_guid),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EIO);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_commit_active_bound_success(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-ok");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_FALSE(test, snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_commit_busy_retains_active_bound(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x73
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_TXN_BUSY;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-busy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EBUSY);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_TRUE(test, snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_commit_sync_eio_retains_active_bound(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x74
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_STORAGE_ERROR;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-eio");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_TRUE(test, snapshot.timer_pending);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_commit_rejects_bad_fds(
	struct kunit *test)
{
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit(-1),
			(long)-EBADF);

	fd = anon_inode_getfd("lcs-not-transaction-commit",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit(fd),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_close_active_unbound_no_source_abort(
	struct kunit *test)
{
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_close_active_bound_aborts_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x75
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[64];
	struct file file = { };
	const void *token;
	ssize_t read_len;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();

	read_len = pkm_lcs_kunit_source_device_read_file(&file, out,
							 sizeof(out), true);
	KUNIT_ASSERT_EQ(test, read_len,
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)read_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_snapshot.transaction_id);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 1ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_binding_precheck_and_complete(
	struct kunit *test)
{
	static const u8 machine_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x11
	};
	static const u8 users_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x22
	};
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, machine_root, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, plan.bound_source_id, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id + 1, 7,
				machine_root),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				machine_root),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.bound_root_guid, machine_root,
			       sizeof(snapshot.bound_root_guid)),
			0);

	memset(&plan, 0, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, machine_root, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, plan.bound_source_id, 7U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 8, machine_root, &plan),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, users_root, &plan),
			(long)-EXDEV);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_binding_terminal_failures(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x33
	};
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				root_guid),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_TIMED_OUT, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, root_guid, &plan),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				root_guid),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, root_guid, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				root_guid),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_binding_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 nil_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = { };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x44
	};
	struct pkm_lcs_transaction_binding_plan plan = {
		.action = 99,
	};
	long fd;
	int not_txn_fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 0, root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	plan.action = 99;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 1, nil_root, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 1, NULL, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 1, root_guid, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, 0, 1, root_guid),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, 1, 0, root_guid),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, 1, 1, nil_root),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				-1, 1, root_guid, &plan),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				-1, 1, 1, root_guid),
			(long)-EBADF);

	not_txn_fd = anon_inode_getfd("lcs-not-transaction-binding",
				     &pkm_lcs_kunit_non_key_fops, NULL,
				     O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_txn_fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				not_txn_fd, 1, root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				not_txn_fd, 1, 1, root_guid),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_read_context_active_states(
	struct kunit *test)
{
	static const u8 machine_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x55
	};
	static const u8 users_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x66
	};
	struct pkm_lcs_transaction_read_plan read = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, machine_root, &read),
			0L);
	KUNIT_EXPECT_EQ(test, read.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, read.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, read.bound_source_id, 0U);
	KUNIT_EXPECT_FALSE(test, read.use_transaction);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				machine_root),
			0L);
	memset(&read, 0, sizeof(read));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, machine_root, &read),
			0L);
	KUNIT_EXPECT_EQ(test, read.txn_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, read.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, read.bound_source_id, 7U);
	KUNIT_EXPECT_TRUE(test, read.use_transaction);
	KUNIT_EXPECT_EQ(test,
			memcmp(read.bound_root_guid, machine_root,
			       sizeof(read.bound_root_guid)),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 8, machine_root, &read),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, users_root, &read),
			(long)-EXDEV);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_read_context_terminal_failures(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x77
	};
	struct pkm_lcs_transaction_read_plan read = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_TIMED_OUT, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_read_context_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 nil_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = { };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x88
	};
	struct pkm_lcs_transaction_read_plan read = {
		.txn_id = 99,
		.use_transaction = true,
	};
	long fd;
	int not_txn_fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 0, root_guid, &read),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, read.txn_id, 0ULL);
	KUNIT_EXPECT_FALSE(test, read.use_transaction);
	read.txn_id = 99;
	read.use_transaction = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, nil_root, &read),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, read.txn_id, 0ULL);
	KUNIT_EXPECT_FALSE(test, read.use_transaction);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, NULL, &read),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, root_guid, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				-1, 1, root_guid, &read),
			(long)-EBADF);

	not_txn_fd = anon_inode_getfd("lcs-not-transaction-read",
				     &pkm_lcs_kunit_non_key_fops, NULL,
				     O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_txn_fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				not_txn_fd, 1, root_guid, &read),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_txn_fd), 0);
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

static void pkm_lcs_kunit_rsi_begin_transaction_request_frame_success(
	struct kunit *test)
{
	u8 frame[64];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + sizeof(u64) +
			      sizeof(u32);
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(frame, 0xcc, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				frame, sizeof(frame), 0x2122232425262728ULL, 0,
				0x0102030405060708ULL, RSI_TXN_READ_WRITE,
				&built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_BEGIN_TRANSACTION);

	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_ID_OFFSET),
			0x2122232425262728ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(frame + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(frame + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(frame + payload_offset),
			0x0102030405060708ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(frame + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_WRITE);
	for (i = expected_len; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xccU);
}

static void pkm_lcs_kunit_rsi_commit_abort_transaction_request_frames(
	struct kunit *test)
{
	u8 commit[64];
	u8 abort[64];
	struct pkm_lcs_rsi_built_request built = { };
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + sizeof(u64);
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	size_t i;

	memset(commit, 0xcc, sizeof(commit));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_commit_transaction_request(
				commit, sizeof(commit), 0x3132333435363738ULL,
				77, 77, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x3132333435363738ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 77ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(commit +
					   RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(commit +
					   RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(commit + RSI_REQUEST_TXN_ID_OFFSET),
			77ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(commit + payload_offset), 77ULL);
	for (i = expected_len; i < sizeof(commit); i++)
		KUNIT_EXPECT_EQ(test, commit[i], 0xccU);

	memset(&built, 0, sizeof(built));
	memset(abort, 0xdd, sizeof(abort));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_abort_transaction_request(
				abort, sizeof(abort), 0x4142434445464748ULL,
				88, 88, &built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, expected_len);
	KUNIT_EXPECT_EQ(test, built.request_id, 0x4142434445464748ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 88ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(abort + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(abort + RSI_REQUEST_TXN_ID_OFFSET),
			88ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(abort + payload_offset),
			88ULL);
	for (i = expected_len; i < sizeof(abort); i++)
		KUNIT_EXPECT_EQ(test, abort[i], 0xddU);
}

static void pkm_lcs_kunit_rsi_transaction_request_frames_reject_bad_inputs(
	struct kunit *test)
{
	u8 frame[64];
	struct pkm_lcs_rsi_built_request built = {
		.len = 11,
		.request_id = 22,
		.txn_id = 33,
		.op_code = 44,
	};
	size_t i;

	memset(frame, 0xaa, sizeof(frame));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				NULL, sizeof(frame), 1, 0, 2,
				RSI_TXN_READ_WRITE, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);

	built.len = 11;
	built.request_id = 22;
	built.txn_id = 33;
	built.op_code = 44;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				frame, sizeof(frame), 1, 0, 2, 0x80, &built),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(frame); i++)
		KUNIT_EXPECT_EQ(test, frame[i], 0xaaU);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_commit_transaction_request(
				frame, sizeof(frame), 1, 1, 1, NULL),
			(long)-EINVAL);
}

static void pkm_lcs_kunit_rsi_transaction_request_frames_reject_short_buffer(
	struct kunit *test)
{
	u8 begin[RSI_REQUEST_HEADER_SIZE + sizeof(u64) + sizeof(u32) - 1];
	u8 commit[RSI_REQUEST_HEADER_SIZE + sizeof(u64) - 1];
	struct pkm_lcs_rsi_built_request built = {
		.len = 11,
		.request_id = 22,
		.txn_id = 33,
		.op_code = 44,
	};
	size_t i;

	memset(begin, 0xaa, sizeof(begin));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_begin_transaction_request(
				begin, sizeof(begin), 1, 0, 2,
				RSI_TXN_READ_ONLY, &built),
			(long)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(begin); i++)
		KUNIT_EXPECT_EQ(test, begin[i], 0xaaU);

	built.len = 11;
	built.request_id = 22;
	built.txn_id = 33;
	built.op_code = 44;
	memset(commit, 0xbb, sizeof(commit));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_build_commit_transaction_request(
				commit, sizeof(commit), 1, 1, 1, &built),
			(long)-EMSGSIZE);
	KUNIT_EXPECT_EQ(test, built.len, (size_t)0);
	KUNIT_EXPECT_EQ(test, built.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)0);
	for (i = 0; i < sizeof(commit); i++)
		KUNIT_EXPECT_EQ(test, commit[i], 0xbbU);
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
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_txn_id)
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
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_txn_id)
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
		if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id) {
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
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
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

static int pkm_lcs_kunit_set_security_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_set_security_source_script *script = raw_script;
	struct pkm_lcs_kunit_read_key_source_script read_script = { };
	size_t read_expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t write_expected_len;
	size_t response_len = 0;
	size_t payload_offset;
	size_t field_mask_offset;
	size_t sd_offset;
	size_t last_write_offset;
	u8 request[512];
	u8 response[512];
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->existing_sd || !script->existing_sd_len ||
	    !script->expected_merged_sd || !script->expected_merged_sd_len) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
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
	if ((size_t)count != read_expected_len) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	read_script.expected_guid = script->expected_guid;
	read_script.name = "Software";
	read_script.sd = script->existing_sd;
	read_script.sd_len = script->existing_sd_len;
	ret = pkm_lcs_kunit_read_key_source_build_response(
		&read_script, request_id, response, sizeof(response),
		&response_len);
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

	write_expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
			     sizeof(u32) + RSI_LENGTH_PREFIX_SIZE +
			     script->expected_merged_sd_len + sizeof(u64);
	if ((size_t)count != write_expected_len) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	if (memcmp(request + payload_offset, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	field_mask_offset = payload_offset + RSI_GUID_SIZE;
	if (get_unaligned_le32(request + field_mask_offset) !=
	    (u32)(RSI_WRITE_KEY_FIELD_SD |
		  RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)) {
		script->result = -EINVAL;
		return script->result;
	}
	sd_offset = field_mask_offset + sizeof(u32);
	if (get_unaligned_le32(request + sd_offset) !=
	    script->expected_merged_sd_len ||
	    memcmp(request + sd_offset + RSI_LENGTH_PREFIX_SIZE,
		   script->expected_merged_sd,
		   script->expected_merged_sd_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	last_write_offset = sd_offset + RSI_LENGTH_PREFIX_SIZE +
			    script->expected_merged_sd_len;
	script->observed_last_write_time =
		get_unaligned_le64(request + last_write_offset);
	if (!script->observed_last_write_time) {
		script->result = -EINVAL;
		return script->result;
	}

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	response_len = RSI_MIN_RESPONSE_SIZE;
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

	if (!script->skip_read_key) {
		ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
		script->reads = script->read_key.reads;
		script->writes = script->read_key.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
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
	struct pkm_lcs_kunit_walk_source_script parent_walk;
	struct pkm_lcs_kunit_read_then_create_source_script create;
	u32 reads;
	u32 writes;
	bool wait_for_stop_after_completion;
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

	if (script->parent_walk.step_count) {
		script->parent_walk.file = script->file;
		ret = pkm_lcs_kunit_walk_source_thread(&script->parent_walk);
		script->reads += script->parent_walk.reads;
		script->writes += script->parent_walk.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	script->create.file = script->file;
	ret = pkm_lcs_kunit_read_then_create_source_thread(&script->create);
	script->reads += script->create.reads;
	script->writes += script->create.writes;
	script->result = ret ? ret : script->create.result;
	if (script->wait_for_stop_after_completion) {
		while (!kthread_should_stop())
			msleep(1);
	}
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
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
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

static int pkm_lcs_kunit_set_value_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_set_value_source_script *script = raw_script;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[256];
	size_t response_len;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_layer_name || !script->expected_value_name) {
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
	if ((size_t)count < offset + RSI_GUID_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_SET_VALUE ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name,
		   field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset ||
	    get_unaligned_le32(request + offset) !=
		    script->expected_value_type) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += sizeof(u32);

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != script->expected_data_len ||
	    (field_len && memcmp(request + offset, script->expected_data,
				 field_len))) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u64) * 2U > (size_t)count - offset ||
	    get_unaligned_le64(request + offset) !=
		    script->expected_sequence ||
	    get_unaligned_le64(request + offset + sizeof(u64)) !=
		    script->expected_expected_sequence) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += sizeof(u64) * 2U;
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}

	response_len = RSI_MIN_RESPONSE_SIZE;
	if (script->extra_response_payload)
		response_len += sizeof(u32);
	memset(response, 0, sizeof(response));
	put_unaligned_le32((u32)response_len,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_SET_VALUE_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload)
		put_unaligned_le32(0xabcdef01U,
				   response + RSI_MIN_RESPONSE_SIZE);

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

static ssize_t pkm_lcs_kunit_set_value_ioctl_source_read(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
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

static int pkm_lcs_kunit_set_value_ioctl_source_write_status(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u64 request_id, u16 request_op, u32 status)
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
	if (count != (ssize_t)sizeof(response))
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}

static int pkm_lcs_kunit_set_value_ioctl_source_write_empty_values(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u64 request_id)
{
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32) * 2U];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	if (pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						 &offset, 0) ||
	    pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						 &offset, 0))
		return -EMSGSIZE;
	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}

static int pkm_lcs_kunit_set_value_ioctl_source_handle_query(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;

	count = pkm_lcs_kunit_set_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_query_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || value_len > (size_t)count - offset ||
	    value_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, value_len))
		return -EINVAL;
	offset += value_len;
	if (offset >= (size_t)count || request[offset] != 0)
		return -EINVAL;
	offset++;
	if (offset != (size_t)count)
		return -EINVAL;

	return pkm_lcs_kunit_set_value_ioctl_source_write_empty_values(
		script, request_id);
}

static int pkm_lcs_kunit_set_value_ioctl_source_handle_set_value(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len, bool *continue_after_set)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;
	int ret;

	*continue_after_set = false;
	count = pkm_lcs_kunit_set_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + RSI_GUID_SIZE)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_SET_VALUE ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, field_len))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name, field_len))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset ||
	    get_unaligned_le32(request + offset) !=
		    script->expected_value_type)
		return -EINVAL;
	offset += sizeof(u32);

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != script->expected_data_len ||
	    (field_len && memcmp(request + offset, script->expected_data,
				 field_len)))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u64) * 2U > (size_t)count - offset ||
	    get_unaligned_le64(request + offset) !=
		    script->expected_sequence ||
	    get_unaligned_le64(request + offset + sizeof(u64)) !=
		    script->expected_expected_sequence)
		return -EINVAL;
	offset += sizeof(u64) * 2U;
	if (offset != (size_t)count)
		return -EINVAL;

	ret = pkm_lcs_kunit_set_value_ioctl_source_write_status(
		script, request_id, request_op, script->set_value_status);
	if (ret)
		return ret;
	*continue_after_set = script->set_value_status == RSI_OK;
	return 0;
}

static int pkm_lcs_kunit_set_value_ioctl_source_handle_write_key(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_mask;
	int ret;

	count = pkm_lcs_kunit_set_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
				     sizeof(u32) + sizeof(u64))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	field_mask = get_unaligned_le32(request + offset);
	if (field_mask != RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)
		return -EINVAL;
	offset += sizeof(u32);
	script->observed_last_write_time = get_unaligned_le64(request + offset);
	if (!script->observed_last_write_time)
		return -EINVAL;

	ret = pkm_lcs_kunit_set_value_ioctl_source_write_status(
		script, request_id, request_op, RSI_OK);
	if (ret)
		return ret;
	script->result = 0;
	return 0;
}

static int pkm_lcs_kunit_set_value_ioctl_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script = raw_script;
	bool continue_after_set = false;
	u8 request[256];
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_value_name || !script->expected_layer_name ||
	    (script->expected_data_len && !script->expected_data)) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_query(
		script, request, sizeof(request));
	if (ret)
		goto out;
	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret)
			goto out;
	}
	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_set_value(
		script, request, sizeof(request), &continue_after_set);
	if (ret || !continue_after_set)
		goto out;
	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_write_key(
		script, request, sizeof(request));

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}

static int pkm_lcs_kunit_enum_children_source_build_response(
	const struct pkm_lcs_kunit_enum_children_source_script *script,
	u64 request_id, u8 *response, size_t response_len, size_t *built_len)
{
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	const char *child_name;
	const char *layer_name;
	const u8 *target_guid;
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = RSI_ENUM_CHILDREN | RSI_RESPONSE_BIT;
	u8 target_type;

	if (!script || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	child_name = script->child_name ? script->child_name : "Child";
	layer_name = script->layer_name ? script->layer_name : "base";
	target_guid = script->hidden ? hidden_guid : script->child_guid;
	target_type = script->hidden ? RSI_PATH_TARGET_HIDDEN :
				       RSI_PATH_TARGET_GUID;
	if (!target_guid)
		return -EINVAL;

	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	if (pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						 &offset, 1))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append_len_prefixed(
		    response, response_len, &offset, child_name,
		    strlen(child_name)))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						 &offset, 1))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append_len_prefixed(
		    response, response_len, &offset, layer_name,
		    strlen(layer_name)))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append_u8(response, response_len,
						&offset, target_type))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append(response, response_len, &offset,
					     target_guid, RSI_GUID_SIZE))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append_u64(response, response_len,
						 &offset, script->sequence))
		return -EMSGSIZE;
	if (pkm_lcs_kunit_walk_source_append_u32(
		    response, response_len, &offset, script->hidden ? 0U : 1U))
		return -EMSGSIZE;
	if (!script->hidden) {
		if (pkm_lcs_kunit_walk_source_append(
			    response, response_len, &offset, target_guid,
			    RSI_GUID_SIZE))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, response_len, &offset,
			    pkm_lcs_kunit_owner_only_sd,
			    sizeof(pkm_lcs_kunit_owner_only_sd)))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append_u8(response, response_len,
							&offset, 0) ||
		    pkm_lcs_kunit_walk_source_append_u8(response, response_len,
							&offset, 0) ||
		    pkm_lcs_kunit_walk_source_append_u64(response,
							 response_len,
							 &offset, 1000))
			return -EMSGSIZE;
	}
	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}

static int pkm_lcs_kunit_enum_children_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_enum_children_source_script *script = raw_script;
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE];
	u8 response[256];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!script || !script->file || !script->expected_parent_guid) {
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
	if (count != (ssize_t)sizeof(request)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_ENUM_CHILDREN ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE,
		   script->expected_parent_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_enum_children_source_build_response(
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
	if (request_op != RSI_LOOKUP ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id)
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
		.query_all = op->query_all,
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
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, op->query_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset || value_len)
		return -EINVAL;
	value_offset += value_len;
	if (value_offset >= (size_t)count ||
	    request[value_offset] != (op->query_all ? 1 : 0))
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
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id ||
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

static int pkm_lcs_kunit_symlink_sequence_handle_enum_children(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	const struct pkm_lcs_kunit_enum_children_source_script *enum_children =
		op->enum_children;
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!enum_children || !enum_children->expected_parent_guid)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != expected_len)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_ENUM_CHILDREN ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE,
		   enum_children->expected_parent_guid, RSI_GUID_SIZE))
		return -EINVAL;

	ret = pkm_lcs_kunit_enum_children_source_build_response(
		enum_children, request_id, response, response_len, &built_len);
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
		case PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN:
			ret = pkm_lcs_kunit_symlink_sequence_handle_enum_children(
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
	KUNIT_EXPECT_EQ(test, result.layer_len, 4U);
	KUNIT_ASSERT_NOT_NULL(test, result.layer);
	KUNIT_EXPECT_EQ(test, memcmp(result.layer, "base", 4), 0);
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

static void pkm_lcs_kunit_rsi_enum_children_info_summary(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 alpha_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 beta_guid[RSI_GUID_SIZE] = { 0xb1 };
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xc1 };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_rsi_built_request built = { };
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE];
	u8 response[512];
	size_t offset;
	size_t response_len;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_enum_children_request(
				request, sizeof(request), 51, 0, parent_guid,
				&built),
			0L);
	KUNIT_EXPECT_EQ(test, built.len, sizeof(request));
	KUNIT_EXPECT_EQ(test, built.request_id, 51ULL);
	KUNIT_EXPECT_EQ(test, built.op_code, (u16)RSI_ENUM_CHILDREN);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + RSI_REQUEST_HEADER_SIZE, parent_guid,
			       RSI_GUID_SIZE),
			0);

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 built.request_id,
					 RSI_ENUM_CHILDREN_RESPONSE, RSI_OK,
					 &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "Alpha", 5);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, alpha_guid, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "BetaLong", 8);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, beta_guid, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "overlay",
		RSI_PATH_TARGET_HIDDEN, hidden_guid, 2);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 2);
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, alpha_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_append_lookup_metadata(
		test, response, sizeof(response), &offset, beta_guid,
		pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd));
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_enum_children_info_summary(
				response, response_len, built.request_id, 3,
				layers, ARRAY_SIZE(layers), NULL, 0,
				&summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.source_path_entry_count, 3U);
	KUNIT_EXPECT_EQ(test, summary.subkey_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.max_subkey_name_len, 5U);
}

static void pkm_lcs_kunit_rsi_query_values_info_summary(struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
		{ .name = "overlay", .name_len = 7, .precedence = 10,
		  .enabled = 1 },
	};
	static const u8 data[] = { 1, 2, 3 };
	static const u8 bigger_data[] = { 1, 2, 3, 4, 5, 6 };
	static const u8 tombstone_data = 0;
	struct pkm_lcs_rsi_query_values_info_summary summary = { };
	u8 response[512];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 52, RSI_QUERY_VALUES_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 3);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "One", "base",
		REG_BINARY, data, sizeof(data), 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "SecondLong",
		"base", REG_BINARY, bigger_data, sizeof(bigger_data), 1);
	pkm_lcs_kunit_rsi_append_query_value_entry(
		test, response, sizeof(response), &offset, "SecondLong",
		"overlay", REG_TOMBSTONE, &tombstone_data, 0, 2);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_query_values_info_summary(
				response, response_len, 52, 3, layers,
				ARRAY_SIZE(layers), NULL, 0, &summary),
			0L);
	KUNIT_EXPECT_EQ(test, summary.source_value_entry_count, 3U);
	KUNIT_EXPECT_EQ(test, summary.source_blanket_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.value_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.max_value_name_len, 3U);
	KUNIT_EXPECT_EQ(test, summary.max_value_data_size, (u32)sizeof(data));
}

static void pkm_lcs_kunit_rsi_enum_children_info_rejects_bad_metadata(
	struct kunit *test)
{
	static const struct pkm_lcs_rsi_layer_view layers[] = {
		{ .name = "base", .name_len = 4, .precedence = 0,
		  .enabled = 1 },
	};
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xd1 };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	u8 response[256];
	size_t offset;
	size_t response_len;

	pkm_lcs_kunit_rsi_response_begin(test, response, sizeof(response),
					 53, RSI_ENUM_CHILDREN_RESPONSE,
					 RSI_OK, &offset);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, response, sizeof(response), &offset, "Child", 5);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 1);
	pkm_lcs_kunit_rsi_append_lookup_path_entry(
		test, response, sizeof(response), &offset, "base",
		RSI_PATH_TARGET_GUID, child_guid, 1);
	pkm_lcs_kunit_rsi_append_u32(test, response, sizeof(response),
				     &offset, 0);
	pkm_lcs_kunit_rsi_finish_response(test, response, offset,
					  &response_len);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_rsi_materialize_enum_children_info_summary(
				response, response_len, 53, 2, layers,
				ARRAY_SIZE(layers), NULL, 0, &summary),
			(long)-EIO);
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
		.sequence = 1,
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
	task = kthread_run(pkm_lcs_kunit_enum_children_source_thread,
			   &script, "pkm-lcs-kunit-enum-children");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout(
				1, 0, parent_guid,
				PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, &frame,
				&response, &enqueue),
			0L);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, response.request_op_code,
			(u16)RSI_ENUM_CHILDREN);
	KUNIT_ASSERT_NOT_NULL(test, frame.data);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_materialize_enum_children_info_summary(
				frame.data, frame.len, response.request_id, 2,
				layers, ARRAY_SIZE(layers), NULL, 0,
				&summary),
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
	task = kthread_run(pkm_lcs_kunit_set_value_source_thread, &script,
			   "pkm-lcs-kunit-set-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_value_round_trip_timeout(
		1, script.expected_txn_id, guid, value_name,
		strlen(value_name), layer_name, strlen(layer_name),
		REG_BINARY, data, sizeof(data), script.expected_sequence,
		script.expected_expected_sequence, 1000, &response, &enqueue);
	thread_ret = kthread_stop(task);
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
	task = kthread_run(pkm_lcs_kunit_set_value_source_thread, &script,
			   "pkm-lcs-kunit-set-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_value_round_trip_timeout(
		1, script.expected_txn_id, guid, value_name,
		strlen(value_name), layer_name, strlen(layer_name),
		REG_BINARY, data, sizeof(data), script.expected_sequence,
		script.expected_expected_sequence, 1000, &response, &enqueue);
	thread_ret = kthread_stop(task);
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
	task = kthread_run(pkm_lcs_kunit_set_value_source_thread, &script,
			   "pkm-lcs-kunit-set-value-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_source_set_value_round_trip_timeout(
		1, script.expected_txn_id, guid, "", 0, layer_name,
		strlen(layer_name), REG_TOMBSTONE, NULL, 0,
		script.expected_sequence, script.expected_expected_sequence,
		1000, &response, &enqueue);
	thread_ret = kthread_stop(task);
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

static int pkm_lcs_kunit_transaction_source_thread(void *data)
{
	struct pkm_lcs_kunit_transaction_source_script *script = data;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[64];
	size_t response_len;
	ssize_t count;
	u64 request_id;

	if (!script || !script->file) {
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

	if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    script->expected_op_code) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_header_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + payload_offset) !=
	    script->expected_payload_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->expected_op_code == RSI_BEGIN_TRANSACTION) {
		if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64) +
			    (ssize_t)sizeof(u32)) {
			script->result = -EINVAL;
			return script->result;
		}
		if (get_unaligned_le32(request + payload_offset +
				       sizeof(u64)) != script->expected_mode) {
			script->result = -EINVAL;
			return script->result;
		}
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(script->expected_op_code | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	response_len = RSI_MIN_RESPONSE_SIZE;
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = (int)count;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}

struct pkm_lcs_kunit_txn_create_flow_source_script {
	struct file *file;
	struct pkm_lcs_kunit_walk_source_script walk;
	struct pkm_lcs_kunit_read_key_source_script read_key;
	struct pkm_lcs_kunit_transaction_source_script begin;
	struct pkm_lcs_kunit_create_source_script create;
	struct pkm_lcs_kunit_walk_source_script retry_walk;
	bool expect_begin;
	bool expect_create;
	bool expect_retry_walk;
	u32 reads;
	u32 writes;
	int result;
};

static int pkm_lcs_kunit_txn_create_flow_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_txn_create_flow_source_script *script =
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

	script->read_key.file = script->file;
	ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
	script->reads += script->read_key.reads;
	script->writes += script->read_key.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	if (script->expect_create) {
		script->create.file = script->file;
		ret = pkm_lcs_kunit_create_source_thread(&script->create);
		script->reads += script->create.reads;
		script->writes += script->create.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	if (script->expect_retry_walk) {
		script->retry_walk.file = script->file;
		ret = pkm_lcs_kunit_walk_source_thread(&script->retry_walk);
		script->reads += script->retry_walk.reads;
		script->writes += script->retry_walk.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	script->result = 0;
	return 0;
}

static void pkm_lcs_kunit_run_transaction_source_round_trip(
	struct kunit *test,
	struct pkm_lcs_kunit_transaction_source_script *script,
	long (*round_trip)(u32 source_id, u64 transaction_id,
			   struct pkm_lcs_source_response_result *response,
			   struct pkm_lcs_source_enqueue_result *enqueue),
	u64 transaction_id, long expected_ret,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct task_struct *task;
	int thread_ret;
	long ret;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, script,
			   "pkm-lcs-kunit-txn-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = round_trip(1, transaction_id, response, enqueue);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, expected_ret);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script->result, 0);
	KUNIT_EXPECT_EQ(test, script->reads, 1U);
	KUNIT_EXPECT_EQ(test, script->writes, 1U);
}

static long pkm_lcs_kunit_commit_round_trip_default(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_commit_transaction_round_trip(
		source_id, transaction_id, response, enqueue);
}

static long pkm_lcs_kunit_begin_readwrite_round_trip_default(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_begin_transaction_round_trip(
		source_id, transaction_id, RSI_TXN_READ_WRITE, response,
		enqueue);
}

static long pkm_lcs_kunit_abort_round_trip_default(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_abort_transaction_round_trip(
		source_id, transaction_id, response, enqueue);
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

static void pkm_lcs_kunit_late_begin_success_enqueues_abort_cleanup(
	struct kunit *test)
{
	const u64 txn_id = 0x6162636465666768ULL;
	struct pkm_lcs_source_response_result begin_response = { };
	struct pkm_lcs_source_response_result abort_response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_begin_transaction_round_trip_timeout(
				1, txn_id, RSI_TXN_READ_WRITE, 1,
				&begin_response, &enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, begin_response.len, (size_t)0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_id);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_WRITE);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&begin_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, begin_response.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, begin_response.txn_id, txn_id);
	KUNIT_EXPECT_EQ(test, begin_response.source_id, 1U);
	KUNIT_EXPECT_EQ(test, begin_response.request_op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, begin_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, begin_response.caller_waiter_attached);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET),
			1ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_id);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    1ULL, RSI_ABORT_TRANSACTION,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&abort_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, abort_response.request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, abort_response.txn_id, txn_id);
	KUNIT_EXPECT_EQ(test, abort_response.request_op_code,
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, abort_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, abort_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, abort_response.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_append_one_create_log(struct kunit *test, int fd,
						const u8 root_guid[16],
						u64 sequence)
{
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xa1
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xa2
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0xa0 },
		{ 0xa1 },
	};
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "LateCommit",
		.child_name_len = 10,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = sequence,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				fd, 1, root_guid, &input, &handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
}

static void pkm_lcs_kunit_transaction_commit_generation_success(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);
	KUNIT_EXPECT_EQ(test, generation_before, 0ULL);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xe5);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-gen");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_COMMITTED);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_commit_dispatches_create_watch(
	struct kunit *test)
{
	static const char child_name[] = "TxnChild";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xb2
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xb3
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xb2 },
	};
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 0xee,
	};
	u8 direct[32] = { };
	u8 subtree[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long parent_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)-EAGAIN);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)16);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 16U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 8U);
	KUNIT_EXPECT_EQ(test, memcmp(direct + 8, child_name,
				     sizeof(child_name) - 1U), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)26);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 26U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 8U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 8, child_name,
				     sizeof(child_name) - 1U), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 16), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 18), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 20, "Parent", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_commit_dispatches_sd_watch(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const target_path[] = { "Machine", "Target" };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 target_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xc2
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 target_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xc2 },
	};
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SD,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SD,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_set_security_log_input input = {
		.key_guid = target_guid,
		.path = target_path,
		.ancestor_guids = target_ancestors,
		.depth = 2,
	};
	u8 direct[16] = { };
	u8 subtree[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long target_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	target_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, target_path, target_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, target_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)target_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)target_fd, direct,
						  sizeof(direct), true),
			(ssize_t)-EAGAIN);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-sd-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)target_fd, direct,
						  sizeof(direct), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)18);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 18U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 0U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 8), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 10), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 12, "Target", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)target_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_commit_generation_overflow_downs_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_set(
				1, root_guid, ~0ULL),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xe6);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-gen-oflow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_SOURCE_DOWN);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_commit_timeout_late_response(
	struct kunit *test, u32 status)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 request_id;
	size_t response_len;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
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
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xa5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_FALSE(test, txn_snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	request_id = get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_snapshot.transaction_id);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    status, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id,
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response_result.status, status);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	if (status == RSI_OK)
		KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	else
		KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_commit_timeout_late_success_consumes_log(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_late_response(test, RSI_OK);
}

static void pkm_lcs_kunit_commit_timeout_late_error_discards_log(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_late_response(test, RSI_STORAGE_ERROR);
}

static void pkm_lcs_kunit_commit_timeout_closed_fd_late_response(
	struct kunit *test, u32 status)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 transaction_id;
	u64 request_id;
	size_t response_len;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	transaction_id = txn_snapshot.transaction_id;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, transaction_id, 1, root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xb5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	request_id = get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			transaction_id);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			1U);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    status, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id, transaction_id);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	if (status == RSI_OK)
		KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	else
		KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.state,
			PKM_LCS_SOURCE_FD_ACTIVE);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_commit_timeout_closed_fd_late_success(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_closed_fd_late_response(test, RSI_OK);
}

static void pkm_lcs_kunit_commit_timeout_closed_fd_late_error(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_closed_fd_late_response(
		test, RSI_STORAGE_ERROR);
}

static void pkm_lcs_kunit_commit_timeout_closed_fd_source_teardown(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 out[64];
	struct file file = { };
	const void *token;
	long fd;
	u32 count = 0;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
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
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xc5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.state, 0);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_commit_timeout_malformed_late_response_downs_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_fd_snapshot = { };
	struct pkm_lcs_source_table_snapshot source_table_snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	u64 request_id;
	size_t response_len;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
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
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xd5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	request_id = get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    0x80000000U, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(long)-EIO);
	KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_fd_snapshot);
	KUNIT_EXPECT_TRUE(test, source_fd_snapshot.closing);
	pkm_lcs_kunit_source_table_snapshot(&source_table_snapshot);
	KUNIT_EXPECT_EQ(test, source_table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, source_table_snapshot.down_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_bind_for_mutation_success_and_reuse(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x51
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-bind-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_bind_for_mutation((int)fd, 1, root_guid,
						      &plan);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, plan.bound_source_id, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.bound_root_guid, root_guid,
			       sizeof(snapshot.bound_root_guid)),
			0);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_bind_for_mutation(
				(int)fd, 1, root_guid, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_BOUND);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_bind_for_mutation_source_failure_rolls_back(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x52
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_TXN_NOT_SUPPORTED;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-bind-unsupported");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_bind_for_mutation((int)fd, 1, root_guid,
						      &plan);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_bind_for_mutation_counter_cap(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x53
	};
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < 16U; i++)
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_bound_transaction_acquire(
					1, &count),
				0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_bind_for_mutation(
				(int)fd, 1, root_guid, &plan),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	for (i = 0; i < 16U; i++)
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_bound_transaction_release(
					1, &count),
				0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_log_key_create_first_bind_and_reuse(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x56
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x57
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x58
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x56 },
		{ 0x57 },
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "policy",
		.layer_len = 6,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 100,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_OK;

	task = kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-log-bind");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_begin_key_create_mutation(
		(int)fd, 1, root_guid, &input, &handle, &binding);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_TRUE(test, handle.active);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.capacity,
			(u32)PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 100ULL);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "App");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "policy");

	input.child_name = "Svc";
	input.child_name_len = 3;
	input.sequence = 101;
	memset(&binding, 0, sizeof(binding));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 2U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 3ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 101ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Svc");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_transaction_log_cancel_does_not_publish(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x59
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5a
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5b
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x59 },
		{ 0x5a },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 7,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_TRUE(test, handle.active);
	pkm_lcs_transaction_fd_cancel_mutation(&handle);
	KUNIT_EXPECT_FALSE(test, handle.active);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5c
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5d
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5e
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x5c },
		{ 0x5d },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 11,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_log_capacity(
				(int)fd, 1),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.capacity, 1U);

	input.sequence = 12;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-ENOMEM);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 11ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_log_rejects_bad_create_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5f
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x60
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x61
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x5f },
		{ 0x62 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = mismatched_ancestors,
		.parent_depth = 2,
		.sequence = 13,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_log_set_security_records_context(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x63
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x64
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x63 },
		{ 0x64 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_security_log_input input = {
		.key_guid = key_guid,
		.path = path,
		.ancestor_guids = ancestors,
		.depth = 2,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_TRUE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_log_rejects_bad_set_security_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x65
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x66
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x65 },
		{ 0x67 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_security_log_input input = {
		.key_guid = key_guid,
		.path = path,
		.ancestor_guids = mismatched_ancestors,
		.depth = 2,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_log_set_value_records_context(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x68
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x69
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x68 },
		{ 0x69 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_value_log_input input = {
		.key_guid = key_guid,
		.value_name = NULL,
		.value_name_len = 0,
		.layer = "base",
		.layer_len = 4,
		.path = path,
		.ancestor_guids = ancestors,
		.depth = 2,
		.sequence = 17,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_TRUE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 17ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_lcs_kunit_transaction_log_rejects_bad_set_value_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6a
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6b
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x6a },
		{ 0x6c },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_value_log_input input = {
		.key_guid = key_guid,
		.value_name = "Answer",
		.value_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.path = path,
		.ancestor_guids = mismatched_ancestors,
		.depth = 2,
		.sequence = 18,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
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

static void pkm_lcs_kunit_reg_create_key_missing_dispatches_watch(
	struct kunit *test)
{
	static const char path_src[] = "Machine\\Parent\\App";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 root_ancestors[1][PKM_LCS_GUID_BYTES] = { { 1 } };
	static const u8 parent_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x61 },
	};
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x96 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "Parent",
			.guid = parent_ancestors[1],
			.sd = pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read,
			.sd_len =
				sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read),
		},
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const struct pkm_lcs_kunit_walk_source_step parent_steps[] = {
		{
			.expected_child = "Parent",
			.guid = parent_ancestors[1],
			.sd = pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read,
			.sd_len =
				sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read),
		},
	};
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
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
		.parent_walk = {
			.steps = parent_steps,
			.step_count = ARRAY_SIZE(parent_steps),
		},
		.create = {
			.skip_read_key = true,
			.create = {
				.parent_guid = parent_ancestors[1],
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
		.wait_for_stop_after_completion = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u8 direct[32] = { };
	u8 subtree[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	long root_fd;
	long parent_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_walk_then_read_create_source_thread,
			   &script, "pkm-lcs-kunit-create-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_for_token(
		token, &ops, -1, (const char __user *)path_src, KEY_READ,
		NULL, 0, &inputs, (u32 __user *)&disposition);
	thread_ret = kthread_stop(task);

	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)11);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 11U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 3U);
	KUNIT_EXPECT_EQ(test, memcmp(direct + 8, "App", 3), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)21);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 21U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 3U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 8, "App", 3), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 11), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 13), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 15, "Parent", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
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

static void pkm_lcs_kunit_reg_create_key_args_copy_success_and_fault(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_create_key_args src = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
	};
	struct reg_create_key_args dst = { };

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, (const void __user *)&src, &dst),
			0L);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, dst.parent_fd, -1);
	KUNIT_EXPECT_EQ(test, dst.path_ptr, src.path_ptr);
	KUNIT_EXPECT_EQ(test, dst.desired_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, dst.txn_fd, -1);

	ctx.fault_src = &src;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, (const void __user *)&src, &dst),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_copy_from_user(
				&ops, NULL, &dst),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, ctx.reads, 2U);
}

static void pkm_lcs_kunit_reg_create_key_args_rejects_padding(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		._pad0 = 1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(NULL, &ops, &args,
							      NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}

static void pkm_lcs_kunit_reg_create_key_args_existing_txn_reads(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const char path_src[] = "Machine";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_key_fd_snapshot snapshot = { };
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
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	sd = kacs_rust_kunit_create_file_sd(token, KEY_READ, 0, 0, 0,
					    &sd_len);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	script.file = &file;
	script.sd = sd;
	script.sd_len = sd_len;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	args.txn_fd = (int)txn_fd;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-txn-unbound");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	memset(&script, 0, sizeof(script));
	script.file = &file;
	script.expected_guid = root_guid;
	script.name = "Machine";
	script.sd = sd;
	script.sd_len = sd_len;
	script.expected_txn_id = txn_snapshot.transaction_id;
	disposition = 0;

	task = kthread_run(pkm_lcs_kunit_read_key_source_thread, &script,
			   "pkm-lcs-kunit-create-txn-bound");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
	thread_ret = kthread_stop(task);

	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_args_txn_failures(
	struct kunit *test)
{
	static const u8 other_root_guid[RSI_GUID_SIZE] = { 2 };
	static const char path_src[] = "Machine";
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct file file = { };
	const void *token;
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	int not_txn_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				other_root_guid),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)txn_fd, REG_TXN_COMMITTED, 0),
			0L);
	args.txn_fd = (int)txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);

	not_txn_fd = anon_inode_getfd("lcs-not-create-txn",
				     &pkm_lcs_kunit_non_key_fops, NULL,
				     O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_txn_fd >= 0);
	args.txn_fd = not_txn_fd;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_txn_fd), 0);

	args.txn_fd = INT_MAX;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(token, &ops,
							      &args, NULL),
			(long)-EBADF);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_args_txn_missing_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x94 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const char path_src[] = "Machine\\App";
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
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_header_txn_id = 0,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
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
		.expect_begin = true,
		.expect_create = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.create.expected_txn_id = txn_snapshot.transaction_id;
	args.txn_fd = (int)txn_fd;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_txn_create_flow_source_thread, &script,
			   "pkm-lcs-kunit-create-txn-missing");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						   &inputs);
	thread_ret = kthread_stop(task);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_CREATED_NEW);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 1U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 1U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
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
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 1ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "App");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, key_snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_STREQ(test, key_snapshot.last_component, "App");
	KUNIT_EXPECT_EQ(test,
			memcmp(key_snapshot.key_guid, child_candidates[0],
			       sizeof(key_snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_args_txn_missing_full_log(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x95 } };
	static const u8 warmup_guid[RSI_GUID_SIZE] = { 0x96 };
	static const char * const parent_path[] = { "Machine" };
	static const u8 parent_ancestors[1][RSI_GUID_SIZE] = { { 1 } };
	static const struct pkm_lcs_kunit_walk_source_step steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const char path_src[] = "Machine\\App";
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
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input log_input = {
		.parent_guid = root_guid,
		.target_guid = warmup_guid,
		.child_name = "Warmup",
		.child_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 1,
		.sequence = 77,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = steps,
			.step_count = ARRAY_SIZE(steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	size_t layer_sd_len = 0;
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_log_capacity(
				(int)txn_fd, 1),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)txn_fd, 1, root_guid, &log_input,
				&handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	script.walk.expected_txn_id = txn_snapshot.transaction_id;
	script.read_key.expected_txn_id = txn_snapshot.transaction_id;
	args.txn_fd = (int)txn_fd;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_txn_create_flow_source_thread,
			   &script, "pkm-lcs-kunit-create-txn-full-log");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						    &inputs);
	thread_ret = kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ret, (long)-ENOMEM);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 77ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_args_txn_missing_entry_race(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 child_candidates[1][RSI_GUID_SIZE] = { { 0x97 } };
	static const u8 existing_guid[RSI_GUID_SIZE] = { 0x98 };
	static const struct pkm_lcs_kunit_walk_source_step missing_steps[] = {
		{
			.expected_child = "App",
			.empty = true,
		},
	};
	static const char path_src[] = "Machine\\App";
	struct pkm_lcs_kunit_walk_source_step retry_steps[] = {
		{
			.expected_child = "App",
			.guid = existing_guid,
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
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_key_fd_snapshot key_snapshot = { };
	struct pkm_lcs_kunit_txn_create_flow_source_script script = {
		.walk = {
			.steps = missing_steps,
			.step_count = ARRAY_SIZE(missing_steps),
		},
		.read_key = {
			.expected_guid = root_guid,
			.name = "Machine",
		},
		.begin = {
			.expected_op_code = RSI_BEGIN_TRANSACTION,
			.expected_header_txn_id = 0,
			.expected_mode = RSI_TXN_READ_WRITE,
			.status = RSI_OK,
		},
		.create = {
			.parent_guid = root_guid,
			.child_guid = child_candidates[0],
			.child_name = "App",
			.layer_name = "base",
			.expected_sequence = 1,
			.entry_status = RSI_ALREADY_EXISTS,
			.expect_key_request = false,
			.allow_any_sd = true,
		},
		.retry_walk = {
			.steps = retry_steps,
			.step_count = ARRAY_SIZE(retry_steps),
		},
		.expect_begin = true,
		.expect_create = true,
		.expect_retry_walk = true,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const u8 *layer_sd;
	const u8 *existing_sd;
	size_t layer_sd_len = 0;
	size_t existing_sd_len = 0;
	u32 disposition = 0;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
	long txn_fd;
	long fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	layer_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_SET_VALUE, 0, 0, 0, &layer_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, layer_sd);
	existing_sd = kacs_rust_kunit_create_file_sd(
		token, KEY_READ, 0, 0, 0, &existing_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, existing_sd);
	inputs.base_metadata_sd = layer_sd;
	inputs.base_metadata_sd_len = layer_sd_len;
	script.read_key.sd =
		pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read;
	script.read_key.sd_len =
		sizeof(pkm_lcs_kunit_parent_sd_create_subkey_ci_generic_read);
	retry_steps[0].sd = existing_sd;
	retry_steps[0].sd_len = existing_sd_len;

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	script.begin.expected_payload_txn_id = txn_snapshot.transaction_id;
	script.create.expected_txn_id = txn_snapshot.transaction_id;
	script.retry_walk.expected_txn_id = txn_snapshot.transaction_id;
	args.txn_fd = (int)txn_fd;
	script.file = &file;

	task = kthread_run(pkm_lcs_kunit_txn_create_flow_source_thread,
			   &script, "pkm-lcs-kunit-create-txn-race");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args,
						   &inputs);
	thread_ret = kthread_stop(task);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, disposition, (u32)REG_OPENED_EXISTING);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 1U);
	KUNIT_EXPECT_EQ(test, guid_sequence.calls, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd,
						      &key_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, key_snapshot.granted_access, KEY_READ);
	KUNIT_EXPECT_EQ(test,
			memcmp(key_snapshot.key_guid, existing_guid,
			       sizeof(key_snapshot.key_guid)),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	pkm_kacs_free((void *)existing_sd);
	pkm_kacs_free((void *)layer_sd);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_reg_create_key_args_bad_flags_before_txn(
	struct kunit *test)
{
	static const char path_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	u32 disposition = 0xaaaaaaaaU;
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.flags = 0x80000000U,
		.txn_fd = 0,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_reg_create_key_args_for_token(NULL, &ops, &args,
							      NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, disposition, 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, ctx.strnlens, 0U);
	KUNIT_EXPECT_EQ(test, ctx.reads, 0U);
	KUNIT_EXPECT_EQ(test, ctx.writes, 0U);
}

static void pkm_lcs_kunit_reg_create_key_args_existing_success(
	struct kunit *test)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	const char path_src[] = "Machine";
	const char layer_src[] = "ignored-for-existing";
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
	struct reg_create_key_args args = {
		.parent_fd = -1,
		.path_ptr = (u64)(unsigned long)path_src,
		.desired_access = KEY_READ,
		.flags = REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
		.layer_ptr = (u64)(unsigned long)layer_src,
		.txn_fd = -1,
		.disposition_ptr = (u64)(unsigned long)&disposition,
	};
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
			   "pkm-lcs-kunit-reg-create-args");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	fd = pkm_lcs_reg_create_key_args_for_token(token, &ops, &args, NULL);
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
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_limits),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_source_down),
	KUNIT_CASE(pkm_lcs_kunit_source_bound_transaction_counter_bad_inputs),
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
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_erange_probe),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_get_security_malformed_source_sd),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_value_success),
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
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_erange_all_or_none),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_index_past_end),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_transaction_context),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_enum_subkey_malformed_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_erange_probe),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_query_key_info_malformed_enum),
	KUNIT_CASE(
		pkm_lcs_kunit_set_security_merge_bridge_preserves_components),
	KUNIT_CASE(pkm_lcs_kunit_set_security_merge_bridge_fails_closed),
	KUNIT_CASE(
		pkm_lcs_kunit_key_fd_set_security_nontransactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_security_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_security_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_nontransactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_transactional_success),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_cas_failure_no_effects),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_set_value_fails_before_source),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_ioctl_access_rejects_bad_fds),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_notify_arm_replace_disarm),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_notify_fails_closed),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_read_poll_drains_records),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_filter_disarm_and_overflow),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_registry_arm_replace_disarm),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_watch_registry_refcounts_close),
	KUNIT_CASE(pkm_lcs_kunit_key_fd_live_dispatch_direct_and_subtree),
	KUNIT_CASE(
		pkm_lcs_kunit_key_fd_live_dispatch_filter_bypass_and_zero_depth),
	KUNIT_CASE(
		pkm_lcs_kunit_key_fd_live_dispatch_context_subkey_created),
	KUNIT_CASE(
		pkm_lcs_kunit_begin_transaction_publishes_active_unbound),
	KUNIT_CASE(pkm_lcs_kunit_begin_transaction_ids_are_monotonic),
	KUNIT_CASE(pkm_lcs_kunit_transaction_timeout_marks_timed_out),
	KUNIT_CASE(pkm_lcs_kunit_transaction_timeout_bound_aborts_source),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_timeout_commit_in_flight_no_abort),
	KUNIT_CASE(pkm_lcs_kunit_source_down_marks_bound_transaction),
	KUNIT_CASE(pkm_lcs_kunit_source_down_ignores_unbound_transaction),
	KUNIT_CASE(pkm_lcs_kunit_transaction_fd_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_reports_active_state),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_reports_timeout_errno),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_maps_terminal_errno),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_rejects_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_precheck_unbound_terminal),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_precheck_timeout_source_down),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_active_bound_no_source_eio),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_active_bound_success),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_busy_retains_active_bound),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_sync_eio_retains_active_bound),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_rejects_bad_fds),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_close_active_unbound_no_source_abort),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_close_active_bound_aborts_source),
	KUNIT_CASE(pkm_lcs_kunit_transaction_binding_precheck_and_complete),
	KUNIT_CASE(pkm_lcs_kunit_transaction_binding_terminal_failures),
	KUNIT_CASE(pkm_lcs_kunit_transaction_binding_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_transaction_read_context_active_states),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_read_context_terminal_failures),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_read_context_rejects_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_bind_for_mutation_success_and_reuse),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_bind_for_mutation_source_failure_rolls_back),
	KUNIT_CASE(pkm_lcs_kunit_transaction_bind_for_mutation_counter_cap),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_key_create_first_bind_and_reuse),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_cancel_does_not_publish),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_rejects_bad_create_shape),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_set_security_records_context),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_rejects_bad_set_security_shape),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_set_value_records_context),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_log_rejects_bad_set_value_shape),
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
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_begin_transaction_request_frame_success),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_commit_abort_transaction_request_frames),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_transaction_request_frames_reject_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_transaction_request_frames_reject_short_buffer),
	KUNIT_CASE(pkm_lcs_kunit_rsi_read_key_bridge_accepts_valid),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_query_values_bridge_materializes_default_reg_link),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_query_values_bridge_blanket_not_found),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_query_values_bridge_rejects_wrong_value),
	KUNIT_CASE(pkm_lcs_kunit_rsi_enum_children_info_summary),
	KUNIT_CASE(pkm_lcs_kunit_rsi_query_values_info_summary),
	KUNIT_CASE(
		pkm_lcs_kunit_rsi_enum_children_info_rejects_bad_metadata),
	KUNIT_CASE(
		pkm_lcs_kunit_source_enum_children_round_trip_retains_frame),
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
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_write_key_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_dispatch_set_value_frame),
	KUNIT_CASE(pkm_lcs_kunit_source_set_value_round_trip_statuses),
	KUNIT_CASE(
		pkm_lcs_kunit_source_dispatch_transaction_control_frames),
	KUNIT_CASE(
		pkm_lcs_kunit_source_abort_response_releases_no_wait_record),
	KUNIT_CASE(
		pkm_lcs_kunit_source_dispatch_transaction_rejects_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_source_dispatch_set_value_rejects_bad_inputs),
	KUNIT_CASE(
		pkm_lcs_kunit_source_transaction_round_trip_statuses),
	KUNIT_CASE(
		pkm_lcs_kunit_source_transaction_round_trip_failures),
	KUNIT_CASE(
		pkm_lcs_kunit_late_begin_success_enqueues_abort_cleanup),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_generation_success),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_dispatches_create_watch),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_dispatches_sd_watch),
	KUNIT_CASE(
		pkm_lcs_kunit_transaction_commit_generation_overflow_downs_source),
	KUNIT_CASE(
		pkm_lcs_kunit_commit_timeout_late_success_consumes_log),
	KUNIT_CASE(
		pkm_lcs_kunit_commit_timeout_late_error_discards_log),
	KUNIT_CASE(
		pkm_lcs_kunit_commit_timeout_closed_fd_late_success),
	KUNIT_CASE(
		pkm_lcs_kunit_commit_timeout_closed_fd_late_error),
	KUNIT_CASE(
		pkm_lcs_kunit_commit_timeout_closed_fd_source_teardown),
	KUNIT_CASE(
		pkm_lcs_kunit_commit_timeout_malformed_late_response_downs_source),
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
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_missing_dispatches_watch),
	KUNIT_CASE(
		pkm_lcs_kunit_reg_create_key_bad_flags_before_usercopy),
	KUNIT_CASE(
		pkm_lcs_kunit_reg_create_key_args_copy_success_and_fault),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_rejects_padding),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_existing_txn_reads),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_txn_failures),
	KUNIT_CASE(
		pkm_lcs_kunit_reg_create_key_args_txn_missing_success),
	KUNIT_CASE(
		pkm_lcs_kunit_reg_create_key_args_txn_missing_full_log),
	KUNIT_CASE(
		pkm_lcs_kunit_reg_create_key_args_txn_missing_entry_race),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_bad_flags_before_txn),
	KUNIT_CASE(pkm_lcs_kunit_reg_create_key_args_existing_success),
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
