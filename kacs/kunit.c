// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM KUnit scaffold.
 *
 * This suite is intentionally tiny. It exists only to prove that PKM-owned
 * KUnit plumbing can execute a narrow C -> Rust -> kacs-core seam without
 * introducing live security semantics.
 */

#include <kunit/test.h>
#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/net.h>
#include <linux/prctl.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#include "access_check.h"
#include "caap_cache.h"
#include "kmes.h"
#include "token_fd.h"
#include "token_runtime.h"

#ifndef PTRACE_MODE_PIDFD_OPEN
#define PTRACE_MODE_PIDFD_OPEN 0x40
#endif

#ifndef PTRACE_MODE_PROC_QUERY_LIMITED
#define PTRACE_MODE_PROC_QUERY_LIMITED 0x80
#endif

#ifndef PTRACE_MODE_PROC_QUERY_INFORMATION
#define PTRACE_MODE_PROC_QUERY_INFORMATION 0x100
#endif

#define PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT \
	(KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC | \
	 KACS_ACCESS_ACCESS_SYSTEM_SECURITY)
#define PKM_KUNIT_CAAP_PRIVILEGE_GRANT KACS_ACCESS_ACCESS_SYSTEM_SECURITY
#define PKM_KUNIT_CAAP_READ_GRANT \
	(KACS_ACCESS_READ_CONTROL | KACS_ACCESS_ACCESS_SYSTEM_SECURITY)
#define PKM_KUNIT_PIP_TYPE_PROTECTED 512U
#define PKM_KUNIT_PIP_TRUST_TEST 5U
#define PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE (1ULL << 3)
#define PKM_KUNIT_SE_TCB_PRIVILEGE (1ULL << 7)
#define PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE (1ULL << 14)
#define PKM_KUNIT_SE_DEBUG_PRIVILEGE (1ULL << 20)
#define PKM_KUNIT_SE_SECURITY_PRIVILEGE (1ULL << 8)
#define PKM_KUNIT_SE_RESTORE_PRIVILEGE (1ULL << 18)
#define PKM_KUNIT_SE_RELABEL_PRIVILEGE (1ULL << 32)
#define PKM_KUNIT_SE_AUDIT_PRIVILEGE (1ULL << 21)
#define PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE (1ULL << 29)
#define PKM_KUNIT_SYSTEM_PRIVILEGES_ALL 0xC000000FFFFFFFFCULL
#define PKM_KUNIT_SE_PRIVILEGE_ENABLED 0x00000002U
#define PKM_KUNIT_SE_PRIVILEGE_REMOVED 0x00000004U
#define PKM_KUNIT_PRIV_RESET_ALL_DEFAULTS 0x80000000U
#define PKM_KUNIT_PRIV_LUID_SECURITY 8U
#define PKM_KUNIT_PRIV_LUID_AUDIT 21U
#define PKM_KUNIT_PRIV_LUID_REMOVE 2U
#define PKM_KUNIT_PRIV_LUID_ENABLE 5U
#define PKM_KUNIT_PRIV_LUID_DISABLE 9U
#define PKM_KUNIT_PRIV_LUID_ABSENT_DISABLE 12U
#define PKM_KUNIT_PRIV_LUID_ABSENT_REMOVE 13U
#define PKM_KUNIT_ADJUSTABLE_PRIV_PRESENT \
	((1ULL << PKM_KUNIT_PRIV_LUID_REMOVE) | \
	 (1ULL << PKM_KUNIT_PRIV_LUID_ENABLE) | \
	 (1ULL << PKM_KUNIT_PRIV_LUID_DISABLE))
#define PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED \
	((1ULL << PKM_KUNIT_PRIV_LUID_REMOVE) | \
	 (1ULL << PKM_KUNIT_PRIV_LUID_DISABLE))
#define PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED_BY_DEFAULT \
	PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED
#define PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_ENABLE_DISABLE \
	((1ULL << PKM_KUNIT_PRIV_LUID_REMOVE) | \
	 (1ULL << PKM_KUNIT_PRIV_LUID_ENABLE))
#define PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE \
	((1ULL << PKM_KUNIT_PRIV_LUID_ENABLE) | \
	 (1ULL << PKM_KUNIT_PRIV_LUID_DISABLE))
#define PKM_KUNIT_SE_GROUP_ENABLED 0x00000004U
#define PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY 0x00000010U
#define PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT 0x0000000EU
#define PKM_KUNIT_ADJUSTABLE_GROUP1_DEFAULT 0x00000000U
#define PKM_KUNIT_ADJUSTABLE_GROUP2_DEFAULT 0x00000010U
#define PKM_KUNIT_ADJUSTABLE_GROUP3_DEFAULT 0x00000006U
#define PKM_KUNIT_ADJUSTABLE_GROUP4_DEFAULT 0xC0000007U
#define PKM_KUNIT_ADJUSTABLE_GROUP_PREV_MASK 0x19ULL
#define PKM_KUNIT_ADJUSTABLE_GROUP_MUTATED_MASK 0x1AULL
#define PKM_KUNIT_KMES_PROCESS_NAME "kunit-ac"
#define PKM_KUNIT_KMES_PROCESS_PATH "/kunit/access-check"
#define PKM_KUNIT_KMES_PRIV_PROCESS_NAME "kunit-priv"
#define PKM_KUNIT_KMES_PRIV_PROCESS_PATH "/kunit/privilege"
#define PKM_KUNIT_KMES_DIRECT_TYPE "kunit-smoke"
#define PKM_KUNIT_KMES_USER_TYPE "kmes-user"
#define PKM_KUNIT_KMES_BATCH_TYPE0 "kmes-batch0"
#define PKM_KUNIT_KMES_BATCH_TYPE1 "kmes-batch1"
#define PKM_KUNIT_KMES_CAPTURE_BYTES 2048U
#define PKM_KUNIT_KMES_DEFAULT_CAPACITY (4U * 1024U * 1024U)
#define PKM_KUNIT_KMES_SWAP_CAPACITY (1U * 1024U * 1024U)
#define PKM_KUNIT_KMES_DOWNSIZE_CAPACITY (128U * 1024U)
#define PKM_KUNIT_KMES_DEFAULT_RATE 10000U
#define PKM_KUNIT_USER_KIND_SYSTEM 0U
#define PKM_KUNIT_USER_KIND_LOCAL_SERVICE 1U
#define PKM_KUNIT_PRLIMIT_READ 1U
#define PKM_KUNIT_PRLIMIT_WRITE 2U
#define PKM_KUNIT_IL_UNTRUSTED 0U
#define PKM_KUNIT_IL_LOW 4096U
#define PKM_KUNIT_IL_MEDIUM 8192U
#define PKM_KUNIT_IL_HIGH 12288U
#define PKM_KUNIT_IL_SYSTEM 16384U
#define PKM_KUNIT_LOGON_TYPE_NETWORK 3U
#define PKM_KUNIT_OWNER_SECURITY_INFORMATION 0x00000001U
#define PKM_KUNIT_GROUP_SECURITY_INFORMATION 0x00000002U
#define PKM_KUNIT_DACL_SECURITY_INFORMATION 0x00000004U
#define PKM_KUNIT_SACL_SECURITY_INFORMATION 0x00000008U
#define PKM_KUNIT_LABEL_SECURITY_INFORMATION 0x00000010U

#ifndef PTRACE_MODE_GETFD
#define PTRACE_MODE_GETFD 0x20
#endif

#ifndef ARCH_SHSTK_DISABLE
#define ARCH_SHSTK_DISABLE 0x5002
#endif

extern size_t kacs_rust_kunit_probe(void);
static const u8 pkm_kunit_kmes_ring_magic[] = "KMESRING";
static const u8 pkm_kunit_anonymous_sid[] = {
	1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0
};
static const u8 pkm_kunit_everyone_sid[] = {
	1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0
};
static const u8 pkm_kunit_authenticated_users_sid[] = {
	1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0
};

static void pkm_kunit_probe_smoke(struct kunit *test)
{
	size_t probe;

	probe = kacs_rust_kunit_probe();
	KUNIT_ASSERT_GT(test, probe, (size_t)0);

	pr_info("pkm: kunit scaffold smoke passed\n");
}

struct pkm_kunit_region {
	u64 base;
	u8 *bytes;
	size_t len;
	bool fault_read;
	bool fault_write;
};

struct pkm_kunit_mem {
	struct pkm_kunit_region regions[8];
	size_t count;
};

struct pkm_kunit_event_counts {
	u32 audit_events;
	u32 privilege_use_events;
};

struct pkm_kunit_kmes_event_view {
	u32 event_size;
	u32 header_size;
	u64 timestamp;
	u64 sequence;
	u16 cpu_id;
	u8 origin_class;
	u16 type_len;
	const u8 *type_ptr;
	const u8 *payload_ptr;
	size_t payload_len;
};

static bool pkm_kunit_mem_read(void *ctx, u64 user_ptr, void *dst, size_t len)
{
	struct pkm_kunit_mem *mem = ctx;
	size_t i;

	for (i = 0; i < mem->count; i++) {
		struct pkm_kunit_region *region = &mem->regions[i];
		size_t start;

		if (user_ptr < region->base)
			continue;

		start = (size_t)(user_ptr - region->base);
		if (start > region->len || len > region->len - start)
			continue;
		if (region->fault_read)
			return false;

		memcpy(dst, region->bytes + start, len);
		return true;
	}

	return false;
}

static bool pkm_kunit_mem_write(void *ctx, u64 user_ptr, const void *src, size_t len)
{
	struct pkm_kunit_mem *mem = ctx;
	size_t i;

	for (i = 0; i < mem->count; i++) {
		struct pkm_kunit_region *region = &mem->regions[i];
		size_t start;

		if (user_ptr < region->base)
			continue;

		start = (size_t)(user_ptr - region->base);
		if (start > region->len || len > region->len - start)
			continue;
		if (region->fault_write)
			return false;

		memcpy(region->bytes + start, src, len);
		return true;
	}

	return false;
}

static bool pkm_kunit_on_audit_event(void *ctx,
				     const struct pkm_kacs_audit_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->audit_events++;
	return true;
}

static bool pkm_kunit_on_privilege_use_event(
	void *ctx, const struct pkm_kacs_privilege_use_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->privilege_use_events++;
	return true;
}

static bool pkm_kunit_fail_audit_event(
	void *ctx, const struct pkm_kacs_audit_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->audit_events++;
	return false;
}

static void pkm_kunit_add_region(struct pkm_kunit_mem *mem, u64 base, u8 *bytes,
				 size_t len)
{
	mem->regions[mem->count].base = base;
	mem->regions[mem->count].bytes = bytes;
	mem->regions[mem->count].len = len;
	mem->regions[mem->count].fault_read = false;
	mem->regions[mem->count].fault_write = false;
	mem->count++;
}

static void pkm_kunit_write_u32(u8 *bytes, size_t offset, u32 value)
{
	bytes[offset + 0] = (u8)(value & 0xff);
	bytes[offset + 1] = (u8)((value >> 8) & 0xff);
	bytes[offset + 2] = (u8)((value >> 16) & 0xff);
	bytes[offset + 3] = (u8)((value >> 24) & 0xff);
}

static void pkm_kunit_write_u64(u8 *bytes, size_t offset, u64 value)
{
	bytes[offset + 0] = (u8)(value & 0xff);
	bytes[offset + 1] = (u8)((value >> 8) & 0xff);
	bytes[offset + 2] = (u8)((value >> 16) & 0xff);
	bytes[offset + 3] = (u8)((value >> 24) & 0xff);
	bytes[offset + 4] = (u8)((value >> 32) & 0xff);
	bytes[offset + 5] = (u8)((value >> 40) & 0xff);
	bytes[offset + 6] = (u8)((value >> 48) & 0xff);
	bytes[offset + 7] = (u8)((value >> 56) & 0xff);
}

static void pkm_kunit_write_u16(u8 *bytes, size_t offset, u16 value)
{
	bytes[offset + 0] = (u8)(value & 0xff);
	bytes[offset + 1] = (u8)((value >> 8) & 0xff);
}

static u32 pkm_kunit_read_u32(const u8 *bytes, size_t offset)
{
	return (u32)bytes[offset + 0] |
	       ((u32)bytes[offset + 1] << 8) |
	       ((u32)bytes[offset + 2] << 16) |
	       ((u32)bytes[offset + 3] << 24);
}

static u16 pkm_kunit_read_u16(const u8 *bytes, size_t offset)
{
	return (u16)bytes[offset + 0] | ((u16)bytes[offset + 1] << 8);
}

static u64 pkm_kunit_read_u64(const u8 *bytes, size_t offset)
{
	return (u64)bytes[offset + 0] |
	       ((u64)bytes[offset + 1] << 8) |
	       ((u64)bytes[offset + 2] << 16) |
	       ((u64)bytes[offset + 3] << 24) |
	       ((u64)bytes[offset + 4] << 32) |
	       ((u64)bytes[offset + 5] << 40) |
	       ((u64)bytes[offset + 6] << 48) |
	       ((u64)bytes[offset + 7] << 56);
}

static u32 pkm_kunit_groups_query_attr(const u8 *bytes, u32 index)
{
	size_t offset = 4;
	u32 i;

	for (i = 0; i < index; i++) {
		u32 sid_len = pkm_kunit_read_u32(bytes, offset);

		offset += 4 + sid_len + 4;
	}

	return pkm_kunit_read_u32(bytes,
				 offset + 4 + pkm_kunit_read_u32(bytes, offset));
}

static void pkm_kunit_expect_bytes_eq(struct kunit *test, const u8 *actual,
				      size_t actual_len, const u8 *expected,
				      size_t expected_len)
{
	KUNIT_ASSERT_EQ(test, actual_len, expected_len);
	KUNIT_EXPECT_EQ(test, memcmp(actual, expected, actual_len), 0);
}

static bool pkm_kunit_snapshot_has_group(
	const struct pkm_kacs_boot_snapshot *snapshot,
	const u8 *sid, size_t sid_len, u32 *attributes_out)
{
	u32 i;

	if (!snapshot || !sid)
		return false;

	for (i = 0; i < snapshot->group_count; i++) {
		if (snapshot->groups_ptr[i].sid_len != sid_len)
			continue;
		if (memcmp(snapshot->groups_ptr[i].sid_ptr, sid, sid_len))
			continue;
		if (attributes_out)
			*attributes_out = snapshot->groups_ptr[i].attributes;
		return true;
	}

	return false;
}

static bool pkm_kunit_contains_bytes(const u8 *haystack, size_t haystack_len,
				     const u8 *needle, size_t needle_len)
{
	size_t i;

	if (needle_len == 0)
		return true;
	if (haystack_len < needle_len)
		return false;

	for (i = 0; i <= haystack_len - needle_len; i++) {
		if (!memcmp(haystack + i, needle, needle_len))
			return true;
	}

	return false;
}

static void pkm_kunit_reset_kmes(void)
{
	pkm_kmes_kunit_reset_all();
	pkm_kmes_kunit_clear_process_override();
	(void)pkm_kmes_kunit_set_current_process_rate_refill_frozen(false);
	(void)pkm_kmes_kunit_set_current_process_rate_tokens(
		PKM_KUNIT_KMES_DEFAULT_RATE);
}

static void pkm_kunit_close_fds(struct kunit *test, int *fds, int count)
{
	int i;

	if (!fds)
		return;

	for (i = 0; i < count; i++) {
		if (fds[i] >= 0)
			KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fds[i]), 0);
		fds[i] = -1;
	}
}

static int pkm_kunit_find_current_kmes_fd(struct kunit *test, int *fds, int count,
					  struct pkm_kmes_kunit_fd_snapshot *out)
{
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	u16 current_cpu;
	int i;
	int ret;

	current_cpu = pkm_kmes_kunit_current_cpu_id();
	for (i = 0; i < count; i++) {
		ret = pkm_kmes_kunit_fd_snapshot(fds[i], &snapshot);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			return -1;
		if (snapshot.cpu_id != current_cpu)
			continue;
		if (out)
			*out = snapshot;
		return fds[i];
	}

	return -1;
}

static bool pkm_kunit_parse_kmes_event(
	const u8 *bytes, size_t len, struct pkm_kunit_kmes_event_view *out)
{
	u32 event_size;
	u32 header_size;
	u16 type_len;

	if (!bytes || !out || len < 29)
		return false;

	event_size = pkm_kunit_read_u32(bytes, 0);
	header_size = pkm_kunit_read_u32(bytes, 4);
	type_len = pkm_kunit_read_u16(bytes, 27);
	if (event_size > len || header_size > event_size)
		return false;
	if (header_size != 29U + (u32)type_len)
		return false;

	out->event_size = event_size;
	out->header_size = header_size;
	out->timestamp = pkm_kunit_read_u64(bytes, 8);
	out->sequence = pkm_kunit_read_u64(bytes, 16);
	out->cpu_id = pkm_kunit_read_u16(bytes, 24);
	out->origin_class = bytes[26];
	out->type_len = type_len;
	out->type_ptr = bytes + 29;
	out->payload_ptr = bytes + header_size;
	out->payload_len = event_size - header_size;
	return true;
}

static void pkm_kunit_expect_boot_snapshot_eq(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs)
{
	u32 i;

	KUNIT_EXPECT_EQ(test, lhs->session_id, rhs->session_id);
	KUNIT_EXPECT_EQ(test, lhs->auth_id, rhs->auth_id);
	KUNIT_EXPECT_EQ(test, lhs->token_id, rhs->token_id);
	KUNIT_EXPECT_EQ(test, lhs->modified_id, rhs->modified_id);
	KUNIT_EXPECT_EQ(test, lhs->logon_type, rhs->logon_type);
	pkm_kunit_expect_bytes_eq(test, lhs->auth_pkg_ptr, lhs->auth_pkg_len,
				  rhs->auth_pkg_ptr, rhs->auth_pkg_len);
	pkm_kunit_expect_bytes_eq(test, lhs->user_sid_ptr, lhs->user_sid_len,
				  rhs->user_sid_ptr, rhs->user_sid_len);
	pkm_kunit_expect_bytes_eq(test, lhs->logon_sid_ptr, lhs->logon_sid_len,
				  rhs->logon_sid_ptr, rhs->logon_sid_len);
	KUNIT_ASSERT_EQ(test, lhs->group_count, rhs->group_count);
	for (i = 0; i < lhs->group_count; i++) {
		KUNIT_EXPECT_EQ(test, lhs->groups_ptr[i].attributes,
				rhs->groups_ptr[i].attributes);
		pkm_kunit_expect_bytes_eq(test, lhs->groups_ptr[i].sid_ptr,
					  lhs->groups_ptr[i].sid_len,
					  rhs->groups_ptr[i].sid_ptr,
					  rhs->groups_ptr[i].sid_len);
	}
	KUNIT_EXPECT_EQ(test, lhs->owner_sid_index, rhs->owner_sid_index);
	KUNIT_EXPECT_EQ(test, lhs->primary_group_index,
			rhs->primary_group_index);
	pkm_kunit_expect_bytes_eq(test, lhs->default_dacl_ptr,
				  lhs->default_dacl_len,
				  rhs->default_dacl_ptr,
				  rhs->default_dacl_len);
	KUNIT_EXPECT_EQ(test, lhs->privileges_present, rhs->privileges_present);
	KUNIT_EXPECT_EQ(test, lhs->privileges_enabled, rhs->privileges_enabled);
	KUNIT_EXPECT_EQ(test, lhs->privileges_enabled_by_default,
			rhs->privileges_enabled_by_default);
	KUNIT_EXPECT_EQ(test, lhs->privileges_used, rhs->privileges_used);
	KUNIT_EXPECT_EQ(test, lhs->integrity_level, rhs->integrity_level);
	KUNIT_EXPECT_EQ(test, lhs->token_type, rhs->token_type);
	KUNIT_EXPECT_EQ(test, lhs->impersonation_level, rhs->impersonation_level);
	KUNIT_EXPECT_EQ(test, lhs->mandatory_policy, rhs->mandatory_policy);
	KUNIT_EXPECT_EQ(test, lhs->interactive_session_id,
			rhs->interactive_session_id);
	KUNIT_EXPECT_EQ(test, lhs->projected_uid, rhs->projected_uid);
	KUNIT_EXPECT_EQ(test, lhs->projected_gid, rhs->projected_gid);
	KUNIT_EXPECT_EQ(test, lhs->audit_policy, rhs->audit_policy);
}

static void pkm_kunit_build_args_v136(u8 *args)
{
	memset(args, 0, 136);
	pkm_kunit_write_u32(args, 0, 136);
}

static const u8 pkm_kunit_system_read_sd[] = {
	1, 0, 4, 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	32, 0, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	2, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 2, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
};

static const u8 pkm_kunit_everyone_read_sd[] = {
	1, 0, 4, 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	32, 0, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	2, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 2, 0,
	1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
};

static const u8 pkm_kunit_system_default_dacl[] = {
	2, 0, 52, 0, 2, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 0, 16,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	0, 0, 24, 0, 0, 0, 0, 16,
	1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
};

static const u8 pkm_kunit_replacement_default_dacl[] = {
	2, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 0, 16,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
};

static const u8 pkm_kunit_invalid_default_dacl[] = {
	2, 0, 7, 0, 0, 0, 0, 0,
};

/* Owner SYSTEM, success-audit SYSTEM READ_CONTROL, allow SYSTEM READ_CONTROL. */
static const u8 pkm_kunit_system_read_audit_sd[] = {
	1, 0, 20, 128, 20, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
	60, 0, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	2, 0, 28, 0, 1, 0, 0, 0,
	2, 64, 20, 0, 0, 0, 2, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	2, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 2, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
};

static const u8 pkm_kunit_system_pip_sd[] = {
	1, 0, 20, 128, 20, 0, 0, 0, 32, 0, 0, 0, 44, 0, 0, 0,
	76, 0, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	4, 0, 32, 0, 1, 0, 0, 0,
	20, 0, 24, 0, 0, 0, 2, 0,
	1, 2, 0, 0, 0, 0, 0, 19, 0, 2, 0, 0, 5, 0, 0, 0,
	4, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 6, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
};

static const u8 pkm_kunit_caap_policy_sid[] = {
	1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 4, 1, 0, 0,
};

static const u8 pkm_kunit_caap_object_sd[] = {
	1, 0, 20, 128, 20, 0, 0, 0, 36, 0, 0, 0, 48, 0, 0, 0,
	80, 0, 0, 0,
	1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 231, 3, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	4, 0, 32, 0, 1, 0, 0, 0,
	19, 0, 24, 0, 0, 0, 0, 0,
	1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 4, 1, 0, 0,
	4, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 2, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
};

static const u8 pkm_kunit_caap_empty_dacl[] = {
	4, 0, 8, 0, 0, 0, 0, 0,
};

static const u8 pkm_kunit_caap_system_read_dacl[] = {
	4, 0, 28, 0, 1, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 2, 0,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
};

static size_t pkm_kunit_build_caap_spec(u8 *spec, const u8 *effective_dacl,
					u32 effective_dacl_len)
{
	size_t offset = 0;

	spec[offset++] = 0x01;
	pkm_kunit_write_u32(spec, offset, 1);
	offset += 4;
	pkm_kunit_write_u32(spec, offset, 0);
	offset += 4;
	pkm_kunit_write_u32(spec, offset, effective_dacl_len);
	offset += 4;
	if (effective_dacl_len && effective_dacl) {
		memcpy(spec + offset, effective_dacl, effective_dacl_len);
		offset += effective_dacl_len;
	}
	pkm_kunit_write_u32(spec, offset, 0);
	offset += 4;
	pkm_kunit_write_u32(spec, offset, 0);
	offset += 4;
	pkm_kunit_write_u32(spec, offset, 0);
	offset += 4;
	return offset;
}

static void pkm_kunit_build_read_control_args(u8 *args, s32 token_fd)
{
	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)token_fd);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);
}

static size_t pkm_kunit_build_restrict_payload(
	u8 *payload,
	const u32 *deny_indices,
	size_t deny_count,
	const struct pkm_kacs_boot_group_view *restrict_sids,
	size_t sid_count)
{
	size_t offset = 0;
	size_t index;

	for (index = 0; index < deny_count; index++) {
		pkm_kunit_write_u32(payload, offset, deny_indices[index]);
		offset += sizeof(u32);
	}

	for (index = 0; index < sid_count; index++) {
		memcpy(payload + offset, restrict_sids[index].sid_ptr,
		       restrict_sids[index].sid_len);
		offset += restrict_sids[index].sid_len;
	}

	return offset;
}

static long pkm_kunit_run_read_control_with_token_fd(int token_fd, const u8 *sd,
						     size_t sd_len,
						     u32 *granted_out)
{
	u8 args[136];
	u8 granted_bytes[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long ret;

	pkm_kunit_build_read_control_args(args, token_fd);
	pkm_kunit_write_u32(args, 16, sd_len);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd, sd_len);
	pkm_kunit_add_region(&mem, 0x3000, granted_bytes, sizeof(granted_bytes));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	if (granted_out)
		*granted_out = pkm_kunit_read_u32(granted_bytes, 0);
	return ret;
}

static long pkm_kunit_run_pip_labeled_access_check(u32 arg_pip_type,
						   u32 arg_pip_trust,
						   u32 *granted)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 96, arg_pip_type);
	pkm_kunit_write_u32(args, 100, arg_pip_trust);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_pip_sd,
			      sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	if (granted)
		*granted = pkm_kunit_read_u32(granted_out, 0);
	return ret;
}

static long pkm_kunit_run_caap_access_check(u32 *granted)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_caap_object_sd));

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_caap_object_sd,
			      sizeof(pkm_kunit_caap_object_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	if (granted)
		*granted = pkm_kunit_read_u32(granted_out, 0);
	return ret;
}

static void pkm_kunit_build_access_system_args(u8 *args, s32 token_fd)
{
	pkm_kunit_build_read_control_args(args, token_fd);
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_ACCESS_SYSTEM_SECURITY);
}

static void pkm_kunit_scalar_denied_writebacks(struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_on_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00060000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, &sinks,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0x00020000U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}

static void pkm_kunit_kmes_direct_emit_writes_single_event(struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	u8 buffer[128] = { 0 };
	size_t written = 0;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(PKM_KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, written, (size_t)view.event_size);
	KUNIT_EXPECT_EQ(test, view.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, view.origin_class, PKM_KMES_ORIGIN_KACS);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)PKM_KUNIT_KMES_DIRECT_TYPE,
				  sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1);
	pkm_kunit_expect_bytes_eq(test, view.payload_ptr, view.payload_len,
				  payload, sizeof(payload));
}

static void pkm_kunit_kmes_direct_invalid_type_drops_structurally(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	u8 buffer[1] = { 0xaa };
	size_t written = 99;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(PKM_KMES_ORIGIN_KACS, NULL, 0, payload,
			     sizeof(payload));

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_snapshot_single_active(&snapshot), 0);
	KUNIT_EXPECT_EQ(test, snapshot.write_pos, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.tail_pos, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 1ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, NULL),
			0);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
	KUNIT_EXPECT_EQ(test, buffer[0], (u8)0xaa);
}

static void pkm_kunit_kmes_attach_success_returns_cpu_fds(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	u8 magic[8] = { 0 };
	long ret;
	int i;
	u16 prev_cpu_id = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	for (i = 0; i < nr_cpu_ids; i++)
		fds[i] = -1;

	pkm_kunit_reset_kmes();
	ret = pkm_kmes_kunit_attach_for_token(token, fds, &count, &capacity);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_GT(test, count, 0);
	KUNIT_EXPECT_EQ(test, capacity, (u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);

	for (i = 0; i < count; i++) {
		KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fds[i], &snapshot),
				0);
		KUNIT_EXPECT_EQ(test, snapshot.capacity, capacity);
		KUNIT_EXPECT_EQ(test, snapshot.generation, 1ULL);
		KUNIT_EXPECT_EQ(test, snapshot.write_pos, 0ULL);
		KUNIT_EXPECT_EQ(test, snapshot.tail_pos, 0ULL);
		KUNIT_EXPECT_EQ(test, snapshot.futex_counter, 0U);
		KUNIT_EXPECT_EQ(test, snapshot.need_wake, (u8)0);
		KUNIT_EXPECT_EQ(test, snapshot.mapping_size,
				8192ULL + (2ULL * capacity));
		if (i > 0)
			KUNIT_EXPECT_GT(test, snapshot.cpu_id, prev_cpu_id);
		prev_cpu_id = snapshot.cpu_id;
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_fd_view(fds[i], 0, magic,
							 sizeof(magic)),
				0);
		pkm_kunit_expect_bytes_eq(test, magic, sizeof(magic),
					  pkm_kunit_kmes_ring_magic,
					  sizeof(pkm_kunit_kmes_ring_magic) - 1);
	}

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			PKM_KUNIT_SE_SECURITY_PRIVILEGE);

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_attach_erange_sets_required_count(
	struct kunit *test)
{
	const void *token;
	int fds[1] = { -1 };
	int count = 0;
	u64 capacity = 0xfeedfaceULL;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	ret = pkm_kmes_kunit_attach_for_token(token, fds, &count, &capacity);
	KUNIT_EXPECT_EQ(test, ret, (long)-ERANGE);
	KUNIT_EXPECT_GT(test, count, 0);
	KUNIT_EXPECT_EQ(test, fds[0], -1);
	KUNIT_EXPECT_EQ(test, capacity, 0xfeedfaceULL);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_attach_denies_without_security(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_priv_adjust_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_SECURITY,
		.attributes = 0,
	};
	u64 previous_enabled = 0;
	int fds[1] = { -1 };
	int count = 1;
	u64 capacity = 0;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_token_has_enabled_privilege(token,
						      PKM_KUNIT_SE_SECURITY_PRIVILEGE));
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_privs(token, &entry, 1,
						     &previous_enabled),
			0);
	KUNIT_ASSERT_FALSE(
		test,
		kacs_rust_token_has_enabled_privilege(token,
						      PKM_KUNIT_SE_SECURITY_PRIVILEGE));

	ret = pkm_kmes_kunit_attach_for_token(token, fds, &count, &capacity);
	KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_attach_checks_privilege_before_usercopy(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_priv_adjust_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_SECURITY,
		.attributes = 0,
	};
	u64 previous_enabled = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_privs(token, &entry, 1,
						     &previous_enabled),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_attach_user_for_token(
				token, (int __user *)1, (int __user *)1,
				(u64 __user *)1),
			(long)-EPERM);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_attach_mapping_view_tracks_emission(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view event = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	u16 current_cpu;
	u8 event_bytes[64] = { 0 };
	u8 mirror_bytes[64] = { 0 };
	long ret;
	int i;
	int current_fd = -1;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	for (i = 0; i < nr_cpu_ids; i++)
		fds[i] = -1;

	pkm_kunit_reset_kmes();
	ret = pkm_kmes_kunit_attach_for_token(token, fds, &count, &capacity);
	KUNIT_ASSERT_EQ(test, ret, 0L);

	current_cpu = pkm_kmes_kunit_current_cpu_id();
	for (i = 0; i < count; i++) {
		KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fds[i], &snapshot),
				0);
		if (snapshot.cpu_id == current_cpu) {
			current_fd = fds[i];
			break;
		}
	}
	KUNIT_ASSERT_GE(test, current_fd, 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_set_fd_need_wake(current_fd, 1), 0);

	pkm_kmes_emit_kernel(PKM_KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(current_fd, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.futex_counter, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.need_wake, (u8)1);
	KUNIT_EXPECT_GT(test, snapshot.write_pos, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(current_fd, 8192, event_bytes,
						 sizeof(event_bytes)),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(event_bytes,
						     sizeof(event_bytes), &event));
	KUNIT_EXPECT_EQ(test, event.origin_class, PKM_KMES_ORIGIN_KACS);
	pkm_kunit_expect_bytes_eq(test, event.type_ptr, event.type_len,
				  (const u8 *)PKM_KUNIT_KMES_DIRECT_TYPE,
				  sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(current_fd, 8192 + capacity,
						 mirror_bytes,
						 sizeof(mirror_bytes)),
			0);
	pkm_kunit_expect_bytes_eq(test, mirror_bytes, sizeof(mirror_bytes),
				  event_bytes, sizeof(event_bytes));

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_swap_old_fd_freezes_and_new_attach_rebinds(
	struct kunit *test)
{
	static const u8 payload0[] = { 0xaa };
	static const u8 payload1[] = { 0xbb };
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot old_before = { };
	struct pkm_kmes_kunit_fd_snapshot old_after = { };
	struct pkm_kmes_kunit_fd_snapshot old_post_emit = { };
	struct pkm_kmes_kunit_fd_snapshot new_before_emit = { };
	struct pkm_kmes_kunit_fd_snapshot new_after_emit = { };
	struct pkm_kmes_kunit_fd_snapshot scan_snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	struct pkm_kunit_kmes_event_view second = { };
	int *fds;
	int *new_fds;
	int count = nr_cpu_ids;
	int new_count = nr_cpu_ids;
	u64 capacity = 0;
	u64 new_capacity = 0;
	int old_fd;
	int new_fd;
	int i;
	bool found_copied_event = false;
	bool found_emitted_event = false;
	u8 old_bytes[128] = { 0 };
	u8 new_bytes[256] = { 0 };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	new_fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*new_fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	KUNIT_ASSERT_NOT_NULL(test, new_fds);
	memset(fds, 0xff, nr_cpu_ids * sizeof(*fds));
	memset(new_fds, 0xff, nr_cpu_ids * sizeof(*new_fds));

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_attach_for_token(token, fds, &count,
							&capacity),
			0L);
	old_fd = pkm_kunit_find_current_kmes_fd(test, fds, count, NULL);
	KUNIT_ASSERT_GE(test, old_fd, 0);

	pkm_kmes_emit_kernel(PKM_KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload0,
			     sizeof(payload0));

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(old_fd, &old_before), 0);
	KUNIT_EXPECT_EQ(test, old_before.generation, 1ULL);
	KUNIT_EXPECT_EQ(test, old_before.capacity,
			(u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);
	KUNIT_EXPECT_GT(test, old_before.write_pos, 0ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_SWAP_CAPACITY),
			0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(old_fd, &old_after), 0);
	KUNIT_EXPECT_EQ(test, old_after.generation, 2ULL);
	KUNIT_EXPECT_EQ(test, old_after.capacity,
			(u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);
	KUNIT_EXPECT_EQ(test, old_after.write_pos, old_before.write_pos);
	KUNIT_EXPECT_EQ(test, old_after.mapping_size,
			8192ULL + (2ULL * PKM_KUNIT_KMES_DEFAULT_CAPACITY));
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(old_fd, 8192, old_bytes,
						 sizeof(old_bytes)),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(old_bytes,
						     sizeof(old_bytes), &first));
	KUNIT_EXPECT_EQ(test, first.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, first.origin_class, PKM_KMES_ORIGIN_KACS);
	KUNIT_EXPECT_EQ(test, first.payload_len, sizeof(payload0));
	KUNIT_EXPECT_EQ(test, first.payload_ptr[0], payload0[0]);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_attach_for_token(token, new_fds, &new_count,
							&new_capacity),
			0L);
	new_fd = pkm_kunit_find_current_kmes_fd(test, new_fds, new_count,
						 &new_before_emit);
	KUNIT_ASSERT_GE(test, new_fd, 0);
	KUNIT_EXPECT_EQ(test, new_capacity, (u64)PKM_KUNIT_KMES_SWAP_CAPACITY);
	KUNIT_EXPECT_EQ(test, new_before_emit.generation, 2ULL);
	KUNIT_EXPECT_EQ(test, new_before_emit.capacity,
			(u64)PKM_KUNIT_KMES_SWAP_CAPACITY);

	pkm_kmes_emit_kernel(PKM_KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload1,
			     sizeof(payload1));

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(old_fd, &old_post_emit),
			0);
	KUNIT_EXPECT_EQ(test, old_post_emit.write_pos, old_before.write_pos);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(new_fd, &new_after_emit),
			0);
	KUNIT_EXPECT_EQ(test, new_after_emit.generation, 2ULL);
	KUNIT_EXPECT_TRUE(test,
			  new_after_emit.write_pos == old_before.write_pos ||
			  new_after_emit.write_pos > old_before.write_pos);

	for (i = 0; i < new_count; i++) {
		if (new_fds[i] < 0)
			continue;
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_fd_snapshot(new_fds[i],
							   &scan_snapshot),
				0);
		KUNIT_EXPECT_EQ(test, scan_snapshot.generation, 2ULL);
		if (!scan_snapshot.write_pos)
			continue;
		memset(new_bytes, 0, sizeof(new_bytes));
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_fd_view(new_fds[i], 8192,
							 new_bytes,
							 sizeof(new_bytes)),
				0);
		KUNIT_ASSERT_TRUE(test,
				  pkm_kunit_parse_kmes_event(
					  new_bytes, sizeof(new_bytes), &first));
		if (first.sequence == 1ULL && first.payload_len == sizeof(payload0) &&
		    first.payload_ptr[0] == payload0[0]) {
			found_copied_event = true;
			if (pkm_kunit_parse_kmes_event(new_bytes + first.event_size,
						       sizeof(new_bytes) -
							       first.event_size,
						       &second)) {
				if (second.sequence == 2ULL &&
				    second.payload_len == sizeof(payload1) &&
				    second.payload_ptr[0] == payload1[0])
					found_emitted_event = true;
			}
		}
		if (first.sequence == 1ULL && first.payload_len == sizeof(payload1) &&
		    first.payload_ptr[0] == payload1[0]) {
			found_emitted_event = true;
		}
	}

	KUNIT_EXPECT_TRUE(test, found_copied_event);
	KUNIT_EXPECT_TRUE(test, found_emitted_event);

	pkm_kunit_close_fds(test, new_fds, new_count);
	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_swap_wakes_old_generation_waiter(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	int fd;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	memset(fds, 0xff, nr_cpu_ids * sizeof(*fds));

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_attach_for_token(token, fds, &count,
							&capacity),
			0L);
	fd = pkm_kunit_find_current_kmes_fd(test, fds, count, NULL);
	KUNIT_ASSERT_GE(test, fd, 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_set_fd_need_wake(fd, 1), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_SWAP_CAPACITY),
			0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd, &snapshot), 0);
	KUNIT_EXPECT_EQ(test, snapshot.generation, 2ULL);
	KUNIT_EXPECT_EQ(test, snapshot.futex_counter, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.need_wake, (u8)1);

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_swap_downsize_preserves_newest_suffix(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	u8 *payload;
	size_t written = 0;
	size_t offset = 0;
	int i;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_DOWNSIZE_CAPACITY,
			       GFP_KERNEL);
	payload = kunit_kzalloc(test, 32000, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_NOT_NULL(test, payload);

	pkm_kunit_reset_kmes();
	for (i = 0; i < 5; i++) {
		memset(payload, 0, 32000);
		payload[0] = (u8)(i + 1);
		pkm_kmes_emit_kernel(PKM_KMES_ORIGIN_KACS,
				     PKM_KUNIT_KMES_DIRECT_TYPE,
				     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1,
				     payload, 32000);
	}

	KUNIT_ASSERT_EQ(
		test,
		pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_DOWNSIZE_CAPACITY),
		0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer,
							  PKM_KUNIT_KMES_DOWNSIZE_CAPACITY,
							  &written, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.capacity,
			(u64)PKM_KUNIT_KMES_DOWNSIZE_CAPACITY);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 5ULL);

	for (i = 0; i < 4; i++) {
		KUNIT_ASSERT_TRUE(
			test,
			pkm_kunit_parse_kmes_event(buffer + offset,
						   written - offset, &view));
		KUNIT_EXPECT_EQ(test, view.sequence, (u64)(i + 2));
		KUNIT_EXPECT_EQ(test, view.payload_ptr[0], (u8)(i + 2));
		offset += view.event_size;
	}
	KUNIT_EXPECT_EQ(test, offset, written);

	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_swap_failed_allocation_keeps_live_ring(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot before = { };
	struct pkm_kmes_kunit_fd_snapshot after = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	int fd;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	memset(fds, 0xff, nr_cpu_ids * sizeof(*fds));

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_attach_for_token(token, fds, &count,
							&capacity),
			0L);
	fd = pkm_kunit_find_current_kmes_fd(test, fds, count, &before);
	KUNIT_ASSERT_GE(test, fd, 0);

	pkm_kmes_kunit_fail_next_swap_alloc();
	KUNIT_EXPECT_EQ(
		test,
		pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_SWAP_CAPACITY),
		-ENOMEM);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd, &after), 0);
	KUNIT_EXPECT_EQ(test, after.generation, before.generation);
	KUNIT_EXPECT_EQ(test, after.capacity, before.capacity);
	KUNIT_EXPECT_EQ(test, after.mapping_size, before.mapping_size);

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_user_success(struct kunit *test)
{
	static const u8 payload[] = { 0x81, 0xa1, 0x6b, 0xc0 };
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 buffer[128] = { 0 };
	size_t written = 0;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	ret = pkm_kmes_kunit_emit_for_token(
		token, PKM_KUNIT_KMES_USER_TYPE,
		sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_EQ(test, view.origin_class, PKM_KMES_ORIGIN_USERSPACE);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)PKM_KUNIT_KMES_USER_TYPE,
				  sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1);
	pkm_kunit_expect_bytes_eq(test, view.payload_ptr, view.payload_len,
				  payload, sizeof(payload));
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used &
				(PKM_KUNIT_SE_AUDIT_PRIVILEGE |
				 PKM_KUNIT_SE_TCB_PRIVILEGE),
			PKM_KUNIT_SE_AUDIT_PRIVILEGE |
				PKM_KUNIT_SE_TCB_PRIVILEGE);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_denies_before_usercopy(struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kacs_priv_adjust_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_AUDIT,
		.attributes = 0,
	};
	u64 previous_enabled = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_token_has_enabled_privilege(token,
						      PKM_KUNIT_SE_AUDIT_PRIVILEGE));
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_privs(token, &entry, 1,
						     &previous_enabled),
			0);
	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token, (const void __user *)1,
						     1, (const void __user *)1,
						     1),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_AUDIT_PRIVILEGE,
			0ULL);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_rejects_invalid_msgpack(struct kunit *test)
{
	static const u8 payload[] = { 0xc1 };
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload,
				sizeof(payload)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_size_check_precedes_usercopy(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token,
						     (const void __user *)1, 1,
						     (const void __user *)1,
						     65536U),
			(long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_rate_limit_denies_without_tcb(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u32 tokens = 99;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_refill_frozen(true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(0), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload,
				sizeof(payload)),
			(long)-EAGAIN);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_tcb_exempts_rate_limit(struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	u32 tokens = 99;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(0), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload,
				sizeof(payload)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 0U);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_batch_success_shared_timestamp(
	struct kunit *test)
{
	static const u8 payload0[] = { 0xc0 };
	static const u8 payload1[] = { 0x81, 0xa1, 0x78, 0x01 };
	struct kmes_emit_entry entries[] = {
		{
			.event_type = PKM_KUNIT_KMES_BATCH_TYPE0,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1,
			.payload = payload0,
			.payload_len = sizeof(payload0),
		},
		{
			.event_type = PKM_KUNIT_KMES_BATCH_TYPE1,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE1) - 1,
			.payload = payload1,
			.payload_len = sizeof(payload1),
		},
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	struct pkm_kunit_kmes_event_view second = { };
	u8 buffer[256] = { 0 };
	u32 emitted = 99;
	size_t written = 0;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	ret = pkm_kmes_kunit_emit_batch_for_token(token, entries,
						  ARRAY_SIZE(entries), &emitted);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, emitted, (u32)ARRAY_SIZE(entries));
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &first));
	KUNIT_ASSERT_TRUE(
		test,
		pkm_kunit_parse_kmes_event(buffer + first.event_size,
					   written - first.event_size, &second));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 2ULL);
	KUNIT_EXPECT_EQ(test, first.timestamp, second.timestamp);
	KUNIT_EXPECT_EQ(test, first.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, second.sequence, 2ULL);
	KUNIT_EXPECT_EQ(test, first.origin_class, PKM_KMES_ORIGIN_USERSPACE);
	KUNIT_EXPECT_EQ(test, second.origin_class, PKM_KMES_ORIGIN_USERSPACE);
	pkm_kunit_expect_bytes_eq(test, first.type_ptr, first.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE0,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1);
	pkm_kunit_expect_bytes_eq(test, second.type_ptr, second.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE1,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE1) - 1);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_batch_partial_refunds_unused_tokens(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	static const u8 bad_type[] = { 0x80 };
	struct kmes_emit_entry entries[] = {
		{
			.event_type = PKM_KUNIT_KMES_BATCH_TYPE0,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1,
			.payload = payload,
			.payload_len = sizeof(payload),
		},
		{
			.event_type = bad_type,
			.event_type_len = sizeof(bad_type),
			.payload = payload,
			.payload_len = sizeof(payload),
		},
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	u8 buffer[128] = { 0 };
	u32 emitted = 99;
	u32 tokens = 0;
	size_t written = 0;
	long ret;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_refill_frozen(true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(5), 0);
	ret = pkm_kmes_kunit_emit_batch_for_token(token, entries,
						  ARRAY_SIZE(entries), &emitted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, emitted, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &first));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	pkm_kunit_expect_bytes_eq(test, first.type_ptr, first.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE0,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_kmes_emit_batch_checks_emitted_out_before_entries(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_batch_user_for_token(
				token, (const struct kmes_emit_entry __user *)1,
				1, (u32 __user *)1),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_access_check_emits_to_kmes_without_sink(
	struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	size_t written = 0;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4104, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00060000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, NULL,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0x00020000U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
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
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"policy",
						 sizeof("policy") - 1));
}

static void pkm_kunit_access_check_failing_audit_sink_fails_closed(
	struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 args[136];
	u8 writebacks[12] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_fail_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00060000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, &sinks,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}

static void pkm_kunit_list_faults_on_results_write(struct kunit *test)
{
	static const u8 sd_bytes[] = {
		1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
		44, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0,
		4, 0, 32, 0, 1, 0, 0, 0,
		0, 0, 24, 0, 0, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0
	};
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kunit_event_counts counts = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_event_sink_ops sinks = {
		.ctx = &counts,
		.on_audit_event = pkm_kunit_on_audit_event,
		.on_privilege_use_event = pkm_kunit_on_privilege_use_event,
	};
	struct pkm_kacs_ingress_summary summary = { };
	const struct pkm_kacs_resolved_ctx *ctx;
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x11, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x22, 16);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(sd_bytes));
	pkm_kunit_write_u32(args, 20, 0x00020000);
	pkm_kunit_write_u32(args, 24, 0x00020000);
	pkm_kunit_write_u32(args, 28, 0x00040000);
	pkm_kunit_write_u32(args, 36, 0x00060000);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);
	pkm_kunit_write_u64(args, 88, 0x3000);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd_bytes, sizeof(sd_bytes));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));
	mem.regions[4].fault_write = true;

	ctx = kacs_rust_kunit_access_check_context();
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = pkm_kacs_access_check_ingress_list(&ops, 0x0100, 0x4000, 2, ctx,
						  &sinks, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
	KUNIT_EXPECT_EQ(test, counts.audit_events, 1U);
	KUNIT_EXPECT_EQ(test, counts.privilege_use_events, 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0x00020000U);
}

static void pkm_kunit_boot_system_defaults(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 logon_sid[] = {
		1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	static const u8 admin_sid[] = {
		1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
	};
	static const u8 everyone_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	};
	static const u8 auth_users_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0,
	};
	static const u8 local_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
	};
	static const char auth_pkg[] = "Negotiate";
	static const u32 expected_attrs[] = {
		0x0000000f,
		0x00000007,
		0x00000007,
		0x00000007,
		0xc0000007,
	};
	static const u8 *expected_group_sids[] = {
		admin_sid,
		everyone_sid,
		auth_users_sid,
		local_sid,
		logon_sid,
	};
	static const size_t expected_group_lens[] = {
		sizeof(admin_sid),
		sizeof(everyone_sid),
		sizeof(auth_users_sid),
		sizeof(local_sid),
		sizeof(logon_sid),
	};
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct pkm_kacs_boot_snapshot effective_snapshot = { };
	const void *effective_token;
	const void *primary_token;
	u32 i;

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_boot_snapshot(&snapshot));

	effective_token = pkm_kacs_current_effective_token_ptr();
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	KUNIT_EXPECT_PTR_EQ(test, effective_token, primary_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(effective_token,
							 &effective_snapshot));
	KUNIT_EXPECT_PTR_EQ(test, effective_snapshot.token_ptr, effective_token);
	KUNIT_EXPECT_EQ(test, snapshot.session_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.auth_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.token_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.modified_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type, 5U);
	pkm_kunit_expect_bytes_eq(test, snapshot.auth_pkg_ptr, snapshot.auth_pkg_len,
				  (const u8 *)auth_pkg, sizeof(auth_pkg) - 1);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr, snapshot.user_sid_len,
				  system_sid, sizeof(system_sid));
	pkm_kunit_expect_bytes_eq(test, snapshot.logon_sid_ptr,
				  snapshot.logon_sid_len, logon_sid,
				  sizeof(logon_sid));
	KUNIT_ASSERT_NOT_NULL(test, snapshot.groups_ptr);
	KUNIT_EXPECT_EQ(test, snapshot.group_count, 5U);
	for (i = 0; i < snapshot.group_count; i++) {
		KUNIT_EXPECT_EQ(test, snapshot.groups_ptr[i].attributes,
				expected_attrs[i]);
		pkm_kunit_expect_bytes_eq(test, snapshot.groups_ptr[i].sid_ptr,
					  snapshot.groups_ptr[i].sid_len,
					  expected_group_sids[i],
					  expected_group_lens[i]);
	}
	KUNIT_EXPECT_EQ(test, snapshot.owner_sid_index, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.primary_group_index, 1U);
	pkm_kunit_expect_bytes_eq(test, snapshot.default_dacl_ptr,
				  snapshot.default_dacl_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_present, 0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled, 0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled_by_default,
			0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.integrity_level, 16384U);
	KUNIT_EXPECT_EQ(test, snapshot.token_type, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.impersonation_level, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.mandatory_policy, 0x00000003U);
	KUNIT_EXPECT_EQ(test, snapshot.interactive_session_id, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_uid, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_gid, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.audit_policy, 0U);
	pkm_kunit_expect_boot_snapshot_eq(test, &snapshot, &effective_snapshot);
}

static void pkm_kunit_current_token_resolution(struct kunit *test)
{
	struct pkm_kacs_resolved_ctx effective = { };
	struct pkm_kacs_resolved_ctx primary = { };
	const void *effective_token;
	const void *primary_token;
	long ret;

	effective_token = pkm_kacs_current_effective_token_ptr();
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	ret = pkm_kacs_resolve_current_effective_ctx(&effective);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, effective.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_EQ(test, effective._reserved, 0U);
	KUNIT_EXPECT_PTR_EQ(test, effective.token, effective_token);
	KUNIT_EXPECT_PTR_EQ(test, effective.caap_cache, NULL);
	KUNIT_EXPECT_EQ(test, effective.default_pip_type, 0U);
	KUNIT_EXPECT_EQ(test, effective.default_pip_trust, 0U);

	ret = pkm_kacs_resolve_current_primary_ctx(&primary);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, primary.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_EQ(test, primary._reserved, 0U);
	KUNIT_EXPECT_PTR_EQ(test, primary.token, primary_token);
	KUNIT_EXPECT_PTR_EQ(test, primary.caap_cache, NULL);
	KUNIT_EXPECT_EQ(test, primary.default_pip_type, 0U);
	KUNIT_EXPECT_EQ(test, primary.default_pip_trust, 0U);
}

static void pkm_kunit_boot_allow_caps(struct kunit *test)
{
	const struct cred *cred = current_cred();
	kernel_cap_t empty = CAP_EMPTY_SET;

	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_CHOWN));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_DAC_OVERRIDE));
	KUNIT_EXPECT_TRUE(test,
			  cap_raised(cred->cap_effective, CAP_DAC_READ_SEARCH));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_FOWNER));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_FSETID));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_KILL));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_SETGID));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_SETUID));
	KUNIT_EXPECT_TRUE(test,
			  cap_raised(cred->cap_effective, CAP_NET_BROADCAST));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_IPC_OWNER));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_LEASE));

	KUNIT_EXPECT_EQ(test,
			memcmp(&cred->cap_effective, &cred->cap_permitted,
			       sizeof(kernel_cap_t)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(&cred->cap_effective, &cred->cap_inheritable,
			       sizeof(kernel_cap_t)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(&cred->cap_ambient, &empty, sizeof(kernel_cap_t)),
			0);
}

static void pkm_kunit_token_deep_copy_independent(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot original = { };
	struct pkm_kacs_boot_snapshot copied = { };
	const void *copy;

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_boot_snapshot(&original));

	copy = kacs_rust_token_deep_copy(original.token_ptr);
	KUNIT_ASSERT_NOT_NULL(test, copy);
	KUNIT_EXPECT_TRUE(test, copy != original.token_ptr);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(copy, &copied));

	pkm_kunit_expect_boot_snapshot_eq(test, &original, &copied);
	kacs_rust_token_drop(copy);
}

static void pkm_kunit_resolved_ctx_fails_closed_on_null_token(struct kunit *test)
{
	struct pkm_kacs_resolved_ctx ctx = {
		.kind = 99,
		._reserved = 99,
		.token = (void *)0x1,
		.caap_cache = (void *)0x2,
		.default_pip_type = 99,
		.default_pip_trust = 99,
	};
	long ret;

	ret = pkm_kacs_resolve_ctx_from_token(NULL, &ctx);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.kind, 99U);
	KUNIT_EXPECT_EQ(test, ctx._reserved, 99U);
	KUNIT_EXPECT_PTR_EQ(test, ctx.token, (void *)0x1);
	KUNIT_EXPECT_PTR_EQ(test, ctx.caap_cache, (void *)0x2);
	KUNIT_EXPECT_EQ(test, ctx.default_pip_type, 99U);
	KUNIT_EXPECT_EQ(test, ctx.default_pip_trust, 99U);
}

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

	fd = pkm_kacs_open_self_token_internal(KACS_REAL_TOKEN,
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

static void pkm_kunit_token_fd_holds_ref_after_source_drop(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot expected = { };
	struct pkm_kacs_boot_snapshot held = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token,
							 &expected));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	kacs_rust_token_drop(target_token);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token, &held));
	pkm_kunit_expect_boot_snapshot_eq(test, &expected, &held);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_open_self_token_invalid_flags(struct kunit *test)
{
	long ret;

	ret = pkm_kacs_open_self_token_internal(0x2, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
}

static void pkm_kunit_process_state_clone_thread_shares_live_object(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view current_view = { };
	struct pkm_kacs_kunit_process_state_view shared_view = { };
	const void *current_state;
	const void *shared_state;

	current_state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				current_state, &current_view),
			0);

	shared_state = pkm_kacs_kunit_inherit_current_process_state(
		CLONE_THREAD);
	KUNIT_ASSERT_NOT_NULL(test, shared_state);
	KUNIT_EXPECT_PTR_EQ(test, shared_state, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				shared_state, &shared_view),
			0);
	KUNIT_EXPECT_PTR_EQ(test, shared_view.rate_bucket_ptr,
			    current_view.rate_bucket_ptr);
	KUNIT_EXPECT_PTR_EQ(test, shared_view.process_sd_ptr,
			    current_view.process_sd_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				KACS_MIT_UI_ACCESS | KACS_MIT_WXP),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				shared_state, &shared_view),
			0);
	KUNIT_EXPECT_EQ(test, shared_view.mitigation_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_WXP);

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				shared_state, &shared_view),
			0);
	KUNIT_EXPECT_EQ(test, shared_view.pip_type,
			PKM_KUNIT_PIP_TYPE_PROTECTED);
	KUNIT_EXPECT_EQ(test, shared_view.pip_trust,
			PKM_KUNIT_PIP_TRUST_TEST);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(0),
			0);
	pkm_kacs_kunit_set_current_pip_context(0, 0);
	pkm_kacs_kunit_put_process_state(shared_state);
}

static void pkm_kunit_process_state_fork_gets_fresh_sd_and_rate_bucket(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view current_view = { };
	struct pkm_kacs_kunit_process_state_view child_view = { };
	const void *current_state;
	const void *child_state;

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	current_state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				current_state, &current_view),
			0);

	child_state = pkm_kacs_kunit_inherit_current_process_state(0);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(child_state,
							      &child_view),
			0);
	KUNIT_EXPECT_TRUE(test, child_state != current_state);
	KUNIT_EXPECT_TRUE(test,
			  child_view.rate_bucket_ptr !=
				  current_view.rate_bucket_ptr);
	KUNIT_EXPECT_TRUE(test,
			  child_view.process_sd_ptr !=
				  current_view.process_sd_ptr);
	KUNIT_EXPECT_EQ(test, child_view.pip_type,
			PKM_KUNIT_PIP_TYPE_PROTECTED);
	KUNIT_EXPECT_EQ(test, child_view.pip_trust,
			PKM_KUNIT_PIP_TRUST_TEST);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				KACS_MIT_UI_ACCESS | KACS_MIT_WXP),
			0);
	pkm_kacs_kunit_put_process_state(child_state);

	child_state = pkm_kacs_kunit_inherit_current_process_state(0);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(child_state,
							      &child_view),
			0);
	KUNIT_EXPECT_EQ(test, child_view.mitigation_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_WXP);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(0),
			0);
	pkm_kacs_kunit_set_current_pip_context(0, 0);
	pkm_kacs_kunit_put_process_state(child_state);
}

static void pkm_kunit_set_psb_self_supported_bits_success(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_WXP | KACS_MIT_UI_ACCESS |
					 KACS_MIT_NO_CHILD | KACS_MIT_PIE |
					 KACS_MIT_SML,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits, args.requested_mitigations);
}

static void pkm_kunit_set_psb_cross_process_success(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, resulting_bits, KACS_MIT_UI_ACCESS);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_set_psb_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0xDEADBEEFU;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xDEADBEEFU);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_set_psb_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0;
	long ret;

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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, resulting_bits, KACS_MIT_UI_ACCESS);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_set_psb_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_set_psb_cfi_alias_expands(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_CFI,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits,
			KACS_MIT_CFIF | KACS_MIT_CFIB);
}

static void pkm_kunit_set_psb_cfi_requires_cpu_support(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_CFI,
		.self_target = 1,
		.ibt_supported = 0,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0xABCDU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-ENODEV);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xABCDU);
}

static void pkm_kunit_set_psb_tlp_lsv_fail_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.initial_mitigation_bits = KACS_MIT_UI_ACCESS,
		.requested_mitigations = KACS_MIT_WXP | KACS_MIT_TLP,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0xBADCAFEU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADCAFEU);
}

static void pkm_kunit_set_psb_unknown_bits_fail_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_UI_ACCESS | 0x80000000U,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0xBADF00DU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADF00DU);
}

static void pkm_kunit_no_child_blocks_process_fork_only(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				KACS_MIT_NO_CHILD, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				KACS_MIT_NO_CHILD, CLONE_THREAD),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(0, 0),
			0);
}

static void pkm_kunit_wxp_rejects_wx_map_and_transition(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mmap(
				KACS_MIT_WXP, PROT_WRITE | PROT_EXEC),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mprotect(
				KACS_MIT_WXP, VM_WRITE, PROT_EXEC),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mprotect(
				KACS_MIT_WXP, VM_EXEC, PROT_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mmap(KACS_MIT_WXP, PROT_READ),
			0);
}

static void pkm_kunit_pie_rejects_et_exec(struct kunit *test)
{
	u8 exec_buf[18] = { 0x7f, 'E', 'L', 'F' };
	u8 pie_buf[18] = { 0x7f, 'E', 'L', 'F' };
	u8 script_buf[4] = { '#', '!', '/', 'b' };

	exec_buf[16] = ET_EXEC & 0xFF;
	exec_buf[17] = (ET_EXEC >> 8) & 0xFF;
	pie_buf[16] = ET_DYN & 0xFF;
	pie_buf[17] = (ET_DYN >> 8) & 0xFF;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_pie_bprm(KACS_MIT_PIE, exec_buf,
						      sizeof(exec_buf)),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_pie_bprm(KACS_MIT_PIE, pie_buf,
						      sizeof(pie_buf)),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_pie_bprm(KACS_MIT_PIE, script_buf,
						      sizeof(script_buf)),
			0);
}

static void pkm_kunit_task_prctl_sml_and_cfib_block_disable_paths(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_SML, PR_SET_SPECULATION_CTRL,
				PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 0, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_CFIB, ARCH_SHSTK_DISABLE, 0, 0, 0, 0),
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

static void pkm_kunit_signal_terminate_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_signal_info_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGWINCH;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_signal_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_signal_suspend_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGSTOP;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_signal_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_signal_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_signal_kernel_originated_bypasses_checks(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = {
		.kernel_originated = 1,
		.sig = SIGTERM,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args), 0L);
}

static void pkm_kunit_signal_unsupported_fails_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = {
		.sig = 0,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args),
			(long)-EACCES);
}

static void pkm_kunit_ptrace_read_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_ptrace_attach_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_ptrace_read_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_ptrace_attach_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_ptrace_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_ptrace_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_ptrace_unknown_mode_fails_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = {
		.mode = 0,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_ptrace_for_subject(&args),
			(long)-EACCES);
}

static void pkm_kunit_pidfd_getfd_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_pidfd_getfd_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_pidfd_getfd_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_pidfd_getfd_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_pidfd_open_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_pidfd_open_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_pidfd_open_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_pidfd_open_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_proc_metadata_query_limited_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_LIMITED;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_proc_metadata_query_limited_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_LIMITED;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_proc_metadata_query_information_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_INFORMATION;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_proc_metadata_query_information_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_INFORMATION;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_proc_metadata_query_mode_combo_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = {
		.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_LIMITED |
			PTRACE_MODE_PROC_QUERY_INFORMATION,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_ptrace_for_subject(&args),
			(long)-EACCES);
}

static void pkm_kunit_setnice_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_setscheduler_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_setioprio_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_process_setinfo_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
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
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_process_setinfo_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_process_setinfo_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_process_setinfo_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = {
		.self_target = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);
}

static void pkm_kunit_affinity_same_process_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = {
		.same_process = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			0L);
}

static void pkm_kunit_affinity_cross_process_success_with_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_affinity_cross_process_denied_without_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_affinity_debug_does_not_bypass_standalone_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
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
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used,
			before.privileges_used);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void
pkm_kunit_affinity_debug_plus_privilege_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE |
			PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);
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
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_DEBUG_PRIVILEGE |
				PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_affinity_privilege_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_prlimit_read_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_READ;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_prlimit_write_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_prlimit_read_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_READ;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_prlimit_write_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_prlimit_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

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
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_prlimit_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}

static void pkm_kunit_prlimit_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = {
		.self_target = 1,
		.flags = PKM_KUNIT_PRLIMIT_WRITE,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);
}

static void pkm_kunit_prlimit_unknown_flags_fail_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = {
		.flags = 0,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);
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
	KUNIT_EXPECT_GT(test, subset_len, (size_t)20);

	pkm_kacs_free((void *)subset);
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
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
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
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
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

static void pkm_kunit_set_process_sd_dacl_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(subject_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_query_limited_process_sd(
		subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}

static void pkm_kunit_set_process_sd_dacl_denied_without_write_dac(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &target_process_sd_len);
	input_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_set_process_sd_owner_self_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(subject_token,
								&target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}

static void pkm_kunit_set_process_sd_owner_foreign_denied(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *foreign_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	foreign_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, foreign_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(foreign_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(foreign_token);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_set_process_sd_label_requires_relabel(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_set_process_sd_label_with_privilege_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RELABEL_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_set_process_sd_cross_process_denied_by_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}

static void pkm_kunit_set_process_sd_sacl_label_combo_invalid(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION |
				 PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(subject_token,
								&target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EINVAL);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}

static void pkm_kunit_set_process_sd_mandatory_resource_attr_protected(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd =
		kacs_rust_kunit_create_process_sd_with_mandatory_resource_attr(
			target_token, &target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(target_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_token_duplicate_primary_to_impersonation(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_LEVEL_DELEGATION,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot original = { };
	struct pkm_kacs_boot_snapshot duplicate = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *subject_token;
	const void *creator_token;
	long source_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(creator_token,
							 &original));

	source_fd = pkm_kacs_open_self_token_internal(KACS_REAL_TOKEN,
						      KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token,
				creator_token, &args),
			0);
	KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(args.result_fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &duplicate));
	KUNIT_EXPECT_TRUE(test, view.token != creator_token);
	KUNIT_EXPECT_TRUE(test, duplicate.token_id != original.token_id);
	KUNIT_EXPECT_EQ(test, duplicate.modified_id, duplicate.token_id);
	KUNIT_EXPECT_EQ(test, duplicate.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, duplicate.impersonation_level,
			(u32)KACS_LEVEL_DELEGATION);
	pkm_kunit_expect_bytes_eq(test, duplicate.user_sid_ptr,
				  duplicate.user_sid_len,
				  original.user_sid_ptr,
				  original.user_sid_len);
	KUNIT_EXPECT_EQ(test, duplicate.privileges_present,
			original.privileges_present);
	KUNIT_EXPECT_EQ(test, duplicate.privileges_enabled,
			original.privileges_enabled);
	KUNIT_EXPECT_EQ(test, duplicate.privileges_enabled_by_default,
			original.privileges_enabled_by_default);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
}

static void pkm_kunit_token_duplicate_impersonation_level_escalation_fails_closed(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_LEVEL_IMPERSONATION,
		.result_fd = -1,
	};
	const void *source_token;
	const void *subject_token;
	const void *creator_token;
	long source_fd;
	long ret;

	source_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_IDENTIFICATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, source_token, KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_duplicate((int)source_fd, subject_token,
						 creator_token, &args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, args.result_fd, -1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(source_token);
}

static void pkm_kunit_token_duplicate_new_handle_checks_new_token_sd_against_subject(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_LEVEL_DELEGATION,
		.result_fd = -1,
	};
	const void *subject_token;
	const void *creator_token;
	long source_fd;
	long ret;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	source_fd = pkm_kacs_open_self_token_internal(KACS_REAL_TOKEN,
						      KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_duplicate((int)source_fd, subject_token,
						 creator_token, &args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, args.result_fd, -1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(subject_token);
}

static void pkm_kunit_token_impersonate_caps_identification_without_privilege(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
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
			(u32)KACS_LEVEL_IDENTIFICATION);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}

static void pkm_kunit_token_impersonate_integrity_ceiling_caps_identification(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_DELEGATION, PKM_KUNIT_IL_HIGH, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_LEVEL_IDENTIFICATION);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}

static void pkm_kunit_token_impersonate_same_user_restriction_mismatch_denies(
	struct kunit *test)
{
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 1, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}

static void pkm_kunit_token_impersonate_anonymous_bypasses_gates(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_LOW, 1, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_HIGH, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_LEVEL_ANONYMOUS);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
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
		KACS_LEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
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
			(u32)KACS_LEVEL_IMPERSONATION);

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

static void pkm_kunit_token_install_requires_assign_primary_handle(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after = { };
	const void *target_token;
	const void *primary_token;
	const void *state_ptr;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(primary_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &after),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after.state_ptr, before.state_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after.process_sd_ptr, before.process_sd_ptr);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_install_requires_assign_primary_privilege(
	struct kunit *test)
{
	const void *target_token;
	const void *caller_without_privilege;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	caller_without_privilege =
		kacs_rust_kunit_create_impersonation_variant_token(
			PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
			KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_NOT_NULL(test, caller_without_privilege);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, target_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)fd,
						 caller_without_privilege);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(caller_without_privilege);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_install_rejects_impersonation_token(
	struct kunit *test)
{
	const void *target_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, target_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_install_same_user_preserves_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after_install = { };
	struct pkm_kacs_kunit_process_state_view after_restore = { };
	const void *old_primary_token;
	const void *new_primary_token;
	const void *state_ptr;
	long old_fd;
	long install_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	old_fd = pkm_kacs_open_self_token_internal(KACS_REAL_TOKEN,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_install),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_install.state_ptr, before.state_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after_install.process_sd_ptr,
			    before.process_sd_ptr);
	KUNIT_EXPECT_EQ(test, after_install.process_sd_len,
			before.process_sd_len);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_restore),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_restore.state_ptr, before.state_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after_restore.process_sd_ptr,
			    before.process_sd_ptr);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(new_primary_token);
}

static void pkm_kunit_token_install_different_user_regenerates_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after_install = { };
	struct pkm_kacs_kunit_process_state_view after_restore = { };
	const void *old_primary_token;
	const void *new_primary_token;
	const void *state_ptr;
	long old_fd;
	long install_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	old_fd = pkm_kacs_open_self_token_internal(KACS_REAL_TOKEN,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_install),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_install.state_ptr, before.state_ptr);
	KUNIT_EXPECT_TRUE(test,
			  after_install.process_sd_ptr !=
				  before.process_sd_ptr);
	KUNIT_EXPECT_GT(test, after_install.process_sd_len, (size_t)0);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_restore),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_restore.state_ptr, before.state_ptr);
	KUNIT_EXPECT_TRUE(test,
			  after_restore.process_sd_ptr !=
				  after_install.process_sd_ptr);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(new_primary_token);
}

static void pkm_kunit_token_install_under_impersonation_revert_lands_on_new_primary(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *old_primary_token;
	const void *new_primary_token;
	const void *client_token;
	long old_fd;
	long install_fd;
	long impersonation_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);

	old_fd = pkm_kacs_open_self_token_internal(KACS_REAL_TOKEN,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_LEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);
	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)impersonation_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  old_primary_token);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)install_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  new_primary_token);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_LEVEL_IMPERSONATION);

	ret = pkm_kacs_revert_impersonation();
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(new_primary_token);
}

static void pkm_kunit_peer_socket_abstract_bind_stamps_once(struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view first = { };
	struct pkm_kacs_kunit_socket_view second = { };
	long ret;

	ret = pkm_kacs_kunit_bind_abstract_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), &first, &second);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, first.socket_sd_ptr);
	KUNIT_EXPECT_EQ(test, first.socket_sd_len, second.socket_sd_len);
	KUNIT_EXPECT_PTR_EQ(test, first.socket_sd_ptr, second.socket_sd_ptr);
	KUNIT_EXPECT_EQ(test, first.max_impersonation,
			(u32)KACS_LEVEL_IMPERSONATION);
}

static void pkm_kunit_peer_socket_set_level_updates_unconnected(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_STREAM, 0, KACS_LEVEL_IDENTIFICATION, &view);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_LEVEL_IDENTIFICATION);
}

static void pkm_kunit_peer_socket_set_level_invalid_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_STREAM, 0, 99U, &view);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_LEVEL_IMPERSONATION);
}

static void pkm_kunit_peer_socket_set_level_connected_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_STREAM, 1, KACS_LEVEL_DELEGATION, &view);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_LEVEL_IMPERSONATION);
}

static void pkm_kunit_peer_socket_capture_identification_on_seqpacket(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot current_snapshot = { };
	struct pkm_kacs_boot_snapshot captured = { };
	struct pkm_kacs_kunit_socket_view listener = { };
	struct pkm_kacs_kunit_socket_view accepted = { };
	const void *captured_token = NULL;
	long ret;

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &current_snapshot));

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_SEQPACKET,
		KACS_LEVEL_IDENTIFICATION, 0, 0, &captured_token,
		&listener, &accepted);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(captured_token,
							 &captured));
	KUNIT_EXPECT_PTR_EQ(test, listener.socket_sd_ptr, NULL);
	KUNIT_EXPECT_EQ(test, captured.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, captured.impersonation_level,
			(u32)KACS_LEVEL_IDENTIFICATION);
	pkm_kunit_expect_bytes_eq(test, captured.user_sid_ptr,
				  captured.user_sid_len,
				  current_snapshot.user_sid_ptr,
				  current_snapshot.user_sid_len);
	kacs_rust_token_drop(captured_token);
}

static void pkm_kunit_peer_socket_capture_anonymous_shape(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot captured = { };
	struct pkm_kacs_kunit_socket_view listener = { };
	struct pkm_kacs_kunit_socket_view accepted = { };
	const void *captured_token = NULL;
	u32 everyone_attributes = 0;
	long ret;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_LEVEL_ANONYMOUS, 0, 0, &captured_token,
		&listener, &accepted);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(captured_token,
							 &captured));
	pkm_kunit_expect_bytes_eq(test, captured.user_sid_ptr,
				  captured.user_sid_len,
				  pkm_kunit_anonymous_sid,
				  sizeof(pkm_kunit_anonymous_sid));
	KUNIT_EXPECT_EQ(test, captured.auth_id, 998ULL);
	KUNIT_EXPECT_EQ(test, captured.logon_type,
			(u32)PKM_KUNIT_LOGON_TYPE_NETWORK);
	KUNIT_EXPECT_EQ(test, captured.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, captured.impersonation_level,
			(u32)KACS_LEVEL_ANONYMOUS);
	KUNIT_EXPECT_EQ(test, captured.integrity_level,
			(u32)PKM_KUNIT_IL_UNTRUSTED);
	KUNIT_EXPECT_EQ(test, captured.privileges_present, 0ULL);
	KUNIT_EXPECT_EQ(test, captured.group_count, 1U);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_snapshot_has_group(
				  &captured, pkm_kunit_everyone_sid,
				  sizeof(pkm_kunit_everyone_sid),
				  &everyone_attributes));
	KUNIT_EXPECT_NE(test,
			everyone_attributes & PKM_KUNIT_SE_GROUP_ENABLED, 0U);
	KUNIT_EXPECT_FALSE(test,
			   pkm_kunit_snapshot_has_group(
				   &captured,
				   pkm_kunit_authenticated_users_sid,
				   sizeof(pkm_kunit_authenticated_users_sid),
				   NULL));
	kacs_rust_token_drop(captured_token);
}

static void pkm_kunit_peer_socket_abstract_connect_denied_without_write_data(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view listener = { };
	struct pkm_kacs_kunit_socket_view accepted = { };
	long ret;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_LEVEL_IMPERSONATION, 1, 0, NULL, &listener, &accepted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_ASSERT_NOT_NULL(test, listener.socket_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, accepted.peer_token, NULL);
}

static void pkm_kunit_peer_socket_open_token_fixed_rights(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	const void *captured_token = NULL;
	long ret;
	long fd;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_LEVEL_IMPERSONATION, 0, 0, &captured_token,
		NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	fd = pkm_kacs_kunit_open_peer_token_for_socket(1, captured_token);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_EQ(test, view.access_mask,
			KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(captured_token);
}

static void pkm_kunit_peer_socket_impersonate_success_and_revert(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *captured_token = NULL;
	const void *client_token;
	const void *primary_token;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_STREAM, KACS_LEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	ret = pkm_kacs_kunit_impersonate_peer_for_socket(1, captured_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &effective));
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_LEVEL_DELEGATION);
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
}

static void pkm_kunit_peer_socket_impersonate_caps_identification_without_privilege(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *captured_token = NULL;
	const void *server_token;
	const void *client_token;
	long token_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_STREAM, KACS_LEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	token_fd = pkm_kacs_kunit_open_peer_token_for_socket(1, captured_token);
	KUNIT_ASSERT_GE(test, token_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)token_fd, &view),
			0);
	KUNIT_EXPECT_EQ(test, view.access_mask,
			KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)token_fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &effective));
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_LEVEL_IDENTIFICATION);
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}

static void pkm_kunit_peer_socket_restricted_mismatch_hard_denies(
	struct kunit *test)
{
	const void *captured_token = NULL;
	const void *server_token;
	const void *client_token;
	long token_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 1, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_STREAM, KACS_LEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	token_fd = pkm_kacs_kunit_open_peer_token_for_socket(1, captured_token);
	KUNIT_ASSERT_GE(test, token_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)token_fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}

static void pkm_kunit_peer_socket_unsupported_or_uncaptured_fail_closed(
	struct kunit *test)
{
	long ret;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_DGRAM,
		KACS_LEVEL_IMPERSONATION, 0, 0, NULL, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_peer_token_for_socket(0, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_peer_token_for_socket(1, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_impersonate_peer_for_socket(0, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_impersonate_peer_for_socket(1, NULL),
			(long)-EACCES);
}

static void pkm_kunit_token_impersonate_rejects_primary_token(
	struct kunit *test)
{
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_LEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}

static void pkm_kunit_token_query_user_probe_and_payload(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_USER,
	};
	u8 buf[32] = { };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(system_sid));

	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(system_sid));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, system_sid,
				  sizeof(system_sid));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_groups_payload(struct kunit *test)
{
	static const u8 administrators_sid[] = {
		1, 2, 0, 0, 0, 0, 0, 5,
		32, 0, 0, 0, 32, 2, 0, 0,
	};
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_GROUPS,
		.buf_len = 160,
	};
	u8 buf[160] = { };
	u32 first_sid_len;
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 5U);

	first_sid_len = pkm_kunit_read_u32(buf, 4);
	KUNIT_ASSERT_EQ(test, first_sid_len, (u32)sizeof(administrators_sid));
	pkm_kunit_expect_bytes_eq(test, &buf[8], first_sid_len,
				  administrators_sid,
				  sizeof(administrators_sid));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 8 + first_sid_len),
			0x0000000FU);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_privileges_payload(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32,
	};
	u8 buf[32] = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);
	kacs_rust_token_drop(target_token);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 32U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0),
			PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8),
			PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16),
			PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 24), 0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_optional_empty_shapes(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_APPCONTAINER_SID,
	};
	u8 buf[4] = { 0xff, 0xff, 0xff, 0xff };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);

	args.token_class = TOKEN_CLASS_RESTRICTED_SIDS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 4U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_requires_cached_query(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_USER,
	};
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_invalid_class(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = 0,
	};
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EINVAL);

	args.token_class = 0x16;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_short_and_fault_buffers(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_USER,
		.buf_len = 1,
	};
	u8 buf[12] = { 0xaa };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, args.buf_len, 12U);
	KUNIT_EXPECT_EQ(test, buf[0], 0xaa);

	args.buf_len = sizeof(buf);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, args.buf_len, 12U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_query_deferred_fields_payload(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_OWNER,
	};
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 administrators_sid[] = {
		1, 2, 0, 0, 0, 0, 0, 5,
		32, 0, 0, 0, 32, 2, 0, 0,
	};
	u8 buf[64] = { };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(system_sid));
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, system_sid,
				  sizeof(system_sid));

	memset(buf, 0, sizeof(buf));
	args.token_class = TOKEN_CLASS_PRIMARY_GROUP;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(administrators_sid));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, administrators_sid,
				  sizeof(administrators_sid));

	memset(buf, 0xff, sizeof(buf));
	args.token_class = TOKEN_CLASS_STATISTICS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 40U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0), 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8), 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 24), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 28), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 32), 0ULL);

	memset(buf, 0, sizeof(buf));
	args.token_class = TOKEN_CLASS_DEFAULT_DACL;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)sizeof(pkm_kunit_system_default_dacl));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_token_adjust_sessionid_updates_target(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_SESSION_ID,
		.buf_len = 4,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_boot_snapshot caller_after = { };
	u8 buf[40] = { };
	const void *caller_token;
	const void *target_token;
	long fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_SESSIONID);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, caller_token, 7U),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, before.interactive_session_id, 0U);
	KUNIT_EXPECT_EQ(test, after.interactive_session_id, 7U);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 7U);

	memset(buf, 0, sizeof(buf));
	args.token_class = TOKEN_CLASS_STATISTICS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), after.modified_id);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(caller_token,
							 &caller_after));
	KUNIT_EXPECT_EQ(test,
			caller_after.privileges_used & PKM_KUNIT_SE_TCB_PRIVILEGE,
			PKM_KUNIT_SE_TCB_PRIVILEGE);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_sessionid_requires_cached_right(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *caller_token;
	const void *target_token;
	long fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(caller_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, caller_token, 9U),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.interactive_session_id,
			before.interactive_session_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_sessionid_requires_tcb(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const void *caller_without_tcb;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_SESSIONID);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, caller_without_tcb, 11U),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.interactive_session_id,
			before.interactive_session_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(caller_without_tcb);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_default_updates_fields(struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.owner_index = 1,
		.group_index = 2,
	};
	struct kacs_query_args args = {
		.buf_len = 64,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default(
				(int)fd, &adjust,
				pkm_kunit_replacement_default_dacl),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, before.owner_sid_index, 0U);
	KUNIT_EXPECT_EQ(test, after.owner_sid_index, 1U);
	KUNIT_EXPECT_EQ(test, before.primary_group_index, 1U);
	KUNIT_EXPECT_EQ(test, after.primary_group_index, 2U);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);
	pkm_kunit_expect_bytes_eq(test, after.default_dacl_ptr,
				  after.default_dacl_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	args.token_class = TOKEN_CLASS_OWNER;
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, after.groups_ptr[0].sid_len);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  after.groups_ptr[0].sid_ptr,
				  after.groups_ptr[0].sid_len);

	memset(buf, 0, sizeof(buf));
	args.token_class = TOKEN_CLASS_PRIMARY_GROUP;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, after.groups_ptr[1].sid_len);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  after.groups_ptr[1].sid_ptr,
				  after.groups_ptr[1].sid_len);

	memset(buf, 0, sizeof(buf));
	args.token_class = TOKEN_CLASS_DEFAULT_DACL;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)sizeof(pkm_kunit_replacement_default_dacl));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	memset(buf, 0, sizeof(buf));
	args.token_class = TOKEN_CLASS_STATISTICS;
	args.buf_len = 40;
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), after.modified_id);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_default_clear_dacl(struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = 0,
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_DEFAULT_DACL,
		.buf_len = 8,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[8] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.default_dacl_len, 0U);
	KUNIT_EXPECT_EQ(test, after.owner_sid_index, before.owner_sid_index);
	KUNIT_EXPECT_EQ(test, after.primary_group_index,
			before.primary_group_index);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_default_requires_cached_right(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.owner_index = 1,
		.group_index = 2,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_default_invalid_owner_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.owner_index = 2,
		.group_index = 0xFFFF,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_default_invalid_dacl_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = sizeof(pkm_kunit_invalid_default_dacl),
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default(
				(int)fd, &adjust, pkm_kunit_invalid_default_dacl),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_updates_and_queries_live_state(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 1, .enable = 1 },
	};
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_GROUPS,
		.buf_len = 160,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[160] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)0);
	KUNIT_EXPECT_EQ(test, adjust.previous_state,
			PKM_KUNIT_ADJUSTABLE_GROUP_PREV_MASK);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.group_count, 5U);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[0].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT &
				~PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[1].attributes,
			PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[2].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP2_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[3].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP3_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[4].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP4_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 5U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(buf, 0),
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT &
				~PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(buf, 1),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_reset_restores_defaults(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 1, .enable = 1 },
	};
	struct kacs_adjust_groups_args reset = {
		.count = 1,
	};
	struct kacs_group_entry reset_entry = {
		.index = 0xFFFFFFFFU,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot mutated = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &mutated));
	KUNIT_EXPECT_EQ(test, mutated.groups_ptr[0].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT &
				~PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, mutated.groups_ptr[1].attributes,
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &reset,
							     &reset_entry),
			(long)0);
	KUNIT_EXPECT_EQ(test, reset.previous_state,
			PKM_KUNIT_ADJUSTABLE_GROUP_MUTATED_MASK);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.groups_ptr[0].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[1].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP1_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[2].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP2_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[3].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP3_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[4].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP4_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 2);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_requires_cached_right(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 0,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_deny_only_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 2, .enable = 1 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_logon_sid_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 4, .enable = 0 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_user_sid_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 1,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_groups_invalid_reset_encoding_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0xFFFFFFFFU, .enable = 0 },
		{ .index = 0, .enable = 0 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_updates_and_queries_live_state(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 2,
	};
	struct kacs_priv_entry entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ENABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct kacs_query_args args = {
		.token_class = TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[32] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    entries),
			(long)0);
	KUNIT_EXPECT_EQ(test, adjust.previous_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_present,
			PKM_KUNIT_ADJUSTABLE_PRIV_PRESENT);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_ENABLE_DISABLE);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled_by_default,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED_BY_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.privileges_used, 0ULL);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 32U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0),
			PKM_KUNIT_ADJUSTABLE_PRIV_PRESENT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8),
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_ENABLE_DISABLE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16),
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED_BY_DEFAULT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 24), 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_remove_preserves_used_and_reset(
	struct kunit *test)
{
	struct kacs_adjust_privs_args remove = {
		.count = 1,
	};
	struct kacs_priv_entry remove_entry = {
		.luid = PKM_KUNIT_PRIV_LUID_REMOVE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_REMOVED,
	};
	struct kacs_adjust_privs_args mutate = {
		.count = 2,
	};
	struct kacs_priv_entry mutate_entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ENABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct kacs_adjust_privs_args reset = {
		.count = 1,
	};
	struct kacs_priv_entry reset_entry = {
		.luid = 0,
		.attributes = PKM_KUNIT_PRIV_RESET_ALL_DEFAULTS,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot removed = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_mark_privileges_used(
				  target_token,
				  1ULL << PKM_KUNIT_PRIV_LUID_REMOVE));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &remove,
							    &remove_entry),
			(long)0);
	KUNIT_EXPECT_EQ(test, remove.previous_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &removed));
	KUNIT_EXPECT_EQ(test, removed.privileges_present,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE);
	KUNIT_EXPECT_EQ(test, removed.privileges_enabled,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, removed.privileges_enabled_by_default,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test,
			removed.privileges_used &
				(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE),
			1ULL << PKM_KUNIT_PRIV_LUID_REMOVE);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &mutate,
							    mutate_entries),
			(long)0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &reset,
							    &reset_entry),
			(long)0);
	KUNIT_EXPECT_EQ(test, reset.previous_enabled,
			1ULL << PKM_KUNIT_PRIV_LUID_ENABLE);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_present,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled_by_default,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used &
				(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE),
			1ULL << PKM_KUNIT_PRIV_LUID_REMOVE);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 3);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_absent_disable_remove_noop(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 2,
	};
	struct kacs_priv_entry entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_ABSENT_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ABSENT_REMOVE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_REMOVED },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    entries),
			(long)0);
	KUNIT_EXPECT_EQ(test, adjust.previous_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_present, before.privileges_present);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled, before.privileges_enabled);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled_by_default,
			before.privileges_enabled_by_default);
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_requires_cached_right(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		.attributes = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_duplicate_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 2,
	};
	struct kacs_priv_entry entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_enable_absent_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_ABSENT_DISABLE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_invalid_reset_encoding_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = 1,
		.attributes = PKM_KUNIT_PRIV_RESET_ALL_DEFAULTS,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_adjust_privs_invalid_attributes_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED |
			      PKM_KUNIT_SE_PRIVILEGE_REMOVED,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_updates_query_and_source_unchanged(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.privs_to_delete = 1ULL << PKM_KUNIT_PRIV_LUID_REMOVE,
		.num_deny_indices = 1,
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args priv_query = {
		.token_class = TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32,
	};
	struct kacs_query_args group_query = {
		.token_class = TOKEN_CLASS_GROUPS,
		.buf_len = 256,
	};
	struct kacs_query_args restricted_query = {
		.token_class = TOKEN_CLASS_RESTRICTED_SIDS,
		.buf_len = 128,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[64] = { 0 };
	u8 priv_buf[32] = { 0 };
	u8 group_buf[256] = { 0 };
	u8 restricted_buf[128] = { 0 };
	const void *subject_token;
	const void *target_token;
	size_t first_group_attr_offset;
	size_t restricted_attr_offset;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, (u32[]){ 0U }, 1, before.groups_ptr, 1);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);

	priv_query.buf_ptr = (u64)(unsigned long)priv_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &priv_query, priv_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 0),
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 8),
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 16),
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 24), 0ULL);

	group_query.buf_ptr = (u64)(unsigned long)group_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &group_query, group_buf),
			(long)0);
	first_group_attr_offset = 4U + 4U + before.groups_ptr[0].sid_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u32(group_buf, first_group_attr_offset) &
				PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY,
			PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY);

	restricted_query.buf_ptr = (u64)(unsigned long)restricted_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &restricted_query,
						      restricted_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 0), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 4),
			(u32)before.groups_ptr[0].sid_len);
	pkm_kunit_expect_bytes_eq(test, restricted_buf + 8,
				  before.groups_ptr[0].sid_len,
				  before.groups_ptr[0].sid_ptr,
				  before.groups_ptr[0].sid_len);
	restricted_attr_offset = 8U + before.groups_ptr[0].sid_len;
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf,
						 restricted_attr_offset),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_intersects_existing_restricted_sids(
	struct kunit *test)
{
	struct kacs_restrict_args first = {
		.num_restrict_sids = 2,
		.result_fd = -1,
	};
	struct kacs_restrict_args second = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args restricted_query = {
		.token_class = TOKEN_CLASS_RESTRICTED_SIDS,
		.buf_len = 128,
	};
	struct pkm_kacs_boot_snapshot before = { };
	u8 first_payload[64] = { 0 };
	u8 second_payload[64] = { 0 };
	u8 restricted_buf[128] = { 0 };
	const void *subject_token;
	const void *target_token;
	const struct pkm_kacs_boot_group_view *everyone_group;
	size_t restricted_attr_offset;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	everyone_group = &before.groups_ptr[1];

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	first.data_len = pkm_kunit_build_restrict_payload(first_payload, NULL, 0,
							  before.groups_ptr, 2);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &first,
							first_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, first.result_fd, 0);

	second.data_len = pkm_kunit_build_restrict_payload(
		second_payload, NULL, 0, everyone_group, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(first.result_fd,
							subject_token,
							subject_token, &second,
							second_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, second.result_fd, 0);

	restricted_query.buf_ptr = (u64)(unsigned long)restricted_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(second.result_fd,
						      &restricted_query,
						      restricted_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 0), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 4),
			(u32)everyone_group->sid_len);
	pkm_kunit_expect_bytes_eq(test, restricted_buf + 8, everyone_group->sid_len,
				  everyone_group->sid_ptr,
				  everyone_group->sid_len);
	restricted_attr_offset = 8U + everyone_group->sid_len;
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf,
						 restricted_attr_offset),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_empty_intersection_fails_closed(
	struct kunit *test)
{
	struct kacs_restrict_args first = {
		.num_restrict_sids = 2,
		.result_fd = -1,
	};
	struct kacs_restrict_args second = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args restricted_query = {
		.token_class = TOKEN_CLASS_RESTRICTED_SIDS,
		.buf_len = 128,
	};
	struct pkm_kacs_boot_snapshot before = { };
	u8 first_payload[64] = { 0 };
	u8 second_payload[64] = { 0 };
	u8 restricted_buf[128] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_GE(test, before.group_count, 3U);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	first.data_len = pkm_kunit_build_restrict_payload(first_payload, NULL, 0,
							  before.groups_ptr, 2);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &first,
							first_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, first.result_fd, 0);

	second.data_len = pkm_kunit_build_restrict_payload(
		second_payload, NULL, 0, &before.groups_ptr[2], 1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(first.result_fd,
							subject_token,
							subject_token, &second,
							second_payload),
			(long)-EINVAL);

	restricted_query.buf_ptr = (u64)(unsigned long)restricted_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(first.result_fd,
						      &restricted_query,
						      restricted_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 0), 2U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_write_restricted_bypasses_read_pass(
	struct kunit *test)
{
	struct kacs_restrict_args restricted = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_restrict_args write_restricted = {
		.num_restrict_sids = 1,
		.flags = KACS_RESTRICT_WRITE_RESTRICTED,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	u8 payload[64] = { 0 };
	u32 granted = 0;
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restricted.data_len = pkm_kunit_build_restrict_payload(payload, NULL, 0,
							       before.groups_ptr, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restricted, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restricted.result_fd, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				restricted.result_fd, pkm_kunit_everyone_read_sd,
				sizeof(pkm_kunit_everyone_read_sd), &granted),
			(long)-EACCES);

	write_restricted.data_len = restricted.data_len;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&write_restricted,
							payload),
			(long)0);
	KUNIT_ASSERT_GE(test, write_restricted.result_fd, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				write_restricted.result_fd,
				pkm_kunit_everyone_read_sd,
				sizeof(pkm_kunit_everyone_read_sd), &granted),
			(long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)write_restricted.result_fd),
			0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restricted.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_requires_cached_duplicate(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(payload, NULL, 0,
							       before.groups_ptr, 1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_duplicate_deny_indices_fail_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 2,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[16] = { 0 };
	u32 deny_indices[2] = { 0U, 0U };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(payload, deny_indices,
							      2, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_reserved_flags_fail_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.flags = 0x2U,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_token_restrict_malformed_payload_fails_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(payload, NULL, 0,
							       before.groups_ptr, 1);
	payload[restrict_args.data_len] = 0xaa;
	restrict_args.data_len += 1;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_access_check_token_fd_current_effective(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long ret;

	pkm_kunit_build_read_control_args(args, -1);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
}

static void pkm_kunit_access_check_token_fd_explicit_handle(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long fd;
	long ret;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_read_control_args(args, (s32)fd);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_access_check_token_fd_invalid_negative(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
}

static const struct file_operations pkm_kunit_non_token_fops = { };

static void pkm_kunit_access_check_token_fd_rejects_non_token_fd(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	int fd;
	long ret;

	fd = anon_inode_getfd("pkm-kunit-not-token",
			      &pkm_kunit_non_token_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_GE(test, fd, 0);

	pkm_kunit_build_read_control_args(args, fd);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}

static void pkm_kunit_access_check_token_fd_bad_size_before_lookup(struct kunit *test)
{
	u8 args[136];
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	memset(args, 0, sizeof(args));
	pkm_kunit_write_u32(args, 0, 4);
	pkm_kunit_write_u32(args, 4, 123456U);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
}

static void pkm_kunit_access_check_token_fd_result_list(struct kunit *test)
{
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x33, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x44, 16);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));

	ret = pkm_kacs_access_check_ingress_list_with_token_fd(
		&ops, 0x0100, 0x4000, 2, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), 0U);
}

static void pkm_kunit_access_check_public_scalar_current_effective(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}

static void pkm_kunit_access_check_public_result_list(struct kunit *test)
{
	u8 object_tree[40] = { 0 };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 results[16] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_write_u16(object_tree, 0, 0);
	pkm_kunit_write_u16(object_tree, 2, 0);
	memset(object_tree + 4, 0x55, 16);
	pkm_kunit_write_u16(object_tree, 20, 1);
	pkm_kunit_write_u16(object_tree, 22, 0);
	memset(object_tree + 24, 0x66, 16);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u64(args, 56, 0x2000);
	pkm_kunit_write_u32(args, 64, 2);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x2000, object_tree, sizeof(object_tree));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));

	ret = pkm_kacs_kunit_access_check_syscall_list(&ops, 0x0100, 0x4000,
						       2);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 8),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 12), 0U);
}

static void pkm_kunit_access_check_public_invalid_token_fd(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -2);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
}

static void pkm_kunit_access_check_public_emits_to_kmes(
	struct kunit *test)
{
	u8 args[136];
	u8 writebacks[12] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	size_t written = 0;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u32(args, 4, (u32)-1);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);
	pkm_kunit_write_u64(args, 120, 0x3004);
	pkm_kunit_write_u64(args, 128, 0x3008);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000,
			      (u8 *)pkm_kunit_system_read_audit_sd,
			      sizeof(pkm_kunit_system_read_audit_sd));
	pkm_kunit_add_region(&mem, 0x3000, writebacks, sizeof(writebacks));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
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

static void pkm_kunit_access_check_privilege_use_emits_to_kmes(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const void *subject_token;
	const void *target_token;
	size_t written = 0;
	long fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4206, PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
				PKM_KUNIT_KMES_PRIV_PROCESS_PATH),
			0);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 0U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 1U);
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
				  (const u8 *)"privilege-use",
				  sizeof("privilege-use") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"SeSecurityPrivilege",
						 sizeof("SeSecurityPrivilege") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
						 sizeof(PKM_KUNIT_KMES_PRIV_PROCESS_NAME) - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)PKM_KUNIT_KMES_PRIV_PROCESS_PATH,
						 sizeof(PKM_KUNIT_KMES_PRIV_PROCESS_PATH) - 1));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_access_check_public_uses_psb_pip_default(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	u32 old_type = 0;
	u32 old_trust = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_pip_sd,
			      sizeof(pkm_kunit_system_pip_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}

static void pkm_kunit_access_check_public_uses_caap_cache(struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u32(args, 16, sizeof(pkm_kunit_caap_object_sd));
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_caap_object_sd,
			      sizeof(pkm_kunit_caap_object_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_kunit_access_check_syscall_scalar(&ops, 0x0100);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			PKM_KUNIT_CAAP_PRIVILEGE_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static void pkm_kunit_access_check_token_ctx_requires_caap_cache(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_resolved_ctx ctx = { };
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_resolve_current_effective_ctx(&ctx), 0L);
	KUNIT_ASSERT_EQ(test, ctx.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_PTR_EQ(test, ctx.caap_cache, NULL);

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, &ctx, NULL,
						    NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);
}

static void pkm_kunit_access_check_psb_pip_default_none_denies(
	struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(0, 0);

	ret = pkm_kunit_run_pip_labeled_access_check(0, 0, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);
}

static void pkm_kunit_access_check_uses_psb_pip_default(struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	ret = pkm_kunit_run_pip_labeled_access_check(0, 0, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
}

static void pkm_kunit_access_check_explicit_pip_overrides_psb(
	struct kunit *test)
{
	u32 old_type = 0;
	u32 old_trust = 0;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_type, &old_trust), 0);
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);

	ret = pkm_kunit_run_pip_labeled_access_check(1, 1, &granted);

	pkm_kacs_kunit_set_current_pip_context(old_type, old_trust);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);
}

static void pkm_kunit_access_check_marks_live_privilege_used(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, before.privileges_used, 0ULL);
	KUNIT_EXPECT_NE(test,
			summary.updated_privileges.used &
				PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_NE(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_access_check_copyout_fault_still_marks_used(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	mem.regions[2].fault_write = true;

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_NE(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_access_check_malformed_input_does_not_mark_used(
	struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_write_u32(args, 68, 1);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static void pkm_kunit_caap_cache_installed_policy_restricts(struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	ret = pkm_kunit_run_caap_access_check(&granted);

	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_PRIVILEGE_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static void pkm_kunit_caap_cache_replace_changes_future_decisions(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_ASSERT_EQ(test, ret, (long)-EACCES);
	KUNIT_ASSERT_EQ(test, granted, PKM_KUNIT_CAAP_PRIVILEGE_GRANT);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	granted = 0xffffffffU;
	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static void pkm_kunit_caap_cache_remove_uses_recovery_policy(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(spec, pkm_kunit_caap_empty_dacl,
					     sizeof(pkm_kunit_caap_empty_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)0);

	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
}

static void pkm_kunit_caap_cache_malformed_replace_keeps_old_policy(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	long ret;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			0);

	spec_len = pkm_kunit_build_caap_spec(spec, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   spec, (u32)spec_len),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static void pkm_kunit_set_caap_public_installs_and_marks_tcb_used(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & PKM_KUNIT_SE_TCB_PRIVILEGE,
			PKM_KUNIT_SE_TCB_PRIVILEGE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static void pkm_kunit_set_caap_public_denies_without_tcb(struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	const void *token;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)0);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_set_caap_public_checks_tcb_before_usercopy(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_user_for_token(
				token, (const void __user *)1,
				sizeof(pkm_kunit_caap_policy_sid),
				(const void __user *)1, 16),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)0);
	kacs_rust_token_drop(token);
}

static void pkm_kunit_set_caap_public_rejects_sid_bounds_before_copy(
	struct kunit *test)
{
	const void *token;

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_user_for_token(
				token, (const void __user *)1, 7, NULL, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_user_for_token(
				token, (const void __user *)1, 69,
				NULL, 0),
			(long)-EINVAL);
}

static void pkm_kunit_set_caap_public_malformed_keeps_old_policy(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	const void *token;
	long ret;

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			0);

	spec_len = pkm_kunit_build_caap_spec(spec, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static struct kunit_case pkm_kunit_cases[] = {
	KUNIT_CASE(pkm_kunit_probe_smoke),
	KUNIT_CASE(pkm_kunit_scalar_denied_writebacks),
	KUNIT_CASE(pkm_kunit_kmes_direct_emit_writes_single_event),
	KUNIT_CASE(pkm_kunit_kmes_direct_invalid_type_drops_structurally),
	KUNIT_CASE(pkm_kunit_kmes_attach_success_returns_cpu_fds),
	KUNIT_CASE(pkm_kunit_kmes_attach_erange_sets_required_count),
	KUNIT_CASE(pkm_kunit_kmes_attach_denies_without_security),
	KUNIT_CASE(pkm_kunit_kmes_attach_checks_privilege_before_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_attach_mapping_view_tracks_emission),
	KUNIT_CASE(pkm_kunit_kmes_swap_old_fd_freezes_and_new_attach_rebinds),
	KUNIT_CASE(pkm_kunit_kmes_swap_wakes_old_generation_waiter),
	KUNIT_CASE(pkm_kunit_kmes_swap_downsize_preserves_newest_suffix),
	KUNIT_CASE(pkm_kunit_kmes_swap_failed_allocation_keeps_live_ring),
	KUNIT_CASE(pkm_kunit_kmes_emit_user_success),
	KUNIT_CASE(pkm_kunit_kmes_emit_denies_before_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_emit_rejects_invalid_msgpack),
	KUNIT_CASE(pkm_kunit_kmes_emit_size_check_precedes_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_emit_rate_limit_denies_without_tcb),
	KUNIT_CASE(pkm_kunit_kmes_emit_tcb_exempts_rate_limit),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_success_shared_timestamp),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_partial_refunds_unused_tokens),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_checks_emitted_out_before_entries),
	KUNIT_CASE(pkm_kunit_access_check_emits_to_kmes_without_sink),
	KUNIT_CASE(pkm_kunit_access_check_failing_audit_sink_fails_closed),
	KUNIT_CASE(pkm_kunit_list_faults_on_results_write),
	KUNIT_CASE(pkm_kunit_boot_system_defaults),
	KUNIT_CASE(pkm_kunit_current_token_resolution),
	KUNIT_CASE(pkm_kunit_boot_allow_caps),
	KUNIT_CASE(pkm_kunit_token_deep_copy_independent),
	KUNIT_CASE(pkm_kunit_resolved_ctx_fails_closed_on_null_token),
	KUNIT_CASE(pkm_kunit_open_self_token_effective_query),
	KUNIT_CASE(pkm_kunit_open_self_token_real_generic_read),
	KUNIT_CASE(pkm_kunit_open_token_denied_by_own_sd),
	KUNIT_CASE(pkm_kunit_open_self_token_maximum_allowed),
	KUNIT_CASE(pkm_kunit_token_fd_holds_ref_after_source_drop),
	KUNIT_CASE(pkm_kunit_open_self_token_invalid_flags),
	KUNIT_CASE(pkm_kunit_process_state_clone_thread_shares_live_object),
	KUNIT_CASE(pkm_kunit_process_state_fork_gets_fresh_sd_and_rate_bucket),
	KUNIT_CASE(pkm_kunit_set_psb_self_supported_bits_success),
	KUNIT_CASE(pkm_kunit_set_psb_cross_process_success),
	KUNIT_CASE(pkm_kunit_set_psb_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_set_psb_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_set_psb_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_set_psb_cfi_alias_expands),
	KUNIT_CASE(pkm_kunit_set_psb_cfi_requires_cpu_support),
	KUNIT_CASE(pkm_kunit_set_psb_tlp_lsv_fail_closed),
	KUNIT_CASE(pkm_kunit_set_psb_unknown_bits_fail_closed),
	KUNIT_CASE(pkm_kunit_no_child_blocks_process_fork_only),
	KUNIT_CASE(pkm_kunit_wxp_rejects_wx_map_and_transition),
	KUNIT_CASE(pkm_kunit_pie_rejects_et_exec),
	KUNIT_CASE(pkm_kunit_task_prctl_sml_and_cfib_block_disable_paths),
	KUNIT_CASE(pkm_kunit_open_process_token_success),
	KUNIT_CASE(pkm_kunit_open_process_token_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_open_process_token_denied_by_target_token_sd),
	KUNIT_CASE(pkm_kunit_open_process_token_denied_by_pip),
	KUNIT_CASE(
		pkm_kunit_open_process_token_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_open_process_token_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_signal_terminate_success),
	KUNIT_CASE(pkm_kunit_signal_info_success),
	KUNIT_CASE(pkm_kunit_signal_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_signal_suspend_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_signal_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_signal_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_signal_kernel_originated_bypasses_checks),
	KUNIT_CASE(pkm_kunit_signal_unsupported_fails_closed),
	KUNIT_CASE(pkm_kunit_ptrace_read_success),
	KUNIT_CASE(pkm_kunit_ptrace_attach_success),
	KUNIT_CASE(pkm_kunit_ptrace_read_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_ptrace_attach_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_ptrace_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_ptrace_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_ptrace_unknown_mode_fails_closed),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_limited_success),
	KUNIT_CASE(
		pkm_kunit_proc_metadata_query_limited_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_information_success),
	KUNIT_CASE(
		pkm_kunit_proc_metadata_query_information_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_mode_combo_fails_closed),
	KUNIT_CASE(pkm_kunit_pidfd_open_success),
	KUNIT_CASE(pkm_kunit_pidfd_open_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_pidfd_open_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_pidfd_open_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_success),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_setnice_success),
	KUNIT_CASE(pkm_kunit_setscheduler_success),
	KUNIT_CASE(pkm_kunit_setioprio_success),
	KUNIT_CASE(pkm_kunit_process_setinfo_denied_by_process_sd),
	KUNIT_CASE(
		pkm_kunit_process_setinfo_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_process_setinfo_debug_still_fails_on_pip),
	KUNIT_CASE(
		pkm_kunit_process_setinfo_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_affinity_same_process_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_affinity_cross_process_success_with_privilege),
	KUNIT_CASE(pkm_kunit_affinity_cross_process_denied_without_privilege),
	KUNIT_CASE(
		pkm_kunit_affinity_debug_does_not_bypass_standalone_privilege),
	KUNIT_CASE(
		pkm_kunit_affinity_debug_plus_privilege_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_affinity_privilege_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_prlimit_read_success),
	KUNIT_CASE(pkm_kunit_prlimit_write_success),
	KUNIT_CASE(pkm_kunit_prlimit_read_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_prlimit_write_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_prlimit_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_prlimit_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_prlimit_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_prlimit_unknown_flags_fail_closed),
	KUNIT_CASE(pkm_kunit_get_process_sd_success),
	KUNIT_CASE(
		pkm_kunit_get_process_sd_label_on_unlabeled_returns_empty_subset),
	KUNIT_CASE(pkm_kunit_get_process_sd_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_get_process_sd_debug_does_not_bypass),
	KUNIT_CASE(pkm_kunit_set_process_sd_dacl_success),
	KUNIT_CASE(pkm_kunit_set_process_sd_dacl_denied_without_write_dac),
	KUNIT_CASE(pkm_kunit_set_process_sd_owner_self_success),
	KUNIT_CASE(pkm_kunit_set_process_sd_owner_foreign_denied),
	KUNIT_CASE(pkm_kunit_set_process_sd_label_requires_relabel),
	KUNIT_CASE(pkm_kunit_set_process_sd_label_with_privilege_succeeds),
	KUNIT_CASE(pkm_kunit_set_process_sd_cross_process_denied_by_pip),
	KUNIT_CASE(pkm_kunit_set_process_sd_sacl_label_combo_invalid),
	KUNIT_CASE(
		pkm_kunit_set_process_sd_mandatory_resource_attr_protected),
	KUNIT_CASE(pkm_kunit_token_duplicate_primary_to_impersonation),
	KUNIT_CASE(
		pkm_kunit_token_duplicate_impersonation_level_escalation_fails_closed),
	KUNIT_CASE(
		pkm_kunit_token_duplicate_new_handle_checks_new_token_sd_against_subject),
	KUNIT_CASE(
		pkm_kunit_token_impersonate_caps_identification_without_privilege),
	KUNIT_CASE(
		pkm_kunit_token_impersonate_integrity_ceiling_caps_identification),
	KUNIT_CASE(
		pkm_kunit_token_impersonate_same_user_restriction_mismatch_denies),
	KUNIT_CASE(pkm_kunit_token_impersonate_anonymous_bypasses_gates),
	KUNIT_CASE(
		pkm_kunit_open_current_thread_token_observes_effective_token_and_revert),
	KUNIT_CASE(pkm_kunit_token_install_requires_assign_primary_handle),
	KUNIT_CASE(pkm_kunit_token_install_requires_assign_primary_privilege),
	KUNIT_CASE(pkm_kunit_token_install_rejects_impersonation_token),
	KUNIT_CASE(pkm_kunit_token_install_same_user_preserves_process_sd),
	KUNIT_CASE(
		pkm_kunit_token_install_different_user_regenerates_process_sd),
	KUNIT_CASE(
		pkm_kunit_token_install_under_impersonation_revert_lands_on_new_primary),
	KUNIT_CASE(pkm_kunit_peer_socket_abstract_bind_stamps_once),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_updates_unconnected),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_invalid_fails_closed),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_connected_fails_closed),
	KUNIT_CASE(pkm_kunit_peer_socket_capture_identification_on_seqpacket),
	KUNIT_CASE(pkm_kunit_peer_socket_capture_anonymous_shape),
	KUNIT_CASE(
		pkm_kunit_peer_socket_abstract_connect_denied_without_write_data),
	KUNIT_CASE(pkm_kunit_peer_socket_open_token_fixed_rights),
	KUNIT_CASE(pkm_kunit_peer_socket_impersonate_success_and_revert),
	KUNIT_CASE(
		pkm_kunit_peer_socket_impersonate_caps_identification_without_privilege),
	KUNIT_CASE(pkm_kunit_peer_socket_restricted_mismatch_hard_denies),
	KUNIT_CASE(pkm_kunit_peer_socket_unsupported_or_uncaptured_fail_closed),
	KUNIT_CASE(pkm_kunit_token_impersonate_rejects_primary_token),
	KUNIT_CASE(pkm_kunit_token_query_user_probe_and_payload),
	KUNIT_CASE(pkm_kunit_token_query_groups_payload),
	KUNIT_CASE(pkm_kunit_token_query_privileges_payload),
	KUNIT_CASE(pkm_kunit_token_query_optional_empty_shapes),
	KUNIT_CASE(pkm_kunit_token_query_requires_cached_query),
	KUNIT_CASE(pkm_kunit_token_query_invalid_class),
	KUNIT_CASE(pkm_kunit_token_query_short_and_fault_buffers),
	KUNIT_CASE(pkm_kunit_token_query_deferred_fields_payload),
	KUNIT_CASE(pkm_kunit_token_adjust_sessionid_updates_target),
	KUNIT_CASE(pkm_kunit_token_adjust_sessionid_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_sessionid_requires_tcb),
	KUNIT_CASE(pkm_kunit_token_adjust_default_updates_fields),
	KUNIT_CASE(pkm_kunit_token_adjust_default_clear_dacl),
	KUNIT_CASE(pkm_kunit_token_adjust_default_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_default_invalid_owner_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_default_invalid_dacl_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_updates_and_queries_live_state),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_reset_restores_defaults),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_deny_only_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_logon_sid_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_user_sid_fails_closed),
	KUNIT_CASE(
		pkm_kunit_token_adjust_groups_invalid_reset_encoding_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_updates_and_queries_live_state),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_remove_preserves_used_and_reset),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_absent_disable_remove_noop),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_duplicate_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_enable_absent_fails_closed),
	KUNIT_CASE(
		pkm_kunit_token_adjust_privs_invalid_reset_encoding_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_invalid_attributes_fails_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_updates_query_and_source_unchanged),
	KUNIT_CASE(pkm_kunit_token_restrict_intersects_existing_restricted_sids),
	KUNIT_CASE(pkm_kunit_token_restrict_empty_intersection_fails_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_write_restricted_bypasses_read_pass),
	KUNIT_CASE(pkm_kunit_token_restrict_requires_cached_duplicate),
	KUNIT_CASE(
		pkm_kunit_token_restrict_duplicate_deny_indices_fail_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_reserved_flags_fail_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_malformed_payload_fails_closed),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_current_effective),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_explicit_handle),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_invalid_negative),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_rejects_non_token_fd),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_bad_size_before_lookup),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_result_list),
	KUNIT_CASE(pkm_kunit_access_check_public_scalar_current_effective),
	KUNIT_CASE(pkm_kunit_access_check_public_result_list),
	KUNIT_CASE(pkm_kunit_access_check_public_invalid_token_fd),
	KUNIT_CASE(pkm_kunit_access_check_public_emits_to_kmes),
	KUNIT_CASE(pkm_kunit_access_check_privilege_use_emits_to_kmes),
	KUNIT_CASE(pkm_kunit_access_check_public_uses_psb_pip_default),
	KUNIT_CASE(pkm_kunit_access_check_public_uses_caap_cache),
	KUNIT_CASE(pkm_kunit_access_check_token_ctx_requires_caap_cache),
	KUNIT_CASE(pkm_kunit_access_check_psb_pip_default_none_denies),
	KUNIT_CASE(pkm_kunit_access_check_uses_psb_pip_default),
	KUNIT_CASE(pkm_kunit_access_check_explicit_pip_overrides_psb),
	KUNIT_CASE(pkm_kunit_access_check_marks_live_privilege_used),
	KUNIT_CASE(pkm_kunit_access_check_copyout_fault_still_marks_used),
	KUNIT_CASE(pkm_kunit_access_check_malformed_input_does_not_mark_used),
	KUNIT_CASE(pkm_kunit_caap_cache_installed_policy_restricts),
	KUNIT_CASE(pkm_kunit_caap_cache_replace_changes_future_decisions),
	KUNIT_CASE(pkm_kunit_caap_cache_remove_uses_recovery_policy),
	KUNIT_CASE(pkm_kunit_caap_cache_malformed_replace_keeps_old_policy),
	KUNIT_CASE(pkm_kunit_set_caap_public_installs_and_marks_tcb_used),
	KUNIT_CASE(pkm_kunit_set_caap_public_denies_without_tcb),
	KUNIT_CASE(pkm_kunit_set_caap_public_checks_tcb_before_usercopy),
	KUNIT_CASE(pkm_kunit_set_caap_public_rejects_sid_bounds_before_copy),
	KUNIT_CASE(pkm_kunit_set_caap_public_malformed_keeps_old_policy),
	{}
};

static struct kunit_suite pkm_kunit_suite = {
	.name = "pkm_kunit_scaffold",
	.test_cases = pkm_kunit_cases,
};

kunit_test_suite(pkm_kunit_suite);
