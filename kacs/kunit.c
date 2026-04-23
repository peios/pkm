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
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#include "access_check.h"
#include "caap_cache.h"
#include "token_fd.h"
#include "token_runtime.h"

#define PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT \
	(KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC | \
	 KACS_ACCESS_ACCESS_SYSTEM_SECURITY)
#define PKM_KUNIT_CAAP_PRIVILEGE_GRANT KACS_ACCESS_ACCESS_SYSTEM_SECURITY
#define PKM_KUNIT_CAAP_READ_GRANT \
	(KACS_ACCESS_READ_CONTROL | KACS_ACCESS_ACCESS_SYSTEM_SECURITY)
#define PKM_KUNIT_PIP_TYPE_PROTECTED 512U
#define PKM_KUNIT_PIP_TRUST_TEST 5U
#define PKM_KUNIT_SE_TCB_PRIVILEGE (1ULL << 7)
#define PKM_KUNIT_SE_SECURITY_PRIVILEGE (1ULL << 8)
#define PKM_KUNIT_SYSTEM_PRIVILEGES_ALL 0xC000000FFFFFFFFCULL

extern size_t kacs_rust_kunit_probe(void);

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

static void pkm_kunit_expect_bytes_eq(struct kunit *test, const u8 *actual,
				      size_t actual_len, const u8 *expected,
				      size_t expected_len)
{
	KUNIT_ASSERT_EQ(test, actual_len, expected_len);
	KUNIT_EXPECT_EQ(test, memcmp(actual, expected, actual_len), 0);
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

static const u8 pkm_kunit_system_default_dacl[] = {
	2, 0, 52, 0, 2, 0, 0, 0,
	0, 0, 20, 0, 0, 0, 0, 16,
	1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	0, 0, 24, 0, 0, 0, 0, 16,
	1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
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

static void pkm_kunit_access_check_requires_audit_sink(struct kunit *test)
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
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
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

	ret = pkm_kacs_access_check_ingress_scalar(&ops, 0x0100, ctx, NULL,
						    &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
	KUNIT_EXPECT_EQ(test, summary.audit_event_count, 1U);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 0U);
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

static void pkm_kunit_access_check_public_requires_audit_transport(
	struct kunit *test)
{
	u8 args[136];
	u8 writebacks[12] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

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
	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 0), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 4), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(writebacks, 8), 0U);
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
	KUNIT_CASE(pkm_kunit_access_check_requires_audit_sink),
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
	KUNIT_CASE(pkm_kunit_access_check_token_fd_current_effective),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_explicit_handle),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_invalid_negative),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_rejects_non_token_fd),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_bad_size_before_lookup),
	KUNIT_CASE(pkm_kunit_access_check_token_fd_result_list),
	KUNIT_CASE(pkm_kunit_access_check_public_scalar_current_effective),
	KUNIT_CASE(pkm_kunit_access_check_public_result_list),
	KUNIT_CASE(pkm_kunit_access_check_public_invalid_token_fd),
	KUNIT_CASE(pkm_kunit_access_check_public_requires_audit_transport),
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
