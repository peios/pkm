// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM KUnit scaffold.
 *
 * This suite is intentionally tiny. It exists only to prove that PKM-owned
 * KUnit plumbing can execute a narrow C -> Rust -> kacs-core seam without
 * introducing live security semantics.
 */

#include <kunit/test.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "access_check.h"
#include "token_runtime.h"

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

static void pkm_kunit_on_audit_event(void *ctx,
				     const struct pkm_kacs_audit_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->audit_events++;
}

static void pkm_kunit_on_privilege_use_event(
	void *ctx, const struct pkm_kacs_privilege_use_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->privilege_use_events++;
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
	KUNIT_EXPECT_EQ(test, lhs->privileges_present, rhs->privileges_present);
	KUNIT_EXPECT_EQ(test, lhs->privileges_enabled, rhs->privileges_enabled);
	KUNIT_EXPECT_EQ(test, lhs->privileges_enabled_by_default,
			rhs->privileges_enabled_by_default);
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
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
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
						  NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)-EFAULT);
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
	KUNIT_EXPECT_EQ(test, snapshot.privileges_present, 0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled, 0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled_by_default,
			0xc000000ffffffffcULL);
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

	ret = pkm_kacs_resolve_current_primary_ctx(&primary);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, primary.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_EQ(test, primary._reserved, 0U);
	KUNIT_EXPECT_PTR_EQ(test, primary.token, primary_token);
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
	};
	long ret;

	ret = pkm_kacs_resolve_ctx_from_token(NULL, &ctx);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, ctx.kind, 99U);
	KUNIT_EXPECT_EQ(test, ctx._reserved, 99U);
	KUNIT_EXPECT_PTR_EQ(test, ctx.token, (void *)0x1);
}

static struct kunit_case pkm_kunit_cases[] = {
	KUNIT_CASE(pkm_kunit_probe_smoke),
	KUNIT_CASE(pkm_kunit_scalar_denied_writebacks),
	KUNIT_CASE(pkm_kunit_list_faults_on_results_write),
	KUNIT_CASE(pkm_kunit_boot_system_defaults),
	KUNIT_CASE(pkm_kunit_current_token_resolution),
	KUNIT_CASE(pkm_kunit_boot_allow_caps),
	KUNIT_CASE(pkm_kunit_token_deep_copy_independent),
	KUNIT_CASE(pkm_kunit_resolved_ctx_fails_closed_on_null_token),
	{}
};

static struct kunit_suite pkm_kunit_suite = {
	.name = "pkm_kunit_scaffold",
	.test_cases = pkm_kunit_cases,
};

kunit_test_suite(pkm_kunit_suite);
