// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


PKM_KUNIT_ASSERT_SIZE(struct kacs_query_args, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_query_args, token_class, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_query_args, buf_len, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_query_args, buf_ptr, 8);


PKM_KUNIT_ASSERT_SIZE(struct kacs_adjust_privs_args, 24);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_privs_args, count, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_privs_args, _pad, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_privs_args, data_ptr, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_privs_args, previous_enabled, 16);


PKM_KUNIT_ASSERT_SIZE(struct kacs_priv_entry, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_priv_entry, luid, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_priv_entry, attributes, 4);


PKM_KUNIT_ASSERT_SIZE(struct kacs_duplicate_args, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_duplicate_args, access_mask, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_duplicate_args, token_type, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_duplicate_args, impersonation_level, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_duplicate_args, result_fd, 12);


PKM_KUNIT_ASSERT_SIZE(struct kacs_adjust_groups_args, 144);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_groups_args, count, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_groups_args, _pad, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_groups_args, data_ptr, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_groups_args, previous_state, 16);


PKM_KUNIT_ASSERT_SIZE(struct kacs_group_entry, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_group_entry, index, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_group_entry, enable, 4);


PKM_KUNIT_ASSERT_SIZE(struct kacs_adjust_default_args, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_default_args, dacl_ptr, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_default_args, dacl_len, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_default_args, owner_index, 12);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_adjust_default_args, group_index, 14);


PKM_KUNIT_ASSERT_SIZE(struct kacs_restrict_args, 40);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, privs_to_delete, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, num_deny_indices, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, num_restrict_sids, 12);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, data_len, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, flags, 20);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, data_ptr, 24);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_restrict_args, result_fd, 32);


PKM_KUNIT_ASSERT_SIZE(struct kacs_link_tokens_args, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_link_tokens_args, elevated_fd, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_link_tokens_args, filtered_fd, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_link_tokens_args, session_id, 8);


PKM_KUNIT_ASSERT_SIZE(struct kacs_get_linked_token_args, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_get_linked_token_args, result_fd, 0);


PKM_KUNIT_ASSERT_SIZE(struct kacs_open_how, 32);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, desired_access, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, create_disposition, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, create_options, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, flags, 12);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, sd_ptr, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, sd_len, 24);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_open_how, __pad, 28);


PKM_KUNIT_ASSERT_SIZE(struct kacs_mount_policy_args, 32);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, policy, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, flags, 4);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, generation, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, __pad0, 12);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, template_sd_ptr, 16);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, template_sd_len, 24);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_mount_policy_args, __pad1, 28);


PKM_KUNIT_ASSERT_SIZE(struct kacs_node_result, 8);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_node_result, granted, 0);

PKM_KUNIT_ASSERT_OFFSET(struct kacs_node_result, status, 4);


PKM_KUNIT_ASSERT_IOC(KACS_IOC_QUERY, 0, _IOC_READ | _IOC_WRITE,
		     sizeof(struct kacs_query_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_ADJUST_PRIVS, 1, _IOC_WRITE,
		     sizeof(struct kacs_adjust_privs_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_DUPLICATE, 2, _IOC_READ | _IOC_WRITE,
		     sizeof(struct kacs_duplicate_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_INSTALL, 3, _IOC_NONE, 0);

PKM_KUNIT_ASSERT_IOC(KACS_IOC_RESTRICT, 4, _IOC_READ | _IOC_WRITE,
		     sizeof(struct kacs_restrict_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_LINK_TOKENS, 5, _IOC_WRITE,
		     sizeof(struct kacs_link_tokens_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_GET_LINKED_TOKEN, 6, _IOC_READ | _IOC_WRITE,
		     sizeof(struct kacs_get_linked_token_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_ADJUST_GROUPS, 7, _IOC_WRITE,
		     sizeof(struct kacs_adjust_groups_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_IMPERSONATE, 8, _IOC_NONE, 0);

PKM_KUNIT_ASSERT_IOC(KACS_IOC_ADJUST_DEFAULT, 9, _IOC_WRITE,
		     sizeof(struct kacs_adjust_default_args));

PKM_KUNIT_ASSERT_IOC(KACS_IOC_ADJUST_SESSIONID, 10, _IOC_WRITE, sizeof(u32));


bool pkm_kunit_mem_read(void *ctx, u64 user_ptr, void *dst, size_t len)
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


bool pkm_kunit_mem_write(void *ctx, u64 user_ptr, const void *src, size_t len)
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


bool pkm_kunit_on_audit_event(void *ctx,
				     const struct pkm_kacs_audit_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->audit_events++;
	return true;
}


bool pkm_kunit_on_privilege_use_event(
	void *ctx, const struct pkm_kacs_privilege_use_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->privilege_use_events++;
	return true;
}


bool pkm_kunit_fail_audit_event(
	void *ctx, const struct pkm_kacs_audit_event_view *event)
{
	struct pkm_kunit_event_counts *counts = ctx;

	counts->audit_events++;
	return false;
}


void pkm_kunit_add_region(struct pkm_kunit_mem *mem, u64 base, u8 *bytes,
				 size_t len)
{
	mem->regions[mem->count].base = base;
	mem->regions[mem->count].bytes = bytes;
	mem->regions[mem->count].len = len;
	mem->regions[mem->count].fault_read = false;
	mem->regions[mem->count].fault_write = false;
	mem->count++;
}


void pkm_kunit_write_u32(u8 *bytes, size_t offset, u32 value)
{
	bytes[offset + 0] = (u8)(value & 0xff);
	bytes[offset + 1] = (u8)((value >> 8) & 0xff);
	bytes[offset + 2] = (u8)((value >> 16) & 0xff);
	bytes[offset + 3] = (u8)((value >> 24) & 0xff);
}


void pkm_kunit_write_u64(u8 *bytes, size_t offset, u64 value)
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


void pkm_kunit_write_u16(u8 *bytes, size_t offset, u16 value)
{
	bytes[offset + 0] = (u8)(value & 0xff);
	bytes[offset + 1] = (u8)((value >> 8) & 0xff);
}


size_t pkm_kunit_utf16_cstr_len(const char *value)
{
	size_t len = 2U;

	if (!value)
		return 0;

	while (*value++) {
		if (len > SIZE_MAX - 2U)
			return 0;
		len += 2U;
	}

	return len;
}


void pkm_kunit_write_utf16_cstr(u8 *bytes, size_t offset,
				       const char *value)
{
	while (value && *value) {
		pkm_kunit_write_u16(bytes, offset, (u16)(u8)*value);
		offset += 2U;
		value++;
	}

	pkm_kunit_write_u16(bytes, offset, 0U);
}


size_t pkm_kunit_build_claim_entry_empty(u8 *dst, size_t dst_len,
						const char *name, u16 value_type,
						u32 flags)
{
	size_t name_len;
	size_t total_len;

	if (!dst || !name)
		return 0;

	name_len = pkm_kunit_utf16_cstr_len(name);
	if (!name_len)
		return 0;

	total_len = 16U + name_len;
	if (total_len > dst_len)
		return 0;

	memset(dst, 0, total_len);
	pkm_kunit_write_u32(dst, 0, 16U);
	pkm_kunit_write_u16(dst, 4, value_type);
	pkm_kunit_write_u32(dst, 8, flags);
	pkm_kunit_write_u32(dst, 12, 0U);
	pkm_kunit_write_utf16_cstr(dst, 16U, name);
	return total_len;
}


size_t pkm_kunit_build_claim_entry_scalar(u8 *dst, size_t dst_len,
						 const char *name, u16 value_type,
						 u32 flags, u64 value)
{
	size_t name_len;
	size_t name_offset = 20U;
	size_t value_offset;
	size_t total_len;

	if (!dst || !name)
		return 0;
	if (value_type != PKM_KUNIT_CLAIM_TYPE_INT64 &&
	    value_type != PKM_KUNIT_CLAIM_TYPE_UINT64 &&
	    value_type != PKM_KUNIT_CLAIM_TYPE_BOOLEAN)
		return 0;

	name_len = pkm_kunit_utf16_cstr_len(name);
	if (!name_len)
		return 0;

	value_offset = name_offset + name_len;
	total_len = value_offset + sizeof(u64);
	if (total_len > dst_len)
		return 0;

	memset(dst, 0, total_len);
	pkm_kunit_write_u32(dst, 0, (u32)name_offset);
	pkm_kunit_write_u16(dst, 4, value_type);
	pkm_kunit_write_u32(dst, 8, flags);
	pkm_kunit_write_u32(dst, 12, 1U);
	pkm_kunit_write_u32(dst, 16, (u32)value_offset);
	pkm_kunit_write_utf16_cstr(dst, name_offset, name);
	pkm_kunit_write_u64(dst, value_offset, value);
	return total_len;
}


size_t pkm_kunit_build_claim_entry_string(u8 *dst, size_t dst_len,
						 const char *name, u32 flags,
						 const char *value)
{
	size_t name_len;
	size_t string_len;
	size_t name_offset = 20U;
	size_t slot_offset;
	size_t string_offset;
	size_t total_len;

	if (!dst || !name || !value)
		return 0;

	name_len = pkm_kunit_utf16_cstr_len(name);
	string_len = pkm_kunit_utf16_cstr_len(value);
	if (!name_len || !string_len)
		return 0;

	slot_offset = name_offset + name_len;
	string_offset = slot_offset + sizeof(u32);
	total_len = string_offset + string_len;
	if (total_len > dst_len)
		return 0;

	memset(dst, 0, total_len);
	pkm_kunit_write_u32(dst, 0, (u32)name_offset);
	pkm_kunit_write_u16(dst, 4, PKM_KUNIT_CLAIM_TYPE_STRING);
	pkm_kunit_write_u32(dst, 8, flags);
	pkm_kunit_write_u32(dst, 12, 1U);
	pkm_kunit_write_u32(dst, 16, (u32)slot_offset);
	pkm_kunit_write_utf16_cstr(dst, name_offset, name);
	pkm_kunit_write_u32(dst, slot_offset, (u32)string_offset);
	pkm_kunit_write_utf16_cstr(dst, string_offset, value);
	return total_len;
}


size_t pkm_kunit_build_claim_entry_sid(u8 *dst, size_t dst_len,
					      const char *name, u32 flags,
					      const u8 *sid, size_t sid_len)
{
	size_t name_len;
	size_t name_offset = 20U;
	size_t slot_offset;
	size_t sid_offset;
	size_t total_len;

	if (!dst || !name || !sid || !sid_len)
		return 0;

	name_len = pkm_kunit_utf16_cstr_len(name);
	if (!name_len)
		return 0;

	slot_offset = name_offset + name_len;
	sid_offset = slot_offset + sizeof(u32);
	total_len = sid_offset + sid_len;
	if (total_len > dst_len)
		return 0;

	memset(dst, 0, total_len);
	pkm_kunit_write_u32(dst, 0, (u32)name_offset);
	pkm_kunit_write_u16(dst, 4, PKM_KUNIT_CLAIM_TYPE_SID);
	pkm_kunit_write_u32(dst, 8, flags);
	pkm_kunit_write_u32(dst, 12, 1U);
	pkm_kunit_write_u32(dst, 16, (u32)slot_offset);
	pkm_kunit_write_utf16_cstr(dst, name_offset, name);
	pkm_kunit_write_u32(dst, slot_offset, (u32)sid_offset);
	memcpy(dst + sid_offset, sid, sid_len);
	return total_len;
}


size_t pkm_kunit_build_claim_entry_octet(u8 *dst, size_t dst_len,
						const char *name, u32 flags,
						const u8 *value, size_t value_len)
{
	size_t name_len;
	size_t name_offset = 20U;
	size_t slot_offset;
	size_t octet_offset;
	size_t total_len;

	if (!dst || !name || (!value && value_len))
		return 0;

	name_len = pkm_kunit_utf16_cstr_len(name);
	if (!name_len)
		return 0;

	slot_offset = name_offset + name_len;
	octet_offset = slot_offset + sizeof(u32);
	total_len = octet_offset + sizeof(u32) + value_len;
	if (total_len > dst_len)
		return 0;

	memset(dst, 0, total_len);
	pkm_kunit_write_u32(dst, 0, (u32)name_offset);
	pkm_kunit_write_u16(dst, 4, PKM_KUNIT_CLAIM_TYPE_OCTET);
	pkm_kunit_write_u32(dst, 8, flags);
	pkm_kunit_write_u32(dst, 12, 1U);
	pkm_kunit_write_u32(dst, 16, (u32)slot_offset);
	pkm_kunit_write_utf16_cstr(dst, name_offset, name);
	pkm_kunit_write_u32(dst, slot_offset, (u32)octet_offset);
	pkm_kunit_write_u32(dst, octet_offset, (u32)value_len);
	if (value_len)
		memcpy(dst + octet_offset + sizeof(u32), value, value_len);
	return total_len;
}


int pkm_kunit_append_claim_entry(u8 *dst, size_t dst_len,
					size_t *offset_io, const u8 *entry,
					size_t entry_len)
{
	size_t total_len;

	if (!dst || !offset_io || !entry || !entry_len || entry_len > U32_MAX)
		return -EINVAL;

	total_len = sizeof(u32) + entry_len;
	if (*offset_io > dst_len || total_len > dst_len - *offset_io)
		return -EINVAL;

	pkm_kunit_write_u32(dst, *offset_io, (u32)entry_len);
	memcpy(dst + *offset_io + sizeof(u32), entry, entry_len);
	*offset_io += total_len;
	return 0;
}


u32 pkm_kunit_read_u32(const u8 *bytes, size_t offset)
{
	return (u32)bytes[offset + 0] |
	       ((u32)bytes[offset + 1] << 8) |
	       ((u32)bytes[offset + 2] << 16) |
	       ((u32)bytes[offset + 3] << 24);
}


u16 pkm_kunit_read_u16(const u8 *bytes, size_t offset)
{
	return (u16)bytes[offset + 0] | ((u16)bytes[offset + 1] << 8);
}


void pkm_kunit_make_sd_ownerless(u8 *sd)
{
	if (!sd)
		return;

	pkm_kunit_write_u32(sd, 4, 0);
}


void pkm_kunit_make_sd_groupless(u8 *sd)
{
	if (!sd)
		return;

	pkm_kunit_write_u32(sd, 8, 0);
}


size_t pkm_kunit_build_owner_subset_sd(u8 *dst, size_t dst_len,
					      const u8 *owner_sid,
					      size_t owner_sid_len)
{
	size_t total_len = 20U + owner_sid_len;

	if (!dst || !owner_sid || !owner_sid_len || total_len > dst_len)
		return 0;

	memset(dst, 0, total_len);
	dst[0] = 1;
	pkm_kunit_write_u16(dst, 2, PKM_KUNIT_SE_SELF_RELATIVE);
	pkm_kunit_write_u32(dst, 4, 20U);
	memcpy(dst + 20U, owner_sid, owner_sid_len);
	return total_len;
}


void pkm_kunit_set_sd_rm_control(u8 *sd, u8 value)
{
	pkm_kunit_write_u16(sd, 2,
			    pkm_kunit_read_u16(sd, 2) |
				    PKM_KUNIT_SE_RM_CONTROL_VALID);
	sd[1] = value;
}


void pkm_kunit_expect_sd_rm_control(struct kunit *test, const u8 *sd,
					   u8 value)
{
	KUNIT_EXPECT_EQ(test, sd[1], value);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u16(sd, 2) &
				PKM_KUNIT_SE_RM_CONTROL_VALID,
			PKM_KUNIT_SE_RM_CONTROL_VALID);
}


void pkm_kunit_set_sd_dacl_reserved_fields(u8 *sd, u8 sbz1, u16 sbz2)
{
	u32 dacl_offset;

	if (!sd)
		return;

	dacl_offset = pkm_kunit_read_u32(sd, 16);
	if (dacl_offset == 0)
		return;

	sd[dacl_offset + 1] = sbz1;
	pkm_kunit_write_u16(sd, dacl_offset + 6, sbz2);
}


void pkm_kunit_expect_sd_dacl_reserved_fields(struct kunit *test,
						     const u8 *sd, u8 sbz1,
						     u16 sbz2)
{
	u32 dacl_offset;

	KUNIT_ASSERT_NOT_NULL(test, sd);
	dacl_offset = pkm_kunit_read_u32(sd, 16);
	KUNIT_ASSERT_NE(test, dacl_offset, 0U);
	KUNIT_EXPECT_EQ(test, sd[dacl_offset + 1], sbz1);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u16(sd, dacl_offset + 6), sbz2);
}


void pkm_kunit_expect_sd_sid_component(struct kunit *test, const u8 *sd,
					      size_t sd_len, size_t offset,
					      const u8 *expected_sid,
					      size_t expected_sid_len)
{
	u32 sid_offset;

	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_NOT_NULL(test, expected_sid);
	sid_offset = pkm_kunit_read_u32(sd, offset);
	KUNIT_ASSERT_NE(test, sid_offset, 0U);
	KUNIT_ASSERT_LE(test, (size_t)sid_offset + expected_sid_len, sd_len);
	pkm_kunit_expect_bytes_eq(test, sd + sid_offset, expected_sid_len,
				  expected_sid, expected_sid_len);
}


void pkm_kunit_expect_stored_sd_has_owner(struct kunit *test,
						 const u8 *sd, size_t sd_len)
{
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, (long)sd_len, 20L);
	KUNIT_EXPECT_EQ(test, kacs_rust_validate_stored_sd_bytes(sd, sd_len),
			0);
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u32(sd, 4), 0U);
}


const u8 *pkm_kunit_dacl_ace_const(const u8 *sd, size_t sd_len,
					  u16 target_index)
{
	const u8 *ace;
	u32 dacl_offset;
	u16 ace_count;
	u16 i;

	if (!sd)
		return NULL;
	dacl_offset = pkm_kunit_read_u32(sd, 16);
	if (dacl_offset == 0 || dacl_offset + 8 > sd_len)
		return NULL;
	ace_count = pkm_kunit_read_u16(sd, dacl_offset + 4);
	if (target_index >= ace_count)
		return NULL;

	ace = sd + dacl_offset + 8;
	for (i = 0; i < target_index; i++) {
		u16 ace_size;

		if (ace + 4 > sd + sd_len)
			return NULL;
		ace_size = pkm_kunit_read_u16(ace, 2);
		if (ace_size < 8 || ace + ace_size > sd + sd_len)
			return NULL;
		ace += ace_size;
	}

	return ace;
}


u8 *pkm_kunit_dacl_ace(u8 *sd, size_t sd_len, u16 target_index)
{
	return (u8 *)pkm_kunit_dacl_ace_const(sd, sd_len, target_index);
}


void pkm_kunit_set_dacl_ace_header(u8 *sd, size_t sd_len,
					  u16 index, u8 ace_type,
					  u8 ace_flags, u32 mask)
{
	u8 *ace;

	ace = pkm_kunit_dacl_ace(sd, sd_len, index);
	if (!ace)
		return;

	ace[0] = ace_type;
	ace[1] = ace_flags;
	pkm_kunit_write_u32(ace, 4, mask);
}


void pkm_kunit_set_dacl_ace_sid(struct kunit *test, u8 *sd,
				       size_t sd_len, u16 index,
				       const u8 *sid, size_t sid_len)
{
	u8 *ace;

	KUNIT_ASSERT_NOT_NULL(test, sid);
	ace = pkm_kunit_dacl_ace(sd, sd_len, index);
	KUNIT_ASSERT_NOT_NULL(test, ace);
	KUNIT_ASSERT_EQ(test, pkm_kunit_read_u16(ace, 2),
			(u16)(8U + sid_len));

	memcpy(ace + 8, sid, sid_len);
}


void pkm_kunit_expect_dacl_ace_header(struct kunit *test, const u8 *sd,
					     size_t sd_len, u16 index,
					     u8 ace_type, u8 ace_flags,
					     u32 mask)
{
	const u8 *ace;

	ace = pkm_kunit_dacl_ace_const(sd, sd_len, index);
	KUNIT_ASSERT_NOT_NULL(test, ace);
	KUNIT_EXPECT_EQ(test, ace[0], ace_type);
	KUNIT_EXPECT_EQ(test, ace[1], ace_flags);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(ace, 4), mask);
}


void pkm_kunit_expect_allow_ace(struct kunit *test, const u8 *sd,
				       size_t sd_len, u16 index, u32 mask,
				       const u8 *sid, size_t sid_len)
{
	const u8 *ace = pkm_kunit_dacl_ace_const(sd, sd_len, index);

	KUNIT_ASSERT_NOT_NULL(test, ace);
	KUNIT_EXPECT_EQ(test, ace[0], 0x00);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(ace, 4), mask);
	pkm_kunit_expect_bytes_eq(test, ace + 8, sid_len, sid, sid_len);
}


void pkm_kunit_expect_owner_rights_read_control_ace(
	struct kunit *test, const u8 *sd, size_t sd_len, u16 index)
{
	pkm_kunit_expect_allow_ace(test, sd, sd_len, index,
				   KACS_ACCESS_READ_CONTROL,
				   pkm_kunit_owner_rights_sid,
				   sizeof(pkm_kunit_owner_rights_sid));
}


u64 pkm_kunit_read_u64(const u8 *bytes, size_t offset)
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


u32 pkm_kunit_query_token_u32(struct kunit *test, int fd, u32 token_class)
{
	struct kacs_query_args args = {
		.token_class = token_class,
		.buf_len = 4,
	};
	u8 buf[4] = { 0 };

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(fd, &args, buf),
			(long)0);
	KUNIT_ASSERT_EQ(test, args.buf_len, 4U);
	return pkm_kunit_read_u32(buf, 0);
}


u32 pkm_kunit_groups_query_attr(const u8 *bytes, u32 index)
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


void pkm_kunit_expect_bytes_eq(struct kunit *test, const u8 *actual,
				      size_t actual_len, const u8 *expected,
				      size_t expected_len)
{
	KUNIT_ASSERT_EQ(test, actual_len, expected_len);
	KUNIT_EXPECT_EQ(test, memcmp(actual, expected, actual_len), 0);
}


void pkm_kunit_expect_token_query_payload_eq(struct kunit *test,
						    int lhs_fd, int rhs_fd,
						    u32 token_class)
{
	struct kacs_query_args lhs = {
		.token_class = token_class,
	};
	struct kacs_query_args rhs = {
		.token_class = token_class,
	};
	u8 *lhs_buf;
	u8 *rhs_buf;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(lhs_fd, &lhs, NULL),
			(long)0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(rhs_fd, &rhs, NULL),
			(long)0);
	KUNIT_ASSERT_EQ(test, lhs.buf_len, rhs.buf_len);
	if (!lhs.buf_len)
		return;

	lhs_buf = kunit_kzalloc(test, lhs.buf_len, GFP_KERNEL);
	rhs_buf = kunit_kzalloc(test, rhs.buf_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, lhs_buf);
	KUNIT_ASSERT_NOT_NULL(test, rhs_buf);

	lhs.buf_ptr = (u64)(unsigned long)lhs_buf;
	rhs.buf_ptr = (u64)(unsigned long)rhs_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(lhs_fd, &lhs, lhs_buf),
			(long)0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(rhs_fd, &rhs, rhs_buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, lhs_buf, lhs.buf_len, rhs_buf,
				  rhs.buf_len);
}


bool pkm_kunit_snapshot_has_group(
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


void pkm_kunit_fill_group_limit_specs(
	struct pkm_kunit_sid_attr_spec *groups, u32 count)
{
	u32 i;

	for (i = 0; i < count; i++) {
		groups[i].sid = pkm_kunit_everyone_sid;
		groups[i].sid_len = sizeof(pkm_kunit_everyone_sid);
		groups[i].attributes = PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				       PKM_KUNIT_SE_GROUP_ENABLED;
	}
}


bool pkm_kunit_contains_bytes(const u8 *haystack, size_t haystack_len,
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


void pkm_kunit_reset_kmes(void)
{
	pkm_kmes_kunit_reset_all();
	pkm_kmes_kunit_clear_process_override();
	(void)pkm_kmes_kunit_set_current_process_rate_refill_frozen(false);
	(void)pkm_kmes_kunit_set_current_process_rate_tokens(
		PKM_KUNIT_KMES_DEFAULT_RATE);
}


void pkm_kunit_close_fds(struct kunit *test, int *fds, int count)
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


int pkm_kunit_dup_fd_same_file(int fd)
{
	struct fd f;
	struct file *file;
	int duplicate_fd;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;

	file = get_file(fd_file(f));
	duplicate_fd = get_unused_fd_flags(0);
	if (duplicate_fd < 0) {
		fput(file);
		fdput(f);
		return duplicate_fd;
	}

	fd_install(duplicate_fd, file);
	fdput(f);
	return duplicate_fd;
}


void pkm_kunit_cleanup_linked_pair(struct kunit *test,
					  struct pkm_kunit_linked_pair *pair)
{
	if (!pair)
		return;

	if (pair->source_token) {
		kacs_rust_token_drop(pair->source_token);
		pair->source_token = NULL;
	}
	if (pair->elevated_fd >= 0) {
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)pair->elevated_fd), 0);
		flush_delayed_fput();
		pair->elevated_fd = -1;
	}
	if (pair->filtered_fd >= 0) {
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)pair->filtered_fd), 0);
		flush_delayed_fput();
		pair->filtered_fd = -1;
	}
	pair->session_id = 0;
}


int pkm_kunit_create_link_candidates(struct kunit *test,
					    const void *caller_token,
					    struct pkm_kunit_linked_pair *out)
{
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot snapshot = { };
	const void *source_token;
	long source_fd;

	if (!test || !caller_token || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->elevated_fd = -1;
	out->filtered_fd = -1;

	source_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0U, 0ULL);
	if (!source_token)
		return -ENOMEM;
	if (!kacs_rust_kunit_token_snapshot(source_token, &snapshot)) {
		kacs_rust_token_drop(source_token);
		return -EINVAL;
	}

	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, source_token, KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	if (source_fd < 0) {
		kacs_rust_token_drop(source_token);
		return (int)source_fd;
	}
	if (pkm_kacs_kunit_token_fd_duplicate((int)source_fd, caller_token,
					      source_token, &duplicate)) {
		close_fd((unsigned int)source_fd);
		kacs_rust_token_drop(source_token);
		return -EINVAL;
	}
	if (duplicate.result_fd < 0) {
		close_fd((unsigned int)source_fd);
		kacs_rust_token_drop(source_token);
		return -EINVAL;
	}

	out->source_token = source_token;
	out->elevated_fd = source_fd;
	out->filtered_fd = duplicate.result_fd;
	out->session_id = snapshot.session_id;
	return 0;
}


int pkm_kunit_create_linked_pair(struct kunit *test,
					const void *caller_token,
					struct pkm_kunit_linked_pair *out)
{
	struct kacs_link_tokens_args link;
	int ret;

	ret = pkm_kunit_create_link_candidates(test, caller_token, out);
	if (ret)
		return ret;

	link.elevated_fd = (s32)out->elevated_fd;
	link.filtered_fd = (s32)out->filtered_fd;
	link.session_id = out->session_id;
	ret = (int)pkm_kacs_kunit_token_fd_link((int)out->elevated_fd,
						 caller_token, &link);
	if (ret) {
		pkm_kunit_cleanup_linked_pair(test, out);
		return ret;
	}

	return 0;
}


int pkm_kunit_create_dynamic_linked_pair(struct kunit *test,
						const void *caller_token,
						struct pkm_kunit_linked_pair *out)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	struct kacs_link_tokens_args link = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	size_t session_spec_len;
	size_t token_spec_len;
	u64 session_id = 0;
	long elevated_fd;
	long filtered_fd;
	int ret;

	if (!test || !caller_token || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->elevated_fd = -1;
	out->filtered_fd = -1;

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	if ((long)session_spec_len <= 0)
		return -EINVAL;
	ret = (int)pkm_kacs_kunit_create_session_for_subject(
		caller_token, session_spec, session_spec_len, &session_id);
	if (ret)
		return ret;

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	if ((long)token_spec_len <= 0)
		return -EINVAL;

	elevated_fd = pkm_kacs_kunit_create_token_for_subject(caller_token,
							      token_spec,
							      token_spec_len);
	if (elevated_fd < 0)
		return (int)elevated_fd;
	out->elevated_fd = elevated_fd;

	ret = pkm_kacs_token_fd_clone_token((int)elevated_fd, &out->source_token,
					    NULL);
	if (ret) {
		pkm_kunit_cleanup_linked_pair(test, out);
		return ret;
	}

	filtered_fd = pkm_kacs_kunit_create_token_for_subject(caller_token,
							      token_spec,
							      token_spec_len);
	if (filtered_fd < 0) {
		pkm_kunit_cleanup_linked_pair(test, out);
		return (int)filtered_fd;
	}
	out->filtered_fd = filtered_fd;
	out->session_id = session_id;

	link.elevated_fd = (s32)elevated_fd;
	link.filtered_fd = (s32)filtered_fd;
	link.session_id = session_id;
	ret = (int)pkm_kacs_kunit_token_fd_link((int)elevated_fd,
						 caller_token, &link);
	if (ret) {
		pkm_kunit_cleanup_linked_pair(test, out);
		return ret;
	}

	return 0;
}


int pkm_kunit_find_current_kmes_fd(struct kunit *test, int *fds, int count,
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


/*
 * v0.20 kmes_attach returns one fd per cpu_id; a consumer enumerates CPUs
 * by attaching cpu_id 0, 1, ... until -EINVAL. This helper reproduces the
 * old "attach every CPU at once" convenience for the tests: it fills
 * fds[cpu_id], records the shared capacity, and reports the CPU count.
 */
long pkm_kunit_kmes_attach_all(const void *token, int *fds, int *count,
				      u64 *capacity)
{
	int n = 0;
	long ret;

	for (;;) {
		int fd = -1;
		u64 cap = 0;

		ret = pkm_kmes_kunit_attach_for_token(token, (u32)n, &fd, &cap);
		if (ret == -EINVAL)
			break;
		if (ret)
			return ret;
		fds[n] = fd;
		*capacity = cap;
		n++;
	}

	*count = n;
	return 0;
}


bool pkm_kunit_parse_kmes_event(
	const u8 *bytes, size_t len, struct pkm_kunit_kmes_event_view *out)
{
	u32 event_size;
	u32 header_size;
	u16 type_len;

	if (!bytes || !out || len < KMES_EVENT_HEADER_BASE_SIZE)
		return false;

	event_size = pkm_kunit_read_u32(bytes, KMES_EVENT_SIZE_OFFSET);
	header_size = pkm_kunit_read_u32(bytes, KMES_EVENT_HEADER_SIZE_OFFSET);
	type_len = pkm_kunit_read_u16(bytes, KMES_EVENT_TYPE_LEN_OFFSET);
	if (event_size > len || header_size > event_size)
		return false;
	if (header_size != KMES_EVENT_HEADER_BASE_SIZE + (u32)type_len)
		return false;

	out->event_size = event_size;
	out->header_size = header_size;
	out->timestamp = pkm_kunit_read_u64(bytes, KMES_EVENT_TIMESTAMP_NS_OFFSET);
	out->sequence = pkm_kunit_read_u64(bytes, KMES_EVENT_SEQUENCE_OFFSET);
	out->cpu_id = pkm_kunit_read_u16(bytes, KMES_EVENT_CPU_ID_OFFSET);
	out->origin_class = bytes[KMES_EVENT_ORIGIN_CLASS_OFFSET];
	out->effective_token_guid =
		bytes + KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET;
	out->true_token_guid = bytes + KMES_EVENT_TRUE_TOKEN_GUID_OFFSET;
	out->process_guid = bytes + KMES_EVENT_PROCESS_GUID_OFFSET;
	out->type_len = type_len;
	out->type_ptr = bytes + KMES_EVENT_HEADER_BASE_SIZE;
	out->payload_ptr = bytes + header_size;
	out->payload_len = event_size - header_size;
	return true;
}


bool pkm_kunit_msgpack_read_be(const u8 *bytes, size_t len,
				      size_t width, u64 *out)
{
	u64 value = 0;
	size_t i;

	if (!bytes || !out || width > sizeof(value) || len < width)
		return false;

	for (i = 0; i < width; i++)
		value = (value << 8) | bytes[i];
	*out = value;
	return true;
}


bool pkm_kunit_msgpack_parse_one(const u8 *bytes, size_t len,
					struct pkm_kunit_msgpack_view *out,
					u32 depth)
{
	struct pkm_kunit_msgpack_view child = { };
	size_t header_len = 1;
	size_t payload_len = 0;
	size_t offset;
	u64 value = 0;
	u64 count = 0;
	u64 entries;
	u8 tag;

	if (!bytes || !out || len == 0 || depth > 32)
		return false;

	memset(out, 0, sizeof(*out));
	tag = bytes[0];

	if (tag <= 0x7f) {
		out->kind = PKM_KUNIT_MSGPACK_UINT;
		out->uint_value = tag;
		out->total_len = 1;
		return true;
	}
	if ((tag & 0xf0) == 0x80) {
		out->kind = PKM_KUNIT_MSGPACK_MAP;
		count = tag & 0x0f;
	} else if ((tag & 0xf0) == 0x90) {
		out->kind = PKM_KUNIT_MSGPACK_ARRAY;
		count = tag & 0x0f;
	} else if ((tag & 0xe0) == 0xa0) {
		out->kind = PKM_KUNIT_MSGPACK_STR;
		payload_len = tag & 0x1f;
		goto bytes_payload;
	} else {
		switch (tag) {
		case 0xc0:
			out->kind = PKM_KUNIT_MSGPACK_NIL;
			out->total_len = 1;
			return true;
		case 0xc2:
		case 0xc3:
			out->kind = PKM_KUNIT_MSGPACK_BOOL;
			out->bool_value = tag == 0xc3;
			out->total_len = 1;
			return true;
		case 0xc4:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 1,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_BIN;
			header_len = 2;
			payload_len = value;
			goto bytes_payload;
		case 0xc5:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 2,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_BIN;
			header_len = 3;
			payload_len = value;
			goto bytes_payload;
		case 0xc6:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 4,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_BIN;
			header_len = 5;
			payload_len = value;
			goto bytes_payload;
		case 0xcc:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 1,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_UINT;
			out->uint_value = value;
			out->total_len = 2;
			return true;
		case 0xcd:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 2,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_UINT;
			out->uint_value = value;
			out->total_len = 3;
			return true;
		case 0xce:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 4,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_UINT;
			out->uint_value = value;
			out->total_len = 5;
			return true;
		case 0xcf:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 8,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_UINT;
			out->uint_value = value;
			out->total_len = 9;
			return true;
		case 0xd9:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 1,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_STR;
			header_len = 2;
			payload_len = value;
			goto bytes_payload;
		case 0xda:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 2,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_STR;
			header_len = 3;
			payload_len = value;
			goto bytes_payload;
		case 0xdb:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 4,
						       &value))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_STR;
			header_len = 5;
			payload_len = value;
			goto bytes_payload;
		case 0xdc:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 2,
						       &count))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_ARRAY;
			header_len = 3;
			break;
		case 0xdd:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 4,
						       &count))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_ARRAY;
			header_len = 5;
			break;
		case 0xde:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 2,
						       &count))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_MAP;
			header_len = 3;
			break;
		case 0xdf:
			if (!pkm_kunit_msgpack_read_be(bytes + 1, len - 1, 4,
						       &count))
				return false;
			out->kind = PKM_KUNIT_MSGPACK_MAP;
			header_len = 5;
			break;
		default:
			return false;
		}
	}

	if (count > U32_MAX || header_len > len)
		return false;
	entries = count;
	if (out->kind == PKM_KUNIT_MSGPACK_MAP) {
		if (entries > U32_MAX / 2)
			return false;
		entries *= 2;
	}
	offset = header_len;
	while (entries--) {
		if (!pkm_kunit_msgpack_parse_one(bytes + offset, len - offset,
						 &child, depth + 1))
			return false;
		if (child.total_len > len - offset)
			return false;
		offset += child.total_len;
	}
	out->count = (u32)count;
	out->data_ptr = bytes + header_len;
	out->data_len = offset - header_len;
	out->total_len = offset;
	return true;

bytes_payload:
	if (payload_len > SIZE_MAX - header_len || header_len > len ||
	    payload_len > len - header_len)
		return false;
	out->data_ptr = bytes + header_len;
	out->data_len = payload_len;
	out->total_len = header_len + payload_len;
	return true;
}


bool pkm_kunit_msgpack_map_get(const struct pkm_kunit_msgpack_view *map,
				      const char *key,
				      struct pkm_kunit_msgpack_view *out)
{
	struct pkm_kunit_msgpack_view key_view = { };
	struct pkm_kunit_msgpack_view value_view = { };
	size_t key_len;
	size_t offset = 0;
	u32 i;

	if (!map || !key || !out || map->kind != PKM_KUNIT_MSGPACK_MAP)
		return false;

	key_len = strlen(key);
	for (i = 0; i < map->count; i++) {
		if (!pkm_kunit_msgpack_parse_one(map->data_ptr + offset,
						 map->data_len - offset,
						 &key_view, 0))
			return false;
		offset += key_view.total_len;
		if (!pkm_kunit_msgpack_parse_one(map->data_ptr + offset,
						 map->data_len - offset,
						 &value_view, 0))
			return false;
		offset += value_view.total_len;
		if (key_view.kind == PKM_KUNIT_MSGPACK_STR &&
		    key_view.data_len == key_len &&
		    !memcmp(key_view.data_ptr, key, key_len)) {
			*out = value_view;
			return true;
		}
	}

	return false;
}


bool pkm_kunit_msgpack_str_eq(
	const struct pkm_kunit_msgpack_view *view, const char *expected)
{
	size_t expected_len;

	if (!view || !expected || view->kind != PKM_KUNIT_MSGPACK_STR)
		return false;
	expected_len = strlen(expected);
	return view->data_len == expected_len &&
	       !memcmp(view->data_ptr, expected, expected_len);
}


bool pkm_kunit_msgpack_bin_eq(
	const struct pkm_kunit_msgpack_view *view, const u8 *expected,
	size_t expected_len)
{
	if (!view || !expected || view->kind != PKM_KUNIT_MSGPACK_BIN)
		return false;
	return view->data_len == expected_len &&
	       !memcmp(view->data_ptr, expected, expected_len);
}


bool pkm_kunit_msgpack_require_key(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const char *key, enum pkm_kunit_msgpack_kind kind,
	struct pkm_kunit_msgpack_view *out)
{
	struct pkm_kunit_msgpack_view value = { };
	bool found;

	found = pkm_kunit_msgpack_map_get(map, key, &value);
	KUNIT_EXPECT_TRUE(test, found);
	if (!found)
		return false;
	KUNIT_EXPECT_EQ(test, value.kind, kind);
	if (value.kind != kind)
		return false;
	if (out)
		*out = value;
	return true;
}


bool pkm_kunit_msgpack_expect_uint_key(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const char *key, u64 expected)
{
	struct pkm_kunit_msgpack_view value = { };

	if (!pkm_kunit_msgpack_require_key(test, map, key,
					   PKM_KUNIT_MSGPACK_UINT, &value))
		return false;
	KUNIT_EXPECT_EQ(test, value.uint_value, expected);
	return value.uint_value == expected;
}


bool pkm_kunit_msgpack_expect_bool_key(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const char *key, bool expected)
{
	struct pkm_kunit_msgpack_view value = { };

	if (!pkm_kunit_msgpack_require_key(test, map, key,
					   PKM_KUNIT_MSGPACK_BOOL, &value))
		return false;
	KUNIT_EXPECT_EQ(test, value.bool_value, expected);
	return value.bool_value == expected;
}


bool pkm_kunit_msgpack_expect_str_key(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const char *key, const char *expected)
{
	struct pkm_kunit_msgpack_view value = { };
	bool matches;

	if (!pkm_kunit_msgpack_require_key(test, map, key,
					   PKM_KUNIT_MSGPACK_STR, &value))
		return false;
	matches = pkm_kunit_msgpack_str_eq(&value, expected);
	KUNIT_EXPECT_TRUE(test, matches);
	return matches;
}


bool pkm_kunit_msgpack_expect_bin_key(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const char *key, const u8 *expected, size_t expected_len)
{
	struct pkm_kunit_msgpack_view value = { };
	bool matches;

	if (!pkm_kunit_msgpack_require_key(test, map, key,
					   PKM_KUNIT_MSGPACK_BIN, &value))
		return false;
	matches = pkm_kunit_msgpack_bin_eq(&value, expected, expected_len);
	KUNIT_EXPECT_TRUE(test, matches);
	return matches;
}


bool pkm_kunit_msgpack_expect_nil_key(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const char *key)
{
	return pkm_kunit_msgpack_require_key(test, map, key,
					    PKM_KUNIT_MSGPACK_NIL, NULL);
}


bool pkm_kunit_msgpack_expect_process_map(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	u64 expected_pid, const char *expected_name, const char *expected_path)
{
	bool ok = true;

	KUNIT_EXPECT_EQ(test, map->kind, PKM_KUNIT_MSGPACK_MAP);
	KUNIT_EXPECT_EQ(test, map->count, 3U);
	ok &= map->kind == PKM_KUNIT_MSGPACK_MAP && map->count == 3U;
	ok &= pkm_kunit_msgpack_expect_uint_key(test, map, "pid",
						expected_pid);
	ok &= pkm_kunit_msgpack_expect_str_key(test, map, "name",
					       expected_name);
	ok &= pkm_kunit_msgpack_expect_str_key(test, map, "executable_path",
					       expected_path);
	return ok;
}


bool pkm_kunit_msgpack_expect_subject_map(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const u8 *expected_user_sid, size_t expected_user_sid_len,
	u32 expected_integrity, u32 expected_pip_type, u32 expected_pip_trust)
{
	struct pkm_kunit_msgpack_view groups = { };
	struct pkm_kunit_msgpack_view group = { };
	size_t offset = 0;
	bool ok = true;
	u32 i;

	KUNIT_EXPECT_EQ(test, map->kind, PKM_KUNIT_MSGPACK_MAP);
	KUNIT_EXPECT_EQ(test, map->count, 5U);
	ok &= map->kind == PKM_KUNIT_MSGPACK_MAP && map->count == 5U;
	ok &= pkm_kunit_msgpack_expect_bin_key(test, map, "user_sid",
					       expected_user_sid,
					       expected_user_sid_len);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, map, "integrity_level",
						expected_integrity);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, map, "pip_type",
						expected_pip_type);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, map, "pip_trust",
						expected_pip_trust);
	if (!pkm_kunit_msgpack_require_key(test, map, "group_sids",
					   PKM_KUNIT_MSGPACK_ARRAY, &groups))
		return false;
	for (i = 0; i < groups.count; i++) {
		if (!pkm_kunit_msgpack_parse_one(groups.data_ptr + offset,
						 groups.data_len - offset,
						 &group, 0)) {
			KUNIT_EXPECT_TRUE(test, false);
			return false;
		}
		KUNIT_EXPECT_EQ(test, group.kind, PKM_KUNIT_MSGPACK_BIN);
		ok &= group.kind == PKM_KUNIT_MSGPACK_BIN;
		offset += group.total_len;
	}
	KUNIT_EXPECT_EQ(test, offset, groups.data_len);
	return ok && offset == groups.data_len;
}


bool pkm_kunit_msgpack_expect_subject_group_sids(
	struct kunit *test, const struct pkm_kunit_msgpack_view *map,
	const struct pkm_kunit_sid_attr_spec *expected_groups,
	u32 expected_group_count)
{
	struct pkm_kunit_msgpack_view groups = { };
	struct pkm_kunit_msgpack_view group = { };
	size_t offset = 0;
	bool ok = true;
	u32 i;

	KUNIT_EXPECT_EQ(test, map->kind, PKM_KUNIT_MSGPACK_MAP);
	ok &= map->kind == PKM_KUNIT_MSGPACK_MAP;
	if (!pkm_kunit_msgpack_require_key(test, map, "group_sids",
					   PKM_KUNIT_MSGPACK_ARRAY, &groups))
		return false;

	KUNIT_EXPECT_EQ(test, groups.count, expected_group_count);
	ok &= groups.count == expected_group_count;
	for (i = 0; i < groups.count; i++) {
		if (!pkm_kunit_msgpack_parse_one(groups.data_ptr + offset,
						 groups.data_len - offset,
						 &group, 0)) {
			KUNIT_EXPECT_TRUE(test, false);
			return false;
		}
		if (i < expected_group_count) {
			bool sid_matches = pkm_kunit_msgpack_bin_eq(
				&group, expected_groups[i].sid,
				expected_groups[i].sid_len);

			KUNIT_EXPECT_TRUE(test, sid_matches);
			ok &= sid_matches;
		}
		offset += group.total_len;
	}
	KUNIT_EXPECT_EQ(test, offset, groups.data_len);
	return ok && offset == groups.data_len;
}


bool pkm_kunit_msgpack_parse_payload_root(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	struct pkm_kunit_msgpack_view *root, u32 expected_count)
{
	bool ok;

	ok = pkm_kunit_msgpack_parse_one(event->payload_ptr, event->payload_len,
					 root, 0);
	KUNIT_EXPECT_TRUE(test, ok);
	if (!ok)
		return false;
	KUNIT_EXPECT_EQ(test, root->kind, PKM_KUNIT_MSGPACK_MAP);
	KUNIT_EXPECT_EQ(test, root->count, expected_count);
	KUNIT_EXPECT_EQ(test, root->total_len, event->payload_len);
	return root->kind == PKM_KUNIT_MSGPACK_MAP &&
	       root->count == expected_count &&
	       root->total_len == event->payload_len;
}


bool pkm_kunit_expect_kmes_event_type(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	const char *expected)
{
	size_t expected_len = strlen(expected);
	bool ok;

	ok = event->type_len == expected_len &&
	     !memcmp(event->type_ptr, expected, expected_len);
	KUNIT_EXPECT_TRUE(test, ok);
	KUNIT_EXPECT_EQ(test, event->origin_class, KMES_ORIGIN_KACS);
	return ok && event->origin_class == KMES_ORIGIN_KACS;
}


bool pkm_kunit_expect_access_audit_schema(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	u32 expected_requested, u32 expected_granted, bool expected_success,
	const char *expected_trigger_kind, const u8 *expected_ace,
	size_t expected_ace_len)
{
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view subject = { };
	struct pkm_kunit_msgpack_view process = { };
	struct pkm_kunit_msgpack_view trigger = { };
	struct pkm_kunit_msgpack_view ace = { };
	bool ace_matches;
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event, "access-audit");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 7))
		return false;
	ok &= pkm_kunit_msgpack_require_key(test, &root, "subject",
					    PKM_KUNIT_MSGPACK_MAP, &subject);
	ok &= pkm_kunit_msgpack_expect_subject_map(
		test, &subject, pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid),
		PKM_KUNIT_IL_SYSTEM, 0U, 0U);
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "object_context");
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"requested_access",
						expected_requested);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"granted_access",
						expected_granted);
	ok &= pkm_kunit_msgpack_expect_bool_key(test, &root, "success",
						expected_success);
	ok &= pkm_kunit_msgpack_require_key(test, &root, "trigger",
					    PKM_KUNIT_MSGPACK_MAP, &trigger);
	KUNIT_EXPECT_EQ(test, trigger.count, 2U);
	ok &= trigger.count == 2U;
	ok &= pkm_kunit_msgpack_expect_str_key(test, &trigger, "kind",
					       expected_trigger_kind);
	if (!pkm_kunit_msgpack_map_get(&trigger, "ace", &ace)) {
		KUNIT_EXPECT_TRUE(test, false);
		ok = false;
	} else if (!expected_ace) {
		KUNIT_EXPECT_EQ(test, ace.kind, PKM_KUNIT_MSGPACK_NIL);
		ok &= ace.kind == PKM_KUNIT_MSGPACK_NIL;
	} else {
		ace_matches = pkm_kunit_msgpack_bin_eq(&ace, expected_ace,
						       expected_ace_len);
		KUNIT_EXPECT_TRUE(test, ace_matches);
		ok &= ace_matches;
	}
	ok &= pkm_kunit_msgpack_require_key(test, &root, "process",
					    PKM_KUNIT_MSGPACK_MAP, &process);
	ok &= pkm_kunit_msgpack_expect_process_map(
		test, &process, 4105, PKM_KUNIT_KMES_PROCESS_NAME,
		PKM_KUNIT_KMES_PROCESS_PATH);
	return ok;
}


bool pkm_kunit_expect_access_audit_subject_group_sids(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	const struct pkm_kunit_sid_attr_spec *expected_groups,
	u32 expected_group_count)
{
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view subject = { };

	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 7))
		return false;
	if (!pkm_kunit_msgpack_require_key(test, &root, "subject",
					   PKM_KUNIT_MSGPACK_MAP, &subject))
		return false;
	return pkm_kunit_msgpack_expect_subject_group_sids(
		test, &subject, expected_groups, expected_group_count);
}


bool pkm_kunit_expect_access_audit_object_context(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	const u8 *expected_context, size_t expected_context_len)
{
	struct pkm_kunit_msgpack_view root = { };
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event, "access-audit");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 7))
		return false;
	ok &= pkm_kunit_msgpack_expect_bin_key(test, &root, "object_context",
					       expected_context,
					       expected_context_len);
	return ok;
}


bool pkm_kunit_expect_continuous_audit_schema(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	u32 expected_requested, u32 expected_matched, u32 expected_granted,
	bool expected_success)
{
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view subject = { };
	struct pkm_kunit_msgpack_view process = { };
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event, "continuous-audit");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 8))
		return false;
	ok &= pkm_kunit_msgpack_require_key(test, &root, "subject",
					    PKM_KUNIT_MSGPACK_MAP, &subject);
	ok &= pkm_kunit_msgpack_expect_subject_map(
		test, &subject, pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid),
		PKM_KUNIT_IL_SYSTEM, 0U, 0U);
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "object_context");
	ok &= pkm_kunit_msgpack_expect_str_key(test, &root, "operation",
					       "file.permission");
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"requested_access",
						expected_requested);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "matched_access",
						expected_matched);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "granted_access",
						expected_granted);
	ok &= pkm_kunit_msgpack_expect_bool_key(test, &root, "success",
						expected_success);
	ok &= pkm_kunit_msgpack_require_key(test, &root, "process",
					    PKM_KUNIT_MSGPACK_MAP, &process);
	ok &= pkm_kunit_msgpack_expect_process_map(
		test, &process, 4301, PKM_KUNIT_KMES_PROCESS_NAME,
		PKM_KUNIT_KMES_PROCESS_PATH);
	return ok;
}


bool pkm_kunit_expect_continuous_audit_schema_op(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	const char *expected_operation, u32 expected_requested,
	u32 expected_matched, u32 expected_granted, bool expected_success,
	u32 expected_pip_type, u32 expected_pip_trust, u64 expected_pid)
{
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view subject = { };
	struct pkm_kunit_msgpack_view process = { };
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event, "continuous-audit");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 8))
		return false;
	ok &= pkm_kunit_msgpack_require_key(test, &root, "subject",
					    PKM_KUNIT_MSGPACK_MAP, &subject);
	ok &= pkm_kunit_msgpack_expect_subject_map(
		test, &subject, pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid),
		PKM_KUNIT_IL_SYSTEM, expected_pip_type, expected_pip_trust);
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "object_context");
	ok &= pkm_kunit_msgpack_expect_str_key(test, &root, "operation",
					       expected_operation);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"requested_access",
						expected_requested);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "matched_access",
						expected_matched);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "granted_access",
						expected_granted);
	ok &= pkm_kunit_msgpack_expect_bool_key(test, &root, "success",
						expected_success);
	ok &= pkm_kunit_msgpack_require_key(test, &root, "process",
					    PKM_KUNIT_MSGPACK_MAP, &process);
	ok &= pkm_kunit_msgpack_expect_process_map(
		test, &process, expected_pid, PKM_KUNIT_KMES_PROCESS_NAME,
		PKM_KUNIT_KMES_PROCESS_PATH);
	return ok;
}


bool pkm_kunit_expect_privilege_use_schema(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	u32 expected_requested, u32 expected_granted, u32 expected_surviving,
	bool expected_success)
{
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view subject = { };
	struct pkm_kunit_msgpack_view process = { };
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event, "privilege-use");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 8))
		return false;
	ok &= pkm_kunit_msgpack_require_key(test, &root, "subject",
					    PKM_KUNIT_MSGPACK_MAP, &subject);
	ok &= pkm_kunit_msgpack_expect_subject_map(
		test, &subject, pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid),
		PKM_KUNIT_IL_SYSTEM, 0U, 0U);
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "object_context");
	ok &= pkm_kunit_msgpack_expect_str_key(test, &root, "privilege",
					       "SeSecurityPrivilege");
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"requested_access",
						expected_requested);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"granted_access",
						expected_granted);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"surviving_access",
						expected_surviving);
	ok &= pkm_kunit_msgpack_expect_bool_key(test, &root, "success",
						expected_success);
	ok &= pkm_kunit_msgpack_require_key(test, &root, "process",
					    PKM_KUNIT_MSGPACK_MAP, &process);
	ok &= pkm_kunit_msgpack_expect_process_map(
		test, &process, 4206, PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
		PKM_KUNIT_KMES_PRIV_PROCESS_PATH);
	return ok;
}


bool pkm_kunit_expect_caap_diagnostic_schema(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	u32 expected_effective, u32 expected_staged)
{
	struct pkm_kunit_msgpack_view root = { };
	struct pkm_kunit_msgpack_view subject = { };
	struct pkm_kunit_msgpack_view process = { };
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event,
					       "caap-policy-diagnostic");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 12))
		return false;
	ok &= pkm_kunit_msgpack_require_key(test, &root, "subject",
					    PKM_KUNIT_MSGPACK_MAP, &subject);
	ok &= pkm_kunit_msgpack_expect_subject_map(
		test, &subject, pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid),
		PKM_KUNIT_IL_SYSTEM, 0U, 0U);
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "object_context");
	ok &= pkm_kunit_msgpack_expect_str_key(test, &root, "kind",
					       "staging-mismatch");
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "phase");
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "policy_sid");
	ok &= pkm_kunit_msgpack_expect_nil_key(test, &root, "rule_index");
	ok &= pkm_kunit_msgpack_expect_str_key(test, &root, "reason",
					       "effective-staged-delta");
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"requested_access",
						KACS_ACCESS_READ_CONTROL);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"effective_granted_access",
						expected_effective);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root,
						"staged_granted_access",
						expected_staged);
	ok &= pkm_kunit_msgpack_expect_bool_key(test, &root,
						"object_results_differ",
						false);
	ok &= pkm_kunit_msgpack_require_key(test, &root, "process",
					    PKM_KUNIT_MSGPACK_MAP, &process);
	ok &= pkm_kunit_msgpack_expect_process_map(
		test, &process, 4307, PKM_KUNIT_KMES_PROCESS_NAME,
		PKM_KUNIT_KMES_PROCESS_PATH);
	return ok;
}


bool pkm_kunit_expect_logon_destroyed_schema(
	struct kunit *test, const struct pkm_kunit_kmes_event_view *event,
	u64 expected_session_id, u32 expected_logon_type,
	const char *expected_auth_package, u64 expected_created_at)
{
	struct pkm_kunit_msgpack_view root = { };
	bool ok = true;

	ok &= pkm_kunit_expect_kmes_event_type(test, event,
					       "logon-session-destroyed");
	if (!pkm_kunit_msgpack_parse_payload_root(test, event, &root, 5))
		return false;
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "session_id",
						expected_session_id);
	ok &= pkm_kunit_msgpack_expect_bin_key(test, &root, "user_sid",
					       pkm_kunit_local_service_sid,
					       sizeof(pkm_kunit_local_service_sid));
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "logon_type",
						expected_logon_type);
	ok &= pkm_kunit_msgpack_expect_str_key(test, &root, "auth_package",
					       expected_auth_package);
	ok &= pkm_kunit_msgpack_expect_uint_key(test, &root, "created_at",
						expected_created_at);
	return ok;
}


void pkm_kunit_expect_boot_snapshot_eq_internal(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs, bool compare_identity)
{
	u32 i;

	KUNIT_EXPECT_PTR_EQ(test, lhs->session_ptr, rhs->session_ptr);
	KUNIT_EXPECT_EQ(test, lhs->session_id, rhs->session_id);
	KUNIT_EXPECT_EQ(test, lhs->auth_id, rhs->auth_id);
	if (compare_identity) {
		KUNIT_EXPECT_EQ(test, lhs->token_id, rhs->token_id);
		pkm_kunit_expect_bytes_eq(test, lhs->token_guid,
					  sizeof(lhs->token_guid),
					  rhs->token_guid,
					  sizeof(rhs->token_guid));
		KUNIT_EXPECT_EQ(test, lhs->modified_id, rhs->modified_id);
	}
	KUNIT_EXPECT_EQ(test, lhs->created_at, rhs->created_at);
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
	KUNIT_EXPECT_EQ(test, lhs->elevation_type, rhs->elevation_type);
	KUNIT_EXPECT_EQ(test, lhs->restricted, rhs->restricted);
	KUNIT_EXPECT_EQ(test, lhs->user_deny_only, rhs->user_deny_only);
	KUNIT_EXPECT_EQ(test, lhs->write_restricted, rhs->write_restricted);
	KUNIT_EXPECT_EQ(test, lhs->confinement_exempt, rhs->confinement_exempt);
	KUNIT_EXPECT_EQ(test, lhs->isolation_boundary, rhs->isolation_boundary);
	pkm_kunit_expect_bytes_eq(test, lhs->source_name_ptr,
				  lhs->source_name_len, rhs->source_name_ptr,
				  rhs->source_name_len);
	KUNIT_EXPECT_EQ(test, lhs->source_id, rhs->source_id);
	KUNIT_EXPECT_EQ(test, lhs->expiration, rhs->expiration);
	KUNIT_EXPECT_EQ(test, lhs->origin, rhs->origin);
	KUNIT_EXPECT_EQ(test, lhs->restricted_sid_count,
			rhs->restricted_sid_count);
	KUNIT_EXPECT_EQ(test, lhs->confinement_sid_present,
			rhs->confinement_sid_present);
	KUNIT_EXPECT_EQ(test, lhs->confinement_capability_count,
			rhs->confinement_capability_count);
	KUNIT_EXPECT_EQ(test, lhs->projected_supplementary_gid_count,
			rhs->projected_supplementary_gid_count);
}


void pkm_kunit_expect_boot_snapshot_eq(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs)
{
	pkm_kunit_expect_boot_snapshot_eq_internal(test, lhs, rhs, true);
}


void pkm_kunit_expect_boot_snapshot_eq_except_identity(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs)
{
	pkm_kunit_expect_boot_snapshot_eq_internal(test, lhs, rhs, false);
}


void pkm_kunit_expect_boot_snapshot_scalars_eq_internal(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs, bool compare_identity)
{
	KUNIT_EXPECT_PTR_EQ(test, lhs->session_ptr, rhs->session_ptr);
	KUNIT_EXPECT_EQ(test, lhs->session_id, rhs->session_id);
	KUNIT_EXPECT_EQ(test, lhs->auth_id, rhs->auth_id);
	if (compare_identity) {
		KUNIT_EXPECT_EQ(test, lhs->token_id, rhs->token_id);
		pkm_kunit_expect_bytes_eq(test, lhs->token_guid,
					  sizeof(lhs->token_guid),
					  rhs->token_guid,
					  sizeof(rhs->token_guid));
		KUNIT_EXPECT_EQ(test, lhs->modified_id, rhs->modified_id);
	}
	KUNIT_EXPECT_EQ(test, lhs->created_at, rhs->created_at);
	KUNIT_EXPECT_EQ(test, lhs->logon_type, rhs->logon_type);
	KUNIT_EXPECT_EQ(test, lhs->group_count, rhs->group_count);
	KUNIT_EXPECT_EQ(test, lhs->owner_sid_index, rhs->owner_sid_index);
	KUNIT_EXPECT_EQ(test, lhs->primary_group_index,
			rhs->primary_group_index);
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
	KUNIT_EXPECT_EQ(test, lhs->elevation_type, rhs->elevation_type);
	KUNIT_EXPECT_EQ(test, lhs->restricted, rhs->restricted);
	KUNIT_EXPECT_EQ(test, lhs->user_deny_only, rhs->user_deny_only);
	KUNIT_EXPECT_EQ(test, lhs->write_restricted, rhs->write_restricted);
	KUNIT_EXPECT_EQ(test, lhs->confinement_exempt, rhs->confinement_exempt);
	KUNIT_EXPECT_EQ(test, lhs->isolation_boundary, rhs->isolation_boundary);
	KUNIT_EXPECT_EQ(test, lhs->source_id, rhs->source_id);
	KUNIT_EXPECT_EQ(test, lhs->expiration, rhs->expiration);
	KUNIT_EXPECT_EQ(test, lhs->origin, rhs->origin);
	KUNIT_EXPECT_EQ(test, lhs->restricted_sid_count,
			rhs->restricted_sid_count);
	KUNIT_EXPECT_EQ(test, lhs->confinement_sid_present,
			rhs->confinement_sid_present);
	KUNIT_EXPECT_EQ(test, lhs->confinement_capability_count,
			rhs->confinement_capability_count);
	KUNIT_EXPECT_EQ(test, lhs->projected_supplementary_gid_count,
			rhs->projected_supplementary_gid_count);
}


void pkm_kunit_expect_boot_snapshot_scalars_eq(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs)
{
	pkm_kunit_expect_boot_snapshot_scalars_eq_internal(test, lhs, rhs, true);
}


void pkm_kunit_expect_boot_snapshot_scalars_eq_except_identity(
	struct kunit *test, const struct pkm_kacs_boot_snapshot *lhs,
	const struct pkm_kacs_boot_snapshot *rhs)
{
	pkm_kunit_expect_boot_snapshot_scalars_eq_internal(test, lhs, rhs, false);
}


bool pkm_kunit_guid_is_zero(const u8 guid[KACS_UUID_BYTES])
{
	static const u8 zero[KACS_UUID_BYTES];

	return memcmp(guid, zero, KACS_UUID_BYTES) == 0;
}


bool pkm_kunit_guid_is_uuid_v4(const u8 guid[KACS_UUID_BYTES])
{
	return !pkm_kunit_guid_is_zero(guid) &&
	       (guid[6] & 0xf0) == 0x40 &&
	       (guid[8] & 0xc0) == 0x80;
}


void pkm_kunit_expect_guid_v4(struct kunit *test,
				     const u8 guid[KACS_UUID_BYTES])
{
	KUNIT_EXPECT_TRUE(test, pkm_kunit_guid_is_uuid_v4(guid));
}


void pkm_kunit_expect_guid_eq(struct kunit *test,
				     const u8 lhs[KACS_UUID_BYTES],
				     const u8 rhs[KACS_UUID_BYTES])
{
	pkm_kunit_expect_bytes_eq(test, lhs, KACS_UUID_BYTES, rhs,
				  KACS_UUID_BYTES);
}


void pkm_kunit_expect_guid_ne(struct kunit *test,
				     const u8 lhs[KACS_UUID_BYTES],
				     const u8 rhs[KACS_UUID_BYTES])
{
	KUNIT_EXPECT_NE(test, memcmp(lhs, rhs, KACS_UUID_BYTES), 0);
}


size_t pkm_kunit_build_session_spec(u8 *dst, u8 logon_type,
					   const char *auth_pkg,
					   const u8 *user_sid,
					   size_t user_sid_len)
{
	size_t auth_pkg_len;

	if (!dst || !auth_pkg || !user_sid)
		return 0;

	auth_pkg_len = strlen(auth_pkg);
	dst[0] = logon_type;
	pkm_kunit_write_u16(dst, 1, (u16)auth_pkg_len);
	memcpy(dst + 3, auth_pkg, auth_pkg_len);
	pkm_kunit_write_u32(dst, 3 + auth_pkg_len, (u32)user_sid_len);
	memcpy(dst + 7 + auth_pkg_len, user_sid, user_sid_len);
	return 7 + auth_pkg_len + user_sid_len;
}


size_t pkm_kunit_sid_attr_array_len(
	const struct pkm_kunit_sid_attr_spec *entries, u32 count)
{
	size_t total = 0;
	u32 i;

	for (i = 0; i < count; i++) {
		if (!entries || !entries[i].sid)
			return 0;
		if (entries[i].sid_len > SIZE_MAX - 8 ||
		    total > SIZE_MAX - (entries[i].sid_len + 8))
			return 0;
		total += entries[i].sid_len + 8;
	}

	return total;
}


size_t pkm_kunit_write_sid_attr_array(
	u8 *dst, const struct pkm_kunit_sid_attr_spec *entries, u32 count)
{
	size_t offset = 0;
	u32 i;

	for (i = 0; i < count; i++) {
		pkm_kunit_write_u32(dst, offset, (u32)entries[i].sid_len);
		memcpy(dst + offset + 4, entries[i].sid, entries[i].sid_len);
		pkm_kunit_write_u32(dst, offset + 4 + entries[i].sid_len,
				    entries[i].attributes);
		offset += entries[i].sid_len + 8;
	}

	return offset;
}


int pkm_kunit_append_bytes_section(u8 *dst, size_t dst_len,
					  size_t *offset_io,
					  const void *bytes, size_t len,
					  u32 *offset_out)
{
	if (!offset_io || !offset_out)
		return -EINVAL;

	if (!bytes || len == 0) {
		*offset_out = 0;
		return 0;
	}

	if (*offset_io > dst_len || len > dst_len - *offset_io ||
	    *offset_io > U32_MAX || len > U32_MAX)
		return -EINVAL;

	memcpy(dst + *offset_io, bytes, len);
	*offset_out = (u32)*offset_io;
	*offset_io += len;
	return 0;
}


int pkm_kunit_append_sid_attr_section(
	u8 *dst, size_t dst_len, size_t *offset_io,
	const struct pkm_kunit_sid_attr_spec *entries, u32 count,
	u32 *offset_out)
{
	size_t len;

	if (!count)
		return pkm_kunit_append_bytes_section(dst, dst_len, offset_io,
						      NULL, 0, offset_out);

	len = pkm_kunit_sid_attr_array_len(entries, count);
	if (!len || *offset_io > dst_len || len > dst_len - *offset_io ||
	    *offset_io > U32_MAX)
		return -EINVAL;

	*offset_out = (u32)*offset_io;
	pkm_kunit_write_sid_attr_array(dst + *offset_io, entries, count);
	*offset_io += len;
	return 0;
}


int pkm_kunit_append_u32_section(u8 *dst, size_t dst_len,
					size_t *offset_io,
					const u32 *values, u32 count,
					u32 *offset_out)
{
	size_t len;
	u32 i;

	if (!count)
		return pkm_kunit_append_bytes_section(dst, dst_len, offset_io,
						      NULL, 0, offset_out);

	len = (size_t)count * sizeof(u32);
	if (!values || *offset_io > dst_len || len > dst_len - *offset_io ||
	    *offset_io > U32_MAX)
		return -EINVAL;

	*offset_out = (u32)*offset_io;
	for (i = 0; i < count; i++)
		pkm_kunit_write_u32(dst + *offset_io, i * sizeof(u32),
				    values[i]);
	*offset_io += len;
	return 0;
}


size_t pkm_kunit_build_token_spec(
	u8 *dst, size_t dst_len, const struct pkm_kunit_token_spec_args *args)
{
	size_t offset = PKM_KUNIT_TOKEN_SPEC_HEADER_LEN;
	u32 section_offset = 0;
	u32 projected_uid;
	u32 projected_gid;

	if (!dst || !args || dst_len < PKM_KUNIT_TOKEN_SPEC_HEADER_LEN ||
	    !args->user_sid || !args->source_name)
		return 0;

	projected_uid = args->projected_uid;
	projected_gid = args->projected_gid;
	if (args->user_sid_len != sizeof(pkm_kunit_system_sid) ||
	    memcmp(args->user_sid, pkm_kunit_system_sid,
		   sizeof(pkm_kunit_system_sid))) {
		if (!projected_uid && !args->allow_zero_projected_uid)
			projected_uid = 65534U;
		if (!projected_gid && !args->allow_zero_projected_gid)
			projected_gid = 65534U;
	}

	memset(dst, 0, dst_len);
	pkm_kunit_write_u32(dst, 0, PKM_KUNIT_TOKEN_SPEC_VERSION);
	dst[4] = args->token_type;
	dst[5] = args->impersonation_level;
	pkm_kunit_write_u32(dst, 8, args->integrity_level);
	pkm_kunit_write_u32(dst, 12, args->mandatory_policy);
	pkm_kunit_write_u64(dst, 16, args->privileges_present);
	pkm_kunit_write_u64(dst, 24, args->privileges_enabled);
	pkm_kunit_write_u32(dst, 36, projected_uid);
	pkm_kunit_write_u32(dst, 40, projected_gid);
	pkm_kunit_write_u32(dst, 44, args->audit_policy);
	pkm_kunit_write_u64(dst, 48, args->expiration);
	pkm_kunit_write_u64(dst, 56, args->session_id);
	pkm_kunit_write_u32(dst, 64, args->owner_sid_index);
	pkm_kunit_write_u32(dst, 68, args->primary_group_index);
	memcpy(dst + 72, args->source_name, 8);
	pkm_kunit_write_u64(dst, 80, args->source_id);

	if (pkm_kunit_append_bytes_section(dst, dst_len, &offset,
					   args->user_sid,
					   args->user_sid_len,
					   &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 88, section_offset);

	if (pkm_kunit_append_sid_attr_section(dst, dst_len, &offset,
					      args->groups, args->group_count,
					      &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 92, section_offset);
	pkm_kunit_write_u32(dst, 96, args->group_count);

	if (pkm_kunit_append_bytes_section(dst, dst_len, &offset,
					   args->default_dacl,
					   args->default_dacl_len,
					   &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 100, section_offset);
	pkm_kunit_write_u32(dst, 104, (u32)args->default_dacl_len);

	if (pkm_kunit_append_bytes_section(dst, dst_len, &offset,
					   args->user_claims,
					   args->user_claims_len,
					   &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 108, section_offset);
	pkm_kunit_write_u32(dst, 112, (u32)args->user_claims_len);

	if (pkm_kunit_append_bytes_section(dst, dst_len, &offset,
					   args->device_claims,
					   args->device_claims_len,
					   &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 116, section_offset);
	pkm_kunit_write_u32(dst, 120, (u32)args->device_claims_len);

	if (pkm_kunit_append_sid_attr_section(dst, dst_len, &offset,
					      args->device_groups,
					      args->device_group_count,
					      &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 124, section_offset);
	pkm_kunit_write_u32(dst, 128, args->device_group_count);

	if (pkm_kunit_append_sid_attr_section(dst, dst_len, &offset,
					      args->restricted_sids,
					      args->restricted_sid_count,
					      &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 132, section_offset);
	pkm_kunit_write_u32(dst, 136, args->restricted_sid_count);

	if (pkm_kunit_append_bytes_section(dst, dst_len, &offset,
					   args->confinement_sid,
					   args->confinement_sid_len,
					   &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 140, section_offset);
	pkm_kunit_write_u32(dst, 144, (u32)args->confinement_sid_len);

	if (pkm_kunit_append_sid_attr_section(dst, dst_len, &offset,
					      args->confinement_caps,
					      args->confinement_cap_count,
					      &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 148, section_offset);
	pkm_kunit_write_u32(dst, 152, args->confinement_cap_count);
	dst[156] = args->confinement_exempt ? 1 : 0;
	dst[157] = args->write_restricted ? 1 : 0;
	dst[158] = args->user_deny_only ? 1 : 0;
	dst[159] = args->isolation_boundary ? 1 : 0;

	if (pkm_kunit_append_u32_section(dst, dst_len, &offset,
					 args->projected_supplementary_gids,
					 args->projected_supplementary_gid_count,
					 &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 160, section_offset);
	pkm_kunit_write_u32(dst, 164,
			    args->projected_supplementary_gid_count);

	if (pkm_kunit_append_sid_attr_section(dst, dst_len, &offset,
					      args->restricted_device_groups,
					      args->restricted_device_group_count,
					      &section_offset))
		return 0;
	pkm_kunit_write_u32(dst, 168, section_offset);
	pkm_kunit_write_u32(dst, 172,
			    args->restricted_device_group_count);
	pkm_kunit_write_u64(dst, 176, args->origin);
	pkm_kunit_write_u32(dst, 184, args->interactive_session_id);

	return offset;
}


void pkm_kunit_build_logon_sid(u64 session_id, u8 out[20])
{
	u32 high = (u32)(session_id >> 32);
	u32 low = (u32)session_id;

	out[0] = 1;
	out[1] = 3;
	out[2] = 0;
	out[3] = 0;
	out[4] = 0;
	out[5] = 0;
	out[6] = 0;
	out[7] = 5;
	out[8] = 5;
	out[9] = 0;
	out[10] = 0;
	out[11] = 0;
	pkm_kunit_write_u32(out, 12, high);
	pkm_kunit_write_u32(out, 16, low);
}


void pkm_kunit_build_args_v136(u8 *args)
{
	memset(args, 0, 136);
	pkm_kunit_write_u32(args, 0, 136);
}


size_t pkm_kunit_build_caap_spec(u8 *spec, const u8 *effective_dacl,
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


size_t pkm_kunit_build_caap_spec_with_staged_dacl(
	u8 *spec, const u8 *effective_dacl, u32 effective_dacl_len,
	const u8 *staged_dacl, u32 staged_dacl_len)
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
	pkm_kunit_write_u32(spec, offset, staged_dacl_len);
	offset += 4;
	if (staged_dacl_len && staged_dacl) {
		memcpy(spec + offset, staged_dacl, staged_dacl_len);
		offset += staged_dacl_len;
	}
	pkm_kunit_write_u32(spec, offset, 0);
	offset += 4;
	return offset;
}


void pkm_kunit_build_read_control_args(u8 *args, s32 token_fd)
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


size_t pkm_kunit_build_read_control_sd(
	u8 *dst, size_t dst_len, const u8 *owner_sid, size_t owner_sid_len,
	const struct pkm_kunit_read_ace_spec *aces, size_t ace_count)
{
	const size_t owner_offset = 20;
	size_t dacl_offset = owner_offset + owner_sid_len;
	size_t acl_size = 8;
	size_t offset;
	size_t i;

	if (!dst || !owner_sid || !aces || !owner_sid_len || !ace_count)
		return 0;
	if (dacl_offset + acl_size > dst_len)
		return 0;

	for (i = 0; i < ace_count; i++)
		acl_size += 8 + aces[i].sid_len;
	if (dacl_offset + acl_size > dst_len)
		return 0;
	if (acl_size > 0xffffU || ace_count > 0xffffU)
		return 0;

	memset(dst, 0, dacl_offset + acl_size);
	dst[0] = 1;
	pkm_kunit_write_u16(dst, 2,
			    PKM_KUNIT_SE_DACL_PRESENT |
				    PKM_KUNIT_SE_SELF_RELATIVE);
	pkm_kunit_write_u32(dst, 4, owner_offset);
	pkm_kunit_write_u32(dst, 16, dacl_offset);
	memcpy(dst + owner_offset, owner_sid, owner_sid_len);

	dst[dacl_offset] = 2;
	pkm_kunit_write_u16(dst, dacl_offset + 2, acl_size);
	pkm_kunit_write_u16(dst, dacl_offset + 4, ace_count);
	offset = dacl_offset + 8;
	for (i = 0; i < ace_count; i++) {
		size_t ace_size = 8 + aces[i].sid_len;

		dst[offset] = aces[i].ace_type;
		pkm_kunit_write_u16(dst, offset + 2, ace_size);
		pkm_kunit_write_u32(dst, offset + 4, KACS_ACCESS_READ_CONTROL);
		memcpy(dst + offset + 8, aces[i].sid, aces[i].sid_len);
		offset += ace_size;
	}

	return dacl_offset + acl_size;
}


size_t pkm_kunit_build_null_dacl_sd(u8 *dst, size_t dst_len,
					   const u8 *owner_sid,
					   size_t owner_sid_len)
{
	const size_t owner_offset = 20;

	if (!dst || !owner_sid || !owner_sid_len ||
	    owner_offset + owner_sid_len > dst_len)
		return 0;

	memset(dst, 0, owner_offset + owner_sid_len);
	dst[0] = 1;
	pkm_kunit_write_u16(dst, 2, PKM_KUNIT_SE_SELF_RELATIVE);
	pkm_kunit_write_u32(dst, 4, owner_offset);
	memcpy(dst + owner_offset, owner_sid, owner_sid_len);
	return owner_offset + owner_sid_len;
}


size_t pkm_kunit_build_confinement_object_sd(u8 *dst, size_t dst_len,
						    const u8 object_guid[16])
{
	const size_t owner_offset = 20;
	const size_t dacl_offset = owner_offset + sizeof(pkm_kunit_system_sid);
	const size_t user_ace_size = 8 + sizeof(pkm_kunit_local_service_sid);
	const size_t object_ace_size =
		4 + 4 + 4 + 16 + sizeof(pkm_kunit_sample_confinement_sid);
	const size_t acl_size = 8 + user_ace_size + object_ace_size;
	const size_t sd_len = dacl_offset + acl_size;
	size_t offset;

	if (!dst || !object_guid || sd_len > dst_len)
		return 0;

	memset(dst, 0, sd_len);
	dst[0] = 1;
	pkm_kunit_write_u16(dst, 2,
			    PKM_KUNIT_SE_DACL_PRESENT |
				    PKM_KUNIT_SE_SELF_RELATIVE);
	pkm_kunit_write_u32(dst, 4, owner_offset);
	pkm_kunit_write_u32(dst, 16, dacl_offset);
	memcpy(dst + owner_offset, pkm_kunit_system_sid,
	       sizeof(pkm_kunit_system_sid));

	dst[dacl_offset] = 4;
	pkm_kunit_write_u16(dst, dacl_offset + 2, acl_size);
	pkm_kunit_write_u16(dst, dacl_offset + 4, 2);

	offset = dacl_offset + 8;
	dst[offset] = 0;
	pkm_kunit_write_u16(dst, offset + 2, user_ace_size);
	pkm_kunit_write_u32(dst, offset + 4, KACS_ACCESS_READ_CONTROL);
	memcpy(dst + offset + 8, pkm_kunit_local_service_sid,
	       sizeof(pkm_kunit_local_service_sid));
	offset += user_ace_size;

	dst[offset] = 5;
	pkm_kunit_write_u16(dst, offset + 2, object_ace_size);
	pkm_kunit_write_u32(dst, offset + 4, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(dst, offset + 8, 1);
	memcpy(dst + offset + 12, object_guid, 16);
	memcpy(dst + offset + 28, pkm_kunit_sample_confinement_sid,
	       sizeof(pkm_kunit_sample_confinement_sid));

	return sd_len;
}


size_t pkm_kunit_build_restrict_payload(
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


long pkm_kunit_run_read_control_with_token_fd_summary(
	int token_fd, const u8 *sd, size_t sd_len, u32 *granted_out,
	struct pkm_kacs_ingress_summary *summary)
{
	u8 args[136];
	u8 granted_bytes[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, token_fd);
	pkm_kunit_write_u32(args, 16, sd_len);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd, sd_len);
	pkm_kunit_add_region(&mem, 0x3000, granted_bytes, sizeof(granted_bytes));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, summary);
	if (granted_out)
		*granted_out = pkm_kunit_read_u32(granted_bytes, 0);
	return ret;
}


long pkm_kunit_run_read_control_with_token_fd(int token_fd, const u8 *sd,
						     size_t sd_len,
						     u32 *granted_out)
{
	struct pkm_kacs_ingress_summary summary = { };

	return pkm_kunit_run_read_control_with_token_fd_summary(
		token_fd, sd, sd_len, granted_out, &summary);
}


long pkm_kunit_create_confined_access_check_token(
	u64 privileges, struct pkm_kacs_token_fd_view *view)
{
	static const u8 source_name[8] = {
		'C', 'o', 'n', 'f', 'A', 'c', 'c', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.privileges_present = privileges,
		.privileges_enabled = privileges,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.source_id = 0x436f6e6641636300ULL,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.confinement_sid = pkm_kunit_sample_confinement_sid,
		.confinement_sid_len = sizeof(pkm_kunit_sample_confinement_sid),
	};
	u8 session_spec[128] = { };
	u8 token_spec[512] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;
	long ret;

	if (!view)
		return -EINVAL;
	memset(view, 0, sizeof(*view));

	subject_token = pkm_kacs_current_primary_token_ptr();
	if (!subject_token)
		return -EACCES;

	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	if (!spec_len)
		return -EINVAL;

	ret = pkm_kacs_kunit_create_session_for_subject(
		subject_token, session_spec, spec_len, &session_id);
	if (ret)
		return ret;

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	if (!spec_len)
		return -EINVAL;

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     spec_len);
	if (fd < 0)
		return fd;

	ret = pkm_kacs_kunit_token_fd_snapshot((int)fd, view);
	if (ret) {
		close_fd((unsigned int)fd);
		return ret;
	}

	return fd;
}


long pkm_kunit_run_pip_labeled_sd_access_check(const u8 *sd,
						      size_t sd_len,
						      u32 arg_pip_type,
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
	pkm_kunit_write_u32(args, 16, (u32)sd_len);
	pkm_kunit_write_u32(args, 20,
			    KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 96, arg_pip_type);
	pkm_kunit_write_u32(args, 100, arg_pip_trust);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)sd, sd_len);
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	if (granted)
		*granted = pkm_kunit_read_u32(granted_out, 0);
	return ret;
}


long pkm_kunit_run_pip_labeled_access_check(u32 arg_pip_type,
						   u32 arg_pip_trust,
						   u32 *granted)
{
	return pkm_kunit_run_pip_labeled_sd_access_check(
		pkm_kunit_system_pip_sd, sizeof(pkm_kunit_system_pip_sd),
		arg_pip_type, arg_pip_trust, granted);
}


long pkm_kunit_run_caap_access_check(u32 *granted)
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


void pkm_kunit_build_access_system_args(u8 *args, s32 token_fd)
{
	pkm_kunit_build_read_control_args(args, token_fd);
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_ACCESS_SYSTEM_SECURITY);
}


struct pkm_kmes_runtime_config pkm_kunit_kmes_default_config(void)
{
	return (struct pkm_kmes_runtime_config) {
		.buffer_capacity = PKM_KUNIT_KMES_DEFAULT_CAPACITY,
		.max_event_size = 65536U,
		.max_nesting_depth = 32U,
		.max_emit_rate_per_process = PKM_KUNIT_KMES_DEFAULT_RATE,
	};
}


void pkm_kunit_expect_create_token_spec_einval(struct kunit *test,
						      const void *subject_token,
						      const u8 *spec,
						      size_t spec_len)
{
	long ret;

	ret = pkm_kacs_kunit_create_token_for_subject(subject_token, spec,
						      spec_len);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	if (ret >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)ret), 0);
}


void pkm_kunit_expect_allow_caps_present(struct kunit *test,
						const struct cred *cred)
{
	static const int allow_caps[] = {
		CAP_CHOWN,
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
		CAP_FOWNER,
		CAP_FSETID,
		CAP_KILL,
		CAP_SETGID,
		CAP_SETUID,
		CAP_NET_BROADCAST,
		CAP_IPC_OWNER,
		CAP_LEASE,
	};
	u32 i;

	KUNIT_ASSERT_NOT_NULL(test, cred);
	for (i = 0; i < ARRAY_SIZE(allow_caps); i++) {
		KUNIT_EXPECT_TRUE(test,
				  cap_raised(cred->cap_effective,
					     allow_caps[i]));
		KUNIT_EXPECT_TRUE(test,
				  cap_raised(cred->cap_permitted,
					     allow_caps[i]));
		KUNIT_EXPECT_TRUE(test,
				  cap_raised(cred->cap_inheritable,
					     allow_caps[i]));
		KUNIT_EXPECT_TRUE(test,
				  cap_raised(cred->cap_bset, allow_caps[i]));
	}
}


void pkm_kunit_expect_linux_cred_projection(struct kunit *test,
						   const struct cred *cred,
						   u32 uid, u32 gid)
{
	KUNIT_ASSERT_NOT_NULL(test, cred);
	KUNIT_ASSERT_NOT_NULL(test, cred->group_info);
	KUNIT_EXPECT_EQ(test, __kuid_val(cred->uid), uid);
	KUNIT_EXPECT_EQ(test, __kuid_val(cred->euid), uid);
	KUNIT_EXPECT_EQ(test, __kuid_val(cred->suid), uid);
	KUNIT_EXPECT_EQ(test, __kuid_val(cred->fsuid), uid);
	KUNIT_EXPECT_EQ(test, __kgid_val(cred->gid), gid);
	KUNIT_EXPECT_EQ(test, __kgid_val(cred->egid), gid);
	KUNIT_EXPECT_EQ(test, __kgid_val(cred->sgid), gid);
	KUNIT_EXPECT_EQ(test, __kgid_val(cred->fsgid), gid);
	KUNIT_EXPECT_EQ(test, cred->group_info->ngroups, 0);
}


void pkm_kunit_expect_process_state_snapshot_eq(
	struct kunit *test, const struct pkm_kacs_kunit_process_state_view *lhs,
	const struct pkm_kacs_kunit_process_state_view *rhs)
{
	KUNIT_EXPECT_PTR_EQ(test, rhs->state_ptr, lhs->state_ptr);
	pkm_kunit_expect_guid_eq(test, rhs->process_guid, lhs->process_guid);
	KUNIT_EXPECT_PTR_EQ(test, rhs->process_sd_ptr, lhs->process_sd_ptr);
	KUNIT_EXPECT_EQ(test, rhs->process_sd_len, lhs->process_sd_len);
	KUNIT_EXPECT_PTR_EQ(test, rhs->rate_bucket_ptr, lhs->rate_bucket_ptr);
	KUNIT_EXPECT_EQ(test, rhs->pip_type, lhs->pip_type);
	KUNIT_EXPECT_EQ(test, rhs->pip_trust, lhs->pip_trust);
	KUNIT_EXPECT_EQ(test, rhs->mitigation_bits, lhs->mitigation_bits);
}


void pkm_kunit_signing_fill_blob(u8 blob[PKM_KUNIT_SIGNING_BLOB_LEN],
					u8 seed)
{
	u32 i;

	blob[0] = PKM_KUNIT_SIGNING_VERSION;
	for (i = 0; i < PKM_KUNIT_SIGNING_SIG_LEN; i++)
		blob[i + 1] = seed + (u8)i;
}


void pkm_kunit_signing_build_elf(
	u8 file[PKM_KUNIT_ELF_LEN],
	const u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN], bool include_sig_section,
	bool valid_sig_section)
{
	static const char shstrtab[] = "\0.shstrtab\0.peios.sig\0";
	const u32 shstrtab_name = 1U;
	const u32 sig_name = sizeof("\0.shstrtab");
	Elf64_Ehdr ehdr = {};
	Elf64_Shdr shdr = {};
	u32 i;

	for (i = 0; i < PKM_KUNIT_ELF_LEN; i++)
		file[i] = (u8)(0x31U + (i * 17U));

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_shoff = PKM_KUNIT_ELF_SHOFF;
	ehdr.e_shentsize = sizeof(Elf64_Shdr);
	ehdr.e_shnum = include_sig_section ? 3 : 2;
	ehdr.e_shstrndx = 1;
	memcpy(file, &ehdr, sizeof(ehdr));

	memcpy(file + PKM_KUNIT_ELF_STRTAB_OFFSET, shstrtab, sizeof(shstrtab));

	memset(&shdr, 0, sizeof(shdr));
	shdr.sh_name = shstrtab_name;
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_offset = PKM_KUNIT_ELF_STRTAB_OFFSET;
	shdr.sh_size = sizeof(shstrtab);
	memcpy(file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr), &shdr,
	       sizeof(shdr));

	if (!include_sig_section)
		return;

	memcpy(file + PKM_KUNIT_ELF_SIG_OFFSET, sig_blob,
	       PKM_KUNIT_SIGNING_BLOB_LEN);
	memset(&shdr, 0, sizeof(shdr));
	shdr.sh_name = sig_name;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_offset = PKM_KUNIT_ELF_SIG_OFFSET;
	shdr.sh_size = valid_sig_section ? PKM_KUNIT_SIGNING_BLOB_LEN :
					   PKM_KUNIT_SIGNING_BLOB_LEN - 1;
	memcpy(file + PKM_KUNIT_ELF_SHOFF + (2 * sizeof(Elf64_Shdr)), &shdr,
	       sizeof(shdr));
}


void pkm_kunit_signing_fill_probe(
	struct pkm_kacs_kunit_signing_probe *probe)
{
	u32 i;

	memset(probe, 0, sizeof(*probe));
	probe->source = PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR;
	for (i = 0; i < sizeof(probe->signature); i++)
		probe->signature[i] = (u8)(0x41U + i);
	for (i = 0; i < sizeof(probe->hash); i++)
		probe->hash[i] = (u8)(0x81U + i);
}


void pkm_kunit_signing_fill_key(
	struct pkm_kacs_kunit_signing_key_entry *key, u8 seed, u32 pip_type,
	u32 pip_trust)
{
	u32 i;

	memset(key, 0, sizeof(*key));
	for (i = 0; i < sizeof(key->public_key); i++)
		key->public_key[i] = seed + (u8)i;
	key->pip_type = pip_type;
	key->pip_trust = pip_trust;
}


void pkm_kunit_signing_fill_tcb_vector_material(
	struct pkm_kacs_kunit_signing_probe *material)
{
	static const u8 hash[32] = {
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	};
	static const u8 signature[64] = {
		0x01, 0x05, 0x5e, 0xed, 0x19, 0xb9, 0x4a, 0x3a,
		0x8d, 0x1f, 0x9d, 0x45, 0xa1, 0x3f, 0x2b, 0x69,
		0x02, 0x04, 0xcb, 0x20, 0x62, 0xdb, 0xfe, 0x84,
		0xcc, 0xb2, 0xf8, 0x37, 0x8a, 0x0d, 0xad, 0x26,
		0x9e, 0x81, 0x4a, 0xe4, 0x54, 0xfb, 0x5b, 0x30,
		0xd3, 0x6a, 0x24, 0x42, 0xe8, 0xa3, 0x2f, 0x6b,
		0xa2, 0xfc, 0xbb, 0x41, 0xba, 0x2e, 0x52, 0x93,
		0x68, 0xd2, 0x26, 0x73, 0x15, 0xc1, 0x3e, 0x02,
	};

	memset(material, 0, sizeof(*material));
	material->source = PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR;
	memcpy(material->hash, hash, sizeof(material->hash));
	memcpy(material->signature, signature, sizeof(material->signature));
}


int pkm_kunit_ed25519_crypto_verify(const u8 *public_key,
					   unsigned int public_key_len,
					   const u8 *msg, unsigned int msg_len,
					   const u8 *signature,
					   unsigned int signature_len)
{
	struct crypto_sig *tfm;
	int ret;

	tfm = crypto_alloc_sig("ed25519", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_sig_set_pubkey(tfm, public_key, public_key_len);
	if (!ret)
		ret = crypto_sig_verify(tfm, signature, signature_len, msg,
					msg_len);
	crypto_free_sig(tfm);
	return ret;
}


int pkm_kunit_check_path_metadata_with_mask(u32 granted_mask, u32 op,
						   u32 mode, const char *name)
{
	const void *subject_token = pkm_kacs_current_effective_token_ptr();
	const u8 *file_sd;
	size_t file_sd_len = 0;
	int ret;

	if (!subject_token)
		return -EACCES;

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   granted_mask,
						   &file_sd_len);
	if (!file_sd)
		return -ENOMEM;

	ret = pkm_kacs_kunit_check_path_metadata_live(
		file_sd, file_sd_len, PKM_KACS_KUNIT_FILE_SD_VALID, op,
		mode, name);
	pkm_kacs_free((void *)file_sd);
	return ret;
}


int pkm_kunit_check_path_metadata_with_foreign_everyone_mask(
	u32 granted_mask, u32 op, u32 mode, const char *name)
{
	const void *owner_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	int ret;

	owner_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0U, 0ULL);
	if (!owner_token)
		return -ENOMEM;

	file_sd = kacs_rust_kunit_create_file_sd(owner_token, 0, 0, 0,
						 granted_mask, &file_sd_len);
	if (!file_sd) {
		kacs_rust_token_drop(owner_token);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_check_path_metadata_live(
		file_sd, file_sd_len, PKM_KACS_KUNIT_FILE_SD_VALID, op,
		mode, name);
	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(owner_token);
	return ret;
}


int pkm_kunit_check_inode_permission_with_mask(
	const void *subject_token, u32 granted_mask, int mask)
{
	const u8 *file_sd;
	size_t file_sd_len = 0;
	int ret;

	if (!subject_token)
		return -EINVAL;

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   granted_mask,
						   &file_sd_len);
	if (!file_sd)
		return -ENOMEM;

	ret = pkm_kacs_kunit_check_inode_permission_live(
		file_sd, file_sd_len, PKM_KACS_KUNIT_FILE_SD_VALID,
		KACS_MOUNT_POLICY_DENY_MISSING, subject_token, mask);
	pkm_kacs_free((void *)file_sd);
	return ret;
}


int pkm_kunit_check_inode_permission_with_mode(
	const void *subject_token, u32 granted_mask, u32 mode, int mask)
{
	const u8 *file_sd;
	size_t file_sd_len = 0;
	int ret;

	if (!subject_token)
		return -EINVAL;

	file_sd = pkm_kunit_create_precise_file_sd(subject_token,
						   granted_mask,
						   &file_sd_len);
	if (!file_sd)
		return -ENOMEM;

	ret = pkm_kacs_kunit_check_inode_permission_live_mode(
		file_sd, file_sd_len, PKM_KACS_KUNIT_FILE_SD_VALID,
		KACS_MOUNT_POLICY_DENY_MISSING, subject_token, mode, mask);
	pkm_kacs_free((void *)file_sd);
	return ret;
}


int pkm_kunit_namespace_parent_op(const void *subject_token,
					 u32 parent_mask, u32 op,
					 const u8 **created_sd_out,
					 size_t *created_sd_len_out)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.old_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.op = op,
	};
	const u8 *parent_sd;
	size_t parent_sd_len = 0;
	int ret;

	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     parent_mask,
						     &parent_sd_len);
	if (!parent_sd)
		return -ENOMEM;
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.old_parent_sd_ptr = parent_sd;
	args.old_parent_sd_len = parent_sd_len;
	ret = pkm_kacs_kunit_check_namespace_live(&args, created_sd_out,
						  created_sd_len_out);
	pkm_kacs_free((void *)parent_sd);
	return ret;
}


int pkm_kunit_namespace_mknod_mode_op(const void *subject_token,
					     u32 parent_mask, umode_t mode,
					     const u8 **created_sd_out,
					     size_t *created_sd_len_out)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.old_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.op = PKM_KACS_KUNIT_NAMESPACE_MKNOD,
		.target_mode = mode,
		.target_mode_set = 1,
	};
	const u8 *parent_sd;
	size_t parent_sd_len = 0;
	int ret;

	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     parent_mask,
						     &parent_sd_len);
	if (!parent_sd)
		return -ENOMEM;
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.old_parent_sd_ptr = parent_sd;
	args.old_parent_sd_len = parent_sd_len;
	ret = pkm_kacs_kunit_check_namespace_live(&args, created_sd_out,
						  created_sd_len_out);
	pkm_kacs_free((void *)parent_sd);
	return ret;
}


int pkm_kunit_namespace_link_op(const void *subject_token,
				       u32 source_mask, u32 parent_mask)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.source_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.new_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.op = PKM_KACS_KUNIT_NAMESPACE_LINK,
	};
	const u8 *source_sd;
	const u8 *parent_sd;
	size_t source_sd_len = 0;
	size_t parent_sd_len = 0;
	int ret;

	source_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     source_mask,
						     &source_sd_len);
	if (!source_sd)
		return -ENOMEM;
	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     parent_mask,
						     &parent_sd_len);
	if (!parent_sd) {
		pkm_kacs_free((void *)source_sd);
		return -ENOMEM;
	}

	args.source_sd_ptr = source_sd;
	args.source_sd_len = source_sd_len;
	args.new_parent_sd_ptr = parent_sd;
	args.new_parent_sd_len = parent_sd_len;
	ret = pkm_kacs_kunit_check_namespace_live(&args, NULL, NULL);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)source_sd);
	return ret;
}


int pkm_kunit_namespace_delete_op(const void *subject_token,
					 u32 target_mask, u32 parent_mask,
					 u32 op, umode_t target_mode)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.source_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.old_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.op = op,
		.source_mode = target_mode,
	};
	const u8 *target_sd;
	const u8 *parent_sd;
	size_t target_sd_len = 0;
	size_t parent_sd_len = 0;
	int ret;

	target_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     target_mask,
						     &target_sd_len);
	if (!target_sd)
		return -ENOMEM;
	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     parent_mask,
						     &parent_sd_len);
	if (!parent_sd) {
		pkm_kacs_free((void *)target_sd);
		return -ENOMEM;
	}

	args.source_sd_ptr = target_sd;
	args.source_sd_len = target_sd_len;
	args.old_parent_sd_ptr = parent_sd;
	args.old_parent_sd_len = parent_sd_len;
	ret = pkm_kacs_kunit_check_namespace_live(&args, NULL, NULL);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)target_sd);
	return ret;
}


int pkm_kunit_namespace_rename_op(const void *subject_token,
					 u32 source_mask,
					 u32 old_parent_mask,
					 u32 new_parent_mask,
					 u32 target_mask,
					 bool target_present,
					 umode_t source_mode)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.source_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.old_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.new_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.op = PKM_KACS_KUNIT_NAMESPACE_RENAME,
		.source_mode = source_mode,
	};
	const u8 *source_sd;
	const u8 *old_parent_sd;
	const u8 *new_parent_sd;
	const u8 *target_sd = NULL;
	size_t source_sd_len = 0;
	size_t old_parent_sd_len = 0;
	size_t new_parent_sd_len = 0;
	size_t target_sd_len = 0;
	int ret;

	source_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     source_mask,
						     &source_sd_len);
	if (!source_sd)
		return -ENOMEM;
	old_parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
							 old_parent_mask,
							 &old_parent_sd_len);
	if (!old_parent_sd) {
		ret = -ENOMEM;
		goto out_source;
	}
	new_parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
							 new_parent_mask,
							 &new_parent_sd_len);
	if (!new_parent_sd) {
		ret = -ENOMEM;
		goto out_old_parent;
	}
	if (target_present) {
		target_sd = pkm_kunit_create_precise_file_sd(subject_token,
							     target_mask,
							     &target_sd_len);
		if (!target_sd) {
			ret = -ENOMEM;
			goto out_new_parent;
		}
		args.target_sd_ptr = target_sd;
		args.target_sd_len = target_sd_len;
		args.target_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	}

	args.source_sd_ptr = source_sd;
	args.source_sd_len = source_sd_len;
	args.old_parent_sd_ptr = old_parent_sd;
	args.old_parent_sd_len = old_parent_sd_len;
	args.new_parent_sd_ptr = new_parent_sd;
	args.new_parent_sd_len = new_parent_sd_len;
	ret = pkm_kacs_kunit_check_namespace_live(&args, NULL, NULL);

	if (target_sd)
		pkm_kacs_free((void *)target_sd);
out_new_parent:
	pkm_kacs_free((void *)new_parent_sd);
out_old_parent:
	pkm_kacs_free((void *)old_parent_sd);
out_source:
	pkm_kacs_free((void *)source_sd);
	return ret;
}


int pkm_kunit_namespace_readlink_op(const void *subject_token,
					   u32 source_mask)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.source_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.op = PKM_KACS_KUNIT_NAMESPACE_READLINK,
		.source_mode = S_IFLNK,
	};
	const u8 *source_sd;
	size_t source_sd_len = 0;
	int ret;

	source_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     source_mask,
						     &source_sd_len);
	if (!source_sd)
		return -ENOMEM;

	args.source_sd_ptr = source_sd;
	args.source_sd_len = source_sd_len;
	ret = pkm_kacs_kunit_check_namespace_live(&args, NULL, NULL);

	pkm_kacs_free((void *)source_sd);
	return ret;
}


int pkm_kunit_namespace_rename_flags_op(const void *subject_token,
					       u32 mount_policy,
					       u32 old_parent_mask,
					       unsigned int flags)
{
	struct pkm_kacs_kunit_namespace_args args = {
		.subject_token = subject_token,
		.old_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.new_parent_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.mount_policy_override = mount_policy,
	};
	const u8 *old_parent_sd;
	const u8 *new_parent_sd;
	size_t old_parent_sd_len = 0;
	size_t new_parent_sd_len = 0;
	int ret;

	/*
	 * RENAME_WHITEOUT authorization checks FILE_ADD_FILE on the source
	 * parent (where the whiteout sentinel lands), so old_parent_mask drives
	 * the grant/deny outcome. The new parent is irrelevant to this hook.
	 */
	old_parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token, old_parent_mask,
		&old_parent_sd_len);
	if (!old_parent_sd)
		return -ENOMEM;
	new_parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		&new_parent_sd_len);
	if (!new_parent_sd) {
		pkm_kacs_free((void *)old_parent_sd);
		return -ENOMEM;
	}

	args.old_parent_sd_ptr = old_parent_sd;
	args.old_parent_sd_len = old_parent_sd_len;
	args.new_parent_sd_ptr = new_parent_sd;
	args.new_parent_sd_len = new_parent_sd_len;
	ret = pkm_kacs_kunit_check_namespace_rename_flags(&args, flags);

	pkm_kacs_free((void *)new_parent_sd);
	pkm_kacs_free((void *)old_parent_sd);
	return ret;
}


void pkm_kunit_expect_ioctl_access(
	struct kunit *test, const struct pkm_kunit_ioctl_expectation *entry)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, entry->allowed_access, entry->mode,
				entry->cmd, entry->compat),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_file_ioctl_snapshot(
				1, entry->denied_access, entry->mode,
				entry->cmd, entry->compat),
			-EACCES);
}


void pkm_kunit_expect_proc_metadata_debug_bypass(
	struct kunit *test, u32 proc_mode)
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

	if (proc_mode == PTRACE_MODE_PROC_QUERY_INFORMATION)
		process_sd = kacs_rust_kunit_create_query_limited_process_sd(
			target_token, &process_sd_len);
	else
		process_sd = kacs_rust_kunit_create_query_information_process_sd(
			target_token, &process_sd_len);

	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | proc_mode;

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


void pkm_kunit_expect_proc_metadata_debug_pip_denial(
	struct kunit *test, u32 proc_mode)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
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

	if (proc_mode == PTRACE_MODE_PROC_QUERY_INFORMATION)
		process_sd = kacs_rust_kunit_create_query_limited_process_sd(
			target_token, &process_sd_len);
	else
		process_sd = kacs_rust_kunit_create_query_information_process_sd(
			target_token, &process_sd_len);

	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_READ | proc_mode;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


const u8 *pkm_kunit_create_default_file_sd(const void *token,
						  size_t *len_out)
{
	return kacs_rust_kunit_create_file_sd(
		token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KUNIT_FILE_SD_ADMIN_MASK, PKM_KUNIT_FILE_SD_ADMIN_MASK, 0,
		len_out);
}


const u8 *pkm_kunit_create_query_only_file_sd(const void *token,
						     size_t *len_out)
{
	return kacs_rust_kunit_create_file_sd(token, 0, 0, 0,
					      PKM_KUNIT_FILE_SD_QUERY_MASK,
					      len_out);
}


const u8 *pkm_kunit_create_write_only_file_sd(const void *token,
						     size_t *len_out)
{
	return kacs_rust_kunit_create_file_sd(token, 0, 0, 0,
					      PKM_KUNIT_FILE_SD_WRITE_MASK,
					      len_out);
}


const u8 *pkm_kunit_create_file_sd_with_mandatory_resource_attr(
	const void *token, size_t *len_out)
{
	return kacs_rust_kunit_create_file_sd_with_mandatory_resource_attr(
		token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KUNIT_FILE_SD_ADMIN_MASK, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		0, len_out);
}


const u8 *pkm_kunit_create_file_sd_with_mandatory_resource_attr_value(
	const void *token, u64 value, size_t *len_out)
{
	return kacs_rust_kunit_create_file_sd_with_mandatory_resource_attr_value(
		token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KUNIT_FILE_SD_ADMIN_MASK, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		0, value, len_out);
}


const u8 *pkm_kunit_create_labeled_file_sd(const void *token,
						  u32 integrity_level,
						  size_t *len_out)
{
	return kacs_rust_kunit_create_labeled_file_sd(
		token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KUNIT_FILE_SD_ADMIN_MASK, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		0, integrity_level, len_out);
}


const u8 *pkm_kunit_create_labeled_audit_file_sd(
	const void *token, u32 integrity_level, size_t *len_out)
{
	return kacs_rust_kunit_create_labeled_audit_file_sd(
		token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KUNIT_FILE_SD_ADMIN_MASK, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		0, integrity_level, len_out);
}


const u8 *pkm_kunit_create_precise_file_sd(const void *token,
						  u32 self_mask,
						  size_t *len_out)
{
	return kacs_rust_kunit_create_file_sd(token, self_mask, 0, 0, 0,
					      len_out);
}


const u8 *pkm_kunit_synthesize_file_sd(const u8 *parent_sd,
					      size_t parent_sd_len,
					      const u8 *template_sd,
					      size_t template_sd_len,
					      u32 child_is_directory,
					      size_t *len_out)
{
	const u8 *sd = NULL;
	size_t sd_len = 0;

	if (kacs_rust_synthesize_file_sd(parent_sd, parent_sd_len, template_sd,
					 template_sd_len,
					 child_is_directory, &sd,
					 &sd_len) != 0)
		return NULL;

	if (len_out)
		*len_out = sd_len;
	return sd;
}


const u8 *pkm_kunit_first_dacl_ace_const(const u8 *sd_bytes)
{
	u32 dacl_offset;

	if (!sd_bytes)
		return NULL;

	dacl_offset = pkm_kunit_read_u32(sd_bytes, 16);
	if (dacl_offset == 0)
		return NULL;
	if (pkm_kunit_read_u16(sd_bytes, dacl_offset + 4) == 0)
		return NULL;

	return sd_bytes + dacl_offset + 8;
}


const u8 *pkm_kunit_first_sacl_ace_const(const u8 *sd_bytes)
{
	u32 sacl_offset;

	if (!sd_bytes)
		return NULL;

	sacl_offset = pkm_kunit_read_u32(sd_bytes, 12);
	if (sacl_offset == 0)
		return NULL;
	if (pkm_kunit_read_u16(sd_bytes, sacl_offset + 4) == 0)
		return NULL;

	return sd_bytes + sacl_offset + 8;
}


u8 *pkm_kunit_first_dacl_ace(u8 *sd_bytes)
{
	return (u8 *)pkm_kunit_first_dacl_ace_const(sd_bytes);
}


const u8 *pkm_kunit_first_inherited_dacl_ace_const(const u8 *sd_bytes)
{
	const u8 *ace;
	u32 dacl_offset;
	u16 ace_count;
	u16 i;

	if (!sd_bytes)
		return NULL;

	dacl_offset = pkm_kunit_read_u32(sd_bytes, 16);
	if (dacl_offset == 0)
		return NULL;

	ace_count = pkm_kunit_read_u16(sd_bytes, dacl_offset + 4);
	ace = sd_bytes + dacl_offset + 8;
	for (i = 0; i < ace_count; i++) {
		u16 ace_size = pkm_kunit_read_u16(ace, 2);

		if ((ace[1] & PKM_KUNIT_INHERITED_ACE) != 0)
			return ace;
		if (ace_size == 0)
			return NULL;
		ace += ace_size;
	}

	return NULL;
}


const u8 *pkm_kunit_first_inherited_sacl_ace_const(const u8 *sd_bytes)
{
	const u8 *ace;
	u32 sacl_offset;
	u16 ace_count;
	u16 i;

	if (!sd_bytes)
		return NULL;

	sacl_offset = pkm_kunit_read_u32(sd_bytes, 12);
	if (sacl_offset == 0)
		return NULL;

	ace_count = pkm_kunit_read_u16(sd_bytes, sacl_offset + 4);
	ace = sd_bytes + sacl_offset + 8;
	for (i = 0; i < ace_count; i++) {
		u16 ace_size = pkm_kunit_read_u16(ace, 2);

		if ((ace[1] & PKM_KUNIT_INHERITED_ACE) != 0)
			return ace;
		if (ace_size == 0)
			return NULL;
		ace += ace_size;
	}

	return NULL;
}


void pkm_kunit_make_first_file_ace_inheritable(u8 *sd_bytes,
						      u8 inherit_flags)
{
	u8 *ace;

	ace = pkm_kunit_first_dacl_ace(sd_bytes);
	if (!ace)
		return;

	ace[1] = inherit_flags;
}


void pkm_kunit_make_first_file_ace_mask(u8 *sd_bytes, u32 mask)
{
	u8 *ace;

	ace = pkm_kunit_first_dacl_ace(sd_bytes);
	if (!ace)
		return;

	pkm_kunit_write_u32(ace, 4, mask);
}


void pkm_kunit_make_first_sacl_ace_inheritable(u8 *sd_bytes,
						      u8 inherit_flags)
{
	u8 *ace;

	ace = (u8 *)pkm_kunit_first_sacl_ace_const(sd_bytes);
	if (!ace)
		return;

	ace[1] = inherit_flags;
}


void pkm_kunit_make_first_file_ace_opaque(u8 *sd_bytes, u8 ace_flags)
{
	u8 *ace;

	ace = pkm_kunit_first_dacl_ace(sd_bytes);
	if (!ace)
		return;

	ace[0] = PKM_KUNIT_OPAQUE_ACE_TYPE;
	ace[1] = ace_flags;
}


void pkm_kunit_make_first_file_ace_sid(u8 *sd_bytes, const u8 *sid,
					      size_t sid_len)
{
	u8 *ace;

	if (!sid)
		return;

	ace = pkm_kunit_first_dacl_ace(sd_bytes);
	if (!ace)
		return;
	if (pkm_kunit_read_u16(ace, 2) != 8U + sid_len)
		return;

	memcpy(ace + 8, sid, sid_len);
}


long pkm_kunit_create_condition_token_ex(
	bool with_device_group, bool with_user_claim, bool with_device_claim,
	const struct pkm_kunit_sid_attr_spec *restricted_sids,
	u32 restricted_sid_count,
	const struct pkm_kunit_sid_attr_spec *restricted_device_groups,
	u32 restricted_device_group_count,
	struct pkm_kacs_token_fd_view *view)
{
	static const u8 source_name[8] = {
		'D', 'e', 'v', 'C', 'o', 'n', 'd', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec device_groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.source_id = 0x444556434f4e4400ULL,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	u8 session_spec[128] = { };
	u8 token_spec[1024] = { };
	u8 user_claim_entry[96] = { };
	u8 device_claim_entry[96] = { };
	u8 user_claims[128] = { };
	u8 device_claims[128] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t user_claims_len = 0;
	size_t device_claims_len = 0;
	size_t entry_len;
	size_t spec_len;
	long fd;
	long ret;

	if (!view)
		return -EINVAL;
	memset(view, 0, sizeof(*view));

	subject_token = pkm_kacs_current_primary_token_ptr();
	if (!subject_token)
		return -EACCES;

	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	if (!spec_len)
		return -EINVAL;

	ret = pkm_kacs_kunit_create_session_for_subject(
		subject_token, session_spec, spec_len, &session_id);
	if (ret)
		return ret;

	spec_args.session_id = session_id;
	if (with_device_group) {
		spec_args.device_groups = device_groups;
		spec_args.device_group_count = ARRAY_SIZE(device_groups);
		spec_args.source_id++;
	}
	if (restricted_sid_count) {
		if (!restricted_sids)
			return -EINVAL;
		spec_args.restricted_sids = restricted_sids;
		spec_args.restricted_sid_count = restricted_sid_count;
		spec_args.source_id += 0x08ULL;
	}
	if (restricted_device_group_count) {
		if (!restricted_device_groups)
			return -EINVAL;
		spec_args.restricted_device_groups = restricted_device_groups;
		spec_args.restricted_device_group_count =
			restricted_device_group_count;
		spec_args.source_id += 0x10ULL;
	}
	if (with_user_claim) {
		entry_len = pkm_kunit_build_claim_entry_scalar(
			user_claim_entry, sizeof(user_claim_entry), "KacsGate",
			PKM_KUNIT_CLAIM_TYPE_BOOLEAN, 0U, 1U);
		if (!entry_len ||
		    pkm_kunit_append_claim_entry(user_claims,
						sizeof(user_claims),
						&user_claims_len,
						user_claim_entry, entry_len))
			return -EINVAL;
		spec_args.user_claims = user_claims;
		spec_args.user_claims_len = user_claims_len;
		spec_args.source_id += 0x100ULL;
	}
	if (with_device_claim) {
		entry_len = pkm_kunit_build_claim_entry_scalar(
			device_claim_entry, sizeof(device_claim_entry),
			"KacsGate", PKM_KUNIT_CLAIM_TYPE_BOOLEAN, 0U, 1U);
		if (!entry_len ||
		    pkm_kunit_append_claim_entry(device_claims,
						sizeof(device_claims),
						&device_claims_len,
						device_claim_entry, entry_len))
			return -EINVAL;
		spec_args.device_claims = device_claims;
		spec_args.device_claims_len = device_claims_len;
		spec_args.source_id += 0x200ULL;
	}

	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	if (!spec_len)
		return -EINVAL;

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     spec_len);
	if (fd < 0)
		return fd;

	ret = pkm_kacs_kunit_token_fd_snapshot((int)fd, view);
	if (ret) {
		close_fd((unsigned int)fd);
		return ret;
	}

	return fd;
}


long pkm_kunit_create_condition_token(
	bool with_device_group, bool with_user_claim, bool with_device_claim,
	const struct pkm_kunit_sid_attr_spec *restricted_device_groups,
	u32 restricted_device_group_count,
	struct pkm_kacs_token_fd_view *view)
{
	return pkm_kunit_create_condition_token_ex(
		with_device_group, with_user_claim, with_device_claim, NULL, 0,
		restricted_device_groups, restricted_device_group_count, view);
}


long pkm_kunit_create_device_condition_token(
	bool with_device_group, struct pkm_kacs_token_fd_view *view)
{
	return pkm_kunit_create_condition_token(with_device_group, false, false,
						NULL, 0, view);
}


void pkm_kunit_expect_native_overwrite_identity(struct kunit *test,
						       u32 create_disposition)
{
	struct pkm_kacs_kunit_native_open_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA |
				  PKM_KUNIT_FILE_WRITE_DATA,
		.create_disposition = create_disposition,
	};
	struct pkm_kacs_kunit_native_identity_result result = {};
	const void *subject_token;
	const u8 *target_sd;
	const u8 *parent_sd;
	size_t target_sd_len = 0;
	size_t parent_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA |
			PKM_KUNIT_FILE_WRITE_ATTRIBUTES |
			KACS_ACCESS_READ_CONTROL,
		&target_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_sd);
	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_READ_DATA | PKM_KUNIT_FILE_WRITE_DATA |
			PKM_KUNIT_FILE_DELETE_CHILD | KACS_ACCESS_DELETE |
			KACS_ACCESS_READ_CONTROL,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_sd;
	args.target_file_sd_len = target_sd_len;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;

	ret = pkm_kacs_kunit_native_overwrite_identity_for_subject(
		&args, &result);
	KUNIT_ASSERT_EQ_MSG(test, ret, 0L, "failure_step=%u",
			    result.failure_step);
	KUNIT_EXPECT_EQ(test, result.status, KACS_STATUS_OVERWRITTEN);
	KUNIT_EXPECT_EQ(test, result.granted_access, args.desired_access);
	KUNIT_EXPECT_GT(test, result.size_before, 0ULL);
	KUNIT_EXPECT_EQ(test, result.size_after, 0ULL);
	KUNIT_EXPECT_EQ(test, result.old_fd_size_after, 0ULL);
	KUNIT_EXPECT_EQ(test, result.same_inode_after, 1U);
	KUNIT_EXPECT_EQ(test, result.hardlink_preserved, 1U);
	KUNIT_EXPECT_EQ(test, result.old_fd_preserved, 1U);
	KUNIT_EXPECT_EQ(test, result.sd_preserved, 1U);

	pkm_kacs_free((void *)parent_sd);
	pkm_kacs_free((void *)target_sd);
}


void pkm_kunit_expect_native_create_owner_success(
	struct kunit *test, const void *subject_token, const u8 *owner_sid,
	size_t owner_sid_len)
{
	struct pkm_kacs_kunit_native_create_args args = {
		.desired_access = PKM_KUNIT_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	u8 creator_sd[128] = { };
	const u8 *parent_sd = NULL;
	const u8 *created_sd = NULL;
	size_t creator_sd_len = 0;
	size_t parent_sd_len = 0;
	size_t created_sd_len = 0;

	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	creator_sd_len = pkm_kunit_build_owner_subset_sd(
		creator_sd, sizeof(creator_sd), owner_sid, owner_sid_len);
	KUNIT_ASSERT_GT(test, (long)creator_sd_len, 0L);

	parent_sd = pkm_kunit_create_precise_file_sd(
		subject_token,
		PKM_KUNIT_FILE_WRITE_DATA | PKM_KUNIT_FILE_READ_DATA,
		&parent_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, parent_sd);
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	args.subject_token = subject_token;
	args.parent_file_sd_ptr = parent_sd;
	args.parent_file_sd_len = parent_sd_len;
	args.parent_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	args.creator_sd_ptr = creator_sd;
	args.creator_sd_len = creator_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_native_create_for_subject(
				&args, &created_sd, &created_sd_len, NULL,
				NULL),
			0L);
	pkm_kunit_expect_sd_sid_component(test, created_sd, created_sd_len, 4,
					  owner_sid, owner_sid_len);

	pkm_kacs_free((void *)created_sd);
	pkm_kacs_free((void *)parent_sd);
}


void pkm_kunit_expect_get_sd_syscall_copyout(
	struct kunit *test, int fd, const u8 *expected, size_t expected_len,
	u32 security_info)
{
	char empty_path[] = "";
	u8 *buffer;
	u8 *short_buffer;
	size_t short_len;

	KUNIT_ASSERT_NOT_NULL(test, expected);
	KUNIT_ASSERT_GT(test, (long)expected_len, 1L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_sd_syscall(
				fd, empty_path, security_info, NULL, 0,
				AT_EMPTY_PATH),
			(long)expected_len);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_sd_syscall(
				fd, empty_path, security_info, NULL,
				(u32)expected_len, AT_EMPTY_PATH),
			(long)-EFAULT);

	buffer = kunit_kzalloc(test, expected_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	memset(buffer, 0xaa, expected_len);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_get_sd_syscall(
				fd, empty_path, security_info, buffer,
				(u32)expected_len, AT_EMPTY_PATH),
			(long)expected_len);
	KUNIT_EXPECT_EQ(test, memcmp(buffer, expected, expected_len), 0);

	short_len = expected_len - 1;
	short_buffer = kunit_kzalloc(test, short_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, short_buffer);
	memset(short_buffer, 0xaa, short_len);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_get_sd_syscall(
				fd, empty_path, security_info, short_buffer,
				(u32)short_len, AT_EMPTY_PATH),
			(long)expected_len);
	KUNIT_EXPECT_EQ(test, short_buffer[0], 0xaa);
}


void pkm_kunit_expect_mount_policy_failure_preserves_state(
	struct kunit *test, const void *subject_token,
	const struct kacs_mount_policy_args *initial_args,
	const struct kacs_mount_policy_args *failure_args,
	long expected_failure_ret, u32 expected_template_len)
{
	long failure_ret = 0;
	u32 policy = 0;
	u32 generation = 0;
	u32 template_len = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_mount_policy_failure_preserves_state(
				subject_token, TMPFS_MAGIC, initial_args,
				failure_args, &failure_ret, &policy,
				&generation, &template_len),
			0L);
	KUNIT_EXPECT_EQ(test, failure_ret, expected_failure_ret);
	KUNIT_EXPECT_EQ(test, policy,
			KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT);
	KUNIT_EXPECT_EQ(test, generation, 1U);
	KUNIT_EXPECT_EQ(test, template_len, expected_template_len);
}


void pkm_kunit_expect_inherited_ace_flags(struct kunit *test,
						 const u8 *sd_bytes,
						 bool expect_inherited,
						 u8 expected_flags)
{
	const u8 *ace;

	ace = pkm_kunit_first_inherited_dacl_ace_const(sd_bytes);
	if (!expect_inherited) {
		KUNIT_EXPECT_NULL(test, ace);
		return;
	}

	KUNIT_ASSERT_NOT_NULL(test, ace);
	KUNIT_EXPECT_EQ(test, ace[1], expected_flags);
}


void pkm_kunit_expect_inherited_sacl_ace_flags(struct kunit *test,
						      const u8 *sd_bytes,
						      bool expect_inherited,
						      u8 expected_flags)
{
	const u8 *ace;

	ace = pkm_kunit_first_inherited_sacl_ace_const(sd_bytes);
	if (!expect_inherited) {
		KUNIT_EXPECT_NULL(test, ace);
		return;
	}

	KUNIT_ASSERT_NOT_NULL(test, ace);
	KUNIT_EXPECT_EQ(test, ace[1], expected_flags);
}


int pkm_kunit_open_current_pidfd(void)
{
	struct file *file = NULL;
	struct pid *pid;
	int fd;

	pid = get_task_pid(current, PIDTYPE_PID);
	if (!pid)
		return -ESRCH;

	fd = pidfd_prepare(pid, 0, &file);
	put_pid(pid);
	if (fd < 0)
		return fd;

	fd_install(fd, file);
	return fd;
}


void pkm_kunit_expect_default_process_sd_shape(
	struct kunit *test, const u8 *process_sd, size_t process_sd_len,
	const struct pkm_kacs_boot_snapshot *snapshot)
{
	const u16 expected_control = PKM_KUNIT_SE_SELF_RELATIVE |
				     PKM_KUNIT_SE_OWNER_DEFAULTED |
				     PKM_KUNIT_SE_GROUP_DEFAULTED |
				     PKM_KUNIT_SE_DACL_DEFAULTED |
				     PKM_KUNIT_SE_DACL_PRESENT;
	const struct pkm_kacs_boot_group_view *primary_group;
	u32 dacl_offset;

	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	KUNIT_ASSERT_NOT_NULL(test, snapshot);
	KUNIT_ASSERT_GT(test, (long)process_sd_len, 20L);
	KUNIT_ASSERT_NE(test, snapshot->primary_group_index, 0U);
	KUNIT_ASSERT_LT(test, snapshot->primary_group_index,
			snapshot->group_count + 1);
	primary_group = &snapshot->groups_ptr[snapshot->primary_group_index - 1];

	KUNIT_EXPECT_EQ(test, process_sd[0], 1);
	KUNIT_EXPECT_EQ(test, process_sd[1], 0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u16(process_sd, 2),
			expected_control);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(process_sd, 12), 0U);
	pkm_kunit_expect_sd_sid_component(test, process_sd, process_sd_len, 4,
					  snapshot->user_sid_ptr,
					  snapshot->user_sid_len);
	pkm_kunit_expect_sd_sid_component(test, process_sd, process_sd_len, 8,
					  primary_group->sid_ptr,
					  primary_group->sid_len);

	dacl_offset = pkm_kunit_read_u32(process_sd, 16);
	KUNIT_ASSERT_NE(test, dacl_offset, 0U);
	KUNIT_ASSERT_LE(test, (size_t)dacl_offset + 8, process_sd_len);
	KUNIT_EXPECT_EQ(test, process_sd[dacl_offset], 2);
	KUNIT_EXPECT_EQ(test, process_sd[dacl_offset + 1], 0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u16(process_sd, dacl_offset + 2),
			(u16)(process_sd_len - dacl_offset));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u16(process_sd, dacl_offset + 4),
			4);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u16(process_sd, dacl_offset + 6),
			0);

	pkm_kunit_expect_allow_ace(test, process_sd, process_sd_len, 0,
				   KACS_ACCESS_GENERIC_ALL,
				   snapshot->user_sid_ptr,
				   snapshot->user_sid_len);
	pkm_kunit_expect_allow_ace(test, process_sd, process_sd_len, 1,
				   KACS_ACCESS_GENERIC_ALL,
				   pkm_kunit_administrators_sid,
				   sizeof(pkm_kunit_administrators_sid));
	pkm_kunit_expect_allow_ace(test, process_sd, process_sd_len, 2,
				   KACS_ACCESS_GENERIC_ALL,
				   pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	pkm_kunit_expect_allow_ace(test, process_sd, process_sd_len, 3,
				   KACS_PROCESS_QUERY_LIMITED,
				   pkm_kunit_everyone_sid,
				   sizeof(pkm_kunit_everyone_sid));
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kunit_dacl_ace_const(process_sd,
						     process_sd_len, 4),
			    NULL);
}


void pkm_kunit_expect_impersonation_gate(
	struct kunit *test,
	const struct pkm_kunit_impersonation_gate_case *gate_case)
{
	const void *server_token;
	const void *client_token;
	u32 effective_level = 0xffffffffU;
	u32 used_impersonate = 0xffffffffU;
	long ret;

	server_token =
		kacs_rust_kunit_create_impersonation_variant_token_with_privileges(
			gate_case->server_user_kind, KACS_TOKEN_TYPE_PRIMARY,
			KACS_IMLEVEL_ANONYMOUS, gate_case->server_integrity,
			gate_case->server_restricted,
			gate_case->server_privileges_present,
			gate_case->server_privileges_enabled,
			gate_case->server_privileges_enabled_by_default);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		gate_case->client_user_kind, KACS_TOKEN_TYPE_IMPERSONATION,
		gate_case->requested_level, gate_case->client_integrity,
		gate_case->client_restricted, 0);
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	ret = kacs_rust_token_impersonation_gate(
		server_token, client_token, &effective_level, &used_impersonate);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, effective_level, gate_case->expected_level);
	KUNIT_EXPECT_EQ(test, used_impersonate,
			gate_case->expected_used_impersonate);

	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


void pkm_kunit_expect_token_own_sd_valid(struct kunit *test,
						const void *token)
{
	struct pkm_kacs_boot_snapshot snapshot = { };

	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &snapshot));
	KUNIT_EXPECT_PTR_EQ(test, snapshot.token_ptr, token);
	KUNIT_ASSERT_NOT_NULL(test, snapshot.own_sd_ptr);
	KUNIT_ASSERT_GT(test, (long)snapshot.own_sd_len, 0L);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_sd_bytes(snapshot.own_sd_ptr,
						    snapshot.own_sd_len),
			0);
}


void pkm_kunit_expect_access_check_list_input_denied(
	struct kunit *test, u8 *object_tree, size_t object_tree_len,
	u64 object_tree_ptr, u32 object_tree_count, u32 results_count)
{
	u8 args[136];
	u8 granted_out[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	u8 results[24] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	};
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	long ret;

	pkm_kunit_build_read_control_args(args, -1);
	pkm_kunit_write_u64(args, 56, object_tree_ptr);
	pkm_kunit_write_u32(args, 64, object_tree_count);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	if (object_tree_ptr && object_tree_len)
		pkm_kunit_add_region(&mem, object_tree_ptr, object_tree,
				      object_tree_len);
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));
	pkm_kunit_add_region(&mem, 0x4000, results, sizeof(results));

	ret = pkm_kacs_kunit_access_check_syscall_list(&ops, 0x0100, 0x4000,
						       results_count);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 0), 0xaaaaaaaaU);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(results, 4), 0xaaaaaaaaU);
}
