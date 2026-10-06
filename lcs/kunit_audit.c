// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit for the LCS registry write records (PEI-617 gap 1 and 2): the
 * continuous-audit mask a key handle caches from SYSTEM_ALARM ACEs, the
 * five mutation records it gates, lcs.audit.key.descriptor.changed,
 * lcs.audit.key.created's shape, lcs.audit.transaction.committed at each
 * of its ends, and kacs.audit.privilege.used on a registry open.
 *
 * Payloads are checked as exact key sets: every map's entry count and
 * every key in it, so a field added or dropped fails here. The records
 * carry outcome.errno as a signed int, which the KACS KUnit reader does
 * not decode, so this file has its own small msgpack reader.
 */

#include "kunit_common.h"

#define PKM_LCS_KUNIT_AUDIT_EVENT_BYTES 4096U

#define PKM_LCS_KUNIT_VALUE_SET "lcs.audit.value.set"
#define PKM_LCS_KUNIT_VALUE_DELETED "lcs.audit.value.deleted"
#define PKM_LCS_KUNIT_KEY_TOMBSTONED "lcs.audit.key.tombstoned"
#define PKM_LCS_KUNIT_KEY_DELETED "lcs.audit.key.deleted"
#define PKM_LCS_KUNIT_KEY_HIDDEN "lcs.audit.key.hidden"
#define PKM_LCS_KUNIT_KEY_CREATED "lcs.audit.key.created"
#define PKM_LCS_KUNIT_DESCRIPTOR_CHANGED "lcs.audit.key.descriptor.changed"
#define PKM_LCS_KUNIT_TXN_COMMITTED "lcs.audit.transaction.committed"
#define PKM_LCS_KUNIT_PRIVILEGE_USED "kacs.audit.privilege.used"

enum pkm_lcs_kunit_mp_kind {
	PKM_LCS_KUNIT_MP_NIL = 0,
	PKM_LCS_KUNIT_MP_BOOL,
	PKM_LCS_KUNIT_MP_UINT,
	PKM_LCS_KUNIT_MP_INT,
	PKM_LCS_KUNIT_MP_STR,
	PKM_LCS_KUNIT_MP_BIN,
	PKM_LCS_KUNIT_MP_ARRAY,
	PKM_LCS_KUNIT_MP_MAP,
};

/* One msgpack value: a scalar, or a container's undecoded entries. */
struct pkm_lcs_kunit_mp {
	enum pkm_lcs_kunit_mp_kind kind;
	const u8 *data;
	size_t data_len;
	size_t total_len;
	u32 count;
	u64 uint_value;
	s64 int_value;
	bool bool_value;
};

static u64 pkm_lcs_kunit_mp_be(const u8 *bytes, size_t width)
{
	u64 value = 0;
	size_t i;

	for (i = 0; i < width; i++)
		value = (value << 8) | bytes[i];
	return value;
}

static bool pkm_lcs_kunit_mp_parse(const u8 *bytes, size_t len,
				   struct pkm_lcs_kunit_mp *out, u32 depth)
{
	struct pkm_lcs_kunit_mp child;
	size_t header = 1;
	size_t payload = 0;
	size_t width = 0;
	size_t offset;
	u64 entries;
	u64 count = 0;
	u64 raw;
	u8 tag;

	if (!bytes || !len || !out || depth > 32)
		return false;
	memset(out, 0, sizeof(*out));
	tag = bytes[0];

	if (tag <= 0x7f) {
		out->kind = PKM_LCS_KUNIT_MP_UINT;
		out->uint_value = tag;
		out->total_len = 1;
		return true;
	}
	if (tag >= 0xe0) {
		out->kind = PKM_LCS_KUNIT_MP_INT;
		out->int_value = (s8)tag;
		out->total_len = 1;
		return true;
	}
	if ((tag & 0xf0) == 0x80 || (tag & 0xf0) == 0x90) {
		out->kind = (tag & 0xf0) == 0x80 ? PKM_LCS_KUNIT_MP_MAP :
						   PKM_LCS_KUNIT_MP_ARRAY;
		count = tag & 0x0f;
		goto container;
	}
	if ((tag & 0xe0) == 0xa0) {
		out->kind = PKM_LCS_KUNIT_MP_STR;
		payload = tag & 0x1f;
		goto bytes_payload;
	}

	switch (tag) {
	case 0xc0:
		out->kind = PKM_LCS_KUNIT_MP_NIL;
		out->total_len = 1;
		return true;
	case 0xc2:
	case 0xc3:
		out->kind = PKM_LCS_KUNIT_MP_BOOL;
		out->bool_value = tag == 0xc3;
		out->total_len = 1;
		return true;
	case 0xc4:
	case 0xc5:
	case 0xc6:
	case 0xd9:
	case 0xda:
	case 0xdb:
		out->kind = tag <= 0xc6 ? PKM_LCS_KUNIT_MP_BIN :
					  PKM_LCS_KUNIT_MP_STR;
		width = 1U << ((tag <= 0xc6 ? tag - 0xc4 : tag - 0xd9));
		header = 1 + width;
		if (header > len)
			return false;
		payload = pkm_lcs_kunit_mp_be(bytes + 1, width);
		goto bytes_payload;
	case 0xcc:
	case 0xcd:
	case 0xce:
	case 0xcf:
		width = 1U << (tag - 0xcc);
		if (1 + width > len)
			return false;
		out->kind = PKM_LCS_KUNIT_MP_UINT;
		out->uint_value = pkm_lcs_kunit_mp_be(bytes + 1, width);
		out->total_len = 1 + width;
		return true;
	case 0xd0:
	case 0xd1:
	case 0xd2:
	case 0xd3:
		width = 1U << (tag - 0xd0);
		if (1 + width > len)
			return false;
		raw = pkm_lcs_kunit_mp_be(bytes + 1, width);
		out->kind = PKM_LCS_KUNIT_MP_INT;
		if (width == 1)
			out->int_value = (s8)raw;
		else if (width == 2)
			out->int_value = (s16)raw;
		else if (width == 4)
			out->int_value = (s32)raw;
		else
			out->int_value = (s64)raw;
		out->total_len = 1 + width;
		return true;
	case 0xdc:
	case 0xdd:
	case 0xde:
	case 0xdf:
		out->kind = tag <= 0xdd ? PKM_LCS_KUNIT_MP_ARRAY :
					  PKM_LCS_KUNIT_MP_MAP;
		width = (tag == 0xdc || tag == 0xde) ? 2 : 4;
		header = 1 + width;
		if (header > len)
			return false;
		count = pkm_lcs_kunit_mp_be(bytes + 1, width);
		goto container;
	default:
		return false;
	}

container:
	if (header > len || count > U32_MAX / 2)
		return false;
	entries = out->kind == PKM_LCS_KUNIT_MP_MAP ? count * 2 : count;
	offset = header;
	while (entries--) {
		if (!pkm_lcs_kunit_mp_parse(bytes + offset, len - offset, &child,
					    depth + 1))
			return false;
		offset += child.total_len;
	}
	out->count = (u32)count;
	out->data = bytes + header;
	out->data_len = offset - header;
	out->total_len = offset;
	return true;

bytes_payload:
	if (header > len || payload > len - header)
		return false;
	out->data = bytes + header;
	out->data_len = payload;
	out->total_len = header + payload;
	return true;
}

static bool pkm_lcs_kunit_mp_get(const struct pkm_lcs_kunit_mp *map,
				 const char *key, struct pkm_lcs_kunit_mp *out)
{
	struct pkm_lcs_kunit_mp key_view;
	size_t key_len = strlen(key);
	size_t offset = 0;
	u32 i;

	if (!map || map->kind != PKM_LCS_KUNIT_MP_MAP)
		return false;
	for (i = 0; i < map->count; i++) {
		if (!pkm_lcs_kunit_mp_parse(map->data + offset,
					    map->data_len - offset, &key_view, 0))
			return false;
		offset += key_view.total_len;
		if (!pkm_lcs_kunit_mp_parse(map->data + offset,
					    map->data_len - offset, out, 0))
			return false;
		offset += out->total_len;
		if (key_view.kind == PKM_LCS_KUNIT_MP_STR &&
		    key_view.data_len == key_len &&
		    !memcmp(key_view.data, key, key_len))
			return true;
	}
	return false;
}

/* `key` is present and is a map of exactly `count` entries. */
static bool pkm_lcs_kunit_mp_map(struct kunit *test,
				 const struct pkm_lcs_kunit_mp *map,
				 const char *key, u32 count,
				 struct pkm_lcs_kunit_mp *out)
{
	if (!pkm_lcs_kunit_mp_get(map, key, out)) {
		KUNIT_FAIL(test, "map key %s missing", key);
		return false;
	}
	if (out->kind != PKM_LCS_KUNIT_MP_MAP) {
		KUNIT_FAIL(test, "%s is not a map", key);
		return false;
	}
	KUNIT_EXPECT_EQ_MSG(test, out->count, count, "entries in %s", key);
	return out->count == count;
}

static void pkm_lcs_kunit_mp_expect_kind(struct kunit *test,
					 const struct pkm_lcs_kunit_mp *map,
					 const char *key,
					 enum pkm_lcs_kunit_mp_kind kind,
					 struct pkm_lcs_kunit_mp *out)
{
	struct pkm_lcs_kunit_mp local;

	if (!out)
		out = &local;
	if (!pkm_lcs_kunit_mp_get(map, key, out)) {
		KUNIT_FAIL(test, "key %s missing", key);
		return;
	}
	KUNIT_EXPECT_EQ_MSG(test, out->kind, kind, "kind of %s", key);
}

static void pkm_lcs_kunit_mp_expect_uint(struct kunit *test,
					 const struct pkm_lcs_kunit_mp *map,
					 const char *key, u64 expected)
{
	struct pkm_lcs_kunit_mp value;

	pkm_lcs_kunit_mp_expect_kind(test, map, key, PKM_LCS_KUNIT_MP_UINT,
				     &value);
	KUNIT_EXPECT_EQ_MSG(test, value.uint_value, expected, "%s", key);
}

static void pkm_lcs_kunit_mp_expect_int(struct kunit *test,
					const struct pkm_lcs_kunit_mp *map,
					const char *key, s64 expected)
{
	struct pkm_lcs_kunit_mp value;

	pkm_lcs_kunit_mp_expect_kind(test, map, key, PKM_LCS_KUNIT_MP_INT,
				     &value);
	KUNIT_EXPECT_EQ_MSG(test, value.int_value, expected, "%s", key);
}

static void pkm_lcs_kunit_mp_expect_bool(struct kunit *test,
					 const struct pkm_lcs_kunit_mp *map,
					 const char *key, bool expected)
{
	struct pkm_lcs_kunit_mp value;

	pkm_lcs_kunit_mp_expect_kind(test, map, key, PKM_LCS_KUNIT_MP_BOOL,
				     &value);
	KUNIT_EXPECT_EQ_MSG(test, value.bool_value, expected, "%s", key);
}

static void pkm_lcs_kunit_mp_expect_bytes(struct kunit *test,
					  const struct pkm_lcs_kunit_mp *map,
					  const char *key,
					  enum pkm_lcs_kunit_mp_kind kind,
					  const void *expected, size_t len)
{
	struct pkm_lcs_kunit_mp value;

	pkm_lcs_kunit_mp_expect_kind(test, map, key, kind, &value);
	KUNIT_ASSERT_EQ_MSG(test, value.data_len, len, "length of %s", key);
	KUNIT_EXPECT_EQ_MSG(test, memcmp(value.data, expected, len), 0, "%s",
			    key);
}

static void pkm_lcs_kunit_mp_expect_str(struct kunit *test,
					const struct pkm_lcs_kunit_mp *map,
					const char *key, const char *expected)
{
	pkm_lcs_kunit_mp_expect_bytes(test, map, key, PKM_LCS_KUNIT_MP_STR,
				      expected, strlen(expected));
}

static void pkm_lcs_kunit_mp_expect_bin(struct kunit *test,
					const struct pkm_lcs_kunit_mp *map,
					const char *key, const u8 *expected,
					size_t len)
{
	pkm_lcs_kunit_mp_expect_bytes(test, map, key, PKM_LCS_KUNIT_MP_BIN,
				      expected, len);
}

static void pkm_lcs_kunit_mp_expect_absent(struct kunit *test,
					   const struct pkm_lcs_kunit_mp *map,
					   const char *key)
{
	struct pkm_lcs_kunit_mp value;

	KUNIT_EXPECT_FALSE_MSG(test, pkm_lcs_kunit_mp_get(map, key, &value),
			       "%s present", key);
}

/*
 * The payload of the latest event of `type` from `origin`, as a map of
 * exactly `count` entries; false when there is no such event.
 */
static bool pkm_lcs_kunit_audit_latest(struct kunit *test, u8 origin,
				       const char *type, u8 *buffer,
				       struct pkm_lcs_kunit_mp *root, u32 count)
{
	size_t written = 0;
	u32 header_size;

	if (pkm_kmes_kunit_copy_latest_matching_event(
		    origin, type, strlen(type), buffer,
		    PKM_LCS_KUNIT_AUDIT_EVENT_BYTES, &written, NULL)) {
		KUNIT_FAIL(test, "no %s event", type);
		return false;
	}
	if (written < KMES_EVENT_HEADER_BASE_SIZE)
		return false;
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	if (header_size >= written)
		return false;
	if (!pkm_lcs_kunit_mp_parse(buffer + header_size, written - header_size,
				    root, 0) ||
	    root->kind != PKM_LCS_KUNIT_MP_MAP) {
		KUNIT_FAIL(test, "%s payload is not a msgpack map", type);
		return false;
	}
	KUNIT_EXPECT_EQ_MSG(test, root->count, count, "top-level keys of %s",
			    type);
	return root->count == count;
}

static bool pkm_lcs_kunit_audit_none(u8 origin, const char *type, u8 *buffer)
{
	size_t written = 0;

	return pkm_kmes_kunit_copy_latest_matching_event(
		       origin, type, strlen(type), buffer,
		       PKM_LCS_KUNIT_AUDIT_EVENT_BYTES, &written,
		       NULL) == -ENOENT;
}

/* subject: {token: {sid, integrity, id, auth-id, type, impersonation}} */
static void pkm_lcs_kunit_audit_expect_caller(
	struct kunit *test, const struct pkm_lcs_kunit_mp *root,
	const void *token)
{
	struct pkm_lcs_kunit_mp subject;
	struct pkm_lcs_kunit_mp caller;
	const u8 *sid = NULL;
	size_t sid_len = 0;

	KUNIT_ASSERT_EQ(test, kacs_rust_token_user_sid(token, &sid, &sid_len),
			0);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, root, "subject", 1U,
						     &subject));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &subject, "token",
						     6U, &caller));
	pkm_lcs_kunit_mp_expect_bin(test, &caller, "sid", sid, sid_len);
	pkm_lcs_kunit_mp_expect_kind(test, &caller, "integrity",
				     PKM_LCS_KUNIT_MP_UINT, NULL);
	pkm_lcs_kunit_mp_expect_kind(test, &caller, "id",
				     PKM_LCS_KUNIT_MP_UINT, NULL);
	pkm_lcs_kunit_mp_expect_kind(test, &caller, "auth-id",
				     PKM_LCS_KUNIT_MP_UINT, NULL);
	pkm_lcs_kunit_mp_expect_kind(test, &caller, "type",
				     PKM_LCS_KUNIT_MP_STR, NULL);
	pkm_lcs_kunit_mp_expect_kind(test, &caller, "impersonation",
				     PKM_LCS_KUNIT_MP_UINT, NULL);
}

/* access: {requested, granted, matched, audit-mask} */
static void pkm_lcs_kunit_audit_expect_handle_access(
	struct kunit *test, const struct pkm_lcs_kunit_mp *root, u32 requested,
	u32 granted, u32 audit_mask)
{
	struct pkm_lcs_kunit_mp access;

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, root, "access", 4U,
						     &access));
	pkm_lcs_kunit_mp_expect_uint(test, &access, "requested", requested);
	pkm_lcs_kunit_mp_expect_uint(test, &access, "granted", granted);
	pkm_lcs_kunit_mp_expect_uint(test, &access, "matched",
				     requested & audit_mask);
	pkm_lcs_kunit_mp_expect_uint(test, &access, "audit-mask", audit_mask);
}

/* outcome: {success} on success, {success, errno} on failure. */
static void pkm_lcs_kunit_audit_expect_outcome(
	struct kunit *test, const struct pkm_lcs_kunit_mp *root,
	int errno_value)
{
	struct pkm_lcs_kunit_mp outcome;

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, root, "outcome",
						     errno_value ? 2U : 1U,
						     &outcome));
	pkm_lcs_kunit_mp_expect_bool(test, &outcome, "success",
				     errno_value == 0);
	if (errno_value)
		pkm_lcs_kunit_mp_expect_int(test, &outcome, "errno",
					    errno_value);
}

/* request: {timed-out} */
static void pkm_lcs_kunit_audit_expect_timed_out(
	struct kunit *test, const struct pkm_lcs_kunit_mp *root, bool timed_out)
{
	struct pkm_lcs_kunit_mp request;

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, root, "request", 1U,
						     &request));
	pkm_lcs_kunit_mp_expect_bool(test, &request, "timed-out", timed_out);
}

/*
 * A complete self-relative key descriptor: owner and group SYSTEM, a SACL
 * with one SYSTEM_ALARM ACE for Everyone over KEY_SET_VALUE, and a DACL
 * granting Everyone KEY_ALL_ACCESS.
 */
static const u8 pkm_lcs_kunit_alarm_key_sd[] = {
	/* revision 1; SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT */
	0x01, 0x00, 0x14, 0x80,
	0x14, 0x00, 0x00, 0x00, /* owner at 20 */
	0x20, 0x00, 0x00, 0x00, /* group at 32 */
	0x2c, 0x00, 0x00, 0x00, /* SACL at 44 */
	0x48, 0x00, 0x00, 0x00, /* DACL at 72 */
	/* owner: S-1-5-18 */
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
	/* group: S-1-5-18 */
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
	/* SACL: revision 2, size 28, one ACE */
	0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
	/* SYSTEM_ALARM_ACE_TYPE, no flags, size 20, KEY_SET_VALUE, S-1-1-0 */
	0x03, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* DACL: revision 2, size 28, one ACE */
	0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
	/* ACCESS_ALLOWED_ACE_TYPE, no flags, size 20, KEY_ALL_ACCESS, S-1-1-0 */
	0x00, 0x00, 0x14, 0x00, 0x3f, 0x00, 0x0f, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
};

/* The owner SID inside pkm_lcs_kunit_alarm_key_sd. */
#define PKM_LCS_KUNIT_ALARM_SD_OWNER (pkm_lcs_kunit_alarm_key_sd + 20)
#define PKM_LCS_KUNIT_ALARM_SD_OWNER_LEN 12U

/*
 * The SYSTEM_ALARM ACE is evaluated at open: a matching ACE gives the plan,
 * and so the handle, a continuous-audit mask. Without a SACL the mask is
 * zero, and an alarm ACE never makes the open itself audited.
 */
static void pkm_lcs_kunit_audit_open_plan_carries_alarm_mask(
	struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	u8 plain[sizeof(pkm_lcs_kunit_alarm_key_sd)];
	const void *token;

	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, pkm_lcs_kunit_alarm_key_sd,
				sizeof(pkm_lcs_kunit_alarm_key_sd),
				KEY_QUERY_VALUE, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.continuous_audit_mask, (u32)KEY_SET_VALUE);
	KUNIT_EXPECT_EQ(test, plan.key_open_sacl_audit_required, 0U);

	/* The same descriptor with SE_SACL_PRESENT clear and no SACL. */
	memcpy(plain, pkm_lcs_kunit_alarm_key_sd, sizeof(plain));
	plain[2] = 0x04;
	memset(plain + 12, 0, 4);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, plain, sizeof(plain), KEY_QUERY_VALUE,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.allowed, 1U);
	KUNIT_EXPECT_EQ(test, plan.continuous_audit_mask, 0U);

	kacs_rust_token_drop(token);
}

/* The mask rides the publish input onto the handle and stays there. */
static void pkm_lcs_kunit_audit_publish_caches_audit_mask(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x11 },
		{ 0x5a },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 7,
		.granted_access = KEY_READ,
		.audit_mask = KEY_SET_VALUE | DELETE,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	long fd;

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));
	fd = pkm_lcs_key_fd_publish(&input);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot), 0L);
	KUNIT_EXPECT_EQ(test, snapshot.audit_mask,
			(u32)(KEY_SET_VALUE | DELETE));
	KUNIT_EXPECT_EQ(test, snapshot.granted_access, (u32)KEY_READ);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
}

static long pkm_lcs_kunit_audit_publish(u32 granted, u32 audit_mask,
					const char * const *path,
					const u8 (*ancestors)[PKM_LCS_GUID_BYTES],
					u32 depth)
{
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 1,
		.granted_access = granted,
		.audit_mask = audit_mask,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = depth,
	};

	memcpy(input.key_guid, ancestors[depth - 1U], sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}

/*
 * A non-transacted SET_VALUE through a handle whose mask covers
 * KEY_SET_VALUE writes lcs.audit.value.set: subject, object, access,
 * mutation, outcome. The data is recorded only as its type, length and
 * SHA-256 digest. The same write through a handle whose mask covers only
 * DELETE writes nothing.
 */
static void pkm_lcs_kunit_audit_value_set_follows_the_handle_mask(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7a },
	};
	static const char value_name[] = "Answer";
	static const u8 data[] = { 0x2a, 0x00, 0x00, 0x00 };
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_value_args args = {
		.name_len = sizeof(value_name) - 1,
		.name_ptr = (u64)(unsigned long)value_name,
		.type = REG_BINARY,
		.data_len = sizeof(data),
		.data_ptr = (u64)(unsigned long)data,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.expected_guid = ancestors[1],
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.expected_data = data,
		.expected_data_len = sizeof(data),
		.expected_value_type = REG_BINARY,
		.set_value_status = RSI_OK,
	};
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp object;
	struct pkm_lcs_kunit_mp key;
	struct pkm_lcs_kunit_mp layer;
	struct pkm_lcs_kunit_mp value;
	struct pkm_lcs_kunit_mp mutation;
	u8 digest[SHA256_DIGEST_SIZE];
	struct file file = { };
	const void *source_token;
	const void *admin_token;
	struct task_struct *task;
	u64 sequence = 0;
	u8 *buffer;
	long audited_fd;
	long quiet_fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	admin_token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, admin_token);
	script.file = &file;

	audited_fd = pkm_lcs_kunit_audit_publish(KEY_SET_VALUE, KEY_SET_VALUE,
						 path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, audited_fd >= 0);
	quiet_fd = pkm_lcs_kunit_audit_publish(KEY_SET_VALUE, DELETE, path,
					       ancestors, 2);
	KUNIT_ASSERT_TRUE(test, quiet_fd >= 0);

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_next_sequence_snapshot(&sequence),
			0L);
	script.expected_sequence = sequence;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-audit-set-value");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_set_value_for_token((int)audited_fd,
						       admin_token, &ops, &args);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_kthread_stop(task), 0);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_EQ(test, script.result, 0);

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_VALUE_SET, buffer, &root,
					5U));
	pkm_lcs_kunit_audit_expect_caller(test, &root, admin_token);

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "object", 2U,
						     &object));
	pkm_lcs_kunit_mp_expect_str(test, &object, "kind", "key");
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "key", 4U,
						     &key));
	pkm_lcs_kunit_mp_expect_bin(test, &key, "guid", ancestors[1],
				    PKM_LCS_GUID_BYTES);
	pkm_lcs_kunit_mp_expect_str(test, &key, "path", "Machine\\Software");
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &key, "layer", 1U,
						     &layer));
	pkm_lcs_kunit_mp_expect_str(test, &layer, "name", "base");
	/* The scripted source has no value before the write: no -previous. */
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &key, "value", 4U,
						     &value));
	pkm_lcs_kunit_mp_expect_str(test, &value, "name", value_name);
	pkm_lcs_kunit_mp_expect_uint(test, &value, "type", REG_BINARY);
	pkm_lcs_kunit_mp_expect_uint(test, &value, "length", sizeof(data));
	sha256(data, sizeof(data), digest);
	pkm_lcs_kunit_mp_expect_bin(test, &value, "digest", digest,
				    sizeof(digest));

	pkm_lcs_kunit_audit_expect_handle_access(test, &root, KEY_SET_VALUE,
						 KEY_SET_VALUE, KEY_SET_VALUE);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "mutation",
						     1U, &mutation));
	pkm_lcs_kunit_mp_expect_uint(test, &mutation, "sequence", sequence);
	pkm_lcs_kunit_mp_expect_absent(test, &root, "transaction");
	pkm_lcs_kunit_mp_expect_absent(test, &root, "request");
	pkm_lcs_kunit_audit_expect_outcome(test, &root, 0);

	/* Gating off: the same write through a DELETE-only mask. */
	memset(&ctx, 0, sizeof(ctx));
	script.reads = 0;
	script.writes = 0;
	script.result = 0;
	script.observed_last_write_time = 0;
	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_next_sequence_snapshot(&sequence),
			0L);
	script.expected_sequence = sequence;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-audit-set-value-quiet");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	ret = pkm_lcs_kunit_key_fd_set_value_for_token((int)quiet_fd,
						       admin_token, &ops, &args);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_kthread_stop(task), 0);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_LCS, PKM_LCS_KUNIT_VALUE_SET,
					buffer));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)audited_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)quiet_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(admin_token);
	kacs_rust_token_drop(source_token);
}

static long pkm_lcs_kunit_audit_refused_write(u32 which, int fd,
					      const void *token,
					      const struct pkm_lcs_usercopy_ops *ops)
{
	struct reg_set_value_args set_value = { .txn_fd = -1 };
	struct reg_delete_value_args delete_value = { .txn_fd = -1 };
	struct reg_blanket_tombstone_args tombstone = { .txn_fd = -1 };
	struct reg_delete_key_args delete_key = { .txn_fd = -1 };
	struct reg_hide_key_args hide_key = { .txn_fd = -1 };

	switch (which) {
	case 0:
		return pkm_lcs_kunit_key_fd_set_value_for_token(fd, token, ops,
								&set_value);
	case 1:
		return pkm_lcs_kunit_key_fd_delete_value_for_token(
			fd, token, ops, &delete_value);
	case 2:
		return pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
			fd, token, ops, &tombstone);
	case 3:
		return pkm_lcs_kunit_key_fd_delete_key_for_token(fd, token, ops,
								 &delete_key);
	default:
		return pkm_lcs_kunit_key_fd_hide_key_for_token(fd, token, ops,
							       &hide_key);
	}
}

/*
 * A handle opened without the right a write needs is refused at its own
 * gate, before any source contact. When the right overlaps the handle's
 * audit mask the refusal is still recorded: subject, object, access,
 * request, outcome, with request.timed-out false, outcome.errno -EACCES,
 * and nothing the request had not yet read. With no mask, nothing is.
 */
static void pkm_lcs_kunit_audit_refused_writes_follow_the_handle_mask(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software", "Gated" };
	static const u8 ancestors[3][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x21 },
		{ 0x7b },
	};
	static const char * const event_types[] = {
		PKM_LCS_KUNIT_VALUE_SET,
		PKM_LCS_KUNIT_VALUE_DELETED,
		PKM_LCS_KUNIT_KEY_TOMBSTONED,
		PKM_LCS_KUNIT_KEY_DELETED,
		PKM_LCS_KUNIT_KEY_HIDDEN,
	};
	static const u32 rights[] = {
		KEY_SET_VALUE, KEY_SET_VALUE, KEY_SET_VALUE, DELETE, DELETE,
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp object;
	struct pkm_lcs_kunit_mp key;
	const void *token;
	u8 *buffer;
	long fd;
	u32 i;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	for (i = 0; i < ARRAY_SIZE(event_types); i++) {
		/* Gating off: no mask, no record. */
		fd = pkm_lcs_kunit_audit_publish(KEY_QUERY_VALUE, 0, path,
						 ancestors, 3);
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		pkm_kmes_kunit_reset_all();
		KUNIT_EXPECT_EQ_MSG(test,
				    pkm_lcs_kunit_audit_refused_write(
					    i, (int)fd, token, &ops),
				    (long)-EACCES, "%s", event_types[i]);
		KUNIT_EXPECT_TRUE_MSG(test,
				      pkm_lcs_kunit_audit_none(KMES_ORIGIN_LCS,
							       event_types[i],
							       buffer),
				      "%s with no mask", event_types[i]);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

		/* Gating on: the right overlaps the mask. */
		fd = pkm_lcs_kunit_audit_publish(KEY_QUERY_VALUE, rights[i],
						 path, ancestors, 3);
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		pkm_kmes_kunit_reset_all();
		KUNIT_EXPECT_EQ_MSG(test,
				    pkm_lcs_kunit_audit_refused_write(
					    i, (int)fd, token, &ops),
				    (long)-EACCES, "%s", event_types[i]);
		KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
						test, KMES_ORIGIN_LCS,
						event_types[i], buffer, &root,
						5U));
		pkm_lcs_kunit_audit_expect_caller(test, &root, token);
		KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root,
							     "object", 2U,
							     &object));
		pkm_lcs_kunit_mp_expect_str(test, &object, "kind", "key");
		/* Refused before the layer or a name was read. */
		KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object,
							     "key", 2U, &key));
		pkm_lcs_kunit_mp_expect_bin(test, &key, "guid", ancestors[2],
					    PKM_LCS_GUID_BYTES);
		pkm_lcs_kunit_mp_expect_str(test, &key, "path",
					    "Machine\\Software\\Gated");
		pkm_lcs_kunit_audit_expect_handle_access(
			test, &root, rights[i], KEY_QUERY_VALUE, rights[i]);
		pkm_lcs_kunit_audit_expect_timed_out(test, &root, false);
		pkm_lcs_kunit_audit_expect_outcome(test, &root, -EACCES);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	kacs_rust_token_drop(token);
}

/*
 * SET_SECURITY: a DACL change whose WRITE_DAC overlaps the mask is recorded
 * even when the handle's gate refuses it, with object.sd.components alone
 * since no descriptor was read. A SACL change from a handle without
 * ACCESS_SYSTEM_SECURITY is refused before it is armed, so asking for one
 * writes nothing; nor does a DACL change the mask does not cover.
 */
static void pkm_lcs_kunit_audit_descriptor_change_gating(struct kunit *test)
{
	static const char * const path[] = { "Machine", "Secured" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x7c },
	};
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_set_security_args dacl = {
		.security_info = DACL_SECURITY_INFORMATION,
		.txn_fd = -1,
	};
	struct reg_set_security_args sacl = {
		.security_info = SACL_SECURITY_INFORMATION,
		.txn_fd = -1,
	};
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp object;
	struct pkm_lcs_kunit_mp key;
	struct pkm_lcs_kunit_mp sd;
	const void *token;
	u8 *buffer;
	long fd;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd = pkm_lcs_kunit_audit_publish(KEY_QUERY_VALUE, WRITE_DAC, path,
					 ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security_for_token(
				(int)fd, token, &ops, &dacl),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_DESCRIPTOR_CHANGED, buffer,
					&root, 5U));
	pkm_lcs_kunit_audit_expect_caller(test, &root, token);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "object", 3U,
						     &object));
	pkm_lcs_kunit_mp_expect_str(test, &object, "kind", "key");
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "key", 2U,
						     &key));
	pkm_lcs_kunit_mp_expect_str(test, &key, "path", "Machine\\Secured");
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "sd", 1U,
						     &sd));
	pkm_lcs_kunit_mp_expect_uint(test, &sd, "components",
				     DACL_SECURITY_INFORMATION);
	pkm_lcs_kunit_audit_expect_handle_access(test, &root, WRITE_DAC,
						 KEY_QUERY_VALUE, WRITE_DAC);
	pkm_lcs_kunit_audit_expect_timed_out(test, &root, false);
	pkm_lcs_kunit_audit_expect_outcome(test, &root, -EACCES);

	/* A SACL change the handle cannot make is not armed at all. */
	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security_for_token(
				(int)fd, token, &ops, &sacl),
			(long)-EACCES);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_DESCRIPTOR_CHANGED, buffer));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	/* A DACL change the mask does not cover. */
	fd = pkm_lcs_kunit_audit_publish(KEY_QUERY_VALUE, KEY_SET_VALUE, path,
					 ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_set_security_for_token(
				(int)fd, token, &ops, &dacl),
			(long)-EACCES);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_DESCRIPTOR_CHANGED, buffer));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	kacs_rust_token_drop(token);
}

static void pkm_lcs_kunit_audit_record_init(
	struct pkm_lcs_key_audit_record *record, u32 event, const char *path)
{
	memset(record, 0, sizeof(*record));
	record->event = event;
	memset(record->key_guid, 0x6d, sizeof(record->key_guid));
	record->key_path = path;
	record->key_path_len = strlen(path);
}

/*
 * The emitter's shape for what the scripted sources here do not reach: a
 * write whose source wait timed out (request.timed-out true, outcome.errno
 * -ETIMEDOUT: read as "may have been applied later"), the value a write
 * replaced, and a staged SACL change with both descriptors, recorded with
 * nothing matched.
 */
static void pkm_lcs_kunit_audit_emitter_timeout_and_previous_shapes(
	struct kunit *test)
{
	static const u8 old_data[] = { 'o', 'l', 'd' };
	static const u8 new_data[] = { 'n', 'e', 'w', '!' };
	struct pkm_lcs_key_audit_record record;
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp object;
	struct pkm_lcs_kunit_mp key;
	struct pkm_lcs_kunit_mp value;
	struct pkm_lcs_kunit_mp sd;
	struct pkm_lcs_kunit_mp transaction;
	u8 digest[SHA256_DIGEST_SIZE];
	const void *token;
	u8 *buffer;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_lcs_kunit_audit_record_init(&record, PKM_LCS_KEY_AUDIT_VALUE_SET,
					"Machine\\Late");
	record.key_layer_name = "base";
	record.key_layer_name_len = 4;
	record.value_name = "V";
	record.value_name_len = 1;
	record.value_name_present = 1;
	record.value_type = REG_BINARY;
	record.value_length = sizeof(new_data);
	pkm_lcs_audit_digest(new_data, sizeof(new_data), record.value_digest);
	record.value_present = 1;
	record.previous_type = REG_SZ;
	record.previous_length = sizeof(old_data);
	pkm_lcs_audit_digest(old_data, sizeof(old_data),
			     record.previous_digest);
	record.previous_present = 1;
	record.requested_access = KEY_SET_VALUE;
	record.granted_access = KEY_SET_VALUE;
	record.audit_mask = KEY_SET_VALUE;
	record.audit_mask_present = 1;
	record.result_errno = ETIMEDOUT;
	record.timed_out = 1;

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_lcs_emit_key_audit_for_token(token, &record),
			0L);
	/* subject, object, access, request, outcome */
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_VALUE_SET, buffer, &root,
					5U));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "object", 2U,
						     &object));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "key", 4U,
						     &key));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &key, "value", 7U,
						     &value));
	pkm_lcs_kunit_mp_expect_uint(test, &value, "type-previous", REG_SZ);
	pkm_lcs_kunit_mp_expect_uint(test, &value, "length-previous",
				     sizeof(old_data));
	sha256(old_data, sizeof(old_data), digest);
	pkm_lcs_kunit_mp_expect_bin(test, &value, "digest-previous", digest,
				    sizeof(digest));
	sha256(new_data, sizeof(new_data), digest);
	pkm_lcs_kunit_mp_expect_bin(test, &value, "digest", digest,
				    sizeof(digest));
	pkm_lcs_kunit_audit_expect_timed_out(test, &root, true);
	pkm_lcs_kunit_audit_expect_outcome(test, &root, -ETIMEDOUT);

	/* A SACL change, staged in a transaction, with both descriptors. */
	pkm_lcs_kunit_audit_record_init(&record,
					PKM_LCS_KEY_AUDIT_DESCRIPTOR_CHANGED,
					"Machine\\Secured");
	record.requested_access = ACCESS_SYSTEM_SECURITY;
	record.granted_access = ACCESS_SYSTEM_SECURITY | KEY_READ;
	record.audit_mask = 0;
	record.audit_mask_present = 1;
	record.sd_components = SACL_SECURITY_INFORMATION;
	record.sd = pkm_lcs_kunit_alarm_key_sd;
	record.sd_len = sizeof(pkm_lcs_kunit_alarm_key_sd);
	pkm_lcs_audit_digest(record.sd, record.sd_len, record.sd_digest);
	record.sd_present = 1;
	record.previous_sd = pkm_lcs_kunit_alarm_key_sd;
	record.previous_sd_len = sizeof(pkm_lcs_kunit_alarm_key_sd);
	pkm_lcs_audit_digest(record.previous_sd, record.previous_sd_len,
			     record.previous_sd_digest);
	record.previous_sd_present = 1;
	record.transaction_id = 77;
	record.transaction_present = 1;

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_lcs_emit_key_audit_for_token(token, &record),
			0L);
	/* subject, object, access, transaction, outcome */
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_DESCRIPTOR_CHANGED, buffer,
					&root, 5U));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "object", 3U,
						     &object));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "sd", 7U,
						     &sd));
	pkm_lcs_kunit_mp_expect_uint(test, &sd, "components",
				     SACL_SECURITY_INFORMATION);
	pkm_lcs_kunit_mp_expect_uint(test, &sd, "length",
				     sizeof(pkm_lcs_kunit_alarm_key_sd));
	pkm_lcs_kunit_mp_expect_uint(test, &sd, "length-previous",
				     sizeof(pkm_lcs_kunit_alarm_key_sd));
	sha256(pkm_lcs_kunit_alarm_key_sd, sizeof(pkm_lcs_kunit_alarm_key_sd),
	       digest);
	pkm_lcs_kunit_mp_expect_bin(test, &sd, "digest", digest,
				    sizeof(digest));
	pkm_lcs_kunit_mp_expect_bin(test, &sd, "digest-previous", digest,
				    sizeof(digest));
	/* Each owner as the descriptor names it: S-1-5-18. */
	pkm_lcs_kunit_mp_expect_bin(test, &sd, "owner",
				    PKM_LCS_KUNIT_ALARM_SD_OWNER,
				    PKM_LCS_KUNIT_ALARM_SD_OWNER_LEN);
	pkm_lcs_kunit_mp_expect_bin(test, &sd, "owner-previous",
				    PKM_LCS_KUNIT_ALARM_SD_OWNER,
				    PKM_LCS_KUNIT_ALARM_SD_OWNER_LEN);
	pkm_lcs_kunit_audit_expect_handle_access(
		test, &root, ACCESS_SYSTEM_SECURITY,
		ACCESS_SYSTEM_SECURITY | KEY_READ, 0);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "transaction",
						     1U, &transaction));
	pkm_lcs_kunit_mp_expect_uint(test, &transaction, "id", 77);
	pkm_lcs_kunit_audit_expect_outcome(test, &root, 0);

	kacs_rust_token_drop(token);
}

/*
 * lcs.audit.key.created: subject, object, access, outcome. The new key's
 * descriptor is recorded by length and owner, and access is the parent
 * check's KEY_CREATE_SUB_KEY with no handle mask. A create that did not
 * succeed is never recorded, and the emitter refuses one.
 */
static void pkm_lcs_kunit_audit_key_created_shape(struct kunit *test)
{
	struct pkm_lcs_key_audit_record record;
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp object;
	struct pkm_lcs_kunit_mp key;
	struct pkm_lcs_kunit_mp sd;
	struct pkm_lcs_kunit_mp access;
	const void *token;
	u8 *buffer;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_lcs_kunit_audit_record_init(&record, PKM_LCS_KEY_AUDIT_KEY_CREATED,
					"Machine\\Software\\New");
	record.key_layer_name = "base";
	record.key_layer_name_len = 4;
	record.requested_access = KEY_CREATE_SUB_KEY;
	record.granted_access = KEY_CREATE_SUB_KEY;
	record.created_volatile = 1;
	record.created_volatile_requested = 1;
	record.sd = pkm_lcs_kunit_alarm_key_sd;
	record.sd_len = sizeof(pkm_lcs_kunit_alarm_key_sd);
	record.sd_present = 1;

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test, pkm_lcs_emit_key_audit_for_token(token, &record),
			0L);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_KEY_CREATED, buffer, &root,
					4U));
	pkm_lcs_kunit_audit_expect_caller(test, &root, token);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "object", 3U,
						     &object));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "key", 7U,
						     &key));
	pkm_lcs_kunit_mp_expect_str(test, &key, "path",
				    "Machine\\Software\\New");
	pkm_lcs_kunit_mp_expect_bool(test, &key, "created", true);
	pkm_lcs_kunit_mp_expect_bool(test, &key, "volatile", true);
	pkm_lcs_kunit_mp_expect_bool(test, &key, "volatile-requested", true);
	pkm_lcs_kunit_mp_expect_bool(test, &key, "symlink", false);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &object, "sd", 2U,
						     &sd));
	pkm_lcs_kunit_mp_expect_uint(test, &sd, "length",
				     sizeof(pkm_lcs_kunit_alarm_key_sd));
	pkm_lcs_kunit_mp_expect_bin(test, &sd, "owner",
				    PKM_LCS_KUNIT_ALARM_SD_OWNER,
				    PKM_LCS_KUNIT_ALARM_SD_OWNER_LEN);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "access", 2U,
						     &access));
	pkm_lcs_kunit_mp_expect_uint(test, &access, "requested",
				     KEY_CREATE_SUB_KEY);
	pkm_lcs_kunit_mp_expect_uint(test, &access, "granted",
				     KEY_CREATE_SUB_KEY);
	pkm_lcs_kunit_audit_expect_outcome(test, &root, 0);

	record.result_errno = EIO;
	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test, pkm_lcs_emit_key_audit_for_token(token, &record),
			(long)-EIO);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_KEY_CREATED, buffer));

	kacs_rust_token_drop(token);
}

/*
 * lcs.audit.transaction.committed: subject, transaction, outcome. On
 * success transaction is {id, state} and outcome {success}; a failure adds
 * commit-outstanding, an errno when a commit call failed, and the reason.
 */
static void pkm_lcs_kunit_audit_transaction_committed_shapes(
	struct kunit *test)
{
	struct pkm_lcs_audit_caller_snapshot caller = { };
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp transaction;
	struct pkm_lcs_kunit_mp outcome;
	const void *token;
	u8 *buffer;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_audit_caller_snapshot_take(token, &caller),
			0L);

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_emit_transaction_committed_audit(
				&caller, 4096, REG_TXN_COMMITTED, 0,
				PKM_LCS_TXN_AUDIT_REASON_NONE, -1),
			0L);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_TXN_COMMITTED, buffer,
					&root, 3U));
	pkm_lcs_kunit_audit_expect_caller(test, &root, token);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "transaction",
						     2U, &transaction));
	pkm_lcs_kunit_mp_expect_uint(test, &transaction, "id", 4096);
	pkm_lcs_kunit_mp_expect_str(test, &transaction, "state", "committed");
	pkm_lcs_kunit_audit_expect_outcome(test, &root, 0);

	/* A commit that timed out with the commit unanswered. */
	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_emit_transaction_committed_audit(
				&caller, 4097, REG_TXN_TIMED_OUT, ETIMEDOUT,
				PKM_LCS_TXN_AUDIT_REASON_TIMED_OUT, 1),
			0L);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_TXN_COMMITTED, buffer,
					&root, 3U));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "transaction",
						     3U, &transaction));
	pkm_lcs_kunit_mp_expect_str(test, &transaction, "state", "timed-out");
	pkm_lcs_kunit_mp_expect_bool(test, &transaction, "commit-outstanding",
				     true);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "outcome", 3U,
						     &outcome));
	pkm_lcs_kunit_mp_expect_bool(test, &outcome, "success", false);
	pkm_lcs_kunit_mp_expect_int(test, &outcome, "errno", -ETIMEDOUT);
	pkm_lcs_kunit_mp_expect_str(test, &outcome, "reason", "timed-out");

	/* A failure with no reason is refused. */
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_emit_transaction_committed_audit(
				&caller, 4098, REG_TXN_ABORTED, 0,
				PKM_LCS_TXN_AUDIT_REASON_NONE, 0),
			(long)-EIO);

	pkm_lcs_audit_caller_snapshot_destroy(&caller);
	kacs_rust_token_drop(token);
}

/*
 * A transaction that staged a recorded write and is closed without a
 * commit writes one record, aborted, naming the stager; one that staged
 * nothing recorded writes none.
 */
static void pkm_lcs_kunit_audit_transaction_close_records_abort(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp transaction;
	struct pkm_lcs_kunit_mp outcome;
	const void *token;
	u8 *buffer;
	long fd;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	/* Nothing recorded, nothing owed. */
	fd = pkm_lcs_transaction_fd_publish(60000);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_TXN_COMMITTED, buffer));

	fd = pkm_lcs_transaction_fd_publish(60000);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_transaction_fd_snapshot((int)fd,
							      &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_mark_audited((int)fd,
								  token),
			0L);
	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_TXN_COMMITTED, buffer,
					&root, 3U));
	pkm_lcs_kunit_audit_expect_caller(test, &root, token);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "transaction",
						     3U, &transaction));
	pkm_lcs_kunit_mp_expect_uint(test, &transaction, "id",
				     snapshot.transaction_id);
	pkm_lcs_kunit_mp_expect_str(test, &transaction, "state", "aborted");
	pkm_lcs_kunit_mp_expect_bool(test, &transaction, "commit-outstanding",
				     false);
	/* No commit call failed: success and reason, no errno. */
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "outcome", 2U,
						     &outcome));
	pkm_lcs_kunit_mp_expect_bool(test, &outcome, "success", false);
	pkm_lcs_kunit_mp_expect_str(test, &outcome, "reason", "aborted");
	pkm_lcs_kunit_mp_expect_absent(test, &outcome, "errno");

	kacs_rust_token_drop(token);
}

/*
 * The transaction timer fires in softirq; its work item writes the record,
 * state and reason timed-out, naming the stager. Closing the fd afterwards
 * writes nothing more: there is exactly one record.
 */
static void pkm_lcs_kunit_audit_transaction_timeout_records_from_work(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x7d
	};
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp transaction;
	struct pkm_lcs_kunit_mp outcome;
	struct file file = { };
	const void *source_token;
	const void *token;
	bool pending = true;
	u32 count = 0;
	u8 *buffer;
	long fd;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_local_administrator_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);

	pkm_kmes_kunit_reset_all();
	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	/* Marked first: the deadline is a millisecond away. */
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_mark_audited((int)fd,
								  token),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_transaction_fd_snapshot((int)fd,
							      &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_source_bound_transaction_acquire(1,
								       &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1, root_guid),
			0L);

	msleep(20);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_flush_timeout_work((int)fd),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_transaction_fd_audit_pending(
					(int)fd, &pending),
			0L);
	KUNIT_EXPECT_FALSE(test, pending);

	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_TXN_COMMITTED, buffer,
					&root, 3U));
	pkm_lcs_kunit_audit_expect_caller(test, &root, token);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "transaction",
						     3U, &transaction));
	pkm_lcs_kunit_mp_expect_uint(test, &transaction, "id",
				     snapshot.transaction_id);
	pkm_lcs_kunit_mp_expect_str(test, &transaction, "state", "timed-out");
	pkm_lcs_kunit_mp_expect_bool(test, &transaction, "commit-outstanding",
				     false);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "outcome", 2U,
						     &outcome));
	pkm_lcs_kunit_mp_expect_bool(test, &outcome, "success", false);
	pkm_lcs_kunit_mp_expect_str(test, &outcome, "reason", "timed-out");

	pkm_kmes_kunit_reset_all();
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_LCS,
					PKM_LCS_KUNIT_TXN_COMMITTED, buffer));

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(source_token);
	kacs_rust_token_drop(token);
}

/*
 * A registry open a privilege contributed to writes
 * kacs.audit.privilege.used with object.kind key, in KACS's access-check
 * shape: subject, emitter, object, operation (name access-check, from the
 * reshape that gives the type its discriminator), privilege, access,
 * outcome. The plain check the layer-write and create-parent paths use
 * writes none.
 */
static void pkm_lcs_kunit_audit_open_records_privilege_use(struct kunit *test)
{
	struct pkm_lcs_key_open_access_plan plan = { };
	struct pkm_lcs_kunit_mp root;
	struct pkm_lcs_kunit_mp object;
	struct pkm_lcs_kunit_mp operation;
	struct pkm_lcs_kunit_mp privilege;
	const u32 desired = KEY_QUERY_VALUE | ACCESS_SYSTEM_SECURITY;
	const void *token;
	u8 *buffer;

	buffer = kunit_kzalloc(test, PKM_LCS_KUNIT_AUDIT_EVENT_BYTES,
			       GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_open_access_check_for_token(
				token, pkm_lcs_kunit_alarm_key_sd,
				sizeof(pkm_lcs_kunit_alarm_key_sd), desired,
				&plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.privilege_use_audit_required, 1U);
	KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_audit_none(
					KMES_ORIGIN_KACS,
					PKM_LCS_KUNIT_PRIVILEGE_USED, buffer));

	pkm_kmes_kunit_reset_all();
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_open_access_check_recording_privilege_use(
				token, pkm_lcs_kunit_alarm_key_sd,
				sizeof(pkm_lcs_kunit_alarm_key_sd), desired,
				&plan),
			0L);
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_audit_latest(
					test, KMES_ORIGIN_KACS,
					PKM_LCS_KUNIT_PRIVILEGE_USED, buffer,
					&root, 7U));
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "object", 1U,
						     &object));
	pkm_lcs_kunit_mp_expect_str(test, &object, "kind", "key");
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "operation",
						     1U, &operation));
	pkm_lcs_kunit_mp_expect_str(test, &operation, "name", "access-check");
	KUNIT_ASSERT_TRUE(test, pkm_lcs_kunit_mp_map(test, &root, "privilege",
						     3U, &privilege));
	pkm_lcs_kunit_mp_expect_str(test, &privilege, "name",
				    "SeSecurityPrivilege");
	pkm_lcs_kunit_mp_expect_uint(test, &privilege, "contributed",
				     ACCESS_SYSTEM_SECURITY);
	pkm_lcs_kunit_mp_expect_uint(test, &privilege, "surviving",
				     ACCESS_SYSTEM_SECURITY);

	pkm_kmes_kunit_reset_all();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_audit_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_audit_open_plan_carries_alarm_mask),
	KUNIT_CASE(pkm_lcs_kunit_audit_publish_caches_audit_mask),
	KUNIT_CASE(pkm_lcs_kunit_audit_value_set_follows_the_handle_mask),
	KUNIT_CASE(pkm_lcs_kunit_audit_refused_writes_follow_the_handle_mask),
	KUNIT_CASE(pkm_lcs_kunit_audit_descriptor_change_gating),
	KUNIT_CASE(pkm_lcs_kunit_audit_emitter_timeout_and_previous_shapes),
	KUNIT_CASE(pkm_lcs_kunit_audit_key_created_shape),
	KUNIT_CASE(pkm_lcs_kunit_audit_transaction_committed_shapes),
	KUNIT_CASE(pkm_lcs_kunit_audit_transaction_close_records_abort),
	KUNIT_CASE(pkm_lcs_kunit_audit_transaction_timeout_records_from_work),
	KUNIT_CASE(pkm_lcs_kunit_audit_open_records_privilege_use),
	{}
};

static struct kunit_suite pkm_lcs_kunit_audit_suite = {
	.name = "pkm_lcs_kunit_audit",
	.test_cases = pkm_lcs_kunit_audit_cases,
};

kunit_test_suite(pkm_lcs_kunit_audit_suite);
