// SPDX-License-Identifier: GPL-2.0-only
/*
 * Registry ingestion: Machine\System\Network -> published policy and
 * network context.
 *
 * The kernel reads its own policy (ratified: pnpd is an observer and an
 * authoring surface, never in the enforcement path). The walk follows the
 * house idioms — discovery via pkm_lcs_walk_absolute_components (the
 * port-reservations pattern), per-key RSI_ENUM_CHILDREN + RSI_QUERY_VALUES
 * round trips (the layer-metadata pattern), layering resolved by the LCS
 * materializers — and feeds the pnp-core builder over the bridge FFI.
 * Validation is pnp-core's; a forest that does not build leaves the
 * previous generation active (atomic transitions), loudly.
 *
 * Two things are read under the Network key. `Rules\` is the policy: the
 * three kernel layers' forests and CurrentReportingLevel. `Interfaces\`
 * and `Networks\` are netd's inventory, from which the network context
 * (context.c) is built: which network each interface is standing on and
 * the operator's word on it, the `Network.*` facts of the packet layers.
 * The inventory is read beside the rules because the two change
 * together from a rule's point of view — a network being recognised is
 * as much a policy change to a flow as a rule being written.
 *
 * Change notification arrives per-key and uncoalesced from the LCS
 * internal watch dispatcher (one watch on the Network key, depth
 * unbounded), so the entry point coalesces into one deferred re-walk
 * (pending flag + delayed work with a short debounce window — a policy
 * save touches many keys, and boot autoapply once ran the generation to
 * 31 re-walking after every one). A re-walk publishes only what changed:
 * the rules by a digest of everything the walk fed the builder, the
 * context by comparing tables. netd rewriting an interface's Status
 * therefore costs a walk, not a generation.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/peios_ntfe.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

#include "../../security/pkm/lcs/rsi.h"
#include "../../security/pkm/lcs/source_device.h"
#include "ntfe.h"

/* Registry value type codes (uapi/pkm/lcs.h). */
#define NTFE_REG_SZ			1U
#define NTFE_REG_EXPAND_SZ		2U
#define NTFE_REG_DWORD			4U
#define NTFE_REG_DWORD_BIG_ENDIAN	5U
#define NTFE_REG_MULTI_SZ		7U
#define NTFE_REG_QWORD			11U

struct peios_ntfe_walk {
	u32 source_id;
	u64 next_sequence;
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_layer_snapshot layers;
	void *builder;
	u32 rules_seen;
	/* FNV-1a over everything the rules walk fed the builder. */
	u64 digest;
	/*
	 * The rules walk only (NULL elsewhere): why it was refused, for
	 * ntfe.policy.rejected, and the path of the rule it is in, relative
	 * to the layer key. path_len is the path's whole length, which may
	 * run past what path holds.
	 */
	struct peios_ntfe_build_why *why;
	char *path;
	u32 path_len;
	u8 layer;
};

/* The digest of the last rules walk that published; 0 = never. */
static u64 ntfe_published_digest;
/* One refresh at a time: bootstrap and the deferred re-walk may overlap. */
static DEFINE_MUTEX(ntfe_refresh_lock);

/*
 * The rules walk's refusal and rule path, under ntfe_refresh_lock: too big
 * for the stack of a walk that recurses. The path holds one byte past
 * what a refusal carries, so a cut can see the character it falls in.
 */
static struct peios_ntfe_build_why ntfe_walk_why;
static char ntfe_walk_path[PEIOS_NTFE_WHY_RULE_LEN + 1];

/*
 * The last refusal recorded as ntfe.policy.rejected, under
 * ntfe_refresh_lock. netd's inventory writes fire the walk too, and a
 * refused policy is refused again by every walk until someone fixes it:
 * the same refusal of the same input — digest, errno and reason — is one
 * record, not one per walk. A walk the rules stage accepts clears it.
 */
static struct {
	bool valid;
	u64 digest;
	long err;
	char reason[PEIOS_NTFE_WHY_REASON_LEN];
} ntfe_last_refusal;

static void ntfe_path_put(struct peios_ntfe_walk *walk, const char *s, u32 n)
{
	u32 at = walk->path_len;

	if (at < sizeof(ntfe_walk_path))
		memcpy(walk->path + at, s,
		       min_t(u32, n, sizeof(ntfe_walk_path) - at));
	walk->path_len = at + n;
}

/* Enters a rule; returns the length to restore on leaving it. */
static u32 ntfe_path_push(struct peios_ntfe_walk *walk, const char *name,
			  u32 name_len)
{
	u32 saved = walk->path_len;

	if (!walk->path)
		return saved;
	if (saved)
		ntfe_path_put(walk, "/", 1);
	ntfe_path_put(walk, name, name_len);
	return saved;
}

/*
 * Records why the rules walk is refused, unless something deeper already
 * did (the first refusal is the one that stopped the walk); with @in_rule,
 * the rule it was in, by path. Returns @err, so a site can return it.
 */
static long ntfe_refuse(struct peios_ntfe_walk *walk, long err,
			const char *reason, bool in_rule)
{
	struct peios_ntfe_build_why *why = walk->why;
	u32 n;

	if (!why || why->reason[0])
		return err;
	strscpy(why->reason, reason, sizeof(why->reason));
	why->layer = walk->layer;
	if (!in_rule || !walk->path_len)
		return err;
	n = min_t(u32, walk->path_len, sizeof(why->rule));
	if (n < walk->path_len) {
		/* Cut at a character boundary, and say so. */
		while (n && ((u8)walk->path[n] & 0xc0) == 0x80)
			n--;
		why->rule_truncated = 1;
	}
	memcpy(why->rule, walk->path, n);
	why->rule_len = n;
	return err;
}

/*
 * Writes ntfe.policy.rejected for a refusal, unless it is the last one
 * recorded over again. Process context, under ntfe_refresh_lock.
 */
static void ntfe_note_refusal(u64 digest, long err,
			      const struct peios_ntfe_build_why *why)
{
	if (ntfe_last_refusal.valid && ntfe_last_refusal.digest == digest &&
	    ntfe_last_refusal.err == err &&
	    !strcmp(ntfe_last_refusal.reason, why->reason))
		return;
	if (peios_ntfe_policy_rejected_emit(why, err) < 0)
		return;
	ntfe_last_refusal.valid = true;
	ntfe_last_refusal.digest = digest;
	ntfe_last_refusal.err = err;
	strscpy(ntfe_last_refusal.reason, why->reason,
		sizeof(ntfe_last_refusal.reason));
}

/* A builder call failed: out of memory, or text that is not UTF-8. */
static long ntfe_refuse_feed(struct peios_ntfe_walk *walk, long err)
{
	if (!err)
		return 0;
	return ntfe_refuse(walk, err,
			   err == -ENOMEM ? "out-of-memory" : "not-utf8", true);
}

#define NTFE_FNV_OFFSET	0xcbf29ce484222325ULL
#define NTFE_FNV_PRIME	0x100000001b3ULL

static void ntfe_digest_bytes(struct peios_ntfe_walk *walk, const void *data,
			     size_t len)
{
	const u8 *p = data;
	u64 h = walk->digest;

	while (len--) {
		h ^= *p++;
		h *= NTFE_FNV_PRIME;
	}
	/* A separator, so "ab"+"c" and "a"+"bc" digest differently. */
	h ^= 0xff;
	h *= NTFE_FNV_PRIME;
	walk->digest = h;
}

static void ntfe_digest_u32(struct peios_ntfe_walk *walk, u32 v)
{
	ntfe_digest_bytes(walk, &v, sizeof(v));
}

long peios_ntfe_network_root_discover_from_machine_hive(u32 source_id,
						       const u8 machine_root_guid[16],
						       bool *present_out,
						       u8 network_guid_out[16])
{
	/* Absolute path: the leading hive component ("Machine") is resolved
	 * locally against the hive root, not round-tripped.
	 */
	static const struct pkm_lcs_path_component_view network_path[] = {
		{ .name = "Machine", .name_len = sizeof("Machine") - 1 },
		{ .name = "System", .name_len = sizeof("System") - 1 },
		{ .name = "Network", .name_len = sizeof("Network") - 1 },
	};
	struct pkm_lcs_resolved_key_path key = { };
	struct pkm_lcs_layer_snapshot layers = { };
	long ret;

	if (present_out)
		*present_out = false;
	if (!source_id || !machine_root_guid || !present_out ||
	    !network_guid_out)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components(
		source_id, 0, machine_root_guid, network_path,
		ARRAY_SIZE(network_path), layers.layers, layers.layer_count,
		NULL, 0, &key);
	if (ret == -ENOENT) {
		/* Absence is not an error: no Network key, no policy and
		 * no context.
		 */
		ret = 0;
		goto out;
	}
	if (ret)
		goto out;

	memcpy(network_guid_out, key.key_guid, 16);
	*present_out = true;
	pkm_lcs_resolved_key_path_destroy(&key);
out:
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

/* Strips registry-string NUL termination (single or REG_MULTI_SZ style). */
static u32 ntfe_str_trim(const u8 *data, u32 len)
{
	while (len && data[len - 1] == '\0')
		len--;
	return len;
}

static long ntfe_feed_value(struct peios_ntfe_walk *walk, const char *name,
			   u32 name_len, u32 type, const u8 *data, u32 len)
{
	ntfe_digest_bytes(walk, name, name_len);
	ntfe_digest_u32(walk, type);
	ntfe_digest_bytes(walk, data, len);
	switch (type) {
	case NTFE_REG_SZ:
	case NTFE_REG_EXPAND_SZ:
		return ntfe_refuse_feed(walk, ntfe_rust_builder_value_str(
			walk->builder, name, name_len, data,
			ntfe_str_trim(data, len)));
	case NTFE_REG_DWORD:
		if (len != 4)
			return ntfe_refuse(walk, -EINVAL, "bad-value-length",
					   true);
		return ntfe_refuse_feed(walk, ntfe_rust_builder_value_int(
			walk->builder, name, name_len,
			get_unaligned_le32(data)));
	case NTFE_REG_DWORD_BIG_ENDIAN:
		if (len != 4)
			return ntfe_refuse(walk, -EINVAL, "bad-value-length",
					   true);
		return ntfe_refuse_feed(walk, ntfe_rust_builder_value_int(
			walk->builder, name, name_len,
			get_unaligned_be32(data)));
	case NTFE_REG_QWORD:
		if (len != 8)
			return ntfe_refuse(walk, -EINVAL, "bad-value-length",
					   true);
		return ntfe_refuse_feed(walk, ntfe_rust_builder_value_int(
			walk->builder, name, name_len,
			(s64)get_unaligned_le64(data)));
	case NTFE_REG_MULTI_SZ: {
		u32 start = 0, i;
		long ret;

		ret = ntfe_rust_builder_value_list_begin(walk->builder, name,
							name_len);
		if (ret)
			return ntfe_refuse_feed(walk, ret);
		len = ntfe_str_trim(data, len);
		for (i = 0; i <= len; i++) {
			if (i == len || data[i] == '\0') {
				if (i > start) {
					ret = ntfe_rust_builder_list_str(
						walk->builder,
						(const char *)data + start,
						i - start);
					if (ret)
						return ntfe_refuse_feed(walk,
									ret);
				}
				start = i + 1;
			}
		}
		return ntfe_refuse_feed(walk,
			ntfe_rust_builder_value_list_end(walk->builder));
	}
	default:
		/*
		 * An unknown value type in a rule key is refused whole:
		 * atomic transitions prefer a loud rejection (and the old
		 * generation) over a silently half-read rule.
		 */
		return ntfe_refuse(walk, -EINVAL, "bad-value-type", true);
	}
}

typedef long (*ntfe_value_cb)(struct peios_ntfe_walk *walk, void *ctx,
			     const char *name, u32 name_len, u32 type,
			     const u8 *data, u32 len);

static long ntfe_feed_value_cb(struct peios_ntfe_walk *walk, void *ctx,
			      const char *name, u32 name_len, u32 type,
			      const u8 *data, u32 len)
{
	return ntfe_feed_value(walk, name, name_len, type, data, len);
}

/* One RSI_QUERY_VALUES round trip: this key's effective values -> cb. */
static long ntfe_for_each_value(struct peios_ntfe_walk *walk, const u8 guid[16],
			       ntfe_value_cb cb, void *ctx)
{
	struct pkm_lcs_rsi_query_values_batch_result batch = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u8 *records = NULL;
	size_t off = 0;
	u32 i;
	long ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		walk->source_id, 0, guid, "", 0, true, &walk->limits,
		walk->limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out;

	/* Two passes: size, then materialize the layering-resolved batch. */
	ret = pkm_lcs_rsi_materialize_query_values_batch_response(
		frame.data, frame.len, response.request_id,
		walk->next_sequence, walk->layers.layers,
		walk->layers.layer_count, NULL, 0, &response.limits, NULL, 0,
		&batch);
	if (ret)
		goto out;
	if (!batch.count)
		goto out;

	records = kvmalloc(batch.required_len, GFP_KERNEL);
	if (!records) {
		ret = -ENOMEM;
		goto out;
	}
	ret = pkm_lcs_rsi_materialize_query_values_batch_response(
		frame.data, frame.len, response.request_id,
		walk->next_sequence, walk->layers.layers,
		walk->layers.layer_count, NULL, 0, &response.limits, records,
		batch.required_len, &batch);
	if (ret)
		goto out;

	/* Record layout: u32 name_len | name | u32 type | u32 data_len |
	 * data, little-endian (the REG_IOC_QUERY_VALUES_BATCH wire shape).
	 */
	for (i = 0; i < batch.count; i++) {
		u32 name_len, type, data_len;
		size_t remaining;
		const char *name;
		const u8 *data;

		remaining = batch.written_len - off;
		if (off > batch.written_len || remaining < 12) {
			ret = -EIO;
			goto out;
		}
		name_len = get_unaligned_le32(records + off);
		off += 4;
		remaining -= 4;
		if (name_len > remaining - 8) {
			ret = -EIO;
			goto out;
		}
		name = (const char *)records + off;
		off += name_len;
		type = get_unaligned_le32(records + off);
		off += 4;
		data_len = get_unaligned_le32(records + off);
		off += 4;
		remaining = batch.written_len - off;
		if (data_len > remaining) {
			ret = -EIO;
			goto out;
		}
		data = records + off;
		off += data_len;

		ret = cb(walk, ctx, name, name_len, type, data, data_len);
		if (ret)
			goto out;
	}
out:
	kvfree(records);
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

static long ntfe_walk_values(struct peios_ntfe_walk *walk, const u8 guid[16])
{
	return ntfe_for_each_value(walk, guid, ntfe_feed_value_cb, NULL);
}

/*
 * CurrentReportingLevel lives on the Rules key itself (ratified:
 * Machine\System\Network\Rules\CurrentReportingLevel). Absent = 1, so
 * everything fires — quietness ships as a visible value. Out-of-range
 * values are refused whole, like any other malformed policy.
 */
#define NTFE_REPORTING_LEVEL_NAME	"CurrentReportingLevel"

static long ntfe_reporting_level_cb(struct peios_ntfe_walk *walk, void *ctx,
				   const char *name, u32 name_len, u32 type,
				   const u8 *data, u32 len)
{
	u8 *level = ctx;
	s64 v;

	if (name_len != sizeof(NTFE_REPORTING_LEVEL_NAME) - 1 ||
	    memcmp(name, NTFE_REPORTING_LEVEL_NAME, name_len))
		return 0;
	switch (type) {
	case NTFE_REG_DWORD:
		if (len != 4)
			goto bad;
		v = get_unaligned_le32(data);
		break;
	case NTFE_REG_DWORD_BIG_ENDIAN:
		if (len != 4)
			goto bad;
		v = get_unaligned_be32(data);
		break;
	case NTFE_REG_QWORD:
		if (len != 8)
			goto bad;
		v = (s64)get_unaligned_le64(data);
		break;
	default:
		goto bad;
	}
	if (v < 1 || v > 6)
		goto bad;
	*level = (u8)v;
	return 0;
bad:
	return ntfe_refuse(walk, -EINVAL, "bad-reporting-level", false);
}

/* Walk one rule key: values, then children as exceptions, recursively. */
static long ntfe_walk_rule(struct peios_ntfe_walk *walk, const u8 guid[16],
			  const char *name, u32 name_len, u32 depth)
{
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u32 i, saved_path;
	long ret;

	saved_path = ntfe_path_push(walk, name, name_len);
	if (depth > PEIOS_NTFE_MAX_RULE_DEPTH) {
		ret = ntfe_refuse(walk, -E2BIG, "rule-too-deep", true);
		goto out_path;
	}
	if (++walk->rules_seen > PEIOS_NTFE_MAX_RULES) {
		ret = ntfe_refuse(walk, -E2BIG, "too-many-rules", true);
		goto out_path;
	}

	ntfe_digest_u32(walk, depth);
	ntfe_digest_bytes(walk, name, name_len);
	ret = ntfe_refuse_feed(walk, ntfe_rust_builder_rule_begin(
		walk->builder, name, name_len));
	if (ret)
		goto out_path;
	ret = ntfe_walk_values(walk, guid);
	if (ret)
		goto out_path;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		walk->source_id, 0, guid, &walk->limits,
		walk->limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out;
	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		frame.data, frame.len, response.request_id,
		walk->next_sequence, walk->layers.layers,
		walk->layers.layer_count, NULL, 0, &response.limits,
		&summary);
	if (ret)
		goto out;

	for (i = 0; i < summary.subkey_count; i++) {
		struct pkm_lcs_rsi_enum_subkey_result subkey = { };
		char *child_name;

		ret = pkm_lcs_rsi_materialize_enum_subkey_response(
			frame.data, frame.len, response.request_id,
			walk->next_sequence, i, walk->layers.layers,
			walk->layers.layer_count, NULL, 0, &response.limits,
			&subkey);
		if (ret)
			goto out;
		if (!subkey.found)
			continue;
		if ((size_t)subkey.name_offset > frame.len ||
		    (size_t)subkey.name_len >
			    frame.len - (size_t)subkey.name_offset) {
			ret = -EIO;
			goto out;
		}
		child_name = kmemdup_nul(frame.data + subkey.name_offset,
					 subkey.name_len, GFP_KERNEL);
		if (!child_name) {
			ret = -ENOMEM;
			goto out;
		}
		ret = ntfe_walk_rule(walk, subkey.child_guid, child_name,
				    subkey.name_len, depth + 1);
		kfree(child_name);
		if (ret)
			goto out;
	}
	ret = ntfe_rust_builder_rule_end(walk->builder);
out:
	pkm_lcs_source_response_frame_destroy(&frame);
out_path:
	/* Anything this rule's walk did not name is a registry read that
	 * failed in it, or memory.
	 */
	if (ret)
		ntfe_refuse(walk, ret,
			    ret == -ENOMEM ? "out-of-memory" :
					     "registry-read-failed", true);
	walk->path_len = saved_path;
	return ret;
}

/* Builds one layer's forest from its layer key, or NULL when absent. */
static long ntfe_build_layer(struct peios_ntfe_walk *walk, bool present,
			    const u8 guid[16], u8 layer, void **forest_out)
{
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u32 i;
	long ret;

	*forest_out = NULL;
	ntfe_digest_u32(walk, layer);
	ntfe_digest_u32(walk, present);
	if (!present)
		return 0;

	walk->layer = layer;
	walk->path_len = 0;
	walk->builder = ntfe_rust_builder_new();
	if (!walk->builder)
		return ntfe_refuse(walk, -ENOMEM, "out-of-memory", false);

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		walk->source_id, 0, guid, &walk->limits,
		walk->limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_builder;
	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		frame.data, frame.len, response.request_id,
		walk->next_sequence, walk->layers.layers,
		walk->layers.layer_count, NULL, 0, &response.limits,
		&summary);
	if (ret)
		goto out_builder;

	for (i = 0; i < summary.subkey_count; i++) {
		struct pkm_lcs_rsi_enum_subkey_result subkey = { };
		char *name;

		ret = pkm_lcs_rsi_materialize_enum_subkey_response(
			frame.data, frame.len, response.request_id,
			walk->next_sequence, i, walk->layers.layers,
			walk->layers.layer_count, NULL, 0, &response.limits,
			&subkey);
		if (ret)
			goto out_builder;
		if (!subkey.found)
			continue;
		if ((size_t)subkey.name_offset > frame.len ||
		    (size_t)subkey.name_len >
			    frame.len - (size_t)subkey.name_offset) {
			ret = -EIO;
			goto out_builder;
		}
		name = kmemdup_nul(frame.data + subkey.name_offset,
				   subkey.name_len, GFP_KERNEL);
		if (!name) {
			ret = -ENOMEM;
			goto out_builder;
		}
		ret = ntfe_walk_rule(walk, subkey.child_guid, name,
				    subkey.name_len, 0);
		kfree(name);
		if (ret)
			goto out_builder;
	}

	pkm_lcs_source_response_frame_destroy(&frame);
	/* build consumes the builder on every path; a refusal names its
	 * reason, rule and layer in walk->why.
	 */
	ret = ntfe_rust_builder_build_why(walk->builder, layer, forest_out,
					  walk->why);
	walk->builder = NULL;
	return ret;

out_builder:
	pkm_lcs_source_response_frame_destroy(&frame);
	ntfe_rust_builder_free(walk->builder);
	walk->builder = NULL;
	return ret;
}

/*
 * One RSI_ENUM_CHILDREN round trip: each subkey of @guid -> cb, with the
 * child's guid and its name (a pointer into the retained frame, valid
 * for the callback; nested round trips take their own frames).
 */
typedef long (*ntfe_child_cb)(struct peios_ntfe_walk *walk, void *ctx,
			     const u8 child_guid[16], const u8 *name,
			     u32 name_len);

static long ntfe_for_each_child(struct peios_ntfe_walk *walk, const u8 guid[16],
			       ntfe_child_cb cb, void *ctx)
{
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u32 i;
	long ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		walk->source_id, 0, guid, &walk->limits,
		walk->limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out;
	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		frame.data, frame.len, response.request_id,
		walk->next_sequence, walk->layers.layers,
		walk->layers.layer_count, NULL, 0, &response.limits, &summary);
	if (ret)
		goto out;

	for (i = 0; i < summary.subkey_count; i++) {
		struct pkm_lcs_rsi_enum_subkey_result subkey = { };

		ret = pkm_lcs_rsi_materialize_enum_subkey_response(
			frame.data, frame.len, response.request_id,
			walk->next_sequence, i, walk->layers.layers,
			walk->layers.layer_count, NULL, 0, &response.limits,
			&subkey);
		if (ret)
			goto out;
		if (!subkey.found)
			continue;
		if ((size_t)subkey.name_offset > frame.len ||
		    (size_t)subkey.name_len >
			    frame.len - (size_t)subkey.name_offset) {
			ret = -EIO;
			goto out;
		}
		ret = cb(walk, ctx, subkey.child_guid,
			 frame.data + subkey.name_offset, subkey.name_len);
		if (ret)
			goto out;
	}
out:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

static bool ntfe_name_is(const u8 *name, u32 name_len, const char *want)
{
	return name_len == strlen(want) && !memcmp(name, want, name_len);
}

/* --- the rules ---------------------------------------------------------- */

struct ntfe_rules_children {
	u8 packet_guid[16], raw_guid[16], flow_guid[16];
	bool packet_present, raw_present, flow_present;
};

static long ntfe_rules_child_cb(struct peios_ntfe_walk *walk, void *ctx,
			       const u8 child_guid[16], const u8 *name,
			       u32 name_len)
{
	struct ntfe_rules_children *c = ctx;

	if (ntfe_name_is(name, name_len, "Packet")) {
		memcpy(c->packet_guid, child_guid, 16);
		c->packet_present = true;
	} else if (ntfe_name_is(name, name_len, "RawPacket")) {
		memcpy(c->raw_guid, child_guid, 16);
		c->raw_present = true;
	} else if (ntfe_name_is(name, name_len, "Flow")) {
		memcpy(c->flow_guid, child_guid, 16);
		c->flow_present = true;
	}
	/* Interface is netd's; unknown layer names are someone else's
	 * future: ignored.
	 */
	return 0;
}

/*
 * Walks the rules subtree and publishes a new policy generation, unless
 * the walk fed the builder exactly what the last published walk did.
 */
static long ntfe_refresh_rules(struct peios_ntfe_walk *walk,
			      const u8 rules_guid[16])
{
	struct ntfe_rules_children c = { };
	void *packet_forest = NULL, *raw_forest = NULL, *flow_forest = NULL;
	u8 reporting_level = 1;
	long ret;

	walk->digest = NTFE_FNV_OFFSET;
	walk->rules_seen = 0;
	peios_ntfe_build_why_reset(&ntfe_walk_why);
	walk->why = &ntfe_walk_why;
	walk->path = ntfe_walk_path;
	walk->path_len = 0;
	walk->layer = PEIOS_NTFE_WHY_NO_LAYER;

	ret = ntfe_for_each_value(walk, rules_guid, ntfe_reporting_level_cb,
				 &reporting_level);
	if (ret)
		goto out;
	ntfe_digest_u32(walk, reporting_level);

	/* Find the layer keys under Rules: Packet, RawPacket, Flow. */
	ret = ntfe_for_each_child(walk, rules_guid, ntfe_rules_child_cb, &c);
	if (ret)
		goto out;

	ret = ntfe_build_layer(walk, c.packet_present, c.packet_guid,
			      PEIOS_NTFE_LAYER_PACKET, &packet_forest);
	if (ret)
		goto out;
	walk->rules_seen = 0;
	ret = ntfe_build_layer(walk, c.raw_present, c.raw_guid,
			      PEIOS_NTFE_LAYER_RAWPACKET, &raw_forest);
	if (ret)
		goto out;
	walk->rules_seen = 0;
	ret = ntfe_build_layer(walk, c.flow_present, c.flow_guid,
			      PEIOS_NTFE_LAYER_FLOW, &flow_forest);
	if (ret)
		goto out;
	walk->layer = PEIOS_NTFE_WHY_NO_LAYER;

	if (walk->digest == ntfe_published_digest) {
		/* The same policy, byte for byte: the active generation
		 * already is it, even when that policy is no forests at all
		 * (a Rules key seeded before its layers). Publishing again
		 * would only re-judge every flow for nothing: a policy save
		 * fires the watch for each key it touches, and netd's
		 * inventory writes share the watch.
		 */
		ret = 0;
		goto out;
	}

	ret = peios_ntfe_policy_publish_why(packet_forest, raw_forest,
					    flow_forest, reporting_level,
					    walk->why);
	if (!ret) {
		ntfe_published_digest = walk->digest;
		packet_forest = NULL;
		raw_forest = NULL;
		flow_forest = NULL;
	}
out:
	if (ret) {
		/* What no site named is a registry read that failed outside
		 * any rule (the Rules key's values, a layer key's children),
		 * or memory.
		 */
		ntfe_refuse(walk, ret,
			    ret == -ENOMEM ? "out-of-memory" :
					     "registry-read-failed", false);
		pr_warn("ntfe: rules refresh failed (%ld, %s); keeping the previous generation\n",
			ret, ntfe_walk_why.reason);
		ntfe_note_refusal(walk->digest, ret, &ntfe_walk_why);
	} else {
		ntfe_last_refusal.valid = false;
	}
	walk->why = NULL;
	walk->path = NULL;
	ntfe_rust_forest_free(packet_forest);
	ntfe_rust_forest_free(raw_forest);
	ntfe_rust_forest_free(flow_forest);
	return ret;
}

/* --- the network context ------------------------------------------------ */

/* One network record as the walk read it: Networks\<id> Name, Trust. */
struct ntfe_network_record {
	char id[PEIOS_NTFE_NETWORK_ID_LEN];
	char name[PEIOS_NTFE_NETWORK_NAME_LEN];
	char trust[PEIOS_NTFE_NETWORK_TRUST_LEN];
};

#define NTFE_MAX_NETWORK_RECORDS	256U

struct ntfe_networks {
	struct ntfe_network_record *records;
	u32 count;
};

/* Copies a registry string into a bounded buffer; confesses truncation. */
static void ntfe_copy_str(char *dst, size_t dst_len, const u8 *data, u32 len,
			 const char *what)
{
	len = ntfe_str_trim(data, len);
	if (len >= dst_len) {
		pr_warn_once("ntfe: network context: %s longer than %zu bytes; truncated\n",
			     what, dst_len - 1);
		len = dst_len - 1;
	}
	memcpy(dst, data, len);
	dst[len] = '\0';
}

static long ntfe_network_value_cb(struct peios_ntfe_walk *walk, void *ctx,
				 const char *name, u32 name_len, u32 type,
				 const u8 *data, u32 len)
{
	struct ntfe_network_record *rec = ctx;

	if (type != NTFE_REG_SZ && type != NTFE_REG_EXPAND_SZ)
		return 0;
	if (ntfe_name_is(name, name_len, "Name"))
		ntfe_copy_str(rec->name, sizeof(rec->name), data, len,
			     "a network's Name");
	else if (ntfe_name_is(name, name_len, "Trust"))
		ntfe_copy_str(rec->trust, sizeof(rec->trust), data, len,
			     "a network's Trust");
	return 0;
}

static long ntfe_network_child_cb(struct peios_ntfe_walk *walk, void *ctx,
				 const u8 child_guid[16], const u8 *name,
				 u32 name_len)
{
	struct ntfe_networks *nets = ctx;
	struct ntfe_network_record *rec;
	long ret;

	if (name_len >= PEIOS_NTFE_NETWORK_ID_LEN) {
		pr_warn_once("ntfe: network context: a Networks record name is not a UUID; ignored\n");
		return 0;
	}
	if (nets->count >= NTFE_MAX_NETWORK_RECORDS) {
		pr_warn_once("ntfe: network context: more than %u network records; the rest are ignored\n",
			     NTFE_MAX_NETWORK_RECORDS);
		return 0;
	}
	rec = &nets->records[nets->count];
	memset(rec, 0, sizeof(*rec));
	memcpy(rec->id, name, name_len);
	/* A record whose values cannot be read is a record with no Name
	 * and no Trust: the id is still a fact.
	 */
	ret = ntfe_for_each_value(walk, child_guid, ntfe_network_value_cb, rec);
	if (ret)
		pr_warn("ntfe: network context: could not read Networks\\%s (%ld)\n",
			rec->id, ret);
	nets->count++;
	return 0;
}

/* Interfaces\<ifid>\Status: Name (the kernel name) and Network (the id). */
struct ntfe_status_values {
	char ifname[IFNAMSIZ];
	char network_id[PEIOS_NTFE_NETWORK_ID_LEN];
};

static long ntfe_status_value_cb(struct peios_ntfe_walk *walk, void *ctx,
				const char *name, u32 name_len, u32 type,
				const u8 *data, u32 len)
{
	struct ntfe_status_values *v = ctx;

	if (type != NTFE_REG_SZ && type != NTFE_REG_EXPAND_SZ)
		return 0;
	if (ntfe_name_is(name, name_len, "Name"))
		ntfe_copy_str(v->ifname, sizeof(v->ifname), data, len,
			     "an interface's Name");
	else if (ntfe_name_is(name, name_len, "Network"))
		ntfe_copy_str(v->network_id, sizeof(v->network_id), data, len,
			     "an interface's Network");
	return 0;
}

struct ntfe_context_build {
	const struct ntfe_networks *nets;
	struct peios_ntfe_context_table *table;
};

/* Under an interface key: only its Status subkey is read. */
static long ntfe_interface_status_cb(struct peios_ntfe_walk *walk, void *ctx,
				    const u8 child_guid[16], const u8 *name,
				    u32 name_len)
{
	struct ntfe_context_build *b = ctx;
	struct ntfe_status_values v = { };
	struct peios_ntfe_context_entry *e;
	u32 i;
	long ret;

	if (!ntfe_name_is(name, name_len, "Status"))
		return 0;
	ret = ntfe_for_each_value(walk, child_guid, ntfe_status_value_cb, &v);
	if (ret) {
		pr_warn("ntfe: network context: could not read an interface's Status (%ld)\n",
			ret);
		return 0;
	}
	/* No name, or no network identified on it: no context. */
	if (!v.ifname[0] || !v.network_id[0])
		return 0;
	if (b->table->count >= PEIOS_NTFE_MAX_CONTEXTS) {
		pr_warn_once("ntfe: network context: more than %u interfaces; the rest carry no context\n",
			     PEIOS_NTFE_MAX_CONTEXTS);
		return 0;
	}
	e = &b->table->entries[b->table->count++];
	memcpy(e->ifname, v.ifname, sizeof(e->ifname));
	memcpy(e->network_id, v.network_id, sizeof(e->network_id));
	for (i = 0; i < b->nets->count; i++) {
		const struct ntfe_network_record *rec = &b->nets->records[i];

		if (strcmp(rec->id, e->network_id))
			continue;
		memcpy(e->network_name, rec->name, sizeof(e->network_name));
		memcpy(e->network_trust, rec->trust, sizeof(e->network_trust));
		break;
	}
	return 0;
}

static long ntfe_interface_child_cb(struct peios_ntfe_walk *walk, void *ctx,
				   const u8 child_guid[16], const u8 *name,
				   u32 name_len)
{
	long ret;

	ret = ntfe_for_each_child(walk, child_guid, ntfe_interface_status_cb,
				 ctx);
	/* An interface key that cannot be listed is an interface without
	 * a context, not a failed table (PEI-1306).
	 */
	if (ret)
		pr_warn("ntfe: network context: could not list an interface's subkeys (%ld)\n",
			ret);
	return 0;
}

/*
 * Reads the inventory into a context table and publishes it. Absence of
 * either key is an empty table. Nothing here refuses: a record that
 * cannot be read is an interface without a context, and the table is
 * published with whatever was readable.
 */
static long ntfe_refresh_context(struct peios_ntfe_walk *walk,
				bool interfaces_present,
				const u8 interfaces_guid[16],
				bool networks_present,
				const u8 networks_guid[16])
{
	struct ntfe_networks nets = { };
	struct ntfe_context_build b = { .nets = &nets };
	long ret = 0;

	b.table = peios_ntfe_context_table_alloc(PEIOS_NTFE_MAX_CONTEXTS);
	if (!b.table)
		return -ENOMEM;
	b.table->count = 0;

	if (networks_present) {
		nets.records = kvcalloc(NTFE_MAX_NETWORK_RECORDS,
					sizeof(*nets.records), GFP_KERNEL);
		if (!nets.records) {
			ret = -ENOMEM;
			goto out;
		}
		/* A list that cannot be read keeps the previous table: a
		 * table published from half a list would strip every network
		 * after the failure of its Name and Trust, and with them every
		 * rule that names them. Only a single record is skipped.
		 */
		ret = ntfe_for_each_child(walk, networks_guid,
					 ntfe_network_child_cb, &nets);
		if (ret)
			goto out;
	}
	if (interfaces_present) {
		ret = ntfe_for_each_child(walk, interfaces_guid,
					 ntfe_interface_child_cb, &b);
		if (ret)
			goto out;
	}

	/* Takes the table, or frees it when nothing changed. */
	ret = peios_ntfe_context_publish(b.table);
	b.table = NULL;
out:
	if (ret)
		pr_warn("ntfe: network context refresh failed (%ld); keeping the previous table\n",
			ret);
	kfree(b.table);
	kvfree(nets.records);
	return ret;
}

/* --- the Network key ---------------------------------------------------- */

struct ntfe_network_children {
	u8 rules_guid[16], interfaces_guid[16], networks_guid[16];
	bool rules_present, interfaces_present, networks_present;
};

static long ntfe_network_child_key_cb(struct peios_ntfe_walk *walk, void *ctx,
				     const u8 child_guid[16], const u8 *name,
				     u32 name_len)
{
	struct ntfe_network_children *c = ctx;

	if (ntfe_name_is(name, name_len, "Rules")) {
		memcpy(c->rules_guid, child_guid, 16);
		c->rules_present = true;
	} else if (ntfe_name_is(name, name_len, "Interfaces")) {
		memcpy(c->interfaces_guid, child_guid, 16);
		c->interfaces_present = true;
	} else if (ntfe_name_is(name, name_len, "Networks")) {
		memcpy(c->networks_guid, child_guid, 16);
		c->networks_present = true;
	}
	/* Profiles, Dns and the rest are netd's and resolvd's. */
	return 0;
}

long peios_ntfe_network_refresh_from_key(u32 source_id,
					const u8 network_guid[16])
{
	struct peios_ntfe_walk walk = { .source_id = source_id };
	struct ntfe_network_children c = { };
	long ret, context_ret;

	if (!source_id || !network_guid)
		return -EINVAL;

	mutex_lock(&ntfe_refresh_lock);
	ret = pkm_lcs_runtime_limits_snapshot(&walk.limits);
	if (ret)
		goto out_unlock;
	ret = pkm_lcs_source_next_sequence_snapshot(&walk.next_sequence);
	if (ret)
		goto out_unlock;
	ret = pkm_lcs_source_layer_snapshot_acquire(&walk.layers);
	if (ret)
		goto out_unlock;

	ret = ntfe_for_each_child(&walk, network_guid, ntfe_network_child_key_cb,
				 &c);
	if (ret)
		goto out;

	/* The rules: no key is no policy, and the previous generation
	 * stands, exactly as a walk that refused would leave it.
	 */
	if (c.rules_present) {
		ret = ntfe_refresh_rules(&walk, c.rules_guid);
	} else {
		pr_info_once("ntfe: no Rules key; keeping the previous generation\n");
		/* Recorded once per absence, not once per walk: an inventory
		 * write walks again, and finds the same nothing.
		 */
		peios_ntfe_build_why_reset(&ntfe_walk_why);
		strscpy(ntfe_walk_why.reason, "no-rules-key",
			sizeof(ntfe_walk_why.reason));
		ntfe_note_refusal(NTFE_FNV_OFFSET, 0, &ntfe_walk_why);
	}

	/* The context, whatever the rules did: the two are independent. */
	context_ret = ntfe_refresh_context(&walk, c.interfaces_present,
					  c.interfaces_guid,
					  c.networks_present, c.networks_guid);
	if (!ret)
		ret = context_ret;
out:
	pkm_lcs_source_layer_snapshot_release(&walk.layers);
out_unlock:
	mutex_unlock(&ntfe_refresh_lock);
	peios_ntfe_policy_note_ingest(ret);
	return ret;
}

/* --- change-notification coalescing ---------------------------------- */

/* Quiet time after the last change before the re-walk runs. */
#define PEIOS_NTFE_REFRESH_DEBOUNCE_MS	50

static void peios_ntfe_refresh_workfn(struct work_struct *work);

static struct {
	spinlock_t lock;
	bool pending;
	u32 source_id;
	u8 guid[16];
	struct delayed_work work;
} peios_ntfe_refresh = {
	.lock = __SPIN_LOCK_UNLOCKED(peios_ntfe_refresh.lock),
	.work = __DELAYED_WORK_INITIALIZER(peios_ntfe_refresh.work,
					   peios_ntfe_refresh_workfn, 0),
};

/*
 * In force: `noted` counts changes as the watch delivers them — inside
 * the registry write that made them, so a writer reads its own change
 * as noted the moment the write returns. `walked` is the count a re-walk
 * started from, recorded when it finishes. The walk reads the key after
 * taking that count, so walked >= N means every change up to the Nth has
 * been read and either published or refused.
 */
static atomic64_t peios_ntfe_changes_noted;
static atomic64_t peios_ntfe_changes_walked;

void peios_ntfe_ingest_progress(u64 *noted, u64 *walked)
{
	/* walked first: a racing walk can only make the pair look less
	 * finished than it is, never more. Acquire pairs with the release
	 * in the work function, so anything read after this — the status's
	 * last_ingest_error — is that walk's or a later one's (PEI-1378).
	 */
	*walked = atomic64_read_acquire(&peios_ntfe_changes_walked);
	*noted = atomic64_read(&peios_ntfe_changes_noted);
}

static void peios_ntfe_refresh_workfn(struct work_struct *work)
{
	u32 source_id;
	u8 guid[16];
	u64 noted;

	spin_lock(&peios_ntfe_refresh.lock);
	if (!peios_ntfe_refresh.pending) {
		spin_unlock(&peios_ntfe_refresh.lock);
		return;
	}
	peios_ntfe_refresh.pending = false;
	noted = atomic64_read(&peios_ntfe_changes_noted);
	source_id = peios_ntfe_refresh.source_id;
	memcpy(guid, peios_ntfe_refresh.guid, 16);
	spin_unlock(&peios_ntfe_refresh.lock);

	/* Failure keeps the previous generation; the walk logged why. The
	 * walk noted its result before returning; release publishes that
	 * result with the count.
	 */
	peios_ntfe_network_refresh_from_key(source_id, guid);
	atomic64_set_release(&peios_ntfe_changes_walked, noted);
}

void peios_ntfe_network_registry_changed(u32 source_id,
					const u8 network_guid[16])
{
	if (!source_id || !network_guid)
		return;

	spin_lock(&peios_ntfe_refresh.lock);
	peios_ntfe_refresh.source_id = source_id;
	memcpy(peios_ntfe_refresh.guid, network_guid, 16);
	peios_ntfe_refresh.pending = true;
	atomic64_inc(&peios_ntfe_changes_noted);
	spin_unlock(&peios_ntfe_refresh.lock);
	/* mod_delayed_work restarts the window: a burst of changes yields
	 * one re-walk, after the burst goes quiet.
	 */
	mod_delayed_work(system_wq, &peios_ntfe_refresh.work,
			 msecs_to_jiffies(PEIOS_NTFE_REFRESH_DEBOUNCE_MS));
}
