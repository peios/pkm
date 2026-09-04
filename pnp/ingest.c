// SPDX-License-Identifier: GPL-2.0-only
/*
 * Registry ingestion: Machine\System\Network -> published policy and
 * network context.
 *
 * The kernel reads its own policy (ratified: pnpd is an observer and an
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
#include <linux/peios_pnp.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

#include "../../security/pkm/lcs/rsi.h"
#include "../../security/pkm/lcs/source_device.h"
#include "pnp.h"

/* Registry value type codes (uapi/pkm/lcs.h). */
#define PNP_REG_SZ			1U
#define PNP_REG_EXPAND_SZ		2U
#define PNP_REG_DWORD			4U
#define PNP_REG_DWORD_BIG_ENDIAN	5U
#define PNP_REG_MULTI_SZ		7U
#define PNP_REG_QWORD			11U

/* Walk bounds: PNP's own, on top of the LCS runtime limits. */
#define PEIOS_PNP_MAX_RULE_DEPTH	12
#define PEIOS_PNP_MAX_RULES		4096

struct peios_pnp_walk {
	u32 source_id;
	u64 next_sequence;
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_layer_snapshot layers;
	void *builder;
	u32 rules_seen;
	/* FNV-1a over everything the rules walk fed the builder. */
	u64 digest;
};

/* The digest of the last rules walk that published; 0 = never. */
static u64 pnp_published_digest;
/* One refresh at a time: bootstrap and the deferred re-walk may overlap. */
static DEFINE_MUTEX(pnp_refresh_lock);

#define PNP_FNV_OFFSET	0xcbf29ce484222325ULL
#define PNP_FNV_PRIME	0x100000001b3ULL

static void pnp_digest_bytes(struct peios_pnp_walk *walk, const void *data,
			     size_t len)
{
	const u8 *p = data;
	u64 h = walk->digest;

	while (len--) {
		h ^= *p++;
		h *= PNP_FNV_PRIME;
	}
	/* A separator, so "ab"+"c" and "a"+"bc" digest differently. */
	h ^= 0xff;
	h *= PNP_FNV_PRIME;
	walk->digest = h;
}

static void pnp_digest_u32(struct peios_pnp_walk *walk, u32 v)
{
	pnp_digest_bytes(walk, &v, sizeof(v));
}

long peios_pnp_network_root_discover_from_machine_hive(u32 source_id,
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
static u32 pnp_str_trim(const u8 *data, u32 len)
{
	while (len && data[len - 1] == '\0')
		len--;
	return len;
}

static long pnp_feed_value(struct peios_pnp_walk *walk, const char *name,
			   u32 name_len, u32 type, const u8 *data, u32 len)
{
	pnp_digest_bytes(walk, name, name_len);
	pnp_digest_u32(walk, type);
	pnp_digest_bytes(walk, data, len);
	switch (type) {
	case PNP_REG_SZ:
	case PNP_REG_EXPAND_SZ:
		return pnp_rust_builder_value_str(walk->builder, name,
						  name_len, data,
						  pnp_str_trim(data, len));
	case PNP_REG_DWORD:
		if (len != 4)
			return -EINVAL;
		return pnp_rust_builder_value_int(walk->builder, name,
						  name_len,
						  get_unaligned_le32(data));
	case PNP_REG_DWORD_BIG_ENDIAN:
		if (len != 4)
			return -EINVAL;
		return pnp_rust_builder_value_int(walk->builder, name,
						  name_len,
						  get_unaligned_be32(data));
	case PNP_REG_QWORD:
		if (len != 8)
			return -EINVAL;
		return pnp_rust_builder_value_int(
			walk->builder, name, name_len,
			(s64)get_unaligned_le64(data));
	case PNP_REG_MULTI_SZ: {
		u32 start = 0, i;
		long ret;

		ret = pnp_rust_builder_value_list_begin(walk->builder, name,
							name_len);
		if (ret)
			return ret;
		len = pnp_str_trim(data, len);
		for (i = 0; i <= len; i++) {
			if (i == len || data[i] == '\0') {
				if (i > start) {
					ret = pnp_rust_builder_list_str(
						walk->builder,
						(const char *)data + start,
						i - start);
					if (ret)
						return ret;
				}
				start = i + 1;
			}
		}
		return pnp_rust_builder_value_list_end(walk->builder);
	}
	default:
		/*
		 * An unknown value type in a rule key is refused whole:
		 * atomic transitions prefer a loud rejection (and the old
		 * generation) over a silently half-read rule.
		 */
		return -EINVAL;
	}
}

typedef long (*pnp_value_cb)(struct peios_pnp_walk *walk, void *ctx,
			     const char *name, u32 name_len, u32 type,
			     const u8 *data, u32 len);

static long pnp_feed_value_cb(struct peios_pnp_walk *walk, void *ctx,
			      const char *name, u32 name_len, u32 type,
			      const u8 *data, u32 len)
{
	return pnp_feed_value(walk, name, name_len, type, data, len);
}

/* One RSI_QUERY_VALUES round trip: this key's effective values -> cb. */
static long pnp_for_each_value(struct peios_pnp_walk *walk, const u8 guid[16],
			       pnp_value_cb cb, void *ctx)
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

static long pnp_walk_values(struct peios_pnp_walk *walk, const u8 guid[16])
{
	return pnp_for_each_value(walk, guid, pnp_feed_value_cb, NULL);
}

/*
 * CurrentReportingLevel lives on the Rules key itself (ratified:
 * Machine\System\Network\Rules\CurrentReportingLevel). Absent = 1, so
 * everything fires — quietness ships as a visible value. Out-of-range
 * values are refused whole, like any other malformed policy.
 */
#define PNP_REPORTING_LEVEL_NAME	"CurrentReportingLevel"

static long pnp_reporting_level_cb(struct peios_pnp_walk *walk, void *ctx,
				   const char *name, u32 name_len, u32 type,
				   const u8 *data, u32 len)
{
	u8 *level = ctx;
	s64 v;

	if (name_len != sizeof(PNP_REPORTING_LEVEL_NAME) - 1 ||
	    memcmp(name, PNP_REPORTING_LEVEL_NAME, name_len))
		return 0;
	switch (type) {
	case PNP_REG_DWORD:
		if (len != 4)
			return -EINVAL;
		v = get_unaligned_le32(data);
		break;
	case PNP_REG_DWORD_BIG_ENDIAN:
		if (len != 4)
			return -EINVAL;
		v = get_unaligned_be32(data);
		break;
	case PNP_REG_QWORD:
		if (len != 8)
			return -EINVAL;
		v = (s64)get_unaligned_le64(data);
		break;
	default:
		return -EINVAL;
	}
	if (v < 1 || v > 6)
		return -EINVAL;
	*level = (u8)v;
	return 0;
}

/* Walk one rule key: values, then children as exceptions, recursively. */
static long pnp_walk_rule(struct peios_pnp_walk *walk, const u8 guid[16],
			  const char *name, u32 name_len, u32 depth)
{
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u32 i;
	long ret;

	if (depth > PEIOS_PNP_MAX_RULE_DEPTH)
		return -E2BIG;
	if (++walk->rules_seen > PEIOS_PNP_MAX_RULES)
		return -E2BIG;

	pnp_digest_u32(walk, depth);
	pnp_digest_bytes(walk, name, name_len);
	ret = pnp_rust_builder_rule_begin(walk->builder, name, name_len);
	if (ret)
		return ret;
	ret = pnp_walk_values(walk, guid);
	if (ret)
		return ret;

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
		ret = pnp_walk_rule(walk, subkey.child_guid, child_name,
				    subkey.name_len, depth + 1);
		kfree(child_name);
		if (ret)
			goto out;
	}
	ret = pnp_rust_builder_rule_end(walk->builder);
out:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

/* Builds one layer's forest from its layer key, or NULL when absent. */
static long pnp_build_layer(struct peios_pnp_walk *walk, bool present,
			    const u8 guid[16], u8 layer, void **forest_out)
{
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u32 i;
	long ret;

	*forest_out = NULL;
	pnp_digest_u32(walk, layer);
	pnp_digest_u32(walk, present);
	if (!present)
		return 0;

	walk->builder = pnp_rust_builder_new();
	if (!walk->builder)
		return -ENOMEM;

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
		ret = pnp_walk_rule(walk, subkey.child_guid, name,
				    subkey.name_len, 0);
		kfree(name);
		if (ret)
			goto out_builder;
	}

	pkm_lcs_source_response_frame_destroy(&frame);
	/* build consumes the builder on every path. */
	ret = pnp_rust_builder_build(walk->builder, layer, forest_out);
	walk->builder = NULL;
	return ret;

out_builder:
	pkm_lcs_source_response_frame_destroy(&frame);
	pnp_rust_builder_free(walk->builder);
	walk->builder = NULL;
	return ret;
}

/*
 * One RSI_ENUM_CHILDREN round trip: each subkey of @guid -> cb, with the
 * child's guid and its name (a pointer into the retained frame, valid
 * for the callback; nested round trips take their own frames).
 */
typedef long (*pnp_child_cb)(struct peios_pnp_walk *walk, void *ctx,
			     const u8 child_guid[16], const u8 *name,
			     u32 name_len);

static long pnp_for_each_child(struct peios_pnp_walk *walk, const u8 guid[16],
			       pnp_child_cb cb, void *ctx)
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

static bool pnp_name_is(const u8 *name, u32 name_len, const char *want)
{
	return name_len == strlen(want) && !memcmp(name, want, name_len);
}

/* --- the rules ---------------------------------------------------------- */

struct pnp_rules_children {
	u8 packet_guid[16], raw_guid[16], flow_guid[16];
	bool packet_present, raw_present, flow_present;
};

static long pnp_rules_child_cb(struct peios_pnp_walk *walk, void *ctx,
			       const u8 child_guid[16], const u8 *name,
			       u32 name_len)
{
	struct pnp_rules_children *c = ctx;

	if (pnp_name_is(name, name_len, "Packet")) {
		memcpy(c->packet_guid, child_guid, 16);
		c->packet_present = true;
	} else if (pnp_name_is(name, name_len, "RawPacket")) {
		memcpy(c->raw_guid, child_guid, 16);
		c->raw_present = true;
	} else if (pnp_name_is(name, name_len, "Flow")) {
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
static long pnp_refresh_rules(struct peios_pnp_walk *walk,
			      const u8 rules_guid[16])
{
	struct pnp_rules_children c = { };
	void *packet_forest = NULL, *raw_forest = NULL, *flow_forest = NULL;
	u8 reporting_level = 1;
	long ret;

	walk->digest = PNP_FNV_OFFSET;
	walk->rules_seen = 0;

	ret = pnp_for_each_value(walk, rules_guid, pnp_reporting_level_cb,
				 &reporting_level);
	if (ret)
		goto out;
	pnp_digest_u32(walk, reporting_level);

	/* Find the layer keys under Rules: Packet, RawPacket, Flow. */
	ret = pnp_for_each_child(walk, rules_guid, pnp_rules_child_cb, &c);
	if (ret)
		goto out;

	ret = pnp_build_layer(walk, c.packet_present, c.packet_guid,
			      PEIOS_PNP_LAYER_PACKET, &packet_forest);
	if (ret)
		goto out;
	walk->rules_seen = 0;
	ret = pnp_build_layer(walk, c.raw_present, c.raw_guid,
			      PEIOS_PNP_LAYER_RAWPACKET, &raw_forest);
	if (ret)
		goto out;
	walk->rules_seen = 0;
	ret = pnp_build_layer(walk, c.flow_present, c.flow_guid,
			      PEIOS_PNP_LAYER_FLOW, &flow_forest);
	if (ret)
		goto out;

	if (walk->digest == pnp_published_digest) {
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

	ret = peios_pnp_policy_publish(packet_forest, raw_forest, flow_forest,
				       reporting_level);
	if (!ret) {
		pnp_published_digest = walk->digest;
		packet_forest = NULL;
		raw_forest = NULL;
		flow_forest = NULL;
	}
out:
	if (ret)
		pr_warn("pnp: rules refresh failed (%ld); keeping the previous generation\n",
			ret);
	pnp_rust_forest_free(packet_forest);
	pnp_rust_forest_free(raw_forest);
	pnp_rust_forest_free(flow_forest);
	return ret;
}

/* --- the network context ------------------------------------------------ */

/* One network record as the walk read it: Networks\<id> Name, Trust. */
struct pnp_network_record {
	char id[PEIOS_PNP_NETWORK_ID_LEN];
	char name[PEIOS_PNP_NETWORK_NAME_LEN];
	char trust[PEIOS_PNP_NETWORK_TRUST_LEN];
};

#define PNP_MAX_NETWORK_RECORDS	256U

struct pnp_networks {
	struct pnp_network_record *records;
	u32 count;
};

/* Copies a registry string into a bounded buffer; confesses truncation. */
static void pnp_copy_str(char *dst, size_t dst_len, const u8 *data, u32 len,
			 const char *what)
{
	len = pnp_str_trim(data, len);
	if (len >= dst_len) {
		pr_warn_once("pnp: network context: %s longer than %zu bytes; truncated\n",
			     what, dst_len - 1);
		len = dst_len - 1;
	}
	memcpy(dst, data, len);
	dst[len] = '\0';
}

static long pnp_network_value_cb(struct peios_pnp_walk *walk, void *ctx,
				 const char *name, u32 name_len, u32 type,
				 const u8 *data, u32 len)
{
	struct pnp_network_record *rec = ctx;

	if (type != PNP_REG_SZ && type != PNP_REG_EXPAND_SZ)
		return 0;
	if (pnp_name_is(name, name_len, "Name"))
		pnp_copy_str(rec->name, sizeof(rec->name), data, len,
			     "a network's Name");
	else if (pnp_name_is(name, name_len, "Trust"))
		pnp_copy_str(rec->trust, sizeof(rec->trust), data, len,
			     "a network's Trust");
	return 0;
}

static long pnp_network_child_cb(struct peios_pnp_walk *walk, void *ctx,
				 const u8 child_guid[16], const u8 *name,
				 u32 name_len)
{
	struct pnp_networks *nets = ctx;
	struct pnp_network_record *rec;
	long ret;

	if (name_len >= PEIOS_PNP_NETWORK_ID_LEN) {
		pr_warn_once("pnp: network context: a Networks record name is not a UUID; ignored\n");
		return 0;
	}
	if (nets->count >= PNP_MAX_NETWORK_RECORDS) {
		pr_warn_once("pnp: network context: more than %u network records; the rest are ignored\n",
			     PNP_MAX_NETWORK_RECORDS);
		return 0;
	}
	rec = &nets->records[nets->count];
	memset(rec, 0, sizeof(*rec));
	memcpy(rec->id, name, name_len);
	/* A record whose values cannot be read is a record with no Name
	 * and no Trust: the id is still a fact.
	 */
	ret = pnp_for_each_value(walk, child_guid, pnp_network_value_cb, rec);
	if (ret)
		pr_warn("pnp: network context: could not read Networks\\%s (%ld)\n",
			rec->id, ret);
	nets->count++;
	return 0;
}

/* Interfaces\<ifid>\Status: Name (the kernel name) and Network (the id). */
struct pnp_status_values {
	char ifname[IFNAMSIZ];
	char network_id[PEIOS_PNP_NETWORK_ID_LEN];
};

static long pnp_status_value_cb(struct peios_pnp_walk *walk, void *ctx,
				const char *name, u32 name_len, u32 type,
				const u8 *data, u32 len)
{
	struct pnp_status_values *v = ctx;

	if (type != PNP_REG_SZ && type != PNP_REG_EXPAND_SZ)
		return 0;
	if (pnp_name_is(name, name_len, "Name"))
		pnp_copy_str(v->ifname, sizeof(v->ifname), data, len,
			     "an interface's Name");
	else if (pnp_name_is(name, name_len, "Network"))
		pnp_copy_str(v->network_id, sizeof(v->network_id), data, len,
			     "an interface's Network");
	return 0;
}

struct pnp_context_build {
	const struct pnp_networks *nets;
	struct peios_pnp_context_table *table;
};

/* Under an interface key: only its Status subkey is read. */
static long pnp_interface_status_cb(struct peios_pnp_walk *walk, void *ctx,
				    const u8 child_guid[16], const u8 *name,
				    u32 name_len)
{
	struct pnp_context_build *b = ctx;
	struct pnp_status_values v = { };
	struct peios_pnp_context_entry *e;
	u32 i;
	long ret;

	if (!pnp_name_is(name, name_len, "Status"))
		return 0;
	ret = pnp_for_each_value(walk, child_guid, pnp_status_value_cb, &v);
	if (ret) {
		pr_warn("pnp: network context: could not read an interface's Status (%ld)\n",
			ret);
		return 0;
	}
	/* No name, or no network identified on it: no context. */
	if (!v.ifname[0] || !v.network_id[0])
		return 0;
	if (b->table->count >= PEIOS_PNP_MAX_CONTEXTS) {
		pr_warn_once("pnp: network context: more than %u interfaces; the rest carry no context\n",
			     PEIOS_PNP_MAX_CONTEXTS);
		return 0;
	}
	e = &b->table->entries[b->table->count++];
	memcpy(e->ifname, v.ifname, sizeof(e->ifname));
	memcpy(e->network_id, v.network_id, sizeof(e->network_id));
	for (i = 0; i < b->nets->count; i++) {
		const struct pnp_network_record *rec = &b->nets->records[i];

		if (strcmp(rec->id, e->network_id))
			continue;
		memcpy(e->network_name, rec->name, sizeof(e->network_name));
		memcpy(e->network_trust, rec->trust, sizeof(e->network_trust));
		break;
	}
	return 0;
}

static long pnp_interface_child_cb(struct peios_pnp_walk *walk, void *ctx,
				   const u8 child_guid[16], const u8 *name,
				   u32 name_len)
{
	return pnp_for_each_child(walk, child_guid, pnp_interface_status_cb,
				  ctx);
}

/*
 * Reads the inventory into a context table and publishes it. Absence of
 * either key is an empty table. Nothing here refuses: a record that
 * cannot be read is an interface without a context, and the table is
 * published with whatever was readable.
 */
static long pnp_refresh_context(struct peios_pnp_walk *walk,
				bool interfaces_present,
				const u8 interfaces_guid[16],
				bool networks_present,
				const u8 networks_guid[16])
{
	struct pnp_networks nets = { };
	struct pnp_context_build b = { .nets = &nets };
	long ret = 0;

	b.table = peios_pnp_context_table_alloc(PEIOS_PNP_MAX_CONTEXTS);
	if (!b.table)
		return -ENOMEM;
	b.table->count = 0;

	if (networks_present) {
		nets.records = kvcalloc(PNP_MAX_NETWORK_RECORDS,
					sizeof(*nets.records), GFP_KERNEL);
		if (!nets.records) {
			ret = -ENOMEM;
			goto out;
		}
		ret = pnp_for_each_child(walk, networks_guid,
					 pnp_network_child_cb, &nets);
		if (ret)
			goto out;
	}
	if (interfaces_present) {
		ret = pnp_for_each_child(walk, interfaces_guid,
					 pnp_interface_child_cb, &b);
		if (ret)
			goto out;
	}

	/* Takes the table, or frees it when nothing changed. */
	ret = peios_pnp_context_publish(b.table);
	b.table = NULL;
out:
	if (ret)
		pr_warn("pnp: network context refresh failed (%ld); keeping the previous table\n",
			ret);
	kfree(b.table);
	kvfree(nets.records);
	return ret;
}

/* --- the Network key ---------------------------------------------------- */

struct pnp_network_children {
	u8 rules_guid[16], interfaces_guid[16], networks_guid[16];
	bool rules_present, interfaces_present, networks_present;
};

static long pnp_network_child_key_cb(struct peios_pnp_walk *walk, void *ctx,
				     const u8 child_guid[16], const u8 *name,
				     u32 name_len)
{
	struct pnp_network_children *c = ctx;

	if (pnp_name_is(name, name_len, "Rules")) {
		memcpy(c->rules_guid, child_guid, 16);
		c->rules_present = true;
	} else if (pnp_name_is(name, name_len, "Interfaces")) {
		memcpy(c->interfaces_guid, child_guid, 16);
		c->interfaces_present = true;
	} else if (pnp_name_is(name, name_len, "Networks")) {
		memcpy(c->networks_guid, child_guid, 16);
		c->networks_present = true;
	}
	/* Profiles, Dns and the rest are netd's and resolvd's. */
	return 0;
}

long peios_pnp_network_refresh_from_key(u32 source_id,
					const u8 network_guid[16])
{
	struct peios_pnp_walk walk = { .source_id = source_id };
	struct pnp_network_children c = { };
	long ret, context_ret;

	if (!source_id || !network_guid)
		return -EINVAL;

	mutex_lock(&pnp_refresh_lock);
	ret = pkm_lcs_runtime_limits_snapshot(&walk.limits);
	if (ret)
		goto out_unlock;
	ret = pkm_lcs_source_next_sequence_snapshot(&walk.next_sequence);
	if (ret)
		goto out_unlock;
	ret = pkm_lcs_source_layer_snapshot_acquire(&walk.layers);
	if (ret)
		goto out_unlock;

	ret = pnp_for_each_child(&walk, network_guid, pnp_network_child_key_cb,
				 &c);
	if (ret)
		goto out;

	/* The rules: no key is no policy, and the previous generation
	 * stands, exactly as a walk that refused would leave it.
	 */
	if (c.rules_present)
		ret = pnp_refresh_rules(&walk, c.rules_guid);
	else
		pr_info_once("pnp: no Rules key; keeping the previous generation\n");

	/* The context, whatever the rules did: the two are independent. */
	context_ret = pnp_refresh_context(&walk, c.interfaces_present,
					  c.interfaces_guid,
					  c.networks_present, c.networks_guid);
	if (!ret)
		ret = context_ret;
out:
	pkm_lcs_source_layer_snapshot_release(&walk.layers);
out_unlock:
	mutex_unlock(&pnp_refresh_lock);
	peios_pnp_policy_note_ingest(ret);
	return ret;
}

/* --- change-notification coalescing ---------------------------------- */

/* Quiet time after the last change before the re-walk runs. */
#define PEIOS_PNP_REFRESH_DEBOUNCE_MS	50

static void peios_pnp_refresh_workfn(struct work_struct *work);

static struct {
	spinlock_t lock;
	bool pending;
	u32 source_id;
	u8 guid[16];
	struct delayed_work work;
} peios_pnp_refresh = {
	.lock = __SPIN_LOCK_UNLOCKED(peios_pnp_refresh.lock),
	.work = __DELAYED_WORK_INITIALIZER(peios_pnp_refresh.work,
					   peios_pnp_refresh_workfn, 0),
};

static void peios_pnp_refresh_workfn(struct work_struct *work)
{
	u32 source_id;
	u8 guid[16];

	spin_lock(&peios_pnp_refresh.lock);
	if (!peios_pnp_refresh.pending) {
		spin_unlock(&peios_pnp_refresh.lock);
		return;
	}
	peios_pnp_refresh.pending = false;
	source_id = peios_pnp_refresh.source_id;
	memcpy(guid, peios_pnp_refresh.guid, 16);
	spin_unlock(&peios_pnp_refresh.lock);

	/* Failure keeps the previous generation; the walk logged why. */
	peios_pnp_network_refresh_from_key(source_id, guid);
}

void peios_pnp_network_registry_changed(u32 source_id,
					const u8 network_guid[16])
{
	if (!source_id || !network_guid)
		return;

	spin_lock(&peios_pnp_refresh.lock);
	peios_pnp_refresh.source_id = source_id;
	memcpy(peios_pnp_refresh.guid, network_guid, 16);
	peios_pnp_refresh.pending = true;
	spin_unlock(&peios_pnp_refresh.lock);
	/* mod_delayed_work restarts the window: a burst of changes yields
	 * one re-walk, after the burst goes quiet.
	 */
	mod_delayed_work(system_wq, &peios_pnp_refresh.work,
			 msecs_to_jiffies(PEIOS_PNP_REFRESH_DEBOUNCE_MS));
}
