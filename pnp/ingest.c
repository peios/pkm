// SPDX-License-Identifier: GPL-2.0-only
/*
 * Registry ingestion: Machine\System\Network\Rules -> published policy.
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
 * Change notification arrives per-key and uncoalesced from the LCS
 * internal watch dispatcher, so the entry point coalesces into one
 * deferred re-walk (pending flag + workqueue), mirroring the bootstrap
 * workfn pattern.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
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
};

long peios_pnp_rules_root_discover_from_machine_hive(u32 source_id,
						     const u8 machine_root_guid[16],
						     bool *present_out,
						     u8 rules_guid_out[16])
{
	/* Absolute path: the leading hive component ("Machine") is resolved
	 * locally against the hive root, not round-tripped.
	 */
	static const struct pkm_lcs_path_component_view rules_path[] = {
		{ .name = "Machine", .name_len = sizeof("Machine") - 1 },
		{ .name = "System", .name_len = sizeof("System") - 1 },
		{ .name = "Network", .name_len = sizeof("Network") - 1 },
		{ .name = "Rules", .name_len = sizeof("Rules") - 1 },
	};
	struct pkm_lcs_resolved_key_path key = { };
	struct pkm_lcs_layer_snapshot layers = { };
	long ret;

	if (present_out)
		*present_out = false;
	if (!source_id || !machine_root_guid || !present_out ||
	    !rules_guid_out)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components(
		source_id, 0, machine_root_guid, rules_path,
		ARRAY_SIZE(rules_path), layers.layers, layers.layer_count,
		NULL, 0, &key);
	if (ret == -ENOENT) {
		/* Absence is not an error: no rules key, no policy. */
		ret = 0;
		goto out;
	}
	if (ret)
		goto out;

	memcpy(rules_guid_out, key.key_guid, 16);
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

/* One RSI_QUERY_VALUES round trip: this key's effective values -> builder. */
static long pnp_walk_values(struct peios_pnp_walk *walk, const u8 guid[16])
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

		ret = pnp_feed_value(walk, name, name_len, type, data,
				     data_len);
		if (ret)
			goto out;
	}
out:
	kvfree(records);
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
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

long peios_pnp_rules_refresh_from_key(u32 source_id, const u8 rules_guid[16])
{
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct peios_pnp_walk walk = { .source_id = source_id };
	u8 packet_guid[16], raw_guid[16];
	bool packet_present = false, raw_present = false;
	void *packet_forest = NULL, *raw_forest = NULL;
	u32 i;
	long ret;

	if (!source_id || !rules_guid)
		return -EINVAL;

	ret = pkm_lcs_runtime_limits_snapshot(&walk.limits);
	if (ret)
		return ret;
	ret = pkm_lcs_source_next_sequence_snapshot(&walk.next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&walk.layers);
	if (ret)
		return ret;

	/* Find the layer keys under Rules. */
	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		source_id, 0, rules_guid, &walk.limits,
		walk.limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out;
	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		frame.data, frame.len, response.request_id,
		walk.next_sequence, walk.layers.layers,
		walk.layers.layer_count, NULL, 0, &response.limits, &summary);
	if (ret)
		goto out;

	for (i = 0; i < summary.subkey_count; i++) {
		struct pkm_lcs_rsi_enum_subkey_result subkey = { };
		const u8 *name;

		ret = pkm_lcs_rsi_materialize_enum_subkey_response(
			frame.data, frame.len, response.request_id,
			walk.next_sequence, i, walk.layers.layers,
			walk.layers.layer_count, NULL, 0, &response.limits,
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
		name = frame.data + subkey.name_offset;
		if (subkey.name_len == 6 && !memcmp(name, "Packet", 6)) {
			memcpy(packet_guid, subkey.child_guid, 16);
			packet_present = true;
		} else if (subkey.name_len == 9 &&
			   !memcmp(name, "RawPacket", 9)) {
			memcpy(raw_guid, subkey.child_guid, 16);
			raw_present = true;
		}
		/* Unknown layer names are someone else's future: ignored. */
	}
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_response_frame_init(&frame);

	ret = pnp_build_layer(&walk, packet_present, packet_guid,
			      PEIOS_PNP_LAYER_PACKET, &packet_forest);
	if (ret)
		goto out;
	walk.rules_seen = 0;
	ret = pnp_build_layer(&walk, raw_present, raw_guid,
			      PEIOS_PNP_LAYER_RAWPACKET, &raw_forest);
	if (ret)
		goto out;

	ret = peios_pnp_policy_publish(packet_forest, raw_forest);
	if (!ret) {
		packet_forest = NULL;
		raw_forest = NULL;
	}
out:
	if (ret)
		pr_warn("pnp: rules refresh failed (%ld); keeping the previous generation\n",
			ret);
	pnp_rust_forest_free(packet_forest);
	pnp_rust_forest_free(raw_forest);
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&walk.layers);
	return ret;
}

/* --- change-notification coalescing ---------------------------------- */

static void peios_pnp_refresh_workfn(struct work_struct *work);

static struct {
	spinlock_t lock;
	bool pending;
	u32 source_id;
	u8 guid[16];
	struct work_struct work;
} peios_pnp_refresh = {
	.lock = __SPIN_LOCK_UNLOCKED(peios_pnp_refresh.lock),
	.work = __WORK_INITIALIZER(peios_pnp_refresh.work,
				   peios_pnp_refresh_workfn),
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
	peios_pnp_rules_refresh_from_key(source_id, guid);
}

void peios_pnp_rules_registry_changed(u32 source_id, const u8 rules_guid[16])
{
	if (!source_id || !rules_guid)
		return;

	spin_lock(&peios_pnp_refresh.lock);
	peios_pnp_refresh.source_id = source_id;
	memcpy(peios_pnp_refresh.guid, rules_guid, 16);
	peios_pnp_refresh.pending = true;
	spin_unlock(&peios_pnp_refresh.lock);
	schedule_work(&peios_pnp_refresh.work);
}
