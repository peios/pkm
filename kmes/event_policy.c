// SPDX-License-Identifier: GPL-2.0-only
/*
 * The kernel's emission policy (PGSS §6.9).
 *
 * Machine\Generic\Events holds one key per event-type segment, any of which
 * may carry an Enabled REG_DWORD of 0 or 1; the deepest one on a type's path
 * decides, and the type's tier decides where none does. Essential types
 * never consult it.
 *
 * The kernel reads the tree the way it reads its other configuration keys
 * (kmes.c, kacs/port_reservations.c): discovery from the Machine hive root
 * at bootstrap, an LCS internal watch afterwards. Rather than resolve each
 * type on every emit, one walk resolves every kernel type at once and
 * publishes the answers as a u64 with a bit per type:
 *
 *  - the walk descends the trie of the kernel types' segments
 *    (event_types.h), so it looks only at keys some kernel type's path
 *    passes through: one RSI lookup and one RSI_QUERY_VALUES per key that
 *    exists, and nothing beneath a key that does not;
 *  - a missing key, a link, or a key that may not be read ends that branch
 *    as §6.9 says, and the deepest Enabled above it decides;
 *  - any other failure (the source timing out, a malformed response) fails
 *    the walk, the old mask stays, and kmes.config.refresh.failed says so.
 *
 * Changes arrive per key from the LCS internal watch, already filtered to
 * the Events key and the five kernel roots beneath it and to the Enabled
 * value (lcs/key_fd.c). They are coalesced into one re-walk that starts
 * PKM_KMES_EVENT_POLICY_DEBOUNCE_MS after the first change of a burst: the
 * window is not extended by later changes, so a change applies within
 * about 50 ms plus one walk, however busy the tree is.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

#include "../lcs/rsi.h"
#include "../lcs/source_device.h"
#include "kmes.h"

#define PKM_KMES_EVENT_TYPES_WANT_TABLES
#include "event_policy.h"

/* Quiet time after the first change of a burst before the re-walk runs. */
#define PKM_KMES_EVENT_POLICY_DEBOUNCE_MS	50

static const char pkm_kmes_event_policy_enabled_name[] = "Enabled";

u64 pkm_kmes_event_enabled_mask __read_mostly = PKM_KMES_EV_DEFAULT_MASK;

/* One refresh at a time: the bootstrap and the deferred re-walk may meet. */
static DEFINE_MUTEX(pkm_kmes_event_policy_lock);

bool pkm_kmes_event_enabled_ffi(u32 id)
{
	if (id >= PKM_KMES_EV_COUNT)
		return true;
	if (pkm_kmes_event_tier((enum pkm_kmes_event_id)id) ==
	    PKM_KMES_EV_TIER_ESSENTIAL)
		return true;
	return READ_ONCE(pkm_kmes_event_enabled_mask) & BIT_ULL(id);
}

u64 pkm_kmes_event_policy_mask(void)
{
	return READ_ONCE(pkm_kmes_event_enabled_mask);
}

static void pkm_kmes_event_policy_publish(u64 mask)
{
	WRITE_ONCE(pkm_kmes_event_enabled_mask, mask);
}

s8 pkm_kmes_event_policy_read_enabled(u32 type, const u8 *data, u32 len,
				      s8 current_setting)
{
	u32 value;

	if (type != REG_DWORD || len != sizeof(u32) || !data)
		return current_setting;
	value = get_unaligned_le32(data);
	if (value == 0)
		return PKM_KMES_EVENT_SETTING_OFF;
	if (value == 1)
		return PKM_KMES_EVENT_SETTING_ON;
	return current_setting;
}

u64 pkm_kmes_event_policy_resolve(
	s8 root_setting,
	const struct pkm_kmes_event_policy_node_state *nodes, u32 node_count)
{
	s8 effective[PKM_KMES_EV_NODE_COUNT];
	bool present[PKM_KMES_EV_NODE_COUNT];
	u64 mask = 0;
	u32 i;

	if (!nodes || node_count != PKM_KMES_EV_NODE_COUNT)
		return PKM_KMES_EV_DEFAULT_MASK;
	if (root_setting != PKM_KMES_EVENT_SETTING_OFF &&
	    root_setting != PKM_KMES_EVENT_SETTING_ON)
		root_setting = PKM_KMES_EVENT_SETTING_ABSENT;

	/*
	 * Pre-order: a node's parent is resolved before it. A node inherits
	 * what was decided above it, and its own Enabled replaces that only
	 * where its key exists -- which it cannot where its parent's does not.
	 */
	for (i = 0; i < PKM_KMES_EV_NODE_COUNT; i++) {
		s16 parent = pkm_kmes_event_nodes[i].parent;
		s8 inherited = parent < 0 ? root_setting : effective[parent];
		bool parent_present = parent < 0 || present[parent];
		s8 own = nodes[i].setting;

		present[i] = parent_present && nodes[i].present;
		effective[i] = inherited;
		if (present[i] && (own == PKM_KMES_EVENT_SETTING_OFF ||
				   own == PKM_KMES_EVENT_SETTING_ON))
			effective[i] = own;
	}

	for (i = 0; i < PKM_KMES_EV_COUNT; i++) {
		enum pkm_kmes_event_tier tier =
			pkm_kmes_event_tier((enum pkm_kmes_event_id)i);
		s8 setting = effective[pkm_kmes_event_leaf[i]];
		bool on;

		if (tier == PKM_KMES_EV_TIER_ESSENTIAL)
			on = true;
		else if (setting == PKM_KMES_EVENT_SETTING_ABSENT)
			on = tier == PKM_KMES_EV_TIER_STANDARD;
		else
			on = setting == PKM_KMES_EVENT_SETTING_ON;
		if (on)
			mask |= BIT_ULL(i);
	}
	return mask;
}

static bool pkm_kmes_event_policy_ascii_equal(const char *a, u32 a_len,
					      const char *b, u32 b_len)
{
	return a_len == b_len && !strncasecmp(a, b, a_len);
}

static bool pkm_kmes_event_policy_is_ascii(const char *s, u32 len)
{
	u32 i;

	for (i = 0; i < len; i++) {
		if ((u8)s[i] >= 0x80)
			return false;
	}
	return true;
}

bool pkm_kmes_event_policy_root_relevant(const char *name, u32 name_len)
{
	u32 i;

	if (!name || !name_len)
		return true;
	if (!pkm_kmes_event_policy_is_ascii(name, name_len))
		return true;
	for (i = 0; i < PKM_KMES_EV_ROOT_COUNT; i++) {
		const char *root = pkm_kmes_event_roots[i];

		if (pkm_kmes_event_policy_ascii_equal(name, name_len, root,
						      strlen(root)))
			return true;
	}
	return false;
}

bool pkm_kmes_event_policy_value_relevant(const u8 *name, u32 name_len)
{
	if (!name || !name_len)
		return true;
	/*
	 * "Enabled" has no letter that folds from outside ASCII, so a name
	 * that is not ASCII is not it.
	 */
	return pkm_kmes_event_policy_ascii_equal(
		(const char *)name, name_len,
		pkm_kmes_event_policy_enabled_name,
		sizeof(pkm_kmes_event_policy_enabled_name) - 1);
}

/* --- the registry walk ------------------------------------------------- */

struct pkm_kmes_event_policy_walk {
	u32 source_id;
	u64 next_sequence;
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_layer_snapshot layers;
};

/*
 * §6.9: a key that does not exist, or that may not be read, ends the walk
 * down that path. A link is not followed -- nothing in the policy tree is
 * meant to be one -- and ends it the same way. Anything else is a failure
 * of the walk as a whole.
 */
static bool pkm_kmes_event_policy_ends_branch(long ret)
{
	return ret == -ENOENT || ret == -EOPNOTSUPP || ret == -EACCES ||
	       ret == -EPERM;
}

/* One RSI_QUERY_VALUES round trip: the setting @guid's Enabled gives. */
static long pkm_kmes_event_policy_query_enabled(
	struct pkm_kmes_event_policy_walk *walk, const u8 guid[16],
	s8 *setting_out)
{
	struct pkm_lcs_rsi_query_values_batch_result batch = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	u8 *records = NULL;
	size_t off = 0;
	u32 i;
	long ret;

	*setting_out = PKM_KMES_EVENT_SETTING_ABSENT;
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
	if (ret || !batch.count)
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

	/*
	 * Record layout: u32 name_len | name | u32 type | u32 data_len | data,
	 * little-endian (the REG_IOC_QUERY_VALUES_BATCH wire shape).
	 */
	for (i = 0; i < batch.count; i++) {
		u32 name_len, type, data_len;
		size_t remaining;
		const char *name;
		const u8 *data;

		if (off > batch.written_len) {
			ret = -EIO;
			goto out;
		}
		remaining = batch.written_len - off;
		if (remaining < 12) {
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

		/* Value names compare ignoring case, as the registry does. */
		if (pkm_kmes_event_policy_ascii_equal(
			    name, name_len, pkm_kmes_event_policy_enabled_name,
			    sizeof(pkm_kmes_event_policy_enabled_name) - 1))
			*setting_out = pkm_kmes_event_policy_read_enabled(
				type, data, data_len, *setting_out);
	}
out:
	kvfree(records);
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

/* One RSI lookup: the guid of @parent_guid's child @segment. */
static long pkm_kmes_event_policy_lookup_child(
	struct pkm_kmes_event_policy_walk *walk, const u8 parent_guid[16],
	const char *parent_name, const char *segment, u32 segment_len,
	u8 child_guid_out[16])
{
	/*
	 * A two-component walk rooted at the parent: the first component
	 * names the root itself and is not round-tripped, the second is one
	 * lookup, materialized against the layer snapshot like any open.
	 */
	const struct pkm_lcs_path_component_view path[] = {
		{ .name = parent_name, .name_len = (u32)strlen(parent_name) },
		{ .name = segment, .name_len = segment_len },
	};
	struct pkm_lcs_resolved_key_path key = { };
	long ret;

	ret = pkm_lcs_walk_absolute_components(
		walk->source_id, 0, parent_guid, path, ARRAY_SIZE(path),
		walk->layers.layers, walk->layers.layer_count, NULL, 0, &key);
	if (ret)
		return ret;
	memcpy(child_guid_out, key.key_guid, 16);
	pkm_lcs_resolved_key_path_destroy(&key);
	return 0;
}

struct pkm_kmes_event_policy_state {
	struct pkm_kmes_event_policy_node_state nodes[PKM_KMES_EV_NODE_COUNT];
	u8 guids[PKM_KMES_EV_NODE_COUNT][16];
};

/* Walk the trie under @events_guid; on success *mask_out is the answer. */
static long pkm_kmes_event_policy_walk_tree(
	struct pkm_kmes_event_policy_walk *walk, const u8 events_guid[16],
	struct pkm_kmes_event_policy_state *state, u64 *mask_out)
{
	s8 root_setting = PKM_KMES_EVENT_SETTING_ABSENT;
	u32 i;
	long ret;

	ret = pkm_kmes_event_policy_query_enabled(walk, events_guid,
						  &root_setting);
	if (ret) {
		if (!pkm_kmes_event_policy_ends_branch(ret))
			return ret;
		/* No Events key (deleted since it was watched): tier decides. */
		*mask_out = PKM_KMES_EV_DEFAULT_MASK;
		return 0;
	}

	for (i = 0; i < PKM_KMES_EV_NODE_COUNT; i++) {
		const struct pkm_kmes_event_node *node =
			&pkm_kmes_event_nodes[i];
		const u8 *parent_guid;
		const char *parent_name;

		state->nodes[i].present = false;
		state->nodes[i].setting = PKM_KMES_EVENT_SETTING_ABSENT;
		if (node->parent >= 0 && !state->nodes[node->parent].present)
			continue;
		if (node->parent < 0) {
			parent_guid = events_guid;
			parent_name = "Events";
		} else {
			parent_guid = state->guids[node->parent];
			parent_name = pkm_kmes_event_nodes[node->parent].segment;
		}

		ret = pkm_kmes_event_policy_lookup_child(
			walk, parent_guid, parent_name, node->segment,
			node->segment_len, state->guids[i]);
		if (ret) {
			if (!pkm_kmes_event_policy_ends_branch(ret))
				return ret;
			continue;
		}
		ret = pkm_kmes_event_policy_query_enabled(
			walk, state->guids[i], &state->nodes[i].setting);
		if (ret) {
			if (!pkm_kmes_event_policy_ends_branch(ret))
				return ret;
			state->nodes[i].setting = PKM_KMES_EVENT_SETTING_ABSENT;
			continue;
		}
		state->nodes[i].present = true;
	}

	*mask_out = pkm_kmes_event_policy_resolve(root_setting, state->nodes,
						  PKM_KMES_EV_NODE_COUNT);
	return 0;
}

long pkm_kmes_event_policy_refresh_from_key(u32 source_id,
					    const u8 events_guid[16])
{
	struct pkm_kmes_event_policy_walk *walk;
	struct pkm_kmes_event_policy_state *state = NULL;
	u64 mask = 0;
	long ret;

	if (!source_id || !events_guid)
		return -EINVAL;

	walk = kzalloc(sizeof(*walk), GFP_KERNEL);
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!walk || !state) {
		ret = -ENOMEM;
		goto out_free;
	}
	walk->source_id = source_id;

	mutex_lock(&pkm_kmes_event_policy_lock);
	ret = pkm_lcs_runtime_limits_snapshot(&walk->limits);
	if (ret)
		goto out_unlock;
	ret = pkm_lcs_source_next_sequence_snapshot(&walk->next_sequence);
	if (ret)
		goto out_unlock;
	ret = pkm_lcs_source_layer_snapshot_acquire(&walk->layers);
	if (ret)
		goto out_unlock;

	ret = pkm_kmes_event_policy_walk_tree(walk, events_guid, state, &mask);
	pkm_lcs_source_layer_snapshot_release(&walk->layers);
	if (!ret)
		pkm_kmes_event_policy_publish(mask);
out_unlock:
	mutex_unlock(&pkm_kmes_event_policy_lock);
out_free:
	if (ret) {
		/* Nothing was published: the mask in force stays. */
		pkm_kmes_emit_config_refresh_failed(
			PKM_KMES_EVENT_POLICY_KEY_PATH,
			sizeof(PKM_KMES_EVENT_POLICY_KEY_PATH) - 1, ret);
	}
	kfree(state);
	kfree(walk);
	return ret;
}

void pkm_kmes_event_policy_reset_to_tier_defaults(void)
{
	mutex_lock(&pkm_kmes_event_policy_lock);
	pkm_kmes_event_policy_publish(PKM_KMES_EV_DEFAULT_MASK);
	mutex_unlock(&pkm_kmes_event_policy_lock);
}

long pkm_kmes_event_policy_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[16], bool *present_out,
	u8 events_guid_out[16])
{
	/*
	 * Absolute path: the leading hive component ("Machine") is resolved
	 * locally against the hive root, not round-tripped.
	 */
	static const struct pkm_lcs_path_component_view events_path[] = {
		{ .name = "Machine", .name_len = sizeof("Machine") - 1 },
		{ .name = "Generic", .name_len = sizeof("Generic") - 1 },
		{ .name = "Events", .name_len = sizeof("Events") - 1 },
	};
	struct pkm_lcs_resolved_key_path key = { };
	struct pkm_lcs_layer_snapshot layers = { };
	long ret;

	if (present_out)
		*present_out = false;
	if (events_guid_out)
		memset(events_guid_out, 0, 16);
	if (!source_id || !machine_root_guid || !present_out ||
	    !events_guid_out)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components(
		source_id, 0, machine_root_guid, events_path,
		ARRAY_SIZE(events_path), layers.layers, layers.layer_count,
		NULL, 0, &key);
	if (ret == -ENOENT) {
		/* No policy key: the tier decides, and the fallback watches. */
		ret = 0;
		goto out;
	}
	if (ret)
		goto out;

	memcpy(events_guid_out, key.key_guid, 16);
	*present_out = true;
	pkm_lcs_resolved_key_path_destroy(&key);
out:
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

/* --- change-notification coalescing ------------------------------------ */

static void pkm_kmes_event_policy_refresh_workfn(struct work_struct *work);

/* Changes the watch passed on, for tests: each one schedules a re-walk. */
static atomic64_t pkm_kmes_event_policy_changes_noted = ATOMIC64_INIT(0);

static struct {
	spinlock_t lock;
	bool pending;
	u32 source_id;
	u8 guid[16];
	struct delayed_work work;
} pkm_kmes_event_policy_refresh = {
	.lock = __SPIN_LOCK_UNLOCKED(pkm_kmes_event_policy_refresh.lock),
	.work = __DELAYED_WORK_INITIALIZER(pkm_kmes_event_policy_refresh.work,
					   pkm_kmes_event_policy_refresh_workfn,
					   0),
};

static void pkm_kmes_event_policy_refresh_workfn(struct work_struct *work)
{
	u32 source_id;
	u8 guid[16];

	spin_lock(&pkm_kmes_event_policy_refresh.lock);
	if (!pkm_kmes_event_policy_refresh.pending) {
		spin_unlock(&pkm_kmes_event_policy_refresh.lock);
		return;
	}
	pkm_kmes_event_policy_refresh.pending = false;
	source_id = pkm_kmes_event_policy_refresh.source_id;
	memcpy(guid, pkm_kmes_event_policy_refresh.guid, 16);
	spin_unlock(&pkm_kmes_event_policy_refresh.lock);

	/* A failed walk keeps the old mask and has said so. */
	pkm_kmes_event_policy_refresh_from_key(source_id, guid);
}

void pkm_kmes_event_policy_registry_changed(u32 source_id,
					    const u8 events_guid[16])
{
	if (!source_id || !events_guid)
		return;

	spin_lock(&pkm_kmes_event_policy_refresh.lock);
	pkm_kmes_event_policy_refresh.source_id = source_id;
	memcpy(pkm_kmes_event_policy_refresh.guid, events_guid, 16);
	pkm_kmes_event_policy_refresh.pending = true;
	atomic64_inc(&pkm_kmes_event_policy_changes_noted);
	spin_unlock(&pkm_kmes_event_policy_refresh.lock);
	/*
	 * queue_delayed_work(), not mod_delayed_work(): a work item already
	 * waiting keeps its deadline, so the window opens at the first change
	 * of a burst and a steady stream of writes cannot postpone the walk.
	 * A change that lands while a walk is running queues the next one.
	 */
	queue_delayed_work(system_wq, &pkm_kmes_event_policy_refresh.work,
			   msecs_to_jiffies(PKM_KMES_EVENT_POLICY_DEBOUNCE_MS));
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_kmes_event_policy_kunit_reset(void)
{
	cancel_delayed_work_sync(&pkm_kmes_event_policy_refresh.work);
	spin_lock(&pkm_kmes_event_policy_refresh.lock);
	pkm_kmes_event_policy_refresh.pending = false;
	spin_unlock(&pkm_kmes_event_policy_refresh.lock);
	pkm_kmes_event_policy_reset_to_tier_defaults();
}

void pkm_kmes_event_policy_kunit_publish(u64 mask)
{
	mutex_lock(&pkm_kmes_event_policy_lock);
	pkm_kmes_event_policy_publish(mask);
	mutex_unlock(&pkm_kmes_event_policy_lock);
}

void pkm_kmes_event_policy_kunit_flush(void)
{
	flush_delayed_work(&pkm_kmes_event_policy_refresh.work);
}

u64 pkm_kmes_event_policy_kunit_changes_noted(void)
{
	return (u64)atomic64_read(&pkm_kmes_event_policy_changes_noted);
}
#endif
