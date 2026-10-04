// SPDX-License-Identifier: GPL-2.0-only
/*
 * Policy publication and lookup.
 *
 * The active policy is an RCU-published pair of opaque Rust forests (one
 * per layer) plus the generation's CurrentReportingLevel. The split of
 * responsibilities is deliberate: C owns the kernel concurrency primitive
 * (RCU — hook-path readers never block, writers swap whole generations
 * atomically, the I4 property), Rust owns everything the forests mean.
 * Old forests are freed after grace via the ntfe_rust_forest_free
 * destructor.
 *
 * Publication is process-context and serialized by a mutex. Before the
 * swap, the forests are checked together (tag/stream identities distinct
 * across both, every counter view has a writer) and the counter store is
 * materialized for their views — so a refused generation leaves both the
 * policy and the store as they were.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include <pkm/ntfe.h>

#include "ntfe.h"

struct peios_ntfe_policy {
	struct rcu_head rcu;
	void *forests[PEIOS_NTFE_LAYER_COUNT];	/* by enum peios_ntfe_layer */
	u64 generation;
	u8 reporting_level;
};

static struct peios_ntfe_policy __rcu *peios_ntfe_active;
static DEFINE_MUTEX(peios_ntfe_publish_lock);
static atomic64_t peios_ntfe_last_ingest_error;
static atomic64_t peios_ntfe_last_ingest_t_ns;

static void peios_ntfe_policy_reclaim(struct rcu_head *head)
{
	struct peios_ntfe_policy *policy =
		container_of(head, struct peios_ntfe_policy, rcu);

	int i;

	for (i = 0; i < PEIOS_NTFE_LAYER_COUNT; i++)
		ntfe_rust_forest_free(policy->forests[i]);
	kfree(policy);
}

/* Collects every forest's views and materializes the counter store. */
static int peios_ntfe_materialize_views(void *const forests[])
{
	struct peios_ntfe_view *views;
	u32 total = 0, n = 0, i, j;
	int ret;

	for (i = 0; i < PEIOS_NTFE_LAYER_COUNT; i++)
		total += ntfe_rust_forest_view_count(forests[i]);
	views = kcalloc(max_t(u32, total, 1), sizeof(*views), GFP_KERNEL);
	if (!views)
		return -ENOMEM;
	for (i = 0; i < PEIOS_NTFE_LAYER_COUNT; i++) {
		u32 count = ntfe_rust_forest_view_count(forests[i]);

		for (j = 0; j < count && n < total; j++) {
			ret = ntfe_rust_forest_view(forests[i], j, &views[n]);
			if (ret)
				goto out;
			n++;
		}
	}
	ret = peios_ntfe_counters_publish(views, n);
out:
	kfree(views);
	return ret;
}

int peios_ntfe_policy_publish(void *packet_forest, void *raw_forest,
			     void *flow_forest, u8 reporting_level)
{
	struct peios_ntfe_policy *fresh, *old;
	int ret;

	ret = ntfe_rust_forests_check(packet_forest, raw_forest, flow_forest);
	if (ret)
		return ret;

	fresh = kzalloc(sizeof(*fresh), GFP_KERNEL);
	if (!fresh)
		return -ENOMEM;
	fresh->forests[PEIOS_NTFE_LAYER_PACKET] = packet_forest;
	fresh->forests[PEIOS_NTFE_LAYER_RAWPACKET] = raw_forest;
	fresh->forests[PEIOS_NTFE_LAYER_FLOW] = flow_forest;
	fresh->reporting_level = reporting_level;

	mutex_lock(&peios_ntfe_publish_lock);
	ret = peios_ntfe_materialize_views(fresh->forests);
	if (ret) {
		mutex_unlock(&peios_ntfe_publish_lock);
		kfree(fresh);
		return ret;
	}
	fresh->generation = ntfe_rust_generation_advance();
	old = rcu_dereference_protected(
		peios_ntfe_active,
		lockdep_is_held(&peios_ntfe_publish_lock));
	rcu_assign_pointer(peios_ntfe_active, fresh);
	mutex_unlock(&peios_ntfe_publish_lock);

	pr_info("ntfe: policy generation %llu active (packet:%s rawpacket:%s flow:%s reporting-level:%u)\n",
		fresh->generation, packet_forest ? "loaded" : "none",
		raw_forest ? "loaded" : "none", flow_forest ? "loaded" : "none",
		reporting_level);

	if (old)
		call_rcu(&old->rcu, peios_ntfe_policy_reclaim);
	return 0;
}

int peios_ntfe_policy_eval(u8 layer, const struct peios_ntfe_snapshot *snap,
			  struct peios_ntfe_outcome *out)
{
	struct peios_ntfe_policy *policy;
	void *forest;
	u8 level;
	int ret;

	if (layer >= PEIOS_NTFE_LAYER_COUNT)
		return -EINVAL;

	rcu_read_lock();
	policy = rcu_dereference(peios_ntfe_active);
	forest = policy ? policy->forests[layer] : NULL;
	if (!forest) {
		rcu_read_unlock();
		return -ENOENT;
	}
	level = policy->reporting_level;
	if (peios_ntfe_kunit_eval_should_fail()) {
		rcu_read_unlock();
		return -ENOMEM;
	}
	/* Bounded, non-sleeping work: pnp-core allocates GFP_ATOMIC, and
	 * the stores it calls back into are softirq-safe.
	 */
	ret = ntfe_rust_evaluate(forest, snap, layer, level, out);
	rcu_read_unlock();
	return ret;
}

bool peios_ntfe_policy_enforcing(void)
{
	struct peios_ntfe_policy *policy;
	bool enforcing;

	rcu_read_lock();
	policy = rcu_dereference(peios_ntfe_active);
	enforcing = policy &&
		    (policy->forests[PEIOS_NTFE_LAYER_PACKET] ||
		     policy->forests[PEIOS_NTFE_LAYER_RAWPACKET] ||
		     policy->forests[PEIOS_NTFE_LAYER_FLOW]);
	rcu_read_unlock();
	return enforcing;
}

bool peios_ntfe_policy_has_layer(u8 layer)
{
	struct peios_ntfe_policy *policy;
	bool present;

	if (layer >= PEIOS_NTFE_LAYER_COUNT)
		return false;
	rcu_read_lock();
	policy = rcu_dereference(peios_ntfe_active);
	present = policy && policy->forests[layer];
	rcu_read_unlock();
	return present;
}

u8 peios_ntfe_policy_reporting_level(void)
{
	struct peios_ntfe_policy *policy;
	u8 level = 1;

	rcu_read_lock();
	policy = rcu_dereference(peios_ntfe_active);
	if (policy)
		level = policy->reporting_level;
	rcu_read_unlock();
	return level;
}

void peios_ntfe_policy_note_ingest(long err)
{
	atomic64_set(&peios_ntfe_last_ingest_error, err < 0 ? -err : err);
	atomic64_set(&peios_ntfe_last_ingest_t_ns, ktime_get_real_ns());
}

void peios_ntfe_status_fill(struct peios_ntfe_status *status)
{
	memset(status, 0, sizeof(*status));
	status->abi = PEIOS_NTFE_ABI_VERSION;
	status->generation = ntfe_rust_generation();
	status->enforcing = peios_ntfe_policy_enforcing();
	status->events_dropped = peios_ntfe_events_dropped();
	status->seen_ingress = atomic64_read(&peios_ntfe_stats.seen_ingress);
	status->seen_egress = atomic64_read(&peios_ntfe_stats.seen_egress);
	status->seen_local_in = atomic64_read(&peios_ntfe_stats.seen_local_in);
	status->deferred = atomic64_read(&peios_ntfe_stats.deferred);
	status->fallback_judged =
		atomic64_read(&peios_ntfe_stats.fallback_judged);
	status->parse_errors = atomic64_read(&peios_ntfe_stats.parse_errors);
	status->judged = atomic64_read(&peios_ntfe_stats.judged);
	status->permissive = atomic64_read(&peios_ntfe_stats.permissive);
	status->fail_closed = atomic64_read(&peios_ntfe_stats.fail_closed);
	status->verdict_pass = atomic64_read(&peios_ntfe_stats.verdict_pass);
	status->verdict_drop = atomic64_read(&peios_ntfe_stats.verdict_drop);
	status->verdict_reject =
		atomic64_read(&peios_ntfe_stats.verdict_reject);
	status->reject_degraded =
		atomic64_read(&peios_ntfe_stats.reject_degraded);
	status->fx_tags = atomic64_read(&peios_ntfe_stats.fx_tags);
	status->fx_counts = atomic64_read(&peios_ntfe_stats.fx_counts);
	status->fx_reports = atomic64_read(&peios_ntfe_stats.fx_reports);
	status->fx_prompts = atomic64_read(&peios_ntfe_stats.fx_prompts);
	status->last_ingest_error =
		atomic64_read(&peios_ntfe_last_ingest_error);
	status->last_ingest_t_ns =
		atomic64_read(&peios_ntfe_last_ingest_t_ns);
	status->tag_writes = atomic64_read(&peios_ntfe_stats.tag_writes);
	status->tag_untracked = atomic64_read(&peios_ntfe_stats.tag_untracked);
	status->tag_refused = atomic64_read(&peios_ntfe_stats.tag_refused);
	status->count_writes = atomic64_read(&peios_ntfe_stats.count_writes);
	status->count_key_absent =
		atomic64_read(&peios_ntfe_stats.count_key_absent);
	status->count_refused = atomic64_read(&peios_ntfe_stats.count_refused);
	status->reports_emitted =
		atomic64_read(&peios_ntfe_stats.reports_emitted);
	status->counter_cells = peios_ntfe_counters_cells();
	status->reporting_level = peios_ntfe_policy_reporting_level();
	status->seen_local_out = atomic64_read(&peios_ntfe_stats.seen_local_out);
	status->flow_judged = atomic64_read(&peios_ntfe_stats.flow_judged);
	status->flow_cached = atomic64_read(&peios_ntfe_stats.flow_cached);
	status->flow_rejudged = atomic64_read(&peios_ntfe_stats.flow_rejudged);
	status->flow_expired = atomic64_read(&peios_ntfe_stats.flow_expired);
	status->flow_uncached = atomic64_read(&peios_ntfe_stats.flow_uncached);
	status->refusals_emitted =
		atomic64_read(&peios_ntfe_stats.refusals_emitted);
	status->refusals_bypassed =
		atomic64_read(&peios_ntfe_stats.refusals_bypassed);
	status->teardowns_emitted =
		atomic64_read(&peios_ntfe_stats.teardowns_emitted);
	status->identity_unresolved =
		atomic64_read(&peios_ntfe_stats.identity_unresolved);
	peios_ntfe_ingest_progress(&status->changes_noted,
				   &status->changes_walked);
	status->contexts = peios_ntfe_context_count();
}
