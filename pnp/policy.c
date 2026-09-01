// SPDX-License-Identifier: GPL-2.0-only
/*
 * Policy publication and lookup.
 *
 * The active policy is an RCU-published pair of opaque Rust forests (one
 * per layer). The split of responsibilities is deliberate: C owns the
 * kernel concurrency primitive (RCU — hook-path readers never block,
 * writers swap whole generations atomically, the I4 property), Rust owns
 * everything the forests mean. Old forests are freed after grace via the
 * pnp_rust_forest_free destructor.
 *
 * Publication is process-context and serialized by a mutex; the only
 * caller today is the KUnit end-to-end test, with the LCS registry
 * ingestion path to follow as the next slice.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include <pkm/pnp.h>

#include "pnp.h"

struct peios_pnp_policy {
	struct rcu_head rcu;
	void *forests[2];		/* indexed by enum peios_pnp_layer */
	u64 generation;
};

static struct peios_pnp_policy __rcu *peios_pnp_active;
static DEFINE_MUTEX(peios_pnp_publish_lock);
static atomic64_t peios_pnp_last_ingest_error;
static atomic64_t peios_pnp_last_ingest_t_ns;

static void peios_pnp_policy_reclaim(struct rcu_head *head)
{
	struct peios_pnp_policy *policy =
		container_of(head, struct peios_pnp_policy, rcu);

	pnp_rust_forest_free(policy->forests[PEIOS_PNP_LAYER_PACKET]);
	pnp_rust_forest_free(policy->forests[PEIOS_PNP_LAYER_RAWPACKET]);
	kfree(policy);
}

int peios_pnp_policy_publish(void *packet_forest, void *raw_forest)
{
	struct peios_pnp_policy *fresh, *old;

	fresh = kzalloc(sizeof(*fresh), GFP_KERNEL);
	if (!fresh)
		return -ENOMEM;
	fresh->forests[PEIOS_PNP_LAYER_PACKET] = packet_forest;
	fresh->forests[PEIOS_PNP_LAYER_RAWPACKET] = raw_forest;

	mutex_lock(&peios_pnp_publish_lock);
	fresh->generation = pnp_rust_generation_advance();
	old = rcu_dereference_protected(
		peios_pnp_active,
		lockdep_is_held(&peios_pnp_publish_lock));
	rcu_assign_pointer(peios_pnp_active, fresh);
	mutex_unlock(&peios_pnp_publish_lock);

	pr_info("pnp: policy generation %llu active (packet:%s rawpacket:%s)\n",
		fresh->generation, packet_forest ? "loaded" : "none",
		raw_forest ? "loaded" : "none");

	if (old)
		call_rcu(&old->rcu, peios_pnp_policy_reclaim);
	return 0;
}

int peios_pnp_policy_eval(u8 layer, const struct peios_pnp_snapshot *snap,
			  struct peios_pnp_outcome *out)
{
	struct peios_pnp_policy *policy;
	void *forest;
	int ret;

	if (layer > PEIOS_PNP_LAYER_RAWPACKET)
		return -EINVAL;

	rcu_read_lock();
	policy = rcu_dereference(peios_pnp_active);
	forest = policy ? policy->forests[layer] : NULL;
	if (!forest) {
		rcu_read_unlock();
		return -ENOENT;
	}
	/* Bounded, non-sleeping work: pnp-core allocates GFP_ATOMIC. */
	ret = pnp_rust_evaluate(forest, snap, out);
	rcu_read_unlock();
	return ret;
}

bool peios_pnp_policy_enforcing(void)
{
	struct peios_pnp_policy *policy;
	bool enforcing;

	rcu_read_lock();
	policy = rcu_dereference(peios_pnp_active);
	enforcing = policy &&
		    (policy->forests[PEIOS_PNP_LAYER_PACKET] ||
		     policy->forests[PEIOS_PNP_LAYER_RAWPACKET]);
	rcu_read_unlock();
	return enforcing;
}

void peios_pnp_policy_note_ingest(long err)
{
	atomic64_set(&peios_pnp_last_ingest_error, err < 0 ? -err : err);
	atomic64_set(&peios_pnp_last_ingest_t_ns, ktime_get_real_ns());
}

void peios_pnp_status_fill(struct peios_pnp_status *status)
{
	memset(status, 0, sizeof(*status));
	status->abi = PEIOS_PNP_ABI_VERSION;
	status->generation = pnp_rust_generation();
	status->enforcing = peios_pnp_policy_enforcing();
	status->events_dropped = peios_pnp_events_dropped();
	status->seen_ingress = atomic64_read(&peios_pnp_stats.seen_ingress);
	status->seen_egress = atomic64_read(&peios_pnp_stats.seen_egress);
	status->seen_local_in = atomic64_read(&peios_pnp_stats.seen_local_in);
	status->deferred = atomic64_read(&peios_pnp_stats.deferred);
	status->fallback_judged =
		atomic64_read(&peios_pnp_stats.fallback_judged);
	status->parse_errors = atomic64_read(&peios_pnp_stats.parse_errors);
	status->judged = atomic64_read(&peios_pnp_stats.judged);
	status->permissive = atomic64_read(&peios_pnp_stats.permissive);
	status->fail_closed = atomic64_read(&peios_pnp_stats.fail_closed);
	status->verdict_pass = atomic64_read(&peios_pnp_stats.verdict_pass);
	status->verdict_drop = atomic64_read(&peios_pnp_stats.verdict_drop);
	status->verdict_reject =
		atomic64_read(&peios_pnp_stats.verdict_reject);
	status->reject_degraded =
		atomic64_read(&peios_pnp_stats.reject_degraded);
	status->fx_tags = atomic64_read(&peios_pnp_stats.fx_tags);
	status->fx_counts = atomic64_read(&peios_pnp_stats.fx_counts);
	status->fx_reports = atomic64_read(&peios_pnp_stats.fx_reports);
	status->fx_prompts = atomic64_read(&peios_pnp_stats.fx_prompts);
	status->last_ingest_error =
		atomic64_read(&peios_pnp_last_ingest_error);
	status->last_ingest_t_ns =
		atomic64_read(&peios_pnp_last_ingest_t_ns);
}
