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

#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "pnp.h"

struct peios_pnp_policy {
	struct rcu_head rcu;
	void *forests[2];		/* indexed by enum peios_pnp_layer */
	u64 generation;
};

static struct peios_pnp_policy __rcu *peios_pnp_active;
static DEFINE_MUTEX(peios_pnp_publish_lock);

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
