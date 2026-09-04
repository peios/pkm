// SPDX-License-Identifier: GPL-2.0-only
/*
 * The network context: which network each interface is standing on.
 *
 * netd identifies the network on a link and writes it back to the
 * registry — `Network` on the interface's Status key, and the record it
 * names under `Networks\<id>`, where the operator's `Name` and `Trust`
 * live. The kernel reads that inventory at ingestion (ingest.c walks it
 * beside the rules) into one fixed-size table keyed by kernel interface
 * name, published here under RCU, and the snapshot builder copies the
 * matching entry into every traversal's `Network.*` facts. So the
 * packet layers judge by network with the same three facts the interface
 * layer conditions on, and the same record behind them.
 *
 * A change of context is a change of policy to every flow on that
 * interface: publishing a table that differs from the active one
 * advances the policy generation, and the Flow layer's lazy re-judgment
 * (flow.c) does the rest on each flow's next packet. Publishing an
 * identical table is a no-op — netd rewrites Status often, and a
 * generation that changes nothing would only churn the sentences.
 *
 * The table is not policy. It has no validation to fail: a record the
 * walk could not read leaves that interface without a context, which the
 * absent-fact law turns into "no rule about a network matches here".
 */

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "pnp.h"

static struct peios_pnp_context_table __rcu *peios_pnp_context_active;
static DEFINE_MUTEX(peios_pnp_context_lock);

struct peios_pnp_context_table *peios_pnp_context_table_alloc(u32 count)
{
	struct peios_pnp_context_table *table;

	if (count > PEIOS_PNP_MAX_CONTEXTS)
		return NULL;
	table = kzalloc(struct_size(table, entries, count), GFP_KERNEL);
	if (table)
		table->count = count;
	return table;
}

static bool context_table_equal(const struct peios_pnp_context_table *a,
				const struct peios_pnp_context_table *b)
{
	u32 na = a ? a->count : 0, nb = b ? b->count : 0;

	if (na != nb)
		return false;
	if (!na)
		return true;
	return !memcmp(a->entries, b->entries, sizeof(a->entries[0]) * na);
}

int peios_pnp_context_publish(struct peios_pnp_context_table *table)
{
	struct peios_pnp_context_table *old;
	u64 generation;

	if (table && table->count > PEIOS_PNP_MAX_CONTEXTS) {
		kfree(table);
		return -EINVAL;
	}

	mutex_lock(&peios_pnp_context_lock);
	old = rcu_dereference_protected(
		peios_pnp_context_active,
		lockdep_is_held(&peios_pnp_context_lock));
	if (context_table_equal(old, table)) {
		mutex_unlock(&peios_pnp_context_lock);
		kfree(table);
		return 0;
	}
	rcu_assign_pointer(peios_pnp_context_active, table);
	generation = pnp_rust_generation_advance();
	mutex_unlock(&peios_pnp_context_lock);

	pr_info("pnp: network context: %u interface%s; generation %llu\n",
		table ? table->count : 0,
		(table && table->count == 1) ? "" : "s", generation);

	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

void peios_pnp_context_fill(const char *ifname,
			    struct peios_pnp_snapshot *snap)
{
	const struct peios_pnp_context_table *table;
	u32 i;

	if (!ifname || !ifname[0])
		return;

	rcu_read_lock();
	table = rcu_dereference(peios_pnp_context_active);
	if (table) {
		for (i = 0; i < table->count; i++) {
			const struct peios_pnp_context_entry *e =
				&table->entries[i];

			if (strncmp(e->ifname, ifname, IFNAMSIZ))
				continue;
			memcpy(snap->network_id, e->network_id,
			       sizeof(snap->network_id));
			memcpy(snap->network_name, e->network_name,
			       sizeof(snap->network_name));
			memcpy(snap->network_trust, e->network_trust,
			       sizeof(snap->network_trust));
			snap->has |= PEIOS_PNP_HAS_NETWORK;
			break;
		}
	}
	rcu_read_unlock();
}

u32 peios_pnp_context_count(void)
{
	const struct peios_pnp_context_table *table;
	u32 count;

	rcu_read_lock();
	table = rcu_dereference(peios_pnp_context_active);
	count = table ? table->count : 0;
	rcu_read_unlock();
	return count;
}
