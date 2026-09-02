// SPDX-License-Identifier: GPL-2.0-only
/*
 * The flow tag store (machinery slice, ratified PEI-598).
 *
 * TAG writes flow-scoped named unsigned integers. The store is a conntrack
 * extension of exactly one pointer, added to every flow at creation
 * (init_conntrack, via the pnp-conntrack-ext patch) and NULL until the
 * flow's first TAG — most flows are never tagged, and they pay eight
 * bytes. The first TAG allocates a small table of (name hash, value)
 * pairs; a full table is replaced by one twice the size (copy, RCU swap,
 * free after grace). Readers walk the table lock-free under RCU (hook
 * context already holds the read lock); writers serialize on the flow's
 * own lock. The ext destructor frees the table when the flow dies.
 *
 * Why not a bigger fixed extension: the conntrack ext *block* is immutable
 * once a flow is confirmed (post-confirm resize was removed upstream as an
 * RCU-reader race), so it can never grow — but an owned allocation behind
 * a pointer can, and it costs untagged flows nothing.
 *
 * Bounds, confessed in stats: a flow may carry at most
 * PEIOS_PNP_TAG_MAX_PER_FLOW distinct tags (a tripwire — the forest
 * defines only so many names), and an atomic allocation can fail.
 * Untracked packets have no flow: the write no-ops, counted.
 *
 * Tags survive policy generations by construction: the table knows only
 * hashes and values, never a generation.
 */

#include <linux/ktime.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <linux/peios_pnp.h>

#include <pkm/pnp.h>

#include "pnp.h"

struct peios_pnp_tag_entry {
	u64 hash;
	u64 value;
	u8 present;			/* 0 = cleared (tombstone, reusable) */
	u8 _pad[7];
};

struct peios_pnp_tag_table {
	struct rcu_head rcu;
	u32 cap;
	u32 len;			/* entries in use, tombstones included */
	struct peios_pnp_tag_entry e[];
};

#define PNP_TAG_INITIAL_CAP	8

static struct peios_pnp_ct *pnp_ct_of(const void *flow);

static struct peios_pnp_tag_table *pnp_tag_table_alloc(u32 cap)
{
	struct peios_pnp_tag_table *t;

	t = kzalloc(struct_size(t, e, cap), GFP_ATOMIC);
	if (t)
		t->cap = cap;
	return t;
}

void peios_pnp_ct_ext_add(struct nf_conn *ct)
{
	struct peios_pnp_ct *pc;

	pc = nf_ct_ext_add(ct, NF_CT_EXT_PNP, GFP_ATOMIC);
	if (pc) {
		memset(pc, 0, sizeof(*pc));
		RCU_INIT_POINTER(pc->tags, NULL);
		/* The flow's birth: the Start.* facts (flow.c reads it). */
		pc->start_secs = ktime_get_real_seconds();
	}
	/* No ext (allocation failed): the flow is untaggable and holds no
	 * sentence; TAG on it confesses as refused, the Flow layer judges
	 * it every packet (confessed). Conntrack itself carries on.
	 */
}

u32 peios_pnp_tags_snapshot(const struct nf_conn *ct, u64 *hashes,
			    u64 *values, u32 max)
{
	struct peios_pnp_ct *pc = pnp_ct_of(ct);
	struct peios_pnp_tag_table *t;
	u32 i, n = 0;

	if (!pc)
		return 0;
	rcu_read_lock();
	t = rcu_dereference(pc->tags);
	if (t) {
		for (i = 0; i < READ_ONCE(t->len); i++) {
			if (!READ_ONCE(t->e[i].present))
				continue;
			if (n < max) {
				hashes[n] = t->e[i].hash;
				values[n] = READ_ONCE(t->e[i].value);
			}
			n++;
		}
	}
	rcu_read_unlock();
	return n;
}

void peios_pnp_ct_destroy(struct nf_conn *ct)
{
	struct peios_pnp_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_PNP);
	struct peios_pnp_tag_table *t;

	if (!pc)
		return;
	/* The flow is dead (refcount 0), but a reader that found this ct
	 * under RCU may still be walking the table: free after grace.
	 */
	t = rcu_dereference_protected(pc->tags, true);
	if (t)
		kfree_rcu(t, rcu);
	RCU_INIT_POINTER(pc->tags, NULL);
}

static struct peios_pnp_ct *pnp_ct_of(const void *flow)
{
	struct nf_conn *ct = (struct nf_conn *)flow;

	if (!ct)
		return NULL;
	return nf_ct_ext_find(ct, NF_CT_EXT_PNP);
}

int peios_pnp_tag_lookup(const void *flow, u64 hash, u64 *value_out)
{
	struct peios_pnp_ct *pc = pnp_ct_of(flow);
	struct peios_pnp_tag_table *t;
	u32 i;

	if (!pc)
		return 0;
	t = rcu_dereference(pc->tags);
	if (!t)
		return 0;
	for (i = 0; i < READ_ONCE(t->len); i++) {
		if (t->e[i].hash == hash) {
			if (!READ_ONCE(t->e[i].present))
				return 0;
			*value_out = READ_ONCE(t->e[i].value);
			return 1;
		}
	}
	return 0;
}

/* Under the flow lock. Returns the entry for `hash`, allocating a slot
 * (or a bigger table) as needed; NULL when refused.
 */
static struct peios_pnp_tag_entry *
pnp_tag_slot(struct peios_pnp_ct *pc, u64 hash, bool create)
{
	struct peios_pnp_tag_table *t, *bigger;
	struct peios_pnp_tag_entry *tomb = NULL;
	u32 i;

	t = rcu_dereference_protected(pc->tags, true);
	if (t) {
		for (i = 0; i < t->len; i++) {
			if (t->e[i].hash == hash)
				return &t->e[i];
			if (!t->e[i].present && !tomb)
				tomb = &t->e[i];
		}
	}
	if (!create)
		return NULL;
	if (tomb) {
		tomb->hash = hash;
		return tomb;
	}
	if (!t) {
		t = pnp_tag_table_alloc(PNP_TAG_INITIAL_CAP);
		if (!t)
			return NULL;
		rcu_assign_pointer(pc->tags, t);
	} else if (t->len == t->cap) {
		if (t->cap >= PEIOS_PNP_TAG_MAX_PER_FLOW)
			return NULL;
		bigger = pnp_tag_table_alloc(min_t(u32, t->cap * 2,
						   PEIOS_PNP_TAG_MAX_PER_FLOW));
		if (!bigger)
			return NULL;
		memcpy(bigger->e, t->e, sizeof(t->e[0]) * t->len);
		bigger->len = t->len;
		rcu_assign_pointer(pc->tags, bigger);
		kfree_rcu(t, rcu);
		t = bigger;
	}
	t->e[t->len].hash = hash;
	t->e[t->len].value = 0;
	t->e[t->len].present = 0;
	/* Publish the entry's identity before the length that exposes it. */
	smp_wmb();
	WRITE_ONCE(t->len, t->len + 1);
	return &t->e[t->len - 1];
}

void peios_pnp_tag_apply(const void *flow, u64 hash, u8 op, u64 operand)
{
	struct nf_conn *ct = (struct nf_conn *)flow;
	struct peios_pnp_ct *pc = pnp_ct_of(flow);
	struct peios_pnp_tag_entry *e;

	if (!ct) {
		atomic64_inc(&peios_pnp_stats.tag_untracked);
		return;
	}
	if (!pc) {
		atomic64_inc(&peios_pnp_stats.tag_refused);
		return;
	}

	spin_lock_bh(&ct->lock);
	e = pnp_tag_slot(pc, hash, op != PEIOS_PNP_TAG_CLEAR);
	if (!e) {
		spin_unlock_bh(&ct->lock);
		if (op == PEIOS_PNP_TAG_CLEAR) {
			/* Clearing an absent tag is a no-op, not a refusal. */
			atomic64_inc(&peios_pnp_stats.tag_writes);
			return;
		}
		atomic64_inc(&peios_pnp_stats.tag_refused);
		return;
	}
	switch (op) {
	case PEIOS_PNP_TAG_SET:
		WRITE_ONCE(e->value, operand);
		WRITE_ONCE(e->present, 1);
		break;
	case PEIOS_PNP_TAG_ADD: {
		u64 cur = e->present ? e->value : 0;
		u64 sum = cur + operand;

		WRITE_ONCE(e->value, sum < cur ? U64_MAX : sum);
		WRITE_ONCE(e->present, 1);
		break;
	}
	case PEIOS_PNP_TAG_CLEAR:
	default:
		WRITE_ONCE(e->present, 0);
		break;
	}
	spin_unlock_bh(&ct->lock);
	atomic64_inc(&peios_pnp_stats.tag_writes);
}
