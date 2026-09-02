// SPDX-License-Identifier: GPL-2.0-only
/*
 * The Flow layer's runtime (rung 2, ratified PEI-598): the sentence cache
 * on the conntrack extension, the dispatch at the IP seats, and the flows
 * dump behind PEIOS_PNP_IOC_FLOWS.
 *
 * A flow is judged once per local endpoint. A normal flow has one: its
 * first packet, at the originator's seat, evaluates the Flow forest and
 * the verdict is written to the flow's sentence (slot 0) with the policy
 * generation and an expiry; every later packet of the flow, in either
 * direction, reads the sentence — a pointer and two compares — instead
 * of evaluating. A loopback flow has two endpoints and two sentences:
 * judged as Outbound at LOCAL_OUT (slot 0) and as Inbound at LOCAL_IN
 * (slot 1), and every packet of it answers to the stricter of the two.
 *
 * A sentence is stale when its generation is not the current one or its
 * expiry has passed (the earliest moment a live-time condition the
 * judgment consulted would flip). A stale sentence is re-judged lazily,
 * on the flow's next packet — a full evaluation, effects included, so a
 * kill by `REJECT, REPORT(n)` reports. Grandfathering was rejected: the
 * registry must not lie about what is enforced.
 *
 * The cache holds the verdict only. Effects run at evaluation and never
 * per packet. DROP and REJECT sentences persist: a cached REJECT refuses
 * every subsequent packet of the flow (each retransmit gets its answer).
 * A flow whose extension could not be allocated has nowhere to hold a
 * sentence and is evaluated on every packet, counted.
 *
 * Concurrency: a sentence is written under the flow's lock with its
 * generation zeroed first and published last (release); it is read
 * lock-free with an acquire and a re-check of the generation, so a
 * reader never applies a torn sentence. Two packets of a new flow racing
 * on different CPUs may both evaluate; the second write wins, harmless.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/peios_pnp.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/util_macros.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include <pkm/pnp.h>

#include "pnp.h"

u64 peios_pnp_path_hash(const char *s, size_t len)
{
	u64 h = 0xcbf29ce484222325ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= (u8)s[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

static struct peios_pnp_ct *pnp_ct_ext(const struct nf_conn *ct)
{
	return ct ? nf_ct_ext_find(ct, NF_CT_EXT_PNP) : NULL;
}

/* Which sentence slot this traversal reads and writes. */
static u32 pnp_sentence_slot(const struct peios_pnp_snapshot *snap)
{
	return snap->loopback && snap->direction == PEIOS_PNP_DIR_IN ? 1 : 0;
}

/* Lock-free read; false when the slot is empty or was torn under us. */
static bool pnp_sentence_read(const struct peios_pnp_sentence *s,
			      struct peios_pnp_sentence *out)
{
	u64 gen = smp_load_acquire(&s->generation);

	if (!gen)
		return false;
	out->expires_at = READ_ONCE(s->expires_at);
	out->rule_hash = READ_ONCE(s->rule_hash);
	out->verdict = READ_ONCE(s->verdict);
	out->reject_kind = READ_ONCE(s->reject_kind);
	smp_rmb();
	if (READ_ONCE(s->generation) != gen)
		return false;
	out->generation = gen;
	return true;
}

static void pnp_sentence_write(struct nf_conn *ct,
			       struct peios_pnp_sentence *s,
			       const struct peios_pnp_sentence *val)
{
	spin_lock_bh(&ct->lock);
	WRITE_ONCE(s->generation, 0);
	smp_wmb();
	WRITE_ONCE(s->expires_at, val->expires_at);
	WRITE_ONCE(s->rule_hash, val->rule_hash);
	WRITE_ONCE(s->verdict, val->verdict);
	WRITE_ONCE(s->reject_kind, val->reject_kind);
	smp_store_release(&s->generation, val->generation);
	spin_unlock_bh(&ct->lock);
}

static bool pnp_sentence_current(const struct peios_pnp_sentence *s, u64 gen,
				 s64 now)
{
	return s->generation == gen && !(s->expires_at && now >= s->expires_at);
}

/* Strictness: DROP > REJECT(Refused) > REJECT(Prohibited) > PASS. */
static bool pnp_sentence_stricter(const struct peios_pnp_sentence *a,
				  const struct peios_pnp_sentence *b)
{
	if (a->verdict != b->verdict)
		return a->verdict > b->verdict;
	if (a->verdict == PEIOS_PNP_VERDICT_REJECT)
		return a->reject_kind < b->reject_kind;
	return false;
}

/*
 * The flow view: the snapshot the Flow layer judges. A Flow fact is one
 * identical for every packet of the flow, so the view is built from the
 * flow, not the packet — the original tuple (a reply packet's addresses
 * and ports are swapped back), the originator's direction, and the facts
 * recorded at the first judgment (interface, VLAN, the peer's MAC). A
 * loopback flow is judged per endpoint: its direction is the slot's.
 * The first judgment of a flow is on its first packet, in the original
 * direction, so it records what it sees.
 */
static void pnp_flow_view(const struct peios_pnp_snapshot *snap,
			  const struct peios_pnp_ct *pc, u32 slot,
			  struct peios_pnp_snapshot *view)
{
	*view = *snap;
	if (snap->flow_reply) {
		u8 addr[16];
		u16 port;

		memcpy(addr, view->src_addr, 16);
		memcpy(view->src_addr, view->dst_addr, 16);
		memcpy(view->dst_addr, addr, 16);
		port = view->src_port;
		view->src_port = view->dst_port;
		view->dst_port = port;
		/* The reply's ICMP type is the answer's; the flow's is the
		 * original tuple's, which conntrack keeps.
		 */
		if (snap->has & PEIOS_PNP_HAS_ICMP) {
			const struct nf_conn *ct = snap->flow;
			const struct nf_conntrack_tuple *t =
				&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

			view->icmp_type = t->dst.u.icmp.type;
			view->icmp_code = t->dst.u.icmp.code;
		}
		view->direction = snap->direction == PEIOS_PNP_DIR_IN ?
			PEIOS_PNP_DIR_OUT : PEIOS_PNP_DIR_IN;
	}
	if (snap->loopback)
		view->direction = slot ? PEIOS_PNP_DIR_IN : PEIOS_PNP_DIR_OUT;
	if (pc && READ_ONCE(pc->judged)) {
		struct net_device *dev;

		smp_rmb();
		if (!snap->loopback)
			view->direction = READ_ONCE(pc->direction);
		view->ifindex = READ_ONCE(pc->ifindex);
		/* Hook context holds the RCU read lock already; the KUnit
		 * caller does not, and nesting is free.
		 */
		rcu_read_lock();
		dev = dev_get_by_index_rcu(&init_net, view->ifindex);
		if (dev)
			strscpy(view->ifname, dev->name, IFNAMSIZ);
		rcu_read_unlock();
		view->has &= ~(PEIOS_PNP_HAS_VLAN | PEIOS_PNP_HAS_MACS |
			       PEIOS_PNP_HAS_SRC_MAC);
		if (READ_ONCE(pc->has_vlan)) {
			view->vlan = READ_ONCE(pc->vlan);
			view->has |= PEIOS_PNP_HAS_VLAN;
		}
		if (READ_ONCE(pc->has_src_mac)) {
			memcpy(view->src_mac, pc->src_mac, 6);
			view->has |= PEIOS_PNP_HAS_SRC_MAC;
		}
	}
	/* A Flow fact set never carries the destination MAC. */
	if (view->has & PEIOS_PNP_HAS_MACS) {
		view->has &= ~PEIOS_PNP_HAS_MACS;
		view->has |= PEIOS_PNP_HAS_SRC_MAC;
	}
}

/* Records the flow facts the tuple does not carry, once. */
static void pnp_flow_record(struct peios_pnp_ct *pc,
			    const struct peios_pnp_snapshot *view)
{
	if (READ_ONCE(pc->judged))
		return;
	WRITE_ONCE(pc->ifindex, view->ifindex);
	WRITE_ONCE(pc->direction, view->direction);
	WRITE_ONCE(pc->loopback, view->loopback);
	if (view->has & PEIOS_PNP_HAS_VLAN) {
		WRITE_ONCE(pc->vlan, view->vlan);
		WRITE_ONCE(pc->has_vlan, 1);
	}
	if (view->has & PEIOS_PNP_HAS_SRC_MAC) {
		memcpy(pc->src_mac, view->src_mac, 6);
		WRITE_ONCE(pc->has_src_mac, 1);
	}
	smp_wmb();
	WRITE_ONCE(pc->judged, 1);
}

/*
 * The endpoints' identities for one judgment: read from the extension
 * when recorded, else resolved (identity.c) and recorded there — fixed for
 * the flow's life, like the direction. `owned` marks a resolution the
 * extension could not keep, released after the evaluation.
 */
struct pnp_identity_pair {
	struct peios_pnp_identity id[2];
	bool owned[2];
};

static void pnp_identity_read(const struct peios_pnp_ct *pc, u32 s,
			      struct peios_pnp_identity *id)
{
	id->kind = READ_ONCE(pc->owner_kind[s]);
	id->unresolved = READ_ONCE(pc->owner_unresolved[s]);
	id->owner = pc->owner[s];	/* borrowed: the extension holds the ref */
}

static void pnp_flow_identity(struct sk_buff *skb,
			      const struct nf_hook_state *state,
			      const struct peios_pnp_snapshot *snap,
			      struct nf_conn *ct, struct peios_pnp_ct *pc,
			      u32 slot, struct pnp_identity_pair *p)
{
	u32 s;

	memset(p, 0, sizeof(*p));
	for (s = 0; s < 2; s++) {
		struct peios_pnp_identity *id = &p->id[s];
		bool other = s != slot;

		/* The other end is a fact only when it is local too. */
		if (other && !snap->loopback)
			continue;
		if (pc && smp_load_acquire(&pc->owner_recorded[s])) {
			pnp_identity_read(pc, s, id);
			continue;
		}
		peios_pnp_identity_resolve(skb, state, snap, other, id);
		if (id->unresolved)
			atomic64_inc(&peios_pnp_stats.identity_unresolved);
		if (id->kind == PEIOS_PNP_LOCAL_ABSENT)
			continue;
		if (!pc) {
			p->owned[s] = true;
			continue;
		}
		spin_lock_bh(&ct->lock);
		if (!pc->owner_recorded[s]) {
			pc->owner[s] = id->owner;
			WRITE_ONCE(pc->owner_kind[s], id->kind);
			WRITE_ONCE(pc->owner_unresolved[s], id->unresolved);
			smp_store_release(&pc->owner_recorded[s], 1);
			spin_unlock_bh(&ct->lock);
		} else {
			/* Two CPUs on a new flow's first packets: the first
			 * record stands, as the first sentence does.
			 */
			spin_unlock_bh(&ct->lock);
			peios_pnp_identity_release(id);
			pnp_identity_read(pc, s, id);
		}
	}
}

static void pnp_identity_pair_release(struct pnp_identity_pair *p)
{
	u32 s;

	for (s = 0; s < 2; s++)
		if (p->owned[s])
			peios_pnp_identity_release(&p->id[s]);
}

/* The identity facts onto the flow view: this end, and the other. */
static void pnp_flow_view_identity(struct peios_pnp_snapshot *view,
				   const struct pnp_identity_pair *p, u32 slot)
{
	const struct peios_pnp_identity *l = &p->id[slot];
	const struct peios_pnp_identity *r = &p->id[slot ^ 1];

	view->local_kind = l->kind;
	view->local_unresolved = l->unresolved;
	view->local_token = l->owner.token;
	view->local_pid = l->owner.pid;
	memcpy(view->local_guid, l->owner.guid, sizeof(view->local_guid));
	strscpy(view->local_comm, l->owner.comm, sizeof(view->local_comm));
	view->remote_kind = r->kind;
	view->remote_unresolved = r->unresolved;
	view->remote_token = r->owner.token;
	view->remote_pid = r->owner.pid;
	memcpy(view->remote_guid, r->owner.guid, sizeof(view->remote_guid));
	strscpy(view->remote_comm, r->owner.comm, sizeof(view->remote_comm));
}

static unsigned int pnp_apply_sentence(struct sk_buff *skb,
				       const struct nf_hook_state *state,
				       const struct peios_pnp_snapshot *snap,
				       const struct peios_pnp_sentence *s)
{
	switch (s->verdict) {
	case PEIOS_PNP_VERDICT_PASS:
		return NF_ACCEPT;
	case PEIOS_PNP_VERDICT_REJECT:
		peios_pnp_refuse(skb, state, snap, s->reject_kind);
		return NF_DROP;
	case PEIOS_PNP_VERDICT_DROP:
	default:
		return NF_DROP;
	}
}

unsigned int peios_pnp_flow_dispatch(struct sk_buff *skb,
				     const struct nf_hook_state *state,
				     const struct peios_pnp_snapshot *snap)
{
	struct nf_conn *ct = (struct nf_conn *)snap->flow;
	struct peios_pnp_sentence cur = { }, other = { };
	struct pnp_identity_pair ids = { };
	struct peios_pnp_snapshot view;
	struct peios_pnp_outcome out;
	struct peios_pnp_ct *pc;
	u64 gen = pnp_rust_generation();
	u8 evflags = 0;
	bool hit = false;
	u32 slot;
	int ret;

	/* Untracked: there is no flow to judge; the Packet verdict stands. */
	if (!ct)
		return NF_ACCEPT;
	pc = pnp_ct_ext(ct);
	slot = pnp_sentence_slot(snap);

	if (pc && pnp_sentence_read(&pc->sentence[slot], &cur)) {
		if (cur.generation != gen) {
			evflags = PEIOS_PNP_EV_F_REJUDGED;
			atomic64_inc(&peios_pnp_stats.flow_rejudged);
		} else if (cur.expires_at && snap->t_secs >= cur.expires_at) {
			evflags = PEIOS_PNP_EV_F_REJUDGED;
			atomic64_inc(&peios_pnp_stats.flow_expired);
		} else {
			hit = true;
		}
	}

	if (hit) {
		atomic64_inc(&peios_pnp_stats.flow_cached);
	} else {
		pnp_flow_view(snap, pc, slot, &view);
		/* The identity facts cost a socket lookup inbound: resolved
		 * only when there is a Flow forest to judge them.
		 */
		if (peios_pnp_policy_has_layer(PEIOS_PNP_LAYER_FLOW)) {
			pnp_flow_identity(skb, state, snap, ct, pc, slot, &ids);
			pnp_flow_view_identity(&view, &ids, slot);
			if (view.local_unresolved || view.remote_unresolved)
				evflags |= PEIOS_PNP_EV_F_IDENTITY_UNRESOLVED;
		}
		ret = peios_pnp_policy_eval(PEIOS_PNP_LAYER_FLOW, &view, &out);
		if (ret == -ENOENT) {
			/* No Flow forest: permissive, and nothing to cache. */
			atomic64_inc(&peios_pnp_stats.permissive);
			pnp_identity_pair_release(&ids);
			return NF_ACCEPT;
		}
		if (ret < 0) {
			atomic64_inc(&peios_pnp_stats.fail_closed);
			memset(&out, 0, sizeof(out));
			out.verdict = PEIOS_PNP_VERDICT_DROP;
			strscpy(out.attributed, "fail-closed",
				sizeof(out.attributed));
			peios_pnp_event_emit(&view, &out, PEIOS_PNP_LAYER_FLOW,
					     PEIOS_PNP_EV_F_FAIL_CLOSED);
			pnp_identity_pair_release(&ids);
			return NF_DROP;
		}
		atomic64_inc(&peios_pnp_stats.judged);
		atomic64_inc(&peios_pnp_stats.flow_judged);
		atomic64_add(out.n_tags, &peios_pnp_stats.fx_tags);
		atomic64_add(out.n_counts, &peios_pnp_stats.fx_counts);
		atomic64_add(out.n_reports, &peios_pnp_stats.fx_reports);
		atomic64_add(out.n_prompts, &peios_pnp_stats.fx_prompts);
		switch (out.verdict) {
		case PEIOS_PNP_VERDICT_PASS:
			atomic64_inc(&peios_pnp_stats.verdict_pass);
			break;
		case PEIOS_PNP_VERDICT_REJECT:
			atomic64_inc(&peios_pnp_stats.verdict_reject);
			break;
		default:
			atomic64_inc(&peios_pnp_stats.verdict_drop);
			break;
		}

		cur.generation = gen;
		cur.expires_at = out.expires_at;
		cur.rule_hash = peios_pnp_path_hash(out.attributed,
						    strnlen(out.attributed,
							    sizeof(out.attributed)));
		cur.verdict = out.verdict;
		cur.reject_kind = out.reject_kind;
		if (pc) {
			pnp_sentence_write(ct, &pc->sentence[slot], &cur);
			pnp_flow_record(pc, &view);
		} else {
			atomic64_inc(&peios_pnp_stats.flow_uncached);
		}

		/* The refusal, when it is one, answers the packet in hand
		 * (the packet snapshot, not the flow view) and goes out before
		 * the event so the event can confess a degradation. The event
		 * describes the flow as judged.
		 */
		if (out.verdict == PEIOS_PNP_VERDICT_REJECT) {
			bool sent = peios_pnp_refuse(skb, state, snap,
						     out.reject_kind);

			if (!sent)
				evflags |= PEIOS_PNP_EV_F_REJECT_DEGRADED;
			peios_pnp_event_emit(&view, &out, PEIOS_PNP_LAYER_FLOW,
					     evflags);
			pnp_identity_pair_release(&ids);
			return NF_DROP;
		}
		peios_pnp_event_emit(&view, &out, PEIOS_PNP_LAYER_FLOW, evflags);
		pnp_identity_pair_release(&ids);
	}

	/* A loopback flow answers to both endpoints' sentences: the other
	 * endpoint's, when current, can only make this one stricter. A stale
	 * one is that seat's to refresh when it next sees the flow.
	 */
	if (snap->loopback && pc &&
	    pnp_sentence_read(&pc->sentence[slot ^ 1], &other) &&
	    pnp_sentence_current(&other, gen, snap->t_secs) &&
	    pnp_sentence_stricter(&other, &cur))
		cur = other;

	return pnp_apply_sentence(skb, state, snap, &cur);
}

/* --- the flows dump ------------------------------------------------- */

static void pnp_sentence_to_rec(const struct peios_pnp_sentence *s,
				struct peios_pnp_flow_rec *rec, u32 slot)
{
	struct peios_pnp_sentence val;

	if (!pnp_sentence_read(s, &val))
		return;
	rec->sentence_generation[slot] = val.generation;
	rec->sentence_expires_at[slot] = val.expires_at;
	rec->sentence_rule_hash[slot] = val.rule_hash;
	rec->sentence_verdict[slot] = val.verdict;
	rec->sentence_reject_kind[slot] = val.reject_kind;
}

/* The endpoint identity recorded for one slot, if any. */
static void pnp_owner_to_rec(const struct peios_pnp_ct *pc,
			     struct peios_pnp_flow_rec *rec, u32 slot)
{
	const struct peios_pnp_owner *o = &pc->owner[slot];

	if (!smp_load_acquire(&pc->owner_recorded[slot]))
		return;
	rec->owner_kind[slot] = READ_ONCE(pc->owner_kind[slot]);
	rec->owner_unresolved[slot] = READ_ONCE(pc->owner_unresolved[slot]);
	rec->owner_pid[slot] = o->pid;
	memcpy(&rec->owner_guid[slot * PEIOS_PNP_GUID_LEN], o->guid,
	       PEIOS_PNP_GUID_LEN);
	memcpy(&rec->owner_comm[slot * PEIOS_PNP_COMM_LEN], o->comm,
	       PEIOS_PNP_COMM_LEN);
	if (o->token)
		pnp_rust_owner_sids(o->token,
				    &rec->owner_user[slot * PEIOS_PNP_SID_LEN],
				    &rec->owner_service[slot *
							PEIOS_PNP_SERVICE_SID_LEN]);
}

/* Fills one record from a live entry; called under its bucket lock. */
static void pnp_flow_fill(struct peios_pnp_flow_rec *rec,
			  const struct nf_conn *ct)
{
	const struct nf_conntrack_tuple *t =
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	const struct peios_pnp_ct *pc = pnp_ct_ext(ct);
	const struct nf_conn_acct *acct = nf_conn_acct_find(ct);
	unsigned long expires = nf_ct_expires(ct);

	memset(rec, 0, sizeof(*rec));
	rec->id = nf_ct_get_id(ct);
	rec->family = nf_ct_l3num(ct) == NFPROTO_IPV6 ? 6 : 4;
	rec->protocol = nf_ct_protonum(ct);
	if (rec->family == 4) {
		memcpy(rec->src_addr, &t->src.u3.ip, 4);
		memcpy(rec->dst_addr, &t->dst.u3.ip, 4);
	} else {
		memcpy(rec->src_addr, &t->src.u3.in6, 16);
		memcpy(rec->dst_addr, &t->dst.u3.in6, 16);
	}
	switch (rec->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		rec->src_port = ntohs(t->src.u.all);
		rec->dst_port = ntohs(t->dst.u.all);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		rec->src_port = ntohs(t->src.u.icmp.id);
		rec->icmp_type = t->dst.u.icmp.type;
		rec->icmp_code = t->dst.u.icmp.code;
		break;
	default:
		break;
	}
	rec->seen_reply = test_bit(IPS_SEEN_REPLY_BIT, &ct->status);
	rec->assured = test_bit(IPS_ASSURED_BIT, &ct->status);
	rec->related = ct->master != NULL;
	rec->timeout_secs = jiffies_to_msecs(expires) / 1000;
	if (acct) {
		rec->packets[0] = atomic64_read(
			&acct->counter[IP_CT_DIR_ORIGINAL].packets);
		rec->bytes[0] = atomic64_read(
			&acct->counter[IP_CT_DIR_ORIGINAL].bytes);
		rec->packets[1] = atomic64_read(
			&acct->counter[IP_CT_DIR_REPLY].packets);
		rec->bytes[1] = atomic64_read(
			&acct->counter[IP_CT_DIR_REPLY].bytes);
	}
	if (pc) {
		rec->start_secs = pc->start_secs;
		if (READ_ONCE(pc->judged)) {
			smp_rmb();
			rec->judged = 1;
			rec->ifindex = READ_ONCE(pc->ifindex);
			rec->direction = READ_ONCE(pc->direction);
			rec->loopback = READ_ONCE(pc->loopback);
		}
		pnp_sentence_to_rec(&pc->sentence[0], rec, 0);
		pnp_sentence_to_rec(&pc->sentence[1], rec, 1);
		pnp_owner_to_rec(pc, rec, 0);
		pnp_owner_to_rec(pc, rec, 1);
		rec->n_tags = min_t(u32,
				    peios_pnp_tags_snapshot(ct, rec->tag_hash,
							    rec->tag_value,
							    PEIOS_PNP_FLOW_MAX_TAGS),
				    PEIOS_PNP_FLOW_MAX_TAGS);
	}
}

#define PNP_FLOWS_BATCH		32

long peios_pnp_flows_dump(struct peios_pnp_flows_query *query)
{
	struct peios_pnp_flow_rec __user *ubuf = u64_to_user_ptr(query->buf);
	struct peios_pnp_flow_rec *batch;
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *nn;
	u32 room = query->buf_len / sizeof(*ubuf);
	u32 written = 0, total = 0, n = 0, i;
	long ret = 0;

	batch = kcalloc(PNP_FLOWS_BATCH, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return -ENOMEM;

	local_bh_disable();
	for (i = 0; i < nf_conntrack_htable_size; i++) {
		spinlock_t *lockp = &nf_conntrack_locks[i % CONNTRACK_LOCKS];

		nf_conntrack_lock(lockp);
		/* The table may have been resized while unlocked. */
		if (i >= nf_conntrack_htable_size) {
			spin_unlock(lockp);
			break;
		}
		hlist_nulls_for_each_entry(h, nn, &nf_conntrack_hash[i], hnnode) {
			struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

			if (NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL)
				continue;
			if (!net_eq(nf_ct_net(ct), &init_net))
				continue;
			if (nf_ct_is_expired(ct) || nf_ct_is_dying(ct))
				continue;
			total++;
			if (written + n >= room || n == PNP_FLOWS_BATCH)
				continue;	/* count only */
			pnp_flow_fill(&batch[n++], ct);
		}
		spin_unlock(lockp);

		/* Flush between buckets, never inside one (a bucket is walked
		 * under its lock; copying to user must not be).
		 */
		if (n >= PNP_FLOWS_BATCH / 2) {
			local_bh_enable();
			if (copy_to_user(ubuf + written, batch, n * sizeof(*batch))) {
				ret = -EFAULT;
				goto out;
			}
			written += n;
			n = 0;
			local_bh_disable();
		}
	}
	local_bh_enable();
	if (n && copy_to_user(ubuf + written, batch, n * sizeof(*batch))) {
		ret = -EFAULT;
		goto out;
	}
	written += n;
out:
	query->count = written;
	query->total = total;
	kfree(batch);
	return ret;
}
