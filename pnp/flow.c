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
		ret = peios_pnp_policy_eval(PEIOS_PNP_LAYER_FLOW, snap, &out);
		if (ret == -ENOENT) {
			/* No Flow forest: permissive, and nothing to cache. */
			atomic64_inc(&peios_pnp_stats.permissive);
			return NF_ACCEPT;
		}
		if (ret < 0) {
			atomic64_inc(&peios_pnp_stats.fail_closed);
			memset(&out, 0, sizeof(out));
			out.verdict = PEIOS_PNP_VERDICT_DROP;
			strscpy(out.attributed, "fail-closed",
				sizeof(out.attributed));
			peios_pnp_event_emit(snap, &out, PEIOS_PNP_LAYER_FLOW,
					     PEIOS_PNP_EV_F_FAIL_CLOSED);
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
			if (!READ_ONCE(pc->judged)) {
				WRITE_ONCE(pc->ifindex, snap->ifindex);
				WRITE_ONCE(pc->direction, snap->direction);
				WRITE_ONCE(pc->loopback, snap->loopback);
				smp_wmb();
				WRITE_ONCE(pc->judged, 1);
			}
		} else {
			atomic64_inc(&peios_pnp_stats.flow_uncached);
		}

		/* The refusal, when it is one, goes out before the event so
		 * the event can confess a degradation.
		 */
		if (out.verdict == PEIOS_PNP_VERDICT_REJECT) {
			bool sent = peios_pnp_refuse(skb, state, snap,
						     out.reject_kind);

			if (!sent)
				evflags |= PEIOS_PNP_EV_F_REJECT_DEGRADED;
			peios_pnp_event_emit(snap, &out, PEIOS_PNP_LAYER_FLOW,
					     evflags);
			return NF_DROP;
		}
		peios_pnp_event_emit(snap, &out, PEIOS_PNP_LAYER_FLOW, evflags);
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
