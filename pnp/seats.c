// SPDX-License-Identifier: GPL-2.0-only
/*
 * The standing seats, the dispatch law, and verdict application
 * (ratified, PEI-598; the Flow layer from the rung-2 design):
 *
 *   RawPacket matches all traffic at the device seats, unconditionally.
 *   The Packet layer judges every traversal exactly once, at its proper
 *   seat — inbound IP at the IP hook (flow facts attached, defrag done),
 *   everything outbound at egress (frame complete, flow facts still
 *   aboard) — falling back to the ingress seat iff the traversal will
 *   never reach its proper seat (non-IP ethertypes; bridge-enslaved
 *   ports, whose frames never cross the IP hooks).
 *   The Flow layer judges every tracked flow once per local endpoint, at
 *   the IP seats (inbound at LOCAL_IN after Packet, outbound at
 *   LOCAL_OUT), and its sentence answers for every later packet.
 *
 * Layers are judged in traversal order (wire-proximate RawPacket first
 * inbound, last outbound; Flow innermost); the first non-PASS verdict
 * ends the traversal. A layer with no published forest is permissive —
 * from boot until the first generation ingests, that is every layer,
 * loudly (generation 0, ratified).
 *
 * REJECT tells the story its kind names (ratified): Refused = RST for
 * TCP, ICMP/ICMPv6 port-unreachable otherwise ("nothing is listening");
 * Prohibited = ICMP admin-prohibited for every protocol ("policy refused
 * you"). Every seat can answer for IP traffic (refuse.c); only a protocol
 * with no refusal vocabulary (non-IP) degrades REJECT to DROP, counted.
 *
 * PNP does not judge its own refusals: an answer it built carries the skb
 * refusal bit, and every seat waves it through unjudged (counted).
 *
 * Evaluation failure (atomic allocation exhausted mid-walk) fails
 * closed: the packet drops and the failure is counted. Totality does not
 * take "no answer" for an answer.
 */

#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

#include <pkm/pnp.h>

#include "pnp.h"

struct peios_pnp_stats peios_pnp_stats;

bool peios_pnp_traversal_reaches_ip_seat(__be16 protocol,
					 const struct net_device *dev)
{
	if (protocol != htons(ETH_P_IP) && protocol != htons(ETH_P_IPV6))
		return false;
	/* Bridge-forwarded frames are switched at L2 and never enter the
	 * IP stack on this device: the ingress seat is their only seat.
	 * (A copy delivered to the bridge device itself is a separate
	 * traversal on that device and is judged there.)
	 */
	if (dev && netif_is_bridge_port(dev))
		return false;
	return true;
}

/* The law: a refusal PNP emitted is not traffic PNP judges. */
static bool pnp_bypass_refusal(const struct sk_buff *skb)
{
	if (!skb->pnp_refusal)
		return false;
	atomic64_inc(&peios_pnp_stats.refusals_bypassed);
	return true;
}

/*
 * Judge one built snapshot against the given layers in traversal order;
 * apply the first non-PASS verdict. NF_ACCEPT when every layer passed or
 * was permissive.
 */
static unsigned int judge(struct sk_buff *skb,
			  const struct nf_hook_state *state,
			  const struct peios_pnp_snapshot *snap,
			  const u8 *layers, int n_layers)
{
	struct peios_pnp_outcome out;
	int i, ret;

	for (i = 0; i < n_layers; i++) {
		u8 evflags = 0;

		ret = peios_pnp_policy_eval(layers[i], snap, &out);
		if (ret == -ENOENT) {
			/* No forest for this layer: permissive (gen 0). */
			atomic64_inc(&peios_pnp_stats.permissive);
			continue;
		}
		if (ret < 0) {
			atomic64_inc(&peios_pnp_stats.fail_closed);
			memset(&out, 0, sizeof(out));
			out.verdict = PEIOS_PNP_VERDICT_DROP;
			strscpy(out.attributed, "fail-closed",
				sizeof(out.attributed));
			peios_pnp_event_emit(snap, &out, layers[i],
					     PEIOS_PNP_EV_F_FAIL_CLOSED);
			return NF_DROP;
		}

		atomic64_inc(&peios_pnp_stats.judged);
		atomic64_add(out.n_tags, &peios_pnp_stats.fx_tags);
		atomic64_add(out.n_counts, &peios_pnp_stats.fx_counts);
		atomic64_add(out.n_reports, &peios_pnp_stats.fx_reports);
		atomic64_add(out.n_prompts, &peios_pnp_stats.fx_prompts);

		switch (out.verdict) {
		case PEIOS_PNP_VERDICT_PASS:
			atomic64_inc(&peios_pnp_stats.verdict_pass);
			peios_pnp_event_emit(snap, &out, layers[i], 0);
			continue;
		case PEIOS_PNP_VERDICT_REJECT:
			atomic64_inc(&peios_pnp_stats.verdict_reject);
			if (!peios_pnp_refuse(skb, state, snap, out.reject_kind))
				evflags |= PEIOS_PNP_EV_F_REJECT_DEGRADED;
			peios_pnp_event_emit(snap, &out, layers[i], evflags);
			return NF_DROP;
		case PEIOS_PNP_VERDICT_DROP:
		default:
			atomic64_inc(&peios_pnp_stats.verdict_drop);
			peios_pnp_event_emit(snap, &out, layers[i], 0);
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

static void build_snapshot(const struct sk_buff *skb,
			   const struct net_device *dev, u8 seat, u8 direction,
			   struct peios_pnp_snapshot *snap)
{
	if (peios_pnp_snapshot_from_skb(skb, dev, seat, direction, snap))
		atomic64_inc(&peios_pnp_stats.parse_errors);
}

unsigned int peios_pnp_hook_ingress(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	/* RawPacket judges everything here; the Packet layer joins as
	 * fallback iff the traversal never reaches its proper seat.
	 */
	u8 layers[2] = { PEIOS_PNP_LAYER_RAWPACKET, PEIOS_PNP_LAYER_PACKET };
	struct peios_pnp_snapshot snap;
	int n_layers = 1;

	if (pnp_bypass_refusal(skb))
		return NF_ACCEPT;
	atomic64_inc(&peios_pnp_stats.seen_ingress);

	if (peios_pnp_traversal_reaches_ip_seat(skb->protocol, state->in)) {
		atomic64_inc(&peios_pnp_stats.deferred);
	} else {
		atomic64_inc(&peios_pnp_stats.fallback_judged);
		n_layers = 2;
	}
	build_snapshot(skb, state->in, PEIOS_PNP_SEAT_INGRESS, PEIOS_PNP_DIR_IN,
		       &snap);
	return judge(skb, state, &snap, layers, n_layers);
}

unsigned int peios_pnp_hook_egress(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	/* Outbound traversal order: the Packet layer's proper seat, then
	 * wire-proximate RawPacket last.
	 */
	static const u8 layers[2] = { PEIOS_PNP_LAYER_PACKET,
				      PEIOS_PNP_LAYER_RAWPACKET };
	struct peios_pnp_snapshot snap;

	if (pnp_bypass_refusal(skb))
		return NF_ACCEPT;
	atomic64_inc(&peios_pnp_stats.seen_egress);
	build_snapshot(skb, state->out, PEIOS_PNP_SEAT_EGRESS, PEIOS_PNP_DIR_OUT,
		       &snap);
	return judge(skb, state, &snap, layers, 2);
}

unsigned int peios_pnp_hook_local_in(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	static const u8 layers[1] = { PEIOS_PNP_LAYER_PACKET };
	struct peios_pnp_snapshot snap;
	unsigned int verdict;

	if (pnp_bypass_refusal(skb))
		return NF_ACCEPT;
	atomic64_inc(&peios_pnp_stats.seen_local_in);
	build_snapshot(skb, state->in, PEIOS_PNP_SEAT_LOCAL_IN,
		       PEIOS_PNP_DIR_IN, &snap);
	/* Packet first (the cheap per-packet filter), then the flow's
	 * sentence — or the Flow layer, for a flow with no current one.
	 */
	verdict = judge(skb, state, &snap, layers, 1);
	if (verdict != NF_ACCEPT)
		return verdict;
	return peios_pnp_flow_dispatch(skb, state, &snap);
}

unsigned int peios_pnp_hook_local_out(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct peios_pnp_snapshot snap;

	if (pnp_bypass_refusal(skb))
		return NF_ACCEPT;
	atomic64_inc(&peios_pnp_stats.seen_local_out);
	/* The outbound Flow seat: first point after conntrack for locally
	 * generated traffic, the entry still unconfirmed, a reject path
	 * available. Packet and RawPacket follow at egress, in wire order.
	 */
	build_snapshot(skb, state->out, PEIOS_PNP_SEAT_LOCAL_OUT,
		       PEIOS_PNP_DIR_OUT, &snap);
	return peios_pnp_flow_dispatch(skb, state, &snap);
}
