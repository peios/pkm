// SPDX-License-Identifier: GPL-2.0-only
/*
 * The standing seats, the dispatch law, and verdict application
 * (ratified, PEI-598):
 *
 *   RawPacket matches all traffic at the device seats, unconditionally.
 *   The Packet layer judges every traversal exactly once, at its proper
 *   seat — inbound IP at the IP hook (flow facts attached, defrag done),
 *   everything outbound at egress (frame complete, flow facts still
 *   aboard) — falling back to the ingress seat iff the traversal will
 *   never reach its proper seat (non-IP ethertypes; bridge-enslaved
 *   ports, whose frames never cross the IP hooks).
 *
 * Layers are judged in traversal order (wire-proximate RawPacket first
 * inbound, last outbound); the first non-PASS verdict ends the
 * traversal. A layer with no published forest is permissive — from boot
 * until the first generation ingests, that is every layer, loudly
 * (generation 0, ratified).
 *
 * REJECT is protocol-phrased by the kept nf_reject machinery, telling
 * the story its kind names (ratified): Refused = RST for TCP, ICMP/ICMPv6
 * port-unreachable otherwise ("nothing is listening"); Prohibited = ICMP
 * admin-prohibited for every protocol ("policy refused you"). Seats that
 * cannot emit a response (the device seats, for now — the
 * outbound-from-egress and non-IP cases from the design's care list)
 * degrade REJECT to DROP and count the degradation.
 *
 * Evaluation failure (atomic allocation exhausted mid-walk) fails
 * closed: the packet drops and the failure is counted. Totality does not
 * take "no answer" for an answer.
 */

#include <linux/etherdevice.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>

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

/* Emit the refusal the kind names, where the seat allows one. */
static unsigned int apply_reject(struct sk_buff *skb,
				 const struct nf_hook_state *state,
				 const struct peios_pnp_snapshot *snap,
				 u8 kind)
{
	bool prohibited = kind == PEIOS_PNP_REJECT_PROHIBITED;

	if (snap->seat != PEIOS_PNP_SEAT_LOCAL_IN) {
		atomic64_inc(&peios_pnp_stats.reject_degraded);
		return NF_DROP;
	}
	if (snap->addr_family == 4) {
		if (prohibited)
			nf_send_unreach(skb, ICMP_PKT_FILTERED, state->hook);
		else if (snap->protocol == IPPROTO_TCP)
			nf_send_reset(state->net, state->sk, skb, state->hook);
		else
			nf_send_unreach(skb, ICMP_PORT_UNREACH, state->hook);
	} else if (snap->addr_family == 6) {
		if (prohibited)
			nf_send_unreach6(state->net, skb, ICMPV6_ADM_PROHIBITED,
					 state->hook);
		else if (snap->protocol == IPPROTO_TCP)
			nf_send_reset6(state->net, state->sk, skb,
				       state->hook);
		else
			nf_send_unreach6(state->net, skb, ICMPV6_PORT_UNREACH,
					 state->hook);
	} else {
		atomic64_inc(&peios_pnp_stats.reject_degraded);
	}
	return NF_DROP;
}

/*
 * Judge one traversal at one seat: build the snapshot once, evaluate the
 * given layers in traversal order, apply the first non-PASS verdict.
 */
static unsigned int judge(struct sk_buff *skb, const struct net_device *dev,
			  const struct nf_hook_state *state, u8 seat,
			  u8 direction, const u8 *layers, int n_layers)
{
	struct peios_pnp_snapshot snap;
	struct peios_pnp_outcome out;
	int i, ret;

	if (peios_pnp_snapshot_from_skb(skb, dev, seat, direction, &snap))
		atomic64_inc(&peios_pnp_stats.parse_errors);

	for (i = 0; i < n_layers; i++) {
		u8 evflags = 0;

		ret = peios_pnp_policy_eval(layers[i], &snap, &out);
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
			peios_pnp_event_emit(&snap, &out, layers[i],
					     PEIOS_PNP_EV_F_FAIL_CLOSED);
			return NF_DROP;
		}

		atomic64_inc(&peios_pnp_stats.judged);
		atomic64_add(out.n_tags, &peios_pnp_stats.fx_tags);
		atomic64_add(out.n_counts, &peios_pnp_stats.fx_counts);
		atomic64_add(out.n_reports, &peios_pnp_stats.fx_reports);
		atomic64_add(out.n_prompts, &peios_pnp_stats.fx_prompts);

		if (out.verdict == PEIOS_PNP_VERDICT_REJECT &&
		    seat != PEIOS_PNP_SEAT_LOCAL_IN)
			evflags |= PEIOS_PNP_EV_F_REJECT_DEGRADED;
		peios_pnp_event_emit(&snap, &out, layers[i], evflags);

		switch (out.verdict) {
		case PEIOS_PNP_VERDICT_PASS:
			atomic64_inc(&peios_pnp_stats.verdict_pass);
			continue;
		case PEIOS_PNP_VERDICT_REJECT:
			atomic64_inc(&peios_pnp_stats.verdict_reject);
			return apply_reject(skb, state, &snap, out.reject_kind);
		case PEIOS_PNP_VERDICT_DROP:
		default:
			atomic64_inc(&peios_pnp_stats.verdict_drop);
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

unsigned int peios_pnp_hook_ingress(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	/* RawPacket judges everything here; the Packet layer joins as
	 * fallback iff the traversal never reaches its proper seat.
	 */
	u8 layers[2] = { PEIOS_PNP_LAYER_RAWPACKET, PEIOS_PNP_LAYER_PACKET };
	int n_layers = 1;

	atomic64_inc(&peios_pnp_stats.seen_ingress);

	if (peios_pnp_traversal_reaches_ip_seat(skb->protocol, state->in)) {
		atomic64_inc(&peios_pnp_stats.deferred);
	} else {
		atomic64_inc(&peios_pnp_stats.fallback_judged);
		n_layers = 2;
	}
	return judge(skb, state->in, state, PEIOS_PNP_SEAT_INGRESS,
		     PEIOS_PNP_DIR_IN, layers, n_layers);
}

unsigned int peios_pnp_hook_egress(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	/* Outbound traversal order: the Packet layer's proper seat, then
	 * wire-proximate RawPacket last.
	 */
	static const u8 layers[2] = { PEIOS_PNP_LAYER_PACKET,
				      PEIOS_PNP_LAYER_RAWPACKET };

	atomic64_inc(&peios_pnp_stats.seen_egress);
	return judge(skb, state->out, state, PEIOS_PNP_SEAT_EGRESS,
		     PEIOS_PNP_DIR_OUT, layers, 2);
}

unsigned int peios_pnp_hook_local_in(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	static const u8 layers[1] = { PEIOS_PNP_LAYER_PACKET };

	atomic64_inc(&peios_pnp_stats.seen_local_in);
	return judge(skb, state->in, state, PEIOS_PNP_SEAT_LOCAL_IN,
		     PEIOS_PNP_DIR_IN, layers, 1);
}
