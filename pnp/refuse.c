// SPDX-License-Identifier: GPL-2.0-only
/*
 * Refusals: the answer a REJECT verdict sends (Flow slice, ratified
 * PEI-598 — "REJECT in every direction").
 *
 * The story is the kind's (Refused = RST for TCP, else port-unreachable;
 * Prohibited = admin-prohibited), and the answer is built by the kernel's
 * own frame-less reject builders — the ones nftables' netdev reject uses —
 * from whichever seat decided. What differs per seat is only delivery:
 *
 *  - the ingress seat answers the peer on the wire, the offending frame's
 *    MACs swapped (nft_reject_netdev verbatim);
 *  - every other seat delivers the answer to ourselves: it is addressed to
 *    us (inbound: from us to the peer, routed out; outbound: the forged
 *    peer answer, routed to a local address), so it goes through the
 *    normal output path and, for the local case, the loopback device —
 *    which retains the route, so no source validation stands in the way.
 *    The stack's own RST/ICMP handlers then fail the local socket with
 *    ECONNREFUSED or EHOSTUNREACH at once, instead of a connect timeout.
 *
 * Every answer carries the skb refusal bit: PNP does not judge its own
 * refusals, and every seat waves them through (seats.c). That also closes
 * the pre-existing hole where an inbound REJECT's RST crossed the egress
 * seat and could be dropped, and mis-attributed, by an outbound rule.
 *
 * What still degrades to DROP (counted, and confessed in the event): a
 * protocol with no refusal vocabulary (non-IP), a broadcast or multicast
 * destination, a packet the builders refuse to answer (fragments, a
 * failed checksum, a refusal of a refusal), or an allocation failure.
 */

#include <linux/etherdevice.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>

#include "pnp.h"

static bool pnp_dst_is_group(const struct sk_buff *skb,
			     const struct peios_pnp_snapshot *snap)
{
	if (snap->addr_family == 4) {
		__be32 d;

		memcpy(&d, snap->dst_addr, 4);
		if (ipv4_is_multicast(d) || ipv4_is_lbcast(d))
			return true;
		/* Subnet broadcast: only the route knows. */
		if (skb_dst(skb) && skb_rtable(skb)->rt_flags &
				    (RTCF_BROADCAST | RTCF_MULTICAST))
			return true;
		return false;
	}
	if (snap->addr_family == 6) {
		struct in6_addr d;

		memcpy(&d, snap->dst_addr, 16);
		return ipv6_addr_is_multicast(&d);
	}
	return true;
}

struct sk_buff *peios_pnp_refuse_build(struct sk_buff *skb,
				       const struct nf_hook_state *state,
				       const struct peios_pnp_snapshot *snap,
				       u8 kind)
{
	const struct net_device *dev = state->in ? state->in : state->out;
	bool prohibited = kind == PEIOS_PNP_REJECT_PROHIBITED;
	bool tcp = snap->protocol == IPPROTO_TCP;
	struct sk_buff *nskb = NULL;

	if (pnp_dst_is_group(skb, snap))
		return NULL;

	if (snap->addr_family == 4) {
		if (prohibited)
			nskb = nf_reject_skb_v4_unreach(state->net, skb, dev,
							state->hook,
							ICMP_PKT_FILTERED);
		else if (tcp)
			nskb = nf_reject_skb_v4_tcp_reset(state->net, skb, dev,
							  state->hook);
		else
			nskb = nf_reject_skb_v4_unreach(state->net, skb, dev,
							state->hook,
							ICMP_PORT_UNREACH);
	} else if (snap->addr_family == 6) {
		if (prohibited)
			nskb = nf_reject_skb_v6_unreach(state->net, skb, dev,
							state->hook,
							ICMPV6_ADM_PROHIBITED);
		else if (tcp)
			nskb = nf_reject_skb_v6_tcp_reset(state->net, skb, dev,
							  state->hook);
		else
			nskb = nf_reject_skb_v6_unreach(state->net, skb, dev,
							state->hook,
							ICMPV6_PORT_UNREACH);
	}
	if (!nskb)
		return NULL;

	nskb->pnp_refusal = 1;
	/* The answer belongs to the flow it refuses (reply direction), so
	 * conntrack files it rather than tracking it anew.
	 */
	nf_ct_attach(nskb, skb);
	if (tcp && !prohibited && skb_nfct(skb))
		nf_ct_set_closing(skb_nfct(skb));
	return nskb;
}

/* The wire: the answer goes back out the device the frame came in on. */
static bool pnp_refuse_send_wire(struct sk_buff *nskb, struct sk_buff *skb,
				 const struct net_device *dev)
{
	const struct ethhdr *eth;

	if (!dev || dev->type != ARPHRD_ETHER || !skb_mac_header_was_set(skb))
		goto drop;
	eth = eth_hdr(skb);
	if (is_multicast_ether_addr(eth->h_dest))
		goto drop;
	nskb->dev = (struct net_device *)dev;
	if (dev_hard_header(nskb, nskb->dev, ntohs(skb->protocol),
			    eth->h_source, eth->h_dest, nskb->len) < 0)
		goto drop;
	dev_queue_xmit(nskb);
	return true;
drop:
	kfree_skb(nskb);
	return false;
}

/* Ourselves: route the answer and hand it to the output path. */
static bool pnp_refuse_send_self(struct sk_buff *nskb, struct sk_buff *skb,
				 const struct nf_hook_state *state, u8 family)
{
	struct net *net = state->net;

	/* The route helpers read the old route's device to choose. */
	if (!skb_dst(skb))
		goto drop;
	skb_dst_set_noref(nskb, skb_dst(skb));
	if (family == 4) {
		if (ip_route_me_harder(net, NULL, nskb, RTN_UNSPEC))
			goto drop;
		if (nskb->len > dst4_mtu(skb_dst(nskb)))
			goto drop;
		ip_local_out(net, NULL, nskb);
	} else {
		if (ip6_route_me_harder(net, NULL, nskb))
			goto drop;
		ip6_local_out(net, NULL, nskb);
	}
	return true;
drop:
	kfree_skb(nskb);
	return false;
}

bool peios_pnp_refuse(struct sk_buff *skb, const struct nf_hook_state *state,
		      const struct peios_pnp_snapshot *snap, u8 kind)
{
	struct sk_buff *nskb;
	bool sent;

	nskb = peios_pnp_refuse_build(skb, state, snap, kind);
	if (!nskb) {
		atomic64_inc(&peios_pnp_stats.reject_degraded);
		return false;
	}
	if (snap->seat == PEIOS_PNP_SEAT_INGRESS)
		sent = pnp_refuse_send_wire(nskb, skb, state->in);
	else
		sent = pnp_refuse_send_self(nskb, skb, state, snap->addr_family);
	if (sent)
		atomic64_inc(&peios_pnp_stats.refusals_emitted);
	else
		atomic64_inc(&peios_pnp_stats.reject_degraded);
	return sent;
}
