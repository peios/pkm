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
 *    The stack's own RST/ICMP handlers then fail the local socket at once
 *    (ECONNREFUSED, EHOSTUNREACH, or EACCES for IPv6 admin-prohibited),
 *    instead of a connect timeout; see the deferred refusals below.
 *
 * Every answer carries the skb refusal bit: NTFE does not judge its own
 * refusals, and every seat waves them through (seats.c). That also closes
 * the pre-existing hole where an inbound REJECT's RST crossed the egress
 * seat and could be dropped, and mis-attributed, by an outbound rule.
 *
 * What still degrades to DROP (counted, and confessed in the event): a
 * protocol with no refusal vocabulary (non-IP), a broadcast or multicast
 * destination, a packet the builders refuse to answer (a non-first
 * fragment, a failed checksum, a refusal of a refusal), an ingress frame
 * on a non-Ethernet device (no link header to answer through), or an
 * allocation failure.
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
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>

#include "ntfe.h"

static bool ntfe_dst_is_group(const struct sk_buff *skb,
			     const struct peios_ntfe_snapshot *snap)
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

struct sk_buff *peios_ntfe_refuse_build(struct sk_buff *skb,
				       const struct nf_hook_state *state,
				       const struct peios_ntfe_snapshot *snap,
				       u8 kind)
{
	const struct net_device *dev = state->in ? state->in : state->out;
	bool prohibited = kind == PEIOS_NTFE_REJECT_PROHIBITED;
	bool tcp = snap->protocol == IPPROTO_TCP;
	struct sk_buff *nskb = NULL;
	int noff = skb_network_offset(skb);

	if (ntfe_dst_is_group(skb, snap))
		return NULL;

	/*
	 * The builders read the offending packet's headers, lengths and
	 * transport offset relative to skb->data, assuming it points at the
	 * network header, as it does at every hook they were written for.
	 * At the egress seat it points at the link header the device has
	 * already pushed, and the answer came out built from the wrong
	 * bytes (PEI-1300). The packet is pulled to its network header for
	 * the build, and pushed back after it.
	 */
	if (noff < 0)
		return NULL;
	__skb_pull(skb, noff);

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
	__skb_push(skb, noff);
	if (!nskb)
		return NULL;

	nskb->ntfe_refusal = 1;
	/* The answer belongs to the flow it refuses (reply direction), so
	 * conntrack files it rather than tracking it anew.
	 */
	nf_ct_attach(nskb, skb);
	if (tcp && !prohibited && skb_nfct(skb))
		nf_ct_set_closing(skb_nfct(skb));
	return nskb;
}

/* The wire: the answer goes back out the device the frame came in on. */
static bool ntfe_refuse_send_wire(struct sk_buff *nskb, struct sk_buff *skb,
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

/*
 * The far end. A refusal answers the packet in hand, so it reaches the
 * end that sent it; the other end of an ESTABLISHED TCP connection would
 * learn only on its own next packet — never, for a quiet peer. TCP has
 * one teardown a peer understands mid-connection, a reset, and the
 * refused packet carries the sequence number to make one: the packet
 * itself, turned into a reset and sent where it was going. Outbound,
 * that reaches the peer on the wire; inbound, our own socket over the
 * loopback route. Both ends fail at once. New flows have no far end to
 * tear down, and UDP has no connection state; neither gets one.
 */
struct sk_buff *peios_ntfe_teardown_build(const struct sk_buff *skb,
					 const struct nf_hook_state *state,
					 const struct peios_ntfe_snapshot *snap)
{
	struct sk_buff *nskb;
	struct tcphdr _oth, *tcph;
	const struct tcphdr *oth;
	int thoff;

	if (snap->protocol != IPPROTO_TCP ||
	    snap->flow_state != PEIOS_NTFE_FLOW_ESTABLISHED)
		return NULL;
	/* No reset for a reset (the refusal already answered it). */
	if (!(snap->has & PEIOS_NTFE_HAS_TCP_FLAGS) || (snap->tcp_flags & 0x04))
		return NULL;

	if (snap->addr_family == 4) {
		thoff = skb_network_offset(skb) + ip_hdrlen(skb);
	} else if (snap->addr_family == 6) {
		u8 proto = ipv6_hdr(skb)->nexthdr;
		__be16 frag_off;

		thoff = ipv6_skip_exthdr(skb,
					 skb_network_offset(skb) +
						 sizeof(struct ipv6hdr),
					 &proto, &frag_off);
		if (thoff < 0 || proto != IPPROTO_TCP || frag_off)
			return NULL;
	} else {
		return NULL;
	}
	oth = skb_header_pointer(skb, thoff, sizeof(_oth), &_oth);
	if (!oth)
		return NULL;

	nskb = alloc_skb(LL_MAX_HEADER + sizeof(struct ipv6hdr) +
			 sizeof(struct tcphdr), GFP_ATOMIC);
	if (!nskb)
		return NULL;
	skb_reserve(nskb, LL_MAX_HEADER);
	skb_reset_network_header(nskb);

	if (snap->addr_family == 4) {
		const struct iphdr *oiph = ip_hdr(skb);
		struct iphdr *niph = skb_put_zero(nskb, sizeof(*niph));

		niph->version = 4;
		niph->ihl = sizeof(*niph) / 4;
		niph->frag_off = htons(IP_DF);
		niph->protocol = IPPROTO_TCP;
		niph->saddr = oiph->saddr;
		niph->daddr = oiph->daddr;
		niph->ttl = READ_ONCE(state->net->ipv4.sysctl_ip_default_ttl);
		nskb->protocol = htons(ETH_P_IP);
	} else {
		const struct ipv6hdr *oip6h = ipv6_hdr(skb);
		struct ipv6hdr *nip6h = skb_put_zero(nskb, sizeof(*nip6h));

		ip6_flow_hdr(nip6h, 0, 0);
		nip6h->hop_limit =
			READ_ONCE(state->net->ipv6.devconf_all->hop_limit);
		nip6h->nexthdr = IPPROTO_TCP;
		nip6h->saddr = oip6h->saddr;
		nip6h->daddr = oip6h->daddr;
		nskb->protocol = htons(ETH_P_IPV6);
	}

	skb_set_transport_header(nskb, nskb->len);
	tcph = skb_put_zero(nskb, sizeof(*tcph));
	tcph->source = oth->source;
	tcph->dest = oth->dest;
	tcph->seq = oth->seq;
	tcph->ack_seq = oth->ack_seq;
	tcph->ack = oth->ack;
	tcph->rst = 1;
	tcph->doff = sizeof(*tcph) / 4;

	if (snap->addr_family == 4) {
		struct iphdr *niph = ip_hdr(nskb);

		tcph->check = ~tcp_v4_check(sizeof(*tcph), niph->saddr,
					    niph->daddr, 0);
		nskb->ip_summed = CHECKSUM_PARTIAL;
		nskb->csum_start = (unsigned char *)tcph - nskb->head;
		nskb->csum_offset = offsetof(struct tcphdr, check);
		niph->tot_len = htons(nskb->len);
		ip_send_check(niph);
	} else {
		struct ipv6hdr *nip6h = ipv6_hdr(nskb);

		nip6h->payload_len = htons(sizeof(*tcph));
		tcph->check = csum_ipv6_magic(&nip6h->saddr, &nip6h->daddr,
					      sizeof(*tcph), IPPROTO_TCP,
					      csum_partial(tcph, sizeof(*tcph),
							   0));
	}

	nskb->ntfe_refusal = 1;
	return nskb;
}

/*
 * Deferred refusals. An outbound packet is refused in its sender's own
 * context more often than not — connect() sends its SYN holding the
 * socket — and the answer to ourselves is handled on the spot, as the
 * loopback device delivers it when the transmit path re-enables bottom
 * halves. TCP files an ICMP error that reaches a socket its owner holds
 * as a soft error, which fails the connect only at the first SYN
 * retransmission (PEI-1307; IPv4's error queue happened to wake a
 * poller, IPv6's does not). A RST is safe: TCP queues it on the socket's
 * backlog and handles it when the owner lets go. So an ICMP refusal of
 * a TCP sender that is held is sent a tick later instead, by which time
 * the call that sent the refused packet has returned. A full queue sends
 * at once (the soft error is the old behaviour, not a lost answer).
 */
#define NTFE_DEFERRED_REFUSALS_MAX	256

static struct sk_buff_head ntfe_deferred_refusals;

static void ntfe_deferred_refusals_workfn(struct work_struct *work)
{
	struct sk_buff *nskb;

	while ((nskb = skb_dequeue(&ntfe_deferred_refusals))) {
		struct net *net = dev_net(skb_dst(nskb)->dev);

		local_bh_disable();
		if (nskb->protocol == htons(ETH_P_IP))
			ip_local_out(net, NULL, nskb);
		else
			ip6_local_out(net, NULL, nskb);
		local_bh_enable();
	}
}

static DECLARE_DELAYED_WORK(ntfe_deferred_refusals_work,
			    ntfe_deferred_refusals_workfn);

void __init peios_ntfe_refuse_init(void)
{
	skb_queue_head_init(&ntfe_deferred_refusals);
}

/* Whether the answer must wait for the refused packet's sender to let go
 * of its socket. Only an outbound packet's socket is its sender: inbound,
 * a socket on the skb is the receiver early demux found.
 */
static bool ntfe_refusal_must_wait(const struct sk_buff *nskb,
				   const struct sk_buff *skb, bool outbound)
{
	const struct sock *sk = skb->sk;
	u8 proto;

	if (!outbound || !sk || !sk_fullsock(sk) ||
	    sk->sk_protocol != IPPROTO_TCP ||
	    !sock_owned_by_user_nocheck(sk))
		return false;
	proto = nskb->protocol == htons(ETH_P_IP) ? ip_hdr(nskb)->protocol :
						    ipv6_hdr(nskb)->nexthdr;
	return proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6;
}

/*
 * An inbound answer to a link-local address. ip6_route_me_harder scopes a
 * link-local lookup to the old route's device, and an inbound packet's
 * old route is the local delivery route, whose device is the loopback —
 * so the refusal to a link-local peer found no route and degraded to
 * DROP (PEI-1383). A link-local address means something only on its
 * link, and the link is the one the packet arrived on: route there.
 */
static int ntfe_route6_on_ingress(struct net *net, struct sk_buff *nskb,
				  int iif)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(nskb);
	struct flowi6 fl6 = {
		.flowi6_oif = iif,
		.flowi6_mark = nskb->mark,
		.daddr = ip6h->daddr,
		.saddr = ip6h->saddr,
		.flowlabel = ip6_flowinfo(ip6h),
	};
	struct dst_entry *dst;
	unsigned int hh_len;

	dst = ip6_route_output(net, NULL, &fl6);
	if (dst->error) {
		int err = dst->error;

		dst_release(dst);
		return err;
	}
	skb_dst_drop(nskb);
	skb_dst_set(nskb, dst);

	hh_len = dst->dev->hard_header_len;
	if (skb_headroom(nskb) < hh_len &&
	    pskb_expand_head(nskb, HH_DATA_ALIGN(hh_len - skb_headroom(nskb)),
			     0, GFP_ATOMIC))
		return -ENOMEM;
	return 0;
}

static bool ntfe_answer6_on_ingress(const struct sk_buff *nskb,
				    const struct sk_buff *skb,
				    const struct peios_ntfe_snapshot *snap)
{
	return snap->direction == PEIOS_NTFE_DIR_IN && skb->skb_iif &&
	       (ipv6_addr_type(&ipv6_hdr(nskb)->daddr) & IPV6_ADDR_LINKLOCAL);
}

/* Route the packet by its own destination and hand it to the output
 * path: a refusal to ourselves lands on the loopback device, a teardown
 * toward the peer goes out to the wire.
 */
static bool ntfe_refuse_send_self(struct sk_buff *nskb, struct sk_buff *skb,
				 const struct nf_hook_state *state,
				 const struct peios_ntfe_snapshot *snap)
{
	u8 family = snap->addr_family;
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
	} else if (ntfe_answer6_on_ingress(nskb, skb, snap)) {
		if (ntfe_route6_on_ingress(net, nskb, skb->skb_iif))
			goto drop;
	} else {
		if (ip6_route_me_harder(net, NULL, nskb))
			goto drop;
	}
	/* The route is now the answer's own, counted: it can wait. */
	if (ntfe_refusal_must_wait(nskb, skb,
				   snap->direction == PEIOS_NTFE_DIR_OUT) &&
	    skb_queue_len_lockless(&ntfe_deferred_refusals) <
		    NTFE_DEFERRED_REFUSALS_MAX) {
		skb_queue_tail(&ntfe_deferred_refusals, nskb);
		schedule_delayed_work(&ntfe_deferred_refusals_work, 1);
		return true;
	}
	if (family == 4)
		ip_local_out(net, NULL, nskb);
	else
		ip6_local_out(net, NULL, nskb);
	return true;
drop:
	kfree_skb(nskb);
	return false;
}

bool peios_ntfe_refuse(struct sk_buff *skb, const struct nf_hook_state *state,
		      const struct peios_ntfe_snapshot *snap, u8 kind)
{
	struct sk_buff *nskb;
	bool sent;

	nskb = peios_ntfe_refuse_build(skb, state, snap, kind);
	if (!nskb) {
		atomic64_inc(&peios_ntfe_stats.reject_degraded);
		return false;
	}
	if (snap->seat == PEIOS_NTFE_SEAT_INGRESS)
		sent = ntfe_refuse_send_wire(nskb, skb, state->in);
	else
		sent = ntfe_refuse_send_self(nskb, skb, state, snap);
	if (sent)
		atomic64_inc(&peios_ntfe_stats.refusals_emitted);
	else
		atomic64_inc(&peios_ntfe_stats.reject_degraded);

	/* An established TCP connection is torn down at both ends. */
	if (snap->seat != PEIOS_NTFE_SEAT_INGRESS) {
		struct sk_buff *reset = peios_ntfe_teardown_build(skb, state,
								 snap);

		if (reset && ntfe_refuse_send_self(reset, skb, state, snap))
			atomic64_inc(&peios_ntfe_stats.teardowns_emitted);
	}
	return sent;
}
