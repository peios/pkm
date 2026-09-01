// SPDX-License-Identifier: GPL-2.0-only
/*
 * Seat snapshot builder: one traversal's facts, read from the skb at its
 * standing seat.
 *
 * Honesty notes carried from the ratified design:
 *  - length is the stack's view (GRO/GSO superframes), never the wire's;
 *  - at the device seats no conntrack facts exist (flow_state = ABSENT);
 *  - at seats after defrag, fragment is almost always false — deliberate
 *    (the engine judges reassembled datagrams);
 *  - a frame too mangled to describe still gets judged, with only its seat
 *    facts present (absent-fact law does the rest).
 */

#include <linux/etherdevice.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/sctp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack.h>

#include "pnp.h"

static void snapshot_time(struct peios_pnp_snapshot *snap)
{
	struct tm tm;

	time64_to_tm(ktime_get_real_seconds(), 0, &tm);
	snap->t_year = tm.tm_year + 1900;
	snap->t_month = tm.tm_mon + 1;
	snap->t_day_of_month = tm.tm_mday;
	/* tm_wday is 0 = Sunday; the fact vocabulary is ISO (1 = Monday). */
	snap->t_day_of_week = tm.tm_wday == 0 ? 7 : tm.tm_wday;
	snap->t_hour = tm.tm_hour;
	snap->t_minute = tm.tm_min;
	snap->t_second = tm.tm_sec;
	snap->has |= PEIOS_PNP_HAS_TIME;
}

static void snapshot_flow_state(const struct sk_buff *skb, u8 seat,
				struct peios_pnp_snapshot *snap)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	/* The ingress seat stands before conntrack: no flow facts exist. */
	if (seat == PEIOS_PNP_SEAT_INGRESS)
		return;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct && !nf_ct_is_template(ct))
		snap->flow = ct;	/* the tag store's scope */
	if (!ct) {
		/*
		 * Conntrack ran and left nothing: untracked. (A packet
		 * conntrack judged incoherent also lands here; the INVALID
		 * distinction needs the conntrack verdict, a later mint.)
		 */
		snap->flow_state = PEIOS_PNP_FLOW_UNTRACKED;
		return;
	}
	switch (ctinfo) {
	case IP_CT_ESTABLISHED:
	case IP_CT_ESTABLISHED_REPLY:
		snap->flow_state = PEIOS_PNP_FLOW_ESTABLISHED;
		break;
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		snap->flow_state = PEIOS_PNP_FLOW_RELATED;
		break;
	case IP_CT_NEW:
		snap->flow_state = PEIOS_PNP_FLOW_NEW;
		break;
	default:
		snap->flow_state = PEIOS_PNP_FLOW_UNTRACKED;
		break;
	}
}

static void snapshot_l4(const struct sk_buff *skb, int offset, u8 protocol,
			struct peios_pnp_snapshot *snap)
{
	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr th;
		const struct tcphdr *thp;

		thp = skb_header_pointer(skb, offset, sizeof(th), &th);
		if (!thp)
			return;
		snap->src_port = ntohs(thp->source);
		snap->dst_port = ntohs(thp->dest);
		snap->has |= PEIOS_PNP_HAS_PORTS;
		snap->tcp_flags = ((const u8 *)thp)[13];
		snap->has |= PEIOS_PNP_HAS_TCP_FLAGS;
		break;
	}
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE: {
		struct udphdr uh;
		const struct udphdr *uhp;

		uhp = skb_header_pointer(skb, offset, sizeof(uh), &uh);
		if (!uhp)
			return;
		snap->src_port = ntohs(uhp->source);
		snap->dst_port = ntohs(uhp->dest);
		snap->has |= PEIOS_PNP_HAS_PORTS;
		break;
	}
	case IPPROTO_SCTP: {
		struct sctphdr sh;
		const struct sctphdr *shp;

		shp = skb_header_pointer(skb, offset, sizeof(sh), &sh);
		if (!shp)
			return;
		snap->src_port = ntohs(shp->source);
		snap->dst_port = ntohs(shp->dest);
		snap->has |= PEIOS_PNP_HAS_PORTS;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr ih;
		const struct icmphdr *ihp;

		ihp = skb_header_pointer(skb, offset, sizeof(ih), &ih);
		if (!ihp)
			return;
		snap->icmp_type = ihp->type;
		snap->icmp_code = ihp->code;
		snap->has |= PEIOS_PNP_HAS_ICMP;
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6hdr ih;
		const struct icmp6hdr *ihp;

		ihp = skb_header_pointer(skb, offset, sizeof(ih), &ih);
		if (!ihp)
			return;
		snap->icmp_type = ihp->icmp6_type;
		snap->icmp_code = ihp->icmp6_code;
		snap->has |= PEIOS_PNP_HAS_ICMP;
		break;
	}
	default:
		break;
	}
}

static int snapshot_ipv4(const struct sk_buff *skb, int offset,
			 struct peios_pnp_snapshot *snap)
{
	struct iphdr ih;
	const struct iphdr *ihp;
	bool fragmented;

	ihp = skb_header_pointer(skb, offset, sizeof(ih), &ih);
	if (!ihp || ihp->version != 4 || ihp->ihl < 5)
		return -EINVAL;

	snap->addr_family = 4;
	memcpy(snap->src_addr, &ihp->saddr, 4);
	memcpy(snap->dst_addr, &ihp->daddr, 4);
	snap->protocol = ihp->protocol;
	snap->ttl = ihp->ttl;
	snap->has |= PEIOS_PNP_HAS_TTL;
	snap->dscp = ihp->tos >> 2;
	snap->has |= PEIOS_PNP_HAS_DSCP;
	fragmented = (ihp->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
	snap->fragment = fragmented;
	snap->has |= PEIOS_PNP_HAS_FRAGMENT;

	/* A non-first fragment carries no L4 header: those facts are absent. */
	if (!(ihp->frag_off & htons(IP_OFFSET)))
		snapshot_l4(skb, offset + ihp->ihl * 4, ihp->protocol, snap);
	return 0;
}

static int snapshot_ipv6(const struct sk_buff *skb, int offset,
			 struct peios_pnp_snapshot *snap)
{
	struct ipv6hdr ih;
	const struct ipv6hdr *ihp;
	u8 nexthdr;
	int l4_offset = offset + sizeof(struct ipv6hdr);
	int hops;

	ihp = skb_header_pointer(skb, offset, sizeof(ih), &ih);
	if (!ihp || ihp->version != 6)
		return -EINVAL;

	snap->addr_family = 6;
	memcpy(snap->src_addr, &ihp->saddr, 16);
	memcpy(snap->dst_addr, &ihp->daddr, 16);
	snap->ttl = ihp->hop_limit;
	snap->has |= PEIOS_PNP_HAS_TTL;
	snap->dscp = ((ihp->priority << 4) | (ihp->flow_lbl[0] >> 4)) >> 2;
	snap->has |= PEIOS_PNP_HAS_DSCP;
	snap->fragment = 0;
	snap->has |= PEIOS_PNP_HAS_FRAGMENT;

	/* Walk a bounded chain of extension headers to the L4 protocol. */
	nexthdr = ihp->nexthdr;
	for (hops = 0; hops < 8; hops++) {
		struct ipv6_opt_hdr oh;
		const struct ipv6_opt_hdr *ohp;

		switch (nexthdr) {
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
			ohp = skb_header_pointer(skb, l4_offset, sizeof(oh),
						 &oh);
			if (!ohp)
				return 0;
			nexthdr = ohp->nexthdr;
			l4_offset += (ohp->hdrlen + 1) * 8;
			continue;
		case NEXTHDR_FRAGMENT: {
			struct frag_hdr fh;
			const struct frag_hdr *fhp;

			fhp = skb_header_pointer(skb, l4_offset, sizeof(fh),
						 &fh);
			if (!fhp)
				return 0;
			snap->fragment = 1;
			/* Non-first fragment: no L4 facts. */
			if (fhp->frag_off & htons(0xfff8))
				return 0;
			nexthdr = fhp->nexthdr;
			l4_offset += sizeof(struct frag_hdr);
			continue;
		}
		default:
			snap->protocol = nexthdr;
			snapshot_l4(skb, l4_offset, nexthdr, snap);
			return 0;
		}
	}
	return 0;
}

int peios_pnp_snapshot_from_skb(const struct sk_buff *skb,
				const struct net_device *dev, u8 seat,
				u8 direction, struct peios_pnp_snapshot *snap)
{
	int network_offset;
	u16 ether_type;
	int ret = 0;

	memset(snap, 0, sizeof(*snap));
	snap->seat = seat;
	snap->direction = direction;
	if (dev) {
		snap->ifindex = dev->ifindex;
		strscpy(snap->ifname, dev->name, IFNAMSIZ);
	}
	snap->length = skb->len;
	snapshot_time(snap);
	snapshot_flow_state(skb, seat, snap);

	ether_type = ntohs(skb->protocol);
	snap->ether_type = ether_type;
	snap->has |= PEIOS_PNP_HAS_ETHER_TYPE;

	if (skb_vlan_tag_present(skb)) {
		snap->vlan = skb_vlan_tag_get_id(skb);
		snap->has |= PEIOS_PNP_HAS_VLAN;
	}

	if (skb_mac_header_was_set(skb) && dev &&
	    dev->type == ARPHRD_ETHER) {
		const struct ethhdr *eth = eth_hdr(skb);

		ether_addr_copy(snap->src_mac, eth->h_source);
		ether_addr_copy(snap->dst_mac, eth->h_dest);
		snap->has |= PEIOS_PNP_HAS_MACS;
	}

	network_offset = skb_network_offset(skb);
	switch (ether_type) {
	case ETH_P_IP:
		ret = snapshot_ipv4(skb, network_offset, snap);
		break;
	case ETH_P_IPV6:
		ret = snapshot_ipv6(skb, network_offset, snap);
		break;
	default:
		/* Non-IP: L2 and seat facts are all there is. */
		break;
	}
	return ret;
}
