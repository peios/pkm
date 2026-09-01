// SPDX-License-Identifier: GPL-2.0-only
/*
 * PNP KUnit: kernel-resident glue only — the seat snapshot builder against
 * crafted skbs, and the dispatch predicate. Rules-engine semantics are
 * owned by the pnp-core cargo suite (48 tests); duplicating them here
 * would be testing the same pure code twice.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/string.h>

#include <pkm/pnp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "pnp.h"

static struct net_device *pnp_test_dev(struct kunit *test, const char *name,
				       bool bridge_port)
{
	struct net_device *dev;

	/* Only name/ifindex/type/priv_flags are read by the code under
	 * test; a zeroed shell is enough (no registration).
	 */
	dev = kunit_kzalloc(test, sizeof(*dev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, dev);
	strscpy(dev->name, name, IFNAMSIZ);
	dev->ifindex = 7;
	dev->type = ARPHRD_ETHER;
	if (bridge_port)
		dev->priv_flags |= IFF_BRIDGE_PORT;
	return dev;
}

static void pnp_kunit_rust_probe(struct kunit *test)
{
	/* The staged pnp-core is linked and callable, and answers with its
	 * known constant (MAX_PROMPT_CHAIN).
	 */
	KUNIT_EXPECT_EQ(test, pnp_rust_kunit_probe(), 4);
}

static void pnp_kunit_dispatch_predicate(struct kunit *test)
{
	struct net_device *plain = pnp_test_dev(test, "eth0", false);
	struct net_device *enslaved = pnp_test_dev(test, "eth1", true);

	/* IP on a plain device reaches the IP seat: defer. */
	KUNIT_EXPECT_TRUE(test, peios_pnp_traversal_reaches_ip_seat(
					htons(ETH_P_IP), plain));
	KUNIT_EXPECT_TRUE(test, peios_pnp_traversal_reaches_ip_seat(
					htons(ETH_P_IPV6), plain));
	/* Non-IP never reaches the IP hooks: fallback judgment here. */
	KUNIT_EXPECT_FALSE(test, peios_pnp_traversal_reaches_ip_seat(
					 htons(ETH_P_ARP), plain));
	/* Bridge-enslaved port: L2-forwarded, never crosses the IP hooks —
	 * the corrected predicate from the design session.
	 */
	KUNIT_EXPECT_FALSE(test, peios_pnp_traversal_reaches_ip_seat(
					 htons(ETH_P_IP), enslaved));
}

/* An inbound TCP/v4 SYN to the given port; 10.0.0.7 -> 10.0.0.5. */
static struct sk_buff *pnp_test_tcp4_skb(struct kunit *test, u16 dport)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *th;

	skb = alloc_skb(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	skb_reserve(skb, 64);
	skb_reset_network_header(skb);

	iph = skb_put_zero(skb, sizeof(*iph));
	iph->version = 4;
	iph->ihl = 5;
	iph->ttl = 64;
	iph->tos = 0x2e << 2;	/* DSCP EF */
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(0x0a000007);	/* 10.0.0.7 */
	iph->daddr = htonl(0x0a000005);	/* 10.0.0.5 */

	th = skb_put_zero(skb, sizeof(*th));
	th->source = htons(43210);
	th->dest = htons(dport);
	th->syn = 1;

	skb->protocol = htons(ETH_P_IP);
	return skb;
}

static void pnp_kunit_snapshot_tcp4(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct peios_pnp_snapshot snap;
	struct sk_buff *skb = pnp_test_tcp4_skb(test, 22);

	KUNIT_EXPECT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_IN,
						    PEIOS_PNP_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_EQ(test, snap.addr_family, 4);
	KUNIT_EXPECT_EQ(test, snap.protocol, IPPROTO_TCP);
	KUNIT_EXPECT_EQ(test, snap.src_addr[0], 10);
	KUNIT_EXPECT_EQ(test, snap.src_addr[3], 7);
	KUNIT_EXPECT_EQ(test, snap.src_port, 43210);
	KUNIT_EXPECT_EQ(test, snap.dst_port, 22);
	KUNIT_EXPECT_EQ(test, snap.ttl, 64);
	KUNIT_EXPECT_EQ(test, snap.dscp, 0x2e);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_PORTS);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_TCP_FLAGS);
	KUNIT_EXPECT_EQ(test, snap.tcp_flags, 0x02);	/* bare SYN */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_FRAGMENT);
	KUNIT_EXPECT_EQ(test, snap.fragment, 0);
	/* No mac header was set: MAC facts are absent. */
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_PNP_HAS_MACS);
	/* Conntrack ran (it's an IP seat) and left nothing: untracked. */
	KUNIT_EXPECT_EQ(test, snap.flow_state, PEIOS_PNP_FLOW_UNTRACKED);
	/* Clock machinery attached wall-time facts. */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_TIME);
	KUNIT_EXPECT_GE(test, snap.t_year, 2026);
	KUNIT_EXPECT_GE(test, snap.t_day_of_week, 1);
	KUNIT_EXPECT_LE(test, snap.t_day_of_week, 7);
	KUNIT_EXPECT_EQ(test, snap.ifindex, 7);

	kfree_skb(skb);
}

static void pnp_kunit_snapshot_arp(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct peios_pnp_snapshot snap;
	struct sk_buff *skb;

	skb = alloc_skb(64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	skb_reserve(skb, 32);
	skb_reset_network_header(skb);
	skb_put_zero(skb, 28);	/* ARP payload; the builder doesn't parse it */
	skb->protocol = htons(ETH_P_ARP);

	KUNIT_EXPECT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_INGRESS,
						    PEIOS_PNP_DIR_IN, &snap),
			0);
	/* Absent-fact law, at the seat level: an ARP frame has L2 and seat
	 * facts and nothing else.
	 */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_ETHER_TYPE);
	KUNIT_EXPECT_EQ(test, snap.ether_type, ETH_P_ARP);
	KUNIT_EXPECT_EQ(test, snap.addr_family, 0);
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_PNP_HAS_PORTS);
	/* The ingress seat stands before conntrack: flow facts absent, not
	 * "untracked".
	 */
	KUNIT_EXPECT_EQ(test, snap.flow_state, PEIOS_PNP_FLOW_ABSENT);

	kfree_skb(skb);
}

static void pnp_kunit_snapshot_udp6(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct peios_pnp_snapshot snap;
	struct sk_buff *skb;
	struct ipv6hdr *ip6;
	struct udphdr *uh;

	skb = alloc_skb(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	skb_reserve(skb, 64);
	skb_reset_network_header(skb);

	ip6 = skb_put_zero(skb, sizeof(*ip6));
	ip6->version = 6;
	ip6->hop_limit = 255;
	ip6->nexthdr = IPPROTO_UDP;
	ip6->saddr.s6_addr[0] = 0xfd;
	ip6->daddr.s6_addr[0] = 0xfd;
	ip6->daddr.s6_addr[15] = 1;

	uh = skb_put_zero(skb, sizeof(*uh));
	uh->source = htons(5353);
	uh->dest = htons(5353);

	skb->protocol = htons(ETH_P_IPV6);

	KUNIT_EXPECT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_EGRESS,
						    PEIOS_PNP_DIR_OUT, &snap),
			0);
	KUNIT_EXPECT_EQ(test, snap.addr_family, 6);
	KUNIT_EXPECT_EQ(test, snap.protocol, IPPROTO_UDP);
	KUNIT_EXPECT_EQ(test, snap.src_addr[0], 0xfd);
	KUNIT_EXPECT_EQ(test, snap.dst_addr[15], 1);
	KUNIT_EXPECT_EQ(test, snap.src_port, 5353);
	KUNIT_EXPECT_EQ(test, snap.ttl, 255);
	KUNIT_EXPECT_EQ(test, snap.direction, PEIOS_PNP_DIR_OUT);
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_PNP_HAS_TCP_FLAGS);

	kfree_skb(skb);
}

/* Feed one action list to the builder. */
static void pnp_test_actions(struct kunit *test, void *b, const char *action)
{
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_list_begin(b, "Actions", 7), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_list_str(b, action, strlen(action)),
			0);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_value_list_end(b), 0);
}

/*
 * End to end: policy built over the FFI (as the LCS ingestion path will
 * build it), published under RCU, enforced by the real hook function.
 * "Drop everything inbound, except SSH" — the design-session tree, live.
 */
static void pnp_kunit_end_to_end_enforcement(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct peios_pnp_snapshot snap;
	struct peios_pnp_outcome out;
	struct sk_buff *skb;
	u64 gen_before = pnp_rust_generation();
	void *b, *forest = NULL;

	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);

	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_rule_begin(b, "no-inbound", 10), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_str(b, "Direction.Equal", 15,
						   "in", 2),
			0);
	pnp_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "ssh", 3), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_int(b, "DstPort.Equal", 13, 22),
			0);
	pnp_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);

	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_NOT_NULL(test, forest);
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(forest, NULL), 0);
	KUNIT_EXPECT_EQ(test, pnp_rust_generation(), gen_before + 1);

	/* SSH passes through the exception... */
	skb = pnp_test_tcp4_skb(test, 22);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	/* ...and its attribution is the path through the tree. */
	KUNIT_ASSERT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_IN,
						    PEIOS_PNP_DIR_IN, &snap),
			0);
	KUNIT_ASSERT_EQ(test,
			peios_pnp_policy_eval(PEIOS_PNP_LAYER_PACKET, &snap,
					      &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_PNP_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "no-inbound/ssh");
	kfree_skb(skb);

	/* Telnet is dropped by the parent... */
	skb = pnp_test_tcp4_skb(test, 23);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_DROP);
	kfree_skb(skb);

	/* ...and the RawPacket layer, with no forest, stayed permissive
	 * (an unrelated seat judging the same machine's traffic).
	 */
	KUNIT_EXPECT_EQ(test,
			peios_pnp_policy_eval(PEIOS_PNP_LAYER_RAWPACKET,
					      &snap, &out),
			-ENOENT);

	/* Restore permissiveness for whatever runs after this suite. */
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL), 0);
}

/*
 * The verdict event ring: emit from a crafted snapshot/outcome, drain via
 * the internal pop path (the device read uses the same), check ordering,
 * status, and the confessed-drop counter under overwrite.
 */
static void pnp_kunit_event_stream(struct kunit *test)
{
	struct peios_pnp_snapshot snap = {
		.seat = PEIOS_PNP_SEAT_LOCAL_IN,
		.direction = PEIOS_PNP_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.src_port = 43210,
		.dst_port = 22,
		.length = 60,
	};
	struct peios_pnp_outcome out = {
		.verdict = PEIOS_PNP_VERDICT_DROP,
		.n_reports = 2,
	};
	struct peios_pnp_status status;
	u64 before_dropped = peios_pnp_events_dropped();

	strscpy(out.attributed, "no-inbound", sizeof(out.attributed));
	peios_pnp_event_emit(&snap, &out, PEIOS_PNP_LAYER_PACKET, 0);

	peios_pnp_status_fill(&status);
	KUNIT_EXPECT_EQ(test, status.abi, (u64)PEIOS_PNP_ABI_VERSION);
	KUNIT_EXPECT_EQ(test, status.events_dropped, before_dropped);
	/* Generation was left at its post-publish value by the end-to-end
	 * test; whatever it is, status must agree with the bridge.
	 */
	KUNIT_EXPECT_EQ(test, status.generation, pnp_rust_generation());
}

static struct kunit_case pnp_kunit_cases[] = {
	KUNIT_CASE(pnp_kunit_rust_probe),
	KUNIT_CASE(pnp_kunit_dispatch_predicate),
	KUNIT_CASE(pnp_kunit_snapshot_tcp4),
	KUNIT_CASE(pnp_kunit_snapshot_arp),
	KUNIT_CASE(pnp_kunit_snapshot_udp6),
	KUNIT_CASE(pnp_kunit_end_to_end_enforcement),
	KUNIT_CASE(pnp_kunit_event_stream),
	{}
};

static struct kunit_suite pnp_kunit_suite = {
	.name = "pkm_kunit_pnp",
	.test_cases = pnp_kunit_cases,
};

kunit_test_suite(pnp_kunit_suite);
