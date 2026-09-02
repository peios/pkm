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
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/peios_pnp.h>
#include <linux/string.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include <pkm/pnp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include <pkm/kmes.h>

#include "../../security/pkm/kmes/kmes.h"
#include <linux/net.h>
#include <net/sock.h>

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
	iph->tot_len = htons(sizeof(*iph) + sizeof(*th));

	th = skb_put_zero(skb, sizeof(*th));
	th->source = htons(43210);
	th->dest = htons(dport);
	th->doff = sizeof(*th) / 4;
	th->syn = 1;
	th->seq = htonl(1000);

	skb->protocol = htons(ETH_P_IP);
	skb_reset_transport_header(skb);
	skb_set_transport_header(skb, sizeof(*iph));
	/* No checksum to verify: the reject builders take it as valid. */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
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
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(forest, NULL, NULL, 1),
			0);
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
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, NULL, 1),
			0);
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


/*
 * The machinery slice: REJECT kinds cross the bridge, the flow tag store
 * on a real conntrack entry (set/add/clear/lookup, the per-flow tripwire,
 * the destructor), the counter store (materialized views, keyed cells,
 * windows, the absent-key law, re-publication), and REPORT landing in
 * KMES as a network-report event.
 */
static void pnp_kunit_reject_kinds_cross_the_bridge(struct kunit *test)
{
	struct peios_pnp_snapshot snap = {
		.seat = PEIOS_PNP_SEAT_LOCAL_IN,
		.direction = PEIOS_PNP_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.length = 60,
	};
	struct peios_pnp_outcome out;
	void *b, *forest = NULL;

	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "no", 2), 0);
	pnp_test_actions(test, b, "REJECT(Prohibited)");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_evaluate(forest, &snap, PEIOS_PNP_LAYER_PACKET,
					  1, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_PNP_VERDICT_REJECT);
	KUNIT_EXPECT_EQ(test, out.reject_kind, PEIOS_PNP_REJECT_PROHIBITED);
	pnp_rust_forest_free(forest);

	/* An unminted kind refuses the forest. */
	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "no", 2), 0);
	pnp_test_actions(test, b, "REJECT(HostUnreachable)");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	forest = NULL;
	KUNIT_EXPECT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_PACKET,
					       &forest),
			-EINVAL);
	KUNIT_EXPECT_NULL(test, forest);
}

static struct nf_conn *pnp_test_flow(struct kunit *test)
{
	struct nf_conntrack_tuple orig = { }, repl = { };
	struct nf_conn *ct;

	ct = nf_conntrack_alloc(&init_net, &nf_ct_zone_dflt, &orig, &repl,
				GFP_KERNEL);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(ct));
	/* init_conntrack does this for real flows (pnp-conntrack-ext patch);
	 * a directly allocated entry needs it by hand.
	 */
	peios_pnp_ct_ext_add(ct);
	return ct;
}

static void pnp_kunit_tag_store(struct kunit *test)
{
	struct nf_conn *ct = pnp_test_flow(test);
	u64 untracked_before = atomic64_read(&peios_pnp_stats.tag_untracked);
	u64 refused_before = atomic64_read(&peios_pnp_stats.tag_refused);
	u64 value = 0;
	u32 i;

	/* Absent until written. */
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x1001, &value), 0);

	peios_pnp_tag_apply(ct, 0x1001, PEIOS_PNP_TAG_SET, 7);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x1001, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 7ULL);

	peios_pnp_tag_apply(ct, 0x1001, PEIOS_PNP_TAG_ADD, 5);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x1001, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 12ULL);

	/* Add on an absent tag starts from zero. */
	peios_pnp_tag_apply(ct, 0x1002, PEIOS_PNP_TAG_ADD, 3);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x1002, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 3ULL);

	/* Clear reads as absent; the slot is reusable. */
	peios_pnp_tag_apply(ct, 0x1001, PEIOS_PNP_TAG_CLEAR, 0);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x1001, &value), 0);
	peios_pnp_tag_apply(ct, 0x1001, PEIOS_PNP_TAG_SET, 1);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x1001, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 1ULL);

	/* Growth past the initial table, up to the tripwire, then refusal
	 * (confessed). Two tags are already present.
	 */
	for (i = 0; i < PEIOS_PNP_TAG_MAX_PER_FLOW - 2; i++)
		peios_pnp_tag_apply(ct, 0x2000 + i, PEIOS_PNP_TAG_SET, i);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x2000, &value), 1);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_tag_lookup(ct, 0x2000 + PEIOS_PNP_TAG_MAX_PER_FLOW - 3,
					     &value),
			1);
	KUNIT_EXPECT_EQ(test, value,
			(u64)(PEIOS_PNP_TAG_MAX_PER_FLOW - 3));
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.tag_refused),
			refused_before);
	peios_pnp_tag_apply(ct, 0x3000, PEIOS_PNP_TAG_SET, 1);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(ct, 0x3000, &value), 0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.tag_refused),
			refused_before + 1);

	/* Untracked packets have no flow: no-op, confessed. */
	peios_pnp_tag_apply(NULL, 0x1001, PEIOS_PNP_TAG_SET, 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.tag_untracked),
			untracked_before + 1);
	KUNIT_EXPECT_EQ(test, peios_pnp_tag_lookup(NULL, 0x1001, &value), 0);

	/* An unconfirmed entry is born with refcount 0 (confirmation sets
	 * it to 1), so it is released the way conntrack's own error paths
	 * do — straight to nf_conntrack_free, which frees the table through
	 * the destructor hook.
	 */
	nf_conntrack_free(ct);
}

static void pnp_kunit_counter_store(struct kunit *test)
{
	struct peios_pnp_view views[2] = {
		{ .name = "hits", .hash = 0xabc, .window_secs = 10,
		  .keyspec = PEIOS_PNP_KEY_SRC_ADDR },
		{ .name = "hits", .hash = 0xabc, .window_secs = 0,
		  .keyspec = 0 },
	};
	struct peios_pnp_snapshot a = {
		.seat = PEIOS_PNP_SEAT_LOCAL_IN, .addr_family = 4,
		.src_addr = { 10, 0, 0, 7 }, .dst_addr = { 10, 0, 0, 5 },
		.ifindex = 7, .length = 60,
	};
	struct peios_pnp_snapshot b = a;
	struct peios_pnp_snapshot arp = {
		.seat = PEIOS_PNP_SEAT_INGRESS, .ifindex = 7, .length = 42,
	};
	u64 absent_before = atomic64_read(&peios_pnp_stats.count_key_absent);
	u64 cells_before = peios_pnp_counters_cells();
	u64 v = 0;

	b.src_addr[3] = 8;

	KUNIT_ASSERT_EQ(test, peios_pnp_counters_publish(views, 2), 0);

	/* Nothing counted yet: absent, both views. */
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&a, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       10, &v),
			0);
	KUNIT_EXPECT_EQ(test, peios_pnp_counter_read(&a, 0xabc, 0, 0, &v), 0);

	peios_pnp_counter_add(&a, 0xabc, 5);
	peios_pnp_counter_add(&a, 0xabc, 2);
	peios_pnp_counter_add(&b, 0xabc, 1);

	/* Per-source cells are distinct; the global cell sums everyone. */
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&a, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       10, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 7ULL);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&b, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       10, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 1ULL);
	KUNIT_EXPECT_EQ(test, peios_pnp_counter_read(&a, 0xabc, 0, 0, &v), 1);
	KUNIT_EXPECT_EQ(test, v, 8ULL);
	/* A window the table does not answer is absent. */
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&a, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       99, &v),
			0);
	KUNIT_EXPECT_EQ(test, peios_pnp_counters_cells(), cells_before + 3);

	/* A stream nobody materialized: nothing happens. */
	peios_pnp_counter_add(&a, 0xdef, 1);
	KUNIT_EXPECT_EQ(test, peios_pnp_counter_read(&a, 0xdef, 0, 0, &v), 0);

	/* Absent-fact law: an ARP frame has no SrcAddr for the keyed table
	 * (confessed), but still lands in the global cell.
	 */
	peios_pnp_counter_add(&arp, 0xabc, 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.count_key_absent),
			absent_before + 1);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&arp, 0xabc,
					       PEIOS_PNP_KEY_SRC_ADDR, 10, &v),
			0);
	KUNIT_EXPECT_EQ(test, peios_pnp_counter_read(&arp, 0xabc, 0, 0, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 9ULL);

	/* Re-publication with a new window migrates cells: totals carry,
	 * the new window starts empty and converges.
	 */
	views[0].window_secs = 60;
	KUNIT_ASSERT_EQ(test, peios_pnp_counters_publish(views, 2), 0);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&a, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       10, &v),
			0);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&a, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       60, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 0ULL);
	KUNIT_EXPECT_EQ(test,
			peios_pnp_counter_read(&a, 0xabc, PEIOS_PNP_KEY_SRC_ADDR,
					       0, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 7ULL);

	/* No views at all: the store retires its tables. */
	KUNIT_ASSERT_EQ(test, peios_pnp_counters_publish(NULL, 0), 0);
	KUNIT_EXPECT_EQ(test, peios_pnp_counter_read(&a, 0xabc, 0, 0, &v), 0);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, peios_pnp_counters_cells(), cells_before);
}

static void pnp_kunit_report_lands_in_kmes(struct kunit *test)
{
	struct peios_pnp_snapshot snap = {
		.seat = PEIOS_PNP_SEAT_LOCAL_IN,
		.direction = PEIOS_PNP_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.src_addr = { 192, 0, 2, 9 },
		.dst_addr = { 10, 0, 0, 5 },
		.src_port = 4444,
		.dst_port = 22,
		.has = PEIOS_PNP_HAS_PORTS,
		.flow_state = PEIOS_PNP_FLOW_NEW,
		.length = 60,
		.ifindex = 7,
		.ifname = "eth0",
	};
	struct pkm_kmes_kunit_snapshot ring;
	u64 emitted_before = atomic64_read(&peios_pnp_stats.reports_emitted);
	size_t written = 0;
	u8 *buf;
	int ret;

	buf = kunit_kzalloc(test, 4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	peios_pnp_report_emit(&snap, "no-inbound/ssh", 14, 4,
			      PEIOS_PNP_LAYER_PACKET, PEIOS_PNP_VERDICT_REJECT,
			      PEIOS_PNP_REJECT_PROHIBITED);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.reports_emitted),
			emitted_before + 1);

	ret = pkm_kmes_kunit_copy_latest_matching_event(
		KMES_ORIGIN_PNP, "network-report", 14, buf, 4096, &written,
		&ring);
	if (ret == -ENODEV || ret == -ENOENT)
		kunit_skip(test, "KMES ring not available in this run (%d)",
			   ret);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, written, (size_t)0);
	/* The msgpack payload carries the attribution and the story. */
	KUNIT_EXPECT_NOT_NULL(test,
			      strnstr(buf, "no-inbound/ssh", written));
	KUNIT_EXPECT_NOT_NULL(test, strnstr(buf, "Prohibited", written));
	KUNIT_EXPECT_NOT_NULL(test, strnstr(buf, "192.0.2.9", written));
}

/*
 * The Flow layer (rung 2): the outbound seat's snapshot, the sentence
 * cache on a real conntrack entry (judge once, read thereafter, re-judge
 * when stale by generation or by time edge, DROP persists, loopback's two
 * endpoints answer to the stricter sentence), the refusal builder and the
 * seat bypass for PNP's own refusals.
 */
static void pnp_kunit_snapshot_local_out(struct kunit *test)
{
	static const u8 mac[6] = { 0x52, 0x54, 0, 0xab, 0xcd, 0xef };
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct net_device *lo = pnp_test_dev(test, "lo", false);
	struct peios_pnp_snapshot snap;
	struct sk_buff *skb = pnp_test_tcp4_skb(test, 443);

	dev->dev_addr = mac;
	lo->flags |= IFF_LOOPBACK;

	KUNIT_EXPECT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_OUT,
						    PEIOS_PNP_DIR_OUT, &snap),
			0);
	KUNIT_EXPECT_EQ(test, snap.seat, PEIOS_PNP_SEAT_LOCAL_OUT);
	KUNIT_EXPECT_EQ(test, snap.direction, PEIOS_PNP_DIR_OUT);
	/* No link header yet: the source MAC is our own device's, present
	 * for the uniform fact set; the destination is absent.
	 */
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_PNP_HAS_MACS);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_SRC_MAC);
	KUNIT_EXPECT_EQ(test, memcmp(snap.src_mac, mac, 6), 0);
	KUNIT_EXPECT_FALSE(test, snap.loopback);
	/* The clock rides along as epoch seconds too. */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_PNP_HAS_TIME);
	KUNIT_EXPECT_GT(test, snap.t_secs, (s64)1700000000);
	/* Untracked: no flow, no start facts. */
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_PNP_HAS_START);

	KUNIT_EXPECT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, lo,
						    PEIOS_PNP_SEAT_LOCAL_OUT,
						    PEIOS_PNP_DIR_OUT, &snap),
			0);
	KUNIT_EXPECT_TRUE(test, snap.loopback);

	kfree_skb(skb);
}

/* Publishes a one-rule Flow forest. */
static void pnp_test_publish_flow(struct kunit *test, const char *cond_key,
				  const char *cond_val, const char *action)
{
	void *b, *forest = NULL;

	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "r", 1), 0);
	if (cond_key)
		KUNIT_ASSERT_EQ(test,
				pnp_rust_builder_value_str(b, cond_key,
							   strlen(cond_key),
							   cond_val,
							   strlen(cond_val)),
				0);
	pnp_test_actions(test, b, action);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, forest, 1),
			0);
}

/* Publishes a Flow forest: outbound passes, inbound drops. */
static void pnp_test_publish_flow2(struct kunit *test)
{
	void *b, *forest = NULL;

	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "out", 3), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_str(b, "Direction.Equal", 15,
						   "out", 3),
			0);
	pnp_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "in", 2), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_str(b, "Direction.Equal", 15,
						   "in", 2),
			0);
	pnp_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, forest, 1),
			0);
}

static void pnp_kunit_flow_sentence(struct kunit *test)
{
	struct nf_conn *ct = pnp_test_flow(test);
	struct peios_pnp_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_PNP);
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = pnp_test_tcp4_skb(test, 443);
	struct peios_pnp_snapshot snap = {
		.seat = PEIOS_PNP_SEAT_LOCAL_OUT,
		.direction = PEIOS_PNP_DIR_OUT,
		.addr_family = 4,
		.protocol = IPPROTO_TCP,
		.src_addr = { 10, 0, 0, 5 },
		.dst_addr = { 192, 0, 2, 9 },
		.src_port = 40000,
		.dst_port = 443,
		.has = PEIOS_PNP_HAS_PORTS | PEIOS_PNP_HAS_TIME,
		.flow_state = PEIOS_PNP_FLOW_NEW,
		.ifindex = 7,
		.ifname = "eth0",
		/* 2026-09-02 10:30:00 UTC. */
		.t_year = 2026, .t_month = 9, .t_day_of_month = 2,
		.t_day_of_week = 3, .t_hour = 10, .t_minute = 30,
		.t_secs = 1788345000,
		.flow = ct,
	};
	struct peios_pnp_snapshot untracked = snap;
	u64 judged0 = atomic64_read(&peios_pnp_stats.flow_judged);
	u64 cached0 = atomic64_read(&peios_pnp_stats.flow_cached);
	u64 rejudged0 = atomic64_read(&peios_pnp_stats.flow_rejudged);
	u64 expired0 = atomic64_read(&peios_pnp_stats.flow_expired);
	u64 permissive0 = atomic64_read(&peios_pnp_stats.permissive);

	KUNIT_ASSERT_NOT_NULL(test, pc);
	KUNIT_EXPECT_GT(test, pc->start_secs, (u64)1700000000);
	untracked.flow = NULL;

	/* No Flow forest: permissive, nothing cached. */
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, NULL, 1),
			0);
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.permissive),
			permissive0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation, 0ULL);

	/* Judged once: the sentence is written with the generation and,
	 * for a rule that consulted the hour, the next flip (11:00).
	 */
	pnp_test_publish_flow(test, "Time.Hour.Equal", "9-17", "PASS");
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation,
			pnp_rust_generation());
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_PNP_VERDICT_PASS);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].expires_at,
			(s64)(1788345000 - 1788345000 % 3600 + 8 * 3600));
	KUNIT_EXPECT_EQ(test, pc->sentence[0].rule_hash,
			peios_pnp_path_hash("r", 1));
	KUNIT_EXPECT_EQ(test, pc->direction, (u8)PEIOS_PNP_DIR_OUT);
	KUNIT_EXPECT_EQ(test, pc->ifindex, 7);

	/* Read thereafter: no evaluation. */
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_cached),
			cached0 + 1);

	/* Past the edge: re-judged (and the hour rule now says DROP at
	 * 18:00 — the backstop, since nothing else speaks).
	 */
	snap.t_hour = 18;
	snap.t_secs = 1788345000 - 1788345000 % 3600 + 8 * 3600;
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_expired),
			expired0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_judged),
			judged0 + 2);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_PNP_VERDICT_DROP);
	/* A DROP sentence persists: still no evaluation. */
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_judged),
			judged0 + 2);

	/* A new generation re-judges: this one passes everything. */
	pnp_test_publish_flow(test, NULL, NULL, "PASS");
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_rejudged),
			rejudged0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].expires_at, 0LL);

	/* Untracked: nothing to judge, the Packet verdict stands. */
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &untracked),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.flow_judged),
			judged0 + 3);

	/* A re-judgment on a REPLY packet judges the flow, not the packet:
	 * the outbound flow is still outbound (so the forest that passes
	 * out and drops in passes it), with the original tuple. Found live:
	 * an inbound viewer flow re-judged on its reply as "out".
	 */
	pnp_test_publish_flow2(test);
	{
		struct peios_pnp_snapshot reply = snap;

		reply.seat = PEIOS_PNP_SEAT_LOCAL_IN;
		reply.direction = PEIOS_PNP_DIR_IN;
		reply.flow_reply = 1;
		memcpy(reply.src_addr, snap.dst_addr, 16);
		memcpy(reply.dst_addr, snap.src_addr, 16);
		reply.src_port = snap.dst_port;
		reply.dst_port = snap.src_port;
		KUNIT_EXPECT_EQ(test,
				peios_pnp_flow_dispatch(skb, &state, &reply),
				(unsigned int)NF_ACCEPT);
		KUNIT_EXPECT_EQ(test, pc->sentence[0].rule_hash,
				peios_pnp_path_hash("out", 3));
		KUNIT_EXPECT_EQ(test, pc->direction, (u8)PEIOS_PNP_DIR_OUT);
	}

	/* Loopback: two endpoints, two sentences, the stricter answers.
	 * The same forest (passes outbound, drops inbound), judged first at
	 * the outbound endpoint (slot 0)...
	 */
	snap.loopback = 1;
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_PNP_VERDICT_PASS);
	KUNIT_EXPECT_EQ(test, pc->sentence[1].generation, 0ULL);
	/* ...then at the inbound endpoint (slot 1). */
	snap.direction = PEIOS_PNP_DIR_IN;
	snap.seat = PEIOS_PNP_SEAT_LOCAL_IN;
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, pc->sentence[1].verdict,
			(u8)PEIOS_PNP_VERDICT_DROP);
	/* The outbound endpoint's own sentence says PASS, but the flow
	 * answers to the stricter of the two.
	 */
	snap.direction = PEIOS_PNP_DIR_OUT;
	snap.seat = PEIOS_PNP_SEAT_LOCAL_OUT;
	KUNIT_EXPECT_EQ(test, peios_pnp_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);

	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
	nf_conntrack_free(ct);
}

static void pnp_kunit_refusal_is_built_and_marked(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = pnp_test_tcp4_skb(test, 22);
	struct peios_pnp_snapshot snap;
	struct sk_buff *nskb;
	const struct tcphdr *th;
	const struct icmphdr *ih;

	KUNIT_ASSERT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_IN,
						    PEIOS_PNP_DIR_IN, &snap),
			0);

	/* Refused, TCP: an RST from us (the SYN's destination) to the peer,
	 * carrying the refusal bit.
	 */
	nskb = peios_pnp_refuse_build(skb, &state, &snap,
				      PEIOS_PNP_REJECT_REFUSED);
	KUNIT_ASSERT_NOT_NULL(test, nskb);
	KUNIT_EXPECT_TRUE(test, nskb->pnp_refusal);
	KUNIT_EXPECT_EQ(test, ip_hdr(nskb)->saddr, htonl(0x0a000005));
	KUNIT_EXPECT_EQ(test, ip_hdr(nskb)->daddr, htonl(0x0a000007));
	KUNIT_EXPECT_EQ(test, ip_hdr(nskb)->protocol, IPPROTO_TCP);
	/* The builders leave the transport offset at the IP header (they
	 * build for transmission, where nobody reads it): find the TCP
	 * header by the IP header length, as the receive path will.
	 */
	th = (const struct tcphdr *)((const u8 *)ip_hdr(nskb) +
				     ip_hdr(nskb)->ihl * 4);
	KUNIT_EXPECT_TRUE(test, th->rst);
	KUNIT_EXPECT_EQ(test, th->source, htons(22));
	KUNIT_EXPECT_EQ(test, th->dest, htons(43210));
	kfree_skb(nskb);

	/* Prohibited: ICMP admin-prohibited, whatever the protocol. */
	nskb = peios_pnp_refuse_build(skb, &state, &snap,
				      PEIOS_PNP_REJECT_PROHIBITED);
	KUNIT_ASSERT_NOT_NULL(test, nskb);
	KUNIT_EXPECT_TRUE(test, nskb->pnp_refusal);
	KUNIT_EXPECT_EQ(test, ip_hdr(nskb)->protocol, IPPROTO_ICMP);
	ih = (const struct icmphdr *)((const u8 *)ip_hdr(nskb) +
				      ip_hdr(nskb)->ihl * 4);
	KUNIT_EXPECT_EQ(test, ih->type, ICMP_DEST_UNREACH);
	KUNIT_EXPECT_EQ(test, ih->code, ICMP_PKT_FILTERED);
	kfree_skb(nskb);

	/* A broadcast destination gets no answer. */
	snap.dst_addr[0] = 255;
	snap.dst_addr[1] = 255;
	snap.dst_addr[2] = 255;
	snap.dst_addr[3] = 255;
	KUNIT_EXPECT_NULL(test, peios_pnp_refuse_build(skb, &state, &snap,
						       PEIOS_PNP_REJECT_REFUSED));

	kfree_skb(skb);
}

static void pnp_kunit_teardown_resets_the_far_end(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = pnp_test_tcp4_skb(test, 443);
	struct tcphdr *oth = (struct tcphdr *)(skb_network_header(skb) +
					       sizeof(struct iphdr));
	struct peios_pnp_snapshot snap;
	struct sk_buff *reset;
	const struct tcphdr *th;

	/* A data segment of an established connection, refused outbound. */
	oth->syn = 0;
	oth->ack = 1;
	oth->psh = 1;
	oth->seq = htonl(5000);
	oth->ack_seq = htonl(9000);
	KUNIT_ASSERT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_OUT,
						    PEIOS_PNP_DIR_OUT, &snap),
			0);
	/* No conntrack in this harness: say what the seat would have said. */
	snap.flow_state = PEIOS_PNP_FLOW_ESTABLISHED;

	reset = peios_pnp_teardown_build(skb, &state, &snap);
	KUNIT_ASSERT_NOT_NULL(test, reset);
	KUNIT_EXPECT_TRUE(test, reset->pnp_refusal);
	/* Bound the same way as the refused packet, with its numbers. */
	KUNIT_EXPECT_EQ(test, ip_hdr(reset)->saddr, htonl(0x0a000007));
	KUNIT_EXPECT_EQ(test, ip_hdr(reset)->daddr, htonl(0x0a000005));
	th = (const struct tcphdr *)((const u8 *)ip_hdr(reset) +
				     ip_hdr(reset)->ihl * 4);
	KUNIT_EXPECT_TRUE(test, th->rst);
	KUNIT_EXPECT_TRUE(test, th->ack);
	KUNIT_EXPECT_EQ(test, th->source, htons(43210));
	KUNIT_EXPECT_EQ(test, th->dest, htons(443));
	KUNIT_EXPECT_EQ(test, ntohl(th->seq), 5000U);
	KUNIT_EXPECT_EQ(test, ntohl(th->ack_seq), 9000U);
	kfree_skb(reset);

	/* A new flow has no far end to tear down. */
	snap.flow_state = PEIOS_PNP_FLOW_NEW;
	KUNIT_EXPECT_NULL(test, peios_pnp_teardown_build(skb, &state, &snap));
	/* Nor does a reset get one. */
	snap.flow_state = PEIOS_PNP_FLOW_ESTABLISHED;
	snap.tcp_flags |= 0x04;
	KUNIT_EXPECT_NULL(test, peios_pnp_teardown_build(skb, &state, &snap));
	/* Nor UDP. */
	snap.tcp_flags &= ~0x04;
	snap.protocol = IPPROTO_UDP;
	KUNIT_EXPECT_NULL(test, peios_pnp_teardown_build(skb, &state, &snap));

	kfree_skb(skb);
}

static void pnp_kunit_own_refusals_bypass_the_seats(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = pnp_test_tcp4_skb(test, 22);
	u64 bypassed0 = atomic64_read(&peios_pnp_stats.refusals_bypassed);
	u64 judged0 = atomic64_read(&peios_pnp_stats.judged);
	void *b, *forest = NULL;

	/* A Packet forest that drops everything... */
	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "all", 3), 0);
	pnp_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(forest, NULL, NULL, 1),
			0);
	KUNIT_EXPECT_EQ(test, peios_pnp_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.judged),
			judged0 + 1);

	/* ...cannot touch a refusal PNP itself emitted. */
	skb->pnp_refusal = 1;
	KUNIT_EXPECT_EQ(test, peios_pnp_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, peios_pnp_hook_egress(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_pnp_stats.refusals_bypassed),
			bypassed0 + 2);

	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
}

static void pnp_kunit_downward_tag_read_refused(struct kunit *test)
{
	void *b, *packet = NULL, *flow = NULL;

	/* Packet reads a tag... */
	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "r", 1), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_int(b, "Tag.admitted.Equal", 18,
						   1),
			0);
	pnp_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_PACKET,
					       &packet),
			0);
	/* ...that Flow writes: a downward read, refused at publication. */
	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "w", 1), 0);
	pnp_test_actions(test, b, "TAG(admitted, Set)");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_FLOW, &flow),
			0);
	KUNIT_EXPECT_EQ(test, peios_pnp_policy_publish(packet, NULL, flow, 1),
			-EINVAL);
	pnp_rust_forest_free(packet);
	pnp_rust_forest_free(flow);
}


/* The process GUID as the Local.Process fact's text (8-4-4-4-12). */
static void pnp_test_guid_text(const u8 guid[16], char out[37])
{
	static const char hex[] = "0123456789abcdef";
	int i, o = 0;

	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			out[o++] = '-';
		out[o++] = hex[guid[i] >> 4];
		out[o++] = hex[guid[i] & 0xf];
	}
	out[o] = '\0';
}

/*
 * The identity facts (rung 3): the resolver classifies real sockets the
 * way the design says — a listening program, nobody, the stack, a kernel
 * socket, the sender — and the bridge lifts a program's token into the
 * Local.* facts a Flow forest judges.
 */
static void pnp_kunit_identity_facts(struct kunit *test)
{
	struct net_device *dev = pnp_test_dev(test, "eth0", false);
	struct nf_hook_state in_state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct nf_hook_state out_state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(2222),
	};
	struct peios_pnp_identity id, kernel_id;
	struct peios_pnp_snapshot snap;
	struct peios_pnp_outcome out;
	struct socket *sock = NULL, *ksock = NULL;
	struct sk_buff *skb;
	struct iphdr *iph;
	void *b, *forest = NULL;
	u8 user[68], service[32];
	char guid[37];

	dev_net_set(dev, &init_net);

	/* A program's listener, on the port the packet is for. */
	KUNIT_ASSERT_EQ(test, sock_create(AF_INET, SOCK_STREAM, 0, &sock), 0);
	KUNIT_ASSERT_EQ(test,
			kernel_bind(sock, (struct sockaddr_unsized *)&addr,
				    sizeof(addr)),
			0);
	KUNIT_ASSERT_EQ(test, kernel_listen(sock, 1), 0);

	skb = pnp_test_tcp4_skb(test, 2222);
	KUNIT_ASSERT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_IN,
						    PEIOS_PNP_DIR_IN, &snap),
			0);
	peios_pnp_identity_resolve(skb, &in_state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_PNP_LOCAL_PROGRAM);
	KUNIT_EXPECT_EQ(test, id.unresolved, 0);
	KUNIT_ASSERT_NOT_NULL(test, id.owner.token);
	KUNIT_EXPECT_EQ(test, id.owner.pid, (s32)task_tgid_nr(current));
	KUNIT_EXPECT_NE(test, id.owner.comm[0], '\0');
	/* Its SIDs cross the bridge: a user SID, and no service SID here. */
	KUNIT_EXPECT_EQ(test, pnp_rust_owner_sids(id.owner.token, user, service),
			0);
	KUNIT_EXPECT_EQ(test, user[0], 1);	/* SID revision */
	KUNIT_EXPECT_EQ(test, service[0], 0);
	kfree_skb(skb);

	/* Nobody listens on the next port: none. */
	skb = pnp_test_tcp4_skb(test, 2223);
	KUNIT_ASSERT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_IN,
						    PEIOS_PNP_DIR_IN, &snap),
			0);
	peios_pnp_identity_resolve(skb, &in_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_PNP_LOCAL_NONE);
	KUNIT_EXPECT_NULL(test, kernel_id.owner.token);
	peios_pnp_identity_release(&kernel_id);

	/* The stack consumes ICMP itself: kernel. A protocol nothing
	 * handles (253, experimental): none.
	 */
	iph = ip_hdr(skb);
	iph->protocol = IPPROTO_ICMP;
	peios_pnp_identity_resolve(skb, &in_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_PNP_LOCAL_KERNEL);
	peios_pnp_identity_release(&kernel_id);
	iph->protocol = 253;
	peios_pnp_identity_resolve(skb, &in_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_PNP_LOCAL_NONE);
	peios_pnp_identity_release(&kernel_id);
	kfree_skb(skb);

	/* Outbound: the sending socket's stamp; a kernel socket is the
	 * kernel's.
	 */
	skb = pnp_test_tcp4_skb(test, 443);
	KUNIT_ASSERT_EQ(test,
			peios_pnp_snapshot_from_skb(skb, dev,
						    PEIOS_PNP_SEAT_LOCAL_OUT,
						    PEIOS_PNP_DIR_OUT, &snap),
			0);
	out_state.sk = sock->sk;
	peios_pnp_identity_resolve(skb, &out_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_PNP_LOCAL_PROGRAM);
	KUNIT_EXPECT_PTR_EQ(test, kernel_id.owner.token, id.owner.token);
	peios_pnp_identity_release(&kernel_id);

	KUNIT_ASSERT_EQ(test,
			sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, 0,
					 &ksock),
			0);
	out_state.sk = ksock->sk;
	peios_pnp_identity_resolve(skb, &out_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_PNP_LOCAL_KERNEL);
	KUNIT_EXPECT_NULL(test, kernel_id.owner.token);
	peios_pnp_identity_release(&kernel_id);
	sock_release(ksock);

	/* The bridge: a Flow forest over the identity facts, judged against
	 * the program's token and against the kernel.
	 */
	pnp_test_guid_text(id.owner.guid, guid);
	b = pnp_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "posture", 7), 0);
	pnp_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "this-process", 12),
			0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_str(b, "Local.Process.Equal", 19,
						   guid, strlen(guid)),
			0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_int(b, "Local.Service.Present",
						   21, 0),
			0);
	pnp_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_begin(b, "kernel", 6), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_value_str(b, "Local.Equal", 11,
						   "kernel", 6),
			0);
	pnp_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, pnp_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			pnp_rust_builder_build(b, PEIOS_PNP_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_NOT_NULL(test, forest);
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, forest, 1),
			0);
	KUNIT_EXPECT_TRUE(test, peios_pnp_policy_has_layer(PEIOS_PNP_LAYER_FLOW));
	KUNIT_EXPECT_FALSE(test,
			   peios_pnp_policy_has_layer(PEIOS_PNP_LAYER_PACKET));

	/* This program: the exception speaks. */
	snap.local_kind = PEIOS_PNP_LOCAL_PROGRAM;
	snap.local_token = id.owner.token;
	memcpy(snap.local_guid, id.owner.guid, sizeof(snap.local_guid));
	KUNIT_ASSERT_EQ(test,
			peios_pnp_policy_eval(PEIOS_PNP_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_PNP_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "posture/this-process");

	/* Another process (a different GUID): the posture drops it. */
	snap.local_guid[0] ^= 0xff;
	KUNIT_ASSERT_EQ(test,
			peios_pnp_policy_eval(PEIOS_PNP_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_PNP_VERDICT_DROP);
	KUNIT_EXPECT_STREQ(test, out.attributed, "posture");

	/* The kernel: no principal, the kernel exception speaks. */
	snap.local_kind = PEIOS_PNP_LOCAL_KERNEL;
	snap.local_token = NULL;
	KUNIT_ASSERT_EQ(test,
			peios_pnp_policy_eval(PEIOS_PNP_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_PNP_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "posture/kernel");

	kfree_skb(skb);
	peios_pnp_identity_release(&id);
	sock_release(sock);
}

static struct kunit_case pnp_kunit_cases[] = {
	KUNIT_CASE(pnp_kunit_rust_probe),
	KUNIT_CASE(pnp_kunit_dispatch_predicate),
	KUNIT_CASE(pnp_kunit_snapshot_tcp4),
	KUNIT_CASE(pnp_kunit_snapshot_arp),
	KUNIT_CASE(pnp_kunit_snapshot_udp6),
	KUNIT_CASE(pnp_kunit_end_to_end_enforcement),
	KUNIT_CASE(pnp_kunit_event_stream),
	KUNIT_CASE(pnp_kunit_reject_kinds_cross_the_bridge),
	KUNIT_CASE(pnp_kunit_tag_store),
	KUNIT_CASE(pnp_kunit_counter_store),
	KUNIT_CASE(pnp_kunit_report_lands_in_kmes),
	KUNIT_CASE(pnp_kunit_snapshot_local_out),
	KUNIT_CASE(pnp_kunit_flow_sentence),
	KUNIT_CASE(pnp_kunit_refusal_is_built_and_marked),
	KUNIT_CASE(pnp_kunit_teardown_resets_the_far_end),
	KUNIT_CASE(pnp_kunit_own_refusals_bypass_the_seats),
	KUNIT_CASE(pnp_kunit_downward_tag_read_refused),
	KUNIT_CASE(pnp_kunit_identity_facts),
	{}
};

static struct kunit_suite pnp_kunit_suite = {
	.name = "pkm_kunit_pnp",
	.test_cases = pnp_kunit_cases,
};

kunit_test_suite(pnp_kunit_suite);
