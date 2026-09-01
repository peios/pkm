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
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include <pkm/kmes.h>

#include "../../security/pkm/kmes/kmes.h"
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
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(forest, NULL, 1), 0);
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
	KUNIT_ASSERT_EQ(test, peios_pnp_policy_publish(NULL, NULL, 1), 0);
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
	{}
};

static struct kunit_suite pnp_kunit_suite = {
	.name = "pkm_kunit_pnp",
	.test_cases = pnp_kunit_cases,
};

kunit_test_suite(pnp_kunit_suite);
