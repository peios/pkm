// SPDX-License-Identifier: GPL-2.0-only
/*
 * NTFE KUnit: kernel-resident glue only — the seat snapshot builder against
 * crafted skbs, and the dispatch predicate. Rules-engine semantics are
 * owned by the pnp-core cargo suite (48 tests); duplicating them here
 * would be testing the same pure code twice.
 */

#include <kunit/test.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/icmp.h>
#include <linux/mman.h>
#include <linux/rtnetlink.h>
#include <linux/uaccess.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/peios_ntfe.h>
#include <linux/string.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include <pkm/ntfe.h>
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

#include "ntfe.h"

/*
 * The seams (ntfe.h): how many of the next evaluations fail, how many of
 * the next device-side allocations are refused, and who records a flow
 * endpoint's identity between its resolution and its record. The suite's
 * exit resets all three, so a failed case cannot leak one into the next.
 */
static atomic_t ntfe_kunit_fail_evals = ATOMIC_INIT(0);
static atomic_t ntfe_kunit_fail_allocs = ATOMIC_INIT(0);
static void (*ntfe_kunit_on_resolved)(struct nf_conn *ct,
				      struct peios_ntfe_ct *pc, u32 slot);

bool peios_ntfe_kunit_eval_should_fail(void)
{
	return atomic_add_unless(&ntfe_kunit_fail_evals, -1, 0);
}

bool peios_ntfe_kunit_alloc_should_fail(void)
{
	return atomic_add_unless(&ntfe_kunit_fail_allocs, -1, 0);
}

void peios_ntfe_kunit_identity_resolved(struct nf_conn *ct,
				       struct peios_ntfe_ct *pc, u32 slot)
{
	void (*fn)(struct nf_conn *ct, struct peios_ntfe_ct *pc, u32 slot) =
		READ_ONCE(ntfe_kunit_on_resolved);

	if (fn)
		fn(ct, pc, slot);
}

static struct net_device *ntfe_test_dev(struct kunit *test, const char *name,
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

static void ntfe_kunit_rust_probe(struct kunit *test)
{
	/* The staged pnp-core is linked and callable, and answers with its
	 * known constant (MAX_PROMPT_CHAIN).
	 */
	KUNIT_EXPECT_EQ(test, ntfe_rust_kunit_probe(), 4);
}

static void ntfe_kunit_dispatch_predicate(struct kunit *test)
{
	struct net_device *plain = ntfe_test_dev(test, "eth0", false);
	struct net_device *enslaved = ntfe_test_dev(test, "eth1", true);

	/* IP on a plain device reaches the IP seat: defer. */
	KUNIT_EXPECT_TRUE(test, peios_ntfe_traversal_reaches_ip_seat(
					htons(ETH_P_IP), plain));
	KUNIT_EXPECT_TRUE(test, peios_ntfe_traversal_reaches_ip_seat(
					htons(ETH_P_IPV6), plain));
	/* Non-IP never reaches the IP hooks: fallback judgment here. */
	KUNIT_EXPECT_FALSE(test, peios_ntfe_traversal_reaches_ip_seat(
					 htons(ETH_P_ARP), plain));
	/* Bridge-enslaved port: L2-forwarded, never crosses the IP hooks —
	 * the corrected predicate from the design session.
	 */
	KUNIT_EXPECT_FALSE(test, peios_ntfe_traversal_reaches_ip_seat(
					 htons(ETH_P_IP), enslaved));
}

/* An inbound TCP/v4 SYN to the given port; 10.0.0.7 -> 10.0.0.5. */
static struct sk_buff *ntfe_test_tcp4_skb(struct kunit *test, u16 dport)
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

static void ntfe_kunit_snapshot_tcp4(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct peios_ntfe_snapshot snap;
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 22);

	KUNIT_EXPECT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_EQ(test, snap.addr_family, 4);
	KUNIT_EXPECT_EQ(test, snap.protocol, IPPROTO_TCP);
	KUNIT_EXPECT_EQ(test, snap.src_addr[0], 10);
	KUNIT_EXPECT_EQ(test, snap.src_addr[3], 7);
	KUNIT_EXPECT_EQ(test, snap.src_port, 43210);
	KUNIT_EXPECT_EQ(test, snap.dst_port, 22);
	KUNIT_EXPECT_EQ(test, snap.ttl, 64);
	KUNIT_EXPECT_EQ(test, snap.dscp, 0x2e);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_PORTS);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_TCP_FLAGS);
	KUNIT_EXPECT_EQ(test, snap.tcp_flags, 0x02);	/* bare SYN */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_FRAGMENT);
	KUNIT_EXPECT_EQ(test, snap.fragment, 0);
	/* No mac header was set: MAC facts are absent. */
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_MACS);
	/* Conntrack ran (it's an IP seat) and left nothing: untracked. */
	KUNIT_EXPECT_EQ(test, snap.flow_state, PEIOS_NTFE_FLOW_UNTRACKED);
	/* Clock machinery attached wall-time facts. */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_TIME);
	KUNIT_EXPECT_GE(test, snap.t_year, 2026);
	KUNIT_EXPECT_GE(test, snap.t_day_of_week, 1);
	KUNIT_EXPECT_LE(test, snap.t_day_of_week, 7);
	KUNIT_EXPECT_EQ(test, snap.ifindex, 7);

	kfree_skb(skb);
}

static void ntfe_kunit_snapshot_arp(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct peios_ntfe_snapshot snap;
	struct sk_buff *skb;

	skb = alloc_skb(64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	skb_reserve(skb, 32);
	skb_reset_network_header(skb);
	skb_put_zero(skb, 28);	/* ARP payload; the builder doesn't parse it */
	skb->protocol = htons(ETH_P_ARP);

	KUNIT_EXPECT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_INGRESS,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	/* Absent-fact law, at the seat level: an ARP frame has L2 and seat
	 * facts and nothing else.
	 */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_ETHER_TYPE);
	KUNIT_EXPECT_EQ(test, snap.ether_type, ETH_P_ARP);
	KUNIT_EXPECT_EQ(test, snap.addr_family, 0);
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_PORTS);
	/* The ingress seat stands before conntrack: flow facts absent, not
	 * "untracked".
	 */
	KUNIT_EXPECT_EQ(test, snap.flow_state, PEIOS_NTFE_FLOW_ABSENT);

	kfree_skb(skb);
}

static void ntfe_kunit_snapshot_udp6(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct peios_ntfe_snapshot snap;
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
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_EGRESS,
						    PEIOS_NTFE_DIR_OUT, &snap),
			0);
	KUNIT_EXPECT_EQ(test, snap.addr_family, 6);
	KUNIT_EXPECT_EQ(test, snap.protocol, IPPROTO_UDP);
	KUNIT_EXPECT_EQ(test, snap.src_addr[0], 0xfd);
	KUNIT_EXPECT_EQ(test, snap.dst_addr[15], 1);
	KUNIT_EXPECT_EQ(test, snap.src_port, 5353);
	KUNIT_EXPECT_EQ(test, snap.ttl, 255);
	KUNIT_EXPECT_EQ(test, snap.direction, PEIOS_NTFE_DIR_OUT);
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_TCP_FLAGS);

	kfree_skb(skb);
}

/* Feed one action list to the builder. */
static void ntfe_test_actions(struct kunit *test, void *b, const char *action)
{
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_list_begin(b, "Actions", 7), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_list_str(b, action, strlen(action)),
			0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_value_list_end(b), 0);
}

/*
 * End to end: policy built over the FFI (as the LCS ingestion path will
 * build it), published under RCU, enforced by the real hook function.
 * "Drop everything inbound, except SSH" — the design-session tree, live.
 */
static void ntfe_kunit_end_to_end_enforcement(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_outcome out;
	struct sk_buff *skb;
	u64 gen_before = ntfe_rust_generation();
	void *b, *forest = NULL;

	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);

	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_rule_begin(b, "no-inbound", 10), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Direction.Equal", 15,
						   "in", 2),
			0);
	ntfe_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "ssh", 3), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_int(b, "DstPort.Equal", 13, 22),
			0);
	ntfe_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);

	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_NOT_NULL(test, forest);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(forest, NULL, NULL, 1),
			0);
	KUNIT_EXPECT_EQ(test, ntfe_rust_generation(), gen_before + 1);

	/* SSH passes through the exception... */
	skb = ntfe_test_tcp4_skb(test, 22);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	/* ...and its attribution is the path through the tree. */
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_PACKET, &snap,
					      &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "no-inbound/ssh");
	kfree_skb(skb);

	/* Telnet is dropped by the parent... */
	skb = ntfe_test_tcp4_skb(test, 23);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_DROP);
	kfree_skb(skb);

	/* ...and the RawPacket layer, with no forest, stayed permissive
	 * (an unrelated seat judging the same machine's traffic).
	 */
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_RAWPACKET,
					      &snap, &out),
			-ENOENT);

	/* Restore permissiveness for whatever runs after this suite. */
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
}

/*
 * The deepest tree ingestion admits, every rule carrying conditions,
 * builds and evaluates. Building it once overflowed the kernel stack:
 * the builder recursed per level with a frame of about a kilobyte
 * (PEI-1299). The builder and the evaluator now walk with a heap stack,
 * so depth costs no kernel stack. A leaf hit is attributed down the
 * whole chain; a miss below the root is answered by the root.
 */
static void ntfe_kunit_deepest_tree(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_outcome out;
	char expect[(PEIOS_NTFE_MAX_RULE_DEPTH + 1) * 4];
	struct sk_buff *skb;
	void *b, *forest = NULL;
	char name[4];
	int depth, len = 0;

	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	for (depth = 0; depth <= PEIOS_NTFE_MAX_RULE_DEPTH; depth++) {
		snprintf(name, sizeof(name), "r%d", depth);
		len += scnprintf(expect + len, sizeof(expect) - len, "%s%s",
				 depth ? "/" : "", name);
		KUNIT_ASSERT_EQ(test,
				ntfe_rust_builder_rule_begin(b, name,
							     strlen(name)),
				0);
		KUNIT_ASSERT_EQ(test,
				ntfe_rust_builder_value_str(b, "Direction.Equal",
							   15, "in", 2),
				0);
		if (depth == 0) {
			ntfe_test_actions(test, b, "DROP");
			continue;
		}
		KUNIT_ASSERT_EQ(test,
				ntfe_rust_builder_value_int(b, "DstPort.Equal", 13,
							   22),
				0);
		KUNIT_ASSERT_EQ(test,
				ntfe_rust_builder_value_int(b, "Protocol.Equal", 14,
							   IPPROTO_TCP),
				0);
		if (depth == PEIOS_NTFE_MAX_RULE_DEPTH)
			ntfe_test_actions(test, b, "PASS");
	}
	for (depth = 0; depth <= PEIOS_NTFE_MAX_RULE_DEPTH; depth++)
		KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);

	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_NOT_NULL(test, forest);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(forest, NULL, NULL, 1),
			0);

	skb = ntfe_test_tcp4_skb(test, 22);
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_PACKET, &snap,
					      &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, expect);
	kfree_skb(skb);

	skb = ntfe_test_tcp4_skb(test, 23);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_PACKET, &snap,
					      &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_DROP);
	KUNIT_EXPECT_STREQ(test, out.attributed, "r0");
	kfree_skb(skb);

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
}

/*
 * The verdict event ring: emit from a crafted snapshot/outcome, drain via
 * the internal pop path (the device read uses the same), check ordering,
 * status, and the confessed-drop counter under overwrite.
 */
static void ntfe_kunit_event_stream(struct kunit *test)
{
	struct peios_ntfe_snapshot snap = {
		.seat = PEIOS_NTFE_SEAT_LOCAL_IN,
		.direction = PEIOS_NTFE_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.src_port = 43210,
		.dst_port = 22,
		.length = 60,
	};
	struct peios_ntfe_outcome out = {
		.verdict = PEIOS_NTFE_VERDICT_DROP,
		.n_reports = 2,
	};
	struct peios_ntfe_status status;
	u64 before_dropped = peios_ntfe_events_dropped();

	strscpy(out.attributed, "no-inbound", sizeof(out.attributed));
	peios_ntfe_event_emit(&snap, &out, PEIOS_NTFE_LAYER_PACKET, 0);

	peios_ntfe_status_fill(&status);
	KUNIT_EXPECT_EQ(test, status.abi, (u64)PEIOS_NTFE_ABI_VERSION);
	KUNIT_EXPECT_EQ(test, status.events_dropped, before_dropped);
	/* Generation was left at its post-publish value by the end-to-end
	 * test; whatever it is, status must agree with the bridge.
	 */
	KUNIT_EXPECT_EQ(test, status.generation, ntfe_rust_generation());
}


/*
 * The machinery slice: REJECT kinds cross the bridge, the flow tag store
 * on a real conntrack entry (set/add/clear/lookup, the per-flow tripwire,
 * the destructor), the counter store (materialized views, keyed cells,
 * windows, the absent-key law, re-publication), and REPORT landing in
 * KMES as an ntfe.verdict.reported event.
 */
static void ntfe_kunit_reject_kinds_cross_the_bridge(struct kunit *test)
{
	struct peios_ntfe_snapshot snap = {
		.seat = PEIOS_NTFE_SEAT_LOCAL_IN,
		.direction = PEIOS_NTFE_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.length = 60,
	};
	struct peios_ntfe_outcome out;
	void *b, *forest = NULL;

	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "no", 2), 0);
	ntfe_test_actions(test, b, "REJECT(Prohibited)");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_evaluate(forest, &snap, PEIOS_NTFE_LAYER_PACKET,
					  1, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_REJECT);
	KUNIT_EXPECT_EQ(test, out.reject_kind, PEIOS_NTFE_REJECT_PROHIBITED);
	ntfe_rust_forest_free(forest);

	/* An unminted kind refuses the forest. */
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "no", 2), 0);
	ntfe_test_actions(test, b, "REJECT(HostUnreachable)");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	forest = NULL;
	KUNIT_EXPECT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			-EINVAL);
	KUNIT_EXPECT_NULL(test, forest);
}

static struct nf_conn *ntfe_test_flow(struct kunit *test)
{
	struct nf_conntrack_tuple orig = { }, repl = { };
	struct nf_conn *ct;

	ct = nf_conntrack_alloc(&init_net, &nf_ct_zone_dflt, &orig, &repl,
				GFP_KERNEL);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(ct));
	/* init_conntrack does this for real flows (ntfe-conntrack-ext patch);
	 * a directly allocated entry needs it by hand.
	 */
	peios_ntfe_ct_ext_add(ct);
	return ct;
}

static void ntfe_kunit_tag_store(struct kunit *test)
{
	struct nf_conn *ct = ntfe_test_flow(test);
	u64 untracked_before = atomic64_read(&peios_ntfe_stats.tag_untracked);
	u64 refused_before = atomic64_read(&peios_ntfe_stats.tag_refused);
	u64 value = 0;
	u32 i;

	/* Absent until written. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x1001, &value), 0);

	peios_ntfe_tag_apply(ct, 0x1001, PEIOS_NTFE_TAG_SET, 7);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x1001, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 7ULL);

	peios_ntfe_tag_apply(ct, 0x1001, PEIOS_NTFE_TAG_ADD, 5);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x1001, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 12ULL);

	/* Add on an absent tag starts from zero. */
	peios_ntfe_tag_apply(ct, 0x1002, PEIOS_NTFE_TAG_ADD, 3);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x1002, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 3ULL);

	/* Clear reads as absent; the slot is reusable. */
	peios_ntfe_tag_apply(ct, 0x1001, PEIOS_NTFE_TAG_CLEAR, 0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x1001, &value), 0);
	peios_ntfe_tag_apply(ct, 0x1001, PEIOS_NTFE_TAG_SET, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x1001, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 1ULL);

	/* Growth past the initial table, up to the tripwire, then refusal
	 * (confessed). Two tags are already present.
	 */
	for (i = 0; i < PEIOS_NTFE_TAG_MAX_PER_FLOW - 2; i++)
		peios_ntfe_tag_apply(ct, 0x2000 + i, PEIOS_NTFE_TAG_SET, i);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x2000, &value), 1);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_tag_lookup(ct, 0x2000 + PEIOS_NTFE_TAG_MAX_PER_FLOW - 3,
					     &value),
			1);
	KUNIT_EXPECT_EQ(test, value,
			(u64)(PEIOS_NTFE_TAG_MAX_PER_FLOW - 3));
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.tag_refused),
			refused_before);
	peios_ntfe_tag_apply(ct, 0x3000, PEIOS_NTFE_TAG_SET, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, 0x3000, &value), 0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.tag_refused),
			refused_before + 1);

	/* Untracked packets have no flow: no-op, confessed. */
	peios_ntfe_tag_apply(NULL, 0x1001, PEIOS_NTFE_TAG_SET, 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.tag_untracked),
			untracked_before + 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(NULL, 0x1001, &value), 0);

	/* An unconfirmed entry is born with refcount 0 (confirmation sets
	 * it to 1), so it is released the way conntrack's own error paths
	 * do — straight to nf_conntrack_free, which frees the table through
	 * the destructor hook.
	 */
	nf_conntrack_free(ct);
}

static void ntfe_kunit_counter_store(struct kunit *test)
{
	struct peios_ntfe_view views[2] = {
		{ .name = "hits", .hash = 0xabc, .window_secs = 10,
		  .keyspec = PEIOS_NTFE_KEY_SRC_ADDR },
		{ .name = "hits", .hash = 0xabc, .window_secs = 0,
		  .keyspec = 0 },
	};
	struct peios_ntfe_snapshot a = {
		.seat = PEIOS_NTFE_SEAT_LOCAL_IN, .addr_family = 4,
		.src_addr = { 10, 0, 0, 7 }, .dst_addr = { 10, 0, 0, 5 },
		.ifindex = 7, .length = 60,
	};
	struct peios_ntfe_snapshot b = a;
	struct peios_ntfe_snapshot arp = {
		.seat = PEIOS_NTFE_SEAT_INGRESS, .ifindex = 7, .length = 42,
	};
	u64 absent_before = atomic64_read(&peios_ntfe_stats.count_key_absent);
	u64 cells_before = peios_ntfe_counters_cells();
	u64 v = 0;

	b.src_addr[3] = 8;

	KUNIT_ASSERT_EQ(test, peios_ntfe_counters_publish(views, 2), 0);

	/* Nothing counted yet: absent, both views. */
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&a, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       10, &v),
			0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counter_read(&a, 0xabc, 0, 0, &v), 0);

	peios_ntfe_counter_add(&a, 0xabc, 5);
	peios_ntfe_counter_add(&a, 0xabc, 2);
	peios_ntfe_counter_add(&b, 0xabc, 1);

	/* Per-source cells are distinct; the global cell sums everyone. */
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&a, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       10, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 7ULL);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&b, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       10, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 1ULL);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counter_read(&a, 0xabc, 0, 0, &v), 1);
	KUNIT_EXPECT_EQ(test, v, 8ULL);
	/* A window the table does not answer is absent. */
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&a, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       99, &v),
			0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counters_cells(), cells_before + 3);

	/* A stream nobody materialized: nothing happens. */
	peios_ntfe_counter_add(&a, 0xdef, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counter_read(&a, 0xdef, 0, 0, &v), 0);

	/* Absent-fact law: an ARP frame has no SrcAddr for the keyed table
	 * (confessed), but still lands in the global cell.
	 */
	peios_ntfe_counter_add(&arp, 0xabc, 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.count_key_absent),
			absent_before + 1);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&arp, 0xabc,
					       PEIOS_NTFE_KEY_SRC_ADDR, 10, &v),
			0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counter_read(&arp, 0xabc, 0, 0, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 9ULL);

	/* Re-publication with a new window migrates cells: totals carry,
	 * the new window starts empty and converges.
	 */
	views[0].window_secs = 60;
	KUNIT_ASSERT_EQ(test, peios_ntfe_counters_publish(views, 2), 0);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&a, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       10, &v),
			0);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&a, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       60, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 0ULL);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_counter_read(&a, 0xabc, PEIOS_NTFE_KEY_SRC_ADDR,
					       0, &v),
			1);
	KUNIT_EXPECT_EQ(test, v, 7ULL);

	/* No views at all: the store retires its tables. */
	KUNIT_ASSERT_EQ(test, peios_ntfe_counters_publish(NULL, 0), 0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counter_read(&a, 0xabc, 0, 0, &v), 0);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, peios_ntfe_counters_cells(), cells_before);
}

/* The kernel has no memmem, and a msgpack payload is binary. */
static const u8 *ntfe_test_find(const u8 *hay, size_t n, const void *needle,
				size_t len)
{
	size_t i;

	for (i = 0; len <= n && i <= n - len; i++)
		if (!memcmp(hay + i, needle, len))
			return hay + i;
	return NULL;
}

/* Whether @lit, a string literal of exact msgpack bytes, is in @p. */
#define NTFE_TEST_HAS(p, n, lit) \
	(ntfe_test_find(p, n, lit, sizeof(lit) - 1) != NULL)

#define NTFE_TEST_REPORT_TYPE	"ntfe.verdict.reported"

/*
 * The `rule` map's opening for @path: its key, a fixmap of @keys entries,
 * and the hash of the whole path. Both paths hashed here hash past
 * U32_MAX, so the value is a uint64 (0xcf).
 */
static size_t ntfe_test_rule_head(u8 *out, u8 keys, const char *path,
				  size_t len)
{
	static const char rule_key[] = "\xa4" "rule";
	static const char hash_key[] = "\xa4" "hash" "\xcf";
	__be64 hash = cpu_to_be64(peios_ntfe_path_hash(path, len));
	size_t at = 0;

	memcpy(out, rule_key, sizeof(rule_key) - 1);
	at += sizeof(rule_key) - 1;
	out[at++] = 0x80 | keys;
	memcpy(out + at, hash_key, sizeof(hash_key) - 1);
	at += sizeof(hash_key) - 1;
	memcpy(out + at, &hash, 8);
	return at + 8;
}

/* The latest report in @buf; returns its payload and sets @len. */
static const u8 *ntfe_test_latest_report(struct kunit *test, u8 *buf,
					 size_t *len)
{
	const size_t head = KMES_EVENT_HEADER_BASE_SIZE +
			    sizeof(NTFE_TEST_REPORT_TYPE) - 1;
	struct pkm_kmes_kunit_snapshot ring;
	size_t written = 0;
	int ret;

	ret = pkm_kmes_kunit_copy_latest_matching_event(
		KMES_ORIGIN_NTFE, NTFE_TEST_REPORT_TYPE,
		sizeof(NTFE_TEST_REPORT_TYPE) - 1, buf, 4096, &written, &ring);
	if (ret == -ENODEV || ret == -ENOENT)
		kunit_skip(test, "KMES ring not available in this run (%d)",
			   ret);
	KUNIT_ASSERT_EQ(test, ret, 0);
	/* A kernel emit's header is the base and the type, unpadded, and
	 * the payload runs to the end of the event.
	 */
	KUNIT_ASSERT_GT(test, written, head);
	*len = written - head;
	return buf + head;
}

static void ntfe_kunit_report_lands_in_kmes(struct kunit *test)
{
	struct peios_ntfe_snapshot snap = {
		.seat = PEIOS_NTFE_SEAT_LOCAL_IN,
		.direction = PEIOS_NTFE_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.src_addr = { 192, 0, 2, 9 },
		.dst_addr = { 10, 0, 0, 5 },
		.src_port = 4444,
		.dst_port = 22,
		.has = PEIOS_NTFE_HAS_PORTS,
		.flow_state = PEIOS_NTFE_FLOW_NEW,
		.length = 60,
		.ifindex = 7,
		.ifname = "eth0",
		.ether_type = ETH_P_IP,
	};
	/* The rule map's tail after the hash; the name closes it. */
	static const char rule_tail[] =
		"\xac" "report-level" "\x04"
		"\xa5" "layer" "\xa6" "packet"
		"\xa4" "seat" "\xa8" "local-in"
		"\xa4" "name" "\xae" "no-inbound/ssh";
	static const char name_cut[] = "\xae" "name-truncated" "\xc3";
	static const char name_head[] = "\xa4" "name" "\xd9";
	u8 want[96];
	u64 emitted_before = atomic64_read(&peios_ntfe_stats.reports_emitted);
	const u8 *p, *name;
	size_t len = 0, want_len, cut, i;
	char *long_rule;
	u8 *buf;

	buf = kunit_kzalloc(test, 4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	peios_ntfe_report_emit(&snap, "no-inbound/ssh", 14, 4,
			      PEIOS_NTFE_LAYER_PACKET, PEIOS_NTFE_VERDICT_REJECT,
			      PEIOS_NTFE_REJECT_PROHIBITED);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.reports_emitted),
			emitted_before + 1);

	p = ntfe_test_latest_report(test, buf, &len);
	/*
	 * Each path segment is a map (PGSS §6.4), checked byte for byte with
	 * its exact size: outcome, network, source, destination, flow,
	 * policy and rule, seven keys at the top.
	 */
	KUNIT_EXPECT_EQ(test, p[0], (u8)0x87);
	KUNIT_EXPECT_TRUE(test, NTFE_TEST_HAS(p, len,
		"\x87" "\xa7" "outcome" "\x82"
		"\xa7" "verdict" "\xa6" "reject"
		"\xa6" "reason" "\xaa" "prohibited"));
	KUNIT_EXPECT_TRUE(test, NTFE_TEST_HAS(p, len,
		"\xa7" "network" "\x86"
		"\xa9" "direction" "\xa2" "in"
		"\xa9" "interface" "\x82"
			"\xa4" "name" "\xa4" "eth0"
			"\xa5" "index" "\x07"
		"\xaa" "ether-type" "\xcd\x08\x00"
		"\xa6" "family" "\x02"		/* AF_INET */
		"\xa8" "protocol" "\x06"
		"\xa6" "length" "\x3c"));
	KUNIT_EXPECT_TRUE(test, NTFE_TEST_HAS(p, len,
		"\xa6" "source" "\x82"
		"\xa7" "address" "\xa9" "192.0.2.9"
		"\xa4" "port" "\xcd\x11\x5c"));
	KUNIT_EXPECT_TRUE(test, NTFE_TEST_HAS(p, len,
		"\xab" "destination" "\x82"
		"\xa7" "address" "\xa8" "10.0.0.5"
		"\xa4" "port" "\x16"));
	KUNIT_EXPECT_TRUE(test, NTFE_TEST_HAS(p, len,
		"\xa4" "flow" "\x81" "\xa5" "state" "\xa3" "new"));
	KUNIT_EXPECT_TRUE(test, NTFE_TEST_HAS(p, len,
		"\xa6" "policy" "\x81" "\xaa" "generation"));
	/* The rule map closes the payload, five keys: no truncation flag. */
	want_len = ntfe_test_rule_head(want, 5, "no-inbound/ssh", 14);
	memcpy(want + want_len, rule_tail, sizeof(rule_tail) - 1);
	want_len += sizeof(rule_tail) - 1;
	KUNIT_ASSERT_GE(test, len, want_len);
	KUNIT_EXPECT_EQ(test, memcmp(p + len - want_len, want, want_len), 0);
	/* The time is the header's; the old t_ns key is gone. */
	KUNIT_EXPECT_FALSE(test, NTFE_TEST_HAS(p, len, "\xa4" "t_ns"));

	/*
	 * PEI-1310: a name too long for the payload is cut at a character
	 * boundary and the cut is said; the event still goes, and the hash
	 * is of the whole path. Two-byte characters throughout, so a
	 * boundary is an even length.
	 */
	long_rule = kunit_kzalloc(test, 600, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, long_rule);
	for (i = 0; i < 600; i += 2) {
		long_rule[i] = (char)0xc3;
		long_rule[i + 1] = (char)0xa9;
	}
	peios_ntfe_report_emit(&snap, long_rule, 600, 4,
			      PEIOS_NTFE_LAYER_PACKET, PEIOS_NTFE_VERDICT_REJECT,
			      PEIOS_NTFE_REJECT_PROHIBITED);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.reports_emitted),
			emitted_before + 2);

	p = ntfe_test_latest_report(test, buf, &len);
	KUNIT_EXPECT_LE(test, len, (size_t)512);
	want_len = ntfe_test_rule_head(want, 6, long_rule, 600);
	KUNIT_EXPECT_TRUE(test, ntfe_test_find(p, len, want, want_len) != NULL);
	name = ntfe_test_find(p, len, name_head, sizeof(name_head) - 1);
	KUNIT_ASSERT_NOT_NULL(test, name);
	name += sizeof(name_head) - 1;
	cut = *name++;
	KUNIT_EXPECT_GT(test, cut, (size_t)0);
	KUNIT_EXPECT_EQ(test, cut % 2, (size_t)0);
	KUNIT_EXPECT_EQ(test, memcmp(name, long_rule, cut), 0);
	/* The flag follows the name and ends the payload. */
	KUNIT_ASSERT_EQ(test, (size_t)(name - p) + cut + sizeof(name_cut) - 1,
			len);
	KUNIT_EXPECT_EQ(test, memcmp(name + cut, name_cut,
				     sizeof(name_cut) - 1), 0);
}

/*
 * The Flow layer (rung 2): the outbound seat's snapshot, the sentence
 * cache on a real conntrack entry (judge once, read thereafter, re-judge
 * when stale by generation or by time edge, DROP persists, loopback's two
 * endpoints answer to the stricter sentence), the refusal builder and the
 * seat bypass for NTFE's own refusals.
 */
static void ntfe_kunit_snapshot_local_out(struct kunit *test)
{
	static const u8 mac[6] = { 0x52, 0x54, 0, 0xab, 0xcd, 0xef };
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct net_device *lo = ntfe_test_dev(test, "lo", false);
	struct peios_ntfe_snapshot snap;
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 443);

	dev->dev_addr = mac;
	lo->flags |= IFF_LOOPBACK;

	KUNIT_EXPECT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_OUT,
						    PEIOS_NTFE_DIR_OUT, &snap),
			0);
	KUNIT_EXPECT_EQ(test, snap.seat, PEIOS_NTFE_SEAT_LOCAL_OUT);
	KUNIT_EXPECT_EQ(test, snap.direction, PEIOS_NTFE_DIR_OUT);
	/* No link header yet: the source MAC is our own device's, present
	 * for the uniform fact set; the destination is absent.
	 */
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_MACS);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_SRC_MAC);
	KUNIT_EXPECT_EQ(test, memcmp(snap.src_mac, mac, 6), 0);
	KUNIT_EXPECT_FALSE(test, snap.loopback);
	/* The clock rides along as epoch seconds too. */
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_TIME);
	KUNIT_EXPECT_GT(test, snap.t_secs, (s64)1700000000);
	/* Untracked: no flow, no start facts. */
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_START);

	KUNIT_EXPECT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, lo,
						    PEIOS_NTFE_SEAT_LOCAL_OUT,
						    PEIOS_NTFE_DIR_OUT, &snap),
			0);
	KUNIT_EXPECT_TRUE(test, snap.loopback);

	kfree_skb(skb);
}

/* Publishes a one-rule Flow forest. */
static void ntfe_test_publish_flow(struct kunit *test, const char *cond_key,
				  const char *cond_val, const char *action)
{
	void *b, *forest = NULL;

	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "r", 1), 0);
	if (cond_key)
		KUNIT_ASSERT_EQ(test,
				ntfe_rust_builder_value_str(b, cond_key,
							   strlen(cond_key),
							   cond_val,
							   strlen(cond_val)),
				0);
	ntfe_test_actions(test, b, action);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, forest, 1),
			0);
}

/* Publishes a Flow forest: outbound passes, inbound drops. */
static void ntfe_test_publish_flow2(struct kunit *test)
{
	void *b, *forest = NULL;

	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "out", 3), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Direction.Equal", 15,
						   "out", 3),
			0);
	ntfe_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "in", 2), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Direction.Equal", 15,
						   "in", 2),
			0);
	ntfe_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, forest, 1),
			0);
}

static void ntfe_kunit_flow_sentence(struct kunit *test)
{
	struct nf_conn *ct = ntfe_test_flow(test);
	struct peios_ntfe_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_NTFE);
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 443);
	struct peios_ntfe_snapshot snap = {
		.seat = PEIOS_NTFE_SEAT_LOCAL_OUT,
		.direction = PEIOS_NTFE_DIR_OUT,
		.addr_family = 4,
		.protocol = IPPROTO_TCP,
		.src_addr = { 10, 0, 0, 5 },
		.dst_addr = { 192, 0, 2, 9 },
		.src_port = 40000,
		.dst_port = 443,
		.has = PEIOS_NTFE_HAS_PORTS | PEIOS_NTFE_HAS_TIME,
		.flow_state = PEIOS_NTFE_FLOW_NEW,
		.ifindex = 7,
		.ifname = "eth0",
		/* 2026-09-02 10:30:00 UTC. */
		.t_year = 2026, .t_month = 9, .t_day_of_month = 2,
		.t_day_of_week = 3, .t_hour = 10, .t_minute = 30,
		.t_secs = 1788345000,
		.flow = ct,
	};
	struct peios_ntfe_snapshot untracked = snap;
	u64 judged0 = atomic64_read(&peios_ntfe_stats.flow_judged);
	u64 cached0 = atomic64_read(&peios_ntfe_stats.flow_cached);
	u64 rejudged0 = atomic64_read(&peios_ntfe_stats.flow_rejudged);
	u64 expired0 = atomic64_read(&peios_ntfe_stats.flow_expired);
	u64 permissive0 = atomic64_read(&peios_ntfe_stats.permissive);

	KUNIT_ASSERT_NOT_NULL(test, pc);
	KUNIT_EXPECT_GT(test, pc->start_secs, (u64)1700000000);
	untracked.flow = NULL;

	/* No Flow forest: permissive, nothing cached. */
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.permissive),
			permissive0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation, 0ULL);

	/* Judged once: the sentence is written with the generation and,
	 * for a rule that consulted the hour, the next flip (11:00).
	 */
	ntfe_test_publish_flow(test, "Time.Hour.Equal", "9-17", "PASS");
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation,
			ntfe_rust_generation());
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].expires_at,
			(s64)(1788345000 - 1788345000 % 3600 + 8 * 3600));
	KUNIT_EXPECT_EQ(test, pc->sentence[0].rule_hash,
			peios_ntfe_path_hash("r", 1));
	KUNIT_EXPECT_EQ(test, pc->direction, (u8)PEIOS_NTFE_DIR_OUT);
	KUNIT_EXPECT_EQ(test, pc->ifindex, 7);

	/* Read thereafter: no evaluation. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_cached),
			cached0 + 1);

	/* Past the edge: re-judged (and the hour rule now says DROP at
	 * 18:00 — the backstop, since nothing else speaks).
	 */
	snap.t_hour = 18;
	snap.t_secs = 1788345000 - 1788345000 % 3600 + 8 * 3600;
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_expired),
			expired0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 2);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_NTFE_VERDICT_DROP);
	/* A DROP sentence persists: still no evaluation. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 2);

	/* A new generation re-judges: this one passes everything. */
	ntfe_test_publish_flow(test, NULL, NULL, "PASS");
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_rejudged),
			rejudged0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].expires_at, 0LL);

	/* Untracked: nothing to judge, the Packet verdict stands. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &untracked),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 3);

	/* A re-judgment on a REPLY packet judges the flow, not the packet:
	 * the outbound flow is still outbound (so the forest that passes
	 * out and drops in passes it), with the original tuple. Found live:
	 * an inbound viewer flow re-judged on its reply as "out".
	 */
	ntfe_test_publish_flow2(test);
	{
		struct peios_ntfe_snapshot reply = snap;

		reply.seat = PEIOS_NTFE_SEAT_LOCAL_IN;
		reply.direction = PEIOS_NTFE_DIR_IN;
		reply.flow_reply = 1;
		memcpy(reply.src_addr, snap.dst_addr, 16);
		memcpy(reply.dst_addr, snap.src_addr, 16);
		reply.src_port = snap.dst_port;
		reply.dst_port = snap.src_port;
		KUNIT_EXPECT_EQ(test,
				peios_ntfe_flow_dispatch(skb, &state, &reply),
				(unsigned int)NF_ACCEPT);
		KUNIT_EXPECT_EQ(test, pc->sentence[0].rule_hash,
				peios_ntfe_path_hash("out", 3));
		KUNIT_EXPECT_EQ(test, pc->direction, (u8)PEIOS_NTFE_DIR_OUT);
	}

	/* Loopback: two endpoints, two sentences, the stricter answers.
	 * The same forest (passes outbound, drops inbound), judged first at
	 * the outbound endpoint (slot 0)...
	 */
	snap.loopback = 1;
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_EQ(test, pc->sentence[1].generation, 0ULL);
	/* ...then at the inbound endpoint (slot 1). */
	snap.direction = PEIOS_NTFE_DIR_IN;
	snap.seat = PEIOS_NTFE_SEAT_LOCAL_IN;
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, pc->sentence[1].verdict,
			(u8)PEIOS_NTFE_VERDICT_DROP);
	/* The outbound endpoint's own sentence says PASS, but the flow
	 * answers to the stricter of the two.
	 */
	snap.direction = PEIOS_NTFE_DIR_OUT;
	snap.seat = PEIOS_NTFE_SEAT_LOCAL_OUT;
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_DROP);

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
	nf_conntrack_free(ct);
}

static void ntfe_kunit_refusal_is_built_and_marked(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 22);
	struct peios_ntfe_snapshot snap;
	struct sk_buff *nskb;
	const struct tcphdr *th;
	const struct icmphdr *ih;

	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);

	/* Refused, TCP: an RST from us (the SYN's destination) to the peer,
	 * carrying the refusal bit.
	 */
	nskb = peios_ntfe_refuse_build(skb, &state, &snap,
				      PEIOS_NTFE_REJECT_REFUSED);
	KUNIT_ASSERT_NOT_NULL(test, nskb);
	KUNIT_EXPECT_TRUE(test, nskb->ntfe_refusal);
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
	nskb = peios_ntfe_refuse_build(skb, &state, &snap,
				      PEIOS_NTFE_REJECT_PROHIBITED);
	KUNIT_ASSERT_NOT_NULL(test, nskb);
	KUNIT_EXPECT_TRUE(test, nskb->ntfe_refusal);
	KUNIT_EXPECT_EQ(test, ip_hdr(nskb)->protocol, IPPROTO_ICMP);
	ih = (const struct icmphdr *)((const u8 *)ip_hdr(nskb) +
				      ip_hdr(nskb)->ihl * 4);
	KUNIT_EXPECT_EQ(test, ih->type, ICMP_DEST_UNREACH);
	KUNIT_EXPECT_EQ(test, ih->code, ICMP_PKT_FILTERED);
	kfree_skb(nskb);

	/* At the egress seat the device has pushed its link header, and
	 * skb->data points at it: the answer is built from the same bytes,
	 * and the packet is left as it was found (PEI-1300).
	 */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	memset(skb->data, 0xee, ETH_HLEN);
	snap.seat = PEIOS_NTFE_SEAT_EGRESS;
	state.hook = NF_NETDEV_EGRESS;
	nskb = peios_ntfe_refuse_build(skb, &state, &snap,
				      PEIOS_NTFE_REJECT_REFUSED);
	KUNIT_ASSERT_NOT_NULL(test, nskb);
	th = (const struct tcphdr *)((const u8 *)ip_hdr(nskb) +
				     ip_hdr(nskb)->ihl * 4);
	KUNIT_EXPECT_TRUE(test, th->rst);
	KUNIT_EXPECT_EQ(test, th->source, htons(22));
	KUNIT_EXPECT_EQ(test, th->dest, htons(43210));
	KUNIT_EXPECT_EQ(test, th->ack_seq, htonl(1001));
	kfree_skb(nskb);
	KUNIT_EXPECT_PTR_EQ(test, skb->data, skb_mac_header(skb));
	KUNIT_EXPECT_EQ(test, skb_network_offset(skb), ETH_HLEN);
	skb_pull(skb, ETH_HLEN);

	/* A broadcast destination gets no answer. */
	snap.dst_addr[0] = 255;
	snap.dst_addr[1] = 255;
	snap.dst_addr[2] = 255;
	snap.dst_addr[3] = 255;
	KUNIT_EXPECT_NULL(test, peios_ntfe_refuse_build(skb, &state, &snap,
						       PEIOS_NTFE_REJECT_REFUSED));

	kfree_skb(skb);
}

static void ntfe_kunit_teardown_resets_the_far_end(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 443);
	struct tcphdr *oth = (struct tcphdr *)(skb_network_header(skb) +
					       sizeof(struct iphdr));
	struct peios_ntfe_snapshot snap;
	struct sk_buff *reset;
	const struct tcphdr *th;

	/* A data segment of an established connection, refused outbound. */
	oth->syn = 0;
	oth->ack = 1;
	oth->psh = 1;
	oth->seq = htonl(5000);
	oth->ack_seq = htonl(9000);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_OUT,
						    PEIOS_NTFE_DIR_OUT, &snap),
			0);
	/* No conntrack in this harness: say what the seat would have said. */
	snap.flow_state = PEIOS_NTFE_FLOW_ESTABLISHED;

	reset = peios_ntfe_teardown_build(skb, &state, &snap);
	KUNIT_ASSERT_NOT_NULL(test, reset);
	KUNIT_EXPECT_TRUE(test, reset->ntfe_refusal);
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
	snap.flow_state = PEIOS_NTFE_FLOW_NEW;
	KUNIT_EXPECT_NULL(test, peios_ntfe_teardown_build(skb, &state, &snap));
	/* Nor does a reset get one. */
	snap.flow_state = PEIOS_NTFE_FLOW_ESTABLISHED;
	snap.tcp_flags |= 0x04;
	KUNIT_EXPECT_NULL(test, peios_ntfe_teardown_build(skb, &state, &snap));
	/* Nor UDP. */
	snap.tcp_flags &= ~0x04;
	snap.protocol = IPPROTO_UDP;
	KUNIT_EXPECT_NULL(test, peios_ntfe_teardown_build(skb, &state, &snap));

	kfree_skb(skb);
}

static void ntfe_kunit_own_refusals_bypass_the_seats(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 22);
	u64 bypassed0 = atomic64_read(&peios_ntfe_stats.refusals_bypassed);
	u64 judged0 = atomic64_read(&peios_ntfe_stats.judged);
	void *b, *forest = NULL;

	/* A Packet forest that drops everything... */
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "all", 3), 0);
	ntfe_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(forest, NULL, NULL, 1),
			0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.judged),
			judged0 + 1);

	/* ...cannot touch a refusal NTFE itself emitted. */
	skb->ntfe_refusal = 1;
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_egress(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.refusals_bypassed),
			bypassed0 + 2);

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
}

/* Ordinary echo is never an NTFE-generated refusal. Both families and both
 * echo types must traverse Packet and RawPacket enforcement in each direction.
 */
static void ntfe_kunit_echo_obeys_policy(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = { .in = dev, .out = dev, .net = &init_net };
	u64 bypassed = atomic64_read(&peios_ntfe_stats.refusals_bypassed);
	int family, reply, layer, allow;

	for (layer = 0; layer < 2; layer++) {
		for (allow = 0; allow < 2; allow++) {
			void *b = ntfe_rust_builder_new(), *forest = NULL;
			u8 policy_layer = layer ? PEIOS_NTFE_LAYER_RAWPACKET :
				PEIOS_NTFE_LAYER_PACKET;
			KUNIT_ASSERT_NOT_NULL(test, b);
			KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "echo", 4), 0);
			ntfe_test_actions(test, b, allow ? "PASS" : "DROP");
			KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
			KUNIT_ASSERT_EQ(test, ntfe_rust_builder_build(b, policy_layer, &forest), 0);
			KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(
				layer ? NULL : forest, layer ? forest : NULL, NULL, 1), 0);
			for (family = 0; family < 2; family++) {
				for (reply = 0; reply < 2; reply++) {
					struct sk_buff *skb = alloc_skb(256, GFP_KERNEL);
					unsigned char *icmp;
					unsigned int expected = allow ? NF_ACCEPT : NF_DROP;
					KUNIT_ASSERT_NOT_NULL(test, skb);
					skb_reserve(skb, 64);
					skb_reset_network_header(skb);
					if (family) {
						struct ipv6hdr *ip = skb_put_zero(skb, sizeof(*ip));
						ip->version = 6;
						ip->nexthdr = IPPROTO_ICMPV6;
						ip->payload_len = htons(8);
						ip->hop_limit = 64;
						ip->saddr.s6_addr[15] = 1;
						ip->daddr.s6_addr[15] = 2;
						skb->protocol = htons(ETH_P_IPV6);
						state.pf = NFPROTO_IPV6;
					} else {
						struct iphdr *ip = skb_put_zero(skb, sizeof(*ip));
						ip->version = 4;
						ip->ihl = 5;
						ip->protocol = IPPROTO_ICMP;
						ip->tot_len = htons(sizeof(*ip) + 8);
						ip->ttl = 64;
						ip->saddr = htonl(0x0a000001);
						ip->daddr = htonl(0x0a000002);
						skb->protocol = htons(ETH_P_IP);
						state.pf = NFPROTO_IPV4;
					}
					skb_reset_transport_header(skb);
					icmp = skb_put_zero(skb, 8);
					icmp[0] = family ? (reply ? 129 : 128) :
						(reply ? ICMP_ECHOREPLY : ICMP_ECHO);
					KUNIT_EXPECT_FALSE(test, skb->ntfe_refusal);
					state.hook = layer ? NF_NETDEV_INGRESS : NF_INET_LOCAL_IN;
					KUNIT_EXPECT_EQ(test, layer ?
						peios_ntfe_hook_ingress(NULL, skb, &state) :
						peios_ntfe_hook_local_in(NULL, skb, &state), expected);
					state.hook = NF_NETDEV_EGRESS;
					KUNIT_EXPECT_EQ(test, peios_ntfe_hook_egress(NULL, skb, &state), expected);
					kfree_skb(skb);
				}
			}
		}
	}
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.refusals_bypassed), bypassed);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1), 0);
}

/* Actual loopback echo traverses the registered networking hooks. Publishing
 * one narrowly matched DROP must stop requests and replies independently,
 * without relying on a caller knowing that a firewall exists.
 */
static void ntfe_kunit_echo_on_wire(struct kunit *test)
{
	struct net_device *lo = init_net.loopback_dev;
	bool was_up = !!(lo->flags & IFF_UP);
	int family, block;

	rtnl_lock();
	KUNIT_EXPECT_EQ(test, dev_open(lo, NULL), 0);
	rtnl_unlock();
	msleep(50);
	for (family = 0; family < 2; family++) {
		for (block = 0; block < 5; block++) {
			void *b = ntfe_rust_builder_new(), *forest = NULL;
			struct socket *sock = NULL;
			struct sockaddr_storage address = { 0 };
			struct msghdr msg = { 0 };
			unsigned char packet[8] = { 0 }, response[128];
			struct kvec vec;
			int address_len, ret, received = -EAGAIN, retry;
			unsigned int type = family ? 128 : ICMP_ECHO;
			KUNIT_ASSERT_NOT_NULL(test, b);
			KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "echo", 4), 0);
			ntfe_test_actions(test, b, "PASS");
			if (block) {
				const char *direction = block % 2 ? "out" : "in";
				unsigned int denied_type = block > 2 ?
					(family ? 129 : ICMP_ECHOREPLY) : type;
				KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "deny", 4), 0);
				KUNIT_ASSERT_EQ(test, ntfe_rust_builder_value_str(b,
					"Direction.Equal", 15, direction, strlen(direction)), 0);
				KUNIT_ASSERT_EQ(test, ntfe_rust_builder_value_int(b,
					"IcmpType.Equal", 14, denied_type), 0);
				ntfe_test_actions(test, b, "DROP");
				KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
			}
			KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
			KUNIT_ASSERT_EQ(test, ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET, &forest), 0);
			KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(forest, NULL, NULL, 1), 0);
			ret = sock_create(family ? AF_INET6 : AF_INET, SOCK_DGRAM,
				family ? IPPROTO_ICMPV6 : IPPROTO_ICMP, &sock);
			KUNIT_ASSERT_EQ(test, ret, 0);
			if (family) {
				struct sockaddr_in6 *a = (void *)&address;
				a->sin6_family = AF_INET6;
				a->sin6_addr = in6addr_loopback;
				address_len = sizeof(*a);
			} else {
				struct sockaddr_in *a = (void *)&address;
				a->sin_family = AF_INET;
				a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				address_len = sizeof(*a);
			}
			packet[0] = type;
			if (!family)
				((struct icmphdr *)packet)->checksum = ip_compute_csum(packet, sizeof(packet));
			msg.msg_name = &address;
			msg.msg_namelen = address_len;
			vec.iov_base = packet;
			vec.iov_len = sizeof(packet);
			ret = kernel_sendmsg(sock, &msg, &vec, 1, sizeof(packet));
			if (!block)
				KUNIT_EXPECT_EQ(test, ret, (int)sizeof(packet));
			/* A drop may be reported at send or consume the skb later. */
			for (retry = 0; retry < 20; retry++) {
				memset(&msg, 0, sizeof(msg));
				vec.iov_base = response;
				vec.iov_len = sizeof(response);
				received = kernel_recvmsg(sock, &msg, &vec, 1,
						  sizeof(response), MSG_DONTWAIT);
				if (received != -EAGAIN)
					break;
				msleep(5);
			}
			if (block)
				KUNIT_EXPECT_EQ_MSG(test, received, -EAGAIN,
					"family=%d block=%d", family, block);
			else {
				KUNIT_EXPECT_EQ(test, received, (int)sizeof(packet));
				if (received > 0)
					KUNIT_EXPECT_EQ(test, response[0], (u8)(family ? 129 : ICMP_ECHOREPLY));
			}
			sock_release(sock);
		}
	}
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1), 0);
	if (!was_up) {
		rtnl_lock();
		dev_close(lo);
		rtnl_unlock();
	}
}

static void ntfe_kunit_downward_tag_read_refused(struct kunit *test)
{
	void *b, *packet = NULL, *flow = NULL;

	/* Packet reads a tag... */
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "r", 1), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_int(b, "Tag.admitted.Equal", 18,
						   1),
			0);
	ntfe_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &packet),
			0);
	/* ...that Flow writes: a downward read, refused at publication. */
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "w", 1), 0);
	ntfe_test_actions(test, b, "TAG(admitted, Set)");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_FLOW, &flow),
			0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_policy_publish(packet, NULL, flow, 1),
			-EINVAL);
	ntfe_rust_forest_free(packet);
	ntfe_rust_forest_free(flow);
}


/* The process GUID as the Local.Process fact's text (8-4-4-4-12). */
/* PCDS §2's text: %pUl is the little-endian GUID form, lowercase. */
static void ntfe_test_guid_text(const u8 guid[16], char out[37])
{
	snprintf(out, 37, "%pUl", guid);
}

/*
 * The identity facts (rung 3): the resolver classifies real sockets the
 * way the design says — a listening program, nobody, the stack, a kernel
 * socket, the sender — and the bridge lifts a program's token into the
 * Local.* facts a Flow forest judges.
 */
static void ntfe_kunit_identity_facts(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
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
	struct peios_ntfe_identity id, kernel_id;
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_outcome out;
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

	skb = ntfe_test_tcp4_skb(test, 2222);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	peios_ntfe_identity_resolve(skb, &in_state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_NTFE_LOCAL_PROGRAM);
	KUNIT_EXPECT_EQ(test, id.unresolved, 0);
	KUNIT_ASSERT_NOT_NULL(test, id.owner.token);
	KUNIT_EXPECT_EQ(test, id.owner.pid, (s32)task_tgid_nr(current));
	KUNIT_EXPECT_NE(test, id.owner.comm[0], '\0');
	/* Its SIDs cross the bridge: a user SID, and no service SID here. */
	KUNIT_EXPECT_EQ(test, ntfe_rust_owner_sids(id.owner.token, user, service),
			0);
	KUNIT_EXPECT_EQ(test, user[0], 1);	/* SID revision */
	KUNIT_EXPECT_EQ(test, service[0], 0);
	kfree_skb(skb);

	/* Nobody listens on the next port: none. */
	skb = ntfe_test_tcp4_skb(test, 2223);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	peios_ntfe_identity_resolve(skb, &in_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_NTFE_LOCAL_NONE);
	KUNIT_EXPECT_NULL(test, kernel_id.owner.token);
	peios_ntfe_identity_release(&kernel_id);

	/* The stack consumes ICMP itself: kernel. A protocol nothing
	 * handles (253, experimental): none.
	 */
	iph = ip_hdr(skb);
	iph->protocol = IPPROTO_ICMP;
	peios_ntfe_identity_resolve(skb, &in_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_NTFE_LOCAL_KERNEL);
	peios_ntfe_identity_release(&kernel_id);
	iph->protocol = 253;
	peios_ntfe_identity_resolve(skb, &in_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_NTFE_LOCAL_NONE);
	peios_ntfe_identity_release(&kernel_id);
	kfree_skb(skb);

	/* Outbound: the sending socket's stamp; a kernel socket is the
	 * kernel's.
	 */
	skb = ntfe_test_tcp4_skb(test, 443);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_OUT,
						    PEIOS_NTFE_DIR_OUT, &snap),
			0);
	out_state.sk = sock->sk;
	peios_ntfe_identity_resolve(skb, &out_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_NTFE_LOCAL_PROGRAM);
	KUNIT_EXPECT_PTR_EQ(test, kernel_id.owner.token, id.owner.token);
	peios_ntfe_identity_release(&kernel_id);

	KUNIT_ASSERT_EQ(test,
			sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, 0,
					 &ksock),
			0);
	out_state.sk = ksock->sk;
	peios_ntfe_identity_resolve(skb, &out_state, &snap, false, &kernel_id);
	KUNIT_EXPECT_EQ(test, kernel_id.kind, (u8)PEIOS_NTFE_LOCAL_KERNEL);
	KUNIT_EXPECT_NULL(test, kernel_id.owner.token);
	peios_ntfe_identity_release(&kernel_id);
	sock_release(ksock);

	/* The bridge: a Flow forest over the identity facts, judged against
	 * the program's token and against the kernel.
	 */
	ntfe_test_guid_text(id.owner.guid, guid);
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "posture", 7), 0);
	ntfe_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "this-process", 12),
			0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Local.Process.Equal", 19,
						   guid, strlen(guid)),
			0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_int(b, "Local.Service.Present",
						   21, 0),
			0);
	ntfe_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "kernel", 6), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Local.Equal", 11,
						   "kernel", 6),
			0);
	ntfe_test_actions(test, b, "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_NOT_NULL(test, forest);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, forest, 1),
			0);
	KUNIT_EXPECT_TRUE(test, peios_ntfe_policy_has_layer(PEIOS_NTFE_LAYER_FLOW));
	KUNIT_EXPECT_FALSE(test,
			   peios_ntfe_policy_has_layer(PEIOS_NTFE_LAYER_PACKET));

	/* This program: the exception speaks. */
	snap.local_kind = PEIOS_NTFE_LOCAL_PROGRAM;
	snap.local_token = id.owner.token;
	memcpy(snap.local_guid, id.owner.guid, sizeof(snap.local_guid));
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "posture/this-process");

	/* Another process (a different GUID): the posture drops it. */
	snap.local_guid[0] ^= 0xff;
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_DROP);
	KUNIT_EXPECT_STREQ(test, out.attributed, "posture");

	/* The kernel: no principal, the kernel exception speaks. */
	snap.local_kind = PEIOS_NTFE_LOCAL_KERNEL;
	snap.local_token = NULL;
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "posture/kernel");

	kfree_skb(skb);
	peios_ntfe_identity_release(&id);
	sock_release(sock);
}

/*
 * The network context (context.c): netd's inventory as a per-interface
 * table, read into the snapshot's Network.* facts and judged by the
 * packet layers. A table that differs from the active one is a new
 * generation (every sentence re-judged); an identical one is nothing.
 */
static void ntfe_kunit_network_context(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct net_device *other = ntfe_test_dev(test, "eth1", false);
	struct peios_ntfe_context_table *table;
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_outcome out;
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 22);
	u64 gen;

	/* No table: no context on any interface, nothing to advance. */
	KUNIT_ASSERT_EQ(test, peios_ntfe_context_publish(NULL), 0);
	gen = ntfe_rust_generation();
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_NETWORK);
	KUNIT_EXPECT_EQ(test, peios_ntfe_context_count(), 0U);

	/* eth0 stands on a network the operator called home. */
	table = peios_ntfe_context_table_alloc(1);
	KUNIT_ASSERT_NOT_NULL(test, table);
	strscpy(table->entries[0].ifname, "eth0", IFNAMSIZ);
	strscpy(table->entries[0].network_id,
		"6f1c2a3b-9d8e-4f70-a1b2-c3d4e5f60718",
		PEIOS_NTFE_NETWORK_ID_LEN);
	strscpy(table->entries[0].network_name, "palfrey-home",
		PEIOS_NTFE_NETWORK_NAME_LEN);
	strscpy(table->entries[0].network_trust, "home",
		PEIOS_NTFE_NETWORK_TRUST_LEN);
	KUNIT_ASSERT_EQ(test, peios_ntfe_context_publish(table), 0);
	KUNIT_EXPECT_EQ(test, ntfe_rust_generation(), gen + 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_context_count(), 1U);

	/* The facts reach a traversal on eth0, and only eth0. */
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_NETWORK);
	KUNIT_EXPECT_STREQ(test, snap.network_id,
			   "6f1c2a3b-9d8e-4f70-a1b2-c3d4e5f60718");
	KUNIT_EXPECT_STREQ(test, snap.network_name, "palfrey-home");
	KUNIT_EXPECT_STREQ(test, snap.network_trust, "home");
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, other,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_FALSE(test, snap.has & PEIOS_NTFE_HAS_NETWORK);

	/* A Flow rule about the network judges by it: it speaks on eth0
	 * and is simply false (absent-fact law) on eth1.
	 */
	ntfe_test_publish_flow(test, "Network.Trust.Equal", "home", "PASS");
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_STREQ(test, out.attributed, "r");
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, other,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_DROP);
	KUNIT_EXPECT_STREQ(test, out.attributed, "backstop");

	/* The same table again (netd rewrote Status): nothing changes,
	 * so nothing advances and no sentence goes stale.
	 */
	gen = ntfe_rust_generation();
	table = peios_ntfe_context_table_alloc(1);
	KUNIT_ASSERT_NOT_NULL(test, table);
	strscpy(table->entries[0].ifname, "eth0", IFNAMSIZ);
	strscpy(table->entries[0].network_id,
		"6f1c2a3b-9d8e-4f70-a1b2-c3d4e5f60718",
		PEIOS_NTFE_NETWORK_ID_LEN);
	strscpy(table->entries[0].network_name, "palfrey-home",
		PEIOS_NTFE_NETWORK_NAME_LEN);
	strscpy(table->entries[0].network_trust, "home",
		PEIOS_NTFE_NETWORK_TRUST_LEN);
	KUNIT_ASSERT_EQ(test, peios_ntfe_context_publish(table), 0);
	KUNIT_EXPECT_EQ(test, ntfe_rust_generation(), gen);

	/* The operator changes the word: a new generation, and the same
	 * rule no longer speaks for eth0. Name and Trust left off the
	 * record are absent facts; the id is still one.
	 */
	table = peios_ntfe_context_table_alloc(1);
	KUNIT_ASSERT_NOT_NULL(test, table);
	strscpy(table->entries[0].ifname, "eth0", IFNAMSIZ);
	strscpy(table->entries[0].network_id,
		"6f1c2a3b-9d8e-4f70-a1b2-c3d4e5f60718",
		PEIOS_NTFE_NETWORK_ID_LEN);
	KUNIT_ASSERT_EQ(test, peios_ntfe_context_publish(table), 0);
	KUNIT_EXPECT_EQ(test, ntfe_rust_generation(), gen + 1);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_TRUE(test, snap.has & PEIOS_NTFE_HAS_NETWORK);
	KUNIT_EXPECT_EQ(test, snap.network_trust[0], 0);
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_DROP);
	ntfe_test_publish_flow(test, "Network.Id.Equal",
			      "6f1c2a3b-9d8e-4f70-a1b2-c3d4e5f60718", "PASS");
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_policy_eval(PEIOS_NTFE_LAYER_FLOW, &snap, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verdict, PEIOS_NTFE_VERDICT_PASS);

	/* Restore for whatever runs after this suite. */
	KUNIT_ASSERT_EQ(test, peios_ntfe_context_publish(NULL), 0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
}

/*
 * In force: a change is noted the moment the watch delivers it, and
 * walked once the debounced re-walk that started after it has finished —
 * here a walk that fails (no such source), which still counts: the
 * change was read and refused, and status says so.
 */
static void ntfe_kunit_ingest_progress(struct kunit *test)
{
	static const u8 guid[16] = { 0x5a };
	struct peios_ntfe_status status;
	u64 noted, walked;
	int i;

	peios_ntfe_ingest_progress(&noted, &walked);
	KUNIT_EXPECT_EQ(test, noted, walked);

	peios_ntfe_network_registry_changed(0x7ffffff0, guid);
	peios_ntfe_network_registry_changed(0x7ffffff0, guid);
	peios_ntfe_status_fill(&status);
	KUNIT_EXPECT_EQ(test, status.changes_noted, noted + 2);
	KUNIT_EXPECT_EQ(test, status.changes_walked, walked);

	for (i = 0; i < 100; i++) {
		peios_ntfe_status_fill(&status);
		if (status.changes_walked == status.changes_noted)
			break;
		msleep(20);
	}
	KUNIT_EXPECT_EQ(test, status.changes_walked, noted + 2);
	KUNIT_EXPECT_NE(test, status.last_ingest_error, 0ULL);
	KUNIT_EXPECT_EQ(test, status.contexts,
			(u64)peios_ntfe_context_count());
}

/*
 * The statements no guest can reach (PEI-1284's kunit stubs): an
 * evaluation that fails, an end nobody stamped, the sentence's and the
 * identity record's concurrency protocols, a handler with no socket, the
 * flow pointer's lifetime, and the device's allocation failures. The
 * failures are made on demand through the seams above.
 */

/* Empties the verdict ring: earlier cases leave their events behind. */
static void ntfe_test_events_drain(void)
{
	struct peios_ntfe_event ev;

	while (peios_ntfe_kunit_events_pop(&ev, 1))
		;
}

/*
 * Drains the ring, keeping the first event of @layer about @dst_port —
 * the one the step under test emitted (anything else the stack judged
 * meanwhile is passed over).
 */
static bool ntfe_test_event_find(u8 layer, u16 dst_port,
				 struct peios_ntfe_event *out)
{
	struct peios_ntfe_event ev;
	bool found = false;

	while (peios_ntfe_kunit_events_pop(&ev, 1)) {
		if (!found && ev.layer == layer && ev.dst_port == dst_port) {
			*out = ev;
			found = true;
		}
	}
	return found;
}

/* An outbound TCP flow's first packet at LOCAL_OUT, 10:30 UTC. */
static void ntfe_test_flow_snap(struct peios_ntfe_snapshot *snap,
			       struct nf_conn *ct)
{
	static const u8 src[4] = { 10, 0, 0, 5 }, dst[4] = { 192, 0, 2, 9 };

	memset(snap, 0, sizeof(*snap));
	snap->seat = PEIOS_NTFE_SEAT_LOCAL_OUT;
	snap->direction = PEIOS_NTFE_DIR_OUT;
	snap->addr_family = 4;
	snap->protocol = IPPROTO_TCP;
	memcpy(snap->src_addr, src, 4);
	memcpy(snap->dst_addr, dst, 4);
	snap->src_port = 40000;
	snap->dst_port = 443;
	snap->has = PEIOS_NTFE_HAS_PORTS | PEIOS_NTFE_HAS_TIME;
	snap->flow_state = PEIOS_NTFE_FLOW_NEW;
	snap->ifindex = 7;
	strscpy(snap->ifname, "eth0", IFNAMSIZ);
	/* 2026-09-02 10:30:00 UTC. */
	snap->t_year = 2026;
	snap->t_month = 9;
	snap->t_day_of_month = 2;
	snap->t_day_of_week = 3;
	snap->t_hour = 10;
	snap->t_minute = 30;
	snap->t_secs = 1788345000;
	snap->flow = ct;
}

/* Publishes a one-rule Packet forest. */
static void ntfe_test_publish_packet(struct kunit *test, const char *action)
{
	void *b, *forest = NULL;

	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "all", 3), 0);
	ntfe_test_actions(test, b, action);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(forest, NULL, NULL, 1),
			0);
}

/* Feeds a two-action list to the builder. */
static void ntfe_test_actions2(struct kunit *test, void *b, const char *first,
			       const char *second)
{
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_list_begin(b, "Actions", 7), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_list_str(b, first, strlen(first)), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_list_str(b, second, strlen(second)),
			0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_value_list_end(b), 0);
}

/*
 * Failing closed (§6.2): an evaluation that cannot finish — the walk's
 * atomic allocation refused, here by the eval seam — drops the packet,
 * counts fail_closed and emits an event attributed `fail-closed` with
 * FAIL_CLOSED. At a per-packet seat, and at the Flow dispatch, which
 * writes no sentence for a judgment it never made.
 */
static void ntfe_kunit_eval_failure_fails_closed(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
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
	struct nf_conn *ct = ntfe_test_flow(test);
	struct peios_ntfe_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_NTFE);
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_event *ev;
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 22);
	u64 failed0 = atomic64_read(&peios_ntfe_stats.fail_closed);
	u64 judged0 = atomic64_read(&peios_ntfe_stats.judged);
	u64 dropped0 = atomic64_read(&peios_ntfe_stats.verdict_drop);
	u64 flow_judged0;

	ev = kunit_kzalloc(test, sizeof(*ev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ev);
	KUNIT_ASSERT_NOT_NULL(test, pc);

	/* A Packet forest that passes everything... */
	ntfe_test_publish_packet(test, "PASS");
	ntfe_test_events_drain();

	/* ...has no answer when its evaluation fails: the packet drops. */
	atomic_set(&ntfe_kunit_fail_evals, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &in_state),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic_read(&ntfe_kunit_fail_evals), 0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.fail_closed),
			failed0 + 1);
	/* A failure is not a verdict: nothing was judged, nothing dropped
	 * by a rule.
	 */
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.judged), judged0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.verdict_drop),
			dropped0);
	KUNIT_ASSERT_TRUE(test,
			  ntfe_test_event_find(PEIOS_NTFE_LAYER_PACKET, 22, ev));
	KUNIT_EXPECT_EQ(test, ev->seat, (u8)PEIOS_NTFE_EV_SEAT_LOCAL_IN);
	KUNIT_EXPECT_EQ(test, ev->verdict, (u8)PEIOS_NTFE_EV_VERDICT_DROP);
	KUNIT_EXPECT_TRUE(test, ev->flags & PEIOS_NTFE_EV_F_FAIL_CLOSED);
	KUNIT_EXPECT_STREQ(test, (const char *)ev->attributed, "fail-closed");

	/* The same packet, the evaluation whole: the forest passes it. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &in_state),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.fail_closed),
			failed0 + 1);

	/* The Flow dispatch: a new flow's first judgment fails. */
	ntfe_test_publish_flow(test, NULL, NULL, "PASS");
	ntfe_test_flow_snap(&snap, ct);
	flow_judged0 = atomic64_read(&peios_ntfe_stats.flow_judged);
	ntfe_test_events_drain();
	atomic_set(&ntfe_kunit_fail_evals, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &out_state, &snap),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, atomic_read(&ntfe_kunit_fail_evals), 0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.fail_closed),
			failed0 + 2);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			flow_judged0);
	/* No judgment, no sentence. */
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation, 0ULL);
	KUNIT_ASSERT_TRUE(test,
			  ntfe_test_event_find(PEIOS_NTFE_LAYER_FLOW, 443, ev));
	KUNIT_EXPECT_EQ(test, ev->verdict, (u8)PEIOS_NTFE_EV_VERDICT_DROP);
	KUNIT_EXPECT_TRUE(test, ev->flags & PEIOS_NTFE_EV_F_FAIL_CLOSED);
	KUNIT_EXPECT_STREQ(test, (const char *)ev->attributed, "fail-closed");

	/* The flow's next packet is simply judged, and sentenced. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &out_state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			flow_judged0 + 1);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation,
			ntfe_rust_generation());

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
	nf_conntrack_free(ct);
}

/*
 * An end that cannot be attributed (§6.7, §6.9). An inet socket nobody
 * stamped — allocated by the stack with no creation hook run, so KACS
 * holds state for it but no owner — reads as the kernel's, confessed in
 * identity_unresolved, on the event's flag and in the flow's slot; its
 * listener record says the same. A loopback flow with no extension,
 * judged at the inbound seat, cannot see its sender: Remote is absent,
 * confessed alike.
 */
static void ntfe_kunit_identity_unresolved(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
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
	struct nf_conntrack_tuple orig = { }, repl = { };
	struct nf_conn *ct = ntfe_test_flow(test), *bare;
	struct peios_ntfe_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_NTFE);
	struct peios_ntfe_listener_rec *rec;
	struct peios_ntfe_identity id;
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_event *ev;
	struct socket *sock = NULL;
	struct sk_buff *skb;
	struct sock *sk;
	u64 unresolved0, uncached0;

	ev = kunit_kzalloc(test, sizeof(*ev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ev);
	rec = kunit_kzalloc(test, sizeof(*rec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rec);
	KUNIT_ASSERT_NOT_NULL(test, pc);
	dev_net_set(dev, &init_net);

	sk = sk_alloc(&init_net, PF_INET, GFP_KERNEL, &tcp_prot, 1);
	KUNIT_ASSERT_NOT_NULL(test, sk);
	skb = ntfe_test_tcp4_skb(test, 443);

	/* Resolved directly: the kernel's, unresolved, no token. */
	ntfe_test_flow_snap(&snap, ct);
	out_state.sk = sk;
	peios_ntfe_identity_resolve(skb, &out_state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_NTFE_LOCAL_KERNEL);
	KUNIT_EXPECT_EQ(test, id.unresolved, 1);
	KUNIT_EXPECT_NULL(test, id.owner.token);
	peios_ntfe_identity_release(&id);

	/* At a flow's first judgment: counted, recorded on the slot as
	 * unresolved (the flows record reads those fields), flagged on the
	 * event.
	 */
	ntfe_test_publish_flow(test, NULL, NULL, "PASS");
	ntfe_test_events_drain();
	unresolved0 = atomic64_read(&peios_ntfe_stats.identity_unresolved);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &out_state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&peios_ntfe_stats.identity_unresolved),
			unresolved0 + 1);
	KUNIT_EXPECT_EQ(test, pc->owner_recorded[0], 1);
	KUNIT_EXPECT_EQ(test, pc->owner_kind[0], (u8)PEIOS_NTFE_LOCAL_KERNEL);
	KUNIT_EXPECT_EQ(test, pc->owner_unresolved[0], 1);
	KUNIT_EXPECT_NULL(test, pc->owner[0].token);
	KUNIT_ASSERT_TRUE(test,
			  ntfe_test_event_find(PEIOS_NTFE_LAYER_FLOW, 443, ev));
	KUNIT_EXPECT_TRUE(test, ev->flags & PEIOS_NTFE_EV_F_IDENTITY_UNRESOLVED);
	KUNIT_EXPECT_EQ(test, ev->local_kind, (u8)PEIOS_NTFE_EV_LOCAL_KERNEL);
	KUNIT_EXPECT_EQ(test, ev->local_unresolved, 1);

	/* Its listener record: KERNEL, with owner_unresolved set... */
	peios_ntfe_kunit_listener_fill(rec, sk, IPPROTO_TCP);
	KUNIT_EXPECT_EQ(test, rec->owner_kind, (u8)PEIOS_NTFE_EV_LOCAL_KERNEL);
	KUNIT_EXPECT_EQ(test, rec->owner_unresolved, 1);
	/* ...where a socket a program made reads as the program's. */
	KUNIT_ASSERT_EQ(test, sock_create(AF_INET, SOCK_STREAM, 0, &sock), 0);
	peios_ntfe_kunit_listener_fill(rec, sock->sk, IPPROTO_TCP);
	KUNIT_EXPECT_EQ(test, rec->owner_kind, (u8)PEIOS_NTFE_EV_LOCAL_PROGRAM);
	KUNIT_EXPECT_EQ(test, rec->owner_unresolved, 0);
	KUNIT_EXPECT_EQ(test, rec->owner_pid, (s32)task_tgid_nr(current));
	sock_release(sock);

	/* A loopback flow with no extension, at the inbound seat: the
	 * sender was never recorded and cannot be seen here. Remote is
	 * absent and confessed; the local end (nobody on the port) is not.
	 */
	bare = nf_conntrack_alloc(&init_net, &nf_ct_zone_dflt, &orig, &repl,
				  GFP_KERNEL);
	KUNIT_ASSERT_FALSE(test, IS_ERR_OR_NULL(bare));
	KUNIT_ASSERT_NULL(test, nf_ct_ext_find(bare, NF_CT_EXT_NTFE));
	ntfe_test_flow_snap(&snap, bare);
	snap.seat = PEIOS_NTFE_SEAT_LOCAL_IN;
	snap.direction = PEIOS_NTFE_DIR_IN;
	snap.loopback = 1;
	ntfe_test_events_drain();
	unresolved0 = atomic64_read(&peios_ntfe_stats.identity_unresolved);
	uncached0 = atomic64_read(&peios_ntfe_stats.flow_uncached);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &in_state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&peios_ntfe_stats.identity_unresolved),
			unresolved0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_uncached),
			uncached0 + 1);
	KUNIT_ASSERT_TRUE(test,
			  ntfe_test_event_find(PEIOS_NTFE_LAYER_FLOW, 443, ev));
	KUNIT_EXPECT_TRUE(test, ev->flags & PEIOS_NTFE_EV_F_IDENTITY_UNRESOLVED);
	KUNIT_EXPECT_EQ(test, ev->remote_kind, (u8)PEIOS_NTFE_EV_LOCAL_ABSENT);
	KUNIT_EXPECT_EQ(test, ev->remote_unresolved, 1);
	KUNIT_EXPECT_EQ(test, ev->local_kind, (u8)PEIOS_NTFE_EV_LOCAL_NONE);
	KUNIT_EXPECT_EQ(test, ev->local_unresolved, 0);

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	nf_conntrack_free(bare);
	nf_conntrack_free(ct);
	kfree_skb(skb);
	sk_free(sk);
}

/*
 * The sentence's concurrency protocol (§6.8). A writer zeroes the
 * generation, writes the fields and publishes the generation last; a
 * reader that finds it mid-write — fields set, generation zero — reads
 * the slot as absent and the flow is simply judged, never answered by
 * the half-written verdict. (The other torn form, a whole write landing
 * between the reader's two generation loads, needs a second CPU at an
 * instant one thread cannot arrange.) Two first packets of a new flow
 * may both evaluate: both judgments run their effects and the second
 * write is the sentence.
 */
static void ntfe_kunit_sentence_concurrency(struct kunit *test)
{
	struct nf_conn *ct = ntfe_test_flow(test), *race = ntfe_test_flow(test);
	struct peios_ntfe_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_NTFE);
	struct peios_ntfe_ct *rpc = nf_ct_ext_find(race, NF_CT_EXT_NTFE);
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 443);
	struct peios_ntfe_snapshot snap, second;
	u64 judged0, cached0, rejudged0, expired0, tags0, writes0;
	u64 value = 0;
	void *b, *forest = NULL;

	KUNIT_ASSERT_NOT_NULL(test, pc);
	KUNIT_ASSERT_NOT_NULL(test, rpc);
	ntfe_test_publish_flow(test, NULL, NULL, "PASS");

	/* A slot caught mid-write: a DROP in the fields, no generation. */
	pc->sentence[0].expires_at = 0;
	pc->sentence[0].rule_hash = 0xdead;
	pc->sentence[0].verdict = PEIOS_NTFE_VERDICT_DROP;
	pc->sentence[0].reject_kind = 0;
	KUNIT_ASSERT_EQ(test, pc->sentence[0].generation, 0ULL);
	ntfe_test_flow_snap(&snap, ct);
	judged0 = atomic64_read(&peios_ntfe_stats.flow_judged);
	cached0 = atomic64_read(&peios_ntfe_stats.flow_cached);
	rejudged0 = atomic64_read(&peios_ntfe_stats.flow_rejudged);
	expired0 = atomic64_read(&peios_ntfe_stats.flow_expired);
	/* Not applied: read as absent, the flow is judged (and passes). */
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 1);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_cached),
			cached0);
	/* Absent, not stale: neither re-judgment counter moves. */
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_rejudged),
			rejudged0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_expired),
			expired0);
	/* The judgment's own write is whole, its generation published. */
	KUNIT_EXPECT_EQ(test, pc->sentence[0].generation,
			ntfe_rust_generation());
	KUNIT_EXPECT_EQ(test, pc->sentence[0].verdict,
			(u8)PEIOS_NTFE_VERDICT_PASS);
	KUNIT_EXPECT_EQ(test, pc->sentence[0].rule_hash,
			peios_ntfe_path_hash("r", 1));

	/* The same holds where a loopback flow reads its other endpoint's
	 * sentence: a half-written DROP there does not make this one
	 * stricter. Slot 0 is current, so this packet reads it.
	 */
	pc->sentence[1].verdict = PEIOS_NTFE_VERDICT_DROP;
	KUNIT_ASSERT_EQ(test, pc->sentence[1].generation, 0ULL);
	snap.loopback = 1;
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_cached),
			cached0 + 1);

	/* The first-packet race. Daytime passes and nighttime drops, both
	 * counting the flow in a tag.
	 */
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "day", 3), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Time.Hour.Equal", 15,
						   "9-17", 4),
			0);
	ntfe_test_actions2(test, b, "TAG(seen, Add)", "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "night", 5), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_str(b, "Time.Hour.Equal", 15,
						   "18-23", 5),
			0);
	ntfe_test_actions2(test, b, "TAG(seen, Add)", "DROP");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_FLOW, &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, forest, 1),
			0);

	/* Two packets of one new flow (two snapshots, one entry), both
	 * having read the slot empty: the first judged at 10:30...
	 */
	ntfe_test_flow_snap(&snap, race);
	second = snap;
	second.t_hour = 18;
	second.t_minute = 0;
	second.t_secs = 1788345000 - 1788345000 % 3600 + 8 * 3600;
	judged0 = atomic64_read(&peios_ntfe_stats.flow_judged);
	cached0 = atomic64_read(&peios_ntfe_stats.flow_cached);
	rejudged0 = atomic64_read(&peios_ntfe_stats.flow_rejudged);
	expired0 = atomic64_read(&peios_ntfe_stats.flow_expired);
	tags0 = atomic64_read(&peios_ntfe_stats.fx_tags);
	writes0 = atomic64_read(&peios_ntfe_stats.tag_writes);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, rpc->sentence[0].verdict,
			(u8)PEIOS_NTFE_VERDICT_PASS);
	/* ...and the second, which read the slot before that write landed
	 * (the empty slot it saw, restored), judged at 18:00.
	 */
	WRITE_ONCE(rpc->sentence[0].generation, 0);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &second),
			(unsigned int)NF_DROP);
	/* Both evaluated, and both ran their effects. */
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_judged),
			judged0 + 2);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_cached),
			cached0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_rejudged),
			rejudged0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.flow_expired),
			expired0);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.fx_tags),
			tags0 + 2);
	KUNIT_EXPECT_EQ(test, atomic64_read(&peios_ntfe_stats.tag_writes),
			writes0 + 2);
	KUNIT_EXPECT_EQ(test,
			peios_ntfe_tag_lookup(race,
					     peios_ntfe_path_hash("seen", 4),
					     &value),
			1);
	KUNIT_EXPECT_EQ(test, value, 2ULL);
	/* The second write won: the slot holds the second outcome. */
	KUNIT_EXPECT_EQ(test, rpc->sentence[0].generation,
			ntfe_rust_generation());
	KUNIT_EXPECT_EQ(test, rpc->sentence[0].verdict,
			(u8)PEIOS_NTFE_VERDICT_DROP);
	KUNIT_EXPECT_EQ(test, rpc->sentence[0].rule_hash,
			peios_ntfe_path_hash("night", 5));

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
	nf_conntrack_free(race);
	nf_conntrack_free(ct);
}

/* The CPU that recorded first, played from inside the seam. */
static int ntfe_test_race_runs;

static void ntfe_test_record_first(struct nf_conn *ct,
				   struct peios_ntfe_ct *pc, u32 slot)
{
	spin_lock_bh(&ct->lock);
	memset(&pc->owner[slot], 0, sizeof(pc->owner[slot]));
	pc->owner[slot].kind = PEIOS_NTFE_OWNER_KERNEL;
	strscpy(pc->owner[slot].comm, "first", sizeof(pc->owner[slot].comm));
	WRITE_ONCE(pc->owner_kind[slot], PEIOS_NTFE_LOCAL_KERNEL);
	WRITE_ONCE(pc->owner_unresolved[slot], 0);
	smp_store_release(&pc->owner_recorded[slot], 1);
	spin_unlock_bh(&ct->lock);
	ntfe_test_race_runs++;
}

/*
 * Two CPUs resolving a new flow's endpoint (§6.9): this one resolved a
 * program's socket, and before it took the flow's lock another recorded
 * the kernel. The first record stands — the judgment, the event and the
 * extension all carry it — and this one's resolution is let go.
 */
static void ntfe_kunit_identity_resolve_race(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPV4,
		.out = dev,
		.net = &init_net,
	};
	struct nf_conn *ct = ntfe_test_flow(test);
	struct peios_ntfe_ct *pc = nf_ct_ext_find(ct, NF_CT_EXT_NTFE);
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 443);
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_identity id;
	struct peios_ntfe_event *ev;
	struct socket *sock = NULL;

	ev = kunit_kzalloc(test, sizeof(*ev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ev);
	KUNIT_ASSERT_NOT_NULL(test, pc);

	/* A program's socket: on its own it resolves as the program. */
	KUNIT_ASSERT_EQ(test, sock_create(AF_INET, SOCK_STREAM, 0, &sock), 0);
	state.sk = sock->sk;
	ntfe_test_flow_snap(&snap, ct);
	peios_ntfe_identity_resolve(skb, &state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_NTFE_LOCAL_PROGRAM);
	KUNIT_EXPECT_NOT_NULL(test, id.owner.token);
	peios_ntfe_identity_release(&id);

	ntfe_test_publish_flow(test, NULL, NULL, "PASS");
	ntfe_test_events_drain();
	ntfe_test_race_runs = 0;
	WRITE_ONCE(ntfe_kunit_on_resolved, ntfe_test_record_first);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flow_dispatch(skb, &state, &snap),
			(unsigned int)NF_ACCEPT);
	WRITE_ONCE(ntfe_kunit_on_resolved, NULL);
	/* The losing branch was taken, once. */
	KUNIT_EXPECT_EQ(test, ntfe_test_race_runs, 1);

	/* The first record stands on the extension... */
	KUNIT_EXPECT_EQ(test, pc->owner_kind[0], (u8)PEIOS_NTFE_LOCAL_KERNEL);
	KUNIT_EXPECT_NULL(test, pc->owner[0].token);
	KUNIT_EXPECT_STREQ(test, pc->owner[0].comm, "first");
	/* ...and is what was judged and told. */
	KUNIT_ASSERT_TRUE(test,
			  ntfe_test_event_find(PEIOS_NTFE_LAYER_FLOW, 443, ev));
	KUNIT_EXPECT_EQ(test, ev->local_kind, (u8)PEIOS_NTFE_EV_LOCAL_KERNEL);
	KUNIT_EXPECT_EQ(test, ev->local_pid, 0);
	KUNIT_EXPECT_STREQ(test, (const char *)ev->local_comm, "first");

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	kfree_skb(skb);
	nf_conntrack_free(ct);
	sock_release(sock);
}

static int ntfe_test_proto_rcv(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static const struct net_protocol ntfe_test_proto = {
	.handler = ntfe_test_proto_rcv,
};

/*
 * The classification is a rule, not a list (§6.9): a protocol nobody
 * receives on a socket reads `kernel` while the stack has a handler
 * registered for it — SCTP while its module is loaded — and `none` once
 * it has not. Played with an experimental protocol number.
 */
static void ntfe_kunit_identity_handler_reads_kernel(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 2223);
	struct peios_ntfe_snapshot snap;
	struct peios_ntfe_identity id;

	dev_net_set(dev, &init_net);
	ip_hdr(skb)->protocol = 253;
	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);

	/* No handler, no socket: nothing will receive it. */
	peios_ntfe_identity_resolve(skb, &state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_NTFE_LOCAL_NONE);
	peios_ntfe_identity_release(&id);

	/* A handler registered: the stack's. */
	KUNIT_ASSERT_EQ(test, inet_add_protocol(&ntfe_test_proto, 253), 0);
	peios_ntfe_identity_resolve(skb, &state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_NTFE_LOCAL_KERNEL);
	KUNIT_EXPECT_EQ(test, id.unresolved, 0);
	peios_ntfe_identity_release(&id);
	KUNIT_ASSERT_EQ(test, inet_del_protocol(&ntfe_test_proto, 253), 0);

	/* Unregistered again: none. */
	peios_ntfe_identity_resolve(skb, &state, &snap, false, &id);
	KUNIT_EXPECT_EQ(test, id.kind, (u8)PEIOS_NTFE_LOCAL_NONE);
	peios_ntfe_identity_release(&id);
	kfree_skb(skb);
}

/*
 * The snapshot's flow pointer (§6.3) is valid for the hook because the
 * skb holds the entry: with every other reference gone, an evaluation
 * still reads and writes the entry's tags, and the entry dies when the
 * skb does, not before.
 */
static void ntfe_kunit_flow_pointer_held_by_skb(struct kunit *test)
{
	struct net_device *dev = ntfe_test_dev(test, "eth0", false);
	struct nf_hook_state state = {
		.hook = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPV4,
		.in = dev,
		.net = &init_net,
	};
	struct nf_conn *ct = ntfe_test_flow(test);
	struct sk_buff *skb = ntfe_test_tcp4_skb(test, 22);
	struct peios_ntfe_snapshot snap;
	u64 hits = peios_ntfe_path_hash("hits", 4), value = 0;
	void *b, *forest = NULL;
	u32 count;

	/* The table's reference, as confirmation sets it; then the skb's. */
	refcount_set(&ct->ct_general.use, 1);
	nf_conntrack_get(&ct->ct_general);
	nf_ct_set(skb, ct, IP_CT_NEW);
	/* Every reference but the skb's goes. */
	nf_ct_put(ct);
	KUNIT_EXPECT_EQ(test, refcount_read(&ct->ct_general.use), 1U);

	KUNIT_ASSERT_EQ(test,
			peios_ntfe_snapshot_from_skb(skb, dev,
						    PEIOS_NTFE_SEAT_LOCAL_IN,
						    PEIOS_NTFE_DIR_IN, &snap),
			0);
	KUNIT_EXPECT_PTR_EQ(test, snap.flow, (const void *)ct);
	KUNIT_EXPECT_EQ(test, snap.flow_state, PEIOS_NTFE_FLOW_NEW);

	/* A Packet forest that counts the flow in a tag and drops it once
	 * the tag reads one.
	 */
	b = ntfe_rust_builder_new();
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "count", 5), 0);
	ntfe_test_actions2(test, b, "TAG(hits, Add)", "PASS");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_begin(b, "again", 5), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_value_int(b, "Tag.hits.Equal", 14, 1),
			0);
	ntfe_test_actions(test, b, "DROP");
	KUNIT_ASSERT_EQ(test, ntfe_rust_builder_rule_end(b), 0);
	KUNIT_ASSERT_EQ(test,
			ntfe_rust_builder_build(b, PEIOS_NTFE_LAYER_PACKET,
					       &forest),
			0);
	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(forest, NULL, NULL, 1),
			0);

	/* Written through the pointer, then read back through it. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_ACCEPT);
	KUNIT_EXPECT_EQ(test, peios_ntfe_hook_local_in(NULL, skb, &state),
			(unsigned int)NF_DROP);
	KUNIT_EXPECT_EQ(test, peios_ntfe_tag_lookup(ct, hits, &value), 1);
	KUNIT_EXPECT_EQ(test, value, 2ULL);
	/* Still alive on the skb's reference alone. */
	KUNIT_EXPECT_EQ(test, refcount_read(&ct->ct_general.use), 1U);

	KUNIT_ASSERT_EQ(test, peios_ntfe_policy_publish(NULL, NULL, NULL, 1),
			0);
	/* The skb goes, and the entry with it. */
	count = nf_conntrack_count(&init_net);
	kfree_skb(skb);
	KUNIT_EXPECT_EQ(test, nf_conntrack_count(&init_net), count - 1);
}

/*
 * The device's allocation failures (§6.A2): read()'s batch, and the
 * counters, flows and listeners dumps' buffers, refused by the alloc
 * seam, are ENOMEM — before any user memory is touched, and with the
 * ring's events still there to read.
 */
static void ntfe_kunit_device_allocation_enomem(struct kunit *test)
{
	struct peios_ntfe_snapshot snap = {
		.seat = PEIOS_NTFE_SEAT_LOCAL_IN,
		.direction = PEIOS_NTFE_DIR_IN,
		.addr_family = 4,
		.protocol = 6,
		.src_port = 43210,
		.dst_port = 7,
		.length = 60,
	};
	struct peios_ntfe_outcome out = {
		.verdict = PEIOS_NTFE_VERDICT_PASS,
	};
	struct peios_ntfe_counters_query counters = { };
	struct peios_ntfe_flows_query flows = { };
	struct peios_ntfe_listeners_query listeners = { };
	const struct file_operations *fops = peios_ntfe_kunit_dev_fops();
	struct peios_ntfe_event *ev;
	struct file *file;
	loff_t pos = 0;

	ev = kunit_kzalloc(test, sizeof(*ev), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ev);
	file = kunit_kzalloc(test, sizeof(*file), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, file);
	file->f_flags = O_NONBLOCK;

	/* The three dumps, each refused its buffer. */
	atomic_set(&ntfe_kunit_fail_allocs, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_counters_dump(&counters),
			(long)-ENOMEM);
	atomic_set(&ntfe_kunit_fail_allocs, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flows_dump(&flows), (long)-ENOMEM);
	atomic_set(&ntfe_kunit_fail_allocs, 1);
	KUNIT_EXPECT_EQ(test, peios_ntfe_listeners_dump(&listeners),
			(long)-ENOMEM);
	KUNIT_EXPECT_EQ(test, atomic_read(&ntfe_kunit_fail_allocs), 0);
	/* With the allocation whole, the same queries (no room) answer. */
	KUNIT_EXPECT_EQ(test, peios_ntfe_counters_dump(&counters), 0L);
	KUNIT_EXPECT_EQ(test, peios_ntfe_flows_dump(&flows), 0L);
	KUNIT_EXPECT_EQ(test, peios_ntfe_listeners_dump(&listeners), 0L);

	/* read(): an event waits; the batch is refused. */
	ntfe_test_events_drain();
	strscpy(out.attributed, "enomem-probe", sizeof(out.attributed));
	peios_ntfe_event_emit(&snap, &out, PEIOS_NTFE_LAYER_PACKET, 0);
	atomic_set(&ntfe_kunit_fail_allocs, 1);
	KUNIT_EXPECT_EQ(test,
			fops->read(file, NULL, sizeof(struct peios_ntfe_event),
				   &pos),
			(ssize_t)-ENOMEM);
	KUNIT_EXPECT_EQ(test, atomic_read(&ntfe_kunit_fail_allocs), 0);
	/* The read claimed the stream; closing gives it back. */
	fops->release(NULL, file);
	/* The ring is untouched: the event is still there. */
	KUNIT_ASSERT_TRUE(test,
			  ntfe_test_event_find(PEIOS_NTFE_LAYER_PACKET, 7, ev));
	KUNIT_EXPECT_STREQ(test, (const char *)ev->attributed, "enomem-probe");
}

static void ntfe_kunit_exit(struct kunit *test)
{
	atomic_set(&ntfe_kunit_fail_evals, 0);
	atomic_set(&ntfe_kunit_fail_allocs, 0);
	WRITE_ONCE(ntfe_kunit_on_resolved, NULL);
}

/*
 * PEI-1377: forty UDP sockets in one SO_REUSEPORT group share one hash
 * slot, more than one batch of the listeners dump. With room for every
 * record, every one is written: the slot is walked again from where the
 * batch filled, as the flows dump does since PEI-1308.
 */
#define NTFE_KUNIT_CROWD	40
#define NTFE_KUNIT_CROWD_PORT	4747
#define NTFE_KUNIT_CROWD_ROOM	512

static void ntfe_kunit_listeners_crowded_bucket(struct kunit *test)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(NTFE_KUNIT_CROWD_PORT),
	};
	struct peios_ntfe_listeners_query query = { };
	struct peios_ntfe_listener_rec *recs;
	struct socket *socks[NTFE_KUNIT_CROWD] = { };
	size_t len = NTFE_KUNIT_CROWD_ROOM * sizeof(*recs);
	unsigned long ubuf;
	u32 i, crowd = 0;

	for (i = 0; i < NTFE_KUNIT_CROWD; i++) {
		KUNIT_ASSERT_EQ(test,
				sock_create_kern(&init_net, AF_INET, SOCK_DGRAM,
						 IPPROTO_UDP, &socks[i]),
				0);
		sock_set_reuseport(socks[i]->sk);
		KUNIT_ASSERT_EQ(test,
				kernel_bind(socks[i],
					    (struct sockaddr_unsized *)&addr,
					    sizeof(addr)),
				0);
	}

	ubuf = kunit_vm_mmap(test, NULL, 0, len, PROT_READ | PROT_WRITE,
			     MAP_ANONYMOUS | MAP_PRIVATE, 0);
	KUNIT_ASSERT_NE(test, ubuf, 0UL);
	recs = kunit_kzalloc(test, len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, recs);

	query.buf = ubuf;
	query.buf_len = len;
	KUNIT_EXPECT_EQ(test, peios_ntfe_listeners_dump(&query), 0L);
	KUNIT_ASSERT_LE(test, query.total, (u32)NTFE_KUNIT_CROWD_ROOM);
	KUNIT_EXPECT_EQ(test, query.count, query.total);
	KUNIT_ASSERT_EQ(test,
			copy_from_user(recs, (void __user *)ubuf,
				       query.count * sizeof(*recs)),
			0UL);
	for (i = 0; i < query.count; i++)
		if (recs[i].port == NTFE_KUNIT_CROWD_PORT &&
		    recs[i].protocol == IPPROTO_UDP)
			crowd++;
	KUNIT_EXPECT_EQ(test, crowd, (u32)NTFE_KUNIT_CROWD);

	for (i = 0; i < NTFE_KUNIT_CROWD; i++)
		if (socks[i])
			sock_release(socks[i]);
}

static struct kunit_case ntfe_kunit_cases[] = {
	KUNIT_CASE(ntfe_kunit_rust_probe),
	KUNIT_CASE(ntfe_kunit_dispatch_predicate),
	KUNIT_CASE(ntfe_kunit_snapshot_tcp4),
	KUNIT_CASE(ntfe_kunit_snapshot_arp),
	KUNIT_CASE(ntfe_kunit_snapshot_udp6),
	KUNIT_CASE(ntfe_kunit_end_to_end_enforcement),
	KUNIT_CASE(ntfe_kunit_deepest_tree),
	KUNIT_CASE(ntfe_kunit_event_stream),
	KUNIT_CASE(ntfe_kunit_reject_kinds_cross_the_bridge),
	KUNIT_CASE(ntfe_kunit_tag_store),
	KUNIT_CASE(ntfe_kunit_counter_store),
	KUNIT_CASE(ntfe_kunit_report_lands_in_kmes),
	KUNIT_CASE(ntfe_kunit_snapshot_local_out),
	KUNIT_CASE(ntfe_kunit_flow_sentence),
	KUNIT_CASE(ntfe_kunit_refusal_is_built_and_marked),
	KUNIT_CASE(ntfe_kunit_teardown_resets_the_far_end),
	KUNIT_CASE(ntfe_kunit_own_refusals_bypass_the_seats),
	KUNIT_CASE(ntfe_kunit_echo_obeys_policy),
	KUNIT_CASE(ntfe_kunit_echo_on_wire),
	KUNIT_CASE(ntfe_kunit_downward_tag_read_refused),
	KUNIT_CASE(ntfe_kunit_identity_facts),
	KUNIT_CASE(ntfe_kunit_network_context),
	KUNIT_CASE(ntfe_kunit_ingest_progress),
	KUNIT_CASE(ntfe_kunit_eval_failure_fails_closed),
	KUNIT_CASE(ntfe_kunit_identity_unresolved),
	KUNIT_CASE(ntfe_kunit_sentence_concurrency),
	KUNIT_CASE(ntfe_kunit_identity_resolve_race),
	KUNIT_CASE(ntfe_kunit_identity_handler_reads_kernel),
	KUNIT_CASE(ntfe_kunit_flow_pointer_held_by_skb),
	KUNIT_CASE(ntfe_kunit_device_allocation_enomem),
	KUNIT_CASE(ntfe_kunit_listeners_crowded_bucket),
	{}
};

static struct kunit_suite ntfe_kunit_suite = {
	.name = "pkm_kunit_ntfe",
	.exit = ntfe_kunit_exit,
	.test_cases = ntfe_kunit_cases,
};

kunit_test_suite(ntfe_kunit_suite);
