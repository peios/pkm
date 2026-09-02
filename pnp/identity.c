// SPDX-License-Identifier: GPL-2.0-only
/*
 * The identity facts (rung 3, PEI-598): what stands at the local end of a
 * flow, and who. Resolved once per flow at its first judgment — never per
 * packet — and recorded on the flow's extension, fixed for the flow's life
 * like the direction and the interface.
 *
 * Classification is by whether anyone answers, not by whether a socket
 * structure exists:
 *
 *   outbound  the sending socket's governing identity, stamped by KACS
 *             (<linux/peios_pnp.h>): `program` when a process's token
 *             stands behind it, else `kernel` (resets, ICMP errors, IGMP,
 *             kernel sockets);
 *   inbound   `shared` for UDP multicast and broadcast, which the stack
 *             delivers to every socket bound to the port (one flow, many
 *             endpoints — the per-program question belongs to the join,
 *             not here); otherwise a transport lookup for the receiver —
 *             TCP, UDP and UDP-Lite by tuple, raw sockets by protocol —
 *             gives `program`; failing that, a protocol the stack consumes
 *             itself (ICMP, neighbour discovery, tunnel outers) is
 *             `kernel`, and one nothing will receive is `none`.
 *
 * A loopback flow has two local ends. The outbound seat resolves both —
 * its own from the socket, the other by running the receiver lookup early
 * on the loopback-destined packet — so the inbound seat's judgment, on the
 * same first packet, sees `Remote.*` without a second lookup.
 */

#include <linux/errno.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/peios_pnp.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/inet6_hashtables.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/raw.h>
#include <net/rawv6.h>
#include <net/request_sock.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "pnp.h"

/* UDP-Lite's socket table (net/ipv4/udplite.c exports it, no header does). */
extern struct udp_table udplite_table;

/*
 * The UDP lookups netfilter's socket match uses exist only when that
 * module is built; the underlying lookups are unconditional and hand
 * back an unreferenced socket under RCU, so the reference is taken here.
 */
static struct sock *pnp_udp4_lookup(struct net *net, u8 protocol, __be32 saddr,
				    __be16 sport, __be32 daddr, __be16 dport,
				    int dif, struct sk_buff *skb)
{
	struct udp_table *table = protocol == IPPROTO_UDPLITE ?
		&udplite_table : net->ipv4.udp_table;
	struct sock *sk;

	rcu_read_lock();
	sk = __udp4_lib_lookup(net, saddr, sport, daddr, dport, dif, 0, table,
			       skb);
	if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sock *pnp_udp6_lookup(struct net *net, u8 protocol,
				    const struct in6_addr *saddr, __be16 sport,
				    const struct in6_addr *daddr, __be16 dport,
				    int dif, struct sk_buff *skb)
{
	struct udp_table *table = protocol == IPPROTO_UDPLITE ?
		&udplite_table : net->ipv4.udp_table;
	struct sock *sk;

	rcu_read_lock();
	sk = __udp6_lib_lookup(net, saddr, sport, daddr, dport, dif, 0, table,
			       skb);
	if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}
#endif

/* The owner a socket carries, mapped to the fact's kinds. */
static void pnp_identity_from_sock(const struct sock *sk,
				   struct peios_pnp_identity *out)
{
	int ret;

	ret = pkm_kacs_socket_owner(sk, &out->owner);
	if (ret) {
		/* A socket with no KACS state at all: not attributable. */
		out->kind = PEIOS_PNP_LOCAL_KERNEL;
		out->unresolved = 1;
		return;
	}
	switch (out->owner.kind) {
	case PEIOS_PNP_OWNER_PROGRAM:
		out->kind = PEIOS_PNP_LOCAL_PROGRAM;
		break;
	case PEIOS_PNP_OWNER_KERNEL:
		out->kind = PEIOS_PNP_LOCAL_KERNEL;
		break;
	default:
		/* An inet socket nobody stamped: the stack's, and confessed. */
		out->kind = PEIOS_PNP_LOCAL_KERNEL;
		out->unresolved = 1;
		break;
	}
}

/*
 * The full socket behind a lookup result: a request minisock stands for
 * its listener, a TIME_WAIT minisock for nobody (the stack answers it).
 */
static const struct sock *pnp_full_sock(const struct sock *sk)
{
	if (!sk)
		return NULL;
	if (sk_fullsock(sk))
		return sk;
	if (sk->sk_state == TCP_NEW_SYN_RECV)
		return inet_reqsk(sk)->rsk_listener;
	return NULL;
}

static struct sock *pnp_raw_v4_lookup(struct net *net, u8 protocol,
				      __be32 saddr, __be32 daddr, int dif)
{
	struct hlist_head *hlist;
	struct sock *sk;

	hlist = &raw_v4_hashinfo.ht[raw_hashfunc(net, protocol)];
	rcu_read_lock();
	sk_for_each_rcu(sk, hlist) {
		if (raw_v4_match(net, sk, protocol, saddr, daddr, dif, 0) &&
		    refcount_inc_not_zero(&sk->sk_refcnt)) {
			rcu_read_unlock();
			return sk;
		}
	}
	rcu_read_unlock();
	return NULL;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sock *pnp_raw_v6_lookup(struct net *net, u8 protocol,
				      const struct in6_addr *saddr,
				      const struct in6_addr *daddr, int dif)
{
	struct hlist_head *hlist;
	struct sock *sk;

	hlist = &raw_v6_hashinfo.ht[raw_hashfunc(net, protocol)];
	rcu_read_lock();
	sk_for_each_rcu(sk, hlist) {
		if (raw_v6_match(net, sk, protocol, daddr, saddr, dif, 0) &&
		    refcount_inc_not_zero(&sk->sk_refcnt)) {
			rcu_read_unlock();
			return sk;
		}
	}
	rcu_read_unlock();
	return NULL;
}
#endif

/*
 * The socket that will receive this packet, with a reference the caller
 * releases (sock_gen_put), or NULL. `*handled` says whether the protocol
 * is one the stack consumes when no socket does.
 */
static struct sock *pnp_receiver_v4(struct net *net, struct sk_buff *skb,
				    int dif, bool *handled, bool *shared)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct rtable *rt = skb_rtable(skb);
	int thoff = ip_hdrlen(skb);
	struct tcphdr _th;
	const struct tcphdr *th;
	struct udphdr _uh;
	const struct udphdr *uh;

	/* A transport with no socket is nobody's: the stack answers it with
	 * a reset or an unreachable rather than consuming it.
	 */
	*handled = iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
		   iph->protocol != IPPROTO_UDPLITE &&
		   rcu_access_pointer(inet_protos[iph->protocol]) != NULL;
	*shared = false;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		th = skb_header_pointer(skb, thoff, sizeof(_th), &_th);
		if (!th)
			return NULL;
		return inet_lookup(net, skb, thoff + __tcp_hdrlen(th),
				   iph->saddr, th->source, iph->daddr,
				   th->dest, dif);
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		if (rt && (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			*shared = true;
			return NULL;
		}
		uh = skb_header_pointer(skb, thoff, sizeof(_uh), &_uh);
		if (!uh)
			return NULL;
		return pnp_udp4_lookup(net, iph->protocol, iph->saddr,
				       uh->source, iph->daddr, uh->dest, dif,
				       skb);
	default:
		return pnp_raw_v4_lookup(net, iph->protocol, iph->saddr,
					 iph->daddr, dif);
	}
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sock *pnp_receiver_v6(struct net *net, struct sk_buff *skb,
				    int dif, bool *handled, bool *shared)
{
	const struct ipv6hdr *ip6 = ipv6_hdr(skb);
	struct tcphdr _th;
	const struct tcphdr *th;
	struct udphdr _uh;
	const struct udphdr *uh;
	int thoff = 0, proto;

	*handled = false;
	*shared = false;
	proto = ipv6_find_hdr(skb, &thoff, -1, NULL, NULL);
	if (proto < 0)
		return NULL;
	*handled = proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
		   proto != IPPROTO_UDPLITE &&
		   rcu_access_pointer(inet6_protos[proto]) != NULL;
	switch (proto) {
	case IPPROTO_TCP:
		th = skb_header_pointer(skb, thoff, sizeof(_th), &_th);
		if (!th)
			return NULL;
		return inet6_lookup(net, skb, thoff + __tcp_hdrlen(th),
				    &ip6->saddr, th->source, &ip6->daddr,
				    th->dest, dif);
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		if (ipv6_addr_is_multicast(&ip6->daddr)) {
			*shared = true;
			return NULL;
		}
		uh = skb_header_pointer(skb, thoff, sizeof(_uh), &_uh);
		if (!uh)
			return NULL;
		return pnp_udp6_lookup(net, (u8)proto, &ip6->saddr, uh->source,
				       &ip6->daddr, uh->dest, dif, skb);
	default:
		return pnp_raw_v6_lookup(net, proto, &ip6->saddr, &ip6->daddr,
					 dif);
	}
}
#else
static struct sock *pnp_receiver_v6(struct net *net, struct sk_buff *skb,
				    int dif, bool *handled, bool *shared)
{
	*handled = false;
	*shared = false;
	return NULL;
}
#endif

/* Whether the packet, as it stands, is addressed to this machine. */
static void pnp_identity_receiver(struct sk_buff *skb,
				  const struct net_device *dev,
				  struct peios_pnp_identity *out)
{
	struct net *net = dev ? dev_net(dev) : NULL;
	bool handled = false, shared = false;
	const struct sock *full;
	struct sock *sk = NULL;
	int dif;

	/* Early demux already found the receiver: use it, no lookup. */
	if (skb->sk && sk_fullsock(skb->sk)) {
		pnp_identity_from_sock(skb->sk, out);
		return;
	}
	/* No device, or one outside any namespace (a synthetic device in a
	 * test): nothing to look up in — the stack's, confessed.
	 */
	if (!net) {
		out->kind = PEIOS_PNP_LOCAL_KERNEL;
		out->unresolved = 1;
		return;
	}
	dif = dev->ifindex;
	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		sk = pnp_receiver_v4(net, skb, dif, &handled, &shared);
		break;
	case ETH_P_IPV6:
		sk = pnp_receiver_v6(net, skb, dif, &handled, &shared);
		break;
	default:
		break;
	}
	if (shared) {
		out->kind = PEIOS_PNP_LOCAL_SHARED;
		return;
	}
	full = pnp_full_sock(sk);
	if (full) {
		pnp_identity_from_sock(full, out);
	} else if (sk) {
		/* A TIME_WAIT minisock: the stack answers, nobody receives. */
		out->kind = PEIOS_PNP_LOCAL_KERNEL;
	} else {
		out->kind = handled ? PEIOS_PNP_LOCAL_KERNEL :
				      PEIOS_PNP_LOCAL_NONE;
	}
	if (sk)
		sock_gen_put(sk);
}

void peios_pnp_identity_resolve(struct sk_buff *skb,
				const struct nf_hook_state *state,
				const struct peios_pnp_snapshot *snap,
				bool other_end, struct peios_pnp_identity *out)
{
	memset(out, 0, sizeof(*out));
	out->owner.kind = PEIOS_PNP_OWNER_UNSTAMPED;

	if (snap->seat == PEIOS_PNP_SEAT_LOCAL_OUT && !other_end) {
		const struct sock *sk = state->sk ? state->sk : skb->sk;

		if (sk && sk_fullsock(sk))
			pnp_identity_from_sock(sk, out);
		else
			out->kind = PEIOS_PNP_LOCAL_KERNEL;
		return;
	}
	if (snap->seat == PEIOS_PNP_SEAT_LOCAL_OUT) {
		/* The other end of a loopback flow: the receiver of this very
		 * packet, looked up early so the inbound seat need not.
		 */
		pnp_identity_receiver(skb, state->out, out);
		return;
	}
	if (!other_end) {
		pnp_identity_receiver(skb, state->in, out);
		return;
	}
	/* The inbound seat cannot see a loopback packet's sender (loopback
	 * transmission orphans the skb); the outbound seat recorded it.
	 */
	out->kind = PEIOS_PNP_LOCAL_ABSENT;
	out->unresolved = 1;
}

void peios_pnp_identity_release(struct peios_pnp_identity *id)
{
	pkm_kacs_socket_owner_put(&id->owner);
}
