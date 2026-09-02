// SPDX-License-Identifier: GPL-2.0-only
/*
 * The listeners dump (PEIOS_PNP_IOC_LISTENERS): what this machine is
 * prepared to receive, and by whom — every TCP socket in the listening
 * state and every bound UDP socket, with the governing identity KACS
 * stamped on it (identity facts, rung 3). The attack surface as a list,
 * without a packet having to arrive: the same stamp the Flow layer reads
 * at a flow's first judgment, read here at rest.
 *
 * Walked the way /proc/net/tcp and /proc/net/udp walk their tables —
 * the listening hash under each bucket's lock, the UDP hash under each
 * slot's lock — for init_net only, batched and copied to user between
 * buckets, never under a lock. Best-effort against tables that change
 * under the walk; the caller is told how many it saw.
 */

#include <linux/errno.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/peios_pnp.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/netns/ipv4.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <pkm/pnp.h>

#include "pnp.h"

/* UDP-Lite's socket table (net/ipv4/udplite.c exports it, no header does). */
extern struct udp_table udplite_table;

#define PNP_LISTENERS_BATCH	32

/* One socket into one record; the owner read takes the socket's lock. */
static void pnp_listener_fill(struct peios_pnp_listener_rec *rec,
			      const struct sock *sk, u8 protocol)
{
	const struct inet_sock *inet = inet_sk(sk);
	struct peios_pnp_owner owner;

	memset(rec, 0, sizeof(*rec));
	rec->protocol = protocol;
	rec->family = sk->sk_family == AF_INET6 ? 6 : 4;
	rec->port = inet->inet_num;
	rec->ifindex = sk->sk_bound_dev_if;
	rec->reuseport = sk->sk_reuseport ? 1 : 0;
	rec->connected = inet->inet_dport != 0;
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6) {
		memcpy(rec->addr, &sk->sk_v6_rcv_saddr, 16);
		rec->v6only = ipv6_only_sock(sk) ? 1 : 0;
	} else
#endif
		memcpy(rec->addr, &inet->inet_rcv_saddr, 4);

	if (pkm_kacs_socket_owner(sk, &owner)) {
		rec->owner_kind = PEIOS_PNP_EV_LOCAL_KERNEL;
		rec->owner_unresolved = 1;
		return;
	}
	switch (owner.kind) {
	case PEIOS_PNP_OWNER_PROGRAM:
		rec->owner_kind = PEIOS_PNP_EV_LOCAL_PROGRAM;
		break;
	case PEIOS_PNP_OWNER_KERNEL:
		rec->owner_kind = PEIOS_PNP_EV_LOCAL_KERNEL;
		break;
	default:
		rec->owner_kind = PEIOS_PNP_EV_LOCAL_KERNEL;
		rec->owner_unresolved = 1;
		break;
	}
	rec->owner_pid = owner.pid;
	memcpy(rec->owner_guid, owner.guid, sizeof(rec->owner_guid));
	memcpy(rec->owner_comm, owner.comm, sizeof(rec->owner_comm));
	if (owner.token)
		pnp_rust_owner_sids(owner.token, rec->owner_user,
				    rec->owner_service);
	pkm_kacs_socket_owner_put(&owner);
}

struct pnp_listeners_walk {
	struct peios_pnp_listener_rec __user *ubuf;
	struct peios_pnp_listener_rec *batch;
	u32 room;		/* records the user buffer holds */
	u32 written;
	u32 total;
	u32 n;			/* records in the batch */
	long err;
};

/* Copies the batch out; never called under a lock. */
static void pnp_listeners_flush(struct pnp_listeners_walk *w)
{
	if (w->err || !w->n)
		return;
	if (copy_to_user(w->ubuf + w->written, w->batch,
			 w->n * sizeof(*w->batch)))
		w->err = -EFAULT;
	w->written += w->n;
	w->n = 0;
}

/* Records a socket seen under its bucket lock, if there is room. */
static void pnp_listeners_note(struct pnp_listeners_walk *w,
			       const struct sock *sk, u8 protocol)
{
	w->total++;
	if (w->written + w->n >= w->room || w->n == PNP_LISTENERS_BATCH)
		return;		/* count only */
	pnp_listener_fill(&w->batch[w->n++], sk, protocol);
}

static void pnp_listeners_tcp(struct pnp_listeners_walk *w)
{
	struct inet_hashinfo *hinfo = init_net.ipv4.tcp_death_row.hashinfo;
	unsigned int bucket;

	for (bucket = 0; bucket <= hinfo->lhash2_mask && !w->err; bucket++) {
		struct inet_listen_hashbucket *ilb2 = &hinfo->lhash2[bucket];
		struct hlist_nulls_node *node;
		struct sock *sk;

		if (hlist_nulls_empty(&ilb2->nulls_head))
			continue;
		spin_lock(&ilb2->lock);
		sk_nulls_for_each(sk, node, &ilb2->nulls_head) {
			if (!net_eq(sock_net(sk), &init_net))
				continue;
			if (sk->sk_state != TCP_LISTEN)
				continue;
			pnp_listeners_note(w, sk, IPPROTO_TCP);
		}
		spin_unlock(&ilb2->lock);
		pnp_listeners_flush(w);
	}
}

static void pnp_listeners_udp(struct pnp_listeners_walk *w,
			      struct udp_table *table, u8 protocol)
{
	unsigned int bucket;

	if (!table)
		return;
	for (bucket = 0; bucket <= table->mask && !w->err; bucket++) {
		struct udp_hslot *hslot = &table->hash[bucket];
		struct sock *sk;

		if (hlist_empty(&hslot->head))
			continue;
		spin_lock_bh(&hslot->lock);
		sk_for_each(sk, &hslot->head) {
			if (!net_eq(sock_net(sk), &init_net))
				continue;
			if (!inet_sk(sk)->inet_num)
				continue;	/* not bound: receives nothing */
			pnp_listeners_note(w, sk, protocol);
		}
		spin_unlock_bh(&hslot->lock);
		pnp_listeners_flush(w);
	}
}

long peios_pnp_listeners_dump(struct peios_pnp_listeners_query *query)
{
	struct pnp_listeners_walk w = {
		.ubuf = u64_to_user_ptr(query->buf),
		.room = query->buf_len / sizeof(struct peios_pnp_listener_rec),
	};

	w.batch = kcalloc(PNP_LISTENERS_BATCH, sizeof(*w.batch), GFP_KERNEL);
	if (!w.batch)
		return -ENOMEM;

	pnp_listeners_tcp(&w);
	if (!w.err)
		pnp_listeners_udp(&w, init_net.ipv4.udp_table, IPPROTO_UDP);
	if (!w.err)
		pnp_listeners_udp(&w, &udplite_table, IPPROTO_UDPLITE);
	pnp_listeners_flush(&w);

	query->count = w.written;
	query->total = w.total;
	kfree(w.batch);
	return w.err;
}
