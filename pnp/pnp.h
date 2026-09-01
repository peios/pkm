/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PNP — Peios Network Policy: packet engine internals.
 *
 * The seat snapshot is the C-side mirror of pnp-core's fact vocabulary
 * (crates/pnp-core/src/snapshot.rs): every fact a rule may mention, plus
 * validity bits implementing the absent-fact law (a fact whose bit is clear
 * does not exist for this traversal; conditions over it are false).
 *
 * Not UAPI: the userspace-visible shapes are minted when the verdict
 * stream and authoring surfaces land.
 */
#ifndef _NET_PNP_PNP_H
#define _NET_PNP_PNP_H

#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/types.h>

struct net_device;
struct nf_hook_state;

/* Which standing seat judged the traversal (ratified seat geometry). */
enum peios_pnp_seat {
	PEIOS_PNP_SEAT_INGRESS = 1,	/* device RX: RawPacket + fallback */
	PEIOS_PNP_SEAT_EGRESS,		/* device TX: RawPacket + outbound */
	PEIOS_PNP_SEAT_LOCAL_IN,	/* IP hook: inbound proper seat */
};

enum peios_pnp_direction {
	PEIOS_PNP_DIR_IN = 0,
	PEIOS_PNP_DIR_OUT = 1,
};

/*
 * Conntrack's flow classification as a snapshot fact. ABSENT means the
 * seat stands before conntrack (the device ingress seat); UNTRACKED means
 * conntrack ran and does not track this packet.
 */
enum peios_pnp_flow_state {
	PEIOS_PNP_FLOW_ABSENT = 0,
	PEIOS_PNP_FLOW_NEW,
	PEIOS_PNP_FLOW_ESTABLISHED,
	PEIOS_PNP_FLOW_RELATED,
	PEIOS_PNP_FLOW_INVALID,
	PEIOS_PNP_FLOW_UNTRACKED,
};

/* Validity bits for facts whose zero values are meaningful. */
#define PEIOS_PNP_HAS_ETHER_TYPE	BIT(0)
#define PEIOS_PNP_HAS_MACS		BIT(1)
#define PEIOS_PNP_HAS_VLAN		BIT(2)
#define PEIOS_PNP_HAS_TTL		BIT(3)
#define PEIOS_PNP_HAS_DSCP		BIT(4)
#define PEIOS_PNP_HAS_FRAGMENT		BIT(5)
#define PEIOS_PNP_HAS_PORTS		BIT(6)
#define PEIOS_PNP_HAS_TCP_FLAGS	BIT(7)
#define PEIOS_PNP_HAS_ICMP		BIT(8)
#define PEIOS_PNP_HAS_TIME		BIT(9)

/*
 * One traversal's facts at its standing seat. Fixed-size, stack-allocated
 * in the hook path; no pointers into the skb survive the call.
 */
struct peios_pnp_snapshot {
	u8 seat;			/* enum peios_pnp_seat */
	u8 direction;			/* enum peios_pnp_direction */
	u8 addr_family;			/* 0 = no L3 facts, else 4 or 6 */
	u8 flow_state;			/* enum peios_pnp_flow_state */
	u32 has;			/* PEIOS_PNP_HAS_* validity bits */
	int ifindex;
	char ifname[IFNAMSIZ];
	u16 ether_type;			/* host order */
	u16 vlan;
	u8 src_mac[6];
	u8 dst_mac[6];
	u8 src_addr[16];		/* v4 in first 4 bytes */
	u8 dst_addr[16];
	u8 protocol;			/* valid iff addr_family != 0 */
	u8 ttl;
	u8 dscp;
	u8 fragment;
	u8 tcp_flags;
	u8 icmp_type;
	u8 icmp_code;
	u16 src_port;			/* host order */
	u16 dst_port;
	u32 length;			/* stack view, not wire view */
	/* Wall clock (UTC; timezone semantics unminted). */
	s64 t_year;
	u8 t_month;			/* 1..12 */
	u8 t_day_of_month;		/* 1..31 */
	u8 t_day_of_week;		/* ISO: 1 = Monday .. 7 = Sunday */
	u8 t_hour, t_minute, t_second;
};

/*
 * Engine counters. Plain atomics (not percpu) while the engine is young:
 * legibility over throughput, revisit with the compiled evaluator.
 */
struct peios_pnp_stats {
	atomic64_t seen_ingress;	/* traversals at the ingress seat */
	atomic64_t seen_egress;		/* traversals at the egress seat */
	atomic64_t seen_local_in;	/* traversals at the IP proper seat */
	atomic64_t deferred;		/* ingress deferrals to the IP seat */
	atomic64_t fallback_judged;	/* ingress fallback judgments */
	atomic64_t parse_errors;	/* snapshot builder refusals */
};

extern struct peios_pnp_stats peios_pnp_stats;

/*
 * The dispatch law (ratified): the Packet layer judges a traversal at its
 * proper seat, falling back to the ingress seat iff the traversal will
 * never reach the proper seat. Decidable at ingress from the ethertype and
 * the device's disposition (bridge-enslaved ports never cross IP hooks).
 */
bool peios_pnp_traversal_reaches_ip_seat(__be16 protocol,
					 const struct net_device *dev);

/*
 * Builds the seat snapshot for one traversal. Returns 0, or -EINVAL when
 * the frame is too mangled to describe (counted; such packets carry only
 * their seat facts).
 */
int peios_pnp_snapshot_from_skb(const struct sk_buff *skb,
				const struct net_device *dev, u8 seat,
				u8 direction,
				struct peios_pnp_snapshot *snap);

/* Hook entry points (seats.c). */
unsigned int peios_pnp_hook_ingress(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state);
unsigned int peios_pnp_hook_egress(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state);
unsigned int peios_pnp_hook_local_in(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state);

/* Rust bridge (security/pkm Rust island; see kacs/pnp_runtime.rs). */
u64 pnp_rust_generation(void);
size_t pnp_rust_kunit_probe(void);

#endif /* _NET_PNP_PNP_H */
