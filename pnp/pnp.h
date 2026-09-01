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

/* The verdicts, in strictness order. Mirrors pnp_runtime.rs. */
enum peios_pnp_verdict {
	PEIOS_PNP_VERDICT_PASS = 0,
	PEIOS_PNP_VERDICT_REJECT = 1,
	PEIOS_PNP_VERDICT_DROP = 2,
};

/* The rules layers, as the bridge numbers them. */
enum peios_pnp_layer {
	PEIOS_PNP_LAYER_PACKET = 0,
	PEIOS_PNP_LAYER_RAWPACKET = 1,
};

/*
 * One evaluation's result, filled by the Rust bridge. Mirrors
 * `PnpOutcomeC` in kacs/pnp_runtime.rs field for field.
 */
struct peios_pnp_outcome {
	u8 verdict;			/* enum peios_pnp_verdict */
	u8 backstop;			/* 1 when the backstop answered */
	u32 n_tags;			/* effects yielded (counted, not yet */
	u32 n_counts;			/* applied: their stores are unwired */
	u32 n_reports;			/* machinery — those facts read as */
	u32 n_prompts;			/* absent, coherently) */
	char attributed[96];		/* winning rule's path, truncated */
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
	atomic64_t judged;		/* evaluations against a live forest */
	atomic64_t permissive;		/* layer had no forest (gen 0 path) */
	atomic64_t fail_closed;		/* evaluation failed; packet dropped */
	atomic64_t verdict_pass;
	atomic64_t verdict_drop;
	atomic64_t verdict_reject;
	atomic64_t reject_degraded;	/* REJECT at a seat that can't emit */
	atomic64_t fx_tags;		/* effects yielded but not yet applied */
	atomic64_t fx_counts;
	atomic64_t fx_reports;
	atomic64_t fx_prompts;
};

extern struct peios_pnp_stats peios_pnp_stats;

/*
 * Policy publication (policy.c). Both pointers are opaque Rust forests
 * from pnp_rust_builder_build (either may be NULL = that layer has no
 * policy and is permissive). Publication is atomic: readers see the old
 * generation or the new one, never a mix; the generation counter
 * advances; old forests are freed after grace.
 */
int peios_pnp_policy_publish(void *packet_forest, void *raw_forest);

/*
 * Evaluates one snapshot against one layer's active forest.
 * 0 = outcome filled; -ENOENT = no forest for the layer (permissive);
 * -ENOMEM = evaluation failed mid-flight (caller fails closed).
 */
int peios_pnp_policy_eval(u8 layer, const struct peios_pnp_snapshot *snap,
			  struct peios_pnp_outcome *out);

/* True when any layer has a published forest. */
bool peios_pnp_policy_enforcing(void);

/* Records the outcome of a registry re-walk for status honesty. */
void peios_pnp_policy_note_ingest(long err);

/* The verdict event stream (events.c; ABI in <pkm/pnp.h>). */
struct peios_pnp_status;
int peios_pnp_events_init(void);
void peios_pnp_event_emit(const struct peios_pnp_snapshot *snap,
			  const struct peios_pnp_outcome *out, u8 layer,
			  u8 flags);
u64 peios_pnp_events_dropped(void);
void peios_pnp_status_fill(struct peios_pnp_status *status);

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
u64 pnp_rust_generation_advance(void);
size_t pnp_rust_kunit_probe(void);
void *pnp_rust_builder_new(void);
void pnp_rust_builder_free(void *builder);
int pnp_rust_builder_rule_begin(void *builder, const char *name,
				size_t name_len);
int pnp_rust_builder_rule_end(void *builder);
int pnp_rust_builder_value_int(void *builder, const char *key, size_t key_len,
			       s64 value);
int pnp_rust_builder_value_str(void *builder, const char *key, size_t key_len,
			       const char *value, size_t value_len);
int pnp_rust_builder_value_list_begin(void *builder, const char *key,
				      size_t key_len);
int pnp_rust_builder_list_str(void *builder, const char *value,
			      size_t value_len);
int pnp_rust_builder_list_int(void *builder, s64 value);
int pnp_rust_builder_value_list_end(void *builder);
int pnp_rust_builder_build(void *builder, u8 layer, void **forest_out);
void pnp_rust_forest_free(void *forest);
int pnp_rust_evaluate(const void *forest,
		      const struct peios_pnp_snapshot *snap,
		      struct peios_pnp_outcome *out);

#endif /* _NET_PNP_PNP_H */
