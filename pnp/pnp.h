/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PNP — Peios Network Policy: packet engine internals.
 *
 * The seat snapshot is the C-side mirror of pnp-core's fact vocabulary
 * (crates/pnp-core/src/snapshot.rs): every fact a rule may mention, plus
 * validity bits implementing the absent-fact law (a fact whose bit is clear
 * does not exist for this traversal; conditions over it are false).
 *
 * The machinery stores (tags.c, counters.c, report.c) sit behind small C
 * entry points the Rust bridge calls during evaluation: reads before the
 * walk (resolving the forest's tag names and counter views against this
 * packet), writes after collation (so a COUNT lands after this packet's own
 * reads — temporal feedback — and a REPORT can carry the verdict).
 *
 * Not UAPI: the userspace-visible shapes live in <pkm/pnp.h>.
 */
#ifndef _NET_PNP_PNP_H
#define _NET_PNP_PNP_H

#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include <pkm/pnp.h>		/* the ABI: key-spec bits, window cap, records */

struct net_device;
struct nf_hook_state;
struct nf_conn;

/* Which standing seat judged the traversal (ratified seat geometry). */
enum peios_pnp_seat {
	PEIOS_PNP_SEAT_INGRESS = 1,	/* device RX: RawPacket + fallback */
	PEIOS_PNP_SEAT_EGRESS,		/* device TX: RawPacket + outbound */
	PEIOS_PNP_SEAT_LOCAL_IN,	/* IP hook: inbound proper seat + Flow */
	PEIOS_PNP_SEAT_LOCAL_OUT,	/* IP hook: outbound Flow seat */
};

static inline bool peios_pnp_seat_is_ip(u8 seat)
{
	return seat == PEIOS_PNP_SEAT_LOCAL_IN || seat == PEIOS_PNP_SEAT_LOCAL_OUT;
}

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
#define PEIOS_PNP_HAS_SRC_MAC		BIT(10)	/* src only (our own device's, outbound) */
#define PEIOS_PNP_HAS_START		BIT(11)	/* the flow's start time */

/*
 * One traversal's facts at its standing seat. Fixed-size, stack-allocated
 * in the hook path; no pointers into the skb survive the call except
 * `flow`, the conntrack entry the skb holds a reference to (NULL when
 * untracked or before conntrack), which the tag store scopes writes to.
 * Mirrors `PnpSnapshotC` in kacs/pnp_runtime.rs field for field.
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
	s64 t_secs;			/* the same clock as epoch seconds */
	/* The flow's start time (Flow layer: the Start.* facts). */
	s64 s_year;
	u8 s_month, s_day_of_month, s_day_of_week;
	u8 s_hour, s_minute, s_second;
	u8 flow_related;		/* ct->master != NULL; valid iff flow */
	u8 flow_reply;			/* packet is in the flow's reply direction */
	u8 loopback;			/* the traversal is on the loopback route */
	const void *flow;		/* struct nf_conn *, or NULL */
};

/* The verdicts, in strictness order. Mirrors pnp_runtime.rs. */
enum peios_pnp_verdict {
	PEIOS_PNP_VERDICT_PASS = 0,
	PEIOS_PNP_VERDICT_REJECT = 1,
	PEIOS_PNP_VERDICT_DROP = 2,
};

/* The story a REJECT tells (ratified: Refused, Prohibited). */
enum peios_pnp_reject_kind {
	PEIOS_PNP_REJECT_REFUSED = 0,	/* TCP RST / ICMP port-unreachable */
	PEIOS_PNP_REJECT_PROHIBITED = 1,	/* ICMP admin-prohibited */
};

/* The rules layers, as the bridge numbers them. */
enum peios_pnp_layer {
	PEIOS_PNP_LAYER_PACKET = 0,
	PEIOS_PNP_LAYER_RAWPACKET = 1,
	PEIOS_PNP_LAYER_FLOW = 2,
	PEIOS_PNP_LAYER_COUNT = 3,
};

/*
 * One evaluation's result, filled by the Rust bridge. Mirrors
 * `PnpOutcomeC` in kacs/pnp_runtime.rs field for field. The effect counts
 * are effects yielded; the stores confess what they refused separately.
 */
struct peios_pnp_outcome {
	u8 verdict;			/* enum peios_pnp_verdict */
	u8 backstop;			/* 1 when the backstop answered */
	u8 reject_kind;			/* enum peios_pnp_reject_kind */
	u8 _pad;
	u32 n_tags;
	u32 n_counts;
	u32 n_reports;
	u32 n_prompts;
	char attributed[96];		/* winning rule's path, truncated */
	/* Epoch seconds when a consulted live-time condition next flips;
	 * 0 = never. The Flow layer's sentence expiry.
	 */
	s64 expires_at;
};

/*
 * A counter view the forest materializes: one (stream, key-spec, window)
 * the store must be able to answer. Exported by the bridge at publication
 * (mirrors `PnpViewC`).
 */
#define PEIOS_PNP_VIEW_NAME_LEN		64

struct peios_pnp_view {
	char name[PEIOS_PNP_VIEW_NAME_LEN];
	u64 hash;
	u32 window_secs;		/* 0 = the cumulative total */
	u8 keyspec;			/* PEIOS_PNP_KEY_* bits */
	u8 _pad[3];
};

/* Key-spec bits: PEIOS_PNP_KEY_* from <pkm/pnp.h> (mirror pnp-core's
 * condition::keyspec).
 */

/* Tag ops on the wire from the bridge (mirror TagOp::code). */
#define PEIOS_PNP_TAG_SET		0
#define PEIOS_PNP_TAG_CLEAR		1
#define PEIOS_PNP_TAG_ADD		2

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
	atomic64_t fx_tags;		/* effects yielded by evaluations */
	atomic64_t fx_counts;
	atomic64_t fx_reports;
	atomic64_t fx_prompts;
	/* The stores' confessions (machinery slice). */
	atomic64_t tag_writes;		/* tag ops applied to a flow */
	atomic64_t tag_untracked;	/* TAG on a packet with no flow: no-op */
	atomic64_t tag_refused;		/* table full / atomic alloc failed */
	atomic64_t count_writes;	/* stream emissions applied */
	atomic64_t count_key_absent;	/* packet lacked a view's key fact */
	atomic64_t count_refused;	/* table at its key cap / alloc failed */
	atomic64_t reports_emitted;	/* KMES network-report events */
	/* The Flow layer (rung 2). */
	atomic64_t seen_local_out;	/* traversals at the outbound IP seat */
	atomic64_t flow_judged;		/* Flow evaluations (sentences written) */
	atomic64_t flow_cached;		/* packets that read a current sentence */
	atomic64_t flow_rejudged;	/* stale by generation: re-judged */
	atomic64_t flow_expired;	/* stale by time edge: re-judged */
	atomic64_t flow_uncached;	/* no extension to hold a sentence */
	atomic64_t refusals_emitted;	/* REJECT answers built and sent */
	atomic64_t refusals_bypassed;	/* own refusals waved through a seat */
	atomic64_t teardowns_emitted;	/* far-end resets of established TCP */
};

extern struct peios_pnp_stats peios_pnp_stats;

/*
 * Policy publication (policy.c). The pointers are opaque Rust forests
 * from pnp_rust_builder_build (any may be NULL = that layer has no
 * policy and is permissive). Publication is atomic: readers see the old
 * generation or the new one, never a mix; the generation counter
 * advances; old forests are freed after grace. The counter store is
 * re-materialized for the new forests' views before the swap.
 */
int peios_pnp_policy_publish(void *packet_forest, void *raw_forest,
			     void *flow_forest, u8 reporting_level);

/*
 * Evaluates one snapshot against one layer's active forest.
 * 0 = outcome filled; -ENOENT = no forest for the layer (permissive);
 * -ENOMEM = evaluation failed mid-flight (caller fails closed).
 */
int peios_pnp_policy_eval(u8 layer, const struct peios_pnp_snapshot *snap,
			  struct peios_pnp_outcome *out);

/* True when any layer has a published forest. */
bool peios_pnp_policy_enforcing(void);

/* The active generation's CurrentReportingLevel (1 when absent). */
u8 peios_pnp_policy_reporting_level(void);

/* Records the outcome of a registry re-walk for status honesty. */
void peios_pnp_policy_note_ingest(long err);

/* The verdict event stream (events.c; ABI in <pkm/pnp.h>). */
struct peios_pnp_status;
struct peios_pnp_counters_query;
struct peios_pnp_flows_query;
int peios_pnp_events_init(void);
void peios_pnp_event_emit(const struct peios_pnp_snapshot *snap,
			  const struct peios_pnp_outcome *out, u8 layer,
			  u8 flags);
u64 peios_pnp_events_dropped(void);
void peios_pnp_status_fill(struct peios_pnp_status *status);

/*
 * The flow tag store (tags.c): a pointer-sized conntrack extension on
 * every flow, NULL until the first TAG, then a growable RCU table of
 * (name hash, value) pairs. Reads are lock-free; writes serialize on the
 * flow's lock. Untracked packets have no flow: TAG no-ops, confessed.
 */
void peios_pnp_ct_ext_add(struct nf_conn *ct);
void peios_pnp_ct_destroy(struct nf_conn *ct);
int peios_pnp_tag_lookup(const void *flow, u64 hash, u64 *value_out);
void peios_pnp_tag_apply(const void *flow, u64 hash, u8 op, u64 operand);
/* Copies up to `max` present tags out (for the flows dump); returns how
 * many the flow carries in total.
 */
u32 peios_pnp_tags_snapshot(const struct nf_conn *ct, u64 *hashes,
			    u64 *values, u32 max);
/* Distinct tags one flow may carry: a tripwire, not a budget. */
#define PEIOS_PNP_TAG_MAX_PER_FLOW	64

/*
 * The Flow layer's runtime (flow.c): one judgment per local endpoint of a
 * flow, cached on the extension as a sentence (verdict, generation,
 * expiry); every later packet of the flow reads the sentence instead of
 * evaluating. Called from the IP seats after the Packet layer passed a
 * tracked packet.
 */
unsigned int peios_pnp_flow_dispatch(struct sk_buff *skb,
				     const struct nf_hook_state *state,
				     const struct peios_pnp_snapshot *snap);
long peios_pnp_flows_dump(struct peios_pnp_flows_query *query);
/* FNV-1a-64, the same identity pnp-core's name_hash computes. */
u64 peios_pnp_path_hash(const char *s, size_t len);

/*
 * Refusals (refuse.c): the answer a REJECT sends. Built from the kernel's
 * own reject builders, marked as PNP's (the skb refusal bit: no seat
 * judges it), and delivered — to the wire from the ingress seat, to
 * ourselves through the output path from every other seat. Returns
 * whether an answer was sent; the caller drops either way and counts a
 * degradation when it was not.
 */
struct sk_buff *peios_pnp_refuse_build(struct sk_buff *skb,
				       const struct nf_hook_state *state,
				       const struct peios_pnp_snapshot *snap,
				       u8 kind);
/* The refused packet of an established TCP flow, turned into a reset
 * bound the same way (NULL when there is no far end to tear down).
 */
struct sk_buff *peios_pnp_teardown_build(const struct sk_buff *skb,
					 const struct nf_hook_state *state,
					 const struct peios_pnp_snapshot *snap);
bool peios_pnp_refuse(struct sk_buff *skb, const struct nf_hook_state *state,
		      const struct peios_pnp_snapshot *snap, u8 kind);

/*
 * The counter store (counters.c): machine-scoped streams, materialized as
 * one keyed table per (stream, key-spec) the forests view, each table
 * answering every window referenced. The store outlives generations.
 */
int peios_pnp_counters_publish(const struct peios_pnp_view *views,
			       u32 count);
int peios_pnp_counter_read(const struct peios_pnp_snapshot *snap, u64 hash,
			   u8 keyspec, u32 window_secs, u64 *value_out);
void peios_pnp_counter_add(const struct peios_pnp_snapshot *snap, u64 hash,
			   u64 amount);
long peios_pnp_counters_dump(struct peios_pnp_counters_query *query);
u64 peios_pnp_counters_cells(void);
/* Keys per table: the keyspace is wire-driven, so the cap is hard. */
#define PEIOS_PNP_COUNTER_MAX_KEYS	4096
/* Distinct windows one table answers: PEIOS_PNP_COUNTER_MAX_WINDOWS
 * (<pkm/pnp.h>).
 */

/*
 * REPORT emission (report.c): one KMES `network-report` event, origin
 * class PNP, msgpack payload built on the stack (softirq-safe).
 */
void peios_pnp_report_emit(const struct peios_pnp_snapshot *snap,
			   const char *rule, size_t rule_len, u8 level,
			   u8 layer, u8 verdict, u8 reject_kind);

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
unsigned int peios_pnp_hook_local_out(void *priv, struct sk_buff *skb,
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
/* Cross-forest checks for forests published together (-EINVAL refuses). */
int pnp_rust_forests_check(const void *packet_forest, const void *raw_forest,
			   const void *flow_forest);
/* The views a forest materializes. */
u32 pnp_rust_forest_view_count(const void *forest);
int pnp_rust_forest_view(const void *forest, u32 index,
			 struct peios_pnp_view *out);
int pnp_rust_evaluate(const void *forest,
		      const struct peios_pnp_snapshot *snap, u8 layer,
		      u8 reporting_level, struct peios_pnp_outcome *out);

#endif /* _NET_PNP_PNP_H */
