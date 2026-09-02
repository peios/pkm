/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * PNP — Peios Network Policy: the verdict event stream and engine status.
 *
 * The engine (net/pnp) judges every traversal at its standing seats and
 * appends one event per evaluation to a bounded ring. /dev/peios-pnp
 * (mode 0600; one reader at a time) drains it: read() returns whole
 * events only — never a partial record — and blocks when the ring is
 * empty unless O_NONBLOCK; poll() raises POLLIN when events are waiting.
 * A slow reader loses the OLDEST events, and the loss is confessed in
 * peios_pnp_status.events_dropped (the honesty rule: drops are counted,
 * never silent).
 *
 * Events are emitted for real evaluations (a published forest judged the
 * traversal) and for fail-closed drops; permissive traversals (a layer
 * with no forest — all of them at generation 0) emit nothing, because
 * there is no decision to attribute. Status tells that story instead:
 * generation 0 means "not enforcing", loudly.
 *
 * This ABI is EXPERIMENTAL while PNP grows: no stability promise until
 * the design ships (PEI-598). Check `abi` before trusting the rest.
 */
#ifndef _UAPI_PKM_PNP_H
#define _UAPI_PKM_PNP_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PEIOS_PNP_ABI_VERSION		3U

/* Which standing seat judged the traversal. */
#define PEIOS_PNP_EV_SEAT_INGRESS	1U
#define PEIOS_PNP_EV_SEAT_EGRESS	2U
#define PEIOS_PNP_EV_SEAT_LOCAL_IN	3U
#define PEIOS_PNP_EV_SEAT_LOCAL_OUT	4U

/* Which rules layer. */
#define PEIOS_PNP_EV_LAYER_PACKET	0U
#define PEIOS_PNP_EV_LAYER_RAWPACKET	1U
#define PEIOS_PNP_EV_LAYER_FLOW		2U

/* The verdict, in strictness order. */
#define PEIOS_PNP_EV_VERDICT_PASS	0U
#define PEIOS_PNP_EV_VERDICT_REJECT	1U
#define PEIOS_PNP_EV_VERDICT_DROP	2U

/* The story a REJECT told (meaningful iff verdict == REJECT). */
#define PEIOS_PNP_EV_REJECT_REFUSED	0U	/* RST / port-unreachable */
#define PEIOS_PNP_EV_REJECT_PROHIBITED	1U	/* admin-prohibited */

/* Traversal direction. */
#define PEIOS_PNP_EV_DIR_IN		0U
#define PEIOS_PNP_EV_DIR_OUT		1U

/* Flow state as the snapshot carried it (0 = the fact was absent). */
#define PEIOS_PNP_EV_FLOW_ABSENT	0U
#define PEIOS_PNP_EV_FLOW_NEW		1U
#define PEIOS_PNP_EV_FLOW_ESTABLISHED	2U
#define PEIOS_PNP_EV_FLOW_RELATED	3U
#define PEIOS_PNP_EV_FLOW_INVALID	4U
#define PEIOS_PNP_EV_FLOW_UNTRACKED	5U

/* Event flags. */
#define PEIOS_PNP_EV_F_BACKSTOP		0x01U	/* nothing yielded; DROP */
#define PEIOS_PNP_EV_F_FAIL_CLOSED	0x02U	/* evaluation failed; DROP */
#define PEIOS_PNP_EV_F_REJECT_DEGRADED	0x04U	/* REJECT emitted as DROP */
#define PEIOS_PNP_EV_F_REJUDGED		0x08U	/* Flow: a stale sentence re-judged */

#define PEIOS_PNP_EV_ATTR_LEN		96U

/*
 * One evaluation. `attributed` is the winning rule's registry path
 * relative to the layer key (or "backstop"), NUL-terminated, truncated.
 * `effects` packs the yielded side-effect counts, 8 bits each:
 * tags | counts<<8 | reports<<16 | prompts<<24 (saturating).
 * Addresses: first 4 bytes when addr_family == 4, all 16 when 6.
 */
struct peios_pnp_event {
	__u64 seq;		/* monotonic; gaps = confessed drops */
	__u64 t_ns;		/* CLOCK_REALTIME nanoseconds */
	__u8 seat;
	__u8 layer;
	__u8 verdict;
	__u8 flags;
	__u8 direction;
	__u8 addr_family;	/* 0 = no L3 facts */
	__u8 protocol;
	__u8 flow_state;
	__u32 ifindex;
	__u16 src_port;		/* host order; 0 when the fact was absent */
	__u16 dst_port;
	__u16 ether_type;	/* host order */
	__u8 reject_kind;	/* PEIOS_PNP_EV_REJECT_* */
	__u8 _pad0;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u32 length;		/* stack view */
	__u32 effects;
	/* UTF-8, NUL-terminated, truncated. */
	__u8 attributed[PEIOS_PNP_EV_ATTR_LEN];
	__u32 _pad1;		/* explicit tail padding to 8-byte size */
};

/* Engine status: counters are cumulative since boot. */
struct peios_pnp_status {
	__u64 abi;		/* PEIOS_PNP_ABI_VERSION */
	__u64 generation;	/* 0 = nothing ever ingested */
	__u64 enforcing;	/* 1 when any layer has a published forest */
	__u64 events_dropped;	/* ring overwrites (confessed) */
	__u64 seen_ingress;
	__u64 seen_egress;
	__u64 seen_local_in;
	__u64 deferred;
	__u64 fallback_judged;
	__u64 parse_errors;
	__u64 judged;
	__u64 permissive;
	__u64 fail_closed;
	__u64 verdict_pass;
	__u64 verdict_drop;
	__u64 verdict_reject;
	__u64 reject_degraded;
	__u64 fx_tags;
	__u64 fx_counts;
	__u64 fx_reports;
	__u64 fx_prompts;
	/* Last registry ingestion: 0 = never attempted or succeeded;
	 * otherwise the positive errno of the last failed re-walk. The
	 * previous generation stays active across a failure.
	 */
	__u64 last_ingest_error;
	__u64 last_ingest_t_ns;
	/* The machinery stores' confessions (ABI 2). */
	__u64 tag_writes;	/* tag ops applied to a flow */
	__u64 tag_untracked;	/* TAG on a packet with no flow: no-op */
	__u64 tag_refused;	/* per-flow tripwire hit / atomic alloc failed */
	__u64 count_writes;	/* stream emissions applied */
	__u64 count_key_absent;	/* packet lacked a view's key fact: no-op */
	__u64 count_refused;	/* table at its key cap / alloc failed */
	__u64 reports_emitted;	/* KMES network-report events */
	__u64 counter_cells;	/* live counter cells across all tables */
	__u64 reporting_level;	/* the active CurrentReportingLevel */
	/* The Flow layer (ABI 3). */
	__u64 seen_local_out;	/* traversals at the outbound IP seat */
	__u64 flow_judged;	/* Flow-layer evaluations (sentences written) */
	__u64 flow_cached;	/* tracked packets that read a current sentence */
	__u64 flow_rejudged;	/* re-judgments: sentence from an older generation */
	__u64 flow_expired;	/* re-judgments: sentence past its time edge */
	__u64 flow_uncached;	/* evaluations on flows with nowhere to hold a sentence */
	__u64 refusals_emitted;	/* REJECT answers PNP built and sent */
	__u64 refusals_bypassed;	/* PNP's own refusals waved through its seats */
	__u64 _reserved[4];
};

/*
 * One counter cell, as the counters dump reports it: the stream and
 * key-spec of its table, the key it holds (only the facts the key-spec
 * names are meaningful; the rest are zero), the cumulative total, and the
 * value of every window the table answers.
 */
#define PEIOS_PNP_COUNTER_NAME_LEN	64U
#define PEIOS_PNP_COUNTER_MAX_WINDOWS	8U

/* Key-spec bits. */
#define PEIOS_PNP_KEY_SRC_ADDR		0x01U
#define PEIOS_PNP_KEY_DST_ADDR		0x02U
#define PEIOS_PNP_KEY_INTERFACE		0x04U

struct peios_pnp_counter_rec {
	__u8 name[PEIOS_PNP_COUNTER_NAME_LEN];	/* stream, NUL-terminated */
	__u64 hash;
	__u8 keyspec;		/* PEIOS_PNP_KEY_* bits */
	__u8 family;		/* 4 / 6 / 0 */
	__u8 _pad0[2];
	__s32 ifindex;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u64 total;
	__u64 last_secs;	/* CLOCK_REALTIME seconds of the last write */
	__u32 n_windows;
	__u32 _pad1;
	__u32 window_secs[PEIOS_PNP_COUNTER_MAX_WINDOWS];
	__u64 window_value[PEIOS_PNP_COUNTER_MAX_WINDOWS];
};

/*
 * The counters dump: fills `buf` with as many records as fit; `count` is
 * how many were written, `total` how many cells exist (so a short buffer
 * is visible).
 */
struct peios_pnp_counters_query {
	__u64 buf;		/* struct peios_pnp_counter_rec __user * */
	__u32 buf_len;		/* bytes */
	__u32 count;		/* out */
	__u32 total;		/* out */
	__u32 _pad0;
};

/*
 * One live flow, as the flows dump reports it (ABI 3): conntrack's view of
 * the flow (original-direction tuple, state, remaining lifetime,
 * accounting), PNP's extension (start time, the interface and direction
 * at first judgment, the sentences, the tags). Tags are reported by hash;
 * the policy names them.
 */
#define PEIOS_PNP_FLOW_MAX_TAGS		8U
#define PEIOS_PNP_FLOW_SENTENCES	2U

struct peios_pnp_flow_rec {
	__u32 id;		/* conntrack's id for the flow */
	__u8 family;		/* 4 / 6 */
	__u8 protocol;
	__u8 direction;		/* originator's side, PEIOS_PNP_EV_DIR_*; valid iff judged */
	__u8 loopback;		/* both endpoints local: two sentences */
	__u8 seen_reply;	/* conntrack has seen the reply direction */
	__u8 assured;
	__u8 related;		/* expected by another flow */
	__u8 judged;		/* the Flow layer has judged it at least once */
	__s32 ifindex;		/* interface at first judgment */
	__u32 timeout_secs;	/* conntrack's remaining lifetime */
	__u8 src_addr[16];	/* original direction */
	__u8 dst_addr[16];
	__u16 src_port;		/* host order; ICMP: the echo id */
	__u16 dst_port;
	__u8 icmp_type;
	__u8 icmp_code;
	__u8 n_tags;
	__u8 _pad0[5];
	__u64 start_secs;	/* CLOCK_REALTIME seconds the flow was created */
	__u64 packets[2];	/* original, reply */
	__u64 bytes[2];
	/* The sentences, one cached Flow-layer judgment per slot, as parallel
	 * arrays (UAPI records hold scalars only). Slot 0: the flow's
	 * sentence (a loopback flow's outbound endpoint); slot 1: a loopback
	 * flow's inbound endpoint, else empty. A slot with generation 0 is
	 * empty.
	 */
	__u64 sentence_generation[PEIOS_PNP_FLOW_SENTENCES];
	__s64 sentence_expires_at[PEIOS_PNP_FLOW_SENTENCES];	/* 0 = never */
	__u64 sentence_rule_hash[PEIOS_PNP_FLOW_SENTENCES];	/* FNV-1a-64 of the rule path */
	__u8 sentence_verdict[PEIOS_PNP_FLOW_SENTENCES];	/* PEIOS_PNP_EV_VERDICT_* */
	__u8 sentence_reject_kind[PEIOS_PNP_FLOW_SENTENCES];	/* PEIOS_PNP_EV_REJECT_* */
	__u8 _pad1[4];
	/* Up to PEIOS_PNP_FLOW_MAX_TAGS present tags, by name hash. */
	__u64 tag_hash[PEIOS_PNP_FLOW_MAX_TAGS];
	__u64 tag_value[PEIOS_PNP_FLOW_MAX_TAGS];
};

/*
 * The flows dump: fills `buf` with as many records as fit; `count` is how
 * many were written, `total` how many live flows the walk saw. A
 * best-effort snapshot of a table that changes under the walk.
 */
struct peios_pnp_flows_query {
	__u64 buf;		/* struct peios_pnp_flow_rec __user * */
	__u32 buf_len;		/* bytes */
	__u32 count;		/* out */
	__u32 total;		/* out */
	__u32 _pad0;
};

#define PEIOS_PNP_IOC_TYPE		'N'
#define PEIOS_PNP_IOC_STATUS_NR		1U
#define PEIOS_PNP_IOC_STATUS \
	_IOR(PEIOS_PNP_IOC_TYPE, PEIOS_PNP_IOC_STATUS_NR, struct peios_pnp_status)
#define PEIOS_PNP_IOC_COUNTERS_NR	2U
#define PEIOS_PNP_IOC_COUNTERS \
	_IOWR(PEIOS_PNP_IOC_TYPE, PEIOS_PNP_IOC_COUNTERS_NR, \
	      struct peios_pnp_counters_query)
#define PEIOS_PNP_IOC_FLOWS_NR		3U
#define PEIOS_PNP_IOC_FLOWS \
	_IOWR(PEIOS_PNP_IOC_TYPE, PEIOS_PNP_IOC_FLOWS_NR, \
	      struct peios_pnp_flows_query)

#endif /* _UAPI_PKM_PNP_H */
