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

#define PEIOS_PNP_ABI_VERSION		1U

/* Which standing seat judged the traversal. */
#define PEIOS_PNP_EV_SEAT_INGRESS	1U
#define PEIOS_PNP_EV_SEAT_EGRESS	2U
#define PEIOS_PNP_EV_SEAT_LOCAL_IN	3U

/* Which rules layer. */
#define PEIOS_PNP_EV_LAYER_PACKET	0U
#define PEIOS_PNP_EV_LAYER_RAWPACKET	1U

/* The verdict, in strictness order. */
#define PEIOS_PNP_EV_VERDICT_PASS	0U
#define PEIOS_PNP_EV_VERDICT_REJECT	1U
#define PEIOS_PNP_EV_VERDICT_DROP	2U

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
	__u16 _pad0;
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
	__u64 _reserved[5];
};

#define PEIOS_PNP_IOC_TYPE		'N'
#define PEIOS_PNP_IOC_STATUS_NR		1U
#define PEIOS_PNP_IOC_STATUS \
	_IOR(PEIOS_PNP_IOC_TYPE, PEIOS_PNP_IOC_STATUS_NR, struct peios_pnp_status)

#endif /* _UAPI_PKM_PNP_H */
