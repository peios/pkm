/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KMES static tracepoints — event-substrate machinery health.
 *
 * Staged by stage-sources.sh into include/trace/events/kmes.h. These trace the
 * HEALTH of the KMES machinery (ring drops, capacity swaps, rate throttling,
 * wakeups, ring lifecycle, ingress rejects, msgpack validation rejects, the
 * KACS->KMES emit boundary) — NOT the security-event payload KMES ships to
 * userspace. No event payload bytes are ever recorded; only cpu ids, counters,
 * sizes, positions, pids, reason codes, and ret.
 *
 * CREATE_TRACE_POINTS is defined in security/pkm/kacs/pkm_trace.c.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM kmes

#if !defined(_TRACE_KMES_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KMES_H

#include <linux/tracepoint.h>
#include <linux/types.h>
#include <pkm/trace.h>

/* ---- kmes_drop: ring/machinery event-loss taxonomy ---- */
#define kmes_drop_reason_symbols					\
	{ KMES_DROP_RING_FULL,			"ring-full" },		\
	{ KMES_DROP_TAIL_RESYNC,		"tail-resync" },	\
	{ KMES_DROP_VALIDATE,			"validate" },		\
	{ KMES_DROP_BATCH_STRUCT_INVALID,	"batch-struct-invalid" }

DECLARE_EVENT_CLASS(kmes_drop_class,

	TP_PROTO(u16 cpu_id, u64 dropped_total, u64 event_size, u64 write_pos,
		 u64 tail_pos, u64 capacity, u8 reason),

	TP_ARGS(cpu_id, dropped_total, event_size, write_pos, tail_pos,
		capacity, reason),

	TP_STRUCT__entry(
		__field(	u64,	dropped_total	)
		__field(	u64,	event_size	)
		__field(	u64,	write_pos	)
		__field(	u64,	tail_pos	)
		__field(	u64,	capacity	)
		__field(	u16,	cpu_id		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->dropped_total = dropped_total;
		__entry->event_size = event_size;
		__entry->write_pos = write_pos;
		__entry->tail_pos = tail_pos;
		__entry->capacity = capacity;
		__entry->cpu_id = cpu_id;
		__entry->reason = reason;
	),

	TP_printk("reason=%s cpu=%u dropped_total=%llu event_size=%llu write_pos=%llu tail_pos=%llu capacity=%llu",
		__print_symbolic(__entry->reason, kmes_drop_reason_symbols),
		__entry->cpu_id, __entry->dropped_total, __entry->event_size,
		__entry->write_pos, __entry->tail_pos, __entry->capacity)
);

DEFINE_EVENT(kmes_drop_class, kmes_drop,
	TP_PROTO(u16 cpu_id, u64 dropped_total, u64 event_size, u64 write_pos,
		 u64 tail_pos, u64 capacity, u8 reason),
	TP_ARGS(cpu_id, dropped_total, event_size, write_pos, tail_pos,
		capacity, reason));

/* ---- kmes_swap: bounded ring capacity swap lifecycle ---- */
#define kmes_swap_reason_symbols					\
	{ KMES_SWAP_BEGIN,		"begin" },			\
	{ KMES_SWAP_COMPLETE,		"complete" },			\
	{ KMES_SWAP_MIGRATE_SKIP,	"migrate-skip" },		\
	{ KMES_SWAP_FAILED,		"failed" }

DECLARE_EVENT_CLASS(kmes_swap_class,

	TP_PROTO(u16 cpu_id, u64 old_capacity, u64 new_capacity, long ret,
		 u8 reason),

	TP_ARGS(cpu_id, old_capacity, new_capacity, ret, reason),

	TP_STRUCT__entry(
		__field(	u64,	old_capacity	)
		__field(	u64,	new_capacity	)
		__field(	long,	ret		)
		__field(	u16,	cpu_id		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->old_capacity = old_capacity;
		__entry->new_capacity = new_capacity;
		__entry->ret = ret;
		__entry->cpu_id = cpu_id;
		__entry->reason = reason;
	),

	TP_printk("reason=%s cpu=%u old_capacity=%llu new_capacity=%llu ret=%ld",
		__print_symbolic(__entry->reason, kmes_swap_reason_symbols),
		__entry->cpu_id, __entry->old_capacity, __entry->new_capacity,
		__entry->ret)
);

DEFINE_EVENT(kmes_swap_class, kmes_swap,
	TP_PROTO(u16 cpu_id, u64 old_capacity, u64 new_capacity, long ret,
		 u8 reason),
	TP_ARGS(cpu_id, old_capacity, new_capacity, ret, reason));

/* ---- kmes_rate: per-process token-bucket backpressure ---- */
#define kmes_rate_reason_symbols					\
	{ KMES_RATE_THROTTLE,		"throttle" },			\
	{ KMES_RATE_RECONFIGURE,	"reconfigure" }

DECLARE_EVENT_CLASS(kmes_rate_class,

	TP_PROTO(u32 pid, u32 requested, u32 tokens_avail, u32 rate, long ret,
		 u8 reason),

	TP_ARGS(pid, requested, tokens_avail, rate, ret, reason),

	TP_STRUCT__entry(
		__field(	long,	ret		)
		__field(	u32,	pid		)
		__field(	u32,	requested	)
		__field(	u32,	tokens_avail	)
		__field(	u32,	rate		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->pid = pid;
		__entry->requested = requested;
		__entry->tokens_avail = tokens_avail;
		__entry->rate = rate;
		__entry->reason = reason;
	),

	TP_printk("reason=%s pid=%u requested=%u tokens_avail=%u rate=%u ret=%ld",
		__print_symbolic(__entry->reason, kmes_rate_reason_symbols),
		__entry->pid, __entry->requested, __entry->tokens_avail,
		__entry->rate, __entry->ret)
);

DEFINE_EVENT(kmes_rate_class, kmes_rate,
	TP_PROTO(u32 pid, u32 requested, u32 tokens_avail, u32 rate, long ret,
		 u8 reason),
	TP_ARGS(pid, requested, tokens_avail, rate, ret, reason));

/* ---- kmes_wake: consumer wakeup machinery ---- */
#define kmes_wake_reason_symbols					\
	{ KMES_WAKE_NOTE,	"note" },				\
	{ KMES_WAKE_FUTEX,	"futex" }

DECLARE_EVENT_CLASS(kmes_wake_class,

	TP_PROTO(u16 cpu_id, u32 futex_counter, u64 write_pos, u64 tail_pos,
		 u8 reason),

	TP_ARGS(cpu_id, futex_counter, write_pos, tail_pos, reason),

	TP_STRUCT__entry(
		__field(	u64,	write_pos	)
		__field(	u64,	tail_pos	)
		__field(	u32,	futex_counter	)
		__field(	u16,	cpu_id		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->write_pos = write_pos;
		__entry->tail_pos = tail_pos;
		__entry->futex_counter = futex_counter;
		__entry->cpu_id = cpu_id;
		__entry->reason = reason;
	),

	TP_printk("reason=%s cpu=%u futex_counter=%u write_pos=%llu tail_pos=%llu",
		__print_symbolic(__entry->reason, kmes_wake_reason_symbols),
		__entry->cpu_id, __entry->futex_counter, __entry->write_pos,
		__entry->tail_pos)
);

DEFINE_EVENT(kmes_wake_class, kmes_wake,
	TP_PROTO(u16 cpu_id, u32 futex_counter, u64 write_pos, u64 tail_pos,
		 u8 reason),
	TP_ARGS(cpu_id, futex_counter, write_pos, tail_pos, reason));

/* ---- kmes_ring_lifecycle: generation-stable ring objects ---- */
#define kmes_ring_lifecycle_reason_symbols				\
	{ KMES_RING_ALLOC,		"alloc" },			\
	{ KMES_RING_FREE,		"free" },			\
	{ KMES_RING_PRODUCER_PAGE,	"producer-page" },		\
	{ KMES_RING_CONSUMER_FD,	"consumer-fd" }

DECLARE_EVENT_CLASS(kmes_ring_lifecycle_class,

	TP_PROTO(u16 cpu_id, u64 generation, u64 capacity, long ret, u8 reason),

	TP_ARGS(cpu_id, generation, capacity, ret, reason),

	TP_STRUCT__entry(
		__field(	u64,	generation	)
		__field(	u64,	capacity	)
		__field(	long,	ret		)
		__field(	u16,	cpu_id		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->generation = generation;
		__entry->capacity = capacity;
		__entry->ret = ret;
		__entry->cpu_id = cpu_id;
		__entry->reason = reason;
	),

	TP_printk("reason=%s cpu=%u generation=%llu capacity=%llu ret=%ld",
		__print_symbolic(__entry->reason,
				 kmes_ring_lifecycle_reason_symbols),
		__entry->cpu_id, __entry->generation, __entry->capacity,
		__entry->ret)
);

DEFINE_EVENT(kmes_ring_lifecycle_class, kmes_ring_lifecycle,
	TP_PROTO(u16 cpu_id, u64 generation, u64 capacity, long ret, u8 reason),
	TP_ARGS(cpu_id, generation, capacity, ret, reason));

/* ---- kmes_ingress_reject: emit rejected before the ring ---- */
#define kmes_ingress_reject_reason_symbols				\
	{ KMES_INGRESS_OVER_MAX,	"over-max" },			\
	{ KMES_INGRESS_OVER_CAP_HALF,	"over-cap-half" },		\
	{ KMES_INGRESS_SIZE_OVERFLOW,	"size-overflow" },		\
	{ KMES_INGRESS_EMIT_OVERSIZE,	"emit-oversize" },		\
	{ KMES_INGRESS_BATCH_PARTIAL,	"batch-partial" }

DECLARE_EVENT_CLASS(kmes_ingress_reject_class,

	TP_PROTO(u32 pid, u64 event_size, u32 max_event_size, u64 capacity,
		 u8 reason, long ret),

	TP_ARGS(pid, event_size, max_event_size, capacity, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	event_size	)
		__field(	u64,	capacity	)
		__field(	long,	ret		)
		__field(	u32,	pid		)
		__field(	u32,	max_event_size	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->event_size = event_size;
		__entry->capacity = capacity;
		__entry->ret = ret;
		__entry->pid = pid;
		__entry->max_event_size = max_event_size;
		__entry->reason = reason;
	),

	TP_printk("reason=%s pid=%u event_size=%llu max_event_size=%u capacity=%llu ret=%ld",
		__print_symbolic(__entry->reason,
				 kmes_ingress_reject_reason_symbols),
		__entry->pid, __entry->event_size, __entry->max_event_size,
		__entry->capacity, __entry->ret)
);

DEFINE_EVENT(kmes_ingress_reject_class, kmes_ingress_reject,
	TP_PROTO(u32 pid, u64 event_size, u32 max_event_size, u64 capacity,
		 u8 reason, long ret),
	TP_ARGS(pid, event_size, max_event_size, capacity, reason, ret));

/* ---- kmes_validate: Rust staged-event validator, C boundary ---- */
#define kmes_validate_reason_symbols					\
	{ KMES_VAL_EINVAL,	"einval" }

DECLARE_EVENT_CLASS(kmes_validate_class,

	TP_PROTO(u16 event_type_len, u32 payload_len, u8 reason, long ret),

	TP_ARGS(event_type_len, payload_len, reason, ret),

	TP_STRUCT__entry(
		__field(	long,	ret		)
		__field(	u32,	payload_len	)
		__field(	u16,	event_type_len	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->payload_len = payload_len;
		__entry->event_type_len = event_type_len;
		__entry->reason = reason;
	),

	TP_printk("reason=%s event_type_len=%u payload_len=%u ret=%ld",
		__print_symbolic(__entry->reason, kmes_validate_reason_symbols),
		__entry->event_type_len, __entry->payload_len, __entry->ret)
);

DEFINE_EVENT(kmes_validate_class, kmes_validate,
	TP_PROTO(u16 event_type_len, u32 payload_len, u8 reason, long ret),
	TP_ARGS(event_type_len, payload_len, reason, ret));

/* ---- kmes_kacs_emit: KACS -> KMES emit boundary (lengths only) ----
 * `type_len` is the event-type length visible at the C boundary; `origin` is
 * the KMES origin class. No payload bytes.
 */
DECLARE_EVENT_CLASS(kmes_kacs_emit_class,

	TP_PROTO(u8 origin, u32 type_len, u32 payload_len, long ret),

	TP_ARGS(origin, type_len, payload_len, ret),

	TP_STRUCT__entry(
		__field(	long,	ret		)
		__field(	u32,	type_len	)
		__field(	u32,	payload_len	)
		__field(	u8,	origin		)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->type_len = type_len;
		__entry->payload_len = payload_len;
		__entry->origin = origin;
	),

	TP_printk("origin=%u type_len=%u payload_len=%u ret=%ld",
		__entry->origin, __entry->type_len, __entry->payload_len,
		__entry->ret)
);

DEFINE_EVENT(kmes_kacs_emit_class, kmes_kacs_emit,
	TP_PROTO(u8 origin, u32 type_len, u32 payload_len, long ret),
	TP_ARGS(origin, type_len, payload_len, ret));

#endif /* _TRACE_KMES_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
