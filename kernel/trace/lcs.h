/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * LCS static tracepoints — the registry source device.
 *
 * Staged by stage-sources.sh into include/trace/events/lcs.h. Traces the RSI
 * request/response path, transaction state machine, key-fd operations, layers,
 * path walk, routing, registration/bootstrap, access decisions, and audit
 * emission. Never records path/name/SD/key/frame bytes: only source/txn/request
 * ids, op/reason/state enums, counts, lengths, masks, folded guid hashes, and
 * ret. CREATE_TRACE_POINTS is defined in security/pkm/kacs/pkm_trace.c.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM lcs

#if !defined(_TRACE_LCS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LCS_H

#include <linux/tracepoint.h>
#include <linux/types.h>
#include <pkm/trace.h>

/* ==== shared op taxonomy (lcs_rsi_request + lcs_rsi_roundtrip) ==== */
#define lcs_op_symbols							\
	{ LCS_OP_LOOKUP,		"lookup" },			\
	{ LCS_OP_READ_KEY,		"read-key" },			\
	{ LCS_OP_ENUM_CHILDREN,		"enum-children" },		\
	{ LCS_OP_QUERY_VALUES,		"query-values" },		\
	{ LCS_OP_SET_VALUE,		"set-value" },			\
	{ LCS_OP_DELETE_VALUE,		"delete-value" },		\
	{ LCS_OP_BLANKET_TOMBSTONE,	"blanket-tombstone" },		\
	{ LCS_OP_DROP_KEY,		"drop-key" },			\
	{ LCS_OP_CREATE_ENTRY,		"create-entry" },		\
	{ LCS_OP_HIDE_ENTRY,		"hide-entry" },			\
	{ LCS_OP_DELETE_ENTRY,		"delete-entry" },		\
	{ LCS_OP_CREATE_KEY,		"create-key" },			\
	{ LCS_OP_WRITE_KEY,		"write-key" },			\
	{ LCS_OP_TXN_BEGIN,		"txn-begin" },			\
	{ LCS_OP_TXN_COMMIT,		"txn-commit" },			\
	{ LCS_OP_TXN_ABORT,		"txn-abort" },			\
	{ LCS_OP_FLUSH,			"flush" },			\
	{ LCS_OP_DELETE_LAYER,		"delete-layer" }

/*
 * One RSI request admission record. Emitted on successful queue admission and on
 * the admission error rungs; the rung is read from `ret` (0 == enqueued,
 * -EAGAIN == in-flight at limit, -EIO == source gone / fd closing,
 * -EOVERFLOW == request-id exhausted). request_id/queue_depth/in_flight_count
 * are 0 on the error rungs (the enqueue_result is only filled on success). No
 * pathname, key name, GUID or frame bytes are recorded.
 */
DECLARE_EVENT_CLASS(lcs_rsi_request_class,

	TP_PROTO(u32 source_id, u8 op, u64 txn_id, u64 request_id,
		 u32 queue_depth, u32 in_flight_count, long ret),

	TP_ARGS(source_id, op, txn_id, request_id, queue_depth,
		in_flight_count, ret),

	TP_STRUCT__entry(
		__field(	u64,	txn_id		)
		__field(	u64,	request_id	)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	queue_depth	)
		__field(	u32,	in_flight_count	)
		__field(	u8,	op		)
	),

	TP_fast_assign(
		__entry->txn_id = txn_id;
		__entry->request_id = request_id;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->queue_depth = queue_depth;
		__entry->in_flight_count = in_flight_count;
		__entry->op = op;
	),

	TP_printk("op=%s source_id=%u txn_id=%llu request_id=%llu queue_depth=%u in_flight=%u ret=%ld",
		__print_symbolic(__entry->op, lcs_op_symbols),
		__entry->source_id, __entry->txn_id, __entry->request_id,
		__entry->queue_depth, __entry->in_flight_count, __entry->ret)
);

/* RSI request admission (source_request.c) */
DEFINE_EVENT(lcs_rsi_request_class, lcs_rsi_request,
	TP_PROTO(u32 source_id, u8 op, u64 txn_id, u64 request_id,
		 u32 queue_depth, u32 in_flight_count, long ret),
	TP_ARGS(source_id, op, txn_id, request_id, queue_depth,
		in_flight_count, ret));

/*
 * A source RSI round trip. `begin` (source_dispatch.c base round-trip fns)
 * carries the op/txn/timeout of the attempt; `complete` (the shared slot-wait
 * and response-wait sinks) reports the outcome with waited/timed_out flags —
 * op/txn are 0 at those sinks when unknown. The ETIMEDOUT paths (slot-wait,
 * response-wait) are the highest-value sites; filter with `timed_out`.
 */
DECLARE_EVENT_CLASS(lcs_rsi_roundtrip_class,

	TP_PROTO(u32 source_id, u8 op, u64 txn_id, u32 timeout_ms, bool waited,
		 bool timed_out, long ret),

	TP_ARGS(source_id, op, txn_id, timeout_ms, waited, timed_out, ret),

	TP_STRUCT__entry(
		__field(	u64,	txn_id		)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	timeout_ms	)
		__field(	u8,	op		)
		__field(	u8,	waited		)
		__field(	u8,	timed_out	)
	),

	TP_fast_assign(
		__entry->txn_id = txn_id;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->timeout_ms = timeout_ms;
		__entry->op = op;
		__entry->waited = waited;
		__entry->timed_out = timed_out;
	),

	TP_printk("op=%s source_id=%u txn_id=%llu timeout_ms=%u waited=%d timed_out=%d ret=%ld",
		__print_symbolic(__entry->op, lcs_op_symbols),
		__entry->source_id, __entry->txn_id, __entry->timeout_ms,
		__entry->waited, __entry->timed_out, __entry->ret)
);

/* Round-trip attempt begin — op/txn/timeout known (source_dispatch.c) */
DEFINE_EVENT(lcs_rsi_roundtrip_class, lcs_rsi_roundtrip_begin,
	TP_PROTO(u32 source_id, u8 op, u64 txn_id, u32 timeout_ms, bool waited,
		 bool timed_out, long ret),
	TP_ARGS(source_id, op, txn_id, timeout_ms, waited, timed_out, ret));

/* Round-trip leg complete — slot-wait / response-wait sinks (source_device.c,
 * source_response.c) */
DEFINE_EVENT(lcs_rsi_roundtrip_class, lcs_rsi_roundtrip_complete,
	TP_PROTO(u32 source_id, u8 op, u64 txn_id, u32 timeout_ms, bool waited,
		 bool timed_out, long ret),
	TP_ARGS(source_id, op, txn_id, timeout_ms, waited, timed_out, ret));

#define lcs_resp_reason_symbols						\
	{ LCS_RESP_ACCEPTED,		"accepted" },			\
	{ LCS_RESP_DESYNC,		"desync" },			\
	{ LCS_RESP_OP_MISMATCH,		"op-mismatch" },		\
	{ LCS_RESP_UNKNOWN_STATUS,	"unknown-status" },		\
	{ LCS_RESP_MALFORMED_PAYLOAD,	"malformed-payload" },		\
	{ LCS_RESP_LATE_COMMIT_FAIL,	"late-commit-fail" },		\
	{ LCS_RESP_LATE_MUTATION_FAIL,	"late-mutation-fail" },		\
	{ LCS_RESP_LATE_BEGIN_FAIL,	"late-begin-fail" }

/*
 * A source RSI response accept/validate outcome, and the late-response effects
 * that silently take a source DOWN. `request_op` is the raw RSI request op the
 * response answers (numeric); `rsi_status` the source-reported status. No name,
 * GUID or frame bytes.
 */
DECLARE_EVENT_CLASS(lcs_rsi_response_class,

	TP_PROTO(u32 source_id, u64 request_id, u64 txn_id, u16 request_op,
		 u32 rsi_status, u8 reason, long ret),

	TP_ARGS(source_id, request_id, txn_id, request_op, rsi_status, reason,
		ret),

	TP_STRUCT__entry(
		__field(	u64,	request_id	)
		__field(	u64,	txn_id		)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	rsi_status	)
		__field(	u16,	request_op	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->request_id = request_id;
		__entry->txn_id = txn_id;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->rsi_status = rsi_status;
		__entry->request_op = request_op;
		__entry->reason = reason;
	),

	TP_printk("reason=%s source_id=%u request_id=%llu txn_id=%llu request_op=%u rsi_status=%u ret=%ld",
		__print_symbolic(__entry->reason, lcs_resp_reason_symbols),
		__entry->source_id, __entry->request_id, __entry->txn_id,
		__entry->request_op, __entry->rsi_status, __entry->ret)
);

/* RSI response accept/validate + late-effect DOWN (source_protocol.c) */
DEFINE_EVENT(lcs_rsi_response_class, lcs_rsi_response,
	TP_PROTO(u32 source_id, u64 request_id, u64 txn_id, u16 request_op,
		 u32 rsi_status, u8 reason, long ret),
	TP_ARGS(source_id, request_id, txn_id, request_op, rsi_status, reason,
		ret));

#define lcs_src_reason_symbols						\
	{ LCS_SRC_OPEN,			"open" },			\
	{ LCS_SRC_RELEASE,		"release" },			\
	{ LCS_SRC_MALFORMED,		"malformed" },			\
	{ LCS_SRC_EXPLICIT,		"explicit" },			\
	{ LCS_SRC_MARK_BY_ID,		"mark-by-id" }

/*
 * A source-fd lifecycle transition. `source_down_id` is the source id driven
 * DOWN by this call (0 == no transition). No pathname/SD bytes.
 */
DECLARE_EVENT_CLASS(lcs_source_fd_class,

	TP_PROTO(u32 source_id, u32 fd_state, u32 slot_status,
		 u32 source_down_id, u8 reason, long ret),

	TP_ARGS(source_id, fd_state, slot_status, source_down_id, reason, ret),

	TP_STRUCT__entry(
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	fd_state	)
		__field(	u32,	slot_status	)
		__field(	u32,	source_down_id	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->fd_state = fd_state;
		__entry->slot_status = slot_status;
		__entry->source_down_id = source_down_id;
		__entry->reason = reason;
	),

	TP_printk("reason=%s source_id=%u fd_state=%u slot_status=%u source_down_id=%u ret=%ld",
		__print_symbolic(__entry->reason, lcs_src_reason_symbols),
		__entry->source_id, __entry->fd_state, __entry->slot_status,
		__entry->source_down_id, __entry->ret)
);

/* Source fd open / mark-down / release lifecycle (source_device.c) */
DEFINE_EVENT(lcs_source_fd_class, lcs_source_fd,
	TP_PROTO(u32 source_id, u32 fd_state, u32 slot_status,
		 u32 source_down_id, u8 reason, long ret),
	TP_ARGS(source_id, fd_state, slot_status, source_down_id, reason, ret));

#define lcs_if_reason_symbols						\
	{ LCS_IF_INSERT,		"insert" },			\
	{ LCS_IF_DELIVERED,		"delivered" },			\
	{ LCS_IF_RELEASE,		"release" }

/*
 * An in-flight RSI request table transition. `in_flight_count` is the
 * post-transition depth.
 */
DECLARE_EVENT_CLASS(lcs_in_flight_class,

	TP_PROTO(u32 source_id, u64 request_id, u32 in_flight_count, u8 reason,
		 long ret),

	TP_ARGS(source_id, request_id, in_flight_count, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	request_id	)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	in_flight_count	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->request_id = request_id;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->in_flight_count = in_flight_count;
		__entry->reason = reason;
	),

	TP_printk("reason=%s source_id=%u request_id=%llu in_flight=%u ret=%ld",
		__print_symbolic(__entry->reason, lcs_if_reason_symbols),
		__entry->source_id, __entry->request_id,
		__entry->in_flight_count, __entry->ret)
);

/* In-flight request table insert/deliver/release (source_device.c) */
DEFINE_EVENT(lcs_in_flight_class, lcs_in_flight,
	TP_PROTO(u32 source_id, u64 request_id, u32 in_flight_count, u8 reason,
		 long ret),
	TP_ARGS(source_id, request_id, in_flight_count, reason, ret));
/* ==== lcs_layer: dynamic-layer table & metadata operations ====
 * source_id is 0 for table-global ops (publish/remove/snapshot) and the
 * broadcast/orchestrate skip-source (0 == none); it is the acting source for
 * _replay and _metadata_refresh. NEVER records layer-name bytes: only
 * layer_name_len and a caller-supplied jhash of the name. Field overloads by
 * event: _snapshot uses `precedence` = resolved layer count and `enabled` =
 * base-metadata-present; _metadata_refresh uses `precedence` = refreshed child
 * count and `effective_changed` = any child's effective config changed.
 */
DECLARE_EVENT_CLASS(lcs_layer,

	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),

	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret),

	TP_STRUCT__entry(
		__field(	long,	ret			)
		__field(	u32,	source_id		)
		__field(	u32,	layer_name_len		)
		__field(	u32,	layer_hash		)
		__field(	u32,	precedence		)
		__field(	u8,	enabled			)
		__field(	u8,	effective_changed	)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->layer_name_len = layer_name_len;
		__entry->layer_hash = layer_hash;
		__entry->precedence = precedence;
		__entry->enabled = enabled;
		__entry->effective_changed = effective_changed;
	),

	TP_printk("source_id=%u name_len=%u name_hash=0x%x precedence=%u enabled=%u effective_changed=%u ret=%ld",
		__entry->source_id, __entry->layer_name_len, __entry->layer_hash,
		__entry->precedence, __entry->enabled, __entry->effective_changed,
		__entry->ret)
);

/* Layer table publish/upsert (layer_table.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_publish,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* Layer table remove (layer_table.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_remove,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* Whole-table layer snapshot acquire (layer_table.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_snapshot,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* Layer-metadata refresh over a Layers root (layer_metadata.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_metadata_refresh,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* Delete-layer orchestration: txn abort + table remove + broadcast (source_layer_operation.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_delete_orchestrate,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* Per-source delete-layer down-cascade broadcast (source_layer_operation.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_broadcast,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* Replay of a source's pending layer-deletes (source_layer_operation.c) */
DEFINE_EVENT(lcs_layer, lcs_layer_replay,
	TP_PROTO(u32 source_id, u32 layer_name_len, u32 layer_hash,
		 u32 precedence, u8 enabled, u8 effective_changed, long ret),
	TP_ARGS(source_id, layer_name_len, layer_hash, precedence, enabled,
		effective_changed, ret));

/* ==== lcs_path_walk: component walk / materialize / symlink resolve ====
 * COUNTS and hashed GUIDs only — never component-name or SD bytes.
 * root_guid_hash is a jhash of the walk root guid, or 0 when none is in scope
 * (materialization has no source/guid). depth_index is the walked component
 * count on success (0 on failure). The ENOENT/ELOOP/malformed-SD/two-pass-EIO
 * taxonomy is carried entirely by `ret`.
 */
DECLARE_EVENT_CLASS(lcs_path_walk,

	TP_PROTO(u32 source_id, u64 txn_id, u64 root_guid_hash,
		 u32 component_count, u32 depth_index, u32 symlink_depth,
		 long ret),

	TP_ARGS(source_id, txn_id, root_guid_hash, component_count, depth_index,
		symlink_depth, ret),

	TP_STRUCT__entry(
		__field(	u64,	txn_id		)
		__field(	u64,	root_guid_hash	)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	component_count	)
		__field(	u32,	depth_index	)
		__field(	u32,	symlink_depth	)
	),

	TP_fast_assign(
		__entry->txn_id = txn_id;
		__entry->root_guid_hash = root_guid_hash;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->component_count = component_count;
		__entry->depth_index = depth_index;
		__entry->symlink_depth = symlink_depth;
	),

	TP_printk("source_id=%u txn_id=%llu root_guid_hash=0x%llx components=%u depth_index=%u symlink_depth=%u ret=%ld",
		__entry->source_id, __entry->txn_id, __entry->root_guid_hash,
		__entry->component_count, __entry->depth_index,
		__entry->symlink_depth, __entry->ret)
);

/* Absolute component walk (path_walk.c) */
DEFINE_EVENT(lcs_path_walk, lcs_walk_absolute,
	TP_PROTO(u32 source_id, u64 txn_id, u64 root_guid_hash,
		 u32 component_count, u32 depth_index, u32 symlink_depth,
		 long ret),
	TP_ARGS(source_id, txn_id, root_guid_hash, component_count, depth_index,
		symlink_depth, ret));

/* Relative (parent-anchored) component walk (path_walk.c) */
DEFINE_EVENT(lcs_path_walk, lcs_walk_relative,
	TP_PROTO(u32 source_id, u64 txn_id, u64 root_guid_hash,
		 u32 component_count, u32 depth_index, u32 symlink_depth,
		 long ret),
	TP_ARGS(source_id, txn_id, root_guid_hash, component_count, depth_index,
		symlink_depth, ret));

/* Symlink-target follow within a walk (path_walk.c) */
DEFINE_EVENT(lcs_path_walk, lcs_walk_symlink,
	TP_PROTO(u32 source_id, u64 txn_id, u64 root_guid_hash,
		 u32 component_count, u32 depth_index, u32 symlink_depth,
		 long ret),
	TP_ARGS(source_id, txn_id, root_guid_hash, component_count, depth_index,
		symlink_depth, ret));

/* Two-pass path/symlink component materialization (path_materialization.c) */
DEFINE_EVENT(lcs_path_walk, lcs_materialize_path,
	TP_PROTO(u32 source_id, u64 txn_id, u64 root_guid_hash,
		 u32 component_count, u32 depth_index, u32 symlink_depth,
		 long ret),
	TP_ARGS(source_id, txn_id, root_guid_hash, component_count, depth_index,
		symlink_depth, ret));

/* Symlink-target value resolution for a key (source_symlink.c) */
DEFINE_EVENT(lcs_path_walk, lcs_resolve_symlink,
	TP_PROTO(u32 source_id, u64 txn_id, u64 root_guid_hash,
		 u32 component_count, u32 depth_index, u32 symlink_depth,
		 long ret),
	TP_ARGS(source_id, txn_id, root_guid_hash, component_count, depth_index,
		symlink_depth, ret));

/* ==== lcs_route: hive/path/symlink -> source+root resolution ====
 * `op` (LCS_ROUTE_*) discriminates the input kind. slot_count/scope_count are
 * the source-slot and token-scope counts; source_id/root_guid_hash are the
 * resolved target (0 on failure). No name/path/target bytes.
 */
#define lcs_route_op_symbols						\
	{ LCS_ROUTE_HIVE_NAME,		"hive-name" },			\
	{ LCS_ROUTE_ABSOLUTE_PATH,	"absolute-path" },		\
	{ LCS_ROUTE_SYMLINK_TARGET,	"symlink-target" }

DECLARE_EVENT_CLASS(lcs_route,

	TP_PROTO(u8 op, u32 slot_count, u32 scope_count, u32 source_id,
		 u64 root_guid_hash, long ret),

	TP_ARGS(op, slot_count, scope_count, source_id, root_guid_hash, ret),

	TP_STRUCT__entry(
		__field(	u64,	root_guid_hash	)
		__field(	long,	ret		)
		__field(	u32,	slot_count	)
		__field(	u32,	scope_count	)
		__field(	u32,	source_id	)
		__field(	u8,	op		)
	),

	TP_fast_assign(
		__entry->root_guid_hash = root_guid_hash;
		__entry->ret = ret;
		__entry->slot_count = slot_count;
		__entry->scope_count = scope_count;
		__entry->source_id = source_id;
		__entry->op = op;
	),

	TP_printk("op=%s slots=%u scopes=%u source_id=%u root_guid_hash=0x%llx ret=%ld",
		__print_symbolic(__entry->op, lcs_route_op_symbols),
		__entry->slot_count, __entry->scope_count, __entry->source_id,
		__entry->root_guid_hash, __entry->ret)
);

/* hive-name / absolute-path / symlink-target routing (source_routing.c) */
DEFINE_EVENT(lcs_route, lcs_route,
	TP_PROTO(u8 op, u32 slot_count, u32 scope_count, u32 source_id,
		 u64 root_guid_hash, long ret),
	TP_ARGS(op, slot_count, scope_count, source_id, root_guid_hash, ret));
/* Resolved in the CREATE_TRACE_POINTS TU (pkm_trace.c) via the definition in
 * security/pkm/lcs/audit.c; declared here so the lcs_access/lcs_audit probes
 * compile. Hashes a 16-byte key GUID to u64 (0 when NULL). Never records raw
 * GUID bytes. */
u64 pkm_lcs_trace_guid_hash(const u8 *guid);

/* ---- lcs_registration: source registration decisions ---- */
#define lcs_registration_decision_symbols				\
	{ LCS_REG_NEW,			"new" },			\
	{ LCS_REG_RESUME_DOWN,		"resume-down" },		\
	{ LCS_REG_COPY,			"copy" },			\
	{ LCS_REG_REPLAY_FAIL,		"replay-fail" },		\
	{ LCS_REG_OVERFLOW_FAIL,	"overflow-fail" }

DECLARE_EVENT_CLASS(lcs_registration,

	TP_PROTO(u32 source_id, u32 resumed_source_id, u8 decision,
		 u32 hive_count, long ret),

	TP_ARGS(source_id, resumed_source_id, decision, hive_count, ret),

	TP_STRUCT__entry(
		__field(	long,	ret			)
		__field(	u32,	source_id		)
		__field(	u32,	resumed_source_id	)
		__field(	u32,	hive_count		)
		__field(	u8,	decision		)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->resumed_source_id = resumed_source_id;
		__entry->hive_count = hive_count;
		__entry->decision = decision;
	),

	TP_printk("decision=%s source_id=%u resumed_source_id=%u hive_count=%u ret=%ld",
		__print_symbolic(__entry->decision,
				 lcs_registration_decision_symbols),
		__entry->source_id, __entry->resumed_source_id,
		__entry->hive_count, __entry->ret)
);

DEFINE_EVENT(lcs_registration, lcs_source_register,
	TP_PROTO(u32 source_id, u32 resumed_source_id, u8 decision,
		 u32 hive_count, long ret),
	TP_ARGS(source_id, resumed_source_id, decision, hive_count, ret));

DEFINE_EVENT(lcs_registration, lcs_registration_publish,
	TP_PROTO(u32 source_id, u32 resumed_source_id, u8 decision,
		 u32 hive_count, long ret),
	TP_ARGS(source_id, resumed_source_id, decision, hive_count, ret));

DEFINE_EVENT(lcs_registration, lcs_registration_copy,
	TP_PROTO(u32 source_id, u32 resumed_source_id, u8 decision,
		 u32 hive_count, long ret),
	TP_ARGS(source_id, resumed_source_id, decision, hive_count, ret));

/* ---- lcs_bootstrap: bootstrap / self-config refresh phases ---- */
#define lcs_bootstrap_stage_symbols					\
	{ LCS_BOOT_REGISTRY,			"registry" },		\
	{ LCS_BOOT_KMES,			"kmes" },		\
	{ LCS_BOOT_LAYERS,			"layers" },		\
	{ LCS_BOOT_SELF_WATCH,			"self-watch" },		\
	{ LCS_BOOT_COMPLETE,			"complete" },		\
	{ LCS_BOOT_SELF_CONFIG_REFRESH,		"self-config-refresh" },	\
	{ LCS_BOOT_SELF_CONFIG_PARAM_INVALID,	"self-config-param-invalid" }

DECLARE_EVENT_CLASS(lcs_bootstrap,

	TP_PROTO(u32 source_id, u8 registry_present, u8 kmes_present,
		 u8 layers_present, u8 stage, long ret),

	TP_ARGS(source_id, registry_present, kmes_present, layers_present,
		stage, ret),

	TP_STRUCT__entry(
		__field(	long,	ret			)
		__field(	u32,	source_id		)
		__field(	u8,	registry_present	)
		__field(	u8,	kmes_present		)
		__field(	u8,	layers_present		)
		__field(	u8,	stage			)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->registry_present = registry_present;
		__entry->kmes_present = kmes_present;
		__entry->layers_present = layers_present;
		__entry->stage = stage;
	),

	TP_printk("stage=%s source_id=%u registry=%u kmes=%u layers=%u ret=%ld",
		__print_symbolic(__entry->stage, lcs_bootstrap_stage_symbols),
		__entry->source_id, __entry->registry_present,
		__entry->kmes_present, __entry->layers_present, __entry->ret)
);

DEFINE_EVENT(lcs_bootstrap, lcs_bootstrap_refresh,
	TP_PROTO(u32 source_id, u8 registry_present, u8 kmes_present,
		 u8 layers_present, u8 stage, long ret),
	TP_ARGS(source_id, registry_present, kmes_present, layers_present,
		stage, ret));

DEFINE_EVENT(lcs_bootstrap, lcs_self_config_refresh,
	TP_PROTO(u32 source_id, u8 registry_present, u8 kmes_present,
		 u8 layers_present, u8 stage, long ret),
	TP_ARGS(source_id, registry_present, kmes_present, layers_present,
		stage, ret));

DEFINE_EVENT(lcs_bootstrap, lcs_self_config_publish,
	TP_PROTO(u32 source_id, u8 registry_present, u8 kmes_present,
		 u8 layers_present, u8 stage, long ret),
	TP_ARGS(source_id, registry_present, kmes_present, layers_present,
		stage, ret));

/* ---- lcs_access: key-open access decisions (verdict via allowed/ret) ---- */
DECLARE_EVENT_CLASS(lcs_access,

	TP_PROTO(u32 source_id, const u8 *key_guid, u32 desired_access,
		 u32 granted_access, u8 allowed, long ret),

	TP_ARGS(source_id, key_guid, desired_access, granted_access, allowed,
		ret),

	TP_STRUCT__entry(
		__field(	u64,	key_guid_hash	)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	desired_access	)
		__field(	u32,	granted_access	)
		__field(	u8,	allowed		)
	),

	TP_fast_assign(
		__entry->key_guid_hash =
			key_guid ? pkm_lcs_trace_guid_hash(key_guid) : 0;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->desired_access = desired_access;
		__entry->granted_access = granted_access;
		__entry->allowed = allowed;
	),

	TP_printk("verdict=%s source_id=%u key_guid_hash=0x%llx desired=0x%x granted=0x%x ret=%ld",
		__entry->allowed ? "allow" : "deny",
		__entry->source_id, __entry->key_guid_hash,
		__entry->desired_access, __entry->granted_access, __entry->ret)
);

DEFINE_EVENT(lcs_access, lcs_key_open,
	TP_PROTO(u32 source_id, const u8 *key_guid, u32 desired_access,
		 u32 granted_access, u8 allowed, long ret),
	TP_ARGS(source_id, key_guid, desired_access, granted_access, allowed, ret));

DEFINE_EVENT(lcs_access, lcs_open_syscall,
	TP_PROTO(u32 source_id, const u8 *key_guid, u32 desired_access,
		 u32 granted_access, u8 allowed, long ret),
	TP_ARGS(source_id, key_guid, desired_access, granted_access, allowed, ret));

DEFINE_EVENT(lcs_access, lcs_access_check,
	TP_PROTO(u32 source_id, const u8 *key_guid, u32 desired_access,
		 u32 granted_access, u8 allowed, long ret),
	TP_ARGS(source_id, key_guid, desired_access, granted_access, allowed, ret));

/* ---- lcs_source_table: slot cap / sequence / generation state ---- */
DECLARE_EVENT_CLASS(lcs_source_table,

	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),

	TP_ARGS(source_id, count, value, ret),

	TP_STRUCT__entry(
		__field(	u64,	value		)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	count		)
	),

	TP_fast_assign(
		__entry->value = value;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->count = count;
	),

	TP_printk("source_id=%u count=%u value=%llu ret=%ld",
		__entry->source_id, __entry->count, __entry->value,
		__entry->ret)
);

DEFINE_EVENT(lcs_source_table, lcs_bound_txn_acquire,
	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),
	TP_ARGS(source_id, count, value, ret));

DEFINE_EVENT(lcs_source_table, lcs_readonly_txn_acquire,
	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),
	TP_ARGS(source_id, count, value, ret));

DEFINE_EVENT(lcs_source_table, lcs_allocate_sequence,
	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),
	TP_ARGS(source_id, count, value, ret));

DEFINE_EVENT(lcs_source_table, lcs_record_generation,
	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),
	TP_ARGS(source_id, count, value, ret));

DEFINE_EVENT(lcs_source_table, lcs_restore_sequence,
	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),
	TP_ARGS(source_id, count, value, ret));

DEFINE_EVENT(lcs_source_table, lcs_assign_key_guid,
	TP_PROTO(u32 source_id, u32 count, u64 value, long ret),
	TP_ARGS(source_id, count, value, ret));

/* ---- lcs_tcb: source-device TCB/admin authority gate ---- */
DECLARE_EVENT_CLASS(lcs_tcb,

	TP_PROTO(u32 source_id, u8 has_tcb, u8 has_admin, long ret),

	TP_ARGS(source_id, has_tcb, has_admin, ret),

	TP_STRUCT__entry(
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u8,	has_tcb		)
		__field(	u8,	has_admin	)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->has_tcb = has_tcb;
		__entry->has_admin = has_admin;
	),

	TP_printk("verdict=%s source_id=%u has_tcb=%u has_admin=%u ret=%ld",
		__entry->ret ? "deny" : "allow",
		__entry->source_id, __entry->has_tcb, __entry->has_admin,
		__entry->ret)
);

DEFINE_EVENT(lcs_tcb, lcs_tcb_check,
	TP_PROTO(u32 source_id, u8 has_tcb, u8 has_admin, long ret),
	TP_ARGS(source_id, has_tcb, has_admin, ret));

/* ---- lcs_runtime_limits: limit validate reject / publish ---- */
#define lcs_runtime_limits_field_symbols				\
	{ LCS_LIM_REQUEST_TIMEOUT_MS,		"request_timeout_ms" },	\
	{ LCS_LIM_TRANSACTION_TIMEOUT_MS,	"transaction_timeout_ms" }, \
	{ LCS_LIM_NOTIFICATION_QUEUE_SIZE,	"notification_queue_size" }, \
	{ LCS_LIM_SYMLINK_DEPTH_LIMIT,		"symlink_depth_limit" },	\
	{ LCS_LIM_MAX_VALUE_SIZE,		"max_value_size" },	\
	{ LCS_LIM_MAX_KEY_DEPTH,		"max_key_depth" },	\
	{ LCS_LIM_MAX_PATH_COMPONENT_LENGTH,	"max_path_component_length" }, \
	{ LCS_LIM_MAX_TOTAL_PATH_LENGTH,	"max_total_path_length" }, \
	{ LCS_LIM_MAX_LAYERS_PER_VALUE,		"max_layers_per_value" }, \
	{ LCS_LIM_MAX_BOUND_TRANSACTIONS_PER_SOURCE, "max_bound_transactions_per_source" }, \
	{ LCS_LIM_MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE, "max_read_only_transactions_per_source" }, \
	{ LCS_LIM_MAX_TOTAL_LAYERS,		"max_total_layers" },	\
	{ LCS_LIM_MAX_REGISTERED_SOURCES,	"max_registered_sources" }, \
	{ LCS_LIM_MAX_HIVES_PER_SOURCE,		"max_hives_per_source" }, \
	{ LCS_LIM_MAX_CONCURRENT_RSI_REQUESTS,	"max_concurrent_rsi_requests" }, \
	{ LCS_LIM_MAX_SCOPE_GUIDS_PER_TOKEN,	"max_scope_guids_per_token" }, \
	{ LCS_LIM_MAX_PRIVATE_LAYERS_PER_TOKEN,	"max_private_layers_per_token" }, \
	{ LCS_LIM_MAX_SUBTREE_WATCH_DEPTH,	"max_subtree_watch_depth" }, \
	{ LCS_LIM_MAX_TRANSACTION_WATCH_EVENT_BURST, "max_transaction_watch_event_burst" }, \
	{ LCS_LIM_ALL,				"all" }

DECLARE_EVENT_CLASS(lcs_runtime_limits,

	TP_PROTO(u32 field_id, u32 value, long ret),

	TP_ARGS(field_id, value, ret),

	TP_STRUCT__entry(
		__field(	long,	ret		)
		__field(	u32,	field_id	)
		__field(	u32,	value		)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->field_id = field_id;
		__entry->value = value;
	),

	TP_printk("field=%s value=%u ret=%ld",
		__print_symbolic(__entry->field_id,
				 lcs_runtime_limits_field_symbols),
		__entry->value, __entry->ret)
);

DEFINE_EVENT(lcs_runtime_limits, lcs_limits_validate,
	TP_PROTO(u32 field_id, u32 value, long ret),
	TP_ARGS(field_id, value, ret));

DEFINE_EVENT(lcs_runtime_limits, lcs_limits_publish,
	TP_PROTO(u32 field_id, u32 value, long ret),
	TP_ARGS(field_id, value, ret));

/* ---- lcs_audit: audit emit / emit-failed ---- */
#define lcs_audit_event_type_symbols					\
	{ LCS_AUDIT_KEY_OPEN,			"key-open" },		\
	{ LCS_AUDIT_BACKUP_START,		"backup-start" },	\
	{ LCS_AUDIT_BACKUP_COMPLETE,		"backup-complete" },	\
	{ LCS_AUDIT_RESTORE_START,		"restore-start" },	\
	{ LCS_AUDIT_RESTORE_COMPLETE,		"restore-complete" },	\
	{ LCS_AUDIT_VALIDATION_FAILURE,		"validation-failure" },	\
	{ LCS_AUDIT_SELF_CONFIG_INVALID,	"self-config-invalid" }

DECLARE_EVENT_CLASS(lcs_audit,

	TP_PROTO(u8 event_type_id, const u8 *key_guid, u32 result_errno,
		 u8 allowed, long ret),

	TP_ARGS(event_type_id, key_guid, result_errno, allowed, ret),

	TP_STRUCT__entry(
		__field(	u64,	key_guid_hash	)
		__field(	long,	ret		)
		__field(	u32,	result_errno	)
		__field(	u8,	event_type_id	)
		__field(	u8,	allowed		)
	),

	TP_fast_assign(
		__entry->key_guid_hash =
			key_guid ? pkm_lcs_trace_guid_hash(key_guid) : 0;
		__entry->ret = ret;
		__entry->result_errno = result_errno;
		__entry->event_type_id = event_type_id;
		__entry->allowed = allowed;
	),

	TP_printk("event=%s key_guid_hash=0x%llx result_errno=%u allowed=%u ret=%ld",
		__print_symbolic(__entry->event_type_id,
				 lcs_audit_event_type_symbols),
		__entry->key_guid_hash, __entry->result_errno,
		__entry->allowed, __entry->ret)
);

DEFINE_EVENT(lcs_audit, lcs_audit_emit,
	TP_PROTO(u8 event_type_id, const u8 *key_guid, u32 result_errno,
		 u8 allowed, long ret),
	TP_ARGS(event_type_id, key_guid, result_errno, allowed, ret));

DEFINE_EVENT(lcs_audit, lcs_audit_emit_failed,
	TP_PROTO(u8 event_type_id, const u8 *key_guid, u32 result_errno,
		 u8 allowed, long ret),
	TP_ARGS(event_type_id, key_guid, result_errno, allowed, ret));
/* ---- lcs_txn: transaction-fd state machine transitions ---- */
#define lcs_txn_state_symbols						\
	{ LCS_TXN_ST_ACTIVE_UNBOUND,	"active-unbound" },		\
	{ LCS_TXN_ST_ACTIVE_BOUND,	"active-bound" },		\
	{ LCS_TXN_ST_COMMITTED,		"committed" },			\
	{ LCS_TXN_ST_ABORTED,		"aborted" },			\
	{ LCS_TXN_ST_TIMED_OUT,		"timed-out" },			\
	{ LCS_TXN_ST_SOURCE_DOWN,	"source-down" }

DECLARE_EVENT_CLASS(lcs_txn,

	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),

	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out),

	TP_STRUCT__entry(
		__field(	u64,	txn_id		)
		__field(	s32,	err		)
		__field(	u32,	source_id	)
		__field(	u8,	old_state	)
		__field(	u8,	new_state	)
		__field(	u8,	timed_out	)
	),

	TP_fast_assign(
		__entry->txn_id = txn_id;
		__entry->err = err;
		__entry->source_id = source_id;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
		__entry->timed_out = timed_out;
	),

	TP_printk("txn=%llu source=%u %s->%s err=%d timed_out=%u",
		__entry->txn_id, __entry->source_id,
		__print_symbolic(__entry->old_state, lcs_txn_state_symbols),
		__print_symbolic(__entry->new_state, lcs_txn_state_symbols),
		__entry->err, __entry->timed_out)
);

/* transaction fd allocated, ACTIVE_UNBOUND (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_begin,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* first mutation binds UNBOUND->BOUND (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_first_bind,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* subsequent mutation appended to a bound txn (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_bind_mutation,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* commit round-trip outcome: COMMITTED / TIMED_OUT / SOURCE_DOWN (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_commit,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* abort: fd close, or layer-writer mass abort (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_abort,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* deadline timer fired -> TIMED_OUT (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_timeout,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* bound source down -> SOURCE_DOWN, per affected txn (transaction_fd.c) */
DEFINE_EVENT(lcs_txn, lcs_txn_source_down,
	TP_PROTO(u64 txn_id, u32 source_id, u32 old_state, u32 new_state,
		 s32 err, bool timed_out),
	TP_ARGS(txn_id, source_id, old_state, new_state, err, timed_out));

/* ---- lcs_key_fd: key-fd lifecycle + ioctl / mutation / read / notify ---- */
#define lcs_key_cmd_symbols						\
	{ LCS_KCMD_NONE,		"none" },			\
	{ LCS_KCMD_SET_VALUE,		"set-value" },			\
	{ LCS_KCMD_DELETE_VALUE,	"delete-value" },		\
	{ LCS_KCMD_BLANKET_TOMBSTONE,	"blanket-tombstone" },		\
	{ LCS_KCMD_DELETE_KEY,		"delete-key" },			\
	{ LCS_KCMD_HIDE_KEY,		"hide-key" },			\
	{ LCS_KCMD_QUERY_VALUE,		"query-value" },		\
	{ LCS_KCMD_QUERY_VALUES_BATCH,	"query-values-batch" },		\
	{ LCS_KCMD_ENUM_VALUES,		"enum-values" },		\
	{ LCS_KCMD_ENUM_SUBKEYS,	"enum-subkeys" },		\
	{ LCS_KCMD_QUERY_KEY_INFO,	"query-key-info" },		\
	{ LCS_KCMD_GET_SECURITY,	"get-security" },		\
	{ LCS_KCMD_SET_SECURITY,	"set-security" },		\
	{ LCS_KCMD_FLUSH,		"flush" },			\
	{ LCS_KCMD_BACKUP,		"backup" },			\
	{ LCS_KCMD_RESTORE,		"restore" },			\
	{ LCS_KCMD_NOTIFY,		"notify" }

/*
 * One key-fd operation. key_guid_hash is a non-reversible u64 fold of the key
 * GUID (0 for nil) - never the raw bytes. `sequence` overloads per event: the
 * mutation transaction id (lcs_key_mutation), the watch action 1=arm/2=disarm
 * (lcs_key_notify), or the count of watch events drained (lcs_key_read); 0
 * otherwise. `txn_fd` is the mutation's transaction fd (or -1). No path/name/SD.
 */
DECLARE_EVENT_CLASS(lcs_key_fd,

	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),

	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access,
		ret),

	TP_STRUCT__entry(
		__field(	u64,	key_guid_hash	)
		__field(	u64,	sequence	)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	granted_access	)
		__field(	s32,	txn_fd		)
		__field(	u8,	cmd		)
	),

	TP_fast_assign(
		__entry->key_guid_hash = key_guid_hash;
		__entry->sequence = sequence;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->granted_access = granted_access;
		__entry->txn_fd = txn_fd;
		__entry->cmd = cmd;
	),

	TP_printk("source=%u guid_hash=0x%llx cmd=%s txn_fd=%d seq=%llu granted=0x%x ret=%ld",
		__entry->source_id, __entry->key_guid_hash,
		__print_symbolic(__entry->cmd, lcs_key_cmd_symbols),
		__entry->txn_fd, __entry->sequence, __entry->granted_access,
		__entry->ret)
);

/* key-fd published; ret is the new fd (or negative errno) (key_fd.c) */
DEFINE_EVENT(lcs_key_fd, lcs_key_publish,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),
	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access, ret));

/* key-fd released on close (key_fd.c) */
DEFINE_EVENT(lcs_key_fd, lcs_key_release,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),
	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access, ret));

/* key-fd ioctl dispatch outcome, cmd names the verb (key_fd.c) */
DEFINE_EVENT(lcs_key_fd, lcs_key_ioctl,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),
	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access, ret));

/* write_key round-trip failure -> source marked down (key_fd.c) */
DEFINE_EVENT(lcs_key_fd, lcs_key_mutation,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),
	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access, ret));

/* watch-queue drain via read(); seq=events, ret=bytes (key_fd.c) */
DEFINE_EVENT(lcs_key_fd, lcs_key_read,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),
	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access, ret));

/* watch arm/disarm via NOTIFY; seq carries 1=arm/2=disarm (key_fd.c) */
DEFINE_EVENT(lcs_key_fd, lcs_key_notify,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u8 cmd, s32 txn_fd,
		 u64 sequence, u32 granted_access, long ret),
	TP_ARGS(source_id, key_guid_hash, cmd, txn_fd, sequence, granted_access, ret));

/* ---- lcs_watch: watch-event dispatch ---- */
/*
 * One watch dispatch effect. key_guid_hash folds the watcher/changed key GUID
 * (0 for the multi-guid self-watch arm). event_type is the REG_WATCH_* code.
 * watch_count is context-specific: the watcher's pending-event depth
 * (lcs_watch_dispatch), the overflowing burst count (lcs_watch_overflow), the
 * key-ref refcount (lcs_watch_orphan), or the number of internal watches armed
 * (lcs_watch_self_watch). No name/SD/key bytes.
 */
DECLARE_EVENT_CLASS(lcs_watch,

	TP_PROTO(u32 source_id, u64 key_guid_hash, u32 event_type,
		 u32 watch_count, long ret),

	TP_ARGS(source_id, key_guid_hash, event_type, watch_count, ret),

	TP_STRUCT__entry(
		__field(	u64,	key_guid_hash	)
		__field(	long,	ret		)
		__field(	u32,	source_id	)
		__field(	u32,	event_type	)
		__field(	u32,	watch_count	)
	),

	TP_fast_assign(
		__entry->key_guid_hash = key_guid_hash;
		__entry->ret = ret;
		__entry->source_id = source_id;
		__entry->event_type = event_type;
		__entry->watch_count = watch_count;
	),

	TP_printk("source=%u guid_hash=0x%llx event_type=%u watch_count=%u ret=%ld",
		__entry->source_id, __entry->key_guid_hash, __entry->event_type,
		__entry->watch_count, __entry->ret)
);

/* per-watcher event delivery (key_fd.c) */
DEFINE_EVENT(lcs_watch, lcs_watch_dispatch,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u32 event_type,
		 u32 watch_count, long ret),
	TP_ARGS(source_id, key_guid_hash, event_type, watch_count, ret));

/* transaction-burst overflow -> OVERFLOW record to watcher (key_fd.c) */
DEFINE_EVENT(lcs_watch, lcs_watch_overflow,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u32 event_type,
		 u32 watch_count, long ret),
	TP_ARGS(source_id, key_guid_hash, event_type, watch_count, ret));

/* mark-orphaned -> immediate drop_key dispatch (key_fd.c) */
DEFINE_EVENT(lcs_watch, lcs_watch_orphan,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u32 event_type,
		 u32 watch_count, long ret),
	TP_ARGS(source_id, key_guid_hash, event_type, watch_count, ret));

/* internal self-watch arm (key_fd.c) */
DEFINE_EVENT(lcs_watch, lcs_watch_self_watch,
	TP_PROTO(u32 source_id, u64 key_guid_hash, u32 event_type,
		 u32 watch_count, long ret),
	TP_ARGS(source_id, key_guid_hash, event_type, watch_count, ret));

#endif /* _TRACE_LCS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
