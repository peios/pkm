/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * StrataFS static tracepoints.
 *
 * Staged by stage-sources.sh into include/trace/events/stratafs.h — the
 * canonical location, so <trace/events/stratafs.h> resolves with no
 * TRACE_INCLUDE_PATH override and this file's events land in the
 * `stratafs:` trace system. CREATE_TRACE_POINTS is defined in the one
 * PKM trace TU (security/pkm/kacs/pkm_trace.c), same as kacs/kmes/lcs.
 *
 * Same invariant as kacs.h: never records a pathname. Events identify a
 * mount by its cookie (§4.2.4) and an object by the merged inode number.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM stratafs

#if !defined(_TRACE_STRATAFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_STRATAFS_H

#include <linux/tracepoint.h>
#include <linux/types.h>

/*
 * One d_revalidate verdict (§4.4.2). `rcu` says the walk was in RCU
 * mode; the contract is that every rcu=1 call returns -ECHILD (refuse
 * and retry in ref-walk) and every rcu=0 call on a non-root dentry
 * returns 0 (rebuild). The root returns 1 and is not traced. `ino` is
 * the merged inode number, or 0 for a negative dentry.
 */
TRACE_EVENT(stratafs_d_revalidate,

	TP_PROTO(u64 cookie, u64 ino, bool rcu, int ret),

	TP_ARGS(cookie, ino, rcu, ret),

	TP_STRUCT__entry(
		__field(	u64,	cookie	)
		__field(	u64,	ino	)
		__field(	bool,	rcu	)
		__field(	int,	ret	)
	),

	TP_fast_assign(
		__entry->cookie = cookie;
		__entry->ino = ino;
		__entry->rcu = rcu;
		__entry->ret = ret;
	),

	TP_printk("cookie=0x%llx ino=%llu rcu=%d ret=%d",
		__entry->cookie, __entry->ino, __entry->rcu, __entry->ret)
);

/*
 * The other half of the §4.4.2 refusal: the directory permission check
 * under MAY_NOT_BLOCK. In practice this fires first — the walk leaves
 * RCU mode at the first stratafs directory it must traverse, so
 * d_revalidate's own -ECHILD branch is the backstop and every traced
 * d_revalidate call arrives with rcu=0.
 */
TRACE_EVENT(stratafs_rcu_walk_refused,

	TP_PROTO(u64 cookie, u64 ino),

	TP_ARGS(cookie, ino),

	TP_STRUCT__entry(
		__field(	u64,	cookie	)
		__field(	u64,	ino	)
	),

	TP_fast_assign(
		__entry->cookie = cookie;
		__entry->ino = ino;
	),

	TP_printk("cookie=0x%llx ino=%llu", __entry->cookie, __entry->ino)
);

/*
 * The §4.5.5 rename identity backstop firing: the provider found by the
 * locked re-lookup is not the object the walk resolved. The attempt
 * fails -ESTALE — which the VFS then heals by retrying the whole
 * syscall with a fresh walk, so the caller usually sees the retry's
 * outcome rather than the errno. This event is the refusal itself.
 */
TRACE_EVENT(stratafs_rename_stale,

	TP_PROTO(u64 cookie, u64 walk_ino, u64 found_ino),

	TP_ARGS(cookie, walk_ino, found_ino),

	TP_STRUCT__entry(
		__field(	u64,	cookie		)
		__field(	u64,	walk_ino	)
		__field(	u64,	found_ino	)
	),

	TP_fast_assign(
		__entry->cookie = cookie;
		__entry->walk_ino = walk_ino;
		__entry->found_ino = found_ino;
	),

	TP_printk("cookie=0x%llx walk_ino=%llu found_ino=%llu",
		__entry->cookie, __entry->walk_ino, __entry->found_ino)
);

#endif /* _TRACE_STRATAFS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
