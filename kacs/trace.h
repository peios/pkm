/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KACS access-decision tracing.
 *
 * A permanent, opt-in diagnostic for the recurring question during boot
 * bring-up: "why did KACS allow or deny this access?" — most often when a
 * filesystem first mounts (the inode-permission / file-open checks that fire
 * before userspace is even up).
 *
 * Design notes:
 *
 *   - OFF by default; enabled with the kernel cmdline token `kacs.trace=1`.
 *     A plain `name=value` token was chosen deliberately over relying on
 *     pr_debug + dynamic_debug: the boot path is exactly where dynamic_debug is
 *     most awkward to turn on (a `dyndbg="file ... +p"` query has to survive
 *     several layers of shell/cmdline quoting), and the access core has early
 *     returns that never reached the existing pr_debug sites at all. A bare
 *     value token is robust to all of that.
 *
 *   - Traces BOTH allow (ret == 0) and deny (ret < 0) at each instrumented
 *     decision point, each tagged with a `site` (the hook/function) and a
 *     `reason` (the specific return path), so a single `kacs.trace=1` boot
 *     shows the complete decision sequence — including the early-exit paths
 *     that the ad-hoc pr_debug logging missed.
 *
 *   - Never logs pathnames — only inode number, superblock magic, and the
 *     resolved mount policy — so it stays safe to leave compiled in (same rule
 *     the existing pr_debug deny logs follow).
 */
#ifndef _PKM_KACS_TRACE_H
#define _PKM_KACS_TRACE_H

#include <linux/types.h>

struct inode;

/* Set from the `kacs.trace=1` boot parameter (see lsm.c). */
extern bool pkm_kacs_trace_enabled;

/*
 * Emit one access-decision trace line. `site` names the hook/function, `reason`
 * the specific return path, `access` carries the desired-access/mask bits, and
 * `ret` the outcome (0 = allow, negative errno = deny). `inode` may be NULL
 * (e.g. a bad-args path); the inode/sb fields are then reported as zero. The
 * caller should gate with PKM_KACS_TRACE so the toggle is checked inline before
 * the call.
 */
void pkm_kacs_trace_access_decision(const char *site, const char *reason,
				    const struct inode *inode, u32 access,
				    long ret);

/*
 * Trace a decision unless tracing is disabled. The toggle check is inlined so
 * an off trace costs a single (unlikely) branch — cheap enough to leave on
 * every hot-path return.
 */
#define PKM_KACS_TRACE(site, reason, inode, access, ret)                    \
	do {                                                                \
		if (unlikely(pkm_kacs_trace_enabled))                       \
			pkm_kacs_trace_access_decision((site), (reason),    \
						       (inode), (access),   \
						       (ret));              \
	} while (0)

#endif /* _PKM_KACS_TRACE_H */
