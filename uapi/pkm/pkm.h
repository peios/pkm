/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_H
#define _UAPI_PKM_H

/*
 * PKM userspace ABI — the published kernel interface to the Peios Kernel
 * Module.
 *
 * PKM is Peios's in-kernel security substrate. Its subsystems —
 *   KACS  tokens, security descriptors, access checks
 *         (<pkm/token.h>, <pkm/sd.h>, <pkm/sid.h>, <pkm/access.h>,
 *          <pkm/file.h>)
 *   KMES  the kernel-mediated event stream (<pkm/kmes.h>)
 * share one wire-format vocabulary (SIDs, security descriptors, access
 * masks) and are versioned and shipped together as a single kernel module.
 * LCS (the registry) joins this header set when it lands.
 *
 * These headers are the single source of truth for the ABI: the kernel
 * compiles against them and so does userspace, so the two see
 * byte-identical definitions by construction. Each header is
 * userspace-clean — it compiles with an ordinary, non-kernel C compiler.
 *
 * Errno: PKM syscalls return a non-negative result on success and a
 * negated standard Linux errno on failure (e.g. -EACCES). There are no
 * PKM-specific errno values; use <errno.h>.
 *
 * Including this umbrella header pulls in the entire ABI.
 */

#include <pkm/syscall.h>
#include <pkm/sid.h>
#include <pkm/sd.h>
#include <pkm/token.h>
#include <pkm/access.h>
#include <pkm/file.h>
#include <pkm/kmes.h>

#endif /* _UAPI_PKM_H */
