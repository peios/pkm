// SPDX-License-Identifier: GPL-2.0-only
/*
 * PKM tracepoint definitions.
 *
 * The single translation unit in the PKM module that defines
 * CREATE_TRACE_POINTS, so the out-of-line tracepoint structures and event
 * probes for every PKM trace system (kacs:, kmes:, lcs:) are emitted here
 * exactly once. Every other PKM object includes the same
 * per-system trace headers WITHOUT CREATE_TRACE_POINTS and get only the
 * inline trace_*() call-site stubs.
 *
 * Include order matters: the headers referenced by the events' TP_fast_assign
 * (e.g. pkm_kacs_superblock_mount_policy) must be visible before the trace
 * header, because the probe bodies are compiled here.
 */
#include <linux/fs.h>

#include "mount_policy.h"

#define CREATE_TRACE_POINTS
#include <trace/events/kacs.h>
#include <trace/events/kmes.h>
#include <trace/events/lcs.h>
