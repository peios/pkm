/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_SYSCALL_H
#define _UAPI_PKM_SYSCALL_H

/*
 * PKM custom syscall numbers.
 *
 * PKM registers these into arch/x86/entry/syscalls/syscall_64.tbl via the
 * patch kernel/patches/arch/syscall-table-pkm.patch. This header is the
 * userspace-facing mirror of that registration: the two must be kept in
 * lockstep — adding, moving, or removing a syscall touches both.
 *
 * The numbers occupy the 1000+ range, which the upstream x86-64 syscall
 * table leaves free for out-of-tree use.
 */

/* KACS — tokens, sessions, impersonation. */
#define SYS_KACS_OPEN_SELF_TOKEN	1000
#define SYS_KACS_OPEN_PROCESS_TOKEN	1001
#define SYS_KACS_OPEN_THREAD_TOKEN	1002
#define SYS_KACS_CREATE_TOKEN		1003
#define SYS_KACS_CREATE_SESSION		1004
#define SYS_KACS_SET_PSB		1005
#define SYS_KACS_DESTROY_EMPTY_SESSION	1006

/* KACS — peer tokens and impersonation. */
#define SYS_KACS_OPEN_PEER_TOKEN	1010
#define SYS_KACS_IMPERSONATE_PEER	1011
#define SYS_KACS_REVERT			1012
#define SYS_KACS_SET_IMPERSONATION_LEVEL 1013

/* KACS — files, security descriptors, access checks, mount policy. */
#define SYS_KACS_OPEN			1020
#define SYS_KACS_GET_SD			1021
#define SYS_KACS_SET_SD			1022
#define SYS_KACS_ACCESS_CHECK		1023
#define SYS_KACS_ACCESS_CHECK_LIST	1024
#define SYS_KACS_SET_CAAP		1025
#define SYS_KACS_GET_MOUNT_POLICY	1026
#define SYS_KACS_SET_MOUNT_POLICY	1027

/* KMES — kernel-mediated event stream. */
#define SYS_KMES_EMIT			1090
#define SYS_KMES_ATTACH			1091
#define SYS_KMES_EMIT_BATCH		1092

/* LCS — registry. */
#define SYS_REG_OPEN_KEY		1100
#define SYS_REG_CREATE_KEY		1101
#define SYS_REG_BEGIN_TRANSACTION	1102

#endif /* _UAPI_PKM_SYSCALL_H */
