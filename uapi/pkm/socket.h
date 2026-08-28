/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_SOCKET_H
#define _UAPI_PKM_SOCKET_H

#include <linux/types.h>

/*
 * KACS socket options — peer identity on local sockets.
 *
 * KACS captures a connecting client's identity onto the accepted end of an
 * AF_UNIX SOCK_STREAM / SOCK_SEQPACKET connection at connect(). This header
 * is the setsockopt(2)/getsockopt(2) surface through which that identity is
 * bounded and read back. Every option lives under one option level,
 * SOL_KACS, which the kernel dispatches ahead of the protocol's own
 * setsockopt/getsockopt (net/socket.c), so the options behave identically
 * on every socket family that supports them.
 *
 * SOL_KACS is 4096: far above the upstream SOL_* range, which grows by one
 * per new protocol, so it cannot collide with a future Linux level.
 *
 * Errors: -ENOPROTOOPT for an option this level does not define (or a
 * get-only option passed to setsockopt); -EOPNOTSUPP on a socket family or
 * type KACS does not capture identity for; -EINVAL for a short optlen or an
 * out-of-range value; -EFAULT for an unreadable/unwritable optval.
 */
#define SOL_KACS			4096

/*
 * getsockopt only. optval: int — a new token fd for the peer identity
 * captured at connect(), carrying fixed TOKEN_QUERY | TOKEN_IMPERSONATE
 * access. The fd is opened O_CLOEXEC. -ENOTCONN if the socket is not
 * connected; -ENODATA if it is connected but carries no captured identity.
 */
#define KACS_SO_PEER_TOKEN		1

/*
 * getsockopt / setsockopt. optval: __u32 KACS_IMLEVEL_* — the maximum
 * impersonation level at which this end's identity may be captured by the
 * peer. Set by the client before connect(); the default is
 * KACS_IMLEVEL_IMPERSONATION. -EISCONN once the socket is connected.
 */
#define KACS_SO_IMPERSONATION_LEVEL	2

#endif /* _UAPI_PKM_SOCKET_H */
