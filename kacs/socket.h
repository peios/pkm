/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_SOCKET_H
#define _SECURITY_PKM_KACS_SOCKET_H

#include <linux/sockptr.h>
#include <linux/types.h>

#include <net/sock.h>

struct sockaddr;
struct socket;

int pkm_kacs_sk_alloc_security(struct sock *sk, int family, gfp_t priority);
void pkm_kacs_sk_free_security(struct sock *sk);
int pkm_kacs_socket_bind(struct socket *sock, struct sockaddr *address,
			 int addrlen);
int pkm_kacs_unix_stream_connect(struct sock *sock, struct sock *other,
				 struct sock *newsk);
int pkm_kacs_unix_may_send(struct socket *sock, struct socket *other);
/* SOL_KACS option handlers, dispatched from net/socket.c. */
int pkm_kacs_sock_setsockopt(struct socket *sock, int optname,
			     sockptr_t optval, unsigned int optlen);
int pkm_kacs_sock_getsockopt(struct socket *sock, int optname,
			     sockptr_t optval, sockptr_t optlen);

#endif /* _SECURITY_PKM_KACS_SOCKET_H */
