/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_SOCKET_H
#define _SECURITY_PKM_KACS_SOCKET_H

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

#endif /* _SECURITY_PKM_KACS_SOCKET_H */
