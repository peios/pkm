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
void pkm_kacs_sk_clone_security(const struct sock *sk, struct sock *newsk);
int pkm_kacs_socket_post_create(struct socket *sock, int family, int type,
				int protocol, int kern);
int pkm_kacs_socket_bind(struct socket *sock, struct sockaddr *address,
			 int addrlen);
int pkm_kacs_socket_connect(struct socket *sock, struct sockaddr *address,
			    int addrlen);
int pkm_kacs_unix_stream_connect(struct sock *sock, struct sock *other,
				 struct sock *newsk);
int pkm_kacs_unix_may_send(struct socket *sock, struct socket *other);
int pkm_kacs_socket_listen(struct socket *sock, int backlog);
/* SOL_KACS option handlers, dispatched from net/socket.c. */
int pkm_kacs_sock_setsockopt(struct socket *sock, int optname,
			     sockptr_t optval, unsigned int optlen);
int pkm_kacs_sock_getsockopt(struct socket *sock, int optname,
			     sockptr_t optval, sockptr_t optlen);

/*
 * Per-message identity (KACS_SCM_TOKEN), reached from net/core/scm.c and
 * net/unix/af_unix.c. Tokens are opaque refcounted immutable objects; every
 * pointer handed across here is a counted reference.
 */
struct cmsghdr;
struct msghdr;
struct scm_cookie;
const void *pkm_kacs_token_get(const void *token);
void pkm_kacs_token_put(const void *token);
int pkm_kacs_scm_cmsg(struct socket *sock, struct cmsghdr *cmsg,
		      struct scm_cookie *scm);
int pkm_kacs_scm_send(struct socket *sock, struct scm_cookie *scm);
void pkm_kacs_scm_token_drop(struct scm_cookie *scm);
void pkm_kacs_scm_recv(struct socket *sock, struct msghdr *msg,
		       struct scm_cookie *scm);
bool pkm_kacs_unix_read_boundary(struct sock *sk, const void *skb_token,
				 struct scm_cookie *scm, int copied);
void pkm_kacs_unix_consumed(struct sock *sk, const void *skb_token);

#endif /* _SECURITY_PKM_KACS_SOCKET_H */
