// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/sockptr.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/un.h>

#include <net/sock.h>

#include <pkm/socket.h>

#include "lsm_internal.h"
#include "socket.h"
#include "token_fd.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

#define PKM_KACS_SOCKET_FILE_WRITE_DATA 0x00000002U
#define PKM_KACS_PEER_TOKEN_ACCESS_MASK \
	(KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE)

static void pkm_kacs_socket_peer_token_drop(struct pkm_kacs_socket_security *sec)
{
	if (!sec || !sec->peer_token)
		return;

	kacs_rust_token_drop(sec->peer_token);
	sec->peer_token = NULL;
}

static bool pkm_kacs_socket_type_supported(int type)
{
	return type == SOCK_STREAM || type == SOCK_SEQPACKET;
}

static bool pkm_kacs_socket_level_valid(u32 level)
{
	switch (level) {
	case KACS_IMLEVEL_ANONYMOUS:
	case KACS_IMLEVEL_IDENTIFICATION:
	case KACS_IMLEVEL_IMPERSONATION:
	case KACS_IMLEVEL_DELEGATION:
		return true;
	default:
		return false;
	}
}

static bool pkm_kacs_sockaddr_is_abstract_unix(const struct sockaddr *address,
					       int addrlen)
{
	const struct sockaddr_un *sun = (const struct sockaddr_un *)address;

	if (!address || addrlen < offsetof(struct sockaddr_un, sun_path) + 1)
		return false;
	if (address->sa_family != AF_UNIX)
		return false;

	return sun->sun_path[0] == '\0';
}

static long pkm_kacs_authorize_socket_sd_access(
	const void *subject_token,
	const struct pkm_kacs_process_sd *socket_sd, u32 desired_access)
{
	u32 granted = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (!subject_token || !socket_sd || !socket_sd->bytes || !socket_sd->len) {
		trace_kacs_socket_sd_authorize(0, 0, 0, 0, desired_access,
					       KACS_SOCK_BAD_ARGS, -EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret) {
		trace_kacs_socket_sd_authorize(0, 0, 0, 0, desired_access,
					       KACS_SOCK_PIP_CONTEXT, ret);
		return ret;
	}

	ret = kacs_rust_check_socket_sd(subject_token, socket_sd->bytes,
					socket_sd->len, desired_access,
					pip_type, pip_trust, &granted);
	trace_kacs_socket_sd_authorize(0, 0, 0, 0, desired_access,
				       KACS_SOCK_SD_DECISION, ret);
	return ret;
}

static long pkm_kacs_create_captured_peer_token(
	const void *client_token, u32 max_impersonation,
	const void **out_token)
{
	if (!client_token || !out_token)
		return -EACCES;
	if (!pkm_kacs_socket_level_valid(max_impersonation))
		return -EINVAL;

	*out_token = NULL;
	if (max_impersonation == KACS_IMLEVEL_ANONYMOUS)
		return kacs_rust_create_anonymous_impersonation_token(
			(void *)out_token);

	return kacs_rust_create_peer_impersonation_token(client_token,
							 max_impersonation,
							 (void *)out_token);
}

static long pkm_kacs_capture_peer_token_core(
	const struct pkm_kacs_socket_security *client_sec,
	struct pkm_kacs_socket_security *accepted_sec,
	const void *client_token)
{
	const void *peer_token = NULL;
	long ret;

	if (!client_sec || !accepted_sec || !client_token)
		return -EACCES;

	ret = pkm_kacs_create_captured_peer_token(client_token,
						  client_sec->max_impersonation,
						  &peer_token);
	if (ret)
		return ret;
	if (!peer_token)
		return -EACCES;

	pkm_kacs_socket_peer_token_drop(accepted_sec);
	accepted_sec->peer_token = peer_token;
	return 0;
}

static long pkm_kacs_bind_abstract_socket_core(
	struct pkm_kacs_socket_security *sec, const void *subject_token)
{
	struct pkm_kacs_process_sd *socket_sd;
	struct pkm_kacs_process_sd *prev;

	if (!sec || !subject_token)
		return -EACCES;
	/* Fast path: already installed, no allocation needed. */
	if (READ_ONCE(sec->socket_sd))
		return 0;

	socket_sd = pkm_kacs_socket_sd_alloc(subject_token);
	if (!socket_sd)
		return -ENOMEM;

	/*
	 * KC-02: two threads sharing one socket fd can both pass the NULL check
	 * and both allocate. Install atomically; if another thread won the race,
	 * drop our loser allocation rather than overwrite (and leak) the winner.
	 */
	prev = cmpxchg(&sec->socket_sd, NULL, socket_sd);
	if (prev)
		pkm_kacs_process_sd_put(socket_sd);
	return 0;
}

static long pkm_kacs_unix_stream_connect_core(
	const struct pkm_kacs_socket_security *client_sec,
	const struct pkm_kacs_socket_security *server_sec,
	struct pkm_kacs_socket_security *accepted_sec,
	const void *client_token)
{
	long ret;

	if (!client_sec || !server_sec || !accepted_sec || !client_token)
		return -EACCES;

	if (server_sec->socket_sd) {
		ret = pkm_kacs_authorize_socket_sd_access(
			client_token, server_sec->socket_sd,
			PKM_KACS_SOCKET_FILE_WRITE_DATA);
		if (ret)
			return ret;
	}

	return pkm_kacs_capture_peer_token_core(client_sec, accepted_sec,
						client_token);
}

static long pkm_kacs_unix_may_send_core(
	const struct pkm_kacs_socket_security *target_sec,
	const void *subject_token)
{
	if (!target_sec)
		return -EACCES;
	if (!target_sec->socket_sd)
		return 0;

	return pkm_kacs_authorize_socket_sd_access(
		subject_token, target_sec->socket_sd,
		PKM_KACS_SOCKET_FILE_WRITE_DATA);
}

static long pkm_kacs_set_socket_impersonation_level_core(
	struct socket *sock, struct pkm_kacs_socket_security *sec, u32 level)
{
	if (!sock || !sock->sk || !sec) {
		trace_kacs_socket_set_imp_level(0, 0, 0, level, 0,
						KACS_SOCK_BAD_ARGS, -EACCES);
		return -EACCES;
	}
	if (sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_socket_type_supported(sock->type)) {
		trace_kacs_socket_set_imp_level(sock->sk->sk_family, sock->type,
						sock->state, level, 0,
						KACS_SOCK_NOT_UNIX, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	if (!pkm_kacs_socket_level_valid(level)) {
		trace_kacs_socket_set_imp_level(sock->sk->sk_family, sock->type,
						sock->state, level, 0,
						KACS_SOCK_BAD_LEVEL, -EINVAL);
		return -EINVAL;
	}
	if (sock->state != SS_UNCONNECTED || sec->peer_token) {
		trace_kacs_socket_set_imp_level(sock->sk->sk_family, sock->type,
						sock->state, level, 0,
						KACS_SOCK_WRONG_STATE, -EISCONN);
		return -EISCONN;
	}

	sec->max_impersonation = level;
	trace_kacs_socket_set_imp_level(sock->sk->sk_family, sock->type,
					sock->state, level, 0,
					KACS_SOCK_LEVEL_SET, 0);
	return 0;
}

static long pkm_kacs_open_peer_token_core(
	const struct pkm_kacs_socket_security *sec)
{
	long ret;

	if (!sec || !sec->peer_token) {
		trace_kacs_socket_open_peer_token(
			0, 0, 0, 0, PKM_KACS_PEER_TOKEN_ACCESS_MASK,
			KACS_SOCK_NO_PEER_TOKEN, -EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_open_token_fd_with_fixed_access(
		sec->peer_token, PKM_KACS_PEER_TOKEN_ACCESS_MASK);
	trace_kacs_socket_open_peer_token(
		0, 0, 0, sec->max_impersonation,
		PKM_KACS_PEER_TOKEN_ACCESS_MASK, KACS_SOCK_OPEN_TOKEN, ret);
	return ret;
}

int pkm_kacs_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct pkm_kacs_socket_security *sec;

	(void)family;
	(void)priority;
	if (!sk || !sk->sk_security)
		return -EACCES;

	sec = pkm_kacs_sock(sk);
	sec->peer_token = NULL;
	sec->socket_sd = NULL;
	sec->max_impersonation = KACS_IMLEVEL_IMPERSONATION;
	return 0;
}

void pkm_kacs_sk_free_security(struct sock *sk)
{
	struct pkm_kacs_socket_security *sec;

	if (!sk || !sk->sk_security)
		return;

	sec = pkm_kacs_sock(sk);
	pkm_kacs_socket_peer_token_drop(sec);
	pkm_kacs_process_sd_put(sec->socket_sd);
	sec->socket_sd = NULL;
	sec->max_impersonation = KACS_IMLEVEL_IMPERSONATION;
}

int pkm_kacs_socket_bind(struct socket *sock, struct sockaddr *address,
			 int addrlen)
{
	struct pkm_kacs_socket_security *sec;
	const void *subject_token;
	long ret;

	if (!sock || !sock->sk) {
		trace_kacs_socket_bind(0, 0, 0, 0, 0, KACS_SOCK_BAD_ARGS,
				       -EACCES);
		return -EACCES;
	}
	if (sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_sockaddr_is_abstract_unix(address, addrlen))
		return 0;

	sec = pkm_kacs_sock(sock->sk);
	if (!sec) {
		trace_kacs_socket_bind(sock->sk->sk_family, sock->type,
				       sock->state, 0, 0,
				       KACS_SOCK_NO_SECURITY, -EACCES);
		return -EACCES;
	}
	if (sec->socket_sd) {
		trace_kacs_socket_bind(sock->sk->sk_family, sock->type,
				       sock->state, sec->max_impersonation, 0,
				       KACS_SOCK_ALREADY_BOUND, 0);
		return 0;
	}

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token) {
		trace_kacs_socket_bind(sock->sk->sk_family, sock->type,
				       sock->state, sec->max_impersonation, 0,
				       KACS_SOCK_NO_TOKEN, -EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_bind_abstract_socket_core(sec, subject_token);
	trace_kacs_socket_bind(sock->sk->sk_family, sock->type, sock->state,
			       sec->max_impersonation, 0, KACS_SOCK_BIND, ret);
	return ret;
}

int pkm_kacs_unix_stream_connect(struct sock *sock,
				 struct sock *other,
				 struct sock *newsk)
{
	struct pkm_kacs_socket_security *client_sec;
	struct pkm_kacs_socket_security *server_sec;
	struct pkm_kacs_socket_security *accepted_sec;
	const void *client_token;
	long ret;

	if (!sock || !other || !newsk) {
		trace_kacs_socket_unix_connect(
			0, 0, 0, 0, PKM_KACS_SOCKET_FILE_WRITE_DATA,
			KACS_SOCK_BAD_ARGS, -EACCES);
		return -EACCES;
	}
	if (sock->sk_family != AF_UNIX || other->sk_family != AF_UNIX ||
	    newsk->sk_family != AF_UNIX) {
		trace_kacs_socket_unix_connect(
			sock->sk_family, sock->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NOT_UNIX,
			-EACCES);
		return -EACCES;
	}
	if (!pkm_kacs_socket_type_supported(sock->sk_type)) {
		trace_kacs_socket_unix_connect(
			sock->sk_family, sock->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NOT_UNIX,
			-EACCES);
		return -EACCES;
	}
	if (!sock->sk_security || !other->sk_security || !newsk->sk_security) {
		trace_kacs_socket_unix_connect(
			sock->sk_family, sock->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NO_SECURITY,
			-EACCES);
		return -EACCES;
	}

	client_sec = pkm_kacs_sock(sock);
	server_sec = pkm_kacs_sock(other);
	accepted_sec = pkm_kacs_sock(newsk);
	client_token = pkm_kacs_current_effective_token_ptr();
	if (!client_sec || !server_sec || !accepted_sec || !client_token) {
		trace_kacs_socket_unix_connect(
			sock->sk_family, sock->sk_type, 0,
			client_sec ? client_sec->max_impersonation : 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NO_TOKEN,
			-EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_unix_stream_connect_core(client_sec, server_sec,
						accepted_sec, client_token);
	trace_kacs_socket_unix_connect(sock->sk_family, sock->sk_type, 0,
				       client_sec->max_impersonation,
				       PKM_KACS_SOCKET_FILE_WRITE_DATA,
				       KACS_SOCK_CONNECT, ret);
	return ret;
}

int pkm_kacs_unix_may_send(struct socket *sock, struct socket *other)
{
	struct pkm_kacs_socket_security *target_sec;
	const void *subject_token;
	long ret;

	if (!sock || !other || !sock->sk || !other->sk) {
		trace_kacs_socket_unix_may_send(
			0, 0, 0, 0, PKM_KACS_SOCKET_FILE_WRITE_DATA,
			KACS_SOCK_BAD_ARGS, -EACCES);
		return -EACCES;
	}
	if (sock->sk->sk_family != AF_UNIX || other->sk->sk_family != AF_UNIX) {
		trace_kacs_socket_unix_may_send(
			sock->sk->sk_family, sock->sk->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NOT_UNIX,
			-EACCES);
		return -EACCES;
	}
	if (!sock->sk->sk_security || !other->sk->sk_security) {
		trace_kacs_socket_unix_may_send(
			sock->sk->sk_family, sock->sk->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NO_SECURITY,
			-EACCES);
		return -EACCES;
	}

	target_sec = pkm_kacs_sock(other->sk);
	if (!target_sec) {
		trace_kacs_socket_unix_may_send(
			sock->sk->sk_family, sock->sk->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NO_SECURITY,
			-EACCES);
		return -EACCES;
	}
	if (!target_sec->socket_sd) {
		trace_kacs_socket_unix_may_send(
			sock->sk->sk_family, sock->sk->sk_type, 0, 0,
			PKM_KACS_SOCKET_FILE_WRITE_DATA, KACS_SOCK_NO_SD, 0);
		return 0;
	}

	subject_token = pkm_kacs_current_effective_token_ptr();
	ret = pkm_kacs_unix_may_send_core(target_sec, subject_token);
	trace_kacs_socket_unix_may_send(sock->sk->sk_family, sock->sk->sk_type,
					0, 0, PKM_KACS_SOCKET_FILE_WRITE_DATA,
					KACS_SOCK_HAVE_SD, ret);
	return ret;
}

/*
 * SOL_KACS option handlers, reached from net/socket.c ahead of the
 * protocol's own setsockopt/getsockopt. optval/optlen are sockptrs so the
 * same entry serves user and kernel (KUnit) callers.
 */
static long pkm_kacs_sockopt_socket(struct socket *sock,
				    struct pkm_kacs_socket_security **sec_out)
{
	if (!sock || !sock->sk || !sock->sk->sk_security)
		return -EACCES;
	if (sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_socket_type_supported(sock->type))
		return -EOPNOTSUPP;

	*sec_out = pkm_kacs_sock(sock->sk);
	return 0;
}

int pkm_kacs_sock_setsockopt(struct socket *sock, int optname,
			     sockptr_t optval, unsigned int optlen)
{
	struct pkm_kacs_socket_security *sec;
	u32 level;
	long ret;

	if (optname != KACS_SO_IMPERSONATION_LEVEL)
		return -ENOPROTOOPT;
	if (optlen < sizeof(level))
		return -EINVAL;
	if (copy_from_sockptr(&level, optval, sizeof(level)))
		return -EFAULT;

	ret = pkm_kacs_sockopt_socket(sock, &sec);
	if (ret)
		return ret;

	return pkm_kacs_set_socket_impersonation_level_core(sock, sec, level);
}

static int pkm_kacs_sockopt_put(sockptr_t optval, sockptr_t optlen,
				const void *val, int len)
{
	if (copy_to_sockptr(optval, val, len))
		return -EFAULT;
	if (copy_to_sockptr(optlen, &len, sizeof(len)))
		return -EFAULT;
	return 0;
}

int pkm_kacs_sock_getsockopt(struct socket *sock, int optname,
			     sockptr_t optval, sockptr_t optlen)
{
	struct pkm_kacs_socket_security *sec;
	int len;
	long ret;

	if (copy_from_sockptr(&len, optlen, sizeof(len)))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case KACS_SO_PEER_TOKEN: {
		int fd;

		if (len < sizeof(fd))
			return -EINVAL;
		ret = pkm_kacs_sockopt_socket(sock, &sec);
		if (ret)
			return ret;
		if (sock->state != SS_CONNECTED)
			return -ENOTCONN;
		if (!sec->peer_token)
			return -ENODATA;

		ret = pkm_kacs_open_peer_token_core(sec);
		if (ret < 0)
			return ret;
		fd = ret;
		ret = pkm_kacs_sockopt_put(optval, optlen, &fd, sizeof(fd));
		if (ret)
			close_fd(fd);
		return ret;
	}
	case KACS_SO_IMPERSONATION_LEVEL: {
		u32 level;

		if (len < sizeof(level))
			return -EINVAL;
		ret = pkm_kacs_sockopt_socket(sock, &sec);
		if (ret)
			return ret;
		level = sec->max_impersonation;
		return pkm_kacs_sockopt_put(optval, optlen, &level,
					    sizeof(level));
	}
	default:
		return -ENOPROTOOPT;
	}
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static struct pkm_kacs_process_sd *pkm_kacs_kunit_read_only_socket_sd_alloc(
	const void *token)
{
	struct pkm_kacs_process_sd *socket_sd;
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_kunit_create_read_only_socket_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	socket_sd = kzalloc(sizeof(*socket_sd), GFP_KERNEL);
	if (!socket_sd) {
		pkm_kacs_free((void *)bytes);
		return NULL;
	}

	refcount_set(&socket_sd->refs, 1);
	socket_sd->bytes = bytes;
	socket_sd->len = len;
	return socket_sd;
}

static void pkm_kacs_kunit_socket_snapshot(
	const struct pkm_kacs_socket_security *sec,
	struct pkm_kacs_kunit_socket_view *out)
{
	if (!out)
		return;

	out->peer_token = sec ? sec->peer_token : NULL;
	out->socket_sd_ptr = sec && sec->socket_sd ? sec->socket_sd->bytes : NULL;
	out->socket_sd_len = sec && sec->socket_sd ? sec->socket_sd->len : 0;
	out->max_impersonation = sec ? sec->max_impersonation : 0;
}

static int pkm_kacs_kunit_init_socket(struct socket *sock, struct sock *sk,
				      void **blob_out, u32 socket_type,
				      u32 connected)
{
	size_t blob_len;
	void *blob;

	if (!sock || !sk || !blob_out)
		return -EINVAL;

	blob_len = pkm_blob_sizes.lbs_sock +
		sizeof(struct pkm_kacs_socket_security);
	blob = kzalloc(blob_len, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	memset(sock, 0, sizeof(*sock));
	memset(sk, 0, sizeof(*sk));

	sk->sk_family = AF_UNIX;
	sk->sk_type = socket_type;
	sk->sk_security = blob;

	sock->type = socket_type;
	sock->state = connected ? SS_CONNECTED : SS_UNCONNECTED;
	sock->sk = sk;

	*blob_out = blob;
	return pkm_kacs_sk_alloc_security(sk, AF_UNIX, GFP_KERNEL);
}

static void pkm_kacs_kunit_cleanup_socket(struct sock *sk, void *blob)
{
	pkm_kacs_sk_free_security(sk);
	kfree(blob);
}

struct pkm_kacs_kunit_peer_capture_state {
	struct socket client_sock;
	struct socket listener_sock;
	struct socket accepted_sock;
	struct sock client_sk;
	struct sock listener_sk;
	struct sock accepted_sk;
	void *client_blob;
	void *listener_blob;
	void *accepted_blob;
};

long pkm_kacs_kunit_bind_abstract_socket_for_subject(
	const void *subject_token,
	struct pkm_kacs_kunit_socket_view *first_out,
	struct pkm_kacs_kunit_socket_view *second_out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	if (!subject_token)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM, 0);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);

	ret = pkm_kacs_bind_abstract_socket_core(sec, subject_token);
	pkm_kacs_kunit_socket_snapshot(sec, first_out);
	if (ret) {
		pkm_kacs_kunit_cleanup_socket(&sk, blob);
		return ret;
	}

	ret = pkm_kacs_bind_abstract_socket_core(sec, subject_token);
	pkm_kacs_kunit_socket_snapshot(sec, second_out);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_bind_abstract_socket_sd_for_subject(
	const void *subject_token, const u8 **sd_out, size_t *sd_len_out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	const u8 *copy;
	long ret;

	if (!subject_token || !sd_out || !sd_len_out)
		return -EINVAL;
	*sd_out = NULL;
	*sd_len_out = 0;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM, 0);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);

	ret = pkm_kacs_bind_abstract_socket_core(sec, subject_token);
	if (ret)
		goto out;
	if (!sec->socket_sd || !sec->socket_sd->bytes || !sec->socket_sd->len) {
		ret = -EACCES;
		goto out;
	}

	copy = kmemdup(sec->socket_sd->bytes, sec->socket_sd->len, GFP_KERNEL);
	if (!copy) {
		ret = -ENOMEM;
		goto out;
	}

	*sd_out = copy;
	*sd_len_out = sec->socket_sd->len;
out:
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_set_socket_impersonation_level(
	u32 socket_type, u32 connected, u32 level,
	struct pkm_kacs_kunit_socket_view *out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);

	ret = pkm_kacs_sock_setsockopt(&sock, KACS_SO_IMPERSONATION_LEVEL,
				       KERNEL_SOCKPTR(&level), sizeof(level));
	pkm_kacs_kunit_socket_snapshot(sec, out);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_capture_peer_socket_for_subject(
	const void *client_token, u32 socket_type, u32 max_impersonation,
	u32 abstract_socket, u32 allow_write, const void **captured_token_out,
	struct pkm_kacs_kunit_socket_view *listener_out,
	struct pkm_kacs_kunit_socket_view *accepted_out)
{
	struct pkm_kacs_kunit_peer_capture_state *state;
	struct pkm_kacs_socket_security *client_sec;
	struct pkm_kacs_socket_security *listener_sec;
	struct pkm_kacs_socket_security *accepted_sec;
	const void *bind_token;
	long ret;

	if (captured_token_out)
		*captured_token_out = NULL;
	if (!client_token)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_socket(&state->client_sock, &state->client_sk,
					 &state->client_blob, socket_type, 0);
	if (ret)
		goto out_free_state;
	ret = pkm_kacs_kunit_init_socket(&state->listener_sock,
					 &state->listener_sk,
					 &state->listener_blob, socket_type, 0);
	if (ret)
		goto out;
	ret = pkm_kacs_kunit_init_socket(&state->accepted_sock,
					 &state->accepted_sk,
					 &state->accepted_blob, socket_type, 1);
	if (ret)
		goto out;
	client_sec = pkm_kacs_sock(&state->client_sk);
	listener_sec = pkm_kacs_sock(&state->listener_sk);
	accepted_sec = pkm_kacs_sock(&state->accepted_sk);

	ret = pkm_kacs_set_socket_impersonation_level_core(&state->client_sock,
							    client_sec,
							    max_impersonation);
	if (ret)
		goto out;

	if (abstract_socket) {
		bind_token = pkm_kacs_current_effective_token_ptr();
		if (!bind_token) {
			ret = -EACCES;
			goto out;
		}
		if (allow_write) {
			ret = pkm_kacs_bind_abstract_socket_core(listener_sec,
								 bind_token);
			if (ret)
				goto out;
		} else {
			listener_sec->socket_sd =
				pkm_kacs_kunit_read_only_socket_sd_alloc(
					bind_token);
			if (!listener_sec->socket_sd) {
				ret = -ENOMEM;
				goto out;
			}
		}
	}

	ret = pkm_kacs_unix_stream_connect_core(client_sec, listener_sec,
						accepted_sec, client_token);
	if (ret)
		goto out;

	if (captured_token_out) {
		*captured_token_out =
			kacs_rust_token_clone(accepted_sec->peer_token);
		if (!*captured_token_out) {
			ret = -EACCES;
			goto out;
		}
	}

out:
	pkm_kacs_kunit_socket_snapshot(state->listener_blob ?
				       pkm_kacs_sock(&state->listener_sk) : NULL,
				       listener_out);
	pkm_kacs_kunit_socket_snapshot(state->accepted_blob ?
				       pkm_kacs_sock(&state->accepted_sk) : NULL,
				       accepted_out);
	if (state->accepted_blob)
		pkm_kacs_kunit_cleanup_socket(&state->accepted_sk,
					      state->accepted_blob);
	if (state->listener_blob)
		pkm_kacs_kunit_cleanup_socket(&state->listener_sk,
					      state->listener_blob);
	if (state->client_blob)
		pkm_kacs_kunit_cleanup_socket(&state->client_sk,
					      state->client_blob);
out_free_state:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_unix_dgram_send_for_subject(
	const void *subject_token, u32 abstract_socket, u32 allow_write,
	struct pkm_kacs_kunit_socket_view *sender_out,
	struct pkm_kacs_kunit_socket_view *target_out)
{
	struct socket sender_sock;
	struct socket target_sock;
	struct sock sender_sk;
	struct sock target_sk;
	struct pkm_kacs_socket_security *target_sec;
	void *sender_blob = NULL;
	void *target_blob = NULL;
	long ret;

	if (!subject_token)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_socket(&sender_sock, &sender_sk,
					 &sender_blob, SOCK_DGRAM, 0);
	if (ret)
		return ret;

	ret = pkm_kacs_kunit_init_socket(&target_sock, &target_sk,
					 &target_blob, SOCK_DGRAM, 0);
	if (ret)
		goto out_sender;

	target_sec = pkm_kacs_sock(&target_sk);
	if (abstract_socket) {
		if (allow_write) {
			ret = pkm_kacs_bind_abstract_socket_core(target_sec,
								 subject_token);
			if (ret)
				goto out_target;
		} else {
			target_sec->socket_sd =
				pkm_kacs_kunit_read_only_socket_sd_alloc(
					subject_token);
			if (!target_sec->socket_sd) {
				ret = -ENOMEM;
				goto out_target;
			}
		}
	}

	ret = pkm_kacs_unix_may_send(&sender_sock, &target_sock);

out_target:
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&sender_sk), sender_out);
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&target_sk), target_out);
	pkm_kacs_kunit_cleanup_socket(&target_sk, target_blob);
out_sender:
	pkm_kacs_kunit_cleanup_socket(&sender_sk, sender_blob);
	return ret;
}

long pkm_kacs_kunit_open_peer_token_for_socket_type(u32 socket_type,
						    u32 connected,
						    const void *peer_token)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	int fd = -1;
	int len = sizeof(fd);
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (connected && pkm_kacs_socket_type_supported(socket_type) &&
	    peer_token)
		sec->peer_token = kacs_rust_token_clone(peer_token);
	ret = pkm_kacs_sock_getsockopt(&sock, KACS_SO_PEER_TOKEN,
				       KERNEL_SOCKPTR(&fd), KERNEL_SOCKPTR(&len));
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret ? ret : fd;
}

long pkm_kacs_kunit_open_peer_token_for_socket(u32 connected,
					       const void *peer_token)
{
	return pkm_kacs_kunit_open_peer_token_for_socket_type(
		SOCK_STREAM, connected, peer_token);
}

long pkm_kacs_kunit_impersonate_peer_for_socket_type(u32 socket_type,
						     u32 connected,
						     const void *peer_token)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	int fd = -1;
	int len = sizeof(fd);
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (connected && pkm_kacs_socket_type_supported(socket_type) &&
	    peer_token)
		sec->peer_token = kacs_rust_token_clone(peer_token);
	ret = pkm_kacs_sock_getsockopt(&sock, KACS_SO_PEER_TOKEN,
				       KERNEL_SOCKPTR(&fd), KERNEL_SOCKPTR(&len));
	if (!ret) {
		ret = pkm_kacs_impersonate_token_for_current(sec->peer_token);
		close_fd(fd);
	}
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_impersonate_peer_for_socket(u32 connected,
						const void *peer_token)
{
	return pkm_kacs_kunit_impersonate_peer_for_socket_type(
		SOCK_STREAM, connected, peer_token);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */
