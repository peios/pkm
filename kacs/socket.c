// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/sockptr.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/un.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/peios_pnp.h>
#include <linux/sched.h>

#include <net/scm.h>
#include <net/sock.h>

#include <pkm/net.h>
#include <pkm/socket.h>

#include "lsm_internal.h"
#include "process_state.h"
#include "socket.h"
#include "token_fd.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

#define PKM_KACS_SOCKET_FILE_WRITE_DATA 0x00000002U
#define PKM_KACS_PEER_TOKEN_ACCESS_MASK \
	(KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE | KACS_TOKEN_DUPLICATE)

static long pkm_kacs_create_captured_peer_token(
	const void *client_token, u32 max_impersonation,
	const void **out_token);
static void pkm_kacs_binder_set(struct pkm_kacs_socket_security *sec,
				const void *token);
static void pkm_kacs_socket_owner_set(struct pkm_kacs_socket_security *sec,
				      const void *token, u8 kind,
				      const u8 *guid, s32 pid,
				      const char *comm);

/*
 * The conveyed-identity register. Readers clone under the lock; a writer
 * swaps under the lock and drops the old reference outside it.
 */
static const void *pkm_kacs_register_clone(struct pkm_kacs_socket_security *sec)
{
	const void *token;

	spin_lock(&sec->register_lock);
	token = sec->peer_token ? kacs_rust_token_clone(sec->peer_token) : NULL;
	spin_unlock(&sec->register_lock);
	return token;
}

/* Installs @token (a counted reference, consumed) as the register. */
static void pkm_kacs_register_set(struct pkm_kacs_socket_security *sec,
				  const void *token)
{
	const void *old;

	spin_lock(&sec->register_lock);
	old = sec->peer_token;
	sec->peer_token = token;
	spin_unlock(&sec->register_lock);
	if (old)
		kacs_rust_token_drop(old);
}

static void pkm_kacs_socket_peer_token_drop(struct pkm_kacs_socket_security *sec)
{
	if (!sec)
		return;
	pkm_kacs_register_set(sec, NULL);
}

/* Installs @token (counted, consumed) as the listener's conveyed identity. */
static void pkm_kacs_listener_set(struct pkm_kacs_socket_security *sec,
				  const void *token)
{
	const void *old;

	spin_lock(&sec->register_lock);
	old = sec->listener_token;
	sec->listener_token = token;
	spin_unlock(&sec->register_lock);
	if (old)
		kacs_rust_token_drop(old);
}

static const void *pkm_kacs_listener_clone(struct pkm_kacs_socket_security *sec)
{
	const void *token;

	spin_lock(&sec->register_lock);
	token = sec->listener_token ?
		kacs_rust_token_clone(sec->listener_token) : NULL;
	spin_unlock(&sec->register_lock);
	return token;
}

/*
 * Captures the caller's effective identity as what a listener conveys to
 * connecting clients. Identification unless the listener chose a level —
 * clients verify servers; they do not collect impersonation-grade tokens
 * on them by default.
 */
static long pkm_kacs_listener_stamp(struct pkm_kacs_socket_security *sec)
{
	const void *effective, *token = NULL;
	u32 level;
	long ret;

	effective = pkm_kacs_current_effective_token_ptr();
	if (!effective)
		return -EACCES;
	level = READ_ONCE(sec->level_set) ? READ_ONCE(sec->max_impersonation) :
					    KACS_IMLEVEL_IDENTIFICATION;
	ret = pkm_kacs_create_captured_peer_token(effective, level, &token);
	if (ret)
		return ret;
	if (!token)
		return -EACCES;
	pkm_kacs_listener_set(sec, token);
	return 0;
}

static void pkm_kacs_socket_convey_drop(struct pkm_kacs_socket_security *sec)
{
	const void *src, *token;

	mutex_lock(&sec->convey_lock);
	src = sec->convey_src;
	token = sec->convey_token;
	sec->convey_src = NULL;
	sec->convey_token = NULL;
	mutex_unlock(&sec->convey_lock);
	if (src)
		kacs_rust_token_drop(src);
	if (token)
		kacs_rust_token_drop(token);
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

	pkm_kacs_register_set(accepted_sec, peer_token);
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
	struct pkm_kacs_socket_security *client_sec,
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

	ret = pkm_kacs_capture_peer_token_core(client_sec, accepted_sec,
					       client_token);
	if (ret)
		return ret;

	/* The connecting end learns who is listening, symmetrically. */
	pkm_kacs_register_set(client_sec,
			      pkm_kacs_listener_clone(
				      (struct pkm_kacs_socket_security *)server_sec));
	return 0;
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
	if (sock->sk->sk_family != AF_UNIX) {
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
	WRITE_ONCE(sec->max_impersonation, level);
	WRITE_ONCE(sec->level_set, true);
	trace_kacs_socket_set_imp_level(sock->sk->sk_family, sock->type,
					sock->state, level, 0,
					KACS_SOCK_LEVEL_SET, 0);
	return 0;
}

static long pkm_kacs_open_peer_token_core(struct pkm_kacs_socket_security *sec)
{
	const void *token;
	long ret;

	token = sec ? pkm_kacs_register_clone(sec) : NULL;
	if (!token) {
		trace_kacs_socket_open_peer_token(
			0, 0, 0, 0, PKM_KACS_PEER_TOKEN_ACCESS_MASK,
			KACS_SOCK_NO_PEER_TOKEN, -ENODATA);
		return -ENODATA;
	}

	ret = pkm_kacs_open_token_fd_with_fixed_access(
		token, PKM_KACS_PEER_TOKEN_ACCESS_MASK);
	kacs_rust_token_drop(token);
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
	spin_lock_init(&sec->register_lock);
	sec->socket_sd = NULL;
	sec->max_impersonation = KACS_IMLEVEL_IMPERSONATION;
	sec->pass_token = false;
	sec->level_set = false;
	sec->listener_token = NULL;
	sec->binder_token = NULL;
	sec->rebind_tcb = false;
	mutex_init(&sec->convey_lock);
	sec->convey_src = NULL;
	sec->convey_token = NULL;
	sec->convey_level = 0;
	spin_lock_init(&sec->owner_lock);
	sec->owner_token = NULL;
	sec->owner_kind = PEIOS_PNP_OWNER_UNSTAMPED;
	memset(sec->owner_guid, 0, sizeof(sec->owner_guid));
	sec->owner_pid = 0;
	sec->owner_comm[0] = '\0';
	return 0;
}

void pkm_kacs_sk_free_security(struct sock *sk)
{
	struct pkm_kacs_socket_security *sec;

	if (!sk || !sk->sk_security)
		return;

	sec = pkm_kacs_sock(sk);
	pkm_kacs_socket_peer_token_drop(sec);
	pkm_kacs_listener_set(sec, NULL);
	pkm_kacs_binder_set(sec, NULL);
	sec->rebind_tcb = false;
	pkm_kacs_socket_owner_set(sec, NULL, PEIOS_PNP_OWNER_UNSTAMPED, NULL, 0,
				  NULL);
	pkm_kacs_socket_convey_drop(sec);
	pkm_kacs_process_sd_put(sec->socket_sd);
	sec->socket_sd = NULL;
	sec->max_impersonation = KACS_IMLEVEL_IMPERSONATION;
	sec->pass_token = false;
}

/* Installs @token (counted, consumed) as the socket's recorded binder. */
static void pkm_kacs_binder_set(struct pkm_kacs_socket_security *sec,
				const void *token)
{
	const void *old;

	spin_lock(&sec->register_lock);
	old = sec->binder_token;
	sec->binder_token = token;
	spin_unlock(&sec->register_lock);
	if (old)
		kacs_rust_token_drop(old);
}

/* ---- the governing identity (net/pnp's Local.* facts) ---- */

static bool pkm_kacs_socket_family_inet(int family)
{
	return family == AF_INET || family == AF_INET6;
}

/*
 * Installs @token (counted, consumed) and the process facts as the
 * socket's governing identity. NULL fields clear. The old reference is
 * dropped outside the lock.
 */
static void pkm_kacs_socket_owner_set(struct pkm_kacs_socket_security *sec,
				      const void *token, u8 kind,
				      const u8 *guid, s32 pid,
				      const char *comm)
{
	const void *old;

	spin_lock_bh(&sec->owner_lock);
	old = sec->owner_token;
	sec->owner_token = token;
	sec->owner_kind = kind;
	if (guid)
		memcpy(sec->owner_guid, guid, sizeof(sec->owner_guid));
	else
		memset(sec->owner_guid, 0, sizeof(sec->owner_guid));
	sec->owner_pid = pid;
	if (comm)
		strscpy(sec->owner_comm, comm, sizeof(sec->owner_comm));
	else
		sec->owner_comm[0] = '\0';
	spin_unlock_bh(&sec->owner_lock);
	if (old)
		kacs_rust_token_drop(old);
}

/*
 * Stamps the caller as the socket's governing identity: the effective
 * token (impersonation attributes the socket to the client, as audit
 * does) and the process facts of this moment. A kernel socket is stamped
 * as the kernel's, with no token. Process context only; the accept path
 * inherits instead (pkm_kacs_sk_clone_security).
 */
static void pkm_kacs_socket_stamp_owner(struct pkm_kacs_socket_security *sec,
					bool kern, u16 family, u16 type,
					u8 state)
{
	const struct pkm_kacs_process_state *pstate;
	const void *effective = NULL, *token = NULL;
	char comm[TASK_COMM_LEN];
	u8 kind = PEIOS_PNP_OWNER_KERNEL;
	const u8 *guid = NULL;
	s32 pid = 0;

	get_task_comm(comm, current);
	if (!kern) {
		effective = pkm_kacs_current_effective_token_ptr();
		if (effective) {
			token = kacs_rust_token_clone(effective);
			pstate = pkm_kacs_current_process_state();
			guid = pstate ? pstate->process_guid : NULL;
			pid = task_tgid_nr(current);
			kind = token ? PEIOS_PNP_OWNER_PROGRAM :
				       PEIOS_PNP_OWNER_UNSTAMPED;
		} else {
			/* A task with no token: nothing to attribute to. */
			kind = PEIOS_PNP_OWNER_UNSTAMPED;
		}
	}
	pkm_kacs_socket_owner_set(sec, token, kind, guid, pid, comm);
	trace_kacs_socket_token(family, type, state, kind, 0, KACS_SOCK_OWNER,
				0);
}

int pkm_kacs_socket_owner(const struct sock *sk, struct peios_pnp_owner *out)
{
	struct pkm_kacs_socket_security *sec;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->kind = PEIOS_PNP_OWNER_UNSTAMPED;
	if (!sk || !sk->sk_security)
		return -ENOENT;
	sec = pkm_kacs_sock(sk);
	spin_lock_bh(&sec->owner_lock);
	out->token = sec->owner_token ? kacs_rust_token_clone(sec->owner_token) :
					NULL;
	out->kind = sec->owner_kind;
	memcpy(out->guid, sec->owner_guid, sizeof(out->guid));
	out->pid = sec->owner_pid;
	strscpy(out->comm, sec->owner_comm, sizeof(out->comm));
	spin_unlock_bh(&sec->owner_lock);
	return 0;
}

void pkm_kacs_socket_owner_put(struct peios_pnp_owner *owner)
{
	if (!owner || !owner->token)
		return;
	kacs_rust_token_drop(owner->token);
	owner->token = NULL;
}

/* An accepted socket inherits its listener's governing identity. */
void pkm_kacs_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	struct pkm_kacs_socket_security *parent, *child;
	struct peios_pnp_owner owner;

	if (!sk || !newsk || !sk->sk_security || !newsk->sk_security)
		return;
	if (!pkm_kacs_socket_family_inet(sk->sk_family))
		return;
	parent = pkm_kacs_sock(sk);
	child = pkm_kacs_sock(newsk);
	spin_lock_bh(&parent->owner_lock);
	owner.token = parent->owner_token ?
		kacs_rust_token_clone(parent->owner_token) : NULL;
	owner.kind = parent->owner_kind;
	memcpy(owner.guid, parent->owner_guid, sizeof(owner.guid));
	owner.pid = parent->owner_pid;
	strscpy(owner.comm, parent->owner_comm, sizeof(owner.comm));
	spin_unlock_bh(&parent->owner_lock);
	pkm_kacs_socket_owner_set(child, owner.token, owner.kind, owner.guid,
				  owner.pid, owner.comm);
}

/* Creation: the first stamp. Kernel sockets are the kernel's. */
int pkm_kacs_socket_post_create(struct socket *sock, int family, int type,
				int protocol, int kern)
{
	(void)protocol;
	if (!sock || !sock->sk || !sock->sk->sk_security)
		return 0;
	if (!pkm_kacs_socket_family_inet(family))
		return 0;
	pkm_kacs_socket_stamp_owner(pkm_kacs_sock(sock->sk), kern != 0, family,
				    type, sock->state);
	return 0;
}

/* connect(2) commits the socket to a role: the caller governs it. */
int pkm_kacs_socket_connect(struct socket *sock, struct sockaddr *address,
			    int addrlen)
{
	(void)address;
	(void)addrlen;
	if (!sock || !sock->sk || !sock->sk->sk_security)
		return 0;
	if (!pkm_kacs_socket_family_inet(sock->sk->sk_family))
		return 0;
	pkm_kacs_socket_stamp_owner(pkm_kacs_sock(sock->sk), false,
				    sock->sk->sk_family, sock->type,
				    sock->state);
	return 0;
}

/*
 * The port a bind(2) claims, in host order, or 0 when the address names no
 * port (ephemeral allocation) or is too short to carry one.
 */
static u16 pkm_kacs_inet_bind_port(const struct sockaddr *address, int addrlen)
{
	if (!address)
		return 0;
	if (address->sa_family == AF_INET) {
		const struct sockaddr_in *sin =
			(const struct sockaddr_in *)address;

		if (addrlen < (int)sizeof(*sin))
			return 0;
		return ntohs(sin->sin_port);
	}
	if (address->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)address;

		/* The RFC 2133 length: everything up to and including the address. */
		if (addrlen < (int)offsetofend(struct sockaddr_in6, sin6_addr))
			return 0;
		return ntohs(sin6->sin6_port);
	}
	return 0;
}

/* The reservation protocol bit for an inet socket, or 0 if none applies. */
static u32 pkm_kacs_inet_bind_protocol(const struct sock *sk)
{
	switch (sk->sk_protocol) {
	case IPPROTO_TCP:
		return KACS_PORT_PROTO_TCP;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		return KACS_PORT_PROTO_UDP;
	default:
		return 0;
	}
}

/*
 * Port reservation check for AF_INET / AF_INET6 (<pkm/net.h>). The caller's
 * effective token is evaluated for KACS_PORT_BIND against the most specific
 * reservation containing (protocol, port). Port 0 and protocols no
 * reservation covers pass untouched. A permitted binder is recorded on the
 * socket for the rebind rule.
 */
static int pkm_kacs_inet_bind(struct socket *sock,
			      const struct sockaddr *address, int addrlen)
{
	struct pkm_kacs_socket_security *sec;
	const void *subject_token;
	const void *binder;
	u32 pip_type = 0, pip_trust = 0;
	u32 protocol;
	u16 port;
	long ret;

	protocol = pkm_kacs_inet_bind_protocol(sock->sk);
	if (!protocol)
		return 0;
	port = pkm_kacs_inet_bind_port(address, addrlen);
	if (!port)
		return 0;

	sec = pkm_kacs_sock(sock->sk);
	if (!sec) {
		trace_kacs_socket_bind(sock->sk->sk_family, sock->type,
				       sock->state, 0, KACS_PORT_BIND,
				       KACS_SOCK_NO_SECURITY, -EACCES);
		return -EACCES;
	}
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token) {
		trace_kacs_socket_bind(sock->sk->sk_family, sock->type,
				       sock->state, 0, KACS_PORT_BIND,
				       KACS_SOCK_NO_TOKEN, -EACCES);
		return -EACCES;
	}
	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret) {
		trace_kacs_socket_bind(sock->sk->sk_family, sock->type,
				       sock->state, 0, KACS_PORT_BIND,
				       KACS_SOCK_PIP_CONTEXT, ret);
		return ret;
	}
	ret = kacs_rust_port_bind_check(subject_token, protocol, port,
					pip_type, pip_trust);
	if (!ret) {
		binder = kacs_rust_token_clone(subject_token);
		if (binder)
			pkm_kacs_binder_set(sec, binder);
		/*
		 * The privilege half of the rebind rule (<pkm/net.h>): a
		 * reusable socket whose binder holds SeTcbPrivilege may
		 * share the port with another principal's binding. Decided
		 * here, where the token can be consulted; the conflict
		 * code reads the flag through
		 * pkm_kacs_reuseport_owner_matches() under its spinlocks.
		 */
		sec->rebind_tcb = false;
		if ((sock->sk->sk_reuse || sock->sk->sk_reuseport) &&
		    kacs_rust_token_has_enabled_privilege(
			    subject_token, KACS_SE_TCB_PRIVILEGE) &&
		    kacs_rust_token_mark_privileges_used(
			    subject_token, KACS_SE_TCB_PRIVILEGE))
			sec->rebind_tcb = true;
	}
	trace_kacs_socket_bind(sock->sk->sk_family, sock->type, sock->state,
			       port, KACS_PORT_BIND, KACS_SOCK_PORT_BIND, ret);
	return ret;
}

/*
 * The owner comparison the inet bind-conflict and reuseport-group code
 * makes between a binding socket @sk (whose uid is @uid) and an existing
 * one @sk2: Linux's same-uid rule, which under Peios is the same-user-SID
 * half of the rebind rule, or a binder that held SeTcbPrivilege. Called
 * under the bind-hash spinlocks; reads only the flag the bind hook set.
 */
bool pkm_kacs_reuseport_owner_matches(const struct sock *sk, kuid_t uid,
				      const struct sock *sk2)
{
	const struct pkm_kacs_socket_security *sec;

	if (uid_eq(uid, sk_uid(sk2)))
		return true;
	if (!sk || !sk->sk_security)
		return false;
	sec = pkm_kacs_sock((struct sock *)sk);
	return sec->rebind_tcb;
}
EXPORT_SYMBOL_GPL(pkm_kacs_reuseport_owner_matches);

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
	if (pkm_kacs_socket_family_inet(sock->sk->sk_family)) {
		ret = pkm_kacs_inet_bind(sock, address, addrlen);
		if (!ret)
			pkm_kacs_socket_stamp_owner(pkm_kacs_sock(sock->sk),
						    false, sock->sk->sk_family,
						    sock->type, sock->state);
		return ret;
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

int pkm_kacs_socket_listen(struct socket *sock, int backlog)
{
	struct pkm_kacs_socket_security *sec;
	long ret;

	(void)backlog;
	if (!sock || !sock->sk || !sock->sk->sk_security)
		return 0;
	if (pkm_kacs_socket_family_inet(sock->sk->sk_family)) {
		pkm_kacs_socket_stamp_owner(pkm_kacs_sock(sock->sk), false,
					    sock->sk->sk_family, sock->type,
					    sock->state);
		return 0;
	}
	if (sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_socket_type_supported(sock->type))
		return 0;

	sec = pkm_kacs_sock(sock->sk);
	ret = pkm_kacs_listener_stamp(sec);
	trace_kacs_socket_token(AF_UNIX, sock->type, sock->state,
				sec->max_impersonation, 0, KACS_SOCK_LISTEN, ret);
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

/*
 * The level and pass-token options bound and drive identity leaving an end,
 * which every AF_UNIX type does — a datagram conveys identity per message.
 * Only the register (KACS_SO_PEER_TOKEN) needs a connection-oriented type.
 */
static long pkm_kacs_sockopt_unix(struct socket *sock,
				  struct pkm_kacs_socket_security **sec_out)
{
	if (!sock || !sock->sk || !sock->sk->sk_security)
		return -EACCES;
	if (sock->sk->sk_family != AF_UNIX)
		return -EOPNOTSUPP;

	*sec_out = pkm_kacs_sock(sock->sk);
	return 0;
}

/* ---- per-message identity: KACS_SCM_TOKEN / KACS_SO_PASS_TOKEN ---- */

const void *pkm_kacs_token_get(const void *token)
{
	return token ? kacs_rust_token_clone(token) : NULL;
}

void pkm_kacs_token_put(const void *token)
{
	if (token)
		kacs_rust_token_drop(token);
}

void pkm_kacs_scm_token_drop(struct scm_cookie *scm)
{
	if (!scm || !scm->kacs_token)
		return;
	kacs_rust_token_drop(scm->kacs_token);
	scm->kacs_token = NULL;
	scm->kacs_deliver = 0;
}

static struct pkm_kacs_socket_security *pkm_kacs_unix_sec(struct socket *sock)
{
	if (!sock || !sock->sk || !sock->sk->sk_security ||
	    sock->sk->sk_family != AF_UNIX)
		return NULL;
	return pkm_kacs_sock(sock->sk);
}

/*
 * Explicit attach: a KACS_SCM_TOKEN cmsg carrying a token fd. Gated as if the
 * sender were impersonating that token — the two-gate model with the sender
 * as installer — and failing loudly rather than downgrading. Attaching is
 * therefore never more than the sender could do by impersonating, sending
 * and reverting.
 */
static long pkm_kacs_scm_attach_gate(struct pkm_kacs_socket_security *sec,
				     const void **token_io,
				     const void *server_primary)
{
	const void *token = *token_io;
	const void *primary = server_primary;
	u32 level, effective = 0, used = 0;
	long ret;

	if (kacs_rust_token_is_primary(token)) {
		const void *derived = NULL;

		ret = pkm_kacs_create_captured_peer_token(
			token, READ_ONCE(sec->max_impersonation), &derived);
		kacs_rust_token_drop(token);
		if (ret)
			return ret;
		if (!derived)
			return -EACCES;
		token = derived;
		*token_io = token;
	}

	level = kacs_rust_token_impersonation_level(token);
	if (level == KACS_IMLEVEL_ANONYMOUS)
		return 0;	/* always a downgrade; no gate runs */

	if (!primary)
		primary = pkm_kacs_current_primary_token_ptr();
	if (!primary)
		return -EACCES;
	ret = kacs_rust_token_impersonation_gate(primary, token, &effective,
						 &used);
	if (ret)
		return ret;
	if (effective < level)
		return -EPERM;
	if (used && !kacs_rust_token_mark_privileges_used(
			    primary, KACS_SE_IMPERSONATE_PRIVILEGE))
		return -EACCES;
	return 0;
}

static int pkm_kacs_scm_cmsg_core(struct socket *sock, struct cmsghdr *cmsg,
				  struct scm_cookie *scm,
				  const void *server_primary)
{
	struct pkm_kacs_socket_security *sec;
	const void *token = NULL;
	u32 access = 0;
	int fd;
	long ret;

	if (!cmsg || !scm)
		return -EINVAL;
	if (cmsg->cmsg_type != KACS_SCM_TOKEN)
		return -EINVAL;
	if (cmsg->cmsg_len != CMSG_LEN(sizeof(fd)))
		return -EINVAL;
	if (scm->kacs_token)
		return -EINVAL;
	sec = pkm_kacs_unix_sec(sock);
	if (!sec)
		return -EOPNOTSUPP;

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	ret = pkm_kacs_token_fd_clone_token(fd, &token, &access);
	if (ret)
		return ret;
	if (!token)
		return -EBADF;
	if ((access & KACS_TOKEN_IMPERSONATE) != KACS_TOKEN_IMPERSONATE) {
		kacs_rust_token_drop(token);
		trace_kacs_socket_token(AF_UNIX, sock->type, sock->state,
					sec->max_impersonation, access,
					KACS_SOCK_GATE, -EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_scm_attach_gate(sec, &token, server_primary);
	trace_kacs_socket_token(AF_UNIX, sock->type, sock->state,
				sec->max_impersonation,
				kacs_rust_token_impersonation_level(token),
				KACS_SOCK_GATE, ret);
	if (ret) {
		kacs_rust_token_drop(token);
		return ret;
	}

	scm->kacs_token = token;
	return 0;
}

int pkm_kacs_scm_cmsg(struct socket *sock, struct cmsghdr *cmsg,
		      struct scm_cookie *scm)
{
	return pkm_kacs_scm_cmsg_core(sock, cmsg, scm, NULL);
}

/*
 * Automatic attach (KACS_SO_PASS_TOKEN): every send carries the sender's
 * effective identity, derived at this end's level. The derivation is cached
 * against the effective token object it was made from — pinned by a
 * reference so its address cannot be recycled — and the level it was made
 * at; a send with the same effective token reuses it.
 */
int pkm_kacs_scm_send(struct socket *sock, struct scm_cookie *scm)
{
	struct pkm_kacs_socket_security *sec;
	const void *effective, *old_src = NULL, *old_token = NULL;
	u32 level;
	long ret = 0;

	if (!scm || scm->kacs_token)
		return 0;
	sec = pkm_kacs_unix_sec(sock);
	if (!sec || !READ_ONCE(sec->pass_token))
		return 0;

	effective = pkm_kacs_current_effective_token_ptr();
	if (!effective)
		return -EACCES;
	level = READ_ONCE(sec->max_impersonation);

	mutex_lock(&sec->convey_lock);
	if (sec->convey_src != effective || sec->convey_level != level ||
	    !sec->convey_token) {
		const void *derived = NULL;

		ret = pkm_kacs_create_captured_peer_token(effective, level,
							  &derived);
		if (!ret && !derived)
			ret = -EACCES;
		if (!ret) {
			old_src = sec->convey_src;
			old_token = sec->convey_token;
			sec->convey_src = kacs_rust_token_clone(effective);
			sec->convey_token = derived;
			sec->convey_level = level;
		}
	}
	if (!ret)
		scm->kacs_token = kacs_rust_token_clone(sec->convey_token);
	mutex_unlock(&sec->convey_lock);

	if (old_src)
		kacs_rust_token_drop(old_src);
	if (old_token)
		kacs_rust_token_drop(old_token);
	trace_kacs_socket_token(AF_UNIX, sock->type, sock->state, level, 0,
				KACS_SOCK_ATTACH, ret);
	return ret;
}

/*
 * Receiver side. Called for the first skb a read touches (@copied == 0):
 * that skb's identity becomes the read's identity, and the read delivers a
 * KACS_SCM_TOKEN only when that identity differs from the register. For
 * later skbs, returns true when the identity changes — the read stops there,
 * so data under different identities is never glued together.
 */
bool pkm_kacs_unix_read_boundary(struct sock *sk, const void *skb_token,
				 struct scm_cookie *scm, int copied)
{
	struct pkm_kacs_socket_security *sec;

	if (!scm)
		return false;
	if (copied)
		return skb_token != scm->kacs_token;

	if (!scm->kacs_token && skb_token)
		scm->kacs_token = kacs_rust_token_clone(skb_token);
	scm->kacs_deliver = 0;
	if (!skb_token || !sk || !sk->sk_security ||
	    sk->sk_family != AF_UNIX)
		return false;
	sec = pkm_kacs_sock(sk);
	spin_lock(&sec->register_lock);
	scm->kacs_deliver = sec->peer_token != skb_token;
	spin_unlock(&sec->register_lock);
	return false;
}

/* The reader's position has passed data conveyed under @skb_token. */
void pkm_kacs_unix_consumed(struct sock *sk, const void *skb_token)
{
	struct pkm_kacs_socket_security *sec;
	bool changed;

	if (!skb_token || !sk || !sk->sk_security ||
	    sk->sk_family != AF_UNIX || sk->sk_type == SOCK_DGRAM)
		return;
	sec = pkm_kacs_sock(sk);
	spin_lock(&sec->register_lock);
	changed = sec->peer_token != skb_token;
	spin_unlock(&sec->register_lock);
	if (!changed)
		return;
	pkm_kacs_register_set(sec, kacs_rust_token_clone(skb_token));
	trace_kacs_socket_token(AF_UNIX, sk->sk_type, 0, sec->max_impersonation,
				kacs_rust_token_impersonation_level(skb_token),
				KACS_SOCK_REGISTER, 0);
}

/* Deliver the read's identity as a KACS_SCM_TOKEN cmsg, then release it. */
void pkm_kacs_scm_recv(struct socket *sock, struct msghdr *msg,
		       struct scm_cookie *scm)
{
	long ret = 0;

	if (!scm || !scm->kacs_token)
		return;
	if (scm->kacs_deliver) {
		if (msg && msg->msg_control &&
		    msg->msg_controllen >= CMSG_SPACE(sizeof(int))) {
			int fd;

			ret = pkm_kacs_open_token_fd_with_fixed_access(
				scm->kacs_token, PKM_KACS_PEER_TOKEN_ACCESS_MASK);
			if (ret >= 0) {
				fd = ret;
				ret = put_cmsg(msg, SOL_KACS, KACS_SCM_TOKEN,
					       sizeof(fd), &fd);
				if (ret)
					close_fd(fd);
			}
		} else if (msg) {
			msg->msg_flags |= MSG_CTRUNC;
			ret = -ETOOSMALL;
		}
		trace_kacs_socket_token(AF_UNIX, sock && sock->sk ? sock->sk->sk_type : 0, 0, 0,
					kacs_rust_token_impersonation_level(scm->kacs_token),
					KACS_SOCK_DELIVER, ret);
	}
	pkm_kacs_scm_token_drop(scm);
}

int pkm_kacs_sock_setsockopt(struct socket *sock, int optname,
			     sockptr_t optval, unsigned int optlen)
{
	struct pkm_kacs_socket_security *sec;
	u32 val;
	long ret;

	if (optname != KACS_SO_IMPERSONATION_LEVEL &&
	    optname != KACS_SO_PASS_TOKEN && optname != KACS_SO_RESTAMP)
		return -ENOPROTOOPT;
	if (optlen < sizeof(val))
		return -EINVAL;
	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	if (optname == KACS_SO_RESTAMP) {
		if (sock && sock->sk && sock->sk->sk_security &&
		    pkm_kacs_socket_family_inet(sock->sk->sk_family)) {
			/* Any state: the caller becomes the governing identity. */
			pkm_kacs_socket_stamp_owner(pkm_kacs_sock(sock->sk),
						    false, sock->sk->sk_family,
						    sock->type, sock->state);
			return 0;
		}
		ret = pkm_kacs_sockopt_socket(sock, &sec);
		if (ret)
			return ret;
		if (sock->sk->sk_state != TCP_LISTEN)
			return -EINVAL;
		ret = pkm_kacs_listener_stamp(sec);
		trace_kacs_socket_token(AF_UNIX, sock->type, sock->state,
					sec->max_impersonation, 0,
					KACS_SOCK_RESTAMP, ret);
		return ret;
	}

	ret = pkm_kacs_sockopt_unix(sock, &sec);
	if (ret)
		return ret;

	if (optname == KACS_SO_PASS_TOKEN) {
		WRITE_ONCE(sec->pass_token, val != 0);
		return 0;
	}
	return pkm_kacs_set_socket_impersonation_level_core(sock, sec, val);
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

		ret = pkm_kacs_open_peer_token_core(sec);
		if (ret < 0)
			return ret;
		fd = ret;
		ret = pkm_kacs_sockopt_put(optval, optlen, &fd, sizeof(fd));
		if (ret)
			close_fd(fd);
		return ret;
	}
	case KACS_SO_IMPERSONATION_LEVEL:
	case KACS_SO_PASS_TOKEN: {
		u32 val;

		if (len < sizeof(val))
			return -EINVAL;
		ret = pkm_kacs_sockopt_unix(sock, &sec);
		if (ret)
			return ret;
		val = optname == KACS_SO_PASS_TOKEN ?
			(READ_ONCE(sec->pass_token) ? 1 : 0) :
			READ_ONCE(sec->max_impersonation);
		return pkm_kacs_sockopt_put(optval, optlen, &val, sizeof(val));
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
	out->listener_token = sec ? sec->listener_token : NULL;
	out->socket_sd_ptr = sec && sec->socket_sd ? sec->socket_sd->bytes : NULL;
	out->socket_sd_len = sec && sec->socket_sd ? sec->socket_sd->len : 0;
	out->max_impersonation = sec ? sec->max_impersonation : 0;
	out->owner_token = sec ? sec->owner_token : NULL;
	out->owner_kind = sec ? sec->owner_kind : 0;
	out->owner_pid = sec ? sec->owner_pid : 0;
	if (sec)
		memcpy(out->owner_guid, sec->owner_guid, sizeof(out->owner_guid));
	else
		memset(out->owner_guid, 0, sizeof(out->owner_guid));
}

static int pkm_kacs_kunit_init_socket_family(struct socket *sock,
					     struct sock *sk, void **blob_out,
					     u16 family, u32 socket_type,
					     u32 connected);
static void pkm_kacs_kunit_cleanup_socket(struct sock *sk, void *blob);

static int pkm_kacs_kunit_init_socket(struct socket *sock, struct sock *sk,
				      void **blob_out, u32 socket_type,
				      u32 connected)
{
	return pkm_kacs_kunit_init_socket_family(sock, sk, blob_out, AF_UNIX,
						 socket_type, connected);
}

static int pkm_kacs_kunit_init_socket_family(struct socket *sock,
					     struct sock *sk, void **blob_out,
					     u16 family, u32 socket_type,
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

	sk->sk_family = family;
	sk->sk_type = socket_type;
	sk->sk_security = blob;

	sock->type = socket_type;
	sock->state = connected ? SS_CONNECTED : SS_UNCONNECTED;
	sock->sk = sk;

	*blob_out = blob;
	return pkm_kacs_sk_alloc_security(sk, family, GFP_KERNEL);
}

/* ---- the governing identity on synthetic inet sockets ---- */

struct pkm_kacs_kunit_owner_socket {
	struct socket sock;
	struct sock sk;
	void *blob;
};

long pkm_kacs_kunit_socket_owner_open(u32 family, u32 kern, void **handle_out,
				      struct pkm_kacs_kunit_socket_view *out)
{
	struct pkm_kacs_kunit_owner_socket *s;
	long ret;

	if (!handle_out)
		return -EINVAL;
	*handle_out = NULL;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	ret = pkm_kacs_kunit_init_socket_family(&s->sock, &s->sk, &s->blob,
						(u16)family, SOCK_STREAM, 0);
	if (ret) {
		kfree(s);
		return ret;
	}
	ret = pkm_kacs_socket_post_create(&s->sock, family, SOCK_STREAM, 0,
					  kern != 0);
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&s->sk), out);
	*handle_out = s;
	return ret;
}

/*
 * One committing act on an open synthetic socket: 1 = bind (port 0),
 * 2 = listen, 3 = connect, 4 = KACS_SO_RESTAMP. The view afterwards.
 */
long pkm_kacs_kunit_socket_owner_act(void *handle, u32 act,
				     struct pkm_kacs_kunit_socket_view *out)
{
	struct pkm_kacs_kunit_owner_socket *s = handle;
	struct sockaddr_in addr = { .sin_family = AF_INET };
	u32 one = 1;
	long ret;

	if (!s)
		return -EINVAL;
	switch (act) {
	case 1:
		ret = pkm_kacs_socket_bind(&s->sock, (struct sockaddr *)&addr,
					   sizeof(addr));
		break;
	case 2:
		ret = pkm_kacs_socket_listen(&s->sock, 1);
		break;
	case 3:
		ret = pkm_kacs_socket_connect(&s->sock, (struct sockaddr *)&addr,
					      sizeof(addr));
		break;
	case 4:
		ret = pkm_kacs_sock_setsockopt(&s->sock, KACS_SO_RESTAMP,
					       KERNEL_SOCKPTR(&one),
					       sizeof(one));
		break;
	default:
		return -EINVAL;
	}
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&s->sk), out);
	return ret;
}

/* Clones the socket the way accept does and views the child. */
long pkm_kacs_kunit_socket_owner_clone(void *handle,
				       struct pkm_kacs_kunit_socket_view *out)
{
	struct pkm_kacs_kunit_owner_socket *s = handle, *child;
	long ret;

	if (!s)
		return -EINVAL;
	child = kzalloc(sizeof(*child), GFP_KERNEL);
	if (!child)
		return -ENOMEM;
	ret = pkm_kacs_kunit_init_socket_family(&child->sock, &child->sk,
						&child->blob, s->sk.sk_family,
						SOCK_STREAM, 1);
	if (ret) {
		kfree(child);
		return ret;
	}
	pkm_kacs_sk_clone_security(&s->sk, &child->sk);
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&child->sk), out);
	pkm_kacs_kunit_cleanup_socket(&child->sk, child->blob);
	kfree(child);
	return 0;
}

/* The engine's read: a counted reference the caller must put. */
long pkm_kacs_kunit_socket_owner_query(void *handle,
				       struct peios_pnp_owner *out)
{
	struct pkm_kacs_kunit_owner_socket *s = handle;

	if (!s)
		return -EINVAL;
	return pkm_kacs_socket_owner(&s->sk, out);
}

void pkm_kacs_kunit_socket_owner_close(void *handle)
{
	struct pkm_kacs_kunit_owner_socket *s = handle;

	if (!s)
		return;
	pkm_kacs_kunit_cleanup_socket(&s->sk, s->blob);
	kfree(s);
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
	/* The connect hook only fires for the connection-oriented types. */
	if (!pkm_kacs_socket_type_supported(socket_type))
		return -EACCES;

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

/*
 * Phase-2 shims: the per-message identity machinery on synthetic sockets.
 * scm_cookie and the register are driven directly, without skbs.
 */
long pkm_kacs_kunit_socket_pass_token_send(u32 socket_type, u32 level,
					   u32 pass, const void **first_out,
					   const void **second_out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	struct scm_cookie a = { }, b = { };
	void *blob = NULL;
	long ret;

	if (first_out)
		*first_out = NULL;
	if (second_out)
		*second_out = NULL;
	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type, 1);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	sec->max_impersonation = level;
	sec->pass_token = pass != 0;

	ret = pkm_kacs_scm_send(&sock, &a);
	if (!ret)
		ret = pkm_kacs_scm_send(&sock, &b);
	if (!ret) {
		if (first_out)
			*first_out = pkm_kacs_token_get(a.kacs_token);
		if (second_out)
			*second_out = pkm_kacs_token_get(b.kacs_token);
	}
	pkm_kacs_scm_token_drop(&a);
	pkm_kacs_scm_token_drop(&b);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_socket_attach_fd(int fd, u32 socket_level,
				     const void *server_primary,
				     const void **token_out)
{
	struct {
		struct cmsghdr hdr;
		int fd;
	} __aligned(sizeof(long)) cm = { };
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	struct scm_cookie scm = { };
	void *blob = NULL;
	long ret;

	if (token_out)
		*token_out = NULL;
	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM, 1);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	sec->max_impersonation = socket_level;

	cm.hdr.cmsg_level = SOL_KACS;
	cm.hdr.cmsg_type = KACS_SCM_TOKEN;
	cm.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	cm.fd = fd;
	ret = pkm_kacs_scm_cmsg_core(&sock, &cm.hdr, &scm, server_primary);
	if (!ret && token_out) {
		*token_out = scm.kacs_token;
		scm.kacs_token = NULL;
	}
	pkm_kacs_scm_token_drop(&scm);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_socket_listen_stamp(u32 level_set, u32 level, u32 restamp,
					const void **first_out,
					const void **second_out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	if (first_out)
		*first_out = NULL;
	if (second_out)
		*second_out = NULL;
	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM, 0);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (level_set) {
		sec->max_impersonation = level;
		sec->level_set = true;
	}
	sk.sk_state = TCP_LISTEN;
	ret = pkm_kacs_socket_listen(&sock, 1);
	if (!ret && first_out)
		*first_out = pkm_kacs_listener_clone(sec);
	if (!ret && restamp) {
		u32 one = 1;

		ret = pkm_kacs_sock_setsockopt(&sock, KACS_SO_RESTAMP,
					       KERNEL_SOCKPTR(&one), sizeof(one));
		if (!ret && second_out)
			*second_out = pkm_kacs_listener_clone(sec);
	}
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_socket_register_flow(u32 socket_type, const void *initial,
					 const void *conveyed, u32 *deliver_out,
					 u32 *boundary_out,
					 const void **register_out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	struct scm_cookie scm = { };
	void *blob = NULL;
	long ret;

	if (register_out)
		*register_out = NULL;
	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type, 1);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (initial)
		pkm_kacs_register_set(sec, kacs_rust_token_clone(initial));

	/* first skb of a read: identity + delivery decision */
	pkm_kacs_unix_read_boundary(&sk, conveyed, &scm, 0);
	if (deliver_out)
		*deliver_out = scm.kacs_deliver;
	/* the reader's position passes it */
	pkm_kacs_unix_consumed(&sk, conveyed);
	if (register_out)
		*register_out = pkm_kacs_register_clone(sec);
	/* a following skb under the original identity is a boundary */
	if (boundary_out)
		*boundary_out = pkm_kacs_unix_read_boundary(&sk, initial, &scm,
							    1) ? 1 : 0;
	pkm_kacs_scm_token_drop(&scm);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return 0;
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */
