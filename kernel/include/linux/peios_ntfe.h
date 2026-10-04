/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Narrow in-kernel interface between the NTFE packet engine (net/ntfe) and
 * the subsystems it hooks: the LCS registry machinery (security/pkm/lcs)
 * for Network-key discovery, refresh, and change notification; and
 * conntrack (net/netfilter) for the flow tag extension's lifecycle. Not
 * UAPI, not exported to modules. Stubbed when NTFE is configured out so
 * neither side grows a hard link-time dependency on it.
 */
#ifndef _LINUX_PEIOS_NTFE_H
#define _LINUX_PEIOS_NTFE_H

#include <linux/types.h>

struct nf_conn;
struct peios_ntfe_tag_table;
struct sock;

/*
 * The identity that governs a socket's traffic, as KACS records it on
 * the socket (security/pkm/kacs/socket.c) and net/ntfe reads it at the IP
 * seats for the Flow layer's `Local.*` facts. KACS stamps an inet socket
 * with the caller's effective token at every act that commits the socket
 * to a role — creation, bind, listen, connect, inheritance at accept,
 * KACS_SO_RESTAMP — and copies the process facts of that moment alongside,
 * so they outlive the process. A kernel socket is stamped as the kernel's.
 */
enum peios_ntfe_owner_kind {
	PEIOS_NTFE_OWNER_UNSTAMPED = 0,	/* never stamped (not inet, or pre-KACS) */
	PEIOS_NTFE_OWNER_PROGRAM,	/* a process: token and facts below */
	PEIOS_NTFE_OWNER_KERNEL,		/* a kernel socket: no token */
};

#define PEIOS_NTFE_OWNER_COMM_LEN	16

struct peios_ntfe_owner {
	const void *token;	/* counted KACS token reference, or NULL */
	u8 kind;		/* enum peios_ntfe_owner_kind */
	u8 guid[16];		/* the process GUID at the stamp */
	s32 pid;		/* the thread-group id at the stamp */
	char comm[PEIOS_NTFE_OWNER_COMM_LEN];	/* the task comm at the stamp */
};

/*
 * Reads the socket's governing identity into @out, handing the caller its
 * own counted reference to the token (release with
 * pkm_kacs_socket_owner_put). -ENOENT when the socket carries no KACS
 * state at all; a socket that was never stamped reads UNSTAMPED.
 */
int pkm_kacs_socket_owner(const struct sock *sk, struct peios_ntfe_owner *out);
void pkm_kacs_socket_owner_put(struct peios_ntfe_owner *owner);

/*
 * One cached Flow-layer judgment — a "sentence" (net/ntfe/flow.c). Written
 * under the flow's lock with `generation` zeroed first and published last
 * (release); read lock-free with an acquire and a re-check of
 * `generation`, so a reader never applies a torn sentence.
 */
struct peios_ntfe_sentence {
	u64 generation;		/* 0 = empty; the policy generation that judged */
	s64 expires_at;		/* CLOCK_REALTIME seconds; 0 = never */
	u64 rule_hash;		/* FNV-1a-64 of the attributing rule's path */
	u8 verdict;		/* enum peios_ntfe_verdict */
	u8 reject_kind;		/* enum peios_ntfe_reject_kind */
	u8 _pad[6];
};

/*
 * The NTFE conntrack extension, added to every flow at creation. Sized here
 * so nf_conntrack_extend.c's type table can see it.
 *
 * - `tags`: NULL until the flow's first TAG, then an RCU-managed table
 *   owned by net/ntfe/tags.c;
 * - `start_secs`: when the flow was created (the `Start.*` facts);
 * - the flow facts the tuple does not carry, recorded at the first
 *   judgment so every later judgment (a re-judge on a reply packet, say)
 *   sees the same facts: the originator's direction, the interface, the
 *   VLAN, the peer's MAC;
 * - the sentences: the Flow layer's cached verdicts, one per local
 *   endpoint — slot 0 for every flow (a loopback flow's outbound
 *   endpoint), slot 1 only for a loopback flow's inbound endpoint;
 * - the endpoints' governing identities (net/ntfe/identity.c), resolved at
 *   the first judgment and fixed for the flow's life, one per slot: the
 *   kind (what answers there), and for a program the owner KACS stamped
 *   on its socket, holding a counted token reference until the flow dies.
 */
struct peios_ntfe_ct {
	struct peios_ntfe_tag_table __rcu *tags;
	u64 start_secs;
	int ifindex;		/* interface at first judgment */
	u8 direction;		/* originator's side, at first judgment */
	u8 judged;		/* the facts below are recorded */
	u8 loopback;		/* both endpoints local: two sentences */
	u8 has_src_mac;
	u16 vlan;
	u8 has_vlan;
	u8 _pad0;
	u8 src_mac[6];
	u8 _pad1[2];
	struct peios_ntfe_sentence sentence[2];
	struct peios_ntfe_owner owner[2];
	u8 owner_kind[2];		/* enum peios_ntfe_local_kind (net/ntfe/ntfe.h) */
	u8 owner_unresolved[2];		/* confessed at resolution */
	u8 owner_recorded[2];		/* published (release) after the fields */
};

#if IS_ENABLED(CONFIG_PEIOS_NTFE)

/*
 * Resolves Machine\System\Network from the machine hive root: the key
 * NTFE reads — Rules\ for the policy, Interfaces\ and Networks\ for the
 * network context. Absence is not an error: *present_out = false,
 * return 0.
 */
long peios_ntfe_network_root_discover_from_machine_hive(u32 source_id,
						       const u8 machine_root_guid[16],
						       bool *present_out,
						       u8 network_guid_out[16]);

/*
 * Walks the Network key: publishes a new policy generation when the
 * rules changed, and a new context table when the inventory did. On any
 * failure the previous generation and table stay (atomic transitions)
 * and the error says why; NTFE keeps its last known-good state.
 */
long peios_ntfe_network_refresh_from_key(u32 source_id,
					const u8 network_guid[16]);

/*
 * Change notification from the LCS internal watch dispatcher. Events are
 * per-key and uncoalesced; this entry point coalesces them into one
 * deferred re-walk (dirty flag + debounced workqueue), so it is cheap to
 * call from the dispatch path.
 */
void peios_ntfe_network_registry_changed(u32 source_id,
					const u8 network_guid[16]);

/*
 * Conntrack lifecycle hooks (net/ntfe/tags.c): add the extension to a
 * fresh, unconfirmed flow (init_conntrack), and release the tag table
 * when the flow is freed (nf_conntrack_free).
 */
void peios_ntfe_ct_ext_add(struct nf_conn *ct);
void peios_ntfe_ct_destroy(struct nf_conn *ct);

#else /* CONFIG_PEIOS_NTFE */

static inline long
peios_ntfe_network_root_discover_from_machine_hive(u32 source_id,
						  const u8 machine_root_guid[16],
						  bool *present_out,
						  u8 network_guid_out[16])
{
	if (present_out)
		*present_out = false;
	return 0;
}

static inline long peios_ntfe_network_refresh_from_key(u32 source_id,
						      const u8 network_guid[16])
{
	return 0;
}

static inline void peios_ntfe_network_registry_changed(u32 source_id,
						      const u8 network_guid[16])
{
}

static inline void peios_ntfe_ct_ext_add(struct nf_conn *ct)
{
}

static inline void peios_ntfe_ct_destroy(struct nf_conn *ct)
{
}

#endif /* CONFIG_PEIOS_NTFE */

#endif /* _LINUX_PEIOS_NTFE_H */
