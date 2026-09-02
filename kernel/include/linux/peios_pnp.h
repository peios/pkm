/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Narrow in-kernel interface between the PNP packet engine (net/pnp) and
 * the subsystems it hooks: the LCS registry machinery (security/pkm/lcs)
 * for rules-subtree discovery, refresh, and change notification; and
 * conntrack (net/netfilter) for the flow tag extension's lifecycle. Not
 * UAPI, not exported to modules. Stubbed when PNP is configured out so
 * neither side grows a hard link-time dependency on it.
 */
#ifndef _LINUX_PEIOS_PNP_H
#define _LINUX_PEIOS_PNP_H

#include <linux/types.h>

struct nf_conn;
struct peios_pnp_tag_table;

/*
 * One cached Flow-layer judgment — a "sentence" (net/pnp/flow.c). Written
 * under the flow's lock with `generation` zeroed first and published last
 * (release); read lock-free with an acquire and a re-check of
 * `generation`, so a reader never applies a torn sentence.
 */
struct peios_pnp_sentence {
	u64 generation;		/* 0 = empty; the policy generation that judged */
	s64 expires_at;		/* CLOCK_REALTIME seconds; 0 = never */
	u64 rule_hash;		/* FNV-1a-64 of the attributing rule's path */
	u8 verdict;		/* enum peios_pnp_verdict */
	u8 reject_kind;		/* enum peios_pnp_reject_kind */
	u8 _pad[6];
};

/*
 * The PNP conntrack extension, added to every flow at creation. Sized here
 * so nf_conntrack_extend.c's type table can see it.
 *
 * - `tags`: NULL until the flow's first TAG, then an RCU-managed table
 *   owned by net/pnp/tags.c;
 * - `start_secs`: when the flow was created (the `Start.*` facts);
 * - the sentences: the Flow layer's cached verdicts, one per local
 *   endpoint — slot 0 for every flow (a loopback flow's outbound
 *   endpoint), slot 1 only for a loopback flow's inbound endpoint.
 */
struct peios_pnp_ct {
	struct peios_pnp_tag_table __rcu *tags;
	u64 start_secs;
	int ifindex;		/* interface at first judgment */
	u8 direction;		/* originator's side, at first judgment */
	u8 judged;		/* ifindex/direction/loopback recorded */
	u8 loopback;		/* both endpoints local: two sentences */
	u8 _pad;
	struct peios_pnp_sentence sentence[2];
};

#if IS_ENABLED(CONFIG_PEIOS_PNP)

/*
 * Resolves Machine\System\Network\Rules from the machine hive root.
 * Absence is not an error: *present_out = false, return 0.
 */
long peios_pnp_rules_root_discover_from_machine_hive(u32 source_id,
						     const u8 machine_root_guid[16],
						     bool *present_out,
						     u8 rules_guid_out[16]);

/*
 * Walks the rules subtree and publishes a new policy generation. On any
 * failure the previous generation stays (atomic transitions) and the
 * error says why; PNP keeps its last known-good policy.
 */
long peios_pnp_rules_refresh_from_key(u32 source_id, const u8 rules_guid[16]);

/*
 * Change notification from the LCS internal watch dispatcher. Events are
 * per-key and uncoalesced; this entry point coalesces them into one
 * deferred re-walk (dirty flag + debounced workqueue), so it is cheap to
 * call from the dispatch path.
 */
void peios_pnp_rules_registry_changed(u32 source_id, const u8 rules_guid[16]);

/*
 * Conntrack lifecycle hooks (net/pnp/tags.c): add the extension to a
 * fresh, unconfirmed flow (init_conntrack), and release the tag table
 * when the flow is freed (nf_conntrack_free).
 */
void peios_pnp_ct_ext_add(struct nf_conn *ct);
void peios_pnp_ct_destroy(struct nf_conn *ct);

#else /* CONFIG_PEIOS_PNP */

static inline long
peios_pnp_rules_root_discover_from_machine_hive(u32 source_id,
						const u8 machine_root_guid[16],
						bool *present_out,
						u8 rules_guid_out[16])
{
	if (present_out)
		*present_out = false;
	return 0;
}

static inline long peios_pnp_rules_refresh_from_key(u32 source_id,
						    const u8 rules_guid[16])
{
	return 0;
}

static inline void peios_pnp_rules_registry_changed(u32 source_id,
						    const u8 rules_guid[16])
{
}

static inline void peios_pnp_ct_ext_add(struct nf_conn *ct)
{
}

static inline void peios_pnp_ct_destroy(struct nf_conn *ct)
{
}

#endif /* CONFIG_PEIOS_PNP */

#endif /* _LINUX_PEIOS_PNP_H */
