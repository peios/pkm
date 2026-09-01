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
 * The PNP conntrack extension: one pointer per flow, NULL until the flow's
 * first TAG, then an RCU-managed table owned by net/pnp/tags.c. Sized here
 * so nf_conntrack_extend.c's type table can see it.
 */
struct peios_pnp_ct {
	struct peios_pnp_tag_table __rcu *tags;
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
