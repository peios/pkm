/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Narrow in-kernel interface between the LCS registry machinery
 * (security/pkm/lcs) and the PNP packet engine (net/pnp): rules-subtree
 * discovery, refresh, and change notification. Not UAPI, not exported to
 * modules. Stubbed when PNP is configured out so LCS never grows a hard
 * link-time dependency on it.
 */
#ifndef _LINUX_PEIOS_PNP_H
#define _LINUX_PEIOS_PNP_H

#include <linux/types.h>

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
 * deferred re-walk (dirty flag + workqueue), so it is cheap to call from
 * the dispatch path.
 */
void peios_pnp_rules_registry_changed(u32 source_id, const u8 rules_guid[16]);

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

#endif /* CONFIG_PEIOS_PNP */

#endif /* _LINUX_PEIOS_PNP_H */
