/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The kernel's emission policy (PGSS §6.9): which of the kernel's own event
 * types are switched on, as configured under Machine\Generic\Events.
 *
 * The policy is cached as one bit per kernel event type in a u64 that a
 * refresh walk recomputes and publishes whole with WRITE_ONCE(). An emitter
 * reads it with one READ_ONCE(), so a decision costs a load and a test, and
 * an essential type costs nothing at all: its tier is a compile-time
 * constant and the check folds to true (§6.9: essential types never consult
 * the policy).
 *
 * Until the registry is readable and the first walk has completed, the mask
 * holds the tier defaults: essential and standard on, verbose and debug off
 * (§6.9: an unreadable policy falls back to tier). A walk that fails keeps
 * the mask it had; nothing is ever published half-computed.
 *
 * See event_types.h for how an emitter calls the check.
 */
#ifndef _SECURITY_PKM_KMES_EVENT_POLICY_H
#define _SECURITY_PKM_KMES_EVENT_POLICY_H

#include <linux/bits.h>
#include <linux/compiler.h>
#include <linux/types.h>

#include "event_types.h"

/* The registry key the policy lives under, in canonical form. */
#define PKM_KMES_EVENT_POLICY_KEY_PATH "Machine\\Generic\\Events"

/*
 * Bit i is set when kernel event type i is switched on. Written only by
 * kmes/event_policy.c, always whole, always with WRITE_ONCE().
 */
extern u64 pkm_kmes_event_enabled_mask;

/*
 * Whether kernel event type @id is switched on. Pass a constant id: an
 * essential type then folds to true without touching the policy.
 */
static __always_inline bool pkm_kmes_event_enabled(enum pkm_kmes_event_id id)
{
	if (pkm_kmes_event_tier(id) == PKM_KMES_EV_TIER_ESSENTIAL)
		return true;
	return READ_ONCE(pkm_kmes_event_enabled_mask) & BIT_ULL(id);
}

/* The same check for Rust emitters (kmes/event_types.rs). */
bool pkm_kmes_event_enabled_ffi(u32 id);

/* The mask in force now, for tests and diagnostics. */
u64 pkm_kmes_event_policy_mask(void);

/*
 * Find Machine\Generic\Events from the Machine hive root. Absence is not an
 * error: *present_out is false and the bootstrap arms the machine-root
 * fallback watch, which re-runs discovery when the key is created.
 */
long pkm_kmes_event_policy_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[16], bool *present_out,
	u8 events_guid_out[16]);

/*
 * Walk the policy under @events_guid and publish the mask it gives. On
 * failure the previous mask stays and a kmes.config.refresh.failed record
 * says why. Serialised against itself.
 */
long pkm_kmes_event_policy_refresh_from_key(u32 source_id,
					    const u8 events_guid[16]);

/*
 * The policy key is absent: no Enabled value can be found, so the tier
 * decides for every type (§6.9). Publishes the tier defaults.
 */
void pkm_kmes_event_policy_reset_to_tier_defaults(void);

/*
 * The internal watch on Machine\Generic\Events saw a change it did not
 * filter out. Coalesces into one re-walk after a short window (see
 * PKM_KMES_EVENT_POLICY_DEBOUNCE_MS in event_policy.c), so a change applies
 * within about 50 ms plus one walk.
 */
void pkm_kmes_event_policy_registry_changed(u32 source_id,
					    const u8 events_guid[16]);

/*
 * Whether a change under Events\<name> can matter to a kernel type: @name
 * is the first segment beneath Events. Names that are not plain ASCII are
 * let through, because the registry folds case beyond ASCII and the walk
 * would find such a key.
 */
bool pkm_kmes_event_policy_root_relevant(const char *name, u32 name_len);

/*
 * Whether a value change concerns the Enabled value. A change that carries
 * no name is let through.
 */
bool pkm_kmes_event_policy_value_relevant(const u8 *name, u32 name_len);

/*
 * The resolution itself, separated from the registry walk so it can be
 * tested on its own.
 *
 * One entry per trie node (event_types.h), in node order. A node's key
 * either exists or does not; where it exists, its Enabled value is one of
 * the settings below. A node whose parent does not exist must not exist
 * either; the resolver enforces it.
 */
enum pkm_kmes_event_setting {
	PKM_KMES_EVENT_SETTING_ABSENT = -1,
	PKM_KMES_EVENT_SETTING_OFF = 0,
	PKM_KMES_EVENT_SETTING_ON = 1,
};

struct pkm_kmes_event_policy_node_state {
	bool present;
	s8 setting;
};

/*
 * The mask @nodes give, with @root_setting the Enabled value on Events
 * itself (ABSENT when the key holds none, or does not exist). Pure.
 */
u64 pkm_kmes_event_policy_resolve(
	s8 root_setting,
	const struct pkm_kmes_event_policy_node_state *nodes, u32 node_count);

/*
 * What a value contributes to the walk: the setting it gives, or @current
 * when it is not a REG_DWORD of 0 or 1 (§6.9: ignored, as though absent).
 */
s8 pkm_kmes_event_policy_read_enabled(u32 type, const u8 *data, u32 len,
				      s8 current_setting);

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_kmes_event_policy_kunit_reset(void);
void pkm_kmes_event_policy_kunit_publish(u64 mask);
void pkm_kmes_event_policy_kunit_flush(void);
u64 pkm_kmes_event_policy_kunit_changes_noted(void);
#endif

#endif /* _SECURITY_PKM_KMES_EVENT_POLICY_H */
