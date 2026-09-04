// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source bootstrap refresh orchestration.
 */

#include <linux/errno.h>
#include <linux/peios_pnp.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <trace/events/lcs.h>

#include "../kacs/port_reservations.h"
#include "source_device.h"

long pkm_lcs_source_bootstrap_refresh_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_bootstrap_refresh_result *result_out)
{
	struct pkm_lcs_source_bootstrap_refresh_result *result;
	u8 registry_guid[RSI_GUID_SIZE] = { };
	u8 kmes_guid[RSI_GUID_SIZE] = { };
	u8 layers_root_guid[RSI_GUID_SIZE] = { };
	u8 port_guid[RSI_GUID_SIZE] = { };
	u8 network_guid[RSI_GUID_SIZE] = { };
	bool registry_root_present = false;
	bool kmes_root_present = false;
	bool layers_root_present = false;
	bool port_root_present = false;
	bool network_root_present = false;
	u8 stage = LCS_BOOT_REGISTRY;
	long ret;

	if (result_out)
		memset(result_out, 0, sizeof(*result_out));
	if (!source_id || !machine_root_guid || !result_out)
		return -EINVAL;

	/*
	 * The refresh result aggregates the full self-config plan, KMES plan,
	 * layer-metadata result, and self-watch arm state. Keep that working
	 * copy off the kernel stack.
	 */
	result = kzalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	ret = pkm_lcs_self_config_registry_root_discover_from_machine_hive(
		source_id, machine_root_guid, &registry_root_present,
		registry_guid);
	if (ret)
		goto out;
	result->registry_root_present = registry_root_present;

	if (registry_root_present) {
		ret = pkm_lcs_runtime_limits_refresh_self_config_from_key(
			source_id, registry_guid, &result->self_config);
		if (ret)
			goto out;
	}

	stage = LCS_BOOT_KMES;
	ret = pkm_kmes_config_root_discover_from_machine_hive(
		source_id, machine_root_guid, &kmes_root_present, kmes_guid);
	if (ret)
		goto out;
	result->kmes_root_present = kmes_root_present;

	if (kmes_root_present) {
		ret = pkm_kmes_runtime_config_refresh_from_key(
			source_id, kmes_guid, &result->kmes_config);
		if (ret)
			goto out;
	}

	stage = LCS_BOOT_LAYERS;
	ret = pkm_lcs_layer_metadata_root_discover_from_machine_hive(
		source_id, machine_root_guid, &layers_root_present,
		layers_root_guid);
	if (ret)
		goto out;
	result->layers_root_present = layers_root_present;

	if (layers_root_present) {
		ret = pkm_lcs_layer_metadata_refresh_all_from_root(
			source_id, layers_root_guid, &result->layers);
		if (ret)
			goto out;
	}

	/*
	 * Port reservations (kacs/port_reservations.c) the fourth kernel-read
	 * key, discovered after the three LCS/KMES keys so nothing about it
	 * can delay or fail their refresh. Only its discovery walk may fail
	 * the bootstrap; a rejected table is not a failure — KACS keeps its
	 * fallback and the audit trail says why.
	 */
	ret = pkm_kacs_port_reservations_root_discover_from_machine_hive(
		source_id, machine_root_guid, &port_root_present, port_guid);
	if (ret)
		goto out;
	result->port_root_present = port_root_present;
	if (port_root_present)
		pkm_kacs_port_reservations_refresh_from_key(source_id,
							    port_guid);

	/*
	 * PNP's Network key (net/pnp/ingest.c) — the policy rules and netd's
	 * inventory, the network context — the fifth kernel-read key,
	 * discovered last like port reservations: only its discovery walk
	 * may fail the bootstrap. A rejected forest is not a failure — PNP
	 * keeps its previous policy generation and says why.
	 */
	ret = peios_pnp_network_root_discover_from_machine_hive(
		source_id, machine_root_guid, &network_root_present, network_guid);
	if (ret)
		goto out;
	result->network_root_present = network_root_present;
	if (network_root_present)
		peios_pnp_network_refresh_from_key(source_id, network_guid);

	stage = LCS_BOOT_SELF_WATCH;
	ret = pkm_lcs_internal_self_watch_arm_full(
		source_id, machine_root_guid, registry_root_present,
		registry_guid, layers_root_present, layers_root_guid,
		kmes_root_present, kmes_guid, port_root_present, port_guid,
		network_root_present, network_guid, &result->self_watch);
	if (ret)
		goto out;

	*result_out = *result;
	ret = 0;
	stage = LCS_BOOT_COMPLETE;
out:
	trace_lcs_bootstrap_refresh(source_id, registry_root_present,
				    kmes_root_present, layers_root_present,
				    stage, ret);
	if (ret && stage != LCS_BOOT_SELF_WATCH) {
		/*
		 * A stage failed before the self-watch was armed — typically a
		 * transient source error while Phase-1.5 autoapply is mutating
		 * the same source (PEI-510). Without a watch nothing would ever
		 * retry, and no kernel-read key would load for the life of the
		 * boot. Arm the machine-root fallback alone: the next subkey
		 * creation under Machine re-runs this refresh, which re-arms
		 * targeted watches once it completes. Best effort — if even
		 * this fails there is nothing left to do but report.
		 */
		struct pkm_lcs_internal_self_watch_arm_result fallback = { };
		long arm_ret;

		arm_ret = pkm_lcs_internal_self_watch_arm_full(
			source_id, machine_root_guid, false, NULL, false, NULL,
			false, NULL, false, NULL, false, NULL, &fallback);
		trace_lcs_bootstrap_refresh(source_id, 0, 0, 0,
					    LCS_BOOT_SELF_WATCH, arm_ret);
	}
	kfree(result);
	return ret;
}
