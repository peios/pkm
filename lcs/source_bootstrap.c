// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source bootstrap refresh orchestration.
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "source_device.h"

long pkm_lcs_source_bootstrap_refresh_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_bootstrap_refresh_result *result_out)
{
	struct pkm_lcs_source_bootstrap_refresh_result *result;
	u8 registry_guid[RSI_GUID_SIZE] = { };
	u8 kmes_guid[RSI_GUID_SIZE] = { };
	u8 layers_root_guid[RSI_GUID_SIZE] = { };
	bool registry_root_present = false;
	bool kmes_root_present = false;
	bool layers_root_present = false;
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

	ret = pkm_lcs_internal_self_watch_arm(
		source_id, machine_root_guid, registry_root_present,
		registry_guid, layers_root_present, layers_root_guid,
		kmes_root_present, kmes_guid, &result->self_watch);
	if (ret)
		goto out;

	*result_out = *result;
	ret = 0;
out:
	kfree(result);
	return ret;
}
