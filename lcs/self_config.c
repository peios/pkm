// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS runtime self-configuration refresh and publication.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <trace/events/lcs.h>

#include "source_device.h"

extern int lcs_rust_plan_self_config_apply(
	const struct pkm_lcs_runtime_limits *current_limits,
	const struct pkm_lcs_self_config_entry *entries, size_t entry_count,
	struct pkm_lcs_self_config_apply_plan *plan_out);
extern int lcs_rust_plan_self_config_apply_from_query_values(
	const struct pkm_lcs_runtime_limits *current_limits, const u8 *frame,
	size_t frame_len, u64 request_id, u64 next_sequence,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	size_t private_layer_count,
	struct pkm_lcs_self_config_apply_plan *plan_out);

static long pkm_lcs_runtime_limits_publish_self_config_plan(
	const struct pkm_lcs_self_config_apply_plan *plan,
	struct pkm_lcs_self_config_apply_plan *result_out)
{
	long ret;
	u32 i;

	if (!plan)
		return -EINVAL;

	if (plan->audit_count > PKM_LCS_SELF_CONFIG_MAX_AUDITS) {
		trace_lcs_self_config_publish(
			0, 0, 0, 0, LCS_BOOT_SELF_CONFIG_PARAM_INVALID, -EIO);
		return -EIO;
	}

	for (i = 0; i < plan->audit_count; i++) {
		const struct pkm_lcs_self_config_audit_intent *audit =
			&plan->audits[i];

		if (!audit->configuration_name_len ||
		    audit->configuration_name_len >
			    PKM_LCS_SELF_CONFIG_MAX_PARAMETER_NAME_LEN) {
			trace_lcs_self_config_publish(
				0, 0, 0, 0,
				LCS_BOOT_SELF_CONFIG_PARAM_INVALID, -EIO);
			return -EIO;
		}

		/*
		 * PSD-005 §3.1 makes self-config audit emission best-effort
		 * after payload construction. A failed KMES attempt must not
		 * roll back valid hot-swaps or alter retained invalid values.
		 */
		pkm_lcs_emit_self_config_invalid_audit(
			audit->configuration_name, audit->configuration_name_len,
			audit->received_kind, audit->received_type,
			audit->received_u32, audit->retained_value);
	}

	ret = pkm_lcs_runtime_limits_publish(&plan->limits);
	if (ret)
		return ret;

	if (result_out)
		*result_out = *plan;
	return 0;
}

long pkm_lcs_runtime_limits_apply_self_config(
	const struct pkm_lcs_self_config_entry *entries, u32 entry_count,
	struct pkm_lcs_self_config_apply_plan *result_out)
{
	struct pkm_lcs_self_config_apply_plan plan = { };
	struct pkm_lcs_runtime_limits active_limits = { };
	long ret;

	if (entry_count && !entries)
		return -EINVAL;

	ret = pkm_lcs_runtime_limits_snapshot(&active_limits);
	if (ret)
		return ret;

	ret = lcs_rust_plan_self_config_apply(&active_limits, entries, entry_count,
					      &plan);
	if (ret)
		return ret;

	return pkm_lcs_runtime_limits_publish_self_config_plan(&plan,
							      result_out);
}

long pkm_lcs_runtime_limits_refresh_self_config_from_key(
	u32 source_id, const u8 registry_guid[RSI_GUID_SIZE],
	struct pkm_lcs_self_config_apply_plan *result_out)
{
	struct pkm_lcs_self_config_apply_plan *plan = NULL;
	struct pkm_lcs_runtime_limits active_limits = { };
	struct pkm_lcs_source_response_frame frame;
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_layer_snapshot layers = { };
	u64 next_sequence = 0;
	long ret;

	if (!source_id || !registry_guid)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_runtime_limits_snapshot(&active_limits);
	if (ret)
		return ret;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		source_id, 0, registry_guid, "", 0, true, &active_limits,
		active_limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		goto out_frame;

	plan = kzalloc(sizeof(*plan), GFP_KERNEL);
	if (!plan) {
		ret = -ENOMEM;
		goto out_frame;
	}

	ret = lcs_rust_plan_self_config_apply_from_query_values(
		&active_limits, frame.data, frame.len, response.request_id,
		next_sequence, layers.layers, layers.layer_count, NULL, 0,
		plan);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_runtime_limits_publish_self_config_plan(plan,
							      result_out);

out_frame:
	trace_lcs_self_config_refresh(source_id, 1, 0, 0,
				      LCS_BOOT_SELF_CONFIG_REFRESH, ret);
	kfree(plan);
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

long pkm_lcs_self_config_registry_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	bool *present_out, u8 registry_guid_out[RSI_GUID_SIZE])
{
	static const struct pkm_lcs_path_component_view registry_path[] = {
		{ .name = "Machine", .name_len = sizeof("Machine") - 1 },
		{ .name = "System", .name_len = sizeof("System") - 1 },
		{ .name = "Registry", .name_len = sizeof("Registry") - 1 },
	};
	struct pkm_lcs_resolved_key_path registry = { };
	struct pkm_lcs_layer_snapshot layers = { };
	long ret;

	if (present_out)
		*present_out = false;
	if (registry_guid_out)
		memset(registry_guid_out, 0, RSI_GUID_SIZE);
	if (!source_id || !machine_root_guid || !present_out ||
	    !registry_guid_out)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components(
		source_id, 0, machine_root_guid, registry_path,
		ARRAY_SIZE(registry_path), layers.layers, layers.layer_count,
		NULL, 0, &registry);
	if (ret == -ENOENT) {
		ret = 0;
		goto out_layers;
	}
	if (ret)
		goto out_layers;

	memcpy(registry_guid_out, registry.key_guid, RSI_GUID_SIZE);
	*present_out = true;

	pkm_lcs_resolved_key_path_destroy(&registry);
out_layers:
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

long pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_self_config_apply_plan *result_out)
{
	struct pkm_lcs_self_config_apply_plan empty_plan = { };
	u8 registry_guid[RSI_GUID_SIZE] = { };
	bool present = false;
	long ret;

	if (result_out)
		*result_out = empty_plan;
	if (!source_id || !machine_root_guid)
		return -EINVAL;

	ret = pkm_lcs_self_config_registry_root_discover_from_machine_hive(
		source_id, machine_root_guid, &present, registry_guid);
	if (ret || !present)
		return ret;

	return pkm_lcs_runtime_limits_refresh_self_config_from_key(
		source_id, registry_guid, result_out);
}
