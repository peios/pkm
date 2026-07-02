// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS access and create/open preflight planning.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <trace/events/lcs.h>

#include "../kacs/access_check.h"
#include "../kacs/caap_cache.h"
#include "../kacs/token_runtime.h"
#include "source_device.h"

extern int lcs_rust_open_preflight(
	u32 desired_access, u32 flags,
	struct pkm_lcs_open_preflight_plan *plan);
extern int lcs_rust_validate_key_create_flags(
	u32 flags, struct pkm_lcs_key_create_options *options);
extern int lcs_rust_plan_key_guid_assignment(
	const u8 candidate_guid[16], const u8 (*active_key_guids)[16],
	size_t active_key_guid_count,
	struct pkm_lcs_key_guid_assignment_plan *plan);
extern int lcs_rust_select_layer_metadata_sd(
	const u8 *layer_name, u32 layer_name_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	size_t metadata_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_metadata_sd_selection *selection);
extern int lcs_rust_key_open_access_plan(
	const void *subject_token, const u8 *sd_ptr, size_t sd_len,
	u32 desired_access, u32 pip_type, u32 pip_trust,
	const void *caap_cache,
	struct pkm_lcs_key_open_access_plan *plan);

long pkm_lcs_open_preflight(u32 desired_access, u32 flags,
			    struct pkm_lcs_open_preflight_plan *plan)
{
	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	return lcs_rust_open_preflight(desired_access, flags, plan);
}

long pkm_lcs_create_preflight(u32 desired_access, u32 flags,
			      struct pkm_lcs_create_preflight_plan *plan)
{
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	ret = pkm_lcs_open_preflight(desired_access, 0, &plan->access);
	if (ret) {
		memset(plan, 0, sizeof(*plan));
		return ret;
	}

	ret = lcs_rust_validate_key_create_flags(flags, &plan->options);
	if (ret)
		memset(plan, 0, sizeof(*plan));
	return ret;
}

long pkm_lcs_key_open_access_check_for_token(
	const void *token, const u8 *sd, size_t sd_len, u32 desired_access,
	struct pkm_lcs_key_open_access_plan *plan)
{
	const void *caap_cache = NULL;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!token)
		return -EACCES;
	if (!sd || !sd_len || !desired_access)
		return -EINVAL;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret)
		return ret;
	ret = lcs_rust_key_open_access_plan(token, sd, sd_len, desired_access,
					    pip_type, pip_trust, caap_cache,
					    plan);
	pkm_kacs_caap_cache_unlock();
	trace_lcs_access_check(0, NULL, desired_access, plan->fd_granted_access,
			       plan->allowed, ret);
	return ret;
}

long pkm_lcs_layer_write_access_check_for_token(
	const void *token, const u8 *metadata_sd, size_t metadata_sd_len,
	struct pkm_lcs_key_open_access_plan *plan)
{
	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!metadata_sd || !metadata_sd_len)
		return -EIO;

	return pkm_lcs_key_open_access_check_for_token(
		token, metadata_sd, metadata_sd_len, KEY_SET_VALUE, plan);
}

long pkm_lcs_base_layer_write_access_check_for_token(
	const void *token, bool base_metadata_present,
	const u8 *base_metadata_sd, size_t base_metadata_sd_len,
	struct pkm_lcs_key_open_access_plan *plan)
{
	const u8 *default_sd;
	size_t default_sd_len = 0;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (base_metadata_present)
		return pkm_lcs_layer_write_access_check_for_token(
			token, base_metadata_sd, base_metadata_sd_len, plan);

	default_sd = kacs_rust_create_lcs_base_layer_default_sd(
		&default_sd_len);
	if (!default_sd || !default_sd_len)
		return -ENOMEM;

	ret = pkm_lcs_layer_write_access_check_for_token(
		token, default_sd, default_sd_len, plan);
	pkm_kacs_free((void *)default_sd);
	return ret;
}

long pkm_lcs_create_layer_write_access_check_for_token_with_limits(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	u32 metadata_count, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_key_open_access_plan *plan)
{
	struct pkm_lcs_layer_metadata_sd_selection selection = { };
	const struct pkm_lcs_layer_metadata_sd_view *selected;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!target || !target->name || !limits)
		return -EINVAL;

	/*
	 * The base layer is hardcoded and has no metadata-table row, so a
	 * caller that names it explicitly ("base") must be authorized through
	 * the base-layer path just like an implicit (omitted) layer -- routing
	 * an explicit "base" through the metadata-SD lookup below would fail
	 * EIO because no cached authorization SD exists for it.
	 */
	if (target->implicit_base ||
	    pkm_lcs_layer_name_is_base(target->name, target->name_len))
		return pkm_lcs_base_layer_write_access_check_for_token(
			token, base_metadata_present, base_metadata_sd,
			base_metadata_sd_len, plan);

	if (metadata_count && !metadata)
		return -EINVAL;

	ret = lcs_rust_select_layer_metadata_sd(
		(const u8 *)target->name, target->name_len, metadata,
		metadata_count, limits, &selection);
	if (ret)
		return ret;
	if (selection.index >= metadata_count)
		return -EIO;

	selected = &metadata[selection.index];
	return pkm_lcs_layer_write_access_check_for_token(
		token, selected->sd, selected->sd_len, plan);
}

long pkm_lcs_create_layer_write_access_check_for_token(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	u32 metadata_count, struct pkm_lcs_key_open_access_plan *plan)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_create_layer_write_access_check_for_token_with_limits(
		token, target, base_metadata_present, base_metadata_sd,
		base_metadata_sd_len, metadata, metadata_count, &limits, plan);
}

long pkm_lcs_live_layer_write_access_check_for_token(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_key_open_access_plan *plan)
{
	struct pkm_lcs_layer_target_admission_plan target_plan = { };
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits;
	long ret;

	if (!plan)
		return -EINVAL;
	memset(plan, 0, sizeof(*plan));
	if (!target || !target->name)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&snapshot);
	if (ret)
		return ret;
	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_create_layer_target_admit_with_limits(
		target, snapshot.layers, snapshot.layer_count, &limits,
		&target_plan);
	if (ret)
		goto out_snapshot;
	ret = pkm_lcs_create_layer_write_access_check_for_token_with_limits(
		token, target, snapshot.base_metadata_present,
		snapshot.base_metadata_sd, snapshot.base_metadata_sd_len,
		snapshot.metadata, snapshot.metadata_count, &limits, plan);

out_snapshot:
	pkm_lcs_source_layer_snapshot_release(&snapshot);
	return ret;
}

static void pkm_lcs_default_key_guid_generate(void *ctx, u8 guid[16])
{
	(void)ctx;

	pkm_kacs_fill_uuid_v4(guid);
}

long pkm_lcs_assign_new_key_guid(
	const u8 (*active_key_guids)[16], u32 active_key_guid_count,
	const struct pkm_lcs_key_guid_generator *generator,
	struct pkm_lcs_key_guid_assignment_plan *plan)
{
	pkm_lcs_key_guid_generator_fn generate =
		pkm_lcs_default_key_guid_generate;
	void *generate_ctx = NULL;
	u8 candidate[16];
	u32 attempt;
	int ret = -EIO;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (active_key_guid_count && !active_key_guids)
		return -EINVAL;
	if (generator) {
		if (!generator->generate)
			return -EINVAL;
		generate = generator->generate;
		generate_ctx = generator->ctx;
	}

	BUILD_BUG_ON(sizeof(candidate) != KACS_UUID_BYTES);

	for (attempt = 0; attempt < PKM_LCS_KEY_GUID_ASSIGNMENT_MAX_ATTEMPTS;
	     attempt++) {
		memset(candidate, 0, sizeof(candidate));
		generate(generate_ctx, candidate);
		ret = lcs_rust_plan_key_guid_assignment(
			candidate, active_key_guids, active_key_guid_count, plan);
		if (!ret)
			return 0;
		if (ret != -EIO)
			return ret;
	}

	memset(plan, 0, sizeof(*plan));
	trace_lcs_assign_key_guid(0, attempt,
				  PKM_LCS_KEY_GUID_ASSIGNMENT_MAX_ATTEMPTS,
				  -EIO);
	return -EIO;
}
