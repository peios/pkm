// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source late-response effect ownership helpers.
 */

#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "source_device.h"

void pkm_lcs_source_late_effect_destroy(
	struct pkm_lcs_source_late_effect *effect)
{
	u32 i;

	if (!effect)
		return;
	if (effect->resolved_path) {
		for (i = 0; i < effect->path_component_count; i++)
			kfree(effect->resolved_path[i]);
		kfree(effect->resolved_path);
	}
	kfree(effect->name);
	kfree(effect->ancestor_guids);
	memset(effect, 0, sizeof(*effect));
}

void pkm_lcs_source_late_effect_move(struct pkm_lcs_source_late_effect *dst,
				     struct pkm_lcs_source_late_effect *src)
{
	if (!dst || !src)
		return;

	pkm_lcs_source_late_effect_destroy(dst);
	*dst = *src;
	memset(src, 0, sizeof(*src));
}

long pkm_lcs_source_late_effect_copy_restore(
	struct pkm_lcs_source_late_effect *dst,
	const struct pkm_lcs_source_restore_commit_late_effect_input *input)
{
	size_t guid_bytes;
	u32 i;

	if (!dst || !input || !input->key_guid || !input->ancestor_guids ||
	    !input->resolved_path || !input->path_component_count)
		return -EINVAL;
	if (input->path_component_count > PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;
	if (check_mul_overflow((size_t)input->path_component_count,
			       sizeof(*dst->ancestor_guids), &guid_bytes))
		return -EOVERFLOW;

	dst->resolved_path = kcalloc(input->path_component_count,
				     sizeof(*dst->resolved_path), GFP_KERNEL);
	if (!dst->resolved_path)
		return -ENOMEM;
	dst->ancestor_guids = kmemdup(input->ancestor_guids, guid_bytes,
				      GFP_KERNEL);
	if (!dst->ancestor_guids) {
		pkm_lcs_source_late_effect_destroy(dst);
		return -ENOMEM;
	}

	for (i = 0; i < input->path_component_count; i++) {
		if (!input->resolved_path[i]) {
			pkm_lcs_source_late_effect_destroy(dst);
			return -EINVAL;
		}
		dst->resolved_path[i] = kstrdup(input->resolved_path[i],
						GFP_KERNEL);
		if (!dst->resolved_path[i]) {
			pkm_lcs_source_late_effect_destroy(dst);
			return -ENOMEM;
		}
	}

	dst->kind = PKM_LCS_SOURCE_LATE_EFFECT_RESTORE_COMMIT;
	dst->path_component_count = input->path_component_count;
	memcpy(dst->key_guid, input->key_guid, sizeof(dst->key_guid));
	return 0;
}

long pkm_lcs_source_late_effect_copy_key_mutation(
	struct pkm_lcs_source_late_effect *dst,
	const struct pkm_lcs_source_key_mutation_late_effect_input *input)
{
	size_t guid_bytes;
	u32 i;

	if (!dst || !input || !input->key_guid || !input->ancestor_guids ||
	    !input->resolved_path || !input->path_component_count)
		return -EINVAL;
	if (input->name_len && !input->name)
		return -EINVAL;
	if (input->path_component_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    input->name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -EINVAL;
	if (!(input->flags &
	      (PKM_LCS_SOURCE_LATE_EFFECT_RECORD_GENERATION |
	       PKM_LCS_SOURCE_LATE_EFFECT_DISPATCH_WATCH |
	       PKM_LCS_SOURCE_LATE_EFFECT_DISPATCH_OVERFLOW |
	       PKM_LCS_SOURCE_LATE_EFFECT_LAYER_RECOVERY)))
		return -EINVAL;
	if (check_mul_overflow((size_t)input->path_component_count,
			       sizeof(*dst->ancestor_guids), &guid_bytes))
		return -EOVERFLOW;

	dst->resolved_path = kcalloc(input->path_component_count,
				     sizeof(*dst->resolved_path), GFP_KERNEL);
	if (!dst->resolved_path)
		return -ENOMEM;
	dst->ancestor_guids = kmemdup(input->ancestor_guids, guid_bytes,
				      GFP_KERNEL);
	if (!dst->ancestor_guids) {
		pkm_lcs_source_late_effect_destroy(dst);
		return -ENOMEM;
	}
	if (input->name_len) {
		dst->name = kmemdup(input->name, input->name_len, GFP_KERNEL);
		if (!dst->name) {
			pkm_lcs_source_late_effect_destroy(dst);
			return -ENOMEM;
		}
	}

	for (i = 0; i < input->path_component_count; i++) {
		if (!input->resolved_path[i]) {
			pkm_lcs_source_late_effect_destroy(dst);
			return -EINVAL;
		}
		dst->resolved_path[i] = kstrdup(input->resolved_path[i],
						GFP_KERNEL);
		if (!dst->resolved_path[i]) {
			pkm_lcs_source_late_effect_destroy(dst);
			return -ENOMEM;
		}
	}

	dst->kind = PKM_LCS_SOURCE_LATE_EFFECT_KEY_MUTATION;
	dst->path_component_count = input->path_component_count;
	dst->name_len = input->name_len;
	dst->event_type = input->event_type;
	dst->flags = input->flags;
	memcpy(dst->key_guid, input->key_guid, sizeof(dst->key_guid));
	return 0;
}
