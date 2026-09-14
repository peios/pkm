// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS layer table and base-layer snapshot state.
 */

#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "../kacs/token_runtime.h"
#include "rsi.h"
#include "source_device.h"

#include <trace/events/lcs.h>

struct pkm_lcs_layer_table_entry {
	bool occupied;
	u8 enabled;
	u8 _pad[2];
	u32 name_len;
	u32 precedence;
	char name[PKM_LCS_MAX_LAYER_NAME_BYTES_HARD + 1U];
	u8 metadata_key_guid[RSI_GUID_SIZE];
	u8 *metadata_sd;
	size_t metadata_sd_len;
	u8 *owner_sid;
	size_t owner_sid_len;
};

struct pkm_lcs_base_layer_metadata_entry {
	bool present;
	u8 metadata_key_guid[RSI_GUID_SIZE];
	u8 *metadata_sd;
	size_t metadata_sd_len;
};

static DEFINE_MUTEX(pkm_lcs_layer_table_lock);
static struct pkm_lcs_layer_table_entry
	pkm_lcs_layer_table[PKM_LCS_MAX_DYNAMIC_LAYERS_DEFAULT];
static struct pkm_lcs_base_layer_metadata_entry pkm_lcs_base_layer_metadata;

static const char pkm_lcs_base_layer_name[] = "base";
static const struct pkm_lcs_rsi_layer_view pkm_lcs_base_layer_snapshot[] = {
	{
		.name = pkm_lcs_base_layer_name,
		.name_len = sizeof(pkm_lcs_base_layer_name) - 1,
		.precedence = 0,
		.enabled = 1,
	},
};

extern int lcs_rust_validate_layer_publication(
	const u8 *layer_name, u32 layer_name_len,
	const u8 metadata_key_guid[16], const u8 *metadata_security_descriptor,
	size_t metadata_security_descriptor_len, u32 precedence, u8 enabled,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_select_layer_owner(
	const u8 *metadata_owner_sid, size_t metadata_owner_sid_len,
	bool metadata_owner_present, const u8 *creator_sid,
	size_t creator_sid_len, bool creator_present,
	const u8 *previous_owner_sid, size_t previous_owner_sid_len,
	bool previous_owner_present, const u8 *metadata_security_descriptor,
	size_t metadata_security_descriptor_len,
	bool metadata_security_descriptor_present, bool is_new_layer,
	struct pkm_lcs_layer_owner_selection_copy *selection_out);
extern int lcs_rust_layer_name_casefold_eq(
	const u8 *left, u32 left_len, const u8 *right, u32 right_len,
	const struct pkm_lcs_runtime_limits *limits,
	u8 *equal_out);

long pkm_lcs_layer_name_casefold_equal_with_limits(
	const char *left, u32 left_len, const char *right, u32 right_len,
	const struct pkm_lcs_runtime_limits *limits, bool *equal)
{
	u8 raw_equal = 0;
	int ret;

	if (!equal)
		return -EINVAL;
	*equal = false;
	if (!left || !right || !limits)
		return -EINVAL;

	ret = lcs_rust_layer_name_casefold_eq((const u8 *)left, left_len,
					      (const u8 *)right, right_len,
					      limits, &raw_equal);
	if (ret)
		return ret;
	*equal = raw_equal != 0;
	return 0;
}

static long pkm_lcs_layer_name_casefold_equal(const char *left, u32 left_len,
					      const char *right, u32 right_len,
					      bool *equal)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_layer_name_casefold_equal_with_limits(
		left, left_len, right, right_len, &limits, equal);
}

long pkm_lcs_layer_name_casefold_is_base(const char *layer_name,
					 u32 layer_name_len, bool *is_base)
{
	return pkm_lcs_layer_name_casefold_equal(
		layer_name, layer_name_len, pkm_lcs_base_layer_name,
		sizeof(pkm_lcs_base_layer_name) - 1, is_base);
}

/*
 * As above, but against limits the caller already holds. Layer identity is the
 * case-folded name, so the reserved name is recognised the same way every other
 * layer name is compared. There used to be a second, ASCII comparator
 * (strncasecmp) beside this one; the two agreed only because the length
 * pre-check made a non-ASCII case pair fail before folding could matter, which
 * made the divergence latent rather than absent (PEI-279).
 */
long pkm_lcs_layer_name_casefold_is_base_with_limits(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, bool *is_base)
{
	return pkm_lcs_layer_name_casefold_equal_with_limits(
		layer_name, layer_name_len, pkm_lcs_base_layer_name,
		sizeof(pkm_lcs_base_layer_name) - 1, limits, is_base);
}

void pkm_lcs_create_layer_target_set_base(
	struct pkm_lcs_create_layer_target *target)
{
	if (!target)
		return;

	target->name = pkm_lcs_base_layer_name;
	target->name_len = sizeof(pkm_lcs_base_layer_name) - 1;
	target->implicit_base = 1;
}

static void pkm_lcs_layer_table_entry_destroy(
	struct pkm_lcs_layer_table_entry *entry)
{
	kfree(entry->metadata_sd);
	kfree(entry->owner_sid);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_base_layer_metadata_destroy_locked(void)
{
	lockdep_assert_held(&pkm_lcs_layer_table_lock);

	kfree(pkm_lcs_base_layer_metadata.metadata_sd);
	memset(&pkm_lcs_base_layer_metadata, 0,
	       sizeof(pkm_lcs_base_layer_metadata));
}

static u32 pkm_lcs_layer_table_count_locked(void)
{
	u32 count = 1U;
	u32 i;

	lockdep_assert_held(&pkm_lcs_layer_table_lock);

	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		if (pkm_lcs_layer_table[i].occupied)
			count++;
	}
	return count;
}

u32 pkm_lcs_layer_table_count(void)
{
	u32 count;

	mutex_lock(&pkm_lcs_layer_table_lock);
	count = pkm_lcs_layer_table_count_locked();
	mutex_unlock(&pkm_lcs_layer_table_lock);
	return count;
}

static long pkm_lcs_layer_table_shape_locked(u32 *count_out,
					     size_t *name_bytes_out,
					     size_t *metadata_sd_bytes_out)
{
	size_t name_bytes = 0;
	size_t metadata_sd_bytes = 0;
	u32 count = 1U;
	u32 i;

	lockdep_assert_held(&pkm_lcs_layer_table_lock);

	if (pkm_lcs_base_layer_metadata.present) {
		if (!pkm_lcs_base_layer_metadata.metadata_sd ||
		    !pkm_lcs_base_layer_metadata.metadata_sd_len)
			return -EIO;
		if (check_add_overflow(
			    metadata_sd_bytes,
			    pkm_lcs_base_layer_metadata.metadata_sd_len,
			    &metadata_sd_bytes))
			return -EOVERFLOW;
	}

	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		if (!pkm_lcs_layer_table[i].occupied)
			continue;
		if (!pkm_lcs_layer_table[i].metadata_sd ||
		    !pkm_lcs_layer_table[i].metadata_sd_len ||
		    !pkm_lcs_layer_table[i].owner_sid ||
		    !pkm_lcs_layer_table[i].owner_sid_len)
			return -EIO;
		count++;
		if (check_add_overflow(
			    name_bytes,
			    (size_t)pkm_lcs_layer_table[i].name_len + 1U,
			    &name_bytes))
			return -EOVERFLOW;
		if (check_add_overflow(
			    metadata_sd_bytes,
			    pkm_lcs_layer_table[i].metadata_sd_len,
			    &metadata_sd_bytes))
			return -EOVERFLOW;
	}

	if (count_out)
		*count_out = count;
	if (name_bytes_out)
		*name_bytes_out = name_bytes;
	if (metadata_sd_bytes_out)
		*metadata_sd_bytes_out = metadata_sd_bytes;
	return 0;
}

long pkm_lcs_normalize_layer_inputs(
	const struct pkm_lcs_rsi_layer_view **layers, u32 *layer_count,
	const struct pkm_lcs_rsi_private_layer_view **private_layers,
	u32 *private_layer_count)
{
	if (!layers || !layer_count || !private_layers || !private_layer_count)
		return -EINVAL;
	if (*layer_count && !*layers)
		return -EINVAL;
	if (*private_layer_count && !*private_layers)
		return -EINVAL;
	if (!*layer_count) {
		*layers = pkm_lcs_base_layer_snapshot;
		*layer_count = ARRAY_SIZE(pkm_lcs_base_layer_snapshot);
	}
	return 0;
}

void pkm_lcs_source_base_layer_snapshot(
	const struct pkm_lcs_rsi_layer_view **layers, u32 *layer_count)
{
	if (layers)
		*layers = pkm_lcs_base_layer_snapshot;
	if (layer_count)
		*layer_count = ARRAY_SIZE(pkm_lcs_base_layer_snapshot);
}

long pkm_lcs_private_credentials_acquire_for_token(
	const void *token, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_private_credential_view *view)
{
	const char *private_layer_name;
	u32 private_layer_name_len;
	u32 private_layer_count;
	u32 scope_count;
	u32 i;
	int ret;

	if (!view || !limits)
		return -EINVAL;
	memset(view, 0, sizeof(*view));
	if (!token)
		return -EACCES;

	/*
	 * The configured caps are checked here, at use, rather than when the
	 * token was built. KACS applies only its own hard 256 when it parses
	 * the credential extension, because reading LCS's configured limits
	 * from KACS would invert the dependency between them.
	 *
	 * So an over-cap token is accepted and then fails every registry
	 * operation any thread holding it performs. That is E2BIG and not
	 * EACCES: nothing about it is an access decision, and reporting a
	 * denial sends whoever is debugging it towards descriptors and
	 * privileges instead of towards a count that was fixed when the token
	 * was assembled, possibly in another process.
	 */
	scope_count = kacs_rust_token_lcs_scope_guid_count(token);
	private_layer_count = kacs_rust_token_lcs_private_layer_count(token);
	if (scope_count > limits->max_scope_guids_per_token ||
	    private_layer_count > limits->max_private_layers_per_token)
		return -E2BIG;

	if (scope_count) {
		view->scope_guids = kcalloc(scope_count,
					    sizeof(*view->scope_guids),
					    GFP_KERNEL);
		if (!view->scope_guids)
			return -ENOMEM;

		for (i = 0; i < scope_count; i++) {
			ret = kacs_rust_token_lcs_scope_guid(
				token, i, view->scope_guids[i]);
			if (ret)
				goto out_error;
		}
		view->scope_count = scope_count;
	}

	if (private_layer_count) {
		view->private_layers = kcalloc(private_layer_count,
					       sizeof(*view->private_layers),
					       GFP_KERNEL);
		if (!view->private_layers) {
			ret = -ENOMEM;
			goto out_error;
		}

		for (i = 0; i < private_layer_count; i++) {
			ret = kacs_rust_token_lcs_private_layer(
				token, i, &private_layer_name,
				&private_layer_name_len);
			if (ret)
				goto out_error;
			view->private_layers[i].name = private_layer_name;
			view->private_layers[i].name_len =
				private_layer_name_len;
		}
		view->private_layer_count = private_layer_count;
	}

	return 0;

out_error:
	pkm_lcs_private_credentials_release(view);
	return ret;
}

void pkm_lcs_private_credentials_release(
	struct pkm_lcs_private_credential_view *view)
{
	if (!view)
		return;

	kfree(view->scope_guids);
	kfree(view->private_layers);
	memset(view, 0, sizeof(*view));
}

long pkm_lcs_source_layer_snapshot_copy(
	struct pkm_lcs_rsi_layer_view *layers, u32 max_layers,
	char *name_buf, size_t name_buf_len, u32 *count_out)
{
	size_t name_offset = 0;
	u32 written = 0;
	u32 required;
	u32 i;

	if (!layers || !count_out)
		return -EINVAL;

	mutex_lock(&pkm_lcs_layer_table_lock);
	required = pkm_lcs_layer_table_count_locked();
	*count_out = required;
	if (max_layers < required) {
		mutex_unlock(&pkm_lcs_layer_table_lock);
		return -ENOSPC;
	}

	layers[written++] = pkm_lcs_base_layer_snapshot[0];
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		struct pkm_lcs_layer_table_entry *entry =
			&pkm_lcs_layer_table[i];
		char *name_dst;

		if (!entry->occupied)
			continue;
		if (!name_buf ||
		    name_offset + entry->name_len + 1U > name_buf_len) {
			mutex_unlock(&pkm_lcs_layer_table_lock);
			return -ENOSPC;
		}

		name_dst = name_buf + name_offset;
		memcpy(name_dst, entry->name, entry->name_len);
		name_dst[entry->name_len] = '\0';
		name_offset += entry->name_len + 1U;

		layers[written].name = name_dst;
		layers[written].name_len = entry->name_len;
		layers[written].precedence = entry->precedence;
		layers[written].enabled = entry->enabled;
		memset(layers[written]._pad, 0, sizeof(layers[written]._pad));
		written++;
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);

	return 0;
}

static long pkm_lcs_source_layer_snapshot_copy_full(
	struct pkm_lcs_rsi_layer_view *layers, u32 max_layers,
	char *name_buf, size_t name_buf_len,
	struct pkm_lcs_layer_metadata_sd_view *metadata, u32 max_metadata,
	u8 *metadata_sd_buf, size_t metadata_sd_buf_len, u32 *count_out,
	bool *base_metadata_present_out, const u8 **base_metadata_sd_out,
	size_t *base_metadata_sd_len_out, u32 *metadata_count_out)
{
	size_t name_offset = 0;
	size_t metadata_sd_offset = 0;
	u32 metadata_written = 0;
	u32 written = 0;
	u32 required;
	u32 required_metadata;
	u32 i;

	if (!layers || !count_out || !base_metadata_present_out ||
	    !base_metadata_sd_out || !base_metadata_sd_len_out ||
	    !metadata_count_out)
		return -EINVAL;
	*base_metadata_present_out = false;
	*base_metadata_sd_out = NULL;
	*base_metadata_sd_len_out = 0;

	mutex_lock(&pkm_lcs_layer_table_lock);
	required = pkm_lcs_layer_table_count_locked();
	required_metadata = required - 1U;
	*count_out = required;
	*metadata_count_out = required_metadata;
	if (max_layers < required || max_metadata < required_metadata) {
		mutex_unlock(&pkm_lcs_layer_table_lock);
		return -ENOSPC;
	}
	if (required_metadata &&
	    (!metadata || !name_buf || !metadata_sd_buf)) {
		mutex_unlock(&pkm_lcs_layer_table_lock);
		return -ENOSPC;
	}
	if (pkm_lcs_base_layer_metadata.present &&
	    (!metadata_sd_buf ||
	     pkm_lcs_base_layer_metadata.metadata_sd_len >
		     metadata_sd_buf_len)) {
		mutex_unlock(&pkm_lcs_layer_table_lock);
		return -ENOSPC;
	}

	layers[written++] = pkm_lcs_base_layer_snapshot[0];
	if (pkm_lcs_base_layer_metadata.present) {
		if (!pkm_lcs_base_layer_metadata.metadata_sd ||
		    !pkm_lcs_base_layer_metadata.metadata_sd_len) {
			mutex_unlock(&pkm_lcs_layer_table_lock);
			return -EIO;
		}
		memcpy(metadata_sd_buf, pkm_lcs_base_layer_metadata.metadata_sd,
		       pkm_lcs_base_layer_metadata.metadata_sd_len);
		*base_metadata_present_out = true;
		*base_metadata_sd_out = metadata_sd_buf;
		*base_metadata_sd_len_out =
			pkm_lcs_base_layer_metadata.metadata_sd_len;
		metadata_sd_offset +=
			pkm_lcs_base_layer_metadata.metadata_sd_len;
	}
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		struct pkm_lcs_layer_table_entry *entry =
			&pkm_lcs_layer_table[i];
		char *name_dst;
		u8 *sd_dst;

		if (!entry->occupied)
			continue;
		if (!entry->metadata_sd || !entry->metadata_sd_len ||
		    !entry->owner_sid || !entry->owner_sid_len) {
			mutex_unlock(&pkm_lcs_layer_table_lock);
			return -EIO;
		}
		if (name_offset + entry->name_len + 1U > name_buf_len ||
		    metadata_sd_offset + entry->metadata_sd_len >
			    metadata_sd_buf_len) {
			mutex_unlock(&pkm_lcs_layer_table_lock);
			return -ENOSPC;
		}

		name_dst = name_buf + name_offset;
		memcpy(name_dst, entry->name, entry->name_len);
		name_dst[entry->name_len] = '\0';
		name_offset += entry->name_len + 1U;

		sd_dst = metadata_sd_buf + metadata_sd_offset;
		memcpy(sd_dst, entry->metadata_sd, entry->metadata_sd_len);
		metadata_sd_offset += entry->metadata_sd_len;

		layers[written].name = name_dst;
		layers[written].name_len = entry->name_len;
		layers[written].precedence = entry->precedence;
		layers[written].enabled = entry->enabled;
		memset(layers[written]._pad, 0, sizeof(layers[written]._pad));
		written++;

		metadata[metadata_written].name = name_dst;
		metadata[metadata_written].sd = sd_dst;
		metadata[metadata_written].sd_len = entry->metadata_sd_len;
		metadata[metadata_written].name_len = entry->name_len;
		metadata[metadata_written]._pad = 0;
		metadata_written++;
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);

	*count_out = written;
	*metadata_count_out = metadata_written;
	return 0;
}

long pkm_lcs_source_layer_snapshot_acquire(
	struct pkm_lcs_layer_snapshot *snapshot)
{
	struct pkm_lcs_layer_metadata_sd_view *metadata = NULL;
	struct pkm_lcs_rsi_layer_view *layers = NULL;
	const u8 *base_metadata_sd = NULL;
	size_t metadata_sd_bytes = 0;
	size_t base_metadata_sd_len = 0;
	size_t name_bytes = 0;
	u8 *metadata_sds = NULL;
	char *names = NULL;
	bool base_metadata_present = false;
	u32 metadata_count = 0;
	u32 metadata_written = 0;
	u32 count = 0;
	u32 written = 0;
	u32 attempt;
	long ret;

	if (!snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));

	for (attempt = 0; attempt < 3; attempt++) {
		mutex_lock(&pkm_lcs_layer_table_lock);
		ret = pkm_lcs_layer_table_shape_locked(
			&count, &name_bytes, &metadata_sd_bytes);
		mutex_unlock(&pkm_lcs_layer_table_lock);
		if (ret)
			return ret;

		if (!count || count > PKM_LCS_MAX_TOTAL_LAYERS_DEFAULT)
			return -EIO;
		metadata_count = count - 1U;

		layers = kvcalloc(count, sizeof(*layers), GFP_KERNEL);
		if (!layers)
			return -ENOMEM;
		if (metadata_count) {
			metadata = kvcalloc(metadata_count, sizeof(*metadata),
					    GFP_KERNEL);
			if (!metadata) {
				kvfree(layers);
				return -ENOMEM;
			}
		}
		if (name_bytes) {
			names = kvmalloc(name_bytes, GFP_KERNEL);
			if (!names) {
				kvfree(metadata);
				kvfree(layers);
				return -ENOMEM;
			}
		}
		if (metadata_sd_bytes) {
			metadata_sds = kvmalloc(metadata_sd_bytes, GFP_KERNEL);
			if (!metadata_sds) {
				kvfree(names);
				kvfree(metadata);
				kvfree(layers);
				return -ENOMEM;
			}
		}

		ret = pkm_lcs_source_layer_snapshot_copy_full(
			layers, count, names, name_bytes, metadata,
			metadata_count, metadata_sds, metadata_sd_bytes,
			&written, &base_metadata_present, &base_metadata_sd,
			&base_metadata_sd_len, &metadata_written);
		if (!ret) {
			snapshot->layers = layers;
			snapshot->layer_count = written;
			snapshot->base_metadata_present =
				base_metadata_present;
			snapshot->base_metadata_sd = base_metadata_sd;
			snapshot->base_metadata_sd_len =
				base_metadata_sd_len;
			snapshot->metadata = metadata;
			snapshot->metadata_count = metadata_written;
			snapshot->owned_layers = layers;
			snapshot->owned_names = names;
			snapshot->owned_metadata = metadata;
			snapshot->owned_metadata_sds = metadata_sds;
			trace_lcs_layer_snapshot(0, 0, 0, written,
						 base_metadata_present ? 1 : 0,
						 0, 0);
			return 0;
		}

		kvfree(metadata_sds);
		kvfree(names);
		kvfree(metadata);
		kvfree(layers);
		metadata_sds = NULL;
		names = NULL;
		metadata = NULL;
		layers = NULL;
		if (ret != -ENOSPC) {
			trace_lcs_layer_snapshot(0, 0, 0, 0, 0, 0, ret);
			return ret;
		}
	}

	trace_lcs_layer_snapshot(0, 0, 0, 0, 0, 0, -ENOSPC);
	return -ENOSPC;
}

void pkm_lcs_source_layer_snapshot_release(
	struct pkm_lcs_layer_snapshot *snapshot)
{
	if (!snapshot)
		return;

	kvfree(snapshot->owned_metadata_sds);
	kvfree(snapshot->owned_metadata);
	kvfree(snapshot->owned_names);
	kvfree(snapshot->owned_layers);
	memset(snapshot, 0, sizeof(*snapshot));
}

long pkm_lcs_layer_table_owner_snapshot(
	const char *layer_name, u32 layer_name_len, u8 **owner_sid_out,
	size_t *owner_sid_len_out, bool *present_out)
{
	u8 *owner_copy = NULL;
	u32 i;
	long ret = 0;

	if (!layer_name || !owner_sid_out || !owner_sid_len_out ||
	    !present_out)
		return -EINVAL;
	*owner_sid_out = NULL;
	*owner_sid_len_out = 0;
	*present_out = false;

	mutex_lock(&pkm_lcs_layer_table_lock);
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		struct pkm_lcs_layer_table_entry *entry =
			&pkm_lcs_layer_table[i];
		bool equal = false;

		if (!entry->occupied)
			continue;
		ret = pkm_lcs_layer_name_casefold_equal(
			layer_name, layer_name_len, entry->name,
			entry->name_len, &equal);
		if (ret)
			break;
		if (!equal)
			continue;
		if (!entry->owner_sid || !entry->owner_sid_len) {
			ret = -EIO;
			break;
		}
		owner_copy = kmemdup(entry->owner_sid, entry->owner_sid_len,
				     GFP_KERNEL);
		if (!owner_copy) {
			ret = -ENOMEM;
			break;
		}
		*owner_sid_out = owner_copy;
		*owner_sid_len_out = entry->owner_sid_len;
		*present_out = true;
		break;
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);
	return ret;
}

long pkm_lcs_layer_owner_select_copy(
	const u8 *metadata_owner_sid, size_t metadata_owner_sid_len,
	bool metadata_owner_present, const u8 *creator_sid,
	size_t creator_sid_len, bool creator_present,
	const u8 *previous_owner_sid, size_t previous_owner_sid_len,
	bool previous_owner_present, const u8 *metadata_sd,
	size_t metadata_sd_len, bool metadata_sd_present, bool is_new_layer,
	u8 **owner_sid_out, size_t *owner_sid_len_out, u32 *source_out)
{
	struct pkm_lcs_layer_owner_selection_copy selection = { };
	u8 *copy;
	int ret;

	if (!owner_sid_out || !owner_sid_len_out)
		return -EINVAL;
	*owner_sid_out = NULL;
	*owner_sid_len_out = 0;
	if (source_out)
		*source_out = 0;

	ret = lcs_rust_select_layer_owner(
		metadata_owner_sid, metadata_owner_sid_len,
		metadata_owner_present, creator_sid, creator_sid_len,
		creator_present, previous_owner_sid, previous_owner_sid_len,
		previous_owner_present, metadata_sd, metadata_sd_len,
		metadata_sd_present, is_new_layer, &selection);
	if (ret)
		return ret;
	if (!selection.owner_sid || !selection.owner_sid_len ||
	    !selection.informational_only)
		return -EIO;

	copy = kmemdup(selection.owner_sid, selection.owner_sid_len,
		      GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	*owner_sid_out = copy;
	*owner_sid_len_out = selection.owner_sid_len;
	if (source_out)
		*source_out = selection.source;
	return 0;
}

static bool pkm_lcs_layer_table_effective_changed(bool existed_before,
						  u8 previous_enabled,
						  u32 previous_precedence,
						  u8 new_enabled,
						  u32 new_precedence)
{
	if (!existed_before)
		return new_enabled != 0;
	if (previous_enabled != new_enabled)
		return true;
	return new_enabled && previous_precedence != new_precedence;
}

long pkm_lcs_layer_table_publish_with_result_with_limits(
	const char *layer_name, u32 layer_name_len, u32 precedence,
	u8 enabled, const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len,
	const u8 *owner_sid, size_t owner_sid_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_table_publish_result *result)
{
	struct pkm_lcs_layer_table_entry *target = NULL;
	u8 *metadata_sd_copy;
	u8 *owner_sid_copy;
	bool existed_before;
	bool effective_changed;
	u8 previous_enabled;
	u32 previous_precedence;
	u32 i;
	int ret;

	if (result)
		memset(result, 0, sizeof(*result));
	if (!layer_name || !metadata_key_guid || !metadata_sd ||
	    !metadata_sd_len || !owner_sid || !owner_sid_len || !limits)
		return -EINVAL;
	if (layer_name_len > PKM_LCS_MAX_LAYER_NAME_BYTES_HARD)
		return -ENAMETOOLONG;

	ret = lcs_rust_validate_layer_publication(
		(const u8 *)layer_name, layer_name_len, metadata_key_guid,
		metadata_sd, metadata_sd_len, precedence, enabled, limits);
	if (ret) {
		trace_lcs_layer_publish(0, layer_name_len,
					jhash(layer_name, layer_name_len, 0),
					precedence, enabled, 0, ret);
		return ret;
	}

	metadata_sd_copy = kmemdup(metadata_sd, metadata_sd_len, GFP_KERNEL);
	if (!metadata_sd_copy)
		return -ENOMEM;
	owner_sid_copy = kmemdup(owner_sid, owner_sid_len, GFP_KERNEL);
	if (!owner_sid_copy) {
		kfree(metadata_sd_copy);
		return -ENOMEM;
	}

	mutex_lock(&pkm_lcs_layer_table_lock);
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		bool equal = false;

		if (!pkm_lcs_layer_table[i].occupied) {
			if (!target)
				target = &pkm_lcs_layer_table[i];
			continue;
		}
		ret = pkm_lcs_layer_name_casefold_equal_with_limits(
			layer_name, layer_name_len, pkm_lcs_layer_table[i].name,
			pkm_lcs_layer_table[i].name_len, limits, &equal);
		if (ret) {
			mutex_unlock(&pkm_lcs_layer_table_lock);
			kfree(metadata_sd_copy);
			kfree(owner_sid_copy);
			return ret;
		}
		if (equal) {
			target = &pkm_lcs_layer_table[i];
			break;
		}
	}
	/*
	 * MaxTotalLayers bounds the whole table, base included (§5.3.1): a
	 * new entry is admitted only while the table holds fewer than that.
	 * Creation is normally refused earlier, at the metadata key, so that
	 * nothing reaches the source; this is the backstop that keeps the
	 * table within the bound every snapshot buffer is sized to (PEI-759).
	 */
	if (!target || (!target->occupied &&
			pkm_lcs_layer_table_count_locked() >=
				limits->max_total_layers)) {
		mutex_unlock(&pkm_lcs_layer_table_lock);
		kfree(metadata_sd_copy);
		kfree(owner_sid_copy);
		return -ENOSPC;
	}

	existed_before = target->occupied;
	previous_enabled = target->enabled;
	previous_precedence = target->precedence;
	effective_changed = pkm_lcs_layer_table_effective_changed(
		existed_before, previous_enabled, previous_precedence, enabled,
		precedence);
	kfree(target->metadata_sd);
	kfree(target->owner_sid);
	memset(target, 0, sizeof(*target));
	target->occupied = true;
	target->enabled = enabled;
	target->name_len = layer_name_len;
	target->precedence = precedence;
	memcpy(target->name, layer_name, layer_name_len);
	target->name[layer_name_len] = '\0';
	memcpy(target->metadata_key_guid, metadata_key_guid, RSI_GUID_SIZE);
	target->metadata_sd = metadata_sd_copy;
	target->metadata_sd_len = metadata_sd_len;
	target->owner_sid = owner_sid_copy;
	target->owner_sid_len = owner_sid_len;
	if (result) {
		result->existed_before = existed_before;
		result->effective_changed = effective_changed;
		result->previous_enabled = previous_enabled;
		result->new_enabled = enabled;
		result->previous_precedence = previous_precedence;
		result->new_precedence = precedence;
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);

	trace_lcs_layer_publish(0, layer_name_len,
				jhash(layer_name, layer_name_len, 0), precedence,
				enabled, effective_changed ? 1 : 0, 0);
	return 0;
}

long pkm_lcs_layer_table_publish_with_result(
	const char *layer_name, u32 layer_name_len, u32 precedence,
	u8 enabled, const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len,
	const u8 *owner_sid, size_t owner_sid_len,
	struct pkm_lcs_layer_table_publish_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_layer_table_publish_with_result_with_limits(
		layer_name, layer_name_len, precedence, enabled,
		metadata_key_guid, metadata_sd, metadata_sd_len, owner_sid,
		owner_sid_len, &limits, result);
}

long pkm_lcs_layer_table_publish(
	const char *layer_name, u32 layer_name_len, u32 precedence,
	u8 enabled, const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len,
	const u8 *owner_sid, size_t owner_sid_len)
{
	return pkm_lcs_layer_table_publish_with_result(
		layer_name, layer_name_len, precedence, enabled,
		metadata_key_guid, metadata_sd, metadata_sd_len, owner_sid,
		owner_sid_len, NULL);
}

long pkm_lcs_base_layer_metadata_publish(
	const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len)
{
	u8 *metadata_sd_copy;
	int ret;

	if (!metadata_key_guid || !metadata_sd || !metadata_sd_len)
		return -EINVAL;
	if (!memchr_inv(metadata_key_guid, 0, RSI_GUID_SIZE))
		return -EIO;

	ret = kacs_rust_validate_stored_sd_bytes(metadata_sd, metadata_sd_len);
	if (ret)
		return -EIO;

	metadata_sd_copy = kmemdup(metadata_sd, metadata_sd_len, GFP_KERNEL);
	if (!metadata_sd_copy)
		return -ENOMEM;

	mutex_lock(&pkm_lcs_layer_table_lock);
	pkm_lcs_base_layer_metadata_destroy_locked();
	pkm_lcs_base_layer_metadata.present = true;
	memcpy(pkm_lcs_base_layer_metadata.metadata_key_guid, metadata_key_guid,
	       RSI_GUID_SIZE);
	pkm_lcs_base_layer_metadata.metadata_sd = metadata_sd_copy;
	pkm_lcs_base_layer_metadata.metadata_sd_len = metadata_sd_len;
	mutex_unlock(&pkm_lcs_layer_table_lock);
	return 0;
}

long pkm_lcs_layer_table_remove_with_limits(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, bool *removed_out)
{
	bool is_base = false;
	bool removed = false;
	u32 i;
	int ret;

	if (removed_out)
		*removed_out = false;
	if (!layer_name || !limits)
		return -EINVAL;

	ret = pkm_lcs_layer_name_casefold_equal_with_limits(
		layer_name, layer_name_len, pkm_lcs_base_layer_name,
		sizeof(pkm_lcs_base_layer_name) - 1, limits, &is_base);
	if (ret)
		return ret;
	if (is_base)
		return -EINVAL;

	mutex_lock(&pkm_lcs_layer_table_lock);
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		bool equal = false;

		if (!pkm_lcs_layer_table[i].occupied)
			continue;
		ret = pkm_lcs_layer_name_casefold_equal_with_limits(
			layer_name, layer_name_len, pkm_lcs_layer_table[i].name,
			pkm_lcs_layer_table[i].name_len, limits, &equal);
		if (ret) {
			mutex_unlock(&pkm_lcs_layer_table_lock);
			return ret;
		}
		if (!equal)
			continue;

		pkm_lcs_layer_table_entry_destroy(&pkm_lcs_layer_table[i]);
		removed = true;
		if (removed_out)
			*removed_out = true;
		break;
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);
	trace_lcs_layer_remove(0, layer_name_len,
			       jhash(layer_name, layer_name_len, 0), 0, 0,
			       removed ? 1 : 0, 0);
	return 0;
}

long pkm_lcs_layer_table_remove(const char *layer_name, u32 layer_name_len,
				bool *removed_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_layer_table_remove_with_limits(
		layer_name, layer_name_len, &limits, removed_out);
}

long pkm_lcs_layer_table_metadata_key_guid_present(
	const u8 metadata_key_guid[RSI_GUID_SIZE], bool *present_out)
{
	u32 i;

	if (!metadata_key_guid || !present_out)
		return -EINVAL;

	*present_out = false;
	mutex_lock(&pkm_lcs_layer_table_lock);
	if (pkm_lcs_base_layer_metadata.present &&
	    !memcmp(pkm_lcs_base_layer_metadata.metadata_key_guid,
		    metadata_key_guid, RSI_GUID_SIZE)) {
		*present_out = true;
		mutex_unlock(&pkm_lcs_layer_table_lock);
		return 0;
	}
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		if (!pkm_lcs_layer_table[i].occupied)
			continue;
		if (!memcmp(pkm_lcs_layer_table[i].metadata_key_guid,
			    metadata_key_guid, RSI_GUID_SIZE)) {
			*present_out = true;
			break;
		}
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);
	return 0;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
/*
 * Leaves a published entry without its owner SID, the half-populated shape
 * publication never produces, so a snapshot reader can be shown refusing it.
 */
long pkm_lcs_kunit_layer_table_strip_owner(const char *layer_name,
					   u32 layer_name_len)
{
	long ret = -ENOENT;
	u32 i;

	if (!layer_name)
		return -EINVAL;
	mutex_lock(&pkm_lcs_layer_table_lock);
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++) {
		struct pkm_lcs_layer_table_entry *entry =
			&pkm_lcs_layer_table[i];
		bool equal = false;

		if (!entry->occupied)
			continue;
		ret = pkm_lcs_layer_name_casefold_equal(
			layer_name, layer_name_len, entry->name,
			entry->name_len, &equal);
		if (ret)
			break;
		if (!equal) {
			ret = -ENOENT;
			continue;
		}
		entry->owner_sid_len = 0;
		ret = 0;
		break;
	}
	mutex_unlock(&pkm_lcs_layer_table_lock);
	return ret;
}

void pkm_lcs_kunit_reset_layer_table(void)
{
	u32 i;

	mutex_lock(&pkm_lcs_layer_table_lock);
	pkm_lcs_base_layer_metadata_destroy_locked();
	for (i = 0; i < ARRAY_SIZE(pkm_lcs_layer_table); i++)
		pkm_lcs_layer_table_entry_destroy(&pkm_lcs_layer_table[i]);
	mutex_unlock(&pkm_lcs_layer_table_lock);
}
#endif
