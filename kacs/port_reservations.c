// SPDX-License-Identifier: GPL-2.0-only
/*
 * Port reservations: loading the table from the registry.
 *
 * Mirrors the KMES configuration consumer (kmes.c): walk to the key from the
 * Machine hive root, run one RSI_QUERY_VALUES round trip, let the LCS Rust
 * ingress resolve layering and serialise the effective values into the
 * table blob, then hand the blob to KACS, which validates and publishes it
 * whole or keeps what it had.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <pkm/trace.h>

#include "../lcs/source_device.h"
#include "port_reservations.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

extern int lcs_rust_port_reservations_blob_from_query_values(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	size_t private_layer_count, u8 *out, size_t out_cap,
	size_t *written_out);

long pkm_kacs_port_reservations_refresh_from_key(u32 source_id,
						 const u8 port_guid[16])
{
	struct pkm_lcs_source_response_frame frame;
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_layer_snapshot layers = { };
	struct pkm_lcs_runtime_limits limits = { };
	u64 next_sequence = 0;
	u8 *blob = NULL;
	size_t blob_len = 0;
	long ret;

	if (!source_id || !port_guid)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_runtime_limits_snapshot(&limits);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		source_id, 0, port_guid, "", 0, true, &limits,
		limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out;
	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		goto out;

	/* The blob is never larger than the frame it is drawn from. */
	blob = kzalloc(frame.len ? frame.len : 1, GFP_KERNEL);
	if (!blob) {
		ret = -ENOMEM;
		goto out;
	}
	ret = lcs_rust_port_reservations_blob_from_query_values(
		frame.data, frame.len, response.request_id, next_sequence,
		layers.layers, layers.layer_count, NULL, 0, blob, frame.len,
		&blob_len);
	if (ret)
		goto out;
	if (!blob_len) {
		/* An empty key has no default reservation: not a table. */
		ret = -EINVAL;
		goto out;
	}
	ret = kacs_rust_port_table_replace(blob, blob_len);

out:
	trace_kacs_socket_bind(0, 0, 0, 0, 0, KACS_SOCK_PORT_TABLE, ret);
	kfree(blob);
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

long pkm_kacs_port_reservations_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[16], bool *present_out,
	u8 port_guid_out[16])
{
	static const struct pkm_lcs_path_component_view port_path[] = {
		{ .name = "Machine", .name_len = sizeof("Machine") - 1 },
		{ .name = "System", .name_len = sizeof("System") - 1 },
		{ .name = "Network", .name_len = sizeof("Network") - 1 },
		{ .name = "TcpIp", .name_len = sizeof("TcpIp") - 1 },
		{ .name = "PortReservations",
		  .name_len = sizeof("PortReservations") - 1 },
	};
	struct pkm_lcs_resolved_key_path key = { };
	struct pkm_lcs_layer_snapshot layers = { };
	long ret;

	if (present_out)
		*present_out = false;
	if (port_guid_out)
		memset(port_guid_out, 0, 16);
	if (!source_id || !machine_root_guid || !present_out || !port_guid_out)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components(
		source_id, 0, machine_root_guid, port_path,
		ARRAY_SIZE(port_path), layers.layers, layers.layer_count, NULL,
		0, &key);
	if (ret == -ENOENT) {
		ret = 0;
		goto out_layers;
	}
	if (ret)
		goto out_layers;

	memcpy(port_guid_out, key.key_guid, 16);
	*present_out = true;
	pkm_lcs_resolved_key_path_destroy(&key);
out_layers:
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}
