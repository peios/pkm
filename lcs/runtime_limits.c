// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS runtime limit state.
 *
 * Source-device workflows consume these limits across source admission, path
 * walking, and source round trips. Keep the mutable seqlock state isolated from
 * those larger workflows.
 */

#include <linux/errno.h>
#include <linux/seqlock.h>

#include <trace/events/lcs.h>

#include "source_device.h"

#define PKM_LCS_RUNTIME_LIMITS_DEFAULT_INITIALIZER                    \
	{                                                             \
		.request_timeout_ms = PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT, \
		.transaction_timeout_ms = 30000U,                     \
		.notification_queue_size = 256U,                      \
		.symlink_depth_limit =                                \
			PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT,          \
		.max_value_size = 1048576U,                           \
		.max_key_depth = 512U,                                \
		.max_path_component_length = 255U,                    \
		.max_total_path_length = 16383U,                      \
		.max_layers_per_value = 128U,                         \
		.max_bound_transactions_per_source = 16U,             \
		.max_read_only_transactions_per_source = 16U,         \
		.max_total_layers = PKM_LCS_MAX_TOTAL_LAYERS_DEFAULT,  \
		.max_registered_sources = 32U,                        \
		.max_hives_per_source = 64U,                          \
		.max_concurrent_rsi_requests =                        \
			PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT,  \
		.max_scope_guids_per_token = 8U,                      \
		.max_private_layers_per_token = 16U,                  \
		.max_subtree_watch_depth = 0U,                        \
		.max_transaction_watch_event_burst = 4096U,           \
	}

static seqlock_t pkm_lcs_runtime_limits_lock =
	__SEQLOCK_UNLOCKED(pkm_lcs_runtime_limits_lock);
static const struct pkm_lcs_runtime_limits pkm_lcs_runtime_limits_default =
	PKM_LCS_RUNTIME_LIMITS_DEFAULT_INITIALIZER;
static struct pkm_lcs_runtime_limits pkm_lcs_runtime_limits_current =
	PKM_LCS_RUNTIME_LIMITS_DEFAULT_INITIALIZER;

long pkm_lcs_runtime_limits_defaults(struct pkm_lcs_runtime_limits *limits)
{
	if (!limits)
		return -EINVAL;

	*limits = pkm_lcs_runtime_limits_default;
	return 0;
}

static bool pkm_lcs_runtime_limits_in_range(u32 value, u32 min, u32 max)
{
	return value >= min && value <= max;
}

long pkm_lcs_runtime_limits_validate(
	const struct pkm_lcs_runtime_limits *limits)
{
	if (!limits)
		return -EINVAL;

#define PKM_LCS_CHECK_LIMIT(_field, _min, _max, _id)                    \
	do {                                                            \
		if (!pkm_lcs_runtime_limits_in_range(limits->_field,    \
						     (_min), (_max))) {     \
			trace_lcs_limits_validate((_id), limits->_field, \
						  -EINVAL);              \
			return -EINVAL;                                  \
		}                                                        \
	} while (0)

	PKM_LCS_CHECK_LIMIT(request_timeout_ms, 1000U, 600000U,
			    LCS_LIM_REQUEST_TIMEOUT_MS);
	PKM_LCS_CHECK_LIMIT(transaction_timeout_ms, 1000U, 600000U,
			    LCS_LIM_TRANSACTION_TIMEOUT_MS);
	PKM_LCS_CHECK_LIMIT(notification_queue_size, 16U, 65536U,
			    LCS_LIM_NOTIFICATION_QUEUE_SIZE);
	PKM_LCS_CHECK_LIMIT(symlink_depth_limit, 1U, 64U,
			    LCS_LIM_SYMLINK_DEPTH_LIMIT);
	PKM_LCS_CHECK_LIMIT(max_value_size, 4096U, 67108864U,
			    LCS_LIM_MAX_VALUE_SIZE);
	PKM_LCS_CHECK_LIMIT(max_key_depth, 32U, 4096U, LCS_LIM_MAX_KEY_DEPTH);
	PKM_LCS_CHECK_LIMIT(max_path_component_length, 64U, 1024U,
			    LCS_LIM_MAX_PATH_COMPONENT_LENGTH);
	PKM_LCS_CHECK_LIMIT(max_total_path_length, 1024U, 65535U,
			    LCS_LIM_MAX_TOTAL_PATH_LENGTH);
	PKM_LCS_CHECK_LIMIT(max_layers_per_value, 1U, 1024U,
			    LCS_LIM_MAX_LAYERS_PER_VALUE);
	PKM_LCS_CHECK_LIMIT(max_bound_transactions_per_source, 1U, 256U,
			    LCS_LIM_MAX_BOUND_TRANSACTIONS_PER_SOURCE);
	PKM_LCS_CHECK_LIMIT(max_read_only_transactions_per_source, 1U, 256U,
			    LCS_LIM_MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE);
	PKM_LCS_CHECK_LIMIT(max_total_layers, 16U, 65536U,
			    LCS_LIM_MAX_TOTAL_LAYERS);
	PKM_LCS_CHECK_LIMIT(max_registered_sources, 1U, 256U,
			    LCS_LIM_MAX_REGISTERED_SOURCES);
	PKM_LCS_CHECK_LIMIT(max_hives_per_source, 1U, 1024U,
			    LCS_LIM_MAX_HIVES_PER_SOURCE);
	PKM_LCS_CHECK_LIMIT(max_concurrent_rsi_requests, 8U, 4096U,
			    LCS_LIM_MAX_CONCURRENT_RSI_REQUESTS);
	PKM_LCS_CHECK_LIMIT(max_scope_guids_per_token, 1U, 256U,
			    LCS_LIM_MAX_SCOPE_GUIDS_PER_TOKEN);
	PKM_LCS_CHECK_LIMIT(max_private_layers_per_token, 1U, 256U,
			    LCS_LIM_MAX_PRIVATE_LAYERS_PER_TOKEN);
	PKM_LCS_CHECK_LIMIT(max_subtree_watch_depth, 0U, 4096U,
			    LCS_LIM_MAX_SUBTREE_WATCH_DEPTH);
	PKM_LCS_CHECK_LIMIT(max_transaction_watch_event_burst, 256U, 65536U,
			    LCS_LIM_MAX_TRANSACTION_WATCH_EVENT_BURST);

#undef PKM_LCS_CHECK_LIMIT

	return 0;
}

long pkm_lcs_runtime_limits_snapshot(struct pkm_lcs_runtime_limits *limits)
{
	unsigned int seq;

	if (!limits)
		return -EINVAL;

	do {
		seq = read_seqbegin(&pkm_lcs_runtime_limits_lock);
		*limits = pkm_lcs_runtime_limits_current;
	} while (read_seqretry(&pkm_lcs_runtime_limits_lock, seq));

	return 0;
}

long pkm_lcs_runtime_limits_publish(
	const struct pkm_lcs_runtime_limits *limits)
{
	u32 previous_max_concurrent;
	long ret;

	ret = pkm_lcs_runtime_limits_validate(limits);
	if (ret)
		return ret;

	write_seqlock(&pkm_lcs_runtime_limits_lock);
	previous_max_concurrent =
		pkm_lcs_runtime_limits_current.max_concurrent_rsi_requests;
	pkm_lcs_runtime_limits_current = *limits;
	write_sequnlock(&pkm_lcs_runtime_limits_lock);
	if (previous_max_concurrent != limits->max_concurrent_rsi_requests)
		pkm_lcs_source_slot_waiters_wake();
	trace_lcs_limits_publish(LCS_LIM_ALL,
				 limits->max_concurrent_rsi_requests, 0);
	return 0;
}

void pkm_lcs_runtime_limits_reset_defaults(void)
{
	u32 previous_max_concurrent;

	write_seqlock(&pkm_lcs_runtime_limits_lock);
	previous_max_concurrent =
		pkm_lcs_runtime_limits_current.max_concurrent_rsi_requests;
	pkm_lcs_runtime_limits_current = pkm_lcs_runtime_limits_default;
	write_sequnlock(&pkm_lcs_runtime_limits_lock);
	if (previous_max_concurrent !=
	    pkm_lcs_runtime_limits_default.max_concurrent_rsi_requests)
		pkm_lcs_source_slot_waiters_wake();
}

void pkm_lcs_runtime_limits_snapshot_or_default(
	struct pkm_lcs_runtime_limits *limits)
{
	if (pkm_lcs_runtime_limits_snapshot(limits))
		*limits = pkm_lcs_runtime_limits_default;
}

u32 pkm_lcs_runtime_request_timeout_ms(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.request_timeout_ms;
}

u32 pkm_lcs_runtime_transaction_timeout_ms(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.transaction_timeout_ms;
}

u32 pkm_lcs_runtime_symlink_depth_limit(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.symlink_depth_limit;
}

u32 pkm_lcs_runtime_max_key_depth(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_key_depth;
}

u32 pkm_lcs_runtime_max_bound_transactions_per_source(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_bound_transactions_per_source;
}

u32 pkm_lcs_runtime_max_read_only_transactions_per_source(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_read_only_transactions_per_source;
}

u32 pkm_lcs_runtime_max_registered_sources(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_registered_sources;
}

u32 pkm_lcs_runtime_max_hives_per_source(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_hives_per_source;
}

u32 pkm_lcs_runtime_max_concurrent_rsi_requests(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_concurrent_rsi_requests;
}

u32 pkm_lcs_runtime_notification_queue_size(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.notification_queue_size;
}

u32 pkm_lcs_runtime_max_subtree_watch_depth(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_subtree_watch_depth;
}

u32 pkm_lcs_runtime_max_transaction_watch_event_burst(void)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return limits.max_transaction_watch_event_burst;
}
