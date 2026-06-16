// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_lcs_kunit_transaction_watch_burst_over_limit_overflows_once(
	struct kunit *test)
{
	static const char * const burst_path[] = { "Machine", "Burst" };
	static const char * const single_path[] = { "Machine", "Single" };
	static const u8 burst_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x91 },
		{ 0x92 },
	};
	static const u8 single_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x91 },
		{ 0x93 },
	};
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_watch_dispatch_context *contexts;
	u32 burst_limit = 256U;
	u32 burst_contexts = burst_limit + 1U;
	u32 context_count = burst_contexts + 1U;
	u8 record[16] = { };
	long burst_fd;
	long single_fd;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.max_transaction_watch_event_burst = burst_limit;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	burst_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		24, KEY_NOTIFY, burst_path, burst_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, burst_fd >= 0);
	single_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		24, KEY_NOTIFY, single_path, single_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, single_fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)burst_fd,
							  &args),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)single_fd,
							  &args),
			0L);

	contexts = kcalloc(context_count, sizeof(*contexts), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, contexts);
	for (i = 0; i < burst_contexts; i++) {
		contexts[i].changed_key_guid = burst_ancestors[1];
		contexts[i].ancestor_guids = burst_ancestors;
		contexts[i].resolved_path = burst_path;
		contexts[i].path_component_count = 2;
		contexts[i].event_type = REG_WATCH_SD_CHANGED;
	}
	contexts[burst_contexts].changed_key_guid = single_ancestors[1];
	contexts[burst_contexts].ancestor_guids = single_ancestors;
	contexts[burst_contexts].resolved_path = single_path;
	contexts[burst_contexts].path_component_count = 2;
	contexts[burst_contexts].event_type = REG_WATCH_SD_CHANGED;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context_batch(
				contexts, context_count),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)burst_fd, record,
						  sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)burst_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);

	memset(record, 0, sizeof(record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)single_fd, record,
						  sizeof(record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(record + 6), 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)single_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);

	kfree(contexts);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)single_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)burst_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_transaction_watch_batch_retains_runtime_limits(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "BatchRetained" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0xd1 },
		{ 0xd2 },
	};
	struct pkm_lcs_key_fd_snapshot snapshot = { };
	struct reg_notify_args args = {
		.filter = REG_NOTIFY_SD,
	};
	struct pkm_lcs_runtime_limits retained = { };
	struct pkm_lcs_runtime_limits live = { };
	struct pkm_lcs_watch_dispatch_context *contexts;
	u32 context_count = 257U;
	long fd;
	u32 i;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&retained), 0L);
	retained.notification_queue_size = 300U;
	retained.max_transaction_watch_event_burst = 257U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&retained), 0L);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	fd = pkm_lcs_kunit_publish_key_fd_from_path(
		28, KEY_NOTIFY, path, ancestors, 2);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test, pkm_lcs_kunit_key_fd_notify((int)fd, &args),
			0L);

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&live), 0L);
	live.notification_queue_size = 16U;
	live.max_transaction_watch_event_burst = 256U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&live), 0L);

	contexts = kcalloc(context_count, sizeof(*contexts), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, contexts);
	for (i = 0; i < context_count; i++) {
		contexts[i].changed_key_guid = ancestors[1];
		contexts[i].ancestor_guids = ancestors;
		contexts[i].resolved_path = path;
		contexts[i].limits = &retained;
		contexts[i].path_component_count = 2;
		contexts[i].event_type = REG_WATCH_SD_CHANGED;
	}

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_dispatch_watch_event_context_batch(
				contexts, context_count),
			0L);
	KUNIT_ASSERT_EQ(test, pkm_lcs_key_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.watch_pending_events, context_count);

	kfree(contexts);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_runtime_limits_reset_defaults();
}


static void pkm_lcs_kunit_begin_transaction_publishes_active_unbound(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_table_snapshot source_snapshot = { };
	long fd;

	pkm_lcs_kunit_reset_source_table();

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_NE(test, txn_snapshot.transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, txn_snapshot.bound_source_id, 0U);
	KUNIT_EXPECT_TRUE(test, txn_snapshot.timer_pending);

	pkm_lcs_kunit_source_table_snapshot(&source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.occupied_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.down_count, 0U);
	KUNIT_EXPECT_FALSE(test, source_snapshot.sequence_initialized);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_lcs_kunit_reset_source_table();
}


static void pkm_lcs_kunit_begin_transaction_ids_are_monotonic(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot first = { };
	struct pkm_lcs_transaction_fd_snapshot second = { };
	long first_fd;
	long second_fd;

	first_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, first_fd >= 0);
	second_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, second_fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)first_fd, &first),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)second_fd,
							&second),
			0L);
	KUNIT_EXPECT_LT(test, first.transaction_id, second.transaction_id);
	KUNIT_EXPECT_EQ(test, first.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, second.state, REG_TXN_ACTIVE_UNBOUND);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first_fd), 0);
}


static void pkm_lcs_kunit_transaction_timeout_marks_timed_out(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	msleep(20);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_FALSE(test, snapshot.timer_pending);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_poll_reports_active_and_terminal_masks(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ACTIVE_BOUND, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_TIMED_OUT, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_poll_reports_runtime_terminals(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x81
	};
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	u32 marked = 0;
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			0U);

	msleep(20);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			(u32)(EPOLLERR | EPOLLHUP));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			0U);
	KUNIT_ASSERT_EQ(test, pkm_lcs_transaction_fd_mark_source_down(1,
								     &marked),
			0L);
	KUNIT_EXPECT_EQ(test, marked, 1U);
	KUNIT_EXPECT_EQ(test, pkm_lcs_kunit_transaction_fd_poll_mask((int)fd),
			(u32)(EPOLLERR | EPOLLHUP));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_timeout_bound_aborts_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x76
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[64];
	struct file file = { };
	const void *token;
	ssize_t read_len;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	msleep(20);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_flush_timeout_work(
				(int)fd),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_FALSE(test, txn_snapshot.timer_pending);

	read_len = pkm_lcs_kunit_source_device_read_file(&file, out,
							 sizeof(out), true);
	KUNIT_ASSERT_EQ(test, read_len,
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_snapshot.transaction_id);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_timeout_commit_in_flight_no_abort(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x77
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_commit_in_flight(
				(int)fd, true),
			0L);

	msleep(20);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_flush_timeout_work(
				(int)fd),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_commit_in_flight(
				(int)fd, false),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_fd_rejects_bad_inputs(
	struct kunit *test)
{
	struct pkm_lcs_transaction_fd_snapshot snapshot = {
		.transaction_id = 99,
	};
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_publish(0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_snapshot(-1, &snapshot),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, snapshot.transaction_id, 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_snapshot(-1, NULL),
			(long)-EINVAL);

	fd = anon_inode_getfd("lcs-not-transaction",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_snapshot(fd, &snapshot),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_status_reports_active_state(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_status_reports_timeout_errno(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	msleep(20);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, ETIMEDOUT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_status_maps_terminal_errno(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ACTIVE_BOUND, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ABORTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_SOURCE_DOWN);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, EIO);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, U32_MAX, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_status_rejects_bad_inputs(
	struct kunit *test)
{
	struct reg_txn_status_args status = {
		.state = 99,
		.terminal_errno = 99,
	};
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_status(-1, &status),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test, status.state, 0U);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_status(-1, NULL),
			(long)-EINVAL);

	fd = anon_inode_getfd("lcs-not-transaction-status",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_status(fd, &status),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_entrypoints_fail_closed(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_TXN_STATUS, 0),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, _IO(REG_IOC_TYPE, 0xfe), 0),
			(long)-ENOTTY);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, _IO('X', REG_IOC_TXN_STATUS_NR), 0),
			(long)-ENOTTY);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_status_copyout_fault(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_TXN_STATUS, 1UL),
			(long)-EFAULT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_rejects_bad_fds(
	struct kunit *test)
{
	struct reg_txn_status_args status = { };
	int fd;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				-1, REG_IOC_COMMIT, 0),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				-1, REG_IOC_TXN_STATUS,
				(unsigned long)&status),
			(long)-EBADF);

	fd = anon_inode_getfd("lcs-not-transaction-raw-ioctl",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				fd, REG_IOC_COMMIT, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				fd, REG_IOC_TXN_STATUS,
				(unsigned long)&status),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_commit_success(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x7a
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 poll_mask = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-raw-commit-ok");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_transaction_fd_raw_ioctl((int)fd, REG_IOC_COMMIT,
						     0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_COMMITTED);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status),
			0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	poll_mask = pkm_lcs_kunit_transaction_fd_poll_mask((int)fd);
	KUNIT_EXPECT_EQ(test, poll_mask, (u32)(EPOLLERR | EPOLLHUP));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_commit_busy_retains(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x7b
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_TXN_BUSY;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-raw-commit-busy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_transaction_fd_raw_ioctl((int)fd, REG_IOC_COMMIT,
						     0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EBUSY);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_TRUE(test, snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status),
			0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_commit_eio_retains(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x7c
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 poll_mask = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_STORAGE_ERROR;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread,
					 &script,
					 "pkm-lcs-kunit-raw-commit-eio");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_transaction_fd_raw_ioctl((int)fd, REG_IOC_COMMIT,
						     0);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_TRUE(test, snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status),
			0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	poll_mask = pkm_lcs_kunit_transaction_fd_poll_mask((int)fd);
	KUNIT_EXPECT_EQ(test, poll_mask, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_raw_ioctl_commit_predispatch_states(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_COMMIT, 0),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_COMMIT, 0),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_COMMIT, 0),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_TIMED_OUT, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_COMMIT, 0),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_raw_ioctl(
				(int)fd, REG_IOC_COMMIT, 0),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_commit_precheck_unbound_terminal(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_commit_precheck_timeout_source_down(
	struct kunit *test)
{
	long fd;

	fd = pkm_lcs_transaction_fd_publish(1);
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	msleep(20);

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_commit_active_bound_no_source_eio(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x71
	};
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 11,
				root_guid),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit((int)fd),
			(long)-EIO);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_commit_active_bound_success(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u32 count = 0;
	u32 poll_mask = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-ok");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_FALSE(test, snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_COMMITTED);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	poll_mask = pkm_lcs_kunit_transaction_fd_poll_mask((int)fd);
	KUNIT_EXPECT_EQ(test, poll_mask, (u32)(EPOLLERR | EPOLLHUP));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_busy_retains_active_bound(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x73
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct reg_txn_status_args status = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_TXN_BUSY;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-busy");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EBUSY);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_TRUE(test, snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_status((int)fd, &status), 0L);
	KUNIT_EXPECT_EQ(test, status.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, status.terminal_errno, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 2U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_sync_eio_retains_active_bound(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x74
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_STORAGE_ERROR;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-eio");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_TRUE(test, snapshot.timer_pending);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_rejects_bad_fds(
	struct kunit *test)
{
	int fd;

	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit(-1),
			(long)-EBADF);

	fd = anon_inode_getfd("lcs-not-transaction-commit",
			      &pkm_lcs_kunit_non_key_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_transaction_fd_commit(fd),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_close_active_unbound_no_source_abort(
	struct kunit *test)
{
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_close_active_bound_aborts_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x75
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 out[64];
	struct file file = { };
	const void *token;
	ssize_t read_len;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();

	read_len = pkm_lcs_kunit_source_device_read_file(&file, out,
							 sizeof(out), true);
	KUNIT_ASSERT_EQ(test, read_len,
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)read_len);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET), 0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_snapshot.transaction_id);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 1ULL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_close_terminal_no_source_abort(
	struct kunit *test)
{
	static const struct {
		u32 state;
		u32 source_id;
	} cases[] = {
		{ REG_TXN_COMMITTED, 1 },
		{ REG_TXN_ABORTED, 1 },
		{ REG_TXN_TIMED_OUT, 1 },
		{ REG_TXN_SOURCE_DOWN, 1 },
	};
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	u32 i;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		long fd;

		fd = pkm_lcs_reg_begin_transaction();
		KUNIT_ASSERT_TRUE(test, fd >= 0);
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_transaction_fd_set_state(
					(int)fd, cases[i].state,
					cases[i].source_id),
				0L);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
		flush_delayed_fput();
	}

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.next_request_id, 0ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_binding_precheck_and_complete(
	struct kunit *test)
{
	static const u8 machine_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x11
	};
	static const u8 users_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x22
	};
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, machine_root, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, plan.bound_source_id, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id + 1, 7,
				machine_root),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				machine_root),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 7U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.bound_root_guid, machine_root,
			       sizeof(snapshot.bound_root_guid)),
			0);

	memset(&plan, 0, sizeof(plan));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, machine_root, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, plan.bound_source_id, 7U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 8, machine_root, &plan),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, users_root, &plan),
			(long)-EXDEV);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_binding_terminal_failures(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x33
	};
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				root_guid),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_TIMED_OUT, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, root_guid, &plan),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				root_guid),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 7, root_guid, &plan),
			(long)-EIO);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				root_guid),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_binding_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 nil_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = { };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x44
	};
	struct pkm_lcs_transaction_binding_plan plan = {
		.action = 99,
	};
	long fd;
	int not_txn_fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 0, root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	plan.action = 99;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 1, nil_root, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 1, NULL, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				(int)fd, 1, root_guid, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, 0, 1, root_guid),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, 1, 0, root_guid),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, 1, 1, nil_root),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				-1, 1, root_guid, &plan),
			(long)-EBADF);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				-1, 1, 1, root_guid),
			(long)-EBADF);

	not_txn_fd = anon_inode_getfd("lcs-not-transaction-binding",
				     &pkm_lcs_kunit_non_key_fops, NULL,
				     O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_txn_fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_mutation_binding(
				not_txn_fd, 1, root_guid, &plan),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				not_txn_fd, 1, 1, root_guid),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_read_context_active_states(
	struct kunit *test)
{
	static const u8 machine_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x55
	};
	static const u8 users_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x66
	};
	struct pkm_lcs_transaction_read_plan read = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, machine_root, &read),
			0L);
	KUNIT_EXPECT_EQ(test, read.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, read.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, read.bound_source_id, 0U);
	KUNIT_EXPECT_FALSE(test, read.use_transaction);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 7,
				machine_root),
			0L);
	memset(&read, 0, sizeof(read));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, machine_root, &read),
			0L);
	KUNIT_EXPECT_EQ(test, read.txn_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, read.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, read.bound_source_id, 7U);
	KUNIT_EXPECT_TRUE(test, read.use_transaction);
	KUNIT_EXPECT_EQ(test,
			memcmp(read.bound_root_guid, machine_root,
			       sizeof(read.bound_root_guid)),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 8, machine_root, &read),
			(long)-EXDEV);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, users_root, &read),
			(long)-EXDEV);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_read_context_terminal_failures(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x77
	};
	struct pkm_lcs_transaction_read_plan read = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_COMMITTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_ABORTED, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_TIMED_OUT, 0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-ETIMEDOUT);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_state(
				(int)fd, REG_TXN_SOURCE_DOWN, 7),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 7, root_guid, &read),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_read_context_rejects_bad_inputs(
	struct kunit *test)
{
	static const u8 nil_root[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = { };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x88
	};
	struct pkm_lcs_transaction_read_plan read = {
		.txn_id = 99,
		.use_transaction = true,
	};
	long fd;
	int not_txn_fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 0, root_guid, &read),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, read.txn_id, 0ULL);
	KUNIT_EXPECT_FALSE(test, read.use_transaction);
	read.txn_id = 99;
	read.use_transaction = true;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, nil_root, &read),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, read.txn_id, 0ULL);
	KUNIT_EXPECT_FALSE(test, read.use_transaction);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, NULL, &read),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				(int)fd, 1, root_guid, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				-1, 1, root_guid, &read),
			(long)-EBADF);

	not_txn_fd = anon_inode_getfd("lcs-not-transaction-read",
				     &pkm_lcs_kunit_non_key_fops, NULL,
				     O_CLOEXEC);
	KUNIT_ASSERT_TRUE(test, not_txn_fd >= 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_prepare_read_context(
				not_txn_fd, 1, root_guid, &read),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)not_txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_late_begin_success_enqueues_abort_cleanup(
	struct kunit *test)
{
	const u64 txn_id = 0x6162636465666768ULL;
	struct pkm_lcs_source_response_result begin_response = { };
	struct pkm_lcs_source_response_result abort_response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_source_fd_snapshot snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	size_t response_len;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_begin_transaction_round_trip_timeout(
				1, txn_id, RSI_TXN_READ_WRITE, 1,
				&begin_response, &enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.txn_id, 0ULL);
	KUNIT_EXPECT_EQ(test, enqueue.op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, begin_response.len, (size_t)0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)enqueue.len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_id);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(out + payload_offset + sizeof(u64)),
			(u32)RSI_TXN_READ_WRITE);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&begin_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, begin_response.request_id, 0ULL);
	KUNIT_EXPECT_EQ(test, begin_response.txn_id, txn_id);
	KUNIT_EXPECT_EQ(test, begin_response.source_id, 1U);
	KUNIT_EXPECT_EQ(test, begin_response.request_op_code,
			(u16)RSI_BEGIN_TRANSACTION);
	KUNIT_EXPECT_EQ(test, begin_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, begin_response.caller_waiter_attached);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	memset(out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET),
			1ULL);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_id);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    1ULL, RSI_ABORT_TRANSACTION,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&abort_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, abort_response.request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, abort_response.txn_id, txn_id);
	KUNIT_EXPECT_EQ(test, abort_response.request_op_code,
			(u16)RSI_ABORT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, abort_response.status, (u32)RSI_OK);
	KUNIT_EXPECT_FALSE(test, abort_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, abort_response.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &snapshot);
	KUNIT_EXPECT_EQ(test, snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.in_flight_request_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.next_request_id, 2ULL);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_generation_success(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);
	KUNIT_EXPECT_EQ(test, generation_before, 0ULL);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xe5);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-gen");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_COMMITTED);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_refreshes_layer_metadata_once(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const char * const watch_path[] = { "Machine", "Software" };
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xf4, 0x10 },
		{ 0xf4, 0x11 },
		{ 0xf4, 0x12 },
		{ 0xf4 },
	};
	static const u8 watch_ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xf4, 0x20 },
	};
	static const char precedence_name[] = "Precedence";
	static const char enabled_name[] = "Enabled";
	struct pkm_lcs_transaction_mutation_handle first_handle = { };
	struct pkm_lcs_transaction_mutation_handle second_handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script refresh = {
		.expected_guid = metadata_ancestors[4],
		.name = "Policy",
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 12,
		.enabled = 1,
		.precedence_present = true,
		.enabled_present = true,
	};
	struct pkm_lcs_kunit_transaction_source_script script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
		.expect_layer_refresh = true,
		.layer_refresh_after = &refresh,
	};
	struct pkm_lcs_transaction_set_value_log_input first_input = {
		.key_guid = metadata_ancestors[4],
		.value_name = precedence_name,
		.value_name_len = sizeof(precedence_name) - 1,
		.layer = "base",
		.layer_len = 4,
		.path = metadata_path,
		.ancestor_guids = metadata_ancestors,
		.depth = ARRAY_SIZE(metadata_ancestors),
		.sequence = 51,
	};
	struct pkm_lcs_transaction_set_value_log_input second_input = {
		.key_guid = metadata_ancestors[4],
		.value_name = enabled_name,
		.value_name_len = sizeof(enabled_name) - 1,
		.layer = "base",
		.layer_len = 4,
		.path = metadata_path,
		.ancestor_guids = metadata_ancestors,
		.depth = ARRAY_SIZE(metadata_ancestors),
		.sequence = 52,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	u8 event[16] = { };
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long fd;
	long watch_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, watch_path, watch_ancestors,
		ARRAY_SIZE(watch_ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				metadata_ancestors[0]),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, metadata_ancestors[0],
				&first_input, &first_handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&first_handle),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, metadata_ancestors[0],
				&second_input, &second_handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&second_handle),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_ancestors[0], &generation_before),
			0L);

	script.file = &file;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, refresh.result, 0);
	KUNIT_EXPECT_EQ(test, refresh.reads, 4U);
	KUNIT_EXPECT_EQ(test, refresh.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 12U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_refreshes_set_security_layer(
	struct kunit *test)
{
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xfa, 0x10 },
		{ 0xfa, 0x11 },
		{ 0xfa, 0x12 },
		{ 0xfa },
	};
	static const char precedence_name[] = "Precedence";
	struct pkm_lcs_transaction_mutation_handle sd_handle = { };
	struct pkm_lcs_transaction_mutation_handle value_handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script refresh = {
		.expected_guid = metadata_ancestors[4],
		.name = "Policy",
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence = 24,
		.enabled = 1,
		.precedence_present = true,
		.enabled_present = true,
	};
	struct pkm_lcs_kunit_transaction_source_script script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
		.expect_layer_refresh = true,
		.layer_refresh_after = &refresh,
	};
	struct pkm_lcs_transaction_set_security_log_input sd_input = {
		.key_guid = metadata_ancestors[4],
		.path = metadata_path,
		.ancestor_guids = metadata_ancestors,
		.depth = ARRAY_SIZE(metadata_ancestors),
	};
	struct pkm_lcs_transaction_set_value_log_input value_input = {
		.key_guid = metadata_ancestors[4],
		.value_name = precedence_name,
		.value_name_len = sizeof(precedence_name) - 1,
		.layer = "base",
		.layer_len = 4,
		.path = metadata_path,
		.ancestor_guids = metadata_ancestors,
		.depth = ARRAY_SIZE(metadata_ancestors),
		.sequence = 61,
	};
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				metadata_ancestors[0]),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)fd, 1, metadata_ancestors[0], &sd_input,
				&sd_handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&sd_handle),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, metadata_ancestors[0],
				&value_input, &value_handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&value_handle),
			0L);

	script.file = &file;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-set-sd-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, refresh.result, 0);
	KUNIT_EXPECT_EQ(test, refresh.reads, 4U);
	KUNIT_EXPECT_EQ(test, refresh.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, "Policy");
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 24U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_refreshes_created_layer(
	struct kunit *test)
{
	static const char child_name[] = "Policy";
	static const char * const metadata_root_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 metadata_root_ancestors[4][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xfb, 0x10 },
		{ 0xfb, 0x11 },
		{ 0xfb, 0x12 },
	};
	static const u8 policy_guid[PKM_LCS_GUID_BYTES] = {
		0xfb, 0x13
	};
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_rsi_layer_view layers[3] = { };
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script refresh = {
		.expected_guid = policy_guid,
		.name = child_name,
		.sd = pkm_lcs_kunit_owner_only_sd,
		.sd_len = sizeof(pkm_lcs_kunit_owner_only_sd),
		.precedence_present = false,
		.enabled_present = false,
	};
	struct pkm_lcs_kunit_transaction_source_script script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
		.expect_layer_refresh = true,
		.layer_refresh_after = &refresh,
	};
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = metadata_root_ancestors[3],
		.target_guid = policy_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = metadata_root_path,
		.parent_ancestor_guids = metadata_root_ancestors,
		.creator_sid = pkm_lcs_kunit_system_sid,
		.creator_sid_len = sizeof(pkm_lcs_kunit_system_sid),
		.parent_depth = ARRAY_SIZE(metadata_root_ancestors),
		.sequence = 71,
	};
	char names[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u8 *owner_sid = NULL;
	size_t owner_sid_len = 0;
	u32 count = 0;
	bool owner_present = false;
	long fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				metadata_root_ancestors[0]),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, metadata_root_ancestors[0],
				&input, &handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle),
			0L);

	script.file = &file;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-create-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 5U);
	KUNIT_EXPECT_EQ(test, script.writes, 5U);
	KUNIT_EXPECT_EQ(test, refresh.result, 0);
	KUNIT_EXPECT_EQ(test, refresh.reads, 4U);
	KUNIT_EXPECT_EQ(test, refresh.writes, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 2U);
	KUNIT_EXPECT_STREQ(test, layers[1].name, child_name);
	KUNIT_EXPECT_EQ(test, layers[1].precedence, 0U);
	KUNIT_EXPECT_EQ(test, layers[1].enabled, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_owner_snapshot(
				child_name, sizeof(child_name) - 1, &owner_sid,
				&owner_sid_len, &owner_present),
			0L);
	KUNIT_ASSERT_TRUE(test, owner_present);
	KUNIT_ASSERT_EQ(test, owner_sid_len,
			sizeof(pkm_lcs_kunit_system_sid));
	KUNIT_EXPECT_EQ(test,
			memcmp(owner_sid, pkm_lcs_kunit_system_sid,
			       owner_sid_len),
			0);
	kfree(owner_sid);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_deletes_layer_metadata(
	struct kunit *test)
{
	static const char child_name[] = "Policy";
	static const char * const metadata_root_path[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const char * const metadata_path[] = {
		"Machine", "System", "Registry", "Layers", "Policy"
	};
	static const u8 metadata_root_ancestors[4][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xfd, 0x10 },
		{ 0xfd, 0x11 },
		{ 0xfd, 0x12 },
	};
	static const u8 metadata_ancestors[5][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0xfd, 0x10 },
		{ 0xfd, 0x11 },
		{ 0xfd, 0x12 },
		{ 0xfd, 0x13 },
	};
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_rsi_layer_view layers[2] = { };
	struct pkm_lcs_kunit_delete_key_ioctl_source_script lookup = {
		.expected_parent_guid = metadata_root_ancestors[3],
		.expected_key_guid = metadata_ancestors[4],
		.expected_child_name = child_name,
		.expected_layer_name = "base",
		.remaining_path_found = false,
	};
	struct pkm_lcs_kunit_delete_layer_source_script delete_layer = {
		.expected_layer_name = child_name,
		.status = RSI_OK,
	};
	struct pkm_lcs_kunit_transaction_source_script script = {
		.expected_op_code = RSI_COMMIT_TRANSACTION,
		.status = RSI_OK,
		.delete_key_lookup_after = &lookup,
		.expect_delete_layer = true,
		.delete_layer_after = &delete_layer,
	};
	struct pkm_lcs_transaction_delete_key_log_input input = {
		.key_guid = metadata_ancestors[4],
		.parent_guid = metadata_root_ancestors[3],
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = metadata_root_path,
		.parent_ancestor_guids = metadata_root_ancestors,
		.parent_depth = ARRAY_SIZE(metadata_root_ancestors),
	};
	char names[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	u64 generation_before = 0;
	u64 generation_after = 0;
	long metadata_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				child_name, sizeof(child_name) - 1U, 7, 1,
				metadata_ancestors[4],
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);
	metadata_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, metadata_path, metadata_ancestors,
		ARRAY_SIZE(metadata_ancestors));
	KUNIT_ASSERT_TRUE(test, metadata_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				metadata_root_ancestors[0]),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)txn_fd, 1, metadata_root_ancestors[0],
				&input, &handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_root_ancestors[0],
				&generation_before),
			0L);

	script.file = &file;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-delete-layer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, lookup.result, 0);
	KUNIT_EXPECT_EQ(test, delete_layer.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_layer_snapshot_copy(
				layers, ARRAY_SIZE(layers), names, sizeof(names),
				&count),
			0L);
	KUNIT_ASSERT_EQ(test, count, 1U);
	KUNIT_EXPECT_STREQ(test, layers[0].name, "base");
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, metadata_root_ancestors[0],
				&generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)metadata_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file,
					      metadata_ancestors[4]);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_dispatches_create_watch(
	struct kunit *test)
{
	static const char child_name[] = "TxnChild";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xb2
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xb3
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xb2 },
	};
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 0xee,
	};
	u8 direct[32] = { };
	u8 subtree[64] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long parent_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)-EAGAIN);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, direct,
						  sizeof(direct), true),
			(ssize_t)16);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 16U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 8U);
	KUNIT_EXPECT_EQ(test, memcmp(direct + 8, child_name,
				     sizeof(child_name) - 1U), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)26);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 26U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 8U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 8, child_name,
				     sizeof(child_name) - 1U), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 16), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 18), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 20, "Parent", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_dispatches_sd_watch(
	struct kunit *test)
{
	static const char * const root_path[] = { "Machine" };
	static const char * const target_path[] = { "Machine", "Target" };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 target_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xc2
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 target_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xc2 },
	};
	struct reg_notify_args direct_args = {
		.filter = REG_NOTIFY_SD,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SD,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_set_security_log_input input = {
		.key_guid = target_guid,
		.path = target_path,
		.ancestor_guids = target_ancestors,
		.depth = 2,
	};
	u8 direct[16] = { };
	u8 subtree[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long target_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	target_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, target_path, target_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, target_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)target_fd,
						    &direct_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)target_fd, direct,
						  sizeof(direct), true),
			(ssize_t)-EAGAIN);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-sd-watch");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)target_fd, direct,
						  sizeof(direct), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(direct), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(direct + 6), 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree,
						  sizeof(subtree), true),
			(ssize_t)18);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree), 18U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 4),
			REG_WATCH_SD_CHANGED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 6), 0U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 8), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree + 10), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree + 12, "Target", 6), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)target_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_delete_key_dispatches_exact_watches(
	struct kunit *test)
{
	static const char child_name[] = "Victim";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const child_path[] = {
		"Machine", "Parent", "Victim"
	};
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd2
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd3
	};
	static const u8 replacement_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd4
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd2 },
	};
	static const u8 child_ancestors[3][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd2 },
		{ 0xd3 },
	};
	struct reg_notify_args parent_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args child_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_kunit_delete_key_ioctl_source_script lookup = {
		.expected_parent_guid = parent_guid,
		.expected_key_guid = child_guid,
		.expected_child_name = child_name,
		.expected_layer_name = "base",
		.remaining_path_found = true,
		.remaining_guid = replacement_guid,
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_delete_key_log_input input = {
		.key_guid = child_guid,
		.parent_guid = parent_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
	};
	u8 parent_record[16] = { };
	u8 child_record[16] = { };
	u8 subtree_record[32] = { };
	struct pkm_lcs_key_fd_snapshot child_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long parent_fd;
	long child_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	child_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, child_path, child_ancestors, 3);
	KUNIT_ASSERT_TRUE(test, child_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &parent_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)child_fd,
						    &child_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, child_record,
						  sizeof(child_record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)-EAGAIN);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;
	script.delete_key_lookup_after = &lookup;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-delete-exact");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, lookup.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)child_fd, &child_snapshot),
			0L);
	KUNIT_EXPECT_TRUE(test, child_snapshot.orphaned);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)14);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 14U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, child_name,
				     sizeof(child_name) - 1U), 0);
	memset(parent_record, 0, sizeof(parent_record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)14);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 14U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, child_name,
				     sizeof(child_name) - 1U), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, child_record,
						  sizeof(child_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(child_record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 6), 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)24);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree_record), 24U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 6), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 8, child_name,
				     sizeof(child_name) - 1U), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 14), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 16), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 18, "Parent", 6), 0);
	memset(subtree_record, 0, sizeof(subtree_record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)24);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree_record), 24U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 4),
			REG_WATCH_SUBKEY_CREATED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 6), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 8, child_name,
				     sizeof(child_name) - 1U), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 14), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 16), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 18, "Parent", 6), 0);
	memset(subtree_record, 0, sizeof(subtree_record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)26);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree_record), 26U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 6), 0U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 8), 2U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 10), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 12, "Parent", 6), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 18), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 20, child_name,
				     sizeof(child_name) - 1U), 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, child_record,
						  sizeof(child_record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)child_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_expect_drop_key_request(test, &file, child_guid);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_delete_replay_timeout_overflows(
	struct kunit *test)
{
	static const char child_name[] = "Lost";
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const child_path[] = {
		"Machine", "Parent", "Lost"
	};
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd8
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd9
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd8 },
	};
	static const u8 child_ancestors[3][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd8 },
		{ 0xd9 },
	};
	struct reg_notify_args parent_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args child_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_delete_key_log_input input = {
		.key_guid = child_guid,
		.parent_guid = parent_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
	};
	u8 parent_record[16] = { };
	u8 child_record[16] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long parent_fd;
	long child_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1000;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	child_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, child_path, child_ancestors, 3);
	KUNIT_ASSERT_TRUE(test, child_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &parent_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)child_fd,
						    &child_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-replay-overflow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_OVERFLOW);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, child_record,
						  sizeof(child_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 4),
			REG_WATCH_OVERFLOW);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)child_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_hide_key_dispatches_exact_watches(
	struct kunit *test)
{
	static const char child_name[] = "Hidden";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const child_path[] = {
		"Machine", "Parent", "Hidden"
	};
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd6
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd7
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd6 },
	};
	static const u8 child_ancestors[3][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd6 },
		{ 0xd7 },
	};
	struct reg_notify_args parent_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args child_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_walk_source_step lookup_step = {
		.expected_child = child_name,
		.empty = true,
	};
	struct pkm_lcs_kunit_walk_source_script lookup = {
		.steps = &lookup_step,
		.step_count = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_hide_key_log_input input = {
		.key_guid = child_guid,
		.parent_guid = parent_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 0xfe,
	};
	u8 parent_record[16] = { };
	u8 child_record[16] = { };
	u8 subtree_record[32] = { };
	struct pkm_lcs_key_fd_snapshot child_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long parent_fd;
	long child_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	child_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, child_path, child_ancestors, 3);
	KUNIT_ASSERT_TRUE(test, child_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &parent_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)child_fd,
						    &child_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_hide_key_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;
	script.hide_key_lookup_after = &lookup;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-hide-exact");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, lookup.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_key_fd_snapshot((int)child_fd, &child_snapshot),
			0L);
	KUNIT_EXPECT_FALSE(test, child_snapshot.orphaned);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)14);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(parent_record), 14U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(parent_record + 6), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(parent_record + 8, child_name,
				     sizeof(child_name) - 1U), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, child_record,
						  sizeof(child_record), true),
			(ssize_t)8);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(child_record), 8U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(child_record + 6), 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)24);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree_record), 24U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 4),
			REG_WATCH_SUBKEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 6), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 8, child_name,
				     sizeof(child_name) - 1U), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 14), 1U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 16), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 18, "Parent", 6), 0);
	memset(subtree_record, 0, sizeof(subtree_record));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)26);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(subtree_record), 26U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 4),
			REG_WATCH_KEY_DELETED);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 6), 0U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 8), 2U);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 10), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 12, "Parent", 6), 0);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(subtree_record + 18), 6U);
	KUNIT_EXPECT_EQ(test, memcmp(subtree_record + 20, child_name,
				     sizeof(child_name) - 1U), 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd,
						  parent_record,
						  sizeof(parent_record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, child_record,
						  sizeof(child_record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, subtree_record,
						  sizeof(subtree_record), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)child_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_hide_key_no_effective_change(
	struct kunit *test)
{
	static const char child_name[] = "Stable";
	static const char * const root_path[] = { "Machine" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const char * const child_path[] = {
		"Machine", "Parent", "Stable"
	};
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xe6
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xe7
	};
	static const u8 policy_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xe8
	};
	static const u8 root_ancestors[1][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xe6 },
	};
	static const u8 child_ancestors[3][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xe6 },
		{ 0xe7 },
	};
	struct reg_notify_args parent_args = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	struct reg_notify_args child_args = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct reg_notify_args subtree_args = {
		.filter = REG_NOTIFY_SUBKEY,
		.subtree = 1,
	};
	struct pkm_lcs_kunit_walk_source_step lookup_step = {
		.expected_child = child_name,
		.layer_name = "policy",
		.guid = child_guid,
		.sequence = 0xfe,
	};
	struct pkm_lcs_kunit_walk_source_script lookup = {
		.steps = &lookup_step,
		.step_count = 1,
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_hide_key_log_input input = {
		.key_guid = child_guid,
		.parent_guid = parent_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 0xfe,
	};
	u8 record[32] = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long root_fd;
	long parent_fd;
	long child_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_layer_table();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	pkm_lcs_kunit_set_sequence_state(true, 0xff);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_layer_table_publish(
				"policy", strlen("policy"), 10, 1, policy_guid,
				pkm_lcs_kunit_owner_only_sd,
				sizeof(pkm_lcs_kunit_owner_only_sd),
				pkm_lcs_kunit_system_sid,
				sizeof(pkm_lcs_kunit_system_sid)),
			0L);

	root_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, root_path, root_ancestors, 1);
	KUNIT_ASSERT_TRUE(test, root_fd >= 0);
	parent_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors, 2);
	KUNIT_ASSERT_TRUE(test, parent_fd >= 0);
	child_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, child_path, child_ancestors, 3);
	KUNIT_ASSERT_TRUE(test, child_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)parent_fd,
						    &parent_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)child_fd,
						    &child_args),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)root_fd,
						    &subtree_args),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_hide_key_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;
	script.hide_key_lookup_after = &lookup;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-hide-nochange");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, lookup.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)parent_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)child_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)root_fd, record,
						  sizeof(record), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)child_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)parent_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)root_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_kunit_reset_layer_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_delete_key_orphan_no_live_ref_drops(
	struct kunit *test)
{
	static const char child_name[] = "Gone";
	static const char * const child_path[] = { "Machine", "Parent", "Gone" };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd4
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xd5
	};
	static const u8 child_ancestors[3][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd4 },
		{ 0xd5 },
	};
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xd4 },
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_kunit_delete_key_ioctl_source_script lookup = {
		.expected_parent_guid = parent_guid,
		.expected_key_guid = child_guid,
		.expected_child_name = child_name,
		.expected_layer_name = "base",
		.remaining_path_found = false,
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_delete_key_log_input input = {
		.key_guid = child_guid,
		.parent_guid = parent_guid,
		.child_name = child_name,
		.child_name_len = sizeof(child_name) - 1U,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	long child_fd;
	long txn_fd;
	long ret;
	int thread_ret;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	child_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_QUERY_VALUE, child_path, child_ancestors, 3);
	KUNIT_ASSERT_TRUE(test, child_fd >= 0);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)txn_fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)child_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;
	script.delete_key_lookup_after = &lookup;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-commit-delete-drop");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)txn_fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, lookup.result, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	pkm_lcs_kunit_expect_drop_key_request(test, &file, child_guid);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_commit_generation_overflow_downs_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_set(
				1, root_guid, ~0ULL),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xe6);

	script.file = &file;
	script.expected_op_code = RSI_COMMIT_TRANSACTION;
	script.expected_header_txn_id = snapshot.transaction_id;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-commit-gen-oflow");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_commit((int)fd);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EIO);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_SOURCE_DOWN);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_commit_timeout_late_success_consumes_log(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_late_response(test, RSI_OK);
}


static void pkm_lcs_kunit_commit_timeout_late_error_discards_log(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_late_response(test, RSI_STORAGE_ERROR);
}


static void pkm_lcs_kunit_commit_timeout_late_success_dispatches_create_watch(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_late_create_watch(test, RSI_OK, true);
}


static void pkm_lcs_kunit_commit_timeout_late_error_no_watch(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_late_create_watch(
		test, RSI_STORAGE_ERROR, false);
}


static void pkm_lcs_kunit_commit_timeout_closed_fd_late_success(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_closed_fd_late_response(test, RSI_OK);
}


static void pkm_lcs_kunit_commit_timeout_closed_fd_late_error(
	struct kunit *test)
{
	pkm_lcs_kunit_commit_timeout_closed_fd_late_response(
		test, RSI_STORAGE_ERROR);
}


static void pkm_lcs_kunit_commit_timeout_closed_fd_source_teardown(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 out[64];
	struct file file = { };
	const void *token;
	long fd;
	u32 count = 0;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xc5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.state, 0);

	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_commit_timeout_malformed_late_response_downs_source(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_fd_snapshot = { };
	struct pkm_lcs_source_table_snapshot source_table_snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	u64 request_id;
	size_t response_len;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xd5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	request_id = get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    0x80000000U, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(long)-EIO);
	KUNIT_EXPECT_TRUE(test, response_result.malformed_source_data);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_fd_snapshot);
	KUNIT_EXPECT_TRUE(test, source_fd_snapshot.closing);
	pkm_lcs_kunit_source_table_snapshot(&source_table_snapshot);
	KUNIT_EXPECT_EQ(test, source_table_snapshot.active_count, 0U);
	KUNIT_EXPECT_EQ(test, source_table_snapshot.down_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			(long)-EIO);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_bind_for_mutation_success_and_reuse(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x51
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-bind-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_bind_for_mutation((int)fd, 1, root_guid,
						      &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, plan.bound_source_id, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_BOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 1U);
	KUNIT_EXPECT_EQ(test,
			memcmp(snapshot.bound_root_guid, root_guid,
			       sizeof(snapshot.bound_root_guid)),
			0);

	memset(&plan, 0, sizeof(plan));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_bind_for_mutation(
				(int)fd, 1, root_guid, &plan),
			0L);
	KUNIT_EXPECT_EQ(test, plan.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_EQ(test, plan.transaction_id, snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, plan.state, REG_TXN_ACTIVE_BOUND);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_bind_for_mutation_source_failure_rolls_back(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x52
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	u32 count = 0;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_TXN_NOT_SUPPORTED;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-bind-unsupported");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_bind_for_mutation((int)fd, 1, root_guid,
						      &plan);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);
	KUNIT_EXPECT_EQ(test, snapshot.bound_source_id, 0U);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_bound_transaction_release(1, &count),
			0L);
	KUNIT_EXPECT_EQ(test, count, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_bind_for_mutation_counter_cap(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x53
	};
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct file file = { };
	const void *token;
	u32 count = 0;
	u32 i;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	for (i = 0; i < 16U; i++)
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_bound_transaction_acquire(
					1, &count),
				0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_bind_for_mutation(
				(int)fd, 1, root_guid, &plan),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, plan.action, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, snapshot.state, REG_TXN_ACTIVE_UNBOUND);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 0U);

	for (i = 0; i < 16U; i++)
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_source_bound_transaction_release(
					1, &count),
				0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_log_key_create_first_bind_and_reuse(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x56
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x57
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x58
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x56 },
		{ 0x57 },
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "policy",
		.layer_len = 6,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 100,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, &script,
			   "pkm-lcs-kunit-log-bind");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_begin_key_create_mutation(
		(int)fd, 1, root_guid, &input, &handle, &binding);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_TRUE(test, handle.active);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.capacity,
			(u32)PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 100ULL);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "App");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "policy");

	input.child_name = "Svc";
	input.child_name_len = 3;
	input.sequence = 101;
	memset(&binding, 0, sizeof(binding));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 2U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 3ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 101ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Svc");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_log_cancel_does_not_publish(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x59
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5a
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5b
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x59 },
		{ 0x5a },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 7,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_TRUE(test, handle.active);
	pkm_lcs_transaction_fd_cancel_mutation(&handle);
	KUNIT_EXPECT_FALSE(test, handle.active);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5c
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5d
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5e
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x5c },
		{ 0x5d },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 11,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_transaction_fd_set_log_capacity(
				(int)fd, 1),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.capacity, 1U);

	input.sequence = 12;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-ENOMEM);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 11ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_rejects_bad_create_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x5f
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x60
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x61
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x5f },
		{ 0x62 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "App",
		.child_name_len = 3,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = mismatched_ancestors,
		.parent_depth = 2,
		.sequence = 13,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_set_security_records_context(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x63
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x64
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x63 },
		{ 0x64 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_security_log_input input = {
		.key_guid = key_guid,
		.path = path,
		.ancestor_guids = ancestors,
		.depth = 2,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_TRUE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_rejects_bad_set_security_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x65
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x66
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x65 },
		{ 0x67 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_security_log_input input = {
		.key_guid = key_guid,
		.path = path,
		.ancestor_guids = mismatched_ancestors,
		.depth = 2,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_security_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_set_value_records_context(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x68
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x69
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x68 },
		{ 0x69 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_value_log_input input = {
		.key_guid = key_guid,
		.value_name = NULL,
		.value_name_len = 0,
		.layer = "base",
		.layer_len = 4,
		.path = path,
		.ancestor_guids = ancestors,
		.depth = 2,
		.sequence = 17,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_TRUE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 17ULL);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "base");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_rejects_bad_set_value_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6a
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6b
	};
	static const char * const path[] = { "Machine", "Target" };
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x6a },
		{ 0x6c },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_value_log_input input = {
		.key_guid = key_guid,
		.value_name = "Answer",
		.value_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.path = path,
		.ancestor_guids = mismatched_ancestors,
		.depth = 2,
		.sequence = 18,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_key_path_records_context(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6d
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6e
	};
	static const u8 delete_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x61
	};
	static const u8 hide_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x62
	};
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x6d },
		{ 0x6e },
	};
	struct pkm_lcs_transaction_delete_key_log_input delete_input = {
		.key_guid = delete_guid,
		.parent_guid = parent_guid,
		.child_name = "Victim",
		.child_name_len = 6,
		.layer = "policy",
		.layer_len = 6,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
	};
	struct pkm_lcs_transaction_hide_key_log_input hide_input = {
		.key_guid = hide_guid,
		.parent_guid = parent_guid,
		.child_name = "Hidden",
		.child_name_len = 6,
		.layer = "policy",
		.layer_len = 6,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = 0x221,
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)fd, 1, root_guid, &delete_input,
				&handle, &binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_TRUE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 1ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0ULL);
	KUNIT_EXPECT_EQ(test,
			memcmp(log.last_key_guid, delete_guid,
			       sizeof(log.last_key_guid)),
			0);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Victim");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "policy");

	memset(&binding, 0, sizeof(binding));
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_hide_key_mutation(
				(int)fd, 1, root_guid, &hide_input, &handle,
				&binding),
			0L);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_REUSE);
	KUNIT_EXPECT_TRUE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 2U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 3ULL);
	KUNIT_EXPECT_EQ(test, log.last_operation_index, 2ULL);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY);
	KUNIT_EXPECT_EQ(test, log.last_parent_depth, 2U);
	KUNIT_EXPECT_EQ(test, log.last_sequence, 0x221ULL);
	KUNIT_EXPECT_EQ(test,
			memcmp(log.last_key_guid, hide_guid,
			       sizeof(log.last_key_guid)),
			0);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Hidden");
	KUNIT_EXPECT_STREQ(test, log.last_layer, "policy");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_lcs_kunit_transaction_log_key_path_first_bind(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x6f
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x70
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x74
	};
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x6f },
		{ 0x70 },
	};
	struct pkm_lcs_kunit_transaction_source_script script = { };
	struct pkm_lcs_transaction_delete_key_log_input input = {
		.key_guid = key_guid,
		.parent_guid = parent_guid,
		.child_name = "Victim",
		.child_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	struct task_struct *task;
	struct file file = { };
	const void *token;
	int thread_ret;
	long ret;
	long fd;

	flush_delayed_fput();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);

	script.file = &file;
	script.expected_op_code = RSI_BEGIN_TRANSACTION;
	script.expected_header_txn_id = 0;
	script.expected_payload_txn_id = snapshot.transaction_id;
	script.expected_mode = RSI_TXN_READ_WRITE;
	script.status = RSI_OK;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_transaction_source_thread, &script,
		"pkm-lcs-kunit-path-log-bind");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_transaction_fd_begin_delete_key_mutation(
		(int)fd, 1, root_guid, &input, &handle, &binding);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 1U);
	KUNIT_EXPECT_EQ(test, script.writes, 1U);
	KUNIT_EXPECT_EQ(test, binding.action, PKM_LCS_TRANSACTION_BIND_NEW);
	KUNIT_EXPECT_TRUE(test, handle.active);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_EXPECT_EQ(test, log.last_kind,
			(u32)PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY);
	KUNIT_EXPECT_EQ(test,
			memcmp(log.last_key_guid, key_guid,
			       sizeof(log.last_key_guid)),
			0);
	KUNIT_EXPECT_STREQ(test, log.last_child_name, "Victim");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_transaction_log_key_path_rejects_bad_shape(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x71
	};
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x72
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0x75
	};
	static const u8 nil_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = { };
	static const char * const parent_path[] = { "Machine", "Parent" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x71 },
		{ 0x72 },
	};
	static const u8 mismatched_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0x71 },
		{ 0x73 },
	};
	struct pkm_lcs_transaction_delete_key_log_input delete_input = {
		.key_guid = key_guid,
		.parent_guid = parent_guid,
		.child_name = "Victim",
		.child_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = mismatched_ancestors,
		.parent_depth = 2,
	};
	struct pkm_lcs_transaction_hide_key_log_input hide_input = {
		.key_guid = key_guid,
		.parent_guid = parent_guid,
		.child_name = "Hidden",
		.child_name_len = 6,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = mismatched_ancestors,
		.parent_depth = 2,
		.sequence = 0,
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1,
				root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)fd, 1, root_guid, &delete_input,
				&handle, &binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_hide_key_mutation(
				(int)fd, 1, root_guid, &hide_input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);

	delete_input.key_guid = nil_guid;
	delete_input.parent_ancestor_guids = parent_ancestors;
	hide_input.key_guid = nil_guid;
	hide_input.parent_ancestor_guids = parent_ancestors;
	hide_input.sequence = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_delete_key_mutation(
				(int)fd, 1, root_guid, &delete_input,
				&handle, &binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_hide_key_mutation(
				(int)fd, 1, root_guid, &hide_input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_lcs_kunit_transaction_log_rejects_malformed_layer_name(
	struct kunit *test)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xba
	};
	static const char * const path[] = { "Machine", "BadLayer" };
	static const u8 ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xba },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_value_log_input input = {
		.key_guid = key_guid,
		.value_name = "Value",
		.value_name_len = 5,
		.layer = "bad/layer",
		.layer_len = 9,
		.path = path,
		.ancestor_guids = ancestors,
		.depth = 2,
		.sequence = 41,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_fd_snapshot snapshot = { };
	long fd;

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd, &snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, snapshot.transaction_id, 1, root_guid),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				(int)fd, 1, root_guid, &input, &handle,
				&binding),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, handle.active);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	KUNIT_EXPECT_EQ(test, log.next_operation_index, 1ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_lcs_kunit_late_set_value_success_applies_effects(
	struct kunit *test)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x88 },
	};
	static const char value_name[] = "Late";
	static const char layer_name[] = "Base";
	static const u8 data[] = { 1, 2, 3, 4 };
	struct pkm_lcs_source_key_mutation_late_effect_input late = {
		.key_guid = ancestors[1],
		.ancestor_guids = ancestors,
		.resolved_path = path,
		.name = value_name,
		.path_component_count = ARRAY_SIZE(path),
		.name_len = sizeof(value_name) - 1,
		.event_type = REG_WATCH_VALUE_SET,
		.flags = PKM_LCS_SOURCE_LATE_EFFECT_RECORD_GENERATION |
			 PKM_LCS_SOURCE_LATE_EFFECT_DISPATCH_WATCH,
	};
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_source_response_result timeout_response = { };
	struct pkm_lcs_source_response_result write_result = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[128];
	u8 event[32] = { };
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	size_t response_len;
	long watch_fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, path, ancestors, ARRAY_SIZE(ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_before),
			0L);

	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1;
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_set_value_round_trip_timeout_late_effect_with_limits(
				1, 0, ancestors[1], value_name,
				sizeof(value_name) - 1, layer_name,
				sizeof(layer_name) - 1, REG_DWORD, data,
				sizeof(data), 10, 0, &limits,
				limits.request_timeout_ms, &late,
				&timeout_response, &enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_SET_VALUE);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&write_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, write_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, write_result.status, (u32)RSI_OK);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)(8 + sizeof(value_name) - 1));
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
			REG_WATCH_VALUE_SET);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6),
			(u16)(sizeof(value_name) - 1));
	KUNIT_EXPECT_EQ(test,
			memcmp(event + 8, value_name, sizeof(value_name) - 1),
			0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


static void pkm_lcs_kunit_late_mutation_without_metadata_downs_source(
	struct kunit *test)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x89 };
	static const char value_name[] = "Late";
	static const char layer_name[] = "Base";
	static const u8 data[] = { 1 };
	struct pkm_lcs_runtime_limits limits = { };
	struct pkm_lcs_source_response_result timeout_response = { };
	struct pkm_lcs_source_response_result write_result = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_source_table_snapshot table = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[128];
	struct file file = { };
	const void *token;
	size_t response_len;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1;

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_source_set_value_round_trip_timeout_with_limits(
				1, 0, key_guid, value_name,
				sizeof(value_name) - 1, layer_name,
				sizeof(layer_name) - 1, REG_DWORD, data,
				sizeof(data), 10, 0, &limits,
				limits.request_timeout_ms, &timeout_response,
				&enqueue),
			(long)-ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, enqueue.op_code, (u16)RSI_SET_VALUE);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)enqueue.len);
	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    enqueue.request_id, enqueue.op_code,
					    RSI_OK, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&write_result),
			(ssize_t)-EIO);
	pkm_lcs_kunit_source_table_snapshot(&table);
	KUNIT_EXPECT_EQ(test, table.active_count, 0U);
	KUNIT_EXPECT_EQ(test, table.down_count, 1U);

	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_lcs_kunit_transaction_cases[] = {
	KUNIT_CASE(pkm_lcs_kunit_transaction_watch_burst_over_limit_overflows_once),
	KUNIT_CASE(pkm_lcs_kunit_transaction_watch_batch_retains_runtime_limits),
	KUNIT_CASE(pkm_lcs_kunit_begin_transaction_publishes_active_unbound),
	KUNIT_CASE(pkm_lcs_kunit_begin_transaction_ids_are_monotonic),
	KUNIT_CASE(pkm_lcs_kunit_transaction_timeout_marks_timed_out),
	KUNIT_CASE(pkm_lcs_kunit_transaction_poll_reports_active_and_terminal_masks),
	KUNIT_CASE(pkm_lcs_kunit_transaction_poll_reports_runtime_terminals),
	KUNIT_CASE(pkm_lcs_kunit_transaction_timeout_bound_aborts_source),
	KUNIT_CASE(pkm_lcs_kunit_transaction_timeout_commit_in_flight_no_abort),
	KUNIT_CASE(pkm_lcs_kunit_transaction_fd_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_reports_active_state),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_reports_timeout_errno),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_maps_terminal_errno),
	KUNIT_CASE(pkm_lcs_kunit_transaction_status_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_entrypoints_fail_closed),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_status_copyout_fault),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_rejects_bad_fds),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_commit_success),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_commit_busy_retains),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_commit_eio_retains),
	KUNIT_CASE(pkm_lcs_kunit_transaction_raw_ioctl_commit_predispatch_states),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_precheck_unbound_terminal),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_precheck_timeout_source_down),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_active_bound_no_source_eio),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_active_bound_success),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_busy_retains_active_bound),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_sync_eio_retains_active_bound),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_rejects_bad_fds),
	KUNIT_CASE(pkm_lcs_kunit_transaction_close_active_unbound_no_source_abort),
	KUNIT_CASE(pkm_lcs_kunit_transaction_close_active_bound_aborts_source),
	KUNIT_CASE(pkm_lcs_kunit_transaction_close_terminal_no_source_abort),
	KUNIT_CASE(pkm_lcs_kunit_transaction_binding_precheck_and_complete),
	KUNIT_CASE(pkm_lcs_kunit_transaction_binding_terminal_failures),
	KUNIT_CASE(pkm_lcs_kunit_transaction_binding_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_transaction_read_context_active_states),
	KUNIT_CASE(pkm_lcs_kunit_transaction_read_context_terminal_failures),
	KUNIT_CASE(pkm_lcs_kunit_transaction_read_context_rejects_bad_inputs),
	KUNIT_CASE(pkm_lcs_kunit_late_begin_success_enqueues_abort_cleanup),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_generation_success),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_refreshes_layer_metadata_once),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_refreshes_set_security_layer),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_refreshes_created_layer),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_deletes_layer_metadata),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_dispatches_create_watch),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_dispatches_sd_watch),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_delete_key_dispatches_exact_watches),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_delete_replay_timeout_overflows),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_hide_key_dispatches_exact_watches),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_hide_key_no_effective_change),
	KUNIT_CASE(pkm_lcs_kunit_transaction_delete_key_orphan_no_live_ref_drops),
	KUNIT_CASE(pkm_lcs_kunit_transaction_commit_generation_overflow_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_late_success_consumes_log),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_late_error_discards_log),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_late_success_dispatches_create_watch),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_late_error_no_watch),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_closed_fd_late_success),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_closed_fd_late_error),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_closed_fd_source_teardown),
	KUNIT_CASE(pkm_lcs_kunit_commit_timeout_malformed_late_response_downs_source),
	KUNIT_CASE(pkm_lcs_kunit_transaction_bind_for_mutation_success_and_reuse),
	KUNIT_CASE(pkm_lcs_kunit_transaction_bind_for_mutation_source_failure_rolls_back),
	KUNIT_CASE(pkm_lcs_kunit_transaction_bind_for_mutation_counter_cap),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_key_create_first_bind_and_reuse),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_cancel_does_not_publish),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_capacity_fails_before_reserve),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_rejects_bad_create_shape),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_set_security_records_context),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_rejects_bad_set_security_shape),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_set_value_records_context),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_rejects_bad_set_value_shape),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_key_path_records_context),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_key_path_first_bind),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_key_path_rejects_bad_shape),
	KUNIT_CASE(pkm_lcs_kunit_transaction_log_rejects_malformed_layer_name),
	KUNIT_CASE(pkm_lcs_kunit_late_set_value_success_applies_effects),
	KUNIT_CASE(pkm_lcs_kunit_late_mutation_without_metadata_downs_source),
	{}
};

static struct kunit_suite pkm_lcs_kunit_transaction_suite = {
	.name = "pkm_lcs_kunit_transaction",
	.test_cases = pkm_lcs_kunit_transaction_cases,
};

kunit_test_suite(pkm_lcs_kunit_transaction_suite);
