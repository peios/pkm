// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_kunit_kmes_direct_emit_writes_single_event(struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	u8 buffer[128] = { 0 };
	size_t written = 0;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, written, (size_t)view.event_size);
	KUNIT_EXPECT_EQ(test, view.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, view.origin_class, KMES_ORIGIN_KACS);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)PKM_KUNIT_KMES_DIRECT_TYPE,
				  sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1);
	pkm_kunit_expect_bytes_eq(test, view.payload_ptr, view.payload_len,
				  payload, sizeof(payload));
}


static void pkm_kunit_kmes_identity_stamps_match_kacs_state(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	u8 buffer[128] = { 0 };
	size_t written = 0;
	struct pkm_kunit_kmes_event_view view = { };
	struct pkm_kacs_kunit_process_state_view process_view = { };
	struct pkm_kacs_boot_snapshot primary_snapshot = { };
	struct pkm_kacs_boot_snapshot client_snapshot = { };
	const void *primary_token;
	const void *client_token;
	const void *state;
	long fd;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(primary_token,
							 &primary_snapshot));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state,
							      &process_view),
			0);

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, NULL),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	pkm_kunit_expect_guid_eq(test, view.effective_token_guid,
				 primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, view.true_token_guid,
				 primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, view.process_guid,
				 process_view.process_guid);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(client_token,
							 &client_snapshot));
	pkm_kunit_expect_guid_ne(test, client_snapshot.token_guid,
				 primary_snapshot.token_guid);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);

	memset(buffer, 0, sizeof(buffer));
	written = 0;
	memset(&view, 0, sizeof(view));
	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, NULL),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	pkm_kunit_expect_guid_eq(test, view.effective_token_guid,
				 client_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, view.true_token_guid,
				 primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, view.process_guid,
				 process_view.process_guid);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_kmes_live_overrun_advances_tail_to_survivors(
	struct kunit *test)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	u8 *payload;
	size_t written = 0;
	size_t offset = 0;
	u32 event_size = 0;
	int i;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_DOWNSIZE_CAPACITY,
			       GFP_KERNEL);
	payload = kunit_kzalloc(test, 32000, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_NOT_NULL(test, payload);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(
		test,
		pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_DOWNSIZE_CAPACITY),
		0);

	for (i = 0; i < 5; i++) {
		memset(payload, 0, 32000);
		payload[0] = (u8)(i + 1);
		pkm_kmes_emit_kernel(KMES_ORIGIN_KACS,
				     PKM_KUNIT_KMES_DIRECT_TYPE,
				     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1,
				     payload, 32000);
	}

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_DOWNSIZE_CAPACITY,
				&written, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.capacity,
			(u64)PKM_KUNIT_KMES_DOWNSIZE_CAPACITY);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 5ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 1ULL);

	for (i = 0; i < 4; i++) {
		KUNIT_ASSERT_TRUE(
			test,
			pkm_kunit_parse_kmes_event(buffer + offset,
						   written - offset, &view));
		if (i == 0) {
			event_size = view.event_size;
			KUNIT_EXPECT_EQ(test, snapshot.tail_pos,
					(u64)event_size);
			KUNIT_EXPECT_EQ(test, snapshot.write_pos,
					(u64)event_size * 5ULL);
			KUNIT_EXPECT_EQ(test, written,
					(size_t)event_size * 4U);
		} else {
			KUNIT_EXPECT_EQ(test, view.event_size, event_size);
		}
		KUNIT_EXPECT_EQ(test, view.sequence, (u64)(i + 2));
		KUNIT_EXPECT_EQ(test, view.payload_ptr[0], (u8)(i + 2));
		offset += view.event_size;
	}
	KUNIT_EXPECT_EQ(test, offset, written);
}


static void pkm_kunit_kmes_direct_invalid_type_drops_structurally(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	u8 buffer[1] = { 0xaa };
	size_t written = 99;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, NULL, 0, payload,
			     sizeof(payload));

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_snapshot_single_active(&snapshot), 0);
	KUNIT_EXPECT_EQ(test, snapshot.write_pos, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.tail_pos, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 1ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, NULL),
			0);
	KUNIT_EXPECT_EQ(test, written, (size_t)0);
	KUNIT_EXPECT_EQ(test, buffer[0], (u8)0xaa);
}


static void pkm_kunit_kmes_attach_success_returns_cpu_fds(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	u8 magic[8] = { 0 };
	long ret;
	int i;
	u16 prev_cpu_id = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	for (i = 0; i < nr_cpu_ids; i++)
		fds[i] = -1;

	pkm_kunit_reset_kmes();
	ret = pkm_kunit_kmes_attach_all(token, fds, &count, &capacity);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_GT(test, count, 0);
	KUNIT_EXPECT_EQ(test, capacity, (u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);

	for (i = 0; i < count; i++) {
		KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fds[i], &snapshot),
				0);
		KUNIT_EXPECT_EQ(test, snapshot.capacity, capacity);
		KUNIT_EXPECT_EQ(test, snapshot.generation, 1ULL);
		KUNIT_EXPECT_EQ(test, snapshot.write_pos, 0ULL);
		KUNIT_EXPECT_EQ(test, snapshot.tail_pos, 0ULL);
		KUNIT_EXPECT_EQ(test, snapshot.futex_counter, 0U);
		KUNIT_EXPECT_EQ(test, snapshot.need_wake, (u8)0);
		KUNIT_EXPECT_EQ(test, snapshot.mapping_size,
				8192ULL + (2ULL * capacity));
		if (i > 0)
			KUNIT_EXPECT_GT(test, snapshot.cpu_id, prev_cpu_id);
		prev_cpu_id = snapshot.cpu_id;
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_fd_view(fds[i], 0, magic,
							 sizeof(magic)),
				0);
		pkm_kunit_expect_bytes_eq(test, magic, sizeof(magic),
					  pkm_kunit_kmes_ring_magic,
					  sizeof(pkm_kunit_kmes_ring_magic) - 1);
	}

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			PKM_KUNIT_SE_SECURITY_PRIVILEGE);

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_attach_repeated_same_cpu_shares_consumer_metadata(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot first = { };
	struct pkm_kmes_kunit_fd_snapshot second = { };
	int fd0 = -1;
	int fd1 = -1;
	u64 cap0 = 0;
	u64 cap1 = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_attach_for_token(token, 0, &fd0, &cap0),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_attach_for_token(token, 0, &fd1, &cap1),
			0L);
	KUNIT_EXPECT_NE(test, fd0, fd1);
	KUNIT_EXPECT_EQ(test, cap0, cap1);

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd0, &first), 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd1, &second), 0);
	KUNIT_EXPECT_EQ(test, first.cpu_id, second.cpu_id);
	KUNIT_EXPECT_EQ(test, first.capacity, second.capacity);
	KUNIT_EXPECT_EQ(test, first.generation, second.generation);
	KUNIT_EXPECT_EQ(test, first.need_wake, (u8)0);
	KUNIT_EXPECT_EQ(test, second.need_wake, (u8)0);

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_set_fd_need_wake(fd0, 1), 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd1, &second), 0);
	KUNIT_EXPECT_EQ(test, second.need_wake, (u8)1);

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_set_fd_need_wake(fd1, 0), 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd0, &first), 0);
	KUNIT_EXPECT_EQ(test, first.need_wake, (u8)0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd0), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd1), 0);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_mmap_clears_write_upgrade(struct kunit *test)
{
	unsigned long initial_flags = VM_SHARED | VM_READ | VM_WRITE |
				      VM_MAYREAD | VM_MAYWRITE;
	unsigned long locked_flags =
		pkm_kmes_kunit_mmap_locked_flags(initial_flags);

	KUNIT_EXPECT_FALSE(test, locked_flags & VM_WRITE);
	KUNIT_EXPECT_FALSE(test, locked_flags & VM_MAYWRITE);
	KUNIT_EXPECT_TRUE(test, locked_flags & VM_SHARED);
	KUNIT_EXPECT_TRUE(test, locked_flags & VM_READ);
	KUNIT_EXPECT_TRUE(test, locked_flags & VM_MAYREAD);
}


static void pkm_kunit_kmes_attach_einval_on_out_of_range_cpu(
	struct kunit *test)
{
	const void *token;
	int fd = 0x5a;
	u64 capacity = 0xfeedfaceULL;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	/*
	 * A ring exists for every possible CPU, so nr_cpu_ids is the first
	 * out-of-range index. Attaching to it fails with EINVAL and leaves the
	 * caller's out-params untouched.
	 */
	ret = pkm_kmes_kunit_attach_for_token(token, (u32)nr_cpu_ids, &fd,
					      &capacity);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, fd, 0x5a);
	KUNIT_EXPECT_EQ(test, capacity, 0xfeedfaceULL);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_attach_denies_without_security(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_priv_adjust_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_SECURITY,
		.attributes = 0,
	};
	u64 previous_enabled = 0;
	int fd = -1;
	u64 capacity = 0;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_token_has_enabled_privilege(token,
						      PKM_KUNIT_SE_SECURITY_PRIVILEGE));
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_privs(token, &entry, 1,
						     &previous_enabled),
			0);
	KUNIT_ASSERT_FALSE(
		test,
		kacs_rust_token_has_enabled_privilege(token,
						      PKM_KUNIT_SE_SECURITY_PRIVILEGE));

	ret = pkm_kmes_kunit_attach_for_token(token, 0, &fd, &capacity);
	KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_SECURITY_PRIVILEGE,
			0ULL);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_attach_checks_privilege_before_usercopy(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_priv_adjust_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_SECURITY,
		.attributes = 0,
	};
	u64 previous_enabled = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_privs(token, &entry, 1,
						     &previous_enabled),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_attach_user_for_token(
				token, 0, (u64 __user *)1),
			(long)-EPERM);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_attach_mapping_view_tracks_emission(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view event = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	u8 event_bytes[128] = { 0 };
	u8 mirror_bytes[128] = { 0 };
	long ret;
	int i;
	int emitted_fd = -1;
	int emitted_count = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	for (i = 0; i < nr_cpu_ids; i++)
		fds[i] = -1;

	pkm_kunit_reset_kmes();
	ret = pkm_kunit_kmes_attach_all(token, fds, &count, &capacity);
	KUNIT_ASSERT_EQ(test, ret, 0L);

	for (i = 0; i < count; i++)
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_set_fd_need_wake(fds[i], 1), 0);

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));

	for (i = 0; i < count; i++) {
		KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fds[i], &snapshot),
				0);
		if (snapshot.write_pos == 0)
			continue;
		emitted_fd = fds[i];
		emitted_count++;
	}
	KUNIT_EXPECT_EQ(test, emitted_count, 1);
	KUNIT_ASSERT_GE(test, emitted_fd, 0);

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(emitted_fd, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.futex_counter, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.need_wake, (u8)1);
	KUNIT_EXPECT_GT(test, snapshot.write_pos, 0ULL);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(emitted_fd, 8192, event_bytes,
						 sizeof(event_bytes)),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(event_bytes,
						     sizeof(event_bytes), &event));
	KUNIT_EXPECT_EQ(test, event.origin_class, KMES_ORIGIN_KACS);
	/* v0.20 header carries the three identity GUIDs: payload sits at the
	 * 77-byte base plus the type string. */
	KUNIT_EXPECT_EQ(test, event.header_size,
			(u32)(KMES_EVENT_HEADER_BASE_SIZE + event.type_len));
	pkm_kunit_expect_bytes_eq(test, event.type_ptr, event.type_len,
				  (const u8 *)PKM_KUNIT_KMES_DIRECT_TYPE,
				  sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(emitted_fd, 8192 + capacity,
						 mirror_bytes,
						 sizeof(mirror_bytes)),
			0);
	pkm_kunit_expect_bytes_eq(test, mirror_bytes, sizeof(mirror_bytes),
				  event_bytes, sizeof(event_bytes));

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_consumer_restart_sees_surviving_events(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view event = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	u8 event_bytes[128] = { 0 };
	int emitted_fd = -1;
	int emitted_count = 0;
	long ret;
	int i;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	for (i = 0; i < nr_cpu_ids; i++)
		fds[i] = -1;

	pkm_kunit_reset_kmes();
	ret = pkm_kunit_kmes_attach_all(token, fds, &count, &capacity);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_GT(test, count, 0);
	pkm_kunit_close_fds(test, fds, count);
	for (i = 0; i < nr_cpu_ids; i++)
		fds[i] = -1;

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload,
			     sizeof(payload));

	count = nr_cpu_ids;
	capacity = 0;
	ret = pkm_kunit_kmes_attach_all(token, fds, &count, &capacity);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	for (i = 0; i < count; i++) {
		KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fds[i], &snapshot),
				0);
		if (snapshot.write_pos == 0)
			continue;
		emitted_fd = fds[i];
		emitted_count++;
	}
	KUNIT_EXPECT_EQ(test, emitted_count, 1);
	KUNIT_ASSERT_GE(test, emitted_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(emitted_fd, 8192, event_bytes,
						 sizeof(event_bytes)),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(event_bytes,
						     sizeof(event_bytes), &event));
	KUNIT_EXPECT_EQ(test, event.origin_class, KMES_ORIGIN_KACS);
	pkm_kunit_expect_bytes_eq(test, event.type_ptr, event.type_len,
				  (const u8 *)PKM_KUNIT_KMES_DIRECT_TYPE,
				  sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1);
	pkm_kunit_expect_bytes_eq(test, event.payload_ptr, event.payload_len,
				  payload, sizeof(payload));

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_swap_old_fd_freezes_and_new_attach_rebinds(
	struct kunit *test)
{
	static const u8 payload0[] = { 0xaa };
	static const u8 payload1[] = { 0xbb };
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot old_before = { };
	struct pkm_kmes_kunit_fd_snapshot old_after = { };
	struct pkm_kmes_kunit_fd_snapshot old_post_emit = { };
	struct pkm_kmes_kunit_fd_snapshot new_before_emit = { };
	struct pkm_kmes_kunit_fd_snapshot new_after_emit = { };
	struct pkm_kmes_kunit_fd_snapshot scan_snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	struct pkm_kunit_kmes_event_view second = { };
	int *fds;
	int *new_fds;
	int count = nr_cpu_ids;
	int new_count = nr_cpu_ids;
	u64 capacity = 0;
	u64 new_capacity = 0;
	int old_fd;
	int new_fd;
	int i;
	bool found_copied_event = false;
	bool found_emitted_event = false;
	u8 old_bytes[128] = { 0 };
	u8 new_bytes[256] = { 0 };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	new_fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*new_fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	KUNIT_ASSERT_NOT_NULL(test, new_fds);
	memset(fds, 0xff, nr_cpu_ids * sizeof(*fds));
	memset(new_fds, 0xff, nr_cpu_ids * sizeof(*new_fds));

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_kmes_attach_all(token, fds, &count,
						  &capacity),
			0L);
	old_fd = pkm_kunit_find_current_kmes_fd(test, fds, count, NULL);
	KUNIT_ASSERT_GE(test, old_fd, 0);

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload0,
			     sizeof(payload0));

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(old_fd, &old_before), 0);
	KUNIT_EXPECT_EQ(test, old_before.generation, 1ULL);
	KUNIT_EXPECT_EQ(test, old_before.capacity,
			(u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);
	KUNIT_EXPECT_GT(test, old_before.write_pos, 0ULL);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_SWAP_CAPACITY),
			0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(old_fd, &old_after), 0);
	KUNIT_EXPECT_EQ(test, old_after.generation, 2ULL);
	KUNIT_EXPECT_EQ(test, old_after.capacity,
			(u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);
	KUNIT_EXPECT_EQ(test, old_after.write_pos, old_before.write_pos);
	KUNIT_EXPECT_EQ(test, old_after.mapping_size,
			8192ULL + (2ULL * PKM_KUNIT_KMES_DEFAULT_CAPACITY));
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_fd_view(old_fd, 8192, old_bytes,
						 sizeof(old_bytes)),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(old_bytes,
						     sizeof(old_bytes), &first));
	KUNIT_EXPECT_EQ(test, first.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, first.origin_class, KMES_ORIGIN_KACS);
	KUNIT_EXPECT_EQ(test, first.payload_len, sizeof(payload0));
	KUNIT_EXPECT_EQ(test, first.payload_ptr[0], payload0[0]);

	KUNIT_ASSERT_EQ(test,
			pkm_kunit_kmes_attach_all(token, new_fds, &new_count,
						  &new_capacity),
			0L);
	new_fd = pkm_kunit_find_current_kmes_fd(test, new_fds, new_count,
						 &new_before_emit);
	KUNIT_ASSERT_GE(test, new_fd, 0);
	KUNIT_EXPECT_EQ(test, new_capacity, (u64)PKM_KUNIT_KMES_SWAP_CAPACITY);
	KUNIT_EXPECT_EQ(test, new_before_emit.generation, 2ULL);
	KUNIT_EXPECT_EQ(test, new_before_emit.capacity,
			(u64)PKM_KUNIT_KMES_SWAP_CAPACITY);

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, PKM_KUNIT_KMES_DIRECT_TYPE,
			     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1, payload1,
			     sizeof(payload1));

	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(old_fd, &old_post_emit),
			0);
	KUNIT_EXPECT_EQ(test, old_post_emit.write_pos, old_before.write_pos);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(new_fd, &new_after_emit),
			0);
	KUNIT_EXPECT_EQ(test, new_after_emit.generation, 2ULL);
	KUNIT_EXPECT_TRUE(test,
			  new_after_emit.write_pos == old_before.write_pos ||
			  new_after_emit.write_pos > old_before.write_pos);

	for (i = 0; i < new_count; i++) {
		if (new_fds[i] < 0)
			continue;
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_fd_snapshot(new_fds[i],
							   &scan_snapshot),
				0);
		KUNIT_EXPECT_EQ(test, scan_snapshot.generation, 2ULL);
		if (!scan_snapshot.write_pos)
			continue;
		memset(new_bytes, 0, sizeof(new_bytes));
		KUNIT_ASSERT_EQ(test,
				pkm_kmes_kunit_copy_fd_view(new_fds[i], 8192,
							 new_bytes,
							 sizeof(new_bytes)),
				0);
		KUNIT_ASSERT_TRUE(test,
				  pkm_kunit_parse_kmes_event(
					  new_bytes, sizeof(new_bytes), &first));
		if (first.sequence == 1ULL && first.payload_len == sizeof(payload0) &&
		    first.payload_ptr[0] == payload0[0]) {
			found_copied_event = true;
			if (pkm_kunit_parse_kmes_event(new_bytes + first.event_size,
						       sizeof(new_bytes) -
							       first.event_size,
						       &second)) {
				if (second.sequence == 2ULL &&
				    second.payload_len == sizeof(payload1) &&
				    second.payload_ptr[0] == payload1[0])
					found_emitted_event = true;
			}
		}
		if (first.sequence == 1ULL && first.payload_len == sizeof(payload1) &&
		    first.payload_ptr[0] == payload1[0]) {
			found_emitted_event = true;
		}
	}

	KUNIT_EXPECT_TRUE(test, found_copied_event);
	KUNIT_EXPECT_TRUE(test, found_emitted_event);

	pkm_kunit_close_fds(test, new_fds, new_count);
	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_swap_wakes_old_generation_waiter(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot snapshot = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	int fd;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	memset(fds, 0xff, nr_cpu_ids * sizeof(*fds));

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_kmes_attach_all(token, fds, &count,
						  &capacity),
			0L);
	fd = pkm_kunit_find_current_kmes_fd(test, fds, count, NULL);
	KUNIT_ASSERT_GE(test, fd, 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_set_fd_need_wake(fd, 1), 0);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_SWAP_CAPACITY),
			0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd, &snapshot), 0);
	KUNIT_EXPECT_EQ(test, snapshot.generation, 2ULL);
	KUNIT_EXPECT_EQ(test, snapshot.futex_counter, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.need_wake, (u8)1);

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_swap_downsize_preserves_newest_suffix(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	u8 *payload;
	size_t written = 0;
	size_t offset = 0;
	int i;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_DOWNSIZE_CAPACITY,
			       GFP_KERNEL);
	payload = kunit_kzalloc(test, 32000, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);
	KUNIT_ASSERT_NOT_NULL(test, payload);

	pkm_kunit_reset_kmes();
	for (i = 0; i < 5; i++) {
		memset(payload, 0, 32000);
		payload[0] = (u8)(i + 1);
		pkm_kmes_emit_kernel(KMES_ORIGIN_KACS,
				     PKM_KUNIT_KMES_DIRECT_TYPE,
				     sizeof(PKM_KUNIT_KMES_DIRECT_TYPE) - 1,
				     payload, 32000);
	}

	KUNIT_ASSERT_EQ(
		test,
		pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_DOWNSIZE_CAPACITY),
		0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer,
							  PKM_KUNIT_KMES_DOWNSIZE_CAPACITY,
							  &written, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.capacity,
			(u64)PKM_KUNIT_KMES_DOWNSIZE_CAPACITY);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 5ULL);

	for (i = 0; i < 4; i++) {
		KUNIT_ASSERT_TRUE(
			test,
			pkm_kunit_parse_kmes_event(buffer + offset,
						   written - offset, &view));
		KUNIT_EXPECT_EQ(test, view.sequence, (u64)(i + 2));
		KUNIT_EXPECT_EQ(test, view.payload_ptr[0], (u8)(i + 2));
		offset += view.event_size;
	}
	KUNIT_EXPECT_EQ(test, offset, written);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_swap_failed_allocation_keeps_live_ring(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_fd_snapshot before = { };
	struct pkm_kmes_kunit_fd_snapshot after = { };
	int *fds;
	int count = nr_cpu_ids;
	u64 capacity = 0;
	int fd;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	fds = kunit_kcalloc(test, nr_cpu_ids, sizeof(*fds), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fds);
	memset(fds, 0xff, nr_cpu_ids * sizeof(*fds));

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_kmes_attach_all(token, fds, &count,
						  &capacity),
			0L);
	fd = pkm_kunit_find_current_kmes_fd(test, fds, count, &before);
	KUNIT_ASSERT_GE(test, fd, 0);

	pkm_kmes_kunit_fail_next_swap_alloc();
	KUNIT_EXPECT_EQ(
		test,
		pkm_kmes_kunit_swap_capacity(PKM_KUNIT_KMES_SWAP_CAPACITY),
		-ENOMEM);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_fd_snapshot(fd, &after), 0);
	KUNIT_EXPECT_EQ(test, after.generation, before.generation);
	KUNIT_EXPECT_EQ(test, after.capacity, before.capacity);
	KUNIT_EXPECT_EQ(test, after.mapping_size, before.mapping_size);

	pkm_kunit_close_fds(test, fds, count);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_user_success(struct kunit *test)
{
	static const u8 payload[] = { 0x81, 0xa1, 0x6b, 0xc0 };
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 buffer[128] = { 0 };
	size_t written = 0;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	ret = pkm_kmes_kunit_emit_for_token(
		token, PKM_KUNIT_KMES_USER_TYPE,
		sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_EQ(test, view.origin_class, KMES_ORIGIN_USERSPACE);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)PKM_KUNIT_KMES_USER_TYPE,
				  sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1);
	pkm_kunit_expect_bytes_eq(test, view.payload_ptr, view.payload_len,
				  payload, sizeof(payload));
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used &
				(PKM_KUNIT_SE_AUDIT_PRIVILEGE |
				 PKM_KUNIT_SE_TCB_PRIVILEGE),
			PKM_KUNIT_SE_AUDIT_PRIVILEGE |
				PKM_KUNIT_SE_TCB_PRIVILEGE);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_denies_before_usercopy(struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kacs_priv_adjust_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_AUDIT,
		.attributes = 0,
	};
	u64 previous_enabled = 0;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_token_has_enabled_privilege(token,
						      PKM_KUNIT_SE_AUDIT_PRIVILEGE));
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_adjust_privs(token, &entry, 1,
						     &previous_enabled),
			0);
	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token, (const void __user *)1,
						     1, (const void __user *)1,
						     1),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_AUDIT_PRIVILEGE,
			0ULL);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_rejects_invalid_msgpack(struct kunit *test)
{
	static const u8 payload[] = { 0xc1 };
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload,
				sizeof(payload)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_size_check_precedes_usercopy(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token,
						     (const void __user *)1, 1,
						     (const void __user *)1,
						     65536U),
			(long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_zero_type_precedes_size_and_usercopy(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token,
						     (const void __user *)1, 0,
						     (const void __user *)1,
						     U32_MAX),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_rate_limit_denies_without_tcb(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u32 tokens = 99;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_refill_frozen(true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(0), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload,
				sizeof(payload)),
			(long)-EAGAIN);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_tcb_exempts_rate_limit(struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	const void *token;
	u32 tokens = 99;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(0), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1, payload,
				sizeof(payload)),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 0U);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_batch_success_shared_timestamp(
	struct kunit *test)
{
	static const u8 payload0[] = { 0xc0 };
	static const u8 payload1[] = { 0x81, 0xa1, 0x78, 0x01 };
	struct kmes_emit_entry entries[] = {
		{
			.event_type = (__u64)(uintptr_t)PKM_KUNIT_KMES_BATCH_TYPE0,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1,
			.payload = (__u64)(uintptr_t)payload0,
			.payload_len = sizeof(payload0),
		},
		{
			.event_type = (__u64)(uintptr_t)PKM_KUNIT_KMES_BATCH_TYPE1,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE1) - 1,
			.payload = (__u64)(uintptr_t)payload1,
			.payload_len = sizeof(payload1),
		},
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	struct pkm_kunit_kmes_event_view second = { };
	u8 buffer[256] = { 0 };
	u32 emitted = 99;
	size_t written = 0;
	long ret;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	ret = pkm_kmes_kunit_emit_batch_for_token(token, entries,
						  ARRAY_SIZE(entries), &emitted);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, emitted, (u32)ARRAY_SIZE(entries));
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &first));
	KUNIT_ASSERT_TRUE(
		test,
		pkm_kunit_parse_kmes_event(buffer + first.event_size,
					   written - first.event_size, &second));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 2ULL);
	KUNIT_EXPECT_EQ(test, first.timestamp, second.timestamp);
	KUNIT_EXPECT_EQ(test, first.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, second.sequence, 2ULL);
	KUNIT_EXPECT_EQ(test, first.origin_class, KMES_ORIGIN_USERSPACE);
	KUNIT_EXPECT_EQ(test, second.origin_class, KMES_ORIGIN_USERSPACE);
	pkm_kunit_expect_bytes_eq(test, first.type_ptr, first.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE0,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1);
	pkm_kunit_expect_bytes_eq(test, second.type_ptr, second.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE1,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE1) - 1);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_batch_partial_refunds_unused_tokens(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	static const u8 bad_type[] = { 0x80 };
	struct kmes_emit_entry entries[] = {
		{
			.event_type = (__u64)(uintptr_t)PKM_KUNIT_KMES_BATCH_TYPE0,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1,
			.payload = (__u64)(uintptr_t)payload,
			.payload_len = sizeof(payload),
		},
		{
			.event_type = (__u64)(uintptr_t)bad_type,
			.event_type_len = sizeof(bad_type),
			.payload = (__u64)(uintptr_t)payload,
			.payload_len = sizeof(payload),
		},
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	u8 buffer[128] = { 0 };
	u32 emitted = 99;
	u32 tokens = 0;
	size_t written = 0;
	long ret;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_refill_frozen(true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(5), 0);
	ret = pkm_kmes_kunit_emit_batch_for_token(token, entries,
						  ARRAY_SIZE(entries), &emitted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, emitted, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 4U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &first));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	pkm_kunit_expect_bytes_eq(test, first.type_ptr, first.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE0,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_batch_checks_emitted_out_before_entries(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_batch_user_for_token(
				token, (const struct kmes_emit_entry __user *)1,
				1, (u32 __user *)1),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_batch_count_precedes_rate_and_emitted_out(
	struct kunit *test)
{
	static const u8 payload[] = { 0xc0 };
	struct kmes_emit_entry entry = {
		.event_type = (__u64)(uintptr_t)PKM_KUNIT_KMES_BATCH_TYPE0,
		.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1,
		.payload = (__u64)(uintptr_t)payload,
		.payload_len = sizeof(payload),
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u32 emitted = 0xaaaaaaaaU;
	u32 tokens = 99;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_refill_frozen(true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(0), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_batch_for_token(token, &entry, 0,
							    &emitted),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, emitted, 0xaaaaaaaaU);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_batch_overflow_precedes_entry_usercopy(
	struct kunit *test)
{
	struct kmes_emit_entry entry = {
		.event_type = 1,
		.event_type_len = 1,
		.payload = 1,
		.payload_len = U32_MAX,
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u32 emitted = 0xaaaaaaaaU;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_batch_for_token(token, &entry, 1,
							    &emitted),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, emitted, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_emit_batch_max_size_precedes_entry_usercopy(
	struct kunit *test)
{
	struct kmes_emit_entry entry = {
		.event_type = 1,
		.event_type_len = 1,
		.payload = 1,
		.payload_len = 65536U,
	};
	const void *token;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u32 emitted = 0xaaaaaaaaU;

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_batch_for_token(token, &entry, 1,
							    &emitted),
			(long)-ENOSPC);
	KUNIT_EXPECT_EQ(test, emitted, 0U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_kernel_batch_continues_after_structural_drop(
	struct kunit *test)
{
	static const u8 payload0[] = { 0xc0 };
	static const u8 payload1[] = { 0x81, 0xa1, 0x79, 0x02 };
	struct pkm_kmes_kernel_event events[] = {
		{
			.event_type = PKM_KUNIT_KMES_BATCH_TYPE0,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1,
			.payload = payload0,
			.payload_len = sizeof(payload0),
		},
		{
			.event_type = PKM_KUNIT_KMES_BATCH_TYPE1,
			.event_type_len = 0,
			.payload = payload0,
			.payload_len = sizeof(payload0),
		},
		{
			.event_type = PKM_KUNIT_KMES_BATCH_TYPE1,
			.event_type_len = sizeof(PKM_KUNIT_KMES_BATCH_TYPE1) - 1,
			.payload = payload1,
			.payload_len = sizeof(payload1),
		},
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view first = { };
	struct pkm_kunit_kmes_event_view second = { };
	u8 buffer[256] = { 0 };
	size_t written = 0;
	size_t offset;

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel_batch(KMES_ORIGIN_KACS, events,
				   ARRAY_SIZE(events));

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(buffer, sizeof(buffer),
							  &written, &snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &first));
	offset = first.event_size;
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer + offset,
						     written - offset, &second));
	offset += second.event_size;
	KUNIT_EXPECT_EQ(test, offset, written);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 3ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 1ULL);
	KUNIT_EXPECT_EQ(test, first.timestamp, second.timestamp);
	KUNIT_EXPECT_EQ(test, first.sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, second.sequence, 3ULL);
	KUNIT_EXPECT_EQ(test, first.origin_class, KMES_ORIGIN_KACS);
	KUNIT_EXPECT_EQ(test, second.origin_class, KMES_ORIGIN_KACS);
	pkm_kunit_expect_bytes_eq(test, first.type_ptr, first.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE0,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE0) - 1);
	pkm_kunit_expect_bytes_eq(test, second.type_ptr, second.type_len,
				  (const u8 *)PKM_KUNIT_KMES_BATCH_TYPE1,
				  sizeof(PKM_KUNIT_KMES_BATCH_TYPE1) - 1);
}


static void pkm_kunit_kmes_kernel_batch_empty_noop(struct kunit *test)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };

	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel_batch(KMES_ORIGIN_KACS, NULL, 0);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
}


static void pkm_kunit_kmes_runtime_config_validates_ranges(
	struct kunit *test)
{
	struct pkm_kmes_runtime_config config;
	struct pkm_kmes_runtime_config snapshot = { };

	pkm_kunit_reset_kmes();
	config = pkm_kunit_kmes_default_config();

	config.buffer_capacity = PKM_KUNIT_KMES_MIN_CAPACITY / 2U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.buffer_capacity = PKM_KUNIT_KMES_MAX_CAPACITY * 2ULL;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.buffer_capacity = PKM_KUNIT_KMES_MIN_CAPACITY + 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.buffer_capacity = PKM_KUNIT_KMES_MIN_CAPACITY +
				 (PKM_KUNIT_KMES_MIN_CAPACITY / 2U);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.max_event_size = PKM_KUNIT_KMES_MIN_EVENT_SIZE - 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.max_event_size = PKM_KUNIT_KMES_MAX_EVENT_SIZE + 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.max_nesting_depth = PKM_KUNIT_KMES_MIN_NESTING_DEPTH - 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.max_nesting_depth = PKM_KUNIT_KMES_MAX_NESTING_DEPTH + 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.max_emit_rate_per_process = PKM_KUNIT_KMES_MIN_RATE - 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);
	config = pkm_kunit_kmes_default_config();
	config.max_emit_rate_per_process = PKM_KUNIT_KMES_MAX_RATE + 1U;
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			(long)-EINVAL);

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_runtime_config_snapshot(&snapshot), 0);
	KUNIT_EXPECT_EQ(test, snapshot.buffer_capacity,
			(u64)PKM_KUNIT_KMES_DEFAULT_CAPACITY);
	KUNIT_EXPECT_EQ(test, snapshot.max_event_size, 65536U);
	KUNIT_EXPECT_EQ(test, snapshot.max_nesting_depth, 32U);
	KUNIT_EXPECT_EQ(test, snapshot.max_emit_rate_per_process,
			(u32)PKM_KUNIT_KMES_DEFAULT_RATE);
}


static void pkm_kunit_kmes_runtime_max_event_size_controls_syscall(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_runtime_config config;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_kunit_reset_kmes();

	config = pkm_kunit_kmes_default_config();
	config.max_event_size = PKM_KUNIT_KMES_MIN_EVENT_SIZE;
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token,
						     (const void __user *)1, 1,
						     (const void __user *)1,
						     1024U),
			(long)-ENOSPC);

	config.max_event_size = 2048U;
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_emit_user_for_token(token,
						     (const void __user *)1, 1,
						     (const void __user *)1,
						     1024U),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_runtime_nesting_depth_controls_validation(
	struct kunit *test)
{
	static const u8 nested_payload[] = {
		0x91, 0x91, 0x91, 0x91, 0xc0,
	};
	const void *token;
	struct pkm_kmes_runtime_config config;
	struct pkm_kmes_kunit_snapshot snapshot = { };

	token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_kunit_reset_kmes();

	config = pkm_kunit_kmes_default_config();
	config.max_nesting_depth = 4U;
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1,
				nested_payload, sizeof(nested_payload)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);

	config.max_nesting_depth = 5U;
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1,
				nested_payload, sizeof(nested_payload)),
			0L);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_kmes_runtime_rate_change_clamps_live_bucket(
	struct kunit *test)
{
	const void *token;
	struct pkm_kmes_runtime_config config;
	u32 tokens = 0;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_refill_frozen(true),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_current_process_rate_tokens(1000U),
			0);

	config = pkm_kunit_kmes_default_config();
	config.max_emit_rate_per_process = PKM_KUNIT_KMES_MIN_RATE;
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_runtime_config_apply(&config),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, (u32)PKM_KUNIT_KMES_MIN_RATE);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_emit_for_token(
				token, PKM_KUNIT_KMES_USER_TYPE,
				sizeof(PKM_KUNIT_KMES_USER_TYPE) - 1,
				&(const u8){ 0xc0 }, 1),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_get_current_process_rate_tokens(&tokens), 0);
	KUNIT_EXPECT_EQ(test, tokens, (u32)(PKM_KUNIT_KMES_MIN_RATE - 1U));
	kacs_rust_token_drop(token);
}

static struct kunit_case pkm_kunit_kmes_cases[] = {
	KUNIT_CASE(pkm_kunit_kmes_direct_emit_writes_single_event),
	KUNIT_CASE(pkm_kunit_kmes_identity_stamps_match_kacs_state),
	KUNIT_CASE(pkm_kunit_kmes_live_overrun_advances_tail_to_survivors),
	KUNIT_CASE(pkm_kunit_kmes_direct_invalid_type_drops_structurally),
	KUNIT_CASE(pkm_kunit_kmes_attach_success_returns_cpu_fds),
	KUNIT_CASE(pkm_kunit_kmes_attach_repeated_same_cpu_shares_consumer_metadata),
	KUNIT_CASE(pkm_kunit_kmes_mmap_clears_write_upgrade),
	KUNIT_CASE(pkm_kunit_kmes_attach_einval_on_out_of_range_cpu),
	KUNIT_CASE(pkm_kunit_kmes_attach_denies_without_security),
	KUNIT_CASE(pkm_kunit_kmes_attach_checks_privilege_before_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_attach_mapping_view_tracks_emission),
	KUNIT_CASE(pkm_kunit_kmes_consumer_restart_sees_surviving_events),
	KUNIT_CASE(pkm_kunit_kmes_swap_old_fd_freezes_and_new_attach_rebinds),
	KUNIT_CASE(pkm_kunit_kmes_swap_wakes_old_generation_waiter),
	KUNIT_CASE(pkm_kunit_kmes_swap_downsize_preserves_newest_suffix),
	KUNIT_CASE(pkm_kunit_kmes_swap_failed_allocation_keeps_live_ring),
	KUNIT_CASE(pkm_kunit_kmes_emit_user_success),
	KUNIT_CASE(pkm_kunit_kmes_emit_denies_before_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_emit_rejects_invalid_msgpack),
	KUNIT_CASE(pkm_kunit_kmes_emit_size_check_precedes_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_emit_zero_type_precedes_size_and_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_emit_rate_limit_denies_without_tcb),
	KUNIT_CASE(pkm_kunit_kmes_emit_tcb_exempts_rate_limit),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_success_shared_timestamp),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_partial_refunds_unused_tokens),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_checks_emitted_out_before_entries),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_count_precedes_rate_and_emitted_out),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_overflow_precedes_entry_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_emit_batch_max_size_precedes_entry_usercopy),
	KUNIT_CASE(pkm_kunit_kmes_kernel_batch_continues_after_structural_drop),
	KUNIT_CASE(pkm_kunit_kmes_kernel_batch_empty_noop),
	KUNIT_CASE(pkm_kunit_kmes_runtime_config_validates_ranges),
	KUNIT_CASE(pkm_kunit_kmes_runtime_max_event_size_controls_syscall),
	KUNIT_CASE(pkm_kunit_kmes_runtime_nesting_depth_controls_validation),
	KUNIT_CASE(pkm_kunit_kmes_runtime_rate_change_clamps_live_bucket),
	{}
};

static struct kunit_suite pkm_kunit_kmes_suite = {
	.name = "pkm_kunit_kmes",
	.test_cases = pkm_kunit_kmes_cases,
};

kunit_test_suite(pkm_kunit_kmes_suite);
