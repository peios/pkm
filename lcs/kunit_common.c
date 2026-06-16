// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


bool pkm_lcs_kunit_usercopy_read(void *raw_ctx, void *dst,
					const void __user *src, size_t len)
{
	struct pkm_lcs_kunit_usercopy_ctx *ctx = raw_ctx;
	const void *ksrc = (const void *)(unsigned long)src;

	ctx->reads++;
	if (!ksrc || ksrc == ctx->fault_src)
		return false;

	memcpy(dst, ksrc, len);
	return true;
}


bool pkm_lcs_kunit_usercopy_write(void *raw_ctx, void __user *dst,
					 const void *src, size_t len)
{
	struct pkm_lcs_kunit_usercopy_ctx *ctx = raw_ctx;
	void *kdst = (void *)(unsigned long)dst;

	ctx->writes++;
	if (!kdst || kdst == ctx->fault_dst)
		return false;

	memcpy(kdst, src, len);
	return true;
}


size_t pkm_lcs_kunit_usercopy_strnlen(void *raw_ctx,
					     const char __user *src,
					     size_t max)
{
	struct pkm_lcs_kunit_usercopy_ctx *ctx = raw_ctx;
	const char *ksrc = (const char *)(unsigned long)src;
	size_t i;

	ctx->strnlens++;
	if (!ksrc || ksrc == ctx->fault_strlen_src)
		return 0;
	if (ksrc == ctx->unterminated_src)
		return max + 1;

	for (i = 0; i < max; i++) {
		if (ksrc[i] == '\0')
			return i + 1;
	}
	return max + 1;
}


struct pkm_lcs_usercopy_ops pkm_lcs_kunit_usercopy_ops(
	struct pkm_lcs_kunit_usercopy_ctx *ctx)
{
	return (struct pkm_lcs_usercopy_ops) {
		.read = pkm_lcs_kunit_usercopy_read,
		.write = pkm_lcs_kunit_usercopy_write,
		.strnlen = pkm_lcs_kunit_usercopy_strnlen,
		.ctx = ctx,
	};
}


ssize_t pkm_lcs_kunit_backup_output_write_iter(
	struct kiocb *iocb, struct iov_iter *from)
{
	struct pkm_lcs_kunit_backup_output_file *output =
		iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);

	if (!output)
		return -EINVAL;
	if (count > sizeof(output->data) - output->len)
		return -ENOSPC;
	if (!copy_from_iter_full(output->data + output->len, count, from))
		return -EFAULT;
	output->len += count;
	return count;
}


ssize_t pkm_lcs_kunit_restore_input_read_iter(
	struct kiocb *iocb, struct iov_iter *to)
{
	struct pkm_lcs_kunit_restore_input_file *input =
		iocb->ki_filp->private_data;
	loff_t pos = iocb->ki_pos;
	size_t count;
	size_t copied;

	if (!input)
		return -EINVAL;
	if (pos < 0)
		return -EINVAL;
	if ((size_t)pos >= input->len)
		return 0;

	count = min_t(size_t, iov_iter_count(to), input->len - (size_t)pos);
	copied = copy_to_iter(input->data + (size_t)pos, count, to);
	iocb->ki_pos += copied;
	return copied;
}


void pkm_lcs_kunit_build_register_args(
	struct reg_src_register_args *args, struct reg_src_hive_entry *hive,
	const char *name, u8 root_guid_first, u64 max_sequence)
{
	memset(args, 0, sizeof(*args));
	memset(hive, 0, sizeof(*hive));
	hive->name_len = strlen(name);
	hive->name_ptr = (u64)(unsigned long)name;
	hive->root_guid[0] = root_guid_first;
	args->hive_count = 1;
	args->max_sequence = max_sequence;
	args->hives_ptr = (u64)(unsigned long)hive;
}


void pkm_lcs_kunit_build_private_register_args(
	struct reg_src_register_args *args, struct reg_src_hive_entry *hive,
	const char *name, u8 root_guid_first, u8 scope_guid_first)
{
	pkm_lcs_kunit_build_register_args(args, hive, name, root_guid_first, 0);
	hive->flags = RSI_HIVE_PRIVATE;
	hive->scope_guid[0] = scope_guid_first;
}


void pkm_lcs_kunit_expect_materialized_component(
	struct kunit *test, const struct pkm_lcs_materialized_path *path,
	u32 index, const char *expected)
{
	size_t expected_len = strlen(expected);

	KUNIT_ASSERT_NOT_NULL(test, path);
	KUNIT_ASSERT_TRUE(test, index < path->component_count);
	KUNIT_ASSERT_NOT_NULL(test, path->components[index].name);
	KUNIT_ASSERT_EQ(test, path->components[index].name_len,
			(u32)expected_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(path->components[index].name, expected,
			       expected_len),
			0);
}


long pkm_lcs_kunit_publish_create_finish_fd(void)
{
	static const char * const path[] = { "Machine" };
	static const u8 ancestors[1][PKM_LCS_GUID_BYTES] = {
		{ 0x8a },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 1,
		.granted_access = KEY_READ,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 1,
	};

	memcpy(input.key_guid, ancestors[0], sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}


long pkm_lcs_kunit_retry_open_resolution_prepare(
	struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 root_guid[RSI_GUID_SIZE], const char *child_name)
{
	if (!resolution || !root_guid || !child_name)
		return -EINVAL;

	memset(resolution, 0, sizeof(*resolution));
	resolution->parent.resolved_path =
		kcalloc(1, sizeof(*resolution->parent.resolved_path),
			GFP_KERNEL);
	if (!resolution->parent.resolved_path)
		return -ENOMEM;
	resolution->parent.ancestor_guids =
		kcalloc(1, sizeof(*resolution->parent.ancestor_guids),
			GFP_KERNEL);
	if (!resolution->parent.ancestor_guids)
		goto out_nomem;
	resolution->parent.resolved_path[0] = kstrdup("Machine", GFP_KERNEL);
	if (!resolution->parent.resolved_path[0])
		goto out_nomem;
	resolution->child_name = kstrdup(child_name, GFP_KERNEL);
	if (!resolution->child_name)
		goto out_nomem;

	resolution->parent.source_id = 1;
	resolution->parent.component_count = 1;
	memcpy(resolution->parent.key_guid, root_guid, RSI_GUID_SIZE);
	memcpy(resolution->parent.ancestor_guids[0], root_guid, RSI_GUID_SIZE);
	resolution->child_name_len = strlen(child_name);
	resolution->child_depth = 2;
	return 0;

out_nomem:
	pkm_lcs_create_missing_parent_resolution_destroy(resolution);
	return -ENOMEM;
}


bool pkm_lcs_kunit_buffer_contains(const u8 *buffer, size_t buffer_len,
					  const char *needle)
{
	size_t needle_len;
	size_t i;

	if (!buffer || !needle)
		return false;

	needle_len = strlen(needle);
	if (!needle_len || needle_len > buffer_len)
		return false;

	for (i = 0; i <= buffer_len - needle_len; i++) {
		if (!memcmp(buffer + i, needle, needle_len))
			return true;
	}

	return false;
}


void pkm_lcs_kunit_expect_latest_lcs_event(
	struct kunit *test, const char *event_type, const char *payload_field)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[1024];
	size_t written = 0;
	u32 header_size;
	u16 type_len;
	size_t event_type_len;

	KUNIT_ASSERT_NOT_NULL(test, event_type);
	event_type_len = strlen(event_type);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_LCS, event_type, event_type_len,
				buffer, sizeof(buffer), &written, &snapshot),
			0);
	KUNIT_ASSERT_GT(test, written, (size_t)KMES_EVENT_HEADER_BASE_SIZE);

	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)event_type_len);
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_LCS);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_EXPECT_EQ(test, buffer[header_size], 0x83);
	if (payload_field)
		KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
						buffer, written, payload_field));
}


void pkm_lcs_kunit_expect_latest_kmes_origin_event(
	struct kunit *test, const char *event_type, u8 expected_map_prefix,
	const char *first_payload_field, const char *second_payload_field)
{
	struct pkm_kmes_kunit_snapshot snapshot = { };
	u8 buffer[1024];
	size_t written = 0;
	u32 header_size;
	u16 type_len;
	size_t event_type_len;

	KUNIT_ASSERT_NOT_NULL(test, event_type);
	event_type_len = strlen(event_type);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_KMES, event_type, event_type_len,
				buffer, sizeof(buffer), &written, &snapshot),
			0);
	KUNIT_ASSERT_GT(test, written, (size_t)KMES_EVENT_HEADER_BASE_SIZE);

	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)event_type_len);
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_KMES);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_EXPECT_EQ(test, buffer[header_size], expected_map_prefix);
	if (first_payload_field)
		KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
						buffer, written,
						first_payload_field));
	if (second_payload_field)
		KUNIT_EXPECT_TRUE(test, pkm_lcs_kunit_buffer_contains(
						buffer, written,
						second_payload_field));
}


void pkm_lcs_kunit_expect_runtime_limits_defaults(
	struct kunit *test, const struct pkm_lcs_runtime_limits *limits)
{
	KUNIT_ASSERT_NOT_NULL(test, limits);
	KUNIT_EXPECT_EQ(test, limits->request_timeout_ms, 30000U);
	KUNIT_EXPECT_EQ(test, limits->transaction_timeout_ms, 30000U);
	KUNIT_EXPECT_EQ(test, limits->notification_queue_size, 256U);
	KUNIT_EXPECT_EQ(test, limits->symlink_depth_limit, 16U);
	KUNIT_EXPECT_EQ(test, limits->max_value_size, 1048576U);
	KUNIT_EXPECT_EQ(test, limits->max_key_depth, 512U);
	KUNIT_EXPECT_EQ(test, limits->max_path_component_length, 255U);
	KUNIT_EXPECT_EQ(test, limits->max_total_path_length, 16383U);
	KUNIT_EXPECT_EQ(test, limits->max_layers_per_value, 128U);
	KUNIT_EXPECT_EQ(test, limits->max_bound_transactions_per_source, 16U);
	KUNIT_EXPECT_EQ(test, limits->max_read_only_transactions_per_source,
			16U);
	KUNIT_EXPECT_EQ(test, limits->max_total_layers, 1024U);
	KUNIT_EXPECT_EQ(test, limits->max_registered_sources, 32U);
	KUNIT_EXPECT_EQ(test, limits->max_hives_per_source, 64U);
	KUNIT_EXPECT_EQ(test, limits->max_concurrent_rsi_requests, 256U);
	KUNIT_EXPECT_EQ(test, limits->max_scope_guids_per_token, 8U);
	KUNIT_EXPECT_EQ(test, limits->max_private_layers_per_token, 16U);
	KUNIT_EXPECT_EQ(test, limits->max_subtree_watch_depth, 0U);
	KUNIT_EXPECT_EQ(test, limits->max_transaction_watch_event_burst, 4096U);
}


void pkm_lcs_kunit_fill_self_config_defaults(
	struct pkm_lcs_self_config_entry *entries)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(pkm_lcs_kunit_self_config_defaults); i++) {
		entries[i].name = pkm_lcs_kunit_self_config_defaults[i].name;
		entries[i].name_len = strlen(entries[i].name);
		entries[i].value_kind = PKM_LCS_SELF_CONFIG_VALUE_DWORD;
		entries[i].value_type = REG_DWORD;
		entries[i].value_u32 =
			pkm_lcs_kunit_self_config_defaults[i].value;
	}
}


bool pkm_lcs_kunit_buffer_contains_bytes(const u8 *buffer,
						size_t buffer_len,
						const u8 *needle,
						size_t needle_len)
{
	size_t i;

	if (!buffer || !needle)
		return false;
	if (!needle_len || needle_len > buffer_len)
		return false;

	for (i = 0; i <= buffer_len - needle_len; i++) {
		if (!memcmp(buffer + i, needle, needle_len))
			return true;
	}

	return false;
}


long pkm_lcs_kunit_publish_key_fd_with_access(u32 granted_access)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 0x51 },
		{ 0x52 },
	};
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 11,
		.granted_access = granted_access,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};

	memcpy(input.key_guid, ancestors[1], sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}


void pkm_lcs_kunit_flush_deferred_key_fd_release(void)
{
	/*
	 * KUnit closes fds through close_fd(), which uses deferred fput in
	 * kernel context. Flush it before tests assert release-time watch
	 * registry effects.
	 */
	task_work_run();
	flush_delayed_fput();
}


long pkm_lcs_kunit_publish_key_fd_for_source(
	u32 source_id, const u8 root_guid[PKM_LCS_GUID_BYTES],
	const u8 key_guid[PKM_LCS_GUID_BYTES], u32 granted_access)
{
	static const char * const path[] = { "Machine", "Software" };
	u8 ancestors[2][PKM_LCS_GUID_BYTES];
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = source_id,
		.granted_access = granted_access,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = 2,
	};

	memset(ancestors, 0, sizeof(ancestors));
	memcpy(ancestors[0], root_guid, sizeof(ancestors[0]));
	memcpy(ancestors[1], key_guid, sizeof(ancestors[1]));
	memcpy(input.key_guid, key_guid, sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}


long pkm_lcs_kunit_publish_key_fd_from_path(
	u32 source_id, u32 granted_access, const char * const *path,
	const u8 (*ancestors)[PKM_LCS_GUID_BYTES], u32 depth)
{
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = source_id,
		.granted_access = granted_access,
		.resolved_path = path,
		.ancestor_guids = ancestors,
		.path_component_count = depth,
	};

	if (!depth)
		return -EINVAL;
	memcpy(input.key_guid, ancestors[depth - 1U], sizeof(input.key_guid));
	return pkm_lcs_key_fd_publish(&input);
}


long pkm_lcs_kunit_publish_key_fd_with_depth(u32 depth)
{
	const char **path;
	u8 (*ancestors)[PKM_LCS_GUID_BYTES];
	struct pkm_lcs_key_fd_publish_input input = {
		.source_id = 12,
		.granted_access = KEY_QUERY_VALUE,
		.path_component_count = depth,
	};
	long fd;
	u32 i;

	if (!depth)
		return -EINVAL;

	path = kcalloc(depth, sizeof(*path), GFP_KERNEL);
	if (!path)
		return -ENOMEM;
	ancestors = kcalloc(depth, sizeof(*ancestors), GFP_KERNEL);
	if (!ancestors) {
		kfree(path);
		return -ENOMEM;
	}

	for (i = 0; i < depth; i++) {
		path[i] = "A";
		ancestors[i][0] = 0x70;
		ancestors[i][14] = (u8)(i >> 8);
		ancestors[i][15] = (u8)i;
	}

	input.resolved_path = path;
	input.ancestor_guids = ancestors;
	memcpy(input.key_guid, ancestors[depth - 1U], sizeof(input.key_guid));
	fd = pkm_lcs_key_fd_publish(&input);

	kfree(ancestors);
	kfree(path);
	return fd;
}


void pkm_lcs_kunit_expect_set_value_success(
	struct kunit *test, struct file *file, int fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args,
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	const u8 *data, size_t data_len, u32 value_type)
{
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.file = file,
		.expected_guid = guid,
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.expected_data = data,
		.expected_data_len = data_len,
		.expected_value_type = value_type,
		.expected_expected_sequence = args->expected_seq,
		.set_value_status = RSI_OK,
	};
	struct task_struct *task;
	u64 sequence_before = 0;
	long ret;
	int thread_ret;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_set_value_ioctl_source_thread,
			   &script, "pkm-lcs-kunit-set-value-success");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(fd, token, ops, args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 3U);
	KUNIT_EXPECT_EQ(test, script.writes, 3U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
}


void pkm_lcs_kunit_expect_set_value_layer_refresh_success(
	struct kunit *test, struct file *file, int fd, const void *token,
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args,
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	const u8 *data, size_t data_len, u32 value_type,
	const char *layer_name, const u8 *metadata_sd, size_t metadata_sd_len,
	u32 refresh_precedence, u32 refresh_enabled)
{
	struct pkm_lcs_kunit_set_value_ioctl_source_script script = {
		.file = file,
		.expected_guid = guid,
		.expected_value_name = value_name,
		.expected_layer_name = "base",
		.expected_data = data,
		.expected_data_len = data_len,
		.expected_value_type = value_type,
		.expected_expected_sequence = args->expected_seq,
		.set_value_status = RSI_OK,
		.expect_layer_refresh = true,
		.refresh_layer_name = layer_name,
		.refresh_sd = metadata_sd,
		.refresh_sd_len = metadata_sd_len,
		.refresh_precedence = refresh_precedence,
		.refresh_enabled = refresh_enabled,
		.refresh_precedence_present = true,
		.refresh_enabled_present = true,
	};
	struct task_struct *task;
	u64 sequence_before = 0;
	long ret;
	int thread_ret;

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_next_sequence_snapshot(&sequence_before),
			0L);
	script.expected_sequence = sequence_before;

	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_set_value_ioctl_source_thread, &script,
		"pkm-lcs-kunit-set-value-layer-refresh");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = pkm_lcs_kunit_key_fd_set_value_for_token(fd, token, ops, args);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 7U);
	KUNIT_EXPECT_EQ(test, script.writes, 7U);
	KUNIT_EXPECT_NE(test, script.observed_last_write_time, 0ULL);
}


int pkm_lcs_kunit_external_fd(unsigned int flags)
{
	return anon_inode_getfd("lcs-external", &pkm_lcs_kunit_non_key_fops,
				NULL, flags | O_CLOEXEC);
}


int pkm_lcs_kunit_backup_output_fd(
	struct pkm_lcs_kunit_backup_output_file *output)
{
	if (output)
		memset(output, 0, sizeof(*output));
	return anon_inode_getfd("lcs-backup-output",
				&pkm_lcs_kunit_backup_output_fops, output,
				O_WRONLY | O_CLOEXEC);
}


int pkm_lcs_kunit_restore_input_fd(
	struct pkm_lcs_kunit_restore_input_file *input)
{
	return anon_inode_getfd("lcs-restore-input",
				&pkm_lcs_kunit_restore_input_fops, input,
				O_RDONLY | O_CLOEXEC);
}


int pkm_lcs_kunit_restore_stream_append(
	struct pkm_lcs_kunit_restore_input_file *input,
	const void *src, size_t len)
{
	if (!input || (!src && len))
		return -EINVAL;
	if (len > sizeof(input->data) - input->len)
		return -ENOSPC;
	memcpy(input->data + input->len, src, len);
	input->len += len;
	return 0;
}


int pkm_lcs_kunit_restore_stream_append_u16(
	struct pkm_lcs_kunit_restore_input_file *input, u16 value)
{
	u8 encoded[sizeof(u16)];

	put_unaligned_le16(value, encoded);
	return pkm_lcs_kunit_restore_stream_append(input, encoded,
						   sizeof(encoded));
}


int pkm_lcs_kunit_restore_stream_append_u32(
	struct pkm_lcs_kunit_restore_input_file *input, u32 value)
{
	u8 encoded[sizeof(u32)];

	put_unaligned_le32(value, encoded);
	return pkm_lcs_kunit_restore_stream_append(input, encoded,
						   sizeof(encoded));
}


int pkm_lcs_kunit_restore_stream_append_u64(
	struct pkm_lcs_kunit_restore_input_file *input, u64 value)
{
	u8 encoded[sizeof(u64)];

	put_unaligned_le64(value, encoded);
	return pkm_lcs_kunit_restore_stream_append(input, encoded,
						   sizeof(encoded));
}


int pkm_lcs_kunit_restore_stream_append_s64(
	struct pkm_lcs_kunit_restore_input_file *input, s64 value)
{
	return pkm_lcs_kunit_restore_stream_append_u64(input, (u64)value);
}


int pkm_lcs_kunit_restore_stream_append_record_header(
	struct pkm_lcs_kunit_restore_input_file *input,
	u16 record_type, u32 record_len)
{
	int ret;

	ret = pkm_lcs_kunit_restore_stream_append_u16(input, record_type);
	if (ret)
		return ret;
	return pkm_lcs_kunit_restore_stream_append_u32(input, record_len);
}


int pkm_lcs_kunit_restore_stream_append_key_record(
	struct pkm_lcs_kunit_restore_input_file *input,
	const u8 guid[PKM_LCS_GUID_BYTES], bool volatile_key, bool symlink)
{
	u8 frame[128];
	size_t written = 0;
	int ret;

	ret = lcs_rust_write_backup_key_record_frame(
		frame, sizeof(frame), guid, volatile_key ? 1 : 0,
		symlink ? 1 : 0, pkm_lcs_kunit_owner_only_sd,
		sizeof(pkm_lcs_kunit_owner_only_sd), 5678, &written);
	if (ret)
		return ret;
	return pkm_lcs_kunit_restore_stream_append(input, frame, written);
}


int pkm_lcs_kunit_restore_stream_append_header(
	struct pkm_lcs_kunit_restore_input_file *input)
{
	static const char hive_name[] = "Machine";
	u32 header_len = 6 + 8 + 4 + 4 + 8 + PKM_LCS_GUID_BYTES + 4 +
			 sizeof(hive_name) - 1;
	int ret;

	ret = pkm_lcs_kunit_restore_stream_append_record_header(
		input, REG_BACKUP_HEADER, header_len);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, REG_BACKUP_MAGIC, sizeof(REG_BACKUP_MAGIC) - 1);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(input, 21U);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(input, 21U);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_s64(input, 1234);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, pkm_lcs_kunit_restore_header_root_guid,
		sizeof(pkm_lcs_kunit_restore_header_root_guid));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(
		input, sizeof(hive_name) - 1);
	if (ret)
		return ret;
	return pkm_lcs_kunit_restore_stream_append(
		input, hive_name, sizeof(hive_name) - 1);
}


int pkm_lcs_kunit_restore_stream_append_trailer(
	struct pkm_lcs_kunit_restore_input_file *input, u64 record_count)
{
	struct sha256_ctx checksum_ctx;
	u8 checksum[SHA256_DIGEST_SIZE];
	size_t trailer_offset;
	int ret;

	trailer_offset = input->len;
	ret = pkm_lcs_kunit_restore_stream_append_record_header(
		input, REG_BACKUP_TRAILER,
		6 + sizeof(u64) + SHA256_DIGEST_SIZE);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u64(input, record_count);
	if (ret)
		return ret;
	memset(checksum, 0, sizeof(checksum));
	ret = pkm_lcs_kunit_restore_stream_append(input, checksum,
						  sizeof(checksum));
	if (ret)
		return ret;

	sha256_init(&checksum_ctx);
	sha256_update(&checksum_ctx, input->data,
		      trailer_offset + 6 + sizeof(u64));
	sha256_final(&checksum_ctx, checksum);
	memcpy(input->data + trailer_offset + 6 + sizeof(u64), checksum,
	       sizeof(checksum));
	return 0;
}


int pkm_lcs_kunit_restore_stream_append_layer_record(
	struct pkm_lcs_kunit_restore_input_file *input,
	const struct pkm_lcs_kunit_restore_layer_record *layer)
{
	struct pkm_lcs_runtime_limits limits = { };
	u8 frame[256];
	size_t written = 0;
	int ret;

	if (!input || !layer || !layer->name || !layer->owner_sid)
		return -EINVAL;
	ret = pkm_lcs_runtime_limits_defaults(&limits);
	if (ret)
		return ret;
	ret = lcs_rust_write_backup_layer_manifest_record_frame(
		frame, sizeof(frame), &limits, (const u8 *)layer->name,
		strlen(layer->name), layer->precedence, layer->enabled,
		layer->owner_sid, layer->owner_sid_len, &written);
	if (ret)
		return ret;
	return pkm_lcs_kunit_restore_stream_append(input, frame, written);
}


int pkm_lcs_kunit_restore_stream_append_data_record(
	struct pkm_lcs_kunit_restore_input_file *input,
	const struct pkm_lcs_kunit_restore_data_record *record, u64 sequence)
{
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x62 };
	static const u8 value_data[] = { 0x2a };
	const u8 *effective_parent_guid = record->parent_guid ?
						  record->parent_guid :
						  pkm_lcs_kunit_restore_header_root_guid;
	const u8 *effective_child_guid = record->child_guid ?
						 record->child_guid :
						 child_guid;
	const u8 *effective_key_guid = record->key_guid ?
					       record->key_guid :
					       pkm_lcs_kunit_restore_header_root_guid;
	const u8 *effective_value_data = record->value_data ?
						 record->value_data :
						 value_data;
	const char *child_name = record->child_name ? record->child_name :
						       "Child";
	const char *value_name = record->value_name ? record->value_name :
						       "Answer";
	size_t effective_value_data_len = record->value_data ?
						  record->value_data_len :
						  sizeof(value_data);
	u32 effective_value_type = record->value_type ? record->value_type :
							REG_BINARY;
	u8 *frame = NULL;
	size_t frame_len = 0;
	long ret;

	if (!input || !record || !record->layer_name)
		return -EINVAL;

	switch (record->record_type) {
	case REG_BACKUP_PATH_ENTRY:
		ret = pkm_lcs_kunit_backup_path_entry_frame(
			effective_parent_guid, child_name, strlen(child_name),
			effective_child_guid, record->hidden,
			record->layer_name, strlen(record->layer_name), sequence,
			&frame,
			&frame_len);
		break;
	case REG_BACKUP_VALUE:
		ret = pkm_lcs_kunit_backup_value_frame(
			effective_key_guid, value_name, strlen(value_name),
			effective_value_type, effective_value_data,
			effective_value_data_len,
			record->layer_name,
			strlen(record->layer_name), sequence, &frame,
			&frame_len);
		break;
	case REG_BACKUP_BLANKET_TOMBSTONE:
		ret = pkm_lcs_kunit_backup_blanket_tombstone_frame(
			effective_key_guid, record->layer_name,
			strlen(record->layer_name), sequence, &frame,
			&frame_len);
		break;
	default:
		return -EINVAL;
	}
	if (ret)
		return (int)ret;
	ret = pkm_lcs_kunit_restore_stream_append(input, frame, frame_len);
	kfree(frame);
	return (int)ret;
}


int pkm_lcs_kunit_restore_stream_build_valid(
	struct pkm_lcs_kunit_restore_input_file *input, bool include_unknown)
{
	return pkm_lcs_kunit_restore_stream_build_with_root_keys(
		input, include_unknown, 1, false, false);
}


int pkm_lcs_kunit_restore_stream_build_with_root_keys(
	struct pkm_lcs_kunit_restore_input_file *input, bool include_unknown,
	u32 root_key_count, bool root_volatile, bool root_symlink)
{
	static const char hive_name[] = "Machine";
	static const u8 unknown_payload[] = { 'o', 'p', 't' };
	struct sha256_ctx checksum_ctx;
	u8 checksum[SHA256_DIGEST_SIZE];
	size_t trailer_offset;
	u64 record_count = 2 + root_key_count + (include_unknown ? 1 : 0);
	u32 header_len = 6 + 8 + 4 + 4 + 8 + PKM_LCS_GUID_BYTES + 4 +
			 sizeof(hive_name) - 1;
	u32 unknown_len = 6 + sizeof(unknown_payload);
	u32 i;
	int ret;

	if (!input)
		return -EINVAL;
	memset(input, 0, sizeof(*input));

	ret = pkm_lcs_kunit_restore_stream_append_record_header(
		input, REG_BACKUP_HEADER, header_len);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, REG_BACKUP_MAGIC, sizeof(REG_BACKUP_MAGIC) - 1);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(input, 21U);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(input, 21U);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_s64(input, 1234);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, pkm_lcs_kunit_restore_header_root_guid,
		sizeof(pkm_lcs_kunit_restore_header_root_guid));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(
		input, sizeof(hive_name) - 1);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, hive_name, sizeof(hive_name) - 1);
	if (ret)
		return ret;

	if (include_unknown) {
		ret = pkm_lcs_kunit_restore_stream_append_record_header(
			input, 0x9001U, unknown_len);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_restore_stream_append(
			input, unknown_payload, sizeof(unknown_payload));
		if (ret)
			return ret;
	}

	for (i = 0; i < root_key_count; i++) {
		ret = pkm_lcs_kunit_restore_stream_append_key_record(
			input, pkm_lcs_kunit_restore_header_root_guid,
			root_volatile, root_symlink);
		if (ret)
			return ret;
	}

	trailer_offset = input->len;
	ret = pkm_lcs_kunit_restore_stream_append_record_header(
		input, REG_BACKUP_TRAILER,
		6 + sizeof(u64) + SHA256_DIGEST_SIZE);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u64(input, record_count);
	if (ret)
		return ret;
	memset(checksum, 0, sizeof(checksum));
	ret = pkm_lcs_kunit_restore_stream_append(input, checksum,
						  sizeof(checksum));
	if (ret)
		return ret;

	sha256_init(&checksum_ctx);
	sha256_update(&checksum_ctx, input->data,
		      trailer_offset + 6 + sizeof(u64));
	sha256_final(&checksum_ctx, checksum);
	memcpy(input->data + trailer_offset + 6 + sizeof(u64), checksum,
	       sizeof(checksum));
	return 0;
}


int pkm_lcs_kunit_restore_stream_build_with_layers(
	struct pkm_lcs_kunit_restore_input_file *input,
	const struct pkm_lcs_kunit_restore_layer_record *layers,
	u32 layer_count, bool layer_after_key)
{
	static const char hive_name[] = "Machine";
	struct sha256_ctx checksum_ctx;
	u8 checksum[SHA256_DIGEST_SIZE];
	size_t trailer_offset;
	u64 record_count = 2 + 1 + layer_count;
	u32 header_len = 6 + 8 + 4 + 4 + 8 + PKM_LCS_GUID_BYTES + 4 +
			 sizeof(hive_name) - 1;
	u32 i;
	int ret;

	if (!input || (!layers && layer_count))
		return -EINVAL;
	memset(input, 0, sizeof(*input));

	ret = pkm_lcs_kunit_restore_stream_append_record_header(
		input, REG_BACKUP_HEADER, header_len);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, REG_BACKUP_MAGIC, sizeof(REG_BACKUP_MAGIC) - 1);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(input, 21U);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(input, 21U);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_s64(input, 1234);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, pkm_lcs_kunit_restore_header_root_guid,
		sizeof(pkm_lcs_kunit_restore_header_root_guid));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u32(
		input, sizeof(hive_name) - 1);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append(
		input, hive_name, sizeof(hive_name) - 1);
	if (ret)
		return ret;

	if (!layer_after_key) {
		for (i = 0; i < layer_count; i++) {
			ret = pkm_lcs_kunit_restore_stream_append_layer_record(
				input, &layers[i]);
			if (ret)
				return ret;
		}
	}

	ret = pkm_lcs_kunit_restore_stream_append_key_record(
		input, pkm_lcs_kunit_restore_header_root_guid, false, false);
	if (ret)
		return ret;

	if (layer_after_key) {
		for (i = 0; i < layer_count; i++) {
			ret = pkm_lcs_kunit_restore_stream_append_layer_record(
				input, &layers[i]);
			if (ret)
				return ret;
		}
	}

	trailer_offset = input->len;
	ret = pkm_lcs_kunit_restore_stream_append_record_header(
		input, REG_BACKUP_TRAILER,
		6 + sizeof(u64) + SHA256_DIGEST_SIZE);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_restore_stream_append_u64(input, record_count);
	if (ret)
		return ret;
	memset(checksum, 0, sizeof(checksum));
	ret = pkm_lcs_kunit_restore_stream_append(input, checksum,
						  sizeof(checksum));
	if (ret)
		return ret;

	sha256_init(&checksum_ctx);
	sha256_update(&checksum_ctx, input->data,
		      trailer_offset + 6 + sizeof(u64));
	sha256_final(&checksum_ctx, checksum);
	memcpy(input->data + trailer_offset + 6 + sizeof(u64), checksum,
	       sizeof(checksum));
	return 0;
}


int pkm_lcs_kunit_restore_stream_build_with_data_records(
	struct pkm_lcs_kunit_restore_input_file *input,
	const struct pkm_lcs_kunit_restore_layer_record *layers,
	u32 layer_count,
	const struct pkm_lcs_kunit_restore_data_record *records,
	u32 record_count)
{
	u64 total_record_count = 2 + 1 + layer_count + record_count;
	u32 i;
	int ret;

	if (!input || (!layers && layer_count) || (!records && record_count))
		return -EINVAL;
	memset(input, 0, sizeof(*input));

	ret = pkm_lcs_kunit_restore_stream_append_header(input);
	if (ret)
		return ret;

	for (i = 0; i < layer_count; i++) {
		ret = pkm_lcs_kunit_restore_stream_append_layer_record(
			input, &layers[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < record_count; i++) {
		if (!records[i].before_key)
			continue;
		ret = pkm_lcs_kunit_restore_stream_append_data_record(
			input, &records[i], i + 1);
		if (ret)
			return ret;
	}

	ret = pkm_lcs_kunit_restore_stream_append_key_record(
		input, pkm_lcs_kunit_restore_header_root_guid, false, false);
	if (ret)
		return ret;

	for (i = 0; i < record_count; i++) {
		if (records[i].before_key)
			continue;
		ret = pkm_lcs_kunit_restore_stream_append_data_record(
			input, &records[i], i + 1);
		if (ret)
			return ret;
	}

	return pkm_lcs_kunit_restore_stream_append_trailer(
		input, total_record_count);
}


long pkm_lcs_kunit_publish_source_one_key_fd_with_access(
	u32 granted_access)
{
	static const u8 root_guid[PKM_LCS_GUID_BYTES] = { 1 };

	return pkm_lcs_kunit_publish_key_fd_for_source(
		1, root_guid, pkm_lcs_kunit_restore_target_guid,
		granted_access);
}


long pkm_lcs_kunit_publish_source_one_backup_key_fd(void)
{
	return pkm_lcs_kunit_publish_source_one_key_fd_with_access(
		KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE);
}


long pkm_lcs_kunit_publish_restarted_missing_key_fd(
	struct file *resumed_file, const void **source_token_out,
	u32 granted_access)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry first_hive;
	struct reg_src_register_args first_args;
	struct reg_src_hive_entry second_hive;
	struct reg_src_register_args second_args;
	struct file first_file = { };
	const void *source_token;
	bool first_open = false;
	bool resumed_open = false;
	long key_fd = -1;
	long ret;

	if (!resumed_file || !source_token_out)
		return -EINVAL;
	*source_token_out = NULL;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_reset_source_table();
	source_token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_TCB_PRIVILEGE);
	if (!source_token)
		return -ENOMEM;

	ret = pkm_lcs_source_device_open_file_for_token(source_token,
						       &first_file);
	if (ret)
		goto out_token;
	first_open = true;
	pkm_lcs_kunit_build_register_args(&first_args, &first_hive,
					  name_src, 1, 0);
	ret = pkm_lcs_source_register_file_for_token(
		source_token, &first_file, &ops,
		(const void __user *)&first_args);
	if (ret)
		goto out_first;

	key_fd = pkm_lcs_kunit_publish_source_one_key_fd_with_access(
		granted_access);
	if (key_fd < 0) {
		ret = key_fd;
		goto out_first;
	}

	ret = pkm_lcs_source_device_release_file(&first_file);
	if (ret)
		goto out_key;
	first_open = false;

	ret = pkm_lcs_source_device_open_file_for_token(source_token,
						       resumed_file);
	if (ret)
		goto out_key;
	resumed_open = true;
	pkm_lcs_kunit_build_register_args(&second_args, &second_hive,
					  name_src, 1, 7);
	ret = pkm_lcs_source_register_file_for_token(
		source_token, resumed_file, &ops,
		(const void __user *)&second_args);
	if (ret)
		goto out_resumed;

	*source_token_out = source_token;
	return key_fd;

out_resumed:
	if (resumed_open)
		(void)pkm_lcs_source_device_release_file(resumed_file);
out_key:
	if (key_fd >= 0) {
		(void)close_fd((unsigned int)key_fd);
		pkm_lcs_kunit_flush_deferred_key_fd_release();
	}
out_first:
	if (first_open)
		(void)pkm_lcs_source_device_release_file(&first_file);
out_token:
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(source_token);
	return ret;
}


long pkm_lcs_kunit_publish_restarted_missing_backup_restore_fd(
	struct file *resumed_file, const void **source_token_out)
{
	return pkm_lcs_kunit_publish_restarted_missing_key_fd(
		resumed_file, source_token_out,
		KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE);
}


ssize_t pkm_lcs_kunit_backup_snapshot_read_source_request(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			return count;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return -EINTR;
		}
		msleep(1);
	}
}


int pkm_lcs_kunit_backup_snapshot_write_status(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id, u16 op_code, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(op_code | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response)) {
		script->result = (int)count;
		return script->result;
	}
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_backup_snapshot_write_empty_enum_children(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id)
{
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32) + sizeof(u32)];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_ENUM_CHILDREN | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
					     &offset, 0);
	pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
					     &offset, 0);
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_backup_snapshot_write_empty_query_values(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id)
{
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32) + sizeof(u32)];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
					     &offset, 0);
	pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
					     &offset, 0);
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_backup_snapshot_write_query_values(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id, const char *value_name, const u8 *value_data,
	size_t value_data_len, bool include_blanket)
{
	u8 response[256];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;
	int ret;

	if (!value_name || !value_data || !value_data_len)
		return -EINVAL;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						   &offset, 1);
	if (ret)
		goto out_error;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, sizeof(response), &offset, value_name,
		strlen(value_name));
	if (ret)
		goto out_error;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, sizeof(response), &offset, "base", strlen("base"));
	if (ret)
		goto out_error;
	ret = pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						   &offset, REG_BINARY);
	if (ret)
		goto out_error;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, sizeof(response), &offset, value_data,
		value_data_len);
	if (ret)
		goto out_error;
	ret = pkm_lcs_kunit_walk_source_append_u64(response, sizeof(response),
						   &offset, 0);
	if (ret)
		goto out_error;
	ret = pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						   &offset,
						   include_blanket ? 1 : 0);
	if (ret)
		goto out_error;
	if (include_blanket) {
		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, sizeof(response), &offset, "base",
			strlen("base"));
		if (ret)
			goto out_error;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, sizeof(response), &offset, 0);
		if (ret)
			goto out_error;
	}
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	return 0;

out_error:
	script->result = ret;
	return ret;
}


int pkm_lcs_kunit_backup_snapshot_write_root_query_values(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id)
{
	static const u8 value_data[] = { 0xde, 0xad, 0xbe, 0xef };

	return pkm_lcs_kunit_backup_snapshot_write_query_values(
		script, request_id, "RootValue", value_data,
		sizeof(value_data), true);
}


int pkm_lcs_kunit_backup_snapshot_write_child_query_values(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id)
{
	static const u8 value_data[] = { 0xc0, 0xff, 0xee };

	return pkm_lcs_kunit_backup_snapshot_write_query_values(
		script, request_id, "ChildValue", value_data,
		sizeof(value_data), true);
}


int pkm_lcs_kunit_backup_snapshot_write_grandchild_query_values(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u64 request_id)
{
	static const u8 value_data[] = { 0x5a, 0x5b };

	return pkm_lcs_kunit_backup_snapshot_write_query_values(
		script, request_id, "GrandchildValue", value_data,
		sizeof(value_data), true);
}


int pkm_lcs_kunit_backup_snapshot_handle_export_read(
	struct pkm_lcs_kunit_backup_snapshot_source_script *script,
	u16 expected_op, const u8 expected_guid[PKM_LCS_GUID_BYTES],
	u8 *request, size_t request_len)
{
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53 };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x54 };
	bool child_request = !memcmp(expected_guid, child_guid,
				     PKM_LCS_GUID_BYTES);
	bool grandchild_request = !memcmp(expected_guid, grandchild_guid,
					  PKM_LCS_GUID_BYTES);
		struct pkm_lcs_kunit_read_key_source_script read_key = {
			.expected_guid = expected_guid,
			.name = grandchild_request ? "Grandchild" :
						     child_request ? "Child" :
								     "Software",
			.last_write_time = child_request || grandchild_request ?
						   5678ULL : 2000ULL,
			.expected_txn_id = script->transaction_id,
		};
	struct pkm_lcs_kunit_enum_children_source_script enum_children = {
		.expected_parent_guid = expected_guid,
		.child_name = child_request ? "Grandchild" : "Child",
		.layer_name = "base",
		.child_guid = child_request && script->cycle_child_response ?
				      key_guid :
				      child_request ? grandchild_guid :
						      child_guid,
		.sequence = 0,
		.hidden = !child_request && !grandchild_request &&
			  script->hidden_child_response,
	};
	u8 response[1024];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 op_code;
	int ret;

	count = pkm_lcs_kunit_backup_snapshot_read_source_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	script->reads++;
	if (count < (ssize_t)RSI_REQUEST_HEADER_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	op_code = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (op_code != expected_op ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->transaction_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	switch (expected_op) {
	case RSI_READ_KEY:
		if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE) {
			script->result = -EINVAL;
			return script->result;
		}
		ret = pkm_lcs_kunit_read_key_source_build_response(
			&read_key, request_id, response, sizeof(response),
			&response_len);
		if (ret) {
			script->result = ret;
			return ret;
		}
		count = pkm_lcs_kunit_source_device_write_file(
			script->file, response, response_len, false, NULL);
		if (count != (ssize_t)response_len) {
			script->result = count < 0 ? (int)count : -EIO;
			return script->result;
		}
		script->writes++;
		return 0;
	case RSI_ENUM_CHILDREN:
		if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE) {
			script->result = -EINVAL;
			return script->result;
		}
		if (grandchild_request ||
		    (child_request && !script->grandchild_response &&
		     !script->cycle_child_response))
			return pkm_lcs_kunit_backup_snapshot_write_empty_enum_children(
				script, request_id);
		if (!child_request && !grandchild_request &&
		    !script->nonempty_child_response &&
		    !script->hidden_child_response)
			return pkm_lcs_kunit_backup_snapshot_write_empty_enum_children(
				script, request_id);
		ret = pkm_lcs_kunit_enum_children_source_build_response(
			&enum_children, request_id, response, sizeof(response),
			&response_len);
		if (ret) {
			script->result = ret;
			return ret;
		}
		count = pkm_lcs_kunit_source_device_write_file(
			script->file, response, response_len, false, NULL);
		if (count != (ssize_t)response_len) {
			script->result = count < 0 ? (int)count : -EIO;
			return script->result;
		}
		script->writes++;
		return 0;
	case RSI_QUERY_VALUES:
		if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
					     sizeof(u32) + sizeof(u8) ||
		    get_unaligned_le32(request + RSI_REQUEST_HEADER_SIZE +
				       RSI_GUID_SIZE) != 0 ||
		    request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
			    sizeof(u32)] != 1) {
			script->result = -EINVAL;
			return script->result;
		}
		if (child_request && script->child_value_response)
			return pkm_lcs_kunit_backup_snapshot_write_child_query_values(
				script, request_id);
		if (child_request)
			return pkm_lcs_kunit_backup_snapshot_write_empty_query_values(
				script, request_id);
		if (grandchild_request && script->grandchild_value_response)
			return pkm_lcs_kunit_backup_snapshot_write_grandchild_query_values(
				script, request_id);
		if (grandchild_request)
			return pkm_lcs_kunit_backup_snapshot_write_empty_query_values(
				script, request_id);
		if (script->root_value_response)
			return pkm_lcs_kunit_backup_snapshot_write_root_query_values(
				script, request_id);
		return pkm_lcs_kunit_backup_snapshot_write_empty_query_values(
			script, request_id);
	default:
		script->result = -EINVAL;
		return script->result;
	}
}


void pkm_lcs_kunit_expect_backup_stream_record_types(
	struct kunit *test,
	const struct pkm_lcs_kunit_backup_output_file *output,
	const u16 *expected_types, size_t expected_type_count,
	const u8 expected_root_guid[PKM_LCS_GUID_BYTES])
{
	struct sha256_ctx checksum_ctx;
	u8 checksum[SHA256_DIGEST_SIZE];
	const u8 *data = output->data;
	size_t offset = 0;
	size_t trailer_offset = 0;
	size_t trailer_prefix_len;
	size_t i;
	bool checked_root_key = false;

	KUNIT_ASSERT_GT(test, output->len, (size_t)0);
	KUNIT_ASSERT_NOT_NULL(test, expected_types);
	KUNIT_ASSERT_GT(test, expected_type_count, (size_t)0);

	for (i = 0; i < expected_type_count; i++) {
		u16 record_type;
		u32 record_len;

		KUNIT_ASSERT_LE(test, offset + 6, output->len);
		record_type = get_unaligned_le16(data + offset);
		record_len = get_unaligned_le32(data + offset + 2);
		KUNIT_EXPECT_EQ(test, record_type, expected_types[i]);
		KUNIT_ASSERT_GE(test, record_len, 6U);
		KUNIT_ASSERT_LE(test, offset + record_len, output->len);

		if (record_type == REG_BACKUP_KEY && expected_root_guid &&
		    !checked_root_key) {
			KUNIT_ASSERT_GE(test, record_len,
					6U + PKM_LCS_GUID_BYTES);
			KUNIT_EXPECT_EQ(
				test,
				memcmp(data + offset + 6, expected_root_guid,
				       PKM_LCS_GUID_BYTES),
				0);
			checked_root_key = true;
		}
		if (record_type == REG_BACKUP_TRAILER) {
			KUNIT_EXPECT_EQ(test, i, expected_type_count - 1);
			KUNIT_ASSERT_EQ(
				test, record_len,
				(u32)(6 + sizeof(u64) + SHA256_DIGEST_SIZE));
			KUNIT_EXPECT_EQ(test,
					get_unaligned_le64(data + offset + 6),
					(u64)expected_type_count);
			trailer_offset = offset;
		}
		offset += record_len;
	}

	KUNIT_ASSERT_EQ(test, offset, output->len);
	KUNIT_ASSERT_GT(test, trailer_offset, (size_t)0);
	trailer_prefix_len = trailer_offset + 6 + sizeof(u64);
	sha256_init(&checksum_ctx);
	sha256_update(&checksum_ctx, data, trailer_prefix_len);
	sha256_final(&checksum_ctx, checksum);
	KUNIT_EXPECT_EQ(test,
			memcmp(checksum,
			       data + trailer_offset + 6 + sizeof(u64),
			       SHA256_DIGEST_SIZE),
			0);
}


int pkm_lcs_kunit_backup_stream_record_at(
	const struct pkm_lcs_kunit_backup_output_file *output,
	size_t record_index, u16 expected_type, const u8 **frame_out,
	size_t *frame_len_out)
{
	const u8 *data;
	size_t offset = 0;
	size_t i;

	if (!output || !frame_out || !frame_len_out)
		return -EINVAL;
	*frame_out = NULL;
	*frame_len_out = 0;
	data = output->data;

	for (i = 0; offset < output->len; i++) {
		u16 record_type;
		u32 record_len;

		if (output->len - offset < 6)
			return -EINVAL;
		record_type = get_unaligned_le16(data + offset);
		record_len = get_unaligned_le32(data + offset + 2);
		if (record_len < 6 || record_len > output->len - offset)
			return -EINVAL;
		if (i == record_index) {
			if (record_type != expected_type)
				return -EINVAL;
			*frame_out = data + offset;
			*frame_len_out = record_len;
			return 0;
		}
		offset += record_len;
	}

	return -ENOENT;
}


void pkm_lcs_kunit_expect_empty_backup_stream(
	struct kunit *test,
	const struct pkm_lcs_kunit_backup_output_file *output,
	const u8 expected_root_guid[PKM_LCS_GUID_BYTES])
{
	static const u16 types[] = {
		REG_BACKUP_HEADER,
		REG_BACKUP_KEY,
		REG_BACKUP_TRAILER,
	};

	pkm_lcs_kunit_expect_backup_stream_record_types(
		test, output, types, ARRAY_SIZE(types), expected_root_guid);
}


void pkm_lcs_kunit_expect_layer_manifest_record(
	struct kunit *test, const u8 *frame, size_t frame_len,
	const char *expected_name, u32 expected_precedence, u8 expected_enabled,
	const u8 *expected_owner, size_t expected_owner_len)
{
	size_t expected_name_len = strlen(expected_name);
	size_t offset = 6;
	u32 record_len;
	u32 name_len;
	u32 owner_len;

	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)6);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(frame),
			(u16)REG_BACKUP_LAYER);
	record_len = get_unaligned_le32(frame + 2);
	KUNIT_ASSERT_EQ(test, (size_t)record_len, frame_len);

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	name_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)name_len, expected_name_len);
	KUNIT_ASSERT_LE(test, offset + name_len, frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(frame + offset, expected_name, name_len),
			0);
	offset += name_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32) + sizeof(u8), frame_len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + offset),
			expected_precedence);
	offset += sizeof(u32);
	KUNIT_EXPECT_EQ(test, frame[offset], expected_enabled);
	offset += sizeof(u8);

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	owner_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)owner_len, expected_owner_len);
	KUNIT_ASSERT_LE(test, offset + owner_len, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_owner, owner_len), 0);
	offset += owner_len;
	KUNIT_EXPECT_EQ(test, offset, frame_len);
}


void pkm_lcs_kunit_expect_key_record(
	struct kunit *test, const u8 *frame, size_t frame_len,
	const u8 expected_guid[PKM_LCS_GUID_BYTES], u32 expected_flags,
	const u8 *expected_sd, size_t expected_sd_len, s64 expected_last_write)
{
	size_t offset = 6;
	u32 record_len;
	u32 sd_len;

	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)6);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(frame), (u16)REG_BACKUP_KEY);
	record_len = get_unaligned_le32(frame + 2);
	KUNIT_ASSERT_EQ(test, (size_t)record_len, frame_len);

	KUNIT_ASSERT_LE(test, offset + PKM_LCS_GUID_BYTES, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_guid,
			       PKM_LCS_GUID_BYTES),
			0);
	offset += PKM_LCS_GUID_BYTES;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32) + sizeof(u32), frame_len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + offset),
			expected_flags);
	offset += sizeof(u32);
	sd_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);

	KUNIT_ASSERT_EQ(test, (size_t)sd_len, expected_sd_len);
	KUNIT_ASSERT_LE(test, offset + sd_len, frame_len);
	if (sd_len)
		KUNIT_EXPECT_EQ(test,
				memcmp(frame + offset, expected_sd, sd_len), 0);
	offset += sd_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u64), frame_len);
	KUNIT_EXPECT_EQ(test, (s64)get_unaligned_le64(frame + offset),
			expected_last_write);
	offset += sizeof(u64);
	KUNIT_EXPECT_EQ(test, offset, frame_len);
}


void pkm_lcs_kunit_expect_path_entry_record(
	struct kunit *test, const u8 *frame, size_t frame_len,
	const u8 expected_parent[PKM_LCS_GUID_BYTES],
	const char *expected_child_name,
	const u8 expected_child[PKM_LCS_GUID_BYTES],
	const char *expected_layer, u64 expected_sequence)
{
	size_t expected_child_name_len = strlen(expected_child_name);
	size_t expected_layer_len = strlen(expected_layer);
	size_t offset = 6;
	u32 record_len;
	u32 name_len;
	u32 layer_len;

	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)6);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(frame),
			(u16)REG_BACKUP_PATH_ENTRY);
	record_len = get_unaligned_le32(frame + 2);
	KUNIT_ASSERT_EQ(test, (size_t)record_len, frame_len);

	KUNIT_ASSERT_LE(test, offset + PKM_LCS_GUID_BYTES, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_parent,
			       PKM_LCS_GUID_BYTES),
			0);
	offset += PKM_LCS_GUID_BYTES;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	name_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)name_len, expected_child_name_len);
	KUNIT_ASSERT_LE(test, offset + name_len, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_child_name, name_len),
			0);
	offset += name_len;

	KUNIT_ASSERT_LE(test, offset + PKM_LCS_GUID_BYTES, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_child,
			       PKM_LCS_GUID_BYTES),
			0);
	offset += PKM_LCS_GUID_BYTES;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	layer_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)layer_len, expected_layer_len);
	KUNIT_ASSERT_LE(test, offset + layer_len, frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(frame + offset, expected_layer, layer_len),
			0);
	offset += layer_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u64), frame_len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(frame + offset),
			expected_sequence);
	offset += sizeof(u64);
	KUNIT_EXPECT_EQ(test, offset, frame_len);
}


void pkm_lcs_kunit_expect_value_record(
	struct kunit *test, const u8 *frame, size_t frame_len,
	const u8 expected_key[PKM_LCS_GUID_BYTES], const char *expected_name,
	u32 expected_type, const u8 *expected_data, size_t expected_data_len,
	const char *expected_layer, u64 expected_sequence)
{
	size_t expected_name_len = strlen(expected_name);
	size_t expected_layer_len = strlen(expected_layer);
	size_t offset = 6;
	u32 record_len;
	u32 name_len;
	u32 data_len;
	u32 layer_len;

	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)6);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(frame),
			(u16)REG_BACKUP_VALUE);
	record_len = get_unaligned_le32(frame + 2);
	KUNIT_ASSERT_EQ(test, (size_t)record_len, frame_len);

	KUNIT_ASSERT_LE(test, offset + PKM_LCS_GUID_BYTES, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_key,
			       PKM_LCS_GUID_BYTES),
			0);
	offset += PKM_LCS_GUID_BYTES;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	name_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)name_len, expected_name_len);
	KUNIT_ASSERT_LE(test, offset + name_len, frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(frame + offset, expected_name, name_len),
			0);
	offset += name_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32) + sizeof(u32), frame_len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(frame + offset),
			expected_type);
	offset += sizeof(u32);
	data_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)data_len, expected_data_len);
	KUNIT_ASSERT_LE(test, offset + data_len, frame_len);
	if (data_len)
		KUNIT_EXPECT_EQ(test,
				memcmp(frame + offset, expected_data,
				       data_len),
				0);
	offset += data_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	layer_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)layer_len, expected_layer_len);
	KUNIT_ASSERT_LE(test, offset + layer_len, frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(frame + offset, expected_layer, layer_len),
			0);
	offset += layer_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u64), frame_len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(frame + offset),
			expected_sequence);
	offset += sizeof(u64);
	KUNIT_EXPECT_EQ(test, offset, frame_len);
}


void pkm_lcs_kunit_expect_blanket_tombstone_record(
	struct kunit *test, const u8 *frame, size_t frame_len,
	const u8 expected_key[PKM_LCS_GUID_BYTES], const char *expected_layer,
	u64 expected_sequence)
{
	size_t expected_layer_len = strlen(expected_layer);
	size_t offset = 6;
	u32 record_len;
	u32 layer_len;

	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)6);
	KUNIT_EXPECT_EQ(test, get_unaligned_le16(frame),
			(u16)REG_BACKUP_BLANKET_TOMBSTONE);
	record_len = get_unaligned_le32(frame + 2);
	KUNIT_ASSERT_EQ(test, (size_t)record_len, frame_len);

	KUNIT_ASSERT_LE(test, offset + PKM_LCS_GUID_BYTES, frame_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(frame + offset, expected_key,
			       PKM_LCS_GUID_BYTES),
			0);
	offset += PKM_LCS_GUID_BYTES;

	KUNIT_ASSERT_LE(test, offset + sizeof(u32), frame_len);
	layer_len = get_unaligned_le32(frame + offset);
	offset += sizeof(u32);
	KUNIT_ASSERT_EQ(test, (size_t)layer_len, expected_layer_len);
	KUNIT_ASSERT_LE(test, offset + layer_len, frame_len);
	KUNIT_EXPECT_EQ(test, memcmp(frame + offset, expected_layer, layer_len),
			0);
	offset += layer_len;

	KUNIT_ASSERT_LE(test, offset + sizeof(u64), frame_len);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(frame + offset),
			expected_sequence);
	offset += sizeof(u64);
	KUNIT_EXPECT_EQ(test, offset, frame_len);
}


int pkm_lcs_kunit_backup_snapshot_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_backup_snapshot_source_script *script =
		raw_script;
	static const u8 key_guid[PKM_LCS_GUID_BYTES] = { 0x52 };
	static const u8 child_guid[PKM_LCS_GUID_BYTES] = { 0x53 };
	static const u8 grandchild_guid[PKM_LCS_GUID_BYTES] = { 0x54 };
	const size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 request[128];
	ssize_t count;
	u64 request_id;
	u16 op_code;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	count = pkm_lcs_kunit_backup_snapshot_read_source_request(
		script, request, sizeof(request));
	if (count < 0)
		return (int)count;
	script->reads++;
	if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64) +
			    (ssize_t)sizeof(u32)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	op_code = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (op_code != RSI_BEGIN_TRANSACTION ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0 ||
	    get_unaligned_le32(request + payload_offset + sizeof(u64)) !=
		    RSI_TXN_READ_ONLY) {
		script->result = -EINVAL;
		return script->result;
	}
	script->transaction_id =
		get_unaligned_le64(request + payload_offset);
	if (!script->transaction_id) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_backup_snapshot_write_status(
		script, request_id, op_code, script->begin_status);
	if (ret)
		return ret;
	if (script->begin_status != RSI_OK) {
		script->result = 0;
		return 0;
	}

	if (script->expect_export_reads) {
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_READ_KEY, key_guid, request,
			sizeof(request));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_ENUM_CHILDREN, key_guid, request,
			sizeof(request));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_QUERY_VALUES, key_guid, request,
			sizeof(request));
		if (ret)
			return ret;
	}

	if (script->expect_child_export_reads) {
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_READ_KEY, child_guid, request,
			sizeof(request));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_ENUM_CHILDREN, child_guid, request,
			sizeof(request));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_QUERY_VALUES, child_guid, request,
			sizeof(request));
		if (ret)
			return ret;
	}

	if (script->expect_grandchild_export_reads) {
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_READ_KEY, grandchild_guid, request,
			sizeof(request));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_ENUM_CHILDREN, grandchild_guid, request,
			sizeof(request));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_backup_snapshot_handle_export_read(
			script, RSI_QUERY_VALUES, grandchild_guid, request,
			sizeof(request));
		if (ret)
			return ret;
	}

	count = pkm_lcs_kunit_backup_snapshot_read_source_request(
		script, request, sizeof(request));
	if (count < 0)
		return (int)count;
	script->reads++;
	if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	op_code = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (op_code != RSI_ABORT_TRANSACTION ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->transaction_id ||
	    get_unaligned_le64(request + payload_offset) !=
		    script->transaction_id) {
		script->result = -EINVAL;
		return script->result;
	}
	script->saw_abort = true;

	ret = pkm_lcs_kunit_backup_snapshot_write_status(
		script, request_id, op_code, script->abort_status);
	if (ret)
		return ret;

	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_backup_call_thread(void *raw_script)
{
	struct pkm_lcs_kunit_backup_call_script *script = raw_script;

	if (!script)
		return -EINVAL;
	script->result = pkm_lcs_kunit_key_fd_backup_for_token(
		(int)script->key_fd, script->token, &script->args);
	return (int)script->result;
}


int pkm_lcs_kunit_restore_txn_source_read_request(
	struct pkm_lcs_kunit_restore_txn_source_script *script, u8 *request,
	size_t request_len, ssize_t *count_out)
{
	ssize_t count;

	if (!script || !request || !request_len || !count_out)
		return -EINVAL;
	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	*count_out = count;
	return 0;
}


int pkm_lcs_kunit_restore_txn_source_write_status(
	struct pkm_lcs_kunit_restore_txn_source_script *script,
	u64 request_id, u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t written;

	if (!script)
		return -EINVAL;
	memset(response, 0, sizeof(response));
	put_unaligned_le32(sizeof(response),
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);
	written = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (written != (ssize_t)sizeof(response)) {
		script->result = (int)written;
		return script->result;
	}
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_restore_txn_expect_non_root_create_key(
	struct pkm_lcs_kunit_restore_txn_source_script *script)
{
	struct pkm_lcs_kunit_create_source_script *create =
		&script->replay_non_root_create;
	u8 request[128];
	ssize_t count;
	u64 request_id;
	int ret;

	create->expected_txn_id = script->transaction_id;
	ret = pkm_lcs_kunit_restore_txn_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_create_source_expect_key_request(
		create, request, (size_t)count, &request_id);
	if (ret) {
		script->result = ret;
		return ret;
	}
	return pkm_lcs_kunit_restore_txn_source_write_status(
		script, request_id, RSI_CREATE_KEY, create->key_status);
}


int pkm_lcs_kunit_restore_txn_expect_non_root_write_key(
	struct pkm_lcs_kunit_restore_txn_source_script *script)
{
	const u8 *expected_guid = script->replay_non_root_create.child_guid;
	u64 expected_last_write =
		script->expected_non_root_last_write_time ?
			script->expected_non_root_last_write_time :
			5678ULL;
	u8 request[128];
	ssize_t count;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u64 request_id;
	u16 request_op;
	u32 field_mask;
	int ret;

	if (!expected_guid)
		return -EINVAL;
	ret = pkm_lcs_kunit_restore_txn_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
				     sizeof(u32) + sizeof(u64)) {
		script->result = -EINVAL;
		return script->result;
	}
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->transaction_id ||
	    memcmp(request + offset, expected_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += RSI_GUID_SIZE;
	field_mask = get_unaligned_le32(request + offset);
	if (field_mask != RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += sizeof(u32);
	if (get_unaligned_le64(request + offset) != expected_last_write) {
		script->result = -EINVAL;
		return script->result;
	}
	return pkm_lcs_kunit_restore_txn_source_write_status(
		script, request_id, request_op, RSI_OK);
}


int pkm_lcs_kunit_restore_txn_expect_non_root_create_entry(
	struct pkm_lcs_kunit_restore_txn_source_script *script)
{
	struct pkm_lcs_kunit_create_source_script *create =
		&script->replay_non_root_create;
	u8 request[128];
	ssize_t count;
	u64 request_id;
	int ret;

	create->expected_txn_id = script->transaction_id;
	ret = pkm_lcs_kunit_restore_txn_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_create_source_expect_entry_request(
		create, request, (size_t)count, &request_id);
	if (ret) {
		script->result = ret;
		return ret;
	}
	return pkm_lcs_kunit_restore_txn_source_write_status(
		script, request_id, RSI_CREATE_ENTRY, create->entry_status);
}


int pkm_lcs_kunit_restore_txn_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_restore_txn_source_script *script = raw_script;
	const size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 request[128];
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;
	ssize_t written;
	u64 request_id;
	u16 op_code;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64) +
			    (ssize_t)sizeof(u32)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	op_code = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	script->transaction_id =
		get_unaligned_le64(request + payload_offset);
	if (op_code != RSI_BEGIN_TRANSACTION ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0 ||
	    !script->transaction_id ||
	    get_unaligned_le32(request + payload_offset + sizeof(u64)) !=
		    RSI_TXN_READ_WRITE) {
		script->result = -EINVAL;
		return script->result;
	}

	memset(response, 0, sizeof(response));
	put_unaligned_le32(sizeof(response),
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(op_code | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->begin_status,
			   response + RSI_RESPONSE_STATUS_OFFSET);
	written = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (written != (ssize_t)sizeof(response)) {
		script->result = (int)written;
		return script->result;
	}
	script->writes++;
	if (script->begin_status != RSI_OK) {
		script->result = 0;
		return 0;
	}

	if (script->expect_read_key) {
		int ret;

		script->read_key.file = script->file;
		script->read_key.expected_txn_id = script->transaction_id;
		ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
		script->reads += script->read_key.reads;
		script->writes += script->read_key.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	if (script->expect_root_content_probe) {
		int ret;

		script->enum_children.file = script->file;
		script->enum_children.expected_txn_id =
			script->transaction_id;
		script->enum_children.check_txn_id = true;
		ret = pkm_lcs_kunit_enum_children_source_thread(
			&script->enum_children);
		script->reads += script->enum_children.reads;
		script->writes += script->enum_children.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}

		if (script->expect_root_path_delete) {
			script->delete_entry.file = script->file;
			script->delete_entry.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_path_entry_source_thread(
				&script->delete_entry);
			script->reads += script->delete_entry.reads;
			script->writes += script->delete_entry.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_child_teardown) {
			script->child_enum_children.file = script->file;
			script->child_enum_children.expected_txn_id =
				script->transaction_id;
			script->child_enum_children.check_txn_id = true;
			ret = pkm_lcs_kunit_enum_children_source_thread(
				&script->child_enum_children);
			script->reads += script->child_enum_children.reads;
			script->writes += script->child_enum_children.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
			if (script->expect_child_teardown_abort_after_enum)
				goto expect_terminal;

			if (script->expect_child_path_delete) {
				script->child_delete_entry.file = script->file;
				script->child_delete_entry.expected_txn_id =
					script->transaction_id;
				ret = pkm_lcs_kunit_path_entry_source_thread(
					&script->child_delete_entry);
				script->reads +=
					script->child_delete_entry.reads;
				script->writes +=
					script->child_delete_entry.writes;
				if (ret) {
					script->result = ret;
					return ret;
				}
			}

			if (script->expect_grandchild_teardown) {
				script->grandchild_enum_children.file =
					script->file;
				script->grandchild_enum_children.expected_txn_id =
					script->transaction_id;
				script->grandchild_enum_children.check_txn_id =
					true;
				ret = pkm_lcs_kunit_enum_children_source_thread(
					&script->grandchild_enum_children);
				script->reads +=
					script->grandchild_enum_children.reads;
				script->writes +=
					script->grandchild_enum_children.writes;
				if (ret) {
					script->result = ret;
					return ret;
				}

				script->grandchild_query_values.file =
					script->file;
				script->grandchild_query_values.expected_txn_id =
					script->transaction_id;
				ret = pkm_lcs_kunit_query_values_source_thread(
					&script->grandchild_query_values);
				script->reads +=
					script->grandchild_query_values.reads;
				script->writes +=
					script->grandchild_query_values.writes;
				if (ret) {
					script->result = ret;
					return ret;
				}

				script->grandchild_drop_key.file = script->file;
				script->grandchild_drop_key.expected_txn_id =
					script->transaction_id;
				ret = pkm_lcs_kunit_drop_key_source_thread(
					&script->grandchild_drop_key);
				script->reads +=
					script->grandchild_drop_key.reads;
				script->writes +=
					script->grandchild_drop_key.writes;
				if (ret) {
					script->result = ret;
					return ret;
				}
			}

			script->child_query_values.file = script->file;
			script->child_query_values.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_query_values_source_thread(
				&script->child_query_values);
			script->reads += script->child_query_values.reads;
			script->writes += script->child_query_values.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}

			script->drop_key.file = script->file;
			script->drop_key.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_drop_key_source_thread(
				&script->drop_key);
			script->reads += script->drop_key.reads;
			script->writes += script->drop_key.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		script->query_values.file = script->file;
		script->query_values.expected_txn_id =
			script->transaction_id;
		ret = pkm_lcs_kunit_query_values_source_thread(
			&script->query_values);
		script->reads += script->query_values.reads;
		script->writes += script->query_values.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}

		if (script->expect_root_value_delete) {
			script->delete_value.file = script->file;
			script->delete_value.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_delete_value_source_thread(
				&script->delete_value);
			script->reads += script->delete_value.reads;
			script->writes += script->delete_value.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_root_blanket_delete) {
			script->blanket_tombstone.file = script->file;
			script->blanket_tombstone.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_blanket_tombstone_source_thread(
				&script->blanket_tombstone);
			script->reads += script->blanket_tombstone.reads;
			script->writes += script->blanket_tombstone.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_root_write_key) {
			const u8 *expected_sd = script->expected_root_write_sd ?
				script->expected_root_write_sd :
				pkm_lcs_kunit_owner_only_sd;
			size_t expected_sd_len =
				script->expected_root_write_sd ?
					script->expected_root_write_sd_len :
					sizeof(pkm_lcs_kunit_owner_only_sd);
			u64 expected_last_write =
				script->expected_root_last_write_time ?
					script->expected_root_last_write_time :
					5678ULL;
			size_t write_len = RSI_REQUEST_HEADER_SIZE +
					   RSI_GUID_SIZE + sizeof(u32) +
					   RSI_LENGTH_PREFIX_SIZE +
					   expected_sd_len + sizeof(u64);
			size_t field_mask_offset;
			size_t sd_offset;
			size_t last_write_offset;

			for (;;) {
				count = pkm_lcs_kunit_source_device_read_file(
					script->file, request, sizeof(request),
					true);
				if (count != -EAGAIN)
					break;
				if (kthread_should_stop()) {
					script->result = -EINTR;
					return script->result;
				}
				msleep(1);
			}
			if (count < 0) {
				script->result = (int)count;
				return script->result;
			}
			script->reads++;
			if ((size_t)count != write_len ||
			    get_unaligned_le16(
				    request + RSI_REQUEST_OP_CODE_OFFSET) !=
				    RSI_WRITE_KEY ||
			    get_unaligned_le64(
				    request + RSI_REQUEST_TXN_ID_OFFSET) !=
				    script->transaction_id ||
			    memcmp(request + RSI_REQUEST_HEADER_SIZE,
				   pkm_lcs_kunit_restore_target_guid,
				   RSI_GUID_SIZE)) {
				script->result = -EINVAL;
				return script->result;
			}
			request_id = get_unaligned_le64(
				request + RSI_REQUEST_ID_OFFSET);
			field_mask_offset = RSI_REQUEST_HEADER_SIZE +
					    RSI_GUID_SIZE;
			if (get_unaligned_le32(request + field_mask_offset) !=
			    (u32)(RSI_WRITE_KEY_FIELD_SD |
				  RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)) {
				script->result = -EINVAL;
				return script->result;
			}
			sd_offset = field_mask_offset + sizeof(u32);
			if (get_unaligned_le32(request + sd_offset) !=
				    expected_sd_len ||
			    memcmp(request + sd_offset + RSI_LENGTH_PREFIX_SIZE,
				   expected_sd, expected_sd_len)) {
				script->result = -EINVAL;
				return script->result;
			}
			last_write_offset = sd_offset + RSI_LENGTH_PREFIX_SIZE +
					    expected_sd_len;
			if (get_unaligned_le64(request + last_write_offset) !=
			    expected_last_write) {
				script->result = -EINVAL;
				return script->result;
			}

			memset(response, 0, sizeof(response));
			put_unaligned_le32(
				sizeof(response),
				response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
			put_unaligned_le64(
				request_id, response + RSI_RESPONSE_ID_OFFSET);
			put_unaligned_le16(
				RSI_WRITE_KEY | RSI_RESPONSE_BIT,
				response + RSI_RESPONSE_OP_CODE_OFFSET);
			put_unaligned_le32(
				RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
			written = pkm_lcs_kunit_source_device_write_file(
				script->file, response, sizeof(response),
				false, NULL);
			if (written != (ssize_t)sizeof(response)) {
				script->result = (int)written;
				return script->result;
			}
			script->writes++;
		}

		if (script->expect_replay_root_hidden_path) {
			script->replay_root_hidden_path.file = script->file;
			script->replay_root_hidden_path.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_path_entry_source_thread(
				&script->replay_root_hidden_path);
			script->reads += script->replay_root_hidden_path.reads;
			script->writes += script->replay_root_hidden_path.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_replay_root_value) {
			script->replay_root_value.file = script->file;
			script->replay_root_value.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_set_value_source_thread(
				&script->replay_root_value);
			script->reads += script->replay_root_value.reads;
			script->writes += script->replay_root_value.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_replay_root_blanket) {
			script->replay_root_blanket.file = script->file;
			script->replay_root_blanket.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_blanket_tombstone_source_thread(
				&script->replay_root_blanket);
			script->reads += script->replay_root_blanket.reads;
			script->writes += script->replay_root_blanket.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_replay_non_root_key) {
			ret = pkm_lcs_kunit_restore_txn_expect_non_root_create_key(
				script);
			if (ret) {
				script->result = ret;
				return ret;
			}
			if (script->replay_non_root_create.key_status != RSI_OK)
				goto expect_terminal;

			ret = pkm_lcs_kunit_restore_txn_expect_non_root_write_key(
				script);
			if (ret) {
				script->result = ret;
				return ret;
			}

			if (script->expect_replay_non_root_path) {
				ret = pkm_lcs_kunit_restore_txn_expect_non_root_create_entry(
					script);
				if (ret) {
					script->result = ret;
					return ret;
				}
			}
		}

		if (script->expect_replay_non_root_hidden_path) {
			script->replay_non_root_hidden_path.file = script->file;
			script->replay_non_root_hidden_path.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_path_entry_source_thread(
				&script->replay_non_root_hidden_path);
			script->reads +=
				script->replay_non_root_hidden_path.reads;
			script->writes +=
				script->replay_non_root_hidden_path.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_replay_non_root_value) {
			script->replay_non_root_value.file = script->file;
			script->replay_non_root_value.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_set_value_source_thread(
				&script->replay_non_root_value);
			script->reads += script->replay_non_root_value.reads;
			script->writes += script->replay_non_root_value.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}

		if (script->expect_replay_non_root_blanket) {
			script->replay_non_root_blanket.file = script->file;
			script->replay_non_root_blanket.expected_txn_id =
				script->transaction_id;
			ret = pkm_lcs_kunit_blanket_tombstone_source_thread(
				&script->replay_non_root_blanket);
			script->reads +=
				script->replay_non_root_blanket.reads;
			script->writes +=
				script->replay_non_root_blanket.writes;
			if (ret) {
				script->result = ret;
				return ret;
			}
		}
	}

expect_terminal:
	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	op_code = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (op_code != (script->expect_commit ? RSI_COMMIT_TRANSACTION :
					      RSI_ABORT_TRANSACTION) ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->transaction_id ||
	    get_unaligned_le64(request + payload_offset) !=
		    script->transaction_id) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->expect_commit)
		script->saw_commit = true;
	else
		script->saw_abort = true;
	if (script->expect_commit && script->commit_no_response) {
		script->commit_request_id = request_id;
		script->commit_request_id_present = true;
		script->result = 0;
		return 0;
	}

	memset(response, 0, sizeof(response));
	put_unaligned_le32(sizeof(response),
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(op_code | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->expect_commit ? script->commit_status :
						   script->abort_status,
			   response + RSI_RESPONSE_STATUS_OFFSET);
	written = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (written != (ssize_t)sizeof(response)) {
		script->result = (int)written;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


void pkm_lcs_kunit_key_fd_restore_commit_timeout_late_response(
	struct kunit *test, u32 late_status, bool expect_effects)
{
	static const char * const path[] = { "Machine", "Software" };
	static const u8 ancestors[2][PKM_LCS_GUID_BYTES] = {
		{ 1 },
		{ 0x52 },
	};
	struct pkm_lcs_source_response_result commit_response = { };
	struct pkm_lcs_source_table_snapshot table_snapshot = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct pkm_lcs_runtime_limits limits = { };
	struct reg_restore_args args = { };
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_VALUE,
	};
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = true,
		.commit_no_response = true,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
		},
		.expect_root_content_probe = true,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = true,
	};
	struct pkm_lcs_kunit_restore_input_file input = { };
	struct task_struct *task;
	u8 response[RSI_MIN_RESPONSE_SIZE];
	struct file file = { };
	const void *source_token;
	const void *token;
	size_t response_len;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u8 event[8] = { };
	long key_fd;
	long watch_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_runtime_limits_reset_defaults();
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_defaults(&limits), 0L);
	limits.request_timeout_ms = 1000U;
	KUNIT_ASSERT_EQ(test, pkm_lcs_runtime_limits_publish(&limits), 0L);

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
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
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_restore_stream_build_valid(&input, true),
			0);
	input_fd = pkm_lcs_kunit_restore_input_fd(&input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-commit-late");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token((int)key_fd,
							       token, &args),
			(long)-ETIMEDOUT);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_TRUE(test, script.saw_commit);
	KUNIT_EXPECT_FALSE(test, script.saw_abort);
	KUNIT_ASSERT_TRUE(test, script.commit_request_id_present);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 0U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);
	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    script.commit_request_id,
					    RSI_COMMIT_TRANSACTION, late_status,
					    &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&commit_response),
			(ssize_t)response_len);
	KUNIT_EXPECT_FALSE(test, commit_response.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, commit_response.request_id,
			script.commit_request_id);
	KUNIT_EXPECT_EQ(test, commit_response.txn_id, script.transaction_id);
	KUNIT_EXPECT_EQ(test, commit_response.status, late_status);
	KUNIT_EXPECT_EQ(test, commit_response.in_flight_count, 0U);

	pkm_lcs_kunit_source_table_snapshot(&table_snapshot);
	KUNIT_EXPECT_EQ(test, table_snapshot.active_count, 1U);
	KUNIT_EXPECT_EQ(test, table_snapshot.down_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, ancestors[0], &generation_after),
			0L);
	if (expect_effects) {
		KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_key_fd_read(
					(int)watch_fd, event, sizeof(event),
					true),
				(ssize_t)8);
		KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 8U);
		KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
				REG_WATCH_OVERFLOW);
		KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 0U);
	} else {
		KUNIT_EXPECT_EQ(test, generation_after, generation_before);
	}
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	pkm_lcs_runtime_limits_reset_defaults();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


void pkm_lcs_kunit_expect_restore_stream_result(
	struct kunit *test, struct pkm_lcs_kunit_restore_input_file *input,
	long expected_ret)
{
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct reg_restore_args args = { };
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	input_fd = pkm_lcs_kunit_restore_input_fd(input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-stream");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			expected_ret);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, 2U);
	KUNIT_EXPECT_EQ(test, script.writes, 2U);
	KUNIT_EXPECT_TRUE(test, script.saw_abort);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used &
				      KACS_SE_RESTORE_PRIVILEGE,
			KACS_SE_RESTORE_PRIVILEGE);
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_RESTORE_COMPLETE", "result_errno");

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


void
pkm_lcs_kunit_expect_restore_root_flag_result_with_sequence(
	struct kunit *test, struct pkm_lcs_kunit_restore_input_file *input,
	long expected_ret, bool target_volatile, bool target_symlink,
	bool override_sequence, u64 next_sequence_override,
	bool expect_root_hidden_replay, u64 *sequence_after_out)
{
	struct reg_restore_args args = { };
	bool expect_success = expected_ret == 0;
	struct pkm_lcs_kunit_restore_txn_source_script script = {
		.begin_status = RSI_OK,
		.abort_status = RSI_OK,
		.expect_commit = expect_success,
		.expect_read_key = true,
		.read_key = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.name = "Software",
			.volatile_key = target_volatile,
			.symlink = target_symlink,
		},
		.expect_root_content_probe = expect_success,
		.enum_children = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.empty = true,
		},
		.query_values = {
			.expected_guid = pkm_lcs_kunit_restore_target_guid,
			.expected_value_name = "",
			.query_all = true,
			.empty = true,
		},
		.expect_root_write_key = expect_success,
		.expect_replay_root_hidden_path = expect_root_hidden_replay,
		.replay_root_hidden_path = {
			.expected_parent_guid =
				pkm_lcs_kunit_restore_target_guid,
			.expected_child_name = "Child",
			.expected_layer_name = "base",
			.expected_sequence = next_sequence_override + 1,
			.expected_op_code = RSI_HIDE_ENTRY,
			.status = RSI_OK,
		},
	};
	struct task_struct *task;
	struct file file = { };
	const void *token;
	const void *source_token;
	long key_fd;
	int input_fd;
	int thread_ret;
	u32 expected_io = expect_success ? 6U : 3U;

	if (expect_root_hidden_replay)
		expected_io++;

	pkm_lcs_kunit_setup_registered_source(test, &file, &source_token);
	if (override_sequence)
		pkm_lcs_kunit_set_sequence_state(true, next_sequence_override);
	token = kacs_rust_kunit_create_logon_type_token(
		KACS_LOGON_TYPE_SERVICE, KACS_SE_RESTORE_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	key_fd = pkm_lcs_kunit_publish_source_one_backup_key_fd();
	KUNIT_ASSERT_TRUE(test, key_fd >= 0);
	input_fd = pkm_lcs_kunit_restore_input_fd(input);
	KUNIT_ASSERT_TRUE(test, input_fd >= 0);
	args.input_fd = input_fd;

	script.file = &file;
	pkm_kmes_kunit_reset_all();
	task = pkm_lcs_kunit_kthread_run(
		pkm_lcs_kunit_restore_txn_source_thread, &script,
		"pkm-lcs-kunit-restore-root-flags");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_restore_for_token(
				(int)key_fd, token, &args),
			expected_ret);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script.result, 0);
	KUNIT_EXPECT_EQ(test, script.reads, expected_io);
	KUNIT_EXPECT_EQ(test, script.writes, expected_io);
	KUNIT_EXPECT_EQ(test, script.saw_commit, expect_success);
	KUNIT_EXPECT_EQ(test, script.saw_abort, !expect_success);
	pkm_lcs_kunit_expect_latest_lcs_event(
		test, "LCS_RESTORE_COMPLETE", "result_errno");
	if (sequence_after_out)
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_source_next_sequence_snapshot(
					sequence_after_out),
				0L);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)input_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)key_fd), 0);
	pkm_lcs_kunit_flush_deferred_key_fd_release();
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
	kacs_rust_token_drop(source_token);
}


void
pkm_lcs_kunit_expect_restore_root_flag_result(
	struct kunit *test, struct pkm_lcs_kunit_restore_input_file *input,
	long expected_ret, bool target_volatile, bool target_symlink)
{
	pkm_lcs_kunit_expect_restore_root_flag_result_with_sequence(
		test, input, expected_ret, target_volatile, target_symlink,
		false, 0, false, NULL);
}


long pkm_lcs_kunit_restore_precedence_publish_layers_root(
	struct kunit *test, const char * const *path,
	u8 ancestors[4][PKM_LCS_GUID_BYTES])
{
	if (!test || !path || !ancestors)
		return -EINVAL;
	memset(ancestors, 0, sizeof(u8[4][PKM_LCS_GUID_BYTES]));
	ancestors[0][0] = 1;
	ancestors[1][0] = 0x64;
	ancestors[2][0] = 0x65;
	memcpy(ancestors[3], pkm_lcs_kunit_restore_target_guid,
	       PKM_LCS_GUID_BYTES);
	return pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE, path, ancestors, 4);
}


u32 pkm_lcs_kunit_write_direct_watch_event(u8 *dst, size_t dst_len,
						  u32 event_type,
						  const char *name)
{
	size_t name_len = name ? strlen(name) : 0;
	u32 total_len;

	if (!dst || dst_len < 8 || name_len > U16_MAX ||
	    name_len + 8 > dst_len)
		return 0;

	total_len = (u32)(8 + name_len);
	put_unaligned_le32(total_len, dst);
	put_unaligned_le16((u16)event_type, dst + 4);
	put_unaligned_le16((u16)name_len, dst + 6);
	if (name_len)
		memcpy(dst + 8, name, name_len);
	return total_len;
}


void pkm_lcs_kunit_expect_drop_key_request(
	struct kunit *test, struct file *file,
	const u8 guid[PKM_LCS_GUID_BYTES])
{
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 request[128];
	ssize_t count;

	memset(request, 0, sizeof(request));
	count = pkm_lcs_kunit_source_device_read_file(file, request,
						      sizeof(request), true);
	KUNIT_ASSERT_EQ(test, count,
			(ssize_t)(RSI_REQUEST_HEADER_SIZE +
				  PKM_LCS_GUID_BYTES));
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le32(request +
					   RSI_REQUEST_TOTAL_LEN_OFFSET),
			(u32)count);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_DROP_KEY);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET),
			0ULL);
	KUNIT_EXPECT_EQ(test,
			memcmp(request + payload_offset, guid,
			       PKM_LCS_GUID_BYTES),
			0);
}


void pkm_lcs_kunit_create_missing_parent_resolution_set_sd(
	struct kunit *test, struct pkm_lcs_create_missing_parent_resolution *result,
	const u8 *sd, size_t sd_len)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x61 };
	u8 *frame;

	KUNIT_ASSERT_NOT_NULL(test, result);
	KUNIT_ASSERT_NOT_NULL(test, sd);
	KUNIT_ASSERT_GT(test, sd_len, (size_t)0);

	frame = kmalloc(sd_len + 3U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, frame);
	memset(frame, 0xa5, 3U);
	memcpy(frame + 3U, sd, sd_len);

	memcpy(result->parent.key_guid, parent_guid,
	       sizeof(result->parent.key_guid));
	result->parent.source_id = 1;
	result->parent.component_count = 2;
	result->parent.final_frame.data = frame;
	result->parent.final_frame.len = sd_len + 3U;
	result->parent.final_sd_offset = 3U;
	result->parent.final_sd_len = sd_len;
}


void pkm_lcs_kunit_guid_sequence_generate(void *raw_ctx, u8 guid[16])
{
	struct pkm_lcs_kunit_guid_sequence *ctx = raw_ctx;
	u32 index;

	if (!ctx || !ctx->guids || !ctx->count) {
		memset(guid, 0, 16);
		return;
	}

	index = ctx->calls < ctx->count ? ctx->calls : ctx->count - 1;
	memcpy(guid, ctx->guids[index], 16);
	ctx->calls++;
}


struct pkm_lcs_key_guid_generator
pkm_lcs_kunit_guid_generator(struct pkm_lcs_kunit_guid_sequence *sequence)
{
	return (struct pkm_lcs_key_guid_generator) {
		.generate = pkm_lcs_kunit_guid_sequence_generate,
		.ctx = sequence,
	};
}


void pkm_lcs_kunit_setup_registered_source(struct kunit *test,
						  struct file *file,
						  const void **token_out)
{
	const char name_src[] = "Machine";
	struct pkm_lcs_kunit_usercopy_ctx ctx = { };
	struct pkm_lcs_usercopy_ops ops = pkm_lcs_kunit_usercopy_ops(&ctx);
	struct reg_src_hive_entry hive;
	struct reg_src_register_args args;
	const void *token;

	KUNIT_ASSERT_NOT_NULL(test, token_out);
	*token_out = NULL;
	pkm_lcs_kunit_reset_source_table();
	token = kacs_rust_kunit_create_logon_type_token(KACS_LOGON_TYPE_SERVICE,
							KACS_SE_TCB_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	*token_out = token;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_device_open_file_for_token(token, file),
			0L);
	pkm_lcs_kunit_build_register_args(&args, &hive, name_src, 1, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_register_file_for_token(
				token, file, &ops, (const void __user *)&args),
			0L);
}


struct task_struct *pkm_lcs_kunit_kthread_run(int (*threadfn)(void *),
						     void *data,
						     const char *name)
{
	struct task_struct *task;

	task = kthread_create(threadfn, data, "%s", name);
	if (IS_ERR(task))
		return task;

	/*
	 * Several source scripts are one-shot responders. Hold a task
	 * reference before wake so kthread_stop_put() remains valid even if
	 * the worker serves the response and exits before the test stops it.
	 */
	get_task_struct(task);
	wake_up_process(task);
	return task;
}


int pkm_lcs_kunit_kthread_stop(struct task_struct *task)
{
	return kthread_stop_put(task);
}


void pkm_lcs_kunit_build_lookup_frame(struct kunit *test, u8 *frame,
					     size_t frame_len, u64 request_id,
					     const char *child_name,
					     size_t *built_len)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x51 };
	struct pkm_lcs_rsi_built_request built = { };

	KUNIT_ASSERT_NOT_NULL(test, built_len);
	*built_len = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_rsi_build_lookup_request(
				frame, frame_len, request_id, 0, parent_guid,
				child_name, strlen(child_name), NULL, &built),
			0L);
	*built_len = built.len;
}


void pkm_lcs_kunit_build_status_response(struct kunit *test, u8 *frame,
						size_t frame_len,
						u64 request_id, u16 request_op,
						u32 status, size_t *built_len)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, built_len);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)RSI_MIN_RESPONSE_SIZE);

	memset(frame, 0, frame_len);
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, frame + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   frame + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, frame + RSI_RESPONSE_STATUS_OFFSET);
	*built_len = RSI_MIN_RESPONSE_SIZE;
}


int pkm_lcs_kunit_create_source_read_request(
	struct pkm_lcs_kunit_create_source_script *script, u8 *request,
	size_t request_len, ssize_t *count)
{
	for (;;) {
		*count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (*count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (*count < 0) {
		script->result = (int)*count;
		return script->result;
	}
	script->reads++;
	return 0;
}


int pkm_lcs_kunit_create_source_expect_bytes(
	const u8 *request, size_t request_len, size_t *offset,
	const void *expected, size_t expected_len)
{
	if (!request || !offset || !expected)
		return -EINVAL;
	if (*offset > request_len || expected_len > request_len - *offset)
		return -EINVAL;
	if (memcmp(request + *offset, expected, expected_len))
		return -EINVAL;
	*offset += expected_len;
	return 0;
}


int pkm_lcs_kunit_create_source_expect_string(
	const u8 *request, size_t request_len, size_t *offset,
	const char *expected)
{
	u32 actual_len;
	u32 expected_len;

	if (!request || !offset || !expected)
		return -EINVAL;
	if (*offset > request_len ||
	    sizeof(actual_len) > request_len - *offset)
		return -EINVAL;
	actual_len = get_unaligned_le32(request + *offset);
	*offset += sizeof(actual_len);

	expected_len = (u32)strlen(expected);
	if (actual_len != expected_len)
		return -EINVAL;
	return pkm_lcs_kunit_create_source_expect_bytes(
		request, request_len, offset, expected, expected_len);
}


int pkm_lcs_kunit_flush_source_thread(void *data)
{
	struct pkm_lcs_kunit_flush_source_script *script = data;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[128];
	size_t response_len = RSI_MIN_RESPONSE_SIZE;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;

	if (!script || !script->file || !script->expected_hive_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;

	if (count < RSI_REQUEST_HEADER_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_FLUSH) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0) {
		script->result = -EINVAL;
		return script->result;
	}
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, (size_t)count, &offset,
		    script->expected_hive_name)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->reset_runtime_limits_before_response)
		pkm_lcs_runtime_limits_reset_defaults();

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_FLUSH_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload) {
		put_unaligned_le32(0xfeedf00d,
				   response + RSI_MIN_RESPONSE_SIZE);
		response_len += sizeof(u32);
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	}

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = (int)count;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_drop_key_source_thread(void *data)
{
	struct pkm_lcs_kunit_drop_key_source_script *script = data;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[128];
	size_t response_len = RSI_MIN_RESPONSE_SIZE;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;

	if (!script || !script->file || !script->expected_guid) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;

	if (count < RSI_REQUEST_HEADER_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_DROP_KEY) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, (size_t)count, &offset, script->expected_guid,
		    RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->reset_runtime_limits_before_response)
		pkm_lcs_runtime_limits_reset_defaults();

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_DROP_KEY_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload) {
		put_unaligned_le32(0x0ddba11,
				   response + RSI_MIN_RESPONSE_SIZE);
		response_len += sizeof(u32);
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	}

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = (int)count;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_delete_layer_source_thread(void *data)
{
	struct pkm_lcs_kunit_delete_layer_source_script *script = data;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32) +
		    2U * RSI_GUID_SIZE + sizeof(u32)];
	u8 request[128];
	size_t response_len = RSI_MIN_RESPONSE_SIZE;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;

	if (!script || !script->file || !script->expected_layer_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}
	if (script->orphaned_guid_count > 2U) {
		script->result = -EINVAL;
		return -EINVAL;
	}
	if (script->status == RSI_OK &&
	    ((script->orphaned_guid_count >= 1U &&
	      !script->orphaned_guid_a) ||
	     (script->orphaned_guid_count >= 2U &&
	      !script->orphaned_guid_b))) {
		script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expected_abort_txn_id) {
		for (;;) {
			count = pkm_lcs_kunit_source_device_read_file(
				script->file, request, sizeof(request), true);
			if (count != -EAGAIN)
				break;
			if (kthread_should_stop()) {
				script->result = -EINTR;
				return script->result;
			}
			msleep(1);
		}
		if (count < 0) {
			script->result = (int)count;
			return script->result;
		}
		script->reads++;

		if (count != RSI_REQUEST_HEADER_SIZE + sizeof(u64)) {
			script->result = -EINVAL;
			return script->result;
		}
		if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
		    RSI_ABORT_TRANSACTION) {
			script->result = -EINVAL;
			return script->result;
		}
		if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_abort_txn_id ||
		    get_unaligned_le64(request + RSI_REQUEST_HEADER_SIZE) !=
			    script->expected_abort_txn_id) {
			script->result = -EINVAL;
			return script->result;
		}

		request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
		memset(response, 0, sizeof(response));
		put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
		put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
		put_unaligned_le16(RSI_ABORT_TRANSACTION_RESPONSE,
				   response + RSI_RESPONSE_OP_CODE_OFFSET);
		put_unaligned_le32(RSI_OK,
				   response + RSI_RESPONSE_STATUS_OFFSET);

		count = pkm_lcs_kunit_source_device_write_file(
			script->file, response, RSI_MIN_RESPONSE_SIZE, false,
			NULL);
		if (count != (ssize_t)RSI_MIN_RESPONSE_SIZE) {
			script->result = (int)count;
			return script->result;
		}
		script->writes++;
		script->abort_before_delete_observed = true;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;

	if (count < RSI_REQUEST_HEADER_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_DELETE_LAYER) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0) {
		script->result = -EINVAL;
		return script->result;
	}
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, (size_t)count, &offset,
		    script->expected_layer_name)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->reset_runtime_limits_before_response)
		pkm_lcs_runtime_limits_reset_defaults();

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_DELETE_LAYER_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->status == RSI_OK) {
		put_unaligned_le32(script->orphaned_guid_count,
				   response + response_len);
		response_len += sizeof(u32);
		if (script->orphaned_guid_count >= 1U) {
			memcpy(response + response_len, script->orphaned_guid_a,
			       RSI_GUID_SIZE);
			response_len += RSI_GUID_SIZE;
		}
		if (script->orphaned_guid_count >= 2U) {
			memcpy(response + response_len, script->orphaned_guid_b,
			       RSI_GUID_SIZE);
			response_len += RSI_GUID_SIZE;
		}
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	}
	if (script->extra_response_payload) {
		put_unaligned_le32(0xde1e7e11, response + response_len);
		response_len += sizeof(u32);
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	}

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = (int)count;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_path_entry_source_thread(void *data)
{
	struct pkm_lcs_kunit_path_entry_source_script *script = data;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[1024];
	size_t response_len = RSI_MIN_RESPONSE_SIZE;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 response_op;

	if (!script || !script->file || !script->expected_parent_guid ||
	    !script->expected_child_name || !script->expected_layer_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}
	if (script->expected_op_code != RSI_HIDE_ENTRY &&
	    script->expected_op_code != RSI_DELETE_ENTRY) {
		script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;

	if (count < RSI_REQUEST_HEADER_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    script->expected_op_code) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, (size_t)count, &offset,
		    script->expected_parent_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, (size_t)count, &offset,
		    script->expected_child_name)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, (size_t)count, &offset,
		    script->expected_layer_name)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->expected_op_code == RSI_HIDE_ENTRY) {
		if (offset > (size_t)count ||
		    sizeof(u64) > (size_t)count - offset) {
			script->result = -EINVAL;
			return script->result;
		}
		if (get_unaligned_le64(request + offset) !=
		    script->expected_sequence) {
			script->result = -EINVAL;
			return script->result;
		}
		offset += sizeof(u64);
	}
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}

	memset(response, 0, sizeof(response));
	response_op = script->expected_op_code | RSI_RESPONSE_BIT;
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload) {
		put_unaligned_le32(0x705e1a5e,
				   response + RSI_MIN_RESPONSE_SIZE);
		response_len += sizeof(u32);
		put_unaligned_le32(response_len,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	}

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_hide_key_ioctl_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_hide_key_ioctl_source_script *script = raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret)
			goto out;
	}

	script->hide.file = script->file;
	ret = pkm_lcs_kunit_path_entry_source_thread(&script->hide);
	script->reads += script->hide.reads;
	script->writes += script->hide.writes;
	if (ret)
		goto out;

	if (script->expect_post_lookup) {
		script->post_lookup.file = script->file;
		ret = pkm_lcs_kunit_walk_source_thread(&script->post_lookup);
		script->reads += script->post_lookup.reads;
		script->writes += script->post_lookup.writes;
	}

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


int pkm_lcs_kunit_create_source_expect_entry_request(
	struct pkm_lcs_kunit_create_source_script *script, const u8 *request,
	size_t request_len, u64 *request_id)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;

	if (!script || !request || !request_id ||
	    request_len < RSI_REQUEST_HEADER_SIZE)
		return -EINVAL;
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_CREATE_ENTRY)
		return -EINVAL;
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_txn_id)
		return -EINVAL;

	*request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, script->parent_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, request_len, &offset, script->child_name))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, request_len, &offset, script->layer_name))
		return -EINVAL;
	if (script->allow_any_child_guid) {
		if (offset > request_len || RSI_GUID_SIZE > request_len - offset)
			return -EINVAL;
		memcpy(script->captured_child_guid, request + offset,
		       RSI_GUID_SIZE);
		offset += RSI_GUID_SIZE;
	} else {
		if (pkm_lcs_kunit_create_source_expect_bytes(
			    request, request_len, &offset, script->child_guid,
			    RSI_GUID_SIZE))
			return -EINVAL;
	}
	if (offset > request_len || sizeof(u64) > request_len - offset)
		return -EINVAL;
	if (get_unaligned_le64(request + offset) != script->expected_sequence)
		return -EINVAL;
	offset += sizeof(u64);
	return offset == request_len ? 0 : -EINVAL;
}


int pkm_lcs_kunit_create_source_expect_key_request(
	struct pkm_lcs_kunit_create_source_script *script, const u8 *request,
	size_t request_len, u64 *request_id)
{
	const u8 *expected_child_guid;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u32 sd_len;

	if (!script || !request || !request_id ||
	    request_len < RSI_REQUEST_HEADER_SIZE)
		return -EINVAL;
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    RSI_CREATE_KEY)
		return -EINVAL;
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_txn_id)
		return -EINVAL;

	*request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	expected_child_guid = script->allow_any_child_guid ?
				      script->captured_child_guid :
				      script->child_guid;
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, expected_child_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_string(
		    request, request_len, &offset, script->child_name))
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, request_len, &offset, script->parent_guid,
		    RSI_GUID_SIZE))
		return -EINVAL;
	if (offset > request_len || sizeof(sd_len) > request_len - offset)
		return -EINVAL;
	sd_len = get_unaligned_le32(request + offset);
	offset += sizeof(sd_len);
	if (script->allow_any_sd) {
		if (!sd_len || sd_len > request_len - offset)
			return -EINVAL;
		offset += sd_len;
	} else {
		if (sd_len != script->sd_len)
			return -EINVAL;
		if (pkm_lcs_kunit_create_source_expect_bytes(
			    request, request_len, &offset, script->sd,
			    script->sd_len))
			return -EINVAL;
	}
	if (offset > request_len || 2U > request_len - offset)
		return -EINVAL;
	if (request[offset] != (script->volatile_key ? 1U : 0U) ||
	    request[offset + 1U] != (script->symlink ? 1U : 0U))
		return -EINVAL;
	offset += 2U;
	return offset == request_len ? 0 : -EINVAL;
}


int pkm_lcs_kunit_create_source_write_status(
	struct pkm_lcs_kunit_create_source_script *script, u64 request_id,
	u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response)) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_create_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_create_source_script *script = raw_script;
	u8 request[1024];
	ssize_t count = 0;
	u64 request_id = 0;
	int ret;

	if (!script || !script->file || !script->parent_guid ||
	    (!script->child_guid && !script->allow_any_child_guid) ||
	    !script->child_name ||
	    !script->layer_name || (!script->sd && !script->allow_any_sd)) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_create_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_create_source_expect_entry_request(
		script, request, count, &request_id);
	if (ret) {
		script->result = ret;
		return ret;
	}
	ret = pkm_lcs_kunit_create_source_write_status(
		script, request_id, RSI_CREATE_ENTRY, script->entry_status);
	if (ret || !script->expect_key_request) {
		if (!ret)
			script->result = 0;
		return ret;
	}

	ret = pkm_lcs_kunit_create_source_read_request(
		script, request, sizeof(request), &count);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_create_source_expect_key_request(
		script, request, count, &request_id);
	if (ret) {
		script->result = ret;
		return ret;
	}
	ret = pkm_lcs_kunit_create_source_write_status(
		script, request_id, RSI_CREATE_KEY, script->key_status);
	if (ret)
		return ret;

	script->result = 0;
	return 0;
}


void pkm_lcs_kunit_rsi_append_bytes(struct kunit *test, u8 *frame,
					   size_t frame_len, size_t *offset,
					   const void *bytes, size_t len)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_TRUE(test, len == 0 || bytes);
	KUNIT_ASSERT_LE(test, len, frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - len);

	memcpy(frame + *offset, bytes, len);
	*offset += len;
}


void pkm_lcs_kunit_rsi_append_u8(struct kunit *test, u8 *frame,
					size_t frame_len, size_t *offset,
					u8 value)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_LE(test, (size_t)1, frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - 1U);

	frame[*offset] = value;
	*offset += 1U;
}


void pkm_lcs_kunit_rsi_append_u32(struct kunit *test, u8 *frame,
					 size_t frame_len, size_t *offset,
					 u32 value)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_LE(test, (size_t)sizeof(value), frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - sizeof(value));

	put_unaligned_le32(value, frame + *offset);
	*offset += sizeof(value);
}


void pkm_lcs_kunit_rsi_append_u64(struct kunit *test, u8 *frame,
					 size_t frame_len, size_t *offset,
					 u64 value)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_LE(test, (size_t)sizeof(value), frame_len);
	KUNIT_ASSERT_LE(test, *offset, frame_len - sizeof(value));

	put_unaligned_le64(value, frame + *offset);
	*offset += sizeof(value);
}


void pkm_lcs_kunit_rsi_append_len_prefixed(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const void *bytes, size_t len)
{
	KUNIT_ASSERT_LE(test, len, (size_t)U32_MAX);

	pkm_lcs_kunit_rsi_append_u32(test, frame, frame_len, offset,
				     (u32)len);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset,
				       bytes, len);
}


void pkm_lcs_kunit_rsi_response_begin(struct kunit *test, u8 *frame,
					     size_t frame_len, u64 request_id,
					     u16 response_op, u32 status,
					     size_t *offset)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, offset);
	KUNIT_ASSERT_GE(test, frame_len, (size_t)RSI_MIN_RESPONSE_SIZE);

	memset(frame, 0, frame_len);
	put_unaligned_le64(request_id, frame + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, frame + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, frame + RSI_RESPONSE_STATUS_OFFSET);
	*offset = RSI_MIN_RESPONSE_SIZE;
}


void pkm_lcs_kunit_rsi_finish_response(struct kunit *test, u8 *frame,
					      size_t offset,
					      size_t *built_len)
{
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, built_len);
	KUNIT_ASSERT_LE(test, offset, (size_t)U32_MAX);

	put_unaligned_le32((u32)offset, frame + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
}


void pkm_lcs_kunit_rsi_append_lookup_path_entry(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const char *layer_name, u8 target_type, const u8 guid[RSI_GUID_SIZE],
	u64 sequence)
{
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, layer_name,
		strlen(layer_name));
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset,
				    target_type);
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset, guid,
				       RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     sequence);
}


void pkm_lcs_kunit_rsi_append_lookup_metadata(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const u8 guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len)
{
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset, guid,
				       RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, frame, frame_len,
					      offset, sd, sd_len);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset, 0);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset, 0);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset, 1000);
}


void pkm_lcs_kunit_rsi_append_lookup_metadata_ex(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const u8 guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	u8 volatile_key, u8 symlink, u64 last_write_time)
{
	pkm_lcs_kunit_rsi_append_bytes(test, frame, frame_len, offset, guid,
				       RSI_GUID_SIZE);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, frame, frame_len,
					      offset, sd, sd_len);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset,
				    volatile_key);
	pkm_lcs_kunit_rsi_append_u8(test, frame, frame_len, offset, symlink);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     last_write_time);
}


void pkm_lcs_kunit_rsi_append_query_value_entry(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const char *value_name, const char *layer_name, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence)
{
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, value_name,
		strlen(value_name));
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, layer_name,
		strlen(layer_name));
	pkm_lcs_kunit_rsi_append_u32(test, frame, frame_len, offset,
				     value_type);
	pkm_lcs_kunit_rsi_append_len_prefixed(test, frame, frame_len,
					      offset, data, data_len);
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     sequence);
}


void pkm_lcs_kunit_rsi_append_query_blanket(
	struct kunit *test, u8 *frame, size_t frame_len, size_t *offset,
	const char *layer_name, u64 sequence)
{
	pkm_lcs_kunit_rsi_append_len_prefixed(
		test, frame, frame_len, offset, layer_name,
		strlen(layer_name));
	pkm_lcs_kunit_rsi_append_u64(test, frame, frame_len, offset,
				     sequence);
}


int pkm_lcs_kunit_walk_source_append(void *dst, size_t dst_len,
					    size_t *offset, const void *src,
					    size_t src_len)
{
	if (!dst || !offset || (!src && src_len))
		return -EINVAL;
	if (*offset > dst_len || src_len > dst_len - *offset)
		return -EMSGSIZE;

	memcpy((u8 *)dst + *offset, src, src_len);
	*offset += src_len;
	return 0;
}


int pkm_lcs_kunit_walk_source_append_u8(u8 *dst, size_t dst_len,
					       size_t *offset, u8 value)
{
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, &value,
						sizeof(value));
}


int pkm_lcs_kunit_walk_source_append_u32(u8 *dst, size_t dst_len,
						size_t *offset, u32 value)
{
	u8 encoded[sizeof(value)];

	put_unaligned_le32(value, encoded);
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, encoded,
						sizeof(encoded));
}


int pkm_lcs_kunit_walk_source_append_u64(u8 *dst, size_t dst_len,
						size_t *offset, u64 value)
{
	u8 encoded[sizeof(value)];

	put_unaligned_le64(value, encoded);
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, encoded,
						sizeof(encoded));
}


int pkm_lcs_kunit_walk_source_append_len_prefixed(
	u8 *dst, size_t dst_len, size_t *offset, const void *src,
	size_t src_len)
{
	int ret;

	if (src_len > U32_MAX)
		return -EOVERFLOW;
	ret = pkm_lcs_kunit_walk_source_append_u32(dst, dst_len, offset,
						   (u32)src_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_walk_source_append(dst, dst_len, offset, src,
						src_len);
}


int pkm_lcs_kunit_walk_source_build_response(
	const struct pkm_lcs_kunit_walk_source_step *step, u64 request_id,
	u16 request_op, u32 index, u8 *response, size_t response_len,
	size_t *built_len)
{
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = request_op | RSI_RESPONSE_BIT;
	u32 path_count;
	u32 metadata_count;
	int ret;

	if (!step || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	path_count = step->empty ? 0U : 1U;
	if (!step->empty && step->include_second_entry)
		path_count = 2U;
	metadata_count = 0U;
	if (!step->empty) {
		if (!step->hidden)
			metadata_count++;
		if (step->include_second_entry && !step->second_hidden)
			metadata_count++;
	}
	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						   &offset, path_count);
	if (ret)
		return ret;
	if (!step->empty) {
		const char *layer_name = step->layer_name ?
					 step->layer_name : "base";
		const u8 *target_guid = step->hidden ? hidden_guid :
						       step->guid;
		u8 target_type = step->hidden ? RSI_PATH_TARGET_HIDDEN :
						RSI_PATH_TARGET_GUID;

		if (!target_guid)
			return -EINVAL;

		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, layer_name,
			strlen(layer_name));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(
			response, response_len, &offset, target_type);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append(
			response, response_len, &offset, target_guid,
			RSI_GUID_SIZE);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset, step->sequence);
		if (ret)
			return ret;
		if (step->include_second_entry) {
			const char *second_layer = step->second_layer_name ?
						  step->second_layer_name :
						  "policy";
			const u8 *second_target_guid = step->second_hidden ?
						       hidden_guid :
						       step->second_guid;
			u8 second_target_type = step->second_hidden ?
						 RSI_PATH_TARGET_HIDDEN :
						 RSI_PATH_TARGET_GUID;

			if (!second_target_guid)
				return -EINVAL;
			ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
				response, response_len, &offset, second_layer,
				strlen(second_layer));
			if (ret)
				return ret;
			ret = pkm_lcs_kunit_walk_source_append_u8(
				response, response_len, &offset,
				second_target_type);
			if (ret)
				return ret;
			ret = pkm_lcs_kunit_walk_source_append(
				response, response_len, &offset,
				second_target_guid, RSI_GUID_SIZE);
			if (ret)
				return ret;
			ret = pkm_lcs_kunit_walk_source_append_u64(
				response, response_len, &offset,
				step->second_sequence);
			if (ret)
				return ret;
		}
	}

	ret = pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						   &offset, metadata_count);
	if (ret)
		return ret;
	if (!step->empty && !step->hidden) {
		const u8 *sd = step->sd ? step->sd :
					 pkm_lcs_kunit_owner_only_sd;
		size_t sd_len = step->sd ? step->sd_len :
					    sizeof(pkm_lcs_kunit_owner_only_sd);

		ret = pkm_lcs_kunit_walk_source_append(
			response, response_len, &offset, step->guid,
			RSI_GUID_SIZE);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, sd, sd_len);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(response,
							  response_len,
							  &offset, 0);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(
			response, response_len, &offset, step->symlink ? 1 : 0);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset, 1000ULL + index);
		if (ret)
			return ret;
	}
	if (!step->empty && step->include_second_entry &&
	    !step->second_hidden) {
		const u8 *second_sd = step->second_sd ?
					      step->second_sd :
					      pkm_lcs_kunit_owner_only_sd;
		size_t second_sd_len = step->second_sd ?
					       step->second_sd_len :
					       sizeof(pkm_lcs_kunit_owner_only_sd);

		if (!step->second_guid)
			return -EINVAL;
		ret = pkm_lcs_kunit_walk_source_append(
			response, response_len, &offset, step->second_guid,
			RSI_GUID_SIZE);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, second_sd,
			second_sd_len);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(
			response, response_len, &offset, 0);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u8(
			response, response_len, &offset,
			step->second_symlink ? 1 : 0);
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset, 2000ULL + index);
		if (ret)
			return ret;
	}

	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}


int pkm_lcs_kunit_walk_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_walk_source_script *script = raw_script;
	u8 request[512];
	u8 response[512];
	u32 i;

	if (!script || !script->file || !script->steps) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (i = 0; i < script->step_count; i++) {
		const struct pkm_lcs_kunit_walk_source_step *step =
			&script->steps[i];
		size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
		u64 request_id;
		u16 request_op;
		u32 child_len;
		size_t response_len = 0;
		ssize_t count;
		int ret;

		for (;;) {
			count = pkm_lcs_kunit_source_device_read_file(
				script->file, request, sizeof(request), true);
			if (count != -EAGAIN)
				break;
			if (kthread_should_stop()) {
				script->result = -EINTR;
				return script->result;
			}
			msleep(1);
		}
		if (count < 0) {
			script->result = (int)count;
			return script->result;
		}
		script->reads++;
		if ((size_t)count < child_offset + sizeof(u32)) {
			script->result = -EINVAL;
			return script->result;
		}

		request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
		request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
		if (request_op != RSI_LOOKUP) {
			script->result = -EINVAL;
			return script->result;
		}
		if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id) {
			script->result = -EINVAL;
			return script->result;
		}
		child_len = get_unaligned_le32(request + child_offset);
		child_offset += sizeof(u32);
		if (child_offset > (size_t)count ||
		    child_len > (size_t)count - child_offset ||
		    child_len != strlen(step->expected_child) ||
		    memcmp(request + child_offset, step->expected_child,
			   child_len)) {
			script->result = -EINVAL;
			return script->result;
		}

		ret = pkm_lcs_kunit_walk_source_build_response(
			step, request_id, request_op, i, response,
			sizeof(response), &response_len);
		if (ret) {
			script->result = ret;
			return script->result;
		}
		if (script->reset_runtime_limits_before_response)
			pkm_lcs_runtime_limits_reset_defaults();
		count = pkm_lcs_kunit_source_device_write_file(
			script->file, response, response_len, false, NULL);
		if (count != (ssize_t)response_len) {
			script->result = count < 0 ? (int)count : -EIO;
			return script->result;
		}
		script->writes++;
	}

	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_read_key_source_build_response(
	const struct pkm_lcs_kunit_read_key_source_script *script,
	u64 request_id, u8 *response, size_t response_len, size_t *built_len)
{
	static const u8 nil_guid[RSI_GUID_SIZE];
	const char *name;
	const u8 *parent_guid;
	const u8 *sd;
	size_t sd_len;
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = RSI_READ_KEY | RSI_RESPONSE_BIT;
	int ret;

	if (!script || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;
	if (script->status) {
		memset(response, 0, response_len);
		put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
				   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
		put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
		put_unaligned_le16(response_op,
				   response + RSI_RESPONSE_OP_CODE_OFFSET);
		put_unaligned_le32(script->status,
				   response + RSI_RESPONSE_STATUS_OFFSET);
		*built_len = RSI_MIN_RESPONSE_SIZE;
		return 0;
	}

	name = script->name ? script->name : "Machine";
	parent_guid = script->parent_guid ? script->parent_guid : nil_guid;
	sd = script->sd ? script->sd : pkm_lcs_kunit_owner_only_sd;
	sd_len = script->sd ? script->sd_len :
			      sizeof(pkm_lcs_kunit_owner_only_sd);

	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, name, strlen(name));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append(response, response_len, &offset,
					       parent_guid, RSI_GUID_SIZE);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, &offset, sd, sd_len);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u8(
		response, response_len, &offset, script->volatile_key ? 1 : 0);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u8(
		response, response_len, &offset, script->symlink ? 1 : 0);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u64(
		response, response_len, &offset,
		script->last_write_time ? script->last_write_time : 2000ULL);
	if (ret)
		return ret;

	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}


int pkm_lcs_kunit_read_key_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_read_key_source_script *script = raw_script;
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u8 request[64];
	u8 response[1024];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!script || !script->file || !script->expected_guid) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count != expected_len) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_read_key_source_build_response(
		script, request_id, response, sizeof(response), &response_len);
	if (ret) {
		script->result = ret;
		return script->result;
	}
	if (script->reset_runtime_limits_before_response)
		pkm_lcs_runtime_limits_reset_defaults();
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_set_security_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_set_security_source_script *script = raw_script;
	struct pkm_lcs_kunit_read_key_source_script read_script = { };
	size_t read_expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t write_expected_len;
	size_t response_len = 0;
	size_t payload_offset;
	size_t field_mask_offset;
	size_t sd_offset;
	size_t last_write_offset;
	u8 request[512];
	u8 response[512];
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->existing_sd || !script->existing_sd_len ||
	    !script->expected_merged_sd || !script->expected_merged_sd_len) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count != read_expected_len) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	read_script.expected_guid = script->expected_guid;
	read_script.name = "Software";
	read_script.sd = script->existing_sd;
	read_script.sd_len = script->existing_sd_len;
	ret = pkm_lcs_kunit_read_key_source_build_response(
		&read_script, request_id, response, sizeof(response),
		&response_len);
	if (ret) {
		script->result = ret;
		return script->result;
	}
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;

	write_expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
			     sizeof(u32) + RSI_LENGTH_PREFIX_SIZE +
			     script->expected_merged_sd_len + sizeof(u64);
	if ((size_t)count != write_expected_len) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}

	payload_offset = RSI_REQUEST_HEADER_SIZE;
	if (memcmp(request + payload_offset, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	field_mask_offset = payload_offset + RSI_GUID_SIZE;
	if (get_unaligned_le32(request + field_mask_offset) !=
	    (u32)(RSI_WRITE_KEY_FIELD_SD |
		  RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)) {
		script->result = -EINVAL;
		return script->result;
	}
	sd_offset = field_mask_offset + sizeof(u32);
	if (get_unaligned_le32(request + sd_offset) !=
	    script->expected_merged_sd_len ||
	    memcmp(request + sd_offset + RSI_LENGTH_PREFIX_SIZE,
		   script->expected_merged_sd,
		   script->expected_merged_sd_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	last_write_offset = sd_offset + RSI_LENGTH_PREFIX_SIZE +
			    script->expected_merged_sd_len;
	script->observed_last_write_time =
		get_unaligned_le64(request + last_write_offset);
	if (!script->observed_last_write_time) {
		script->result = -EINVAL;
		return script->result;
	}

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	response_len = RSI_MIN_RESPONSE_SIZE;
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_read_then_create_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_read_then_create_source_script *script = raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->read_key.file = script->file;
	script->create.file = script->file;

	if (!script->skip_read_key) {
		ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
		script->reads = script->read_key.reads;
		script->writes = script->read_key.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	ret = pkm_lcs_kunit_create_source_thread(&script->create);
	script->reads += script->create.reads;
	script->writes += script->create.writes;
	script->result = ret ? ret : script->create.result;
	return script->result;
}


int pkm_lcs_kunit_walk_then_read_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_walk_then_read_source_script *script = raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->walk);
	script->reads = script->walk.reads;
	script->writes = script->walk.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	script->read_key.file = script->file;
	ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
	script->reads += script->read_key.reads;
	script->writes += script->read_key.writes;
	script->result = ret ? ret : script->read_key.result;
	return script->result;
}


int
pkm_lcs_kunit_walk_then_query_values_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_walk_then_query_values_source_script *script =
		raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->walk);
	script->reads = script->walk.reads;
	script->writes = script->walk.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}
	if (!script->expect_query) {
		script->result = 0;
		return 0;
	}

	script->query.file = script->file;
	ret = pkm_lcs_kunit_query_values_source_thread(&script->query);
	script->reads += script->query.reads;
	script->writes += script->query.writes;
	script->result = ret ? ret : script->query.result;
	return script->result;
}


int pkm_lcs_kunit_walk_then_read_create_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_walk_then_read_create_source_script *script =
		raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->walk);
	script->reads = script->walk.reads;
	script->writes = script->walk.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	if (script->parent_walk.step_count) {
		script->parent_walk.file = script->file;
		ret = pkm_lcs_kunit_walk_source_thread(&script->parent_walk);
		script->reads += script->parent_walk.reads;
		script->writes += script->parent_walk.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	script->create.file = script->file;
	ret = pkm_lcs_kunit_read_then_create_source_thread(&script->create);
	script->reads += script->create.reads;
	script->writes += script->create.writes;
	script->result = ret ? ret : script->create.result;
	if (script->wait_for_stop_after_completion) {
		while (!kthread_should_stop())
			msleep(1);
	}
	return script->result;
}


int pkm_lcs_kunit_query_values_source_append_value(
	u8 *response, size_t response_len, size_t *offset, const char *value_name,
	const char *layer_name, u32 value_type, const u8 *data, size_t data_len,
	u64 sequence)
{
	int ret;

	if (!response || !offset || !value_name || !layer_name ||
	    (data_len && !data))
		return -EINVAL;

	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, offset, value_name,
		strlen(value_name));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, offset, layer_name,
		strlen(layer_name));
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, response_len, offset, value_type);
	if (ret)
		return ret;
	ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
		response, response_len, offset, data, data_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_walk_source_append_u64(response, response_len,
						    offset, sequence);
}


int pkm_lcs_kunit_query_values_source_build_response(
	const struct pkm_lcs_kunit_query_values_source_script *script,
	u64 request_id, u8 *response, size_t response_len, size_t *built_len)
{
	const char *value_name;
	const char *layer_name;
	const u8 *data;
	size_t data_len;
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = RSI_QUERY_VALUES | RSI_RESPONSE_BIT;
	u32 value_count;
	int ret;

	if (!script || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	value_name = script->response_value_name ?
				     script->response_value_name :
				     script->expected_value_name;
	layer_name = script->layer_name ? script->layer_name : "base";
	data = script->data ? script->data : (const u8 *)"Machine\\Target";
	data_len = script->data ? script->data_len :
				  strlen("Machine\\Target");
	value_count = script->empty ? 0U :
				    (script->include_second_value ? 2U : 1U);

	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						   &offset, value_count);
	if (ret)
		return ret;
	if (!script->empty) {
		ret = pkm_lcs_kunit_query_values_source_append_value(
			response, response_len, &offset, value_name, layer_name,
			script->value_type, data, data_len, script->sequence);
		if (ret)
			return ret;
	}
	if (!script->empty && script->include_second_value) {
		const char *second_value_name =
			script->second_response_value_name ?
				script->second_response_value_name :
				value_name;
		const char *second_layer_name =
			script->second_layer_name ?
				script->second_layer_name :
				"base";
		const u8 *second_data = script->second_data ?
						script->second_data :
						data;
		size_t second_data_len = script->second_data ?
						 script->second_data_len :
						 data_len;
		u32 second_value_type = script->second_value_type ?
						script->second_value_type :
						script->value_type;

		ret = pkm_lcs_kunit_query_values_source_append_value(
			response, response_len, &offset, second_value_name,
			second_layer_name, second_value_type, second_data,
			second_data_len, script->second_sequence);
		if (ret)
			return ret;
	}
	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, response_len, &offset,
		script->include_blanket ? 1U : 0U);
	if (ret)
		return ret;
	if (script->include_blanket) {
		const char *blanket_layer = script->blanket_layer_name ?
						    script->blanket_layer_name :
						    "overlay";

		ret = pkm_lcs_kunit_walk_source_append_len_prefixed(
			response, response_len, &offset, blanket_layer,
			strlen(blanket_layer));
		if (ret)
			return ret;
		ret = pkm_lcs_kunit_walk_source_append_u64(
			response, response_len, &offset,
			script->blanket_sequence);
		if (ret)
			return ret;
	}

	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}


int pkm_lcs_kunit_query_values_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_query_values_source_script *script = raw_script;
	size_t value_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	u8 request[128];
	u8 response[512];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_value_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count < value_offset + sizeof(u32) + sizeof(u8)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset ||
	    value_len != strlen(script->expected_value_name) ||
	    memcmp(request + value_offset, script->expected_value_name,
		   value_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	value_offset += value_len;
	if (value_offset >= (size_t)count ||
	    request[value_offset] != (script->query_all ? 1 : 0)) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_query_values_source_build_response(
		script, request_id, response, sizeof(response), &response_len);
	if (ret) {
		script->result = ret;
		return script->result;
	}
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_layer_metadata_refresh_source_read(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	u8 *request, size_t request_len, ssize_t *count_out)
{
	ssize_t count;

	if (!script || !request || !count_out)
		return -EINVAL;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0)
		return (int)count;
	script->reads++;
	*count_out = count;
	return 0;
}


int pkm_lcs_kunit_layer_metadata_refresh_write_frame(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	const u8 *response, size_t response_len)
{
	ssize_t count;

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	u8 *request, size_t request_len)
{
	struct pkm_lcs_kunit_read_key_source_script read_key = {
		.expected_guid = script->expected_guid,
		.name = script->name ? script->name : "Policy",
		.sd = script->sd,
		.sd_len = script->sd_len,
	};
	u8 response[512];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	ret = pkm_lcs_kunit_layer_metadata_refresh_source_read(
		script, request, request_len, &count);
	if (ret)
		return ret;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE)
		return -EINVAL;
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0 ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	ret = pkm_lcs_kunit_read_key_source_build_response(
		&read_key, request_id, response, sizeof(response),
		&response_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_layer_metadata_refresh_write_frame(
		script, response, response_len);
}


int pkm_lcs_kunit_layer_metadata_refresh_write_query_response(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	u64 request_id, const char *value_name, bool present, u32 value)
{
	u8 response[256];
	u8 data[sizeof(u32)];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	int ret;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, sizeof(response), &offset, present ? 1U : 0U);
	if (ret)
		return ret;
	if (present) {
		put_unaligned_le32(value, data);
		ret = pkm_lcs_kunit_query_values_source_append_value(
			response, sizeof(response), &offset, value_name, "base",
			REG_DWORD, data, sizeof(data), 0);
		if (ret)
			return ret;
	}
	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, sizeof(response), &offset, 0);
	if (ret)
		return ret;
	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	return pkm_lcs_kunit_layer_metadata_refresh_write_frame(
		script, response, offset);
}


int pkm_lcs_kunit_layer_metadata_refresh_write_binary_query_response(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	u64 request_id, const char *value_name, bool present, const u8 *data,
	size_t data_len)
{
	u8 response[256];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	int ret;

	if (present && (!data || !data_len))
		return -EINVAL;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, sizeof(response), &offset, present ? 1U : 0U);
	if (ret)
		return ret;
	if (present) {
		ret = pkm_lcs_kunit_query_values_source_append_value(
			response, sizeof(response), &offset, value_name, "base",
			REG_BINARY, data, data_len, 0);
		if (ret)
			return ret;
	}
	ret = pkm_lcs_kunit_walk_source_append_u32(
		response, sizeof(response), &offset, 0);
	if (ret)
		return ret;
	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	return pkm_lcs_kunit_layer_metadata_refresh_write_frame(
		script, response, offset);
}


int pkm_lcs_kunit_layer_metadata_refresh_handle_query(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	u8 *request, size_t request_len, const char *expected_value_name,
	bool present, u32 value)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	ret = pkm_lcs_kunit_layer_metadata_refresh_source_read(
		script, request, request_len, &count);
	if (ret)
		return ret;
	if ((size_t)count < offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0 ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || value_len > (size_t)count - offset ||
	    value_len != strlen(expected_value_name) ||
	    memcmp(request + offset, expected_value_name, value_len))
		return -EINVAL;
	offset += value_len;
	if (offset >= (size_t)count || request[offset] != 0)
		return -EINVAL;
	offset++;
	if (offset != (size_t)count)
		return -EINVAL;

	return pkm_lcs_kunit_layer_metadata_refresh_write_query_response(
		script, request_id, expected_value_name, present, value);
}


int pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	static const char expected_value_name[] = "Owner";
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	ret = pkm_lcs_kunit_layer_metadata_refresh_source_read(
		script, request, request_len, &count);
	if (ret)
		return ret;
	if ((size_t)count < offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) != 0 ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || value_len > (size_t)count - offset ||
	    value_len != strlen(expected_value_name) ||
	    memcmp(request + offset, expected_value_name, value_len))
		return -EINVAL;
	offset += value_len;
	if (offset >= (size_t)count || request[offset] != 0)
		return -EINVAL;
	offset++;
	if (offset != (size_t)count)
		return -EINVAL;

	return pkm_lcs_kunit_layer_metadata_refresh_write_binary_query_response(
		script, request_id, expected_value_name, script->owner_present,
		script->owner_sid, script->owner_sid_len);
}


bool pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
	const struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script)
{
	return script && script->enabled_present && script->enabled > 1U;
}


int pkm_lcs_kunit_layer_metadata_refresh_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script *script =
		raw_script;
	u8 request[256];
	int ret;

	if (!script || !script->file || !script->expected_guid) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		script, request, sizeof(request));
	if (ret)
		goto out;
	if (script->stop_after_read_key)
		goto out;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		script, request, sizeof(request), "Precedence",
		script->precedence_present, script->precedence);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		script, request, sizeof(request), "Enabled",
		script->enabled_present, script->enabled);
	if (ret)
		goto out;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(script))
		goto out;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		script, request, sizeof(request));

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


int pkm_lcs_kunit_layer_create_watch_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_layer_create_watch_source_script *script =
		raw_script;
	u8 request[256];
	int ret;

	if (!script || !script->lookup.file || !script->lookup.steps) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_walk_source_thread(&script->lookup);
	script->reads += script->lookup.reads;
	script->writes += script->lookup.writes;
	if (ret || !script->expect_refresh)
		goto out;

	script->refresh.file = script->lookup.file;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		&script->refresh, request, sizeof(request));
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Precedence",
		script->refresh.precedence_present,
		script->refresh.precedence);
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Enabled",
		script->refresh.enabled_present, script->refresh.enabled);
	if (ret)
		goto out_refresh;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
		    &script->refresh))
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		&script->refresh, request, sizeof(request));

out_refresh:
	script->reads += script->refresh.reads;
	script->writes += script->refresh.writes;
	script->refresh.result = ret;
out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


int pkm_lcs_kunit_set_security_layer_refresh_source_thread(
	void *raw_script)
{
	struct pkm_lcs_kunit_set_security_layer_refresh_source_script *script =
		raw_script;
	u8 request[256];
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->set_security.file = script->file;
	ret = pkm_lcs_kunit_set_security_source_thread(&script->set_security);
	script->reads += script->set_security.reads;
	script->writes += script->set_security.writes;
	if (ret)
		goto out;

	script->refresh.file = script->file;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		&script->refresh, request, sizeof(request));
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Precedence",
		script->refresh.precedence_present,
		script->refresh.precedence);
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Enabled",
		script->refresh.enabled_present, script->refresh.enabled);
	if (ret)
		goto out_refresh;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
		    &script->refresh))
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		&script->refresh, request, sizeof(request));

out_refresh:
	script->reads += script->refresh.reads;
	script->writes += script->refresh.writes;
	script->refresh.result = ret;
out:
	script->result = ret;
	return ret;
}


int pkm_lcs_kunit_create_layer_refresh_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_create_layer_refresh_source_script *script =
		raw_script;
	u8 request[256];
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->create.file = script->file;
	ret = pkm_lcs_kunit_create_source_thread(&script->create);
	script->reads = script->create.reads;
	script->writes = script->create.writes;
	if (ret)
		goto out;

	script->refresh.file = script->file;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		&script->refresh, request, sizeof(request));
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Precedence",
		script->refresh.precedence_present,
		script->refresh.precedence);
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Enabled",
		script->refresh.enabled_present, script->refresh.enabled);
	if (ret)
		goto out_refresh;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
		    &script->refresh))
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		&script->refresh, request, sizeof(request));

out_refresh:
	script->reads += script->refresh.reads;
	script->writes += script->refresh.writes;
	script->refresh.result = ret;
out:
	script->result = ret;
	return ret;
}


int pkm_lcs_kunit_set_value_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_set_value_source_script *script = raw_script;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[256];
	size_t response_len;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_layer_name || !script->expected_value_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count < offset + RSI_GUID_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_SET_VALUE ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name,
		   field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset ||
	    get_unaligned_le32(request + offset) !=
		    script->expected_value_type) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += sizeof(u32);

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != script->expected_data_len ||
	    (field_len && memcmp(request + offset, script->expected_data,
				 field_len))) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u64) * 2U > (size_t)count - offset ||
	    get_unaligned_le64(request + offset) !=
		    script->expected_sequence ||
	    get_unaligned_le64(request + offset + sizeof(u64)) !=
		    script->expected_expected_sequence) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += sizeof(u64) * 2U;
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}

	response_len = RSI_MIN_RESPONSE_SIZE;
	if (script->extra_response_payload)
		response_len += sizeof(u32);
	memset(response, 0, sizeof(response));
	put_unaligned_le32((u32)response_len,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_SET_VALUE_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload)
		put_unaligned_le32(0xabcdef01U,
				   response + RSI_MIN_RESPONSE_SIZE);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_delete_value_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_delete_value_source_script *script = raw_script;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[192];
	size_t response_len;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_layer_name || !script->expected_value_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count < offset + RSI_GUID_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_DELETE_VALUE_ENTRY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name,
		   field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}

	response_len = RSI_MIN_RESPONSE_SIZE;
	if (script->extra_response_payload)
		response_len += sizeof(u32);
	memset(response, 0, sizeof(response));
	put_unaligned_le32((u32)response_len,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_DELETE_VALUE_ENTRY_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload)
		put_unaligned_le32(0xabcdef02U,
				   response + RSI_MIN_RESPONSE_SIZE);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_blanket_tombstone_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_blanket_tombstone_source_script *script =
		raw_script;
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32)];
	u8 request[160];
	size_t response_len;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_layer_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if ((size_t)count < offset + RSI_GUID_SIZE) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_SET_BLANKET_TOMBSTONE ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count ||
	    sizeof(u32) > (size_t)count - offset) {
		script->result = -EINVAL;
		return script->result;
	}
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count ||
	    field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name,
		   field_len)) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u8) + sizeof(u64) > (size_t)count - offset ||
	    request[offset] != (script->expected_set ? 1U : 0U) ||
	    get_unaligned_le64(request + offset + sizeof(u8)) !=
		    script->expected_sequence) {
		script->result = -EINVAL;
		return script->result;
	}
	offset += sizeof(u8) + sizeof(u64);
	if (offset != (size_t)count) {
		script->result = -EINVAL;
		return script->result;
	}

	response_len = RSI_MIN_RESPONSE_SIZE;
	if (script->extra_response_payload)
		response_len += sizeof(u32);
	memset(response, 0, sizeof(response));
	put_unaligned_le32((u32)response_len,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_SET_BLANKET_TOMBSTONE_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	if (script->extra_response_payload)
		put_unaligned_le32(0xabcdef03U,
				   response + RSI_MIN_RESPONSE_SIZE);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


ssize_t pkm_lcs_kunit_set_value_ioctl_source_read(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}


int pkm_lcs_kunit_set_value_ioctl_source_write_status(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u64 request_id, u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response))
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_set_value_ioctl_source_write_empty_values(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u64 request_id)
{
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32) * 2U];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	if (pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						 &offset, 0) ||
	    pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						 &offset, 0))
		return -EMSGSIZE;
	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_set_value_ioctl_source_handle_query(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;

	count = pkm_lcs_kunit_set_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_query_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || value_len > (size_t)count - offset ||
	    value_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, value_len))
		return -EINVAL;
	offset += value_len;
	if (offset >= (size_t)count || request[offset] != 0)
		return -EINVAL;
	offset++;
	if (offset != (size_t)count)
		return -EINVAL;

	return pkm_lcs_kunit_set_value_ioctl_source_write_empty_values(
		script, request_id);
}


int pkm_lcs_kunit_set_value_ioctl_source_handle_set_value(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len, bool *continue_after_set)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;
	int ret;

	*continue_after_set = false;
	count = pkm_lcs_kunit_set_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + RSI_GUID_SIZE)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_SET_VALUE ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, field_len))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name, field_len))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset ||
	    get_unaligned_le32(request + offset) !=
		    script->expected_value_type)
		return -EINVAL;
	offset += sizeof(u32);

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != script->expected_data_len ||
	    (field_len && memcmp(request + offset, script->expected_data,
				 field_len)))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u64) * 2U > (size_t)count - offset ||
	    get_unaligned_le64(request + offset) !=
		    script->expected_sequence ||
	    get_unaligned_le64(request + offset + sizeof(u64)) !=
		    script->expected_expected_sequence)
		return -EINVAL;
	offset += sizeof(u64) * 2U;
	if (offset != (size_t)count)
		return -EINVAL;

	ret = pkm_lcs_kunit_set_value_ioctl_source_write_status(
		script, request_id, request_op, script->set_value_status);
	if (ret)
		return ret;
	*continue_after_set = script->set_value_status == RSI_OK;
	return 0;
}


int pkm_lcs_kunit_set_value_ioctl_source_handle_write_key(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_mask;
	int ret;

	count = pkm_lcs_kunit_set_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
				     sizeof(u32) + sizeof(u64))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	field_mask = get_unaligned_le32(request + offset);
	if (field_mask != RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)
		return -EINVAL;
	offset += sizeof(u32);
	script->observed_last_write_time = get_unaligned_le64(request + offset);
	if (!script->observed_last_write_time)
		return -EINVAL;

	ret = pkm_lcs_kunit_set_value_ioctl_source_write_status(
		script, request_id, request_op, RSI_OK);
	if (ret)
		return ret;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_set_value_ioctl_source_handle_layer_refresh(
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	struct pkm_lcs_kunit_layer_metadata_refresh_source_script refresh = {
		.file = script->file,
		.expected_guid = script->expected_guid,
		.name = script->refresh_layer_name,
		.sd = script->refresh_sd,
		.sd_len = script->refresh_sd_len,
		.precedence = script->refresh_precedence,
		.enabled = script->refresh_enabled,
		.precedence_present = script->refresh_precedence_present,
		.enabled_present = script->refresh_enabled_present,
	};
	int ret;

	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		&refresh, request, request_len);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&refresh, request, request_len, "Precedence",
		refresh.precedence_present, refresh.precedence);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&refresh, request, request_len, "Enabled",
		refresh.enabled_present, refresh.enabled);
	if (ret)
		goto out;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(&refresh))
		goto out;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		&refresh, request, request_len);

out:
	script->reads += refresh.reads;
	script->writes += refresh.writes;
	return ret;
}


int pkm_lcs_kunit_set_value_ioctl_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_set_value_ioctl_source_script *script = raw_script;
	bool continue_after_set = false;
	u8 request[1024];
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_value_name || !script->expected_layer_name ||
	    (script->expected_data_len && !script->expected_data)) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_query(
		script, request, sizeof(request));
	if (ret)
		goto out;
	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret)
			goto out;
	}
	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_set_value(
		script, request, sizeof(request), &continue_after_set);
	if (ret || !continue_after_set)
		goto out;
	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_write_key(
		script, request, sizeof(request));
	if (ret || !script->expect_layer_refresh)
		goto out;
	ret = pkm_lcs_kunit_set_value_ioctl_source_handle_layer_refresh(
		script, request, sizeof(request));

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


ssize_t pkm_lcs_kunit_delete_value_ioctl_source_read(
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}


int pkm_lcs_kunit_delete_value_ioctl_source_write_status(
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script,
	u64 request_id, u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response))
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_delete_value_ioctl_source_write_query_response(
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script,
	u64 request_id, bool after)
{
	const char *layer_name = after ? script->after_layer_name :
					script->before_layer_name;
	const u8 *data = after ? script->after_data : script->before_data;
	size_t data_len = after ? script->after_data_len :
				  script->before_data_len;
	u32 value_type = after ? script->after_value_type :
				 script->before_value_type;
	u64 sequence = after ? script->after_sequence : script->before_sequence;
	bool found = after ? script->after_found : script->before_found;
	u8 response[1024];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	if (pkm_lcs_kunit_walk_source_append_u32(
		    response, sizeof(response), &offset, found ? 1U : 0U))
		return -EMSGSIZE;
	if (found) {
		if (!layer_name)
			layer_name = "base";
		if (!data) {
			data = (const u8 *)"value";
			data_len = strlen("value");
		}
		if (pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, sizeof(response), &offset,
			    script->expected_value_name,
			    strlen(script->expected_value_name)) ||
		    pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, sizeof(response), &offset, layer_name,
			    strlen(layer_name)) ||
		    pkm_lcs_kunit_walk_source_append_u32(
			    response, sizeof(response), &offset, value_type) ||
		    pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, sizeof(response), &offset, data,
			    data_len) ||
		    pkm_lcs_kunit_walk_source_append_u64(
			    response, sizeof(response), &offset, sequence))
			return -EMSGSIZE;
	}
	if (pkm_lcs_kunit_walk_source_append_u32(response, sizeof(response),
						 &offset, 0))
		return -EMSGSIZE;
	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_delete_value_ioctl_source_handle_query(
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script,
	u8 *request, size_t request_len, bool after)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;

	count = pkm_lcs_kunit_delete_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    (after ? script->expected_after_query_txn_id :
			     script->expected_before_query_txn_id) ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || value_len > (size_t)count - offset ||
	    value_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, value_len))
		return -EINVAL;
	offset += value_len;
	if (offset >= (size_t)count || request[offset] != 0)
		return -EINVAL;
	offset++;
	if (offset != (size_t)count)
		return -EINVAL;

	return pkm_lcs_kunit_delete_value_ioctl_source_write_query_response(
		script, request_id, after);
}


int pkm_lcs_kunit_delete_value_ioctl_source_handle_delete(
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script,
	u8 *request, size_t request_len, bool *continue_after_delete)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;
	int ret;

	*continue_after_delete = false;
	count = pkm_lcs_kunit_delete_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + RSI_GUID_SIZE)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_DELETE_VALUE_ENTRY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_value_name) ||
	    memcmp(request + offset, script->expected_value_name, field_len))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name, field_len))
		return -EINVAL;
	offset += field_len;
	if (offset != (size_t)count)
		return -EINVAL;

	ret = pkm_lcs_kunit_delete_value_ioctl_source_write_status(
		script, request_id, request_op, script->delete_status);
	if (ret)
		return ret;
	*continue_after_delete = script->delete_status == RSI_OK;
	return 0;
}


int pkm_lcs_kunit_delete_value_ioctl_source_handle_write_key(
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_mask;
	int ret;

	count = pkm_lcs_kunit_delete_value_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
				     sizeof(u32) + sizeof(u64))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	field_mask = get_unaligned_le32(request + offset);
	if (field_mask != RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)
		return -EINVAL;
	offset += sizeof(u32);
	script->observed_last_write_time = get_unaligned_le64(request + offset);
	if (!script->observed_last_write_time)
		return -EINVAL;

	ret = pkm_lcs_kunit_delete_value_ioctl_source_write_status(
		script, request_id, request_op, RSI_OK);
	if (ret)
		return ret;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_delete_value_ioctl_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_delete_value_ioctl_source_script *script =
		raw_script;
	bool continue_after_delete = false;
	u8 request[1024];
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_value_name || !script->expected_layer_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret)
			goto out;
	}
	ret = pkm_lcs_kunit_delete_value_ioctl_source_handle_query(
		script, request, sizeof(request), false);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_delete_value_ioctl_source_handle_delete(
		script, request, sizeof(request), &continue_after_delete);
	if (ret || !continue_after_delete)
		goto out;
	ret = pkm_lcs_kunit_delete_value_ioctl_source_handle_query(
		script, request, sizeof(request), true);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_delete_value_ioctl_source_handle_write_key(
		script, request, sizeof(request));

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


ssize_t pkm_lcs_kunit_blanket_tombstone_ioctl_source_read(
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}


int pkm_lcs_kunit_blanket_tombstone_ioctl_source_write_status(
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script,
	u64 request_id, u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response))
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int
pkm_lcs_kunit_blanket_tombstone_ioctl_source_write_query_response(
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script,
	u64 request_id, bool after)
{
	const char *value_layer = after ? script->after_value_layer_name :
					  script->before_value_layer_name;
	const u8 *data = after ? script->after_data : script->before_data;
	size_t data_len = after ? script->after_data_len :
				  script->before_data_len;
	u32 value_type = after ? script->after_value_type :
				 script->before_value_type;
	u64 value_sequence = after ? script->after_value_sequence :
				     script->before_value_sequence;
	bool value_found = after ? script->after_value_found :
				   script->before_value_found;
	bool blanket_found = after ? script->after_blanket_found :
				     script->before_blanket_found;
	u64 blanket_sequence = after ? script->after_blanket_sequence :
				       script->before_blanket_sequence;
	u8 response[1024];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_QUERY_VALUES_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);

	if (pkm_lcs_kunit_walk_source_append_u32(
		    response, sizeof(response), &offset, value_found ? 1U : 0U))
		return -EMSGSIZE;
	if (value_found) {
		if (!value_layer)
			value_layer = "base";
		if (!data) {
			data = (const u8 *)"value";
			data_len = strlen("value");
		}
		if (pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, sizeof(response), &offset,
			    script->expected_value_name,
			    strlen(script->expected_value_name)) ||
		    pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, sizeof(response), &offset, value_layer,
			    strlen(value_layer)) ||
		    pkm_lcs_kunit_walk_source_append_u32(
			    response, sizeof(response), &offset, value_type) ||
		    pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, sizeof(response), &offset, data,
			    data_len) ||
		    pkm_lcs_kunit_walk_source_append_u64(
			    response, sizeof(response), &offset,
			    value_sequence))
			return -EMSGSIZE;
	}

	if (pkm_lcs_kunit_walk_source_append_u32(
		    response, sizeof(response), &offset,
		    blanket_found ? 1U : 0U))
		return -EMSGSIZE;
	if (blanket_found &&
	    (pkm_lcs_kunit_walk_source_append_len_prefixed(
		     response, sizeof(response), &offset,
		     script->expected_layer_name,
		     strlen(script->expected_layer_name)) ||
	     pkm_lcs_kunit_walk_source_append_u64(
		     response, sizeof(response), &offset,
		     blanket_sequence)))
		return -EMSGSIZE;

	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_query(
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script,
	u8 *request, size_t request_len, bool after)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;

	count = pkm_lcs_kunit_blanket_tombstone_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    (after ? script->expected_after_query_txn_id :
			     script->expected_before_query_txn_id) ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || value_len > (size_t)count - offset ||
	    value_len)
		return -EINVAL;
	offset += value_len;
	if (offset >= (size_t)count || request[offset] != 1U)
		return -EINVAL;
	offset++;
	if (offset != (size_t)count)
		return -EINVAL;

	return pkm_lcs_kunit_blanket_tombstone_ioctl_source_write_query_response(
		script, request_id, after);
}


int pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_blanket(
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script,
	u8 *request, size_t request_len, bool *continue_after_blanket)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_len;
	int ret;

	*continue_after_blanket = false;
	count = pkm_lcs_kunit_blanket_tombstone_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < offset + RSI_GUID_SIZE)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_SET_BLANKET_TOMBSTONE ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	if (offset > (size_t)count || sizeof(u32) > (size_t)count - offset)
		return -EINVAL;
	field_len = get_unaligned_le32(request + offset);
	offset += sizeof(u32);
	if (offset > (size_t)count || field_len > (size_t)count - offset ||
	    field_len != strlen(script->expected_layer_name) ||
	    memcmp(request + offset, script->expected_layer_name, field_len))
		return -EINVAL;
	offset += field_len;

	if (offset > (size_t)count ||
	    sizeof(u8) + sizeof(u64) > (size_t)count - offset ||
	    request[offset] != (script->expected_set ? 1U : 0U) ||
	    get_unaligned_le64(request + offset + sizeof(u8)) !=
		    script->expected_sequence)
		return -EINVAL;
	offset += sizeof(u8) + sizeof(u64);
	if (offset != (size_t)count)
		return -EINVAL;

	ret = pkm_lcs_kunit_blanket_tombstone_ioctl_source_write_status(
		script, request_id, request_op, script->blanket_status);
	if (ret)
		return ret;
	*continue_after_blanket = script->blanket_status == RSI_OK;
	return 0;
}


int pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_write_key(
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_mask;
	int ret;

	count = pkm_lcs_kunit_blanket_tombstone_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
				     sizeof(u32) + sizeof(u64))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_guid, RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	field_mask = get_unaligned_le32(request + offset);
	if (field_mask != RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)
		return -EINVAL;
	offset += sizeof(u32);
	script->observed_last_write_time = get_unaligned_le64(request + offset);
	if (!script->observed_last_write_time)
		return -EINVAL;

	ret = pkm_lcs_kunit_blanket_tombstone_ioctl_source_write_status(
		script, request_id, request_op, RSI_OK);
	if (ret)
		return ret;
	script->result = 0;
	return 0;
}


int
pkm_lcs_kunit_blanket_tombstone_ioctl_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_blanket_tombstone_ioctl_source_script *script =
		raw_script;
	bool continue_after_blanket = false;
	u8 request[1024];
	int ret;

	if (!script || !script->file || !script->expected_guid ||
	    !script->expected_value_name || !script->expected_layer_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret)
			goto out;
	}
	ret = pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_query(
		script, request, sizeof(request), false);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_blanket(
		script, request, sizeof(request), &continue_after_blanket);
	if (ret || !continue_after_blanket)
		goto out;
	ret = pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_query(
		script, request, sizeof(request), true);
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_blanket_tombstone_ioctl_source_handle_write_key(
		script, request, sizeof(request));

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


int pkm_lcs_kunit_enum_children_source_build_response(
	const struct pkm_lcs_kunit_enum_children_source_script *script,
	u64 request_id, u8 *response, size_t response_len, size_t *built_len)
{
	static const u8 hidden_guid[RSI_GUID_SIZE] = { };
	u32 child_count;
	u32 metadata_count;
	const char *child_name;
	const char *layer_name;
	const u8 *target_guid;
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	u16 response_op = RSI_ENUM_CHILDREN | RSI_RESPONSE_BIT;
	u8 target_type;
	u32 i;

	if (!script || !response || !built_len)
		return -EINVAL;
	if (response_len < RSI_MIN_RESPONSE_SIZE)
		return -EMSGSIZE;

	child_name = script->child_name ? script->child_name : "Child";
	layer_name = script->layer_name ? script->layer_name : "base";
	target_guid = script->hidden ? hidden_guid : script->child_guid;
	target_type = script->hidden ? RSI_PATH_TARGET_HIDDEN :
				       RSI_PATH_TARGET_GUID;
	child_count = script->empty ? 0U :
				    (script->repeated_child_count ?
					     script->repeated_child_count :
					     (script->include_second_entry ? 2U :
								      1U));
	if (!script->empty && !script->repeated_child_count && !target_guid)
		return -EINVAL;
	metadata_count = 0U;
	if (!script->empty) {
		if (!script->hidden)
			metadata_count++;
		if (script->include_second_entry && !script->second_hidden)
			metadata_count++;
		if (script->repeated_child_count)
			metadata_count = child_count;
	}

	memset(response, 0, response_len);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(response_op, response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	if (pkm_lcs_kunit_walk_source_append_u32(response, response_len,
						 &offset, child_count))
		return -EMSGSIZE;

	for (i = 0; i < child_count; i++) {
		char generated_name[32];
		u8 generated_guid[RSI_GUID_SIZE] = { 0x80 };

		if (script->repeated_child_count) {
			scnprintf(generated_name, sizeof(generated_name),
				  "Layer%04u", i);
			generated_guid[1] = (u8)(i + 1U);
			child_name = generated_name;
			target_guid = generated_guid;
			target_type = RSI_PATH_TARGET_GUID;
		} else if (i == 1U) {
			child_name = script->second_child_name ?
					     script->second_child_name :
					     child_name;
			layer_name = script->second_layer_name ?
					     script->second_layer_name :
					     layer_name;
			target_guid = script->second_hidden ?
					      hidden_guid :
					      (script->second_child_guid ?
						       script->second_child_guid :
						       target_guid);
			target_type = script->second_hidden ?
					      RSI_PATH_TARGET_HIDDEN :
					      RSI_PATH_TARGET_GUID;
		}

		if (pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, response_len, &offset, child_name,
			    strlen(child_name)))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append_u32(response, response_len,
							 &offset, 1))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, response_len, &offset, layer_name,
			    strlen(layer_name)))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append_u8(
			    response, response_len, &offset, target_type))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append(response, response_len,
						     &offset, target_guid,
						     RSI_GUID_SIZE))
			return -EMSGSIZE;
		if (pkm_lcs_kunit_walk_source_append_u64(
			    response, response_len, &offset,
			    (i == 1U && script->include_second_entry) ?
				    script->second_sequence :
				    script->sequence))
			return -EMSGSIZE;
	}

	if (pkm_lcs_kunit_walk_source_append_u32(
		    response, response_len, &offset, metadata_count))
		return -EMSGSIZE;
	for (i = 0; i < metadata_count; i++) {
		u8 generated_guid[RSI_GUID_SIZE] = { 0x80 };

		target_guid = script->child_guid;
		if (script->repeated_child_count) {
			generated_guid[1] = (u8)(i + 1U);
			target_guid = generated_guid;
		} else if (!script->hidden && i == 1U &&
			   script->include_second_entry) {
			target_guid = script->second_child_guid ?
					      script->second_child_guid :
					      target_guid;
		} else if (script->hidden && script->include_second_entry &&
			   !script->second_hidden) {
			target_guid = script->second_child_guid;
		}

		if (pkm_lcs_kunit_walk_source_append(response, response_len,
						     &offset, target_guid,
						     RSI_GUID_SIZE) ||
		    pkm_lcs_kunit_walk_source_append_len_prefixed(
			    response, response_len, &offset,
			    pkm_lcs_kunit_owner_only_sd,
			    sizeof(pkm_lcs_kunit_owner_only_sd)) ||
		    pkm_lcs_kunit_walk_source_append_u8(response, response_len,
							&offset, 0) ||
		    pkm_lcs_kunit_walk_source_append_u8(response, response_len,
							&offset, 0) ||
		    pkm_lcs_kunit_walk_source_append_u64(response,
							 response_len, &offset,
							 1000))
			return -EMSGSIZE;
	}
	if (offset > U32_MAX)
		return -EOVERFLOW;
	put_unaligned_le32((u32)offset, response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	*built_len = offset;
	return 0;
}


int pkm_lcs_kunit_enum_children_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_enum_children_source_script *script = raw_script;
	u8 request[RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE];
	u8 response[4096];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!script || !script->file || !script->expected_parent_guid) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;
	if (count != (ssize_t)sizeof(request)) {
		script->result = -EINVAL;
		return script->result;
	}

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_ENUM_CHILDREN ||
	    (script->check_txn_id &&
	     get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		     script->expected_txn_id) ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE,
		   script->expected_parent_guid, RSI_GUID_SIZE)) {
		script->result = -EINVAL;
		return script->result;
	}

	ret = pkm_lcs_kunit_enum_children_source_build_response(
		script, request_id, response, sizeof(response), &response_len);
	if (ret) {
		script->result = ret;
		return script->result;
	}
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = count < 0 ? (int)count : -EIO;
		return script->result;
	}
	script->writes++;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_layer_metadata_refresh_all_source_thread(
	void *raw_script)
{
	struct pkm_lcs_kunit_layer_metadata_refresh_all_source_script *script =
		raw_script;
	u8 request[256];
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->enum_children.file = script->file;
	ret = pkm_lcs_kunit_enum_children_source_thread(&script->enum_children);
	script->reads = script->enum_children.reads;
	script->writes = script->enum_children.writes;
	if (ret)
		goto out;
	if (!script->expect_refresh)
		goto out;

	script->refresh.file = script->file;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		&script->refresh, request, sizeof(request));
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Precedence",
		script->refresh.precedence_present,
		script->refresh.precedence);
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&script->refresh, request, sizeof(request), "Enabled",
		script->refresh.enabled_present, script->refresh.enabled);
	if (ret)
		goto out_refresh;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
		    &script->refresh))
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		&script->refresh, request, sizeof(request));

out_refresh:
	script->reads += script->refresh.reads;
	script->writes += script->refresh.writes;
out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


int pkm_lcs_kunit_source_bootstrap_handle_layer_refresh_all(
	struct pkm_lcs_kunit_source_bootstrap_source_script *script)
{
	struct pkm_lcs_kunit_layer_metadata_refresh_all_source_script *refresh =
		&script->layers_refresh;
	u8 request[256];
	int ret;

	refresh->enum_children.file = script->file;
	ret = pkm_lcs_kunit_enum_children_source_thread(
		&refresh->enum_children);
	refresh->reads = refresh->enum_children.reads;
	refresh->writes = refresh->enum_children.writes;
	if (ret)
		goto out;
	if (!refresh->expect_refresh)
		goto out;

	refresh->refresh.file = script->file;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
		&refresh->refresh, request, sizeof(request));
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&refresh->refresh, request, sizeof(request), "Precedence",
		refresh->refresh.precedence_present,
		refresh->refresh.precedence);
	if (ret)
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
		&refresh->refresh, request, sizeof(request), "Enabled",
		refresh->refresh.enabled_present, refresh->refresh.enabled);
	if (ret)
		goto out_refresh;
	if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
		    &refresh->refresh))
		goto out_refresh;
	ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
		&refresh->refresh, request, sizeof(request));

out_refresh:
	refresh->reads += refresh->refresh.reads;
	refresh->writes += refresh->refresh.writes;
out:
	refresh->result = ret;
	return ret;
}


int pkm_lcs_kunit_source_bootstrap_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_source_bootstrap_source_script *script =
		raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->self_config_walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->self_config_walk);
	script->reads += script->self_config_walk.reads;
	script->writes += script->self_config_walk.writes;
	if (ret)
		goto out;

	script->self_config_query.file = script->file;
	ret = pkm_lcs_kunit_query_values_source_thread(
		&script->self_config_query);
	script->reads += script->self_config_query.reads;
	script->writes += script->self_config_query.writes;
	if (ret)
		goto out;

	script->kmes_walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->kmes_walk);
	script->reads += script->kmes_walk.reads;
	script->writes += script->kmes_walk.writes;
	if (ret)
		goto out;
	if (script->expect_kmes_query) {
		script->kmes_query.file = script->file;
		ret = pkm_lcs_kunit_query_values_source_thread(
			&script->kmes_query);
		script->reads += script->kmes_query.reads;
		script->writes += script->kmes_query.writes;
		if (ret)
			goto out;
	}

	script->layers_walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->layers_walk);
	script->reads += script->layers_walk.reads;
	script->writes += script->layers_walk.writes;
	if (ret || !script->expect_layers_refresh)
		goto out;

	ret = pkm_lcs_kunit_source_bootstrap_handle_layer_refresh_all(script);
	script->reads += script->layers_refresh.reads;
	script->writes += script->layers_refresh.writes;

out:
	script->result = ret;
	while (!kthread_should_stop())
		msleep(1);
	return ret;
}


ssize_t pkm_lcs_kunit_delete_key_ioctl_source_read(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}


int pkm_lcs_kunit_delete_key_ioctl_source_write_status(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u64 request_id, u16 request_op, u32 status)
{
	u8 response[RSI_MIN_RESPONSE_SIZE];
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(request_op | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(status, response + RSI_RESPONSE_STATUS_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, sizeof(response), false, NULL);
	if (count != (ssize_t)sizeof(response))
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_delete_key_ioctl_source_write_empty_enum(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u64 request_id)
{
	u8 response[RSI_MIN_RESPONSE_SIZE + sizeof(u32) * 2U];
	size_t offset = RSI_MIN_RESPONSE_SIZE;
	ssize_t count;

	memset(response, 0, sizeof(response));
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(RSI_ENUM_CHILDREN_RESPONSE,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(RSI_OK, response + RSI_RESPONSE_STATUS_OFFSET);
	if (pkm_lcs_kunit_walk_source_append_u32(
		    response, sizeof(response), &offset, 0) ||
	    pkm_lcs_kunit_walk_source_append_u32(
		    response, sizeof(response), &offset, 0))
		return -EMSGSIZE;
	put_unaligned_le32((u32)offset,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, offset, false, NULL);
	if (count != (ssize_t)offset)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_delete_key_ioctl_source_handle_enum(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u8 *request, size_t request_len, bool *has_visible_children)
{
	struct pkm_lcs_kunit_enum_children_source_script enum_script = { };
	u8 response[256];
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	*has_visible_children = false;
	count = pkm_lcs_kunit_delete_key_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_ENUM_CHILDREN ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE,
		   script->expected_key_guid, RSI_GUID_SIZE))
		return -EINVAL;

	if (!script->visible_child_guid)
		return pkm_lcs_kunit_delete_key_ioctl_source_write_empty_enum(
			script, request_id);

	enum_script.file = script->file;
	enum_script.expected_parent_guid = script->expected_key_guid;
	enum_script.child_guid = script->visible_child_guid;
	enum_script.child_name = script->visible_child_name ?
					 script->visible_child_name :
					 "Child";
	enum_script.layer_name = script->visible_child_layer_name ?
					 script->visible_child_layer_name :
					 "base";
	ret = pkm_lcs_kunit_enum_children_source_build_response(
		&enum_script, request_id, response, sizeof(response),
		&response_len);
	if (ret)
		return ret;
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	*has_visible_children = true;
	return 0;
}


int pkm_lcs_kunit_delete_key_ioctl_source_handle_delete(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u8 *request, size_t request_len, bool *continue_after_delete)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	*continue_after_delete = false;
	count = pkm_lcs_kunit_delete_key_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < RSI_REQUEST_HEADER_SIZE)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_DELETE_ENTRY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id)
		return -EINVAL;
	if (pkm_lcs_kunit_create_source_expect_bytes(
		    request, (size_t)count, &offset,
		    script->expected_parent_guid, RSI_GUID_SIZE) ||
	    pkm_lcs_kunit_create_source_expect_string(
		    request, (size_t)count, &offset,
		    script->expected_child_name) ||
	    pkm_lcs_kunit_create_source_expect_string(
		    request, (size_t)count, &offset,
		    script->expected_layer_name) ||
	    offset != (size_t)count)
		return -EINVAL;

	ret = pkm_lcs_kunit_delete_key_ioctl_source_write_status(
		script, request_id, request_op, script->delete_status);
	if (ret)
		return ret;
	*continue_after_delete = script->delete_status == RSI_OK;
	return 0;
}


int pkm_lcs_kunit_delete_key_ioctl_source_handle_lookup(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	struct pkm_lcs_kunit_walk_source_step step = { };
	u8 response[256];
	size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t response_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 child_len;
	int ret;

	count = pkm_lcs_kunit_delete_key_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < child_offset + sizeof(u32))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_LOOKUP ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE,
		   script->expected_parent_guid, RSI_GUID_SIZE))
		return -EINVAL;

	child_len = get_unaligned_le32(request + child_offset);
	child_offset += sizeof(u32);
	if (child_offset > (size_t)count ||
	    child_len > (size_t)count - child_offset ||
	    child_len != strlen(script->expected_child_name) ||
	    memcmp(request + child_offset, script->expected_child_name,
		   child_len))
		return -EINVAL;
	child_offset += child_len;
	if (child_offset != (size_t)count)
		return -EINVAL;

	step.expected_child = script->expected_child_name;
	step.guid = script->remaining_guid ? script->remaining_guid :
					      script->expected_key_guid;
	step.empty = !script->remaining_path_found;
	ret = pkm_lcs_kunit_walk_source_build_response(
		&step, request_id, request_op, 0, response, sizeof(response),
		&response_len);
	if (ret)
		return ret;
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_delete_key_ioctl_source_handle_parent_write(
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script,
	u8 *request, size_t request_len)
{
	size_t offset = RSI_REQUEST_HEADER_SIZE;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 field_mask;
	int ret;

	count = pkm_lcs_kunit_delete_key_ioctl_source_read(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE +
				     sizeof(u32) + sizeof(u64))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_WRITE_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    script->expected_txn_id ||
	    memcmp(request + offset, script->expected_parent_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;
	offset += RSI_GUID_SIZE;

	field_mask = get_unaligned_le32(request + offset);
	if (field_mask != RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)
		return -EINVAL;
	offset += sizeof(u32);
	script->observed_parent_last_write_time =
		get_unaligned_le64(request + offset);
	if (!script->observed_parent_last_write_time)
		return -EINVAL;

	ret = pkm_lcs_kunit_delete_key_ioctl_source_write_status(
		script, request_id, request_op, RSI_OK);
	if (ret)
		return ret;
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_delete_key_ioctl_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_delete_key_ioctl_source_script *script =
		raw_script;
	bool continue_after_delete = false;
	bool has_visible_children = false;
	u8 request[1024];
	int ret;

	if (!script || !script->file || !script->expected_parent_guid ||
	    !script->expected_key_guid || !script->expected_child_name ||
	    !script->expected_layer_name) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret)
			goto out;
	}
	ret = pkm_lcs_kunit_delete_key_ioctl_source_handle_enum(
		script, request, sizeof(request), &has_visible_children);
	if (ret || has_visible_children)
		goto out;
	ret = pkm_lcs_kunit_delete_key_ioctl_source_handle_delete(
		script, request, sizeof(request), &continue_after_delete);
	if (ret || !continue_after_delete)
		goto out;
	if (!script->skip_orphan_lookup) {
		ret = pkm_lcs_kunit_delete_key_ioctl_source_handle_lookup(
			script, request, sizeof(request));
		if (ret)
			goto out;
	}
	ret = pkm_lcs_kunit_delete_key_ioctl_source_handle_parent_write(
		script, request, sizeof(request));
	if (ret)
		goto out;
	if (script->expect_delete_layer) {
		script->delete_layer.file = script->file;
		ret = pkm_lcs_kunit_delete_layer_source_thread(
			&script->delete_layer);
		script->reads += script->delete_layer.reads;
		script->writes += script->delete_layer.writes;
	}

out:
	script->result = ret;
	return ret;
}


ssize_t pkm_lcs_kunit_symlink_follow_read_request(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}


int pkm_lcs_kunit_symlink_follow_write_response(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	const u8 *response, size_t response_len)
{
	ssize_t count;

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_symlink_follow_handle_lookup(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	const struct pkm_lcs_kunit_walk_source_step *step, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 child_len;
	int ret;

	count = pkm_lcs_kunit_symlink_follow_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < child_offset + sizeof(u32))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_LOOKUP)
		return -EINVAL;
	child_len = get_unaligned_le32(request + child_offset);
	child_offset += sizeof(u32);
	if (child_offset > (size_t)count ||
	    child_len > (size_t)count - child_offset ||
	    child_len != strlen(step->expected_child) ||
	    memcmp(request + child_offset, step->expected_child,
		   child_len))
		return -EINVAL;

	ret = pkm_lcs_kunit_walk_source_build_response(
		step, request_id, request_op, script->reads - 1U, response,
		response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_follow_write_response(
		script, response, built_len);
}


int pkm_lcs_kunit_symlink_follow_handle_query(
	struct pkm_lcs_kunit_symlink_follow_source_script *script,
	u8 *request, size_t request_len, u8 *response, size_t response_len)
{
	struct pkm_lcs_kunit_query_values_source_script query = {
		.expected_guid = script->link_step.guid,
		.expected_value_name = "",
		.value_type = script->target_value_type,
		.data = script->target_data,
		.data_len = script->target_data_len,
	};
	size_t value_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	count = pkm_lcs_kunit_symlink_follow_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < value_offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, script->link_step.guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset || value_len)
		return -EINVAL;
	value_offset += value_len;
	if (value_offset >= (size_t)count || request[value_offset])
		return -EINVAL;

	ret = pkm_lcs_kunit_query_values_source_build_response(
		&query, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_follow_write_response(
		script, response, built_len);
}


int pkm_lcs_kunit_symlink_follow_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_symlink_follow_source_script *script = raw_script;
	u8 request[128];
	u8 response[256];
	int ret;

	if (!script || !script->file || !script->link_step.expected_child ||
	    !script->link_step.guid || !script->target_data) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	ret = pkm_lcs_kunit_symlink_follow_handle_lookup(
		script, &script->link_step, request, sizeof(request),
		response, sizeof(response));
	if (ret)
		goto out;
	ret = pkm_lcs_kunit_symlink_follow_handle_query(
		script, request, sizeof(request), response, sizeof(response));
	if (ret || !script->expect_target_lookup)
		goto out;
	ret = pkm_lcs_kunit_symlink_follow_handle_lookup(
		script, &script->target_step, request, sizeof(request),
		response, sizeof(response));

out:
	script->result = ret;
	return ret;
}


ssize_t pkm_lcs_kunit_symlink_sequence_read_request(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	u8 *request, size_t request_len)
{
	ssize_t count;

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, request_len, true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count >= 0)
		script->reads++;
	return count;
}


int pkm_lcs_kunit_symlink_sequence_write_response(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const u8 *response, size_t response_len)
{
	ssize_t count;

	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len)
		return count < 0 ? (int)count : -EIO;
	script->writes++;
	return 0;
}


int pkm_lcs_kunit_symlink_sequence_handle_lookup(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len, u32 index)
{
	const struct pkm_lcs_kunit_walk_source_step *step = op->lookup_step;
	size_t child_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 child_len;
	int ret;

	if (!step || !step->expected_child)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < child_offset + sizeof(u32))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_LOOKUP ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id)
		return -EINVAL;
	child_len = get_unaligned_le32(request + child_offset);
	child_offset += sizeof(u32);
	if (child_offset > (size_t)count ||
	    child_len > (size_t)count - child_offset ||
	    child_len != strlen(step->expected_child) ||
	    memcmp(request + child_offset, step->expected_child, child_len))
		return -EINVAL;

	ret = pkm_lcs_kunit_walk_source_build_response(
		step, request_id, request_op, index, response, response_len,
		&built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}


int pkm_lcs_kunit_symlink_sequence_handle_query(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	struct pkm_lcs_kunit_query_values_source_script query = {
		.expected_guid = op->query_guid,
		.expected_value_name = "",
		.layer_name = op->query_layer_name,
		.value_type = op->query_value_type,
		.data = op->query_data,
		.data_len = op->query_data_len,
		.second_layer_name = op->second_query_layer_name,
		.second_data = op->second_query_data,
		.second_data_len = op->second_query_data_len,
		.second_value_type = op->second_query_value_type,
		.sequence = op->query_sequence,
		.second_sequence = op->second_query_sequence,
		.query_all = op->query_all,
		.include_second_value = op->include_second_query_value,
	};
	size_t value_offset = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	u32 value_len;
	int ret;

	if (!op->query_guid || !op->query_data)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count < value_offset + sizeof(u32) + sizeof(u8))
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_QUERY_VALUES ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, op->query_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	value_len = get_unaligned_le32(request + value_offset);
	value_offset += sizeof(u32);
	if (value_offset > (size_t)count ||
	    value_len > (size_t)count - value_offset || value_len)
		return -EINVAL;
	value_offset += value_len;
	if (value_offset >= (size_t)count ||
	    request[value_offset] != (op->query_all ? 1 : 0))
		return -EINVAL;

	ret = pkm_lcs_kunit_query_values_source_build_response(
		&query, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}


int pkm_lcs_kunit_symlink_sequence_handle_read_key(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	const struct pkm_lcs_kunit_read_key_source_script *read_key =
		op->read_key;
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!read_key || !read_key->expected_guid)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != expected_len)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_READ_KEY ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE, read_key->expected_guid,
		   RSI_GUID_SIZE))
		return -EINVAL;

	ret = pkm_lcs_kunit_read_key_source_build_response(
		read_key, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}


int pkm_lcs_kunit_symlink_sequence_handle_enum_children(
	struct pkm_lcs_kunit_symlink_sequence_source_script *script,
	const struct pkm_lcs_kunit_symlink_sequence_op *op, u8 *request,
	size_t request_len, u8 *response, size_t response_len)
{
	const struct pkm_lcs_kunit_enum_children_source_script *enum_children =
		op->enum_children;
	size_t expected_len = RSI_REQUEST_HEADER_SIZE + RSI_GUID_SIZE;
	size_t built_len = 0;
	ssize_t count;
	u64 request_id;
	u16 request_op;
	int ret;

	if (!enum_children || !enum_children->expected_parent_guid)
		return -EINVAL;

	count = pkm_lcs_kunit_symlink_sequence_read_request(
		script, request, request_len);
	if (count < 0)
		return (int)count;
	if ((size_t)count != expected_len)
		return -EINVAL;

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	request_op = get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET);
	if (request_op != RSI_ENUM_CHILDREN ||
	    get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
		    op->expected_txn_id ||
	    memcmp(request + RSI_REQUEST_HEADER_SIZE,
		   enum_children->expected_parent_guid, RSI_GUID_SIZE))
		return -EINVAL;

	ret = pkm_lcs_kunit_enum_children_source_build_response(
		enum_children, request_id, response, response_len, &built_len);
	if (ret)
		return ret;
	return pkm_lcs_kunit_symlink_sequence_write_response(
		script, response, built_len);
}


int pkm_lcs_kunit_symlink_sequence_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_symlink_sequence_source_script *script =
		raw_script;
	u8 request[128];
	u8 response[1024];
	u32 i;
	int ret = 0;

	if (!script || !script->file || !script->ops || !script->op_count) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (i = 0; i < script->op_count; i++) {
		const struct pkm_lcs_kunit_symlink_sequence_op *op =
			&script->ops[i];

		switch (op->op) {
		case PKM_LCS_KUNIT_SYMLINK_SEQ_LOOKUP:
			ret = pkm_lcs_kunit_symlink_sequence_handle_lookup(
				script, op, request, sizeof(request), response,
				sizeof(response), i);
			break;
		case PKM_LCS_KUNIT_SYMLINK_SEQ_QUERY_DEFAULT:
			ret = pkm_lcs_kunit_symlink_sequence_handle_query(
				script, op, request, sizeof(request), response,
				sizeof(response));
			break;
		case PKM_LCS_KUNIT_SYMLINK_SEQ_READ_KEY:
			ret = pkm_lcs_kunit_symlink_sequence_handle_read_key(
				script, op, request, sizeof(request), response,
				sizeof(response));
			break;
		case PKM_LCS_KUNIT_SYMLINK_SEQ_ENUM_CHILDREN:
			ret = pkm_lcs_kunit_symlink_sequence_handle_enum_children(
				script, op, request, sizeof(request), response,
				sizeof(response));
			break;
		default:
			ret = -EINVAL;
			break;
		}
		if (ret)
			break;
		if (script->reset_limits_after_write &&
		    i == script->reset_limits_after_write_index)
			pkm_lcs_runtime_limits_reset_defaults();
	}

	script->result = ret;
	return ret;
}


int pkm_lcs_kunit_blocking_source_read_thread(void *raw_script)
{
	struct pkm_lcs_kunit_blocking_source_read_script *script = raw_script;

	complete(&script->started);
	script->ret = pkm_lcs_kunit_source_device_read_file(
		script->file, script->buf, script->buf_len, false);
	complete(&script->done);
	return 0;
}


void pkm_lcs_kunit_source_fd_force_closing(
	struct pkm_lcs_source_fd *source_fd)
{
	mutex_lock(&source_fd->queue_lock);
	source_fd->closing = true;
	mutex_unlock(&source_fd->queue_lock);
	wake_up_interruptible(&source_fd->read_wait);
}


int pkm_lcs_kunit_transaction_source_thread(void *data)
{
	struct pkm_lcs_kunit_transaction_source_script *script = data;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[1024];
	size_t response_len;
	ssize_t count;
	u64 request_id;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	for (;;) {
		count = pkm_lcs_kunit_source_device_read_file(
			script->file, request, sizeof(request), true);
		if (count != -EAGAIN)
			break;
		if (kthread_should_stop()) {
			script->result = -EINTR;
			return script->result;
		}
		msleep(1);
	}
	if (count < 0) {
		script->result = (int)count;
		return script->result;
	}
	script->reads++;

	if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64)) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le16(request + RSI_REQUEST_OP_CODE_OFFSET) !=
	    script->expected_op_code) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + RSI_REQUEST_TXN_ID_OFFSET) !=
	    script->expected_header_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}
	if (get_unaligned_le64(request + payload_offset) !=
	    script->expected_payload_txn_id) {
		script->result = -EINVAL;
		return script->result;
	}
	if (script->expected_op_code == RSI_BEGIN_TRANSACTION) {
		if (count < RSI_REQUEST_HEADER_SIZE + (ssize_t)sizeof(u64) +
			    (ssize_t)sizeof(u32)) {
			script->result = -EINVAL;
			return script->result;
		}
		if (get_unaligned_le32(request + payload_offset +
				       sizeof(u64)) != script->expected_mode) {
			script->result = -EINVAL;
			return script->result;
		}
	}
	if (script->reset_runtime_limits_before_response)
		pkm_lcs_runtime_limits_reset_defaults();

	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);
	memset(response, 0, sizeof(response));
	put_unaligned_le32(RSI_MIN_RESPONSE_SIZE,
			   response + RSI_RESPONSE_TOTAL_LEN_OFFSET);
	put_unaligned_le64(request_id, response + RSI_RESPONSE_ID_OFFSET);
	put_unaligned_le16(script->expected_op_code | RSI_RESPONSE_BIT,
			   response + RSI_RESPONSE_OP_CODE_OFFSET);
	put_unaligned_le32(script->status, response + RSI_RESPONSE_STATUS_OFFSET);
	response_len = RSI_MIN_RESPONSE_SIZE;
	count = pkm_lcs_kunit_source_device_write_file(
		script->file, response, response_len, false, NULL);
	if (count != (ssize_t)response_len) {
		script->result = (int)count;
		return script->result;
	}
	script->writes++;
	if (script->delete_key_lookup_after) {
		struct pkm_lcs_kunit_delete_key_ioctl_source_script *lookup =
			script->delete_key_lookup_after;
		u32 lookup_reads = lookup->reads;
		u32 lookup_writes = lookup->writes;

		lookup->file = script->file;
		lookup->expected_txn_id = 0;
		ret = pkm_lcs_kunit_delete_key_ioctl_source_handle_lookup(
			lookup, request, sizeof(request));
		script->reads += lookup->reads - lookup_reads;
		script->writes += lookup->writes - lookup_writes;
		lookup->result = ret;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}
	if (script->hide_key_lookup_after) {
		struct pkm_lcs_kunit_walk_source_script *lookup =
			script->hide_key_lookup_after;
		u32 lookup_reads = lookup->reads;
		u32 lookup_writes = lookup->writes;

		lookup->file = script->file;
		lookup->expected_txn_id = 0;
		ret = pkm_lcs_kunit_walk_source_thread(lookup);
		script->reads += lookup->reads - lookup_reads;
		script->writes += lookup->writes - lookup_writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}
	if (script->expect_layer_refresh) {
		struct pkm_lcs_kunit_layer_metadata_refresh_source_script *refresh =
			script->layer_refresh_after;
		u32 refresh_reads;
		u32 refresh_writes;

		if (!refresh) {
			script->result = -EINVAL;
			return script->result;
		}
		refresh->file = script->file;
		refresh_reads = refresh->reads;
		refresh_writes = refresh->writes;
		ret = pkm_lcs_kunit_layer_metadata_refresh_handle_read_key(
			refresh, request, sizeof(request));
		if (ret)
			goto out_refresh;
		ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
			refresh, request, sizeof(request), "Precedence",
			refresh->precedence_present, refresh->precedence);
		if (ret)
			goto out_refresh;
		ret = pkm_lcs_kunit_layer_metadata_refresh_handle_query(
			refresh, request, sizeof(request), "Enabled",
			refresh->enabled_present, refresh->enabled);
		if (ret)
			goto out_refresh;
		if (pkm_lcs_kunit_layer_metadata_refresh_stops_after_enabled(
			    refresh))
			goto out_refresh;
		ret = pkm_lcs_kunit_layer_metadata_refresh_handle_owner_query(
			refresh, request, sizeof(request));

out_refresh:
		script->reads += refresh->reads - refresh_reads;
		script->writes += refresh->writes - refresh_writes;
		refresh->result = ret;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}
	if (script->expect_delete_layer) {
		struct pkm_lcs_kunit_delete_layer_source_script *delete_layer =
			script->delete_layer_after;
		u32 delete_reads;
		u32 delete_writes;

		if (!delete_layer) {
			script->result = -EINVAL;
			return script->result;
		}
		delete_layer->file = script->file;
		delete_reads = delete_layer->reads;
		delete_writes = delete_layer->writes;
		ret = pkm_lcs_kunit_delete_layer_source_thread(delete_layer);
		script->reads += delete_layer->reads - delete_reads;
		script->writes += delete_layer->writes - delete_writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}
	script->result = 0;
	return 0;
}


int pkm_lcs_kunit_txn_create_flow_source_thread(void *raw_script)
{
	struct pkm_lcs_kunit_txn_create_flow_source_script *script =
		raw_script;
	int ret;

	if (!script || !script->file) {
		if (script)
			script->result = -EINVAL;
		return -EINVAL;
	}

	script->walk.file = script->file;
	ret = pkm_lcs_kunit_walk_source_thread(&script->walk);
	script->reads = script->walk.reads;
	script->writes = script->walk.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	script->read_key.file = script->file;
	ret = pkm_lcs_kunit_read_key_source_thread(&script->read_key);
	script->reads += script->read_key.reads;
	script->writes += script->read_key.writes;
	if (ret) {
		script->result = ret;
		return ret;
	}

	if (script->expect_begin) {
		script->begin.file = script->file;
		ret = pkm_lcs_kunit_transaction_source_thread(&script->begin);
		script->reads += script->begin.reads;
		script->writes += script->begin.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	if (script->expect_create) {
		script->create.file = script->file;
		ret = pkm_lcs_kunit_create_source_thread(&script->create);
		script->reads += script->create.reads;
		script->writes += script->create.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	if (script->expect_retry_walk) {
		script->retry_walk.file = script->file;
		ret = pkm_lcs_kunit_walk_source_thread(&script->retry_walk);
		script->reads += script->retry_walk.reads;
		script->writes += script->retry_walk.writes;
		if (ret) {
			script->result = ret;
			return ret;
		}
	}

	script->result = 0;
	return 0;
}


void pkm_lcs_kunit_run_transaction_source_round_trip(
	struct kunit *test,
	struct pkm_lcs_kunit_transaction_source_script *script,
	long (*round_trip)(u32 source_id, u64 transaction_id,
			   struct pkm_lcs_source_response_result *response,
			   struct pkm_lcs_source_enqueue_result *enqueue),
	u64 transaction_id, long expected_ret,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	struct task_struct *task;
	int thread_ret;
	long ret;

	task = pkm_lcs_kunit_kthread_run(pkm_lcs_kunit_transaction_source_thread, script,
			   "pkm-lcs-kunit-txn-src");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));

	ret = round_trip(1, transaction_id, response, enqueue);
	thread_ret = pkm_lcs_kunit_kthread_stop(task);

	KUNIT_EXPECT_EQ(test, ret, expected_ret);
	KUNIT_EXPECT_EQ(test, thread_ret, 0);
	KUNIT_EXPECT_EQ(test, script->result, 0);
	KUNIT_EXPECT_EQ(test, script->reads, 1U);
	KUNIT_EXPECT_EQ(test, script->writes, 1U);
}


long pkm_lcs_kunit_commit_round_trip_default(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_commit_transaction_round_trip(
		source_id, transaction_id, response, enqueue);
}


long pkm_lcs_kunit_begin_readwrite_round_trip_default(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_begin_transaction_round_trip(
		source_id, transaction_id, RSI_TXN_READ_WRITE, response,
		enqueue);
}


long pkm_lcs_kunit_abort_round_trip_default(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	return pkm_lcs_source_abort_transaction_round_trip(
		source_id, transaction_id, response, enqueue);
}


void pkm_lcs_kunit_append_one_create_log(struct kunit *test, int fd,
						const u8 root_guid[16],
						u64 sequence)
{
	static const u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xa1
	};
	static const u8 child_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xa2
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0xa0 },
		{ 0xa1 },
	};
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_key_create_log_input input = {
		.parent_guid = parent_guid,
		.target_guid = child_guid,
		.child_name = "LateCommit",
		.child_name_len = 10,
		.layer = "base",
		.layer_len = 4,
		.parent_path = parent_path,
		.parent_ancestor_guids = parent_ancestors,
		.parent_depth = 2,
		.sequence = sequence,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_key_create_mutation(
				fd, 1, root_guid, &input, &handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
				pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
}


void pkm_lcs_kunit_append_set_value_log_for_layer(
	struct kunit *test, int fd, const u8 root_guid[16],
	const char *layer, u64 sequence)
{
	static const u8 key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		0xb8
	};
	static const char * const path[] = { "Machine", "LayerAbort" };
	static const u8 ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 1 },
		{ 0xb8 },
	};
	struct pkm_lcs_transaction_mutation_handle handle = { };
	struct pkm_lcs_transaction_set_value_log_input input = {
		.key_guid = key_guid,
		.value_name = "Value",
		.value_name_len = 5,
		.layer = layer,
		.layer_len = strlen(layer),
		.path = path,
		.ancestor_guids = ancestors,
		.depth = 2,
		.sequence = sequence,
	};
	struct pkm_lcs_transaction_binding_plan binding = { };

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_begin_set_value_mutation(
				fd, 1, root_guid, &input, &handle, &binding),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_commit_mutation(&handle), 0L);
}


void pkm_lcs_kunit_commit_timeout_late_response(
	struct kunit *test, u32 status)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 request_id;
	size_t response_len;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);

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
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xa5);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout((int)fd,
								    1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_EXPECT_FALSE(test, txn_snapshot.timer_pending);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.queued_request_count, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.in_flight_request_count, 1U);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, out, sizeof(out), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	request_id = get_unaligned_le64(out + RSI_REQUEST_ID_OFFSET);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			txn_snapshot.transaction_id);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    status, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id,
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response_result.status, status);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	if (status == RSI_OK)
		KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	else
		KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	KUNIT_EXPECT_EQ(test, txn_snapshot.state, REG_TXN_TIMED_OUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)fd, &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
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


void pkm_lcs_kunit_commit_timeout_late_create_watch(
	struct kunit *test, u32 status, bool expect_event)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	static const char * const parent_path[] = { "Machine", "Software" };
	static const u8 parent_ancestors[2][PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		{ 0xa0 },
		{ 0xa1 },
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	struct reg_notify_args notify = {
		.filter = REG_NOTIFY_SUBKEY,
	};
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 request[64];
	u8 event[32] = { };
	struct file file = { };
	const void *token;
	u64 request_id;
	size_t response_len;
	u32 count = 0;
	long watch_fd;
	long txn_fd;

	pkm_lcs_kunit_flush_deferred_key_fd_release();
	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	watch_fd = pkm_lcs_kunit_publish_key_fd_from_path(
		1, KEY_NOTIFY, parent_path, parent_ancestors,
		ARRAY_SIZE(parent_ancestors));
	KUNIT_ASSERT_TRUE(test, watch_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_key_fd_notify((int)watch_fd, &notify),
			0L);

	txn_fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, txn_fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)txn_fd,
							&txn_snapshot),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)txn_fd, txn_snapshot.transaction_id, 1,
				root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)txn_fd, root_guid,
					    0xa7);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_key_fd_read((int)watch_fd, event,
						  sizeof(event), true),
			(ssize_t)-EAGAIN);

	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_commit_timeout(
				(int)txn_fd, 1),
			(long)-ETIMEDOUT);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_device_read_file(
				&file, request, sizeof(request), true),
			(ssize_t)(RSI_REQUEST_HEADER_SIZE + sizeof(u64)));
	request_id = get_unaligned_le64(request + RSI_REQUEST_ID_OFFSET);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    status, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id,
			txn_snapshot.transaction_id);
	KUNIT_EXPECT_EQ(test, response_result.request_op_code,
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test, response_result.status, status);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);

	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_log_snapshot((int)txn_fd,
							    &log),
			0L);
	KUNIT_EXPECT_EQ(test, log.entry_count, 0U);
	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.state, PKM_LCS_SOURCE_FD_ACTIVE);

	if (expect_event) {
		KUNIT_ASSERT_EQ(test,
				pkm_lcs_kunit_key_fd_read((int)watch_fd,
							  event,
							  sizeof(event),
							  true),
				(ssize_t)18);
		KUNIT_EXPECT_EQ(test, get_unaligned_le32(event), 18U);
		KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 4),
				REG_WATCH_SUBKEY_CREATED);
		KUNIT_EXPECT_EQ(test, get_unaligned_le16(event + 6), 10U);
		KUNIT_EXPECT_EQ(test, memcmp(event + 8, "LateCommit", 10), 0);
	} else {
		KUNIT_EXPECT_EQ(test,
				pkm_lcs_kunit_key_fd_read((int)watch_fd,
							  event,
							  sizeof(event),
							  true),
				(ssize_t)-EAGAIN);
	}

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)txn_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)watch_fd), 0);
	KUNIT_EXPECT_EQ(test, pkm_lcs_source_device_release_file(&file), 0);
	pkm_lcs_kunit_reset_source_table();
	kacs_rust_token_drop(token);
}


void pkm_lcs_kunit_commit_timeout_closed_fd_late_response(
	struct kunit *test, u32 status)
{
	static const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES] = {
		1
	};
	struct pkm_lcs_transaction_mutation_log_snapshot log = { };
	struct pkm_lcs_transaction_fd_snapshot txn_snapshot = { };
	struct pkm_lcs_source_response_result response_result = { };
	struct pkm_lcs_source_fd_snapshot source_snapshot = { };
	u8 response[RSI_MIN_RESPONSE_SIZE];
	u8 out[64];
	struct file file = { };
	const void *token;
	u64 generation_before = 0;
	u64 generation_after = 0;
	u64 transaction_id;
	u64 request_id;
	size_t response_len;
	size_t payload_offset = RSI_REQUEST_HEADER_SIZE;
	u32 count = 0;
	long fd;

	pkm_lcs_kunit_setup_registered_source(test, &file, &token);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_before),
			0L);

	fd = pkm_lcs_reg_begin_transaction();
	KUNIT_ASSERT_TRUE(test, fd >= 0);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_snapshot((int)fd,
							&txn_snapshot),
			0L);
	transaction_id = txn_snapshot.transaction_id;
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_source_bound_transaction_acquire(1, &count),
			0L);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_transaction_fd_complete_first_bind(
				(int)fd, transaction_id, 1, root_guid),
			0L);
	pkm_lcs_kunit_append_one_create_log(test, (int)fd, root_guid, 0xb5);

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
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le16(out + RSI_REQUEST_OP_CODE_OFFSET),
			(u16)RSI_COMMIT_TRANSACTION);
	KUNIT_EXPECT_EQ(test,
			get_unaligned_le64(out + RSI_REQUEST_TXN_ID_OFFSET),
			transaction_id);
	KUNIT_EXPECT_EQ(test, get_unaligned_le64(out + payload_offset),
			transaction_id);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			1U);

	pkm_lcs_kunit_build_status_response(test, response, sizeof(response),
					    request_id, RSI_COMMIT_TRANSACTION,
					    status, &response_len);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_source_device_write_file(
				&file, response, response_len, false,
				&response_result),
			(ssize_t)response_len);
	KUNIT_EXPECT_EQ(test, response_result.request_id, request_id);
	KUNIT_EXPECT_EQ(test, response_result.txn_id, transaction_id);
	KUNIT_EXPECT_FALSE(test, response_result.caller_waiter_attached);
	KUNIT_EXPECT_EQ(test, response_result.in_flight_count, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_lcs_kunit_transaction_fd_retained_commit_count(),
			0U);
	KUNIT_ASSERT_EQ(test,
			pkm_lcs_kunit_source_hive_generation_snapshot(
				1, root_guid, &generation_after),
			0L);
	if (status == RSI_OK)
		KUNIT_EXPECT_EQ(test, generation_after, generation_before + 1);
	else
		KUNIT_EXPECT_EQ(test, generation_after, generation_before);

	pkm_lcs_kunit_source_fd_snapshot(&file, &source_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.state,
			PKM_LCS_SOURCE_FD_ACTIVE);
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


void pkm_lcs_kunit_create_missing_set_child_path(
	struct kunit *test, struct pkm_lcs_create_missing_parent_resolution *res)
{
	static const u8 root_guid[RSI_GUID_SIZE] = { 1 };
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x22 };

	KUNIT_ASSERT_NOT_NULL(test, res);

	res->parent.resolved_path = kcalloc(2, sizeof(*res->parent.resolved_path),
					   GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path);
	res->parent.ancestor_guids = kcalloc(2, sizeof(*res->parent.ancestor_guids),
					     GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.ancestor_guids);
	res->parent.resolved_path[0] = kstrdup("Machine", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path[0]);
	res->parent.resolved_path[1] = kstrdup("Software", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path[1]);
	res->child_name = kstrdup("App", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->child_name);

	res->parent.source_id = 1;
	res->parent.component_count = 2;
	memcpy(res->parent.key_guid, parent_guid, sizeof(res->parent.key_guid));
	memcpy(res->parent.ancestor_guids[0], root_guid, RSI_GUID_SIZE);
	memcpy(res->parent.ancestor_guids[1], parent_guid, RSI_GUID_SIZE);
	res->child_name_len = 3;
	res->child_depth = 3;
}


void pkm_lcs_kunit_create_missing_set_layer_metadata_child_path(
	struct kunit *test, struct pkm_lcs_create_missing_parent_resolution *res)
{
	static const char * const components[] = {
		"Machine", "System", "Registry", "Layers"
	};
	static const u8 ancestor_guids[ARRAY_SIZE(components)][RSI_GUID_SIZE] = {
		{ 1 },
		{ 0xa8, 0x11 },
		{ 0xa8, 0x12 },
		{ 0xa8, 0x13 },
	};
	u32 i;

	KUNIT_ASSERT_NOT_NULL(test, res);

	res->parent.resolved_path =
		kcalloc(ARRAY_SIZE(components),
			sizeof(*res->parent.resolved_path), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path);
	res->parent.ancestor_guids =
		kcalloc(ARRAY_SIZE(components),
			sizeof(*res->parent.ancestor_guids), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->parent.ancestor_guids);

	for (i = 0; i < ARRAY_SIZE(components); i++) {
		res->parent.resolved_path[i] =
			kstrdup(components[i], GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, res->parent.resolved_path[i]);
		memcpy(res->parent.ancestor_guids[i], ancestor_guids[i],
		       RSI_GUID_SIZE);
	}
	res->child_name = kstrdup("Policy", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, res->child_name);

	res->parent.source_id = 1;
	res->parent.component_count = ARRAY_SIZE(components);
	memcpy(res->parent.key_guid, ancestor_guids[ARRAY_SIZE(components) - 1],
	       sizeof(res->parent.key_guid));
	res->child_name_len = strlen("Policy");
	res->child_depth = ARRAY_SIZE(components) + 1;
}


long pkm_lcs_kunit_dispatch_status_only_waitable_request(
	u16 op_code, struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *enqueue)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0xa1 };
	static const u8 child_guid[RSI_GUID_SIZE] = { 0xa2 };
	static const u8 key_guid[RSI_GUID_SIZE] = { 0xa3 };
	static const u8 sd[] = {
		0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00,
		0x11, 0x22, 0x33, 0x44,
	};

	switch (op_code) {
	case RSI_CREATE_ENTRY:
		return pkm_lcs_source_dispatch_create_entry_waitable_request(
			1, 0x0102030405060708ULL, parent_guid, "Child",
			strlen("Child"), "base", strlen("base"), child_guid,
			0x1112131415161718ULL, waiter, enqueue);
	case RSI_HIDE_ENTRY:
		return pkm_lcs_source_dispatch_hide_entry_waitable_request(
			1, 0x1213141516171819ULL, parent_guid, "Child",
			strlen("Child"), "base", strlen("base"),
			0x1a1b1c1d1e1f2021ULL, waiter, enqueue);
	case RSI_DELETE_ENTRY:
		return pkm_lcs_source_dispatch_delete_entry_waitable_request(
			1, 0x2223242526272829ULL, parent_guid, "Child",
			strlen("Child"), "base", strlen("base"), waiter,
			enqueue);
	case RSI_CREATE_KEY:
		return pkm_lcs_source_dispatch_create_key_waitable_request(
			1, 0x2122232425262728ULL, key_guid, "Child",
			strlen("Child"), parent_guid, sd, sizeof(sd), false,
			false, waiter, enqueue);
	case RSI_WRITE_KEY:
		return pkm_lcs_source_dispatch_write_key_waitable_request(
			1, 0x3132333435363738ULL, key_guid, sd, sizeof(sd),
			0x4142434445464748ULL, waiter, enqueue);
	case RSI_DROP_KEY:
		return pkm_lcs_source_dispatch_drop_key_waitable_request(
			1, 0x494a4b4c4d4e4f50ULL, key_guid, waiter, enqueue);
	case RSI_SET_VALUE:
		return pkm_lcs_source_dispatch_set_value_waitable_request(
			1, 0x5152535455565758ULL, key_guid, "Value",
			strlen("Value"), "base", strlen("base"), REG_BINARY,
			sd, sizeof(sd), 0x595a5b5c5d5e5f60ULL, 0, waiter,
			enqueue);
	case RSI_DELETE_VALUE_ENTRY:
		return pkm_lcs_source_dispatch_delete_value_entry_waitable_request(
			1, 0x6162636465666768ULL, key_guid, "Value",
			strlen("Value"), "base", strlen("base"), waiter,
			enqueue);
	case RSI_SET_BLANKET_TOMBSTONE:
		return pkm_lcs_source_dispatch_set_blanket_tombstone_waitable_request(
			1, 0x696a6b6c6d6e6f70ULL, key_guid, "base",
			strlen("base"), true, 0x7172737475767778ULL, waiter,
			enqueue);
	case RSI_BEGIN_TRANSACTION:
		return pkm_lcs_source_dispatch_begin_transaction_waitable_request(
			1, 0x5152535455565758ULL, RSI_TXN_READ_WRITE, waiter,
			enqueue);
	case RSI_COMMIT_TRANSACTION:
		return pkm_lcs_source_dispatch_commit_transaction_waitable_request(
			1, 0x6162636465666768ULL, waiter, enqueue);
	case RSI_ABORT_TRANSACTION:
		return pkm_lcs_source_dispatch_abort_transaction_waitable_request(
			1, 0x7172737475767778ULL, waiter, enqueue);
	case RSI_FLUSH:
		return pkm_lcs_source_dispatch_flush_waitable_request(
			1, "Machine", strlen("Machine"), waiter, enqueue);
	default:
		return -EINVAL;
	}
}


void pkm_lcs_kunit_fill_name(char *name, size_t len, char value)
{
	memset(name, value, len);
	name[len] = '\0';
}


void pkm_lcs_kunit_expect_source_validation_audit(
	struct kunit *test, const char *validation_class,
	const u8 key_guid[RSI_GUID_SIZE])
{
	static const char event_type[] = "LCS_SOURCE_VALIDATION_FAILURE";
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	u8 buffer[512];
	size_t written = 0;
	u32 header_size;
	u16 type_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_latest_matching_event(
				KMES_ORIGIN_LCS, event_type,
				sizeof(event_type) - 1, buffer, sizeof(buffer),
				&written, &kmes_snapshot),
			0);
	type_len = get_unaligned_le16(buffer + KMES_EVENT_TYPE_LEN_OFFSET);
	header_size = get_unaligned_le32(buffer + KMES_EVENT_HEADER_SIZE_OFFSET);
	KUNIT_ASSERT_EQ(test, type_len, (u16)(sizeof(event_type) - 1));
	KUNIT_EXPECT_EQ(test, buffer[KMES_EVENT_ORIGIN_CLASS_OFFSET],
			(u8)KMES_ORIGIN_LCS);
	KUNIT_EXPECT_EQ(test,
			memcmp(buffer + KMES_EVENT_HEADER_BASE_SIZE, event_type,
			       type_len),
			0);
	KUNIT_ASSERT_TRUE(test, written > header_size);
	KUNIT_EXPECT_TRUE(test,
			  pkm_lcs_kunit_buffer_contains(buffer, written,
							validation_class));
	if (key_guid) {
		KUNIT_EXPECT_TRUE(
			test, pkm_lcs_kunit_buffer_contains_bytes(
				      buffer, written, key_guid, RSI_GUID_SIZE));
	}
}


void pkm_lcs_kunit_poll_capture_queue(
	struct file *file, wait_queue_head_t *wait_address,
	struct poll_table_struct *table)
{
	struct pkm_lcs_kunit_poll_capture *capture =
		container_of(table, struct pkm_lcs_kunit_poll_capture, table);

	capture->file = file;
	capture->wait_address = wait_address;
	capture->calls++;
}


int pkm_lcs_kunit_slot_wait_round_trip_thread(void *raw_script)
{
	static const u8 parent_guid[RSI_GUID_SIZE] = { 0x81 };
	struct pkm_lcs_kunit_slot_wait_round_trip_script *script = raw_script;

	complete(&script->started);
	script->ret = pkm_lcs_source_lookup_round_trip_timeout(
		1, 0xf1f2f3f4f5f6f7f8ULL, parent_guid, "Blocked",
		strlen("Blocked"), 1000, &script->response, &script->enqueue);
	complete(&script->done);
	return 0;
}
