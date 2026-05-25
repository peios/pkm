/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace-cleanliness smoke test for the PKM UAPI headers.
 *
 * This compiles with an ordinary, non-kernel C compiler — the precondition
 * for the cgo -godefs binding generator and for any userspace consumer of
 * the PKM ABI. It is built by check-userspace-clean.sh.
 */
#include <stddef.h>

#include <pkm/pkm.h>

#define ASSERT_STRUCT_SIZE(type, expected) \
	_Static_assert(sizeof(struct type) == (expected), \
		       #type " size disagrees with its header constant")

#define ASSERT_FIELD_OFFSET(type, field, expected) \
	_Static_assert(offsetof(struct type, field) == (expected), \
		       #type "." #field " offset disagrees with PSD-005")

#define ASSERT_IOCTL_ENCODING(command, expected_nr, expected_dir, expected_size) \
	_Static_assert(_IOC_TYPE(command) == REG_IOC_TYPE, \
		       #command " type disagrees with PSD-005"); \
	_Static_assert(_IOC_NR(command) == (expected_nr), \
		       #command " number disagrees with PSD-005"); \
	_Static_assert(_IOC_DIR(command) == (expected_dir), \
		       #command " direction disagrees with PSD-005"); \
	_Static_assert(_IOC_SIZE(command) == (expected_size), \
		       #command " size disagrees with PSD-005")

/* The headers must be internally consistent: each declared size constant
 * must agree with the layout of the struct it describes. */
_Static_assert(sizeof(struct kacs_access_check_args)
		       == KACS_ACCESS_CHECK_ARGS_SIZE,
	       "kacs_access_check_args size disagrees with its header constant");
_Static_assert(sizeof(struct kacs_object_type_entry)
		       == KACS_OBJECT_TYPE_ENTRY_SIZE,
	       "kacs_object_type_entry size disagrees with its header constant");
/* The KMES event header is offset-defined, not a struct: its field offsets
 * must be contiguous and the base size must be one past the last field. */
_Static_assert(KMES_EVENT_HEADER_SIZE_OFFSET
		       == KMES_EVENT_SIZE_OFFSET + sizeof(__u32),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_TIMESTAMP_NS_OFFSET
		       == KMES_EVENT_HEADER_SIZE_OFFSET + sizeof(__u32),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_SEQUENCE_OFFSET
		       == KMES_EVENT_TIMESTAMP_NS_OFFSET + sizeof(__u64),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_CPU_ID_OFFSET
		       == KMES_EVENT_SEQUENCE_OFFSET + sizeof(__u64),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_ORIGIN_CLASS_OFFSET
		       == KMES_EVENT_CPU_ID_OFFSET + sizeof(__u16),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET
		       == KMES_EVENT_ORIGIN_CLASS_OFFSET + sizeof(__u8),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_TRUE_TOKEN_GUID_OFFSET
		       == KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET + KMES_EVENT_GUID_SIZE,
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_PROCESS_GUID_OFFSET
		       == KMES_EVENT_TRUE_TOKEN_GUID_OFFSET + KMES_EVENT_GUID_SIZE,
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_TYPE_LEN_OFFSET
		       == KMES_EVENT_PROCESS_GUID_OFFSET + KMES_EVENT_GUID_SIZE,
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_HEADER_BASE_SIZE
		       == KMES_EVENT_TYPE_LEN_OFFSET + sizeof(__u16),
	       "KMES event-header base size disagrees with its field offsets");
_Static_assert(sizeof(struct kmes_emit_entry) == 32,
	       "kmes_emit_entry must be 32 bytes");
_Static_assert(RSI_REQUEST_ID_OFFSET
		       == RSI_REQUEST_TOTAL_LEN_OFFSET + sizeof(__u32),
	       "RSI request-header offsets are not contiguous");
_Static_assert(RSI_REQUEST_OP_CODE_OFFSET
		       == RSI_REQUEST_ID_OFFSET + sizeof(__u64),
	       "RSI request-header offsets are not contiguous");
_Static_assert(RSI_REQUEST_TXN_ID_OFFSET
		       == RSI_REQUEST_OP_CODE_OFFSET + sizeof(__u16),
	       "RSI request-header offsets are not contiguous");
_Static_assert(RSI_REQUEST_HEADER_SIZE
		       == RSI_REQUEST_TXN_ID_OFFSET + sizeof(__u64),
	       "RSI request-header size disagrees with PSD-005");
_Static_assert(RSI_RESPONSE_ID_OFFSET
		       == RSI_RESPONSE_TOTAL_LEN_OFFSET + sizeof(__u32),
	       "RSI response-header offsets are not contiguous");
_Static_assert(RSI_RESPONSE_OP_CODE_OFFSET
		       == RSI_RESPONSE_ID_OFFSET + sizeof(__u64),
	       "RSI response-header offsets are not contiguous");
_Static_assert(RSI_RESPONSE_HEADER_SIZE
		       == RSI_RESPONSE_OP_CODE_OFFSET + sizeof(__u16),
	       "RSI response-header size disagrees with PSD-005");
_Static_assert(RSI_RESPONSE_STATUS_OFFSET == RSI_RESPONSE_HEADER_SIZE,
	       "RSI response status must be first payload field");
_Static_assert(RSI_MIN_RESPONSE_SIZE
		       == RSI_RESPONSE_STATUS_OFFSET + RSI_STATUS_SIZE,
	       "RSI minimum response size disagrees with PSD-005");
_Static_assert(RSI_LENGTH_PREFIX_SIZE == sizeof(__u32),
	       "RSI length-prefixed fields use uint32 lengths");
_Static_assert(RSI_GUID_SIZE == 16,
	       "RSI GUID fields must be 16 raw bytes");
_Static_assert(RSI_LOOKUP_RESPONSE == (RSI_LOOKUP | RSI_RESPONSE_BIT),
	       "RSI response op-code high bit disagrees with PSD-005");
_Static_assert(RSI_PATH_TARGET_GUID == 0 && RSI_PATH_TARGET_HIDDEN == 1,
	       "RSI path target codes disagree with PSD-005");
_Static_assert(RSI_WRITE_KEY_FIELD_KNOWN_MASK
		       == (RSI_WRITE_KEY_FIELD_SD
			   | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME),
	       "RSI_WRITE_KEY field mask disagrees with PSD-005");
_Static_assert(REG_WATCH_EVENT_TYPE_OFFSET
		       == REG_WATCH_EVENT_TOTAL_LEN_OFFSET + sizeof(__u32),
	       "watch event offsets are not contiguous");
_Static_assert(REG_WATCH_EVENT_NAME_LEN_OFFSET
		       == REG_WATCH_EVENT_TYPE_OFFSET + sizeof(__u16),
	       "watch event offsets are not contiguous");
_Static_assert(REG_WATCH_EVENT_NAME_OFFSET
		       == REG_WATCH_EVENT_NAME_LEN_OFFSET + sizeof(__u16),
	       "watch event offsets are not contiguous");
_Static_assert(REG_WATCH_EVENT_MIN_SIZE == REG_WATCH_EVENT_NAME_OFFSET,
	       "watch event minimum size disagrees with PSD-005");
_Static_assert(REG_WATCH_SUBTREE_PATH_DEPTH_SIZE == sizeof(__u16),
	       "watch subtree path_depth size disagrees with PSD-005");
_Static_assert(REG_WATCH_SUBTREE_PATH_COMPONENTS_REL_OFFSET
		       == REG_WATCH_SUBTREE_PATH_DEPTH_REL_OFFSET
				  + REG_WATCH_SUBTREE_PATH_DEPTH_SIZE,
	       "watch subtree extension offsets are not contiguous");
_Static_assert(REG_WATCH_PATH_COMPONENT_LEN_SIZE == sizeof(__u16),
	       "watch subtree component length size disagrees with PSD-005");

ASSERT_STRUCT_SIZE(reg_create_key_args, REG_CREATE_KEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_create_key_args, parent_fd, 0);
ASSERT_FIELD_OFFSET(reg_create_key_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_create_key_args, path_ptr, 8);
ASSERT_FIELD_OFFSET(reg_create_key_args, desired_access, 16);
ASSERT_FIELD_OFFSET(reg_create_key_args, flags, 20);
ASSERT_FIELD_OFFSET(reg_create_key_args, layer_ptr, 24);
ASSERT_FIELD_OFFSET(reg_create_key_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_create_key_args, _pad1, 36);
ASSERT_FIELD_OFFSET(reg_create_key_args, disposition_ptr, 40);

ASSERT_STRUCT_SIZE(reg_query_value_args, REG_QUERY_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_query_value_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_query_value_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_query_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_query_value_args, type, 16);
ASSERT_FIELD_OFFSET(reg_query_value_args, data_len, 20);
ASSERT_FIELD_OFFSET(reg_query_value_args, txn_fd, 24);
ASSERT_FIELD_OFFSET(reg_query_value_args, layer_buf_len, 28);
ASSERT_FIELD_OFFSET(reg_query_value_args, data_ptr, 32);
ASSERT_FIELD_OFFSET(reg_query_value_args, sequence, 40);
ASSERT_FIELD_OFFSET(reg_query_value_args, layer_len, 48);
ASSERT_FIELD_OFFSET(reg_query_value_args, _pad1, 52);
ASSERT_FIELD_OFFSET(reg_query_value_args, layer_ptr, 56);

ASSERT_STRUCT_SIZE(reg_set_value_args, REG_SET_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_set_value_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_set_value_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_set_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_set_value_args, type, 16);
ASSERT_FIELD_OFFSET(reg_set_value_args, data_len, 20);
ASSERT_FIELD_OFFSET(reg_set_value_args, data_ptr, 24);
ASSERT_FIELD_OFFSET(reg_set_value_args, layer_len, 32);
ASSERT_FIELD_OFFSET(reg_set_value_args, _pad1, 36);
ASSERT_FIELD_OFFSET(reg_set_value_args, layer_ptr, 40);
ASSERT_FIELD_OFFSET(reg_set_value_args, txn_fd, 48);
ASSERT_FIELD_OFFSET(reg_set_value_args, _pad2, 52);
ASSERT_FIELD_OFFSET(reg_set_value_args, expected_seq, 56);

ASSERT_STRUCT_SIZE(reg_delete_value_args, REG_DELETE_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_delete_value_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_delete_value_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_delete_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_delete_value_args, layer_len, 16);
ASSERT_FIELD_OFFSET(reg_delete_value_args, _pad1, 20);
ASSERT_FIELD_OFFSET(reg_delete_value_args, layer_ptr, 24);
ASSERT_FIELD_OFFSET(reg_delete_value_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_delete_value_args, _pad2, 36);

ASSERT_STRUCT_SIZE(reg_blanket_tombstone_args,
		   REG_BLANKET_TOMBSTONE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, layer_len, 0);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, layer_ptr, 8);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, set, 16);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, _pad1, 17);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, txn_fd, 20);

ASSERT_STRUCT_SIZE(reg_query_values_batch_args,
		   REG_QUERY_VALUES_BATCH_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, buf_len, 0);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, count, 4);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, buf_ptr, 8);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, _pad, 20);

ASSERT_STRUCT_SIZE(reg_enum_value_args, REG_ENUM_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_enum_value_args, index, 0);
ASSERT_FIELD_OFFSET(reg_enum_value_args, name_len, 4);
ASSERT_FIELD_OFFSET(reg_enum_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_enum_value_args, type, 16);
ASSERT_FIELD_OFFSET(reg_enum_value_args, data_len, 20);
ASSERT_FIELD_OFFSET(reg_enum_value_args, data_ptr, 24);
ASSERT_FIELD_OFFSET(reg_enum_value_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_enum_value_args, _pad, 36);

ASSERT_STRUCT_SIZE(reg_enum_subkey_args, REG_ENUM_SUBKEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, index, 0);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, name_len, 4);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, last_write_time, 16);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, subkey_count, 24);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, value_count, 28);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, _pad, 36);

ASSERT_STRUCT_SIZE(reg_query_key_info_args, REG_QUERY_KEY_INFO_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, last_write_time, 16);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, subkey_count, 24);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, value_count, 28);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, max_subkey_name_len, 32);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, max_value_name_len, 36);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, max_value_data_size, 40);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, sd_size, 44);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, volatile_key, 48);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, symlink, 49);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, _pad1, 50);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, hive_generation, 56);

ASSERT_STRUCT_SIZE(reg_delete_key_args, REG_DELETE_KEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_delete_key_args, layer_len, 0);
ASSERT_FIELD_OFFSET(reg_delete_key_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_delete_key_args, layer_ptr, 8);
ASSERT_FIELD_OFFSET(reg_delete_key_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_delete_key_args, _pad1, 20);

ASSERT_STRUCT_SIZE(reg_hide_key_args, REG_HIDE_KEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_hide_key_args, layer_len, 0);
ASSERT_FIELD_OFFSET(reg_hide_key_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_hide_key_args, layer_ptr, 8);
ASSERT_FIELD_OFFSET(reg_hide_key_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_hide_key_args, _pad1, 20);

ASSERT_STRUCT_SIZE(reg_get_security_args, REG_GET_SECURITY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_get_security_args, security_info, 0);
ASSERT_FIELD_OFFSET(reg_get_security_args, sd_len, 4);
ASSERT_FIELD_OFFSET(reg_get_security_args, sd_ptr, 8);

ASSERT_STRUCT_SIZE(reg_set_security_args, REG_SET_SECURITY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_set_security_args, security_info, 0);
ASSERT_FIELD_OFFSET(reg_set_security_args, sd_len, 4);
ASSERT_FIELD_OFFSET(reg_set_security_args, sd_ptr, 8);
ASSERT_FIELD_OFFSET(reg_set_security_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_set_security_args, _pad, 20);

ASSERT_STRUCT_SIZE(reg_notify_args, REG_NOTIFY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_notify_args, filter, 0);
ASSERT_FIELD_OFFSET(reg_notify_args, subtree, 4);
ASSERT_FIELD_OFFSET(reg_notify_args, _pad, 5);

ASSERT_STRUCT_SIZE(reg_backup_args, REG_BACKUP_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_backup_args, output_fd, 0);

ASSERT_STRUCT_SIZE(reg_restore_args, REG_RESTORE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_restore_args, input_fd, 0);

ASSERT_STRUCT_SIZE(reg_txn_status_args, REG_TXN_STATUS_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_txn_status_args, state, 0);
ASSERT_FIELD_OFFSET(reg_txn_status_args, terminal_errno, 4);

ASSERT_STRUCT_SIZE(reg_src_register_args, REG_SRC_REGISTER_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_src_register_args, hive_count, 0);
ASSERT_FIELD_OFFSET(reg_src_register_args, _pad, 4);
ASSERT_FIELD_OFFSET(reg_src_register_args, max_sequence, 8);
ASSERT_FIELD_OFFSET(reg_src_register_args, hives_ptr, 16);

ASSERT_STRUCT_SIZE(reg_src_hive_entry, REG_SRC_HIVE_ENTRY_SIZE);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, name_len, 0);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, root_guid, 16);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, flags, 32);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, _pad1, 36);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, scope_guid, 40);

ASSERT_IOCTL_ENCODING(REG_SRC_REGISTER, REG_SRC_REGISTER_NR, _IOC_WRITE,
		      REG_SRC_REGISTER_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_QUERY_VALUE, REG_IOC_QUERY_VALUE_NR,
		      _IOC_READ | _IOC_WRITE, REG_QUERY_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_SET_VALUE, REG_IOC_SET_VALUE_NR, _IOC_WRITE,
		      REG_SET_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_DELETE_VALUE, REG_IOC_DELETE_VALUE_NR,
		      _IOC_WRITE, REG_DELETE_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_BLANKET_TOMBSTONE,
		      REG_IOC_BLANKET_TOMBSTONE_NR, _IOC_WRITE,
		      REG_BLANKET_TOMBSTONE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_QUERY_VALUES_BATCH,
		      REG_IOC_QUERY_VALUES_BATCH_NR, _IOC_READ | _IOC_WRITE,
		      REG_QUERY_VALUES_BATCH_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_ENUM_VALUES, REG_IOC_ENUM_VALUES_NR,
		      _IOC_READ | _IOC_WRITE, REG_ENUM_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_ENUM_SUBKEYS, REG_IOC_ENUM_SUBKEYS_NR,
		      _IOC_READ | _IOC_WRITE, REG_ENUM_SUBKEY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_QUERY_KEY_INFO, REG_IOC_QUERY_KEY_INFO_NR,
		      _IOC_READ, REG_QUERY_KEY_INFO_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_DELETE_KEY, REG_IOC_DELETE_KEY_NR, _IOC_WRITE,
		      REG_DELETE_KEY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_HIDE_KEY, REG_IOC_HIDE_KEY_NR, _IOC_WRITE,
		      REG_HIDE_KEY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_GET_SECURITY, REG_IOC_GET_SECURITY_NR,
		      _IOC_READ | _IOC_WRITE, REG_GET_SECURITY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_SET_SECURITY, REG_IOC_SET_SECURITY_NR,
		      _IOC_WRITE, REG_SET_SECURITY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_NOTIFY, REG_IOC_NOTIFY_NR, _IOC_WRITE,
		      REG_NOTIFY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_FLUSH, REG_IOC_FLUSH_NR, _IOC_NONE, 0);
ASSERT_IOCTL_ENCODING(REG_IOC_BACKUP, REG_IOC_BACKUP_NR, _IOC_WRITE,
		      REG_BACKUP_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_RESTORE, REG_IOC_RESTORE_NR, _IOC_WRITE,
		      REG_RESTORE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_COMMIT, REG_IOC_COMMIT_NR, _IOC_NONE, 0);
ASSERT_IOCTL_ENCODING(REG_IOC_TXN_STATUS, REG_IOC_TXN_STATUS_NR, _IOC_READ,
		      REG_TXN_STATUS_ARGS_SIZE);
_Static_assert(sizeof(REG_BACKUP_MAGIC) - 1 == 8,
	       "REG_BACKUP_MAGIC must be eight bytes");

int main(void)
{
	/* Touch constants and a struct from across the header set so the
	 * compiler resolves real symbols, not merely the #include lines. */
	return (int)(SYS_KACS_OPEN
		     + KACS_TOKEN_QUERY
		     + KACS_SD_DACL_PRESENT
		     + KMES_ORIGIN_KACS
		     + SYS_REG_OPEN_KEY
		     + REG_OPEN_LINK
		     + KEY_QUERY_VALUE
		     + REG_IOC_QUERY_VALUE
		     + REG_BACKUP_HEADER
		     + sizeof(struct kacs_query_args));
}
