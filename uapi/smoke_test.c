/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace-cleanliness smoke test for the PKM UAPI headers.
 *
 * This compiles with an ordinary, non-kernel C compiler — the precondition
 * for the cgo -godefs binding generator and for any userspace consumer of
 * the PKM ABI. It is built by check-userspace-clean.sh.
 */
#include <pkm/pkm.h>

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
_Static_assert(KMES_EVENT_TYPE_LEN_OFFSET
		       == KMES_EVENT_ORIGIN_CLASS_OFFSET + sizeof(__u8),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_HEADER_BASE_SIZE
		       == KMES_EVENT_TYPE_LEN_OFFSET + sizeof(__u16),
	       "KMES event-header base size disagrees with its field offsets");
_Static_assert(sizeof(struct kmes_emit_entry) == 32,
	       "kmes_emit_entry must be 32 bytes");
_Static_assert(_IOC_TYPE(REG_IOC_QUERY_VALUE) == REG_IOC_TYPE,
	       "REG_IOC_QUERY_VALUE type disagrees with PSD-005");
_Static_assert(_IOC_NR(REG_IOC_QUERY_VALUE) == REG_IOC_QUERY_VALUE_NR,
	       "REG_IOC_QUERY_VALUE number disagrees with PSD-005");
_Static_assert(_IOC_DIR(REG_IOC_QUERY_VALUE) == (_IOC_READ | _IOC_WRITE),
	       "REG_IOC_QUERY_VALUE direction disagrees with PSD-005");
_Static_assert(_IOC_SIZE(REG_IOC_QUERY_VALUE) == REG_QUERY_VALUE_ARGS_SIZE,
	       "REG_IOC_QUERY_VALUE size disagrees with PSD-005");
_Static_assert(_IOC_DIR(REG_IOC_FLUSH) == _IOC_NONE,
	       "REG_IOC_FLUSH direction disagrees with PSD-005");
_Static_assert(_IOC_SIZE(REG_IOC_FLUSH) == 0,
	       "REG_IOC_FLUSH must not carry an argument");
_Static_assert(_IOC_TYPE(REG_SRC_REGISTER) == REG_IOC_TYPE,
	       "REG_SRC_REGISTER type disagrees with PSD-005");
_Static_assert(_IOC_SIZE(REG_SRC_REGISTER) == REG_SRC_REGISTER_ARGS_SIZE,
	       "REG_SRC_REGISTER size disagrees with PSD-005");
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
