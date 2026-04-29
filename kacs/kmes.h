/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_KMES_H
#define _SECURITY_PKM_KACS_KMES_H

#include <linux/types.h>

#define PKM_KMES_ORIGIN_USERSPACE 0U
#define PKM_KMES_ORIGIN_KMES 1U
#define PKM_KMES_ORIGIN_KACS 2U
#define PKM_KMES_ORIGIN_LCS 3U

int pkm_kmes_init(void);
void pkm_kmes_emit_kernel(u8 origin_class, const void *event_type,
			  size_t event_type_len, const void *payload,
			  size_t payload_len);
int pkm_kmes_current_process_info(u64 *pid_out, u8 *name_out,
				  size_t name_out_len, size_t *name_len_out,
				  u8 *path_out, size_t path_out_len,
				  size_t *path_len_out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
struct pkm_kmes_kunit_snapshot {
	u16 cpu_id;
	u16 _reserved;
	u64 capacity;
	u64 write_pos;
	u64 tail_pos;
	u64 last_sequence;
	u64 dropped_events;
};

void pkm_kmes_kunit_reset_all(void);
int pkm_kmes_kunit_snapshot_single_active(struct pkm_kmes_kunit_snapshot *out);
int pkm_kmes_kunit_copy_single_buffer(u8 *out, size_t out_len,
				      size_t *written_out,
				      struct pkm_kmes_kunit_snapshot *out_snapshot);
int pkm_kmes_kunit_set_process_override(u64 pid, const char *name,
					const char *path);
void pkm_kmes_kunit_clear_process_override(void);
#endif

#endif /* _SECURITY_PKM_KACS_KMES_H */
