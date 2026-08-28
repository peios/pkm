/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_IPC_H
#define _SECURITY_PKM_KACS_IPC_H

#include <linux/types.h>

struct kern_ipc_perm;

/* Object kinds: the ipc_ids index order (ipc/util.h), for ipc_lsm_with_object. */
#define PKM_KACS_IPC_SEM	0
#define PKM_KACS_IPC_MSG	1
#define PKM_KACS_IPC_SHM	2

/* System V IPC objects: LSM hooks (lsm.c) */
int pkm_kacs_ipc_alloc_security(struct kern_ipc_perm *perm);
void pkm_kacs_ipc_free_security(struct kern_ipc_perm *perm);
int pkm_kacs_ipc_permission(struct kern_ipc_perm *perm, short flag);
int pkm_kacs_shm_shmctl(struct kern_ipc_perm *perm, int cmd);
int pkm_kacs_msg_queue_msgctl(struct kern_ipc_perm *perm, int cmd);
int pkm_kacs_sem_semctl(struct kern_ipc_perm *perm, int cmd);

/* kacs_get_sd / kacs_set_sd on a SysV object addressed by (ids index, id) */
long pkm_kacs_ipc_sd_query(int kind, int id, const void *subject_token,
			   u32 security_info, const u8 **out_sd_ptr,
			   size_t *out_sd_len);
long pkm_kacs_ipc_sd_set(int kind, int id, const void *subject_token,
			 u32 security_info, const u8 *input_sd_ptr,
			 size_t input_sd_len);
int pkm_kacs_ipc_kind_from_sd_flags(u32 flags);

#endif /* _SECURITY_PKM_KACS_IPC_H */
