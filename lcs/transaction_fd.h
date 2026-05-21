/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_TRANSACTION_FD_H
#define _SECURITY_PKM_LCS_TRANSACTION_FD_H

#include <linux/types.h>

#define PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT 30000U

struct reg_txn_status_args;

struct pkm_lcs_transaction_fd_snapshot {
	u64 transaction_id;
	u32 state;
	u32 bound_source_id;
	bool timer_pending;
	u8 _pad[3];
};

long pkm_lcs_transaction_fd_publish(u32 timeout_ms);
long pkm_lcs_reg_begin_transaction(void);
long pkm_lcs_transaction_fd_commit(int fd);
long pkm_lcs_transaction_fd_status(int fd, struct reg_txn_status_args *out);
long pkm_lcs_transaction_fd_snapshot(
	int fd, struct pkm_lcs_transaction_fd_snapshot *out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_transaction_fd_set_state(int fd, u32 state,
					    u32 bound_source_id);
#endif

#endif /* _SECURITY_PKM_LCS_TRANSACTION_FD_H */
