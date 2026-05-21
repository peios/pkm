/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_TRANSACTION_FD_H
#define _SECURITY_PKM_LCS_TRANSACTION_FD_H

#include <linux/types.h>

#define PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT 30000U

struct pkm_lcs_transaction_fd_snapshot {
	u64 transaction_id;
	u32 state;
	u32 bound_source_id;
	bool timer_pending;
	u8 _pad[3];
};

long pkm_lcs_transaction_fd_publish(u32 timeout_ms);
long pkm_lcs_reg_begin_transaction(void);
long pkm_lcs_transaction_fd_snapshot(
	int fd, struct pkm_lcs_transaction_fd_snapshot *out);

#endif /* _SECURITY_PKM_LCS_TRANSACTION_FD_H */
