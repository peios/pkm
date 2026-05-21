/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_TRANSACTION_FD_H
#define _SECURITY_PKM_LCS_TRANSACTION_FD_H

#include <linux/types.h>

#define PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT 30000U
#define PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES 16U

#define PKM_LCS_TRANSACTION_BIND_NEW 1U
#define PKM_LCS_TRANSACTION_BIND_REUSE 2U

struct reg_txn_status_args;

struct pkm_lcs_transaction_fd_snapshot {
	u64 transaction_id;
	u32 state;
	u32 bound_source_id;
	bool timer_pending;
	u8 _pad[3];
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

struct pkm_lcs_transaction_binding_plan {
	u64 transaction_id;
	u32 action;
	u32 state;
	u32 bound_source_id;
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

long pkm_lcs_transaction_fd_publish(u32 timeout_ms);
long pkm_lcs_reg_begin_transaction(void);
long pkm_lcs_transaction_fd_commit(int fd);
long pkm_lcs_transaction_fd_status(int fd, struct reg_txn_status_args *out);
long pkm_lcs_transaction_fd_prepare_mutation_binding(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out);
long pkm_lcs_transaction_fd_complete_first_bind(
	int fd, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES]);
long pkm_lcs_transaction_fd_snapshot(
	int fd, struct pkm_lcs_transaction_fd_snapshot *out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_transaction_fd_set_state(int fd, u32 state,
					    u32 bound_source_id);
#endif

#endif /* _SECURITY_PKM_LCS_TRANSACTION_FD_H */
