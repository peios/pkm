/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_SOURCE_TRANSACTION_H
#define _SECURITY_PKM_LCS_SOURCE_TRANSACTION_H
#include <linux/types.h>
struct file;
struct pkm_lcs_source_fd;
/* One owner represents the live file object (all dup'd handles) or the scope
 * of an in-kernel operation. No task/process heartbeat implies ownership. */
long pkm_lcs_source_transaction_own(u64 id, u32 lifetime_ms);
void pkm_lcs_source_transaction_put(u64 id);
void pkm_lcs_source_transaction_end(u64 id);
void pkm_lcs_source_transaction_begin_failed(u64 id, u64 session);
long pkm_lcs_source_transaction_bind(u64 id, struct pkm_lcs_source_fd *source);
long pkm_lcs_source_lifetime_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg);
#endif
