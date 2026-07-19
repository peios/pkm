/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TOKEN_LOGON_SESSION_H
#define _SECURITY_PKM_KACS_TOKEN_LOGON_SESSION_H

#include <linux/types.h>

long pkm_kacs_create_logon_session_core(const void *subject_token,
				  const u8 *spec, size_t spec_len,
				  u64 *logon_session_id_out);
long pkm_kacs_destroy_empty_logon_session_core(const void *subject_token,
					 u64 auth_id);
long pkm_kacs_create_token_core(const void *subject_token,
				const u8 *spec, size_t spec_len);

#endif /* _SECURITY_PKM_KACS_TOKEN_LOGON_SESSION_H */
