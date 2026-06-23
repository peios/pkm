/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_PRIMARY_TOKEN_H
#define _SECURITY_PKM_KACS_PRIMARY_TOKEN_H

struct cred;

long pkm_kacs_prepare_current_token_cred(const void *token, struct cred **out);

#endif /* _SECURITY_PKM_KACS_PRIMARY_TOKEN_H */
