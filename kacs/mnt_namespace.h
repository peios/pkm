/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_MNT_NAMESPACE_H
#define _SECURITY_PKM_KACS_MNT_NAMESPACE_H

#include <linux/kacs_mntns.h>
#include <linux/types.h>

struct pkm_kacs_process_sd;

/* The object fs/namespace.c keeps in struct mnt_namespace. */
struct pkm_kacs_mntns_security {
	struct pkm_kacs_process_sd *sd;
};

/*
 * The decision itself, against an explicit token and descriptor, so KUnit
 * can drive it without a live namespace. @sd NULL is a namespace with no
 * descriptor. Records privilege use on the privileged rung and emits the
 * access-check audit events on the descriptor rung, as the live path does.
 */
bool pkm_kacs_may_mount_op_for_token(const void *subject_token,
				     const struct pkm_kacs_process_sd *sd,
				     unsigned int op);

/* The default descriptor for a namespace @token is creating. */
struct pkm_kacs_process_sd *pkm_kacs_mntns_sd_alloc(const void *token);

#endif /* _SECURITY_PKM_KACS_MNT_NAMESPACE_H */
