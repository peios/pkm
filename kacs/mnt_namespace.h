/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_MNT_NAMESPACE_H
#define _SECURITY_PKM_KACS_MNT_NAMESPACE_H

#include <linux/fs.h>
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
				     unsigned int op, const char *fstype);

/* The default descriptor for a namespace @token is creating. */
struct pkm_kacs_process_sd *pkm_kacs_mntns_sd_alloc(const void *token);

/*
 * A tmpfs brought into being by a token that holds no mount privilege was
 * admitted by a namespace descriptor, and nobody privileged will seed its
 * descriptors: stamp it synthesize-ephemeral with a creator-owned template
 * so its files are reachable by the one identity that can reach the table.
 * Any other superblock, and any superblock a privileged token mounts, is
 * left exactly as it was. Returns 0, or a negative errno if the template
 * could not be built. Split from the hook for KUnit.
 */
long pkm_kacs_mntns_stamp_superblock_for_token(struct super_block *sb,
					       const void *token);

/* LSM sb_kern_mount hook (lsm.c). */
int pkm_kacs_sb_kern_mount(const struct super_block *sb);

#endif /* _SECURITY_PKM_KACS_MNT_NAMESPACE_H */
