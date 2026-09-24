/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_KACS_MNTNS_H
#define _LINUX_KACS_MNTNS_H

#include <linux/err.h>
#include <linux/types.h>

/*
 * Typed, kernel-private interface between fs/namespace.c and the KACS
 * mount-namespace object (security/pkm/kacs/mnt_namespace.c). These symbols
 * are not exported to modules and have no userspace representation; the
 * rights a descriptor carries are <pkm/mntns.h>.
 *
 * A mount namespace other than the initial one carries a security descriptor
 * minted from its creator's token. fs/namespace.c keeps the pointer in
 * struct mnt_namespace and asks KACS, rather than CAP_SYS_ADMIN, whether the
 * current task may reshape its current mount table.
 */

struct pkm_kacs_mntns_security;

/*
 * What a mount-table change is, as far as the namespace descriptor is
 * concerned. BIND, UMOUNT and PIVOT_ROOT can be admitted by the descriptor;
 * NEW_FS can be, for the filesystem types KACS keeps on its allowlist
 * (tmpfs, proc and stratafs, whose parsers take no untrusted image); OTHER
 * always needs the privilege.
 */
#define PKM_KACS_MNTNS_OP_OTHER		0U
#define PKM_KACS_MNTNS_OP_BIND		1U
#define PKM_KACS_MNTNS_OP_UMOUNT	2U
#define PKM_KACS_MNTNS_OP_PIVOT_ROOT	3U
#define PKM_KACS_MNTNS_OP_NEW_FS	4U

#ifdef CONFIG_SECURITY_PKM
/*
 * Mint the descriptor for a mount namespace the current task is creating.
 * Returns the object to keep in the namespace, or an ERR_PTR. Sleeping
 * process-context call.
 */
struct pkm_kacs_mntns_security *pkm_kacs_mntns_security_create(void);
void pkm_kacs_mntns_security_free(struct pkm_kacs_mntns_security *sec);

/*
 * Whether the current task holds the mount privilege (SeManageVolume or
 * SeTcb). Read-only: records no privilege use. fs/namespace.c uses it to
 * decide whether a new namespace's mounts are slaved to the parent's.
 */
bool pkm_kacs_mntns_creator_privileged(void);

/*
 * Whether the current task may perform @op on the mount table whose
 * namespace carries @sec (NULL for the initial namespace and for anonymous
 * ones). @fstype is the filesystem type name for NEW_FS and NULL otherwise.
 * Replaces the CAP_SYS_ADMIN test in may_mount() and mount_capable().
 */
bool pkm_kacs_may_mount_op(const struct pkm_kacs_mntns_security *sec,
			   unsigned int op, const char *fstype);
#else
static inline struct pkm_kacs_mntns_security *
pkm_kacs_mntns_security_create(void)
{
	return NULL;
}

static inline void pkm_kacs_mntns_security_free(
	struct pkm_kacs_mntns_security *sec)
{
}

static inline bool pkm_kacs_mntns_creator_privileged(void)
{
	return true;
}

static inline bool pkm_kacs_may_mount_op(
	const struct pkm_kacs_mntns_security *sec, unsigned int op,
	const char *fstype)
{
	return false;
}
#endif

#endif /* _LINUX_KACS_MNTNS_H */
