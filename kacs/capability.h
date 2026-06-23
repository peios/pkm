/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_CAPABILITY_H
#define _SECURITY_PKM_KACS_CAPABILITY_H

#include <linux/capability.h>
#include <linux/types.h>

struct cred;
struct task_struct;
struct user_namespace;

u64 pkm_kacs_allow_cap_mask_u64(void);
void pkm_kacs_raise_allow_compat_caps(struct cred *cred);
void pkm_kacs_capget_fixup(kernel_cap_t *effective,
			   kernel_cap_t *inheritable,
			   kernel_cap_t *permitted);
long pkm_kacs_proc_status_cap_fixup(kernel_cap_t *inheritable,
				    kernel_cap_t *permitted,
				    kernel_cap_t *effective,
				    kernel_cap_t *bset,
				    kernel_cap_t *ambient);
void pkm_kacs_reset_allow_compat_caps(struct cred *cred);
void pkm_kacs_copy_exec_compat_caps(struct cred *new, const struct cred *old);
bool pkm_kacs_allow_caps_present(const kernel_cap_t *caps);
u64 pkm_kacs_kernel_cap_to_u64(const kernel_cap_t *caps);
kernel_cap_t pkm_kacs_u64_to_kernel_cap(u64 mask);
long pkm_kacs_check_capability_for_token(const void *subject_token, int cap);
long pkm_kacs_capable_in_cred_ns(const struct cred *cred,
				 struct user_namespace *target_ns, int cap,
				 unsigned int opts);
long pkm_kacs_capget_for_task(const struct task_struct *target,
			      kernel_cap_t *effective,
			      kernel_cap_t *inheritable,
			      kernel_cap_t *permitted);
int pkm_kacs_capable(const struct cred *cred,
		     struct user_namespace *target_ns, int cap,
		     unsigned int opts);
long pkm_kacs_capset_core(const void *subject_token, struct cred *new,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted);
int pkm_kacs_capset(struct cred *new, const struct cred *old,
		    const kernel_cap_t *effective,
		    const kernel_cap_t *inheritable,
		    const kernel_cap_t *permitted);
long pkm_kacs_prctl_capability_guard_core(const void *subject_token,
					  u64 ambient_mask, int option,
					  unsigned long arg2,
					  unsigned long arg3,
					  unsigned long arg4,
					  unsigned long arg5);
long pkm_kacs_prctl_capability_guard(int option, unsigned long arg2,
				     unsigned long arg3,
				     unsigned long arg4,
				     unsigned long arg5);

#endif /* _SECURITY_PKM_KACS_CAPABILITY_H */
