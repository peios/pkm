/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_PSB_H
#define _SECURITY_PKM_KACS_PSB_H

#include <linux/types.h>

struct file;
struct vm_area_struct;

int pkm_kacs_task_prctl(int option, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5);
int pkm_kacs_mmap_file(struct file *file, unsigned long reqprot,
		       unsigned long prot, unsigned long flags);
int pkm_kacs_file_mprotect(struct vm_area_struct *vma,
			   unsigned long reqprot, unsigned long prot);
int pkm_kacs_check_pie_bprm_core(u32 mitigation_bits, const u8 *buf,
				 size_t len);
void pkm_kacs_exec_pip_from_file(const struct file *file,
				 u32 *pip_type_out, u32 *pip_trust_out);

#endif /* _SECURITY_PKM_KACS_PSB_H */
