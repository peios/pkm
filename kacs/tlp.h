/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PKM_KACS_TLP_H
#define PKM_KACS_TLP_H

#include <linux/types.h>

struct file;

int pkm_kacs_check_tlp_file_core(u32 mitigation_bits, struct file *file,
				 bool executable_transition);

#endif /* PKM_KACS_TLP_H */
