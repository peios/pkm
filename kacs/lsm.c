// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM kernel scaffold.
 *
 * This file deliberately provides only the smallest built-in LSM/init shape
 * needed to prove that the slow-track subtree compiles into the kernel and
 * that the C/Rust boundary executes at boot. It does not implement any KACS
 * semantics yet.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>

extern int kacs_rust_init(void);

static const struct lsm_id pkm_lsmid = {
	.name = "pkm",
	.id = 1000,
};

static int __init pkm_init(void)
{
	int ret;

	ret = kacs_rust_init();
	if (ret) {
		pr_err("pkm: slow-track Rust init failed (%d)\n", ret);
		return ret;
	}

	pr_info("pkm: slow-track kernel scaffold initialized\n");
	return 0;
}

DEFINE_LSM(pkm) = {
	.id = &pkm_lsmid,
	.init = pkm_init,
};
