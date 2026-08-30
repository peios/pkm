/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_FIRMWARE_H
#define _SECURITY_PKM_KACS_FIRMWARE_H

#include <linux/fs.h>
#include <linux/kernel_read_file.h>
#include <linux/types.h>

struct pkm_kacs_signing_trust_result;

/*
 * Firmware-load verification (PEI-493): every file the kernel reads as
 * READING_FIRMWARE must carry a PIP signature that verifies at the
 * PeiosTcb tier, or the loader is refused. Both LSM read hooks are
 * needed: kernel_post_read_file sees the whole file in memory (the
 * common case) and kernel_read_file is the only hook a partial read
 * ever passes through.
 */
int pkm_kacs_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			      bool contents);
int pkm_kacs_kernel_post_read_file(struct file *file, char *buf, loff_t size,
				   enum kernel_read_file_id id);

/* Whether a refusal is handed to the loader (true) or only logged. */
bool pkm_kacs_firmware_sig_enforced(void);

/*
 * The verdict for one firmware read, given the outcome of probing and
 * verifying its signature. Pure, so KUnit can drive every branch:
 * returns 0 to allow or -EPERM to refuse, and names why in *reason_out
 * (a KACS_FW_* code). @enforce false turns every refusal into 0 while
 * leaving the reason intact, which is what log mode reports.
 */
int pkm_kacs_firmware_verdict(
	int probe_ret, u32 source, int verify_ret,
	const struct pkm_kacs_signing_trust_result *result, bool enforce,
	u8 *reason_out);

#endif /* _SECURITY_PKM_KACS_FIRMWARE_H */
