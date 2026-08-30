// SPDX-License-Identifier: GPL-2.0-only
/*
 * Firmware-load verification (PEI-493).
 *
 * Firmware is code that runs on a device with DMA into host memory. A
 * tampered blob is a complete compromise of the kernel and everything
 * above it -- strictly worse than an unsigned binary, which at least runs
 * with no PIP tier. Binaries carry PIP signatures and modules carry
 * modsig; until this file, firmware was the one class of code the kernel
 * loaded on faith, and KACS never saw it because a firmware load is not
 * an exec.
 *
 * The signature is the ordinary PIP blob (signing.c): for a non-ELF file
 * it lives in the security.peios.sig xattr, stamped by peipkg at install
 * from the <file>.peios.sig sidecar the package carries. The bar is the
 * PeiosTcb tier, the same floor a usermodehelper exec must clear, because
 * both are the kernel choosing to run code it did not ship.
 *
 * Two hooks, because the VFS only calls kernel_post_read_file for a
 * whole-file read. That is the common case and hands us the exact bytes
 * the loader will decompress and give to the device, so those are what
 * gets hashed -- no second read, no TOCTOU. A partial read (a driver
 * pulling a window out of a large blob) only passes through
 * kernel_read_file, where nothing has been read yet, so that path
 * verifies the file through the reader probe instead.
 *
 * Policy: `enforce` refuses the load with -EPERM; `log` records the
 * verdict in a rate-limited warning and the kacs:kacs_firmware_load
 * tracepoint and lets the load proceed. 2026.8 ships in log mode so the
 * farm can be signed and any blob the packaging missed shows up in the
 * log rather than as a device that stopped working. The Kconfig default
 * is the release's policy; `kacs_fwsig=enforce|log` on the command line
 * overrides it for one boot, which is how the test stage exercises both.
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kernel_read_file.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

#include <trace/events/kacs.h>

#include "firmware.h"
#include "signing.h"

static bool pkm_kacs_fwsig_enforce __ro_after_init =
	IS_ENABLED(CONFIG_SECURITY_PKM_FIRMWARE_SIG_ENFORCE);

static int __init pkm_kacs_fwsig_setup(char *str)
{
	if (!str)
		return 0;
	if (strcmp(str, "enforce") == 0) {
		pkm_kacs_fwsig_enforce = true;
		return 1;
	}
	if (strcmp(str, "log") == 0) {
		pkm_kacs_fwsig_enforce = false;
		return 1;
	}
	pr_warn("pkm: kacs_fwsig=%s ignored (expected enforce or log)\n", str);
	return 0;
}
__setup("kacs_fwsig=", pkm_kacs_fwsig_setup);

bool pkm_kacs_firmware_sig_enforced(void)
{
	return pkm_kacs_fwsig_enforce;
}

int pkm_kacs_firmware_verdict(
	int probe_ret, u32 source, int verify_ret,
	const struct pkm_kacs_signing_trust_result *result, bool enforce,
	u8 *reason_out)
{
	u8 reason;

	if (!reason_out)
		return -EINVAL;

	/*
	 * Every branch below that is not ALLOWED refuses. In particular
	 * "could not establish trust" (a probe or crypto failure) lands on
	 * the same answer as "is not trusted": if it did not, whatever
	 * prevents verification from running would become the bypass. Same
	 * reasoning as pkm_kacs_umh_exec_denied().
	 */
	if (probe_ret)
		reason = KACS_FW_PROBE_FAILED;
	else if (source == PKM_KACS_SIGNING_SOURCE_NONE)
		reason = KACS_FW_UNSIGNED;
	else if (verify_ret || !result)
		reason = KACS_FW_UNVERIFIABLE;
	else if (!result->verified)
		reason = KACS_FW_NO_KEY_MATCH;
	else if (result->pip_trust < PKM_KACS_PIP_TRUST_PEIOS_TCB)
		reason = KACS_FW_BELOW_TCB;
	else
		reason = KACS_FW_ALLOWED;

	*reason_out = reason;
	if (reason == KACS_FW_ALLOWED)
		return 0;
	return enforce ? -EPERM : 0;
}

static const char *pkm_kacs_firmware_reason_str(u8 reason)
{
	switch (reason) {
	case KACS_FW_ALLOWED:
		return "verified";
	case KACS_FW_UNSIGNED:
		return "no signature";
	case KACS_FW_NO_KEY_MATCH:
		return "signature does not verify against any built-in key";
	case KACS_FW_BELOW_TCB:
		return "signing key is below the PeiosTcb tier";
	case KACS_FW_UNVERIFIABLE:
		return "signature could not be verified";
	case KACS_FW_PROBE_FAILED:
		return "signature material could not be read";
	default:
		return "unknown";
	}
}

/*
 * Common tail for both hooks: verify whatever the probe found, decide,
 * record, release. @file_len is only for the trace.
 */
static int pkm_kacs_firmware_decide(struct file *file, int probe_ret,
				    struct pkm_kacs_signing_material *material,
				    u64 file_len)
{
	struct pkm_kacs_signing_trust_result result = {};
	bool enforce = pkm_kacs_fwsig_enforce;
	int verify_ret = 0;
	u8 reason = 0;
	int ret;

	if (!probe_ret && material->source != PKM_KACS_SIGNING_SOURCE_NONE)
		verify_ret = pkm_kacs_signing_verify_builtin(material, &result);

	ret = pkm_kacs_firmware_verdict(probe_ret, material->source,
					verify_ret, &result, enforce, &reason);

	trace_kacs_firmware_load(file_len, material->source, result.pip_trust,
				 enforce, reason, ret);
	if (reason != KACS_FW_ALLOWED)
		pr_warn_ratelimited("pkm: firmware %pD: %s; %s\n", file,
				    pkm_kacs_firmware_reason_str(reason),
				    enforce ? "refused" :
					      "loaded (kacs_fwsig=log)");

	pkm_kacs_signing_material_release(material);
	return ret;
}

int pkm_kacs_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			      bool contents)
{
	struct pkm_kacs_signing_material material = {};
	loff_t size;
	int ret;

	if (id != READING_FIRMWARE)
		return 0;
	/*
	 * A whole-file read comes back through kernel_post_read_file with
	 * the bytes in hand; verify there, once, against what was read.
	 */
	if (contents)
		return 0;
	if (!file || !file_inode(file))
		return -EPERM;

	size = i_size_read(file_inode(file));
	ret = pkm_kacs_signing_probe_file(file, &material);
	return pkm_kacs_firmware_decide(file, ret, &material,
					size < 0 ? 0 : (u64)size);
}

int pkm_kacs_kernel_post_read_file(struct file *file, char *buf, loff_t size,
				   enum kernel_read_file_id id)
{
	struct pkm_kacs_signing_material material = {};
	int ret;

	if (id != READING_FIRMWARE)
		return 0;
	if (!file || size < 0 || (size > 0 && !buf))
		return -EPERM;

	ret = pkm_kacs_signing_probe_file_buffer(file, buf, (size_t)size,
						 &material);
	return pkm_kacs_firmware_decide(file, ret, &material, (u64)size);
}
