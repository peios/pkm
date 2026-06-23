/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PKM_KACS_SIGNING_H
#define PKM_KACS_SIGNING_H

#include <crypto/sha2.h>
#include <linux/types.h>

struct file;
struct pkm_kacs_kunit_signing_probe;

#define PKM_KACS_SIGNING_BLOB_LEN 65U
#define PKM_KACS_SIGNING_SIGNATURE_LEN 64U
#define PKM_KACS_SIGNING_VERSION 0x01U
#define PKM_KACS_SIGNING_ELF_SECTION ".peios.sig"
#define PKM_KACS_SIGNING_XATTR_NAME "security.peios.sig"
#define PKM_KACS_SIGNING_HASH_CHUNK 4096U
#define PKM_KACS_SIGNING_PUBLIC_KEY_LEN 32U
#define PKM_KACS_SIGNING_SOURCE_NONE 0U
#define PKM_KACS_SIGNING_SOURCE_ELF 1U
#define PKM_KACS_SIGNING_SOURCE_XATTR 2U
#define PKM_KACS_PIP_TYPE_PROTECTED 512U
#define PKM_KACS_PIP_TRUST_PEIOS_TCB 8192U

struct pkm_kacs_signing_material {
	u32 source;
	u8 signature[PKM_KACS_SIGNING_SIGNATURE_LEN];
	u8 hash[SHA256_DIGEST_SIZE];
};

struct pkm_kacs_signing_trust_result {
	u32 verified;
	u32 pip_type;
	u32 pip_trust;
};

int pkm_kacs_signing_probe_file(struct file *file,
				struct pkm_kacs_signing_material *out);
int pkm_kacs_signing_verify_builtin(
	const struct pkm_kacs_signing_material *material,
	struct pkm_kacs_signing_trust_result *result);
void pkm_kacs_exec_pip_from_material(
	const struct pkm_kacs_signing_material *material, u32 *pip_type_out,
	u32 *pip_trust_out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_signing_material_from_kunit_probe(
	const struct pkm_kacs_kunit_signing_probe *material,
	struct pkm_kacs_signing_material *material_out);
#endif

#endif /* PKM_KACS_SIGNING_H */
