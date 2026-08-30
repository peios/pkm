/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PKM_KACS_SIGNING_H
#define PKM_KACS_SIGNING_H

#include <crypto/sha2.h>
#include <linux/types.h>

struct file;
struct pkm_kacs_kunit_signing_probe;

#define PKM_KACS_SIGNING_BLOB_LEN 3310U
#define PKM_KACS_SIGNING_SIGNATURE_LEN 3309U
#define PKM_KACS_SIGNING_VERSION 0x01U
#define PKM_KACS_SIGNING_ELF_SECTION ".peios.sig"
#define PKM_KACS_SIGNING_XATTR_NAME "security.peios.sig"
#define PKM_KACS_SIGNING_HASH_CHUNK 4096U
#define PKM_KACS_SIGNING_PUBLIC_KEY_LEN 1952U
#define PKM_KACS_SIGNING_SOURCE_NONE 0U
#define PKM_KACS_SIGNING_SOURCE_ELF 1U
#define PKM_KACS_SIGNING_SOURCE_XATTR 2U
#define PKM_KACS_PIP_TYPE_PROTECTED 512U
#define PKM_KACS_PIP_TRUST_PEIOS_TCB 8192U

struct pkm_kacs_signing_material {
	u32 source;
	/*
	 * Owned heap buffer holding the raw signature blob exactly as it
	 * appears on disk: PKM_KACS_SIGNING_BLOB_LEN bytes, a version byte
	 * followed by the ML-DSA-65 signature. NULL when no signature was
	 * found. Heap rather than inline because the signature is 3309 bytes
	 * and this struct is stack-allocated throughout the exec path.
	 * Release with pkm_kacs_signing_material_release().
	 */
	u8 *blob;
	u8 hash[SHA256_DIGEST_SIZE];
};

/*
 * The signature within the blob, or NULL if unsigned. A view, not a copy —
 * valid only until pkm_kacs_signing_material_release().
 */
static inline const u8 *pkm_kacs_signing_material_sig(
	const struct pkm_kacs_signing_material *material)
{
	return material->blob ? material->blob + 1 : NULL;
}

/* Idempotent: safe on a zeroed or already-released material. */
void pkm_kacs_signing_material_release(
	struct pkm_kacs_signing_material *material);

struct pkm_kacs_signing_trust_result {
	u32 verified;
	u32 pip_type;
	u32 pip_trust;
};

int pkm_kacs_signing_probe_file(struct file *file,
				struct pkm_kacs_signing_material *out);
/*
 * Like pkm_kacs_signing_probe_file(), but hashes the bytes the caller was
 * handed rather than re-reading the file. For a loader that already holds
 * the whole file in memory (firmware), verifying that buffer is verifying
 * what the device will get; a second read would reopen the TOCTOU window
 * the reader probe's size check only narrows. The signature blob itself
 * still comes from the file (ELF section within the buffer, or the xattr).
 */
int pkm_kacs_signing_probe_file_buffer(struct file *file, const u8 *buf,
				       size_t len,
				       struct pkm_kacs_signing_material *out);
int pkm_kacs_signing_crypto_probe(void);
int pkm_kacs_signing_verify_builtin(
	const struct pkm_kacs_signing_material *material,
	struct pkm_kacs_signing_trust_result *result);
int pkm_kacs_exec_pip_from_material(
	const struct pkm_kacs_signing_material *material, u32 *pip_type_out,
	u32 *pip_trust_out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_signing_material_from_kunit_probe(
	const struct pkm_kacs_kunit_signing_probe *material,
	struct pkm_kacs_signing_material *material_out);
#endif

#endif /* PKM_KACS_SIGNING_H */
