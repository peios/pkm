// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ed25519 HACL* verifier interface.
 *
 * The implementation is generated from HACL* commit:
 * 504c2987452f87fe44bce9b9f12e19d6e051761f
 *
 * Do not edit generated output by hand.
 */

#ifndef PKM_KERNEL_CRYPTO_ED25519_HACL_H
#define PKM_KERNEL_CRYPTO_ED25519_HACL_H

#include <linux/types.h>

#define ED25519_HACL_PUBLIC_KEY_SIZE 32U
#define ED25519_HACL_SIGNATURE_SIZE 64U
#define ED25519_HACL_SCRATCH_U64 640U

bool ed25519_hacl_verify(uint8_t *public_key, uint32_t msg_len, uint8_t *msg,
			 uint8_t *signature, uint64_t *scratch);

#endif /* PKM_KERNEL_CRYPTO_ED25519_HACL_H */
