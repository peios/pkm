// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ed25519 signature verification for the kernel signature crypto API.
 *
 * The arithmetic core is generated from HACL* by
 * kernel/scripts/update-ed25519-hacl.py.
 */

#include <crypto/internal/sig.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>

#include "ed25519-hacl.h"

struct ed25519_ctx {
	u8 public_key[ED25519_HACL_PUBLIC_KEY_SIZE];
	bool pub_key_set;
	struct mutex lock;
	u64 scratch[ED25519_HACL_SCRATCH_U64];
};

static int ed25519_verify(struct crypto_sig *tfm, const void *src,
			  unsigned int slen, const void *msg,
			  unsigned int mlen)
{
	static const u8 empty_msg[1] = {};
	struct ed25519_ctx *ctx = crypto_sig_ctx(tfm);
	const u8 *msg_bytes = msg ? msg : empty_msg;
	bool ok;

	if (!ctx->pub_key_set)
		return -EINVAL;
	if (!src || (!msg && mlen != 0))
		return -EINVAL;
	if (slen != ED25519_HACL_SIGNATURE_SIZE)
		return -EINVAL;

	mutex_lock(&ctx->lock);
	ok = ed25519_hacl_verify(ctx->public_key, mlen, (u8 *)msg_bytes,
				 (u8 *)src, ctx->scratch);
	mutex_unlock(&ctx->lock);

	return ok ? 0 : -EKEYREJECTED;
}

static int ed25519_set_pub_key(struct crypto_sig *tfm, const void *key,
			       unsigned int keylen)
{
	struct ed25519_ctx *ctx = crypto_sig_ctx(tfm);

	if (!key || keylen != ED25519_HACL_PUBLIC_KEY_SIZE)
		return -EINVAL;

	memcpy(ctx->public_key, key, sizeof(ctx->public_key));
	ctx->pub_key_set = true;
	return 0;
}

static unsigned int ed25519_key_size(struct crypto_sig *tfm)
{
	return ED25519_HACL_PUBLIC_KEY_SIZE * BITS_PER_BYTE;
}

static unsigned int ed25519_digest_size(struct crypto_sig *tfm)
{
	/*
	 * Ed25519 signs the supplied message directly. The generic signature
	 * API names this parameter "digest", so report the API length ceiling.
	 */
	return UINT_MAX;
}

static unsigned int ed25519_max_size(struct crypto_sig *tfm)
{
	return ED25519_HACL_SIGNATURE_SIZE;
}

static int ed25519_init_tfm(struct crypto_sig *tfm)
{
	struct ed25519_ctx *ctx = crypto_sig_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	mutex_init(&ctx->lock);
	return 0;
}

static struct sig_alg ed25519_alg = {
	.verify = ed25519_verify,
	.set_pub_key = ed25519_set_pub_key,
	.key_size = ed25519_key_size,
	.digest_size = ed25519_digest_size,
	.max_size = ed25519_max_size,
	.init = ed25519_init_tfm,
	.base = {
		.cra_name = "ed25519",
		.cra_driver_name = "ed25519-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ed25519_ctx),
	},
};

static int __init ed25519_init(void)
{
	return crypto_register_sig(&ed25519_alg);
}

static void __exit ed25519_exit(void)
{
	crypto_unregister_sig(&ed25519_alg);
}

module_init(ed25519_init);
module_exit(ed25519_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ed25519 signature verification");
