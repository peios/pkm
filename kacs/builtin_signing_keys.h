/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Default KACS built-in binary-signing key table.
 *
 * Kernel staging replaces this file with a table generated from
 * PKM_KACS_TCB_PUBKEY_HEX. The default terminator-only table is valid only
 * before staging or for KUnit/test builds that use the hard-coded KUnit key.
 */

#ifndef PKM_KACS_BUILTIN_SIGNING_KEYS_H
#define PKM_KACS_BUILTIN_SIGNING_KEYS_H

#define PKM_KACS_BUILTIN_SIGNING_KEY_TABLE \
	{ { 0 }, 0, 0 }

#endif /* PKM_KACS_BUILTIN_SIGNING_KEYS_H */
