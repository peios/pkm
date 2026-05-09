/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Default KACS built-in binary-signing key table.
 *
 * Production builds may replace this file during kernel staging with a table
 * generated from PKM_KACS_TCB_PUBKEY_HEX. The default is terminator-only, so
 * binaries resolve to PIP None/0 unless a build supplies a TCB public key.
 */

#ifndef PKM_KACS_BUILTIN_SIGNING_KEYS_H
#define PKM_KACS_BUILTIN_SIGNING_KEYS_H

#define PKM_KACS_BUILTIN_SIGNING_KEY_TABLE \
	{ { 0 }, 0, 0 }

#endif /* PKM_KACS_BUILTIN_SIGNING_KEYS_H */
