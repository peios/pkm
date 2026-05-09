#!/usr/bin/env python3
#
# Generate the kernel Ed25519 verifier core from HACL* generated C.
#
# This script deliberately imports only the verifier dependency closure used by
# Hacl_Ed25519_verify. It rejects the signing/key-generation entry points and
# signing-only precomputation tables that are present in the packaged HACL*
# Ed25519 distribution artifact.

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


FALLBACK_HACL_COMMIT = "unknown"

CURVE_FIELD_FUNCTIONS = [
    "Hacl_Impl_Curve25519_Field51_fadd",
    "Hacl_Impl_Curve25519_Field51_fsub",
    "Hacl_Impl_Curve25519_Field51_fmul",
    "Hacl_Impl_Curve25519_Field51_fsqr",
]

CURVE_FUNCTIONS = [
    "Hacl_Curve25519_51_fsquare_times",
    "Hacl_Curve25519_51_finv",
]

ED25519_FUNCTIONS = [
    "fsum",
    "fdifference",
    "Hacl_Bignum25519_reduce_513",
    "fmul0",
    "times_2",
    "times_d",
    "times_2d",
    "fsquare",
    "fsquare_times",
    "fsquare_times_inplace",
    "Hacl_Bignum25519_inverse",
    "reduce",
    "Hacl_Bignum25519_load_51",
    "Hacl_Impl_Ed25519_PointDouble_point_double",
    "Hacl_Impl_Ed25519_PointAdd_point_add",
    "Hacl_Impl_Ed25519_PointConstants_make_point_inf",
    "pow2_252m2",
    "is_0",
    "mul_modp_sqrt_m1",
    "recover_x",
    "Hacl_Impl_Ed25519_PointDecompress_point_decompress",
    "barrett_reduction",
    "gte_q",
    "eq",
    "Hacl_Impl_Ed25519_PointEqual_point_equal",
    "Hacl_Impl_Ed25519_PointNegate_point_negate",
    "point_mul_g_double_vartime",
    "point_negate_mul_double_g_vartime",
    "store_56",
    "load_64_bytes",
    "load_32_bytes",
    "sha512_pre_pre2_msg",
    "sha512_modq_pre_pre2",
    "Hacl_Ed25519_verify",
]

SHA512_PRE_PRE2_MSG_KERNEL = """static inline void
sha512_pre_pre2_msg(
  uint8_t *hash,
  uint8_t *prefix,
  uint8_t *prefix2,
  uint32_t len,
  uint8_t *input
)
{
  struct sha512_ctx ctx;

  sha512_init(&ctx);
  sha512_update(&ctx, prefix, 32U);
  sha512_update(&ctx, prefix2, 32U);
  sha512_update(&ctx, input, len);
  sha512_final(&ctx, hash);
}
"""

FORBIDDEN_OUTPUT_PATTERNS = [
    "Hacl_Ed25519_secret_to_public",
    "Hacl_Ed25519_expand_keys",
    "Hacl_Ed25519_sign_expanded",
    "Hacl_Ed25519_sign",
    "point_mul_g_compress",
    "secret_expand",
    "sha512_modq_pre(",
    "sha512_pre_msg",
    "mul_modq",
    "add_modq",
    "Hacl_Ed25519_PrecompTable_precomp_basepoint_table_w4",
    "Hacl_Ed25519_PrecompTable_precomp_g_pow2_64_table_w4",
    "Hacl_Ed25519_PrecompTable_precomp_g_pow2_128_table_w4",
    "Hacl_Ed25519_PrecompTable_precomp_g_pow2_192_table_w4",
]


def die(message: str) -> None:
    print(f"update-ed25519-hacl: {message}", file=sys.stderr)
    sys.exit(1)


def parse_args() -> tuple[Path, Path]:
    hacl = os.environ.get("HACL_STAR_DIR", "/tmp/hacl-star")
    out = None
    args = sys.argv[1:]
    i = 0

    while i < len(args):
        arg = args[i]
        if arg == "--hacl-star":
            i += 1
            if i >= len(args):
                die("--hacl-star requires a path")
            hacl = args[i]
        elif arg == "--out":
            i += 1
            if i >= len(args):
                die("--out requires a path")
            out = args[i]
        elif arg in ("-h", "--help"):
            print("usage: update-ed25519-hacl.py [--hacl-star PATH] --out DIR")
            sys.exit(0)
        else:
            die(f"unknown argument: {arg}")
        i += 1

    if out is None:
        die("usage: update-ed25519-hacl.py [--hacl-star PATH] --out DIR")

    return Path(hacl).resolve(), Path(out).resolve()


def require_file(path: Path) -> None:
    if not path.is_file():
        die(f"required file missing: {path}")


def hacl_commit(path: Path) -> str:
    require_file(path / "dist/gcc-compatible/Hacl_Ed25519.c")
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except subprocess.CalledProcessError as exc:
        print(
            f"update-ed25519-hacl: warning: cannot read HACL* git commit from {path}: {exc}",
            file=sys.stderr,
        )
        return FALLBACK_HACL_COMMIT


def find_definition(text: str, name: str) -> str:
    lines = text.splitlines()
    name_re = re.compile(rf"\b{re.escape(name)}\s*\(")

    def is_function_start(line: str) -> bool:
        stripped = line.lstrip()
        return stripped in ("void", "bool", "uint64_t") or stripped.startswith(
            ("static ", "void ", "bool ", "uint64_t ")
        )

    for idx, line in enumerate(lines):
        if not name_re.search(line):
            continue

        start = idx
        while start > 0:
            if is_function_start(lines[start]):
                break
            start -= 1

        if not is_function_start(lines[start]):
            continue

        open_seen = False
        depth = 0
        end = start
        for end in range(start, len(lines)):
            for char in lines[end]:
                if char == "{":
                    depth += 1
                    open_seen = True
                elif char == "}":
                    depth -= 1
                    if open_seen and depth == 0:
                        return "\n".join(lines[start : end + 1]) + "\n"

    die(f"could not find definition for {name}")
    raise AssertionError("unreachable")


def find_static_table(text: str, name: str) -> str:
    marker = name + "["
    start = text.find(marker)
    if start == -1:
        die(f"could not find table {name}")
    start = text.rfind("static const", 0, start)
    if start == -1:
        die(f"could not find table declaration for {name}")
    end = text.find("\n  };", start)
    if end == -1:
        die(f"could not find table terminator for {name}")
    return text[start : end + len("\n  };")] + "\n"


def make_helpers_static(code: str) -> str:
    code = re.sub(r"(?m)^void (Hacl_[A-Za-z0-9_]+)\(", r"static void \1(", code)
    code = re.sub(r"(?m)^bool (Hacl_[A-Za-z0-9_]+)\(", r"static bool \1(", code)
    code = re.sub(r"(?m)^void\n(Hacl_[A-Za-z0-9_]+)\(", r"static void\n\1(", code)
    code = re.sub(r"(?m)^bool\n(Hacl_[A-Za-z0-9_]+)\(", r"static bool\n\1(", code)
    return code


def adapt_kernel_code(code: str) -> str:
    code = make_helpers_static(code)

    code = code.replace(
        "static inline void\n"
        "point_mul_g_double_vartime(uint64_t *out, uint8_t *scalar1, uint8_t *scalar2, uint64_t *q2)\n",
        "static inline void\n"
        "point_mul_g_double_vartime(\n"
        "  uint64_t *out,\n"
        "  uint8_t *scalar1,\n"
        "  uint8_t *scalar2,\n"
        "  uint64_t *q2,\n"
        "  uint64_t *table2\n"
        ")\n",
    )
    code = code.replace(
        "  uint64_t table2[640U] = { 0U };\n",
        "  memset(table2, 0, ED25519_HACL_SCRATCH_U64 * sizeof(uint64_t));\n",
    )
    code = code.replace(
        "  uint64_t *t0 = table2;",
        "  uint64_t *t0 = table2;",
    )
    code = code.replace(
        "static inline void\n"
        "point_negate_mul_double_g_vartime(\n"
        "  uint64_t *out,\n"
        "  uint8_t *scalar1,\n"
        "  uint8_t *scalar2,\n"
        "  uint64_t *q2\n"
        ")\n",
        "static inline void\n"
        "point_negate_mul_double_g_vartime(\n"
        "  uint64_t *out,\n"
        "  uint8_t *scalar1,\n"
        "  uint8_t *scalar2,\n"
        "  uint64_t *q2,\n"
        "  uint64_t *table2\n"
        ")\n",
    )
    code = code.replace(
        "  point_mul_g_double_vartime(out, scalar1, scalar2, q2_neg);\n",
        "  point_mul_g_double_vartime(out, scalar1, scalar2, q2_neg, table2);\n",
    )

    code = re.sub(
        r"static bool\nHacl_Ed25519_verify\(uint8_t \*public_key, uint32_t msg_len, uint8_t \*msg, uint8_t \*signature\)",
        "bool\ned25519_hacl_verify(\n"
        "  uint8_t *public_key,\n"
        "  uint32_t msg_len,\n"
        "  uint8_t *msg,\n"
        "  uint8_t *signature,\n"
        "  uint64_t *table2\n"
        ")",
        code,
    )
    code = code.replace(
        "      point_negate_mul_double_g_vartime(exp_d, sb, hb, a_);\n",
        "      point_negate_mul_double_g_vartime(exp_d, sb, hb, a_, table2);\n",
    )

    return code


def generated_header(source_commit: str) -> str:
    return f"""// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ed25519 HACL* verifier interface.
 *
 * The implementation is generated from HACL* commit:
 * {source_commit}
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
"""


def generated_source(hacl: Path, source_commit: str) -> str:
    ed = (hacl / "dist/gcc-compatible/Hacl_Ed25519.c").read_text()
    field = (hacl / "dist/gcc-compatible/internal/Hacl_Bignum25519_51.h").read_text()
    curve = (hacl / "dist/gcc-compatible/Hacl_Curve25519_51.c").read_text()
    table = (hacl / "dist/gcc-compatible/internal/Hacl_Ed25519_PrecompTable.h").read_text()

    pieces: list[str] = []
    pieces.append(
        f"""// SPDX-License-Identifier: MIT
/*
 * MIT License
 *
 * Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
 * Copyright (c) 2022-2023 HACL* Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Generated from HACL* commit {source_commit} by
 * kernel/scripts/update-ed25519-hacl.py. The generator imports only the
 * Hacl_Ed25519_verify dependency closure, rewrites SHA-512 to the in-kernel
 * helper, and moves the verifier scratch table into the crypto tfm context.
 */

#include <crypto/sha2.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unaligned.h>

#include "ed25519-hacl.h"

typedef unsigned __int128 FStar_UInt128_uint128;

static inline FStar_UInt128_uint128 FStar_UInt128_add(FStar_UInt128_uint128 a,
\t\t\t\t\t\t      FStar_UInt128_uint128 b)
{{
\treturn a + b;
}}

static inline FStar_UInt128_uint128 FStar_UInt128_add_mod(FStar_UInt128_uint128 a,
\t\t\t\t\t\t\t  FStar_UInt128_uint128 b)
{{
\treturn a + b;
}}

static inline FStar_UInt128_uint128 FStar_UInt128_shift_right(FStar_UInt128_uint128 a,
\t\t\t\t\t\t\t     uint32_t s)
{{
\treturn a >> s;
}}

static inline FStar_UInt128_uint128 FStar_UInt128_uint64_to_uint128(uint64_t a)
{{
\treturn (FStar_UInt128_uint128)a;
}}

static inline uint64_t FStar_UInt128_uint128_to_uint64(FStar_UInt128_uint128 a)
{{
\treturn (uint64_t)a;
}}

static inline FStar_UInt128_uint128 FStar_UInt128_mul_wide(uint64_t a, uint64_t b)
{{
\treturn ((FStar_UInt128_uint128)a) * b;
}}

static noinline uint64_t FStar_UInt64_eq_mask(uint64_t a, uint64_t b)
{{
\tuint64_t x = a ^ b;
\tuint64_t minus_x = ~x + 1ULL;
\tuint64_t x_or_minus_x = x | minus_x;
\tuint64_t xnx = x_or_minus_x >> 63U;

\treturn xnx - 1ULL;
}}

static noinline uint64_t FStar_UInt64_gte_mask(uint64_t a, uint64_t b)
{{
\tuint64_t x = a;
\tuint64_t y = b;
\tuint64_t x_xor_y = x ^ y;
\tuint64_t x_sub_y = x - y;
\tuint64_t x_sub_y_xor_y = x_sub_y ^ y;
\tuint64_t q = x_xor_y | x_sub_y_xor_y;
\tuint64_t x_xor_q = x ^ q;
\tuint64_t x_xor_q_ = x_xor_q >> 63U;

\treturn x_xor_q_ - 1ULL;
}}

static inline uint64_t load64_le(uint8_t *b)
{{
\treturn get_unaligned_le64(b);
}}

static inline uint32_t load32_le(uint8_t *b)
{{
\treturn get_unaligned_le32(b);
}}

static inline void store64_le(uint8_t *b, uint64_t v)
{{
\tput_unaligned_le64(v, b);
}}

static inline void store32_le(uint8_t *b, uint32_t v)
{{
\tput_unaligned_le32(v, b);
}}

#define KRML_MAYBE_UNUSED_VAR(x) ((void)(x))
#define KRML_MAYBE_FOR4(i, z, n, k, x) \\
\tdo {{ for (uint32_t i = (z); i < (n); i += (k)) {{ x }} }} while (0)
#define KRML_MAYBE_FOR5(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)
#define KRML_MAYBE_FOR7(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)
#define KRML_MAYBE_FOR15(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)
#define KRML_MAYBE_FOR16(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)

static inline uint64_t Hacl_Bignum_Lib_bn_get_bits_u64(uint32_t len,
\t\t\t\t\t\t\t       uint64_t *b,
\t\t\t\t\t\t\t       uint32_t i,
\t\t\t\t\t\t\t       uint32_t l)
{{
\tuint32_t i1 = i / 64U;
\tuint32_t j = i % 64U;
\tuint64_t p1 = b[i1] >> j;
\tuint64_t ite;

\tif (i1 + 1U < len && 0U < j)
\t\tite = p1 | b[i1 + 1U] << (64U - j);
\telse
\t\tite = p1;

\treturn ite & ((1ULL << l) - 1ULL);
}}

"""
    )

    pieces.extend(find_definition(field, name) for name in CURVE_FIELD_FUNCTIONS)
    pieces.extend(find_definition(curve, name) for name in CURVE_FUNCTIONS)
    pieces.append(
        find_static_table(
            table, "Hacl_Ed25519_PrecompTable_precomp_basepoint_table_w5"
        )
    )
    for name in ED25519_FUNCTIONS:
        if name == "sha512_pre_pre2_msg":
            pieces.append(SHA512_PRE_PRE2_MSG_KERNEL)
        else:
            pieces.append(find_definition(ed, name))

    return adapt_kernel_code("\n".join(pieces))


def reject_forbidden_output(path: Path) -> None:
    text = path.read_text()
    for pattern in FORBIDDEN_OUTPUT_PATTERNS:
        if pattern in text:
            die(f"forbidden generated Ed25519 signing artifact remains: {pattern}")


def main() -> None:
    hacl, out_dir = parse_args()
    source_commit = hacl_commit(hacl)
    out_dir.mkdir(parents=True, exist_ok=True)

    header_path = out_dir / "ed25519-hacl.h"
    source_path = out_dir / "ed25519-hacl.c"

    header_path.write_text(generated_header(source_commit))
    source_path.write_text(generated_source(hacl, source_commit))
    reject_forbidden_output(source_path)

    print(f"HACL* source commit: {source_commit}")
    print(f"wrote {header_path}")
    print(f"wrote {source_path}")


if __name__ == "__main__":
    main()
