// SPDX-License-Identifier: MIT
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
 * Generated from HACL* commit 504c2987452f87fe44bce9b9f12e19d6e051761f by
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
						      FStar_UInt128_uint128 b)
{
	return a + b;
}

static inline FStar_UInt128_uint128 FStar_UInt128_add_mod(FStar_UInt128_uint128 a,
							  FStar_UInt128_uint128 b)
{
	return a + b;
}

static inline FStar_UInt128_uint128 FStar_UInt128_shift_right(FStar_UInt128_uint128 a,
							     uint32_t s)
{
	return a >> s;
}

static inline FStar_UInt128_uint128 FStar_UInt128_uint64_to_uint128(uint64_t a)
{
	return (FStar_UInt128_uint128)a;
}

static inline uint64_t FStar_UInt128_uint128_to_uint64(FStar_UInt128_uint128 a)
{
	return (uint64_t)a;
}

static inline FStar_UInt128_uint128 FStar_UInt128_mul_wide(uint64_t a, uint64_t b)
{
	return ((FStar_UInt128_uint128)a) * b;
}

static noinline uint64_t FStar_UInt64_eq_mask(uint64_t a, uint64_t b)
{
	uint64_t x = a ^ b;
	uint64_t minus_x = ~x + 1ULL;
	uint64_t x_or_minus_x = x | minus_x;
	uint64_t xnx = x_or_minus_x >> 63U;

	return xnx - 1ULL;
}

static noinline uint64_t FStar_UInt64_gte_mask(uint64_t a, uint64_t b)
{
	uint64_t x = a;
	uint64_t y = b;
	uint64_t x_xor_y = x ^ y;
	uint64_t x_sub_y = x - y;
	uint64_t x_sub_y_xor_y = x_sub_y ^ y;
	uint64_t q = x_xor_y | x_sub_y_xor_y;
	uint64_t x_xor_q = x ^ q;
	uint64_t x_xor_q_ = x_xor_q >> 63U;

	return x_xor_q_ - 1ULL;
}

static inline uint64_t load64_le(uint8_t *b)
{
	return get_unaligned_le64(b);
}

static inline uint32_t load32_le(uint8_t *b)
{
	return get_unaligned_le32(b);
}

static inline void store64_le(uint8_t *b, uint64_t v)
{
	put_unaligned_le64(v, b);
}

static inline void store32_le(uint8_t *b, uint32_t v)
{
	put_unaligned_le32(v, b);
}

#define KRML_MAYBE_UNUSED_VAR(x) ((void)(x))
#define KRML_MAYBE_FOR4(i, z, n, k, x) \
	do { for (uint32_t i = (z); i < (n); i += (k)) { x } } while (0)
#define KRML_MAYBE_FOR5(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)
#define KRML_MAYBE_FOR7(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)
#define KRML_MAYBE_FOR15(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)
#define KRML_MAYBE_FOR16(i, z, n, k, x) KRML_MAYBE_FOR4(i, z, n, k, x)

static inline uint64_t Hacl_Bignum_Lib_bn_get_bits_u64(uint32_t len,
							       uint64_t *b,
							       uint32_t i,
							       uint32_t l)
{
	uint32_t i1 = i / 64U;
	uint32_t j = i % 64U;
	uint64_t p1 = b[i1] >> j;
	uint64_t ite;

	if (i1 + 1U < len && 0U < j)
		ite = p1 | b[i1 + 1U] << (64U - j);
	else
		ite = p1;

	return ite & ((1ULL << l) - 1ULL);
}


static inline void Hacl_Impl_Curve25519_Field51_fadd(uint64_t *out, uint64_t *f1, uint64_t *f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f20 = f2[0U];
  uint64_t f11 = f1[1U];
  uint64_t f21 = f2[1U];
  uint64_t f12 = f1[2U];
  uint64_t f22 = f2[2U];
  uint64_t f13 = f1[3U];
  uint64_t f23 = f2[3U];
  uint64_t f14 = f1[4U];
  uint64_t f24 = f2[4U];
  out[0U] = f10 + f20;
  out[1U] = f11 + f21;
  out[2U] = f12 + f22;
  out[3U] = f13 + f23;
  out[4U] = f14 + f24;
}

static inline void Hacl_Impl_Curve25519_Field51_fsub(uint64_t *out, uint64_t *f1, uint64_t *f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f20 = f2[0U];
  uint64_t f11 = f1[1U];
  uint64_t f21 = f2[1U];
  uint64_t f12 = f1[2U];
  uint64_t f22 = f2[2U];
  uint64_t f13 = f1[3U];
  uint64_t f23 = f2[3U];
  uint64_t f14 = f1[4U];
  uint64_t f24 = f2[4U];
  out[0U] = f10 + 0x3fffffffffff68ULL - f20;
  out[1U] = f11 + 0x3ffffffffffff8ULL - f21;
  out[2U] = f12 + 0x3ffffffffffff8ULL - f22;
  out[3U] = f13 + 0x3ffffffffffff8ULL - f23;
  out[4U] = f14 + 0x3ffffffffffff8ULL - f24;
}

static inline void
Hacl_Impl_Curve25519_Field51_fmul(
  uint64_t *out,
  uint64_t *f1,
  uint64_t *f2,
  FStar_UInt128_uint128 *uu___
)
{
  KRML_MAYBE_UNUSED_VAR(uu___);
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f13 = f1[3U];
  uint64_t f14 = f1[4U];
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  uint64_t f23 = f2[3U];
  uint64_t f24 = f2[4U];
  uint64_t tmp1 = f21 * 19ULL;
  uint64_t tmp2 = f22 * 19ULL;
  uint64_t tmp3 = f23 * 19ULL;
  uint64_t tmp4 = f24 * 19ULL;
  FStar_UInt128_uint128 o00 = FStar_UInt128_mul_wide(f10, f20);
  FStar_UInt128_uint128 o10 = FStar_UInt128_mul_wide(f10, f21);
  FStar_UInt128_uint128 o20 = FStar_UInt128_mul_wide(f10, f22);
  FStar_UInt128_uint128 o30 = FStar_UInt128_mul_wide(f10, f23);
  FStar_UInt128_uint128 o40 = FStar_UInt128_mul_wide(f10, f24);
  FStar_UInt128_uint128 o01 = FStar_UInt128_add(o00, FStar_UInt128_mul_wide(f11, tmp4));
  FStar_UInt128_uint128 o11 = FStar_UInt128_add(o10, FStar_UInt128_mul_wide(f11, f20));
  FStar_UInt128_uint128 o21 = FStar_UInt128_add(o20, FStar_UInt128_mul_wide(f11, f21));
  FStar_UInt128_uint128 o31 = FStar_UInt128_add(o30, FStar_UInt128_mul_wide(f11, f22));
  FStar_UInt128_uint128 o41 = FStar_UInt128_add(o40, FStar_UInt128_mul_wide(f11, f23));
  FStar_UInt128_uint128 o02 = FStar_UInt128_add(o01, FStar_UInt128_mul_wide(f12, tmp3));
  FStar_UInt128_uint128 o12 = FStar_UInt128_add(o11, FStar_UInt128_mul_wide(f12, tmp4));
  FStar_UInt128_uint128 o22 = FStar_UInt128_add(o21, FStar_UInt128_mul_wide(f12, f20));
  FStar_UInt128_uint128 o32 = FStar_UInt128_add(o31, FStar_UInt128_mul_wide(f12, f21));
  FStar_UInt128_uint128 o42 = FStar_UInt128_add(o41, FStar_UInt128_mul_wide(f12, f22));
  FStar_UInt128_uint128 o03 = FStar_UInt128_add(o02, FStar_UInt128_mul_wide(f13, tmp2));
  FStar_UInt128_uint128 o13 = FStar_UInt128_add(o12, FStar_UInt128_mul_wide(f13, tmp3));
  FStar_UInt128_uint128 o23 = FStar_UInt128_add(o22, FStar_UInt128_mul_wide(f13, tmp4));
  FStar_UInt128_uint128 o33 = FStar_UInt128_add(o32, FStar_UInt128_mul_wide(f13, f20));
  FStar_UInt128_uint128 o43 = FStar_UInt128_add(o42, FStar_UInt128_mul_wide(f13, f21));
  FStar_UInt128_uint128 o04 = FStar_UInt128_add(o03, FStar_UInt128_mul_wide(f14, tmp1));
  FStar_UInt128_uint128 o14 = FStar_UInt128_add(o13, FStar_UInt128_mul_wide(f14, tmp2));
  FStar_UInt128_uint128 o24 = FStar_UInt128_add(o23, FStar_UInt128_mul_wide(f14, tmp3));
  FStar_UInt128_uint128 o34 = FStar_UInt128_add(o33, FStar_UInt128_mul_wide(f14, tmp4));
  FStar_UInt128_uint128 o44 = FStar_UInt128_add(o43, FStar_UInt128_mul_wide(f14, f20));
  FStar_UInt128_uint128 tmp_w0 = o04;
  FStar_UInt128_uint128 tmp_w1 = o14;
  FStar_UInt128_uint128 tmp_w2 = o24;
  FStar_UInt128_uint128 tmp_w3 = o34;
  FStar_UInt128_uint128 tmp_w4 = o44;
  FStar_UInt128_uint128 l_ = FStar_UInt128_add(tmp_w0, FStar_UInt128_uint64_to_uint128(0ULL));
  uint64_t tmp01 = FStar_UInt128_uint128_to_uint64(l_) & 0x7ffffffffffffULL;
  uint64_t c0 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_, 51U));
  FStar_UInt128_uint128 l_0 = FStar_UInt128_add(tmp_w1, FStar_UInt128_uint64_to_uint128(c0));
  uint64_t tmp11 = FStar_UInt128_uint128_to_uint64(l_0) & 0x7ffffffffffffULL;
  uint64_t c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_0, 51U));
  FStar_UInt128_uint128 l_1 = FStar_UInt128_add(tmp_w2, FStar_UInt128_uint64_to_uint128(c1));
  uint64_t tmp21 = FStar_UInt128_uint128_to_uint64(l_1) & 0x7ffffffffffffULL;
  uint64_t c2 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_1, 51U));
  FStar_UInt128_uint128 l_2 = FStar_UInt128_add(tmp_w3, FStar_UInt128_uint64_to_uint128(c2));
  uint64_t tmp31 = FStar_UInt128_uint128_to_uint64(l_2) & 0x7ffffffffffffULL;
  uint64_t c3 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_2, 51U));
  FStar_UInt128_uint128 l_3 = FStar_UInt128_add(tmp_w4, FStar_UInt128_uint64_to_uint128(c3));
  uint64_t tmp41 = FStar_UInt128_uint128_to_uint64(l_3) & 0x7ffffffffffffULL;
  uint64_t c4 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_3, 51U));
  uint64_t l_4 = tmp01 + c4 * 19ULL;
  uint64_t tmp0_ = l_4 & 0x7ffffffffffffULL;
  uint64_t c5 = l_4 >> 51U;
  uint64_t o0 = tmp0_;
  uint64_t o1 = tmp11 + c5;
  uint64_t o2 = tmp21;
  uint64_t o3 = tmp31;
  uint64_t o4 = tmp41;
  out[0U] = o0;
  out[1U] = o1;
  out[2U] = o2;
  out[3U] = o3;
  out[4U] = o4;
}

static inline void
Hacl_Impl_Curve25519_Field51_fsqr(uint64_t *out, uint64_t *f, FStar_UInt128_uint128 *uu___)
{
  KRML_MAYBE_UNUSED_VAR(uu___);
  uint64_t f0 = f[0U];
  uint64_t f1 = f[1U];
  uint64_t f2 = f[2U];
  uint64_t f3 = f[3U];
  uint64_t f4 = f[4U];
  uint64_t d0 = 2ULL * f0;
  uint64_t d1 = 2ULL * f1;
  uint64_t d2 = 38ULL * f2;
  uint64_t d3 = 19ULL * f3;
  uint64_t d419 = 19ULL * f4;
  uint64_t d4 = 2ULL * d419;
  FStar_UInt128_uint128
  s0 =
    FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_mul_wide(f0, f0),
        FStar_UInt128_mul_wide(d4, f1)),
      FStar_UInt128_mul_wide(d2, f3));
  FStar_UInt128_uint128
  s1 =
    FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_mul_wide(d0, f1),
        FStar_UInt128_mul_wide(d4, f2)),
      FStar_UInt128_mul_wide(d3, f3));
  FStar_UInt128_uint128
  s2 =
    FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_mul_wide(d0, f2),
        FStar_UInt128_mul_wide(f1, f1)),
      FStar_UInt128_mul_wide(d4, f3));
  FStar_UInt128_uint128
  s3 =
    FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_mul_wide(d0, f3),
        FStar_UInt128_mul_wide(d1, f2)),
      FStar_UInt128_mul_wide(f4, d419));
  FStar_UInt128_uint128
  s4 =
    FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_mul_wide(d0, f4),
        FStar_UInt128_mul_wide(d1, f3)),
      FStar_UInt128_mul_wide(f2, f2));
  FStar_UInt128_uint128 o00 = s0;
  FStar_UInt128_uint128 o10 = s1;
  FStar_UInt128_uint128 o20 = s2;
  FStar_UInt128_uint128 o30 = s3;
  FStar_UInt128_uint128 o40 = s4;
  FStar_UInt128_uint128 l_ = FStar_UInt128_add(o00, FStar_UInt128_uint64_to_uint128(0ULL));
  uint64_t tmp0 = FStar_UInt128_uint128_to_uint64(l_) & 0x7ffffffffffffULL;
  uint64_t c0 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_, 51U));
  FStar_UInt128_uint128 l_0 = FStar_UInt128_add(o10, FStar_UInt128_uint64_to_uint128(c0));
  uint64_t tmp1 = FStar_UInt128_uint128_to_uint64(l_0) & 0x7ffffffffffffULL;
  uint64_t c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_0, 51U));
  FStar_UInt128_uint128 l_1 = FStar_UInt128_add(o20, FStar_UInt128_uint64_to_uint128(c1));
  uint64_t tmp2 = FStar_UInt128_uint128_to_uint64(l_1) & 0x7ffffffffffffULL;
  uint64_t c2 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_1, 51U));
  FStar_UInt128_uint128 l_2 = FStar_UInt128_add(o30, FStar_UInt128_uint64_to_uint128(c2));
  uint64_t tmp3 = FStar_UInt128_uint128_to_uint64(l_2) & 0x7ffffffffffffULL;
  uint64_t c3 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_2, 51U));
  FStar_UInt128_uint128 l_3 = FStar_UInt128_add(o40, FStar_UInt128_uint64_to_uint128(c3));
  uint64_t tmp4 = FStar_UInt128_uint128_to_uint64(l_3) & 0x7ffffffffffffULL;
  uint64_t c4 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(l_3, 51U));
  uint64_t l_4 = tmp0 + c4 * 19ULL;
  uint64_t tmp0_ = l_4 & 0x7ffffffffffffULL;
  uint64_t c5 = l_4 >> 51U;
  uint64_t o0 = tmp0_;
  uint64_t o1 = tmp1 + c5;
  uint64_t o2 = tmp2;
  uint64_t o3 = tmp3;
  uint64_t o4 = tmp4;
  out[0U] = o0;
  out[1U] = o1;
  out[2U] = o2;
  out[3U] = o3;
  out[4U] = o4;
}

static void
Hacl_Curve25519_51_fsquare_times(
  uint64_t *o,
  uint64_t *inp,
  FStar_UInt128_uint128 *tmp,
  uint32_t n
)
{
  Hacl_Impl_Curve25519_Field51_fsqr(o, inp, tmp);
  for (uint32_t i = 0U; i < n - 1U; i++)
  {
    Hacl_Impl_Curve25519_Field51_fsqr(o, o, tmp);
  }
}

static void Hacl_Curve25519_51_finv(uint64_t *o, uint64_t *i, FStar_UInt128_uint128 *tmp)
{
  uint64_t t1[20U] = { 0U };
  uint64_t *a1 = t1;
  uint64_t *b1 = t1 + 5U;
  uint64_t *t010 = t1 + 15U;
  FStar_UInt128_uint128 *tmp10 = tmp;
  Hacl_Curve25519_51_fsquare_times(a1, i, tmp10, 1U);
  Hacl_Curve25519_51_fsquare_times(t010, a1, tmp10, 2U);
  Hacl_Impl_Curve25519_Field51_fmul(b1, t010, i, tmp);
  Hacl_Impl_Curve25519_Field51_fmul(a1, b1, a1, tmp);
  Hacl_Curve25519_51_fsquare_times(t010, a1, tmp10, 1U);
  Hacl_Impl_Curve25519_Field51_fmul(b1, t010, b1, tmp);
  Hacl_Curve25519_51_fsquare_times(t010, b1, tmp10, 5U);
  Hacl_Impl_Curve25519_Field51_fmul(b1, t010, b1, tmp);
  uint64_t *b10 = t1 + 5U;
  uint64_t *c10 = t1 + 10U;
  uint64_t *t011 = t1 + 15U;
  FStar_UInt128_uint128 *tmp11 = tmp;
  Hacl_Curve25519_51_fsquare_times(t011, b10, tmp11, 10U);
  Hacl_Impl_Curve25519_Field51_fmul(c10, t011, b10, tmp);
  Hacl_Curve25519_51_fsquare_times(t011, c10, tmp11, 20U);
  Hacl_Impl_Curve25519_Field51_fmul(t011, t011, c10, tmp);
  Hacl_Curve25519_51_fsquare_times(t011, t011, tmp11, 10U);
  Hacl_Impl_Curve25519_Field51_fmul(b10, t011, b10, tmp);
  Hacl_Curve25519_51_fsquare_times(t011, b10, tmp11, 50U);
  Hacl_Impl_Curve25519_Field51_fmul(c10, t011, b10, tmp);
  uint64_t *b11 = t1 + 5U;
  uint64_t *c1 = t1 + 10U;
  uint64_t *t01 = t1 + 15U;
  FStar_UInt128_uint128 *tmp1 = tmp;
  Hacl_Curve25519_51_fsquare_times(t01, c1, tmp1, 100U);
  Hacl_Impl_Curve25519_Field51_fmul(t01, t01, c1, tmp);
  Hacl_Curve25519_51_fsquare_times(t01, t01, tmp1, 50U);
  Hacl_Impl_Curve25519_Field51_fmul(t01, t01, b11, tmp);
  Hacl_Curve25519_51_fsquare_times(t01, t01, tmp1, 5U);
  uint64_t *a = t1;
  uint64_t *t0 = t1 + 15U;
  Hacl_Impl_Curve25519_Field51_fmul(o, t0, a, tmp);
}

static const
uint64_t
Hacl_Ed25519_PrecompTable_precomp_basepoint_table_w5[640U] =
  {
    0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
    0ULL, 0ULL, 0ULL, 0ULL, 1738742601995546ULL, 1146398526822698ULL, 2070867633025821ULL,
    562264141797630ULL, 587772402128613ULL, 1801439850948184ULL, 1351079888211148ULL,
    450359962737049ULL, 900719925474099ULL, 1801439850948198ULL, 1ULL, 0ULL, 0ULL, 0ULL, 0ULL,
    1841354044333475ULL, 16398895984059ULL, 755974180946558ULL, 900171276175154ULL,
    1821297809914039ULL, 1661154287933054ULL, 284530020860578ULL, 1390261174866914ULL,
    1524110943907984ULL, 1045603498418422ULL, 928651508580478ULL, 1383326941296346ULL,
    961937908925785ULL, 80455759693706ULL, 904734540352947ULL, 1507481815385608ULL,
    2223447444246085ULL, 1083941587175919ULL, 2059929906842505ULL, 1581435440146976ULL,
    782730187692425ULL, 9928394897574ULL, 1539449519985236ULL, 1923587931078510ULL,
    552919286076056ULL, 376925408065760ULL, 447320488831784ULL, 1362918338468019ULL,
    1470031896696846ULL, 2189796996539902ULL, 1337552949959847ULL, 1762287177775726ULL,
    237994495816815ULL, 1277840395970544ULL, 543972849007241ULL, 1224692671618814ULL,
    162359533289271ULL, 282240927125249ULL, 586909166382289ULL, 17726488197838ULL,
    377014554985659ULL, 1433835303052512ULL, 702061469493692ULL, 1142253108318154ULL,
    318297794307551ULL, 954362646308543ULL, 517363881452320ULL, 1868013482130416ULL,
    262562472373260ULL, 902232853249919ULL, 2107343057055746ULL, 462368348619024ULL,
    1893758677092974ULL, 2177729767846389ULL, 2168532543559143ULL, 443867094639821ULL,
    730169342581022ULL, 1564589016879755ULL, 51218195700649ULL, 76684578423745ULL,
    560266272480743ULL, 922517457707697ULL, 2066645939860874ULL, 1318277348414638ULL,
    1576726809084003ULL, 1817337608563665ULL, 1874240939237666ULL, 754733726333910ULL,
    97085310406474ULL, 751148364309235ULL, 1622159695715187ULL, 1444098819684916ULL,
    130920805558089ULL, 1260449179085308ULL, 1860021740768461ULL, 110052860348509ULL,
    193830891643810ULL, 164148413933881ULL, 180017794795332ULL, 1523506525254651ULL,
    465981629225956ULL, 559733514964572ULL, 1279624874416974ULL, 2026642326892306ULL,
    1425156829982409ULL, 2160936383793147ULL, 1061870624975247ULL, 2023497043036941ULL,
    117942212883190ULL, 490339622800774ULL, 1729931303146295ULL, 422305932971074ULL,
    529103152793096ULL, 1211973233775992ULL, 721364955929681ULL, 1497674430438813ULL,
    342545521275073ULL, 2102107575279372ULL, 2108462244669966ULL, 1382582406064082ULL,
    2206396818383323ULL, 2109093268641147ULL, 10809845110983ULL, 1605176920880099ULL,
    744640650753946ULL, 1712758897518129ULL, 373410811281809ULL, 648838265800209ULL,
    813058095530999ULL, 513987632620169ULL, 465516160703329ULL, 2136322186126330ULL,
    1979645899422932ULL, 1197131006470786ULL, 1467836664863979ULL, 1340751381374628ULL,
    1810066212667962ULL, 1009933588225499ULL, 1106129188080873ULL, 1388980405213901ULL,
    533719246598044ULL, 1169435803073277ULL, 198920999285821ULL, 487492330629854ULL,
    1807093008537778ULL, 1540899012923865ULL, 2075080271659867ULL, 1527990806921523ULL,
    1323728742908002ULL, 1568595959608205ULL, 1388032187497212ULL, 2026968840050568ULL,
    1396591153295755ULL, 820416950170901ULL, 520060313205582ULL, 2016404325094901ULL,
    1584709677868520ULL, 272161374469956ULL, 1567188603996816ULL, 1986160530078221ULL,
    553930264324589ULL, 1058426729027503ULL, 8762762886675ULL, 2216098143382988ULL,
    1835145266889223ULL, 1712936431558441ULL, 1017009937844974ULL, 585361667812740ULL,
    2114711541628181ULL, 2238729632971439ULL, 121257546253072ULL, 847154149018345ULL,
    211972965476684ULL, 287499084460129ULL, 2098247259180197ULL, 839070411583329ULL,
    339551619574372ULL, 1432951287640743ULL, 526481249498942ULL, 931991661905195ULL,
    1884279965674487ULL, 200486405604411ULL, 364173020594788ULL, 518034455936955ULL,
    1085564703965501ULL, 16030410467927ULL, 604865933167613ULL, 1695298441093964ULL,
    498856548116159ULL, 2193030062787034ULL, 1706339802964179ULL, 1721199073493888ULL,
    820740951039755ULL, 1216053436896834ULL, 23954895815139ULL, 1662515208920491ULL,
    1705443427511899ULL, 1957928899570365ULL, 1189636258255725ULL, 1795695471103809ULL,
    1691191297654118ULL, 282402585374360ULL, 460405330264832ULL, 63765529445733ULL,
    469763447404473ULL, 733607089694996ULL, 685410420186959ULL, 1096682630419738ULL,
    1162548510542362ULL, 1020949526456676ULL, 1211660396870573ULL, 613126398222696ULL,
    1117829165843251ULL, 742432540886650ULL, 1483755088010658ULL, 942392007134474ULL,
    1447834130944107ULL, 489368274863410ULL, 23192985544898ULL, 648442406146160ULL,
    785438843373876ULL, 249464684645238ULL, 170494608205618ULL, 335112827260550ULL,
    1462050123162735ULL, 1084803668439016ULL, 853459233600325ULL, 215777728187495ULL,
    1965759433526974ULL, 1349482894446537ULL, 694163317612871ULL, 860536766165036ULL,
    1178788094084321ULL, 1652739626626996ULL, 2115723946388185ULL, 1577204379094664ULL,
    1083882859023240ULL, 1768759143381635ULL, 1737180992507258ULL, 246054513922239ULL,
    577253134087234ULL, 356340280578042ULL, 1638917769925142ULL, 223550348130103ULL,
    470592666638765ULL, 22663573966996ULL, 596552461152400ULL, 364143537069499ULL, 3942119457699ULL,
    107951982889287ULL, 1843471406713209ULL, 1625773041610986ULL, 1466141092501702ULL,
    1043024095021271ULL, 310429964047508ULL, 98559121500372ULL, 152746933782868ULL,
    259407205078261ULL, 828123093322585ULL, 1576847274280091ULL, 1170871375757302ULL,
    1588856194642775ULL, 984767822341977ULL, 1141497997993760ULL, 809325345150796ULL,
    1879837728202511ULL, 201340910657893ULL, 1079157558888483ULL, 1052373448588065ULL,
    1732036202501778ULL, 2105292670328445ULL, 679751387312402ULL, 1679682144926229ULL,
    1695823455818780ULL, 498852317075849ULL, 1786555067788433ULL, 1670727545779425ULL,
    117945875433544ULL, 407939139781844ULL, 854632120023778ULL, 1413383148360437ULL,
    286030901733673ULL, 1207361858071196ULL, 461340408181417ULL, 1096919590360164ULL,
    1837594897475685ULL, 533755561544165ULL, 1638688042247712ULL, 1431653684793005ULL,
    1036458538873559ULL, 390822120341779ULL, 1920929837111618ULL, 543426740024168ULL,
    645751357799929ULL, 2245025632994463ULL, 1550778638076452ULL, 223738153459949ULL,
    1337209385492033ULL, 1276967236456531ULL, 1463815821063071ULL, 2070620870191473ULL,
    1199170709413753ULL, 273230877394166ULL, 1873264887608046ULL, 890877152910775ULL,
    983226445635730ULL, 44873798519521ULL, 697147127512130ULL, 961631038239304ULL,
    709966160696826ULL, 1706677689540366ULL, 502782733796035ULL, 812545535346033ULL,
    1693622521296452ULL, 1955813093002510ULL, 1259937612881362ULL, 1873032503803559ULL,
    1140330566016428ULL, 1675726082440190ULL, 60029928909786ULL, 170335608866763ULL,
    766444312315022ULL, 2025049511434113ULL, 2200845622430647ULL, 1201269851450408ULL,
    590071752404907ULL, 1400995030286946ULL, 2152637413853822ULL, 2108495473841983ULL,
    3855406710349ULL, 1726137673168580ULL, 51004317200100ULL, 1749082328586939ULL,
    1704088976144558ULL, 1977318954775118ULL, 2062602253162400ULL, 948062503217479ULL,
    361953965048030ULL, 1528264887238440ULL, 62582552172290ULL, 2241602163389280ULL,
    156385388121765ULL, 2124100319761492ULL, 388928050571382ULL, 1556123596922727ULL,
    979310669812384ULL, 113043855206104ULL, 2023223924825469ULL, 643651703263034ULL,
    2234446903655540ULL, 1577241261424997ULL, 860253174523845ULL, 1691026473082448ULL,
    1091672764933872ULL, 1957463109756365ULL, 530699502660193ULL, 349587141723569ULL,
    674661681919563ULL, 1633727303856240ULL, 708909037922144ULL, 2160722508518119ULL,
    1302188051602540ULL, 976114603845777ULL, 120004758721939ULL, 1681630708873780ULL,
    622274095069244ULL, 1822346309016698ULL, 1100921177951904ULL, 2216952659181677ULL,
    1844020550362490ULL, 1976451368365774ULL, 1321101422068822ULL, 1189859436282668ULL,
    2008801879735257ULL, 2219413454333565ULL, 424288774231098ULL, 359793146977912ULL,
    270293357948703ULL, 587226003677000ULL, 1482071926139945ULL, 1419630774650359ULL,
    1104739070570175ULL, 1662129023224130ULL, 1609203612533411ULL, 1250932720691980ULL,
    95215711818495ULL, 498746909028150ULL, 158151296991874ULL, 1201379988527734ULL,
    561599945143989ULL, 2211577425617888ULL, 2166577612206324ULL, 1057590354233512ULL,
    1968123280416769ULL, 1316586165401313ULL, 762728164447634ULL, 2045395244316047ULL,
    1531796898725716ULL, 315385971670425ULL, 1109421039396756ULL, 2183635256408562ULL,
    1896751252659461ULL, 840236037179080ULL, 796245792277211ULL, 508345890111193ULL,
    1275386465287222ULL, 513560822858784ULL, 1784735733120313ULL, 1346467478899695ULL,
    601125231208417ULL, 701076661112726ULL, 1841998436455089ULL, 1156768600940434ULL,
    1967853462343221ULL, 2178318463061452ULL, 481885520752741ULL, 675262828640945ULL,
    1033539418596582ULL, 1743329872635846ULL, 159322641251283ULL, 1573076470127113ULL,
    954827619308195ULL, 778834750662635ULL, 619912782122617ULL, 515681498488209ULL,
    1675866144246843ULL, 811716020969981ULL, 1125515272217398ULL, 1398917918287342ULL,
    1301680949183175ULL, 726474739583734ULL, 587246193475200ULL, 1096581582611864ULL,
    1469911826213486ULL, 1990099711206364ULL, 1256496099816508ULL, 2019924615195672ULL,
    1251232456707555ULL, 2042971196009755ULL, 214061878479265ULL, 115385726395472ULL,
    1677875239524132ULL, 756888883383540ULL, 1153862117756233ULL, 503391530851096ULL,
    946070017477513ULL, 1878319040542579ULL, 1101349418586920ULL, 793245696431613ULL,
    397920495357645ULL, 2174023872951112ULL, 1517867915189593ULL, 1829855041462995ULL,
    1046709983503619ULL, 424081940711857ULL, 2112438073094647ULL, 1504338467349861ULL,
    2244574127374532ULL, 2136937537441911ULL, 1741150838990304ULL, 25894628400571ULL,
    512213526781178ULL, 1168384260796379ULL, 1424607682379833ULL, 938677789731564ULL,
    872882241891896ULL, 1713199397007700ULL, 1410496326218359ULL, 854379752407031ULL,
    465141611727634ULL, 315176937037857ULL, 1020115054571233ULL, 1856290111077229ULL,
    2028366269898204ULL, 1432980880307543ULL, 469932710425448ULL, 581165267592247ULL,
    496399148156603ULL, 2063435226705903ULL, 2116841086237705ULL, 498272567217048ULL,
    1829438076967906ULL, 1573925801278491ULL, 460763576329867ULL, 1705264723728225ULL,
    999514866082412ULL, 29635061779362ULL, 1884233592281020ULL, 1449755591461338ULL,
    42579292783222ULL, 1869504355369200ULL, 495506004805251ULL, 264073104888427ULL,
    2088880861028612ULL, 104646456386576ULL, 1258445191399967ULL, 1348736801545799ULL,
    2068276361286613ULL, 884897216646374ULL, 922387476801376ULL, 1043886580402805ULL,
    1240883498470831ULL, 1601554651937110ULL, 804382935289482ULL, 512379564477239ULL,
    1466384519077032ULL, 1280698500238386ULL, 211303836685749ULL, 2081725624793803ULL,
    545247644516879ULL, 215313359330384ULL, 286479751145614ULL, 2213650281751636ULL,
    2164927945999874ULL, 2072162991540882ULL, 1443769115444779ULL, 1581473274363095ULL,
    434633875922699ULL, 340456055781599ULL, 373043091080189ULL, 839476566531776ULL,
    1856706858509978ULL, 931616224909153ULL, 1888181317414065ULL, 213654322650262ULL,
    1161078103416244ULL, 1822042328851513ULL, 915817709028812ULL, 1828297056698188ULL,
    1212017130909403ULL, 60258343247333ULL, 342085800008230ULL, 930240559508270ULL,
    1549884999174952ULL, 809895264249462ULL, 184726257947682ULL, 1157065433504828ULL,
    1209999630381477ULL, 999920399374391ULL, 1714770150788163ULL, 2026130985413228ULL,
    506776632883140ULL, 1349042668246528ULL, 1937232292976967ULL, 942302637530730ULL,
    160211904766226ULL, 1042724500438571ULL, 212454865139142ULL, 244104425172642ULL,
    1376990622387496ULL, 76126752421227ULL, 1027540886376422ULL, 1912210655133026ULL,
    13410411589575ULL, 1475856708587773ULL, 615563352691682ULL, 1446629324872644ULL,
    1683670301784014ULL, 1049873327197127ULL, 1826401704084838ULL, 2032577048760775ULL,
    1922203607878853ULL, 836708788764806ULL, 2193084654695012ULL, 1342923183256659ULL,
    849356986294271ULL, 1228863973965618ULL, 94886161081867ULL, 1423288430204892ULL,
    2016167528707016ULL, 1633187660972877ULL, 1550621242301752ULL, 340630244512994ULL,
    2103577710806901ULL, 221625016538931ULL, 421544147350960ULL, 580428704555156ULL,
    1479831381265617ULL, 518057926544698ULL, 955027348790630ULL, 1326749172561598ULL,
    1118304625755967ULL, 1994005916095176ULL, 1799757332780663ULL, 751343129396941ULL,
    1468672898746144ULL, 1451689964451386ULL, 755070293921171ULL, 904857405877052ULL,
    1276087530766984ULL, 403986562858511ULL, 1530661255035337ULL, 1644972908910502ULL,
    1370170080438957ULL, 139839536695744ULL, 909930462436512ULL, 1899999215356933ULL,
    635992381064566ULL, 788740975837654ULL, 224241231493695ULL, 1267090030199302ULL,
    998908061660139ULL, 1784537499699278ULL, 859195370018706ULL, 1953966091439379ULL,
    2189271820076010ULL, 2039067059943978ULL, 1526694380855202ULL, 2040321513194941ULL,
    329922071218689ULL, 1953032256401326ULL, 989631424403521ULL, 328825014934242ULL,
    9407151397696ULL, 63551373671268ULL, 1624728632895792ULL, 1608324920739262ULL,
    1178239350351945ULL, 1198077399579702ULL, 277620088676229ULL, 1775359437312528ULL,
    1653558177737477ULL, 1652066043408850ULL, 1063359889686622ULL, 1975063804860653ULL
  };

static inline void fsum(uint64_t *out, uint64_t *a, uint64_t *b)
{
  Hacl_Impl_Curve25519_Field51_fadd(out, a, b);
}

static inline void fdifference(uint64_t *out, uint64_t *a, uint64_t *b)
{
  Hacl_Impl_Curve25519_Field51_fsub(out, a, b);
}

static void Hacl_Bignum25519_reduce_513(uint64_t *a)
{
  uint64_t f0 = a[0U];
  uint64_t f1 = a[1U];
  uint64_t f2 = a[2U];
  uint64_t f3 = a[3U];
  uint64_t f4 = a[4U];
  uint64_t l_ = f0 + 0ULL;
  uint64_t tmp0 = l_ & 0x7ffffffffffffULL;
  uint64_t c0 = l_ >> 51U;
  uint64_t l_0 = f1 + c0;
  uint64_t tmp1 = l_0 & 0x7ffffffffffffULL;
  uint64_t c1 = l_0 >> 51U;
  uint64_t l_1 = f2 + c1;
  uint64_t tmp2 = l_1 & 0x7ffffffffffffULL;
  uint64_t c2 = l_1 >> 51U;
  uint64_t l_2 = f3 + c2;
  uint64_t tmp3 = l_2 & 0x7ffffffffffffULL;
  uint64_t c3 = l_2 >> 51U;
  uint64_t l_3 = f4 + c3;
  uint64_t tmp4 = l_3 & 0x7ffffffffffffULL;
  uint64_t c4 = l_3 >> 51U;
  uint64_t l_4 = tmp0 + c4 * 19ULL;
  uint64_t tmp0_ = l_4 & 0x7ffffffffffffULL;
  uint64_t c5 = l_4 >> 51U;
  a[0U] = tmp0_;
  a[1U] = tmp1 + c5;
  a[2U] = tmp2;
  a[3U] = tmp3;
  a[4U] = tmp4;
}

static inline void fmul0(uint64_t *output, uint64_t *input, uint64_t *input2)
{
  FStar_UInt128_uint128 tmp[10U];
  for (uint32_t _i = 0U; _i < 10U; ++_i)
    tmp[_i] = FStar_UInt128_uint64_to_uint128(0ULL);
  Hacl_Impl_Curve25519_Field51_fmul(output, input, input2, tmp);
}

static inline void times_2(uint64_t *out, uint64_t *a)
{
  uint64_t a0 = a[0U];
  uint64_t a1 = a[1U];
  uint64_t a2 = a[2U];
  uint64_t a3 = a[3U];
  uint64_t a4 = a[4U];
  uint64_t o0 = 2ULL * a0;
  uint64_t o1 = 2ULL * a1;
  uint64_t o2 = 2ULL * a2;
  uint64_t o3 = 2ULL * a3;
  uint64_t o4 = 2ULL * a4;
  out[0U] = o0;
  out[1U] = o1;
  out[2U] = o2;
  out[3U] = o3;
  out[4U] = o4;
}

static inline void times_d(uint64_t *out, uint64_t *a)
{
  uint64_t d[5U] = { 0U };
  d[0U] = 0x00034dca135978a3ULL;
  d[1U] = 0x0001a8283b156ebdULL;
  d[2U] = 0x0005e7a26001c029ULL;
  d[3U] = 0x000739c663a03cbbULL;
  d[4U] = 0x00052036cee2b6ffULL;
  fmul0(out, d, a);
}

static inline void times_2d(uint64_t *out, uint64_t *a)
{
  uint64_t d2[5U] = { 0U };
  d2[0U] = 0x00069b9426b2f159ULL;
  d2[1U] = 0x00035050762add7aULL;
  d2[2U] = 0x0003cf44c0038052ULL;
  d2[3U] = 0x0006738cc7407977ULL;
  d2[4U] = 0x0002406d9dc56dffULL;
  fmul0(out, d2, a);
}

static inline void fsquare(uint64_t *out, uint64_t *a)
{
  FStar_UInt128_uint128 tmp[5U];
  for (uint32_t _i = 0U; _i < 5U; ++_i)
    tmp[_i] = FStar_UInt128_uint64_to_uint128(0ULL);
  Hacl_Impl_Curve25519_Field51_fsqr(out, a, tmp);
}

static inline void fsquare_times(uint64_t *output, uint64_t *input, uint32_t count)
{
  FStar_UInt128_uint128 tmp[5U];
  for (uint32_t _i = 0U; _i < 5U; ++_i)
    tmp[_i] = FStar_UInt128_uint64_to_uint128(0ULL);
  Hacl_Curve25519_51_fsquare_times(output, input, tmp, count);
}

static inline void fsquare_times_inplace(uint64_t *output, uint32_t count)
{
  FStar_UInt128_uint128 tmp[5U];
  for (uint32_t _i = 0U; _i < 5U; ++_i)
    tmp[_i] = FStar_UInt128_uint64_to_uint128(0ULL);
  Hacl_Curve25519_51_fsquare_times(output, output, tmp, count);
}

static void Hacl_Bignum25519_inverse(uint64_t *out, uint64_t *a)
{
  FStar_UInt128_uint128 tmp[10U];
  for (uint32_t _i = 0U; _i < 10U; ++_i)
    tmp[_i] = FStar_UInt128_uint64_to_uint128(0ULL);
  Hacl_Curve25519_51_finv(out, a, tmp);
}

static inline void reduce(uint64_t *out)
{
  uint64_t o0 = out[0U];
  uint64_t o1 = out[1U];
  uint64_t o2 = out[2U];
  uint64_t o3 = out[3U];
  uint64_t o4 = out[4U];
  uint64_t l_ = o0 + 0ULL;
  uint64_t tmp0 = l_ & 0x7ffffffffffffULL;
  uint64_t c0 = l_ >> 51U;
  uint64_t l_0 = o1 + c0;
  uint64_t tmp1 = l_0 & 0x7ffffffffffffULL;
  uint64_t c1 = l_0 >> 51U;
  uint64_t l_1 = o2 + c1;
  uint64_t tmp2 = l_1 & 0x7ffffffffffffULL;
  uint64_t c2 = l_1 >> 51U;
  uint64_t l_2 = o3 + c2;
  uint64_t tmp3 = l_2 & 0x7ffffffffffffULL;
  uint64_t c3 = l_2 >> 51U;
  uint64_t l_3 = o4 + c3;
  uint64_t tmp4 = l_3 & 0x7ffffffffffffULL;
  uint64_t c4 = l_3 >> 51U;
  uint64_t l_4 = tmp0 + c4 * 19ULL;
  uint64_t tmp0_ = l_4 & 0x7ffffffffffffULL;
  uint64_t c5 = l_4 >> 51U;
  uint64_t f0 = tmp0_;
  uint64_t f1 = tmp1 + c5;
  uint64_t f2 = tmp2;
  uint64_t f3 = tmp3;
  uint64_t f4 = tmp4;
  uint64_t m0 = FStar_UInt64_gte_mask(f0, 0x7ffffffffffedULL);
  uint64_t m1 = FStar_UInt64_eq_mask(f1, 0x7ffffffffffffULL);
  uint64_t m2 = FStar_UInt64_eq_mask(f2, 0x7ffffffffffffULL);
  uint64_t m3 = FStar_UInt64_eq_mask(f3, 0x7ffffffffffffULL);
  uint64_t m4 = FStar_UInt64_eq_mask(f4, 0x7ffffffffffffULL);
  uint64_t mask = (((m0 & m1) & m2) & m3) & m4;
  uint64_t f0_ = f0 - (mask & 0x7ffffffffffedULL);
  uint64_t f1_ = f1 - (mask & 0x7ffffffffffffULL);
  uint64_t f2_ = f2 - (mask & 0x7ffffffffffffULL);
  uint64_t f3_ = f3 - (mask & 0x7ffffffffffffULL);
  uint64_t f4_ = f4 - (mask & 0x7ffffffffffffULL);
  uint64_t f01 = f0_;
  uint64_t f11 = f1_;
  uint64_t f21 = f2_;
  uint64_t f31 = f3_;
  uint64_t f41 = f4_;
  out[0U] = f01;
  out[1U] = f11;
  out[2U] = f21;
  out[3U] = f31;
  out[4U] = f41;
}

static void Hacl_Bignum25519_load_51(uint64_t *output, uint8_t *input)
{
  uint64_t u64s[4U] = { 0U };
  KRML_MAYBE_FOR4(i,
    0U,
    4U,
    1U,
    uint64_t *os = u64s;
    uint8_t *bj = input + i * 8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[i] = x;);
  uint64_t u64s3 = u64s[3U];
  u64s[3U] = u64s3 & 0x7fffffffffffffffULL;
  output[0U] = u64s[0U] & 0x7ffffffffffffULL;
  output[1U] = u64s[0U] >> 51U | (u64s[1U] & 0x3fffffffffULL) << 13U;
  output[2U] = u64s[1U] >> 38U | (u64s[2U] & 0x1ffffffULL) << 26U;
  output[3U] = u64s[2U] >> 25U | (u64s[3U] & 0xfffULL) << 39U;
  output[4U] = u64s[3U] >> 12U;
}

static void Hacl_Impl_Ed25519_PointDouble_point_double(uint64_t *out, uint64_t *p)
{
  uint64_t tmp[20U] = { 0U };
  uint64_t *tmp1 = tmp;
  uint64_t *tmp20 = tmp + 5U;
  uint64_t *tmp30 = tmp + 10U;
  uint64_t *tmp40 = tmp + 15U;
  uint64_t *x10 = p;
  uint64_t *y10 = p + 5U;
  uint64_t *z1 = p + 10U;
  fsquare(tmp1, x10);
  fsquare(tmp20, y10);
  fsum(tmp30, tmp1, tmp20);
  fdifference(tmp40, tmp1, tmp20);
  fsquare(tmp1, z1);
  times_2(tmp1, tmp1);
  uint64_t *tmp10 = tmp;
  uint64_t *tmp2 = tmp + 5U;
  uint64_t *tmp3 = tmp + 10U;
  uint64_t *tmp4 = tmp + 15U;
  uint64_t *x1 = p;
  uint64_t *y1 = p + 5U;
  fsum(tmp2, x1, y1);
  fsquare(tmp2, tmp2);
  Hacl_Bignum25519_reduce_513(tmp3);
  fdifference(tmp2, tmp3, tmp2);
  Hacl_Bignum25519_reduce_513(tmp10);
  Hacl_Bignum25519_reduce_513(tmp4);
  fsum(tmp10, tmp10, tmp4);
  uint64_t *tmp_f = tmp;
  uint64_t *tmp_e = tmp + 5U;
  uint64_t *tmp_h = tmp + 10U;
  uint64_t *tmp_g = tmp + 15U;
  uint64_t *x3 = out;
  uint64_t *y3 = out + 5U;
  uint64_t *z3 = out + 10U;
  uint64_t *t3 = out + 15U;
  fmul0(x3, tmp_e, tmp_f);
  fmul0(y3, tmp_g, tmp_h);
  fmul0(t3, tmp_e, tmp_h);
  fmul0(z3, tmp_f, tmp_g);
}

static void Hacl_Impl_Ed25519_PointAdd_point_add(uint64_t *out, uint64_t *p, uint64_t *q)
{
  uint64_t tmp[30U] = { 0U };
  uint64_t *tmp1 = tmp;
  uint64_t *tmp20 = tmp + 5U;
  uint64_t *tmp30 = tmp + 10U;
  uint64_t *tmp40 = tmp + 15U;
  uint64_t *x1 = p;
  uint64_t *y1 = p + 5U;
  uint64_t *x2 = q;
  uint64_t *y2 = q + 5U;
  fdifference(tmp1, y1, x1);
  fdifference(tmp20, y2, x2);
  fmul0(tmp30, tmp1, tmp20);
  fsum(tmp1, y1, x1);
  fsum(tmp20, y2, x2);
  fmul0(tmp40, tmp1, tmp20);
  uint64_t *tmp10 = tmp;
  uint64_t *tmp2 = tmp + 5U;
  uint64_t *tmp3 = tmp + 10U;
  uint64_t *tmp4 = tmp + 15U;
  uint64_t *tmp5 = tmp + 20U;
  uint64_t *tmp6 = tmp + 25U;
  uint64_t *z1 = p + 10U;
  uint64_t *t1 = p + 15U;
  uint64_t *z2 = q + 10U;
  uint64_t *t2 = q + 15U;
  times_2d(tmp10, t1);
  fmul0(tmp10, tmp10, t2);
  times_2(tmp2, z1);
  fmul0(tmp2, tmp2, z2);
  fdifference(tmp5, tmp4, tmp3);
  fdifference(tmp6, tmp2, tmp10);
  fsum(tmp10, tmp2, tmp10);
  fsum(tmp2, tmp4, tmp3);
  uint64_t *tmp_g = tmp;
  uint64_t *tmp_h = tmp + 5U;
  uint64_t *tmp_e = tmp + 20U;
  uint64_t *tmp_f = tmp + 25U;
  uint64_t *x3 = out;
  uint64_t *y3 = out + 5U;
  uint64_t *z3 = out + 10U;
  uint64_t *t3 = out + 15U;
  fmul0(x3, tmp_e, tmp_f);
  fmul0(y3, tmp_g, tmp_h);
  fmul0(t3, tmp_e, tmp_h);
  fmul0(z3, tmp_f, tmp_g);
}

static void Hacl_Impl_Ed25519_PointConstants_make_point_inf(uint64_t *b)
{
  uint64_t *x = b;
  uint64_t *y = b + 5U;
  uint64_t *z = b + 10U;
  uint64_t *t = b + 15U;
  x[0U] = 0ULL;
  x[1U] = 0ULL;
  x[2U] = 0ULL;
  x[3U] = 0ULL;
  x[4U] = 0ULL;
  y[0U] = 1ULL;
  y[1U] = 0ULL;
  y[2U] = 0ULL;
  y[3U] = 0ULL;
  y[4U] = 0ULL;
  z[0U] = 1ULL;
  z[1U] = 0ULL;
  z[2U] = 0ULL;
  z[3U] = 0ULL;
  z[4U] = 0ULL;
  t[0U] = 0ULL;
  t[1U] = 0ULL;
  t[2U] = 0ULL;
  t[3U] = 0ULL;
  t[4U] = 0ULL;
}

static inline void pow2_252m2(uint64_t *out, uint64_t *z)
{
  uint64_t buf[20U] = { 0U };
  uint64_t *a = buf;
  uint64_t *t00 = buf + 5U;
  uint64_t *b0 = buf + 10U;
  uint64_t *c0 = buf + 15U;
  fsquare_times(a, z, 1U);
  fsquare_times(t00, a, 2U);
  fmul0(b0, t00, z);
  fmul0(a, b0, a);
  fsquare_times(t00, a, 1U);
  fmul0(b0, t00, b0);
  fsquare_times(t00, b0, 5U);
  fmul0(b0, t00, b0);
  fsquare_times(t00, b0, 10U);
  fmul0(c0, t00, b0);
  fsquare_times(t00, c0, 20U);
  fmul0(t00, t00, c0);
  fsquare_times_inplace(t00, 10U);
  fmul0(b0, t00, b0);
  fsquare_times(t00, b0, 50U);
  uint64_t *a0 = buf;
  uint64_t *t0 = buf + 5U;
  uint64_t *b = buf + 10U;
  uint64_t *c = buf + 15U;
  fsquare_times(a0, z, 1U);
  fmul0(c, t0, b);
  fsquare_times(t0, c, 100U);
  fmul0(t0, t0, c);
  fsquare_times_inplace(t0, 50U);
  fmul0(t0, t0, b);
  fsquare_times_inplace(t0, 2U);
  fmul0(out, t0, a0);
}

static inline bool is_0(uint64_t *x)
{
  uint64_t x0 = x[0U];
  uint64_t x1 = x[1U];
  uint64_t x2 = x[2U];
  uint64_t x3 = x[3U];
  uint64_t x4 = x[4U];
  return x0 == 0ULL && x1 == 0ULL && x2 == 0ULL && x3 == 0ULL && x4 == 0ULL;
}

static inline void mul_modp_sqrt_m1(uint64_t *x)
{
  uint64_t sqrt_m1[5U] = { 0U };
  sqrt_m1[0U] = 0x00061b274a0ea0b0ULL;
  sqrt_m1[1U] = 0x0000d5a5fc8f189dULL;
  sqrt_m1[2U] = 0x0007ef5e9cbd0c60ULL;
  sqrt_m1[3U] = 0x00078595a6804c9eULL;
  sqrt_m1[4U] = 0x0002b8324804fc1dULL;
  fmul0(x, x, sqrt_m1);
}

static inline bool recover_x(uint64_t *x, uint64_t *y, uint64_t sign)
{
  uint64_t tmp[15U] = { 0U };
  uint64_t *x2 = tmp;
  uint64_t x00 = y[0U];
  uint64_t x1 = y[1U];
  uint64_t x21 = y[2U];
  uint64_t x30 = y[3U];
  uint64_t x4 = y[4U];
  bool
  b =
    x00 >= 0x7ffffffffffedULL && x1 == 0x7ffffffffffffULL && x21 == 0x7ffffffffffffULL &&
      x30 == 0x7ffffffffffffULL
    && x4 == 0x7ffffffffffffULL;
  bool res;
  if (b)
  {
    res = false;
  }
  else
  {
    uint64_t tmp1[20U] = { 0U };
    uint64_t *one = tmp1;
    uint64_t *y2 = tmp1 + 5U;
    uint64_t *dyyi = tmp1 + 10U;
    uint64_t *dyy = tmp1 + 15U;
    one[0U] = 1ULL;
    one[1U] = 0ULL;
    one[2U] = 0ULL;
    one[3U] = 0ULL;
    one[4U] = 0ULL;
    fsquare(y2, y);
    times_d(dyy, y2);
    fsum(dyy, dyy, one);
    Hacl_Bignum25519_reduce_513(dyy);
    Hacl_Bignum25519_inverse(dyyi, dyy);
    fdifference(x2, y2, one);
    fmul0(x2, x2, dyyi);
    reduce(x2);
    bool x2_is_0 = is_0(x2);
    uint8_t z;
    if (x2_is_0)
    {
      if (sign == 0ULL)
      {
        x[0U] = 0ULL;
        x[1U] = 0ULL;
        x[2U] = 0ULL;
        x[3U] = 0ULL;
        x[4U] = 0ULL;
        z = 1U;
      }
      else
      {
        z = 0U;
      }
    }
    else
    {
      z = 2U;
    }
    if (z == 0U)
    {
      res = false;
    }
    else if (z == 1U)
    {
      res = true;
    }
    else
    {
      uint64_t *x210 = tmp;
      uint64_t *x31 = tmp + 5U;
      uint64_t *t00 = tmp + 10U;
      pow2_252m2(x31, x210);
      fsquare(t00, x31);
      fdifference(t00, t00, x210);
      Hacl_Bignum25519_reduce_513(t00);
      reduce(t00);
      bool t0_is_0 = is_0(t00);
      if (!t0_is_0)
      {
        mul_modp_sqrt_m1(x31);
      }
      uint64_t *x211 = tmp;
      uint64_t *x3 = tmp + 5U;
      uint64_t *t01 = tmp + 10U;
      fsquare(t01, x3);
      fdifference(t01, t01, x211);
      Hacl_Bignum25519_reduce_513(t01);
      reduce(t01);
      bool z1 = is_0(t01);
      if (z1)
      {
        uint64_t *x32 = tmp + 5U;
        uint64_t *t0 = tmp + 10U;
        reduce(x32);
        uint64_t x0 = x32[0U];
        uint64_t x01 = x0 & 1ULL;
        if (!(x01 == sign))
        {
          t0[0U] = 0ULL;
          t0[1U] = 0ULL;
          t0[2U] = 0ULL;
          t0[3U] = 0ULL;
          t0[4U] = 0ULL;
          fdifference(x32, t0, x32);
          Hacl_Bignum25519_reduce_513(x32);
          reduce(x32);
        }
        memcpy(x, x32, 5U * sizeof (uint64_t));
        res = true;
      }
      else
      {
        res = false;
      }
    }
  }
  bool res0 = res;
  return res0;
}

static bool Hacl_Impl_Ed25519_PointDecompress_point_decompress(uint64_t *out, uint8_t *s)
{
  uint64_t tmp[10U] = { 0U };
  uint64_t *y = tmp;
  uint64_t *x = tmp + 5U;
  uint8_t s31 = s[31U];
  uint8_t z = (uint32_t)s31 >> 7U;
  uint64_t sign = (uint64_t)z;
  Hacl_Bignum25519_load_51(y, s);
  bool z0 = recover_x(x, y, sign);
  bool res;
  if (z0)
  {
    uint64_t *outx = out;
    uint64_t *outy = out + 5U;
    uint64_t *outz = out + 10U;
    uint64_t *outt = out + 15U;
    memcpy(outx, x, 5U * sizeof (uint64_t));
    memcpy(outy, y, 5U * sizeof (uint64_t));
    outz[0U] = 1ULL;
    outz[1U] = 0ULL;
    outz[2U] = 0ULL;
    outz[3U] = 0ULL;
    outz[4U] = 0ULL;
    fmul0(outt, x, y);
    res = true;
  }
  else
  {
    res = false;
  }
  bool res0 = res;
  return res0;
}

static inline void barrett_reduction(uint64_t *z, uint64_t *t)
{
  uint64_t t0 = t[0U];
  uint64_t t1 = t[1U];
  uint64_t t2 = t[2U];
  uint64_t t3 = t[3U];
  uint64_t t4 = t[4U];
  uint64_t t5 = t[5U];
  uint64_t t6 = t[6U];
  uint64_t t7 = t[7U];
  uint64_t t8 = t[8U];
  uint64_t t9 = t[9U];
  uint64_t m00 = 0x12631a5cf5d3edULL;
  uint64_t m10 = 0xf9dea2f79cd658ULL;
  uint64_t m20 = 0x000000000014deULL;
  uint64_t m30 = 0x00000000000000ULL;
  uint64_t m40 = 0x00000010000000ULL;
  uint64_t m0 = m00;
  uint64_t m1 = m10;
  uint64_t m2 = m20;
  uint64_t m3 = m30;
  uint64_t m4 = m40;
  uint64_t m010 = 0x9ce5a30a2c131bULL;
  uint64_t m110 = 0x215d086329a7edULL;
  uint64_t m210 = 0xffffffffeb2106ULL;
  uint64_t m310 = 0xffffffffffffffULL;
  uint64_t m410 = 0x00000fffffffffULL;
  uint64_t mu0 = m010;
  uint64_t mu1 = m110;
  uint64_t mu2 = m210;
  uint64_t mu3 = m310;
  uint64_t mu4 = m410;
  uint64_t y_ = (t5 & 0xffffffULL) << 32U;
  uint64_t x_ = t4 >> 24U;
  uint64_t z00 = x_ | y_;
  uint64_t y_0 = (t6 & 0xffffffULL) << 32U;
  uint64_t x_0 = t5 >> 24U;
  uint64_t z10 = x_0 | y_0;
  uint64_t y_1 = (t7 & 0xffffffULL) << 32U;
  uint64_t x_1 = t6 >> 24U;
  uint64_t z20 = x_1 | y_1;
  uint64_t y_2 = (t8 & 0xffffffULL) << 32U;
  uint64_t x_2 = t7 >> 24U;
  uint64_t z30 = x_2 | y_2;
  uint64_t y_3 = (t9 & 0xffffffULL) << 32U;
  uint64_t x_3 = t8 >> 24U;
  uint64_t z40 = x_3 | y_3;
  uint64_t q0 = z00;
  uint64_t q1 = z10;
  uint64_t q2 = z20;
  uint64_t q3 = z30;
  uint64_t q4 = z40;
  FStar_UInt128_uint128 xy000 = FStar_UInt128_mul_wide(q0, mu0);
  FStar_UInt128_uint128 xy010 = FStar_UInt128_mul_wide(q0, mu1);
  FStar_UInt128_uint128 xy020 = FStar_UInt128_mul_wide(q0, mu2);
  FStar_UInt128_uint128 xy030 = FStar_UInt128_mul_wide(q0, mu3);
  FStar_UInt128_uint128 xy040 = FStar_UInt128_mul_wide(q0, mu4);
  FStar_UInt128_uint128 xy100 = FStar_UInt128_mul_wide(q1, mu0);
  FStar_UInt128_uint128 xy110 = FStar_UInt128_mul_wide(q1, mu1);
  FStar_UInt128_uint128 xy120 = FStar_UInt128_mul_wide(q1, mu2);
  FStar_UInt128_uint128 xy130 = FStar_UInt128_mul_wide(q1, mu3);
  FStar_UInt128_uint128 xy14 = FStar_UInt128_mul_wide(q1, mu4);
  FStar_UInt128_uint128 xy200 = FStar_UInt128_mul_wide(q2, mu0);
  FStar_UInt128_uint128 xy210 = FStar_UInt128_mul_wide(q2, mu1);
  FStar_UInt128_uint128 xy220 = FStar_UInt128_mul_wide(q2, mu2);
  FStar_UInt128_uint128 xy23 = FStar_UInt128_mul_wide(q2, mu3);
  FStar_UInt128_uint128 xy24 = FStar_UInt128_mul_wide(q2, mu4);
  FStar_UInt128_uint128 xy300 = FStar_UInt128_mul_wide(q3, mu0);
  FStar_UInt128_uint128 xy310 = FStar_UInt128_mul_wide(q3, mu1);
  FStar_UInt128_uint128 xy32 = FStar_UInt128_mul_wide(q3, mu2);
  FStar_UInt128_uint128 xy33 = FStar_UInt128_mul_wide(q3, mu3);
  FStar_UInt128_uint128 xy34 = FStar_UInt128_mul_wide(q3, mu4);
  FStar_UInt128_uint128 xy400 = FStar_UInt128_mul_wide(q4, mu0);
  FStar_UInt128_uint128 xy41 = FStar_UInt128_mul_wide(q4, mu1);
  FStar_UInt128_uint128 xy42 = FStar_UInt128_mul_wide(q4, mu2);
  FStar_UInt128_uint128 xy43 = FStar_UInt128_mul_wide(q4, mu3);
  FStar_UInt128_uint128 xy44 = FStar_UInt128_mul_wide(q4, mu4);
  FStar_UInt128_uint128 z01 = xy000;
  FStar_UInt128_uint128 z11 = FStar_UInt128_add_mod(xy010, xy100);
  FStar_UInt128_uint128 z21 = FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy020, xy110), xy200);
  FStar_UInt128_uint128
  z31 =
    FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy030, xy120), xy210),
      xy300);
  FStar_UInt128_uint128
  z41 =
    FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy040,
            xy130),
          xy220),
        xy310),
      xy400);
  FStar_UInt128_uint128
  z5 =
    FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy14, xy23), xy32),
      xy41);
  FStar_UInt128_uint128 z6 = FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy24, xy33), xy42);
  FStar_UInt128_uint128 z7 = FStar_UInt128_add_mod(xy34, xy43);
  FStar_UInt128_uint128 z8 = xy44;
  FStar_UInt128_uint128 carry0 = FStar_UInt128_shift_right(z01, 56U);
  FStar_UInt128_uint128 c00 = carry0;
  FStar_UInt128_uint128 carry1 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z11, c00), 56U);
  FStar_UInt128_uint128 c10 = carry1;
  FStar_UInt128_uint128 carry2 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z21, c10), 56U);
  FStar_UInt128_uint128 c20 = carry2;
  FStar_UInt128_uint128 carry3 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z31, c20), 56U);
  FStar_UInt128_uint128 c30 = carry3;
  FStar_UInt128_uint128 carry4 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z41, c30), 56U);
  uint64_t
  t100 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(z41, c30)) & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c40 = carry4;
  uint64_t t410 = t100;
  FStar_UInt128_uint128 carry5 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z5, c40), 56U);
  uint64_t
  t101 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(z5, c40)) & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c5 = carry5;
  uint64_t t51 = t101;
  FStar_UInt128_uint128 carry6 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z6, c5), 56U);
  uint64_t
  t102 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(z6, c5)) & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c6 = carry6;
  uint64_t t61 = t102;
  FStar_UInt128_uint128 carry7 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z7, c6), 56U);
  uint64_t
  t103 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(z7, c6)) & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c7 = carry7;
  uint64_t t71 = t103;
  FStar_UInt128_uint128 carry8 = FStar_UInt128_shift_right(FStar_UInt128_add_mod(z8, c7), 56U);
  uint64_t
  t104 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(z8, c7)) & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c8 = carry8;
  uint64_t t81 = t104;
  uint64_t t91 = FStar_UInt128_uint128_to_uint64(c8);
  uint64_t qmu4_ = t410;
  uint64_t qmu5_ = t51;
  uint64_t qmu6_ = t61;
  uint64_t qmu7_ = t71;
  uint64_t qmu8_ = t81;
  uint64_t qmu9_ = t91;
  uint64_t y_4 = (qmu5_ & 0xffffffffffULL) << 16U;
  uint64_t x_4 = qmu4_ >> 40U;
  uint64_t z02 = x_4 | y_4;
  uint64_t y_5 = (qmu6_ & 0xffffffffffULL) << 16U;
  uint64_t x_5 = qmu5_ >> 40U;
  uint64_t z12 = x_5 | y_5;
  uint64_t y_6 = (qmu7_ & 0xffffffffffULL) << 16U;
  uint64_t x_6 = qmu6_ >> 40U;
  uint64_t z22 = x_6 | y_6;
  uint64_t y_7 = (qmu8_ & 0xffffffffffULL) << 16U;
  uint64_t x_7 = qmu7_ >> 40U;
  uint64_t z32 = x_7 | y_7;
  uint64_t y_8 = (qmu9_ & 0xffffffffffULL) << 16U;
  uint64_t x_8 = qmu8_ >> 40U;
  uint64_t z42 = x_8 | y_8;
  uint64_t qdiv0 = z02;
  uint64_t qdiv1 = z12;
  uint64_t qdiv2 = z22;
  uint64_t qdiv3 = z32;
  uint64_t qdiv4 = z42;
  uint64_t r0 = t0;
  uint64_t r1 = t1;
  uint64_t r2 = t2;
  uint64_t r3 = t3;
  uint64_t r4 = t4 & 0xffffffffffULL;
  FStar_UInt128_uint128 xy00 = FStar_UInt128_mul_wide(qdiv0, m0);
  FStar_UInt128_uint128 xy01 = FStar_UInt128_mul_wide(qdiv0, m1);
  FStar_UInt128_uint128 xy02 = FStar_UInt128_mul_wide(qdiv0, m2);
  FStar_UInt128_uint128 xy03 = FStar_UInt128_mul_wide(qdiv0, m3);
  FStar_UInt128_uint128 xy04 = FStar_UInt128_mul_wide(qdiv0, m4);
  FStar_UInt128_uint128 xy10 = FStar_UInt128_mul_wide(qdiv1, m0);
  FStar_UInt128_uint128 xy11 = FStar_UInt128_mul_wide(qdiv1, m1);
  FStar_UInt128_uint128 xy12 = FStar_UInt128_mul_wide(qdiv1, m2);
  FStar_UInt128_uint128 xy13 = FStar_UInt128_mul_wide(qdiv1, m3);
  FStar_UInt128_uint128 xy20 = FStar_UInt128_mul_wide(qdiv2, m0);
  FStar_UInt128_uint128 xy21 = FStar_UInt128_mul_wide(qdiv2, m1);
  FStar_UInt128_uint128 xy22 = FStar_UInt128_mul_wide(qdiv2, m2);
  FStar_UInt128_uint128 xy30 = FStar_UInt128_mul_wide(qdiv3, m0);
  FStar_UInt128_uint128 xy31 = FStar_UInt128_mul_wide(qdiv3, m1);
  FStar_UInt128_uint128 xy40 = FStar_UInt128_mul_wide(qdiv4, m0);
  FStar_UInt128_uint128 carry9 = FStar_UInt128_shift_right(xy00, 56U);
  uint64_t t105 = FStar_UInt128_uint128_to_uint64(xy00) & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c0 = carry9;
  uint64_t t010 = t105;
  FStar_UInt128_uint128
  carry10 =
    FStar_UInt128_shift_right(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy01, xy10), c0),
      56U);
  uint64_t
  t106 =
    FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy01, xy10), c0)) &
      0xffffffffffffffULL;
  FStar_UInt128_uint128 c11 = carry10;
  uint64_t t110 = t106;
  FStar_UInt128_uint128
  carry11 =
    FStar_UInt128_shift_right(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy02,
            xy11),
          xy20),
        c11),
      56U);
  uint64_t
  t107 =
    FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy02,
            xy11),
          xy20),
        c11))
    & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c21 = carry11;
  uint64_t t210 = t107;
  FStar_UInt128_uint128
  carry =
    FStar_UInt128_shift_right(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy03,
              xy12),
            xy21),
          xy30),
        c21),
      56U);
  uint64_t
  t108 =
    FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy03,
              xy12),
            xy21),
          xy30),
        c21))
    & 0xffffffffffffffULL;
  FStar_UInt128_uint128 c31 = carry;
  uint64_t t310 = t108;
  uint64_t
  t411 =
    FStar_UInt128_uint128_to_uint64(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_add_mod(xy04,
                xy13),
              xy22),
            xy31),
          xy40),
        c31))
    & 0xffffffffffULL;
  uint64_t qmul0 = t010;
  uint64_t qmul1 = t110;
  uint64_t qmul2 = t210;
  uint64_t qmul3 = t310;
  uint64_t qmul4 = t411;
  uint64_t b5 = (r0 - qmul0) >> 63U;
  uint64_t t109 = (b5 << 56U) + r0 - qmul0;
  uint64_t c1 = b5;
  uint64_t t011 = t109;
  uint64_t b6 = (r1 - (qmul1 + c1)) >> 63U;
  uint64_t t1010 = (b6 << 56U) + r1 - (qmul1 + c1);
  uint64_t c2 = b6;
  uint64_t t111 = t1010;
  uint64_t b7 = (r2 - (qmul2 + c2)) >> 63U;
  uint64_t t1011 = (b7 << 56U) + r2 - (qmul2 + c2);
  uint64_t c3 = b7;
  uint64_t t211 = t1011;
  uint64_t b8 = (r3 - (qmul3 + c3)) >> 63U;
  uint64_t t1012 = (b8 << 56U) + r3 - (qmul3 + c3);
  uint64_t c4 = b8;
  uint64_t t311 = t1012;
  uint64_t b9 = (r4 - (qmul4 + c4)) >> 63U;
  uint64_t t1013 = (b9 << 40U) + r4 - (qmul4 + c4);
  uint64_t t412 = t1013;
  uint64_t s0 = t011;
  uint64_t s1 = t111;
  uint64_t s2 = t211;
  uint64_t s3 = t311;
  uint64_t s4 = t412;
  uint64_t m01 = 0x12631a5cf5d3edULL;
  uint64_t m11 = 0xf9dea2f79cd658ULL;
  uint64_t m21 = 0x000000000014deULL;
  uint64_t m31 = 0x00000000000000ULL;
  uint64_t m41 = 0x00000010000000ULL;
  uint64_t y0 = m01;
  uint64_t y1 = m11;
  uint64_t y2 = m21;
  uint64_t y3 = m31;
  uint64_t y4 = m41;
  uint64_t b10 = (s0 - y0) >> 63U;
  uint64_t t1014 = (b10 << 56U) + s0 - y0;
  uint64_t b0 = b10;
  uint64_t t01 = t1014;
  uint64_t b11 = (s1 - (y1 + b0)) >> 63U;
  uint64_t t1015 = (b11 << 56U) + s1 - (y1 + b0);
  uint64_t b1 = b11;
  uint64_t t11 = t1015;
  uint64_t b12 = (s2 - (y2 + b1)) >> 63U;
  uint64_t t1016 = (b12 << 56U) + s2 - (y2 + b1);
  uint64_t b2 = b12;
  uint64_t t21 = t1016;
  uint64_t b13 = (s3 - (y3 + b2)) >> 63U;
  uint64_t t1017 = (b13 << 56U) + s3 - (y3 + b2);
  uint64_t b3 = b13;
  uint64_t t31 = t1017;
  uint64_t b = (s4 - (y4 + b3)) >> 63U;
  uint64_t t10 = (b << 56U) + s4 - (y4 + b3);
  uint64_t b4 = b;
  uint64_t t41 = t10;
  uint64_t mask = b4 - 1ULL;
  uint64_t z03 = s0 ^ (mask & (s0 ^ t01));
  uint64_t z13 = s1 ^ (mask & (s1 ^ t11));
  uint64_t z23 = s2 ^ (mask & (s2 ^ t21));
  uint64_t z33 = s3 ^ (mask & (s3 ^ t31));
  uint64_t z43 = s4 ^ (mask & (s4 ^ t41));
  uint64_t z04 = z03;
  uint64_t z14 = z13;
  uint64_t z24 = z23;
  uint64_t z34 = z33;
  uint64_t z44 = z43;
  uint64_t o0 = z04;
  uint64_t o1 = z14;
  uint64_t o2 = z24;
  uint64_t o3 = z34;
  uint64_t o4 = z44;
  uint64_t z0 = o0;
  uint64_t z1 = o1;
  uint64_t z2 = o2;
  uint64_t z3 = o3;
  uint64_t z4 = o4;
  z[0U] = z0;
  z[1U] = z1;
  z[2U] = z2;
  z[3U] = z3;
  z[4U] = z4;
}

static inline bool gte_q(uint64_t *s)
{
  uint64_t s0 = s[0U];
  uint64_t s1 = s[1U];
  uint64_t s2 = s[2U];
  uint64_t s3 = s[3U];
  uint64_t s4 = s[4U];
  if (s4 > 0x00000010000000ULL)
  {
    return true;
  }
  if (s4 < 0x00000010000000ULL)
  {
    return false;
  }
  if (s3 > 0x00000000000000ULL || s2 > 0x000000000014deULL)
  {
    return true;
  }
  if (s2 < 0x000000000014deULL)
  {
    return false;
  }
  if (s1 > 0xf9dea2f79cd658ULL)
  {
    return true;
  }
  if (s1 < 0xf9dea2f79cd658ULL)
  {
    return false;
  }
  return s0 >= 0x12631a5cf5d3edULL;
}

static inline bool eq(uint64_t *a, uint64_t *b)
{
  uint64_t a0 = a[0U];
  uint64_t a1 = a[1U];
  uint64_t a2 = a[2U];
  uint64_t a3 = a[3U];
  uint64_t a4 = a[4U];
  uint64_t b0 = b[0U];
  uint64_t b1 = b[1U];
  uint64_t b2 = b[2U];
  uint64_t b3 = b[3U];
  uint64_t b4 = b[4U];
  return a0 == b0 && a1 == b1 && a2 == b2 && a3 == b3 && a4 == b4;
}

static bool Hacl_Impl_Ed25519_PointEqual_point_equal(uint64_t *p, uint64_t *q)
{
  uint64_t tmp[20U] = { 0U };
  uint64_t *pxqz = tmp;
  uint64_t *qxpz = tmp + 5U;
  fmul0(pxqz, p, q + 10U);
  reduce(pxqz);
  fmul0(qxpz, q, p + 10U);
  reduce(qxpz);
  bool b = eq(pxqz, qxpz);
  if (b)
  {
    uint64_t *pyqz = tmp + 10U;
    uint64_t *qypz = tmp + 15U;
    fmul0(pyqz, p + 5U, q + 10U);
    reduce(pyqz);
    fmul0(qypz, q + 5U, p + 10U);
    reduce(qypz);
    return eq(pyqz, qypz);
  }
  return false;
}

static void Hacl_Impl_Ed25519_PointNegate_point_negate(uint64_t *p, uint64_t *out)
{
  uint64_t zero[5U] = { 0U };
  zero[0U] = 0ULL;
  zero[1U] = 0ULL;
  zero[2U] = 0ULL;
  zero[3U] = 0ULL;
  zero[4U] = 0ULL;
  uint64_t *x = p;
  uint64_t *y = p + 5U;
  uint64_t *z = p + 10U;
  uint64_t *t = p + 15U;
  uint64_t *x1 = out;
  uint64_t *y1 = out + 5U;
  uint64_t *z1 = out + 10U;
  uint64_t *t1 = out + 15U;
  fdifference(x1, zero, x);
  Hacl_Bignum25519_reduce_513(x1);
  memcpy(y1, y, 5U * sizeof (uint64_t));
  memcpy(z1, z, 5U * sizeof (uint64_t));
  fdifference(t1, zero, t);
  Hacl_Bignum25519_reduce_513(t1);
}

static inline void
point_mul_g_double_vartime(
  uint64_t *out,
  uint8_t *scalar1,
  uint8_t *scalar2,
  uint64_t *q2,
  uint64_t *table2
)
{
  uint64_t tmp[28U] = { 0U };
  uint64_t *g = tmp;
  uint64_t *bscalar1 = tmp + 20U;
  uint64_t *bscalar2 = tmp + 24U;
  uint64_t *gx = g;
  uint64_t *gy = g + 5U;
  uint64_t *gz = g + 10U;
  uint64_t *gt = g + 15U;
  gx[0U] = 0x00062d608f25d51aULL;
  gx[1U] = 0x000412a4b4f6592aULL;
  gx[2U] = 0x00075b7171a4b31dULL;
  gx[3U] = 0x0001ff60527118feULL;
  gx[4U] = 0x000216936d3cd6e5ULL;
  gy[0U] = 0x0006666666666658ULL;
  gy[1U] = 0x0004ccccccccccccULL;
  gy[2U] = 0x0001999999999999ULL;
  gy[3U] = 0x0003333333333333ULL;
  gy[4U] = 0x0006666666666666ULL;
  gz[0U] = 1ULL;
  gz[1U] = 0ULL;
  gz[2U] = 0ULL;
  gz[3U] = 0ULL;
  gz[4U] = 0ULL;
  gt[0U] = 0x00068ab3a5b7dda3ULL;
  gt[1U] = 0x00000eea2a5eadbbULL;
  gt[2U] = 0x0002af8df483c27eULL;
  gt[3U] = 0x000332b375274732ULL;
  gt[4U] = 0x00067875f0fd78b7ULL;
  KRML_MAYBE_FOR4(i,
    0U,
    4U,
    1U,
    uint64_t *os = bscalar1;
    uint8_t *bj = scalar1 + i * 8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[i] = x;);
  KRML_MAYBE_FOR4(i,
    0U,
    4U,
    1U,
    uint64_t *os = bscalar2;
    uint8_t *bj = scalar2 + i * 8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[i] = x;);
  memset(table2, 0, ED25519_HACL_SCRATCH_U64 * sizeof(uint64_t));
  uint64_t tmp1[20U] = { 0U };
  uint64_t *t0 = table2;
  uint64_t *t1 = table2 + 20U;
  Hacl_Impl_Ed25519_PointConstants_make_point_inf(t0);
  memcpy(t1, q2, 20U * sizeof (uint64_t));
  KRML_MAYBE_FOR15(i,
    0U,
    15U,
    1U,
    uint64_t *t11 = table2 + (i + 1U) * 20U;
    Hacl_Impl_Ed25519_PointDouble_point_double(tmp1, t11);
    memcpy(table2 + (2U * i + 2U) * 20U, tmp1, 20U * sizeof (uint64_t));
    uint64_t *t2 = table2 + (2U * i + 2U) * 20U;
    Hacl_Impl_Ed25519_PointAdd_point_add(tmp1, q2, t2);
    memcpy(table2 + (2U * i + 3U) * 20U, tmp1, 20U * sizeof (uint64_t)););
  uint64_t tmp10[20U] = { 0U };
  uint32_t i0 = 255U;
  uint64_t bits_c = Hacl_Bignum_Lib_bn_get_bits_u64(4U, bscalar1, i0, 5U);
  uint32_t bits_l32 = (uint32_t)bits_c;
  const
  uint64_t
  *a_bits_l = Hacl_Ed25519_PrecompTable_precomp_basepoint_table_w5 + bits_l32 * 20U;
  memcpy(out, (uint64_t *)a_bits_l, 20U * sizeof (uint64_t));
  uint32_t i1 = 255U;
  uint64_t bits_c0 = Hacl_Bignum_Lib_bn_get_bits_u64(4U, bscalar2, i1, 5U);
  uint32_t bits_l320 = (uint32_t)bits_c0;
  const uint64_t *a_bits_l0 = table2 + bits_l320 * 20U;
  memcpy(tmp10, (uint64_t *)a_bits_l0, 20U * sizeof (uint64_t));
  Hacl_Impl_Ed25519_PointAdd_point_add(out, out, tmp10);
  uint64_t tmp11[20U] = { 0U };
  for (uint32_t i = 0U; i < 51U; i++)
  {
    KRML_MAYBE_FOR5(i2, 0U, 5U, 1U, Hacl_Impl_Ed25519_PointDouble_point_double(out, out););
    uint32_t k = 255U - 5U * i - 5U;
    uint64_t bits_l = Hacl_Bignum_Lib_bn_get_bits_u64(4U, bscalar2, k, 5U);
    uint32_t bits_l321 = (uint32_t)bits_l;
    const uint64_t *a_bits_l1 = table2 + bits_l321 * 20U;
    memcpy(tmp11, (uint64_t *)a_bits_l1, 20U * sizeof (uint64_t));
    Hacl_Impl_Ed25519_PointAdd_point_add(out, out, tmp11);
    uint32_t k0 = 255U - 5U * i - 5U;
    uint64_t bits_l0 = Hacl_Bignum_Lib_bn_get_bits_u64(4U, bscalar1, k0, 5U);
    uint32_t bits_l322 = (uint32_t)bits_l0;
    const
    uint64_t
    *a_bits_l2 = Hacl_Ed25519_PrecompTable_precomp_basepoint_table_w5 + bits_l322 * 20U;
    memcpy(tmp11, (uint64_t *)a_bits_l2, 20U * sizeof (uint64_t));
    Hacl_Impl_Ed25519_PointAdd_point_add(out, out, tmp11);
  }
}

static inline void
point_negate_mul_double_g_vartime(
  uint64_t *out,
  uint8_t *scalar1,
  uint8_t *scalar2,
  uint64_t *q2,
  uint64_t *table2
)
{
  uint64_t q2_neg[20U] = { 0U };
  Hacl_Impl_Ed25519_PointNegate_point_negate(q2, q2_neg);
  point_mul_g_double_vartime(out, scalar1, scalar2, q2_neg, table2);
}

static inline void store_56(uint8_t *out, uint64_t *b)
{
  uint64_t b0 = b[0U];
  uint64_t b1 = b[1U];
  uint64_t b2 = b[2U];
  uint64_t b3 = b[3U];
  uint64_t b4 = b[4U];
  uint32_t b4_ = (uint32_t)b4;
  uint8_t *b8 = out;
  store64_le(b8, b0);
  uint8_t *b80 = out + 7U;
  store64_le(b80, b1);
  uint8_t *b81 = out + 14U;
  store64_le(b81, b2);
  uint8_t *b82 = out + 21U;
  store64_le(b82, b3);
  store32_le(out + 28U, b4_);
}

static inline void load_64_bytes(uint64_t *out, uint8_t *b)
{
  uint8_t *b80 = b;
  uint64_t u = load64_le(b80);
  uint64_t z = u;
  uint64_t b0 = z & 0xffffffffffffffULL;
  uint8_t *b81 = b + 7U;
  uint64_t u0 = load64_le(b81);
  uint64_t z0 = u0;
  uint64_t b1 = z0 & 0xffffffffffffffULL;
  uint8_t *b82 = b + 14U;
  uint64_t u1 = load64_le(b82);
  uint64_t z1 = u1;
  uint64_t b2 = z1 & 0xffffffffffffffULL;
  uint8_t *b83 = b + 21U;
  uint64_t u2 = load64_le(b83);
  uint64_t z2 = u2;
  uint64_t b3 = z2 & 0xffffffffffffffULL;
  uint8_t *b84 = b + 28U;
  uint64_t u3 = load64_le(b84);
  uint64_t z3 = u3;
  uint64_t b4 = z3 & 0xffffffffffffffULL;
  uint8_t *b85 = b + 35U;
  uint64_t u4 = load64_le(b85);
  uint64_t z4 = u4;
  uint64_t b5 = z4 & 0xffffffffffffffULL;
  uint8_t *b86 = b + 42U;
  uint64_t u5 = load64_le(b86);
  uint64_t z5 = u5;
  uint64_t b6 = z5 & 0xffffffffffffffULL;
  uint8_t *b87 = b + 49U;
  uint64_t u6 = load64_le(b87);
  uint64_t z6 = u6;
  uint64_t b7 = z6 & 0xffffffffffffffULL;
  uint8_t *b8 = b + 56U;
  uint64_t u7 = load64_le(b8);
  uint64_t z7 = u7;
  uint64_t b88 = z7 & 0xffffffffffffffULL;
  uint8_t b63 = b[63U];
  uint64_t b9 = (uint64_t)b63;
  out[0U] = b0;
  out[1U] = b1;
  out[2U] = b2;
  out[3U] = b3;
  out[4U] = b4;
  out[5U] = b5;
  out[6U] = b6;
  out[7U] = b7;
  out[8U] = b88;
  out[9U] = b9;
}

static inline void load_32_bytes(uint64_t *out, uint8_t *b)
{
  uint8_t *b80 = b;
  uint64_t u0 = load64_le(b80);
  uint64_t z = u0;
  uint64_t b0 = z & 0xffffffffffffffULL;
  uint8_t *b81 = b + 7U;
  uint64_t u1 = load64_le(b81);
  uint64_t z0 = u1;
  uint64_t b1 = z0 & 0xffffffffffffffULL;
  uint8_t *b82 = b + 14U;
  uint64_t u2 = load64_le(b82);
  uint64_t z1 = u2;
  uint64_t b2 = z1 & 0xffffffffffffffULL;
  uint8_t *b8 = b + 21U;
  uint64_t u3 = load64_le(b8);
  uint64_t z2 = u3;
  uint64_t b3 = z2 & 0xffffffffffffffULL;
  uint32_t u = load32_le(b + 28U);
  uint32_t b4 = u;
  uint64_t b41 = (uint64_t)b4;
  out[0U] = b0;
  out[1U] = b1;
  out[2U] = b2;
  out[3U] = b3;
  out[4U] = b41;
}

static inline void
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

static inline void
sha512_modq_pre_pre2(
  uint64_t *out,
  uint8_t *prefix,
  uint8_t *prefix2,
  uint32_t len,
  uint8_t *input
)
{
  uint64_t tmp[10U] = { 0U };
  uint8_t hash[64U] = { 0U };
  sha512_pre_pre2_msg(hash, prefix, prefix2, len, input);
  load_64_bytes(tmp, hash);
  barrett_reduction(out, tmp);
}

bool
ed25519_hacl_verify(
  uint8_t *public_key,
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *signature,
  uint64_t *table2
)
{
  uint64_t a_[20U] = { 0U };
  bool b = Hacl_Impl_Ed25519_PointDecompress_point_decompress(a_, public_key);
  if (b)
  {
    uint64_t r_[20U] = { 0U };
    uint8_t *rs = signature;
    bool b_ = Hacl_Impl_Ed25519_PointDecompress_point_decompress(r_, rs);
    if (b_)
    {
      uint8_t hb[32U] = { 0U };
      uint8_t *rs1 = signature;
      uint8_t *sb = signature + 32U;
      uint64_t tmp[5U] = { 0U };
      load_32_bytes(tmp, sb);
      bool b1 = gte_q(tmp);
      bool b10 = b1;
      if (b10)
      {
        return false;
      }
      uint64_t tmp0[5U] = { 0U };
      sha512_modq_pre_pre2(tmp0, rs1, public_key, msg_len, msg);
      store_56(hb, tmp0);
      uint64_t exp_d[20U] = { 0U };
      point_negate_mul_double_g_vartime(exp_d, sb, hb, a_, table2);
      bool b2 = Hacl_Impl_Ed25519_PointEqual_point_equal(exp_d, r_);
      return b2;
    }
    return false;
  }
  return false;
}
