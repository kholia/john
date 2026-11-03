/*
 * Shared bitslice implementation of the Lotus Notes/Domino hash core for
 * lotus5, dominosec and dominosec8 (openwall/john issue #5451).
 *
 * The S-box (lotus_magic_table) is implemented in bitslice as 3-input LUT
 * expressions by src/lotus_sboxes.h.  All of the hash algorithms here use
 * the S-box in two modes:
 *
 *   XOR mode:  out = T[b ^ t]  (lotus_transform_password, checksum update)
 *   ADD mode:  out = T[j + t]  (mix loops, j a per-position constant
 *              counting down from 48 to 1)
 *
 * The ADD mode requires an addition of a compile-time constant before the
 * S-box, implemented with a carry chain that is one vector op per bit.
 *
 * Vector types and lane layout follow the DES bitslice implementation
 * (DES_bs_b.c): one lane per bit of the vector, thus LOTUS_BS_DEPTH
 * candidates are processed in parallel.  Lane l of vector v is bit l of
 * the vector in memory (little-endian), where l = candidate index.
 *
 * This file is a *_plug.c (auto-built, not a format itself).
 */

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "lotus_common.h"

#if defined(__GNUC__) || defined(__clang__)
#define LOTUS_NOINLINE __attribute__((noinline))
#else
#define LOTUS_NOINLINE
#endif

/*
 * Vector types and elementary ops.
 */
#if defined(__AVX512F__) && !defined(JOHN_NO_SIMD)
#include <immintrin.h>

typedef __m512i vtype;
#define VZERO()			_mm512_setzero_si512()
#define VONES()			_mm512_set1_epi32(-1)
#define VNOT(a)			_mm512_xor_si512((a), VONES())
#define VXOR(a, b)		_mm512_xor_si512((a), (b))
#define VAND(a, b)		_mm512_and_si512((a), (b))
#define VOR(a, b)		_mm512_or_si512((a), (b))
#define VANDN(a, b)		_mm512_andnot_si512((b), (a)) /* a and not b */
#define VLUT3(a, b, c, imm)	_mm512_ternarylogic_epi32((a), (b), (c), (imm))
/* use the LUT3 variant of the S-box expressions (one VPTERNLOG per node) */
#define LOTUS_SBOX_LUT3		1

#elif defined(__AVX2__) && !defined(JOHN_NO_SIMD)
#include <immintrin.h>

typedef __m256i vtype;
#define VZERO()			_mm256_setzero_si256()
#define VONES()			_mm256_set1_epi32(-1)
#define VNOT(a)			_mm256_xor_si256((a), VONES())
#define VXOR(a, b)		_mm256_xor_si256((a), (b))
#define VAND(a, b)		_mm256_and_si256((a), (b))
#define VOR(a, b)		_mm256_or_si256((a), (b))
#define VANDN(a, b)		_mm256_andnot_si256((b), (a))

#elif (defined(__SSE2__) || defined(__ARM_NEON)) && !defined(JOHN_NO_SIMD)
#ifdef __SSE2__
#include <emmintrin.h>
typedef __m128i vtype;
#define VZERO()			_mm_setzero_si128()
#define VONES()			_mm_set1_epi32(-1)
#define VNOT(a)			_mm_xor_si128((a), VONES())
#define VXOR(a, b)		_mm_xor_si128((a), (b))
#define VAND(a, b)		_mm_and_si128((a), (b))
#define VOR(a, b)		_mm_or_si128((a), (b))
#define VANDN(a, b)		_mm_andnot_si128((b), (a))
#else
#include <arm_neon.h>
typedef uint32x4_t vtype;
#define VZERO()			vdupq_n_u32(0)
#define VONES()			vdupq_n_u32(~0u)
#define VNOT(a)			vmvnq_u32(a)
#define VXOR(a, b)		veorq_u32((a), (b))
#define VAND(a, b)		vandq_u32((a), (b))
#define VOR(a, b)		vorrq_u32((a), (b))
#define VANDN(a, b)		vbicq_u32((a), (b))
#endif

#else
/* Portable fallback: 64-bit machine words */
typedef uint64_t vtype;
#define VZERO()			((vtype)0)
#define VONES()			(~(vtype)0)
#define VNOT(a)			(~(a))
#define VXOR(a, b)		((a) ^ (b))
#define VAND(a, b)		((a) & (b))
#define VOR(a, b)		((a) | (b))
#define VANDN(a, b)		((a) & ~(b))
#endif

#include "lotus_sboxes.h"

/* A vector seen as an array of lane-group words (lane l is bit l). */
typedef union {
	vtype		v;
	uint64_t	u64[sizeof(vtype) / 8];
	uint32_t	u32[sizeof(vtype) / 4];
	uint16_t	u16[sizeof(vtype) / 2];
	unsigned char	u8[sizeof(vtype)];
} lotus_bs_vec;

const unsigned char lotus_magic_table[304] = {
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
	0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
	0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
	0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
	0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
	0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
	0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
	0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
	0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
	0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
	0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
	0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
	0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
	0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
	0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
	0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
	0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
	0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
	0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
	0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
	0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
	0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
	0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
	0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
	0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
	0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
	0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
	0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
	0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
	0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
	0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,

	/* double power! */
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
	0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
	0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
	0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
	0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36
};

/*
 * u[8] = a[8] + J (mod 256), J a compile-time constant.
 * Sum bit k is a_k ^ J_k ^ carry_k, where the carry is an AND (J bit 0)
 * or OR (J bit 1) of a_k and the incoming carry.
 */
#define LOTUS_XORC(x, b)	((b) ? VNOT(x) : (x))

#define LOTUS_BS_ADD(U0, U1, U2, U3, U4, U5, U6, U7, \
    A0, A1, A2, A3, A4, A5, A6, A7, J) do { \
	vtype c_; \
	U0 = LOTUS_XORC(A0, (J) & 1); \
	c_ = ((J) & 1) ? (A0) : VZERO(); \
	U1 = VXOR(LOTUS_XORC(A1, ((J) >> 1) & 1), c_); \
	c_ = (((J) >> 1) & 1) ? VOR(A1, c_) : VAND(A1, c_); \
	U2 = VXOR(LOTUS_XORC(A2, ((J) >> 2) & 1), c_); \
	c_ = (((J) >> 2) & 1) ? VOR(A2, c_) : VAND(A2, c_); \
	U3 = VXOR(LOTUS_XORC(A3, ((J) >> 3) & 1), c_); \
	c_ = (((J) >> 3) & 1) ? VOR(A3, c_) : VAND(A3, c_); \
	U4 = VXOR(LOTUS_XORC(A4, ((J) >> 4) & 1), c_); \
	c_ = (((J) >> 4) & 1) ? VOR(A4, c_) : VAND(A4, c_); \
	U5 = VXOR(LOTUS_XORC(A5, ((J) >> 5) & 1), c_); \
	c_ = (((J) >> 5) & 1) ? VOR(A5, c_) : VAND(A5, c_); \
	U6 = VXOR(LOTUS_XORC(A6, ((J) >> 6) & 1), c_); \
	c_ = (((J) >> 6) & 1) ? VOR(A6, c_) : VAND(A6, c_); \
	U7 = VXOR(LOTUS_XORC(A7, (J) >> 7), c_); \
} while (0)

/*
 * One mix step: m[I] ^= S(t + J); t = m[I].  (J counts down from 48 as
 * I counts up from 0, matching the reference scalar code.)
 */
#define LOTUS_BS_STEP(M, I, J) do { \
	vtype u0, u1, u2, u3, u4, u5, u6, u7; \
	vtype z0, z1, z2, z3, z4, z5, z6, z7; \
	LOTUS_BS_ADD(u0, u1, u2, u3, u4, u5, u6, u7, \
	    t0, t1, t2, t3, t4, t5, t6, t7, J); \
	lotus_sbox(u0, u1, u2, u3, u4, u5, u6, u7, \
	    &z0, &z1, &z2, &z3, &z4, &z5, &z6, &z7); \
	t0 = M[I][0] = VXOR(M[I][0], z0); \
	t1 = M[I][1] = VXOR(M[I][1], z1); \
	t2 = M[I][2] = VXOR(M[I][2], z2); \
	t3 = M[I][3] = VXOR(M[I][3], z3); \
	t4 = M[I][4] = VXOR(M[I][4], z4); \
	t5 = M[I][5] = VXOR(M[I][5], z5); \
	t6 = M[I][6] = VXOR(M[I][6], z6); \
	t7 = M[I][7] = VXOR(M[I][7], z7); \
} while (0)

#define LOTUS_BS_MIX48(M) \
	LOTUS_BS_STEP(M, 0, 48); \
	LOTUS_BS_STEP(M, 1, 47); \
	LOTUS_BS_STEP(M, 2, 46); \
	LOTUS_BS_STEP(M, 3, 45); \
	LOTUS_BS_STEP(M, 4, 44); \
	LOTUS_BS_STEP(M, 5, 43); \
	LOTUS_BS_STEP(M, 6, 42); \
	LOTUS_BS_STEP(M, 7, 41); \
	LOTUS_BS_STEP(M, 8, 40); \
	LOTUS_BS_STEP(M, 9, 39); \
	LOTUS_BS_STEP(M, 10, 38); \
	LOTUS_BS_STEP(M, 11, 37); \
	LOTUS_BS_STEP(M, 12, 36); \
	LOTUS_BS_STEP(M, 13, 35); \
	LOTUS_BS_STEP(M, 14, 34); \
	LOTUS_BS_STEP(M, 15, 33); \
	LOTUS_BS_STEP(M, 16, 32); \
	LOTUS_BS_STEP(M, 17, 31); \
	LOTUS_BS_STEP(M, 18, 30); \
	LOTUS_BS_STEP(M, 19, 29); \
	LOTUS_BS_STEP(M, 20, 28); \
	LOTUS_BS_STEP(M, 21, 27); \
	LOTUS_BS_STEP(M, 22, 26); \
	LOTUS_BS_STEP(M, 23, 25); \
	LOTUS_BS_STEP(M, 24, 24); \
	LOTUS_BS_STEP(M, 25, 23); \
	LOTUS_BS_STEP(M, 26, 22); \
	LOTUS_BS_STEP(M, 27, 21); \
	LOTUS_BS_STEP(M, 28, 20); \
	LOTUS_BS_STEP(M, 29, 19); \
	LOTUS_BS_STEP(M, 30, 18); \
	LOTUS_BS_STEP(M, 31, 17); \
	LOTUS_BS_STEP(M, 32, 16); \
	LOTUS_BS_STEP(M, 33, 15); \
	LOTUS_BS_STEP(M, 34, 14); \
	LOTUS_BS_STEP(M, 35, 13); \
	LOTUS_BS_STEP(M, 36, 12); \
	LOTUS_BS_STEP(M, 37, 11); \
	LOTUS_BS_STEP(M, 38, 10); \
	LOTUS_BS_STEP(M, 39, 9); \
	LOTUS_BS_STEP(M, 40, 8); \
	LOTUS_BS_STEP(M, 41, 7); \
	LOTUS_BS_STEP(M, 42, 6); \
	LOTUS_BS_STEP(M, 43, 5); \
	LOTUS_BS_STEP(M, 44, 4); \
	LOTUS_BS_STEP(M, 45, 3); \
	LOTUS_BS_STEP(M, 46, 2); \
	LOTUS_BS_STEP(M, 47, 1);

/*
 * lotus5's lotus_mix(): 18 passes over the first 48 bytes of the matrix,
 * with the S-box chain value t carried across passes.
 */
static void lotus_bs_mix(vtype m[48][8])
{
	vtype t0 = VZERO(), t1 = VZERO(), t2 = VZERO(), t3 = VZERO(),
	    t4 = VZERO(), t5 = VZERO(), t6 = VZERO(), t7 = VZERO();
	int i;

	for (i = 0; i < 18; i++) {
		LOTUS_BS_MIX48(m);
	}
}

/*
 * dominosec's mdtransform_norecalc(), bitsliced.  One 48-step feed-in
 * producing x, 16 passes of the mix over x (t carried through from the
 * feed-in), one 16-step feed-out updating the state.
 */
static void lotus_bs_mdtransform_norecalc(vtype state[16][8], vtype block[16][8])
{
	vtype x[48][8];
	vtype t0 = VZERO(), t1 = VZERO(), t2 = VZERO(), t3 = VZERO(),
	    t4 = VZERO(), t5 = VZERO(), t6 = VZERO(), t7 = VZERO();
	int i;

	/*
	 * Feed-in (48 steps), mix (16 passes over x), feed-out (16 steps).
	 * Positions/sources follow mdtransform_norecalc_1() exactly:
	 * 0..15 = state, 16..31 = block, 32..47 = state ^ block, with
	 * j = 48 - I counting down; feed-out j = 48 - I for I = 0..15.
	 */
#define SRCBYTE(I, k) \
	((I) < 16 ? state[I][k] : \
	 ((I) < 32 ? block[I - 16][k] : \
	  VXOR(state[I - 32][k], block[I - 32][k])))
#define FEED(I) do { \
	vtype u0, u1, u2, u3, u4, u5, u6, u7; \
	vtype z0, z1, z2, z3, z4, z5, z6, z7; \
	LOTUS_BS_ADD(u0, u1, u2, u3, u4, u5, u6, u7, \
	    t0, t1, t2, t3, t4, t5, t6, t7, 48 - (I)); \
	lotus_sbox(u0, u1, u2, u3, u4, u5, u6, u7, \
	    &z0, &z1, &z2, &z3, &z4, &z5, &z6, &z7); \
	t0 = VXOR(SRCBYTE(I, 0), z0); x[I][0] = t0; \
	t1 = VXOR(SRCBYTE(I, 1), z1); x[I][1] = t1; \
	t2 = VXOR(SRCBYTE(I, 2), z2); x[I][2] = t2; \
	t3 = VXOR(SRCBYTE(I, 3), z3); x[I][3] = t3; \
	t4 = VXOR(SRCBYTE(I, 4), z4); x[I][4] = t4; \
	t5 = VXOR(SRCBYTE(I, 5), z5); x[I][5] = t5; \
	t6 = VXOR(SRCBYTE(I, 6), z6); x[I][6] = t6; \
	t7 = VXOR(SRCBYTE(I, 7), z7); x[I][7] = t7; \
} while (0)

	FEED(0); FEED(1); FEED(2); FEED(3); FEED(4); FEED(5); FEED(6); FEED(7);
	FEED(8); FEED(9); FEED(10); FEED(11); FEED(12); FEED(13); FEED(14); FEED(15);
	FEED(16); FEED(17); FEED(18); FEED(19); FEED(20); FEED(21); FEED(22); FEED(23);
	FEED(24); FEED(25); FEED(26); FEED(27); FEED(28); FEED(29); FEED(30); FEED(31);
	FEED(32); FEED(33); FEED(34); FEED(35); FEED(36); FEED(37); FEED(38); FEED(39);
	FEED(40); FEED(41); FEED(42); FEED(43); FEED(44); FEED(45); FEED(46); FEED(47);
#undef SRCBYTE
#undef FEED

	for (i = 0; i < 16; i++) {
		LOTUS_BS_MIX48(x);
	}

#define OUT(I) do { \
	vtype u0, u1, u2, u3, u4, u5, u6, u7; \
	vtype z0, z1, z2, z3, z4, z5, z6, z7; \
	LOTUS_BS_ADD(u0, u1, u2, u3, u4, u5, u6, u7, \
	    t0, t1, t2, t3, t4, t5, t6, t7, 48 - (I)); \
	lotus_sbox(u0, u1, u2, u3, u4, u5, u6, u7, \
	    &z0, &z1, &z2, &z3, &z4, &z5, &z6, &z7); \
	t0 = state[I][0] = VXOR(x[I][0], z0); \
	t1 = state[I][1] = VXOR(x[I][1], z1); \
	t2 = state[I][2] = VXOR(x[I][2], z2); \
	t3 = state[I][3] = VXOR(x[I][3], z3); \
	t4 = state[I][4] = VXOR(x[I][4], z4); \
	t5 = state[I][5] = VXOR(x[I][5], z5); \
	t6 = state[I][6] = VXOR(x[I][6], z6); \
	t7 = state[I][7] = VXOR(x[I][7], z7); \
} while (0)

	OUT(0); OUT(1); OUT(2); OUT(3); OUT(4); OUT(5); OUT(6); OUT(7);
	OUT(8); OUT(9); OUT(10); OUT(11); OUT(12); OUT(13); OUT(14); OUT(15);
#undef OUT
}

/*
 * dominosec's mdtransform(): norecalc + checksum update over the block.
 */
static void lotus_bs_mdtransform(vtype state[16][8], vtype checksum[16][8],
    vtype block[16][8])
{
	int i, k;

	lotus_bs_mdtransform_norecalc(state, block);

	/* t = checksum[15]; for each byte: c = S(block[i] ^ t);
	 * checksum[i] ^= c; t = checksum[i] */
	{
		vtype t[8];
		for (k = 0; k < 8; k++)
			t[k] = checksum[15][k];
		for (i = 0; i < 16; i++) {
			vtype u[8], z[8];
			for (k = 0; k < 8; k++)
				u[k] = VXOR(block[i][k], t[k]);
			lotus_sbox(u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
			    &z[0], &z[1], &z[2], &z[3], &z[4], &z[5], &z[6], &z[7]);
			for (k = 0; k < 8; k++) {
				t[k] = VXOR(checksum[i][k], z[k]);
				checksum[i][k] = t[k];
			}
		}
	}
}

/*
 * Transpose 16 bytes per lane into bitsliced form.  bytes[l][p] is byte
 * p of lane l; lanes >= count must already be zeroed in `bytes` by the
 * caller.  out[p][k] lane l = bit k of bytes[l][p].
 *
 * The scalar code builds a byte plane first; on x86 with SSE2 or better
 * planes are converted to lane bit vectors with movemask.
 */
static void lotus_bs_transpose16(const unsigned char (*bytes)[16],
    vtype out[16][8])
{
	unsigned char plane[16][LOTUS_BS_DEPTH];
	int l, p, k;

	memset(plane, 0, sizeof(plane));
	for (l = 0; l < LOTUS_BS_DEPTH; l++)
		for (p = 0; p < 16; p++)
			plane[p][l] = bytes[l][p];

#if defined(__AVX512BW__) && !defined(JOHN_NO_SIMD)
	for (p = 0; p < 16; p++)
		for (k = 0; k < 8; k++) {
			lotus_bs_vec v;
			int g;
			for (g = 0; g < LOTUS_BS_DEPTH; g += 64) {
				__m512i b = _mm512_loadu_si512(
				    (const void *)(plane[p] + g));
				__m512i bit = _mm512_and_si512(b,
				    _mm512_set1_epi8(1 << k));
				v.u64[g >> 6] = _mm512_cmp_epi8_mask(bit,
				    _mm512_setzero_si512(), _MM_CMPINT_NE);
			}
			out[p][k] = v.v;
		}
#elif defined(__AVX2__) && !defined(JOHN_NO_SIMD)
	for (p = 0; p < 16; p++)
		for (k = 0; k < 8; k++) {
			lotus_bs_vec v;
			int g;
			for (g = 0; g < LOTUS_BS_DEPTH; g += 32) {
				__m256i m = _mm256_set1_epi8(1 << k);
				__m256i b = _mm256_loadu_si256(
				    (const __m256i *)(plane[p] + g));
				v.u32[g >> 5] = _mm256_movemask_epi8(
				    _mm256_cmpeq_epi8(
				    _mm256_and_si256(b, m), m));
			}
			out[p][k] = v.v;
		}
#elif defined(__SSE2__) && !defined(JOHN_NO_SIMD)
	for (p = 0; p < 16; p++)
		for (k = 0; k < 8; k++) {
			lotus_bs_vec v;
			int g;
			for (g = 0; g < LOTUS_BS_DEPTH; g += 16) {
				__m128i m = _mm_set1_epi8(1 << k);
				__m128i b = _mm_loadu_si128(
				    (const __m128i *)(plane[p] + g));
				v.u16[g >> 4] = _mm_movemask_epi8(
				    _mm_cmpeq_epi8(
				    _mm_and_si128(b, m), m));
			}
			out[p][k] = v.v;
		}
#else
	{
		lotus_bs_vec v[16][8];
		for (p = 0; p < 16; p++)
			for (k = 0; k < 8; k++) {
				int g;
				for (g = 0; g < (int)(sizeof(vtype)); g++) {
					unsigned char byte = 0;
					for (l = 0; l < 8; l++)
						byte |= (plane[p][g * 8 + l] >>
						    k & 1) << l;
					v[p][k].u8[g] = byte;
				}
				out[p][k] = v[p][k].v;
			}
	}
#endif
}

/*
 * Reverse: bitsliced 16 bytes into out[l][p] for the first count lanes.
 */
static void lotus_bs_untranspose16(const vtype in[16][8], int count,
    unsigned char (*out)[16])
{
	int l, p, k;

	for (l = 0; l < count; l++) {
		for (p = 0; p < 16; p++) {
			unsigned char b = 0;
			for (k = 0; k < 8; k++) {
				lotus_bs_vec v;
				v.v = in[p][k];
				b |= ((v.u8[l >> 3] >> (l & 7)) & 1) << k;
			}
			out[l][p] = b;
		}
	}
}

/*
 * lotus5, one batch of LOTUS_BS_DEPTH candidates (count <= that; keys of
 * the remaining lanes are read as zeroed buffers by the caller padding
 * the keys array, or garbage lanes are simply ignored in the output).
 * Exactly mirrors crypt_all() in lotus5_fmt_plug.c.
 */
void lotus_bs_crypt_lotus5(char (*keys)[17], int count,
    unsigned char (*out)[16])
{
	/* m[0..15] row 0, [16..31] row 1, [32..47] row 2, [48..63] row 3 */
	vtype m[64][8];
	vtype row1[16][8];
	unsigned char bytes[LOTUS_BS_DEPTH][16];
	int i, k, l;

	memset(bytes, 0, sizeof(bytes));
	for (l = 0; l < count; l++) {
		int len = strnlen(keys[l], 16);
		memset(bytes[l], 16 - len, 16);
		memcpy(bytes[l], keys[l], len);
	}
	/* row 0 = 0; rows 1 and 2 = key padded with (16 - len) */
	memset(m, 0, sizeof(m));
	lotus_bs_transpose16(bytes, row1);
	for (i = 0; i < 16; i++)
		for (k = 0; k < 8; k++)
			m[16 + i][k] = m[32 + i][k] = row1[i][k];

	/* row 3 = lotus_transform_password(row 1) */
	{
		vtype t[8], z[8];
		for (k = 0; k < 8; k++)
			t[k] = VZERO();
		for (i = 0; i < 16; i++) {
			vtype u[8];
			for (k = 0; k < 8; k++)
				u[k] = VXOR(m[16 + i][k], t[k]);
			lotus_sbox(u[0], u[1], u[2], u[3], u[4], u[5], u[6],
			    u[7], &z[0], &z[1], &z[2], &z[3], &z[4], &z[5],
			    &z[6], &z[7]);
			for (k = 0; k < 8; k++) {
				m[48 + i][k] = z[k];
				t[k] = z[k];
			}
		}
	}

	lotus_bs_mix(m);

	/* row 1 = row 3; row 2 = row 0 ^ row 1 */
	for (i = 0; i < 16; i++)
		for (k = 0; k < 8; k++) {
			m[16 + i][k] = m[48 + i][k];
			m[32 + i][k] = VXOR(m[i][k], m[16 + i][k]);
		}

	lotus_bs_mix(m);

	lotus_bs_untranspose16(m, count, out);
}

/*
 * domino big-md over variable-length input, one batch.  All inputs must
 * need the same number of 16-byte blocks (caller groups by length).
 * Mirrors domino_big_md_3() per candidate.
 */
void lotus_bs_domino_md(const unsigned char *const *in, const int *len,
    int count, unsigned char (*out)[16])
{
	vtype state[16][8], checksum[16][8], block[16][8];
	unsigned char bytes[LOTUS_BS_DEPTH][16];
	int nblocks = len[0] / 16 + 1;
	int b, i, l;

	memset(state, 0, sizeof(state));
	memset(checksum, 0, sizeof(checksum));

	for (b = 0; b < nblocks; b++) {
		memset(bytes, 0, sizeof(bytes));
		for (l = 0; l < count; l++) {
			int idx = b * 16;
			for (i = 0; i < 16; i++, idx++)
				bytes[l][i] = idx < len[l] ? in[l][idx] :
				    16 - (len[l] - b * 16);
		}
		lotus_bs_transpose16(bytes, block);
		lotus_bs_mdtransform(state, checksum, block);
	}

	/* final pass with the checksum as the block */
	lotus_bs_mdtransform_norecalc(state, checksum);

	lotus_bs_untranspose16(state, count, out);
}

/*
 * domino big-md over the 34-byte digest34 buffers (dominosec second
 * pass), one batch.  Mirrors domino_big_md_3_34().
 */
void lotus_bs_domino_md_34(const unsigned char (*in)[34], int count,
    unsigned char (*out)[16])
{
	vtype state[16][8], checksum[16][8], block[16][8];
	unsigned char bytes[LOTUS_BS_DEPTH][16];
	int l;

	memset(state, 0, sizeof(state));
	memset(checksum, 0, sizeof(checksum));

	memset(bytes, 0, sizeof(bytes));
	for (l = 0; l < count; l++)
		memcpy(bytes[l], in[l], 16);
	lotus_bs_transpose16(bytes, (vtype (*)[8])block);
	lotus_bs_mdtransform((vtype (*)[8])state, (vtype (*)[8])checksum,
	    (vtype (*)[8])block);

	memset(bytes, 0, sizeof(bytes));
	for (l = 0; l < count; l++)
		memcpy(bytes[l], in[l] + 16, 16);
	lotus_bs_transpose16(bytes, (vtype (*)[8])block);
	lotus_bs_mdtransform((vtype (*)[8])state, (vtype (*)[8])checksum,
	    (vtype (*)[8])block);

	memset(bytes, 0, sizeof(bytes));
	for (l = 0; l < count; l++) {
		memcpy(bytes[l], in[l] + 32, 2);
		memset(bytes[l] + 2, 14, 14);
	}
	lotus_bs_transpose16(bytes, (vtype (*)[8])block);
	lotus_bs_mdtransform((vtype (*)[8])state, (vtype (*)[8])checksum,
	    (vtype (*)[8])block);

	lotus_bs_mdtransform_norecalc(state, checksum);

	lotus_bs_untranspose16(state, count, out);
}

/*
 * dominosec and dominosec8 shared first pass: fill the hex part (bytes
 * 6..33) of digest34 for count keys, mirroring the keys_changed branch of
 * their crypt_all().  Keys are grouped by password length class (number of
 * 16-byte blocks minus one) so that each lotus_bs_domino_md batch contains
 * only inputs needing the same number of blocks.  The salt prefix (bytes
 * 0..5) is left to the caller, exactly like the scalar code.
 */
void lotus_bs_domino_digest34(char (*keys)[65], int count,
    unsigned char (*digest34)[34])
{
	const unsigned char *in[LOTUS_BS_DEPTH];
	int len[LOTUS_BS_DEPTH];
	int idxmap[LOTUS_BS_DEPTH];
	unsigned char (*md16)[16] =
	    mem_alloc(LOTUS_BS_DEPTH * 16); /* malloc to keep stack small */
	int cls, index, l;

	for (cls = 0; cls < 5; cls++) {
		int fill = 0;

		for (index = 0; index <= count; index++) {
			int take = index < count &&
			    (int)strnlen(keys[index], 64) / 16 == cls;

			if (take) {
				len[fill] = strnlen(keys[index], 64);
				in[fill] = keys[index];
				idxmap[fill] = index;
				fill++;
			}
			if (fill == LOTUS_BS_DEPTH ||
			    (index == count && fill)) {
				lotus_bs_domino_md(in, len, fill, md16);
				for (l = 0; l < fill; l++) {
					unsigned char *d = digest34[idxmap[l]];
					int i, j;
					for (i = 0, j = 6; i < 14; i++, j += 2) {
						d[j] = itoa16u[md16[l][i] >> 4];
						d[j + 1] = itoa16u[md16[l][i] & 0xf];
					}
				}
				fill = 0;
			}
			if (index == count)
				break;
		}
	}

	MEM_FREE(md16);
}

/*
 * dominosec and dominosec8 second pass: hash the digest34 buffers into
 * out, in batches.
 */
void lotus_bs_domino_sec(const unsigned char (*digest34)[34], int count,
    unsigned char (*out)[16])
{
	int base;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (base = 0; base < count; base += LOTUS_BS_DEPTH) {
		int n = count - base;
		if (n > LOTUS_BS_DEPTH)
			n = LOTUS_BS_DEPTH;
		lotus_bs_domino_md_34(digest34 + base, n, out + base);
	}
}
