/*
 * Shared code for the Lotus Notes/Domino formats: lotus5, dominosec,
 * dominosec8.  Provides the common lotus_magic_table and the bitslice
 * implementation of the hash core (issue #5451).
 */

#ifndef _LOTUS_COMMON_H
#define _LOTUS_COMMON_H

#include <stdint.h>

/* The Lotus/Domino S-box as used by lotus5, dominosec and dominosec8.
 * The second copy of the first 48 entries allows lotus5's unmasked
 * lotus_magic_table[j + t] lookups with j up to 48. */
extern const unsigned char lotus_magic_table[304];

/*
 * Bitslice depth (number of candidates processed in parallel, one bit of
 * a byte per lane).  Selected like DES_BS_DEPTH in DES_bs_b.c: AVX-512
 * gives 512 lanes, AVX-2 256, SSE2/NEON 128, and without SIMD 64.
 */
#if defined(__AVX512F__) && !defined(JOHN_NO_SIMD)
#define LOTUS_BS_DEPTH			512
#elif defined(__AVX2__) && !defined(JOHN_NO_SIMD)
#define LOTUS_BS_DEPTH			256
#elif (defined(__SSE2__) || defined(__ARM_NEON)) && !defined(JOHN_NO_SIMD)
#define LOTUS_BS_DEPTH			128
#else
#define LOTUS_BS_DEPTH			64
#endif

/*
 * The bitslice implementations only pay off with 512-bit vectors (one
 * VPTERNLOG per LUT3 of the S-box circuit); with emulated gates at 256
 * bits and below, the current 8-bit lookup table code is as fast or
 * faster (as anticipated in issue #5451).  Formats therefore use bitslice
 * only when LOTUS_BS_IN_USE is defined; for testing it can be forced on
 * with -DLOTUS_BS_MIN_DEPTH=128.
 */
#ifndef LOTUS_BS_MIN_DEPTH
#define LOTUS_BS_MIN_DEPTH		512
#endif
#if LOTUS_BS_DEPTH >= LOTUS_BS_MIN_DEPTH
#define LOTUS_BS_IN_USE			1
#endif

/*
 * Bitslice implementations (in lotus_common_plug.c).  Each function
 * processes one batch of LOTUS_BS_DEPTH candidates; count entries are
 * taken from the input, the remaining lanes compute garbage which the
 * caller must ignore.  All of them run the exact same algorithms as the
 * scalar reference code in the format files.
 */

/* lotus5: hash count keys (NUL-terminated, at most 16 chars each, laid
 * out as keys[index][17]) into out[index][16] bytes. */
extern void lotus_bs_crypt_lotus5(char (*keys)[17], int count,
    unsigned char (*out)[16]);

/* dominosec/domino big-md over a variable-length buffer: hash the first
 * len[index] bytes of in[index] (len must be in 1..64; all inputs must
 * require the same number of 16-byte blocks, i.e. len/16 must be the
 * same for all, which the caller ensures by grouping) into out[index][16]. */
extern void lotus_bs_domino_md(const unsigned char *const *in,
    const int *len, int count, unsigned char (*out)[16]);

/* dominosec/domino8 first pass: hex part of digest34 (bytes 6..33) for
 * count keys of up to 64 chars, grouped by length class internally. */
extern void lotus_bs_domino_digest34(char (*keys)[65], int count,
    unsigned char (*digest34)[34]);

/* dominosec/domino8 second pass: digest34 buffers into out[index][16]. */
extern void lotus_bs_domino_sec(const unsigned char (*digest34)[34],
    int count, unsigned char (*out)[16]);

/* domino big-md over the fixed-size 34-byte digest34 buffers (dominosec
 * second pass) into out[index][16]. */
extern void lotus_bs_domino_md_34(const unsigned char (*in)[34], int count,
    unsigned char (*out)[16]);

#endif /* _LOTUS_COMMON_H */
