#include <stdio.h>
#include <time.h>
#include <immintrin.h>
typedef __m256i vtype;
#define VZERO()         _mm256_setzero_si256()
#define VONES()         _mm256_set1_epi32(-1)
#define VNOT(a)         _mm256_xor_si256((a), VONES())
#define VXOR(a, b)      _mm256_xor_si256((a), (b))
#define VAND(a, b)      _mm256_and_si256((a), (b))
#define VOR(a, b)       _mm256_or_si256((a), (b))
#define VANDN(a, b)     _mm256_andnot_si256((b), (a))
#include "lotus_lut3.inc"
#define LOTUS_NOINLINE __attribute__((noinline))
#include "lotus_sboxes.h"
volatile vtype sink;
int main(void) {
	vtype in[8];
	int i;
	for (i = 0; i < 8; i++)
		__asm__("" : "=x"(in[i]) : "0"(in[i]));
	in[0] = _mm256_set1_epi32(i); /* still opaque-ish */
	struct timespec t0, t1;
	long N = 200000;
	vtype x0 = _mm256_set1_epi32(0x12345678);
	vtype x1 = _mm256_set1_epi32(0x9abcdef0);
	vtype x2 = _mm256_set1_epi32(0x13579bdf);
	vtype x3 = _mm256_set1_epi32(0x2468ace0);
	vtype x4 = _mm256_set1_epi32(0x0f0f0f0f);
	vtype x5 = _mm256_set1_epi32(0xf0f0f0f0);
	vtype x6 = _mm256_set1_epi32(0x55555555);
	vtype x7 = _mm256_set1_epi32(0xaaaaaaaa);
	__asm__("" :: "x"(x0), "x"(x1), "x"(x2), "x"(x3), "x"(x4), "x"(x5), "x"(x6), "x"(x7));
	vtype o0, o1, o2, o3, o4, o5, o6, o7;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (long r = 0; r < N; r++) {
		lotus_sbox(x0, x1, x2, x3, x4, x5, x6, x7,
		    &o0, &o1, &o2, &o3, &o4, &o5, &o6, &o7);
		__asm__("" :: "x"(o0), "x"(o1), "x"(o2), "x"(o3), "x"(o4), "x"(o5), "x"(o6), "x"(o7));
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double sec = (t1.tv_sec-t0.tv_sec)+1e-9*(t1.tv_nsec-t0.tv_nsec);
	sink = o0;
	printf("%.1f ns/sbox = ~%.0f cycles @3.3GHz\n", sec/N*1e9, sec/N*3.3e9);
	return 0;
}
