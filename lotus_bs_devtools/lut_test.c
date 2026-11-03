#include <stdio.h>
#include <immintrin.h>
typedef __m256i vtype;
#define VZERO()         _mm256_setzero_si256()
#define VONES()         _mm256_set1_epi32(-1)
#define VNOT(a)         _mm256_xor_si256((a), VONES())
#define VXOR(a, b)      _mm256_xor_si256((a), (b))
#define VAND(a, b)      _mm256_and_si256((a), (b))
#define VOR(a, b)       _mm256_or_si256((a), (b))
#define VANDN(a, b)     _mm256_andnot_si256((b), (a))

static vtype lotus_lut2(vtype a, vtype b, int imm)
{
	switch (imm) {
	case 0x0: return VZERO();
	case 0x1: return VNOT(VOR(a, b));
	case 0x2: return VANDN(b, a);
	case 0x3: return VNOT(a);
	case 0x4: return VANDN(a, b);
	case 0x5: return VNOT(b);
	case 0x6: return VXOR(a, b);
	case 0x7: return VNOT(VAND(a, b));
	case 0x8: return VAND(a, b);
	case 0x9: return VNOT(VXOR(a, b));
	case 0xa: return b;
	case 0xb: return VOR(VNOT(a), b);
	case 0xc: return a;
	case 0xd: return VOR(a, VNOT(b));
	case 0xe: return VOR(a, b);
	case 0xf: return VONES();
	}
	return VZERO();
}

static vtype lotus_lut3(vtype a, vtype b, vtype c, int imm)
{
	/* c is bit 0 of the LUT index, so it selects between the even and
	 * odd bits of imm, not between its nibbles. */
	int lo = (imm & 1) | ((imm >> 1) & 2) | ((imm >> 2) & 4) | ((imm >> 3) & 8);
	int hi = ((imm >> 1) & 1) | ((imm >> 2) & 2) | ((imm >> 3) & 4) | ((imm >> 4) & 8);
	return VOR(VANDN(lotus_lut2(a, b, lo), c),
	    VAND(lotus_lut2(a, b, hi), c));
}

int main(void)
{
	int fails = 0;
	for (int imm = 0; imm < 256; imm++)
		for (int av = 0; av < 2; av++)
			for (int bv = 0; bv < 2; bv++)
				for (int cv = 0; cv < 2; cv++) {
					vtype A = av ? VONES() : VZERO();
					vtype B = bv ? VONES() : VZERO();
					vtype C = cv ? VONES() : VZERO();
					int got = _mm256_testz_si256(lotus_lut3(A,B,C,imm),
					                             lotus_lut3(A,B,C,imm));
					int want = (imm >> ((av<<2)|(bv<<1)|cv)) & 1;
					/* testz=1 means all zero → got should be !want */
					if (got != !want) {
						printf("imm=%02x a=%d b=%d c=%d got=%d want=%d\n",
						       imm, av, bv, cv, !got, want);
						if (++fails > 10) return 1;
					}
				}
	if (fails) return 1;
	puts("lut3 emulation: OK");
	return 0;
}
