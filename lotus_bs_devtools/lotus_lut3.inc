static inline __attribute__((always_inline)) vtype lotus_lut2(vtype a, vtype b, int imm)
{
	switch (imm) {
	case 0x0: return VZERO();
	case 0x1: return VNOT(VOR(a, b));	/* nor */
	case 0x2: return VANDN(b, a);		/* ~a & b */
	case 0x3: return VNOT(a);
	case 0x4: return VANDN(a, b);		/* a & ~b */
	case 0x5: return VNOT(b);
	case 0x6: return VXOR(a, b);
	case 0x7: return VNOT(VAND(a, b));	/* nand */
	case 0x8: return VAND(a, b);
	case 0x9: return VNOT(VXOR(a, b));	/* xnor */
	case 0xa: return b;
	case 0xb: return VOR(VNOT(a), b);	/* ~a | b */
	case 0xc: return a;
	case 0xd: return VOR(a, VNOT(b));	/* a | ~b */
	case 0xe: return VOR(a, b);
	case 0xf: return VONES();
	}
	return VZERO();
}

static inline __attribute__((always_inline)) vtype lotus_lut3(vtype a, vtype b, vtype c, int imm)
{
	/* c is bit 0 of the LUT index, so it selects between the even and
	 * odd bits of imm, not between its nibbles. */
	int lo = (imm & 1) | ((imm >> 1) & 2) | ((imm >> 2) & 4) | ((imm >> 3) & 8);
	int hi = ((imm >> 1) & 1) | ((imm >> 2) & 2) | ((imm >> 3) & 4) | ((imm >> 4) & 8);
	return VOR(VANDN(lotus_lut2(a, b, lo), c),
	    VAND(lotus_lut2(a, b, hi), c));
}

#define VLUT3(a, b, c, imm)	lotus_lut3(a, b, c, imm)
