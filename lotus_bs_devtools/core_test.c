/* Standalone test: bitslice core vs scalar reference implementations.
 * Build: gcc -O2 -mavx2 -I/home/user/repos/john/src core_test.c lotus_common_plug.c
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "lotus_common.h"

/* scalar reference (from lotus5_fmt_plug.c) */
static void lotus_transform_password_ref(const unsigned char *i0, unsigned char *o0)
{
	unsigned char t = 0;
	int i;
	for (i = 0; i < 8; i++) {
		t = *o0++ = lotus_magic_table[*i0++ ^ t];
		t = *o0++ = lotus_magic_table[*i0++ ^ t];
	}
}

static void lotus_mix_ref(unsigned char *m)
{
	unsigned char t = 0, *p = m;
	int i, j;
	for (i = 18; i > 0; i--) {
		p = m;
		for (j = 48; j > 0; j--) {
			t = p[0] ^= lotus_magic_table[j + t];
			j--;
			t = p[1] ^= lotus_magic_table[j + t];
			p += 2;
		}
	}
}

static void lotus5_ref(const char *key, unsigned char *out)
{
	unsigned char m[64];
	int password_length = strlen(key);
	memset(m, 0, 16);
	memset(m + 16, 16 - password_length, 16);
	memcpy(m + 16, key, password_length);
	memcpy(m + 32, m + 16, 16);
	lotus_transform_password_ref(m + 16, m + 48);
	lotus_mix_ref(m);
	memcpy(m + 16, m + 48, 16);
	{
		int i;
		for (i = 0; i < 16; i++)
			m[32 + i] = m[i] ^ m[16 + i];
	}
	lotus_mix_ref(m);
	memcpy(out, m, 16);
}

/* scalar reference for dominosec mdtransform (from DOMINOSEC_fmt_plug.c) */
static void mdtransform_norecalc_ref(unsigned char state[16], unsigned char block[16])
{
	unsigned char x[48];
	unsigned char *p;
	unsigned int i, j, t;

	t = 0; p = x;
	for (j = 48; j > 32; j--) {
		t = state[p - x] ^ lotus_magic_table[j + t];
		*p++ = t;
	}
	for (; j > 16; j--) {
		t = block[p - x - 16] ^ lotus_magic_table[j + t];
		*p++ = t;
	}
	for (; j > 0; j--) {
		t = state[p - x - 32] ^ block[p - x - 32] ^ lotus_magic_table[j + t];
		*p++ = t;
	}
	for (i = 0; i < 16; i++) {
		p = x;
		for (j = 48; j > 0; j--) {
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j + t];
		}
	}
	p = x;
	for (j = 48; j > 32; j--) {
		state[p - x] = t = *p ^ lotus_magic_table[j + t];
		p++;
	}
}

static void mdtransform_ref(unsigned char state[16], unsigned char checksum[16],
    unsigned char block[16])
{
	unsigned char c;
	unsigned int i, t;

	mdtransform_norecalc_ref(state, block);
	t = checksum[15];
	for (i = 0; i < 16; i++) {
		c = lotus_magic_table[block[i] ^ t];
		t = checksum[i] ^= c;
	}
}

static void domino_md_ref(const unsigned char *in, unsigned int size,
    unsigned char *out)
{
	unsigned char state[16] = {0}, checksum[16] = {0}, block[16];
	unsigned int curpos = 0;

	while (curpos + 15 < size) {
		mdtransform_ref(state, checksum, (unsigned char *)in + curpos);
		curpos += 16;
	}
	{
		unsigned int pad = size - curpos;
		memcpy(block, in + curpos, pad);
		memset(block + pad, 16 - pad, 16 - pad);
		mdtransform_ref(state, checksum, block);
	}
	mdtransform_norecalc_ref(state, checksum);
	memcpy(out, state, 16);
}

static void domino_md_34_ref(const unsigned char *in, unsigned char *out)
{
	unsigned char state[16] = {0}, checksum[16] = {0}, block[16];

	mdtransform_ref(state, checksum, in);
	mdtransform_ref(state, checksum, in + 16);
	memcpy(block, in + 32, 2);
	memset(block + 2, 14, 14);
	mdtransform_ref(state, checksum, block);
	mdtransform_norecalc_ref(state, checksum);
	memcpy(out, state, 16);
}

static int fails;

static void check(const char *what, const unsigned char *got,
    const unsigned char *want, int n)
{
	if (memcmp(got, want, n)) {
		int i;
		printf("FAIL %s\n  got  ", what);
		for (i = 0; i < n; i++) printf("%02x", got[i]);
		printf("\n  want ");
		for (i = 0; i < n; i++) printf("%02x", want[i]);
		printf("\n");
		fails++;
	}
}

int main(void)
{
	unsigned char out[LOTUS_BS_DEPTH][16], want[16];
	char keys[LOTUS_BS_DEPTH][17];
	const char *testkeys[] = {"", "x", "secret", "password", "lotus",
	    "dirtydog", "0123456789abcdef", "0123456789abcde",
	    "whatdoyouknow", "sixteenchars!!!!"};
	int i, n = sizeof(testkeys) / sizeof(testkeys[0]);

	printf("LOTUS_BS_DEPTH = %d\n", LOTUS_BS_DEPTH);

	/* lotus5: batch of all test keys (fill lanes cyclically) */
	for (i = 0; i < LOTUS_BS_DEPTH; i++)
		{
			const char *k = testkeys[i % n];
			int j;
			for (j = 0; k[j]; j++) keys[i][j] = k[j];
			keys[i][j] = 0;
		}
	lotus_bs_crypt_lotus5(keys, LOTUS_BS_DEPTH, out);
	for (i = 0; i < LOTUS_BS_DEPTH; i++) {
		char label[64];
		lotus5_ref(keys[i], want);
		snprintf(label, sizeof(label), "lotus5 lane %d key '%s'", i, keys[i]);
		check(label, out[i], want, 16);
		if (i >= n * 2 + 4) /* checked enough repetitions */
			i = LOTUS_BS_DEPTH; /* break via loop end */
	}
	/* also partial batch */
	lotus_bs_crypt_lotus5(keys, 3, out);
	for (i = 0; i < 3; i++) {
		char label[64];
		lotus5_ref(keys[i], want);
		snprintf(label, sizeof(label), "lotus5 partial lane %d", i);
		check(label, out[i], want, 16);
	}

	/* dominosec stage 1: group by length class */
	{
		const unsigned char *in[LOTUS_BS_DEPTH];
		int len[LOTUS_BS_DEPTH];
		static unsigned char buffers[LOTUS_BS_DEPTH][64];
		int cls;
		for (cls = 0; cls <= 4; cls++) {
			int cnt = 0;
			for (i = 0; i < LOTUS_BS_DEPTH; i++) {
				int l = cls * 16 + (i % 16); /* lengths within class cls */
				if (l > 64) l = 64;
				int j;
				for (j = 0; j < l; j++)
					buffers[i][j] = (unsigned char)(i * 7 + j * 13 + l);
				in[i] = buffers[i];
				len[i] = l;
				cnt++;
			}
			/* all lanes same class? len/16 must be equal: cls*16+i%16 in [cls*16, cls*16+15] → len/16 == cls ✓ (len=64: 64/16=4 ✓) */
			lotus_bs_domino_md(in, len, LOTUS_BS_DEPTH, out);
			for (i = 0; i < 20; i++) {
				char label[80];
				domino_md_ref(in[i], len[i], want);
				snprintf(label, sizeof(label), "domino_md class %d lane %d len %d", cls, i, len[i]);
				check(label, out[i], want, 16);
			}
		}
		/* edge: len 0 and len 64, each as its own (single-class) batch */
		{
			memset(buffers[0], 0x41, 64);
			in[0] = buffers[0]; len[0] = 0;
			lotus_bs_domino_md(in, len, 1, out);
			domino_md_ref(in[0], 0, want);
			check("domino_md len 0", out[0], want, 16);
			memset(buffers[1], 0x42, 64);
			in[1] = buffers[1]; len[1] = 64;
			lotus_bs_domino_md(in + 1, len + 1, 1, out);
			domino_md_ref(in[1], 64, want);
			check("domino_md len 64", out[0], want, 16);
		}
	}

	/* dominosec stage 2 */
	{
		static const unsigned char in34[LOTUS_BS_DEPTH][34];
		/* use varied digest34 data */
		static unsigned char d34[LOTUS_BS_DEPTH][34];
		for (i = 0; i < LOTUS_BS_DEPTH; i++) {
			int j;
			for (j = 0; j < 34; j++)
				d34[i][j] = (unsigned char)(i * 31 + j * 5);
		}
		lotus_bs_domino_md_34((const unsigned char (*)[34])d34, LOTUS_BS_DEPTH, out);
		for (i = 0; i < 20; i++) {
			char label[64];
			domino_md_34_ref(d34[i], want);
			snprintf(label, sizeof(label), "domino_md_34 lane %d", i);
			check(label, out[i], want, 16);
		}
	}

	if (!fails)
		puts("core tests: ALL OK");
	else
		printf("%d FAILURES\n", fails);
	return !!fails;
}
