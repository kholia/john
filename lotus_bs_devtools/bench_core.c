#include <stdio.h>
#include <string.h>
#include <time.h>
#include "lotus_common.h"
int main(void) {
	static char keys[LOTUS_BS_DEPTH][17];
	static unsigned char out[LOTUS_BS_DEPTH][16];
	int i, r;
	struct timespec t0, t1;
	const int REPS = 200;
	for (i = 0; i < LOTUS_BS_DEPTH; i++)
		snprintf(keys[i], 17, "hash%d", i % 100000);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (r = 0; r < REPS; r++)
		lotus_bs_crypt_lotus5(keys, LOTUS_BS_DEPTH, out);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double sec = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
	printf("depth %d: %.1f c/s/core (lotus5)\n", LOTUS_BS_DEPTH,
	       REPS * LOTUS_BS_DEPTH / sec);
	/* domino_md_34 */
	static const unsigned char in34[LOTUS_BS_DEPTH][34];
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (r = 0; r < REPS; r++)
		lotus_bs_domino_md_34(in34, LOTUS_BS_DEPTH, out);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	sec = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
	printf("depth %d: %.1f c/s/core (domino_md_34)\n", LOTUS_BS_DEPTH,
	       REPS * LOTUS_BS_DEPTH / sec);
	return 0;
}
