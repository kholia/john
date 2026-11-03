//original work by Jeff Fay
//some optimisations by bartavelle at bandecon.com
/* OpenMP support and further optimizations (including some code rewrites)
 * by Solar Designer */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lotus5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lotus5);
#else

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "lotus_common.h"

#ifndef LOTUS_BS_IN_USE
#ifdef __x86_64__
#define LOTUS_N 3
#define LOTUS_N_STR " X3"
#else
#define LOTUS_N 2
#define LOTUS_N_STR " X2"
#endif
#endif

#ifdef LOTUS_BS_IN_USE
#define LOTUS_STR2(x)	#x
#define LOTUS_STR(x)	LOTUS_STR2(x)
#define LOTUS_BS_NAME	"LOTUS " LOTUS_STR(LOTUS_BS_DEPTH) \
    "/" LOTUS_STR(LOTUS_BS_DEPTH)
#endif

/*preprocessor constants that John The Ripper likes*/
#define FORMAT_LABEL                   "lotus5"
#define FORMAT_NAME                    "Lotus Notes/Domino 5"
#ifdef LOTUS_BS_IN_USE
#define ALGORITHM_NAME                 LOTUS_BS_NAME
#else
#define ALGORITHM_NAME                 "8/" ARCH_BITS_STR LOTUS_N_STR
#endif
#define BENCHMARK_COMMENT              ""
#define BENCHMARK_LENGTH               0x107
#define PLAINTEXT_LENGTH               16
#define CIPHERTEXT_LENGTH              32
#define BINARY_SIZE                    16
#define SALT_SIZE                      0
#define BINARY_ALIGN			sizeof(uint32_t)
#define SALT_ALIGN				1
#ifdef LOTUS_BS_IN_USE
#define MIN_KEYS_PER_CRYPT             LOTUS_BS_DEPTH
#define MAX_KEYS_PER_CRYPT             LOTUS_BS_DEPTH
#else
#define MIN_KEYS_PER_CRYPT             LOTUS_N
/* Must be divisible by any LOTUS_N (thus, by 2 and 3) */
#define MAX_KEYS_PER_CRYPT             (64 * LOTUS_N)
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               16 // MKPC and scale tuned for i7
#endif

/*A struct used for JTR's benchmarks*/
static struct fmt_tests tests[] = {
  {"06E0A50B579AD2CD5FFDC48564627EE7", "secret"},
  {"355E98E7C7B59BD810ED845AD0FD2FC4", "password"},
  {"CD2D90E8E00D8A2A63A81F531EA8A9A3", "lotus"},
  {"69D90B46B1AC0912E5CCF858094BBBFC", "dirtydog"},
  {NULL}
};

/*Some more JTR variables*/
static uint32_t (*crypt_key)[BINARY_SIZE / 4];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	crypt_key = mem_calloc_align(sizeof(*crypt_key),
	    self->params.max_keys_per_crypt, MEM_ALIGN_CACHE);
	saved_key = mem_calloc_align(sizeof(*saved_key),
	    self->params.max_keys_per_crypt, MEM_ALIGN_CACHE);
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

/*Utility function to convert hex to bin */
static void * get_binary(char *ciphertext)
{
  static uint32_t out[BINARY_SIZE/4];
  char *realcipher = (char*)out;
  int i;

  for (i = 0; i < BINARY_SIZE; i++)
      realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
  return (void*)out;
}

/*Another function required by JTR: decides whether we have a valid
 * ciphertext */
static int
valid (char *ciphertext, struct fmt_main *self)
{
  int i;

  for (i = 0; i < CIPHERTEXT_LENGTH; i++)
	  if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9'))
				  //|| ((ciphertext[i] >= 'a') && (ciphertext[i] <= 'f'))
				  || ((ciphertext[i] >= 'A') && (ciphertext[i] <= 'F'))))
	  {
		  return 0;
	  }
  return !ciphertext[i];
}

/*sets the value of saved_key so we can play with it*/
static void set_key (char *key, int index)
{
  strnzcpy (saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

/*retrieves the saved key; used by JTR*/
static char * get_key (int index)
{
	return saved_key[index];
}

static int cmp_all (void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one (void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact (char *source, int index)
{
	return 1;
}

#ifdef LOTUS_BS_IN_USE

/*the last public function; generates ciphertext*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int base;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (base = 0; base < count; base += LOTUS_BS_DEPTH) {
		int n = count - base;
		if (n > LOTUS_BS_DEPTH)
			n = LOTUS_BS_DEPTH;
		lotus_bs_crypt_lotus5(saved_key + base, n,
		    (unsigned char (*)[16])(crypt_key + base));
	}

	return count;
}

#else /* LOTUS_BS_IN_USE */

/*Beginning of private functions*/
/* Takes the plaintext password and generates the second row of our
 * working matrix for the final call to the mixing function*/
MAYBE_INLINE static void
#if LOTUS_N == 3
lotus_transform_password (unsigned char *i0, unsigned char *o0,
    unsigned char *i1, unsigned char *o1,
    unsigned char *i2, unsigned char *o2)
#else
lotus_transform_password (unsigned char *i0, unsigned char *o0,
    unsigned char *i1, unsigned char *o1)
#endif
{
  unsigned char t0, t1;
#if LOTUS_N == 3
  unsigned char t2;
#endif
  int i;

#if LOTUS_N == 3
  t0 = t1 = t2 = 0;
#else
  t0 = t1 = 0;
#endif
  for (i = 0; i < 8; i++)
    {
      t0 = *o0++ = lotus_magic_table[ARCH_INDEX(*i0++ ^ t0)];
      t1 = *o1++ = lotus_magic_table[ARCH_INDEX(*i1++ ^ t1)];
#if LOTUS_N == 3
      t2 = *o2++ = lotus_magic_table[ARCH_INDEX(*i2++ ^ t2)];
#endif
      t0 = *o0++ = lotus_magic_table[ARCH_INDEX(*i0++ ^ t0)];
      t1 = *o1++ = lotus_magic_table[ARCH_INDEX(*i1++ ^ t1)];
#if LOTUS_N == 3
      t2 = *o2++ = lotus_magic_table[ARCH_INDEX(*i2++ ^ t2)];
#endif
    }
}

/* The mixing function: perturbs the first three rows of the matrix*/
#if LOTUS_N == 3
static void lotus_mix (unsigned char *m0, unsigned char *m1,
    unsigned char *m2)
#else
static void lotus_mix (unsigned char *m0, unsigned char *m1)
#endif
{
  unsigned char t0, t1;
  unsigned char *p0, *p1;
#if LOTUS_N == 3
  unsigned char t2;
  unsigned char *p2;
#endif
  int i, j;

#if LOTUS_N == 3
  t0 = t1 = t2 = 0;
#else
  t0 = t1 = 0;
#endif

  for (i = 18; i > 0; i--)
    {
      p0 = m0;
      p1 = m1;
#if LOTUS_N == 3
      p2 = m2;
#endif
      for (j = 48; j > 0; j--)
	{
	  t0 = p0[0] ^= lotus_magic_table[ARCH_INDEX(j + t0)];
	  t1 = p1[0] ^= lotus_magic_table[ARCH_INDEX(j + t1)];
#if LOTUS_N == 3
	  t2 = p2[0] ^= lotus_magic_table[ARCH_INDEX(j + t2)];
#endif
	  j--;
	  t0 = p0[1] ^= lotus_magic_table[ARCH_INDEX(j + t0)];
	  p0 += 2;
	  t1 = p1[1] ^= lotus_magic_table[ARCH_INDEX(j + t1)];
	  p1 += 2;
#if LOTUS_N == 3
	  t2 = p2[1] ^= lotus_magic_table[ARCH_INDEX(j + t2)];
	  p2 += 2;
#endif
	}
    }
}

/*the last public function; generates ciphertext*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += LOTUS_N) {
		struct {
			union {
				unsigned char m[64];
				unsigned char m4[4][16];
				ARCH_WORD m4w[4][16 / ARCH_SIZE];
			} u;
		} ctx[LOTUS_N];
		int password_length;

		memset(ctx[0].u.m4[0], 0, 16);
		password_length = strlen(saved_key[index]);
		memset(ctx[0].u.m4[1], (PLAINTEXT_LENGTH - password_length), PLAINTEXT_LENGTH);
		memcpy(ctx[0].u.m4[1], saved_key[index], password_length);
		memcpy(ctx[0].u.m4[2], ctx[0].u.m4[1], 16);

		memset(ctx[1].u.m4[0], 0, 16);
		password_length = strlen(saved_key[index + 1]);
		memset(ctx[1].u.m4[1], (PLAINTEXT_LENGTH - password_length), PLAINTEXT_LENGTH);
		memcpy(ctx[1].u.m4[1], saved_key[index + 1], password_length);
		memcpy(ctx[1].u.m4[2], ctx[1].u.m4[1], 16);

#if LOTUS_N == 3
		memset(ctx[2].u.m4[0], 0, 16);
		password_length = strlen(saved_key[index + 2]);
		memset(ctx[2].u.m4[1], (PLAINTEXT_LENGTH - password_length), PLAINTEXT_LENGTH);
		memcpy(ctx[2].u.m4[1], saved_key[index + 2], password_length);
		memcpy(ctx[2].u.m4[2], ctx[2].u.m4[1], 16);

		lotus_transform_password(ctx[0].u.m4[1], ctx[0].u.m4[3],
		                         ctx[1].u.m4[1], ctx[1].u.m4[3],
		                         ctx[2].u.m4[1], ctx[2].u.m4[3]);
		lotus_mix(ctx[0].u.m, ctx[1].u.m, ctx[2].u.m);
#else
		lotus_transform_password(ctx[0].u.m4[1], ctx[0].u.m4[3],
		                         ctx[1].u.m4[1], ctx[1].u.m4[3]);
		lotus_mix(ctx[0].u.m, ctx[1].u.m);
#endif

		memcpy(ctx[0].u.m4[1], ctx[0].u.m4[3], 16);
		memcpy(ctx[1].u.m4[1], ctx[1].u.m4[3], 16);
#if LOTUS_N == 3
		memcpy(ctx[2].u.m4[1], ctx[2].u.m4[3], 16);
#endif
		{
			int i;
			for (i = 0; i < 16 / ARCH_SIZE; i++) {
				ctx[0].u.m4w[2][i] = ctx[0].u.m4w[0][i] ^ ctx[0].u.m4w[1][i];
				ctx[1].u.m4w[2][i] = ctx[1].u.m4w[0][i] ^ ctx[1].u.m4w[1][i];
#if LOTUS_N == 3
				ctx[2].u.m4w[2][i] = ctx[2].u.m4w[0][i] ^ ctx[2].u.m4w[1][i];
#endif
			}
		}
#if LOTUS_N == 3
		lotus_mix(ctx[0].u.m, ctx[1].u.m, ctx[2].u.m);
#else
		lotus_mix(ctx[0].u.m, ctx[1].u.m);
#endif
		memcpy(crypt_key[index], ctx[0].u.m4[0], BINARY_SIZE);
		memcpy(crypt_key[index + 1], ctx[1].u.m4[0], BINARY_SIZE);
#if LOTUS_N == 3
		memcpy(crypt_key[index + 2], ctx[2].u.m4[0], BINARY_SIZE);
#endif
	}

	return count;
}

#endif /* LOTUS_BS_IN_USE */

#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

/* C's version of a class specifier */
struct fmt_main fmt_lotus5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
