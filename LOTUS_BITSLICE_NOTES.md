# Lotus/Domino bitslice port — working notes (issue openwall/john#5451)

**Scratch file — do NOT commit.** Dev tooling lives in `lotus_bs_devtools/` (also do not commit).

## Goal
Bitslice implementations of the Lotus hash core for the 3 CPU formats:
`lotus5`, `dominosec`, `dominosec8` (OpenCL kernel + lotus85 deferred per user decision).

## Established facts

- All 3 formats use one S-box: `lotus_magic_table` (256-entry permutation; first 48
  entries duplicated to 304 for unmasked `T[j + t]`).
  - **No algebraic structure**: permutation, not affine, ANF degree 7, ~113-140
    monomials per output bit, cycles {1,5,5,8,12,23,202}. Needs real logic synthesis.
- Two S-box use-modes:
  - XOR mode `T[b ^ t]` (lotus5 transform_password, dominosec checksums) — free in bitslice.
  - ADD mode `T[j + t]`, j = 48..1 compile-time constant per position (all mix loops)
    — implemented as a constant carry-chain adder (~13 vector ops, macro
    `LOTUS_BS_ADD` in lotus_common_plug.c; carry = AND when j-bit=0, OR when j-bit=1).
- DOMINOSEC8's Lotus part is identical to DOMINOSEC's + PBKDF2-HMAC-SHA1 tail (stays scalar).
- `src/sboxes-t.c` DES LUT3 expressions are by Sovyn Y. (the person referenced in the
  issue); we generate equivalent-style expressions for the Lotus S-box with ABC.
- Related issue #5706: VPERMB/vpshufb byte-lookup alternative (NOT this issue).

## Files created in repo (intended for the final change)

- `src/lotus_sboxes.h` — generated S-box expressions (currently: 608 LUT3 +
  223 2-input gates = 608-op netlist), header verified 256/256 vs table.
- `src/lotus_common.h` — shared decls: `lotus_magic_table[304]` extern,
  `LOTUS_BS_DEPTH` ladder (512 AVX-512 / 256 AVX2 / 128 SSE2+NEON / 64 scalar),
  3 batch-API prototypes.
- `src/lotus_common_plug.c` — the bitslice core (auto-built via `*_plug.c` wildcard,
  no Makefile change needed). vtype ladder copied from DES_bs_b.c style; VLUT3
  emulation (mux of two lut2 with **even/odd bit compression of imm** — NOT nibbles!)
  for non-AVX-512; `lotus_sbox` is `LOTUS_NOINLINE` (called 1744x/batch; inlining
  explodes code size); macros LOTUS_BS_STEP/MIX48 (48 steps unrolled, j=48-I),
  lotus5 driver, dominosec mdtransform_norecalc/mdtransform (FEED/OUT macros),
  domino_md (variable length, one class per batch), domino_md_34 (fixed 34-byte
  second pass), movemask-based transpose16 (SSE2/AVX2/AVX512BW), scalar
  untranspose16.

## Verification status (all PASS)

- `lotus_bs_devtools/core_test.c` — checks bitslice vs scalar reference for:
  lotus5 (all test vectors incl. partial batch), domino_md (all 5 length classes +
  len 0 + len 64), domino_md_34. PASS on: AVX2 build, SSE2 build, JOHN_NO_SIMD build.
- `lotus_bs_devtools/lut_test.c` — exhaustive VLUT3 emulation test (256 imms x 8 inputs). PASS.
- S-box header verified symbolically (python, every node) + standalone C harness.

### Bugs found & fixed so far (do not reintroduce)
1. lut3 emulation: c (bit 0 of index) selects **even vs odd bits of imm**, not nibbles.
2. `lotus_lut2/lotus_lut3` MUST be `always_inline` (or calls dominate; was 7x slowdown).
3. lotus5 driver: password must transpose into **row 1** (m[16]), not row 0.
4. BLIF cover semantics: f = (OR of 1-cubes if any, else 1) AND NOT(OR of 0-cubes).
5. Truth-table indexing conventions (tt[c], c = sum ins[b]<<b; emit VLUT3(r,q,p,imm)).
6. Macro-invocation lines need semicolons: `STEP(...); STEP(...);`.

## Performance (i3-1215U, AVX2, no AVX-512 on this machine!)

Baselines (single thread, run/john.baseline preserved):
- lotus5 scalar: 243,744 c/s; dominosec: 124,704 c/s (many salts), 81,792 (1 salt);
  8-thread: lotus5 1088K, dominosec 420K/283K, dominosec8 2756 (PBKDF2-bound).
- Bitslice core (AVX2, emulated LUT3, single thread): lotus5 **184K c/s** (~25% WORSE
  than scalar), domino_md_34 109K c/s. IPC ~2.26; throughput-bound (not latency).
  sbox disasm: 3058 instr (2261 vector ops + 559 vmovdqa), 0 calls.

### KEY FINDING (in flight): 2-input-LUT netlist for non-AVX-512
On AVX2 each LUT3 costs ~3.7 ops (mux emulation). ABC `if -K 2 -a` + mfs maps the
S-box to **983 two-input nodes** (verified k2-mfs-e flow, all nodes <= 2 inputs) —
each is exactly ONE vector op on AVX2/SSE2/NEON → est. ~2.7x fewer sbox instructions
→ est. ~450-500K c/s on AVX2 (vs 184K emulated, vs 244K scalar).
Plan: emit **dual-variant lotus_sboxes.h**: `#ifdef LOTUS_SBOX_LUT3` → 608-LUT3
netlist (AVX-512, VPTERNLOG = 1 op → est. ~1.4M c/s/core there); `#else` → 983-node
2-input netlist. Core sets LOTUS_SBOX_LUT3 in its __AVX512F__ branch.
gen_sbox.py already extended with FLOWS_K2 (run was cancelled; k2-mfs-e.blif =
983 nodes exists and verifies). emit_sbox.py NOT yet updated for dual emission.

## Follow-up (2026-11-03): dominosec8 bitslice enabled from AVX2 (depth 256) up

- `DOMINOSEC8_fmt_plug.c` now sets `LOTUS_BS_MIN_DEPTH 256` per-format
  (before `#include "lotus_common.h"`, `#ifndef`-guarded so `-D` overrides
  still work). lotus5/dominosec unchanged: scalar below AVX-512.
- Replaces an earlier unstaged hack (`#define LOTUS_BS_IN_USE` unconditionally)
  which would also have enabled it at depth 128/64 and caused a macro
  redefinition warning on AVX-512 builds.
- Rationale: dominosec8 is PBKDF2-bound (Lotus core <1% of runtime) → core
  choice is throughput-neutral at 256. Measured (pinned 1T, CPU 0):
  576 c/s bitslice-256 vs 585 c/s baseline scalar (noise); 8T 3034 c/s
  (matches earlier forced-256 3041). Real speedup remains AVX-512-only.
  Bonus: MKPC = LOTUS_BS_DEPTH batches the PBKDF2 OMP loop better.
- Verified: `--test` PASS (`[LOTUS 256/256]` in algo name), scalar #else
  branch syntax-checked with `-DLOTUS_BS_MIN_DEPTH=512`. Staged.

## FINAL STATE (session complete)

All three CPU formats integrated and verified. Change set (staged in git):
- src/lotus_sboxes.h (dual-variant: 600-LUT3 AVX-512 netlist + 951-gate
  2-input netlist; both verified symbolically + C harness 256/256)
- src/lotus_common.h (table extern, depth ladder, LOTUS_BS_IN_USE gate:
  bitslice active only at depth >= 512 i.e. AVX-512; scalar elsewhere,
  as anticipated in the issue; test override -DLOTUS_BS_MIN_DEPTH=128)
- src/lotus_common_plug.c (bitslice core + dominosec digest34/sec drivers)
- src/lotus5_fmt_plug.c, src/DOMINOSEC_fmt_plug.c, src/DOMINOSEC8_fmt_plug.c
  (dual-path like rawMD5; static lotus_magic_table copies removed - shared
  extern now; dominosec8 PBKDF2 tail unchanged)

Verification matrix (all PASS):
- core_test.c reference checks: AVX2, SSE2, JOHN_NO_SIMD builds
- john --test on: default AVX2 build (scalar paths), forced-bitslice builds
  at depth 256 (all 3 formats: [LOTUS 256/256] PASS), --disable-simd build,
  ASan build (both scalar and forced-bitslice paths), make check x2
- full AVX-512 build via ./configure --enable-simd=avx512: compiles+links
  clean; lotus_common_plug.o contains 1738 vpternlogd (LUT3 path confirmed);
  can't RUN here (no AVX-512 CPU - correctness rests on the identical
  netlist verified by harness + Intel ternarylogic imm semantics)

Benchmarks (this throttling AVX2-only i3-1215U; frequency unstable, treat
8-thread numbers as +/-25%):
- shipped default build (scalar paths): lotus5 1454K c/s (baseline 1088K),
  dominosec 695K many-salts (baseline 420K), dominosec8 3432 (baseline 2756)
  -- differences are mostly CPU-state noise; single-thread pinned lotus5
  252K vs 242K baseline (+4%), dominosec 128.7K vs 124.8K (+3%)
- bitslice at depth 256 (forced, NOT shipped): lotus5 762K/8threads vs
  scalar 1088K (slower, expected), dominosec 387K vs 452K, dominosec8
  3041 vs 2722 (faster - PBKDF2-dominated)
- AVX-512 projection (ops model, not measured): lotus5 ~1744*700/512 =
  ~2400 vector ops/candidate -> several times faster than scalar; needs
  benchmark on real AVX-512 hardware (follow-up)

## Original remaining-work notes (superseded above)

1. Update emit_sbox.py to emit both variants into one header (reuse the k<=2 pattern
   table; with a K=2 netlist there are no VLUT3 lines at all in the #else branch).
   Re-verify: symbolic check both variants + C harness for both (compile harness with
   -DLOTUS_SBOX_LUT3 + scalar VLUT3 for the LUT3 branch; plain for 2-input branch).
2. Re-run core_test (all 3 build flavors) + bench_core with the 2-input netlist.
3. Integrate `src/lotus5_fmt_plug.c` (dual path like rawMD5_fmt_plug.c):
   - `#if LOTUS_BS_DEPTH >= 256` (or 128 — decide by bench) bitslice crypt_all looping
     batches of LOTUS_BS_DEPTH, OMP over batches; MIN/MAX_KEYS_PER_CRYPT =
     LOTUS_BS_DEPTH; ALGORITHM_NAME e.g. "LOTUS 256/256 AVX2"; keep existing scalar
     code under #else (unchanged); crypt_key/get_hash/cmp unchanged.
   - Remove local lotus_magic_table (use shared extern). NOTE: scalar fallback path
     also uses the table — keep referencing lotus_magic_table from lotus_common.
4. `src/DOMINOSEC_fmt_plug.c`: crypt_all groups indices by length class
   (nblocks = len/16+1, classes 1..5); per class run batches of
   lotus_bs_domino_md; digest34 build stays scalar (hex_table); stage2 via
   lotus_bs_domino_md_34; keep keys_changed/salt_changed caching semantics;
   keep scalar path under #else.
5. `src/DOMINOSEC8_fmt_plug.c`: same core usage (identical stage1/stage2 code),
   PBKDF2-HMAC-SHA1 tail unchanged; keep scalar path under #else.
6. Builds/tests: default (AVX2 host), Makefile.legacy linux-x86-64-avx512 (compile +
   --test via qemu? NO — at least compile-check; correctness of LUT3 branch verified
   via harness), sse2 build, ./configure --disable-simd (scalar path), ASan, make check.
7. Benchmarks vs run/john.baseline; report table.

## Tooling (lotus_bs_devtools/)

- `gen_sbox.py` — ABC synthesis flows (LUT3 + K2), verification, writes
  /tmp/sbox/best{,2}.blif + T.json. ABC built at /tmp/abc/abc (`make ABC_USE_NO_READLINE=1`).
- `emit_sbox.py` — BLIF → src/lotus_sboxes.h + standalone C harness; symbolic
  per-node verification (catches pattern-table bugs; keep it!).
- `core_test.c` — bitslice vs scalar reference (needs -I src, link lotus_common_plug.c).
- `bench_core.c`, `bench_sbox.c`, `lut_test.c`, `sbox.pla`, `best.blif` (608 LUT3),
  `T.json`.
- Repo tree also has stale untracked files: src/h, src/w, run/john.baseline (intentional).

## Commands

```
# regenerate sbox expressions:
python3 /tmp/scripts/gen_sbox.py && python3 /tmp/scripts/emit_sbox.py
# core tests (3 flavors):
gcc -O2 -mavx2 -I src -o /tmp/core_avx2 lotus_bs_devtools/core_test.c src/lotus_common_plug.c && /tmp/core_avx2
gcc -O2 -I src -o /tmp/core_sse2 ... && gcc -O2 -DJOHN_NO_SIMD -I src -o /tmp/core_scalar ...
# bench:
gcc -O2 -mavx2 -I src -o /tmp/bench lotus_bs_devtools/bench_core.c src/lotus_common_plug.c && /tmp/bench
# format tests after integration:
cd run && ./john --format=lotus5 --test
```
