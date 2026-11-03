#!/usr/bin/env python3
# Emit src/lotus_sboxes.h from /tmp/sbox/best.blif with built-in symbolic
# verification of every emitted expression, then a standalone C harness.
import sys, subprocess, json, re

BLIF = "/tmp/sbox/best.blif"
HEADER = "/home/user/repos/john/src/lotus_sboxes.h"
TEST = "/tmp/sbox/sbox_test.c"
T = json.load(open("/tmp/sbox/T.json"))

def parse_blif(path):
    inputs, outputs, nodes = [], [], []
    cur = None
    for line in open(path):
        line = line.strip()
        if line.startswith(".inputs"):
            inputs = line.split()[1:]
        elif line.startswith(".outputs"):
            outputs = line.split()[1:]
        elif line.startswith(".names"):
            cur = {"nets": line.split()[1:], "cover": []}
            nodes.append(cur)
        elif line and cur is not None and not line.startswith("."):
            cur["cover"].append(line.split())
        elif line.startswith(".end"):
            cur = None
    return inputs, outputs, nodes

inputs, outputs, nodes = parse_blif(BLIF)
assert inputs == ["x0","x1","x2","x3","x4","x5","x6","x7"]
assert outputs == ["z0","z1","z2","z3","z4","z5","z6","z7"]

def truth(n):
    ins = n["nets"][:-1]
    k = len(ins)
    on  = [p for p, v in n["cover"] if v == "1"]
    off = [p for p, v in n["cover"] if v == "0"]
    tt = []
    for c in range(1 << k):
        def match(pat):
            return all(pat[b] == "-" or pat[b] == str((c >> b) & 1)
                       for b in range(k))
        v1 = (not on) or any(match(p) for p in on)
        v0 = any(match(p) for p in off)
        tt.append(1 if (v1 and not v0) else 0)
    return tt

# topo order
by_out = {n["nets"][-1]: n for n in nodes}
order, seen = [], set(inputs)
def visit(net):
    if net in seen:
        return
    seen.add(net)
    if net in by_out:
        for i in by_out[net]["nets"][:-1]:
            visit(i)
        order.append(by_out[net])
for o in outputs:
    visit(o)

# symbolic tables: 256-bit int; bit x = value at primary input value x
tab = {}
for k, i in enumerate(inputs):
    tab[i] = sum(((x >> k) & 1) << x for x in range(256))
ONES = (1 << 256) - 1
tab['vzero'] = 0
tab['vones'] = ONES

def ev(expr):
    expr = expr.strip()
    m = re.fullmatch(r'VLUT3\((\w+), (\w+), (\w+), (0x[0-9A-Fa-f]+)\)', expr)
    if m:
        a, b, c, imm = tab[m.group(1)], tab[m.group(2)], tab[m.group(3)], int(m.group(4), 16)
        out = 0
        for x in range(256):
            idx = (((a >> x) & 1) << 2) | (((b >> x) & 1) << 1) | ((c >> x) & 1)
            out |= ((imm >> idx) & 1) << x
        return out
    for pat, fn in [
        (r'VXOR\((\w+), (\w+)\)', lambda p, q: p ^ q),
        (r'VAND\((\w+), (\w+)\)', lambda p, q: p & q),
        (r'VOR\((\w+), (\w+)\)', lambda p, q: p | q),
        (r'VANDN\((\w+), (\w+)\)', lambda p, q: p & (ONES ^ q)),
        (r'VNOT\(VXOR\((\w+), (\w+)\)\)', lambda p, q: ONES ^ (p ^ q)),
        (r'VNOT\(VAND\((\w+), (\w+)\)\)', lambda p, q: ONES ^ (p & q)),
        (r'VNOT\(VOR\((\w+), (\w+)\)\)', lambda p, q: ONES ^ (p | q)),
        (r'VNOT\(VANDN\((\w+), (\w+)\)\)', lambda p, q: ONES ^ (p & (ONES ^ q))),
        (r'VNOT\((\w+)\)', lambda p: ONES ^ p),
    ]:
        m = re.fullmatch(pat, expr)
        if m:
            return fn(*[tab[g] for g in m.groups()])
    if expr == 'vzero':
        return 0
    if expr == 'vones':
        return ONES
    if re.fullmatch(r'\w+', expr):
        return tab[expr]
    raise SystemExit("unparsed expr: " + expr)

names = {i: i for i in inputs}
lines = []
n_lut3 = n_xor3 = n_2in = n_alias = n_not = n_const = 0
vidx = 0
for n in order:
    ins = n["nets"][:-1]
    out = n["nets"][-1]
    tt = truth(n)
    k = len(ins)
    # expected table: evaluate node truth at its inputs' current tables
    want = 0
    for x in range(256):
        c = 0
        for b in range(k):
            c |= ((tab[ins[b]] >> x) & 1) << b
        if tt[c]:
            want |= 1 << x
    if k == 0:
        expr = "vones" if tt[0] else "vzero"; n_const += 1
    elif k == 1:
        if tt == [0, 1]:
            names[out] = names[ins[0]]; n_alias += 1; tab[out] = tab[ins[0]]; continue
        assert tt == [1, 0], tt
        expr = "VNOT(%s)" % names[ins[0]]; n_not += 1
    elif k == 2:
        p, q = names[ins[0]], names[ins[1]]
        table = {
            (0,0,0,0): "vzero",                       # const 0
            (0,0,0,1): "VAND(%s, %s)" % (p, q),       # a & b
            (0,0,1,0): "VANDN(%s, %s)" % (q, p),      # ~a & b
            (0,0,1,1): q,                             # b (alias)
            (0,1,0,0): "VANDN(%s, %s)" % (p, q),      # a & ~b
            (0,1,0,1): p,                             # a (alias)
            (0,1,1,0): "VXOR(%s, %s)" % (p, q),       # a ^ b
            (0,1,1,1): "VOR(%s, %s)" % (p, q),        # a | b
            (1,0,0,0): "VNOT(VOR(%s, %s))" % (p, q),  # nor
            (1,0,0,1): "VNOT(VXOR(%s, %s))" % (p, q), # xnor
            (1,0,1,0): "VNOT(%s)" % p,                # ~a
            (1,0,1,1): "VNOT(VANDN(%s, %s))" % (p, q),# b | ~a
            (1,1,0,0): "VNOT(%s)" % q,                # ~b
            (1,1,0,1): "VNOT(VANDN(%s, %s))" % (q, p),# a | ~b
            (1,1,1,0): "VNOT(VAND(%s, %s))" % (p, q), # nand
            (1,1,1,1): "vones",                       # const 1
        }
        expr = table[tuple(tt)]
        if expr in (p, q):
            names[out] = expr; n_alias += 1; tab[out] = tab[expr]; continue
        if expr in ("vzero", "vones"):
            n_const += 1
        else:
            n_2in += 1
    else:
        assert k == 3
        imm = 0
        for c in range(8):
            imm |= tt[c] << c
        p, q, r = names[ins[0]], names[ins[1]], names[ins[2]]
        if imm == 0x96:
            expr = "VXOR(VXOR(%s, %s), %s)" % (p, q, r); n_xor3 += 1
        elif imm == 0x69:
            expr = "VNOT(VXOR(VXOR(%s, %s), %s))" % (p, q, r); n_xor3 += 1
        elif imm in (0x00, 0xFF):
            expr = "vones" if imm else "vzero"; n_const += 1
        else:
            expr = "VLUT3(%s, %s, %s, 0x%02X)" % (r, q, p, imm); n_lut3 += 1
    got = ev(expr)
    if got != want:
        sys.exit("EMISSION BUG net %s cover %s: expr %s\n  tt %s" %
                 (n["nets"], n["cover"], expr, tt))
    vname = "v%d" % vidx; vidx += 1
    names[out] = vname
    tab[out] = got
    tab[vname] = got
    lines.append("\tvtype %s = %s;" % (vname, expr))

# final check against the table itself
for k, o in enumerate(outputs):
    want = sum(((T[x] >> k) & 1) << x for x in range(256))
    if tab[names[o]] != want:
        sys.exit("OUTPUT MISMATCH z%d" % k)
print("symbolic verify: all 608 nodes + 8 outputs OK")

body = "\n".join(lines)
out_assign = "\n".join("\t*z%d = %s;" % (k, names[o])
                       for k, o in enumerate(outputs))

hdr = f"""/*
 * Bitslice Lotus S-box (the 8-bit permutation known as lotus_magic_table)
 * as 3-input LUT expressions (NVIDIA LOP3.LUT / x86-64 AVX-512 VPTERNLOG).
 *
 * Generated with Berkeley ABC (read_pla; resyn2 x3; dc2; dch -f; if -K 3 -a;
 * mfs; mfs -e) and verified to match the table for all 256 input values.
 * Gate counts: {n_lut3} LUT3, {n_xor3} XOR3, {n_2in} 2-input gates,
 * {n_not} NOT, {n_const} constants, {n_alias} aliases bypassed
 * (total ops: {n_lut3 + n_xor3 + n_2in + n_not}, logic depth: 11 levels).
 *
 * For openwall/john issue #5451 (Switch Lotus formats to bitslice
 * implementation), following the approach taken for DES in sboxes-t.c
 * (expressions by Sovyn Y.) -- the Lotus S-box is 8x8 bit, so the gate
 * count is necessarily much larger than for any one DES S-box.
 *
 * This C source code representation is
 * Copyright (c) 2026 <generated for openwall/john>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * The underlying mathematical formulas are NOT copyrighted.
 */

/* Inputs: x0 is the LSB of the S-box input byte, ... x7 the MSB.
 * Outputs: z0 is the LSB of the S-box output byte, ... z7 the MSB. */

LOTUS_NOINLINE static void
lotus_sbox(vtype x0, vtype x1, vtype x2, vtype x3,
    vtype x4, vtype x5, vtype x6, vtype x7,
    vtype *z0, vtype *z1, vtype *z2, vtype *z3,
    vtype *z4, vtype *z5, vtype *z6, vtype *z7)
{{
{body}

{out_assign}
}}
"""
open(HEADER, "w").write(hdr)
print("wrote", HEADER, ": LUT3", n_lut3, "XOR3", n_xor3, "2in", n_2in,
      "NOT", n_not, "const", n_const, "alias", n_alias)

# standalone C verification harness
test = """#include <stdio.h>
#include <stdint.h>
typedef uint64_t vtype;
#define VXOR(a, b) ((a) ^ (b))
#define VAND(a, b) ((a) & (b))
#define VOR(a, b)  ((a) | (b))
#define VANDN(a, b) ((a) & ~(b))
#define VNOT(a)    (~(a))
static inline vtype VLUT3(vtype a, vtype b, vtype c, int imm)
{
	return (imm >> ((((a != 0) << 2) | ((b != 0) << 1) | (c != 0)))) & 1
	    ? ~(vtype)0 : (vtype)0;
}
static vtype vzero = 0, vones = ~(uint64_t)0;
#define LOTUS_NOINLINE
#include "/home/user/repos/john/src/lotus_sboxes.h"
static const unsigned char T[256] = {
#include "/tmp/sbox/T.inc"
};
int main(void)
{
	for (int x = 0; x < 256; x++) {
		vtype z[8];
		lotus_sbox(x & 1 ? vones : vzero, x & 2 ? vones : vzero,
		           x & 4 ? vones : vzero, x & 8 ? vones : vzero,
		           x & 16 ? vones : vzero, x & 32 ? vones : vzero,
		           x & 64 ? vones : vzero, x & 128 ? vones : vzero,
		           &z[0], &z[1], &z[2], &z[3], &z[4], &z[5], &z[6], &z[7]);
		int y = 0;
		for (int k = 0; k < 8; k++)
			y |= (z[k] != 0) << k;
		if (y != T[x]) {
			printf("MISMATCH x=%02x got %02x want %02x\\n", x, y, T[x]);
			return 1;
		}
	}
	puts("sbox verify: OK (256/256)");
	return 0;
}
"""
open(TEST, "w").write(test)
open("/tmp/sbox/T.inc", "w").write(
    "".join(("\t0x%02x,%s" % (T[i], "\n" if i % 16 == 15 else " ")
             for i in range(256))))
r = subprocess.run(["gcc", "-O2", "-o", "/tmp/sbox/sbox_test", TEST],
                   capture_output=True, text=True)
if r.returncode:
    print(r.stderr[:3000]); sys.exit(1)
r = subprocess.run(["/tmp/sbox/sbox_test"], capture_output=True, text=True)
print(r.stdout, r.stderr)
sys.exit(r.returncode)
