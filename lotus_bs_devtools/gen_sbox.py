#!/usr/bin/env python3
# Generate LUT3 S-box expressions for the Lotus "magic table" using ABC.
# Multi-output function via .pla input; verifies the mapped netlist by
# simulation before accepting. Emits /tmp/sbox/best.blif + stats.
import re, subprocess, sys, shutil, json

ABC = "/tmp/abc/abc"
SRC = "/home/user/repos/john/src/lotus5_fmt_plug.c"
OUT = "/tmp/sbox"

src = open(SRC).read()
m = re.search(r'lotus_magic_table\[\] = \{(.*?)\};', src, re.S)
vals = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1))]
T = vals[:256]
assert sorted(T) == list(range(256)), "not a permutation!"

def write_pla(path):
    with open(path, "w") as f:
        f.write(".i 8\n.o 8\n")
        f.write(".p 256\n")
        for x in range(256):
            # ilbl order i0..i7: leftmost char = i0? Try both, verify later.
            inpat = "".join(str((x >> k) & 1) for k in range(8))
            outpat = "".join(str((T[x] >> k) & 1) for k in range(8))
            f.write(f"{inpat} {outpat}\n")
        f.write(".e\n")

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

def simulate(inputs, outputs, nodes):
    """Return list of 8 ints (truth tables) for outputs, or None if netlist
    is not simulatable (e.g., latches)."""
    def lut_of(n):
        ins = n["nets"][:-1]
        on, off = [], []
        for pat, val in n["cover"]:
            if len(pat) != len(ins) or val not in ("0", "1"):
                return None
            (on if val == "1" else off).append(pat)
        imm = [0] * (1 << len(ins))
        for c in range(1 << len(ins)):
            def match(pat):
                return all(pat[b] == "-" or pat[b] == str((c >> b) & 1)
                           for b in range(len(ins)))
            v1 = (not on) or any(match(p) for p in on)
            v0 = any(match(p) for p in off)
            imm[c] = 1 if (v1 and not v0) else 0
        return ins, imm
    gates = []
    for n in nodes:
        r = lut_of(n)
        if r is None:
            return None
        gates.append((n["nets"][-1], r[0], r[1]))
    tts = [0] * len(outputs)
    for x in range(256):
        val = {}
        for k, name in enumerate(inputs):
            val[name] = (x >> k) & 1
        changed = True
        remaining = list(gates)
        while remaining:
            progressed = False
            for g in list(remaining):
                out, ins, imm = g
                if all(i in val for i in ins):
                    idx = 0
                    for b, i in enumerate(ins):
                        idx |= val[i] << b
                    val[out] = imm[idx]
                    remaining.remove(g)
                    progressed = True
            if not progressed:
                return None
        for k, name in enumerate(outputs):
            if val.get(name, 0):
                tts[k] |= 1 << x
    return tts

def expected_tts():
    tts = []
    for b in range(8):
        v = 0
        for x in range(256):
            if (T[x] >> b) & 1:
                v |= 1 << x
        tts.append(v)
    return tts

RESYN2 = "balance; rewrite; refactor; balance; rewrite; rewrite -z; " \
         "balance; refactor -z; rewrite -z; balance"

FLOWS = {
    "plain":        ["if -K 3"],
    "dch":          ["strash", "dch -f", "if -K 3"],
    "dch-a":        ["strash", "dch -f", "if -K 3 -a"],
    "resyn2+dch-a": [RESYN2, "strash", "dch -f", "if -K 3 -a"],
    "resyn2x3+dch-a": [RESYN2 + "; " + RESYN2 + "; " + RESYN2, "strash", "dch -f", "if -K 3 -a"],
    "resyn2x3+mfs": [RESYN2 + "; " + RESYN2 + "; " + RESYN2,
                     "strash", "dch -f", "if -K 3 -a", "mfs", "mfs -e"],
    "resyn2x3+dc2+mfs": [RESYN2 + "; " + RESYN2 + "; " + RESYN2,
                     "strash", "dc2", "dch -f", "if -K 3 -a", "mfs", "mfs -e"],
}

FLOWS_K2 = {
    "k2-plain":  ["strash", "dch -f", "if -K 2 -a"],
    "k2-resyn":  [RESYN2 + "; " + RESYN2 + "; " + RESYN2, "strash", "dch -f", "if -K 2 -a"],
    "k2-mfs":    [RESYN2 + "; " + RESYN2 + "; " + RESYN2, "strash", "dch -f", "if -K 2 -a", "mfs"],
    "k2-mfs-e":  [RESYN2 + "; " + RESYN2 + "; " + RESYN2, "strash", "dc2", "dch -f", "if -K 2 -a", "mfs", "mfs -e"],
    "k2-mfs-e2": [RESYN2 + "; " + RESYN2 + "; " + RESYN2, "strash", "dc2", "dch -f", "if -K 2 -a", "mfs", "mfs -e", "mfs -e"],
}

write_pla(f"{OUT}/sbox.pla")
exp = expected_tts()
results = []
for name, cmds in FLOWS.items():
    blif_path = f"{OUT}/{name}.blif"
    script = [f"read_pla {OUT}/sbox.pla"] + cmds + [f"write_blif {blif_path}"]
    p = subprocess.run([ABC, "-q", "; ".join(script) + "; quit"],
                       capture_output=True, text=True)
    try:
        inputs, outputs, nodes = parse_blif(blif_path)
        tts = simulate(inputs, outputs, nodes)
        if tts is None:
            print(f"{name}: netlist not simulatable")
            continue
        ok = (tts == exp)
        # input convention check: if wrong, try reversed input order
        if not ok and tts[::-1] == exp:
            print("NOTE: output order reversed")
        luts = [n for n in nodes if n["nets"][-1] not in outputs]
        print(f"{name:17s} LUT3={len(luts):4d} verify={'OK' if ok else 'FAIL'}")
        if ok:
            results.append((len(luts), name, blif_path))
    except Exception as e:
        print(f"{name}: FAILED {e}")

if not results:
    sys.exit("no verified result!")
results.sort()
best = results[0]
print("\nBEST LUT3:", best[1], "count =", best[0])
shutil.copy(best[2], f"{OUT}/best.blif")

# 2-input-LUT flows (each node -> one vector op on non-AVX-512 targets)
results2 = []
for name, cmds in FLOWS_K2.items():
    blif_path = f"{OUT}/{name}.blif"
    script = [f"read_pla {OUT}/sbox.pla"] + cmds + [f"write_blif {blif_path}"]
    p = subprocess.run([ABC, "-q", "; ".join(script) + "; quit"],
                       capture_output=True, text=True)
    try:
        inputs, outputs, nodes = parse_blif(blif_path)
        tts = simulate(inputs, outputs, nodes)
        if tts is None:
            print(f"{name}: not simulatable"); continue
        ok = (tts == exp)
        luts = [n for n in nodes if n["nets"][-1] not in outputs]
        kbad = [n for n in luts if len(n["nets"]) - 1 > 2]
        print(f"{name:12s} nodes={len(luts):4d} >2in={len(kbad)} verify={'OK' if ok else 'FAIL'}")
        if ok and not kbad:
            results2.append((len(luts), name, blif_path))
    except Exception as e:
        print(f"{name}: FAILED {e}")

if results2:
    results2.sort()
    b2 = results2[0]
    print("\nBEST K2:", b2[1], "count =", b2[0])
    shutil.copy(b2[2], f"{OUT}/best2.blif")

json.dump(T, open(f"{OUT}/T.json", "w"))
