#!/usr/bin/env python3
"""Join native and wasm benchmark CSVs row by row (same mode, op and size).

Usage: compare_native_wasm.py NATIVE.csv WASM.csv [OTHER.csv ...]
Each input is the output of bench_runs (or bench_wasm.mjs), including the
leading `digest,<mode>,<sha256>` lines. Fails if the digests differ or the
rows do not match one to one, so only identical jobs are ever compared.
Every output row is one job; there is no ranking across jobs or modes, and
the ratio is only between the same job on two paths.
"""
import csv, sys

def load(path):
    digests, rows = {}, {}
    for line in open(path):
        line = line.strip()
        if line.startswith("digest,"):
            _, mode, hexd = line.split(",")
            digests[int(mode)] = hexd
    body = [l for l in open(path) if not l.startswith("digest,")]
    for r in csv.DictReader(body):
        rows[(int(r["mode"]), r["op"], int(r["bytes"]))] = r
    return digests, rows

def main(paths):
    if len(paths) < 2:
        sys.exit(__doc__)
    data = [(p, *load(p)) for p in paths]
    base_p, base_d, base_r = data[0]
    for p, d, r in data[1:]:
        if d != base_d or len(d) != 3:
            sys.exit(f"FAIL: envelope digests differ or are missing ({base_p} vs {p}): not the same job")
        if set(r) != set(base_r):
            sys.exit(f"FAIL: row sets differ ({base_p} vs {p})")
    names = [p.rsplit("/", 1)[-1].removesuffix(".csv") for p, _, _ in data]
    print("mode,op,bytes," + ",".join(f"{n}_median_mib_s,{n}_spread_pct" for n in names) +
          "," + ",".join(f"{n}_vs_{names[0]}" for n in names[1:]))
    for key in sorted(base_r, key=lambda k: (k[0], k[2], k[1])):
        med = [float(r[key]["median_mib_s"]) for _, _, r in data]
        spr = [r[key]["spread_pct"] for _, _, r in data]
        cells = [f"{m:.3f},{s}" for m, s in zip(med, spr)]
        ratios = [f"{m / med[0]:.2f}" for m in med[1:]]
        print(f"{key[0]},{key[1]},{key[2]}," + ",".join(cells) + "," + ",".join(ratios))

main(sys.argv[1:])
