#!/usr/bin/env python3
"""Tests for compare_native_wasm.py: run with `python3 scripts/test_compare_native_wasm.py`."""
import os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "compare_native_wasm.py")
HEADER = "mode,op,bytes,runs,iterations,median_mib_s,min_mib_s,max_mib_s,spread_pct"
DIGESTS = {0: "aa", 1: "bb", 2: "cc"}

def csv_text(digests=DIGESTS, rows=None, extra_digest_lines=()):
    rows = rows if rows is not None else [(m, op, 64) for m in range(3) for op in ("seal", "open")]
    lines = [f"digest,{m},{h}" for m, h in digests.items()] + list(extra_digest_lines) + [HEADER]
    lines += [f"{m},{op},{b},3,10,5.0,4.0,6.0,40.0" for m, op, b in rows]
    return "\n".join(lines) + "\n"

class Compare(unittest.TestCase):
    def run_script(self, *texts):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, t in enumerate(texts):
                p = os.path.join(d, f"in{i}.csv")
                open(p, "w").write(t)
                paths.append(p)
            return subprocess.run([sys.executable, SCRIPT, *paths], capture_output=True, text=True)

    def test_matching_inputs_join(self):
        r = self.run_script(csv_text(), csv_text())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(r.stdout.strip().splitlines()), 1 + 6)

    def test_changed_digest_fails(self):
        r = self.run_script(csv_text(), csv_text(digests={0: "aa", 1: "xx", 2: "cc"}))
        self.assertNotEqual(r.returncode, 0)

    def test_missing_row_fails(self):
        r = self.run_script(csv_text(), csv_text(rows=[(0, "seal", 64)]))
        self.assertNotEqual(r.returncode, 0)

    def test_duplicate_row_key_fails(self):
        dup = [(m, op, 64) for m in range(3) for op in ("seal", "open")] + [(0, "seal", 64)]
        r = self.run_script(csv_text(), csv_text(rows=dup))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("duplicate", r.stderr)

    def test_digest_modes_must_be_0_1_2_in_every_input(self):
        wrong = {0: "aa", 1: "bb", 3: "dd"}
        self.assertNotEqual(self.run_script(csv_text(digests=wrong), csv_text(digests=wrong)).returncode, 0)
        self.assertNotEqual(self.run_script(csv_text(), csv_text(digests=wrong)).returncode, 0)

    def test_duplicate_digest_line_fails(self):
        r = self.run_script(csv_text(), csv_text(extra_digest_lines=["digest,1,bb"]))
        self.assertNotEqual(r.returncode, 0)

if __name__ == "__main__":
    unittest.main()
