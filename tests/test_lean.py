"""Differential test: the Python implementation against the Lean spec in spec/.

The Lean spec is a line-by-line transcription of SP 800-38G Rev. 1 with machine-checked
proofs (spec/FF1Spec/Proofs.lean). Skipped unless the spec has been built:

    cd spec && lake build
"""
import functools
import json
import os
import pathlib
import random
import subprocess
import unittest

from ff1 import FF1

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEAN_BIN = pathlib.Path(os.environ.get("FF1_LEAN_BIN", ROOT / "spec" / ".lake" / "build" / "bin" / "ff1spec"))
ACVP = json.loads((ROOT / "tests" / "data" / "acvp_ff1.json").read_text())


@functools.cache
def alphabet_for(radix):
    """Distinct symbols for any radix up to 2**16 (supplementary-plane code points)."""
    return "".join(chr(0x10000 + i) for i in range(radix))


@functools.cache
def cipher(key, radix):
    return FF1(key, alphabet=alphabet_for(radix))


def run_lean(cases):
    """cases: (op, key bytes, radix, tweak bytes, numerals) -> list of numeral lists."""
    lines = []
    for op, key, radix, tweak, xs in cases:
        lines.append(f"{op} {key.hex()} {radix} {tweak.hex() or '-'} {','.join(map(str, xs))}\n")
    out = subprocess.run([str(LEAN_BIN)], input="".join(lines), capture_output=True, text=True,
                         check=True).stdout.splitlines()
    assert len(out) == len(cases), out[-3:]
    return [[int(x) for x in line.split(",")] for line in out]


@unittest.skipUnless(LEAN_BIN.exists(), f"Lean spec not built ({LEAN_BIN})")
class MatchesLeanSpec(unittest.TestCase):

    def test_random_inputs(self):
        rng = random.Random(800_38)
        keys = [rng.randbytes(size) for size in (16, 24, 32) for _ in range(2)]
        cases, expected = [], []
        for _ in range(2000):
            radix = rng.choice([2, 3, 7, 10, 16, 26, 36, 62, 64, 100, 255, 256, 1000, 65535, 65536])
            c = cipher(rng.choice(keys), radix)
            n = rng.randint(c.minlen, rng.choice([30, 60, 200]))
            xs = [rng.randrange(radix) for _ in range(n)]
            tweak = rng.randbytes(rng.choice([0, 1, 7, 15, 16, 17, 40]))
            op = rng.choice("ED")
            text = "".join(c.alphabet[x] for x in xs)
            result = c.encrypt(text, tweak) if op == "E" else c.decrypt(text, tweak)
            cases.append((op, c._key, radix, tweak, xs))
            expected.append([c._index[ch] for ch in result])
        for case, got, want in zip(cases, run_lean(cases), expected):
            with self.subTest(op=case[0], radix=case[2], n=len(case[4])):
                self.assertEqual(got, want)

    def test_spec_matches_acvp(self):
        cases, expected = [], []
        for group in ACVP["testGroups"]:
            alphabet = group["alphabet"]
            for t in group["tests"]:
                src, dst = (t["pt"], t["ct"]) if group["direction"] == "encrypt" else (t["ct"], t["pt"])
                cases.append(("E" if group["direction"] == "encrypt" else "D", bytes.fromhex(t["key"]),
                              len(alphabet), bytes.fromhex(t["tweak"]), [alphabet.index(ch) for ch in src]))
                expected.append([alphabet.index(ch) for ch in dst])
        self.assertEqual(run_lean(cases), expected)


if __name__ == "__main__":
    unittest.main()
