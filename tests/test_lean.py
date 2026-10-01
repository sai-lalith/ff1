"""Differential test: the Python implementation against the Lean spec in spec/.

The Lean spec is a line-by-line transcription of SP 800-38G Rev. 1 with machine-checked
proofs (spec/FF1Spec/Proofs.lean). Skipped unless the spec has been built:

    cd spec && lake build

FF1_DIFF_CASES (default 2000) and FF1_DIFF_SEED (default 80038) control the random test;
CI runs 20,000 cases per PR and a weekly job runs 200,000 with a fresh seed.
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


CASES = int(os.environ.get("FF1_DIFF_CASES", "2000"))
SEED = int(os.environ.get("FF1_DIFF_SEED", "80038"))
CHUNK = 2000


@functools.lru_cache(maxsize=64)
def alphabet_for(radix):
    """Distinct symbols for any radix up to 2**16 (supplementary-plane code points)."""
    return "".join(chr(0x10000 + i) for i in range(radix))


@functools.lru_cache(maxsize=256)
def cipher(key, radix):
    return FF1(key, alphabet=alphabet_for(radix))


def lean_line(op, key, radix, tweak, xs):
    return f"{op} {key.hex()} {radix} {tweak.hex() or '-'} {','.join(map(str, xs))}"


def run_lean(cases):
    """cases: (op, key bytes, radix, tweak bytes, numerals) -> list of numeral lists."""
    results = []
    for start in range(0, len(cases), CHUNK):
        chunk = cases[start:start + CHUNK]
        stdin = "".join(lean_line(*case) + "\n" for case in chunk)
        out = subprocess.run([str(LEAN_BIN)], input=stdin, capture_output=True, text=True,
                             check=True).stdout.splitlines()
        assert len(out) == len(chunk), out[-3:]
        results += [[int(x) for x in line.split(",")] for line in out]
    return results


def random_case(rng, keys):
    """One random (op, key, radix, tweak, numerals) case, biased towards edge values."""
    r = rng.random()
    if r < 0.35:
        radix = rng.randint(2, 64)
    elif r < 0.55:
        radix = rng.choice([2, 4, 8, 16, 32, 64, 128, 1024, 4096, 2 ** 16])
    elif r < 0.80:
        radix = rng.choice([10, 26, 36, 62, 100, 255, 256, 257, 1000, 2 ** 16 - 1])
    else:
        radix = rng.randint(65, 2 ** 16)
    # Fresh keys for cheap small alphabets; a fixed pool where building the alphabet is costly.
    key = rng.randbytes(rng.choice([16, 24, 32])) if radix <= 64 else rng.choice(keys)
    c = cipher(key, radix)

    longest = 1000 if radix <= 256 else 300
    n = rng.choices(
        [c.minlen, c.minlen + 1, rng.randint(c.minlen, 64), rng.randint(c.minlen, 200),
         rng.randint(c.minlen, longest)],
        weights=[10, 10, 50, 25, 5])[0]
    fill = rng.random()
    if fill < 0.05:
        xs = [0] * n
    elif fill < 0.10:
        xs = [radix - 1] * n
    else:
        xs = [rng.randrange(radix) for _ in range(n)]
    t = rng.choices(
        [0, rng.randint(1, 32), rng.choice([15, 16, 17, 31, 32, 33]), rng.randint(0, 300)],
        weights=[20, 40, 25, 15])[0]
    return rng.choice("ED"), c, rng.randbytes(t), xs


@unittest.skipUnless(LEAN_BIN.exists(), f"Lean spec not built ({LEAN_BIN})")
class MatchesLeanSpec(unittest.TestCase):

    def test_random_inputs(self):
        rng = random.Random(SEED)
        keys = [rng.randbytes(size) for size in (16, 24, 32) for _ in range(4)]
        cases, expected = [], []
        for _ in range(CASES):
            op, c, tweak, xs = random_case(rng, keys)
            text = "".join(c.alphabet[x] for x in xs)
            result = c.encrypt(text, tweak) if op == "E" else c.decrypt(text, tweak)
            cases.append((op, c._key, c.radix, tweak, xs))
            expected.append([c._index[ch] for ch in result])
        mismatches = [i for i, (got, want) in enumerate(zip(run_lean(cases), expected)) if got != want]
        if mismatches:
            self.fail(f"FF1_DIFF_SEED={SEED}: {len(mismatches)} of {CASES} cases differ from the spec; "
                      f"first Lean input: {lean_line(*cases[mismatches[0]])[:300]}")

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
