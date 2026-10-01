"""Differential test against an independent FF3-1 implementation (mysto `ff3`).

Skipped unless `ff3` is installed: pip install -e '.[test]'
"""
import random
import unittest

from ff3_1 import FF3_1

try:
    from ff3 import FF3Cipher
except ImportError:
    FF3Cipher = None


@unittest.skipIf(FF3Cipher is None, "reference implementation `ff3` not installed")
class MatchesReference(unittest.TestCase):

    def test_random_inputs(self):
        rng = random.Random(2021)
        for _ in range(2000):
            radix = rng.choice([2, 8, 10, 16, 26, 36, 62])
            key = rng.randbytes(rng.choice([16, 24, 32]))
            tweak = rng.randbytes(7)
            ours = FF3_1(key, radix=radix)
            ref = FF3Cipher.withCustomAlphabet(key.hex(), tweak.hex(), ours.alphabet)
            minlen = next(n for n in range(2, 100) if radix ** n >= ours.DOMAIN_MIN)
            n = rng.randint(minlen, ours.maxlen)
            pt = "".join(rng.choice(ours.alphabet) for _ in range(n))
            with self.subTest(radix=radix, key=key.hex(), tweak=tweak.hex(), pt=pt):
                ct = ours.encrypt(pt, tweak)
                self.assertEqual(ct, ref.encrypt(pt))
                self.assertEqual(ours.decrypt(ct, tweak), ref.decrypt(ct))


if __name__ == "__main__":
    unittest.main()
