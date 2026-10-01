"""Spec-step checks and structural properties that hold for any correct FF1."""
import random
import unittest

from ff1 import FF1

KEY = "2B7E151628AED2A6ABF7158809CF4F3C"


class SpecSteps(unittest.TestCase):
    # Intermediate values from NIST FF1 sample #1, round 0 (u = v = 5, b = 3, d = 8).
    P = bytes([1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0])
    Q = bytes(14) + bytes([221, 213])
    R = bytes([195, 184, 41, 161, 232, 100, 43, 120, 204, 41, 148, 123, 59, 147, 219, 99])

    def test_prf(self):
        self.assertEqual(FF1(KEY)._prf(self.P + self.Q), self.R)

    def test_round_function(self):
        y = FF1(KEY)._round(self.P, bytes(12), 0, 56789, 3, 8)
        self.assertEqual(y, 14103068008476060536)

    def test_round_function_matches_reference(self):
        # The optimized round function must equal the direct transcription of steps 6.i-6.iv,
        # including halves spanning several blocks (b > 15) and outputs needing d > 16.
        rng = random.Random(7)
        alphabets = ["".join(chr(0x10000 + i) for i in range(r)) for r in (2, 10, 1000, 65536)]
        ciphers = [FF1(rng.randbytes(16), alphabet=a) for a in alphabets for _ in range(3)]
        for _ in range(300):
            c = rng.choice(ciphers)
            n = rng.randint(c.minlen, 120)
            tweak = rng.randbytes(rng.choice([0, 5, 16, 40, 100]))
            u, v, blen, d, p, q_prefix = c._setup(n, tweak)
            fast = c._round_function(p + q_prefix, blen, d)
            for i in range(10):
                x = rng.randrange(c.radix ** v)
                self.assertEqual(fast(i, x), c._round(p, q_prefix, i, x, blen, d))

    def test_length_limits(self):
        c = FF1(KEY)
        self.assertEqual(c.minlen, 6)
        self.assertEqual(FF1(KEY, radix=2).minlen, 20)
        c.encrypt("1" * 6)
        c.encrypt("1" * 1000)
        with self.assertRaises(ValueError):
            c.encrypt("1" * 5)   # 10**5 < 1,000,000


class Properties(unittest.TestCase):

    def test_round_trip_random(self):
        rng = random.Random(1)
        for _ in range(500):
            c = FF1(rng.randbytes(rng.choice([16, 24, 32])), radix=rng.choice([2, 10, 16, 26, 36, 62]))
            pt = "".join(rng.choice(c.alphabet) for _ in range(rng.randint(c.minlen, 80)))
            tweak = rng.randbytes(rng.randint(0, 40))
            ct = c.encrypt(pt, tweak)
            self.assertEqual(len(ct), len(pt))
            self.assertTrue(set(ct) <= set(c.alphabet))
            self.assertEqual(c.decrypt(ct, tweak), pt)

    def test_whole_domain_is_permutation(self):
        # Shrink the domain floor so every input of a small domain can be enumerated.
        class Small(FF1):
            DOMAIN_MIN = 2

        for radix, n in [(2, 10), (3, 6), (10, 3), (17, 3), (62, 2)]:
            with self.subTest(radix=radix, n=n):
                c = Small(KEY, radix=radix)
                domain = [c._str(x, n) for x in range(radix ** n)]
                cts = [c.encrypt(pt, b"tw") for pt in domain]
                self.assertEqual(sorted(cts), sorted(domain))
                self.assertEqual([c.decrypt(ct, b"tw") for ct in cts], domain)

    def test_tweak_and_key_change_output(self):
        pt = "4111111111111111"
        base = FF1(KEY).encrypt(pt, b"a")
        self.assertNotEqual(FF1(KEY).encrypt(pt, b"b"), base)
        self.assertNotEqual(FF1(KEY).encrypt(pt), base)
        self.assertNotEqual(FF1("2B7E151628AED2A6ABF7158809CF4F3D").encrypt(pt, b"a"), base)


class Validation(unittest.TestCase):

    def test_bad_inputs(self):
        c = FF1(KEY)
        cases = [
            lambda: FF1(b"short"),
            lambda: FF1("not hex"),
            lambda: FF1(KEY, alphabet="aab"),
            lambda: FF1(KEY, radix=63),
            lambda: FF1(KEY, alphabet="a"),
            lambda: c.encrypt("12345678x"),
            lambda: c.encrypt("123456789", "zz"),
        ]
        for i, case in enumerate(cases):
            with self.subTest(i):
                with self.assertRaises(ValueError):
                    case()


if __name__ == "__main__":
    unittest.main()
