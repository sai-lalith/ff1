"""Spec-step checks and structural properties that hold for any correct FF3-1."""
import random
import unittest

from ff3_1 import FF3_1
from ff3_1.cipher import _split_tweak

KEY = "EF4359D8D580AA4F7F036D6F04FC6A94"
TWEAK = "D8E7920AFA330A"


class SpecSteps(unittest.TestCase):

    def test_tweak_split(self):
        # T = D8E792 0A FA330A: the 4th byte's high nibble goes to T_L, low nibble to T_R.
        t_left, t_right = _split_tweak("D8E7920AFA330A")
        self.assertEqual(t_left.hex().upper(), "D8E79200")
        self.assertEqual(t_right.hex().upper(), "FA330AA0")

    def test_p_block(self):
        # NIST FF3 sample #1, round 0: B = "567890000", W = FA330A73.
        c = FF3_1(KEY)
        p = c._p(0, bytes.fromhex("FA330A73"), "567890000")
        self.assertEqual(p, bytes([250, 51, 10, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 129, 205]))

    def test_length_limits(self):
        c = FF3_1(KEY)
        self.assertEqual(c.maxlen, 56)
        c.encrypt("1" * 6, TWEAK)
        c.encrypt("1" * 56, TWEAK)
        with self.assertRaises(ValueError):
            c.encrypt("1" * 5, TWEAK)   # 10**5 < 1,000,000
        with self.assertRaises(ValueError):
            c.encrypt("1" * 57, TWEAK)
        self.assertEqual(FF3_1(KEY, radix=26).maxlen, 40)
        self.assertEqual(FF3_1(KEY, radix=36).maxlen, 36)


class Properties(unittest.TestCase):

    def test_round_trip_random(self):
        rng = random.Random(1)
        for _ in range(500):
            radix = rng.choice([2, 10, 16, 26, 36, 62])
            c = FF3_1(rng.randbytes(rng.choice([16, 24, 32])), radix=radix)
            minlen = next(n for n in range(2, 100) if radix ** n >= c.DOMAIN_MIN)
            n = rng.randint(minlen, c.maxlen)
            pt = "".join(rng.choice(c.alphabet) for _ in range(n))
            tweak = rng.randbytes(7)
            ct = c.encrypt(pt, tweak)
            self.assertEqual(len(ct), n)
            self.assertTrue(set(ct) <= set(c.alphabet))
            self.assertEqual(c.decrypt(ct, tweak), pt)

    def test_whole_domain_is_permutation(self):
        # Shrink the domain floor so every input of a small domain can be enumerated.
        class Small(FF3_1):
            DOMAIN_MIN = 2

        for radix, n in [(2, 10), (3, 6), (10, 3), (17, 3), (62, 2)]:
            with self.subTest(radix=radix, n=n):
                c = Small(KEY, radix=radix)
                domain = [c._str_rev(x, n)[::-1] for x in range(radix ** n)]
                cts = [c.encrypt(pt, TWEAK) for pt in domain]
                self.assertEqual(sorted(cts), sorted(domain))
                self.assertEqual([c.decrypt(ct, TWEAK) for ct in cts], domain)

    def test_tweak_and_key_change_output(self):
        pt = "4111111111111111"
        base = FF3_1(KEY).encrypt(pt, TWEAK)
        self.assertNotEqual(FF3_1(KEY).encrypt(pt, "D8E7920AFA330B"), base)
        self.assertNotEqual(FF3_1("EF4359D8D580AA4F7F036D6F04FC6A95").encrypt(pt, TWEAK), base)


class Validation(unittest.TestCase):

    def test_bad_inputs(self):
        c = FF3_1(KEY)
        cases = [
            lambda: FF3_1(b"short"),
            lambda: FF3_1("not hex"),
            lambda: FF3_1(KEY, alphabet="aab"),
            lambda: FF3_1(KEY, radix=63),
            lambda: c.encrypt("12345678x", TWEAK),
            lambda: c.encrypt("123456789", "D8E7920AFA330A73"),  # 64-bit FF3 tweak
            lambda: c.encrypt("123456789", "D8E7"),
        ]
        for i, case in enumerate(cases):
            with self.subTest(i):
                with self.assertRaises(ValueError):
                    case()


if __name__ == "__main__":
    unittest.main()
