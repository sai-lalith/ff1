"""Known-answer tests: published FF1 vectors must encrypt and decrypt exactly."""
import json
import pathlib
import unittest

from ff1 import FF1

K128 = "2B7E151628AED2A6ABF7158809CF4F3C"
K192 = K128 + "EF4359D8D580AA4F"
K256 = K192 + "7F036D6F04FC6A94"
T10 = "39383736353433323130"
T11 = "3737373770717273373737"

# NIST FF1 samples #1-#9:
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
NIST_SAMPLES = [
    (1, K128, 10, "", "0123456789", "2433477484"),
    (2, K128, 10, T10, "0123456789", "6124200773"),
    (3, K128, 36, T11, "0123456789abcdefghi", "a9tv40mll9kdu509eum"),
    (4, K192, 10, "", "0123456789", "2830668132"),
    (5, K192, 10, T10, "0123456789", "2496655549"),
    (6, K192, 36, T11, "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"),
    (7, K256, 10, "", "0123456789", "6657667009"),
    (8, K256, 10, T10, "0123456789", "1001623463"),
    (9, K256, 36, T11, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"),
]

ACVP = json.loads((pathlib.Path(__file__).parent / "data" / "acvp_ff1.json").read_text())


class KnownAnswerTests(unittest.TestCase):

    def test_nist_samples(self):
        for num, key, radix, tweak, pt, ct in NIST_SAMPLES:
            with self.subTest(sample=num):
                c = FF1(key, radix=radix)
                self.assertEqual(c.encrypt(pt, tweak), ct)
                self.assertEqual(c.decrypt(ct, tweak), pt)

    def test_acvp(self):
        # 750 vectors from NIST's ACVP server: radix 2/4/16/32/64, all key sizes, tweaks 0-16 bytes.
        for group in ACVP["testGroups"]:
            for t in group["tests"]:
                with self.subTest(tg=group["tgId"], tc=t["tcId"]):
                    c = FF1(t["key"], alphabet=group["alphabet"])
                    if group["direction"] == "encrypt":
                        self.assertEqual(c.encrypt(t["pt"], t["tweak"]), t["ct"])
                    else:
                        self.assertEqual(c.decrypt(t["ct"], t["tweak"]), t["pt"])


if __name__ == "__main__":
    unittest.main()
