"""Known-answer tests: published FF3-1 vectors must encrypt and decrypt exactly.

Vectors are the FF3-1 (56-bit tweak) cases collected in mysto/python-fpe
(Apache-2.0), ff3/ff3_test.py. The ACVP set comes from NIST's Automated
Cryptographic Validation Protocol; "tg"/"tc" are its test-group/test-case ids.
"""
import string
import unittest

from ff3_1 import FF3_1

DIGITS = "0123456789"
LOWER = string.ascii_lowercase
B64 = string.digits + string.ascii_uppercase + string.ascii_lowercase + "+/"

ACVP_VECTORS = [
    # AES-128
    ("tg1 tc1", DIGITS, "2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564",
     "3992520240", "8901801106"),
    ("tg1 tc2", DIGITS, "01C63017111438F7FC8E24EB16C71AB5", "C4E822DCD09F27",
     "60761757463116869318437658042297305934914824457484538562",
     "35637144092473838892796702739628394376915177448290847293"),
    ("tg2 tc26", LOWER, "718385E6542534604419E83CE387A437", "B6F35084FA90E1",
     "wfmwlrorcd", "ywowehycyd"),
    ("tg2 tc27", LOWER, "DB602DFF22ED7E84C8D8C865A941A238", "EBEFD63BCC2083",
     "kkuomenbzqvggfbteqdyanwpmhzdmoicekiihkrm",
     "belcfahcwwytwrckieymthabgjjfkxtxauipmjja"),
    ("tg3 tc51", B64, "AEE87D0D485B3AFD12BD1E0B9D03D50D", "5F9140601D224B",
     "ixvuuIHr0e", "GR90R1q838"),
    ("tg3 tc52", B64, "7B6C88324732F7F4AD435DA9AD77F917", "3F42102C0BAB39",
     "21q1kbbIVSrAFtdFWzdMeIDpRqpo", "cvQ/4aGUV4wRnyO3CHmgEKW5hk8H"),
    # AES-192
    ("tg4 tc76", DIGITS, "F62EDB777A671075D47563F3A1E9AC797AA706A2D8E02FC8", "493B8451BF6716",
     "4406616808", "1807744762"),
    ("tg4 tc77", DIGITS, "0951B475D1A327C52756F2624AF224C80E9BE85F09B2D44F", "D679E2EA3054E1",
     "99980459818278359406199791971849884432821321826358606310",
     "84359031857952748660483617398396641079558152339419110919"),
    ("tg5 tc101", LOWER, "49CCB8F62D941E5684599ECA0300937B5C766D053E109777", "0BFCF75CDC2FC1",
     "jaxlrchjjx", "kjdbfqyahd"),
    ("tg5 tc102", LOWER, "03D253674A9309FF07ED0E71B24CBFE769025E09FCE544D7", "B33176B1DA0F6C",
     "tafzrybuvhiqvcyztuxfnwfprmqlwpayphxbawpl",
     "loaemzbgqkywkdhmncrijzildzleoqibtthdiliv"),
    ("tg6 tc126", B64, "1C24B74B7C1B9969314CB53E92F98EFD620D5520017FB076", "0380341C425A6F",
     "6np8r2t8zo", "HgpCXoA1Rt"),
    ("tg6 tc127", B64, "C0ABADFC071379824A070E8C3FD40DD9BFD7A3C99A0D5FE3", "6C2926C705DDAF",
     "GKB6sa9g56BSJ09iJ4dsaxRdsMvo", "gC0tTSdDPxM79QOWi+z+SNL9C4V+"),
    # AES-256
    ("tg7 tc151", DIGITS, "1FAA03EFF55A06F8FAB3F1DC57127D493E2F8F5C365540467A3A055BDBE6481D",
     "4D67130C030445", "3679409436", "1735794859"),
    ("tg7 tc152", DIGITS, "9CE16E125BD422A011408EB083355E7089E70A4CD2F59E141D0B94A74BCC5967",
     "4684635BD2C821",
     "85783290820098255530464619643265070052870796363685134012",
     "75104723514036464144839960480545848044718729603261409917"),
    ("tg8 tc176", LOWER, "6187F8BDE99F7DAF9E3EE8A8654308E7E51D31FA88AFFAEB5592041C033B736B",
     "5820812B3D5DD1", "mkblaoiyfd", "ifpyiihvvq"),
    ("tg8 tc177", LOWER, "F6807FB9688937E4D4956006C8F0CB2394148A5F4B14666CF353F4941428FFD7",
     "30C87B99890096",
     "wrammvhudopmaazlsxevzwzwpezzmghwfnmkitnk",
     "nzftnfkliuctlmtdfrxfhwgevrbcbgljurnytxkj"),
    ("tg9 tc201", B64, "9C2B69F7DDF181C54398E345BE04C2F6B00B9DD1679200E1E04C4FF961AE0F09",
     "103C238B4B1E44", "H2/c6FblSA", "EOg4H1bE+8"),
    ("tg9 tc202", B64, "C58BCBD08B90006CEC7E82B2D987D79F6A21111DEF0CEBB273CBAEB2D6CD4044",
     "7036604882667B", "bz5TcS1krnD8IOLdrQeKzXkLAa6h", "Z6x3/9LPW8SZunRezRM8J68Q4J03"),
]

OTHER_VECTORS = [
    # NIST FF3 sample #1 with its tweak truncated to 56 bits.
    ("nist sample1 56-bit tweak", DIGITS, "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A",
     "890121234567890000", "477064185124354662"),
    # Long radix-62 input; exercises a 12-byte NUM block with the top bit set.
    ("radix62 sign byte", string.ascii_uppercase + string.ascii_lowercase + string.digits,
     "2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564",
     "Ceciestuntestdechiffrement123cet", "0uaTPI9g49f9MMw54OvY8x5rmNcrhydM"),
]


class KnownAnswerTests(unittest.TestCase):

    def check(self, vectors):
        for name, alphabet, key, tweak, pt, ct in vectors:
            with self.subTest(name):
                c = FF3_1(key, alphabet=alphabet)
                self.assertEqual(c.encrypt(pt, tweak), ct)
                self.assertEqual(c.decrypt(ct, tweak), pt)

    def test_acvp(self):
        self.check(ACVP_VECTORS)

    def test_other(self):
        self.check(OTHER_VECTORS)


if __name__ == "__main__":
    unittest.main()
