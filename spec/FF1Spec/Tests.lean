import FF1Spec.FF1
import FF1Spec.Hex

/-!
# Known-answer tests, checked at build time

`#guard` fails the build if a check is false, so `lake build` proves that the spec
reproduces the published vectors.
-/

namespace FF1Spec.Tests

open FF1Spec

def aesHex (key pt : String) : List UInt8 :=
  aesCipher ((ofHex? key).get!) ((ofHex? pt).get!)

-- FIPS 197 Appendix C.1-C.3
#guard aesHex "000102030405060708090a0b0c0d0e0f" "00112233445566778899aabbccddeeff"
  = (ofHex? "69c4e0d86a7b0430d8cdb78070b4c55a").get!
#guard aesHex "000102030405060708090a0b0c0d0e0f1011121314151617" "00112233445566778899aabbccddeeff"
  = (ofHex? "dda97ca4864cdfe06eaf70a0ec0d7191").get!
#guard aesHex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  "00112233445566778899aabbccddeeff" = (ofHex? "8ea2b7ca516745bfeafc49904b496089").get!

def base36 := "0123456789abcdefghijklmnopqrstuvwxyz"

/-- Encrypt and decrypt one NIST sample, comparing both directions. -/
def checkSample (key : String) (radix : Nat) (tweak pt ct : String) : Bool :=
  let c := aesCipher (ofHex? key).get!
  let T := (ofHex? tweak).get!
  let X := ofAlphabet base36 pt
  let Y := ofAlphabet base36 ct
  encrypt c radix T X = Y && decrypt c radix T Y = X

def k128 := "2B7E151628AED2A6ABF7158809CF4F3C"
def k192 := k128 ++ "EF4359D8D580AA4F"
def k256 := k192 ++ "7F036D6F04FC6A94"
def t10 := "39383736353433323130"
def t11 := "3737373770717273373737"

-- NIST FF1 samples #1-#9 (FF1samples.pdf)
#guard checkSample k128 10 "" "0123456789" "2433477484"
#guard checkSample k128 10 t10 "0123456789" "6124200773"
#guard checkSample k128 36 t11 "0123456789abcdefghi" "a9tv40mll9kdu509eum"
#guard checkSample k192 10 "" "0123456789" "2830668132"
#guard checkSample k192 10 t10 "0123456789" "2496655549"
#guard checkSample k192 36 t11 "0123456789abcdefghi" "xbj3kv35jrawxv32ysr"
#guard checkSample k256 10 "" "0123456789" "6657667009"
#guard checkSample k256 10 t10 "0123456789" "1001623463"
#guard checkSample k256 36 t11 "0123456789abcdefghi" "xs8a0azh2avyalyzuwd"

-- BITLEN examples from the glossary
#guard bitlen 64 = 7
#guard bitlen 10 = 4

end FF1Spec.Tests
