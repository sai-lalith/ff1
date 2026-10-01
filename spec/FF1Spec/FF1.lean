import FF1Spec.AES

/-!
# FF1 (NIST SP 800-38G Rev. 1, second public draft, February 2025)

A direct transcription of Algorithms 1-6. Numeral strings are `List Nat` (each entry
a numeral in [0, radix)), byte strings are `List UInt8`, and the block cipher CIPH_K
is a parameter so that the theorems in `FF1Spec/Proofs.lean` hold for any cipher.

Input validation (radix range, minlen/maxlen, tweak length) is the caller's job;
these functions are total and only meaningful on valid inputs.
-/

namespace FF1Spec

abbrev Bytes := List UInt8

/-- A block cipher's forward function on 16-byte blocks. -/
abbrev Cipher := Bytes → Bytes

/-! ## Algorithms 1-3: numeral strings and integers -/

/-- Algorithm 1, NUM_radix(X): the number a numeral string represents, most significant first. -/
def num (radix : Nat) (X : List Nat) : Nat :=
  X.foldl (fun x d => x * radix + d) 0

/-- Algorithm 2, NUM(X) for a byte string. -/
def numBytes (X : Bytes) : Nat :=
  num 256 (X.map UInt8.toNat)

/-- Algorithm 3, STR^m_radix(x): the m-numeral representation of x, most significant first. -/
def str (radix : Nat) : Nat → Nat → List Nat
  | 0, _ => []
  | m + 1, x => str radix m (x / radix) ++ [x % radix]

/-- [x]^s: x as an s-byte big-endian string. -/
def bytesOf (s x : Nat) : Bytes :=
  (str 256 s x).map Nat.toUInt8

/-- BITLEN(x): the m with 2^(m-1) ≤ x < 2^m, for positive x. -/
def bitlen (x : Nat) : Nat :=
  if x = 0 then 0 else Nat.log2 x + 1

/-! ## Algorithm 4: PRF -/

def xorBytes (X Y : Bytes) : Bytes :=
  List.zipWith (· ^^^ ·) X Y

/-- Split a byte string into 16-byte blocks. -/
def blocks (X : Bytes) : List Bytes :=
  if _h : X.length ≤ 16 then [X] else X.take 16 :: blocks (X.drop 16)
termination_by X.length
decreasing_by simp; omega

/-- Algorithm 4, PRF(X): CBC-MAC with Y_0 = 0^128. -/
def prf (ciph : Cipher) (X : Bytes) : Bytes :=
  (blocks X).foldl (fun Y Xj => ciph (xorBytes Y Xj)) (List.replicate 16 0)

/-! ## Algorithms 5 and 6: FF1.Encrypt and FF1.Decrypt -/

/-- Round length m (step 6.v): u on even rounds, v on odd rounds. -/
def roundLen (u v i : Nat) : Nat :=
  if i % 2 = 0 then u else v

/-- Steps 3-6.iv: y for round i, computed from the half that the round leaves unchanged. -/
def roundValue (ciph : Cipher) (radix : Nat) (T : Bytes) (n : Nat) (i : Nat) (X : List Nat) : Nat :=
  let u := n / 2
  let v := n - u
  let t := T.length
  let b := (bitlen (radix ^ v - 1) + 7) / 8                       -- step 3
  let d := 4 * ((b + 3) / 4) + 4                                  -- step 4
  let P : Bytes := [1, 2, 1] ++ bytesOf 3 radix ++ [10, (u % 256).toUInt8]
    ++ bytesOf 4 n ++ bytesOf 4 t                                  -- step 5
  let Q := T ++ List.replicate ((16 - (t + b + 1) % 16) % 16) 0
    ++ [i.toUInt8] ++ bytesOf b (num radix X)                      -- step 6.i
  let R := prf ciph (P ++ Q)                                       -- step 6.ii
  let S := (R ++ ((List.range ((d + 15) / 16)).drop 1).flatMap
    (fun j => ciph (xorBytes R (bytesOf 16 j)))).take d            -- step 6.iii
  numBytes S                                                       -- step 6.iv

/-- One encryption round (steps 6.v-6.ix), for any round function F. -/
def encRound (F : Nat → List Nat → Nat) (radix u v : Nat) (s : List Nat × List Nat) (i : Nat) :
    List Nat × List Nat :=
  let (A, B) := s
  let m := roundLen u v i
  let c := (num radix A + F i B) % radix ^ m
  (B, str radix m c)

/-- One decryption round (steps 6.v-6.ix of Algorithm 6). -/
def decRound (F : Nat → List Nat → Nat) (radix u v : Nat) (s : List Nat × List Nat) (i : Nat) :
    List Nat × List Nat :=
  let (A, B) := s
  let m := roundLen u v i
  let c := (((num radix B : Int) - F i A) % ((radix ^ m : Nat) : Int)).toNat
  (str radix m c, A)

/-- Algorithm 5, FF1.Encrypt(K, T, X). -/
def encrypt (ciph : Cipher) (radix : Nat) (T : Bytes) (X : List Nat) : List Nat :=
  let n := X.length
  let u := n / 2
  let v := n - u
  let s := (List.range 10).foldl (encRound (roundValue ciph radix T n) radix u v)
    (X.take u, X.drop u)
  s.1 ++ s.2

/-- Algorithm 6, FF1.Decrypt(K, T, X). -/
def decrypt (ciph : Cipher) (radix : Nat) (T : Bytes) (X : List Nat) : List Nat :=
  let n := X.length
  let u := n / 2
  let v := n - u
  let s := (List.range 10).reverse.foldl (decRound (roundValue ciph radix T n) radix u v)
    (X.take u, X.drop u)
  s.1 ++ s.2

/-- FF1 instantiated with AES under key K. -/
def aesCipher (key : Bytes) : Cipher :=
  let w := FF1Spec.AES.expandKey key.toArray
  fun block => (FF1Spec.AES.encryptExpanded w block.toArray).toList

end FF1Spec
