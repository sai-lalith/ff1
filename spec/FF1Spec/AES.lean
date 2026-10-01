/-!
# AES forward cipher (FIPS 197)

Only the forward direction is needed: SP 800-38G Rev. 1 requires CIPH_K to be the
forward transformation. The S-box is computed from its definition (multiplicative
inverse in GF(2^8) followed by the affine map) rather than typed in as a table.
Checked against the FIPS 197 Appendix C vectors in `FF1Spec/Tests.lean`.
-/

namespace FF1Spec.AES

/-- Multiply by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1. -/
def xtime (b : UInt8) : UInt8 :=
  (b <<< 1) ^^^ (if b &&& 0x80 != 0 then 0x1b else 0)

def gmul (a b : UInt8) : UInt8 := Id.run do
  let mut a := a
  let mut b := b
  let mut p : UInt8 := 0
  for _ in [0:8] do
    if b &&& 1 != 0 then p := p ^^^ a
    a := xtime a
    b := b >>> 1
  return p

/-- Multiplicative inverse in GF(2^8) as a^254 (with 0 ↦ 0). -/
def ginv (a : UInt8) : UInt8 := Id.run do
  let mut r : UInt8 := 1
  for _ in [0:254] do
    r := gmul r a
  return r

def rotl8 (b : UInt8) (k : UInt8) : UInt8 := (b <<< k) ||| (b >>> (8 - k))

def sboxEntry (x : UInt8) : UInt8 :=
  let b := ginv x
  b ^^^ rotl8 b 1 ^^^ rotl8 b 2 ^^^ rotl8 b 3 ^^^ rotl8 b 4 ^^^ 0x63

def sbox : Array UInt8 := (Array.range 256).map (fun i => sboxEntry i.toUInt8)

def sub (b : UInt8) : UInt8 := sbox[b.toNat]!

/-- Key expansion: the round keys as one byte array of 16 * (Nr + 1) bytes. -/
def expandKey (key : Array UInt8) : Array UInt8 := Id.run do
  let nk := key.size / 4
  let nr := nk + 6
  let mut w := key
  let mut rcon : UInt8 := 1
  for i in [nk:4 * (nr + 1)] do
    let mut t := #[w[4 * (i - 1)]!, w[4 * (i - 1) + 1]!, w[4 * (i - 1) + 2]!, w[4 * (i - 1) + 3]!]
    if i % nk == 0 then
      t := #[sub t[1]! ^^^ rcon, sub t[2]!, sub t[3]!, sub t[0]!]
      rcon := xtime rcon
    else if nk > 6 && i % nk == 4 then
      t := t.map sub
    for j in [0:4] do
      w := w.push (w[4 * (i - nk) + j]! ^^^ t[j]!)
  return w

def addRoundKey (s w : Array UInt8) (round : Nat) : Array UInt8 :=
  (Array.range 16).map (fun j => s[j]! ^^^ w[16 * round + j]!)

/-- State byte (row r, column c) lives at index r + 4c, matching the input byte order. -/
def shiftRows (s : Array UInt8) : Array UInt8 :=
  (Array.range 16).map (fun j => let r := j % 4; let c := j / 4; s[r + 4 * ((c + r) % 4)]!)

def mixColumns (s : Array UInt8) : Array UInt8 := Id.run do
  let mut out := #[]
  for c in [0:4] do
    let a0 := s[4 * c]!
    let a1 := s[4 * c + 1]!
    let a2 := s[4 * c + 2]!
    let a3 := s[4 * c + 3]!
    out := out.push (xtime a0 ^^^ (xtime a1 ^^^ a1) ^^^ a2 ^^^ a3)
    out := out.push (a0 ^^^ xtime a1 ^^^ (xtime a2 ^^^ a2) ^^^ a3)
    out := out.push (a0 ^^^ a1 ^^^ xtime a2 ^^^ (xtime a3 ^^^ a3))
    out := out.push ((xtime a0 ^^^ a0) ^^^ a1 ^^^ a2 ^^^ xtime a3)
  return out

/-- Encrypt one 16-byte block with expanded key `w` (from `expandKey`). -/
def encryptExpanded (w block : Array UInt8) : Array UInt8 := Id.run do
  let nr := w.size / 16 - 1
  let mut s := addRoundKey block w 0
  for round in [1:nr] do
    s := addRoundKey (mixColumns (shiftRows (s.map sub))) w round
  return addRoundKey (shiftRows (s.map sub)) w nr

/-- Encrypt one 16-byte block under a 16-, 24- or 32-byte key. -/
def encryptBlock (key block : Array UInt8) : Array UInt8 :=
  encryptExpanded (expandKey key) block

end FF1Spec.AES
