/-! Hex and numeral-string conversions shared by the tests and the CLI. -/

namespace FF1Spec

def hexDigit? (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def ofHex? (s : String) : Option (List UInt8) :=
  let rec go : List Char → Option (List UInt8)
    | [] => some []
    | a :: b :: rest => do
        let hi ← hexDigit? a
        let lo ← hexDigit? b
        return (hi * 16 + lo).toUInt8 :: (← go rest)
    | [_] => none
  go s.toList

/-- Numeral string over `alphabet`, e.g. "0123456789abcdefghijklmnopqrstuvwxyz". -/
def ofAlphabet (alphabet s : String) : List Nat :=
  s.toList.map (fun c => alphabet.toList.idxOf c)

def toAlphabet (alphabet : String) (X : List Nat) : String :=
  String.ofList (X.map (fun d => alphabet.toList.getD d '?'))

end FF1Spec
