import FF1Spec

/-!
Batch driver for differential testing. Each stdin line is

    E|D <key hex> <radix> <tweak hex, or - for empty> <numerals, comma-separated>

and the matching stdout line is the result's numerals, comma-separated, or `error: ...`.
-/

open FF1Spec

def parseNumerals (s : String) : Option (List Nat) :=
  (s.splitOn ",").mapM String.toNat?

def runLine (line : String) : String :=
  match line.splitOn " " with
  | [op, key, radix, tweak, xs] =>
    match ofHex? key, radix.toNat?, (if tweak = "-" then some [] else ofHex? tweak), parseNumerals xs with
    | some k, some r, some t, some x =>
      let c := aesCipher k
      let y := if op = "D" then decrypt c r t x else encrypt c r t x
      ",".intercalate (y.map toString)
    | _, _, _, _ => "error: bad field"
  | _ => "error: expected 5 fields"

partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  stdout.putStrLn (runLine line.trimAscii.toString)
  stdout.flush
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
