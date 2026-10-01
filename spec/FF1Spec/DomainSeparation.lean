import FF1Spec.Proofs

/-!
# Domain separation of the round PRF inputs

Every call FF1 makes to its PRF is on the block string `roundInput radix T n i X`
(P || Q in step 6.ii), where X is the half that round i leaves unchanged. This file
proves, for every parameter choice SP 800-38G Rev. 1 allows:

* `roundInput_length`: P || Q is a whole number of 128-bit blocks, as PRF requires.
* `roundInput_injective`: equal PRF inputs force equal radix, message length, tweak,
  round number and NUM_radix(X). So no two distinct (parameters, tweak, round, half)
  combinations ever share a PRF input, either within one message or across messages,
  tweaks and lengths.

This is the precondition the published FF1 security analyses rely on, and it is the
property that Beyne's attack broke for FF3 and FF3-1, whose tweak schedule let
different tweaks produce identical round-function inputs.
-/

namespace FF1Spec

theorem toUInt8_inj {a b : Nat} (ha : a < 256) (hb : b < 256) (h : a.toUInt8 = b.toUInt8) :
    a = b := by
  have := congrArg UInt8.toNat h
  rw [Nat.toUInt8_eq, Nat.toUInt8_eq, UInt8.toNat_ofNat', UInt8.toNat_ofNat'] at this
  omega

theorem length_bytesOf (s x : Nat) : (bytesOf s x).length = s := by
  simp [bytesOf, length_str]

theorem map_toUInt8_inj : ∀ {L L' : List Nat}, Valid 256 L → Valid 256 L' →
    L.map Nat.toUInt8 = L'.map Nat.toUInt8 → L = L'
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | a :: L, b :: L', hL, hL', h => by
    simp only [List.map_cons, List.cons.injEq] at h
    rw [toUInt8_inj (hL a (by simp)) (hL' b (by simp)) h.1,
      map_toUInt8_inj (fun d hd => hL d (by simp [hd])) (fun d hd => hL' d (by simp [hd])) h.2]

/-- [x]^s is injective on numbers below 256^s. -/
theorem bytesOf_inj {s x y : Nat} (hx : x < 256 ^ s) (hy : y < 256 ^ s)
    (h : bytesOf s x = bytesOf s y) : x = y := by
  have h' := congrArg (num 256)
    (map_toUInt8_inj (valid_str (by decide) s x) (valid_str (by decide) s y) h)
  rwa [num_str, num_str, Nat.mod_eq_of_lt hx, Nat.mod_eq_of_lt hy] at h'

theorem length_blockP (radix n t : Nat) : (blockP radix n t).length = 16 := by
  simp [blockP, length_bytesOf]

/-- P || Q is a whole number of 16-byte blocks. -/
theorem roundInput_length (radix : Nat) (T : Bytes) (n i : Nat) (X : List Nat) :
    (roundInput radix T n i X).length % 16 = 0 := by
  simp only [roundInput, blockQ, List.length_append, length_blockP, List.length_replicate,
    length_bytesOf, List.length_singleton]
  omega

/-- A half of length at most v fits in the b bytes that Q reserves for it (step 3). -/
theorem num_lt_byteLen {radix v : Nat} (hr : 0 < radix) (X : List Nat) (hX : Valid radix X)
    (hlen : X.length ≤ v) : num radix X < 256 ^ byteLen radix v := by
  have h1 : num radix X < radix ^ v :=
    Nat.lt_of_lt_of_le (num_lt X hX) (Nat.pow_le_pow_right hr hlen)
  have h2 : radix ^ v ≤ 2 ^ bitlen (radix ^ v - 1) := by
    unfold bitlen
    split
    · rw [Nat.pow_zero]; omega
    · have := @Nat.lt_log2_self (radix ^ v - 1); omega
  have h3 : 2 ^ bitlen (radix ^ v - 1) ≤ 256 ^ byteLen radix v := by
    rw [show (256 : Nat) = 2 ^ 8 from rfl, ← Nat.pow_mul]
    exact Nat.pow_le_pow_right (by decide) (by unfold byteLen; omega)
  omega

/-- Equal PRF inputs imply equal radix, length, tweak, round and NUM_radix of the half.

The hypotheses are the spec's own limits: radix ≤ 2^16, n < 2^32, tweak length < 2^32,
round index ≤ 9, and the half X has at most v = n - ⌊n/2⌋ numerals below the radix. -/
theorem roundInput_injective {radix radix' n n' i i' : Nat} {T T' : Bytes} {X X' : List Nat}
    (hr : 0 < radix) (hr' : 0 < radix') (hrad : radix < 256 ^ 3) (hrad' : radix' < 256 ^ 3)
    (hn : n < 256 ^ 4) (hn' : n' < 256 ^ 4) (ht : T.length < 256 ^ 4) (ht' : T'.length < 256 ^ 4)
    (hi : i < 256) (hi' : i' < 256) (hX : Valid radix X) (hX' : Valid radix' X')
    (hlen : X.length ≤ n - n / 2) (hlen' : X'.length ≤ n' - n' / 2)
    (h : roundInput radix T n i X = roundInput radix' T' n' i' X') :
    radix = radix' ∧ n = n' ∧ T = T' ∧ i = i' ∧ num radix X = num radix' X' := by
  -- P: the fixed-length fields give radix, n and t.
  obtain ⟨hP, hQ⟩ := List.append_inj h (by rw [length_blockP, length_blockP])
  unfold blockP at hP
  obtain ⟨hP1, htP⟩ := List.append_inj' hP (by rw [length_bytesOf, length_bytesOf])
  obtain ⟨hP2, hnP⟩ := List.append_inj' hP1 (by rw [length_bytesOf, length_bytesOf])
  obtain ⟨hP3, -⟩ := List.append_inj' hP2 rfl
  obtain ⟨-, hrP⟩ := List.append_inj' hP3 (by rw [length_bytesOf, length_bytesOf])
  have hradix := bytesOf_inj hrad hrad' hrP
  have hlenT := bytesOf_inj ht ht' htP
  have hn_eq := bytesOf_inj hn hn' hnP
  subst hradix hn_eq
  -- Q: then the tweak, the round byte and the encoding of NUM_radix(X).
  unfold blockQ at hQ
  obtain ⟨hQ1, hnum⟩ := List.append_inj' hQ (by rw [length_bytesOf, length_bytesOf])
  obtain ⟨hQ2, hiQ⟩ := List.append_inj' hQ1 rfl
  obtain ⟨hT, -⟩ := List.append_inj hQ2 hlenT
  have hi_eq := toUInt8_inj hi hi' (List.singleton_inj.mp hiQ)
  have hnum_eq := bytesOf_inj (num_lt_byteLen hr X hX hlen) (num_lt_byteLen hr X' hX' hlen') hnum
  exact ⟨rfl, rfl, hT, hi_eq, hnum_eq⟩

/-- For halves of equal length (as in the same round of the same message), the half itself
is determined: different halves never share a PRF input. -/
theorem roundInput_injective_half {radix n i : Nat} {T T' : Bytes} {X X' : List Nat}
    (hr : 0 < radix) (hrad : radix < 256 ^ 3) (hn : n < 256 ^ 4)
    (ht : T.length < 256 ^ 4) (ht' : T'.length < 256 ^ 4) (hi : i < 256)
    (hX : Valid radix X) (hX' : Valid radix X') (hlen : X.length ≤ n - n / 2)
    (heq : X.length = X'.length)
    (h : roundInput radix T n i X = roundInput radix T' n i X') : X = X' := by
  obtain ⟨-, -, -, -, hnum⟩ := roundInput_injective hr hr hrad hrad hn hn ht ht' hi hi hX hX'
    hlen (heq ▸ hlen) h
  rw [← str_num hr X hX, ← str_num hr X' hX', heq, hnum]

end FF1Spec
