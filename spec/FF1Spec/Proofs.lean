import FF1Spec.FF1

/-!
# Correctness theorems for the FF1 spec

For every block cipher `ciph`, radix `≥ 1`, tweak `T` and numeral string `X` whose
numerals are below the radix:

* `encrypt_length`, `encrypt_valid`: encryption is format-preserving.
* `decrypt_encrypt`, `encrypt_decrypt`: decryption inverts encryption and vice versa,
  so FF1 is a permutation of the valid strings of each length.
* `encrypt_injective`: distinct plaintexts give distinct ciphertexts.

None of this depends on AES: the Feistel structure is invertible for any round function.
-/

namespace FF1Spec

/-- Every numeral in `X` is below `radix`. -/
def Valid (radix : Nat) (X : List Nat) : Prop := ∀ d ∈ X, d < radix

theorem valid_append {r : Nat} {X : List Nat} {d : Nat} (h : Valid r (X ++ [d])) :
    Valid r X ∧ d < r :=
  ⟨fun e he => h e (List.mem_append_left _ he), h d (by simp)⟩

/-- Induction from the right end of a list. -/
theorem snoc_induction {P : List Nat → Prop} (nil : P []) (snoc : ∀ X d, P X → P (X ++ [d]))
    (X : List Nat) : P X := by
  have h : ∀ L : List Nat, P L.reverse := by
    intro L
    induction L with
    | nil => exact nil
    | cons d L ih => simpa using snoc _ d ih
  simpa using h X.reverse

/-! ## Numeral-string lemmas (Algorithms 1 and 3) -/

theorem length_str (r m x : Nat) : (str r m x).length = m := by
  induction m generalizing x with
  | zero => rfl
  | succ m ih => simp [str, ih]

theorem valid_str {r : Nat} (hr : 0 < r) (m x : Nat) : Valid r (str r m x) := by
  induction m generalizing x with
  | zero => simp [Valid, str]
  | succ m ih =>
    intro d hd
    simp only [str, List.mem_append, List.mem_singleton] at hd
    rcases hd with hd | hd
    · exact ih _ d hd
    · exact hd ▸ Nat.mod_lt _ hr

theorem num_append (r : Nat) (X : List Nat) (d : Nat) : num r (X ++ [d]) = num r X * r + d := by
  simp [num, List.foldl_append]

/-- NUM_radix(STR^m_radix(x)) = x mod radix^m. -/
theorem num_str {r : Nat} (m x : Nat) : num r (str r m x) = x % r ^ m := by
  induction m generalizing x with
  | zero => simp [str, num, Nat.mod_one]
  | succ m ih =>
    rw [str, num_append, ih, Nat.pow_succ', Nat.mod_mul, Nat.mul_comm (x / r % r ^ m) r]
    omega

/-- A numeral string of length m represents a number below radix^m. -/
theorem num_lt {r : Nat} (X : List Nat) (h : Valid r X) : num r X < r ^ X.length := by
  induction X using snoc_induction with
  | nil => simp [num]
  | snoc X d ih =>
    obtain ⟨hX, hd⟩ := valid_append h
    have h1 : (num r X + 1) * r ≤ r ^ X.length * r := Nat.mul_le_mul_right _ (ih hX)
    rw [Nat.add_mul, Nat.one_mul] at h1
    rw [num_append, List.length_append, List.length_singleton, Nat.pow_succ]
    omega

/-- STR^m_radix(NUM_radix(X)) = X for a valid X of length m. -/
theorem str_num {r : Nat} (hr : 0 < r) (X : List Nat) (h : Valid r X) :
    str r X.length (num r X) = X := by
  induction X using snoc_induction with
  | nil => rfl
  | snoc X d ih =>
    obtain ⟨hX, hd⟩ := valid_append h
    have h1 : (num r X * r + d) / r = num r X := by
      rw [Nat.mul_comm, Nat.mul_add_div hr, Nat.div_eq_of_lt hd, Nat.add_zero]
    have h2 : (num r X * r + d) % r = d := by
      rw [Nat.mul_comm, Nat.mul_add_mod, Nat.mod_eq_of_lt hd]
    rw [List.length_append, List.length_singleton, str, num_append, h1, h2, ih hX]

/-! ## Modular arithmetic for one round -/

theorem sub_after_add {a y M : Nat} (ha : a < M) :
    ((((a + y) % M : Nat) : Int) - y) % (M : Int) = a := by
  rw [Int.natCast_emod, Int.sub_emod, Int.emod_emod_of_dvd _ (Int.dvd_refl _), ← Int.sub_emod]
  have : ((a + y : Nat) : Int) - y = a := by omega
  rw [this, Int.emod_eq_of_lt (by omega) (by omega)]

theorem add_after_sub {b y M : Nat} (hb : b < M) :
    ((((b : Int) - y) % (M : Int)).toNat + y) % M = b := by
  have hM : (M : Int) ≠ 0 := by omega
  have hnn := Int.emod_nonneg ((b : Int) - y) hM
  apply Int.ofNat.inj
  rw [Int.ofNat_eq_natCast, Int.ofNat_eq_natCast, Int.natCast_emod, Int.natCast_add,
    Int.toNat_of_nonneg hnn, Int.add_emod, Int.emod_emod_of_dvd _ (Int.dvd_refl _), ← Int.add_emod]
  have : (b : Int) - y + y = b := by omega
  rw [this, Int.emod_eq_of_lt (by omega) (by omega)]

/-! ## One Feistel round -/

variable {F : Nat → List Nat → Nat} {r u v : Nat}

theorem dec_enc_round (hr : 0 < r) (i : Nat) (A B : List Nat)
    (hA : A.length = roundLen u v i) (hvA : Valid r A) :
    decRound F r u v (encRound F r u v (A, B) i) i = (A, B) := by
  simp only [encRound, decRound]
  rw [num_str, Nat.mod_mod, sub_after_add (hA ▸ num_lt A hvA), Int.toNat_natCast, ← hA,
    str_num hr A hvA]

theorem enc_dec_round (hr : 0 < r) (i : Nat) (A B : List Nat)
    (hB : B.length = roundLen u v i) (hvB : Valid r B) :
    encRound F r u v (decRound F r u v (A, B) i) i = (A, B) := by
  simp only [encRound, decRound]
  have hpos : 0 < r ^ roundLen u v i := Nat.pow_pos hr
  have hlt := Int.emod_lt_of_pos ((num r B : Int) - F i A) (by omega : (0 : Int) < (r ^ roundLen u v i : Nat))
  have hnn := Int.emod_nonneg ((num r B : Int) - F i A) (by omega : ((r ^ roundLen u v i : Nat) : Int) ≠ 0)
  have hc : (((num r B : Int) - F i A) % ((r ^ roundLen u v i : Nat) : Int)).toNat
      < r ^ roundLen u v i := by omega
  rw [num_str, Nat.mod_eq_of_lt hc, add_after_sub (hB ▸ num_lt B hvB), ← hB,
    str_num hr B hvB]

theorem roundLen_add_two (u v i : Nat) : roundLen u v (i + 2) = roundLen u v i := by
  unfold roundLen
  split <;> split <;> omega

/-! ## Ten rounds -/

/-- State before encryption round i: lengths (m_i, m_{i+1}), all numerals valid. -/
def EncInv (r u v i : Nat) (s : List Nat × List Nat) : Prop :=
  s.1.length = roundLen u v i ∧ s.2.length = roundLen u v (i + 1) ∧ Valid r s.1 ∧ Valid r s.2

/-- State before decryption round i: lengths (m_{i+1}, m_i), all numerals valid. -/
def DecInv (r u v i : Nat) (s : List Nat × List Nat) : Prop :=
  s.1.length = roundLen u v (i + 1) ∧ s.2.length = roundLen u v i ∧ Valid r s.1 ∧ Valid r s.2

theorem encInv_step (hr : 0 < r) {i : Nat} {s : List Nat × List Nat} (h : EncInv r u v i s) :
    EncInv r u v (i + 1) (encRound F r u v s i) := by
  obtain ⟨A, B⟩ := s
  obtain ⟨-, h2, -, h4⟩ := h
  refine ⟨h2, ?_, h4, valid_str hr _ _⟩
  simp only [encRound, length_str]
  exact (roundLen_add_two u v i).symm

theorem decInv_step (hr : 0 < r) {i : Nat} {s : List Nat × List Nat} (h : DecInv r u v (i + 1) s) :
    DecInv r u v i (decRound F r u v s (i + 1)) := by
  obtain ⟨A, B⟩ := s
  obtain ⟨h1, -, h3, -⟩ := h
  refine ⟨by simp [decRound, length_str], ?_, valid_str hr _ _, h3⟩
  simp only [decRound]
  rw [h1, roundLen_add_two]

theorem decInv_final (hr : 0 < r) {i : Nat} {s : List Nat × List Nat} (h : DecInv r u v i s) :
    EncInv r u v i (decRound F r u v s i) := by
  obtain ⟨A, B⟩ := s
  obtain ⟨h1, -, h3, -⟩ := h
  exact ⟨by simp [decRound, length_str], h1, valid_str hr _ _, h3⟩

theorem encInv_rounds (hr : 0 < r) :
    ∀ (len k : Nat) (s : List Nat × List Nat), EncInv r u v k s →
      EncInv r u v (k + len) ((List.range' k len).foldl (encRound F r u v) s)
  | 0, _, _, h => h
  | len + 1, k, s, h => by
    rw [List.range'_succ, List.foldl_cons, Nat.add_comm len 1, ← Nat.add_assoc]
    exact encInv_rounds hr len (k + 1) _ (encInv_step hr h)

theorem decInv_rounds (hr : 0 < r) :
    ∀ (len k : Nat) (s : List Nat × List Nat), DecInv r u v (k + len) s →
      DecInv r u v k ((List.range' (k + 1) len).reverse.foldl (decRound F r u v) s)
  | 0, _, _, h => h
  | len + 1, k, s, h => by
    rw [List.range'_succ, List.reverse_cons, List.foldl_append, List.foldl_cons, List.foldl_nil]
    have := decInv_rounds hr len (k + 1) s (by rw [Nat.add_right_comm]; exact h)
    exact decInv_step hr this

theorem dec_enc_rounds (hr : 0 < r) :
    ∀ (len k : Nat) (s : List Nat × List Nat), EncInv r u v k s →
      (List.range' k len).reverse.foldl (decRound F r u v)
        ((List.range' k len).foldl (encRound F r u v) s) = s
  | 0, _, _, _ => rfl
  | len + 1, k, (A, B), h => by
    rw [List.range'_succ, List.foldl_cons, List.reverse_cons, List.foldl_append, List.foldl_cons,
      List.foldl_nil, dec_enc_rounds hr len (k + 1) _ (encInv_step hr h)]
    exact dec_enc_round hr k A B h.1 h.2.2.1

theorem enc_dec_rounds (hr : 0 < r) :
    ∀ (len k : Nat) (s : List Nat × List Nat), DecInv r u v (k + len) s →
      (List.range' k (len + 1)).foldl (encRound F r u v)
        ((List.range' k (len + 1)).reverse.foldl (decRound F r u v) s) = s
  | 0, k, (A, B), h => by
    simp only [List.range'_succ, List.range'_zero, List.reverse_cons, List.reverse_nil,
      List.nil_append, List.foldl_cons, List.foldl_nil]
    exact enc_dec_round hr k A B h.2.1 h.2.2.2
  | len + 1, k, s, h => by
    have hrest := decInv_rounds (F := F) hr (len + 1) k s h
    generalize hd : (List.range' (k + 1) (len + 1)).reverse.foldl (decRound F r u v) s = s' at hrest
    obtain ⟨A, B⟩ := s'
    rw [List.range'_succ, List.reverse_cons, List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil]
    rw [hd, enc_dec_round hr k A B hrest.2.1 hrest.2.2.2, ← hd]
    exact enc_dec_rounds hr len (k + 1) s (by rw [show k + 1 + len = k + (len + 1) by omega]; exact h)

/-! ## Main theorems -/

variable (ciph : Cipher) (radix : Nat) (T : Bytes)

theorem encInv_init (X : List Nat) (hX : Valid radix X) :
    EncInv radix (X.length / 2) (X.length - X.length / 2) 0 (X.take (X.length / 2), X.drop (X.length / 2)) :=
  ⟨by simp [roundLen]; omega, by simp [roundLen],
    fun d hd => hX d (List.mem_of_mem_take hd), fun d hd => hX d (List.mem_of_mem_drop hd)⟩

theorem encrypt_inv (hr : 0 < radix) (X : List Nat) (hX : Valid radix X) :
    EncInv radix (X.length / 2) (X.length - X.length / 2) 10
      ((List.range 10).foldl (encRound (roundValue ciph radix T X.length) radix
        (X.length / 2) (X.length - X.length / 2)) (X.take (X.length / 2), X.drop (X.length / 2))) := by
  have := encInv_rounds (F := roundValue ciph radix T X.length) hr 10 0 _ (encInv_init radix X hX)
  simpa [List.range_eq_range'] using this

/-- Encryption preserves length. -/
theorem encrypt_length (hr : 0 < radix) (X : List Nat) (hX : Valid radix X) :
    (encrypt ciph radix T X).length = X.length := by
  obtain ⟨h1, h2, -, -⟩ := encrypt_inv ciph radix T hr X hX
  simp only [encrypt, List.length_append, h1, h2]
  simp [roundLen]
  omega

/-- Encryption preserves the alphabet. -/
theorem encrypt_valid (hr : 0 < radix) (X : List Nat) (hX : Valid radix X) :
    Valid radix (encrypt ciph radix T X) := by
  obtain ⟨-, -, h3, h4⟩ := encrypt_inv ciph radix T hr X hX
  intro d hd
  simp only [encrypt, List.mem_append] at hd
  exact hd.elim (h3 d) (h4 d)

/-- FF1.Decrypt(K, T, FF1.Encrypt(K, T, X)) = X. -/
theorem decrypt_encrypt (hr : 0 < radix) (X : List Nat) (hX : Valid radix X) :
    decrypt ciph radix T (encrypt ciph radix T X) = X := by
  have hlen := encrypt_length ciph radix T hr X hX
  obtain ⟨h1, h2, h3, h4⟩ := encrypt_inv ciph radix T hr X hX
  unfold decrypt
  rw [hlen]
  simp only [encrypt]
  rw [List.take_left' (by rw [h1]; simp [roundLen]), List.drop_left' (by rw [h1]; simp [roundLen])]
  have := dec_enc_rounds (F := roundValue ciph radix T X.length) hr 10 0 _
    (encInv_init radix X hX)
  simp only [← List.range_eq_range'] at this
  simp [this, List.take_append_drop]

theorem decInv_init (X : List Nat) (hX : Valid radix X) :
    DecInv radix (X.length / 2) (X.length - X.length / 2) 9 (X.take (X.length / 2), X.drop (X.length / 2)) :=
  ⟨by simp [roundLen]; omega, by simp [roundLen],
    fun d hd => hX d (List.mem_of_mem_take hd), fun d hd => hX d (List.mem_of_mem_drop hd)⟩

theorem decrypt_inv (hr : 0 < radix) (X : List Nat) (hX : Valid radix X) :
    EncInv radix (X.length / 2) (X.length - X.length / 2) 0
      ((List.range 10).reverse.foldl (decRound (roundValue ciph radix T X.length) radix
        (X.length / 2) (X.length - X.length / 2)) (X.take (X.length / 2), X.drop (X.length / 2))) := by
  have h9 := decInv_rounds (F := roundValue ciph radix T X.length) (u := X.length / 2)
    (v := X.length - X.length / 2) hr 9 0 _ (decInv_init radix X hX)
  have h0 := decInv_final (F := roundValue ciph radix T X.length) hr h9
  have : (List.range 10).reverse = (List.range' 1 9).reverse ++ [0] := by decide
  rw [this, List.foldl_append, List.foldl_cons, List.foldl_nil]
  exact h0

theorem decrypt_length (hr : 0 < radix) (X : List Nat) (hX : Valid radix X) :
    (decrypt ciph radix T X).length = X.length := by
  obtain ⟨h1, h2, -, -⟩ := decrypt_inv ciph radix T hr X hX
  simp only [decrypt, List.length_append, h1, h2]
  simp [roundLen]
  omega

/-- FF1.Encrypt(K, T, FF1.Decrypt(K, T, Y)) = Y. -/
theorem encrypt_decrypt (hr : 0 < radix) (Y : List Nat) (hY : Valid radix Y) :
    encrypt ciph radix T (decrypt ciph radix T Y) = Y := by
  have hlen := decrypt_length ciph radix T hr Y hY
  obtain ⟨h1, h2, h3, h4⟩ := decrypt_inv ciph radix T hr Y hY
  unfold encrypt
  rw [hlen]
  simp only [decrypt]
  rw [List.take_left' (by rw [h1]; simp [roundLen]), List.drop_left' (by rw [h1]; simp [roundLen])]
  have := enc_dec_rounds (F := roundValue ciph radix T Y.length) hr 9 0 _ (decInv_init radix Y hY)
  simp only [Nat.reduceAdd, ← List.range_eq_range'] at this
  rw [Prod.eta, this, List.take_append_drop]

/-- Distinct valid plaintexts encrypt to distinct ciphertexts. -/
theorem encrypt_injective (hr : 0 < radix) (X Y : List Nat) (hX : Valid radix X) (hY : Valid radix Y)
    (h : encrypt ciph radix T X = encrypt ciph radix T Y) : X = Y := by
  rw [← decrypt_encrypt ciph radix T hr X hX, h, decrypt_encrypt ciph radix T hr Y hY]

end FF1Spec
