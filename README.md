# ff1

**FF1 format-preserving encryption** for Python, following NIST SP 800-38G Rev. 1
([second public draft, Feb 2025](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd)).
Ciphertext keeps the plaintext's length and alphabet: a 16-digit number encrypts to a
16-digit number.

```sh
pip install ff1-fpe
```

```python
from ff1 import FF1

c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"))  # AES-128/192/256 key
ct = c.encrypt("0123456789", tweak=b"98765432")
c.decrypt(ct, tweak=b"98765432")                             # -> "0123456789"

FF1(key, radix=36)                                           # 0-9a-z
FF1(key, alphabet="abcdefghijklmnopqrstuvwxyz")              # any symbols, up to 65536
```

- **Tweak:** optional bytes (or a hex string). It is public but should vary per
  record, so that equal values in different records encrypt differently.
- **Length:** inputs need `radix**len >= 1,000,000` (at least 6 decimal digits).
- **Errors:** invalid input raises `ValueError`.

`examples/demo.py` shows card tokenization that keeps the issuer prefix and a valid
Luhn checksum. Run `pip install .` first.

## Why trust it

- **NIST vectors:** it passes all 9 NIST FF1 samples and all 750 ACVP vectors, in both
  directions, covering radix 2–64, all three key sizes, and tweaks of 0–16 bytes.
- **Lean spec:** [`spec/`](spec/) transcribes SP 800-38G Rev. 1 into Lean 4, with
  machine-checked proofs that, for any block cipher:
  - FF1 is format-preserving.
  - Decryption inverts encryption, and vice versa.

  `lake build` also checks the spec's own AES against FIPS 197 and the spec itself
  against the NIST samples.
- **Differential testing:** `tests/test_lean.py` checks the Python against the Lean spec
  on random inputs (20,000 per PR and 200,000 weekly) with radix up to 2^16 and
  edge-biased lengths and tweaks. It also runs the ACVP vectors through the spec.

```sh
python -m unittest                       # Lean tests are skipped unless the spec is built
(cd spec && lake build) && python -m unittest
```

## Caveats

- **Audit:** this code is not audited, and it is not constant-time (pure Python
  integer arithmetic).
- **Integrity:** FPE provides confidentiality only, with no integrity protection.
- **Proof scope:** the proofs cover correctness, not security.
- **FF3/FF3-1:** these are deliberately not included. NIST removed them after
  Beyne's attack.

MIT licensed. This project grew out of a CSD451 course project; see the git history.
