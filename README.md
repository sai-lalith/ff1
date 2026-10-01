# ff3-1

A small, dependency-light Python implementation of **FF3-1 format-preserving encryption**
(NIST SP 800-38G Rev. 1). Ciphertext has the same length and alphabet as the plaintext:
a 16-digit number encrypts to a 16-digit number, a lowercase word to a lowercase word.

```python
from ff3_1 import FF3_1

cipher = FF3_1(bytes.fromhex("EF4359D8D580AA4F7F036D6F04FC6A94"))   # AES-128/192/256 key
ct = cipher.encrypt("890121234567890000", tweak="D8E7920AFA330A")   # -> "477064185124354662"
cipher.decrypt(ct, tweak="D8E7920AFA330A")                          # -> "890121234567890000"
```

## Install

```sh
pip install .            # library only (needs pycryptodome)
pip install -e '.[test]' # plus the reference implementation used by the tests
```

## API

`FF3_1(key, radix=10, alphabet=None)`

- `key`: 16, 24 or 32 bytes, or the same as a hex string.
- `radix`: alphabet size. The cipher uses the first `radix` characters of
  `0-9a-zA-Z` (up to 62).
- `alphabet`: any string of unique characters. Overrides `radix`, for example
  `"abcdefghijklmnopqrstuvwxyz"` or a 64-character base64 set.

`cipher.encrypt(text, tweak)` / `cipher.decrypt(text, tweak)`

- `tweak`: 7 bytes (56 bits), or a 14-character hex string. FF3-1 tweaks are 56 bits.
  Old FF3 64-bit tweaks are rejected.
- `text` must use only characters from the alphabet. Its length must be between
  `minlen` (where `radix**minlen >= 1,000,000`, which is 6 for decimal) and
  `cipher.maxlen` (56 for decimal).
- Invalid input raises `ValueError`.

The tweak is public, but it should vary per record (a customer ID or column name,
for example). That way the same value stored in two places encrypts to two
different ciphertexts.

## Demo

```sh
pip install .   # or: pip install -e .
python examples/demo.py
```

The demo encrypts digit strings, custom alphabets and radix-36 IDs. It also shows
**card tokenization**: it keeps the 6-digit issuer prefix, encrypts the account
digits and recomputes the Luhn check digit. The result is still a valid-looking card
number from the same issuer. Plain FPE on its own does *not* preserve the Luhn
checksum.

## How correctness is checked

```sh
python -m unittest -v
```

The tests check the implementation in several independent ways:

1. **Known-answer tests** (`tests/test_vectors.py`): 18 NIST ACVP FF3-1 vectors
   covering AES-128/192/256 and radix 10/26/64, plus the NIST sample with a 56-bit
   tweak. Every vector is checked in both directions.
2. **Spec-step tests** (`tests/test_properties.py`): the tweak split into T_L/T_R and
   the round-0 `P` block from the NIST worked example are checked byte for byte. This
   catches mistakes that end-to-end vectors would only report as "wrong output".
3. **Differential testing** (`tests/test_reference.py`): 2,000 random
   key/tweak/radix/length cases compared against
   [mysto/python-fpe](https://github.com/mysto/python-fpe), an independently written
   implementation. Skipped if `ff3` isn't installed.
4. **Whole-domain permutation**: on small domains, every possible input is encrypted.
   The test checks that the result is exactly a permutation of the domain and that
   decryption inverts it.
5. **Mutation check**: injecting plausible bugs into the cipher makes the suite fail
   every time. The bugs tried include a wrong tweak split, a wrong `P` width, a missing
   key reversal, swapped halves, a wrong `u` and a wrong round count.

## Caveats

- FF3-1's standing at NIST has been uncertain since cryptanalysis of FF3 and FF3-1.
  Check the current status of SP 800-38G before relying on it, and prefer FF1 for new
  systems where you have the choice.
- This code has not been audited or side-channel hardened. It is pure Python and not
  constant-time.
- FPE gives confidentiality only. It provides no integrity or authenticity.

## Origin

This repo started as **Credit-Card-FPE**, a credit-card processing demo (socket
client/server) built on a hand-written FF3-1 for the CSD451 course project. That code,
along with the project report and the NIST draft, is kept unchanged in
[`archive/`](archive/). The rest of the coursework is in
[Crypto-Course-Work](https://github.com/sai-lalith/Crypto-Course-Work).

The archived cipher (`archive/ff3_1.py`) round-tripped correctly but did not match the
standard, because of three spec deviations: a 192-bit numeral block, PKCS7 padding
before AES, and an un-zeroed tweak nibble in T_L. The library here is a rewrite.

## License

MIT
