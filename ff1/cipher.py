"""FF1 format-preserving encryption, per NIST SP 800-38G Rev. 1 (2nd public draft), section 4.

Example:
    >>> from ff1 import FF1
    >>> c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"))
    >>> c.encrypt("0123456789", bytes.fromhex("39383736353433323130"))
    '6124200773'
"""
import functools

from Crypto.Cipher import AES

# Default alphabet: a cipher with radix r uses the first r characters.
BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

ROUNDS = 10
MAX_RADIX = 2 ** 16
MAX_LEN = 2 ** 32 - 1


def _to_bytes(value, name):
    """Accept raw bytes or a hex string."""
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise ValueError(f"{name} is not a valid hex string") from None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes or a hex string")


class FF1:
    """FF1 cipher bound to one AES key and alphabet.

    key:      16, 24 or 32 bytes (or the equivalent hex string).
    radix:    number of symbols; uses the first `radix` characters of BASE62.
    alphabet: explicit symbol set, overriding `radix` (up to 65536 symbols).
    """

    # The spec requires radix**minlen >= 1,000,000.
    DOMAIN_MIN = 1_000_000

    def __init__(self, key, radix=10, alphabet=None):
        key = _to_bytes(key, "key")
        if len(key) not in (16, 24, 32):
            raise ValueError("key must be 16, 24 or 32 bytes")
        if alphabet is None:
            if not 2 <= radix <= len(BASE62):
                raise ValueError(f"radix must be in [2, {len(BASE62)}] without a custom alphabet")
            alphabet = BASE62[:radix]
        if len(set(alphabet)) != len(alphabet):
            raise ValueError("alphabet contains duplicate characters")
        if not 2 <= len(alphabet) <= MAX_RADIX:
            raise ValueError(f"radix must be in [2, {MAX_RADIX}]")
        self.alphabet = alphabet
        self.radix = len(alphabet)
        self.minlen = next(n for n in range(2, 64) if self.radix ** n >= self.DOMAIN_MIN)
        self._index = {ch: i for i, ch in enumerate(alphabet)}
        self._charset = frozenset(alphabet)
        # Default alphabets up to base 36 are exactly what int(s, radix) parses, and bases
        # 2/8/10/16 are what format() writes, so those conversions can run in C.
        self._native = alphabet == BASE62[:self.radix] and self.radix <= 36
        self._format = {2: "b", 8: "o", 10: "d", 16: "x"}.get(self.radix) if self._native else None
        self._key = key
        self._ecb = AES.new(key, AES.MODE_ECB)
        # CBC-MAC state of P plus the tweak part of Q. It depends only on public inputs
        # (radix, length, tweak), so repeated calls with the same tweak and length reuse it.
        self._prefix_state = functools.lru_cache(maxsize=256)(self._mac_int)

    def encrypt(self, plaintext, tweak=b""):
        """Encrypt `plaintext` (a string over the alphabet) under `tweak` (bytes or hex)."""
        return self._crypt(plaintext, tweak, decrypt=False)

    def decrypt(self, ciphertext, tweak=b""):
        """Invert `encrypt`."""
        return self._crypt(ciphertext, tweak, decrypt=True)

    def _crypt(self, text, tweak, decrypt):
        n = len(text)
        if n < self.minlen:
            raise ValueError(f"input too short: minimum length for radix {self.radix} is {self.minlen}")
        if n > MAX_LEN:
            raise ValueError("input too long")
        if not self._charset.issuperset(text):
            bad = {ch for ch in text if ch not in self._index}
            raise ValueError(f"input contains characters outside the alphabet: {sorted(bad)!r}")
        tweak = _to_bytes(tweak, "tweak")
        t = len(tweak)
        if t > MAX_LEN:
            raise ValueError("tweak too long")

        u, v, blen, d, p, q_prefix = self._setup(n, tweak)
        a = self._num(text[:u])
        b = self._num(text[u:])
        mod_u, mod_v = self.radix ** u, self.radix ** v
        round_value = self._round_function(p + q_prefix, blen, d)

        rounds = range(ROUNDS - 1, -1, -1) if decrypt else range(ROUNDS)
        for i in rounds:
            modulus = mod_u if i % 2 == 0 else mod_v
            if decrypt:
                a, b = (b - round_value(i, a)) % modulus, a
            else:
                a, b = b, (a + round_value(i, b)) % modulus
        return self._str(a, u) + self._str(b, v)

    def _setup(self, n, tweak):
        """Steps 1-5 plus the round-independent start of Q: (u, v, b, d, P, T || 0^pad)."""
        radix, t = self.radix, len(tweak)
        u = n // 2
        v = n - u
        blen = ((radix ** v - 1).bit_length() + 7) // 8
        d = 4 * ((blen + 3) // 4) + 4
        p = (bytes([1, 2, 1]) + radix.to_bytes(3, "big") + bytes([10, u % 256])
             + n.to_bytes(4, "big") + t.to_bytes(4, "big"))
        return u, v, blen, d, p, tweak + bytes((-t - blen - 1) % 16)

    def _round_function(self, prefix, blen, d):
        """Steps 6.i-6.iv as a function of (i, x), equivalent to `_round` but faster.

        P || Q = prefix || [i]^1 || [x]^b, and `prefix` (P plus the tweak part of Q) is the
        same in every round. Its CBC-MAC up to the last full block is computed once (and
        cached across calls), so each round only runs CBC over the blocks holding i and x:
        one AES call for halves of up to 15 bytes, which covers inputs up to 36 decimal digits.
        """
        full = len(prefix) - len(prefix) % 16
        head = prefix[:full]
        state = self._prefix_state(head) if full <= 512 else self._mac_int(head)
        tail_head = int.from_bytes(prefix[full:], "big") << (8 * (blen + 1))
        tail_blocks = (len(prefix) - full + 1 + blen) // 16
        round_shift = 8 * blen
        encrypt = self._ecb.encrypt
        extra = (d + 15) // 16 - 1
        drop = 8 * (16 * (extra + 1) - d)
        out = bytearray(16)
        mask = (1 << 128) - 1

        key, state_iv, tail_len = self._key, state.to_bytes(16, "big"), 16 * tail_blocks

        def round_value(i, x):
            tail = tail_head | (i << round_shift) | x
            if tail_blocks <= 3:  # a few ECB calls beat creating a CBC object
                y = state
                for k in range(tail_blocks - 1, -1, -1):
                    encrypt((y ^ ((tail >> (128 * k)) & mask)).to_bytes(16, "big"), output=out)
                    y = int.from_bytes(out, "big")
                r = out
            else:  # continue the CBC-MAC from the cached state, in one C call
                r = AES.new(key, AES.MODE_CBC, iv=state_iv).encrypt(tail.to_bytes(tail_len, "big"))[-16:]
            if extra:
                y = int.from_bytes(r, "big")
                counters = b"".join((y ^ j).to_bytes(16, "big") for j in range(1, extra + 1))
                return int.from_bytes(bytes(r) + encrypt(counters), "big") >> drop
            return int.from_bytes(r, "big") >> drop

        return round_value

    def _round(self, p, q_prefix, i, x, blen, d):
        """Steps 6.i-6.iv: y = NUM(S) for round i, where x = NUM_radix of the unchanged half.

        Direct transcription of the spec, kept as the reference for `_round_function`.
        """
        q = q_prefix + bytes([i]) + x.to_bytes(blen, "big")
        r = self._prf(p + q)
        s = r
        for j in range(1, (d + 15) // 16):
            s += self._ecb.encrypt((int.from_bytes(r, "big") ^ j).to_bytes(16, "big"))
        return int.from_bytes(s[:d], "big")

    def _prf(self, x):
        """PRF (Algorithm 4): CBC-MAC with a zero IV, i.e. the last CBC ciphertext block."""
        return self._mac_int(x).to_bytes(16, "big")

    def _mac_int(self, x):
        """CBC-MAC of the block string `x`, as an integer."""
        if len(x) > 64:
            return int.from_bytes(AES.new(self._key, AES.MODE_CBC, iv=bytes(16)).encrypt(x)[-16:], "big")
        y = 0
        for j in range(0, len(x), 16):
            y = int.from_bytes(self._ecb.encrypt((y ^ int.from_bytes(x[j:j + 16], "big")).to_bytes(16, "big")), "big")
        return y

    def _num(self, s):
        """NUM_radix (Algorithm 1): read `s` as a big-endian base-radix number."""
        # int() refuses more than 4300 digits by default (CPython's int/str conversion limit).
        if self._native and len(s) <= 4000:
            return int(s, self.radix)
        index, radix, x = self._index, self.radix, 0
        for ch in s:
            x = x * radix + index[ch]
        return x

    def _str(self, x, m):
        """STR^m_radix (Algorithm 3): write `x` as `m` big-endian base-radix symbols."""
        if self._format and m <= 4000:
            return format(x, f"0{m}{self._format}")
        alphabet, radix, out = self.alphabet, self.radix, []
        for _ in range(m):
            x, digit = divmod(x, radix)
            out.append(alphabet[digit])
        return "".join(reversed(out))
