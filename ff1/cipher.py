"""FF1 format-preserving encryption, per NIST SP 800-38G Rev. 1 (2nd public draft), section 4.

Example:
    >>> from ff1 import FF1
    >>> c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"))
    >>> c.encrypt("0123456789", bytes.fromhex("39383736353433323130"))
    '6124200773'
"""
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
        self._key = key
        self._ecb = AES.new(key, AES.MODE_ECB)

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
        bad = {ch for ch in text if ch not in self._index}
        if bad:
            raise ValueError(f"input contains characters outside the alphabet: {sorted(bad)!r}")
        tweak = _to_bytes(tweak, "tweak")
        t = len(tweak)
        if t > MAX_LEN:
            raise ValueError("tweak too long")

        radix = self.radix
        u = n // 2
        v = n - u
        a = self._num(text[:u])
        b = self._num(text[u:])
        blen = ((radix ** v - 1).bit_length() + 7) // 8
        d = 4 * ((blen + 3) // 4) + 4
        p = (bytes([1, 2, 1]) + radix.to_bytes(3, "big") + bytes([10, u % 256])
             + n.to_bytes(4, "big") + t.to_bytes(4, "big"))
        q_prefix = tweak + bytes((-t - blen - 1) % 16)
        mod_u, mod_v = radix ** u, radix ** v

        rounds = range(ROUNDS - 1, -1, -1) if decrypt else range(ROUNDS)
        for i in rounds:
            modulus = mod_u if i % 2 == 0 else mod_v
            if decrypt:
                y = self._round(p, q_prefix, i, a, blen, d)
                a, b = (b - y) % modulus, a
            else:
                y = self._round(p, q_prefix, i, b, blen, d)
                a, b = b, (a + y) % modulus
        return self._str(a, u) + self._str(b, v)

    def _round(self, p, q_prefix, i, x, blen, d):
        """Steps 6.i-6.iv: y = NUM(S) for round i, where x = NUM_radix of the unchanged half."""
        q = q_prefix + bytes([i]) + x.to_bytes(blen, "big")
        r = self._prf(p + q)
        s = r
        for j in range(1, (d + 15) // 16):
            s += self._ecb.encrypt((int.from_bytes(r, "big") ^ j).to_bytes(16, "big"))
        return int.from_bytes(s[:d], "big")

    def _prf(self, x):
        """PRF (Algorithm 4): CBC-MAC with a zero IV, i.e. the last CBC ciphertext block."""
        return AES.new(self._key, AES.MODE_CBC, iv=bytes(16)).encrypt(x)[-16:]

    def _num(self, s):
        """NUM_radix (Algorithm 1): read `s` as a big-endian base-radix number."""
        x = 0
        for ch in s:
            x = x * self.radix + self._index[ch]
        return x

    def _str(self, x, m):
        """STR^m_radix (Algorithm 3): write `x` as `m` big-endian base-radix symbols."""
        out = []
        for _ in range(m):
            x, digit = divmod(x, self.radix)
            out.append(self.alphabet[digit])
        return "".join(reversed(out))
