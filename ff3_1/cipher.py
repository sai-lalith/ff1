"""FF3-1 format-preserving encryption, per NIST SP 800-38G Rev. 1, section 5.2.

Example:
    >>> from ff3_1 import FF3_1
    >>> c = FF3_1(bytes.fromhex("EF4359D8D580AA4F7F036D6F04FC6A94"))
    >>> c.encrypt("890121234567890000", "D8E7920AFA330A")
    '477064185124354662'
"""
from Crypto.Cipher import AES

# Default alphabet: a cipher with radix r uses the first r characters.
BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

TWEAK_LEN = 7  # 56 bits
ROUNDS = 8


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


def _split_tweak(tweak):
    """T_L = T[0..27] || 0^4,  T_R = T[32..55] || T[28..31] || 0^4 (bit indices)."""
    tweak = _to_bytes(tweak, "tweak")
    if len(tweak) != TWEAK_LEN:
        raise ValueError("tweak must be 7 bytes (56 bits)")
    t_left = tweak[:3] + bytes([tweak[3] & 0xF0])
    t_right = tweak[4:] + bytes([(tweak[3] & 0x0F) << 4])
    return t_left, t_right


class FF3_1:
    """FF3-1 cipher bound to one AES key and alphabet.

    key:      16, 24 or 32 bytes (or the equivalent hex string).
    radix:    number of symbols; uses the first `radix` characters of BASE62.
    alphabet: explicit symbol set, overriding `radix` (e.g. "abcdefghijklmnopqrstuvwxyz").
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
        self.alphabet = alphabet
        self.radix = len(alphabet)
        if not 2 <= self.radix <= 2 ** 16:
            raise ValueError("radix must be in [2, 65536]")
        self._index = {ch: i for i, ch in enumerate(alphabet)}
        # maxlen = 2 * floor(log_radix(2**96)), computed exactly with integers.
        half = 0
        while self.radix ** (half + 1) <= 2 ** 96:
            half += 1
        self.maxlen = 2 * half
        # CIPH_REVB(K): the spec runs AES under the byte-reversed key.
        self._aes = AES.new(key[::-1], AES.MODE_ECB)

    def encrypt(self, plaintext, tweak):
        """Encrypt `plaintext` (a string over the alphabet) under a 56-bit `tweak`."""
        return self._crypt(plaintext, tweak, decrypt=False)

    def decrypt(self, ciphertext, tweak):
        """Invert `encrypt`."""
        return self._crypt(ciphertext, tweak, decrypt=True)

    def _crypt(self, text, tweak, decrypt):
        n = len(text)
        if n < 2 or self.radix ** n < self.DOMAIN_MIN:
            raise ValueError(f"input too short: radix**length must be >= {self.DOMAIN_MIN}")
        if n > self.maxlen:
            raise ValueError(f"input too long: maximum length for radix {self.radix} is {self.maxlen}")
        bad = set(text) - self._index.keys()
        if bad:
            raise ValueError(f"input contains characters outside the alphabet: {sorted(bad)!r}")

        t_left, t_right = _split_tweak(tweak)

        u = (n + 1) // 2
        v = n - u
        a, b = text[:u], text[u:]
        rounds = range(ROUNDS - 1, -1, -1) if decrypt else range(ROUNDS)
        for i in rounds:
            if i % 2 == 0:
                m, w = u, t_right
            else:
                m, w = v, t_left
            modulus = self.radix ** m
            if decrypt:
                y = self._round(i, w, a)
                c = (self._num_rev(b) - y) % modulus
                b, a = a, self._str_rev(c, m)
            else:
                y = self._round(i, w, b)
                c = (self._num_rev(a) + y) % modulus
                a, b = b, self._str_rev(c, m)
        return a + b

    def _round(self, i, w, half):
        """Round function: NUM(REVB(CIPH_REVB(K)(REVB(P))))."""
        s = self._aes.encrypt(self._p(i, w, half)[::-1])[::-1]
        return int.from_bytes(s, "big")

    def _p(self, i, w, half):
        """P = (W xor [i]^4) || [NUM_radix(REV(half))]^12, a single 16-byte block."""
        p = (int.from_bytes(w, "big") ^ i).to_bytes(4, "big")
        return p + self._num_rev(half).to_bytes(12, "big")

    def _num_rev(self, s):
        """NUM_radix(REV(s)): read `s` as a little-endian base-radix number."""
        x = 0
        for ch in reversed(s):
            x = x * self.radix + self._index[ch]
        return x

    def _str_rev(self, x, m):
        """REV(STR^m_radix(x)): write `x` as `m` little-endian base-radix symbols."""
        out = []
        for _ in range(m):
            x, d = divmod(x, self.radix)
            out.append(self.alphabet[d])
        return "".join(out)
