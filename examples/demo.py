"""Using the ff1 library: tokenize card numbers so they still look like card numbers.

Install the package first (pip install .), then:  python examples/demo.py
"""
import os

from ff1 import FF1


def luhn_check_digit(digits):
    """Check digit that makes `digits + check` pass the Luhn test."""
    total = 0
    for i, d in enumerate(reversed(digits)):
        d = int(d)
        if i % 2 == 0:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return str(-total % 10)


def is_luhn_valid(number):
    return luhn_check_digit(number[:-1]) == number[-1]


def tokenize_card(cipher, card, tweak):
    """Keep the 6-digit issuer prefix, encrypt the account digits, recompute the check digit.

    The result is a Luhn-valid number from the same issuer, so systems that validate
    or route on card format keep working.
    """
    bin_, account = card[:6], card[6:-1]
    body = bin_ + cipher.encrypt(account, tweak)
    return body + luhn_check_digit(body)


def detokenize_card(cipher, token, tweak):
    bin_, account = token[:6], token[6:-1]
    body = bin_ + cipher.decrypt(account, tweak)
    return body + luhn_check_digit(body)


def main():
    # In production the key comes from a KMS/HSM, never from code or a PIN.
    key = os.urandom(16)
    cipher = FF1(key)  # radix 10 by default

    # 1. Plain digit strings: output has the same length and alphabet.
    tweak = b"cards-table"  # any bytes; optional, defaults to empty
    ct = cipher.encrypt("4088498645809206", tweak)
    print("digits     ", "4088498645809206", "->", ct, "->", cipher.decrypt(ct, tweak))

    # 2. Card tokenization preserving issuer prefix and Luhn validity.
    #    Using a per-record tweak (e.g. the customer id) means equal card numbers
    #    in different records encrypt differently.
    card = "4111111111111111"
    for customer_tweak in (b"customer-1", b"customer-2"):
        token = tokenize_card(cipher, card, customer_tweak)
        back = detokenize_card(cipher, token, customer_tweak)
        print(f"card       {card} -> {token} (luhn ok: {is_luhn_valid(token)}) -> {back}")

    # 3. Other alphabets: radix 36 IDs and a custom lowercase alphabet.
    ids = FF1(key, radix=36)
    ct = ids.encrypt("order9z81kq2", tweak)
    print("radix 36   ", "order9z81kq2", "->", ct, "->", ids.decrypt(ct, tweak))

    names = FF1(key, alphabet="abcdefghijklmnopqrstuvwxyz")
    ct = names.encrypt("alicesmith", tweak)
    print("lowercase  ", "alicesmith", "->", ct, "->", names.decrypt(ct, tweak))

    # 4. Inputs the spec does not allow raise ValueError.
    for bad in ("12345", "1234-5678-9012"):
        try:
            cipher.encrypt(bad, tweak)
        except ValueError as e:
            print(f"rejected    {bad!r}: {e}")


if __name__ == "__main__":
    main()
