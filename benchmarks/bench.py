"""Rough throughput benchmark: python benchmarks/bench.py"""
import random
import timeit

from ff1 import FF1

KEY = bytes(range(16))
rng = random.Random(0)

CASES = [
    ("card number, radix 10, n=16", FF1(KEY), 16, b"customer-42"),
    ("radix 10, n=64", FF1(KEY), 64, b""),
    ("radix 36, n=20", FF1(KEY, radix=36), 20, b"t"),
    ("radix 16, n=256", FF1(KEY, radix=16), 256, b"t"),
    ("radix 1000, n=32", FF1(KEY, alphabet="".join(chr(0x4E00 + i) for i in range(1000))), 32, b"t"),
]

for name, c, n, tweak in CASES:
    pt = "".join(rng.choice(c.alphabet) for _ in range(n))
    runs, total = timeit.Timer(lambda: c.encrypt(pt, tweak)).autorange()
    print(f"{name:32} {total / runs * 1e6:8.1f} µs/encrypt")
