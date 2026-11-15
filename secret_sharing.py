"""Core secret-sharing primitives for ShareGuard.

Two schemes are implemented over the prime field GF(p), p = 2^61 - 1:
  * Additive n-of-n sharing  - fast, all shares are needed to reconstruct.
  * Shamir (t, n) sharing    - any t of the n shares reconstruct the secret.
Both are linear, so shares of different secrets can be added share-by-share
and the result reconstructs to the sum of the secrets.
"""
import secrets

PRIME = 2 ** 61 - 1          # Mersenne prime
SCALE = 100                  # fixed-point scale (2 decimal places)


# ---------- fixed-point encoding ----------
def to_int(x: float, scale: int = SCALE) -> int:
    """Convert a float to a scaled integer (may be negative)."""
    return int(round(x * scale))


def to_field(v: int, prime: int = PRIME) -> int:
    """Map a (possibly negative) integer into GF(p)."""
    if abs(v) >= prime // 2:
        raise ValueError("Value too large for the field; reduce SCALE or data range")
    return v % prime


def from_field(v: int, prime: int = PRIME) -> int:
    """Map a field element back to a signed integer."""
    return v - prime if v > prime // 2 else v


# ---------- additive sharing ----------
def additive_split(secret: int, n: int, prime: int = PRIME):
    if n < 2:
        raise ValueError("Need at least 2 shares")
    shares = [secrets.randbelow(prime) for _ in range(n - 1)]
    shares.append((secret - sum(shares)) % prime)
    return shares


def additive_combine(shares, prime: int = PRIME) -> int:
    return sum(shares) % prime


# ---------- Shamir sharing ----------
def shamir_split(secret: int, n: int, t: int, prime: int = PRIME):
    """Return n points (x, y) of a random degree t-1 polynomial with f(0)=secret."""
    if not (2 <= t <= n):
        raise ValueError("Require 2 <= t <= n")
    coeffs = [secret % prime] + [secrets.randbelow(prime) for _ in range(t - 1)]
    def f(x):
        acc = 0
        for c in reversed(coeffs):          # Horner's rule
            acc = (acc * x + c) % prime
        return acc
    return [(x, f(x)) for x in range(1, n + 1)]


def shamir_combine(points, prime: int = PRIME) -> int:
    """Lagrange interpolation at x = 0 using the supplied (x, y) points."""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = (num * (-xj)) % prime
                den = (den * (xi - xj)) % prime
        secret = (secret + yi * num * pow(den, -1, prime)) % prime
    return secret
