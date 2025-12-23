# ecc_toy.py


import random
import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple

def inv_mod(x: int, p: int) -> int:
    """Modular inverse using Fermat (p prime)."""
    return pow(x % p, p-2, p)

@dataclass(eq=True, frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]
    curve: "Curve"
    def is_at_infinity(self) -> bool:
        return self.x is None and self.y is None
    def __repr__(self) -> str:
        if self.is_at_infinity(): return "Point(inf)"
        return f"Point({self.x},{self.y})"

class Curve:
    def __init__(self, p: int, a: int, b: int, Gx: int, Gy: int, n: Optional[int]=None, name: str='toy'):
        self.p = p
        self.a = a
        self.b = b
        self.G = Point(Gx, Gy, self)
        self.n = n or p
        self.name = name

# --- Core ECC ops --------------------------------------------------------

def point_add(P: Point, Q: Point) -> Point:
    """Add two points on the same curve."""
    curve = P.curve if not P.is_at_infinity() else Q.curve
    if P.is_at_infinity(): return Q
    if Q.is_at_infinity(): return P
    p = curve.p
    if P.x == Q.x and (P.y != Q.y or P.y == 0):
        return type(P)(None, None, curve)  # infinity
    if P.x == Q.x:
        # doubling
        s = ((3 * P.x * P.x + curve.a) * inv_mod(2 * P.y, p)) % p
    else:
        s = ((Q.y - P.y) * inv_mod(Q.x - P.x, p)) % p
    xr = (s*s - P.x - Q.x) % p
    yr = (s * (P.x - xr) - P.y) % p
    return type(P)(xr, yr, curve)

def scalar_mult(k: int, P: Point) -> Point:
    """Multiply point P by scalar k (double-and-add)."""
    if P.is_at_infinity(): return type(P)(None, None, P.curve)
    if k % P.curve.p == 0: return type(P)(None, None, P.curve)
    if k < 0:
        # -P
        return scalar_mult(-k, type(P)(P.x, (-P.y) % P.curve.p, P.curve))
    result = type(P)(None, None, P.curve)
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def random_scalar(curve: Curve) -> int:
    return random.randrange(1, curve.n)

# --- Message <-> Point (toy) ---------------------------------------------

def encode_message_to_point(curve: Curve, msg: bytes) -> Point:
    """Try-and-increment mapping: hash(msg) as starting x, find y with quadratic residue."""
    h = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % curve.p
    for i in range(curve.p):
        x = (h + i) % curve.p
        rhs = (x*x*x + curve.a * x + curve.b) % curve.p
        # Legendre symbol check: rhs^(p-1)/2 mod p == 1 for quadratic residue
        if pow(rhs, (curve.p-1)//2, curve.p) == 1:
            # small-field brute force square root (toy)
            for y in range(curve.p):
                if (y*y) % curve.p == rhs:
                    return type(curve.G)(x, y, curve)
    raise ValueError("Failed to encode message as point")

def decode_point_to_message(curve: Curve, P: Point) -> str:
    """Toy decode: return hex(x) - not reversible to original plaintext."""
    if P.is_at_infinity(): return ""
    return hex(P.x)

# --- Key generation ------------------------------------------------------

def generate_keypair(curve: Curve) -> Tuple[int, Point]:
    d = random_scalar(curve)
    Q = scalar_mult(d, curve.G)
    return d, Q

# --- ElGamal -------------------------------------------------------------

def elgamal_encrypt(curve: Curve, Q_receiver: Point, M: Point) -> Tuple[Point, Point]:
    k = random_scalar(curve)
    C1 = scalar_mult(k, curve.G)
    C2 = point_add(M, scalar_mult(k, Q_receiver))
    return (C1, C2)

def elgamal_decrypt(curve: Curve, d_receiver: int, C1: Point, C2: Point) -> Point:
    S = scalar_mult(d_receiver, C1)
    negS = type(C1)(S.x, (-S.y) % curve.p, curve)
    return point_add(C2, negS)

# --- ECDSA (toy) --------------------------------------------------------

# Replace inv_mod with an extended-gcd version (works for any modulus)
def inv_mod(x: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm.
    Raises ValueError if inverse does not exist."""
    x = x % m
    if x == 0:
        raise ValueError("Inverse does not exist")
    # extended gcd
    a, b = m, x
    u0, u1 = 1, 0
    v0, v1 = 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        u0, u1 = u1, u0 - q * u1
        v0, v1 = v1, v0 - q * v1
    # now a = gcd(m, x); v0 is inverse of x modulo m if gcd==1
    if a != 1:
        raise ValueError("Inverse does not exist (gcd != 1)")
    inv = v0 % m
    return inv

# helper: compute order of a point (works for small/toy curves)
def point_order(P: Point) -> int:
    """Return smallest k > 0 such that k*P = O (point at infinity)."""
    if P.is_at_infinity():
        return 1
    cur = type(P)(None, None, P.curve)  # O
    k = 1
    cur = point_add(cur, P)
    while not cur.is_at_infinity():
        k += 1
        cur = point_add(cur, P)
        # safety guard to avoid infinite loop for buggy curves
        if k > P.curve.p + 5:
            # fallback — use curve.p as last resort (should not happen for toy)
            return P.curve.p
    return k

def ecdsa_sign(curve: Curve, d: int, msg: bytes) -> Tuple[int,int]:
    # Use the actual order of G (n). If curve.n is not the order, compute it.
    n = curve.n
    try:
        # if curve.n might not be correct for toy curves, compute true order
        # but avoid recomputing repeatedly: if curve.n differs from actual, override locally
        true_order = point_order(curve.G)
        if true_order != n:
            n = true_order
    except Exception:
        n = curve.n

    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
    while True:
        k = random_scalar(curve) % n
        if k == 0:
            continue
        R = scalar_mult(k, curve.G)
        if R.is_at_infinity():
            continue
        r = R.x % n
        if r == 0:
            continue
        try:
            k_inv = inv_mod(k, n)
        except ValueError:
            continue
        s = (k_inv * (z + (r * d) % n)) % n
        if s == 0:
            continue
        return (r, s)

def ecdsa_verify(curve: Curve, Q: Point, msg: bytes, signature: Tuple[int,int]) -> bool:
    r, s = signature
    # determine order n (use actual point order if possible)
    n = curve.n
    try:
        true_order = point_order(curve.G)
        if true_order != n:
            n = true_order
    except Exception:
        n = curve.n

    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
    try:
        s_inv = inv_mod(s, n)
    except ValueError:
        return False
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n
    P = point_add(scalar_mult(u1, curve.G), scalar_mult(u2, Q))
    if P.is_at_infinity():
        return False
    return (P.x % n) == (r % n)

# --- ECDH ---------------------------------------------------------------

def ecdh_shared_secret(curve: Curve, priv: int, pub_point: Point) -> int:
    """Compute ECDH shared secret: S = priv * pub_point. Return x-coordinate (toy)."""
    S = scalar_mult(priv, pub_point)
    if S.is_at_infinity():
        raise ValueError("Shared secret is point at infinity")
    return S.x
