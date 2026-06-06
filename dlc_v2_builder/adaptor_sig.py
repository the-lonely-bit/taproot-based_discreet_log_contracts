"""
Real BIP-340 Schnorr adaptor signatures (Adaptor Signature v2).

This module implements *cryptographic* adaptor signatures — the construction the original
NexumBit docs described but the v1 code did not actually use. It provides genuine, trustless
atomicity: completing an adaptor signature on-chain reveals the adaptor secret `t`, which the
counterparty extracts to complete their own claim. No coordinator needs to hold or distribute
the secret, and the secret cannot be withheld once a claim is broadcast.

Scheme (parity-correct, verified by the roundtrip test in tests/test_adaptor_signature.py):

  Setup:  signer secret d, pubkey P = d·G (x-only, even-Y per BIP-340);
          adaptor secret t, adaptor point T = t·G (full point, parity preserved).

  Presign(d, m, T) -> (R', s'):
      pick nonce k (deterministic, retried with a counter) such that
      R_adapted = k·G + T has even Y.
      R' = k·G
      e  = int(H_BIP340challenge( x(R_adapted) || x(P) || m )) mod n
      s' = (k + e·d) mod n
      presignature = compressed(R') || ser256(s')

  Verify(P, m, presig, T):
      R_adapted = R' + T must have even Y
      e = H(...) as above
      check s'·G == R' + e·P

  Complete(presig, t) -> 64-byte BIP-340 signature (r, s):
      R_adapted = R' + T,   s = (s' + t) mod n,   r = x(R_adapted)
      This (r, s) verifies as a standard BIP-340 signature for P over m.

  Extract(presig, full_sig, T) -> t:
      t = (s - s') mod n, validated against T = t·G.

Pure-Python secp256k1 math is used deliberately: it is self-contained, dependency-free, and
the canonical reference implementation, making it auditable and exactly reproducible by the
in-browser (noble) signer and the offline signer.py.
"""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

# secp256k1 domain parameters
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)

Point = Optional[Tuple[int, int]]  # None == point at infinity


# ── field / curve helpers ──────────────────────────────────────────────────

def _tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def _modinv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _modinv(2 * y1 % _P, _P) % _P
    else:
        lam = (y2 - y1) * _modinv((x2 - x1) % _P, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(p: Point, k: int) -> Point:
    r: Point = None
    addend = p
    k %= _N
    while k:
        if k & 1:
            r = _point_add(r, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return r


def _has_even_y(p: Point) -> bool:
    assert p is not None
    return p[1] % 2 == 0


def _lift_x(x: int) -> Point:
    """BIP-340 lift_x: even-Y point with the given x-coordinate, or None."""
    if x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def _bytes32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _ser_compressed(p: Point) -> bytes:
    assert p is not None
    return (b"\x02" if p[1] % 2 == 0 else b"\x03") + _bytes32(p[0])


def _parse_point(b: bytes) -> Point:
    """Parse a 33-byte compressed point, or a 32-byte x-only (even-Y) point."""
    if len(b) == 33 and b[0] in (0x02, 0x03):
        x = _int(b[1:])
        pt = _lift_x(x)
        if pt is None:
            raise ValueError("invalid compressed point (x not on curve)")
        if b[0] == 0x03:
            pt = (pt[0], _P - pt[1])
        return pt
    if len(b) == 32:
        pt = _lift_x(_int(b))
        if pt is None:
            raise ValueError("invalid x-only point")
        return pt
    raise ValueError(f"expected 33-byte compressed or 32-byte x-only point, got {len(b)}")


# ── public API ─────────────────────────────────────────────────────────────

def pubkey_xonly(seckey: bytes) -> bytes:
    """32-byte x-only pubkey for a 32-byte secret (BIP-340)."""
    d = _int(seckey) % _N
    if d == 0:
        raise ValueError("secret key is zero")
    P = _point_mul(_G, d)
    return _bytes32(P[0])


def point_from_secret(secret: bytes) -> bytes:
    """33-byte compressed adaptor point T = t·G for adaptor secret t."""
    t = _int(secret) % _N
    if t == 0:
        raise ValueError("adaptor secret is zero")
    return _ser_compressed(_point_mul(_G, t))


def _challenge(r_adapted_x: int, px: int, msg: bytes) -> int:
    return _int(_tagged_hash("BIP0340/challenge", _bytes32(r_adapted_x) + _bytes32(px) + msg)) % _N


def adaptor_presign(seckey: bytes, msg: bytes, adaptor_point: bytes) -> bytes:
    """
    Produce an adaptor pre-signature: compressed(R') || ser256(s')  (65 bytes).
    `adaptor_point` is T (33-byte compressed preferred to preserve parity).
    """
    if len(msg) != 32:
        raise ValueError("msg must be 32 bytes (sighash)")
    d0 = _int(seckey) % _N
    if d0 == 0:
        raise ValueError("secret key is zero")
    P = _point_mul(_G, d0)
    # BIP-340: sign under the even-Y representative of P
    d = d0 if _has_even_y(P) else _N - d0
    px = P[0]
    T = _parse_point(adaptor_point)

    for counter in range(0, 256):
        k_seed = _tagged_hash(
            "NexumBit/adaptor/nonce",
            seckey + msg + _ser_compressed(T) + counter.to_bytes(4, "big"),
        )
        k = _int(k_seed) % _N
        if k == 0:
            continue
        Rp = _point_mul(_G, k)            # R' = k·G
        R_adapted = _point_add(Rp, T)     # R = R' + T
        if R_adapted is None:
            continue
        if not _has_even_y(R_adapted):
            continue                      # retry until adapted nonce has even Y
        e = _challenge(R_adapted[0], px, msg)
        s = (k + e * d) % _N
        return _ser_compressed(Rp) + _bytes32(s)
    raise RuntimeError("failed to find suitable nonce (vanishingly unlikely)")


def adaptor_verify(pubkey_xonly_bytes: bytes, msg: bytes, presig: bytes, adaptor_point: bytes) -> bool:
    """Verify an adaptor pre-signature without knowing the adaptor secret."""
    try:
        if len(presig) != 65 or len(pubkey_xonly_bytes) != 32 or len(msg) != 32:
            return False
        Rp = _parse_point(presig[:33])
        s = _int(presig[33:65])
        if s >= _N:
            return False
        P = _lift_x(_int(pubkey_xonly_bytes))
        if P is None:
            return False
        T = _parse_point(adaptor_point)
        R_adapted = _point_add(Rp, T)
        if R_adapted is None or not _has_even_y(R_adapted):
            return False
        e = _challenge(R_adapted[0], P[0], msg)
        # check s·G == R' + e·P
        lhs = _point_mul(_G, s)
        rhs = _point_add(Rp, _point_mul(P, e))
        return lhs == rhs
    except Exception:
        return False


def adaptor_complete(presig: bytes, adaptor_secret: bytes) -> bytes:
    """
    Complete a pre-signature with the adaptor secret t, yielding a standard 64-byte BIP-340
    signature (r || s) that verifies for the signer's pubkey over msg.
    """
    if len(presig) != 65:
        raise ValueError("presig must be 65 bytes")
    Rp = _parse_point(presig[:33])
    s_prime = _int(presig[33:65])
    t = _int(adaptor_secret) % _N
    if t == 0:
        raise ValueError("adaptor secret is zero")
    T = _point_mul(_G, t)
    R_adapted = _point_add(Rp, T)
    if R_adapted is None or not _has_even_y(R_adapted):
        raise ValueError("adapted nonce has odd Y — presignature is malformed")
    s = (s_prime + t) % _N
    return _bytes32(R_adapted[0]) + _bytes32(s)


def adaptor_extract(presig: bytes, full_sig: bytes, adaptor_point: bytes) -> Optional[bytes]:
    """
    Recover the adaptor secret t from a pre-signature and the completed (on-chain) signature.
    Returns the 32-byte secret, or None if it does not match the adaptor point.
    """
    try:
        if len(presig) != 65 or len(full_sig) != 64:
            return None
        s_prime = _int(presig[33:65])
        s = _int(full_sig[32:64])
        t = (s - s_prime) % _N
        if t == 0:
            return None
        T_expected = _parse_point(adaptor_point)
        if _point_mul(_G, t) != T_expected:
            return None
        return _bytes32(t)
    except Exception:
        return None


def schnorr_verify(pubkey_xonly_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    """Standard BIP-340 Schnorr verification (used to confirm completed signatures)."""
    try:
        if len(sig) != 64 or len(pubkey_xonly_bytes) != 32 or len(msg) != 32:
            return False
        P = _lift_x(_int(pubkey_xonly_bytes))
        if P is None:
            return False
        r = _int(sig[:32])
        s = _int(sig[32:64])
        if r >= _P or s >= _N:
            return False
        e = _challenge(r, P[0], msg)
        R = _point_add(_point_mul(_G, s), _point_mul(P, (_N - e) % _N))
        if R is None or not _has_even_y(R) or R[0] != r:
            return False
        return True
    except Exception:
        return False
