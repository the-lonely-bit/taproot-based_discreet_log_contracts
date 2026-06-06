#!/usr/bin/env python3
"""
NexumBit Recovery & Signing Tool v2.0

Self-sovereign recovery tool for NexumBit DLC bridge swaps.
Works independently of the NexumBit backend.

Two modes:
  [1] Sign an existing PSBT (hex input)
  [2] Build + Sign from Recovery Kit (JSON file or paste)

Supports:
  - Taproot key-path spend (P2TR funding PSBTs: witness_utxo only, no tap scripts — e.g. LTC aggregate DLC funding)
  - Bitcoin Cash / eCash: same key-path shape, but signing uses replay-protected sighash when network is bch/xec (not BTC BIP-341 TapSighash)
  - Taproot script-path claim (pre-signed or manual adaptor signature; same shape as oracle co-sign + lender)
  - FAL hashlock lender claim (OP_SHA256 preimage + lender Schnorr — mode [1] prompts for 32-byte preimage)
  - Taproot script-path refund (CLTV + single key), including fixed-term lender leaf and safety refund
  - Private key input: WIF or raw 64-char hex
  - Broadcasting to Bitcoin / Fractal Bitcoin / Litecoin / Bellscoin / DigiByte / Groestlcoin / Bitcoin Cash / eCash / Ravencoin networks

Dependencies: pip install embit base58 httpx bitcash
  - segwit_addr.py (bundled): DGB/GRS/LTC/BEL/RVN bech32 (dgb1, grs1, ltc1, bel1, rvn1)
  - bitcash CashAddr: BCH (bitcoincash:) and XEC (ecash:) Taproot addresses
  - embit:  Required (Schnorr signatures, key derivation)
  - base58: Required (WIF decoding)
  - httpx:  Optional (broadcasting — can broadcast manually without it)

Usage:  python signer.py
"""

import sys
import os
import re
import json
import hashlib
import struct
import base64
from io import BytesIO
from typing import Optional, Tuple, Dict, List, Any

try:
    from embit.ec import PrivateKey, PublicKey
    from embit import script as embit_script
    from embit.transaction import Transaction as EmbitTx
    from embit.transaction import TransactionInput as EmbitTxIn
    from embit.transaction import TransactionOutput as EmbitTxOut
    from embit.transaction import SIGHASH as EmbitSIGHASH
    from embit.script import Script as EmbitScript
    HAS_EMBIT = True
except ImportError:
    HAS_EMBIT = False
    EmbitTx = None  # type: ignore

try:
    import base58
    HAS_BASE58 = True
except ImportError:
    HAS_BASE58 = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# Local segwit_addr for DGB/GRS/LTC/BEL/RVN (dgb1, grs1, ltc1, bel1, rvn1) — always available
try:
    from segwit_addr import decode as segwit_decode
    HAS_SEGWIT_ADDR = True
except ImportError:
    # Allow running from project root: python psbt-signer/signer.py
    _signer_dir = os.path.dirname(os.path.abspath(__file__))
    if _signer_dir not in sys.path:
        sys.path.insert(0, _signer_dir)
    try:
        from segwit_addr import decode as segwit_decode
        HAS_SEGWIT_ADDR = True
    except ImportError:
        HAS_SEGWIT_ADDR = False

# Bitcoin Cash CashAddr (P2TR) — same primitives as backend `bch_address.py`
HAS_BCH_CASHADDR = False
BCH_MAINNET_PREFIX = "bitcoincash"

try:
    from bitcash.cashaddress import (
        calculate_checksum,
        convertbits,
        b32encode,
        b32decode,
        verify_checksum,
    )

    def _bch_encode_cashaddr(prefix: str, version_byte: int, payload: bytes) -> str:
        data = [version_byte] + list(payload)
        payload_5 = convertbits(data, 8, 5)
        checksum = calculate_checksum(prefix, payload_5)
        return prefix + ":" + b32encode(payload_5 + checksum)

    def bch_taproot_output_pubkey_to_cashaddr(
        output_pubkey_xonly: bytes, prefix: str = BCH_MAINNET_PREFIX
    ) -> str:
        if len(output_pubkey_xonly) != 32:
            raise ValueError("Taproot output pubkey must be 32 bytes")
        # Match BCH wallets: P2TR uses CashAddr version 11 (same 32-byte x-only as v3, different string).
        return _bch_encode_cashaddr(prefix, 11, output_pubkey_xonly)

    def bch_cashaddr_to_scriptpubkey(address: str) -> bytes:
        addr = "".join((address or "").split())
        if not addr:
            raise ValueError("empty address")
        lower = addr.lower()
        if ":" not in lower:
            addr = f"{BCH_MAINNET_PREFIX}:{addr}"
        else:
            addr = lower
        prefix, base32string = addr.split(":", 1)
        decoded = b32decode(base32string)
        if not verify_checksum(prefix, decoded):
            raise ValueError("invalid CashAddr checksum")
        converted = convertbits(decoded, 5, 8)
        if not converted or len(converted) < 2:
            raise ValueError("invalid CashAddr payload")
        version_byte = converted[0]
        payload = bytes(converted[1:-6])
        if version_byte in (3, 11) and len(payload) == 32:
            return bytes([0x51, 0x20]) + payload
        if len(payload) == 20:
            if version_byte == 0:
                return bytes([0x76, 0xA9, 0x14]) + payload + bytes([0x88, 0xAC])
            if version_byte == 8:
                return bytes([0xA9, 0x14]) + payload + bytes([0x87])
        raise ValueError(
            f"unsupported CashAddr version/length: v={version_byte} len={len(payload)}"
        )

    HAS_BCH_CASHADDR = True
except ImportError:
    def bch_taproot_output_pubkey_to_cashaddr(output_pubkey_xonly: bytes, prefix: str = BCH_MAINNET_PREFIX) -> str:
        raise RuntimeError("bitcash required for BCH: pip install bitcash")

    def bch_cashaddr_to_scriptpubkey(address: str) -> bytes:
        raise RuntimeError("bitcash required for BCH: pip install bitcash")


def _looks_like_bch_cashaddr(addr: str) -> bool:
    s = "".join((addr or "").split()).lower()
    if s.startswith("bitcoincash:") or s.startswith("bchtest:"):
        return True
    if ":" not in s and 25 <= len(s) <= 200 and all(
        c in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" for c in s
    ):
        return True
    return False


def _looks_like_ecash_cashaddr(addr: str) -> bool:
    s = "".join((addr or "").split()).lower()
    return s.startswith("ecash:")


def _hex_bytes(s: Any, field: str = "hex") -> bytes:
    """Parse hex from recovery-kit strings; strips spaces/newlines inside pasted hex."""
    if s is None:
        raise ValueError(f"{field}: missing")
    cleaned = re.sub(r"[^0-9a-fA-F]", "", str(s).strip())
    if not cleaned:
        raise ValueError(f"{field}: empty")
    if len(cleaned) % 2:
        raise ValueError(f"{field}: odd hex length ({len(cleaned)} chars after cleaning)")
    return bytes.fromhex(cleaned)


_KIT_KEY_ALIASES = {
    "redeem_scriptpt_hex": "redeem_script_hex",
    "success_controlblock": "success_control_block",
}


def _normalize_kit_key(name: Any) -> Any:
    if not isinstance(name, str):
        return name
    compact = re.sub(r"\s+", "", name)
    return _KIT_KEY_ALIASES.get(compact, compact)


def _normalize_recovery_kit(obj: Any) -> Any:
    """Fix whitespace-broken JSON keys from ugly pastes (matches backend/signer.py)."""
    if isinstance(obj, dict):
        return {_normalize_kit_key(k): _normalize_recovery_kit(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_recovery_kit(x) for x in obj]
    return obj


def normalize_signer_network(net: str) -> str:
    """Map recovery-kit / API chain strings to NETWORKS keys."""
    n = (net or "btc").strip().lower()
    aliases = {
        "bitcoin_cash_mainnet": "bch",
        "bitcoin_cash": "bch",
        "bitcoin cash": "bch",
        "ecash_mainnet": "xec",
        "ecash": "xec",
        "ravencoin_mainnet": "rvn",
        "ravencoin": "rvn",
        "dogecoin_mainnet": "doge",
        "dogecoin": "doge",
    }
    return aliases.get(n, n)


# ═══════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════

VERSION = "2.0.0"

NETWORKS = {
    "btc": {
        "name": "Bitcoin",
        "broadcast_url": "https://mempool.space/api/tx",
        "tx_url": "https://mempool.space/tx/",
        "height_url": "https://mempool.space/api/blocks/tip/height",
    },
    "fb": {
        "name": "Fractal Bitcoin",
        "broadcast_url": "https://mempool.fractalbitcoin.io/api/tx",
        "tx_url": "https://mempool.fractalbitcoin.io/tx/",
        "height_url": "https://mempool.fractalbitcoin.io/api/blocks/tip/height",
    },
    "ltc": {
        "name": "Litecoin",
        "broadcast_url": "https://litecoinspace.org/api/tx",
        "tx_url": "https://litecoinspace.org/tx/",
        "height_url": "https://litecoinspace.org/api/blocks/tip/height",
    },
    "bel": {
        "name": "Bellscoin",
        "broadcast_url": "https://nintondo.io/api/electrs/tx",
        "tx_url": "https://nintondo.io/bells/mainnet/explorer/tx/",
        "height_url": "https://nintondo.io/api/electrs/blocks/tip/height",
    },
    "dgb": {
        "name": "DigiByte",
        # Blockbook uses /api/v2/sendtx/ (not /api/tx); returns JSON {"result":"<txid>"}
        "broadcast_url": "https://digibyte.atomicwallet.io/api/v2/sendtx/",
        "broadcast_urls": ["https://digibyte.atomicwallet.io/api/v2/sendtx/"],
        "tx_url": "https://digibyte.atomicwallet.io/tx/",
        "height_url": "https://digibyte.atomicwallet.io/api/v2",
        "height_json": True,  # Blockbook: parse blockbook.bestHeight from JSON
    },
    "grs": {
        "name": "Groestlcoin",
        "broadcast_url": "https://blockbook.groestlcoin.org/api/v2/sendtx/",
        "broadcast_urls": ["https://blockbook.groestlcoin.org/api/v2/sendtx/"],
        "tx_url": "https://blockbook.groestlcoin.org/tx/",
        "height_url": "https://blockbook.groestlcoin.org/api/v2",
        "height_json": True,
    },
    "bch": {
        "name": "Bitcoin Cash",
        # Blockchair first (reliable). BCExplorer POST /api/tx often proxies a node that returns RPC -4 for edge-case txs.
        "broadcast_url": "https://api.blockchair.com/bitcoin-cash/push/transaction",
        "broadcast_urls": [
            "https://api.blockchair.com/bitcoin-cash/push/transaction",
            "https://bchexplorer.cash/api/tx",
        ],
        "tx_url": "https://blockchair.com/bitcoin-cash/transaction/",
        "height_url": "https://api.blockchair.com/bitcoin-cash/stats",
        "height_blockchair": True,
    },
    "xec": {
        "name": "eCash",
        "broadcast_url": "https://api.blockchair.com/ecash/push/transaction",
        "broadcast_urls": ["https://api.blockchair.com/ecash/push/transaction"],
        "tx_url": "https://blockchair.com/ecash/transaction/",
        "height_url": "https://api.blockchair.com/ecash/stats",
        "height_blockchair": True,
    },
    "rvn": {
        "name": "Ravencoin",
        "broadcast_url": "https://blockbook.ravencoin.org/api/v2/sendtx/",
        "broadcast_urls": ["https://blockbook.ravencoin.org/api/v2/sendtx/"],
        "tx_url": "https://blockbook.ravencoin.org/tx/",
        "height_url": "https://blockbook.ravencoin.org/api/v2",
        "height_json": True,
    },
    "zec": {
        "name": "Zcash (transparent)",
        "broadcast_url": "https://api.blockchair.com/zcash/push/transaction",
        "broadcast_urls": ["https://api.blockchair.com/zcash/push/transaction"],
        "tx_url": "https://blockchair.com/zcash/transaction/",
        "height_url": "https://api.blockchair.com/zcash/stats",
        "height_blockchair": True,
    },
    "doge": {
        "name": "Dogecoin",
        "broadcast_url": "https://api.blockchair.com/dogecoin/push/transaction",
        "broadcast_urls": ["https://api.blockchair.com/dogecoin/push/transaction"],
        "tx_url": "https://blockchair.com/dogecoin/transaction/",
        "height_url": "https://api.blockchair.com/dogecoin/stats",
        "height_blockchair": True,
    },
}

LOCKTIME_SEQUENCE = 0xFFFFFFFE   # Enable nLockTime
DEFAULT_FEE_RATE  = 5            # sat/vB — conservative default
TAPROOT_SCRIPT_VSIZE = 180       # Estimated vsize for 1-in-1-out Taproot script-path spend
# Rough legacy tx size for 1×P2SH HTLC refund (large redeem + ECDSA sig); sat/byte ≈ sat/vB here.
P2SH_HTLC_REFUND_VSIZE = 360
SIGHASH_ALL_FORKID = 0x41        # Bitcoin Cash / eCash replay-protected ECDSA


# ═══════════════════════════════════════════════════════════════
# Low-level helpers
# ═══════════════════════════════════════════════════════════════

def read_compact(s: BytesIO) -> int:
    b = s.read(1)[0]
    if b < 0xFD: return b
    if b == 0xFD: return struct.unpack('<H', s.read(2))[0]
    if b == 0xFE: return struct.unpack('<I', s.read(4))[0]
    return struct.unpack('<Q', s.read(8))[0]


def write_compact(n: int) -> bytes:
    if n < 0xFD: return struct.pack('<B', n)
    if n <= 0xFFFF: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xFFFFFFFF: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def hash256(data: bytes) -> bytes:
    """Bitcoin double-SHA256 (hash256)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def bch_replay_signature_hash(
    tx: "Tx",
    input_index: int,
    script_code: bytes,
    prevout_value: int,
    n_hash_type: int = 0x00000041,
) -> bytes:
    """
    Bitcoin Cash replay-protected signature digest (BIP143-style with SIGHASH_FORKID).

    Matches bitcoin-cash-node ``SignatureHash`` when the fork-id branch is taken
    (``SCRIPT_ENABLE_SIGHASH_FORKID``), fork id 0 in the sighash word — i.e.
    ``n_hash_type`` is typically ``0x00000041`` (``ALL|FORKID``).

    Used for Taproot-shaped funding inputs (witness stack Schnorr + 0x41 suffix):
    ``script_code`` is the full prevout ``scriptPubKey`` from the PSBT witness_utxo.
    """
    if input_index < 0 or input_index >= len(tx.ins):
        raise ValueError("invalid input index")

    anyone = (n_hash_type & 0x80) != 0
    base = n_hash_type & 0x1F  # ALL / NONE / SINGLE

    if not anyone:
        prevouts_blob = b"".join(i.txid + struct.pack("<I", i.vout) for i in tx.ins)
        hash_prevouts = hash256(prevouts_blob)
    else:
        hash_prevouts = b"\x00" * 32

    if (
        not anyone
        and base != 0x02  # NONE
        and base != 0x03  # SINGLE
    ):
        seq_blob = b"".join(struct.pack("<I", i.sequence) for i in tx.ins)
        hash_sequence = hash256(seq_blob)
    else:
        hash_sequence = b"\x00" * 32

    if base not in (0x02, 0x03):
        outs_blob = b"".join(
            struct.pack("<q", o.value) + write_compact(len(o.spk)) + o.spk for o in tx.outs
        )
        hash_outputs = hash256(outs_blob)
    elif base == 0x03 and input_index < len(tx.outs):
        o = tx.outs[input_index]
        outs_blob = struct.pack("<q", o.value) + write_compact(len(o.spk)) + o.spk
        hash_outputs = hash256(outs_blob)
    else:
        hash_outputs = b"\x00" * 32

    inp = tx.ins[input_index]
    preimage = BytesIO()
    preimage.write(struct.pack("<i", tx.version))
    preimage.write(hash_prevouts)
    preimage.write(hash_sequence)
    preimage.write(inp.txid + struct.pack("<I", inp.vout))
    preimage.write(write_compact(len(script_code)) + script_code)
    preimage.write(struct.pack("<q", prevout_value))
    preimage.write(struct.pack("<I", inp.sequence))
    preimage.write(hash_outputs)
    preimage.write(struct.pack("<I", tx.locktime))
    preimage.write(struct.pack("<I", n_hash_type))
    return hash256(preimage.getvalue())


def tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def tap_leaf_hash(script: bytes, leaf_ver: int = 0xC0) -> bytes:
    buf = struct.pack('B', leaf_ver) + write_compact(len(script)) + script
    return tagged_hash("TapLeaf", buf)


# ═══════════════════════════════════════════════════════════════
# BIP-340 adaptor signatures (Protocol v2) — self-contained secp256k1
# Mirrors backend/services/adaptor_signature.py byte-for-byte so an offline
# claim/recovery here is identical to the in-browser / backend signer. Lets the
# receiver COMPLETE a pre-signature with the adaptor secret t to produce a
# standard Schnorr signature for the single-key claim leaf.
# ═══════════════════════════════════════════════════════════════

_ADP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_ADP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_ADP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_ADP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_ADP_G = (_ADP_GX, _ADP_GY)


def _adp_inv(a, m=_ADP_P):
    return pow(a, m - 2, m)


def _adp_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _ADP_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _adp_inv(2 * y1 % _ADP_P) % _ADP_P
    else:
        lam = (y2 - y1) * _adp_inv((x2 - x1) % _ADP_P) % _ADP_P
    x3 = (lam * lam - x1 - x2) % _ADP_P
    y3 = (lam * (x1 - x3) - y1) % _ADP_P
    return (x3, y3)


def _adp_mul(p, k):
    r = None
    k %= _ADP_N
    while k:
        if k & 1:
            r = _adp_add(r, p)
        p = _adp_add(p, p)
        k >>= 1
    return r


def _adp_even(p):
    return p[1] % 2 == 0


def _adp_lift_x(x):
    if x >= _ADP_P:
        return None
    y_sq = (pow(x, 3, _ADP_P) + 7) % _ADP_P
    y = pow(y_sq, (_ADP_P + 1) // 4, _ADP_P)
    if pow(y, 2, _ADP_P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _ADP_P - y)


def _adp_b32(n):
    return n.to_bytes(32, "big")


def _adp_ser(p):
    return (b"\x02" if p[1] % 2 == 0 else b"\x03") + _adp_b32(p[0])


def _adp_parse(b):
    if len(b) == 33 and b[0] in (0x02, 0x03):
        pt = _adp_lift_x(int.from_bytes(b[1:], "big"))
        if pt is None:
            raise ValueError("invalid compressed point")
        return pt if b[0] == 0x02 else (pt[0], _ADP_P - pt[1])
    if len(b) == 32:
        pt = _adp_lift_x(int.from_bytes(b, "big"))
        if pt is None:
            raise ValueError("invalid x-only point")
        return pt
    raise ValueError("expected 33-byte compressed or 32-byte x-only point")


def _adp_challenge(r_x, p_x, msg):
    return int.from_bytes(
        tagged_hash("BIP0340/challenge", _adp_b32(r_x) + _adp_b32(p_x) + msg), "big"
    ) % _ADP_N


def adaptor_point_from_secret(secret: bytes) -> bytes:
    t = int.from_bytes(secret, "big") % _ADP_N
    if t == 0:
        raise ValueError("adaptor secret is zero")
    return _adp_ser(_adp_mul(_ADP_G, t))


def adaptor_presign(seckey: bytes, msg: bytes, adaptor_point: bytes) -> bytes:
    if len(msg) != 32:
        raise ValueError("msg must be 32 bytes")
    d0 = int.from_bytes(seckey, "big") % _ADP_N
    if d0 == 0:
        raise ValueError("secret key is zero")
    P = _adp_mul(_ADP_G, d0)
    d = d0 if _adp_even(P) else _ADP_N - d0
    T = _adp_parse(adaptor_point)
    for counter in range(256):
        k = int.from_bytes(
            tagged_hash("NexumBit/adaptor/nonce",
                        seckey + msg + _adp_ser(T) + counter.to_bytes(4, "big")), "big"
        ) % _ADP_N
        if k == 0:
            continue
        Rp = _adp_mul(_ADP_G, k)
        R_adapted = _adp_add(Rp, T)
        if R_adapted is None or not _adp_even(R_adapted):
            continue
        e = _adp_challenge(R_adapted[0], P[0], msg)
        s = (k + e * d) % _ADP_N
        return _adp_ser(Rp) + _adp_b32(s)
    raise RuntimeError("failed to find nonce")


def adaptor_complete(presig: bytes, adaptor_secret: bytes) -> bytes:
    if len(presig) != 65:
        raise ValueError("presig must be 65 bytes")
    Rp = _adp_parse(presig[:33])
    s_prime = int.from_bytes(presig[33:65], "big")
    t = int.from_bytes(adaptor_secret, "big") % _ADP_N
    if t == 0:
        raise ValueError("adaptor secret is zero")
    R_adapted = _adp_add(Rp, _adp_mul(_ADP_G, t))
    if R_adapted is None or not _adp_even(R_adapted):
        raise ValueError("adapted nonce has odd Y — presignature malformed")
    s = (s_prime + t) % _ADP_N
    return _adp_b32(R_adapted[0]) + _adp_b32(s)


def adaptor_extract(presig: bytes, full_sig: bytes, adaptor_point: bytes):
    if len(presig) != 65 or len(full_sig) != 64:
        return None
    t = (int.from_bytes(full_sig[32:64], "big") - int.from_bytes(presig[33:65], "big")) % _ADP_N
    if t == 0:
        return None
    if _adp_mul(_ADP_G, t) != _adp_parse(adaptor_point):
        return None
    return _adp_b32(t)


def tap_branch_hash(a: bytes, b: bytes) -> bytes:
    if a > b: a, b = b, a
    return tagged_hash("TapBranch", a + b)


def tap_tweak(internal_key: bytes, merkle_root: bytes) -> bytes:
    return tagged_hash("TapTweak", internal_key + merkle_root)


def address_to_scriptpubkey(addr: str) -> bytes:
    """
    Convert address to raw scriptpubkey bytes.
    Supports: bc1, tb1 (embit); ecash: / bitcoincash: CashAddr P2TR (bitcash);
    dgb1, grs1, ltc1, bel1, rvn1 (segwit_addr for Taproot).
    """
    addr = "".join((addr or "").split())
    addr_lower = addr.lower()
    # eCash CashAddr (ecash:… Taproot) — before BCH so explicit ecash: is unambiguous
    if HAS_BCH_CASHADDR and _looks_like_ecash_cashaddr(addr_lower):
        try:
            return bch_cashaddr_to_scriptpubkey(addr)
        except Exception as e:
            raise ValueError(f"Invalid or undecodable eCash CashAddr: {e}") from e
    # Bitcoin Cash CashAddr (P2TR q/p… or bitcoincash:…)
    if HAS_BCH_CASHADDR and _looks_like_bch_cashaddr(addr_lower):
        try:
            return bch_cashaddr_to_scriptpubkey(addr)
        except Exception as e:
            raise ValueError(f"Invalid or undecodable CashAddr: {e}") from e
    # Alt-chain bech32m (dgb1, grs1, ltc1, bel1, rvn1, doge1)
    if HAS_SEGWIT_ADDR:
        for hrp in ("dgb", "grs", "ltc", "bel", "rvn", "doge"):
            if addr_lower.startswith(hrp + "1"):
                try:
                    ver, prog = segwit_decode(hrp, addr)
                    if ver == 1 and prog and len(prog) == 32:  # Taproot
                        return bytes([0x51, 0x20]) + bytes(prog)
                    if ver == 0 and prog and len(prog) in (20, 32):  # v0 segwit
                        return bytes([0x00, len(prog)]) + bytes(prog)
                except Exception:
                    pass
    # Bitcoin/Fractal (bc1, tb1) — use embit
    try:
        return embit_script.address_to_scriptpubkey(addr).data
    except Exception:
        if addr_lower.startswith(("dgb1", "grs1", "ltc1", "bel1", "rvn1", "doge1")):
            raise ValueError(
                f"DGB/GRS/LTC/BEL/RVN/DOGE address detected but segwit_addr module not found. "
                f"Ensure segwit_addr.py is in the same directory as signer.py."
            ) from None
        raise


# ═══════════════════════════════════════════════════════════════
# Key handling
# ═══════════════════════════════════════════════════════════════

def decode_wif(wif: str) -> Tuple[bytes, bool]:
    """
    Decode WIF to (32-byte secret, compressed).
    Accepts any standard version byte after base58check (0x80 BTC/FB/DGB/GRS/BCH/…,
    0xEF testnet, 0xB0 Litecoin, 0x9E Doge/BEL-style, 0x99 Bellscoin wallets, etc.).
    """
    raw = base58.b58decode_check(wif)
    if len(raw) == 34 and raw[-1] == 0x01:
        return raw[1:33], True
    if len(raw) == 33:
        return raw[1:33], False
    raise ValueError(f"Invalid WIF (version=0x{raw[0]:02x}, len={len(raw)})")


def parse_private_key(key_input: str) -> Tuple[bytes, bytes]:
    """
    Parse private key from WIF or raw hex.
    Returns (32-byte key, 32-byte x-only pubkey).
    """
    key_input = key_input.strip()
    hex_clean = re.sub(r"[^0-9a-fA-F]", "", key_input)

    # Try raw hex (64 hex chars = 32 bytes); allow spaces in pasted hex
    if len(hex_clean) == 64:
        try:
            key_bytes = bytes.fromhex(hex_clean)
            xonly = PrivateKey(key_bytes).get_public_key().xonly()
            return key_bytes, xonly
        except Exception:
            pass

    # Try WIF
    if HAS_BASE58:
        try:
            key_bytes, _ = decode_wif(key_input)
            xonly = PrivateKey(key_bytes).get_public_key().xonly()
            return key_bytes, xonly
        except Exception:
            pass

    raise ValueError("Invalid key. Provide a standard base58-check WIF or 64-char raw hex.")


def derive_btc_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From BTC private key (WIF or 64-char hex), derive Taproot address and pubkeys.

    Returns:
        (address bc1p..., xonly 64 hex, compressed 66 hex)
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for BTC derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("bc", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode BTC address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_fb_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From Fractal Bitcoin private key (WIF or 64-char hex), derive Taproot address and pubkeys.
    FB shares the bc1p HRP with mainnet Bitcoin.

    Returns:
        (address bc1p..., xonly 64 hex, compressed 66 hex)
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for FB derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("bc", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode FB address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_dgb_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From DGB private key (WIF or 64-char hex), derive the Taproot address and pubkey.

    Returns:
        (address, pubkey_xonly_hex, pubkey_compressed_hex)
        - address: dgb1p... Taproot address
        - pubkey_xonly_hex: 64-char hex (x-only, for DLC user_refund_xonly etc.)
        - pubkey_compressed_hex: 66-char hex (02/03 + x-only, for compatibility)
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for DGB derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("dgb", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode DGB address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_grs_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From GRS private key (WIF or 64-char hex), derive the Taproot address and pubkey.

    Returns:
        (address, pubkey_xonly_hex, pubkey_compressed_hex)
        - address: grs1p... Taproot address
        - pubkey_xonly_hex: 64-char hex
        - pubkey_compressed_hex: 66-char hex
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for GRS derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("grs", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode GRS address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_ltc_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From LTC private key (WIF or 64-char hex), derive Taproot address and pubkeys.

    Returns:
        (address ltc1p..., xonly 64 hex, compressed 66 hex)
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for LTC derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("ltc", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode LTC address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_bel_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From Bellscoin private key (WIF or 64-char hex), derive Taproot address and pubkeys.

    Returns:
        (address bel1p..., xonly 64 hex, compressed 66 hex)
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for BEL derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("bel", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode BEL address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_bch_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From BCH private key (WIF or 64-char hex), derive Taproot CashAddr and pubkeys.

    Returns:
        (address bitcoincash:..., xonly 64 hex, compressed 66 hex)
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for BCH derivation")
    if not HAS_BCH_CASHADDR:
        raise RuntimeError("bitcash required for BCH: pip install bitcash")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    address = bch_taproot_output_pubkey_to_cashaddr(output_xonly)
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_xec_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From eCash private key (WIF or 64-char hex), derive Taproot CashAddr (ecash:…) and pubkeys.
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for XEC derivation")
    if not HAS_BCH_CASHADDR:
        raise RuntimeError("bitcash required for XEC: pip install bitcash")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    address = bch_taproot_output_pubkey_to_cashaddr(output_xonly, prefix="ecash")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_rvn_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From Ravencoin private key (WIF or 64-char hex), derive Taproot address (rvn1p…) and pubkeys.
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for RVN derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("rvn", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode RVN address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


def derive_doge_from_private_key(key_input: str) -> Tuple[str, str, str]:
    """
    From Dogecoin private key (WIF or 64-char hex), derive Taproot address (doge1p…) and pubkeys.
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for DOGE derivation")
    key_bytes, xonly = parse_private_key(key_input)
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    output_key = pub.taproot_tweak(b"")
    output_xonly = output_key.xonly()
    try:
        from embit import bech32
        address = bech32.encode("doge", 1, output_xonly)
    except ImportError:
        address = None
    if address is None:
        raise ValueError("Could not encode DOGE address (embit.bech32 required)")
    xonly_hex = xonly.hex()
    compressed_hex = pub.sec().hex()
    return address, xonly_hex, compressed_hex


# ═══════════════════════════════════════════════════════════════
# Minimal transaction types
# ═══════════════════════════════════════════════════════════════

class TxIn:
    def __init__(self, txid: bytes, vout: int, script_sig: bytes = b'', sequence: int = 0xFFFFFFFF):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence


class TxOut:
    def __init__(self, value: int, spk: bytes):
        self.value = value
        self.spk = spk


class Tx:
    def __init__(self):
        self.version = 2
        self.ins: List[TxIn] = []
        self.outs: List[TxOut] = []
        self.locktime = 0

    @classmethod
    def parse(cls, raw: bytes) -> 'Tx':
        tx, s = cls(), BytesIO(raw)
        tx.version = struct.unpack('<i', s.read(4))[0]
        p = s.tell(); m = s.read(1)[0]
        if m == 0: s.read(1)  # skip segwit flag
        else: s.seek(p)
        for _ in range(read_compact(s)):
            txid = s.read(32); vo = struct.unpack('<I', s.read(4))[0]
            sl = read_compact(s); ss = s.read(sl); sq = struct.unpack('<I', s.read(4))[0]
            tx.ins.append(TxIn(txid, vo, ss, sq))
        for _ in range(read_compact(s)):
            v = struct.unpack('<q', s.read(8))[0]; sl = read_compact(s); sp = s.read(sl)
            tx.outs.append(TxOut(v, sp))
        tx.locktime = struct.unpack('<I', s.read(4))[0]
        return tx

    def raw(self, witnesses: Optional[Dict] = None) -> bytes:
        o = BytesIO()
        o.write(struct.pack('<i', self.version))
        if witnesses: o.write(b'\x00\x01')
        o.write(write_compact(len(self.ins)))
        for i in self.ins:
            o.write(i.txid + struct.pack('<I', i.vout))
            o.write(write_compact(len(i.script_sig)) + i.script_sig)
            o.write(struct.pack('<I', i.sequence))
        o.write(write_compact(len(self.outs)))
        for t in self.outs:
            o.write(struct.pack('<q', t.value) + write_compact(len(t.spk)) + t.spk)
        if witnesses:
            for idx in range(len(self.ins)):
                wit = witnesses.get(idx, [])
                o.write(write_compact(len(wit)))
                for item in wit: o.write(write_compact(len(item)) + item)
        o.write(struct.pack('<I', self.locktime))
        return o.getvalue()


# ═══════════════════════════════════════════════════════════════
# P2SH HTLC (hybrid DLC routes — BCH / XEC / RVN / ZEC)
# ═══════════════════════════════════════════════════════════════

def _push_bytes_htlc(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([0x4C, n]) + data
    if n <= 0xFFFF:
        return bytes([0x4D]) + n.to_bytes(2, "little") + data
    return bytes([0x4E]) + n.to_bytes(4, "little") + data


def _serialize_scriptcode(redeem_script: bytes) -> bytes:
    """BIP143 scriptCode: compact length + redeem script (P2SH spends use redeemScript as scriptCode)."""
    return write_compact(len(redeem_script)) + redeem_script


def _bch_replay_protected_sighash(
    tx: Tx,
    input_index: int,
    redeem_script: bytes,
    value: int,
    fork_id: int = 0,
) -> bytes:
    """Digest for BCH/XEC replay-protected ECDSA (ALL|FORKID)."""
    n_hash_type = SIGHASH_ALL_FORKID

    def _hp() -> bytes:
        buf = b"".join(tx.ins[i].txid + struct.pack("<I", tx.ins[i].vout) for i in range(len(tx.ins)))
        return hash256(buf)

    def _hs() -> bytes:
        buf = b"".join(struct.pack("<I", tx.ins[i].sequence) for i in range(len(tx.ins)))
        return hash256(buf)

    def _ho() -> bytes:
        buf = b"".join(
            struct.pack("<q", o.value) + write_compact(len(o.spk)) + o.spk for o in tx.outs
        )
        return hash256(buf)

    inp = tx.ins[input_index]
    outpoint = inp.txid + struct.pack("<I", inp.vout)
    script_code = _serialize_scriptcode(redeem_script)
    preimage = (
        struct.pack("<i", tx.version)
        + _hp()
        + _hs()
        + outpoint
        + script_code
        + struct.pack("<q", value)
        + struct.pack("<I", inp.sequence)
        + _ho()
        + struct.pack("<I", tx.locktime)
        + struct.pack("<I", ((fork_id << 8) | n_hash_type))
    )
    return hash256(preimage)


def _legacy_embit_sighash(tx: Tx, input_index: int, redeem_script: bytes) -> bytes:
    """Bitcoin-like legacy sighash (Ravencoin / Zcash transparent P2SH)."""
    vin = []
    for i in tx.ins:
        tid_be = bytes(reversed(i.txid))
        vin.append(EmbitTxIn(tid_be, i.vout, EmbitScript(i.script_sig), i.sequence))
    vout = [EmbitTxOut(o.value, EmbitScript(o.spk)) for o in tx.outs]
    etx = EmbitTx(version=tx.version, vin=vin, vout=vout, locktime=tx.locktime)
    return etx.sighash_legacy(input_index, EmbitScript(redeem_script), EmbitSIGHASH.ALL)


def _extract_htlc_sender_pubkey_compressed(redeem: bytes) -> bytes:
    """Last branch: CLTV DROP <33-byte pk> OP_CHECKSIG OP_ENDIF."""
    if len(redeem) < 37 or redeem[-2] != 0xAC or redeem[-1] != 0x68:
        raise ValueError("Unexpected HTLC redeem script tail (expected … OP_CHECKSIG OP_ENDIF)")
    if redeem[-36] != 0x21:
        raise ValueError("Expected 0x21 push before sender OP_CHECKSIG")
    pk = redeem[-35:-2]
    if len(pk) != 33 or pk[0] not in (0x02, 0x03):
        raise ValueError("Sender pubkey must be 33-byte compressed secp256k1")
    return pk


def _p2pkh_scriptpubkey_compressed(pub33: bytes) -> bytes:
    """Classic P2PKH locking script (standard on BCH/XEC mempools)."""
    from embit.hashes import hash160

    h20 = hash160(pub33)
    return bytes([0x76, 0xA9, 0x14]) + h20 + bytes([0x88, 0xAC])


def _p2sh_htlc_refund_output_scriptpubkey(sender_spk: bytes, redeem: bytes, net: str) -> Tuple[bytes, bool]:
    """
    BCH/eCash standard relay only allows a small set of output types (P2PKH, P2SH, …).
    Taproot-shaped CashAddr decodes to OP_1 <32-byte> (same bytes as BTC P2TR), which is
    **non-standard** for typical BCH mempool relay — Blockchair / nodes reject it (scriptpubkey).
    Use P2PKH built from the HTLC sender pubkey (same key as the p… Taproot CashAddr).
    """
    if net not in ("bch", "xec"):
        return sender_spk, False
    if len(sender_spk) == 34 and sender_spk[0] == 0x51 and sender_spk[1] == 0x20:
        pk = _extract_htlc_sender_pubkey_compressed(redeem)
        return _p2pkh_scriptpubkey_compressed(pk), True
    return sender_spk, False


def _p2sh_htlc_refund_network(kit: Dict) -> str:
    desc = (kit.get("dlc_a") or {}).get("descriptor") or {}
    t = str(desc.get("type", "")).lower()
    ch = str(desc.get("chain") or kit.get("from_chain") or "BCH").upper()
    if t == "bch_htlc":
        ch = "BCH"
    m = {"BCH": "bch", "XEC": "xec", "RVN": "rvn", "ZEC": "zec"}
    net = m.get(ch)
    if not net:
        raise ValueError(f"Unsupported P2SH HTLC chain {ch!r} (expected BCH/XEC/RVN/ZEC)")
    if net not in NETWORKS:
        raise ValueError(f"Network {net!r} not configured in signer NETWORKS")
    return net


def _is_p2sh_htlc_dlc_a(kit: Dict) -> bool:
    desc = (kit.get("dlc_a") or {}).get("descriptor") or {}
    return str(desc.get("type", "")).lower() in ("p2sh_htlc", "bch_htlc")


def build_p2sh_htlc_refund_unsigned(kit: Dict, fee_rate: int = DEFAULT_FEE_RATE) -> Tuple[Tx, bytes, int, int, int, str, bool]:
    """
    Build unsigned legacy refund tx for P2SH HTLC DLC A.
    Returns (tx, redeem_script, dlc_value_sats, fee, output_value, network_key, bch_p2pkh_output).
    ``bch_p2pkh_output`` is True when the refund was directed to P2PKH for BCH/eCash relay (see _p2sh_htlc_refund_output_scriptpubkey).
    """
    dlc = kit.get("dlc_a") or {}
    desc = dlc.get("descriptor") or {}
    redeem = _hex_bytes(desc.get("redeem_script_hex"), "redeem_script_hex")
    if not redeem:
        raise ValueError("redeem_script_hex missing from P2SH HTLC descriptor")

    cltv = int(desc.get("cltv_height") or kit.get("timeout_a") or 0)
    if cltv <= 0:
        raise ValueError("cltv_height / timeout_a missing for HTLC refund")

    dlc_value = int(dlc.get("value") or kit.get("from_amount") or 0)
    if dlc_value <= 0:
        raise ValueError("DLC A value unknown")

    vout = int(dlc.get("vout") or 0)
    txid_raw = dlc.get("txid")
    if not txid_raw:
        raise ValueError("DLC A txid missing")
    prev_txid = _hex_bytes(txid_raw, "dlc_a.txid")[::-1]

    sender_addr = kit.get("user_address_from")
    if not sender_addr:
        raise ValueError("user_address_from missing")
    sender_spk = address_to_scriptpubkey(sender_addr)

    fee = max(1, int(fee_rate)) * P2SH_HTLC_REFUND_VSIZE
    output_value = dlc_value - fee
    if output_value < 546:
        raise ValueError(
            f"DLC value ({dlc_value} sats) too small for fee (~{fee} sats est.) — increase amount or lower fee_rate"
        )

    net = _p2sh_htlc_refund_network(kit)
    sender_spk, bch_p2pkh_output = _p2sh_htlc_refund_output_scriptpubkey(sender_spk, redeem, net)

    tx = Tx()
    tx.version = 2
    tx.locktime = cltv
    tx.ins = [TxIn(prev_txid, vout, b"", LOCKTIME_SEQUENCE)]
    tx.outs = [TxOut(output_value, sender_spk)]

    return tx, redeem, dlc_value, fee, output_value, net, bch_p2pkh_output


def sign_p2sh_htlc_refund_tx(tx: Tx, redeem: bytes, dlc_value: int, net: str, key_bytes: bytes) -> str:
    """ECDSA-sign input 0 and return complete raw tx hex (legacy, no witness)."""
    use_bch_sighash = net in ("bch", "xec")
    pk_pub = PrivateKey(key_bytes).get_public_key().sec()
    sender_expect = _extract_htlc_sender_pubkey_compressed(redeem)
    if pk_pub != sender_expect:
        raise ValueError(
            f"Key does not match HTLC sender pubkey in redeem script.\n"
            f"    Expected (hex): {sender_expect.hex()}\n"
            f"    Your key:       {pk_pub.hex()}"
        )

    if use_bch_sighash:
        msg = _bch_replay_protected_sighash(tx, 0, redeem, dlc_value)
        sighash_byte = SIGHASH_ALL_FORKID
    else:
        msg = _legacy_embit_sighash(tx, 0, redeem)
        sighash_byte = 0x01

    sig = PrivateKey(key_bytes).sign(msg)
    der = sig.serialize() if hasattr(sig, "serialize") else bytes(sig)
    sig_and_type = der + bytes([sighash_byte])
    script_sig = _push_bytes_htlc(sig_and_type) + b"\x00" + _push_bytes_htlc(redeem)
    tx.ins[0].script_sig = script_sig
    return tx.raw().hex()


# ═══════════════════════════════════════════════════════════════
# PSBT parser
# ═══════════════════════════════════════════════════════════════

class PInput:
    __slots__ = ('utxo_value', 'utxo_spk', 'tap_internal_key', 'tap_merkle_root',
                 'leaves', 'tap_script_sigs')
    def __init__(self):
        self.utxo_value = 0
        self.utxo_spk = b''
        self.tap_internal_key = None
        self.tap_merkle_root = None
        self.leaves = []           # [(control_block, script, leaf_ver)]
        self.tap_script_sigs = {}  # {(xonly_32, leaf_hash_32): sig_bytes}


def _parse_psbt_minimal(data: bytes) -> Tuple[Tx, List[PInput]]:
    """Parse PSBT v0 with the built-in reader (fast path)."""
    s = BytesIO(data)
    if s.read(5) != b'psbt\xff':
        raise ValueError("Bad PSBT magic")
    tx = None
    # Global map
    while True:
        kl = read_compact(s)
        if kl == 0:
            break
        k = s.read(kl)
        vl = read_compact(s)
        v = s.read(vl)
        if k[0] == 0x00:
            tx = Tx.parse(v)
    if not tx:
        raise ValueError("Missing unsigned tx in PSBT")
    # Per-input maps
    inputs = []
    for _ in range(len(tx.ins)):
        p = PInput()
        while True:
            kl = read_compact(s)
            if kl == 0:
                break
            k = s.read(kl)
            vl = read_compact(s)
            v = s.read(vl)
            if k[0] == 0x01:       # WITNESS_UTXO
                vs = BytesIO(v)
                p.utxo_value = struct.unpack('<q', vs.read(8))[0]
                p.utxo_spk = vs.read(read_compact(vs))
            elif k[0] == 0x15:     # TAP_LEAF_SCRIPT
                cb = k[1:]
                leaf_ver = cb[0] & 0xFE
                script = v[:-1] if (v and v[-1] == leaf_ver) else v
                p.leaves.append((cb, script, leaf_ver))
            elif k[0] == 0x14:     # TAP_SCRIPT_SIG
                key_data = k[1:]
                if len(key_data) == 64:
                    p.tap_script_sigs[(key_data[:32], key_data[32:])] = v
            elif k[0] == 0x17:     # TAP_INTERNAL_KEY
                p.tap_internal_key = v
            elif k[0] == 0x18:     # TAP_MERKLE_ROOT
                p.tap_merkle_root = v
        inputs.append(p)
    # Skip output maps
    for _ in range(len(tx.outs)):
        while True:
            kl = read_compact(s)
            if kl == 0:
                break
            s.read(kl)
            vl = read_compact(s)
            s.read(vl)
    return tx, inputs


def _parse_psbt_via_embit(data: bytes) -> Tuple[Tx, List[PInput]]:
    """
    Fallback: embit's PSBT parser (handles more variants / edge cases than _parse_psbt_minimal).
    """
    if not HAS_EMBIT:
        raise ValueError("embit required for PSBT fallback parse")
    from embit.psbt import PSBT

    psbt = PSBT.parse(data)
    raw_tx = psbt.tx.serialize()
    tx = Tx.parse(raw_tx)
    inputs: List[PInput] = []
    for inp in psbt.inputs:
        p = PInput()
        if inp.witness_utxo is not None:
            p.utxo_value = inp.witness_utxo.value
            p.utxo_spk = inp.witness_utxo.script_pubkey.data
        elif inp.non_witness_utxo is not None and inp.vout is not None:
            prev_out = inp.non_witness_utxo.vout[inp.vout]
            p.utxo_value = prev_out.value
            p.utxo_spk = prev_out.script_pubkey.data
        if inp.taproot_internal_key is not None:
            p.tap_internal_key = inp.taproot_internal_key.xonly()
        if inp.taproot_merkle_root is not None:
            p.tap_merkle_root = inp.taproot_merkle_root
        for control_block, leaf_val in (inp.taproot_scripts or {}).items():
            if not leaf_val:
                continue
            leaf_ver = leaf_val[-1] & 0xFE
            script = leaf_val[:-1] if len(leaf_val) > 1 else leaf_val
            p.leaves.append((control_block, script, leaf_ver))
        for (pub, leaf_h), sig in (inp.taproot_sigs or {}).items():
            p.tap_script_sigs[(pub.xonly(), leaf_h)] = (
                sig if isinstance(sig, bytes) else sig.serialize()
                if hasattr(sig, "serialize")
                else bytes(sig)
            )
        inputs.append(p)
    return tx, inputs


def parse_psbt(data: bytes) -> Tuple[Tx, List[PInput]]:
    """Parse PSBT v0. Returns (unsigned_tx, list_of_inputs). Uses embit if the minimal parser fails."""
    try:
        return _parse_psbt_minimal(data)
    except Exception as e_min:
        if not HAS_EMBIT:
            raise
        try:
            return _parse_psbt_via_embit(data)
        except Exception as e_emb:
            raise ValueError(
                f"PSBT parse failed (minimal: {e_min!s}; embit: {e_emb!s})"
            ) from e_emb


# ═══════════════════════════════════════════════════════════════
# PSBT serializer
# ═══════════════════════════════════════════════════════════════

def _psbt_kv(key: bytes, value: bytes) -> bytes:
    """Encode one PSBT key-value pair."""
    return write_compact(len(key)) + key + write_compact(len(value)) + value


def build_psbt_bytes(tx: Tx, psbt_inputs: List[Dict], num_outputs: int) -> bytes:
    """
    Serialize a PSBT v0 from components.

    psbt_inputs:  list of dicts with keys:
        witness_utxo:     (value_int, scriptpubkey_bytes)
        tap_internal_key: 32-byte x-only pubkey
        tap_merkle_root:  32-byte hash
        tap_leaf_scripts: [(control_block_bytes, script_bytes, leaf_version)]
        tap_script_sigs:  {(xonly_32, leaf_hash_32): signature_bytes}
    """
    o = BytesIO()
    o.write(b'psbt\xff')

    # ── Global: unsigned tx ──
    o.write(_psbt_kv(b'\x00', tx.raw()))
    o.write(b'\x00')  # end global

    # ── Per-input maps ──
    for inp in psbt_inputs:
        # 0x01 WITNESS_UTXO
        if 'witness_utxo' in inp:
            val, spk = inp['witness_utxo']
            o.write(_psbt_kv(b'\x01',
                struct.pack('<q', val) + write_compact(len(spk)) + spk))

        # 0x14 TAP_SCRIPT_SIG  (key = 0x14 || xonly || leaf_hash)
        for (xonly, lh), sig in inp.get('tap_script_sigs', {}).items():
            o.write(_psbt_kv(b'\x14' + xonly + lh, sig))

        # 0x15 TAP_LEAF_SCRIPT (key = 0x15 || control_block, val = script || leaf_ver)
        for cb, scr, lv in inp.get('tap_leaf_scripts', []):
            o.write(_psbt_kv(b'\x15' + cb, scr + bytes([lv])))

        # 0x17 TAP_INTERNAL_KEY
        if inp.get('tap_internal_key'):
            o.write(_psbt_kv(b'\x17', inp['tap_internal_key']))

        # 0x18 TAP_MERKLE_ROOT
        if inp.get('tap_merkle_root'):
            o.write(_psbt_kv(b'\x18', inp['tap_merkle_root']))

        o.write(b'\x00')  # end input

    # ── Per-output maps (empty) ──
    for _ in range(num_outputs):
        o.write(b'\x00')

    return o.getvalue()


# ═══════════════════════════════════════════════════════════════
# Leaf verification
# ═══════════════════════════════════════════════════════════════

def verify_leaf(pinp: PInput, cb: bytes, script: bytes, leaf_ver: int) -> bool:
    """
    Verify a Taproot leaf + control-block commits to the UTXO output key.
    Falls back to True if EC math libraries aren't available
    (the network will reject invalid spends regardless).
    """
    if len(pinp.utxo_spk) != 34 or pinp.utxo_spk[0] != 0x51:
        return False
    output_key = pinp.utxo_spk[2:]
    internal_key = cb[1:33]
    path_hashes = [cb[33 + i*32 : 33 + (i+1)*32] for i in range((len(cb) - 33) // 32)]

    lh = tap_leaf_hash(script, leaf_ver)
    merkle_root = lh
    for ph in path_hashes:
        merkle_root = tap_branch_hash(merkle_root, ph)

    tweak_hash = tap_tweak(internal_key, merkle_root)

    # Try coincurve for full EC point verification
    try:
        import coincurve
        P = coincurve.PublicKey(b'\x02' + internal_key)
        Q = P.add(tweak_hash)
        return Q.format(compressed=True)[1:] == output_key
    except (ImportError, Exception):
        pass

    # Cannot do EC math locally — trust network verification
    return True


# ═══════════════════════════════════════════════════════════════
# Script analysis
# ═══════════════════════════════════════════════════════════════

def analyze_script(script: bytes) -> Dict[str, Any]:
    """Determine whether a tapscript is a claim or refund path and extract keys."""
    # FAL hashlock: OP_SHA256 <32 h> OP_EQUALVERIFY <32 lender> OP_CHECKSIG
    #  A8 20...32 88 20...32 AC  (69 bytes)
    if (len(script) == 69 and script[0] == 0xA8 and script[1] == 0x20
            and script[34] == 0x88 and script[35] == 0x20 and script[68] == 0xAC):
        return {
            'type': 'lender_claim_hashlock',
            'lender_pubkey': script[36:68],
            'sigs_needed': 1,
            'description': 'FAL lender claim: SHA256 preimage + lender key',
        }

    # v2 claim: <32> OP_CHECKSIG  (single receiver key — adaptor completed off-chain)
    if len(script) == 34 and script[0] == 0x20 and script[33] == 0xAC:
        return {
            'type': 'v2_claim',
            'receiver_pubkey': script[1:33],
            'sigs_needed': 1,
            'description': 'v2 claim (single-key): completed BIP-340 adaptor signature',
        }

    # v1 success: <32> OP_CHECKSIGVERIFY <32> OP_CHECKSIG
    #          20 <adaptor|oracle:32> AD 20 <receiver|lender:32> AC
    if (len(script) == 68 and script[0] == 0x20 and script[33] == 0xAD
            and script[34] == 0x20 and script[67] == 0xAC):
        return {
            'type': 'claim',
            'adaptor_point': script[1:33],
            'receiver_pubkey': script[35:67],
            'sigs_needed': 2,
            'description': 'Claim (dual-sig path): co-sign + receiver key (swap adaptor or oracle)',
        }

    # Refund: <locktime_push> OP_CLTV OP_DROP <32> OP_CHECKSIG
    #         ... B1 75 20 <sender:32> AC
    for i in range(len(script)):
        if (i + 36 <= len(script) and script[i] == 0xB1 and script[i+1] == 0x75
                and script[i+2] == 0x20 and script[i+35] == 0xAC):
            sender_key = script[i+3:i+35]
            lt_data = script[:i]
            locktime = 0
            if lt_data and lt_data[0] <= 0x08:
                push_len = lt_data[0]
                lt_bytes = lt_data[1:1+push_len]
                locktime = int.from_bytes(lt_bytes, 'little')
            return {
                'type': 'refund',
                'sender_pubkey': sender_key,
                'locktime': locktime,
                'sigs_needed': 1,
                'description': f'Refund path: sender key (locktime={locktime:,})',
            }

    return {'type': 'unknown', 'sigs_needed': 0, 'description': 'Unknown script type'}


# ═══════════════════════════════════════════════════════════════
# Taproot script-path sighash (BIP-341)
# ═══════════════════════════════════════════════════════════════

def sighash_script_path(tx: Tx, idx: int, inputs: List[PInput],
                        leaf_hash: bytes, sighash_type: int = 0x00) -> bytes:
    """Compute BIP-341 Taproot script-path sighash."""
    s = BytesIO()
    s.write(b'\x00')                              # epoch
    s.write(struct.pack('<B', sighash_type))       # hash_type
    s.write(struct.pack('<i', tx.version))          # nVersion
    s.write(struct.pack('<I', tx.locktime))         # nLockTime

    anyonecanpay = (sighash_type & 0x80) != 0
    ht_base = sighash_type & 0x03

    if not anyonecanpay:
        h = hashlib.sha256()
        for inp in tx.ins: h.update(inp.txid + struct.pack('<I', inp.vout))
        s.write(h.digest())                        # sha_prevouts
        h = hashlib.sha256()
        for p in inputs: h.update(struct.pack('<q', p.utxo_value))
        s.write(h.digest())                        # sha_amounts
        h = hashlib.sha256()
        for p in inputs: h.update(write_compact(len(p.utxo_spk)) + p.utxo_spk)
        s.write(h.digest())                        # sha_scriptpubkeys
        h = hashlib.sha256()
        for inp in tx.ins: h.update(struct.pack('<I', inp.sequence))
        s.write(h.digest())                        # sha_sequences

    if ht_base < 2:
        h = hashlib.sha256()
        for o in tx.outs: h.update(struct.pack('<q', o.value) + write_compact(len(o.spk)) + o.spk)
        s.write(h.digest())                        # sha_outputs

    s.write(struct.pack('<B', 2))                  # spend_type = ext_flag=1, no annex

    if anyonecanpay:
        inp = tx.ins[idx]; p = inputs[idx]
        s.write(inp.txid + struct.pack('<I', inp.vout))
        s.write(struct.pack('<q', p.utxo_value))
        s.write(write_compact(len(p.utxo_spk)) + p.utxo_spk)
        s.write(struct.pack('<I', inp.sequence))
    else:
        s.write(struct.pack('<I', idx))

    # Script-path extension
    s.write(leaf_hash)
    s.write(b'\x00')                               # key_version
    s.write(struct.pack('<i', -1))                 # codesep_pos = 0xFFFFFFFF

    return tagged_hash("TapSighash", s.getvalue())


# ═══════════════════════════════════════════════════════════════
# Signing
# ═══════════════════════════════════════════════════════════════

def schnorr_sign(privkey_bytes: bytes, msg: bytes) -> bytes:
    pk = PrivateKey(privkey_bytes)
    sig = pk.schnorr_sign(msg)
    return sig.serialize() if hasattr(sig, 'serialize') else bytes(sig)


def bip322_hash(message: str) -> bytes:
    """BIP-322 signed message hash (tagged SHA256)."""
    tag = b"BIP0322-signed-message"
    tag_hash = hashlib.sha256(tag).digest()
    msg_bytes = message.encode("utf-8")
    return hashlib.sha256(tag_hash + tag_hash + msg_bytes).digest()


def _p2tr_output_xonly_from_witness_utxo_spk(spk: bytes) -> Optional[bytes]:
    """
    Extract 32-byte Taproot output key (x-only) from witness_utxo scriptPubKey.

    - Bitcoin-style v1 P2TR: ``51 20`` + 32 bytes (34 bytes total).
    - Bitcoin Cash native P2TR locking: ``aa 20`` + 32 bytes + ``87`` (35 bytes; on-chain ``aa20…87`` form).
    """
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return spk[2:34]
    if len(spk) == 35 and spk[0] == 0xAA and spk[1] == 0x20 and spk[34] == 0x87:
        return spk[2:34]
    return None


def _p2wpkh_hash_from_witness_utxo_spk(spk: bytes) -> Optional[bytes]:
    """Extract HASH160(pubkey) from native SegWit v0 P2WPKH witness_utxo."""
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        return spk[2:22]
    return None


def _p2pkh_scriptcode(pubkey_hash: bytes) -> bytes:
    """BIP-143 scriptCode for P2WPKH: DUP HASH160 <20> EQUALVERIFY CHECKSIG."""
    if len(pubkey_hash) != 20:
        raise ValueError("pubkey hash must be 20 bytes")
    return bytes.fromhex("76a914") + pubkey_hash + bytes.fromhex("88ac")


def sign_bip322_message(message: str, key_bytes: bytes, scriptpubkey: bytes) -> str:
    """
    Sign a BIP-322 simple message for Taproot (P2TR) address.
    Returns base64-encoded signature suitable for verify_bip322.
    """
    if not HAS_EMBIT:
        raise RuntimeError("embit required for BIP-322 signing")
    if len(scriptpubkey) != 34 or scriptpubkey[0] != 0x51 or scriptpubkey[1] != 0x20:
        raise ValueError("BIP-322 sign supports Taproot (P2TR) only")
    output_xonly = scriptpubkey[2:]
    pk = PrivateKey(key_bytes)
    output_key = pk.get_public_key().taproot_tweak(b"")
    if output_key.xonly() != output_xonly:
        raise ValueError("Key does not match address")
    pk_tweaked = pk.taproot_tweak(b"")
    msg_hash = bip322_hash(message)
    # to_spend: version 0, input with scriptSig 0x0020||msg_hash, output to scriptpubkey
    prevout = bytes(32)
    prevout_idx = 0xFFFFFFFF
    script_sig = bytes([0x00, 0x20]) + msg_hash
    tx_to_spend = Tx()
    tx_to_spend.version = 0
    tx_to_spend.ins = [TxIn(prevout, prevout_idx, script_sig, 0)]
    tx_to_spend.outs = [TxOut(0, scriptpubkey)]
    tx_to_spend.locktime = 0
    tx_to_spend_raw = tx_to_spend.raw()
    txid_spend = hashlib.sha256(hashlib.sha256(tx_to_spend_raw).digest()).digest()[::-1]
    # to_sign: input from txid_spend:0, witness_utxo = scriptpubkey
    from embit.script import Script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    from embit.transaction import SIGHASH
    spk_script = Script(scriptpubkey)
    op_return_script = Script(bytes.fromhex("6a"))
    inp = TransactionInput(txid_spend, 0, embit_script.Script(b""), 0)
    out = TransactionOutput(0, op_return_script)
    embit_tx = Transaction(version=0, vin=[inp], vout=[out], locktime=0)
    sighash = embit_tx.sighash_taproot(0, [spk_script], [0], sighash=SIGHASH.DEFAULT)
    sig = schnorr_sign(pk_tweaked.secret, sighash)
    # Encode witness: BIP-322 simple = [schnorr_64]
    witness = [sig]
    encoded = write_compact(len(witness))
    for w in witness:
        encoded += write_compact(len(w)) + w
    return base64.b64encode(encoded).decode("ascii")


def sign_bip322_zec_transparent(message: str, key_bytes: bytes, address: str) -> str:
    """
    BIP-322 simple for Zcash mainnet transparent t1 (P2PKH) or t3 (P2SH wrapping that P2PKH).
    Returns base64-encoded **full signed to_sign transaction** (required for non-segwit BIP-322).
    """
    import base64 as _b64

    from embit import compact
    from embit.base58 import encode_check
    from embit.hashes import hash160
    from embit.script import Script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    ZEC_PUB = bytes([0x1C, 0xB8])
    ZEC_SCR = bytes([0x1C, 0xBD])

    a = address.strip()
    pk = PrivateKey(key_bytes)
    pub = pk.get_public_key()
    pubc = pub.sec()
    h20 = hash160(pubc)
    redeem_p2pkh = bytes([0x76, 0xA9, 0x14]) + h20 + bytes([0x88, 0xAC])

    if a.startswith("t1"):
        if encode_check(ZEC_PUB + h20) != a:
            raise ValueError("Private key does not match t1 address")
        spk = redeem_p2pkh
        sighash_script = Script(spk)

        def _script_sig(sig):
            return embit_script.script_sig_p2pkh(sig, pub)

    elif a.startswith("t3"):
        r20 = hash160(redeem_p2pkh)
        if encode_check(ZEC_SCR + r20) != a:
            raise ValueError(
                "Private key does not match t3 address (expected P2SH of standard P2PKH redeem script)"
            )
        spk = bytes([0xA9, 0x14]) + r20 + bytes([0x87])
        # P2SH spends sign with the redeem script, not the outer P2SH scriptPubKey
        sighash_script = Script(redeem_p2pkh)

        def _script_sig(sig):
            der = sig.serialize() + bytes([embit_script.SIGHASH_ALL])
            chunk = lambda b: compact.to_bytes(len(b)) + b
            return Script(chunk(der) + chunk(pubc) + chunk(redeem_p2pkh))

    else:
        raise ValueError("Zcash transparent quote address must be mainnet t1 or t3")

    msg_hash = bip322_hash(message)
    vin0 = TransactionInput(bytes(32), 0xFFFFFFFF, Script(bytes([0x00, 0x20]) + msg_hash), 0)
    to_spend = Transaction(0, [vin0], [TransactionOutput(0, Script(spk))], 0)
    unsigned = Transaction(
        0, [TransactionInput(to_spend.txid(), 0, Script(b""), 0)], [TransactionOutput(0, Script(b"\x6a"))], 0
    )
    h = unsigned.sighash_legacy(0, sighash_script)
    sig = pk.sign(h)
    scr = _script_sig(sig)
    signed = Transaction(
        0, [TransactionInput(to_spend.txid(), 0, scr, 0)], [TransactionOutput(0, Script(b"\x6a"))], 0
    )
    return _b64.b64encode(signed.serialize()).decode("ascii")


def sign_and_finalize(psbt_hex: str, key_bytes: bytes,
                      adaptor_key_bytes: Optional[bytes] = None,
                      preimage: Optional[bytes] = None,
                      network: Optional[str] = None) -> Tuple[Optional[str], str]:
    """
    Sign a PSBT and finalize it into a raw transaction.
    For FAL hashlock lender claims, pass the 32-byte attestation preimage as ``preimage``.
    ``network``: when ``bch`` or ``xec``, Taproot key-path inputs use BCH replay-protected
    sighash (fork-id BIP143 digest + Schnorr witness ``sig || 0x41``), not BTC BIP-341 TapSighash.
    Returns (raw_tx_hex, txid) on success, or (None, error_msg).
    """
    tx, inputs = parse_psbt(bytes.fromhex(psbt_hex))
    my_xonly = PrivateKey(key_bytes).get_public_key().xonly()

    adaptor_xonly = None
    if adaptor_key_bytes:
        adaptor_xonly = PrivateKey(adaptor_key_bytes).get_public_key().xonly()

    witnesses = {}
    signed = 0

    # Embit tx for BIP-341 key-path sighash (funding PSBTs have no TAP_LEAF_SCRIPT entries)
    embit_tx = None
    if HAS_EMBIT:
        try:
            from embit.transaction import Transaction as EmbitTransaction
            from embit.script import Script as EmbitScript
            from embit.transaction import SIGHASH as EmbitSIGHASH

            raw_unsigned = tx.raw()
            embit_tx = EmbitTransaction.read_from(BytesIO(raw_unsigned))
            _embit_script = EmbitScript
            _embit_sighash = EmbitSIGHASH
        except Exception as e:
            embit_tx = None
            _embit_script = None
            _embit_sighash = None
            print(f"  ⚠ Could not load tx for Taproot key-path sighash: {e}")
    else:
        _embit_script = None
        _embit_sighash = None

    net_key = normalize_signer_network(network or "") or ""
    use_bch_replay_sighash = net_key in ("bch", "xec")

    pk_for_key_path = PrivateKey(key_bytes)
    my_pubkey_compressed = pk_for_key_path.get_public_key().sec()

    for idx, pinp in enumerate(inputs):
        # ── Native SegWit v0 P2WPKH funding input (common for CoinPool top-ups) ──
        p2wpkh_hash = _p2wpkh_hash_from_witness_utxo_spk(pinp.utxo_spk) if pinp.utxo_spk else None
        if (
            embit_tx is not None
            and _embit_script is not None
            and _embit_sighash is not None
            and not pinp.leaves
            and p2wpkh_hash is not None
        ):
            try:
                from embit.hashes import hash160 as embit_hash160
            except Exception as e:
                return None, f"Could not load hash160 for P2WPKH signing: {e}"
            if embit_hash160(my_pubkey_compressed) != p2wpkh_hash:
                print(
                    f"  · Input {idx}: P2WPKH — pubkey hash does not match this key "
                    f"(expected …{p2wpkh_hash.hex()[-8:]})"
                )
                continue
            try:
                script_code = _embit_script(_p2pkh_scriptcode(p2wpkh_hash))
                msg = embit_tx.sighash_segwit(
                    idx, script_code, pinp.utxo_value, sighash=_embit_sighash.ALL
                )
            except Exception as e:
                return None, f"P2WPKH sighash failed (input {idx}): {e}"
            sig_obj = pk_for_key_path.sign(msg)
            sig_bytes = sig_obj.serialize() if hasattr(sig_obj, "serialize") else bytes(sig_obj)
            witnesses[idx] = [sig_bytes + b"\x01", my_pubkey_compressed]
            signed += 1
            print(f"  ✓ Input {idx}: P2WPKH signed (CoinPool top-up / wallet funding)")
            continue

        # ── Taproot key-path (P2TR spend with empty script tree — typical funding PSBT) ──
        out_xonly = _p2tr_output_xonly_from_witness_utxo_spk(pinp.utxo_spk) if pinp.utxo_spk else None
        if (
            embit_tx is not None
            and _embit_script is not None
            and _embit_sighash is not None
            and not pinp.leaves
            and out_xonly is not None
        ):
            my_untweaked_xonly = pk_for_key_path.get_public_key().xonly()
            my_tweaked_xonly = pk_for_key_path.get_public_key().taproot_tweak(b"").xonly()
            if out_xonly == my_tweaked_xonly:
                key_path_signer = pk_for_key_path.taproot_tweak(b"")
                key_path_label = "BIP341 tweaked"
            elif out_xonly == my_untweaked_xonly:
                key_path_signer = pk_for_key_path
                key_path_label = "untweaked CoinPool"
            else:
                print(
                    f"  · Input {idx}: Taproot key-path — output key does not match this key "
                    f"(expected output xonly …{out_xonly.hex()[-8:]}, "
                    f"key gives tweaked …{my_tweaked_xonly.hex()[-8:]} / "
                    f"untweaked …{my_untweaked_xonly.hex()[-8:]})"
                )
                continue
            try:
                for j, inp in enumerate(inputs):
                    if not inp.utxo_spk or inp.utxo_value <= 0:
                        raise ValueError(f"missing witness_utxo for input {j}")
                if use_bch_replay_sighash:
                    msg = bch_replay_signature_hash(
                        tx, idx, pinp.utxo_spk, pinp.utxo_value, 0x00000041
                    )
                else:
                    script_pubkeys = [_embit_script(i.utxo_spk) for i in inputs]
                    values = [i.utxo_value for i in inputs]
                    msg = embit_tx.sighash_taproot(
                        idx, script_pubkeys, values, sighash=_embit_sighash.DEFAULT
                    )
            except Exception as e:
                return None, f"Taproot key-path sighash failed (input {idx}): {e}"
            sig_obj = key_path_signer.schnorr_sign(msg)
            sig_bytes = sig_obj.serialize() if hasattr(sig_obj, "serialize") else bytes(sig_obj)
            if use_bch_replay_sighash:
                witnesses[idx] = [sig_bytes + b"\x41"]
                print(
                    f"  ✓ Input {idx}: Taproot key-path signed ({key_path_label}; BCH/XEC replay-protected sighash, witness …41)"
                )
            else:
                witnesses[idx] = [sig_bytes]
                print(f"  ✓ Input {idx}: Taproot key-path signed ({key_path_label}; funding / P2TR spend)")
            signed += 1
            continue

        if not pinp.leaves:
            print(f"  · Input {idx}: no taproot leaf scripts and not a key-path P2TR input — skipping")
            continue

        for cb, script, leaf_ver in pinp.leaves:
            info = analyze_script(script)
            print(f"  · Input {idx}: {info['description']}")

            lh = tap_leaf_hash(script, leaf_ver)
            msg = sighash_script_path(tx, idx, inputs, lh)
            print(f"    leaf_hash: {lh.hex()[:24]}…")
            print(f"    sighash:   {msg.hex()[:24]}…")

            if info['type'] == 'v2_claim':
                recv_pk = info['receiver_pubkey']
                completed = pinp.tap_script_sigs.get((recv_pk, lh))
                if completed:
                    witnesses[idx] = [completed, script, cb]
                    signed += 1
                    print(f"  ✓ Input {idx}: v2 claim finalized (pre-completed signature)")
                    break
                if my_xonly != recv_pk:
                    return None, (
                        f"Receiver key mismatch: script expects {recv_pk.hex()[:16]}…, "
                        f"your key is {my_xonly.hex()[:16]}…"
                    )
                return None, (
                    "v2 claim PSBT missing pre-completed signature — rebuild with "
                    "build_v2_claim_psbt (recovery kit mode [C] on a v2 swap)"
                )

            if info['type'] == 'claim':
                adaptor_point = info['adaptor_point']
                pre_sig = pinp.tap_script_sigs.get((adaptor_point, lh))

                if pre_sig:
                    # Pre-signed second key (adaptor or oracle): user only signs as receiver/lender
                    print(f"    ✓ Pre-signed co-signature found ({pre_sig.hex()[:24]}…)")
                    if my_xonly != info['receiver_pubkey']:
                        return None, (f"Receiver key mismatch: script expects "
                                      f"{info['receiver_pubkey'].hex()[:16]}…, "
                                      f"your key is {my_xonly.hex()[:16]}…")
                    sig_receiver = schnorr_sign(key_bytes, msg)
                    print(f"    sig_receiver: {sig_receiver.hex()[:24]}…")
                    witnesses[idx] = [sig_receiver, pre_sig, script, cb]
                    signed += 1
                    print(f"  ✓ Input {idx}: claim signed (pre-signed co-sig + receiver/lender)")
                    break

                # Manual adaptor signing
                if not adaptor_key_bytes:
                    return None, "Adaptor secret required (not pre-signed, not provided)"
                if adaptor_xonly != adaptor_point:
                    return None, (f"Adaptor mismatch: script expects "
                                  f"{adaptor_point.hex()[:16]}…, "
                                  f"provided key is {adaptor_xonly.hex()[:16]}…")
                if my_xonly != info['receiver_pubkey']:
                    return None, (f"Receiver key mismatch: script expects "
                                  f"{info['receiver_pubkey'].hex()[:16]}…, "
                                  f"your key is {my_xonly.hex()[:16]}…")
                sig_adaptor = schnorr_sign(adaptor_key_bytes, msg)
                sig_receiver = schnorr_sign(key_bytes, msg)
                print(f"    sig_adaptor:  {sig_adaptor.hex()[:24]}…")
                print(f"    sig_receiver: {sig_receiver.hex()[:24]}…")
                witnesses[idx] = [sig_receiver, sig_adaptor, script, cb]
                signed += 1
                print(f"  ✓ Input {idx}: claim signed (adaptor + receiver)")
                break

            elif info['type'] == 'lender_claim_hashlock':
                if not preimage or len(preimage) != 32:
                    return None, (
                        "32-byte attestation preimage required for FAL hashlock claim "
                        "(use attestation_preimage_hex from the API / UI)"
                    )
                if my_xonly != info['lender_pubkey']:
                    return None, (
                        f"Lender key mismatch: script expects {info['lender_pubkey'].hex()[:16]}…, "
                        f"your key is {my_xonly.hex()[:16]}…"
                    )
                sig_lender = schnorr_sign(key_bytes, msg)
                print(f"    sig_lender: {sig_lender.hex()[:24]}…")
                # Witness (bottom→top): lender_sig, preimage, script, control block
                witnesses[idx] = [sig_lender, preimage, script, cb]
                signed += 1
                print(f"  ✓ Input {idx}: FAL hashlock claim signed (preimage + lender)")
                break

            elif info['type'] == 'refund':
                if my_xonly != info['sender_pubkey']:
                    return None, (f"Sender key mismatch: script expects "
                                  f"{info['sender_pubkey'].hex()[:16]}…, "
                                  f"your key is {my_xonly.hex()[:16]}…")
                sig_sender = schnorr_sign(key_bytes, msg)
                print(f"    sig_sender: {sig_sender.hex()[:24]}…")
                witnesses[idx] = [sig_sender, script, cb]
                signed += 1
                print(f"  ✓ Input {idx}: refund signed")
                break

            else:
                print(f"  ⚠ Input {idx}: unknown script type — skipping")

    if signed == 0:
        return None, "No inputs could be signed (key mismatch or unsupported script)"

    print(f"\n  Finalized {signed} input(s)")
    raw_tx = tx.raw(witnesses)
    txid = hashlib.sha256(hashlib.sha256(tx.raw()).digest()).digest()[::-1].hex()
    return raw_tx.hex(), txid


# ═══════════════════════════════════════════════════════════════
# PSBT builders  (from recovery-kit data)
# ═══════════════════════════════════════════════════════════════

def build_refund_psbt(kit: Dict, fee_rate: int = DEFAULT_FEE_RATE) -> Tuple[str, int, int]:
    """
    Build a refund PSBT for DLC A from recovery-kit data.

    Returns (psbt_hex, fee, output_value).
    The PSBT has nLockTime = timeout.  It is valid to sign now but can only
    be broadcast once the Bitcoin network reaches the timeout block height.
    """
    if _is_p2sh_htlc_dlc_a(kit):
        raise ValueError(
            "DLC A is a P2SH HTLC (BCH / XEC / RVN / ZEC hybrid). "
            "Use recovery kit mode [R] — the signer builds a legacy transaction, not a Taproot PSBT."
        )
    dlc = kit.get('dlc_a') or {}
    if not dlc.get('txid'):
        raise ValueError("DLC A not funded — nothing to refund")
    desc = dlc.get('descriptor')
    if not desc:
        raise ValueError("DLC A descriptor missing from recovery kit")

    timeout = kit.get('timeout_a') or desc.get('timeout')
    if not timeout:
        raise ValueError("Timeout not found in recovery kit")

    dlc_value = dlc.get('value') or kit.get('from_amount')
    if not dlc_value:
        raise ValueError("DLC A value unknown")
    vout = dlc.get('vout') or 0

    for field in ('scriptpubkey', 'refund_script', 'refund_control_block',
                  'internal_pubkey', 'merkle_root'):
        if not desc.get(field):
            raise ValueError(f"Descriptor missing required field '{field}'")

    scriptpubkey = _hex_bytes(desc.get("scriptpubkey"), "scriptpubkey")
    refund_script = _hex_bytes(desc.get("refund_script"), "refund_script")
    refund_cb     = _hex_bytes(desc.get("refund_control_block"), "refund_control_block")
    internal_key  = _hex_bytes(desc.get("internal_pubkey"), "internal_pubkey")
    merkle_root   = _hex_bytes(desc.get("merkle_root"), "merkle_root")
    leaf_ver      = refund_cb[0] & 0xFE

    sender_addr = kit.get('user_address_from')
    if not sender_addr:
        raise ValueError("user_address_from missing from recovery kit")
    sender_spk = address_to_scriptpubkey(sender_addr)

    # Fee
    fee = TAPROOT_SCRIPT_VSIZE * fee_rate
    output_value = dlc_value - fee
    if output_value < 330:
        fee = TAPROOT_SCRIPT_VSIZE  # fall back to 1 sat/vB
        output_value = dlc_value - fee
        if output_value < 330:
            raise ValueError(f"DLC value ({dlc_value} sats) too small to cover fee")

    # Transaction
    tx = Tx()
    tx.version = 2
    tx.locktime = timeout
    tx.ins = [TxIn(_hex_bytes(dlc.get("txid"), "dlc_a.txid")[::-1], vout, b'', LOCKTIME_SEQUENCE)]
    tx.outs = [TxOut(output_value, sender_spk)]

    # PSBT
    psbt_input = {
        'witness_utxo': (dlc_value, scriptpubkey),
        'tap_internal_key': internal_key,
        'tap_merkle_root': merkle_root,
        'tap_leaf_scripts': [(refund_cb, refund_script, leaf_ver)],
        'tap_script_sigs': {},
    }
    return build_psbt_bytes(tx, [psbt_input], 1).hex(), fee, output_value


def build_claim_psbt(kit: Dict, fee_rate: int = DEFAULT_FEE_RATE) -> Tuple[str, int, int]:
    """
    Build a claim PSBT for DLC B from recovery-kit data.

    The adaptor signature is computed from the kit's adaptor_secret and
    pre-embedded into the PSBT.  The user only needs to sign with their
    receiver key.

    Returns (psbt_hex, fee, output_value).
    """
    dlc = kit.get('dlc_b') or {}
    if not dlc.get('txid'):
        raise ValueError("DLC B not funded — nothing to claim")
    desc = dlc.get('descriptor')
    if not desc:
        raise ValueError("DLC B descriptor missing from recovery kit")

    adaptor_secret_hex = kit.get('adaptor_secret')
    if not adaptor_secret_hex:
        raise ValueError("Adaptor secret not in kit — swap is not yet claim-eligible. "
                         "Both DLCs must be funded and confirmed before the adaptor secret "
                         "is included in the recovery kit.")

    dlc_value = dlc.get('value') or kit.get('to_amount')
    if not dlc_value:
        raise ValueError("DLC B value unknown")
    vout = dlc.get('vout') or 0

    for field in ('scriptpubkey', 'success_script', 'success_control_block',
                  'internal_pubkey', 'merkle_root'):
        if not desc.get(field):
            raise ValueError(f"Descriptor missing required field '{field}'")

    scriptpubkey = _hex_bytes(desc.get("scriptpubkey"), "scriptpubkey")
    success_script = _hex_bytes(desc.get("success_script"), "success_script")
    success_cb     = _hex_bytes(desc.get("success_control_block"), "success_control_block")
    internal_key   = _hex_bytes(desc.get("internal_pubkey"), "internal_pubkey")
    merkle_root    = _hex_bytes(desc.get("merkle_root"), "merkle_root")
    leaf_ver       = success_cb[0] & 0xFE

    receiver_addr = kit.get('user_address_to')
    if not receiver_addr:
        raise ValueError("user_address_to missing from recovery kit")
    receiver_spk = address_to_scriptpubkey(receiver_addr)

    # Fee
    fee = TAPROOT_SCRIPT_VSIZE * fee_rate
    output_value = dlc_value - fee
    if output_value < 330:
        fee = TAPROOT_SCRIPT_VSIZE
        output_value = dlc_value - fee
        if output_value < 330:
            raise ValueError(f"DLC value ({dlc_value} sats) too small to cover fee")

    # Transaction
    tx = Tx()
    tx.version = 2
    tx.locktime = 0
    tx.ins = [TxIn(_hex_bytes(dlc.get("txid"), "dlc_b.txid")[::-1], vout, b'', LOCKTIME_SEQUENCE)]
    tx.outs = [TxOut(output_value, receiver_spk)]

    # Pre-sign adaptor signature
    leaf_hash = tap_leaf_hash(success_script, leaf_ver)
    temp_inp = PInput()
    temp_inp.utxo_value = dlc_value
    temp_inp.utxo_spk = scriptpubkey
    sighash = sighash_script_path(tx, 0, [temp_inp], leaf_hash)

    adaptor_key_bytes = _hex_bytes(adaptor_secret_hex, "adaptor_secret")
    adaptor_sig = schnorr_sign(adaptor_key_bytes, sighash)
    adaptor_xonly = PrivateKey(adaptor_key_bytes).get_public_key().xonly()

    # PSBT with pre-embedded adaptor signature
    psbt_input = {
        'witness_utxo': (dlc_value, scriptpubkey),
        'tap_internal_key': internal_key,
        'tap_merkle_root': merkle_root,
        'tap_leaf_scripts': [(success_cb, success_script, leaf_ver)],
        'tap_script_sigs': {(adaptor_xonly, leaf_hash): adaptor_sig},
    }
    return build_psbt_bytes(tx, [psbt_input], 1).hex(), fee, output_value


def _is_v2_kit(kit: Dict) -> bool:
    if int(kit.get('protocol_version', 1)) == 2:
        return True
    desc = (kit.get('dlc_b') or {}).get('descriptor') or {}
    return int(desc.get('version', 1)) == 2


def _v2_expected_receiver_xonly(kit: Dict) -> bytes:
    desc = (kit.get('dlc_b') or {}).get('descriptor') or {}
    pk_hex = desc.get('receiver_pubkey') or ''
    if not pk_hex:
        eph = (kit.get('dlc_b_receiver_eph_pubkey') or kit.get('user_pubkey_to') or '').strip()
        if len(eph) == 66 and eph[:2] in ('02', '03'):
            pk_hex = eph[2:]
    if not pk_hex:
        raise ValueError("cannot determine DLC B receiver_pubkey from kit")
    return _hex_bytes(pk_hex, 'receiver_pubkey')


def build_v2_claim_psbt(
    kit: Dict,
    fee_rate: int = DEFAULT_FEE_RATE,
    claim_privkey: Optional[bytes] = None,
) -> Tuple[str, int, int]:
    """
    Build a Protocol v2 (adaptor-signature) claim PSBT from recovery-kit data.

    v2 differs from the deprecated v1 claim: the claim leaf is a single ephemeral
    receiver key (``<receiver> CHECKSIG``). We COMPLETE a BIP-340 adaptor
    pre-signature with the adaptor secret ``t`` to produce the final Schnorr
    signature, embed it as the single tap-script sig, and the existing finalize
    path turns it into the witness ``[sig, claim_script, control_block]``.

    Required kit fields (all client-held; the backend never has the ephemeral key
    or t):
      - dlc_b.descriptor: {claim_script, claim_control_block, scriptpubkey,
                           internal_pubkey, merkle_root, adaptor_point}
      - dlc_b.txid / vout / value
      - receiver_ephemeral_privkey: 64-hex per-swap ephemeral claim key
      - adaptor_secret OR revealed_secret: 64-hex t (the swap secret)
      - user_address_to: destination

    Returns (psbt_hex, fee, output_value).
    """
    dlc = kit.get('dlc_b') or {}
    if not dlc.get('txid'):
        raise ValueError("DLC B not funded — nothing to claim")
    desc = dlc.get('descriptor') or {}

    if int(desc.get('version', 1)) != 2:
        raise ValueError("Not a v2 descriptor — use the v1 claim flow")

    expected_recv = _v2_expected_receiver_xonly(kit)

    eph_key = claim_privkey
    if eph_key is None:
        eph_hex = kit.get('receiver_ephemeral_privkey') or kit.get('ephemeral_privkey')
        if eph_hex:
            eph_key = _hex_bytes(eph_hex, 'receiver_ephemeral_privkey')
    if eph_key is None:
        raise ValueError(
            "receiver_ephemeral_privkey missing from kit — when prompted, enter the "
            "private key whose x-only pubkey matches DLC B receiver_pubkey "
            f"({expected_recv.hex()[:16]}…). This may be your per-swap ephemeral key "
            "OR your wallet key if the swap was created before ephemeral keys were enabled."
        )
    if PrivateKey(eph_key).get_public_key().xonly() != expected_recv:
        raise ValueError(
            f"claim private key does not match DLC B receiver_pubkey "
            f"(expected {expected_recv.hex()[:16]}…)"
        )

    secret_hex = kit.get('adaptor_secret') or kit.get('revealed_secret')
    if not secret_hex:
        raise ValueError("adaptor secret (t) not available yet — wait for the counterparty "
                         "to claim (revealing t) or use the holder's secret")
    t_bytes = _hex_bytes(secret_hex, 'adaptor_secret')
    T_hex = desc.get('adaptor_point') or kit.get('adaptor_point')
    if T_hex:
        T_bytes = _hex_bytes(T_hex, 'adaptor_point')
    else:
        # Secret-holder: T = t·G even if not yet published to the relay
        T_bytes = adaptor_point_from_secret(t_bytes)

    for field in ('scriptpubkey', 'claim_script', 'claim_control_block',
                  'internal_pubkey', 'merkle_root'):
        if not desc.get(field):
            raise ValueError(f"v2 descriptor missing required field '{field}'")

    scriptpubkey = _hex_bytes(desc.get("scriptpubkey"), "scriptpubkey")
    claim_script = _hex_bytes(desc.get("claim_script"), "claim_script")
    claim_cb     = _hex_bytes(desc.get("claim_control_block"), "claim_control_block")
    internal_key = _hex_bytes(desc.get("internal_pubkey"), "internal_pubkey")
    merkle_root  = _hex_bytes(desc.get("merkle_root"), "merkle_root")
    leaf_ver     = claim_cb[0] & 0xFE

    dlc_value = dlc.get('value') or kit.get('to_amount')
    if not dlc_value:
        raise ValueError("DLC B value unknown")
    vout = dlc.get('vout') or 0

    receiver_addr = kit.get('user_address_to')
    if not receiver_addr:
        raise ValueError("user_address_to missing from recovery kit")
    receiver_spk = address_to_scriptpubkey(receiver_addr)

    fee = TAPROOT_SCRIPT_VSIZE * fee_rate
    output_value = dlc_value - fee
    if output_value < 330:
        fee = TAPROOT_SCRIPT_VSIZE
        output_value = dlc_value - fee
        if output_value < 330:
            raise ValueError(f"DLC value ({dlc_value} sats) too small to cover fee")

    tx = Tx()
    tx.version = 2
    tx.locktime = 0
    tx.ins = [TxIn(_hex_bytes(dlc.get("txid"), "dlc_b.txid")[::-1], vout, b'', LOCKTIME_SEQUENCE)]
    tx.outs = [TxOut(output_value, receiver_spk)]

    leaf_hash = tap_leaf_hash(claim_script, leaf_ver)
    temp_inp = PInput()
    temp_inp.utxo_value = dlc_value
    temp_inp.utxo_spk = scriptpubkey
    sighash = sighash_script_path(tx, 0, [temp_inp], leaf_hash)

    presig = adaptor_presign(eph_key, sighash, T_bytes)
    completed_sig = adaptor_complete(presig, t_bytes)  # 64-byte BIP-340 sig
    eph_xonly = PrivateKey(eph_key).get_public_key().xonly()

    psbt_input = {
        'witness_utxo': (dlc_value, scriptpubkey),
        'tap_internal_key': internal_key,
        'tap_merkle_root': merkle_root,
        'tap_leaf_scripts': [(claim_cb, claim_script, leaf_ver)],
        'tap_script_sigs': {(eph_xonly, leaf_hash): completed_sig},
    }
    return build_psbt_bytes(tx, [psbt_input], 1).hex(), fee, output_value


# ═══════════════════════════════════════════════════════════════
# Network helpers
# ═══════════════════════════════════════════════════════════════

def _broadcast_one(raw_hex: str, url: str, network: str = "") -> str:
    """Broadcast to a single URL. Returns txid on success."""
    # Blockchair: POST form data=data (hex), JSON response with transaction_hash
    if "api.blockchair.com" in url and "/push/transaction" in url:
        r = httpx.post(url, data={"data": raw_hex}, timeout=60)
        if r.status_code == 200:
            j = r.json()
            ctx = j.get("context") or {}
            if ctx.get("code") not in (200, None) and ctx.get("error"):
                raise RuntimeError(str(ctx.get("error", "broadcast failed")))
            data_block = j.get("data") or {}
            txid = (data_block.get("transaction_hash") or data_block.get("txid") or "").strip()
            if not txid and isinstance(data_block, dict):
                txid = (data_block.get("data") or {}).get("transaction_hash", "") or ""
            if txid:
                return txid
            raise RuntimeError(f"Blockchair broadcast: {str(j)[:400]}")
        raise RuntimeError(f"Broadcast failed ({r.status_code}): {r.text}")

    r = httpx.post(url, content=raw_hex, headers={"Content-Type": "text/plain"}, timeout=60)
    if r.status_code == 200:
        # Blockbook /api/v2/sendtx/ returns JSON {"result":"<txid>"}; mempool returns plain txid
        body = r.text.strip()
        if body.startswith("{"):
            try:
                j = r.json()
                return (j.get("result") or j.get("txid") or "").strip()
            except Exception:
                pass
        return body
    raise RuntimeError(f"Broadcast failed ({r.status_code}): {r.text}")


def broadcast(raw_hex: str, network: str) -> str:
    """Broadcast a raw transaction. Returns txid on success."""
    cfg = NETWORKS[network]
    urls = cfg.get("broadcast_urls") or [cfg["broadcast_url"]]
    # Allow env override for DGB (Atomic may reject Taproot)
    if network == "dgb" and os.environ.get("DGB_BROADCAST_URL"):
        urls = [os.environ["DGB_BROADCAST_URL"]] + [u for u in urls if u != os.environ["DGB_BROADCAST_URL"]]
    if network == "grs" and os.environ.get("GRS_BROADCAST_URL"):
        urls = [os.environ["GRS_BROADCAST_URL"]] + [u for u in urls if u != os.environ["GRS_BROADCAST_URL"]]
    if network == "bel" and os.environ.get("BEL_BROADCAST_URL"):
        urls = [os.environ["BEL_BROADCAST_URL"]] + [u for u in urls if u != os.environ["BEL_BROADCAST_URL"]]
    if network == "ltc" and os.environ.get("LTC_BROADCAST_URL"):
        urls = [os.environ["LTC_BROADCAST_URL"]] + [u for u in urls if u != os.environ["LTC_BROADCAST_URL"]]
    if network == "bch" and os.environ.get("BCH_BROADCAST_URL"):
        urls = [os.environ["BCH_BROADCAST_URL"]] + [u for u in urls if u != os.environ["BCH_BROADCAST_URL"]]
    if network == "xec" and os.environ.get("XEC_BROADCAST_URL"):
        urls = [os.environ["XEC_BROADCAST_URL"]] + [u for u in urls if u != os.environ["XEC_BROADCAST_URL"]]
    if network == "rvn" and os.environ.get("RVN_BROADCAST_URL"):
        urls = [os.environ["RVN_BROADCAST_URL"]] + [u for u in urls if u != os.environ["RVN_BROADCAST_URL"]]
    last_err: Optional[BaseException] = None
    errs: List[str] = []
    for url in urls:
        try:
            return _broadcast_one(raw_hex, url, network)
        except Exception as e:
            last_err = e
            short = str(e).replace("\n", " ")
            if len(short) > 180:
                short = short[:177] + "..."
            errs.append(f"{url}: {short}")
            continue
    detail = " | ".join(errs[:6])
    if len(errs) > 6:
        detail += f" | … (+{len(errs) - 6} more)"
    raise RuntimeError(
        f"Broadcast failed after {len(urls)} endpoint(s): {detail}"
    ) from last_err


def get_block_height(network: str) -> Optional[int]:
    """Fetch current block height. Returns None on failure."""
    try:
        cfg = NETWORKS[network]
        r = httpx.get(cfg["height_url"], timeout=10)
        if r.status_code == 200:
            if cfg.get("height_blockchair"):
                data = r.json().get("data") or {}
                h = data.get("best_block_height")
                if h is None:
                    h = data.get("blocks")
                return int(h) if h is not None else None
            if cfg.get("height_json"):
                data = r.json()
                return int(data.get("blockbook", {}).get("bestHeight", 0))
            return int(r.text.strip())
    except Exception:
        pass
    return None


def _do_broadcast(raw_hex: str, net: str):
    """Broadcast helper with error handling."""
    if not HAS_HTTPX:
        print("  ✗ httpx not installed — broadcast manually")
        print(f"    POST the raw hex to: {NETWORKS[net]['broadcast_url']}")
        return
    try:
        txid = broadcast(raw_hex, net)
        print(f"\n  ✓ Broadcast OK!")
        print(f"    TXID: {txid}")
        print(f"    View: {NETWORKS[net]['tx_url']}{txid}")
    except Exception as e:
        print(f"\n  ✗ {e}")
        urls = NETWORKS[net].get("broadcast_urls") or [NETWORKS[net]["broadcast_url"]]
        print(f"    Broadcast manually:")
        for u in urls[:3]:
            if "api.blockchair.com" in u and "/push/transaction" in u:
                print(f"      curl -sS -X POST '{u}' --data-urlencode 'data=<raw_hex>'")
            else:
                print(f"      curl -X POST {u} -d '<raw_hex>'")
        if net == "dgb":
            print(f"    Or set DGB_BROADCAST_URL to a Taproot-supporting endpoint (DigiByte Core 8.23+)")
        if net == "grs":
            print(f"    Or set GRS_BROADCAST_URL to a Taproot-supporting endpoint")
        if net == "bel":
            print(f"    Or set BEL_BROADCAST_URL to another electrs-compatible /tx endpoint")
        if net == "ltc":
            print(f"    Or set LTC_BROADCAST_URL to another mempool-style /tx endpoint")
        if net == "bch":
            print(
                "    Or set BCH_BROADCAST_URL (tried: Blockchair push/transaction, then BCExplorer /api/tx)"
            )
            print(
                "    If the tx was signed with network=bch, Taproot key-path uses replay-protected (fork-id BIP143) sighash."
                "\n    Persistent RPC -4 after that: verify witness_utxo scriptPubKey matches the chain UTXO, or use a BCH node wallet to sign."
            )
        if net == "xec":
            print(f"    Or set XEC_BROADCAST_URL to another Blockchair-compatible ecash push/transaction URL")
        if net == "rvn":
            print(f"    Or set RVN_BROADCAST_URL to another Blockbook /api/v2/sendtx/ endpoint")
        if net == "doge":
            print(f"    Or set DOGE_BROADCAST_URL to another Blockchair-compatible dogecoin push/transaction URL")


# ═══════════════════════════════════════════════════════════════
# Mode 1 — Sign existing PSBT
# ═══════════════════════════════════════════════════════════════

def mode_sign_psbt():
    """Interactive: sign an existing PSBT from hex."""
    # Network
    print("\n[1] Network (btc / fb / ltc / bel / dgb / grs / bch / xec / rvn / zec / doge):")
    net = input("    > ").strip().lower()
    net = normalize_signer_network(net)
    if net not in NETWORKS:
        print(f"  ✗ Unknown network '{net}'"); return
    print(f"    ✓ {NETWORKS[net]['name']}")

    # PSBT
    print("\n[2] PSBT hex:")
    psbt_hex = input("    > ").strip()
    if not psbt_hex:
        print("  ✗ Empty"); return
    try:
        tx, inputs = parse_psbt(bytes.fromhex(psbt_hex))
        print(f"    ✓ {len(inputs)} input(s), {len(tx.outs)} output(s), locktime={tx.locktime}")
    except Exception as e:
        print(f"  ✗ Bad PSBT: {e}"); return

    # Analyze scripts
    needs_adaptor = False
    has_pre_signed = False
    needs_preimage = False
    for idx, pinp in enumerate(inputs):
        for cb, script_data, leaf_ver in pinp.leaves:
            info = analyze_script(script_data)
            print(f"    Input {idx}: {pinp.utxo_value:,} sats — {info['description']}")
            if info['type'] == 'lender_claim_hashlock':
                needs_preimage = True
            if info['type'] == 'claim':
                lh = tap_leaf_hash(script_data, leaf_ver)
                if pinp.tap_script_sigs.get((info['adaptor_point'], lh)):
                    print(f"    ✓ Co-signature pre-embedded (no adaptor secret needed)")
                    has_pre_signed = True
                else:
                    needs_adaptor = True

    # Private key
    print(f"\n[3] Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        key_bytes, my_xonly = parse_private_key(key_input)
        print(f"    ✓ xonly: {my_xonly.hex()[:16]}…")
    except Exception as e:
        print(f"  ✗ {e}"); return

    adaptor_bytes = None
    preimage_bytes = None
    step = 4

    # FAL hashlock: 32-byte preimage (64 hex chars)
    if needs_preimage:
        print(f"\n[{step}] FAL attestation preimage (64 hex chars = 32 bytes):")
        ph = input("    > ").strip()
        if not ph or len(ph) != 64:
            print("  ✗ Must be 64 hex chars"); return
        try:
            preimage_bytes = bytes.fromhex(ph)
            print(f"    ✓ preimage (first bytes): {preimage_bytes.hex()[:16]}…")
        except Exception as e:
            print(f"  ✗ Invalid: {e}"); return
        step += 1

    # Adaptor secret (only if needed and not pre-signed)
    if needs_adaptor and not has_pre_signed:
        print(f"\n[{step}] Adaptor secret (64-char hex):")
        ah = input("    > ").strip()
        if not ah or len(ah) != 64:
            print("  ✗ Must be 64 hex chars"); return
        try:
            adaptor_bytes = bytes.fromhex(ah)
            ax = PrivateKey(adaptor_bytes).get_public_key().xonly()
            print(f"    ✓ adaptor xonly: {ax.hex()[:16]}…")
        except Exception as e:
            print(f"  ✗ Invalid: {e}"); return
        step += 1
    elif has_pre_signed:
        print(f"\n    ℹ Co-signature pre-embedded — no adaptor secret needed")

    # Sign
    print(f"\n[{step}] Signing…")
    raw_hex, result = sign_and_finalize(
        psbt_hex, key_bytes, adaptor_bytes, preimage_bytes, network=net
    )
    if not raw_hex:
        print(f"\n  ✗ Failed: {result}"); return

    print(f"\n{'─' * 60}")
    print(f"  Signed transaction ({len(raw_hex)//2} bytes)")
    print(f"{'─' * 60}")
    print(raw_hex)
    print(f"{'─' * 60}")
    print(f"  TXID: {result}")

    step += 1
    print(f"\n[{step}] Broadcast to {NETWORKS[net]['name']}? (y/n)")
    if input("    > ").strip().lower() == 'y':
        _do_broadcast(raw_hex, net)


# ═══════════════════════════════════════════════════════════════
# Mode 2 — Recovery Kit
# ═══════════════════════════════════════════════════════════════

def _load_kit() -> Optional[Dict]:
    """Load recovery kit from file path or pasted JSON."""
    print("\n[1] Load recovery kit")
    print("    Enter file path, or paste JSON (end with empty line):")
    first_line = input("    > ").strip()
    if not first_line:
        print("  ✗ Empty input"); return None

    # Try as file
    if not first_line.startswith('{'):
        path = os.path.expanduser(first_line)
        if os.path.isfile(path):
            try:
                with open(path, 'r') as f:
                    kit = json.load(f)
                print(f"    ✓ Loaded from {path}")
                return _normalize_recovery_kit(kit)
            except Exception as e:
                print(f"  ✗ Failed to read file: {e}"); return None
        else:
            print(f"  ✗ File not found: {path}"); return None

    # Collect pasted JSON
    lines = [first_line]
    # Keep reading until we have valid JSON or empty line
    depth = first_line.count('{') - first_line.count('}')
    while depth > 0:
        line = input("      ")
        lines.append(line)
        depth += line.count('{') - line.count('}')
    try:
        kit = json.loads('\n'.join(lines))
        print(f"    ✓ Parsed JSON")
        return _normalize_recovery_kit(kit)
    except json.JSONDecodeError as e:
        print(f"  ✗ Invalid JSON: {e}"); return None


def _show_kit_summary(kit: Dict):
    """Display recovery kit summary."""
    print(f"\n{'═' * 60}")
    print(f"  Swap:      {kit.get('swap_id', '?')[:16]}…")
    print(f"  State:     {kit.get('state', 'unknown')}")
    print(f"  Direction: {kit.get('from_chain', '?')} → {kit.get('to_chain', '?')}")
    print(f"  Send:      {kit.get('from_amount', 0):,} sats")
    print(f"  Receive:   {kit.get('to_amount', 0):,} sats")
    print(f"  From addr: {kit.get('user_address_from', 'N/A')}")
    print(f"  To addr:   {kit.get('user_address_to', 'N/A')}")

    dlc_a = kit.get('dlc_a') or {}
    dlc_b = kit.get('dlc_b') or {}

    print(f"\n  DLC A (your funding — {kit.get('from_chain', '?')}):")
    if dlc_a.get('txid'):
        val = dlc_a.get('value') or kit.get('from_amount', 0)
        print(f"    Funded: ✓  txid={dlc_a['txid'][:16]}…  vout={dlc_a.get('vout', 0)}  value={val:,}")
        print(f"    Timeout: block {kit.get('timeout_a', '?'):,}")
    else:
        print(f"    Funded: ✗  (not yet funded)")

    print(f"  DLC B (your incoming — {kit.get('to_chain', '?')}):")
    if dlc_b.get('txid'):
        val = dlc_b.get('value') or kit.get('to_amount', 0)
        print(f"    Funded: ✓  txid={dlc_b['txid'][:16]}…  vout={dlc_b.get('vout', 0)}  value={val:,}")
        print(f"    Timeout: block {kit.get('timeout_b', '?'):,}")
    else:
        print(f"    Funded: ✗  (not yet funded)")

    if _is_v2_kit(kit):
        print(f"\n  Protocol: v2 adaptor claim (single-key leaf)")
        try:
            rx = _v2_expected_receiver_xonly(kit).hex()
            print(f"    DLC B receiver x-only: {rx[:20]}…")
        except Exception:
            pass
        if kit.get('receiver_ephemeral_privkey') or kit.get('ephemeral_privkey'):
            print(f"    Claim privkey in kit: ✓")
        else:
            print(f"    Claim privkey in kit: ✗ — you will be prompted for the matching private key")

    has_secret = bool(kit.get('adaptor_secret') or kit.get('revealed_secret'))
    print(f"  Adaptor secret t: {'✓ included' if has_secret else '✗ not included (not yet claim-eligible)'}")
    if kit.get('claim_eligibility_reason'):
        print(f"    {kit['claim_eligibility_reason']}")

    # Pre-built PSBTs
    pre = kit.get('pre_built_psbts') or {}
    if pre.get('refund_psbt_hex'):
        print(f"  Pre-built refund PSBT: ✓ included")
    if pre.get('claim_psbt_hex'):
        print(f"  Pre-built claim PSBT: ✓ included")

    print(f"{'═' * 60}")


def mode_recovery_kit():
    """Interactive: build + sign from recovery kit JSON."""
    kit = _load_kit()
    if not kit:
        return

    # Validate minimum fields
    required = ['swap_id', 'dlc_a', 'dlc_b']
    missing = [f for f in required if f not in kit]
    if missing:
        print(f"  ✗ Invalid recovery kit — missing: {', '.join(missing)}")
        return

    _show_kit_summary(kit)

    # Check pre-built PSBTs
    pre = kit.get('pre_built_psbts') or {}
    has_pre_refund = bool(pre.get('refund_psbt_hex'))
    has_pre_claim  = bool(pre.get('claim_psbt_hex'))

    # Determine what's possible
    dlc_a = kit.get('dlc_a') or {}
    dlc_b = kit.get('dlc_b') or {}
    can_refund = bool(dlc_a.get('txid') and dlc_a.get('descriptor'))
    if _is_v2_kit(kit):
        can_claim = bool(
            dlc_b.get('txid') and dlc_b.get('descriptor')
            and (kit.get('adaptor_secret') or kit.get('revealed_secret'))
        )
    else:
        can_claim = bool(dlc_b.get('txid') and dlc_b.get('descriptor') and kit.get('adaptor_secret'))

    if not can_refund and not can_claim and not has_pre_refund and not has_pre_claim:
        print("\n  No actions available:")
        if not dlc_a.get('txid'):
            print("    · DLC A not funded — nothing to refund")
        if not dlc_b.get('txid'):
            print("    · DLC B not funded — nothing to claim")
        elif not kit.get('adaptor_secret'):
            print("    · Adaptor secret not in kit — claim not possible")
            print("    · Wait for both DLCs to confirm, then re-download the kit from the platform")
        return

    # Menu
    print("\n[2] Select action:")
    options = []
    if can_refund:
        print("    [R]  Build + sign refund for DLC A (reclaim your locked funds after timeout)")
        options.append('R')
    if can_claim:
        print("    [C]  Build + sign claim for DLC B (claim your incoming funds)")
        options.append('C')
    if has_pre_refund:
        print("    [SR] Sign pre-built refund PSBT from kit")
        options.append('SR')
    if has_pre_claim:
        print("    [SC] Sign pre-built claim PSBT from kit")
        options.append('SC')

    action = input("    > ").strip().upper()

    # Pre-built PSBT paths
    if action == 'SR' and has_pre_refund:
        net = normalize_signer_network(kit.get('from_chain', 'btc'))
        print(f"\n    Using pre-built refund PSBT (network: {net.upper()})")
        _sign_and_broadcast(pre['refund_psbt_hex'], net, 'refund')
        return
    if action == 'SC' and has_pre_claim:
        net = normalize_signer_network(kit.get('to_chain', 'fb'))
        print(f"\n    Using pre-built claim PSBT (network: {net.upper()})")
        _sign_and_broadcast(pre['claim_psbt_hex'], net, 'claim')
        return

    # Build-from-descriptor paths
    if action == 'R' and can_refund:
        _build_sign_refund(kit)
    elif action == 'C' and can_claim:
        _build_sign_claim(kit)
    else:
        print(f"  ✗ Invalid choice '{action}'. Options: {', '.join(options)}")


def _build_sign_refund(kit: Dict):
    """Build refund PSBT from kit descriptor data, sign, broadcast."""
    desc_a = (kit.get("dlc_a") or {}).get("descriptor") or {}
    timeout = (
        kit.get("timeout_a")
        or desc_a.get("timeout")
        or desc_a.get("cltv_height")
    )

    # ── Hybrid P2SH HTLC (BCH / XEC / RVN / ZEC): legacy ECDSA, not Taproot PSBT ──
    if _is_p2sh_htlc_dlc_a(kit):
        net = _p2sh_htlc_refund_network(kit)
        use_bch = net in ("bch", "xec")

        if HAS_HTTPX:
            height = get_block_height(net)
            if height:
                print(f"\n    Current {net.upper()} block height: {height:,}")
                if timeout and height < int(timeout):
                    remaining = int(timeout) - height
                    print(f"    ⚠ CLTV refund height {int(timeout):,} — {remaining:,} blocks away")
                    print(f"      You can sign now, but broadcast will fail until chain height ≥ {int(timeout):,}")
                else:
                    print(f"    ✓ Chain height ≥ {int(timeout):,} — refund is broadcastable")
        else:
            print(f"\n    ℹ Install httpx to check block height (pip install httpx)")

        print(f"\n[3] Fee rate in sat/byte for size estimate (default {DEFAULT_FEE_RATE}):")
        fr = input("    > ").strip()
        fee_rate = int(fr) if fr.isdigit() and int(fr) > 0 else DEFAULT_FEE_RATE

        print(f"\n[4] Building P2SH HTLC refund transaction (legacy, not Taproot PSBT)…")
        try:
            tx, redeem, dlc_val, fee, out_val, net, bch_p2pkh_out = build_p2sh_htlc_refund_unsigned(kit, fee_rate)
        except Exception as e:
            print(f"  ✗ Build failed: {e}")
            return

        print(f"    ✓ Est. fee: ~{fee} sats (~{fee_rate} sat/byte × {P2SH_HTLC_REFUND_VSIZE} vB)")
        print(f"    ✓ Output: {out_val:,} sats → {kit.get('user_address_from', '?')}")
        if bch_p2pkh_out:
            print(
                "    ℹ Refund output uses **P2PKH** (standard BCH/eCash relay). "
                "Same key as your Taproot CashAddr — spend with the same private key; "
                "your wallet may show a `q…` / legacy-style address for this UTXO."
            )
        print(f"    ✓ nLockTime: {int(timeout)}  sighash: {'BCH replay (ALL|FORKID)' if use_bch else 'legacy ECDSA'}")
        print(f"\n    Use the private key for the HTLC **sender** (refund) path — must match pubkey in redeem script.")

        print(f"\n[5] Private key (WIF or 64-char hex):")
        key_input = input("    > ").strip()
        try:
            key_bytes, _xo = parse_private_key(key_input)
        except Exception as e:
            print(f"  ✗ {e}")
            return

        print(f"\n[6] Signing…")
        try:
            raw_hex = sign_p2sh_htlc_refund_tx(tx, redeem, dlc_val, net, key_bytes)
        except Exception as e:
            print(f"  ✗ {e}")
            return

        txid_guess = hashlib.sha256(hashlib.sha256(bytes.fromhex(raw_hex)).digest()).digest()[::-1].hex()
        print(f"\n{'─' * 60}")
        print(f"  Signed refund transaction ({len(raw_hex) // 2} bytes)")
        print(f"{'─' * 60}")
        print(raw_hex)
        print(f"{'─' * 60}")
        print(f"  TXID (expected): {txid_guess}")

        print(f"\n[7] Broadcast to {NETWORKS[net]['name']}? (y/n)")
        if input("    > ").strip().lower() == "y":
            _do_broadcast(raw_hex, net)
        else:
            print(f"    Skipped.")
        return

    # ── Taproot DLC A refund (standard PSBT) ──
    net = normalize_signer_network(kit.get('from_chain', 'btc'))

    # Block height check
    if HAS_HTTPX:
        height = get_block_height(net)
        if height:
            print(f"\n    Current {net.upper()} block height: {height:,}")
            if timeout and height < timeout:
                remaining = timeout - height
                print(f"    ⚠ Timeout at block {timeout:,} — {remaining:,} blocks away")
                print(f"      You can sign now, but broadcast will fail until block {timeout:,}")
            else:
                print(f"    ✓ Timeout {timeout:,} reached — refund is immediately broadcastable")
    else:
        print(f"\n    ℹ Install httpx to check block height (pip install httpx)")

    # Fee rate
    print(f"\n[3] Fee rate in sat/vB (default {DEFAULT_FEE_RATE}):")
    fr = input("    > ").strip()
    fee_rate = int(fr) if fr.isdigit() and int(fr) > 0 else DEFAULT_FEE_RATE

    # Build
    print(f"\n[4] Building refund PSBT…")
    try:
        psbt_hex, fee, out_val = build_refund_psbt(kit, fee_rate)
        print(f"    ✓ Fee: {fee} sats ({fee_rate} sat/vB)")
        print(f"    ✓ Output: {out_val:,} sats → {kit.get('user_address_from', '?')}")
        print(f"    ✓ nLockTime: {timeout} (valid after this block)")
    except Exception as e:
        print(f"  ✗ Build failed: {e}"); return

    _sign_and_broadcast(psbt_hex, net, 'refund')


def _build_sign_claim(kit: Dict):
    """Build claim PSBT from kit descriptor data (v1 co-sign or v2 adaptor), finalize, broadcast."""
    if _is_v2_kit(kit):
        _build_sign_v2_claim(kit)
        return

    net = normalize_signer_network(kit.get('to_chain', 'fb'))

    print(f"\n[3] Fee rate in sat/vB (default {DEFAULT_FEE_RATE}):")
    fr = input("    > ").strip()
    fee_rate = int(fr) if fr.isdigit() and int(fr) > 0 else DEFAULT_FEE_RATE

    print(f"\n[4] Building claim PSBT with pre-signed adaptor…")
    try:
        psbt_hex, fee, out_val = build_claim_psbt(kit, fee_rate)
        print(f"    ✓ Fee: {fee} sats ({fee_rate} sat/vB)")
        print(f"    ✓ Output: {out_val:,} sats → {kit.get('user_address_to', '?')}")
        print(f"    ✓ Adaptor signature pre-embedded — only your receiver key needed")
    except Exception as e:
        print(f"  ✗ Build failed: {e}"); return

    _sign_and_broadcast(psbt_hex, net, 'claim')


def _build_sign_v2_claim(kit: Dict):
    """v2 adaptor claim: complete signature locally, finalize 3-item witness, broadcast."""
    net = normalize_signer_network(kit.get('to_chain', 'fb'))
    try:
        expected_recv = _v2_expected_receiver_xonly(kit)
    except Exception as e:
        print(f"  ✗ {e}"); return

    print(f"\n    v2 claim — receiver x-only pubkey: {expected_recv.hex()[:16]}…")
    print(f"    (Must match the private key you enter below.)")

    claim_privkey = None
    if not (kit.get('receiver_ephemeral_privkey') or kit.get('ephemeral_privkey')):
        print(f"\n[3] Claim private key (WIF or 64-char hex) — NOT your DGB funding key:")
        print(f"    This is the key for FB claim leg receiver_pubkey above.")
        print(f"    Use the ephemeral key from your Recovery Kit, or your FB wallet key if")
        print(f"    that pubkey matches your UniSat/OKX FB Taproot key.")
        key_input = input("    > ").strip()
        try:
            claim_privkey, my_x = parse_private_key(key_input)
            if my_x != expected_recv:
                print(f"  ✗ Key mismatch: yours {my_x.hex()[:16]}… expected {expected_recv.hex()[:16]}…")
                return
            print(f"    ✓ Key matches receiver_pubkey")
        except Exception as e:
            print(f"  ✗ {e}"); return
        fr_step = "[4]"
        build_step = "[5]"
        broadcast_step = "[6]"
    else:
        fr_step = "[3]"
        build_step = "[4]"
        broadcast_step = "[5]"

    print(f"\n{fr_step} Fee rate in sat/vB (default {DEFAULT_FEE_RATE}):")
    fr = input("    > ").strip()
    fee_rate = int(fr) if fr.isdigit() and int(fr) > 0 else DEFAULT_FEE_RATE

    print(f"\n{build_step} Building v2 adaptor claim (presign → complete → embed sig)…")
    try:
        psbt_hex, fee, out_val = build_v2_claim_psbt(kit, fee_rate, claim_privkey=claim_privkey)
        print(f"    ✓ Fee: {fee} sats ({fee_rate} sat/vB)")
        print(f"    ✓ Output: {out_val:,} sats → {kit.get('user_address_to', '?')}")
        print(f"    ✓ Completed BIP-340 signature embedded in PSBT")
    except Exception as e:
        print(f"  ✗ Build failed: {e}"); return

    print(f"\n{build_step}b Finalizing signed transaction…")
    raw_hex, result = finalize_presigned_v2_psbt(psbt_hex)
    if not raw_hex:
        print(f"  ✗ Finalize failed: {result}"); return

    print(f"\n{'─' * 60}")
    print(f"  Signed v2 claim transaction ({len(raw_hex) // 2} bytes)")
    print(f"{'─' * 60}")
    print(raw_hex)
    print(f"{'─' * 60}")
    print(f"  TXID: {result}")

    print(f"\n{broadcast_step} Broadcast to {NETWORKS[net]['name']}? (y/n)")
    if input("    > ").strip().lower() == 'y':
        _do_broadcast(raw_hex, net)
    else:
        print("    Skipped. Broadcast manually or via the bridge finalize endpoint.")


def finalize_presigned_v2_psbt(psbt_hex: str) -> Tuple[Optional[str], str]:
    """Finalize a v2 claim PSBT that already has the completed tapscript signature."""
    tx, inputs = parse_psbt(bytes.fromhex(psbt_hex))
    witnesses = {}
    signed = 0
    for idx, pinp in enumerate(inputs):
        for cb, script, leaf_ver in pinp.leaves:
            info = analyze_script(script)
            if info.get('type') != 'v2_claim':
                continue
            lh = tap_leaf_hash(script, leaf_ver)
            recv_pk = info['receiver_pubkey']
            sig = pinp.tap_script_sigs.get((recv_pk, lh))
            if not sig:
                return None, "PSBT missing completed v2 claim signature"
            witnesses[idx] = [sig, script, cb]
            signed += 1
            break
    if signed == 0:
        return None, "No v2 claim leaf found in PSBT"
    raw_tx = tx.raw(witnesses)
    txid = hashlib.sha256(hashlib.sha256(tx.raw()).digest()).digest()[::-1].hex()
    return raw_tx.hex(), txid


def _sign_and_broadcast(psbt_hex: str, net: str, action_type: str):
    """Parse → show analysis → get key → sign → optionally broadcast."""
    net = normalize_signer_network(net)
    if net not in NETWORKS:
        print(f"  ✗ Unknown network '{net}' — use btc, fb, ltc, bel, dgb, grs, bch, xec, rvn, zec, or doge")
        return
    # Quick analysis
    try:
        tx, inputs = parse_psbt(bytes.fromhex(psbt_hex))
        print(f"\n    PSBT: {len(inputs)} input(s), {len(tx.outs)} output(s)")
        if tx.locktime > 0:
            print(f"    nLockTime: {tx.locktime:,}")
        for idx, pinp in enumerate(inputs):
            print(f"    Input {idx}: {pinp.utxo_value:,} sats")
            for cb, scr, lv in pinp.leaves:
                info = analyze_script(scr)
                print(f"      {info['description']}")
                if info['type'] == 'claim':
                    lh = tap_leaf_hash(scr, lv)
                    if pinp.tap_script_sigs.get((info['adaptor_point'], lh)):
                        print(f"      ✓ Adaptor sig: pre-embedded")
    except Exception as e:
        print(f"  ✗ Bad PSBT: {e}"); return

    # Private key
    print(f"\n[5] Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        key_bytes, my_xonly = parse_private_key(key_input)
        print(f"    ✓ xonly: {my_xonly.hex()[:16]}…")
    except Exception as e:
        print(f"  ✗ {e}"); return

    # Sign
    print(f"\n[6] Signing…")
    raw_hex, result = sign_and_finalize(psbt_hex, key_bytes, network=net)
    if not raw_hex:
        print(f"\n  ✗ Failed: {result}"); return

    print(f"\n{'─' * 60}")
    print(f"  Signed {action_type} transaction ({len(raw_hex)//2} bytes)")
    print(f"{'─' * 60}")
    print(raw_hex)
    print(f"{'─' * 60}")
    print(f"  TXID: {result}")

    # Broadcast
    print(f"\n[7] Broadcast to {NETWORKS[net]['name']}? (y/n)")
    if input("    > ").strip().lower() == 'y':
        _do_broadcast(raw_hex, net)
    else:
        print(f"    Skipped. You can broadcast later using:")
        print(f"    curl -X POST {NETWORKS[net]['broadcast_url']} -d '<raw_hex>'")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def mode_sign_bip322():
    """Sign a BIP-322 message (Taproot simple witness, or Zcash transparent full-tx). Usage: python signer.py sign-bip322 <message>"""
    if len(sys.argv) < 3:
        print("Usage: python signer.py sign-bip322 <message>")
        print("  Message is the exact string to sign (e.g. addrFrom|addrTo|hCommit|ts)")
        sys.exit(1)
    message = " ".join(sys.argv[2:])  # Allow message with spaces
    print(f"\n  BIP-322 sign mode")
    print(f"  Message ({len(message)} chars): {message[:60]}{'…' if len(message) > 60 else ''}")
    print(f"\n  Address (Taproot: dgb1 / grs1 / ltc1 / bel1 / rvn1 / doge1 / ecash / bitcoincash / bc1p — or Zcash transparent t1 / t3):")
    addr = input("    > ").strip()
    print(f"\n  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        key_bytes, _ = parse_private_key(key_input)
    except Exception as e:
        print(f"  ✗ Invalid key: {e}")
        sys.exit(1)
    try:
        if addr.startswith("t1") or addr.startswith("t3"):
            sig_b64 = sign_bip322_zec_transparent(message, key_bytes, addr)
        else:
            scriptpubkey = address_to_scriptpubkey(addr)
            sig_b64 = sign_bip322_message(message, key_bytes, scriptpubkey)
        print(f"\n  Signature (base64):")
        print(sig_b64)
    except Exception as e:
        print(f"  ✗ Sign failed: {e}")
        sys.exit(1)


def mode_derive_btc():
    """Derive BTC Taproot address from private key. Usage: python signer.py derive-btc"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive BTC (Taproot) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_btc_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_fb():
    """Derive Fractal Bitcoin Taproot address from private key. Usage: python signer.py derive-fb"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive FB (Fractal Bitcoin Taproot) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_fb_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_dgb():
    """Derive DGB address and pubkey from private key. Usage: python signer.py derive-dgb"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive DGB address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_dgb_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_grs():
    """Derive GRS address and pubkey from private key. Usage: python signer.py derive-grs"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive GRS address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_grs_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_ltc():
    """Derive LTC Taproot address from private key. Usage: python signer.py derive-ltc"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive LTC (Taproot) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_ltc_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_bel():
    """Derive BEL Taproot address from private key. Usage: python signer.py derive-bel"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive Bellscoin (Taproot) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_bel_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_bch():
    """Derive BCH Taproot CashAddr from private key. Usage: python signer.py derive-bch"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    if not HAS_BCH_CASHADDR:
        print("✗ bitcash required for BCH: pip install bitcash")
        sys.exit(1)
    print("\n  Derive Bitcoin Cash (Taproot / CashAddr) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_bch_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_xec():
    """Derive eCash Taproot CashAddr from private key. Usage: python signer.py derive-xec"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    if not HAS_BCH_CASHADDR:
        print("✗ bitcash required for XEC: pip install bitcash")
        sys.exit(1)
    print("\n  Derive eCash (Taproot / ecash: CashAddr) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_xec_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_rvn():
    """Derive Ravencoin Taproot address from private key. Usage: python signer.py derive-rvn"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive Ravencoin (Taproot / rvn1) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_rvn_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def mode_derive_doge():
    """Derive Dogecoin Taproot address from private key. Usage: python signer.py derive-doge"""
    if not HAS_EMBIT:
        print("✗ embit required: pip install embit")
        sys.exit(1)
    if not HAS_BASE58:
        print("✗ base58 required: pip install base58")
        sys.exit(1)
    print("\n  Derive Dogecoin (Taproot / doge1) address from private key")
    print("  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        address, xonly_hex, compressed_hex = derive_doge_from_private_key(key_input)
        print(f"\n  Address:  {address}")
        print(f"  Pubkey (x-only, 64 hex):  {xonly_hex}")
        print(f"  Pubkey (compressed, 66 hex):  {compressed_hex}")
    except Exception as e:
        print(f"  ✗ {e}")
        sys.exit(1)


def main():
    # CLI mode: python signer.py derive-btc / derive-fb / derive-dgb / etc.
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-btc":
        mode_derive_btc()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-fb":
        mode_derive_fb()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-dgb":
        mode_derive_dgb()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-grs":
        mode_derive_grs()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-ltc":
        mode_derive_ltc()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-bel":
        mode_derive_bel()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-bch":
        mode_derive_bch()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-xec":
        mode_derive_xec()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-rvn":
        mode_derive_rvn()
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "derive-doge":
        mode_derive_doge()
        return
    # CLI mode: python signer.py sign-bip322 <message>
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "sign-bip322":
        if not HAS_EMBIT:
            print("✗ embit required: pip install embit")
            sys.exit(1)
        if not HAS_BASE58:
            print("✗ base58 required: pip install base58")
            sys.exit(1)
        mode_sign_bip322()
        return

    print(f"\n{'═' * 60}")
    print(f"  NexumBit Recovery & Signing Tool v{VERSION}")
    print(f"  Self-sovereign recovery for DLC bridge swaps")
    print(f"  + Cross-Chain DLC Lending PSBTs")
    print(f"{'═' * 60}")
    print(f"\n  Lending PSBT types (use mode [1] to sign):")
    print(f"    - repay          : Borrower reclaims collateral after repayment")
    print(f"    - lender-claim   : Oracle mode — co-sig in PSBT; you sign as lender")
    print(f"    - FAL hashlock   : Fractal attestation — paste 32-byte preimage when prompted")
    print(f"    - fixed-term     : CLTV lender leaf — signer uses refund-style path; respect nLockTime")
    print(f"    - safety-refund  : Borrower emergency exit after long timeout")

    if not HAS_EMBIT:
        print("\n  ✗ embit required: pip install embit"); sys.exit(1)
    if not HAS_BASE58:
        print("\n  ✗ base58 required: pip install base58"); sys.exit(1)
    if not HAS_HTTPX:
        print("  ℹ httpx not found — broadcasting disabled (pip install httpx)")

    print("\n  Select mode:")
    print("    [1] Sign existing PSBT (hex)")
    print("    [2] Recover from Recovery Kit (JSON)")
    print("    [3] Sign BIP-322 message (quotes)")
    print("    [4] Derive BTC Taproot address from private key")
    print("    [5] Derive FB  Taproot address from private key")
    print("    [6] Derive DGB Taproot address from private key")
    print("    [7] Derive GRS Taproot address from private key")
    print("    [8] Derive LTC Taproot address from private key")
    print("    [9] Derive BEL Taproot address from private key")
    print("    [10] Derive BCH Taproot (CashAddr) address from private key")
    print("    [11] Derive XEC Taproot (ecash: CashAddr) address from private key")
    print("    [12] Derive RVN Taproot (rvn1) address from private key")
    print("    [13] Derive DOGE Taproot (doge1) address from private key")

    mode = input("\n  > ").strip()
    if mode == '1':
        mode_sign_psbt()
    elif mode == '2':
        mode_recovery_kit()
    elif mode == '3':
        sys.argv = [sys.argv[0], "sign-bip322"] + [input("  Message to sign: ").strip()]
        mode_sign_bip322()
    elif mode == '4':
        mode_derive_btc()
    elif mode == '5':
        mode_derive_fb()
    elif mode == '6':
        mode_derive_dgb()
    elif mode == '7':
        mode_derive_grs()
    elif mode == '8':
        mode_derive_ltc()
    elif mode == '9':
        mode_derive_bel()
    elif mode == '10':
        mode_derive_bch()
    elif mode == '11':
        mode_derive_xec()
    elif mode == '12':
        mode_derive_rvn()
    elif mode == '13':
        mode_derive_doge()
    else:
        print(f"  ✗ Unknown mode '{mode}'")

    print()


if __name__ == "__main__":
    main()