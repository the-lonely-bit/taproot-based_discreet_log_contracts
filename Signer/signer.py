#!/usr/bin/env python3
"""
NexumBit Recovery & Signing Tool v2.0

Self-sovereign recovery tool for NexumBit DLC bridge swaps.
Works independently of the NexumBit backend.

Two modes:
  [1] Sign an existing PSBT (hex input)
  [2] Build + Sign from Recovery Kit (JSON file or paste)

Supports:
  - Taproot script-path claim (pre-signed or manual adaptor signature; same shape as oracle co-sign + lender)
  - FAL hashlock lender claim (OP_SHA256 preimage + lender Schnorr — mode [1] prompts for 32-byte preimage)
  - Taproot script-path refund (CLTV + single key), including fixed-term lender leaf and safety refund
  - Private key input: WIF or raw 64-char hex
  - Broadcasting to Bitcoin / Fractal Bitcoin / Litecoin / Bellscoin / DigiByte / Groestlcoin networks

Dependencies: pip install embit base58 httpx
  - segwit_addr.py (bundled): DGB/GRS/LTC/BEL address support (dgb1, grs1, ltc1, bel1)
  - embit:  Required (Schnorr signatures, key derivation)
  - base58: Required (WIF decoding)
  - httpx:  Optional (broadcasting — can broadcast manually without it)

Usage:  python signer.py
"""

import sys
import os
import json
import hashlib
import struct
import base64
from io import BytesIO
from typing import Optional, Tuple, Dict, List, Any

try:
    from embit.ec import PrivateKey, PublicKey
    from embit import script as embit_script
    HAS_EMBIT = True
except ImportError:
    HAS_EMBIT = False

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

# Local segwit_addr for DGB/GRS/LTC/BEL (dgb1, grs1, ltc1, bel1) — always available
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
}

LOCKTIME_SEQUENCE = 0xFFFFFFFE   # Enable nLockTime
DEFAULT_FEE_RATE  = 5            # sat/vB — conservative default
TAPROOT_SCRIPT_VSIZE = 180       # Estimated vsize for 1-in-1-out Taproot script-path spend


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


def tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def tap_leaf_hash(script: bytes, leaf_ver: int = 0xC0) -> bytes:
    buf = struct.pack('B', leaf_ver) + write_compact(len(script)) + script
    return tagged_hash("TapLeaf", buf)


def tap_branch_hash(a: bytes, b: bytes) -> bytes:
    if a > b: a, b = b, a
    return tagged_hash("TapBranch", a + b)


def tap_tweak(internal_key: bytes, merkle_root: bytes) -> bytes:
    return tagged_hash("TapTweak", internal_key + merkle_root)


def address_to_scriptpubkey(addr: str) -> bytes:
    """
    Convert address to raw scriptpubkey bytes.
    Supports: bc1, tb1 (embit), dgb1, grs1, ltc1, bel1 (segwit_addr for Taproot).
    """
    addr_lower = addr.strip().lower()
    # Alt-chain bech32m (dgb1, grs1, ltc1, bel1)
    if HAS_SEGWIT_ADDR:
        for hrp in ("dgb", "grs", "ltc", "bel"):
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
        if addr_lower.startswith(("dgb1", "grs1", "ltc1", "bel1")):
            raise ValueError(
                f"DGB/GRS/LTC/BEL address detected but segwit_addr module not found. "
                f"Ensure segwit_addr.py is in the same directory as signer.py."
            ) from None
        raise


# ═══════════════════════════════════════════════════════════════
# Key handling
# ═══════════════════════════════════════════════════════════════

def decode_wif(wif: str) -> Tuple[bytes, bool]:
    """
    Decode WIF to (32-byte secret, compressed).
    Supports: Bitcoin/FB mainnet (0x80), testnet (0xEF), DGB/GRS mainnet (0x80).
    """
    raw = base58.b58decode_check(wif)
    if raw[0] in (0x80, 0xEF):
        if len(raw) == 34 and raw[-1] == 0x01: return raw[1:33], True
        if len(raw) == 33: return raw[1:33], False
    raise ValueError(f"Invalid WIF (version=0x{raw[0]:02x}, len={len(raw)})")


def parse_private_key(key_input: str) -> Tuple[bytes, bytes]:
    """
    Parse private key from WIF or raw hex.
    Returns (32-byte key, 32-byte x-only pubkey).
    """
    key_input = key_input.strip()

    # Try raw hex (64 chars = 32 bytes)
    if len(key_input) == 64:
        try:
            key_bytes = bytes.fromhex(key_input)
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

    raise ValueError("Invalid key. Provide WIF (starts with K/L/5) or 64-char raw hex.")


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


def parse_psbt(data: bytes) -> Tuple[Tx, List[PInput]]:
    """Parse PSBT v0. Returns (unsigned_tx, list_of_inputs)."""
    s = BytesIO(data)
    if s.read(5) != b'psbt\xff':
        raise ValueError("Bad PSBT magic")
    tx = None
    # Global map
    while True:
        kl = read_compact(s)
        if kl == 0: break
        k = s.read(kl); vl = read_compact(s); v = s.read(vl)
        if k[0] == 0x00: tx = Tx.parse(v)
    if not tx:
        raise ValueError("Missing unsigned tx in PSBT")
    # Per-input maps
    inputs = []
    for _ in range(len(tx.ins)):
        p = PInput()
        while True:
            kl = read_compact(s)
            if kl == 0: break
            k = s.read(kl); vl = read_compact(s); v = s.read(vl)
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
            if kl == 0: break
            s.read(kl); vl = read_compact(s); s.read(vl)
    return tx, inputs


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

    # Success: <32> OP_CHECKSIGVERIFY <32> OP_CHECKSIG
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


def sign_and_finalize(psbt_hex: str, key_bytes: bytes,
                      adaptor_key_bytes: Optional[bytes] = None,
                      preimage: Optional[bytes] = None) -> Tuple[Optional[str], str]:
    """
    Sign a PSBT and finalize it into a raw transaction.
    For FAL hashlock lender claims, pass the 32-byte attestation preimage as ``preimage``.
    Returns (raw_tx_hex, txid) on success, or (None, error_msg).
    """
    tx, inputs = parse_psbt(bytes.fromhex(psbt_hex))
    my_xonly = PrivateKey(key_bytes).get_public_key().xonly()

    adaptor_xonly = None
    if adaptor_key_bytes:
        adaptor_xonly = PrivateKey(adaptor_key_bytes).get_public_key().xonly()

    witnesses = {}
    signed = 0

    for idx, pinp in enumerate(inputs):
        if not pinp.leaves:
            print(f"  · Input {idx}: no taproot leaf scripts — skipping")
            continue

        for cb, script, leaf_ver in pinp.leaves:
            info = analyze_script(script)
            print(f"  · Input {idx}: {info['description']}")

            lh = tap_leaf_hash(script, leaf_ver)
            msg = sighash_script_path(tx, idx, inputs, lh)
            print(f"    leaf_hash: {lh.hex()[:24]}…")
            print(f"    sighash:   {msg.hex()[:24]}…")

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

    scriptpubkey = bytes.fromhex(desc['scriptpubkey'])
    refund_script = bytes.fromhex(desc['refund_script'])
    refund_cb     = bytes.fromhex(desc['refund_control_block'])
    internal_key  = bytes.fromhex(desc['internal_pubkey'])
    merkle_root   = bytes.fromhex(desc['merkle_root'])
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
    tx.ins = [TxIn(bytes.fromhex(dlc['txid'])[::-1], vout, b'', LOCKTIME_SEQUENCE)]
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

    scriptpubkey = bytes.fromhex(desc['scriptpubkey'])
    success_script = bytes.fromhex(desc['success_script'])
    success_cb     = bytes.fromhex(desc['success_control_block'])
    internal_key   = bytes.fromhex(desc['internal_pubkey'])
    merkle_root    = bytes.fromhex(desc['merkle_root'])
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
    tx.ins = [TxIn(bytes.fromhex(dlc['txid'])[::-1], vout, b'', LOCKTIME_SEQUENCE)]
    tx.outs = [TxOut(output_value, receiver_spk)]

    # Pre-sign adaptor signature
    leaf_hash = tap_leaf_hash(success_script, leaf_ver)
    temp_inp = PInput()
    temp_inp.utxo_value = dlc_value
    temp_inp.utxo_spk = scriptpubkey
    sighash = sighash_script_path(tx, 0, [temp_inp], leaf_hash)

    adaptor_key_bytes = bytes.fromhex(adaptor_secret_hex)
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


# ═══════════════════════════════════════════════════════════════
# Network helpers
# ═══════════════════════════════════════════════════════════════

def _broadcast_one(raw_hex: str, url: str) -> str:
    """Broadcast to a single URL. Returns txid on success."""
    r = httpx.post(url, content=raw_hex, headers={"Content-Type": "text/plain"}, timeout=30)
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
    last_err = None
    for url in urls:
        try:
            return _broadcast_one(raw_hex, url)
        except Exception as e:
            err_str = str(e)
            last_err = e
            # Taproot rejection: try next endpoint
            if "soft-fork" in err_str or "Witness version reserved" in err_str or "code 64" in err_str:
                continue
            raise
    raise last_err or RuntimeError("Broadcast failed")


def get_block_height(network: str) -> Optional[int]:
    """Fetch current block height. Returns None on failure."""
    try:
        cfg = NETWORKS[network]
        r = httpx.get(cfg["height_url"], timeout=10)
        if r.status_code == 200:
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
            print(f"      curl -X POST {u} -d '<raw_hex>'")
        if net == "dgb":
            print(f"    Or set DGB_BROADCAST_URL to a Taproot-supporting endpoint (DigiByte Core 8.23+)")
        if net == "grs":
            print(f"    Or set GRS_BROADCAST_URL to a Taproot-supporting endpoint")
        if net == "bel":
            print(f"    Or set BEL_BROADCAST_URL to another electrs-compatible /tx endpoint")
        if net == "ltc":
            print(f"    Or set LTC_BROADCAST_URL to another mempool-style /tx endpoint")


# ═══════════════════════════════════════════════════════════════
# Mode 1 — Sign existing PSBT
# ═══════════════════════════════════════════════════════════════

def mode_sign_psbt():
    """Interactive: sign an existing PSBT from hex."""
    # Network
    print("\n[1] Network (btc / fb / ltc / bel / dgb / grs):")
    net = input("    > ").strip().lower()
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
    raw_hex, result = sign_and_finalize(psbt_hex, key_bytes, adaptor_bytes, preimage_bytes)
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
                return kit
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
        return kit
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

    has_secret = bool(kit.get('adaptor_secret'))
    print(f"\n  Adaptor secret: {'✓ included' if has_secret else '✗ not included (not yet claim-eligible)'}")
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
    can_claim  = bool(dlc_b.get('txid') and dlc_b.get('descriptor') and kit.get('adaptor_secret'))

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
        net = kit.get('from_chain', 'btc').lower()
        print(f"\n    Using pre-built refund PSBT (network: {net.upper()})")
        _sign_and_broadcast(pre['refund_psbt_hex'], net, 'refund')
        return
    if action == 'SC' and has_pre_claim:
        net = kit.get('to_chain', 'fb').lower()
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
    net = kit.get('from_chain', 'btc').lower()
    timeout = kit.get('timeout_a') or (kit.get('dlc_a', {}).get('descriptor') or {}).get('timeout')

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
    """Build claim PSBT from kit descriptor data (with adaptor), sign, broadcast."""
    net = kit.get('to_chain', 'fb').lower()

    # Fee rate
    print(f"\n[3] Fee rate in sat/vB (default {DEFAULT_FEE_RATE}):")
    fr = input("    > ").strip()
    fee_rate = int(fr) if fr.isdigit() and int(fr) > 0 else DEFAULT_FEE_RATE

    # Build
    print(f"\n[4] Building claim PSBT with pre-signed adaptor…")
    try:
        psbt_hex, fee, out_val = build_claim_psbt(kit, fee_rate)
        print(f"    ✓ Fee: {fee} sats ({fee_rate} sat/vB)")
        print(f"    ✓ Output: {out_val:,} sats → {kit.get('user_address_to', '?')}")
        print(f"    ✓ Adaptor signature pre-embedded — only your receiver key needed")
    except Exception as e:
        print(f"  ✗ Build failed: {e}"); return

    _sign_and_broadcast(psbt_hex, net, 'claim')


def _sign_and_broadcast(psbt_hex: str, net: str, action_type: str):
    """Parse → show analysis → get key → sign → optionally broadcast."""
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
    raw_hex, result = sign_and_finalize(psbt_hex, key_bytes)
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
    """Sign a BIP-322 message for Taproot (P2TR) address. Usage: python signer.py sign-bip322 <message>"""
    if len(sys.argv) < 3:
        print("Usage: python signer.py sign-bip322 <message>")
        print("  Message is the exact string to sign (e.g. addrFrom|addrTo|hCommit|ts)")
        sys.exit(1)
    message = " ".join(sys.argv[2:])  # Allow message with spaces
    print(f"\n  BIP-322 sign mode")
    print(f"  Message ({len(message)} chars): {message[:60]}{'…' if len(message) > 60 else ''}")
    print(f"\n  Taproot address (dgb1... / grs1... / ltc1... / bel1... / bc1p...):")
    addr = input("    > ").strip()
    print(f"\n  Private key (WIF or 64-char hex):")
    key_input = input("    > ").strip()
    try:
        scriptpubkey = address_to_scriptpubkey(addr)
    except Exception as e:
        print(f"  ✗ Invalid address: {e}")
        sys.exit(1)
    try:
        key_bytes, _ = parse_private_key(key_input)
    except Exception as e:
        print(f"  ✗ Invalid key: {e}")
        sys.exit(1)
    try:
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
    else:
        print(f"  ✗ Unknown mode '{mode}'")

    print()


if __name__ == "__main__":
    main()
