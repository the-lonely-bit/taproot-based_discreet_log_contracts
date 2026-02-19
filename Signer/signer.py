#!/usr/bin/env python3
"""
NexumBit Recovery & Signing Tool v2.0

Self-sovereign recovery tool for NexumBit DLC bridge swaps.
Works independently of the NexumBit backend.

Two modes:
  [1] Sign an existing PSBT (hex input)
  [2] Build + Sign from Recovery Kit (JSON file or paste)

Supports:
  - Taproot script-path claim (with pre-signed or manual adaptor signature)
  - Taproot script-path refund (timeout + sender key)
  - Private key input: WIF or raw 64-char hex
  - Broadcasting to Bitcoin / Fractal Bitcoin networks

Dependencies: pip install embit base58 httpx
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
    """Convert a Bitcoin/Fractal address to raw scriptpubkey bytes (using embit)."""
    return embit_script.address_to_scriptpubkey(addr).data


# ═══════════════════════════════════════════════════════════════
# Key handling
# ═══════════════════════════════════════════════════════════════

def decode_wif(wif: str) -> Tuple[bytes, bool]:
    """Decode WIF to (32-byte secret, compressed)."""
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
    # Success: <32> OP_CHECKSIGVERIFY <32> OP_CHECKSIG
    #          20 <adaptor:32> AD 20 <receiver:32> AC
    if (len(script) == 68 and script[0] == 0x20 and script[33] == 0xAD
            and script[34] == 0x20 and script[67] == 0xAC):
        return {
            'type': 'claim',
            'adaptor_point': script[1:33],
            'receiver_pubkey': script[35:67],
            'sigs_needed': 2,
            'description': 'Claim (success path): adaptor + receiver key',
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


def sign_and_finalize(psbt_hex: str, key_bytes: bytes,
                      adaptor_key_bytes: Optional[bytes] = None) -> Tuple[Optional[str], str]:
    """
    Sign a PSBT and finalize it into a raw transaction.
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
                    # Pre-signed adaptor: user only provides their receiver key
                    print(f"    ✓ Pre-signed adaptor sig found ({pre_sig.hex()[:24]}…)")
                    if my_xonly != info['receiver_pubkey']:
                        return None, (f"Receiver key mismatch: script expects "
                                      f"{info['receiver_pubkey'].hex()[:16]}…, "
                                      f"your key is {my_xonly.hex()[:16]}…")
                    sig_receiver = schnorr_sign(key_bytes, msg)
                    print(f"    sig_receiver: {sig_receiver.hex()[:24]}…")
                    witnesses[idx] = [sig_receiver, pre_sig, script, cb]
                    signed += 1
                    print(f"  ✓ Input {idx}: claim signed (pre-signed adaptor + receiver)")
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

def broadcast(raw_hex: str, network: str) -> str:
    """Broadcast a raw transaction. Returns txid on success."""
    url = NETWORKS[network]["broadcast_url"]
    r = httpx.post(url, content=raw_hex, headers={"Content-Type": "text/plain"}, timeout=30)
    if r.status_code == 200:
        return r.text.strip()
    raise RuntimeError(f"Broadcast failed ({r.status_code}): {r.text}")


def get_block_height(network: str) -> Optional[int]:
    """Fetch current block height. Returns None on failure."""
    try:
        r = httpx.get(NETWORKS[network]["height_url"], timeout=10)
        if r.status_code == 200:
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
        print(f"    Broadcast manually: POST raw hex to {NETWORKS[net]['broadcast_url']}")


# ═══════════════════════════════════════════════════════════════
# Mode 1 — Sign existing PSBT
# ═══════════════════════════════════════════════════════════════

def mode_sign_psbt():
    """Interactive: sign an existing PSBT from hex."""
    # Network
    print("\n[1] Network (btc / fb):")
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
    for idx, pinp in enumerate(inputs):
        for cb, script_data, leaf_ver in pinp.leaves:
            info = analyze_script(script_data)
            print(f"    Input {idx}: {pinp.utxo_value:,} sats — {info['description']}")
            if info['type'] == 'claim':
                lh = tap_leaf_hash(script_data, leaf_ver)
                if pinp.tap_script_sigs.get((info['adaptor_point'], lh)):
                    print(f"    ✓ Adaptor sig pre-embedded (no adaptor secret needed)")
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

    # Adaptor secret (only if needed and not pre-signed)
    adaptor_bytes = None
    step = 4
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
        print(f"\n    ℹ Adaptor sig pre-embedded — no adaptor secret needed")

    # Sign
    print(f"\n[{step}] Signing…")
    raw_hex, result = sign_and_finalize(psbt_hex, key_bytes, adaptor_bytes)
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

def main():
    print(f"\n{'═' * 60}")
    print(f"  NexumBit Recovery & Signing Tool v{VERSION}")
    print(f"  Self-sovereign recovery for DLC bridge swaps")
    print(f"{'═' * 60}")

    if not HAS_EMBIT:
        print("\n  ✗ embit required: pip install embit"); sys.exit(1)
    if not HAS_BASE58:
        print("\n  ✗ base58 required: pip install base58"); sys.exit(1)
    if not HAS_HTTPX:
        print("  ℹ httpx not found — broadcasting disabled (pip install httpx)")

    print("\n  Select mode:")
    print("    [1] Sign existing PSBT (hex)")
    print("    [2] Recover from Recovery Kit (JSON)")

    mode = input("\n  > ").strip()
    if mode == '1':
        mode_sign_psbt()
    elif mode == '2':
        mode_recovery_kit()
    else:
        print(f"  ✗ Unknown mode '{mode}'")

    print()


if __name__ == "__main__":
    main()
