"""
Protocol v2 DLC builder — genuine BIP-340 adaptor-signature swaps.

Supersedes deprecated v1 ``dlc_builder.build_dlc`` (coordinator 2-of-2 co-sign path).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

from dlc_builder.script import build_dlc_refund_script, tagged_hash
from dlc_builder.taproot import (
    TAPROOT_LEAF_VERSION,
    compute_merkle_proof,
    create_control_block,
    taproot_address_from_pubkey,
    taproot_leaf_hash,
    taproot_output_script,
    taproot_tree_helper,
    taproot_tweak_pubkey,
)

from .script import build_dlc_v2_claim_script

# BIP-341 suggested NUMS point (no known discrete log).
NUMS_X = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)


@dataclass
class DLCv2Descriptor:
    """Everything needed to fund, claim, or refund a v2 DLC output."""

    version: int
    receiver_pubkey: str
    sender_pubkey: str
    adaptor_point: Optional[str]
    timeout: int
    internal_pubkey: str
    merkle_root: str
    output_pubkey: str
    output_key_parity: int
    claim_script: str
    refund_script: str
    claim_leaf_hash: str
    refund_leaf_hash: str
    claim_control_block: str
    refund_control_block: str
    address: str
    scriptpubkey: str

    def to_dict(self) -> dict:
        return asdict(self)


def generate_adaptor_secret() -> Tuple[str, str]:
    """Return (32-byte secret hex, 33-byte compressed adaptor point hex)."""
    from .adaptor_sig import point_from_secret

    secret = secrets.token_bytes(32)
    return secret.hex(), point_from_secret(secret).hex()


def _normalize_xonly(pubkey_hex: str) -> str:
    pubkey_hex = pubkey_hex.strip().lower()
    if len(pubkey_hex) == 64:
        return pubkey_hex
    if len(pubkey_hex) == 66 and pubkey_hex[:2] in ("02", "03"):
        return pubkey_hex[2:]
    raise ValueError(
        f"Invalid pubkey length: {len(pubkey_hex)} (expected 64 or 66 hex chars)"
    )


def _normalize_adaptor_point(point_hex: str) -> str:
    point_hex = point_hex.strip().lower()
    if len(point_hex) != 66 or point_hex[:2] not in ("02", "03"):
        raise ValueError("adaptor_point must be 66 hex chars compressed (02/03 prefix)")
    return point_hex


def _point_add_xonly(a_xonly: bytes, b_compressed: bytes) -> Tuple[bytes, int]:
    try:
        from coincurve import PublicKey

        a = PublicKey(b"\x02" + a_xonly)
        b = PublicKey(b_compressed)
        q = PublicKey.combine_keys([a, b]).format(compressed=True)
        return q[1:], q[0] - 2
    except ImportError:
        from .adaptor_sig import _parse_point, _point_add, _ser_compressed

        a = _parse_point(b"\x02" + a_xonly)
        b = _parse_point(b_compressed)
        q = _point_add(a, b)
        sec = _ser_compressed(q)
        return sec[1:], sec[0] - 2


def derive_unspendable_internal_key(
    claim_leaf_hash: bytes, refund_leaf_hash: bytes
) -> bytes:
    return derive_unspendable_internal_key_multi(claim_leaf_hash, refund_leaf_hash)


def derive_unspendable_internal_key_multi(*leaf_hashes: bytes) -> bytes:
    """internal = NUMS + r·G, r = TaggedHash('NexumDLCv2/internal', leaves)."""
    if not leaf_hashes:
        raise ValueError("at least one leaf hash required")
    r = tagged_hash("NexumDLCv2/internal", b"".join(leaf_hashes))
    try:
        from coincurve import PrivateKey

        r_point = PrivateKey(r).public_key.format(compressed=True)
    except ImportError:
        from embit import ec

        r_point = ec.PrivateKey(r).get_public_key().serialize()
    internal_xonly, _ = _point_add_xonly(NUMS_X, r_point)
    return internal_xonly


def build_dlc_v2(
    *,
    receiver_pubkey_hex: str,
    sender_pubkey_hex: str,
    adaptor_point_hex: Optional[str] = None,
    timeout: int,
    network: str = "mainnet",
    hrp: Optional[str] = None,
) -> DLCv2Descriptor:
    """
    Build a v2 DLC descriptor (address + scripts + control blocks).

    ``adaptor_point_hex`` is optional: T does not affect the address/scripts.
    """
    receiver_xonly_hex = _normalize_xonly(receiver_pubkey_hex)
    sender_xonly_hex = _normalize_xonly(sender_pubkey_hex)
    adaptor_point_hex = (
        _normalize_adaptor_point(adaptor_point_hex) if adaptor_point_hex else None
    )
    if timeout < 0:
        raise ValueError(f"timeout must be non-negative, got {timeout}")

    receiver_xonly = bytes.fromhex(receiver_xonly_hex)
    sender_xonly = bytes.fromhex(sender_xonly_hex)

    claim_script = build_dlc_v2_claim_script(receiver_xonly)
    refund_script = build_dlc_refund_script(timeout, sender_xonly)

    merkle_root, leaf_hashes = taproot_tree_helper([claim_script, refund_script])
    claim_leaf_hash, refund_leaf_hash = leaf_hashes[0], leaf_hashes[1]

    if claim_leaf_hash != taproot_leaf_hash(claim_script, TAPROOT_LEAF_VERSION):
        raise ValueError("claim leaf hash mismatch")
    if refund_leaf_hash != taproot_leaf_hash(refund_script, TAPROOT_LEAF_VERSION):
        raise ValueError("refund leaf hash mismatch")

    internal_pubkey = derive_unspendable_internal_key(claim_leaf_hash, refund_leaf_hash)
    output_pubkey, output_key_parity = taproot_tweak_pubkey(internal_pubkey, merkle_root)
    scriptpubkey = taproot_output_script(output_pubkey)
    if hrp:
        address = taproot_address_from_pubkey(output_pubkey, hrp=hrp)
    else:
        address = taproot_address_from_pubkey(output_pubkey, network)

    claim_control_block = create_control_block(
        internal_pubkey,
        claim_script,
        compute_merkle_proof(claim_leaf_hash, leaf_hashes),
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=output_key_parity,
    )
    refund_control_block = create_control_block(
        internal_pubkey,
        refund_script,
        compute_merkle_proof(refund_leaf_hash, leaf_hashes),
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=output_key_parity,
    )

    return DLCv2Descriptor(
        version=2,
        receiver_pubkey=receiver_xonly_hex,
        sender_pubkey=sender_xonly_hex,
        adaptor_point=adaptor_point_hex,
        timeout=timeout,
        internal_pubkey=internal_pubkey.hex(),
        merkle_root=merkle_root.hex(),
        output_pubkey=output_pubkey.hex(),
        output_key_parity=output_key_parity,
        claim_script=claim_script.hex(),
        refund_script=refund_script.hex(),
        claim_leaf_hash=claim_leaf_hash.hex(),
        refund_leaf_hash=refund_leaf_hash.hex(),
        claim_control_block=claim_control_block.hex(),
        refund_control_block=refund_control_block.hex(),
        address=address,
        scriptpubkey=scriptpubkey.hex(),
    )
