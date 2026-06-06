"""
Lending DLC Builder — 3-leaf collateral DLC for cross-chain lending.

Builds a Tapscript MAST tree with:
  Leaf 0: Repay          (v2: single-key + off-chain adaptor; v1: deprecated co-sign)
  Leaf 1: Lender Claim   (oracle + lender / FAL / fixed_term)
  Leaf 2: Safety Refund  (CLTV + borrower)
"""
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from dlc_v2_builder import derive_unspendable_internal_key_multi
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

from . import attestation as att_modes
from .lending_scripts import (
    build_lender_claim_hashlock_script,
    build_lender_claim_script,
    build_lender_claim_timelocked_script,
    build_lending_v2_repay_script,
    build_repay_script,
    build_safety_refund_script,
)
from .script_builder import tagged_hash

logger = logging.getLogger(__name__)


@dataclass
class LendingDLCDescriptor:
    """Complete descriptor for a 3-leaf collateral DLC."""

    borrower_pubkey: str
    lender_pubkey: str
    oracle_pubkey: str
    adaptor_point: str
    safety_timeout: int

    internal_pubkey: str
    internal_private_key: Optional[str]
    merkle_root: str
    output_pubkey: str
    output_key_parity: int

    repay_script: str
    lender_claim_script: str
    safety_script: str

    repay_leaf_hash: str
    lender_claim_leaf_hash: str
    safety_leaf_hash: str

    repay_control_block: str
    lender_claim_control_block: str
    safety_control_block: str

    address: str
    scriptpubkey: str

    repay_pubkey: str = ""
    attestation_mode: str = "oracle"
    attestation_hash_hex: str = ""
    lender_claim_cltv_height: int = 0


def _normalize_xonly(pubkey_hex: str, name: str) -> str:
    if len(pubkey_hex) == 64:
        return pubkey_hex
    if len(pubkey_hex) == 66 and pubkey_hex[:2] in ("02", "03"):
        return pubkey_hex[2:]
    raise ValueError(f"{name} invalid length {len(pubkey_hex)}")


def _derive_internal_pubkey(
    adaptor_point: bytes,
    borrower: bytes,
    lender: bytes,
    binding_key: bytes,
    timeout: int,
) -> Tuple[Optional[str], bytes]:
    """v1 internal key derivation (deprecated)."""
    if len(binding_key) != 32:
        raise ValueError("binding_key must be 32 bytes")
    unique_data = (
        adaptor_point + borrower + lender + binding_key + timeout.to_bytes(8, "big")
    )
    privkey_bytes = tagged_hash("LendingDLCKey", unique_data)
    try:
        from coincurve import PrivateKey

        pk = PrivateKey(privkey_bytes)
        compressed = pk.public_key.format(compressed=True)
        return privkey_bytes.hex(), compressed[1:]
    except Exception:
        pass
    try:
        from embit import ec

        pk = ec.PrivateKey(privkey_bytes)
        pub = pk.get_public_key().serialize()
        return privkey_bytes.hex(), pub[1:]
    except Exception:
        logger.error("Failed to derive lending DLC internal pubkey — using NUMS fallback")
        nums = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        return None, nums


def build_collateral_dlc(
    adaptor_point_hex: str,
    borrower_pubkey_hex: str,
    lender_pubkey_hex: str,
    oracle_pubkey_hex: str,
    safety_timeout: int,
    network: str = "mainnet",
    attestation_mode: str = "oracle",
    attestation_hash_hex: str = "",
    lender_claim_cltv_height: int = 0,
    *,
    protocol_version: int = 2,
    repay_pubkey_hex: str = "",
) -> LendingDLCDescriptor:
    """
    Build a 3-leaf collateral DLC for cross-chain lending.

    ``protocol_version`` 2 (default): v2 repay leaf + unspendable NUMS internal key.
    ``protocol_version`` 1: deprecated v1 repay co-sign (reference only).
    """
    if len(adaptor_point_hex) != 66 or adaptor_point_hex[:2] not in ("02", "03"):
        raise ValueError(f"adaptor_point must be 66 hex compressed pubkey, got {len(adaptor_point_hex)}")
    if safety_timeout < 0:
        raise ValueError(f"safety_timeout must be non-negative, got {safety_timeout}")
    if attestation_mode not in att_modes.VALID_MODES:
        raise ValueError(f"invalid attestation_mode: {attestation_mode}")

    borrower_hex = _normalize_xonly(borrower_pubkey_hex, "borrower_pubkey")
    repay_hex = _normalize_xonly(repay_pubkey_hex or borrower_pubkey_hex, "repay_pubkey")
    lender_hex = _normalize_xonly(lender_pubkey_hex, "lender_pubkey")
    oracle_hex = _normalize_xonly(oracle_pubkey_hex, "oracle_pubkey") if oracle_pubkey_hex else "0" * 64

    adaptor_point = bytes.fromhex(adaptor_point_hex)
    borrower = bytes.fromhex(borrower_hex)
    lender = bytes.fromhex(lender_hex)
    oracle = bytes.fromhex(oracle_hex)

    from embit.ec import PublicKey

    adaptor_xonly = PublicKey.parse(adaptor_point).xonly()

    if attestation_mode == att_modes.ORACLE:
        binding_key = oracle
        lender_claim = build_lender_claim_script(oracle, lender)
    elif attestation_mode == att_modes.FAL:
        if len(attestation_hash_hex) != 64:
            raise ValueError("FAL mode requires attestation_hash_hex (64 hex chars)")
        binding_key = bytes.fromhex(attestation_hash_hex)
        lender_claim = build_lender_claim_hashlock_script(binding_key, lender)
    elif attestation_mode == att_modes.FIXED_TERM:
        if lender_claim_cltv_height <= 0:
            raise ValueError("fixed_term mode requires positive lender_claim_cltv_height")
        import hashlib

        binding_key = hashlib.sha256(
            b"fixed_term" + lender + borrower + lender_claim_cltv_height.to_bytes(8, "big")
        ).digest()
        lender_claim = build_lender_claim_timelocked_script(lender_claim_cltv_height, lender)
    else:
        raise ValueError(f"unsupported attestation_mode: {attestation_mode}")

    if protocol_version >= 2:
        repay = build_lending_v2_repay_script(bytes.fromhex(repay_hex))
    else:
        repay = build_repay_script(adaptor_xonly, borrower)
    safety = build_safety_refund_script(safety_timeout, borrower)

    scripts = [repay, lender_claim, safety]
    merkle_root, leaf_hashes = taproot_tree_helper(scripts)
    repay_lh, claim_lh, safety_lh = leaf_hashes

    for i, (sc, lh) in enumerate(zip(scripts, leaf_hashes)):
        expected = taproot_leaf_hash(sc, TAPROOT_LEAF_VERSION)
        if lh != expected:
            raise ValueError(f"Leaf {i} hash mismatch")

    if protocol_version >= 2:
        int_priv_hex = None
        int_pub = derive_unspendable_internal_key_multi(repay_lh, claim_lh, safety_lh)
    else:
        int_priv_hex, int_pub = _derive_internal_pubkey(
            adaptor_point, borrower, lender, binding_key, safety_timeout
        )

    output_pubkey, parity = taproot_tweak_pubkey(int_pub, merkle_root)
    spk = taproot_output_script(output_pubkey)
    address = taproot_address_from_pubkey(output_pubkey, network)

    repay_proof = compute_merkle_proof(repay_lh, leaf_hashes)
    claim_proof = compute_merkle_proof(claim_lh, leaf_hashes)
    safety_proof = compute_merkle_proof(safety_lh, leaf_hashes)

    repay_cb = create_control_block(
        int_pub, repay, repay_proof,
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=parity,
    )
    claim_cb = create_control_block(
        int_pub, lender_claim, claim_proof,
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=parity,
    )
    safety_cb = create_control_block(
        int_pub, safety, safety_proof,
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=parity,
    )

    for name, cb in [("repay", repay_cb), ("claim", claim_cb), ("safety", safety_cb)]:
        if cb[0] not in (0xC0, 0xC1):
            raise ValueError(f"Invalid {name} control block header: 0x{cb[0]:02x}")

    return LendingDLCDescriptor(
        borrower_pubkey=borrower_hex,
        repay_pubkey=repay_hex,
        lender_pubkey=lender_hex,
        oracle_pubkey=oracle_hex,
        adaptor_point=adaptor_point_hex,
        safety_timeout=safety_timeout,
        attestation_mode=attestation_mode,
        attestation_hash_hex=attestation_hash_hex if attestation_mode == att_modes.FAL else "",
        lender_claim_cltv_height=lender_claim_cltv_height if attestation_mode == att_modes.FIXED_TERM else 0,
        internal_pubkey=int_pub.hex(),
        internal_private_key=int_priv_hex,
        merkle_root=merkle_root.hex(),
        output_pubkey=output_pubkey.hex(),
        output_key_parity=parity,
        repay_script=repay.hex(),
        lender_claim_script=lender_claim.hex(),
        safety_script=safety.hex(),
        repay_leaf_hash=repay_lh.hex(),
        lender_claim_leaf_hash=claim_lh.hex(),
        safety_leaf_hash=safety_lh.hex(),
        repay_control_block=repay_cb.hex(),
        lender_claim_control_block=claim_cb.hex(),
        safety_control_block=safety_cb.hex(),
        address=address,
        scriptpubkey=spk.hex(),
    )
