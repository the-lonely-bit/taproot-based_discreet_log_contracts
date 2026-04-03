"""
Lending DLC Builder — 3-leaf collateral DLC for cross-chain lending.

Builds a Tapscript MAST tree with:
  Leaf 0: Repay          (adaptor + borrower)
  Leaf 1: Lender Claim   (oracle + lender)
  Leaf 2: Safety Refund  (CLTV + borrower)

Reuses taproot_tree_helper (supports N leaves) and compute_merkle_proof
(extended to N leaves).  Does NOT modify any existing swap code.
"""
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from .script_builder import tagged_hash
from .lending_scripts import (
    build_repay_script,
    build_lender_claim_script,
    build_lender_claim_hashlock_script,
    build_lender_claim_timelocked_script,
    build_safety_refund_script,
)
from dlc_builder.taproot import (
    taproot_tree_helper,
    taproot_tweak_pubkey,
    taproot_output_script,
    taproot_address_from_pubkey,
    create_control_block,
    compute_merkle_proof,
    taproot_leaf_hash,
    TAPROOT_LEAF_VERSION,
)
from . import attestation as att_modes

logger = logging.getLogger(__name__)


@dataclass
class LendingDLCDescriptor:
    """Complete descriptor for a 3-leaf collateral DLC."""

    # Parties (x-only hex, 64 chars)
    borrower_pubkey: str
    lender_pubkey: str
    oracle_pubkey: str

    # Adaptor (for repay leaf)
    adaptor_point: str          # 66 hex (compressed)

    # Safety timeout (absolute block height)
    safety_timeout: int

    # Taproot internals
    internal_pubkey: str
    internal_private_key: Optional[str]
    merkle_root: str
    output_pubkey: str
    output_key_parity: int

    # Scripts (hex)
    repay_script: str
    lender_claim_script: str
    safety_script: str

    # Leaf hashes (hex)
    repay_leaf_hash: str
    lender_claim_leaf_hash: str
    safety_leaf_hash: str

    # Control blocks (hex)
    repay_control_block: str
    lender_claim_control_block: str
    safety_control_block: str

    # Output
    address: str
    scriptpubkey: str

    # Attestation (must follow all required fields — dataclass rule)
    # oracle | fal | fixed_term (see attestation.py)
    attestation_mode: str = "oracle"
    # FAL: SHA256(preimage) as 64 hex (32-byte hash commitment)
    attestation_hash_hex: str = ""
    # fixed_term: absolute block height for lender-claim CLTV leaf
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
    """binding_key: oracle x-only (32B), or attestation hash (32B), or fixed-term binding."""
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
) -> LendingDLCDescriptor:
    """
    Build a 3-leaf collateral DLC for cross-chain lending.

    Args:
        adaptor_point_hex:  66 hex (compressed) — for repay leaf
        borrower_pubkey_hex: 64 or 66 hex — borrower x-only
        lender_pubkey_hex:   64 or 66 hex — lender x-only
        oracle_pubkey_hex:   64 hex — oracle x-only (legacy oracle mode)
        safety_timeout:      absolute block height for safety refund
        network:             Taproot address network string
        attestation_mode:    oracle | fal | fixed_term
        attestation_hash_hex: 64 hex SHA256 preimage commitment (FAL)
        lender_claim_cltv_height: absolute CLTV height for lender claim (fixed_term)
    """
    if len(adaptor_point_hex) != 66 or adaptor_point_hex[:2] not in ("02", "03"):
        raise ValueError(f"adaptor_point must be 66 hex compressed pubkey, got {len(adaptor_point_hex)}")
    if safety_timeout < 0:
        raise ValueError(f"safety_timeout must be non-negative, got {safety_timeout}")
    if attestation_mode not in att_modes.VALID_MODES:
        raise ValueError(f"invalid attestation_mode: {attestation_mode}")

    borrower_hex = _normalize_xonly(borrower_pubkey_hex, "borrower_pubkey")
    lender_hex = _normalize_xonly(lender_pubkey_hex, "lender_pubkey")
    oracle_hex = _normalize_xonly(oracle_pubkey_hex, "oracle_pubkey") if oracle_pubkey_hex else "0" * 64

    adaptor_point = bytes.fromhex(adaptor_point_hex)
    borrower = bytes.fromhex(borrower_hex)
    lender = bytes.fromhex(lender_hex)
    oracle = bytes.fromhex(oracle_hex)

    # Convert adaptor compressed → x-only for Tapscript
    from embit.ec import PublicKey
    adaptor_xonly = PublicKey.parse(adaptor_point).xonly()

    # --- Build lender-claim leaf + internal key binding ---
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

    # --- Build the 3 leaf scripts ---
    repay = build_repay_script(adaptor_xonly, borrower)
    safety = build_safety_refund_script(safety_timeout, borrower)

    logger.info(
        f"Lending scripts: repay={len(repay)}B, claim={len(lender_claim)}B, safety={len(safety)}B"
    )

    # --- Build Taproot MAST tree (3 leaves) ---
    scripts = [repay, lender_claim, safety]
    merkle_root, leaf_hashes = taproot_tree_helper(scripts)
    repay_lh, claim_lh, safety_lh = leaf_hashes

    # Verify leaf hashes match
    for i, (sc, lh) in enumerate(zip(scripts, leaf_hashes)):
        expected = taproot_leaf_hash(sc, TAPROOT_LEAF_VERSION)
        if lh != expected:
            raise ValueError(f"Leaf {i} hash mismatch")

    # --- Derive internal pubkey ---
    int_priv_hex, int_pub = _derive_internal_pubkey(
        adaptor_point, borrower, lender, binding_key, safety_timeout
    )

    # --- Tweak to output key ---
    output_pubkey, parity = taproot_tweak_pubkey(int_pub, merkle_root)
    spk = taproot_output_script(output_pubkey)
    address = taproot_address_from_pubkey(output_pubkey, network)

    # --- Control blocks (merkle proofs for 3 leaves) ---
    repay_proof = compute_merkle_proof(repay_lh, leaf_hashes)
    claim_proof = compute_merkle_proof(claim_lh, leaf_hashes)
    safety_proof = compute_merkle_proof(safety_lh, leaf_hashes)

    repay_cb = create_control_block(int_pub, repay, repay_proof,
                                    leaf_version=TAPROOT_LEAF_VERSION,
                                    output_key_parity=parity)
    claim_cb = create_control_block(int_pub, lender_claim, claim_proof,
                                    leaf_version=TAPROOT_LEAF_VERSION,
                                    output_key_parity=parity)
    safety_cb = create_control_block(int_pub, safety, safety_proof,
                                     leaf_version=TAPROOT_LEAF_VERSION,
                                     output_key_parity=parity)

    for name, cb in [("repay", repay_cb), ("claim", claim_cb), ("safety", safety_cb)]:
        if cb[0] not in (0xC0, 0xC1):
            raise ValueError(f"Invalid {name} control block header: 0x{cb[0]:02x}")

    logger.info(f"Lending DLC address: {address}")

    return LendingDLCDescriptor(
        borrower_pubkey=borrower_hex,
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
