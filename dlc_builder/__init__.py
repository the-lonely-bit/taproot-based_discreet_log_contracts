"""
Standalone Taproot DLC builder for atomic swaps.
BIP-340 (Schnorr), BIP-341 (Taproot), BIP-342 (Tapscript).
"""
from .builder import (
    DLCBuilder,
    DLCDescriptor,
    build_dlc,
    generate_adaptor_secret,
)
from .script import (
    build_dlc_success_script,
    build_dlc_refund_script,
    tagged_hash,
)
from .taproot import (
    TAPROOT_LEAF_VERSION,
    taproot_address_from_pubkey,
    taproot_output_script,
    taproot_leaf_hash,
    taproot_tree_helper,
    taproot_tweak_pubkey,
    create_control_block,
    compute_merkle_proof,
    DEFAULT_HRP_MAP,
)

__all__ = [
    "DLCBuilder",
    "DLCDescriptor",
    "build_dlc",
    "generate_adaptor_secret",
    "build_dlc_success_script",
    "build_dlc_refund_script",
    "tagged_hash",
    "TAPROOT_LEAF_VERSION",
    "taproot_address_from_pubkey",
    "taproot_output_script",
    "taproot_leaf_hash",
    "taproot_tree_helper",
    "taproot_tweak_pubkey",
    "create_control_block",
    "compute_merkle_proof",
    "DEFAULT_HRP_MAP",
]
