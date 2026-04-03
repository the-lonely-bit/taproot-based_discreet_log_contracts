"""
Collateral DLC builder for cross-chain lending (3-leaf Taproot MAST).

Depends on the sibling ``dlc_builder`` package for Taproot helpers (BIP-341/342).
"""
from . import attestation
from .builder import LendingDLCDescriptor, build_collateral_dlc

__all__ = [
    "LendingDLCDescriptor",
    "build_collateral_dlc",
    "attestation",
]
