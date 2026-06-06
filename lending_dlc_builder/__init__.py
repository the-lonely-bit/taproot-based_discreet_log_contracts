"""
Collateral DLC builder for cross-chain lending (3-leaf Taproot MAST).

Protocol v2 (default): single-key repay leaf + NUMS internal key.
Depends on ``dlc_builder`` (Taproot helpers) and ``dlc_v2_builder`` (NUMS tweak).
Loan delivery DLC: use ``dlc_v2_builder.build_dlc_v2``.
"""
from . import attestation
from .builder import LendingDLCDescriptor, build_collateral_dlc
from .lending_scripts import build_lending_v2_repay_script

__all__ = [
    "LendingDLCDescriptor",
    "build_collateral_dlc",
    "build_lending_v2_repay_script",
    "attestation",
]
