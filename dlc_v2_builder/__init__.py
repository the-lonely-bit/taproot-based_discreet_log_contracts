"""
Protocol v2 — genuine BIP-340 adaptor-signature DLCs for atomic swaps.

Use this package for new integrations. The sibling ``dlc_builder`` package
retains deprecated v1 scripts for reference only.
"""
from .adaptor_sig import (
    adaptor_complete,
    adaptor_extract,
    adaptor_presign,
    adaptor_verify,
    point_from_secret,
    pubkey_xonly,
    schnorr_verify,
)
from .builder import (
    DLCv2Descriptor,
    build_dlc_v2,
    derive_unspendable_internal_key,
    derive_unspendable_internal_key_multi,
    generate_adaptor_secret,
)
from .script import build_dlc_v2_claim_script

__all__ = [
    "DLCv2Descriptor",
    "build_dlc_v2",
    "build_dlc_v2_claim_script",
    "derive_unspendable_internal_key",
    "derive_unspendable_internal_key_multi",
    "generate_adaptor_secret",
    "adaptor_presign",
    "adaptor_verify",
    "adaptor_complete",
    "adaptor_extract",
    "pubkey_xonly",
    "point_from_secret",
    "schnorr_verify",
]
