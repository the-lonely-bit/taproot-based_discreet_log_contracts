"""Attestation mode for collateral DLC lender-claim leaf (open-source copy)."""

ORACLE = "oracle"
FAL = "fal"
FIXED_TERM = "fixed_term"

VALID_MODES = frozenset({ORACLE, FAL, FIXED_TERM})
