"""
Lending-specific Tapscript leaf builders for 3-leaf collateral DLCs.

Three leaves:
  1. Repay   – adaptor + borrower (identical structure to swap success script)
  2. Lender Claim – oracle + lender  (new: oracle co-signs liquidation/default)
  3. Safety Refund – CLTV + borrower  (identical structure to swap refund script)

All use the existing Script class from script_builder.py.
No changes to the existing swap scripts.
"""
import logging
from .script_builder import Script

logger = logging.getLogger(__name__)


def build_repay_script(adaptor_point_xonly: bytes, borrower_pubkey: bytes) -> bytes:
    """
    Leaf 1 — Borrower reclaims collateral after repayment.

    Script: <adaptor_xonly> OP_CHECKSIGVERIFY <borrower_xonly> OP_CHECKSIG

    Witness: <adaptor_sig> <borrower_sig>

    Server pre-signs with the adaptor secret only after confirming
    on-chain repayment with deep confirmations.
    """
    if len(adaptor_point_xonly) != 32:
        raise ValueError(f"adaptor_point_xonly must be 32 bytes (x-only), got {len(adaptor_point_xonly)}")
    if len(borrower_pubkey) != 32:
        raise ValueError(f"borrower_pubkey must be 32 bytes (x-only), got {len(borrower_pubkey)}")

    s = Script()
    s.push_data(adaptor_point_xonly)
    s.op(Script.OP_CHECKSIGVERIFY)
    s.push_data(borrower_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_lender_claim_hashlock_script(secret_hash: bytes, lender_pubkey: bytes) -> bytes:
    """
    Leaf 2 (FAL) — Lender claims with preimage matching SHA256(secret_hash target).

    Script: OP_SHA256 <32-byte h> OP_EQUALVERIFY <lender_xonly> OP_CHECKSIG

    Witness (bottom→top): <64-byte lender_sig> <32-byte preimage>
    """
    if len(secret_hash) != 32:
        raise ValueError(f"secret_hash must be 32 bytes, got {len(secret_hash)}")
    if len(lender_pubkey) != 32:
        raise ValueError(f"lender_pubkey must be 32 bytes (x-only), got {len(lender_pubkey)}")
    s = Script()
    s.op(Script.OP_SHA256)
    s.push_data(secret_hash)
    s.op(Script.OP_EQUALVERIFY)
    s.push_data(lender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_lender_claim_timelocked_script(cltv_height: int, lender_pubkey: bytes) -> bytes:
    """
    Leaf 2 (fixed-term, no liquidation) — Lender claims after absolute CLTV height.

    Script: <height> OP_CHECKLOCKTIMEVERIFY OP_DROP <lender_xonly> OP_CHECKSIG
    """
    if cltv_height < 0:
        raise ValueError(f"cltv_height must be non-negative, got {cltv_height}")
    if len(lender_pubkey) != 32:
        raise ValueError(f"lender_pubkey must be 32 bytes (x-only), got {len(lender_pubkey)}")
    s = Script()
    s.push_int(cltv_height)
    s.op(Script.OP_CHECKLOCKTIMEVERIFY)
    s.op(Script.OP_DROP)
    s.push_data(lender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_lender_claim_script(oracle_pubkey: bytes, lender_pubkey: bytes) -> bytes:
    """
    Leaf 2 — Lender claims collateral with oracle attestation.

    Script: <oracle_xonly> OP_CHECKSIGVERIFY <lender_xonly> OP_CHECKSIG

    Witness: <oracle_sig> <lender_sig>

    Oracle signs when:
      (a) collateral ratio breaches liquidation threshold, OR
      (b) loan term expired without repayment.
    Lender can NEVER claim without oracle co-signature.
    """
    if len(oracle_pubkey) != 32:
        raise ValueError(f"oracle_pubkey must be 32 bytes (x-only), got {len(oracle_pubkey)}")
    if len(lender_pubkey) != 32:
        raise ValueError(f"lender_pubkey must be 32 bytes (x-only), got {len(lender_pubkey)}")

    s = Script()
    s.push_data(oracle_pubkey)
    s.op(Script.OP_CHECKSIGVERIFY)
    s.push_data(lender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_safety_refund_script(timeout_blocks: int, borrower_pubkey: bytes) -> bytes:
    """
    Leaf 3 — Borrower emergency exit after collateral lock expires.

    Script: <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <borrower_xonly> OP_CHECKSIG

    Witness: <borrower_sig>   (nLockTime >= timeout)

    Timeout = col_tip + loan_duration_blocks + lender_grace_blocks.
    This is the ON-CHAIN collateral lock: the borrower cannot touch the
    collateral until this block height is reached. Before it, only the
    repay leaf (server-gated) or lender claim leaf (oracle-gated) can spend.
    Guarantees borrower can always recover if server AND oracle both fail.
    """
    if len(borrower_pubkey) != 32:
        raise ValueError(f"borrower_pubkey must be 32 bytes (x-only), got {len(borrower_pubkey)}")
    if timeout_blocks < 0:
        raise ValueError(f"timeout_blocks must be non-negative, got {timeout_blocks}")

    s = Script()
    s.push_int(timeout_blocks)
    s.op(Script.OP_CHECKLOCKTIMEVERIFY)
    s.op(Script.OP_DROP)
    s.push_data(borrower_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()
