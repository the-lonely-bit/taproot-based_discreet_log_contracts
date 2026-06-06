#!/usr/bin/env python3
"""
Minimal cross-chain loan on-chain layout (v2).

  - Loan delivery DLC (lender chain): 2-leaf v2 via dlc_v2_builder
  - Collateral DLC (borrower chain): 3-leaf via lending_dlc_builder

Run from nexum-open-source:
  export PYTHONPATH=.
  python3 lending_dlc_builder/example_loan.py
"""
import secrets

from embit import ec

from dlc_v2_builder import build_dlc_v2, generate_adaptor_secret
from lending_dlc_builder import build_collateral_dlc


def _xonly() -> str:
    return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()


def main() -> None:
    lender_wallet = _xonly()
    borrower_wallet = _xonly()
    borrower_repay_eph = _xonly()  # browser ephemeral key for collateral repay
    borrower_claim_eph = _xonly()  # browser ephemeral key for loan delivery claim
    oracle = _xonly()

    loan_secret_hex, loan_point_hex = generate_adaptor_secret()
    col_secret_hex, col_point_hex = generate_adaptor_secret()

    loan_delivery = build_dlc_v2(
        receiver_pubkey_hex=borrower_claim_eph,
        sender_pubkey_hex=lender_wallet,
        adaptor_point_hex=loan_point_hex,
        timeout=900_000,
        network="mainnet",
    )

    collateral = build_collateral_dlc(
        adaptor_point_hex=col_point_hex,
        borrower_pubkey_hex=borrower_wallet,
        lender_pubkey_hex=lender_wallet,
        oracle_pubkey_hex=oracle,
        safety_timeout=901_000,
        network="mainnet",
        attestation_mode="oracle",
        protocol_version=2,
        repay_pubkey_hex=borrower_repay_eph,
    )

    print("Loan delivery (lender funds):", loan_delivery.address)
    print("Collateral (borrower funds):", collateral.address)
    print("Loan adaptor T:", loan_point_hex)
    print("Collateral adaptor T:", col_point_hex)
    print("(Adaptor secrets stay server-gated for collateral repay until repayment confirmed.)")


if __name__ == "__main__":
    main()
