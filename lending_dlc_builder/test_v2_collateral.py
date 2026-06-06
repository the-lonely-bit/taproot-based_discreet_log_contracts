"""Smoke tests: collateral DLC v2 repay leaf + NUMS internal key."""
import secrets
import sys

from embit import ec

from lending_dlc_builder import build_collateral_dlc
from lending_dlc_builder.lending_scripts import (
    build_lending_v2_repay_script,
    build_repay_script,
)


def _xonly_hex() -> str:
    return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()


def test_v2_repay_script_shape():
    key = bytes.fromhex(_xonly_hex())
    v2 = build_lending_v2_repay_script(key)
    v1 = build_repay_script(key, key)
    assert len(v2) < len(v1)
    assert v2.endswith(bytes([0xAC]))  # OP_CHECKSIG


def _compressed_hex() -> str:
    return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().serialize().hex()


def test_v2_collateral_descriptor():
    adaptor = _compressed_hex()
    borrower = _xonly_hex()
    repay_eph = _xonly_hex()
    lender = _xonly_hex()
    oracle = _xonly_hex()

    desc = build_collateral_dlc(
        adaptor_point_hex=adaptor,
        borrower_pubkey_hex=borrower,
        lender_pubkey_hex=lender,
        oracle_pubkey_hex=oracle,
        safety_timeout=900_000,
        network="mainnet",
        protocol_version=2,
        repay_pubkey_hex=repay_eph,
    )
    assert desc.repay_pubkey == repay_eph
    assert desc.internal_private_key is None
    assert desc.address.startswith("bc1p")
    repay_bytes = bytes.fromhex(desc.repay_script)
    assert repay_bytes == build_lending_v2_repay_script(bytes.fromhex(repay_eph))


def test_v1_collateral_still_builds():
    adaptor = _compressed_hex()
    desc = build_collateral_dlc(
        adaptor_point_hex=adaptor,
        borrower_pubkey_hex=_xonly_hex(),
        lender_pubkey_hex=_xonly_hex(),
        oracle_pubkey_hex=_xonly_hex(),
        safety_timeout=900_000,
        protocol_version=1,
    )
    assert desc.internal_private_key is not None or desc.internal_pubkey


if __name__ == "__main__":
    test_v2_repay_script_shape()
    test_v2_collateral_descriptor()
    test_v1_collateral_still_builds()
    print("ok")
    sys.exit(0)
