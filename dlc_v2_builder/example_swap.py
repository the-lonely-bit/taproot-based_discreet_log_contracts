#!/usr/bin/env python3
"""
Minimal v2 swap leg demo: build descriptors + adaptor signature roundtrip.

Run from nexum-open-source:
  export PYTHONPATH=.
  python3 dlc_v2_builder/example_swap.py
"""
import secrets

from embit import ec

from dlc_v2_builder import (
    adaptor_complete,
    adaptor_extract,
    adaptor_presign,
    adaptor_verify,
    build_dlc_v2,
    generate_adaptor_secret,
    point_from_secret,
    pubkey_xonly,
    schnorr_verify,
)


def _xonly_from_scalar(scalar: bytes) -> str:
    return ec.PrivateKey(scalar).get_public_key().xonly().hex()


def main() -> None:
    # Ephemeral claim keys (held by browser/offline signer, NOT the wallet funding key)
    claim_a = secrets.token_bytes(32)
    claim_b = secrets.token_bytes(32)
    # Wallet keys that fund and can refund after timeout
    wallet_a = secrets.token_bytes(32)
    wallet_b = secrets.token_bytes(32)

    secret_hex, point_hex = generate_adaptor_secret()
    t = bytes.fromhex(secret_hex)
    T = bytes.fromhex(point_hex)

    timeout_a = 900_000
    timeout_b = 900_144  # B unlocks later → A is secret-holder

    leg_a = build_dlc_v2(
        receiver_pubkey_hex=_xonly_from_scalar(claim_b),
        sender_pubkey_hex=_xonly_from_scalar(wallet_a),
        adaptor_point_hex=point_hex,
        timeout=timeout_a,
        network="mainnet",
    )
    leg_b = build_dlc_v2(
        receiver_pubkey_hex=_xonly_from_scalar(claim_a),
        sender_pubkey_hex=_xonly_from_scalar(wallet_b),
        adaptor_point_hex=point_hex,
        timeout=timeout_b,
        hrp="fb",
    )

    print("Leg A (BTC):", leg_a.address)
    print("Leg B (FB): ", leg_b.address)
    print("Adaptor T:  ", point_hex)

    # Claim sighash is tx-specific; use a stand-in 32-byte digest for the demo.
    sighash = secrets.token_bytes(32)

    # Secret-holder (A) pre-signs leg B (counterparty claims A's funded output)
    presig_b = adaptor_presign(claim_a, sighash, T)
    assert adaptor_verify(pubkey_xonly(claim_a), sighash, presig_b, T)

    # A completes with t → on-chain Schnorr sig reveals t
    full_sig = adaptor_complete(presig_b, t)
    assert schnorr_verify(pubkey_xonly(claim_a), sighash, full_sig)

    extracted = adaptor_extract(presig_b, full_sig, T)
    assert extracted == t
    print("Adaptor roundtrip OK — counterparty can complete their presig with extracted t")


if __name__ == "__main__":
    main()
