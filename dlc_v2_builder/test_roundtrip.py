"""Smoke test: BIP-340 adaptor presign → complete → extract roundtrip."""
import secrets
import sys

from dlc_v2_builder import (
    adaptor_complete,
    adaptor_extract,
    adaptor_presign,
    adaptor_verify,
    build_dlc_v2,
    point_from_secret,
    pubkey_xonly,
    schnorr_verify,
)


def test_adaptor_roundtrip():
    d = secrets.token_bytes(32)
    t = secrets.token_bytes(32)
    msg = secrets.token_bytes(32)
    p = pubkey_xonly(d)
    T = point_from_secret(t)
    presig = adaptor_presign(d, msg, T)
    assert adaptor_verify(p, msg, presig, T)
    full = adaptor_complete(presig, t)
    assert schnorr_verify(p, msg, full)
    assert adaptor_extract(presig, full, T) == t


def test_build_descriptor():
    d = secrets.token_bytes(32)
    sender = secrets.token_bytes(32)
    from embit import ec

    receiver_x = ec.PrivateKey(d).get_public_key().xonly().hex()
    sender_x = ec.PrivateKey(sender).get_public_key().xonly().hex()
    desc = build_dlc_v2(
        receiver_pubkey_hex=receiver_x,
        sender_pubkey_hex=sender_x,
        timeout=900_000,
        network="mainnet",
    )
    assert desc.version == 2
    assert desc.address.startswith("bc1p")
    assert len(desc.claim_script) > 0


if __name__ == "__main__":
    test_adaptor_roundtrip()
    test_build_descriptor()
    print("ok")
    sys.exit(0)
