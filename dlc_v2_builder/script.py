"""v2 Tapscript helpers (claim leaf only; refund reuses dlc_builder)."""
from dlc_builder.script import Script


def build_dlc_v2_claim_script(receiver_pubkey: bytes) -> bytes:
    """
    v2 claim path: <receiver_xonly> OP_CHECKSIG

    Atomicity is off-chain via BIP-340 adaptor signatures (see adaptor_sig.py).
    """
    if len(receiver_pubkey) != 32:
        raise ValueError(f"Receiver pubkey must be 32 bytes (x-only), got {len(receiver_pubkey)}")
    script = Script()
    script.push_data(receiver_pubkey)
    script.op(Script.OP_CHECKSIG)
    return script.to_bytes()
