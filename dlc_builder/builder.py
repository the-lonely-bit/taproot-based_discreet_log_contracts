"""
DLC Builder: Taproot Discreet Log Contracts for atomic swaps.
Builds claim path (adaptor + receiver sig) and refund path (CLTV + sender sig).
"""
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional

from .script import (
    tagged_hash,
    build_dlc_success_script,
    build_dlc_refund_script,
)
from .taproot import (
    taproot_tree_helper,
    taproot_tweak_pubkey,
    taproot_output_script,
    taproot_address_from_pubkey,
    create_control_block,
    compute_merkle_proof,
    taproot_leaf_hash,
    TAPROOT_LEAF_VERSION,
)


@dataclass
class DLCDescriptor:
    """Full DLC descriptor for spending and address derivation."""
    adaptor_point: str       # 66 hex (33 bytes compressed)
    timeout: int             # Absolute block height for refund
    receiver_pubkey: str     # 64 hex (x-only)
    sender_pubkey: str        # 64 hex (x-only)
    internal_pubkey: str     # 64 hex
    merkle_root: str         # 64 hex
    output_pubkey: str       # 64 hex
    output_key_parity: int   # 0 or 1
    success_script: str      # hex
    refund_script: str       # hex
    success_leaf_hash: str   # hex
    refund_leaf_hash: str    # hex
    success_control_block: str  # hex
    refund_control_block: str   # hex
    address: str             # bech32m
    scriptpubkey: str        # hex
    internal_private_key: Optional[str] = None  # 64 hex, if derived


def _normalize_xonly(pubkey_hex: str) -> str:
    if len(pubkey_hex) == 64:
        return pubkey_hex
    if len(pubkey_hex) == 66 and pubkey_hex.startswith(("02", "03")):
        return pubkey_hex[2:]
    raise ValueError(f"Pubkey must be 64 or 66 hex chars, got {len(pubkey_hex)}")


def _derive_internal_pubkey(
    adaptor_point: bytes,
    receiver_pubkey: bytes,
    sender_pubkey: bytes,
    timeout: int,
) -> Tuple[Optional[str], bytes]:
    """Deterministic internal key from DLC parameters."""
    data = adaptor_point + receiver_pubkey + sender_pubkey + timeout.to_bytes(8, "big")
    priv = tagged_hash("DLCInternalKey", data)
    try:
        from coincurve import PrivateKey
        pk = PrivateKey(priv)
        pub = pk.public_key.format(compressed=True)
    except (ImportError, Exception):
        from embit import ec
        pk = ec.PrivateKey(priv)
        pub = pk.get_public_key().serialize()
    xonly = pub[1:]
    return priv.hex(), xonly


def generate_adaptor_secret() -> Tuple[str, str]:
    """Random adaptor secret and compressed public point. Returns (secret_hex, point_hex)."""
    secret_bytes = secrets.token_bytes(32)
    try:
        from coincurve import PrivateKey
        priv = PrivateKey(secret_bytes)
        point = priv.public_key.format(compressed=True)
    except (ImportError, Exception):
        from embit import ec
        priv = ec.PrivateKey(secret_bytes)
        point = priv.get_public_key().serialize()
    return secret_bytes.hex(), point.hex()


class DLCBuilder:
    """Build Taproot DLCs for atomic swaps (adaptor signature + CLTV refund)."""

    def build_dlc(
        self,
        adaptor_point_hex: str,
        timeout: int,
        receiver_pubkey_hex: str,
        sender_pubkey_hex: str,
        network: str = "mainnet",
        hrp: Optional[str] = None,
    ) -> DLCDescriptor:
        """
        Build a full DLC descriptor.
        adaptor_point_hex: 66 hex (33 bytes compressed).
        receiver/sender_pubkey_hex: 64 hex (x-only) or 66 hex (compressed).
        timeout: absolute block height for refund path.
        network: mainnet, testnet, litecoin, litecoin_testnet, digibyte, bellcoin (ignored if hrp is set).
        hrp: optional custom bech32 HRP (e.g. "dgb" for DigiByte).
        """
        if len(adaptor_point_hex) != 66 or not adaptor_point_hex.startswith(("02", "03")):
            raise ValueError("Adaptor point must be 66 hex chars (compressed)")
        rec = _normalize_xonly(receiver_pubkey_hex)
        snd = _normalize_xonly(sender_pubkey_hex)
        if timeout < 0:
            raise ValueError("Timeout must be non-negative")

        adaptor_point = bytes.fromhex(adaptor_point_hex)
        receiver_pubkey = bytes.fromhex(rec)
        sender_pubkey = bytes.fromhex(snd)

        success_script = build_dlc_success_script(adaptor_point, receiver_pubkey)
        refund_script = build_dlc_refund_script(timeout, sender_pubkey)

        merkle_root, leaf_hashes = taproot_tree_helper([success_script, refund_script])
        success_leaf_hash = leaf_hashes[0]
        refund_leaf_hash = leaf_hashes[1]
        assert success_leaf_hash == taproot_leaf_hash(success_script)
        assert refund_leaf_hash == taproot_leaf_hash(refund_script)

        internal_priv_hex, internal_pubkey = _derive_internal_pubkey(
            adaptor_point, receiver_pubkey, sender_pubkey, timeout
        )
        output_pubkey, output_key_parity = taproot_tweak_pubkey(internal_pubkey, merkle_root)
        scriptpubkey = taproot_output_script(output_pubkey)
        address = taproot_address_from_pubkey(output_pubkey, network=network, hrp=hrp)

        success_proof = compute_merkle_proof(success_leaf_hash, leaf_hashes)
        refund_proof = compute_merkle_proof(refund_leaf_hash, leaf_hashes)
        success_cb = create_control_block(
            internal_pubkey, success_script, success_proof,
            leaf_version=TAPROOT_LEAF_VERSION, output_key_parity=output_key_parity,
        )
        refund_cb = create_control_block(
            internal_pubkey, refund_script, refund_proof,
            leaf_version=TAPROOT_LEAF_VERSION, output_key_parity=output_key_parity,
        )

        return DLCDescriptor(
            adaptor_point=adaptor_point_hex,
            timeout=timeout,
            receiver_pubkey=receiver_pubkey_hex,
            sender_pubkey=sender_pubkey_hex,
            internal_pubkey=internal_pubkey.hex(),
            merkle_root=merkle_root.hex(),
            output_pubkey=output_pubkey.hex(),
            output_key_parity=output_key_parity,
            success_script=success_script.hex(),
            refund_script=refund_script.hex(),
            success_leaf_hash=success_leaf_hash.hex(),
            refund_leaf_hash=refund_leaf_hash.hex(),
            success_control_block=success_cb.hex(),
            refund_control_block=refund_cb.hex(),
            address=address,
            scriptpubkey=scriptpubkey.hex(),
            internal_private_key=internal_priv_hex,
        )


# Convenience
_default_builder = DLCBuilder()


def build_dlc(
    adaptor_point_hex: str,
    timeout: int,
    receiver_pubkey_hex: str,
    sender_pubkey_hex: str,
    network: str = "mainnet",
    hrp: Optional[str] = None,
) -> DLCDescriptor:
    """Build a DLC descriptor (uses default DLCBuilder instance)."""
    return _default_builder.build_dlc(
        adaptor_point_hex, timeout, receiver_pubkey_hex, sender_pubkey_hex,
        network=network, hrp=hrp,
    )
