"""
Taproot (BIP-340, BIP-341, BIP-342) helpers for DLC address and tree construction.
"""
from typing import List, Tuple, Optional

from .script import tagged_hash

# Leaf version MUST be 0xC0 for Tapscript (0x00 is reserved, unspendable).
TAPROOT_LEAF_VERSION = 0xC0


def taproot_leaf_hash(script: bytes, leaf_version: int = TAPROOT_LEAF_VERSION) -> bytes:
    """TapLeaf hash = TaggedHash("TapLeaf", leaf_version || compact_size(script) || script)."""
    if leaf_version != 0xC0:
        raise ValueError("Leaf version must be 0xC0 for Tapscript")
    n = len(script)
    if n < 0xFD:
        size = bytes([n])
    elif n <= 0xFFFF:
        size = bytes([0xFD]) + n.to_bytes(2, "little")
    else:
        size = bytes([0xFE]) + n.to_bytes(4, "little")
    return tagged_hash("TapLeaf", bytes([leaf_version]) + size + script)


def taproot_branch_hash(left: bytes, right: bytes) -> bytes:
    """TapBranch hash; inputs sorted lexicographically."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Branch hashes must be 32 bytes")
    if left > right:
        left, right = right, left
    return tagged_hash("TapBranch", left + right)


def taproot_tweak_pubkey(
    internal_pubkey: bytes,
    merkle_root: Optional[bytes] = None,
) -> Tuple[bytes, int]:
    """Tweak internal key with merkle root; returns (output_xonly_pubkey, parity)."""
    if len(internal_pubkey) != 32:
        raise ValueError("Internal pubkey must be 32 bytes")
    if merkle_root is not None and len(merkle_root) != 32:
        raise ValueError("Merkle root must be 32 bytes")
    try:
        from embit.ec import PublicKey
        P = PublicKey.from_xonly(internal_pubkey)
        Q = P.taproot_tweak(merkle_root or b"")
        sec = Q.sec()
        parity = sec[0] - 2
        return sec[1:33], parity
    except (ImportError, Exception):
        pass
    # Fallback: coincurve for combine
    try:
        from coincurve import PublicKey, PrivateKey
        tweak = tagged_hash("TapTweak", internal_pubkey + (merkle_root or b""))
        P_obj = PublicKey(b"\x02" + internal_pubkey)
        t_point = PrivateKey(tweak).public_key
        Q = PublicKey.combine_keys([P_obj, t_point]).format(compressed=True)
        return Q[1:], Q[0] - 2
    except (ImportError, Exception):
        raise RuntimeError("Need embit or coincurve for Taproot tweak")


def taproot_output_script(output_pubkey: bytes) -> bytes:
    """scriptPubKey for Taproot: OP_1 <32-byte-xonly>."""
    if len(output_pubkey) != 32:
        raise ValueError("Output pubkey must be 32 bytes")
    return bytes([0x51, 0x20]) + output_pubkey


def taproot_tree_helper(scripts: List[bytes]) -> Tuple[bytes, List[bytes]]:
    """
    Build Taproot script tree; returns (merkle_root, leaf_hashes).
    Supports any N >= 1 leaves (pairwise reduction, odd node carried).
    """
    if not scripts:
        raise ValueError("At least one script required")
    leaf_hashes = [taproot_leaf_hash(s) for s in scripts]
    if len(leaf_hashes) == 1:
        return leaf_hashes[0], leaf_hashes
    current_level = leaf_hashes[:]
    while len(current_level) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                next_level.append(taproot_branch_hash(current_level[i], current_level[i + 1]))
            else:
                next_level.append(current_level[i])
        current_level = next_level
    return current_level[0], leaf_hashes


def create_control_block(
    internal_pubkey: bytes,
    script: bytes,
    merkle_proof: List[bytes],
    leaf_version: int = TAPROOT_LEAF_VERSION,
    output_key_parity: int = 0,
) -> bytes:
    """Control block: (leaf_version|parity) || internal_pubkey || merkle_proof..."""
    if len(internal_pubkey) != 32:
        raise ValueError("Internal pubkey must be 32 bytes")
    if leaf_version != 0xC0:
        raise ValueError("Leaf version must be 0xC0")
    header = (leaf_version & 0xFE) | (output_key_parity & 0x01)
    out = bytes([header]) + internal_pubkey
    for h in merkle_proof:
        if len(h) != 32:
            raise ValueError("Merkle proof element must be 32 bytes")
        out += h
    return out


def compute_merkle_proof(target_leaf_hash: bytes, all_leaf_hashes: List[bytes]) -> List[bytes]:
    """
    Merkle proof for target leaf. Supports N-leaf trees (same layout as taproot_tree_helper).
    """
    if target_leaf_hash not in all_leaf_hashes:
        raise ValueError("Target leaf not in tree")
    if len(all_leaf_hashes) == 1:
        return []
    if len(all_leaf_hashes) == 2:
        return [all_leaf_hashes[1] if all_leaf_hashes[0] == target_leaf_hash else all_leaf_hashes[0]]
    idx = all_leaf_hashes.index(target_leaf_hash)
    level = list(all_leaf_hashes)
    proof: List[bytes] = []
    while len(level) > 1:
        next_level: List[bytes] = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                left, right = level[i], level[i + 1]
                if idx == i:
                    proof.append(right)
                elif idx == i + 1:
                    proof.append(left)
                branch = taproot_branch_hash(left, right)
                next_level.append(branch)
                if idx == i or idx == i + 1:
                    idx = len(next_level) - 1
                i += 2
            else:
                next_level.append(level[i])
                if idx == i:
                    idx = len(next_level) - 1
                i += 1
        level = next_level
    return proof


# Bech32m encoding (BIP-350)
def _bech32_polymod(values: List[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: List[int], spec: str) -> List[int]:
    values = _bech32_hrp_expand(hrp) + data
    const = 0x2BC830A3 if spec == "bech32m" else 1
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _bech32_encode(hrp: str, data: List[int], spec: str) -> str:
    combined = data + _bech32_create_checksum(hrp, data, spec)
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(charset[d] for d in combined)


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> List[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for v in data:
        acc = ((acc << frombits) | v) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


# Known networks: mainnet (BTC/FB), testnet, litecoin, litecoin_testnet, digibyte, bellcoin.
# Pass hrp= to support any other chain.
DEFAULT_HRP_MAP = {
    "mainnet": "bc",
    "testnet": "tb",
    "litecoin": "ltc",
    "litecoin_testnet": "tltc",
    "digibyte": "dgb",
    "bellcoin": "bel",
}


def taproot_address_from_pubkey(
    output_pubkey: bytes,
    network: str = "mainnet",
    hrp: Optional[str] = None,
) -> str:
    """
    Bech32m Taproot address from 32-byte output pubkey.
    network: one of mainnet, testnet, litecoin, litecoin_testnet, digibyte, bellcoin.
    hrp: if set, overrides network and uses this HRP (e.g. "dgb" for DigiByte).
    """
    if len(output_pubkey) != 32:
        raise ValueError("Output pubkey must be 32 bytes")
    human = hrp if hrp is not None else DEFAULT_HRP_MAP.get(network, "bc")
    witver = 1
    witprog = _convertbits(output_pubkey, 8, 5)
    return _bech32_encode(human, [witver] + witprog, "bech32m")
