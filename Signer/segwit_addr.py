# Bech32/Bech32m decode for DGB, LTC, BEL addresses (dgb1, ltc1, bel1)
# Minimal implementation from sipa/bech32 ref/python/segwit_addr.py
# Used when embit doesn't support alt-chain HRPs.

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _verify_checksum(hrp, data):
    const = _polymod(_hrp_expand(hrp) + data)
    return const == 1 or const == BECH32M_CONST


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for v in data:
        if v < 0 or v >> frombits:
            return None
        acc = ((acc << frombits) | v) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None
    return ret


def decode(hrp, addr):
    """Decode segwit address. Returns (witver, witprog) or (None, None)."""
    if not addr or (addr.lower() != addr and addr.upper() != addr):
        return (None, None)
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return (None, None)
    if addr[:pos] != hrp:
        return (None, None)
    if not all(c in CHARSET for c in addr[pos + 1 :]):
        return (None, None)
    data = [CHARSET.find(c) for c in addr[pos + 1 :]]
    if not _verify_checksum(hrp, data):
        return (None, None)
    decoded = _convertbits(data[1:-6], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) not in (20, 32):
        return (None, None)
    return (data[0], decoded)
