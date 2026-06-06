# DLC v2 Builder (Protocol v2)

**Production swap protocol** for NexumBit: genuine **BIP-340 adaptor signatures** with a single-key claim leaf and unspendable NUMS internal key.

> **Deprecated:** use [`dlc_builder`](../dlc_builder/README.md) only for legacy v1 reference (`<adaptor> CHECKSIGVERIFY <receiver> CHECKSIG` coordinator co-sign model). New swaps use this package.

## What v2 changes

| | v1 (`dlc_builder`) | v2 (`dlc_v2_builder`) |
|---|---|---|
| Claim script | `<point> CHECKSIGVERIFY <receiver> CHECKSIG` | `<receiver> CHECKSIG` |
| Atomicity | Coordinator-held co-sign key | BIP-340 adaptor presign / complete / extract |
| Internal key | Derived (key-path risk) | NUMS + per-DLC tweak (script-path only) |
| Adaptor point `T` | In script | Off-chain only; address independent of `T` |
| Claim key | Wallet pubkey | Per-swap **ephemeral** key (browser / `Signer/`) |

## Install

```bash
cd nexum-open-source
pip install -r dlc_v2_builder/requirements.txt -r dlc_builder/requirements.txt
export PYTHONPATH=.
```

## Build a v2 DLC

```python
from dlc_v2_builder import build_dlc_v2, generate_adaptor_secret

secret_hex, point_hex = generate_adaptor_secret()  # secret-holder keeps secret_hex

desc = build_dlc_v2(
    receiver_pubkey_hex="...",   # 64-char x-only ephemeral claim key
    sender_pubkey_hex="...",     # 64-char x-only wallet key (refund path)
    adaptor_point_hex=point_hex, # optional at build time
    timeout=850000,
    network="mainnet",           # or hrp="fb", "dgb", "ltc", ...
)
print(desc.address, desc.claim_control_block)
```

## Adaptor signature API

Pure Python secp256k1 — byte-compatible with `Signer/signer.py` and the in-browser `adaptor-signer.js`:

```python
from dlc_v2_builder import (
    adaptor_presign, adaptor_verify, adaptor_complete, adaptor_extract,
    pubkey_xonly, point_from_secret,
)

d = bytes.fromhex("...")  # ephemeral claim scalar
t = bytes.fromhex("...")  # adaptor secret (secret-holder only until claim)
T = point_from_secret(t)
P = pubkey_xonly(d)
msg = bytes.fromhex("...")  # 32-byte BIP-341 script-path sighash

presig = adaptor_presign(d, msg, T)       # 65 bytes: R' || s'
assert adaptor_verify(P, msg, presig, T)
sig = adaptor_complete(presig, t)         # 64-byte on-chain Schnorr
t2 = adaptor_extract(presig, sig, T)      # counterparty learns t
```

## Examples & tests

```bash
export PYTHONPATH=.
python3 dlc_v2_builder/example_swap.py
python3 dlc_v2_builder/test_roundtrip.py
```

## Spec

Full protocol: [`PROTOCOL.md`](../PROTOCOL.md). Offline recovery: [`Signer/README.md`](../Signer/README.md).
