# Taproot DLC Builder (v1 — deprecated)

> **New swaps use Protocol v2:** [`dlc_v2_builder`](../dlc_v2_builder/README.md) — real BIP-340 adaptor signatures, single-key claim leaf, unspendable NUMS internal key. This package remains for **legacy v1** reference and shared Taproot helpers (`taproot.py`) used by `lending_dlc_builder`.

A **standalone**, **generic** library to build **Discreet Log Contracts (DLCs)** on Taproot for atomic swaps. No backend or API — just the crypto and script construction.

- **Claim path (v1):** coordinator co-sign + receiver signature (`<adaptor> CHECKSIGVERIFY <receiver> CHECKSIG`).
- **Refund path:** `OP_CHECKLOCKTIMEVERIFY` + sender signature after timeout.
- **Chain-agnostic:** works with any Taproot-capable chain by setting `network` or custom `hrp`.
- **Merkle trees:** `taproot_tree_helper` / `compute_merkle_proof` support **N leaves** (not only two) — used by the sibling [`lending_dlc_builder`](../lending_dlc_builder/README.md) package for 3-leaf collateral DLCs.

## BIP compliance

| BIP   | Usage |
|-------|--------|
| BIP-340 | Schnorr signatures (script checksigs) |
| BIP-341 | Taproot output, merkle tree, tweak |
| BIP-342 | Tapscript (leaf version `0xC0`) |
| BIP-350 | Bech32m address encoding |

## Install

```bash
pip install embit  # required
pip install coincurve  # optional, for faster tweak
```

Or from the repo (no install):

```bash
cd nexum-open-source
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python -c "from dlc_builder import build_dlc, generate_adaptor_secret; print('OK')"
```

## Usage

### Generate adaptor secret and point

```python
from dlc_builder import generate_adaptor_secret, build_dlc

secret_hex, point_hex = generate_adaptor_secret()
# Use point_hex in both DLCs; keep secret_hex to create adaptor signatures.
```

### Build a DLC (e.g. Bitcoin mainnet)

```python
from dlc_builder import build_dlc

descriptor = build_dlc(
    adaptor_point_hex="03...",   # 66 hex (33 bytes compressed)
    timeout=850000,             # absolute block height for refund
    receiver_pubkey_hex="...",  # 64 hex x-only (who can claim with adaptor sig)
    sender_pubkey_hex="...",    # 64 hex x-only (who can refund after timeout)
    network="mainnet",          # bc1p... address
)
print(descriptor.address)       # Taproot bech32m address
print(descriptor.scriptpubkey) # scriptPubKey hex
# success_control_block, refund_control_block for spending
```

### Other networks

- `network="testnet"` → `tb1p...`
- `network="litecoin"` → `ltc1p...`
- `network="litecoin_testnet"` → `tltc1p...`
- Any other chain: pass **`hrp="xx"`** (e.g. `hrp="bel"` for Bellscoin); `network` is ignored when `hrp` is set.

```python
descriptor = build_dlc(
    adaptor_point_hex=point_hex,
    timeout=height + 100,
    receiver_pubkey_hex=receiver_xonly,
    sender_pubkey_hex=sender_xonly,
    hrp="bel",   # custom chain
)
```

### Programmatic API

- **`build_dlc(...)`** — one-shot build, returns `DLCDescriptor`.
- **`generate_adaptor_secret()`** — returns `(secret_hex, point_hex)`.
- **`DLCBuilder().build_dlc(...)`** — same, with an explicit builder instance.
- **`DLCDescriptor`** — dataclass with `address`, `scriptpubkey`, scripts, control blocks, leaf hashes, etc.

Lower-level helpers (script building, taproot tree, address encoding) are in `dlc_builder.script` and `dlc_builder.taproot` if you need them.

## What this is (and isn’t)

- **This is:** DLC construction only — scripts, merkle tree, tweak, address, control blocks. You can plug this into your own matching service, PSBT builder, or wallet.
- **This is not:** A full swap backend, API, or wallet. No keys, no network calls, no persistence.

## License

Use and adapt as you like; see repo license.
