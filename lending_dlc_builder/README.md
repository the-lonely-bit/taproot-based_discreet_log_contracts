# Lending DLC builder (collateral contract)

Standalone Python package for **Protocol v2** cross-chain lending on-chain layout:

- **Collateral DLC** — 3-leaf Taproot MAST (this package)
- **Loan delivery DLC** — 2-leaf v2 swap-style DLC via sibling [`dlc_v2_builder`](../dlc_v2_builder/README.md)

## Scope

| Included here | Not included (product / ops) |
|---------------|------------------------------|
| Tapscript for **repay**, **lender claim**, **safety** leaves | Matching API, loan store, wallet UI |
| v2 repay leaf (`<repay_key> CHECKSIG`) + NUMS internal key | **When** oracle signs, price feeds, liquidation bots |
| `build_collateral_dlc(..., protocol_version=2)` | **FAL** covenant ops on Fractal — see backend runbooks |
| Attestation modes: `oracle` \| `fal` \| `fixed_term` | Orchestration (when to broadcast which PSBT) |

This package answers: *“Given pubkeys and parameters, what does the **collateral** output look like on-chain?”*

## Protocol v2 vs v1

| | v1 (deprecated) | v2 (default) |
|---|---|---|
| Repay leaf | `<adaptor> CHECKSIGVERIFY <borrower> CHECKSIG` | `<repay_key> CHECKSIG` |
| Adaptor atomicity | Coordinator co-sign | BIP-340 adaptor (server-gated `t` release) |
| Internal key | Derived (key-path possible) | NUMS + per-DLC tweak (script-path only) |
| `repay_pubkey` | Same as borrower | May be ephemeral browser key |

**Loan delivery** (lender-chain leg) is **not** built here — use `dlc_v2_builder.build_dlc_v2` with the borrower's ephemeral claim key.

### Trust model (lending ≠ swaps)

- **Collateral repay:** server holds `adaptor_secret_collateral` until on-chain repayment is deeply confirmed, then releases `t` (or a completed signature) for the borrower to reclaim collateral.
- **Loan delivery claim:** gated on collateral confirmations (business rule).
- **Lender-claim / safety:** unchanged (oracle / FAL / CLTV).

## Three leaves (v2)

| Leaf | Path |
|------|------|
| Repay | Single-key + off-chain BIP-340 adaptor complete |
| Lender claim | Oracle + lender **or** hashlock + lender **or** CLTV + lender |
| Safety refund | CLTV + borrower |

Depends on [`dlc_builder`](../dlc_builder/README.md) (Taproot helpers) and [`dlc_v2_builder`](../dlc_v2_builder/README.md) (NUMS internal key).

## Install

```bash
cd nexum-open-source
pip install -r dlc_v2_builder/requirements.txt -r dlc_builder/requirements.txt -r lending_dlc_builder/requirements.txt
export PYTHONPATH=.
```

## Quick example (v2 collateral)

```python
from lending_dlc_builder import build_collateral_dlc

desc = build_collateral_dlc(
    adaptor_point_hex="03" + "11" * 32,
    borrower_pubkey_hex="22" * 32,       # wallet key (safety refund)
    repay_pubkey_hex="33" * 32,          # optional ephemeral repay key
    lender_pubkey_hex="44" * 32,
    oracle_pubkey_hex="55" * 32,
    safety_timeout=900_000,
    network="mainnet",
    attestation_mode="oracle",
    protocol_version=2,                  # default
)
print(desc.address, desc.repay_script)
```

## Loan delivery + collateral (v2)

```python
from dlc_v2_builder import build_dlc_v2, generate_adaptor_secret
from lending_dlc_builder import build_collateral_dlc

_, loan_T = generate_adaptor_secret()
_, col_T = generate_adaptor_secret()

loan = build_dlc_v2(
    receiver_pubkey_hex="<borrower_ephemeral_claim>",
    sender_pubkey_hex="<lender_wallet>",
    adaptor_point_hex=loan_T,
    timeout=900_000,
)
collateral = build_collateral_dlc(
    adaptor_point_hex=col_T,
    borrower_pubkey_hex="<borrower_wallet>",
    repay_pubkey_hex="<borrower_ephemeral_repay>",
    lender_pubkey_hex="<lender_wallet>",
    oracle_pubkey_hex="<oracle>",
    safety_timeout=901_000,
    protocol_version=2,
)
```

See [`example_loan.py`](example_loan.py).

## Attestation modes

| Mode | Lender-claim leaf |
|------|-------------------|
| `oracle` | Oracle `OP_CHECKSIGVERIFY` + lender |
| `fal` | `OP_SHA256` + hash compare + lender (preimage in witness) |
| `fixed_term` | `OP_CHECKLOCKTIMEVERIFY` + lender only |

## Tests

```bash
export PYTHONPATH=.
python3 lending_dlc_builder/test_v2_collateral.py
python3 lending_dlc_builder/example_loan.py
```

## Witness stacks

See **[WITNESS.md](WITNESS.md)** — v2 repay uses a single completed Schnorr signature (adaptor-completed off-chain).

## Maintenance

Sync from main repo:

- `backend/services/lending_dlc_builder.py`
- `backend/services/lending_script_builder.py` → `lending_scripts.py`

## License

Same as the parent `nexum-open-source` package.
