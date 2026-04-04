# Lending DLC builder (collateral contract)

Standalone Python package that builds the **3-leaf Taproot collateral DLC** used in NexumBit **cross-chain lending**.

### How each mode is “handled” (split of concerns)

- **`oracle`** — On-chain: lender-claim script needs **oracle Schnorr sig + lender sig** in the witness. Open-source: script is complete. **You** must operate or integrate an oracle that signs the correct sighash when **your** policy says liquidate / default.
- **`fixed_term`** — On-chain: lender claims after **CLTV** with lender sig only. **You** must set `lender_claim_cltv_height` consistently with your loan term and block time.
- **`fal`** — On-chain: lender-claim is **hashlock**; witness includes **preimage**. Open-source: builds the **hash commitment** leaf correctly. **Revealing** the preimage via Fractal covenant spends, indexing, and PSBT completion is **outside** this library (backend FAL pipeline).

## Three leaves (summary)

| Leaf | Path |
|------|------|
| Repay | Adaptor + borrower signature |
| Lender claim | Oracle + lender **or** hashlock + lender **or** CLTV + lender |
| Safety refund | CLTV + borrower |

It **reuses** [`../dlc_builder`](../dlc_builder/README.md) for BIP-341/342 helpers. The open-source `dlc_builder` **taproot** module supports **N-leaf** Merkle trees (required for three leaves).

## Install

```bash
cd nexum-open-source
pip install -r dlc_builder/requirements.txt -r lending_dlc_builder/requirements.txt
export PYTHONPATH=.
```

## Quick example

```python
from lending_dlc_builder import build_collateral_dlc

# adaptor_point_hex: 66-char compressed secp256k1 pubkey (hex)
# borrower / lender / oracle: x-only pubkeys (64 hex) or compressed (66 hex)
desc = build_collateral_dlc(
    adaptor_point_hex="03" + "11" * 32,
    borrower_pubkey_hex="22" * 32,
    lender_pubkey_hex="33" * 32,
    oracle_pubkey_hex="44" * 32,
    safety_timeout=900_000,
    network="mainnet",
    attestation_mode="oracle",  # or "fixed_term" / "fal"
)
print(desc.address)
```

For **`fal`**, pass `attestation_hash_hex` (64 hex = SHA256 preimage commitment).  
For **`fixed_term`**, pass `lender_claim_cltv_height` &gt; 0.

## Attestation modes

| Mode | Lender-claim leaf |
|------|-------------------|
| `oracle` | Oracle `OP_CHECKSIGVERIFY` + lender |
| `fal` | `OP_SHA256` + hash compare + lender (preimage in witness) |
| `fixed_term` | `OP_CHECKLOCKTIMEVERIFY` + lender only |

## Witness stacks (integrators)

See **[WITNESS.md](WITNESS.md)** for expected **stack items per leaf** (repay, lender-claim variants, safety) and locktime notes.

## License

Same as the parent `nexum-open-source` package (see root `LICENSE`).
