# Witness stacks — collateral DLC (Tapscript leaves)

This document describes **what must appear in the witness** to spend the **collateral** output along each **script path**. It matches `lending_scripts.py` in this package.

For **Taproot script-path** spends (BIP-341 / BIP-342), the full transaction witness typically includes, **in addition** to the items below, the **tapscript** and **control block** (see `LendingDLCDescriptor` fields: `repay_script`, `lender_claim_script`, `safety_script`, and corresponding `*_control_block`). Wallet / PSBT tooling usually attaches those; integrators should use the **descriptor** returned by `build_collateral_dlc(...)`.

**Notation:** *Stack bottom → top* is the order values are **consumed** by the script (bottom first), consistent with the inline comments in `lending_scripts.py`. Schnorr **signatures** are **64-byte** (x-only, BIP-340) unless your stack uses 65-byte encodings — follow your signer.

---

## 1. Repay leaf

**Script shape:** `<adaptor_xonly> OP_CHECKSIGVERIFY <borrower_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `adaptor_sig` | Schnorr signature for the internal/adaptor path (VERIFY) |
| `borrower_sig` | Borrower signature for `OP_CHECKSIG` |

**Transaction:** `nLockTime` / height locks are not required by this leaf itself beyond what your protocol adds elsewhere.

**Operational note:** Who holds the adaptor secret and when it is released is **protocol policy**, not encoded in this file.

---

## 2. Lender-claim leaf — three variants (attestation mode)

Only **one** of these is compiled into a given output; chosen by `attestation_mode` in `build_collateral_dlc`.

### 2a. `oracle` mode

**Script shape:** `<oracle_xonly> OP_CHECKSIGVERIFY <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `oracle_sig` | Oracle attestation signature (VERIFY) |
| `lender_sig` | Lender signature |

The oracle must sign the **correct Taproot script-path sighash** for this input (same leaf hash / control block your PSBT uses). **When** the oracle signs (liquidation, expiry, etc.) is **off-chain policy**.

---

### 2b. `fixed_term` mode

**Script shape:** `<height> OP_CHECKLOCKTIMEVERIFY OP_DROP <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Single Schnorr signature |

**Transaction:** `nLockTime` (or input’s sequence / locktime semantics) must satisfy **`>= lender_claim_cltv_height`** passed into `build_collateral_dlc` (absolute height per script). Wallets must set transaction lock time accordingly.

---

### 2c. `fal` mode (hashlock)

**Script shape:** `OP_SHA256 <h_32> OP_EQUALVERIFY <lender_xonly> OP_CHECKSIG`

Per-source comment: *Witness (bottom→top): 64-byte `lender_sig` · 32-byte `preimage`*

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Lender Schnorr signature |
| `preimage` | 32 bytes such that `SHA256(preimage)` equals the **32-byte hash** committed in-script (from `attestation_hash_hex` — the **hash** of the secret, not the secret committed elsewhere on FB) |

**Check:** The pushed hash in-script is the **32-byte value** used in `OP_EQUALVERIFY` after `OP_SHA256` hashes the preimage — i.e. script verifies `SHA256(preimage) == H` where `H` is embedded as `<h_32>` in the script (implementation uses the attestation hash commitment as binding; see `builder.py`).

**Operational note:** **How** the preimage becomes available (e.g. Fractal covenant reveal) is **outside** this library — see product backend / runbooks.

---

## 3. Safety refund leaf

**Script shape:** `<timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <borrower_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `borrower_sig` | Borrower signature |

**Transaction:** `nLockTime` **≥ `safety_timeout`** (absolute block height in the script). This is the long **borrower-only** escape hatch after the agreed timeout.

---

## Summary table

| Leaf | Modes | Witness stack (bottom → top) |
|------|--------|------------------------------|
| Repay | all | `adaptor_sig`, `borrower_sig` |
| Lender claim | `oracle` | `oracle_sig`, `lender_sig` |
| Lender claim | `fixed_term` | `lender_sig` (+ locktime ≥ CLTV height) |
| Lender claim | `fal` | `lender_sig`, `preimage` |
| Safety | all | `borrower_sig` (+ locktime ≥ safety timeout) |

---

## References

- [BIP-341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)  
- [BIP-342 — Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)  
- [Bitcoin Optech — Taproot](https://bitcoinops.org/en/topics/taproot/)  

---

*For integration testing, build a descriptor with `build_collateral_dlc`, construct a PSBT spending the relevant leaf, and verify your signer produces signatures that validate against the script and sighash.*
