# Witness stacks — collateral DLC (Tapscript leaves)

This document describes **what must appear in the witness** to spend the **collateral** output along each **script path**. It matches `lending_scripts.py` in this package.

For **Taproot script-path** spends (BIP-341 / BIP-342), the full transaction witness typically includes, **in addition** to the items below, the **tapscript** and **control block** (see `LendingDLCDescriptor` fields: `repay_script`, `lender_claim_script`, `safety_script`, and corresponding `*_control_block`).

**Notation:** *Stack bottom → top* is the order values are **consumed** by the script. Schnorr signatures are **64-byte** BIP-340 unless your signer uses another encoding.

**Protocol version:** `build_collateral_dlc(..., protocol_version=2)` is the default. v1 repay witness is documented in [Deprecated v1 repay](#deprecated-v1-repay) below.

---

## 1. Repay leaf (v2 — default)

**Script shape:** `<repay_xonly> OP_CHECKSIG`

`repay_xonly` is `repay_pubkey` in the descriptor (may be an ephemeral browser key, not the borrower's wallet key).

| Stack (bottom → top) | Role |
|----------------------|------|
| `completed_schnorr_sig` | BIP-340 signature = `adaptorComplete(presig, t)` under the repay key |

**Off-chain (not in witness stack items above):**

1. Borrower (or server on borrower's behalf) holds a **claim pre-signature** `(R', s')` over the repay sighash.
2. Server releases adaptor secret `t` only after **confirmed on-chain loan repayment**.
3. Client completes: standard 64-byte Schnorr valid under `repay_xonly`.

Adaptor math: [`dlc_v2_builder/adaptor_sig.py`](../dlc_v2_builder/adaptor_sig.py) and [`Signer/signer.py`](../Signer/signer.py).

**Operational note:** Server-gated `t` release is **protocol policy**, not encoded in the script.

---

## 2. Lender-claim leaf — three variants (attestation mode)

Only **one** of these is compiled into a given output; chosen by `attestation_mode` in `build_collateral_dlc`.

### 2a. `oracle` mode

**Script shape:** `<oracle_xonly> OP_CHECKSIGVERIFY <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `oracle_sig` | Oracle attestation signature (VERIFY) |
| `lender_sig` | Lender signature |

### 2b. `fixed_term` mode

**Script shape:** `<height> OP_CHECKLOCKTIMEVERIFY OP_DROP <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Single Schnorr signature |

**Transaction:** `nLockTime` **≥ `lender_claim_cltv_height`**.

### 2c. `fal` mode (hashlock)

**Script shape:** `OP_SHA256 <h_32> OP_EQUALVERIFY <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Lender Schnorr signature |
| `preimage` | 32 bytes where `SHA256(preimage) == H` (committed in-script) |

---

## 3. Safety refund leaf

**Script shape:** `<timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <borrower_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `borrower_sig` | Borrower **wallet** signature |

**Transaction:** `nLockTime` **≥ `safety_timeout`**.

---

## Summary table (v2)

| Leaf | Modes | Witness stack (bottom → top) |
|------|--------|------------------------------|
| Repay | v2 (default) | `completed_schnorr_sig` |
| Lender claim | `oracle` | `oracle_sig`, `lender_sig` |
| Lender claim | `fixed_term` | `lender_sig` (+ locktime ≥ CLTV height) |
| Lender claim | `fal` | `lender_sig`, `preimage` |
| Safety | all | `borrower_sig` (+ locktime ≥ safety timeout) |

---

## Deprecated v1 repay

`protocol_version=1` only (reference):

**Script shape:** `<adaptor_xonly> OP_CHECKSIGVERIFY <borrower_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `adaptor_sig` | Coordinator co-sign (not real BIP-340 adaptor) |
| `borrower_sig` | Borrower signature |

---

## Loan delivery DLC (separate output)

The **loan delivery** leg is a **2-leaf v2 DLC** built with `dlc_v2_builder.build_dlc_v2` (not this package). Claim witness matches swap v2:

| Stack (bottom → top) | Role |
|----------------------|------|
| `completed_schnorr_sig` | Adaptor-completed claim under borrower's ephemeral key |

---

## References

- [BIP-341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP-342 — Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [`dlc_v2_builder/README.md`](../dlc_v2_builder/README.md)
