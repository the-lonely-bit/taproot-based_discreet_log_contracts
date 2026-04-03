# NexumBit Recovery & Signing Tool

Standalone, self-sovereign tool for recovering funds from NexumBit DLC bridge swaps **without** relying on the NexumBit backend — and for signing **cross-chain lending** Taproot PSBTs (collateral repay, lender claim, safety paths) when you paste a PSBT hex.

This README matches **`signer.py` v2.x** (see the module docstring and `VERSION` in code for the exact build).

## When You Need This

- The NexumBit platform is down or unreachable
- You have a funded DLC swap and need to claim or refund independently
- You want to verify and sign PSBTs offline before broadcasting
- You have a **lending** PSBT (repay, lender-claim, FAL hashlock, fixed-term CLTV leaf, or safety refund) and need to complete witness data (private key, optional adaptor secret, optional **FAL preimage**)

## Requirements

```
pip install embit base58 httpx
```

| Package | Required | Purpose |
|---------|----------|---------|
| `embit` | Yes | Schnorr signatures, key derivation, address parsing |
| `base58` | Yes | WIF private key decoding |
| `httpx` | No | Broadcasting transactions (can broadcast manually without it) |

## Usage

```
python signer.py
```

Interactive menu:

| Key | Action |
|-----|--------|
| **[1]** | Sign an existing PSBT (hex) — swaps **or** lending collateral PSBTs |
| **[2]** | Recover from Recovery Kit (JSON) |
| **[3]** | Sign BIP-322 message (quotes) |
| **[4]** | Derive **BTC** Taproot address from private key |
| **[5]** | Derive **FB** Taproot address from private key |
| **[6]** | Derive **DGB** Taproot address from private key |
| **[7]** | Derive **GRS** Taproot address from private key |
| **[8]** | Derive **LTC** Taproot address from private key |
| **[9]** | Derive **BEL** Taproot address from private key |

### Mode [1] — Sign existing PSBT

Use this when you already have a PSBT hex (e.g., from the NexumBit frontend, API, or another tool). The script **analyzes** each Tapscript leaf and prints a short description per input.

1. Select network: `btc`, `fb`, `ltc`, `bel` (Bellscoin / Nintondo electrs), `dgb`, `grs` (Groestlcoin Blockbook)
2. Paste the PSBT hex
3. Review the printed line(s) per input (claim, refund, lender hashlock, etc.)
4. Enter your private key (WIF or 64-char raw hex)
5. **If the spend is a FAL hashlock lender claim**, you will be prompted for the **32-byte preimage** (64 hex characters) — this is *not* the adaptor secret
6. **If** the claim path still needs an adaptor signature and none is pre-embedded in the PSBT, enter the **64-char hex adaptor secret**; if a co-signature is already embedded, the tool skips this step
7. Optionally broadcast

**Lending PSBT types** (all use mode **[1]** with a pasted hex): repay; oracle-style lender claim (often co-sig already in PSBT); **FAL** hashlock (preimage + lender key); fixed-term CLTV lender leaf (respect `nLockTime` like a refund); safety refund for the borrower.

### Mode [2] — Recover from Recovery Kit

Use this when the NexumBit platform is down and you have a recovery kit JSON.

1. Provide the recovery kit (file path or paste JSON)
2. Review the swap summary
3. Choose an action:
   - **[R] Refund** — build and sign a refund PSBT for your locked DLC A funds (available after timeout)
   - **[C] Claim** — build and sign a claim PSBT for your incoming DLC B funds (adaptor sig auto-embedded)
   - **[SR] Sign pre-built refund PSBT** — sign the refund PSBT that was pre-built into the kit
   - **[SC] Sign pre-built claim PSBT** — sign the claim PSBT that was pre-built into the kit
4. Enter your private key
5. Optionally broadcast

## Recovery Kit

The recovery kit is a JSON file you can download from the NexumBit platform while it's running. It contains everything needed to independently complete or exit your swap:

- DLC contract descriptors (Taproot scripts, control blocks, internal keys)
- Funding transaction details (txid, vout, value)
- Timeout block heights
- Adaptor secret (only included when both DLCs are funded and confirmed)
- Pre-built PSBTs for refund and claim (ready to sign)

**Save your recovery kit as soon as your swap is matched and funded.** If the platform goes down later, you'll have everything you need.

### Getting Your Recovery Kit

While the platform is running, click the "Recovery Kit" button on any active swap, or call the API directly:

```
GET /v1/swap/{swap_id}/recovery-kit?address={your_wallet_address}
```

Save the JSON response to a file.

## Private Key

The tool accepts private keys in two formats:

- **WIF** (Wallet Import Format): starts with `K`, `L`, or `5`
- **Raw hex**: 64 hexadecimal characters (32 bytes)

### How to Get Your Private Key

If you use **UniSat Wallet**, your private key is derived from your seed phrase. To extract it:

1. Use a BIP39-compatible tool to derive keys from your seed phrase
2. Use the derivation path matching your address type:
   - Native SegWit (bc1q...): `m/84'/0'/0'/0/0`
   - Taproot (bc1p...): `m/86'/0'/0'/0/0`
3. The resulting private key can be entered as raw hex

**Security warning**: Never share your private key or seed phrase with anyone. Only enter it into this tool running on your own machine.

## How It Works

### Refund (DLC A)

Your DLC A contains funds you locked. The refund script requires only your signature after the timeout block height:

```
<timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <your_pubkey> OP_CHECKSIG
```

The tool builds a transaction with `nLockTime = timeout`, signs it with your key, and the network will accept it once the block height is reached.

### Claim (DLC B)

Your DLC B contains funds from your counterparty. The claim script requires two signatures — the adaptor secret and your receiver key:

```
<adaptor_point> OP_CHECKSIGVERIFY <your_pubkey> OP_CHECKSIG
```

The tool uses the adaptor secret from your recovery kit to compute the adaptor signature, embeds it in the PSBT, and you sign with your receiver key.

### Lending collateral PSBTs (mode [1] only)

For **cross-chain lending**, collateral spends use Tapscript leaves described in the open-source package `nexum-open-source/lending_dlc_builder/` (see **`WITNESS.md`** for witness stacks). The signer does not build those transactions — it **signs** PSBTs your wallet or the platform already constructed. When you paste a hex, mode **[1]** may ask for:

- **Preimage (64 hex chars)** only for **FAL hashlock** lender-claim paths (`OP_SHA256` + `OP_EQUALVERIFY` + lender `OP_CHECKSIG`).
- **Adaptor secret** only when the claim path needs it and no co-signature is already in the PSBT.

## Security Notes

- The adaptor secret is only included in the recovery kit when **both** DLCs are funded and confirmed. This prevents claiming before the counterparty has locked their funds.
- Having the adaptor secret does **not** let you steal the counterparty's funds. Each DLC's claim script requires a different private key.
- The refund path does **not** require the adaptor secret — only your own key and the timeout.
- Timelock ordering (DLC A timeout > DLC B timeout) ensures both parties have time to claim before refunds become available.

## Manual Broadcasting

If you don't have `httpx` installed, you can broadcast the signed raw transaction manually:

```bash
# Bitcoin
curl -X POST https://mempool.space/api/tx -d '<raw_tx_hex>'

# Fractal Bitcoin
curl -X POST https://mempool.fractalbitcoin.io/api/tx -d '<raw_tx_hex>'

# DigiByte (Blockbook uses v2/sendtx/)
curl -X POST https://digibyte.atomicwallet.io/api/v2/sendtx/ -d '<raw_tx_hex>'

# Groestlcoin (Blockbook)
curl -X POST https://blockbook.groestlcoin.org/api/v2/sendtx/ -d '<raw_tx_hex>'

# Litecoin (mempool-style API)
curl -X POST https://litecoinspace.org/api/tx -d '<raw_tx_hex>'

# Bellscoin (Nintondo electrs)
curl -X POST https://nintondo.io/api/electrs/tx -d '<raw_tx_hex>'
```

### DigiByte Taproot (claim/refund) broadcast

The default DGB endpoint (Atomic Wallet) may reject Taproot transactions with "Witness version reserved for soft-fork upgrades". For DLC claim/refund (Taproot script-path spends), use a Taproot-supporting endpoint:

1. **Manual**: Paste the raw hex at https://digibyteblockexplorer.com/sendtx
2. **Env override**: Set `DGB_BROADCAST_URL` to your endpoint (e.g. GetBlock with API key, or your DigiByte Core 8.23+ node's Blockbook `/api/tx`)

Optional overrides: `GRS_BROADCAST_URL`, `BEL_BROADCAST_URL`, `LTC_BROADCAST_URL` (same semantics as `DGB_BROADCAST_URL`).

## CLI shortcuts (no menu)

| Command | Purpose |
|--------|---------|
| `python3 signer.py derive-btc` | Show `bc1p…` + pubkeys from WIF/hex |
| `python3 signer.py derive-fb` | Show FB Taproot address + pubkeys |
| `python3 signer.py derive-dgb` | Show `dgb1p…` + pubkeys |
| `python3 signer.py derive-grs` | Show `grs1p…` + pubkeys |
| `python3 signer.py derive-ltc` | Show `ltc1p…` + pubkeys |
| `python3 signer.py derive-bel` | Show `bel1p…` + pubkeys |
| `python3 signer.py sign-bip322 "<message>"` | BIP-322 signature (base64) for quote signing |

Interactive menu **[3]** matches `sign-bip322`; **[4]–[9]** match the six `derive-*` chains in the table (BTC, FB, DGB, GRS, LTC, BEL).

## License

This tool is provided as part of the NexumBit open protocol specification. Use at your own risk.
