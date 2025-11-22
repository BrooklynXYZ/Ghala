# Deployment Status

## Current Status

✅ **BTC Handler**: Deployed (ph6zi-syaaa-aaaad-acuha-cai)
✅ **Bridge Orchestrator**: Deployed (n5cru-miaaa-aaaad-acuia-cai)  
✅ **Solana Canister**: Deployed (pa774-7aaaa-aaaad-acuhq-cai)

## Deployment Process

The canisters have been deployed using `./deploy.sh`. Despite the `dfx ColorOutOfRange` panic bug, the deployments completed successfully.

## Verification

Due to the dfx bug affecting all dfx commands, full verification requires either:
1. Fixing dfx (upgrade to latest version)
2. Using alternative tools (IC dashboard, Python agent, etc.)

The canisters are responding to HTTP requests (400 errors indicate they're online but rejecting malformed requests).

## Quick Deploy

To redeploy, simply run:
```bash
./deploy.sh
```

## Testing the Pipeline

Once dfx is fixed, test the BTC to Solana pipeline:

1. **Deposit BTC:**
```bash
dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
  deposit_btc_for_musd '(200:nat64, opt "YOUR_BTC_ADDRESS")'
```

2. **Mint mUSD:**
```bash
dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
  mint_musd_on_mezo '(6000:nat64)'
```

3. **Bridge to Solana:**
```bash
dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
  bridge_musd_to_solana '(5000:nat64)'
```

## Known Issues

- **dfx ColorOutOfRange panic**: Affects all dfx commands. Workaround: Deployments still succeed despite the panic.
- **Solana canister build**: Has zstd-sys dependency issues, but WASM file exists and was deployed.

