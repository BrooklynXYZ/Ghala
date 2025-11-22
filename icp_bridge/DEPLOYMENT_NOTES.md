# Deployment Notes and Known Issues

## Deployment Status

✅ **All three canisters deployed successfully to mainnet:**
- BTC Handler: `ph6zi-syaaa-aaaad-acuha-cai`
- Bridge Orchestrator: `n5cru-miaaa-aaaad-acuia-cai`
- Solana Canister: `pa774-7aaaa-aaaad-acuhq-cai`

## Known Issues

### 1. Solana Canister Build Issue (zstd-sys)

**Problem**: The Solana canister cannot be built due to `zstd-sys` dependency trying to compile C code for `wasm32-unknown-unknown` target, which is not supported.

**Current Workaround**: Using a pre-built WASM file from `.dfx/ic/canisters/solana_canister/solana_canister.wasm`

**Root Cause**: 
- `sol_rpc_client` and `sol_rpc_types` depend on `solana-account-decoder-client-types`
- This crate always pulls in `zstd` compression library
- `zstd-sys` tries to compile C code which doesn't work for wasm32

**Attempted Fixes**:
- Disabled default features on `sol_rpc_client` and `sol_rpc_types` ❌
- Disabled default features on `solana-*` crates ❌
- Tried patching `zstd-sys` ❌

**Recommended Solution**:
- Replace `sol_rpc_client`/`sol_rpc_types` with direct HTTP calls to Solana RPC
- Or wait for upstream fix in sol_rpc crates
- Or use a different Solana RPC library that doesn't require zstd

### 2. dfx ColorOutOfRange Panic

**Problem**: dfx panics with `ColorOutOfRange` error when deploying, but deployments still succeed.

**Workaround**: Scripts set `NO_COLOR=1`, `DFX_NO_COLOR=1`, `TERM=dumb`, and `DFX_WARNING=-mainnet_plaintext_identity`

**Status**: Deployments complete successfully despite the panic

### 3. Potential Bug: bridge_musd_to_solana

**Issue**: The `bridge_musd_to_solana` function calls `send_sol` with `musd_amount` directly, but:
- `send_sol` expects lamports (SOL native currency)
- `musd_amount` is in mUSD (Mezo stablecoin, 18 decimals)

**Impact**: This may cause incorrect amounts to be sent, or the function may need to convert mUSD to SOL first.

**Location**: `icp_bridge/src/bridge_canister/src/lib.rs:1369`

**Recommendation**: Review the bridging logic to ensure proper conversion between mUSD and SOL, or implement wrapped mUSD token on Solana.

## Candid Interface Updates

✅ **Solana Canister Candid**: Updated to include `get_solana_transaction_status` method
✅ **Bridge Canister Candid**: Includes all methods (deposit_btc_for_musd, mint_musd_on_mezo, bridge_musd_to_solana)
✅ **BTC Handler Candid**: Includes get_btc_balance and other methods

## Testing

A test script is available at `test-workflow.sh` to test the end-to-end workflow:

```bash
./test-workflow.sh <BTC_ADDRESS> [BTC_AMOUNT_SATOSHIS]
```

**Requirements for testing**:
- Valid BTC address with balance
- Canisters properly configured with canister IDs
- Sufficient cycles for transactions

## Next Steps

1. **Fix Solana canister build**: Implement direct HTTP calls or find alternative to sol_rpc
2. **Review bridge_musd_to_solana**: Ensure proper mUSD to SOL conversion
3. **End-to-end testing**: Test complete workflow with real BTC deposits
4. **Monitor canister logs**: Check for any runtime errors or issues

## Deployment Commands

To redeploy all canisters:
```bash
./deploy.sh
```

To deploy individual canisters:
```bash
dfx canister install --network ic --mode upgrade <canister_name> \
  --wasm .dfx/ic/canisters/<canister_name>/<canister_name>.wasm \
  --yes
```

