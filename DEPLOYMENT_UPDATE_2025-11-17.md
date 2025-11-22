# Deployment Update - November 17, 2025

## Summary

Successfully redeployed the **Bridge Orchestrator** canister with critical fixes for BTC deposit recognition.

## Critical Fix Deployed

✅ **BTC Deposit Recognition Fix**
- **Issue**: Canister was not recognizing pre-existing funds on BTC addresses (from faucets or previous deposits)
- **Fix**: Updated `deposit_btc_for_musd` to use actual on-chain balance instead of requested amount
- **Impact**: Pre-existing testnet funds are now automatically recognized

## Deployed Canister IDs

### Production Canister IDs (ICP Mainnet)

| Canister | Canister ID | Status | Fix Applied |
|----------|-------------|--------|-------------|
| **Bridge Orchestrator** | `n5cru-miaaa-aaaad-acuia-cai` | ✅ **UPDATED** | ✅ Yes |
| **BTC Handler** | `ph6zi-syaaa-aaaad-acuha-cai` | ✅ Running | No changes needed |
| **Solana Canister** | `pa774-7aaaa-aaaad-acuhq-cai` | ✅ Running | No changes needed |

### Canister URLs (Candid Interface)

- **Bridge Orchestrator**: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=n5cru-miaaa-aaaad-acuia-cai
- **BTC Handler**: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=ph6zi-syaaa-aaaad-acuha-cai
- **Solana Canister**: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=pa774-7aaaa-aaaad-acuhq-cai

### Canister URLs (Web Interface)

- **Bridge Orchestrator**: https://n5cru-miaaa-aaaad-acuia-cai.ic0.app
- **BTC Handler**: https://ph6zi-syaaa-aaaad-acuha-cai.ic0.app
- **Solana Canister**: https://pa774-7aaaa-aaaad-acuhq-cai.ic0.app

## What Changed

### Code Changes
- **File**: `icp_bridge/src/bridge_canister/src/lib.rs`
- **Function**: `deposit_btc_for_musd`
- **Lines**: 298-360

### Key Changes:
1. Changed verification from `btc_amount` to minimum 1 satoshi check
2. Position updates now use actual balance from address (`verified_balance`)
3. Added calculation for newly recognized funds
4. Position always reflects actual on-chain balance as source of truth

## Testing the Fix

### How to Test:
1. **With Pre-existing Funds**:
   - If you have testnet assets (mezo.mUSD, mezoBTC) on a deposit address
   - Call `deposit_btc_for_musd` with any amount (e.g., 1 satoshi)
   - The canister will now recognize the **full balance** on the address
   - Position will be updated with actual balance, not just requested amount

2. **With New Deposits**:
   - Generate a BTC address
   - Send testnet funds to the address
   - Wait for 6+ confirmations
   - Call `deposit_btc_for_musd` - should recognize full balance

### Expected Behavior:
- ✅ Pre-existing funds are recognized automatically
- ✅ Position reflects actual on-chain balance
- ✅ No double-counting of funds
- ✅ Works with funds from faucets

## Deployment Details

- **Deployment Date**: November 17, 2025
- **Deployment Method**: Upgrade mode (preserves all data)
- **Identity Used**: `mainnet-deploy`
- **Network**: ICP Mainnet (`ic`)
- **Data Preservation**: ✅ All position data preserved

## Verification

Run health check:
```bash
dfx canister --network ic call bridge_orchestrator health_check
```

Expected response:
```json
{
  status: "healthy",
  canister_id: "n5cru-miaaa-aaaad-acuia-cai",
  btc_canister_configured: true,
  solana_canister_configured: true,
  ...
}
```

## Next Steps

1. ✅ **Deployment Complete** - Bridge Orchestrator updated
2. **Test with Pre-existing Funds** - Verify the fix works with faucet assets
3. **Monitor Performance** - Watch for any issues
4. **Update Mobile App** - No changes needed (uses same canister IDs)

## Notes

- **BTC Handler** and **Solana Canister** were not updated as they don't need changes
- All canister IDs remain the same
- All existing positions and data are preserved
- The fix is backward compatible

## Support

For issues or questions:
- Check canister status: `dfx canister --network ic status bridge_orchestrator`
- Review logs via Candid interface
- See `REDEPLOYMENT_GUIDE.md` for upgrade instructions
- See `CHANGELOG.md` for full change history

