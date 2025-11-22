# Changelog

All notable changes to the DegenForge project since November 5th, 2025.

## [Unreleased] - 2025-11-17

### Security Fixes
- **CRITICAL**: Fixed BTC deposit recognition bug in `deposit_btc_for_musd`
  - Now uses actual balance from address instead of requested amount
  - Handles pre-existing funds from faucets or previous deposits
  - Changed minimum verification from `btc_amount` to 1 satoshi to detect any balance
  - Position updates now reflect actual on-chain balance as source of truth
  - Location: `icp_bridge/src/bridge_canister/src/lib.rs` (lines 298-360)

### Security Review
- Completed comprehensive security review of all canister code
- Verified integer overflow protection (all arithmetic uses `checked_add`, `checked_sub`, etc.)
- Confirmed transaction verification before state updates
- Validated access control for administrative functions
- Reviewed nonce management for race condition prevention

### Documentation
- Created `REDEPLOYMENT_GUIDE.md` with instructions for upgrading canisters
- Documented stable memory persistence across upgrades
- Added verification checklist for post-deployment testing

### Repository Cleanup
- Removed empty `SOLEZO_contract/` directory
- Removed invalid `~/` directory entry
- Kept `icp-coder/` directory (required for MCP functionality, already in .gitignore)

---

## [2025-11-17] - Backend Cleanup

### Changed
- Backend cleanup and optimization
- Updated gitignore configuration
- Removed documentation and resources section from README

---

## [2025-11-16] - Bitcoin Canister Fixes

### Fixed
- **Bitcoin Canister**: Fixed deposit recognition issues
  - Enhanced balance checking logic
  - Improved error handling for BTC address generation
  - Better logging for debugging deposit issues

### Added
- Solana canister deployment script (`deploy-solana-canister.sh`)
- Updated dependencies for Solana integration

---

## [2025-11-15] - Solana Integration Enhancements

### Added
- **Solana Canister**: Full Devnet integration
  - Configured Solana integration for Devnet testing
  - Implemented threshold Ed25519 signing for Solana bridge
  - Added base64 encoding support for transaction serialization
  - Mainnet Solana transaction support preparation

### Enhanced
- **Mobile App**: Solana transaction status checking
  - Real-time transaction monitoring
  - Status polling and updates
  - Better error handling for Solana operations

### Fixed
- Fixed h3 error in mobile components
- Fixed rendering and BigInt logging issues

---

## [2025-11-11] - Chain Fusion & Transaction Tracking

### Added
- **Chain Fusion Integration**: EVM RPC canister integration
  - Integrated ICP's Chain Fusion technology for Ethereum interactions
  - Faster transaction submission via inter-canister calls
  - Reduced HTTP outcall overhead
  - Location: `icp_bridge/src/bridge_canister/src/lib.rs`

- **Transaction Tracking**: Enhanced monitoring
  - Real-time transaction status tracking
  - Custom alert components for transaction notifications
  - Success toast notifications
  - Activity screen improvements

### Fixed
- Fixed rendering issues in mobile app
- Fixed BigInt logging issues in utilities

### Documentation
- Added deployment documentation (`DEPLOYMENT_SUMMARY.md`)
- Improved mainnet deployment script with better error handling
- Added health check verification steps

---

## [2025-11-10] - Logging & Error Handling

### Added
- **Centralized Logger**: Unified logging system
  - Created `Mobile/utils/logger.ts` for consistent logging
  - Better error tracking and debugging
  - Improved error messages for users

### Enhanced
- Error handling across mobile app
- Better error recovery mechanisms
- More informative error messages

### Documentation
- Added `BUILD.md` for mobile app build instructions
- Created `.env.example` for environment configuration
- Updated `.gitignore` for better file management

---

## [2025-11-08] - Configuration & Transaction Tracking

### Added
- **Transaction Tracking**: Initial implementation
  - Real transaction tracking (untested initially)
  - Transaction monitoring service
  - Activity screen updates

### Enhanced
- Canister configuration improvements
- Mobile app and canister integration
- ICP declarations and types

---

## [2025-11-06] - Rust Migration & RPC Integration

### Major Changes
- **Rust Migration**: Migrated canisters from Python/Kybra to Rust
  - Complete rewrite of bridge orchestrator in Rust
  - Improved performance and memory management
  - Better type safety and error handling

### Added
- **Mezo & Solana RPC Integration**:
  - Integrated Mezo Network RPC endpoints
  - Updated contract addresses for testnet
  - Enhanced RPC error handling

### Updated
- `lib.rs` with improved error handling
- Contract addresses for Mezo testnet
- RPC configuration

---

## Summary of Key Improvements

### Security
- ✅ Fixed critical BTC deposit recognition bug
- ✅ Added comprehensive overflow protection
- ✅ Improved transaction verification
- ✅ Enhanced access control

### Performance
- ✅ Chain Fusion integration for faster transactions
- ✅ Reduced HTTP outcall overhead
- ✅ Optimized transaction polling

### User Experience
- ✅ Real-time transaction tracking
- ✅ Better error messages
- ✅ Improved mobile app UI/UX
- ✅ Enhanced logging and debugging

### Infrastructure
- ✅ Rust migration for better performance
- ✅ Solana integration for Devnet
- ✅ Improved deployment scripts
- ✅ Better documentation

---

## Files Modified Since November 5th

### Canister Code
- `icp_bridge/src/bridge_canister/src/lib.rs` - Major updates (deposit fix, chain fusion)
- `icp_bridge/src/btc_canister/src/lib.rs` - Deposit recognition fixes
- `icp_bridge/src/solana_canister/src/lib.rs` - Solana integration

### Mobile App
- `Mobile/services/ICPBridgeService.ts` - Transaction monitoring
- `Mobile/services/TransactionMonitorService.ts` - New service
- `Mobile/components/ui/CustomAlert.tsx` - New component
- `Mobile/utils/logger.ts` - New centralized logger
- Multiple screen updates for better UX

### Backend
- `backend/src/services/mezo.service.ts` - Service improvements
- `backend/src/controllers/lending.controller.ts` - Controller updates

### Deployment
- `icp_bridge/deploy-mainnet.sh` - Enhanced deployment script
- `icp_bridge/deploy-solana-canister.sh` - New deployment script
- `icp_bridge/DEPLOYMENT_SUMMARY.md` - New documentation

---

## Breaking Changes

None. All changes are backward compatible. Canisters can be upgraded without data loss.

---

## Migration Notes

### For Developers
1. **Redeployment**: Canisters can be upgraded using `dfx deploy --network ic`
2. **Data Preservation**: All position data in stable memory is preserved
3. **Configuration**: No changes needed to existing canister IDs

### For Users
- No action required
- Existing positions are preserved
- Pre-existing funds on BTC addresses will now be recognized automatically

---

## Known Issues

- Bitcoin testnet integration may have reliability issues (documented in README)
- Some edge cases in transaction polling may need further optimization

---

## Next Steps

1. Complete end-to-end testing with the fixed deposit recognition
2. Test pre-existing funds recognition with faucet assets
3. Monitor canister performance after redeployment
4. Continue Solana mainnet integration preparation

