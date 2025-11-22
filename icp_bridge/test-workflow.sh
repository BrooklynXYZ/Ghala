#!/bin/bash
# Test script for end-to-end BTC → MUSD → Solana workflow
# Note: This requires actual BTC deposits and proper configuration

set -e

cd "$(dirname "$0")"

export NO_COLOR=1
export DFX_NO_COLOR=1
export TERM=dumb
export DFX_WARNING=-mainnet_plaintext_identity

echo "========================================"
echo "Testing End-to-End Workflow"
echo "========================================"
echo ""
echo "This script tests the complete workflow:"
echo "1. deposit_btc_for_musd - Register BTC deposit"
echo "2. mint_musd_on_mezo - Mint MUSD on Mezo"
echo "3. bridge_musd_to_solana - Bridge MUSD to Solana"
echo ""
echo "⚠️  WARNING: This requires:"
echo "   - Actual BTC address with balance"
echo "   - Proper canister configuration"
echo "   - Sufficient cycles"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Test cancelled"
    exit 1
fi

# Test parameters (adjust as needed)
BTC_ADDRESS="${1:-}"  # Pass BTC address as first argument
BTC_AMOUNT="${2:-100000}"  # Default: 100000 satoshis (0.001 BTC)

if [ -z "$BTC_ADDRESS" ]; then
    echo "❌ Error: BTC address required"
    echo "Usage: $0 <BTC_ADDRESS> [BTC_AMOUNT_SATOSHIS]"
    exit 1
fi

echo ""
echo "Test Parameters:"
echo "  BTC Address: $BTC_ADDRESS"
echo "  BTC Amount: $BTC_AMOUNT satoshis"
echo ""

# Step 1: Deposit BTC
echo "Step 1: Depositing BTC for mUSD..."
echo "Calling: deposit_btc_for_musd($BTC_AMOUNT, Some(\"$BTC_ADDRESS\"))"
DEPOSIT_RESULT=$(dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
    deposit_btc_for_musd "($BTC_AMOUNT : nat64, opt \"$BTC_ADDRESS\")" 2>&1 || echo "ERROR")
echo "$DEPOSIT_RESULT"
echo ""

# Check if deposit succeeded
if echo "$DEPOSIT_RESULT" | grep -q "error\|ERROR\|trap"; then
    echo "❌ Step 1 failed: BTC deposit failed"
    exit 1
fi

echo "✅ Step 1 completed: BTC deposit registered"
sleep 3

# Step 2: Mint MUSD
echo ""
echo "Step 2: Minting MUSD on Mezo..."
echo "Calling: mint_musd_on_mezo($BTC_AMOUNT)"
MINT_RESULT=$(dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
    mint_musd_on_mezo "($BTC_AMOUNT : nat64)" 2>&1 || echo "ERROR")
echo "$MINT_RESULT"
echo ""

# Check if mint succeeded
if echo "$MINT_RESULT" | grep -q "error\|ERROR\|trap"; then
    echo "❌ Step 2 failed: MUSD minting failed"
    exit 1
fi

# Extract mUSD amount from result (if available)
MUSD_AMOUNT=$(echo "$MINT_RESULT" | grep -oP 'musd_amount[^,}]*' | grep -oP '\d+' | head -1 || echo "$BTC_AMOUNT")
echo "✅ Step 2 completed: MUSD minted (amount: $MUSD_AMOUNT)"
sleep 3

# Step 3: Bridge to Solana
echo ""
echo "Step 3: Bridging MUSD to Solana..."
echo "Calling: bridge_musd_to_solana($MUSD_AMOUNT)"
BRIDGE_RESULT=$(dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
    bridge_musd_to_solana "($MUSD_AMOUNT : nat64)" 2>&1 || echo "ERROR")
echo "$BRIDGE_RESULT"
echo ""

# Check if bridge succeeded
if echo "$BRIDGE_RESULT" | grep -q "error\|ERROR\|trap"; then
    echo "❌ Step 3 failed: Solana bridging failed"
    exit 1
fi

echo "✅ Step 3 completed: MUSD bridged to Solana"
echo ""
echo "========================================"
echo "✅ All workflow steps completed successfully!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Check Solana transaction status using get_solana_transaction_status"
echo "2. Verify position using get_user_position"
echo "3. Check canister logs for detailed information"
echo ""

