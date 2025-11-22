#!/bin/bash
# Verify canister deployments
# Uses HTTP calls to bypass dfx ColorOutOfRange panic

cd "$(dirname "$0")"

echo "Verifying canister deployments..."
echo ""

# Check if canisters are accessible via HTTP
echo "Checking BTC Handler (ph6zi-syaaa-aaaad-acuha-cai)..."
BTC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://ph6zi-syaaa-aaaad-acuha-cai.ic0.app/" 2>/dev/null || echo "000")
if [ "$BTC_STATUS" = "200" ] || [ "$BTC_STATUS" = "404" ]; then
    echo "✅ BTC Handler is accessible (HTTP $BTC_STATUS)"
else
    echo "⚠️  BTC Handler HTTP check returned: $BTC_STATUS"
fi

echo ""
echo "Checking Bridge Orchestrator (n5cru-miaaa-aaaad-acuia-cai)..."
BRIDGE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://n5cru-miaaa-aaaad-acuia-cai.ic0.app/" 2>/dev/null || echo "000")
if [ "$BRIDGE_STATUS" = "200" ] || [ "$BRIDGE_STATUS" = "404" ]; then
    echo "✅ Bridge Orchestrator is accessible (HTTP $BRIDGE_STATUS)"
else
    echo "⚠️  Bridge Orchestrator HTTP check returned: $BRIDGE_STATUS"
fi

echo ""
echo "Note: To fully verify, try calling the canisters directly:"
echo "  (dfx may panic, but the calls might still work)"
echo ""
echo "If dfx is fixed, run:"
echo "  dfx canister call --network ic ph6zi-syaaa-aaaad-acuha-cai get_canister_stats"
echo "  dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai debug_get_config"

