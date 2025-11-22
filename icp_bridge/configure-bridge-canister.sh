#!/bin/bash

# Configure Bridge Canister IDs on Mainnet
# This script must be run with the controller identity that deployed the Bridge canister

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "======================================"
echo "Configure Bridge Canister IDs"
echo "======================================"
echo ""

# Bridge canister ID (from user's message)
BRIDGE_CANISTER_ID="n5cru-miaaa-aaaad-acuia-cai"
BTC_CANISTER_ID="ph6zi-syaaa-aaaad-acuha-cai"
SOLANA_CANISTER_ID="pa774-7aaaa-aaaad-acuhq-cai"

# Check if custom IDs are provided as arguments
if [ $# -eq 2 ]; then
    BTC_CANISTER_ID="$1"
    SOLANA_CANISTER_ID="$2"
    echo -e "${BLUE}Using provided canister IDs:${NC}"
    echo "  BTC Handler:    ${BTC_CANISTER_ID}"
    echo "  Solana Canister: ${SOLANA_CANISTER_ID}"
    echo ""
elif [ $# -eq 3 ]; then
    BRIDGE_CANISTER_ID="$1"
    BTC_CANISTER_ID="$2"
    SOLANA_CANISTER_ID="$3"
    echo -e "${BLUE}Using provided canister IDs:${NC}"
    echo "  Bridge Canister: ${BRIDGE_CANISTER_ID}"
    echo "  BTC Handler:    ${BTC_CANISTER_ID}"
    echo "  Solana Canister: ${SOLANA_CANISTER_ID}"
    echo ""
else
    echo -e "${BLUE}Using default canister IDs:${NC}"
    echo "  Bridge Canister: ${BRIDGE_CANISTER_ID}"
    echo "  BTC Handler:    ${BTC_CANISTER_ID}"
    echo "  Solana Canister: ${SOLANA_CANISTER_ID}"
    echo ""
    echo -e "${YELLOW}To use custom IDs, run:${NC}"
    echo "  $0 <btc_canister_id> <solana_canister_id>"
    echo "  or"
    echo "  $0 <bridge_canister_id> <btc_canister_id> <solana_canister_id>"
    echo ""
fi

# Step 1: Check and manage identity
echo -e "${YELLOW}Step 1: Checking current identity...${NC}"
CURRENT_IDENTITY=$(dfx identity whoami 2>&1)
echo -e "${GREEN}Current identity: ${CURRENT_IDENTITY}${NC}"
echo ""

# List all identities with explanation
echo -e "${BLUE}Available identities on this machine:${NC}"
echo "(The identity marked with * is currently active)"
dfx identity list
echo ""

# If identity is not set or is anonymous, provide guidance
if [ -z "$CURRENT_IDENTITY" ] || [ "$CURRENT_IDENTITY" == "anonymous" ]; then
    echo -e "${RED}✗ Error: No identity selected or using anonymous identity${NC}"
    echo ""
    echo -e "${YELLOW}To fix this:${NC}"
    echo "  1. See all available identities:"
    echo "     dfx identity list"
    echo ""
    echo "  2. Switch to the controller identity (the one that deployed the Bridge canister):"
    echo "     dfx identity use <IDENTITY_NAME>"
    echo ""
    echo "  3. Verify the switch worked:"
    echo "     dfx identity whoami"
    echo ""
    echo "  4. Then run this script again"
    exit 1
fi

# Check if user wants to switch identity
echo -e "${YELLOW}Is '${CURRENT_IDENTITY}' the identity that deployed the Bridge canister?${NC}"
echo "If not, you need to switch to the controller identity first."
echo ""
read -p "Continue with current identity '${CURRENT_IDENTITY}'? (y/n): " use_current
if [ "$use_current" != "y" ]; then
    echo ""
    echo -e "${YELLOW}Please switch to the controller identity:${NC}"
    echo "  1. List identities:"
    echo "     dfx identity list"
    echo ""
    echo "  2. Switch to controller identity:"
    echo "     dfx identity use <controller-identity-name>"
    echo ""
    echo "  3. Verify:"
    echo "     dfx identity whoami"
    echo ""
    echo "  4. Run this script again"
    exit 0
fi
echo ""

# Step 2: Verify identity is a controller
echo -e "${YELLOW}Step 2: Verifying identity is a controller of Bridge canister...${NC}"
echo "Checking canister controllers for: ${BRIDGE_CANISTER_ID}"

# Get canister status to check controllers
STATUS_OUTPUT=$(dfx canister --network ic status "$BRIDGE_CANISTER_ID" 2>&1 || echo "error")

if echo "$STATUS_OUTPUT" | grep -q "error\|Error\|not found"; then
    echo -e "${RED}✗ Error: Could not get canister status${NC}"
    echo "$STATUS_OUTPUT"
    echo ""
    echo "Please verify:"
    echo "  1. The canister ID is correct: ${BRIDGE_CANISTER_ID}"
    echo "  2. You have access to the canister"
    echo "  3. The canister exists on mainnet"
    exit 1
fi

# Extract controller information
CONTROLLERS=$(echo "$STATUS_OUTPUT" | grep -i "controllers" || echo "")
echo "$STATUS_OUTPUT"
echo ""

if [ -z "$CONTROLLERS" ]; then
    echo -e "${YELLOW}⚠ Warning: Could not verify controllers from status output${NC}"
    echo "Proceeding anyway, but the call may fail if identity is not a controller."
    echo ""
    read -p "Continue? (y/n): " continue
    if [ "$continue" != "y" ]; then
        exit 0
    fi
else
    echo -e "${GREEN}✓ Canister status retrieved${NC}"
    echo ""
fi

# Step 3: Validate canister ID formats
echo -e "${YELLOW}Step 3: Validating canister ID formats...${NC}"

# Basic validation: ICP canister IDs are typically 27 characters with dashes
validate_canister_id() {
    local id="$1"
    local name="$2"
    
    if [ -z "$id" ]; then
        echo -e "${RED}✗ Error: ${name} canister ID is empty${NC}"
        return 1
    fi
    
    # Check format: should contain dashes and be reasonable length
    if [[ ! "$id" =~ ^[a-z0-9-]+$ ]] || [ ${#id} -lt 20 ] || [ ${#id} -gt 30 ]; then
        echo -e "${RED}✗ Error: ${name} canister ID format looks invalid: ${id}${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ ${name} canister ID format valid: ${id}${NC}"
    return 0
}

validate_canister_id "$BRIDGE_CANISTER_ID" "Bridge" || exit 1
validate_canister_id "$BTC_CANISTER_ID" "BTC Handler" || exit 1
validate_canister_id "$SOLANA_CANISTER_ID" "Solana" || exit 1
echo ""

# Step 4: Confirm configuration
echo -e "${YELLOW}Step 4: Configuration Summary${NC}"
echo "  Bridge Canister: ${BRIDGE_CANISTER_ID}"
echo "  BTC Handler:     ${BTC_CANISTER_ID}"
echo "  Solana Canister:  ${SOLANA_CANISTER_ID}"
echo "  Identity:        ${CURRENT_IDENTITY}"
echo "  Network:         IC Mainnet"
echo ""
read -p "Proceed with configuration? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Configuration cancelled"
    exit 0
fi
echo ""

# Step 5: Call set_canister_ids
echo -e "${YELLOW}Step 5: Configuring Bridge canister...${NC}"
echo "Calling set_canister_ids on ${BRIDGE_CANISTER_ID}..."

CONFIG_RESULT=$(dfx canister --network ic call "$BRIDGE_CANISTER_ID" set_canister_ids "(\"${BTC_CANISTER_ID}\", \"${SOLANA_CANISTER_ID}\")" 2>&1)

if echo "$CONFIG_RESULT" | grep -q "error\|Error\|Unauthorized\|trap"; then
    echo -e "${RED}✗ Configuration failed:${NC}"
    echo "$CONFIG_RESULT"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo ""
    echo "  1. Check which identity is currently active:"
    echo "     dfx identity whoami"
    echo ""
    echo "  2. List all available identities:"
    echo "     dfx identity list"
    echo "     (The identity with * is currently active)"
    echo ""
    echo "  3. Switch to the controller identity (the one that deployed the Bridge canister):"
    echo "     dfx identity use <controller-identity-name>"
    echo ""
    echo "  4. Verify the identity is a controller:"
    echo "     dfx canister --network ic status ${BRIDGE_CANISTER_ID}"
    echo "     (Check the 'controllers' field in the output)"
    echo ""
    echo "  5. If using a different machine, ensure you have the identity file"
    exit 1
else
    echo -e "${GREEN}✓ Configuration successful!${NC}"
    echo "$CONFIG_RESULT"
    echo ""
fi

# Step 6: Verify configuration
echo -e "${YELLOW}Step 6: Verifying configuration...${NC}"
HEALTH_CHECK=$(dfx canister --network ic call "$BRIDGE_CANISTER_ID" health_check 2>&1 || echo "error")

if echo "$HEALTH_CHECK" | grep -q "error\|Error"; then
    echo -e "${YELLOW}⚠ Health check failed (may need time to initialize)${NC}"
    echo "$HEALTH_CHECK"
else
    echo -e "${GREEN}✓ Health check passed${NC}"
    echo "$HEALTH_CHECK"
fi
echo ""

echo "======================================"
echo -e "${GREEN}Configuration Complete!${NC}"
echo "======================================"
echo ""
echo "Bridge canister is now configured with:"
echo "  BTC Handler:     ${BTC_CANISTER_ID}"
echo "  Solana Canister:  ${SOLANA_CANISTER_ID}"
echo ""
echo "The Bridge canister can now:"
echo "  - Call the BTC Handler for deposit verification"
echo "  - Call the Solana canister for bridging operations"
echo ""
echo "Test the configuration:"
echo "  dfx canister --network ic call ${BRIDGE_CANISTER_ID} health_check"
echo ""

