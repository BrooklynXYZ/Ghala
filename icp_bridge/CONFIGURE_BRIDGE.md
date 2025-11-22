# Configuring Bridge Canister IDs

## Overview

The Bridge canister (`n5cru-miaaa-aaaad-acuia-cai`) needs to be configured with the BTC Handler and Solana canister IDs before it can process deposits and bridge operations.

The `set_canister_ids` method **requires controller authentication** - it cannot be called by anonymous users.

## Managing Identities with dfx

Before configuring the Bridge canister, you need to use the **controller identity** (the one that deployed the Bridge canister). Here are the essential `dfx identity` commands:

### List all identities

Shows all available identities on your machine:

```bash
dfx identity list
```

**Output example:**
```
alice
bob *
default
```

The identity marked with `*` is the currently active identity.

### Check current identity

Shows which identity is currently active:

```bash
dfx identity whoami
```

**Output example:**
```
default
```

### Switch to a specific identity

Switches to the specified identity:

```bash
dfx identity use <IDENTITY_NAME>
```

Replace `<IDENTITY_NAME>` with one of the names from `dfx identity list` (e.g., `default`, `mainnet-deploy`, or a custom name).

**Example:**
```bash
dfx identity use default
```

After switching, verify with:
```bash
dfx identity whoami
```

## Quick Start

### Option 1: Use the Configuration Script (Recommended)

```bash
cd icp_bridge
./configure-bridge-canister.sh
```

The script will:
1. Check your current identity
2. Verify it's a controller
3. Configure the canister IDs
4. Verify the configuration

### Option 2: Manual Configuration

#### Step 1: List all identities

```bash
dfx identity list
```

This shows all available identities on your machine. The output looks like:
```
alice
bob *
default
```

The identity marked with `*` is the currently active identity.

#### Step 2: Check current identity

```bash
dfx identity whoami
```

This returns the name of the currently active identity.

#### Step 3: Switch to the controller identity

The controller identity is the one that was used to deploy the Bridge canister. Switch to it:

```bash
dfx identity use <controller-identity-name>
```

Replace `<controller-identity-name>` with one of the names from `dfx identity list` (e.g., `default`, `mainnet-deploy`, or a custom name).

**Example:**
```bash
dfx identity use default
```

#### Step 4: Verify you're a controller

```bash
dfx canister --network ic status n5cru-miaaa-aaaad-acuia-cai
```

Check the "controllers" field in the output - your identity's principal should be listed there.

#### Step 5: Configure the canister IDs

```bash
dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai set_canister_ids \
  '("ph6zi-syaaa-aaaad-acuha-cai", "pa774-7aaaa-aaaad-acuhq-cai")'
```

- `ph6zi-syaaa-aaaad-acuha-cai` = BTC Handler canister ID
- `pa774-7aaaa-aaaad-acuhq-cai` = Solana canister ID

#### Step 6: Verify configuration

```bash
dfx canister --network ic call n5cru-miaaa-aaaad-acuia-cai health_check
```

The response should show `btc_canister_configured: true` and `solana_canister_configured: true`.

## Troubleshooting

### Error: "Unauthorized: Anonymous callers cannot set canister IDs"

**Cause**: You're not using an authenticated identity, or the identity is not a controller.

**Solution**:
1. Check your current identity:
   ```bash
   dfx identity whoami
   ```

2. List all available identities:
   ```bash
   dfx identity list
   ```
   (The identity with `*` is currently active)

3. If it shows `anonymous` or the wrong identity, switch to the controller identity:
   ```bash
   dfx identity use <controller-identity-name>
   ```
   Replace `<controller-identity-name>` with the name from `dfx identity list` (e.g., `default`).

4. Verify the switch worked:
   ```bash
   dfx identity whoami
   ```

5. Verify the identity is a controller:
   ```bash
   dfx canister --network ic status n5cru-miaaa-aaaad-acuia-cai | grep controllers
   ```

### Error: "Unauthorized: Only canister controllers can set canister IDs"

**Cause**: The identity you're using is not listed as a controller of the Bridge canister.

**Solution**:
1. Check which identity is currently active:
   ```bash
   dfx identity whoami
   ```

2. List all available identities:
   ```bash
   dfx identity list
   ```
   (The identity with `*` is currently active)

3. Check which identity was used to deploy the canister (check deployment logs or ask the person who deployed it)

4. Switch to the deployment identity:
   ```bash
   dfx identity use <deployment-identity>
   ```
   Replace `<deployment-identity>` with the name from `dfx identity list`.

5. Verify the switch:
   ```bash
   dfx identity whoami
   ```

6. If you don't have access to the deployment identity, you need to:
   - Get the identity file from the person who deployed the canister, OR
   - Add your identity as a controller (requires existing controller access)

### Error: "BTC canister not configured"

**Cause**: The `set_canister_ids` method hasn't been called yet, or the configuration was lost.

**Solution**: Follow the configuration steps above to set the canister IDs.

### Error: "BTC deposit verification failed: Insufficient BTC deposit. Required minimum: 1, Found: 0"

**Cause**: The Bridge canister couldn't verify your BTC balance. This was caused by the Bridge not passing sufficient cycles to the BTC Handler when querying the Bitcoin canister.

**Solution**:
1. Ensure the canisters have been deployed with the latest code
2. Verify your BTC address has a balance:
   ```bash
   dfx canister call --network ic ph6zi-syaaa-aaaad-acuha-cai get_btc_balance '("YOUR_BTC_ADDRESS")'
   ```
3. Provide your BTC address explicitly when calling `deposit_btc_for_musd`:
   ```bash
   dfx canister call --network ic n5cru-miaaa-aaaad-acuia-cai \
     deposit_btc_for_musd '(200:nat64, opt "YOUR_BTC_ADDRESS")'
   ```
4. Check that your BTC transactions have at least 6 confirmations

**Technical Details**: The fix ensures the Bridge passes 15 billion cycles to the BTC Handler, which needs 10 billion cycles to query the Bitcoin canister on ICP.

## Canister IDs Reference

- **Bridge Canister**: `n5cru-miaaa-aaaad-acuia-cai`
- **BTC Handler**: `ph6zi-syaaa-aaaad-acuha-cai`
- **Solana Canister**: `pa774-7aaaa-aaaad-acuhq-cai`

## Security Notes

1. **Controller Access**: Only controllers can configure canister IDs. This is a security feature to prevent unauthorized changes.

2. **Identity Management**: Keep your controller identity secure. Never share identity files or private keys.

3. **Verification**: Always verify the configuration after setting canister IDs using the `health_check` method.

## Code Reference

The authorization logic is implemented in `src/bridge_canister/src/lib.rs`:

```209:237:icp_bridge/src/bridge_canister/src/lib.rs
#[ic_cdk::update]
async fn set_canister_ids(btc_canister: String, solana_canister: String) -> String {
    let caller = ic_cdk::caller();
    
    if caller == Principal::anonymous() {
        ic_cdk::trap("Unauthorized: Anonymous callers cannot set canister IDs");
    }
    
    if !is_controller(caller).await {
        ic_cdk::trap("Unauthorized: Only canister controllers can set canister IDs");
    }
    
    if Principal::from_text(&btc_canister).is_err() {
        ic_cdk::trap(&format!("Invalid BTC canister ID format: {}", btc_canister));
    }
    
    if Principal::from_text(&solana_canister).is_err() {
        ic_cdk::trap(&format!("Invalid Solana canister ID format: {}", solana_canister));
    }
    
    CANISTER_IDS.with(|ids| {
        *ids.borrow_mut() = RefCell::new(CanisterIds {
            btc_canister: Some(btc_canister.clone()),
            solana_canister: Some(solana_canister.clone()),
        });
    });
    
    format!("Canister IDs set: BTC={}, Solana={}", btc_canister, solana_canister)
}
```

The `is_controller` function checks if the caller is in the canister's controllers list:

```194:207:icp_bridge/src/bridge_canister/src/lib.rs
async fn is_controller(caller: Principal) -> bool {
    let canister_id = ic_cdk::id();
    match ic_cdk::api::management_canister::main::canister_status(
        CanisterIdRecord { canister_id }
    ).await {
        Ok((status,)) => {
            status.settings.controllers.iter().any(|&controller| controller == caller)
        }
        Err(_) => {
            ic_cdk::println!("Failed to get canister status for authorization check");
            false
        }
    }
}
```

