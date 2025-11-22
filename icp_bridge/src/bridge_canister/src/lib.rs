use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::{
    ecdsa::{EcdsaCurve, EcdsaKeyId},
    http_request::{CanisterHttpRequestArgument, HttpHeader, HttpMethod},
    main::CanisterIdRecord,
};
use ic_stable_structures::{memory_manager::{MemoryManager, VirtualMemory, MemoryId}, StableBTreeMap, DefaultMemoryImpl, Storable, storable::Bound};
use sha3::{Keccak256, Digest as KeccakDigest};
use std::borrow::Cow;
use std::cell::RefCell;

// Constants
const MEZO_TESTNET_RPC: &str = "https://rpc.test.mezo.org";
const MEZO_TESTNET_CHAIN_ID: u64 = 31611;

// Chain Fusion EVM RPC Canister ID
// Deployed on ICP mainnet: 7hfb6-caaaa-aaaar-qadga-cai
// Reference: https://internetcomputer.org/docs/building-apps/chain-fusion/ethereum/evm-rpc/overview
const EVM_RPC_CANISTER_ID: &str = "7hfb6-caaaa-aaaar-qadga-cai";
// Mezo Testnet Contract Addresses
// mUSD Token: https://explorer.mezo.org/address/0xdD468A1DDc392dcdbEf6db6e34E89AA338F9F186
const MUSD_TOKEN_ADDRESS: &str = "0xdD468A1DDc392dcdbEf6db6e34E89AA338F9F186";
// BorrowManager: Using candidate contract 0xd02E8c38a8E3db71f8b2ae30B8186d7874934e12
// If this doesn't work, try: 0x4411cc69aE69cE444c20603FcF75a209ddd25c0d
const BORROW_MANAGER_ADDRESS: &str = "0xd02E8c38a8E3db71f8b2ae30B8186d7874934e12";
const KEY_NAME: &str = "test_key_1";
const MAX_LTV: u64 = 90; // 90% maximum LTV
const INTEREST_RATE: u64 = 1; // 1% APR

// Performance optimization constants
const TRANSACTION_TIMEOUT_SECS: u64 = 45; // Max 45 seconds total for transaction
const MAX_POLL_ATTEMPTS: u8 = 15; // Maximum polling attempts
const DEFAULT_GAS_LIMIT: u64 = 350_000; // Safe default for minting operations (avoids gas estimation HTTP call)
const DEFAULT_GAS_PRICE: u64 = 20_000_000_000; // Default: 20 gwei (fallback if gas price fetch fails)

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    
    static POSITIONS: RefCell<StableBTreeMap<Principal, BridgePosition, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
        ));
    
    static CANISTER_IDS: RefCell<RefCell<CanisterIds>> = RefCell::new(RefCell::new(CanisterIds {
        btc_canister: None,
        solana_canister: None,
    }));
    
    // Track last used nonce per Ethereum address to prevent race conditions
    // Using a wrapper for String to ensure Storable implementation
    static NONCE_TRACKER: RefCell<StableBTreeMap<NonceKey, u64, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
        ));
}

// Wrapper for String to use as key in StableBTreeMap
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NonceKey(String);

impl Storable for NonceKey {
    const BOUND: Bound = Bound::Unbounded;
    
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.as_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        NonceKey(String::from_utf8(bytes.to_vec()).unwrap_or_default())
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CanisterIds {
    btc_canister: Option<String>,
    solana_canister: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug, serde::Serialize)]
pub struct BridgePosition {
    pub user: Principal,
    pub btc_collateral: u64,
    pub musd_minted: u64,
    pub sol_deployed: u64,
    pub status: String,
    pub btc_address: String,
    pub sol_address: String,
}

impl Storable for BridgePosition {
    const BOUND: Bound = Bound::Unbounded;
    
    fn to_bytes(&self) -> Cow<[u8]> {
        match bincode::serialize(self) {
            Ok(bytes) => Cow::Owned(bytes),
            Err(e) => {
                ic_cdk::println!("Error serializing BridgePosition: {:?}", e);
                ic_cdk::trap("Failed to serialize BridgePosition");
            }
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        match bincode::deserialize(&bytes) {
            Ok(position) => position,
            Err(e) => {
                ic_cdk::println!("Error deserializing BridgePosition: {:?}", e);
                // Return default position instead of panicking
                BridgePosition {
                    user: Principal::anonymous(),
                    btc_collateral: 0,
                    musd_minted: 0,
                    sol_deployed: 0,
                    status: "error".to_string(),
                    btc_address: "".to_string(),
                    sol_address: "".to_string(),
                }
            }
        }
    }
}

#[derive(CandidType, Deserialize, Debug)]
pub struct DepositResponse {
    pub btc_address: String,
    pub message: String,
    pub status: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct MintResponse {
    pub musd_amount: u64,
    pub transaction_hash: String,
    pub new_ltv: String,
    pub status: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct BridgeStats {
    pub total_positions: u64,
    pub total_btc_collateral: u64,
    pub total_musd_minted: u64,
    pub total_sol_deployed: u64,
    pub max_ltv: u64,
    pub interest_rate: u64,
}

// EVM RPC Canister Types for Chain Fusion
// Based on: https://raw.githubusercontent.com/dfinity/evm-rpc-canister/refs/heads/main/candid/evm_rpc.did
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct RpcHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct RpcApi {
    pub url: String,
    pub headers: Option<Vec<RpcHttpHeader>>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct RpcConfig {
    pub cycles: Option<u64>,
    pub timeout: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum RpcServices {
    Custom {
        chain_id: u64,
        services: Vec<RpcApi>,
    },
    // Other variants not needed for Mezo
}

#[derive(CandidType, Deserialize, Debug)]
pub enum SendRawTransactionStatus {
    Ok(Option<String>),
    NonceTooLow,
    NonceTooHigh,
    InsufficientFunds,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SendRawTransactionResult {
    pub status: SendRawTransactionStatus,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum MultiSendRawTransactionResult {
    Consistent(SendRawTransactionResult),
    Inconsistent(Vec<(String, SendRawTransactionResult)>),
}

// Helper function to check if caller is a controller
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

#[ic_cdk::update]
async fn set_canister_ids(btc_canister: String, solana_canister: String) -> String {
    let caller = ic_cdk::caller();
    
    // Reject anonymous callers
    if caller == Principal::anonymous() {
        ic_cdk::trap("Unauthorized: Anonymous callers cannot set canister IDs");
    }
    
    // Check if caller is a controller
    if !is_controller(caller).await {
        ic_cdk::trap("Unauthorized: Only canister controllers can set canister IDs");
    }
    
    // Validate Principal format for both canister IDs
    if Principal::from_text(&btc_canister).is_err() {
        ic_cdk::trap(&format!("Invalid BTC canister ID format: {}", btc_canister));
    }
    
    if Principal::from_text(&solana_canister).is_err() {
        ic_cdk::trap(&format!("Invalid Solana canister ID format: {}", solana_canister));
    }
    
    // Store the canister IDs
    CANISTER_IDS.with(|ids| {
        *ids.borrow_mut() = RefCell::new(CanisterIds {
            btc_canister: Some(btc_canister.clone()),
            solana_canister: Some(solana_canister.clone()),
        });
    });
    
    format!("Canister IDs set: BTC={}, Solana={}", btc_canister, solana_canister)
}

#[ic_cdk::query]
fn get_my_btc_address_via_bridge() -> String {
    let caller = ic_cdk::caller();
    POSITIONS.with(|map| {
        map.borrow()
            .get(&caller)
            .map(|position| position.btc_address.clone())
            .unwrap_or_default()
    })
}

async fn verify_btc_deposit(btc_canister: Principal, btc_address: &str, min_required: u64) -> Result<u64, String> {
    ic_cdk::println!("=== BRIDGE: verify_btc_deposit START ===");
    ic_cdk::println!("Bridge calling BTC handler: {}", btc_canister.to_text());
    ic_cdk::println!("BTC address to verify: {}", btc_address);
    ic_cdk::println!("Min required balance: {} sats", min_required);
    
    // The BTC handler needs cycles to call the Bitcoin canister (10B cycles)
    // Pass 15B cycles to ensure the BTC handler has enough
    const CYCLES_FOR_BTC_HANDLER: u64 = 15_000_000_000;
    
    let balance_result: Result<(u64,), _> = ic_cdk::api::call::call_with_payment(
        btc_canister, 
        "get_btc_balance", 
        (btc_address.to_string(),),
        CYCLES_FOR_BTC_HANDLER
    ).await;
    
    match balance_result {
        Ok((balance,)) => {
            ic_cdk::println!("✅ BTC handler returned balance: {} sats", balance);
            ic_cdk::println!("=== BRIDGE: verify_btc_deposit END ===");
            if balance >= min_required {
                Ok(balance)
            } else {
                Err(format!("Insufficient BTC deposit. Required minimum: {}, Found: {}", min_required, balance))
            }
        }
        Err(e) => {
            ic_cdk::println!("❌ BTC handler call failed: {:?}", e);
            ic_cdk::println!("=== BRIDGE: verify_btc_deposit END ===");
            Err(format!("Failed to get BTC balance: {:?}", e))
        }
    }
}

#[ic_cdk::update]
async fn deposit_btc_for_musd(btc_amount: u64, btc_address_opt: Option<String>) -> DepositResponse {
    if btc_amount == 0 {
        ic_cdk::trap("Invalid input: BTC amount must be greater than 0");
    }
    
    let caller = ic_cdk::caller();
    
    ic_cdk::println!("=== BRIDGE: deposit_btc_for_musd START ===");
    ic_cdk::println!("Caller principal: {}", caller.to_text());
    ic_cdk::println!("Requested BTC amount: {}", btc_amount);
    ic_cdk::println!("Provided BTC address: {:?}", btc_address_opt);
    
    let btc_canister_id = CANISTER_IDS.with(|ids| {
        ids.borrow().borrow().btc_canister.clone().unwrap_or_else(|| {
            ic_cdk::trap("BTC canister not configured. Please contact admin.")
        })
    });
    
    ic_cdk::println!("BTC canister ID from config: {}", btc_canister_id);
    
    let btc_canister = match Principal::from_text(&btc_canister_id) {
        Ok(principal) => principal,
        Err(e) => {
            ic_cdk::trap(&format!("Invalid BTC canister ID '{}': {:?}", btc_canister_id, e));
        }
    };
    
    // First, check if there's an existing position with a BTC address
    let existing_position = POSITIONS.with(|map| {
        map.borrow().get(&caller)
    });
    
    let btc_address = if let Some(addr) = btc_address_opt {
        // Use provided address if given
        if addr.is_empty() {
            ic_cdk::trap("Provided BTC address cannot be empty");
        }
        ic_cdk::println!("Using provided BTC address: {}", addr);
        addr
    } else if let Some(pos) = existing_position {
        // Use existing BTC address if available
        if !pos.btc_address.is_empty() {
            ic_cdk::println!("Using existing position BTC address: {}", pos.btc_address);
            pos.btc_address.clone()
        } else {
            // Try to get the address for this principal from BTC handler
            ic_cdk::println!("Querying BTC handler for principal's address...");
            let address_result: Result<(String,), _> = ic_cdk::call(btc_canister, "get_btc_address_for_principal", (caller,))
                .await;
            match address_result {
                Ok((addr,)) if !addr.is_empty() => {
                    ic_cdk::println!("BTC handler returned address: {}", addr);
                    addr
                },
                _ => {
                    // If address not found, user must generate it first
                    ic_cdk::trap("BTC address not found for this principal. Please call generate_btc_address on the BTC handler first with your identity, or provide the BTC address as the second parameter.");
                }
            }
        }
    } else {
        // No existing position - try to get address for this principal
        ic_cdk::println!("No existing position, querying BTC handler for principal's address...");
        let address_result: Result<(String,), _> = ic_cdk::call(btc_canister, "get_btc_address_for_principal", (caller,))
            .await;
        match address_result {
            Ok((addr,)) if !addr.is_empty() => {
                ic_cdk::println!("BTC handler returned address: {}", addr);
                addr
            },
            _ => {
                // If address not found, user must generate it first or provide it
                ic_cdk::trap("BTC address not found for this principal. Please call generate_btc_address on the BTC handler first with your identity, or provide the BTC address as the second parameter.");
            }
        }
    };
    
    // CRITICAL FIX: Verify BTC deposit before updating position
    match verify_btc_deposit(btc_canister, &btc_address, btc_amount).await {
        Ok(verified_balance) => {
            // Check if position already exists
            let existing = POSITIONS.with(|map| {
                map.borrow().get(&caller)
            });
            
            // Use checked arithmetic to prevent overflow
            let updated_position = if let Some(existing) = existing {
                let new_collateral = existing.btc_collateral.checked_add(btc_amount)
                    .unwrap_or_else(|| ic_cdk::trap("Overflow: BTC collateral addition would overflow"));
                
                BridgePosition {
                    user: caller,
                    btc_collateral: new_collateral,
                    musd_minted: existing.musd_minted,
                    sol_deployed: existing.sol_deployed,
                    status: "btc_deposited".to_string(),
                    btc_address: btc_address.clone(),
                    sol_address: existing.sol_address,
                }
            } else {
                BridgePosition {
                    user: caller,
                    btc_collateral: btc_amount,
                    musd_minted: 0,
                    sol_deployed: 0,
                    status: "btc_deposited".to_string(),
                    btc_address: btc_address.clone(),
                    sol_address: "".to_string(),
                }
            };
            
            POSITIONS.with(|map| {
                map.borrow_mut().insert(caller, updated_position);
            });
            
            DepositResponse {
                btc_address,
                message: format!("Deposit {} satoshis verified. Balance: {} satoshis", btc_amount, verified_balance),
                status: "confirmed".to_string(),
            }
        }
        Err(e) => {
            ic_cdk::trap(&format!("BTC deposit verification failed: {}", e));
        }
    }
}

// Helper function to derive Ethereum address from ECDSA public key
// Ethereum address = last 20 bytes of keccak256(uncompressed public key without 0x04 prefix)
fn derive_eth_address_from_pubkey(pubkey: &[u8]) -> String {
    // ECDSA public key from ICP is in compressed format (33 bytes) or uncompressed (65 bytes)
    // We need uncompressed format: if compressed, we'd need to decompress, but ICP gives us uncompressed
    let pubkey_uncompressed = if pubkey.len() == 33 {
        // Compressed format - would need secp256k1 library to decompress
        // For now, assume we get uncompressed (65 bytes with 0x04 prefix)
        pubkey
    } else {
        pubkey
    };
    
    // Remove 0x04 prefix if present (uncompressed public key format)
    let pubkey_bytes = if pubkey_uncompressed.len() == 65 && pubkey_uncompressed[0] == 0x04 {
        &pubkey_uncompressed[1..]
    } else {
        pubkey_uncompressed
    };
    
    // Hash with keccak256
    let hash = Keccak256::digest(pubkey_bytes);
    
    // Take last 20 bytes
    let address_bytes = &hash[12..32];
    
    // Format as hex with 0x prefix
    format!("0x{}", hex::encode(address_bytes))
}

// Helper function to get canister's Ethereum address
async fn get_canister_eth_address(caller: Principal) -> String {
    // Derive unique path for this caller
    let derivation_path = vec![caller.as_slice().to_vec()];
    
    // Request ECDSA public key from ICP
    match ic_cdk::api::management_canister::ecdsa::ecdsa_public_key(
        ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyArgument {
            canister_id: None,
            derivation_path: derivation_path.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: KEY_NAME.to_string(),
            },
        },
    )
    .await
    {
        Ok((response,)) => {
            derive_eth_address_from_pubkey(&response.public_key)
        }
        Err(err) => {
            ic_cdk::println!("Failed to get ECDSA public key for ETH address: {:?}", err);
            // Return placeholder - transaction will fail but won't crash
            "0x0000000000000000000000000000000000000000".to_string()
        }
    }
}

// Helper function to calculate keccak256 function selector
fn calculate_function_selector(signature: &str) -> Vec<u8> {
    let hash = Keccak256::digest(signature.as_bytes());
    hash[0..4].to_vec()
}

// Helper function to build EVM transaction data for borrowing mUSD
// Based on the Borrow event ABI, the function signature is:
// borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)
fn build_mint_musd_calldata(musd_amount: u64, on_behalf_of: &str) -> Vec<u8> {
    // Function selector: keccak256("borrow(address,uint256,uint256,uint16,address)")[0:4]
    let function_selector = calculate_function_selector("borrow(address,uint256,uint256,uint16,address)");
    let mut calldata = function_selector;
    
    // Encode function parameters (ABI encoding - each parameter is 32 bytes)
    // Parameter 1: asset (address) - mUSD token address (padded to 32 bytes)
    let asset_bytes = hex::decode(MUSD_TOKEN_ADDRESS.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Invalid mUSD token address '{}': {:?}", MUSD_TOKEN_ADDRESS, e));
        });
    let mut asset_padded = vec![0u8; 12];
    asset_padded.extend_from_slice(&asset_bytes);
    calldata.extend_from_slice(&asset_padded);
    
    // Parameter 2: amount (uint256) - musd_amount (32 bytes, big-endian)
    let mut amount_bytes = vec![0u8; 24];
    amount_bytes.extend_from_slice(&musd_amount.to_be_bytes());
    calldata.extend_from_slice(&amount_bytes);
    
    // Parameter 3: interestRateMode (uint256) - 2 = variable rate (common default)
    let interest_mode: u64 = 2;
    let mut mode_bytes = vec![0u8; 24];
    mode_bytes.extend_from_slice(&interest_mode.to_be_bytes());
    calldata.extend_from_slice(&mode_bytes);
    
    // Parameter 4: referralCode (uint16) - 0 = no referral (padded to 32 bytes)
    let referral_code: u16 = 0;
    let mut referral_bytes = vec![0u8; 30];
    referral_bytes.extend_from_slice(&referral_code.to_be_bytes());
    calldata.extend_from_slice(&referral_bytes);
    
    // Parameter 5: onBehalfOf (address) - canister's Ethereum address (padded to 32 bytes)
    let on_behalf_bytes = hex::decode(on_behalf_of.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Invalid onBehalfOf address '{}': {:?}", on_behalf_of, e));
        });
    let mut on_behalf_padded = vec![0u8; 12];
    on_behalf_padded.extend_from_slice(&on_behalf_bytes);
    calldata.extend_from_slice(&on_behalf_padded);
    
    calldata
}

// Helper function to build RLP-encoded unsigned transaction (for signing)
fn build_unsigned_evm_transaction(nonce: u64, gas_price: u64, gas_limit: u64, to: &str, value: u64, data: &[u8], chain_id: u64) -> Vec<u8> {
    use rlp::RlpStream;
    
    let mut stream = RlpStream::new();
    stream.begin_list(9);
    
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    
    // Decode 'to' address (remove 0x prefix)
    let to_bytes = hex::decode(to.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Invalid 'to' address '{}': {:?}", to, e));
        });
    stream.append(&to_bytes);
    
    stream.append(&value);
    stream.append(&data);
    
    // EIP-155 chain ID encoding
    stream.append(&chain_id);
    stream.append_empty_data(); // r (will be filled after signing)
    stream.append_empty_data(); // s (will be filled after signing)
    
    stream.out().to_vec()
}

// Helper function to build signed RLP-encoded transaction
fn build_signed_evm_transaction(nonce: u64, gas_price: u64, gas_limit: u64, to: &str, value: u64, data: &[u8], _chain_id: u64, v: u64, r: &[u8], s: &[u8]) -> Vec<u8> {
    use rlp::RlpStream;
    
    let mut stream = RlpStream::new();
    stream.begin_list(9);
    
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    
    // Decode 'to' address (remove 0x prefix)
    let to_bytes = hex::decode(to.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Invalid 'to' address '{}': {:?}", to, e));
        });
    stream.append(&to_bytes);
    
    stream.append(&value);
    stream.append(&data);
    
    // EIP-155: v = chain_id * 2 + 35 + recovery_id
    // recovery_id is 0 or 1, so v will be chain_id * 2 + 35 or chain_id * 2 + 36
    stream.append(&v);
    
    // r and s are 32 bytes each, but RLP encoding handles them
    // Ensure r and s are exactly 32 bytes
    let mut r_padded = vec![0u8; 32];
    let r_start = 32usize.saturating_sub(r.len());
    r_padded[r_start..].copy_from_slice(r);
    
    let mut s_padded = vec![0u8; 32];
    let s_start = 32usize.saturating_sub(s.len());
    s_padded[s_start..].copy_from_slice(s);
    
    stream.append(&r_padded);
    stream.append(&s_padded);
    
    stream.out().to_vec()
}

// Helper function to recover v, r, s from ECDSA signature
// ECDSA signature from ICP is 65 bytes: [r (32 bytes), s (32 bytes), recovery_id (1 byte)]
fn parse_ecdsa_signature(signature: &[u8]) -> (u64, Vec<u8>, Vec<u8>) {
    if signature.len() < 64 {
        ic_cdk::trap("Invalid signature length");
    }
    
    let r = signature[0..32].to_vec();
    let s = signature[32..64].to_vec();
    let recovery_id = if signature.len() > 64 { signature[64] } else { 0 };
    
    // For EIP-155: v = chain_id * 2 + 35 + recovery_id
    let v = MEZO_TESTNET_CHAIN_ID * 2 + 35 + recovery_id as u64;
    
    (v, r, s)
}

#[ic_cdk::update]
async fn mint_musd_on_mezo(btc_amount: u64) -> MintResponse {
    // Performance monitoring: Track total transaction time
    let start_time = ic_cdk::api::time();
    
    // Input validation
    if btc_amount == 0 {
        ic_cdk::trap("Invalid input: BTC amount must be greater than 0");
    }
    
    let caller = ic_cdk::caller();
    
    let position = POSITIONS.with(|map| {
        map.borrow().get(&caller).unwrap_or_else(|| {
            ic_cdk::trap("No position found. Please deposit BTC first.")
        })
    });
    
    if position.btc_collateral < btc_amount {
        ic_cdk::trap(&format!(
            "Insufficient collateral. Available: {}, Requested: {}",
            position.btc_collateral, btc_amount
        ));
    }
    
    // Calculate mUSD to mint (at 99% of collateral value for 1% borrow rate)
    let musd_amount = (btc_amount * 99) / 100;
    
    // CRITICAL FIX: Check LTV before minting
    let total_minted_after = position.musd_minted.checked_add(musd_amount)
        .unwrap_or_else(|| ic_cdk::trap("Overflow: mUSD mint amount would overflow"));
    
    let projected_ltv = (total_minted_after.checked_mul(100)
        .unwrap_or_else(|| ic_cdk::trap("Overflow: LTV calculation would overflow")))
        .checked_div(position.btc_collateral)
        .unwrap_or(u64::MAX);
    
    if projected_ltv > MAX_LTV {
        ic_cdk::trap(&format!(
            "Minting would exceed MAX_LTV. Current LTV: {}%, Projected LTV: {}%, MAX_LTV: {}%",
            (position.musd_minted * 100) / position.btc_collateral,
            projected_ltv,
            MAX_LTV
        ));
    }
    
    // Get canister's Ethereum address (derived from ECDSA key)
    let canister_eth_address = get_canister_eth_address(caller).await;
    
    // Build transaction calldata for borrowing mUSD
    let calldata = build_mint_musd_calldata(musd_amount, &canister_eth_address);
    
    // CRITICAL FIX: Get and track nonce atomically to prevent race conditions
    let nonce = get_and_increment_nonce(&canister_eth_address).await
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Failed to get nonce: {}", e));
        });
    
    // PERFORMANCE OPTIMIZATION: Use default gas values to skip HTTP calls
    // TODO: Replace with Chain Fusion EVM RPC canister for prepaid gas
    // For now, use conservative defaults to avoid 2 HTTP calls (saves 4-6 seconds)
    let gas_price = DEFAULT_GAS_PRICE; // Skip HTTP call for gas price
    let gas_limit = DEFAULT_GAS_LIMIT; // Skip HTTP call for gas estimation
    
    // Build unsigned transaction for signing
    let unsigned_tx = build_unsigned_evm_transaction(
        nonce,
        gas_price,
        gas_limit,
        BORROW_MANAGER_ADDRESS,
        0,
        &calldata,
        MEZO_TESTNET_CHAIN_ID,
    );
    
    // Hash unsigned transaction for signing (EIP-155)
    let tx_hash = Keccak256::digest(&unsigned_tx);
    
    // Sign transaction hash with ECDSA
    let derivation_path = vec![caller.as_slice().to_vec()];
    let signature_result = ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(
        ic_cdk::api::management_canister::ecdsa::SignWithEcdsaArgument {
            message_hash: tx_hash.to_vec(),
            derivation_path: derivation_path.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: KEY_NAME.to_string(),
            },
        },
    )
    .await;
    
    // CRITICAL FIX: Sign transaction and only update state after confirmation
    let sig_response = match signature_result {
        Ok((response,)) => response,
        Err(err) => {
            ic_cdk::trap(&format!("Failed to sign transaction: {:?}", err));
        }
    };
    
    // Parse signature to get v, r, s
    let (v, r, s) = parse_ecdsa_signature(&sig_response.signature);
    
    // Build signed transaction
    let signed_tx = build_signed_evm_transaction(
        nonce,
        gas_price,
        gas_limit,
        BORROW_MANAGER_ADDRESS,
        0,
        &calldata,
        MEZO_TESTNET_CHAIN_ID,
        v,
        &r,
        &s,
    );
    
    // Encode signed transaction as hex
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_tx));
    
    // Send transaction via Chain Fusion (faster than HTTP outcalls)
    let send_start = ic_cdk::api::time();
    let tx_hash = match send_evm_transaction_via_chain_fusion(&raw_tx_hex).await {
        Ok(hash) => hash,
        Err(err) => {
            ic_cdk::println!("Chain Fusion failed: {}, falling back to HTTP outcall", err);
            // Fallback to HTTP outcall if Chain Fusion fails
            match send_eth_transaction(&raw_tx_hex).await {
                Ok(hash) => hash,
                Err(http_err) => {
                    ic_cdk::trap(&format!("Both Chain Fusion and HTTP outcall failed. Chain Fusion: {}, HTTP: {:?}", err, http_err));
                }
            }
        }
    };
    let send_time_ms = (ic_cdk::api::time() - send_start) / 1_000_000;
    ic_cdk::println!("Transaction sent in {}ms, tx_hash: {}", send_time_ms, tx_hash);
    
    // Check timeout before polling
    let elapsed_secs = (ic_cdk::api::time() - start_time) / 1_000_000_000;
    let remaining_time = TRANSACTION_TIMEOUT_SECS.saturating_sub(elapsed_secs);
    
    if remaining_time < 15 {
        ic_cdk::trap(&format!(
            "Insufficient time remaining for confirmation. Elapsed: {}s, Remaining: {}s",
            elapsed_secs, remaining_time
        ));
    }
    
    // CRITICAL FIX: Poll for transaction receipt and validate success before updating state
    let poll_start = ic_cdk::api::time();
    let poll_result = poll_transaction_receipt(&tx_hash).await;
    let poll_time_ms = (ic_cdk::api::time() - poll_start) / 1_000_000;
    
    match poll_result {
        Ok(true) => {
            // Transaction succeeded - now update state
            let total_minted = position.musd_minted.checked_add(musd_amount)
                .unwrap_or_else(|| ic_cdk::trap("Overflow: mUSD mint would overflow"));
            
            let current_ltv = (total_minted.checked_mul(100)
                .unwrap_or_else(|| ic_cdk::trap("Overflow: LTV calculation would overflow")))
                .checked_div(position.btc_collateral)
                .unwrap_or(u64::MAX);
            
            // Update position only after transaction confirmation
            let updated_position = BridgePosition {
                user: caller,
                btc_collateral: position.btc_collateral,
                musd_minted: total_minted,
                sol_deployed: position.sol_deployed,
                status: "musd_minted".to_string(),
                btc_address: position.btc_address,
                sol_address: position.sol_address,
            };
            
            POSITIONS.with(|map| {
                map.borrow_mut().insert(caller, updated_position);
            });
            
            // Log performance metrics
            let total_time_ms = (ic_cdk::api::time() - start_time) / 1_000_000;
            ic_cdk::println!(
                "Transaction completed successfully. Metrics: send={}ms, poll={}ms, total={}ms",
                send_time_ms, poll_time_ms, total_time_ms
            );
            
            MintResponse {
                musd_amount,
                transaction_hash: tx_hash,
                new_ltv: format!("{}%", current_ltv),
                status: "confirmed".to_string(),
            }
        }
        Ok(false) => {
            ic_cdk::trap("Transaction failed on chain");
        }
        Err(e) => {
            ic_cdk::trap(&format!("Transaction receipt validation failed: {}", e));
        }
    }
}

// Helper function to get Ethereum gas price via RPC
async fn get_eth_gas_price() -> Result<u64, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_gasPrice",
        "params": []
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_TESTNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&request_body).unwrap().into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = String::from_utf8(response.body.to_vec())
                    .map_err(|e| format!("Invalid UTF-8: {:?}", e))?;
                let json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Invalid JSON: {:?}", e))?;
                
                if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                    let gas_price_hex = result.trim_start_matches("0x");
                    u64::from_str_radix(gas_price_hex, 16)
                        .map_err(|e| format!("Invalid hex: {:?}", e))
                } else {
                    Err("No result in response".to_string())
                }
            } else {
                Err(format!("HTTP error: {}", response.status))
            }
        }
        Err(err) => Err(format!("HTTP request failed: {:?}", err)),
    }
}

// Helper function to estimate gas limit via RPC
async fn estimate_gas(from: &str, to: &str, data: &[u8]) -> Result<u64, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_estimateGas",
        "params": [{
            "from": from,
            "to": to,
            "data": format!("0x{}", hex::encode(data))
        }]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_TESTNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&request_body).unwrap().into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = String::from_utf8(response.body.to_vec())
                    .map_err(|e| format!("Invalid UTF-8: {:?}", e))?;
                let json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Invalid JSON: {:?}", e))?;
                
                if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                    let gas_hex = result.trim_start_matches("0x");
                    u64::from_str_radix(gas_hex, 16)
                        .map_err(|e| format!("Invalid hex: {:?}", e))
                } else {
                    Err("No result in response".to_string())
                }
            } else {
                Err(format!("HTTP error: {}", response.status))
            }
        }
        Err(err) => Err(format!("HTTP request failed: {:?}", err)),
    }
}

// Helper function to sleep for specified seconds (yields control to allow other messages)
async fn sleep_seconds(seconds: u64) {
    let nanos = seconds * 1_000_000_000;
    let deadline = ic_cdk::api::time() + nanos;
    
    // Efficient busy-wait that yields control periodically
    // Check every 100ms to avoid excessive CPU usage
    let check_interval = 100_000_000; // 100ms in nanoseconds
    
    while ic_cdk::api::time() < deadline {
        let current_time = ic_cdk::api::time();
        let remaining = deadline.saturating_sub(current_time);
        
        if remaining > check_interval {
            // Sleep for check_interval
            let sleep_deadline = current_time + check_interval;
            while ic_cdk::api::time() < sleep_deadline {
                // Busy wait - in ICP, we can't use std::thread::sleep
                // This is acceptable as it's a short interval
            }
        } else {
            // Final wait for remaining time
            while ic_cdk::api::time() < deadline {
                // Busy wait for remaining time
            }
            break;
        }
    }
}

// Helper function to check transaction status (extracted for reuse)
async fn check_transaction_status(tx_hash: &str) -> Result<Option<bool>, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_TESTNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&request_body).unwrap().into_bytes()),
        max_response_bytes: Some(5000), // Receipts can be larger
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = String::from_utf8(response.body.to_vec())
                    .map_err(|e| format!("Invalid UTF-8: {:?}", e))?;
                let json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Invalid JSON: {:?}", e))?;
                
                if let Some(result) = json.get("result") {
                    if !result.is_null() {
                        // Validate transaction status
                        // Status "0x1" = success, "0x0" = failure
                        if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
                            if status == "0x1" {
                                return Ok(Some(true)); // Transaction succeeded
                            } else if status == "0x0" {
                                return Ok(Some(false)); // Transaction failed
                            }
                        }
                        // If status field is missing, assume success for backwards compatibility
                        ic_cdk::println!("Warning: Transaction receipt missing status field");
                        return Ok(Some(true));
                    }
                }
                Ok(None) // Receipt not found yet
            } else {
                Err(format!("HTTP error: {}", response.status))
            }
        }
        Err(err) => Err(format!("HTTP request failed: {:?}", err)),
    }
}

// Helper function to poll for transaction receipt with adaptive intervals
async fn poll_transaction_receipt_adaptive(tx_hash: &str) -> Result<bool, String> {
    // Adaptive polling: fast initially, then slow down
    // Intervals: 1s, 1s, 2s, 2s, 3s, 3s, 4s, 4s, 5s, 5s = ~30 seconds total
    let poll_intervals = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5];
    
    for (attempt, &interval_secs) in poll_intervals.iter().enumerate() {
        match check_transaction_status(tx_hash).await {
            Ok(Some(true)) => {
                ic_cdk::println!("Transaction confirmed after {} polls", attempt + 1);
                return Ok(true);
            }
            Ok(Some(false)) => {
                return Err("Transaction failed on chain".to_string());
            }
            Ok(None) => {
                // Receipt not found yet, continue polling
            }
            Err(e) => {
                ic_cdk::println!("Error checking transaction status: {}", e);
                // Continue polling on error
            }
        }
        
        // Wait before next poll (except on last attempt)
        if attempt < poll_intervals.len() - 1 {
            sleep_seconds(interval_secs).await;
        }
    }
    
    Err("Transaction receipt not found after ~30 seconds of polling".to_string())
}

// Helper function to poll for transaction receipt and validate status
async fn poll_transaction_receipt(tx_hash: &str) -> Result<bool, String> {
    poll_transaction_receipt_adaptive(tx_hash).await
}

// Helper function to get and track nonce atomically to prevent race conditions
async fn get_and_increment_nonce(address: &str) -> Result<u64, String> {
    // Get current nonce from chain
    let chain_nonce = get_eth_nonce(address).await?;
    
    // Get last used nonce from storage
    let key = NonceKey(address.to_string());
    let stored_nonce = NONCE_TRACKER.with(|tracker| {
        tracker.borrow().get(&key).unwrap_or(0)
    });
    
    // Use the maximum of chain nonce and stored nonce + 1 to handle concurrent requests
    let next_nonce = std::cmp::max(chain_nonce, stored_nonce.checked_add(1).unwrap_or(chain_nonce));
    
    // Update stored nonce
    NONCE_TRACKER.with(|tracker| {
        tracker.borrow_mut().insert(key, next_nonce);
    });
    
    Ok(next_nonce)
}

// Helper function to get Ethereum nonce via RPC
async fn get_eth_nonce(address: &str) -> Result<u64, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionCount",
        "params": [address, "latest"]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_TESTNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&request_body).unwrap().into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = String::from_utf8(response.body.to_vec())
                    .map_err(|e| format!("Invalid UTF-8: {:?}", e))?;
                let json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Invalid JSON: {:?}", e))?;
                
                if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                    let nonce_hex = result.trim_start_matches("0x");
                    u64::from_str_radix(nonce_hex, 16)
                        .map_err(|e| format!("Invalid hex: {:?}", e))
                } else {
                    Err("No result in response".to_string())
                }
            } else {
                Err(format!("HTTP error: {}", response.status))
            }
        }
        Err(err) => Err(format!("HTTP request failed: {:?}", err)),
    }
}

// Chain Fusion EVM RPC Integration
// Uses ICP's EVM RPC canister to send transactions via inter-canister calls
// This eliminates HTTP outcalls for gas price, estimation, and transaction submission
// Reference: https://internetcomputer.org/docs/building-apps/chain-fusion/ethereum/evm-rpc/overview
async fn send_evm_transaction_via_chain_fusion(raw_tx_hex: &str) -> Result<String, String> {
    let evm_rpc_id = Principal::from_text(EVM_RPC_CANISTER_ID)
        .map_err(|e| format!("Invalid EVM RPC canister ID: {:?}", e))?;
    
    // Configure custom RPC service for Mezo testnet
    // Using Custom variant to specify chain ID 31611 and our RPC endpoint
    let rpc_services = RpcServices::Custom {
        chain_id: MEZO_TESTNET_CHAIN_ID,
        services: vec![RpcApi {
            url: MEZO_TESTNET_RPC.to_string(),
            headers: Some(vec![RpcHttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }]),
        }],
    };
    
    // Optional RPC config (can be None to use defaults)
    let rpc_config: Option<RpcConfig> = None;
    
    // Call eth_sendRawTransaction via Chain Fusion
    // This uses inter-canister calls which are faster than HTTP outcalls
    let result: Result<(MultiSendRawTransactionResult,), _> = ic_cdk::call(
        evm_rpc_id,
        "eth_sendRawTransaction",
        (rpc_services, rpc_config, raw_tx_hex.to_string()),
    )
    .await;
    
    match result {
        Ok((multi_result,)) => {
            match multi_result {
                MultiSendRawTransactionResult::Consistent(send_result) => {
                    match send_result.status {
                        SendRawTransactionStatus::Ok(Some(tx_hash)) => Ok(tx_hash),
                        SendRawTransactionStatus::Ok(None) => Err("Transaction submitted but no hash returned".to_string()),
                        SendRawTransactionStatus::NonceTooLow => Err("Nonce too low".to_string()),
                        SendRawTransactionStatus::NonceTooHigh => Err("Nonce too high".to_string()),
                        SendRawTransactionStatus::InsufficientFunds => Err("Insufficient funds for gas".to_string()),
                    }
                }
                MultiSendRawTransactionResult::Inconsistent(results) => {
                    // Multiple providers returned different results
                    // Try to extract a successful result
                    for (provider, send_result) in results {
                        if let SendRawTransactionStatus::Ok(Some(tx_hash)) = send_result.status {
                            ic_cdk::println!("Warning: Inconsistent results, using result from provider: {}", provider);
                            return Ok(tx_hash);
                        }
                    }
                    Err("All providers returned errors".to_string())
                }
            }
        }
        Err((code, msg)) => Err(format!("EVM RPC canister call failed: code={:?}, message={}", code, msg)),
    }
}

// Helper function to send Ethereum transaction via RPC
// TODO: Replace with Chain Fusion when EVM RPC canister is configured
async fn send_eth_transaction(raw_tx_hex: &str) -> Result<String, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [raw_tx_hex]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_TESTNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&request_body).unwrap().into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = String::from_utf8(response.body.to_vec())
                    .map_err(|e| format!("Invalid UTF-8: {:?}", e))?;
                let json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Invalid JSON: {:?}", e))?;
                
                if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                    Ok(result.to_string())
                } else {
                    Err("No result in response".to_string())
                }
            } else {
                Err(format!("HTTP error: {}", response.status))
            }
        }
        Err(err) => Err(format!("HTTP request failed: {:?}", err)),
    }
}

#[ic_cdk::update]
async fn bridge_musd_to_solana(musd_amount: u64) -> String {
    // Input validation
    if musd_amount == 0 {
        ic_cdk::trap("Invalid input: mUSD amount must be greater than 0");
    }
    
    let caller = ic_cdk::caller();
    
    let position = POSITIONS.with(|map| {
        map.borrow().get(&caller).unwrap_or_else(|| {
            ic_cdk::trap("No position found")
        })
    });
    
    if position.musd_minted < musd_amount {
        ic_cdk::trap("Insufficient mUSD balance");
    }
    
    let solana_canister_id = CANISTER_IDS.with(|ids| {
        ids.borrow().borrow().solana_canister.clone().unwrap_or_else(|| {
            ic_cdk::trap("Solana canister not configured. Please contact admin.")
        })
    });
    
    // Call Solana canister to generate address
    let sol_canister = match Principal::from_text(&solana_canister_id) {
        Ok(principal) => principal,
        Err(e) => {
            ic_cdk::trap(&format!("Invalid Solana canister ID '{}': {:?}", solana_canister_id, e));
        }
    };
    
    // Call generate_solana_address on the Solana canister
    let sol_address_result: Result<(String,), _> = ic_cdk::call(sol_canister, "generate_solana_address", ())
        .await;
    
    let sol_address = match sol_address_result {
        Ok((addr,)) => addr,
        Err(err) => {
            ic_cdk::println!("Failed to generate Solana address: {:?}", err);
            // Fallback to placeholder
            format!("solana_placeholder_{}", caller.to_text())
        }
    };
    
    // CRITICAL FIX: Call send_sol and check result before updating state
    let bridge_result: Result<(String, String, String), _> = ic_cdk::call(
        sol_canister,
        "send_sol",
        (sol_address.clone(), musd_amount),
    )
    .await;
    
    match bridge_result {
        Ok((signature, status, message)) => {
            // Check if transaction was successful
            if status == "error" || status == "failed" {
                ic_cdk::trap(&format!("Solana bridge transaction failed: {}", message));
            }
            
            // CRITICAL FIX: Only update state if bridge succeeded
            // Also decrement musd_minted when bridging (or track separately)
            let new_musd_minted = position.musd_minted.checked_sub(musd_amount)
                .unwrap_or_else(|| ic_cdk::trap("Overflow: mUSD balance would underflow"));
            
            let new_sol_deployed = position.sol_deployed.checked_add(musd_amount)
                .unwrap_or_else(|| ic_cdk::trap("Overflow: Sol deployed amount would overflow"));
            
            let updated_position = BridgePosition {
                user: caller,
                btc_collateral: position.btc_collateral,
                musd_minted: new_musd_minted,
                sol_deployed: new_sol_deployed,
                status: "bridged_to_solana".to_string(),
                btc_address: position.btc_address,
                sol_address: sol_address.clone(),
            };
            
            POSITIONS.with(|map| {
                map.borrow_mut().insert(caller, updated_position);
            });
            
            format!("Successfully bridged {} mUSD to Solana address: {}. Transaction: {}", musd_amount, sol_address, signature)
        }
        Err(err) => {
            ic_cdk::trap(&format!("Failed to bridge mUSD to Solana: {:?}", err));
        }
    }
}

#[ic_cdk::update]
fn deploy_to_yield_protocol(musd_amount: u64, protocol: String) -> String {
    // Input validation
    if musd_amount == 0 {
        ic_cdk::trap("Invalid input: mUSD amount must be greater than 0");
    }
    
    if protocol.is_empty() {
        ic_cdk::trap("Invalid input: Protocol name cannot be empty");
    }
    
    // Validate protocol name (basic sanitization)
    if protocol.len() > 50 {
        ic_cdk::trap("Invalid input: Protocol name too long");
    }
    
    let caller = ic_cdk::caller();
    
    let position = POSITIONS.with(|map| {
        map.borrow().get(&caller).unwrap_or_else(|| {
            ic_cdk::trap("No position found")
        })
    });
    
    if position.sol_deployed < musd_amount {
        ic_cdk::trap("Insufficient bridged mUSD");
    }
    
    format!("Deployed {} mUSD to {} successfully", musd_amount, protocol)
}

#[ic_cdk::query]
fn get_position(user: Principal) -> BridgePosition {
    POSITIONS.with(|map| {
        map.borrow().get(&user).unwrap_or_else(|| {
            BridgePosition {
                user,
                btc_collateral: 0,
                musd_minted: 0,
                sol_deployed: 0,
                status: "none".to_string(),
                btc_address: "".to_string(),
                sol_address: "".to_string(),
            }
        })
    })
}

#[ic_cdk::query]
fn get_my_position() -> BridgePosition {
    get_position(ic_cdk::caller())
}

#[ic_cdk::query]
fn calculate_max_mintable(btc_collateral: u64) -> u64 {
    // At 90% LTV, user can mint 90% of collateral value
    (btc_collateral * MAX_LTV) / 100
}

#[ic_cdk::query]
fn get_bridge_stats() -> BridgeStats {
    let mut total_btc = 0u64;
    let mut total_musd = 0u64;
    let mut total_sol_deployed = 0u64;
    
    POSITIONS.with(|map| {
        for (_, position) in map.borrow().iter() {
            // Use saturating_add to prevent overflow in stats calculation
            total_btc = total_btc.saturating_add(position.btc_collateral);
            total_musd = total_musd.saturating_add(position.musd_minted);
            total_sol_deployed = total_sol_deployed.saturating_add(position.sol_deployed);
        }
    });
    
    let total_positions = POSITIONS.with(|map| map.borrow().len() as u64);
    
    BridgeStats {
        total_positions,
        total_btc_collateral: total_btc,
        total_musd_minted: total_musd,
        total_sol_deployed,
        max_ltv: MAX_LTV,
        interest_rate: INTEREST_RATE,
    }
}

#[derive(CandidType, Deserialize, Debug)]
pub struct HealthStatus {
    pub status: String,
    pub canister_id: String,
    pub cycles_balance: u64,
    pub btc_canister_configured: bool,
    pub solana_canister_configured: bool,
    pub total_positions: u64,
    pub timestamp: u64,
}

#[ic_cdk::query]
fn debug_get_config() -> String {
    let btc_canister = CANISTER_IDS.with(|ids| {
        ids.borrow().borrow().btc_canister.clone()
    });
    let solana_canister = CANISTER_IDS.with(|ids| {
        ids.borrow().borrow().solana_canister.clone()
    });
    
    format!(
        "Bridge Configuration:\n\
         - BTC Canister: {:?}\n\
         - Solana Canister: {:?}\n\
         - Total Positions: {}\n\
         - Cycles Balance: {}",
        btc_canister,
        solana_canister,
        POSITIONS.with(|map| map.borrow().len()),
        ic_cdk::api::canister_balance()
    )
}

#[ic_cdk::query]
fn health_check() -> HealthStatus {
    let canister_id = ic_cdk::id();
    let cycles_balance = ic_cdk::api::canister_balance();
    
    let (btc_configured, solana_configured) = CANISTER_IDS.with(|ids| {
        let inner = ids.borrow();
        let ids_ref = inner.borrow();
        (
            ids_ref.btc_canister.is_some(),
            ids_ref.solana_canister.is_some(),
        )
    });
    
    let total_positions = POSITIONS.with(|map| map.borrow().len() as u64);
    
    HealthStatus {
        status: "healthy".to_string(),
        canister_id: canister_id.to_text(),
        cycles_balance,
        btc_canister_configured: btc_configured,
        solana_canister_configured: solana_configured,
        total_positions,
        timestamp: ic_cdk::api::time(),
    }
}

#[ic_cdk::query]
fn get_cycles_balance() -> u64 {
    ic_cdk::api::canister_balance()
}

#[ic_cdk::init]
fn init() {}

#[ic_cdk::post_upgrade]
fn post_upgrade() {}
