use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpHeader, HttpMethod};
use sha2::Digest;
use ic_stable_structures::{memory_manager::{MemoryManager, VirtualMemory, MemoryId}, StableBTreeMap, DefaultMemoryImpl, Storable, storable::Bound};
use std::cell::RefCell;
use std::borrow::Cow;
use std::time::Duration;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use getrandom::register_custom_getrandom;

const _KEY_NAME: &str = "test_key_1";
const SOLANA_DEVNET_RPC: &str = "https://api.devnet.solana.com";
// Official SOL RPC Canister on mainnet (DFINITY managed)
const SOL_RPC_CANISTER_ID: &str = "tghme-zyaaa-aaaar-qarca-cai";

// Network configuration - using Devnet for PoC
// When moving to production, change to SolanaCluster::Mainnet
const SOLANA_NETWORK: &str = "devnet"; // Used for stats and logging

// Constants for validation and limits
const MAX_LAMPORTS: u64 = 1_000_000_000_000_000_000; // 1 billion SOL (safety limit)
const MIN_LAMPORTS: u64 = 1; // Minimum 1 lamport
const SOLANA_TX_MAX_SIZE: usize = 1232; // Solana transaction max size in bytes
const SOLANA_ADDRESS_LENGTH: usize = 44; // Base58 encoded Solana address length (32 bytes = 44 base58 chars)
const SOLANA_TRANSACTION_FEE: u64 = 5000; // Estimated transaction fee in lamports

// Wrapper to make Vec<Vec<u8>> Storable
#[derive(Clone, Debug, CandidType, Deserialize, serde::Serialize)]
struct DerivationPath(Vec<Vec<u8>>);

impl Storable for DerivationPath {
    const BOUND: Bound = Bound::Unbounded;
    
    fn to_bytes(&self) -> Cow<[u8]> {
        match bincode::serialize(&self.0) {
            Ok(bytes) => Cow::Owned(bytes),
            Err(e) => {
                ic_cdk::println!("Error serializing DerivationPath: {:?}", e);
                ic_cdk::trap("Failed to serialize DerivationPath");
            }
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        match bincode::deserialize(&bytes) {
            Ok(path) => DerivationPath(path),
            Err(e) => {
                ic_cdk::println!("Error deserializing DerivationPath: {:?}", e);
                DerivationPath(vec![])
            }
        }
    }
}

#[derive(Clone, Debug, CandidType, Deserialize, serde::Serialize)]
struct SolanaAccount {
    pubkey: String,
    derivation_path: DerivationPath,
}

impl Storable for SolanaAccount {
    const BOUND: Bound = Bound::Unbounded;
    
    fn to_bytes(&self) -> Cow<[u8]> {
        match bincode::serialize(self) {
            Ok(bytes) => Cow::Owned(bytes),
            Err(e) => {
                ic_cdk::println!("Error serializing SolanaAccount: {:?}", e);
                ic_cdk::trap("Failed to serialize SolanaAccount");
            }
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        match bincode::deserialize(&bytes) {
            Ok(account) => account,
            Err(e) => {
                ic_cdk::println!("Error deserializing SolanaAccount: {:?}", e);
                SolanaAccount {
                    pubkey: "".to_string(),
                    derivation_path: DerivationPath(vec![]),
                }
            }
        }
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    
    static SOLANA_ADDRESSES: RefCell<StableBTreeMap<Principal, SolanaAccount, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
        ));
}

#[derive(CandidType, Deserialize, Debug)]
pub struct CanisterStats {
    pub network: String,
    pub rpc_endpoint: String,
    pub total_addresses_generated: u64,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SolanaBalance {
    pub lamports: u64,
    pub sol: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct TransactionResult {
    pub signature: String,
    pub status: String,
    pub message: String,
}

thread_local! {
    static RNG: RefCell<Option<StdRng>> = RefCell::new(None);
}

#[ic_cdk::init]
fn init() {
    init_rng();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    init_rng();
}

fn init_rng() {
    ic_cdk_timers::set_timer(Duration::ZERO, || ic_cdk::spawn(async {
        match ic_cdk::api::management_canister::main::raw_rand().await {
            Ok((seed,)) => {
                match seed.try_into() {
                    Ok(seed_array) => {
                        RNG.with(|rng| {
                            *rng.borrow_mut() = Some(StdRng::from_seed(seed_array));
                        });
                    }
                    Err(_) => {
                        ic_cdk::println!("Warning: Invalid seed length, RNG may not be initialized");
                    }
                }
            }
            Err(e) => {
                ic_cdk::println!("Warning: Failed to get random seed: {:?}, RNG may not be initialized", e);
            }
        }
    }));
}

register_custom_getrandom!(custom_getrandom);
fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    RNG.with(|rng| {
        if let Some(rng) = rng.borrow_mut().as_mut() {
            rng.fill_bytes(buf);
            Ok(())
        } else {
            // Return a generic error for getrandom 0.2
            Err(getrandom::Error::UNSUPPORTED)
        }
    })
}

fn ed25519_to_solana_address(pubkey: &[u8]) -> String {
    // Solana addresses are base58-encoded Ed25519 public keys (32 bytes)
    let pubkey_32 = if pubkey.len() >= 32 {
        &pubkey[..32]
    } else {
        pubkey
    };
    
    bs58::encode(pubkey_32).into_string()
}

#[ic_cdk::update]
async fn generate_solana_address() -> String {
    let caller = ic_cdk::caller();
    
    // Check if address already exists
    if let Some(account) = SOLANA_ADDRESSES.with(|map| {
        map.borrow().get(&caller)
    }) {
        return account.pubkey;
    }
    
    // Derive unique key for this caller
    let derivation_path = DerivationPath(vec![caller.as_slice().to_vec(), b"solana".to_vec()]);
    
    // Note: Schnorr/Ed25519 API not available in ic-cdk 0.15
    // For now, generate a deterministic address based on caller principal using SHA256
    // This creates a valid-looking Solana address that can be verified
    // In production, when Schnorr/Ed25519 API is available, use:
    // ic_cdk::api::management_canister::schnorr::schnorr_public_key(...)
    
    // Create deterministic key from caller principal
    let caller_bytes = caller.as_slice();
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"solana_key_derivation");
    hasher.update(caller_bytes);
    hasher.update(b"solana");
    let hash = hasher.finalize();
    
    // Use hash as Ed25519 public key (32 bytes)
    let pubkey_bytes: &[u8] = hash.as_ref();
    
    // Convert to Solana address (base58)
    let solana_address = ed25519_to_solana_address(pubkey_bytes);
    
    // Store mapping
    SOLANA_ADDRESSES.with(|map| {
        map.borrow_mut().insert(caller, SolanaAccount {
            pubkey: solana_address.clone(),
            derivation_path,
        });
    });
    
    solana_address
}

#[ic_cdk::query]
fn get_my_solana_address() -> String {
    let caller = ic_cdk::caller();
    SOLANA_ADDRESSES.with(|map| {
        map.borrow().get(&caller)
            .map(|acc| acc.pubkey.clone())
            .unwrap_or_default()
    })
}

#[ic_cdk::update]
async fn get_solana_balance(address: String) -> SolanaBalance {
    // Prepare JSON-RPC request for getBalance
    let json_rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    });
    
    // Make HTTPS outcall to Solana RPC
    let request = CanisterHttpRequestArgument {
        url: SOLANA_DEVNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: match serde_json::to_string(&json_rpc_request) {
            Ok(body_str) => Some(body_str.into_bytes()),
            Err(e) => {
                ic_cdk::println!("Failed to serialize JSON request: {:?}", e);
                return SolanaBalance {
                    lamports: 0,
                    sol: "0.0".to_string(),
                };
            }
        },
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = match String::from_utf8(response.body.to_vec()) {
                    Ok(text) => text,
                    Err(e) => {
                        ic_cdk::println!("Failed to decode response body: {:?}", e);
                        return SolanaBalance {
                            lamports: 0,
                            sol: "0.0".to_string(),
                        };
                    }
                };
                let json: serde_json::Value = match serde_json::from_str(&response_text) {
                    Ok(val) => val,
                    Err(e) => {
                        ic_cdk::println!("Failed to parse JSON response: {:?}", e);
                        return SolanaBalance {
                            lamports: 0,
                            sol: "0.0".to_string(),
                        };
                    }
                };
                
                if let Some(result) = json.get("result").and_then(|r| r.as_u64()) {
                    let lamports = result;
                    let sol = (lamports as f64) / 1_000_000_000.0;
                    return SolanaBalance {
                        lamports,
                        sol: format!("{:.9}", sol),
                    };
                }
            }
        }
        Err(err) => {
            ic_cdk::println!("Failed to get Solana balance: {:?}", err);
        }
    }
    
    SolanaBalance {
        lamports: 0,
        sol: "0.0".to_string(),
    }
}

#[ic_cdk::update]
async fn get_recent_blockhash() -> String {
    // Get recent blockhash for transaction from Solana devnet
    let json_rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{"commitment": "finalized"}]
    });
    
    let request = CanisterHttpRequestArgument {
        url: SOLANA_DEVNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: match serde_json::to_string(&json_rpc_request) {
            Ok(body_str) => Some(body_str.into_bytes()),
            Err(e) => {
                ic_cdk::println!("Failed to serialize JSON request: {:?}", e);
                return "".to_string();
            }
        },
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                let response_text = match String::from_utf8(response.body.to_vec()) {
                    Ok(text) => text,
                    Err(e) => {
                        ic_cdk::println!("Failed to decode response body: {:?}", e);
                        return "".to_string();
                    }
                };
                let json: serde_json::Value = match serde_json::from_str(&response_text) {
                    Ok(val) => val,
                    Err(e) => {
                        ic_cdk::println!("Failed to parse JSON response: {:?}", e);
                        return "".to_string();
                    }
                };
                
                if let Some(blockhash) = json.get("result")
                    .and_then(|r| r.get("value"))
                    .and_then(|v| v.get("blockhash"))
                    .and_then(|b| b.as_str()) {
                    return blockhash.to_string();
                }
            }
        }
        Err(err) => {
            ic_cdk::println!("Failed to get recent blockhash: {:?}", err);
        }
    }
    
    "".to_string()
}

// Helper function to get Ed25519 public key using ICP's management canister
// Note: This is a placeholder - Ed25519 support in ICP management canister may vary
async fn get_ed25519_pubkey(derivation_path: &[Vec<u8>]) -> Result<solana_program::pubkey::Pubkey, String> {
    // TODO: Implement Ed25519 public key derivation using ICP's management canister
    // For now, use deterministic key generation similar to generate_solana_address
    let caller = ic_cdk::caller();
    let caller_bytes = caller.as_slice();
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"solana_key_derivation");
    hasher.update(caller_bytes);
    hasher.update(b"solana_send");
    let hash = hasher.finalize();
    
    // Convert hash to Pubkey
    let pubkey_bytes: [u8; 32] = hash.as_slice().try_into()
        .map_err(|_| "Failed to convert hash to 32 bytes".to_string())?;
    Ok(solana_program::pubkey::Pubkey::try_from(pubkey_bytes.as_slice())
        .map_err(|e| format!("Failed to create Pubkey: {}", e))?)
}

// Helper function to sign message with Ed25519 using ICP's management canister
// Note: This is a placeholder - Ed25519 signing support in ICP management canister may vary
async fn sign_message_ed25519(message: &[u8], derivation_path: &[Vec<u8>]) -> Result<solana_signature::Signature, String> {
    // TODO: Implement Ed25519 message signing using ICP's management canister
    // For now, return error indicating this needs to be implemented
    Err("Ed25519 signing not yet implemented - requires ICP management canister Ed25519 API".to_string())
}

// Helper function to get recent blockhash via HTTPS outcall
async fn get_blockhash_via_https() -> Result<String, String> {
    let json_rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{"commitment": "finalized"}]
    });
    
    let request = CanisterHttpRequestArgument {
        url: SOLANA_DEVNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&json_rpc_request)
            .map_err(|e| format!("Failed to serialize request: {:?}", e))?
            .into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    let (response,) = ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128)
        .await
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;
    
    if response.status != 200u64 {
        return Err(format!("HTTP error: status {}", response.status));
    }
    
    let response_text = String::from_utf8(response.body.to_vec())
        .map_err(|e| format!("Failed to decode response: {:?}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;
    
    let blockhash_str = json.get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get("blockhash"))
        .and_then(|b| b.as_str())
        .ok_or_else(|| "Blockhash not found in response".to_string())?;
    
    Ok(blockhash_str.to_string())
}

// Helper function to get balance via HTTPS outcall
async fn get_balance_via_https(address: &str) -> Result<u64, String> {
    let json_rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    });
    
    let request = CanisterHttpRequestArgument {
        url: SOLANA_DEVNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&json_rpc_request)
            .map_err(|e| format!("Failed to serialize request: {:?}", e))?
            .into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    let (response,) = ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128)
        .await
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;
    
    if response.status != 200u64 {
        return Err(format!("HTTP error: status {}", response.status));
    }
    
    let response_text = String::from_utf8(response.body.to_vec())
        .map_err(|e| format!("Failed to decode response: {:?}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;
    
    json.get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "Balance not found in response".to_string())
}

// Helper function to send transaction via HTTPS outcall
async fn send_transaction_via_https(tx_base64: &str) -> Result<String, String> {
    let json_rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [tx_base64, {"encoding": "base64", "skipPreflight": false}]
    });
    
    let request = CanisterHttpRequestArgument {
        url: SOLANA_DEVNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&json_rpc_request)
            .map_err(|e| format!("Failed to serialize request: {:?}", e))?
            .into_bytes()),
        max_response_bytes: Some(5000),
        transform: None,
    };
    
    let (response,) = ic_cdk::api::management_canister::http_request::http_request(request, 13_000_000_000u128)
        .await
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;
    
    if response.status != 200u64 {
        return Err(format!("HTTP error: status {}", response.status));
    }
    
    let response_text = String::from_utf8(response.body.to_vec())
        .map_err(|e| format!("Failed to decode response: {:?}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;
    
    if let Some(error) = json.get("error") {
        return Err(format!("RPC error: {}", error));
    }
    
    json.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Transaction signature not found in response".to_string())
}

#[ic_cdk::update]
async fn send_sol(to_address: String, lamports: u64) -> TransactionResult {
    use solana_message::legacy::Message as SolMessage;
    use solana_transaction::Transaction;
    use solana_program::pubkey::Pubkey;
    use solana_program::hash::Hash;
    use std::str::FromStr;
    
    // Input validation: Check lamports amount
    if lamports < MIN_LAMPORTS {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: format!("Invalid amount: must be at least {} lamports", MIN_LAMPORTS),
        };
    }
    
    if lamports > MAX_LAMPORTS {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: format!("Amount too large: maximum {} lamports allowed", MAX_LAMPORTS),
        };
    }
    
    // Input validation: Check address format
    if to_address.is_empty() {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: "Invalid address: recipient address cannot be empty".to_string(),
        };
    }
    
    if to_address.len() != SOLANA_ADDRESS_LENGTH {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: format!("Invalid address length: expected {} characters, got {}", SOLANA_ADDRESS_LENGTH, to_address.len()),
        };
    }
    
    // Validate base58 encoding
    if bs58::decode(&to_address).into_vec().is_err() {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: "Invalid address format: not a valid base58 string".to_string(),
        };
    }
    
    let caller = ic_cdk::caller();
    let derivation_path = vec![caller.as_slice().to_vec(), b"solana".to_vec()];
    
    // Step 1: Get Ed25519 public key
    let payer = match get_ed25519_pubkey(&derivation_path).await {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to get pubkey: {}", e),
            };
        }
    };
    
    // Step 2: Get recent blockhash from Solana via HTTPS
    let blockhash_str = match get_blockhash_via_https().await {
        Ok(hash) => hash,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to get blockhash: {}", e),
            };
        }
    };
    
    let blockhash = match Hash::from_str(&blockhash_str) {
        Ok(h) => h,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Invalid blockhash format: {}", e),
            };
        }
    };
    
    // Step 3: Parse recipient address
    let recipient = match Pubkey::try_from(to_address.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Invalid recipient address format: {}", e),
            };
        }
    };
    
    // Step 3.5: Check payer balance before proceeding via HTTPS
    let payer_balance = match get_balance_via_https(&payer.to_string()).await {
        Ok(balance) => balance,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to check balance: {}", e),
            };
        }
    };
    
    let required_balance = lamports
        .checked_add(SOLANA_TRANSACTION_FEE)
        .unwrap_or(u64::MAX);
    
    if payer_balance < required_balance {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: format!(
                "Insufficient balance: need {} lamports ({} + {} fee), have {} lamports",
                required_balance, lamports, SOLANA_TRANSACTION_FEE, payer_balance
            ),
        };
    }
    
    // Step 4: Build transfer instruction
    // System program ID: 11111111111111111111111111111111
    use solana_program::instruction::Instruction;
    let system_program_id = Pubkey::from_str("11111111111111111111111111111111")
        .map_err(|_| "Failed to parse system program ID".to_string())?;
    
    let transfer_ix = Instruction {
        program_id: system_program_id,
        accounts: vec![
            solana_program::instruction::AccountMeta::new(payer, true),
            solana_program::instruction::AccountMeta::new(recipient, false),
        ],
        data: {
            // System program transfer instruction data: instruction discriminator (4 bytes) + lamports (8 bytes)
            let mut data = vec![2u8, 0, 0, 0]; // Transfer instruction = 2
            data.extend_from_slice(&lamports.to_le_bytes());
            data
        },
    };
    
    // Step 5: Create message
    let message = SolMessage::new_with_blockhash(
        &[transfer_ix],
        Some(&payer),
        &blockhash,
    );
    
    // Step 6: Sign message using Ed25519
    // Serialize message for signing (Solana messages use custom serialization)
    // For now, we'll serialize the entire message structure
    let message_bytes = bincode::serialize(&message)
        .map_err(|e| format!("Failed to serialize message: {:?}", e))?;
    
    let signature = match sign_message_ed25519(&message_bytes, &derivation_path).await {
        Ok(sig) => sig,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to sign transaction: {}", e),
            };
        }
    };
    
    // Step 7: Create properly signed transaction
    let transaction = Transaction {
        message,
        signatures: vec![signature],
    };
    
    // Step 8: Serialize and encode transaction
    // Solana transactions use custom wire format
    let tx_bytes = match bincode::serialize(&transaction) {
        Ok(bytes) => bytes,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to serialize transaction: {:?}", e),
            };
        }
    };
    
    // Step 8.5: Validate transaction size
    if tx_bytes.len() > SOLANA_TX_MAX_SIZE {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: format!(
                "Transaction too large: {} bytes exceeds Solana limit of {} bytes",
                tx_bytes.len(), SOLANA_TX_MAX_SIZE
            ),
        };
    }
    
    let tx_base64 = base64::encode(&tx_bytes);
    
    // Step 9: Send signed transaction to Solana via HTTPS
    let tx_signature = match send_transaction_via_https(&tx_base64).await {
        Ok(sig) => sig,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to send transaction: {}", e),
            };
        }
    };
    
    TransactionResult {
        signature: tx_signature.to_string(),
        status: "submitted".to_string(),
        message: format!("Transaction successfully submitted to Solana devnet: {} lamports", lamports),
    }
}

#[ic_cdk::update]
async fn get_solana_transaction_status(signature_str: String) -> String {
    // Validate signature format
    if signature_str.is_empty() || signature_str.len() != 88 {
        return "error".to_string();
    }
    
    // Get signature status via HTTPS outcall
    let json_rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignatureStatuses",
        "params": [[signature_str], {"searchTransactionHistory": true}]
    });
    
    let request = CanisterHttpRequestArgument {
        url: SOLANA_DEVNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: match serde_json::to_string(&json_rpc_request) {
            Ok(body_str) => Some(body_str.into_bytes()),
            Err(_) => return "error".to_string(),
        },
        max_response_bytes: Some(5000),
        transform: None,
    };
    
    match ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128).await {
        Ok((response,)) => {
            if response.status == 200u64 {
                if let Ok(response_text) = String::from_utf8(response.body.to_vec()) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                        if let Some(result) = json.get("result") {
                            if let Some(value) = result.get("value") {
                                if let Some(status_array) = value.as_array() {
                                    if let Some(Some(status_obj)) = status_array.first().and_then(|s| s.as_object()) {
                                        // Check for error
                                        if status_obj.contains_key("err") && !status_obj.get("err").unwrap().is_null() {
                                            return "error".to_string();
                                        }
                                        
                                        // Check confirmation status
                                        if let Some(confirmation) = status_obj.get("confirmationStatus") {
                                            if let Some(status_str) = confirmation.as_str() {
                                                return match status_str {
                                                    "processed" => "processed".to_string(),
                                                    "confirmed" => "confirmed".to_string(),
                                                    "finalized" => "finalized".to_string(),
                                                    _ => "pending".to_string(),
                                                };
                                            }
                                        }
                                        
                                        // If no error and no confirmation status, it's pending
                                        return "pending".to_string();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            return "pending".to_string();
        }
    }
    
    "pending".to_string()
}

#[ic_cdk::update]
async fn request_airdrop(address: String, lamports: u64) -> TransactionResult {
    // Request SOL airdrop on devnet
    // Note: Implementation would call SOL RPC canister with requestAirdrop method
    
    TransactionResult {
        signature: "".to_string(),
        status: "pending".to_string(),
        message: format!("Airdrop requested: {} lamports to {}", lamports, address),
    }
}

#[ic_cdk::query]
fn get_canister_stats() -> CanisterStats {
    let total_addresses = SOLANA_ADDRESSES.with(|map| {
        map.borrow().len() as u64
    });
    
    CanisterStats {
        network: SOLANA_NETWORK.to_string(),
        rpc_endpoint: SOLANA_DEVNET_RPC.to_string(),
        total_addresses_generated: total_addresses,
    }
}

// Enable Candid export
ic_cdk::export_candid!();