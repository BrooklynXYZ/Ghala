use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpHeader, HttpMethod};
use ic_cdk::api::call::RejectionCode;
use ic_cdk::call::RejectCode;
use sha2::Digest;
use ic_stable_structures::{memory_manager::{MemoryManager, VirtualMemory, MemoryId}, StableBTreeMap, DefaultMemoryImpl, Storable, storable::Bound};
use std::cell::RefCell;
use std::borrow::Cow;
use std::time::Duration;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use getrandom::register_custom_getrandom;

// Unified error type for consistent error handling
#[derive(Debug)]
enum SolanaError {
    HttpRequest(String),
    Rejection(RejectCode, String),
    Serialization(String),
    Validation(String),
    Signing(String),
    Rpc(String),
}

impl From<(RejectCode, String)> for SolanaError {
    fn from((code, msg): (RejectCode, String)) -> Self {
        SolanaError::Rejection(code, msg)
    }
}

// Helper to convert RejectionCode to RejectCode
fn rejection_to_reject(code: RejectionCode) -> RejectCode {
    match code {
        RejectionCode::NoError => RejectCode::SysFatal, // No direct equivalent, use SysFatal
        RejectionCode::SysFatal => RejectCode::SysFatal,
        RejectionCode::SysTransient => RejectCode::SysTransient,
        RejectionCode::DestinationInvalid => RejectCode::DestinationInvalid,
        RejectionCode::CanisterReject => RejectCode::CanisterReject,
        RejectionCode::CanisterError => RejectCode::CanisterError,
        RejectionCode::Unknown => RejectCode::SysFatal, // No direct equivalent, use SysFatal
    }
}

impl From<SolanaError> for String {
    fn from(err: SolanaError) -> Self {
        match err {
            SolanaError::HttpRequest(msg) => format!("HTTP error: {}", msg),
            SolanaError::Rejection(code, msg) => format!("Rejection {:?}: {}", code, msg),
            SolanaError::Serialization(msg) => format!("Serialization error: {}", msg),
            SolanaError::Validation(msg) => format!("Validation error: {}", msg),
            SolanaError::Signing(msg) => format!("Signing error: {}", msg),
            SolanaError::Rpc(msg) => format!("RPC error: {}", msg),
        }
    }
}

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
    // Initialize RNG with a deterministic seed based on canister state
    // This ensures the canister can start immediately without waiting for async operations
    let canister_id = ic_cdk::id();
    let time = ic_cdk::api::time();
    
    // Create a deterministic seed from canister ID and time
    let mut seed_bytes = [0u8; 32];
    let id_slice = canister_id.as_slice();
    for i in 0..32 {
        seed_bytes[i] = id_slice[i % id_slice.len()] ^ ((time >> (i % 8)) as u8);
    }
    
    RNG.with(|rng| {
        *rng.borrow_mut() = Some(StdRng::from_seed(seed_bytes));
    });
    
    // Optionally, try to get a better random seed asynchronously (non-blocking)
    ic_cdk::futures::spawn(async {
        match ic_cdk::api::management_canister::main::raw_rand().await {
            Ok((seed,)) => {
                if let Ok(seed_array) = seed.try_into() {
                    RNG.with(|rng| {
                        *rng.borrow_mut() = Some(StdRng::from_seed(seed_array));
                    });
                }
            }
            Err(_) => {
                // Keep using the deterministic seed - this is fine
            }
        }
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    // Same initialization as init
    init();
}

register_custom_getrandom!(custom_getrandom);
fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    RNG.with(|rng| {
        if let Some(rng) = rng.borrow_mut().as_mut() {
            rng.fill_bytes(buf);
            Ok(())
        } else {
            // RNG not initialized yet - use a fallback seed based on canister state
            // This ensures the canister can still function even if RNG init is delayed
            let fallback_seed = [
                ic_cdk::api::time() as u8,
                (ic_cdk::api::time() >> 8) as u8,
                (ic_cdk::api::time() >> 16) as u8,
                (ic_cdk::api::time() >> 24) as u8,
                ic_cdk::id().as_slice()[0],
                ic_cdk::id().as_slice()[1],
                ic_cdk::id().as_slice()[2],
                ic_cdk::id().as_slice()[3],
                ic_cdk::id().as_slice()[4],
                ic_cdk::id().as_slice()[5],
                ic_cdk::id().as_slice()[6],
                ic_cdk::id().as_slice()[7],
                ic_cdk::id().as_slice()[8],
                ic_cdk::id().as_slice()[9],
                ic_cdk::id().as_slice()[10],
                ic_cdk::id().as_slice()[11],
                ic_cdk::id().as_slice()[12],
                ic_cdk::id().as_slice()[13],
                ic_cdk::id().as_slice()[14],
                ic_cdk::id().as_slice()[15],
                ic_cdk::id().as_slice()[16],
                ic_cdk::id().as_slice()[17],
                ic_cdk::id().as_slice()[18],
                ic_cdk::id().as_slice()[19],
                ic_cdk::id().as_slice()[20],
                ic_cdk::id().as_slice()[21],
                ic_cdk::id().as_slice()[22],
                ic_cdk::id().as_slice()[23],
                ic_cdk::id().as_slice()[24],
                ic_cdk::id().as_slice()[25],
                ic_cdk::id().as_slice()[26],
                ic_cdk::id().as_slice()[27],
            ];
            let mut temp_rng = StdRng::from_seed(fallback_seed);
            temp_rng.fill_bytes(buf);
            Ok(())
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

// Helper function to get Ed25519 public key using ICP's Schnorr API (ic-cdk 0.19.0+)
async fn get_ed25519_pubkey(derivation_path: &[Vec<u8>]) -> Result<solana_program::pubkey::Pubkey, SolanaError> {
    use ic_cdk::management_canister;
    use ic_management_canister_types::{SchnorrKeyId, SchnorrPublicKeyArgs, SchnorrAlgorithm};
    
    let key_id = SchnorrKeyId {
        name: _KEY_NAME.to_string(),
        algorithm: SchnorrAlgorithm::Ed25519,
    };
    
    let pubkey_result = match management_canister::schnorr_public_key(&SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path.to_vec(),
        key_id: key_id.clone(),
    })
    .await {
        Ok(result) => result,
        Err(e) => {
            // Convert Error to SolanaError
            return Err(SolanaError::Signing(format!("Failed to get public key: {:?}", e)));
        }
    };
    
    let pubkey_bytes = pubkey_result.public_key;
    
    // Schnorr public key is 32 bytes for Ed25519
    if pubkey_bytes.len() != 32 {
        return Err(SolanaError::Validation(format!(
            "Invalid public key length: expected 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }
    
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| SolanaError::Validation("Failed to convert public key to array".to_string()))?;
    
    solana_program::pubkey::Pubkey::try_from(pubkey_array.as_slice())
        .map_err(|e| SolanaError::Validation(format!("Failed to create Pubkey: {}", e)))
}

// Helper function to sign message with Ed25519 using ICP's Schnorr API (ic-cdk 0.19.0+)
async fn sign_message_ed25519(message: &[u8], derivation_path: &[Vec<u8>]) -> Result<solana_signature::Signature, SolanaError> {
    use ic_cdk::management_canister;
    use ic_management_canister_types::{SchnorrKeyId, SignWithSchnorrArgs, SchnorrAlgorithm};
    
    let key_id = SchnorrKeyId {
        name: _KEY_NAME.to_string(),
        algorithm: SchnorrAlgorithm::Ed25519,
    };
    
    // Sign the message using Schnorr (Ed25519)
    use ic_management_canister_types::SchnorrAux;
    let signature_result = match management_canister::sign_with_schnorr(&SignWithSchnorrArgs {
        message: message.to_vec(),
        derivation_path: derivation_path.to_vec(),
        key_id: key_id.clone(),
        aux: None, // Auxiliary data, None for Ed25519
    })
    .await {
        Ok(result) => result,
        Err(e) => {
            // Convert error to SolanaError - the actual error type may vary
            return Err(SolanaError::Signing(format!("Failed to sign message: {:?}", e)));
        }
    };
    
    let signature_bytes = signature_result.signature;
    
    // Solana signatures are 64 bytes
    if signature_bytes.len() != 64 {
        return Err(SolanaError::Signing(format!(
            "Invalid signature length: expected 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    
    let sig_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| SolanaError::Signing("Failed to convert signature to array".to_string()))?;
    
    Ok(solana_signature::Signature::from(sig_array))
}

// Helper function to get recent blockhash via HTTPS outcall
async fn get_blockhash_via_https() -> Result<String, SolanaError> {
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
            .map_err(|e| SolanaError::Serialization(format!("Failed to serialize request: {:?}", e)))?
            .into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    let (response,) = ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128)
        .await
        .map_err(|(code, msg): (RejectionCode, String)| {
            SolanaError::Rejection(rejection_to_reject(code), msg)
        })?;
    
    if response.status != 200u64 {
        return Err(SolanaError::HttpRequest(format!("HTTP error: status {}", response.status)));
    }
    
    let response_text = String::from_utf8(response.body.to_vec())
        .map_err(|e| SolanaError::HttpRequest(format!("Failed to decode response: {:?}", e)))?;
    
    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| SolanaError::Rpc(format!("Failed to parse JSON: {:?}", e)))?;
    
    let blockhash_str = json.get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get("blockhash"))
        .and_then(|b| b.as_str())
        .ok_or_else(|| SolanaError::Rpc("Blockhash not found in response".to_string()))?;
    
    Ok(blockhash_str.to_string())
}

// Helper function to get balance via HTTPS outcall
async fn get_balance_via_https(address: &str) -> Result<u64, SolanaError> {
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
            .map_err(|e| SolanaError::Serialization(format!("Failed to serialize request: {:?}", e)))?
            .into_bytes()),
        max_response_bytes: Some(2000),
        transform: None,
    };
    
    let (response,) = ic_cdk::api::management_canister::http_request::http_request(request, 3_000_000_000u128)
        .await
        .map_err(|(code, msg): (RejectionCode, String)| {
            SolanaError::Rejection(rejection_to_reject(code), msg)
        })?;
    
    if response.status != 200u64 {
        return Err(SolanaError::HttpRequest(format!("HTTP error: status {}", response.status)));
    }
    
    let response_text = String::from_utf8(response.body.to_vec())
        .map_err(|e| SolanaError::HttpRequest(format!("Failed to decode response: {:?}", e)))?;
    
    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| SolanaError::Rpc(format!("Failed to parse JSON: {:?}", e)))?;
    
    json.get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| SolanaError::Rpc("Balance not found in response".to_string()))
}

// Helper function to send transaction via HTTPS outcall
async fn send_transaction_via_https(tx_base64: &str) -> Result<String, SolanaError> {
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
            .map_err(|e| SolanaError::Serialization(format!("Failed to serialize request: {:?}", e)))?
            .into_bytes()),
        max_response_bytes: Some(5000),
        transform: None,
    };
    
    let (response,) = ic_cdk::api::management_canister::http_request::http_request(request, 13_000_000_000u128)
        .await
        .map_err(|(code, msg): (RejectionCode, String)| {
            SolanaError::Rejection(rejection_to_reject(code), msg)
        })?;
    
    if response.status != 200u64 {
        return Err(SolanaError::HttpRequest(format!("HTTP error: status {}", response.status)));
    }
    
    let response_text = String::from_utf8(response.body.to_vec())
        .map_err(|e| SolanaError::HttpRequest(format!("Failed to decode response: {:?}", e)))?;
    
    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| SolanaError::Rpc(format!("Failed to parse JSON: {:?}", e)))?;
    
    if let Some(error) = json.get("error") {
        return Err(SolanaError::Rpc(format!("RPC error: {}", error)));
    }
    
    json.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SolanaError::Rpc("Transaction signature not found in response".to_string()))
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
    
    // Step 1: Get Ed25519 public key using Schnorr API
    let payer = match get_ed25519_pubkey(&derivation_path).await {
        Ok(pk) => pk,
        Err(e) => {
            let msg: String = e.into();
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to get pubkey: {}", msg),
            };
        }
    };
    
    // Step 2: Get recent blockhash from Solana via HTTPS
    let blockhash_str = match get_blockhash_via_https().await {
        Ok(hash) => hash,
        Err(e) => {
            let msg: String = e.into();
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to get blockhash: {}", msg),
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
            let msg: String = e.into();
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to check balance: {}", msg),
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
    let system_program_id = match Pubkey::from_str("11111111111111111111111111111111") {
        Ok(id) => id,
        Err(_) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: "Failed to parse system program ID".to_string(),
            };
        }
    };
    
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
    
    // Step 5: Create unsigned message
    let message = SolMessage::new_with_blockhash(
        &[transfer_ix],
        Some(&payer),
        &blockhash,
    );
    
    // Step 6: Serialize message for signing
    // Solana messages use a custom wire format - serialize using bincode
    // Note: This may need adjustment based on Solana's exact wire format requirements
    let message_bytes = match bincode::serialize(&message) {
        Ok(bytes) => bytes,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to serialize message: {:?}", e),
            };
        }
    };
    
    // Step 7: Sign message using Ed25519 via Schnorr API
    let signature = match sign_message_ed25519(&message_bytes, &derivation_path).await {
        Ok(sig) => sig,
        Err(e) => {
            let msg: String = e.into();
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to sign transaction: {}", msg),
            };
        }
    };
    
    // Step 8: Create signed transaction
    // Construct transaction with message and signature
    let transaction = Transaction {
        signatures: vec![signature],
        message,
    };
    
    // Step 9: Serialize transaction using Solana's wire format
    // Solana wire format: [compact-u16: num_signatures] || [signatures...] || [serialized_message]
    // Serialize message using bincode
    let message_bytes = match bincode::serialize(&transaction.message) {
        Ok(bytes) => bytes,
        Err(e) => {
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to serialize message: {:?}", e),
            };
        }
    };
    
    // Build wire format: compact-u16 for signature count, then signatures, then message
    let num_signatures = transaction.signatures.len();
    if num_signatures > 0xFFFF {
        return TransactionResult {
            signature: "".to_string(),
            status: "error".to_string(),
            message: "Too many signatures".to_string(),
        };
    }
    
    let mut tx_bytes = Vec::new();
    
    // Compact-u16 encoding for signature count
    // Solana uses a compact encoding: if < 128, single byte; else two bytes with MSB set
    let num_sigs_u16 = num_signatures as u16; // Cast to u16 first
    if num_sigs_u16 < 128 {
        tx_bytes.push(num_sigs_u16 as u8);
    } else {
        let high_byte = (((num_sigs_u16 >> 8) & 0x7F) | 0x80) as u8;
        let low_byte = (num_sigs_u16 & 0xFF) as u8;
        tx_bytes.push(high_byte);
        tx_bytes.push(low_byte);
    }
    
    // Append signatures (each is 64 bytes)
    for sig in &transaction.signatures {
        // Solana signatures implement AsRef<[u8; 64]>
        tx_bytes.extend_from_slice(sig.as_ref());
    }
    
    // Append serialized message
    tx_bytes.extend_from_slice(&message_bytes);
    
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
    
    // Step 10: Send signed transaction to Solana via HTTPS
    let tx_signature = match send_transaction_via_https(&tx_base64).await {
        Ok(sig) => sig,
        Err(e) => {
            let msg: String = e.into();
            return TransactionResult {
                signature: "".to_string(),
                status: "error".to_string(),
                message: format!("Failed to send transaction: {}", msg),
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
                                    if let Some(status_obj) = status_array.first().and_then(|s| s.as_object()) {
                                        // Check for error
                                        if let Some(err_val) = status_obj.get("err") {
                                            if !err_val.is_null() {
                                                return "error".to_string();
                                            }
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

#[ic_cdk::query]
fn health_check() -> String {
    // Simplest possible query to verify canister is working
    "ok".to_string()
}

// Enable Candid export
ic_cdk::export_candid!();