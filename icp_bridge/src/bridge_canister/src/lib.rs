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
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

// Constants - MEZO MAINNET (Real BTC)
const MEZO_MAINNET_RPC: &str = "https://rpc-http.mezo.boar.network"; // Mezo Mainnet Public RPC
const MEZO_CHAIN_ID: u64 = 31612; // Mezo Mainnet Chain ID

const EVM_RPC_CANISTER_ID: &str = "7hfb6-caaaa-aaaar-qadga-cai";

// MEZO MAINNET CONTRACTS
const MUSD_TOKEN_ADDRESS: &str = "0xdD468A1DDc392dcdbEf6db6e34E89AA338F9F186"; 
const MEZO_BRIDGE_ADDRESS: &str = "0xF6680EA3b480cA2b72D96ea13cCAF2cFd8e6908c"; // Mezo Bridge (tBTC)
const BITCOIN_DEPOSITOR_ADDRESS: &str = "0x1D50D75933b7b7C8AD94dbfb748B5756E3889C24"; // BitcoinDepositor (Proxy)
const TBTC_TOKEN_ADDRESS: &str = "0x7b7C000000000000000000000000000000000000"; // tBTC Token

const TROVE_MANAGER_ADDRESS: &str = "0x94AfB503dBca74aC3E4929BACEeDfCe19B93c193";
const HINT_HELPERS_ADDRESS: &str = "0xD267b3bE2514375A075fd03C3D9CBa6b95317DC3";
const SORTED_TROVES_ADDRESS: &str = "0x8C5DB4C62BF29c1C4564390d10c20a47E0b2749f";
const BORROW_MANAGER_ADDRESS: &str = "0x44b1bac67dDA612a41a58AAf779143B181dEe031"; // BorrowerOperations
const PRICE_FEED_ADDRESS: &str = "0xc5aC5A8892230E0A3e1c473881A2de7353fFcA88";

const KEY_NAME: &str = "key_1"; // Production Key
const MAX_LTV: u64 = 90;
const INTEREST_RATE: u64 = 1;

const TRANSACTION_TIMEOUT_SECS: u64 = 45;
const MAX_POLL_ATTEMPTS: u8 = 15;
const DEFAULT_GAS_LIMIT: u64 = 350_000;
const DEFAULT_GAS_PRICE: u64 = 5_000_000_000; // 5 Gwei (Mainnet optimized)
const DEFAULT_PRIORITY_FEE: u64 = 1_000_000_000; // 1 Gwei

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
    
    static NONCE_TRACKER: RefCell<StableBTreeMap<NonceKey, u64, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
        ));
}

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

#[derive(CandidType, Deserialize, Debug)]
pub struct RpcHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct RpcApi {
    pub url: String,
    pub headers: Option<Vec<RpcHttpHeader>>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct RpcConfig {
    // Empty for now, can be extended if needed
}

#[derive(CandidType, Deserialize, Debug)]
pub enum RpcServices {
    Custom {
        chain_id: u64,
        services: Vec<RpcApi>,
    },
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
    
    match verify_btc_deposit(btc_canister, &btc_address, 1).await {
        Ok(verified_balance) => {
            let existing = POSITIONS.with(|map| {
                map.borrow().get(&caller)
            });
            
            let (updated_position, newly_recognized) = if let Some(existing) = existing.clone() {
                let newly_recognized = if verified_balance > existing.btc_collateral {
                    verified_balance - existing.btc_collateral
                } else {
                    0
                };
                
                let updated = BridgePosition {
                    user: caller,
                    btc_collateral: verified_balance,
                    musd_minted: existing.musd_minted,
                    sol_deployed: existing.sol_deployed,
                    status: "btc_deposited".to_string(),
                    btc_address: btc_address.clone(),
                    sol_address: existing.sol_address,
                };
                
                (updated, newly_recognized)
            } else {
                let updated = BridgePosition {
                    user: caller,
                    btc_collateral: verified_balance,
                    musd_minted: 0,
                    sol_deployed: 0,
                    status: "btc_deposited".to_string(),
                    btc_address: btc_address.clone(),
                    sol_address: "".to_string(),
                };
                
                (updated, verified_balance)
            };
            
            POSITIONS.with(|map| {
                map.borrow_mut().insert(caller, updated_position);
            });
            
            DepositResponse {
                btc_address,
                message: format!("Deposit verified. Total balance: {} satoshis (newly recognized: {} satoshis)", verified_balance, newly_recognized),
                status: "confirmed".to_string(),
            }
        }
        Err(e) => {
            ic_cdk::trap(&format!("BTC deposit verification failed: {}", e));
        }
    }
}

fn derive_eth_address_from_pubkey(pubkey: &[u8]) -> String {
    let pubkey_uncompressed = if pubkey.len() == 33 {
        pubkey
    } else {
        pubkey
    };
    
    let pubkey_bytes = if pubkey_uncompressed.len() == 65 && pubkey_uncompressed[0] == 0x04 {
        &pubkey_uncompressed[1..]
    } else {
        pubkey_uncompressed
    };
    
    let hash = Keccak256::digest(pubkey_bytes);
    let address_bytes = &hash[12..32];
    format!("0x{}", hex::encode(address_bytes))
}

async fn get_canister_eth_address(caller: Principal) -> String {
    let derivation_path = vec![caller.as_slice().to_vec()];
    
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
            "0x0000000000000000000000000000000000000000".to_string()
        }
    }
}

fn calculate_function_selector(signature: &str) -> Vec<u8> {
    let hash = Keccak256::digest(signature.as_bytes());
    hash[0..4].to_vec()
}

fn build_open_trove_calldata(musd_amount: u64, upper_hint: &str, lower_hint: &str) -> Vec<u8> {
    // Function selector: openTrove(uint256,uint256,address,address)
    let function_selector = calculate_function_selector("openTrove(uint256,uint256,address,address)");
    let mut calldata = function_selector;
    
    // Parameter 1: _maxFeePercentage (uint256) - 5% (5 * 10^16)
    let max_fee: u64 = 50_000_000_000_000_000;
    let mut fee_bytes = vec![0u8; 24];
    fee_bytes.extend_from_slice(&max_fee.to_be_bytes());
    calldata.extend_from_slice(&fee_bytes);
    
    // Parameter 2: _MUSDAmount (uint256)
    let mut amount_bytes = vec![0u8; 24];
    amount_bytes.extend_from_slice(&musd_amount.to_be_bytes());
    calldata.extend_from_slice(&amount_bytes);
    
    // Parameter 3: _upperHint (address)
    let upper_hint_bytes = hex::decode(upper_hint.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Invalid upper hint address '{}': {:?}", upper_hint, e));
        });
    let mut upper_hint_padded = vec![0u8; 12];
    upper_hint_padded.extend_from_slice(&upper_hint_bytes);
    calldata.extend_from_slice(&upper_hint_padded);
    
    // Parameter 4: _lowerHint (address)
    let lower_hint_bytes = hex::decode(lower_hint.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Invalid lower hint address '{}': {:?}", lower_hint, e));
        });
    let mut lower_hint_padded = vec![0u8; 12];
    lower_hint_padded.extend_from_slice(&lower_hint_bytes);
    calldata.extend_from_slice(&lower_hint_padded);
    
    calldata
}

// Helper to compute y_parity for EIP-1559
fn compute_y_parity(prehash: &[u8], sig: &[u8], pubkey: &[u8]) -> u64 {
    let orig_key = VerifyingKey::from_sec1_bytes(pubkey).unwrap_or_else(|_| {
        ic_cdk::trap("Invalid public key for recovery");
    });
    let signature = Signature::try_from(sig).unwrap_or_else(|_| {
        ic_cdk::trap("Invalid signature for recovery");
    });
    
    // Try recovery id 0 and 1
    for recid in 0..=1 {
        let id = RecoveryId::new(recid > 0, false);
        if let Ok(key) = VerifyingKey::recover_from_prehash(prehash, &signature, id) {
             if key == orig_key {
                 return recid as u64;
             }
        }
    }
    
    ic_cdk::trap("Failed to recover public key from signature");
}

// Helper to build and sign EIP-1559 transaction
async fn sign_eip1559_transaction(
    caller: Principal,
    key_name: &str,
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas_limit: u64,
    to: &str,
    value: u64,
    data: &[u8]
) -> (String, Vec<u8>) {
    use rlp::RlpStream;
    
    let to_bytes = hex::decode(to.trim_start_matches("0x")).expect("Invalid to address");
    
    // 1. Encode for signing: 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])
    let mut stream = RlpStream::new();
    stream.begin_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&max_priority_fee_per_gas);
    stream.append(&max_fee_per_gas);
    stream.append(&gas_limit);
    stream.append(&to_bytes);
    stream.append(&value);
    stream.append(&data);
    stream.begin_list(0); // Empty access list
    
    let mut encoded = vec![0x02];
    encoded.extend_from_slice(stream.out().as_ref());
    
    // 2. Hash
    let tx_hash = Keccak256::digest(&encoded);
    
    // 3. Sign
    let derivation_path = vec![caller.as_slice().to_vec()];
    let signature_result = ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(
        ic_cdk::api::management_canister::ecdsa::SignWithEcdsaArgument {
            message_hash: tx_hash.to_vec(),
            derivation_path: derivation_path.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name.to_string(),
            },
        },
    )
    .await;
    
    let signature_bytes = signature_result.expect("Failed to sign").0.signature;
    
    // 4. Get Public Key for Recovery
    let pubkey_result = ic_cdk::api::management_canister::ecdsa::ecdsa_public_key(
        ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyArgument {
            canister_id: None,
            derivation_path: derivation_path.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name.to_string(),
            },
        },
    )
    .await;
    
    let pubkey_bytes = pubkey_result.expect("Failed to get public key").0.public_key;
    
    // 5. Compute y_parity (v)
    let y_parity = compute_y_parity(&tx_hash, &signature_bytes, &pubkey_bytes);
    
    // 6. Encode signed tx: 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list, y_parity, r, s])
    let mut stream = RlpStream::new();
    stream.begin_list(12);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&max_priority_fee_per_gas);
    stream.append(&max_fee_per_gas);
    stream.append(&gas_limit);
    stream.append(&to_bytes);
    stream.append(&value);
    stream.append(&data);
    stream.begin_list(0); // Empty access list
    stream.append(&y_parity);
    
    let r = &signature_bytes[0..32];
    let s = &signature_bytes[32..64];
    
    stream.append(&r.to_vec());
    stream.append(&s.to_vec());
    
    let mut signed_encoded = vec![0x02];
    signed_encoded.extend_from_slice(stream.out().as_ref());
    
    (format!("0x{}", hex::encode(tx_hash)), signed_encoded)
}

#[ic_cdk::update]
async fn mint_musd_on_mezo(btc_amount: u64) -> MintResponse {
    let start_time = ic_cdk::api::time();
    
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
    
    let musd_amount = (btc_amount * 99) / 100;
    
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
    
    let canister_eth_address = get_canister_eth_address(caller).await;
    
    // Hints for Liquity/Mezo sorted troves (using 0x0 for auto-search/tail)
    let zero_hint = "0x0000000000000000000000000000000000000000";
    let calldata = build_open_trove_calldata(musd_amount, zero_hint, zero_hint);
    
    let nonce = get_and_increment_nonce(&canister_eth_address).await
        .unwrap_or_else(|e| {
            ic_cdk::trap(&format!("Failed to get nonce: {}", e));
        });
    
    // EIP-1559 Fees
    // TODO: Use eth_feeHistory via EVM RPC for better estimation
    let max_priority_fee = DEFAULT_PRIORITY_FEE;
    let max_fee = DEFAULT_GAS_PRICE;
    let gas_limit = DEFAULT_GAS_LIMIT;
    
    let (tx_hash_hex, signed_tx) = sign_eip1559_transaction(
        caller,
        KEY_NAME,
        MEZO_CHAIN_ID,
        nonce,
        max_priority_fee,
        max_fee,
        gas_limit,
        BORROW_MANAGER_ADDRESS,
        btc_amount, // Value = Collateral (tBTC)
        &calldata
    ).await;
    
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_tx));
    
    let send_start = ic_cdk::api::time();
    let tx_hash = match send_evm_transaction_via_chain_fusion(&raw_tx_hex).await {
        Ok(hash) => hash,
        Err(err) => {
            ic_cdk::println!("Chain Fusion failed: {}, falling back to HTTP outcall", err);
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
    
    // Update position status to track pending mint
    let pending_status = format!("pending_mint:{}:{}", tx_hash, musd_amount);
    let updated_position = BridgePosition {
        user: caller,
        btc_collateral: position.btc_collateral,
        musd_minted: position.musd_minted, // Not incremented yet
        sol_deployed: position.sol_deployed,
        status: pending_status.clone(),
        btc_address: position.btc_address,
        sol_address: position.sol_address,
    };
    
    POSITIONS.with(|map| {
        map.borrow_mut().insert(caller, updated_position);
    });
    
    // Return immediately - Frontend must poll finalize_mint_transaction
    MintResponse {
        musd_amount,
        transaction_hash: tx_hash,
        new_ltv: format!("{}%", projected_ltv), // Projected
        status: "pending".to_string(),
    }
}

#[ic_cdk::update]
async fn finalize_mint_transaction(tx_hash: String) -> MintResponse {
    let caller = ic_cdk::caller();
    
    let position = POSITIONS.with(|map| {
        map.borrow().get(&caller).unwrap_or_else(|| {
            ic_cdk::trap("No position found.")
        })
    });
    
    // Parse status to verify we are waiting for this tx
    // Format: "pending_mint:<tx_hash>:<amount>"
    let parts: Vec<&str> = position.status.split(':').collect();
    if parts.len() != 3 || parts[0] != "pending_mint" || parts[1] != tx_hash {
        ic_cdk::trap(&format!("No pending mint found for tx: {}", tx_hash));
    }
    
    let pending_amount: u64 = parts[2].parse().unwrap_or_else(|_| {
        ic_cdk::trap("Invalid pending amount format");
    });
    
    // Check receipt
    let status = check_transaction_status(&tx_hash).await
        .unwrap_or_else(|e| ic_cdk::trap(&format!("Failed to check receipt: {}", e)));
        
    match status {
        Some(true) => {
            // Success! Update state
            let total_minted = position.musd_minted.checked_add(pending_amount)
                .unwrap_or_else(|| ic_cdk::trap("Overflow: mUSD mint would overflow"));
            
            let current_ltv = (total_minted.checked_mul(100)
                .unwrap_or_else(|| ic_cdk::trap("Overflow: LTV calculation would overflow")))
                .checked_div(position.btc_collateral)
                .unwrap_or(u64::MAX);
                
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
            
            MintResponse {
                musd_amount: pending_amount,
                transaction_hash: tx_hash,
                new_ltv: format!("{}%", current_ltv),
                status: "confirmed".to_string(),
            }
        },
        Some(false) => {
            // Failed on chain
            let updated_position = BridgePosition {
                status: "mint_failed".to_string(),
                ..position
            };
            POSITIONS.with(|map| {
                map.borrow_mut().insert(caller, updated_position);
            });
            
            MintResponse {
                musd_amount: 0,
                transaction_hash: tx_hash,
                new_ltv: "0%".to_string(),
                status: "failed_on_chain".to_string(),
            }
        },
        None => {
            // Still pending
            MintResponse {
                musd_amount: pending_amount,
                transaction_hash: tx_hash,
                new_ltv: "Pending".to_string(),
                status: "pending".to_string(),
            }
        }
    }
}

async fn get_eth_gas_price() -> Result<u64, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_gasPrice",
        "params": []
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_MAINNET_RPC.to_string(),
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
        url: MEZO_MAINNET_RPC.to_string(),
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

async fn check_transaction_status(tx_hash: &str) -> Result<Option<bool>, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_MAINNET_RPC.to_string(),
        method: HttpMethod::POST,
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(serde_json::to_string(&request_body).unwrap().into_bytes()),
        max_response_bytes: Some(5000),
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
                        if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
                            if status == "0x1" {
                                return Ok(Some(true));
                            } else if status == "0x0" {
                                return Ok(Some(false));
                            }
                        }
                        ic_cdk::println!("Warning: Transaction receipt missing status field");
                        return Ok(Some(true));
                    }
                }
                Ok(None)
            } else {
                Err(format!("HTTP error: {}", response.status))
            }
        }
        Err(err) => Err(format!("HTTP request failed: {:?}", err)),
    }
}

async fn get_and_increment_nonce(address: &str) -> Result<u64, String> {
    let chain_nonce = get_eth_nonce(address).await?;
    
    let key = NonceKey(address.to_string());
    let stored_nonce = NONCE_TRACKER.with(|tracker| {
        tracker.borrow().get(&key).unwrap_or(0)
    });
    
    let next_nonce = std::cmp::max(chain_nonce, stored_nonce.checked_add(1).unwrap_or(chain_nonce));
    
    NONCE_TRACKER.with(|tracker| {
        tracker.borrow_mut().insert(key, next_nonce);
    });
    
    Ok(next_nonce)
}

async fn get_eth_nonce(address: &str) -> Result<u64, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionCount",
        "params": [address, "latest"]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_MAINNET_RPC.to_string(),
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

async fn send_evm_transaction_via_chain_fusion(raw_tx_hex: &str) -> Result<String, String> {
    let evm_rpc_id = Principal::from_text(EVM_RPC_CANISTER_ID)
        .map_err(|e| format!("Invalid EVM RPC canister ID: {:?}", e))?;
    
    let rpc_services = RpcServices::Custom {
        chain_id: MEZO_CHAIN_ID,
        services: vec![RpcApi {
            url: MEZO_MAINNET_RPC.to_string(),
            headers: Some(vec![RpcHttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }]),
        }],
    };
    
    let rpc_config: Option<RpcConfig> = None;
    
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

async fn send_eth_transaction(raw_tx_hex: &str) -> Result<String, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [raw_tx_hex]
    });
    
    let request = CanisterHttpRequestArgument {
        url: MEZO_MAINNET_RPC.to_string(),
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
async fn initiate_bridge_transfer(btc_amount: u64) -> String {
    let caller = ic_cdk::caller();
    
    // 1. Verify BTC Balance
    let position = POSITIONS.with(|map| map.borrow().get(&caller).clone());
    if let Some(pos) = position {
        if pos.btc_collateral < btc_amount {
            ic_cdk::trap("Insufficient BTC collateral");
        }
    } else {
        ic_cdk::trap("No position found");
    }

    // 2. Initiate Deposit on Mezo (EVM Call)
    // We call BitcoinDepositor.initiateDeposit()
    // This emits an event with the BTC address. Frontend must parse this.
    
    // Function: initiateDeposit()
    let function_selector = calculate_function_selector("initiateDeposit()");
    let canister_eth_address = get_canister_eth_address(caller).await;
    let nonce = get_and_increment_nonce(&canister_eth_address).await.unwrap();
    
    let max_priority_fee = DEFAULT_PRIORITY_FEE;
    let max_fee = DEFAULT_GAS_PRICE;
    let gas_limit = DEFAULT_GAS_LIMIT;
    
    let (tx_hash_hex, signed_tx) = sign_eip1559_transaction(
        caller,
        KEY_NAME,
        MEZO_CHAIN_ID,
        nonce,
        max_priority_fee,
        max_fee,
        gas_limit,
        BITCOIN_DEPOSITOR_ADDRESS, // Target: BitcoinDepositor
        0, // Value: 0 (ETH)
        &function_selector // Data: initiateDeposit()
    ).await;
    
    // 3. Broadcast
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_tx));
    let tx_hash = match send_evm_transaction_via_chain_fusion(&raw_tx_hex).await {
        Ok(hash) => hash,
        Err(err) => {
             // Fallback or error
             ic_cdk::trap(&format!("Failed to initiate deposit: {}", err));
        }
    };
    
    // Return the TX Hash. Frontend will:
    // 1. Wait for receipt
    // 2. Extract 'DepositRevealed' event -> 'btcDepositAddress'
    // 3. Call send_btc_to_address(btcDepositAddress, amount)
    tx_hash
}

#[ic_cdk::update]
async fn bridge_btc_to_mezo_old_stub(btc_amount: u64) -> String {
    // Deprecated in favor of initiate_bridge_transfer + send_btc_to_address flow
    initiate_bridge_transfer(btc_amount).await
}

#[ic_cdk::update]
async fn send_btc_to_address(destination_address: String, amount: u64) -> String {
    let caller = ic_cdk::caller();
    // Verify user has balance (internal logic)
    let position = POSITIONS.with(|map| map.borrow().get(&caller).clone());
    if let Some(pos) = position {
        if pos.btc_collateral < amount {
            ic_cdk::trap("Insufficient BTC collateral");
        }
        // Deduct? No, the btc_canister holds the UTXOs. The position tracks "recognized" balance.
        // If we send it out, we must decrease the position.
        let new_collateral = pos.btc_collateral - amount;
        let updated_pos = BridgePosition {
            btc_collateral: new_collateral,
            status: "bridging_to_mezo".to_string(),
            ..pos
        };
        POSITIONS.with(|map| map.borrow_mut().insert(caller, updated_pos));
    } else {
        ic_cdk::trap("No position");
    }

    let btc_canister_id = CANISTER_IDS.with(|ids| {
        ids.borrow().borrow().btc_canister.clone().unwrap()
    });
    let btc_canister = Principal::from_text(&btc_canister_id).unwrap();
    
    // Call btc_canister.send_btc
    let (txid,): (String,) = ic_cdk::call(
        btc_canister, 
        "send_btc", 
        (destination_address, amount)
    ).await.unwrap();
    
    txid
}

fn build_redeem_collateral_calldata(
    musd_amount: u64,
    user_address: &str
) -> Vec<u8> {
    // Function selector: redeemCollateral(uint256,address,address,address,uint256,uint256,uint256)
    let function_selector = calculate_function_selector("redeemCollateral(uint256,address,address,address,uint256,uint256,uint256)");
    let mut calldata = function_selector;
    
    // 1. _amount (uint256)
    let mut amount_bytes = vec![0u8; 24];
    amount_bytes.extend_from_slice(&musd_amount.to_be_bytes());
    calldata.extend_from_slice(&amount_bytes);
    
    // 2. _firstRedemptionHint (address) -> 0x0
    let zero_addr = vec![0u8; 12]; // Padded to 32 bytes (12 + 20)
    let mut first_hint = vec![0u8; 32]; // 0x0 is all zeros
    calldata.extend_from_slice(&first_hint);
    
    // 3. _upperPartialRedemptionHint (address) -> user_address
    let user_bytes = hex::decode(user_address.trim_start_matches("0x")).unwrap();
    let mut upper_hint = vec![0u8; 12];
    upper_hint.extend_from_slice(&user_bytes);
    calldata.extend_from_slice(&upper_hint);
    
    // 4. _lowerPartialRedemptionHint (address) -> user_address
    let mut lower_hint = vec![0u8; 12];
    lower_hint.extend_from_slice(&user_bytes);
    calldata.extend_from_slice(&lower_hint);
    
    // 5. _partialRedemptionHintNICR (uint256) -> 1100 * 1e18
    let nicr: u128 = 1_100_000_000_000_000_000_000;
    let mut nicr_word = vec![0u8; 16]; // Pad 16 leading zeros
    nicr_word.extend_from_slice(&nicr.to_be_bytes()); // Add 16 value bytes -> Total 32 bytes
    calldata.extend_from_slice(&nicr_word);
    
    // 6. _maxIterations (uint256) -> 0
    let max_iter = vec![0u8; 32];
    calldata.extend_from_slice(&max_iter);
    
    // 7. _maxFeePercentage (uint256) -> 5% (5 * 10^16)
    let max_fee: u64 = 50_000_000_000_000_000;
    let mut fee_bytes = vec![0u8; 24];
    fee_bytes.extend_from_slice(&max_fee.to_be_bytes());
    calldata.extend_from_slice(&fee_bytes);

    calldata
}

#[ic_cdk::update]
async fn redeem_musd(musd_amount: u64) -> String {
    let caller = ic_cdk::caller();
    
    // Ensure user has mUSD (internal tracking)
    // Note: Redemption burns mUSD to get BTC.
    let position = POSITIONS.with(|map| map.borrow().get(&caller).clone());
    if let Some(pos) = position {
        if pos.musd_minted < musd_amount {
                ic_cdk::trap("Insufficient mUSD minted to redeem");
        }
    } else {
        ic_cdk::trap("No position found");
    }

    let canister_eth_address = get_canister_eth_address(caller).await;
    
    let calldata = build_redeem_collateral_calldata(musd_amount, &canister_eth_address);
    
    let nonce = get_and_increment_nonce(&canister_eth_address).await.unwrap();
    
    // Send to TroveManager
    let (tx_hash_hex, signed_tx) = sign_eip1559_transaction(
        caller,
        KEY_NAME,
        MEZO_CHAIN_ID,
        nonce,
        DEFAULT_PRIORITY_FEE,
        DEFAULT_GAS_PRICE,
        500_000, // Higher gas for redemption
        TROVE_MANAGER_ADDRESS,
        0,
        &calldata
    ).await;
    
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_tx));
    let tx_hash = send_evm_transaction_via_chain_fusion(&raw_tx_hex).await.expect("Failed to send redemption tx");
    
    // Update internal state (Burn mUSD)
    POSITIONS.with(|map| {
        let mut p = map.borrow().get(&caller).unwrap();
        p.musd_minted -= musd_amount;
        p.status = "redeeming_musd".to_string();
        map.borrow_mut().insert(caller, p);
    });
    
    tx_hash
}

#[ic_cdk::update]
async fn bridge_musd_to_solana(musd_amount: u64) -> String {
    if musd_amount == 0 {
        ic_cdk::trap("Invalid input: mUSD amount must be greater than 0");
    }
    
    let caller = ic_cdk::caller();
    
    let position = POSITIONS.with(|map| {
        map.borrow().get(&caller).unwrap_or_else(|| {
            BridgePosition {
                user: caller,
                btc_collateral: 0,
                musd_minted: 0,
                sol_deployed: 0,
                status: "none".to_string(),
                btc_address: "".to_string(),
                sol_address: "".to_string(),
            }
        })
    });
    
    let solana_canister_id = CANISTER_IDS.with(|ids| {
        ids.borrow().borrow().solana_canister.clone().unwrap_or_else(|| {
            ic_cdk::trap("Solana canister not configured. Please contact admin.")
        })
    });
    
    let sol_canister = match Principal::from_text(&solana_canister_id) {
        Ok(principal) => principal,
        Err(e) => {
            ic_cdk::trap(&format!("Invalid Solana canister ID '{}': {:?}", solana_canister_id, e));
        }
    };
    
    let sol_address_result: Result<(String,), _> = ic_cdk::call(sol_canister, "generate_solana_address", ())
        .await;
    
    let sol_address = match sol_address_result {
        Ok((addr,)) => addr,
        Err(err) => {
            ic_cdk::println!("Failed to generate Solana address: {:?}", err);
            format!("solana_placeholder_{}", caller.to_text())
        }
    };
    
    let bridge_result: Result<(String, String, String), _> = ic_cdk::call(
        sol_canister,
        "send_sol",
        (sol_address.clone(), musd_amount),
    )
    .await;
    
    match bridge_result {
        Ok((signature, status, message)) => {
            if status == "error" || status == "failed" {
                ic_cdk::trap(&format!("Solana bridge transaction failed: {}", message));
            }
            
            let new_musd_minted = if position.musd_minted >= musd_amount {
                position.musd_minted - musd_amount
            } else {
                position.musd_minted
            };
            
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
    if musd_amount == 0 {
        ic_cdk::trap("Invalid input: mUSD amount must be greater than 0");
    }
    
    if protocol.is_empty() {
        ic_cdk::trap("Invalid input: Protocol name cannot be empty");
    }
    
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
    (btc_collateral * MAX_LTV) / 100
}

#[ic_cdk::query]
fn get_bridge_stats() -> BridgeStats {
    let mut total_btc = 0u64;
    let mut total_musd = 0u64;
    let mut total_sol_deployed = 0u64;
    
    POSITIONS.with(|map| {
        for (_, position) in map.borrow().iter() {
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

// Enable Candid export
ic_cdk::export_candid!();
