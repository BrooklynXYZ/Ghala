use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::ecdsa::{EcdsaCurve, EcdsaKeyId};
// Use the Bitcoin canister API (not deprecated management canister API)
use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::bitcoin::{
    BitcoinNetwork, GetBalanceRequest, GetUtxosRequest, GetUtxosResponse,
    Utxo, MillisatoshiPerByte,
};
use ic_stable_structures::{memory_manager::{MemoryManager, VirtualMemory, MemoryId}, StableBTreeMap, DefaultMemoryImpl, Storable, storable::Bound};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::borrow::Cow;
// Bitcoin transaction building temporarily disabled due to wasm32 compatibility issues
// TODO: Implement manual transaction building or use wasm-compatible bitcoin library
// use std::str::FromStr;
// use bitcoin::{Address, Network, Transaction, TxIn, TxOut, OutPoint, Txid, ScriptBuf, Sequence, Witness, Amount};
// use bitcoin::blockdata::script::Builder;
// use bitcoin::sighash::{SighashCache, EcdsaSighashType};
// use bitcoin::consensus::Encodable;

mod bitcoin_address;

const KEY_NAME: &str = "test_key_1";
// SWITCH TO MAINNET for reliable Bitcoin integration
const BTC_NETWORK: BitcoinNetwork = BitcoinNetwork::Mainnet;

// Bitcoin canister IDs (not deprecated management canister API)
const BITCOIN_TESTNET_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";
const BITCOIN_MAINNET_CANISTER_ID: &str = "ghsi2-tqaaa-aaaan-aaaca-cai";

// Helper to get the correct Bitcoin canister ID based on network
fn get_bitcoin_canister_id() -> Principal {
    let canister_id = match BTC_NETWORK {
        BitcoinNetwork::Mainnet => BITCOIN_MAINNET_CANISTER_ID,
        BitcoinNetwork::Testnet => BITCOIN_TESTNET_CANISTER_ID,
        _ => BITCOIN_TESTNET_CANISTER_ID,
    };
    Principal::from_text(canister_id).expect("Invalid Bitcoin canister ID")
}

#[derive(Clone, Debug, CandidType, Deserialize)]
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
                ic_cdk::trap(&format!("Failed to deserialize DerivationPath: {:?}. This could lead to using the wrong Bitcoin address.", e));
            }
        }
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    
    static BTC_ADDRESSES: RefCell<StableBTreeMap<Principal, String, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
        ));
    
    static DERIVATION_PATHS: RefCell<StableBTreeMap<Principal, DerivationPath, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
        ));
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct UTXOInfo {
    pub outpoint: ByteBuf,
    pub value: u64,
    pub height: u64,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct CanisterStats {
    pub network: String,
    pub key_name: String,
    pub total_addresses_generated: u64,
}

#[ic_cdk::update]
async fn generate_btc_address() -> String {
    let caller = ic_cdk::caller();
    
    if let Some(addr) = BTC_ADDRESSES.with(|map| map.borrow().get(&caller)) {
        return addr;
    }
    
    let derivation_path = DerivationPath(vec![caller.as_slice().to_vec()]);
    
    let public_key_response = match ic_cdk::api::management_canister::ecdsa::ecdsa_public_key(
        ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyArgument {
            canister_id: None,
            derivation_path: derivation_path.0.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: KEY_NAME.to_string(),
            },
        },
    )
    .await
    {
        Ok((response,)) => response,
        Err(err) => {
            ic_cdk::trap(&format!("Failed to get ECDSA public key: {:?}", err));
        }
    };
    
    ic_cdk::println!("=== ADDRESS GENERATION DEBUG ===");
    ic_cdk::println!("Public key length: {}", public_key_response.public_key.len());
    ic_cdk::println!("Public key (hex): {}", hex::encode(&public_key_response.public_key));
    ic_cdk::println!("Derivation path: {:?}", derivation_path.0);
    ic_cdk::println!("Caller Principal: {}", caller.to_text());
    
    let btc_address = bitcoin_address::public_key_to_p2pkh(
        &public_key_response.public_key,
        BTC_NETWORK == BitcoinNetwork::Mainnet,
    );
    
    ic_cdk::println!("Generated BTC address: {}", btc_address);
    ic_cdk::println!("Network: {:?}", BTC_NETWORK);
    ic_cdk::println!("Address format: {}", if BTC_NETWORK == BitcoinNetwork::Mainnet { "Mainnet (1...)" } else { "Testnet (m... or n...)" });
    ic_cdk::println!("=== END ADDRESS GENERATION ===");
    
    BTC_ADDRESSES.with(|map| {
        map.borrow_mut().insert(caller, btc_address.clone());
    });
    
    DERIVATION_PATHS.with(|map| {
        map.borrow_mut().insert(caller, derivation_path);
    });
    
    btc_address
}

#[ic_cdk::query]
fn get_my_btc_address() -> String {
    let caller = ic_cdk::caller();
    BTC_ADDRESSES.with(|map| {
        map.borrow().get(&caller).unwrap_or_default()
    })
}

#[ic_cdk::update]
fn get_btc_address_for_principal(principal: Principal) -> String {
    BTC_ADDRESSES.with(|map| {
        map.borrow().get(&principal).unwrap_or_default()
    })
}

#[ic_cdk::update]
async fn get_btc_balance(address: String) -> u64 {
    if address.is_empty() {
        ic_cdk::trap("Address cannot be empty");
    }
    
    ic_cdk::println!("=== BTC BALANCE QUERY START (using Bitcoin canister API) ===");
    ic_cdk::println!("Address: {}", address);
    ic_cdk::println!("Network: {:?}", BTC_NETWORK);
    ic_cdk::println!("Bitcoin Canister ID: {}", get_bitcoin_canister_id().to_text());
    
    const CYCLES_FOR_BTC_CALL: u64 = 10_000_000_000;
    
    // First, check UTXOs to see if transaction is visible
    ic_cdk::println!("Step 1: Checking UTXOs via Bitcoin canister...");
    let utxos_request = GetUtxosRequest {
        address: address.clone(),
        network: BTC_NETWORK,
        filter: None,
    };
    
    let bitcoin_canister = get_bitcoin_canister_id();
    
    match ic_cdk::api::call::call_with_payment::<(GetUtxosRequest,), (GetUtxosResponse,)>(
        bitcoin_canister,
        "bitcoin_get_utxos",
        (utxos_request,),
        CYCLES_FOR_BTC_CALL
    ).await {
        Ok((utxos_response,)) => {
            ic_cdk::println!("✅ UTXOs Query Success: {} UTXOs found", utxos_response.utxos.len());
            for (i, utxo) in utxos_response.utxos.iter().enumerate() {
                ic_cdk::println!("  UTXO[{}]: value={} sats, height={}", i, utxo.value, utxo.height);
            }
            ic_cdk::println!("  Tip height: {}", utxos_response.tip_height);
        }
        Err(e) => {
            ic_cdk::println!("❌ UTXOs Query Failed: {:?}", e);
        }
    }
    
    // Now try balance with 6 confirmations
    ic_cdk::println!("Step 2: Querying balance with 6 confirmations via Bitcoin canister...");
    let request = GetBalanceRequest {
        address: address.clone(),
        network: BTC_NETWORK,
        min_confirmations: Some(6),
    };
    
    match ic_cdk::api::call::call_with_payment::<(GetBalanceRequest,), (u64,)>(
        bitcoin_canister,
        "bitcoin_get_balance",
        (request,),
        CYCLES_FOR_BTC_CALL
    ).await {
        Ok((balance,)) => {
            ic_cdk::println!("✅ Balance with 6 confirmations: {} satoshis", balance);
            ic_cdk::println!("=== BTC BALANCE QUERY END ===");
            balance
        }
        Err(err) => {
            ic_cdk::println!("❌ Balance query failed: {:?}", err);
            
            // Try with 0 confirmations as fallback
            ic_cdk::println!("Step 3: Retrying with 0 confirmations...");
            let request_zero = GetBalanceRequest {
                address: address.clone(),
                network: BTC_NETWORK,
                min_confirmations: Some(0),
            };
            
            match ic_cdk::api::call::call_with_payment::<(GetBalanceRequest,), (u64,)>(
                bitcoin_canister,
                "bitcoin_get_balance",
                (request_zero,),
                CYCLES_FOR_BTC_CALL
            ).await {
                Ok((balance,)) => {
                    ic_cdk::println!("✅ Balance with 0 confirmations: {} satoshis", balance);
                    ic_cdk::println!("=== BTC BALANCE QUERY END ===");
                    balance
                }
                Err(err2) => {
                    ic_cdk::println!("❌ Balance query with 0 confirmations also failed: {:?}", err2);
                    ic_cdk::println!("=== BTC BALANCE QUERY END ===");
                    ic_cdk::trap(&format!("Bitcoin API Error: {:?}, Address: {}", err2, address));
                }
            }
        }
    }
}

#[ic_cdk::update]
async fn get_utxos(address: String) -> Vec<UTXOInfo> {
    if address.is_empty() {
        ic_cdk::trap("Address cannot be empty");
    }
    
    ic_cdk::println!("Getting UTXOs from Bitcoin canister for address: {}", address);
    
    let bitcoin_canister = get_bitcoin_canister_id();
    
    // Cycle cost for Bitcoin API calls
    // 10 billion cycles is plenty for testnet requests
    const CYCLES_FOR_BTC_CALL: u64 = 10_000_000_000;
    
    let utxos_result = ic_cdk::api::call::call_with_payment::<(GetUtxosRequest,), (GetUtxosResponse,)>(
        bitcoin_canister,
        "bitcoin_get_utxos",
        (GetUtxosRequest {
            address: address.clone(),
            network: BTC_NETWORK,
            filter: None,
        },),
        CYCLES_FOR_BTC_CALL,
    )
    .await;
    
    match utxos_result {
        Ok((response,)) => {
            ic_cdk::println!("✅ Found {} UTXOs", response.utxos.len());
            response.utxos.into_iter().map(|utxo| {
                let mut outpoint = utxo.outpoint.txid.to_vec();
                outpoint.extend_from_slice(&utxo.outpoint.vout.to_le_bytes());
                UTXOInfo {
                    outpoint: ByteBuf::from(outpoint),
                    value: utxo.value,
                    height: utxo.height as u64,
                }
            }).collect()
        }
        Err(err) => {
            ic_cdk::trap(&format!("Bitcoin Canister API Error: {:?}, Address: {}", err, address));
        }
    }
}

#[ic_cdk::update]
fn admin_clear_btc_state() {
    let caller = ic_cdk::caller();
    if !ic_cdk::api::is_controller(&caller) {
        ic_cdk::trap("Only the controller can clear BTC state");
    }

    BTC_ADDRESSES.with(|map| {
        let mut map = map.borrow_mut();
        // Collect keys first to avoid borrowing issues while removing
        let keys: Vec<_> = map.iter().map(|(k, _)| k).collect();
        for k in keys {
            map.remove(&k);
        }
    });

    DERIVATION_PATHS.with(|map| {
        let mut map = map.borrow_mut();
        // Collect keys first to avoid borrowing issues while removing
        let keys: Vec<_> = map.iter().map(|(k, _)| k).collect();
        for k in keys {
            map.remove(&k);
        }
    });
    
    ic_cdk::println!("BTC addresses and derivation paths cleared by admin.");
}

#[ic_cdk::update]
async fn sign_transaction(message_hash: ByteBuf) -> ByteBuf {
    let caller = ic_cdk::caller();
    
    let derivation_path = DERIVATION_PATHS.with(|map| {
        map.borrow().get(&caller).unwrap_or_else(|| {
            ic_cdk::trap("No BTC address found for caller")
        })
    });
    
    let signature_result = ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(
        ic_cdk::api::management_canister::ecdsa::SignWithEcdsaArgument {
            message_hash: message_hash.to_vec(),
            derivation_path: derivation_path.0.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: KEY_NAME.to_string(),
            },
        },
    )
    .await;
    
    let signature = match signature_result {
        Ok((response,)) => response.signature,
        Err(err) => {
            ic_cdk::trap(&format!("Failed to sign transaction: {:?}", err));
        }
    };
    
    ByteBuf::from(signature)
}

// fn transform_network(network: BitcoinNetwork) -> Network {
//     match network {
//         BitcoinNetwork::Mainnet => Network::Bitcoin,
//         BitcoinNetwork::Testnet => Network::Testnet,
//         BitcoinNetwork::Regtest => Network::Regtest,
//     }
// }

#[ic_cdk::update]
async fn send_btc(_to_address: String, _amount_satoshis: u64) -> String {
    // TODO: Bitcoin transaction building temporarily disabled due to wasm32 compatibility issues with bitcoin crate
    // The bitcoin crate requires native compilation (secp256k1-sys) which doesn't work with wasm32-unknown-unknown
    // Need to implement manual transaction building or use a wasm-compatible bitcoin library
    ic_cdk::trap("Bitcoin transaction sending is temporarily disabled. Manual transaction building needs to be implemented for wasm32 compatibility.")
}

#[ic_cdk::query]
fn debug_get_address_map() -> Vec<(String, String)> {
    BTC_ADDRESSES.with(|map| {
        map.borrow().iter()
            .map(|(principal, address)| (principal.to_text(), address))
            .collect()
    })
}

#[ic_cdk::query]
fn get_canister_stats() -> CanisterStats {
    let total_addresses = BTC_ADDRESSES.with(|map| {
        map.borrow().len() as u64
    });
    
    CanisterStats {
        network: match BTC_NETWORK {
            BitcoinNetwork::Mainnet => "mainnet".to_string(),
            BitcoinNetwork::Testnet => "testnet".to_string(),
            BitcoinNetwork::Regtest => "regtest".to_string(),
        },
        key_name: KEY_NAME.to_string(),
        total_addresses_generated: total_addresses,
    }
}

#[ic_cdk::init]
fn init() {}

#[ic_cdk::post_upgrade]
fn post_upgrade() {}
