import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface CanisterStats {
  'network' : string,
  'rpc_endpoint' : string,
  'total_addresses_generated' : bigint,
}
export interface SolanaBalance { 'sol' : string, 'lamports' : bigint }
export interface TransactionResult {
  'status' : string,
  'signature' : string,
  'message' : string,
}
export interface _SERVICE {
  'generate_solana_address' : ActorMethod<[], string>,
  'get_canister_stats' : ActorMethod<[], CanisterStats>,
  'get_my_solana_address' : ActorMethod<[], string>,
  'get_recent_blockhash' : ActorMethod<[], string>,
  'get_solana_balance' : ActorMethod<[string], SolanaBalance>,
  'get_solana_transaction_status' : ActorMethod<[string], string>,
  'health_check' : ActorMethod<[], string>,
  'request_airdrop' : ActorMethod<[string, bigint], TransactionResult>,
  'send_sol' : ActorMethod<[string, bigint], TransactionResult>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
