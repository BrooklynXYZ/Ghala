export const idlFactory = ({ IDL }) => {
  const CanisterStats = IDL.Record({
    'network' : IDL.Text,
    'rpc_endpoint' : IDL.Text,
    'total_addresses_generated' : IDL.Nat64,
  });
  const SolanaBalance = IDL.Record({
    'sol' : IDL.Text,
    'lamports' : IDL.Nat64,
  });
  const TransactionResult = IDL.Record({
    'status' : IDL.Text,
    'signature' : IDL.Text,
    'message' : IDL.Text,
  });
  return IDL.Service({
    'generate_solana_address' : IDL.Func([], [IDL.Text], []),
    'get_canister_stats' : IDL.Func([], [CanisterStats], ['query']),
    'get_my_solana_address' : IDL.Func([], [IDL.Text], ['query']),
    'get_recent_blockhash' : IDL.Func([], [IDL.Text], []),
    'get_solana_balance' : IDL.Func([IDL.Text], [SolanaBalance], []),
    'get_solana_transaction_status' : IDL.Func([IDL.Text], [IDL.Text], []),
    'health_check' : IDL.Func([], [IDL.Text], ['query']),
    'request_airdrop' : IDL.Func(
        [IDL.Text, IDL.Nat64],
        [TransactionResult],
        [],
      ),
    'send_sol' : IDL.Func([IDL.Text, IDL.Nat64], [TransactionResult], []),
  });
};
export const init = ({ IDL }) => { return []; };
