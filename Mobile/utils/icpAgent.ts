import { Actor, HttpAgent, Identity } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { idlFactory as btcIdlFactory } from '../declarations/btc_handler';
import { idlFactory as bridgeIdlFactory } from '../declarations/bridge_orchestrator';
import { idlFactory as solanaIdlFactory } from '../declarations/solana_canister';
import { CANISTER_CONFIG } from '../canister-ids.config';
import logger from './logger';

const ICP_HOST = CANISTER_CONFIG.ICP_HOST;

export const CANISTER_IDS = {
  BTC_HANDLER: CANISTER_CONFIG.BTC_HANDLER,
  BRIDGE_ORCHESTRATOR: CANISTER_CONFIG.BRIDGE_ORCHESTRATOR,
  SOLANA_CANISTER: CANISTER_CONFIG.SOLANA_CANISTER,
};

export const createAgent = async (identity?: Identity, retries = 3): Promise<HttpAgent> => {
  let lastError: Error | null = null;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const agent = new HttpAgent({ host: ICP_HOST, identity });
      if (__DEV__) {
        await agent.fetchRootKey();
      }
      return agent;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt < retries) {
        logger.debug(`Agent creation attempt ${attempt} failed, retrying...`, { error: lastError });
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt)); // Exponential backoff
      }
    }
  }
  
  throw new Error(`Failed to create ICP agent after ${retries} attempts: ${lastError?.message || 'Unknown error'}`);
};

export const createActor = <T>(
  canisterId: string,
  idlFactory: any,
  identity?: Identity
): Promise<T> => {
  return createAgent(identity).then((agent) => {
    return Actor.createActor<T>(idlFactory, { agent, canisterId });
  });
};
export interface BridgePosition {
  user: Principal;
  btc_collateral: bigint;
  musd_minted: bigint;
  sol_deployed: bigint;
  status: string;
  btc_address: string;
  sol_address: string;
}

export interface DepositResponse {
  btc_address: string;
  message: string;
  status: string;
}

export interface MintResponse {
  musd_amount: bigint;
  transaction_hash: string;
  new_ltv: string;
  status: string;
}

export interface SolanaBalance {
  lamports: bigint;
  sol: string;
}

export interface TransactionResult {
  signature: string;
  status: string;
  message: string;
}

// Helper function to retry API calls with exponential backoff
async function retryApiCall<T>(
  operation: () => Promise<T>,
  operationName: string,
  maxRetries = 3
): Promise<T> {
  let lastError: Error | null = null;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt < maxRetries) {
        const delay = 1000 * attempt; // Exponential backoff
        logger.debug(`${operationName} attempt ${attempt} failed, retrying in ${delay}ms...`, { error: lastError });
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  logger.error(`${operationName} failed after ${maxRetries} attempts`, lastError);
  throw lastError || new Error(`${operationName} failed`);
}

export class BTCHandlerAPI {
  private actorPromise: Promise<any>;

  constructor(identity?: Identity) {
    this.actorPromise = createActor(CANISTER_IDS.BTC_HANDLER, btcIdlFactory, identity);
  }

  async generateBTCAddress(): Promise<string> {
    return retryApiCall(
      async () => {
        const actor = await this.actorPromise;
        return await actor.generate_btc_address();
      },
      'generateBTCAddress'
    );
  }

  async getMyBTCAddress(): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const address = await actor.get_my_btc_address();
      return address;
    } catch (error) {
      logger.error('Error getting BTC address', error);
      throw error;
    }
  }

  async getBTCBalance(address: string): Promise<bigint> {
    try {
      const actor = await this.actorPromise;
      const balance = await actor.get_btc_balance(address);
      return balance;
    } catch (error) {
      logger.error('Error getting BTC balance', error);
      throw error;
    }
  }

  async sendBTC(toAddress: string, amount: bigint): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const result = await actor.send_btc(toAddress, amount);
      return result;
    } catch (error) {
      logger.error('Error sending BTC', error);
      throw error;
    }
  }
}

export class BridgeOrchestratorAPI {
  private actorPromise: Promise<any>;

  constructor(identity?: Identity) {
    this.actorPromise = createActor(CANISTER_IDS.BRIDGE_ORCHESTRATOR, bridgeIdlFactory, identity);
  }

  async depositBTCForMUSD(btcAmount: bigint): Promise<DepositResponse> {
    try {
      const actor = await this.actorPromise;
      const response = await actor.deposit_btc_for_musd(btcAmount);
      return response;
    } catch (error) {
      logger.error('Error depositing BTC', error);
      throw error;
    }
  }

  async mintMUSDOnMezo(btcAmount: bigint): Promise<MintResponse> {
    try {
      const actor = await this.actorPromise;
      const response = await actor.mint_musd_on_mezo(btcAmount);
      return response;
    } catch (error) {
      logger.error('Error minting mUSD', error);
      throw error;
    }
  }

  async finalizeMintTransaction(txHash: string): Promise<MintResponse> {
    try {
      const actor = await this.actorPromise;
      const response = await actor.finalize_mint_transaction(txHash);
      return response;
    } catch (error) {
      logger.error('Error finalizing mint transaction', error);
      throw error;
    }
  }

  async initiateBridgeTransfer(btcAmount: bigint): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const txHash = await actor.initiate_bridge_transfer(btcAmount);
      return txHash;
    } catch (error) {
      logger.error('Error initiating bridge transfer', error);
      throw error;
    }
  }

  async sendBTCToAddress(destinationAddress: string, amount: bigint): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const txid = await actor.send_btc_to_address(destinationAddress, amount);
      return txid;
    } catch (error) {
      logger.error('Error sending BTC to address', error);
      throw error;
    }
  }

  async bridgeMUSDToSolana(musdAmount: bigint): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const result = await actor.bridge_musd_to_solana(musdAmount);
      return result;
    } catch (error) {
      logger.error('Error bridging to Solana', error);
      throw error;
    }
  }

  async getMyPosition(): Promise<BridgePosition> {
    try {
      const actor = await this.actorPromise;
      const position = await actor.get_my_position();
      return position;
    } catch (error) {
      logger.error('Error getting position', error);
      throw error;
    }
  }

  async calculateMaxMintable(btcCollateral: bigint): Promise<bigint> {
    try {
      const actor = await this.actorPromise;
      const maxMintable = await actor.calculate_max_mintable(btcCollateral);
      return maxMintable;
    } catch (error) {
      logger.error('Error calculating max mintable', error);
      throw error;
    }
  }

  async getBridgeStats(): Promise<any> {
    try {
      const actor = await this.actorPromise;
      const stats = await actor.get_bridge_stats();
      return stats;
    } catch (error) {
      logger.error('Error getting bridge stats', error);
      throw error;
    }
  }

  async deployToYieldProtocol(musdAmount: bigint, protocol: string): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const result = await actor.deploy_to_yield_protocol(musdAmount, protocol);
      return result;
    } catch (error) {
      logger.error('Error deploying to yield protocol', error);
      throw error;
    }
  }
}

export class SolanaCanisterAPI {
  private actorPromise: Promise<any>;

  constructor(identity?: Identity) {
    this.actorPromise = createActor(CANISTER_IDS.SOLANA_CANISTER, solanaIdlFactory, identity);
  }

  async generateSolanaAddress(): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const address = await actor.generate_solana_address();
      return address;
    } catch (error) {
      logger.error('Error generating Solana address', error);
      throw error;
    }
  }

  async getMySolanaAddress(): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const address = await actor.get_my_solana_address();
      return address;
    } catch (error) {
      logger.error('Error getting Solana address', error);
      throw error;
    }
  }

  async getSolanaBalance(address: string): Promise<SolanaBalance> {
    try {
      const actor = await this.actorPromise;
      const balance = await actor.get_solana_balance(address);
      return balance;
    } catch (error) {
      logger.error('Error getting Solana balance', error);
      throw error;
    }
  }

  async sendSOL(toAddress: string, lamports: bigint): Promise<TransactionResult> {
    try {
      const actor = await this.actorPromise;
      const result = await actor.send_sol(toAddress, lamports);
      return result;
    } catch (error) {
      logger.error('Error sending SOL', error);
      throw error;
    }
  }

  async requestAirdrop(address: string, lamports: bigint): Promise<TransactionResult> {
    try {
      const actor = await this.actorPromise;
      const result = await actor.request_airdrop(address, lamports);
      return result;
    } catch (error) {
      logger.error('Error requesting airdrop', error);
      throw error;
    }
  }

  async getSolanaTransactionStatus(signature: string): Promise<string> {
    try {
      const actor = await this.actorPromise;
      const status = await actor.get_solana_transaction_status(signature);
      return status;
    } catch (error) {
      logger.error('Error getting Solana transaction status', error);
      throw error;
    }
  }
}

export const satoshisToBTC = (satoshis: bigint): string => {
  return (Number(satoshis) / 100_000_000).toFixed(8);
};

export const btcToSatoshis = (btc: number): bigint => {
  return BigInt(Math.floor(btc * 100_000_000));
};

export const lamportsToSOL = (lamports: bigint): string => {
  return (Number(lamports) / 1_000_000_000).toFixed(9);
};

export const solToLamports = (sol: number): bigint => {
  return BigInt(Math.floor(sol * 1_000_000_000));
};

export const formatPrincipal = (principal: Principal): string => {
  const text = principal.toText();
  if (text.length <= 12) return text;
  return `${text.slice(0, 6)}...${text.slice(-4)}`;
};

export const areCanistersConfigured = (): boolean => {
  return (
    CANISTER_IDS.BTC_HANDLER !== '' &&
    CANISTER_IDS.BRIDGE_ORCHESTRATOR !== '' &&
    CANISTER_IDS.SOLANA_CANISTER !== ''
  );
};

export let btcHandlerAPI: BTCHandlerAPI;
export let bridgeOrchestratorAPI: BridgeOrchestratorAPI;
export let solanaCanisterAPI: SolanaCanisterAPI;

export const initializeAPIs = (identity?: Identity) => {
  btcHandlerAPI = new BTCHandlerAPI(identity);
  bridgeOrchestratorAPI = new BridgeOrchestratorAPI(identity);
  solanaCanisterAPI = new SolanaCanisterAPI(identity);
};

