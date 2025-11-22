import { Identity } from '@dfinity/agent';
import {
  initializeAPIs,
  btcHandlerAPI,
  bridgeOrchestratorAPI,
  solanaCanisterAPI,
  satoshisToBTC,
  btcToSatoshis,
  solToLamports,
  type BridgePosition,
  type DepositResponse,
  type MintResponse,
  type SolanaBalance,
  type TransactionResult,
} from '@/utils/icpAgent';
import { validateCanisterConfig } from '@/canister-ids.config';
import logger from '@/utils/logger';

class ICPBridgeService {
  private isInitialized = false;

  async initialize(identity?: Identity, retries = 3): Promise<void> {
    if (!validateCanisterConfig()) {
      logger.warn('Invalid canister configuration. ICP features will be disabled.');
      return;
    }
    
    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        initializeAPIs(identity);
        this.isInitialized = true;
        logger.info('ICP Bridge Service initialized');
        return;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (attempt < retries) {
          logger.debug(`ICP Bridge Service initialization attempt ${attempt} failed, retrying...`, { error: lastError });
          await new Promise(resolve => setTimeout(resolve, 1000 * attempt)); // Exponential backoff
        }
      }
    }
    
    logger.warn('Failed to initialize ICP Bridge Service after all retries. ICP features will be disabled.', lastError);
    this.isInitialized = false;
  }

  isReady(): boolean {
    return this.isInitialized;
  }

  async getBTCDepositAddress(): Promise<string> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      let address = await btcHandlerAPI.getMyBTCAddress();
      if (!address) {
        address = await btcHandlerAPI.generateBTCAddress();
        logger.debug('Generated BTC address', { address });
      }
      return address;
    } catch (error) {
      logger.error('Error getting BTC address', error);
      throw error;
    }
  }

  async getBTCBalance(address: string): Promise<{ satoshis: bigint; btc: string }> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const satoshis = await btcHandlerAPI.getBTCBalance(address);
      return { satoshis, btc: satoshisToBTC(satoshis) };
    } catch (error) {
      logger.error('Error getting BTC balance', error);
      throw error;
    }
  }

  async depositBTCForMUSD(btcAmount: number): Promise<DepositResponse> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const response = await bridgeOrchestratorAPI.depositBTCForMUSD(btcToSatoshis(btcAmount));
      logger.debug('BTC deposited', { response, btcAmount });
      return response;
    } catch (error) {
      logger.error('Error depositing BTC', error);
      throw error;
    }
  }

  async mintMUSDOnMezo(btcAmount: number): Promise<MintResponse> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const response = await bridgeOrchestratorAPI.mintMUSDOnMezo(btcToSatoshis(btcAmount));
      logger.debug('mUSD mint initiated', { response, btcAmount });
      return response;
    } catch (error) {
      logger.error('Error minting mUSD', error);
      throw error;
    }
  }

  async finalizeMintTransaction(txHash: string): Promise<MintResponse> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const response = await bridgeOrchestratorAPI.finalizeMintTransaction(txHash);
      logger.debug('mUSD mint finalized', { response });
      return response;
    } catch (error) {
      logger.error('Error finalizing mUSD mint', error);
      throw error;
    }
  }

  async initiateBridgeTransfer(btcAmount: number): Promise<string> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const txHash = await bridgeOrchestratorAPI.initiateBridgeTransfer(btcToSatoshis(btcAmount));
      logger.debug('Bridge transfer initiated', { txHash, btcAmount });
      return txHash;
    } catch (error) {
      logger.error('Error initiating bridge transfer', error);
      throw error;
    }
  }

  async sendBTCToAddress(address: string, btcAmount: number): Promise<string> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const txid = await bridgeOrchestratorAPI.sendBTCToAddress(address, btcToSatoshis(btcAmount));
      logger.debug('BTC sent to address', { address, btcAmount, txid });
      return txid;
    } catch (error) {
      logger.error('Error sending BTC to address', error);
      throw error;
    }
  }

  async bridgeMUSDToSolana(musdAmount: number): Promise<string> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const signature = await bridgeOrchestratorAPI.bridgeMUSDToSolana(BigInt(Math.floor(musdAmount * 1e18)));
      logger.debug('Bridged to Solana', { signature, musdAmount });
      return signature;
    } catch (error) {
      logger.error('Error bridging to Solana', error);
      throw error;
    }
  }

  async getMyPosition(): Promise<BridgePosition> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    return bridgeOrchestratorAPI.getMyPosition();
  }

  async calculateMaxMintable(btcAmount: number): Promise<{ maxMintable: bigint; maxMintableFormatted: string }> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    const maxMintable = await bridgeOrchestratorAPI.calculateMaxMintable(btcToSatoshis(btcAmount));
    return { maxMintable, maxMintableFormatted: (Number(maxMintable) / 1e18).toFixed(2) };
  }

  async getBridgeStats(): Promise<any> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    return bridgeOrchestratorAPI.getBridgeStats();
  }

  async getSolanaAddress(): Promise<string> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      let address = await solanaCanisterAPI.getMySolanaAddress();
      if (!address) {
        address = await solanaCanisterAPI.generateSolanaAddress();
        logger.debug('Generated Solana address', { address });
      }
      return address;
    } catch (error) {
      logger.error('Error getting Solana address', error);
      throw error;
    }
  }

  async getSolanaBalance(address: string): Promise<SolanaBalance> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    return solanaCanisterAPI.getSolanaBalance(address);
  }

  async sendSOL(toAddress: string, solAmount: number): Promise<TransactionResult> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    return solanaCanisterAPI.sendSOL(toAddress, solToLamports(solAmount));
  }

  async requestSolanaAirdrop(address: string, solAmount: number): Promise<TransactionResult> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    return solanaCanisterAPI.requestAirdrop(address, solToLamports(solAmount));
  }

  async getSolanaTransactionStatus(signature: string): Promise<string> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      const status = await solanaCanisterAPI.getSolanaTransactionStatus(signature);
      return status;
    } catch (error) {
      logger.error('Error getting Solana transaction status', error);
      return 'pending';
    }
  }

  async completeBridgeFlow(btcAmount: number): Promise<{
    deposit: DepositResponse;
    mint: MintResponse;
    bridge: string;
  }> {
    if (!this.isInitialized) throw new Error('Service not initialized');
    try {
      logger.info('Starting bridge flow', { btcAmount });
      const deposit = await this.depositBTCForMUSD(btcAmount);
      const mint = await this.mintMUSDOnMezo(btcAmount);
      const bridge = await this.bridgeMUSDToSolana(Number(mint.musd_amount) / 1e18);
      logger.info('Bridge flow completed', { deposit, mint, bridge });
      return { deposit, mint, bridge };
    } catch (error) {
      logger.error('Bridge flow failed', error, { btcAmount });
      throw error;
    }
  }
}

export default new ICPBridgeService();

