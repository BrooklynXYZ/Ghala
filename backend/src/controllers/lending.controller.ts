import { Request, Response } from 'express';
import { mezoService } from '@/services/mezo.service';
import { walletService } from '@/services/wallet.service';
import {
  DepositRequest,
  MintRequest,
  LoanPosition,
  RiskAssessment,
  MaxMintableResponse,
  ApiResponse,
  InsufficientCollateralError,
  LTVExceededError,
  TransactionFailedError,
  WalletNotConnectedError
} from '@/types';

export class LendingController {
  
  async depositCollateral(req: Request, res: Response): Promise<void> {
    try {
      const { btcAmount, walletAddress }: DepositRequest = req.body;
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'Please provide a valid Bearer token',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const userData = await walletService.verifyJWTToken(token);

      if (!btcAmount || !walletAddress) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields',
          message: 'btcAmount and walletAddress are required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      if (userData.address.toLowerCase() !== walletAddress.toLowerCase()) {
        res.status(403).json({
          success: false,
          error: 'Address mismatch',
          message: 'Wallet address does not match authenticated user',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const amount = parseFloat(btcAmount);
      if (isNaN(amount) || amount <= 0) {
        res.status(400).json({
          success: false,
          error: 'Invalid amount',
          message: 'btcAmount must be a positive number',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const result = await mezoService.depositCollateral({
        btcAmount,
        walletAddress
      });

      res.status(200).json({
        success: true,
        data: result,
        message: 'BTC collateral deposited successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Deposit collateral error:', error);
      
      if (error instanceof InsufficientCollateralError) {
        res.status(400).json({
          success: false,
          error: 'Insufficient collateral',
          message: error.message,
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      if (error instanceof TransactionFailedError) {
        res.status(500).json({
          success: false,
          error: 'Transaction failed',
          message: error.message,
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to deposit collateral',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async mintMUSD(req: Request, res: Response): Promise<void> {
    try {
      const { musdAmount, walletAddress }: MintRequest = req.body;
      const authHeader = req.headers.authorization;
      
      // Validate authentication
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'Please provide a valid Bearer token',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const userData = await walletService.verifyJWTToken(token);

      // Validate input
      if (!musdAmount || !walletAddress) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields',
          message: 'musdAmount and walletAddress are required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Validate wallet address matches authenticated user
      if (userData.address.toLowerCase() !== walletAddress.toLowerCase()) {
        res.status(403).json({
          success: false,
          error: 'Address mismatch',
          message: 'Wallet address does not match authenticated user',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Validate amount
      const amount = parseFloat(musdAmount);
      if (isNaN(amount) || amount <= 0) {
        res.status(400).json({
          success: false,
          error: 'Invalid amount',
          message: 'musdAmount must be a positive number',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Execute mint
      const result = await mezoService.mintMUSD({
        musdAmount,
        walletAddress
      });

      res.status(200).json({
        success: true,
        data: result,
        message: 'mUSD minted successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Mint mUSD error:', error);
      
      if (error instanceof LTVExceededError) {
        res.status(400).json({
          success: false,
          error: 'LTV exceeded',
          message: error.message,
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      if (error instanceof TransactionFailedError) {
        res.status(500).json({
          success: false,
          error: 'Transaction failed',
          message: error.message,
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to mint mUSD',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async getLoanPosition(req: Request, res: Response): Promise<void> {
    try {
      const { address } = req.params;
      const authHeader = req.headers.authorization;
      
      // Validate authentication
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'Please provide a valid Bearer token',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const userData = await walletService.verifyJWTToken(token);

      // Validate wallet address matches authenticated user
      if (userData.address.toLowerCase() !== address.toLowerCase()) {
        res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'Cannot access positions for other users',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Get position
      const position = await mezoService.getLoanPosition(address);

      res.status(200).json({
        success: true,
        data: position,
        message: 'Loan position retrieved successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Get loan position error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve loan position',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async calculateMaxMintable(req: Request, res: Response): Promise<void> {
    try {
      const { btcAmount } = req.query;
      
      if (!btcAmount || typeof btcAmount !== 'string') {
        res.status(400).json({
          success: false,
          error: 'Missing btcAmount',
          message: 'btcAmount query parameter is required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Validate amount
      const amount = parseFloat(btcAmount);
      if (isNaN(amount) || amount <= 0) {
        res.status(400).json({
          success: false,
          error: 'Invalid amount',
          message: 'btcAmount must be a positive number',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Calculate max mintable
      const result = await mezoService.getMaxMintable(btcAmount);

      res.status(200).json({
        success: true,
        data: result,
        message: 'Maximum mintable amount calculated successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Calculate max mintable error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to calculate maximum mintable amount',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async getRiskAssessment(req: Request, res: Response): Promise<void> {
    try {
      const { address } = req.params;
      const authHeader = req.headers.authorization;
      
      // Validate authentication
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'Please provide a valid Bearer token',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const userData = await walletService.verifyJWTToken(token);

      // Validate wallet address matches authenticated user
      if (userData.address.toLowerCase() !== address.toLowerCase()) {
        res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'Cannot access risk assessment for other users',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Get position and calculate risk
      const position = await mezoService.getLoanPosition(address);
      const ltv = parseFloat(position.currentLTV.replace('%', ''));
      const healthFactor = parseFloat(position.healthFactor);
      const isAtRisk = await mezoService.isLiquidationRisk(address);

      // Determine risk level
      let riskLevel: 'low' | 'medium' | 'high';
      let recommendations: string[] = [];

      if (ltv >= 85) {
        riskLevel = 'high';
        recommendations = [
          'Consider adding more collateral immediately',
          'Reduce your mUSD debt to lower LTV',
          'Monitor BTC price closely for liquidation risk'
        ];
      } else if (ltv >= 70) {
        riskLevel = 'medium';
        recommendations = [
          'Consider adding collateral to reduce risk',
          'Monitor market conditions',
          'Set up price alerts for BTC'
        ];
      } else {
        riskLevel = 'low';
        recommendations = [
          'Your position is healthy',
          'Continue monitoring market conditions',
          'Consider optimizing your yield strategy'
        ];
      }

      const riskAssessment: RiskAssessment = {
        riskLevel,
        recommendations,
        liquidationRisk: isAtRisk ? 1 : 0,
        healthFactor: position.healthFactor
      };

      res.status(200).json({
        success: true,
        data: riskAssessment,
        message: 'Risk assessment completed successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Get risk assessment error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to calculate risk assessment',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async getNetworkStatus(req: Request, res: Response): Promise<void> {
    try {
      const networkStatus = await mezoService.getNetworkStatus();

      res.status(200).json({
        success: true,
        data: networkStatus,
        message: 'Network status retrieved successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Get network status error:', error);
      
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve network status',
        timestamp: new Date()
      } as ApiResponse);
    }
  }
}

// Export singleton instance
export const lendingController = new LendingController();
