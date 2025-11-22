import { Request, Response } from 'express';
import { walletService } from '@/services/wallet.service';
import { WalletAuthRequest, AuthResponse, ApiResponse, WalletNotConnectedError } from '@/types';

export class AuthController {

  async connectWallet(req: Request, res: Response): Promise<void> {
    try {
      const { address, signature, message, walletType }: WalletAuthRequest = req.body;

      // Validate input
      if (!address || !signature || !message || !walletType) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields',
          message: 'address, signature, message, and walletType are required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Validate wallet type
      if (!['mezo-passport', 'phantom'].includes(walletType)) {
        res.status(400).json({
          success: false,
          error: 'Invalid wallet type',
          message: 'walletType must be either "mezo-passport" or "phantom"',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Validate address format
      if (!walletService.isValidAddress(address, walletType)) {
        res.status(400).json({
          success: false,
          error: 'Invalid address format',
          message: `Invalid ${walletType} address format`,
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Authenticate wallet
      const authResult = await walletService.authenticateWallet({
        address,
        signature,
        message,
        walletType
      });

      res.status(200).json({
        success: true,
        data: authResult,
        message: 'Wallet connected successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Connect wallet error:', error);

      if (error instanceof WalletNotConnectedError) {
        res.status(401).json({
          success: false,
          error: 'Authentication failed',
          message: error.message,
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to connect wallet',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async getSignMessage(req: Request, res: Response): Promise<void> {
    try {
      const { address } = req.params;

      if (!address) {
        res.status(400).json({
          success: false,
          error: 'Missing address',
          message: 'Address parameter is required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Detect wallet type from address format
      const walletType = walletService.detectWalletType(address);

      if (!walletType) {
        res.status(400).json({
          success: false,
          error: 'Invalid address format',
          message: 'Address format not recognized for Mezo Passport or Phantom wallet',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      // Generate message for signing
      const timestamp = Math.floor(Date.now() / 1000);
      const message = walletService.generateSignMessage(address, timestamp);

      res.status(200).json({
        success: true,
        data: {
          message,
          timestamp,
          walletType,
          address
        },
        message: 'Sign message generated successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Get sign message error:', error);

      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to generate sign message',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async verifyToken(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Missing token',
          message: 'Authorization header with Bearer token is required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const userData = await walletService.verifyJWTToken(token);

      res.status(200).json({
        success: true,
        data: {
          valid: true,
          user: userData,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
        },
        message: 'Token is valid',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Verify token error:', error);

      res.status(401).json({
        success: false,
        error: 'Invalid token',
        message: 'Token is invalid or expired',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Missing token',
          message: 'Authorization header with Bearer token is required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const authResult = await walletService.refreshToken(token);

      res.status(200).json({
        success: true,
        data: authResult,
        message: 'Token refreshed successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Refresh token error:', error);

      res.status(401).json({
        success: false,
        error: 'Token refresh failed',
        message: 'Cannot refresh invalid or expired token',
        timestamp: new Date()
      } as ApiResponse);
    }
  }

  async getWalletInfo(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: 'Missing token',
          message: 'Authorization header with Bearer token is required',
          timestamp: new Date()
        } as ApiResponse);
        return;
      }

      const token = authHeader.substring(7);
      const userData = await walletService.verifyJWTToken(token);

      // Format address for display
      const formattedAddress = walletService.formatAddress(userData.address);

      res.status(200).json({
        success: true,
        data: {
          address: userData.address,
          formattedAddress,
          walletType: userData.walletType,
          isConnected: true
        },
        message: 'Wallet info retrieved successfully',
        timestamp: new Date()
      } as ApiResponse);

    } catch (error) {
      console.error('❌ Get wallet info error:', error);

      res.status(401).json({
        success: false,
        error: 'Authentication failed',
        message: 'Invalid or expired token',
        timestamp: new Date()
      } as ApiResponse);
    }
  }
}

// Export singleton instance
export const authController = new AuthController();
