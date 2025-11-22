import React, { useState, useCallback, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  TouchableOpacity,
  Clipboard,
} from 'react-native';
import Animated, {
  FadeInDown,
  FadeInUp,
  SlideInRight,
  useSharedValue,
  withSpring,
  withTiming,
  withSequence,
  withRepeat,
  useAnimatedStyle,
  Easing,
} from 'react-native-reanimated';
import * as Haptics from 'expo-haptics';
import { Feather } from '@expo/vector-icons';
import {
  Colors,
  Typography,
  Spacing,
  BorderRadius,
  Layout,
  Borders,
} from '@/constants/designTokens';
import { ActionButton } from '@/components/ui/ActionButton';
import { SectionCard } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { SuccessToast } from '@/components/ui/SuccessToast';
import { useTheme } from '@/contexts/ThemeContext';
import { useWallet } from '@/contexts/WalletProvider';
import ICPBridgeService from '@/services/ICPBridgeService';
import TransactionMonitorService from '@/services/TransactionMonitorService';
import transactionStore from '@/utils/transactionStore';
import logger from '@/utils/logger';

interface MintScreenProps {
  onNavigate: (screen: string) => void;
}

export const MintScreen: React.FC<MintScreenProps> = ({ onNavigate }) => {
  const { colors: themeColors } = useTheme();
  const { address } = useWallet();
  const [btcAmount, setBtcAmount] = useState('');
  const [isConfirmed, setIsConfirmed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [touched, setTouched] = useState(false);
  const [walletBalance, setWalletBalance] = useState(0);
  const [btcDepositAddress, setBtcDepositAddress] = useState('');
  const [showCopiedToast, setShowCopiedToast] = useState(false);
  const [mintResult, setMintResult] = useState<{
    txHash: string;
    musdAmount: number;
    newLtv: string;
  } | null>(null);

  const progressValue = useSharedValue(0);

  const btcPrice = 65000;
  const ltvRatio = 0.5;
  const fee = 0.01;

  const btcValue = parseFloat(btcAmount) || 0;
  const usdValue = btcValue * btcPrice;
  const musdMinted = usdValue * ltvRatio;
  const feeAmount = musdMinted * fee;
  const netMinted = musdMinted - feeAmount;

  useEffect(() => {
    loadBalance();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address]);

  const loadBalance = async () => {
    if (!address) return;
    try {
      const btcAddr = await ICPBridgeService.getBTCDepositAddress();
      setBtcDepositAddress(btcAddr);
      const { btc } = await ICPBridgeService.getBTCBalance(btcAddr);
      setWalletBalance(parseFloat(btc));
    } catch (error) {
      logger.error('Failed to load BTC balance', error);
      setWalletBalance(0);
    }
  };

  const copyAddressToClipboard = async () => {
    if (btcDepositAddress) {
      await Clipboard.setString(btcDepositAddress);
      setShowCopiedToast(true);
    }
  };

  // Validation
  const validateAmount = useCallback((value: string) => {
    const numValue = parseFloat(value);

    if (!value || numValue === 0) {
      return '';
    }

    if (isNaN(numValue)) {
      return 'Please enter a valid number';
    }

    if (numValue <= 0) {
      return 'Amount must be greater than 0';
    }

    if (numValue > walletBalance) {
      return 'Insufficient balance';
    }

    return '';
  }, [walletBalance, minMintAmount]);

  useEffect(() => {
    if (touched) {
      setError(validateAmount(btcAmount));
    }
  }, [btcAmount, touched, validateAmount]);

  const [mintStep, setMintStep] = useState(0);
  const [stepStatus, setStepStatus] = useState('');

  // ... existing state ...

  const handleConfirm = useCallback(async () => {
    const validationError = validateAmount(btcAmount);
    if (validationError) {
      setError(validationError);
      setTouched(true);
      return;
    }

    setIsLoading(true);
    setMintStep(1);
    setStepStatus('Requesting Mezo Deposit Address...');
    progressValue.value = 0;
    progressValue.value = withTiming(1, { duration: 15000 }); // Longer for multi-step

    const btcValue = parseFloat(btcAmount);
    const musdAmount = usdValue * ltvRatio - (usdValue * ltvRatio * fee);

    const tx = await transactionStore.addTransaction({
      type: 'mint',
      token: 'mUSD',
      amount: musdAmount,
      status: 'pending',
    });

    try {
      await ICPBridgeService.initialize();

      // Step 1: Initiate Deposit on Mezo (Get EVM Tx to find logs)
      setStepStatus('Requesting Mezo Deposit Address...');
      const initTxHash = await ICPBridgeService.initiateBridgeTransfer(btcValue);
      console.log('Init Tx:', initTxHash);

      // Step 2: Parse Logs (Mocking this part as we need an EVM indexer)
      setMintStep(2);
      setStepStatus('Identifying Bridge Address...');
      await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate log parsing
      const mockMezoBtcAddress = "tb1q4280xaxzd80af93nyy9m65ykhrz64c4nXZ_MOCK"; 

      // Step 3: Send BTC to that address
      setMintStep(3);
      setStepStatus(`Sending BTC to ${mockMezoBtcAddress.slice(0, 8)}...`);
      const btcTxId = await ICPBridgeService.sendBTCToAddress(mockMezoBtcAddress, btcValue);
      console.log('BTC Sent:', btcTxId);

      // Step 4: Submit Proof (Mocking Off-chain Relayer)
      setMintStep(4);
      setStepStatus('Waiting for BTC Confirmations & Proving...');
      await new Promise(resolve => setTimeout(resolve, 5000)); // Simulate proof generation time

      // Step 5: Open Trove (Finalize)
      setMintStep(5);
      setStepStatus('Opening Trove on Mezo...');
      
      // This is the existing logic (calls openTrove)
      let result = await ICPBridgeService.mintMUSDOnMezo(btcValue);
      
      if (result.transaction_hash) {
        await transactionStore.updateTransaction(tx.id, {
          mezoTxHash: result.transaction_hash,
        });
      }

      // Poll for finalization if pending
      const MAX_POLLS = 60;
      let polls = 0;
      while (result.status === 'pending' && polls < MAX_POLLS) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        result = await ICPBridgeService.finalizeMintTransaction(result.transaction_hash);
        polls++;
      }

      if (result.status === 'confirmed') {
        await transactionStore.updateTransaction(tx.id, {
          status: 'confirmed',
          mezoTxHash: result.transaction_hash,
          amount: Number(result.musd_amount) / 1e18,
        });

        setMintResult({
          txHash: result.transaction_hash,
          musdAmount: Number(result.musd_amount) / 1e18,
          newLtv: result.new_ltv,
        });

        setIsConfirmed(true);
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      } else {
        throw new Error(result.status === 'pending' ? 'Transaction timed out' : 'Mint failed on chain');
      }

      TransactionMonitorService.startMonitoring(tx.id, 'mint');
    } catch (error: any) {
      logger.error('Mint failed', error);
      await transactionStore.updateTransaction(tx.id, {
        status: 'failed',
        errorMessage: error.message || 'Failed to mint mUSD',
      });
      setError(error.message || 'Failed to mint mUSD');
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
    } finally {
      setIsLoading(false);
      setMintStep(0);
      setStepStatus('');
    }
  }, [btcAmount, validateAmount, progressValue, usdValue, ltvRatio, fee]);

  const handleMaxAmount = useCallback(() => {
    setBtcAmount(walletBalance.toString());
    setTouched(true);
  }, [walletBalance]);

  const handleAmountChange = useCallback((value: string) => {
    // Only allow numbers and decimal point
    const cleaned = value.replace(/[^0-9.]/g, '');
    // Only allow one decimal point
    const parts = cleaned.split('.');
    if (parts.length > 2) return;

    setBtcAmount(cleaned);
  }, []);

  const isValid = btcValue > 0 && !error && btcValue >= minMintAmount && btcValue <= walletBalance;

  if (isConfirmed) {
    return (
      <ScrollView
        style={[styles.container, { backgroundColor: themeColors.background }]}
        contentContainerStyle={styles.contentContainer}
      >
        <Animated.View
          entering={FadeInDown.duration(600).delay(100)}
          style={styles.successSection}
        >
          <SuccessIcon />
          <Animated.Text
            entering={FadeInUp.duration(500).delay(300)}
            style={[styles.successTitle, { color: themeColors.textPrimary }]}
            numberOfLines={1}
          >
            Mint Successful
          </Animated.Text>
          <Animated.Text
            entering={FadeInUp.duration(500).delay(400)}
            style={[styles.successSubtitle, { color: themeColors.textSecondary }]}
            numberOfLines={2}
          >
            Your mUSD has been minted on Mezo
          </Animated.Text>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(600).delay(500)}>
          <PremiumAmountCard value={mintResult?.musdAmount || netMinted} themeColors={themeColors} />
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(600).delay(600)}>
          <SectionCard borderRadius="none" padding="xl">
            <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>Transaction Details</Text>
            <DetailRow
              label="Amount Minted"
              value={`${(mintResult?.musdAmount || netMinted).toFixed(2)} mUSD`}
              icon="check-circle"
              themeColors={themeColors}
            />
            <DetailRow
              label="BTC Collateral"
              value={`${btcAmount} BTC`}
              icon="lock"
              themeColors={themeColors}
            />
            <DetailRow
              label="LTV Ratio"
              value={mintResult?.newLtv || `${(ltvRatio * 100).toFixed(0)}%`}
              icon="trending-up"
              themeColors={themeColors}
            />
          </SectionCard>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(600).delay(700)}>
          <SectionCard borderRadius="none" padding="xl">
            <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>Transaction Proof</Text>
            <ProofBox
              label="Transaction Hash"
              value={mintResult?.txHash || '0x...'}
              themeColors={themeColors}
            />
            <View style={[styles.detailRow, { marginTop: Spacing.md }]}>
              <View style={styles.detailLeft}>
                <Feather name="check-circle" size={16} color={Colors.semantic.success} />
                <Text style={[styles.detailLabel, { color: themeColors.textSecondary }]}>
                  Minted via ICP Bridge
                </Text>
              </View>
            </View>
          </SectionCard>
        </Animated.View>

        <Animated.View
          entering={FadeInUp.duration(600).delay(800)}
          style={styles.actionsSection}
        >
          <ActionButton variant="accent" fullWidth onPress={() => onNavigate('Bridge')}>
            Proceed to Bridge
          </ActionButton>
          <ActionButton variant="secondary" fullWidth onPress={() => onNavigate('Home')}>
            Back to Home
          </ActionButton>
        </Animated.View>

        <View style={styles.bottomSpacer} />
      </ScrollView>
    );
  }

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={[styles.container, { backgroundColor: themeColors.background }]}
    >
      <ScrollView
        style={[styles.container, { backgroundColor: themeColors.background }]}
        contentContainerStyle={styles.contentContainer}
        keyboardShouldPersistTaps="handled"
      >
        <Animated.View entering={FadeInDown.duration(500).delay(100)} style={styles.header}>
          <Text style={[styles.title, { color: themeColors.textPrimary }]}>
            Mint mUSD
          </Text>
          <Text style={[styles.subtitle, { color: themeColors.textSecondary }]}>
            Deposit BTC collateral to mint stablecoin
          </Text>
        </Animated.View>

        {walletBalance === 0 && btcDepositAddress && (
          <Animated.View entering={FadeInDown.duration(500).delay(150)}>
            <SectionCard borderRadius="none" padding="xl">
              <View style={styles.depositAddressSection}>
                <View style={styles.depositAddressHeader}>
                  <Feather name="download" size={20} color={themeColors.textPrimary} />
                  <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>
                    Deposit Bitcoin
                  </Text>
                </View>
                <Text style={[styles.depositAddressDescription, { color: themeColors.textSecondary }]}>
                  Send testnet BTC to this address to add collateral
                </Text>
                <TouchableOpacity
                  onPress={copyAddressToClipboard}
                  style={[styles.addressBox, { backgroundColor: themeColors.surfaceSecondary, borderColor: themeColors.border }]}
                  activeOpacity={0.7}
                >
                  <Text style={[styles.addressText, { color: themeColors.textPrimary }]} numberOfLines={1}>
                    {btcDepositAddress}
                  </Text>
                  <Feather name="copy" size={18} color={themeColors.textSecondary} />
                </TouchableOpacity>
                <View style={styles.depositAddressFooter}>
                  <Feather name="info" size={14} color={themeColors.textTertiary} />
                  <Text style={[styles.depositAddressNote, { color: themeColors.textTertiary }]}>
                    Get testnet BTC from a faucet, then use it here to mint mUSD
                  </Text>
                </View>
              </View>
            </SectionCard>
          </Animated.View>
        )}

        <Animated.View entering={FadeInDown.duration(500).delay(200)}>
          <SectionCard borderRadius="none" padding="xl">
            <View style={styles.inputHeader}>
              <Text style={[styles.inputLabel, { color: themeColors.textPrimary }]}>
                Amount
              </Text>
              <TouchableOpacity
                onPress={handleMaxAmount}
                style={[
                  styles.maxButton,
                  {
                    backgroundColor: themeColors.surfaceSecondary,
                    borderColor: themeColors.border,
                  },
                ]}
              >
                <Text style={[styles.maxButtonText, { color: themeColors.textPrimary }]}>
                  MAX
                </Text>
              </TouchableOpacity>
            </View>

            <View style={styles.largeInputContainer}>
              <Input
                value={btcAmount}
                onChangeText={handleAmountChange}
                placeholder="0.00"
                keyboardType="decimal-pad"
                error={touched ? error : undefined}
                onBlur={() => setTouched(true)}
                style={styles.largeInput}
                variant="filled"
                rightElement={
                  <Text style={[styles.inputUnit, { color: themeColors.textSecondary }]}>
                    BTC
                  </Text>
                }
              />
            </View>

            <View style={styles.balanceRow}>
              <View style={[styles.balanceItem, { flex: 1, marginRight: Spacing.md }]}>
                <Feather name="briefcase" size={14} color={themeColors.textSecondary} />
                <Text
                  style={[styles.balanceLabel, { color: themeColors.textSecondary, flex: 1 }]}
                  numberOfLines={1}
                  adjustsFontSizeToFit
                >
                  Balance: {walletBalance} BTC
                </Text>
                <TouchableOpacity onPress={loadBalance} style={styles.refreshButton}>
                  <Feather name="refresh-cw" size={14} color={Colors.accent.primary} />
                </TouchableOpacity>
              </View>
              <View style={styles.balanceItem}>
                <Feather name="trending-up" size={14} color={themeColors.textSecondary} />
                <Text
                  style={[styles.priceLabel, { color: themeColors.textSecondary }]}
                  numberOfLines={1}
                  adjustsFontSizeToFit
                >
                  ~${btcPrice.toLocaleString()}
                </Text>
              </View>
            </View>
          </SectionCard>
        </Animated.View>

        {btcValue > 0 && isValid && (
          <>
            <Animated.View
              entering={FadeInDown.duration(500).delay(100)}
              style={styles.statsGrid}
            >
              <SectionCard borderRadius="none" padding="lg" style={styles.statBox}>
                <Feather name="dollar-sign" size={20} color={themeColors.textSecondary} />
                <Text style={[styles.statLabel, { color: themeColors.textSecondary }]}>
                  USD Value
                </Text>
                <Text
                  style={[styles.statValue, { color: themeColors.textPrimary }]}
                  numberOfLines={1}
                  adjustsFontSizeToFit
                >
                  ${usdValue.toLocaleString()}
                </Text>
              </SectionCard>
              <SectionCard borderRadius="none" padding="lg" style={styles.statBox}>
                <Feather name="arrow-down-circle" size={20} color={Colors.accent.primary} />
                <Text style={[styles.statLabel, { color: themeColors.textSecondary }]}>
                  You Receive
                </Text>
                <Text
                  style={[styles.statValue, { color: themeColors.textPrimary }]}
                  numberOfLines={1}
                  adjustsFontSizeToFit
                >
                  {netMinted.toFixed(2)}
                </Text>
                <Text style={[styles.statUnit, { color: themeColors.textTertiary }]}>
                  mUSD
                </Text>
              </SectionCard>
            </Animated.View>

            <Animated.View entering={FadeInDown.duration(500).delay(200)}>
              <SectionCard borderRadius="none" padding="xl">
                <View style={styles.ltvHeader}>
                  <View>
                    <Text style={[styles.ltvLabel, { color: themeColors.textPrimary }]}>
                      Loan-to-Value Ratio
                    </Text>
                    <Text style={[styles.ltvDescription, { color: themeColors.textSecondary }]}>
                      Safe collateralization
                    </Text>
                  </View>
                  <Text style={[styles.ltvValue, { color: themeColors.textPrimary }]}>
                    {(ltvRatio * 100).toFixed(0)}%
                  </Text>
                </View>
                <View style={styles.progressBarContainer}>
                  <Animated.View
                    entering={SlideInRight.duration(600).delay(400)}
                    style={[styles.progressBar, { backgroundColor: themeColors.surfaceSecondary }]}
                  >
                    <Animated.View
                      style={[styles.progressFill, { width: `${ltvRatio * 100}%` }]}
                    />
                  </Animated.View>
                </View>
                <View style={styles.ltvRange}>
                  <View style={styles.rangeItem}>
                    <View style={[styles.rangeDot, { backgroundColor: Colors.semantic.success }]} />
                    <Text style={[styles.rangeLabel, { color: themeColors.textSecondary }]}>Safe</Text>
                  </View>
                  <View style={styles.rangeItem}>
                    <View style={[styles.rangeDot, { backgroundColor: Colors.semantic.error }]} />
                    <Text style={[styles.rangeLabel, { color: themeColors.textSecondary }]}>Risky</Text>
                  </View>
                </View>
              </SectionCard>
            </Animated.View>

            <Animated.View entering={FadeInDown.duration(500).delay(300)}>
              <SectionCard borderRadius="none" padding="xl">
                <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>Fee Breakdown</Text>
                <FeeRow
                  label="Mint Amount"
                  value={`${musdMinted.toFixed(2)} mUSD`}
                  icon="plus-circle"
                  themeColors={themeColors}
                />
                <FeeRow
                  label="Protocol Fee (1%)"
                  value={`${feeAmount.toFixed(2)} mUSD`}
                  icon="minus-circle"
                  themeColors={themeColors}
                />
                <View style={[styles.feeDivider, { backgroundColor: themeColors.border }]} />
                <FeeRow
                  label="You Receive"
                  value={`${netMinted.toFixed(2)} mUSD`}
                  icon="check-circle"
                  bold
                  themeColors={themeColors}
                />
              </SectionCard>
            </Animated.View>
          </>
        )}

        <Animated.View
          entering={FadeInUp.duration(500).delay(400)}
          style={styles.actionsSection}
        >
          <ActionButton
            variant="accent"
            fullWidth
            disabled={!isValid}
            loading={isLoading}
            onPress={handleConfirm}
          >
            {isLoading ? (stepStatus || 'Minting...') : 'Confirm Mint'}
          </ActionButton>
          <ActionButton variant="secondary" fullWidth onPress={() => onNavigate('Home')}>
            Cancel
          </ActionButton>
        </Animated.View>

        <View style={styles.bottomSpacer} />
      </ScrollView>

      {showCopiedToast && (
        <SuccessToast
          message="Bitcoin address copied to clipboard"
          onClose={() => setShowCopiedToast(false)}
        />
      )}
    </KeyboardAvoidingView>
  );
};

const SuccessIcon: React.FC = () => {
  const scale = useSharedValue(0);
  const rotation = useSharedValue(0);
  const pulseScale = useSharedValue(1);

  useEffect(() => {
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);

    scale.value = withSequence(
      withSpring(1.2, { damping: 8, stiffness: 100 }),
      withSpring(1, { damping: 12, stiffness: 150 })
    );

    rotation.value = withSequence(
      withTiming(10, { duration: 100 }),
      withTiming(-10, { duration: 100 }),
      withTiming(0, { duration: 100 })
    );

    pulseScale.value = withRepeat(
      withSequence(
        withTiming(1.05, { duration: 800, easing: Easing.inOut(Easing.ease) }),
        withTiming(1, { duration: 800, easing: Easing.inOut(Easing.ease) })
      ),
      -1,
      true
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const animatedStyle = useAnimatedStyle(() => ({
    transform: [
      { scale: scale.value },
      { rotate: `${rotation.value}deg` },
    ],
  }));

  const pulseStyle = useAnimatedStyle(() => ({
    transform: [{ scale: pulseScale.value }],
  }));

  const { colors: themeColors } = useTheme();

  return (
    <Animated.View style={animatedStyle}>
      <Animated.View
        style={[
          styles.successIcon,
          {
            backgroundColor: themeColors.surfaceSecondary,
            borderColor: Colors.semantic.success,
          },
          pulseStyle,
        ]}
      >
        <Feather name="check" size={64} color={Colors.semantic.success} />
      </Animated.View>
    </Animated.View>
  );
};

const PremiumAmountCard: React.FC<{ value: number; themeColors: ReturnType<typeof useTheme>['colors'] }> = ({
  value,
  themeColors
}) => {
  const shimmerTranslateX = useSharedValue(-300);
  const cardScale = useSharedValue(0.95);

  useEffect(() => {
    shimmerTranslateX.value = withRepeat(
      withTiming(300, { duration: 2000, easing: Easing.linear }),
      -1,
      false
    );

    cardScale.value = withSpring(1, {
      damping: 15,
      stiffness: 100,
    });

    const timer = setTimeout(() => {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    }, 100);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const shimmerStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: shimmerTranslateX.value }],
  }));

  const cardStyle = useAnimatedStyle(() => ({
    transform: [{ scale: cardScale.value }],
  }));

  return (
    <Animated.View style={cardStyle}>
      <View
        style={[
          styles.premiumCard,
          {
            backgroundColor: themeColors.surface,
            borderColor: themeColors.border,
          },
        ]}
      >
        <View style={styles.shimmerContainer}>
          <Animated.View style={[styles.shimmer, shimmerStyle]} />
        </View>

        <Text style={[styles.premiumLabel, { color: themeColors.textSecondary }]} numberOfLines={1}>
          You Received
        </Text>

        <AnimatedCounter value={value} decimals={2} themeColors={themeColors} />

        <View style={styles.unitContainer}>
          <View style={[styles.unitBadge, { borderColor: Colors.accent.primary }]}>
            <Text style={[styles.premiumUnit, { color: Colors.accent.primary }]} numberOfLines={1}>
              mUSD
            </Text>
          </View>
        </View>

        <View style={styles.decorativeElements}>
          <View style={[styles.decorativeDot, { backgroundColor: Colors.accent.primary }]} />
          <View style={[styles.decorativeDot, { backgroundColor: Colors.accent.primary }]} />
          <View style={[styles.decorativeDot, { backgroundColor: Colors.accent.primary }]} />
        </View>
      </View>
    </Animated.View>
  );
};

interface AnimatedCounterProps {
  value: number;
  decimals?: number;
  themeColors: ReturnType<typeof useTheme>['colors'];
}

const AnimatedCounter: React.FC<AnimatedCounterProps> = ({ value, decimals = 2, themeColors }) => {
  const [displayValue, setDisplayValue] = useState(0);
  const textScale = useSharedValue(1);

  useEffect(() => {
    let startValue = 0;
    const duration = 1800;
    const startTime = Date.now();
    let lastHapticValue = 0;

    const animate = () => {
      const now = Date.now();
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 4);
      const current = startValue + (value - startValue) * eased;

      setDisplayValue(current);

      if (Math.floor(current / 1000) > lastHapticValue) {
        lastHapticValue = Math.floor(current / 1000);
        Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      }

      if (progress < 1) {
        requestAnimationFrame(animate);
      } else {
        setDisplayValue(value);
        textScale.value = withSequence(
          withSpring(1.1, { damping: 8 }),
          withSpring(1, { damping: 10 })
        );
        Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
      }
    };

    requestAnimationFrame(animate);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  const animatedTextStyle = useAnimatedStyle(() => ({
    transform: [{ scale: textScale.value }],
  }));

  const formattedValue = displayValue.toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });

  return (
    <Animated.Text
      style={[
        styles.premiumAmount,
        { color: themeColors.textPrimary },
        animatedTextStyle,
      ]}
      numberOfLines={1}
      adjustsFontSizeToFit
    >
      {formattedValue}
    </Animated.Text>
  );
};

// Detail Row Component
interface DetailRowProps {
  label: string;
  value: string;
  icon?: string;
  themeColors: ReturnType<typeof useTheme>['colors'];
}

const DetailRow = React.memo<DetailRowProps>(({ label, value, icon, themeColors }) => (
  <View style={styles.detailRow}>
    <View style={styles.detailLeft}>
      {icon && <Feather name={icon as any} size={16} color={themeColors.textSecondary} />}
      <Text style={[styles.detailLabel, { color: themeColors.textSecondary }]}>{label}</Text>
    </View>
    <Text style={[styles.detailValue, { color: themeColors.textPrimary }]}>{value}</Text>
  </View>
));

DetailRow.displayName = 'DetailRow';

// Proof Box Component
interface ProofBoxProps {
  label: string;
  value: string;
  themeColors: ReturnType<typeof useTheme>['colors'];
}

const ProofBox = React.memo<ProofBoxProps>(({ label, value, themeColors }) => (
  <View style={styles.proofRow}>
    <View style={styles.proofLeft}>
      <Feather name="shield" size={16} color={themeColors.textSecondary} />
      <Text style={[styles.proofLabel, { color: themeColors.textSecondary }]}>{label}</Text>
    </View>
    <TouchableOpacity style={styles.proofValue}>
      <Text style={[styles.proofText, { color: themeColors.textPrimary }]}>
        {value.slice(0, 8)}...{value.slice(-6)}
      </Text>
      <Feather name="copy" size={14} color={themeColors.textTertiary} />
    </TouchableOpacity>
  </View>
));

ProofBox.displayName = 'ProofBox';

// Fee Row Component
interface FeeRowProps {
  label: string;
  value: string;
  icon?: string;
  bold?: boolean;
  themeColors: ReturnType<typeof useTheme>['colors'];
}

const FeeRow = React.memo<FeeRowProps>(({ label, value, icon, bold, themeColors }) => (
  <View style={styles.feeRow}>
    <View style={styles.feeLeft}>
      {icon && (
        <Feather
          name={icon as any}
          size={16}
          color={bold ? themeColors.textPrimary : themeColors.textSecondary}
        />
      )}
      <Text style={[
        styles.feeLabel,
        bold && styles.feeLabelBold,
        { color: bold ? themeColors.textPrimary : themeColors.textSecondary }
      ]}>{label}</Text>
    </View>
    <Text style={[
      styles.feeValue,
      bold && styles.feeValueBold,
      { color: themeColors.textPrimary }
    ]}>{value}</Text>
  </View>
));

FeeRow.displayName = 'FeeRow';

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  contentContainer: {
    paddingHorizontal: Layout.screenPadding,
    paddingTop: Spacing.xxxl,
  },
  header: {
    marginBottom: Spacing.xxxl,
  },
  title: {
    ...Typography.h1,
    marginBottom: Spacing.xs,
  },
  subtitle: {
    ...Typography.body,
  },
  inputHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: Spacing.md,
  },
  inputLabel: {
    ...Typography.labelMedium,
  },
  maxButton: {
    borderWidth: Borders.width.regular,
    paddingVertical: Spacing.xxs,
    paddingHorizontal: Spacing.sm,
  },
  maxButtonText: {
    ...Typography.label,
  },
  largeInputContainer: {
    marginBottom: Spacing.md,
  },
  largeInput: {
    ...Typography.display.small,
    height: 80,
  },
  inputUnit: {
    ...Typography.h3,
  },
  balanceRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: Spacing.sm,
  },
  balanceItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xxs,
  },
  balanceLabel: {
    ...Typography.bodySmall,
  },
  refreshButton: {
    padding: Spacing.xxs,
    marginLeft: Spacing.xxs,
  },
  priceLabel: {
    ...Typography.bodySmallSemibold,
  },
  statsGrid: {
    flexDirection: 'row',
    gap: Spacing.md,
    marginBottom: Spacing.xl,
  },
  statBox: {
    flex: 1,
    alignItems: 'center',
    gap: Spacing.xs,
  },
  statLabel: {
    ...Typography.labelSmall,
    textAlign: 'center',
  },
  statValue: {
    ...Typography.h3,
    textAlign: 'center',
  },
  statUnit: {
    ...Typography.bodySmall,
    textAlign: 'center',
  },
  sectionTitle: {
    ...Typography.labelMedium,
    marginBottom: Spacing.md,
  },
  ltvHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: Spacing.lg,
  },
  ltvLabel: {
    ...Typography.bodySmallSemibold,
    marginBottom: Spacing.xxs,
  },
  ltvDescription: {
    ...Typography.caption,
  },
  ltvValue: {
    ...Typography.h2,
  },
  progressBarContainer: {
    marginBottom: Spacing.md,
  },
  progressBar: {
    height: 8,
    borderRadius: BorderRadius.sm,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: Colors.semantic.success,
  },
  ltvRange: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  rangeItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xxs,
  },
  rangeDot: {
    width: 8,
    height: 8,
    borderRadius: BorderRadius.circle,
  },
  rangeLabel: {
    ...Typography.caption,
  },
  feeRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: Spacing.sm,
  },
  feeLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
  },
  feeLabel: {
    ...Typography.bodySmall,
  },
  feeLabelBold: {
    ...Typography.bodySemibold,
  },
  feeValue: {
    ...Typography.bodySmallSemibold,
  },
  feeValueBold: {
    ...Typography.h5,
  },
  feeDivider: {
    height: Borders.width.thick,
    marginVertical: Spacing.md,
  },
  actionsSection: {
    gap: Spacing.md,
    marginTop: Spacing.md,
    marginBottom: Spacing.xxl,
  },
  bottomSpacer: {
    height: 120,
  },
  successSection: {
    alignItems: 'center',
    marginBottom: Spacing.xxxxl,
    paddingTop: Spacing.xxxxl + Spacing.md,
    paddingBottom: Spacing.xxxl,
  },
  successIcon: {
    width: 120,
    height: 120,
    borderWidth: 3,
    borderColor: Colors.semantic.success,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: Spacing.xxl,
    shadowColor: Colors.semantic.success,
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3,
    shadowRadius: 16,
    elevation: 12,
  },
  successTitle: {
    ...Typography.h1,
    marginBottom: Spacing.sm,
    fontWeight: '700',
    letterSpacing: -0.5,
  },
  successSubtitle: {
    ...Typography.body,
    textAlign: 'center',
    opacity: 0.8,
  },
  premiumCard: {
    borderWidth: 2,
    paddingVertical: Spacing.xxxxl,
    paddingHorizontal: Spacing.xl,
    position: 'relative',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.1,
    shadowRadius: 12,
    elevation: 5,
  },
  shimmerContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    overflow: 'hidden',
  },
  shimmer: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    width: 100,
    backgroundColor: 'rgba(255, 255, 255, 0.1)',
    transform: [{ skewX: '-20deg' }],
  },
  premiumLabel: {
    ...Typography.labelMedium,
    marginBottom: Spacing.lg,
    textAlign: 'center',
    textTransform: 'uppercase',
    letterSpacing: 2,
    fontWeight: '600',
  },
  premiumAmount: {
    fontSize: 56,
    fontWeight: '800',
    textAlign: 'center',
    marginBottom: Spacing.md,
    fontFamily: 'SpaceGrotesk_700Bold',
    letterSpacing: -2,
    lineHeight: 64,
  },
  unitContainer: {
    alignItems: 'center',
    marginTop: Spacing.sm,
  },
  unitBadge: {
    borderWidth: 2,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
    backgroundColor: 'rgba(234, 193, 25, 0.05)',
  },
  premiumUnit: {
    ...Typography.h4,
    fontWeight: '700',
    letterSpacing: 1,
  },
  decorativeElements: {
    position: 'absolute',
    bottom: Spacing.lg,
    left: 0,
    right: 0,
    flexDirection: 'row',
    justifyContent: 'center',
    gap: Spacing.sm,
  },
  decorativeDot: {
    width: 4,
    height: 4,
    opacity: 0.3,
  },
  resultLabel: {
    ...Typography.labelMedium,
    marginBottom: Spacing.sm,
    textAlign: 'center',
  },
  resultAmount: {
    ...Typography.display.large,
    marginBottom: Spacing.xs,
    textAlign: 'center',
  },
  resultUnit: {
    ...Typography.h4,
    textAlign: 'center',
  },
  detailRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: Spacing.sm,
  },
  detailLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
  },
  detailLabel: {
    ...Typography.bodySmall,
  },
  detailValue: {
    ...Typography.bodySmallSemibold,
  },
  proofRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: Spacing.sm,
  },
  proofLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
  },
  proofLabel: {
    ...Typography.bodySmall,
  },
  proofValue: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
  },
  proofText: {
    ...Typography.mono,
  },
  depositAddressSection: {
    gap: Spacing.md,
  },
  depositAddressHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
    marginBottom: Spacing.xs,
  },
  depositAddressDescription: {
    ...Typography.bodySmall,
    marginBottom: Spacing.md,
    lineHeight: 20,
  },
  addressBox: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: Spacing.md,
    borderWidth: Borders.width.thin,
    borderRadius: BorderRadius.md,
    gap: Spacing.sm,
  },
  addressText: {
    ...Typography.mono,
    fontSize: 13,
    flex: 1,
  },
  depositAddressFooter: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: Spacing.xs,
    marginTop: Spacing.xs,
  },
  depositAddressNote: {
    ...Typography.caption,
    flex: 1,
    lineHeight: 16,
  },
});
