import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
} from 'react-native';
import Animated, {
  FadeInDown,
  FadeInUp,
  FadeIn,
  FadeInLeft,
  SlideInRight,
  useAnimatedStyle,
  useSharedValue,
  withSpring,
} from 'react-native-reanimated';
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
import { SectionCard, InteractiveCard } from '@/components/ui/Card';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { SuccessToast } from '@/components/ui/SuccessToast';
import { CustomAlert } from '@/components/ui/CustomAlert';
import { useTheme } from '@/contexts/ThemeContext';
import { useWallet } from '@/contexts/WalletProvider';
import ICPBridgeService from '@/services/ICPBridgeService';
import EthereumWalletService from '@/services/EthereumWalletService';
import TransactionMonitorService from '@/services/TransactionMonitorService';
import transactionStore from '@/utils/transactionStore';
import logger from '@/utils/logger';

interface BridgeScreenProps {
  onNavigate: (screen: string) => void;
}

type StepStatus = 'pending' | 'in_progress' | 'confirmed' | 'failed';

interface BridgeStep {
  id: number;
  label: string;
  description: string;
  txHash?: string;
  confirmations?: number;
  status: StepStatus;
  icon: string;
}

export const BridgeScreen: React.FC<BridgeScreenProps> = ({ onNavigate }) => {
  const { colors: themeColors } = useTheme();
  const { address } = useWallet();
  const [currentStep, setCurrentStep] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [bridgeAmount, setBridgeAmount] = useState(0);
  const [showSuccessToast, setShowSuccessToast] = useState(false);
  const [alertConfig, setAlertConfig] = useState<{
    visible: boolean;
    title: string;
    message: string;
    type: 'error' | 'info';
  }>({ visible: false, title: '', message: '', type: 'info' });
  const [steps, setSteps] = useState<BridgeStep[]>([
    {
      id: 0,
      label: 'Check Position',
      description: 'Verify mUSD balance and readiness',
      status: 'pending',
      icon: 'check-circle',
    },
    {
      id: 1,
      label: 'Bridge to Solana',
      description: 'Transfer mUSD to Solana network',
      status: 'pending',
      icon: 'loader',
    },
    {
      id: 2,
      label: 'Receive on Solana',
      description: 'mUSD available in Solana wallet',
      status: 'pending',
      icon: 'circle',
    },
  ]);

  const poolData = {
    poolName: 'Marinade Finance',
    apy: 8.5,
    tvl: 1250000000,
    logo: '🌊',
    risk: 'Low' as const,
  };

  useEffect(() => {
    loadPosition();
  }, [address]);

  const loadPosition = async () => {
    if (!address) return;
    try {
      logger.debug('BridgeScreen: Loading tracked mUSD balance from bridge', { address });

      const position = await ICPBridgeService.getMyPosition();
      const musdAmount = Number((position as any).musd_minted) / 1e18;
      
      logger.debug('BridgeScreen: Got tracked mUSD from bridge position', { musdAmount });

      setBridgeAmount(musdAmount);

      if (musdAmount > 0) {
        updateStepStatus(0, 'confirmed', `✓ Position verified: ${musdAmount.toFixed(2)} mUSD available to bridge`);
      } else {
        updateStepStatus(0, 'pending', 'No mUSD available. Mint mUSD first using the Mint screen.');
      }
    } catch (error) {
      logger.error('BridgeScreen: Failed to load bridge position', error);
      setBridgeAmount(0);
      updateStepStatus(0, 'pending', 'Unable to verify position. Please mint mUSD first.');
    }
  };

  const updateStepStatus = (stepId: number, status: StepStatus, description?: string, txHash?: string) => {
    setSteps(prevSteps =>
      prevSteps.map(step =>
        step.id === stepId
          ? {
            ...step,
            status,
            description: description || step.description,
            txHash: txHash || step.txHash,
            icon: status === 'confirmed' ? 'check-circle' : status === 'in_progress' ? 'loader' : status === 'failed' ? 'x-circle' : 'circle',
          }
          : step
      )
    );
  };

  useEffect(() => {
    if (currentStep === 0 && steps[0].status === 'confirmed') {
      setTimeout(() => {
        setCurrentStep(1);
      }, 1000);
    }
  }, [steps, currentStep]);

  const handleContinue = async () => {
    if (currentStep >= steps.length - 1) return;
    if (bridgeAmount <= 0) {
      setAlertConfig({
        visible: true,
        title: 'No Balance',
        message: 'No mUSD to bridge. Please mint mUSD first.',
        type: 'info',
      });
      return;
    }

    setIsProcessing(true);

    try {
      if (currentStep === 1) {
        updateStepStatus(1, 'in_progress', 'Initiating bridge to Solana...');

        const tx = await transactionStore.addTransaction({
          type: 'bridge',
          token: 'mUSD',
          amount: bridgeAmount,
          status: 'pending',
        });

        logger.info('Bridge transaction created', { txId: tx.id, amount: bridgeAmount });

        ICPBridgeService.bridgeMUSDToSolana(bridgeAmount)
          .then(async (signature) => {
            logger.info('Bridge initiated successfully', { signature });
            await transactionStore.updateTransaction(tx.id, {
              solanaTxSig: signature,
            });
          })
          .catch(async (error) => {
            logger.error('Bridge initiation failed', error);
            await transactionStore.updateTransaction(tx.id, {
              status: 'failed',
              errorMessage: error.message || 'Failed to initiate bridge',
            });
            updateStepStatus(1, 'failed', error.message || 'Failed to initiate bridge');
          });

        TransactionMonitorService.startMonitoring(tx.id, 'bridge');

        updateStepStatus(1, 'in_progress', 'Bridge initiated - monitoring status...');
        updateStepStatus(2, 'in_progress', 'Waiting for Solana confirmation...');

        setCurrentStep(2);
        setShowSuccessToast(true);
      } else {
        setSteps((prev) =>
          prev.map((step, idx) =>
            idx === currentStep
              ? { ...step, status: 'confirmed' }
              : step
          )
        );
        setCurrentStep(currentStep + 1);
        setSteps((prev) =>
          prev.map((step, idx) =>
            idx === currentStep + 1 ? { ...step, status: 'in_progress' } : step
          )
        );
      }
    } catch (error: any) {
      logger.error('Bridge operation failed', error);
      updateStepStatus(currentStep, 'failed', error.message || 'Operation failed');
      setAlertConfig({
        visible: true,
        title: 'Bridge Failed',
        message: error.message || 'Unknown error',
        type: 'error',
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const isComplete = steps.every((s) => s.status === 'confirmed');
  const progressPercentage = ((steps.filter((s) => s.status === 'confirmed').length) / steps.length) * 100;

  return (
    <>
      <ScrollView
        style={[styles.container, { backgroundColor: themeColors.background }]}
        contentContainerStyle={styles.contentContainer}
        showsVerticalScrollIndicator={false}
      >
      {/* Header */}
      <Animated.View entering={FadeInDown.duration(500).delay(100)} style={styles.header}>
        <View style={styles.headerTop}>
          <View>
            <Text style={[styles.title, { color: themeColors.textPrimary }]}>
              Bridge to Solana
            </Text>
            <Text style={[styles.subtitle, { color: themeColors.textSecondary }]}>
              Wrap {bridgeAmount.toLocaleString()} mUSD and earn yield
            </Text>
          </View>
          {isComplete && (
            <Animated.View entering={FadeIn.duration(500)}>
              <Feather name="check-circle" size={32} color={Colors.semantic.success} />
            </Animated.View>
          )}
        </View>

        {/* Progress Bar */}
        <View style={styles.progressContainer}>
          <View style={[styles.progressBar, { backgroundColor: themeColors.surfaceSecondary }]}>
            <Animated.View
              entering={SlideInRight.duration(800).delay(200)}
              style={[styles.progressFill, { width: `${progressPercentage}%` }]}
            />
          </View>
          <Text style={[styles.progressText, { color: themeColors.textSecondary }]}>
            {Math.round(progressPercentage)}% Complete
          </Text>
        </View>
      </Animated.View>

      {/* Bridge Steps */}
      <Animated.View
        entering={FadeInDown.duration(500).delay(200)}
        style={styles.section}
      >
        <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>
          Bridge Progress
        </Text>
        {steps.map((step, index) => (
          <AnimatedStepCard
            key={step.id}
            step={step}
            index={index}
            isActive={currentStep === index}
            delay={300 + index * 100}
            themeColors={themeColors}
          />
        ))}
      </Animated.View>

      {/* Target Pool */}
      <Animated.View
        entering={FadeInDown.duration(500).delay(400)}
        style={styles.section}
      >
        <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>
          Target Yield Pool
        </Text>
        <InteractiveCard
          borderRadius="none"
          padding="xl"
          onPress={() => onNavigate('PoolDetail')}
        >
          <View style={styles.poolHeader}>
            <View
              style={[
                styles.poolIconContainer,
                {
                  backgroundColor: themeColors.surfaceSecondary,
                  borderColor: themeColors.border,
                },
              ]}
            >
              <Text style={styles.poolIcon}>{poolData.logo}</Text>
            </View>
            <View style={styles.poolInfo}>
              <Text style={[styles.poolName, { color: themeColors.textPrimary }]}>
                {poolData.poolName}
              </Text>
              <View style={styles.poolMetaRow}>
                <StatusBadge status="success" label={`${poolData.risk} Risk`} size="sm" showDot={false} />
                <Text style={[styles.poolTvl, { color: themeColors.textTertiary }]}>
                  TVL: ${(poolData.tvl / 1000000000).toFixed(2)}B
                </Text>
              </View>
            </View>
          </View>

          <View style={styles.poolApyContainer}>
            <Text style={styles.poolApyLabel}>Annual Yield</Text>
            <Text style={styles.poolApyValue}>{poolData.apy}%</Text>
          </View>

          <View style={styles.poolEstimate}>
            <Feather name="trending-up" size={16} color={Colors.semantic.success} />
            <Text style={[styles.poolEstimateText, { color: themeColors.textSecondary }]}>
              Estimated: ${((bridgeAmount * poolData.apy) / 100).toLocaleString()}/year
            </Text>
          </View>
        </InteractiveCard>
      </Animated.View>

      {/* Bridge Details */}
      <Animated.View
        entering={FadeInDown.duration(500).delay(500).springify()}
        style={styles.section}
      >
        <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>
          Bridge Details
        </Text>
        <SectionCard borderRadius="none" padding="xl">
          <DetailRow label="Amount" value={`${bridgeAmount.toLocaleString()} mUSD`} icon="dollar-sign" themeColors={themeColors} delay={600} />
          <DetailRow label="From" value="Mezo Network" icon="hexagon" themeColors={themeColors} delay={700} />
          <DetailRow label="To" value="Solana" icon="zap" themeColors={themeColors} delay={800} />
          <DetailRow label="Bridge Fee" value="0.5%" icon="percent" themeColors={themeColors} delay={900} />
          <DetailRow label="Estimated Time" value="~5 minutes" icon="clock" themeColors={themeColors} delay={1000} />
        </SectionCard>
      </Animated.View>

      {/* Action Buttons */}
      <Animated.View
        entering={FadeInUp.duration(500).delay(600)}
        style={styles.actionsSection}
      >
        {!isComplete ? (
          <ActionButton
            variant="accent"
            fullWidth
            loading={isProcessing}
            onPress={handleContinue}
            disabled={steps[currentStep]?.status === 'confirmed'}
          >
            {isProcessing
              ? `Processing Step ${currentStep + 1}...`
              : currentStep === steps.length - 1
                ? 'Deposit to Pool'
                : 'Continue Bridge'}
          </ActionButton>
        ) : (
          <ActionButton
            variant="accent"
            fullWidth
            onPress={() => onNavigate('Activity')}
            icon={<Feather name="check-circle" size={20} color={Colors.text.inverse} />}
          >
            View Transaction
          </ActionButton>
        )}
        <ActionButton variant="secondary" fullWidth onPress={() => onNavigate('Home')}>
          {isComplete ? 'Back to Home' : 'Cancel'}
        </ActionButton>
      </Animated.View>

      <View style={styles.bottomSpacer} />
    </ScrollView>

    {showSuccessToast && (
      <SuccessToast
        message="Bridge initiated! Transaction is being processed in the background."
        onAction={() => {
          setShowSuccessToast(false);
          onNavigate('Activity');
        }}
        actionLabel="View Status"
        onClose={() => setShowSuccessToast(false)}
      />
    )}

    <CustomAlert
      visible={alertConfig.visible}
      title={alertConfig.title}
      message={alertConfig.message}
      type={alertConfig.type}
      onConfirm={() => setAlertConfig({ ...alertConfig, visible: false })}
    />
    </>
  );
};

// Animated Step Card Component
interface AnimatedStepCardProps {
  step: BridgeStep;
  index: number;
  isActive: boolean;
  delay: number;
  themeColors: ReturnType<typeof useTheme>['colors'];
}

const AnimatedStepCard: React.FC<AnimatedStepCardProps> = ({
  step,
  index,
  isActive,
  delay,
  themeColors,
}) => {
  const scale = useSharedValue(isActive ? 1.02 : 1);

  useEffect(() => {
    scale.value = withSpring(isActive ? 1.02 : 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isActive]);

  const animatedStyle = useAnimatedStyle(() => ({
    transform: [{ scale: scale.value }],
  }));

  const getStatusColor = () => {
    switch (step.status) {
      case 'confirmed':
        return Colors.semantic.success;
      case 'in_progress':
        return Colors.accent.primary;
      case 'failed':
        return Colors.semantic.error;
      default:
        return themeColors.textTertiary;
    }
  };

  const getStatusIcon = () => {
    switch (step.status) {
      case 'confirmed':
        return 'check-circle';
      case 'in_progress':
        return 'loader';
      case 'failed':
        return 'x-circle';
      default:
        return 'circle';
    }
  };

  return (
    <Animated.View
      entering={FadeInDown.duration(400).delay(delay)}
      style={animatedStyle}
    >
      <SectionCard
        borderRadius="none"
        padding="lg"
        style={{
          ...styles.stepCard,
          ...(isActive ? styles.stepCardActive : {}),
        }}
      >
        <View style={styles.stepRow}>
          <View style={styles.stepLeft}>
            <View
              style={[
                styles.stepIconContainer,
                { borderColor: getStatusColor() },
                step.status === 'confirmed' && { backgroundColor: getStatusColor() },
              ]}
            >
              <Feather
                name={getStatusIcon() as any}
                size={20}
                color={step.status === 'confirmed' ? Colors.text.inverse : getStatusColor()}
              />
            </View>
            <View style={styles.stepContent}>
              <Text style={[styles.stepLabel, { color: themeColors.textPrimary }]}>
                {step.label}
              </Text>
              <Text style={[styles.stepDescription, { color: themeColors.textSecondary }]}>
                {step.description}
              </Text>
              {step.txHash && (
                <TouchableOpacity style={styles.txHashRow}>
                  <Text style={[styles.txHash, { color: themeColors.textTertiary }]}>
                    {step.txHash.slice(0, 8)}...{step.txHash.slice(-6)}
                  </Text>
                  <Feather name="external-link" size={12} color={themeColors.textTertiary} />
                </TouchableOpacity>
              )}
            </View>
          </View>
          <StatusBadge
            status={step.status === 'in_progress' ? 'pending' : step.status}
            size="sm"
          />
        </View>
      </SectionCard>
    </Animated.View>
  );
};

// Detail Row Component
interface DetailRowProps {
  label: string;
  value: string;
  icon?: string;
  themeColors: ReturnType<typeof useTheme>['colors'];
  delay?: number;
}

const DetailRow = React.memo<DetailRowProps>(({ label, value, icon, themeColors, delay = 0 }) => (
  <Animated.View 
    entering={FadeInLeft.delay(delay).springify().damping(14)}
    style={styles.detailRow}
  >
    <View style={styles.detailLeft}>
      {icon && <Feather name={icon as any} size={16} color={themeColors.textSecondary} />}
      <Text style={[styles.detailLabel, { color: themeColors.textSecondary }]}>{label}</Text>
    </View>
    <Text style={[styles.detailValue, { color: themeColors.textPrimary }]}>{value}</Text>
  </Animated.View>
));

DetailRow.displayName = 'DetailRow';

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.bg.primary,
  },
  contentContainer: {
    paddingHorizontal: Layout.screenPadding,
    paddingTop: Spacing.xxxl,
  },
  header: {
    marginBottom: Spacing.xxl,
  },
  headerTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: Spacing.lg,
  },
  title: {
    ...Typography.h1,
    color: Colors.text.primary,
    marginBottom: Spacing.xs,
  },
  subtitle: {
    ...Typography.body,
    color: Colors.text.secondary,
  },
  progressContainer: {
    gap: Spacing.xs,
  },
  progressBar: {
    height: 8,
    backgroundColor: Colors.neutral[200],
    borderRadius: BorderRadius.sm,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: Colors.accent.primary,
  },
  progressText: {
    ...Typography.caption,
    color: Colors.text.secondary,
    textAlign: 'right',
  },
  section: {
    marginBottom: Spacing.xl,
  },
  sectionTitle: {
    ...Typography.labelMedium,
    color: Colors.text.primary,
    marginBottom: Spacing.md,
  },
  stepCard: {
    marginBottom: Spacing.sm,
  },
  stepCardActive: {
    borderColor: Colors.accent.primary,
    borderWidth: Borders.width.thick,
  },
  stepRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  stepLeft: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: Spacing.md,
    flex: 1,
  },
  stepIconContainer: {
    width: 40,
    height: 40,
    borderRadius: BorderRadius.circle,
    borderWidth: Borders.width.thick,
    justifyContent: 'center',
    alignItems: 'center',
  },
  stepContent: {
    flex: 1,
    gap: Spacing.xxs,
  },
  stepLabel: {
    ...Typography.bodySemibold,
    color: Colors.text.primary,
  },
  stepDescription: {
    ...Typography.bodySmall,
    color: Colors.text.secondary,
  },
  txHashRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xxs,
    marginTop: Spacing.xxs,
  },
  txHash: {
    ...Typography.mono,
    color: Colors.text.tertiary,
    fontSize: 11,
  },
  poolHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.md,
    marginBottom: Spacing.lg,
  },
  poolIconContainer: {
    width: 56,
    height: 56,
    borderWidth: Borders.width.thick,
    borderColor: Colors.border.primary,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: Colors.bg.secondary,
  },
  poolIcon: {
    fontSize: 32,
  },
  poolInfo: {
    flex: 1,
    gap: Spacing.xs,
  },
  poolName: {
    ...Typography.h5,
    color: Colors.text.primary,
  },
  poolMetaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
  },
  poolTvl: {
    ...Typography.caption,
    color: Colors.text.secondary,
  },
  poolApyContainer: {
    borderWidth: Borders.width.thick,
    borderColor: Colors.border.primary,
    padding: Spacing.md,
    marginBottom: Spacing.md,
    alignItems: 'center',
  },
  poolApyLabel: {
    ...Typography.labelSmall,
    color: Colors.text.secondary,
    marginBottom: Spacing.xxs,
  },
  poolApyValue: {
    ...Typography.h2,
    color: Colors.semantic.success,
  },
  poolEstimate: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
    padding: Spacing.sm,
    backgroundColor: Colors.semantic.successBg,
    borderWidth: Borders.width.thin,
    borderColor: Colors.semantic.successBorder,
  },
  poolEstimateText: {
    ...Typography.bodySmall,
    color: Colors.semantic.success,
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
    color: Colors.text.secondary,
  },
  detailValue: {
    ...Typography.bodySmallSemibold,
    color: Colors.text.primary,
  },
  actionsSection: {
    gap: Spacing.md,
    marginBottom: Spacing.xxl,
  },
  bottomSpacer: {
    height: 120,
  },
});
