import React, { useState, useCallback, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  TouchableOpacity,
} from 'react-native';
import Animated, {
  FadeInDown,
  FadeInUp,
  FadeInLeft,
  SlideInRight,
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
import { SectionCard } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { useTheme } from '@/contexts/ThemeContext';

interface SendScreenProps {
  onNavigate: (screen: string) => void;
}

export const SendScreen: React.FC<SendScreenProps> = ({ onNavigate }) => {
  const { colors: themeColors } = useTheme();
  const [recipientAddress, setRecipientAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [isConfirmed, setIsConfirmed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState({ recipient: '', amount: '' });
  const [touched, setTouched] = useState({ recipient: false, amount: false });

  // Mock wallet data
  const walletBalance = 25000; // mUSD
  const networkFee = 0.001; // Fixed fee in mUSD
  const minSendAmount = 1; // Minimum mUSD to send

  const amountValue = parseFloat(amount) || 0;
  const totalCost = amountValue + networkFee;
  const mockTxHash = '0x9f8c4a2b1e3d5f7a9c1b3e5f7a9c1b3e5f7a9c1b3e5f7a9c1b3e5f7a9c1b3e';

  // Validation
  const validateRecipient = useCallback((value: string) => {
    if (!value) {
      return '';
    }

    // Simple validation - check if it looks like an address (starts with 0x and has correct length)
    if (!value.startsWith('0x') || value.length !== 42) {
      return 'Invalid address format';
    }

    return '';
  }, []);

  const validateAmount = useCallback((value: string) => {
    const numValue = parseFloat(value);

    if (!value || numValue === 0) {
      return '';
    }

    if (isNaN(numValue)) {
      return 'Please enter a valid number';
    }

    if (numValue < minSendAmount) {
      return `Minimum amount is ${minSendAmount} mUSD`;
    }

    if (numValue + networkFee > walletBalance) {
      return 'Insufficient balance (including fee)';
    }

    return '';
  }, [walletBalance, minSendAmount, networkFee]);

  useEffect(() => {
    if (touched.recipient) {
      setErrors(prev => ({ ...prev, recipient: validateRecipient(recipientAddress) }));
    }
    if (touched.amount) {
      setErrors(prev => ({ ...prev, amount: validateAmount(amount) }));
    }
  }, [recipientAddress, amount, touched, validateRecipient, validateAmount]);

  const handleConfirm = useCallback(async () => {
    const recipientError = validateRecipient(recipientAddress);
    const amountError = validateAmount(amount);

    if (recipientError || amountError) {
      setErrors({ recipient: recipientError, amount: amountError });
      setTouched({ recipient: true, amount: true });
      return;
    }

    setIsLoading(true);

    // Simulate sending
    await new Promise((resolve) => setTimeout(resolve, 2000));
    setIsLoading(false);
    setIsConfirmed(true);
  }, [recipientAddress, amount, validateRecipient, validateAmount]);

  const handleMaxAmount = useCallback(() => {
    const maxSendable = Math.max(0, walletBalance - networkFee);
    setAmount(maxSendable.toString());
    setTouched(prev => ({ ...prev, amount: true }));
  }, [walletBalance, networkFee]);

  const handleAmountChange = useCallback((value: string) => {
    // Only allow numbers and decimal point
    const cleaned = value.replace(/[^0-9.]/g, '');
    // Only allow one decimal point
    const parts = cleaned.split('.');
    if (parts.length > 2) return;

    setAmount(cleaned);
  }, []);

  const isValid =
    recipientAddress &&
    amountValue > 0 &&
    !errors.recipient &&
    !errors.amount &&
    amountValue >= minSendAmount &&
    totalCost <= walletBalance;

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
          <Animated.View
            entering={FadeInUp.duration(500).delay(200)}
            style={[styles.successIcon, { backgroundColor: themeColors.surfaceSecondary }]}
          >
            <Feather name="check" size={64} color={Colors.semantic.success} />
          </Animated.View>
          <Animated.Text
            entering={FadeInUp.duration(500).delay(300)}
            style={[styles.successTitle, { color: themeColors.textPrimary }]}
          >
            Transfer Successful
          </Animated.Text>
          <Animated.Text
            entering={FadeInUp.duration(500).delay(400)}
            style={[styles.successSubtitle, { color: themeColors.textSecondary }]}
          >
            Your mUSD has been sent
          </Animated.Text>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(600).delay(500).springify()}>
          <SectionCard borderRadius="none" padding="xxxl">
            <Text style={[styles.resultLabel, { color: themeColors.textSecondary }]}>Amount Sent</Text>
            <Animated.Text 
              entering={FadeInUp.delay(600).springify()}
              style={[styles.resultAmount, { color: themeColors.textPrimary }]}
            >
              {amountValue.toFixed(2)}
            </Animated.Text>
            <Text style={[styles.resultUnit, { color: themeColors.textTertiary }]}>mUSD</Text>
          </SectionCard>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(600).delay(600)}>
          <SectionCard borderRadius="none" padding="xl">
            <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>Transaction Details</Text>
            <DetailRow
              label="Recipient"
              value={`${recipientAddress.slice(0, 10)}...${recipientAddress.slice(-8)}`}
              icon="user"
              themeColors={themeColors}
              delay={700}
            />
            <DetailRow
              label="Amount"
              value={`${amountValue.toFixed(2)} mUSD`}
              icon="dollar-sign"
              themeColors={themeColors}
              delay={800}
            />
            <DetailRow
              label="Network Fee"
              value={`${networkFee.toFixed(3)} mUSD`}
              icon="zap"
              themeColors={themeColors}
              delay={900}
            />
            <DetailRow
              label="Total Cost"
              value={`${totalCost.toFixed(2)} mUSD`}
              icon="credit-card"
              themeColors={themeColors}
              delay={1000}
            />
          </SectionCard>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(600).delay(700)}>
          <SectionCard borderRadius="none" padding="xl">
            <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>Transaction Proof</Text>
            <Animated.View 
              entering={FadeInLeft.delay(1100).springify()}
              style={styles.txHashContainer}
            >
              <Feather name="shield" size={16} color={themeColors.textSecondary} />
              <Text style={[styles.txHashLabel, { color: themeColors.textSecondary }]}>TX Hash</Text>
              <TouchableOpacity style={styles.txHashValue}>
                <Text style={[styles.txHashText, { color: themeColors.textPrimary }]}>
                  {mockTxHash.slice(0, 10)}...{mockTxHash.slice(-8)}
                </Text>
                <Feather name="copy" size={14} color={themeColors.textTertiary} />
              </TouchableOpacity>
            </Animated.View>
          </SectionCard>
        </Animated.View>

        <Animated.View
          entering={FadeInUp.duration(600).delay(800)}
          style={styles.actionsSection}
        >
          <ActionButton variant="accent" fullWidth onPress={() => onNavigate('Activity')}>
            View in Activity
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
        <Animated.View entering={FadeInDown.duration(500).delay(100).springify()} style={styles.header}>
          <Text style={[styles.title, { color: themeColors.textPrimary }]}>
            Send mUSD
          </Text>
          <Text style={[styles.subtitle, { color: themeColors.textSecondary }]}>
            Transfer mUSD to any address
          </Text>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(500).delay(200).springify()}>
          <SectionCard borderRadius="none" padding="xl">
            <Text style={[styles.inputLabel, { color: themeColors.textPrimary }]}>
              Recipient Address
            </Text>
            <Input
              value={recipientAddress}
              onChangeText={setRecipientAddress}
              placeholder="0x..."
              error={touched.recipient ? errors.recipient : undefined}
              onBlur={() => setTouched(prev => ({ ...prev, recipient: true }))}
              style={styles.addressInput}
              variant="filled"
            />
            <View style={styles.balanceRow}>
              <Feather name="info" size={14} color={themeColors.textTertiary} />
              <Text style={[styles.helperText, { color: themeColors.textTertiary }]}>
                Enter a valid Ethereum address
              </Text>
            </View>
          </SectionCard>
        </Animated.View>

        <Animated.View entering={FadeInDown.duration(500).delay(300).springify()}>
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
                value={amount}
                onChangeText={handleAmountChange}
                placeholder="0.00"
                keyboardType="decimal-pad"
                error={touched.amount ? errors.amount : undefined}
                onBlur={() => setTouched(prev => ({ ...prev, amount: true }))}
                style={styles.largeInput}
                variant="filled"
                rightElement={
                  <Text style={[styles.inputUnit, { color: themeColors.textSecondary }]}>
                    mUSD
                  </Text>
                }
              />
            </View>

            <View style={styles.balanceRow}>
              <View style={styles.balanceItem}>
                <Feather name="briefcase" size={14} color={themeColors.textSecondary} />
                <Text style={[styles.balanceLabel, { color: themeColors.textSecondary }]}>
                  Balance: {walletBalance.toLocaleString()} mUSD
                </Text>
              </View>
            </View>
          </SectionCard>
        </Animated.View>

        {amountValue > 0 && isValid && (
          <Animated.View entering={FadeInDown.duration(500).delay(400).springify()}>
            <SectionCard borderRadius="none" padding="xl">
              <Text style={[styles.sectionTitle, { color: themeColors.textPrimary }]}>Transaction Summary</Text>
              <FeeRow
                label="Send Amount"
                value={`${amountValue.toFixed(2)} mUSD`}
                icon="arrow-up"
                themeColors={themeColors}
                delay={500}
              />
              <FeeRow
                label="Network Fee"
                value={`${networkFee.toFixed(3)} mUSD`}
                icon="zap"
                themeColors={themeColors}
                delay={600}
              />
              <View style={[styles.feeDivider, { backgroundColor: themeColors.border }]} />
              <FeeRow
                label="Total Cost"
                value={`${totalCost.toFixed(2)} mUSD`}
                icon="credit-card"
                bold
                themeColors={themeColors}
                delay={700}
              />
            </SectionCard>
          </Animated.View>
        )}

        <Animated.View
          entering={FadeInUp.duration(500).delay(500)}
          style={styles.actionsSection}
        >
          <ActionButton
            variant="accent"
            fullWidth
            disabled={!isValid}
            loading={isLoading}
            onPress={handleConfirm}
          >
            {isLoading ? 'Sending...' : 'Confirm Send'}
          </ActionButton>
          <ActionButton variant="secondary" fullWidth onPress={() => onNavigate('Home')}>
            Cancel
          </ActionButton>
        </Animated.View>

        <View style={styles.bottomSpacer} />
      </ScrollView>
    </KeyboardAvoidingView>
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

// Fee Row Component
interface FeeRowProps {
  label: string;
  value: string;
  icon?: string;
  bold?: boolean;
  themeColors: ReturnType<typeof useTheme>['colors'];
  delay?: number;
}

const FeeRow = React.memo<FeeRowProps>(({ label, value, icon, bold, themeColors, delay = 0 }) => (
  <Animated.View 
    entering={FadeInLeft.delay(delay).springify().damping(14)}
    style={styles.feeRow}
  >
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
  </Animated.View>
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
    marginBottom: Spacing.sm,
  },
  maxButton: {
    borderWidth: Borders.width.regular,
    paddingVertical: Spacing.xxs,
    paddingHorizontal: Spacing.sm,
  },
  maxButtonText: {
    ...Typography.label,
  },
  addressInput: {
    ...Typography.body,
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
    alignItems: 'center',
    gap: Spacing.xxs,
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
  helperText: {
    ...Typography.caption,
  },
  sectionTitle: {
    ...Typography.labelMedium,
    marginBottom: Spacing.md,
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
    borderWidth: Borders.width.bold,
    borderColor: Colors.semantic.success,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: Spacing.xxl,
  },
  successTitle: {
    ...Typography.h1,
    marginBottom: Spacing.sm,
  },
  successSubtitle: {
    ...Typography.body,
    textAlign: 'center',
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
  txHashContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
    paddingVertical: Spacing.sm,
  },
  txHashLabel: {
    ...Typography.bodySmall,
  },
  txHashValue: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
    flex: 1,
    justifyContent: 'flex-end',
  },
  txHashText: {
    ...Typography.mono,
  },
});
