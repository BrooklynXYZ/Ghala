# Ghala - Non-Custodial BTC-Backed DeFi Yield Platform

> **Unlock Your Bitcoin's Earning Potential Without Selling**

Ghala is the first fully non-custodial platform that enables Bitcoin holders to access Solana DeFi yields without wrapping, selling, or giving up control of their Bitcoin. By leveraging Mezo's native BTC-backed stablecoin (mUSD), Internet Computer's chain fusion technology, and Solana's high-performance DeFi ecosystem, Ghala creates a trustless bridge between Bitcoin's security and DeFi's yield opportunities.

---

## 🎯 The Problem We're Solving

**Bitcoin holders are locked out of DeFi yield opportunities.**

Bitcoin is the most trusted and secure cryptocurrency, holding over $1 trillion in value. However, Bitcoin holders face a fundamental dilemma: their BTC sits idle, generating no yield, while DeFi protocols on other chains offer attractive returns of 5-20% APY.

### Why Current Solutions Fall Short

If you want to earn yield on your Bitcoin today, you're forced to:

1. **Trust Centralized Bridges**
   - Give up custody of your BTC to centralized operators
   - Risk loss from hacks, exploits, or operator misconduct
   - Examples: Wrapped BTC (wBTC) requires BitGo as custodian

2. **Wrap Your Bitcoin**
   - Convert BTC to synthetic tokens on other chains (wBTC, renBTC, tBTC)
   - Pay high fees for bridging (often 0.25-1% per transaction)
   - Accept counterparty risk from the wrapping protocol

3. **Navigate Complex Multi-Step Processes**
   - Manually bridge to Ethereum/other chains
   - Manually interact with DeFi protocols
   - Track positions across multiple wallets and chains
   - High technical barrier for average users

4. **Accept High Costs and Risks**
   - Bridge fees, gas fees, smart contract risks
   - Liquidation risks from complex lending protocols
   - Potential loss of funds during multi-step processes

**The market desperately needs a solution that lets Bitcoin holders keep their BTC while earning DeFi yields - without compromise.**

---

## 💡 Our Solution: The Ghala Bridge

Ghala solves this problem by creating the first **truly non-custodial** bridge from Bitcoin to Solana DeFi, powered by three innovative technologies working together:

### The Three-Layer Architecture

**Layer 1: Mezo Network (Bitcoin L2)**
- Mezo is a Bitcoin Layer 2 that speaks Bitcoin's language natively
- Users deposit their BTC as collateral on Mezo (staying within the Bitcoin ecosystem)
- Mint mUSD, a stablecoin backed by their BTC, at a fixed low interest rate (~1% APR)
- No wrapping, no conversion - just using Bitcoin as productive collateral

**Layer 2: Internet Computer Protocol (ICP Bridge)**
- ICP acts as the trustless bridge operator between chains
- Uses "chain fusion" technology to directly interact with Bitcoin, Mezo, and Solana
- No centralized operators, no multisig committees, no trusted third parties
- Runs smart contracts (canisters) that orchestrate the entire bridge flow automatically

**Layer 3: Solana DeFi Ecosystem**
- High-performance blockchain with sub-second finality
- Rich ecosystem of yield-generating protocols
- Low transaction fees (fractions of a cent)
- Perfect for deploying stablecoins into productive yield strategies

### How Users Experience Ghala

From a user's perspective, Ghala is beautifully simple:

1. **Open the mobile app** and connect your Bitcoin wallet
2. **Deposit your BTC** to a secure address on Mezo Network
3. **Mint mUSD** - the app automatically mints mUSD stablecoin against your BTC collateral
4. **Bridge to Solana** - one tap bridges your mUSD to Solana
5. **Deploy to yield** - choose a yield strategy and start earning
6. **Track everything** - see your positions, yields, and activity in one clean dashboard

That's it. No technical knowledge required. No manual bridging. No custody risk.

### The Complete Flow (Behind the Scenes)

When a user wants to earn yield on their Bitcoin, here's what happens:

**Step 1: Collateral Deposit**
- User sends BTC to Mezo Network (Bitcoin L2)
- BTC is locked in Mezo's borrowing protocol
- User maintains ownership - they can withdraw anytime by repaying their loan

**Step 2: Stablecoin Minting**
- User mints mUSD against their BTC collateral
- mUSD is a stablecoin pegged 1:1 to USD
- Over-collateralized (users must maintain healthy collateral ratios)
- Fixed ~1% annual interest rate (far cheaper than most lending protocols)

**Step 3: Bridge Initiation**
- User requests to bridge mUSD to Solana
- ICP Bridge Orchestrator canister receives the request
- Verifies user's position and mUSD balance

**Step 4: Cross-Chain Coordination**
- Bridge canister communicates with Mezo Network via HTTPS
- Verifies the mUSD mint and locks it for bridging
- Coordinates with Solana canister to prepare destination

**Step 5: Solana Delivery**
- Solana canister mints wrapped mUSD on Solana
- Delivers directly to user's Solana wallet
- User now has mUSD on Solana, ready for DeFi

**Step 6: Yield Deployment**
- User selects a yield strategy
- mUSD is deployed into Solana DeFi protocols
- User earns yield while their BTC remains safely collateralized on Mezo

**Step 7: Exit Strategy**
- User can withdraw from yield protocols anytime
- Bridge mUSD back from Solana to Mezo
- Repay mUSD loan and unlock their original BTC
- Full circle, fully non-custodial

---

## 🌟 What Makes Ghala Unique

### 1. True Non-Custodial Design

**Other Bridges**: Require you to send BTC to a centralized custodian or multisig wallet.

**Ghala**: Your BTC never leaves your control. It stays in Mezo's smart contracts, which you control. You can always reclaim your BTC by repaying your mUSD loan - no permission needed from any centralized entity.

### 2. Native Bitcoin Integration

**Other Solutions**: Wrap your Bitcoin into synthetic tokens (wBTC, renBTC) that trade on other chains.

**Ghala**: Uses Mezo's native BTC collateral system. Your real Bitcoin stays in the Bitcoin ecosystem (via Mezo L2), backing your mUSD 1:1. No wrapping, no synthetic derivatives.

### 3. Trustless Bridge Technology

**Other Bridges**: Operated by centralized companies, multisig committees, or validator networks that can be compromised.

**Ghala**: Uses Internet Computer's chain fusion technology. ICP canisters (smart contracts) are completely autonomous, tamper-proof, and run without any centralized operators. They directly interact with Bitcoin, Mezo, and Solana through decentralized consensus.

### 4. Seamless User Experience

**Other Solutions**: Require technical expertise, multiple wallets, manual bridging, and complex DeFi interactions.

**Ghala**: Mobile-first design with one-tap operations. Everything automated behind the scenes. Users just see: Deposit → Mint → Bridge → Earn. Simple.

### 5. Low Fixed Interest Rate

**Other Lending Protocols**: Variable interest rates that can spike to 10-30% during market stress.

**Ghala**: Fixed ~1% APR on mUSD minting. Predictable costs. Users keep most of their earned yield.

### 6. Bitcoin → Solana Pathway

**Most DeFi**: Concentrated on Ethereum, with high gas fees ($20-100 per transaction).

**Ghala**: Bridges to Solana, where transactions cost less than $0.01. Enables micro-yield strategies and frequent rebalancing without fee concerns.

### 7. Automated Position Management

**Traditional DeFi**: Users must manually monitor collateral ratios, rebalance positions, claim rewards, and manage liquidation risks.

**Ghala** (Roadmap): Intelligent automation that monitors positions, alerts users to risks, and can auto-rebalance to maintain healthy collateralization.

---

## 🏗️ Technical Architecture

Ghala is built on four major components that work together seamlessly:

### 1. Mobile Application

**Technology**: React Native with Expo for cross-platform iOS and Android support.

**What It Does**:
- Provides the user interface for all operations
- Integrates with multiple blockchain wallets (WalletConnect for Bitcoin/Ethereum, Phantom/Solflare for Solana)
- Implements biometric authentication for security
- Displays real-time positions across all chains
- Manages transaction lifecycle and status updates

**Key Features**:
- **Mint Screen**: Deposit BTC and mint mUSD
- **Bridge Screen**: Transfer mUSD from Mezo to Solana
- **Pool Screen**: Browse and select yield strategies
- **Activity Screen**: Track all transactions and history
- **Profile Screen**: Manage wallet connections and settings

**Why Mobile-First**: Most crypto users access DeFi through mobile devices. Desktop-only solutions create barriers. Ghala brings institutional-grade DeFi to your pocket.

### 2. Backend API Server

**Technology**: Node.js with TypeScript and Express framework.

**What It Does**:
- Acts as the gateway to Mezo Network
- Manages user authentication and sessions
- Executes smart contract calls to Mezo's mUSD protocol
- Calculates collateral ratios and maximum mintable amounts
- Tracks user loan positions and health factors
- Provides price oracle data (BTC/USD pricing)

**Why It's Needed**: Mezo Network uses Ethereum-compatible RPC endpoints. The backend abstracts this complexity, providing simple REST APIs to the mobile app. It also handles authentication and security middleware to protect user operations.

### 3. ICP Bridge Canisters

**Technology**: Rust-based smart contracts (canisters) running on Internet Computer Protocol.

**What They Do**:

**BTC Handler Canister**:
- Generates Bitcoin addresses for each user
- Monitors Bitcoin testnet for deposits
- Tracks transaction confirmations
- Manages UTXO (Bitcoin's transaction model)
- Handles Bitcoin address derivation using chain fusion technology
- **Correct Architecture**: Uses ICP's Bitcoin Canister API (testnet4 canister `g4xu7-jiaaa-aaaan-aaaaq-cai`) for reliable UTXO queries and pays required cycles for API calls.

**Bridge Orchestrator Canister**:
- Coordinates the entire bridge flow
- Communicates with Mezo Network via HTTPS outcalls
- Tracks user positions (BTC deposited, mUSD minted, assets bridged)
- Enforces the closed-loop architecture (only internally-minted mUSD can be bridged)
- Calculates loan-to-value ratios and liquidation risks
- Provides bridge statistics and monitoring

**Solana Handler Canister**:
- Generates Solana addresses for users
- Creates and signs Solana transactions
- Handles SPL token operations (Solana's token standard)
- Mints wrapped mUSD on Solana
- Delivers assets to user wallets
- Monitors transaction finality on Solana

**Why ICP**: Internet Computer is the only blockchain that can natively interact with Bitcoin, make HTTPS calls to external APIs (like Mezo), and sign transactions on other chains (like Solana) - all in a completely decentralized manner. This eliminates the need for centralized bridge operators.

**Closed-Loop Security Architecture**:

The Bridge Orchestrator implements a critical security feature: only mUSD that was minted through Ghala's deposit flow can be bridged to Solana. This means:

- ✅ BTC deposited through Ghala → mUSD minted → Can be bridged to Solana
- ❌ mUSD minted externally → Cannot be bridged through Ghala

**Why this matters**: This design ensures that every mUSD bridged through Ghala has verified BTC collateral backing it. It prevents exploitation, maintains accurate accounting of collateralization ratios, and provides complete auditability. Users can trust that the system is solvent and secure.

### 4. mUSD Protocol Contracts

**Technology**: Solidity smart contracts deployed on Mezo Network.

**What They Do**:
- Implement the mUSD stablecoin (ERC20 token)
- Manage collateral deposits and withdrawals
- Handle minting and burning of mUSD
- Track individual debt positions (called "Troves")
- Implement liquidation mechanisms for undercollateralized positions
- Manage a stability pool for system solvency
- Integrate with price oracles for accurate BTC/USD pricing

**Why Mezo**: Mezo is a Bitcoin Layer 2 that allows smart contracts while maintaining native Bitcoin compatibility. Users can deposit BTC without wrapping or leaving the Bitcoin security model.

### 5. Bridge Event Listener

**Technology**: TypeScript service running continuously.

**What It Does**:
- Listens for bridge events on Mezo Network
- Detects when mUSD is locked for bridging
- Automatically mints equivalent wrapped mUSD on Solana
- Handles decimal conversions (Mezo uses 18 decimals, Solana uses 6)
- Ensures 1:1 peg between Mezo mUSD and Solana wrapped mUSD

**Why It's Needed**: This service acts as the relay between Mezo and Solana, ensuring that when mUSD is locked on Mezo, the equivalent amount appears on Solana. It maintains the bridge's integrity and liquidity on both sides.

---

## ⚠️ Known Issues & Troubleshooting

### Bitcoin Testnet Reliability
The Bitcoin Testnet canister on ICP (`g4xu7-jiaaa-aaaan-aaaaq-cai`) is currently undergoing maintenance and can be unreliable, occasionally returning empty UTXOs for valid transactions. This is a known infrastructure issue on the testnet environment.

**Status**: The Ghala codebase implements the correct architecture:
1. **Correct API**: Uses `bitcoin_canister` API instead of deprecated management API.
2. **Correct Canister ID**: Targets Bitcoin Testnet4 (`g4xu7-jiaaa-aaaan-aaaaq-cai`).
3. **Cycles Payment**: Attaches 10B cycles per call (exceeding the required minimums).

If you encounter empty UTXOs despite confirmed transactions, this is an external infrastructure issue, not a codebase error. The workaround for reliable operation is to deploy on Mainnet.

---

## 🚀 Installation and Running the Project

### Prerequisites

You'll need the following installed on your system:

**Core Requirements**:
- Node.js version 20 or higher (JavaScript runtime)
- Rust version 1.70 or higher (for ICP canisters)
- dfx CLI (Internet Computer SDK for deploying canisters)

**Optional**:
- Solana CLI (if testing Solana integration directly)
- Android Studio or Xcode (for running mobile app on devices)

### Setting Up the Mobile Application

1. Navigate to the Mobile directory
2. Install all dependencies using npm
3. For iOS: Run the iOS simulator command
4. For Android: Run the Android emulator command

The mobile app will launch on your device/emulator and connect to the configured backend and canisters.

### Setting Up the Backend API

1. Navigate to the backend directory
2. Install dependencies with npm
3. Copy the example environment file and configure:
   - Mezo RPC endpoint
   - mUSD contract addresses
   - API keys and secrets
4. Start the development server

The API will run locally and be ready to accept requests from the mobile app.

### Setting Up ICP Canisters

**For Local Development**:
1. Navigate to the icp_bridge directory
2. Ensure Rust toolchain includes WebAssembly target
3. Start the local Internet Computer replica
4. Deploy all three canisters (BTC Handler, Bridge Orchestrator, Solana Handler)
5. Note the generated canister IDs and update mobile app configuration

**For Production (Internet Computer Mainnet)**:
1. Ensure you have sufficient cycles (ICP's computation units)
2. Deploy using the mainnet network flag
3. Configure cross-canister references
4. Update mobile app with production canister IDs

**Important Note**: Bitcoin integration requires cycles to be attached to calls. Ensure your BTC Handler canister has sufficient cycles (recommended 1T+ cycles).

### Setting Up the Bridge Listener

1. Navigate to the bridge listener directory
2. Install dependencies
3. Configure the wrapped mUSD mint authority keypair
4. Start the listener service

The listener will continuously monitor Mezo for bridge events and handle Solana minting.

### Running Everything Together

**Complete Development Setup**:
1. Start backend API (runs on port 3000 by default)
2. Start ICP local replica (runs on port 4943)
3. Deploy canisters to local replica
4. Start bridge listener service
5. Update mobile app configuration with local endpoints
6. Launch mobile app

All components will communicate locally for development and testing.

**Production Deployment**:
- Deploy ICP canisters to mainnet
- Deploy backend to cloud hosting (AWS, Google Cloud, etc.)
- Configure production environment variables
- Build mobile app for production
- Distribute APK (Android) or through App Store (iOS)

---

## 🎯 Why This Project Matters

### The Broader Impact

**Unlocking Trillions in Idle Bitcoin**:
- Over $1 trillion in Bitcoin sits idle globally
- Most holders never touch DeFi due to complexity and risk
- Ghala could unlock even 1% of this capital into productive use
- That's $10+ billion in new DeFi liquidity

**Democratizing Access to Yield**:
- Currently, only sophisticated users access DeFi yields
- Ghala brings institutional-grade strategies to retail users
- Mobile-first design meets users where they are
- No technical knowledge required

**Proving Chain Fusion Technology**:
- First real-world application of ICP's chain fusion at scale
- Demonstrates trustless cross-chain communication
- Validates the vision of interconnected blockchain ecosystems
- Opens the door for more complex multi-chain applications

**Bridging Bitcoin and DeFi**:
- Bitcoin is the most trusted crypto but isolated from DeFi
- Solana has the best DeFi infrastructure but lacks BTC liquidity
- Ghala connects these ecosystems for mutual benefit
- Creates new possibilities for both communities

### The Use Cases

**Conservative Bitcoin Holders**:
- Want to earn yield but won't risk selling BTC
- Want exposure to DeFi without learning complex protocols
- Value security and simplicity over maximum yield

**DeFi Yield Farmers**:
- Have BTC but currently bridge it manually
- Waste time managing positions across multiple wallets
- Pay high fees for centralized bridges
- Want automated position management

**Institutional Players**:
- Need compliant, non-custodial solutions
- Require auditability and transparency
- Want exposure to DeFi without custody risk
- Looking for productive use of BTC treasury

**Emerging Market Users**:
- Hold Bitcoin as savings but have limited banking access
- Need to generate income from crypto holdings
- Mobile-first solution fits their usage patterns
- Low fees make small positions economically viable

---

## 🔮 Vision and Roadmap

### Near-Term Goals

**Resolve Technical Blockers**:
- Fix Bitcoin balance recognition issue
- Complete end-to-end testing on testnets
- Validate all components work together seamlessly
- Ensure system stability and reliability

**Launch Beta Program**:
- Invite limited users to test the full flow
- Gather feedback on UX and pain points
- Identify and fix edge cases
- Build confidence in system security

**Integrate Yield Strategies**:
- Select first set of Solana DeFi protocols
- Implement yield strategy smart routing
- Add portfolio analytics and performance tracking
- Enable users to compare and select strategies

### Medium-Term Goals

**Expand Protocol Integrations**:
- Add more Solana DeFi protocols
- Implement auto-compounding strategies
- Enable multi-protocol diversification
- Build proprietary yield optimization algorithms

**Enhance Automation**:
- Automated collateral monitoring
- Risk alerts and notifications
- Auto-rebalancing to maintain health ratios
- One-click emergency exit mechanisms

**Scale User Base**:
- Public launch of mobile app
- Marketing and user acquisition campaigns
- Educational content for Bitcoin holders
- Partnership with Bitcoin wallets and exchanges

### Long-Term Vision

**Multi-Chain Expansion**:
- Support multiple chains beyond Solana
- Enable yield strategies across Ethereum L2s, Cosmos, etc.
- Aggregate best yields regardless of chain
- Become the universal Bitcoin DeFi gateway

**Advanced Features**:
- Leverage strategies (use yield to mint more mUSD)
- Delta-neutral strategies (hedge BTC price risk)
- Social trading (follow top performers)
- DAO governance for protocol parameters

**Institutional Products**:
- White-label solutions for funds and institutions
- Compliance and reporting tools
- Custom yield strategies
- Treasury management features

---

## 🌐 Ecosystem and Technology

### Why These Technologies?

**Mezo Network (Bitcoin L2)**:
- Chosen because it's the only L2 with native BTC collateral
- No wrapping or synthetic tokens required
- Maintains Bitcoin security model
- Smart contract capabilities for mUSD protocol

**Internet Computer Protocol (Bridge)**:
- Only blockchain with native Bitcoin integration
- Can make HTTPS calls to any API (Mezo)
- Can sign transactions on other chains (Solana)
- Completely decentralized with no operators
- Tamper-proof canisters with formal verification

**Solana (Yield Destination)**:
- Fastest blockchain with sub-second finality
- Lowest transaction fees (< $0.01)
- Rich DeFi ecosystem with proven protocols
- Best infrastructure for frequent rebalancing

**React Native + Expo (Mobile App)**:
- Single codebase for iOS and Android
- Native performance and UX
- Rapid development and iteration
- Large ecosystem of libraries and tools

### The Technology Stack Summary

**Frontend**: React Native, Expo, TypeScript, React Navigation
**Backend**: Node.js, Express, TypeScript, Ethers.js
**Blockchain**: Rust (ICP canisters), Solidity (Mezo contracts)
**Infrastructure**: Internet Computer, Mezo Network, Bitcoin, Solana
**Security**: Biometric authentication, WalletConnect, closed-loop architecture

---

## 🤝 Contributing and Community

We're building Ghala in public and welcome contributions from developers, designers, and Bitcoin enthusiasts.

**Ways to Contribute**:
- Report bugs and issues you encounter
- Suggest features and improvements
- Contribute to documentation
- Share feedback on user experience
- Spread the word in Bitcoin and DeFi communities

**Future Plans**:
- Open source key components
- Launch developer documentation
- Create contribution guidelines
- Build an active community on Discord/Telegram

---


## 📄 License

MIT License - This project is open source and available for anyone to use, modify, and distribute.

---

## 🏆 Acknowledgments

Built with ❤️ for the ICP Hackathon, bringing together the best of Bitcoin security, Internet Computer innovation, and Solana DeFi performance.

---

**Ghala - Your Bitcoin, Now Earning**
