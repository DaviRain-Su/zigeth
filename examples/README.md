# 📚 Zigeth Examples

This directory contains comprehensive examples demonstrating the most common Ethereum operations using the zigeth library.

## 📋 Examples Overview

| Example | File | Description | Difficulty |
|---------|------|-------------|------------|
| **1** | `01_wallet_creation.zig` | Wallet creation and management | ⭐ Beginner |
| **2** | `02_query_blockchain.zig` | Querying blockchain data | ⭐ Beginner |
| **3** | `03_send_transaction.zig` | Sending transactions | ⭐⭐ Intermediate |
| **4** | `04_smart_contracts.zig` | Smart contract interaction | ⭐⭐ Intermediate |
| **5** | `05_transaction_receipts.zig` | Transaction receipts and status | ⭐⭐ Intermediate |
| **6** | `06_event_monitoring.zig` | Event monitoring and subscriptions | ⭐⭐⭐ Advanced |
| **7** | `07_complete_workflow.zig` | Complete end-to-end workflow | ⭐⭐⭐ Advanced |
| **8** | `08_account_abstraction.zig` | ERC-4337 Account Abstraction (AA) | ⭐⭐⭐ Advanced |
| **9** | `09_etherspot_userop.zig` | Etherspot UserOperation with v0.7 | ⭐⭐⭐ Advanced |

## 🚀 Running Examples

### Prerequisites

1. **Install Zig 0.14.1 or later**
   ```bash
   # Download from https://ziglang.org/download/
   ```

2. **Clone the zigeth repository**
   ```bash
   git clone https://github.com/ch4r10t33r/zigeth.git
   cd zigeth
   ```

3. **Build the library**
   ```bash
   zig build
   ```

### Running an Example

To run any example:

```bash
# Run directly
zig run examples/01_wallet_creation.zig --dep zigeth -Mzigeth=src/root.zig --dep secp256k1 -Msecp256k1=<path> -lc

# Or compile first
zig build-exe examples/01_wallet_creation.zig --dep zigeth -Mzigeth=src/root.zig -lc
./01_wallet_creation
```

### Using build.zig (Recommended)

Add to your `build.zig`:

```zig
// Add example builds
const examples = [_][]const u8{
    "01_wallet_creation",
    "02_query_blockchain",
    "03_send_transaction",
    "04_smart_contracts",
    "05_transaction_receipts",
    "06_event_monitoring",
    "07_complete_workflow",
};

for (examples) |example_name| {
    const example = b.addExecutable(.{
        .name = example_name,
        .root_source_file = b.path(b.fmt("examples/{s}.zig", .{example_name})),
        .target = target,
        .optimize = optimize,
    });
    
    example.root_module.addImport("zigeth", zigeth_mod);
    example.linkLibC();
    
    const run_example = b.addRunArtifact(example);
    const run_step = b.step(
        b.fmt("example-{s}", .{example_name}),
        b.fmt("Run example: {s}", .{example_name})
    );
    run_step.dependOn(&run_example.step);
}
```

Then run:
```bash
zig build example-01_wallet_creation
zig build example-02_query_blockchain
# etc.
```

## 📖 Example Descriptions

### 1. Wallet Creation (`01_wallet_creation.zig`)

Learn how to:
- Generate new random wallets
- Import wallets from private keys
- Export private keys securely
- Use mnemonic phrases (BIP-39)
- Create HD wallets (BIP-32/BIP-44)
- Encrypt wallets with keystores
- Sign messages

**Topics covered**: Wallet, HDWallet, Mnemonic, Keystore, Private keys

**Use cases**: Wallet apps, key management, account generation

### 2. Query Blockchain (`02_query_blockchain.zig`)

Learn how to:
- Connect to Ethereum networks
- Query account balances
- Get current block number
- Retrieve block details
- Check gas prices
- Get transaction counts (nonces)
- Detect contract addresses
- Query multiple chains

**Topics covered**: Providers, RPC, Blocks, Balances, Multi-chain

**Use cases**: Block explorers, analytics, monitoring

### 3. Send Transaction (`03_send_transaction.zig`)

Learn how to:
- Create transactions (Legacy, EIP-1559)
- Sign transactions with EIP-155
- Use middleware for automation
- Estimate gas limits
- Set optimal gas prices
- Manage nonces
- Send transactions to network

**Topics covered**: Transactions, Middleware, Signing, Gas, Nonces

**Use cases**: Wallets, DeFi apps, transaction builders

### 4. Smart Contracts (`04_smart_contracts.zig`)

Learn how to:
- Interact with ERC-20 tokens
- Encode function calls
- Use ABI encoding/decoding
- Parse event signatures
- Deploy contracts
- Use pre-defined selectors

**Topics covered**: ABI, Contracts, Events, ERC standards

**Use cases**: DeFi, NFTs, Token interactions

### 5. Transaction Receipts (`05_transaction_receipts.zig`)

Learn how to:
- Get transaction receipts
- Check transaction status
- Calculate transaction fees
- Wait for confirmations
- Parse event logs
- Handle contract creation
- Understand bloom filters

**Topics covered**: Receipts, Logs, Status, Fees

**Use cases**: Transaction tracking, confirmation monitoring

### 6. Event Monitoring (`06_event_monitoring.zig`)

Learn how to:
- Use WebSocket subscriptions
- Subscribe to new blocks
- Monitor pending transactions
- Filter contract events
- Parse ERC-20 Transfer events
- Query historical logs
- Unsubscribe from events

**Topics covered**: WebSocket, Subscriptions, Events, Filters

**Use cases**: Real-time monitoring, event indexing, notifications

### 7. Complete Workflow (`07_complete_workflow.zig`)

Learn how to:
- Execute a complete transaction flow
- Use all components together
- Follow best practices
- Handle the full lifecycle

**Topics covered**: Everything (end-to-end)

**Use cases**: Complete applications, learning the full API

### 8. Account Abstraction (`08_account_abstraction.zig`)

Learn how to:
- Work with ERC-4337 Account Abstraction
- Use all three EntryPoint versions (v0.6, v0.7, v0.8)
- Create UserOperations for different versions
- Validate and size UserOperations
- Use gas estimators and paymaster modes
- Initialize account factories
- Understand gas overhead constants

**Topics covered**: 
- EntryPoint versions (v0.6, v0.7, v0.8) and addresses
- UserOperation creation and validation
- Multi-version support via compile-time polymorphism
- Gas estimation (local mode)
- Paymaster modes (SPONSOR and ERC20)
- Account factory initialization
- Size comparison (v0.6 vs v0.7 - gas optimization)

**Use cases**: 
- Quick validation of AA library functionality
- Learning EntryPoint versions and differences
- Understanding UserOperation structure
- Testing gas estimation
- Exploring paymaster integration
- Smart contract wallet development
- DeFi applications with Account Abstraction

**Key Features Demonstrated**:
- ✅ All 3 EntryPoint versions
- ✅ Multi-version UserOperation support
- ✅ Compile-time type validation
- ✅ Gas overhead constants
- ✅ Paymaster modes
- ✅ Account factory pattern
- ✅ Size optimization (v0.7: 148 bytes vs v0.6: 212 bytes)

### 9. Etherspot UserOperation (`09_etherspot_userop.zig`)

Learn how to:
- Use Etherspot's Modular Smart Account Factory
- Create a UserOperation for EntryPoint v0.7
- Integrate with Etherspot Arka Paymaster
- Submit to Etherspot Skandha Bundler
- Build complete sponsored transaction workflow
- Calculate CREATE2 addresses
- Encode transactions and sign UserOperations
- Poll for transaction receipts

**Topics covered**: 
- Etherspot infrastructure (Factory, Arka, Skandha)
- EntryPoint v0.7 integration
- Modular Smart Account deployment
- Paymaster sponsorship (gasless transactions)
- UserOperation creation and signing
- JSON-RPC communication
- Complete end-to-end workflow

**Use cases**: 
- Building dApps with Etherspot infrastructure
- Sponsored transactions (no gas fees for users)
- Smart contract wallet integration
- Production AA implementations
- Multi-chain deployment (Etherspot supports many networks)
- Enterprise-grade AA solutions

**Key Features Demonstrated**:
- ✅ Etherspot Modular Smart Account Factory
- ✅ EntryPoint v0.7 (gas-optimized)
- ✅ Arka Paymaster integration (pm_sponsorUserOperation)
- ✅ Skandha Bundler submission (eth_sendUserOperation)
- ✅ CREATE2 deterministic addresses
- ✅ Complete UserOp lifecycle
- ✅ JSON serialization for RPC
- ✅ Production-ready workflow

**Configuration**:
- **Network**: Sepolia Testnet (Chain ID: 11155111)
- **EntryPoint v0.7**: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- **Factory**: `0x7f6d8F107fE8551160BD5351d5F1514320aB6E50` (Etherspot Modular)
- **Paymaster**: `0x00000000000De1aaB9389285965F49D387000000` (Arka)
- **Bundler RPC**: `https://sepolia-bundler.etherspot.io/v2` (Skandha)
- **Paymaster RPC**: `https://arka.etherspot.io` (Arka API)

## 🎯 Common Patterns

### Pattern 1: Simple Address Creation

```zig
// Easy way: Use hex string literals!
const address = try zigeth.primitives.Address.fromHex(
    allocator,
    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
);

// For smart contracts too:
const usdc = try zigeth.primitives.Address.fromHex(
    allocator,
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
);
```

### Pattern 2: Simple Balance Check

```zig
var provider = try zigeth.providers.Networks.mainnet(allocator);
defer provider.deinit();

const address = try zigeth.primitives.Address.fromHex(allocator, "0x...");
const balance = try provider.getBalance(address);
const eth = try zigeth.utils.units.weiToEther(balance);
std.debug.print("Balance: {d} ETH\n", .{eth});
```

### Pattern 3: Send ETH Transfer

```zig
// Setup
var provider = try zigeth.providers.Networks.sepolia(allocator);
var signer = try zigeth.middleware.SignerMiddleware.init(allocator, private_key, config);

// Create transaction
var tx = zigeth.types.Transaction.newEip1559(allocator);
tx.from = from_address;
tx.to = try zigeth.primitives.Address.fromHex(allocator, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");
tx.value = zigeth.primitives.U256.fromInt(100_000_000_000_000_000); // 0.1 ETH
tx.nonce = try provider.getTransactionCount(from_address);
tx.gas_limit = 21000;

// Sign and send
const raw_tx = try signer.signAndSerialize(&tx);
const tx_hash = try provider.sendRawTransaction(raw_tx);

// Wait for confirmation
const receipt = try provider.waitForTransaction(tx_hash, 60000);
```

### Pattern 4: Read ERC-20 Balance

```zig
const balance_of = zigeth.abi.Function{
    .name = "balanceOf",
    .inputs = &[_]zigeth.abi.Parameter{
        .{ .name = "account", .type = address_type, .indexed = false },
    },
    .outputs = &[_]zigeth.abi.Parameter{
        .{ .name = "balance", .type = uint256_type, .indexed = false },
    },
    .state_mutability = .view,
};

const call_data = try zigeth.abi.encodeFunctionCall(allocator, balance_of, &params);
// Use provider.eth.call() to execute
```

### Pattern 5: Account Abstraction - Sponsored Transaction

```zig
const aa = zigeth.account_abstraction;

// 1. Setup
const entry_point = try aa.EntryPoint.v07(allocator, &rpc_client);
var smart_account = aa.SmartAccount.init(
    allocator,
    account_address,
    entry_point.address,
    .v0_7,
    owner_address,
    &rpc_client,
    &factory,
    0, // salt
);

// 2. Create transaction
const call_data = try smart_account.encodeExecute(
    recipient_address,
    value, // Amount in wei
    &[_]u8{}, // Additional data if needed
);
defer allocator.free(call_data);

// 3. Estimate gas
var gas_estimator = aa.GasEstimator.init(allocator, null, &rpc_client);
const test_op = aa.UserOpUtils.zero(aa.types.UserOperationV07);
const gas_estimates = try gas_estimator.estimateGas(test_op);

// 4. Create UserOperation
const user_op_any = try smart_account.createUserOperation(call_data, gas_estimates);
var user_op = user_op_any.v07;

// 5. Get paymaster sponsorship (FREE for user!)
var paymaster = aa.PaymasterClient.init(allocator, paymaster_url, api_key);
defer paymaster.deinit();
try paymaster.sponsorUserOperation(&user_op, entry_point.address, .sponsor);

// 6. Sign
const signature = try smart_account.signUserOperation(user_op, private_key);
defer allocator.free(signature);
user_op.signature = signature;

// 7. Send to bundler
var bundler = aa.BundlerClient.init(allocator, bundler_url, entry_point.address);
defer bundler.deinit();
const user_op_hash = try bundler.sendUserOperation(user_op);

// 8. Wait for execution
const receipt = try bundler.getUserOperationReceipt(user_op_hash);
std.debug.print("Success: {}\n", .{receipt.?.success});
```

### Pattern 6: Account Abstraction - Batch Transactions

```zig
// Execute multiple calls atomically
const batch_calls = [_]aa.Call{
    .{
        .to = usdc_address,
        .value = 0,
        .data = try encodeApprove(spender, amount), // Approve USDC
    },
    .{
        .to = dex_address,
        .value = 0,
        .data = try encodeSwap(usdc_address, eth_address, amount), // Swap on DEX
    },
};

const call_data = try smart_account.encodeExecuteBatch(&batch_calls);
defer allocator.free(call_data);

// Create UserOperation and send (same as Pattern 5)
// If one call fails, entire batch reverts (atomic)
```

## ⚠️ Important Notes

### Testnet Usage

All examples that send transactions should use **testnet networks**:

- **Sepolia**: `zigeth.providers.Networks.sepolia(allocator)`
- Get free testnet ETH from faucets:
  - https://sepoliafaucet.com/
  - https://www.alchemy.com/faucets/ethereum-sepolia

### Private Keys

**Never use real private keys in examples or test code!**

- Use test mnemonics like: `"test test test test test test test test test test test junk"`
- Generate new wallets for testing
- Use testnet networks only

### API Keys

The examples use Etherspot's public API key. For production:

1. Get your own API key from [Etherspot](https://etherspot.io/)
2. Replace in the RPC URLs
3. Consider rate limits and usage quotas

## 🔧 Troubleshooting

### Example won't compile

```bash
# Make sure you're in the zigeth directory
cd zigeth

# Clean build cache
rm -rf zig-cache zig-out .zig-cache

# Rebuild
zig build
```

### Import errors

Make sure you're using the correct module imports:

```zig
const zigeth = @import("zigeth");

// Then access modules:
zigeth.primitives.Address
zigeth.providers.Networks
zigeth.signer.Wallet
// etc.
```

### Network connection errors

- Check your internet connection
- Verify the RPC endpoint is accessible
- Check for rate limiting
- Try a different network/provider

## 📚 Learning Path

**Recommended order for learning:**

1. Start with `01_wallet_creation.zig` - Understand key management
2. Move to `02_query_blockchain.zig` - Learn data queries
3. Try `03_send_transaction.zig` - Send your first transaction
4. Explore `04_smart_contracts.zig` - Interact with contracts
5. Study `05_transaction_receipts.zig` - Understand receipts
6. Experiment with `06_event_monitoring.zig` - Real-time events
7. Master `07_complete_workflow.zig` - Put it all together
8. **Advanced**: `08_account_abstraction.zig` - ERC-4337 and smart accounts
9. **Production**: `09_etherspot_userop.zig` - Real-world AA with Etherspot

**Alternative path for Account Abstraction developers:**

1. `01_wallet_creation.zig` - Understand EOA (Externally Owned Accounts)
2. `02_query_blockchain.zig` - Learn blockchain queries
3. `08_account_abstraction.zig` - Learn AA fundamentals
4. `09_etherspot_userop.zig` - Production AA with Etherspot infrastructure
5. `04_smart_contracts.zig` - Understand contract interactions (AA uses these!)
6. `07_complete_workflow.zig` - Traditional workflow comparison

**Fast track for Etherspot developers:**

1. `08_account_abstraction.zig` - Understand ERC-4337 basics
2. `09_etherspot_userop.zig` - Complete Etherspot integration
3. Start building your sponsored dApp!

## 🌐 Multi-Chain Support

All examples can be adapted for different networks:

```zig
// Ethereum
var provider = try zigeth.providers.Networks.mainnet(allocator);

// Polygon
var provider = try zigeth.providers.Networks.polygon(allocator);

// Arbitrum  
var provider = try zigeth.providers.Networks.arbitrum(allocator);

// Optimism
var provider = try zigeth.providers.Networks.optimism(allocator);

// Base
var provider = try zigeth.providers.Networks.base(allocator);

// Sepolia (testnet)
var provider = try zigeth.providers.Networks.sepolia(allocator);

// Local development
var provider = try zigeth.providers.Networks.localhost(allocator);

// Custom RPC
var provider = try zigeth.providers.Networks.custom(allocator, "https://your-rpc-url");
```

## 🤝 Contributing Examples

Have a useful example? Contributions are welcome!

1. Create a new example file: `XX_your_example.zig`
2. Follow the existing format:
   - Clear comments explaining what it does
   - Step-by-step code with output
   - Error handling
   - Resource cleanup
3. Update this README with your example
4. Submit a pull request!

## 💡 Tips

- **Start simple**: Begin with wallet creation and queries
- **Use testnets**: Always test on Sepolia first
- **Check balances**: Ensure sufficient funds before sending
- **Handle errors**: Use `try` and `catch` appropriately
- **Clean up**: Always use `defer` for resource cleanup
- **Read receipts**: Always verify transaction success
- **Monitor gas**: Use middleware for optimal gas prices

## 🔗 Additional Resources

### General Ethereum Development
- [Zigeth Documentation](../README.md)
- [Zig Language](https://ziglang.org/learn/)
- [Ethereum Documentation](https://ethereum.org/en/developers/)
- [Etherspot RPC](https://etherspot.io/)
- [EIP Specifications](https://eips.ethereum.org/)

### Account Abstraction (ERC-4337)
- [EIP-4337 Specification](https://eips.ethereum.org/EIPS/eip-4337) - Official ERC-4337 standard
- [Account Abstraction README](../src/account_abstraction/README.md) - Zigeth AA package documentation
- [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) - Reference Solidity contracts
- [Viem Account Abstraction](https://viem.sh/account-abstraction) - TypeScript reference
- [Etherspot Skandha](https://github.com/etherspot/skandha) - Open-source bundler
- [Etherspot Arka](https://github.com/etherspot/arka) - Open-source paymaster
- [ERC-4337 Resources](https://www.erc4337.io/) - Community resources

## 📞 Support

- **Issues**: https://github.com/ch4r10t33r/zigeth/issues
- **Discussions**: https://github.com/ch4r10t33r/zigeth/discussions
- **Documentation**: https://github.com/ch4r10t33r/zigeth#readme

---

Happy coding with zigeth! 🚀

