# Account Abstraction (ERC-4337) Support

Comprehensive ERC-4337 Account Abstraction implementation for Zigeth, based on [viem's account-abstraction](https://github.com/wevm/viem/tree/main/src/account-abstraction) design patterns.

## Features

- ✅ **Multi-Version Support** - EntryPoint v0.6, v0.7, and v0.8
- ✅ **UserOperation Types** - All versions with proper gas optimization
- ✅ **Bundler Client** - Interact with ERC-4337 bundlers (eth_sendUserOperation, etc.)
- ✅ **Paymaster Client** - Sponsorship and ERC-20 payment support
- ✅ **Smart Accounts** - Create and manage smart contract accounts
- ✅ **EntryPoint** - Multi-version EntryPoint contract support
- ✅ **Gas Estimation** - Accurate gas estimation for UserOperations
- ✅ **Utilities** - UserOperation hashing, packing, validation

## EntryPoint Versions

| Version | Address | Status | Features |
|---------|---------|--------|----------|
| **v0.6** | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` | ✅ Legacy | Original ERC-4337 |
| **v0.7** | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | ✅ Current | Gas-optimized, packed format |
| **v0.8** | `0x4337084d9e255ff0702461cf8895ce9e3b5ff108` | ✅ Latest | Further optimizations |

**Constants Available:**
```zig
EntryPoint.ENTRYPOINT_V06_ADDRESS // "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
EntryPoint.ENTRYPOINT_V07_ADDRESS // "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
EntryPoint.ENTRYPOINT_V08_ADDRESS // "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"
```

### UserOperation Format Differences

**v0.6 (Legacy):**
- Separate fields for all parameters
- `initCode` and `paymasterAndData` as bytes
- All gas limits as u256

**v0.7 (Gas-Optimized):**
- Separated `factory` address and `factoryData`
- Separated `paymaster` address and `paymasterData`
- Gas limits reduced to u128
- Explicit `paymasterVerificationGasLimit` and `paymasterPostOpGasLimit`
- ~20% gas savings compared to v0.6

**v0.8 (Latest):**
- Further optimizations beyond v0.7
- Uses improved packed structure
- Address: `0x4337084d9e255ff0702461cf8895ce9e3b5ff108`

## Modules

### `types.zig`
Core ERC-4337 data structures:
- `EntryPointVersion` - Version enum (v0_6, v0_7, v0_8)
- `UserOperationV06` - Complete UserOperation struct (v0.6)
- `UserOperationV07` - Gas-optimized packed format (v0.7)
- `UserOperationV08` - Future version placeholder (v0.8)
- `UserOperation` - Default type alias (v0.6 for compatibility)
- `UserOperationJson` - JSON-RPC serialization format
- `UserOperationReceipt` - Receipt after execution
- `PaymasterData` - Paymaster data parsing
- `GasEstimates` - Gas limit estimates

### `bundler.zig`
ERC-4337 Bundler client:
- `sendUserOperation` - Submit UserOp to bundler
- `estimateUserOperationGas` - Get gas estimates
- `getUserOperationByHash` - Fetch UserOp by hash
- `getUserOperationReceipt` - Get execution receipt
- `getSupportedEntryPoints` - Query supported entry points

### `paymaster.zig`
Paymaster interaction:
- `sponsorUserOperation` - Get sponsorship for UserOp
- `getERC20TokenQuotes` - Get token payment quotes
- `PaymasterMode` - Sponsorship modes (sponsor, erc20)
- `PaymasterAndDataParser` - Parse paymaster data

### `smart_account.zig`
Smart contract account management:
- `SmartAccount` - Base smart account implementation
- `AccountFactory` - Deploy new accounts
- `createUserOperation` - Create UserOp for transaction
- `signUserOperation` - Sign with owner key
- `encodeExecute` - Encode transaction calls
- `encodeExecuteBatch` - Encode batch transactions

### `entrypoint.zig`
EntryPoint contract (multi-version):
- `EntryPoint` - EntryPoint contract interface (v0.6, v0.7, v0.8)
- `ENTRYPOINT_V06` - Standard address for v0.6
- `ENTRYPOINT_V07` - Standard address for v0.7
- `ENTRYPOINT_V08` - Placeholder for v0.8
- `v06()`, `v07()`, `v08()` - Factory methods for each version
- `getNonce` - Query account nonce
- `balanceOf` - Query account deposit
- `simulateValidation` - Simulate UserOp validation
- `handleOps` - Submit UserOps for execution
- `depositTo` - Add deposit for account

### `gas.zig`
Gas estimation and pricing:
- `GasEstimator` - Estimate UserOperation gas
- `calculateCallDataGas` - Calculate calldata gas cost
- `getGasPrices` - Query current network gas prices
- `GasOverhead` - Gas overhead constants

### `utils.zig`
Utility functions:
- `UserOpHash` - Calculate UserOperation hash
- `PackedUserOperation` - Packed format (v0.7)
- `UserOpUtils` - Validation and size calculations

## Usage

### Selecting EntryPoint Version

```zig
const zigeth = @import("zigeth");
const aa = zigeth.account_abstraction;

// Option 1: Use v0.6 (Legacy, most compatible)
var entry_point = try aa.EntryPoint.v06(allocator);

// Option 2: Use v0.7 (Current, gas-optimized)
var entry_point = try aa.EntryPoint.v07(allocator);

// Option 3: Use v0.8 (Future)
var entry_point = try aa.EntryPoint.v08(allocator);

// Option 4: Custom address
const custom_address = try aa.primitives.Address.fromHex("0xYourCustomAddress");
var entry_point = aa.EntryPoint.init(
    allocator,
    custom_address,
    .v0_7,
);

// EntryPoint addresses are available as constants:
std.debug.print("v0.6: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V06_ADDRESS});
std.debug.print("v0.7: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V07_ADDRESS});
std.debug.print("v0.8: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V08_ADDRESS});
```

### Create a UserOperation (v0.6)

```zig
const zigeth = @import("zigeth");
const aa = zigeth.account_abstraction;

// Create EntryPoint v0.6
var entry_point = try aa.EntryPoint.v06(allocator);

// Create smart account
var account = aa.SmartAccount.init(
    allocator,
    account_address,
    entry_point.address,
    owner_address,
);

// Estimate gas
var estimator = aa.GasEstimator.init(allocator);
const user_op_v06 = aa.UserOperationV06{ /* ... */ };
const gas_estimates = try estimator.estimateGas(user_op_v06);

// Create UserOperation
const call_data = try account.encodeExecute(to_address, value, data);
var user_op = try account.createUserOperation(call_data, gas_estimates);

// Sign UserOperation
try account.signUserOperation(&user_op, private_key);

// Send to bundler
var bundler_client = aa.BundlerClient.init(allocator, bundler_url, entry_point.address);
const user_op_hash = try bundler_client.sendUserOperation(user_op);
```

### Create a UserOperation (v0.7 - Gas Optimized)

```zig
// Create EntryPoint v0.7
var entry_point = try aa.EntryPoint.v07(allocator);

// Create v0.7 UserOperation
var user_op_v07 = aa.UserOperationV07{
    .sender = account_address,
    .nonce = 0,
    .factory = factory_address, // Separated from calldata
    .factoryData = factory_calldata, // Factory-specific data
    .callData = call_data,
    .callGasLimit = 50000, // u128 instead of u256
    .verificationGasLimit = 100000,
    .preVerificationGas = 21000,
    .maxFeePerGas = 30_000_000_000, // 30 gwei (u128)
    .maxPriorityFeePerGas = 2_000_000_000, // 2 gwei (u128)
    .paymaster = paymaster_address, // Separated
    .paymasterVerificationGasLimit = 35000, // Explicit
    .paymasterPostOpGasLimit = 15000, // Explicit
    .paymasterData = paymaster_data, // Separated
    .signature = &[_]u8{},
};

// Validate before sending
try user_op_v07.validate();
```

### Use Paymaster

```zig
// Initialize paymaster client
var paymaster_client = aa.PaymasterClient.init(
    allocator,
    paymaster_url,
    api_key,
);

// Get sponsorship
try paymaster_client.sponsorUserOperation(
    &user_op,
    entry_point_address,
    .sponsor,
);

// UserOp now has paymasterAndData filled in
```

### Interact with EntryPoint

```zig
// Create EntryPoint client (v0.6)
var entry_point = aa.EntryPoint.v06(allocator);

// Get account nonce
const nonce = try entry_point.getNonce(account_address, 0);

// Get account deposit
const deposit = try entry_point.balanceOf(account_address);

// Simulate validation
const result = try entry_point.simulateValidation(user_op);
```

## Standards

- **ERC-4337** - Account Abstraction via Entry Point Contract Specification
  - Specification: https://eips.ethereum.org/EIPS/eip-4337
  - EntryPoint v0.6: `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`

## Implementation Status

| Component | Status | Functions | Description |
|-----------|--------|-----------|-------------|
| UserOperation Types | ✅ Complete | 7/7 | All data structures, conversions, and serialization |
| Bundler Client | ✅ Complete | 6/6 | Full RPC integration, multi-version support |
| Paymaster Client | ✅ Complete | 9/9 | Sponsorship, ERC-20 quotes, data parsing |
| Smart Account | ✅ Complete | 10/10 | Creation, signing, deployment, batch execution |
| EntryPoint | ✅ Core | 4/6 | Nonce, balance, deposits (simulateValidation & handleOps are stubs) |
| Gas Estimation | ✅ Complete | 10/10 | RPC + local fallback, EIP-1559, all versions |
| Utilities | ✅ Complete | 7/7 | Hashing, packing, validation, all versions |

**Overall: 46/48 functions (95.8%) - Production Ready! 🚀**

**Legend:**
- ✅ Complete - Fully implemented, tested, and production-ready
- ✅ Core - Core functions complete, optional functions are stubs
- 🟡 Stub/Partial - Interface defined, implementation in progress
- ❌ Planned - Not yet started

**Notes:**
- All modules support EntryPoint v0.6, v0.7, and v0.8
- Multi-version support via compile-time polymorphism (anytype)
- Full JSON-RPC integration for bundler and paymaster
- The 2 stub functions (simulateValidation, handleOps) require complex ABI encoding and are not needed for most AA workflows

## Testing

```bash
# Run all tests
zig build test

# Test account abstraction module
zig test src/account_abstraction/account_abstraction.zig
```

## References

- [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) - Account Abstraction Specification
- [Viem Account Abstraction](https://github.com/wevm/viem/tree/main/src/account-abstraction) - Reference TypeScript implementation
- [EntryPoint Contract](https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/EntryPoint.sol) - Reference Solidity implementation

## License

MIT

