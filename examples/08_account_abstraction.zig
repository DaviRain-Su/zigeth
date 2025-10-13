const std = @import("std");
const zigeth = @import("zigeth");
const aa = zigeth.account_abstraction;

/// ERC-4337 Account Abstraction Example
/// Demonstrates all features: Multi-version support, paymaster, gas estimation, smart accounts
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    printHeader();

    // ============================================================================
    // EXAMPLE 1: EntryPoint Versions
    // ============================================================================
    try example1_entrypoints(allocator);

    // ============================================================================
    // EXAMPLE 2: UserOperation Creation (Multi-Version)
    // ============================================================================
    try example2_useroperation_creation(allocator);

    // ============================================================================
    // EXAMPLE 3: Gas Estimation
    // ============================================================================
    try example3_gas_estimation(allocator);

    // ============================================================================
    // EXAMPLE 4: Smart Account Management
    // ============================================================================
    try example4_smart_account(allocator);

    // ============================================================================
    // EXAMPLE 5: Paymaster Integration
    // ============================================================================
    try example5_paymaster(allocator);

    // ============================================================================
    // EXAMPLE 6: Bundler Client
    // ============================================================================
    try example6_bundler(allocator);

    // ============================================================================
    // EXAMPLE 7: Complete Workflow (Putting It All Together)
    // ============================================================================
    try example7_complete_workflow(allocator);

    printFooter();
}

fn printHeader() void {
    std.debug.print("\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("║                                                                              ║\n", .{});
    std.debug.print("║         Zigeth ERC-4337 Account Abstraction - Comprehensive Examples        ║\n", .{});
    std.debug.print("║                                                                              ║\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}

fn printSectionHeader(comptime number: u8, comptime title: []const u8) void {
    std.debug.print("\n", .{});
    std.debug.print("┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE {}: {s: <66} │\n", .{ number, title });
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});
}

fn printFooter() void {
    std.debug.print("\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("║                                                                              ║\n", .{});
    std.debug.print("║                     ✅ All Examples Complete!                                ║\n", .{});
    std.debug.print("║                                                                              ║\n", .{});
    std.debug.print("║  The Zigeth Account Abstraction package supports:                           ║\n", .{});
    std.debug.print("║  • EntryPoint v0.6, v0.7, and v0.8                                           ║\n", .{});
    std.debug.print("║  • Multi-version UserOperations (compile-time polymorphism)                  ║\n", .{});
    std.debug.print("║  • Complete bundler integration                                              ║\n", .{});
    std.debug.print("║  • Paymaster sponsorship and ERC-20 payments                                 ║\n", .{});
    std.debug.print("║  • Smart account creation and management                                     ║\n", .{});
    std.debug.print("║  • Comprehensive gas estimation                                              ║\n", .{});
    std.debug.print("║  • Batch transaction support                                                 ║\n", .{});
    std.debug.print("║                                                                              ║\n", .{});
    std.debug.print("║  Ready for production ERC-4337 applications! 🚀                              ║\n", .{});
    std.debug.print("║                                                                              ║\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}

// ============================================================================
// EXAMPLE 1: EntryPoint Versions
// ============================================================================
fn example1_entrypoints(allocator: std.mem.Allocator) !void {
    printSectionHeader(1, "EntryPoint Versions (v0.6, v0.7, v0.8)");

    std.debug.print("Creating EntryPoint instances for all three versions:\n\n", .{});

    // v0.6
    const ep_v06 = try aa.EntryPoint.v06(allocator, null);
    std.debug.print("✅ EntryPoint v0.6:\n", .{});
    std.debug.print("   Address: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V06_ADDRESS});
    std.debug.print("   Version: {}\n", .{ep_v06.version});
    std.debug.print("   Features: Original ERC-4337, all gas fields are u256\n\n", .{});

    // v0.7
    const ep_v07 = try aa.EntryPoint.v07(allocator, null);
    std.debug.print("✅ EntryPoint v0.7:\n", .{});
    std.debug.print("   Address: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V07_ADDRESS});
    std.debug.print("   Version: {}\n", .{ep_v07.version});
    std.debug.print("   Features: Gas-optimized, u128 gas fields, packed format\n\n", .{});

    // v0.8
    const ep_v08 = try aa.EntryPoint.v08(allocator, null);
    std.debug.print("✅ EntryPoint v0.8:\n", .{});
    std.debug.print("   Address: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V08_ADDRESS});
    std.debug.print("   Version: {}\n", .{ep_v08.version});
    std.debug.print("   Features: Latest optimizations\n\n", .{});

    std.debug.print("💡 Tip: Use v0.7 for best gas efficiency!\n", .{});
}

// ============================================================================
// EXAMPLE 2: UserOperation Creation (Multi-Version)
// ============================================================================
fn example2_useroperation_creation(allocator: std.mem.Allocator) !void {
    printSectionHeader(2, "UserOperation Creation (Multi-Version Support)");

    std.debug.print("Creating UserOperations for each EntryPoint version:\n\n", .{});

    // v0.6 UserOperation
    std.debug.print("✅ UserOperationV06 (v0.6 format):\n", .{});
    const user_op_v06 = aa.types.UserOperationV06{
        .sender = zigeth.primitives.Address.fromBytes([_]u8{0x11} ** 20),
        .nonce = 0,
        .initCode = &[_]u8{},
        .callData = &[_]u8{ 0x01, 0x02, 0x03 },
        .callGasLimit = 100000,
        .verificationGasLimit = 150000,
        .preVerificationGas = 21000,
        .maxFeePerGas = 30_000_000_000, // 30 gwei
        .maxPriorityFeePerGas = 2_000_000_000, // 2 gwei
        .paymasterAndData = &[_]u8{},
        .signature = &[_]u8{},
    };
    std.debug.print("   • Gas fields: u256\n", .{});
    std.debug.print("   • paymasterAndData: Combined field\n", .{});
    std.debug.print("   • Size: {} bytes\n\n", .{aa.UserOpUtils.getSize(user_op_v06)});

    // v0.7 UserOperation
    std.debug.print("✅ UserOperationV07 (v0.7 format - Gas-optimized):\n", .{});
    const user_op_v07 = aa.types.UserOperationV07{
        .sender = zigeth.primitives.Address.fromBytes([_]u8{0x22} ** 20),
        .nonce = 0,
        .factory = null,
        .factoryData = &[_]u8{},
        .callData = &[_]u8{ 0x01, 0x02, 0x03 },
        .callGasLimit = 100000, // u128
        .verificationGasLimit = 150000, // u128
        .preVerificationGas = 21000,
        .maxFeePerGas = 30_000_000_000, // u128
        .maxPriorityFeePerGas = 2_000_000_000, // u128
        .paymaster = null,
        .paymasterVerificationGasLimit = 0,
        .paymasterPostOpGasLimit = 0,
        .paymasterData = &[_]u8{},
        .signature = &[_]u8{},
    };
    std.debug.print("   • Gas fields: u128 (more efficient)\n", .{});
    std.debug.print("   • Separate factory and paymaster fields\n", .{});
    std.debug.print("   • Size: {} bytes\n\n", .{aa.UserOpUtils.getSize(user_op_v07)});

    // Demonstrate multi-version support
    std.debug.print("✅ Multi-version validation (works with all types):\n", .{});
    const is_valid_v06 = aa.UserOpUtils.isValid(user_op_v06);
    const is_valid_v07 = aa.UserOpUtils.isValid(user_op_v07);
    std.debug.print("   • v0.6 valid: {}\n", .{is_valid_v06});
    std.debug.print("   • v0.7 valid: {}\n\n", .{is_valid_v07});

    // Version conversion
    std.debug.print("✅ Version conversion (v0.7 → v0.6):\n", .{});
    const converted = try user_op_v07.toV06(allocator);
    defer allocator.free(converted.initCode);
    defer allocator.free(converted.paymasterAndData);
    std.debug.print("   • Converted successfully\n", .{});
    std.debug.print("   • v0.6 callGasLimit: {} (was u128: {})\n", .{ converted.callGasLimit, user_op_v07.callGasLimit });
    std.debug.print("   • Size after conversion: {} bytes\n", .{aa.UserOpUtils.getSize(converted)});
}

// ============================================================================
// EXAMPLE 3: Gas Estimation
// ============================================================================
fn example3_gas_estimation(allocator: std.mem.Allocator) !void {
    printSectionHeader(3, "Gas Estimation (Local & RPC)");

    std.debug.print("Demonstrating gas estimation capabilities:\n\n", .{});

    // Create gas estimator (without RPC - local mode)
    var gas_estimator = aa.GasEstimator.init(allocator, null, null);

    // Create a test UserOperation
    const test_user_op = aa.UserOpUtils.zero(aa.types.UserOperationV07);

    // Estimate gas
    std.debug.print("✅ Local gas estimation:\n", .{});
    const gas_estimates = try gas_estimator.estimateGas(test_user_op);
    std.debug.print("   • preVerificationGas:   {} gas\n", .{gas_estimates.preVerificationGas});
    std.debug.print("   • verificationGasLimit: {} gas\n", .{gas_estimates.verificationGasLimit});
    std.debug.print("   • callGasLimit:         {} gas\n\n", .{gas_estimates.callGasLimit});

    // Get gas prices
    std.debug.print("✅ Gas prices (fallback defaults):\n", .{});
    const gas_prices = try gas_estimator.getGasPrices();
    std.debug.print("   • maxFeePerGas:         {} wei ({} gwei)\n", .{ gas_prices.maxFeePerGas, gas_prices.maxFeePerGas / 1_000_000_000 });
    std.debug.print("   • maxPriorityFeePerGas: {} wei ({} gwei)\n\n", .{ gas_prices.maxPriorityFeePerGas, gas_prices.maxPriorityFeePerGas / 1_000_000_000 });

    // Calculate total cost
    std.debug.print("✅ Total gas cost calculation:\n", .{});
    const total_cost = aa.GasEstimator.calculateTotalGasCost(gas_estimates, gas_prices.maxFeePerGas);
    std.debug.print("   • Total cost: {} wei\n", .{total_cost});
    std.debug.print("   • Total cost: ~{} ETH\n\n", .{@as(f64, @floatFromInt(total_cost)) / 1e18});

    // Apply safety margin
    std.debug.print("✅ Safety margins (preventing out-of-gas):\n", .{});
    const safe_110 = aa.GasEstimator.applyGasMultiplier(gas_estimates, 110);
    const safe_120 = aa.GasEstimator.applyGasMultiplier(gas_estimates, 120);
    std.debug.print("   • 110% margin: {} total gas\n", .{safe_110.preVerificationGas + safe_110.verificationGasLimit + safe_110.callGasLimit});
    std.debug.print("   • 120% margin: {} total gas\n", .{safe_120.preVerificationGas + safe_120.verificationGasLimit + safe_120.callGasLimit});

    std.debug.print("\n💡 Tip: With RPC client, estimator queries real network prices via eth_gasPrice!\n", .{});
}

// ============================================================================
// EXAMPLE 4: Smart Account Management
// ============================================================================
fn example4_smart_account(allocator: std.mem.Allocator) !void {
    printSectionHeader(4, "Smart Account Management");

    std.debug.print("Creating and managing an ERC-4337 smart account:\n\n", .{});

    // Setup
    const owner = zigeth.primitives.Address.fromBytes([_]u8{0xAA} ** 20);
    const factory_address = zigeth.primitives.Address.fromBytes([_]u8{0xBB} ** 20);
    const entry_point_address = try zigeth.primitives.Address.fromHex(aa.EntryPoint.ENTRYPOINT_V07_ADDRESS);

    // Create factory
    var factory = aa.AccountFactory.init(allocator, factory_address);

    // Predict account address (CREATE2)
    std.debug.print("✅ Deterministic address calculation (CREATE2):\n", .{});
    const salt: u256 = 0;
    const predicted_address = try factory.getAddress(owner, salt);
    const addr_hex = try predicted_address.toHex(allocator);
    defer allocator.free(addr_hex);
    std.debug.print("   • Owner: {s}...{s}\n", .{ "0xaa", "aa" });
    std.debug.print("   • Salt: {}\n", .{salt});
    std.debug.print("   • Predicted address: {s}\n\n", .{addr_hex});

    // Create smart account
    var smart_account = aa.SmartAccount.init(
        allocator,
        predicted_address,
        entry_point_address,
        .v0_7,
        owner,
        null, // No RPC for this example
        &factory,
        salt,
    );

    // Encode execute call
    std.debug.print("✅ Encode execute call:\n", .{});
    const recipient = zigeth.primitives.Address.fromBytes([_]u8{0xCC} ** 20);
    const value: u256 = 1_000_000_000_000_000_000; // 1 ETH
    const execute_data = try smart_account.encodeExecute(recipient, value, &[_]u8{});
    defer allocator.free(execute_data);
    std.debug.print("   • Function: execute(address, uint256, bytes)\n", .{});
    std.debug.print("   • Recipient: {s}...{s}\n", .{ "0xcc", "cc" });
    std.debug.print("   • Value: 1 ETH\n", .{});
    std.debug.print("   • Encoded calldata: {} bytes\n\n", .{execute_data.len});

    // Encode batch execute
    std.debug.print("✅ Encode batch execute (atomic multi-call):\n", .{});
    const batch_calls = [_]aa.Call{
        .{
            .to = zigeth.primitives.Address.fromBytes([_]u8{0xDD} ** 20),
            .value = 100_000_000_000_000_000, // 0.1 ETH
            .data = &[_]u8{},
        },
        .{
            .to = zigeth.primitives.Address.fromBytes([_]u8{0xEE} ** 20),
            .value = 200_000_000_000_000_000, // 0.2 ETH
            .data = &[_]u8{ 0xa9, 0x05, 0x9c, 0xbb }, // transfer selector
        },
    };
    const batch_data = try smart_account.encodeExecuteBatch(&batch_calls);
    defer allocator.free(batch_data);
    std.debug.print("   • Function: executeBatch(address[], uint256[], bytes[])\n", .{});
    std.debug.print("   • Number of calls: {}\n", .{batch_calls.len});
    std.debug.print("   • Encoded calldata: {} bytes\n\n", .{batch_data.len});

    // Create init code
    std.debug.print("✅ Generate deployment init code (v0.6 format):\n", .{});
    const init_code = try factory.createInitCode(owner, salt);
    defer allocator.free(init_code);
    std.debug.print("   • Init code length: {} bytes\n", .{init_code.len});
    std.debug.print("   • Format: factory_address(20) + createAccount(owner, salt)\n\n", .{});

    // Create factory data (v0.7 format)
    std.debug.print("✅ Generate factory data (v0.7+ format):\n", .{});
    const factory_data = try factory.createFactoryData(owner, salt);
    defer allocator.free(factory_data.data);
    const factory_hex = try factory_data.factory.toHex(allocator);
    defer allocator.free(factory_hex);
    std.debug.print("   • Factory: {s}\n", .{factory_hex});
    std.debug.print("   • Factory data length: {} bytes\n", .{factory_data.data.len});
    std.debug.print("   • Format: createAccount(owner, salt) calldata\n", .{});

    std.debug.print("\n💡 Tip: Factory enables deterministic account addresses via CREATE2!\n", .{});
}

// ============================================================================
// EXAMPLE 5: Paymaster Integration
// ============================================================================
fn example5_paymaster(allocator: std.mem.Allocator) !void {
    printSectionHeader(5, "Paymaster Integration (Sponsorship & ERC-20)");

    std.debug.print("Demonstrating paymaster features:\n\n", .{});

    // Paymaster modes
    std.debug.print("✅ Paymaster modes:\n", .{});
    std.debug.print("   • SPONSOR: {s}\n", .{aa.PaymasterMode.sponsor.toString()});
    std.debug.print("   • ERC20:   {s}\n\n", .{aa.PaymasterMode.erc20.toString()});

    // Create paymaster data
    std.debug.print("✅ PaymasterData packing/unpacking:\n", .{});
    const pm_address = zigeth.primitives.Address.fromBytes([_]u8{0xFF} ** 20);
    const pm_data = aa.types.PaymasterData{
        .paymaster = pm_address,
        .verificationGasLimit = 50000,
        .postOpGasLimit = 30000,
        .data = &[_]u8{ 0xAA, 0xBB, 0xCC },
    };

    // Pack
    const packed_data = try pm_data.pack(allocator);
    defer allocator.free(packed_data);
    std.debug.print("   • Packed size: {} bytes\n", .{packed_data.len});
    std.debug.print("   • Format: paymaster(20) + verGas(16) + postGas(16) + data\n\n", .{});

    // Unpack
    const unpacked = try aa.types.PaymasterData.unpack(packed_data, allocator);
    defer allocator.free(unpacked.data);
    std.debug.print("   • Unpacked successfully\n", .{});
    std.debug.print("   • Verification gas: {}\n", .{unpacked.verificationGasLimit});
    std.debug.print("   • Post-op gas: {}\n", .{unpacked.postOpGasLimit});
    std.debug.print("   • Data length: {}\n\n", .{unpacked.data.len});

    // Stub signatures
    std.debug.print("✅ Stub signatures for gas estimation:\n", .{});
    const stub_v06 = try aa.PaymasterStub.createStubSignature(allocator, pm_address);
    defer allocator.free(stub_v06);
    std.debug.print("   • v0.6 stub: {} bytes\n", .{stub_v06.len});
    std.debug.print("   • Format: address(20) + validUntil(6) + validAfter(6) + sig(65)\n\n", .{});

    const stub_v07 = try aa.PaymasterStub.createStubSignatureV07(allocator, pm_address, 50000, 30000);
    defer allocator.free(stub_v07);
    std.debug.print("   • v0.7+ stub: {} bytes\n", .{stub_v07.len});
    std.debug.print("   • Format: address(20) + verGas(16) + postGas(16) + sig(65)\n", .{});

    std.debug.print("\n💡 Tip: Paymasters enable sponsored transactions - free for users!\n", .{});
}

// ============================================================================
// EXAMPLE 6: Bundler Client
// ============================================================================
fn example6_bundler(_: std.mem.Allocator) !void {
    printSectionHeader(6, "Bundler Client (RPC Interface)");

    std.debug.print("Bundler client interface (offline demo):\n\n", .{});

    const entry_point_addr = try zigeth.primitives.Address.fromHex(aa.EntryPoint.ENTRYPOINT_V07_ADDRESS);

    std.debug.print("✅ BundlerClient capabilities:\n", .{});
    std.debug.print("   • sendUserOperation(anytype) - Send v0.6, v0.7, or v0.8 UserOps\n", .{});
    std.debug.print("   • estimateUserOperationGas(anytype) - Estimate gas for any version\n", .{});
    std.debug.print("   • getUserOperationByHash(hash, Type) - Type-safe retrieval\n", .{});
    std.debug.print("   • getUserOperationReceipt(hash) - Get execution receipt\n", .{});
    std.debug.print("   • getSupportedEntryPoints() - Query bundler capabilities\n", .{});
    std.debug.print("   • getChainId() - Get network chain ID\n\n", .{});

    std.debug.print("✅ Multi-version support:\n", .{});
    std.debug.print("   • Accepts UserOperationV06, V07, or V08\n", .{});
    std.debug.print("   • Compile-time type validation\n", .{});
    std.debug.print("   • Zero runtime overhead\n", .{});
    std.debug.print("   • Same function for all versions!\n\n", .{});

    std.debug.print("Example usage:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("var bundler = try aa.BundlerClient.init(allocator, rpc_url, entry_point);\n", .{});
    std.debug.print("defer bundler.deinit();\n\n", .{});
    std.debug.print("// Works with any version!\n", .{});
    std.debug.print("const hash_v06 = try bundler.sendUserOperation(user_op_v06);\n", .{});
    std.debug.print("const hash_v07 = try bundler.sendUserOperation(user_op_v07);\n", .{});
    std.debug.print("const hash_v08 = try bundler.sendUserOperation(user_op_v08);\n", .{});
    std.debug.print("```\n", .{});

    _ = entry_point_addr;
    std.debug.print("\n💡 Tip: Bundler clients abstract away version differences!\n", .{});
}

// ============================================================================
// EXAMPLE 7: Complete Workflow
// ============================================================================
fn example7_complete_workflow(allocator: std.mem.Allocator) !void {
    printSectionHeader(7, "Complete Workflow (All Components)");

    std.debug.print("Complete ERC-4337 transaction workflow:\n\n", .{});

    // Setup addresses
    const owner = zigeth.primitives.Address.fromBytes([_]u8{0x01} ** 20);
    const factory_addr = zigeth.primitives.Address.fromBytes([_]u8{0x02} ** 20);
    const entry_point_addr = try zigeth.primitives.Address.fromHex(aa.EntryPoint.ENTRYPOINT_V07_ADDRESS);
    const recipient = zigeth.primitives.Address.fromBytes([_]u8{0x03} ** 20);

    std.debug.print("Step 1️⃣  Setup Factory and Calculate Account Address\n", .{});
    var factory = aa.AccountFactory.init(allocator, factory_addr);
    const account_address = try factory.getAddress(owner, 0);
    std.debug.print("   ✓ Account address calculated via CREATE2\n\n", .{});

    std.debug.print("Step 2️⃣  Create Smart Account Instance\n", .{});
    var smart_account = aa.SmartAccount.init(
        allocator,
        account_address,
        entry_point_addr,
        .v0_7,
        owner,
        null, // No RPC in this demo
        &factory,
        0, // salt
    );
    std.debug.print("   ✓ Smart account created (v0.7)\n\n", .{});

    std.debug.print("Step 3️⃣  Encode Transaction Call Data\n", .{});
    const value: u256 = 500_000_000_000_000_000; // 0.5 ETH
    const call_data = try smart_account.encodeExecute(recipient, value, &[_]u8{});
    defer allocator.free(call_data);
    std.debug.print("   ✓ Encoded execute(to, value, data)\n", .{});
    std.debug.print("   ✓ Call data: {} bytes\n\n", .{call_data.len});

    std.debug.print("Step 4️⃣  Estimate Gas\n", .{});
    var gas_estimator = aa.GasEstimator.init(allocator, null, null);
    const test_op = aa.UserOpUtils.zero(aa.types.UserOperationV07);
    const gas_estimates = try gas_estimator.estimateGas(test_op);
    std.debug.print("   ✓ Gas estimated: {} + {} + {} gas\n\n", .{
        gas_estimates.preVerificationGas,
        gas_estimates.verificationGasLimit,
        gas_estimates.callGasLimit,
    });

    std.debug.print("Step 5️⃣  Create UserOperation\n", .{});
    const user_op_any = try smart_account.createUserOperation(call_data, gas_estimates);
    var user_op = user_op_any.v0_7;
    std.debug.print("   ✓ UserOperationV07 created\n", .{});
    std.debug.print("   ✓ Sender: (smart account)\n", .{});
    std.debug.print("   ✓ Nonce: {}\n\n", .{user_op.nonce});

    std.debug.print("Step 6️⃣  Get Gas Prices\n", .{});
    const gas_prices = try gas_estimator.getGasPrices();
    user_op.maxFeePerGas = @intCast(gas_prices.maxFeePerGas);
    user_op.maxPriorityFeePerGas = @intCast(gas_prices.maxPriorityFeePerGas);
    std.debug.print("   ✓ Max fee: {} gwei\n", .{gas_prices.maxFeePerGas / 1_000_000_000});
    std.debug.print("   ✓ Priority fee: {} gwei\n\n", .{gas_prices.maxPriorityFeePerGas / 1_000_000_000});

    std.debug.print("Step 7️⃣  Get Paymaster Sponsorship (if available)\n", .{});
    std.debug.print("   • Would call: paymaster.sponsorUserOperation(&user_op, ...)\n", .{});
    std.debug.print("   • Paymaster fills: gas estimates + paymaster data\n", .{});
    std.debug.print("   • Result: Free transaction for user! 🎉\n\n", .{});

    std.debug.print("Step 8️⃣  Sign UserOperation\n", .{});
    std.debug.print("   • Calculate UserOp hash (EIP-4337)\n", .{});
    std.debug.print("   • Sign with private key (ECDSA)\n", .{});
    std.debug.print("   • Attach signature to user_op.signature\n\n", .{});

    std.debug.print("Step 9️⃣  Send to Bundler\n", .{});
    std.debug.print("   • bundler.sendUserOperation(user_op)\n", .{});
    std.debug.print("   • Returns: UserOperation hash\n\n", .{});

    std.debug.print("Step 🔟 Wait for Execution\n", .{});
    std.debug.print("   • Poll: bundler.getUserOperationReceipt(hash)\n", .{});
    std.debug.print("   • When receipt available: Transaction executed!\n", .{});
    std.debug.print("   • Check: receipt.success for status\n\n", .{});

    std.debug.print("🎉 Complete workflow demonstrated!\n", .{});
    std.debug.print("💡 With RPC clients, all these steps execute on real network!\n", .{});
}

