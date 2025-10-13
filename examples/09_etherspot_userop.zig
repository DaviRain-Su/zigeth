const std = @import("std");
const zigeth = @import("zigeth");
const aa = zigeth.account_abstraction;

/// Example: Creating UserOperation with Etherspot Factory (EntryPoint v0.7)
/// Based on: https://github.com/etherspot/etherspot-modular-sdk
///
/// This demonstrates:
/// - Using Etherspot's Modular Smart Account Factory
/// - Creating a UserOperationV07 for EntryPoint v0.7
/// - Integrating with Etherspot Arka Paymaster
/// - Complete sponsored transaction workflow
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("  Etherspot UserOperation Example - EntryPoint v0.7\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // ============================================================================
    // CONFIGURATION
    // ============================================================================
    std.debug.print("📋 Configuration:\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Etherspot Addresses (Sepolia Testnet)
    const ETHERSPOT_FACTORY = "0x7f6d8F107fE8551160BD5351d5F1514320aB6E50"; // Modular Smart Account Factory
    const ETHERSPOT_PAYMASTER = "0x00000000000De1aaB9389285965F49D387000000"; // Arka Paymaster (Sepolia)
    const ENTRYPOINT_V07 = aa.EntryPoint.ENTRYPOINT_V07_ADDRESS;
    const BUNDLER_RPC = "https://sepolia-bundler.etherspot.io/v2"; // Skandha Bundler
    const PAYMASTER_RPC = "https://arka.etherspot.io"; // Arka Paymaster
    const CHAIN_ID: u64 = 11155111; // Sepolia

    std.debug.print("   • Network: Sepolia Testnet (chainId: {})\n", .{CHAIN_ID});
    std.debug.print("   • EntryPoint v0.7: {s}\n", .{ENTRYPOINT_V07});
    std.debug.print("   • Factory: {s}\n", .{ETHERSPOT_FACTORY});
    std.debug.print("   • Paymaster: {s}\n", .{ETHERSPOT_PAYMASTER});
    std.debug.print("   • Bundler RPC: {s}\n", .{BUNDLER_RPC});
    std.debug.print("   • Paymaster RPC: {s}\n\n", .{PAYMASTER_RPC});

    // ============================================================================
    // STEP 1: Setup Owner and Factory
    // ============================================================================
    std.debug.print("Step 1️⃣  Setup Owner EOA and Factory\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Owner address (EOA that controls the smart account)
    // In production: const owner = wallet.getAddress();
    const owner = try zigeth.primitives.Address.fromHex("0xe532535813B4Db08dB1434D1B2373Fb87aED5018");
    const owner_hex = try owner.toHex(allocator);
    defer allocator.free(owner_hex);
    std.debug.print("   ✓ Owner EOA: {s}\n", .{owner_hex});

    // Etherspot Modular Smart Account Factory
    const factory_address = try zigeth.primitives.Address.fromHex(ETHERSPOT_FACTORY);
    var factory = aa.AccountFactory.init(allocator, factory_address);
    std.debug.print("   ✓ Factory initialized: {s}\n\n", .{ETHERSPOT_FACTORY});

    // ============================================================================
    // STEP 2: Calculate Smart Account Address (CREATE2)
    // ============================================================================
    std.debug.print("Step 2️⃣  Calculate Smart Account Address (Deterministic)\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Salt for deterministic address (use 0 for first account)
    const salt: u256 = 0;
    const smart_account_address = try factory.getAddress(owner, salt);
    const account_hex = try smart_account_address.toHex(allocator);
    defer allocator.free(account_hex);

    std.debug.print("   ✓ Calculated via CREATE2\n", .{});
    std.debug.print("   • Owner: {s}\n", .{owner_hex});
    std.debug.print("   • Salt: {}\n", .{salt});
    std.debug.print("   • Smart Account: {s}\n\n", .{account_hex});

    // ============================================================================
    // STEP 3: Initialize Smart Account Instance
    // ============================================================================
    std.debug.print("Step 3️⃣  Initialize Smart Account\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    const entry_point_address = try zigeth.primitives.Address.fromHex(ENTRYPOINT_V07);

    // Note: In production, pass RPC client for nonce queries and deployment checks
    var smart_account = aa.SmartAccount.init(
        allocator,
        smart_account_address,
        entry_point_address,
        .v0_7, // EntryPoint v0.7
        owner,
        null, // RPC client (set to real client in production)
        &factory,
        salt,
    );

    std.debug.print("   ✓ Smart account initialized for EntryPoint v0.7\n", .{});
    std.debug.print("   • Account: {s}\n", .{account_hex});
    std.debug.print("   • Entry Point: {s}\n\n", .{ENTRYPOINT_V07});

    // ============================================================================
    // STEP 4: Create Transaction Call Data
    // ============================================================================
    std.debug.print("Step 4️⃣  Encode Transaction Call Data\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Example: Send 0.1 ETH to recipient
    const recipient = try zigeth.primitives.Address.fromHex("0x481C94F3Bb756F979dE8F9aEA88D0A9b3c543AC3");
    const value: u256 = 100_000_000_000_000_000; // 0.1 ETH
    const data = &[_]u8{}; // No additional data for simple transfer

    // Encode execute(address to, uint256 value, bytes data)
    const call_data = try smart_account.encodeExecute(recipient, value, data);
    defer allocator.free(call_data);

    const recipient_hex = try recipient.toHex(allocator);
    defer allocator.free(recipient_hex);

    std.debug.print("   ✓ Encoded execute(address, uint256, bytes)\n", .{});
    std.debug.print("   • Function: execute()\n", .{});
    std.debug.print("   • Recipient: {s}\n", .{recipient_hex});
    std.debug.print("   • Value: 0.1 ETH\n", .{});
    std.debug.print("   • Call data size: {} bytes\n\n", .{call_data.len});

    // ============================================================================
    // STEP 5: Estimate Gas
    // ============================================================================
    std.debug.print("Step 5️⃣  Estimate Gas (Local Fallback)\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // In production: Initialize with bundler and RPC clients for accurate estimates
    var gas_estimator = aa.GasEstimator.init(allocator, null, null);

    // Create a test UserOperation for estimation
    const test_user_op = aa.UserOpUtils.zero(aa.types.UserOperationV07);
    const gas_estimates = try gas_estimator.estimateGas(test_user_op);

    std.debug.print("   ✓ Gas estimated\n", .{});
    std.debug.print("   • preVerificationGas:   {} gas\n", .{gas_estimates.preVerificationGas});
    std.debug.print("   • verificationGasLimit: {} gas\n", .{gas_estimates.verificationGasLimit});
    std.debug.print("   • callGasLimit:         {} gas\n\n", .{gas_estimates.callGasLimit});

    // Get gas prices
    const gas_prices = try gas_estimator.getGasPrices();
    std.debug.print("   ✓ Gas prices (fallback)\n", .{});
    std.debug.print("   • maxFeePerGas:         {} gwei\n", .{gas_prices.maxFeePerGas / 1_000_000_000});
    std.debug.print("   • maxPriorityFeePerGas: {} gwei\n\n", .{gas_prices.maxPriorityFeePerGas / 1_000_000_000});

    // ============================================================================
    // STEP 6: Create UserOperation V0.7
    // ============================================================================
    std.debug.print("Step 6️⃣  Create UserOperationV07\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Create UserOperation using smart account
    const user_op_any = try smart_account.createUserOperation(call_data, gas_estimates);
    var user_op = user_op_any.v0_7;

    // Set gas prices
    user_op.maxFeePerGas = @intCast(gas_prices.maxFeePerGas);
    user_op.maxPriorityFeePerGas = @intCast(gas_prices.maxPriorityFeePerGas);

    std.debug.print("   ✓ UserOperationV07 created\n", .{});
    std.debug.print("   • sender: {s}\n", .{account_hex});
    std.debug.print("   • nonce: {}\n", .{user_op.nonce});
    std.debug.print("   • callGasLimit: {} (u128)\n", .{user_op.callGasLimit});
    std.debug.print("   • verificationGasLimit: {} (u128)\n", .{user_op.verificationGasLimit});
    std.debug.print("   • preVerificationGas: {}\n", .{user_op.preVerificationGas});
    std.debug.print("   • maxFeePerGas: {} gwei (u128)\n", .{user_op.maxFeePerGas / 1_000_000_000});
    std.debug.print("   • maxPriorityFeePerGas: {} gwei (u128)\n\n", .{user_op.maxPriorityFeePerGas / 1_000_000_000});

    // Display factory info (if account not deployed)
    if (user_op.factory) |factory_addr| {
        const factory_hex_str = try factory_addr.toHex(allocator);
        defer allocator.free(factory_hex_str);
        std.debug.print("   ✓ Factory deployment data included\n", .{});
        std.debug.print("   • factory: {s}\n", .{factory_hex_str});
        std.debug.print("   • factoryData: {} bytes\n\n", .{user_op.factoryData.len});
    }

    // ============================================================================
    // STEP 7: Request Paymaster Sponsorship (Etherspot Arka)
    // ============================================================================
    std.debug.print("Step 7️⃣  Request Paymaster Sponsorship\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    std.debug.print("   📡 Would make request to Arka Paymaster:\n", .{});
    std.debug.print("   • Endpoint: {s}\n", .{PAYMASTER_RPC});
    std.debug.print("   • Method: pm_sponsorUserOperation\n", .{});
    std.debug.print("   • Mode: SPONSOR (gasless transaction)\n\n", .{});

    std.debug.print("   Example RPC request:\n", .{});
    std.debug.print("   ```json\n", .{});
    std.debug.print("   {{\n", .{});
    std.debug.print("     \"jsonrpc\": \"2.0\",\n", .{});
    std.debug.print("     \"id\": 1,\n", .{});
    std.debug.print("     \"method\": \"pm_sponsorUserOperation\",\n", .{});
    std.debug.print("     \"params\": [{{\n", .{});
    std.debug.print("       \"userOperation\": {{...}},\n", .{});
    std.debug.print("       \"entryPoint\": \"{s}\",\n", .{ENTRYPOINT_V07});
    std.debug.print("       \"context\": {{ \"mode\": \"sponsor\" }}\n", .{});
    std.debug.print("     }}]\n", .{});
    std.debug.print("   }}\n", .{});
    std.debug.print("   ```\n\n", .{});

    std.debug.print("   ✓ In production, use:\n", .{});
    std.debug.print("   ```zig\n", .{});
    std.debug.print("   var paymaster = aa.PaymasterClient.init(allocator, paymaster_rpc, api_key);\n", .{});
    std.debug.print("   defer paymaster.deinit();\n", .{});
    std.debug.print("   try paymaster.sponsorUserOperation(&user_op, entry_point, .sponsor);\n", .{});
    std.debug.print("   ```\n\n", .{});

    // Simulate paymaster response
    const paymaster_address = try zigeth.primitives.Address.fromHex(ETHERSPOT_PAYMASTER);
    user_op.paymaster = paymaster_address;
    user_op.paymasterVerificationGasLimit = 50000;
    user_op.paymasterPostOpGasLimit = 30000;
    user_op.paymasterData = &[_]u8{ 0xAB, 0xCD, 0xEF }; // Paymaster signature

    std.debug.print("   ✓ Paymaster response (simulated):\n", .{});
    std.debug.print("   • paymaster: {s}\n", .{ETHERSPOT_PAYMASTER});
    std.debug.print("   • paymasterVerificationGasLimit: {}\n", .{user_op.paymasterVerificationGasLimit});
    std.debug.print("   • paymasterPostOpGasLimit: {}\n", .{user_op.paymasterPostOpGasLimit});
    std.debug.print("   • paymasterData: {} bytes\n\n", .{user_op.paymasterData.len});

    // ============================================================================
    // STEP 8: Calculate UserOperation Hash
    // ============================================================================
    std.debug.print("Step 8️⃣  Calculate UserOperation Hash\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Calculate hash for signing (EIP-4337 compliant) - works with any version
    const user_op_hash = try aa.UserOpHash.calculate(allocator, user_op, entry_point_address, CHAIN_ID);
    const hash_hex = try user_op_hash.toHex(allocator);
    defer allocator.free(hash_hex);

    std.debug.print("   ✓ UserOperation hash calculated\n", .{});
    std.debug.print("   • Hash: {s}\n", .{hash_hex});
    std.debug.print("   • Algorithm: keccak256(pack(userOp)) + entryPoint + chainId\n\n", .{});

    // ============================================================================
    // STEP 9: Sign UserOperation
    // ============================================================================
    std.debug.print("Step 9️⃣  Sign UserOperation\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    std.debug.print("   ✓ Would sign with owner's private key\n", .{});
    std.debug.print("   • Message hash: {s}\n", .{hash_hex});
    std.debug.print("   • Signer: Owner EOA\n", .{});
    std.debug.print("   • Algorithm: ECDSA (secp256k1)\n\n", .{});

    std.debug.print("   Example:\n", .{});
    std.debug.print("   ```zig\n", .{});
    std.debug.print("   // In production: Use actual private key\n", .{});
    std.debug.print("   const private_key = \"0x90fe97b36cda0d5eb623fec1fe31f1056cff15e85d49aa7530c26b358b2529ce\"; // 64 hex chars (32 bytes)\n", .{});
    std.debug.print("   const signature = try smart_account.signUserOperation(user_op, private_key);\n", .{});
    std.debug.print("   defer allocator.free(signature);\n", .{});
    std.debug.print("   user_op.signature = signature;\n", .{});
    std.debug.print("   ```\n\n", .{});

    // Simulate signature
    user_op.signature = &[_]u8{0x01} ** 65; // 65-byte ECDSA signature
    std.debug.print("   ✓ Signature attached: {} bytes\n\n", .{user_op.signature.len});

    // ============================================================================
    // STEP 10: Serialize UserOperation for RPC
    // ============================================================================
    std.debug.print("Step 🔟 Serialize UserOperation to JSON\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    // Convert to JSON format for RPC submission
    const user_op_json = try aa.types.UserOperationJson.fromUserOperation(allocator, user_op);
    defer user_op_json.deinit(allocator);

    std.debug.print("   ✓ Converted to JSON format (all fields as hex strings)\n", .{});
    std.debug.print("   • sender: {s}\n", .{user_op_json.sender});
    std.debug.print("   • nonce: {s}\n", .{user_op_json.nonce});
    std.debug.print("   • callGasLimit: {s}\n", .{user_op_json.callGasLimit});
    std.debug.print("   • Ready for JSON-RPC submission\n\n", .{});

    // ============================================================================
    // STEP 11: Send to Bundler (Etherspot Skandha)
    // ============================================================================
    std.debug.print("Step 1️⃣1️⃣  Send to Bundler\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    std.debug.print("   📡 Would make request to Skandha Bundler:\n", .{});
    std.debug.print("   • Endpoint: {s}\n", .{BUNDLER_RPC});
    std.debug.print("   • Method: eth_sendUserOperation\n\n", .{});

    std.debug.print("   Example RPC request:\n", .{});
    std.debug.print("   ```json\n", .{});
    std.debug.print("   {{\n", .{});
    std.debug.print("     \"jsonrpc\": \"2.0\",\n", .{});
    std.debug.print("     \"id\": 1,\n", .{});
    std.debug.print("     \"method\": \"eth_sendUserOperation\",\n", .{});
    std.debug.print("     \"params\": [\n", .{});
    std.debug.print("       {{...userOperation...}},\n", .{});
    std.debug.print("       \"{s}\"\n", .{ENTRYPOINT_V07});
    std.debug.print("     ]\n", .{});
    std.debug.print("   }}\n", .{});
    std.debug.print("   ```\n\n", .{});

    std.debug.print("   ✓ In production, use:\n", .{});
    std.debug.print("   ```zig\n", .{});
    std.debug.print("   var bundler = aa.BundlerClient.init(allocator, bundler_rpc, entry_point);\n", .{});
    std.debug.print("   defer bundler.deinit();\n", .{});
    std.debug.print("   const user_op_hash = try bundler.sendUserOperation(user_op);\n", .{});
    std.debug.print("   ```\n\n", .{});

    std.debug.print("   Expected response:\n", .{});
    std.debug.print("   • UserOperation hash: 0xabc123...\n\n", .{});

    // ============================================================================
    // STEP 12: Wait for Execution
    // ============================================================================
    std.debug.print("Step 1️⃣2️⃣  Wait for Transaction Execution\n", .{});
    std.debug.print("─" ** 80 ++ "\n", .{});

    std.debug.print("   ✓ In production, poll for receipt:\n", .{});
    std.debug.print("   ```zig\n", .{});
    std.debug.print("   // Wait for execution (poll every 5 seconds)\n", .{});
    std.debug.print("   while (true) {{\n", .{});
    std.debug.print("       const receipt = try bundler.getUserOperationReceipt(user_op_hash);\n", .{});
    std.debug.print("       if (receipt) |r| {{\n", .{});
    std.debug.print("           std.debug.print(\"Status: {{}}\\n\", .{{r.success}});\n", .{});
    std.debug.print("           std.debug.print(\"Gas used: {{}}\\n\", .{{r.actualGasUsed}});\n", .{});
    std.debug.print("           break;\n", .{});
    std.debug.print("       }}\n", .{});
    std.debug.print("       std.time.sleep(5 * std.time.ns_per_s);\n", .{});
    std.debug.print("   }}\n", .{});
    std.debug.print("   ```\n\n", .{});

    // ============================================================================
    // SUMMARY
    // ============================================================================
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("  🎉 Complete Etherspot UserOperation Workflow!\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    std.debug.print("✅ What was demonstrated:\n", .{});
    std.debug.print("   1. Etherspot Modular Smart Account Factory\n", .{});
    std.debug.print("   2. CREATE2 deterministic address calculation\n", .{});
    std.debug.print("   3. UserOperationV07 creation (EntryPoint v0.7)\n", .{});
    std.debug.print("   4. Transaction encoding (execute function)\n", .{});
    std.debug.print("   5. Gas estimation\n", .{});
    std.debug.print("   6. Arka Paymaster sponsorship (gasless transaction!)\n", .{});
    std.debug.print("   7. UserOperation signing\n", .{});
    std.debug.print("   8. JSON serialization for RPC\n", .{});
    std.debug.print("   9. Skandha Bundler submission\n", .{});
    std.debug.print("  10. Receipt polling\n\n", .{});

    std.debug.print("💡 To make this work with REAL network:\n", .{});
    std.debug.print("   1. Get Etherspot API key from https://etherspot.io/\n", .{});
    std.debug.print("   2. Initialize RPC client:\n", .{});
    std.debug.print("      const rpc = try zigeth.rpc.RpcClient.init(allocator, rpc_url);\n", .{});
    std.debug.print("   3. Pass RPC to SmartAccount, BundlerClient, PaymasterClient\n", .{});
    std.debug.print("   4. Use real private key for signing\n", .{});
    std.debug.print("   5. Ensure smart account has sufficient deposit in EntryPoint\n\n", .{});

    std.debug.print("🔗 Etherspot Resources:\n", .{});
    std.debug.print("   • Docs: https://etherspot.fyi/\n", .{});
    std.debug.print("   • Skandha Bundler: https://github.com/etherspot/skandha\n", .{});
    std.debug.print("   • Arka Paymaster: https://github.com/etherspot/arka\n", .{});
    std.debug.print("   • SDK Examples: https://github.com/etherspot/etherspot-modular-sdk\n\n", .{});

    std.debug.print("📚 Zigeth Documentation:\n", .{});
    std.debug.print("   • AA Package: src/account_abstraction/README.md\n", .{});
    std.debug.print("   • All Examples: examples/README.md\n\n", .{});
}
