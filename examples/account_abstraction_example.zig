const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("=" ** 60 ++ "\n", .{});
    std.debug.print("Zigeth Account Abstraction (ERC-4337) Example\n", .{});
    std.debug.print("=" ** 60 ++ "\n\n", .{});

    // 1. Show all EntryPoint versions
    std.debug.print("1. EntryPoint Versions:\n", .{});
    
    std.debug.print("   v0.6 (Legacy):\n", .{});
    std.debug.print("      Address: {s}\n", .{zigeth.account_abstraction.EntryPoint.ENTRYPOINT_V06_ADDRESS});
    var entry_point_v06 = try zigeth.account_abstraction.EntryPoint.v06(allocator);
    std.debug.print("      Version: {:?}\n", .{entry_point_v06.version});
    
    std.debug.print("   v0.7 (Current - Gas-optimized):\n", .{});
    std.debug.print("      Address: {s}\n", .{zigeth.account_abstraction.EntryPoint.ENTRYPOINT_V07_ADDRESS});
    var entry_point_v07 = try zigeth.account_abstraction.EntryPoint.v07(allocator);
    std.debug.print("      Version: {:?}\n", .{entry_point_v07.version});
    
    std.debug.print("   v0.8 (Future):\n", .{});
    std.debug.print("      Address: {s}\n", .{zigeth.account_abstraction.EntryPoint.ENTRYPOINT_V08_ADDRESS});
    var entry_point_v08 = try zigeth.account_abstraction.EntryPoint.v08(allocator);
    std.debug.print("      Version: {:?}\n\n", .{entry_point_v08.version});
    
    // Use v0.7 for rest of example
    var entry_point = entry_point_v07;

    // 2. Create Smart Account
    std.debug.print("2. Creating Smart Account...\n", .{});
    const account_address = zigeth.primitives.Address.fromBytes([_]u8{0xAA} ** 20);
    const owner_address = zigeth.primitives.Address.fromBytes([_]u8{0xBB} ** 20);

    var smart_account = zigeth.account_abstraction.SmartAccount.init(
        allocator,
        account_address,
        entry_point.address,
        owner_address,
    );

    const account_hex = try smart_account.address.toHex(allocator);
    defer allocator.free(account_hex);
    std.debug.print("   Account: {s}\n", .{account_hex});

    const owner_hex = try smart_account.owner.toHex(allocator);
    defer allocator.free(owner_hex);
    std.debug.print("   Owner:   {s}\n\n", .{owner_hex});

    // 3. Create Gas Estimator
    std.debug.print("3. Estimating gas...\n", .{});
    var gas_estimator = zigeth.account_abstraction.GasEstimator.init(allocator);

    const user_op = zigeth.account_abstraction.UserOpUtils.zero();
    const gas_estimates = try gas_estimator.estimateGas(user_op);

    std.debug.print("   preVerificationGas:    {}\n", .{gas_estimates.preVerificationGas});
    std.debug.print("   verificationGasLimit:  {}\n", .{gas_estimates.verificationGasLimit});
    std.debug.print("   callGasLimit:          {}\n\n", .{gas_estimates.callGasLimit});

    // 4. Get gas prices
    std.debug.print("4. Getting gas prices...\n", .{});
    const gas_prices = try gas_estimator.getGasPrices();
    std.debug.print("   maxFeePerGas:          {} wei\n", .{gas_prices.maxFeePerGas});
    std.debug.print("   maxPriorityFeePerGas:  {} wei\n\n", .{gas_prices.maxPriorityFeePerGas});

    // 5. Calculate total cost
    std.debug.print("5. Calculating total cost...\n", .{});
    const total_gas_cost = zigeth.account_abstraction.gas.GasEstimator.calculateTotalGasCost(
        gas_estimates,
        gas_prices.maxFeePerGas,
    );
    std.debug.print("   Total gas cost: {} wei\n\n", .{total_gas_cost});

    // 6. Create bundler client
    std.debug.print("6. Creating bundler client...\n", .{});
    var bundler = zigeth.account_abstraction.BundlerClient.init(
        allocator,
        "https://bundler.example.com/rpc",
        entry_point.address,
    );
    std.debug.print("   Bundler URL: {s}\n\n", .{bundler.rpc_url});

    // 7. Create paymaster client
    std.debug.print("7. Creating paymaster client...\n", .{});
    var paymaster_client = zigeth.account_abstraction.PaymasterClient.init(
        allocator,
        "https://paymaster.example.com/rpc",
        "test_api_key",
    );
    std.debug.print("   Paymaster URL: {s}\n", .{paymaster_client.rpc_url});
    std.debug.print("   API Key: {s}\n\n", .{paymaster_client.api_key.?});

    // 8. Show gas overhead constants
    std.debug.print("8. Gas overhead constants:\n", .{});
    std.debug.print("   FIXED:                 {} gas\n", .{zigeth.account_abstraction.GasOverhead.FIXED});
    std.debug.print("   PER_USER_OP:           {} gas\n", .{zigeth.account_abstraction.GasOverhead.PER_USER_OP});
    std.debug.print("   ACCOUNT_DEPLOYMENT:    {} gas\n", .{zigeth.account_abstraction.GasOverhead.ACCOUNT_DEPLOYMENT});
    std.debug.print("   PAYMASTER_VERIFICATION: {} gas\n", .{zigeth.account_abstraction.GasOverhead.PAYMASTER_VERIFICATION});
    std.debug.print("   PAYMASTER_POST_OP:     {} gas\n\n", .{zigeth.account_abstraction.GasOverhead.PAYMASTER_POST_OP});

    std.debug.print("=" ** 60 ++ "\n", .{});
    std.debug.print("✅ Account Abstraction module loaded successfully!\n", .{});
    std.debug.print("=" ** 60 ++ "\n\n", .{});
}
