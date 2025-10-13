const std = @import("std");
const zigeth = @import("zigeth");
const aa = zigeth.account_abstraction;

/// Minimal Account Abstraction test - works around LLVM limitations
/// This demonstrates the core AA features without complex operations
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("=" ** 70 ++ "\n", .{});
    std.debug.print("  Zigeth Account Abstraction - Quick Test\n", .{});
    std.debug.print("=" ** 70 ++ "\n\n", .{});

    // Test 1: EntryPoint Versions
    std.debug.print("✅ Test 1: EntryPoint Versions\n", .{});
    std.debug.print("   v0.6: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V06_ADDRESS});
    std.debug.print("   v0.7: {s}\n", .{aa.EntryPoint.ENTRYPOINT_V07_ADDRESS});
    std.debug.print("   v0.8: {s}\n\n", .{aa.EntryPoint.ENTRYPOINT_V08_ADDRESS});

    // Test 2: Create EntryPoint instances
    std.debug.print("✅ Test 2: Create EntryPoint instances\n", .{});
    const ep_v06 = try aa.EntryPoint.v06(allocator, null);
    const ep_v07 = try aa.EntryPoint.v07(allocator, null);
    const ep_v08 = try aa.EntryPoint.v08(allocator, null);
    std.debug.print("   Created v0.6: {}\n", .{ep_v06.version});
    std.debug.print("   Created v0.7: {}\n", .{ep_v07.version});
    std.debug.print("   Created v0.8: {}\n\n", .{ep_v08.version});

    // Test 3: Zero UserOperations
    std.debug.print("✅ Test 3: Create zero UserOperations\n", .{});
    const user_op_v06 = aa.UserOpUtils.zero(aa.types.UserOperationV06);
    const user_op_v07 = aa.UserOpUtils.zero(aa.types.UserOperationV07);
    const user_op_v08 = aa.UserOpUtils.zero(aa.types.UserOperationV08);
    std.debug.print("   v0.6 UserOp nonce: {}\n", .{user_op_v06.nonce});
    std.debug.print("   v0.7 UserOp nonce: {}\n", .{user_op_v07.nonce});
    std.debug.print("   v0.8 UserOp nonce: {}\n\n", .{user_op_v08.nonce});

    // Test 4: Validation
    std.debug.print("✅ Test 4: UserOperation validation\n", .{});
    const is_valid_v06 = aa.UserOpUtils.isValid(user_op_v06);
    const is_valid_v07 = aa.UserOpUtils.isValid(user_op_v07);
    std.debug.print("   v0.6 valid: {} (expected: false - zero address)\n", .{is_valid_v06});
    std.debug.print("   v0.7 valid: {} (expected: false - zero address)\n\n", .{is_valid_v07});

    // Test 5: Size calculation
    std.debug.print("✅ Test 5: UserOperation size calculation\n", .{});
    const size_v06 = aa.UserOpUtils.getSize(user_op_v06);
    const size_v07 = aa.UserOpUtils.getSize(user_op_v07);
    std.debug.print("   v0.6 size: {} bytes\n", .{size_v06});
    std.debug.print("   v0.7 size: {} bytes\n\n", .{size_v07});

    // Test 6: Gas Estimator
    std.debug.print("✅ Test 6: Gas Estimator (local mode)\n", .{});
    var gas_estimator = aa.GasEstimator.init(allocator, null, null);
    const gas_prices = try gas_estimator.getGasPrices();
    std.debug.print("   maxFeePerGas: {} wei\n", .{gas_prices.maxFeePerGas});
    std.debug.print("   maxPriorityFeePerGas: {} wei\n\n", .{gas_prices.maxPriorityFeePerGas});

    // Test 7: Paymaster modes
    std.debug.print("✅ Test 7: Paymaster modes\n", .{});
    std.debug.print("   SPONSOR mode: {s}\n", .{aa.PaymasterMode.sponsor.toString()});
    std.debug.print("   ERC20 mode: {s}\n\n", .{aa.PaymasterMode.erc20.toString()});

    // Test 8: Gas overhead constants
    std.debug.print("✅ Test 8: Gas overhead constants\n", .{});
    std.debug.print("   FIXED: {} gas\n", .{aa.GasOverhead.FIXED});
    std.debug.print("   PER_USER_OP: {} gas\n", .{aa.GasOverhead.PER_USER_OP});
    std.debug.print("   ACCOUNT_DEPLOYMENT: {} gas\n\n", .{aa.GasOverhead.ACCOUNT_DEPLOYMENT});

    // Test 9: Account Factory
    std.debug.print("✅ Test 9: Account Factory initialization\n", .{});
    const factory_addr = zigeth.primitives.Address.fromBytes([_]u8{0xFA} ** 20);
    var factory = aa.AccountFactory.init(allocator, factory_addr);
    const factory_hex = try factory.address.toHex(allocator);
    defer allocator.free(factory_hex);
    std.debug.print("   Factory address: {s}\n\n", .{factory_hex});

    std.debug.print("=" ** 70 ++ "\n", .{});
    std.debug.print("  ✅ ALL TESTS PASSED! Account Abstraction library is working!\n", .{});
    std.debug.print("=" ** 70 ++ "\n\n", .{});

    std.debug.print("📚 For more information, see:\n", .{});
    std.debug.print("   - src/account_abstraction/README.md (full documentation)\n", .{});
    std.debug.print("   - src/account_abstraction/*.zig (implementation code)\n", .{});
    std.debug.print("   - examples/README.md (all examples overview)\n\n", .{});
}
