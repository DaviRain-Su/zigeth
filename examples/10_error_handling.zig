const std = @import("std");
const zigeth = @import("zigeth");

/// Example: Comprehensive Error Handling in Zigeth
/// Demonstrates best practices for error handling, formatting, and reporting
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("  Zigeth Error Handling - Best Practices\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // ============================================================================
    // EXAMPLE 1: Basic Error Context
    // ============================================================================
    try example1_basic_error_context(allocator);

    // ============================================================================
    // EXAMPLE 2: Error Formatting (JSON, Text, Log)
    // ============================================================================
    try example2_error_formatting(allocator);

    // ============================================================================
    // EXAMPLE 3: RPC Error Handling
    // ============================================================================
    try example3_rpc_errors(allocator);

    // ============================================================================
    // EXAMPLE 4: Transaction Error Handling
    // ============================================================================
    try example4_transaction_errors(allocator);

    // ============================================================================
    // EXAMPLE 5: Error Recovery Patterns
    // ============================================================================
    try example5_error_recovery(allocator);

    // ============================================================================
    // EXAMPLE 6: Production Error Reporting
    // ============================================================================
    try example6_production_reporting(allocator);

    std.debug.print("\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("  ✅ All Error Handling Examples Complete!\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}

fn example1_basic_error_context(allocator: std.mem.Allocator) !void {
    std.debug.print("┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE 1: Basic Error Context                                             │\n", .{});
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});

    // Create error context
    const ctx = zigeth.ErrorContext.init("RPC", "eth_getBlockByNumber");
    const ctx_with_details = ctx.withDetails("Block 999999999 not found");
    const ctx_with_code = ctx_with_details.withCode(-32000);

    std.debug.print("✅ Error Context Created:\n", .{});
    std.debug.print("   • Module: {s}\n", .{ctx_with_code.module});
    std.debug.print("   • Operation: {s}\n", .{ctx_with_code.operation});
    std.debug.print("   • Details: {s}\n", .{ctx_with_code.details.?});
    std.debug.print("   • Code: {}\n\n", .{ctx_with_code.code.?});

    // Format the error
    const formatted = try zigeth.errors.formatError(allocator, error.BlockNotFound, ctx_with_code);
    defer allocator.free(formatted);
    std.debug.print("📝 Formatted Error:\n{s}\n", .{formatted});
}

fn example2_error_formatting(allocator: std.mem.Allocator) !void {
    std.debug.print("\n┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE 2: Error Formatting (JSON, Text, Log)                              │\n", .{});
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});

    const ctx = zigeth.ErrorContext.init("Provider", "getBalance")
        .withDetails("RPC endpoint unreachable")
        .withCode(-1);

    const formatter = zigeth.ErrorFormatter.init(allocator, true); // with colors

    // JSON format (for APIs)
    const json = try formatter.toJson(error.NetworkError, ctx);
    defer allocator.free(json);
    std.debug.print("📄 JSON Format (for APIs):\n", .{});
    std.debug.print("{s}\n\n", .{json});

    // Text format (for CLI/user display)
    const text = try formatter.toText(error.NetworkError, ctx);
    defer allocator.free(text);
    std.debug.print("📝 Text Format (for CLI/user display):\n", .{});
    std.debug.print("{s}\n", .{text});

    // Log format (for log files)
    const log_entry = try formatter.toLog(error.NetworkError, ctx);
    defer allocator.free(log_entry);
    std.debug.print("📋 Log Format (for log files):\n", .{});
    std.debug.print("{s}\n\n", .{log_entry});

    // User-friendly message
    const user_msg = zigeth.errors.Helpers.getUserMessage(error.NetworkError);
    std.debug.print("💬 User-Friendly Message:\n", .{});
    std.debug.print("   {s}\n", .{user_msg});
}

fn example3_rpc_errors(allocator: std.mem.Allocator) !void {
    std.debug.print("\n┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE 3: RPC Error Handling                                               │\n", .{});
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});

    std.debug.print("✅ Module-Specific Error Sets:\n\n", .{});

    // Demonstrate RPC errors
    std.debug.print("📡 RPC Errors:\n", .{});
    const rpc_errors = [_]zigeth.RpcErrors{
        error.ConnectionFailed,
        error.Timeout,
        error.InvalidJsonRpcResponse,
        error.JsonRpcError,
    };

    for (rpc_errors) |err| {
        const ctx = zigeth.ErrorContext.init("RPC", "call");
        const formatted = try zigeth.errors.formatError(allocator, err, ctx);
        defer allocator.free(formatted);
        std.debug.print("   • {s}: {s}\n", .{ @errorName(err), zigeth.errors.Helpers.getUserMessage(err) });
    }

    std.debug.print("\n💼 Wallet Errors:\n", .{});
    const wallet_errors = [_]zigeth.WalletErrors{
        error.InvalidPrivateKey,
        error.InvalidMnemonic,
        error.InvalidKeystore,
    };

    for (wallet_errors) |err| {
        std.debug.print("   • {s}: {s}\n", .{ @errorName(err), zigeth.errors.Helpers.getUserMessage(err) });
    }

    std.debug.print("\n📝 Contract Errors:\n", .{});
    const contract_errors = [_]zigeth.ContractErrors{
        error.ContractNotFound,
        error.ContractCallFailed,
        error.AbiEncodingFailed,
    };

    for (contract_errors) |err| {
        std.debug.print("   • {s}: {s}\n", .{ @errorName(err), zigeth.errors.Helpers.getUserMessage(err) });
    }
}

fn example4_transaction_errors(allocator: std.mem.Allocator) !void {
    std.debug.print("\n┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE 4: Transaction Error Handling                                       │\n", .{});
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});

    // Simulate transaction errors
    std.debug.print("✅ Common Transaction Errors:\n\n", .{});

    const tx_errors = [_]struct {
        err: zigeth.TransactionErrors,
        description: []const u8,
    }{
        .{ .err = error.InsufficientFunds, .description = "Sender doesn't have enough ETH" },
        .{ .err = error.NonceTooLow, .description = "Nonce already used" },
        .{ .err = error.GasTooLow, .description = "Gas limit too low for execution" },
        .{ .err = error.TransactionUnderpriced, .description = "Gas price too low" },
        .{ .err = error.InvalidSignature, .description = "Signature verification failed" },
    };

    for (tx_errors) |item| {
        const ctx = zigeth.ErrorContext.init("Transaction", "send")
            .withDetails(item.description);

        const formatted = try zigeth.errors.formatError(allocator, item.err, ctx);
        defer allocator.free(formatted);

        std.debug.print("{s}\n", .{formatted});
        std.debug.print("   → User message: {s}\n\n", .{
            zigeth.errors.Helpers.getUserMessage(item.err),
        });
    }
}

fn example5_error_recovery(allocator: std.mem.Allocator) !void {
    _ = allocator;
    std.debug.print("\n┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE 5: Error Recovery Patterns                                          │\n", .{});
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});

    std.debug.print("✅ Error Classification:\n\n", .{});

    // Test error classification
    const test_errors = [_]anyerror{
        error.NetworkError,
        error.Timeout,
        error.InvalidAddress,
        error.InsufficientFunds,
    };

    for (test_errors) |err| {
        std.debug.print("Error: {s}\n", .{@errorName(err)});
        std.debug.print("   • Network error? {}\n", .{zigeth.errors.Helpers.isNetworkError(err)});
        std.debug.print("   • RPC error? {}\n", .{zigeth.errors.Helpers.isRpcError(err)});
        std.debug.print("   • Validation error? {}\n", .{zigeth.errors.Helpers.isValidationError(err)});
        std.debug.print("   • Retryable? {}\n\n", .{zigeth.errors.Helpers.isRetryable(err)});
    }

    std.debug.print("💡 Usage in code:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("if (zigeth.errors.Helpers.isRetryable(err)) {{\n", .{});
    std.debug.print("    // Retry with exponential backoff\n", .{});
    std.debug.print("    return zigeth.errors.ErrorRecovery.retryWithBackoff(...);\n", .{});
    std.debug.print("}}\n", .{});
    std.debug.print("```\n", .{});
}

fn example6_production_reporting(allocator: std.mem.Allocator) !void {
    std.debug.print("\n┌─────────────────────────────────────────────────────────────────────────────┐\n", .{});
    std.debug.print("│ EXAMPLE 6: Production Error Reporting                                       │\n", .{});
    std.debug.print("└─────────────────────────────────────────────────────────────────────────────┘\n\n", .{});

    std.debug.print("✅ Production Error Reporter:\n\n", .{});

    // Initialize error reporter (in production, open actual log file)
    var reporter = zigeth.ErrorReporter.init(allocator, null);
    defer reporter.deinit();

    // Report various errors
    const errors_to_report = [_]struct {
        err: anyerror,
        module: []const u8,
        operation: []const u8,
        details: []const u8,
    }{
        .{
            .err = error.ConnectionFailed,
            .module = "Provider",
            .operation = "connect",
            .details = "Failed to connect to https://sepolia.etherspot.io",
        },
        .{
            .err = error.InvalidSignature,
            .module = "Transaction",
            .operation = "verify",
            .details = "ECDSA signature verification failed",
        },
        .{
            .err = error.PaymasterRejected,
            .module = "AccountAbstraction",
            .operation = "sponsorUserOperation",
            .details = "Paymaster rejected: insufficient deposit",
        },
    };

    std.debug.print("Simulated error reports:\n\n", .{});

    for (errors_to_report, 1..) |item, i| {
        const ctx = zigeth.ErrorContext.init(item.module, item.operation)
            .withDetails(item.details);

        std.debug.print("{}. ", .{i});
        try reporter.report(item.err, ctx);
        std.debug.print("\n", .{});
    }

    std.debug.print("\n💡 In production:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("// Open log file\n", .{});
    std.debug.print("const log_file = try std.fs.cwd().createFile(\"zigeth.log\", .{{}});\n", .{});
    std.debug.print("var reporter = zigeth.ErrorReporter.init(allocator, log_file);\n", .{});
    std.debug.print("defer reporter.deinit();\n\n", .{});
    std.debug.print("// Report errors (will write to file + stderr)\n", .{});
    std.debug.print("try reporter.report(err, context);\n", .{});
    std.debug.print("```\n", .{});
}
