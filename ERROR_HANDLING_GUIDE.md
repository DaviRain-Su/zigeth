# Error Handling Guide for Zigeth

This guide provides best practices and patterns for error handling in Zigeth applications.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Error Sets](#error-sets)
3. [Error Context](#error-context)
4. [Error Formatting](#error-formatting)
5. [Module-Specific Errors](#module-specific-errors)
6. [Error Recovery](#error-recovery)
7. [Production Reporting](#production-reporting)
8. [Best Practices](#best-practices)
9. [Common Patterns](#common-patterns)

---

## Overview

Zigeth provides a comprehensive error handling system with:

- **Standardized error sets** for consistent error types across modules
- **Error context** for debugging with module, operation, and details
- **Multiple output formats** (JSON, text, log) for different use cases
- **Error classification** helpers for recovery strategies
- **Production-ready** error reporting with file logging

## Error Sets

### Core Zigeth Errors

```zig
const zigeth = @import("zigeth");

// Common errors across all modules
pub const ZigethError = error{
    // General
    OutOfMemory,
    Unexpected,
    InvalidInput,
    NotImplemented,
    
    // Network
    NetworkError,
    ConnectionFailed,
    Timeout,
    
    // Blockchain
    BlockNotFound,
    TransactionNotFound,
    ContractNotFound,
    
    // Validation
    InvalidAddress,
    InvalidHash,
    InvalidSignature,
    
    // ...and more
};
```

### Module-Specific Error Sets

| Error Set | Module | Common Errors |
|-----------|--------|---------------|
| `RpcErrors` | RPC Client | ConnectionFailed, Timeout, InvalidResponse |
| `TransactionErrors` | Transactions | InsufficientFunds, NonceTooLow, GasTooLow |
| `ContractErrors` | Smart Contracts | ContractNotFound, AbiEncodingFailed |
| `WalletErrors` | Wallets | InvalidPrivateKey, InvalidMnemonic, WalletLocked |
| `AccountAbstractionErrors` | ERC-4337 | PaymasterRejected, InvalidUserOperation |

## Error Context

Add context to errors for better debugging:

```zig
const ctx = zigeth.ErrorContext.init("RPC", "eth_getBlockByNumber");
const ctx_with_details = ctx.withDetails("Block 999999999 not found");
const ctx_with_code = ctx_with_details.withCode(-32000);

// Log with context
zigeth.errors.logError(error.BlockNotFound, ctx_with_code);

// Format with context
const formatted = try zigeth.errors.formatError(allocator, error.BlockNotFound, ctx_with_code);
defer allocator.free(formatted);
std.debug.print("{s}\n", .{formatted});
```

Output:
```
[RPC] Error -32000: eth_getBlockByNumber failed: BlockNotFound
  Details: Block 999999999 not found
```

## Error Formatting

### JSON Format (for APIs)

```zig
const formatter = zigeth.ErrorFormatter.init(allocator, false);
const json = try formatter.toJson(error.NetworkError, context);
defer allocator.free(json);

// Returns:
// {"error":"NetworkError","module":"Provider","operation":"getBalance","details":"...","code":-1}
```

**Use case**: REST APIs, structured logging systems, error tracking services

### Text Format (for CLI/users)

```zig
const formatter = zigeth.ErrorFormatter.init(allocator, true); // with colors
const text = try formatter.toText(error.InsufficientFunds, context);
defer allocator.free(text);

// Returns (with ANSI colors):
// ❌ Error in Transaction.send: InsufficientFunds
//    Details: Sender doesn't have enough ETH
```

**Use case**: Command-line applications, user interfaces, error messages

### Log Format (for log files)

```zig
const log_entry = try formatter.toLog(error.PaymasterRejected, context);
defer allocator.free(log_entry);

// Returns:
// [ERROR] PaymasterRejected module=AccountAbstraction operation=sponsorUserOperation details="..."
```

**Use case**: Application logs, monitoring systems, audit trails

## Module-Specific Errors

### RPC Errors

```zig
// Try RPC call
const result = provider.getBlockByNumber(block_num) catch |err| {
    const ctx = zigeth.ErrorContext.init("RPC", "getBlockByNumber")
        .withDetails("Failed to fetch block");
    
    if (zigeth.errors.Helpers.isRpcError(err)) {
        // Handle RPC-specific errors
        std.log.err("RPC call failed, check endpoint", .{});
    }
    
    zigeth.errors.logError(err, ctx);
    return err;
};
```

### Transaction Errors

```zig
// Send transaction
const tx_hash = provider.sendTransaction(signed_tx) catch |err| {
    const ctx = zigeth.ErrorContext.init("Transaction", "send");
    
    switch (err) {
        error.InsufficientFunds => {
            std.log.err("Not enough ETH for transaction", .{});
            // Suggest user add funds
        },
        error.NonceTooLow => {
            std.log.err("Nonce conflict, refreshing...", .{});
            // Retry with updated nonce
        },
        error.GasTooLow => {
            std.log.err("Gas limit too low, increasing...", .{});
            // Retry with higher gas
        },
        else => {
            zigeth.errors.logError(err, ctx);
        },
    }
    
    return err;
};
```

### Account Abstraction Errors

```zig
// Sponsor UserOperation
paymaster.sponsorUserOperation(&user_op, entry_point, .sponsor) catch |err| {
    const ctx = zigeth.ErrorContext.init("AccountAbstraction", "sponsorUserOperation");
    
    switch (err) {
        error.PaymasterRejected => {
            std.log.err("Paymaster rejected sponsorship", .{});
            // Fallback to ERC-20 payment or user-paid gas
        },
        error.InvalidUserOperation => {
            std.log.err("UserOperation validation failed", .{});
            // Check gas limits, nonce, signature
        },
        else => {
            zigeth.errors.logError(err, ctx);
        },
    }
    
    return err;
};
```

## Error Recovery

### Retry with Exponential Backoff

```zig
const result = try zigeth.errors.ErrorRecovery.retryWithBackoff(
    BlockType,
    getBlockOperation,
    3, // max retries
    1000, // initial delay: 1 second
);

// Retries: 1s → 2s → 4s
// Logs warnings on each retry
// Returns error if all retries fail
```

### Try with Fallback

```zig
// Try primary RPC, fallback to secondary
const balance = try zigeth.errors.ErrorRecovery.tryWithFallback(
    u256,
    primary_provider.getBalance(address),
    secondary_provider.getBalance(address),
);
```

### Conditional Retry

```zig
const result = operation() catch |err| {
    if (zigeth.errors.Helpers.isRetryable(err)) {
        // Retry transient errors
        return try retryOperation();
    }
    
    // Don't retry permanent errors
    return err;
};
```

## Production Reporting

### Setup Error Reporter

```zig
// Initialize with log file
const log_file = try std.fs.cwd().createFile("zigeth.log", .{
    .truncate = false, // Append mode
});

var reporter = zigeth.ErrorReporter.init(allocator, log_file);
defer reporter.deinit();
```

### Report Errors

```zig
// Simple reporting
try reporter.report(err, context);

// With stack trace (debug builds only)
try reporter.reportWithTrace(err, context);
```

### Example Production Handler

```zig
pub fn handleError(
    reporter: *zigeth.ErrorReporter,
    err: anyerror,
    module: []const u8,
    operation: []const u8,
) void {
    const ctx = zigeth.ErrorContext.init(module, operation);
    
    // Log to file and stderr
    reporter.report(err, ctx) catch |report_err| {
        std.log.err("Failed to report error: {s}", .{@errorName(report_err)});
    };
    
    // Show user-friendly message
    const user_msg = zigeth.errors.Helpers.getUserMessage(err);
    std.debug.print("\n⚠️  {s}\n", .{user_msg});
    
    // Decide on recovery strategy
    if (zigeth.errors.Helpers.isRetryable(err)) {
        std.debug.print("   Retrying operation...\n", .{});
    } else {
        std.debug.print("   Please check your input and try again.\n", .{});
    }
}
```

## Best Practices

### 1. Always Add Context

❌ **Bad**:
```zig
const balance = try provider.getBalance(address);
```

✅ **Good**:
```zig
const balance = provider.getBalance(address) catch |err| {
    const ctx = zigeth.ErrorContext.init("Provider", "getBalance")
        .withDetails("Failed to query balance for user");
    zigeth.errors.logError(err, ctx);
    return err;
};
```

### 2. Use Module-Specific Error Sets

❌ **Bad**:
```zig
pub fn sendTransaction(tx: Transaction) !Hash {
    // Returns generic errors
}
```

✅ **Good**:
```zig
pub fn sendTransaction(tx: Transaction) zigeth.TransactionErrors!Hash {
    // Returns specific error set
}
```

### 3. Classify and Handle Appropriately

```zig
const result = operation() catch |err| {
    // Network errors → retry
    if (zigeth.errors.Helpers.isNetworkError(err)) {
        return try retryOperation();
    }
    
    // Validation errors → return immediately (user input issue)
    if (zigeth.errors.Helpers.isValidationError(err)) {
        std.log.err("Invalid input: {s}", .{@errorName(err)});
        return err;
    }
    
    // Unknown errors → log and return
    zigeth.errors.logError(err, context);
    return err;
};
```

### 4. Provide User-Friendly Messages

```zig
const result = operation() catch |err| {
    // Technical logging
    zigeth.errors.logError(err, context);
    
    // User-friendly display
    const user_msg = zigeth.errors.Helpers.getUserMessage(err);
    std.debug.print("Error: {s}\n", .{user_msg});
    
    return err;
};
```

### 5. Use Error Reporter in Production

```zig
// Setup once at application start
var error_reporter = zigeth.ErrorReporter.init(allocator, log_file);
defer error_reporter.deinit();

// Use throughout application
if (operation()) |_| {
    // Success
} else |err| {
    try error_reporter.report(err, context);
    // Handle error
}
```

## Common Patterns

### Pattern 1: Try-Catch with Context

```zig
pub fn getBalance(self: *Provider, address: Address) !u256 {
    return self.rpc.call("eth_getBalance", params) catch |err| {
        const ctx = zigeth.ErrorContext.init("Provider", "getBalance")
            .withDetails("RPC call failed");
        return zigeth.errors.wrapError(err, ctx);
    };
}
```

### Pattern 2: Retry Transient Errors

```zig
pub fn robustCall(provider: *Provider, method: []const u8, params: anytype) !std.json.Value {
    var retries: u32 = 0;
    const max_retries = 3;
    
    while (retries < max_retries) : (retries += 1) {
        const result = provider.call(method, params) catch |err| {
            if (zigeth.errors.Helpers.isRetryable(err) and retries < max_retries - 1) {
                std.log.warn("Attempt {}/{} failed, retrying...", .{ retries + 1, max_retries });
                std.time.sleep(1 * std.time.ns_per_s);
                continue;
            }
            return err;
        };
        
        return result;
    }
    
    return error.MaxRetriesExceeded;
}
```

### Pattern 3: Fallback Providers

```zig
pub fn getBalanceWithFallback(
    primary: *Provider,
    fallback: *Provider,
    address: Address,
) !u256 {
    return zigeth.errors.ErrorRecovery.tryWithFallback(
        u256,
        primary.getBalance(address),
        fallback.getBalance(address),
    );
}
```

### Pattern 4: Comprehensive Error Handler

```zig
pub fn handleOperationError(
    err: anyerror,
    reporter: *zigeth.ErrorReporter,
    context: zigeth.ErrorContext,
) void {
    // Report to log
    reporter.report(err, context) catch {};
    
    // Classify error
    if (zigeth.errors.Helpers.isNetworkError(err)) {
        std.debug.print("⚠️  Network issue detected. Checking connection...\n", .{});
    } else if (zigeth.errors.Helpers.isValidationError(err)) {
        std.debug.print("⚠️  Validation failed. Please check your input.\n", .{});
    } else {
        std.debug.print("⚠️  {s}\n", .{zigeth.errors.Helpers.getUserMessage(err)});
    }
}
```

## Examples

See [`examples/10_error_handling.zig`](examples/10_error_handling.zig) for comprehensive examples demonstrating:

1. **Basic Error Context** - Creating and using error contexts
2. **Error Formatting** - JSON, text, and log formats
3. **RPC Error Handling** - Network and protocol errors
4. **Transaction Errors** - Common transaction failure scenarios
5. **Error Recovery** - Retry strategies and fallbacks
6. **Production Reporting** - File logging and monitoring

## Quick Reference

### Create Error Context

```zig
const ctx = zigeth.ErrorContext.init("ModuleName", "operationName")
    .withDetails("Additional information")
    .withCode(-32000);
```

### Format Error

```zig
// For APIs
const json = try formatter.toJson(err, ctx);

// For users
const text = try formatter.toText(err, ctx);

// For logs
const log_entry = try formatter.toLog(err, ctx);
```

### Classify Error

```zig
if (zigeth.errors.Helpers.isNetworkError(err)) { /* retry */ }
if (zigeth.errors.Helpers.isValidationError(err)) { /* return */ }
if (zigeth.errors.Helpers.isRetryable(err)) { /* retry with backoff */ }
```

### Get User Message

```zig
const msg = zigeth.errors.Helpers.getUserMessage(err);
std.debug.print("{s}\n", .{msg});
```

### Report to Production System

```zig
var reporter = zigeth.ErrorReporter.init(allocator, log_file);
defer reporter.deinit();

try reporter.report(err, context);
```

## Integration with Existing Code

### Updating Existing Functions

**Before**:
```zig
pub fn getBalance(self: *Provider, address: Address) !u256 {
    const result = try self.rpc.call("eth_getBalance", params);
    return parseBalance(result);
}
```

**After**:
```zig
pub fn getBalance(self: *Provider, address: Address) !u256 {
    const result = self.rpc.call("eth_getBalance", params) catch |err| {
        const ctx = zigeth.ErrorContext.init("Provider", "getBalance");
        zigeth.errors.logError(err, ctx);
        return err;
    };
    
    return parseBalance(result) catch |err| {
        const ctx = zigeth.ErrorContext.init("Provider", "parseBalance")
            .withDetails("Failed to parse balance from RPC response");
        zigeth.errors.logError(err, ctx);
        return err;
    };
}
```

## Testing Error Handling

```zig
test "error context and formatting" {
    const allocator = std.testing.allocator;
    
    const ctx = zigeth.ErrorContext.init("Test", "operation")
        .withDetails("Test error");
    
    const formatted = try zigeth.errors.formatError(
        allocator,
        error.InvalidInput,
        ctx,
    );
    defer allocator.free(formatted);
    
    try std.testing.expect(std.mem.indexOf(u8, formatted, "Test") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "InvalidInput") != null);
}

test "error helpers" {
    try std.testing.expect(zigeth.errors.Helpers.isNetworkError(error.Timeout));
    try std.testing.expect(zigeth.errors.Helpers.isRetryable(error.NonceTooLow));
    try std.testing.expect(!zigeth.errors.Helpers.isRetryable(error.InvalidAddress));
}
```

## Performance Considerations

### Error Context

- **Lightweight**: Error context is just a struct with pointers
- **Zero allocation**: Creating context doesn't allocate memory
- **Optional**: Can be null for simple cases

### Error Formatting

- **Allocates**: Formatting creates a new string (remember to free!)
- **Use sparingly**: Only format when displaying/logging
- **Cache if repeated**: Don't format same error multiple times

### Logging

- **Structured**: Use log format for parsing
- **Buffered I/O**: Error reporter uses buffered writes
- **Async option**: Consider async logging for high-throughput apps

## Migration Guide

### Step 1: Add Centralized Errors

```zig
// In your project's main file
const zigeth = @import("zigeth");

pub const ProjectErrors = error{
    // Project-specific errors
    ConfigurationError,
    DatabaseError,
} || zigeth.ZigethError;
```

### Step 2: Update Error Returns

```zig
// Old
pub fn operation() !Result {
    return error.SomeError;
}

// New
pub fn operation() ProjectErrors!Result {
    const ctx = zigeth.ErrorContext.init("Module", "operation");
    return zigeth.errors.wrapError(error.SomeError, ctx);
}
```

### Step 3: Add Error Reporter

```zig
// Application initialization
var error_reporter = zigeth.ErrorReporter.init(allocator, log_file);
defer error_reporter.deinit();

// Pass to modules that need it
try myModule.init(allocator, &error_reporter);
```

### Step 4: Update Error Handlers

```zig
// Replace generic catches
operation() catch |err| {
    std.log.err("Error: {s}", .{@errorName(err)});
    return err;
};

// With contextual catches
operation() catch |err| {
    const ctx = zigeth.ErrorContext.init("Module", "operation");
    try error_reporter.report(err, ctx);
    
    if (zigeth.errors.Helpers.isRetryable(err)) {
        return try retryOperation();
    }
    
    return err;
};
```

## Common Error Scenarios

### Scenario 1: Network Failure

```zig
const balance = provider.getBalance(address) catch |err| {
    if (zigeth.errors.Helpers.isNetworkError(err)) {
        std.debug.print("⚠️  Network error. Retrying with fallback provider...\n", .{});
        return try fallback_provider.getBalance(address);
    }
    return err;
};
```

### Scenario 2: Invalid User Input

```zig
const address = zigeth.primitives.Address.fromHex(user_input) catch |err| {
    if (err == error.InvalidAddress or err == error.InvalidHexLength) {
        const msg = zigeth.errors.Helpers.getUserMessage(err);
        std.debug.print("❌ {s}\n", .{msg});
        std.debug.print("   Please enter a valid Ethereum address (0x...)\n", .{});
        return err;
    }
    return err;
};
```

### Scenario 3: RPC Error with Code

```zig
const block = provider.getBlockByNumber(block_num) catch |err| {
    // RPC returned error with code
    const ctx = zigeth.ErrorContext.init("RPC", "getBlockByNumber")
        .withCode(-32000) // From JSON-RPC error
        .withDetails("Block not found or not finalized yet");
    
    try error_reporter.report(err, ctx);
    
    std.debug.print("Block #{} not available yet. Try a lower block number.\n", .{block_num});
    return err;
};
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                             │
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐ │
│  │   Provider   │      │  Transaction │      │   Contract   │ │
│  │   Module     │      │    Module    │      │    Module    │ │
│  └──────┬───────┘      └──────┬───────┘      └──────┬───────┘ │
│         │                     │                     │          │
│         └─────────────────────┼─────────────────────┘          │
│                               │                                │
│                    ┌──────────▼───────────┐                    │
│                    │   errors.zig         │                    │
│                    │  - Error Sets        │                    │
│                    │  - Error Context     │                    │
│                    │  - ErrorFormatter    │                    │
│                    │  - ErrorReporter     │                    │
│                    │  - Helpers           │                    │
│                    └──────────┬───────────┘                    │
│                               │                                │
│         ┌─────────────────────┼─────────────────────┐          │
│         │                     │                     │          │
│  ┌──────▼───────┐     ┌──────▼───────┐     ┌──────▼───────┐  │
│  │ stdout/stderr│     │  Log File    │     │   Monitoring │  │
│  │  (Console)   │     │  (File)      │     │   Service    │  │
│  └──────────────┘     └──────────────┘     └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Summary

✅ **Consistent**: Standard error types across all modules  
✅ **Contextual**: Rich error information for debugging  
✅ **Flexible**: Multiple output formats (JSON, text, log)  
✅ **Actionable**: Error classification for recovery strategies  
✅ **Production-Ready**: File logging and monitoring integration  
✅ **User-Friendly**: Clear messages for end users  

See `examples/10_error_handling.zig` for working code examples!

