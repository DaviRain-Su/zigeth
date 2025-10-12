const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;

/// Paymaster mode for sponsorship
pub const PaymasterMode = enum {
    sponsor, // Paymaster sponsors the entire operation
    erc20, // User pays with ERC-20 tokens
};

/// Paymaster client for interacting with paymasters
pub const PaymasterClient = struct {
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    api_key: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, rpc_url: []const u8, api_key: ?[]const u8) PaymasterClient {
        return .{
            .allocator = allocator,
            .rpc_url = rpc_url,
            .api_key = api_key,
        };
    }

    /// Get paymaster data for sponsorship (v0.6 format)
    /// Method: pm_sponsorUserOperation
    pub fn sponsorUserOperation(
        self: *PaymasterClient,
        user_op: *types.UserOperationV06,
        entry_point: primitives.Address,
        mode: PaymasterMode,
    ) !void {
        _ = self;
        _ = user_op;
        _ = entry_point;
        _ = mode;
        // TODO: Implement RPC call to paymaster
        // POST {"jsonrpc":"2.0","method":"pm_sponsorUserOperation","params":[userOp, entryPoint, {mode}],"id":1}
        // Response fills in: paymasterAndData, verificationGasLimit, preVerificationGas, callGasLimit
    }

    /// Get ERC-20 token quotes (v0.6 format)
    /// Method: pm_getERC20TokenQuotes
    pub fn getERC20TokenQuotes(
        self: *PaymasterClient,
        user_op: types.UserOperationV06,
        entry_point: primitives.Address,
        tokens: []const primitives.Address,
    ) ![]TokenQuote {
        _ = self;
        _ = user_op;
        _ = entry_point;
        _ = tokens;
        // TODO: Implement RPC call to paymaster
        return &[_]TokenQuote{};
    }

    /// Verify paymaster signature
    pub fn verifyPaymasterData(
        self: *PaymasterClient,
        paymaster_and_data: []const u8,
    ) !types.PaymasterData {
        // TODO: Parse and verify paymaster data
        return types.PaymasterData.unpack(paymaster_and_data, self.allocator);
    }
};

/// Token quote from paymaster
pub const TokenQuote = struct {
    token: primitives.Address,
    symbol: []const u8,
    decimals: u8,
    etherTokenExchangeRate: u256,
    serviceFeePercent: u8,
};

/// Paymaster and data parser
pub const PaymasterAndDataParser = struct {
    /// Parse paymaster address from paymasterAndData
    pub fn getPaymasterAddress(paymaster_and_data: []const u8) !primitives.Address {
        if (paymaster_and_data.len < 20) {
            return error.InvalidPaymasterData;
        }
        // First 20 bytes are the paymaster address
        var address_bytes: [20]u8 = undefined;
        @memcpy(&address_bytes, paymaster_and_data[0..20]);
        return primitives.Address.fromBytes(address_bytes);
    }

    /// Parse verification gas limit
    pub fn getVerificationGasLimit(paymaster_and_data: []const u8) !u256 {
        if (paymaster_and_data.len < 52) {
            return 0; // No paymaster verification gas specified
        }
        // Bytes 20-36 (16 bytes) for verification gas limit
        // TODO: Parse uint128 from bytes[20..36]
        return 0;
    }

    /// Parse post-op gas limit
    pub fn getPostOpGasLimit(paymaster_and_data: []const u8) !u256 {
        if (paymaster_and_data.len < 68) {
            return 0; // No post-op gas specified
        }
        // Bytes 36-52 (16 bytes) for post-op gas limit
        // TODO: Parse uint128 from bytes[36..52]
        return 0;
    }

    /// Get paymaster-specific data
    pub fn getPaymasterData(paymaster_and_data: []const u8) []const u8 {
        if (paymaster_and_data.len <= 52) {
            return &[_]u8{};
        }
        // Remaining bytes after address and gas limits
        return paymaster_and_data[52..];
    }
};

/// Paymaster stub signature helper
pub const PaymasterStub = struct {
    /// Create a stub signature for gas estimation
    /// This allows estimating gas before getting actual paymaster signature
    pub fn createStubSignature(allocator: std.mem.Allocator, paymaster: primitives.Address) ![]u8 {
        _ = allocator;
        _ = paymaster;
        // TODO: Create stub paymasterAndData for estimation
        // Format: paymaster_address (20 bytes) + validUntil (6 bytes) + validAfter (6 bytes) + signature (65 bytes)
        return &[_]u8{};
    }
};
