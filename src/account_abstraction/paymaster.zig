const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const rpc_mod = @import("../rpc/client.zig");

/// Paymaster mode for sponsorship
pub const PaymasterMode = enum {
    sponsor, // Paymaster sponsors the entire operation
    erc20, // User pays with ERC-20 tokens

    pub fn toString(self: PaymasterMode) []const u8 {
        return switch (self) {
            .sponsor => "SPONSOR",
            .erc20 => "ERC20",
        };
    }
};

/// Paymaster client for interacting with paymasters
/// Supports all EntryPoint versions (v0.6, v0.7, v0.8)
pub const PaymasterClient = struct {
    allocator: std.mem.Allocator,
    rpc_client: rpc_mod.RpcClient,
    api_key: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, rpc_url: []const u8, api_key: ?[]const u8) !PaymasterClient {
        return .{
            .allocator = allocator,
            .rpc_client = try rpc_mod.RpcClient.init(allocator, rpc_url),
            .api_key = api_key,
        };
    }

    pub fn deinit(self: *PaymasterClient) void {
        self.rpc_client.deinit();
    }

    /// Get paymaster data for sponsorship (supports v0.6, v0.7, v0.8)
    /// Method: pm_sponsorUserOperation
    /// Updates the UserOperation with paymaster data and gas estimates
    pub fn sponsorUserOperation(
        self: *PaymasterClient,
        user_op: anytype,
        entry_point: primitives.Address,
        mode: PaymasterMode,
    ) !void {
        // Validate UserOperation type at compile time
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != *types.UserOperationV06 and
                UserOpType != *types.UserOperationV07 and
                UserOpType != *types.UserOperationV08)
            {
                @compileError("user_op must be *UserOperationV06, *UserOperationV07, or *UserOperationV08");
            }
        }

        // Convert UserOperation to JSON
        const user_op_json = try types.UserOperationJson.fromUserOperation(self.allocator, user_op.*);
        defer user_op_json.deinit();

        // Convert EntryPoint to hex
        const entry_point_hex = try entry_point.toHex(self.allocator);
        defer self.allocator.free(entry_point_hex);

        // Build context object
        var context_obj = std.json.ObjectMap.init(self.allocator);
        defer context_obj.deinit();
        try context_obj.put("mode", .{ .string = mode.toString() });

        // Build params array: [userOp, entryPoint, context]
        var params_array = std.ArrayList(std.json.Value).init(self.allocator);
        defer params_array.deinit();

        const user_op_value = try std.json.Value.jsonStringify(user_op_json, .{}, self.allocator);
        defer if (user_op_value == .object) user_op_value.object.deinit();

        try params_array.append(user_op_value);
        try params_array.append(.{ .string = entry_point_hex });
        try params_array.append(.{ .object = context_obj });

        const params = std.json.Value{ .array = try params_array.toOwnedSlice() };
        defer params.array.deinit(self.allocator);

        // Make RPC call
        const response = try self.rpc_client.call("pm_sponsorUserOperation", params);
        defer response.deinit(self.allocator);

        // Parse response and update UserOperation
        const result_obj = response.object;

        // Update paymaster fields based on version
        if (UserOpType == *types.UserOperationV06) {
            // v0.6: paymasterAndData field
            if (result_obj.get("paymasterAndData")) |paymaster_data| {
                const hex_str = paymaster_data.string;
                user_op.paymasterAndData = try hexToBytes(self.allocator, hex_str);
            }
        } else {
            // v0.7/v0.8: separate paymaster, paymasterData, and gas limits
            if (result_obj.get("paymaster")) |pm_addr| {
                user_op.paymaster = try primitives.Address.fromHex(pm_addr.string);
            }
            if (result_obj.get("paymasterData")) |pm_data| {
                user_op.paymasterData = try hexToBytes(self.allocator, pm_data.string);
            }

            if (UserOpType == *types.UserOperationV07) {
                if (result_obj.get("paymasterVerificationGasLimit")) |gas| {
                    user_op.paymasterVerificationGasLimit = try parseHexU128(gas.string);
                }
                if (result_obj.get("paymasterPostOpGasLimit")) |gas| {
                    user_op.paymasterPostOpGasLimit = try parseHexU128(gas.string);
                }
            }
        }

        // Update gas estimates (common to all versions)
        if (result_obj.get("preVerificationGas")) |gas| {
            const pre_gas = try parseHexU256(gas.string);
            user_op.preVerificationGas = pre_gas;
        }
        if (result_obj.get("verificationGasLimit")) |gas| {
            const ver_gas = try parseHexU256(gas.string);
            if (UserOpType == *types.UserOperationV06) {
                user_op.verificationGasLimit = ver_gas;
            } else {
                user_op.verificationGasLimit = @intCast(ver_gas);
            }
        }
        if (result_obj.get("callGasLimit")) |gas| {
            const call_gas = try parseHexU256(gas.string);
            if (UserOpType == *types.UserOperationV06) {
                user_op.callGasLimit = call_gas;
            } else {
                user_op.callGasLimit = @intCast(call_gas);
            }
        }
    }

    /// Get ERC-20 token quotes (supports v0.6, v0.7, v0.8)
    /// Method: pm_getERC20TokenQuotes
    pub fn getERC20TokenQuotes(
        self: *PaymasterClient,
        user_op: anytype,
        entry_point: primitives.Address,
        tokens: []const primitives.Address,
    ) ![]TokenQuote {
        // Validate UserOperation type at compile time
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                @compileError("user_op must be UserOperationV06, UserOperationV07, or UserOperationV08");
            }
        }

        // Convert UserOperation to JSON
        const user_op_json = try types.UserOperationJson.fromUserOperation(self.allocator, user_op);
        defer user_op_json.deinit();

        // Convert EntryPoint to hex
        const entry_point_hex = try entry_point.toHex(self.allocator);
        defer self.allocator.free(entry_point_hex);

        // Convert token addresses to hex array
        var token_array = std.ArrayList(std.json.Value).init(self.allocator);
        defer token_array.deinit();

        for (tokens) |token| {
            const token_hex = try token.toHex(self.allocator);
            defer self.allocator.free(token_hex);
            try token_array.append(.{ .string = try self.allocator.dupe(u8, token_hex) });
        }

        // Build params array: [userOp, entryPoint, tokens]
        var params_array = std.ArrayList(std.json.Value).init(self.allocator);
        defer params_array.deinit();

        const user_op_value = try std.json.Value.jsonStringify(user_op_json, .{}, self.allocator);
        defer if (user_op_value == .object) user_op_value.object.deinit();

        try params_array.append(user_op_value);
        try params_array.append(.{ .string = entry_point_hex });
        try params_array.append(.{ .array = try token_array.toOwnedSlice() });

        const params = std.json.Value{ .array = try params_array.toOwnedSlice() };
        defer params.array.deinit(self.allocator);

        // Make RPC call
        const response = try self.rpc_client.call("pm_getERC20TokenQuotes", params);
        defer response.deinit(self.allocator);

        // Parse response array
        const quotes_array = response.array;
        var result = std.ArrayList(TokenQuote).init(self.allocator);
        errdefer result.deinit();

        for (quotes_array) |quote_value| {
            const quote_obj = quote_value.object;

            const token_addr = try primitives.Address.fromHex(quote_obj.get("token").?.string);
            const symbol = try self.allocator.dupe(u8, quote_obj.get("symbol").?.string);
            const decimals = @as(u8, @intCast(quote_obj.get("decimals").?.integer));
            const exchange_rate = try parseHexU256(quote_obj.get("etherTokenExchangeRate").?.string);
            const service_fee = @as(u8, @intCast(quote_obj.get("serviceFeePercent").?.integer));

            try result.append(TokenQuote{
                .token = token_addr,
                .symbol = symbol,
                .decimals = decimals,
                .etherTokenExchangeRate = exchange_rate,
                .serviceFeePercent = service_fee,
            });
        }

        return try result.toOwnedSlice();
    }

    /// Verify paymaster signature
    /// Parses paymasterAndData into structured PaymasterData
    pub fn verifyPaymasterData(
        self: *PaymasterClient,
        paymaster_and_data: []const u8,
    ) !types.PaymasterData {
        // Parse paymaster data using the parser
        const paymaster_addr = try PaymasterAndDataParser.getPaymasterAddress(paymaster_and_data);
        const verification_gas = try PaymasterAndDataParser.getVerificationGasLimit(paymaster_and_data);
        const post_op_gas = try PaymasterAndDataParser.getPostOpGasLimit(paymaster_and_data);
        const data = PaymasterAndDataParser.getPaymasterData(paymaster_and_data);

        return types.PaymasterData{
            .paymaster = paymaster_addr,
            .verificationGasLimit = verification_gas,
            .postOpGasLimit = post_op_gas,
            .data = try self.allocator.dupe(u8, data),
        };
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

    /// Parse verification gas limit (for v0.7+ format)
    pub fn getVerificationGasLimit(paymaster_and_data: []const u8) !u256 {
        if (paymaster_and_data.len < 36) {
            return 0; // No paymaster verification gas specified
        }
        // Bytes 20-36 (16 bytes) for verification gas limit (u128)
        var gas_bytes: [16]u8 = undefined;
        @memcpy(&gas_bytes, paymaster_and_data[20..36]);
        return std.mem.readInt(u128, &gas_bytes, .big);
    }

    /// Parse post-op gas limit (for v0.7+ format)
    pub fn getPostOpGasLimit(paymaster_and_data: []const u8) !u256 {
        if (paymaster_and_data.len < 52) {
            return 0; // No post-op gas specified
        }
        // Bytes 36-52 (16 bytes) for post-op gas limit (u128)
        var gas_bytes: [16]u8 = undefined;
        @memcpy(&gas_bytes, paymaster_and_data[36..52]);
        return std.mem.readInt(u128, &gas_bytes, .big);
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
    /// Create a stub signature for gas estimation (v0.6 format)
    /// This allows estimating gas before getting actual paymaster signature
    /// Format: paymaster_address (20 bytes) + validUntil (6 bytes) + validAfter (6 bytes) + signature (65 bytes)
    pub fn createStubSignature(allocator: std.mem.Allocator, paymaster: primitives.Address) ![]u8 {
        const stub_size = 20 + 6 + 6 + 65; // 97 bytes total
        const stub_data = try allocator.alloc(u8, stub_size);

        // Paymaster address (20 bytes)
        @memcpy(stub_data[0..20], &paymaster.bytes);

        // validUntil (6 bytes) - far future timestamp
        const valid_until: u48 = 0xFFFFFFFFFFFF;
        std.mem.writeInt(u48, stub_data[20..26][0..6], valid_until, .big);

        // validAfter (6 bytes) - current time (0 for testing)
        const valid_after: u48 = 0;
        std.mem.writeInt(u48, stub_data[26..32][0..6], valid_after, .big);

        // Stub signature (65 bytes) - dummy ECDSA signature
        // r (32 bytes)
        @memset(stub_data[32..64], 0xAA);
        // s (32 bytes)
        @memset(stub_data[64..96], 0xBB);
        // v (1 byte)
        stub_data[96] = 27;

        return stub_data;
    }

    /// Create stub signature for v0.7+ format
    /// Format: paymaster (20 bytes) + verificationGasLimit (16 bytes) + postOpGasLimit (16 bytes) + data
    pub fn createStubSignatureV07(
        allocator: std.mem.Allocator,
        paymaster: primitives.Address,
        verification_gas: u128,
        post_op_gas: u128,
    ) ![]u8 {
        const stub_size = 20 + 16 + 16 + 65; // 117 bytes
        const stub_data = try allocator.alloc(u8, stub_size);

        // Paymaster address (20 bytes)
        @memcpy(stub_data[0..20], &paymaster.bytes);

        // verificationGasLimit (16 bytes)
        std.mem.writeInt(u128, stub_data[20..36][0..16], verification_gas, .big);

        // postOpGasLimit (16 bytes)
        std.mem.writeInt(u128, stub_data[36..52][0..16], post_op_gas, .big);

        // Stub signature (65 bytes)
        @memset(stub_data[52..84], 0xAA); // r
        @memset(stub_data[84..116], 0xBB); // s
        stub_data[116] = 27; // v

        return stub_data;
    }
};

// Helper functions

/// Convert hex string to bytes
fn hexToBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    // Remove "0x" prefix if present
    const hex = if (std.mem.startsWith(u8, hex_str, "0x"))
        hex_str[2..]
    else
        hex_str;

    if (hex.len % 2 != 0) {
        return error.InvalidHexLength;
    }

    const byte_len = hex.len / 2;
    const bytes = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(bytes);

    for (0..byte_len) |i| {
        bytes[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }

    return bytes;
}

/// Parse hex string to u256
fn parseHexU256(hex_str: []const u8) !u256 {
    const hex = if (std.mem.startsWith(u8, hex_str, "0x"))
        hex_str[2..]
    else
        hex_str;

    return try std.fmt.parseInt(u256, hex, 16);
}

/// Parse hex string to u128
fn parseHexU128(hex_str: []const u8) !u128 {
    const hex = if (std.mem.startsWith(u8, hex_str, "0x"))
        hex_str[2..]
    else
        hex_str;

    return try std.fmt.parseInt(u128, hex, 16);
}
