const std = @import("std");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const hex_utils = @import("../utils/hex.zig");

/// EntryPoint version
pub const EntryPointVersion = enum {
    v0_6,
    v0_7,
    v0_8,
};

/// ERC-4337 UserOperation structure (v0.6)
/// Reference: https://eips.ethereum.org/EIPS/eip-4337
/// Used with EntryPoint v0.6: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
pub const UserOperationV06 = struct {
    sender: primitives.Address,
    nonce: u256,
    initCode: []const u8,
    callData: []const u8,
    callGasLimit: u256,
    verificationGasLimit: u256,
    preVerificationGas: u256,
    maxFeePerGas: u256,
    maxPriorityFeePerGas: u256,
    paymasterAndData: []const u8,
    signature: []const u8,

    /// Calculate UserOperation hash for signing
    pub fn hash(self: UserOperationV06, allocator: std.mem.Allocator, entry_point: primitives.Address, chain_id: u64) !Hash {
        // Use the utils module for hash calculation
        const utils = @import("utils.zig");
        return try utils.UserOpHash.calculate(
            allocator,
            self,
            entry_point,
            chain_id,
        );
    }

    /// Validate UserOperation fields
    pub fn validate(self: UserOperationV06) !void {
        if (self.sender.isZero()) {
            return error.InvalidSender;
        }
        if (self.callGasLimit == 0 and self.callData.len > 0) {
            return error.InvalidCallGasLimit;
        }
        if (self.verificationGasLimit == 0) {
            return error.InvalidVerificationGasLimit;
        }
        if (self.maxFeePerGas == 0) {
            return error.InvalidMaxFeePerGas;
        }
    }
};

/// ERC-4337 UserOperation structure (v0.7 - Packed)
/// Reference: https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.7.0
/// Used with EntryPoint v0.7: 0x0000000071727De22E5E9d8BAf0edAc6f37da032
/// Gas-optimized packed format
pub const UserOperationV07 = struct {
    sender: primitives.Address,
    nonce: u256,
    factory: ?primitives.Address, // Replaces initCode (address only)
    factoryData: []const u8, // Factory calldata (separated from address)
    callData: []const u8,
    callGasLimit: u128, // Reduced from u256
    verificationGasLimit: u128, // Reduced from u256
    preVerificationGas: u256,
    maxFeePerGas: u128, // Reduced from u256
    maxPriorityFeePerGas: u128, // Reduced from u256
    paymaster: ?primitives.Address, // Replaces paymasterAndData (address only)
    paymasterVerificationGasLimit: u128, // Explicit field
    paymasterPostOpGasLimit: u128, // Explicit field
    paymasterData: []const u8, // Paymaster-specific data
    signature: []const u8,

    /// Convert to v0.6 format
    pub fn toV06(self: UserOperationV07, allocator: std.mem.Allocator) !UserOperationV06 {
        // Combine factory + factoryData into initCode
        var init_code = try std.ArrayList(u8).initCapacity(allocator, 0);
        errdefer init_code.deinit(allocator);

        if (self.factory) |factory| {
            // Format: factory_address (20 bytes) ++ factoryData
            try init_code.appendSlice(allocator, &factory.bytes);
            try init_code.appendSlice(allocator, self.factoryData);
        }

        const init_code_slice = try init_code.toOwnedSlice(allocator);

        // Combine paymaster fields into paymasterAndData
        var paymaster_and_data = try std.ArrayList(u8).initCapacity(allocator, 0);
        errdefer paymaster_and_data.deinit(allocator);

        if (self.paymaster) |paymaster| {
            // Format: paymaster_address (20 bytes) ++ verificationGasLimit (16 bytes) ++ postOpGasLimit (16 bytes) ++ paymasterData
            try paymaster_and_data.appendSlice(allocator, &paymaster.bytes);

            // Encode verification gas limit (u128, 16 bytes)
            var ver_gas_bytes: [16]u8 = undefined;
            std.mem.writeInt(u128, &ver_gas_bytes, self.paymasterVerificationGasLimit, .big);
            try paymaster_and_data.appendSlice(allocator, &ver_gas_bytes);

            // Encode post-op gas limit (u128, 16 bytes)
            var post_gas_bytes: [16]u8 = undefined;
            std.mem.writeInt(u128, &post_gas_bytes, self.paymasterPostOpGasLimit, .big);
            try paymaster_and_data.appendSlice(allocator, &post_gas_bytes);

            // Append paymaster-specific data
            try paymaster_and_data.appendSlice(allocator, self.paymasterData);
        }

        const paymaster_and_data_slice = try paymaster_and_data.toOwnedSlice(allocator);

        return UserOperationV06{
            .sender = self.sender,
            .nonce = self.nonce,
            .initCode = init_code_slice,
            .callData = self.callData,
            .callGasLimit = @intCast(self.callGasLimit),
            .verificationGasLimit = @intCast(self.verificationGasLimit),
            .preVerificationGas = self.preVerificationGas,
            .maxFeePerGas = @intCast(self.maxFeePerGas),
            .maxPriorityFeePerGas = @intCast(self.maxPriorityFeePerGas),
            .paymasterAndData = paymaster_and_data_slice,
            .signature = self.signature,
        };
    }

    /// Validate UserOperation fields
    pub fn validate(self: UserOperationV07) !void {
        if (self.sender.isZero()) {
            return error.InvalidSender;
        }
        if (self.callGasLimit == 0 and self.callData.len > 0) {
            return error.InvalidCallGasLimit;
        }
        if (self.verificationGasLimit == 0) {
            return error.InvalidVerificationGasLimit;
        }
        if (self.maxFeePerGas == 0) {
            return error.InvalidMaxFeePerGas;
        }
    }
};

/// ERC-4337 UserOperation structure (v0.8 - Future)
/// Placeholder for future EntryPoint v0.8
/// May include additional optimizations and features
pub const UserOperationV08 = struct {
    // v0.8 may include further optimizations
    // For now, use v0.7 structure as base
    sender: primitives.Address,
    nonce: u256,
    factory: ?primitives.Address,
    factoryData: []const u8,
    callData: []const u8,
    callGasLimit: u128,
    verificationGasLimit: u128,
    preVerificationGas: u256,
    maxFeePerGas: u128,
    maxPriorityFeePerGas: u128,
    paymaster: ?primitives.Address,
    paymasterVerificationGasLimit: u128,
    paymasterPostOpGasLimit: u128,
    paymasterData: []const u8,
    signature: []const u8,

    /// Validate UserOperation fields
    pub fn validate(self: UserOperationV08) !void {
        if (self.sender.isZero()) {
            return error.InvalidSender;
        }
        if (self.callGasLimit == 0 and self.callData.len > 0) {
            return error.InvalidCallGasLimit;
        }
        if (self.verificationGasLimit == 0) {
            return error.InvalidVerificationGasLimit;
        }
        if (self.maxFeePerGas == 0) {
            return error.InvalidMaxFeePerGas;
        }
    }
};

/// Default UserOperation type (v0.6 for compatibility)
pub const UserOperation = UserOperationV06;

/// ERC-4337 UserOperation (JSON-RPC format)
/// Used for serialization/deserialization
pub const UserOperationJson = struct {
    sender: []const u8,
    nonce: []const u8,
    initCode: []const u8,
    callData: []const u8,
    callGasLimit: []const u8,
    verificationGasLimit: []const u8,
    preVerificationGas: []const u8,
    maxFeePerGas: []const u8,
    maxPriorityFeePerGas: []const u8,
    paymasterAndData: []const u8,
    signature: []const u8,

    /// Convert from UserOperation (any version) to JSON format
    /// Supports v0.6, v0.7, and v0.8
    pub fn fromUserOperation(allocator: std.mem.Allocator, user_op: anytype) !UserOperationJson {
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != UserOperationV06 and
                UserOpType != UserOperationV07 and
                UserOpType != UserOperationV08)
            {
                @compileError("user_op must be UserOperationV06, V07, or V08");
            }
        }

        // Convert address to hex string
        const sender_hex = try user_op.sender.toHex(allocator);

        // Convert nonce to hex string
        const nonce_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{user_op.nonce});

        // Convert call data to hex
        const call_data_hex = try bytesToHex(allocator, user_op.callData);
        const signature_hex = try bytesToHex(allocator, user_op.signature);

        // Version-specific field handling
        var init_code_hex: []const u8 = undefined;
        var paymaster_and_data_hex: []const u8 = undefined;

        if (UserOpType == UserOperationV06) {
            // v0.6: direct fields
            init_code_hex = try bytesToHex(allocator, user_op.initCode);
            paymaster_and_data_hex = try bytesToHex(allocator, user_op.paymasterAndData);
        } else {
            // v0.7/v0.8: need to combine fields
            // Combine factory + factoryData into initCode
            if (user_op.factory) |factory| {
                var init_code_data = try std.ArrayList(u8).initCapacity(allocator, 0);
                errdefer init_code_data.deinit(allocator);
                try init_code_data.appendSlice(allocator, &factory.bytes);
                try init_code_data.appendSlice(allocator, user_op.factoryData);
                const init_code_bytes = try init_code_data.toOwnedSlice(allocator);
                defer allocator.free(init_code_bytes);
                init_code_hex = try bytesToHex(allocator, init_code_bytes);
            } else {
                init_code_hex = try bytesToHex(allocator, &[_]u8{});
            }

            // Combine paymaster fields into paymasterAndData
            if (user_op.paymaster) |paymaster| {
                var paymaster_data = try std.ArrayList(u8).initCapacity(allocator, 0);
                errdefer paymaster_data.deinit(allocator);
                try paymaster_data.appendSlice(allocator, &paymaster.bytes);

                // Add verification gas limit (16 bytes, u128)
                var ver_gas_bytes: [16]u8 = undefined;
                std.mem.writeInt(u128, &ver_gas_bytes, user_op.paymasterVerificationGasLimit, .big);
                try paymaster_data.appendSlice(allocator, &ver_gas_bytes);

                // Add post-op gas limit (16 bytes, u128)
                var post_gas_bytes: [16]u8 = undefined;
                std.mem.writeInt(u128, &post_gas_bytes, user_op.paymasterPostOpGasLimit, .big);
                try paymaster_data.appendSlice(allocator, &post_gas_bytes);

                // Add paymaster-specific data
                try paymaster_data.appendSlice(allocator, user_op.paymasterData);

                const paymaster_bytes = try paymaster_data.toOwnedSlice(allocator);
                defer allocator.free(paymaster_bytes);
                paymaster_and_data_hex = try bytesToHex(allocator, paymaster_bytes);
            } else {
                paymaster_and_data_hex = try bytesToHex(allocator, &[_]u8{});
            }
        }

        // Convert gas values to hex strings
        const call_gas_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{user_op.callGasLimit});
        const verification_gas_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{user_op.verificationGasLimit});
        const pre_verification_gas_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{user_op.preVerificationGas});
        const max_fee_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{user_op.maxFeePerGas});
        const max_priority_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{user_op.maxPriorityFeePerGas});

        return UserOperationJson{
            .sender = sender_hex,
            .nonce = nonce_hex,
            .initCode = init_code_hex,
            .callData = call_data_hex,
            .callGasLimit = call_gas_hex,
            .verificationGasLimit = verification_gas_hex,
            .preVerificationGas = pre_verification_gas_hex,
            .maxFeePerGas = max_fee_hex,
            .maxPriorityFeePerGas = max_priority_hex,
            .paymasterAndData = paymaster_and_data_hex,
            .signature = signature_hex,
        };
    }

    pub fn deinit(self: UserOperationJson, allocator: std.mem.Allocator) void {
        allocator.free(self.sender);
        allocator.free(self.nonce);
        allocator.free(self.initCode);
        allocator.free(self.callData);
        allocator.free(self.callGasLimit);
        allocator.free(self.verificationGasLimit);
        allocator.free(self.preVerificationGas);
        allocator.free(self.maxFeePerGas);
        allocator.free(self.maxPriorityFeePerGas);
        allocator.free(self.paymasterAndData);
        allocator.free(self.signature);
    }

    /// Convert from JSON format to UserOperation (v0.6)
    pub fn toUserOperation(self: UserOperationJson, allocator: std.mem.Allocator) !UserOperationV06 {
        // Parse address from hex
        const sender = try primitives.Address.fromHex(self.sender);

        // Parse nonce from hex
        const nonce = try parseHexU256(self.nonce);

        // Parse bytes from hex
        const init_code = try hexToBytes(allocator, self.initCode);
        const call_data = try hexToBytes(allocator, self.callData);
        const paymaster_and_data = try hexToBytes(allocator, self.paymasterAndData);
        const signature = try hexToBytes(allocator, self.signature);

        // Parse gas values from hex
        const call_gas_limit = try parseHexU256(self.callGasLimit);
        const verification_gas_limit = try parseHexU256(self.verificationGasLimit);
        const pre_verification_gas = try parseHexU256(self.preVerificationGas);
        const max_fee_per_gas = try parseHexU256(self.maxFeePerGas);
        const max_priority_fee_per_gas = try parseHexU256(self.maxPriorityFeePerGas);

        return UserOperationV06{
            .sender = sender,
            .nonce = nonce,
            .initCode = init_code,
            .callData = call_data,
            .callGasLimit = call_gas_limit,
            .verificationGasLimit = verification_gas_limit,
            .preVerificationGas = pre_verification_gas,
            .maxFeePerGas = max_fee_per_gas,
            .maxPriorityFeePerGas = max_priority_fee_per_gas,
            .paymasterAndData = paymaster_and_data,
            .signature = signature,
        };
    }
};

/// UserOperation receipt
pub const UserOperationReceipt = struct {
    userOpHash: Hash,
    entryPoint: primitives.Address,
    sender: primitives.Address,
    nonce: u256,
    paymaster: ?primitives.Address,
    actualGasCost: u256,
    actualGasUsed: u256,
    success: bool,
    reason: ?[]const u8,
    logs: []const Log,
};

/// UserOperation event log
pub const Log = struct {
    address: primitives.Address,
    topics: []const Hash,
    data: []const u8,
    blockNumber: u64,
    blockHash: Hash,
    transactionHash: Hash,
    transactionIndex: u32,
    logIndex: u32,
};

/// Paymaster data structure
pub const PaymasterData = struct {
    paymaster: primitives.Address,
    verificationGasLimit: u256,
    postOpGasLimit: u256,
    data: []const u8,

    /// Pack paymaster data into bytes (v0.7+ format)
    /// Format: paymaster_address (20 bytes) + verificationGasLimit (16 bytes) + postOpGasLimit (16 bytes) + data
    pub fn pack(self: PaymasterData, allocator: std.mem.Allocator) ![]u8 {
        var packed_data = try std.ArrayList(u8).initCapacity(allocator, 0);
        errdefer packed_data.deinit(allocator);

        // Paymaster address (20 bytes)
        try packed_data.appendSlice(allocator, &self.paymaster.bytes);

        // Verification gas limit (16 bytes, u128)
        var ver_gas_bytes: [16]u8 = undefined;
        const ver_gas_u128: u128 = @intCast(self.verificationGasLimit);
        std.mem.writeInt(u128, &ver_gas_bytes, ver_gas_u128, .big);
        try packed_data.appendSlice(allocator, &ver_gas_bytes);

        // Post-op gas limit (16 bytes, u128)
        var post_gas_bytes: [16]u8 = undefined;
        const post_gas_u128: u128 = @intCast(self.postOpGasLimit);
        std.mem.writeInt(u128, &post_gas_bytes, post_gas_u128, .big);
        try packed_data.appendSlice(allocator, &post_gas_bytes);

        // Paymaster-specific data
        try packed_data.appendSlice(allocator, self.data);

        return try packed_data.toOwnedSlice(allocator);
    }

    /// Unpack paymaster data from bytes (v0.7+ format)
    pub fn unpack(data: []const u8, allocator: std.mem.Allocator) !PaymasterData {
        if (data.len < 52) {
            return error.InvalidPaymasterData;
        }

        // Extract paymaster address (20 bytes)
        var paymaster_bytes: [20]u8 = undefined;
        @memcpy(&paymaster_bytes, data[0..20]);
        const paymaster = primitives.Address.fromBytes(paymaster_bytes);

        // Extract verification gas limit (16 bytes, u128)
        var ver_gas_bytes: [16]u8 = undefined;
        @memcpy(&ver_gas_bytes, data[20..36]);
        const ver_gas_limit: u256 = std.mem.readInt(u128, &ver_gas_bytes, .big);

        // Extract post-op gas limit (16 bytes, u128)
        var post_gas_bytes: [16]u8 = undefined;
        @memcpy(&post_gas_bytes, data[36..52]);
        const post_gas_limit: u256 = std.mem.readInt(u128, &post_gas_bytes, .big);

        // Extract remaining data
        const pm_data = if (data.len > 52)
            try allocator.dupe(u8, data[52..])
        else
            &[_]u8{};

        return PaymasterData{
            .paymaster = paymaster,
            .verificationGasLimit = ver_gas_limit,
            .postOpGasLimit = post_gas_limit,
            .data = pm_data,
        };
    }
};

/// Gas estimates for UserOperation
pub const GasEstimates = struct {
    preVerificationGas: u256,
    verificationGasLimit: u256,
    callGasLimit: u256,
    paymasterVerificationGasLimit: ?u256 = null,
    paymasterPostOpGasLimit: ?u256 = null,
};

// Helper functions for hex conversion

/// Convert bytes to hex string with "0x" prefix
fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    if (bytes.len == 0) {
        return try allocator.dupe(u8, "0x");
    }

    return try hex_utils.bytesToHex(allocator, bytes);
}

/// Convert hex string to bytes
fn hexToBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    // Remove "0x" prefix if present
    const hex = if (std.mem.startsWith(u8, hex_str, "0x"))
        hex_str[2..]
    else
        hex_str;

    // Empty string = empty bytes
    if (hex.len == 0) {
        return try allocator.dupe(u8, &[_]u8{});
    }

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

    if (hex.len == 0) {
        return 0;
    }

    return try std.fmt.parseInt(u256, hex, 16);
}
