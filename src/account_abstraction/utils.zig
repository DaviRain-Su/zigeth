const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const keccak = @import("../crypto/keccak.zig");

/// UserOperation hash calculator
/// Supports all EntryPoint versions (v0.6, v0.7, v0.8)
pub const UserOpHash = struct {
    /// Calculate UserOperation hash for signing (supports all versions)
    /// Follows EIP-4337 specification
    pub fn calculate(
        allocator: std.mem.Allocator,
        user_op: anytype,
        entry_point: primitives.Address,
        chain_id: u64,
    ) !Hash {
        // Validate type
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                @compileError("user_op must be UserOperationV06, V07, or V08");
            }
        }

        // Step 1: Pack UserOperation (without signature)
        const packed_data = try packUserOperation(allocator, user_op);
        defer allocator.free(packed_data);

        // Step 2: Hash the packed UserOperation
        const user_op_hash = keccak.hash(packed_data);

        // Step 3: Create final hash: keccak256(userOpHash ++ entryPoint ++ chainId)
        var final_data = std.ArrayList(u8).init(allocator);
        defer final_data.deinit();

        try final_data.appendSlice(&user_op_hash.bytes);
        try final_data.appendSlice(&entry_point.bytes);

        var chain_id_bytes: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, chain_id_bytes[24..32][0..8], chain_id, .big);
        try final_data.appendSlice(&chain_id_bytes);

        return keccak.hash(final_data.items);
    }

    /// Pack UserOperation for hashing (supports all versions)
    fn packUserOperation(allocator: std.mem.Allocator, user_op: anytype) ![]u8 {
        const UserOpType = @TypeOf(user_op);

        var packed_bytes = std.ArrayList(u8).init(allocator);
        errdefer packed_bytes.deinit();

        // Common fields across all versions
        try packed_bytes.appendSlice(&user_op.sender.bytes);

        var nonce_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &nonce_bytes, user_op.nonce, .big);
        try packed_bytes.appendSlice(&nonce_bytes);

        // Hash initCode or factory data
        if (UserOpType == types.UserOperationV06) {
            const init_hash = keccak.hash(user_op.initCode);
            try packed_bytes.appendSlice(&init_hash.bytes);
        } else {
            // v0.7/v0.8: hash factoryData
            const factory_hash = keccak.hash(user_op.factoryData);
            try packed_bytes.appendSlice(&factory_hash.bytes);
        }

        // Hash callData
        const call_hash = keccak.hash(user_op.callData);
        try packed_bytes.appendSlice(&call_hash.bytes);

        // Gas limits (version-specific encoding)
        if (UserOpType == types.UserOperationV06) {
            // v0.6: all u256
            var gas_bytes: [32]u8 = undefined;

            std.mem.writeInt(u256, &gas_bytes, user_op.callGasLimit, .big);
            try packed_bytes.appendSlice(&gas_bytes);

            std.mem.writeInt(u256, &gas_bytes, user_op.verificationGasLimit, .big);
            try packed_bytes.appendSlice(&gas_bytes);

            std.mem.writeInt(u256, &gas_bytes, user_op.preVerificationGas, .big);
            try packed_bytes.appendSlice(&gas_bytes);

            std.mem.writeInt(u256, &gas_bytes, user_op.maxFeePerGas, .big);
            try packed_bytes.appendSlice(&gas_bytes);

            std.mem.writeInt(u256, &gas_bytes, user_op.maxPriorityFeePerGas, .big);
            try packed_bytes.appendSlice(&gas_bytes);

            // Hash paymasterAndData
            const paymaster_hash = keccak.hash(user_op.paymasterAndData);
            try packed_bytes.appendSlice(&paymaster_hash.bytes);
        } else {
            // v0.7/v0.8: u128 for most gas fields
            var gas_bytes_128: [16]u8 = undefined;
            var gas_bytes_256: [32]u8 = undefined;

            std.mem.writeInt(u128, &gas_bytes_128, user_op.callGasLimit, .big);
            try packed_bytes.appendSlice(&gas_bytes_128);

            std.mem.writeInt(u128, &gas_bytes_128, user_op.verificationGasLimit, .big);
            try packed_bytes.appendSlice(&gas_bytes_128);

            std.mem.writeInt(u256, &gas_bytes_256, user_op.preVerificationGas, .big);
            try packed_bytes.appendSlice(&gas_bytes_256);

            std.mem.writeInt(u128, &gas_bytes_128, user_op.maxFeePerGas, .big);
            try packed_bytes.appendSlice(&gas_bytes_128);

            std.mem.writeInt(u128, &gas_bytes_128, user_op.maxPriorityFeePerGas, .big);
            try packed_bytes.appendSlice(&gas_bytes_128);

            // Hash paymasterData
            const paymaster_hash = keccak.hash(user_op.paymasterData);
            try packed_bytes.appendSlice(&paymaster_hash.bytes);
        }

        return try packed_bytes.toOwnedSlice();
    }
};

/// Packed UserOperation (ERC-4337 v0.7)
/// More gas-efficient representation
pub const PackedUserOperation = struct {
    sender: primitives.Address,
    nonce: u256,
    initCode: []const u8,
    callData: []const u8,
    accountGasLimits: [32]u8, // Packed: verificationGasLimit (16 bytes) + callGasLimit (16 bytes)
    preVerificationGas: u256,
    gasFees: [32]u8, // Packed: maxPriorityFeePerGas (16 bytes) + maxFeePerGas (16 bytes)
    paymasterAndData: []const u8,
    signature: []const u8,

    /// Convert from standard UserOperation to packed format
    pub fn fromUserOperation(user_op: types.UserOperation) PackedUserOperation {
        // Pack account gas limits: verificationGasLimit (16 bytes) + callGasLimit (16 bytes)
        var account_gas_limits: [32]u8 = [_]u8{0} ** 32;

        // Pack verification gas limit (first 16 bytes)
        const ver_gas_u128: u128 = @intCast(user_op.verificationGasLimit);
        std.mem.writeInt(u128, account_gas_limits[0..16][0..16], ver_gas_u128, .big);

        // Pack call gas limit (last 16 bytes)
        const call_gas_u128: u128 = @intCast(user_op.callGasLimit);
        std.mem.writeInt(u128, account_gas_limits[16..32][0..16], call_gas_u128, .big);

        // Pack gas fees: maxPriorityFeePerGas (16 bytes) + maxFeePerGas (16 bytes)
        var gas_fees: [32]u8 = [_]u8{0} ** 32;

        // Pack max priority fee (first 16 bytes)
        const priority_fee_u128: u128 = @intCast(user_op.maxPriorityFeePerGas);
        std.mem.writeInt(u128, gas_fees[0..16][0..16], priority_fee_u128, .big);

        // Pack max fee per gas (last 16 bytes)
        const max_fee_u128: u128 = @intCast(user_op.maxFeePerGas);
        std.mem.writeInt(u128, gas_fees[16..32][0..16], max_fee_u128, .big);

        return PackedUserOperation{
            .sender = user_op.sender,
            .nonce = user_op.nonce,
            .initCode = user_op.initCode,
            .callData = user_op.callData,
            .accountGasLimits = account_gas_limits,
            .preVerificationGas = user_op.preVerificationGas,
            .gasFees = gas_fees,
            .paymasterAndData = user_op.paymasterAndData,
            .signature = user_op.signature,
        };
    }

    /// Convert to standard UserOperation format
    pub fn toUserOperation(self: PackedUserOperation) types.UserOperation {
        // Unpack account gas limits
        // First 16 bytes: verificationGasLimit
        const verification_gas_limit_u128 = std.mem.readInt(u128, self.accountGasLimits[0..16][0..16], .big);
        const verification_gas_limit: u256 = @intCast(verification_gas_limit_u128);

        // Last 16 bytes: callGasLimit
        const call_gas_limit_u128 = std.mem.readInt(u128, self.accountGasLimits[16..32][0..16], .big);
        const call_gas_limit: u256 = @intCast(call_gas_limit_u128);

        // Unpack gas fees
        // First 16 bytes: maxPriorityFeePerGas
        const max_priority_fee_u128 = std.mem.readInt(u128, self.gasFees[0..16][0..16], .big);
        const max_priority_fee: u256 = @intCast(max_priority_fee_u128);

        // Last 16 bytes: maxFeePerGas
        const max_fee_u128 = std.mem.readInt(u128, self.gasFees[16..32][0..16], .big);
        const max_fee: u256 = @intCast(max_fee_u128);

        return types.UserOperation{
            .sender = self.sender,
            .nonce = self.nonce,
            .initCode = self.initCode,
            .callData = self.callData,
            .callGasLimit = call_gas_limit,
            .verificationGasLimit = verification_gas_limit,
            .preVerificationGas = self.preVerificationGas,
            .maxFeePerGas = max_fee,
            .maxPriorityFeePerGas = max_priority_fee,
            .paymasterAndData = self.paymasterAndData,
            .signature = self.signature,
        };
    }
};

/// UserOperation utilities
/// Supports all EntryPoint versions (v0.6, v0.7, v0.8)
pub const UserOpUtils = struct {
    /// Check if UserOperation is valid (supports all versions)
    pub fn isValid(user_op: anytype) bool {
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                return false;
            }
        }

        // Basic validation
        if (user_op.sender.isZero()) return false;
        if (user_op.callData.len > 0 and user_op.callGasLimit == 0) return false;
        if (user_op.verificationGasLimit == 0) return false;
        if (user_op.maxFeePerGas == 0) return false;

        return true;
    }

    /// Get UserOperation size in bytes (supports all versions)
    pub fn getSize(user_op: anytype) usize {
        const UserOpType = @TypeOf(user_op);

        var size: usize = 20 + 32; // sender + nonce

        if (UserOpType == types.UserOperationV06) {
            size += user_op.initCode.len;
            size += user_op.callData.len;
            size += 32 * 5; // All gas fields are u256
            size += user_op.paymasterAndData.len;
            size += user_op.signature.len;
        } else {
            // v0.7/v0.8
            size += user_op.factoryData.len;
            size += user_op.callData.len;
            size += 16 * 4; // Most gas fields are u128
            size += 32; // preVerificationGas is u256
            size += user_op.paymasterData.len;
            size += user_op.signature.len;
        }

        return size;
    }

    /// Create a zero UserOperation for testing
    /// Returns specified version
    pub fn zero(comptime UserOpType: type) UserOpType {
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                @compileError("UserOpType must be UserOperationV06, V07, or V08");
            }
        }

        if (UserOpType == types.UserOperationV06) {
            return types.UserOperationV06{
                .sender = primitives.Address.fromBytes([_]u8{0} ** 20),
                .nonce = 0,
                .initCode = &[_]u8{},
                .callData = &[_]u8{},
                .callGasLimit = 0,
                .verificationGasLimit = 0,
                .preVerificationGas = 0,
                .maxFeePerGas = 0,
                .maxPriorityFeePerGas = 0,
                .paymasterAndData = &[_]u8{},
                .signature = &[_]u8{},
            };
        } else if (UserOpType == types.UserOperationV07) {
            return types.UserOperationV07{
                .sender = primitives.Address.fromBytes([_]u8{0} ** 20),
                .nonce = 0,
                .factory = null,
                .factoryData = &[_]u8{},
                .callData = &[_]u8{},
                .callGasLimit = 0,
                .verificationGasLimit = 0,
                .preVerificationGas = 0,
                .maxFeePerGas = 0,
                .maxPriorityFeePerGas = 0,
                .paymaster = null,
                .paymasterVerificationGasLimit = 0,
                .paymasterPostOpGasLimit = 0,
                .paymasterData = &[_]u8{},
                .signature = &[_]u8{},
            };
        } else {
            return types.UserOperationV08{
                .sender = primitives.Address.fromBytes([_]u8{0} ** 20),
                .nonce = 0,
                .factory = null,
                .factoryData = &[_]u8{},
                .callData = &[_]u8{},
                .callGasLimit = 0,
                .verificationGasLimit = 0,
                .preVerificationGas = 0,
                .maxFeePerGas = 0,
                .maxPriorityFeePerGas = 0,
                .paymaster = null,
                .paymasterVerificationGasLimit = 0,
                .paymasterPostOpGasLimit = 0,
                .paymasterData = &[_]u8{},
                .signature = &[_]u8{},
            };
        }
    }
};
