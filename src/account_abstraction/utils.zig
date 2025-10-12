const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const keccak = @import("../crypto/keccak.zig");

/// UserOperation hash calculator
pub const UserOpHash = struct {
    /// Calculate UserOperation hash for signing (v0.6)
    /// Follows EIP-4337 specification
    pub fn calculate(
        allocator: std.mem.Allocator,
        user_op: types.UserOperationV06,
        entry_point: primitives.Address,
        chain_id: u64,
    ) !Hash {
        _ = allocator;
        _ = user_op;
        _ = entry_point;
        _ = chain_id;

        // TODO: Implement UserOperation hash calculation
        // 1. Pack UserOperation struct (without signature)
        // 2. Hash the packed data: keccak256(pack(userOp))
        // 3. Create final hash: keccak256(userOpHash, entryPoint, chainId)

        return Hash{};
    }

    /// Pack UserOperation for hashing (ABI encoding, v0.6)
    fn packUserOperation(allocator: std.mem.Allocator, user_op: types.UserOperationV06) ![]u8 {
        _ = allocator;
        _ = user_op;

        // TODO: Implement ABI encoding for UserOperation
        // abi.encode(
        //   sender, nonce, keccak256(initCode), keccak256(callData),
        //   callGasLimit, verificationGasLimit, preVerificationGas,
        //   maxFeePerGas, maxPriorityFeePerGas, keccak256(paymasterAndData)
        // )

        return &[_]u8{};
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
        const account_gas_limits: [32]u8 = [_]u8{0} ** 32;
        const gas_fees: [32]u8 = [_]u8{0} ** 32;

        // TODO: Pack gas limits and fees into 32-byte arrays

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
        // TODO: Unpack gas limits and fees

        return types.UserOperation{
            .sender = self.sender,
            .nonce = self.nonce,
            .initCode = self.initCode,
            .callData = self.callData,
            .callGasLimit = 0, // TODO: Unpack from accountGasLimits
            .verificationGasLimit = 0, // TODO: Unpack from accountGasLimits
            .preVerificationGas = self.preVerificationGas,
            .maxFeePerGas = 0, // TODO: Unpack from gasFees
            .maxPriorityFeePerGas = 0, // TODO: Unpack from gasFees
            .paymasterAndData = self.paymasterAndData,
            .signature = self.signature,
        };
    }
};

/// UserOperation utilities
pub const UserOpUtils = struct {
    /// Check if UserOperation is valid (v0.6)
    pub fn isValid(user_op: types.UserOperationV06) bool {
        user_op.validate() catch return false;
        return true;
    }

    /// Get UserOperation size in bytes (v0.6)
    pub fn getSize(user_op: types.UserOperationV06) usize {
        return 20 + // sender
            32 + // nonce
            user_op.initCode.len +
            user_op.callData.len +
            32 + // callGasLimit
            32 + // verificationGasLimit
            32 + // preVerificationGas
            32 + // maxFeePerGas
            32 + // maxPriorityFeePerGas
            user_op.paymasterAndData.len +
            user_op.signature.len;
    }

    /// Create a zero UserOperation for testing (v0.6)
    pub fn zero() types.UserOperationV06 {
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
    }
};
