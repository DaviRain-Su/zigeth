const std = @import("std");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;

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
    pub fn hash(self: UserOperation, allocator: std.mem.Allocator, entry_point: primitives.Address, chain_id: u64) !Hash {
        _ = self;
        _ = allocator;
        _ = entry_point;
        _ = chain_id;
        // TODO: Implement proper UserOperation hash calculation
        // Following EIP-4337 specification
        return Hash{};
    }

    /// Validate UserOperation fields
    pub fn validate(self: UserOperation) !void {
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
        // TODO: Implement conversion
        // - Combine factory + factoryData into initCode
        // - Combine paymaster fields into paymasterAndData
        _ = allocator;
        return UserOperationV06{
            .sender = self.sender,
            .nonce = self.nonce,
            .initCode = &[_]u8{},
            .callData = self.callData,
            .callGasLimit = self.callGasLimit,
            .verificationGasLimit = self.verificationGasLimit,
            .preVerificationGas = self.preVerificationGas,
            .maxFeePerGas = self.maxFeePerGas,
            .maxPriorityFeePerGas = self.maxPriorityFeePerGas,
            .paymasterAndData = &[_]u8{},
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

    /// Convert from UserOperation (v0.6) to JSON format
    pub fn fromUserOperation(allocator: std.mem.Allocator, user_op: UserOperationV06) !UserOperationJson {
        _ = allocator;
        _ = user_op;
        // TODO: Implement conversion
        return UserOperationJson{
            .sender = "",
            .nonce = "",
            .initCode = "",
            .callData = "",
            .callGasLimit = "",
            .verificationGasLimit = "",
            .preVerificationGas = "",
            .maxFeePerGas = "",
            .maxPriorityFeePerGas = "",
            .paymasterAndData = "",
            .signature = "",
        };
    }

    /// Convert from JSON format to UserOperation (v0.6)
    pub fn toUserOperation(self: UserOperationJson, allocator: std.mem.Allocator) !UserOperationV06 {
        _ = self;
        _ = allocator;
        // TODO: Implement conversion
        return UserOperationV06{
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
    paymasterVerificationGasLimit: u256,
    paymasterPostOpGasLimit: u256,
    paymasterData: []const u8,

    /// Pack paymaster data into bytes
    pub fn pack(self: PaymasterData, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        _ = allocator;
        // TODO: Implement packing
        return &[_]u8{};
    }

    /// Unpack paymaster data from bytes
    pub fn unpack(data: []const u8, allocator: std.mem.Allocator) !PaymasterData {
        _ = data;
        _ = allocator;
        // TODO: Implement unpacking
        return PaymasterData{
            .paymaster = primitives.Address.fromBytes([_]u8{0} ** 20),
            .paymasterVerificationGasLimit = 0,
            .paymasterPostOpGasLimit = 0,
            .paymasterData = &[_]u8{},
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
