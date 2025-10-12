const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;

/// ERC-4337 EntryPoint contract
/// Supports v0.6, v0.7, and v0.8
pub const EntryPoint = struct {
    address: primitives.Address,
    allocator: std.mem.Allocator,
    version: types.EntryPointVersion,

    /// EntryPoint v0.6 standard address (Legacy)
    pub const ENTRYPOINT_V06_ADDRESS = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";

    /// EntryPoint v0.7 standard address (Current - Gas-optimized)
    pub const ENTRYPOINT_V07_ADDRESS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

    /// EntryPoint v0.8 standard address
    pub const ENTRYPOINT_V08_ADDRESS = "0x4337084d9e255ff0702461cf8895ce9e3b5ff108";

    pub fn init(allocator: std.mem.Allocator, address: primitives.Address, version: types.EntryPointVersion) EntryPoint {
        return .{
            .allocator = allocator,
            .address = address,
            .version = version,
        };
    }

    /// Create EntryPoint with v0.6 standard address
    pub fn v06(allocator: std.mem.Allocator) !EntryPoint {
        const address = try primitives.Address.fromHex(ENTRYPOINT_V06_ADDRESS);
        return init(allocator, address, .v0_6);
    }

    /// Create EntryPoint with v0.7 standard address
    pub fn v07(allocator: std.mem.Allocator) !EntryPoint {
        const address = try primitives.Address.fromHex(ENTRYPOINT_V07_ADDRESS);
        return init(allocator, address, .v0_7);
    }

    /// Create EntryPoint with v0.8 standard address
    pub fn v08(allocator: std.mem.Allocator) !EntryPoint {
        const address = try primitives.Address.fromHex(ENTRYPOINT_V08_ADDRESS);
        return init(allocator, address, .v0_8);
    }

    /// Get nonce for sender
    /// Call: getNonce(address sender, uint192 key)
    pub fn getNonce(self: *EntryPoint, sender: primitives.Address, key: u192) !u256 {
        _ = self;
        _ = sender;
        _ = key;
        // TODO: Implement contract call to EntryPoint.getNonce()
        return 0;
    }

    /// Get account deposit balance
    /// Call: balanceOf(address account)
    pub fn balanceOf(self: *EntryPoint, account: primitives.Address) !u256 {
        _ = self;
        _ = account;
        // TODO: Implement contract call to EntryPoint.balanceOf()
        return 0;
    }

    /// Get deposit info for account
    /// Call: getDepositInfo(address account)
    pub fn getDepositInfo(self: *EntryPoint, account: primitives.Address) !DepositInfo {
        _ = self;
        _ = account;
        // TODO: Implement contract call to EntryPoint.getDepositInfo()
        return DepositInfo{
            .deposit = 0,
            .staked = false,
            .stake = 0,
            .unstakeDelaySec = 0,
            .withdrawTime = 0,
        };
    }

    /// Simulate UserOperation validation
    /// Call: simulateValidation(UserOperation calldata userOp)
    pub fn simulateValidation(self: *EntryPoint, user_op: types.UserOperation) !ValidationResult {
        _ = self;
        _ = user_op;
        // TODO: Implement contract call to EntryPoint.simulateValidation()
        return ValidationResult{
            .returnInfo = .{
                .preOpGas = 0,
                .prefund = 0,
                .sigFailed = false,
                .validAfter = 0,
                .validUntil = 0,
                .paymasterContext = &[_]u8{},
            },
            .senderInfo = null,
            .factoryInfo = null,
            .paymasterInfo = null,
        };
    }

    /// Handle UserOperation aggregation
    /// Call: handleOps(UserOperation[] calldata ops, address payable beneficiary)
    pub fn handleOps(
        self: *EntryPoint,
        user_ops: []const types.UserOperation,
        beneficiary: primitives.Address,
    ) !Hash {
        _ = self;
        _ = user_ops;
        _ = beneficiary;
        // TODO: Implement handleOps transaction
        return Hash{};
    }

    /// Add deposit for account
    /// Call: depositTo(address account) payable
    pub fn depositTo(self: *EntryPoint, account: primitives.Address, amount: u256) !Hash {
        _ = self;
        _ = account;
        _ = amount;
        // TODO: Implement depositTo transaction
        return Hash{};
    }
};

/// Deposit information for an account
pub const DepositInfo = struct {
    deposit: u256,
    staked: bool,
    stake: u256,
    unstakeDelaySec: u32,
    withdrawTime: u48,
};

/// Validation result from simulateValidation
pub const ValidationResult = struct {
    returnInfo: ReturnInfo,
    senderInfo: ?StakeInfo,
    factoryInfo: ?StakeInfo,
    paymasterInfo: ?StakeInfo,
};

pub const ReturnInfo = struct {
    preOpGas: u256,
    prefund: u256,
    sigFailed: bool,
    validAfter: u48,
    validUntil: u48,
    paymasterContext: []const u8,
};

pub const StakeInfo = struct {
    stake: u256,
    unstakeDelaySec: u32,
};
