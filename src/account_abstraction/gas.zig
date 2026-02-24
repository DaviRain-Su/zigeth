const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const rpc_mod = @import("../rpc/client.zig");
const bundler = @import("bundler.zig");

/// Gas estimation utilities for UserOperations
/// Supports all EntryPoint versions (v0.6, v0.7, v0.8)
pub const GasEstimator = struct {
    allocator: std.mem.Allocator,
    bundler_client: ?*bundler.BundlerClient,
    rpc_client: ?*rpc_mod.RpcClient,

    pub fn init(
        allocator: std.mem.Allocator,
        bundler_client: ?*bundler.BundlerClient,
        rpc_client: ?*rpc_mod.RpcClient,
    ) GasEstimator {
        return .{
            .allocator = allocator,
            .bundler_client = bundler_client,
            .rpc_client = rpc_client,
        };
    }

    /// Estimate gas for UserOperation (supports v0.6, v0.7, v0.8)
    /// If bundler client is available, uses eth_estimateUserOperationGas
    /// Otherwise, falls back to local estimation
    pub fn estimateGas(
        self: *GasEstimator,
        user_op: anytype,
    ) !types.GasEstimates {
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

        // Try to use bundler for accurate estimation
        if (self.bundler_client) |bundler_client| {
            return try bundler_client.estimateUserOperationGas(user_op);
        }

        // Fallback to local estimation
        return try self.estimateGasLocal(user_op);
    }

    /// Local gas estimation (fallback when no bundler)
    fn estimateGasLocal(self: *GasEstimator, user_op: anytype) !types.GasEstimates {
        const UserOpType = @TypeOf(user_op);

        // Get callData based on version
        const call_data = if (UserOpType == types.UserOperationV06)
            user_op.callData
        else if (UserOpType == types.UserOperationV07)
            user_op.callData
        else
            user_op.callData;

        const call_data_gas = calculateCallDataGas(call_data);
        const verification_gas = try self.estimateVerificationGasLocal(user_op);
        const call_gas = try self.estimateCallGasLocal(user_op);

        return types.GasEstimates{
            .preVerificationGas = call_data_gas + GasOverhead.FIXED,
            .verificationGasLimit = verification_gas,
            .callGasLimit = call_gas,
        };
    }

    /// Calculate call data gas cost
    fn calculateCallDataGas(call_data: []const u8) u256 {
        var gas: u256 = 0;
        for (call_data) |byte| {
            if (byte == 0) {
                gas += 4; // Zero byte costs 4 gas
            } else {
                gas += 16; // Non-zero byte costs 16 gas
            }
        }
        return gas;
    }

    /// Estimate verification gas (local estimation)
    fn estimateVerificationGasLocal(self: *GasEstimator, user_op: anytype) !u256 {
        _ = self;
        const UserOpType = @TypeOf(user_op);

        var base_verification: u256 = 100000; // Base verification cost

        // Add init code gas if deploying
        if (UserOpType == types.UserOperationV06) {
            if (user_op.initCode.len > 0) {
                base_verification += GasOverhead.ACCOUNT_DEPLOYMENT;
                base_verification += calculateCallDataGas(user_op.initCode);
            }
        } else if (UserOpType == types.UserOperationV07 or UserOpType == types.UserOperationV08) {
            if (user_op.factory != null) {
                base_verification += GasOverhead.ACCOUNT_DEPLOYMENT;
                base_verification += calculateCallDataGas(user_op.factoryData);
            }
        }

        // Add paymaster verification gas if present
        if (UserOpType == types.UserOperationV06) {
            if (user_op.paymasterAndData.len > 0) {
                base_verification += GasOverhead.PAYMASTER_VERIFICATION;
            }
        } else if (UserOpType == types.UserOperationV07 or UserOpType == types.UserOperationV08) {
            if (user_op.paymaster != null) {
                base_verification += GasOverhead.PAYMASTER_VERIFICATION;
                if (UserOpType == types.UserOperationV07) {
                    base_verification += user_op.paymasterVerificationGasLimit;
                }
            }
        }

        return base_verification;
    }

    /// Estimate call gas (local estimation)
    fn estimateCallGasLocal(self: *GasEstimator, user_op: anytype) !u256 {
        _ = self;
        const UserOpType = @TypeOf(user_op);

        const call_data = if (UserOpType == types.UserOperationV06)
            user_op.callData
        else if (UserOpType == types.UserOperationV07)
            user_op.callData
        else
            user_op.callData;

        const base_gas: u256 = 21000;
        const data_gas = calculateCallDataGas(call_data);
        const execution_gas: u256 = 50000; // Conservative estimate for execution logic

        // Add paymaster post-op gas if applicable
        var total_gas = base_gas + data_gas + execution_gas;

        if (UserOpType == types.UserOperationV06) {
            if (user_op.paymasterAndData.len > 0) {
                total_gas += GasOverhead.PAYMASTER_POST_OP;
            }
        } else if (UserOpType == types.UserOperationV07 or UserOpType == types.UserOperationV08) {
            if (user_op.paymaster != null) {
                total_gas += GasOverhead.PAYMASTER_POST_OP;
                if (UserOpType == types.UserOperationV07) {
                    total_gas += user_op.paymasterPostOpGasLimit;
                }
            }
        }

        return total_gas;
    }

    /// Calculate total gas cost in wei
    pub fn calculateTotalGasCost(
        estimates: types.GasEstimates,
        max_fee_per_gas: u256,
    ) u256 {
        const total_gas = estimates.preVerificationGas +
            estimates.verificationGasLimit +
            estimates.callGasLimit;

        return total_gas * max_fee_per_gas;
    }

    /// Get current gas prices from network
    /// Uses eth_gasPrice and eth_maxPriorityFeePerGas if RPC client available
    /// Otherwise returns conservative default values
    pub fn getGasPrices(self: *GasEstimator) !GasPrices {
        if (self.rpc_client) |rpc| {
            return try self.getGasPricesFromRpc(rpc);
        }

        // Fallback to conservative defaults
        return GasPrices{
            .maxFeePerGas = 30_000_000_000, // 30 gwei
            .maxPriorityFeePerGas = 2_000_000_000, // 2 gwei
        };
    }

    /// Get gas prices from RPC
    fn getGasPricesFromRpc(self: *GasEstimator, rpc: *rpc_mod.RpcClient) !GasPrices {
        // Get base fee from latest block
        var params_empty_list = std.json.Array.init(self.allocator);
        defer params_empty_list.deinit();
        const params_empty = std.json.Value{ .array = params_empty_list };

        // Get eth_gasPrice
        const gas_price_response = try rpc.call("eth_gasPrice", params_empty);
        const gas_price_hex = gas_price_response.string;
        const gas_price_str = if (std.mem.startsWith(u8, gas_price_hex, "0x"))
            gas_price_hex[2..]
        else
            gas_price_hex;
        const base_fee = try std.fmt.parseInt(u256, gas_price_str, 16);

        // Get eth_maxPriorityFeePerGas (EIP-1559)
        var max_priority_fee: u256 = 2_000_000_000; // Default 2 gwei
        if (rpc.call("eth_maxPriorityFeePerGas", params_empty)) |priority_response| {
            const priority_hex = priority_response.string;
            const priority_str = if (std.mem.startsWith(u8, priority_hex, "0x"))
                priority_hex[2..]
            else
                priority_hex;
            max_priority_fee = try std.fmt.parseInt(u256, priority_str, 16);
        } else |_| {
            // If eth_maxPriorityFeePerGas not supported, use 2 gwei default
        }

        // Calculate maxFeePerGas: baseFee * 2 + maxPriorityFeePerGas
        // (multiply by 2 to handle base fee fluctuations)
        const max_fee = (base_fee * 2) + max_priority_fee;

        return GasPrices{
            .maxFeePerGas = max_fee,
            .maxPriorityFeePerGas = max_priority_fee,
        };
    }

    /// Estimate pre-verification gas for a UserOperation
    /// This is the gas needed to submit the UserOp to the mempool
    pub fn estimatePreVerificationGas(self: *GasEstimator, user_op: anytype) !u256 {
        _ = self;
        const UserOpType = @TypeOf(user_op);

        // Calculate based on UserOperation data size
        var total_size: usize = 0;

        // Add all field sizes
        if (UserOpType == types.UserOperationV06) {
            total_size += user_op.initCode.len;
            total_size += user_op.callData.len;
            total_size += user_op.paymasterAndData.len;
            total_size += user_op.signature.len;
            total_size += 32 * 6; // Fixed-size fields
        } else if (UserOpType == types.UserOperationV07 or UserOpType == types.UserOperationV08) {
            total_size += user_op.factoryData.len;
            total_size += user_op.callData.len;
            total_size += user_op.paymasterData.len;
            total_size += user_op.signature.len;
            total_size += 32 * 8; // More fixed-size fields in v0.7/v0.8
        }

        // Calculate calldata gas
        const calldata_gas = @as(u256, @intCast(total_size)) * 16; // Assume non-zero bytes

        // Add fixed overhead
        return GasOverhead.FIXED + GasOverhead.PER_USER_OP + calldata_gas;
    }

    /// Apply a multiplier to gas estimates for safety margin
    pub fn applyGasMultiplier(estimates: types.GasEstimates, multiplier_percent: u32) types.GasEstimates {
        const multiplier: u256 = @intCast(multiplier_percent);
        return types.GasEstimates{
            .preVerificationGas = (estimates.preVerificationGas * multiplier) / 100,
            .verificationGasLimit = (estimates.verificationGasLimit * multiplier) / 100,
            .callGasLimit = (estimates.callGasLimit * multiplier) / 100,
        };
    }
};

pub const GasPrices = struct {
    maxFeePerGas: u256,
    maxPriorityFeePerGas: u256,
};

/// Gas overhead constants for different operations
pub const GasOverhead = struct {
    /// Fixed gas overhead per UserOperation
    pub const FIXED = 21000;

    /// Per-UserOperation overhead in a bundle
    pub const PER_USER_OP = 18300;

    /// Overhead for account deployment
    pub const ACCOUNT_DEPLOYMENT = 200000;

    /// Overhead for paymaster verification
    pub const PAYMASTER_VERIFICATION = 35000;

    /// Overhead for paymaster post-op
    pub const PAYMASTER_POST_OP = 15000;
};
