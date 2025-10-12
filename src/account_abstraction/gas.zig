const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");

/// Gas estimation utilities for UserOperations
pub const GasEstimator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) GasEstimator {
        return .{ .allocator = allocator };
    }

    /// Estimate gas for UserOperation (works with v0.6)
    pub fn estimateGas(
        self: *GasEstimator,
        user_op: types.UserOperationV06,
    ) !types.GasEstimates {
        _ = self;

        // TODO: Implement proper gas estimation
        // This should call eth_estimateUserOperationGas on bundler
        // For now, return conservative estimates

        const call_data_gas = calculateCallDataGas(user_op.callData);
        const verification_gas = estimateVerificationGas(user_op);
        const call_gas = estimateCallGas(user_op);

        return types.GasEstimates{
            .preVerificationGas = call_data_gas + 21000, // Base transaction + calldata
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

    /// Estimate verification gas
    fn estimateVerificationGas(user_op: types.UserOperationV06) u256 {
        _ = user_op;
        // TODO: Implement accurate verification gas estimation
        // Consider:
        // - Signature verification cost
        // - Init code execution (if deploying)
        // - Account verification logic
        // Conservative estimate: 100k gas
        return 100000;
    }

    /// Estimate call gas
    fn estimateCallGas(user_op: types.UserOperationV06) u256 {
        // TODO: Implement accurate call gas estimation
        // Should simulate the actual call execution
        // For now, use a conservative base estimate + calldata length
        const base_gas: u256 = 21000;
        const data_gas = calculateCallDataGas(user_op.callData);
        const execution_gas: u256 = 50000; // Conservative estimate for execution

        return base_gas + data_gas + execution_gas;
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
    pub fn getGasPrices(self: *GasEstimator) !GasPrices {
        _ = self;
        // TODO: Query current gas prices from network
        // eth_gasPrice, eth_maxPriorityFeePerGas
        return GasPrices{
            .maxFeePerGas = 30_000_000_000, // 30 gwei
            .maxPriorityFeePerGas = 2_000_000_000, // 2 gwei
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
