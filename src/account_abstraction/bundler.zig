const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const rpc = @import("../rpc/client.zig");

/// ERC-4337 Bundler Client
/// Implements eth_* methods for UserOperation handling
pub const BundlerClient = struct {
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    entry_point: primitives.Address,

    pub fn init(allocator: std.mem.Allocator, rpc_url: []const u8, entry_point: primitives.Address) BundlerClient {
        return .{
            .allocator = allocator,
            .rpc_url = rpc_url,
            .entry_point = entry_point,
        };
    }

    /// Send UserOperation to bundler (v0.6 format)
    /// Method: eth_sendUserOperation
    pub fn sendUserOperation(self: *BundlerClient, user_op: types.UserOperationV06) !Hash {
        _ = self;
        _ = user_op;
        // TODO: Implement RPC call to bundler
        // POST {"jsonrpc":"2.0","method":"eth_sendUserOperation","params":[userOp, entryPoint],"id":1}
        return Hash{};
    }

    /// Estimate UserOperation gas (v0.6 format)
    /// Method: eth_estimateUserOperationGas
    pub fn estimateUserOperationGas(self: *BundlerClient, user_op: types.UserOperationV06) !types.GasEstimates {
        _ = self;
        _ = user_op;
        // TODO: Implement gas estimation via bundler
        return types.GasEstimates{
            .preVerificationGas = 0,
            .verificationGasLimit = 0,
            .callGasLimit = 0,
        };
    }

    /// Get UserOperation by hash (returns v0.6 format)
    /// Method: eth_getUserOperationByHash
    pub fn getUserOperationByHash(self: *BundlerClient, user_op_hash: Hash) !?types.UserOperationV06 {
        _ = self;
        _ = user_op_hash;
        // TODO: Implement fetching UserOperation from bundler
        return null;
    }

    /// Get UserOperation receipt
    /// Method: eth_getUserOperationReceipt
    pub fn getUserOperationReceipt(self: *BundlerClient, user_op_hash: Hash) !?types.UserOperationReceipt {
        _ = self;
        _ = user_op_hash;
        // TODO: Implement fetching receipt from bundler
        return null;
    }

    /// Get supported entry points
    /// Method: eth_supportedEntryPoints
    pub fn getSupportedEntryPoints(self: *BundlerClient) ![]primitives.Address {
        _ = self;
        // TODO: Implement fetching supported entry points
        return &[_]primitives.Address{};
    }

    /// Get chain ID
    /// Method: eth_chainId
    pub fn getChainId(self: *BundlerClient) !u64 {
        _ = self;
        // TODO: Implement chain ID query
        return 1;
    }
};
