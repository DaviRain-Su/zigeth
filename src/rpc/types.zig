const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;

/// JSON-RPC request
pub const JsonRpcRequest = struct {
    jsonrpc: []const u8 = "2.0",
    method: []const u8,
    params: std.json.Value,
    id: u64,

    pub fn init(allocator: std.mem.Allocator, method: []const u8, params: std.json.Value, id: u64) !JsonRpcRequest {
        _ = allocator;
        return .{
            .method = method,
            .params = params,
            .id = id,
        };
    }
};

/// JSON-RPC response
pub const JsonRpcResponse = struct {
    jsonrpc: []const u8,
    result: ?std.json.Value,
    @"error": ?JsonRpcError,
    id: u64,
};

/// JSON-RPC error
pub const JsonRpcError = struct {
    code: i64,
    message: []const u8,
    data: ?std.json.Value = null,
};

/// Block parameter for RPC calls
pub const BlockParameter = union(enum) {
    number: u64,
    tag: BlockTag,
    hash: Hash,

    pub const BlockTag = enum {
        earliest,
        latest,
        pending,
        safe,
        finalized,

        pub fn toString(self: BlockTag) []const u8 {
            return switch (self) {
                .earliest => "earliest",
                .latest => "latest",
                .pending => "pending",
                .safe => "safe",
                .finalized => "finalized",
            };
        }
    };

    pub fn fromTag(tag: BlockTag) BlockParameter {
        return .{ .tag = tag };
    }

    pub fn fromNumber(number: u64) BlockParameter {
        return .{ .number = number };
    }

    pub fn fromHash(hash: Hash) BlockParameter {
        return .{ .hash = hash };
    }
};

/// Call parameters for eth_call and eth_estimateGas
pub const CallParams = struct {
    from: ?Address = null,
    to: ?Address,
    gas: ?u64 = null,
    gas_price: ?u256 = null,
    value: ?u256 = null,
    data: ?[]const u8 = null,
};

/// Transaction parameters for eth_sendTransaction
pub const TransactionParams = struct {
    from: Address,
    to: ?Address,
    gas: ?u64 = null,
    gas_price: ?u256 = null,
    value: ?u256 = null,
    data: ?[]const u8 = null,
    nonce: ?u64 = null,
    chain_id: ?u64 = null,

    // EIP-1559 fields
    max_fee_per_gas: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
};

/// Filter options for eth_getLogs
pub const FilterOptions = struct {
    from_block: ?BlockParameter = null,
    to_block: ?BlockParameter = null,
    address: ?Address = null,
    topics: ?[]?Hash = null,
    block_hash: ?Hash = null,
};

/// Subscription parameters for eth_subscribe
pub const SubscriptionParams = union(enum) {
    new_heads: void,
    logs: FilterOptions,
    new_pending_transactions: void,
    syncing: void,
};

/// Fee history result
pub const FeeHistory = struct {
    oldest_block: u64,
    base_fee_per_gas: []u256,
    gas_used_ratio: []f64,
    reward: ?[][]u256 = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: FeeHistory) void {
        self.allocator.free(self.base_fee_per_gas);
        self.allocator.free(self.gas_used_ratio);
        if (self.reward) |rewards| {
            for (rewards) |reward| {
                self.allocator.free(reward);
            }
            self.allocator.free(rewards);
        }
    }
};

/// Sync status
pub const SyncStatus = union(enum) {
    syncing: SyncProgress,
    not_syncing: void,

    pub const SyncProgress = struct {
        starting_block: u64,
        current_block: u64,
        highest_block: u64,
    };
};

/// Peer information
pub const PeerInfo = struct {
    id: []const u8,
    name: []const u8,
    enode: []const u8,
    enr: ?[]const u8,
    caps: [][]const u8,
    network: Network,
    protocols: Protocols,

    pub const Network = struct {
        local_address: []const u8,
        remote_address: []const u8,
        inbound: bool,
        trusted: bool,
        static: bool,
    };

    pub const Protocols = struct {
        eth: ?EthProtocol = null,
        snap: ?SnapProtocol = null,
    };

    pub const EthProtocol = struct {
        version: u64,
        difficulty: u256,
        head: Hash,
    };

    pub const SnapProtocol = struct {
        version: u64,
    };
};

test "block parameter tag" {
    const param = BlockParameter.fromTag(.latest);
    try std.testing.expectEqual(BlockParameter.BlockTag.latest, param.tag);
}

test "block parameter number" {
    const param = BlockParameter.fromNumber(12345);
    try std.testing.expectEqual(@as(u64, 12345), param.number);
}

test "block parameter hash" {
    const hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const param = BlockParameter.fromHash(hash);
    try std.testing.expect(param.hash.eql(hash));
}

test "block tag to string" {
    try std.testing.expectEqualStrings("latest", BlockParameter.BlockTag.latest.toString());
    try std.testing.expectEqualStrings("earliest", BlockParameter.BlockTag.earliest.toString());
    try std.testing.expectEqualStrings("pending", BlockParameter.BlockTag.pending.toString());
    try std.testing.expectEqualStrings("safe", BlockParameter.BlockTag.safe.toString());
    try std.testing.expectEqualStrings("finalized", BlockParameter.BlockTag.finalized.toString());
}
