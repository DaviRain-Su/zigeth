const std = @import("std");
const RpcClient = @import("./client.zig").RpcClient;
const types = @import("./types.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const Address = @import("../primitives/address.zig").Address;
const U256 = @import("../primitives/uint.zig").U256;

/// Debug namespace (debug_*) methods
/// These methods are typically only available on development nodes
pub const DebugNamespace = struct {
    client: *RpcClient,

    pub fn init(client: *RpcClient) DebugNamespace {
        return .{ .client = client };
    }

    /// debug_traceTransaction - Returns the trace of a transaction
    pub fn traceTransaction(self: DebugNamespace, hash: Hash, options: ?TraceOptions) !TraceResult {
        _ = self;
        _ = hash;
        _ = options;
        return error.NotImplemented;
    }

    /// debug_traceBlockByNumber - Returns the trace of all transactions in a block
    pub fn traceBlockByNumber(self: DebugNamespace, block: types.BlockParameter, options: ?TraceOptions) ![]TraceResult {
        _ = self;
        _ = block;
        _ = options;
        return error.NotImplemented;
    }

    /// debug_traceBlockByHash - Returns the trace of all transactions in a block
    pub fn traceBlockByHash(self: DebugNamespace, hash: Hash, options: ?TraceOptions) ![]TraceResult {
        _ = self;
        _ = hash;
        _ = options;
        return error.NotImplemented;
    }

    /// debug_traceCall - Executes and returns trace of a call
    pub fn traceCall(
        self: DebugNamespace,
        call_params: types.CallParams,
        block: types.BlockParameter,
        options: ?TraceOptions,
    ) !TraceResult {
        _ = self;
        _ = call_params;
        _ = block;
        _ = options;
        return error.NotImplemented;
    }

    /// debug_storageRangeAt - Returns storage range
    pub fn storageRangeAt(
        self: DebugNamespace,
        block_hash: Hash,
        tx_index: u64,
        address: Address,
        start_key: Hash,
        limit: u64,
    ) !StorageRange {
        _ = self;
        _ = block_hash;
        _ = tx_index;
        _ = address;
        _ = start_key;
        _ = limit;
        return error.NotImplemented;
    }

    /// debug_getModifiedAccountsByNumber - Returns accounts modified in a block
    pub fn getModifiedAccountsByNumber(
        self: DebugNamespace,
        start_block: u64,
        end_block: u64,
    ) ![]Address {
        _ = self;
        _ = start_block;
        _ = end_block;
        return error.NotImplemented;
    }

    /// debug_getModifiedAccountsByHash - Returns accounts modified in a block
    pub fn getModifiedAccountsByHash(
        self: DebugNamespace,
        start_hash: Hash,
        end_hash: Hash,
    ) ![]Address {
        _ = self;
        _ = start_hash;
        _ = end_hash;
        return error.NotImplemented;
    }
};

/// Trace options for debug calls
pub const TraceOptions = struct {
    disable_storage: ?bool = null,
    disable_stack: ?bool = null,
    enable_memory: ?bool = null,
    enable_return_data: ?bool = null,
    tracer: ?[]const u8 = null,
    timeout: ?[]const u8 = null,
};

/// Result of a trace operation
pub const TraceResult = struct {
    gas: u64,
    return_value: []const u8,
    struct_logs: []StructLog,
    allocator: std.mem.Allocator,

    pub fn deinit(self: TraceResult) void {
        self.allocator.free(self.return_value);
        for (self.struct_logs) |log| {
            log.deinit();
        }
        if (self.struct_logs.len > 0) {
            self.allocator.free(self.struct_logs);
        }
    }
};

/// Individual step in execution trace
pub const StructLog = struct {
    pc: u64,
    op: []const u8,
    gas: u64,
    gas_cost: u64,
    depth: u64,
    stack: ?[]U256 = null,
    memory: ?[]const u8 = null,
    storage: ?std.StringHashMap(Hash) = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: StructLog) void {
        if (self.stack) |stack| {
            self.allocator.free(stack);
        }
        if (self.memory) |memory| {
            self.allocator.free(memory);
        }
        if (self.storage) |*storage| {
            var it = storage.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            storage.deinit();
        }
    }
};

/// Storage range result
pub const StorageRange = struct {
    storage: std.StringHashMap(StorageEntry),
    next_key: ?Hash,
    allocator: std.mem.Allocator,

    pub const StorageEntry = struct {
        key: Hash,
        value: Hash,
    };

    pub fn deinit(self: *StorageRange) void {
        var it = self.storage.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.storage.deinit();
    }
};

test "debug namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const debug = DebugNamespace.init(&client);
    try std.testing.expect(debug.client.endpoint.len > 0);
}

test "trace options default" {
    const options = TraceOptions{};
    try std.testing.expect(options.disable_storage == null);
    try std.testing.expect(options.disable_stack == null);
}
