const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Bytes = @import("../primitives/bytes.zig").Bytes;

/// Ethereum event log
pub const Log = struct {
    /// Contract address that emitted the log
    address: Address,

    /// Indexed log topics (up to 4)
    topics: []Hash,

    /// Non-indexed log data
    data: Bytes,

    /// Block number where this log was emitted (optional for pending logs)
    block_number: ?u64,

    /// Transaction hash that created this log (optional for pending logs)
    transaction_hash: ?Hash,

    /// Transaction index in the block (optional for pending logs)
    transaction_index: ?u64,

    /// Log index in the block (optional for pending logs)
    log_index: ?u64,

    /// Block hash (optional for pending logs)
    block_hash: ?Hash,

    /// Whether the log was removed due to a chain reorganization
    removed: bool,

    allocator: std.mem.Allocator,

    /// Create a new log
    pub fn init(
        allocator: std.mem.Allocator,
        address: Address,
        topics: []const Hash,
        data: Bytes,
    ) !Log {
        const topics_copy = try allocator.dupe(Hash, topics);
        return .{
            .address = address,
            .topics = topics_copy,
            .data = data,
            .block_number = null,
            .transaction_hash = null,
            .transaction_index = null,
            .log_index = null,
            .block_hash = null,
            .removed = false,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: Log) void {
        if (self.topics.len > 0) {
            self.allocator.free(self.topics);
        }
        self.data.deinit();
    }

    /// Get the event signature (first topic, if exists)
    pub fn getEventSignature(self: Log) ?Hash {
        if (self.topics.len > 0) {
            return self.topics[0];
        }
        return null;
    }

    /// Get indexed parameter at index (0-based, skipping event signature)
    pub fn getIndexedParam(self: Log, index: usize) ?Hash {
        // First topic is event signature, so indexed params start at index 1
        const param_index = index + 1;
        if (param_index < self.topics.len) {
            return self.topics[param_index];
        }
        return null;
    }

    /// Get number of indexed parameters (excluding event signature)
    pub fn getIndexedParamCount(self: Log) usize {
        if (self.topics.len > 0) {
            return self.topics.len - 1;
        }
        return 0;
    }

    /// Check if log matches an event signature
    pub fn matchesSignature(self: Log, signature: Hash) bool {
        if (self.getEventSignature()) |sig| {
            return sig.eql(signature);
        }
        return false;
    }

    /// Check if log is from a pending transaction
    pub fn isPending(self: Log) bool {
        return self.block_number == null;
    }
};

test "log creation" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const topics = [_]Hash{
        Hash.fromBytes([_]u8{0x01} ** 32),
        Hash.fromBytes([_]u8{0x02} ** 32),
    };
    const data = try Bytes.fromSlice(allocator, &[_]u8{ 1, 2, 3, 4 });

    const log = try Log.init(allocator, addr, &topics, data);
    defer log.deinit();

    try std.testing.expect(std.mem.eql(u8, &log.address.bytes, &addr.bytes));
    try std.testing.expectEqual(@as(usize, 2), log.topics.len);
}

test "log event signature" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const sig = Hash.fromBytes([_]u8{0x01} ** 32);
    const topics = [_]Hash{sig};
    const data = try Bytes.fromSlice(allocator, &[_]u8{});

    const log = try Log.init(allocator, addr, &topics, data);
    defer log.deinit();

    const event_sig = log.getEventSignature();
    try std.testing.expect(event_sig != null);
    try std.testing.expect(event_sig.?.eql(sig));
    try std.testing.expect(log.matchesSignature(sig));
}

test "log indexed parameters" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const topics = [_]Hash{
        Hash.fromBytes([_]u8{0x01} ** 32), // event signature
        Hash.fromBytes([_]u8{0x02} ** 32), // param 0
        Hash.fromBytes([_]u8{0x03} ** 32), // param 1
    };
    const data = try Bytes.fromSlice(allocator, &[_]u8{});

    const log = try Log.init(allocator, addr, &topics, data);
    defer log.deinit();

    try std.testing.expectEqual(@as(usize, 2), log.getIndexedParamCount());

    const param0 = log.getIndexedParam(0);
    try std.testing.expect(param0 != null);
    try std.testing.expect(param0.?.eql(topics[1]));

    const param1 = log.getIndexedParam(1);
    try std.testing.expect(param1 != null);
    try std.testing.expect(param1.?.eql(topics[2]));

    const param2 = log.getIndexedParam(2);
    try std.testing.expect(param2 == null);
}

test "log pending status" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const data = try Bytes.fromSlice(allocator, &[_]u8{});

    var log = try Log.init(allocator, addr, &[_]Hash{}, data);
    defer log.deinit();

    try std.testing.expect(log.isPending());

    log.block_number = 12345;
    try std.testing.expect(!log.isPending());
}
