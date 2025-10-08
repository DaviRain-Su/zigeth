const std = @import("std");
const hex = @import("../utils/hex.zig");

/// Dynamic byte array for Ethereum data
pub const Bytes = struct {
    data: []u8,
    allocator: std.mem.Allocator,

    /// Create from an existing byte slice (copies the data)
    pub fn fromSlice(allocator: std.mem.Allocator, bytes: []const u8) !Bytes {
        const data = try allocator.dupe(u8, bytes);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Create from hex string
    pub fn fromHex(allocator: std.mem.Allocator, hex_str: []const u8) !Bytes {
        const data = try hex.hexToBytes(allocator, hex_str);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Create empty bytes
    pub fn empty(allocator: std.mem.Allocator) Bytes {
        return .{
            .data = &[_]u8{},
            .allocator = allocator,
        };
    }

    /// Create with specific capacity
    pub fn withCapacity(allocator: std.mem.Allocator, capacity: usize) !Bytes {
        const data = try allocator.alloc(u8, capacity);
        @memset(data, 0);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: Bytes) void {
        if (self.data.len > 0) {
            self.allocator.free(self.data);
        }
    }

    /// Convert to hex string
    pub fn toHex(self: Bytes) ![]u8 {
        return try hex.bytesToHex(self.allocator, self.data);
    }

    /// Get length
    pub fn len(self: Bytes) usize {
        return self.data.len;
    }

    /// Check if empty
    pub fn isEmpty(self: Bytes) bool {
        return self.data.len == 0;
    }

    /// Clone the bytes
    pub fn clone(self: Bytes) !Bytes {
        return try fromSlice(self.allocator, self.data);
    }

    /// Slice the bytes (returns a view, doesn't allocate)
    pub fn slice(self: Bytes, start: usize, end: usize) []const u8 {
        return self.data[start..end];
    }

    /// Compare with another Bytes
    pub fn eql(self: Bytes, other: Bytes) bool {
        return std.mem.eql(u8, self.data, other.data);
    }

    /// Compare with a slice
    pub fn eqlSlice(self: Bytes, other: []const u8) bool {
        return std.mem.eql(u8, self.data, other);
    }
};

test "bytes creation" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 1, 2, 3, 4, 5 };
    const bytes = try Bytes.fromSlice(allocator, &data);
    defer bytes.deinit();

    try std.testing.expectEqual(@as(usize, 5), bytes.len());
    try std.testing.expect(!bytes.isEmpty());
}

test "bytes from hex" {
    const allocator = std.testing.allocator;

    const bytes = try Bytes.fromHex(allocator, "0xdeadbeef");
    defer bytes.deinit();

    try std.testing.expectEqual(@as(usize, 4), bytes.len());
    try std.testing.expectEqual(@as(u8, 0xde), bytes.data[0]);
    try std.testing.expectEqual(@as(u8, 0xad), bytes.data[1]);
}

test "bytes to hex" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const bytes = try Bytes.fromSlice(allocator, &data);
    defer bytes.deinit();

    const hex_str = try bytes.toHex();
    defer allocator.free(hex_str);

    try std.testing.expectEqualStrings("0xdeadbeef", hex_str);
}

test "bytes empty" {
    const allocator = std.testing.allocator;

    const bytes = Bytes.empty(allocator);
    defer bytes.deinit();

    try std.testing.expect(bytes.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), bytes.len());
}

test "bytes equality" {
    const allocator = std.testing.allocator;

    const data1 = [_]u8{ 1, 2, 3 };
    const data2 = [_]u8{ 1, 2, 3 };
    const data3 = [_]u8{ 4, 5, 6 };

    const bytes1 = try Bytes.fromSlice(allocator, &data1);
    defer bytes1.deinit();
    const bytes2 = try Bytes.fromSlice(allocator, &data2);
    defer bytes2.deinit();
    const bytes3 = try Bytes.fromSlice(allocator, &data3);
    defer bytes3.deinit();

    try std.testing.expect(bytes1.eql(bytes2));
    try std.testing.expect(!bytes1.eql(bytes3));
}

test "bytes with capacity" {
    const allocator = std.testing.allocator;

    const bytes = try Bytes.withCapacity(allocator, 10);
    defer bytes.deinit();

    try std.testing.expectEqual(@as(usize, 10), bytes.len());
}

test "bytes clone" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 1, 2, 3 };
    const bytes1 = try Bytes.fromSlice(allocator, &data);
    defer bytes1.deinit();

    const bytes2 = try bytes1.clone();
    defer bytes2.deinit();

    try std.testing.expect(bytes1.eql(bytes2));
    // Ensure they're different allocations
    try std.testing.expect(bytes1.data.ptr != bytes2.data.ptr);
}
