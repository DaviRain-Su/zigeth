const std = @import("std");
const hex = @import("../utils/hex.zig");

/// Ethereum hash (32 bytes) - typically Keccak-256
pub const Hash = struct {
    bytes: [32]u8,

    /// Create a hash from a 32-byte array
    pub fn fromBytes(bytes: [32]u8) Hash {
        return .{ .bytes = bytes };
    }

    /// Create a hash from a slice (must be exactly 32 bytes)
    pub fn fromSlice(slice: []const u8) !Hash {
        if (slice.len != 32) {
            return error.InvalidHashLength;
        }
        var hash: Hash = undefined;
        @memcpy(&hash.bytes, slice);
        return hash;
    }

    /// Create a hash from a hex string
    pub fn fromHex(hex_str: []const u8) !Hash {
        var temp_allocator_buffer: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);
        const allocator = fba.allocator();

        const bytes = try hex.hexToBytes(allocator, hex_str);
        if (bytes.len != 32) {
            return error.InvalidHashLength;
        }

        var hash: Hash = undefined;
        @memcpy(&hash.bytes, bytes);
        return hash;
    }

    /// Convert hash to hex string with 0x prefix
    pub fn toHex(self: Hash, allocator: std.mem.Allocator) ![]u8 {
        return try hex.bytesToHex(allocator, &self.bytes);
    }

    /// Check if hash is all zeros
    pub fn isZero(self: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &[_]u8{0} ** 32);
    }

    /// Check if two hashes are equal
    pub fn eql(self: Hash, other: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Create a zero hash
    pub fn zero() Hash {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    /// Format hash for printing
    pub fn format(
        self: Hash,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("0x", .{});
        for (self.bytes) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
    }
};

test "hash creation" {
    const hash = Hash.fromBytes([_]u8{0} ** 32);
    try std.testing.expect(hash.isZero());
}

test "hash from hex" {
    const allocator = std.testing.allocator;

    const hex_str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const hash = try Hash.fromHex(hex_str);

    const result = try hash.toHex(allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(hex_str, result);
}

test "hash equality" {
    const hash1 = Hash.fromBytes([_]u8{1} ** 32);
    const hash2 = Hash.fromBytes([_]u8{1} ** 32);
    const hash3 = Hash.fromBytes([_]u8{2} ** 32);

    try std.testing.expect(hash1.eql(hash2));
    try std.testing.expect(!hash1.eql(hash3));
}

test "hash zero" {
    const hash = Hash.zero();
    try std.testing.expect(hash.isZero());
}

test "hash from slice" {
    const slice = [_]u8{0xab} ** 32;
    const hash = try Hash.fromSlice(&slice);
    try std.testing.expect(!hash.isZero());
    try std.testing.expectEqual(@as(u8, 0xab), hash.bytes[0]);
}
