//! u256 Utilities for Ethereum
//!
//! Zig has native u256 support. This module provides utility functions
//! for Ethereum-specific operations like big-endian byte conversions and hex formatting.
//!
//! **Recommended Usage:**
//! - Use native `u256` type for all new code
//! - Use utility functions (`u256FromBytes`, `u256ToBytes`, etc.) for Ethereum conversions
//! - The legacy `U256` wrapper struct is provided for backwards compatibility only
//!
//! **Example:**
//! ```zig
//! const value: u256 = 1_000_000_000_000_000_000; // 1 ETH in wei
//! const bytes = u256ToBytes(value); // Convert to Ethereum format (big-endian)
//! const hex_str = try u256ToHex(value, allocator);
//! ```

const std = @import("std");
const hex = @import("../utils/hex.zig");

/// Create u256 from bytes (big-endian, 32 bytes) - Ethereum format
pub fn u256FromBytes(bytes: [32]u8) u256 {
    return std.mem.readInt(u256, &bytes, .big);
}

/// Convert u256 to bytes (big-endian, 32 bytes) - Ethereum format
pub fn u256ToBytes(value: u256) [32]u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return bytes;
}

/// Create u256 from hex string
pub fn u256FromHex(hex_str: []const u8) !u256 {
    var temp_allocator_buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);
    const allocator = fba.allocator();

    const bytes = try hex.hexToBytes(allocator, hex_str);
    if (bytes.len > 32) {
        return error.ValueTooLarge;
    }

    // Pad with zeros if needed
    var padded: [32]u8 = [_]u8{0} ** 32;
    const offset = 32 - bytes.len;
    @memcpy(padded[offset..], bytes);

    return u256FromBytes(padded);
}

/// Convert u256 to hex string
pub fn u256ToHex(value: u256, allocator: std.mem.Allocator) ![]u8 {
    const bytes = u256ToBytes(value);
    return try hex.bytesToHex(allocator, &bytes);
}

/// Try to convert u256 to u64 (returns error if too large)
pub fn u256ToU64(value: u256) !u64 {
    if (value > std.math.maxInt(u64)) {
        return error.ValueTooLarge;
    }
    return @intCast(value);
}

/// Legacy U256 type - DEPRECATED, use native u256 instead
/// Kept for backwards compatibility during migration
pub const U256 = struct {
    value: u256,

    pub fn fromInt(v: u64) U256 {
        return .{ .value = v };
    }

    pub fn zero() U256 {
        return .{ .value = 0 };
    }

    pub fn one() U256 {
        return .{ .value = 1 };
    }

    pub fn max() U256 {
        return .{ .value = std.math.maxInt(u256) };
    }

    pub fn fromBytes(bytes: [32]u8) U256 {
        return .{ .value = u256FromBytes(bytes) };
    }

    pub fn toBytes(self: U256) [32]u8 {
        return u256ToBytes(self.value);
    }

    pub fn fromHex(hex_str: []const u8) !U256 {
        return .{ .value = try u256FromHex(hex_str) };
    }

    pub fn toHex(self: U256, allocator: std.mem.Allocator) ![]u8 {
        return u256ToHex(self.value, allocator);
    }

    pub fn isZero(self: U256) bool {
        return self.value == 0;
    }

    pub fn eql(self: U256, other: U256) bool {
        return self.value == other.value;
    }

    pub fn lt(self: U256, other: U256) bool {
        return self.value < other.value;
    }

    pub fn lte(self: U256, other: U256) bool {
        return self.value <= other.value;
    }

    pub fn gt(self: U256, other: U256) bool {
        return self.value > other.value;
    }

    pub fn gte(self: U256, other: U256) bool {
        return self.value >= other.value;
    }

    pub fn add(self: U256, other: U256) U256 {
        return .{ .value = self.value +% other.value };
    }

    pub fn sub(self: U256, other: U256) U256 {
        return .{ .value = self.value -% other.value };
    }

    pub fn mulScalar(self: U256, scalar: u64) U256 {
        return .{ .value = self.value *% scalar };
    }

    pub fn divScalar(self: U256, scalar: u64) struct { quotient: U256, remainder: u64 } {
        return .{
            .quotient = .{ .value = self.value / scalar },
            .remainder = @intCast(self.value % scalar),
        };
    }

    pub fn toU64(self: U256) u64 {
        return @intCast(self.value & std.math.maxInt(u64));
    }

    pub fn tryToU64(self: U256) !u64 {
        return u256ToU64(self.value);
    }

    pub fn format(
        self: U256,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("0x{x}", .{self.value});
    }
};

test "u256 from bytes" {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    bytes[31] = 42; // Last byte (big-endian)

    const val = u256FromBytes(bytes);
    try std.testing.expectEqual(@as(u256, 42), val);
}

test "u256 to bytes" {
    const val: u256 = 42;
    const bytes = u256ToBytes(val);

    try std.testing.expectEqual(@as(u8, 42), bytes[31]);
    try std.testing.expectEqual(@as(u8, 0), bytes[0]);
}

test "u256 from hex" {
    const allocator = std.testing.allocator;

    const val = try u256FromHex("0x2a"); // 42 in decimal
    try std.testing.expectEqual(@as(u256, 42), val);

    const hex_str = try u256ToHex(val, allocator);
    defer allocator.free(hex_str);
}

test "u256 to u64" {
    const val: u256 = 42;
    try std.testing.expectEqual(@as(u64, 42), try u256ToU64(val));

    const too_large: u256 = @as(u256, std.math.maxInt(u64)) + 1;
    try std.testing.expectError(error.ValueTooLarge, u256ToU64(too_large));
}

test "legacy U256 wrapper" {
    const val = U256.fromInt(42);
    try std.testing.expectEqual(@as(u256, 42), val.value);
    try std.testing.expect(!val.isZero());

    const zero = U256.zero();
    try std.testing.expect(zero.isZero());
}
