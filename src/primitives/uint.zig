//! u256 Utilities for Ethereum
//!
//! Zig has native u256 support. This module provides utility functions
//! for Ethereum-specific operations like big-endian byte conversions and hex formatting.
//!
//! **Usage:**
//! - Use native `u256` type for all code
//! - Use utility functions (`u256FromBytes`, `u256ToBytes`, etc.) for Ethereum conversions
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
