const std = @import("std");

/// Convert bytes to hex string with 0x prefix
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, 2 + bytes.len * 2);

    result[0] = '0';
    result[1] = 'x';

    for (bytes, 0..) |byte, i| {
        result[2 + i * 2] = hex_chars[byte >> 4];
        result[2 + i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

/// Convert hex string to bytes (handles with or without 0x prefix)
pub fn hexToBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    var start: usize = 0;

    // Skip 0x prefix if present
    if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X')) {
        start = 2;
    }

    const hex_part = hex_str[start..];
    const hex_len = hex_part.len;

    // Handle odd-length hex strings by padding with leading zero
    const is_odd = hex_len % 2 != 0;
    const result_len = (hex_len + 1) / 2;

    const result = try allocator.alloc(u8, result_len);
    errdefer allocator.free(result);

    if (is_odd) {
        // First byte comes from a single nibble (padded with 0)
        result[0] = try hexCharToNibble(hex_part[0]);
        // Process remaining pairs
        for (1..result_len) |i| {
            const high = try hexCharToNibble(hex_part[i * 2 - 1]);
            const low = try hexCharToNibble(hex_part[i * 2]);
            result[i] = (high << 4) | low;
        }
    } else {
        // Even length - process pairs normally
        for (0..result_len) |i| {
            const high = try hexCharToNibble(hex_part[i * 2]);
            const low = try hexCharToNibble(hex_part[i * 2 + 1]);
            result[i] = (high << 4) | low;
        }
    }

    return result;
}

/// Convert a single hex character to its nibble value
fn hexCharToNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexCharacter,
    };
}

/// Check if a string is a valid hex string
pub fn isValidHex(hex_str: []const u8) bool {
    var start: usize = 0;

    if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X')) {
        start = 2;
    }

    const hex_len = hex_str.len - start;
    if (hex_len % 2 != 0) {
        return false;
    }

    for (hex_str[start..]) |c| {
        switch (c) {
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return false,
        }
    }

    return true;
}

test "bytes to hex" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const hex_str = try bytesToHex(allocator, &bytes);
    defer allocator.free(hex_str);

    try std.testing.expectEqualStrings("0xdeadbeef", hex_str);
}

test "hex to bytes" {
    const allocator = std.testing.allocator;

    const hex_str = "0xdeadbeef";
    const bytes = try hexToBytes(allocator, hex_str);
    defer allocator.free(bytes);

    const expected = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "hex to bytes without prefix" {
    const allocator = std.testing.allocator;

    const hex_str = "deadbeef";
    const bytes = try hexToBytes(allocator, hex_str);
    defer allocator.free(bytes);

    const expected = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "is valid hex" {
    try std.testing.expect(isValidHex("0xdeadbeef"));
    try std.testing.expect(isValidHex("deadbeef"));
    try std.testing.expect(isValidHex("0x1234567890abcdef"));
    try std.testing.expect(!isValidHex("0xgg"));
    try std.testing.expect(!isValidHex("0x123")); // Odd length
    try std.testing.expect(!isValidHex("xyz"));
}

test "hex char to nibble" {
    try std.testing.expectEqual(@as(u8, 0), try hexCharToNibble('0'));
    try std.testing.expectEqual(@as(u8, 9), try hexCharToNibble('9'));
    try std.testing.expectEqual(@as(u8, 10), try hexCharToNibble('a'));
    try std.testing.expectEqual(@as(u8, 15), try hexCharToNibble('f'));
    try std.testing.expectEqual(@as(u8, 10), try hexCharToNibble('A'));
    try std.testing.expectEqual(@as(u8, 15), try hexCharToNibble('F'));
    try std.testing.expectError(error.InvalidHexCharacter, hexCharToNibble('g'));
}
