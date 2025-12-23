const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;

/// Format an address for display (shortened format)
/// Example: 0x1234...5678
pub fn formatAddressShort(allocator: std.mem.Allocator, address: Address) ![]u8 {
    const hex = try address.toHex(allocator);
    defer allocator.free(hex);

    if (hex.len < 12) {
        return try allocator.dupe(u8, hex);
    }

    // 0x + first 4 chars + ... + last 4 chars
    var result = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer result.deinit(allocator);

    try result.appendSlice(allocator, hex[0..6]); // 0x1234
    try result.appendSlice(allocator, "..."); // ...
    try result.appendSlice(allocator, hex[hex.len - 4 ..]); // 5678

    return try result.toOwnedSlice(allocator);
}

/// Format a hash for display (shortened format)
/// Example: 0xabcd...ef01
pub fn formatHashShort(allocator: std.mem.Allocator, hash: Hash) ![]u8 {
    const hex = try hash.toHex(allocator);
    defer allocator.free(hex);

    if (hex.len < 12) {
        return try allocator.dupe(u8, hex);
    }

    var result = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer result.deinit(allocator);

    try result.appendSlice(allocator, hex[0..6]); // 0xabcd
    try result.appendSlice(allocator, "..."); // ...
    try result.appendSlice(allocator, hex[hex.len - 4 ..]); // ef01

    return try result.toOwnedSlice(allocator);
}

/// Format bytes for display with optional length limit
pub fn formatBytes(allocator: std.mem.Allocator, bytes: []const u8, max_length: ?usize) ![]u8 {
    const hex_module = @import("./hex.zig");
    const hex = try hex_module.bytesToHex(allocator, bytes);
    defer allocator.free(hex);

    if (max_length) |max| {
        if (hex.len <= max) {
            return try allocator.dupe(u8, hex);
        }

        // Truncate with ...
        const prefix_len = (max - 3) / 2;
        const suffix_len = max - 3 - prefix_len;

        var result = try std.ArrayList(u8).initCapacity(allocator, prefix_len + 3 + suffix_len);
        defer result.deinit(allocator);

        try result.appendSlice(allocator, hex[0..prefix_len]);
        try result.appendSlice(allocator, "...");
        try result.appendSlice(allocator, hex[hex.len - suffix_len ..]);

        return try result.toOwnedSlice(allocator);
    }

    return try allocator.dupe(u8, hex);
}

/// Format a U256 as a decimal string
pub fn formatU256(allocator: std.mem.Allocator, value: U256) ![]u8 {
    // Convert to decimal string
    var result = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer result.deinit(allocator);

    // Handle zero case
    if (value.isZero()) {
        try result.append(allocator, '0');
        return try result.toOwnedSlice();
    }

    // Use a simple algorithm: repeatedly divide by 10
    var temp = value;
    var digits = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer digits.deinit(allocator);

    while (!temp.isZero()) {
        const div_result = temp.divScalar(10);
        const digit = @as(u8, @intCast(div_result.remainder));
        try digits.append(allocator, '0' + digit);
        temp = div_result.quotient;
    }

    // Reverse digits
    var i: usize = digits.items.len;
    while (i > 0) {
        i -= 1;
        try result.append(allocator, digits.items[i]);
    }

    return try result.toOwnedSlice(allocator);
}

/// Format a U256 as a hex string with 0x prefix
pub fn formatU256Hex(allocator: std.mem.Allocator, value: U256) ![]u8 {
    return try value.toHex(allocator);
}

/// Format a number with thousand separators
pub fn formatWithSeparators(allocator: std.mem.Allocator, number_str: []const u8, separator: u8) ![]u8 {
    if (number_str.len <= 3) {
        return try allocator.dupe(u8, number_str);
    }

    var result = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer result.deinit(allocator);

    const len = number_str.len;
    var count: usize = 0;

    var i: usize = len;
    while (i > 0) {
        i -= 1;
        if (count > 0 and count % 3 == 0) {
            try result.insert(allocator, 0, separator);
        }
        try result.insert(allocator, 0, number_str[i]);
        count += 1;
    }

    return try result.toOwnedSlice(allocator);
}

/// Pad a string to a specific length with a character
pub fn padLeft(allocator: std.mem.Allocator, str: []const u8, length: usize, pad_char: u8) ![]u8 {
    if (str.len >= length) {
        return try allocator.dupe(u8, str);
    }

    const result = try allocator.alloc(u8, length);
    const pad_count = length - str.len;

    @memset(result[0..pad_count], pad_char);
    @memcpy(result[pad_count..], str);

    return result;
}

/// Pad a string to a specific length with a character (right side)
pub fn padRight(allocator: std.mem.Allocator, str: []const u8, length: usize, pad_char: u8) ![]u8 {
    if (str.len >= length) {
        return try allocator.dupe(u8, str);
    }

    const result = try allocator.alloc(u8, length);

    @memcpy(result[0..str.len], str);
    @memset(result[str.len..], pad_char);

    return result;
}

/// Truncate a string to a maximum length
pub fn truncate(allocator: std.mem.Allocator, str: []const u8, max_length: usize) ![]u8 {
    if (str.len <= max_length) {
        return try allocator.dupe(u8, str);
    }

    return try allocator.dupe(u8, str[0..max_length]);
}

test "format address short" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ++ [_]u8{0x34} ** 9 ++ [_]u8{0x56});
    const formatted = try formatAddressShort(allocator, addr);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "...") != null);
    try std.testing.expect(formatted.len < 42); // Less than full address
}

test "format hash short" {
    const allocator = std.testing.allocator;

    const hash = Hash.fromBytes([_]u8{0xab} ** 32);
    const formatted = try formatHashShort(allocator, hash);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "...") != null);
    try std.testing.expect(formatted.len < 66); // Less than full hash
}

test "format bytes with limit" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const formatted = try formatBytes(allocator, &data, 10);
    defer allocator.free(formatted);

    try std.testing.expect(formatted.len <= 10);
}

test "format U256 decimal" {
    const allocator = std.testing.allocator;

    const value = U256.fromInt(1234567890);
    const formatted = try formatU256(allocator, value);
    defer allocator.free(formatted);

    try std.testing.expectEqualStrings("1234567890", formatted);
}

test "format U256 zero" {
    const allocator = std.testing.allocator;

    const value = U256.zero();
    const formatted = try formatU256(allocator, value);
    defer allocator.free(formatted);

    try std.testing.expectEqualStrings("0", formatted);
}

test "format with separators" {
    const allocator = std.testing.allocator;

    const formatted = try formatWithSeparators(allocator, "1234567890", ',');
    defer allocator.free(formatted);

    try std.testing.expectEqualStrings("1,234,567,890", formatted);
}

test "pad left" {
    const allocator = std.testing.allocator;

    const padded = try padLeft(allocator, "123", 6, '0');
    defer allocator.free(padded);

    try std.testing.expectEqualStrings("000123", padded);
}

test "pad right" {
    const allocator = std.testing.allocator;

    const padded = try padRight(allocator, "123", 6, '0');
    defer allocator.free(padded);

    try std.testing.expectEqualStrings("123000", padded);
}

test "truncate" {
    const allocator = std.testing.allocator;

    const truncated = try truncate(allocator, "Hello, World!", 5);
    defer allocator.free(truncated);

    try std.testing.expectEqualStrings("Hello", truncated);
}
