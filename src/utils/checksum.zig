const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const keccak = @import("../crypto/keccak.zig");
const hex_module = @import("./hex.zig");

/// Convert an address to EIP-55 checksummed format
/// https://eips.ethereum.org/EIPS/eip-55
pub fn toChecksumAddress(allocator: std.mem.Allocator, address: Address) ![]u8 {
    // Get lowercase hex without 0x prefix
    const hex_full = try address.toHex(allocator);
    defer allocator.free(hex_full);

    const hex_lower = hex_full[2..]; // Skip "0x"

    // Hash the lowercase address
    const hash = keccak.hashString(hex_lower);

    // Apply checksum: uppercase if hash nibble >= 8
    var result = try allocator.alloc(u8, 42); // 0x + 40 chars
    result[0] = '0';
    result[1] = 'x';

    for (hex_lower, 0..) |c, i| {
        const hash_byte = hash.bytes[i / 2];
        const hash_nibble = if (i % 2 == 0) hash_byte >> 4 else hash_byte & 0x0f;

        if (hash_nibble >= 8 and c >= 'a' and c <= 'f') {
            result[2 + i] = c - 32; // Convert to uppercase
        } else {
            result[2 + i] = c;
        }
    }

    return result;
}

/// Verify that an address is correctly checksummed according to EIP-55
pub fn verifyChecksum(allocator: std.mem.Allocator, address_str: []const u8) !bool {
    // Must start with 0x and be 42 characters
    if (address_str.len != 42 or address_str[0] != '0' or address_str[1] != 'x') {
        return error.InvalidAddressFormat;
    }

    // If all lowercase or all uppercase (except 0x), it's valid but not checksummed
    const hex_part = address_str[2..];
    var has_lower = false;
    var has_upper = false;

    for (hex_part) |c| {
        if (c >= 'a' and c <= 'f') has_lower = true;
        if (c >= 'A' and c <= 'F') has_upper = true;
    }

    // All lowercase or all uppercase is considered valid (not checksummed)
    if (!has_lower or !has_upper) {
        return true;
    }

    // Parse address and compute correct checksum
    const addr = try Address.fromHex(address_str);
    const expected = try toChecksumAddress(allocator, addr);
    defer allocator.free(expected);

    // Compare
    return std.mem.eql(u8, address_str, expected);
}

/// Convert an address to EIP-1191 checksummed format with chain ID
/// https://eips.ethereum.org/EIPS/eip-1191
pub fn toChecksumAddressEip1191(
    allocator: std.mem.Allocator,
    address: Address,
    chain_id: u64,
) ![]u8 {
    // Get lowercase hex without 0x prefix
    const hex_full = try address.toHex(allocator);
    defer allocator.free(hex_full);

    const hex_lower = hex_full[2..]; // Skip "0x"

    // Prepare input: chain_id + "0x" + address_lowercase
    const input = try std.fmt.allocPrint(allocator, "{d}0x{s}", .{ chain_id, hex_lower });
    defer allocator.free(input);

    // Hash the input
    const hash = keccak.hashString(input);

    // Apply checksum
    var result = try allocator.alloc(u8, 42); // 0x + 40 chars
    result[0] = '0';
    result[1] = 'x';

    for (hex_lower, 0..) |c, i| {
        const hash_byte = hash.bytes[i / 2];
        const hash_nibble = if (i % 2 == 0) hash_byte >> 4 else hash_byte & 0x0f;

        if (hash_nibble >= 8 and c >= 'a' and c <= 'f') {
            result[2 + i] = c - 32; // Convert to uppercase
        } else {
            result[2 + i] = c;
        }
    }

    return result;
}

/// Verify EIP-1191 checksummed address
pub fn verifyChecksumEip1191(
    allocator: std.mem.Allocator,
    address_str: []const u8,
    chain_id: u64,
) !bool {
    if (address_str.len != 42 or address_str[0] != '0' or address_str[1] != 'x') {
        return error.InvalidAddressFormat;
    }

    const hex_part = address_str[2..];
    var has_lower = false;
    var has_upper = false;

    for (hex_part) |c| {
        if (c >= 'a' and c <= 'f') has_lower = true;
        if (c >= 'A' and c <= 'F') has_upper = true;
    }

    if (!has_lower or !has_upper) {
        return true;
    }

    const addr = try Address.fromHex(address_str);
    const expected = try toChecksumAddressEip1191(allocator, addr, chain_id);
    defer allocator.free(expected);

    return std.mem.eql(u8, address_str, expected);
}

/// Normalize an address to lowercase with 0x prefix
pub fn normalizeAddress(allocator: std.mem.Allocator, address_str: []const u8) ![]u8 {
    const addr = try Address.fromHex(address_str);
    return try addr.toHex(allocator);
}

/// Check if two addresses are equal (case-insensitive)
pub fn addressesEqual(addr1: []const u8, addr2: []const u8) !bool {
    if (addr1.len != 42 or addr2.len != 42) {
        return error.InvalidAddressFormat;
    }

    // Compare case-insensitively
    for (addr1, addr2) |c1, c2| {
        const lower1 = std.ascii.toLower(c1);
        const lower2 = std.ascii.toLower(c2);
        if (lower1 != lower2) {
            return false;
        }
    }

    return true;
}

test "checksum address EIP-55" {
    const allocator = std.testing.allocator;

    // Test with a known address
    const addr_bytes = [_]u8{
        0x5a, 0xAe, 0xB6, 0x05, 0x3F, 0x3E, 0x94, 0xC9,
        0xb9, 0xA0, 0x9f, 0x33, 0x66, 0x9a, 0x65, 0x7b,
        0xB6, 0xe4, 0x10, 0x57,
    };
    const addr = Address.fromBytes(addr_bytes);

    const checksummed = try toChecksumAddress(allocator, addr);
    defer allocator.free(checksummed);

    // Should have mixed case
    try std.testing.expect(checksummed.len == 42);
    try std.testing.expect(checksummed[0] == '0');
    try std.testing.expect(checksummed[1] == 'x');
}

test "verify checksum valid" {
    const allocator = std.testing.allocator;

    // All lowercase is valid (not checksummed but valid)
    const valid1 = try verifyChecksum(allocator, "0x5aaeb6053f3e94c9b9a09f33669a657bb6e41057");
    try std.testing.expect(valid1);

    // All uppercase is valid (not checksummed but valid)
    const valid2 = try verifyChecksum(allocator, "0x5AAEB6053F3E94C9B9A09F33669A657BB6E41057");
    try std.testing.expect(valid2);
}

test "checksum address EIP-1191" {
    const allocator = std.testing.allocator;

    const addr_bytes = [_]u8{
        0x5a, 0xAe, 0xB6, 0x05, 0x3F, 0x3E, 0x94, 0xC9,
        0xb9, 0xA0, 0x9f, 0x33, 0x66, 0x9a, 0x65, 0x7b,
        0xB6, 0xe4, 0x10, 0x57,
    };
    const addr = Address.fromBytes(addr_bytes);

    // Test with mainnet (chain_id = 1)
    const checksummed = try toChecksumAddressEip1191(allocator, addr, 1);
    defer allocator.free(checksummed);

    try std.testing.expect(checksummed.len == 42);
    try std.testing.expect(checksummed[0] == '0');
    try std.testing.expect(checksummed[1] == 'x');
}

test "normalize address" {
    const allocator = std.testing.allocator;

    const mixed_case = "0x5aAeB6053F3E94C9b9A09f33669a657Bb6e41057";
    const normalized = try normalizeAddress(allocator, mixed_case);
    defer allocator.free(normalized);

    try std.testing.expect(normalized.len == 42);

    // Should be all lowercase
    for (normalized[2..]) |c| {
        if (c >= 'a' and c <= 'f') {
            // Lowercase letters are ok
        } else if (c >= '0' and c <= '9') {
            // Numbers are ok
        } else {
            try std.testing.expect(false); // Should not have uppercase
        }
    }
}

test "addresses equal case insensitive" {
    const addr1 = "0x5aaeb6053f3e94c9b9a09f33669a657bb6e41057";
    const addr2 = "0x5AAEB6053F3E94C9B9A09F33669A657BB6E41057";
    const addr3 = "0x5aAeB6053F3E94C9b9A09f33669a657Bb6e41057";

    try std.testing.expect(try addressesEqual(addr1, addr2));
    try std.testing.expect(try addressesEqual(addr1, addr3));
    try std.testing.expect(try addressesEqual(addr2, addr3));
}

test "addresses not equal" {
    const addr1 = "0x5aaeb6053f3e94c9b9a09f33669a657bb6e41057";
    const addr2 = "0x1234567890123456789012345678901234567890";

    try std.testing.expect(!try addressesEqual(addr1, addr2));
}

test "invalid address format" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidAddressFormat, verifyChecksum(allocator, "0x123"));
    try std.testing.expectError(error.InvalidAddressFormat, verifyChecksum(allocator, "5aaeb6053f3e94c9b9a09f33669a657bb6e41057"));
}

test "verify EIP-1191 checksum" {
    const allocator = std.testing.allocator;

    const addr_bytes = [_]u8{
        0x5a, 0xAe, 0xB6, 0x05, 0x3F, 0x3E, 0x94, 0xC9,
        0xb9, 0xA0, 0x9f, 0x33, 0x66, 0x9a, 0x65, 0x7b,
        0xB6, 0xe4, 0x10, 0x57,
    };
    const addr = Address.fromBytes(addr_bytes);

    // Generate checksummed address for chain 1
    const checksummed = try toChecksumAddressEip1191(allocator, addr, 1);
    defer allocator.free(checksummed);

    // Verify it
    const is_valid = try verifyChecksumEip1191(allocator, checksummed, 1);
    try std.testing.expect(is_valid);
}
