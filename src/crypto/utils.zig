const std = @import("std");
const Hash = @import("../primitives/hash.zig").Hash;
const Address = @import("../primitives/address.zig").Address;
const keccak = @import("./keccak.zig");

/// Generate a random 32-byte value
pub fn randomBytes32(random: std.rand.Random) [32]u8 {
    var bytes: [32]u8 = undefined;
    random.bytes(&bytes);
    return bytes;
}

/// Generate random bytes of any length
pub fn randomBytes(allocator: std.mem.Allocator, random: std.rand.Random, len: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, len);
    random.bytes(bytes);
    return bytes;
}

/// Constant-time comparison of two byte slices
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) {
        return false;
    }

    var result: u8 = 0;
    for (a, b) |a_byte, b_byte| {
        result |= a_byte ^ b_byte;
    }

    return result == 0;
}

/// XOR two byte arrays of equal length
pub fn xorBytes(allocator: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    if (a.len != b.len) {
        return error.UnequalLength;
    }

    const result = try allocator.alloc(u8, a.len);
    for (a, b, 0..) |a_byte, b_byte, i| {
        result[i] = a_byte ^ b_byte;
    }

    return result;
}

/// Pad data to a multiple of block_size using PKCS#7 padding
pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8, block_size: usize) ![]u8 {
    const padding_len = block_size - (data.len % block_size);
    const padded_len = data.len + padding_len;

    const result = try allocator.alloc(u8, padded_len);
    @memcpy(result[0..data.len], data);

    // Fill padding bytes with padding length value
    @memset(result[data.len..], @intCast(padding_len));

    return result;
}

/// Remove PKCS#7 padding from data
pub fn pkcs7Unpad(data: []const u8) ![]const u8 {
    if (data.len == 0) {
        return error.InvalidPadding;
    }

    const padding_len = data[data.len - 1];
    if (padding_len == 0 or padding_len > data.len) {
        return error.InvalidPadding;
    }

    // Verify all padding bytes are correct
    const start = data.len - padding_len;
    for (data[start..]) |byte| {
        if (byte != padding_len) {
            return error.InvalidPadding;
        }
    }

    return data[0..start];
}

/// Derive a key using a simple KDF (Key Derivation Function)
/// Note: For production, use proper KDFs like PBKDF2, scrypt, or Argon2
pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    key_len: usize,
) ![]u8 {
    if (iterations == 0) {
        return error.InvalidIterations;
    }

    const key = try allocator.alloc(u8, key_len);

    // Simple iterative hashing (NOT secure for production)
    // Use PBKDF2 or better in production
    var current = try allocator.alloc(u8, password.len + salt.len);
    defer allocator.free(current);

    @memcpy(current[0..password.len], password);
    @memcpy(current[password.len..], salt);

    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        const hash_result = keccak.hash(current);
        @memcpy(current[0..32], &hash_result.bytes);
        if (current.len > 32) {
            @memcpy(current[32..], salt);
        }
    }

    const copy_len = @min(key_len, 32);
    @memcpy(key[0..copy_len], current[0..copy_len]);

    return key;
}

/// Calculate checksum for data using Keccak-256
pub fn checksum(data: []const u8) [4]u8 {
    const hash_result = keccak.hash(data);
    var result: [4]u8 = undefined;
    @memcpy(&result, hash_result.bytes[0..4]);
    return result;
}

/// Verify checksum
pub fn verifyChecksum(data: []const u8, expected: [4]u8) bool {
    const actual = checksum(data);
    return std.mem.eql(u8, &actual, &expected);
}

/// Compute EIP-55 checksummed address
pub fn checksumAddress(address: Address, allocator: std.mem.Allocator) ![]u8 {
    const hex = @import("../utils/hex.zig");

    // Get lowercase hex without 0x prefix
    const addr_hex = try hex.bytesToHex(allocator, &address.bytes);
    defer allocator.free(addr_hex);

    const addr_lower = addr_hex[2..]; // Skip "0x"

    // Hash the lowercase address
    const hash_result = keccak.hash(addr_lower);

    // Create checksummed version
    const result = try allocator.alloc(u8, 42); // "0x" + 40 hex chars
    result[0] = '0';
    result[1] = 'x';

    for (addr_lower, 0..) |char, i| {
        const hash_byte = hash_result.bytes[i / 2];
        const hash_nibble = if (i % 2 == 0) hash_byte >> 4 else hash_byte & 0x0F;

        if (char >= 'a' and char <= 'f') {
            // Uppercase if hash nibble >= 8
            result[2 + i] = if (hash_nibble >= 8)
                char - 32 // Convert to uppercase
            else
                char;
        } else {
            result[2 + i] = char;
        }
    }

    return result;
}

/// Convert address to EIP-1191 checksummed format (chain-specific)
pub fn checksumAddressEip1191(
    address: Address,
    chain_id: u64,
    allocator: std.mem.Allocator,
) ![]u8 {
    const hex = @import("../utils/hex.zig");

    // Format: chain_id + address (lowercase)
    const addr_hex = try hex.bytesToHex(allocator, &address.bytes);
    defer allocator.free(addr_hex);

    const addr_lower = addr_hex[2..]; // Skip "0x"

    const chain_str = try std.fmt.allocPrint(allocator, "{d}", .{chain_id});
    defer allocator.free(chain_str);

    // Concatenate chain_id + address
    const to_hash = try std.fmt.allocPrint(allocator, "{s}{s}", .{ chain_str, addr_lower });
    defer allocator.free(to_hash);

    const hash_result = keccak.hash(to_hash);

    // Create checksummed version
    const result = try allocator.alloc(u8, 42);
    result[0] = '0';
    result[1] = 'x';

    for (addr_lower, 0..) |char, i| {
        const hash_byte = hash_result.bytes[i / 2];
        const hash_nibble = if (i % 2 == 0) hash_byte >> 4 else hash_byte & 0x0F;

        if (char >= 'a' and char <= 'f') {
            result[2 + i] = if (hash_nibble >= 8) char - 32 else char;
        } else {
            result[2 + i] = char;
        }
    }

    return result;
}

test "random bytes generation" {
    var prng = std.rand.DefaultPrng.init(0);
    const random = prng.random();

    const bytes1 = randomBytes32(random);
    const bytes2 = randomBytes32(random);

    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &bytes1, &bytes2));
}

test "constant time equal" {
    const a = "hello";
    const b = "hello";
    const c = "world";

    try std.testing.expect(constantTimeEqual(a, b));
    try std.testing.expect(!constantTimeEqual(a, c));
}

test "xor bytes" {
    const allocator = std.testing.allocator;

    const a = [_]u8{ 0xFF, 0x00, 0xAA };
    const b = [_]u8{ 0x0F, 0xFF, 0x55 };

    const result = try xorBytes(allocator, &a, &b);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(u8, 0xF0), result[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), result[1]);
    try std.testing.expectEqual(@as(u8, 0xFF), result[2]);
}

test "pkcs7 padding" {
    const allocator = std.testing.allocator;

    const data = "hello";
    const padded = try pkcs7Pad(allocator, data, 8);
    defer allocator.free(padded);

    // Should be padded to 8 bytes
    try std.testing.expectEqual(@as(usize, 8), padded.len);

    // Last 3 bytes should be 0x03 (padding length)
    try std.testing.expectEqual(@as(u8, 3), padded[5]);
    try std.testing.expectEqual(@as(u8, 3), padded[6]);
    try std.testing.expectEqual(@as(u8, 3), padded[7]);

    // Unpad
    const unpadded = try pkcs7Unpad(padded);
    try std.testing.expectEqualStrings("hello", unpadded);
}

test "checksum calculation" {
    const data = "hello world";
    const cs = checksum(data);

    // Should be 4 bytes
    try std.testing.expect(cs.len == 4);

    // Verify checksum
    try std.testing.expect(verifyChecksum(data, cs));

    // Wrong checksum should fail
    const wrong = [_]u8{ 0, 0, 0, 0 };
    try std.testing.expect(!verifyChecksum(data, wrong));
}

test "key derivation" {
    const allocator = std.testing.allocator;

    const password = "my_password";
    const salt = "random_salt";

    const key = try deriveKey(allocator, password, salt, 1000, 32);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 32), key.len);
}
