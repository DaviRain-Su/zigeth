const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const uint_utils = @import("../primitives/uint.zig");

/// Packed ABI encoding (tightly packed, no padding)
/// Used for hashing and signature generation (e.g., EIP-712)
pub const PackedEncoder = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) PackedEncoder {
        return .{
            .allocator = allocator,
            .buffer = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *PackedEncoder) void {
        self.buffer.deinit();
    }

    /// Encode a uint256 (no padding)
    pub fn encodeUint256(self: *PackedEncoder, value: u256) !void {
        const bytes = uint_utils.u256ToBytes(value);
        try self.buffer.appendSlice(&bytes);
    }

    /// Encode a uint of specific size
    pub fn encodeUint(self: *PackedEncoder, value: u256, size_bytes: usize) !void {
        if (size_bytes > 32) return error.InvalidSize;

        const bytes = uint_utils.u256ToBytes(value);

        // Take only the required bytes from the end
        const offset = 32 - size_bytes;
        try self.buffer.appendSlice(bytes[offset..]);
    }

    /// Encode an address (20 bytes, no padding)
    pub fn encodeAddress(self: *PackedEncoder, addr: Address) !void {
        try self.buffer.appendSlice(&addr.bytes);
    }

    /// Encode a boolean (1 byte: 0x00 or 0x01)
    pub fn encodeBool(self: *PackedEncoder, value: bool) !void {
        try self.buffer.append(if (value) 1 else 0);
    }

    /// Encode bytes (no length prefix, no padding)
    pub fn encodeBytes(self: *PackedEncoder, data: []const u8) !void {
        try self.buffer.appendSlice(data);
    }

    /// Encode a string (UTF-8 bytes, no length prefix)
    pub fn encodeString(self: *PackedEncoder, str: []const u8) !void {
        try self.buffer.appendSlice(str);
    }

    /// Encode a hash (32 bytes)
    pub fn encodeHash(self: *PackedEncoder, hash: Hash) !void {
        try self.buffer.appendSlice(&hash.bytes);
    }

    /// Get the encoded data
    pub fn toSlice(self: *PackedEncoder) []const u8 {
        return self.buffer.items;
    }

    /// Get owned encoded data
    pub fn toOwnedSlice(self: *PackedEncoder) ![]u8 {
        return try self.buffer.toOwnedSlice();
    }

    /// Reset encoder for reuse
    pub fn reset(self: *PackedEncoder) void {
        self.buffer.clearRetainingCapacity();
    }
};

/// Encode multiple values in packed format
pub fn encodePacked(
    allocator: std.mem.Allocator,
    values: []const PackedValue,
) ![]u8 {
    var encoder = PackedEncoder.init(allocator);
    defer encoder.deinit();

    for (values) |value| {
        try encodePackedValue(&encoder, value);
    }

    return try encoder.toOwnedSlice();
}

/// Packed value (tightly packed, no padding)
pub const PackedValue = union(enum) {
    uint256: u256,
    uint: struct { value: u256, size_bytes: usize },
    address: Address,
    bool_val: bool,
    bytes: []const u8,
    string: []const u8,
    hash: Hash,
};

fn encodePackedValue(encoder: *PackedEncoder, value: PackedValue) !void {
    switch (value) {
        .uint256 => |u| try encoder.encodeUint256(u),
        .uint => |u| try encoder.encodeUint(u.value, u.size_bytes),
        .address => |a| try encoder.encodeAddress(a),
        .bool_val => |b| try encoder.encodeBool(b),
        .bytes => |b| try encoder.encodeBytes(b),
        .string => |s| try encoder.encodeString(s),
        .hash => |h| try encoder.encodeHash(h),
    }
}

/// Compute keccak256 of packed encoded values
pub fn hashPacked(
    allocator: std.mem.Allocator,
    values: []const PackedValue,
) !Hash {
    const encoded = try encodePacked(allocator, values);
    defer allocator.free(encoded);

    const keccak = @import("../crypto/keccak.zig");
    return keccak.hash(encoded);
}

test "packed encode uint256" {
    const allocator = std.testing.allocator;

    var encoder = PackedEncoder.init(allocator);
    defer encoder.deinit();

    const value = @as(u256, 42);
    try encoder.encodeUint256(value);

    const result = encoder.toSlice();
    try std.testing.expectEqual(@as(usize, 32), result.len);
    try std.testing.expectEqual(@as(u8, 42), result[31]);
}

test "packed encode address" {
    const allocator = std.testing.allocator;

    var encoder = PackedEncoder.init(allocator);
    defer encoder.deinit();

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    try encoder.encodeAddress(addr);

    const result = encoder.toSlice();
    // Should be exactly 20 bytes, no padding
    try std.testing.expectEqual(@as(usize, 20), result.len);
    try std.testing.expectEqual(@as(u8, 0x12), result[0]);
}

test "packed encode bool" {
    const allocator = std.testing.allocator;

    var encoder = PackedEncoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeBool(true);
    const result = encoder.toSlice();

    // Should be exactly 1 byte
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u8, 1), result[0]);
}

test "packed encode string" {
    const allocator = std.testing.allocator;

    var encoder = PackedEncoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeString("hello");
    const result = encoder.toSlice();

    // Should be exactly 5 bytes, no padding
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqualStrings("hello", result);
}

test "packed encode multiple values" {
    const allocator = std.testing.allocator;

    const values = [_]PackedValue{
        .{ .address = Address.fromBytes([_]u8{0xAB} ** 20) },
        .{ .uint256 = @as(u256, 100) },
        .{ .bool_val = true },
    };

    const encoded = try encodePacked(allocator, &values);
    defer allocator.free(encoded);

    // 20 (address) + 32 (uint256) + 1 (bool) = 53 bytes
    try std.testing.expectEqual(@as(usize, 53), encoded.len);
    try std.testing.expectEqual(@as(u8, 0xAB), encoded[0]);
    try std.testing.expectEqual(@as(u8, 100), encoded[51]); // uint256 value
    try std.testing.expectEqual(@as(u8, 1), encoded[52]); // bool
}

test "packed encode vs standard" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);

    // Packed: exactly 20 bytes
    var packed_enc = PackedEncoder.init(allocator);
    defer packed_enc.deinit();
    try packed_enc.encodeAddress(addr);
    try std.testing.expectEqual(@as(usize, 20), packed_enc.toSlice().len);

    // Standard ABI would be 32 bytes with left padding
    const Encoder = @import("./encode.zig").Encoder;
    var standard = Encoder.init(allocator);
    defer standard.deinit();
    try standard.encodeAddress(addr);
    try std.testing.expectEqual(@as(usize, 32), standard.toSlice().len);
}

test "hash packed values" {
    const allocator = std.testing.allocator;

    const values = [_]PackedValue{
        .{ .string = "hello" },
        .{ .uint256 = @as(u256, 123) },
    };

    const hash = try hashPacked(allocator, &values);

    // Should produce a valid hash
    try std.testing.expect(!hash.isZero());
}
