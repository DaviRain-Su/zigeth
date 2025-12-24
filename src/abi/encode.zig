const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const types = @import("./types.zig");
const uint_utils = @import("../primitives/uint.zig");

/// ABI encoder for Ethereum smart contract calls
pub const Encoder = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) !Encoder {
        return .{
            .allocator = allocator,
            .buffer = try std.ArrayList(u8).initCapacity(allocator, 0),
        };
    }

    pub fn deinit(self: *Encoder) void {
        self.buffer.deinit(self.allocator);
    }

    /// Encode a uint256 value
    pub fn encodeUint256(self: *Encoder, value: u256) !void {
        const bytes = uint_utils.u256ToBytes(value);
        try self.buffer.appendSlice(self.allocator, &bytes);
    }

    /// Encode a uint value of any size (padded to 32 bytes)
    /// Alias for encodeUint256 for clarity
    pub fn encodeUint(self: *Encoder, value: u256) !void {
        try self.encodeUint256(value);
    }

    /// Encode an int256 value
    pub fn encodeInt256(self: *Encoder, value: i256) !void {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(i256, &bytes, value, .big);
        try self.buffer.appendSlice(self.allocator, &bytes);
    }

    /// Encode an address (padded to 32 bytes, left-padded with zeros)
    pub fn encodeAddress(self: *Encoder, addr: Address) !void {
        var bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(bytes[12..32], &addr.bytes);
        try self.buffer.appendSlice(self.allocator, &bytes);
    }

    /// Encode a boolean (0 or 1, padded to 32 bytes)
    pub fn encodeBool(self: *Encoder, value: bool) !void {
        var bytes: [32]u8 = [_]u8{0} ** 32;
        bytes[31] = if (value) 1 else 0;
        try self.buffer.appendSlice(self.allocator, &bytes);
    }

    /// Encode fixed-size bytes (right-padded with zeros to 32 bytes)
    pub fn encodeFixedBytes(self: *Encoder, data: []const u8) !void {
        if (data.len > 32) return error.BytesTooLong;

        var bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(bytes[0..data.len], data);
        try self.buffer.appendSlice(self.allocator, &bytes);
    }

    /// Encode dynamic bytes (length + data, padded)
    pub fn encodeDynamicBytes(self: *Encoder, data: []const u8) !void {
        // Encode length
        try self.encodeUint(data.len);

        // Encode data with padding
        try self.buffer.appendSlice(self.allocator, data);

        // Pad to multiple of 32 bytes
        const padding = (32 - (data.len % 32)) % 32;
        if (padding > 0) {
            try self.buffer.appendNTimes(self.allocator, 0, padding);
        }
    }

    /// Encode a string (same as dynamic bytes)
    pub fn encodeString(self: *Encoder, str: []const u8) !void {
        try self.encodeDynamicBytes(str);
    }

    /// Get the encoded data
    pub fn toSlice(self: *Encoder) []const u8 {
        return self.buffer.items;
    }

    /// Get owned encoded data
    pub fn toOwnedSlice(self: *Encoder) ![]u8 {
        return try self.buffer.toOwnedSlice(self.allocator);
    }

    /// Reset the encoder for reuse
    pub fn reset(self: *Encoder) void {
        self.buffer.clearRetainingCapacity();
    }
};

/// Encode function call data (selector + encoded parameters)
pub fn encodeFunctionCall(
    allocator: std.mem.Allocator,
    function: types.Function,
    args: []const types.AbiValue,
) ![]u8 {
    if (args.len != function.inputs.len) {
        return error.ArgumentCountMismatch;
    }

    var encoder = try Encoder.init(allocator);
    defer encoder.deinit();

    // Add function selector (first 4 bytes)
    const selector = try function.getSelector(allocator);
    defer allocator.free(selector);
    try encoder.buffer.appendSlice(allocator, selector);

    // Encode arguments
    for (args, function.inputs) |arg, param| {
        try encodeValue(&encoder, arg, param.type);
    }

    return try encoder.toOwnedSlice();
}

/// Encode a single ABI value
fn encodeValue(encoder: *Encoder, value: types.AbiValue, abi_type: types.AbiType) !void {
    switch (value) {
        .uint => |u| try encoder.encodeUint256(u),
        .int => |i| try encoder.encodeInt256(i),
        .address => |a| try encoder.encodeAddress(a),
        .bool_val => |b| try encoder.encodeBool(b),
        .fixed_bytes => |fb| try encoder.encodeFixedBytes(fb),
        .string => |s| try encoder.encodeString(s),
        .bytes => |b| try encoder.encodeDynamicBytes(b),
        .array => |arr| {
            // Dynamic array: encode length + elements
            try encoder.encodeUint(arr.len);
            for (arr) |elem| {
                try encodeValue(encoder, elem, abi_type);
            }
        },
        .tuple => |tup| {
            // Tuple: encode each field
            if (abi_type != .tuple) return error.TypeMismatch;
            for (tup, 0..) |elem, i| {
                try encodeValue(encoder, elem, abi_type.tuple.fields[i]);
            }
        },
    }
}

/// Pad data to 32-byte boundary
pub fn padRight(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const padding = (32 - (data.len % 32)) % 32;
    const total_len = data.len + padding;
    const result = try allocator.alloc(u8, total_len);

    @memcpy(result[0..data.len], data);
    @memset(result[data.len..], 0);

    return result;
}

/// Pad data on the left (for numbers and addresses)
pub fn padLeft(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len >= 32) {
        return try allocator.dupe(u8, data[data.len - 32 ..]);
    }

    const result = try allocator.alloc(u8, 32);
    @memset(result[0 .. 32 - data.len], 0);
    @memcpy(result[32 - data.len ..], data);

    return result;
}

test "encode uint256" {
    const allocator = std.testing.allocator;

    var encoder = try Encoder.init(allocator);
    defer encoder.deinit();

    const value: u256 = 42;
    try encoder.encodeUint256(value);

    const result = encoder.toSlice();
    try std.testing.expectEqual(@as(usize, 32), result.len);
    try std.testing.expectEqual(@as(u8, 42), result[31]);
}

test "encode address" {
    const allocator = std.testing.allocator;

    var encoder = try Encoder.init(allocator);
    defer encoder.deinit();

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    try encoder.encodeAddress(addr);

    const result = encoder.toSlice();
    try std.testing.expectEqual(@as(usize, 32), result.len);
    // First 12 bytes should be zero (left padding)
    for (result[0..12]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
    // Last 20 bytes should be the address
    try std.testing.expectEqual(@as(u8, 0x12), result[12]);
}

test "encode bool" {
    const allocator = std.testing.allocator;

    var encoder = try Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeBool(true);
    const result_true = encoder.toSlice();
    try std.testing.expectEqual(@as(usize, 32), result_true.len);
    try std.testing.expectEqual(@as(u8, 1), result_true[31]);

    encoder.reset();
    try encoder.encodeBool(false);
    const result_false = encoder.toSlice();
    try std.testing.expectEqual(@as(usize, 32), result_false.len);
    try std.testing.expectEqual(@as(u8, 0), result_false[31]);
}

test "encode string" {
    const allocator = std.testing.allocator;

    var encoder = try Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeString("hello");
    const result = encoder.toSlice();

    // Should have: length (32 bytes) + data (5 bytes) + padding (27 bytes) = 64 bytes
    try std.testing.expectEqual(@as(usize, 64), result.len);
    // Length should be 5
    try std.testing.expectEqual(@as(u8, 5), result[31]);
    // Data should start at byte 32
    try std.testing.expectEqualStrings("hello", result[32..37]);
}

test "encode fixed bytes" {
    const allocator = std.testing.allocator;

    var encoder = try Encoder.init(allocator);
    defer encoder.deinit();

    const data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try encoder.encodeFixedBytes(&data);

    const result = encoder.toSlice();
    try std.testing.expectEqual(@as(usize, 32), result.len);
    try std.testing.expectEqual(@as(u8, 0xde), result[0]);
    try std.testing.expectEqual(@as(u8, 0xad), result[1]);
    try std.testing.expectEqual(@as(u8, 0xbe), result[2]);
    try std.testing.expectEqual(@as(u8, 0xef), result[3]);
}

test "pad left" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x12, 0x34 };
    const padded = try padLeft(allocator, &data);
    defer allocator.free(padded);

    try std.testing.expectEqual(@as(usize, 32), padded.len);
    try std.testing.expectEqual(@as(u8, 0x12), padded[30]);
    try std.testing.expectEqual(@as(u8, 0x34), padded[31]);
}

test "pad right" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x12, 0x34 };
    const padded = try padRight(allocator, &data);
    defer allocator.free(padded);

    try std.testing.expectEqual(@as(usize, 32), padded.len);
    try std.testing.expectEqual(@as(u8, 0x12), padded[0]);
    try std.testing.expectEqual(@as(u8, 0x34), padded[1]);
    // Rest should be zeros
    for (padded[2..]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
