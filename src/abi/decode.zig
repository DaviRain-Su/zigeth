const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const types = @import("./types.zig");
const uint_utils = @import("../primitives/uint.zig");

/// ABI decoder for Ethereum smart contract responses
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    data: []const u8,
    position: usize,

    pub fn init(allocator: std.mem.Allocator, data: []const u8) Decoder {
        return .{
            .allocator = allocator,
            .data = data,
            .position = 0,
        };
    }

    /// Read 32 bytes at current position
    fn read32(self: *Decoder) ![]const u8 {
        if (self.position + 32 > self.data.len) {
            return error.InsufficientData;
        }
        const slice = self.data[self.position .. self.position + 32];
        self.position += 32;
        return slice;
    }

    /// Decode a uint256
    pub fn decodeUint256(self: *Decoder) !u256 {
        const bytes = try self.read32();
        var arr: [32]u8 = undefined;
        @memcpy(&arr, bytes);
        return uint_utils.u256FromBytes(arr);
    }

    /// Decode a uint of any size
    /// Alias for decodeUint256 for clarity
    pub fn decodeUint(self: *Decoder) !u256 {
        return self.decodeUint256();
    }

    /// Decode an address
    pub fn decodeAddress(self: *Decoder) !Address {
        const bytes = try self.read32();
        // Address is the last 20 bytes
        var addr_bytes: [20]u8 = undefined;
        @memcpy(&addr_bytes, bytes[12..32]);
        return Address.fromBytes(addr_bytes);
    }

    /// Decode a boolean
    pub fn decodeBool(self: *Decoder) !bool {
        const bytes = try self.read32();
        return bytes[31] != 0;
    }

    /// Decode fixed-size bytes
    pub fn decodeFixedBytes(self: *Decoder, size: usize) ![]u8 {
        if (size > 32) return error.InvalidSize;

        const bytes = try self.read32();
        const result = try self.allocator.alloc(u8, size);
        @memcpy(result, bytes[0..size]);
        return result;
    }

    /// Decode dynamic bytes
    pub fn decodeDynamicBytes(self: *Decoder) ![]u8 {
        const length = try self.decodeUint();
        if (length > self.data.len) return error.InvalidLength;

        const len_usize = @as(usize, @intCast(length));
        if (self.position + len_usize > self.data.len) {
            return error.InsufficientData;
        }

        const result = try self.allocator.alloc(u8, len_usize);
        @memcpy(result, self.data[self.position .. self.position + len_usize]);

        // Skip data and padding
        const padding = (32 - (len_usize % 32)) % 32;
        self.position += len_usize + padding;

        return result;
    }

    /// Decode a string
    pub fn decodeString(self: *Decoder) ![]u8 {
        return try self.decodeDynamicBytes();
    }

    /// Get current position
    pub fn getPosition(self: Decoder) usize {
        return self.position;
    }

    /// Set position
    pub fn setPosition(self: *Decoder, pos: usize) void {
        self.position = pos;
    }

    /// Check if more data is available
    pub fn hasMore(self: Decoder) bool {
        return self.position < self.data.len;
    }
};

/// Decode function return data
pub fn decodeFunctionReturn(
    allocator: std.mem.Allocator,
    data: []const u8,
    output_types: []const types.Parameter,
) ![]types.AbiValue {
    var decoder = Decoder.init(allocator, data);
    var results = try std.ArrayList(types.AbiValue).initCapacity(allocator, 0);
    defer results.deinit(allocator);

    for (output_types) |param| {
        const value = try decodeValue(&decoder, param.type);
        try results.append(allocator, value);
    }

    return try results.toOwnedSlice(allocator);
}

/// Decode a single value
fn decodeValue(decoder: *Decoder, abi_type: types.AbiType) !types.AbiValue {
    return switch (abi_type) {
        .uint256, .uint128, .uint64, .uint32, .uint16, .uint8 => .{ .uint = try decoder.decodeUint256() },
        .int256, .int128, .int64, .int32, .int16, .int8 => .{ .int = @bitCast(try decoder.decodeUint()) },
        .address => .{ .address = try decoder.decodeAddress() },
        .bool_type => .{ .bool_val = try decoder.decodeBool() },
        .bytes32, .bytes16, .bytes8, .bytes4, .bytes2, .bytes1 => .{ .fixed_bytes = try decoder.decodeFixedBytes(32) },
        .string => .{ .string = try decoder.decodeString() },
        .bytes => .{ .bytes = try decoder.decodeDynamicBytes() },
        else => error.NotImplemented,
    };
}

test "decode uint256" {
    const allocator = std.testing.allocator;

    var data: [32]u8 = [_]u8{0} ** 32;
    data[31] = 42;

    var decoder = Decoder.init(allocator, &data);
    const value = try decoder.decodeUint256();

    try std.testing.expectEqual(@as(u256, 42), value);
}

test "decode address" {
    const allocator = std.testing.allocator;

    var data: [32]u8 = [_]u8{0} ** 32;
    @memset(data[12..32], 0xAB);

    var decoder = Decoder.init(allocator, &data);
    const addr = try decoder.decodeAddress();

    try std.testing.expectEqual(@as(u8, 0xAB), addr.bytes[0]);
}

test "decode bool" {
    const allocator = std.testing.allocator;

    var data_true: [32]u8 = [_]u8{0} ** 32;
    data_true[31] = 1;

    var decoder_true = Decoder.init(allocator, &data_true);
    try std.testing.expect(try decoder_true.decodeBool());

    var data_false: [32]u8 = [_]u8{0} ** 32;
    var decoder_false = Decoder.init(allocator, &data_false);
    try std.testing.expect(!try decoder_false.decodeBool());
}

test "decode string" {
    const allocator = std.testing.allocator;

    // Encoded "hello": length (32 bytes) + data (5 bytes) + padding (27 bytes)
    var data: [64]u8 = [_]u8{0} ** 64;
    data[31] = 5; // length
    @memcpy(data[32..37], "hello");

    var decoder = Decoder.init(allocator, &data);
    const str = try decoder.decodeString();
    defer allocator.free(str);

    try std.testing.expectEqualStrings("hello", str);
}

test "decode multiple values" {
    const allocator = std.testing.allocator;

    var data: [96]u8 = [_]u8{0} ** 96;
    // First value: uint256 = 100
    data[31] = 100;
    // Second value: address
    @memset(data[44..64], 0xAB);
    // Third value: bool = true
    data[95] = 1;

    var decoder = Decoder.init(allocator, &data);

    const val1 = try decoder.decodeUint256();
    try std.testing.expectEqual(@as(u256, 100), val1);

    const val2 = try decoder.decodeAddress();
    try std.testing.expectEqual(@as(u8, 0xAB), val2.bytes[0]);

    const val3 = try decoder.decodeBool();
    try std.testing.expect(val3);

    try std.testing.expect(!decoder.hasMore());
}
