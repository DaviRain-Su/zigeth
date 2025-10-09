const std = @import("std");

/// RLP Item represents data to be encoded
pub const RlpItem = union(enum) {
    bytes: []const u8,
    list: []const RlpItem,
    string: []const u8,
    uint: u64,
    bigint: []const u8, // Big-endian bytes for large numbers
};

/// RLP Encoder for building encoded data
pub const Encoder = struct {
    buffer: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Encoder {
        return .{
            .buffer = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Encoder) void {
        self.buffer.deinit();
    }

    /// Get the encoded bytes
    pub fn toSlice(self: Encoder) []const u8 {
        return self.buffer.items;
    }

    /// Get owned slice and reset encoder
    pub fn toOwnedSlice(self: *Encoder) ![]u8 {
        return try self.buffer.toOwnedSlice();
    }

    /// Encode an RLP item
    pub fn encode(self: *Encoder, item: RlpItem) std.mem.Allocator.Error!void {
        switch (item) {
            .bytes => |b| try self.encodeBytes(b),
            .string => |s| try self.encodeBytes(s),
            .list => |l| try self.encodeList(l),
            .uint => |u| {
                // Convert uint to minimal big-endian bytes
                if (u == 0) {
                    try self.encodeBytes(&[_]u8{});
                } else {
                    var bytes = [_]u8{0} ** 8;
                    std.mem.writeInt(u64, &bytes, u, .big);

                    // Find first non-zero byte
                    var start: usize = 0;
                    while (start < 8 and bytes[start] == 0) : (start += 1) {}

                    try self.encodeBytes(bytes[start..]);
                }
            },
            .bigint => |b| try self.encodeBytes(b),
        }
    }

    /// Encode bytes (string)
    pub fn encodeBytes(self: *Encoder, data: []const u8) !void {
        if (data.len == 0) {
            // Empty string
            try self.buffer.append(0x80);
        } else if (data.len == 1 and data[0] < 0x80) {
            // Single byte < 0x80
            try self.buffer.append(data[0]);
        } else if (data.len <= 55) {
            // Short string (0-55 bytes)
            try self.buffer.append(0x80 + @as(u8, @intCast(data.len)));
            try self.buffer.appendSlice(data);
        } else {
            // Long string (> 55 bytes)
            const len_bytes = try encodeLengthBytes(self.allocator, data.len);
            defer self.allocator.free(len_bytes);

            try self.buffer.append(0xb7 + @as(u8, @intCast(len_bytes.len)));
            try self.buffer.appendSlice(len_bytes);
            try self.buffer.appendSlice(data);
        }
    }

    /// Encode a list of items
    pub fn encodeList(self: *Encoder, items: []const RlpItem) !void {
        // Encode all items to a temporary buffer
        var temp_encoder = Encoder.init(self.allocator);
        defer temp_encoder.deinit();

        for (items) |item| {
            try temp_encoder.encode(item);
        }

        const payload = temp_encoder.toSlice();

        if (payload.len <= 55) {
            // Short list
            try self.buffer.append(0xc0 + @as(u8, @intCast(payload.len)));
            try self.buffer.appendSlice(payload);
        } else {
            // Long list
            const len_bytes = try encodeLengthBytes(self.allocator, payload.len);
            defer self.allocator.free(len_bytes);

            try self.buffer.append(0xf7 + @as(u8, @intCast(len_bytes.len)));
            try self.buffer.appendSlice(len_bytes);
            try self.buffer.appendSlice(payload);
        }
    }
};

/// Encode length as big-endian bytes (minimal representation)
fn encodeLengthBytes(allocator: std.mem.Allocator, length: usize) ![]u8 {
    if (length == 0) {
        return try allocator.dupe(u8, &[_]u8{0});
    }

    // Count bytes needed
    var temp = length;
    var byte_count: usize = 0;
    while (temp > 0) : (temp >>= 8) {
        byte_count += 1;
    }

    var result = try allocator.alloc(u8, byte_count);

    // Write big-endian
    temp = length;
    var i: usize = byte_count;
    while (i > 0) {
        i -= 1;
        result[i] = @as(u8, @intCast(temp & 0xFF));
        temp >>= 8;
    }

    return result;
}

/// Encode a single item and return owned slice
pub fn encodeItem(allocator: std.mem.Allocator, item: RlpItem) ![]u8 {
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encode(item);
    return try encoder.toOwnedSlice();
}

/// Encode a list of items and return owned slice
pub fn encodeList(allocator: std.mem.Allocator, items: []const RlpItem) ![]u8 {
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeList(items);
    return try encoder.toOwnedSlice();
}

/// Encode bytes and return owned slice
pub fn encodeBytes(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeBytes(data);
    return try encoder.toOwnedSlice();
}

/// Encode a uint and return owned slice
pub fn encodeUint(allocator: std.mem.Allocator, value: u64) ![]u8 {
    return try encodeItem(allocator, .{ .uint = value });
}

test "encode single byte less than 0x80" {
    const allocator = std.testing.allocator;

    const encoded = try encodeBytes(allocator, &[_]u8{0x42});
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, encoded);
}

test "encode empty string" {
    const allocator = std.testing.allocator;

    const encoded = try encodeBytes(allocator, &[_]u8{});
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, encoded);
}

test "encode short string" {
    const allocator = std.testing.allocator;

    const data = "dog";
    const encoded = try encodeBytes(allocator, data);
    defer allocator.free(encoded);

    // Expected: 0x83 (0x80 + 3) followed by "dog"
    const expected = [_]u8{ 0x83, 'd', 'o', 'g' };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode long string" {
    const allocator = std.testing.allocator;

    // 56 bytes
    const data = [_]u8{0x42} ** 56;
    const encoded = try encodeBytes(allocator, &data);
    defer allocator.free(encoded);

    // Expected: 0xb8 (0xb7 + 1), 0x38 (56), then 56 bytes
    try std.testing.expectEqual(@as(u8, 0xb8), encoded[0]);
    try std.testing.expectEqual(@as(u8, 56), encoded[1]);
    try std.testing.expectEqual(@as(usize, 58), encoded.len);
}

test "encode empty list" {
    const allocator = std.testing.allocator;

    const items = [_]RlpItem{};
    const encoded = try encodeList(allocator, &items);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{0xc0}, encoded);
}

test "encode list of strings" {
    const allocator = std.testing.allocator;

    const items = [_]RlpItem{
        .{ .string = "cat" },
        .{ .string = "dog" },
    };

    const encoded = try encodeList(allocator, &items);
    defer allocator.free(encoded);

    // Expected: 0xc8 (0xc0 + 8), then encoded items
    // "cat" = 0x83 'c' 'a' 't' (4 bytes)
    // "dog" = 0x83 'd' 'o' 'g' (4 bytes)
    const expected = [_]u8{ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode nested list" {
    const allocator = std.testing.allocator;

    const inner = [_]RlpItem{.{ .string = "a" }};
    const items = [_]RlpItem{
        .{ .list = &inner },
        .{ .string = "b" },
    };

    const encoded = try encodeList(allocator, &items);
    defer allocator.free(encoded);

    // Inner list ["a"] = 0xc1 0x61
    // Outer list [["a"], "b"] = 0xc4 0xc1 0x61 0x62
    const expected = [_]u8{ 0xc4, 0xc1, 0x61, 0x62 };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode uint zero" {
    const allocator = std.testing.allocator;

    const encoded = try encodeUint(allocator, 0);
    defer allocator.free(encoded);

    // Zero is encoded as empty string
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, encoded);
}

test "encode uint small" {
    const allocator = std.testing.allocator;

    const encoded = try encodeUint(allocator, 127);
    defer allocator.free(encoded);

    // 127 = 0x7f, which is a single byte < 0x80
    try std.testing.expectEqualSlices(u8, &[_]u8{0x7f}, encoded);
}

test "encode uint 128" {
    const allocator = std.testing.allocator;

    const encoded = try encodeUint(allocator, 128);
    defer allocator.free(encoded);

    // 128 = 0x80, encoded as string
    const expected = [_]u8{ 0x81, 0x80 };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode uint large" {
    const allocator = std.testing.allocator;

    const encoded = try encodeUint(allocator, 0x123456);
    defer allocator.free(encoded);

    // 0x123456 = 3 bytes
    const expected = [_]u8{ 0x83, 0x12, 0x34, 0x56 };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode item union" {
    const allocator = std.testing.allocator;

    var encoder = Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encode(.{ .bytes = "hello" });

    const result = encoder.toSlice();
    const expected = [_]u8{ 0x85, 'h', 'e', 'l', 'l', 'o' };
    try std.testing.expectEqualSlices(u8, &expected, result);
}
