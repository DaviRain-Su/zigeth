const std = @import("std");

/// Decoded RLP value
pub const RlpValue = union(enum) {
    bytes: []const u8,
    list: []RlpValue,

    pub fn deinit(self: RlpValue, allocator: std.mem.Allocator) void {
        switch (self) {
            .bytes => {}, // Data is a slice into original buffer
            .list => |items| {
                for (items) |item| {
                    item.deinit(allocator);
                }
                allocator.free(items);
            },
        }
    }

    /// Check if this is a bytes value
    pub fn isBytes(self: RlpValue) bool {
        return self == .bytes;
    }

    /// Check if this is a list
    pub fn isList(self: RlpValue) bool {
        return self == .list;
    }

    /// Get bytes value (returns error if not bytes)
    pub fn getBytes(self: RlpValue) ![]const u8 {
        if (self.isBytes()) {
            return self.bytes;
        }
        return error.NotBytes;
    }

    /// Get list value (returns error if not list)
    pub fn getList(self: RlpValue) ![]RlpValue {
        if (self.isList()) {
            return self.list;
        }
        return error.NotList;
    }
};

/// RLP Decoder
pub const Decoder = struct {
    data: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, data: []const u8) Decoder {
        return .{
            .data = data,
            .pos = 0,
            .allocator = allocator,
        };
    }

    /// Decode next RLP value
    pub fn decode(self: *Decoder) !RlpValue {
        if (self.pos >= self.data.len) {
            return error.UnexpectedEndOfInput;
        }

        const prefix = self.data[self.pos];
        self.pos += 1;

        if (prefix <= 0x7f) {
            // Single byte
            return RlpValue{ .bytes = self.data[self.pos - 1 .. self.pos] };
        } else if (prefix <= 0xb7) {
            // Short string (0-55 bytes)
            const length = prefix - 0x80;
            if (self.pos + length > self.data.len) {
                return error.UnexpectedEndOfInput;
            }
            const result = RlpValue{ .bytes = self.data[self.pos .. self.pos + length] };
            self.pos += length;
            return result;
        } else if (prefix <= 0xbf) {
            // Long string (> 55 bytes)
            const len_of_len = prefix - 0xb7;
            if (self.pos + len_of_len > self.data.len) {
                return error.UnexpectedEndOfInput;
            }

            const length = try decodeLength(self.data[self.pos .. self.pos + len_of_len]);
            self.pos += len_of_len;

            if (self.pos + length > self.data.len) {
                return error.UnexpectedEndOfInput;
            }

            const result = RlpValue{ .bytes = self.data[self.pos .. self.pos + length] };
            self.pos += length;
            return result;
        } else if (prefix <= 0xf7) {
            // Short list (0-55 bytes total payload)
            const length = prefix - 0xc0;
            if (self.pos + length > self.data.len) {
                return error.UnexpectedEndOfInput;
            }

            return try self.decodeListPayload(self.pos + length);
        } else {
            // Long list (> 55 bytes total payload)
            const len_of_len = prefix - 0xf7;
            if (self.pos + len_of_len > self.data.len) {
                return error.UnexpectedEndOfInput;
            }

            const length = try decodeLength(self.data[self.pos .. self.pos + len_of_len]);
            self.pos += len_of_len;

            if (self.pos + length > self.data.len) {
                return error.UnexpectedEndOfInput;
            }

            return try self.decodeListPayload(self.pos + length);
        }
    }

    /// Decode list payload
    fn decodeListPayload(self: *Decoder, end: usize) !RlpValue {
        var items = try std.ArrayList(RlpValue).initCapacity(self.allocator, 0);
        errdefer {
            for (items.items) |item| {
                item.deinit(self.allocator);
            }
            items.deinit(self.allocator);
        }

        while (self.pos < end) {
            const item = try self.decode();
            try items.append(self.allocator, item);
        }

        if (self.pos != end) {
            return error.InvalidListLength;
        }

        return RlpValue{ .list = try items.toOwnedSlice(self.allocator) };
    }

    /// Check if there's more data
    pub fn hasMore(self: Decoder) bool {
        return self.pos < self.data.len;
    }
};

/// Decode length from big-endian bytes
fn decodeLength(bytes: []const u8) !usize {
    if (bytes.len == 0 or bytes.len > 8) {
        return error.InvalidLength;
    }

    var result: usize = 0;
    for (bytes) |byte| {
        result = (result << 8) | byte;
    }

    return result;
}

/// Decode a single RLP value
pub fn decode(allocator: std.mem.Allocator, data: []const u8) !RlpValue {
    var decoder = Decoder.init(allocator, data);
    return try decoder.decode();
}

/// Decode bytes from RLP
pub fn decodeBytes(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const value = try decode(allocator, data);
    defer value.deinit(allocator);

    return try value.getBytes();
}

/// Decode list from RLP
pub fn decodeList(allocator: std.mem.Allocator, data: []const u8) ![]RlpValue {
    const value = try decode(allocator, data);
    // Don't deinit here - caller owns the list

    return try value.getList();
}

/// Decode uint from RLP bytes
pub fn decodeUint(data: []const u8) !u64 {
    if (data.len == 0) {
        return 0;
    }
    if (data.len > 8) {
        return error.ValueTooLarge;
    }

    var result: u64 = 0;
    for (data) |byte| {
        result = (result << 8) | byte;
    }

    return result;
}

test "decode single byte" {
    const allocator = std.testing.allocator;

    const data = [_]u8{0x42};
    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isBytes());
    const bytes = try value.getBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, bytes);
}

test "decode empty string" {
    const allocator = std.testing.allocator;

    const data = [_]u8{0x80};
    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isBytes());
    const bytes = try value.getBytes();
    try std.testing.expectEqual(@as(usize, 0), bytes.len);
}

test "decode short string" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x83, 'd', 'o', 'g' };
    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isBytes());
    const bytes = try value.getBytes();
    try std.testing.expectEqualSlices(u8, "dog", bytes);
}

test "decode long string" {
    const allocator = std.testing.allocator;

    // 56 bytes of 0x42
    var data: [58]u8 = undefined;
    data[0] = 0xb8; // Long string prefix
    data[1] = 56; // Length
    @memset(data[2..], 0x42);

    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isBytes());
    const bytes = try value.getBytes();
    try std.testing.expectEqual(@as(usize, 56), bytes.len);
}

test "decode empty list" {
    const allocator = std.testing.allocator;

    const data = [_]u8{0xc0};
    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isList());
    const list = try value.getList();
    try std.testing.expectEqual(@as(usize, 0), list.len);
}

test "decode list of strings" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' };
    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isList());
    const list = try value.getList();
    try std.testing.expectEqual(@as(usize, 2), list.len);

    const cat = try list[0].getBytes();
    const dog = try list[1].getBytes();
    try std.testing.expectEqualSlices(u8, "cat", cat);
    try std.testing.expectEqualSlices(u8, "dog", dog);
}

test "decode nested list" {
    const allocator = std.testing.allocator;

    // [["a"], "b"]
    const data = [_]u8{ 0xc4, 0xc1, 0x61, 0x62 };
    const value = try decode(allocator, &data);
    defer value.deinit(allocator);

    try std.testing.expect(value.isList());
    const list = try value.getList();
    try std.testing.expectEqual(@as(usize, 2), list.len);

    // First item is a list
    try std.testing.expect(list[0].isList());
    const inner_list = try list[0].getList();
    try std.testing.expectEqual(@as(usize, 1), inner_list.len);

    const a = try inner_list[0].getBytes();
    try std.testing.expectEqualSlices(u8, "a", a);

    // Second item is bytes
    const b = try list[1].getBytes();
    try std.testing.expectEqualSlices(u8, "b", b);
}

test "decode uint zero" {
    const data = [_]u8{};
    const value = try decodeUint(&data);
    try std.testing.expectEqual(@as(u64, 0), value);
}

test "decode uint small" {
    const data = [_]u8{0x7f};
    const value = try decodeUint(&data);
    try std.testing.expectEqual(@as(u64, 127), value);
}

test "decode uint 128" {
    const data = [_]u8{0x80};
    const value = try decodeUint(&data);
    try std.testing.expectEqual(@as(u64, 128), value);
}

test "decode uint large" {
    const data = [_]u8{ 0x12, 0x34, 0x56 };
    const value = try decodeUint(&data);
    try std.testing.expectEqual(@as(u64, 0x123456), value);
}

test "decode multiple values" {
    const allocator = std.testing.allocator;

    // Two strings: "cat" and "dog"
    const data = [_]u8{ 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' };

    var decoder = Decoder.init(allocator, &data);

    const value1 = try decoder.decode();
    defer value1.deinit(allocator);
    const cat = try value1.getBytes();
    try std.testing.expectEqualSlices(u8, "cat", cat);

    const value2 = try decoder.decode();
    defer value2.deinit(allocator);
    const dog = try value2.getBytes();
    try std.testing.expectEqualSlices(u8, "dog", dog);

    try std.testing.expect(!decoder.hasMore());
}

test "roundtrip encoding and decoding" {
    const allocator = std.testing.allocator;
    const encode_module = @import("./encode.zig");

    // Encode a list
    const items = [_]encode_module.RlpItem{
        .{ .string = "hello" },
        .{ .uint = 42 },
    };

    const encoded = try encode_module.encodeList(allocator, &items);
    defer allocator.free(encoded);

    // Decode it back
    const value = try decode(allocator, encoded);
    defer value.deinit(allocator);

    try std.testing.expect(value.isList());
    const list = try value.getList();
    try std.testing.expectEqual(@as(usize, 2), list.len);

    const hello = try list[0].getBytes();
    try std.testing.expectEqualSlices(u8, "hello", hello);

    const num_bytes = try list[1].getBytes();
    const num = try decodeUint(num_bytes);
    try std.testing.expectEqual(@as(u64, 42), num);
}
