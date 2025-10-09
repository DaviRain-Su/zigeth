const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Bytes = @import("../primitives/bytes.zig").Bytes;

/// ABI type system for Solidity types
pub const AbiType = union(enum) {
    // Static types (fixed size)
    uint8,
    uint16,
    uint32,
    uint64,
    uint128,
    uint256,
    int8,
    int16,
    int32,
    int64,
    int128,
    int256,
    address,
    bool_type,

    // Fixed-size bytes
    bytes1,
    bytes2,
    bytes4,
    bytes8,
    bytes16,
    bytes32,

    // Dynamic types
    string,
    bytes,

    // Complex types
    array: struct {
        element_type: *const AbiType,
        length: ?usize, // null for dynamic arrays
    },

    tuple: struct {
        fields: []const AbiType,
    },

    /// Check if type is dynamic (requires length prefix)
    pub fn isDynamic(self: AbiType) bool {
        return switch (self) {
            .string, .bytes => true,
            .array => |arr| arr.length == null or arr.element_type.isDynamic(),
            .tuple => |tup| {
                for (tup.fields) |field| {
                    if (field.isDynamic()) return true;
                }
                return false;
            },
            else => false,
        };
    }

    /// Get the size of a static type in bytes
    pub fn staticSize(self: AbiType) ?usize {
        return switch (self) {
            .uint8, .int8 => 32, // All types padded to 32 bytes
            .uint16, .int16 => 32,
            .uint32, .int32 => 32,
            .uint64, .int64 => 32,
            .uint128, .int128 => 32,
            .uint256, .int256 => 32,
            .address => 32,
            .bool_type => 32,
            .bytes1, .bytes2, .bytes4, .bytes8, .bytes16, .bytes32 => 32,
            .string, .bytes => null, // Dynamic
            .array => |arr| {
                if (arr.length) |len| {
                    if (arr.element_type.staticSize()) |elem_size| {
                        return elem_size * len;
                    }
                }
                return null; // Dynamic
            },
            .tuple => |tup| {
                var total: usize = 0;
                for (tup.fields) |field| {
                    if (field.staticSize()) |size| {
                        total += size;
                    } else {
                        return null; // Contains dynamic field
                    }
                }
                return total;
            },
        };
    }

    /// Convert AbiType to string representation for selector generation
    pub fn toString(self: AbiType, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .uint8 => try allocator.dupe(u8, "uint8"),
            .uint16 => try allocator.dupe(u8, "uint16"),
            .uint32 => try allocator.dupe(u8, "uint32"),
            .uint64 => try allocator.dupe(u8, "uint64"),
            .uint128 => try allocator.dupe(u8, "uint128"),
            .uint256 => try allocator.dupe(u8, "uint256"),
            .int8 => try allocator.dupe(u8, "int8"),
            .int16 => try allocator.dupe(u8, "int16"),
            .int32 => try allocator.dupe(u8, "int32"),
            .int64 => try allocator.dupe(u8, "int64"),
            .int128 => try allocator.dupe(u8, "int128"),
            .int256 => try allocator.dupe(u8, "int256"),
            .address => try allocator.dupe(u8, "address"),
            .bool_type => try allocator.dupe(u8, "bool"),
            .bytes1 => try allocator.dupe(u8, "bytes1"),
            .bytes2 => try allocator.dupe(u8, "bytes2"),
            .bytes4 => try allocator.dupe(u8, "bytes4"),
            .bytes8 => try allocator.dupe(u8, "bytes8"),
            .bytes16 => try allocator.dupe(u8, "bytes16"),
            .bytes32 => try allocator.dupe(u8, "bytes32"),
            .string => try allocator.dupe(u8, "string"),
            .bytes => try allocator.dupe(u8, "bytes"),
            .array => |arr| {
                const elem_str = try arr.element_type.toString(allocator);
                defer allocator.free(elem_str);
                if (arr.length) |len| {
                    return try std.fmt.allocPrint(allocator, "{s}[{d}]", .{ elem_str, len });
                } else {
                    return try std.fmt.allocPrint(allocator, "{s}[]", .{elem_str});
                }
            },
            .tuple => try allocator.dupe(u8, "tuple"),
        };
    }
};

/// ABI encoded value
pub const AbiValue = union(enum) {
    uint: u256,
    int: i256,
    address: Address,
    bool_val: bool,
    fixed_bytes: []const u8,
    string: []const u8,
    bytes: []const u8,
    array: []const AbiValue,
    tuple: []const AbiValue,
};

/// Function parameter definition
pub const Parameter = struct {
    name: []const u8,
    type: AbiType,
    indexed: bool = false, // For events
};

/// Function signature
pub const Function = struct {
    name: []const u8,
    inputs: []const Parameter,
    outputs: []const Parameter,
    state_mutability: StateMutability,

    pub const StateMutability = enum {
        pure,
        view,
        nonpayable,
        payable,
    };

    /// Get function selector (first 4 bytes of keccak256(signature))
    pub fn getSelector(self: Function, allocator: std.mem.Allocator) ![]u8 {
        const signature = try self.getSignature(allocator);
        defer allocator.free(signature);

        const keccak = @import("../crypto/keccak.zig");
        const selector = keccak.functionSelector(signature);

        return try allocator.dupe(u8, &selector);
    }

    /// Get function signature string
    pub fn getSignature(self: Function, allocator: std.mem.Allocator) ![]u8 {
        var sig = std.ArrayList(u8).init(allocator);
        defer sig.deinit();

        try sig.appendSlice(self.name);
        try sig.append('(');

        for (self.inputs, 0..) |param, i| {
            if (i > 0) try sig.append(',');
            try sig.appendSlice(try param.type.toString(allocator));
        }

        try sig.append(')');
        return sig.toOwnedSlice();
    }
};

/// Event signature
pub const Event = struct {
    name: []const u8,
    inputs: []const Parameter,
    anonymous: bool = false,

    /// Get event signature hash
    pub fn getSignature(self: Event, allocator: std.mem.Allocator) ![]u8 {
        var sig = std.ArrayList(u8).init(allocator);
        defer sig.deinit();

        try sig.appendSlice(self.name);
        try sig.append('(');

        for (self.inputs, 0..) |param, i| {
            if (i > 0) try sig.append(',');
            try sig.appendSlice(try param.type.toString(allocator));
        }

        try sig.append(')');
        return sig.toOwnedSlice();
    }
};

/// Helper to convert AbiType to string
fn typeToString(t: AbiType, allocator: std.mem.Allocator) ![]const u8 {
    _ = allocator;
    return switch (t) {
        .uint8 => "uint8",
        .uint16 => "uint16",
        .uint32 => "uint32",
        .uint64 => "uint64",
        .uint128 => "uint128",
        .uint256 => "uint256",
        .int8 => "int8",
        .int16 => "int16",
        .int32 => "int32",
        .int64 => "int64",
        .int128 => "int128",
        .int256 => "int256",
        .address => "address",
        .bool_type => "bool",
        .bytes1 => "bytes1",
        .bytes2 => "bytes2",
        .bytes4 => "bytes4",
        .bytes8 => "bytes8",
        .bytes16 => "bytes16",
        .bytes32 => "bytes32",
        .string => "string",
        .bytes => "bytes",
        else => "complex", // array/tuple need recursive handling
    };
}

// Add toString method to AbiType
pub fn toString(self: AbiType, allocator: std.mem.Allocator) ![]const u8 {
    return try typeToString(self, allocator);
}

test "abi type is dynamic" {
    try std.testing.expect(!AbiType.uint256.isDynamic());
    try std.testing.expect(!AbiType.address.isDynamic());
    try std.testing.expect(AbiType.string.isDynamic());
    try std.testing.expect(AbiType.bytes.isDynamic());
}

test "abi type static size" {
    try std.testing.expectEqual(@as(?usize, 32), AbiType.uint256.staticSize());
    try std.testing.expectEqual(@as(?usize, 32), AbiType.address.staticSize());
    try std.testing.expectEqual(@as(?usize, null), AbiType.string.staticSize());
}

test "function signature" {
    const allocator = std.testing.allocator;

    const func = Function{
        .name = "transfer",
        .inputs = &[_]Parameter{
            .{ .name = "to", .type = .address },
            .{ .name = "amount", .type = .uint256 },
        },
        .outputs = &[_]Parameter{
            .{ .name = "success", .type = .bool_type },
        },
        .state_mutability = .nonpayable,
    };

    const sig = try func.getSignature(allocator);
    defer allocator.free(sig);

    try std.testing.expectEqualStrings("transfer(address,uint256)", sig);
}

test "function selector" {
    const allocator = std.testing.allocator;

    const func = Function{
        .name = "transfer",
        .inputs = &[_]Parameter{
            .{ .name = "to", .type = .address },
            .{ .name = "amount", .type = .uint256 },
        },
        .outputs = &[_]Parameter{},
        .state_mutability = .nonpayable,
    };

    const selector = try func.getSelector(allocator);
    defer allocator.free(selector);

    // transfer(address,uint256) selector is 0xa9059cbb
    try std.testing.expectEqual(@as(usize, 4), selector.len);
    try std.testing.expectEqual(@as(u8, 0xa9), selector[0]);
    try std.testing.expectEqual(@as(u8, 0x05), selector[1]);
    try std.testing.expectEqual(@as(u8, 0x9c), selector[2]);
    try std.testing.expectEqual(@as(u8, 0xbb), selector[3]);
}
