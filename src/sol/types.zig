const std = @import("std");
const abi = @import("../abi/types.zig");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;
const Bytes = @import("../primitives/bytes.zig").Bytes;

/// Solidity type to Zig type mappings
pub const SolidityType = enum {
    address,
    bool_type,
    string,
    bytes,
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
    bytes1,
    bytes2,
    bytes4,
    bytes8,
    bytes16,
    bytes32,

    /// Convert Solidity type to ABI type
    pub fn toAbiType(self: SolidityType) abi.AbiType {
        return switch (self) {
            .address => .address,
            .bool_type => .bool_type,
            .string => .string,
            .bytes => .bytes,
            .uint8 => .uint8,
            .uint16 => .uint16,
            .uint32 => .uint32,
            .uint64 => .uint64,
            .uint128 => .uint128,
            .uint256 => .uint256,
            .int8 => .int8,
            .int16 => .int16,
            .int32 => .int32,
            .int64 => .int64,
            .int128 => .int128,
            .int256 => .int256,
            .bytes1 => .{ .fixed_bytes = 1 },
            .bytes2 => .{ .fixed_bytes = 2 },
            .bytes4 => .{ .fixed_bytes = 4 },
            .bytes8 => .{ .fixed_bytes = 8 },
            .bytes16 => .{ .fixed_bytes = 16 },
            .bytes32 => .{ .fixed_bytes = 32 },
        };
    }

    /// Get Solidity type name
    pub fn typeName(self: SolidityType) []const u8 {
        return switch (self) {
            .address => "address",
            .bool_type => "bool",
            .string => "string",
            .bytes => "bytes",
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
            .bytes1 => "bytes1",
            .bytes2 => "bytes2",
            .bytes4 => "bytes4",
            .bytes8 => "bytes8",
            .bytes16 => "bytes16",
            .bytes32 => "bytes32",
        };
    }

    /// Check if type is a uint
    pub fn isUint(self: SolidityType) bool {
        return switch (self) {
            .uint8, .uint16, .uint32, .uint64, .uint128, .uint256 => true,
            else => false,
        };
    }

    /// Check if type is an int
    pub fn isInt(self: SolidityType) bool {
        return switch (self) {
            .int8, .int16, .int32, .int64, .int128, .int256 => true,
            else => false,
        };
    }

    /// Check if type is fixed bytes
    pub fn isFixedBytes(self: SolidityType) bool {
        return switch (self) {
            .bytes1, .bytes2, .bytes4, .bytes8, .bytes16, .bytes32 => true,
            else => false,
        };
    }

    /// Check if type is dynamic (requires length prefix in ABI)
    pub fn isDynamic(self: SolidityType) bool {
        return switch (self) {
            .string, .bytes => true,
            else => false,
        };
    }

    /// Get size in bits for integer types
    pub fn bitSize(self: SolidityType) ?usize {
        return switch (self) {
            .uint8, .int8 => 8,
            .uint16, .int16 => 16,
            .uint32, .int32 => 32,
            .uint64, .int64 => 64,
            .uint128, .int128 => 128,
            .uint256, .int256 => 256,
            else => null,
        };
    }

    /// Get size in bytes for fixed types
    pub fn byteSize(self: SolidityType) ?usize {
        return switch (self) {
            .address => 20,
            .bool_type => 1,
            .bytes1 => 1,
            .bytes2 => 2,
            .bytes4 => 4,
            .bytes8 => 8,
            .bytes16 => 16,
            .bytes32 => 32,
            .uint8, .int8 => 1,
            .uint16, .int16 => 2,
            .uint32, .int32 => 4,
            .uint64, .int64 => 8,
            .uint128, .int128 => 16,
            .uint256, .int256 => 32,
            else => null,
        };
    }
};

/// Parse Solidity type string to SolidityType enum
pub fn parseType(type_str: []const u8) !SolidityType {
    if (std.mem.eql(u8, type_str, "address")) return .address;
    if (std.mem.eql(u8, type_str, "bool")) return .bool_type;
    if (std.mem.eql(u8, type_str, "string")) return .string;
    if (std.mem.eql(u8, type_str, "bytes")) return .bytes;
    if (std.mem.eql(u8, type_str, "uint8")) return .uint8;
    if (std.mem.eql(u8, type_str, "uint16")) return .uint16;
    if (std.mem.eql(u8, type_str, "uint32")) return .uint32;
    if (std.mem.eql(u8, type_str, "uint64")) return .uint64;
    if (std.mem.eql(u8, type_str, "uint128")) return .uint128;
    if (std.mem.eql(u8, type_str, "uint256")) return .uint256;
    if (std.mem.eql(u8, type_str, "int8")) return .int8;
    if (std.mem.eql(u8, type_str, "int16")) return .int16;
    if (std.mem.eql(u8, type_str, "int32")) return .int32;
    if (std.mem.eql(u8, type_str, "int64")) return .int64;
    if (std.mem.eql(u8, type_str, "int128")) return .int128;
    if (std.mem.eql(u8, type_str, "int256")) return .int256;
    if (std.mem.eql(u8, type_str, "bytes1")) return .bytes1;
    if (std.mem.eql(u8, type_str, "bytes2")) return .bytes2;
    if (std.mem.eql(u8, type_str, "bytes4")) return .bytes4;
    if (std.mem.eql(u8, type_str, "bytes8")) return .bytes8;
    if (std.mem.eql(u8, type_str, "bytes16")) return .bytes16;
    if (std.mem.eql(u8, type_str, "bytes32")) return .bytes32;

    return error.UnknownSolidityType;
}

/// Common Solidity value types mapped to Zig
pub const SolidityValue = union(enum) {
    address: Address,
    bool_val: bool,
    string: []const u8,
    bytes: []const u8,
    uint8: u8,
    uint16: u16,
    uint32: u32,
    uint64: u64,
    uint128: u128,
    uint256: U256,
    int8: i8,
    int16: i16,
    int32: i32,
    int64: i64,
    int128: i128,
    int256: U256, // Signed represented as U256 for now
    fixed_bytes: []const u8,

    /// Convert to AbiValue
    pub fn toAbiValue(self: SolidityValue) abi.AbiValue {
        return switch (self) {
            .address => |a| .{ .address = a },
            .bool_val => |b| .{ .bool_val = b },
            .string => |s| .{ .string = s },
            .bytes => |b| .{ .bytes = b },
            .uint8 => |u| .{ .uint = U256.fromInt(u) },
            .uint16 => |u| .{ .uint = U256.fromInt(u) },
            .uint32 => |u| .{ .uint = U256.fromInt(u) },
            .uint64 => |u| .{ .uint = U256.fromInt(u) },
            .uint128 => |u| .{ .uint = U256.fromInt(u) },
            .uint256 => |u| .{ .uint = u },
            .int8 => |i| .{ .int = U256.fromInt(@as(u64, @intCast(@abs(i)))) },
            .int16 => |i| .{ .int = U256.fromInt(@as(u64, @intCast(@abs(i)))) },
            .int32 => |i| .{ .int = U256.fromInt(@as(u64, @intCast(@abs(i)))) },
            .int64 => |i| .{ .int = U256.fromInt(@as(u64, @intCast(@abs(i)))) },
            .int128 => |i| .{ .int = U256.fromInt(@as(u64, @intCast(@abs(i)))) },
            .int256 => |i| .{ .int = i },
            .fixed_bytes => |b| .{ .bytes = b },
        };
    }
};

/// Standard Solidity interfaces
pub const StandardInterface = enum {
    erc20,
    erc721,
    erc1155,
    ownable,
    pausable,
    access_control,

    /// Get function signatures for the interface
    pub fn getFunctions(self: StandardInterface, allocator: std.mem.Allocator) ![]abi.Function {
        return switch (self) {
            .erc20 => try getErc20Functions(allocator),
            .erc721 => try getErc721Functions(allocator),
            .erc1155 => try getErc1155Functions(allocator),
            .ownable => try getOwnableFunctions(allocator),
            .pausable => try getPausableFunctions(allocator),
            .access_control => try getAccessControlFunctions(allocator),
        };
    }

    /// Get event signatures for the interface
    pub fn getEvents(self: StandardInterface, allocator: std.mem.Allocator) ![]abi.Event {
        return switch (self) {
            .erc20 => try getErc20Events(allocator),
            .erc721 => try getErc721Events(allocator),
            .erc1155 => try getErc1155Events(allocator),
            .ownable => try getOwnableEvents(allocator),
            .pausable => try getPausableEvents(allocator),
            .access_control => try getAccessControlEvents(allocator),
        };
    }
};

/// ERC-20 token interface functions
fn getErc20Functions(allocator: std.mem.Allocator) ![]abi.Function {
    const functions = [_]abi.Function{
        .{
            .name = "totalSupply",
            .inputs = &[_]abi.Parameter{},
            .outputs = &[_]abi.Parameter{
                .{ .name = "supply", .type = .uint256 },
            },
            .state_mutability = .view,
        },
        .{
            .name = "balanceOf",
            .inputs = &[_]abi.Parameter{
                .{ .name = "account", .type = .address },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "balance", .type = .uint256 },
            },
            .state_mutability = .view,
        },
        .{
            .name = "transfer",
            .inputs = &[_]abi.Parameter{
                .{ .name = "to", .type = .address },
                .{ .name = "amount", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "success", .type = .bool_type },
            },
            .state_mutability = .nonpayable,
        },
        .{
            .name = "allowance",
            .inputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address },
                .{ .name = "spender", .type = .address },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "remaining", .type = .uint256 },
            },
            .state_mutability = .view,
        },
        .{
            .name = "approve",
            .inputs = &[_]abi.Parameter{
                .{ .name = "spender", .type = .address },
                .{ .name = "amount", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "success", .type = .bool_type },
            },
            .state_mutability = .nonpayable,
        },
        .{
            .name = "transferFrom",
            .inputs = &[_]abi.Parameter{
                .{ .name = "from", .type = .address },
                .{ .name = "to", .type = .address },
                .{ .name = "amount", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "success", .type = .bool_type },
            },
            .state_mutability = .nonpayable,
        },
    };

    return try allocator.dupe(abi.Function, &functions);
}

/// ERC-20 token interface events
fn getErc20Events(allocator: std.mem.Allocator) ![]abi.Event {
    const events = [_]abi.Event{
        .{
            .name = "Transfer",
            .inputs = &[_]abi.Parameter{
                .{ .name = "from", .type = .address, .indexed = true },
                .{ .name = "to", .type = .address, .indexed = true },
                .{ .name = "value", .type = .uint256, .indexed = false },
            },
        },
        .{
            .name = "Approval",
            .inputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address, .indexed = true },
                .{ .name = "spender", .type = .address, .indexed = true },
                .{ .name = "value", .type = .uint256, .indexed = false },
            },
        },
    };

    return try allocator.dupe(abi.Event, &events);
}

/// ERC-721 NFT interface functions
fn getErc721Functions(allocator: std.mem.Allocator) ![]abi.Function {
    const functions = [_]abi.Function{
        .{
            .name = "balanceOf",
            .inputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "balance", .type = .uint256 },
            },
            .state_mutability = .view,
        },
        .{
            .name = "ownerOf",
            .inputs = &[_]abi.Parameter{
                .{ .name = "tokenId", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address },
            },
            .state_mutability = .view,
        },
        .{
            .name = "transferFrom",
            .inputs = &[_]abi.Parameter{
                .{ .name = "from", .type = .address },
                .{ .name = "to", .type = .address },
                .{ .name = "tokenId", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
        .{
            .name = "approve",
            .inputs = &[_]abi.Parameter{
                .{ .name = "to", .type = .address },
                .{ .name = "tokenId", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
        .{
            .name = "setApprovalForAll",
            .inputs = &[_]abi.Parameter{
                .{ .name = "operator", .type = .address },
                .{ .name = "approved", .type = .bool_type },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
        .{
            .name = "getApproved",
            .inputs = &[_]abi.Parameter{
                .{ .name = "tokenId", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "operator", .type = .address },
            },
            .state_mutability = .view,
        },
    };

    return try allocator.dupe(abi.Function, &functions);
}

/// ERC-721 NFT interface events
fn getErc721Events(allocator: std.mem.Allocator) ![]abi.Event {
    const events = [_]abi.Event{
        .{
            .name = "Transfer",
            .inputs = &[_]abi.Parameter{
                .{ .name = "from", .type = .address, .indexed = true },
                .{ .name = "to", .type = .address, .indexed = true },
                .{ .name = "tokenId", .type = .uint256, .indexed = true },
            },
        },
        .{
            .name = "Approval",
            .inputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address, .indexed = true },
                .{ .name = "approved", .type = .address, .indexed = true },
                .{ .name = "tokenId", .type = .uint256, .indexed = true },
            },
        },
        .{
            .name = "ApprovalForAll",
            .inputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address, .indexed = true },
                .{ .name = "operator", .type = .address, .indexed = true },
                .{ .name = "approved", .type = .bool_type, .indexed = false },
            },
        },
    };

    return try allocator.dupe(abi.Event, &events);
}

/// ERC-1155 multi-token interface functions (subset)
fn getErc1155Functions(allocator: std.mem.Allocator) ![]abi.Function {
    const functions = [_]abi.Function{
        .{
            .name = "balanceOf",
            .inputs = &[_]abi.Parameter{
                .{ .name = "account", .type = .address },
                .{ .name = "id", .type = .uint256 },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "balance", .type = .uint256 },
            },
            .state_mutability = .view,
        },
        .{
            .name = "setApprovalForAll",
            .inputs = &[_]abi.Parameter{
                .{ .name = "operator", .type = .address },
                .{ .name = "approved", .type = .bool_type },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
    };

    return try allocator.dupe(abi.Function, &functions);
}

/// ERC-1155 multi-token interface events (subset)
fn getErc1155Events(allocator: std.mem.Allocator) ![]abi.Event {
    const events = [_]abi.Event{
        .{
            .name = "TransferSingle",
            .inputs = &[_]abi.Parameter{
                .{ .name = "operator", .type = .address, .indexed = true },
                .{ .name = "from", .type = .address, .indexed = true },
                .{ .name = "to", .type = .address, .indexed = true },
                .{ .name = "id", .type = .uint256, .indexed = false },
                .{ .name = "value", .type = .uint256, .indexed = false },
            },
        },
    };

    return try allocator.dupe(abi.Event, &events);
}

/// Ownable interface functions (OpenZeppelin)
fn getOwnableFunctions(allocator: std.mem.Allocator) ![]abi.Function {
    const functions = [_]abi.Function{
        .{
            .name = "owner",
            .inputs = &[_]abi.Parameter{},
            .outputs = &[_]abi.Parameter{
                .{ .name = "owner", .type = .address },
            },
            .state_mutability = .view,
        },
        .{
            .name = "transferOwnership",
            .inputs = &[_]abi.Parameter{
                .{ .name = "newOwner", .type = .address },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
        .{
            .name = "renounceOwnership",
            .inputs = &[_]abi.Parameter{},
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
    };

    return try allocator.dupe(abi.Function, &functions);
}

/// Ownable interface events
fn getOwnableEvents(allocator: std.mem.Allocator) ![]abi.Event {
    const events = [_]abi.Event{
        .{
            .name = "OwnershipTransferred",
            .inputs = &[_]abi.Parameter{
                .{ .name = "previousOwner", .type = .address, .indexed = true },
                .{ .name = "newOwner", .type = .address, .indexed = true },
            },
        },
    };

    return try allocator.dupe(abi.Event, &events);
}

/// Pausable interface functions (OpenZeppelin)
fn getPausableFunctions(allocator: std.mem.Allocator) ![]abi.Function {
    const functions = [_]abi.Function{
        .{
            .name = "paused",
            .inputs = &[_]abi.Parameter{},
            .outputs = &[_]abi.Parameter{
                .{ .name = "paused", .type = .bool_type },
            },
            .state_mutability = .view,
        },
    };

    return try allocator.dupe(abi.Function, &functions);
}

/// Pausable interface events
fn getPausableEvents(allocator: std.mem.Allocator) ![]abi.Event {
    const events = [_]abi.Event{
        .{
            .name = "Paused",
            .inputs = &[_]abi.Parameter{
                .{ .name = "account", .type = .address, .indexed = false },
            },
        },
        .{
            .name = "Unpaused",
            .inputs = &[_]abi.Parameter{
                .{ .name = "account", .type = .address, .indexed = false },
            },
        },
    };

    return try allocator.dupe(abi.Event, &events);
}

/// AccessControl interface functions (OpenZeppelin - subset)
fn getAccessControlFunctions(allocator: std.mem.Allocator) ![]abi.Function {
    const functions = [_]abi.Function{
        .{
            .name = "hasRole",
            .inputs = &[_]abi.Parameter{
                .{ .name = "role", .type = .{ .fixed_bytes = 32 } },
                .{ .name = "account", .type = .address },
            },
            .outputs = &[_]abi.Parameter{
                .{ .name = "hasRole", .type = .bool_type },
            },
            .state_mutability = .view,
        },
        .{
            .name = "grantRole",
            .inputs = &[_]abi.Parameter{
                .{ .name = "role", .type = .{ .fixed_bytes = 32 } },
                .{ .name = "account", .type = .address },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
        .{
            .name = "revokeRole",
            .inputs = &[_]abi.Parameter{
                .{ .name = "role", .type = .{ .fixed_bytes = 32 } },
                .{ .name = "account", .type = .address },
            },
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
    };

    return try allocator.dupe(abi.Function, &functions);
}

/// AccessControl interface events
fn getAccessControlEvents(allocator: std.mem.Allocator) ![]abi.Event {
    const events = [_]abi.Event{
        .{
            .name = "RoleGranted",
            .inputs = &[_]abi.Parameter{
                .{ .name = "role", .type = .{ .fixed_bytes = 32 }, .indexed = true },
                .{ .name = "account", .type = .address, .indexed = true },
                .{ .name = "sender", .type = .address, .indexed = true },
            },
        },
        .{
            .name = "RoleRevoked",
            .inputs = &[_]abi.Parameter{
                .{ .name = "role", .type = .{ .fixed_bytes = 32 }, .indexed = true },
                .{ .name = "account", .type = .address, .indexed = true },
                .{ .name = "sender", .type = .address, .indexed = true },
            },
        },
    };

    return try allocator.dupe(abi.Event, &events);
}

test "solidity type to abi type" {
    const sol_type = SolidityType.uint256;
    const abi_type = sol_type.toAbiType();
    try std.testing.expectEqual(abi.AbiType.uint256, abi_type);
}

test "solidity type name" {
    try std.testing.expectEqualStrings("address", SolidityType.address.typeName());
    try std.testing.expectEqualStrings("uint256", SolidityType.uint256.typeName());
    try std.testing.expectEqualStrings("bytes32", SolidityType.bytes32.typeName());
}

test "solidity type checks" {
    try std.testing.expect(SolidityType.uint256.isUint());
    try std.testing.expect(!SolidityType.address.isUint());

    try std.testing.expect(SolidityType.int256.isInt());
    try std.testing.expect(!SolidityType.uint256.isInt());

    try std.testing.expect(SolidityType.bytes32.isFixedBytes());
    try std.testing.expect(!SolidityType.bytes.isFixedBytes());

    try std.testing.expect(SolidityType.string.isDynamic());
    try std.testing.expect(!SolidityType.uint256.isDynamic());
}

test "solidity type sizes" {
    try std.testing.expectEqual(@as(?usize, 256), SolidityType.uint256.bitSize());
    try std.testing.expectEqual(@as(?usize, 64), SolidityType.uint64.bitSize());
    try std.testing.expect(SolidityType.address.bitSize() == null);

    try std.testing.expectEqual(@as(?usize, 20), SolidityType.address.byteSize());
    try std.testing.expectEqual(@as(?usize, 32), SolidityType.bytes32.byteSize());
    try std.testing.expect(SolidityType.string.byteSize() == null);
}

test "parse solidity type" {
    const addr = try parseType("address");
    try std.testing.expectEqual(SolidityType.address, addr);

    const uint = try parseType("uint256");
    try std.testing.expectEqual(SolidityType.uint256, uint);

    const bytes = try parseType("bytes32");
    try std.testing.expectEqual(SolidityType.bytes32, bytes);

    try std.testing.expectError(error.UnknownSolidityType, parseType("invalid"));
}

test "erc20 interface" {
    const allocator = std.testing.allocator;

    const functions = try StandardInterface.erc20.getFunctions(allocator);
    defer allocator.free(functions);

    const events = try StandardInterface.erc20.getEvents(allocator);
    defer allocator.free(events);

    try std.testing.expectEqual(@as(usize, 6), functions.len);
    try std.testing.expectEqual(@as(usize, 2), events.len);

    // Check transfer function exists
    var found = false;
    for (functions) |func| {
        if (std.mem.eql(u8, func.name, "transfer")) {
            found = true;
            try std.testing.expectEqual(@as(usize, 2), func.inputs.len);
        }
    }
    try std.testing.expect(found);
}

test "erc721 interface" {
    const allocator = std.testing.allocator;

    const functions = try StandardInterface.erc721.getFunctions(allocator);
    defer allocator.free(functions);

    const events = try StandardInterface.erc721.getEvents(allocator);
    defer allocator.free(events);

    try std.testing.expectEqual(@as(usize, 6), functions.len);
    try std.testing.expectEqual(@as(usize, 3), events.len);
}

test "solidity value to abi value" {
    const sol_val = SolidityValue{ .uint256 = U256.fromInt(1000) };
    const abi_val = sol_val.toAbiValue();

    try std.testing.expect(abi_val == .uint);
    try std.testing.expect(abi_val.uint.eql(U256.fromInt(1000)));
}
