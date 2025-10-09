const std = @import("std");
const abi = @import("../abi/types.zig");
const Contract = @import("../contract/contract.zig").Contract;
const sol_types = @import("./types.zig");

/// Generate contract binding from ABI functions and events
pub fn ContractBinding(
    comptime name: []const u8,
    comptime functions: []const abi.Function,
    comptime events: []const abi.Event,
) type {
    return struct {
        contract: Contract,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, address: @import("../primitives/address.zig").Address) !Self {
            const contract = try Contract.init(allocator, address, functions, events);
            return .{ .contract = contract };
        }

        pub fn deinit(self: Self) void {
            self.contract.deinit();
        }

        pub fn getAddress(self: Self) @import("../primitives/address.zig").Address {
            return self.contract.address;
        }

        pub fn getName() []const u8 {
            return name;
        }
    };
}

/// Generate function call builder
pub fn FunctionCall(comptime function_name: []const u8) type {
    _ = function_name; // Reserved for future use in generated method names
    return struct {
        builder: @import("../contract/call.zig").CallBuilder,

        const Self = @This();

        pub fn build(self: *Self) ![]u8 {
            return try self.builder.buildCallData();
        }

        pub fn setFrom(self: *Self, from: @import("../primitives/address.zig").Address) void {
            self.builder.setFrom(from);
        }

        pub fn setGasLimit(self: *Self, gas_limit: u64) void {
            self.builder.setGasLimit(gas_limit);
        }
    };
}

/// Helper to create ERC-20 contract binding
pub fn Erc20Contract(allocator: std.mem.Allocator, address: @import("../primitives/address.zig").Address) !Contract {
    const functions = try sol_types.StandardInterface.erc20.getFunctions(allocator);
    defer allocator.free(functions);

    const events = try sol_types.StandardInterface.erc20.getEvents(allocator);
    defer allocator.free(events);

    return try Contract.init(allocator, address, functions, events);
}

/// Helper to create ERC-721 contract binding
pub fn Erc721Contract(allocator: std.mem.Allocator, address: @import("../primitives/address.zig").Address) !Contract {
    const functions = try sol_types.StandardInterface.erc721.getFunctions(allocator);
    defer allocator.free(functions);

    const events = try sol_types.StandardInterface.erc721.getEvents(allocator);
    defer allocator.free(events);

    return try Contract.init(allocator, address, functions, events);
}

/// Helper to create ERC-1155 contract binding
pub fn Erc1155Contract(allocator: std.mem.Allocator, address: @import("../primitives/address.zig").Address) !Contract {
    const functions = try sol_types.StandardInterface.erc1155.getFunctions(allocator);
    defer allocator.free(functions);

    const events = try sol_types.StandardInterface.erc1155.getEvents(allocator);
    defer allocator.free(events);

    return try Contract.init(allocator, address, functions, events);
}

/// Generate event filter helper
pub fn EventFilter(comptime event_name: []const u8) type {
    return struct {
        filter: @import("../contract/event.zig").EventFilter,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .filter = @import("../contract/event.zig").EventFilter.init(allocator),
            };
        }

        pub fn deinit(self: Self) void {
            self.filter.deinit();
        }

        pub fn setAddress(self: *Self, address: @import("../primitives/address.zig").Address) void {
            self.filter.setAddress(address);
        }

        pub fn setBlockRange(self: *Self, from: u64, to: u64) void {
            self.filter.setBlockRange(from, to);
        }

        pub fn getName() []const u8 {
            return event_name;
        }
    };
}

/// ABI JSON parser helper
pub const AbiParser = struct {
    /// Parse ABI JSON string into functions and events
    pub fn parseAbi(allocator: std.mem.Allocator, abi_json: []const u8) !ParsedAbi {
        _ = abi_json;
        // TODO: Implement full ABI JSON parsing
        return ParsedAbi{
            .functions = &[_]abi.Function{},
            .events = &[_]abi.Event{},
            .allocator = allocator,
        };
    }
};

pub const ParsedAbi = struct {
    functions: []const abi.Function,
    events: []const abi.Event,
    allocator: std.mem.Allocator,

    pub fn deinit(self: ParsedAbi) void {
        if (self.functions.len > 0) {
            self.allocator.free(self.functions);
        }
        if (self.events.len > 0) {
            self.allocator.free(self.events);
        }
    }
};

/// Selector generation helpers
pub const Selectors = struct {
    /// Common ERC-20 function selectors
    pub const ERC20_TRANSFER = "0xa9059cbb";
    pub const ERC20_APPROVE = "0x095ea7b3";
    pub const ERC20_TRANSFER_FROM = "0x23b872dd";
    pub const ERC20_BALANCE_OF = "0x70a08231";
    pub const ERC20_ALLOWANCE = "0xdd62ed3e";
    pub const ERC20_TOTAL_SUPPLY = "0x18160ddd";

    /// Common ERC-721 function selectors
    pub const ERC721_TRANSFER_FROM = "0x23b872dd";
    pub const ERC721_SAFE_TRANSFER_FROM = "0x42842e0e";
    pub const ERC721_APPROVE = "0x095ea7b3";
    pub const ERC721_SET_APPROVAL_FOR_ALL = "0xa22cb465";
    pub const ERC721_OWNER_OF = "0x6352211e";
    pub const ERC721_BALANCE_OF = "0x70a08231";

    /// Common event signatures (topic0)
    pub const TRANSFER_EVENT = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    pub const APPROVAL_EVENT = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
};

/// Value conversion helpers
pub const ValueConversion = struct {
    /// Convert Zig value to Solidity AbiValue
    pub fn toAbiValue(comptime T: type, value: T) abi.AbiValue {
        const type_info = @typeInfo(T);

        return switch (type_info) {
            .Int => |int_info| {
                if (int_info.signedness == .unsigned) {
                    return .{ .uint = @import("../primitives/uint.zig").U256.fromInt(@as(u64, @intCast(value))) };
                } else {
                    return .{ .int = @import("../primitives/uint.zig").U256.fromInt(@as(u64, @intCast(@abs(value)))) };
                }
            },
            .Bool => .{ .bool_val = value },
            .Pointer => |ptr_info| {
                if (ptr_info.child == u8) {
                    // String or bytes
                    return .{ .bytes = value };
                } else {
                    @compileError("Unsupported pointer type");
                }
            },
            else => @compileError("Unsupported type for ABI conversion"),
        };
    }

    /// Convert Address to AbiValue
    pub fn addressToAbiValue(addr: @import("../primitives/address.zig").Address) abi.AbiValue {
        return .{ .address = addr };
    }

    /// Convert U256 to AbiValue
    pub fn u256ToAbiValue(value: @import("../primitives/uint.zig").U256) abi.AbiValue {
        return .{ .uint = value };
    }
};

test "contract binding type generation" {
    const Address = @import("../primitives/address.zig").Address;
    const allocator = std.testing.allocator;

    const TestContract = ContractBinding("TestContract", &[_]abi.Function{}, &[_]abi.Event{});

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try TestContract.init(allocator, addr);
    defer contract.deinit();

    try std.testing.expectEqualStrings("TestContract", TestContract.getName());
    try std.testing.expectEqual(addr, contract.getAddress());
}

test "erc20 contract helper" {
    const Address = @import("../primitives/address.zig").Address;
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Erc20Contract(allocator, addr);
    defer contract.deinit();

    try std.testing.expect(contract.hasFunction("transfer"));
    try std.testing.expect(contract.hasFunction("balanceOf"));
    try std.testing.expect(contract.hasEvent("Transfer"));
}

test "erc721 contract helper" {
    const Address = @import("../primitives/address.zig").Address;
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Erc721Contract(allocator, addr);
    defer contract.deinit();

    try std.testing.expect(contract.hasFunction("ownerOf"));
    try std.testing.expect(contract.hasFunction("transferFrom"));
    try std.testing.expect(contract.hasEvent("Transfer"));
}

test "value conversion uint" {
    const value: u64 = 1000;
    const abi_val = ValueConversion.toAbiValue(u64, value);

    try std.testing.expect(abi_val == .uint);
    const U256 = @import("../primitives/uint.zig").U256;
    try std.testing.expect(abi_val.uint.eql(U256.fromInt(1000)));
}

test "value conversion bool" {
    const value: bool = true;
    const abi_val = ValueConversion.toAbiValue(bool, value);

    try std.testing.expect(abi_val == .bool_val);
    try std.testing.expect(abi_val.bool_val);
}

test "value conversion address" {
    const Address = @import("../primitives/address.zig").Address;
    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const abi_val = ValueConversion.addressToAbiValue(addr);

    try std.testing.expect(abi_val == .address);
    try std.testing.expectEqual(addr, abi_val.address);
}

test "selectors constants" {
    try std.testing.expectEqualStrings("0xa9059cbb", Selectors.ERC20_TRANSFER);
    try std.testing.expectEqualStrings("0x70a08231", Selectors.ERC20_BALANCE_OF);
}
