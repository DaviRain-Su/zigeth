const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const abi = @import("../abi/types.zig");
const encode = @import("../abi/encode.zig");
const decode = @import("../abi/decode.zig");

/// Smart contract abstraction
pub const Contract = struct {
    address: Address,
    abi_functions: []const abi.Function,
    abi_events: []const abi.Event,
    allocator: std.mem.Allocator,

    /// Create a new contract instance
    pub fn init(
        allocator: std.mem.Allocator,
        address: Address,
        functions: []const abi.Function,
        events: []const abi.Event,
    ) !Contract {
        const functions_copy = try allocator.dupe(abi.Function, functions);
        const events_copy = try allocator.dupe(abi.Event, events);

        return .{
            .address = address,
            .abi_functions = functions_copy,
            .abi_events = events_copy,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: Contract) void {
        if (self.abi_functions.len > 0) {
            self.allocator.free(self.abi_functions);
        }
        if (self.abi_events.len > 0) {
            self.allocator.free(self.abi_events);
        }
    }

    /// Find a function by name
    pub fn getFunction(self: Contract, name: []const u8) ?abi.Function {
        for (self.abi_functions) |func| {
            if (std.mem.eql(u8, func.name, name)) {
                return func;
            }
        }
        return null;
    }

    /// Find a function by selector
    pub fn getFunctionBySelector(self: Contract, selector: []const u8) !?abi.Function {
        for (self.abi_functions) |func| {
            const func_selector = try func.getSelector(self.allocator);
            defer self.allocator.free(func_selector);

            if (std.mem.eql(u8, func_selector, selector)) {
                return func;
            }
        }
        return null;
    }

    /// Find an event by name
    pub fn getEvent(self: Contract, name: []const u8) ?abi.Event {
        for (self.abi_events) |event| {
            if (std.mem.eql(u8, event.name, name)) {
                return event;
            }
        }
        return null;
    }

    /// Encode a function call
    pub fn encodeCall(
        self: Contract,
        function_name: []const u8,
        args: []const abi.AbiValue,
    ) ![]u8 {
        const func = self.getFunction(function_name) orelse return error.FunctionNotFound;
        return try encode.encodeFunctionCall(self.allocator, func, args);
    }

    /// Decode function return data
    pub fn decodeReturn(
        self: Contract,
        function_name: []const u8,
        data: []const u8,
    ) ![]abi.AbiValue {
        const func = self.getFunction(function_name) orelse return error.FunctionNotFound;
        return try decode.decodeFunctionReturn(self.allocator, data, func.outputs);
    }

    /// Check if contract has a function
    pub fn hasFunction(self: Contract, name: []const u8) bool {
        return self.getFunction(name) != null;
    }

    /// Check if contract has an event
    pub fn hasEvent(self: Contract, name: []const u8) bool {
        return self.getEvent(name) != null;
    }

    /// Get number of functions
    pub fn getFunctionCount(self: Contract) usize {
        return self.abi_functions.len;
    }

    /// Get number of events
    pub fn getEventCount(self: Contract) usize {
        return self.abi_events.len;
    }
};

test "contract creation" {
    const allocator = std.testing.allocator;

    const functions = [_]abi.Function{
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
    };

    const events = [_]abi.Event{
        .{
            .name = "Transfer",
            .inputs = &[_]abi.Parameter{
                .{ .name = "from", .type = .address, .indexed = true },
                .{ .name = "to", .type = .address, .indexed = true },
                .{ .name = "value", .type = .uint256, .indexed = false },
            },
        },
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &functions, &events);
    defer contract.deinit();

    try std.testing.expectEqual(@as(usize, 1), contract.getFunctionCount());
    try std.testing.expectEqual(@as(usize, 1), contract.getEventCount());
}

test "contract get function by name" {
    const allocator = std.testing.allocator;

    const functions = [_]abi.Function{
        .{
            .name = "transfer",
            .inputs = &[_]abi.Parameter{},
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &functions, &[_]abi.Event{});
    defer contract.deinit();

    const func = contract.getFunction("transfer");
    try std.testing.expect(func != null);
    try std.testing.expectEqualStrings("transfer", func.?.name);

    const not_found = contract.getFunction("nonexistent");
    try std.testing.expect(not_found == null);
}

test "contract has function" {
    const allocator = std.testing.allocator;

    const functions = [_]abi.Function{
        .{
            .name = "approve",
            .inputs = &[_]abi.Parameter{},
            .outputs = &[_]abi.Parameter{},
            .state_mutability = .nonpayable,
        },
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &functions, &[_]abi.Event{});
    defer contract.deinit();

    try std.testing.expect(contract.hasFunction("approve"));
    try std.testing.expect(!contract.hasFunction("transfer"));
}

test "contract has event" {
    const allocator = std.testing.allocator;

    const events = [_]abi.Event{
        .{
            .name = "Approval",
            .inputs = &[_]abi.Parameter{},
        },
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &[_]abi.Function{}, &events);
    defer contract.deinit();

    try std.testing.expect(contract.hasEvent("Approval"));
    try std.testing.expect(!contract.hasEvent("Transfer"));
}
