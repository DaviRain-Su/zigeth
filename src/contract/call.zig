const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const abi = @import("../abi/types.zig");
const Contract = @import("./contract.zig").Contract;

/// Contract call builder
pub const CallBuilder = struct {
    allocator: std.mem.Allocator,
    contract: *const Contract,
    function: abi.Function,
    args: std.ArrayList(abi.AbiValue),
    from: ?Address,
    value: ?u256,
    gas_limit: ?u64,

    pub fn init(allocator: std.mem.Allocator, contract: *const Contract, function: abi.Function) !CallBuilder {
        return .{
            .allocator = allocator,
            .contract = contract,
            .function = function,
            .args = try std.ArrayList(abi.AbiValue).initCapacity(allocator, 0),
            .from = null,
            .value = null,
            .gas_limit = null,
        };
    }

    pub fn deinit(self: *CallBuilder) void {
        self.args.deinit(self.allocator);
    }

    /// Add an argument
    pub fn addArg(self: *CallBuilder, arg: abi.AbiValue) !void {
        try self.args.append(self.allocator, arg);
    }

    /// Set sender address
    pub fn setFrom(self: *CallBuilder, from: Address) void {
        self.from = from;
    }

    /// Set value to send (for payable functions)
    pub fn setValue(self: *CallBuilder, value: u256) void {
        self.value = value;
    }

    /// Set gas limit
    pub fn setGasLimit(self: *CallBuilder, gas_limit: u64) void {
        self.gas_limit = gas_limit;
    }

    /// Build the call data
    pub fn buildCallData(self: *CallBuilder) ![]u8 {
        const encode_module = @import("../abi/encode.zig");
        return try encode_module.encodeFunctionCall(
            self.allocator,
            self.function,
            self.args.items,
        );
    }

    /// Get the target contract address
    pub fn getTo(self: CallBuilder) Address {
        return self.contract.address;
    }
};

/// Contract call parameters
pub const CallParams = struct {
    from: ?Address,
    to: Address,
    data: []const u8,
    value: ?u256,
    gas_limit: ?u64,

    pub fn init(to: Address, data: []const u8) CallParams {
        return .{
            .from = null,
            .to = to,
            .data = data,
            .value = null,
            .gas_limit = null,
        };
    }
};

/// Contract call result
pub const CallResult = struct {
    success: bool,
    data: []u8,
    gas_used: ?u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: CallResult) void {
        self.allocator.free(self.data);
    }

    /// Decode the result using function outputs
    pub fn decode(self: CallResult, function: abi.Function) ![]abi.AbiValue {
        if (!self.success) {
            return error.CallFailed;
        }
        const decode_module = @import("../abi/decode.zig");
        return try decode_module.decodeFunctionReturn(self.allocator, self.data, function.outputs);
    }
};

/// Execute a view/pure function call (no state change)
pub fn callView(
    allocator: std.mem.Allocator,
    contract: *const Contract,
    function: abi.Function,
    args: []const abi.AbiValue,
) !CallResult {
    _ = contract; // Will be used in future RPC implementation

    // Verify function is view or pure
    if (function.state_mutability != .view and function.state_mutability != .pure) {
        return error.NotViewFunction;
    }

    // Encode the call data
    const encode_module = @import("../abi/encode.zig");
    const call_data = try encode_module.encodeFunctionCall(allocator, function, args);
    defer allocator.free(call_data);

    // TODO: Execute the call via RPC (eth_call)
    // For now, return a placeholder
    return CallResult{
        .success = false,
        .data = try allocator.dupe(u8, &[_]u8{}),
        .gas_used = null,
        .allocator = allocator,
    };
}

/// Execute a state-changing function call (sends transaction)
pub fn callMutating(
    allocator: std.mem.Allocator,
    contract: *const Contract,
    function: abi.Function,
    args: []const abi.AbiValue,
    from: Address,
    value: ?u256,
    gas_limit: ?u64,
) !Hash {
    _ = contract; // Will be used in future RPC implementation
    _ = from; // Will be used in future RPC implementation
    _ = gas_limit; // Will be used in future RPC implementation

    // Verify function is not pure/view
    if (function.state_mutability == .view or function.state_mutability == .pure) {
        return error.ViewFunctionCannotMutate;
    }

    // Verify function is payable if sending value
    if (value != null and function.state_mutability != .payable) {
        return error.FunctionNotPayable;
    }

    // Encode the call data
    const encode_module = @import("../abi/encode.zig");
    const call_data = try encode_module.encodeFunctionCall(allocator, function, args);
    defer allocator.free(call_data);

    // TODO: Create and send transaction via RPC
    // For now, return a placeholder hash

    return Hash.zero();
}

test "call builder creation" {
    const allocator = std.testing.allocator;

    const func = abi.Function{
        .name = "balanceOf",
        .inputs = &[_]abi.Parameter{
            .{ .name = "account", .type = .address },
        },
        .outputs = &[_]abi.Parameter{
            .{ .name = "balance", .type = .uint256 },
        },
        .state_mutability = .view,
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &[_]abi.Function{func}, &[_]abi.Event{});
    defer contract.deinit();

    var builder = try CallBuilder.init(allocator, &contract, func);
    defer builder.deinit();

    try std.testing.expectEqual(addr, builder.getTo());
}

test "call builder add arguments" {
    const allocator = std.testing.allocator;

    const func = abi.Function{
        .name = "transfer",
        .inputs = &[_]abi.Parameter{
            .{ .name = "to", .type = .address },
            .{ .name = "amount", .type = .uint256 },
        },
        .outputs = &[_]abi.Parameter{},
        .state_mutability = .nonpayable,
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &[_]abi.Function{}, &[_]abi.Event{});
    defer contract.deinit();

    var builder = try CallBuilder.init(allocator, &contract, func);
    defer builder.deinit();

    const to_addr = Address.fromBytes([_]u8{0x34} ** 20);
    try builder.addArg(.{ .address = to_addr });
    try builder.addArg(.{ .uint = 1000 });

    try std.testing.expectEqual(@as(usize, 2), builder.args.items.len);
}

test "call builder set parameters" {
    const allocator = std.testing.allocator;

    const func = abi.Function{
        .name = "test",
        .inputs = &[_]abi.Parameter{},
        .outputs = &[_]abi.Parameter{},
        .state_mutability = .payable,
    };

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const contract = try Contract.init(allocator, addr, &[_]abi.Function{}, &[_]abi.Event{});
    defer contract.deinit();

    var builder = try CallBuilder.init(allocator, &contract, func);
    defer builder.deinit();

    const from = Address.fromBytes([_]u8{0x34} ** 20);
    builder.setFrom(from);
    builder.setValue(1000000);
    builder.setGasLimit(100000);

    try std.testing.expect(builder.from != null);
    try std.testing.expect(builder.value != null);
    try std.testing.expectEqual(@as(?u64, 100000), builder.gas_limit);
}

test "call params creation" {
    const to = Address.fromBytes([_]u8{0x12} ** 20);
    const data = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb }; // transfer selector

    const params = CallParams.init(to, &data);

    try std.testing.expectEqual(to, params.to);
    try std.testing.expectEqual(@as(usize, 4), params.data.len);
    try std.testing.expect(params.from == null);
}

test "call result decode" {
    const allocator = std.testing.allocator;

    // Simulated return data (uint256 = 1000)
    // 1000 = 0x3E8, in big-endian 32 bytes the last two bytes are 0x03 0xE8
    var return_data: [32]u8 = [_]u8{0} ** 32;
    return_data[30] = 0x03;
    return_data[31] = 0xE8; // 1000 = 0x3E8 in hex

    const func = abi.Function{
        .name = "balanceOf",
        .inputs = &[_]abi.Parameter{},
        .outputs = &[_]abi.Parameter{
            .{ .name = "balance", .type = .uint256 },
        },
        .state_mutability = .view,
    };

    const result = CallResult{
        .success = true,
        .data = try allocator.dupe(u8, &return_data),
        .gas_used = 21000,
        .allocator = allocator,
    };
    defer result.deinit();

    const decoded = try result.decode(func);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expect(decoded[0] == .uint);
    try std.testing.expect(decoded[0].uint == 1000);
}
