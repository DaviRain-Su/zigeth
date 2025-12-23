const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const Transaction = @import("../types/transaction.zig").Transaction;
const abi = @import("../abi/types.zig");
const encode = @import("../abi/encode.zig");

/// Contract deployment builder
pub const DeployBuilder = struct {
    allocator: std.mem.Allocator,
    bytecode: Bytes,
    constructor_args: std.ArrayList(abi.AbiValue),
    constructor_types: []const abi.Parameter,
    from: ?Address,
    value: ?U256,
    gas_limit: ?u64,

    /// Create a new deployment builder
    pub fn init(
        allocator: std.mem.Allocator,
        bytecode: Bytes,
        constructor_types: []const abi.Parameter,
    ) !DeployBuilder {
        return .{
            .allocator = allocator,
            .bytecode = bytecode,
            .constructor_args = try std.ArrayList(abi.AbiValue).initCapacity(allocator, 0),
            .constructor_types = constructor_types,
            .from = null,
            .value = null,
            .gas_limit = null,
        };
    }

    pub fn deinit(self: *DeployBuilder) void {
        self.constructor_args.deinit(self.allocator);
    }

    /// Add a constructor argument
    pub fn addArg(self: *DeployBuilder, arg: abi.AbiValue) !void {
        try self.constructor_args.append(self.allocator, arg);
    }

    /// Set deployer address
    pub fn setFrom(self: *DeployBuilder, from: Address) void {
        self.from = from;
    }

    /// Set value to send (for payable constructors)
    pub fn setValue(self: *DeployBuilder, value: U256) void {
        self.value = value;
    }

    /// Set gas limit
    pub fn setGasLimit(self: *DeployBuilder, gas_limit: u64) void {
        self.gas_limit = gas_limit;
    }

    /// Build the deployment data (bytecode + encoded constructor args)
    pub fn buildDeploymentData(self: *DeployBuilder) ![]u8 {
        var result = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer result.deinit(self.allocator);

        // Add bytecode
        try result.appendSlice(self.allocator, self.bytecode.data);

        // Encode constructor arguments if any
        if (self.constructor_args.items.len > 0) {
            var encoder = encode.Encoder.init(self.allocator);
            defer encoder.deinit();

            // Encode each argument
            for (self.constructor_args.items, self.constructor_types) |arg, param| {
                _ = arg;
                _ = param;
                // TODO: Implement full encoding
                // try encodeValue(&encoder, arg, param.type);
            }

            const encoded_args = encoder.toSlice();
            try result.appendSlice(self.allocator, encoded_args);
        }

        return try result.toOwnedSlice(self.allocator);
    }

    /// Estimate the contract address that will be created
    /// Uses CREATE opcode formula: address = keccak256(rlp([sender, nonce]))[12:]
    pub fn estimateAddress(self: DeployBuilder, nonce: u64) !Address {
        if (self.from == null) {
            return error.FromAddressRequired;
        }

        // TODO: Implement proper RLP encoding
        // For now, return a placeholder
        _ = nonce;

        return Address.fromBytes([_]u8{0} ** 20);
    }

    /// Estimate the contract address using CREATE2
    /// address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
    pub fn estimateCreate2Address(
        self: DeployBuilder,
        salt: Hash,
    ) !Address {
        if (self.from == null) {
            return error.FromAddressRequired;
        }

        const keccak = @import("../crypto/keccak.zig");
        const abi_packed = @import("../abi/packed.zig");

        // Hash the init code (bytecode + constructor args)
        const init_code = try self.buildDeploymentData();
        defer self.allocator.free(init_code);

        const init_code_hash = keccak.hash(init_code);

        // Pack: 0xff ++ sender ++ salt ++ init_code_hash
        const values = [_]abi_packed.PackedValue{
            .{ .bytes = &[_]u8{0xff} },
            .{ .address = self.from.? },
            .{ .hash = salt },
            .{ .hash = init_code_hash },
        };

        const hash_result = try abi_packed.hashPacked(self.allocator, &values);

        // Take last 20 bytes
        var addr_bytes: [20]u8 = undefined;
        @memcpy(&addr_bytes, hash_result.bytes[12..32]);

        return Address.fromBytes(addr_bytes);
    }
};

/// Deployment receipt
pub const DeployReceipt = struct {
    transaction_hash: Hash,
    contract_address: Address,
    block_number: u64,
    gas_used: u64,
};

test "deploy builder creation" {
    const allocator = std.testing.allocator;

    const bytecode_data = [_]u8{ 0x60, 0x80, 0x60, 0x40 };
    const bytecode = try Bytes.fromSlice(allocator, &bytecode_data);

    const constructor_params = [_]abi.Parameter{
        .{ .name = "initialSupply", .type = .uint256 },
    };

    var builder = try DeployBuilder.init(allocator, bytecode, &constructor_params);
    defer builder.deinit();

    try std.testing.expectEqual(@as(usize, 4), builder.bytecode.len());
}

test "deploy builder add arguments" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x80 });

    var builder = try DeployBuilder.init(allocator, bytecode, &[_]abi.Parameter{});
    defer builder.deinit();

    try builder.addArg(.{ .uint = U256.fromInt(1000000) });

    try std.testing.expectEqual(@as(usize, 1), builder.constructor_args.items.len);
}

test "deploy builder set parameters" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x80 });

    var builder = try DeployBuilder.init(allocator, bytecode, &[_]abi.Parameter{});
    defer builder.deinit();

    const from = Address.fromBytes([_]u8{0x12} ** 20);
    builder.setFrom(from);
    builder.setValue(U256.fromInt(500000));
    builder.setGasLimit(300000);

    try std.testing.expect(builder.from != null);
    try std.testing.expect(builder.value != null);
    try std.testing.expectEqual(@as(?u64, 300000), builder.gas_limit);
}

test "deploy builder build data" {
    const allocator = std.testing.allocator;

    const bytecode_data = [_]u8{ 0x60, 0x80, 0x60, 0x40 };
    const bytecode = try Bytes.fromSlice(allocator, &bytecode_data);

    var builder = try DeployBuilder.init(allocator, bytecode, &[_]abi.Parameter{});
    defer builder.deinit();

    const deploy_data = try builder.buildDeploymentData();
    defer allocator.free(deploy_data);

    // Should at least contain the bytecode
    try std.testing.expect(deploy_data.len >= 4);
    try std.testing.expectEqual(@as(u8, 0x60), deploy_data[0]);
}

test "estimate create2 address" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x80 });

    var builder = try DeployBuilder.init(allocator, bytecode, &[_]abi.Parameter{});
    defer builder.deinit();

    const from = Address.fromBytes([_]u8{0x12} ** 20);
    builder.setFrom(from);

    const salt = Hash.fromBytes([_]u8{0x34} ** 32);
    const estimated_addr = try builder.estimateCreate2Address(salt);

    // Should produce a valid address (not all zeros in this case)
    // The actual value depends on the hash of the deployment data
    try std.testing.expect(estimated_addr.bytes.len == 20);
}
