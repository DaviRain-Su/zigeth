const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const rpc_mod = @import("../rpc/client.zig");
const entrypoint_mod = @import("entrypoint.zig");
const utils = @import("utils.zig");
const keccak = @import("../crypto/keccak.zig");
const ecdsa = @import("../crypto/ecdsa.zig");

/// Union type to return any UserOperation version
pub const UserOperationAny = union(types.EntryPointVersion) {
    v0_6: types.UserOperationV06,
    v0_7: types.UserOperationV07,
    v0_8: types.UserOperationV08,
};

/// Smart Account implementation
/// Base for creating ERC-4337 compliant smart contract accounts
/// Supports all EntryPoint versions (v0.6, v0.7, v0.8)
pub const SmartAccount = struct {
    allocator: std.mem.Allocator,
    address: primitives.Address,
    entry_point: primitives.Address,
    entry_point_version: types.EntryPointVersion,
    owner: primitives.Address,
    nonce: u256,
    rpc_client: ?*rpc_mod.RpcClient,
    factory: ?*AccountFactory,
    salt: u256,

    pub fn init(
        allocator: std.mem.Allocator,
        address: primitives.Address,
        entry_point: primitives.Address,
        entry_point_version: types.EntryPointVersion,
        owner: primitives.Address,
        rpc_client: ?*rpc_mod.RpcClient,
        factory: ?*AccountFactory,
        salt: u256,
    ) SmartAccount {
        return .{
            .allocator = allocator,
            .address = address,
            .entry_point = entry_point,
            .entry_point_version = entry_point_version,
            .owner = owner,
            .nonce = 0,
            .rpc_client = rpc_client,
            .factory = factory,
            .salt = salt,
        };
    }

    /// Create a UserOperation for a transaction
    /// Returns appropriate version based on entry_point_version
    pub fn createUserOperation(
        self: *SmartAccount,
        call_data: []const u8,
        gas_limits: types.GasEstimates,
    ) !UserOperationAny {
        // Get current nonce if RPC available
        if (self.rpc_client) |rpc| {
            const ep = entrypoint_mod.EntryPoint.init(
                self.allocator,
                self.entry_point,
                self.entry_point_version,
                rpc,
            );
            var entry_point = ep;
            self.nonce = try entry_point.getNonce(self.address, 0);
        }

        // Check if account needs deployment
        const is_deployed = if (self.rpc_client != null)
            try self.isDeployed()
        else
            true; // Assume deployed if no RPC

        // Get init code for v0.6 or factory data for v0.7+
        const init_code = if (!is_deployed and self.factory != null)
            try self.getInitCode()
        else
            &[_]u8{};

        return switch (self.entry_point_version) {
            .v0_6 => UserOperationAny{
                .v0_6 = types.UserOperationV06{
                    .sender = self.address,
                    .nonce = self.nonce,
                    .initCode = init_code,
                    .callData = call_data,
                    .callGasLimit = gas_limits.callGasLimit,
                    .verificationGasLimit = gas_limits.verificationGasLimit,
                    .preVerificationGas = gas_limits.preVerificationGas,
                    .maxFeePerGas = 0,
                    .maxPriorityFeePerGas = 0,
                    .paymasterAndData = &[_]u8{},
                    .signature = &[_]u8{},
                },
            },
            .v0_7 => blk: {
                // For v0.7, use factory and factoryData instead of initCode
                var factory_addr: ?primitives.Address = null;
                var factory_data: []const u8 = &[_]u8{};

                if (!is_deployed and self.factory != null) {
                    const factory_info = try self.factory.?.createFactoryData(self.owner, self.salt);
                    factory_addr = factory_info.factory;
                    factory_data = factory_info.data;
                }

                break :blk UserOperationAny{
                    .v0_7 = types.UserOperationV07{
                        .sender = self.address,
                        .nonce = self.nonce,
                        .factory = factory_addr,
                        .factoryData = factory_data,
                        .callData = call_data,
                        .callGasLimit = @intCast(gas_limits.callGasLimit),
                        .verificationGasLimit = @intCast(gas_limits.verificationGasLimit),
                        .preVerificationGas = gas_limits.preVerificationGas,
                        .maxFeePerGas = 0,
                        .maxPriorityFeePerGas = 0,
                        .paymaster = null,
                        .paymasterVerificationGasLimit = 0,
                        .paymasterPostOpGasLimit = 0,
                        .paymasterData = &[_]u8{},
                        .signature = &[_]u8{},
                    },
                };
            },
            .v0_8 => blk: {
                // For v0.8, same as v0.7
                var factory_addr: ?primitives.Address = null;
                var factory_data: []const u8 = &[_]u8{};

                if (!is_deployed and self.factory != null) {
                    const factory_info = try self.factory.?.createFactoryData(self.owner, self.salt);
                    factory_addr = factory_info.factory;
                    factory_data = factory_info.data;
                }

                break :blk UserOperationAny{
                    .v0_8 = types.UserOperationV08{
                        .sender = self.address,
                        .nonce = self.nonce,
                        .factory = factory_addr,
                        .factoryData = factory_data,
                        .callData = call_data,
                        .callGasLimit = @intCast(gas_limits.callGasLimit),
                        .verificationGasLimit = @intCast(gas_limits.verificationGasLimit),
                        .preVerificationGas = gas_limits.preVerificationGas,
                        .maxFeePerGas = 0,
                        .maxPriorityFeePerGas = 0,
                        .paymaster = null,
                        .paymasterVerificationGasLimit = 0,
                        .paymasterPostOpGasLimit = 0,
                        .paymasterData = &[_]u8{},
                        .signature = &[_]u8{},
                    },
                };
            },
        };
    }

    /// Sign a UserOperation (works with any version via anytype)
    pub fn signUserOperation(
        self: *SmartAccount,
        user_op: anytype,
        private_key: []const u8,
    ) ![]u8 {
        // Validate type
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != *types.UserOperationV06 and
                UserOpType != *types.UserOperationV07 and
                UserOpType != *types.UserOperationV08)
            {
                @compileError("user_op must be pointer to UserOperationV06, V07, or V08");
            }
        }

        // Calculate UserOperation hash
        const user_op_hash = try self.calculateUserOpHash(user_op.*);

        // Sign the hash with ECDSA
        const signature = try ecdsa.sign(
            self.allocator,
            &user_op_hash.bytes,
            private_key,
        );

        return signature;
    }

    /// Calculate UserOperation hash for signing
    fn calculateUserOpHash(self: *SmartAccount, user_op: anytype) !Hash {
        // Get chain ID
        var chain_id: u64 = 1; // Default to mainnet

        if (self.rpc_client) |rpc| {
            const params_empty = std.json.Value{ .array = &[_]std.json.Value{} };
            if (rpc.call("eth_chainId", params_empty)) |response| {
                defer response.deinit(self.allocator);
                const chain_id_hex = response.string;
                const hex_str = if (std.mem.startsWith(u8, chain_id_hex, "0x"))
                    chain_id_hex[2..]
                else
                    chain_id_hex;
                chain_id = try std.fmt.parseInt(u64, hex_str, 16);
            } else |_| {
                // Use default if call fails
            }
        }

        // Use utils.UserOpHash.calculate for the actual hashing
        return try utils.UserOpHash.calculate(
            self.allocator,
            user_op,
            self.entry_point,
            chain_id,
        );
    }

    /// Get account nonce from chain
    pub fn getNonce(self: *SmartAccount) !u256 {
        const rpc = self.rpc_client orelse return self.nonce;

        var entry_point = entrypoint_mod.EntryPoint.init(
            self.allocator,
            self.entry_point,
            self.entry_point_version,
            rpc,
        );

        const nonce = try entry_point.getNonce(self.address, 0);
        self.nonce = nonce;
        return nonce;
    }

    /// Check if account is deployed
    pub fn isDeployed(self: *SmartAccount) !bool {
        const rpc = self.rpc_client orelse return false;

        // Get code at address using eth_getCode
        var params_array = std.json.Array.init(self.allocator);
        defer params_array.deinit();

        const address_hex = try self.address.toHex(self.allocator);
        defer self.allocator.free(address_hex);

        try params_array.append(.{ .string = address_hex });
        try params_array.append(.{ .string = "latest" });

        const params = std.json.Value{ .array = params_array };

        const response = try rpc.call("eth_getCode", params);
        const code_hex = response.string;

        // If code is "0x" or "0x0", account is not deployed
        return !std.mem.eql(u8, code_hex, "0x") and !std.mem.eql(u8, code_hex, "0x0");
    }

    /// Get account initCode for deployment
    pub fn getInitCode(self: *SmartAccount) ![]const u8 {
        // Check if already deployed
        if (self.rpc_client != null) {
            if (try self.isDeployed()) {
                return &[_]u8{}; // Empty initCode - already deployed
            }
        }

        // Generate initCode from factory if available
        if (self.factory) |factory| {
            return try factory.createInitCode(self.owner, self.salt);
        }

        // No factory configured and not deployed
        return &[_]u8{};
    }

    /// Encode execute call data
    /// Function: execute(address dest, uint256 value, bytes calldata func)
    pub fn encodeExecute(
        self: *SmartAccount,
        to: primitives.Address,
        value: u256,
        data: []const u8,
    ) ![]u8 {
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        errdefer call_data.deinit(self.allocator);

        // Function selector: execute(address,uint256,bytes) = 0xb61d27f6
        try call_data.appendSlice(self.allocator, &[_]u8{ 0xb6, 0x1d, 0x27, 0xf6 });

        // Encode address (32 bytes, left-padded)
        var addr_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(addr_bytes[12..], &to.bytes);
        try call_data.appendSlice(self.allocator, &addr_bytes);

        // Encode value (32 bytes)
        var value_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &value_bytes, value, .big);
        try call_data.appendSlice(self.allocator, &value_bytes);

        // Encode data offset (32 bytes) - points to start of data
        const data_offset: u256 = 96; // After selector + address + value
        var offset_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &offset_bytes, data_offset, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        // Encode data length (32 bytes)
        const data_len: u256 = @intCast(data.len);
        var len_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &len_bytes, data_len, .big);
        try call_data.appendSlice(self.allocator, &len_bytes);

        // Encode data (padded to 32-byte boundary)
        try call_data.appendSlice(self.allocator, data);

        // Pad to 32-byte boundary
        const padding = (32 - (data.len % 32)) % 32;
        if (padding > 0) {
            try call_data.appendNTimes(self.allocator, 0, padding);
        }

        return try call_data.toOwnedSlice(self.allocator);
    }

    /// Encode batch execute call data
    /// Function: executeBatch(address[] dests, uint256[] values, bytes[] funcs)
    pub fn encodeExecuteBatch(
        self: *SmartAccount,
        calls: []const Call,
    ) ![]u8 {
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        errdefer call_data.deinit(self.allocator);

        // Function selector: executeBatch(address[],uint256[],bytes[]) = 0x47e1da2a
        try call_data.appendSlice(self.allocator, &[_]u8{ 0x47, 0xe1, 0xda, 0x2a });

        // ABI encoding for three dynamic arrays
        // Layout: [selector][offset_to_dests][offset_to_values][offset_to_funcs][dests_array][values_array][funcs_array]

        // Calculate offsets
        const offset_to_dests: u256 = 96; // 3 * 32 (three offset slots)
        const offset_to_values: u256 = offset_to_dests + 32 + (calls.len * 32); // After dests array

        // Calculate offset to funcs (after values array)
        const offset_to_funcs: u256 = offset_to_values + 32 + (calls.len * 32);

        // Encode offsets (3 x 32 bytes)
        var offset_bytes: [32]u8 = undefined;

        std.mem.writeInt(u256, &offset_bytes, offset_to_dests, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        std.mem.writeInt(u256, &offset_bytes, offset_to_values, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        std.mem.writeInt(u256, &offset_bytes, offset_to_funcs, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        // Encode dests array
        const array_len: u256 = @intCast(calls.len);
        std.mem.writeInt(u256, &offset_bytes, array_len, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        for (calls) |call| {
            var addr_bytes: [32]u8 = [_]u8{0} ** 32;
            @memcpy(addr_bytes[12..], &call.to.bytes);
            try call_data.appendSlice(self.allocator, &addr_bytes);
        }

        // Encode values array
        std.mem.writeInt(u256, &offset_bytes, array_len, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        for (calls) |call| {
            var value_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &value_bytes, call.value, .big);
            try call_data.appendSlice(self.allocator, &value_bytes);
        }

        // Encode funcs array (dynamic bytes array)
        std.mem.writeInt(u256, &offset_bytes, array_len, .big);
        try call_data.appendSlice(self.allocator, &offset_bytes);

        // Calculate offsets for each bytes element
        var current_offset: u256 = 32 * calls.len; // After all offset slots
        for (calls) |_| {
            std.mem.writeInt(u256, &offset_bytes, current_offset, .big);
            try call_data.appendSlice(self.allocator, &offset_bytes);
            // Update for next element (need to calculate size)
        }

        // Encode each bytes element
        for (calls) |call| {
            // Length
            const data_len: u256 = @intCast(call.data.len);
            std.mem.writeInt(u256, &offset_bytes, data_len, .big);
            try call_data.appendSlice(self.allocator, &offset_bytes);

            // Data
            try call_data.appendSlice(self.allocator, call.data);

            // Padding to 32-byte boundary
            const padding = (32 - (call.data.len % 32)) % 32;
            if (padding > 0) {
                try call_data.appendNTimes(self.allocator, 0, padding);
            }

            // Update offset for next element
            current_offset += 32 + call.data.len + padding;
        }

        return try call_data.toOwnedSlice(self.allocator);
    }
};

/// Call structure for batch operations
pub const Call = struct {
    to: primitives.Address,
    value: u256,
    data: []const u8,
};

/// Simple Account Factory
/// For deploying new smart accounts
pub const AccountFactory = struct {
    address: primitives.Address,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, factory_address: primitives.Address) AccountFactory {
        return .{
            .allocator = allocator,
            .address = factory_address,
        };
    }

    /// Get account address (deterministic via CREATE2)
    pub fn getAddress(self: *AccountFactory, owner: primitives.Address, salt: u256) !primitives.Address {
        // CREATE2 address calculation:
        // address = keccak256(0xff ++ factory ++ salt ++ keccak256(initCodeHash))[12:]

        // For SimpleAccount, the initCodeHash includes the owner
        // This is a simplified version - actual implementation depends on factory

        var data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer data.deinit(self.allocator);

        // 0xff prefix
        try data.append(self.allocator, 0xff);

        // Factory address (20 bytes)
        try data.appendSlice(self.allocator, &self.address.bytes);

        // Salt (32 bytes)
        var salt_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &salt_bytes, salt, .big);
        try data.appendSlice(self.allocator, &salt_bytes);

        // InitCode hash (simplified - includes owner)
        var init_hash_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer init_hash_data.deinit(self.allocator);
        try init_hash_data.appendSlice(self.allocator, &owner.bytes);

        const init_code_hash = keccak.hash(init_hash_data.items);
        try data.appendSlice(self.allocator, &init_code_hash.bytes);

        // Calculate final address
        const address_hash = keccak.hash(data.items);

        // Take last 20 bytes
        var address_bytes: [20]u8 = undefined;
        @memcpy(&address_bytes, address_hash.bytes[12..]);

        return primitives.Address.fromBytes(address_bytes);
    }

    /// Create init code for account deployment (v0.6 format)
    /// Format: factory_address (20 bytes) ++ createAccount(owner, salt) calldata
    pub fn createInitCode(self: *AccountFactory, owner: primitives.Address, salt: u256) ![]u8 {
        var init_code = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        errdefer init_code.deinit(self.allocator);

        // Factory address (20 bytes)
        try init_code.appendSlice(self.allocator, &self.address.bytes);

        // Function selector: createAccount(address,uint256) = 0x5fbfb9cf
        try init_code.appendSlice(self.allocator, &[_]u8{ 0x5f, 0xbf, 0xb9, 0xcf });

        // Encode owner address (32 bytes, left-padded)
        var owner_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(owner_bytes[12..], &owner.bytes);
        try init_code.appendSlice(self.allocator, &owner_bytes);

        // Encode salt (32 bytes)
        var salt_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &salt_bytes, salt, .big);
        try init_code.appendSlice(self.allocator, &salt_bytes);

        return try init_code.toOwnedSlice(self.allocator);
    }

    /// Create factory and factory data for v0.7+ format
    /// Returns: (factory_address, factory_data)
    pub fn createFactoryData(self: *AccountFactory, owner: primitives.Address, salt: u256) !struct { factory: primitives.Address, data: []u8 } {
        var factory_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        errdefer factory_data.deinit(self.allocator);

        // Function selector: createAccount(address,uint256) = 0x5fbfb9cf
        try factory_data.appendSlice(self.allocator, &[_]u8{ 0x5f, 0xbf, 0xb9, 0xcf });

        // Encode owner address (32 bytes, left-padded)
        var owner_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(owner_bytes[12..], &owner.bytes);
        try factory_data.appendSlice(self.allocator, &owner_bytes);

        // Encode salt (32 bytes)
        var salt_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &salt_bytes, salt, .big);
        try factory_data.appendSlice(self.allocator, &salt_bytes);

        return .{
            .factory = self.address,
            .data = try factory_data.toOwnedSlice(self.allocator),
        };
    }
};
