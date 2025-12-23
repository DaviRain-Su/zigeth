const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const rpc_client = @import("../rpc/client.zig");

/// ERC-4337 Bundler Client
/// Implements eth_* methods for UserOperation handling
///
/// This client supports all three UserOperation versions:
/// - UserOperationV06: Original ERC-4337 format
/// - UserOperationV07: Gas-optimized packed format
/// - UserOperationV08: Latest format with additional optimizations
///
/// Methods use Zig's `anytype` for polymorphism, allowing any UserOperation
/// version to be passed. The type is validated at compile time for safety.
///
/// Example usage:
/// ```zig
/// var bundler = try BundlerClient.init(allocator, rpc_url, entry_point);
/// defer bundler.deinit();
///
/// // Works with v0.6
/// const user_op_v06: UserOperationV06 = ...;
/// const hash_v06 = try bundler.sendUserOperation(user_op_v06);
///
/// // Works with v0.7
/// const user_op_v07: UserOperationV07 = ...;
/// const hash_v07 = try bundler.sendUserOperation(user_op_v07);
///
/// // Works with v0.8
/// const user_op_v08: UserOperationV08 = ...;
/// const hash_v08 = try bundler.sendUserOperation(user_op_v08);
///
/// // Retrieve with specific version
/// const retrieved_v07 = try bundler.getUserOperationByHash(hash, UserOperationV07);
/// ```
pub const BundlerClient = struct {
    allocator: std.mem.Allocator,
    rpc_client: rpc_client.RpcClient,
    entry_point: primitives.Address,

    pub fn init(allocator: std.mem.Allocator, rpc_url: []const u8, entry_point: primitives.Address) !BundlerClient {
        return .{
            .allocator = allocator,
            .rpc_client = try rpc_client.RpcClient.init(allocator, rpc_url),
            .entry_point = entry_point,
        };
    }

    pub fn deinit(self: *BundlerClient) void {
        self.rpc_client.deinit();
    }

    /// Send UserOperation to bundler (supports v0.6, v0.7, v0.8)
    /// Method: eth_sendUserOperation
    pub fn sendUserOperation(self: *BundlerClient, user_op: anytype) !Hash {
        // Validate UserOperation type at compile time
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                @compileError("user_op must be UserOperationV06, UserOperationV07, or UserOperationV08");
            }
        }

        // Convert UserOperation to JSON
        const user_op_json = try types.UserOperationJson.fromUserOperation(self.allocator, user_op);

        // Convert EntryPoint address to hex string
        const entry_point_hex = try self.entry_point.toHex(self.allocator);
        defer self.allocator.free(entry_point_hex);

        // Build params array: [userOp, entryPoint]
        var params_array = try std.ArrayList(std.json.Value).initCapacity(self.allocator, 0);
        defer params_array.deinit(self.allocator);

        const user_op_value = try std.json.Value.jsonStringify(user_op_json, .{}, self.allocator);
        const entry_point_value = std.json.Value{ .string = entry_point_hex };

        try params_array.append(self.allocator, user_op_value);
        try params_array.append(self.allocator, entry_point_value);

        const params = std.json.Value{ .array = params_array.items };

        // Make RPC call
        const response = try self.rpc_client.call("eth_sendUserOperation", params);

        // Parse result as hash string
        const hash_str = response.string;
        return try Hash.fromHex(hash_str);
    }

    /// Estimate UserOperation gas (supports v0.6, v0.7, v0.8)
    /// Method: eth_estimateUserOperationGas
    pub fn estimateUserOperationGas(self: *BundlerClient, user_op: anytype) !types.GasEstimates {
        // Validate UserOperation type at compile time
        const UserOpType = @TypeOf(user_op);
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                @compileError("user_op must be UserOperationV06, UserOperationV07, or UserOperationV08");
            }
        }

        // Convert UserOperation to JSON
        const user_op_json = try types.UserOperationJson.fromUserOperation(self.allocator, user_op);
        defer user_op_json.deinit(self.allocator);

        // Serialize UserOperation to JSON string
        var json_string = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer json_string.deinit(self.allocator);
        try std.json.stringify(user_op_json, .{}, json_string.writer(self.allocator));

        // Parse JSON string into Value
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, json_string.items, .{});
        defer parsed.deinit();
        const user_op_value = parsed.value;

        // Convert EntryPoint address to hex string
        const entry_point_hex = try self.entry_point.toHex(self.allocator);
        defer self.allocator.free(entry_point_hex);
        const entry_point_value = std.json.Value{ .string = entry_point_hex };

        // Build params array: [userOp, entryPoint]
        var params_array = try std.ArrayList(std.json.Value).initCapacity(self.allocator, 0);
        defer params_array.deinit(self.allocator);
        try params_array.append(self.allocator, user_op_value);
        try params_array.append(self.allocator, entry_point_value);

        const params = std.json.Value{ .array = params_array.items };

        // Make RPC call
        const response = try self.rpc_client.call("eth_estimateUserOperationGas", params);

        // Parse result object
        const result_obj = response.object;

        return types.GasEstimates{
            .preVerificationGas = try std.fmt.parseInt(u256, result_obj.get("preVerificationGas").?.string[2..], 16),
            .verificationGasLimit = try std.fmt.parseInt(u256, result_obj.get("verificationGasLimit").?.string[2..], 16),
            .callGasLimit = try std.fmt.parseInt(u256, result_obj.get("callGasLimit").?.string[2..], 16),
        };
    }

    /// Get UserOperation by hash (supports v0.6, v0.7, v0.8)
    /// Method: eth_getUserOperationByHash
    /// Returns the specified UserOperation version type
    pub fn getUserOperationByHash(self: *BundlerClient, user_op_hash: Hash, comptime UserOpType: type) !?UserOpType {
        // Validate UserOperation type at compile time
        comptime {
            if (UserOpType != types.UserOperationV06 and
                UserOpType != types.UserOperationV07 and
                UserOpType != types.UserOperationV08)
            {
                @compileError("UserOpType must be UserOperationV06, UserOperationV07, or UserOperationV08");
            }
        }

        // Convert hash to hex string
        const hash_hex = try user_op_hash.toHex(self.allocator);
        defer self.allocator.free(hash_hex);

        // Build params array: [userOpHash]
        var params_array = try std.ArrayList(std.json.Value).initCapacity(self.allocator, 0);
        defer params_array.deinit(self.allocator);

        const hash_value = std.json.Value{ .string = hash_hex };
        try params_array.append(self.allocator, hash_value);

        const params = std.json.Value{ .array = params_array.items };

        // Make RPC call
        const response = try self.rpc_client.call("eth_getUserOperationByHash", params);

        // Check if result is null
        if (response == .null) {
            return null;
        }

        // Parse result as UserOperation of the requested type
        const user_op_json = try std.json.parseFromValue(types.UserOperationJson, self.allocator, response, .{});
        defer user_op_json.deinit();

        return try user_op_json.value.toUserOperation(self.allocator, UserOpType);
    }

    /// Get UserOperation receipt
    /// Method: eth_getUserOperationReceipt
    pub fn getUserOperationReceipt(self: *BundlerClient, user_op_hash: Hash) !?types.UserOperationReceipt {
        // Convert hash to hex string
        const hash_hex = try user_op_hash.toHex(self.allocator);
        defer self.allocator.free(hash_hex);

        // Build params array: [userOpHash]
        var params_array = try std.ArrayList(std.json.Value).initCapacity(self.allocator, 0);
        defer params_array.deinit(self.allocator);

        const hash_value = std.json.Value{ .string = hash_hex };
        try params_array.append(self.allocator, hash_value);

        const params = std.json.Value{ .array = params_array.items };

        // Make RPC call
        const response = try self.rpc_client.call("eth_getUserOperationReceipt", params);

        // Check if result is null
        if (response == .null) {
            return null;
        }

        // Parse result as UserOperationReceipt
        const receipt_parsed = try std.json.parseFromValue(types.UserOperationReceipt, self.allocator, response, .{});
        defer receipt_parsed.deinit();

        return receipt_parsed.value;
    }

    /// Get supported entry points
    /// Method: eth_supportedEntryPoints
    pub fn getSupportedEntryPoints(self: *BundlerClient) ![]primitives.Address {
        // Build empty params array
        const params = std.json.Value{ .array = &[_]std.json.Value{} };

        // Make RPC call
        const response = try self.rpc_client.call("eth_supportedEntryPoints", params);

        // Parse result as array of address strings
        const addresses_array = response.array;

        var result = try std.ArrayList(primitives.Address).initCapacity(self.allocator, 0);
        errdefer result.deinit(self.allocator);

        for (addresses_array) |addr_value| {
            const addr_str = addr_value.string;
            const address = try primitives.Address.fromHex(addr_str);
            try result.append(self.allocator, address);
        }

        return try result.toOwnedSlice(self.allocator);
    }

    /// Get chain ID
    /// Method: eth_chainId
    pub fn getChainId(self: *BundlerClient) !u64 {
        // Build empty params array
        const params = std.json.Value{ .array = &[_]std.json.Value{} };

        // Make RPC call
        const response = try self.rpc_client.call("eth_chainId", params);

        // Parse result as hex string and convert to u64
        const chain_id_hex = response.string;

        // Remove "0x" prefix if present
        const hex_str = if (std.mem.startsWith(u8, chain_id_hex, "0x"))
            chain_id_hex[2..]
        else
            chain_id_hex;

        return try std.fmt.parseInt(u64, hex_str, 16);
    }
};
