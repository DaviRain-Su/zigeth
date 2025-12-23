const std = @import("std");
const types = @import("types.zig");
const primitives = @import("../primitives/address.zig");
const Hash = @import("../primitives/hash.zig").Hash;
const rpc_client = @import("../rpc/client.zig");
const abi = @import("../abi/types.zig");
const encode = @import("../abi/encode.zig");
const decode = @import("../abi/decode.zig");

/// ERC-4337 EntryPoint contract
/// Supports v0.6, v0.7, and v0.8
pub const EntryPoint = struct {
    address: primitives.Address,
    allocator: std.mem.Allocator,
    version: types.EntryPointVersion,
    rpc_client: ?*rpc_client.RpcClient,

    /// EntryPoint v0.6 standard address (Legacy)
    pub const ENTRYPOINT_V06_ADDRESS = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";

    /// EntryPoint v0.7 standard address (Current - Gas-optimized)
    pub const ENTRYPOINT_V07_ADDRESS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

    /// EntryPoint v0.8 standard address
    pub const ENTRYPOINT_V08_ADDRESS = "0x4337084d9e255ff0702461cf8895ce9e3b5ff108";

    pub fn init(allocator: std.mem.Allocator, address: primitives.Address, version: types.EntryPointVersion, rpc: ?*rpc_client.RpcClient) EntryPoint {
        return .{
            .allocator = allocator,
            .address = address,
            .version = version,
            .rpc_client = rpc,
        };
    }

    /// Create EntryPoint with v0.6 standard address
    pub fn v06(allocator: std.mem.Allocator, rpc: ?*rpc_client.RpcClient) !EntryPoint {
        const address = try primitives.Address.fromHex(ENTRYPOINT_V06_ADDRESS);
        return init(allocator, address, .v0_6, rpc);
    }

    /// Create EntryPoint with v0.7 standard address
    pub fn v07(allocator: std.mem.Allocator, rpc: ?*rpc_client.RpcClient) !EntryPoint {
        const address = try primitives.Address.fromHex(ENTRYPOINT_V07_ADDRESS);
        return init(allocator, address, .v0_7, rpc);
    }

    /// Create EntryPoint with v0.8 standard address
    pub fn v08(allocator: std.mem.Allocator, rpc: ?*rpc_client.RpcClient) !EntryPoint {
        const address = try primitives.Address.fromHex(ENTRYPOINT_V08_ADDRESS);
        return init(allocator, address, .v0_8, rpc);
    }

    /// Helper function to make eth_call
    fn ethCall(self: *EntryPoint, call_data: []const u8) ![]const u8 {
        const rpc = self.rpc_client orelse return error.NoRpcClient;

        // Convert address to hex string
        const to_hex = try self.address.toHex(self.allocator);
        defer self.allocator.free(to_hex);

        // Convert call data to hex string
        const data_hex = try std.fmt.allocPrint(self.allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(call_data)});
        defer self.allocator.free(data_hex);

        // Build eth_call params
        var params_array = try std.ArrayList(std.json.Value).initCapacity(self.allocator, 0);
        defer params_array.deinit(self.allocator);

        // Call object
        var call_obj = std.json.ObjectMap.init(self.allocator);
        try call_obj.put("to", .{ .string = to_hex });
        try call_obj.put("data", .{ .string = data_hex });
        try params_array.append(self.allocator, .{ .object = call_obj });

        // Block parameter (latest)
        try params_array.append(self.allocator, .{ .string = "latest" });

        const params = std.json.Value{ .array = params_array.items };

        // Make RPC call
        const response = try rpc.call("eth_call", params);

        // Return hex string (caller is responsible for parsing)
        return try self.allocator.dupe(u8, response.string);
    }

    /// Helper function to send transaction
    fn sendTransaction(self: *EntryPoint, call_data: []const u8, from: primitives.Address, value: u256) !Hash {
        const rpc = self.rpc_client orelse return error.NoRpcClient;

        // Convert addresses to hex
        const to_hex = try self.address.toHex(self.allocator);
        defer self.allocator.free(to_hex);

        const from_hex = try from.toHex(self.allocator);
        defer self.allocator.free(from_hex);

        // Convert call data to hex string
        const data_hex = try std.fmt.allocPrint(self.allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(call_data)});
        defer self.allocator.free(data_hex);

        // Convert value to hex
        const value_hex = try std.fmt.allocPrint(self.allocator, "0x{x}", .{value});
        defer self.allocator.free(value_hex);

        // Build eth_sendTransaction params
        var params_array = try std.ArrayList(std.json.Value).initCapacity(self.allocator, 0);
        defer params_array.deinit(self.allocator);

        // Transaction object
        var tx_obj = std.json.ObjectMap.init(self.allocator);
        try tx_obj.put("from", .{ .string = from_hex });
        try tx_obj.put("to", .{ .string = to_hex });
        try tx_obj.put("data", .{ .string = data_hex });
        try tx_obj.put("value", .{ .string = value_hex });
        try params_array.append(self.allocator, .{ .object = tx_obj });

        const params = std.json.Value{ .array = params_array.items };

        // Make RPC call
        const response = try rpc.call("eth_sendTransaction", params);

        // Parse hash from response
        return try Hash.fromHex(response.string);
    }

    /// Get nonce for sender
    /// Call: getNonce(address sender, uint192 key)
    pub fn getNonce(self: *EntryPoint, sender: primitives.Address, key: u192) !u256 {
        // Build call data
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer call_data.deinit(self.allocator);

        // Function selector: getNonce(address,uint192) = 0x35567e1a
        try call_data.appendSlice(self.allocator, &[_]u8{ 0x35, 0x56, 0x7e, 0x1a });

        // Encode address (32 bytes, left-padded)
        var addr_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(addr_bytes[12..], &sender.bytes);
        try call_data.appendSlice(self.allocator, &addr_bytes);

        // Encode uint192 key (32 bytes)
        var key_bytes: [32]u8 = [_]u8{0} ** 32;
        const key_u256: u256 = @intCast(key);
        std.mem.writeInt(u256, &key_bytes, key_u256, .big);
        try call_data.appendSlice(self.allocator, &key_bytes);

        // Make eth_call
        const result_hex = try self.ethCall(call_data.items);
        defer self.allocator.free(result_hex);

        // Remove "0x" prefix and parse as u256
        const hex_str = if (std.mem.startsWith(u8, result_hex, "0x"))
            result_hex[2..]
        else
            result_hex;

        return try std.fmt.parseInt(u256, hex_str, 16);
    }

    /// Get account deposit balance
    /// Call: balanceOf(address account)
    pub fn balanceOf(self: *EntryPoint, account: primitives.Address) !u256 {
        // Build call data
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer call_data.deinit(self.allocator);

        // Function selector: balanceOf(address) = 0x70a08231
        try call_data.appendSlice(self.allocator, &[_]u8{ 0x70, 0xa0, 0x82, 0x31 });

        // Encode address (32 bytes, left-padded)
        var addr_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(addr_bytes[12..], &account.bytes);
        try call_data.appendSlice(self.allocator, &addr_bytes);

        // Make eth_call
        const result_hex = try self.ethCall(call_data.items);
        defer self.allocator.free(result_hex);

        // Parse result
        const hex_str = if (std.mem.startsWith(u8, result_hex, "0x"))
            result_hex[2..]
        else
            result_hex;

        return try std.fmt.parseInt(u256, hex_str, 16);
    }

    /// Get deposit info for account
    /// Call: getDepositInfo(address account)
    /// Returns: (uint112 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime)
    pub fn getDepositInfo(self: *EntryPoint, account: primitives.Address) !DepositInfo {
        // Build call data
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer call_data.deinit(self.allocator);

        // Function selector: getDepositInfo(address) = 0x5287ce12
        try call_data.appendSlice(self.allocator, &[_]u8{ 0x52, 0x87, 0xce, 0x12 });

        // Encode address (32 bytes, left-padded)
        var addr_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(addr_bytes[12..], &account.bytes);
        try call_data.appendSlice(self.allocator, &addr_bytes);

        // Make eth_call
        const result_hex = try self.ethCall(call_data.items);
        defer self.allocator.free(result_hex);

        // Parse result (5 return values, each 32 bytes)
        const hex_str = if (std.mem.startsWith(u8, result_hex, "0x"))
            result_hex[2..]
        else
            result_hex;

        // Decode each 32-byte chunk
        const deposit = try std.fmt.parseInt(u256, hex_str[0..64], 16);
        const staked_val = try std.fmt.parseInt(u256, hex_str[64..128], 16);
        const stake = try std.fmt.parseInt(u256, hex_str[128..192], 16);
        const unstake_delay = try std.fmt.parseInt(u32, hex_str[192..256], 16);
        const withdraw_time = try std.fmt.parseInt(u48, hex_str[256..320], 16);

        return DepositInfo{
            .deposit = deposit,
            .staked = staked_val != 0,
            .stake = stake,
            .unstakeDelaySec = unstake_delay,
            .withdrawTime = withdraw_time,
        };
    }

    /// Simulate UserOperation validation
    /// Call: simulateValidation(UserOperation calldata userOp)
    pub fn simulateValidation(self: *EntryPoint, user_op: types.UserOperation) !ValidationResult {
        // Build call data
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer call_data.deinit(self.allocator);

        // Function selector: simulateValidation((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes))
        // v0.6 selector = 0xee219423
        try call_data.appendSlice(self.allocator, &[_]u8{ 0xee, 0x21, 0x94, 0x23 });

        // TODO: Full UserOperation encoding (complex tuple encoding)
        // For now, this is a placeholder showing the structure
        // A complete implementation would need to:
        // 1. Encode the UserOperation struct as ABI tuple
        // 2. Handle dynamic bytes arrays (initCode, callData, paymasterAndData, signature)
        // 3. Properly offset pointers for dynamic data
        _ = user_op;

        // This is a stub - actual implementation requires full ABI tuple encoding
        return error.NotImplemented;

        // When fully implemented, would parse the complex return struct:
        // (ReturnInfo, StakeInfo, StakeInfo, StakeInfo)
    }

    /// Handle UserOperation aggregation
    /// Call: handleOps(UserOperation[] calldata ops, address payable beneficiary)
    pub fn handleOps(
        self: *EntryPoint,
        user_ops: []const types.UserOperation,
        beneficiary: primitives.Address,
        from: primitives.Address,
    ) !Hash {
        // Build call data
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer call_data.deinit(self.allocator);

        // Function selector: handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)
        // v0.6 selector = 0x1fad948c
        try call_data.appendSlice(self.allocator, &[_]u8{ 0x1f, 0xad, 0x94, 0x8c });

        // TODO: Full UserOperation array encoding (very complex)
        // Would need to:
        // 1. Encode array offset
        // 2. Encode array length
        // 3. Encode each UserOperation struct
        // 4. Handle all dynamic arrays properly
        // 5. Encode beneficiary address
        _ = user_ops;
        _ = beneficiary;
        _ = from; // Will be used when fully implemented

        // This is a stub - actual implementation requires complex array+tuple encoding
        return error.NotImplemented;

        // When fully implemented, would send transaction:
        // return try self.sendTransaction(call_data.items, from, 0);
    }

    /// Add deposit for account
    /// Call: depositTo(address account) payable
    pub fn depositTo(self: *EntryPoint, account: primitives.Address, amount: u256, from: primitives.Address) !Hash {
        // Build call data
        var call_data = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer call_data.deinit(self.allocator);

        // Function selector: depositTo(address) = 0xb760faf9
        try call_data.appendSlice(self.allocator, &[_]u8{ 0xb7, 0x60, 0xfa, 0xf9 });

        // Encode address (32 bytes, left-padded)
        var addr_bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(addr_bytes[12..], &account.bytes);
        try call_data.appendSlice(self.allocator, &addr_bytes);

        // Send transaction with value
        return try self.sendTransaction(call_data.items, from, amount);
    }
};

/// Deposit information for an account
pub const DepositInfo = struct {
    deposit: u256,
    staked: bool,
    stake: u256,
    unstakeDelaySec: u32,
    withdrawTime: u48,
};

/// Validation result from simulateValidation
pub const ValidationResult = struct {
    returnInfo: ReturnInfo,
    senderInfo: ?StakeInfo,
    factoryInfo: ?StakeInfo,
    paymasterInfo: ?StakeInfo,
};

pub const ReturnInfo = struct {
    preOpGas: u256,
    prefund: u256,
    sigFailed: bool,
    validAfter: u48,
    validUntil: u48,
    paymasterContext: []const u8,
};

pub const StakeInfo = struct {
    stake: u256,
    unstakeDelaySec: u32,
};
