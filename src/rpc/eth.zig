const std = @import("std");
const RpcClient = @import("./client.zig").RpcClient;
const types = @import("./types.zig");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const Block = @import("../types/block.zig").Block;
const Transaction = @import("../types/transaction.zig").Transaction;
const Receipt = @import("../types/receipt.zig").Receipt;
const Log = @import("../types/log.zig").Log;

/// Ethereum namespace (eth_*) methods
pub const EthNamespace = struct {
    client: *RpcClient,

    pub fn init(client: *RpcClient) EthNamespace {
        return .{ .client = client };
    }

    /// eth_blockNumber - Returns the current block number
    pub fn blockNumber(self: EthNamespace) !u64 {
        const result = try self.client.callNoParams("eth_blockNumber");

        // Parse hex string to u64
        if (result != .string) {
            return error.InvalidResponse;
        }

        const hex_str = result.string;
        return try parseHexU64(hex_str);
    }

    /// eth_getBalance - Returns the balance of an account
    pub fn getBalance(self: EthNamespace, address: Address, block: types.BlockParameter) !U256 {
        const addr_hex = try address.toHex(self.client.allocator);
        defer self.client.allocator.free(addr_hex);

        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = addr_hex },
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_getBalance", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try U256.fromHex(result.string);
    }

    /// eth_getTransactionCount - Returns the number of transactions sent from an address
    pub fn getTransactionCount(self: EthNamespace, address: Address, block: types.BlockParameter) !u64 {
        const addr_hex = try address.toHex(self.client.allocator);
        defer self.client.allocator.free(addr_hex);

        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = addr_hex },
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_getTransactionCount", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_getBlockByNumber - Returns information about a block by number
    pub fn getBlockByNumber(self: EthNamespace, block: types.BlockParameter, full_tx: bool) !Block {
        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = block_param },
            .{ .bool = full_tx },
        };

        const result = try self.client.callWithParams("eth_getBlockByNumber", &params);

        // TODO: Parse JSON block object into Block struct
        _ = result;
        return error.NotImplemented;
    }

    /// eth_getBlockByHash - Returns information about a block by hash
    pub fn getBlockByHash(self: EthNamespace, hash: Hash, full_tx: bool) !Block {
        const hash_hex = try hash.toHex(self.client.allocator);
        defer self.client.allocator.free(hash_hex);

        var params = [_]std.json.Value{
            .{ .string = hash_hex },
            .{ .bool = full_tx },
        };

        const result = try self.client.callWithParams("eth_getBlockByHash", &params);

        // TODO: Parse JSON block object into Block struct
        _ = result;
        return error.NotImplemented;
    }

    /// eth_getTransactionByHash - Returns a transaction by hash
    pub fn getTransactionByHash(self: EthNamespace, hash: Hash) !Transaction {
        const hash_hex = try hash.toHex(self.client.allocator);
        defer self.client.allocator.free(hash_hex);

        var params = [_]std.json.Value{
            .{ .string = hash_hex },
        };

        const result = try self.client.callWithParams("eth_getTransactionByHash", &params);

        // TODO: Parse JSON transaction object into Transaction struct
        _ = result;
        return error.NotImplemented;
    }

    /// eth_getTransactionReceipt - Returns the receipt of a transaction
    pub fn getTransactionReceipt(self: EthNamespace, hash: Hash) !Receipt {
        const hash_hex = try hash.toHex(self.client.allocator);
        defer self.client.allocator.free(hash_hex);

        var params = [_]std.json.Value{
            .{ .string = hash_hex },
        };

        const result = try self.client.callWithParams("eth_getTransactionReceipt", &params);

        // TODO: Parse JSON receipt object into Receipt struct
        _ = result;
        return error.NotImplemented;
    }

    /// eth_call - Executes a message call (doesn't create a transaction)
    pub fn call(self: EthNamespace, params: types.CallParams, block: types.BlockParameter) ![]u8 {
        const call_obj = try callParamsToJson(self.client.allocator, params);
        defer call_obj.deinit();

        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var rpc_params = [_]std.json.Value{
            call_obj.value,
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_call", &rpc_params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        // Parse hex result
        const hex_module = @import("../utils/hex.zig");
        return try hex_module.hexToBytes(self.client.allocator, result.string);
    }

    /// eth_estimateGas - Estimates gas needed for a transaction
    pub fn estimateGas(self: EthNamespace, params: types.CallParams) !u64 {
        const call_obj = try callParamsToJson(self.client.allocator, params);
        defer call_obj.deinit();

        var rpc_params = [_]std.json.Value{
            call_obj.value,
        };

        const result = try self.client.callWithParams("eth_estimateGas", &rpc_params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_gasPrice - Returns the current gas price in wei
    pub fn gasPrice(self: EthNamespace) !U256 {
        const result = try self.client.callNoParams("eth_gasPrice");

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try U256.fromHex(result.string);
    }

    /// eth_maxPriorityFeePerGas - Returns the current max priority fee per gas
    pub fn maxPriorityFeePerGas(self: EthNamespace) !U256 {
        const result = try self.client.callNoParams("eth_maxPriorityFeePerGas");

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try U256.fromHex(result.string);
    }

    /// eth_feeHistory - Returns historical gas information
    pub fn feeHistory(
        self: EthNamespace,
        block_count: u64,
        newest_block: types.BlockParameter,
        reward_percentiles: ?[]const f64,
    ) !types.FeeHistory {
        const block_count_hex = try std.fmt.allocPrint(self.client.allocator, "0x{x}", .{block_count});
        defer self.client.allocator.free(block_count_hex);

        const block_param = try blockParameterToString(self.client.allocator, newest_block);
        defer self.client.allocator.free(block_param);

        var percentiles_array = std.json.Array.init(self.client.allocator);
        defer percentiles_array.deinit();

        if (reward_percentiles) |percentiles| {
            for (percentiles) |p| {
                try percentiles_array.append(.{ .float = p });
            }
        }

        var params = [_]std.json.Value{
            .{ .string = block_count_hex },
            .{ .string = block_param },
            .{ .array = percentiles_array },
        };

        const result = try self.client.callWithParams("eth_feeHistory", &params);

        // TODO: Parse JSON fee history object
        _ = result;
        return error.NotImplemented;
    }

    /// eth_getCode - Returns code at a given address
    pub fn getCode(self: EthNamespace, address: Address, block: types.BlockParameter) ![]u8 {
        const addr_hex = try address.toHex(self.client.allocator);
        defer self.client.allocator.free(addr_hex);

        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = addr_hex },
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_getCode", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        // Parse hex bytecode
        const hex_module = @import("../utils/hex.zig");
        return try hex_module.hexToBytes(self.client.allocator, result.string);
    }

    /// eth_getStorageAt - Returns the value from a storage position
    pub fn getStorageAt(self: EthNamespace, address: Address, position: U256, block: types.BlockParameter) !Hash {
        const addr_hex = try address.toHex(self.client.allocator);
        defer self.client.allocator.free(addr_hex);

        const position_hex = try position.toHex(self.client.allocator);
        defer self.client.allocator.free(position_hex);

        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = addr_hex },
            .{ .string = position_hex },
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_getStorageAt", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try Hash.fromHex(result.string);
    }

    /// eth_getLogs - Returns an array of logs matching the filter
    pub fn getLogs(self: EthNamespace, filter: types.FilterOptions) ![]Log {
        const filter_obj = try filterOptionsToJson(self.client.allocator, filter);
        defer filter_obj.deinit();

        var params = [_]std.json.Value{
            filter_obj.value,
        };

        const result = try self.client.callWithParams("eth_getLogs", &params);

        // TODO: Parse JSON logs array into Log structs
        _ = result;
        return error.NotImplemented;
    }

    /// eth_sendRawTransaction - Sends a signed transaction
    pub fn sendRawTransaction(self: EthNamespace, signed_tx: []const u8) !Hash {
        const hex_module = @import("../utils/hex.zig");
        const tx_hex = try hex_module.bytesToHex(self.client.allocator, signed_tx);
        defer self.client.allocator.free(tx_hex);

        var params = [_]std.json.Value{
            .{ .string = tx_hex },
        };

        const result = try self.client.callWithParams("eth_sendRawTransaction", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try Hash.fromHex(result.string);
    }

    /// eth_sendTransaction - Creates and sends a transaction
    pub fn sendTransaction(self: EthNamespace, params: types.TransactionParams) !Hash {
        const tx_obj = try transactionParamsToJson(self.client.allocator, params);
        defer tx_obj.deinit();

        var rpc_params = [_]std.json.Value{
            tx_obj.value,
        };

        const result = try self.client.callWithParams("eth_sendTransaction", &rpc_params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try Hash.fromHex(result.string);
    }

    /// eth_chainId - Returns the chain ID
    pub fn chainId(self: EthNamespace) !u64 {
        const result = try self.client.callNoParams("eth_chainId");

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_syncing - Returns sync status
    pub fn syncing(self: EthNamespace) !types.SyncStatus {
        const result = try self.client.callNoParams("eth_syncing");

        // Result is either false or an object with sync info
        if (result == .bool and !result.bool) {
            return types.SyncStatus{ .syncing = false };
        }

        if (result != .object) {
            return error.InvalidResponse;
        }

        // TODO: Parse sync status object
        return types.SyncStatus{ .syncing = true };
    }

    /// eth_getBlockTransactionCountByHash - Returns the number of transactions in a block
    pub fn getBlockTransactionCountByHash(self: EthNamespace, hash: Hash) !u64 {
        const hash_hex = try hash.toHex(self.client.allocator);
        defer self.client.allocator.free(hash_hex);

        var params = [_]std.json.Value{
            .{ .string = hash_hex },
        };

        const result = try self.client.callWithParams("eth_getBlockTransactionCountByHash", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_getBlockTransactionCountByNumber - Returns the number of transactions in a block
    pub fn getBlockTransactionCountByNumber(self: EthNamespace, block: types.BlockParameter) !u64 {
        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_getBlockTransactionCountByNumber", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_getUncleCountByBlockHash - Returns the number of uncles in a block
    pub fn getUncleCountByBlockHash(self: EthNamespace, hash: Hash) !u64 {
        const hash_hex = try hash.toHex(self.client.allocator);
        defer self.client.allocator.free(hash_hex);

        var params = [_]std.json.Value{
            .{ .string = hash_hex },
        };

        const result = try self.client.callWithParams("eth_getUncleCountByBlockHash", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_getUncleCountByBlockNumber - Returns the number of uncles in a block
    pub fn getUncleCountByBlockNumber(self: EthNamespace, block: types.BlockParameter) !u64 {
        const block_param = try blockParameterToString(self.client.allocator, block);
        defer self.client.allocator.free(block_param);

        var params = [_]std.json.Value{
            .{ .string = block_param },
        };

        const result = try self.client.callWithParams("eth_getUncleCountByBlockNumber", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try parseHexU64(result.string);
    }

    /// eth_accounts - Returns list of addresses owned by client
    pub fn accounts(self: EthNamespace) ![]Address {
        const result = try self.client.callNoParams("eth_accounts");

        if (result != .array) {
            return error.InvalidResponse;
        }

        var addresses = std.ArrayList(Address).init(self.client.allocator);
        errdefer addresses.deinit();

        for (result.array.items) |item| {
            if (item != .string) {
                return error.InvalidResponse;
            }
            const addr = try Address.fromHex(item.string);
            try addresses.append(addr);
        }

        return try addresses.toOwnedSlice();
    }

    /// eth_sign - Signs data with an address
    pub fn sign(self: EthNamespace, address: Address, data: []const u8) ![]u8 {
        const addr_hex = try address.toHex(self.client.allocator);
        defer self.client.allocator.free(addr_hex);

        const hex_module = @import("../utils/hex.zig");
        const data_hex = try hex_module.bytesToHex(self.client.allocator, data);
        defer self.client.allocator.free(data_hex);

        var params = [_]std.json.Value{
            .{ .string = addr_hex },
            .{ .string = data_hex },
        };

        const result = try self.client.callWithParams("eth_sign", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try hex_module.hexToBytes(self.client.allocator, result.string);
    }

    /// eth_signTransaction - Signs a transaction
    pub fn signTransaction(self: EthNamespace, params: types.TransactionParams) ![]u8 {
        const tx_obj = try transactionParamsToJson(self.client.allocator, params);
        defer tx_obj.deinit();

        var rpc_params = [_]std.json.Value{
            tx_obj.value,
        };

        const result = try self.client.callWithParams("eth_signTransaction", &rpc_params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        const hex_module = @import("../utils/hex.zig");
        return try hex_module.hexToBytes(self.client.allocator, result.string);
    }
};

/// Helper functions for parameter conversion
/// Convert BlockParameter to string for RPC
fn blockParameterToString(allocator: std.mem.Allocator, block: types.BlockParameter) ![]u8 {
    return switch (block) {
        .latest => try allocator.dupe(u8, "latest"),
        .earliest => try allocator.dupe(u8, "earliest"),
        .pending => try allocator.dupe(u8, "pending"),
        .safe => try allocator.dupe(u8, "safe"),
        .finalized => try allocator.dupe(u8, "finalized"),
        .number => |num| try std.fmt.allocPrint(allocator, "0x{x}", .{num}),
    };
}

/// Parse hex string to u64
fn parseHexU64(hex_str: []const u8) !u64 {
    // Remove 0x prefix if present
    const str = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
    return try std.fmt.parseInt(u64, str, 16);
}

/// JSON object wrapper for automatic cleanup
const JsonObjectWrapper = struct {
    value: std.json.Value,
    allocator: std.mem.Allocator,

    fn deinit(self: JsonObjectWrapper) void {
        if (self.value == .object) {
            self.value.object.deinit();
        }
    }
};

/// Convert CallParams to JSON object
fn callParamsToJson(allocator: std.mem.Allocator, params: types.CallParams) !JsonObjectWrapper {
    var obj = std.json.ObjectMap.init(allocator);

    // Required fields
    if (params.to) |to| {
        const to_hex = try to.toHex(allocator);
        try obj.put("to", .{ .string = to_hex });
    }

    // Optional fields
    if (params.from) |from| {
        const from_hex = try from.toHex(allocator);
        try obj.put("from", .{ .string = from_hex });
    }

    if (params.data) |data| {
        const hex_module = @import("../utils/hex.zig");
        const data_hex = try hex_module.bytesToHex(allocator, data);
        try obj.put("data", .{ .string = data_hex });
    }

    if (params.value) |value| {
        const value_hex = try value.toHex(allocator);
        try obj.put("value", .{ .string = value_hex });
    }

    if (params.gas) |gas| {
        const gas_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{gas});
        try obj.put("gas", .{ .string = gas_hex });
    }

    if (params.gas_price) |gas_price| {
        const gp_hex = try gas_price.toHex(allocator);
        try obj.put("gasPrice", .{ .string = gp_hex });
    }

    return JsonObjectWrapper{
        .value = .{ .object = obj },
        .allocator = allocator,
    };
}

/// Convert TransactionParams to JSON object
fn transactionParamsToJson(allocator: std.mem.Allocator, params: types.TransactionParams) !JsonObjectWrapper {
    var obj = std.json.ObjectMap.init(allocator);

    const from_hex = try params.from.toHex(allocator);
    try obj.put("from", .{ .string = from_hex });

    if (params.to) |to| {
        const to_hex = try to.toHex(allocator);
        try obj.put("to", .{ .string = to_hex });
    }

    if (params.data) |data| {
        const hex_module = @import("../utils/hex.zig");
        const data_hex = try hex_module.bytesToHex(allocator, data);
        try obj.put("data", .{ .string = data_hex });
    }

    if (params.value) |value| {
        const value_hex = try value.toHex(allocator);
        try obj.put("value", .{ .string = value_hex });
    }

    if (params.gas) |gas| {
        const gas_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{gas});
        try obj.put("gas", .{ .string = gas_hex });
    }

    if (params.gas_price) |gas_price| {
        const gp_hex = try gas_price.toHex(allocator);
        try obj.put("gasPrice", .{ .string = gp_hex });
    }

    if (params.nonce) |nonce| {
        const nonce_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{nonce});
        try obj.put("nonce", .{ .string = nonce_hex });
    }

    return JsonObjectWrapper{
        .value = .{ .object = obj },
        .allocator = allocator,
    };
}

/// Convert FilterOptions to JSON object
fn filterOptionsToJson(allocator: std.mem.Allocator, filter: types.FilterOptions) !JsonObjectWrapper {
    var obj = std.json.ObjectMap.init(allocator);

    if (filter.from_block) |from| {
        const from_str = try blockParameterToString(allocator, from);
        try obj.put("fromBlock", .{ .string = from_str });
    }

    if (filter.to_block) |to| {
        const to_str = try blockParameterToString(allocator, to);
        try obj.put("toBlock", .{ .string = to_str });
    }

    if (filter.address) |addr| {
        const addr_hex = try addr.toHex(allocator);
        try obj.put("address", .{ .string = addr_hex });
    }

    if (filter.topics) |topics| {
        var topics_array = std.json.Array.init(allocator);
        for (topics) |topic_opt| {
            if (topic_opt) |topic| {
                const topic_hex = try topic.toHex(allocator);
                try topics_array.append(.{ .string = topic_hex });
            } else {
                try topics_array.append(.null);
            }
        }
        try obj.put("topics", .{ .array = topics_array });
    }

    if (filter.block_hash) |hash| {
        const hash_hex = try hash.toHex(allocator);
        try obj.put("blockHash", .{ .string = hash_hex });
    }

    return JsonObjectWrapper{
        .value = .{ .object = obj },
        .allocator = allocator,
    };
}

test "eth namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const eth = EthNamespace.init(&client);
    try std.testing.expect(eth.client.endpoint.len > 0);
}

test "block parameter to string" {
    const allocator = std.testing.allocator;

    const latest = try blockParameterToString(allocator, .latest);
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("latest", latest);

    const number = try blockParameterToString(allocator, .{ .number = 12345 });
    defer allocator.free(number);
    try std.testing.expectEqualStrings("0x3039", number);
}

test "parse hex u64" {
    const value1 = try parseHexU64("0x10");
    try std.testing.expectEqual(@as(u64, 16), value1);

    const value2 = try parseHexU64("3039");
    try std.testing.expectEqual(@as(u64, 12345), value2);

    const value3 = try parseHexU64("0xff");
    try std.testing.expectEqual(@as(u64, 255), value3);
}

test "call params to json" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const params = types.CallParams{
        .to = addr,
        .from = null,
        .data = null,
        .value = null,
        .gas = 21000,
        .gas_price = null,
    };

    const json_obj = try callParamsToJson(allocator, params);
    defer json_obj.deinit();

    try std.testing.expect(json_obj.value == .object);
    try std.testing.expect(json_obj.value.object.contains("to"));
    try std.testing.expect(json_obj.value.object.contains("gas"));
}
