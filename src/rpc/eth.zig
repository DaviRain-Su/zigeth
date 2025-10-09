const std = @import("std");
const RpcClient = @import("./client.zig").RpcClient;
const types = @import("./types.zig");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;
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
        _ = result;
        // TODO: Parse JSON result
        return error.NotImplemented;
    }

    /// eth_getBalance - Returns the balance of an account
    pub fn getBalance(self: EthNamespace, address: Address, block: types.BlockParameter) !U256 {
        _ = self;
        _ = address;
        _ = block;
        // TODO: Implement
        return error.NotImplemented;
    }

    /// eth_getTransactionCount - Returns the number of transactions sent from an address
    pub fn getTransactionCount(self: EthNamespace, address: Address, block: types.BlockParameter) !u64 {
        _ = self;
        _ = address;
        _ = block;
        return error.NotImplemented;
    }

    /// eth_getBlockByNumber - Returns information about a block by number
    pub fn getBlockByNumber(self: EthNamespace, block: types.BlockParameter, full_tx: bool) !Block {
        _ = self;
        _ = block;
        _ = full_tx;
        return error.NotImplemented;
    }

    /// eth_getBlockByHash - Returns information about a block by hash
    pub fn getBlockByHash(self: EthNamespace, hash: Hash, full_tx: bool) !Block {
        _ = self;
        _ = hash;
        _ = full_tx;
        return error.NotImplemented;
    }

    /// eth_getTransactionByHash - Returns a transaction by hash
    pub fn getTransactionByHash(self: EthNamespace, hash: Hash) !Transaction {
        _ = self;
        _ = hash;
        return error.NotImplemented;
    }

    /// eth_getTransactionReceipt - Returns the receipt of a transaction
    pub fn getTransactionReceipt(self: EthNamespace, hash: Hash) !Receipt {
        _ = self;
        _ = hash;
        return error.NotImplemented;
    }

    /// eth_call - Executes a message call (doesn't create a transaction)
    pub fn call(self: EthNamespace, params: types.CallParams, block: types.BlockParameter) ![]u8 {
        _ = self;
        _ = params;
        _ = block;
        return error.NotImplemented;
    }

    /// eth_estimateGas - Estimates gas needed for a transaction
    pub fn estimateGas(self: EthNamespace, params: types.CallParams) !u64 {
        _ = self;
        _ = params;
        return error.NotImplemented;
    }

    /// eth_gasPrice - Returns the current gas price in wei
    pub fn gasPrice(self: EthNamespace) !U256 {
        _ = self;
        return error.NotImplemented;
    }

    /// eth_maxPriorityFeePerGas - Returns the current max priority fee per gas
    pub fn maxPriorityFeePerGas(self: EthNamespace) !U256 {
        _ = self;
        return error.NotImplemented;
    }

    /// eth_feeHistory - Returns historical gas information
    pub fn feeHistory(
        self: EthNamespace,
        block_count: u64,
        newest_block: types.BlockParameter,
        reward_percentiles: ?[]const f64,
    ) !types.FeeHistory {
        _ = self;
        _ = block_count;
        _ = newest_block;
        _ = reward_percentiles;
        return error.NotImplemented;
    }

    /// eth_getCode - Returns code at a given address
    pub fn getCode(self: EthNamespace, address: Address, block: types.BlockParameter) ![]u8 {
        _ = self;
        _ = address;
        _ = block;
        return error.NotImplemented;
    }

    /// eth_getStorageAt - Returns the value from a storage position
    pub fn getStorageAt(self: EthNamespace, address: Address, position: U256, block: types.BlockParameter) !Hash {
        _ = self;
        _ = address;
        _ = position;
        _ = block;
        return error.NotImplemented;
    }

    /// eth_getLogs - Returns an array of logs matching the filter
    pub fn getLogs(self: EthNamespace, filter: types.FilterOptions) ![]Log {
        _ = self;
        _ = filter;
        return error.NotImplemented;
    }

    /// eth_sendRawTransaction - Sends a signed transaction
    pub fn sendRawTransaction(self: EthNamespace, signed_tx: []const u8) !Hash {
        _ = self;
        _ = signed_tx;
        return error.NotImplemented;
    }

    /// eth_sendTransaction - Creates and sends a transaction
    pub fn sendTransaction(self: EthNamespace, params: types.TransactionParams) !Hash {
        _ = self;
        _ = params;
        return error.NotImplemented;
    }

    /// eth_chainId - Returns the chain ID
    pub fn chainId(self: EthNamespace) !u64 {
        _ = self;
        return error.NotImplemented;
    }

    /// eth_syncing - Returns sync status
    pub fn syncing(self: EthNamespace) !types.SyncStatus {
        _ = self;
        return error.NotImplemented;
    }

    /// eth_getBlockTransactionCountByHash - Returns the number of transactions in a block
    pub fn getBlockTransactionCountByHash(self: EthNamespace, hash: Hash) !u64 {
        _ = self;
        _ = hash;
        return error.NotImplemented;
    }

    /// eth_getBlockTransactionCountByNumber - Returns the number of transactions in a block
    pub fn getBlockTransactionCountByNumber(self: EthNamespace, block: types.BlockParameter) !u64 {
        _ = self;
        _ = block;
        return error.NotImplemented;
    }

    /// eth_getUncleCountByBlockHash - Returns the number of uncles in a block
    pub fn getUncleCountByBlockHash(self: EthNamespace, hash: Hash) !u64 {
        _ = self;
        _ = hash;
        return error.NotImplemented;
    }

    /// eth_getUncleCountByBlockNumber - Returns the number of uncles in a block
    pub fn getUncleCountByBlockNumber(self: EthNamespace, block: types.BlockParameter) !u64 {
        _ = self;
        _ = block;
        return error.NotImplemented;
    }

    /// eth_accounts - Returns list of addresses owned by client
    pub fn accounts(self: EthNamespace) ![]Address {
        _ = self;
        return error.NotImplemented;
    }

    /// eth_sign - Signs data with an address
    pub fn sign(self: EthNamespace, address: Address, data: []const u8) ![]u8 {
        _ = self;
        _ = address;
        _ = data;
        return error.NotImplemented;
    }

    /// eth_signTransaction - Signs a transaction
    pub fn signTransaction(self: EthNamespace, params: types.TransactionParams) ![]u8 {
        _ = self;
        _ = params;
        return error.NotImplemented;
    }
};

test "eth namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const eth = EthNamespace.init(&client);
    try std.testing.expect(eth.client.endpoint.len > 0);
}
