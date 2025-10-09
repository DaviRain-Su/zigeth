const std = @import("std");
const RpcClient = @import("../rpc/client.zig").RpcClient;
const EthNamespace = @import("../rpc/eth.zig").EthNamespace;
const NetNamespace = @import("../rpc/net.zig").NetNamespace;
const Web3Namespace = @import("../rpc/web3.zig").Web3Namespace;
const DebugNamespace = @import("../rpc/debug.zig").DebugNamespace;
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;
const Block = @import("../types/block.zig").Block;
const Transaction = @import("../types/transaction.zig").Transaction;
const Receipt = @import("../types/receipt.zig").Receipt;

/// Provider interface for Ethereum network access
pub const Provider = struct {
    rpc_client: RpcClient,
    eth: EthNamespace,
    net: NetNamespace,
    web3: Web3Namespace,
    debug: DebugNamespace,
    allocator: std.mem.Allocator,

    /// Initialize a new provider
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) !Provider {
        const rpc_client = try RpcClient.init(allocator, endpoint);
        var provider = Provider{
            .rpc_client = rpc_client,
            .eth = undefined,
            .net = undefined,
            .web3 = undefined,
            .debug = undefined,
            .allocator = allocator,
        };

        // Initialize namespaces with pointer to rpc_client
        provider.eth = EthNamespace.init(&provider.rpc_client);
        provider.net = NetNamespace.init(&provider.rpc_client);
        provider.web3 = Web3Namespace.init(&provider.rpc_client);
        provider.debug = DebugNamespace.init(&provider.rpc_client);

        return provider;
    }

    /// Free allocated memory
    pub fn deinit(self: Provider) void {
        self.rpc_client.deinit();
    }

    /// Get the endpoint URL
    pub fn getEndpoint(self: Provider) []const u8 {
        return self.rpc_client.endpoint;
    }

    /// Get current block number
    pub fn getBlockNumber(self: Provider) !u64 {
        return try self.eth.blockNumber();
    }

    /// Get account balance
    pub fn getBalance(self: Provider, address: Address) !U256 {
        return try self.eth.getBalance(address, .{ .tag = .latest });
    }

    /// Get transaction count (nonce)
    pub fn getTransactionCount(self: Provider, address: Address) !u64 {
        return try self.eth.getTransactionCount(address, .{ .tag = .latest });
    }

    /// Get contract code
    pub fn getCode(self: Provider, address: Address) ![]u8 {
        return try self.eth.getCode(address, .{ .tag = .latest });
    }

    /// Get chain ID
    pub fn getChainId(self: Provider) !u64 {
        return try self.eth.chainId();
    }

    /// Get network ID
    pub fn getNetworkId(self: Provider) !u64 {
        return try self.net.version();
    }

    /// Get gas price
    pub fn getGasPrice(self: Provider) !U256 {
        return try self.eth.gasPrice();
    }

    /// Get latest block
    pub fn getLatestBlock(self: Provider) !Block {
        return try self.eth.getBlockByNumber(.{ .tag = .latest }, false);
    }

    /// Get block by number
    pub fn getBlock(self: Provider, block_number: u64, full_tx: bool) !Block {
        return try self.eth.getBlockByNumber(.{ .number = block_number }, full_tx);
    }

    /// Get block by hash
    pub fn getBlockByHash(self: Provider, hash: Hash, full_tx: bool) !Block {
        return try self.eth.getBlockByHash(hash, full_tx);
    }

    /// Get transaction by hash
    pub fn getTransaction(self: Provider, hash: Hash) !Transaction {
        return try self.eth.getTransactionByHash(hash);
    }

    /// Get transaction receipt
    pub fn getTransactionReceipt(self: Provider, hash: Hash) !Receipt {
        return try self.eth.getTransactionReceipt(hash);
    }

    /// Send signed transaction
    pub fn sendTransaction(self: Provider, signed_tx: []const u8) !Hash {
        return try self.eth.sendRawTransaction(signed_tx);
    }

    /// Estimate gas for transaction
    pub fn estimateGas(self: Provider, params: @import("../rpc/types.zig").CallParams) !u64 {
        return try self.eth.estimateGas(params);
    }

    /// Wait for transaction to be mined
    pub fn waitForTransaction(
        self: Provider,
        tx_hash: Hash,
        timeout_ms: u64,
        poll_interval_ms: u64,
    ) !Receipt {
        const start_time = std.time.milliTimestamp();

        while (true) {
            // Try to get receipt
            const receipt = self.eth.getTransactionReceipt(tx_hash) catch |err| {
                if (err == error.ReceiptNotFound) {
                    // Check timeout
                    const elapsed = std.time.milliTimestamp() - start_time;
                    if (elapsed > timeout_ms) {
                        return error.TransactionTimeout;
                    }

                    // Wait before retrying
                    std.time.sleep(poll_interval_ms * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };

            return receipt;
        }
    }

    /// Check if address is a contract
    pub fn isContract(self: Provider, address: Address) !bool {
        const code = try self.getCode(address);
        defer self.allocator.free(code);
        return code.len > 0;
    }
};

test "provider creation" {
    const allocator = std.testing.allocator;

    const provider = try Provider.init(allocator, "http://localhost:8545");
    defer provider.deinit();

    try std.testing.expectEqualStrings("http://localhost:8545", provider.getEndpoint());
}

test "provider has all namespaces" {
    const allocator = std.testing.allocator;

    const provider = try Provider.init(allocator, "http://localhost:8545");
    defer provider.deinit();

    try std.testing.expect(provider.eth.client.endpoint.len > 0);
    try std.testing.expect(provider.net.client.endpoint.len > 0);
    try std.testing.expect(provider.web3.client.endpoint.len > 0);
    try std.testing.expect(provider.debug.client.endpoint.len > 0);
}
