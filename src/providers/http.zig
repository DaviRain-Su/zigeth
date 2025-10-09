const std = @import("std");
const Provider = @import("./provider.zig").Provider;

/// HTTP provider for Ethereum
pub const HttpProvider = struct {
    provider: Provider,

    /// Create a new HTTP provider
    pub fn init(allocator: std.mem.Allocator, url: []const u8) !HttpProvider {
        const provider = try Provider.init(allocator, url);
        return .{ .provider = provider };
    }

    /// Free allocated memory
    pub fn deinit(self: HttpProvider) void {
        self.provider.deinit();
    }

    /// Get the underlying provider
    pub fn getProvider(self: *HttpProvider) *Provider {
        return @constCast(&self.provider);
    }

    /// Common provider methods (convenience wrappers)
    pub fn getBlockNumber(self: HttpProvider) !u64 {
        return try self.provider.getBlockNumber();
    }

    pub fn getBalance(self: HttpProvider, address: @import("../primitives/address.zig").Address) !@import("../primitives/uint.zig").U256 {
        return try self.provider.getBalance(address);
    }

    pub fn getChainId(self: HttpProvider) !u64 {
        return try self.provider.getChainId();
    }

    pub fn getTransactionCount(self: HttpProvider, address: @import("../primitives/address.zig").Address) !u64 {
        return try self.provider.getTransactionCount(address);
    }

    pub fn getGasPrice(self: HttpProvider) !@import("../primitives/uint.zig").U256 {
        return try self.provider.getGasPrice();
    }

    pub fn getLatestBlock(self: HttpProvider) !@import("../types/block.zig").Block {
        return try self.provider.getLatestBlock();
    }

    pub fn getTransaction(self: HttpProvider, hash: @import("../primitives/hash.zig").Hash) !@import("../types/transaction.zig").Transaction {
        return try self.provider.getTransaction(hash);
    }

    pub fn getTransactionReceipt(self: HttpProvider, hash: @import("../primitives/hash.zig").Hash) !@import("../types/receipt.zig").Receipt {
        return try self.provider.getTransactionReceipt(hash);
    }

    pub fn sendTransaction(self: HttpProvider, signed_tx: []const u8) !@import("../primitives/hash.zig").Hash {
        return try self.provider.sendTransaction(signed_tx);
    }

    pub fn waitForTransaction(
        self: HttpProvider,
        tx_hash: @import("../primitives/hash.zig").Hash,
        timeout_ms: u64,
    ) !@import("../types/receipt.zig").Receipt {
        return try self.provider.waitForTransaction(tx_hash, timeout_ms, 1000);
    }

    pub fn isContract(self: HttpProvider, address: @import("../primitives/address.zig").Address) !bool {
        return try self.provider.isContract(address);
    }
};

/// Create HTTP provider for common networks
pub const Networks = struct {
    /// Ethereum mainnet (Etherspot RPC v2 - Chain ID: 1)
    pub fn mainnet(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "https://rpc.etherspot.io/v2/1?api-key=etherspot_3ZSiRBeAjmYnJu1bCsaRXjeD");
    }

    /// Ethereum Sepolia testnet (Etherspot RPC v2 - Chain ID: 11155111)
    pub fn sepolia(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "https://rpc.etherspot.io/v2/11155111?api-key=etherspot_3ZSiRBeAjmYnJu1bCsaRXjeD");
    }

    /// Polygon mainnet (Etherspot RPC v2 - Chain ID: 137)
    pub fn polygon(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "https://rpc.etherspot.io/v2/137?api-key=etherspot_3ZSiRBeAjmYnJu1bCsaRXjeD");
    }

    /// Arbitrum mainnet (Etherspot RPC v2 - Chain ID: 42161)
    pub fn arbitrum(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "https://rpc.etherspot.io/v2/42161?api-key=etherspot_3ZSiRBeAjmYnJu1bCsaRXjeD");
    }

    /// Optimism mainnet (Etherspot RPC v2 - Chain ID: 10)
    pub fn optimism(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "https://rpc.etherspot.io/v2/10?api-key=etherspot_3ZSiRBeAjmYnJu1bCsaRXjeD");
    }

    /// Base mainnet (Etherspot RPC v2 - Chain ID: 8453)
    pub fn base(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "https://rpc.etherspot.io/v2/8453?api-key=etherspot_3ZSiRBeAjmYnJu1bCsaRXjeD");
    }

    /// Local development node
    pub fn localhost(allocator: std.mem.Allocator) !HttpProvider {
        return try HttpProvider.init(allocator, "http://localhost:8545");
    }

    /// Custom endpoint
    pub fn custom(allocator: std.mem.Allocator, url: []const u8) !HttpProvider {
        return try HttpProvider.init(allocator, url);
    }
};

test "http provider creation" {
    const allocator = std.testing.allocator;

    const provider = try HttpProvider.init(allocator, "http://localhost:8545");
    defer provider.deinit();

    try std.testing.expectEqualStrings("http://localhost:8545", provider.provider.getEndpoint());
}

test "http provider networks" {
    const allocator = std.testing.allocator;

    const mainnet = try Networks.mainnet(allocator);
    defer mainnet.deinit();
    try std.testing.expect(std.mem.indexOf(u8, mainnet.provider.getEndpoint(), "etherspot.io/v2/1") != null);

    const sepolia = try Networks.sepolia(allocator);
    defer sepolia.deinit();
    try std.testing.expect(std.mem.indexOf(u8, sepolia.provider.getEndpoint(), "etherspot.io/v2/11155111") != null);

    const polygon = try Networks.polygon(allocator);
    defer polygon.deinit();
    try std.testing.expect(std.mem.indexOf(u8, polygon.provider.getEndpoint(), "etherspot.io/v2/137") != null);

    const localhost = try Networks.localhost(allocator);
    defer localhost.deinit();
    try std.testing.expectEqualStrings("http://localhost:8545", localhost.provider.getEndpoint());
}

test "http provider get provider" {
    const allocator = std.testing.allocator;

    var http_provider = try HttpProvider.init(allocator, "http://localhost:8545");
    defer http_provider.deinit();

    const provider = http_provider.getProvider();
    try std.testing.expect(provider.rpc_client.endpoint.len > 0);
}
