const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Block = @import("../types/block.zig").Block;
const Transaction = @import("../types/transaction.zig").Transaction;
const Receipt = @import("../types/receipt.zig").Receipt;

/// Mock provider for testing (returns pre-configured responses)
pub const MockProvider = struct {
    allocator: std.mem.Allocator,
    chain_id: u64,
    block_number: u64,
    balances: std.AutoHashMap(Address, u256),
    transactions: std.AutoHashMap(Hash, Transaction),
    receipts: std.AutoHashMap(Hash, Receipt),
    gas_price: u256,

    /// Create a new mock provider
    pub fn init(allocator: std.mem.Allocator) MockProvider {
        return .{
            .allocator = allocator,
            .chain_id = 1,
            .block_number = 1000000,
            .balances = std.AutoHashMap(Address, u256).init(allocator),
            .transactions = std.AutoHashMap(Hash, Transaction).init(allocator),
            .receipts = std.AutoHashMap(Hash, Receipt).init(allocator),
            .gas_price = 30_000_000_000, // 30 gwei
        };
    }

    /// Free allocated memory
    pub fn deinit(self: *MockProvider) void {
        self.balances.deinit();

        var tx_it = self.transactions.iterator();
        while (tx_it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.transactions.deinit();

        var receipt_it = self.receipts.iterator();
        while (receipt_it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.receipts.deinit();
    }

    /// Set chain ID
    pub fn setChainId(self: *MockProvider, chain_id: u64) void {
        self.chain_id = chain_id;
    }

    /// Set current block number
    pub fn setBlockNumber(self: *MockProvider, block_number: u64) void {
        self.block_number = block_number;
    }

    /// Set balance for an address
    pub fn setBalance(self: *MockProvider, address: Address, balance: u256) !void {
        try self.balances.put(address, balance);
    }

    /// Add a transaction
    pub fn addTransaction(self: *MockProvider, hash: Hash, tx: Transaction) !void {
        try self.transactions.put(hash, tx);
    }

    /// Add a receipt
    pub fn addReceipt(self: *MockProvider, hash: Hash, receipt: Receipt) !void {
        try self.receipts.put(hash, receipt);
    }

    /// Set gas price
    pub fn setGasPrice(self: *MockProvider, gas_price: u256) void {
        self.gas_price = gas_price;
    }

    /// Mock implementations
    pub fn getChainId(self: MockProvider) !u64 {
        return self.chain_id;
    }

    pub fn getBlockNumber(self: MockProvider) !u64 {
        return self.block_number;
    }

    pub fn getBalance(self: MockProvider, address: Address) !u256 {
        return self.balances.get(address) orelse 0;
    }

    pub fn getTransaction(self: MockProvider, hash: Hash) !Transaction {
        return self.transactions.get(hash) orelse error.TransactionNotFound;
    }

    pub fn getTransactionReceipt(self: MockProvider, hash: Hash) !Receipt {
        return self.receipts.get(hash) orelse error.ReceiptNotFound;
    }

    pub fn getGasPrice(self: MockProvider) !u256 {
        return self.gas_price;
    }

    /// Increment block number (simulate mining)
    pub fn mineBlock(self: *MockProvider) void {
        self.block_number += 1;
    }

    /// Reset to initial state
    pub fn reset(self: *MockProvider) void {
        self.balances.clearAndFree();
        self.transactions.clearAndFree();
        self.receipts.clearAndFree();
        self.block_number = 1000000;
        self.chain_id = 1;
        self.gas_price = 30_000_000_000;
    }
};

test "mock provider creation" {
    const allocator = std.testing.allocator;

    var provider = MockProvider.init(allocator);
    defer provider.deinit();

    const chain_id = try provider.getChainId();
    try std.testing.expectEqual(@as(u64, 1), chain_id);

    const block_num = try provider.getBlockNumber();
    try std.testing.expectEqual(@as(u64, 1000000), block_num);
}

test "mock provider set balance" {
    const allocator = std.testing.allocator;

    var provider = MockProvider.init(allocator);
    defer provider.deinit();

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const balance: u256 = 1_000_000_000_000_000_000; // 1 ETH

    try provider.setBalance(addr, balance);

    const retrieved = try provider.getBalance(addr);
    try std.testing.expectEqual(balance, retrieved);
}

test "mock provider mine block" {
    const allocator = std.testing.allocator;

    var provider = MockProvider.init(allocator);
    defer provider.deinit();

    const initial = try provider.getBlockNumber();
    provider.mineBlock();
    const after = try provider.getBlockNumber();

    try std.testing.expectEqual(initial + 1, after);
}

test "mock provider gas price" {
    const allocator = std.testing.allocator;

    var provider = MockProvider.init(allocator);
    defer provider.deinit();

    const custom_price: u256 = 50_000_000_000; // 50 gwei
    provider.setGasPrice(custom_price);

    const price = try provider.getGasPrice();
    try std.testing.expectEqual(custom_price, price);
}

test "mock provider reset" {
    const allocator = std.testing.allocator;

    var provider = MockProvider.init(allocator);
    defer provider.deinit();

    // Set some state
    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    try provider.setBalance(addr, 1000);
    provider.setBlockNumber(2000000);

    // Reset
    provider.reset();

    // Check state is reset
    const block_num = try provider.getBlockNumber();
    try std.testing.expectEqual(@as(u64, 1000000), block_num);

    const balance = try provider.getBalance(addr);
    try std.testing.expectEqual(@as(u256, 0), balance);
}
