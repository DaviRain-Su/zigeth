const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Bloom = @import("../primitives/bloom.zig").Bloom;
const Log = @import("./log.zig").Log;

/// Transaction execution status
pub const TransactionStatus = enum(u8) {
    /// Transaction failed
    failed = 0,
    /// Transaction succeeded
    success = 1,
};

/// Transaction receipt
pub const Receipt = struct {
    /// Transaction hash
    transaction_hash: Hash,

    /// Transaction index in the block
    transaction_index: u64,

    /// Block hash where this transaction was included
    block_hash: Hash,

    /// Block number where this transaction was included
    block_number: u64,

    /// Sender address
    from: Address,

    /// Recipient address (null for contract creation)
    to: ?Address,

    /// Cumulative gas used in the block up to and including this transaction
    cumulative_gas_used: u64,

    /// Gas used by this transaction alone
    gas_used: u64,

    /// Effective gas price paid
    effective_gas_price: u256,

    /// Contract address created (if contract creation transaction)
    contract_address: ?Address,

    /// Logs emitted by the transaction
    logs: []Log,

    /// Logs bloom filter
    logs_bloom: Bloom,

    /// Transaction type
    transaction_type: u8,

    /// Execution status (post-Byzantium)
    status: ?TransactionStatus,

    /// Root hash (pre-Byzantium)
    root: ?Hash,

    allocator: std.mem.Allocator,

    /// Create a new receipt
    pub fn init(
        allocator: std.mem.Allocator,
        transaction_hash: Hash,
        transaction_index: u64,
        block_hash: Hash,
        block_number: u64,
        from: Address,
        to: ?Address,
        cumulative_gas_used: u64,
        gas_used: u64,
        effective_gas_price: u256,
        logs: []const Log,
        logs_bloom: Bloom,
        status: TransactionStatus,
    ) !Receipt {
        const logs_copy = try allocator.dupe(Log, logs);

        return .{
            .transaction_hash = transaction_hash,
            .transaction_index = transaction_index,
            .block_hash = block_hash,
            .block_number = block_number,
            .from = from,
            .to = to,
            .cumulative_gas_used = cumulative_gas_used,
            .gas_used = gas_used,
            .effective_gas_price = effective_gas_price,
            .contract_address = null,
            .logs = logs_copy,
            .logs_bloom = logs_bloom,
            .transaction_type = 0,
            .status = status,
            .root = null,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: Receipt) void {
        if (self.logs.len > 0) {
            // Note: Individual logs should be managed separately
            self.allocator.free(self.logs);
        }
    }

    /// Check if transaction was successful
    pub fn isSuccess(self: Receipt) bool {
        if (self.status) |status| {
            return status == .success;
        }
        // Pre-Byzantium: check if root exists (no status field)
        return self.root != null;
    }

    /// Check if transaction failed
    pub fn isFailed(self: Receipt) bool {
        return !self.isSuccess();
    }

    /// Check if this is a contract creation receipt
    pub fn isContractCreation(self: Receipt) bool {
        return self.contract_address != null;
    }

    /// Get number of logs
    pub fn getLogCount(self: Receipt) usize {
        return self.logs.len;
    }

    /// Calculate transaction fee (gas_used * effective_gas_price)
    pub fn calculateFee(self: Receipt) u256 {
        return self.effective_gas_price * self.gas_used;
    }

    /// Check if receipt contains logs from a specific address
    pub fn hasLogsFrom(self: Receipt, address: Address) bool {
        for (self.logs) |log| {
            if (std.mem.eql(u8, &log.address.bytes, &address.bytes)) {
                return true;
            }
        }
        return false;
    }

    /// Get logs from a specific address
    pub fn getLogsFrom(self: Receipt, allocator: std.mem.Allocator, address: Address) ![]Log {
        var matching_logs = std.ArrayList(Log).init(allocator);
        defer matching_logs.deinit();

        for (self.logs) |log| {
            if (std.mem.eql(u8, &log.address.bytes, &address.bytes)) {
                try matching_logs.append(log);
            }
        }

        return matching_logs.toOwnedSlice();
    }
};

test "receipt creation" {
    const allocator = std.testing.allocator;

    const tx_hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const block_hash = Hash.fromBytes([_]u8{0x02} ** 32);
    const from = Address.fromBytes([_]u8{0x03} ** 20);
    const to = Address.fromBytes([_]u8{0x04} ** 20);

    const receipt = try Receipt.init(
        allocator,
        tx_hash,
        0, // tx_index
        block_hash,
        12345, // block_number
        from,
        to,
        21000, // cumulative_gas_used
        21000, // gas_used
        @as(u256, 20000000000), // effective_gas_price
        &[_]Log{}, // no logs
        Bloom.empty(),
        .success,
    );
    defer receipt.deinit();

    try std.testing.expect(receipt.isSuccess());
    try std.testing.expect(!receipt.isFailed());
    try std.testing.expectEqual(@as(u64, 12345), receipt.block_number);
}

test "receipt transaction fee" {
    const allocator = std.testing.allocator;

    const tx_hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const block_hash = Hash.fromBytes([_]u8{0x02} ** 32);
    const from = Address.fromBytes([_]u8{0x03} ** 20);

    const receipt = try Receipt.init(
        allocator,
        tx_hash,
        0,
        block_hash,
        12345,
        from,
        null,
        21000,
        21000,
        @as(u256, 20000000000), // 20 gwei
        &[_]Log{},
        Bloom.empty(),
        .success,
    );
    defer receipt.deinit();

    const fee = receipt.calculateFee();
    // 21000 * 20000000000 = 420000000000000
    try std.testing.expectEqual(@as(u256, 420000000000000), fee);
}

test "receipt success and failure" {
    const allocator = std.testing.allocator;

    const tx_hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const block_hash = Hash.fromBytes([_]u8{0x02} ** 32);
    const from = Address.fromBytes([_]u8{0x03} ** 20);

    // Successful transaction
    const success_receipt = try Receipt.init(
        allocator,
        tx_hash,
        0,
        block_hash,
        12345,
        from,
        null,
        21000,
        21000,
        @as(u256, 20000000000),
        &[_]Log{},
        Bloom.empty(),
        .success,
    );
    defer success_receipt.deinit();

    try std.testing.expect(success_receipt.isSuccess());
    try std.testing.expect(!success_receipt.isFailed());

    // Failed transaction
    const failed_receipt = try Receipt.init(
        allocator,
        tx_hash,
        0,
        block_hash,
        12345,
        from,
        null,
        21000,
        21000,
        @as(u256, 20000000000),
        &[_]Log{},
        Bloom.empty(),
        .failed,
    );
    defer failed_receipt.deinit();

    try std.testing.expect(!failed_receipt.isSuccess());
    try std.testing.expect(failed_receipt.isFailed());
}

test "receipt contract creation" {
    const allocator = std.testing.allocator;

    const tx_hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const block_hash = Hash.fromBytes([_]u8{0x02} ** 32);
    const from = Address.fromBytes([_]u8{0x03} ** 20);
    const contract_addr = Address.fromBytes([_]u8{0x05} ** 20);

    var receipt = try Receipt.init(
        allocator,
        tx_hash,
        0,
        block_hash,
        12345,
        from,
        null, // no 'to' for contract creation
        100000,
        100000,
        @as(u256, 20000000000),
        &[_]Log{},
        Bloom.empty(),
        .success,
    );
    defer receipt.deinit();

    try std.testing.expect(!receipt.isContractCreation());

    receipt.contract_address = contract_addr;
    try std.testing.expect(receipt.isContractCreation());
}
