const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Bloom = @import("../primitives/bloom.zig").Bloom;
const U256 = @import("../primitives/uint.zig").U256;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const Transaction = @import("./transaction.zig").Transaction;

/// Block header information
pub const BlockHeader = struct {
    /// Parent block hash
    parent_hash: Hash,

    /// Ommers/uncles hash (SHA3 of RLP encoded list of uncle headers)
    uncle_hash: Hash,

    /// Miner/beneficiary address
    miner: Address,

    /// State root
    state_root: Hash,

    /// Transactions root
    transactions_root: Hash,

    /// Receipts root
    receipts_root: Hash,

    /// Logs bloom filter
    logs_bloom: Bloom,

    /// Difficulty
    difficulty: U256,

    /// Block number
    number: u64,

    /// Gas limit
    gas_limit: u64,

    /// Gas used
    gas_used: u64,

    /// Block timestamp (Unix timestamp in seconds)
    timestamp: u64,

    /// Extra data
    extra_data: Bytes,

    /// Mix hash (for PoW)
    mix_hash: Hash,

    /// Nonce (for PoW)
    nonce: u64,

    /// Base fee per gas (EIP-1559, post-London)
    base_fee_per_gas: ?U256,

    /// Withdrawals root (post-Shanghai)
    withdrawals_root: ?Hash,

    /// Blob gas used (EIP-4844)
    blob_gas_used: ?u64,

    /// Excess blob gas (EIP-4844)
    excess_blob_gas: ?u64,

    /// Parent beacon block root (EIP-4788)
    parent_beacon_block_root: ?Hash,

    /// Calculate block hash (simplified - actual implementation would hash RLP-encoded header)
    pub fn calculateHash(self: BlockHeader, allocator: std.mem.Allocator) !Hash {
        _ = self;
        _ = allocator;
        // TODO: Implement proper RLP encoding and Keccak-256 hashing
        return Hash.zero();
    }

    /// Check if this is a post-merge block (PoS)
    pub fn isPostMerge(self: BlockHeader) bool {
        // Post-merge blocks have difficulty = 0
        return self.difficulty.isZero();
    }

    /// Check if this is a post-London block (has base fee)
    pub fn isPostLondon(self: BlockHeader) bool {
        return self.base_fee_per_gas != null;
    }

    /// Check if this is a post-Shanghai block (has withdrawals)
    pub fn isPostShanghai(self: BlockHeader) bool {
        return self.withdrawals_root != null;
    }
};

/// Ethereum block
pub const Block = struct {
    /// Block hash
    hash: Hash,

    /// Block header
    header: BlockHeader,

    /// Transactions in the block (can be full transactions or just hashes)
    transactions: []Transaction,

    /// Uncle blocks
    uncles: []Hash,

    /// Total difficulty up to this block
    total_difficulty: U256,

    /// Block size in bytes
    size: u64,

    allocator: std.mem.Allocator,

    /// Create a new block
    pub fn init(
        allocator: std.mem.Allocator,
        hash: Hash,
        header: BlockHeader,
        transactions: []const Transaction,
        uncles: []const Hash,
        total_difficulty: U256,
        size: u64,
    ) !Block {
        const transactions_copy = try allocator.dupe(Transaction, transactions);
        const uncles_copy = try allocator.dupe(Hash, uncles);

        return .{
            .hash = hash,
            .header = header,
            .transactions = transactions_copy,
            .uncles = uncles_copy,
            .total_difficulty = total_difficulty,
            .size = size,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: Block) void {
        if (self.transactions.len > 0) {
            self.allocator.free(self.transactions);
        }
        if (self.uncles.len > 0) {
            self.allocator.free(self.uncles);
        }
        self.header.extra_data.deinit();
    }

    /// Get block number
    pub fn getNumber(self: Block) u64 {
        return self.header.number;
    }

    /// Get block timestamp
    pub fn getTimestamp(self: Block) u64 {
        return self.header.timestamp;
    }

    /// Get number of transactions
    pub fn getTransactionCount(self: Block) usize {
        return self.transactions.len;
    }

    /// Get number of uncles
    pub fn getUncleCount(self: Block) usize {
        return self.uncles.len;
    }

    /// Check if block is empty (no transactions)
    pub fn isEmpty(self: Block) bool {
        return self.transactions.len == 0;
    }

    /// Calculate block reward (simplified - doesn't include uncle rewards)
    pub fn calculateBaseReward(self: Block) U256 {
        // Post-merge: no block reward
        if (self.header.isPostMerge()) {
            return U256.zero();
        }

        // Pre-merge block rewards:
        // Block 0-4,369,999: 5 ETH
        // Block 4,370,000-7,279,999: 3 ETH (Byzantium)
        // Block 7,280,000-onwards: 2 ETH (Constantinople)
        const block_num = self.header.number;

        if (block_num < 4_370_000) {
            return U256.fromInt(5_000_000_000_000_000_000); // 5 ETH
        } else if (block_num < 7_280_000) {
            return U256.fromInt(3_000_000_000_000_000_000); // 3 ETH
        } else {
            return U256.fromInt(2_000_000_000_000_000_000); // 2 ETH
        }
    }

    /// Get gas utilization percentage
    pub fn getGasUtilization(self: Block) f64 {
        if (self.header.gas_limit == 0) {
            return 0.0;
        }
        return (@as(f64, @floatFromInt(self.header.gas_used)) / @as(f64, @floatFromInt(self.header.gas_limit))) * 100.0;
    }

    /// Check if block is full (gas used >= gas limit)
    pub fn isFull(self: Block) bool {
        return self.header.gas_used >= self.header.gas_limit;
    }
};

test "block header post-merge detection" {
    const header = BlockHeader{
        .parent_hash = Hash.zero(),
        .uncle_hash = Hash.zero(),
        .miner = Address.fromBytes([_]u8{0} ** 20),
        .state_root = Hash.zero(),
        .transactions_root = Hash.zero(),
        .receipts_root = Hash.zero(),
        .logs_bloom = Bloom.empty(),
        .difficulty = U256.zero(), // Post-merge: difficulty = 0
        .number = 15537394,
        .gas_limit = 30000000,
        .gas_used = 15000000,
        .timestamp = 1663224162,
        .extra_data = Bytes.empty(std.testing.allocator),
        .mix_hash = Hash.zero(),
        .nonce = 0,
        .base_fee_per_gas = U256.fromInt(15000000000),
        .withdrawals_root = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
        .parent_beacon_block_root = null,
    };
    defer header.extra_data.deinit();

    try std.testing.expect(header.isPostMerge());
    try std.testing.expect(header.isPostLondon());
    try std.testing.expect(!header.isPostShanghai());
}

test "block creation" {
    const allocator = std.testing.allocator;

    const hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const header = BlockHeader{
        .parent_hash = Hash.zero(),
        .uncle_hash = Hash.zero(),
        .miner = Address.fromBytes([_]u8{0x12} ** 20),
        .state_root = Hash.zero(),
        .transactions_root = Hash.zero(),
        .receipts_root = Hash.zero(),
        .logs_bloom = Bloom.empty(),
        .difficulty = U256.fromInt(1000000),
        .number = 12345,
        .gas_limit = 30000000,
        .gas_used = 15000000,
        .timestamp = 1663224162,
        .extra_data = Bytes.empty(allocator),
        .mix_hash = Hash.zero(),
        .nonce = 12345678,
        .base_fee_per_gas = null,
        .withdrawals_root = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
        .parent_beacon_block_root = null,
    };

    const block = try Block.init(
        allocator,
        hash,
        header,
        &[_]Transaction{}, // no transactions
        &[_]Hash{}, // no uncles
        U256.fromInt(5000000),
        1024,
    );
    defer block.deinit();

    try std.testing.expectEqual(@as(u64, 12345), block.getNumber());
    try std.testing.expect(block.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), block.getTransactionCount());
}

test "block gas utilization" {
    const allocator = std.testing.allocator;

    const hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const header = BlockHeader{
        .parent_hash = Hash.zero(),
        .uncle_hash = Hash.zero(),
        .miner = Address.fromBytes([_]u8{0x12} ** 20),
        .state_root = Hash.zero(),
        .transactions_root = Hash.zero(),
        .receipts_root = Hash.zero(),
        .logs_bloom = Bloom.empty(),
        .difficulty = U256.fromInt(1000000),
        .number = 12345,
        .gas_limit = 30000000,
        .gas_used = 15000000, // 50% utilization
        .timestamp = 1663224162,
        .extra_data = Bytes.empty(allocator),
        .mix_hash = Hash.zero(),
        .nonce = 12345678,
        .base_fee_per_gas = null,
        .withdrawals_root = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
        .parent_beacon_block_root = null,
    };

    const block = try Block.init(
        allocator,
        hash,
        header,
        &[_]Transaction{},
        &[_]Hash{},
        U256.fromInt(5000000),
        1024,
    );
    defer block.deinit();

    const utilization = block.getGasUtilization();
    try std.testing.expectApproxEqRel(50.0, utilization, 0.01);
    try std.testing.expect(!block.isFull());
}

test "block reward calculation" {
    const allocator = std.testing.allocator;

    // Pre-merge block (block 1000000, should get 5 ETH)
    const hash = Hash.fromBytes([_]u8{0x01} ** 32);
    const header = BlockHeader{
        .parent_hash = Hash.zero(),
        .uncle_hash = Hash.zero(),
        .miner = Address.fromBytes([_]u8{0x12} ** 20),
        .state_root = Hash.zero(),
        .transactions_root = Hash.zero(),
        .receipts_root = Hash.zero(),
        .logs_bloom = Bloom.empty(),
        .difficulty = U256.fromInt(1000000), // Non-zero difficulty
        .number = 1000000,
        .gas_limit = 30000000,
        .gas_used = 15000000,
        .timestamp = 1663224162,
        .extra_data = Bytes.empty(allocator),
        .mix_hash = Hash.zero(),
        .nonce = 12345678,
        .base_fee_per_gas = null,
        .withdrawals_root = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
        .parent_beacon_block_root = null,
    };

    const block = try Block.init(
        allocator,
        hash,
        header,
        &[_]Transaction{},
        &[_]Hash{},
        U256.fromInt(5000000),
        1024,
    );
    defer block.deinit();

    const reward = block.calculateBaseReward();
    try std.testing.expect(reward.eql(U256.fromInt(5_000_000_000_000_000_000)));
}
