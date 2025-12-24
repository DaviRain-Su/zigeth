const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const Transaction = @import("../types/transaction.zig").Transaction;
const TransactionType = @import("../types/transaction.zig").TransactionType;
const PrivateKey = @import("../crypto/secp256k1.zig").PrivateKey;
const Signer = @import("../crypto/ecdsa.zig").Signer;
const TransactionSigner = @import("../crypto/ecdsa.zig").TransactionSigner;
const keccak = @import("../crypto/keccak.zig");
const RlpEthereumEncoder = @import("../rlp/packed.zig").TransactionEncoder;

/// Signing configuration
pub const SignerConfig = struct {
    chain_id: u64,
    use_eip155: bool,

    pub fn mainnet() SignerConfig {
        return .{ .chain_id = 1, .use_eip155 = true };
    }

    pub fn sepolia() SignerConfig {
        return .{ .chain_id = 11155111, .use_eip155 = true };
    }

    pub fn polygon() SignerConfig {
        return .{ .chain_id = 137, .use_eip155 = true };
    }

    pub fn arbitrum() SignerConfig {
        return .{ .chain_id = 42161, .use_eip155 = true };
    }

    pub fn optimism() SignerConfig {
        return .{ .chain_id = 10, .use_eip155 = true };
    }

    pub fn custom(chain_id: u64) SignerConfig {
        return .{ .chain_id = chain_id, .use_eip155 = true };
    }
};

/// Signer middleware for transaction signing
pub const SignerMiddleware = struct {
    private_key: PrivateKey,
    config: SignerConfig,
    signer: Signer,
    allocator: std.mem.Allocator,

    /// Create a new signer middleware
    pub fn init(allocator: std.mem.Allocator, private_key: PrivateKey, config: SignerConfig) !SignerMiddleware {
        const signer = Signer.init(private_key);

        return .{
            .private_key = private_key,
            .config = config,
            .signer = signer,
            .allocator = allocator,
        };
    }

    /// Get the address associated with this signer
    pub fn getAddress(self: *SignerMiddleware) !Address {
        return try self.signer.getAddress();
    }

    /// Sign a transaction
    pub fn signTransaction(self: *SignerMiddleware, tx: *Transaction) !Signature {
        // Set chain ID for EIP-155
        if (self.config.use_eip155) {
            tx.chain_id = self.config.chain_id;
        }

        // Get transaction hash based on type
        const tx_hash = try self.getTransactionHash(tx);

        // Sign the hash
        const sig = try self.signer.signHash(tx_hash);

        // For EIP-155, adjust v value
        if (self.config.use_eip155 and (tx.type == .legacy or tx.type == .eip2930)) {
            const v = @as(u8, @intCast(sig.getRecoveryId()));
            const eip155_v = Signature.eip155V(self.config.chain_id, v);
            return Signature.init(sig.r, sig.s, eip155_v);
        }

        return sig;
    }

    /// Get transaction hash for signing
    fn getTransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        switch (tx.type) {
            .legacy => {
                return try self.getLegacyTransactionHash(tx);
            },
            .eip2930 => {
                return try self.getEip2930TransactionHash(tx);
            },
            .eip1559 => {
                return try self.getEip1559TransactionHash(tx);
            },
            .eip4844 => {
                return try self.getEip4844TransactionHash(tx);
            },
            .eip7702 => {
                return try self.getEip7702TransactionHash(tx);
            },
        }
    }

    /// Get hash for legacy transaction (EIP-155 if enabled)
    fn getLegacyTransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // Use RLP TransactionEncoder for legacy transactions
        const encoded = try RlpEthereumEncoder.encodeLegacyForSigning(self.allocator, tx.*);
        defer self.allocator.free(encoded);

        return keccak.hash(encoded);
    }

    /// Get hash for EIP-2930 transaction
    fn getEip2930TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // Simplified: hash transaction data
        _ = self;
        const to_bytes = if (tx.to) |to_addr| to_addr.bytes else [_]u8{0} ** 20;
        return keccak.hash(&to_bytes);
    }

    /// Get hash for EIP-1559 transaction
    fn getEip1559TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // Simplified: hash transaction data
        _ = self;
        const to_bytes = if (tx.to) |to_addr| to_addr.bytes else [_]u8{0} ** 20;
        return keccak.hash(&to_bytes);
    }

    /// Get hash for EIP-4844 transaction
    fn getEip4844TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // Simplified: use EIP-1559 hash for now
        return try self.getEip1559TransactionHash(tx);
    }

    /// Get hash for EIP-7702 transaction
    fn getEip7702TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // Simplified: use EIP-1559 hash for now
        return try self.getEip1559TransactionHash(tx);
    }

    /// Sign and serialize transaction to raw bytes
    pub fn signAndSerialize(self: *SignerMiddleware, tx: *Transaction) ![]u8 {
        const sig = try self.signTransaction(tx);

        // TODO: Implement full transaction serialization with RLP
        // For now, return minimal serialized data as stub (includes signature info)
        // Transaction data (tx) would be included in full serialization
        var stub = try self.allocator.alloc(u8, 65);
        @memcpy(stub[0..32], &sig.r);
        @memcpy(stub[32..64], &sig.s);
        stub[64] = sig.v;

        return stub;
    }

    /// Serialize a signed transaction
    fn serializeSignedTransaction(self: *SignerMiddleware, tx: *Transaction) ![]u8 {
        _ = self;
        _ = tx;
        // TODO: Implement full RLP serialization
        return error.NotImplemented;
    }

    /// Sign a message
    pub fn signMessage(self: *SignerMiddleware, message: []const u8) !Signature {
        return try self.signer.signMessage(message);
    }

    /// Sign a personal message (with Ethereum prefix)
    pub fn signPersonalMessage(self: *SignerMiddleware, message: []const u8) !Signature {
        return try self.signer.signPersonalMessage(self.allocator, message);
    }

    /// Get chain ID
    pub fn getChainId(self: SignerMiddleware) u64 {
        return self.config.chain_id;
    }

    /// Check if EIP-155 is enabled
    pub fn isEip155Enabled(self: SignerMiddleware) bool {
        return self.config.use_eip155;
    }
};

// Tests
test "signer config mainnet" {
    const config = SignerConfig.mainnet();
    try std.testing.expectEqual(@as(u64, 1), config.chain_id);
    try std.testing.expect(config.use_eip155);
}

test "signer config sepolia" {
    const config = SignerConfig.sepolia();
    try std.testing.expectEqual(@as(u64, 11155111), config.chain_id);
    try std.testing.expect(config.use_eip155);
}

test "signer config custom" {
    const config = SignerConfig.custom(42);
    try std.testing.expectEqual(@as(u64, 42), config.chain_id);
    try std.testing.expect(config.use_eip155);
}

test "signer middleware creation" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const config = SignerConfig.mainnet();

    var middleware = try SignerMiddleware.init(allocator, private_key, config);

    try std.testing.expectEqual(@as(u64, 1), middleware.getChainId());
    try std.testing.expect(middleware.isEip155Enabled());
}

test "signer middleware get address" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const config = SignerConfig.mainnet();

    var middleware = try SignerMiddleware.init(allocator, private_key, config);

    const addr = try middleware.getAddress();
    try std.testing.expect(!addr.isZero());
}

test "signer middleware sign message" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const config = SignerConfig.mainnet();

    var middleware = try SignerMiddleware.init(allocator, private_key, config);

    const message = "Hello, Ethereum!";
    const sig = try middleware.signMessage(message);

    try std.testing.expect(sig.isValid());
}
