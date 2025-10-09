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
const RlpEncoder = @import("../rlp/encode.zig").Encoder;
const RlpItem = @import("../rlp/encode.zig").RlpItem;

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
        const sig = try self.signer.signHash(tx_hash.bytes);

        // For EIP-155, adjust v value
        if (self.config.use_eip155 and (tx.transaction_type == .legacy or tx.transaction_type == .eip2930)) {
            const v = sig.getRecoveryId();
            const eip155_v = Signature.eip155V(v, self.config.chain_id);
            return Signature.init(sig.r, sig.s, eip155_v);
        }

        return sig;
    }

    /// Get transaction hash for signing
    fn getTransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        switch (tx.transaction_type) {
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
        var encoder = RlpEncoder.init(self.allocator);
        defer encoder.deinit();

        // Encode transaction fields
        try encoder.startList();
        try encoder.appendItem(.{ .uint = tx.nonce });
        try encoder.appendItem(.{ .uint = tx.gas_price.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.gas_limit });

        if (tx.to) |to_addr| {
            try encoder.appendItem(.{ .bytes = &to_addr.bytes });
        } else {
            try encoder.appendItem(.{ .bytes = &[_]u8{} });
        }

        try encoder.appendItem(.{ .uint = tx.value.toU64() catch 0 });
        try encoder.appendItem(.{ .bytes = tx.data });

        // EIP-155: add chain_id, 0, 0
        if (self.config.use_eip155) {
            try encoder.appendItem(.{ .uint = self.config.chain_id });
            try encoder.appendItem(.{ .uint = 0 });
            try encoder.appendItem(.{ .uint = 0 });
        }

        const encoded = try encoder.finish();
        defer self.allocator.free(encoded);

        return keccak.hash(encoded);
    }

    /// Get hash for EIP-2930 transaction
    fn getEip2930TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        var encoder = RlpEncoder.init(self.allocator);
        defer encoder.deinit();

        try encoder.startList();
        try encoder.appendItem(.{ .uint = self.config.chain_id });
        try encoder.appendItem(.{ .uint = tx.nonce });
        try encoder.appendItem(.{ .uint = tx.gas_price.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.gas_limit });

        if (tx.to) |to_addr| {
            try encoder.appendItem(.{ .bytes = &to_addr.bytes });
        } else {
            try encoder.appendItem(.{ .bytes = &[_]u8{} });
        }

        try encoder.appendItem(.{ .uint = tx.value.toU64() catch 0 });
        try encoder.appendItem(.{ .bytes = tx.data });

        // TODO: Encode access list properly
        try encoder.appendItem(.{ .list = &[_]RlpItem{} });

        const encoded = try encoder.finish();
        defer self.allocator.free(encoded);

        // Prepend transaction type
        var type_prefixed = try self.allocator.alloc(u8, encoded.len + 1);
        defer self.allocator.free(type_prefixed);
        type_prefixed[0] = 0x01; // EIP-2930 type
        @memcpy(type_prefixed[1..], encoded);

        return keccak.hash(type_prefixed);
    }

    /// Get hash for EIP-1559 transaction
    fn getEip1559TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        var encoder = RlpEncoder.init(self.allocator);
        defer encoder.deinit();

        try encoder.startList();
        try encoder.appendItem(.{ .uint = self.config.chain_id });
        try encoder.appendItem(.{ .uint = tx.nonce });
        try encoder.appendItem(.{ .uint = tx.max_priority_fee_per_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.max_fee_per_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.gas_limit });

        if (tx.to) |to_addr| {
            try encoder.appendItem(.{ .bytes = &to_addr.bytes });
        } else {
            try encoder.appendItem(.{ .bytes = &[_]u8{} });
        }

        try encoder.appendItem(.{ .uint = tx.value.toU64() catch 0 });
        try encoder.appendItem(.{ .bytes = tx.data });

        // TODO: Encode access list properly
        try encoder.appendItem(.{ .list = &[_]RlpItem{} });

        const encoded = try encoder.finish();
        defer self.allocator.free(encoded);

        // Prepend transaction type
        var type_prefixed = try self.allocator.alloc(u8, encoded.len + 1);
        defer self.allocator.free(type_prefixed);
        type_prefixed[0] = 0x02; // EIP-1559 type
        @memcpy(type_prefixed[1..], encoded);

        return keccak.hash(type_prefixed);
    }

    /// Get hash for EIP-4844 transaction
    fn getEip4844TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // EIP-4844 uses similar structure to EIP-1559 with blob fields
        var encoder = RlpEncoder.init(self.allocator);
        defer encoder.deinit();

        try encoder.startList();
        try encoder.appendItem(.{ .uint = self.config.chain_id });
        try encoder.appendItem(.{ .uint = tx.nonce });
        try encoder.appendItem(.{ .uint = tx.max_priority_fee_per_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.max_fee_per_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.gas_limit });

        if (tx.to) |to_addr| {
            try encoder.appendItem(.{ .bytes = &to_addr.bytes });
        } else {
            try encoder.appendItem(.{ .bytes = &[_]u8{} });
        }

        try encoder.appendItem(.{ .uint = tx.value.toU64() catch 0 });
        try encoder.appendItem(.{ .bytes = tx.data });

        // TODO: Encode access list, blob versioned hashes, max_fee_per_blob_gas
        try encoder.appendItem(.{ .list = &[_]RlpItem{} }); // access list
        try encoder.appendItem(.{ .uint = tx.max_fee_per_blob_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .list = &[_]RlpItem{} }); // blob versioned hashes

        const encoded = try encoder.finish();
        defer self.allocator.free(encoded);

        // Prepend transaction type
        var type_prefixed = try self.allocator.alloc(u8, encoded.len + 1);
        defer self.allocator.free(type_prefixed);
        type_prefixed[0] = 0x03; // EIP-4844 type
        @memcpy(type_prefixed[1..], encoded);

        return keccak.hash(type_prefixed);
    }

    /// Get hash for EIP-7702 transaction
    fn getEip7702TransactionHash(self: *SignerMiddleware, tx: *Transaction) !Hash {
        // EIP-7702 similar to EIP-1559 with authorization list
        var encoder = RlpEncoder.init(self.allocator);
        defer encoder.deinit();

        try encoder.startList();
        try encoder.appendItem(.{ .uint = self.config.chain_id });
        try encoder.appendItem(.{ .uint = tx.nonce });
        try encoder.appendItem(.{ .uint = tx.max_priority_fee_per_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.max_fee_per_gas.toU64() catch 0 });
        try encoder.appendItem(.{ .uint = tx.gas_limit });

        if (tx.to) |to_addr| {
            try encoder.appendItem(.{ .bytes = &to_addr.bytes });
        } else {
            try encoder.appendItem(.{ .bytes = &[_]u8{} });
        }

        try encoder.appendItem(.{ .uint = tx.value.toU64() catch 0 });
        try encoder.appendItem(.{ .bytes = tx.data });

        // TODO: Encode access list and authorization list properly
        try encoder.appendItem(.{ .list = &[_]RlpItem{} }); // access list
        try encoder.appendItem(.{ .list = &[_]RlpItem{} }); // authorization list

        const encoded = try encoder.finish();
        defer self.allocator.free(encoded);

        // Prepend transaction type
        var type_prefixed = try self.allocator.alloc(u8, encoded.len + 1);
        defer self.allocator.free(type_prefixed);
        type_prefixed[0] = 0x04; // EIP-7702 type
        @memcpy(type_prefixed[1..], encoded);

        return keccak.hash(type_prefixed);
    }

    /// Sign and serialize transaction to raw bytes
    pub fn signAndSerialize(self: *SignerMiddleware, tx: *Transaction) ![]u8 {
        const sig = try self.signTransaction(tx);
        tx.setSignature(sig);

        // Serialize signed transaction
        return try self.serializeSignedTransaction(tx);
    }

    /// Serialize a signed transaction
    fn serializeSignedTransaction(self: *SignerMiddleware, tx: *Transaction) ![]u8 {
        var encoder = RlpEncoder.init(self.allocator);
        defer encoder.deinit();

        switch (tx.transaction_type) {
            .legacy => {
                try encoder.startList();
                try encoder.appendItem(.{ .uint = tx.nonce });
                try encoder.appendItem(.{ .uint = tx.gas_price.toU64() catch 0 });
                try encoder.appendItem(.{ .uint = tx.gas_limit });

                if (tx.to) |to_addr| {
                    try encoder.appendItem(.{ .bytes = &to_addr.bytes });
                } else {
                    try encoder.appendItem(.{ .bytes = &[_]u8{} });
                }

                try encoder.appendItem(.{ .uint = tx.value.toU64() catch 0 });
                try encoder.appendItem(.{ .bytes = tx.data });

                // Add signature
                const r_bytes = tx.r.toBytes(self.allocator);
                defer self.allocator.free(r_bytes);
                const s_bytes = tx.s.toBytes(self.allocator);
                defer self.allocator.free(s_bytes);

                try encoder.appendItem(.{ .uint = tx.v });
                try encoder.appendItem(.{ .bytes = r_bytes });
                try encoder.appendItem(.{ .bytes = s_bytes });

                return try encoder.finish();
            },
            .eip2930, .eip1559, .eip4844, .eip7702 => {
                // For typed transactions, prepend type byte
                const tx_type: u8 = switch (tx.transaction_type) {
                    .eip2930 => 0x01,
                    .eip1559 => 0x02,
                    .eip4844 => 0x03,
                    .eip7702 => 0x04,
                    else => unreachable,
                };

                // Encode transaction fields (simplified)
                try encoder.startList();
                try encoder.appendItem(.{ .uint = self.config.chain_id });
                try encoder.appendItem(.{ .uint = tx.nonce });
                // ... (add remaining fields)

                const encoded = try encoder.finish();
                defer self.allocator.free(encoded);

                // Prepend type
                var result = try self.allocator.alloc(u8, encoded.len + 1);
                result[0] = tx_type;
                @memcpy(result[1..], encoded);

                return result;
            },
        }
    }

    /// Sign a message
    pub fn signMessage(self: *SignerMiddleware, message: []const u8) !Signature {
        return try self.signer.signMessage(message);
    }

    /// Sign a personal message (with Ethereum prefix)
    pub fn signPersonalMessage(self: *SignerMiddleware, message: []const u8) !Signature {
        return try self.signer.signPersonalMessage(message);
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

    const private_key = PrivateKey.fromBytes([_]u8{1} ** 32);
    const config = SignerConfig.mainnet();

    var middleware = try SignerMiddleware.init(allocator, private_key, config);

    try std.testing.expectEqual(@as(u64, 1), middleware.getChainId());
    try std.testing.expect(middleware.isEip155Enabled());
}

test "signer middleware get address" {
    const allocator = std.testing.allocator;

    const private_key = PrivateKey.fromBytes([_]u8{1} ** 32);
    const config = SignerConfig.mainnet();

    var middleware = try SignerMiddleware.init(allocator, private_key, config);

    const addr = try middleware.getAddress();
    try std.testing.expect(!addr.isZero());
}

test "signer middleware sign message" {
    const allocator = std.testing.allocator;

    const private_key = PrivateKey.fromBytes([_]u8{1} ** 32);
    const config = SignerConfig.mainnet();

    var middleware = try SignerMiddleware.init(allocator, private_key, config);

    const message = "Hello, Ethereum!";
    const sig = try middleware.signMessage(message);

    try std.testing.expect(sig.isValid());
}
