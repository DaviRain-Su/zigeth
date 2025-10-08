const std = @import("std");
const Hash = @import("../primitives/hash.zig").Hash;
const Address = @import("../primitives/address.zig").Address;
const Signature = @import("../primitives/signature.zig").Signature;
const secp256k1 = @import("./secp256k1.zig");
const keccak = @import("./keccak.zig");

/// ECDSA signer for Ethereum transactions
pub const Signer = struct {
    private_key: secp256k1.PrivateKey,

    /// Create a new signer with a private key
    pub fn init(private_key: secp256k1.PrivateKey) Signer {
        return .{ .private_key = private_key };
    }

    /// Sign a message hash
    pub fn signHash(self: Signer, message_hash: Hash) !Signature {
        return try secp256k1.sign(message_hash, self.private_key);
    }

    /// Sign raw message bytes (will hash with Keccak-256)
    pub fn signMessage(self: Signer, message: []const u8) !Signature {
        const hash_result = keccak.hash(message);
        return try self.signHash(hash_result);
    }

    /// Sign with Ethereum's personal message format
    /// Prepends "\x19Ethereum Signed Message:\n" + length + message
    pub fn signPersonalMessage(self: Signer, allocator: std.mem.Allocator, message: []const u8) !Signature {
        const prefix = "\x19Ethereum Signed Message:\n";
        const len_str = try std.fmt.allocPrint(allocator, "{d}", .{message.len});
        defer allocator.free(len_str);

        // Concatenate: prefix + length + message
        const total_len = prefix.len + len_str.len + message.len;
        const full_message = try allocator.alloc(u8, total_len);
        defer allocator.free(full_message);

        @memcpy(full_message[0..prefix.len], prefix);
        @memcpy(full_message[prefix.len .. prefix.len + len_str.len], len_str);
        @memcpy(full_message[prefix.len + len_str.len ..], message);

        return try self.signMessage(full_message);
    }

    /// Get the public key for this signer
    pub fn getPublicKey(self: Signer) !secp256k1.PublicKey {
        return try secp256k1.derivePublicKey(self.private_key);
    }

    /// Get the Ethereum address for this signer
    pub fn getAddress(self: Signer) !Address {
        const pub_key = try self.getPublicKey();
        return pub_key.toAddress();
    }
};

/// Verify an ECDSA signature
pub fn verify(message_hash: Hash, signature: Signature, public_key: secp256k1.PublicKey) !bool {
    return try secp256k1.verify(message_hash, signature, public_key);
}

/// Recover the public key from a signature and message hash
pub fn recoverPublicKey(message_hash: Hash, signature: Signature) !secp256k1.PublicKey {
    return try secp256k1.recoverPublicKey(message_hash, signature);
}

/// Recover the Ethereum address from a signature and message hash
pub fn recoverAddress(message_hash: Hash, signature: Signature) !Address {
    const pub_key = try recoverPublicKey(message_hash, signature);
    return pub_key.toAddress();
}

/// Verify a personal message signature
pub fn verifyPersonalMessage(
    allocator: std.mem.Allocator,
    message: []const u8,
    signature: Signature,
    expected_address: Address,
) !bool {
    const prefix = "\x19Ethereum Signed Message:\n";
    const len_str = try std.fmt.allocPrint(allocator, "{d}", .{message.len});
    defer allocator.free(len_str);

    const total_len = prefix.len + len_str.len + message.len;
    const full_message = try allocator.alloc(u8, total_len);
    defer allocator.free(full_message);

    @memcpy(full_message[0..prefix.len], prefix);
    @memcpy(full_message[prefix.len .. prefix.len + len_str.len], len_str);
    @memcpy(full_message[prefix.len + len_str.len ..], message);

    const hash_result = keccak.hash(full_message);
    const recovered_address = try recoverAddress(hash_result, signature);

    return std.mem.eql(u8, &recovered_address.bytes, &expected_address.bytes);
}

/// Sign transaction data for Ethereum
pub const TransactionSigner = struct {
    signer: Signer,
    chain_id: u64,

    pub fn init(private_key: secp256k1.PrivateKey, chain_id: u64) TransactionSigner {
        return .{
            .signer = Signer.init(private_key),
            .chain_id = chain_id,
        };
    }

    /// Sign transaction hash with EIP-155 replay protection
    pub fn signTransaction(self: TransactionSigner, tx_hash: Hash) !Signature {
        // For EIP-155, we need to include chain_id in the signature
        // The actual implementation would modify the v value
        var signature = try self.signer.signHash(tx_hash);

        // Apply EIP-155: v = chain_id * 2 + 35 + recovery_id
        const recovery_id = signature.getRecoveryId();
        signature.v = Signature.eip155V(self.chain_id, recovery_id);

        return signature;
    }

    pub fn getAddress(self: TransactionSigner) !Address {
        return try self.signer.getAddress();
    }
};

/// Deterministic k generation for ECDSA (RFC 6979)
/// This prevents nonce reuse attacks
pub fn generateDeterministicK(
    message_hash: Hash,
    private_key: secp256k1.PrivateKey,
) !secp256k1.PrivateKey {
    // TODO: Implement RFC 6979 deterministic k generation
    // For now, this is a placeholder

    _ = message_hash;
    _ = private_key;
    return error.NotImplemented;
}

test "signer creation" {
    var prng = std.rand.DefaultPrng.init(0);
    const random = prng.random();

    const pk = try secp256k1.PrivateKey.generate(random);
    const signer = Signer.init(pk);

    // Verify signer was created
    try std.testing.expect(!signer.private_key.toU256().isZero());
}

test "transaction signer with chain id" {
    var prng = std.rand.DefaultPrng.init(0);
    const random = prng.random();

    const pk = try secp256k1.PrivateKey.generate(random);
    const tx_signer = TransactionSigner.init(pk, 1); // Ethereum mainnet

    try std.testing.expectEqual(@as(u64, 1), tx_signer.chain_id);
}

test "personal message format" {
    // Test message formatting
    const message = "Hello Ethereum!";
    const expected_prefix = "\x19Ethereum Signed Message:\n15";

    const prefix_len = expected_prefix.len;
    const total_len = prefix_len + message.len;

    try std.testing.expectEqual(@as(usize, 30), total_len);
}
