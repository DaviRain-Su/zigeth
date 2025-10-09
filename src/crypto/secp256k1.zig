const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const U256 = @import("../primitives/uint.zig").U256;
const keccak = @import("./keccak.zig");

/// secp256k1 curve parameters
pub const Secp256k1 = struct {
    /// Field prime (p)
    pub const P = U256.fromInt(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F);

    /// Curve order (n)
    pub const N = U256.fromInt(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141);

    /// Generator point G
    pub const G_X = U256.fromInt(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798);
    pub const G_Y = U256.fromInt(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8);
};

/// Private key (32 bytes)
pub const PrivateKey = struct {
    bytes: [32]u8,

    /// Create from bytes
    pub fn fromBytes(bytes: [32]u8) !PrivateKey {
        // Verify the key is in valid range (0 < key < N)
        const key_value = U256.fromBytes(bytes);
        if (key_value.isZero() or key_value.gte(Secp256k1.N)) {
            return error.InvalidPrivateKey;
        }
        return .{ .bytes = bytes };
    }

    /// Create from U256
    pub fn fromU256(value: U256) !PrivateKey {
        if (value.isZero() or value.gte(Secp256k1.N)) {
            return error.InvalidPrivateKey;
        }
        return .{ .bytes = value.toBytes() };
    }

    /// Generate a random private key
    pub fn generate(random: std.rand.Random) !PrivateKey {
        var bytes: [32]u8 = undefined;
        random.bytes(&bytes);

        // Ensure the key is valid
        const key_value = U256.fromBytes(bytes);
        if (key_value.isZero() or key_value.gte(Secp256k1.N)) {
            // Try again recursively (very unlikely to fail twice)
            return try generate(random);
        }

        return .{ .bytes = bytes };
    }

    /// Convert to U256
    pub fn toU256(self: PrivateKey) U256 {
        return U256.fromBytes(self.bytes);
    }
};

/// Public key (uncompressed: 64 bytes, compressed: 33 bytes)
pub const PublicKey = struct {
    /// X coordinate (32 bytes)
    x: [32]u8,
    /// Y coordinate (32 bytes)
    y: [32]u8,

    /// Create from uncompressed bytes (64 bytes)
    pub fn fromUncompressed(bytes: []const u8) !PublicKey {
        if (bytes.len != 64) {
            return error.InvalidPublicKeyLength;
        }

        var pk: PublicKey = undefined;
        @memcpy(&pk.x, bytes[0..32]);
        @memcpy(&pk.y, bytes[32..64]);

        return pk;
    }

    /// Create from compressed bytes (33 bytes)
    pub fn fromCompressed(bytes: []const u8) !PublicKey {
        if (bytes.len != 33) {
            return error.InvalidPublicKeyLength;
        }

        // TODO: Implement point decompression
        // For now, return error
        return error.NotImplemented;
    }

    /// Get uncompressed form (64 bytes)
    pub fn toUncompressed(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, 64);
        @memcpy(result[0..32], &self.x);
        @memcpy(result[32..64], &self.y);
        return result;
    }

    /// Get compressed form (33 bytes)
    pub fn toCompressed(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, 33);

        // Prefix byte: 0x02 if y is even, 0x03 if y is odd
        const y_value = U256.fromBytes(self.y);
        result[0] = if (y_value.toU64() & 1 == 0) 0x02 else 0x03;

        @memcpy(result[1..33], &self.x);
        return result;
    }

    /// Derive Ethereum address from public key
    pub fn toAddress(self: PublicKey) Address {
        // Ethereum address is the last 20 bytes of Keccak-256(public_key)
        var pub_bytes: [64]u8 = undefined;
        @memcpy(pub_bytes[0..32], &self.x);
        @memcpy(pub_bytes[32..64], &self.y);

        const hash_result = keccak.hash(&pub_bytes);

        var addr_bytes: [20]u8 = undefined;
        @memcpy(&addr_bytes, hash_result.bytes[12..32]);

        return Address.fromBytes(addr_bytes);
    }
};

/// Derive public key from private key
/// Note: This is a placeholder. In production, use libsecp256k1 or a proper EC implementation
pub fn derivePublicKey(private_key: PrivateKey) !PublicKey {
    // TODO: Implement proper scalar multiplication on secp256k1
    // For now, return a placeholder
    // In production, this would use: public_key = private_key * G

    _ = private_key;
    return error.NotImplemented;
}

/// Sign a message hash with a private key
/// Note: This is a placeholder. In production, use libsecp256k1
pub fn sign(message_hash: Hash, private_key: PrivateKey) !Signature {
    // TODO: Implement proper ECDSA signing
    // For now, return a placeholder

    _ = message_hash;
    _ = private_key;
    return error.NotImplemented;
}

/// Verify a signature
/// Note: This is a placeholder. In production, use libsecp256k1
pub fn verify(message_hash: Hash, signature: Signature, public_key: PublicKey) !bool {
    // TODO: Implement proper ECDSA verification

    _ = message_hash;
    _ = signature;
    _ = public_key;
    return error.NotImplemented;
}

/// Recover public key from signature and message hash
/// Note: This is a placeholder. In production, use libsecp256k1
pub fn recoverPublicKey(message_hash: Hash, signature: Signature) !PublicKey {
    // TODO: Implement public key recovery from signature

    _ = message_hash;
    _ = signature;
    return error.NotImplemented;
}

test "private key validation" {
    // Valid private key
    const valid_bytes = [_]u8{1} ** 32;
    const pk = try PrivateKey.fromBytes(valid_bytes);
    try std.testing.expect(!pk.toU256().isZero());

    // Zero private key is invalid
    const zero_bytes = [_]u8{0} ** 32;
    const zero_result = PrivateKey.fromBytes(zero_bytes);
    try std.testing.expectError(error.InvalidPrivateKey, zero_result);
}

test "private key generation" {
    var prng = std.rand.DefaultPrng.init(0);
    const random = prng.random();

    const pk = try PrivateKey.generate(random);
    try std.testing.expect(!pk.toU256().isZero());
}

test "public key uncompressed format" {
    const allocator = std.testing.allocator;

    var pk = PublicKey{
        .x = [_]u8{1} ** 32,
        .y = [_]u8{2} ** 32,
    };

    const uncompressed = try pk.toUncompressed(allocator);
    defer allocator.free(uncompressed);

    try std.testing.expectEqual(@as(usize, 64), uncompressed.len);
    try std.testing.expectEqual(@as(u8, 1), uncompressed[0]);
    try std.testing.expectEqual(@as(u8, 2), uncompressed[32]);
}

test "public key to address" {
    // Known test vector
    var pk = PublicKey{
        .x = [_]u8{0xab} ** 32,
        .y = [_]u8{0xcd} ** 32,
    };

    const addr = pk.toAddress();

    // Address should be 20 bytes and not all zeros
    try std.testing.expect(!addr.isZero());
}

test "public key compressed format" {
    const allocator = std.testing.allocator;

    // Even y-coordinate
    var pk_even = PublicKey{
        .x = [_]u8{1} ** 32,
        .y = [_]u8{0} ** 32, // Even (last byte is 0)
    };

    const compressed_even = try pk_even.toCompressed(allocator);
    defer allocator.free(compressed_even);

    try std.testing.expectEqual(@as(usize, 33), compressed_even.len);
    try std.testing.expectEqual(@as(u8, 0x02), compressed_even[0]);

    // Odd y-coordinate
    var pk_odd = PublicKey{
        .x = [_]u8{1} ** 32,
        .y = [_]u8{1} ** 32, // Odd (last byte is 1)
    };

    const compressed_odd = try pk_odd.toCompressed(allocator);
    defer allocator.free(compressed_odd);

    try std.testing.expectEqual(@as(usize, 33), compressed_odd.len);
    try std.testing.expectEqual(@as(u8, 0x03), compressed_odd[0]);
}
