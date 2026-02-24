const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const uint_utils = @import("../primitives/uint.zig");
const u256FromBytes = uint_utils.u256FromBytes;
const u256ToBytes = uint_utils.u256ToBytes;
const keccak = @import("./keccak.zig");
const secp = @import("secp256k1");

/// secp256k1 curve parameters
pub const Secp256k1 = struct {
    /// Field prime (p)
    pub const P: u256 = u256FromBytes([_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
    });

    /// Curve order (n)
    pub const N: u256 = u256FromBytes([_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    });

    /// Generator point G
    pub const G_X: u256 = u256FromBytes([_]u8{
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    });
    pub const G_Y: u256 = u256FromBytes([_]u8{
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
    });
};

/// Private key (32 bytes)
pub const PrivateKey = struct {
    bytes: [32]u8,

    /// Create from bytes
    pub fn fromBytes(bytes: [32]u8) !PrivateKey {
        // Verify the key is in valid range (0 < key < N)
        const key_value = u256FromBytes(bytes);
        if (key_value == 0 or key_value >= Secp256k1.N) {
            return error.InvalidPrivateKey;
        }
        return .{ .bytes = bytes };
    }

    /// Create from u256
    pub fn fromU256(value: u256) !PrivateKey {
        if (value == 0 or value >= Secp256k1.N) {
            return error.InvalidPrivateKey;
        }
        return .{ .bytes = u256ToBytes(value) };
    }

    /// Generate a random private key
    pub fn generate(random: std.Random) !PrivateKey {
        var bytes: [32]u8 = undefined;
        random.bytes(&bytes);

        // Ensure the key is valid
        const key_value = u256FromBytes(bytes);
        if (key_value == 0 or key_value >= Secp256k1.N) {
            // Try again recursively (very unlikely to fail twice)
            return try generate(random);
        }

        return .{ .bytes = bytes };
    }

    /// Convert to u256
    pub fn toU256(self: PrivateKey) u256 {
        return u256FromBytes(self.bytes);
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
        const y_value = u256FromBytes(self.y);
        result[0] = if (y_value & 1 == 0) 0x02 else 0x03;

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
pub fn derivePublicKey(private_key: PrivateKey) !PublicKey {
    var ctx = try secp.Secp256k1.init();

    // Use a workaround: sign a dummy message and recover the pubkey
    // This gives us the public key corresponding to the private key
    const dummy_msg: [32]u8 = [_]u8{1} ** 32;
    const dummy_sig = try ctx.sign(dummy_msg, private_key.bytes);
    const pubkey_65 = try ctx.recoverPubkey(dummy_msg, dummy_sig);

    // Convert from 65-byte (0x04 prefix + x + y) to our format (x + y)
    return try PublicKey.fromUncompressed(pubkey_65[1..65]);
}

/// Sign a message hash with a private key
pub fn sign(message_hash: Hash, private_key: PrivateKey) !Signature {
    var ctx = try secp.Secp256k1.init();
    const sig_bytes = try ctx.sign(message_hash.bytes, private_key.bytes);

    // sig_bytes is [65]u8: [r (32) | s (32) | v (1)]
    var sig: Signature = undefined;
    @memcpy(&sig.r, sig_bytes[0..32]);
    @memcpy(&sig.s, sig_bytes[32..64]);
    // Convert recovery ID (0-3) to Ethereum v (27-30)
    sig.v = sig_bytes[64] + 27;

    return sig;
}

/// Verify a signature
pub fn verify(message_hash: Hash, signature: Signature, public_key: PublicKey) !bool {
    // For verification, we can recover the public key and compare
    const recovered_pubkey = try recoverPublicKey(message_hash, signature);

    return std.mem.eql(u8, &public_key.x, &recovered_pubkey.x) and
        std.mem.eql(u8, &public_key.y, &recovered_pubkey.y);
}

/// Recover public key from signature and message hash
pub fn recoverPublicKey(message_hash: Hash, signature: Signature) !PublicKey {
    var ctx = try secp.Secp256k1.init();

    // Convert our signature format to library format
    var sig_bytes: [65]u8 = undefined;
    @memcpy(sig_bytes[0..32], &signature.r);
    @memcpy(sig_bytes[32..64], &signature.s);
    // Convert Ethereum v back to recovery ID (0-3)
    // For legacy signatures (v = 27 or 28), recovery_id = v - 27
    // For EIP-155 signatures (v >= 35), recovery_id = (v - 35) % 2
    sig_bytes[64] = signature.getCompactV();

    const pubkey_65 = try ctx.recoverPubkey(message_hash.bytes, sig_bytes);

    // Convert from 65-byte (0x04 prefix + x + y) to our format (x + y)
    return try PublicKey.fromUncompressed(pubkey_65[1..65]);
}

test "private key validation" {
    // Valid private key
    const valid_bytes = [_]u8{1} ** 32;
    const pk = try PrivateKey.fromBytes(valid_bytes);
    try std.testing.expect(pk.toU256() != 0);

    // Zero private key is invalid
    const zero_bytes = [_]u8{0} ** 32;
    const zero_result = PrivateKey.fromBytes(zero_bytes);
    try std.testing.expectError(error.InvalidPrivateKey, zero_result);
}

test "private key generation" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const pk = try PrivateKey.generate(random);
    try std.testing.expect(pk.toU256() != 0);
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

test "derive public key from private key" {
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    const private_key = try PrivateKey.generate(random);
    const public_key = try derivePublicKey(private_key);

    // Public key should not be all zeros
    const x_zero = std.mem.allEqual(u8, &public_key.x, 0);
    const y_zero = std.mem.allEqual(u8, &public_key.y, 0);
    try std.testing.expect(!x_zero or !y_zero);
}

test "sign and verify" {
    var prng = std.Random.DefaultPrng.init(54321);
    const random = prng.random();

    // Generate a private key
    const private_key = try PrivateKey.generate(random);

    // Derive public key
    const public_key = try derivePublicKey(private_key);

    // Create a message hash
    const message = "Hello, Ethereum!";
    const message_hash = keccak.hash(message);

    // Sign the message
    const signature = try sign(message_hash, private_key);

    // Verify the signature
    const is_valid = try verify(message_hash, signature, public_key);
    try std.testing.expect(is_valid);
}

test "recover public key from signature" {
    var prng = std.Random.DefaultPrng.init(98765);
    const random = prng.random();

    // Generate a private key
    const private_key = try PrivateKey.generate(random);

    // Derive public key
    const original_pubkey = try derivePublicKey(private_key);

    // Create a message hash
    const message = "Test recovery";
    const message_hash = keccak.hash(message);

    // Sign the message
    const signature = try sign(message_hash, private_key);

    // Recover public key from signature
    const recovered_pubkey = try recoverPublicKey(message_hash, signature);

    // Compare the public keys
    try std.testing.expect(std.mem.eql(u8, &original_pubkey.x, &recovered_pubkey.x));
    try std.testing.expect(std.mem.eql(u8, &original_pubkey.y, &recovered_pubkey.y));
}

test "address derivation from keypair" {
    var prng = std.Random.DefaultPrng.init(11111);
    const random = prng.random();

    // Generate a private key
    const private_key = try PrivateKey.generate(random);

    // Derive public key
    const public_key = try derivePublicKey(private_key);

    // Derive address
    const address = public_key.toAddress();

    // Address should not be zero
    try std.testing.expect(!address.isZero());
}
