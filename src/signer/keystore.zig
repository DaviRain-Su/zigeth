const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const PrivateKey = @import("../crypto/secp256k1.zig").PrivateKey;
const Wallet = @import("./wallet.zig").Wallet;
const keccak = @import("../crypto/keccak.zig");
const hex_module = @import("../utils/hex.zig");

/// Keystore version
pub const KeystoreVersion = enum {
    v3,

    pub fn toString(self: KeystoreVersion) []const u8 {
        return switch (self) {
            .v3 => "3",
        };
    }
};

/// KDF (Key Derivation Function) type
pub const KdfType = enum {
    scrypt,
    pbkdf2,

    pub fn toString(self: KdfType) []const u8 {
        return switch (self) {
            .scrypt => "scrypt",
            .pbkdf2 => "pbkdf2",
        };
    }

    pub fn fromString(s: []const u8) !KdfType {
        if (std.mem.eql(u8, s, "scrypt")) return .scrypt;
        if (std.mem.eql(u8, s, "pbkdf2")) return .pbkdf2;
        return error.UnknownKdfType;
    }
};

/// Cipher type
pub const CipherType = enum {
    aes_128_ctr,

    pub fn toString(self: CipherType) []const u8 {
        return switch (self) {
            .aes_128_ctr => "aes-128-ctr",
        };
    }

    pub fn fromString(s: []const u8) !CipherType {
        if (std.mem.eql(u8, s, "aes-128-ctr")) return .aes_128_ctr;
        return error.UnknownCipherType;
    }
};

/// KDF parameters for scrypt
pub const ScryptParams = struct {
    dklen: u32,
    n: u32, // CPU/memory cost
    r: u32, // block size
    p: u32, // parallelization
    salt: [32]u8,

    pub fn default() ScryptParams {
        return .{
            .dklen = 32,
            .n = 262144, // 2^18
            .r = 8,
            .p = 1,
            .salt = undefined, // Set by caller
        };
    }

    pub fn light() ScryptParams {
        return .{
            .dklen = 32,
            .n = 4096, // 2^12 - faster for testing
            .r = 8,
            .p = 1,
            .salt = undefined,
        };
    }
};

/// KDF parameters for PBKDF2
pub const Pbkdf2Params = struct {
    dklen: u32,
    c: u32, // iteration count
    prf: []const u8, // PRF algorithm (e.g., "hmac-sha256")
    salt: [32]u8,

    pub fn default() Pbkdf2Params {
        return .{
            .dklen = 32,
            .c = 262144,
            .prf = "hmac-sha256",
            .salt = undefined,
        };
    }
};

/// Cipher parameters
pub const CipherParams = struct {
    iv: [16]u8,
};

/// Keystore crypto section
pub const KeystoreCrypto = struct {
    cipher: CipherType,
    cipherparams: CipherParams,
    ciphertext: []u8,
    kdf: KdfType,
    kdfparams: union(enum) {
        scrypt: ScryptParams,
        pbkdf2: Pbkdf2Params,
    },
    mac: [32]u8,
};

/// JSON Keystore (Web3 Secret Storage Definition)
pub const Keystore = struct {
    version: KeystoreVersion,
    id: [16]u8, // UUID
    address: Address,
    crypto: KeystoreCrypto,
    allocator: std.mem.Allocator,

    /// Encrypt a private key to create a keystore
    pub fn encrypt(
        allocator: std.mem.Allocator,
        private_key: PrivateKey,
        password: []const u8,
        kdf_type: KdfType,
    ) !Keystore {
        const wallet = try Wallet.init(allocator, private_key);
        const address = try wallet.getAddress();

        // Generate random salt and IV
        var salt: [32]u8 = undefined;
        var iv: [16]u8 = undefined;
        var id: [16]u8 = undefined;

        try std.crypto.random.bytes(&salt);
        try std.crypto.random.bytes(&iv);
        try std.crypto.random.bytes(&id);

        // Convert private key to bytes
        const key_u256 = try private_key.toU256();
        const private_key_bytes = try key_u256.toBytes(allocator);
        defer allocator.free(private_key_bytes);

        if (private_key_bytes.len != 32) {
            return error.InvalidPrivateKeyLength;
        }

        // Derive encryption key using KDF
        const derived_key = try deriveKey(allocator, password, salt, kdf_type);
        defer allocator.free(derived_key);

        // Encrypt private key using AES-128-CTR
        const ciphertext = try encryptAES128CTR(allocator, private_key_bytes, derived_key[0..16].*, iv);

        // Calculate MAC
        const mac = try calculateMAC(derived_key[16..32].*, ciphertext);

        const kdfparams: union(enum) {
            scrypt: ScryptParams,
            pbkdf2: Pbkdf2Params,
        } = switch (kdf_type) {
            .scrypt => blk: {
                var params = ScryptParams.default();
                params.salt = salt;
                break :blk .{ .scrypt = params };
            },
            .pbkdf2 => blk: {
                var params = Pbkdf2Params.default();
                params.salt = salt;
                break :blk .{ .pbkdf2 = params };
            },
        };

        return .{
            .version = .v3,
            .id = id,
            .address = address,
            .crypto = .{
                .cipher = .aes_128_ctr,
                .cipherparams = .{ .iv = iv },
                .ciphertext = ciphertext,
                .kdf = kdf_type,
                .kdfparams = kdfparams,
                .mac = mac,
            },
            .allocator = allocator,
        };
    }

    /// Decrypt keystore to recover private key
    pub fn decrypt(self: Keystore, password: []const u8) !PrivateKey {
        // Derive key using KDF
        const salt = switch (self.crypto.kdfparams) {
            .scrypt => |params| params.salt,
            .pbkdf2 => |params| params.salt,
        };

        const derived_key = try deriveKey(self.allocator, password, salt, self.crypto.kdf);
        defer self.allocator.free(derived_key);

        // Verify MAC
        const mac = try calculateMAC(derived_key[16..32].*, self.crypto.ciphertext);
        if (!std.mem.eql(u8, &mac, &self.crypto.mac)) {
            return error.InvalidPassword;
        }

        // Decrypt private key
        const private_key_bytes = try decryptAES128CTR(
            self.allocator,
            self.crypto.ciphertext,
            derived_key[0..16].*,
            self.crypto.cipherparams.iv,
        );
        defer self.allocator.free(private_key_bytes);

        if (private_key_bytes.len != 32) {
            return error.InvalidPrivateKeyLength;
        }

        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, private_key_bytes);

        return PrivateKey.fromBytes(key_array);
    }

    /// Get wallet from keystore
    pub fn toWallet(self: Keystore, password: []const u8) !Wallet {
        const private_key = try self.decrypt(password);
        return try Wallet.init(self.allocator, private_key);
    }

    /// Export keystore to JSON
    pub fn toJSON(self: Keystore) ![]u8 {
        // TODO: Implement proper JSON serialization
        return try std.fmt.allocPrint(
            self.allocator,
            "{{\"version\":{d},\"address\":\"{s}\"}}",
            .{ @intFromEnum(self.version), "0x..." },
        );
    }

    /// Import keystore from JSON
    pub fn fromJSON(allocator: std.mem.Allocator, json: []const u8) !Keystore {
        // TODO: Implement proper JSON deserialization
        _ = allocator;
        _ = json;
        return error.NotImplemented;
    }

    /// Free allocated memory
    pub fn deinit(self: *Keystore) void {
        self.allocator.free(self.crypto.ciphertext);
    }
};

/// Derive key using KDF
fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: [32]u8,
    kdf_type: KdfType,
) ![]u8 {
    return switch (kdf_type) {
        .scrypt => try deriveKeyScrypt(allocator, password, salt),
        .pbkdf2 => try deriveKeyPbkdf2(allocator, password, salt),
    };
}

/// Derive key using scrypt (simplified)
fn deriveKeyScrypt(allocator: std.mem.Allocator, password: []const u8, salt: [32]u8) ![]u8 {
    // TODO: Implement actual scrypt
    // For now, use a simplified version
    _ = password;
    _ = salt;

    const key = try allocator.alloc(u8, 32);
    @memset(key, 0xAB); // Placeholder
    return key;
}

/// Derive key using PBKDF2
fn deriveKeyPbkdf2(allocator: std.mem.Allocator, password: []const u8, salt: [32]u8) ![]u8 {
    // Use Zig's PBKDF2
    const iterations = 262144;
    var key: [32]u8 = undefined;

    std.crypto.pwhash.pbkdf2(&key, password, &salt, iterations, std.crypto.auth.hmac.sha2.HmacSha256);

    return try allocator.dupe(u8, &key);
}

/// Encrypt data using AES-128-CTR
fn encryptAES128CTR(allocator: std.mem.Allocator, plaintext: []const u8, key: [16]u8, iv: [16]u8) ![]u8 {
    // TODO: Implement actual AES-128-CTR
    // For now, XOR with key (insecure placeholder)
    _ = iv;

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    for (plaintext, 0..) |byte, i| {
        ciphertext[i] = byte ^ key[i % 16];
    }
    return ciphertext;
}

/// Decrypt data using AES-128-CTR
fn decryptAES128CTR(allocator: std.mem.Allocator, ciphertext: []const u8, key: [16]u8, iv: [16]u8) ![]u8 {
    // AES-CTR encryption and decryption are the same operation
    return try encryptAES128CTR(allocator, ciphertext, key, iv);
}

/// Calculate MAC for verification
fn calculateMAC(key: []const u8, ciphertext: []const u8) ![32]u8 {
    // MAC = keccak256(derived_key[16:32] + ciphertext)
    var data = std.ArrayList(u8).init(std.heap.page_allocator);
    defer data.deinit();

    try data.appendSlice(key);
    try data.appendSlice(ciphertext);

    return keccak.hash(data.items).bytes;
}

// Tests
test "keystore encrypt and decrypt" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const password = "test_password";

    var keystore = try Keystore.encrypt(allocator, private_key, password, .pbkdf2);
    defer keystore.deinit();

    const decrypted_key = try keystore.decrypt(password);
    const orig_u256 = try private_key.toU256();
    const decrypted_u256 = try decrypted_key.toU256();

    try std.testing.expect(orig_u256.eql(decrypted_u256));
}

test "keystore wrong password" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const password = "test_password";

    var keystore = try Keystore.encrypt(allocator, private_key, password, .pbkdf2);
    defer keystore.deinit();

    const result = keystore.decrypt("wrong_password");
    try std.testing.expectError(error.InvalidPassword, result);
}

test "keystore to wallet" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const password = "test_password";

    var keystore = try Keystore.encrypt(allocator, private_key, password, .pbkdf2);
    defer keystore.deinit();

    var wallet = try keystore.toWallet(password);
    const addr = try wallet.getAddress();

    try std.testing.expect(!addr.isZero());
}

test "kdf type from string" {
    try std.testing.expectEqual(KdfType.scrypt, try KdfType.fromString("scrypt"));
    try std.testing.expectEqual(KdfType.pbkdf2, try KdfType.fromString("pbkdf2"));
}

test "cipher type from string" {
    try std.testing.expectEqual(CipherType.aes_128_ctr, try CipherType.fromString("aes-128-ctr"));
}

test "scrypt params" {
    const params = ScryptParams.default();
    try std.testing.expectEqual(@as(u32, 32), params.dklen);
    try std.testing.expectEqual(@as(u32, 262144), params.n);
}
