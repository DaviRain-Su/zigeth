const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const U256 = @import("../primitives/uint.zig").U256;
const Transaction = @import("../types/transaction.zig").Transaction;
const PrivateKey = @import("../crypto/secp256k1.zig").PrivateKey;
const PublicKey = @import("../crypto/secp256k1.zig").PublicKey;
const Signer = @import("../crypto/ecdsa.zig").Signer;
const keccak = @import("../crypto/keccak.zig");
const SignerInterface = @import("./signer.zig").SignerInterface;
const SignerCapabilities = @import("./signer.zig").SignerCapabilities;

/// Software wallet with private key
pub const Wallet = struct {
    private_key: PrivateKey,
    signer: Signer,
    address: Address,
    allocator: std.mem.Allocator,
    capabilities: SignerCapabilities,

    /// Create a new wallet from a private key
    pub fn init(allocator: std.mem.Allocator, private_key: PrivateKey) !Wallet {
        const signer = try Signer.init(allocator, private_key);
        const address = try signer.getAddress();

        return .{
            .private_key = private_key,
            .signer = signer,
            .address = address,
            .allocator = allocator,
            .capabilities = SignerCapabilities.full(),
        };
    }

    /// Create a wallet from a private key hex string
    pub fn fromPrivateKeyHex(allocator: std.mem.Allocator, hex: []const u8) !Wallet {
        const hex_module = @import("../utils/hex.zig");

        // Remove 0x prefix if present
        const hex_clean = if (std.mem.startsWith(u8, hex, "0x"))
            hex[2..]
        else
            hex;

        if (hex_clean.len != 64) {
            return error.InvalidPrivateKeyLength;
        }

        const key_bytes = try hex_module.hexToBytes(allocator, hex_clean);
        defer allocator.free(key_bytes);

        if (key_bytes.len != 32) {
            return error.InvalidPrivateKeyLength;
        }

        var key_array: [32]u8 = undefined;
        @memcpy(&key_array, key_bytes);

        const private_key = PrivateKey.fromBytes(key_array);
        return try init(allocator, private_key);
    }

    /// Generate a new random wallet
    pub fn generate(allocator: std.mem.Allocator) !Wallet {
        const private_key = try PrivateKey.generate();
        return try init(allocator, private_key);
    }

    /// Get the wallet's address
    pub fn getAddress(self: Wallet) !Address {
        return self.address;
    }

    /// Get the private key (use with caution!)
    pub fn getPrivateKey(self: Wallet) PrivateKey {
        return self.private_key;
    }

    /// Get the public key
    pub fn getPublicKey(self: *Wallet) !PublicKey {
        return try self.signer.getPublicKey();
    }

    /// Export private key as hex string
    pub fn exportPrivateKey(self: Wallet) ![]u8 {
        const hex_module = @import("../utils/hex.zig");
        const key_u256 = try self.private_key.toU256();
        const key_bytes = try key_u256.toBytes(self.allocator);
        defer self.allocator.free(key_bytes);

        const hex = try hex_module.bytesToHex(self.allocator, key_bytes);
        return hex;
    }

    /// Sign a transaction
    pub fn signTransaction(self: *Wallet, tx: *Transaction, chain_id: u64) !Signature {
        // Set chain ID for EIP-155
        tx.chain_id = chain_id;

        // Get transaction hash
        const tx_hash = try self.getTransactionHash(tx, chain_id);

        // Sign the hash
        const sig = try self.signer.signHash(tx_hash.bytes);

        // Adjust v value for EIP-155
        const v = sig.getRecoveryId();
        const eip155_v = Signature.eip155V(v, chain_id);

        return Signature.init(sig.r, sig.s, eip155_v);
    }

    /// Get transaction hash for signing
    fn getTransactionHash(self: *Wallet, tx: *Transaction, chain_id: u64) !Hash {
        _ = self;
        _ = tx;
        _ = chain_id;
        // TODO: Implement proper transaction hash calculation
        return Hash.zero();
    }

    /// Sign a message hash
    pub fn signHash(self: *Wallet, hash: [32]u8) !Signature {
        return try self.signer.signHash(hash);
    }

    /// Sign a message (with Ethereum prefix)
    pub fn signMessage(self: *Wallet, message: []const u8) !Signature {
        return try self.signer.signPersonalMessage(message);
    }

    /// Sign typed data (EIP-712)
    pub fn signTypedData(self: *Wallet, domain_hash: [32]u8, message_hash: [32]u8) !Signature {
        // EIP-712: keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))
        var data: [66]u8 = undefined;
        data[0] = 0x19;
        data[1] = 0x01;
        @memcpy(data[2..34], &domain_hash);
        @memcpy(data[34..66], &message_hash);

        const hash = keccak.hash(&data);
        return try self.signer.signHash(hash.bytes);
    }

    /// Verify a signature
    pub fn verifySignature(self: *Wallet, hash: [32]u8, signature: Signature) !bool {
        const ecdsa = @import("../crypto/ecdsa.zig");
        const recovered_addr = try ecdsa.recoverAddress(hash, signature);
        return recovered_addr.eql(self.address);
    }

    /// Get signer interface
    pub fn asInterface(self: *Wallet) SignerInterface {
        const signerInterface = @import("./signer.zig").signerInterface;
        return signerInterface(Wallet, self);
    }

    /// Get capabilities
    pub fn getCapabilities(self: Wallet) SignerCapabilities {
        return self.capabilities;
    }
};

/// HD Wallet (BIP-32/BIP-44) - Framework
pub const HDWallet = struct {
    master_key: PrivateKey,
    chain_code: [32]u8,
    allocator: std.mem.Allocator,
    path: []const u8,

    /// Create HD wallet from seed
    pub fn fromSeed(allocator: std.mem.Allocator, seed: []const u8) !HDWallet {
        if (seed.len < 16 or seed.len > 64) {
            return error.InvalidSeedLength;
        }

        // TODO: Implement BIP-32 key derivation
        // For now, use seed as master key (simplified)
        var master_key_bytes: [32]u8 = undefined;
        @memcpy(master_key_bytes[0..@min(32, seed.len)], seed[0..@min(32, seed.len)]);

        const master_key = try PrivateKey.fromBytes(master_key_bytes);

        return .{
            .master_key = master_key,
            .chain_code = [_]u8{0} ** 32,
            .allocator = allocator,
            .path = "m",
        };
    }

    /// Derive child wallet at path (e.g., "m/44'/60'/0'/0/0")
    pub fn deriveChild(self: HDWallet, path: []const u8) !Wallet {
        // TODO: Implement proper BIP-32/BIP-44 derivation
        _ = path;
        return try Wallet.init(self.allocator, self.master_key);
    }

    /// Get wallet at index (simplified derivation)
    pub fn getWallet(self: HDWallet, index: u32) !Wallet {
        // TODO: Implement proper derivation
        _ = index;
        return try Wallet.init(self.allocator, self.master_key);
    }
};

/// Mnemonic (BIP-39) - Framework
pub const Mnemonic = struct {
    words: []const []const u8,
    allocator: std.mem.Allocator,

    /// Generate a new mnemonic (12/24 words)
    pub fn generate(allocator: std.mem.Allocator, word_count: usize) !Mnemonic {
        if (word_count != 12 and word_count != 24) {
            return error.InvalidWordCount;
        }

        // TODO: Implement BIP-39 word generation
        const words = try allocator.alloc([]const u8, word_count);
        for (words, 0..) |*word, i| {
            _ = i;
            word.* = "word"; // Placeholder
        }

        return .{
            .words = words,
            .allocator = allocator,
        };
    }

    /// Create mnemonic from phrase
    pub fn fromPhrase(allocator: std.mem.Allocator, phrase: []const u8) !Mnemonic {
        // Split by spaces
        var words = std.ArrayList([]const u8).init(allocator);
        defer words.deinit();

        var iter = std.mem.splitScalar(u8, phrase, ' ');
        while (iter.next()) |word| {
            if (word.len > 0) {
                const word_copy = try allocator.dupe(u8, word);
                try words.append(word_copy);
            }
        }

        return .{
            .words = try words.toOwnedSlice(),
            .allocator = allocator,
        };
    }

    /// Convert to seed (for HD wallet)
    pub fn toSeed(self: Mnemonic, passphrase: []const u8) ![]u8 {
        // TODO: Implement BIP-39 seed derivation (PBKDF2)
        _ = passphrase;
        const seed = try self.allocator.alloc(u8, 64);
        @memset(seed, 0);
        return seed;
    }

    /// Get phrase as string
    pub fn toPhrase(self: Mnemonic) ![]u8 {
        var phrase = std.ArrayList(u8).init(self.allocator);
        defer phrase.deinit();

        for (self.words, 0..) |word, i| {
            if (i > 0) try phrase.append(' ');
            try phrase.appendSlice(word);
        }

        return phrase.toOwnedSlice();
    }

    /// Free memory
    pub fn deinit(self: *Mnemonic) void {
        for (self.words) |word| {
            self.allocator.free(word);
        }
        self.allocator.free(self.words);
    }
};

// Tests
test "wallet creation from private key" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    var wallet = try Wallet.init(allocator, private_key);

    const addr = try wallet.getAddress();
    try std.testing.expect(!addr.isZero());
}

test "wallet generate" {
    const allocator = std.testing.allocator;

    var wallet = try Wallet.generate(allocator);
    const addr = try wallet.getAddress();
    try std.testing.expect(!addr.isZero());
}

test "wallet sign message" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    var wallet = try Wallet.init(allocator, private_key);

    const message = "Hello, Ethereum!";
    const sig = try wallet.signMessage(message);

    try std.testing.expect(sig.isValid());
}

test "wallet sign hash" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    var wallet = try Wallet.init(allocator, private_key);

    const hash = [_]u8{0xAB} ** 32;
    const sig = try wallet.signHash(hash);

    try std.testing.expect(sig.isValid());
}

test "wallet verify signature" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    var wallet = try Wallet.init(allocator, private_key);

    const hash = [_]u8{0xAB} ** 32;
    const sig = try wallet.signHash(hash);

    const valid = try wallet.verifySignature(hash, sig);
    try std.testing.expect(valid);
}

test "wallet capabilities" {
    const allocator = std.testing.allocator;

    const private_key = try PrivateKey.fromBytes([_]u8{1} ** 32);
    const wallet = try Wallet.init(allocator, private_key);

    const caps = wallet.getCapabilities();
    try std.testing.expect(caps.can_sign_transactions);
    try std.testing.expect(caps.can_sign_messages);
    try std.testing.expect(caps.supports_eip712);
}

test "mnemonic from phrase" {
    const allocator = std.testing.allocator;

    const phrase = "word word word word word word word word word word word word";
    var mnemonic = try Mnemonic.fromPhrase(allocator, phrase);
    defer mnemonic.deinit();

    try std.testing.expectEqual(@as(usize, 12), mnemonic.words.len);
}

test "hd wallet from seed" {
    const allocator = std.testing.allocator;

    const seed = [_]u8{0xAB} ** 32;
    const hd_wallet = try HDWallet.fromSeed(allocator, &seed);

    var wallet = try hd_wallet.deriveChild("m/44'/60'/0'/0/0");
    const addr = try wallet.getAddress();
    try std.testing.expect(!addr.isZero());
}
