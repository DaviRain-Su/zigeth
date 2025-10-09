const std = @import("std");
const Hash = @import("../primitives/hash.zig").Hash;

/// Keccak-256 hash function (NOT SHA3-256)
/// Ethereum uses Keccak-256, which is the original Keccak submission
/// before it was standardized as SHA3-256 with different padding
pub const Keccak256 = std.crypto.hash.sha3.Keccak256;

/// Hash a byte slice using Keccak-256
pub fn hash(data: []const u8) Hash {
    var h: [32]u8 = undefined;
    Keccak256.hash(data, &h, .{});
    return Hash.fromBytes(h);
}

/// Hash multiple byte slices using Keccak-256
pub fn hashMulti(parts: []const []const u8) Hash {
    var hasher = Keccak256.init(.{});
    for (parts) |part| {
        hasher.update(part);
    }
    var h: [32]u8 = undefined;
    hasher.final(&h);
    return Hash.fromBytes(h);
}

/// Create a Keccak-256 hasher for incremental hashing
pub const Hasher = struct {
    inner: Keccak256,

    pub fn init() Hasher {
        return .{
            .inner = Keccak256.init(.{}),
        };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        self.inner.update(data);
    }

    pub fn final(self: *Hasher) Hash {
        var h: [32]u8 = undefined;
        self.inner.final(&h);
        return Hash.fromBytes(h);
    }

    pub fn reset(self: *Hasher) void {
        self.inner = Keccak256.init(.{});
    }
};

/// Hash a string (convenience function)
pub fn hashString(s: []const u8) Hash {
    return hash(s);
}

/// Hash two hashes together (useful for Merkle trees)
pub fn hashPair(a: Hash, b: Hash) Hash {
    var data: [64]u8 = undefined;
    @memcpy(data[0..32], &a.bytes);
    @memcpy(data[32..64], &b.bytes);
    return hash(&data);
}

/// Calculate Ethereum function selector (first 4 bytes of function signature hash)
pub fn functionSelector(signature: []const u8) [4]u8 {
    const h = hash(signature);
    var selector: [4]u8 = undefined;
    @memcpy(&selector, h.bytes[0..4]);
    return selector;
}

/// Calculate Ethereum event signature (full hash of event signature)
pub fn eventSignature(signature: []const u8) Hash {
    return hash(signature);
}

test "keccak256 basic" {
    const data = "hello world";
    const h = hash(data);

    // Verify hash is not zero
    try std.testing.expect(!h.isZero());
}

test "keccak256 empty string" {
    const data = "";
    const h = hash(data);

    // Keccak-256 of empty string is a known value
    const expected_hex = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const expected = try Hash.fromHex(expected_hex);

    try std.testing.expect(h.eql(expected));
}

test "keccak256 incremental" {
    const part1 = "hello";
    const part2 = " ";
    const part3 = "world";

    // Hash all at once
    const h1 = hash("hello world");

    // Hash incrementally
    var hasher = Hasher.init();
    hasher.update(part1);
    hasher.update(part2);
    hasher.update(part3);
    const h2 = hasher.final();

    try std.testing.expect(h1.eql(h2));
}

test "keccak256 multi" {
    const parts = [_][]const u8{ "hello", " ", "world" };
    const h1 = hashMulti(&parts);
    const h2 = hash("hello world");

    try std.testing.expect(h1.eql(h2));
}

test "function selector" {
    // transfer(address,uint256) -> 0xa9059cbb
    const sig = "transfer(address,uint256)";
    const selector = functionSelector(sig);

    try std.testing.expectEqual(@as(u8, 0xa9), selector[0]);
    try std.testing.expectEqual(@as(u8, 0x05), selector[1]);
    try std.testing.expectEqual(@as(u8, 0x9c), selector[2]);
    try std.testing.expectEqual(@as(u8, 0xbb), selector[3]);
}

test "event signature" {
    // Transfer(address,address,uint256)
    const sig = "Transfer(address,address,uint256)";
    const event_sig = eventSignature(sig);

    // This should produce a specific hash
    try std.testing.expect(!event_sig.isZero());
}

test "hash pair" {
    const a = Hash.fromBytes([_]u8{1} ** 32);
    const b = Hash.fromBytes([_]u8{2} ** 32);

    const combined = hashPair(a, b);
    try std.testing.expect(!combined.isZero());
    try std.testing.expect(!combined.eql(a));
    try std.testing.expect(!combined.eql(b));
}
