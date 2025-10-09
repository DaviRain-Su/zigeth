const std = @import("std");
const encode = @import("./encode.zig");
const decode = @import("./decode.zig");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256; // Legacy compatibility
const uint_utils = @import("../primitives/uint.zig");
const Signature = @import("../primitives/signature.zig").Signature;
const Transaction = @import("../types/transaction.zig").Transaction;
const TransactionType = @import("../types/transaction.zig").TransactionType;

/// Helper for encoding Ethereum transactions
pub const TransactionEncoder = struct {
    /// Encode a legacy transaction for signing (without signature)
    pub fn encodeLegacyForSigning(
        allocator: std.mem.Allocator,
        tx: Transaction,
    ) ![]u8 {
        if (tx.type != .legacy) {
            return error.NotLegacyTransaction;
        }

        var items = std.ArrayList(encode.RlpItem).init(allocator);
        defer items.deinit();

        // nonce
        try items.append(.{ .uint = tx.nonce });

        // gas_price
        const gas_price_bytes = uint_utils.u256ToBytes(tx.gas_price.?);
        try items.append(.{ .bytes = &gas_price_bytes });

        // gas_limit
        try items.append(.{ .uint = tx.gas_limit });

        // to (or empty for contract creation)
        if (tx.to) |to_addr| {
            try items.append(.{ .bytes = &to_addr.bytes });
        } else {
            try items.append(.{ .bytes = &[_]u8{} });
        }

        // value
        const value_bytes = uint_utils.u256ToBytes(tx.value);
        try items.append(.{ .bytes = &value_bytes });

        // data
        try items.append(.{ .bytes = tx.data.data });

        // For EIP-155: v, r, s (chain_id, 0, 0)
        if (tx.chain_id) |chain_id| {
            try items.append(.{ .uint = chain_id });
            try items.append(.{ .uint = 0 });
            try items.append(.{ .uint = 0 });
        }

        return try encode.encodeList(allocator, items.items);
    }

    /// Encode a signed legacy transaction
    pub fn encodeLegacySigned(
        allocator: std.mem.Allocator,
        tx: Transaction,
    ) ![]u8 {
        if (tx.type != .legacy) {
            return error.NotLegacyTransaction;
        }

        if (tx.signature == null) {
            return error.TransactionNotSigned;
        }

        var items = std.ArrayList(encode.RlpItem).init(allocator);
        defer items.deinit();

        // nonce
        try items.append(.{ .uint = tx.nonce });

        // gas_price
        const gas_price_bytes = uint_utils.u256ToBytes(tx.gas_price.?);
        try items.append(.{ .bytes = &gas_price_bytes });

        // gas_limit
        try items.append(.{ .uint = tx.gas_limit });

        // to
        if (tx.to) |to_addr| {
            try items.append(.{ .bytes = &to_addr.bytes });
        } else {
            try items.append(.{ .bytes = &[_]u8{} });
        }

        // value
        const value_bytes = uint_utils.u256ToBytes(tx.value);
        try items.append(.{ .bytes = &value_bytes });

        // data
        try items.append(.{ .bytes = tx.data.data });

        // Signature (v, r, s)
        const sig = tx.signature.?;
        try items.append(.{ .uint = sig.v });

        // r and s are already [32]u8 arrays
        try items.append(.{ .bytes = &sig.r });
        try items.append(.{ .bytes = &sig.s });

        return try encode.encodeList(allocator, items.items);
    }
};

/// Helper for encoding common Ethereum data structures
pub const EthereumEncoder = struct {
    /// Encode an address
    pub fn encodeAddress(allocator: std.mem.Allocator, address: Address) ![]u8 {
        return try encode.encodeBytes(allocator, &address.bytes);
    }

    /// Encode a hash
    pub fn encodeHash(allocator: std.mem.Allocator, hash: Hash) ![]u8 {
        return try encode.encodeBytes(allocator, &hash.bytes);
    }

    /// Encode a U256
    pub fn encodeU256(allocator: std.mem.Allocator, value: U256) ![]u8 {
        const bytes = value.toBytes();

        // Find first non-zero byte
        var start: usize = 0;
        while (start < 32 and bytes[start] == 0) : (start += 1) {}

        if (start == 32) {
            // All zeros
            return try encode.encodeBytes(allocator, &[_]u8{});
        }

        return try encode.encodeBytes(allocator, bytes[start..]);
    }

    /// Encode an address list
    pub fn encodeAddressList(
        allocator: std.mem.Allocator,
        addresses: []const Address,
    ) ![]u8 {
        var items = std.ArrayList(encode.RlpItem).init(allocator);
        defer items.deinit();

        for (addresses) |addr| {
            try items.append(.{ .bytes = &addr.bytes });
        }

        return try encode.encodeList(allocator, items.items);
    }

    /// Encode a hash list
    pub fn encodeHashList(
        allocator: std.mem.Allocator,
        hashes: []const Hash,
    ) ![]u8 {
        var items = std.ArrayList(encode.RlpItem).init(allocator);
        defer items.deinit();

        for (hashes) |hash| {
            try items.append(.{ .bytes = &hash.bytes });
        }

        return try encode.encodeList(allocator, items.items);
    }
};

/// Helper for decoding common Ethereum data structures
pub const EthereumDecoder = struct {
    /// Decode an address from RLP bytes
    pub fn decodeAddress(data: []const u8) !Address {
        if (data.len != 20) {
            return error.InvalidAddressLength;
        }
        var bytes: [20]u8 = undefined;
        @memcpy(&bytes, data);
        return Address.fromBytes(bytes);
    }

    /// Decode a hash from RLP bytes
    pub fn decodeHash(data: []const u8) !Hash {
        if (data.len != 32) {
            return error.InvalidHashLength;
        }
        var bytes: [32]u8 = undefined;
        @memcpy(&bytes, data);
        return Hash.fromBytes(bytes);
    }

    /// Decode a U256 from RLP bytes
    pub fn decodeU256(data: []const u8) !U256 {
        if (data.len == 0) {
            return U256.zero();
        }
        if (data.len > 32) {
            return error.ValueTooLarge;
        }

        // Pad to 32 bytes
        var bytes: [32]u8 = [_]u8{0} ** 32;
        const offset = 32 - data.len;
        @memcpy(bytes[offset..], data);

        return U256.fromBytes(bytes);
    }
};

test "encode address" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x42} ** 20);
    const encoded = try EthereumEncoder.encodeAddress(allocator, addr);
    defer allocator.free(encoded);

    // 20 bytes with prefix
    try std.testing.expectEqual(@as(usize, 21), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x80 + 20), encoded[0]);
}

test "encode hash" {
    const allocator = std.testing.allocator;

    const hash = Hash.fromBytes([_]u8{0xab} ** 32);
    const encoded = try EthereumEncoder.encodeHash(allocator, hash);
    defer allocator.free(encoded);

    // 32 bytes with prefix
    try std.testing.expectEqual(@as(usize, 33), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x80 + 32), encoded[0]);
}

test "encode U256 zero" {
    const allocator = std.testing.allocator;

    const value = U256.zero();
    const encoded = try EthereumEncoder.encodeU256(allocator, value);
    defer allocator.free(encoded);

    // Empty bytes
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, encoded);
}

test "encode U256 small" {
    const allocator = std.testing.allocator;

    const value = U256.fromInt(42);
    const encoded = try EthereumEncoder.encodeU256(allocator, value);
    defer allocator.free(encoded);

    // Single byte
    try std.testing.expectEqualSlices(u8, &[_]u8{0x2a}, encoded);
}

test "decode address" {
    const addr_bytes = [_]u8{0x12} ** 20;
    const addr = try EthereumDecoder.decodeAddress(&addr_bytes);

    try std.testing.expectEqual(Address.fromBytes(addr_bytes), addr);
}

test "decode hash" {
    const hash_bytes = [_]u8{0xab} ** 32;
    const hash = try EthereumDecoder.decodeHash(&hash_bytes);

    try std.testing.expectEqual(Hash.fromBytes(hash_bytes), hash);
}

test "decode U256 zero" {
    const value = try EthereumDecoder.decodeU256(&[_]u8{});
    try std.testing.expect(value.isZero());
}

test "decode U256 small" {
    const value = try EthereumDecoder.decodeU256(&[_]u8{0x2a});
    try std.testing.expect(value.eql(U256.fromInt(42)));
}

test "encode address list" {
    const allocator = std.testing.allocator;

    const addresses = [_]Address{
        Address.fromBytes([_]u8{0x11} ** 20),
        Address.fromBytes([_]u8{0x22} ** 20),
    };

    const encoded = try EthereumEncoder.encodeAddressList(allocator, &addresses);
    defer allocator.free(encoded);

    // List prefix + 2 addresses
    try std.testing.expect(encoded.len > 40);
}

test "encode hash list" {
    const allocator = std.testing.allocator;

    const hashes = [_]Hash{
        Hash.fromBytes([_]u8{0xaa} ** 32),
        Hash.fromBytes([_]u8{0xbb} ** 32),
    };

    const encoded = try EthereumEncoder.encodeHashList(allocator, &hashes);
    defer allocator.free(encoded);

    // List prefix + 2 hashes
    try std.testing.expect(encoded.len > 64);
}

test "roundtrip U256 encoding" {
    const allocator = std.testing.allocator;

    const original = U256.fromInt(0x123456);
    const encoded = try EthereumEncoder.encodeU256(allocator, original);
    defer allocator.free(encoded);

    // Decode the RLP first
    const rlp_value = try decode.decode(allocator, encoded);
    defer rlp_value.deinit(allocator);

    const bytes = try rlp_value.getBytes();
    const decoded = try EthereumDecoder.decodeU256(bytes);

    try std.testing.expect(decoded.eql(original));
}
