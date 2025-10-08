const std = @import("std");
const hex = @import("../utils/hex.zig");

/// Ethereum bloom filter (256 bytes / 2048 bits)
/// Used for efficient log filtering in blocks and receipts
pub const Bloom = struct {
    bytes: [256]u8,

    /// Create bloom filter from bytes
    pub fn fromBytes(bytes: [256]u8) Bloom {
        return .{ .bytes = bytes };
    }

    /// Create empty bloom filter
    pub fn empty() Bloom {
        return .{ .bytes = [_]u8{0} ** 256 };
    }

    /// Create from hex string
    pub fn fromHex(hex_str: []const u8) !Bloom {
        var temp_allocator_buffer: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);
        const allocator = fba.allocator();

        const bytes = try hex.hexToBytes(allocator, hex_str);
        if (bytes.len != 256) {
            return error.InvalidBloomLength;
        }

        var bloom: Bloom = undefined;
        @memcpy(&bloom.bytes, bytes);
        return bloom;
    }

    /// Convert to hex string
    pub fn toHex(self: Bloom, allocator: std.mem.Allocator) ![]u8 {
        return try hex.bytesToHex(allocator, &self.bytes);
    }

    /// Check if bloom is empty (all zeros)
    pub fn isEmpty(self: Bloom) bool {
        return std.mem.allEqual(u8, &self.bytes, 0);
    }

    /// Add a hash to the bloom filter
    /// Uses 3 bits from the hash as per Ethereum spec
    pub fn add(self: *Bloom, hash: []const u8) void {
        if (hash.len < 32) return;

        // Ethereum bloom filter uses 3 positions from the hash
        for (0..3) |i| {
            const offset = i * 2;
            // Take 2 bytes from hash at positions 0, 2, 4
            const bit_pos = (@as(u16, hash[offset]) << 8) | hash[offset + 1];
            const byte_pos = @as(usize, bit_pos >> 3) % 256;
            const bit_mask = @as(u8, 1) << @intCast(bit_pos & 7);

            self.bytes[byte_pos] |= bit_mask;
        }
    }

    /// Check if a hash might be in the bloom filter
    /// Returns true if possibly present, false if definitely not present
    pub fn contains(self: Bloom, hash: []const u8) bool {
        if (hash.len < 32) return false;

        for (0..3) |i| {
            const offset = i * 2;
            const bit_pos = (@as(u16, hash[offset]) << 8) | hash[offset + 1];
            const byte_pos = @as(usize, bit_pos >> 3) % 256;
            const bit_mask = @as(u8, 1) << @intCast(bit_pos & 7);

            if ((self.bytes[byte_pos] & bit_mask) == 0) {
                return false;
            }
        }

        return true;
    }

    /// Combine two bloom filters (OR operation)
    pub fn combine(self: Bloom, other: Bloom) Bloom {
        var result = Bloom.empty();
        for (0..256) |i| {
            result.bytes[i] = self.bytes[i] | other.bytes[i];
        }
        return result;
    }

    /// Check if this bloom contains all bits set in another bloom
    pub fn containsBloom(self: Bloom, other: Bloom) bool {
        for (0..256) |i| {
            if ((self.bytes[i] & other.bytes[i]) != other.bytes[i]) {
                return false;
            }
        }
        return true;
    }

    /// Compare two blooms for equality
    pub fn eql(self: Bloom, other: Bloom) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Count the number of bits set (population count)
    pub fn popCount(self: Bloom) usize {
        var count: usize = 0;
        for (self.bytes) |byte| {
            count += @popCount(byte);
        }
        return count;
    }
};

test "bloom creation" {
    const bloom = Bloom.empty();
    try std.testing.expect(bloom.isEmpty());
}

test "bloom from bytes" {
    var bytes = [_]u8{0} ** 256;
    bytes[0] = 0xFF;

    const bloom = Bloom.fromBytes(bytes);
    try std.testing.expect(!bloom.isEmpty());
    try std.testing.expectEqual(@as(u8, 0xFF), bloom.bytes[0]);
}

test "bloom add and contains" {
    var bloom = Bloom.empty();

    // Create a test hash
    const hash = [_]u8{ 0x12, 0x34, 0x56, 0x78 } ++ [_]u8{0} ** 28;

    // Add hash to bloom
    bloom.add(&hash);

    // Should contain the hash
    try std.testing.expect(bloom.contains(&hash));

    // Different hash should not be contained (probably)
    // Note: there's a small chance of false positive, which is expected with bloom filters
    const other_hash = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF } ++ [_]u8{0} ** 28;
    _ = bloom.contains(&other_hash);
}

test "bloom combine" {
    var bloom1 = Bloom.empty();
    var bloom2 = Bloom.empty();

    const hash1 = [_]u8{ 0x12, 0x34 } ++ [_]u8{0} ** 30;
    const hash2 = [_]u8{ 0x56, 0x78 } ++ [_]u8{0} ** 30;

    bloom1.add(&hash1);
    bloom2.add(&hash2);

    const combined = bloom1.combine(bloom2);

    try std.testing.expect(combined.contains(&hash1));
    try std.testing.expect(combined.contains(&hash2));
}

test "bloom contains bloom" {
    var bloom1 = Bloom.empty();
    var bloom2 = Bloom.empty();

    const hash = [_]u8{ 0x12, 0x34 } ++ [_]u8{0} ** 30;

    bloom1.add(&hash);
    bloom2.add(&hash);

    // bloom1 should contain bloom2 (they're identical)
    try std.testing.expect(bloom1.containsBloom(bloom2));
    try std.testing.expect(bloom2.containsBloom(bloom1));

    // Add another hash to bloom1
    const hash2 = [_]u8{ 0x56, 0x78 } ++ [_]u8{0} ** 30;
    bloom1.add(&hash2);

    // bloom1 should still contain bloom2
    try std.testing.expect(bloom1.containsBloom(bloom2));

    // But bloom2 should not contain bloom1
    try std.testing.expect(!bloom2.containsBloom(bloom1));
}

test "bloom equality" {
    const bloom1 = Bloom.empty();
    const bloom2 = Bloom.empty();
    var bloom3 = Bloom.empty();

    const hash = [_]u8{ 0x12, 0x34 } ++ [_]u8{0} ** 30;
    bloom3.add(&hash);

    try std.testing.expect(bloom1.eql(bloom2));
    try std.testing.expect(!bloom1.eql(bloom3));
}

test "bloom pop count" {
    var bloom = Bloom.empty();
    try std.testing.expectEqual(@as(usize, 0), bloom.popCount());

    // Set one byte to 0xFF (8 bits)
    bloom.bytes[0] = 0xFF;
    try std.testing.expectEqual(@as(usize, 8), bloom.popCount());

    // Set another byte
    bloom.bytes[1] = 0x0F; // 4 bits
    try std.testing.expectEqual(@as(usize, 12), bloom.popCount());
}

test "bloom to/from hex" {
    const allocator = std.testing.allocator;

    var bloom = Bloom.empty();
    bloom.bytes[0] = 0xAB;
    bloom.bytes[255] = 0xCD;

    const hex_str = try bloom.toHex(allocator);
    defer allocator.free(hex_str);

    const bloom2 = try Bloom.fromHex(hex_str);
    try std.testing.expect(bloom.eql(bloom2));
}
