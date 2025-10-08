const std = @import("std");
const hex = @import("../utils/hex.zig");

/// 256-bit unsigned integer for Ethereum
/// Used for balances, gas, nonces, etc.
pub const U256 = struct {
    limbs: [4]u64, // Little-endian: limbs[0] is least significant

    /// Create from a u64
    pub fn fromInt(value: u64) U256 {
        return .{
            .limbs = [_]u64{ value, 0, 0, 0 },
        };
    }

    /// Create zero
    pub fn zero() U256 {
        return .{
            .limbs = [_]u64{ 0, 0, 0, 0 },
        };
    }

    /// Create one
    pub fn one() U256 {
        return .{
            .limbs = [_]u64{ 1, 0, 0, 0 },
        };
    }

    /// Create max value (2^256 - 1)
    pub fn max() U256 {
        return .{
            .limbs = [_]u64{ std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64) },
        };
    }

    /// Create from bytes (big-endian, 32 bytes)
    pub fn fromBytes(bytes: [32]u8) U256 {
        var result = U256.zero();
        // Convert big-endian bytes to little-endian limbs
        for (0..4) |i| {
            const offset = (3 - i) * 8; // Read from end (big-endian)
            result.limbs[i] = std.mem.readInt(u64, bytes[offset..][0..8], .big);
        }
        return result;
    }

    /// Convert to bytes (big-endian, 32 bytes)
    pub fn toBytes(self: U256) [32]u8 {
        var bytes: [32]u8 = undefined;
        // Convert little-endian limbs to big-endian bytes
        for (0..4) |i| {
            const offset = (3 - i) * 8; // Write to end (big-endian)
            std.mem.writeInt(u64, bytes[offset..][0..8], self.limbs[i], .big);
        }
        return bytes;
    }

    /// Create from hex string
    pub fn fromHex(hex_str: []const u8) !U256 {
        var temp_allocator_buffer: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);
        const allocator = fba.allocator();

        const bytes = try hex.hexToBytes(allocator, hex_str);
        if (bytes.len > 32) {
            return error.ValueTooLarge;
        }

        // Pad with zeros if needed
        var padded: [32]u8 = [_]u8{0} ** 32;
        const offset = 32 - bytes.len;
        @memcpy(padded[offset..], bytes);

        return fromBytes(padded);
    }

    /// Convert to hex string
    pub fn toHex(self: U256, allocator: std.mem.Allocator) ![]u8 {
        const bytes = self.toBytes();
        return try hex.bytesToHex(allocator, &bytes);
    }

    /// Check if zero
    pub fn isZero(self: U256) bool {
        return self.limbs[0] == 0 and self.limbs[1] == 0 and self.limbs[2] == 0 and self.limbs[3] == 0;
    }

    /// Compare equality
    pub fn eql(self: U256, other: U256) bool {
        return std.mem.eql(u64, &self.limbs, &other.limbs);
    }

    /// Compare less than
    pub fn lt(self: U256, other: U256) bool {
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (self.limbs[i] < other.limbs[i]) return true;
            if (self.limbs[i] > other.limbs[i]) return false;
        }
        return false;
    }

    /// Compare less than or equal
    pub fn lte(self: U256, other: U256) bool {
        return self.eql(other) or self.lt(other);
    }

    /// Compare greater than
    pub fn gt(self: U256, other: U256) bool {
        return !self.lte(other);
    }

    /// Compare greater than or equal
    pub fn gte(self: U256, other: U256) bool {
        return !self.lt(other);
    }

    /// Add two U256 values
    pub fn add(self: U256, other: U256) U256 {
        var result = U256.zero();
        var carry: u64 = 0;

        for (0..4) |i| {
            const sum = @addWithOverflow(self.limbs[i], other.limbs[i]);
            const sum_with_carry = @addWithOverflow(sum[0], carry);

            result.limbs[i] = sum_with_carry[0];
            carry = sum[1] + sum_with_carry[1];
        }

        return result;
    }

    /// Subtract two U256 values (assumes self >= other)
    pub fn sub(self: U256, other: U256) U256 {
        var result = U256.zero();
        var borrow: u64 = 0;

        for (0..4) |i| {
            const diff = @subWithOverflow(self.limbs[i], other.limbs[i]);
            const diff_with_borrow = @subWithOverflow(diff[0], borrow);

            result.limbs[i] = diff_with_borrow[0];
            borrow = diff[1] + diff_with_borrow[1];
        }

        return result;
    }

    /// Multiply by a u64
    pub fn mulScalar(self: U256, scalar: u64) U256 {
        var result = U256.zero();
        var carry: u64 = 0;

        for (0..4) |i| {
            const prod = @as(u128, self.limbs[i]) * @as(u128, scalar) + carry;
            result.limbs[i] = @truncate(prod);
            carry = @truncate(prod >> 64);
        }

        return result;
    }

    /// Divide by a u64, returns (quotient, remainder)
    pub fn divScalar(self: U256, scalar: u64) struct { quotient: U256, remainder: u64 } {
        var quotient = U256.zero();
        var remainder: u64 = 0;

        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            const dividend = (@as(u128, remainder) << 64) | self.limbs[i];
            quotient.limbs[i] = @truncate(dividend / scalar);
            remainder = @truncate(dividend % scalar);
        }

        return .{ .quotient = quotient, .remainder = remainder };
    }

    /// Convert to u64 (truncates if too large)
    pub fn toU64(self: U256) u64 {
        return self.limbs[0];
    }

    /// Try to convert to u64 (returns error if too large)
    pub fn tryToU64(self: U256) !u64 {
        if (self.limbs[1] != 0 or self.limbs[2] != 0 or self.limbs[3] != 0) {
            return error.ValueTooLarge;
        }
        return self.limbs[0];
    }

    /// Format for printing
    pub fn format(
        self: U256,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        // Simple decimal conversion for display
        if (self.isZero()) {
            try writer.print("0", .{});
            return;
        }

        // For simplicity, just show hex representation
        try writer.print("0x", .{});
        var started = false;
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (started or self.limbs[i] != 0) {
                if (started) {
                    try writer.print("{x:0>16}", .{self.limbs[i]});
                } else {
                    try writer.print("{x}", .{self.limbs[i]});
                    started = true;
                }
            }
        }
    }
};

test "u256 from int" {
    const val = U256.fromInt(42);
    try std.testing.expectEqual(@as(u64, 42), val.limbs[0]);
    try std.testing.expectEqual(@as(u64, 0), val.limbs[1]);
}

test "u256 zero and one" {
    const zero = U256.zero();
    const one = U256.one();

    try std.testing.expect(zero.isZero());
    try std.testing.expect(!one.isZero());
    try std.testing.expectEqual(@as(u64, 1), one.limbs[0]);
}

test "u256 from bytes" {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    bytes[31] = 42; // Last byte (big-endian)

    const val = U256.fromBytes(bytes);
    try std.testing.expectEqual(@as(u64, 42), val.limbs[0]);
}

test "u256 to bytes" {
    const val = U256.fromInt(42);
    const bytes = val.toBytes();

    try std.testing.expectEqual(@as(u8, 42), bytes[31]);
    try std.testing.expectEqual(@as(u8, 0), bytes[0]);
}

test "u256 comparison" {
    const a = U256.fromInt(100);
    const b = U256.fromInt(200);
    const c = U256.fromInt(100);

    try std.testing.expect(a.lt(b));
    try std.testing.expect(!b.lt(a));
    try std.testing.expect(a.eql(c));
    try std.testing.expect(!a.eql(b));
}

test "u256 addition" {
    const a = U256.fromInt(100);
    const b = U256.fromInt(50);
    const result = a.add(b);

    try std.testing.expectEqual(@as(u64, 150), result.limbs[0]);
}

test "u256 subtraction" {
    const a = U256.fromInt(100);
    const b = U256.fromInt(50);
    const result = a.sub(b);

    try std.testing.expectEqual(@as(u64, 50), result.limbs[0]);
}

test "u256 multiplication" {
    const a = U256.fromInt(100);
    const result = a.mulScalar(3);

    try std.testing.expectEqual(@as(u64, 300), result.limbs[0]);
}

test "u256 division" {
    const a = U256.fromInt(100);
    const result = a.divScalar(3);

    try std.testing.expectEqual(@as(u64, 33), result.quotient.limbs[0]);
    try std.testing.expectEqual(@as(u64, 1), result.remainder);
}

test "u256 from hex" {
    const allocator = std.testing.allocator;

    const val = try U256.fromHex("0x2a"); // 42 in decimal
    try std.testing.expectEqual(@as(u64, 42), val.limbs[0]);

    const hex_str = try val.toHex(allocator);
    defer allocator.free(hex_str);
}

test "u256 max value" {
    const max_val = U256.max();
    try std.testing.expect(!max_val.isZero());
    try std.testing.expectEqual(std.math.maxInt(u64), max_val.limbs[0]);
    try std.testing.expectEqual(std.math.maxInt(u64), max_val.limbs[3]);
}
