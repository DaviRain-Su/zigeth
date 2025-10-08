const std = @import("std");
const hex = @import("../utils/hex.zig");

/// ECDSA signature for Ethereum transactions
/// Consists of r (32 bytes), s (32 bytes), and v (1 byte recovery id)
pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,
    v: u8,

    /// Create signature from components
    pub fn init(r: [32]u8, s: [32]u8, v: u8) Signature {
        return .{
            .r = r,
            .s = s,
            .v = v,
        };
    }

    /// Create signature from 65-byte slice (r + s + v)
    pub fn fromBytes(bytes: []const u8) !Signature {
        if (bytes.len != 65) {
            return error.InvalidSignatureLength;
        }

        var sig: Signature = undefined;
        @memcpy(&sig.r, bytes[0..32]);
        @memcpy(&sig.s, bytes[32..64]);
        sig.v = bytes[64];

        return sig;
    }

    /// Create signature from hex string (130 hex chars + 2 for v, optionally with 0x prefix)
    pub fn fromHex(allocator: std.mem.Allocator, hex_str: []const u8) !Signature {
        const bytes = try hex.hexToBytes(allocator, hex_str);
        defer allocator.free(bytes);

        return try fromBytes(bytes);
    }

    /// Convert signature to bytes (65 bytes: r + s + v)
    pub fn toBytes(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, 65);
        @memcpy(result[0..32], &self.r);
        @memcpy(result[32..64], &self.s);
        result[64] = self.v;
        return result;
    }

    /// Convert signature to hex string
    pub fn toHex(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try self.toBytes(allocator);
        defer allocator.free(bytes);
        return try hex.bytesToHex(allocator, bytes);
    }

    /// Get compact form (without chain ID for legacy signatures)
    pub fn getCompactV(self: Signature) u8 {
        if (self.v >= 27) {
            return self.v - 27;
        }
        return self.v;
    }

    /// Get recovery ID (0 or 1)
    pub fn getRecoveryId(self: Signature) u8 {
        return self.getCompactV() % 2;
    }

    /// Extract chain ID from v (for EIP-155 signatures)
    pub fn getChainId(self: Signature) ?u64 {
        if (self.v >= 35) {
            return (self.v - 35) / 2;
        }
        return null;
    }

    /// Create EIP-155 compliant v value
    pub fn eip155V(chain_id: u64, recovery_id: u8) u8 {
        return @intCast(chain_id * 2 + 35 + recovery_id);
    }

    /// Verify signature is valid (basic checks)
    pub fn isValid(self: Signature) bool {
        // Check that r and s are not zero
        const r_zero = std.mem.allEqual(u8, &self.r, 0);
        const s_zero = std.mem.allEqual(u8, &self.s, 0);

        if (r_zero or s_zero) {
            return false;
        }

        // V should be 27, 28, or EIP-155 compliant (>= 35)
        if (self.v != 27 and self.v != 28 and self.v < 35) {
            return false;
        }

        return true;
    }

    /// Compare two signatures
    pub fn eql(self: Signature, other: Signature) bool {
        return std.mem.eql(u8, &self.r, &other.r) and
            std.mem.eql(u8, &self.s, &other.s) and
            self.v == other.v;
    }
};

test "signature creation" {
    const r = [_]u8{1} ** 32;
    const s = [_]u8{2} ** 32;
    const v: u8 = 27;

    const sig = Signature.init(r, s, v);

    try std.testing.expectEqual(v, sig.v);
    try std.testing.expect(std.mem.eql(u8, &r, &sig.r));
    try std.testing.expect(std.mem.eql(u8, &s, &sig.s));
}

test "signature from bytes" {
    var bytes: [65]u8 = undefined;
    @memset(bytes[0..32], 1);
    @memset(bytes[32..64], 2);
    bytes[64] = 27;

    const sig = try Signature.fromBytes(&bytes);

    try std.testing.expectEqual(@as(u8, 27), sig.v);
    try std.testing.expect(std.mem.allEqual(u8, &sig.r, 1));
    try std.testing.expect(std.mem.allEqual(u8, &sig.s, 2));
}

test "signature to bytes" {
    const allocator = std.testing.allocator;

    const r = [_]u8{1} ** 32;
    const s = [_]u8{2} ** 32;
    const v: u8 = 27;

    const sig = Signature.init(r, s, v);
    const bytes = try sig.toBytes(allocator);
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(usize, 65), bytes.len);
    try std.testing.expectEqual(@as(u8, 27), bytes[64]);
}

test "signature recovery id" {
    const sig1 = Signature.init([_]u8{0} ** 32, [_]u8{0} ** 32, 27);
    const sig2 = Signature.init([_]u8{0} ** 32, [_]u8{0} ** 32, 28);

    try std.testing.expectEqual(@as(u8, 0), sig1.getRecoveryId());
    try std.testing.expectEqual(@as(u8, 1), sig2.getRecoveryId());
}

test "signature chain id extraction" {
    // Legacy signature (no chain ID)
    const sig_legacy = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, 27);
    try std.testing.expectEqual(@as(?u64, null), sig_legacy.getChainId());

    // EIP-155 signature with chain ID 1 (Ethereum mainnet)
    const v_mainnet = Signature.eip155V(1, 0);
    const sig_mainnet = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, v_mainnet);
    try std.testing.expectEqual(@as(?u64, 1), sig_mainnet.getChainId());

    // Chain ID 137 (Polygon)
    const v_polygon = Signature.eip155V(137, 1);
    const sig_polygon = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, v_polygon);
    try std.testing.expectEqual(@as(?u64, 137), sig_polygon.getChainId());
}

test "signature validation" {
    // Valid signature
    const sig_valid = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, 27);
    try std.testing.expect(sig_valid.isValid());

    // Invalid: zero r
    const sig_zero_r = Signature.init([_]u8{0} ** 32, [_]u8{2} ** 32, 27);
    try std.testing.expect(!sig_zero_r.isValid());

    // Invalid: zero s
    const sig_zero_s = Signature.init([_]u8{1} ** 32, [_]u8{0} ** 32, 27);
    try std.testing.expect(!sig_zero_s.isValid());

    // Invalid: bad v
    const sig_bad_v = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, 5);
    try std.testing.expect(!sig_bad_v.isValid());
}

test "signature equality" {
    const sig1 = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, 27);
    const sig2 = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, 27);
    const sig3 = Signature.init([_]u8{1} ** 32, [_]u8{2} ** 32, 28);

    try std.testing.expect(sig1.eql(sig2));
    try std.testing.expect(!sig1.eql(sig3));
}

test "eip155 v calculation" {
    // Mainnet (chain_id=1) with recovery_id=0
    try std.testing.expectEqual(@as(u8, 37), Signature.eip155V(1, 0));

    // Mainnet (chain_id=1) with recovery_id=1
    try std.testing.expectEqual(@as(u8, 38), Signature.eip155V(1, 1));

    // Polygon (chain_id=137) with recovery_id=0
    try std.testing.expectEqual(@as(u8, 309), Signature.eip155V(137, 0));
}
