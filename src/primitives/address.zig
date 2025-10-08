const std = @import("std");
const hex = @import("../utils/hex.zig");

/// Ethereum address (20 bytes)
pub const Address = struct {
    bytes: [20]u8,

    pub fn fromBytes(bytes: [20]u8) Address {
        return .{ .bytes = bytes };
    }

    pub fn fromHex(hex_str: []const u8) !Address {
        var temp_allocator_buffer: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);
        const allocator = fba.allocator();

        const bytes = try hex.hexToBytes(allocator, hex_str);
        if (bytes.len != 20) {
            return error.InvalidAddressLength;
        }

        var addr: Address = undefined;
        @memcpy(&addr.bytes, bytes);
        return addr;
    }

    pub fn toHex(self: Address, allocator: std.mem.Allocator) ![]u8 {
        return try hex.bytesToHex(allocator, &self.bytes);
    }

    pub fn isZero(self: Address) bool {
        return std.mem.eql(u8, &self.bytes, &[_]u8{0} ** 20);
    }
};

test "address creation" {
    const addr = Address.fromBytes([_]u8{0} ** 20);
    try std.testing.expect(addr.isZero());
}
