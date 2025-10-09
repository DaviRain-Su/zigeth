const std = @import("std");
const RpcClient = @import("./client.zig").RpcClient;

/// Network namespace (net_*) methods
pub const NetNamespace = struct {
    client: *RpcClient,

    pub fn init(client: *RpcClient) NetNamespace {
        return .{ .client = client };
    }

    /// net_version - Returns the current network ID
    pub fn version(self: NetNamespace) !u64 {
        const result = try self.client.callNoParams("net_version");

        if (result != .string) {
            return error.InvalidResponse;
        }

        // Network ID is returned as a decimal string (not hex)
        return try std.fmt.parseInt(u64, result.string, 10);
    }

    /// net_listening - Returns true if the client is actively listening for network connections
    pub fn listening(self: NetNamespace) !bool {
        const result = try self.client.callNoParams("net_listening");

        if (result != .bool) {
            return error.InvalidResponse;
        }

        return result.bool;
    }

    /// net_peerCount - Returns the number of peers currently connected
    pub fn peerCount(self: NetNamespace) !u64 {
        const result = try self.client.callNoParams("net_peerCount");

        if (result != .string) {
            return error.InvalidResponse;
        }

        // Parse hex string to u64
        return try parseHexU64(result.string);
    }
};

/// Parse hex string to u64
fn parseHexU64(hex_str: []const u8) !u64 {
    const str = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
    return try std.fmt.parseInt(u64, str, 16);
}

test "net namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const net = NetNamespace.init(&client);
    try std.testing.expect(net.client.endpoint.len > 0);
}

test "parse hex u64" {
    const value1 = try parseHexU64("0x10");
    try std.testing.expectEqual(@as(u64, 16), value1);

    const value2 = try parseHexU64("0xff");
    try std.testing.expectEqual(@as(u64, 255), value2);

    const value3 = try parseHexU64("1a");
    try std.testing.expectEqual(@as(u64, 26), value3);
}
