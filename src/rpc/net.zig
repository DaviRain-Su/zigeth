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
        _ = result;
        // TODO: Parse JSON result
        return error.NotImplemented;
    }

    /// net_listening - Returns true if the client is actively listening for network connections
    pub fn listening(self: NetNamespace) !bool {
        const result = try self.client.callNoParams("net_listening");
        _ = result;
        return error.NotImplemented;
    }

    /// net_peerCount - Returns the number of peers currently connected
    pub fn peerCount(self: NetNamespace) !u64 {
        const result = try self.client.callNoParams("net_peerCount");
        _ = result;
        return error.NotImplemented;
    }
};

test "net namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const net = NetNamespace.init(&client);
    try std.testing.expect(net.client.endpoint.len > 0);
}
