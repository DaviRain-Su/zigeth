const std = @import("std");
const RpcClient = @import("./client.zig").RpcClient;
const Hash = @import("../primitives/hash.zig").Hash;

/// Web3 namespace (web3_*) methods
pub const Web3Namespace = struct {
    client: *RpcClient,

    pub fn init(client: *RpcClient) Web3Namespace {
        return .{ .client = client };
    }

    /// web3_clientVersion - Returns the current client version
    pub fn clientVersion(self: Web3Namespace) ![]u8 {
        const result = try self.client.callNoParams("web3_clientVersion");
        _ = result;
        // TODO: Parse JSON result and return string
        return error.NotImplemented;
    }

    /// web3_sha3 - Returns Keccak-256 hash of the given data
    pub fn sha3(self: Web3Namespace, data: []const u8) !Hash {
        _ = self;
        _ = data;
        // Note: This could be implemented locally without RPC call
        // using our keccak module
        return error.NotImplemented;
    }
};

test "web3 namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const web3 = Web3Namespace.init(&client);
    try std.testing.expect(web3.client.endpoint.len > 0);
}
