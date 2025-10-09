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

        if (result != .string) {
            return error.InvalidResponse;
        }

        // Return owned copy of the string
        return try self.client.allocator.dupe(u8, result.string);
    }

    /// web3_sha3 - Returns Keccak-256 hash of the given data
    pub fn sha3(self: Web3Namespace, data: []const u8) !Hash {
        const hex_module = @import("../utils/hex.zig");

        // Convert data to hex for RPC call
        const data_hex = try hex_module.bytesToHex(self.client.allocator, data);
        defer self.client.allocator.free(data_hex);

        var params = [_]std.json.Value{
            .{ .string = data_hex },
        };

        const result = try self.client.callWithParams("web3_sha3", &params);

        if (result != .string) {
            return error.InvalidResponse;
        }

        return try Hash.fromHex(result.string);
    }

    /// Compute sha3 locally (more efficient than RPC call)
    pub fn sha3Local(data: []const u8) Hash {
        const keccak = @import("../crypto/keccak.zig");
        return keccak.hash(data);
    }
};

test "web3 namespace creation" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const web3 = Web3Namespace.init(&client);
    try std.testing.expect(web3.client.endpoint.len > 0);
}

test "sha3 local computation" {
    const data = "Hello, Ethereum!";
    const hash = Web3Namespace.sha3Local(data);

    // Should produce a valid hash (not all zeros)
    try std.testing.expect(!hash.isZero());

    // Should be deterministic
    const hash2 = Web3Namespace.sha3Local(data);
    try std.testing.expect(hash.eql(hash2));
}

test "sha3 local vs keccak" {
    const keccak = @import("../crypto/keccak.zig");

    const data = "test data";
    const web3_hash = Web3Namespace.sha3Local(data);
    const keccak_hash = keccak.hash(data);

    // Should produce the same result
    try std.testing.expect(web3_hash.eql(keccak_hash));
}

test "sha3 local empty data" {
    const hash = Web3Namespace.sha3Local(&[_]u8{});

    // Empty string has a known hash
    // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    const expected = Hash.fromBytes([_]u8{
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
    });

    try std.testing.expect(hash.eql(expected));
}
