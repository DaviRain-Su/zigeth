const std = @import("std");
const types = @import("./types.zig");

/// JSON-RPC client for Ethereum
pub const RpcClient = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    next_id: u64,

    /// Create a new RPC client
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) !RpcClient {
        const endpoint_copy = try allocator.dupe(u8, endpoint);
        return .{
            .allocator = allocator,
            .endpoint = endpoint_copy,
            .next_id = 1,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: RpcClient) void {
        self.allocator.free(self.endpoint);
    }

    /// Get next request ID
    fn getNextId(self: *RpcClient) u64 {
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    /// Make a JSON-RPC call
    pub fn call(
        self: *RpcClient,
        method: []const u8,
        params: std.json.Value,
    ) !std.json.Value {
        const id = self.getNextId();
        const request = try types.JsonRpcRequest.init(self.allocator, method, params, id);

        // TODO: Implement actual HTTP request
        // For now, return a placeholder
        _ = request;
        return error.NotImplemented;
    }

    /// Make a JSON-RPC call with array parameters
    pub fn callWithParams(
        self: *RpcClient,
        method: []const u8,
        params: []const std.json.Value,
    ) !std.json.Value {
        const params_array = std.json.Value{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(params)) };
        return try self.call(method, params_array);
    }

    /// Make a JSON-RPC call with no parameters
    pub fn callNoParams(self: *RpcClient, method: []const u8) !std.json.Value {
        const params = std.json.Value{ .array = std.json.Array.init(self.allocator) };
        return try self.call(method, params);
    }
};

/// HTTP transport for RPC client
pub const HttpTransport = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    headers: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator, url: []const u8) !HttpTransport {
        const url_copy = try allocator.dupe(u8, url);
        return .{
            .allocator = allocator,
            .url = url_copy,
            .headers = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *HttpTransport) void {
        self.allocator.free(self.url);

        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }

    pub fn addHeader(self: *HttpTransport, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.headers.put(key_copy, value_copy);
    }

    pub fn send(self: *HttpTransport, request: []const u8) ![]u8 {
        // TODO: Implement actual HTTP request using std.http.Client
        _ = self;
        _ = request;
        return error.NotImplemented;
    }
};

test "rpc client creation" {
    const allocator = std.testing.allocator;

    const client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    try std.testing.expectEqualStrings("http://localhost:8545", client.endpoint);
    try std.testing.expectEqual(@as(u64, 1), client.next_id);
}

test "rpc client id increment" {
    const allocator = std.testing.allocator;

    var client = try RpcClient.init(allocator, "http://localhost:8545");
    defer client.deinit();

    const id1 = client.getNextId();
    const id2 = client.getNextId();
    const id3 = client.getNextId();

    try std.testing.expectEqual(@as(u64, 1), id1);
    try std.testing.expectEqual(@as(u64, 2), id2);
    try std.testing.expectEqual(@as(u64, 3), id3);
}

test "http transport creation" {
    const allocator = std.testing.allocator;

    var transport = try HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();

    try std.testing.expectEqualStrings("http://localhost:8545", transport.url);
}

test "http transport headers" {
    const allocator = std.testing.allocator;

    var transport = try HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();

    try transport.addHeader("Content-Type", "application/json");
    try transport.addHeader("Authorization", "Bearer token123");

    try std.testing.expectEqual(@as(usize, 2), transport.headers.count());
}
