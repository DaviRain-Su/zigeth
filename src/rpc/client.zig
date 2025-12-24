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

        // Serialize request to JSON
        var request_str = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer request_str.deinit();

        try std.json.stringify(request, .{}, request_str.writer());

        // Make HTTP request
        var transport = try HttpTransport.init(self.allocator, self.endpoint);
        defer transport.deinit();

        try transport.addHeader("Content-Type", "application/json");

        const response_body = try transport.send(request_str.items);
        defer self.allocator.free(response_body);

        // Parse response
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            self.allocator,
            response_body,
            .{},
        );
        defer parsed.deinit();

        // Extract result or error
        if (parsed.value != .object) {
            return error.InvalidJsonRpcResponse;
        }

        const obj = parsed.value.object;

        // Check for error
        if (obj.get("error")) |err| {
            if (err != .null) {
                return error.JsonRpcError;
            }
        }

        // Get result
        const result = obj.get("result") orelse return error.MissingResult;

        // Return owned copy of the result
        return try copyJsonValue(self.allocator, result);
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
        // Create empty array using fromOwnedSlice with empty slice
        const empty_slice: []std.json.Value = &[_]std.json.Value{};
        const params = std.json.Value{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(empty_slice)) };
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
        // Parse URL
        const uri = try std.Uri.parse(self.url);

        // Create HTTP client
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Build extra headers array
        var extra_headers_list = try std.ArrayList(std.http.Header).initCapacity(self.allocator, 0);
        defer extra_headers_list.deinit();

        var it = self.headers.iterator();
        while (it.next()) |entry| {
            try extra_headers_list.append(.{
                .name = entry.key_ptr.*,
                .value = entry.value_ptr.*,
            });
        }

        // Prepare headers
        var header_buffer: [4096]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &header_buffer,
            .extra_headers = extra_headers_list.items,
        });
        defer req.deinit();

        // Set transfer encoding
        req.transfer_encoding = .chunked;

        try req.send();

        // Write body
        try req.writeAll(request);
        try req.finish();

        // Wait for response
        try req.wait();

        // Check status
        if (req.response.status != .ok) {
            return error.HttpRequestFailed;
        }

        // Read response body
        var response_body = try std.ArrayList(u8).initCapacity(self.allocator, 0);
        defer response_body.deinit();

        const max_size = 10 * 1024 * 1024; // 10 MB max
        try req.reader().readAllArrayList(&response_body, max_size);

        return try response_body.toOwnedSlice(self.allocator);
    }
};

/// Deep copy a JSON value
fn copyJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    return switch (value) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .integer = i },
        .float => |f| .{ .float = f },
        .number_string => |ns| .{ .number_string = try allocator.dupe(u8, ns) },
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var new_array = std.json.Array.init(allocator);
            for (arr.items) |item| {
                const copied = try copyJsonValue(allocator, item);
                try new_array.append(copied);
            }
            break :blk .{ .array = new_array };
        },
        .object => |obj| blk: {
            var new_obj = std.json.ObjectMap.init(allocator);
            var it = obj.iterator();
            while (it.next()) |entry| {
                const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
                const value_copy = try copyJsonValue(allocator, entry.value_ptr.*);
                try new_obj.put(key_copy, value_copy);
            }
            break :blk .{ .object = new_obj };
        },
    };
}

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

test "copy json value string" {
    const allocator = std.testing.allocator;

    const original = std.json.Value{ .string = "hello" };
    const copied = try copyJsonValue(allocator, original);
    defer allocator.free(copied.string);

    try std.testing.expectEqualStrings("hello", copied.string);
}

test "copy json value integer" {
    const allocator = std.testing.allocator;

    const original = std.json.Value{ .integer = 42 };
    const copied = try copyJsonValue(allocator, original);

    try std.testing.expectEqual(@as(i64, 42), copied.integer);
}

test "copy json value bool" {
    const allocator = std.testing.allocator;

    const original = std.json.Value{ .bool = true };
    const copied = try copyJsonValue(allocator, original);

    try std.testing.expect(copied.bool);
}

test "copy json value null" {
    const allocator = std.testing.allocator;

    const original = std.json.Value{ .null = {} };
    const copied = try copyJsonValue(allocator, original);

    try std.testing.expect(copied == .null);
}

test "copy json value array" {
    const allocator = std.testing.allocator;

    var arr = std.json.Array.init(allocator);
    defer arr.deinit();

    try arr.append(.{ .integer = 1 });
    try arr.append(.{ .string = "test" });

    const original = std.json.Value{ .array = arr };
    const copied = try copyJsonValue(allocator, original);
    defer {
        allocator.free(copied.array.items[1].string);
        copied.array.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), copied.array.items.len);
    try std.testing.expectEqual(@as(i64, 1), copied.array.items[0].integer);
    try std.testing.expectEqualStrings("test", copied.array.items[1].string);
}
