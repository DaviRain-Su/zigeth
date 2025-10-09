const std = @import("std");
const Provider = @import("./provider.zig").Provider;

/// IPC provider for local Ethereum nodes (Unix socket communication)
pub const IpcProvider = struct {
    provider: Provider,
    socket_path: []const u8,
    allocator: std.mem.Allocator,

    /// Create a new IPC provider
    pub fn init(allocator: std.mem.Allocator, socket_path: []const u8) !IpcProvider {
        // For IPC, we use a dummy HTTP endpoint since actual communication
        // would happen through Unix sockets
        const provider = try Provider.init(allocator, "ipc://local");
        const path_copy = try allocator.dupe(u8, socket_path);

        return .{
            .provider = provider,
            .socket_path = path_copy,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: IpcProvider) void {
        self.allocator.free(self.socket_path);
        self.provider.deinit();
    }

    /// Get the underlying provider
    pub fn getProvider(self: *IpcProvider) *Provider {
        return @constCast(&self.provider);
    }

    /// Connect to IPC socket
    pub fn connect(self: *IpcProvider) !void {
        // TODO: Implement actual Unix socket connection
        _ = self;
    }

    /// Disconnect from IPC socket
    pub fn disconnect(self: *IpcProvider) void {
        // TODO: Implement actual Unix socket disconnection
        _ = self;
    }

    /// Check if connected
    pub fn isConnected(self: IpcProvider) bool {
        // TODO: Check actual IPC connection status
        _ = self;
        return false;
    }

    /// Get socket path
    pub fn getSocketPath(self: IpcProvider) []const u8 {
        return self.socket_path;
    }
};

/// Common IPC socket paths
pub const SocketPaths = struct {
    /// Default Geth IPC path (Unix)
    pub const GETH_UNIX = "/tmp/geth.ipc";

    /// Default Geth IPC path (macOS)
    pub const GETH_MACOS = "~/Library/Ethereum/geth.ipc";

    /// Default Geth IPC path (Windows)
    pub const GETH_WINDOWS = "\\\\.\\pipe\\geth.ipc";

    /// Get default path for current OS
    pub fn getDefault() []const u8 {
        return switch (std.builtin.os.tag) {
            .linux => GETH_UNIX,
            .macos => GETH_MACOS,
            .windows => GETH_WINDOWS,
            else => GETH_UNIX,
        };
    }
};

test "ipc provider creation" {
    const allocator = std.testing.allocator;

    const provider = try IpcProvider.init(allocator, "/tmp/geth.ipc");
    defer provider.deinit();

    try std.testing.expectEqualStrings("/tmp/geth.ipc", provider.getSocketPath());
}

test "ipc socket paths" {
    const default_path = SocketPaths.getDefault();
    try std.testing.expect(default_path.len > 0);

    // Check that it contains expected path components
    try std.testing.expect(
        std.mem.indexOf(u8, SocketPaths.GETH_UNIX, "geth.ipc") != null or
            std.mem.indexOf(u8, SocketPaths.GETH_UNIX, "tmp") != null,
    );
}

test "ipc provider get provider" {
    const allocator = std.testing.allocator;

    var ipc_provider = try IpcProvider.init(allocator, "/tmp/geth.ipc");
    defer ipc_provider.deinit();

    const provider = ipc_provider.getProvider();
    try std.testing.expect(provider.rpc_client.endpoint.len > 0);
}
