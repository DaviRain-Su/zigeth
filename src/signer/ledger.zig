const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const Transaction = @import("../types/transaction.zig").Transaction;
const SignerInterface = @import("./signer.zig").SignerInterface;
const SignerCapabilities = @import("./signer.zig").SignerCapabilities;

/// Ledger device model
pub const LedgerModel = enum {
    nano_s,
    nano_x,
    nano_s_plus,

    pub fn toString(self: LedgerModel) []const u8 {
        return switch (self) {
            .nano_s => "Nano S",
            .nano_x => "Nano X",
            .nano_s_plus => "Nano S Plus",
        };
    }
};

/// Ledger application
pub const LedgerApp = enum {
    ethereum,
    bitcoin,

    pub fn toString(self: LedgerApp) []const u8 {
        return switch (self) {
            .ethereum => "Ethereum",
            .bitcoin => "Bitcoin",
        };
    }
};

/// BIP-44 derivation path
pub const DerivationPath = struct {
    purpose: u32,
    coin_type: u32,
    account: u32,
    change: u32,
    address_index: u32,

    /// Standard Ethereum path: m/44'/60'/0'/0/0
    pub fn ethereum(account: u32, index: u32) DerivationPath {
        return .{
            .purpose = 44 | 0x80000000, // Hardened
            .coin_type = 60 | 0x80000000, // Hardened (Ethereum)
            .account = account | 0x80000000, // Hardened
            .change = 0,
            .address_index = index,
        };
    }

    /// Standard Ethereum Legacy path: m/44'/60'/0'/0
    pub fn ethereumLegacy(index: u32) DerivationPath {
        return .{
            .purpose = 44 | 0x80000000,
            .coin_type = 60 | 0x80000000,
            .account = index | 0x80000000,
            .change = 0,
            .address_index = 0,
        };
    }

    /// Convert to string format: "m/44'/60'/0'/0/0"
    pub fn toString(self: DerivationPath, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "m/{d}'/{d}'/{d}'/{d}/{d}",
            .{
                self.purpose & 0x7FFFFFFF,
                self.coin_type & 0x7FFFFFFF,
                self.account & 0x7FFFFFFF,
                self.change,
                self.address_index,
            },
        );
    }

    /// Encode path for Ledger APDU
    pub fn encode(self: DerivationPath, allocator: std.mem.Allocator) ![]u8 {
        var buffer = try allocator.alloc(u8, 21);
        buffer[0] = 5; // Path length

        std.mem.writeInt(u32, buffer[1..5], self.purpose, .big);
        std.mem.writeInt(u32, buffer[5..9], self.coin_type, .big);
        std.mem.writeInt(u32, buffer[9..13], self.account, .big);
        std.mem.writeInt(u32, buffer[13..17], self.change, .big);
        std.mem.writeInt(u32, buffer[17..21], self.address_index, .big);

        return buffer;
    }
};

/// Ledger transport type
pub const TransportType = enum {
    usb,
    bluetooth,
    web_hid,
};

/// Ledger device connection status
pub const ConnectionStatus = enum {
    disconnected,
    connected,
    app_open,
    locked,
};

/// Ledger hardware wallet
pub const LedgerWallet = struct {
    model: LedgerModel,
    app: LedgerApp,
    path: DerivationPath,
    address: ?Address,
    transport_type: TransportType,
    connection_status: ConnectionStatus,
    allocator: std.mem.Allocator,
    capabilities: SignerCapabilities,

    /// Create a new Ledger wallet instance
    pub fn init(
        allocator: std.mem.Allocator,
        model: LedgerModel,
        path: DerivationPath,
    ) !LedgerWallet {
        return .{
            .model = model,
            .app = .ethereum,
            .path = path,
            .address = null,
            .transport_type = .usb,
            .connection_status = .disconnected,
            .allocator = allocator,
            .capabilities = SignerCapabilities.hardware(),
        };
    }

    /// Connect to Ledger device
    pub fn connect(self: *LedgerWallet) !void {
        // TODO: Implement actual USB/HID connection
        // This would use libusb or platform-specific HID APIs
        self.connection_status = .connected;
    }

    /// Disconnect from Ledger device
    pub fn disconnect(self: *LedgerWallet) void {
        self.connection_status = .disconnected;
        self.address = null;
    }

    /// Check if connected
    pub fn isConnected(self: LedgerWallet) bool {
        return self.connection_status != .disconnected;
    }

    /// Open Ethereum app on Ledger
    pub fn openApp(self: *LedgerWallet) !void {
        if (!self.isConnected()) {
            return error.NotConnected;
        }

        // TODO: Send APDU command to open app
        self.connection_status = .app_open;
    }

    /// Get address from Ledger
    pub fn getAddress(self: *LedgerWallet) !Address {
        if (self.address) |addr| {
            return addr;
        }

        if (!self.isConnected()) {
            return error.NotConnected;
        }

        // TODO: Send APDU command to get address
        // APDU: E0 02 00 00 + path_length + path
        const addr = Address.fromBytes([_]u8{0} ** 20); // Placeholder
        self.address = addr;
        return addr;
    }

    /// Sign a transaction hash
    pub fn signHash(self: *LedgerWallet, hash: [32]u8) !Signature {
        if (!self.isConnected()) {
            return error.NotConnected;
        }

        // TODO: Send APDU command to sign
        // APDU: E0 04 00 00 + data
        _ = hash;

        return Signature.init(
            [_]u8{0} ** 32,
            [_]u8{0} ** 32,
            0,
        );
    }

    /// Sign a transaction
    pub fn signTransaction(self: *LedgerWallet, tx: *Transaction, chain_id: u64) !Signature {
        if (!self.isConnected()) {
            return error.NotConnected;
        }

        // TODO: Encode transaction for Ledger
        // TODO: Send APDU command to sign transaction
        _ = tx;
        _ = chain_id;

        return Signature.init(
            [_]u8{0} ** 32,
            [_]u8{0} ** 32,
            0,
        );
    }

    /// Sign a message (requires user confirmation on device)
    pub fn signMessage(self: *LedgerWallet, message: []const u8) !Signature {
        if (!self.isConnected()) {
            return error.NotConnected;
        }

        // TODO: Send APDU command to sign message
        // APDU: E0 08 00 00 + message_length + message
        _ = message;

        return Signature.init(
            [_]u8{0} ** 32,
            [_]u8{0} ** 32,
            0,
        );
    }

    /// Sign EIP-712 typed data
    pub fn signTypedData(
        self: *LedgerWallet,
        domain_hash: [32]u8,
        message_hash: [32]u8,
    ) !Signature {
        if (!self.isConnected()) {
            return error.NotConnected;
        }

        // TODO: Send APDU command for EIP-712
        _ = domain_hash;
        _ = message_hash;

        return Signature.init(
            [_]u8{0} ** 32,
            [_]u8{0} ** 32,
            0,
        );
    }

    /// Verify signature (delegated to software verification)
    pub fn verifySignature(self: *LedgerWallet, hash: [32]u8, signature: Signature) !bool {
        const ecdsa = @import("../crypto/ecdsa.zig");
        const addr = try self.getAddress();
        const recovered_addr = try ecdsa.recoverAddress(hash, signature);
        return recovered_addr.eql(addr);
    }

    /// Get device info
    pub fn getDeviceInfo(self: LedgerWallet) DeviceInfo {
        return .{
            .model = self.model,
            .app = self.app,
            .path = self.path,
            .transport = self.transport_type,
            .status = self.connection_status,
        };
    }

    /// Get signer interface
    pub fn asInterface(self: *LedgerWallet) SignerInterface {
        const signerInterface = @import("./signer.zig").signerInterface;
        return signerInterface(LedgerWallet, self);
    }

    /// Get capabilities
    pub fn getCapabilities(self: LedgerWallet) SignerCapabilities {
        return self.capabilities;
    }

    /// Set derivation path
    pub fn setPath(self: *LedgerWallet, path: DerivationPath) void {
        self.path = path;
        self.address = null; // Invalidate cached address
    }
};

/// Device information
pub const DeviceInfo = struct {
    model: LedgerModel,
    app: LedgerApp,
    path: DerivationPath,
    transport: TransportType,
    status: ConnectionStatus,

    pub fn format(
        self: DeviceInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print(
            "Ledger {s} - {s} ({})",
            .{ self.model.toString(), self.app.toString(), self.status },
        );
    }
};

/// APDU command structure (for Ledger communication)
pub const APDU = struct {
    cla: u8, // Class
    ins: u8, // Instruction
    p1: u8, // Parameter 1
    p2: u8, // Parameter 2
    data: []const u8,

    /// Ethereum app commands
    pub const Command = struct {
        pub const GET_ADDRESS: u8 = 0x02;
        pub const SIGN_TX: u8 = 0x04;
        pub const SIGN_MESSAGE: u8 = 0x08;
        pub const GET_APP_CONFIG: u8 = 0x06;
    };

    /// Encode APDU to bytes
    pub fn encode(self: APDU, allocator: std.mem.Allocator) ![]u8 {
        const total_len = 5 + self.data.len;
        var buffer = try allocator.alloc(u8, total_len);

        buffer[0] = self.cla;
        buffer[1] = self.ins;
        buffer[2] = self.p1;
        buffer[3] = self.p2;
        buffer[4] = @intCast(self.data.len);

        if (self.data.len > 0) {
            @memcpy(buffer[5..], self.data);
        }

        return buffer;
    }
};

// Tests
test "derivation path ethereum" {
    const path = DerivationPath.ethereum(0, 0);
    try std.testing.expectEqual(@as(u32, 44 | 0x80000000), path.purpose);
    try std.testing.expectEqual(@as(u32, 60 | 0x80000000), path.coin_type);
    try std.testing.expectEqual(@as(u32, 0 | 0x80000000), path.account);
    try std.testing.expectEqual(@as(u32, 0), path.address_index);
}

test "derivation path to string" {
    const allocator = std.testing.allocator;
    const path = DerivationPath.ethereum(0, 0);
    const str = try path.toString(allocator);
    defer allocator.free(str);

    try std.testing.expect(std.mem.indexOf(u8, str, "m/44'/60'/0'") != null);
}

test "derivation path encode" {
    const allocator = std.testing.allocator;
    const path = DerivationPath.ethereum(0, 0);
    const encoded = try path.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 21), encoded.len);
    try std.testing.expectEqual(@as(u8, 5), encoded[0]); // Path length
}

test "ledger wallet creation" {
    const allocator = std.testing.allocator;

    const path = DerivationPath.ethereum(0, 0);
    var wallet = try LedgerWallet.init(allocator, .nano_s, path);

    try std.testing.expectEqual(LedgerModel.nano_s, wallet.model);
    try std.testing.expect(!wallet.isConnected());
}

test "ledger wallet connect" {
    const allocator = std.testing.allocator;

    const path = DerivationPath.ethereum(0, 0);
    var wallet = try LedgerWallet.init(allocator, .nano_s, path);

    try wallet.connect();
    try std.testing.expect(wallet.isConnected());

    wallet.disconnect();
    try std.testing.expect(!wallet.isConnected());
}

test "ledger wallet capabilities" {
    const allocator = std.testing.allocator;

    const path = DerivationPath.ethereum(0, 0);
    const wallet = try LedgerWallet.init(allocator, .nano_s, path);

    const caps = wallet.getCapabilities();
    try std.testing.expect(caps.can_sign_transactions);
    try std.testing.expect(caps.requires_confirmation);
}

test "apdu encode" {
    const allocator = std.testing.allocator;

    const apdu = APDU{
        .cla = 0xE0,
        .ins = APDU.Command.GET_ADDRESS,
        .p1 = 0x00,
        .p2 = 0x00,
        .data = &[_]u8{ 0x01, 0x02, 0x03 },
    };

    const encoded = try apdu.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 8), encoded.len);
    try std.testing.expectEqual(@as(u8, 0xE0), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x02), encoded[1]);
}
