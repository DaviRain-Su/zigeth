const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Signature = @import("../primitives/signature.zig").Signature;
const Transaction = @import("../types/transaction.zig").Transaction;

/// Signer interface - all wallet types must implement this
pub const SignerInterface = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Get the address associated with this signer
        getAddress: *const fn (ptr: *anyopaque) anyerror!Address,

        /// Sign a transaction
        signTransaction: *const fn (ptr: *anyopaque, tx: *Transaction, chain_id: u64) anyerror!Signature,

        /// Sign a message hash
        signHash: *const fn (ptr: *anyopaque, hash: [32]u8) anyerror!Signature,

        /// Sign a message (with Ethereum prefix)
        signMessage: *const fn (ptr: *anyopaque, message: []const u8) anyerror!Signature,

        /// Verify a signature (optional, default implementation available)
        verifySignature: *const fn (ptr: *anyopaque, hash: [32]u8, signature: Signature) anyerror!bool,
    };

    /// Get the address associated with this signer
    pub fn getAddress(self: SignerInterface) !Address {
        return self.vtable.getAddress(self.ptr);
    }

    /// Sign a transaction
    pub fn signTransaction(self: SignerInterface, tx: *Transaction, chain_id: u64) !Signature {
        return self.vtable.signTransaction(self.ptr, tx, chain_id);
    }

    /// Sign a message hash
    pub fn signHash(self: SignerInterface, hash: [32]u8) !Signature {
        return self.vtable.signHash(self.ptr, hash);
    }

    /// Sign a message (with Ethereum prefix)
    pub fn signMessage(self: SignerInterface, message: []const u8) !Signature {
        return self.vtable.signMessage(self.ptr, message);
    }

    /// Verify a signature
    pub fn verifySignature(self: SignerInterface, hash: [32]u8, signature: Signature) !bool {
        return self.vtable.verifySignature(self.ptr, hash, signature);
    }
};

/// Helper function to create a SignerInterface from a concrete type
pub fn signerInterface(comptime T: type, ptr: *T) SignerInterface {
    const gen = struct {
        fn getAddress(p: *anyopaque) anyerror!Address {
            const self: *T = @ptrCast(@alignCast(p));
            return self.getAddress();
        }

        fn signTransaction(p: *anyopaque, tx: *Transaction, chain_id: u64) anyerror!Signature {
            const self: *T = @ptrCast(@alignCast(p));
            return self.signTransaction(tx, chain_id);
        }

        fn signHash(p: *anyopaque, hash: [32]u8) anyerror!Signature {
            const self: *T = @ptrCast(@alignCast(p));
            return self.signHash(hash);
        }

        fn signMessage(p: *anyopaque, message: []const u8) anyerror!Signature {
            const self: *T = @ptrCast(@alignCast(p));
            return self.signMessage(message);
        }

        fn verifySignature(p: *anyopaque, hash: [32]u8, signature: Signature) anyerror!bool {
            const self: *T = @ptrCast(@alignCast(p));
            return self.verifySignature(hash, signature);
        }

        const vtable = SignerInterface.VTable{
            .getAddress = getAddress,
            .signTransaction = signTransaction,
            .signHash = signHash,
            .signMessage = signMessage,
            .verifySignature = verifySignature,
        };
    };

    return .{
        .ptr = ptr,
        .vtable = &gen.vtable,
    };
}

/// Signer types
pub const SignerType = enum {
    software,
    hardware,
    remote,
};

/// Signer capabilities
pub const SignerCapabilities = struct {
    can_sign_transactions: bool,
    can_sign_messages: bool,
    supports_eip712: bool,
    supports_batch: bool,
    requires_confirmation: bool,

    pub fn full() SignerCapabilities {
        return .{
            .can_sign_transactions = true,
            .can_sign_messages = true,
            .supports_eip712 = true,
            .supports_batch = true,
            .requires_confirmation = false,
        };
    }

    pub fn basic() SignerCapabilities {
        return .{
            .can_sign_transactions = true,
            .can_sign_messages = true,
            .supports_eip712 = false,
            .supports_batch = false,
            .requires_confirmation = false,
        };
    }

    pub fn hardware() SignerCapabilities {
        return .{
            .can_sign_transactions = true,
            .can_sign_messages = true,
            .supports_eip712 = true,
            .supports_batch = false,
            .requires_confirmation = true,
        };
    }
};

// Tests
test "signer capabilities full" {
    const caps = SignerCapabilities.full();
    try std.testing.expect(caps.can_sign_transactions);
    try std.testing.expect(caps.can_sign_messages);
    try std.testing.expect(caps.supports_eip712);
    try std.testing.expect(caps.supports_batch);
    try std.testing.expect(!caps.requires_confirmation);
}

test "signer capabilities hardware" {
    const caps = SignerCapabilities.hardware();
    try std.testing.expect(caps.can_sign_transactions);
    try std.testing.expect(caps.can_sign_messages);
    try std.testing.expect(caps.supports_eip712);
    try std.testing.expect(!caps.supports_batch);
    try std.testing.expect(caps.requires_confirmation);
}
