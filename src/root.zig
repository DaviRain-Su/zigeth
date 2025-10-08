//! Zeth - Ethereum library for Zig
//!
//! This library provides primitives, RPC client, and utilities
//! for interacting with Ethereum networks.

const std = @import("std");

// Re-export main modules
pub const primitives = @import("primitives/address.zig");
pub const types = struct {
    pub const Transaction = @import("types/transaction.zig").Transaction;
    pub const Block = @import("types/block.zig").Block;
    pub const Receipt = @import("types/receipt.zig").Receipt;
};

pub const crypto = struct {
    pub const keccak = @import("crypto/keccak.zig");
    pub const secp256k1 = @import("crypto/secp256k1.zig");
};

pub const abi = struct {
    pub const encode = @import("abi/encode.zig");
    pub const decode = @import("abi/decode.zig");
};

pub const rlp = struct {
    pub const encode = @import("rlp/encode.zig");
    pub const decode = @import("rlp/decode.zig");
};

pub const providers = struct {
    pub const Provider = @import("providers/provider.zig").Provider;
    pub const HttpProvider = @import("providers/http.zig").HttpProvider;
};

pub const rpc = @import("rpc/client.zig");
pub const contract = @import("contract/contract.zig");
pub const signer = @import("signer/wallet.zig");
pub const utils = @import("utils/hex.zig");

test {
    std.testing.refAllDecls(@This());
}
