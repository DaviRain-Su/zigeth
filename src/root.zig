//! Zeth - Ethereum library for Zig
//!
//! This library provides primitives, RPC client, and utilities
//! for interacting with Ethereum networks.

const std = @import("std");

// Re-export main modules
pub const primitives = struct {
    pub const Address = @import("primitives/address.zig").Address;
    pub const Hash = @import("primitives/hash.zig").Hash;
    pub const Bytes = @import("primitives/bytes.zig").Bytes;
    pub const Signature = @import("primitives/signature.zig").Signature;
    pub const U256 = @import("primitives/uint.zig").U256;
    pub const Bloom = @import("primitives/bloom.zig").Bloom;
};
pub const types = struct {
    pub const Transaction = @import("types/transaction.zig").Transaction;
    pub const TransactionType = @import("types/transaction.zig").TransactionType;
    pub const Block = @import("types/block.zig").Block;
    pub const BlockHeader = @import("types/block.zig").BlockHeader;
    pub const Receipt = @import("types/receipt.zig").Receipt;
    pub const TransactionStatus = @import("types/receipt.zig").TransactionStatus;
    pub const Log = @import("types/log.zig").Log;
    pub const AccessList = @import("types/access_list.zig").AccessList;
    pub const AccessListEntry = @import("types/access_list.zig").AccessList.AccessListEntry;
    pub const Authorization = @import("types/transaction.zig").Authorization;
    pub const AuthorizationList = @import("types/transaction.zig").AuthorizationList;
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

pub const utils = struct {
    pub const hex = @import("utils/hex.zig");
    pub const format = @import("utils/format.zig");
    pub const units = @import("utils/units.zig");
    pub const checksum = @import("utils/checksum.zig");
};

test {
    std.testing.refAllDecls(@This());
}
