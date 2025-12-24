const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const Signature = @import("../primitives/signature.zig").Signature;
const AccessList = @import("./access_list.zig").AccessList;

/// Transaction type
pub const TransactionType = enum(u8) {
    /// Legacy transaction (pre-EIP-2718)
    legacy = 0,
    /// EIP-2930: Optional access lists
    eip2930 = 1,
    /// EIP-1559: Fee market change
    eip1559 = 2,
    /// EIP-4844: Shard blob transactions
    eip4844 = 3,
    /// EIP-7702: Set EOA account code
    eip7702 = 4,
};

/// Authorization tuple for EIP-7702
/// Allows EOAs to temporarily set code from a contract
pub const Authorization = struct {
    /// Chain ID
    chain_id: u64,
    /// Address of the code to set
    address: Address,
    /// Nonce of the authorizing account
    nonce: u64,
    /// Authorization signature (y_parity, r, s)
    y_parity: u8,
    r: u256,
    s: u256,
};

/// Authorization list for EIP-7702 transactions
pub const AuthorizationList = struct {
    authorizations: []Authorization,
    allocator: std.mem.Allocator,

    /// Create an empty authorization list
    pub fn empty(allocator: std.mem.Allocator) AuthorizationList {
        return .{
            .authorizations = &[_]Authorization{},
            .allocator = allocator,
        };
    }

    /// Create authorization list from authorizations
    pub fn init(allocator: std.mem.Allocator, authorizations: []const Authorization) !AuthorizationList {
        const auth_copy = try allocator.dupe(Authorization, authorizations);
        return .{
            .authorizations = auth_copy,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: AuthorizationList) void {
        if (self.authorizations.len > 0) {
            self.allocator.free(self.authorizations);
        }
    }

    /// Get number of authorizations
    pub fn len(self: AuthorizationList) usize {
        return self.authorizations.len;
    }

    /// Check if authorization list is empty
    pub fn isEmpty(self: AuthorizationList) bool {
        return self.authorizations.len == 0;
    }
};

/// Ethereum transaction
pub const Transaction = struct {
    /// Transaction type
    type: TransactionType,

    /// Sender address (recovered from signature)
    from: ?Address,

    /// Recipient address (null for contract creation)
    to: ?Address,

    /// Transaction nonce
    nonce: u64,

    /// Gas limit
    gas_limit: u64,

    /// Gas price (legacy and EIP-2930)
    gas_price: ?u256,

    /// Max fee per gas (EIP-1559)
    max_fee_per_gas: ?u256,

    /// Max priority fee per gas (EIP-1559)
    max_priority_fee_per_gas: ?u256,

    /// Value to transfer (in wei)
    value: u256,

    /// Transaction data / input
    data: Bytes,

    /// Chain ID (EIP-155)
    chain_id: ?u64,

    /// Access list (EIP-2930 and EIP-1559)
    access_list: ?AccessList,

    /// Authorization list (EIP-7702)
    authorization_list: ?AuthorizationList,

    /// Max fee per blob gas (EIP-4844)
    max_fee_per_blob_gas: ?u256,

    /// Blob versioned hashes (EIP-4844)
    blob_versioned_hashes: ?[]Hash,

    /// Transaction signature
    signature: ?Signature,

    /// Transaction hash
    hash: ?Hash,

    /// Block hash where this transaction was included
    block_hash: ?Hash,

    /// Block number where this transaction was included
    block_number: ?u64,

    /// Transaction index in the block
    transaction_index: ?u64,

    allocator: std.mem.Allocator,

    /// Create a new legacy transaction
    pub fn newLegacy(
        allocator: std.mem.Allocator,
        to: ?Address,
        value: u256,
        data: Bytes,
        nonce: u64,
        gas_limit: u64,
        gas_price: u256,
    ) Transaction {
        return .{
            .type = .legacy,
            .from = null,
            .to = to,
            .nonce = nonce,
            .gas_limit = gas_limit,
            .gas_price = gas_price,
            .max_fee_per_gas = null,
            .max_priority_fee_per_gas = null,
            .value = value,
            .data = data,
            .chain_id = null,
            .access_list = null,
            .authorization_list = null,
            .max_fee_per_blob_gas = null,
            .blob_versioned_hashes = null,
            .signature = null,
            .hash = null,
            .block_hash = null,
            .block_number = null,
            .transaction_index = null,
            .allocator = allocator,
        };
    }

    /// Create a new EIP-1559 transaction
    pub fn newEip1559(
        allocator: std.mem.Allocator,
        to: ?Address,
        value: u256,
        data: Bytes,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u256,
        max_priority_fee_per_gas: u256,
        chain_id: u64,
        access_list: ?AccessList,
    ) Transaction {
        return .{
            .type = .eip1559,
            .from = null,
            .to = to,
            .nonce = nonce,
            .gas_limit = gas_limit,
            .gas_price = null,
            .max_fee_per_gas = max_fee_per_gas,
            .max_priority_fee_per_gas = max_priority_fee_per_gas,
            .value = value,
            .data = data,
            .chain_id = chain_id,
            .access_list = access_list,
            .authorization_list = null,
            .max_fee_per_blob_gas = null,
            .blob_versioned_hashes = null,
            .signature = null,
            .hash = null,
            .block_hash = null,
            .block_number = null,
            .transaction_index = null,
            .allocator = allocator,
        };
    }

    /// Create a new EIP-2930 transaction
    pub fn newEip2930(
        allocator: std.mem.Allocator,
        to: ?Address,
        value: u256,
        data: Bytes,
        nonce: u64,
        gas_limit: u64,
        gas_price: u256,
        chain_id: u64,
        access_list: AccessList,
    ) Transaction {
        return .{
            .type = .eip2930,
            .from = null,
            .to = to,
            .nonce = nonce,
            .gas_limit = gas_limit,
            .gas_price = gas_price,
            .max_fee_per_gas = null,
            .max_priority_fee_per_gas = null,
            .value = value,
            .data = data,
            .chain_id = chain_id,
            .access_list = access_list,
            .authorization_list = null,
            .max_fee_per_blob_gas = null,
            .blob_versioned_hashes = null,
            .signature = null,
            .hash = null,
            .block_hash = null,
            .block_number = null,
            .transaction_index = null,
            .allocator = allocator,
        };
    }

    /// Create a new EIP-7702 transaction
    pub fn newEip7702(
        allocator: std.mem.Allocator,
        to: ?Address,
        value: u256,
        data: Bytes,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u256,
        max_priority_fee_per_gas: u256,
        chain_id: u64,
        access_list: ?AccessList,
        authorization_list: AuthorizationList,
    ) Transaction {
        return .{
            .type = .eip7702,
            .from = null,
            .to = to,
            .nonce = nonce,
            .gas_limit = gas_limit,
            .gas_price = null,
            .max_fee_per_gas = max_fee_per_gas,
            .max_priority_fee_per_gas = max_priority_fee_per_gas,
            .value = value,
            .data = data,
            .chain_id = chain_id,
            .access_list = access_list,
            .authorization_list = authorization_list,
            .max_fee_per_blob_gas = null,
            .blob_versioned_hashes = null,
            .signature = null,
            .hash = null,
            .block_hash = null,
            .block_number = null,
            .transaction_index = null,
            .allocator = allocator,
        };
    }

    /// Create a new EIP-4844 transaction
    pub fn newEip4844(
        allocator: std.mem.Allocator,
        to: ?Address,
        value: u256,
        data: Bytes,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u256,
        max_priority_fee_per_gas: u256,
        max_fee_per_blob_gas: u256,
        chain_id: u64,
        access_list: ?AccessList,
        blob_versioned_hashes: []Hash,
    ) !Transaction {
        const hashes_copy = try allocator.dupe(Hash, blob_versioned_hashes);
        return .{
            .type = .eip4844,
            .from = null,
            .to = to,
            .nonce = nonce,
            .gas_limit = gas_limit,
            .gas_price = null,
            .max_fee_per_gas = max_fee_per_gas,
            .max_priority_fee_per_gas = max_priority_fee_per_gas,
            .value = value,
            .data = data,
            .chain_id = chain_id,
            .access_list = access_list,
            .authorization_list = null,
            .max_fee_per_blob_gas = max_fee_per_blob_gas,
            .blob_versioned_hashes = hashes_copy,
            .signature = null,
            .hash = null,
            .block_hash = null,
            .block_number = null,
            .transaction_index = null,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: Transaction) void {
        self.data.deinit();
        if (self.access_list) |list| {
            list.deinit();
        }
        if (self.authorization_list) |list| {
            list.deinit();
        }
        if (self.blob_versioned_hashes) |hashes| {
            self.allocator.free(hashes);
        }
    }

    /// Check if this is a contract creation transaction
    pub fn isContractCreation(self: Transaction) bool {
        return self.to == null;
    }

    /// Check if transaction is pending (not yet included in a block)
    pub fn isPending(self: Transaction) bool {
        return self.block_number == null;
    }

    /// Get the effective gas price
    pub fn getGasPrice(self: Transaction) ?u256 {
        return switch (self.type) {
            .legacy, .eip2930 => self.gas_price,
            .eip1559, .eip4844, .eip7702 => self.max_fee_per_gas,
        };
    }

    /// Set the signature
    pub fn setSignature(self: *Transaction, signature: Signature) void {
        self.signature = signature;
    }

    /// Set the sender address
    pub fn setFrom(self: *Transaction, from: Address) void {
        self.from = from;
    }
};

test "legacy transaction creation" {
    const allocator = std.testing.allocator;

    const to = Address.fromBytes([_]u8{0x12} ** 20);
    const value = @as(u256, 1000);
    const data = try Bytes.fromSlice(allocator, &[_]u8{ 1, 2, 3 });

    const tx = Transaction.newLegacy(
        allocator,
        to,
        value,
        data,
        0, // nonce
        21000, // gas_limit
        @as(u256, 20000000000), // gas_price (20 gwei)
    );
    defer tx.deinit();

    try std.testing.expectEqual(TransactionType.legacy, tx.type);
    try std.testing.expectEqual(@as(u64, 0), tx.nonce);
    try std.testing.expect(!tx.isContractCreation());
}

test "eip1559 transaction creation" {
    const allocator = std.testing.allocator;

    const to = Address.fromBytes([_]u8{0x12} ** 20);
    const value = @as(u256, 1000);
    const data = try Bytes.fromSlice(allocator, &[_]u8{});

    const tx = Transaction.newEip1559(
        allocator,
        to,
        value,
        data,
        5, // nonce
        21000, // gas_limit
        @as(u256, 30000000000), // max_fee_per_gas
        @as(u256, 2000000000), // max_priority_fee_per_gas
        1, // chain_id (mainnet)
        null, // no access list
    );
    defer tx.deinit();

    try std.testing.expectEqual(TransactionType.eip1559, tx.type);
    try std.testing.expectEqual(@as(u64, 5), tx.nonce);
    try std.testing.expectEqual(@as(?u64, 1), tx.chain_id);
}

test "contract creation transaction" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x60, 0x60, 0x40 });

    const tx = Transaction.newLegacy(
        allocator,
        null, // no recipient = contract creation
        0,
        bytecode,
        0,
        100000,
        @as(u256, 20000000000),
    );
    defer tx.deinit();

    try std.testing.expect(tx.isContractCreation());
}

test "transaction gas price" {
    const allocator = std.testing.allocator;

    const data = try Bytes.fromSlice(allocator, &[_]u8{});
    const to = Address.fromBytes([_]u8{0x12} ** 20);

    // Legacy transaction
    const legacy_tx = Transaction.newLegacy(
        allocator,
        to,
        0,
        data,
        0,
        21000,
        @as(u256, 20000000000),
    );

    const legacy_price = legacy_tx.getGasPrice();
    try std.testing.expect(legacy_price != null);
    try std.testing.expectEqual(@as(u256, 20000000000), legacy_price.?);

    // EIP-1559 transaction
    const data2 = try Bytes.fromSlice(allocator, &[_]u8{});
    const eip1559_tx = Transaction.newEip1559(
        allocator,
        to,
        0,
        data2,
        0,
        21000,
        @as(u256, 30000000000),
        @as(u256, 2000000000),
        1,
        null,
    );
    defer eip1559_tx.deinit();

    const eip1559_price = eip1559_tx.getGasPrice();
    try std.testing.expect(eip1559_price != null);
    try std.testing.expectEqual(@as(u256, 30000000000), eip1559_price.?);
}

test "transaction pending status" {
    const allocator = std.testing.allocator;

    const data = try Bytes.fromSlice(allocator, &[_]u8{});
    const to = Address.fromBytes([_]u8{0x12} ** 20);

    var tx = Transaction.newLegacy(
        allocator,
        to,
        0,
        data,
        0,
        21000,
        @as(u256, 20000000000),
    );
    defer tx.deinit();

    try std.testing.expect(tx.isPending());

    tx.block_number = 12345;
    try std.testing.expect(!tx.isPending());
}

test "authorization list" {
    const allocator = std.testing.allocator;

    const auth = Authorization{
        .chain_id = 1,
        .address = Address.fromBytes([_]u8{0x12} ** 20),
        .nonce = 5,
        .y_parity = 0,
        .r = @as(u256, 12345),
        .s = @as(u256, 67890),
    };

    const auths = [_]Authorization{auth};
    const auth_list = try AuthorizationList.init(allocator, &auths);
    defer auth_list.deinit();

    try std.testing.expectEqual(@as(usize, 1), auth_list.len());
    try std.testing.expect(!auth_list.isEmpty());
    try std.testing.expectEqual(@as(u64, 1), auth_list.authorizations[0].chain_id);
}

test "eip7702 transaction creation" {
    const allocator = std.testing.allocator;

    const to = Address.fromBytes([_]u8{0x12} ** 20);
    const value = @as(u256, 1000);
    const data = try Bytes.fromSlice(allocator, &[_]u8{ 1, 2, 3 });

    const auth = Authorization{
        .chain_id = 1,
        .address = Address.fromBytes([_]u8{0xAB} ** 20),
        .nonce = 0,
        .y_parity = 1,
        .r = @as(u256, 11111),
        .s = @as(u256, 22222),
    };

    const auths = [_]Authorization{auth};
    const auth_list = try AuthorizationList.init(allocator, &auths);

    const tx = Transaction.newEip7702(
        allocator,
        to,
        value,
        data,
        5, // nonce
        21000, // gas_limit
        @as(u256, 30000000000), // max_fee_per_gas
        @as(u256, 2000000000), // max_priority_fee_per_gas
        1, // chain_id (mainnet)
        null, // no access list
        auth_list,
    );
    defer tx.deinit();

    try std.testing.expectEqual(TransactionType.eip7702, tx.type);
    try std.testing.expectEqual(@as(u64, 5), tx.nonce);
    try std.testing.expectEqual(@as(?u64, 1), tx.chain_id);
    try std.testing.expect(tx.authorization_list != null);
    try std.testing.expectEqual(@as(usize, 1), tx.authorization_list.?.len());
}

test "eip7702 gas price" {
    const allocator = std.testing.allocator;

    const to = Address.fromBytes([_]u8{0x12} ** 20);
    const data = try Bytes.fromSlice(allocator, &[_]u8{});
    const auth_list = AuthorizationList.empty(allocator);

    const tx = Transaction.newEip7702(
        allocator,
        to,
        0,
        data,
        0,
        21000,
        @as(u256, 30000000000), // max_fee_per_gas
        @as(u256, 2000000000), // max_priority_fee_per_gas
        1,
        null,
        auth_list,
    );
    defer tx.deinit();

    const gas_price = tx.getGasPrice();
    try std.testing.expect(gas_price != null);
    try std.testing.expectEqual(@as(u256, 30000000000), gas_price.?);
}
