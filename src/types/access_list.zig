const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;

/// EIP-2930: Optional access list for transactions
/// Access lists specify accounts and storage keys that the transaction plans to access
pub const AccessList = struct {
    entries: []AccessListEntry,
    allocator: std.mem.Allocator,

    /// Single entry in an access list
    pub const AccessListEntry = struct {
        address: Address,
        storage_keys: []const Hash,
    };

    /// Create an empty access list
    pub fn empty(allocator: std.mem.Allocator) AccessList {
        return .{
            .entries = &[_]AccessListEntry{},
            .allocator = allocator,
        };
    }

    /// Create access list from entries
    pub fn init(allocator: std.mem.Allocator, entries: []const AccessListEntry) !AccessList {
        const entries_copy = try allocator.alloc(AccessListEntry, entries.len);
        for (entries, 0..) |entry, i| {
            entries_copy[i] = .{
                .address = entry.address,
                .storage_keys = try allocator.dupe(Hash, entry.storage_keys),
            };
        }
        return .{
            .entries = entries_copy,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: AccessList) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.storage_keys);
        }
        if (self.entries.len > 0) {
            self.allocator.free(self.entries);
        }
    }

    /// Get number of entries
    pub fn len(self: AccessList) usize {
        return self.entries.len;
    }

    /// Check if access list is empty
    pub fn isEmpty(self: AccessList) bool {
        return self.entries.len == 0;
    }

    /// Add an entry to the access list
    pub fn addEntry(self: *AccessList, address: Address, storage_keys: []const Hash) !void {
        const new_entries = try self.allocator.alloc(AccessListEntry, self.entries.len + 1);
        @memcpy(new_entries[0..self.entries.len], self.entries);

        new_entries[self.entries.len] = .{
            .address = address,
            .storage_keys = try self.allocator.dupe(Hash, storage_keys),
        };

        if (self.entries.len > 0) {
            self.allocator.free(self.entries);
        }
        self.entries = new_entries;
    }

    /// Check if an address is in the access list
    pub fn containsAddress(self: AccessList, address: Address) bool {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, &entry.address.bytes, &address.bytes)) {
                return true;
            }
        }
        return false;
    }

    /// Check if a storage key for an address is in the access list
    pub fn containsStorageKey(self: AccessList, address: Address, storage_key: Hash) bool {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, &entry.address.bytes, &address.bytes)) {
                for (entry.storage_keys) |key| {
                    if (key.eql(storage_key)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
};

test "access list creation" {
    const allocator = std.testing.allocator;

    const list = AccessList.empty(allocator);
    defer list.deinit();

    try std.testing.expect(list.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "access list add entry" {
    const allocator = std.testing.allocator;

    var list = AccessList.empty(allocator);
    defer list.deinit();

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const keys = [_]Hash{Hash.fromBytes([_]u8{0x34} ** 32)};

    try list.addEntry(addr, &keys);

    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expect(list.containsAddress(addr));
}

test "access list contains storage key" {
    const allocator = std.testing.allocator;

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    const key = Hash.fromBytes([_]u8{0x34} ** 32);
    const keys = [_]Hash{key};

    const entry = AccessList.AccessListEntry{
        .address = addr,
        .storage_keys = &keys,
    };

    const entries = [_]AccessList.AccessListEntry{entry};
    const list = try AccessList.init(allocator, &entries);
    defer list.deinit();

    try std.testing.expect(list.containsAddress(addr));
    try std.testing.expect(list.containsStorageKey(addr, key));

    const other_key = Hash.fromBytes([_]u8{0x56} ** 32);
    try std.testing.expect(!list.containsStorageKey(addr, other_key));
}
