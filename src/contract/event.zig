const std = @import("std");
const Address = @import("../primitives/address.zig").Address;
const Hash = @import("../primitives/hash.zig").Hash;
const U256 = @import("../primitives/uint.zig").U256;
const Bytes = @import("../primitives/bytes.zig").Bytes;
const Log = @import("../types/log.zig").Log;
const abi = @import("../abi/types.zig");
const decode = @import("../abi/decode.zig");
const keccak = @import("../crypto/keccak.zig");
const DeployBuilder = @import("./deploy.zig").DeployBuilder;

/// Parsed event data
pub const ParsedEvent = struct {
    event: abi.Event,
    indexed_args: []abi.AbiValue,
    data_args: []abi.AbiValue,
    log: Log,
    allocator: std.mem.Allocator,

    pub fn deinit(self: ParsedEvent) void {
        self.allocator.free(self.indexed_args);
        self.allocator.free(self.data_args);
    }

    /// Get an indexed argument by name
    pub fn getIndexedArg(self: ParsedEvent, name: []const u8) ?abi.AbiValue {
        var idx: usize = 0;
        for (self.event.inputs) |param| {
            if (param.indexed) {
                if (std.mem.eql(u8, param.name, name)) {
                    if (idx < self.indexed_args.len) {
                        return self.indexed_args[idx];
                    }
                    return null;
                }
                idx += 1;
            }
        }
        return null;
    }

    /// Get a non-indexed argument by name
    pub fn getDataArg(self: ParsedEvent, name: []const u8) ?abi.AbiValue {
        var idx: usize = 0;
        for (self.event.inputs) |param| {
            if (!param.indexed) {
                if (std.mem.eql(u8, param.name, name)) {
                    if (idx < self.data_args.len) {
                        return self.data_args[idx];
                    }
                    return null;
                }
                idx += 1;
            }
        }
        return null;
    }
};

/// Event filter for querying logs
pub const EventFilter = struct {
    contract_address: ?Address,
    event_signature: ?Hash,
    indexed_filters: []?Hash,
    from_block: ?u64,
    to_block: ?u64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) EventFilter {
        return .{
            .contract_address = null,
            .event_signature = null,
            .indexed_filters = &[_]?Hash{},
            .from_block = null,
            .to_block = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: EventFilter) void {
        if (self.indexed_filters.len > 0) {
            self.allocator.free(self.indexed_filters);
        }
    }

    /// Set the contract address to filter by
    pub fn setAddress(self: *EventFilter, address: Address) void {
        self.contract_address = address;
    }

    /// Set the event signature to filter by
    pub fn setEventSignature(self: *EventFilter, sig: Hash) void {
        self.event_signature = sig;
    }

    /// Set block range
    pub fn setBlockRange(self: *EventFilter, from: u64, to: u64) void {
        self.from_block = from;
        self.to_block = to;
    }
};

/// Parse an event log using the event ABI
pub fn parseEvent(
    allocator: std.mem.Allocator,
    event: abi.Event,
    log: Log,
) !ParsedEvent {
    // Verify event signature matches (if not anonymous)
    if (!event.anonymous) {
        const event_sig_str = try event.getSignature(allocator);
        defer allocator.free(event_sig_str);

        const expected_sig = keccak.eventSignature(event_sig_str);

        if (log.topics.len == 0 or !log.topics[0].eql(expected_sig)) {
            return error.EventSignatureMismatch;
        }
    }

    // Extract indexed arguments from topics
    var indexed_args = try std.ArrayList(abi.AbiValue).initCapacity(allocator, 0);
    defer indexed_args.deinit(allocator);

    var topic_idx: usize = if (event.anonymous) 0 else 1; // Skip event signature if not anonymous

    for (event.inputs) |param| {
        if (param.indexed) {
            if (topic_idx >= log.topics.len) {
                return error.InsufficientTopics;
            }

            const topic = log.topics[topic_idx];

            // For dynamic types, topic is the hash of the value
            // For static types, topic is the value itself (padded to 32 bytes)
            const value = switch (param.type) {
                .address => blk: {
                    var addr_bytes: [20]u8 = undefined;
                    @memcpy(&addr_bytes, topic.bytes[12..32]);
                    break :blk abi.AbiValue{ .address = Address.fromBytes(addr_bytes) };
                },
                .uint256, .uint128, .uint64, .uint32, .uint16, .uint8 => blk: {
                    break :blk abi.AbiValue{ .uint = U256.fromBytes(topic.bytes) };
                },
                .bool_type => blk: {
                    break :blk abi.AbiValue{ .bool_val = topic.bytes[31] != 0 };
                },
                // For dynamic types, the topic is a hash
                .string, .bytes => blk: {
                    break :blk abi.AbiValue{ .bytes = try allocator.dupe(u8, &topic.bytes) };
                },
                else => return error.UnsupportedIndexedType,
            };

            try indexed_args.append(allocator, value);
            topic_idx += 1;
        }
    }

    // Decode non-indexed arguments from data
    var data_args = try std.ArrayList(abi.AbiValue).initCapacity(allocator, 0);
    defer data_args.deinit(allocator);

    if (log.data.len() > 0) {
        var decoder = decode.Decoder.init(allocator, log.data.data);

        for (event.inputs) |param| {
            if (!param.indexed) {
                const value = switch (param.type) {
                    .uint256, .uint128, .uint64, .uint32, .uint16, .uint8 => blk: {
                        const val = try decoder.decodeUint256();
                        break :blk abi.AbiValue{ .uint = val };
                    },
                    .address => blk: {
                        const addr = try decoder.decodeAddress();
                        break :blk abi.AbiValue{ .address = addr };
                    },
                    .bool_type => blk: {
                        const b = try decoder.decodeBool();
                        break :blk abi.AbiValue{ .bool_val = b };
                    },
                    .string => blk: {
                        const str = try decoder.decodeString();
                        break :blk abi.AbiValue{ .string = str };
                    },
                    .bytes => blk: {
                        const bytes = try decoder.decodeDynamicBytes();
                        break :blk abi.AbiValue{ .bytes = bytes };
                    },
                    else => return error.UnsupportedDataType,
                };

                try data_args.append(allocator, value);
            }
        }
    }

    return ParsedEvent{
        .event = event,
        .indexed_args = try indexed_args.toOwnedSlice(allocator),
        .data_args = try data_args.toOwnedSlice(allocator),
        .log = log,
        .allocator = allocator,
    };
}

/// Parse multiple event logs
pub fn parseEvents(
    allocator: std.mem.Allocator,
    event: abi.Event,
    logs: []const Log,
) ![]ParsedEvent {
    var results = try std.ArrayList(ParsedEvent).initCapacity(allocator, 0);
    defer results.deinit(allocator);

    for (logs) |log| {
        const parsed = parseEvent(allocator, event, log) catch continue;
        try results.append(allocator, parsed);
    }

    return try results.toOwnedSlice(allocator);
}

/// Get event signature hash from event definition
pub fn getEventSignatureHash(allocator: std.mem.Allocator, event: abi.Event) !Hash {
    const sig_str = try event.getSignature(allocator);
    defer allocator.free(sig_str);

    return keccak.eventSignature(sig_str);
}

test "deploy builder creation" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x80 });

    const constructor_params = [_]abi.Parameter{
        .{ .name = "initialSupply", .type = .uint256 },
    };

    var builder = DeployBuilder.init(allocator, bytecode, &constructor_params);
    defer builder.deinit();

    try std.testing.expectEqual(@as(usize, 2), builder.bytecode.len());
}

test "deploy builder with arguments" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x80 });

    var builder = DeployBuilder.init(allocator, bytecode, &[_]abi.Parameter{});
    defer builder.deinit();

    try builder.addArg(.{ .uint = U256.fromInt(1000000) });
    try builder.addArg(.{ .address = Address.fromBytes([_]u8{0x12} ** 20) });

    try std.testing.expectEqual(@as(usize, 2), builder.constructor_args.items.len);
}

test "event signature hash" {
    const allocator = std.testing.allocator;

    const event = abi.Event{
        .name = "Transfer",
        .inputs = &[_]abi.Parameter{
            .{ .name = "from", .type = .address, .indexed = true },
            .{ .name = "to", .type = .address, .indexed = true },
            .{ .name = "value", .type = .uint256, .indexed = false },
        },
    };

    const sig_hash = try getEventSignatureHash(allocator, event);

    // Should produce a valid hash (Transfer event has a known signature)
    try std.testing.expect(!sig_hash.isZero());
}

test "event filter creation" {
    const allocator = std.testing.allocator;

    var filter = EventFilter.init(allocator);
    defer filter.deinit();

    const addr = Address.fromBytes([_]u8{0x12} ** 20);
    filter.setAddress(addr);

    const sig = Hash.fromBytes([_]u8{0x34} ** 32);
    filter.setEventSignature(sig);

    filter.setBlockRange(1000000, 2000000);

    try std.testing.expect(filter.contract_address != null);
    try std.testing.expect(filter.event_signature != null);
    try std.testing.expectEqual(@as(?u64, 1000000), filter.from_block);
    try std.testing.expectEqual(@as(?u64, 2000000), filter.to_block);
}

test "create2 address estimation" {
    const allocator = std.testing.allocator;

    const bytecode = try Bytes.fromSlice(allocator, &[_]u8{ 0x60, 0x80 });

    var builder = DeployBuilder.init(allocator, bytecode, &[_]abi.Parameter{});
    defer builder.deinit();

    const from = Address.fromBytes([_]u8{0x12} ** 20);
    builder.setFrom(from);

    const salt = Hash.fromBytes([_]u8{0x34} ** 32);
    const estimated_addr = try builder.estimateCreate2Address(salt);

    try std.testing.expect(estimated_addr.bytes.len == 20);
}
