const std = @import("std");
const u256ToU64 = @import("../primitives/uint.zig").u256ToU64;

/// Ethereum unit denominations
pub const Unit = enum {
    wei,
    kwei, // kilowei (1e3)
    mwei, // megawei (1e6)
    gwei, // gigawei (1e9)
    szabo, // microether (1e12)
    finney, // milliether (1e15)
    ether, // ether (1e18)
    kether, // kiloether (1e21)
    mether, // megaether (1e24)
    gether, // gigaether (1e27)
    tether, // teraether (1e30)

    /// Get the multiplier for this unit (as powers of 10)
    pub fn exponent(self: Unit) u8 {
        return switch (self) {
            .wei => 0,
            .kwei => 3,
            .mwei => 6,
            .gwei => 9,
            .szabo => 12,
            .finney => 15,
            .ether => 18,
            .kether => 21,
            .mether => 24,
            .gether => 27,
            .tether => 30,
        };
    }

    /// Get the multiplier as a u256
    pub fn multiplier(self: Unit) u256 {
        const exp = self.exponent();
        var result: u256 = 1;

        var i: u8 = 0;
        while (i < exp) : (i += 1) {
            result = result *% 10;
        }

        return result;
    }
};

/// Convert from wei to another unit
pub fn fromWei(wei: u256, unit: Unit) WeiConversion {
    const mult = unit.multiplier();
    const quotient = wei / mult;
    const remainder = wei % mult;

    return WeiConversion{
        .integer_part = quotient,
        .remainder_wei = remainder,
        .unit = unit,
    };
}

/// Convert to wei from another unit
pub fn toWei(amount: u64, unit: Unit) u256 {
    const mult = unit.multiplier();
    return @as(u256, amount) *% mult;
}

/// Convert to wei from a floating point amount (ether)
pub fn etherToWei(ether: f64) !u256 {
    if (ether < 0) {
        return error.NegativeValue;
    }

    // 1 ether = 1e18 wei
    const wei_per_ether: f64 = 1_000_000_000_000_000_000.0;
    const wei_value = ether * wei_per_ether;

    if (wei_value > @as(f64, @floatFromInt(std.math.maxInt(u64)))) {
        return error.Overflow;
    }

    return @as(u256, @as(u64, @intFromFloat(wei_value)));
}

/// Convert wei to ether as a floating point
pub fn weiToEther(wei: u256) !f64 {
    const wei_u64 = u256ToU64(wei) catch return error.ValueTooLarge;
    const wei_per_ether: f64 = 1_000_000_000_000_000_000.0;
    return @as(f64, @floatFromInt(wei_u64)) / wei_per_ether;
}

/// Result of a wei conversion
pub const WeiConversion = struct {
    integer_part: u256,
    remainder_wei: u256,
    unit: Unit,

    /// Format as a string with decimal places
    pub fn format(
        self: WeiConversion,
        allocator: std.mem.Allocator,
        decimal_places: u8,
    ) ![]u8 {
        const format_module = @import("./format.zig");

        // Get integer part
        const integer_str = try format_module.formatU256Native(allocator, self.integer_part);
        defer allocator.free(integer_str);

        if (decimal_places == 0 or self.remainder_wei == 0) {
            return try std.fmt.allocPrint(allocator, "{s}", .{integer_str});
        }

        // Calculate decimal part
        const mult = self.unit.multiplier();
        const remainder_u64 = u256ToU64(self.remainder_wei) catch 0;
        const divisor = u256ToU64(mult) catch return error.UnitTooLarge;

        // Convert remainder to decimal string
        const decimal_value = (@as(f64, @floatFromInt(remainder_u64)) / @as(f64, @floatFromInt(divisor))) *
            std.math.pow(f64, 10.0, @as(f64, @floatFromInt(decimal_places)));

        const decimal_int = @as(u64, @intFromFloat(decimal_value));

        // Format with appropriate decimal places using allocPrint
        const decimal_str = try std.fmt.allocPrint(allocator, "{d}", .{decimal_int});
        defer allocator.free(decimal_str);

        // Pad with zeros if needed
        var result = try std.ArrayList(u8).initCapacity(allocator, 0);
        errdefer result.deinit(allocator);

        try result.appendSlice(allocator, integer_str);
        try result.append(allocator, '.');

        // Add leading zeros if decimal is shorter than decimal_places
        if (decimal_str.len < decimal_places) {
            var zeros_needed = decimal_places - decimal_str.len;
            while (zeros_needed > 0) : (zeros_needed -= 1) {
                try result.append(allocator, '0');
            }
        }
        try result.appendSlice(allocator, decimal_str);

        return try result.toOwnedSlice(allocator);
    }
};

/// Parse a unit string to Unit enum
pub fn parseUnit(str: []const u8) !Unit {
    const lower = try std.ascii.allocLowerString(std.heap.page_allocator, str);
    defer std.heap.page_allocator.free(lower);

    if (std.mem.eql(u8, lower, "wei")) return .wei;
    if (std.mem.eql(u8, lower, "kwei")) return .kwei;
    if (std.mem.eql(u8, lower, "mwei")) return .mwei;
    if (std.mem.eql(u8, lower, "gwei")) return .gwei;
    if (std.mem.eql(u8, lower, "szabo")) return .szabo;
    if (std.mem.eql(u8, lower, "finney")) return .finney;
    if (std.mem.eql(u8, lower, "ether")) return .ether;
    if (std.mem.eql(u8, lower, "kether")) return .kether;
    if (std.mem.eql(u8, lower, "mether")) return .mether;
    if (std.mem.eql(u8, lower, "gether")) return .gether;
    if (std.mem.eql(u8, lower, "tether")) return .tether;

    return error.InvalidUnit;
}

/// Common gas price conversions
pub const GasPrice = struct {
    /// Convert gwei to wei
    pub fn gweiToWei(gwei: u64) u256 {
        return toWei(gwei, .gwei);
    }

    /// Convert wei to gwei
    pub fn weiToGwei(wei: u256) !u64 {
        const conversion = fromWei(wei, .gwei);
        return u256ToU64(conversion.integer_part);
    }
};

test "unit exponents" {
    try std.testing.expectEqual(@as(u8, 0), Unit.wei.exponent());
    try std.testing.expectEqual(@as(u8, 9), Unit.gwei.exponent());
    try std.testing.expectEqual(@as(u8, 18), Unit.ether.exponent());
}

test "to wei from ether" {
    const wei = toWei(1, .ether);
    const expected: u256 = 1_000_000_000_000_000_000;
    try std.testing.expectEqual(expected, wei);
}

test "to wei from gwei" {
    const wei = toWei(1, .gwei);
    const expected: u256 = 1_000_000_000;
    try std.testing.expectEqual(expected, wei);
}

test "from wei to ether" {
    const wei: u256 = 1_000_000_000_000_000_000;
    const conversion = fromWei(wei, .ether);

    try std.testing.expectEqual(@as(u256, 1), conversion.integer_part);
    try std.testing.expectEqual(@as(u256, 0), conversion.remainder_wei);
}

test "from wei to gwei" {
    const wei: u256 = 5_000_000_000;
    const conversion = fromWei(wei, .gwei);

    try std.testing.expectEqual(@as(u256, 5), conversion.integer_part);
    try std.testing.expectEqual(@as(u256, 0), conversion.remainder_wei);
}

test "ether to wei float" {
    const wei = try etherToWei(1.5);
    const expected: u256 = 1_500_000_000_000_000_000;
    try std.testing.expectEqual(expected, wei);
}

test "wei to ether float" {
    const wei: u256 = 1_500_000_000_000_000_000;
    const ether = try weiToEther(wei);
    try std.testing.expectApproxEqRel(1.5, ether, 0.0001);
}

test "gas price conversions" {
    const wei = GasPrice.gweiToWei(30);
    const expected: u256 = 30_000_000_000;
    try std.testing.expectEqual(expected, wei);

    const gwei = try GasPrice.weiToGwei(wei);
    try std.testing.expectEqual(@as(u64, 30), gwei);
}

test "parse unit" {
    try std.testing.expectEqual(Unit.wei, try parseUnit("wei"));
    try std.testing.expectEqual(Unit.gwei, try parseUnit("gwei"));
    try std.testing.expectEqual(Unit.ether, try parseUnit("ether"));
    try std.testing.expectEqual(Unit.gwei, try parseUnit("GWEI"));
    try std.testing.expectError(error.InvalidUnit, parseUnit("invalid"));
}

test "conversion format" {
    const allocator = std.testing.allocator;

    const wei: u256 = 1_500_000_000;
    const conversion = fromWei(wei, .gwei);

    const formatted = try conversion.format(allocator, 2);
    defer allocator.free(formatted);

    try std.testing.expect(formatted.len > 0);
}
