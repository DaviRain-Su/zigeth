//! Zigeth CLI - Command line interface for Ethereum interactions
const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage(stdout);
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "version")) {
        try stdout.print("zigeth v0.1.0\n", .{});
    } else if (std.mem.eql(u8, command, "help")) {
        try printUsage(stdout);
    } else if (std.mem.eql(u8, command, "address")) {
        try handleAddressCommand(allocator, stdout, args[2..]);
    } else {
        try stdout.print("Unknown command: {s}\n\n", .{command});
        try printUsage(stdout);
    }
}

fn printUsage(writer: anytype) !void {
    try writer.print(
        \\Zigeth - Ethereum library and CLI tool
        \\
        \\Usage: zigeth <command> [options]
        \\
        \\Commands:
        \\  version              Show version information
        \\  help                 Show this help message
        \\  address <command>    Address utilities
        \\
        \\Address commands:
        \\  create               Create a new random address
        \\  checksum <address>   Convert address to checksummed format
        \\
        \\Examples:
        \\  zigeth version
        \\  zigeth address create
        \\
    , .{});
}

fn handleAddressCommand(allocator: std.mem.Allocator, writer: anytype, args: []const [:0]const u8) !void {
    if (args.len == 0) {
        try writer.print("Error: address command requires a subcommand\n", .{});
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "create")) {
        // Create a zero address for demonstration
        const addr = zigeth.primitives.Address.fromBytes([_]u8{0} ** 20);
        const hex_str = try addr.toHex(allocator);
        defer allocator.free(hex_str);
        try writer.print("Address: {s}\n", .{hex_str});
    } else if (std.mem.eql(u8, subcommand, "checksum")) {
        if (args.len < 2) {
            try writer.print("Error: checksum requires an address argument\n", .{});
            return;
        }
        // This is a placeholder - checksum implementation would go here
        try writer.print("Checksum not yet implemented\n", .{});
    } else {
        try writer.print("Unknown address subcommand: {s}\n", .{subcommand});
    }
}

test "address creation" {
    const addr = zigeth.primitives.Address.fromBytes([_]u8{0} ** 20);
    try std.testing.expect(addr.isZero());
}

test "address hex conversion" {
    const allocator = std.testing.allocator;

    const addr = zigeth.primitives.Address.fromBytes([_]u8{ 0xde, 0xad, 0xbe, 0xef } ++ [_]u8{0} ** 16);
    const hex_str = try addr.toHex(allocator);
    defer allocator.free(hex_str);

    try std.testing.expect(std.mem.startsWith(u8, hex_str, "0xdeadbeef"));
}
