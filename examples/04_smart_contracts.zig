/// Example: Smart Contract Interaction
/// This example demonstrates how to:
/// - Interact with ERC-20 tokens
/// - Call view functions
/// - Send transactions to contracts
/// - Parse event logs
/// - Use contract abstractions
const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n📜 Zigeth Smart Contract Examples\n", .{});
    std.debug.print("══════════════════════════════════\n\n", .{});

    // Connect to Ethereum mainnet
    var provider = try zigeth.providers.Networks.mainnet(allocator);
    defer provider.deinit();

    // Example 1: ERC-20 Token Interaction
    std.debug.print("Example 1: ERC-20 Token (USDC)\n", .{});
    std.debug.print("───────────────────────────────\n", .{});
    {
        // USDC contract on Ethereum mainnet - simple string literal!
        const usdc_address = try zigeth.primitives.Address.fromHex(allocator, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

        const addr_hex = try usdc_address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ USDC Contract: {s}\n", .{addr_hex});

        // Create ERC-20 contract binding
        const erc20 = try zigeth.sol.Erc20Contract(allocator, usdc_address);
        defer erc20.deinit();

        std.debug.print("   Contract type: ERC-20\n", .{});
        std.debug.print("   Standard functions: balanceOf, transfer, approve, etc.\n\n", .{});
    }

    // Example 2: Encode function call (balanceOf)
    std.debug.print("Example 2: Encode Function Call\n", .{});
    std.debug.print("────────────────────────────────\n", .{});
    {
        // Create function definition
        const balance_of = zigeth.abi.Function{
            .name = "balanceOf",
            .inputs = &[_]zigeth.abi.Parameter{
                .{
                    .name = "account",
                    .type = try zigeth.abi.AbiType.parse(allocator, "address"),
                    .indexed = false,
                },
            },
            .outputs = &[_]zigeth.abi.Parameter{
                .{
                    .name = "balance",
                    .type = try zigeth.abi.AbiType.parse(allocator, "uint256"),
                    .indexed = false,
                },
            },
            .state_mutability = .view,
        };

        // Encode call
        const check_address = try zigeth.primitives.Address.fromHex(allocator, "0x0000000000000000000000000000000000000001");
        const params = [_]zigeth.abi.AbiValue{
            .{ .address = check_address },
        };

        const encoded = try zigeth.abi.encodeFunctionCall(
            allocator,
            balance_of,
            &params,
        );
        defer allocator.free(encoded);

        const encoded_hex = try zigeth.utils.hex.bytesToHex(allocator, encoded);
        defer allocator.free(encoded_hex);

        std.debug.print("✅ Encoded balanceOf call\n", .{});
        std.debug.print("   Function: balanceOf(address)\n", .{});
        std.debug.print("   Encoded data: {s}\n", .{encoded_hex[0..@min(66, encoded_hex.len)]});
        std.debug.print("   Data length: {} bytes\n\n", .{encoded.len});
    }

    // Example 3: Parse event logs
    std.debug.print("Example 3: Parse Event Logs\n", .{});
    std.debug.print("───────────────────────────\n", .{});
    {
        // ERC-20 Transfer event signature
        const transfer_sig = "Transfer(address,address,uint256)";
        const event_hash = zigeth.crypto.keccak.eventSignature(transfer_sig);

        const hash_hex = try event_hash.toHex(allocator);
        defer allocator.free(hash_hex);

        std.debug.print("✅ Transfer event signature\n", .{});
        std.debug.print("   Event: {s}\n", .{transfer_sig});
        std.debug.print("   Keccak-256 hash: {s}\n\n", .{hash_hex});
    }

    // Example 4: Contract deployment data
    std.debug.print("Example 4: Contract Deployment\n", .{});
    std.debug.print("──────────────────────────────\n", .{});
    {
        // Example: Simple storage contract
        const bytecode = [_]u8{
            0x60, 0x80, 0x60, 0x40, // Contract bytecode (simplified)
            0x52, 0x34, 0x80, 0x15,
        };

        std.debug.print("✅ Contract deployment\n", .{});
        std.debug.print("   Bytecode length: {} bytes\n", .{bytecode.len});
        std.debug.print("   Deployment uses 'to' = null\n", .{});
        std.debug.print("   Contract address calculated from sender + nonce\n\n", .{});
    }

    // Example 5: Using pre-defined selectors
    std.debug.print("Example 5: Function Selectors\n", .{});
    std.debug.print("─────────────────────────────\n", .{});
    {
        const selectors = zigeth.sol.Selectors;

        std.debug.print("✅ Common ERC-20 selectors:\n", .{});
        std.debug.print("   balanceOf:     0x{x:0>8}\n", .{selectors.ERC20_BALANCE_OF});
        std.debug.print("   transfer:      0x{x:0>8}\n", .{selectors.ERC20_TRANSFER});
        std.debug.print("   approve:       0x{x:0>8}\n", .{selectors.ERC20_APPROVE});
        std.debug.print("   transferFrom:  0x{x:0>8}\n", .{selectors.ERC20_TRANSFER_FROM});
        std.debug.print("   allowance:     0x{x:0>8}\n\n", .{selectors.ERC20_ALLOWANCE});
    }

    // Example 6: ABI encoding patterns
    std.debug.print("Example 6: ABI Encoding Patterns\n", .{});
    std.debug.print("─────────────────────────────────\n", .{});
    {
        // Encode different types
        const types_to_encode = [_]struct {
            type_name: []const u8,
            description: []const u8,
        }{
            .{ .type_name = "uint256", .description = "Unsigned 256-bit integer" },
            .{ .type_name = "address", .description = "Ethereum address (20 bytes)" },
            .{ .type_name = "bool", .description = "Boolean value" },
            .{ .type_name = "bytes", .description = "Dynamic byte array" },
            .{ .type_name = "string", .description = "UTF-8 string" },
            .{ .type_name = "uint256[]", .description = "Dynamic array of uint256" },
            .{ .type_name = "bytes32", .description = "Fixed 32-byte array" },
        };

        std.debug.print("✅ Supported ABI types:\n", .{});
        for (types_to_encode) |t| {
            std.debug.print("   • {s:<12} - {s}\n", .{ t.type_name, t.description });
        }
        std.debug.print("\n", .{});
    }

    // Example 7: Event filtering
    std.debug.print("Example 7: Event Filtering\n", .{});
    std.debug.print("──────────────────────────\n", .{});
    {
        // USDC contract
        const usdc_address = try zigeth.primitives.Address.fromHex(allocator, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

        // Create filter for Transfer events
        const filter = zigeth.rpc.FilterOptions{
            .address = usdc_address,
            .topics = null, // Could filter by specific addresses
            .from_block = null,
            .to_block = null,
        };

        std.debug.print("✅ Event filter created\n", .{});
        std.debug.print("   Contract: USDC\n", .{});
        std.debug.print("   Event: All Transfer events\n", .{});
        std.debug.print("   Usage: provider.eth.getLogs(filter)\n\n", .{});
    }

    // Example 8: Multi-call pattern (reading multiple values)
    std.debug.print("Example 8: Multi-Call Pattern\n", .{});
    std.debug.print("──────────────────────────────\n", .{});
    {
        std.debug.print("✅ Best practices for multi-call:\n", .{});
        std.debug.print("   1. Create provider connection\n", .{});
        std.debug.print("   2. Prepare multiple CallParams\n", .{});
        std.debug.print("   3. Execute calls in sequence or parallel\n", .{});
        std.debug.print("   4. Decode results\n", .{});
        std.debug.print("   5. Close connections\n\n", .{});

        std.debug.print("   Example pattern:\n", .{});
        std.debug.print("   - Get token balance\n", .{});
        std.debug.print("   - Get token name\n", .{});
        std.debug.print("   - Get token symbol\n", .{});
        std.debug.print("   - Get token decimals\n", .{});
        std.debug.print("   All in efficient sequence!\n\n", .{});
    }

    std.debug.print("🎉 All smart contract examples completed!\n", .{});
    std.debug.print("💡 Tip: Use ERC-20, ERC-721, ERC-1155 helpers from zigeth.sol\n\n", .{});
}
