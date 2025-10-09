/// Example: Querying Blockchain Data
/// This example demonstrates how to:
/// - Connect to Ethereum networks
/// - Query account balances
/// - Get block information
/// - Retrieve transactions
/// - Check transaction receipts
/// - Query gas prices

const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n🔍 Zigeth Blockchain Query Examples\n", .{});
    std.debug.print("════════════════════════════════════\n\n", .{});

    // Connect to Ethereum mainnet via Etherspot
    std.debug.print("📡 Connecting to Ethereum mainnet...\n", .{});
    var provider = try zigeth.providers.Networks.mainnet(allocator);
    defer provider.deinit();

    std.debug.print("✅ Connected to Ethereum\n\n", .{});

    // Example 1: Get current block number
    std.debug.print("Example 1: Current Block Number\n", .{});
    std.debug.print("────────────────────────────────\n", .{});
    {
        const block_number = try provider.getBlockNumber();
        std.debug.print("✅ Latest block: {d}\n\n", .{block_number});
    }

    // Example 2: Get chain information
    std.debug.print("Example 2: Chain Information\n", .{});
    std.debug.print("────────────────────────────\n", .{});
    {
        const chain_id = try provider.getChainId();
        const network_id = try provider.getNetworkId();

        std.debug.print("✅ Chain ID: {d}\n", .{chain_id});
        std.debug.print("   Network ID: {d}\n\n", .{network_id});
    }

    // Example 3: Query account balance
    std.debug.print("Example 3: Account Balance\n", .{});
    std.debug.print("──────────────────────────\n", .{});
    {
        // Vitalik's address - simple string literal!
        const address = try zigeth.primitives.Address.fromHex(
            allocator,
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );

        const balance = try provider.getBalance(address);

        const addr_hex = try address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ Address: {s}\n", .{addr_hex});
        std.debug.print("   Balance: {} wei\n", .{balance});

        // Convert to ether
        const ether = try zigeth.utils.units.weiToEther(balance);
        std.debug.print("   Balance: {d:.4} ETH\n\n", .{ether});
    }

    // Example 4: Get current gas price
    std.debug.print("Example 4: Gas Price\n", .{});
    std.debug.print("────────────────────\n", .{});
    {
        const gas_price = try provider.getGasPrice();

        std.debug.print("✅ Gas price: {} wei\n", .{gas_price});

        // Convert to gwei
        const gas_u64 = try gas_price.toU64();
        const gwei = @as(f64, @floatFromInt(gas_u64)) / 1_000_000_000.0;
        std.debug.print("   Gas price: {d:.2} gwei\n\n", .{gwei});
    }

    // Example 5: Get latest block details
    std.debug.print("Example 5: Latest Block\n", .{});
    std.debug.print("───────────────────────\n", .{});
    {
        const block = try provider.getLatestBlock();
        defer block.deinit();

        const block_hash = try block.hash.toHex(allocator);
        defer allocator.free(block_hash);

        std.debug.print("✅ Block #{d}\n", .{block.header.number});
        std.debug.print("   Hash: {s}\n", .{block_hash});
        std.debug.print("   Timestamp: {d}\n", .{block.header.timestamp});
        std.debug.print("   Gas used: {d}\n", .{block.header.gas_used});
        std.debug.print("   Gas limit: {d}\n", .{block.header.gas_limit});
        std.debug.print("   Transactions: {d}\n", .{block.transactions.len});

        if (block.header.base_fee_per_gas) |base_fee| {
            std.debug.print("   Base fee: {} wei\n", .{base_fee});
        }
        std.debug.print("\n", .{});
    }

    // Example 6: Get transaction count (nonce)
    std.debug.print("Example 6: Transaction Count\n", .{});
    std.debug.print("────────────────────────────\n", .{});
    {
        // Vitalik's address
        const address = try zigeth.primitives.Address.fromHex(
            allocator,
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );

        const nonce = try provider.getTransactionCount(address);

        const addr_hex = try address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ Address: {s}\n", .{addr_hex});
        std.debug.print("   Transaction count (nonce): {d}\n\n", .{nonce});
    }

    // Example 7: Check if address is a contract
    std.debug.print("Example 7: Contract Detection\n", .{});
    std.debug.print("──────────────────────────────\n", .{});
    {
        // USDT contract on Ethereum
        const usdt_address = try zigeth.primitives.Address.fromHex(
            allocator,
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        );

        const is_contract = try provider.isContract(usdt_address);

        const addr_hex = try usdt_address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ Address: {s}\n", .{addr_hex});
        std.debug.print("   Is contract: {}\n\n", .{is_contract});
    }

    // Example 8: Multi-chain queries
    std.debug.print("Example 8: Multi-Chain Queries\n", .{});
    std.debug.print("───────────────────────────────\n", .{});
    {
        // Connect to different networks
        const networks = [_]struct {
            name: []const u8,
            provider_fn: fn (std.mem.Allocator) anyerror!zigeth.providers.HttpProvider,
        }{
            .{ .name = "Ethereum", .provider_fn = zigeth.providers.Networks.mainnet },
            .{ .name = "Polygon", .provider_fn = zigeth.providers.Networks.polygon },
            .{ .name = "Arbitrum", .provider_fn = zigeth.providers.Networks.arbitrum },
        };

        for (networks) |network| {
            var net_provider = try network.provider_fn(allocator);
            defer net_provider.deinit();

            const chain_id = try net_provider.getChainId();
            const block_num = try net_provider.getBlockNumber();

            std.debug.print("✅ {s}: Chain ID {d}, Block #{d}\n", .{
                network.name,
                chain_id,
                block_num,
            });
        }
        std.debug.print("\n", .{});
    }

    std.debug.print("🎉 All blockchain query examples completed!\n\n", .{});
}

