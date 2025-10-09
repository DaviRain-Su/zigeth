/// Example: Event Monitoring and Subscriptions
/// This example demonstrates how to:
/// - Subscribe to new blocks (WebSocket)
/// - Monitor pending transactions
/// - Filter and parse event logs
/// - Track specific contract events
/// - Use real-time subscriptions
const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n📡 Zigeth Event Monitoring Examples\n", .{});
    std.debug.print("════════════════════════════════════\n\n", .{});

    // Example 1: WebSocket subscription setup
    std.debug.print("Example 1: WebSocket Real-Time Subscriptions\n", .{});
    std.debug.print("─────────────────────────────────────────────\n", .{});
    {
        std.debug.print("✅ WebSocket provider setup:\n\n", .{});

        std.debug.print("   // Create WebSocket provider\n", .{});
        std.debug.print("   var ws_provider = try zigeth.providers.WsProvider.init(\n", .{});
        std.debug.print("       allocator,\n", .{});
        std.debug.print("       \"wss://rpc.etherspot.io/v2/1?api-key=...\"\n", .{});
        std.debug.print("   );\n", .{});
        std.debug.print("   defer ws_provider.deinit();\n\n", .{});

        std.debug.print("   // Connect to WebSocket\n", .{});
        std.debug.print("   try ws_provider.connect();\n", .{});
        std.debug.print("   defer ws_provider.disconnect();\n\n", .{});
    }

    // Example 2: Subscribe to new blocks
    std.debug.print("Example 2: New Block Subscription\n", .{});
    std.debug.print("──────────────────────────────────\n", .{});
    {
        std.debug.print("✅ Subscribe to block headers:\n\n", .{});

        std.debug.print("   // Subscribe to new block headers\n", .{});
        std.debug.print("   const sub_id = try ws_provider.subscribeNewHeads();\n", .{});
        std.debug.print("   defer allocator.free(sub_id);\n\n", .{});

        std.debug.print("   // Receive new blocks in real-time\n", .{});
        std.debug.print("   while (true) {{\n", .{});
        std.debug.print("       const message = try ws_provider.receiveMessage();\n", .{});
        std.debug.print("       defer allocator.free(message);\n\n", .{});

        std.debug.print("       // Parse block header\n", .{});
        std.debug.print("       std.debug.print(\"New block received!\\n\", .{{}});\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    // Example 3: Subscribe to pending transactions
    std.debug.print("Example 3: Pending Transaction Subscription\n", .{});
    std.debug.print("────────────────────────────────────────────\n", .{});
    {
        std.debug.print("✅ Monitor mempool:\n\n", .{});

        std.debug.print("   // Subscribe to pending transactions\n", .{});
        std.debug.print("   const pending_sub = try ws_provider.subscribePendingTransactions();\n", .{});
        std.debug.print("   defer allocator.free(pending_sub);\n\n", .{});

        std.debug.print("   // Receive transaction hashes as they enter mempool\n", .{});
        std.debug.print("   const message = try ws_provider.receiveMessage();\n", .{});
        std.debug.print("   // Parse to get transaction hash\n\n", .{});
    }

    // Example 4: Subscribe to specific contract logs
    std.debug.print("Example 4: Contract Event Subscription\n", .{});
    std.debug.print("───────────────────────────────────────\n", .{});
    {
        // USDC contract - simple string literal!
        const usdc_address = try zigeth.primitives.Address.fromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

        const addr_hex = try usdc_address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ Subscribe to USDC Transfer events:\n", .{});
        std.debug.print("   Contract: {s}\n\n", .{addr_hex});

        std.debug.print("   // Create filter\n", .{});
        std.debug.print("   const filter = zigeth.rpc.FilterOptions{{\n", .{});
        std.debug.print("       .address = usdc_address,\n", .{});
        std.debug.print("       .topics = null, // All events\n", .{});
        std.debug.print("       .from_block = null,\n", .{});
        std.debug.print("       .to_block = null,\n", .{});
        std.debug.print("   }};\n\n", .{});

        std.debug.print("   // Subscribe\n", .{});
        std.debug.print("   const log_sub = try ws_provider.subscribeLogs(filter);\n", .{});
        std.debug.print("   defer allocator.free(log_sub);\n\n", .{});
    }

    // Example 5: Parse ERC-20 Transfer event
    std.debug.print("Example 5: Parse Transfer Event\n", .{});
    std.debug.print("────────────────────────────────\n", .{});
    {
        std.debug.print("✅ ERC-20 Transfer event structure:\n", .{});
        std.debug.print("   event Transfer(address indexed from, address indexed to, uint256 value)\n\n", .{});

        std.debug.print("   Topics:\n", .{});
        std.debug.print("   [0] = keccak256(\"Transfer(address,address,uint256)\")\n", .{});
        std.debug.print("   [1] = from address (indexed)\n", .{});
        std.debug.print("   [2] = to address (indexed)\n\n", .{});

        std.debug.print("   Data:\n", .{});
        std.debug.print("   value (uint256) - non-indexed parameter\n\n", .{});

        std.debug.print("   Parsing code:\n", .{});
        std.debug.print("   const transfer_sig = zigeth.crypto.keccak.eventSignature(\n", .{});
        std.debug.print("       \"Transfer(address,address,uint256)\"\n", .{});
        std.debug.print("   );\n\n", .{});

        std.debug.print("   if (log.matchesSignature(transfer_sig)) {{\n", .{});
        std.debug.print("       const from_hash = log.getIndexedParam(0);\n", .{});
        std.debug.print("       const to_hash = log.getIndexedParam(1);\n", .{});
        std.debug.print("       // Decode log.data for value\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    // Example 6: Historical log filtering
    std.debug.print("Example 6: Historical Log Query\n", .{});
    std.debug.print("────────────────────────────────\n", .{});
    {
        std.debug.print("✅ Query past events:\n\n", .{});

        std.debug.print("   // Get logs from last 1000 blocks\n", .{});
        std.debug.print("   const current_block = try provider.getBlockNumber();\n", .{});
        std.debug.print("   const from_block = current_block - 1000;\n\n", .{});

        std.debug.print("   const filter = zigeth.rpc.FilterOptions{{\n", .{});
        std.debug.print("       .address = contract_address,\n", .{});
        std.debug.print("       .topics = &[_]?zigeth.primitives.Hash{{\n", .{});
        std.debug.print("           transfer_signature, // Filter by event\n", .{});
        std.debug.print("           null, // Any from address\n", .{});
        std.debug.print("           my_address_hash, // Only to my address\n", .{});
        std.debug.print("       }},\n", .{});
        std.debug.print("       .from_block = from_block,\n", .{});
        std.debug.print("       .to_block = current_block,\n", .{});
        std.debug.print("   }};\n\n", .{});

        std.debug.print("   const logs = try provider.eth.getLogs(filter);\n", .{});
        std.debug.print("   defer allocator.free(logs);\n\n", .{});
    }

    // Example 7: Unsubscribe from events
    std.debug.print("Example 7: Unsubscribe\n", .{});
    std.debug.print("──────────────────────\n", .{});
    {
        std.debug.print("✅ Clean up subscriptions:\n\n", .{});

        std.debug.print("   // Unsubscribe from event\n", .{});
        std.debug.print("   try ws_provider.unsubscribe(subscription_id);\n\n", .{});

        std.debug.print("   // Check subscription count\n", .{});
        std.debug.print("   const count = ws_provider.getSubscriptionCount();\n", .{});
        std.debug.print("   std.debug.print(\"Active subscriptions: {{}}\\n\", .{{count}});\n\n", .{});
    }

    // Example 8: Event monitoring best practices
    std.debug.print("Example 8: Best Practices\n", .{});
    std.debug.print("─────────────────────────\n", .{});
    {
        std.debug.print("✅ Event monitoring tips:\n\n", .{});
        std.debug.print("   1. Use WebSocket for real-time events\n", .{});
        std.debug.print("   2. Use HTTP for historical queries\n", .{});
        std.debug.print("   3. Filter by address to reduce data\n", .{});
        std.debug.print("   4. Use indexed parameters for efficient filtering\n", .{});
        std.debug.print("   5. Always check logs_bloom before parsing\n", .{});
        std.debug.print("   6. Handle disconnections and reconnect\n", .{});
        std.debug.print("   7. Process logs in batches for efficiency\n", .{});
        std.debug.print("   8. Store subscription IDs for cleanup\n\n", .{});
    }

    std.debug.print("🎉 All event monitoring examples completed!\n", .{});
    std.debug.print("💡 Tip: Use WebSocket for real-time, HTTP for historical data\n\n", .{});
}
