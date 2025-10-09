/// Example: Transaction Receipts and Status
/// This example demonstrates how to:
/// - Get transaction receipts
/// - Check transaction status
/// - Parse transaction data
/// - Calculate transaction fees
/// - Filter logs from receipts
const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n🧾 Zigeth Transaction Receipt Examples\n", .{});
    std.debug.print("═══════════════════════════════════════\n\n", .{});

    // Connect to Ethereum mainnet
    var provider = try zigeth.providers.Networks.mainnet(allocator);
    defer provider.deinit();

    std.debug.print("✅ Connected to Ethereum mainnet\n\n", .{});

    // Example 1: Transaction Receipt Structure
    std.debug.print("Example 1: Receipt Structure\n", .{});
    std.debug.print("────────────────────────────\n", .{});
    {
        std.debug.print("✅ Receipt contains:\n", .{});
        std.debug.print("   • transaction_hash - Transaction identifier\n", .{});
        std.debug.print("   • transaction_index - Position in block\n", .{});
        std.debug.print("   • block_hash - Block identifier\n", .{});
        std.debug.print("   • block_number - Block number\n", .{});
        std.debug.print("   • from - Sender address\n", .{});
        std.debug.print("   • to - Recipient address (or null for contract creation)\n", .{});
        std.debug.print("   • gas_used - Actual gas consumed\n", .{});
        std.debug.print("   • effective_gas_price - Gas price paid\n", .{});
        std.debug.print("   • status - Success or failure\n", .{});
        std.debug.print("   • contract_address - Deployed contract (if any)\n", .{});
        std.debug.print("   • logs - Event logs emitted\n", .{});
        std.debug.print("   • logs_bloom - Bloom filter for efficient log searching\n\n", .{});
    }

    // Example 2: Check transaction status
    std.debug.print("Example 2: Transaction Status\n", .{});
    std.debug.print("─────────────────────────────\n", .{});
    {
        // Example transaction hash (would be from an actual transaction)
        const tx_hash = zigeth.primitives.Hash.fromBytes([_]u8{0xAB} ** 32);

        const hash_hex = try tx_hash.toHex(allocator);
        defer allocator.free(hash_hex);

        std.debug.print("📝 To check transaction status:\n", .{});
        std.debug.print("   Transaction: {s}\n\n", .{hash_hex});

        std.debug.print("   Code pattern:\n", .{});
        std.debug.print("   const receipt = try provider.getTransactionReceipt(tx_hash);\n", .{});
        std.debug.print("   defer receipt.deinit();\n\n", .{});

        std.debug.print("   if (receipt.isSuccess()) {{\n", .{});
        std.debug.print("       std.debug.print(\"✅ Transaction successful!\\n\", .{{}});\n", .{});
        std.debug.print("   }} else {{\n", .{});
        std.debug.print("       std.debug.print(\"❌ Transaction failed\\n\", .{{}});\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    // Example 3: Calculate transaction fee
    std.debug.print("Example 3: Transaction Fee Calculation\n", .{});
    std.debug.print("───────────────────────────────────────\n", .{});
    {
        std.debug.print("✅ Fee calculation:\n", .{});
        std.debug.print("   Fee = gas_used × effective_gas_price\n\n", .{});

        // Simulated receipt data
        const gas_used: u64 = 21000;
        const gas_price: u256 = 50_000_000_000; // 50 gwei

        const fee = gas_price * gas_used;

        std.debug.print("   Gas used: {d}\n", .{gas_used});
        std.debug.print("   Gas price: 50 gwei\n", .{});
        std.debug.print("   Total fee: {d} wei\n", .{fee});

        // Convert to ETH (simple cast since we know it's a small value)
        const fee_u64: u64 = @intCast(fee); // Safe cast for this example
        const fee_eth = @as(f64, @floatFromInt(fee_u64)) / 1_000_000_000_000_000_000.0;
        std.debug.print("   Total fee: {d:.6} ETH\n\n", .{fee_eth});
    }

    // Example 4: Wait for transaction confirmation
    std.debug.print("Example 4: Wait for Confirmation\n", .{});
    std.debug.print("─────────────────────────────────\n", .{});
    {
        std.debug.print("✅ Waiting pattern:\n\n", .{});
        std.debug.print("   // Send transaction\n", .{});
        std.debug.print("   const tx_hash = try provider.sendRawTransaction(signed_tx);\n\n", .{});

        std.debug.print("   // Wait for confirmation (60 seconds timeout)\n", .{});
        std.debug.print("   const receipt = try provider.waitForTransaction(\n", .{});
        std.debug.print("       tx_hash,\n", .{});
        std.debug.print("       60000,  // timeout in milliseconds\n", .{});
        std.debug.print("       1000    // poll interval in milliseconds\n", .{});
        std.debug.print("   );\n", .{});
        std.debug.print("   defer receipt.deinit();\n\n", .{});

        std.debug.print("   if (receipt.isSuccess()) {{\n", .{});
        std.debug.print("       std.debug.print(\"Transaction confirmed!\\n\", .{{}});\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    // Example 5: Parse logs from receipt
    std.debug.print("Example 5: Parse Event Logs\n", .{});
    std.debug.print("───────────────────────────\n", .{});
    {
        std.debug.print("✅ Log parsing pattern:\n\n", .{});
        std.debug.print("   for (receipt.logs) |log| {{\n", .{});
        std.debug.print("       // Check event signature (topic[0])\n", .{});
        std.debug.print("       const event_sig = log.getEventSignature();\n\n", .{});

        std.debug.print("       if (event_sig) |sig| {{\n", .{});
        std.debug.print("           // Match against known events\n", .{});
        std.debug.print("           if (log.matchesSignature(transfer_signature)) {{\n", .{});
        std.debug.print("               // Parse Transfer event\n", .{});
        std.debug.print("               const from = log.getIndexedParam(0);\n", .{});
        std.debug.print("               const to = log.getIndexedParam(1);\n", .{});
        std.debug.print("               // Decode data for value\n", .{});
        std.debug.print("           }}\n", .{});
        std.debug.print("       }}\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    // Example 6: Contract creation receipt
    std.debug.print("Example 6: Contract Creation\n", .{});
    std.debug.print("────────────────────────────\n", .{});
    {
        std.debug.print("✅ When deploying a contract:\n\n", .{});
        std.debug.print("   const receipt = try provider.getTransactionReceipt(deploy_tx_hash);\n", .{});
        std.debug.print("   defer receipt.deinit();\n\n", .{});

        std.debug.print("   if (receipt.contract_address) |addr| {{\n", .{});
        std.debug.print("       // Contract was deployed!\n", .{});
        std.debug.print("       std.debug.print(\"Contract deployed at: {{}}\\n\", .{{addr}});\n", .{});
        std.debug.print("       \n", .{});
        std.debug.print("       // Verify it's a contract\n", .{});
        std.debug.print("       const is_contract = try provider.isContract(addr);\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    // Example 7: Transaction types in receipts
    std.debug.print("Example 7: Transaction Types\n", .{});
    std.debug.print("────────────────────────────\n", .{});
    {
        std.debug.print("✅ Receipt transaction_type field:\n", .{});
        std.debug.print("   0 (0x00) - Legacy transaction\n", .{});
        std.debug.print("   1 (0x01) - EIP-2930 (Access Lists)\n", .{});
        std.debug.print("   2 (0x02) - EIP-1559 (Fee Market)\n", .{});
        std.debug.print("   3 (0x03) - EIP-4844 (Blob Transactions)\n", .{});
        std.debug.print("   4 (0x04) - EIP-7702 (Set EOA Code)\n\n", .{});
    }

    // Example 8: Bloom filter usage
    std.debug.print("Example 8: Bloom Filters\n", .{});
    std.debug.print("────────────────────────\n", .{});
    {
        std.debug.print("✅ Bloom filters for efficient log searching:\n", .{});
        std.debug.print("   • Receipts include logs_bloom (256 bytes)\n", .{});
        std.debug.print("   • Quick check if address/topic might be in logs\n", .{});
        std.debug.print("   • Reduces need to scan all logs\n", .{});
        std.debug.print("   • False positives possible, no false negatives\n\n", .{});

        std.debug.print("   Usage:\n", .{});
        std.debug.print("   if (receipt.logs_bloom.contains(topic_hash)) {{\n", .{});
        std.debug.print("       // Topic might be in logs, check actual logs\n", .{});
        std.debug.print("   }}\n\n", .{});
    }

    std.debug.print("🎉 All receipt examples completed!\n", .{});
    std.debug.print("💡 Tip: Always check receipt.status before considering TX successful\n\n", .{});
}
