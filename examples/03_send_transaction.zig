/// Example: Sending Transactions
/// This example demonstrates how to:
/// - Create transactions (Legacy, EIP-1559)
/// - Sign transactions
/// - Send transactions
/// - Wait for confirmations
/// - Check transaction status
/// - Use middleware for automation
const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n💸 Zigeth Transaction Examples\n", .{});
    std.debug.print("═══════════════════════════════\n\n", .{});

    // Setup: Create wallet and connect to network
    std.debug.print("📡 Setting up wallet and provider...\n", .{});

    // IMPORTANT: Replace with your own private key in production!
    const private_key = try zigeth.crypto.PrivateKey.fromBytes([_]u8{0x01} ** 32);
    const signer_config = zigeth.middleware.SignerConfig.sepolia(); // Using Sepolia testnet

    var signer_middleware = try zigeth.middleware.SignerMiddleware.init(
        allocator,
        private_key,
        signer_config,
    );

    var provider = try zigeth.providers.Networks.sepolia(allocator);
    defer provider.deinit();

    const from_address = try signer_middleware.getAddress();
    const from_hex = try from_address.toHex(allocator);
    defer allocator.free(from_hex);

    std.debug.print("✅ Wallet address: {s}\n", .{from_hex});
    std.debug.print("✅ Connected to Sepolia testnet\n\n", .{});

    // Example 1: Create a simple ETH transfer (Legacy)
    std.debug.print("Example 1: Legacy Transaction\n", .{});
    std.debug.print("─────────────────────────────\n", .{});
    {
        const to_address = try zigeth.primitives.Address.fromHex("0x9999999999999999999999999999999999999999");
        const empty_data = try zigeth.primitives.Bytes.fromSlice(allocator, &[_]u8{});

        var tx = zigeth.types.Transaction.newLegacy(
            allocator,
            to_address,
            @as(u256, 1_000_000_000_000_000), // 0.001 ETH
            empty_data,
            0, // nonce
            21000, // gas_limit
            @as(u256, 20_000_000_000), // 20 gwei gas_price
        );

        tx.from = from_address;

        std.debug.print("✅ Created legacy transaction\n", .{});
        std.debug.print("   To: {any}\n", .{tx.to.?});
        std.debug.print("   Value: {d} wei\n", .{tx.value});
        std.debug.print("   Gas limit: {d}\n", .{tx.gas_limit});
        std.debug.print("   Gas price: {d} wei\n\n", .{tx.gas_price.?});
    }

    // Example 2: Create EIP-1559 transaction
    std.debug.print("Example 2: EIP-1559 Transaction\n", .{});
    std.debug.print("────────────────────────────────\n", .{});
    {
        const to_address = try zigeth.primitives.Address.fromHex("0x8888888888888888888888888888888888888888");
        const empty_data = try zigeth.primitives.Bytes.fromSlice(allocator, &[_]u8{});

        var tx = zigeth.types.Transaction.newEip1559(
            allocator,
            to_address,
            @as(u256, 1_000_000_000_000_000), // 0.001 ETH
            empty_data,
            1, // nonce
            21000, // gas_limit
            @as(u256, 50_000_000_000), // 50 gwei max_fee
            @as(u256, 2_000_000_000), // 2 gwei priority_fee
            11155111, // chain_id (Sepolia)
            null, // access_list
        );

        tx.from = from_address;

        std.debug.print("✅ Created EIP-1559 transaction\n", .{});
        std.debug.print("   Type: EIP-1559\n", .{});
        std.debug.print("   Max fee: {d} wei\n", .{tx.max_fee_per_gas.?});
        std.debug.print("   Priority fee: {d} wei\n\n", .{tx.max_priority_fee_per_gas.?});
    }

    // Example 3: Using Middleware for Automatic Gas & Nonce
    std.debug.print("Example 3: Transaction with Middleware\n", .{});
    std.debug.print("───────────────────────────────────────\n", .{});
    {
        // Setup middleware
        const gas_config = zigeth.middleware.GasConfig.fast(); // Fast confirmation
        var gas_middleware = zigeth.middleware.GasMiddleware.init(
            allocator,
            provider.getProvider(),
            gas_config,
        );

        var nonce_middleware = try zigeth.middleware.NonceMiddleware.init(
            allocator,
            provider.getProvider(),
            .hybrid, // Hybrid strategy for reliability
        );
        defer nonce_middleware.deinit();

        // Create transaction with middleware
        const to_address = try zigeth.primitives.Address.fromHex("0x7777777777777777777777777777777777777777");
        const empty_data = try zigeth.primitives.Bytes.fromSlice(allocator, &[_]u8{});
        const nonce = try nonce_middleware.reserveNonce(from_address);

        // Create transaction with initial values
        var tx = zigeth.types.Transaction.newEip1559(
            allocator,
            to_address,
            @as(u256, 1_000_000_000_000_000), // 0.001 ETH
            empty_data,
            nonce,
            21000, // initial gas_limit (will be estimated)
            @as(u256, 50_000_000_000), // temp values
            @as(u256, 2_000_000_000),
            11155111, // Sepolia
            null,
        );
        tx.from = from_address;

        // Apply middleware to optimize gas settings
        try gas_middleware.applyGasSettings(&tx);

        std.debug.print("✅ Transaction configured with middleware\n", .{});
        std.debug.print("   Nonce: {d} (auto-managed)\n", .{tx.nonce});
        std.debug.print("   Gas limit: {d}\n", .{tx.gas_limit});
        std.debug.print("   Max fee: {any}\n", .{tx.max_fee_per_gas});

        // Check if we have sufficient balance
        const has_balance = try gas_middleware.checkSufficientBalance(
            from_address,
            tx.value,
            tx.gas_limit,
        );
        std.debug.print("   Sufficient balance: {}\n\n", .{has_balance});
    }

    // Example 4: Sign transaction
    std.debug.print("Example 4: Sign Transaction\n", .{});
    std.debug.print("───────────────────────────\n", .{});
    {
        const to_address = try zigeth.primitives.Address.fromHex("0x6666666666666666666666666666666666666666");
        const empty_data = try zigeth.primitives.Bytes.fromSlice(allocator, &[_]u8{});

        var tx = zigeth.types.Transaction.newEip1559(
            allocator,
            to_address,
            @as(u256, 1_000_000_000_000_000), // 0.001 ETH
            empty_data,
            0, // nonce
            21000, // gas_limit
            @as(u256, 50_000_000_000), // 50 gwei max_fee
            @as(u256, 2_000_000_000), // 2 gwei priority_fee
            11155111, // Sepolia
            null, // access_list
        );
        tx.from = from_address;

        // Sign the transaction
        const signature = try signer_middleware.signTransaction(&tx);

        std.debug.print("✅ Transaction signed\n", .{});
        std.debug.print("   Signature v: {}\n", .{signature.v});
        std.debug.print("   Signature valid: {}\n", .{signature.isValid()});

        // Sign and serialize for sending
        const raw_tx = try signer_middleware.signAndSerialize(&tx);
        defer allocator.free(raw_tx);

        std.debug.print("   Serialized length: {} bytes\n", .{raw_tx.len});
        std.debug.print("   Ready to send!\n\n", .{});
    }

    // Example 5: Complete transaction flow (simulated)
    std.debug.print("Example 5: Complete Transaction Flow\n", .{});
    std.debug.print("─────────────────────────────────────\n", .{});
    {
        std.debug.print("📝 Transaction flow:\n", .{});
        std.debug.print("   1. Create transaction ✅\n", .{});
        std.debug.print("   2. Get nonce from network ✅\n", .{});
        std.debug.print("   3. Estimate gas limit ✅\n", .{});
        std.debug.print("   4. Get optimal gas price ✅\n", .{});
        std.debug.print("   5. Check balance ✅\n", .{});
        std.debug.print("   6. Sign transaction ✅\n", .{});
        std.debug.print("   7. Serialize to raw bytes ✅\n", .{});
        std.debug.print("   8. Send to network (would use provider.sendRawTransaction)\n", .{});
        std.debug.print("   9. Wait for confirmation (would use provider.waitForTransaction)\n", .{});
        std.debug.print("   10. Verify receipt (would check receipt.status)\n\n", .{});

        std.debug.print("💡 To actually send transactions:\n", .{});
        std.debug.print("   1. Ensure you have testnet ETH\n", .{});
        std.debug.print("   2. Use your own private key\n", .{});
        std.debug.print("   3. Uncomment the send code below:\n\n", .{});

        std.debug.print("   // const tx_hash = try provider.sendRawTransaction(raw_tx);\n", .{});
        std.debug.print("   // const receipt = try provider.waitForTransaction(tx_hash, 60000);\n", .{});
        std.debug.print("   // defer receipt.deinit();\n", .{});
        std.debug.print("   // if (receipt.status == .success) {{\n", .{});
        std.debug.print("   //     std.debug.print(\"Transaction successful!\\n\", .{{}});\n", .{});
        std.debug.print("   // }}\n\n", .{});
    }

    std.debug.print("🎉 All transaction examples completed!\n", .{});
    std.debug.print("💡 Tip: Use Sepolia testnet for actual testing\n\n", .{});
}
