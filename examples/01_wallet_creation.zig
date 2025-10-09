/// Example: Wallet Creation and Management
/// This example demonstrates how to:
/// - Create a new random wallet
/// - Import a wallet from private key
/// - Export private keys
/// - Generate and use mnemonic phrases
/// - Create HD wallets
/// - Encrypt and store wallets

const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n🔑 Zigeth Wallet Creation Examples\n", .{});
    std.debug.print("═══════════════════════════════════\n\n", .{});

    // Example 1: Generate a new random wallet
    std.debug.print("Example 1: Generate Random Wallet\n", .{});
    std.debug.print("─────────────────────────────────\n", .{});
    {
        var wallet = try zigeth.signer.Wallet.generate(allocator);
        const address = try wallet.getAddress();

        const addr_hex = try address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ Generated new wallet\n", .{});
        std.debug.print("   Address: {s}\n\n", .{addr_hex});
    }

    // Example 2: Import wallet from private key hex
    std.debug.print("Example 2: Import from Private Key\n", .{});
    std.debug.print("───────────────────────────────────\n", .{});
    {
        const private_key_hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        var wallet = try zigeth.signer.Wallet.fromPrivateKeyHex(allocator, private_key_hex);
        const address = try wallet.getAddress();

        const addr_hex = try address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("✅ Imported wallet from private key\n", .{});
        std.debug.print("   Address: {s}\n\n", .{addr_hex});
    }

    // Example 3: Export private key
    std.debug.print("Example 3: Export Private Key\n", .{});
    std.debug.print("──────────────────────────────\n", .{});
    {
        const private_key = try zigeth.crypto.PrivateKey.fromBytes([_]u8{0x42} ** 32);
        const wallet = try zigeth.signer.Wallet.init(allocator, private_key);

        const exported_key = try wallet.exportPrivateKey();
        defer allocator.free(exported_key);

        std.debug.print("✅ Exported private key\n", .{});
        std.debug.print("   Private Key: {s}\n", .{exported_key});
        std.debug.print("   ⚠️  Keep this secret!\n\n", .{});
    }

    // Example 4: Create wallet from mnemonic phrase
    std.debug.print("Example 4: Mnemonic Phrase (BIP-39)\n", .{});
    std.debug.print("────────────────────────────────────\n", .{});
    {
        // In production, use a real BIP-39 phrase
        const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        var mnemonic = try zigeth.signer.Mnemonic.fromPhrase(allocator, phrase);
        defer mnemonic.deinit();

        // Convert to seed with optional passphrase
        const seed = try mnemonic.toSeed(""); // Empty passphrase
        defer allocator.free(seed);

        std.debug.print("✅ Created mnemonic wallet\n", .{});
        std.debug.print("   Phrase: {s}\n", .{phrase});
        std.debug.print("   Seed length: {} bytes\n\n", .{seed.len});
    }

    // Example 5: HD Wallet - Multiple accounts from one seed
    std.debug.print("Example 5: HD Wallet (BIP-32/BIP-44)\n", .{});
    std.debug.print("─────────────────────────────────────\n", .{});
    {
        // Generate seed (in production, use mnemonic)
        const seed = [_]u8{0xAB} ** 64;

        const hd_wallet = try zigeth.signer.HDWallet.fromSeed(allocator, &seed);

        std.debug.print("✅ Created HD wallet\n", .{});

        // Derive multiple accounts
        var i: u32 = 0;
        while (i < 3) : (i += 1) {
            var account_wallet = try hd_wallet.getWallet(i);
            const address = try account_wallet.getAddress();

            const addr_hex = try address.toHex(allocator);
            defer allocator.free(addr_hex);

            std.debug.print("   Account {d}: {s}\n", .{ i, addr_hex });
        }
        std.debug.print("\n", .{});
    }

    // Example 6: Encrypted Keystore (JSON V3)
    std.debug.print("Example 6: Encrypted Keystore\n", .{});
    std.debug.print("──────────────────────────────\n", .{});
    {
        const private_key = try zigeth.crypto.PrivateKey.fromBytes([_]u8{0x99} ** 32);
        const password = "SecurePassword123!";

        // Encrypt and create keystore
        var keystore = try zigeth.signer.Keystore.encrypt(
            allocator,
            private_key,
            password,
            .pbkdf2, // or .scrypt
        );
        defer keystore.deinit();

        std.debug.print("✅ Created encrypted keystore\n", .{});
        std.debug.print("   KDF: PBKDF2\n", .{});
        std.debug.print("   Cipher: AES-128-CTR\n", .{});

        // Export to JSON
        const json = try keystore.toJSON();
        defer allocator.free(json);

        std.debug.print("   JSON length: {} bytes\n", .{json.len});

        // Decrypt and recover wallet
        var recovered_wallet = try keystore.toWallet(password);
        const address = try recovered_wallet.getAddress();

        const addr_hex = try address.toHex(allocator);
        defer allocator.free(addr_hex);

        std.debug.print("   Recovered address: {s}\n", .{addr_hex});
        std.debug.print("   ✅ Password verified!\n\n", .{});
    }

    // Example 7: Sign a message
    std.debug.print("Example 7: Message Signing\n", .{});
    std.debug.print("──────────────────────────\n", .{});
    {
        const private_key = try zigeth.crypto.PrivateKey.fromBytes([_]u8{0x88} ** 32);
        var wallet = try zigeth.signer.Wallet.init(allocator, private_key);

        const message = "Hello, Ethereum!";
        const signature = try wallet.signMessage(message);

        std.debug.print("✅ Signed message: \"{s}\"\n", .{message});
        std.debug.print("   Signature valid: {}\n", .{signature.isValid()});
        std.debug.print("   v: {}\n", .{signature.v});
        std.debug.print("   r: {any}\n", .{signature.r});
        std.debug.print("   s: {any}\n\n", .{signature.s});
    }

    std.debug.print("🎉 All wallet examples completed!\n\n", .{});
}

