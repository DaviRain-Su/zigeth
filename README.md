# Zigeth

A comprehensive Ethereum library for Zig, providing primitives, RPC client, ABI/RLP encoding/decoding, contract interaction, and wallet management for seamless integration with Ethereum networks.

## 🏗️ Architecture

```
zigeth/
├── src/
│   ├── root.zig              # Main library entry point
│   ├── main.zig              # Executable entry point
│   │
│   ├── primitives/           # Core Ethereum data types
│   │   ├── address.zig       # 20-byte Ethereum addresses
│   │   ├── hash.zig          # 32-byte hash values
│   │   ├── signature.zig     # ECDSA signatures
│   │   ├── bytes.zig         # Dynamic byte arrays
│   │   ├── uint.zig          # Large unsigned integers
│   │   └── bloom.zig         # Bloom filters
│   │
│   ├── types/                # Ethereum protocol types
│   │   ├── transaction.zig   # Transaction structures
│   │   ├── block.zig         # Block data structures
│   │   ├── receipt.zig       # Transaction receipts
│   │   ├── log.zig           # Event logs
│   │   └── access_list.zig   # EIP-2930 access lists
│   │
│   ├── crypto/               # Cryptographic operations
│   │   ├── keccak.zig        # Keccak-256 hashing
│   │   ├── secp256k1.zig     # Elliptic curve operations
│   │   ├── ecdsa.zig         # Digital signatures
│   │   └── utils.zig         # Crypto utilities
│   │
│   ├── abi/                  # Application Binary Interface
│   │   ├── encode.zig        # ABI encoding
│   │   ├── decode.zig        # ABI decoding
│   │   ├── types.zig         # ABI type definitions
│   │   └── packed.zig        # Packed encoding
│   │
│   ├── rlp/                  # Recursive Length Prefix
│   │   ├── encode.zig        # RLP encoding
│   │   ├── decode.zig        # RLP decoding
│   │   └── packed.zig        # Packed RLP encoding
│   │
│   ├── rpc/                  # JSON-RPC client
│   │   ├── client.zig        # RPC client core
│   │   ├── eth.zig           # eth_* namespace
│   │   ├── net.zig           # net_* namespace
│   │   ├── web3.zig          # web3_* namespace
│   │   ├── debug.zig         # debug_* namespace
│   │   └── types.zig         # RPC type definitions
│   │
│   ├── providers/            # Network providers
│   │   ├── provider.zig      # Base provider interface
│   │   ├── http.zig          # HTTP provider
│   │   ├── ws.zig            # WebSocket provider
│   │   ├── ipc.zig           # IPC provider
│   │   └── mock.zig          # Mock provider for testing
│   │
│   ├── contract/             # Smart contract interaction
│   │   ├── contract.zig      # Contract abstraction
│   │   ├── call.zig          # Contract calls
│   │   ├── deploy.zig        # Contract deployment
│   │   └── event.zig         # Event parsing
│   │
│   ├── signer/               # Transaction signing
│   │   ├── signer.zig        # Signer interface
│   │   ├── wallet.zig        # Software wallet
│   │   ├── keystore.zig      # Keystore management
│   │   └── ledger.zig        # Hardware wallet (Ledger)
│   │
│   ├── middleware/           # Transaction middleware
│   │   ├── gas.zig           # Gas estimation
│   │   ├── nonce.zig         # Nonce management
│   │   └── signer.zig        # Signing middleware
│   │
│   ├── network/              # Network configuration
│   │   ├── chain.zig         # Chain parameters
│   │   └── networks.zig      # Pre-configured networks
│   │
│   ├── sol/                  # Solidity integration
│   │   ├── types.zig         # Solidity type mappings
│   │   └── macros.zig        # Code generation macros
│   │
│   └── utils/                # Utility functions
│       ├── hex.zig           # Hex encoding/decoding
│       ├── format.zig        # Formatting utilities
│       ├── units.zig         # Unit conversions (wei, gwei, ether)
│       └── checksum.zig      # EIP-55 checksummed addresses
│
├── build.zig                 # Build configuration
└── build.zig.zon             # Package manifest
```

## ✨ Features

- **🔐 Cryptographic Primitives**: Keccak-256, ECDSA, secp256k1 operations
- **📦 ABI & RLP**: Full encoding/decoding support for Ethereum data formats
- **🌐 Multiple Providers**: HTTP, WebSocket, IPC, and mock providers
- **📡 JSON-RPC Client**: Complete implementation of eth, net, web3, and debug namespaces
- **📝 Smart Contracts**: Contract deployment, interaction, and event parsing
- **🔑 Wallet Management**: Software wallets, keystore, and Ledger hardware wallet support
- **⚙️ Middleware**: Gas estimation, nonce management, and transaction signing
- **🌍 Network Support**: Pre-configured settings for major Ethereum networks
- **🧰 Utilities**: Hex encoding, unit conversions, checksummed addresses

## 📋 Requirements

- Zig 0.14.1 or later

## 🚀 Installation

Add zigeth to your project's `build.zig.zon`:

```zig
.dependencies = .{
    .zigeth = .{
        .url = "https://github.com/yourusername/zigeth/archive/main.tar.gz",
        .hash = "...", // Run `zig build` to get the hash
    },
},
```

Then in your `build.zig`:

```zig
const zigeth = b.dependency("zigeth", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("zigeth", zigeth.module("zigeth"));
```

## 📖 Quick Start

```zig
const std = @import("std");
const zigeth = @import("zigeth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create an HTTP provider
    const provider = try zigeth.providers.HttpProvider.init(
        allocator,
        "https://eth-mainnet.g.alchemy.com/v2/your-api-key"
    );
    defer provider.deinit();

    // Get the latest block number
    const block_number = try provider.getBlockNumber();
    std.debug.print("Latest block: {}\n", .{block_number});

    // Create an address
    const addr = try zigeth.primitives.Address.fromHex(
        "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    );

    // Get balance
    const balance = try provider.getBalance(addr, .latest);
    std.debug.print("Balance: {} wei\n", .{balance});
}
```

## 🔨 Building

Build the library:
```bash
zig build
```

Run tests:
```bash
zig build test
```

Run the executable:
```bash
zig build run
```

## 📚 Documentation

Generate and view documentation:
```bash
zig build-lib src/root.zig -femit-docs
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

[Add your license information here]

## 🔗 Resources

- [Zig Programming Language](https://ziglang.org/)
- [Ethereum Documentation](https://ethereum.org/en/developers/docs/)
- [JSON-RPC API](https://ethereum.org/en/developers/docs/apis/json-rpc/)
- [ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html)
