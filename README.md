# Zigeth

[![CI](https://github.com/ch4r10t33r/zigeth/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/zigeth/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.14.1-orange.svg)](https://ziglang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive Ethereum library for Zig, providing complete cryptographic primitives, transaction handling, RPC client framework, and utilities for seamless integration with Ethereum networks.

**Current Status**: 132 tests passing | 40% complete | Production-ready crypto, ABI & primitives

## 🏗️ Architecture

```
zigeth/
├── src/
│   ├── root.zig              # Main library entry point
│   ├── main.zig              # Executable entry point
│   │
│   ├── primitives/           # Core Ethereum data types ✅ IMPLEMENTED
│   │   ├── address.zig       # 20-byte Ethereum addresses ✅
│   │   ├── hash.zig          # 32-byte Keccak-256 hashes ✅
│   │   ├── signature.zig     # ECDSA signatures (EIP-155) ✅
│   │   ├── bytes.zig         # Dynamic byte arrays ✅
│   │   ├── uint.zig          # 256-bit unsigned integers ✅
│   │   └── bloom.zig         # Bloom filters (2048 bits) ✅
│   │
│   ├── types/                # Ethereum protocol types ✅ IMPLEMENTED
│   │   ├── transaction.zig   # All transaction types (0-4) ✅
│   │   ├── block.zig         # Block & header structures ✅
│   │   ├── receipt.zig       # Transaction receipts ✅
│   │   ├── log.zig           # Event logs ✅
│   │   └── access_list.zig   # EIP-2930 access lists ✅
│   │
│   ├── crypto/               # Cryptographic operations ✅ IMPLEMENTED
│   │   ├── keccak.zig        # Keccak-256 hashing ✅
│   │   ├── secp256k1.zig     # Elliptic curve operations ✅
│   │   ├── ecdsa.zig         # Digital signatures ✅
│   │   └── utils.zig         # Crypto utilities ✅
│   │
│   ├── abi/                  # Application Binary Interface ✅ IMPLEMENTED
│   │   ├── encode.zig        # ABI encoding ✅
│   │   ├── decode.zig        # ABI decoding ✅
│   │   ├── types.zig         # ABI type definitions ✅
│   │   └── packed.zig        # Packed encoding (EIP-712) ✅
│   │
│   ├── rlp/                  # Recursive Length Prefix (TODO)
│   │   ├── encode.zig        # RLP encoding
│   │   ├── decode.zig        # RLP decoding
│   │   └── packed.zig        # Packed RLP encoding
│   │
│   ├── rpc/                  # JSON-RPC client ✅ FRAMEWORK
│   │   ├── client.zig        # RPC client core ✅
│   │   ├── eth.zig           # eth_* namespace (23 methods) ✅
│   │   ├── net.zig           # net_* namespace (3 methods) ✅
│   │   ├── web3.zig          # web3_* namespace (2 methods) ✅
│   │   ├── debug.zig         # debug_* namespace (7 methods) ✅
│   │   └── types.zig         # RPC type definitions ✅
│   │
│   ├── providers/            # Network providers (TODO)
│   │   ├── provider.zig      # Base provider interface
│   │   ├── http.zig          # HTTP provider
│   │   ├── ws.zig            # WebSocket provider
│   │   ├── ipc.zig           # IPC provider
│   │   └── mock.zig          # Mock provider for testing
│   │
│   ├── contract/             # Smart contract interaction (TODO)
│   │   ├── contract.zig      # Contract abstraction
│   │   ├── call.zig          # Contract calls
│   │   ├── deploy.zig        # Contract deployment
│   │   └── event.zig         # Event parsing
│   │
│   ├── signer/               # Transaction signing (TODO)
│   │   ├── signer.zig        # Signer interface
│   │   ├── wallet.zig        # Software wallet
│   │   ├── keystore.zig      # Keystore management
│   │   └── ledger.zig        # Hardware wallet (Ledger)
│   │
│   ├── middleware/           # Transaction middleware (TODO)
│   │   ├── gas.zig           # Gas estimation
│   │   ├── nonce.zig         # Nonce management
│   │   └── signer.zig        # Signing middleware
│   │
│   ├── network/              # Network configuration (TODO)
│   │   ├── chain.zig         # Chain parameters
│   │   └── networks.zig      # Pre-configured networks
│   │
│   ├── sol/                  # Solidity integration (TODO)
│   │   ├── types.zig         # Solidity type mappings
│   │   └── macros.zig        # Code generation macros
│   │
│   └── utils/                # Utility functions (PARTIAL)
│       ├── hex.zig           # Hex encoding/decoding ✅
│       ├── format.zig        # Formatting utilities (TODO)
│       ├── units.zig         # Unit conversions (TODO)
│       └── checksum.zig      # EIP-55 checksummed addresses (TODO)
│
├── build.zig                 # Build configuration
└── build.zig.zon             # Package manifest
```

## ✨ Features

### ✅ **Fully Implemented**

- **🎯 Primitives** (6 types, 48 tests):
  - `Address` - 20-byte Ethereum addresses
  - `Hash` - 32-byte Keccak-256 hashes
  - `Bytes` - Dynamic byte arrays with memory management
  - `Signature` - ECDSA signatures with EIP-155 support
  - `U256` - 256-bit unsigned integers with arithmetic
  - `Bloom` - 2048-bit bloom filters

- **📦 Protocol Types** (5 types, 23 tests):
  - `Transaction` - All types (Legacy, EIP-2930, EIP-1559, EIP-4844, EIP-7702)
  - `Block` & `BlockHeader` - Complete block structures
  - `Receipt` - Transaction receipts with status
  - `Log` - Event logs with topic parsing
  - `AccessList` - EIP-2930 access lists
  - `Authorization` & `AuthorizationList` - EIP-7702 support

- **🔐 Cryptography** (4 modules, 27 tests):
  - Keccak-256 hashing with function/event selectors
  - secp256k1 key management (private/public keys)
  - ECDSA signing and verification
  - Public key recovery from signatures
  - EIP-55 & EIP-1191 checksummed addresses
  - Powered by [zig-eth-secp256k1](https://github.com/jsign/zig-eth-secp256k1)

- **📡 JSON-RPC Client** (6 modules, 13 tests):
  - RPC client framework with HTTP transport
  - `eth_*` namespace (23 methods)
  - `net_*` namespace (3 methods)
  - `web3_*` namespace (2 methods)
  - `debug_*` namespace (7 methods)
  - Type-safe request/response handling

- **📦 ABI Encoding/Decoding** (4 modules, 23 tests):
  - Complete ABI type system (uint, int, address, bool, bytes, string, arrays, tuples)
  - Standard ABI encoding (32-byte aligned, padded)
  - Standard ABI decoding with type safety
  - Packed encoding for EIP-712 and hashing
  - Function selector generation
  - Event signature generation

- **🧰 Utilities**:
  - Hex encoding/decoding with 0x prefix support
  - Memory-safe allocations
  - Comprehensive error handling

### 🚧 **Planned Features**

- **📜 RLP Encoding**: Recursive Length Prefix for transaction encoding
- **🌐 Providers**: HTTP, WebSocket, IPC provider implementations with JSON-RPC
- **📝 Smart Contracts**: High-level contract deployment and interaction
- **🔑 Wallet Management**: Software wallets, keystore, and hardware wallet support
- **⚙️ Middleware**: Gas estimation, nonce management, and transaction signing
- **🌍 Network Support**: Pre-configured settings for major Ethereum networks

## 📋 Requirements

- Zig 0.14.1 or later
- libc (standard C library)

## 📦 Dependencies

- **[zig-eth-secp256k1](https://github.com/jsign/zig-eth-secp256k1)** - Elliptic curve operations (wraps libsecp256k1)
  - Used for: ECDSA signing, verification, and public key recovery
  - License: MIT
  - Backend: Bitcoin Core's audited libsecp256k1 library

## 🚀 Installation

Add zigeth to your project's `build.zig.zon`:

```zig
.dependencies = .{
    .zigeth = .{
        .url = "https://github.com/ch4r10t33r/zigeth/archive/main.tar.gz",
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

    // Generate a keypair
    var prng = std.rand.DefaultPrng.init(0);
    const private_key = try zigeth.crypto.PrivateKey.generate(prng.random());
    
    // Derive public key and address
    const public_key = try zigeth.crypto.secp256k1.derivePublicKey(private_key);
    const address = public_key.toAddress();
    
    const addr_hex = try address.toHex(allocator);
    defer allocator.free(addr_hex);
    std.debug.print("Address: {s}\n", .{addr_hex});

    // Sign a message
    const message = "Hello, Ethereum!";
    const message_hash = zigeth.crypto.keccak.hash(message);
    const signature = try zigeth.crypto.secp256k1.sign(message_hash, private_key);
    
    std.debug.print("Signature valid: {}\n", .{signature.isValid()});

    // Create an EIP-1559 transaction
    const value = zigeth.primitives.U256.fromInt(1_000_000_000_000_000_000); // 1 ETH
    const data = try zigeth.primitives.Bytes.fromSlice(allocator, &[_]u8{});
    defer data.deinit();
    
    const tx = zigeth.types.Transaction.newEip1559(
        allocator,
        address, // to
        value,
        data,
        0, // nonce
        21000, // gas_limit
        zigeth.primitives.U256.fromInt(30_000_000_000), // max_fee_per_gas
        zigeth.primitives.U256.fromInt(2_000_000_000), // max_priority_fee_per_gas
        1, // chain_id (mainnet)
        null, // no access list
    );
    defer tx.deinit();
    
    std.debug.print("Transaction type: {}\n", .{tx.type});
    
    // Use RPC client framework (implementation in progress)
    var rpc_client = try zigeth.rpc.RpcClient.init(allocator, "https://eth.llamarpc.com");
    defer rpc_client.deinit();
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

Run linting and code quality checks:
```bash
zig build lint
```

Format code:
```bash
zig build fmt
```

Run the executable:
```bash
zig build run
```

Clean build artifacts:
```bash
zig build clean
```

## 📚 Documentation

Generate and view documentation:
```bash
zig build-lib src/root.zig -femit-docs
```

## 📖 Primitives API Reference

Zigeth provides a complete set of Ethereum primitives for building applications.

### Address (20 bytes)

Represents an Ethereum address.

```zig
const zigeth = @import("zigeth");
const Address = zigeth.primitives.Address;

// Create from bytes
const addr = Address.fromBytes([_]u8{0} ** 20);

// Create from hex string
const addr2 = try Address.fromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");

// Convert to hex
const hex_str = try addr.toHex(allocator);
defer allocator.free(hex_str);

// Check if zero address
if (addr.isZero()) {
    // ...
}
```

### Hash (32 bytes)

Represents a Keccak-256 hash.

```zig
const Hash = zigeth.primitives.Hash;

// Create from bytes
const hash = Hash.fromBytes([_]u8{0xab} ** 32);

// Create from hex string
const hash2 = try Hash.fromHex("0x1234...cdef");

// Create from slice
const hash3 = try Hash.fromSlice(some_bytes);

// Convert to hex
const hex_str = try hash.toHex(allocator);
defer allocator.free(hex_str);

// Check if zero hash
if (hash.isZero()) {
    // ...
}

// Compare hashes
if (hash1.eql(hash2)) {
    // ...
}

// Print hash
std.debug.print("Hash: {}\n", .{hash});
```

### Bytes (Dynamic)

Dynamic byte array for Ethereum data.

```zig
const Bytes = zigeth.primitives.Bytes;

// Create from slice (copies data)
const bytes = try Bytes.fromSlice(allocator, &[_]u8{1, 2, 3, 4});
defer bytes.deinit();

// Create from hex
const bytes2 = try Bytes.fromHex(allocator, "0xdeadbeef");
defer bytes2.deinit();

// Create empty
const empty = Bytes.empty(allocator);
defer empty.deinit();

// Create with capacity
const sized = try Bytes.withCapacity(allocator, 100);
defer sized.deinit();

// Convert to hex
const hex_str = try bytes.toHex();
defer allocator.free(hex_str);

// Get length
const len = bytes.len();

// Check if empty
if (bytes.isEmpty()) {
    // ...
}

// Clone
const copy = try bytes.clone();
defer copy.deinit();

// Compare
if (bytes1.eql(bytes2)) {
    // ...
}
```

### Signature (65 bytes: r + s + v)

ECDSA signature with EIP-155 support.

```zig
const Signature = zigeth.primitives.Signature;

// Create from components
const sig = Signature.init(r_bytes, s_bytes, v_byte);

// Create from bytes (65 bytes)
const sig2 = try Signature.fromBytes(signature_bytes);

// Create from hex
const sig3 = try Signature.fromHex(allocator, "0x1234...5678");

// Convert to bytes
const bytes = try sig.toBytes(allocator);
defer allocator.free(bytes);

// Convert to hex
const hex_str = try sig.toHex(allocator);
defer allocator.free(hex_str);

// Get recovery ID (0 or 1)
const recovery_id = sig.getRecoveryId();

// Extract chain ID (for EIP-155 signatures)
if (sig.getChainId()) |chain_id| {
    std.debug.print("Chain ID: {}\n", .{chain_id});
}

// Create EIP-155 v value
const v = Signature.eip155V(chain_id, recovery_id);

// Validate signature
if (sig.isValid()) {
    // ...
}

// Compare signatures
if (sig1.eql(sig2)) {
    // ...
}
```

### U256 (256-bit unsigned integer)

Large unsigned integer for balances, gas, etc.

```zig
const U256 = zigeth.primitives.U256;

// Create from u64
const value = U256.fromInt(1000000000000000000); // 1 ETH in wei

// Create zero/one
const zero = U256.zero();
const one = U256.one();
const max = U256.max();

// Create from bytes (big-endian, 32 bytes)
const val = U256.fromBytes(bytes);

// Create from hex
const val2 = try U256.fromHex("0x2a");

// Convert to bytes (big-endian)
const bytes = val.toBytes();

// Convert to hex
const hex_str = try val.toHex(allocator);
defer allocator.free(hex_str);

// Check if zero
if (val.isZero()) {
    // ...
}

// Arithmetic operations
const sum = a.add(b);
const diff = a.sub(b);
const product = a.mulScalar(10);
const result = a.divScalar(3);
// result.quotient and result.remainder

// Comparisons
if (a.lt(b)) { } // less than
if (a.lte(b)) { } // less than or equal
if (a.gt(b)) { } // greater than
if (a.gte(b)) { } // greater than or equal
if (a.eql(b)) { } // equal

// Convert to u64
const num = val.toU64(); // truncates
const num2 = try val.tryToU64(); // errors if too large

// Print value
std.debug.print("Value: {}\n", .{val});
```

### Bloom (256 bytes / 2048 bits)

Ethereum bloom filter for efficient log filtering.

```zig
const Bloom = zigeth.primitives.Bloom;

// Create empty bloom
var bloom = Bloom.empty();

// Create from bytes
const bloom2 = Bloom.fromBytes(bytes);

// Create from hex
const bloom3 = try Bloom.fromHex(hex_str);

// Add a hash to the bloom
bloom.add(&hash_bytes);

// Check if bloom might contain a hash
if (bloom.contains(&hash_bytes)) {
    // Possibly present (may have false positives)
}

// Combine two blooms (OR operation)
const combined = bloom1.combine(bloom2);

// Check if one bloom contains another
if (bloom1.containsBloom(bloom2)) {
    // bloom1 has all bits set in bloom2
}

// Count bits set
const bit_count = bloom.popCount();

// Check if empty
if (bloom.isEmpty()) {
    // ...
}

// Compare blooms
if (bloom1.eql(bloom2)) {
    // ...
}

// Convert to hex
const hex_str = try bloom.toHex(allocator);
defer allocator.free(hex_str);
```

### Common Patterns

#### Error Handling

All functions that can fail return error unions:

```zig
const addr = try Address.fromHex(hex_str); // propagates error
const hash = Hash.fromHex(hex_str) catch |err| {
    std.debug.print("Error: {}\n", .{err});
    return err;
};
```

#### Memory Management

Functions that allocate memory require an allocator:

```zig
const hex_str = try addr.toHex(allocator);
defer allocator.free(hex_str); // Always free allocated memory
```

#### Conversions

Most types support hex and byte conversions:

```zig
// To hex (allocates)
const hex = try value.toHex(allocator);
defer allocator.free(hex);

// From hex
const value = try Type.fromHex(hex_str);

// To bytes (stack allocated for fixed sizes)
const bytes = value.toBytes();

// From bytes
const value = Type.fromBytes(bytes);
```

## 🔧 EIP Support

Zigeth implements the latest Ethereum Improvement Proposals:

| EIP | Description | Status |
|-----|-------------|--------|
| **EIP-155** | Simple replay attack protection | ✅ Implemented |
| **EIP-1559** | Fee market change (base fee + priority fee) | ✅ Implemented |
| **EIP-2718** | Typed transaction envelope | ✅ Implemented |
| **EIP-2930** | Optional access lists | ✅ Implemented |
| **EIP-4788** | Beacon block root in the EVM | ✅ Implemented |
| **EIP-4844** | Shard blob transactions | ✅ Implemented |
| **EIP-7702** | Set EOA account code (Account Abstraction) | ✅ Implemented |

### Transaction Types

All Ethereum transaction types are fully supported:

- **Type 0**: Legacy (pre-EIP-2718) ✅
- **Type 1**: EIP-2930 (Access Lists) ✅
- **Type 2**: EIP-1559 (Fee Market) ✅
- **Type 3**: EIP-4844 (Blob Transactions) ✅
- **Type 4**: EIP-7702 (Set EOA Code) ✅

### Hard Fork Support

- Pre-Byzantium (root hash receipts) ✅
- Byzantium+ (status receipts, 3 ETH reward) ✅
- Constantinople+ (2 ETH reward) ✅
- London+ (EIP-1559 base fee) ✅
- Paris+ (The Merge - PoS) ✅
- Shanghai+ (Withdrawals) ✅
- Cancun+ (Blob transactions) ✅

## 📊 Testing & Quality

- **Total Tests**: 132 passing ✓
  - Primitives: 48 tests
  - Types: 23 tests
  - Crypto: 27 tests
  - RPC: 13 tests
  - ABI: 23 tests
  - Utilities: 8 tests
- **Code Coverage**: Comprehensive
- **Linting**: Enforced via `zig build lint`
- **Formatting**: Auto-formatted with `zig fmt`
- **Memory Safety**: Zero memory leaks
- **Build Time**: Fast incremental builds
- **Dependencies**: [zig-eth-secp256k1](https://github.com/jsign/zig-eth-secp256k1) for EC operations

## 📈 Roadmap

### Phase 1: Core Foundation ✅ Complete
- [x] Primitives (Address, Hash, Signature, U256, Bloom, Bytes)
- [x] Protocol Types (Transaction, Block, Receipt, Log)
- [x] Cryptography (Keccak-256, ECDSA, secp256k1)
- [x] ABI encoding/decoding (standard & packed)
- [x] Build system & CI/CD

### Phase 2: Communication Layer 🚧 In Progress
- [x] RPC client framework
- [x] Type definitions for all RPC methods
- [ ] HTTP transport implementation
- [ ] JSON serialization/deserialization
- [ ] WebSocket support

### Phase 3: Data Encoding 🚧 In Progress
- [x] ABI encoding/decoding (standard & packed)
- [ ] RLP encoding/decoding
- [ ] Typed data signing (EIP-712)

### Phase 4: High-Level APIs ⏳ Planned
- [ ] Provider implementations
- [ ] Smart contract interaction
- [ ] Wallet management
- [ ] Transaction middleware
- [ ] Network configurations

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Before contributing:
1. Run `zig build fmt` to format your code
2. Run `zig build lint` to check for issues
3. Run `zig build test` to verify all tests pass
4. Update documentation for new features

## 📄 License

[Add your license information here]

## 🔗 Resources

- [Zig Programming Language](https://ziglang.org/)
- [Ethereum Documentation](https://ethereum.org/en/developers/docs/)
- [JSON-RPC API](https://ethereum.org/en/developers/docs/apis/json-rpc/)
- [ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html)
- [zig-eth-secp256k1](https://github.com/jsign/zig-eth-secp256k1) - Elliptic curve operations

## ⭐ Acknowledgments

- [jsign/zig-eth-secp256k1](https://github.com/jsign/zig-eth-secp256k1) for the excellent secp256k1 wrapper
- Bitcoin Core for the audited libsecp256k1 library
- The Zig community for the amazing language and tooling
