# Zigeth

[![CI](https://github.com/ch4r10t33r/zigeth/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/zigeth/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.14.1-orange.svg)](https://ziglang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive Ethereum library for Zig, providing complete cryptographic primitives, transaction handling, RPC client framework, and utilities for seamless integration with Ethereum networks.

---

## 📊 Library Readiness Status

| Component | Status | Progress | Tests | Description |
|-----------|--------|----------|-------|-------------|
| **🎯 Primitives** | ✅ **Production Ready** | ████████████████████ 100% | 48/48 | Address, Hash, Bytes, Signature, U256, Bloom |
| **📦 Types** | ✅ **Production Ready** | ████████████████████ 100% | 23/23 | Transaction, Block, Receipt, Log, AccessList |
| **🔐 Crypto** | ✅ **Production Ready** | ████████████████████ 100% | 27/27 | Keccak-256, secp256k1, ECDSA, Key management |
| **📡 ABI** | ✅ **Production Ready** | ████████████████████ 100% | 23/23 | Encoding, Decoding, Types, Packed (EIP-712) |
| **📝 Contract** | ✅ **Production Ready** | ████████████████████ 100% | 19/19 | Calls, Deploy, Events, CREATE2 |
| **🌐 RPC** | ✅ **Production Ready** | ████████████████████ 100% | 27/27 | Full HTTP client, eth/net/web3/debug |
| **📜 RLP** | ✅ **Production Ready** | ████████████████████ 100% | 36/36 | Encoding, Decoding, Ethereum types |
| **🔌 Providers** | ⏳ **Planned** | ░░░░░░░░░░░░░░░░░░░░ 0% | 0/0 | HTTP, WebSocket, IPC |
| **🔑 Wallet** | ⏳ **Planned** | ░░░░░░░░░░░░░░░░░░░░ 0% | 0/0 | Software wallet, Keystore |
| **⚙️ Middleware** | ⏳ **Planned** | ░░░░░░░░░░░░░░░░░░░░ 0% | 0/0 | Gas, Nonce, Signing |
| **🌍 Networks** | ⏳ **Planned** | ░░░░░░░░░░░░░░░░░░░░ 0% | 0/0 | Pre-configured networks |
| **🧰 Utils** | ✅ **Production Ready** | ████████████████████ 100% | 35/35 | Hex, Format, Units, Checksum (EIP-55/1191) |
| **⚡ Solidity** | ✅ **Production Ready** | ████████████████████ 100% | 15/15 | Type mappings, Standard interfaces, Helpers |

### Overall Progress
**Total**: 242/242 tests passing ✅ | **70% Complete** | **9/12 modules production-ready**

**Legend**: ✅ Production Ready | 🚧 In Progress | ⏳ Planned

---

**Current Status**: 242 tests passing | 70% complete | Production-ready crypto, ABI, primitives, contracts, RLP, RPC, Solidity & utilities

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
│   ├── rlp/                  # Recursive Length Prefix ✅ IMPLEMENTED
│   │   ├── encode.zig        # RLP encoding ✅
│   │   ├── decode.zig        # RLP decoding ✅
│   │   └── packed.zig        # Ethereum-specific encoding ✅
│   │
│   ├── rpc/                  # JSON-RPC client ✅ IMPLEMENTED
│   │   ├── client.zig        # RPC client core ✅
│   │   ├── eth.zig           # eth_* namespace (23 methods) ✅ COMPLETE
│   │   ├── net.zig           # net_* namespace (3 methods) ✅ COMPLETE
│   │   ├── web3.zig          # web3_* namespace (2 methods) ✅ COMPLETE
│   │   ├── debug.zig         # debug_* namespace (7 methods) ✅ COMPLETE
│   │   └── types.zig         # RPC type definitions ✅
│   │
│   ├── providers/            # Network providers (TODO)
│   │   ├── provider.zig      # Base provider interface
│   │   ├── http.zig          # HTTP provider
│   │   ├── ws.zig            # WebSocket provider
│   │   ├── ipc.zig           # IPC provider
│   │   └── mock.zig          # Mock provider for testing
│   │
│   ├── contract/             # Smart contract interaction ✅ IMPLEMENTED
│   │   ├── contract.zig      # Contract abstraction ✅
│   │   ├── call.zig          # Contract calls ✅
│   │   ├── deploy.zig        # Contract deployment ✅
│   │   └── event.zig         # Event parsing ✅
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
│   ├── sol/                  # Solidity integration ✅ IMPLEMENTED
│   │   ├── types.zig         # Solidity type mappings ✅
│   │   └── macros.zig        # Code generation helpers ✅
│   │
│   └── utils/                # Utility functions ✅ IMPLEMENTED
│       ├── hex.zig           # Hex encoding/decoding ✅
│       ├── format.zig        # Formatting utilities ✅
│       ├── units.zig         # Unit conversions (wei/gwei/ether) ✅
│       └── checksum.zig      # EIP-55/EIP-1191 checksummed addresses ✅
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

- **📡 JSON-RPC Client** (6 modules, 27 tests):
  - **Full HTTP transport implementation** using std.http.Client
  - JSON-RPC 2.0 request/response handling
  - Automatic JSON serialization/deserialization
  - Deep JSON value copying for memory safety
  - Error handling (HTTP errors, JSON-RPC errors)
  - `eth_*` namespace (23 methods) - ALL IMPLEMENTED
    - Block queries (getBlockByNumber, getBlockByHash)
    - Transaction queries (getTransactionByHash, getTransactionReceipt)
    - Account operations (getBalance, getCode, getStorageAt)
    - Gas estimation & pricing
    - Transaction sending & signing
    - Event log filtering (getLogs)
  - `net_*` namespace (3 methods) - ALL IMPLEMENTED
  - `web3_*` namespace (2 methods + sha3Local bonus) - ALL IMPLEMENTED
  - `debug_*` namespace (7 methods) - ALL IMPLEMENTED
    - Transaction tracing (traceTransaction)
    - Block tracing (traceBlockByNumber, traceBlockByHash)
    - Call tracing (traceCall)
    - Storage inspection (storageRangeAt)
    - Account modification tracking
  - Complete JSON parsing for all complex types (Block, Transaction, Receipt, Log, Trace)
  - Type-safe request/response handling
  - **Ready for live Ethereum node connections**

- **📦 ABI Encoding/Decoding** (4 modules, 23 tests):
  - Complete ABI type system (uint, int, address, bool, bytes, string, arrays, tuples)
  - Standard ABI encoding (32-byte aligned, padded)
  - Standard ABI decoding with type safety
  - Packed encoding for EIP-712 and hashing
  - Function selector generation
  - Event signature generation

- **📝 Smart Contract Interaction** (4 modules, 19 tests):
  - `Contract` - High-level contract abstraction with ABI management
  - `CallBuilder` - Type-safe contract call construction
  - `DeployBuilder` - Contract deployment with constructor arguments
  - CREATE2 address prediction
  - Event parsing and filtering
  - Function result decoding
  - View/pure call execution
  - State-changing transaction handling

- **🧰 Utilities** (4 modules, 35 tests):
  - Hex encoding/decoding with 0x prefix support
  - Formatting (address/hash short forms, byte formatting, U256 formatting)
  - Unit conversions (wei/gwei/ether and all denominations)
  - EIP-55 checksummed addresses
  - EIP-1191 checksummed addresses (chain-specific)
  - Gas price conversions
  - Number formatting with separators
  - String padding and truncation
  - Memory-safe allocations
  - Comprehensive error handling

- **📜 RLP Encoding/Decoding** (3 modules, 36 tests):
  - Complete RLP specification implementation
  - Single byte encoding (< 0x80)
  - Short string encoding (0-55 bytes)
  - Long string encoding (> 55 bytes)
  - Short list encoding (0-55 bytes payload)
  - Long list encoding (> 55 bytes payload)
  - Nested list support
  - Ethereum-specific encoders (Address, Hash, U256)
  - Transaction encoding helpers
  - Full decode support with type-safe values
  - Roundtrip encoding/decoding verification

- **⚡ Solidity Integration** (2 modules, 15 tests):
  - Complete Solidity type to Zig type mappings
  - Standard interface definitions (ERC-20, ERC-721, ERC-1155)
  - OpenZeppelin pattern support (Ownable, Pausable, AccessControl)
  - Contract binding code generation
  - Function call builders
  - Event filter helpers
  - Pre-defined function selectors (ERC-20, ERC-721)
  - Pre-defined event signatures
  - Value conversion helpers (Zig ↔ ABI)
  - Type introspection (isDynamic, bitSize, byteSize)
  - Quick contract creation helpers (Erc20Contract, Erc721Contract)

### 🚧 **Planned Features**

- **🌐 Providers**: HTTP, WebSocket, IPC provider implementations with JSON-RPC
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
    
    // Contract interaction (ERC-20 token example)
    const token_functions = [_]zigeth.abi.Function{
        .{
            .name = "balanceOf",
            .inputs = &[_]zigeth.abi.Parameter{
                .{ .name = "account", .type = .address },
            },
            .outputs = &[_]zigeth.abi.Parameter{
                .{ .name = "balance", .type = .uint256 },
            },
            .state_mutability = .view,
        },
    };
    
    const token_events = [_]zigeth.abi.Event{
        .{
            .name = "Transfer",
            .inputs = &[_]zigeth.abi.Parameter{
                .{ .name = "from", .type = .address, .indexed = true },
                .{ .name = "to", .type = .address, .indexed = true },
                .{ .name = "value", .type = .uint256, .indexed = false },
            },
        },
    };
    
    const token_contract = try zigeth.contract.Contract.init(
        allocator,
        address, // token contract address
        &token_functions,
        &token_events,
    );
    defer token_contract.deinit();
    
    // Encode a contract call
    const call_args = [_]zigeth.abi.AbiValue{
        .{ .address = address },
    };
    const call_data = try token_contract.encodeCall("balanceOf", &call_args);
    defer allocator.free(call_data);
    
    std.debug.print("Contract call data encoded\n", .{});
    
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

## 📝 Smart Contract Interaction

Zigeth provides a comprehensive framework for interacting with smart contracts.

### Contract Abstraction

```zig
const zigeth = @import("zigeth");

// Define your contract's ABI
const functions = [_]zigeth.abi.Function{
    .{
        .name = "balanceOf",
        .inputs = &[_]zigeth.abi.Parameter{
            .{ .name = "account", .type = .address },
        },
        .outputs = &[_]zigeth.abi.Parameter{
            .{ .name = "balance", .type = .uint256 },
        },
        .state_mutability = .view,
    },
    .{
        .name = "transfer",
        .inputs = &[_]zigeth.abi.Parameter{
            .{ .name = "to", .type = .address },
            .{ .name = "amount", .type = .uint256 },
        },
        .outputs = &[_]zigeth.abi.Parameter{
            .{ .name = "success", .type = .bool_type },
        },
        .state_mutability = .nonpayable,
    },
};

const events = [_]zigeth.abi.Event{
    .{
        .name = "Transfer",
        .inputs = &[_]zigeth.abi.Parameter{
            .{ .name = "from", .type = .address, .indexed = true },
            .{ .name = "to", .type = .address, .indexed = true },
            .{ .name = "value", .type = .uint256, .indexed = false },
        },
    },
};

// Create contract instance
const contract_addr = try zigeth.primitives.Address.fromHex("0x...");
const contract = try zigeth.contract.Contract.init(
    allocator,
    contract_addr,
    &functions,
    &events,
);
defer contract.deinit();
```

### Contract Calls

Build and execute contract calls:

```zig
// Build a call using CallBuilder
const func = contract.getFunction("balanceOf").?;
var builder = zigeth.contract.CallBuilder.init(allocator, &contract, func);
defer builder.deinit();

// Add arguments
const account = try zigeth.primitives.Address.fromHex("0x...");
try builder.addArg(.{ .address = account });

// Set optional parameters
builder.setFrom(sender_address);
builder.setGasLimit(100000);

// Build call data
const call_data = try builder.buildCallData();
defer allocator.free(call_data);

// Or encode directly from contract
const args = [_]zigeth.abi.AbiValue{
    .{ .address = account },
};
const call_data2 = try contract.encodeCall("balanceOf", &args);
defer allocator.free(call_data2);
```

### Contract Deployment

Deploy contracts with constructor arguments:

```zig
// Bytecode of your contract
const bytecode_hex = "0x608060405234801561001057600080fd5b50...";
const bytecode_bytes = try zigeth.utils.hex.hexToBytes(allocator, bytecode_hex);
defer allocator.free(bytecode_bytes);

const bytecode = try zigeth.primitives.Bytes.fromSlice(allocator, bytecode_bytes);

// Define constructor parameters
const constructor_params = [_]zigeth.abi.Parameter{
    .{ .name = "initialSupply", .type = .uint256 },
    .{ .name = "name", .type = .string },
};

// Build deployment
var deploy = zigeth.contract.DeployBuilder.init(allocator, bytecode, &constructor_params);
defer deploy.deinit();

// Add constructor arguments
try deploy.addArg(.{ .uint = zigeth.primitives.U256.fromInt(1000000) });
try deploy.addArg(.{ .string = "MyToken" });

// Set deployment parameters
deploy.setFrom(deployer_address);
deploy.setValue(zigeth.primitives.U256.zero());
deploy.setGasLimit(2000000);

// Get deployment data
const deploy_data = try deploy.buildDeploymentData();
defer allocator.free(deploy_data);
```

### CREATE2 Address Prediction

Predict contract addresses before deployment:

```zig
// Standard CREATE (uses nonce)
const nonce: u64 = 5;
const predicted_addr = try deploy.estimateAddress(nonce);

// CREATE2 (deterministic)
const salt = zigeth.primitives.Hash.fromBytes([_]u8{0x12} ** 32);
const create2_addr = try deploy.estimateCreate2Address(salt);

std.debug.print("Contract will be deployed to: {}\n", .{create2_addr});
```

### Event Parsing

Parse and filter contract events:

```zig
// Get Transfer event from contract
const event = contract.getEvent("Transfer").?;

// Parse a log
const log = /* ... received from RPC ... */;
const parsed = try zigeth.contract.parseEvent(allocator, event, log);
defer parsed.deinit();

// Access indexed arguments
const from = parsed.getIndexedArg("from");
const to = parsed.getIndexedArg("to");

// Access non-indexed arguments
const value = parsed.getDataArg("value");

if (value) |v| {
    std.debug.print("Transferred: {}\n", .{v.uint});
}

// Parse multiple logs
const logs: []zigeth.types.Log = /* ... */;
const parsed_events = try zigeth.contract.parseEvents(allocator, event, logs);
defer {
    for (parsed_events) |p| p.deinit();
    allocator.free(parsed_events);
}

// Create event filter
var filter = zigeth.contract.EventFilter.init(allocator);
defer filter.deinit();

filter.setAddress(contract_addr);
filter.setBlockRange(1000000, 2000000);

const event_sig = try zigeth.contract.getEventSignatureHash(allocator, event);
filter.setEventSignature(event_sig);
```

## 🧰 Utilities

Zigeth provides comprehensive utility functions for common Ethereum operations.

### Unit Conversions

Convert between wei, gwei, and ether:

```zig
const zigeth = @import("zigeth");
const units = zigeth.utils.units;

// Convert to wei
const wei_from_ether = units.toWei(1, .ether); // 1 ETH = 1e18 wei
const wei_from_gwei = units.toWei(30, .gwei);   // 30 gwei = 30e9 wei

// Convert from wei
const wei = zigeth.primitives.U256.fromInt(1_500_000_000_000_000_000);
const conversion = try units.fromWei(wei, .ether);
// conversion.integer_part = 1
// conversion.remainder_wei = 0.5 ETH in wei

// Format with decimals
const formatted = try conversion.format(allocator, 4);
defer allocator.free(formatted);
// Result: "1.5000"

// Floating point conversions
const wei2 = try units.etherToWei(2.5);  // 2.5 ETH to wei
const ether = try units.weiToEther(wei); // wei to ether (f64)

// Gas price helpers
const gas_wei = units.GasPrice.gweiToWei(30); // 30 gwei to wei
const gas_gwei = try units.GasPrice.weiToGwei(gas_wei); // back to gwei
```

Supported units:
- `wei` (1)
- `kwei` (1e3)
- `mwei` (1e6)
- `gwei` (1e9) - commonly used for gas prices
- `szabo` (1e12)
- `finney` (1e15)
- `ether` (1e18)
- `kether` (1e21)
- `mether` (1e24)
- `gether` (1e27)
- `tether` (1e30)

### Formatting

Format addresses, hashes, and numbers for display:

```zig
const zigeth = @import("zigeth");
const format = zigeth.utils.format;

// Shorten addresses for display
const addr = try zigeth.primitives.Address.fromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");
const short = try format.formatAddressShort(allocator, addr);
defer allocator.free(short);
// Result: "0x742d...0bEb"

// Shorten hashes
const hash = zigeth.primitives.Hash.fromBytes([_]u8{0xab} ** 32);
const short_hash = try format.formatHashShort(allocator, hash);
defer allocator.free(short_hash);
// Result: "0xabab...abab"

// Format bytes with length limit
const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
const formatted_bytes = try format.formatBytes(allocator, &data, 10);
defer allocator.free(formatted_bytes);

// Format U256 as decimal
const value = zigeth.primitives.U256.fromInt(1234567890);
const decimal = try format.formatU256(allocator, value);
defer allocator.free(decimal);
// Result: "1234567890"

// Format U256 as hex
const hex = try format.formatU256Hex(allocator, value);
defer allocator.free(hex);
// Result: "0x499602d2"

// Add thousand separators
const with_sep = try format.formatWithSeparators(allocator, "1234567890", ',');
defer allocator.free(with_sep);
// Result: "1,234,567,890"

// Pad strings
const padded = try format.padLeft(allocator, "42", 10, '0');
defer allocator.free(padded);
// Result: "0000000042"

const padded2 = try format.padRight(allocator, "42", 10, '0');
defer allocator.free(padded2);
// Result: "4200000000"

// Truncate strings
const truncated = try format.truncate(allocator, "Hello, World!", 5);
defer allocator.free(truncated);
// Result: "Hello"
```

### Checksummed Addresses

EIP-55 and EIP-1191 checksummed addresses:

```zig
const zigeth = @import("zigeth");
const checksum = zigeth.utils.checksum;

// EIP-55 checksum (standard Ethereum)
const addr = try zigeth.primitives.Address.fromHex("0x5aaeb6053f3e94c9b9a09f33669a657bb6e41057");
const checksummed = try checksum.toChecksumAddress(allocator, addr);
defer allocator.free(checksummed);
// Result: "0x5aAeB6053F3E94C9b9A09f33669A657bB6e41057" (mixed case)

// Verify checksum
const is_valid = try checksum.verifyChecksum(allocator, checksummed);
// Result: true

// EIP-1191 checksum (chain-specific)
const checksummed_eip1191 = try checksum.toChecksumAddressEip1191(allocator, addr, 1); // mainnet
defer allocator.free(checksummed_eip1191);

const is_valid_1191 = try checksum.verifyChecksumEip1191(allocator, checksummed_eip1191, 1);
// Result: true

// Normalize address (lowercase)
const normalized = try checksum.normalizeAddress(allocator, "0x5aAeB6053F3E94C9b9A09f33669A657bB6e41057");
defer allocator.free(normalized);
// Result: "0x5aaeb6053f3e94c9b9a09f33669a657bb6e41057"

// Compare addresses (case-insensitive)
const equal = try checksum.addressesEqual(
    "0x5aaeb6053f3e94c9b9a09f33669a657bb6e41057",
    "0x5AAEB6053F3E94C9B9A09F33669A657BB6E41057",
);
// Result: true
```

### Hex Utilities

Already covered in primitives, but available as standalone utilities:

```zig
const zigeth = @import("zigeth");
const hex = zigeth.utils.hex;

// Bytes to hex
const bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
const hex_str = try hex.bytesToHex(allocator, &bytes);
defer allocator.free(hex_str);
// Result: "0xdeadbeef"

// Hex to bytes
const bytes2 = try hex.hexToBytes(allocator, "0xdeadbeef");
defer allocator.free(bytes2);

// Validate hex
const is_valid = hex.isValidHex("0xdeadbeef"); // true
const is_invalid = hex.isValidHex("0xgg"); // false
```

## 📜 RLP Encoding/Decoding

Zigeth provides a complete implementation of Ethereum's Recursive Length Prefix (RLP) encoding scheme.

### Basic RLP Encoding

```zig
const zigeth = @import("zigeth");
const rlp = zigeth.rlp;

// Encode bytes/string
const encoded_str = try rlp.encodeBytes(allocator, "dog");
defer allocator.free(encoded_str);
// Result: [0x83, 'd', 'o', 'g']

// Encode uint
const encoded_num = try rlp.encodeUint(allocator, 127);
defer allocator.free(encoded_num);
// Result: [0x7f] (single byte < 0x80)

// Encode empty string
const empty = try rlp.encodeBytes(allocator, &[_]u8{});
defer allocator.free(empty);
// Result: [0x80]

// Encode list of items
const items = [_]rlp.RlpItem{
    .{ .string = "cat" },
    .{ .string = "dog" },
};
const encoded_list = try rlp.encodeList(allocator, &items);
defer allocator.free(encoded_list);
// Result: [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
```

### Using the Encoder Builder

```zig
// Build complex structures
var encoder = rlp.Encoder.init(allocator);
defer encoder.deinit();

// Add items
try encoder.encode(.{ .string = "hello" });
try encoder.encode(.{ .uint = 42 });

// Nested list
const nested = [_]rlp.RlpItem{
    .{ .string = "a" },
    .{ .string = "b" },
};
try encoder.encode(.{ .list = &nested });

// Get result
const result = try encoder.toOwnedSlice();
defer allocator.free(result);
```

### RLP Decoding

```zig
// Decode single value
const data = [_]u8{ 0x83, 'd', 'o', 'g' };
const value = try rlp.decodeValue(allocator, &data);
defer value.deinit(allocator);

if (value.isBytes()) {
    const bytes = try value.getBytes();
    // bytes = "dog"
}

// Decode list
const list_data = [_]u8{ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' };
const list_value = try rlp.decodeValue(allocator, &list_data);
defer list_value.deinit(allocator);

if (list_value.isList()) {
    const items = try list_value.getList();
    for (items) |item| {
        const str = try item.getBytes();
        std.debug.print("Item: {s}\n", .{str});
    }
}

// Use decoder for multiple values
var decoder = rlp.Decoder.init(allocator, data);

while (decoder.hasMore()) {
    const item = try decoder.decode();
    defer item.deinit(allocator);
    // Process item...
}
```

### Ethereum-Specific Encoding

```zig
// Encode Address
const addr = try zigeth.primitives.Address.fromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");
const encoded_addr = try rlp.EthereumEncoder.encodeAddress(allocator, addr);
defer allocator.free(encoded_addr);

// Encode Hash
const hash = zigeth.primitives.Hash.fromBytes([_]u8{0xab} ** 32);
const encoded_hash = try rlp.EthereumEncoder.encodeHash(allocator, hash);
defer allocator.free(encoded_hash);

// Encode U256
const value = zigeth.primitives.U256.fromInt(1000000);
const encoded_value = try rlp.EthereumEncoder.encodeU256(allocator, value);
defer allocator.free(encoded_value);

// Encode address list
const addresses = [_]zigeth.primitives.Address{
    addr1,
    addr2,
    addr3,
};
const encoded_addrs = try rlp.EthereumEncoder.encodeAddressList(allocator, &addresses);
defer allocator.free(encoded_addrs);
```

### Ethereum-Specific Decoding

```zig
// Decode Address (from RLP bytes payload)
const addr_data = ...; // 20 bytes from RLP
const addr = try rlp.EthereumDecoder.decodeAddress(addr_data);

// Decode Hash (from RLP bytes payload)
const hash_data = ...; // 32 bytes from RLP
const hash = try rlp.EthereumDecoder.decodeHash(hash_data);

// Decode U256 (from RLP bytes payload)
const uint_data = ...; // Variable length bytes from RLP
const value = try rlp.EthereumDecoder.decodeU256(uint_data);
```

### Transaction Encoding (Legacy)

```zig
// Encode legacy transaction for signing
const tx = ...; // Your transaction
const encoded_for_signing = try rlp.TransactionEncoder.encodeLegacyForSigning(
    allocator,
    tx,
);
defer allocator.free(encoded_for_signing);

// After signing, encode with signature
const encoded_signed = try rlp.TransactionEncoder.encodeLegacySigned(
    allocator,
    tx,
);
defer allocator.free(encoded_signed);
```

### RLP Specification

The RLP encoding follows the Ethereum Yellow Paper specification:

1. **Single byte** (< 0x80): Encoded as itself
2. **String 0-55 bytes**: `[0x80 + length, ...bytes]`
3. **String > 55 bytes**: `[0xb7 + length_of_length, ...length_bytes, ...bytes]`
4. **List 0-55 bytes payload**: `[0xc0 + payload_length, ...encoded_items]`
5. **List > 55 bytes payload**: `[0xf7 + length_of_length, ...length_bytes, ...encoded_items]`

## ⚡ Solidity Integration

Zigeth provides first-class support for Solidity contracts with type mappings and standard interface definitions.

### Standard Interfaces

Quick contract creation for common standards:

```zig
const zigeth = @import("zigeth");

// Create ERC-20 token contract
const usdc_addr = try zigeth.primitives.Address.fromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const usdc = try zigeth.sol.Erc20Contract(allocator, usdc_addr);
defer usdc.deinit();

// Contract has all ERC-20 methods ready
const balance_args = [_]zigeth.abi.AbiValue{
    .{ .address = my_address },
};
const call_data = try usdc.encodeCall("balanceOf", &balance_args);
defer allocator.free(call_data);

// Create ERC-721 NFT contract
const bayc_addr = try zigeth.primitives.Address.fromHex("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D");
const bayc = try zigeth.sol.Erc721Contract(allocator, bayc_addr);
defer bayc.deinit();

// Query NFT owner
const owner_args = [_]zigeth.abi.AbiValue{
    .{ .uint = zigeth.primitives.U256.fromInt(1234) }, // tokenId
};
const owner_call = try bayc.encodeCall("ownerOf", &owner_args);
defer allocator.free(owner_call);

// Create ERC-1155 multi-token contract
const erc1155 = try zigeth.sol.Erc1155Contract(allocator, contract_addr);
defer erc1155.deinit();
```

### Type Mappings

Map between Solidity and Zig types:

```zig
const zigeth = @import("zigeth");

// Parse Solidity type strings
const sol_type = try zigeth.sol.parseType("uint256");
const abi_type = sol_type.toAbiType();

// Check type properties
const is_uint = sol_type.isUint(); // true
const is_dynamic = sol_type.isDynamic(); // false
const bits = sol_type.bitSize(); // 256
const bytes = sol_type.byteSize(); // 32
const name = sol_type.typeName(); // "uint256"

// Supported types:
// - address, bool, string, bytes
// - uint8, uint16, uint32, uint64, uint128, uint256
// - int8, int16, int32, int64, int128, int256
// - bytes1, bytes2, bytes4, bytes8, bytes16, bytes32
```

### Value Conversion

Convert Zig values to ABI values:

```zig
// Convert primitive types
const uint_val = zigeth.sol.ValueConversion.toAbiValue(u64, 1000);
// Result: AbiValue{ .uint = U256.fromInt(1000) }

const bool_val = zigeth.sol.ValueConversion.toAbiValue(bool, true);
// Result: AbiValue{ .bool_val = true }

// Convert Address
const addr_val = zigeth.sol.ValueConversion.addressToAbiValue(address);
// Result: AbiValue{ .address = address }

// Convert U256
const u256_val = zigeth.sol.ValueConversion.u256ToAbiValue(value);
// Result: AbiValue{ .uint = value }
```

### Pre-defined Selectors

Use pre-computed function selectors:

```zig
const zigeth = @import("zigeth");

// ERC-20 selectors
const transfer_sel = zigeth.sol.Selectors.ERC20_TRANSFER; // "0xa9059cbb"
const approve_sel = zigeth.sol.Selectors.ERC20_APPROVE; // "0x095ea7b3"
const balance_sel = zigeth.sol.Selectors.ERC20_BALANCE_OF; // "0x70a08231"

// ERC-721 selectors
const owner_sel = zigeth.sol.Selectors.ERC721_OWNER_OF; // "0x6352211e"
const transfer_from_sel = zigeth.sol.Selectors.ERC721_TRANSFER_FROM;

// Event signatures (topic0)
const transfer_event = zigeth.sol.Selectors.TRANSFER_EVENT;
const approval_event = zigeth.sol.Selectors.APPROVAL_EVENT;
```

### Custom Contract Binding

Generate type-safe contract bindings:

```zig
const MyContractBinding = zigeth.sol.ContractBinding(
    "MyContract",
    &my_functions,
    &my_events,
);

const contract = try MyContractBinding.init(allocator, contract_addr);
defer contract.deinit();

std.debug.print("Contract: {s}\n", .{MyContractBinding.getName()});
std.debug.print("Address: {}\n", .{contract.getAddress()});
```

### Standard Interfaces

Get functions and events for standard interfaces:

```zig
// ERC-20 interface
const erc20_functions = try zigeth.sol.StandardInterface.erc20.getFunctions(allocator);
defer allocator.free(erc20_functions);
// Returns: totalSupply, balanceOf, transfer, allowance, approve, transferFrom

const erc20_events = try zigeth.sol.StandardInterface.erc20.getEvents(allocator);
defer allocator.free(erc20_events);
// Returns: Transfer, Approval

// ERC-721 interface
const erc721_functions = try zigeth.sol.StandardInterface.erc721.getFunctions(allocator);
defer allocator.free(erc721_functions);
// Returns: balanceOf, ownerOf, transferFrom, approve, setApprovalForAll, getApproved

// Also supports: ERC-1155, Ownable, Pausable, AccessControl
```

## 🔧 EIP Support

Zigeth implements the latest Ethereum Improvement Proposals:

| EIP | Description | Status |
|-----|-------------|--------|
| **EIP-55** | Mixed-case checksum address encoding | ✅ Implemented |
| **EIP-155** | Simple replay attack protection | ✅ Implemented |
| **EIP-1191** | Checksummed addresses for different chains | ✅ Implemented |
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

- **Total Tests**: 242 passing ✓
  - Primitives: 48 tests
  - Types: 23 tests
  - Crypto: 27 tests
  - RPC: 27 tests
  - ABI: 23 tests
  - Contract: 19 tests
  - RLP: 36 tests
  - Solidity: 15 tests
  - Utilities: 35 tests
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
