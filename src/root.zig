//! Zeth - Ethereum library for Zig
//!
//! This library provides primitives, RPC client, and utilities
//! for interacting with Ethereum networks.

const std = @import("std");

// Re-export main modules
pub const primitives = struct {
    pub const Address = @import("primitives/address.zig").Address;
    pub const Hash = @import("primitives/hash.zig").Hash;
    pub const Bytes = @import("primitives/bytes.zig").Bytes;
    pub const Signature = @import("primitives/signature.zig").Signature;
    pub const U256 = @import("primitives/uint.zig").U256;
    pub const Bloom = @import("primitives/bloom.zig").Bloom;
};
pub const types = struct {
    pub const Transaction = @import("types/transaction.zig").Transaction;
    pub const TransactionType = @import("types/transaction.zig").TransactionType;
    pub const Block = @import("types/block.zig").Block;
    pub const BlockHeader = @import("types/block.zig").BlockHeader;
    pub const Receipt = @import("types/receipt.zig").Receipt;
    pub const TransactionStatus = @import("types/receipt.zig").TransactionStatus;
    pub const Log = @import("types/log.zig").Log;
    pub const AccessList = @import("types/access_list.zig").AccessList;
    pub const AccessListEntry = @import("types/access_list.zig").AccessList.AccessListEntry;
    pub const Authorization = @import("types/transaction.zig").Authorization;
    pub const AuthorizationList = @import("types/transaction.zig").AuthorizationList;
};

pub const crypto = struct {
    pub const keccak = @import("crypto/keccak.zig");
    pub const secp256k1 = @import("crypto/secp256k1.zig");
    pub const ecdsa = @import("crypto/ecdsa.zig");
    pub const utils = @import("crypto/utils.zig");

    // Re-export commonly used types
    pub const Keccak256 = keccak.Keccak256;
    pub const PrivateKey = secp256k1.PrivateKey;
    pub const PublicKey = secp256k1.PublicKey;
    pub const Signer = ecdsa.Signer;
    pub const TransactionSigner = ecdsa.TransactionSigner;
};

pub const abi = struct {
    pub const abi_types = @import("abi/types.zig");
    pub const encode = @import("abi/encode.zig");
    pub const decode = @import("abi/decode.zig");
    pub const abi_packed = @import("abi/packed.zig");

    // Re-export commonly used types
    pub const AbiType = abi_types.AbiType;
    pub const AbiValue = abi_types.AbiValue;
    pub const Function = abi_types.Function;
    pub const Event = abi_types.Event;
    pub const Parameter = abi_types.Parameter;
    pub const Encoder = encode.Encoder;
    pub const Decoder = decode.Decoder;
    pub const PackedEncoder = abi_packed.PackedEncoder;
    pub const PackedValue = abi_packed.PackedValue;
    pub const encodeFunctionCall = encode.encodeFunctionCall;
    pub const decodeFunctionReturn = decode.decodeFunctionReturn;
    pub const encodePacked = abi_packed.encodePacked;
    pub const hashPacked = abi_packed.hashPacked;
};

pub const rlp = struct {
    pub const encode = @import("rlp/encode.zig");
    pub const decode = @import("rlp/decode.zig");
    pub const ethereum = @import("rlp/packed.zig");

    // Re-export commonly used types
    pub const Encoder = encode.Encoder;
    pub const Decoder = decode.Decoder;
    pub const RlpItem = encode.RlpItem;
    pub const RlpValue = decode.RlpValue;
    pub const encodeItem = encode.encodeItem;
    pub const encodeList = encode.encodeList;
    pub const encodeBytes = encode.encodeBytes;
    pub const encodeUint = encode.encodeUint;
    pub const decodeValue = decode.decode;
    pub const decodeBytes = decode.decodeBytes;
    pub const decodeList = decode.decodeList;
    pub const decodeUint = decode.decodeUint;
    pub const TransactionEncoder = ethereum.TransactionEncoder;
    pub const EthereumEncoder = ethereum.EthereumEncoder;
    pub const EthereumDecoder = ethereum.EthereumDecoder;
};

pub const providers = struct {
    pub const Provider = @import("providers/provider.zig").Provider;
    pub const HttpProvider = @import("providers/http.zig").HttpProvider;
    pub const WsProvider = @import("providers/ws.zig").WsProvider;
    pub const IpcProvider = @import("providers/ipc.zig").IpcProvider;
    pub const MockProvider = @import("providers/mock.zig").MockProvider;
    pub const Networks = @import("providers/http.zig").Networks;
    pub const SocketPaths = @import("providers/ipc.zig").SocketPaths;
};

pub const rpc = struct {
    pub const client = @import("rpc/client.zig");
    pub const rpc_types = @import("rpc/types.zig");
    pub const eth = @import("rpc/eth.zig");
    pub const net = @import("rpc/net.zig");
    pub const web3 = @import("rpc/web3.zig");
    pub const debug = @import("rpc/debug.zig");

    // Re-export commonly used types
    pub const RpcClient = client.RpcClient;
    pub const HttpTransport = client.HttpTransport;
    pub const EthNamespace = eth.EthNamespace;
    pub const NetNamespace = net.NetNamespace;
    pub const Web3Namespace = web3.Web3Namespace;
    pub const DebugNamespace = debug.DebugNamespace;
    pub const BlockParameter = rpc_types.BlockParameter;
    pub const CallParams = rpc_types.CallParams;
    pub const TransactionParams = rpc_types.TransactionParams;
    pub const FilterOptions = rpc_types.FilterOptions;
};

pub const contract = struct {
    pub const Contract = @import("contract/contract.zig").Contract;
    pub const CallBuilder = @import("contract/call.zig").CallBuilder;
    pub const CallParams = @import("contract/call.zig").CallParams;
    pub const CallResult = @import("contract/call.zig").CallResult;
    pub const callView = @import("contract/call.zig").callView;
    pub const callMutating = @import("contract/call.zig").callMutating;
    pub const DeployBuilder = @import("contract/deploy.zig").DeployBuilder;
    pub const DeployReceipt = @import("contract/deploy.zig").DeployReceipt;
    pub const ParsedEvent = @import("contract/event.zig").ParsedEvent;
    pub const EventFilter = @import("contract/event.zig").EventFilter;
    pub const parseEvent = @import("contract/event.zig").parseEvent;
    pub const parseEvents = @import("contract/event.zig").parseEvents;
    pub const getEventSignatureHash = @import("contract/event.zig").getEventSignatureHash;
};

pub const sol = struct {
    pub const sol_types = @import("sol/types.zig");
    pub const macros = @import("sol/macros.zig");

    // Re-export commonly used types
    pub const SolidityType = sol_types.SolidityType;
    pub const SolidityValue = sol_types.SolidityValue;
    pub const StandardInterface = sol_types.StandardInterface;
    pub const parseType = sol_types.parseType;
    pub const ContractBinding = macros.ContractBinding;
    pub const FunctionCall = macros.FunctionCall;
    pub const EventFilter = macros.EventFilter;
    pub const Erc20Contract = macros.Erc20Contract;
    pub const Erc721Contract = macros.Erc721Contract;
    pub const Erc1155Contract = macros.Erc1155Contract;
    pub const AbiParser = macros.AbiParser;
    pub const ParsedAbi = macros.ParsedAbi;
    pub const Selectors = macros.Selectors;
    pub const ValueConversion = macros.ValueConversion;
};

pub const signer = @import("signer/wallet.zig");

pub const utils = struct {
    pub const hex = @import("utils/hex.zig");
    pub const format = @import("utils/format.zig");
    pub const units = @import("utils/units.zig");
    pub const checksum = @import("utils/checksum.zig");
};

pub const middleware = struct {
    const gas_mod = @import("middleware/gas.zig");
    const nonce_mod = @import("middleware/nonce.zig");
    const signer_mod = @import("middleware/signer.zig");

    pub const GasStrategy = gas_mod.GasStrategy;
    pub const GasConfig = gas_mod.GasConfig;
    pub const FeeData = gas_mod.FeeData;
    pub const GasMiddleware = gas_mod.GasMiddleware;

    pub const NonceStrategy = nonce_mod.NonceStrategy;
    pub const PendingTransaction = nonce_mod.PendingTransaction;
    pub const NonceMiddleware = nonce_mod.NonceMiddleware;

    pub const SignerConfig = signer_mod.SignerConfig;
    pub const SignerMiddleware = signer_mod.SignerMiddleware;
};

test {
    std.testing.refAllDecls(@This());
}
