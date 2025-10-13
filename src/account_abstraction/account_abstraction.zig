// Account Abstraction (ERC-4337) Support for Zigeth
//
// This module provides comprehensive support for ERC-4337 Account Abstraction,
// including UserOperation handling, bundler interaction, paymaster support,
// and smart account management.
//
// Reference: https://eips.ethereum.org/EIPS/eip-4337
// Based on: https://github.com/wevm/viem/tree/main/src/account-abstraction

const std = @import("std");

pub const types = @import("types.zig");
pub const bundler = @import("bundler.zig");
pub const paymaster = @import("paymaster.zig");
pub const smart_account = @import("smart_account.zig");
pub const entrypoint = @import("entrypoint.zig");
pub const gas = @import("gas.zig");
pub const utils = @import("utils.zig");

// Re-export commonly used types
pub const EntryPointVersion = types.EntryPointVersion;
pub const UserOperation = types.UserOperation; // Default: v0.6
pub const UserOperationV06 = types.UserOperationV06;
pub const UserOperationV07 = types.UserOperationV07;
pub const UserOperationV08 = types.UserOperationV08;
pub const UserOperationJson = types.UserOperationJson;
pub const UserOperationReceipt = types.UserOperationReceipt;
pub const GasEstimates = types.GasEstimates;
pub const PaymasterData = types.PaymasterData;

// Re-export bundler client
pub const BundlerClient = bundler.BundlerClient;

// Re-export paymaster client
pub const PaymasterClient = paymaster.PaymasterClient;
pub const PaymasterMode = paymaster.PaymasterMode;
pub const TokenQuote = paymaster.TokenQuote;
pub const PaymasterStub = paymaster.PaymasterStub;

// Re-export smart account
pub const SmartAccount = smart_account.SmartAccount;
pub const AccountFactory = smart_account.AccountFactory;
pub const Call = smart_account.Call;

// Re-export EntryPoint
pub const EntryPoint = entrypoint.EntryPoint;
pub const DepositInfo = entrypoint.DepositInfo;
pub const ValidationResult = entrypoint.ValidationResult;

// Re-export gas estimator
pub const GasEstimator = gas.GasEstimator;
pub const GasPrices = gas.GasPrices;
pub const GasOverhead = gas.GasOverhead;

// Re-export utilities
pub const UserOpHash = utils.UserOpHash;
pub const UserOpUtils = utils.UserOpUtils;
pub const PackedUserOperation = utils.PackedUserOperation;

test {
    std.testing.refAllDecls(@This());
}
