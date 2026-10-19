//! Contains ZKsync OS specific precompiles.
use crate::ZkSpecId;
use revm::interpreter::CallInputs;
use revm::precompile::secp256r1::P256VERIFY_ADDRESS;
use revm::precompile::u64_to_address;
use revm::{
    context::Cfg,
    context_interface::ContextTr,
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::InterpreterResult,
    precompile::{
        Precompiles, blake2, bls12_381, bn254, hash, identity, kzg_point_evaluation, modexp,
        secp256k1, secp256r1,
    },
    primitives::{Address, AddressSet, OnceLock},
};
use std::string::String;

pub mod calldata_view;
pub(crate) mod utils;
pub mod v1;
pub mod v2;
pub mod v3;

use v1::deployer::CONTRACT_DEPLOYER_ADDRESS;
use v1::l1_messenger::L1_MESSENGER_ADDRESS;
use v1::l2_base_token::L2_BASE_TOKEN_ADDRESS;

use v3::interop_commitment_leaf::INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS;
use v3::l1_messenger::L1_MESSENGER_HOOK_ADDRESS;
use v3::mint_base_token::MINT_BASE_TOKEN_HOOK_ADDRESS;
use v3::set_bytecode_on_address::SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS;

type CustomPrecompile<CTX> =
    fn(ctx: &mut CTX, inputs: &CallInputs, is_delegate: bool) -> InterpreterResult;

/// Returns `Some(InterpreterResult)` if a precompile is defined for the given [ZkSpecId] and address.
/// Returns `None` if no precompile is defined.
fn maybe_call_custom_precompile<CTX>(
    spec: ZkSpecId,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Option<InterpreterResult>
where
    CTX: ContextTr,
    CTX::Journal: crate::l2_to_l1_logs::L2ToL1LogStore + crate::force_deploy::ForceDeployRecorder,
{
    let precompile_address = inputs.bytecode_address;

    let precompile_call = match spec {
        ZkSpecId::AtlasV1 => match precompile_address {
            CONTRACT_DEPLOYER_ADDRESS => {
                v1::deployer::deployer_precompile_call as CustomPrecompile<_>
            }
            L1_MESSENGER_ADDRESS => {
                v1::l1_messenger::l1_messenger_precompile_call as CustomPrecompile<_>
            }
            L2_BASE_TOKEN_ADDRESS => {
                v1::l2_base_token::l2_base_token_precompile_call as CustomPrecompile<_>
            }
            _ => return None,
        },
        ZkSpecId::AtlasV2 => match precompile_address {
            CONTRACT_DEPLOYER_ADDRESS => {
                v2::deployer::deployer_precompile_call as CustomPrecompile<_>
            }
            L1_MESSENGER_ADDRESS => {
                v2::l1_messenger::l1_messenger_precompile_call as CustomPrecompile<_>
            }
            L2_BASE_TOKEN_ADDRESS => {
                v2::l2_base_token::l2_base_token_precompile_call as CustomPrecompile<_>
            }
            _ => return None,
        },
        ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 | ZkSpecId::AtlasV5 => match precompile_address {
            CONTRACT_DEPLOYER_ADDRESS => {
                v3::deployer::deployer_precompile_call as CustomPrecompile<_>
            }
            MINT_BASE_TOKEN_HOOK_ADDRESS => {
                v3::mint_base_token::mint_base_token_precompile_call as CustomPrecompile<_>
            }
            SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS => {
                v3::set_bytecode_on_address::set_bytecode_on_address_precompile_call
                    as CustomPrecompile<_>
            }
            L1_MESSENGER_HOOK_ADDRESS => {
                v3::l1_messenger::l1_messenger_precompile_call as CustomPrecompile<_>
            }
            INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS if ZkSpecId::AtlasV4.is_enabled_in(spec) => {
                v3::interop_commitment_leaf::interop_commitment_leaf_precompile_call
                    as CustomPrecompile<_>
            }
            _ => return None,
        },
    };

    let is_delegate = inputs.bytecode_address != inputs.target_address;
    Some(precompile_call(context, inputs, is_delegate))
}

/// ZKsync OS precompile provider
#[derive(Debug, Clone)]
pub struct ZKsyncPrecompiles {
    /// Inner precompile provider is same as Ethereums.
    inner: EthPrecompiles,
    /// Spec id of the precompile provider.
    spec: ZkSpecId,
    /// Addresses warmed at the start of a transaction for the active spec.
    warm_addresses: &'static AddressSet,
}

impl ZKsyncPrecompiles {
    /// Create a new precompile provider with the given ZkSpec.
    #[inline]
    pub fn new_with_spec(spec: ZkSpecId) -> Self {
        let precompiles = match spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 | ZkSpecId::AtlasV3 => {
                static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
                INSTANCE.get_or_init(|| {
                    let mut precompiles = Precompiles::default();
                    // Generating the list instead of using default Cancun fork,
                    // because we need to remove Blake2 and Point Evaluation and
                    // add P256 precompile.
                    precompiles.extend([
                        secp256k1::ECRECOVER,
                        hash::SHA256,
                        hash::RIPEMD160,
                        identity::FUN,
                        modexp::BERLIN,
                        bn254::add::ISTANBUL,
                        bn254::mul::ISTANBUL,
                        bn254::pair::ISTANBUL,
                        secp256r1::P256VERIFY_OSAKA,
                    ]);
                    precompiles
                })
            }
            ZkSpecId::AtlasV4 | ZkSpecId::AtlasV5 => {
                static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
                INSTANCE.get_or_init(|| {
                    // AtlasV4 (ZKsync OS v0.4.0, Pectra + Fusaka) is the AtlasV1-V3
                    // base set plus the Pectra-era precompiles: BLAKE2F (0x09),
                    // point evaluation (0x0a), and BLS12-381 EIP-2537 (0x0b-0x11).
                    //
                    // MODEXP carries the Osaka rules, which ZKsync OS v0.4.0
                    // applies: the EIP-7883 gas schedule and the EIP-7823 cap of
                    // 1024 bytes on the base and the modulus.
                    let mut precompiles = Precompiles::default();
                    precompiles.extend([
                        secp256k1::ECRECOVER,
                        hash::SHA256,
                        hash::RIPEMD160,
                        identity::FUN,
                        modexp::OSAKA,
                        bn254::add::ISTANBUL,
                        bn254::mul::ISTANBUL,
                        bn254::pair::ISTANBUL,
                        secp256r1::P256VERIFY_OSAKA,
                        blake2::FUN,
                        kzg_point_evaluation::POINT_EVALUATION,
                    ]);
                    precompiles.extend(bls12_381::precompiles());
                    precompiles
                })
            }
        };

        let warm_addresses = match spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
                static WARM: OnceLock<AddressSet> = OnceLock::new();
                WARM.get_or_init(|| {
                    // Old versions did not warm the P256 precompile, but warmed
                    // Blake2 (0x09) and Point Evaluation (0x0a) even though
                    // they are not active precompiles.
                    let mut warm: AddressSet = precompiles
                        .addresses()
                        .filter(|&&address| address != u64_to_address(P256VERIFY_ADDRESS))
                        .copied()
                        .collect();
                    warm.insert(u64_to_address(9));
                    warm.insert(u64_to_address(10));
                    warm
                })
            }
            ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 | ZkSpecId::AtlasV5 => {
                precompiles.addresses_set()
            }
        };

        Self {
            inner: EthPrecompiles {
                precompiles,
                spec: spec.into_eth_spec(),
            },
            spec,
            warm_addresses,
        }
    }

    /// Precompiles getter.
    #[inline]
    pub fn precompiles(&self) -> &'static Precompiles {
        self.inner.precompiles
    }
}

impl<CTX> PrecompileProvider<CTX> for ZKsyncPrecompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
    CTX::Journal: crate::l2_to_l1_logs::L2ToL1LogStore + crate::force_deploy::ForceDeployRecorder,
{
    type Output = InterpreterResult;

    #[inline]
    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        *self = Self::new_with_spec(spec);
        true
    }

    #[inline]
    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        maybe_call_custom_precompile(self.spec, context, inputs).map_or_else(
            || self.inner.run(context, inputs),
            |result| Ok(Some(result)),
        )
    }

    #[inline]
    fn warm_addresses(&self) -> &AddressSet {
        self.warm_addresses
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        // Report the addresses this provider dispatches under the active spec,
        // beside the standard Ethereum precompiles. The arms hold the same
        // grouping as `maybe_call_custom_precompile`. From AtlasV3 on, the
        // system contracts are served through hooks, and the hooks accept the
        // L1 messenger and the base token as their callers, so the code of
        // those two contracts runs and they are not precompiles.
        //
        // `warm_addresses` stays narrower on purpose: it decides cold-access
        // gas, so an address added there changes execution.
        let custom = match self.spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
                *address == CONTRACT_DEPLOYER_ADDRESS
                    || *address == L1_MESSENGER_ADDRESS
                    || *address == L2_BASE_TOKEN_ADDRESS
            }
            ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 | ZkSpecId::AtlasV5 => {
                *address == CONTRACT_DEPLOYER_ADDRESS
                    || *address == L1_MESSENGER_HOOK_ADDRESS
                    || *address == SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS
                    || *address == MINT_BASE_TOKEN_HOOK_ADDRESS
                    || (ZkSpecId::AtlasV4.is_enabled_in(self.spec)
                        && *address == INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS)
            }
        };
        self.inner.contains(address) || custom
    }
}

impl Default for ZKsyncPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(ZkSpecId::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::builder::ZkBuilder;
    use crate::api::default_ctx::zk_context;
    use crate::constants::{COMPLEX_UPGRADER_ADDRESS, LARGE_CONTRACTS_MAX_CODE_SIZE};
    use crate::{ZKsyncTx, ZkSpecId};
    use revm::primitives::eip170;
    use revm::{
        ExecuteEvm,
        context::TxEnv,
        context_interface::result::{ExecutionResult, Output},
        database::{CacheDB, EmptyDB},
        primitives::{B256, Bytes, TxKind, U256, address, keccak256},
        state::{AccountInfo, Bytecode},
    };
    use v1::deployer::{L2_GENESIS_UPGRADE_ADDRESS, SET_EVM_BYTECODE_DETAILS};

    const CALLER: Address = address!("0000000000000000000000000000000000000c0f");
    const DEPLOY_TARGET: Address = address!("0000000000000000000000000000000000004444");
    const BYTECODE_HOLDER: Address = address!("0000000000000000000000000000000000005555");
    const DECLARED_BYTECODE_LENGTH: u32 = 32;
    /// Covers the per-byte gas the hooks charge for a 64 KiB bytecode.
    const FORCE_DEPLOY_GAS_LIMIT: u64 = 10_000_000;

    const JUMPDEST: u8 = 0x5b;
    const OP_MSTORE: u8 = 0x52;
    const OP_GAS: u8 = 0x5a;
    const OP_PUSH1: u8 = 0x60;
    const OP_PUSH20: u8 = 0x73;
    const OP_PUSH32: u8 = 0x7f;
    const OP_CALL: u8 = 0xf1;
    const OP_RETURN: u8 = 0xf3;

    const ALL_SPECS: [ZkSpecId; 5] = [
        ZkSpecId::AtlasV1,
        ZkSpecId::AtlasV2,
        ZkSpecId::AtlasV3,
        ZkSpecId::AtlasV4,
        ZkSpecId::AtlasV5,
    ];

    /// The two force-deploy entry points. They share the calldata parsing.
    #[derive(Clone, Copy, Debug)]
    enum ForceDeployHook {
        /// `setBytecodeDetailsEVM` on the contract deployer, called by the
        /// genesis upgrade.
        Deployer,
        /// The set-bytecode-on-address hook (AtlasV3 onwards), called by the
        /// complex upgrader.
        SetBytecodeOnAddress,
    }

    impl ForceDeployHook {
        fn address(self) -> Address {
            match self {
                Self::Deployer => CONTRACT_DEPLOYER_ADDRESS,
                Self::SetBytecodeOnAddress => SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS,
            }
        }

        /// The account the hook accepts calls from.
        fn caller(self) -> Address {
            match self {
                Self::Deployer => L2_GENESIS_UPGRADE_ADDRESS,
                Self::SetBytecodeOnAddress => COMPLEX_UPGRADER_ADDRESS,
            }
        }

        /// The deployer takes a selector before the arguments, the hook takes
        /// the arguments alone.
        fn selector_length(self) -> u8 {
            match self {
                Self::Deployer => 4,
                Self::SetBytecodeOnAddress => 0,
            }
        }
    }

    /// Code that writes `content` into memory at `offset`.
    fn store_code(offset: u8, content: [u8; 32]) -> Vec<u8> {
        let mut code = vec![OP_PUSH32];
        code.extend_from_slice(&content);
        code.extend_from_slice(&[OP_PUSH1, offset, OP_MSTORE]);
        code
    }

    /// Code that calls `hook` to force deploy `declared_length` bytes of the
    /// bytecode with `observable_bytecode_hash`, and returns the status of the
    /// call as a 32 byte word.
    fn upgrade_code(
        hook: ForceDeployHook,
        observable_bytecode_hash: B256,
        declared_length: u32,
    ) -> Bytes {
        let arguments_offset = hook.selector_length();
        let mut address_word = [0u8; 32];
        address_word[12..].copy_from_slice(DEPLOY_TARGET.as_slice());
        let mut length_word = [0u8; 32];
        length_word[28..].copy_from_slice(&declared_length.to_be_bytes());

        // (address, bytes32 bytecodeHash, uint32 len, bytes32
        // observableBytecodeHash). The versioned hash stays zero, because the
        // code lookup uses the observable hash.
        let mut code = Vec::new();
        if arguments_offset != 0 {
            let mut selector_word = [0u8; 32];
            selector_word[..4].copy_from_slice(SET_EVM_BYTECODE_DETAILS);
            code.extend(store_code(0, selector_word));
        }
        code.extend(store_code(arguments_offset, address_word));
        code.extend(store_code(arguments_offset + 64, length_word));
        code.extend(store_code(
            arguments_offset + 96,
            observable_bytecode_hash.0,
        ));

        code.extend_from_slice(&[
            OP_PUSH1,
            0, // return data length
            OP_PUSH1,
            0, // return data offset
            OP_PUSH1,
            arguments_offset + 128, // argument length
            OP_PUSH1,
            0, // argument offset
            OP_PUSH1,
            0, // call value
            OP_PUSH20,
        ]);
        code.extend_from_slice(hook.address().as_slice());
        code.extend_from_slice(&[OP_GAS, OP_CALL]);
        // Return the call status.
        code.extend_from_slice(&[OP_PUSH1, 0, OP_MSTORE, OP_PUSH1, 32, OP_PUSH1, 0, OP_RETURN]);
        code.into()
    }

    /// Force deploy `declared_length` bytes through `hook` against a database
    /// that holds `stored_bytecode`, with `code_size_limit` as the EVM
    /// config's `limit_contract_code_size`, and report whether the hook call
    /// succeeded.
    fn force_deploy_succeeds_with(
        spec: ZkSpecId,
        hook: ForceDeployHook,
        stored_bytecode: &[u8],
        declared_length: u32,
        code_size_limit: Option<usize>,
    ) -> bool {
        let observable_bytecode_hash = keccak256(stored_bytecode);
        let mut database = CacheDB::new(EmptyDB::default());
        database.insert_account_info(
            CALLER,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
        // The database serves the bytecode by its observable (keccak256) hash.
        database.insert_account_info(
            BYTECODE_HOLDER,
            AccountInfo {
                code: Some(Bytecode::new_raw(Bytes::copy_from_slice(stored_bytecode))),
                ..Default::default()
            },
        );
        database.insert_account_info(
            hook.caller(),
            AccountInfo {
                code: Some(Bytecode::new_raw(upgrade_code(
                    hook,
                    observable_bytecode_hash,
                    declared_length,
                ))),
                ..Default::default()
            },
        );

        let mut evm = zk_context(database, spec)
            .modify_cfg_chained(|cfg| cfg.limit_contract_code_size = code_size_limit)
            .build_zk();
        let transaction = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(hook.caller()))
                    .gas_limit(FORCE_DEPLOY_GAS_LIMIT),
            )
            .tx_hash(B256::ZERO)
            .build_fill()
            .expect("transaction builds");
        let result = evm.transact(transaction).expect("transaction runs").result;
        let ExecutionResult::Success {
            output: Output::Call(status),
            ..
        } = result
        else {
            panic!("{spec:?}: the force deploy transaction did not succeed: {result:?}");
        };
        status.iter().any(|byte| *byte != 0)
    }

    /// Force deploy [`DECLARED_BYTECODE_LENGTH`] bytes through the deployer
    /// under the default code-size limit.
    fn force_deploy_succeeds(spec: ZkSpecId, stored_bytecode: &[u8]) -> bool {
        force_deploy_succeeds_with(
            spec,
            ForceDeployHook::Deployer,
            stored_bytecode,
            DECLARED_BYTECODE_LENGTH,
            None,
        )
    }

    #[test]
    fn deployer_reverts_when_the_stored_bytecode_is_shorter_than_declared() {
        let declared_length = DECLARED_BYTECODE_LENGTH as usize;
        let full_bytecode = [JUMPDEST; DECLARED_BYTECODE_LENGTH as usize];
        let short_bytecode = &full_bytecode[..declared_length - 1];

        for spec in ALL_SPECS {
            // A bytecode of the declared length shows that the calldata reaches
            // the code lookup.
            assert!(force_deploy_succeeds(spec, &full_bytecode), "{spec:?}");
            assert!(!force_deploy_succeeds(spec, short_bytecode), "{spec:?}");
        }
    }

    /// The AtlasV3+ force-deploy hooks enforce the code-size limit of the EVM
    /// config: EIP-170 by default, 64 KiB on a chain with large contracts
    /// enabled.
    #[test]
    fn force_deploy_follows_the_configured_code_size_limit() {
        let large = Some(LARGE_CONTRACTS_MAX_CODE_SIZE);
        // (bytecode length, `limit_contract_code_size`, whether the hook accepts it)
        let cases = [
            (eip170::MAX_CODE_SIZE, None, true),
            (eip170::MAX_CODE_SIZE + 1, None, false),
            (eip170::MAX_CODE_SIZE + 1, large, true),
            (LARGE_CONTRACTS_MAX_CODE_SIZE, large, true),
            (LARGE_CONTRACTS_MAX_CODE_SIZE + 1, large, false),
        ];

        for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4, ZkSpecId::AtlasV5] {
            for hook in [
                ForceDeployHook::Deployer,
                ForceDeployHook::SetBytecodeOnAddress,
            ] {
                for (length, code_size_limit, accepted) in cases {
                    let bytecode = vec![JUMPDEST; length];
                    assert_eq!(
                        force_deploy_succeeds_with(
                            spec,
                            hook,
                            &bytecode,
                            length as u32,
                            code_size_limit
                        ),
                        accepted,
                        "{spec:?} {hook:?}: {length} bytes, limit {code_size_limit:?}"
                    );
                }
            }
        }
    }

    /// MODEXP carries the Osaka gas schedule on AtlasV4 and the Berlin schedule
    /// on the earlier specs. EIP-7883 raises the floor from 200 to 500, so a
    /// minimal exponentiation shows which schedule a spec applies.
    #[test]
    fn modexp_gas_schedule_follows_the_spec() {
        // Lengths of one byte each, then the base, the exponent and the modulus.
        let mut input = [0u8; 99];
        input[31] = 1;
        input[63] = 1;
        input[95] = 1;
        input[96] = 8;
        input[97] = 9;
        input[98] = 10;

        let address = u64_to_address(5);
        let gas_of = |spec: ZkSpecId| {
            ZKsyncPrecompiles::new_with_spec(spec)
                .precompiles()
                .get(&address)
                .expect("every supported spec holds MODEXP")
                .execute(&input, 100_000, 0)
                .expect("a minimal exponentiation succeeds")
                .gas_used
        };

        assert_eq!(
            gas_of(ZkSpecId::AtlasV3),
            200,
            "AtlasV3 prices MODEXP at Berlin"
        );
        assert_eq!(
            gas_of(ZkSpecId::AtlasV4),
            500,
            "AtlasV4 prices MODEXP at EIP-7883"
        );
    }

    /// AtlasV5 changes no precompile: it runs the AtlasV4 set and the same
    /// hooks.
    #[test]
    fn atlas_v5_keeps_the_atlas_v4_precompiles() {
        type Provider = dyn PrecompileProvider<
                crate::api::default_ctx::ZkContext<EmptyDB>,
                Output = InterpreterResult,
            >;
        let v4 = ZKsyncPrecompiles::new_with_spec(ZkSpecId::AtlasV4);
        let v5 = ZKsyncPrecompiles::new_with_spec(ZkSpecId::AtlasV5);
        assert!(core::ptr::eq(v4.precompiles(), v5.precompiles()));
        assert_eq!(v4.warm_addresses, v5.warm_addresses);
        let (v4, v5): (&Provider, &Provider) = (&v4, &v5);
        for hook in [
            CONTRACT_DEPLOYER_ADDRESS,
            L1_MESSENGER_HOOK_ADDRESS,
            SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS,
            MINT_BASE_TOKEN_HOOK_ADDRESS,
            INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS,
        ] {
            assert!(v4.contains(&hook), "{hook}");
            assert!(v5.contains(&hook), "{hook}");
        }
    }
}
