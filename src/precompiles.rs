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
    precompile::{Precompiles, bn254, hash, identity, modexp, secp256k1, secp256r1},
    primitives::{Address, OnceLock},
};
use std::boxed::Box;
use std::string::String;

pub mod calldata_view;
pub(crate) mod utils;
pub mod v1;
pub mod v2;
pub mod v3;

use v1::deployer::CONTRACT_DEPLOYER_ADDRESS;
use v1::l1_messenger::L1_MESSENGER_ADDRESS;
use v1::l2_base_token::L2_BASE_TOKEN_ADDRESS;

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
    CTX::Journal: crate::l2_to_l1_logs::L2ToL1LogStore,
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
        ZkSpecId::AtlasV3 => match precompile_address {
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
        };

        Self {
            inner: EthPrecompiles {
                precompiles,
                spec: spec.into_eth_spec(),
            },
            spec,
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
    CTX::Journal: crate::l2_to_l1_logs::L2ToL1LogStore,
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
    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let spec = self.spec;
        // Historical versions warmed Blake2 (0x09) and Point Evaluation (0x0a)
        // even though they are not active precompiles.
        let extra = match spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
                vec![u64_to_address(9), u64_to_address(10)]
            }
            ZkSpecId::AtlasV3 => vec![],
        };
        Box::new(
            self.inner
                .warm_addresses()
                .filter(move |x| {
                    match spec {
                        ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
                            // Old versions did not warm P256 precompile, so we need to filter it out.
                            *x != u64_to_address(P256VERIFY_ADDRESS)
                        }
                        ZkSpecId::AtlasV3 => true,
                    }
                })
                .chain(extra),
        )
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        // Report the addresses this provider dispatches under the active spec,
        // beside the standard Ethereum precompiles. AtlasV3 serves the system
        // contracts through hooks, and it accepts the L1 messenger and the base
        // token as the callers of those hooks, so their own code runs and they
        // are not precompiles there.
        //
        // `warm_addresses` stays narrower on purpose: it decides cold-access
        // gas, so an address added there changes execution.
        let custom = match self.spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
                *address == CONTRACT_DEPLOYER_ADDRESS
                    || *address == L1_MESSENGER_ADDRESS
                    || *address == L2_BASE_TOKEN_ADDRESS
            }
            ZkSpecId::AtlasV3 => {
                *address == CONTRACT_DEPLOYER_ADDRESS
                    || *address == L1_MESSENGER_HOOK_ADDRESS
                    || *address == SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS
                    || *address == MINT_BASE_TOKEN_HOOK_ADDRESS
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
    use crate::{ZKsyncTx, ZkSpecId};
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
    const DECLARED_BYTECODE_LENGTH: u8 = 32;
    const DEPLOYER_CALLDATA_LENGTH: u8 = 132;

    const OP_MSTORE: u8 = 0x52;
    const OP_GAS: u8 = 0x5a;
    const OP_PUSH1: u8 = 0x60;
    const OP_PUSH20: u8 = 0x73;
    const OP_PUSH32: u8 = 0x7f;
    const OP_CALL: u8 = 0xf1;
    const OP_RETURN: u8 = 0xf3;

    const ALL_SPECS: [ZkSpecId; 3] = [ZkSpecId::AtlasV1, ZkSpecId::AtlasV2, ZkSpecId::AtlasV3];

    /// Code that writes `content` into memory at `offset`.
    fn store_code(offset: u8, content: [u8; 32]) -> Vec<u8> {
        let mut code = vec![OP_PUSH32];
        code.extend_from_slice(&content);
        code.extend_from_slice(&[OP_PUSH1, offset, OP_MSTORE]);
        code
    }

    /// Code that force deploys [`DECLARED_BYTECODE_LENGTH`] bytes of the
    /// bytecode with `observable_bytecode_hash`, and returns the status of the
    /// deployer call as a 32 byte word.
    fn genesis_upgrade_code(observable_bytecode_hash: B256) -> Bytes {
        let mut selector_word = [0u8; 32];
        selector_word[..4].copy_from_slice(SET_EVM_BYTECODE_DETAILS);
        let mut address_word = [0u8; 32];
        address_word[12..].copy_from_slice(DEPLOY_TARGET.as_slice());
        let mut length_word = [0u8; 32];
        length_word[31] = DECLARED_BYTECODE_LENGTH;

        // setBytecodeDetailsEVM(address, bytes32 bytecodeHash, uint32 len,
        // bytes32 observableBytecodeHash). The versioned hash at offset 36 stays
        // zero, because the code lookup uses the observable hash at offset 100.
        let mut code = store_code(0, selector_word);
        code.extend(store_code(4, address_word));
        code.extend(store_code(68, length_word));
        code.extend(store_code(100, observable_bytecode_hash.0));

        code.extend_from_slice(&[
            OP_PUSH1,
            0, // return data length
            OP_PUSH1,
            0, // return data offset
            OP_PUSH1,
            DEPLOYER_CALLDATA_LENGTH,
            OP_PUSH1,
            0, // argument offset
            OP_PUSH1,
            0, // call value
            OP_PUSH20,
        ]);
        code.extend_from_slice(CONTRACT_DEPLOYER_ADDRESS.as_slice());
        code.extend_from_slice(&[OP_GAS, OP_CALL]);
        // Return the call status.
        code.extend_from_slice(&[OP_PUSH1, 0, OP_MSTORE, OP_PUSH1, 32, OP_PUSH1, 0, OP_RETURN]);
        code.into()
    }

    /// Force deploy [`DECLARED_BYTECODE_LENGTH`] bytes against a database that
    /// holds `stored_bytecode`, and report whether the deployer call succeeded.
    fn force_deploy_succeeds(spec: ZkSpecId, stored_bytecode: &[u8]) -> bool {
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
            L2_GENESIS_UPGRADE_ADDRESS,
            AccountInfo {
                code: Some(Bytecode::new_raw(genesis_upgrade_code(
                    observable_bytecode_hash,
                ))),
                ..Default::default()
            },
        );

        let mut evm = zk_context(database, spec).build_zk();
        let transaction = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(L2_GENESIS_UPGRADE_ADDRESS))
                    .gas_limit(1_000_000),
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

    #[test]
    fn deployer_reverts_when_the_stored_bytecode_is_shorter_than_declared() {
        const JUMPDEST: u8 = 0x5b;
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
}
