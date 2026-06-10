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
fn maybe_call_custom_precompile<CTX: ContextTr>(
    spec: ZkSpecId,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Option<InterpreterResult> {
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
        ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 => match precompile_address {
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
            ZkSpecId::AtlasV4 => {
                static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
                INSTANCE.get_or_init(|| {
                    // AtlasV4 (ZKsync OS v0.4.0, Pectra + Fusaka) is the AtlasV1-V3
                    // base set plus the Pectra-era precompiles: BLAKE2F (0x09),
                    // point evaluation (0x0a), and BLS12-381 EIP-2537 (0x0b-0x11).
                    let mut precompiles = Precompiles::default();
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
                        blake2::FUN,
                        kzg_point_evaluation::POINT_EVALUATION,
                    ]);
                    precompiles.extend(bls12_381::precompiles());
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
            ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 => vec![],
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
                        ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 => true,
                    }
                })
                .chain(extra),
        )
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

impl Default for ZKsyncPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(ZkSpecId::default())
    }
}
