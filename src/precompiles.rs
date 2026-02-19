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

use v1::deployer::CONTRACT_DEPLOYER_ADDRESS;
use v1::l1_messenger::L1_MESSENGER_ADDRESS;
use v1::l2_base_token::L2_BASE_TOKEN_ADDRESS;

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
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
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
        // TODO: temporary workaround to not warm P256 precompile
        Box::new(
            self.inner
                .warm_addresses()
                .filter(|x| *x != u64_to_address(P256VERIFY_ADDRESS)),
        )
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

impl Default for ZKsyncPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(ZkSpecId::AtlasV2)
    }
}
