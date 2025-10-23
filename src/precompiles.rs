//! Contains ZKsync OS specific precompiles.
use crate::ZkSpecId;
use revm::{
    context::Cfg,
    context_interface::ContextTr,
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{InputsImpl, InterpreterResult},
    precompile::{Precompiles, bn254, hash, identity, modexp, secp256k1},
    primitives::{Address, OnceLock},
};
use std::boxed::Box;
use std::string::String;
pub mod calldata_view;
pub mod deployer;
pub mod l1_messenger;
pub mod l2_base_token;

use deployer::{CONTRACT_DEPLOYER_ADDRESS, deployer_precompile_call};
use l1_messenger::{L1_MESSENGER_ADDRESS, l1_messenger_precompile_call};
use l2_base_token::{L2_BASE_TOKEN_ADDRESS, l2_base_token_precompile_call};

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
            ZkSpecId::Atlas => {
                static INSTANCE: OnceLock<Precompiles> = OnceLock::new();
                INSTANCE.get_or_init(|| {
                    let mut precompiles = Precompiles::default();
                    // Generating the list instead of using default Cancun fork,
                    // because we need to remove Blake2 and Point Evaluation
                    precompiles.extend([
                        secp256k1::ECRECOVER,
                        hash::SHA256,
                        hash::RIPEMD160,
                        identity::FUN,
                        modexp::BERLIN,
                        bn254::add::ISTANBUL,
                        bn254::mul::ISTANBUL,
                        bn254::pair::ISTANBUL,
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
        address: &Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        // If the code is loaded from different account it is a delegatecall
        let delegate =
            matches!(inputs.bytecode_address, Some(addr) if addr != inputs.target_address);
        if *address == CONTRACT_DEPLOYER_ADDRESS {
            return Ok(Some(deployer_precompile_call(
                context, inputs, is_static, delegate, gas_limit,
            )));
        } else if *address == L1_MESSENGER_ADDRESS {
            return Ok(Some(l1_messenger_precompile_call(
                context, inputs, is_static, delegate, gas_limit,
            )));
        } else if *address == L2_BASE_TOKEN_ADDRESS {
            return Ok(Some(l2_base_token_precompile_call(
                context, inputs, is_static, delegate, gas_limit,
            )));
        }

        self.inner
            .run(context, address, inputs, is_static, gas_limit)
    }

    #[inline]
    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        self.inner.warm_addresses()
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

impl Default for ZKsyncPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(ZkSpecId::Atlas)
    }
}
