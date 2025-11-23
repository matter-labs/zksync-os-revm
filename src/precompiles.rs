//! Contains ZKsync OS specific precompiles.
use crate::ZkSpecId;
use revm::{
    context::Cfg,
    context_interface::ContextTr,
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{InputsImpl, InterpreterResult},
    precompile::{Precompiles, bn254, hash, identity, modexp, secp256k1, secp256r1},
    primitives::{Address, OnceLock},
};
use std::string::String;
use std::{boxed::Box, collections::HashMap};
pub mod calldata_view;
pub(crate) mod utils;
pub mod v1;
pub mod v2;

use v1::deployer::CONTRACT_DEPLOYER_ADDRESS;
use v1::l1_messenger::L1_MESSENGER_ADDRESS;
use v1::l2_base_token::L2_BASE_TOKEN_ADDRESS;

type CustomPrecompile<CTX> = fn(
    ctx: &mut CTX,
    inputs: &InputsImpl,
    is_static: bool,
    is_delegate: bool,
    gas_limit: u64,
) -> InterpreterResult;

/// ZKsync OS precompile provider
#[derive(Debug, Clone)]
pub struct ZKsyncPrecompiles<CTX: ContextTr> {
    /// Inner precompile provider is same as Ethereums.
    inner: EthPrecompiles,
    // Custom precompiles specific to ZKsync OS.
    custom_precompiles: HashMap<Address, CustomPrecompile<CTX>>,
    /// Spec id of the precompile provider.
    spec: ZkSpecId,
}

impl<CTX: ContextTr> ZKsyncPrecompiles<CTX> {
    /// Create a new precompile provider with the given ZkSpec.
    #[inline]
    pub fn new_with_spec(spec: ZkSpecId) -> Self {
        let precompiles = match spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
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
                        secp256r1::P256VERIFY
                    ]);
                    precompiles
                })
            }
        };

        let custom_precompiles = match spec {
            ZkSpecId::AtlasV1 => [
                (
                    CONTRACT_DEPLOYER_ADDRESS,
                    v1::deployer::deployer_precompile_call::<CTX> as CustomPrecompile<CTX>,
                ),
                (
                    L1_MESSENGER_ADDRESS,
                    v1::l1_messenger::l1_messenger_precompile_call::<CTX> as CustomPrecompile<CTX>,
                ),
                (
                    L2_BASE_TOKEN_ADDRESS,
                    v1::l2_base_token::l2_base_token_precompile_call::<CTX>
                        as CustomPrecompile<CTX>,
                ),
            ]
            .into(),
            ZkSpecId::AtlasV2 => [
                (
                    CONTRACT_DEPLOYER_ADDRESS,
                    v2::deployer::deployer_precompile_call::<CTX> as CustomPrecompile<CTX>,
                ),
                (
                    L1_MESSENGER_ADDRESS,
                    v2::l1_messenger::l1_messenger_precompile_call::<CTX> as CustomPrecompile<CTX>,
                ),
                (
                    L2_BASE_TOKEN_ADDRESS,
                    v2::l2_base_token::l2_base_token_precompile_call::<CTX>
                        as CustomPrecompile<CTX>,
                ),
            ]
            .into(),
        };
        Self {
            inner: EthPrecompiles {
                precompiles,
                spec: spec.into_eth_spec(),
            },
            custom_precompiles,
            spec,
        }
    }

    /// Precompiles getter.
    #[inline]
    pub fn precompiles(&self) -> &'static Precompiles {
        self.inner.precompiles
    }
}

impl<CTX> PrecompileProvider<CTX> for ZKsyncPrecompiles<CTX>
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
        if let Some(precompile_call) = self.custom_precompiles.get(address) {
            // If the code is loaded from different account it is a delegatecall
            let delegate =
                matches!(inputs.bytecode_address, Some(addr) if addr != inputs.target_address);

            return Ok(Some(precompile_call(
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

impl<CTX: ContextTr> Default for ZKsyncPrecompiles<CTX> {
    fn default() -> Self {
        Self::new_with_spec(ZkSpecId::AtlasV2)
    }
}
