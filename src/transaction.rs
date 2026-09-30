//! Contains the `[ZKsyncTx]` type and its implementation.
pub mod abstraction;
pub mod error;
pub mod priority_tx;

pub use abstraction::{ZKsyncTx, ZkTxTr};
pub use error::ZKsyncTxError;

/// Gas price shared by fee accounting and the GASPRICE opcode.
#[inline]
pub(crate) fn effective_gas_price_for_spec<TX: ZkTxTr>(
    tx: &TX,
    base_fee: u128,
    spec_id: crate::ZkSpecId,
) -> u128 {
    // L1->L2 transactions use their own gas_price set on L1,
    // independent of the L2 block base_fee.
    if tx.is_l1_to_l2_tx() {
        return tx.effective_gas_price(base_fee);
    }
    if crate::ZkSpecId::AtlasV3.is_enabled_in(spec_id) && base_fee == 0 {
        0
    } else {
        tx.effective_gas_price(base_fee)
    }
}
