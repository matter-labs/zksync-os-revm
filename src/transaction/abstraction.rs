//! ZKsync OS transaction abstraction containing the `[ZkTxTr]` trait and corresponding `[ZKsyncTx]` type.
use super::priority_tx::{
    L1_PRIORITY_TRANSACTION_TYPE, L1ToL2TransactionParts, UPGRADE_TRANSACTION_TYPE,
};
use auto_impl::auto_impl;
use revm::{
    context::{
        TxEnv,
        tx::{TxEnvBuildError, TxEnvBuilder},
    },
    context_interface::transaction::Transaction,
    handler::SystemCallTx,
    primitives::{Address, B256, Bytes, TxKind, U256},
};

/// ZKsync OS Transaction trait.
#[auto_impl(&, &mut, Box, Arc)]
pub trait ZkTxTr: Transaction {
    /// Mint of the deposit transaction
    fn mint(&self) -> Option<U256>;

    fn is_l1_to_l2_tx(&self) -> bool {
        self.tx_type() == UPGRADE_TRANSACTION_TYPE || self.tx_type() == L1_PRIORITY_TRANSACTION_TYPE
    }

    fn refund_recipient(&self) -> Option<Address>;

    fn gas_used_override(&self) -> Option<u64>;

    fn force_fail(&self) -> bool;
}

/// ZKsync OS transaction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZKsyncTx<T: Transaction> {
    /// Base transaction fields.
    pub base: T,
    /// L1 -> L2 transaction parts.
    pub l1_to_l2_part: L1ToL2TransactionParts,
    /// The gas spent on executing the transaction in the original ZKsync OS environment.
    pub gas_used_override: Option<u64>,
    /// The execution status (success/revert) from the original ZKsync OS environment.
    pub force_fail: bool,
}

impl<T: Transaction> AsRef<T> for ZKsyncTx<T> {
    fn as_ref(&self) -> &T {
        &self.base
    }
}

impl<T: Transaction> ZKsyncTx<T> {
    /// Create a new ZKsync OS transaction.
    pub fn new(base: T) -> Self {
        Self {
            base,
            l1_to_l2_part: L1ToL2TransactionParts::default(),
            gas_used_override: None,
            force_fail: false,
        }
    }
}

impl ZKsyncTx<TxEnv> {
    /// Create a new ZKsync OS transaction.
    pub fn builder() -> ZKsyncTxBuilder {
        ZKsyncTxBuilder::new()
    }
}

impl Default for ZKsyncTx<TxEnv> {
    fn default() -> Self {
        Self {
            base: TxEnv::default(),
            l1_to_l2_part: L1ToL2TransactionParts::default(),
            gas_used_override: None,
            force_fail: false,
        }
    }
}

impl<TX: Transaction + SystemCallTx> SystemCallTx for ZKsyncTx<TX> {
    fn new_system_tx_with_caller(
        caller: Address,
        system_contract_address: Address,
        data: Bytes,
    ) -> Self {
        ZKsyncTx::new(TX::new_system_tx_with_caller(
            caller,
            system_contract_address,
            data,
        ))
    }
}

impl<T: Transaction> Transaction for ZKsyncTx<T> {
    type AccessListItem<'a>
        = T::AccessListItem<'a>
    where
        T: 'a;
    type Authorization<'a>
        = T::Authorization<'a>
    where
        T: 'a;

    fn tx_type(&self) -> u8 {
        self.base.tx_type()
    }

    fn caller(&self) -> Address {
        self.base.caller()
    }

    fn gas_limit(&self) -> u64 {
        self.base.gas_limit()
    }

    fn value(&self) -> U256 {
        self.base.value()
    }

    fn input(&self) -> &Bytes {
        self.base.input()
    }

    fn nonce(&self) -> u64 {
        self.base.nonce()
    }

    fn kind(&self) -> TxKind {
        self.base.kind()
    }

    fn chain_id(&self) -> Option<u64> {
        self.base.chain_id()
    }

    fn access_list(&self) -> Option<impl Iterator<Item = Self::AccessListItem<'_>>> {
        self.base.access_list()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.base.max_priority_fee_per_gas()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.base.max_fee_per_gas()
    }

    fn gas_price(&self) -> u128 {
        self.base.gas_price()
    }

    fn blob_versioned_hashes(&self) -> &[B256] {
        self.base.blob_versioned_hashes()
    }

    fn max_fee_per_blob_gas(&self) -> u128 {
        self.base.max_fee_per_blob_gas()
    }

    fn effective_gas_price(&self, base_fee: u128) -> u128 {
        // L1 to L2 transactions use gas_price directly
        if self.is_l1_to_l2_tx() {
            return self.gas_price();
        }
        self.base.effective_gas_price(base_fee)
    }

    fn authorization_list_len(&self) -> usize {
        self.base.authorization_list_len()
    }

    fn authorization_list(&self) -> impl Iterator<Item = Self::Authorization<'_>> {
        self.base.authorization_list()
    }
}

impl<T: Transaction> ZkTxTr for ZKsyncTx<T> {
    fn mint(&self) -> Option<U256> {
        self.l1_to_l2_part.mint
    }

    fn refund_recipient(&self) -> Option<Address> {
        self.l1_to_l2_part.refund_recipient
    }

    fn gas_used_override(&self) -> Option<u64> {
        self.gas_used_override
    }

    fn force_fail(&self) -> bool {
        self.force_fail
    }
}

/// Builder for constructing [`ZKsyncTx`] instances
#[derive(Default, Debug)]
pub struct ZKsyncTxBuilder {
    base: TxEnvBuilder,
    l1_to_l2_part: L1ToL2TransactionParts,
    gas_used_override: Option<u64>,
    force_fail: bool,
}

impl ZKsyncTxBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            base: TxEnvBuilder::new(),
            l1_to_l2_part: L1ToL2TransactionParts::default(),
            gas_used_override: None,
            force_fail: false,
        }
    }

    /// Set the base transaction builder based for TxEnvBuilder.
    pub fn base(mut self, base: TxEnvBuilder) -> Self {
        self.base = base;
        self
    }

    /// Set the mint of the L1 -> L2 part of the transaction.
    pub fn mint(mut self, mint: U256) -> Self {
        self.l1_to_l2_part.mint = Some(mint);
        self
    }

    /// Sets the gas amount spent in the transaction based
    /// on the original ZKsync OS execution environment.
    pub fn gas_used_override(mut self, gas_used_override: Option<u64>) -> Self {
        self.gas_used_override = gas_used_override;
        self
    }

    /// Sets the execution status of the transaction
    /// based on the original ZKsync OS execution environment.
    pub fn force_fail(mut self, force_fail: bool) -> Self {
        self.force_fail = force_fail;
        self
    }

    /// Set the refund recipient of the L1 -> L2 part of the transaction.
    pub fn refund_recipient(mut self, refund_recipient: Option<Address>) -> Self {
        self.l1_to_l2_part.refund_recipient = refund_recipient;
        self
    }

    /// Build the [`ZKsyncTx`] with default values for missing fields.
    ///
    /// This is useful for testing and debugging where it is not necessary to
    /// have full [`ZKsyncTx`] instance.
    ///
    /// If the source hash is not [`B256::ZERO`], set the transaction type to L1 -> L2 part and remove the enveloped transaction.
    pub fn build_fill(self) -> ZKsyncTx<TxEnv> {
        let base = self.base.build_fill();

        ZKsyncTx {
            base,
            l1_to_l2_part: self.l1_to_l2_part,
            gas_used_override: self.gas_used_override,
            force_fail: self.force_fail,
        }
    }

    /// Build the [`ZKsyncTx`] instance, return error if the transaction is not valid.
    ///
    pub fn build(self) -> Result<ZKsyncTx<TxEnv>, ZkBuilderror> {
        let base = self.base.build()?;

        Ok(ZKsyncTx {
            base,
            l1_to_l2_part: self.l1_to_l2_part,
            gas_used_override: self.gas_used_override,
            force_fail: self.force_fail,
        })
    }
}

/// Error type for building [`TxEnv`]
#[derive(
    Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum ZkBuilderror {
    /// Base transaction build error
    Base(TxEnvBuildError),
}

impl From<TxEnvBuildError> for ZkBuilderror {
    fn from(error: TxEnvBuildError) -> Self {
        ZkBuilderror::Base(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{context_interface::Transaction, primitives::Address};

    #[test]
    fn test_deposit_transaction_fields() {
        let base_tx = TxEnv::builder()
            .gas_limit(10)
            .gas_price(100)
            .gas_priority_fee(Some(5));

        let zk_tx = ZKsyncTx::builder()
            .base(base_tx)
            .mint(U256::ZERO)
            .build()
            .unwrap();
        // Verify transaction type (deposit transactions should have tx_type based on ZkSpecId)
        // The tx_type is derived from the transaction structure, not set manually
        // Verify common fields access
        assert_eq!(zk_tx.gas_limit(), 10);
        assert_eq!(zk_tx.kind(), revm::primitives::TxKind::Call(Address::ZERO));
        // Verify gas related calculations - deposit transactions use gas_price for effective gas price
        assert_eq!(zk_tx.effective_gas_price(90), 95);
        assert_eq!(zk_tx.max_fee_per_gas(), 100);
    }
}
