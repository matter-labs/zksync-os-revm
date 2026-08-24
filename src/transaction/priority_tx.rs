//! Contains Deposit transaction parts.
use revm::primitives::{Address, B256, U256};

/// Upgrade transaction type.
pub const UPGRADE_TRANSACTION_TYPE: u8 = 0x7E;

/// Priority transaction type.
pub const L1_PRIORITY_TRANSACTION_TYPE: u8 = 0x7f;

/// Deposit transaction parts.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct L1ToL2TransactionParts {
    pub mint: Option<U256>,
    pub refund_recipient: Option<Address>,
    pub settlement_layer_chain_id: Option<U256>,
    /// The transaction's identity hash — used for the bootloader result L2→L1
    /// log and the block header's transactions rolling hash. A proving consumer
    /// must authenticate it against the tx preimage (`keccak256(preimage) ==
    /// tx_hash`) or second-prover soundness breaks.
    #[serde(default)]
    pub tx_hash: B256,
}

impl L1ToL2TransactionParts {
    /// The identity hash is a required parameter: it has no meaningful default,
    /// and a filled-in [`B256::ZERO`] corrupts the message root of the block.
    pub fn new(
        mint: Option<U256>,
        refund_recipient: Option<Address>,
        settlement_layer_chain_id: Option<U256>,
        tx_hash: B256,
    ) -> Self {
        Self {
            mint,
            refund_recipient,
            settlement_layer_chain_id,
            tx_hash,
        }
    }
}
