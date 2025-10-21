//! Contains Deposit transaction parts.
use revm::primitives::{Address, U256};

/// Upgrade transaction type.
pub const UPGRADE_TRANSACTION_TYPE: u8 = 0x7E;

/// Priority transaction type.
pub const L1_PRIORITY_TRANSACTION_TYPE: u8 = 0x7f;

/// Deposit transaction parts.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct L1ToL2TransactionParts {
    pub mint: Option<U256>,
    pub refund_recipient: Option<Address>,
}

impl L1ToL2TransactionParts {
    pub fn new(mint: Option<U256>, refund_recipient: Option<Address>) -> Self {
        Self {
            mint,
            refund_recipient,
        }
    }
}
