//! Contains the `[ZKsyncTxError]` type.
use core::fmt::Display;
use revm::context_interface::{
    result::{EVMError, InvalidTransaction},
    transaction::TransactionError,
};

/// ZKsync OS transaction validation error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ZKsyncTxError {
    /// Base transaction error.
    Base(InvalidTransaction),
}

impl TransactionError for ZKsyncTxError {}

impl Display for ZKsyncTxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Base(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for ZKsyncTxError {}

impl From<InvalidTransaction> for ZKsyncTxError {
    fn from(value: InvalidTransaction) -> Self {
        Self::Base(value)
    }
}

impl<DBError> From<ZKsyncTxError> for EVMError<DBError, ZKsyncTxError> {
    fn from(value: ZKsyncTxError) -> Self {
        Self::Transaction(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::string::ToString;

    #[test]
    fn test_display_zk_errors() {
        assert_eq!(
            ZKsyncTxError::Base(InvalidTransaction::NonceTooHigh { tx: 2, state: 1 }).to_string(),
            "nonce 2 too high, expected 1"
        );
    }
}
