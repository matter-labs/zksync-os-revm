//! L2→L1 log collection.
//!
//! The L1Messenger precompile records a structured L2→L1 log for every message
//! it accepts. The logs live in the state journal ([`crate::journal::ZkJournal`])
//! so that a frame revert discards the logs of that frame.

use revm::primitives::{Address, B256};

/// Structured L2→L1 log entry matching the ZKsync OS protocol format.
#[derive(Debug, Clone)]
pub struct L2ToL1Log {
    pub l2_shard_id: u8,
    pub is_service: bool,
    pub tx_number_in_block: u16,
    pub sender: Address,
    pub key: B256,
    pub value: B256,
}

/// Store of the L2→L1 logs of a transaction.
///
/// The L1Messenger precompile is generic over `CTX: ContextTr` and reaches the
/// store through `ctx.journal_mut()`.
pub trait L2ToL1LogStore {
    /// Record the log of a user message.
    fn push_l2_to_l1_log(&mut self, sender: Address, key: B256, value: B256);

    /// Record the result log of an L1→L2 transaction.
    ///
    /// In ZKsync OS the bootloader emits this log after each priority
    /// transaction, through `emit_l1_l2_tx_log(tx_hash, success)`. REVM has no
    /// bootloader, so the handler emits it after the transaction body.
    fn emit_l1_tx_result(&mut self, tx_hash: B256, success: bool);
}
