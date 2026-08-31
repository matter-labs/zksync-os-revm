//! Force-deploy declarations.
//!
//! The deployer precompile's `setBytecodeDetailsEVM` declares the observable
//! bytecode hash in its calldata, and native records that value verbatim in the
//! account properties — it is not recomputed from the deployed code. The record
//! lives in the state journal ([`crate::journal::ZkJournal`]) so that a frame
//! revert discards the declaration of a deployment that never landed.

use revm::primitives::{Address, B256};

/// Journal store of the force-deploy declarations of a transaction.
pub trait ForceDeployRecorder {
    /// Record a force-deploy: the deployed address and the observable bytecode
    /// hash the call declared.
    fn record_force_deploy(&mut self, address: Address, observable_bytecode_hash: B256);

    /// Take the force-deploy declarations of the transaction. The last
    /// declaration of an address wins, matching the account's final state.
    fn take_force_deploys(&mut self) -> Vec<(Address, B256)>;
}
