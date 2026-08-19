//! Pre-block system state transitions performed by ZKsync OS.
//!
//! Some EIPs require the state transition function to perform special system
//! calls at block boundaries, outside of normal transaction execution (e.g.
//! [EIP-2935](https://eips.ethereum.org/EIPS/eip-2935)). ZKsync OS does this in
//! its pre-tx loop. A consistency checker that replays a block
//! transaction-by-transaction does not otherwise execute these block-level
//! calls, so it must invoke [`apply_pre_block_system_calls`] before replaying
//! transactions to stay in sync with the STF.

use crate::ZkSpecId;
use crate::constants::HISTORY_STORAGE_ADDRESS;
use revm::ExecuteCommitEvm;
use revm::handler::system_call::SystemCallEvm;
use revm::primitives::{B256, Bytes};

/// Applies ZKsync OS's pre-block system state transitions for `spec` and commits
/// them, mirroring what the STF performs in its pre-tx loop.
///
/// Call this before replaying a block's transactions. The transitions are driven
/// as canonical system calls (caller = `SYSTEM_ADDRESS`), so the deployed system
/// contracts perform the actual storage writes — exactly as on a real chain.
///
/// Currently this covers EIP-2935 (historical block hash), active from
/// [`ZkSpecId::AtlasV4`]. `parent_hash` is the hash of the block immediately
/// preceding the one being executed; the history contract derives the
/// ring-buffer slot from the block number in the EVM block environment.
pub fn apply_pre_block_system_calls<EVM>(
    evm: &mut EVM,
    spec: ZkSpecId,
    parent_hash: B256,
) -> Result<(), EVM::Error>
where
    EVM: SystemCallEvm + ExecuteCommitEvm,
{
    // EIP-2935: write the parent block hash into the history storage contract.
    if ZkSpecId::AtlasV4.is_enabled_in(spec) {
        let outcome = evm.system_call(
            HISTORY_STORAGE_ADDRESS,
            Bytes::copy_from_slice(parent_hash.as_slice()),
        )?;
        evm.commit(outcome.state);
    }

    Ok(())
}
