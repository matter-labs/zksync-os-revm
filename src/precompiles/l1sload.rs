//! L1SLOAD precompile (`0x101`, RIP-7728), from AtlasV6 on, for chains that
//! enable it with [`ZKsyncEvm::with_l1sload`](crate::ZKsyncEvm::with_l1sload).
//! Otherwise `0x101` is an empty, cold account, as in ZKsync OS with the chain
//! config flag off.
//!
//! Input is `address ‖ key_1 … key_k` (`1 ≤ k ≤ 5`), output `value_1 … value_k`,
//! read at the L1 block whose hash `L2InteropRootStorage` holds (the anchor).
//! Values are proven against the block's [`L1Witness`], so the witness is
//! untrusted. Behaviour mirrors the ZKsync OS hook:
//! - gas is `2000 + 2000·k`;
//! - a call with value, bad input, too little gas, no anchor, a stale anchor
//!   (`block.timestamp > anchor time + L1_ANCHOR_MAX_LAG`) or one that takes the
//!   transaction past [`L1SLOAD_MAX_KEYS_PER_TX`] distinct reads reverts and
//!   consumes all gas passed, without touching the witness;
//! - the anchor slots are read as system reads: no gas, the slots stay warm,
//!   `L2InteropRootStorage` itself does not;
//! - a witness that does not prove the read stops the replay with
//!   `EVMError::Custom`, since ZKsync OS could not seal such a block.
mod proof;

pub use proof::L1Witness;

use proof::read_l1_storage;

use crate::precompiles::{calldata_view::CalldataView, utils::revert_consuming_all_gas};
use revm::{
    context_interface::{Block, ContextTr, JournalTr},
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    primitives::{Address, B256, Bytes, HashSet, U256, address, b256},
    state::EvmState,
};
use std::{format, string::String, vec::Vec};

pub const L1SLOAD_ADDRESS: Address = address!("0000000000000000000000000000000000000101");

/// RIP-7728 `MAX_NUM_STORAGE_SLOTS`.
pub const L1SLOAD_MAX_KEYS: usize = 5;

/// Most distinct `(anchor, address, key)` reads one transaction may make
/// across all its L1SLOAD calls, as in ZKsync OS.
pub const L1SLOAD_MAX_KEYS_PER_TX: usize = 64;

/// RIP-7728 `L1SLOAD_BASE_GAS`.
pub const L1SLOAD_BASE_GAS: u64 = 2000;
/// RIP-7728 `L1SLOAD_PER_LOAD_GAS`.
pub const L1SLOAD_PER_KEY_GAS: u64 = 2000;

/// `L2InteropRootStorage`, which holds the anchor.
pub const L1SLOAD_ANCHOR_HOLDER: Address = address!("0000000000000000000000000000000000010008");

/// `keccak256("zksync-os.l1sload.anchor.block-hash")`.
pub const L1SLOAD_ANCHOR_BLOCK_HASH_SLOT: B256 =
    b256!("142c4a6779611c44dc597e02ef1171577327f02356cebd6f373cfaa886831283");

/// `keccak256("zksync-os.l1sload.anchor.timestamp")`: the L1 time the anchor
/// was recorded at.
pub const L1SLOAD_ANCHOR_TIMESTAMP_SLOT: B256 =
    b256!("840528b13813a4d88e7572e39ead87b5d3a2ef4d72fc74665e1c19c022e232ce");

/// Seconds the L2 block time may run past the anchor's L1 time.
pub const L1_ANCHOR_MAX_LAG: u64 = 3600;

pub const fn l1sload_gas(num_keys: usize) -> u64 {
    L1SLOAD_BASE_GAS + L1SLOAD_PER_KEY_GAS * num_keys as u64
}

/// One read, as [`L1SLOAD_MAX_KEYS_PER_TX`] counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct L1sloadRead {
    pub anchor: B256,
    pub address: Address,
    pub key: B256,
}

/// The distinct reads of the transaction in progress, kept by the journal.
/// Frame reverts keep them; each transaction starts with none.
pub trait L1sloadReadSet {
    fn l1sload_reads(&mut self) -> &mut HashSet<L1sloadRead>;
}

/// Run L1SLOAD against the block's witness. `Err` means the witness does not
/// prove the read, or the database failed.
pub fn l1sload_precompile_call<CTX>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    witness: &L1Witness,
) -> Result<InterpreterResult, String>
where
    CTX: ContextTr<Journal: JournalTr<State = EvmState> + L1sloadReadSet>,
{
    let failed = || Ok(revert_consuming_all_gas(inputs.gas_limit));

    // Also the value a CALLCODE or DELEGATECALL passes along, which ZKsync OS
    // rejects too.
    if !inputs.value.get().is_zero() {
        return failed();
    }

    let view = CalldataView::new(ctx, &inputs.input);
    let Some((address, keys)) = parse_input(view.as_slice()) else {
        return failed();
    };
    drop(view);

    let mut gas = Gas::new(inputs.gas_limit);
    if !gas.record_regular_cost(l1sload_gas(keys.len())) {
        return failed();
    }

    let anchor = B256::from(read_anchor_slot(ctx, L1SLOAD_ANCHOR_BLOCK_HASH_SLOT)?);
    if anchor.is_zero() {
        return failed();
    }
    let anchor_time = read_anchor_slot(ctx, L1SLOAD_ANCHOR_TIMESTAMP_SLOT)?;
    if anchor_is_stale(ctx.block().timestamp(), anchor_time) {
        return failed();
    }

    // A call that would go over the cap adds none of its reads.
    let reads = ctx.journal_mut().l1sload_reads();
    let new_reads: HashSet<L1sloadRead> = keys
        .iter()
        .map(|&key| L1sloadRead {
            anchor,
            address,
            key,
        })
        .filter(|read| !reads.contains(read))
        .collect();
    if reads.len() + new_reads.len() > L1SLOAD_MAX_KEYS_PER_TX {
        return failed();
    }
    reads.extend(new_reads);

    let values = read_l1_storage(witness, anchor, address, &keys).map_err(|err| {
        format!(
            "L1SLOAD: the witness does not prove the read of {address} at L1 block {anchor}: {err}"
        )
    })?;
    let output: Vec<u8> = values.iter().flat_map(|value| value.0).collect();
    Ok(InterpreterResult::new(
        InstructionResult::Return,
        Bytes::from(output),
        gas,
    ))
}

/// `block_timestamp > anchor_time + L1_ANCHOR_MAX_LAG`, with the add
/// saturating as in ZKsync OS.
fn anchor_is_stale(block_timestamp: U256, anchor_time: U256) -> bool {
    block_timestamp > anchor_time.saturating_add(U256::from(L1_ANCHOR_MAX_LAG))
}

/// Split the input into the address and 1 to [`L1SLOAD_MAX_KEYS`] keys.
fn parse_input(input: &[u8]) -> Option<(Address, Vec<B256>)> {
    let (address, keys) = input.split_at_checked(Address::len_bytes())?;
    let (keys, rest) = keys.as_chunks::<32>();
    if keys.is_empty() || !rest.is_empty() || keys.len() > L1SLOAD_MAX_KEYS {
        return None;
    }
    Some((
        Address::from_slice(address),
        keys.iter().copied().map(B256::from).collect(),
    ))
}

/// Read a slot of the anchor holder as a ZKsync OS system read: the slot is
/// warmed under a journal entry, but the holder account keeps its warmth, so a
/// later `CALL` to it still pays for a cold account.
fn read_anchor_slot<CTX>(ctx: &mut CTX, slot: B256) -> Result<U256, String>
where
    CTX: ContextTr<Journal: JournalTr<State = EvmState>>,
{
    let journal = ctx.journal_mut();
    let was_cold = journal
        .load_account(L1SLOAD_ANCHOR_HOLDER)
        .map_err(|err| format!("L1SLOAD: failed to load the anchor holder: {err}"))?
        .is_cold;
    let value = journal
        .sload_skip_cold_load(L1SLOAD_ANCHOR_HOLDER, U256::from_be_bytes(slot.0), false)
        .map_err(|err| format!("L1SLOAD: failed to read anchor slot {slot}: {err:?}"))?
        .data;
    if was_cold && let Some(holder) = journal.evm_state_mut().get_mut(&L1SLOAD_ANCHOR_HOLDER) {
        holder.mark_cold();
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::keccak256;

    #[test]
    fn anchor_slots_are_the_namespaced_hashes() {
        assert_eq!(
            keccak256("zksync-os.l1sload.anchor.block-hash"),
            L1SLOAD_ANCHOR_BLOCK_HASH_SLOT
        );
        assert_eq!(
            keccak256("zksync-os.l1sload.anchor.timestamp"),
            L1SLOAD_ANCHOR_TIMESTAMP_SLOT
        );
    }

    /// The same cases as ZKsync OS's `anchor_staleness_boundaries`.
    #[test]
    fn anchor_staleness_boundaries() {
        let at = U256::from;
        let anchored = 1_700_000_000u64;
        assert!(!anchor_is_stale(at(anchored), at(anchored)));
        assert!(!anchor_is_stale(
            at(anchored + L1_ANCHOR_MAX_LAG),
            at(anchored)
        ));
        assert!(anchor_is_stale(
            at(anchored + L1_ANCHOR_MAX_LAG + 1),
            at(anchored)
        ));
        assert!(!anchor_is_stale(at(anchored - 1), at(anchored)));
        assert!(!anchor_is_stale(at(L1_ANCHOR_MAX_LAG), U256::ZERO));
        assert!(anchor_is_stale(at(L1_ANCHOR_MAX_LAG + 1), U256::ZERO));
        // The add saturates instead of wrapping.
        assert!(!anchor_is_stale(at(u64::MAX), U256::MAX));
    }

    #[test]
    fn parses_an_address_and_one_to_five_keys() {
        let address = [0x11u8; 20];
        let input = |num_keys: usize| {
            let mut input = address.to_vec();
            for i in 0..num_keys {
                input.extend_from_slice(&[i as u8; 32]);
            }
            input
        };
        for num_keys in 1..=L1SLOAD_MAX_KEYS {
            let (parsed_address, keys) = parse_input(&input(num_keys)).expect("valid input");
            assert_eq!(parsed_address, Address::from(address));
            assert_eq!(keys.len(), num_keys);
            assert_eq!(keys[num_keys - 1], B256::repeat_byte((num_keys - 1) as u8));
        }
        assert!(parse_input(&address[..19]).is_none());
        assert!(parse_input(&address).is_none(), "no keys");
        assert!(parse_input(&input(6)).is_none(), "more than five keys");
        let mut truncated = input(1);
        truncated.pop();
        assert!(parse_input(&truncated).is_none());
    }
}
