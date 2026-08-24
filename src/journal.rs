//! Contains the [`ZkJournal`] type: the REVM journal extended with the L2→L1 log store.
use crate::l2_to_l1_logs::{L2ToL1Log, L2ToL1LogStore};
use revm::{
    Journal,
    bytecode::Bytecode,
    context::JournalEntry,
    context_interface::{
        Database,
        context::{SStoreResult, SelfDestructResult, StateLoad},
        journaled_state::{
            AccountInfoLoad, AccountLoad, JournalCheckpoint, JournalLoadError, JournalTr,
            TransferError,
        },
    },
    inspector::JournalExt,
    primitives::{
        Address, AddressMap, AddressSet, B256, HashSet, Log, StorageKey, StorageValue, U256,
        address, hardfork::SpecId,
    },
    state::{Account, EvmState},
};
use std::vec::Vec;

/// Sender of the result log of an L1→L2 transaction.
const BOOTLOADER_FORMAL_ADDRESS: Address = address!("0000000000000000000000000000000000008001");

/// State journal that also holds the L2→L1 logs of the transaction.
///
/// An L2→L1 log is a state change of the frame that emits it. It therefore
/// belongs to the journal: a frame that reverts drops its logs, and a frame
/// that commits keeps them, exactly as for storage writes and EVM logs.
/// ZKsync OS applies the same rule, through the frame snapshot of its log
/// storage (`zk_ee/src/common_structs/logs_storage.rs`).
///
/// The caller takes the surviving logs with [`ZkJournal::take_l2_to_l1_logs`]
/// after each transaction.
#[derive(Debug, Clone)]
pub struct ZkJournal<DB> {
    /// Journal of the EVM state.
    inner: Journal<DB>,
    /// L2→L1 logs of the transaction that survived every revert so far.
    l2_to_l1_logs: Vec<L2ToL1Log>,
    /// Log count at the time each open checkpoint was taken, innermost last.
    open_checkpoint_log_counts: Vec<usize>,
    /// Log count at the boundary of the transaction in progress. Logs below it
    /// belong to transactions that are complete, and no revert may drop them.
    log_count_at_transaction_start: usize,
    /// Number of the transaction in the block, recorded in every log.
    tx_number: u16,
    /// Whether [`Self::set_tx_number`] has run for the transaction in progress.
    /// Each transaction boundary clears it, so the number cannot carry over
    /// from the transaction before.
    tx_number_set: bool,
}

impl<DB> ZkJournal<DB> {
    /// Set the number of the transaction in the block. Call before each transaction.
    ///
    /// The number reaches L1 inside every log of the transaction
    /// (`tx_number_in_block`), so it feeds the L2→L1 rolling hash and the
    /// message tree. Zero is the number of the first transaction and cannot
    /// double as "unset", which is why a separate flag guards it.
    pub fn set_tx_number(&mut self, tx_number: u16) {
        self.tx_number = tx_number;
        self.tx_number_set = true;
    }

    /// Take the L2→L1 logs of the transaction.
    pub fn take_l2_to_l1_logs(&mut self) -> Vec<L2ToL1Log> {
        debug_assert!(
            self.open_checkpoint_log_counts.is_empty(),
            "the logs of a transaction are taken at its boundary, with no checkpoint open",
        );
        self.log_count_at_transaction_start = 0;
        core::mem::take(&mut self.l2_to_l1_logs)
    }

    /// Drop the L2→L1 state of the transaction in progress.
    fn reset_transaction_logs(&mut self) {
        self.l2_to_l1_logs.clear();
        self.open_checkpoint_log_counts.clear();
        self.log_count_at_transaction_start = 0;
        self.tx_number_set = false;
    }
}

impl<DB> L2ToL1LogStore for ZkJournal<DB> {
    fn push_l2_to_l1_log(&mut self, sender: Address, key: B256, value: B256) {
        assert!(
            self.tx_number_set,
            "set_tx_number must run for the transaction that emits an L2->L1 log",
        );
        self.l2_to_l1_logs.push(L2ToL1Log {
            l2_shard_id: 0,
            is_service: true,
            tx_number_in_block: self.tx_number,
            sender,
            key,
            value,
        });
    }

    fn emit_l1_tx_result(&mut self, tx_hash: B256, success: bool) {
        let value = B256::from(U256::from(success as u8));
        self.push_l2_to_l1_log(BOOTLOADER_FORMAL_ADDRESS, tx_hash, value);
    }
}

impl<DB: Database> JournalTr for ZkJournal<DB> {
    type Database = DB;
    type State = EvmState;
    type JournaledAccount<'a>
        = <Journal<DB> as JournalTr>::JournaledAccount<'a>
    where
        DB: 'a;

    fn new(database: DB) -> Self {
        Self {
            inner: Journal::new(database),
            l2_to_l1_logs: Vec::new(),
            open_checkpoint_log_counts: Vec::new(),
            log_count_at_transaction_start: 0,
            tx_number: 0,
            tx_number_set: false,
        }
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        self.open_checkpoint_log_counts
            .push(self.l2_to_l1_logs.len());
        self.inner.checkpoint()
    }

    #[inline]
    fn checkpoint_commit(&mut self) {
        self.open_checkpoint_log_counts.pop();
        self.inner.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        // Every checkpoint pushes one log count, so the stack is never empty here.
        debug_assert!(
            !self.open_checkpoint_log_counts.is_empty(),
            "checkpoint revert without an open checkpoint"
        );
        // An empty stack means the caller reverts without a checkpoint: drop the
        // logs of the transaction in progress, and keep the earlier ones.
        let log_count = self
            .open_checkpoint_log_counts
            .pop()
            .unwrap_or(self.log_count_at_transaction_start);
        self.l2_to_l1_logs.truncate(log_count);
        self.inner.checkpoint_revert(checkpoint)
    }

    #[inline]
    fn create_account_checkpoint(
        &mut self,
        caller: Address,
        address: Address,
        balance: U256,
        spec_id: SpecId,
    ) -> Result<JournalCheckpoint, TransferError> {
        self.open_checkpoint_log_counts
            .push(self.l2_to_l1_logs.len());
        let checkpoint = self
            .inner
            .create_account_checkpoint(caller, address, balance, spec_id);
        if checkpoint.is_err() {
            // The inner journal closes the checkpoint it opened.
            self.open_checkpoint_log_counts.pop();
        }
        checkpoint
    }

    #[inline]
    fn commit_tx(&mut self) {
        // The logs stay pending until the caller takes them.
        self.open_checkpoint_log_counts.clear();
        self.log_count_at_transaction_start = self.l2_to_l1_logs.len();
        self.tx_number_set = false;
        self.inner.commit_tx()
    }

    #[inline]
    fn discard_tx(&mut self) {
        self.open_checkpoint_log_counts.clear();
        self.l2_to_l1_logs
            .truncate(self.log_count_at_transaction_start);
        self.log_count_at_transaction_start = self.l2_to_l1_logs.len();
        self.tx_number_set = false;
        self.inner.discard_tx()
    }

    /// Clear the residue of the transaction in progress, L2→L1 logs included.
    ///
    /// The trait default reaches [`Self::finalize`], which owns the EVM state
    /// alone. A caller that resets this way has not taken the logs, so they are
    /// residue of the same transaction and go with it.
    #[inline]
    fn clear(&mut self) {
        self.reset_transaction_logs();
        let _ = self.finalize();
    }

    #[inline]
    fn db(&self) -> &Self::Database {
        self.inner.db()
    }

    #[inline]
    fn db_mut(&mut self) -> &mut Self::Database {
        self.inner.db_mut()
    }

    #[inline]
    fn db_and_state(&self) -> (&Self::Database, &Self::State) {
        self.inner.db_and_state()
    }

    #[inline]
    fn db_and_state_mut(&mut self) -> (&mut Self::Database, &mut Self::State) {
        self.inner.db_and_state_mut()
    }

    #[inline]
    fn evm_state(&self) -> &Self::State {
        self.inner.evm_state()
    }

    #[inline]
    fn evm_state_mut(&mut self) -> &mut Self::State {
        self.inner.evm_state_mut()
    }

    #[inline]
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, JournalLoadError<DB::Error>> {
        self.inner
            .sload_skip_cold_load(address, key, skip_cold_load)
    }

    #[inline]
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, JournalLoadError<DB::Error>> {
        self.inner
            .sstore_skip_cold_load(address, key, value, skip_cold_load)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: StorageKey) -> StorageValue {
        self.inner.tload(address, key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: StorageKey, value: StorageValue) {
        self.inner.tstore(address, key, value)
    }

    #[inline]
    fn log(&mut self, log: Log) {
        self.inner.log(log)
    }

    #[inline]
    fn take_logs(&mut self) -> Vec<Log> {
        self.inner.take_logs()
    }

    #[inline]
    fn logs(&self) -> &[Log] {
        self.inner.logs()
    }

    #[inline]
    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, JournalLoadError<DB::Error>> {
        self.inner.selfdestruct(address, target, skip_cold_load)
    }

    #[inline]
    fn warm_access_list(&mut self, access_list: AddressMap<HashSet<StorageKey>>) {
        self.inner.warm_access_list(access_list)
    }

    #[inline]
    fn warm_coinbase_account(&mut self, address: Address) {
        self.inner.warm_coinbase_account(address)
    }

    #[inline]
    fn warm_precompiles(&mut self, addresses: &AddressSet) {
        self.inner.warm_precompiles(addresses)
    }

    #[inline]
    fn precompile_addresses(&self) -> &AddressSet {
        self.inner.precompile_addresses()
    }

    #[inline]
    fn set_spec_id(&mut self, spec_id: SpecId) {
        self.inner.set_spec_id(spec_id)
    }

    #[inline]
    fn set_eip7708_config(&mut self, disabled: bool, eip8246_delayed_clear_disabled: bool) {
        self.inner
            .set_eip7708_config(disabled, eip8246_delayed_clear_disabled)
    }

    #[inline]
    fn touch_account(&mut self, address: Address) {
        self.inner.touch_account(address)
    }

    #[inline]
    fn transfer(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Result<Option<TransferError>, DB::Error> {
        self.inner.transfer(from, to, balance)
    }

    #[inline]
    fn transfer_loaded(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Option<TransferError> {
        self.inner.transfer_loaded(from, to, balance)
    }

    #[inline]
    #[allow(deprecated)]
    fn caller_accounting_journal_entry(
        &mut self,
        address: Address,
        old_balance: U256,
        bump_nonce: bool,
    ) {
        self.inner
            .caller_accounting_journal_entry(address, old_balance, bump_nonce)
    }

    #[inline]
    fn balance_incr(&mut self, address: Address, balance: U256) -> Result<(), DB::Error> {
        self.inner.balance_incr(address, balance)
    }

    #[inline]
    #[allow(deprecated)]
    fn nonce_bump_journal_entry(&mut self, address: Address) {
        self.inner.nonce_bump_journal_entry(address)
    }

    #[inline]
    fn load_account(&mut self, address: Address) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_account(address)
    }

    #[inline]
    fn load_account_with_code(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_account_with_code(address)
    }

    #[inline]
    fn load_account_delegated(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<AccountLoad>, DB::Error> {
        self.inner.load_account_delegated(address)
    }

    #[inline]
    fn load_account_mut_skip_cold_load(
        &mut self,
        address: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, JournalLoadError<DB::Error>> {
        self.inner
            .load_account_mut_skip_cold_load(address, skip_cold_load)
    }

    #[inline]
    fn load_account_mut_optional_code(
        &mut self,
        address: Address,
        load_code: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, DB::Error> {
        self.inner
            .load_account_mut_optional_code(address, load_code)
    }

    #[inline]
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, JournalLoadError<DB::Error>> {
        self.inner
            .load_account_info_skip_cold_load(address, load_code, skip_cold_load)
    }

    #[inline]
    fn set_code_with_hash(&mut self, address: Address, code: Bytecode, hash: B256) {
        self.inner.set_code_with_hash(address, code, hash)
    }

    #[inline]
    fn depth(&self) -> usize {
        self.inner.depth()
    }

    #[inline]
    fn finalize(&mut self) -> Self::State {
        self.inner.finalize()
    }
}

impl<DB: Database> JournalExt for ZkJournal<DB> {
    #[inline]
    fn journal(&self) -> &[JournalEntry] {
        self.inner.journal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::builder::ZkBuilder;
    use crate::api::default_ctx::zk_context;
    use crate::precompiles::v1::l1_messenger::{L1_MESSENGER_ADDRESS, SEND_TO_L1_SELECTOR};
    use crate::precompiles::v3::l1_messenger::L1_MESSENGER_HOOK_ADDRESS;
    use crate::{ZKsyncTx, ZkSpecId};
    use revm::{
        ExecuteEvm,
        context::TxEnv,
        database::{CacheDB, EmptyDB},
        primitives::{Bytes, TxKind, keccak256},
        state::AccountInfo,
    };

    const CALLER: Address = address!("0000000000000000000000000000000000000c0f");
    const UNFUNDED_CALLER: Address = address!("0000000000000000000000000000000000000d0f");
    const OUTER_CONTRACT: Address = address!("0000000000000000000000000000000000001111");
    const MESSAGE_SENDER_CONTRACT: Address = address!("0000000000000000000000000000000000002222");
    const SECOND_MESSAGE_SENDER_CONTRACT: Address =
        address!("0000000000000000000000000000000000003333");
    const MESSAGE: [u8; 32] = [0xaa; 32];
    const SECOND_MESSAGE: [u8; 32] = [0xbb; 32];

    const OP_STOP: u8 = 0x00;
    const OP_POP: u8 = 0x50;
    const OP_MSTORE: u8 = 0x52;
    const OP_GAS: u8 = 0x5a;
    const OP_PUSH1: u8 = 0x60;
    const OP_PUSH20: u8 = 0x73;
    const OP_PUSH32: u8 = 0x7f;
    const OP_CALL: u8 = 0xf1;
    const OP_REVERT: u8 = 0xfd;

    const ALL_SPECS: [ZkSpecId; 4] = [
        ZkSpecId::AtlasV1,
        ZkSpecId::AtlasV2,
        ZkSpecId::AtlasV3,
        ZkSpecId::AtlasV4,
    ];

    /// How a frame ends.
    #[derive(Clone, Copy, Debug)]
    enum FrameEnd {
        Commit,
        Revert,
    }

    fn frame_end_code(end: FrameEnd) -> Vec<u8> {
        match end {
            FrameEnd::Commit => vec![OP_STOP],
            FrameEnd::Revert => vec![OP_PUSH1, 0, OP_PUSH1, 0, OP_REVERT],
        }
    }

    /// Big endian 32 byte encoding of `value`.
    fn word(value: u8) -> [u8; 32] {
        let mut encoded = [0u8; 32];
        encoded[31] = value;
        encoded
    }

    /// Code that writes `content` into memory at `offset`.
    fn store_code(offset: u8, content: [u8; 32]) -> Vec<u8> {
        let mut code = vec![OP_PUSH32];
        code.extend_from_slice(&content);
        code.extend_from_slice(&[OP_PUSH1, offset, OP_MSTORE]);
        code
    }

    /// Code that calls `target` with the first `argument_length` memory bytes.
    fn call_code(target: Address, argument_length: u8) -> Vec<u8> {
        let mut code = vec![
            OP_PUSH1,
            0, // return data length
            OP_PUSH1,
            0, // return data offset
            OP_PUSH1,
            argument_length,
            OP_PUSH1,
            0, // argument offset
            OP_PUSH1,
            0, // call value
            OP_PUSH20,
        ];
        code.extend_from_slice(target.as_slice());
        code.extend_from_slice(&[OP_GAS, OP_CALL, OP_POP]);
        code
    }

    /// Address that holds the code which sends the message.
    ///
    /// From AtlasV3 on, the hook accepts the L1 messenger contract as its only
    /// caller, so the code must sit at that address. Under the older specs the
    /// L1 messenger itself is the precompile, and any contract may call it.
    fn message_sender_address(spec: ZkSpecId) -> Address {
        match spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => MESSAGE_SENDER_CONTRACT,
            ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 => L1_MESSENGER_ADDRESS,
        }
    }

    /// Code that sends `message` to L1 and then ends the frame.
    fn send_message_code(spec: ZkSpecId, message: [u8; 32], end: FrameEnd) -> Bytes {
        let mut code = Vec::new();
        match spec {
            ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => {
                // sendToL1(bytes): selector, offset, length, message.
                let mut selector = [0u8; 32];
                selector[..4].copy_from_slice(SEND_TO_L1_SELECTOR);
                code.extend(store_code(0, selector));
                code.extend(store_code(4, word(32)));
                code.extend(store_code(36, word(32)));
                code.extend(store_code(68, message));
                code.extend(call_code(L1_MESSENGER_ADDRESS, 100));
            }
            ZkSpecId::AtlasV3 | ZkSpecId::AtlasV4 => {
                // The hook takes abi.encodePacked(address sender, bytes message).
                let mut sender = [0u8; 32];
                sender[..20].copy_from_slice(L1_MESSENGER_ADDRESS.as_slice());
                code.extend(store_code(0, sender));
                code.extend(store_code(20, message));
                code.extend(call_code(L1_MESSENGER_HOOK_ADDRESS, 52));
            }
        }
        code.extend(frame_end_code(end));
        code.into()
    }

    /// Code that calls each target in turn and then ends the frame.
    fn outer_frame_code(targets: &[Address], end: FrameEnd) -> Bytes {
        let mut code = Vec::new();
        for target in targets {
            code.extend(call_code(*target, 0));
        }
        code.extend(frame_end_code(end));
        code.into()
    }

    /// Database that holds `accounts` next to the funded caller.
    fn database(accounts: &[(Address, Bytes)]) -> CacheDB<EmptyDB> {
        let mut database = CacheDB::new(EmptyDB::default());
        database.insert_account_info(
            CALLER,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
        for (address, code) in accounts {
            database.insert_account_info(
                *address,
                AccountInfo {
                    code: Some(Bytecode::new_raw(code.clone())),
                    ..Default::default()
                },
            );
        }
        database
    }

    /// Run one transaction against `accounts` and return the L2→L1 logs it keeps.
    fn run_transaction(
        spec: ZkSpecId,
        accounts: &[(Address, Bytes)],
        entry: Address,
    ) -> Vec<L2ToL1Log> {
        let mut evm = zk_context(database(accounts), spec).build_zk();
        evm.0.ctx.journaled_state.set_tx_number(0);
        let transaction = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(entry))
                    .gas_limit(1_000_000),
            )
            .tx_hash(B256::ZERO)
            .build_fill()
            .expect("transaction builds");
        evm.transact(transaction).expect("transaction runs");
        evm.0.ctx.journaled_state.take_l2_to_l1_logs()
    }

    /// Run one transaction against `accounts`, then one transaction that the
    /// handler rejects, and return the L2→L1 logs that survive both.
    fn run_transaction_then_rejected_transaction(
        spec: ZkSpecId,
        accounts: &[(Address, Bytes)],
        entry: Address,
    ) -> Vec<L2ToL1Log> {
        let mut evm = zk_context(database(accounts), spec).build_zk();
        evm.0.ctx.journaled_state.set_tx_number(0);
        let transaction = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(entry))
                    .gas_limit(1_000_000),
            )
            .tx_hash(B256::ZERO)
            .build_fill()
            .expect("transaction builds");
        evm.transact(transaction).expect("transaction runs");

        evm.0.ctx.journaled_state.set_tx_number(1);
        // The caller holds no funds, so the handler rejects the transaction.
        let rejected = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(UNFUNDED_CALLER)
                    .kind(TxKind::Call(entry))
                    .gas_limit(1_000_000)
                    .gas_price(1),
            )
            .tx_hash(B256::ZERO)
            .build_fill()
            .expect("transaction builds");
        evm.transact(rejected).expect_err("transaction is rejected");

        evm.0.ctx.journaled_state.take_l2_to_l1_logs()
    }

    #[test]
    fn log_of_committed_frame_survives() {
        for spec in ALL_SPECS {
            let sender = message_sender_address(spec);
            let accounts = [
                (sender, send_message_code(spec, MESSAGE, FrameEnd::Commit)),
                (
                    OUTER_CONTRACT,
                    outer_frame_code(&[sender], FrameEnd::Commit),
                ),
            ];

            let logs = run_transaction(spec, &accounts, OUTER_CONTRACT);

            assert_eq!(logs.len(), 1, "{spec:?}");
            assert_eq!(logs[0].value, keccak256(MESSAGE), "{spec:?}");
            assert_eq!(logs[0].sender, L1_MESSENGER_ADDRESS, "{spec:?}");
        }
    }

    #[test]
    fn log_of_reverted_frame_is_discarded() {
        for spec in ALL_SPECS {
            let sender = message_sender_address(spec);
            let accounts = [
                (sender, send_message_code(spec, MESSAGE, FrameEnd::Revert)),
                (
                    OUTER_CONTRACT,
                    outer_frame_code(&[sender], FrameEnd::Commit),
                ),
            ];

            let logs = run_transaction(spec, &accounts, OUTER_CONTRACT);

            assert!(logs.is_empty(), "{spec:?} kept {} logs", logs.len());
        }
    }

    #[test]
    fn log_of_committed_frame_inside_reverted_frame_is_discarded() {
        for spec in ALL_SPECS {
            let sender = message_sender_address(spec);
            let accounts = [
                (sender, send_message_code(spec, MESSAGE, FrameEnd::Commit)),
                (
                    OUTER_CONTRACT,
                    outer_frame_code(&[sender], FrameEnd::Revert),
                ),
            ];

            let logs = run_transaction(spec, &accounts, OUTER_CONTRACT);

            assert!(logs.is_empty(), "{spec:?} kept {} logs", logs.len());
        }
    }

    #[test]
    fn log_of_reverted_transaction_is_discarded() {
        for spec in ALL_SPECS {
            let sender = message_sender_address(spec);
            let accounts = [(sender, send_message_code(spec, MESSAGE, FrameEnd::Revert))];

            let logs = run_transaction(spec, &accounts, sender);

            assert!(logs.is_empty(), "{spec:?} kept {} logs", logs.len());
        }
    }

    #[test]
    fn log_of_committed_transaction_survives_a_rejected_transaction() {
        for spec in ALL_SPECS {
            let sender = message_sender_address(spec);
            let accounts = [
                (sender, send_message_code(spec, MESSAGE, FrameEnd::Commit)),
                (
                    OUTER_CONTRACT,
                    outer_frame_code(&[sender], FrameEnd::Commit),
                ),
            ];

            // The message comes from the top frame, and then from a nested frame.
            for entry in [sender, OUTER_CONTRACT] {
                let logs = run_transaction_then_rejected_transaction(spec, &accounts, entry);

                assert_eq!(logs.len(), 1, "{spec:?} {entry}");
                assert_eq!(logs[0].value, keccak256(MESSAGE), "{spec:?} {entry}");
            }
        }
    }

    #[test]
    fn revert_of_one_frame_keeps_the_log_of_the_next_frame() {
        // AtlasV3 is absent: its hook accepts a single caller address, so two
        // message senders cannot coexist.
        for spec in [ZkSpecId::AtlasV1, ZkSpecId::AtlasV2] {
            let accounts = [
                (
                    MESSAGE_SENDER_CONTRACT,
                    send_message_code(spec, MESSAGE, FrameEnd::Revert),
                ),
                (
                    SECOND_MESSAGE_SENDER_CONTRACT,
                    send_message_code(spec, SECOND_MESSAGE, FrameEnd::Commit),
                ),
                (
                    OUTER_CONTRACT,
                    outer_frame_code(
                        &[MESSAGE_SENDER_CONTRACT, SECOND_MESSAGE_SENDER_CONTRACT],
                        FrameEnd::Commit,
                    ),
                ),
            ];

            let logs = run_transaction(spec, &accounts, OUTER_CONTRACT);

            assert_eq!(logs.len(), 1, "{spec:?}");
            assert_eq!(logs[0].value, keccak256(SECOND_MESSAGE), "{spec:?}");
        }
    }

    /// Zero is a valid transaction number, so an unset number cannot be told
    /// from the first transaction by value alone.
    #[test]
    #[should_panic(expected = "set_tx_number must run")]
    fn a_log_without_a_transaction_number_is_refused() {
        let mut journal = ZkJournal::new(database(&[]));
        journal.push_l2_to_l1_log(CALLER, B256::ZERO, B256::ZERO);
    }

    /// The number of one transaction must not reach the logs of the next: two
    /// logs claiming one transaction diverge from the message tree of ZKsync OS.
    #[test]
    #[should_panic(expected = "set_tx_number must run")]
    fn the_transaction_number_does_not_carry_over_a_boundary() {
        let mut journal = ZkJournal::new(database(&[]));
        journal.set_tx_number(0);
        journal.push_l2_to_l1_log(CALLER, B256::ZERO, B256::ZERO);
        journal.commit_tx();
        journal.push_l2_to_l1_log(CALLER, B256::ZERO, B256::ZERO);
    }

    #[test]
    fn clear_drops_the_pending_l2_to_l1_logs() {
        let mut journal = ZkJournal::new(database(&[]));
        journal.set_tx_number(0);
        journal.push_l2_to_l1_log(CALLER, B256::ZERO, B256::ZERO);
        journal.clear();
        assert!(journal.take_l2_to_l1_logs().is_empty());
    }
}
