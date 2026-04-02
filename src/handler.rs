//!Handler related to ZKsync OS chain
use core::cell::Cell;
use std::boxed::Box;

use crate::{
    api::exec::ZkContextTr,
    constants::{BASE_TOKEN_HOLDER_ADDRESS, L2_ASSET_TRACKER_ADDRESS, L2_BASE_TOKEN_ADDRESS},
    spec::ZkSpecId,
    transaction::{ZKsyncTxError, ZkTxTr},
};
use revm::{
    context::{LocalContextTr, result::InvalidTransaction},
    context_interface::{
        Block, Cfg, ContextSetters, ContextTr, JournalTr, Transaction,
        context::ContextError,
        journaled_state::{JournalCheckpoint, account::JournaledAccountTr},
        result::{EVMError, ExecutionResult, FromStringError, HaltReason},
        transaction::TransactionType,
    },
    handler::{
        EthFrame, EvmTr, FrameResult, Handler, MainnetHandler, evm::FrameTr, handler::EvmTrError,
        post_execution, pre_execution::validate_account_nonce_and_code, system_call::SystemCallTx,
    },
    inspector::{Inspector, InspectorEvmTr, InspectorHandler},
    interpreter::{
        CallOutcome, Gas, InitialAndFloorGas, InstructionResult, InterpreterResult,
        interpreter::EthInterpreter, interpreter_action::FrameInit,
    },
    primitives::{Bytes, U256},
    state::EvmState,
};

const HANDLE_FINALIZE_BASE_TOKEN_BRIDGING_ON_L2_SELECTOR: [u8; 4] = [0x03, 0x11, 0x7c, 0x8c];
/// L2AssetTracker storage slot for `uint256 public L1_CHAIN_ID`.
/// Verified via `forge inspect L2AssetTracker storage-layout`.
const L2_ASSET_TRACKER_L1_CHAIN_ID_SLOT: U256 = U256::from_limbs([154, 0, 0, 0]);

#[derive(Clone, Copy, Debug)]
struct AtlasL1FeeFlow {
    mint: U256,
    prepaid_fee: U256,
    upfront_transfer: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum L1TxAccountingMode {
    Legacy,
    AtlasV3,
}

/// ZKsync OS handler extends the [`Handler`] with ZKsync OS specific logic.
#[derive(Debug, Clone)]
pub struct ZKsyncHandler<EVM, ERROR, FRAME> {
    /// Mainnet handler allows us to use functions from the mainnet handler inside ZKsync OS handler.
    /// So we dont duplicate the logic
    pub mainnet: MainnetHandler<EVM, ERROR, FRAME>,
    /// Phantom data to avoid type inference issues.
    pub _phantom: core::marker::PhantomData<(EVM, ERROR, FRAME)>,
    /// Provisional checkpoint for AtlasV3 upfront mint notification and transfer.
    /// It is committed only if the main tx body succeeds.
    pending_value_mint_checkpoint: Cell<Option<JournalCheckpoint>>,
}

impl<EVM, ERROR, FRAME> ZKsyncHandler<EVM, ERROR, FRAME> {
    /// Create a new ZKsync OS handler.
    pub fn new() -> Self {
        Self {
            mainnet: MainnetHandler::default(),
            _phantom: core::marker::PhantomData,
            pending_value_mint_checkpoint: Cell::new(None),
        }
    }

    fn forced_fail_execution_result(&mut self, evm: &mut EVM) -> Result<FrameResult, ERROR>
    where
        EVM: EvmTr<Frame = FRAME>,
        EVM::Context: ZkContextTr + ContextSetters,
        <EVM::Context as ContextTr>::Tx: Clone + SystemCallTx,
        <EVM::Context as ContextTr>::Journal: JournalTr<State = EvmState>,
        ERROR: EvmTrError<EVM> + From<ZKsyncTxError> + FromStringError + IsTxError,
        FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
    {
        {
            let (tx, journal) = evm.ctx().tx_journal_mut();
            let caller = tx.caller();
            let is_create = tx.kind().is_create();
            let mut caller_account = journal.load_account_with_code_mut(caller)?.data;
            if is_create {
                // Bump the nonce for creates, because usually it is handled in `handle_create`.
                // Forced failure doesn't call the actual execution path.
                caller_account.bump_nonce();
            }
        } // release tx/journal borrows

        // Synthesize a top-level REVERT frame result (no state changes).
        let ir = InterpreterResult::new(
            InstructionResult::Revert,
            Default::default(),
            Gas::new_spent(0),
        );
        let mut frame_result = FrameResult::Call(CallOutcome::new(ir, 0..0));

        // Rewrite gas to match ZKsync OS semantics.
        let gas_limit = evm.ctx().tx().gas_limit();
        let gas_used = evm.ctx().tx().gas_used_override().unwrap_or(gas_limit);
        let used = gas_used.min(gas_limit);
        let unused = gas_limit - used;
        let gas = frame_result.gas_mut();
        *gas = Gas::new_spent(gas_limit);
        gas.erase_cost(unused);

        // Normalize as a regular top-level frame return.
        self.last_frame_result(evm, &mut frame_result)?;
        Ok(frame_result)
    }

    #[inline]
    fn effective_gas_price_for_spec<TX: ZkTxTr>(
        tx: &TX,
        base_fee: u128,
        spec_id: ZkSpecId,
    ) -> u128 {
        // L1->L2 transactions use their own gas_price set on L1,
        // independent of the L2 block base_fee.
        if tx.is_l1_to_l2_tx() {
            return tx.effective_gas_price(base_fee);
        }
        if ZkSpecId::AtlasV3.is_enabled_in(spec_id) && base_fee == 0 {
            0
        } else {
            tx.effective_gas_price(base_fee)
        }
    }

    #[inline]
    fn effective_balance_spending_for_spec<TX: ZkTxTr>(
        tx: &TX,
        base_fee: u128,
        blob_price: u128,
        spec_id: ZkSpecId,
    ) -> Result<U256, InvalidTransaction> {
        let mut effective_balance_spending = (tx.gas_limit() as u128)
            .checked_mul(Self::effective_gas_price_for_spec(tx, base_fee, spec_id))
            .and_then(|gas_cost| U256::from(gas_cost).checked_add(tx.value()))
            .ok_or(InvalidTransaction::OverflowPaymentInTransaction)?;

        if tx.tx_type() == TransactionType::Eip4844 as u8 {
            let blob_gas = tx.total_blob_gas() as u128;
            effective_balance_spending = effective_balance_spending
                .checked_add(U256::from(blob_price.saturating_mul(blob_gas)))
                .ok_or(InvalidTransaction::OverflowPaymentInTransaction)?;
        }

        Ok(effective_balance_spending)
    }

    #[inline]
    fn l1_tx_accounting_mode<TX: ZkTxTr>(tx: &TX, spec_id: ZkSpecId) -> Option<L1TxAccountingMode> {
        if !tx.is_l1_to_l2_tx() {
            return None;
        }

        Some(if ZkSpecId::AtlasV3.is_enabled_in(spec_id) {
            L1TxAccountingMode::AtlasV3
        } else {
            L1TxAccountingMode::Legacy
        })
    }

    #[inline]
    fn atlas_l1_fee_flow<TX: ZkTxTr>(tx: &TX, base_fee: u128, spec_id: ZkSpecId) -> AtlasL1FeeFlow {
        debug_assert!(ZkSpecId::AtlasV3.is_enabled_in(spec_id));
        let effective_gas_price = Self::effective_gas_price_for_spec(tx, base_fee, spec_id);
        let prepaid_fee = U256::from(tx.gas_limit()) * U256::from(effective_gas_price);
        let mint = tx.mint().unwrap_or_default();
        let upfront_transfer = mint.saturating_sub(prepaid_fee);
        AtlasL1FeeFlow {
            mint,
            prepaid_fee,
            upfront_transfer,
        }
    }

    #[inline]
    fn saturating_initial_tx_gas<TX: Transaction>(
        tx: &TX,
        spec_id: ZkSpecId,
        is_eip7623_disabled: bool,
    ) -> InitialAndFloorGas {
        let mut gas = revm::context_interface::cfg::gas::calculate_initial_tx_gas_for_tx(
            tx,
            spec_id.into_eth_spec(),
        );
        if is_eip7623_disabled {
            gas.floor_gas = 0;
        }
        let gas_limit = tx.gas_limit();
        gas.initial_gas = gas.initial_gas.min(gas_limit);
        gas.floor_gas = gas.floor_gas.min(gas_limit);
        gas
    }
}

impl<EVM, ERROR, FRAME> Default for ZKsyncHandler<EVM, ERROR, FRAME> {
    fn default() -> Self {
        Self::new()
    }
}

impl<EVM, ERROR, FRAME> ZKsyncHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<Frame = FRAME>,
    EVM::Context: ZkContextTr + ContextSetters,
    <EVM::Context as ContextTr>::Tx: Clone + SystemCallTx,
    <EVM::Context as ContextTr>::Journal: JournalTr<State = EvmState>,
    ERROR: EvmTrError<EVM> + From<ZKsyncTxError> + FromStringError + IsTxError,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
{
    /// Read L1 chain ID from L2AssetTracker storage (slot 154).
    /// Returns U256::ZERO if the account is not present in state
    /// (e.g., tests that don't deploy L2AssetTracker).
    fn read_l1_chain_id(evm: &mut EVM) -> U256 {
        let journal = evm.ctx().journal_mut();
        // Load the account first so sload doesn't hit ColdLoadSkipped.
        if journal.load_account(L2_ASSET_TRACKER_ADDRESS).is_err() {
            return U256::ZERO;
        }
        journal
            .sload(L2_ASSET_TRACKER_ADDRESS, L2_ASSET_TRACKER_L1_CHAIN_ID_SLOT)
            .map(|v| v.data)
            .unwrap_or(U256::ZERO)
    }

    fn notify_l2_asset_tracker(
        &self,
        evm: &mut EVM,
        frame_result: &FrameResult,
    ) -> Result<(), ERROR> {
        if !evm.ctx().tx().is_l1_to_l2_tx() {
            return Ok(());
        }

        let total_deposited = evm.ctx().tx().mint().unwrap_or_default();
        if total_deposited.is_zero() {
            return Ok(());
        }

        let l1_chain_id = Self::read_l1_chain_id(evm);
        let basefee = evm.ctx().block().basefee() as u128;
        let spec_id = evm.ctx().cfg().spec();
        let gas_price = U256::from(Self::effective_gas_price_for_spec(
            evm.ctx().tx(),
            basefee,
            spec_id,
        ));
        let gas_limit = U256::from(evm.ctx().tx().gas_limit());
        let max_fee_commitment = gas_price
            .checked_mul(gas_limit)
            .ok_or_else(|| ERROR::from_string("L1 max fee commitment overflow".into()))?;
        let pay_to_operator = U256::from(frame_result.gas().used())
            .checked_mul(gas_price)
            .ok_or_else(|| ERROR::from_string("L1 operator fee overflow".into()))?;
        let is_success = frame_result.interpreter_result().result.is_ok();

        // Operator fee notification
        if !pay_to_operator.is_zero() {
            self.execute_asset_tracker_call(evm, l1_chain_id, pay_to_operator)?;
        }

        // Refund notification
        let refund = if is_success {
            max_fee_commitment
                .checked_sub(pay_to_operator)
                .ok_or_else(|| {
                    ERROR::from_string(
                        "Invalid L1 tx replay invariant: operator fee exceeds prepaid fee".into(),
                    )
                })?
        } else {
            total_deposited
                .checked_sub(pay_to_operator)
                .ok_or_else(|| {
                    ERROR::from_string(
                        "Invalid L1 tx replay invariant: operator fee exceeds deposited amount"
                            .into(),
                    )
                })?
        };
        if !refund.is_zero() {
            self.execute_asset_tracker_call(evm, l1_chain_id, refund)?;
        }

        Ok(())
    }

    fn execute_asset_tracker_call(
        &self,
        evm: &mut EVM,
        l1_chain_id: U256,
        amount: U256,
    ) -> Result<(), ERROR> {
        let original_tx = evm.ctx().tx().clone();
        let mut calldata = [0u8; 68];
        calldata[..4].copy_from_slice(&HANDLE_FINALIZE_BASE_TOKEN_BRIDGING_ON_L2_SELECTOR);
        calldata[4..36].copy_from_slice(&l1_chain_id.to_be_bytes::<32>());
        calldata[36..68].copy_from_slice(&amount.to_be_bytes::<32>());

        evm.ctx()
            .set_tx(<EVM::Context as ContextTr>::Tx::new_system_tx_with_caller(
                L2_BASE_TOKEN_ADDRESS,
                L2_ASSET_TRACKER_ADDRESS,
                Bytes::copy_from_slice(&calldata),
            ));

        let mut handler = Self::new();
        let execution_result = handler.execution(evm, &InitialAndFloorGas::new(0, 0));
        evm.ctx().set_tx(original_tx);
        evm.ctx().local_mut().clear();
        evm.frame_stack().clear();

        let frame_result = execution_result?;
        if frame_result.interpreter_result().result.is_ok() {
            return Ok(());
        }

        // A revert here means token accounting is broken — treat as a fatal system error,
        // matching ZKsync OS bootloader behavior which returns internal_error!() on revert.
        Err(ERROR::from_string(
            "L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted during L1 replay".into(),
        ))
    }
}

/// Trait to check if the error is a transaction error.
///
/// Used in cache_error handler to catch deposit transaction that was halted.
pub trait IsTxError {
    /// Check if the error is a transaction error.
    fn is_tx_error(&self) -> bool;
}

impl<DB, TX> IsTxError for EVMError<DB, TX> {
    fn is_tx_error(&self) -> bool {
        matches!(self, EVMError::Transaction(_))
    }
}

impl<EVM, ERROR, FRAME> Handler for ZKsyncHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<Frame = FRAME>,
    EVM::Context: ZkContextTr + ContextSetters,
    <EVM::Context as ContextTr>::Tx: Clone + SystemCallTx,
    <EVM::Context as ContextTr>::Journal: JournalTr<State = EvmState>,
    ERROR: EvmTrError<EVM> + From<ZKsyncTxError> + FromStringError + IsTxError,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    fn validate_env(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        let ctx = evm.ctx();
        let tx = ctx.tx();
        if tx.is_l1_to_l2_tx() {
            return Ok(());
        }

        self.mainnet.validate_env(evm)
    }

    #[inline]
    fn validate_initial_tx_gas(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<InitialAndFloorGas, Self::Error> {
        let ctx = evm.ctx_ref();
        let tx = ctx.tx();
        let spec_id = ctx.cfg().spec();
        let is_eip7623_disabled = ctx.cfg().is_eip7623_disabled();
        let is_relaxed_l1 =
            Self::l1_tx_accounting_mode(tx, spec_id) == Some(L1TxAccountingMode::AtlasV3);

        let validated = revm::handler::validation::validate_initial_tx_gas(
            tx,
            spec_id.into_eth_spec(),
            is_eip7623_disabled,
        );

        match validated {
            Ok(gas) => Ok(gas),
            Err(InvalidTransaction::CallGasCostMoreThanGasLimit { .. })
            | Err(InvalidTransaction::GasFloorMoreThanGasLimit { .. })
                if is_relaxed_l1 =>
            {
                // L1->L2 txs are pre-validated on L1. If intrinsic/floor gas exceeds the tx gas
                // limit, keep processing by saturating to the provided gas limit.
                Ok(Self::saturating_initial_tx_gas(
                    tx,
                    spec_id,
                    is_eip7623_disabled,
                ))
            }
            Err(err) => Err(err.into()),
        }
    }

    #[inline]
    fn post_execution(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
        init_and_floor_gas: InitialAndFloorGas,
        eip7702_gas_refund: i64,
    ) -> Result<(), Self::Error> {
        let is_success = exec_result.interpreter_result().result.is_ok();
        if let Some(checkpoint) = self.pending_value_mint_checkpoint.take() {
            if is_success {
                evm.ctx().journal_mut().checkpoint_commit();
            } else {
                evm.ctx().journal_mut().checkpoint_revert(checkpoint);
            }
        }

        if let Some(gas_used_override) = evm.ctx().tx().gas_used_override() {
            let gas_limit = evm.ctx().tx().gas_limit();
            // Just in case use at most `gas_limit` gas to prevent the underflow
            let used = gas_used_override.min(gas_limit);
            let unused = gas_limit - used;

            // Rewrite the Gas object to match ZKsync OS usage.
            let gas = exec_result.gas_mut();
            *gas = Gas::new_spent(gas_limit);
            gas.erase_cost(unused);
            // IMPORTANT: ignore EVM-native refunds: (do NOT call `gas.record_refund(...)` here)
            //    self.refund(evm, exec_result, eip7702_gas_refund);  // <-- intentionally NOT called

            // Reimburse sender and reward beneficiary using the rewritten Gas.
            if ZkSpecId::AtlasV3.is_enabled_in(evm.ctx().cfg().spec()) {
                self.notify_l2_asset_tracker(evm, exec_result)?;
            }
            self.reimburse_caller(evm, exec_result)?;
            self.reward_beneficiary(evm, exec_result)?;
        } else {
            // Vanilla path: keep default EVM accounting
            if ZkSpecId::AtlasV3.is_enabled_in(evm.ctx().cfg().spec()) {
                self.notify_l2_asset_tracker(evm, exec_result)?;
            }
            self.refund(evm, exec_result, eip7702_gas_refund);
            self.eip7623_check_gas_floor(evm, exec_result, init_and_floor_gas);
            self.reimburse_caller(evm, exec_result)?;
            self.reward_beneficiary(evm, exec_result)?;
        }

        Ok(())
    }

    fn execution(
        &mut self,
        evm: &mut Self::Evm,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, Self::Error> {
        if evm.ctx().tx().force_fail() {
            return self.forced_fail_execution_result(evm);
        }

        let gas_limit = evm
            .ctx()
            .tx()
            .gas_limit()
            .saturating_sub(init_and_floor_gas.initial_gas);
        let first_frame_input = self.first_frame_input(evm, gas_limit)?;
        let mut frame_result = self.run_exec_loop(evm, first_frame_input)?;
        self.last_frame_result(evm, &mut frame_result)?;
        Ok(frame_result)
    }

    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<(), Self::Error> {
        let ctx = evm.ctx();

        let basefee = ctx.block().basefee() as u128;
        let spec_id = ctx.cfg().spec();
        let blob_price = ctx.block().blob_gasprice().unwrap_or_default();
        let is_eip3607_disabled = ctx.cfg().is_eip3607_disabled();
        let is_nonce_check_disabled = ctx.cfg().is_nonce_check_disabled();

        let (tx, journal) = ctx.tx_journal_mut();

        // For L1->L2 transactions, balance setup is spec-dependent and handled below.
        if let Some(l1_mode) = Self::l1_tx_accounting_mode(tx, spec_id) {
            match l1_mode {
                L1TxAccountingMode::Legacy => {
                    let mut caller_account = journal.load_account_with_code_mut(tx.caller())?.data;
                    let new_balance = caller_account.balance().saturating_add(tx.value());
                    caller_account.touch();
                    caller_account.set_balance(new_balance);
                    return Ok(());
                }
                L1TxAccountingMode::AtlasV3 => {
                    // Ensure caller is present in journal for later CALL value transfer path,
                    // even when there is no upfront treasury transfer.
                    journal.load_account_with_code_mut(tx.caller())?;

                    // On AtlasV3, `mint` (reserved[0]) is split into:
                    // 1) max fee commitment (kept in treasury until post-execution)
                    // 2) upfront transfer to caller (available during execution)
                    let fee_flow = Self::atlas_l1_fee_flow(tx, basefee, spec_id);
                    if fee_flow.upfront_transfer > U256::ZERO {
                        // Match zkOS semantics: the upfront value mint and treasury transfer
                        // are provisional until the main tx body succeeds.
                        let checkpoint = journal.checkpoint();
                        self.pending_value_mint_checkpoint.set(Some(checkpoint));

                        let result = (|| -> Result<(), Self::Error> {
                            let l1_chain_id = Self::read_l1_chain_id(evm);
                            self.execute_asset_tracker_call(
                                evm,
                                l1_chain_id,
                                fee_flow.upfront_transfer,
                            )?;

                            let (tx, journal) = evm.ctx().tx_journal_mut();
                            let _ = tx; // reborrow after execute_asset_tracker_call
                            journal.transfer(
                                BASE_TOKEN_HOLDER_ADDRESS,
                                tx.caller(),
                                fee_flow.upfront_transfer,
                            )?;
                            Ok(())
                        })();

                        if let Err(err) = result {
                            self.pending_value_mint_checkpoint.set(None);
                            evm.ctx().journal_mut().checkpoint_revert(checkpoint);
                            return Err(err);
                        }
                    }
                    return Ok(());
                }
            }
        }

        if tx.is_service_tx() {
            return Ok(());
        }

        let mut caller_account = journal.load_account_with_code_mut(tx.caller())?.data;
        // validates account nonce and code
        validate_account_nonce_and_code(
            &caller_account.account().info,
            tx.nonce(),
            is_eip3607_disabled,
            is_nonce_check_disabled,
        )?;

        let mut new_balance = *caller_account.balance();
        let max_balance_spending = tx.max_balance_spending()?;

        if max_balance_spending > new_balance {
            return Err(InvalidTransaction::LackOfFundForMaxFee {
                fee: Box::new(max_balance_spending),
                balance: Box::new(new_balance),
            }
            .into());
        }

        let effective_balance_spending = Self::effective_balance_spending_for_spec(
            tx, basefee, blob_price, spec_id,
        )
        .expect("effective balance is always smaller than max balance so it can't overflow");

        // subtracting max balance spending with value that is going to be deducted later in the call.
        let gas_balance_spending = effective_balance_spending - tx.value();
        new_balance = new_balance.saturating_sub(gas_balance_spending);

        // Touch account so we know it is changed.
        caller_account.touch();
        caller_account.set_balance(new_balance);

        // Bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
        if tx.kind().is_call() {
            caller_account.bump_nonce();
        }

        Ok(())
    }

    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        frame_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        let basefee = evm.ctx().block().basefee() as u128;
        let spec_id = evm.ctx().cfg().spec();
        let l1_mode = Self::l1_tx_accounting_mode(evm.ctx().tx(), spec_id);

        let Some(l1_mode) = l1_mode else {
            let caller = evm.ctx().tx().caller();
            let effective_gas_price =
                Self::effective_gas_price_for_spec(evm.ctx().tx(), basefee, spec_id);
            // Clamp defensively to avoid accidental wrap if call ordering changes.
            let refunded_gas = frame_result.gas().refunded().max(0) as u64;
            let refund = U256::from(
                effective_gas_price
                    .saturating_mul((frame_result.gas().remaining() + refunded_gas) as u128),
            );
            evm.ctx()
                .journal_mut()
                .load_account_mut(caller)?
                .incr_balance(refund);
            return Ok(());
        };

        // For L1->L2 transactions, mint and gas fees were not applied to the
        // sender before execution. Handle all balance accounting here.
        let caller = evm.ctx().tx().caller();
        let refund_recipient = evm
            .ctx()
            .tx()
            .refund_recipient()
            .expect("Refund recipient is missing for L1 -> L2 tx");

        let effective_gas_price =
            Self::effective_gas_price_for_spec(evm.ctx().tx(), basefee, spec_id);
        let spent_fee = U256::from(frame_result.gas().used()) * U256::from(effective_gas_price);

        match l1_mode {
            L1TxAccountingMode::Legacy => {
                let is_success = frame_result.interpreter_result().result.is_ok();
                let mint = evm.ctx().tx().mint().unwrap_or_default();
                let value = evm.ctx().tx().value();

                if !is_success {
                    // On failure, value transfer was rolled back so sender still holds
                    // the extra `value` credited before execution. Move it to refund_recipient.
                    evm.ctx()
                        .journal_mut()
                        .transfer(caller, refund_recipient, value)?;
                }

                // Mint the remaining refund directly to refund_recipient.
                let refund = mint.saturating_sub(value).saturating_sub(spent_fee);
                evm.ctx()
                    .journal_mut()
                    .balance_incr(refund_recipient, refund)?;
            }
            L1TxAccountingMode::AtlasV3 => {
                let is_success = frame_result.interpreter_result().result.is_ok();
                let fee_flow = Self::atlas_l1_fee_flow(evm.ctx().tx(), basefee, spec_id);

                let refund_from_treasury = if is_success {
                    fee_flow.prepaid_fee.saturating_sub(spent_fee)
                } else {
                    fee_flow.mint.saturating_sub(spent_fee)
                };

                if refund_from_treasury > U256::ZERO {
                    evm.ctx().journal_mut().transfer(
                        BASE_TOKEN_HOLDER_ADDRESS,
                        refund_recipient,
                        refund_from_treasury,
                    )?;
                }
            }
        };
        Ok(())
    }

    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        frame_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        let beneficiary = evm.ctx().block().beneficiary();
        let basefee = evm.ctx().block().basefee() as u128;
        let spec_id = evm.ctx().cfg().spec();
        let effective_gas_price =
            Self::effective_gas_price_for_spec(evm.ctx().tx(), basefee, spec_id);
        let reward = U256::from(frame_result.gas().used()) * U256::from(effective_gas_price);
        let l1_mode = Self::l1_tx_accounting_mode(evm.ctx().tx(), spec_id);

        if l1_mode == Some(L1TxAccountingMode::AtlasV3) {
            // AtlasV3 L1->L2 fees are paid from treasury, not minted.
            if reward > U256::ZERO {
                evm.ctx()
                    .journal_mut()
                    .transfer(BASE_TOKEN_HOLDER_ADDRESS, beneficiary, reward)?;
            }
        } else {
            // Other tx paths keep regular "mint fee to beneficiary" semantics.
            evm.ctx().journal_mut().balance_incr(beneficiary, reward)?;
        }

        Ok(())
    }

    fn execution_result(
        &mut self,
        evm: &mut Self::Evm,
        frame_result: <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        match core::mem::replace(evm.ctx().error(), Ok(())) {
            Err(ContextError::Db(e)) => return Err(e.into()),
            Err(ContextError::Custom(e)) => return Err(Self::Error::from_string(e)),
            Ok(_) => (),
        }

        let exec_result = post_execution::output(evm.ctx(), frame_result);

        evm.ctx().journal_mut().commit_tx();
        evm.ctx().local_mut().clear();
        evm.frame_stack().clear();

        Ok(exec_result)
    }
}

impl<EVM, ERROR> InspectorHandler for ZKsyncHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: InspectorEvmTr<
            Context: ZkContextTr,
            Frame = EthFrame<EthInterpreter>,
            Inspector: Inspector<<<Self as Handler>::Evm as EvmTr>::Context, EthInterpreter>,
        >,
    EVM::Context: ContextSetters,
    <EVM::Context as ContextTr>::Tx: Clone + SystemCallTx,
    <EVM::Context as ContextTr>::Journal: JournalTr<State = EvmState>,
    ERROR: EvmTrError<EVM> + From<ZKsyncTxError> + FromStringError + IsTxError,
{
    type IT = EthInterpreter;

    fn inspect_execution(
        &mut self,
        evm: &mut Self::Evm,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, Self::Error> {
        if evm.ctx().tx().force_fail() {
            return self.forced_fail_execution_result(evm);
        }

        let gas_limit = evm
            .ctx()
            .tx()
            .gas_limit()
            .saturating_sub(init_and_floor_gas.initial_gas);
        let first_frame_input = self.first_frame_input(evm, gas_limit)?;
        let mut frame_result = self.inspect_run_exec_loop(evm, first_frame_input)?;
        self.last_frame_result(evm, &mut frame_result)?;
        Ok(frame_result)
    }
}
