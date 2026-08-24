//!Handler related to ZKsync OS chain
use core::cell::Cell;
use std::boxed::Box;

use crate::{
    api::exec::ZkContextTr,
    constants::{BASE_TOKEN_HOLDER_ADDRESS, L2_ASSET_TRACKER_ADDRESS, L2_BASE_TOKEN_ADDRESS},
    l2_to_l1_logs::L2ToL1LogStore,
    spec::ZkSpecId,
    transaction::{ZKsyncTxError, ZkTxTr},
};
use revm::{
    context::{LocalContextTr, result::InvalidTransaction},
    context_interface::{
        Block, Cfg, ContextSetters, ContextTr, JournalTr, Transaction,
        context::ContextError,
        journaled_state::{JournalCheckpoint, account::JournaledAccountTr},
        result::{
            EVMError, ExecutionResult, FromStringError, HaltReason, InvalidHeader, ResultGas,
        },
        transaction::TransactionType,
    },
    handler::{
        EthFrame, EvmTr, FrameResult, Handler, MainnetHandler,
        evm::FrameTr,
        handler::EvmTrError,
        post_execution,
        pre_execution::{
            apply_auth_list, apply_eip7702_auth_list, validate_account_nonce_and_code,
        },
        system_call::SystemCallTx,
    },
    inspector::{Inspector, InspectorEvmTr, InspectorHandler},
    interpreter::{
        CallOutcome, Gas, GasTracker, InitialAndFloorGas, InstructionResult, InterpreterResult,
        interpreter::EthInterpreter, interpreter_action::FrameInit,
    },
    primitives::{
        Bytes, U256,
        eip7702::{PER_AUTH_BASE_COST, PER_EMPTY_ACCOUNT_COST},
        hardfork::SpecId,
    },
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

    fn forced_fail_execution_result(
        &mut self,
        evm: &mut EVM,
        tx_gas: &mut GasTracker,
    ) -> Result<FrameResult, ERROR>
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
            Gas::new_spent_with_reservoir(0, 0),
        );
        let mut frame_result = FrameResult::Call(CallOutcome::new(ir, 0..0));

        // Rewrite gas to match ZKsync OS semantics.
        let gas_limit = evm.ctx().tx().gas_limit();
        let gas_used = evm.ctx().tx().gas_used_override().unwrap_or(gas_limit);
        let used = gas_used.min(gas_limit);
        let unused = gas_limit - used;
        let gas = frame_result.gas_mut();
        *gas = Gas::new_spent_with_reservoir(gas_limit, 0);
        gas.erase_cost(unused);

        // Normalize as a regular top-level frame return.
        self.last_frame_result(evm, &mut frame_result, tx_gas)?;
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
            None,
        );
        if is_eip7623_disabled {
            gas.floor_gas = 0;
        }
        let gas_limit = tx.gas_limit();
        // Clamp the total intrinsic gas to the tx gas limit, letting state gas
        // keep as much of the budget as possible (regular gas absorbs the cut).
        let total = gas.initial_total_gas().min(gas_limit);
        gas.initial_state_gas = gas.initial_state_gas.min(total);
        gas.initial_regular_gas = total - gas.initial_state_gas;
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
    fn read_l1_chain_id(evm: &mut EVM) -> Result<U256, ERROR> {
        let journal = evm.ctx().journal_mut();
        // Load the account first so the storage read runs against a present journal entry.
        journal
            .load_account(L2_ASSET_TRACKER_ADDRESS)
            .map_err(|err| ERROR::from_string(format!("failed to load L2AssetTracker: {err:?}")))?;

        let value = journal
            .sload_skip_cold_load(
                L2_ASSET_TRACKER_ADDRESS,
                L2_ASSET_TRACKER_L1_CHAIN_ID_SLOT,
                false,
            )
            .map_err(|err| {
                ERROR::from_string(format!(
                    "failed to read L2AssetTracker.L1_CHAIN_ID: {err:?}"
                ))
            })?;

        Ok(value.data)
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

        let l1_chain_id = Self::read_l1_chain_id(evm)?;
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
        // Mirrors `Handler::run_system_call`: no intrinsic gas, and the
        // checkpoint that `execution` settles is opened here since
        // pre-execution is skipped.
        let init_and_floor_gas = InitialAndFloorGas::new(0, 0);
        let mut gas = handler.tx_gas(evm, &init_and_floor_gas);
        let checkpoint = evm.ctx().journal_mut().checkpoint();
        let execution_result = handler.execution(evm, checkpoint, &mut gas);
        evm.ctx().set_tx(original_tx);
        evm.ctx().local_mut().clear();
        evm.frame_stack().clear();

        let frame_result = execution_result?;
        if frame_result.is_some_and(|result| result.instruction_result().is_ok()) {
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
        let (is_l1_to_l2, spec_id) = {
            let ctx = evm.ctx();
            (ctx.tx().is_l1_to_l2_tx(), ctx.cfg().spec())
        };
        if is_l1_to_l2 {
            return Ok(());
        }

        if !spec_id.borrows_eip7702_from_prague() {
            return self.mainnet.validate_env(evm);
        }

        // revm gates type-0x04 acceptance on `SpecId >= PRAGUE`. Validate under Prague
        // so set-code txs are admitted; this differs from Cancun only by accepting
        // EIP-7702 txs, so other tx types are unaffected. Execution stays on Cancun.
        let spec = SpecId::PRAGUE;
        let ctx = evm.ctx();
        if spec.is_enabled_in(SpecId::MERGE) && ctx.block().prevrandao().is_none() {
            return Err(InvalidHeader::PrevrandaoNotSet.into());
        }
        if spec.is_enabled_in(SpecId::CANCUN) && ctx.block().blob_excess_gas_and_price().is_none() {
            return Err(InvalidHeader::ExcessBlobGasNotSet.into());
        }
        revm::handler::validation::validate_tx_env(ctx, spec).map_err(Into::into)
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

        // Mirrors the upstream default implementation. EIP-2780 is part of
        // Amsterdam and thus never active for ZK specs (they map to Osaka at most).
        let eip2780 = ctx.cfg().is_amsterdam_eip2780_enabled().then(|| {
            // Self-transfer: a `Call` whose recipient is the sender itself.
            let is_self_transfer = tx.kind().to() == Some(&tx.caller());
            revm::context_interface::cfg::gas_params::Eip2780TxInfo {
                value: tx.value(),
                is_self_transfer,
            }
        });

        // Charge the auth-list intrinsic gas (25000/auth) by metering under Prague,
        // but keep the EIP-7623 calldata floor off (not part of "Cancun + 7702").
        let (gas_spec, gas_eip7623_disabled) = if spec_id.borrows_eip7702_from_prague() {
            (SpecId::PRAGUE, true)
        } else {
            (spec_id.into_eth_spec(), is_eip7623_disabled)
        };

        let validated = revm::handler::validation::validate_initial_tx_gas(
            tx,
            gas_spec,
            gas_eip7623_disabled,
            ctx.cfg().is_amsterdam_eip8037_enabled(),
            ctx.cfg().tx_gas_limit_cap(),
            eip2780,
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

    /// Apply the EIP-7702 authorization list with the canonical refund.
    ///
    /// revm reads the per-authorization refund from the gas params of the eth
    /// spec, which are Cancun's (= 0) on a spec that borrows EIP-7702 from
    /// Prague, so the handler applies the Prague value.
    #[inline]
    fn apply_eip7702_auth_list(
        &self,
        evm: &mut Self::Evm,
        gas: &mut GasTracker,
    ) -> Result<Option<u64>, Self::Error> {
        if !evm.ctx().cfg().spec().borrows_eip7702_from_prague() {
            return apply_eip7702_auth_list(evm.ctx_mut(), gas);
        }

        let chain_id = evm.ctx().cfg().chain_id();
        let (tx, journal) = evm.ctx().tx_journal_mut();

        // Only set-code (type-0x04) txs carry an authorization list.
        if tx.tx_type() != TransactionType::Eip7702 as u8 {
            return Ok(Some(0));
        }

        let refunded_authorities =
            apply_auth_list::<_, Self::Error>(chain_id, tx.authorization_list(), journal)?;

        // EIP-8037 splits the refund into regular and state gas, and it is
        // inactive at Cancun, so the whole refund is regular gas.
        Ok(Some(
            (PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST).saturating_mul(refunded_authorities),
        ))
    }

    #[inline]
    fn post_execution(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
        init_and_floor_gas: InitialAndFloorGas,
        eip7702_gas_refund: i64,
    ) -> Result<ResultGas, Self::Error> {
        let is_success = exec_result.interpreter_result().result.is_ok();
        if let Some(checkpoint) = self.pending_value_mint_checkpoint.take() {
            if is_success {
                evm.ctx().journal_mut().checkpoint_commit();
            } else {
                evm.ctx().journal_mut().checkpoint_revert(checkpoint);
            }
        }

        let result_gas = if let Some(gas_used_override) = evm.ctx().tx().gas_used_override() {
            let gas_limit = evm.ctx().tx().gas_limit();
            // Just in case use at most `gas_limit` gas to prevent the underflow
            let used = gas_used_override.min(gas_limit);
            let unused = gas_limit - used;

            // Rewrite the Gas object to match ZKsync OS usage.
            let gas = exec_result.gas_mut();
            *gas = Gas::new_spent_with_reservoir(gas_limit, 0);
            gas.erase_cost(unused);
            // IMPORTANT: ignore EVM-native refunds: (do NOT call `gas.record_refund(...)` here)
            //    self.refund(evm, exec_result, eip7702_gas_refund);  // <-- intentionally NOT called

            let result_gas = post_execution::build_result_gas(
                exec_result.instruction_result().is_halt(),
                exec_result.gas(),
                init_and_floor_gas,
            );

            // Reimburse sender and reward beneficiary using the rewritten Gas.
            if ZkSpecId::AtlasV3.is_enabled_in(evm.ctx().cfg().spec()) {
                self.notify_l2_asset_tracker(evm, exec_result)?;
            }
            self.reimburse_caller(evm, exec_result)?;
            self.reward_beneficiary(evm, exec_result)?;
            result_gas
        } else {
            // Vanilla path: keep default EVM accounting
            if ZkSpecId::AtlasV3.is_enabled_in(evm.ctx().cfg().spec()) {
                self.notify_l2_asset_tracker(evm, exec_result)?;
            }
            self.refund(evm, exec_result, eip7702_gas_refund)?;
            let result_gas = post_execution::build_result_gas(
                exec_result.instruction_result().is_halt(),
                exec_result.gas(),
                init_and_floor_gas,
            );
            self.eip7623_check_gas_floor(evm, exec_result, init_and_floor_gas);
            self.reimburse_caller(evm, exec_result)?;
            self.reward_beneficiary(evm, exec_result)?;
            result_gas
        };

        // Emit the bootloader result L2→L1 log for L1→L2 transactions.
        // In zksync-os this is done by the bootloader after each L1→L2 tx,
        // after the operator fee and the refund. L2→L1 logs feed a rolling hash
        // and the message tree, so the position of this log is part of the
        // protocol.
        // From AtlasV3 (ZKsync OS v0.3.x) on, only priority operations emit the
        // result log "by protocol convention"
        // (basic_bootloader .../zk/process_l1_transaction.rs). Earlier versions
        // emit it for priority operations and upgrade transactions alike.
        let emit_result_log = if ZkSpecId::AtlasV3.is_enabled_in(evm.ctx().cfg().spec()) {
            evm.ctx().tx().tx_type()
                == crate::transaction::priority_tx::L1_PRIORITY_TRANSACTION_TYPE
        } else {
            evm.ctx().tx().is_l1_to_l2_tx()
        };
        if emit_result_log {
            let tx_hash = evm.ctx().tx().tx_hash();
            evm.ctx()
                .journal_mut()
                .emit_l1_tx_result(tx_hash, is_success);
        }

        Ok(result_gas)
    }

    fn execution(
        &mut self,
        evm: &mut Self::Evm,
        checkpoint: JournalCheckpoint,
        gas: &mut GasTracker,
    ) -> Result<Option<FrameResult>, Self::Error> {
        if evm.ctx().tx().force_fail() {
            // The forced failure skips the first frame entirely; keep the
            // pre-execution state changes as a successful frame init would.
            evm.ctx().journal_mut().checkpoint_commit();
            return Ok(Some(self.forced_fail_execution_result(evm, gas)?));
        }

        let Some(first_frame_input) = self.first_frame_input(evm, gas)? else {
            revm::handler::execution::runtime_oog_unwind(evm.ctx(), checkpoint)?;
            return Ok(None);
        };
        // The runtime gas phase is complete: commit its state changes.
        evm.ctx().journal_mut().checkpoint_commit();

        let mut frame_result = self.run_exec_loop(evm, first_frame_input)?;
        self.last_frame_result(evm, &mut frame_result, gas)?;
        Ok(Some(frame_result))
    }

    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
        _init_and_floor_gas: &mut InitialAndFloorGas,
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
                        // Match zkOS semantics: the upfront asset-tracker notification and
                        // treasury transfer form one atomic value-mint step. They must either
                        // both persist or both roll back together.
                        let checkpoint = journal.checkpoint();
                        self.pending_value_mint_checkpoint.set(Some(checkpoint));

                        let result = (|| -> Result<(), Self::Error> {
                            let l1_chain_id = Self::read_l1_chain_id(evm)?;
                            self.execute_asset_tracker_call(
                                evm,
                                l1_chain_id,
                                fee_flow.upfront_transfer,
                            )?;

                            let (tx, journal) = evm.ctx().tx_journal_mut();
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
        let gas_used = frame_result
            .gas()
            .used()
            .saturating_sub(frame_result.gas().reservoir());
        let spent_fee = U256::from(gas_used) * U256::from(effective_gas_price);

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
        let l1_mode = Self::l1_tx_accounting_mode(evm.ctx().tx(), spec_id);
        let gas_used = frame_result
            .gas()
            .used()
            .saturating_sub(frame_result.gas().reservoir());
        let reward = U256::from(gas_used) * U256::from(effective_gas_price);

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
        result_gas: ResultGas,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        match core::mem::replace(evm.ctx().error(), Ok(())) {
            Err(ContextError::Db(e)) => return Err(e.into()),
            Err(ContextError::Custom(e)) => return Err(Self::Error::from_string(e)),
            Ok(_) => (),
        }

        let exec_result = post_execution::output(evm.ctx(), frame_result, result_gas);

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
        checkpoint: JournalCheckpoint,
        gas: &mut GasTracker,
    ) -> Result<Option<FrameResult>, Self::Error> {
        if evm.ctx().tx().force_fail() {
            // The forced failure skips the first frame entirely; keep the
            // pre-execution state changes as a successful frame init would.
            evm.ctx().journal_mut().checkpoint_commit();
            return Ok(Some(self.forced_fail_execution_result(evm, gas)?));
        }

        let Some(first_frame_input) = self.first_frame_input(evm, gas)? else {
            revm::handler::execution::runtime_oog_unwind(evm.ctx(), checkpoint)?;
            return Ok(None);
        };
        // The runtime gas phase is complete: commit its state changes.
        evm.ctx().journal_mut().checkpoint_commit();

        let mut frame_result = self.inspect_run_exec_loop(evm, first_frame_input)?;
        self.last_frame_result(evm, &mut frame_result, gas)?;
        Ok(Some(frame_result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::builder::ZkBuilder;
    use crate::api::default_ctx::zk_context;
    use crate::api::exec::ZkError;
    use crate::precompiles::v1::l1_messenger::L1_MESSENGER_ADDRESS;
    use crate::precompiles::v3::l1_messenger::L1_MESSENGER_HOOK_ADDRESS;
    use crate::transaction::priority_tx::L1_PRIORITY_TRANSACTION_TYPE;
    use crate::{ZKsyncTx, ZkContext, ZkSpecId};
    use revm::{
        ExecuteEvm,
        context::TxEnv,
        context_interface::{
            either::Either,
            result::ExecResultAndState,
            transaction::{Authorization, RecoveredAuthority, RecoveredAuthorization},
        },
        database::{CacheDB, EmptyDB},
        primitives::{Address, B256, TxKind, address},
        state::{AccountInfo, Bytecode},
    };

    const CALLER: Address = address!("0000000000000000000000000000000000000c0f");
    const TARGET: Address = address!("0000000000000000000000000000000000001111");
    const REFUND_RECIPIENT: Address = address!("0000000000000000000000000000000000002222");
    const AUTHORITY: Address = address!("0000000000000000000000000000000000003333");
    const MESSAGE: [u8; 32] = [0xaa; 32];
    const TX_GAS_LIMIT: u64 = 1_000_000;
    const TX_GAS_PRICE: u128 = 1;

    const OP_STOP: u8 = 0x00;
    const OP_POP: u8 = 0x50;
    const OP_MSTORE: u8 = 0x52;
    const OP_GAS: u8 = 0x5a;
    const OP_PUSH1: u8 = 0x60;
    const OP_PUSH20: u8 = 0x73;
    const OP_PUSH32: u8 = 0x7f;
    const OP_CALL: u8 = 0xf1;

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

    /// Code of the L1 messenger contract: send [`MESSAGE`] to L1 through the hook.
    fn message_sender_code() -> Bytes {
        // The hook takes abi.encodePacked(address sender, bytes message).
        let mut sender = [0u8; 32];
        sender[..20].copy_from_slice(L1_MESSENGER_ADDRESS.as_slice());
        let mut code = store_code(0, sender);
        code.extend(store_code(20, MESSAGE));
        code.extend(call_code(L1_MESSENGER_HOOK_ADDRESS, 52));
        code.push(OP_STOP);
        code.into()
    }

    /// Code of the L2 asset tracker: send one message to L1 on every notification.
    fn asset_tracker_code() -> Bytes {
        let mut code = call_code(L1_MESSENGER_ADDRESS, 0);
        code.push(OP_STOP);
        code.into()
    }

    /// Run one L1 priority transaction and return the L2→L1 logs it produces.
    ///
    /// The asset tracker sends a message to L1 on every fee and refund
    /// notification, which makes the position of the result log observable.
    fn run_priority_transaction(tx_hash: B256) -> Vec<crate::l2_to_l1_logs::L2ToL1Log> {
        let mut database = CacheDB::new(EmptyDB::default());
        database.insert_account_info(
            BASE_TOKEN_HOLDER_ADDRESS,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
        database.insert_account_info(
            L1_MESSENGER_ADDRESS,
            AccountInfo {
                code: Some(Bytecode::new_raw(message_sender_code())),
                ..Default::default()
            },
        );
        database.insert_account_info(
            L2_ASSET_TRACKER_ADDRESS,
            AccountInfo {
                code: Some(Bytecode::new_raw(asset_tracker_code())),
                ..Default::default()
            },
        );

        let mut evm = zk_context(database, ZkSpecId::AtlasV3).build_zk();
        evm.0.ctx.journaled_state.set_tx_number(0);
        // The mint equals the prepaid fee, so there is no upfront transfer.
        let mint = U256::from(TX_GAS_LIMIT) * U256::from(TX_GAS_PRICE);
        let transaction = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .tx_type(Some(L1_PRIORITY_TRANSACTION_TYPE))
                    .caller(CALLER)
                    .kind(TxKind::Call(TARGET))
                    .gas_limit(TX_GAS_LIMIT)
                    .gas_price(TX_GAS_PRICE),
            )
            .mint(mint)
            .refund_recipient(Some(REFUND_RECIPIENT))
            .tx_hash(tx_hash)
            .build_fill()
            .expect("transaction builds");
        evm.transact(transaction).expect("transaction runs");
        evm.0.ctx.journaled_state.take_l2_to_l1_logs()
    }

    #[test]
    fn l1_result_log_follows_the_fee_and_refund_logs() {
        let tx_hash = B256::from([0x11; 32]);

        let logs = run_priority_transaction(tx_hash);

        let (result_log, fee_logs) = logs.split_last().expect("the transaction emits logs");
        assert_eq!(result_log.key, tx_hash);
        assert!(
            !fee_logs.is_empty(),
            "the fee and refund steps must emit a log"
        );
        assert!(
            fee_logs
                .iter()
                .all(|log| log.sender == L1_MESSENGER_ADDRESS)
        );
    }

    /// Whether the authority of the authorization holds a state entry.
    #[derive(Clone, Copy, Debug)]
    enum Authority {
        InState,
        Absent,
    }

    /// Run one set-code (type-0x04) transaction that delegates [`AUTHORITY`] to
    /// [`TARGET`], with `calldata_length` non-zero calldata bytes, and report
    /// the outcome.
    fn run_set_code_transaction(
        spec: ZkSpecId,
        authority: Authority,
        calldata_length: usize,
    ) -> Result<ExecResultAndState<ExecutionResult>, ZkError<ZkContext<CacheDB<EmptyDB>>>> {
        let mut database = CacheDB::new(EmptyDB::default());
        database.insert_account_info(
            CALLER,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
        if let Authority::InState = authority {
            database.insert_account_info(
                AUTHORITY,
                AccountInfo {
                    balance: U256::from(1u64),
                    ..Default::default()
                },
            );
        }

        let authorization = RecoveredAuthorization::new_unchecked(
            Authorization {
                // A zero chain id authorizes the delegation on every chain.
                chain_id: U256::ZERO,
                address: TARGET,
                nonce: 0,
            },
            RecoveredAuthority::Valid(AUTHORITY),
        );

        let mut evm = zk_context(database, spec).build_zk();
        let transaction = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(TARGET))
                    .gas_limit(TX_GAS_LIMIT)
                    .gas_price(TX_GAS_PRICE)
                    .data(Bytes::from(vec![0x01u8; calldata_length]))
                    .authorization_list(vec![Either::Right(authorization)]),
            )
            .tx_hash(B256::from([0x33; 32]))
            .build_fill()
            .expect("transaction builds");
        assert_eq!(
            transaction.tx_type(),
            TransactionType::Eip7702 as u8,
            "the authorization list must make this a set-code transaction"
        );
        evm.transact(transaction)
    }

    #[test]
    fn set_code_transaction_is_rejected_before_the_supporting_spec() {
        for spec in [ZkSpecId::AtlasV1, ZkSpecId::AtlasV2] {
            let error = run_set_code_transaction(spec, Authority::InState, 0)
                .expect_err("the spec does not support EIP-7702");

            assert!(
                matches!(
                    error,
                    EVMError::Transaction(ZKsyncTxError::Base(
                        InvalidTransaction::Eip7702NotSupported
                    ))
                ),
                "{spec:?}: {error:?}"
            );
        }
    }

    #[test]
    fn set_code_transaction_delegates_the_authority() {
        for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4] {
            let outcome = run_set_code_transaction(spec, Authority::InState, 0)
                .expect("the transaction runs");

            let authority = outcome
                .state
                .get(&AUTHORITY)
                .expect("the authorization touches the authority");
            let code = authority
                .info
                .code
                .as_ref()
                .expect("the authority holds code");
            assert_eq!(code.eip7702_address(), Some(TARGET), "{spec:?}");
        }
    }

    #[test]
    fn set_code_transaction_takes_the_prague_gas_rules() {
        // The Cancun gas parameters price an authorization at zero. Under
        // Prague each authorization costs 25000 on top of the 21000 base, and
        // an authority that holds a state entry refunds 12500 of it. The
        // refund is capped at one fifth of the gas spent.
        const INTRINSIC_GAS: u64 = 21_000 + PER_EMPTY_ACCOUNT_COST;
        const CAPPED_REFUND: u64 = INTRINSIC_GAS / 5;

        for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4] {
            let with_refund = run_set_code_transaction(spec, Authority::InState, 0)
                .expect("the transaction runs");
            let without_refund =
                run_set_code_transaction(spec, Authority::Absent, 0).expect("the transaction runs");

            assert_eq!(
                with_refund.result.tx_gas_used(),
                INTRINSIC_GAS - CAPPED_REFUND,
                "{spec:?}"
            );
            assert_eq!(
                without_refund.result.tx_gas_used(),
                INTRINSIC_GAS,
                "{spec:?}"
            );
        }
    }

    #[test]
    fn set_code_transaction_holds_the_eip7623_floor_off_on_a_cancun_spec() {
        // Enough non-zero calldata to raise the EIP-7623 floor above the
        // intrinsic cost: the floor charges 10 gas per token where the
        // intrinsic charges 4, and a non-zero byte is 4 tokens.
        const CALLDATA_LENGTH: usize = 1_200;
        const CALLDATA_TOKENS: u64 = 4 * CALLDATA_LENGTH as u64;
        const INTRINSIC_GAS: u64 = 21_000 + PER_EMPTY_ACCOUNT_COST + 4 * CALLDATA_TOKENS;
        const FLOOR_GAS: u64 = 21_000 + 10 * CALLDATA_TOKENS;
        // The calldata must be long enough for the floor to bind.
        const _: () = assert!(FLOOR_GAS > INTRINSIC_GAS);

        let on_cancun =
            run_set_code_transaction(ZkSpecId::AtlasV3, Authority::InState, CALLDATA_LENGTH)
                .expect("the transaction runs");
        let on_osaka =
            run_set_code_transaction(ZkSpecId::AtlasV4, Authority::InState, CALLDATA_LENGTH)
                .expect("the transaction runs");

        // The Cancun eth spec predates EIP-7623, so the floor stays off and the
        // authorization refund lands in full.
        assert_eq!(
            on_cancun.result.tx_gas_used(),
            INTRINSIC_GAS - (PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST)
        );
        // The Osaka eth spec carries EIP-7623, so revm raises the gas spent to
        // the floor.
        assert_eq!(on_osaka.result.tx_gas_used(), FLOOR_GAS);
    }
}
