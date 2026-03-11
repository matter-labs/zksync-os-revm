//!Handler related to ZKsync OS chain
use std::boxed::Box;

use crate::{
    api::exec::ZkContextTr,
    spec::ZkSpecId,
    transaction::{ZKsyncTxError, ZkTxTr},
};
use revm::{
    context::{LocalContextTr, result::InvalidTransaction},
    context_interface::{
        Block, Cfg, ContextTr, JournalTr, Transaction,
        context::ContextError,
        journaled_state::account::JournaledAccountTr,
        result::{EVMError, ExecutionResult, FromStringError, HaltReason},
        transaction::TransactionType,
    },
    handler::{
        EthFrame, EvmTr, FrameResult, Handler, MainnetHandler, evm::FrameTr, handler::EvmTrError,
        post_execution, pre_execution::validate_account_nonce_and_code,
    },
    inspector::{Inspector, InspectorEvmTr, InspectorHandler},
    interpreter::{
        CallOutcome, Gas, InitialAndFloorGas, InstructionResult, InterpreterResult,
        interpreter::EthInterpreter, interpreter_action::FrameInit,
    },
    primitives::{Address, U256, address},
};

pub const BASE_TOKEN_HOLDER_ADDRESS: Address = address!("0000000000000000000000000000000000010011");

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
}

impl<EVM, ERROR, FRAME> ZKsyncHandler<EVM, ERROR, FRAME> {
    /// Create a new ZKsync OS handler.
    pub fn new() -> Self {
        Self {
            mainnet: MainnetHandler::default(),
            _phantom: core::marker::PhantomData,
        }
    }

    fn forced_fail_execution_result(&mut self, evm: &mut EVM) -> Result<FrameResult, ERROR>
    where
        EVM: EvmTr<Context: ZkContextTr, Frame = FRAME>,
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
    fn effective_gas_price_for_spec<TX: Transaction>(
        tx: &TX,
        base_fee: u128,
        spec_id: ZkSpecId,
    ) -> u128 {
        if ZkSpecId::AtlasV3.is_enabled_in(spec_id) && base_fee == 0 {
            0
        } else {
            tx.effective_gas_price(base_fee)
        }
    }

    #[inline]
    fn effective_balance_spending_for_spec<TX: Transaction>(
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
    EVM: EvmTr<Context: ZkContextTr, Frame = FRAME>,
    ERROR: EvmTrError<EVM> + From<ZKsyncTxError> + FromStringError + IsTxError,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    fn validate_env(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        // Do not perform any additional validation for L1 -> L2 transactions, they are pre-verified on Settlement Layer.
        let ctx = evm.ctx();
        let tx = ctx.tx();
        if tx.is_l1_to_l2_tx() {
            return Ok(());
        }

        // Do not perform any extra validation for L1 -> L2 transactions, they are pre-verified on L1.
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
            self.reimburse_caller(evm, exec_result)?;
            self.reward_beneficiary(evm, exec_result)?;
        } else {
            // Vanilla path: keep default EVM accounting
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
                        journal.transfer(
                            BASE_TOKEN_HOLDER_ADDRESS,
                            tx.caller(),
                            fee_flow.upfront_transfer,
                        )?;
                    }
                    return Ok(());
                }
            }
        }

        let mut caller_account = journal.load_account_with_code_mut(tx.caller())?.data;
        let is_service_tx = tx.is_service_tx();

        if !is_service_tx {
            // validates account nonce and code
            validate_account_nonce_and_code(
                &caller_account.account().info,
                tx.nonce(),
                is_eip3607_disabled,
                is_nonce_check_disabled,
            )?;
        }

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
        if tx.kind().is_call() && !is_service_tx {
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
            let refund = U256::from(effective_gas_price.saturating_mul(
                (frame_result.gas().remaining() + frame_result.gas().refunded() as u64) as u128,
            ));
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

                if !is_success && fee_flow.upfront_transfer > U256::ZERO {
                    // Upfront transfer happens outside EVM frame rollback in REVM.
                    // Compensate it on revert to match bootloader behavior.
                    evm.ctx().journal_mut().transfer(
                        caller,
                        refund_recipient,
                        fee_flow.upfront_transfer,
                    )?;
                }

                let refund_from_treasury = if is_success {
                    fee_flow.prepaid_fee.saturating_sub(spent_fee)
                } else {
                    fee_flow
                        .mint
                        .saturating_sub(spent_fee)
                        .saturating_sub(fee_flow.upfront_transfer)
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
