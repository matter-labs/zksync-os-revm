//!Handler related to ZKsync OS chain
use std::boxed::Box;

use crate::{
    api::exec::ZkContextTr,
    transaction::{ZKsyncTxError, ZkTxTr},
};
use revm::{
    context::{LocalContextTr, result::InvalidTransaction},
    context_interface::{
        Block, Cfg, ContextTr, JournalTr, Transaction,
        context::ContextError,
        result::{EVMError, ExecutionResult, FromStringError, HaltReason},
    },
    handler::{
        EthFrame, EvmTr, FrameResult, Handler, MainnetHandler,
        evm::FrameTr,
        handler::EvmTrError,
        post_execution::{self, reimburse_caller},
        pre_execution::validate_account_nonce_and_code,
    },
    inspector::{Inspector, InspectorEvmTr, InspectorHandler},
    interpreter::{
        CallOutcome, Gas, InitialAndFloorGas, InstructionResult, InterpreterResult,
        interpreter::EthInterpreter, interpreter_action::FrameInit,
    },
    primitives::U256,
};

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

    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<(), Self::Error> {
        let ctx = evm.ctx();

        let basefee = ctx.block().basefee() as u128;
        let blob_price = ctx.block().blob_gasprice().unwrap_or_default();
        let is_l1_to_l2_tx = ctx.tx().is_l1_to_l2_tx();
        let is_eip3607_disabled = ctx.cfg().is_eip3607_disabled();
        let is_nonce_check_disabled = ctx.cfg().is_nonce_check_disabled();

        let mint = ctx.tx().mint().unwrap_or_default();

        let (tx, journal) = ctx.tx_journal_mut();

        let caller_account = journal.load_account_code(tx.caller())?.data;

        if !is_l1_to_l2_tx {
            // validates account nonce and code
            validate_account_nonce_and_code(
                &mut caller_account.info,
                tx.nonce(),
                is_eip3607_disabled,
                is_nonce_check_disabled,
            )?;
        }

        // old balance is journaled before mint is incremented.
        let old_balance = caller_account.info.balance;

        let mut new_balance = caller_account.info.balance.saturating_add(U256::from(mint));

        let max_balance_spending = tx.max_balance_spending()?;

        if !is_l1_to_l2_tx && max_balance_spending > new_balance {
            // skip max balance check for deposit transactions.
            // this check for deposit was skipped previously in `validate_tx_against_state` function
            return Err(InvalidTransaction::LackOfFundForMaxFee {
                fee: Box::new(max_balance_spending),
                balance: Box::new(new_balance),
            }
            .into());
        }

        let effective_balance_spending = tx
            .effective_balance_spending(basefee, blob_price)
            .expect("effective balance is always smaller than max balance so it can't overflow");

        // subtracting max balance spending with value that is going to be deducted later in the call.
        let gas_balance_spending = effective_balance_spending - tx.value();

        new_balance = new_balance.saturating_sub(gas_balance_spending);

        // Touch account so we know it is changed.
        caller_account.mark_touch();
        caller_account.info.balance = new_balance;

        // Bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
        if !is_l1_to_l2_tx && tx.kind().is_call() {
            caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
        }

        // NOTE: all changes to the caller account should journaled so in case of error
        // we can revert the changes.
        journal.caller_accounting_journal_entry(tx.caller(), old_balance, tx.kind().is_call());

        Ok(())
    }

    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        frame_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        reimburse_caller(evm.ctx(), frame_result.gas(), U256::ZERO)?;

        let is_l1_to_l2_tx = evm.ctx().tx().is_l1_to_l2_tx();
        if is_l1_to_l2_tx {
            let caller = evm.ctx().tx().caller();
            let refund_recipient = evm
                .ctx()
                .tx()
                .refund_recipient()
                .expect("Refund recipient is missing for L1 -> L2 tx");

            let basefee = evm.ctx().block().basefee() as u128;
            let effective_gas_price = evm.ctx().tx().effective_gas_price(basefee);
            let spent_fee =
                U256::from(frame_result.gas().spent()) * U256::from(effective_gas_price);
            let mint = evm.ctx().tx().mint().unwrap_or_default();
            let value = evm.ctx().tx().value();

            // Did the call succeed?
            let is_success = frame_result.interpreter_result().result.is_ok();

            let additional_refund = if is_success {
                mint - value - spent_fee
            } else {
                mint - spent_fee
            };

            // // Return balance of not spend gas.
            evm.ctx()
                .journal_mut()
                .transfer(caller, refund_recipient, additional_refund)?;
        }
        Ok(())
    }

    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        frame_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        let beneficiary = evm.ctx().block().beneficiary();
        let basefee = evm.ctx().block().basefee() as u128;
        let effective_gas_price = evm.ctx().tx().effective_gas_price(basefee);

        // reward beneficiary
        evm.ctx().journal_mut().balance_incr(
            beneficiary,
            U256::from(effective_gas_price * frame_result.gas().used() as u128),
        )?;

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

    fn run_without_catch_error(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        let init_and_floor_gas = self.validate(evm)?;
        let eip7702_refund = self.pre_execution(evm)? as i64;

        // === forced-fail short-circuit ===
        let mut exec_result = if evm.ctx().tx().force_fail() {
            let (tx, journal) = evm.ctx().tx_journal_mut();
            let caller_account = journal.load_account_code(tx.caller())?.data;
            if tx.kind().is_create() {
                // Bump the nonce for creates, because usually it is handled in `handle_create`.
                // And force faillure doesn't call the actual execution.
                caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
            }
            // Synthesize a top-level REVERT frame result (no state changes).
            // 1) Make an InterpreterResult with REVERT + returndata.
            let ir = InterpreterResult::new(
                InstructionResult::Revert,
                Default::default(),
                Gas::new_spent(0),
            );
            // 2) Wrap it as a CallOutcome; memory range is irrelevant here.
            let mut fr = FrameResult::Call(CallOutcome::new(ir, 0..0));

            let gas_limit = evm.ctx().tx().gas_limit();
            let gas_used = evm.ctx().tx().gas_used_override().unwrap_or(gas_limit);

            // 3) Set gas to match your ZK usage now (limit – unused).
            let used = gas_used.min(gas_limit);
            let unused = gas_limit - used;
            let gas = fr.gas_mut();
            *gas = Gas::new_spent(gas_limit);
            gas.erase_cost(unused);

            // Ensure gas object is initialized the same way a normal top-level return would do.
            // last_frame_result() sets `Gas::new_spent(gas_limit)` and handles "remaining" & refund flags.
            self.last_frame_result(evm, &mut fr)?;

            fr
        } else {
            self.execution(evm, &init_and_floor_gas)?
        };

        self.post_execution(evm, &mut exec_result, init_and_floor_gas, eip7702_refund)?;
        self.execution_result(evm, exec_result)
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
}
