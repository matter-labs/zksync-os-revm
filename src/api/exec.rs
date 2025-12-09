//! Implementation of the [`ExecuteEvm`] trait for the [`ZKsyncEvm`].
use crate::{ZKsyncTxError, ZkSpecId, evm::ZKsyncEvm, handler::ZKsyncHandler, transaction::ZkTxTr};
use revm::{
    DatabaseCommit, ExecuteCommitEvm, ExecuteEvm,
    context::{ContextSetters, result::ExecResultAndState},
    context_interface::{
        Cfg, ContextTr, Database, JournalTr,
        result::{EVMError, ExecutionResult, HaltReason},
    },
    handler::{
        EthFrame, Handler, PrecompileProvider, SystemCallTx, instructions::EthInstructions,
        system_call::SystemCallEvm,
    },
    inspector::{
        InspectCommitEvm, InspectEvm, InspectSystemCallEvm, Inspector, InspectorHandler, JournalExt,
    },
    interpreter::{InterpreterResult, interpreter::EthInterpreter},
    primitives::{Address, Bytes},
    state::EvmState,
};

/// Type alias for ZKsync OS context
pub trait ZkContextTr:
    ContextTr<Journal: JournalTr<State = EvmState>, Tx: ZkTxTr, Cfg: Cfg<Spec = ZkSpecId>>
{
}

impl<T> ZkContextTr for T where
    T: ContextTr<Journal: JournalTr<State = EvmState>, Tx: ZkTxTr, Cfg: Cfg<Spec = ZkSpecId>>
{
}

/// Type alias for the error type of the ZKsyncEvm.
pub type ZkError<CTX> = EVMError<<<CTX as ContextTr>::Db as Database>::Error, ZKsyncTxError>;

impl<CTX, INSP, PRECOMPILE> ExecuteEvm
    for ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, PRECOMPILE>
where
    CTX: ZkContextTr + ContextSetters,
    PRECOMPILE: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    type Tx = <CTX as ContextTr>::Tx;
    type Block = <CTX as ContextTr>::Block;
    type State = EvmState;
    type Error = ZkError<CTX>;
    type ExecutionResult = ExecutionResult<HaltReason>;

    fn set_block(&mut self, block: Self::Block) {
        self.0.ctx.set_block(block);
    }

    fn transact_one(&mut self, tx: Self::Tx) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.ctx.set_tx(tx);
        let mut h = ZKsyncHandler::<_, _, EthFrame<EthInterpreter>>::new();
        h.run(self)
    }

    fn finalize(&mut self) -> Self::State {
        self.0.ctx.journal_mut().finalize()
    }

    fn replay(
        &mut self,
    ) -> Result<ExecResultAndState<Self::ExecutionResult, Self::State>, Self::Error> {
        let mut h = ZKsyncHandler::<_, _, EthFrame<EthInterpreter>>::new();
        h.run(self).map(|result| {
            let state = self.finalize();
            ExecResultAndState::new(result, state)
        })
    }
}

impl<CTX, INSP, PRECOMPILE> ExecuteCommitEvm
    for ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, PRECOMPILE>
where
    CTX: ZkContextTr<Db: DatabaseCommit> + ContextSetters,
    PRECOMPILE: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    fn commit(&mut self, state: Self::State) {
        self.0.ctx.db_mut().commit(state);
    }
}

impl<CTX, INSP, PRECOMPILE> InspectEvm
    for ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, PRECOMPILE>
where
    CTX: ZkContextTr<Journal: JournalExt> + ContextSetters,
    INSP: Inspector<CTX, EthInterpreter>,
    PRECOMPILE: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    type Inspector = INSP;

    fn set_inspector(&mut self, inspector: Self::Inspector) {
        self.0.inspector = inspector;
    }

    fn inspect_one_tx(&mut self, tx: Self::Tx) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.ctx.set_tx(tx);
        let mut h = ZKsyncHandler::<_, _, EthFrame<EthInterpreter>>::new();
        h.inspect_run(self)
    }
}

impl<CTX, INSP, PRECOMPILE> InspectCommitEvm
    for ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, PRECOMPILE>
where
    CTX: ZkContextTr<Journal: JournalExt, Db: DatabaseCommit> + ContextSetters,
    INSP: Inspector<CTX, EthInterpreter>,
    PRECOMPILE: PrecompileProvider<CTX, Output = InterpreterResult>,
{
}

impl<CTX, INSP, PRECOMPILE> SystemCallEvm
    for ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, PRECOMPILE>
where
    CTX: ZkContextTr<Tx: SystemCallTx> + ContextSetters,
    PRECOMPILE: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    fn system_call_one_with_caller(
        &mut self,
        caller: Address,
        system_contract_address: Address,
        data: Bytes,
    ) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.ctx.set_tx(CTX::Tx::new_system_tx_with_caller(
            caller,
            system_contract_address,
            data,
        ));
        let mut h = ZKsyncHandler::<_, _, EthFrame<EthInterpreter>>::new();
        h.run_system_call(self)
    }
}

impl<CTX, INSP, PRECOMPILE> InspectSystemCallEvm
    for ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, PRECOMPILE>
where
    CTX: ZkContextTr<Journal: JournalExt, Tx: SystemCallTx> + ContextSetters,
    INSP: Inspector<CTX, EthInterpreter>,
    PRECOMPILE: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    fn inspect_one_system_call_with_caller(
        &mut self,
        caller: Address,
        system_contract_address: Address,
        data: Bytes,
    ) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.ctx.set_tx(CTX::Tx::new_system_tx_with_caller(
            caller,
            system_contract_address,
            data,
        ));
        let mut h = ZKsyncHandler::<_, _, EthFrame<EthInterpreter>>::new();
        h.inspect_run_system_call(self)
    }
}
