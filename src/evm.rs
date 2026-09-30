//! Contains the `[ZKsyncEvm]` type and its implementation of the execution EVM traits.
use crate::{
    ZkSpecId,
    precompiles::ZKsyncPrecompiles,
    transaction::{ZkTxTr, effective_gas_price_for_spec},
};
use revm::{
    Database, Inspector,
    bytecode::opcode::GASPRICE,
    context::{Cfg, ContextError, ContextSetters, Evm, FrameStack},
    context_interface::{Block, ContextTr},
    handler::{
        EthFrame, EvmTr, FrameInitOrResult, ItemOrResult, PrecompileProvider,
        evm::FrameTr,
        instructions::{EthInstructions, InstructionProvider},
    },
    inspector::{InspectorEvmTr, JournalExt},
    interpreter::{
        Instruction, InstructionContext, InstructionExecResult, InstructionResult,
        InterpreterResult, interpreter::EthInterpreter,
    },
    primitives::U256,
};

/// ZKsync OS EVM extends the [`Evm`] type with specific types and logic.
#[derive(Debug, Clone)]
pub struct ZKsyncEvm<
    CTX,
    INSP,
    I = EthInstructions<EthInterpreter, CTX>,
    P = ZKsyncPrecompiles,
    F = EthFrame<EthInterpreter>,
>(
    /// Inner EVM type.
    pub Evm<CTX, INSP, I, P, F>,
);

impl<CTX: ContextTr<Tx: ZkTxTr, Cfg: Cfg<Spec = ZkSpecId>>, INSP>
    ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, ZKsyncPrecompiles>
{
    /// Create a new ZKsync OS EVM.
    pub fn new(ctx: CTX, inspector: INSP) -> Self {
        let spec = ctx.cfg().spec().into();
        let mut instruction = EthInstructions::new_mainnet_with_spec(spec);
        // Keep REVM's gas table, but use the same price as ZKsync fee accounting.
        instruction.instruction_table_mut()[GASPRICE as usize] = Instruction::new(gasprice::<CTX>);
        Self(Evm {
            precompiles: ZKsyncPrecompiles::new_with_spec(ctx.cfg().spec()),
            ctx,
            inspector,
            instruction,
            frame_stack: FrameStack::new(),
        })
    }
}

fn gasprice<CTX: ContextTr<Tx: ZkTxTr, Cfg: Cfg<Spec = ZkSpecId>>>(
    context: InstructionContext<'_, CTX, EthInterpreter>,
) -> InstructionExecResult {
    let price = effective_gas_price_for_spec(
        context.host.tx(),
        context.host.block().basefee() as u128,
        context.host.cfg().spec(),
    );
    if !context.interpreter.stack.push(U256::from(price)) {
        return Err(InstructionResult::StackOverflow);
    }
    Ok(())
}

impl<CTX, INSP, I, P> ZKsyncEvm<CTX, INSP, I, P> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> ZKsyncEvm<CTX, OINSP, I, P> {
        ZKsyncEvm(self.0.with_inspector(inspector))
    }

    /// Consumes self and returns a new Evm type with given Precompiles.
    pub fn with_precompiles<OP>(self, precompiles: OP) -> ZKsyncEvm<CTX, INSP, I, OP> {
        ZKsyncEvm(self.0.with_precompiles(precompiles))
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> INSP {
        self.0.into_inspector()
    }
}

impl<CTX, INSP, I, P> InspectorEvmTr for ZKsyncEvm<CTX, INSP, I, P>
where
    CTX: ContextTr<Journal: JournalExt> + ContextSetters,
    I: InstructionProvider<Context = CTX, InterpreterTypes = EthInterpreter>,
    P: PrecompileProvider<CTX, Output = InterpreterResult>,
    INSP: Inspector<CTX, I::InterpreterTypes>,
{
    type Inspector = INSP;

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.0.all_inspector()
    }

    fn all_mut_inspector(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
        &mut Self::Inspector,
    ) {
        self.0.all_mut_inspector()
    }

    fn inspector(&mut self) -> &mut Self::Inspector {
        &mut self.0.inspector
    }

    fn ctx_inspector(&mut self) -> (&mut Self::Context, &mut Self::Inspector) {
        (&mut self.0.ctx, &mut self.0.inspector)
    }

    fn ctx_inspector_frame(
        &mut self,
    ) -> (&mut Self::Context, &mut Self::Inspector, &mut Self::Frame) {
        (
            &mut self.0.ctx,
            &mut self.0.inspector,
            self.0.frame_stack.get(),
        )
    }

    fn ctx_inspector_frame_instructions(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Inspector,
        &mut Self::Frame,
        &mut Self::Instructions,
    ) {
        (
            &mut self.0.ctx,
            &mut self.0.inspector,
            self.0.frame_stack.get(),
            &mut self.0.instruction,
        )
    }
}

impl<CTX, INSP, I, P> EvmTr for ZKsyncEvm<CTX, INSP, I, P, EthFrame<EthInterpreter>>
where
    CTX: ContextTr,
    I: InstructionProvider<Context = CTX, InterpreterTypes = EthInterpreter>,
    P: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    type Context = CTX;
    type Instructions = I;
    type Precompiles = P;
    type Frame = EthFrame<EthInterpreter>;

    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.0.all()
    }

    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.0.all_mut()
    }

    fn ctx(&mut self) -> &mut Self::Context {
        &mut self.0.ctx
    }

    fn ctx_ref(&self) -> &Self::Context {
        &self.0.ctx
    }

    fn ctx_instructions(&mut self) -> (&mut Self::Context, &mut Self::Instructions) {
        (&mut self.0.ctx, &mut self.0.instruction)
    }

    fn ctx_precompiles(&mut self) -> (&mut Self::Context, &mut Self::Precompiles) {
        (&mut self.0.ctx, &mut self.0.precompiles)
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        &mut self.0.frame_stack
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_init(frame_input)
    }

    fn frame_run(
        &mut self,
    ) -> Result<
        FrameInitOrResult<Self::Frame>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_run()
    }

    #[doc = " Returns the result of the frame to the caller. Frame is popped from the frame stack."]
    #[doc = " Consumes the frame result or returns it if there is more frames to run."]
    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<
        Option<<Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_return_result(result)
    }
}
