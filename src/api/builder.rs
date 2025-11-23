//! Builder trait [`ZkBuilder`] used to build [`ZKsyncEvm`].
use crate::{ZkSpecId, evm::ZKsyncEvm, precompiles::ZKsyncPrecompiles, transaction::ZkTxTr};
use revm::{
    Context, Database,
    context::{Cfg, ContextTr},
    context_interface::{Block, JournalTr},
    handler::instructions::EthInstructions,
    interpreter::interpreter::EthInterpreter,
    state::EvmState,
};

/// Type alias for default ZKsyncEvm
pub type DefaultZKsyncEvm<CTX, INSP = ()> =
    ZKsyncEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, ZKsyncPrecompiles<CTX>>;

/// Trait that allows for ZKsyncEvm to be built.
pub trait ZkBuilder: Sized {
    /// Type of the context.
    type Context: ContextTr;

    /// Build the ZKsync OS EVM.
    fn build_zk(self) -> DefaultZKsyncEvm<Self::Context>;

    /// Build the ZKsync OS EVM with an inspector.
    fn build_zk_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> DefaultZKsyncEvm<Self::Context, INSP>;
}

impl<BLOCK, TX, CFG, DB, JOURNAL> ZkBuilder for Context<BLOCK, TX, CFG, DB, JOURNAL>
where
    BLOCK: Block,
    TX: ZkTxTr,
    CFG: Cfg<Spec = ZkSpecId>,
    DB: Database,
    JOURNAL: JournalTr<Database = DB, State = EvmState>,
{
    type Context = Self;

    fn build_zk(self) -> DefaultZKsyncEvm<Self::Context> {
        ZKsyncEvm::new(self, ())
    }

    fn build_zk_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> DefaultZKsyncEvm<Self::Context, INSP> {
        ZKsyncEvm::new(self, inspector)
    }
}
