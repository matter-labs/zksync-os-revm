//! Contains trait [`DefaultZk`] used to create a default context.
use crate::journal::ZkJournal;
use crate::{ZKsyncTx, ZkSpecId};
use revm::{
    Context,
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::Database,
    database_interface::EmptyDB,
    primitives::B256,
};

/// Type alias for the default context type of the ZKsyncEvm.
///
/// The journal is a [`ZkJournal`], which holds the L2→L1 logs produced by the
/// L1Messenger precompile. Take them with `ctx.journaled_state.take_l2_to_l1_logs()`.
pub type ZkContext<DB> = Context<BlockEnv, ZKsyncTx<TxEnv>, CfgEnv<ZkSpecId>, DB, ZkJournal<DB>>;

/// Trait that allows for a default context to be created.
pub trait DefaultZk {
    /// Create a default context.
    fn default() -> ZkContext<EmptyDB>;
}

impl DefaultZk for ZkContext<EmptyDB> {
    fn default() -> Self {
        zk_context(EmptyDB::default(), ZkSpecId::default())
    }
}

/// Create a ZKsync OS context over `db`.
///
/// The context holds a placeholder transaction. Set the transaction to run
/// before execution.
pub fn zk_context<DB: Database>(db: DB, spec: ZkSpecId) -> ZkContext<DB> {
    Context::<BlockEnv, TxEnv, CfgEnv<ZkSpecId>, DB, ZkJournal<DB>>::new(db, spec)
        .with_tx(placeholder_tx())
}

/// A transaction that holds only defaults, for a context that has no
/// transaction to execute yet.
///
/// The identity hash of a real transaction comes from its preimage, so this
/// placeholder holds [`B256::ZERO`].
fn placeholder_tx() -> ZKsyncTx<TxEnv> {
    ZKsyncTx::new(TxEnv::default(), B256::ZERO)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::builder::ZkBuilder;
    use revm::{
        ExecuteEvm,
        inspector::{InspectEvm, NoOpInspector},
    };

    #[test]
    fn default_run_zk() {
        let ctx = <ZkContext<EmptyDB> as DefaultZk>::default();
        assert_eq!(ctx.tx, placeholder_tx());
        // convert to ZKsync OS context
        let mut evm = ctx.build_zk_with_inspector(NoOpInspector {});
        // execute
        let _ = evm.transact(placeholder_tx());
        // inspect
        let _ = evm.inspect_one_tx(placeholder_tx());
    }
}
