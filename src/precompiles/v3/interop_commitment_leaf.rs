use crate::l2_to_l1_logs::L2ToL1LogStore;
use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::revert;
use crate::precompiles::v3::common::zksync_os_hook_input_check;
use revm::interpreter::CallInputs;
use revm::{
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, B256, address},
};

/// The hook introduced in AtlasV4 to publish every interop commitment-tree leaf to DA.
pub const INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS: Address =
    address!("0000000000000000000000000000000000007004");

/// The only contract allowed to report interop commitment-tree leaves.
pub const L2_INTEROP_COMMITMENT_TREE_ADDRESS: Address =
    address!("0000000000000000000000000000000000010012");

/// Record an interop commitment-tree leaf as an L2→L1 log.
///
/// This hook is available from AtlasV4 onward. The caller contract has already
/// charged EVM gas, so the hook consumes no additional EVM gas and returns no data.
pub fn interop_commitment_leaf_precompile_call<CTX>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult
where
    CTX: ContextTr,
    CTX::Journal: L2ToL1LogStore,
{
    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    let caller = inputs.caller;
    let call_value = inputs.value.get();
    let gas = Gas::new(inputs.gas_limit);

    if let Some(early_return) = zksync_os_hook_input_check(
        inputs,
        &caller,
        is_delegate,
        call_value,
        gas,
        &[L2_INTEROP_COMMITMENT_TREE_ADDRESS],
    ) {
        return early_return;
    }

    if calldata.len() != 32 {
        return revert(gas);
    }

    let leaf_hash = B256::from_slice(calldata);
    drop(view);
    ctx.journal_mut()
        .push_l2_to_l1_log(L2_INTEROP_COMMITMENT_TREE_ADDRESS, B256::ZERO, leaf_hash);

    InterpreterResult::new(InstructionResult::Stop, [].into(), gas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2_to_l1_logs::L2ToL1Log;
    use crate::precompiles::ZKsyncPrecompiles;
    use crate::transaction::abstraction::ZKsyncTxBuilder;
    use crate::{ZkBuilder, ZkSpecId, zk_context};
    use revm::database::{CacheDB, EmptyDB};
    use revm::primitives::{Bytes, TxKind, U256};
    use revm::state::{AccountInfo, Bytecode};
    use revm::{ExecuteEvm, context::TxEnv};

    const OP_MSTORE: u8 = 0x52;
    const OP_GAS: u8 = 0x5a;
    const OP_PUSH1: u8 = 0x60;
    const OP_PUSH20: u8 = 0x73;
    const OP_PUSH32: u8 = 0x7f;
    const OP_CALL: u8 = 0xf1;
    const OP_RETURN: u8 = 0xf3;
    const OP_REVERT: u8 = 0xfd;

    const CALLER: Address = address!("0000000000000000000000000000000000000c0f");

    fn calls_the_hook(leaf: B256, terminator: u8) -> Bytes {
        let mut code = vec![OP_PUSH32];
        code.extend_from_slice(leaf.as_slice());
        code.extend_from_slice(&[OP_PUSH1, 0, OP_MSTORE]);
        code.extend_from_slice(&[
            OP_PUSH1, 0, OP_PUSH1, 0, OP_PUSH1, 32, OP_PUSH1, 0, OP_PUSH1, 0, OP_PUSH20,
        ]);
        code.extend_from_slice(INTEROP_COMMITMENT_LEAF_HOOK_ADDRESS.as_slice());
        code.extend_from_slice(&[OP_GAS, OP_CALL]);
        code.extend_from_slice(&[
            OP_PUSH1, 0, OP_MSTORE, OP_PUSH1, 32, OP_PUSH1, 0, terminator,
        ]);
        code.into()
    }

    fn logs_of_a_call(spec: ZkSpecId, contract: Address, code: Bytes) -> Vec<L2ToL1Log> {
        let mut database = CacheDB::new(EmptyDB::default());
        database.insert_account_info(
            CALLER,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
        database.insert_account_info(
            contract,
            AccountInfo {
                code: Some(Bytecode::new_raw(code)),
                ..Default::default()
            },
        );

        let mut evm = zk_context(database, spec)
            .modify_cfg_chained(|cfg| cfg.spec = spec)
            .build_zk()
            .with_precompiles(ZKsyncPrecompiles::new_with_spec(spec));
        let transaction = ZKsyncTxBuilder::new()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(contract))
                    .gas_limit(1_000_000)
                    .gas_price(0),
            )
            .tx_hash(B256::ZERO)
            .build()
            .expect("transaction builds");
        evm.0.ctx.journaled_state.set_tx_number(0);
        evm.transact(transaction).expect("transaction runs");
        evm.0.ctx.journaled_state.take_l2_to_l1_logs()
    }

    #[test]
    fn records_the_leaf_hash_as_a_service_log() {
        let leaf = B256::repeat_byte(0xab);
        let logs = logs_of_a_call(
            ZkSpecId::AtlasV4,
            L2_INTEROP_COMMITMENT_TREE_ADDRESS,
            calls_the_hook(leaf, OP_RETURN),
        );
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].l2_shard_id, 0);
        assert!(logs[0].is_service);
        assert_eq!(logs[0].tx_number_in_block, 0);
        assert_eq!(logs[0].sender, L2_INTEROP_COMMITMENT_TREE_ADDRESS);
        assert_eq!(logs[0].key, B256::ZERO);
        assert_eq!(logs[0].value, leaf);
    }

    #[test]
    fn rejects_a_caller_other_than_the_commitment_tree() {
        let logs = logs_of_a_call(
            ZkSpecId::AtlasV4,
            address!("0000000000000000000000000000000000009999"),
            calls_the_hook(B256::repeat_byte(0xab), OP_RETURN),
        );
        assert!(logs.is_empty());
    }

    #[test]
    fn a_reverted_frame_discards_the_leaf_log() {
        let logs = logs_of_a_call(
            ZkSpecId::AtlasV4,
            L2_INTEROP_COMMITMENT_TREE_ADDRESS,
            calls_the_hook(B256::repeat_byte(0xab), OP_REVERT),
        );
        assert!(logs.is_empty());
    }

    #[test]
    fn older_specs_see_an_empty_account_at_the_hook_address() {
        for spec in [ZkSpecId::AtlasV1, ZkSpecId::AtlasV2, ZkSpecId::AtlasV3] {
            let logs = logs_of_a_call(
                spec,
                L2_INTEROP_COMMITMENT_TREE_ADDRESS,
                calls_the_hook(B256::repeat_byte(0xab), OP_RETURN),
            );
            assert!(logs.is_empty(), "{spec:?} must not serve the hook");
        }
    }
}
