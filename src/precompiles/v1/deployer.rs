use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::{oog_error, revert};
use revm::interpreter::CallInputs;
use revm::{
    Database,
    context::JournalTr,
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, B256, Bytes, U256, address},
    state::Bytecode,
};

// setBytecodeDetailsEVM(address,bytes32,uint32,bytes32) - f6eca0b0
pub const SET_EVM_BYTECODE_DETAILS: &[u8] = &[0xf6, 0xec, 0xa0, 0xb0];
// Contract Deployer system hook (contract) needed for all envs (force deploy)
pub const CONTRACT_DEPLOYER_ADDRESS: Address = address!("0000000000000000000000000000000000008006");

pub const L2_GENESIS_UPGRADE_ADDRESS: Address =
    address!("000000000000000000000000000000000000800f");

pub const MAX_CODE_SIZE: usize = 0x6000;

/// Run the deployer precompile.
pub fn deployer_precompile_call<CTX>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult
where
    CTX: ContextTr,
{
    let view = CalldataView::new(ctx, &inputs.input);
    let mut calldata = view.as_slice();
    let caller = inputs.caller;
    let call_value = inputs.value.get();
    let mut gas = Gas::new(inputs.gas_limit);

    // Mirror the same behaviour as on ZKsync OS
    if is_delegate || call_value != U256::ZERO {
        return revert(gas);
    }

    if !gas.record_cost(1) {
        return oog_error();
    }

    if calldata.len() < 4 {
        return revert(gas);
    }

    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    match selector {
        s if s == SET_EVM_BYTECODE_DETAILS => {
            if inputs.is_static {
                return revert(gas);
            }

            // in future we need to handle regular(not genesis) protocol upgrades
            if caller != L2_GENESIS_UPGRADE_ADDRESS {
                return revert(gas);
            }

            // decoding according to setDeployedCodeEVM(address,bytes)
            calldata = &calldata[4..];
            if calldata.len() < 128 {
                return revert(gas);
            }

            // check that first 12 bytes in address encoding are zero
            if calldata[0..12].iter().any(|byte| *byte != 0) {
                return revert(gas);
            }
            let address = Address::from_slice(&calldata[12..32]);

            let bytecode_hash =
                B256::from_slice(calldata[32..64].try_into().expect("Always valid"));

            let bytecode_length: u32 = match U256::from_be_slice(&calldata[64..96]).try_into() {
                Ok(length) => length,
                Err(_) => {
                    return revert(gas);
                }
            };

            let _observable_bytecode_hash =
                B256::from_slice(calldata[96..128].try_into().expect("Always valid"));

            // Although this can be called as a part of protocol upgrade,
            // we are checking the next invariants, just in case
            // EIP-158: reject code of length > 24576.
            if bytecode_length as usize > MAX_CODE_SIZE {
                return revert(gas);
            }

            // finished reading calldata, release borrow before mutating context
            drop(view);

            let bytecode = ctx.db_mut().code_by_hash(bytecode_hash).expect(
                "The bytecode is expected to be pre-loaded for any deployer precompile call",
            );

            let bytecode_padded = Bytecode::new_legacy(Bytes::copy_from_slice(
                &bytecode.original_bytes()[0..bytecode_length as usize],
            ));
            ctx.journal_mut().touch_account(address);
            ctx.journal_mut().load_account(address);
            ctx.journal_mut().set_code(address, bytecode_padded);
            InterpreterResult::new(InstructionResult::Return, [].into(), gas)
        }
        _ => revert(gas),
    }
}
