use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::revert;
use crate::precompiles::v3::common::zksync_os_hook_input_check;
use crate::precompiles::v3::set_bytecode_on_address::{
    set_bytecode_on_address_internal, set_bytecode_on_address_parse_calldata,
};
use revm::interpreter::CallInputs;
use revm::{
    context_interface::ContextTr,
    interpreter::{Gas, InterpreterResult},
    primitives::{Address, address},
};

// setBytecodeDetailsEVM(address,bytes32,uint32,bytes32) - f6eca0b0
pub const SET_EVM_BYTECODE_DETAILS: &[u8] = &[0xf6, 0xec, 0xa0, 0xb0];
pub const L2_GENESIS_UPGRADE_ADDRESS: Address =
    address!("000000000000000000000000000000000000800f");

pub const MAX_CODE_SIZE: usize = 0x6000;

/// Run the deployer precompile.
pub fn deployer_precompile_call<CTX: ContextTr>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult {
    let view = CalldataView::new(ctx, &inputs.input);
    let mut calldata = view.as_slice();
    let caller = inputs.caller;
    let call_value = inputs.value.get();
    let gas = Gas::new(inputs.gas_limit);

    let allowed_callers = [L2_GENESIS_UPGRADE_ADDRESS];
    if let Some(early_return) = zksync_os_hook_input_check(
        inputs,
        &caller,
        is_delegate,
        call_value,
        gas,
        &allowed_callers,
    ) {
        return early_return;
    }

    if calldata.len() < 4 {
        return revert(gas);
    }

    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    match selector {
        s if s == SET_EVM_BYTECODE_DETAILS => {
            // in future we need to handle regular(not genesis) protocol upgrades
            if caller != L2_GENESIS_UPGRADE_ADDRESS {
                return revert(gas);
            }

            calldata = &calldata[4..];

            let (address, observable_bytecode_hash, bytecode_length) =
                match set_bytecode_on_address_parse_calldata(calldata, gas) {
                    Ok(x) => x,
                    Err(early_return) => return early_return,
                };

            // finished reading calldata, release borrow before mutating context
            drop(view);

            set_bytecode_on_address_internal(
                ctx,
                address,
                observable_bytecode_hash,
                bytecode_length,
                gas,
            )
        }
        _ => revert(gas),
    }
}
