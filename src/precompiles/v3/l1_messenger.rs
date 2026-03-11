use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::revert;
use crate::precompiles::v3::common::zksync_os_hook_input_check;
use revm::interpreter::CallInputs;
use revm::{
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, address},
};

pub const L1_MESSENGER_HOOK_ADDRESS: Address = address!("0000000000000000000000000000000000007001");

pub const L1_MESSENGER_ADDRESS: Address = address!("0000000000000000000000000000000000008008");

/// Run the L1 messenger precompile.
pub fn l1_messenger_precompile_call<CTX: ContextTr>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult {
    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    let caller = inputs.caller;
    let call_value = inputs.value.get();
    let gas = Gas::new(inputs.gas_limit);

    let allowed_callers = [L1_MESSENGER_ADDRESS];
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

    if calldata.len() < 20 {
        return revert(gas);
    }

    // Do nothing, effects should not be observable
    InterpreterResult::new(InstructionResult::Stop, [].into(), gas)
}
