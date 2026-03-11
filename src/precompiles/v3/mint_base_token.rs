use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::revert;
use crate::precompiles::v3::common::zksync_os_hook_input_check;
use revm::interpreter::CallInputs;
use revm::{
    context::JournalTr,
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, U256, address},
};

pub const MINT_BASE_TOKEN_HOOK_ADDRESS: Address =
    address!("0000000000000000000000000000000000007100");

// L2 base token system contract
pub const L2_BASE_TOKEN_ADDRESS: Address = address!("000000000000000000000000000000000000800a");

/// Run the mint base token precompile.
pub fn mint_base_token_precompile_call<CTX: ContextTr>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult {
    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    let caller = inputs.caller;
    let call_value = inputs.value.get();
    let gas = Gas::new(inputs.gas_limit);

    let allowed_callers = [L2_BASE_TOKEN_ADDRESS];
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

    if calldata.len() != 32 {
        return revert(gas);
    }

    let value_to_mint = U256::from_be_slice(calldata);

    // finished reading calldata, release borrow before mutating context
    drop(view);

    ctx.journal_mut().touch_account(caller);
    ctx.journal_mut()
        .load_account(caller)
        .expect("load_account");

    match ctx.journal_mut().balance_incr(caller, value_to_mint) {
        Ok(_) => InterpreterResult::new(InstructionResult::Stop, [].into(), gas),
        Err(_) => revert(gas),
    }
}
