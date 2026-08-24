use crate::l2_to_l1_logs::L2ToL1LogStore;
use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::{b160_to_b256, revert};
use crate::precompiles::v3::common::zksync_os_hook_input_check;
use revm::interpreter::CallInputs;
use revm::{
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, address, keccak256},
};

pub const L1_MESSENGER_HOOK_ADDRESS: Address = address!("0000000000000000000000000000000000007001");

pub const L1_MESSENGER_ADDRESS: Address = address!("0000000000000000000000000000000000008008");

/// Run the L1 messenger precompile.
pub fn l1_messenger_precompile_call<CTX>(
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

    // Calldata is abi.encodePacked(address msg.sender, bytes message); the
    // L1MessageSent event is emitted by the L1 messenger contract itself, so
    // the hook's only observable effect for the second execution is the
    // structured L2->L1 log (key = padded sender, value = keccak256(message)),
    // mirroring the native hook's emit_l1_message.
    let sender = Address::from_slice(&calldata[..20]);
    let message_hash = keccak256(&calldata[20..]);
    drop(view);
    ctx.journal_mut()
        .push_l2_to_l1_log(L1_MESSENGER_ADDRESS, b160_to_b256(sender), message_hash);

    InterpreterResult::new(InstructionResult::Stop, [].into(), gas)
}
