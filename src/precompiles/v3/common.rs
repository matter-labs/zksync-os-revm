use revm::{
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    primitives::{Address, U256, address},
};

use crate::precompiles::utils::revert;

pub const CONTRACT_DEPLOYER_ADDRESS: Address = address!("0000000000000000000000000000000000008006");

pub fn zksync_os_hook_input_check(
    inputs: &CallInputs,
    caller: &Address,
    is_delegate: bool,
    call_value: U256,
    gas: Gas,
    allowed_addresses: &[Address],
) -> Option<InterpreterResult> {
    if !allowed_addresses.contains(caller) {
        // Pretend to be an empty contract
        return Some(InterpreterResult::new(
            InstructionResult::Stop,
            [].into(),
            gas,
        ));
    }

    // Mirror the same behaviour as on ZKsync OS
    if is_delegate || call_value != U256::ZERO {
        return Some(revert(gas));
    }

    if inputs.is_static {
        return Some(revert(gas));
    }

    None
}
