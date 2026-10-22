use revm::{
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, B256},
};

#[inline(always)]
pub fn b160_to_b256(addr: Address) -> B256 {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice()); // pad left, store address in low 20 bytes
    B256::from(out)
}

pub fn revert(g: Gas) -> InterpreterResult {
    InterpreterResult::new(InstructionResult::Revert, [].into(), g)
}

/// A revert with no output that consumes all `gas_limit`, as a ZKsync OS hook
/// fails a call it exhausts.
pub fn revert_consuming_all_gas(gas_limit: u64) -> InterpreterResult {
    let mut gas = Gas::new(gas_limit);
    gas.spend_all();
    revert(gas)
}

pub fn oog_error() -> InterpreterResult {
    InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0))
}
