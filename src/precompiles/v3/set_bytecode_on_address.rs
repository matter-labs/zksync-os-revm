use crate::precompiles::calldata_view::CalldataView;
use crate::precompiles::utils::{oog_error, revert};
use crate::precompiles::v3::common::{
    COMPLEX_UPGRADER_ADDRESS, CONTRACT_DEPLOYER_ADDRESS, zksync_os_hook_input_check,
};
use crate::precompiles::v3::deployer::MAX_CODE_SIZE;
use crate::precompiles::v3::gas_cost::set_bytecode_details_extra_gas;
use revm::Database;
use revm::interpreter::CallInputs;
use revm::interpreter::gas::{COLD_ACCOUNT_ACCESS_COST, WARM_STORAGE_READ_COST};
use revm::primitives::{B256, Bytes};
use revm::state::Bytecode;
use revm::{
    context::JournalTr,
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, U256, address},
};

pub const SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS: Address =
    address!("0000000000000000000000000000000000007002");

/// Run the set-bytecode-on-address precompile.
pub fn set_bytecode_on_address_precompile_call<CTX: ContextTr>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult {
    let calldata_view = CalldataView::new(ctx, &inputs.input);
    let calldata = calldata_view.as_slice();
    let caller = inputs.caller;
    let call_value = inputs.value.get();
    let gas = Gas::new(inputs.gas_limit);

    let allowed_callers = [CONTRACT_DEPLOYER_ADDRESS, COMPLEX_UPGRADER_ADDRESS];
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

    let (address, bytecode_hash, bytecode_length) =
        match set_bytecode_on_address_parse_calldata(calldata, gas) {
            Ok(x) => x,
            Err(early_return) => return early_return,
        };

    // finished reading calldata, release borrow before mutating context
    drop(calldata_view);

    set_bytecode_on_address_internal(ctx, address, bytecode_hash, bytecode_length, gas)
}

pub fn set_bytecode_on_address_parse_calldata(
    calldata: &[u8],
    gas: Gas,
) -> Result<(Address, B256, u32), InterpreterResult> {
    if calldata.len() < 128 {
        return Err(revert(gas));
    }

    // check that first 12 bytes in address encoding are zero
    if calldata[0..12].iter().any(|byte| *byte != 0) {
        return Err(revert(gas));
    }

    let address = Address::from_slice(&calldata[12..32]);

    let bytecode_hash = B256::from_slice(&calldata[32..64]);

    let bytecode_length: u32 = match U256::from_be_slice(&calldata[64..96]).try_into() {
        Ok(length) => length,
        Err(_) => {
            return Err(revert(gas));
        }
    };
    // Although this can be called as a part of protocol upgrade,
    // we are checking the next invariants, just in case
    // EIP-158: reject code of length > 24576.
    if bytecode_length as usize > MAX_CODE_SIZE {
        return Err(revert(gas));
    }

    Ok((address, bytecode_hash, bytecode_length))
}

pub fn set_bytecode_on_address_internal<CTX: ContextTr>(
    ctx: &mut CTX,
    address: Address,
    bytecode_hash: B256,
    bytecode_length: u32,
    mut gas: Gas,
) -> InterpreterResult {
    // Charge extra gas for `set_bytecode_details`
    let extra_gas = set_bytecode_details_extra_gas(bytecode_length as u64);
    if !gas.record_regular_cost(extra_gas) {
        return oog_error();
    }

    let bytecode = ctx
        .db_mut()
        .code_by_hash(bytecode_hash)
        .expect("The bytecode is expected to be pre-loaded for any deployer precompile call");
    let bytecode_length = bytecode_length as usize;
    if bytecode.original_bytes().len() < bytecode_length {
        return revert(gas);
    }

    let bytecode_padded = Bytecode::new_legacy(Bytes::copy_from_slice(
        &bytecode.original_bytes()[0..bytecode_length],
    ));
    let account = ctx
        .journal_mut()
        .load_account(address)
        .expect("load account");
    let gas_for_access = if account.is_cold {
        COLD_ACCOUNT_ACCESS_COST
    } else {
        WARM_STORAGE_READ_COST
    };
    // Charge base cost for warm/cold read
    if !gas.record_regular_cost(gas_for_access) {
        return oog_error();
    }

    ctx.journal_mut().touch_account(address);
    ctx.journal_mut()
        .load_account(address)
        .expect("load_account");
    ctx.journal_mut().set_code(address, bytecode_padded);
    InterpreterResult::new(InstructionResult::Stop, [].into(), gas)
}
