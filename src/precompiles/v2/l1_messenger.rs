use std::vec::Vec;

use crate::precompiles::v2::gas_cost::{HOOK_BASE_GAS_COST, l1_message_gas_cost, log_gas_cost};
use crate::precompiles::{calldata_view::CalldataView, utils::b160_to_b256};
use revm::interpreter::CallInputs;
use revm::{
    context::JournalTr,
    context_interface::ContextTr,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, B256, Bytes, Log, LogData, U256, address, keccak256},
};

// sendToL1(bytes) - 62f84b24
pub const SEND_TO_L1_SELECTOR: &[u8] = &[0x62, 0xf8, 0x4b, 0x24];

const L1_MESSAGE_SENT_TOPIC: [u8; 32] = [
    0x3a, 0x36, 0xe4, 0x72, 0x91, 0xf4, 0x20, 0x1f, 0xaf, 0x13, 0x7f, 0xab, 0x08, 0x1d, 0x92, 0x29,
    0x5b, 0xce, 0x2d, 0x53, 0xbe, 0x2c, 0x6c, 0xa6, 0x8b, 0xa8, 0x2c, 0x7f, 0xaa, 0x9c, 0xe2, 0x41,
];

pub const L1_MESSENGER_ADDRESS: Address = address!("0000000000000000000000000000000000008008");

pub const L2_TO_L1_LOG_SERIALIZE_SIZE: usize = 88;

pub(crate) fn send_to_l1_inner<CTX: ContextTr>(
    ctx: &mut CTX,
    gas: &mut Gas,
    abi_encoded_message: Vec<u8>,
    caller: Address,
) -> Result<B256, InterpreterResult> {
    let revert = |g: Gas| {
        Err(InterpreterResult::new(
            InstructionResult::Revert,
            [].into(),
            g,
        ))
    };
    let data = abi_encoded_message.as_slice();

    let abi_encoded_message_len: u32 = match data.len().try_into() {
        Ok(len) => len,
        Err(_) => return revert(*gas),
    };

    if abi_encoded_message_len < 32 {
        return revert(*gas);
    }

    let message_offset: u32 = match U256::from_be_slice(&data[..32]).try_into() {
        Ok(offset) => offset,
        Err(_) => return revert(*gas),
    };

    if message_offset != 32 {
        return revert(*gas);
    }

    let length_encoding_end = match message_offset.checked_add(32) {
        Some(length_encoding_end) => length_encoding_end,
        None => return revert(*gas),
    };
    if abi_encoded_message_len < length_encoding_end {
        return revert(*gas);
    }

    let length: u32 = match U256::from_be_slice(
        &data[(length_encoding_end as usize) - 32..length_encoding_end as usize],
    )
    .try_into()
    {
        Ok(length) => length,
        Err(_) => return revert(*gas),
    };

    let message_end = match length_encoding_end.checked_add(length) {
        Some(message_end) => message_end,
        None => return revert(*gas),
    };
    if abi_encoded_message_len < message_end {
        return revert(*gas);
    }

    if !abi_encoded_message_len.is_multiple_of(32) {
        return revert(*gas);
    }
    let message = &data[(length_encoding_end as usize)..message_end as usize];

    // Charge gas for emitting l1 message and log
    let gas_cost =
        l1_message_gas_cost(message.len()) + log_gas_cost(3, abi_encoded_message_len as u64);
    if !gas.record_cost(gas_cost) {
        // Out-of-gas error
        return Err(InterpreterResult::new(
            InstructionResult::OutOfGas,
            [].into(),
            Gas::new(0),
        ));
    }

    let message_hash = keccak256(message);
    let log = Log {
        address: L1_MESSENGER_ADDRESS,
        data: LogData::new_unchecked(
            vec![
                B256::from_slice(&L1_MESSAGE_SENT_TOPIC),
                b160_to_b256(caller),
                message_hash,
            ],
            Bytes::from(abi_encoded_message),
        ),
    };
    ctx.journal_mut().log(log);

    // TODO: save L2 -> L1 message in a context of block

    Ok(message_hash)
}

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
    let mut gas = Gas::new(inputs.gas_limit);
    let revert = |g: Gas| InterpreterResult::new(InstructionResult::Revert, [].into(), g);
    // Mirror the same behaviour as on ZKsync OS
    if is_delegate || call_value != U256::ZERO {
        return revert(gas);
    }

    // Charge base cost for calling system hook
    if !gas.record_cost(HOOK_BASE_GAS_COST) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    // Check after charging the gas
    if inputs.is_static {
        return revert(gas);
    }

    if calldata.len() < 4 {
        return revert(gas);
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    match selector {
        s if s == SEND_TO_L1_SELECTOR => {
            let call_payload = Vec::from(&calldata[4..]);
            drop(view);
            match send_to_l1_inner(ctx, &mut gas, call_payload, caller) {
                Ok(message_hash) => {
                    InterpreterResult::new(InstructionResult::Return, message_hash.into(), gas)
                }
                Err(interpreter_result) => interpreter_result,
            }
        }
        _ => revert(gas),
    }
}
