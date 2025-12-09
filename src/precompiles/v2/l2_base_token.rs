use std::vec::Vec;

use super::l1_messenger::send_to_l1_inner;
use crate::precompiles::v2::gas_cost::{HOOK_BASE_GAS_COST, log_gas_cost};
use crate::precompiles::{calldata_view::CalldataView, utils::b160_to_b256};
use revm::interpreter::CallInputs;
use revm::{
    context::{ContextTr, JournalTr},
    interpreter::{Gas, InstructionResult, InterpreterResult, gas::WARM_STORAGE_READ_COST},
    primitives::{Address, B256, Bytes, Log, LogData, U256, address},
};

pub const L2_BASE_TOKEN_ADDRESS: Address = address!("000000000000000000000000000000000000800a");

// withdraw(address) - 51cff8d9
pub const WITHDRAW_SELECTOR: &[u8] = &[0x51, 0xcf, 0xf8, 0xd9];

// withdrawWithMessage(address,bytes) - 84bc3eb0
pub const WITHDRAW_WITH_MESSAGE_SELECTOR: &[u8] = &[0x84, 0xbc, 0x3e, 0xb0];

// finalizeEthWithdrawal(uint256,uint256,uint16,bytes,bytes32[]) - 6c0960f9
pub const FINALIZE_ETH_WITHDRAWAL_SELECTOR: &[u8] = &[0x6c, 0x09, 0x60, 0xf9];

// keccak256("Withdrawal(address,address,uint256)")
const WITHDRAWAL_TOPIC: [u8; 32] = [
    0x27, 0x17, 0xea, 0xd6, 0xb9, 0x20, 0x0d, 0xd2, 0x35, 0xaa, 0xd4, 0x68, 0xc9, 0x80, 0x9e, 0xa4,
    0x00, 0xfe, 0x33, 0xac, 0x69, 0xb5, 0xbf, 0xaa, 0x6d, 0x3e, 0x90, 0xfc, 0x92, 0x2b, 0x63, 0x98,
];

// keccak256("WithdrawalWithMessage(address,address,uint256,bytes)")
const WITHDRAWAL_WITH_MESSAGE_TOPIC: [u8; 32] = [
    0xc4, 0x05, 0xfe, 0x89, 0x58, 0x41, 0x0b, 0xba, 0xf0, 0xc7, 0x3b, 0x7a, 0x0c, 0x3e, 0x20, 0x85,
    0x9e, 0x86, 0xca, 0x16, 0x8a, 0x4c, 0x9b, 0x0d, 0xef, 0x9c, 0x54, 0xd2, 0x55, 0x5a, 0x30, 0x6b,
];

/// Run the L2 base token precompile.
pub fn l2_base_token_precompile_call<CTX: ContextTr>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    is_delegate: bool,
) -> InterpreterResult {
    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    let mut gas = Gas::new(inputs.gas_limit);
    let oog_error = || InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    let revert = |g: Gas| InterpreterResult::new(InstructionResult::Revert, [].into(), g);
    // Mirror the same behaviour as on ZKsync OS
    if is_delegate {
        return revert(gas);
    }

    // Charge base cost for calling system hook
    if !gas.record_cost(HOOK_BASE_GAS_COST) {
        return oog_error();
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
    drop(view);
    match selector {
        s if s == WITHDRAW_SELECTOR => withdraw(ctx, inputs, gas),
        s if s == WITHDRAW_WITH_MESSAGE_SELECTOR => withdraw_with_message(ctx, inputs, gas),
        _ => revert(gas),
    }
}

/// Handles withdraw(address) calls - burns tokens and sends L1 message
/// Emits Withdrawal event on success
fn withdraw<CTX: ContextTr>(ctx: &mut CTX, inputs: &CallInputs, mut gas: Gas) -> InterpreterResult {
    let revert = |g: Gas| InterpreterResult::new(InstructionResult::Revert, [].into(), g);

    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    // Calldata length shouldn't be able to overflow u32, due to gas limitations.
    let calldata_len: u32 = match calldata.len().try_into() {
        Ok(calldata_len) => calldata_len,
        Err(_) => {
            return revert(gas);
        }
    };

    // following solidity abi for withdraw(address)
    if calldata_len < 36 {
        return revert(gas);
    }

    // Prepare L1 messenger payload while calldata borrow is active.
    let mut l1_messenger_calldata = [0u8; 128];
    l1_messenger_calldata[31] = 32; // offset
    l1_messenger_calldata[63] = 56; // length
    l1_messenger_calldata[64..68].copy_from_slice(FINALIZE_ETH_WITHDRAWAL_SELECTOR);
    // check that first 12 bytes in address encoding are zero
    if calldata[4..4 + 12].iter().any(|byte| *byte != 0) {
        return revert(gas);
    }
    let l1_receiver = calldata[(4 + 12)..36].to_vec();
    l1_messenger_calldata[68..88].copy_from_slice(&l1_receiver);
    l1_messenger_calldata[88..120].copy_from_slice(&inputs.value.get().to_be_bytes::<32>());

    drop(view);

    // Charge gas for the token burning
    if !gas.record_cost(WARM_STORAGE_READ_COST) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    ctx.journal_mut().touch_account(L2_BASE_TOKEN_ADDRESS);
    let mut from_account = ctx
        .journal_mut()
        .load_account_with_code_mut(L2_BASE_TOKEN_ADDRESS)
        .expect("load account");
    let balance_before = from_account.info.balance;
    let Some(from_balance_decr) = balance_before.checked_sub(inputs.value.get()) else {
        return revert(gas);
    };
    from_account.set_balance(from_balance_decr);

    if let Err(interpreter_result) = send_to_l1_inner(
        ctx,
        &mut gas,
        Vec::from(l1_messenger_calldata),
        L2_BASE_TOKEN_ADDRESS,
    ) {
        return interpreter_result;
    };

    let log = Log {
        address: L2_BASE_TOKEN_ADDRESS,
        data: LogData::new_unchecked(
            vec![
                B256::from_slice(&WITHDRAWAL_TOPIC),
                b160_to_b256(inputs.caller), // _l2Sender
                U256::from_be_slice(&l1_receiver).into(),
            ],
            inputs.value.get().to_be_bytes::<32>().into(),
        ),
    };
    ctx.journal_mut().log(log);

    // Charge gas for emitting log
    let gas_cost = log_gas_cost(3, 32);
    if !gas.record_cost(gas_cost) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    InterpreterResult::new(InstructionResult::Return, [].into(), gas)
}

/// Handles withdrawWithMessage(address,bytes) calls - burns tokens and sends L1 message with additional data
/// Emits WithdrawalWithMessage event on success
fn withdraw_with_message<CTX: ContextTr>(
    ctx: &mut CTX,
    inputs: &CallInputs,
    mut gas: Gas,
) -> InterpreterResult {
    let revert = |g: Gas| InterpreterResult::new(InstructionResult::Revert, [].into(), g);

    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();

    // Calldata length shouldn't be able to overflow u32, due to gas limitations.
    let calldata_len: u32 = match calldata.len().try_into() {
        Ok(calldata_len) => calldata_len,
        Err(_) => {
            return revert(gas);
        }
    };

    // following solidity abi for withdrawWithMessage(address,bytes)
    if calldata_len < 68 {
        return revert(gas);
    }
    let message_offset: u32 = match U256::from_be_slice(&calldata[36..68]).try_into() {
        Ok(offset) => offset,
        Err(_) => {
            return revert(gas);
        }
    };
    // length located at 4+message_offset..4+message_offset+32
    // we want to check that 4+message_offset+32 will not overflow u32
    let length_encoding_end = match message_offset.checked_add(36) {
        Some(length_encoding_end) => length_encoding_end,
        None => {
            return revert(gas);
        }
    };
    if calldata_len < length_encoding_end {
        return revert(gas);
    }
    let length: u32 = match U256::from_be_slice(
        &calldata[(length_encoding_end as usize) - 32..length_encoding_end as usize],
    )
    .try_into()
    {
        Ok(length) => length,
        Err(_) => {
            return revert(gas);
        }
    };
    // to check that it will not overflow
    let message_end = match length_encoding_end.checked_add(length) {
        Some(message_end) => message_end,
        None => {
            return revert(gas);
        }
    };
    if calldata_len < message_end {
        return revert(gas);
    }
    let additional_data = calldata[(length_encoding_end as usize)..message_end as usize].to_vec();

    // check that first 12 bytes in address encoding are zero
    if calldata[4..4 + 12].iter().any(|byte| *byte != 0) {
        return revert(gas);
    }

    let message_length = 76 + length;
    let mut abi_encoded_message_length = 32 + 32 + message_length;
    if !abi_encoded_message_length.is_multiple_of(32) {
        abi_encoded_message_length += 32 - (abi_encoded_message_length % 32);
    }
    let mut message = Vec::with_capacity(abi_encoded_message_length as usize);
    // Offset and length
    message.extend_from_slice(&[0u8; 64]);
    message[31] = 32; // offset
    message[32..64].copy_from_slice(&U256::from(message_length).to_be_bytes::<32>());
    message.extend_from_slice(FINALIZE_ETH_WITHDRAWAL_SELECTOR);
    let l1_receiver = calldata[(4 + 12)..36].to_vec();
    message.extend_from_slice(&l1_receiver);
    message.extend_from_slice(&inputs.value.get().to_be_bytes::<32>());
    message.extend_from_slice(inputs.caller.as_ref());
    message.extend_from_slice(&additional_data);
    // Populating the rest of the message with zeros to make it a multiple of 32 bytes
    message.extend(core::iter::repeat_n(
        0u8,
        abi_encoded_message_length as usize - message.len(),
    ));

    drop(view);

    // Charge gas for the token burning
    if !gas.record_cost(WARM_STORAGE_READ_COST) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    ctx.journal_mut().touch_account(L2_BASE_TOKEN_ADDRESS);
    let mut from_account = ctx
        .journal_mut()
        .load_account_with_code_mut(L2_BASE_TOKEN_ADDRESS)
        .expect("load account");
    let balance_before = from_account.info.balance;
    let Some(from_balance_decr) = balance_before.checked_sub(inputs.value.get()) else {
        return revert(gas);
    };
    from_account.set_balance(from_balance_decr);
    if let Err(interpreter_result) = send_to_l1_inner(ctx, &mut gas, message, L2_BASE_TOKEN_ADDRESS)
    {
        return interpreter_result;
    };

    /*
        event WithdrawalWithMessage(
            address indexed _l2Sender,
            address indexed _l1Receiver,
            uint256 _amount,
            bytes _additionalData
        );
    */

    // ABI encode event data: _amount (32 bytes) + _additionalData offset (32) + length (32) + data
    let abi_encoded_event_length = 32 + 32 + 32 + additional_data.len();
    let abi_encoded_event_length = if !abi_encoded_event_length.is_multiple_of(32) {
        abi_encoded_event_length + (32 - (abi_encoded_event_length % 32))
    } else {
        abi_encoded_event_length
    };

    let mut event_data = std::vec::Vec::with_capacity(abi_encoded_event_length + 32);
    event_data.extend_from_slice(&inputs.value.get().to_be_bytes::<32>());
    event_data.extend_from_slice(&[0u8; 64]);
    event_data[63] = 64; // offset
    event_data[64..96].copy_from_slice(&U256::from(additional_data.len()).to_be_bytes::<32>());
    event_data.extend_from_slice(&additional_data);
    // Populating the rest of the event data with zeros to make it a multiple of 32 bytes
    event_data.extend(core::iter::repeat_n(
        0u8,
        abi_encoded_event_length - event_data.len(),
    ));

    let log = Log {
        address: L2_BASE_TOKEN_ADDRESS,
        data: LogData::new_unchecked(
            vec![
                B256::from_slice(&WITHDRAWAL_WITH_MESSAGE_TOPIC),
                b160_to_b256(inputs.caller), // _l2Sender
                U256::from_be_slice(&l1_receiver).into(),
            ],
            Bytes::from(event_data),
        ),
    };
    ctx.journal_mut().log(log);

    // Charge gas for emitting log
    let gas_cost = log_gas_cost(3, abi_encoded_event_length as u64);
    if !gas.record_cost(gas_cost) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    InterpreterResult::new(InstructionResult::Return, [].into(), gas)
}
