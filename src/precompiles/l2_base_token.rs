use std::vec::Vec;

use revm::{
    context::{Cfg, ContextTr, JournalTr},
    interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult},
    primitives::{Address, U256, address},
};

use super::l1_messenger::send_to_l1_inner;
use crate::ZkSpecId;
use crate::precompiles::calldata_view::CalldataView;

pub const L2_BASE_TOKEN_ADDRESS: Address = address!("000000000000000000000000000000000000800a");

// withdraw(address) - 51cff8d9
pub const WITHDRAW_SELECTOR: &[u8] = &[0x51, 0xcf, 0xf8, 0xd9];

// withdrawWithMessage(address,bytes) - 84bc3eb0
pub const WITHDRAW_WITH_MESSAGE_SELECTOR: &[u8] = &[0x84, 0xbc, 0x3e, 0xb0];

// finalizeEthWithdrawal(uint256,uint256,uint16,bytes,bytes32[]) - 6c0960f9
pub const FINALIZE_ETH_WITHDRAWAL_SELECTOR: &[u8] = &[0x6c, 0x09, 0x60, 0xf9];

/// Run the L2 base token precompile.
pub fn l2_base_token_precompile_call<CTX>(
    ctx: &mut CTX,
    inputs: &InputsImpl,
    is_static: bool,
    is_delegate: bool,
    gas_limit: u64,
) -> InterpreterResult
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
{
    let view = CalldataView::new(ctx, &inputs.input);
    let calldata = view.as_slice();
    let mut gas = Gas::new(gas_limit);
    let oog_error = || InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    let revert = |g: Gas| InterpreterResult::new(InstructionResult::Revert, [].into(), g);
    // Mirror the same behaviour as on ZKsync OS
    if is_delegate {
        return revert(gas);
    }

    // Charge base cost for calling system hook
    if !gas.record_cost(100) {
        return oog_error();
    }

    // Check after charging the gas
    if is_static {
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
fn withdraw<CTX>(ctx: &mut CTX, inputs: &InputsImpl, mut gas: Gas) -> InterpreterResult
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
{
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
    l1_messenger_calldata[68..88].copy_from_slice(&calldata[(4 + 12)..36]);
    l1_messenger_calldata[88..120].copy_from_slice(&inputs.call_value.to_be_bytes::<32>());

    drop(view);

    // Touch account gas cost
    if gas.record_cost(100) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    ctx.journal_mut()
        .warm_account(L2_BASE_TOKEN_ADDRESS)
        .expect("warm account");

    ctx.journal_mut().touch_account(L2_BASE_TOKEN_ADDRESS);
    let mut from_account = ctx
        .journal_mut()
        .load_account(L2_BASE_TOKEN_ADDRESS)
        .expect("load account");
    let from_balance = &mut from_account.info.balance;
    let balance_before = *from_balance;
    let Some(from_balance_decr) = from_balance.checked_sub(inputs.call_value) else {
        return revert(gas);
    };
    *from_balance = from_balance_decr;
    ctx.journal_mut()
        .caller_accounting_journal_entry(L2_BASE_TOKEN_ADDRESS, balance_before, false);

    send_to_l1_inner(
        ctx,
        &mut gas,
        Vec::from(l1_messenger_calldata),
        L2_BASE_TOKEN_ADDRESS,
    )
}

/// Handles withdrawWithMessage(address,bytes) calls - burns tokens and sends L1 message with additional data
/// Emits WithdrawalWithMessage event on success
fn withdraw_with_message<CTX>(ctx: &mut CTX, inputs: &InputsImpl, mut gas: Gas) -> InterpreterResult
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
{
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
    let additional_data = &calldata[(length_encoding_end as usize)..message_end as usize];

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
    message.extend_from_slice(&calldata[16..36]);
    message.extend_from_slice(&inputs.call_value.to_be_bytes::<32>());
    message.extend_from_slice(inputs.caller_address.as_ref());
    message.extend_from_slice(additional_data);
    // Populating the rest of the message with zeros to make it a multiple of 32 bytes
    message.extend(core::iter::repeat_n(
        0u8,
        abi_encoded_message_length as usize - message.len(),
    ));

    drop(view);

    // Touch account gas cost
    if gas.record_cost(100) {
        // Out-of-gas error
        return InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    }

    ctx.journal_mut()
        .warm_account(L2_BASE_TOKEN_ADDRESS)
        .expect("warm account");

    ctx.journal_mut().touch_account(L2_BASE_TOKEN_ADDRESS);
    let mut from_account = ctx
        .journal_mut()
        .load_account(L2_BASE_TOKEN_ADDRESS)
        .expect("load account");
    let from_balance = &mut from_account.info.balance;
    let balance_before = *from_balance;
    let Some(from_balance_decr) = from_balance.checked_sub(inputs.call_value) else {
        return revert(gas);
    };
    *from_balance = from_balance_decr;
    ctx.journal_mut()
        .caller_accounting_journal_entry(L2_BASE_TOKEN_ADDRESS, balance_before, false);
    send_to_l1_inner(ctx, &mut gas, message, L2_BASE_TOKEN_ADDRESS)
}
