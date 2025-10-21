use std::vec::Vec;

use revm::{
    context::{Cfg, ContextTr, JournalTr},
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::{Address, U256, address},
};

use crate::ZkSpecId;

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
    caller: Address,
    is_static: bool,
    gas_limit: u64,
    call_value: U256,
    calldata: &[u8],
) -> InterpreterResult
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
{
    let error = || {
        InterpreterResult::new(
            InstructionResult::Revert,
            [].into(),
            Gas::new(gas_limit - 10),
        )
    };
    if calldata.len() < 4 {
        return error();
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    // Calldata length shouldn't be able to overflow u32, due to gas
    // limitations.
    let calldata_len: u32 = match calldata.len().try_into() {
        Ok(calldata_len) => calldata_len,
        Err(_) => {
            return error();
        }
    };
    match selector {
        s if s == WITHDRAW_SELECTOR => {
            if is_static {
                return error();
            }
            // following solidity abi for withdraw(address)
            if calldata_len < 36 {
                return error();
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
            let Some(from_balance_decr) = from_balance.checked_sub(call_value) else {
                return error();
            };
            *from_balance = from_balance_decr;
            ctx.journal_mut().caller_accounting_journal_entry(
                L2_BASE_TOKEN_ADDRESS,
                balance_before,
                false,
            );

            // Sending L2->L1 message.
            // ABI-encoded messages should consist of the following:
            // 32 bytes offset (must be 32)
            // 32 bytes length of the message
            // followed by the message itself, padded to be a multiple of 32 bytes.
            // In this case, it is known that the message is 56 bytes long:
            // - IMailbox.finalizeEthWithdrawal.selector (4)
            // - l1_receiver (20)
            // - nominal_token_value (32)

            // So the padded message will be 64 bytes long.
            // Total length of the encoded message will be 32 + 32 + 64 = 128 bytes.
            let mut l1_messenger_calldata = [0u8; 128];
            l1_messenger_calldata[31] = 32; // offset
            l1_messenger_calldata[63] = 56; // length
            l1_messenger_calldata[64..68].copy_from_slice(FINALIZE_ETH_WITHDRAWAL_SELECTOR);
            // check that first 12 bytes in address encoding are zero
            if calldata[4..4 + 12].iter().any(|byte| *byte != 0) {
                return error();
            }
            l1_messenger_calldata[68..88].copy_from_slice(&calldata[(4 + 12)..36]);
            l1_messenger_calldata[88..120].copy_from_slice(&call_value.to_be_bytes::<32>());

            // let result = send_to_l1_inner(
            //     &l1_messenger_calldata,
            //     resources,
            //     system,
            //     L2_BASE_TOKEN_ADDRESS,
            //     caller_ee,
            // )?;
            InterpreterResult::new(InstructionResult::Return, [].into(), Gas::new(gas_limit))
        }
        s if s == WITHDRAW_WITH_MESSAGE_SELECTOR => {
            if is_static {
                return error();
            }
            // following solidity abi for withdrawWithMessage(address,bytes)
            if calldata_len < 68 {
                return error();
            }
            let message_offset: u32 = match U256::from_be_slice(&calldata[36..68]).try_into() {
                Ok(offset) => offset,
                Err(_) => {
                    return error();
                }
            };
            // length located at 4+message_offset..4+message_offset+32
            // we want to check that 4+message_offset+32 will not overflow u32
            let length_encoding_end = match message_offset.checked_add(36) {
                Some(length_encoding_end) => length_encoding_end,
                None => {
                    return error();
                }
            };
            if calldata_len < length_encoding_end {
                return error();
            }
            let length: u32 = match U256::from_be_slice(
                &calldata[(length_encoding_end as usize) - 32..length_encoding_end as usize],
            )
            .try_into()
            {
                Ok(length) => length,
                Err(_) => {
                    return error();
                }
            };
            // to check that it will not overflow
            let message_end = match length_encoding_end.checked_add(length) {
                Some(message_end) => message_end,
                None => {
                    return error();
                }
            };
            if calldata_len < message_end {
                return error();
            }
            let additional_data = &calldata[(length_encoding_end as usize)..message_end as usize];

            // check that first 12 bytes in address encoding are zero
            if calldata[4..4 + 12].iter().any(|byte| *byte != 0) {
                return error();
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
            let Some(from_balance_decr) = from_balance.checked_sub(call_value) else {
                return error();
            };
            *from_balance = from_balance_decr;
            ctx.journal_mut().caller_accounting_journal_entry(
                L2_BASE_TOKEN_ADDRESS,
                balance_before,
                false,
            );

            // Sending L2->L1 message.
            // ABI-encoded messages should consist of the following:
            // 32 bytes offset (must be 32)
            // 32 bytes length of the message
            // followed by the message itself, padded to be a multiple of 32 bytes.
            // In this case, the message will consist of the following:
            // Packed ABI encoding of:
            // - IMailbox.finalizeEthWithdrawal.selector (4)
            // - l1_receiver (20)
            // - nominal_token_value (32)
            // - sender (20)
            // - additional_data (length of additional_data)
            let message_length = 76 + length;
            let abi_encoded_message_length = 32 + 32 + message_length;
            let abi_encoded_message_length = if !abi_encoded_message_length.is_multiple_of(32) {
                abi_encoded_message_length + (32 - (abi_encoded_message_length % 32))
            } else {
                abi_encoded_message_length
            };
            let mut message = Vec::with_capacity(abi_encoded_message_length as usize);
            // Offset and length
            message.extend_from_slice(&[0u8; 64]);
            message[31] = 32; // offset
            message[32..64].copy_from_slice(&U256::from(message_length).to_be_bytes::<32>());
            message.extend_from_slice(FINALIZE_ETH_WITHDRAWAL_SELECTOR);
            message.extend_from_slice(&calldata[16..36]);
            message.extend_from_slice(&call_value.to_be_bytes::<32>());
            message.extend_from_slice(caller.as_ref());
            message.extend_from_slice(additional_data);
            // Populating the rest of the message with zeros to make it a multiple of 32 bytes
            message.extend(core::iter::repeat_n(
                0u8,
                abi_encoded_message_length as usize - message.len(),
            ));

            // let result = send_to_l1_inner(
            //     &message,
            //     resources,
            //     system,
            //     L2_BASE_TOKEN_ADDRESS,
            //     caller_ee,
            // )?;

            InterpreterResult::new(InstructionResult::Return, [].into(), Gas::new(gas_limit))
        }
        _ => error(),
    }
}
