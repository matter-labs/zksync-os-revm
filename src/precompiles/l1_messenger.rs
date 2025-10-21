use revm::{
    context::{Cfg, JournalTr},
    context_interface::ContextTr,
    interpreter::{
        Gas, InstructionResult, InterpreterResult,
        gas::{KECCAK256, KECCAK256WORD, LOG, LOGDATA, LOGTOPIC},
    },
    primitives::{Address, B256, Bytes, Log, LogData, U256, address, keccak256},
};
use std::vec;
use std::vec::Vec;

use crate::ZkSpecId;

// sendToL1(bytes) - 62f84b24
pub const SEND_TO_L1_SELECTOR: &[u8] = &[0x62, 0xf8, 0x4b, 0x24];

const L1_MESSAGE_SENT_TOPIC: [u8; 32] = [
    0x3a, 0x36, 0xe4, 0x72, 0x91, 0xf4, 0x20, 0x1f, 0xaf, 0x13, 0x7f, 0xab, 0x08, 0x1d, 0x92, 0x29,
    0x5b, 0xce, 0x2d, 0x53, 0xbe, 0x2c, 0x6c, 0xa6, 0x8b, 0xa8, 0x2c, 0x7f, 0xaa, 0x9c, 0xe2, 0x41,
];

pub const L1_MESSENGER_ADDRESS: Address = address!("0000000000000000000000000000000000008008");

#[inline(always)]
fn b160_to_b256(addr: Address) -> B256 {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice()); // pad left, store address in low 20 bytes
    B256::from(out)
}

/// Run the L1 messenger precompile.
pub fn l1_messenger_precompile_call<CTX>(
    ctx: &mut CTX,
    caller: Address,
    is_static: bool,
    gas_limit: u64,
    call_value: U256,
    mut calldata: &[u8],
) -> InterpreterResult
where
    CTX: ContextTr<Cfg: Cfg<Spec = ZkSpecId>>,
{
    let mut gas = Gas::new(gas_limit);
    let oog_error = || InterpreterResult::new(InstructionResult::OutOfGas, [].into(), Gas::new(0));
    let error = move || InterpreterResult::new(InstructionResult::Revert, [].into(), gas);

    if !gas.record_cost(10) {
        return oog_error();
    }

    if calldata.len() < 4 {
        return error();
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    match selector {
        s if s == SEND_TO_L1_SELECTOR => {
            if call_value != U256::ZERO {
                return error();
            }
            if is_static {
                return error();
            }

            // decoding according to setDeployedCodeEVM(address,bytes)
            calldata = &calldata[4..];
            let abi_encoded_message_len: u32 = match calldata.len().try_into() {
                Ok(len) => len,
                Err(_) => {
                    return error();
                }
            };

            if abi_encoded_message_len < 32 {
                return error();
            }

            let message_offset: u32 = match U256::from_be_slice(&calldata[..32]).try_into() {
                Ok(offset) => offset,
                Err(_) => {
                    return error();
                }
            };

            // Note, that in general, Solidity allows to have non-strict offsets, i.e. it should be possible
            // to call a function with offset pointing to a faraway point in calldata. However,
            // when explicitly calling a contract Solidity encodes it via a strict encoding and allowing
            // only standard encoding here allows for cheaper and easier implementation.
            if message_offset != 32 {
                return error();
            }
            // length located at message_offset..message_offset+32
            // we want to check that message_offset+32 will not overflow u32
            let length_encoding_end = match message_offset.checked_add(32) {
                Some(length_encoding_end) => length_encoding_end,
                None => {
                    return error();
                }
            };
            if abi_encoded_message_len < length_encoding_end {
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
            if abi_encoded_message_len < message_end {
                return error();
            }
            // Note, that in general, Solidity allows to have non-strict offsets, i.e. it should be possible
            // to call a function with offset pointing to a faraway point in calldata. However,
            // when explicitly calling a contract Solidity encodes it via a strict encoding and allowing
            // only standard encoding here allows for cheaper and easier implementation.
            if !abi_encoded_message_len.is_multiple_of(32) {
                return error();
            }

            let message = &calldata[(length_encoding_end as usize)..message_end as usize];
            let words = (message.len() as u64).div_ceil(32);
            let keccak256_gas = KECCAK256.saturating_add(KECCAK256WORD.saturating_mul(words));
            let log_gas = LOG
                .saturating_add(LOGTOPIC.saturating_mul(3))
                // no data payload, but include formula for completeness:
                .saturating_add(LOGDATA.saturating_mul(message.len() as u64));
            let needed_gas = keccak256_gas + log_gas;
            if !gas.record_cost(needed_gas) {
                return oog_error();
            }
            let message_hash = keccak256(message);
            let topics = vec![
                B256::from_slice(&L1_MESSAGE_SENT_TOPIC),
                b160_to_b256(caller),
                message_hash,
            ];
            let log = Log {
                address: L1_MESSENGER_ADDRESS,
                data: LogData::new_unchecked(topics, Bytes::from(Vec::from(calldata))),
            };
            ctx.journal_mut().log(log);
            InterpreterResult::new(InstructionResult::Return, message_hash.into(), gas)
        }
        _ => error(),
    }
}
