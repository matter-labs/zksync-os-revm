use revm::interpreter::gas::{KECCAK256, KECCAK256WORD, LOG, LOGDATA, LOGTOPIC};
use std::ops::Mul;

use crate::precompiles::l1_messenger::L2_TO_L1_LOG_SERIALIZE_SIZE;

pub const HOOK_BASE_GAS_COST: u64 = 100;

/// Gas cost per byte of bytecode for force deployments.
const SET_BYTECODE_DETAILS_EXTRA_GAS_PER_BYTE: u64 = 50;

pub fn keccak256_gas_cost(len: usize) -> u64 {
    let words = len.div_ceil(32);
    KECCAK256.saturating_add(KECCAK256WORD.saturating_mul(words as u64))
}

pub fn l1_message_gas_cost(message_len: usize) -> u64 {
    let hashing_cost = keccak256_gas_cost(L2_TO_L1_LOG_SERIALIZE_SIZE)
        + keccak256_gas_cost(64).mul(3)
        + keccak256_gas_cost(message_len);
    let log_cost = LOG + LOGDATA * message_len as u64;
    hashing_cost + log_cost
}

pub fn log_gas_cost(topics: u64, data: u64) -> u64 {
    let static_cost = LOG;
    let topic_cost = LOGTOPIC * topics;
    let len_cost = data * LOGDATA;
    static_cost + topic_cost + len_cost
}

pub fn set_bytecode_details_extra_gas(bytecode_len: u64) -> u64 {
    SET_BYTECODE_DETAILS_EXTRA_GAS_PER_BYTE * bytecode_len
}
