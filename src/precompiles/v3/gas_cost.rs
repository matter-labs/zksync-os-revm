/// Gas cost per byte of bytecode for force deployments.
const SET_BYTECODE_DETAILS_EXTRA_GAS_PER_BYTE: u64 = 50;

pub fn set_bytecode_details_extra_gas(bytecode_len: u64) -> u64 {
    SET_BYTECODE_DETAILS_EXTRA_GAS_PER_BYTE * bytecode_len
}
