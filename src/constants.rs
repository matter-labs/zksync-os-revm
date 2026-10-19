use revm::primitives::{Address, address};

pub const L2_BASE_TOKEN_ADDRESS: Address = address!("000000000000000000000000000000000000800a");
pub const BASE_TOKEN_HOLDER_ADDRESS: Address = address!("0000000000000000000000000000000000010011");
pub const L2_ASSET_TRACKER_ADDRESS: Address = address!("000000000000000000000000000000000001000f");
pub const CONTRACT_DEPLOYER_ADDRESS: Address = address!("0000000000000000000000000000000000008006");
pub const COMPLEX_UPGRADER_ADDRESS: Address = address!("000000000000000000000000000000000000800f");

/// EIP-2935 historical block hash contract (canonical mainnet address).
pub const HISTORY_STORAGE_ADDRESS: Address = address!("0000F90827F1C53a10cb7A02335B175320002935");

/// Deployed-code limit of a chain with large contracts enabled (ZKsync OS
/// `LARGE_MAX_CODE_SIZE`, 0.6.0 onwards). Such a chain sets it as
/// `CfgEnv::limit_contract_code_size`; the initcode limit follows at twice it.
pub const LARGE_CONTRACTS_MAX_CODE_SIZE: usize = 0x10000;
