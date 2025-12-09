//! Precompiles V1
//!
//! Initial precompiles implementation kept only for legacy compatibility.
//! This version is not used by the current system.
//!
//! Please note it does not charge gas correctly, and is *NOT*
//! fully aligned with the ZKsync OS implementation.
//! As a result, the consistency checker may report divergences.
//! However there were no divergance trigger on Stage/Testnet/Mainnet chains.
pub mod deployer;
pub mod l1_messenger;
pub mod l2_base_token;
