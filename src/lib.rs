//! ZKsync OS specific constants, types, and helpers.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod api;
pub mod block_system_calls;
pub mod constants;
pub mod evm;
pub mod handler;
pub mod journal;
pub mod l2_to_l1_logs;
pub mod precompiles;
pub mod spec;
pub mod transaction;

pub use api::{
    builder::ZkBuilder,
    default_ctx::{DefaultZk, ZkContext, zk_context},
};
pub use block_system_calls::apply_pre_block_system_calls;
pub use evm::ZKsyncEvm;
pub use journal::ZkJournal;
pub use spec::*;
pub use transaction::{ZKsyncTx, error::ZKsyncTxError};
