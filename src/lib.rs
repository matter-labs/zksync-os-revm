//! ZKsync OS specific constants, types, and helpers.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod api;
pub mod evm;
pub mod handler;
pub mod precompiles;
pub mod spec;
pub mod transaction;

pub use api::{
    builder::ZkBuilder,
    default_ctx::{DefaultZk, ZkContext},
};
pub use evm::ZKsyncEvm;
pub use spec::*;
pub use transaction::{ZKsyncTx, error::ZKsyncTxError};
