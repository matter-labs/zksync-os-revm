//! Contains the `[ZkSpecId]` type and its implementation.
use core::str::FromStr;
use revm::primitives::hardfork::{SpecId, UnknownHardfork};

/// ZKsync OS spec id.
#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[allow(non_camel_case_types)]
pub enum ZkSpecId {
    #[default]
    Atlas,
}

impl ZkSpecId {
    /// Converts the [`ZkSpecId`] into a [`SpecId`].
    pub const fn into_eth_spec(self) -> SpecId {
        match self {
            Self::Atlas => SpecId::CANCUN,
        }
    }

    /// Checks if the [`ZkSpecId`] is enabled in the other [`ZkSpecId`].
    pub const fn is_enabled_in(self, other: ZkSpecId) -> bool {
        other as u8 <= self as u8
    }
}

impl From<ZkSpecId> for SpecId {
    fn from(spec: ZkSpecId) -> Self {
        spec.into_eth_spec()
    }
}

impl FromStr for ZkSpecId {
    type Err = UnknownHardfork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            name::ATLAS => Ok(ZkSpecId::Atlas),
            _ => Err(UnknownHardfork),
        }
    }
}

impl From<ZkSpecId> for &'static str {
    fn from(spec_id: ZkSpecId) -> Self {
        match spec_id {
            ZkSpecId::Atlas => name::ATLAS,
        }
    }
}

/// String identifiers for ZKsync OS hardforks
pub mod name {
    /// Initial spec name.
    pub const ATLAS: &str = "Atlas";
}
