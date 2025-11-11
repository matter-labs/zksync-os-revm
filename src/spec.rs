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
    AtlasV1,
    #[default]
    AtlasV2,
}

impl ZkSpecId {
    /// Converts the [`ZkSpecId`] into a [`SpecId`].
    pub const fn into_eth_spec(self) -> SpecId {
        match self {
            Self::AtlasV1 => SpecId::CANCUN,
            Self::AtlasV2 => SpecId::CANCUN,
        }
    }

    /// Inclusive bounds of supported ZKsync OS Server execution *versions* for this spec.
    /// If a single version is supported, `min == max`.
    pub const fn supported_exec_version_bounds(self) -> (u64, u64) {
        match self {
            ZkSpecId::AtlasV1 => (1, 3),
            ZkSpecId::AtlasV2 => (4, 4),
        }
    }

    /// Checks if the [`ZkSpecId`] is enabled in the other [`ZkSpecId`].
    pub const fn is_enabled_in(self, other: ZkSpecId) -> bool {
        other as u8 <= self as u8
    }

    /// Fast const check for a specific version.
    pub const fn supports_exec_version(self, v: u64) -> bool {
        let (min, max) = self.supported_exec_version_bounds();
        v >= min && v <= max
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
            name::ATLASV1 => Ok(ZkSpecId::AtlasV1),
            name::ATLASV2 => Ok(ZkSpecId::AtlasV2),
            _ => Err(UnknownHardfork),
        }
    }
}

impl From<ZkSpecId> for &'static str {
    fn from(spec_id: ZkSpecId) -> Self {
        match spec_id {
            ZkSpecId::AtlasV1 => name::ATLASV1,
            ZkSpecId::AtlasV2 => name::ATLASV2,
        }
    }
}

/// String identifiers for ZKsync OS hardforks
pub mod name {
    /// Initial spec name.
    pub const ATLASV1: &str = "AtlasV1";
    pub const ATLASV2: &str = "AtlasV2";
}
