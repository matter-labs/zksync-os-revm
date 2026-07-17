//! Contains the `[ZkSpecId]` type and its implementation.
use core::str::FromStr;
use revm::primitives::hardfork::{SpecId, UnknownHardfork};

/// Identifies which EVM variant should be used during execution.
/// Differences between variants may include supported opcodes,
/// available precompiles, and gas-charging rules.
///
/// Note: The ZKsync OS Server is responsible for mapping its own
/// `ExecutionVersion` to one of these spec IDs.
/// Default is the latest supported spec.
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
    AtlasV2,
    #[default]
    AtlasV3,
}

impl ZkSpecId {
    /// Converts the [`ZkSpecId`] into a [`SpecId`].
    pub const fn into_eth_spec(self) -> SpecId {
        match self {
            Self::AtlasV1 | Self::AtlasV2 | Self::AtlasV3 => SpecId::CANCUN,
        }
    }

    /// Checks whether a feature introduced in `self` is enabled under `other`.
    ///
    /// This returns `true` when `other` is the same or newer than `self`.
    pub const fn is_enabled_in(self, other: ZkSpecId) -> bool {
        self as u8 <= other as u8
    }

    /// Whether EIP-7702 (set-code txs) is enabled. `AtlasV3` is "Cancun + 7702":
    /// the eth spec stays Cancun (see [`Self::into_eth_spec`]); this only adds 7702.
    pub const fn supports_eip7702(self) -> bool {
        ZkSpecId::AtlasV3.is_enabled_in(self)
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
            name::ATLASV3 => Ok(ZkSpecId::AtlasV3),
            _ => Err(UnknownHardfork),
        }
    }
}

impl From<ZkSpecId> for &'static str {
    fn from(spec_id: ZkSpecId) -> Self {
        match spec_id {
            ZkSpecId::AtlasV1 => name::ATLASV1,
            ZkSpecId::AtlasV2 => name::ATLASV2,
            ZkSpecId::AtlasV3 => name::ATLASV3,
        }
    }
}

/// String identifiers for ZKsync OS hardforks
pub mod name {
    /// Initial spec name.
    pub const ATLASV1: &str = "AtlasV1";
    pub const ATLASV2: &str = "AtlasV2";
    pub const ATLASV3: &str = "AtlasV3";
}
