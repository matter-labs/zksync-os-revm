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
    AtlasV3,
    AtlasV4,
    /// ZKsync OS 0.6.0 (protocol v34). The AtlasV4 EVM rules; the chain config
    /// adds L1 transaction filtering and large contracts, which reach REVM as
    /// operator hints and `CfgEnv::limit_contract_code_size`.
    AtlasV5,
    /// The ZKsync OS release after 0.6.0 (protocol v36). AtlasV5 plus the
    /// L1SLOAD precompile on chains that enable it.
    #[default]
    AtlasV6,
}

impl ZkSpecId {
    /// Converts the [`ZkSpecId`] into a [`SpecId`].
    pub const fn into_eth_spec(self) -> SpecId {
        match self {
            Self::AtlasV1 | Self::AtlasV2 | Self::AtlasV3 => SpecId::CANCUN,
            Self::AtlasV4 | Self::AtlasV5 | Self::AtlasV6 => SpecId::OSAKA,
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

    /// Whether the handler must take the EIP-7702 rules from Prague.
    ///
    /// The eth spec of `AtlasV3` is Cancun, which rejects set-code
    /// transactions and prices an authorization list at zero. The handler
    /// therefore admits the transaction, meters the intrinsic gas and applies
    /// the authorization refund under Prague, and holds the EIP-7623 calldata
    /// floor off. A spec whose eth spec already reaches Prague gets those
    /// rules from revm.
    pub const fn borrows_eip7702_from_prague(self) -> bool {
        self.supports_eip7702() && !self.into_eth_spec().is_enabled_in(SpecId::PRAGUE)
    }

    /// Whether the spec has the L1SLOAD precompile; a chain still has to enable it.
    pub const fn supports_l1sload(self) -> bool {
        ZkSpecId::AtlasV6.is_enabled_in(self)
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
            name::ATLASV4 => Ok(ZkSpecId::AtlasV4),
            name::ATLASV5 => Ok(ZkSpecId::AtlasV5),
            name::ATLASV6 => Ok(ZkSpecId::AtlasV6),
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
            ZkSpecId::AtlasV4 => name::ATLASV4,
            ZkSpecId::AtlasV5 => name::ATLASV5,
            ZkSpecId::AtlasV6 => name::ATLASV6,
        }
    }
}

/// String identifiers for ZKsync OS hardforks
pub mod name {
    /// Initial spec name.
    pub const ATLASV1: &str = "AtlasV1";
    pub const ATLASV2: &str = "AtlasV2";
    pub const ATLASV3: &str = "AtlasV3";
    pub const ATLASV4: &str = "AtlasV4";
    pub const ATLASV5: &str = "AtlasV5";
    pub const ATLASV6: &str = "AtlasV6";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_v5_runs_osaka() {
        assert_eq!(ZkSpecId::AtlasV5.into_eth_spec(), SpecId::OSAKA);
        assert!(ZkSpecId::AtlasV4.is_enabled_in(ZkSpecId::AtlasV5));
        assert!(!ZkSpecId::AtlasV5.is_enabled_in(ZkSpecId::AtlasV4));
        assert!(ZkSpecId::AtlasV5.supports_eip7702());
        assert!(!ZkSpecId::AtlasV5.borrows_eip7702_from_prague());
        assert_eq!("AtlasV5".parse::<ZkSpecId>().ok(), Some(ZkSpecId::AtlasV5));
        assert_eq!(<&'static str>::from(ZkSpecId::AtlasV5), "AtlasV5");
    }

    #[test]
    fn atlas_v6_is_the_latest_spec_and_adds_l1sload() {
        assert_eq!(ZkSpecId::default(), ZkSpecId::AtlasV6);
        assert_eq!(ZkSpecId::AtlasV6.into_eth_spec(), SpecId::OSAKA);
        assert!(ZkSpecId::AtlasV6.supports_l1sload());
        assert!(!ZkSpecId::AtlasV5.supports_l1sload());
        assert_eq!("AtlasV6".parse::<ZkSpecId>().ok(), Some(ZkSpecId::AtlasV6));
        assert_eq!(<&'static str>::from(ZkSpecId::AtlasV6), "AtlasV6");
    }
}
