# Changelog

## Unreleased (compared to `main` @ `616c360`)

### Added
- Introduced `AtlasV3` spec support with new `v3` precompile module wiring.
- Added v3 hook precompiles:
  - `L1_MESSENGER_HOOK_ADDRESS` (`0x...7001`)
  - `SET_BYTECODE_ON_ADDRESS_HOOK_ADDRESS` (`0x...7002`)
  - `MINT_BASE_TOKEN_HOOK_ADDRESS` (`0x...7100`)
- Added AtlasV3 treasury-based L1->L2 accounting path using `BASE_TOKEN_HOLDER_ADDRESS`.
- Added service transaction support via `service_tx` flag on `ZKsyncTx`.
- Added `is_service_tx()` to `ZkTxTr` (with backward-compatible default implementation returning `false`).
- Added modular force-fail handling through `execution()` / `inspect_execution()` path instead of relying on `run_without_catch_error`.

### Changed
- Default `ZkSpecId` is now `AtlasV3`.
- `ZKsyncPrecompiles::default()` now uses `ZkSpecId::default()`.
- `ZkContext::default()` now uses `ZkSpecId::default()` (aligned with spec default).
- `ZkSpecId::is_enabled_in()` semantics were corrected to `self <= other`.
- For `AtlasV3`, if block base fee is zero, effective tx gas price is forced to zero (priority fee ignored).
- For `AtlasV3` L1->L2 txs, intrinsic/floor gas checks saturate to tx gas limit instead of hard-failing.
- Service txs do not bump nonce in handler call-path validation.
- P256 precompile warming is now spec-aware (allowed for `AtlasV3`, filtered for `AtlasV1/V2`).

### Fixed
- Added calldata-length guard in v3 deployer before selector slicing to avoid panic on short calldata.
- Added bytecode-length guard in `set_bytecode_on_address_internal` before slicing DB bytecode.
- Replaced per-call `Vec<Address>` allowlists in v3 hook validation with `&[Address]` slices.
- Removed redundant static-call check in v3 deployer (already covered by common hook input check).
- Hardened refund calculation by clamping negative refunded gas before conversion.
- Removed unused `PostExecutionTransferFailed` error variant.
- Corrected v3 precompile doc comments and simplified redundant calldata hash conversion.
- Deduplicated `CONTRACT_DEPLOYER_ADDRESS` constant in v3 precompiles.

### Compatibility Notes
- `AtlasV3` is intentionally the default spec in this version.
- External `ZkTxTr` implementors are backward-compatible after this update because `is_service_tx()` has a default implementation.
- External code constructing `ZKsyncTx` via struct literals must include the new `service_tx` field (or migrate to builder/constructors).
- External uses of `is_enabled_in()` should be reviewed because semantics are now corrected and explicitly documented.
