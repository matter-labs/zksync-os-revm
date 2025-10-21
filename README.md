# ZKsync OS REVM

This repo contains the custom EVM implementation compatible with the ZKsync OS execution environment based on REVM. In addition to standard EVM functionality, it supports ZKsync OS extensions:
- ZKsync L1 -> L2 transactions
- ZKsync upgrade transaction
- ZKsync OS hooks
    - Deployer
    - L2 -> L1 messenger
    - L2 Base token

This code can be used as an alternative implementation of ZKsync OS, but its primary use for now is the consistency checker in the ZKsync OS server. The ZKsync OS server executes transactions in its native environment and then re-executes the transactions on this variant of REVM.

### Gas override & transaction force failing 

One of the specific features implemented for the consistency checker is gas override. The transaction may provide a `gasUsed`. This value will be used as the amount of gas used by the transaction instead of vanilla EVM. This is needed because ZKsync OS has a concept of double accounting, and when a transaction uses a lot of native resources, the user is charged more gas at the end of the transaction. 

The other feature is force transaction failing. When the transaction has the `force_fail` flag set to `true`, REVM assumes the transaction will fail and skips execution while bumping the nonce and charging fees. This is needed for simpler re-execution in the main ZKsync OS node.
