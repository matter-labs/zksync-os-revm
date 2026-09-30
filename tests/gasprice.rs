use revm::{
    ExecuteEvm,
    context::TxEnv,
    database::{CacheDB, EmptyDB},
    primitives::{Address, B256, Bytes, TxKind, U256, address},
    state::{AccountInfo, Bytecode},
};
use zksync_os_revm::{
    ZKsyncTx, ZkBuilder, ZkSpecId,
    constants::BASE_TOKEN_HOLDER_ADDRESS,
    transaction::priority_tx::{L1_PRIORITY_TRANSACTION_TYPE, UPGRADE_TRANSACTION_TYPE},
    zk_context,
};

const CALLER: Address = address!("0000000000000000000000000000000000100001");
const TARGET: Address = address!("0000000000000000000000000000000000100002");
const INITIAL_BALANCE: u64 = 1_000_000_000_000_000_000;
const GAS_LIMIT: u64 = 200_000;
const GAS_PRICE: u128 = 2_000_000_000;
const TIP: u128 = 1_000_000_000;
const ALL_SPECS: [ZkSpecId; 4] = [
    ZkSpecId::AtlasV1,
    ZkSpecId::AtlasV2,
    ZkSpecId::AtlasV3,
    ZkSpecId::AtlasV4,
];
// GASPRICE PUSH1 1 ADD PUSH0 SSTORE STOP. Adding one ensures a zero gas
// price still produces a storage write that the consistency checker compares.
const CODE: &[u8] = &[0x3a, 0x60, 0x01, 0x01, 0x5f, 0x55, 0x00];

/// Returns slot zero, the caller's final balance, and the gas used.
fn execute_gasprice(
    spec: ZkSpecId,
    basefee: u64,
    create: bool,
    tx_type: u8,
    priority_fee: Option<u128>,
) -> (U256, U256, u64) {
    let mut db = CacheDB::new(EmptyDB::default());
    for address in [CALLER, BASE_TOKEN_HOLDER_ADDRESS] {
        db.insert_account_info(
            address,
            AccountInfo {
                balance: U256::from(INITIAL_BALANCE),
                ..Default::default()
            },
        );
    }
    if !create {
        db.insert_account_info(
            TARGET,
            AccountInfo {
                code: Some(Bytecode::new_raw(Bytes::from_static(CODE))),
                ..Default::default()
            },
        );
    }
    let mut evm = zk_context(db, spec)
        .modify_block_chained(|block| block.basefee = basefee)
        .build_zk();
    evm.0.ctx.journaled_state.set_tx_number(0);
    let tx = ZKsyncTx::builder()
        .base(
            TxEnv::builder()
                .caller(CALLER)
                .kind(if create {
                    TxKind::Create
                } else {
                    TxKind::Call(TARGET)
                })
                .data(if create {
                    Bytes::from_static(CODE)
                } else {
                    Bytes::new()
                })
                .nonce(0)
                .gas_limit(GAS_LIMIT)
                .gas_price(GAS_PRICE)
                .gas_priority_fee(priority_fee)
                .tx_type(Some(tx_type)),
        )
        .mint(U256::from(GAS_LIMIT) * U256::from(GAS_PRICE))
        .refund_recipient(Some(CALLER))
        .tx_hash(B256::repeat_byte(0x17))
        .build_fill()
        .expect("transaction builds");
    let result = evm.transact(tx).expect("transaction executes");
    assert!(result.result.is_success(), "{:?}", result.result);
    let target = if create { CALLER.create(0) } else { TARGET };
    (
        result.state[&target].storage[&U256::ZERO].present_value,
        result.state[&CALLER].info.balance,
        result.result.tx_gas_used(),
    )
}

#[test]
fn zero_base_fee_l2_gasprice_matches_zero_fee_accounting() {
    for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4] {
        for create in [false, true] {
            for (tx_type, tip) in [(0, None), (2, Some(TIP))] {
                let (slot, balance, _) = execute_gasprice(spec, 0, create, tx_type, tip);
                assert_eq!(slot, U256::ONE, "{spec:?}, create={create}, type={tx_type}");
                assert_eq!(balance, U256::from(INITIAL_BALANCE));
            }
        }
    }
}

#[test]
fn zero_tip_and_zero_base_fee_keep_gasprice_zero() {
    for spec in [ZkSpecId::AtlasV3, ZkSpecId::AtlasV4] {
        let (slot, balance, _) = execute_gasprice(spec, 0, false, 2, Some(0));
        assert_eq!(slot, U256::ONE);
        assert_eq!(balance, U256::from(INITIAL_BALANCE));
    }
}

#[test]
fn nonzero_base_fee_preserves_effective_gasprice() {
    for spec in ALL_SPECS {
        for (tx_type, tip, expected) in [
            (0, None, GAS_PRICE),
            (2, Some(0), TIP),
            (2, Some(TIP / 2), TIP + TIP / 2),
            (2, Some(GAS_PRICE), GAS_PRICE),
        ] {
            let (slot, balance, gas_used) = execute_gasprice(spec, TIP as u64, false, tx_type, tip);
            assert_eq!(slot, U256::from(expected + 1), "{spec:?}, type={tx_type}");
            assert_eq!(
                U256::from(INITIAL_BALANCE) - balance,
                U256::from(gas_used) * U256::from(expected)
            );
        }
    }
}

#[test]
fn earlier_specs_preserve_zero_base_fee_gasprice() {
    for spec in [ZkSpecId::AtlasV1, ZkSpecId::AtlasV2] {
        for (tx_type, tip, expected) in [(0, None, GAS_PRICE), (2, Some(TIP), TIP)] {
            let (slot, balance, gas_used) = execute_gasprice(spec, 0, false, tx_type, tip);
            assert_eq!(slot, U256::from(expected + 1), "{spec:?}, type={tx_type}");
            assert_eq!(
                U256::from(INITIAL_BALANCE) - balance,
                U256::from(gas_used) * U256::from(expected)
            );
        }
    }
}

#[test]
fn zero_base_fee_l1_and_upgrade_transactions_keep_their_gasprice() {
    for spec in ALL_SPECS {
        for tx_type in [L1_PRIORITY_TRANSACTION_TYPE, UPGRADE_TRANSACTION_TYPE] {
            let (slot, _, _) = execute_gasprice(spec, 0, false, tx_type, None);
            assert_eq!(slot, U256::from(GAS_PRICE + 1), "{spec:?}, type={tx_type}");
        }
    }
}
