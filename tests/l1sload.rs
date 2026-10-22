//! L1SLOAD (`0x101`) against a real mainnet witness: the header of block
//! 26239270 and `eth_getProof` results for `L1MessageRoot`, USDC and an absent
//! account (the same fixture as ZKsync OS's `tests/instances/l1sload`).
//!
//! A probe contract calls L1SLOAD, then `L2InteropRootStorage`, whose test code
//! reads the anchor slots, and reports status, gas and output of both calls.
//! Before that it can call a reader contract that makes more L1SLOAD calls in
//! the same transaction.
use revm::{
    ExecuteEvm,
    context::TxEnv,
    context_interface::result::{EVMError, ExecutionResult, Output},
    database::{CacheDB, EmptyDB},
    primitives::{Address, B256, Bytes, HashMap, TxKind, U256, address, keccak256},
    state::{AccountInfo, Bytecode},
};
use serde::Deserialize;
use zksync_os_revm::{
    L1Witness, ZKsyncTx, ZkBuilder, ZkContext, ZkSpecId,
    api::builder::DefaultZKsyncEvm,
    precompiles::l1sload::{
        L1_ANCHOR_MAX_LAG, L1SLOAD_ADDRESS, L1SLOAD_ANCHOR_BLOCK_HASH_SLOT, L1SLOAD_ANCHOR_HOLDER,
        L1SLOAD_ANCHOR_TIMESTAMP_SLOT, l1sload_gas,
    },
    zk_context,
};

type Evm = DefaultZKsyncEvm<ZkContext<CacheDB<EmptyDB>>>;

const FIXTURE: &str = include_str!("fixtures/l1sload_mainnet.json");

const CALLER: Address = address!("0000000000000000000000000000000000000c0f");
const PROBE: Address = address!("0000000000000000000000000000000000001000");
const READER: Address = address!("0000000000000000000000000000000000002000");
/// L1 time of the anchor; the block runs a minute later.
const ANCHOR_TIME: u64 = 1_700_000_000;
const TX_GAS_LIMIT: u64 = 5_000_000;
/// Gas the probe passes to L1SLOAD unless a test says otherwise.
const CALL_GAS: u64 = 100_000;
/// Gas the probe passes to the reader.
const READER_GAS: u64 = 3_000_000;

/// EIP-2929 access costs.
const WARM_ACCESS: u64 = 100;
const COLD_ACCOUNT_ACCESS: u64 = 2600;
const COLD_SLOAD: u64 = 2100;
/// What a CALL or CALLCODE with value adds to its cost. The callee also gets
/// a 2300 stipend on top of the gas passed to it.
const CALL_VALUE_COST: u64 = 9000;
/// What a CALL with value to an empty account adds to its cost.
const NEW_ACCOUNT_COST: u64 = 25000;

const SPECS_WITHOUT_L1SLOAD: [ZkSpecId; 5] = [
    ZkSpecId::AtlasV1,
    ZkSpecId::AtlasV2,
    ZkSpecId::AtlasV3,
    ZkSpecId::AtlasV4,
    ZkSpecId::AtlasV5,
];

#[derive(Clone, Deserialize)]
struct Read {
    label: String,
    address: Address,
    keys: Vec<B256>,
    values: Vec<B256>,
    account_proof: Vec<B256>,
    storage_proofs: Vec<Vec<B256>>,
}

#[derive(Deserialize)]
struct Fixture {
    block_hash: B256,
    header_rlp: Bytes,
    reads: Vec<Read>,
    preimages: HashMap<B256, Bytes>,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).unwrap()
}

impl Fixture {
    /// What a sequencer's source serves for `eth_getProof(read.address, keys)`
    /// at the anchor, as preimages only: the header, the account proof and
    /// each key's storage proof.
    fn served(&self, read: &Read, keys: &[B256]) -> Vec<Vec<u8>> {
        let node = |hash: &B256| self.preimages[hash].to_vec();
        let mut served = vec![self.header_rlp.to_vec()];
        served.extend(read.account_proof.iter().map(node));
        for key in keys {
            let index = read.keys.iter().position(|k| k == key).unwrap();
            served.extend(read.storage_proofs[index].iter().map(node));
        }
        served
    }

    fn witness(&self, read: &Read, keys: &[B256]) -> L1Witness {
        L1Witness::from_preimages(self.served(read, keys))
    }

    /// An AtlasV6 run at the fixture's anchor that reads `keys` of `read`,
    /// with exactly the nodes a source serves for them.
    fn run(&self, read: &Read, keys: &[B256]) -> Run {
        Run {
            spec: ZkSpecId::AtlasV6,
            witness: Some(self.witness(read, keys)),
            anchor: Some(self.block_hash),
            block_time: ANCHOR_TIME + 60,
            input: input(read.address, keys),
            kind: CallKind::Call,
            value: 0,
            tx_value: 0,
            call_gas: CALL_GAS,
            reads_before: None,
        }
    }
}

fn input(address: Address, keys: &[B256]) -> Vec<u8> {
    let mut input = address.to_vec();
    for key in keys {
        input.extend_from_slice(key.as_slice());
    }
    input
}

/// How the probe calls L1SLOAD.
#[derive(Clone, Copy, Debug)]
enum CallKind {
    Call,
    CallCode,
    DelegateCall,
}

impl CallKind {
    fn opcode(self) -> u8 {
        match self {
            Self::Call => 0xf1,
            Self::CallCode => 0xf2,
            Self::DelegateCall => 0xf4,
        }
    }

    fn takes_value(self) -> bool {
        !matches!(self, Self::DelegateCall)
    }

    /// Gas between the two GAS readings of [`Code::measured_call`], besides
    /// the call itself: the pushes and the second GAS.
    fn measured_call_overhead(self) -> u64 {
        let pushes = if self.takes_value() { 7 } else { 6 };
        pushes * 3 + 2
    }
}

/// Minimal EVM assembler: every constant is a PUSH32 (3 gas).
#[derive(Default)]
struct Code(Vec<u8>);

impl Code {
    const STOP: u8 = 0x00;
    const MSTORE: u8 = 0x52;
    const MLOAD: u8 = 0x51;
    const ADD: u8 = 0x01;
    const SUB: u8 = 0x03;
    const SLOAD: u8 = 0x54;
    const POP: u8 = 0x50;
    const GAS: u8 = 0x5a;
    const SWAP1: u8 = 0x90;
    const DUP3: u8 = 0x82;
    const PUSH0: u8 = 0x5f;
    const CALLDATASIZE: u8 = 0x36;
    const CALLDATACOPY: u8 = 0x37;
    const RETURNDATASIZE: u8 = 0x3d;
    const RETURNDATACOPY: u8 = 0x3e;
    const CALL: u8 = 0xf1;
    const RETURN: u8 = 0xf3;
    const REVERT: u8 = 0xfd;

    fn op(&mut self, op: u8) -> &mut Self {
        self.0.push(op);
        self
    }

    fn push_word(&mut self, value: U256) -> &mut Self {
        self.0.push(0x7f);
        self.0.extend_from_slice(&value.to_be_bytes::<32>());
        self
    }

    fn push(&mut self, value: impl TryInto<u64>) -> &mut Self {
        let value = value
            .try_into()
            .unwrap_or_else(|_| unreachable!("fits in u64"));
        self.push_word(U256::from(value))
    }

    fn push_address(&mut self, address: Address) -> &mut Self {
        self.push_word(U256::from_be_slice(address.as_slice()))
    }

    /// Write `bytes` to memory at `offset`, a word at a time.
    fn store_bytes(&mut self, offset: usize, bytes: &[u8]) -> &mut Self {
        for (i, chunk) in bytes.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            self.push_word(U256::from_be_bytes(word))
                .push(offset + 32 * i)
                .op(Self::MSTORE);
        }
        self
    }

    /// CALL `to` with no return data, and drop the status.
    fn plain_call(&mut self, to: Address, value: u64, args: (usize, usize), gas: u64) -> &mut Self {
        self.push(0u64)
            .push(0u64)
            .push(args.1)
            .push(args.0)
            .push(value)
            .push_address(to)
            .push(gas)
            .op(Self::CALL)
            .op(Self::POP)
    }

    /// Call `to` and store the status at `out` and the gas the call took at
    /// `out + 32`.
    #[allow(clippy::too_many_arguments)]
    fn measured_call(
        &mut self,
        kind: CallKind,
        to: Address,
        value: u64,
        args: (usize, usize),
        ret: (usize, usize),
        gas: u64,
        out: usize,
    ) -> &mut Self {
        self.op(Self::GAS)
            .push(ret.1)
            .push(ret.0)
            .push(args.1)
            .push(args.0);
        if kind.takes_value() {
            self.push(value);
        }
        self.push_address(to)
            .push(gas)
            .op(kind.opcode())
            .op(Self::GAS)
            // [gas before, status, gas after] -> gas before - gas after
            .op(Self::DUP3)
            .op(Self::SUB)
            .push(out + 32)
            .op(Self::MSTORE)
            .push(out)
            .op(Self::MSTORE)
            .op(Self::POP)
    }

    fn into_bytecode(self) -> Bytecode {
        Bytecode::new_raw(self.0.into())
    }
}

/// Where the probe writes its report: the L1SLOAD call's status, gas and
/// output length, the holder call's status and gas, the two slot reads the
/// holder reports, then the L1SLOAD output.
const REPORT: usize = 0x200;
/// Offset of the L1SLOAD output in the report.
const OUTPUT: usize = 0xe0;

/// The probe: optionally the reader, then L1SLOAD with the calldata, then a
/// call to the anchor holder.
fn probe_code(run: &Run) -> Bytecode {
    let mut code = Code::default();
    code.push(0u64)
        .push(REPORT + 0x200)
        .op(Code::MSTORE) // expand memory up front, so no call pays for it
        .op(Code::CALLDATASIZE)
        .op(Code::PUSH0)
        .op(Code::PUSH0)
        .op(Code::CALLDATACOPY);
    if run.reads_before.is_some() {
        code.plain_call(READER, 0, (0, 0), READER_GAS);
    }
    code.measured_call(
        run.kind,
        L1SLOAD_ADDRESS,
        run.value,
        (0, run.input.len()),
        (0, 0),
        run.call_gas,
        REPORT,
    )
    .op(Code::RETURNDATASIZE)
    .push(REPORT + 0x40)
    .op(Code::MSTORE)
    .op(Code::RETURNDATASIZE)
    .op(Code::PUSH0)
    .push(REPORT + OUTPUT)
    .op(Code::RETURNDATACOPY)
    .measured_call(
        CallKind::Call,
        L1SLOAD_ANCHOR_HOLDER,
        0,
        (0, 0),
        (REPORT + 0xa0, 64),
        CALL_GAS,
        REPORT + 0x60,
    )
    .push(REPORT + 0x40)
    .op(Code::MLOAD)
    .push(OUTPUT)
    .op(Code::ADD)
    .push(REPORT)
    .op(Code::RETURN);
    code.into_bytecode()
}

/// L1SLOAD calls that the reader makes, in the same transaction, before the
/// probe's own call: one call per input, in order.
#[derive(Clone)]
struct ReadsBefore {
    inputs: Vec<Vec<u8>>,
    call_gas: u64,
    /// Whether the reader's frame reverts after its calls.
    revert: bool,
}

impl ReadsBefore {
    fn new(inputs: Vec<Vec<u8>>) -> Self {
        Self {
            inputs,
            call_gas: CALL_GAS,
            revert: false,
        }
    }
}

fn reader_code(reads: &ReadsBefore) -> Bytecode {
    let mut code = Code::default();
    for input in &reads.inputs {
        code.store_bytes(0, input)
            .plain_call(L1SLOAD_ADDRESS, 0, (0, input.len()), reads.call_gas);
    }
    if reads.revert {
        code.op(Code::PUSH0).op(Code::PUSH0).op(Code::REVERT);
    } else {
        code.op(Code::STOP);
    }
    code.into_bytecode()
}

/// Gas each slot read the anchor holder reports takes besides the SLOAD:
/// from after one GAS to the next, SWAP1, SLOAD, POP, GAS.
const HOLDER_REPORT_OVERHEAD: u64 = 3 + 2 + 2;
/// The rest of the holder's code. For each slot: PUSH32, GAS, then SWAP1,
/// SUB, and an MSTORE that grows memory by one word, plus the push of its
/// offset (PUSH0, then PUSH32). Then PUSH32, PUSH0, RETURN.
const HOLDER_UNREPORTED_GAS: u64 = 2 * (3 + 2 + 3 + 3 + 6) + (2 + 3) + (3 + 2);

/// The anchor holder's test code: returns the gas of reading the anchor's
/// block-hash slot, then of its timestamp slot.
fn holder_code() -> Bytecode {
    let mut code = Code::default();
    for (slot, offset) in [
        (L1SLOAD_ANCHOR_BLOCK_HASH_SLOT, 0u64),
        (L1SLOAD_ANCHOR_TIMESTAMP_SLOT, 32),
    ] {
        code.push_word(U256::from_be_bytes(slot.0))
            .op(Code::GAS)
            .op(Code::SWAP1)
            .op(Code::SLOAD)
            .op(Code::POP)
            .op(Code::GAS)
            .op(Code::SWAP1)
            .op(Code::SUB);
        if offset == 0 {
            code.op(Code::PUSH0);
        } else {
            code.push(offset);
        }
        code.op(Code::MSTORE);
    }
    code.push(64u64).op(Code::PUSH0).op(Code::RETURN);
    code.into_bytecode()
}

#[derive(Debug)]
struct Outcome {
    /// Whether the call to `0x101` succeeded.
    success: bool,
    /// Gas the call to `0x101` took, access cost included.
    gas: u64,
    /// Return data of the call to `0x101`.
    output: Vec<u8>,
    /// Access cost of the later call to the anchor holder.
    holder_access: u64,
    /// Cost of the holder's SLOAD of the anchor's block-hash slot.
    holder_sload: u64,
    /// Cost of the holder's SLOAD of the anchor's timestamp slot.
    holder_timestamp_sload: u64,
}

struct Run {
    spec: ZkSpecId,
    witness: Option<L1Witness>,
    anchor: Option<B256>,
    /// Timestamp of the L2 block.
    block_time: u64,
    input: Vec<u8>,
    kind: CallKind,
    /// Value the probe's call passes, for CALL and CALLCODE.
    value: u64,
    /// Value the transaction sends to the probe.
    tx_value: u64,
    call_gas: u64,
    reads_before: Option<ReadsBefore>,
}

impl Run {
    /// A fresh EVM with the probe's state, L1SLOAD on if the run has a witness.
    fn evm(&self) -> Evm {
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            CALLER,
            AccountInfo {
                balance: U256::from(10u64.pow(18)),
                ..Default::default()
            },
        );
        db.insert_account_info(
            PROBE,
            AccountInfo {
                balance: U256::from(10u64.pow(18)),
                code: Some(probe_code(self)),
                ..Default::default()
            },
        );
        if let Some(reads) = &self.reads_before {
            db.insert_account_info(
                READER,
                AccountInfo {
                    balance: U256::from(10u64.pow(18)),
                    code: Some(reader_code(reads)),
                    ..Default::default()
                },
            );
        }
        db.insert_account_info(
            L1SLOAD_ANCHOR_HOLDER,
            AccountInfo {
                code: Some(holder_code()),
                ..Default::default()
            },
        );
        if let Some(anchor) = self.anchor {
            for (slot, value) in [
                (
                    L1SLOAD_ANCHOR_BLOCK_HASH_SLOT,
                    U256::from_be_bytes(anchor.0),
                ),
                (L1SLOAD_ANCHOR_TIMESTAMP_SLOT, U256::from(ANCHOR_TIME)),
            ] {
                db.insert_account_storage(
                    L1SLOAD_ANCHOR_HOLDER,
                    U256::from_be_bytes(slot.0),
                    value,
                )
                .unwrap();
            }
        }

        let evm = zk_context(db, self.spec)
            .modify_block_chained(|block| block.timestamp = U256::from(self.block_time))
            .build_zk();
        match &self.witness {
            Some(witness) => evm.with_l1sload(witness.clone()),
            None => evm,
        }
    }

    /// Run the probe on a fresh EVM.
    fn execute(self) -> Result<Outcome, String> {
        self.transact(&mut self.evm())
    }

    /// Run the probe once on `evm`. `Err` is the replay error of a witness
    /// that does not prove the read.
    fn transact(&self, evm: &mut Evm) -> Result<Outcome, String> {
        let tx = ZKsyncTx::builder()
            .base(
                TxEnv::builder()
                    .caller(CALLER)
                    .kind(TxKind::Call(PROBE))
                    .value(U256::from(self.tx_value))
                    .data(self.input.clone().into())
                    .gas_limit(TX_GAS_LIMIT)
                    .gas_price(0),
            )
            .tx_hash(B256::ZERO)
            .build_fill()
            .expect("transaction builds");
        let result = match evm.transact(tx) {
            Ok(result) => result.result,
            Err(EVMError::Custom(err)) => return Err(err),
            Err(err) => panic!("unexpected EVM error: {err:?}"),
        };
        let ExecutionResult::Success {
            output: Output::Call(report),
            ..
        } = result
        else {
            panic!("the probe did not succeed: {result:?}");
        };

        let word = |offset: usize| U256::from_be_slice(&report[offset..offset + 32]).to::<u64>();
        let holder_call = word(0x80);
        let (hash_read, timestamp_read) = (word(0xa0), word(0xc0));
        Ok(Outcome {
            success: word(0x00) == 1,
            gas: word(0x20) - self.kind.measured_call_overhead(),
            output: report[OUTPUT..OUTPUT + word(0x40) as usize].to_vec(),
            holder_access: holder_call
                - CallKind::Call.measured_call_overhead()
                - HOLDER_UNREPORTED_GAS
                - hash_read
                - timestamp_read,
            holder_sload: hash_read - HOLDER_REPORT_OVERHEAD,
            holder_timestamp_sload: timestamp_read - HOLDER_REPORT_OVERHEAD,
        })
    }
}

fn concat(values: &[B256]) -> Vec<u8> {
    values.iter().flat_map(|value| value.0).collect()
}

/// The replay error's text for a hash the witness has no preimage of.
fn missing_preimage(hash: B256) -> String {
    format!("missing preimage of {hash}")
}

/// Assert a failed call with no output, and that the call took `gas` in all.
fn assert_fails_taking(outcome: &Outcome, gas: u64, what: &str) {
    assert!(!outcome.success, "{what}: the call must fail");
    assert!(outcome.output.is_empty(), "{what}: no output");
    assert_eq!(outcome.gas, gas, "{what}: gas the call took");
}

/// Assert a failure that consumed all the gas a plain CALL passed.
fn assert_consumes_all_gas(outcome: &Outcome, call_gas: u64, what: &str) {
    assert_fails_taking(outcome, WARM_ACCESS + call_gas, what);
}

#[test]
fn reads_mainnet_storage_at_the_anchor() {
    let fx = fixture();
    for read in &fx.reads {
        let outcome = fx
            .run(read, &read.keys)
            .execute()
            .unwrap_or_else(|err| panic!("{}: {err}", read.label));
        assert!(outcome.success, "{}", read.label);
        assert_eq!(outcome.output, concat(&read.values), "{}", read.label);
        assert_eq!(
            outcome.gas,
            WARM_ACCESS + l1sload_gas(read.keys.len()),
            "{}",
            read.label
        );
    }
}

#[test]
fn an_absent_account_and_absent_slots_read_as_zero() {
    let fx = fixture();

    let message_root = &fx.reads[0];
    assert_eq!(message_root.label, "L1MessageRoot");
    let absent_slots = &message_root.keys[2..];
    let outcome = fx.run(message_root, absent_slots).execute().unwrap();
    assert!(outcome.success);
    assert_eq!(outcome.output, vec![0u8; 64]);

    // An absent account has the empty storage root, so its slots need no proof.
    let absent = &fx.reads[ABSENT];
    assert_eq!(absent.label, "Absent account");
    let mut run = fx.run(absent, &[]);
    run.input = input(absent.address, &[B256::ZERO, B256::repeat_byte(0x42)]);
    let outcome = run.execute().unwrap();
    assert!(outcome.success);
    assert_eq!(outcome.output, vec![0u8; 64]);
}

#[test]
fn rejects_malformed_input() {
    let fx = fixture();
    let read = &fx.reads[0];
    let one_key = input(read.address, &read.keys[..1]);
    let cases = [
        ("no keys", read.address.to_vec()),
        ("truncated key", one_key[..one_key.len() - 1].to_vec()),
        ("six keys", input(read.address, &[read.keys[0]; 6])),
    ];
    for (what, bad) in cases {
        let mut run = fx.run(read, &read.keys);
        run.input = bad;
        let outcome = run.execute().unwrap_or_else(|err| panic!("{what}: {err}"));
        assert_consumes_all_gas(&outcome, CALL_GAS, what);
    }
}

/// Value fails the call, whether a CALL or CALLCODE sends it or a DELEGATECALL
/// passes it along, and the callee's stipend is consumed too.
#[test]
fn rejects_value_in_any_kind_of_call() {
    let fx = fixture();
    let read = &fx.reads[0];
    let run = |kind, value, tx_value| {
        let mut run = fx.run(read, &read.keys[..1]);
        run.kind = kind;
        run.value = value;
        run.tx_value = tx_value;
        run.execute().unwrap()
    };

    for kind in [CallKind::DelegateCall, CallKind::CallCode] {
        let outcome = run(kind, 0, 0);
        assert!(outcome.success, "{kind:?} without value");
        assert_eq!(outcome.output, concat(&read.values[..1]), "{kind:?}");
    }

    assert_fails_taking(
        &run(CallKind::Call, 1, 0),
        WARM_ACCESS + CALL_VALUE_COST + NEW_ACCOUNT_COST + CALL_GAS,
        "CALL with value",
    );
    assert_fails_taking(
        &run(CallKind::DelegateCall, 0, 1),
        WARM_ACCESS + CALL_GAS,
        "DELEGATECALL with value",
    );
    // The value goes to the probe itself, so no new account.
    assert_fails_taking(
        &run(CallKind::CallCode, 1, 0),
        WARM_ACCESS + CALL_VALUE_COST + CALL_GAS,
        "CALLCODE with value",
    );
}

#[test]
fn charges_2000_plus_2000_per_key_and_fails_below_it() {
    let fx = fixture();
    let read = &fx.reads[0];
    for num_keys in 1..=read.keys.len() {
        let keys = &read.keys[..num_keys];
        let cost = l1sload_gas(num_keys);

        let mut exact = fx.run(read, keys);
        exact.call_gas = cost;
        let outcome = exact.execute().unwrap();
        assert!(outcome.success, "{num_keys} keys with exactly {cost} gas");
        assert_eq!(outcome.gas, WARM_ACCESS + cost);

        let mut short = fx.run(read, keys);
        short.call_gas = cost - 1;
        let outcome = short.execute().unwrap();
        assert_consumes_all_gas(&outcome, cost - 1, "one gas short");
    }
}

/// The fixture's absent account: the header and its account proof prove any
/// number of its keys, so the cap tests read its keys `0, 1, 2, …`.
const ABSENT: usize = 2;

fn key(i: usize) -> B256 {
    B256::from(U256::from(i))
}

fn keys(range: core::ops::Range<usize>) -> Vec<B256> {
    range.map(key).collect()
}

/// The reader's calls for `keys` of the absent account, four keys a call.
fn calls_reading(fx: &Fixture, keys: &[B256]) -> ReadsBefore {
    let address = fx.reads[ABSENT].address;
    ReadsBefore::new(keys.chunks(4).map(|keys| input(address, keys)).collect())
}

/// The reader's `before`, then the probe's read of `probe_keys` of the
/// absent account.
fn absent_account_run(fx: &Fixture, before: ReadsBefore, probe_keys: &[B256]) -> Run {
    let absent = &fx.reads[ABSENT];
    let mut run = fx.run(absent, &[]);
    run.input = input(absent.address, probe_keys);
    run.reads_before = Some(before);
    run
}

/// One transaction makes at most 64 distinct reads across its L1SLOAD calls; a
/// key it has read before, in an earlier call or the same one, counts once.
#[test]
fn caps_the_distinct_reads_of_a_transaction_at_64() {
    let fx = fixture();

    let outcome = absent_account_run(&fx, calls_reading(&fx, &keys(0..60)), &keys(60..64))
        .execute()
        .unwrap();
    assert!(outcome.success, "the 64th distinct key is read");
    assert_eq!(outcome.output, vec![0u8; 4 * 32]);

    let outcome = absent_account_run(&fx, calls_reading(&fx, &keys(0..64)), &keys(64..65))
        .execute()
        .unwrap();
    assert_consumes_all_gas(&outcome, CALL_GAS, "the 65th distinct key");

    let outcome = absent_account_run(
        &fx,
        calls_reading(&fx, &keys(0..64)),
        &[key(0), key(17), key(63)],
    )
    .execute()
    .unwrap();
    assert!(outcome.success, "re-reads after 64 distinct keys");

    let outcome = absent_account_run(&fx, calls_reading(&fx, &keys(0..63)), &[key(63); 5])
        .execute()
        .unwrap();
    assert!(outcome.success, "five reads of one key count once");
}

/// A call whose new reads would take the transaction past the cap fails
/// before it reads the witness, and adds none of them.
#[test]
fn a_call_over_the_key_cap_adds_no_reads_and_reads_no_witness() {
    let fx = fixture();

    // The witness has no proof for this `L1MessageRoot` key, so reading it
    // would be a replay error.
    let unserved = &fx.reads[0];
    let mut run = absent_account_run(&fx, calls_reading(&fx, &keys(0..64)), &[]);
    run.input = input(unserved.address, &unserved.keys[..1]);
    let outcome = run
        .execute()
        .expect("a call over the cap is a failed call, not a replay error");
    assert_consumes_all_gas(&outcome, CALL_GAS, "over the cap");

    // After 62 keys, one old and three new would make 65. That call adds
    // nothing, so two new keys still fit.
    let mut before = calls_reading(&fx, &keys(0..62));
    before.inputs.push(input(
        fx.reads[ABSENT].address,
        &[key(0), key(62), key(63), key(64)],
    ));
    let outcome = absent_account_run(&fx, before, &[key(64), key(65)])
        .execute()
        .unwrap();
    assert!(outcome.success, "62 + 2 distinct keys after a failed call");
}

/// The cap counts the reads of frames that revert. A call that fails before
/// the read, here for too little gas, adds none.
#[test]
fn the_key_cap_counts_reverted_frames_but_not_failed_calls() {
    let fx = fixture();

    let mut reverted = calls_reading(&fx, &keys(0..64));
    reverted.revert = true;
    let outcome = absent_account_run(&fx, reverted, &keys(64..65))
        .execute()
        .unwrap();
    assert_consumes_all_gas(&outcome, CALL_GAS, "64 keys read in a reverted frame");

    let mut short = calls_reading(&fx, &keys(0..64));
    short.call_gas = l1sload_gas(4) - 1;
    let outcome = absent_account_run(&fx, short, &keys(64..68))
        .execute()
        .unwrap();
    assert!(outcome.success, "calls short of gas read no key");
}

/// `set_l1sload` on an EVM that has already run a transaction changes the
/// warmth of `0x101` for the next one, in both directions.
#[test]
fn set_l1sload_on_a_used_evm_updates_the_warm_set() {
    let fx = fixture();
    let read = &fx.reads[0];
    let on = fx.run(read, &read.keys);
    let mut off = fx.run(read, &read.keys);
    off.witness = None;
    let assert_on = |outcome: Outcome, what: &str| {
        assert!(outcome.success, "{what}");
        assert_eq!(outcome.output, concat(&read.values), "{what}");
        assert_eq!(
            outcome.gas,
            WARM_ACCESS + l1sload_gas(read.keys.len()),
            "{what}"
        );
    };
    let assert_off = |outcome: Outcome, what: &str| {
        assert!(outcome.success, "{what}");
        assert!(outcome.output.is_empty(), "{what}");
        assert_eq!(outcome.gas, COLD_ACCOUNT_ACCESS, "{what}");
    };

    let mut evm = off.evm();
    assert_off(off.transact(&mut evm).unwrap(), "off, first transaction");
    evm.set_l1sload(on.witness.clone());
    assert_on(off.transact(&mut evm).unwrap(), "turned on");

    let mut evm = on.evm();
    assert_on(on.transact(&mut evm).unwrap(), "on, first transaction");
    evm.set_l1sload(None);
    assert_off(on.transact(&mut evm).unwrap(), "turned off");
}

/// A forged header or node is keyed by its own hash, so the one the walk needs
/// is missing.
#[test]
fn stops_the_replay_on_a_witness_that_does_not_prove_the_read() {
    let fx = fixture();
    let read = &fx.reads[1];
    let run = |served: Vec<Vec<u8>>| {
        let mut run = fx.run(read, &read.keys);
        run.witness = Some(L1Witness::from_preimages(served));
        run.execute()
            .expect_err("an unproven read must stop the replay")
    };

    let mut served = fx.served(read, &read.keys);
    let header = &mut served[0];
    let last = header.len() - 1;
    header[last] ^= 1;
    let err = run(served);
    assert!(err.contains(&missing_preimage(fx.block_hash)), "{err}");

    let missing = read.storage_proofs[0][1];
    let served = fx
        .served(read, &read.keys)
        .into_iter()
        .filter(|node| keccak256(node) != missing)
        .collect();
    let err = run(served);
    assert!(err.contains(&missing_preimage(missing)), "{err}");
}

/// Before AtlasV6, and on a chain that does not enable it, `0x101` is an
/// empty, cold account: the call succeeds, returns nothing and costs a cold
/// access.
#[test]
fn is_an_empty_account_on_older_specs_and_when_disabled() {
    let fx = fixture();
    let read = &fx.reads[0];
    let runs = SPECS_WITHOUT_L1SLOAD
        .into_iter()
        .map(|spec| (spec, true))
        .chain([(ZkSpecId::AtlasV6, false)]);
    for (spec, enabled) in runs {
        let mut run = fx.run(read, &read.keys);
        run.spec = spec;
        if !enabled {
            run.witness = None;
        }
        let outcome = run.execute().unwrap();
        let what = format!("{spec:?}, witness supplied: {enabled}");
        assert!(outcome.success, "{what}");
        assert!(outcome.output.is_empty(), "{what}");
        assert_eq!(outcome.gas, COLD_ACCOUNT_ACCESS, "{what}");
        // Nothing read the anchor.
        assert_eq!(outcome.holder_sload, COLD_SLOAD, "{what}");
        assert_eq!(outcome.holder_timestamp_sload, COLD_SLOAD, "{what}");
    }
}

/// The anchor reads warm the slots but not `L2InteropRootStorage`. A call that
/// fails, here for want of an anchor, leaves the slots cold and reads no
/// witness.
#[test]
fn the_anchor_read_warms_the_slot_but_not_the_holder() {
    let fx = fixture();
    let read = &fx.reads[0];

    let mut control = fx.run(read, &read.keys);
    control.witness = None;
    let control = control.execute().unwrap();
    assert_eq!(control.holder_access, COLD_ACCOUNT_ACCESS);
    assert_eq!(control.holder_sload, COLD_SLOAD);
    assert_eq!(control.holder_timestamp_sload, COLD_SLOAD);

    let read_done = fx.run(read, &read.keys).execute().unwrap();
    assert!(read_done.success);
    assert_eq!(read_done.holder_access, COLD_ACCOUNT_ACCESS);
    assert_eq!(read_done.holder_sload, WARM_ACCESS);
    assert_eq!(read_done.holder_timestamp_sload, WARM_ACCESS);

    let mut failed = fx.run(read, &read.keys);
    failed.witness = Some(L1Witness::new());
    failed.anchor = None;
    let failed = failed
        .execute()
        .expect("no anchor is a failed call, not a replay error");
    assert_consumes_all_gas(&failed, CALL_GAS, "no anchor");
    assert_eq!(failed.holder_access, COLD_ACCOUNT_ACCESS);
    assert_eq!(
        failed.holder_sload, COLD_SLOAD,
        "the failed call's read is reverted"
    );
    assert_eq!(failed.holder_timestamp_sload, COLD_SLOAD);
}

/// The anchor is fresh up to `L1_ANCHOR_MAX_LAG` seconds after its L1 time.
/// One second later the call fails before it reads the witness, and the
/// anchor reads go with it.
#[test]
fn an_anchor_goes_stale_one_second_past_the_lag() {
    let fx = fixture();
    let read = &fx.reads[0];

    let mut fresh = fx.run(read, &read.keys);
    fresh.block_time = ANCHOR_TIME + L1_ANCHOR_MAX_LAG;
    let fresh = fresh.execute().unwrap();
    assert!(fresh.success);
    assert_eq!(fresh.output, concat(&read.values));

    let mut stale = fx.run(read, &read.keys);
    stale.witness = Some(L1Witness::new());
    stale.block_time = ANCHOR_TIME + L1_ANCHOR_MAX_LAG + 1;
    let stale = stale
        .execute()
        .expect("a stale anchor is a failed call, not a replay error");
    assert_consumes_all_gas(&stale, CALL_GAS, "stale anchor");
    assert_eq!(stale.holder_sload, COLD_SLOAD);
    assert_eq!(stale.holder_timestamp_sload, COLD_SLOAD);
}
