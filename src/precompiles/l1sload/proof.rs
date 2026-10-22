//! Verification of an L1SLOAD read against the block's witness: the anchored
//! L1 header and the `eth_getProof` trie nodes, each keyed by its own hash.
//! The walk and its size caps follow ZKsync OS. It is hand-rolled rather than
//! alloy-trie's because the witness is untrusted and alloy-trie's node decoding
//! panics on some malformed nodes.
use alloy_rlp::Header;
use core::fmt;
use revm::primitives::{Address, B256, B256Map, Bytes, U256, b256, keccak256};
use std::vec::Vec;

/// Root of an empty Merkle Patricia trie, `keccak256(rlp(""))`.
const EMPTY_ROOT_HASH: B256 =
    b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

const MAX_HEADER_LEN: usize = 1024;
/// A branch node with 16 hashed children.
const MAX_NODE_LEN: usize = 532;

/// The keccak256 preimages the sequencer's L1 witness source served for a
/// block, keyed by their hash. A block that reads nothing from L1 gets an
/// empty one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct L1Witness {
    preimages: B256Map<Bytes>,
}

impl L1Witness {
    pub fn new() -> Self {
        Self::default()
    }

    /// The witness made of `preimages`, in any order.
    pub fn from_preimages<P: Into<Bytes>>(preimages: impl IntoIterator<Item = P>) -> Self {
        let mut witness = Self::new();
        for preimage in preimages {
            witness.insert(preimage);
        }
        witness
    }

    /// Add `preimage` under its keccak256 hash, and return the hash.
    pub fn insert(&mut self, preimage: impl Into<Bytes>) -> B256 {
        let preimage = preimage.into();
        let hash = keccak256(&preimage);
        self.preimages.insert(hash, preimage);
        hash
    }

    fn preimage(&self, hash: B256, cap: usize) -> Result<&[u8], L1WitnessError> {
        let preimage = self
            .preimages
            .get(&hash)
            .ok_or(L1WitnessError::Missing(hash))?;
        if preimage.len() > cap {
            return Err(L1WitnessError::TooLarge {
                hash,
                len: preimage.len(),
                cap,
            });
        }
        Ok(preimage)
    }
}

/// Why the witness does not prove a read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum L1WitnessError {
    /// No preimage of this hash; a forged preimage shows up this way too.
    Missing(B256),
    TooLarge {
        hash: B256,
        len: usize,
        cap: usize,
    },
    MalformedHeader,
    MalformedNode,
    MalformedAccount,
    MalformedStorageValue,
}

impl fmt::Display for L1WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(hash) => write!(f, "missing preimage of {hash}"),
            Self::TooLarge { hash, len, cap } => {
                write!(
                    f,
                    "preimage of {hash} is {len} bytes, over the {cap}-byte cap"
                )
            }
            Self::MalformedHeader => f.write_str("malformed L1 header"),
            Self::MalformedNode => f.write_str("malformed trie node"),
            Self::MalformedAccount => f.write_str("malformed L1 account"),
            Self::MalformedStorageValue => f.write_str("malformed L1 storage value"),
        }
    }
}

impl std::error::Error for L1WitnessError {}

/// Read `keys` of `address` at the L1 block whose hash is `anchor`. An absent
/// account or slot reads as zero.
pub(super) fn read_l1_storage(
    witness: &L1Witness,
    anchor: B256,
    address: Address,
    keys: &[B256],
) -> Result<Vec<B256>, L1WitnessError> {
    let header = witness.preimage(anchor, MAX_HEADER_LEN)?;
    let state_root = header_state_root(header)?;

    let account = trie_get(witness, state_root, keccak256(address))?;
    let storage_root = match account {
        Some(account) => account_storage_root(account)?,
        None => EMPTY_ROOT_HASH,
    };

    keys.iter()
        .map(
            |key| match trie_get(witness, storage_root, keccak256(key))? {
                Some(value) => decode_storage_value(value),
                None => Ok(B256::ZERO),
            },
        )
        .collect()
}

/// The state root, the 4th item of an RLP-encoded L1 block header. Only the
/// first four items (32, 32, 20 and 32 bytes) are parsed, as in ZKsync OS.
fn header_state_root(header: &[u8]) -> Result<B256, L1WitnessError> {
    let malformed = |_| L1WitnessError::MalformedHeader;
    let mut buf = header;
    let mut fields = Header::decode_bytes(&mut buf, true).map_err(malformed)?;
    if !buf.is_empty() {
        return Err(L1WitnessError::MalformedHeader);
    }
    let mut state_root = &[][..];
    for expected_len in [32, 32, 20, 32] {
        state_root = Header::decode_bytes(&mut fields, false).map_err(malformed)?;
        if state_root.len() != expected_len {
            return Err(L1WitnessError::MalformedHeader);
        }
    }
    Ok(B256::from_slice(state_root))
}

/// The storage root of an RLP-encoded account, `[nonce, balance, storageRoot,
/// codeHash]`, with ZKsync OS's field size limits. An empty encoding is the
/// empty account.
fn account_storage_root(account: &[u8]) -> Result<B256, L1WitnessError> {
    if account.is_empty() {
        return Ok(EMPTY_ROOT_HASH);
    }
    let malformed = |_| L1WitnessError::MalformedAccount;
    let mut buf = account;
    let mut fields = Header::decode_bytes(&mut buf, true).map_err(malformed)?;
    if !buf.is_empty() {
        return Err(L1WitnessError::MalformedAccount);
    }
    let nonce = Header::decode_bytes(&mut fields, false).map_err(malformed)?;
    let balance = Header::decode_bytes(&mut fields, false).map_err(malformed)?;
    let storage_root = Header::decode_bytes(&mut fields, false).map_err(malformed)?;
    let code_hash = Header::decode_bytes(&mut fields, false).map_err(malformed)?;
    if !fields.is_empty()
        || nonce.len() > 8
        || balance.len() > 32
        || storage_root.len() > 32
        || code_hash.len() > 32
    {
        return Err(L1WitnessError::MalformedAccount);
    }
    Ok(B256::left_padding_from(storage_root))
}

/// Decode a storage leaf value, the canonical RLP encoding of a non-zero
/// big-endian integer. As in ZKsync OS, an empty value reads as zero and an
/// encoded zero is rejected.
fn decode_storage_value(encoded: &[u8]) -> Result<B256, L1WitnessError> {
    if encoded.is_empty() {
        return Ok(B256::ZERO);
    }
    let mut buf = encoded;
    let bytes =
        Header::decode_bytes(&mut buf, false).map_err(|_| L1WitnessError::MalformedStorageValue)?;
    if !buf.is_empty() || bytes.is_empty() || bytes.len() > 32 || bytes[0] == 0 {
        return Err(L1WitnessError::MalformedStorageValue);
    }
    Ok(B256::from(U256::from_be_slice(bytes)))
}

enum NodeRef<'a> {
    Empty,
    Hash(B256),
    /// A child shorter than 32 bytes, embedded in its parent.
    Inline(&'a [u8]),
}

impl<'a> NodeRef<'a> {
    fn decode(buf: &mut &'a [u8]) -> Result<Self, L1WitnessError> {
        let item = *buf;
        let header = Header::decode(buf).map_err(|_| L1WitnessError::MalformedNode)?;
        let encoded_len = item.len() - buf.len() + header.payload_length;
        let payload = &buf[..header.payload_length];
        *buf = &buf[header.payload_length..];
        if header.list {
            if encoded_len >= 32 {
                return Err(L1WitnessError::MalformedNode);
            }
            return Ok(Self::Inline(&item[..encoded_len]));
        }
        match payload.len() {
            0 => Ok(Self::Empty),
            32 => Ok(Self::Hash(B256::from_slice(payload))),
            _ => Err(L1WitnessError::MalformedNode),
        }
    }
}

/// Look up `hashed_key` in the trie with root `root`: the leaf value, or
/// `None` when the trie proves the key absent.
fn trie_get(
    witness: &L1Witness,
    root: B256,
    hashed_key: B256,
) -> Result<Option<&[u8]>, L1WitnessError> {
    if root == EMPTY_ROOT_HASH {
        // ZKsync OS answers an empty trie without asking for its root node.
        return Ok(None);
    }

    let mut nibbles = [0u8; 64];
    for (i, byte) in hashed_key.iter().enumerate() {
        nibbles[2 * i] = byte >> 4;
        nibbles[2 * i + 1] = byte & 0x0f;
    }
    let mut path: &[u8] = &nibbles;

    // ZKsync OS also caps a path at 65 nodes. Every node after the root
    // consumes at least one of the 64 nibbles, so this walk can't exceed it.
    let mut node = witness.preimage(root, MAX_NODE_LEN)?;
    loop {
        let mut buf = node;
        let mut items =
            Header::decode_bytes(&mut buf, true).map_err(|_| L1WitnessError::MalformedNode)?;
        if !buf.is_empty() {
            return Err(L1WitnessError::MalformedNode);
        }

        let child = match count_items(items)? {
            17 => {
                // Branch: 16 children, then a value that a 32-byte path never reaches.
                let (&nibble, rest) = path.split_first().ok_or(L1WitnessError::MalformedNode)?;
                let mut child = NodeRef::Empty;
                for index in 0..16 {
                    let reference = NodeRef::decode(&mut items)?;
                    if index == nibble {
                        child = reference;
                    }
                }
                Header::decode_bytes(&mut items, false)
                    .map_err(|_| L1WitnessError::MalformedNode)?;
                path = rest;
                child
            }
            2 => {
                let encoded_path = Header::decode_bytes(&mut items, false)
                    .map_err(|_| L1WitnessError::MalformedNode)?;
                let (is_leaf, segment) = decode_hex_prefix(encoded_path)?;
                if is_leaf {
                    let value = Header::decode_bytes(&mut items, false)
                        .map_err(|_| L1WitnessError::MalformedNode)?;
                    return Ok((segment == path).then_some(value));
                }
                // Extension: a shared path segment, then one child.
                if segment.is_empty() || path.is_empty() {
                    return Err(L1WitnessError::MalformedNode);
                }
                let Some(rest) = path.strip_prefix(segment.as_slice()) else {
                    return Ok(None);
                };
                path = rest;
                match NodeRef::decode(&mut items)? {
                    NodeRef::Empty => return Err(L1WitnessError::MalformedNode),
                    reference => reference,
                }
            }
            _ => return Err(L1WitnessError::MalformedNode),
        };

        node = match child {
            NodeRef::Empty => return Ok(None),
            NodeRef::Hash(hash) => witness.preimage(hash, MAX_NODE_LEN)?,
            NodeRef::Inline(encoding) => encoding,
        };
    }
}

/// Number of items in an RLP list payload.
fn count_items(mut payload: &[u8]) -> Result<usize, L1WitnessError> {
    let mut count = 0;
    while !payload.is_empty() {
        let header = Header::decode(&mut payload).map_err(|_| L1WitnessError::MalformedNode)?;
        payload = &payload[header.payload_length..];
        count += 1;
    }
    Ok(count)
}

/// Decode a hex-prefix encoded path into whether it ends a leaf and its nibbles.
fn decode_hex_prefix(encoded: &[u8]) -> Result<(bool, Vec<u8>), L1WitnessError> {
    let (&first, rest) = encoded.split_first().ok_or(L1WitnessError::MalformedNode)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(L1WitnessError::MalformedNode);
    }
    let is_leaf = flag & 2 != 0;
    let is_odd = flag & 1 != 0;
    let mut nibbles = Vec::with_capacity(2 * rest.len() + 1);
    if is_odd {
        nibbles.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return Err(L1WitnessError::MalformedNode);
    }
    for byte in rest {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    Ok((is_leaf, nibbles))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_storage_values() {
        let word = |low: &[u8]| {
            let mut out = [0u8; 32];
            out[32 - low.len()..].copy_from_slice(low);
            B256::from(out)
        };
        assert_eq!(decode_storage_value(&[0x01]), Ok(word(&[0x01])));
        assert_eq!(
            decode_storage_value(&[0x82, 0x01, 0x00]),
            Ok(word(&[0x01, 0x00]))
        );

        assert_eq!(decode_storage_value(&[]), Ok(B256::ZERO), "absent");

        for bad in [
            &[0x80][..],         // zero
            &[0x00],             // zero, as a single byte
            &[0x82, 0x00, 0x01], // leading zero
            &[0x81, 0x05],       // non-canonical single byte
            &[0x01, 0x02],       // trailing bytes
        ] {
            assert_eq!(
                decode_storage_value(bad),
                Err(L1WitnessError::MalformedStorageValue),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn decodes_hex_prefix_paths() {
        assert_eq!(decode_hex_prefix(&[0x00, 0x12]), Ok((false, vec![1, 2])));
        assert_eq!(
            decode_hex_prefix(&[0x1a, 0x12]),
            Ok((false, vec![0xa, 1, 2]))
        );
        assert_eq!(decode_hex_prefix(&[0x3f]), Ok((true, vec![0xf])));
        assert!(
            decode_hex_prefix(&[0x01]).is_err(),
            "even path with padding"
        );
        assert!(decode_hex_prefix(&[0x40]).is_err(), "unknown flag");
    }

    #[test]
    fn parses_the_state_root_and_rejects_malformed_headers() {
        /// An RLP list of strings of the given lengths, the 4th filled with 0x22.
        fn header(field_lens: &[usize], trailing: &[u8]) -> Vec<u8> {
            let mut payload = Vec::new();
            for (i, len) in field_lens.iter().enumerate() {
                payload.push(0x80 + *len as u8);
                payload.extend(core::iter::repeat_n(if i == 3 { 0x22 } else { 0x11 }, *len));
            }
            let mut out = vec![0xf8, payload.len() as u8];
            out.extend(payload);
            out.extend_from_slice(trailing);
            out
        }
        assert_eq!(
            header_state_root(&header(&[32, 32, 20, 32], &[])),
            Ok(B256::repeat_byte(0x22))
        );
        // Later fields don't matter.
        assert_eq!(
            header_state_root(&header(&[32, 32, 20, 32, 0, 8], &[])),
            Ok(B256::repeat_byte(0x22))
        );
        for (what, bad) in [
            ("no state root", header(&[32, 32, 20], &[])),
            ("trailing bytes", header(&[32, 32, 20, 32], &[0x00])),
            ("short beneficiary", header(&[32, 32, 19, 32], &[])),
        ] {
            assert_eq!(
                header_state_root(&bad),
                Err(L1WitnessError::MalformedHeader),
                "{what}"
            );
        }
    }

    #[test]
    fn reads_the_storage_root_of_an_account() {
        let account = |fields: &[&[u8]]| {
            let mut payload = Vec::new();
            for field in fields {
                payload.push(0x80 + field.len() as u8);
                payload.extend_from_slice(field);
            }
            let mut out = vec![0xf8, payload.len() as u8];
            out.extend(payload);
            out
        };
        let root = [0x33; 32];
        assert_eq!(
            account_storage_root(&[]),
            Ok(EMPTY_ROOT_HASH),
            "empty account"
        );
        assert_eq!(
            account_storage_root(&account(&[&[0x05, 0x06], &[0x07; 12], &root, &[0x44; 32]])),
            Ok(B256::from(root))
        );
        assert_eq!(
            account_storage_root(&account(&[&[0x05; 9], &[0x07], &root, &[0x44; 32]])),
            Err(L1WitnessError::MalformedAccount),
            "nonce over 8 bytes"
        );
        assert_eq!(
            account_storage_root(&account(&[&[0x05], &[0x07], &root])),
            Err(L1WitnessError::MalformedAccount),
            "three fields"
        );
    }

    #[test]
    fn rejects_a_preimage_over_the_size_cap() {
        let mut witness = L1Witness::new();
        let hash = witness.insert(vec![0u8; MAX_NODE_LEN + 1]);
        assert_eq!(
            witness.preimage(hash, MAX_NODE_LEN),
            Err(L1WitnessError::TooLarge {
                hash,
                len: MAX_NODE_LEN + 1,
                cap: MAX_NODE_LEN
            })
        );
    }

    /// Shapes the mainnet fixture lacks: an extension at the root, a long
    /// extension below a branch, embedded leaves, and every way a path can miss.
    #[test]
    fn walks_extensions_and_embedded_nodes_built_by_alloy_trie() {
        use alloy_trie::{HashBuilder, Nibbles, proof::ProofRetainer};

        let key = |hex: &str| B256::from_slice(&revm::primitives::hex::decode(hex).unwrap());
        let zeros = "00".repeat(30);
        // All keys share the nibbles `12`, so the root is an extension. `a`
        // and `b` share 63 nibbles: a 60-nibble extension, then a branch with
        // embedded leaves. ZKsync OS rejects that last shape, but it needs a
        // 252-bit keccak prefix collision, so no real L1 trie has it.
        let a = key(&format!("1200{zeros}"));
        let b = key(&format!("1200{}01", "00".repeat(29)));
        let c = key(&format!("12ff{zeros}"));
        let values = [
            (a, vec![0x01]),
            (b, vec![0x82, 0x01, 0x00]),
            (c, [&[0xa0][..], &[0xff; 32]].concat()),
        ];
        let absent = [
            key(&format!("1300{zeros}")), // diverges in the root extension
            key(&format!("1250{zeros}")), // takes an empty branch slot
            key(&format!("12f0{zeros}")), // reaches leaf `c` with another path
            key(&format!("1200{}02", "00".repeat(29))), // an empty slot of the deep branch
            key(&format!("1200{}10{}", "00".repeat(10), "00".repeat(19))), // diverges in the deep extension
        ];

        let targets: Vec<Nibbles> = values
            .iter()
            .map(|(key, _)| *key)
            .chain(absent)
            .map(Nibbles::unpack)
            .collect();
        let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
        let mut sorted = values.clone();
        sorted.sort();
        for (key, value) in &sorted {
            builder.add_leaf(Nibbles::unpack(key), value);
        }
        let root = builder.root();
        let nodes: Vec<Bytes> = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        assert!(
            nodes.iter().any(|node| node.len() < 32),
            "the trie must embed a node"
        );
        let witness = L1Witness::from_preimages(nodes);

        for (key, value) in &values {
            assert_eq!(
                trie_get(&witness, root, *key),
                Ok(Some(value.as_slice())),
                "{key}"
            );
        }
        for key in absent {
            assert_eq!(trie_get(&witness, root, key), Ok(None), "{key}");
        }
    }

    /// alloy-trie's `TrieNode::decode` and `verify_proof` panic on a 33-byte
    /// leaf path; this walk just doesn't match it.
    #[test]
    fn a_leaf_with_a_33_byte_path_does_not_panic() {
        let mut node = vec![0xe4, 0xa2, 0x20];
        node.extend_from_slice(&[0x11; 33]);
        node.push(0x01);
        let mut witness = L1Witness::new();
        let root = witness.insert(node);
        assert_eq!(trie_get(&witness, root, B256::repeat_byte(0x11)), Ok(None));
    }
}
