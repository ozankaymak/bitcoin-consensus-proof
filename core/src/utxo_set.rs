/// # Bitcoin UTXO Set Management
///
/// This module implements the Unspent Transaction Output (UTXO) set for Bitcoin,
/// optimized for zero-knowledge circuit compatibility. The UTXO set is the collection
/// of all unspent transaction outputs in the Bitcoin blockchain, representing coins
/// that can be spent in future transactions.
///
/// ## Architecture
///
/// The implementation uses a Jellyfish Merkle Tree (JMT) for efficient and provable
/// UTXO management. This allows:
///
/// - Efficient verification of UTXO existence or non-existence
/// - Compact cryptographic proofs of UTXO state
/// - Circuit-friendly operations for zero-knowledge proofs
/// - Deterministic state transitions
///
/// ## Key Components
///
/// - `UTXOSetGuest`: The circuit-side UTXO set management, storing just the JMT root
/// - `KeyOutPoint`: A unique identifier for a transaction output (txid + vout)
/// - `UTXO`: The data structure representing an unspent output including its value and script
/// - Cryptographic proofs for verifying UTXO operations without full state
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};

use crate::transaction::CircuitTransaction;
use jmt::{
    proof::{SparseMerkleProof, UpdateMerkleProof},
    KeyHash, OwnedValue, RootHash, Version,
};

/// Circuit-compatible UTXO set implementation
///
/// This structure represents the UTXO set state for zero-knowledge circuit execution.
/// Instead of storing the full UTXO database, it maintains just the Jellyfish Merkle
/// Tree (JMT) root hash, allowing for cryptographic verification of UTXO state without
/// storing all UTXOs.
///
/// Features:
/// - Stores the cryptographic root hash of the UTXO set as a JMT
/// - Maintains a version number for tracking state transitions
/// - Includes a cache for in-memory UTXOs during block processing
/// - Supports cryptographic proofs for UTXO inclusion and non-inclusion
///
/// The guest-side implementation focuses on verification rather than storage,
/// as the full UTXO set data is maintained by the host.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOSetGuest {
    /// The Jellyfish Merkle Tree root hash representing the current UTXO state
    pub jmt_root: RootHash,

    /// Cache for UTXOs created and spent during block processing
    /// Using BTreeMap for deterministic iteration order, critical for reproducible circuit execution
    #[serde(skip)]
    #[borsh(skip)]
    pub utxo_cache: BTreeMap<KeyOutPoint, UTXO>,
    // pub spent_utxos: BTreeMap<KeyOutPoint, UTXO>,  // Commented out but may be used in the future
}

/// Unique identifier for a transaction output (UTXO)
///
/// In Bitcoin, each unspent transaction output (UTXO) is uniquely identified by:
/// - The transaction ID (txid) of the transaction that created it
/// - The index (vout) of the output within that transaction
///
/// This structure provides a circuit-compatible representation of this identifier,
/// with efficient serialization, hashing, and comparison operations.
#[derive(
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Debug,
    BorshDeserialize,
    BorshSerialize,
    Hash,
    Ord,
    PartialOrd,
)]
pub struct KeyOutPoint {
    /// 32-byte transaction identifier hash
    pub txid: [u8; 32],

    /// Output index within the transaction (0-based)
    pub vout: u32,
}

/// Serialized byte representation of a transaction output reference
///
/// This type provides a standardized byte serialization of a KeyOutPoint,
/// used for storage and cryptographic operations. The format is:
/// - First 32 bytes: Transaction ID
/// - Last 4 bytes: Output index (big-endian encoded)
#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct OutPointBytes(pub [u8; 36]);

/// Converts a KeyOutPoint to its byte representation
impl From<KeyOutPoint> for OutPointBytes {
    fn from(key: KeyOutPoint) -> Self {
        let mut bytes = [0u8; 36];
        bytes[0..32].copy_from_slice(&key.txid[..]);
        bytes[32..36].copy_from_slice(&key.vout.to_be_bytes());
        OutPointBytes(bytes)
    }
}

/// Converts a byte representation back to a KeyOutPoint
impl Into<KeyOutPoint> for OutPointBytes {
    fn into(self) -> KeyOutPoint {
        KeyOutPoint {
            txid: self.0[0..32].try_into().unwrap(),
            vout: u32::from_be_bytes(self.0[32..36].try_into().unwrap()),
        }
    }
}

/// Allows OutPointBytes to be used with functions requiring AsRef<[u8]>
impl AsRef<[u8]> for OutPointBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Circuit-compatible representation of an unspent transaction output
///
/// This structure represents a spendable Bitcoin output with all the
/// information needed to validate spending conditions and enforce consensus
/// rules. In addition to the output's value and locking script, it includes
/// metadata like creation height and whether it's from a coinbase transaction.
///
/// The UTXO structure is optimized for use in zero-knowledge circuits while
/// maintaining compatibility with Bitcoin's consensus rules.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXO {
    /// Amount in satoshis (1 BTC = 100,000,000 satoshis)
    pub value: u64,

    /// Block height where this output was created
    pub block_height: u32,

    /// Block timestamp when this output was created
    pub block_time: u32,

    /// Whether this output is from a coinbase transaction (mining reward)
    /// Coinbase outputs have special consensus rules (e.g., maturity period)
    pub is_coinbase: bool,

    /// The locking script that specifies spending conditions (serialized)
    pub script_pubkey: Vec<u8>,
}

impl UTXO {
    /// Creates a UTXO from a bitcoin-rs TxOut with additional metadata
    ///
    /// This method converts a standard Bitcoin transaction output into our
    /// circuit-compatible UTXO representation, adding important consensus-related
    /// metadata such as the block height, time, and coinbase status.
    ///
    /// # Arguments
    ///
    /// * `txout` - The bitcoin-rs transaction output to convert
    /// * `block_height` - The height of the block containing this output
    /// * `block_time` - The timestamp of the block containing this output
    /// * `is_coinbase` - Whether this output is from a coinbase transaction
    ///
    /// # Returns
    ///
    /// A new UTXO containing the output's value, script, and metadata
    pub fn from_txout(
        txout: &bitcoin::TxOut,
        block_height: u32,
        block_time: u32,
        is_coinbase: bool,
    ) -> Self {
        println!("[DEBUG] Creating UTXO from TxOut");
        let result = UTXO {
            value: Amount::to_sat(txout.value),
            block_height,
            block_time,
            is_coinbase,
            script_pubkey: txout.script_pubkey.to_bytes().to_vec(),
        };
        println!("[DEBUG] Resulting UTXO: {:?}", result);
        result
    }

    /// Converts a UTXO back to a bitcoin-rs TxOut
    ///
    /// This method creates a standard bitcoin-rs transaction output from
    /// our circuit-compatible UTXO representation. Note that this conversion
    /// loses metadata like block height and coinbase status, as the bitcoin-rs
    /// TxOut type only contains the value and script.
    ///
    /// # Returns
    ///
    /// A bitcoin-rs TxOut with the same value and script as this UTXO
    pub fn into_txout(&self) -> bitcoin::TxOut {
        println!("[DEBUG] Converting UTXO into TxOut");
        let result = bitcoin::TxOut {
            value: Amount::from_sat(self.value),
            script_pubkey: ScriptBuf::from_bytes(self.script_pubkey.clone()),
        };
        println!("[DEBUG] Resulting TxOut: {:?}", result);
        result
    }
}

/// Wrapper for UTXO bytes with convenient conversion methods
///
/// This type provides a wrapper around the serialized byte representation
/// of a UTXO, allowing it to be easily passed to functions that work with
/// byte arrays while maintaining the semantic connection to UTXOs. It also
/// provides convenient conversion methods to and from UTXO objects.
#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOBytes(pub Vec<u8>);

/// Converts a UTXO to its byte representation
impl From<UTXO> for UTXOBytes {
    fn from(utxo: UTXO) -> Self {
        // Use the UTXO's to_bytes method to get the serialized representation
        UTXOBytes(utxo.to_bytes())
    }
}

/// Converts a byte representation back to a UTXO
impl Into<UTXO> for UTXOBytes {
    fn into(self) -> UTXO {
        // Use the UTXO's from_bytes method to deserialize
        UTXO::from_bytes(&self.0)
    }
}

/// Allows UTXOBytes to be used with functions requiring AsRef<[u8]>
impl AsRef<[u8]> for UTXOBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl KeyOutPoint {
    /// Creates a KeyOutPoint from a bitcoin-rs OutPoint
    ///
    /// This method provides convenient conversion from the bitcoin-rs library's
    /// OutPoint type to our circuit-compatible KeyOutPoint representation.
    ///
    /// # Arguments
    ///
    /// * `outpoint` - A reference to a bitcoin-rs OutPoint
    ///
    /// # Returns
    ///
    /// A new KeyOutPoint instance with the same txid and vout
    pub fn from_outpoint(outpoint: &OutPoint) -> Self {
        KeyOutPoint {
            txid: outpoint.txid.to_byte_array(),
            vout: outpoint.vout,
        }
    }

    /// Converts a KeyOutPoint back to a bitcoin-rs OutPoint
    ///
    /// This method creates a standard bitcoin-rs OutPoint from our
    /// circuit-compatible KeyOutPoint, enabling seamless integration
    /// with the bitcoin-rs library functions.
    ///
    /// # Returns
    ///
    /// A new bitcoin-rs OutPoint with the same txid and vout
    pub fn to_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&self.txid).unwrap(),
            vout: self.vout,
        }
    }

    /// Computes the Jellyfish Merkle Tree key hash for this OutPoint
    ///
    /// This method converts the KeyOutPoint into a cryptographic hash
    /// suitable for use as a key in the Jellyfish Merkle Tree (JMT).
    /// The hash is derived from the concatenation of the txid and vout,
    /// ensuring a unique, fixed-size identifier for each UTXO.
    ///
    /// # Returns
    ///
    /// A KeyHash object that can be used with the JMT
    pub fn to_key_hash(&self) -> KeyHash {
        // Create a buffer with the concatenated txid and vout
        let mut key_bytes = Vec::with_capacity(36);
        key_bytes.extend_from_slice(&self.txid);
        key_bytes.extend_from_slice(&self.vout.to_be_bytes());

        // Create a KeyHash using SHA-256
        KeyHash::with::<Sha256>(&key_bytes)
    }
}

impl UTXO {
    /// Serializes a UTXO to a compact byte representation
    ///
    /// This method creates a binary representation of the UTXO suitable for
    /// storage in the Jellyfish Merkle Tree or other serialization needs.
    /// The format is:
    /// - 8 bytes: Value (in satoshis, big-endian)
    /// - 4 bytes: Block height (big-endian)
    /// - 4 bytes: Block time (big-endian)
    /// - 1 byte: Coinbase flag (1=true, 0=false)
    /// - Remaining bytes: ScriptPubKey (variable length)
    ///
    /// # Returns
    ///
    /// A vector of bytes containing the serialized UTXO
    pub fn to_bytes(&self) -> Vec<u8> {
        println!("[DEBUG] Serializing UTXO to bytes");
        // Pre-allocate capacity for efficiency
        let mut bytes = Vec::with_capacity(8 + 4 + 4 + 1 + self.script_pubkey.len());

        // Append value (8 bytes)
        bytes.extend_from_slice(&self.value.to_be_bytes());

        // Append block height (4 bytes)
        bytes.extend_from_slice(&self.block_height.to_be_bytes());

        // Append block time (4 bytes)
        bytes.extend_from_slice(&self.block_time.to_be_bytes());

        // Append coinbase flag (1 byte)
        bytes.push(if self.is_coinbase { 1 } else { 0 });

        // Append script (variable length)
        bytes.extend_from_slice(&self.script_pubkey);

        let result = bytes;
        println!("[DEBUG] Serialized UTXO Bytes: {:?}", result);
        result
    }

    /// Deserializes a UTXO from its byte representation
    ///
    /// This method reconstructs a UTXO from its serialized form created by
    /// the `to_bytes` method. It's used when retrieving UTXOs from storage
    /// or when verifying UTXO inclusion proofs.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized UTXO bytes
    ///
    /// # Returns
    ///
    /// A reconstructed UTXO
    pub fn from_bytes(bytes: &[u8]) -> Self {
        println!("[DEBUG] Deserializing UTXO from bytes");

        // Extract value (first 8 bytes)
        let value = u64::from_be_bytes(bytes[0..8].try_into().unwrap());

        // Extract block height (next 4 bytes)
        let block_height = u32::from_be_bytes(bytes[8..12].try_into().unwrap());

        // Extract block time (next 4 bytes)
        let block_time = u32::from_be_bytes(bytes[12..16].try_into().unwrap());

        // Extract coinbase flag (next 1 byte)
        let is_coinbase = bytes[16] == 1;

        // Extract script (remaining bytes)
        let script_pubkey = bytes[17..].to_vec();

        let result = UTXO {
            value,
            script_pubkey,
            block_height,
            block_time,
            is_coinbase,
        };
        println!("[DEBUG] Deserialized UTXO: {:?}", result);
        result
    }

    /// Checks if the UTXO is mature and can be spent
    ///
    /// In Bitcoin, coinbase outputs (mining rewards) have a special consensus rule:
    /// they must have at least 100 confirmations before they can be spent. This
    /// prevents miners from immediately spending rewards that might be invalidated
    /// by a chain reorganization.
    ///
    /// # Arguments
    ///
    /// * `current_height` - The current blockchain height
    ///
    /// # Returns
    ///
    /// `true` if the UTXO can be spent, `false` otherwise
    pub fn is_mature(&self, current_height: u32) -> bool {
        println!("[DEBUG] Checking if UTXO is mature");

        // Non-coinbase outputs can be spent immediately
        if !self.is_coinbase {
            return true;
        }

        // Coinbase outputs require 100 confirmations before they can be spent
        // Check if we have enough confirmations (current height - UTXO height >= 100)
        let result = current_height >= self.block_height + 100;
        println!("[DEBUG] Is UTXO Mature: {}", result);
        result
    }
}

impl UTXOSetGuest {
    /// Creates a new, empty UTXO set state
    ///
    /// This constructor initializes a fresh UTXOSetGuest with:
    /// - A zero root hash (representing an empty Jellyfish Merkle Tree)
    /// - Version set to 0 (initial state)
    /// - An empty UTXO cache
    ///
    /// This is typically used when starting from the genesis block or
    /// when initializing a new verification context.
    ///
    /// # Returns
    ///
    /// A new UTXOSetGuest instance with default values
    pub fn new() -> Self {
        println!("[DEBUG] Creating new UTXOSetGuest");
        let result = UTXOSetGuest {
            jmt_root: RootHash::from([0u8; 32]), // Empty Merkle tree root
            utxo_cache: BTreeMap::new(),         // Empty cache
        };
        println!("[DEBUG] New UTXOSetGuest: {:?}", result);
        result
    }

    /// Creates a UTXO set state with a specified root hash and version
    ///
    /// This constructor is used when verifying from a specific state rather
    /// than from scratch. It's particularly useful in contexts where verification
    /// needs to start from a trusted checkpoint or when verifying incremental
    /// updates to the UTXO set.
    ///
    /// # Arguments
    ///
    /// * `jmt_root` - The Jellyfish Merkle Tree root hash to start from
    /// * `version` - The version number associated with this state
    ///
    /// # Returns
    ///
    /// A new UTXOSetGuest instance initialized with the provided state
    pub fn with_root(jmt_root: RootHash) -> Self {
        println!("[DEBUG] Creating UTXOSetGuest with root and version");
        let result = UTXOSetGuest {
            jmt_root,                    // The provided root hash
            utxo_cache: BTreeMap::new(), // Empty cache
        };
        println!("[DEBUG] UTXOSetGuest with Root: {:?}", result);
        result
    }

    /// Returns the current JMT root hash representing the UTXO set state
    ///
    /// The root hash is a cryptographic commitment to the entire UTXO set.
    /// It can be used to verify the inclusion or non-inclusion of any UTXO
    /// in the set using Sparse Merkle Tree proofs.
    ///
    /// # Returns
    ///
    /// The current Jellyfish Merkle Tree root hash
    pub fn get_root(&self) -> RootHash {
        println!("[DEBUG] Getting JMT root");
        let result = self.jmt_root;
        println!("[DEBUG] JMT Root: {:?}", result);
        result
    }

    /// Removes and returns a UTXO from the cache
    ///
    /// This method removes a UTXO from the in-memory cache and returns it.
    /// This is typically used when a UTXO is spent, allowing it to be
    /// removed from the cache while still being accessible for further processing.
    ///
    /// # Arguments
    ///
    /// * `utxo_key` - The key (txid + vout) of the UTXO to remove
    ///
    /// # Returns
    ///
    /// The removed UTXO if it was in the cache, or None if not found
    pub fn pop_utxo_from_cache(&mut self, utxo_key: &KeyOutPoint) -> Option<UTXO> {
        println!("[DEBUG] Popping UTXO from cache");
        let result = self.utxo_cache.remove(utxo_key);
        println!("[DEBUG] Popped UTXO: {:?}", result);
        result
    }

    /// Add outputs from a transaction to the UTXO set
    pub fn add_transaction_outputs(
        &mut self,
        transaction: &CircuitTransaction,
        block_height: u32,
        block_time: u32,
        is_coinbase: bool,
    ) {
        println!("[DEBUG] Adding transaction outputs to UTXO cache");
        let txid = transaction.txid();

        for (vout, output) in transaction.output.iter().enumerate() {
            let utxo_key = KeyOutPoint {
                txid,
                vout: vout as u32,
            };

            let utxo = UTXO {
                value: output.value.to_sat(),
                script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                block_height,
                block_time,
                is_coinbase,
            };

            // Add to cache
            self.utxo_cache.insert(utxo_key, utxo);
        }
    }

    /// Remove a UTXO (spent)
    pub fn remove_utxo(&mut self, utxo_key: &KeyOutPoint) {
        println!("[DEBUG] Removing UTXO from cache");
        // Remove from cache if it exists
        self.utxo_cache.remove(utxo_key);

        // In a real implementation, this would update the JMT root using a proof
        // from the host, but for now we just remove from the cache
    }

    // /// Verify an inclusion proof for a UTXO
    // pub fn verify_inclusion_proof(
    //     &self,
    //     utxo_key: &KeyOutPoint,
    //     utxo: &UTXO,
    //     batch_proof: &TransactionElementsBatchProof,
    // ) -> bool {
    //     for proof in batch_proof {
    //         let key_hash = utxo_key.to_key_hash();
    //         let value = utxo.to_bytes();

    //         proof
    //             .proof
    //             .verify(self.jmt_root, key_hash, Some(&value))
    //             .is_ok()
    //     }
    //     true
    // }

    // /// Verify an inclusion proof for a UTXO that doesn't exist
    // pub fn verify_non_inclusion_proof(
    //     &self,
    //     utxo_key: &KeyOutPoint,
    //     proof: &UTXOInclusionProof,
    // ) -> bool {
    //     let key_hash = utxo_key.to_key_hash();
    //     proof.proof.verify(self.jmt_root, key_hash, None).is_ok()
    // }

    // /// Verify a range of UTXOs (useful for proving absence of double-spends)
    // pub fn verify_range_proof(
    //     &self,
    //     proof: &UTXOInclusionProof,
    //     start_key: &KeyOutPoint,
    //     end_key: &KeyOutPoint,
    // ) -> bool {
    //     let start_hash = start_key.to_key_hash();
    //     let end_hash = end_key.to_key_hash();

    //     proof
    //         .range_proof
    //         .verify(self.jmt_root, start_hash, end_hash)
    //         .is_ok()
    // }

    // /// Apply a batch of updates to the UTXO set
    // pub fn apply_updates(&mut self, updates: &[UTXOUpdate]) -> bool {
    //     if updates.is_empty() {
    //         return true;
    //     }

    //     let mut new_root = self.jmt_root;
    //     let mut success = true;

    //     // Process each update
    //     for update in updates {
    //         let key_hash = update.key.to_key_hash();

    //         // Verify the update proof is valid before applying
    //         if update.value.is_some() {
    //             // Insert or update
    //             let utxo = update.value.as_ref().unwrap();
    //             let value_bytes = utxo.to_bytes();

    //             // Verify the update proof
    //             if let Ok(root) =
    //                 update
    //                     .proof
    //                     .update_proof
    //                     .verify_update(new_root, key_hash, Some(&value_bytes))
    //             {
    //                 new_root = root;
    //                 // Also add to cache
    //                 self.utxo_cache.insert(update.key.clone(), utxo.clone());
    //             } else {
    //                 success = false;
    //                 break;
    //             }
    //         } else {
    //             // Delete
    //             if let Ok(root) = update
    //                 .proof
    //                 .update_proof
    //                 .verify_update(new_root, key_hash, None)
    //             {
    //                 new_root = root;
    //                 // Also remove from cache
    //                 self.utxo_cache.remove(&update.key);
    //             } else {
    //                 success = false;
    //                 break;
    //             }
    //         }
    //     }

    //     if success {
    //         // Only update the root if all updates succeeded
    //         self.jmt_root = new_root;
    //         self.version += 1;
    //     }

    //     success
    // }

    /// Commit all cached changes to the JMT at the end of block processing
    // pub fn commit_block_changes(&mut self, update_proofs: &[UTXOUpdate]) -> bool {
    //     // Apply the updates with proofs to the JMT
    //     if !self.apply_updates(update_proofs) {
    //         return false;
    //     }

    //     // Clear the cache after committing
    //     self.clear_cache();
    //     return true;
    // }

    /// Get a UTXO from the cache
    pub fn get_cached_utxo(&self, key: &KeyOutPoint) -> Option<UTXO> {
        println!("[DEBUG] Getting cached UTXO");
        let result = self.utxo_cache.get(key).cloned();
        println!("[DEBUG] Cached UTXO: {:?}", result);
        result
    }

    /// Check if a UTXO exists in the cache
    pub fn has_cached_utxo(&self, key: &KeyOutPoint) -> bool {
        println!("[DEBUG] Checking if UTXO is cached");
        let result = self.utxo_cache.contains_key(key);
        println!("[DEBUG] Has Cached UTXO: {}", result);
        result
    }

    /// Add a UTXO to the cache (without updating the JMT)
    pub fn cache_utxo(&mut self, key: KeyOutPoint, utxo: UTXO) {
        println!("[DEBUG] Caching UTXO");
        self.utxo_cache.insert(key, utxo);
    }

    /// Process a transaction's outputs, adding them to the UTXO cache
    pub fn process_tx_outputs(
        &mut self,
        transaction: &CircuitTransaction,
        block_height: u32,
        block_time: u32,
        is_coinbase: bool,
    ) {
        println!("[DEBUG] Processing transaction outputs");
        let txid = transaction.txid();

        for (vout, output) in transaction.output.iter().enumerate() {
            let utxo_key = KeyOutPoint {
                txid,
                vout: vout as u32,
            };

            let utxo = UTXO {
                value: output.value.to_sat(),
                script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                block_height,
                block_time,
                is_coinbase,
            };

            // Add to cache
            self.utxo_cache.insert(utxo_key, utxo);
        }
    }

    /// Clear the UTXO cache
    pub fn clear_cache(&mut self) {
        println!("[DEBUG] Clearing UTXO cache");
        self.utxo_cache.clear();
    }
}
