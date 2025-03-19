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

/// Guest-side UTXO set implementation storing only the JMT root
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOSetGuest {
    pub jmt_root: RootHash,
    pub version: Version,
    // Cache stores UTXOs that are spent and created in the same block
    // Using BTreeMap for deterministic iteration order
    #[serde(skip)]
    #[borsh(skip)]
    pub utxo_cache: BTreeMap<KeyOutPoint, UTXO>,
    // pub spent_utxos: BTreeMap<KeyOutPoint, UTXO>,
}

/// A UTXO key represents a specific output from a transaction
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
    pub txid: [u8; 32], // Transaction ID
    pub vout: u32,      // Output index
}

pub struct OutPointBytes(pub [u8; 36]);

impl From<KeyOutPoint> for OutPointBytes {
    fn from(key: KeyOutPoint) -> Self {
        let mut bytes = [0u8; 36];
        bytes[0..32].copy_from_slice(&key.txid[..]);
        bytes[32..36].copy_from_slice(&key.vout.to_be_bytes());
        OutPointBytes(bytes)
    }
}

impl Into<KeyOutPoint> for OutPointBytes {
    fn into(self) -> KeyOutPoint {
        KeyOutPoint {
            txid: self.0[0..32].try_into().unwrap(),
            vout: u32::from_be_bytes(self.0[32..36].try_into().unwrap()),
        }
    }
}

impl AsRef<[u8]> for OutPointBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A UTXO contains the output's value, script, and metadata
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXO {
    pub value: u64,             // Amount in satoshis
    pub block_height: u32,      // Block height where this UTXO was created
    pub block_time: u32,        // Block time where this UTXO was created
    pub is_coinbase: bool,      // Whether this UTXO is from a coinbase transaction
    pub script_pubkey: Vec<u8>, // Output script
}

impl UTXO {
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

pub struct UTXOBytes(pub Vec<u8>);

impl From<UTXO> for UTXOBytes {
    fn from(utxo: UTXO) -> Self {
        UTXOBytes(utxo.to_bytes())
    }
}

impl Into<UTXO> for UTXOBytes {
    fn into(self) -> UTXO {
        UTXO::from_bytes(&self.0)
    }
}

impl AsRef<[u8]> for UTXOBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Proof for UTXO set operations, contains everything needed to verify
/// and apply changes to the UTXO set
#[derive(Serialize, Deserialize, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOInclusioWithDeletionProof {
    // /// Proof for updating the JMT
    // pub update_proof: jmt::proof::UpdateMerkleProof<Sha256>,
    /// Proof for checking UTXO existence
    pub proof: jmt::proof::SparseMerkleProof<Sha256>,
    // /// Proof for checking range of UTXOs (for double-spend prevention)
    // pub range_proof: jmt::proof::SparseMerkleRangeProof<Sha256>,
}

/// Info needed for a JMT update within the zkVM
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct TransactionElementsBatchProof {
    /// The key to update
    pub key: KeyOutPoint,
    /// The new UTXO value (None for deletion)
    pub value: Option<UTXO>,
    /// Proof for the update
    pub jmt_proof: UpdateMerkleProof<Sha256>,
}

impl KeyOutPoint {
    pub fn from_outpoint(outpoint: &OutPoint) -> Self {
        KeyOutPoint {
            txid: outpoint.txid.to_byte_array(),
            vout: outpoint.vout,
        }
    }

    pub fn to_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&self.txid).unwrap(),
            vout: self.vout,
        }
    }

    /// Convert to JMT key hash
    pub fn to_key_hash(&self) -> KeyHash {
        let mut key_bytes = Vec::with_capacity(36);
        key_bytes.extend_from_slice(&self.txid);
        key_bytes.extend_from_slice(&self.vout.to_be_bytes());

        KeyHash::with::<Sha256>(&key_bytes)
    }
}

impl UTXO {
    /// Serialize UTXO to bytes for JMT storage
    pub fn to_bytes(&self) -> Vec<u8> {
        println!("[DEBUG] Serializing UTXO to bytes");
        let mut bytes = Vec::with_capacity(8 + 4 + 1 + self.script_pubkey.len());
        bytes.extend_from_slice(&self.value.to_be_bytes());
        bytes.extend_from_slice(&self.block_height.to_be_bytes());
        bytes.push(if self.is_coinbase { 1 } else { 0 });
        bytes.extend_from_slice(&self.script_pubkey);
        let result = bytes;
        println!("[DEBUG] Serialized UTXO Bytes: {:?}", result);
        result
    }

    /// Deserialize UTXO from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        println!("[DEBUG] Deserializing UTXO from bytes");
        let value = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let block_height = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let block_time = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let is_coinbase = bytes[17] == 1;
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

    /// Check if the UTXO is mature (based on the coinbase maturity rule)
    pub fn is_mature(&self, current_height: u32) -> bool {
        println!("[DEBUG] Checking if UTXO is mature");
        if !self.is_coinbase {
            return true; // Non-coinbase outputs are immediately spendable
        }

        // Coinbase outputs require 100 confirmations before they can be spent
        let result = current_height >= self.block_height + 100;
        println!("[DEBUG] Is UTXO Mature: {}", result);
        result
    }
}

impl UTXOSetGuest {
    pub fn new() -> Self {
        println!("[DEBUG] Creating new UTXOSetGuest");
        let result = UTXOSetGuest {
            jmt_root: RootHash::from([0u8; 32]),
            version: 0,
            utxo_cache: BTreeMap::new(),
            // spent_utxos: BTreeMap::new(),
        };
        println!("[DEBUG] New UTXOSetGuest: {:?}", result);
        result
    }

    /// Create a new UTXOSetGuest with a given root hash and version
    pub fn with_root(jmt_root: RootHash, version: Version) -> Self {
        println!("[DEBUG] Creating UTXOSetGuest with root and version");
        let result = UTXOSetGuest {
            jmt_root,
            version,
            utxo_cache: BTreeMap::new(),
            // spent_utxos: BTreeMap::new(),
        };
        println!("[DEBUG] UTXOSetGuest with Root: {:?}", result);
        result
    }

    /// Get the current JMT root
    pub fn get_root(&self) -> RootHash {
        println!("[DEBUG] Getting JMT root");
        let result = self.jmt_root;
        println!("[DEBUG] JMT Root: {:?}", result);
        result
    }

    /// Get the current version
    pub fn get_version(&self) -> Version {
        println!("[DEBUG] Getting version");
        let result = self.version;
        println!("[DEBUG] Version: {:?}", result);
        result
    }

    /// Update the JMT root hash and version
    pub fn update_root(&mut self, new_root: RootHash, new_version: Version) {
        println!("[DEBUG] Updating JMT root and version");
        self.jmt_root = new_root;
        self.version = new_version;
        println!(
            "[DEBUG] Updated JMT Root: {:?}, Version: {:?}",
            self.jmt_root, self.version
        );
    }

    /// Verify that a UTXO exists
    pub fn verify_utxo_exists(&self, utxo_key: &KeyOutPoint) -> bool {
        println!("[DEBUG] Verifying UTXO existence");
        // Check cache first
        if self.has_cached_utxo(utxo_key) {
            return true;
        }

        // Otherwise, we need to verify with a proof
        // This is a stub implementation - in real code, you would need to provide a proof
        // from the host that can be verified against the root
        let result = false;
        println!("[DEBUG] UTXO Exists: {}", result);
        result
    }

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

    /// Method that categorizes the cached UTXOs for efficient block processing
    ///
    /// This method does three important things:
    /// 1. Identifies UTXOs that were created and spent within the same block (no JMT update needed)
    /// 2. Identifies UTXOs that need to be added to the JMT (created but not spent)
    /// 3. Identifies UTXOs that need to be removed from the JMT (spent from previous blocks)
    ///
    /// Returns a tuple of (to_add, to_remove) where each is a set of UTXO keys
    pub fn categorize_cached_changes(&self) -> (Vec<&KeyOutPoint>, Vec<&KeyOutPoint>) {
        println!("[DEBUG] Categorizing cached changes");
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();

        // In a real implementation, this would analyze the cache and identify
        // which UTXOs need to be added to the JMT and which need to be removed

        // For now, we return empty vectors as this is just a stub
        let result = (to_add, to_remove);
        println!("[DEBUG] Categorized Cached Changes: {:?}", result);
        result
    }
}
