use anyhow::{anyhow, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use std::path::Path;

use jmt::{
    storage::{
        HasPreimage, LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeUpdateBatch, TreeWriter,
    },
    KeyHash, OwnedValue, RootHash, Sha256Jmt, Version,
};

use bitcoin_consensus_core::{
    utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO},
    TransactionUTXOProofs, UTXOInsertionProof,
};

/// RocksDB storage implementation for the Jellyfish Merkle Tree
pub struct RocksDbStorage {
    /// The underlying RocksDB instance
    db: DB,
}

// Column family names
const NODES_CF: &str = "nodes";
const VALUES_CF: &str = "values";
const PREIMAGES_CF: &str = "preimages";
const METADATA_CF: &str = "metadata";

// Special keys for metadata
const LATEST_ROOT_KEY: &[u8] = b"LATEST_ROOT";
const LATEST_VERSION_KEY: &[u8] = b"LATEST_VERSION";
const RIGHTMOST_LEAF_KEY: &[u8] = b"RIGHTMOST_LEAF";

impl RocksDbStorage {
    /// Create a new RocksDbStorage at the specified path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Define column families with appropriate options
        let cf_names = vec![
            ColumnFamilyDescriptor::new(NODES_CF, Options::default()),
            ColumnFamilyDescriptor::new(VALUES_CF, Options::default()),
            ColumnFamilyDescriptor::new(PREIMAGES_CF, Options::default()),
            ColumnFamilyDescriptor::new(METADATA_CF, Options::default()),
        ];

        // Open database with column families
        let db = DB::open_cf_descriptors(&opts, path, cf_names)
            .context("Failed to open RocksDB database")?;

        Ok(Self { db })
    }

    /// Get a JMT instance that uses this storage
    pub fn get_jmt(&self) -> Sha256Jmt<Self> {
        Sha256Jmt::new(self)
    }

    /// Store the original key (preimage) for a key hash
    pub fn store_key_preimage(&self, key_hash: KeyHash, preimage: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(PREIMAGES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", PREIMAGES_CF))?;

        self.db
            .put_cf(cf, key_hash.0.to_vec(), preimage)
            .context("Failed to store key preimage")?;

        Ok(())
    }

    /// Get the latest root hash
    pub fn get_latest_root(&self) -> Result<Option<RootHash>> {
        let cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;

        if let Some(bytes) = self.db.get_cf(cf, LATEST_ROOT_KEY)? {
            let hash: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid root hash format"))?;
            Ok(Some(RootHash(hash)))
        } else {
            Ok(None)
        }
    }

    /// Store the latest root hash
    pub fn store_latest_root(&self, root_hash: RootHash) -> Result<()> {
        let cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;

        self.db
            .put_cf(cf, LATEST_ROOT_KEY, root_hash.0.to_vec())
            .context("Failed to store latest root hash")?;

        Ok(())
    }

    /// Update storage with a tree update batch and set the new root hash
    pub fn update_with_batch(&self, root_hash: RootHash, batch: TreeUpdateBatch) -> Result<()> {
        println!("[DEBUG] Updating storage with batch");
        self.write_node_batch(&batch.node_batch)?;
        println!("[DEBUG] Wrote node batch");
        self.store_latest_root(root_hash)?;
        println!("[DEBUG] Stored latest root");
        Ok(())
    }

    /// Get the latest version of the tree
    pub fn get_latest_version(&self) -> Result<Version> {
        let cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;

        if let Some(bytes) = self.db.get_cf(cf, LATEST_VERSION_KEY)? {
            let version: [u8; 8] = bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid version format"))?;
            Ok(u64::from_be_bytes(version))
        } else {
            Ok(0)
        }
    }

    /// Store the latest version
    pub fn store_latest_version(&self, version: Version) -> Result<()> {
        let cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;

        self.db
            .put_cf(cf, LATEST_VERSION_KEY, version.to_be_bytes().to_vec())
            .context("Failed to store latest version")?;

        Ok(())
    }

    /// Generates a proof for a given UTXO key TODO: Change this
    pub fn generate_proof(&self, utxo_key: &KeyOutPoint, version: Version) -> Result<()> {
        println!("[DEBUG] Generating proof for UTXO key: {:?}", utxo_key);

        // Get the JMT tree
        let tree = self.get_jmt();

        // Compute the key hash using OutPointBytes
        let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());

        // Retrieve the value and proof from the tree
        let (value_opt, proof) = tree.get_with_proof(key_hash, version)?;

        // Ensure the value exists
        if value_opt.is_none() {
            return Err(anyhow!("UTXO not found for the given key"));
        }

        // Verify the proof
        proof.verify_existence(tree.get_root_hash(version)?, key_hash, &value_opt.unwrap())?;

        println!("[DEBUG] Proof verified for UTXO key: {:?}", utxo_key);

        Ok(())
    }

    // /// Generates UTXO inclusion proofs for a list of UTXO keys
    // pub fn generate_utxo_inclusion_proofs(
    //     &self,
    //     utxo_keys: &[KeyOutPoint],
    //     version: Version,
    // ) -> Result<Vec<TransactionUTXOProofs>> {
    //     println!("[DEBUG] Generating UTXO inclusion proofs");
    //     let mut proofs = Vec::new();

    //     for utxo_key in utxo_keys {
    //         let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
    //         let (value_opt, proof) = self.get_jmt().get_with_proof(key_hash, version)?;

    //         if let Some(value) = value_opt {
    //             let utxo: UTXO = UTXOBytes(value).into();
    //             // Get latest root and unwrap it since we need it
    //             let root = match self.get_latest_root()? {
    //                 Some(r) => r,
    //                 None => return Err(anyhow!("No root hash found")),
    //             };

    //             let transaction_proof = TransactionUTXOProofs {
    //                 update_proof: vec![Some((proof, utxo, root))].into_iter().collect(),
    //                 new_root: root,
    //             };
    //             proofs.push(transaction_proof);
    //         } else {
    //             return Err(anyhow!("UTXO not found for key: {:?}", utxo_key));
    //         }
    //     }

    //     println!("[DEBUG] Generated UTXO inclusion proofs: {:?}", proofs);
    //     Ok(proofs)
    // }

    /// Generates UTXO insertion proofs for a list of UTXO keys
    pub fn generate_utxo_insertion_proofs(
        &self,
        utxo_keys: &[KeyOutPoint],
        version: Version,
    ) -> Result<Vec<UTXOInsertionProof>> {
        println!("[DEBUG] Generating UTXO insertion proofs");
        let mut proofs = Vec::new();

        for utxo_key in utxo_keys {
            let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
            let (value_opt, _) = self.get_jmt().get_with_proof(key_hash, version)?;

            if let Some(value) = value_opt {
                // Convert SparseMerkleProof to UpdateMerkleProof
                // This requires an additional call to get the update proof
                let (new_root, update_proof, _) = self
                    .get_jmt()
                    .put_value_set_with_proof([(key_hash, Some(value.clone()))], version)?;

                let insertion_proof = UTXOInsertionProof {
                    key: *utxo_key,
                    update_proof,
                    new_root,
                };
                proofs.push(insertion_proof);
            } else {
                return Err(anyhow!("UTXO not found for key: {:?}", utxo_key));
            }
        }

        println!("[DEBUG] Generated UTXO insertion proofs: {:?}", proofs);
        Ok(proofs)
    }
}

impl TreeReader for RocksDbStorage {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let cf = self
            .db
            .cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;

        let key_bytes = borsh::to_vec(node_key).context("Failed to serialize node key")?;

        if let Some(bytes) = self.db.get_cf(cf, key_bytes)? {
            let node = Node::try_from_slice(&bytes).context("Failed to deserialize node")?;
            Ok(Some(node))
        } else {
            Ok(None)
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let metadata_cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;

        // Check if we have cached the rightmost leaf
        if let Some(bytes) = self.db.get_cf(metadata_cf, RIGHTMOST_LEAF_KEY)? {
            let (node_key_bytes, leaf_node_bytes) = bytes.split_at(bytes.len() / 2);

            let node_key = NodeKey::try_from_slice(node_key_bytes)
                .context("Failed to deserialize rightmost leaf node key")?;

            let leaf_node = LeafNode::try_from_slice(leaf_node_bytes)
                .context("Failed to deserialize rightmost leaf node")?;

            return Ok(Some((node_key, leaf_node)));
        }

        // If not cached, we need to scan for leaf nodes
        // This is inefficient and should be replaced with proper tracking
        // of the rightmost leaf during tree updates
        let nodes_cf = self
            .db
            .cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;

        let mut rightmost: Option<(NodeKey, LeafNode)> = None;

        let iter = self.db.iterator_cf(nodes_cf, IteratorMode::Start);
        for result in iter {
            let (key_bytes, node_bytes) = result?;

            let node_key =
                NodeKey::try_from_slice(&key_bytes).context("Failed to deserialize node key")?;

            let node = Node::try_from_slice(&node_bytes).context("Failed to deserialize node")?;

            if let Node::Leaf(leaf_node) = node {
                if rightmost.is_none()
                    || leaf_node.key_hash() > rightmost.as_ref().unwrap().1.key_hash()
                {
                    rightmost = Some((node_key, leaf_node));
                }
            }
        }

        // If we found a rightmost leaf, cache it for future queries
        if let Some((ref node_key, ref leaf_node)) = rightmost {
            let mut combined = borsh::to_vec(node_key)?;
            combined.extend(borsh::to_vec(leaf_node)?);
            self.db.put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined)?;
        }

        Ok(rightmost)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let cf = self
            .db
            .cf_handle(VALUES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", VALUES_CF))?;

        // Create composite key prefix (key_hash part)
        let prefix = key_hash.0.to_vec();

        // First try direct lookup for exact version match
        let mut exact_key = prefix.clone();
        exact_key.extend_from_slice(&max_version.to_be_bytes());

        if let Some(value) = self.db.get_cf(cf, &exact_key)? {
            return Ok(Some(value.to_vec()));
        }

        // Use prefix iterator to efficiently find all versions of this key
        let iter = self.db.prefix_iterator_cf(cf, &prefix);

        let mut latest_version = 0;
        let mut latest_value = None;

        for result in iter {
            let (key, value) = result?;

            // Skip if key is too short (should have key_hash + version)
            if key.len() < prefix.len() + 8 {
                continue;
            }

            // Extract version from composite key
            // Version is stored after the key_hash
            let version_bytes: [u8; 8] = key[prefix.len()..prefix.len() + 8]
                .try_into()
                .map_err(|_| anyhow!("Invalid version format"))?;

            let version = u64::from_be_bytes(version_bytes);

            // Check if this version is valid and newer than what we've seen so far
            if version <= max_version && version > latest_version {
                latest_version = version;
                latest_value = Some(value.to_vec());
            }
        }

        Ok(latest_value)
    }
}

impl HasPreimage for RocksDbStorage {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        let cf = self
            .db
            .cf_handle(PREIMAGES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", PREIMAGES_CF))?;

        Ok(self.db.get_cf(cf, key_hash.0.to_vec())?)
    }
}

impl TreeWriter for RocksDbStorage {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        println!("[DEBUG] Writing node batch");
        let nodes_cf = self
            .db
            .cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;
        println!("[DEBUG] Got nodes column family");

        let values_cf = self
            .db
            .cf_handle(VALUES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", VALUES_CF))?;
        println!("[DEBUG] Got values column family");

        let metadata_cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;
        println!("[DEBUG] Got metadata column family");

        let mut batch = WriteBatch::default();
        println!("[DEBUG] Created write batch");
        let mut rightmost_leaf: Option<(NodeKey, LeafNode)> = None;
        println!("[DEBUG] Created rightmost leaf");

        // Write nodes
        for (key, node) in node_batch.nodes() {
            println!("[DEBUG] Writing node: {:?}", key);
            let key_bytes = borsh::to_vec(key)?;
            println!("[DEBUG] Serialized key");
            let node_bytes = borsh::to_vec(node)?;
            println!("[DEBUG] Serialized node");
            batch.put_cf(nodes_cf, key_bytes, node_bytes);
            println!("[DEBUG] Put node in batch");

            // Track potential rightmost leaf
            if let Node::Leaf(leaf_node) = node {
                println!("[DEBUG] Found leaf node");
                if rightmost_leaf.is_none()
                    || leaf_node.key_hash() > rightmost_leaf.as_ref().unwrap().1.key_hash()
                {
                    println!("[DEBUG] Updating rightmost leaf");
                    rightmost_leaf = Some((key.clone(), leaf_node.clone()));
                }
            }
        }
        println!("Wrote nodes");

        // Write values - using key_hash-first format for efficient lookups
        for ((version, key_hash), value_opt) in node_batch.values() {
            println!("Writing value: {:?}", key_hash);
            // Create composite key: key_hash (32 bytes) + version (8 bytes)
            let mut key = key_hash.0.to_vec();
            println!("Created key");
            key.extend_from_slice(&version.to_be_bytes());
            println!("Extended key");

            if let Some(value) = value_opt {
                batch.put_cf(values_cf, key, value);
            } else {
                batch.delete_cf(values_cf, key);
            }
        }

        println!("AAAAAAAAAAAAAAAA");

        // Update rightmost leaf if we found one
        if let Some((ref node_key, ref leaf_node)) = rightmost_leaf {
            println!("Updating rightmost leaf");
            // Instead of trying to use the stored rightmost leaf,
            // let's just compare key hashes directly and always update
            // This is simpler and avoids deserialization issues
            let mut combined = borsh::to_vec(node_key)?;
            combined.extend(borsh::to_vec(leaf_node)?);
            batch.put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined);
        }

        println!("Wrote rightmost leaf");
        // Commit all changes atomically
        self.db.write(batch)?;
        println!("Wrote batch");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::proof::UpdateMerkleProof;
    use tempfile::tempdir;

    #[test]
    fn test_utxo_lifecycle() -> Result<()> {
        // Create a temporary directory for the test database
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path();
        println!("Using temporary database at {:?}", db_path);

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path)?;
        let tree = storage.get_jmt();

        println!("Storage initialized");

        // Create UTXO
        let utxo_id = b"utxo_1";
        let utxo_data = b"utxo_data_1".to_vec();
        let key_hash = KeyHash::with::<sha2::Sha256>(utxo_id);
        storage.store_key_preimage(key_hash, utxo_id)?;

        println!("UTXO created");

        // Insert the UTXO
        let (root_after_insert, batch) = tree.put_value_set(
            [(key_hash, Some(utxo_data.clone()))],
            0, // version
        )?;

        println!("UTXO inserted");

        storage.update_with_batch(root_after_insert, batch)?;

        println!("Storage updated");
        println!("Root hash: {:?}", root_after_insert);
        println!("Key hash: {:?}", key_hash);
        println!("UTXO data: {:?}", utxo_data);
        println!("UTXO ID: {:?}", utxo_id);

        // Verify UTXO exists
        let (value_opt, proof) = tree.get_with_proof(key_hash, 0)?;
        assert_eq!(value_opt, Some(utxo_data.clone()));

        println!("UTXO verified");

        // Verify proof is valid
        assert!(proof
            .verify_existence(root_after_insert, key_hash, &utxo_data)
            .is_ok());

        println!("Proof verified");

        // Spend the UTXO (delete it)
        let (root_after_delete, deletion_proof, batch) = tree.put_value_set_with_proof(
            [(key_hash, None)],
            1, // next version
        )?;

        println!("UTXO deleted");
        println!("Root hash after delete: {:?}", root_after_delete);
        println!("Deletion proof: {:?}", deletion_proof);
        println!("Batch: {:?}", batch);

        storage.update_with_batch(root_after_delete, batch)?;

        println!("Storage updated after delete");

        // Verify UTXO is gone
        let value_after_delete = tree.get(key_hash, 1)?;
        assert_eq!(value_after_delete, None);

        println!("UTXO verified after delete");

        // Verify deletion proof is valid
        let updates: [(KeyHash, Option<Vec<u8>>); 1] = [(key_hash, None)];

        println!("Updates: {:?}", updates);

        assert!(deletion_proof
            .verify_update(root_after_insert, root_after_delete, &updates)
            .is_ok());

        println!("Deletion proof verified");

        // Check that we can retrieve the latest root
        let stored_root = storage.get_latest_root()?;

        println!("Stored root: {:?}", stored_root);

        assert_eq!(stored_root, Some(root_after_delete));

        println!("Root verified");

        Ok(())
    }

    #[test]
    fn test_transaction_utxo_insertion_and_deletion() -> Result<()> {
        // Create a temporary directory for the test database
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path();
        println!("Using temporary database at {:?}", db_path);

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path)?;
        let tree = storage.get_jmt();

        println!("HOST SIDE: Storage initialized");

        // Add dummy data to the tree before the main test logic
        let dummy_utxos = generate_dummy_utxos(5);
        let mut dummy_updates = Vec::new();

        for (i, (key, utxo)) in dummy_utxos.clone().into_iter().enumerate() {
            let key_bytes = OutPointBytes::from(key);
            let utxo_bytes = UTXOBytes::from(utxo);
            let key_hash = KeyHash::with::<sha2::Sha256>(&key_bytes);

            storage.store_key_preimage(key_hash, key_bytes.as_ref())?;
            dummy_updates.push((key_hash, Some(utxo_bytes.0.clone())));

            println!("HOST SIDE: Added dummy UTXO {}: {:?}", i, key);
        }

        // Insert all dummy UTXOs in a batch
        let (dummy_root, dummy_batch) = tree.put_value_set(
            dummy_updates,
            0, // version
        )?;

        storage.update_with_batch(dummy_root, dummy_batch)?;
        println!(
            "HOST SIDE: Populated tree with {} dummy UTXOs",
            dummy_utxos.len()
        );
        println!("HOST SIDE: Root after dummy data: {:?}", dummy_root);

        // Create utxo_spent, transaction, and utxo_created
        let utxo_spent_key: KeyOutPoint = KeyOutPoint {
            txid: [1u8; 32],
            vout: 1,
        };

        let utxo_spent_key_bytes = OutPointBytes::from(utxo_spent_key);

        let utxo_spent = UTXO {
            value: 100_000_000,
            block_height: 500_000,
            block_time: 1_500_000_000,
            is_coinbase: false,
            script_pubkey: vec![0u8; 34],
        };

        let utxo_spent_bytes = UTXOBytes::from(utxo_spent);

        let utxo_created_key: KeyOutPoint = KeyOutPoint {
            txid: [2u8; 32],
            vout: 2,
        };

        let utxo_created_key_bytes = OutPointBytes::from(utxo_created_key);

        let utxo_created = UTXO {
            value: 50_000_000,
            block_height: 500_001,
            block_time: 1_500_000_600,
            is_coinbase: false,
            script_pubkey: vec![1u8; 34],
        };

        let utxo_created_bytes = UTXOBytes::from(utxo_created);

        // Use the dummy_root instead of zero_root
        let initial_root = storage.get_latest_root()?;
        println!("HOST SIDE: Initial root: {:?}", initial_root);
        assert_eq!(initial_root, Some(dummy_root));

        let utxo_spent_key_hash = KeyHash::with::<sha2::Sha256>(&utxo_spent_key_bytes);
        storage.store_key_preimage(utxo_spent_key_hash, utxo_spent_bytes.as_ref())?;

        // Insert the UTXO
        let (root_after_insert, batch) = tree.put_value_set(
            [(utxo_spent_key_hash, Some(utxo_spent_bytes.0.clone()))],
            1, // version (incremented because we added dummy data at version 0)
        )?;

        println!("HOST SIDE: UTXO inserted");

        storage.update_with_batch(root_after_insert, batch)?;

        println!("HOST SIDE: Storage updated");
        println!("HOST SIDE: Root hash: {:?}", root_after_insert);
        println!("HOST SIDE: Key hash: {:?}", utxo_spent_key_hash);
        println!("HOST SIDE: UTXO data: {:?}", utxo_spent_bytes.0.clone());
        println!("HOST SIDE: UTXO key: {:?}", utxo_spent_key);

        // Now process the transaction on the host side

        // Verify KeyOutPoint exists with UTXO in the tree, and generate proof
        let (value_opt, proof) = tree.get_with_proof(utxo_spent_key_hash, 1)?;
        assert_eq!(value_opt, Some(utxo_spent_bytes.0.clone()));

        println!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");
        println!("Proof before delete for comparison: {:?}", proof);

        // Verify proof is valid (Also will be done on the guest side)
        assert!(proof
            .verify_existence(root_after_insert, utxo_spent_key_hash, &utxo_spent_bytes.0)
            .is_ok());

        println!("HOST SIDE: Inclusion Proof verified");

        // Spend the UTXO (delete it). Here, the deletion proof does not allow the
        let (root_after_delete, deletion_proof, batch) = tree.put_value_set_with_proof(
            [(utxo_spent_key_hash, None)],
            2, // next version
        )?;

        // Here, make sure the deletion proof is taken as a sparse merkle proof
        // and not an update proof, then convert it to an update proof
        // Okay, the most reasonable thing to do is to just two inclusion proofs
        // one for the spent UTXO, and one for the None, which is the deletion
        // proof. Then, serialize them and compare their Merkle paths.

        println!("HOST SIDE: UTXO deleted");
        println!("HOST SIDE: Root hash after delete: {:?}", root_after_delete);
        println!("HOST SIDE: Deletion proof: {:?}", deletion_proof);
        println!("HOST SIDE: Batch: {:?}", batch);

        storage.update_with_batch(root_after_delete, batch)?;

        println!("HOST SIDE: Storage updated after delete");

        // Verify UTXO is gone
        let (value_after_delete, proof_after_delete) =
            tree.get_with_proof(utxo_spent_key_hash, 2)?;
        assert_eq!(value_after_delete, None);

        println!(
            "Proof after delete for comparison: {:?}",
            proof_after_delete
        );

        // We should use verify_nonexistence instead of verify_existence for a deleted UTXO
        assert!(proof_after_delete
            .verify_nonexistence(root_after_delete, utxo_spent_key_hash)
            .is_ok());

        println!("HOST SIDE: UTXO verified after delete");

        // Verify deletion proof is valid
        let updates = vec![(utxo_spent_key_hash, None::<Vec<u8>>)];

        println!("HOST SIDE: Updates: {:?}", updates);

        assert!(deletion_proof
            .verify_update(root_after_insert, root_after_delete, &updates)
            .is_ok());

        println!("HOST SIDE: Deletion proof verified");

        // Check that we can retrieve the latest root
        let stored_root_after_delete = storage.get_latest_root()?;

        println!(
            "HOST SIDE: Stored root after spent UTXO deletion: {:?}",
            stored_root_after_delete
        );

        assert_eq!(stored_root_after_delete, Some(root_after_delete));

        println!("HOST SIDE: Root verified after spent UTXO deletion");

        // Now, insert the new UTXO
        let utxo_created_key_hash = KeyHash::with::<sha2::Sha256>(&utxo_created_key_bytes);
        storage.store_key_preimage(utxo_created_key_hash, utxo_created_key_bytes.as_ref())?;

        // Insert the UTXO
        let (root_after_insert, update_proof, batch) = tree.put_value_set_with_proof(
            [(utxo_created_key_hash, Some(utxo_created_bytes.0.clone()))],
            3, // version (incremented)
        )?;

        println!("HOST SIDE: UTXO inserted");
        println!("HOST SIDE: Root hash after insert: {:?}", root_after_insert);
        println!("HOST SIDE: Key hash: {:?}", utxo_created_key_hash);
        println!("HOST SIDE: UTXO data: {:?}", utxo_created_bytes.0.clone());
        println!("HOST SIDE: UTXO key: {:?}", utxo_created_key);
        println!("HOST SIDE: Batch: {:?}", batch);
        storage.update_with_batch(root_after_insert, batch)?;

        // Now verify the update proof for the new UTXO
        let (value_opt, inclusion_proof) = tree.get_with_proof(utxo_created_key_hash, 3)?;
        println!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");
        println!("HOST SIDE: Value: {:?}", value_opt);
        println!("HOST SIDE: Proof: {:?}", inclusion_proof);
        assert_eq!(value_opt, Some(utxo_created_bytes.0.clone()));
        // let update_proof = UpdateMerkleProof::new(vec![inclusion_proof]);
        // println!("HOST SIDE: update_proof: {:?}", update_proof);

        let latest_root = storage.get_latest_root()?;
        println!("HOST SIDE: Latest root: {:?}", latest_root);
        assert_eq!(latest_root, Some(root_after_insert));

        // println!("update batch: {:?}", batch);

        let updates = vec![(utxo_created_key_hash, Some(utxo_created_bytes.0.clone()))];

        println!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");
        assert!(update_proof
            .verify_update(root_after_delete, root_after_insert, &updates)
            .is_ok());

        Ok(())
    }

    // Helper function to generate dummy UTXOs for testing
    fn generate_dummy_utxos(count: usize) -> Vec<(KeyOutPoint, UTXO)> {
        let mut dummy_utxos = Vec::with_capacity(count);

        for i in 0..count {
            // Create unique dummy key
            let mut txid = [0u8; 32];
            // Use a different pattern for each dummy UTXO to ensure uniqueness
            txid[0] = 100 + i as u8;
            txid[1] = 200 + i as u8;

            let key = KeyOutPoint {
                txid,
                vout: i as u32,
            };

            // Create dummy UTXO with varying values
            let utxo = UTXO {
                value: 10_000_000 + (i as u64 * 1_000_000),
                block_height: 400_000 + i as u32,
                block_time: 1_400_000_000 + (i as u32 * 600),
                is_coinbase: i % 5 == 0,          // Every 5th is coinbase
                script_pubkey: vec![i as u8; 34], // Varying script
            };

            dummy_utxos.push((key, utxo));
        }

        dummy_utxos
    }
}
