use anyhow::{anyhow, Context, Result};
use borsh::BorshDeserialize;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use std::path::Path;
use tracing::{info, warn};

use jmt::{
    storage::{
        HasPreimage, LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeUpdateBatch, TreeWriter,
    },
    KeyHash, OwnedValue, RootHash, Sha256Jmt, Version,
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

    /// Inspect all keys and values in all column families for debugging
    pub fn inspect_all(&self) -> Result<()> {
        for cf_name in [NODES_CF, VALUES_CF, PREIMAGES_CF, METADATA_CF] {
            let cf = self
                .db
                .cf_handle(cf_name)
                .ok_or_else(|| anyhow!("Column family '{}' not found", cf_name))?;

            info!("--- Column Family: {} ---", cf_name);
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);

            for result in iter {
                let (key, value) = result?;
                info!("Key: ");

                match cf_name {
                    NODES_CF => {
                        if let Ok(node_key) = NodeKey::try_from_slice(&key) {
                            info!("{:?}", node_key);
                        } else {
                            info!("{:?}", key);
                        }

                        if let Ok(node) = Node::try_from_slice(&value) {
                            info!(" => Node: {:?}", node);
                        } else {
                            info!(" => Raw: {:?}", value);
                        }
                    }
                    VALUES_CF => {
                        if key.len() >= 40 {
                            let key_hash: [u8; 32] = key[..32].try_into().unwrap_or([0u8; 32]);
                            let version =
                                u64::from_be_bytes(key[32..40].try_into().unwrap_or([0u8; 8]));
                            info!("KeyHash: {:x?}, Version: {}", key_hash, version);
                        } else {
                            info!("{:?}", key);
                        }
                        info!(" => Value: {:?}", value);
                    }
                    PREIMAGES_CF => {
                        info!(
                            "{:x?} => Preimage: {:?}",
                            key,
                            String::from_utf8_lossy(&value)
                        );
                    }
                    METADATA_CF => {
                        let name = match &*key {
                            b"LATEST_ROOT" => "LATEST_ROOT",
                            b"LATEST_VERSION" => "LATEST_VERSION",
                            b"RIGHTMOST_LEAF" => "RIGHTMOST_LEAF",
                            _ => "UNKNOWN",
                        };
                        info!("{} => {:?}", name, value);
                    }
                    _ => {
                        info!("{:?} => {:?}", key, value);
                    }
                }
            }
            println!();
        }
        Ok(())
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
    pub fn update_with_batch(
        &self,
        root_hash: RootHash,
        batch: TreeUpdateBatch,
        version: Version,
    ) -> Result<()> {
        info!("[DEBUG] Updating storage with batch");
        // Check if the tree already has a root (if not, this is the first insertion)
        let has_existing_root = self.get_latest_root()?.is_some();
        info!("[DEBUG] Has existing root: {}", has_existing_root);

        self.write_node_batch(&batch.node_batch)?;
        info!("[DEBUG] Wrote node batch");
        self.store_latest_root(root_hash)?;
        info!("[DEBUG] Stored latest root");
        self.store_latest_version(version)?;
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

        // Create the prefix we want to match exactly
        let prefix = key_hash.0.to_vec();

        // Create read options with prefix seeking enabled
        let mut read_options = rocksdb::ReadOptions::default();
        read_options.set_prefix_same_as_start(true); // This is the key setting

        // Use prefix iterator with the configured read options
        let iter = self.db.iterator_cf_opt(
            cf,
            read_options,
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );

        let mut latest_version = 0;
        let mut latest_value = None;

        for result in iter {
            let (key, value) = result?;

            // Double-check the key starts with our prefix
            // (this is just a safety check as set_prefix_same_as_start should ensure this)
            if !key.starts_with(&prefix) {
                break; // Stop iterating once we've moved past our prefix
            }

            // Skip if key is too short (should have key_hash + version)
            if key.len() < prefix.len() + 8 {
                continue;
            }

            // Extract version from composite key
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
        info!("[DEBUG] Writing node batch");
        let nodes_cf = self
            .db
            .cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;
        info!("[DEBUG] Got nodes column family");

        let values_cf = self
            .db
            .cf_handle(VALUES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", VALUES_CF))?;
        info!("[DEBUG] Got values column family");

        let metadata_cf = self
            .db
            .cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;
        info!("[DEBUG] Got metadata column family");

        let mut batch = WriteBatch::default();
        info!("[DEBUG] Created write batch");
        let mut rightmost_leaf: Option<(NodeKey, LeafNode)> = None;
        info!("[DEBUG] Created rightmost leaf");

        // Check if this is the first insertion (tree is empty)
        let is_empty_tree = self.get_latest_root()?.is_none();
        info!("[DEBUG] Is empty tree: {}", is_empty_tree);

        // Write nodes
        for (key, node) in node_batch.nodes() {
            info!("[DEBUG] Writing node: {:?}", key);
            let key_bytes = borsh::to_vec(key)?;
            info!("[DEBUG] Serialized key");
            let node_bytes = borsh::to_vec(node)?;
            info!("[DEBUG] Serialized node");
            batch.put_cf(nodes_cf, key_bytes, node_bytes);
            info!("[DEBUG] Put node in batch");

            // Track potential rightmost leaf
            if let Node::Leaf(leaf_node) = node {
                info!("[DEBUG] Found leaf node");
                if rightmost_leaf.is_none()
                    || leaf_node.key_hash() > rightmost_leaf.as_ref().unwrap().1.key_hash()
                {
                    info!("[DEBUG] Updating rightmost leaf");
                    rightmost_leaf = Some((key.clone(), leaf_node.clone()));
                }
            }
        }
        info!("Wrote nodes");

        // Write values - using key_hash-first format for efficient lookups
        for ((version, key_hash), value_opt) in node_batch.values() {
            info!("Writing value: {:?}", key_hash);
            // Create composite key: key_hash (32 bytes) + version (8 bytes)
            let mut key = key_hash.0.to_vec();
            info!("Created key");
            key.extend_from_slice(&version.to_be_bytes());
            info!("Extended key");

            if let Some(value) = value_opt {
                batch.put_cf(values_cf, key, value);
                info!(
                    "[DEBUG] Added value for key_hash: {:?}, version: {}",
                    key_hash, version
                );
            } else {
                // For nonexistence cases, we need to handle empty trees differently
                if is_empty_tree {
                    info!("[DEBUG] Skipping delete operation for empty tree");
                } else {
                    batch.delete_cf(values_cf, key);
                    info!(
                        "[DEBUG] Deleted value for key_hash: {:?}, version: {}",
                        key_hash, version
                    );
                }
            }
        }

        // Update rightmost leaf if we found one
        if let Some((ref node_key, ref leaf_node)) = rightmost_leaf {
            info!("Updating rightmost leaf");
            // Instead of trying to use the stored rightmost leaf,
            // let's just compare key hashes directly and always update
            // This is simpler and avoids deserialization issues
            let mut combined = borsh::to_vec(node_key)?;
            combined.extend(borsh::to_vec(leaf_node)?);
            batch.put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined);
        }

        info!("Wrote rightmost leaf");
        // Commit all changes atomically
        self.db.write(batch)?;
        info!("Wrote batch");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_consensus_core::utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO};
    use jmt::ValueHash;
    use tempfile::tempdir;

    #[test]
    fn test_utxo_lifecycle() -> Result<()> {
        // Create a temporary directory for the test database
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path();
        info!("Using temporary database at {:?}", db_path);

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path)?;
        let tree = storage.get_jmt();

        info!("Storage initialized");

        // Create UTXO
        let utxo_id = b"utxo_1";
        let utxo_data = b"utxo_data_1".to_vec();
        let key_hash = KeyHash::with::<sha2::Sha256>(utxo_id);
        storage.store_key_preimage(key_hash, utxo_id)?;

        info!("UTXO created");

        // Insert the UTXO
        let (root_after_insert, batch) = tree.put_value_set(
            [(key_hash, Some(utxo_data.clone()))],
            0, // version
        )?;

        info!("UTXO inserted");

        storage.update_with_batch(root_after_insert, batch, 0)?;

        info!("Storage updated");
        info!("Root hash: {:?}", root_after_insert);
        info!("Key hash: {:?}", key_hash);
        info!("UTXO data: {:?}", utxo_data);
        info!("UTXO ID: {:?}", utxo_id);

        // Verify UTXO exists
        let (value_opt, proof) = tree.get_with_proof(key_hash, 0)?;
        assert_eq!(value_opt, Some(utxo_data.clone()));

        info!("UTXO verified");

        // Verify proof is valid
        assert!(proof
            .verify_existence(root_after_insert, key_hash, &utxo_data)
            .is_ok());

        info!("Proof verified");

        // Spend the UTXO (delete it)
        let (root_after_delete, deletion_proof, batch) = tree.put_value_set_with_proof(
            [(key_hash, None)],
            1, // next version
        )?;

        info!("UTXO deleted");
        info!("Root hash after delete: {:?}", root_after_delete);
        info!("Deletion proof: {:?}", deletion_proof);
        info!("Batch: {:?}", batch);

        storage.update_with_batch(root_after_delete, batch, 1)?;

        info!("Storage updated after delete");

        // Verify UTXO is gone
        let value_after_delete = tree.get(key_hash, 1)?;
        assert_eq!(value_after_delete, None);

        info!("UTXO verified after delete");

        // Verify deletion proof is valid
        let updates: [(KeyHash, Option<Vec<u8>>); 1] = [(key_hash, None)];

        info!("Updates: {:?}", updates);

        assert!(deletion_proof
            .verify_update(root_after_insert, root_after_delete, &updates)
            .is_ok());

        info!("Deletion proof verified");

        // Check that we can retrieve the latest root
        let stored_root = storage.get_latest_root()?;

        info!("Stored root: {:?}", stored_root);

        assert_eq!(stored_root, Some(root_after_delete));

        info!("Root verified");

        Ok(())
    }

    #[test]
    fn test_transaction_utxo_insertion_and_deletion() -> Result<()> {
        // Create a temporary directory for the test database
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path();
        info!("Using temporary database at {:?}", db_path);

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path)?;
        let tree = storage.get_jmt();

        info!("HOST SIDE: Storage initialized");

        // Add dummy data to the tree before the main test logic
        let dummy_utxos = generate_dummy_utxos(5);
        let mut dummy_updates = Vec::new();

        for (i, (key, utxo)) in dummy_utxos.clone().into_iter().enumerate() {
            let key_bytes = OutPointBytes::from(key);
            let utxo_bytes = UTXOBytes::from(utxo);
            let key_hash = KeyHash::with::<sha2::Sha256>(&key_bytes);

            storage.store_key_preimage(key_hash, key_bytes.as_ref())?;
            dummy_updates.push((key_hash, Some(utxo_bytes.0.clone())));

            info!("HOST SIDE: Added dummy UTXO {}: {:?}", i, key);
        }

        // Insert all dummy UTXOs in a batch
        let (dummy_root, dummy_batch) = tree.put_value_set(
            dummy_updates,
            0, // version
        )?;

        storage.update_with_batch(dummy_root, dummy_batch, 0)?;
        info!(
            "HOST SIDE: Populated tree with {} dummy UTXOs",
            dummy_utxos.len()
        );
        info!("HOST SIDE: Root after dummy data: {:?}", dummy_root);

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
        info!("HOST SIDE: Initial root: {:?}", initial_root);
        assert_eq!(initial_root, Some(dummy_root));

        let utxo_spent_key_hash = KeyHash::with::<sha2::Sha256>(&utxo_spent_key_bytes);
        storage.store_key_preimage(utxo_spent_key_hash, utxo_spent_bytes.as_ref())?;

        // Insert the UTXO
        let (root_after_insert, batch) = tree.put_value_set(
            [(utxo_spent_key_hash, Some(utxo_spent_bytes.0.clone()))],
            1, // version (incremented because we added dummy data at version 0)
        )?;

        info!("HOST SIDE: UTXO inserted");

        storage.update_with_batch(root_after_insert, batch, 1)?;

        info!("HOST SIDE: Storage updated");
        info!("HOST SIDE: Root hash: {:?}", root_after_insert);
        info!("HOST SIDE: Key hash: {:?}", utxo_spent_key_hash);
        info!("HOST SIDE: UTXO data: {:?}", utxo_spent_bytes.0.clone());
        info!("HOST SIDE: UTXO key: {:?}", utxo_spent_key);

        // Now process the transaction on the host side

        // Verify KeyOutPoint exists with UTXO in the tree, and generate proof
        let (value_opt, proof) = tree.get_with_proof(utxo_spent_key_hash, 1)?;
        assert_eq!(value_opt, Some(utxo_spent_bytes.0.clone()));

        info!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");
        info!("Proof before delete for comparison: {:?}", proof);

        // Verify proof is valid (Also will be done on the guest side)
        assert!(proof
            .verify_existence(root_after_insert, utxo_spent_key_hash, &utxo_spent_bytes.0)
            .is_ok());

        info!("HOST SIDE: Inclusion Proof verified");

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

        info!("HOST SIDE: UTXO deleted");
        info!("HOST SIDE: Root hash after delete: {:?}", root_after_delete);
        info!("HOST SIDE: Deletion proof: {:?}", deletion_proof);
        info!("HOST SIDE: Batch: {:?}", batch);

        storage.update_with_batch(root_after_delete, batch, 2)?;

        info!("HOST SIDE: Storage updated after delete");

        // Verify UTXO is gone
        let (value_after_delete, proof_after_delete) =
            tree.get_with_proof(utxo_spent_key_hash, 2)?;
        assert_eq!(value_after_delete, None);

        info!(
            "Proof after delete for comparison: {:?}",
            proof_after_delete
        );

        // We should use verify_nonexistence instead of verify_existence for a deleted UTXO
        assert!(proof_after_delete
            .verify_nonexistence(root_after_delete, utxo_spent_key_hash)
            .is_ok());

        info!("HOST SIDE: UTXO verified after delete");

        // Verify deletion proof is valid
        let updates = vec![(utxo_spent_key_hash, None::<Vec<u8>>)];

        info!("HOST SIDE: Updates: {:?}", updates);

        info!("DELETION PROOF: {:?}", deletion_proof);

        assert!(deletion_proof
            .verify_update(root_after_insert, root_after_delete, &updates)
            .is_ok());

        info!("HOST SIDE: Deletion proof verified");

        // Check that we can retrieve the latest root
        let stored_root_after_delete = storage.get_latest_root()?;

        info!(
            "HOST SIDE: Stored root after spent UTXO deletion: {:?}",
            stored_root_after_delete
        );

        assert_eq!(stored_root_after_delete, Some(root_after_delete));

        info!("HOST SIDE: Root verified after spent UTXO deletion");

        // Now, insert the new UTXO
        let utxo_created_key_hash = KeyHash::with::<sha2::Sha256>(&utxo_created_key_bytes);
        storage.store_key_preimage(utxo_created_key_hash, utxo_created_key_bytes.as_ref())?;

        // Insert the UTXO
        let (root_after_insert, update_proof, batch) = tree.put_value_set_with_proof(
            [(utxo_created_key_hash, Some(utxo_created_bytes.0.clone()))],
            3, // version (incremented)
        )?;

        info!("HOST SIDE: UTXO inserted");
        info!("HOST SIDE: Root hash after insert: {:?}", root_after_insert);
        info!("HOST SIDE: Key hash: {:?}", utxo_created_key_hash);
        info!("HOST SIDE: UTXO data: {:?}", utxo_created_bytes.0.clone());
        info!("HOST SIDE: UTXO key: {:?}", utxo_created_key);
        info!("HOST SIDE: Batch: {:?}", batch);
        storage.update_with_batch(root_after_insert, batch, 3)?;

        // Now verify the update proof for the new UTXO
        let (value_opt, inclusion_proof) = tree.get_with_proof(utxo_created_key_hash, 3)?;
        info!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");
        info!("HOST SIDE: Value: {:?}", value_opt);
        info!("HOST SIDE: Proof: {:?}", inclusion_proof);
        assert_eq!(value_opt, Some(utxo_created_bytes.0.clone()));
        // let update_proof = UpdateMerkleProof::new(vec![inclusion_proof]);
        // info!("HOST SIDE: update_proof: {:?}", update_proof);

        let latest_root = storage.get_latest_root()?;
        info!("HOST SIDE: Latest root: {:?}", latest_root);
        assert_eq!(latest_root, Some(root_after_insert));

        // info!("update batch: {:?}", batch);

        let updates = vec![(utxo_created_key_hash, Some(utxo_created_bytes.0.clone()))];

        info!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");
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

    #[test]
    fn test_utxo_update() -> Result<()> {
        // Create a temporary directory for the test database
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path();
        info!("Using temporary database at {:?}", db_path);

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path)?;
        let tree = storage.get_jmt();

        info!("HOST SIDE: Storage initialized");

        // Add dummy data to the tree before the main test logic
        let dummy_utxos = generate_dummy_utxos(5);
        let mut dummy_updates = Vec::new();

        for (i, (key, utxo)) in dummy_utxos.clone().into_iter().enumerate() {
            let key_bytes = OutPointBytes::from(key);
            let utxo_bytes = UTXOBytes::from(utxo);
            let key_hash = KeyHash::with::<sha2::Sha256>(&key_bytes);

            storage.store_key_preimage(key_hash, key_bytes.as_ref())?;
            dummy_updates.push((key_hash, Some(utxo_bytes.0.clone())));

            info!("HOST SIDE: Added dummy UTXO {}: {:?}", i, key);
        }

        // Insert all dummy UTXOs in a batch
        let (dummy_root, dummy_batch) = tree.put_value_set(
            dummy_updates,
            0, // version
        )?;

        storage.update_with_batch(dummy_root, dummy_batch, 0)?;
        info!(
            "HOST SIDE: Populated tree with {} dummy UTXOs",
            dummy_utxos.len()
        );
        info!("HOST SIDE: Root after dummy data: {:?}", dummy_root);

        // Create the UTXO to be updated (utxo_A)
        let utxo_key: KeyOutPoint = KeyOutPoint {
            txid: [3u8; 32],
            vout: 1,
        };

        let utxo_key_bytes = OutPointBytes::from(utxo_key);

        let utxo_a = UTXO {
            value: 100_000_000,
            block_height: 500_000,
            block_time: 1_500_000_000,
            is_coinbase: false,
            script_pubkey: vec![0u8; 34],
        };

        let utxo_a_bytes = UTXOBytes::from(utxo_a);

        // Use the dummy_root instead of zero_root
        let initial_root = storage.get_latest_root()?;
        info!("HOST SIDE: Initial root: {:?}", initial_root);
        assert_eq!(initial_root, Some(dummy_root));

        let utxo_key_hash = KeyHash::with::<sha2::Sha256>(&utxo_key_bytes);
        storage.store_key_preimage(utxo_key_hash, utxo_key_bytes.as_ref())?;

        // Insert the UTXO_A
        let (root_after_insert_a, batch) = tree.put_value_set(
            [(utxo_key_hash, Some(utxo_a_bytes.0.clone()))],
            1, // version (incremented because we added dummy data at version 0)
        )?;
        let utxo_a_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_a_bytes);
        info!("HOST SIDE: UTXO_A value hash: {:?}", utxo_a_value_hash);
        info!("HOST SIDE: UTXO_A inserted");

        storage.update_with_batch(root_after_insert_a, batch, 1)?;

        info!("HOST SIDE: Storage updated");
        info!(
            "HOST SIDE: Root hash after insert A: {:?}",
            root_after_insert_a
        );
        info!("HOST SIDE: Key hash: {:?}", utxo_key_hash);
        info!("HOST SIDE: UTXO_A data: {:?}", utxo_a_bytes.0.clone());
        info!("HOST SIDE: UTXO key: {:?}", utxo_key);

        // Verify UTXO_A was inserted correctly
        let (value_opt_a, proof_a) = tree.get_with_proof(utxo_key_hash, 1)?;
        assert_eq!(value_opt_a, Some(utxo_a_bytes.0.clone()));

        info!("HOST SIDE: UTXO_A verified in tree");
        assert!(proof_a
            .verify_existence(root_after_insert_a, utxo_key_hash, &utxo_a_bytes.0)
            .is_ok());

        info!("HOST SIDE: UTXO_A inclusion proof verified");

        // Now create UTXO_B (the updated version of UTXO_A)
        let utxo_b = UTXO {
            value: 90_000_000,         // Decreased value (as if part was spent)
            block_height: 500_001,     // Updated block height
            block_time: 1_500_000_600, // Updated block time
            is_coinbase: false,
            script_pubkey: vec![0u8; 34], // Same script pubkey
        };

        let utxo_b_bytes = UTXOBytes::from(utxo_b);
        let utxo_b_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_b_bytes);
        info!("HOST SIDE: UTXO_B value hash: {:?}", utxo_b_value_hash);

        // Update UTXO_A to UTXO_B (same key, different value)
        let (root_after_update, update_proof, batch) = tree.put_value_set_with_proof(
            [(utxo_key_hash, Some(utxo_b_bytes.0.clone()))],
            2, // next version
        )?;

        info!("HOST SIDE: UTXO updated from A to B");
        info!("HOST SIDE: Root hash after update: {:?}", root_after_update);
        info!("HOST SIDE: Update proof: {:?}", update_proof);
        let update_proof_to_borsh = borsh::to_vec(&update_proof)?;
        info!("Update proof serialized: {:?}", update_proof_to_borsh);
        let key_hash_from_borsh = borsh::from_slice::<KeyHash>(&update_proof_to_borsh[5..37])?;
        info!("Key hash from borsh: {:?}", key_hash_from_borsh);
        let value_a_hash_from_borsh =
            borsh::from_slice::<ValueHash>(&update_proof_to_borsh[37..69])?;
        info!("Value A hash from borsh: {:?}", value_a_hash_from_borsh);
        assert_eq!(key_hash_from_borsh, utxo_key_hash);
        assert_eq!(value_a_hash_from_borsh, utxo_a_value_hash);

        info!("HOST SIDE: Batch: {:?}", batch);

        storage.update_with_batch(root_after_update, batch, 2)?;

        info!("HOST SIDE: Storage updated after UTXO update");

        // Verify UTXO was updated correctly
        let (value_after_update, proof_after_update) = tree.get_with_proof(utxo_key_hash, 2)?;
        assert_eq!(value_after_update, Some(utxo_b_bytes.0.clone()));

        info!("HOST SIDE: Updated UTXO verified in tree");
        assert!(proof_after_update
            .verify_existence(root_after_update, utxo_key_hash, &utxo_b_bytes.0)
            .is_ok());

        info!("HOST SIDE: Updated UTXO inclusion proof verified");

        // Verify update proof is valid
        let updates = vec![(utxo_key_hash, Some(utxo_b_bytes.0.clone()))];

        info!("HOST SIDE: Updates: {:?}", updates);
        info!("UPDATE PROOF: {:?}", update_proof);

        assert!(update_proof
            .verify_update(root_after_insert_a, root_after_update, &updates)
            .is_ok());

        info!("HOST SIDE: Update proof verified");

        // Check that we can retrieve the latest root
        let stored_root_after_update = storage.get_latest_root()?;

        info!(
            "HOST SIDE: Stored root after UTXO update: {:?}",
            stored_root_after_update
        );

        assert_eq!(stored_root_after_update, Some(root_after_update));

        info!("HOST SIDE: Root verified after UTXO update");

        // Additional test: verify that we can still access the original UTXO_A at its version
        let (value_at_version_1, _) = tree.get_with_proof(utxo_key_hash, 1)?;
        assert_eq!(value_at_version_1, Some(utxo_a_bytes.0.clone()));
        info!("HOST SIDE: Original UTXO_A still accessible at version 1");

        // Current version should have UTXO_B
        let value_at_version_2 = tree.get(utxo_key_hash, 2)?;
        assert_eq!(value_at_version_2, Some(utxo_b_bytes.0.clone()));
        info!("HOST SIDE: Updated UTXO_B accessible at version 2");

        Ok(())
    }

    #[test]
    fn test_first_utxo_insertion() -> Result<()> {
        // Create a temporary directory for the test database
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path();
        info!("Using temporary database at {:?}", db_path);

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path)?;
        let tree = storage.get_jmt();

        info!("HOST SIDE: Storage initialized");

        // Create the UTXO to be updated (utxo_A)
        let utxo_key: KeyOutPoint = KeyOutPoint {
            txid: [3u8; 32],
            vout: 1,
        };

        let utxo_key_bytes = OutPointBytes::from(utxo_key);

        let utxo_a = UTXO {
            value: 100_000_000,
            block_height: 500_000,
            block_time: 1_500_000_000,
            is_coinbase: false,
            script_pubkey: vec![0u8; 34],
        };

        let utxo_a_bytes = UTXOBytes::from(utxo_a);

        let initial_root_none = storage.get_latest_root()?;
        assert_eq!(initial_root_none, None);

        let initial_root: RootHash = RootHash([
            83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76,
            68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
        ]);

        let utxo_key_hash = KeyHash::with::<sha2::Sha256>(&utxo_key_bytes);
        storage.store_key_preimage(utxo_key_hash, utxo_key_bytes.as_ref())?;

        // Insert the UTXO_A
        let (root_after_insert_a, update_proof, batch) = tree.put_value_set_with_proof(
            [(utxo_key_hash, Some(utxo_a_bytes.0.clone()))],
            0, // version (incremented because we added dummy data at version 0)
        )?;

        storage.update_with_batch(root_after_insert_a, batch, 0)?;
        let utxo_a_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_a_bytes);

        info!("HOST SIDE: UTXO_A value hash: {:?}", utxo_a_value_hash);
        info!("HOST SIDE: UTXO_A inserted");

        info!("HOST SIDE: Storage updated");
        info!(
            "HOST SIDE: Root hash after insert A: {:?}",
            root_after_insert_a
        );
        info!("HOST SIDE: Key hash: {:?}", utxo_key_hash);
        info!("HOST SIDE: UTXO_A data: {:?}", utxo_a_bytes.0.clone());
        info!("HOST SIDE: UTXO key: {:?}", utxo_key);

        // Verify UTXO_A was inserted correctly
        let (value_opt_a, proof_a) = tree.get_with_proof(utxo_key_hash, 0)?;
        info!("Inclusion proof for UTXO_A: {:?}", proof_a);

        info!("HOST SIDE: KeyOutPoint-UTXO taken from the tree with proof");

        assert_eq!(value_opt_a, Some(utxo_a_bytes.0.clone()));

        info!("HOST SIDE: UTXO_A verified in tree");

        let update = [(utxo_key_hash, Some(utxo_a_bytes.0.clone()))];

        update_proof
            .verify_update(initial_root, root_after_insert_a, update)
            .unwrap();

        info!("HOST SIDE: UTXO_A verified in tree");
        assert!(proof_a
            .verify_existence(root_after_insert_a, utxo_key_hash, &utxo_a_bytes.0)
            .is_ok());

        info!("HOST SIDE: UTXO_A inclusion proof verified");

        Ok(())
    }
}
