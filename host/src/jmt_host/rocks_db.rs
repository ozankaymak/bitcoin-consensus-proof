use std::path::Path;
use anyhow::{Result, anyhow, Context};
use borsh::{BorshSerialize, BorshDeserialize};
use rocksdb::{DB, Options, WriteBatch, ColumnFamilyDescriptor, IteratorMode};

use jmt::{
    KeyHash, OwnedValue, Version, Sha256Jmt, RootHash,
    storage::{
        NodeBatch, Node, NodeKey, LeafNode, TreeReader, TreeWriter, 
        TreeUpdateBatch, HasPreimage
    },
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
        let cf = self.db.cf_handle(PREIMAGES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", PREIMAGES_CF))?;
            
        self.db.put_cf(cf, key_hash.0.to_vec(), preimage)
            .context("Failed to store key preimage")?;
        
        Ok(())
    }
    
    /// Get the latest root hash
    pub fn get_latest_root(&self) -> Result<Option<RootHash>> {
        let cf = self.db.cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;
            
        if let Some(bytes) = self.db.get_cf(cf, LATEST_ROOT_KEY)? {
            let hash: [u8; 32] = bytes.try_into()
                .map_err(|_| anyhow!("Invalid root hash format"))?;
            Ok(Some(RootHash(hash)))
        } else {
            Ok(None)
        }
    }
    
    /// Store the latest root hash
    pub fn store_latest_root(&self, root_hash: RootHash) -> Result<()> {
        let cf = self.db.cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;
            
        self.db.put_cf(cf, LATEST_ROOT_KEY, root_hash.0.to_vec())
            .context("Failed to store latest root hash")?;
        
        Ok(())
    }
    
    /// Update storage with a tree update batch and set the new root hash
    pub fn update_with_batch(&self, root_hash: RootHash, batch: TreeUpdateBatch) -> Result<()> {
        self.write_node_batch(&batch.node_batch)?;
        self.store_latest_root(root_hash)?;
        Ok(())
    }
}

impl TreeReader for RocksDbStorage {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let cf = self.db.cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;
            
        let key_bytes = borsh::to_vec(node_key)
            .context("Failed to serialize node key")?;
        
        if let Some(bytes) = self.db.get_cf(cf, key_bytes)? {
            let node = Node::try_from_slice(&bytes)
                .context("Failed to deserialize node")?;
            Ok(Some(node))
        } else {
            Ok(None)
        }
    }
    
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let metadata_cf = self.db.cf_handle(METADATA_CF)
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
        let nodes_cf = self.db.cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;
            
        let mut rightmost: Option<(NodeKey, LeafNode)> = None;
        
        let iter = self.db.iterator_cf(nodes_cf, IteratorMode::Start);
        for result in iter {
            let (key_bytes, node_bytes) = result?;
            
            let node_key = NodeKey::try_from_slice(&key_bytes)
                .context("Failed to deserialize node key")?;
                
            let node = Node::try_from_slice(&node_bytes)
                .context("Failed to deserialize node")?;
                
            if let Node::Leaf(leaf_node) = node {
                if rightmost.is_none() || 
                   leaf_node.key_hash() > rightmost.as_ref().unwrap().1.key_hash() {
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
        key_hash: KeyHash
    ) -> Result<Option<OwnedValue>> {
        let cf = self.db.cf_handle(VALUES_CF)
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
        let cf = self.db.cf_handle(PREIMAGES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", PREIMAGES_CF))?;
            
        Ok(self.db.get_cf(cf, key_hash.0.to_vec())?)
    }
}

impl TreeWriter for RocksDbStorage {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let nodes_cf = self.db.cf_handle(NODES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", NODES_CF))?;
            
        let values_cf = self.db.cf_handle(VALUES_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", VALUES_CF))?;
            
        let metadata_cf = self.db.cf_handle(METADATA_CF)
            .ok_or_else(|| anyhow!("Column family '{}' not found", METADATA_CF))?;
            
        let mut batch = WriteBatch::default();
        let mut rightmost_leaf: Option<(NodeKey, LeafNode)> = None;
        
        // Write nodes
        for (key, node) in node_batch.nodes() {
            let key_bytes = borsh::to_vec(key)?;
            let node_bytes = borsh::to_vec(node)?;
            batch.put_cf(nodes_cf, key_bytes, node_bytes);
            
            // Track potential rightmost leaf
            if let Node::Leaf(leaf_node) = node {
                if rightmost_leaf.is_none() || 
                   leaf_node.key_hash() > rightmost_leaf.as_ref().unwrap().1.key_hash() {
                    rightmost_leaf = Some((key.clone(), leaf_node.clone()));
                }
            }
        }
        
        // Write values - using key_hash-first format for efficient lookups
        for ((version, key_hash), value_opt) in node_batch.values() {
            // Create composite key: key_hash (32 bytes) + version (8 bytes)
            let mut key = key_hash.0.to_vec();
            key.extend_from_slice(&version.to_be_bytes());
            
            if let Some(value) = value_opt {
                batch.put_cf(values_cf, key, value);
            } else {
                batch.delete_cf(values_cf, key);
            }
        }
        
        // Update rightmost leaf if we found one
        if let Some((ref node_key, ref leaf_node)) = rightmost_leaf {
            // Get the existing rightmost leaf
            if let Some(existing_bytes) = self.db.get_cf(metadata_cf, RIGHTMOST_LEAF_KEY)? {
                let mid = existing_bytes.len() / 2;
                let leaf_node_bytes = &existing_bytes[mid..];
                let existing_leaf = LeafNode::try_from_slice(leaf_node_bytes)?;
                
                // Only update if our new leaf is further right
                if leaf_node.key_hash() > existing_leaf.key_hash() {
                    let mut combined = borsh::to_vec(node_key)?;
                    combined.extend(borsh::to_vec(leaf_node)?);
                    batch.put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined);
                }
            } else {
                // No existing rightmost leaf, so store this one
                let mut combined = borsh::to_vec(node_key)?;
                combined.extend(borsh::to_vec(leaf_node)?);
                batch.put_cf(metadata_cf, RIGHTMOST_LEAF_KEY, combined);
            }
        }
        
        // Commit all changes atomically
        self.db.write(batch)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(proof.verify_existence(root_after_insert, key_hash, &utxo_data).is_ok());

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

        assert!(deletion_proof.verify_update(root_after_insert, root_after_delete, &updates).is_ok());

        println!("Deletion proof verified");
        
        // Check that we can retrieve the latest root
        let stored_root = storage.get_latest_root()?;

        println!("Stored root: {:?}", stored_root);

        assert_eq!(stored_root, Some(root_after_delete));

        println!("Root verified");
        
        Ok(())
    }
}