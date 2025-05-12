use chrono::Local;
use rusqlite::{params, Connection, Result as SqliteResult};
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct ProofEntry {
    pub block_height: u32,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub method_id: [u32; 8],
    pub receipt: Vec<u8>, // This includes the receipt and journal together
}

pub struct Db {
    conn: Connection,
}

// Helper function to convert method_id to bytes
fn method_id_to_bytes(method_id: &[u32; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for &id in method_id.iter() {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

// Helper function to convert bytes to method_id
fn bytes_to_method_id(bytes: &[u8]) -> [u32; 8] {
    let mut method_id = [0u32; 8];
    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let bytes_slice = &bytes[start..end];
        method_id[i] = u32::from_le_bytes(bytes_slice.try_into().unwrap());
    }
    method_id
}

impl Db {
    /// Create a new database connection and initialize tables
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        // Open the SQLite connection with explicit read-write flags
        // This ensures the database is opened with write permissions
        let conn = Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        // Create the proofs table with the exact structure of ProofEntry
        conn.execute(
            "CREATE TABLE IF NOT EXISTS proofs (
                block_height INTEGER NOT NULL,
                block_hash BLOB NOT NULL,
                prev_hash BLOB NOT NULL,
                method_id BLOB NOT NULL,
                receipt BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                PRIMARY KEY (block_height, block_hash)
            )",
            [],
        )?;

        Ok(Db { conn })
    }

    /// Store a new proof
    pub fn save_proof(
        &mut self,
        proof_entry: ProofEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let method_id_bytes = method_id_to_bytes(&proof_entry.method_id);

        // Get current date and time for created_at
        let now = Local::now();

        // Begin a transaction for atomicity
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO proofs 
             (block_height, block_hash, prev_hash, method_id, receipt, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                proof_entry.block_height,
                proof_entry.block_hash,
                proof_entry.prev_hash,
                method_id_bytes,
                proof_entry.receipt,
                now.to_rfc3339(),
            ],
        )?;

        // Commit the transaction
        tx.commit()?;

        Ok(())
    }

    /// Get a proof by height and hash
    pub fn get_proof(
        &self,
        block_height: u32,
        block_hash: &[u8; 32],
    ) -> SqliteResult<Option<ProofEntry>> {
        let result = self.conn.query_row(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt
             FROM proofs
             WHERE block_height = ?1 AND block_hash = ?2",
            params![block_height, block_hash],
            |row| {
                let block_height = row.get(0)?;

                let block_hash_data: Vec<u8> = row.get(1)?;
                let mut block_hash = [0u8; 32];
                block_hash.copy_from_slice(&block_hash_data);

                let prev_hash_data: Vec<u8> = row.get(2)?;
                let mut prev_hash = [0u8; 32];
                prev_hash.copy_from_slice(&prev_hash_data);

                let method_id_data: Vec<u8> = row.get(3)?;
                let method_id = bytes_to_method_id(&method_id_data);

                let receipt: Vec<u8> = row.get(4)?;

                Ok(ProofEntry {
                    block_height,
                    block_hash,
                    prev_hash,
                    method_id,
                    receipt,
                })
            },
        );

        match result {
            Ok(proof) => Ok(Some(proof)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Find a proof by block hash
    pub fn find_proof_by_hash(&self, block_hash: &[u8; 32]) -> SqliteResult<Option<ProofEntry>> {
        let result = self.conn.query_row(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt
             FROM proofs
             WHERE block_hash = ?1",
            params![block_hash],
            |row| {
                let block_height = row.get(0)?;

                let block_hash_data: Vec<u8> = row.get(1)?;
                let mut block_hash = [0u8; 32];
                block_hash.copy_from_slice(&block_hash_data);

                let prev_hash_data: Vec<u8> = row.get(2)?;
                let mut prev_hash = [0u8; 32];
                prev_hash.copy_from_slice(&prev_hash_data);

                let method_id_data: Vec<u8> = row.get(3)?;
                let method_id = bytes_to_method_id(&method_id_data);

                let receipt: Vec<u8> = row.get(4)?;

                Ok(ProofEntry {
                    block_height,
                    block_hash,
                    prev_hash,
                    method_id,
                    receipt,
                })
            },
        );

        match result {
            Ok(proof) => Ok(Some(proof)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get all the blocks that have the highest height
    pub fn get_chain_tips(&self) -> SqliteResult<Vec<ProofEntry>> {
        // Handle case where table is empty
        let max_height: Option<u32> = self
            .conn
            .query_row("SELECT MAX(block_height) FROM proofs", [], |row| row.get(0))
            .unwrap_or(None);

        let max_height = match max_height {
            Some(h) => h,
            None => return Ok(Vec::new()), // Empty table
        };

        // Then get all blocks at that height
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt
             FROM proofs
             WHERE block_height = ?1",
        )?;

        let proof_iter = stmt.query_map(params![max_height], |row| {
            let block_height = row.get(0)?;

            let block_hash_data: Vec<u8> = row.get(1)?;
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&block_hash_data);

            let prev_hash_data: Vec<u8> = row.get(2)?;
            let mut prev_hash = [0u8; 32];
            prev_hash.copy_from_slice(&prev_hash_data);

            let method_id_data: Vec<u8> = row.get(3)?;
            let method_id = bytes_to_method_id(&method_id_data);

            let receipt: Vec<u8> = row.get(4)?;

            Ok(ProofEntry {
                block_height,
                block_hash,
                prev_hash,
                method_id,
                receipt,
            })
        })?;

        let mut tips = Vec::new();
        for proof_result in proof_iter {
            tips.push(proof_result?);
        }

        Ok(tips)
    }

    /// Get blocks at a specific height
    pub fn get_blocks_at_height(&self, height: u32) -> SqliteResult<Vec<ProofEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt
             FROM proofs
             WHERE block_height = ?1",
        )?;

        let proof_iter = stmt.query_map(params![height], |row| {
            let block_height = row.get(0)?;

            let block_hash_data: Vec<u8> = row.get(1)?;
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&block_hash_data);

            let prev_hash_data: Vec<u8> = row.get(2)?;
            let mut prev_hash = [0u8; 32];
            prev_hash.copy_from_slice(&prev_hash_data);

            let method_id_data: Vec<u8> = row.get(3)?;
            let method_id = bytes_to_method_id(&method_id_data);

            let receipt: Vec<u8> = row.get(4)?;

            Ok(ProofEntry {
                block_height,
                block_hash,
                prev_hash,
                method_id,
                receipt,
            })
        })?;

        let mut proofs = Vec::new();
        for proof_result in proof_iter {
            proofs.push(proof_result?);
        }

        Ok(proofs)
    }

    /// Delete a proof by height and hash
    pub fn delete_proof(&self, block_height: u32, block_hash: &[u8; 32]) -> SqliteResult<bool> {
        let rows_affected = self.conn.execute(
            "DELETE FROM proofs WHERE block_height = ?1 AND block_hash = ?2",
            params![block_height, block_hash],
        )?;

        Ok(rows_affected > 0)
    }

    /// Count total proofs in the database
    pub fn count_proofs(&self) -> SqliteResult<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM proofs", [], |row| row.get(0))
    }

    /// Get proofs within a height range
    pub fn get_proofs_in_range(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> SqliteResult<Vec<ProofEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt
             FROM proofs
             WHERE block_height >= ?1 AND block_height <= ?2
             ORDER BY block_height",
        )?;

        let proof_iter = stmt.query_map(params![start_height, end_height], |row| {
            let block_height = row.get(0)?;

            let block_hash_data: Vec<u8> = row.get(1)?;
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&block_hash_data);

            let prev_hash_data: Vec<u8> = row.get(2)?;
            let mut prev_hash = [0u8; 32];
            prev_hash.copy_from_slice(&prev_hash_data);

            let method_id_data: Vec<u8> = row.get(3)?;
            let method_id = bytes_to_method_id(&method_id_data);

            let receipt: Vec<u8> = row.get(4)?;

            Ok(ProofEntry {
                block_height,
                block_hash,
                prev_hash,
                method_id,
                receipt,
            })
        })?;

        let mut proofs = Vec::new();
        for proof_result in proof_iter {
            proofs.push(proof_result?);
        }

        Ok(proofs)
    }

    /// Get the maximum height in the database
    pub fn get_max_height(&self) -> SqliteResult<Option<u32>> {
        self.conn
            .query_row("SELECT MAX(block_height) FROM proofs", [], |row| row.get(0))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Helper function to create a test database
    fn create_test_db() -> (Db, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = Db::new(db_path.to_str().unwrap()).unwrap();
        (db, temp_dir)
    }

    // Helper function to create a sample ProofEntry
    fn create_sample_proof(height: u32, hash_seed: u8) -> ProofEntry {
        let mut block_hash = [0u8; 32];
        block_hash[0] = hash_seed;

        let mut prev_hash = [0u8; 32];
        prev_hash[0] = hash_seed.saturating_sub(1);

        ProofEntry {
            block_height: height,
            block_hash,
            prev_hash,
            method_id: [1, 2, 3, 4, 5, 6, 7, 8],
            receipt: vec![1, 2, 3, 4, 5],
        }
    }

    #[test]
    fn test_new_database_creation() {
        let (db, _temp_dir) = create_test_db();

        // Test that we can count proofs in a new database
        let count = db.count_proofs().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_save_and_retrieve_proof() {
        let (mut db, _temp_dir) = create_test_db();

        let proof = create_sample_proof(100, 1);

        // Save the proof
        db.save_proof(proof.clone()).unwrap();

        // Retrieve by height and hash
        let retrieved = db.get_proof(100, &proof.block_hash).unwrap();
        assert!(retrieved.is_some());

        let retrieved_proof = retrieved.unwrap();
        assert_eq!(retrieved_proof.block_height, proof.block_height);
        assert_eq!(retrieved_proof.block_hash, proof.block_hash);
        assert_eq!(retrieved_proof.prev_hash, proof.prev_hash);
        assert_eq!(retrieved_proof.method_id, proof.method_id);
        assert_eq!(retrieved_proof.receipt, proof.receipt);
    }

    #[test]
    fn test_find_proof_by_hash() {
        let (mut db, _temp_dir) = create_test_db();

        let proof = create_sample_proof(200, 2);
        db.save_proof(proof.clone()).unwrap();

        // Find by hash only
        let found = db.find_proof_by_hash(&proof.block_hash).unwrap();
        assert!(found.is_some());

        let found_proof = found.unwrap();
        assert_eq!(found_proof.block_height, proof.block_height);
        assert_eq!(found_proof.block_hash, proof.block_hash);
    }

    #[test]
    fn test_get_nonexistent_proof() {
        let (db, _temp_dir) = create_test_db();

        let fake_hash = [99u8; 32];
        let result = db.get_proof(999, &fake_hash).unwrap();
        assert!(result.is_none());

        let result2 = db.find_proof_by_hash(&fake_hash).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn test_get_chain_tips() {
        let (mut db, _temp_dir) = create_test_db();

        // Insert proofs at different heights
        db.save_proof(create_sample_proof(100, 1)).unwrap();
        db.save_proof(create_sample_proof(200, 2)).unwrap();
        db.save_proof(create_sample_proof(300, 3)).unwrap();
        db.save_proof(create_sample_proof(300, 4)).unwrap(); // Another at same height

        let tips = db.get_chain_tips().unwrap();
        assert_eq!(tips.len(), 2); // Two blocks at height 300

        for tip in &tips {
            assert_eq!(tip.block_height, 300);
        }
    }

    #[test]
    fn test_get_chain_tips_empty_db() {
        let (db, _temp_dir) = create_test_db();

        let tips = db.get_chain_tips().unwrap();
        assert_eq!(tips.len(), 0);
    }

    #[test]
    fn test_get_blocks_at_height() {
        let (mut db, _temp_dir) = create_test_db();

        // Insert multiple blocks at same height
        db.save_proof(create_sample_proof(150, 1)).unwrap();
        db.save_proof(create_sample_proof(150, 2)).unwrap();
        db.save_proof(create_sample_proof(150, 3)).unwrap();
        db.save_proof(create_sample_proof(200, 4)).unwrap();

        let blocks_at_150 = db.get_blocks_at_height(150).unwrap();
        assert_eq!(blocks_at_150.len(), 3);

        let blocks_at_200 = db.get_blocks_at_height(200).unwrap();
        assert_eq!(blocks_at_200.len(), 1);

        let blocks_at_999 = db.get_blocks_at_height(999).unwrap();
        assert_eq!(blocks_at_999.len(), 0);
    }

    #[test]
    fn test_delete_proof() {
        let (mut db, _temp_dir) = create_test_db();

        let proof = create_sample_proof(100, 1);
        db.save_proof(proof.clone()).unwrap();

        // Verify it exists
        let exists = db.get_proof(100, &proof.block_hash).unwrap();
        assert!(exists.is_some());

        // Delete it
        let deleted = db.delete_proof(100, &proof.block_hash).unwrap();
        assert!(deleted);

        // Verify it's gone
        let gone = db.get_proof(100, &proof.block_hash).unwrap();
        assert!(gone.is_none());

        // Try to delete non-existent proof
        let fake_hash = [99u8; 32];
        let not_deleted = db.delete_proof(999, &fake_hash).unwrap();
        assert!(!not_deleted);
    }

    #[test]
    fn test_count_proofs() {
        let (mut db, _temp_dir) = create_test_db();

        assert_eq!(db.count_proofs().unwrap(), 0);

        db.save_proof(create_sample_proof(100, 1)).unwrap();
        assert_eq!(db.count_proofs().unwrap(), 1);

        db.save_proof(create_sample_proof(200, 2)).unwrap();
        assert_eq!(db.count_proofs().unwrap(), 2);

        // Replace existing proof (same height and hash)
        let proof = create_sample_proof(100, 1);
        db.save_proof(proof).unwrap();
        assert_eq!(db.count_proofs().unwrap(), 2); // Still 2
    }

    #[test]
    fn test_get_proofs_in_range() {
        let (mut db, _temp_dir) = create_test_db();

        // Insert proofs at various heights
        db.save_proof(create_sample_proof(50, 1)).unwrap();
        db.save_proof(create_sample_proof(100, 2)).unwrap();
        db.save_proof(create_sample_proof(150, 3)).unwrap();
        db.save_proof(create_sample_proof(200, 4)).unwrap();
        db.save_proof(create_sample_proof(250, 5)).unwrap();

        // Test inclusive range
        let range_proofs = db.get_proofs_in_range(100, 200).unwrap();
        assert_eq!(range_proofs.len(), 3); // Heights 100, 150, 200

        // Test range with no proofs
        let empty_range = db.get_proofs_in_range(300, 400).unwrap();
        assert_eq!(empty_range.len(), 0);

        // Test single height range
        let single_height = db.get_proofs_in_range(150, 150).unwrap();
        assert_eq!(single_height.len(), 1);
        assert_eq!(single_height[0].block_height, 150);

        // Verify ordering
        let all_proofs = db.get_proofs_in_range(0, u32::MAX).unwrap();
        for i in 1..all_proofs.len() {
            assert!(all_proofs[i].block_height >= all_proofs[i - 1].block_height);
        }
    }

    #[test]
    fn test_get_max_height() {
        let (mut db, _temp_dir) = create_test_db();

        // Empty database
        assert_eq!(db.get_max_height().unwrap(), None);

        // Add some proofs
        db.save_proof(create_sample_proof(100, 1)).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(100));

        db.save_proof(create_sample_proof(500, 2)).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(500));

        db.save_proof(create_sample_proof(300, 3)).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(500)); // Still 500

        // Delete the highest proof
        let proof_at_500 = create_sample_proof(500, 2);
        db.delete_proof(500, &proof_at_500.block_hash).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(300));
    }

    #[test]
    fn test_method_id_conversion() {
        let original_method_id = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let bytes = method_id_to_bytes(&original_method_id);
        let converted_back = bytes_to_method_id(&bytes);

        assert_eq!(original_method_id, converted_back);
        assert_eq!(bytes.len(), 32); // 8 * 4 bytes
    }

    #[test]
    fn test_update_existing_proof() {
        let (mut db, _temp_dir) = create_test_db();

        let mut proof = create_sample_proof(100, 1);
        db.save_proof(proof.clone()).unwrap();

        // Update the receipt
        proof.receipt = vec![9, 8, 7, 6, 5];
        db.save_proof(proof.clone()).unwrap();

        // Verify the update
        let updated = db.get_proof(100, &proof.block_hash).unwrap().unwrap();
        assert_eq!(updated.receipt, vec![9, 8, 7, 6, 5]);

        // Count should still be 1
        assert_eq!(db.count_proofs().unwrap(), 1);
    }

    #[test]
    fn test_large_number_of_proofs() {
        let (mut db, _temp_dir) = create_test_db();

        // Insert many proofs
        for i in 0..1000 {
            let proof = create_sample_proof(i, (i % 256) as u8);
            db.save_proof(proof).unwrap();
        }

        assert_eq!(db.count_proofs().unwrap(), 1000);
        assert_eq!(db.get_max_height().unwrap(), Some(999));

        // Get a range
        let range = db.get_proofs_in_range(400, 600).unwrap();
        assert_eq!(range.len(), 201); // Heights 400-600 inclusive
    }

    #[test]
    fn test_primary_key_constraint() {
        let (mut db, _temp_dir) = create_test_db();

        // Insert a proof
        let proof1 = create_sample_proof(100, 1);
        db.save_proof(proof1.clone()).unwrap();

        // Try to insert another proof with same height but different hash
        let proof2 = create_sample_proof(100, 2);
        db.save_proof(proof2.clone()).unwrap();

        // Both should exist
        assert!(db.get_proof(100, &proof1.block_hash).unwrap().is_some());
        assert!(db.get_proof(100, &proof2.block_hash).unwrap().is_some());
        assert_eq!(db.count_proofs().unwrap(), 2);
    }

    #[test]
    fn test_edge_cases() {
        let (mut db, _temp_dir) = create_test_db();

        // Test with empty receipt
        let mut proof = create_sample_proof(100, 1);
        proof.receipt = vec![];
        db.save_proof(proof.clone()).unwrap();

        let retrieved = db.get_proof(100, &proof.block_hash).unwrap().unwrap();
        assert_eq!(retrieved.receipt.len(), 0);

        // Test with max u32 height
        let max_height_proof = create_sample_proof(u32::MAX, 255);
        db.save_proof(max_height_proof.clone()).unwrap();

        let retrieved_max = db
            .get_proof(u32::MAX, &max_height_proof.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_max.block_height, u32::MAX);

        // Test with all-zero hashes
        let mut zero_proof = create_sample_proof(200, 0);
        zero_proof.block_hash = [0u8; 32];
        zero_proof.prev_hash = [0u8; 32];
        db.save_proof(zero_proof.clone()).unwrap();

        let retrieved_zero = db.find_proof_by_hash(&[0u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved_zero.block_height, 200);
    }
}
