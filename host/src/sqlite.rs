use chrono::Local;
use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult}; // OptionalExtension might not be needed for MAX() queries now
use std::convert::TryFrom; // For try_into on slices to arrays
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq)] // Added PartialEq for easier assertions in tests
pub struct ProofEntry {
    pub block_height: u32,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub method_id: [u32; 8],
    pub receipt: Vec<u8>, // This includes the receipt and journal together
    pub last_version: u64,
}

// --- Helper Error Type for method_id conversion ---
#[derive(Debug)]
pub struct MethodIdConversionError {
    message: String,
}

impl MethodIdConversionError {
    fn new(msg: &str) -> Self {
        MethodIdConversionError {
            message: msg.to_string(),
        }
    }
}

impl fmt::Display for MethodIdConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for MethodIdConversionError {}

// --- Helper functions for method_id conversion ---
fn method_id_to_bytes(method_id: &[u32; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32); // 8 * 4 bytes
    for &id in method_id.iter() {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

fn bytes_to_method_id(bytes: &[u8]) -> Result<[u32; 8], MethodIdConversionError> {
    if bytes.len() != 32 {
        return Err(MethodIdConversionError::new(&format!(
            "Invalid byte slice length for method_id, expected 32, got {}",
            bytes.len()
        )));
    }
    let mut method_id = [0u32; 8];
    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let byte_slice_for_u32 = &bytes[start..end];

        match <[u8; 4]>::try_from(byte_slice_for_u32) {
            Ok(arr) => method_id[i] = u32::from_le_bytes(arr),
            Err(_) => {
                return Err(MethodIdConversionError::new(
                    "Internal error: Failed to convert slice to [u8; 4] for method_id element",
                ));
            }
        }
    }
    Ok(method_id)
}

pub struct ProofDb {
    conn: Connection,
}

impl ProofDb {
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS proofs (
                block_height INTEGER NOT NULL,
                block_hash BLOB NOT NULL,
                prev_hash BLOB NOT NULL,
                method_id BLOB NOT NULL,
                receipt BLOB NOT NULL,
                last_version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (block_height, block_hash)
            )",
            [],
        )?;

        Ok(ProofDb { conn })
    }

    fn map_row_to_proof_entry(row: &rusqlite::Row<'_>) -> SqliteResult<ProofEntry> {
        let block_height: u32 = row.get(0)?;

        let block_hash_data: Vec<u8> = row.get(1)?;
        let block_hash: [u8; 32] =
            block_hash_data
                .as_slice()
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| {
                    rusqlite::Error::FromSqlConversionFailure(
                        block_hash_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

        let prev_hash_data: Vec<u8> = row.get(2)?;
        let prev_hash: [u8; 32] =
            prev_hash_data
                .as_slice()
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| {
                    rusqlite::Error::FromSqlConversionFailure(
                        prev_hash_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

        let method_id_data: Vec<u8> = row.get(3)?;
        let method_id = bytes_to_method_id(&method_id_data).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                method_id_data.len(),
                rusqlite::types::Type::Blob,
                Box::new(e) as Box<dyn Error + Send + Sync + 'static>,
            )
        })?;

        let receipt: Vec<u8> = row.get(4)?;
        let last_version: u64 = row.get(5)?;

        Ok(ProofEntry {
            block_height,
            block_hash,
            prev_hash,
            method_id,
            receipt,
            last_version,
        })
    }

    pub fn save_proof(&mut self, proof_entry: ProofEntry) -> SqliteResult<()> {
        let method_id_bytes = method_id_to_bytes(&proof_entry.method_id);
        let now_rfc3339 = Local::now().to_rfc3339();

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO proofs 
             (block_height, block_hash, prev_hash, method_id, receipt, last_version, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                proof_entry.block_height,
                proof_entry.block_hash.as_slice(),
                proof_entry.prev_hash.as_slice(),
                method_id_bytes,
                proof_entry.receipt,
                proof_entry.last_version,
                now_rfc3339,
            ],
        )?;
        tx.commit()
    }

    pub fn get_proof(
        &self,
        block_height: u32,
        block_hash: &[u8; 32],
    ) -> SqliteResult<Option<ProofEntry>> {
        self.conn
            .query_row(
                "SELECT block_height, block_hash, prev_hash, method_id, receipt, last_version
             FROM proofs
             WHERE block_height = ?1 AND block_hash = ?2",
                params![block_height, block_hash.as_slice()],
                Self::map_row_to_proof_entry,
            )
            .optional() // .optional() is correct here, for when the specific proof doesn't exist.
    }

    pub fn find_proof_by_hash(&self, block_hash: &[u8; 32]) -> SqliteResult<Option<ProofEntry>> {
        self.conn
            .query_row(
                "SELECT block_height, block_hash, prev_hash, method_id, receipt, last_version
             FROM proofs
             WHERE block_hash = ?1
             LIMIT 1",
                params![block_hash.as_slice()],
                Self::map_row_to_proof_entry,
            )
            .optional() // .optional() is correct here.
    }

    /// Get all proof entries that represent the highest block height(s) in the database (chain tips).
    pub fn get_chain_tips(&self) -> SqliteResult<Vec<ProofEntry>> {
        // MAX() on an empty table returns a single row with a NULL value.
        // row.get(0) will infer its target type as Option<u32> from max_height_val's type.
        let max_height_val: Option<u32> =
            self.conn
                .query_row("SELECT MAX(block_height) FROM proofs", [], |row| row.get(0))?;

        match max_height_val {
            Some(max_height) => {
                // If MAX returned a non-NULL value
                let mut stmt = self.conn.prepare(
                    "SELECT block_height, block_hash, prev_hash, method_id, receipt, last_version
                     FROM proofs
                     WHERE block_height = ?1",
                )?;
                let proof_iter =
                    stmt.query_map(params![max_height], Self::map_row_to_proof_entry)?;
                proof_iter.collect()
            }
            None => Ok(Vec::new()), // This case means MAX(block_height) was NULL (i.e., table is empty)
        }
    }

    pub fn get_blocks_at_height(&self, height: u32) -> SqliteResult<Vec<ProofEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt, last_version
             FROM proofs
             WHERE block_height = ?1",
        )?;
        let proof_iter = stmt.query_map(params![height], Self::map_row_to_proof_entry)?;
        proof_iter.collect()
    }

    pub fn delete_proof(&self, block_height: u32, block_hash: &[u8; 32]) -> SqliteResult<bool> {
        let rows_affected = self.conn.execute(
            "DELETE FROM proofs WHERE block_height = ?1 AND block_hash = ?2",
            params![block_height, block_hash.as_slice()],
        )?;
        Ok(rows_affected > 0)
    }

    pub fn count_proofs(&self) -> SqliteResult<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM proofs", [], |row| row.get(0)) // COUNT(*) on empty table returns 0, not NULL.
    }

    pub fn get_proofs_in_range(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> SqliteResult<Vec<ProofEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt, last_version
             FROM proofs
             WHERE block_height >= ?1 AND block_height <= ?2
             ORDER BY block_height ASC",
        )?;
        let proof_iter = stmt.query_map(
            params![start_height, end_height],
            Self::map_row_to_proof_entry,
        )?;
        proof_iter.collect()
    }

    /// Get the maximum block_height present in the database.
    pub fn get_max_height(&self) -> SqliteResult<Option<u32>> {
        // row.get(0) infers target type Option<u32> from function return type.
        // This correctly handles MAX() returning NULL on an empty table.
        self.conn
            .query_row("SELECT MAX(block_height) FROM proofs", [], |row| row.get(0))
    }

    /// Get the latest (maximum) last_version from any proof in the database.
    pub fn get_latest_version(&self) -> SqliteResult<Option<u64>> {
        // row.get(0) infers target type Option<u64> from function return type.
        self.conn
            .query_row("SELECT MAX(last_version) FROM proofs", [], |row| row.get(0))
    }

    pub fn get_proofs_by_version(&self, version: u64) -> SqliteResult<Vec<ProofEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt, last_version
             FROM proofs
             WHERE last_version = ?1",
        )?;
        let proof_iter = stmt.query_map(params![version], Self::map_row_to_proof_entry)?;
        proof_iter.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Helper function to create a test database
    fn create_test_db() -> (ProofDb, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("test.db");
        let db = ProofDb::new(db_path.to_str().expect("Path to_str failed"))
            .expect("Failed to create ProofDb");
        (db, temp_dir)
    }

    // Helper function to create a sample ProofEntry
    fn create_sample_proof(height: u32, hash_seed: u8, version: u64) -> ProofEntry {
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
            last_version: version,
        }
    }

    #[test]
    fn test_new_database_creation() {
        let (db, _temp_dir) = create_test_db();
        let count = db.count_proofs().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_save_and_retrieve_proof() {
        let (mut db, _temp_dir) = create_test_db();
        let proof = create_sample_proof(100, 1, 42);

        db.save_proof(proof.clone()).unwrap();

        let retrieved = db.get_proof(100, &proof.block_hash).unwrap();
        assert!(retrieved.is_some(), "Proof should be found");
        assert_eq!(retrieved.unwrap(), proof);
    }

    #[test]
    fn test_retrieve_proof_non_existent() {
        let (db, _temp_dir) = create_test_db();
        let proof = db.get_proof(100, &[0; 32]).unwrap();
        assert!(proof.is_none());
    }

    #[test]
    fn test_find_proof_by_hash() {
        let (mut db, _temp_dir) = create_test_db();
        let proof = create_sample_proof(200, 2, 100);
        db.save_proof(proof.clone()).unwrap();

        let found = db.find_proof_by_hash(&proof.block_hash).unwrap();
        assert!(found.is_some(), "Proof should be found by hash");
        assert_eq!(found.unwrap(), proof);
    }

    #[test]
    fn test_find_proof_by_hash_multiple_heights() {
        let (mut db, _temp_dir) = create_test_db();
        let mut common_hash = [0u8; 32];
        common_hash[0] = 55;

        let proof1 = ProofEntry {
            block_height: 10,
            block_hash: common_hash,
            ..create_sample_proof(10, 55, 1)
        };
        let proof2 = ProofEntry {
            block_height: 20,
            block_hash: common_hash,
            ..create_sample_proof(20, 55, 2)
        };

        db.save_proof(proof1.clone()).unwrap();
        db.save_proof(proof2.clone()).unwrap();

        let found = db.find_proof_by_hash(&common_hash).unwrap();
        assert!(found.is_some());
        let found_proof = found.unwrap();
        // With LIMIT 1 and no specific ORDER BY, it could be either.
        // The important part is that *one* is found.
        assert!(found_proof == proof1 || found_proof == proof2);
    }

    #[test]
    fn test_get_nonexistent_proof() {
        let (db, _temp_dir) = create_test_db();
        let fake_hash = [99u8; 32];
        let result_get = db.get_proof(999, &fake_hash).unwrap();
        assert!(result_get.is_none());

        let result_find = db.find_proof_by_hash(&fake_hash).unwrap();
        assert!(result_find.is_none());
    }

    // This test should now pass with the corrected get_chain_tips
    #[test]
    fn test_get_chain_tips_empty_db() {
        let (db, _temp_dir) = create_test_db();
        let tips = db.get_chain_tips().unwrap(); // This was panicking
        assert!(tips.is_empty(), "Tips should be empty for an empty DB");
    }

    #[test]
    fn test_get_chain_tips() {
        let (mut db, _temp_dir) = create_test_db();

        let proof100 = create_sample_proof(100, 1, 10);
        let proof200 = create_sample_proof(200, 2, 20);
        let proof300a = create_sample_proof(300, 3, 30);
        let proof300b = create_sample_proof(300, 4, 31);

        db.save_proof(proof100.clone()).unwrap();
        db.save_proof(proof200.clone()).unwrap();
        db.save_proof(proof300a.clone()).unwrap();
        db.save_proof(proof300b.clone()).unwrap();

        let tips = db.get_chain_tips().unwrap();
        assert_eq!(tips.len(), 2, "Should be two tips at height 300");

        assert!(tips.contains(&proof300a));
        assert!(tips.contains(&proof300b));
        for tip in &tips {
            assert_eq!(tip.block_height, 300);
        }
    }

    #[test]
    fn test_get_blocks_at_height() {
        let (mut db, _temp_dir) = create_test_db();
        let proof150a = create_sample_proof(150, 1, 10);
        let proof150b = create_sample_proof(150, 2, 11);
        let proof150c = create_sample_proof(150, 3, 12);
        let proof200 = create_sample_proof(200, 4, 20);

        db.save_proof(proof150a.clone()).unwrap();
        db.save_proof(proof150b.clone()).unwrap();
        db.save_proof(proof150c.clone()).unwrap();
        db.save_proof(proof200.clone()).unwrap();

        let blocks_at_150 = db.get_blocks_at_height(150).unwrap();
        assert_eq!(blocks_at_150.len(), 3);
        assert!(blocks_at_150.contains(&proof150a));
        assert!(blocks_at_150.contains(&proof150b));
        assert!(blocks_at_150.contains(&proof150c));

        let blocks_at_200 = db.get_blocks_at_height(200).unwrap();
        assert_eq!(blocks_at_200.len(), 1);
        assert_eq!(blocks_at_200[0], proof200);

        let blocks_at_999 = db.get_blocks_at_height(999).unwrap();
        assert!(blocks_at_999.is_empty());
    }

    #[test]
    fn test_delete_proof() {
        let (mut db, _temp_dir) = create_test_db();
        let proof = create_sample_proof(100, 1, 42);
        db.save_proof(proof.clone()).unwrap();

        assert!(db.get_proof(100, &proof.block_hash).unwrap().is_some());

        let deleted = db.delete_proof(100, &proof.block_hash).unwrap();
        assert!(deleted);

        assert!(db.get_proof(100, &proof.block_hash).unwrap().is_none());

        let fake_hash = [99u8; 32];
        let not_deleted = db.delete_proof(999, &fake_hash).unwrap();
        assert!(!not_deleted);
    }

    #[test]
    fn test_count_proofs() {
        let (mut db, _temp_dir) = create_test_db();
        assert_eq!(db.count_proofs().unwrap(), 0);

        db.save_proof(create_sample_proof(100, 1, 10)).unwrap();
        assert_eq!(db.count_proofs().unwrap(), 1);

        db.save_proof(create_sample_proof(200, 2, 20)).unwrap();
        assert_eq!(db.count_proofs().unwrap(), 2);

        let proof_updated = create_sample_proof(100, 1, 15);
        db.save_proof(proof_updated).unwrap();
        assert_eq!(
            db.count_proofs().unwrap(),
            2,
            "Count should remain 2 after replace"
        );
    }

    #[test]
    fn test_get_proofs_in_range() {
        let (mut db, _temp_dir) = create_test_db();
        let p50 = create_sample_proof(50, 1, 5);
        let p100 = create_sample_proof(100, 2, 10);
        let p150 = create_sample_proof(150, 3, 15);
        let p200 = create_sample_proof(200, 4, 20);
        let p250 = create_sample_proof(250, 5, 25);

        db.save_proof(p50.clone()).unwrap();
        db.save_proof(p100.clone()).unwrap();
        db.save_proof(p150.clone()).unwrap();
        db.save_proof(p200.clone()).unwrap();
        db.save_proof(p250.clone()).unwrap();

        let range_proofs = db.get_proofs_in_range(100, 200).unwrap();
        assert_eq!(range_proofs.len(), 3);
        assert!(range_proofs.contains(&p100));
        assert!(range_proofs.contains(&p150));
        assert!(range_proofs.contains(&p200));

        assert_eq!(range_proofs[0].block_height, 100);
        assert_eq!(range_proofs[1].block_height, 150);
        assert_eq!(range_proofs[2].block_height, 200);

        let empty_range = db.get_proofs_in_range(300, 400).unwrap();
        assert!(empty_range.is_empty());

        let single_height = db.get_proofs_in_range(150, 150).unwrap();
        assert_eq!(single_height.len(), 1);
        assert_eq!(single_height[0], p150);
    }

    // This test should also pass with the corrected get_max_height
    #[test]
    fn test_get_max_height() {
        let (mut db, _temp_dir) = create_test_db();
        assert_eq!(
            db.get_max_height().unwrap(),
            None,
            "Max height should be None for empty DB"
        );

        db.save_proof(create_sample_proof(100, 1, 10)).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(100));

        db.save_proof(create_sample_proof(500, 2, 50)).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(500));

        db.save_proof(create_sample_proof(300, 3, 30)).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(500));

        let proof_at_500 = create_sample_proof(500, 2, 50);
        db.delete_proof(500, &proof_at_500.block_hash).unwrap();
        assert_eq!(db.get_max_height().unwrap(), Some(300));
    }

    #[test]
    fn test_method_id_conversion() {
        let original_method_id = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let bytes = method_id_to_bytes(&original_method_id);
        assert_eq!(bytes.len(), 32);
        let converted_back = bytes_to_method_id(&bytes).unwrap();
        assert_eq!(original_method_id, converted_back);
    }

    #[test]
    fn test_bytes_to_method_id_invalid_length() {
        let bytes_short = vec![0u8; 31];
        let result_short = bytes_to_method_id(&bytes_short);
        assert!(result_short.is_err());
        assert_eq!(
            result_short.unwrap_err().to_string(),
            "Invalid byte slice length for method_id, expected 32, got 31"
        );

        let bytes_long = vec![0u8; 33];
        let result_long = bytes_to_method_id(&bytes_long);
        assert!(result_long.is_err());
        assert_eq!(
            result_long.unwrap_err().to_string(),
            "Invalid byte slice length for method_id, expected 32, got 33"
        );
    }

    #[test]
    fn test_update_existing_proof() {
        let (mut db, _temp_dir) = create_test_db();
        let mut proof = create_sample_proof(100, 1, 10);
        db.save_proof(proof.clone()).unwrap();

        proof.receipt = vec![9, 8, 7];
        proof.last_version = 20;
        db.save_proof(proof.clone()).unwrap();

        let updated = db.get_proof(100, &proof.block_hash).unwrap().unwrap();
        assert_eq!(updated.receipt, vec![9, 8, 7]);
        assert_eq!(updated.last_version, 20);
        assert_eq!(updated, proof);

        assert_eq!(
            db.count_proofs().unwrap(),
            1,
            "Count should be 1 after update"
        );
    }

    #[test]
    fn test_large_number_of_proofs() {
        let (mut db, _temp_dir) = create_test_db();
        let num_proofs = 1000;
        for i in 0..num_proofs {
            let proof = create_sample_proof(i as u32, (i % 256) as u8, i as u64);
            db.save_proof(proof).unwrap();
        }

        assert_eq!(db.count_proofs().unwrap(), num_proofs as u64);
        assert_eq!(db.get_max_height().unwrap(), Some((num_proofs - 1) as u32));

        let range = db.get_proofs_in_range(400, 600).unwrap();
        assert_eq!(range.len(), 201);
    }

    #[test]
    fn test_primary_key_constraint_allows_forks() {
        let (mut db, _temp_dir) = create_test_db();
        let proof1 = create_sample_proof(100, 1, 10);
        db.save_proof(proof1.clone()).unwrap();

        let proof2 = create_sample_proof(100, 2, 11);
        db.save_proof(proof2.clone()).unwrap();

        assert!(db.get_proof(100, &proof1.block_hash).unwrap().is_some());
        assert!(db.get_proof(100, &proof2.block_hash).unwrap().is_some());
        assert_eq!(
            db.count_proofs().unwrap(),
            2,
            "Should have two distinct proofs at same height"
        );
    }

    #[test]
    fn test_edge_cases() {
        let (mut db, _temp_dir) = create_test_db();

        let mut proof_empty_receipt = create_sample_proof(10, 1, 10);
        proof_empty_receipt.receipt = vec![];
        db.save_proof(proof_empty_receipt.clone()).unwrap();
        let retrieved_empty_receipt = db
            .get_proof(10, &proof_empty_receipt.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_empty_receipt.receipt, Vec::<u8>::new());
        assert_eq!(retrieved_empty_receipt, proof_empty_receipt);

        let i64_max_as_u64 = i64::MAX as u64;

        let proof_max_vals = create_sample_proof(u32::MAX, 255, i64_max_as_u64);
        db.save_proof(proof_max_vals.clone()).unwrap();
        let retrieved_max_vals = db
            .get_proof(u32::MAX, &proof_max_vals.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_max_vals, proof_max_vals);

        let mut zero_proof = create_sample_proof(200, 0, 0);
        zero_proof.block_hash = [0u8; 32];
        zero_proof.prev_hash = [0u8; 32];
        db.save_proof(zero_proof.clone()).unwrap();
        let retrieved_zero = db.get_proof(200, &[0u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved_zero, zero_proof);
    }

    // This test should also pass with the corrected get_latest_version
    #[test]
    fn test_get_latest_version() {
        let (mut db, _temp_dir) = create_test_db();
        assert_eq!(
            db.get_latest_version().unwrap(),
            None,
            "Latest version should be None for empty DB"
        );

        db.save_proof(create_sample_proof(100, 1, 10)).unwrap();
        assert_eq!(db.get_latest_version().unwrap(), Some(10));

        db.save_proof(create_sample_proof(200, 2, 50)).unwrap();
        assert_eq!(db.get_latest_version().unwrap(), Some(50));

        db.save_proof(create_sample_proof(300, 3, 30)).unwrap();
        assert_eq!(db.get_latest_version().unwrap(), Some(50));

        db.save_proof(create_sample_proof(400, 4, 100)).unwrap();
        assert_eq!(db.get_latest_version().unwrap(), Some(100));
    }

    #[test]
    fn test_get_proofs_by_version() {
        let (mut db, _temp_dir) = create_test_db();
        let p_v10_h100 = create_sample_proof(100, 1, 10);
        let p_v20_h200 = create_sample_proof(200, 2, 20);
        let p_v10_h300 = create_sample_proof(300, 3, 10);
        let p_v30_h400 = create_sample_proof(400, 4, 30);

        db.save_proof(p_v10_h100.clone()).unwrap();
        db.save_proof(p_v20_h200.clone()).unwrap();
        db.save_proof(p_v10_h300.clone()).unwrap();
        db.save_proof(p_v30_h400.clone()).unwrap();

        let proofs_v10 = db.get_proofs_by_version(10).unwrap();
        assert_eq!(proofs_v10.len(), 2);
        assert!(proofs_v10.contains(&p_v10_h100));
        assert!(proofs_v10.contains(&p_v10_h300));

        let proofs_v20 = db.get_proofs_by_version(20).unwrap();
        assert_eq!(proofs_v20.len(), 1);
        assert_eq!(proofs_v20[0], p_v20_h200);

        let proofs_v99 = db.get_proofs_by_version(99).unwrap();
        assert!(proofs_v99.is_empty());
    }

    #[test]
    fn test_version_persistence_on_update() {
        let (mut db, _temp_dir) = create_test_db();
        let initial_proof = create_sample_proof(150, 5, 42);
        db.save_proof(initial_proof.clone()).unwrap();

        let retrieved_initial = db
            .get_proof(150, &initial_proof.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_initial.last_version, 42);

        let mut updated_proof = initial_proof.clone();
        updated_proof.last_version = 84;
        updated_proof.receipt = vec![1, 0, 1, 0];
        db.save_proof(updated_proof.clone()).unwrap();

        let retrieved_updated = db
            .get_proof(150, &initial_proof.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_updated.last_version, 84);
        assert_eq!(retrieved_updated.receipt, vec![1, 0, 1, 0]);
        assert_eq!(retrieved_updated, updated_proof);
        assert_eq!(db.count_proofs().unwrap(), 1);
    }

    #[test]
    fn test_version_with_chain_operations() {
        let (mut db, _temp_dir) = create_test_db();
        let p1 = create_sample_proof(100, 1, 10);
        let p2 = create_sample_proof(200, 2, 20);
        let p3a = create_sample_proof(300, 3, 30);
        let p3b = create_sample_proof(300, 4, 31);

        db.save_proof(p1).unwrap();
        db.save_proof(p2).unwrap();
        db.save_proof(p3a.clone()).unwrap();
        db.save_proof(p3b.clone()).unwrap();

        let tips = db.get_chain_tips().unwrap();
        assert_eq!(tips.len(), 2);
        let tip_versions: Vec<u64> = tips.iter().map(|p| p.last_version).collect();
        assert!(tip_versions.contains(&30));
        assert!(tip_versions.contains(&31));

        let blocks_at_300 = db.get_blocks_at_height(300).unwrap();
        assert_eq!(blocks_at_300.len(), 2);
        assert!(blocks_at_300.contains(&p3a));
        assert!(blocks_at_300.contains(&p3b));
        let height_300_versions: Vec<u64> = blocks_at_300.iter().map(|p| p.last_version).collect();
        assert!(height_300_versions.contains(&30));
        assert!(height_300_versions.contains(&31));
    }
}
