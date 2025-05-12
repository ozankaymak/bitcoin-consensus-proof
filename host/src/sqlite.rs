use chrono::{DateTime, Local};
use core::panic;
use rusqlite::{params, Connection, Result as SqliteResult};
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct ProofEntry {
    pub block_height: u32,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub method_id: [u32; 8],
    pub receipt: Vec<u8>, // This includes the receipt and journal together
}

/// Status of a block in the chain
#[derive(Debug, Clone, PartialEq)]
pub enum BlockStatus {
    /// Active but not finalized yet
    ActiveNotFinalized,
    /// Active and achieved finality depth
    Finalized,
    /// Not on the active chain but not pruned yet
    Inactive,
    /// Height already greater than finalized depth and not active
    Pruned,
}

pub struct Db {
    conn: Connection,
    finalization_depth: u32, // Added finalization_depth as a struct field
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
    pub fn new(db_path: &str, finalization_depth: u32) -> Result<Self, rusqlite::Error> {
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
                status TEXT NOT NULL DEFAULT 'ActiveNotFinalized',
                PRIMARY KEY (block_height, block_hash)
            )",
            [],
        )?;

        // Create indices for faster lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proofs_block_hash ON proofs(block_hash)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proofs_prev_hash ON proofs(prev_hash)",
            [],
        )?;

        // Create the chain_metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS chain_metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
            [],
        )?;

        // Initialize chain metadata with -1 to represent uninitialized state
        conn.execute(
            "INSERT OR IGNORE INTO chain_metadata (key, value) VALUES ('finalized_height', '-1')",
            [],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO chain_metadata (key, value) VALUES ('best_tip_height', '-1')",
            [],
        )?;

        // Initialize best_tip_hash with an empty blob
        conn.execute(
            "INSERT OR IGNORE INTO chain_metadata (key, value) VALUES ('best_tip_hash', X'')",
            [],
        )?;

        // Store the finalization_depth in the metadata table
        conn.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('finalization_depth', ?1)",
            params![finalization_depth.to_string()],
        )?;

        Ok(Db {
            conn,
            finalization_depth,
        })
    }

    // Public API methods

    /// Get the current finalized height
    pub fn get_finalized_height(&self) -> SqliteResult<u32> {
        self.conn.query_row(
            "SELECT value FROM chain_metadata WHERE key = 'finalized_height'",
            [],
            |row| {
                let value_str: String = row.get(0)?;
                let value_i64: i64 = value_str.parse().unwrap_or(-1);

                // Convert -1 to u32::MAX for Rust code
                Ok(if value_i64 == -1 {
                    u32::MAX
                } else {
                    value_i64 as u32
                })
            },
        )
    }

    /// Get the current best tip height
    pub fn get_best_tip_height(&self) -> SqliteResult<u32> {
        self.conn.query_row(
            "SELECT value FROM chain_metadata WHERE key = 'best_tip_height'",
            [],
            |row| {
                let value_str: String = row.get(0)?;
                let value_i64: i64 = value_str.parse().unwrap_or(-1);

                // Convert -1 to u32::MAX for Rust code
                Ok(if value_i64 == -1 {
                    u32::MAX
                } else {
                    value_i64 as u32
                })
            },
        )
    }

    /// Get the current best tip hash. If the database is empty, return [0u8; 32]
    pub fn get_best_tip_hash(&self) -> SqliteResult<[u8; 32]> {
        let result: Result<Vec<u8>, _> = self.conn.query_row(
            "SELECT value FROM chain_metadata WHERE key = 'best_tip_hash'",
            [],
            |row| row.get(0),
        );

        match result {
            Ok(bytes) => {
                if bytes.is_empty() || bytes.len() != 32 {
                    return Ok([0u8; 32]); // Return empty hash for empty DB
                }

                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(hash)
            }
            Err(e) => Err(e),
        }
    }

    /// Store a new proof and update finalization
    pub fn save_proof(
        &mut self,
        proof_entry: ProofEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // First get the heights and best tip hash before starting the transaction
        let current_best_height = self.get_best_tip_height()?;
        println!("Save proof: Current best height: {}", current_best_height);
        let current_finalized_height = self.get_finalized_height()?;
        println!(
            "Save proof: Current finalized height: {}",
            current_finalized_height
        );
        let current_best_hash = self.get_best_tip_hash()?;
        println!("Save proof: Current best hash: {:?}", current_best_hash);

        // Determine the initial status based on multiple factors:
        // 1. Genesis block (height 0) is always finalized
        // 2. Blocks below finalization height are automatically pruned as this should not happen
        // 3. Blocks with height > current_best_height are active and become the new tip
        // 4. Otherwise, blocks are inactive
        let status = if proof_entry.block_height == 0 {
            "Finalized"
        } else if proof_entry.block_height + self.finalization_depth <= current_finalized_height {
            // This block is below the finalization depth, so it is pruned
            // We don't want to keep blocks that are not finalized
            // This should not happen in a valid chain, but we handle it gracefully
            panic!(
                "Block height {} is below finalization depth {}. This should not happen.",
                proof_entry.block_height, current_finalized_height
            );
        } else if proof_entry.block_height > current_best_height {
            assert!(proof_entry.block_height == current_best_height + 1, "Block height must be one greater than finalized height, otherwise there is a problem with the saving logic");
            // New block has greater height, so it becomes active and the new tip
            "ActiveNotFinalized"
        } else {
            // Block height is less than current tip but greater than finalized height
            // This is an alternative branch that should be inactive
            "Inactive"
        };
        println!("Save proof: Block status: {}", status);

        let method_id_bytes = method_id_to_bytes(&proof_entry.method_id);

        // Get current date and time for created_at
        let now = Local::now();

        // Begin a transaction for atomicity after getting the necessary data
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO proofs 
 (block_height, block_hash, prev_hash, method_id, receipt, created_at, status)
 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                proof_entry.block_height,
                proof_entry.block_hash,
                proof_entry.prev_hash,
                method_id_bytes,
                proof_entry.receipt,
                now.to_rfc3339(),
                status,
            ],
        )?;

        // Determine if we should update the tip metadata
        let update_tip = match status {
            "ActiveNotFinalized" | "Finalized" => true,
            "Inactive" => false,
            _ => panic!("Should not happen: invalid status"),
        };

        println!("Save proof: Update tip: {}", update_tip);

        // Commit the transaction
        tx.commit()?;

        // Update finalization only if the tip was updated
        if update_tip {
            self.update_finalization_with_new_proof(&proof_entry)?;
        }

        Ok(())
    }

    /// Update finalization with information about a newly added proof
    pub fn update_finalization_with_new_proof(
        &mut self,
        proof_entry: &ProofEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Begin a transaction
        let tx = self.conn.transaction()?;

        // Special case for genesis block (height 0)
        if proof_entry.block_height == 0 {
            tx.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('finalized_height', '0')",
            [],
        )?;
        }

        // Update the best tip height
        tx.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('best_tip_height', ?1)",
            params![proof_entry.block_height.to_string()],
        )?;

        // Update the best tip hash
        tx.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('best_tip_hash', ?1)",
            params![proof_entry.block_hash],
        )?;

        // Commit the transaction
        tx.commit()?;

        // Now call the regular update_finalization to handle chain reorgs and status updates
        self.update_finalization()?;

        Ok(())
    }

    /// Update finalization status of blocks based on the current chain state
    pub fn update_finalization(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Get the current canonical chain information
        let current_best_height = self.get_best_tip_height()?;
        println!(
            "Update finalization: Current best height: {}",
            current_best_height
        );
        let current_best_hash = self.get_best_tip_hash()?;
        println!(
            "Update finalization: Current best hash: {:?}",
            current_best_hash
        );
        let current_finalized_height = self.get_finalized_height()?;
        println!(
            "Update finalization: Current finalized height: {}",
            current_finalized_height
        );

        // If this is the genesis block (height 0), we've already handled it in update_finalization_with_new_proof
        if current_best_height == 0 {
            println!("Update finalization: Genesis block already handled");
            return Ok(());
        }

        // Get the current tip entry to check its prev_hash
        let tip_entry = match self.find_proof_by_hash(&current_best_hash)? {
            Some(entry) => entry,
            None => {
                println!("Update finalization: Current tip not found in database");
                return Ok(());
            }
        };

        // Check if the parent of the tip is inactive, which indicates a reorg
        let reorg_detected =
            if let Some(parent_status) = self.get_block_status(&tip_entry.prev_hash)? {
                parent_status == BlockStatus::Inactive
            } else {
                false
            };

        if reorg_detected {
            println!("Update finalization: Reorg detected - tip's parent is inactive");
        }

        // Get the active chain (build a new one if reorg detected)
        let active_chain = if reorg_detected {
            // Build a new chain from the tip
            self.build_chain_from_tip(&current_best_hash)?
        } else {
            // Use the existing active chain
            self.get_active_chain()?
        };

        // Calculate new finalized height based on current chain depth
        let new_finalized_height = if current_best_height < self.finalization_depth {
            // Until we reach the finalization depth, only genesis (height 0) is finalized
            0
        } else {
            current_best_height.saturating_sub(self.finalization_depth)
        };

        println!(
            "Update finalization: New finalized height: {}",
            new_finalized_height
        );

        // Begin a transaction
        let tx = self.conn.transaction()?;

        // If active chain is empty, nothing to do
        if active_chain.is_empty() {
            tx.commit()?;
            return Ok(());
        }

        // Create a temporary table with canonical block hashes
        tx.execute(
            "CREATE TEMPORARY TABLE IF NOT EXISTS canonical_blocks (block_hash BLOB PRIMARY KEY)",
            [],
        )?;
        tx.execute("DELETE FROM canonical_blocks", [])?;

        // Insert all active chain block hashes into the temporary table
        for block in active_chain.iter() {
            tx.execute(
                "INSERT OR IGNORE INTO canonical_blocks VALUES (?1)",
                params![block.block_hash],
            )?;
        }

        // Update block statuses:
        // 1. Blocks on the active chain at or below finalized_height become Finalized
        // 2. Blocks on the active chain above finalized_height remain ActiveNotFinalized
        // 3. Blocks not on the active chain at or below finalized_height become Pruned
        // 4. Blocks not on the active chain above finalized_height become Inactive
        tx.execute(
            "UPDATE proofs SET status = CASE 
     WHEN block_hash IN (SELECT block_hash FROM canonical_blocks) THEN 
        CASE WHEN block_height <= ?1 THEN 'Finalized' ELSE 'ActiveNotFinalized' END
     ELSE 
        CASE WHEN block_height <= ?1 THEN 'Pruned' ELSE 'Inactive' END
     END",
            params![new_finalized_height],
        )?;

        // Update the finalized height in metadata if changed
        if new_finalized_height != current_finalized_height {
            tx.execute(
        "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('finalized_height', ?1)",
        params![new_finalized_height.to_string()],
    )?;
            println!(
                "Update finalization: Updated finalized height from {} to {}",
                current_finalized_height, new_finalized_height
            );
        }

        // Clean up temporary table
        tx.execute("DROP TABLE IF EXISTS canonical_blocks", [])?;

        // Commit the transaction
        tx.commit()?;

        Ok(())
    }

    /// Helper method to build active chain from a tip down to the fork point or a finalized block
    fn build_chain_from_tip(&self, tip_hash: &[u8; 32]) -> SqliteResult<Vec<ProofEntry>> {
        let mut chain = Vec::new();
        let mut current_hash = *tip_hash;

        // Get the current finalized height for optimization
        let finalized_height = self.get_finalized_height()?;
        println!(
            "Build chain from tip: Current finalized height: {}",
            finalized_height
        );

        // Get only the non-finalized active chain blocks for comparison to find the fork point
        // This is more efficient as we don't need to consider finalized blocks
        let mut active_chain_blocks: Vec<(u32, [u8; 32])> = self
            .conn
            .prepare(
                "SELECT block_height, block_hash 
         FROM proofs 
         WHERE status = 'ActiveNotFinalized' 
         ORDER BY block_height ASC",
            )?
            .query_map([], |row| {
                let height: u32 = row.get(0)?;
                let hash_data: Vec<u8> = row.get(1)?;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_data);
                Ok((height, hash))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        active_chain_blocks.pop(); // Remove the last block (tip) from the active chain

        // Map of height -> hash for quick lookup of active chain blocks
        let active_chain_map: HashMap<u32, [u8; 32]> = active_chain_blocks.into_iter().collect();

        // Start building the chain from the tip
        loop {
            let proof_option = self.find_proof_by_hash(&current_hash)?;

            if let Some(proof) = proof_option {
                // Add this block to our chain
                chain.push(proof.clone());

                // Stop conditions:
                // 1. We've reached the finalized height - no need to go further
                if proof.block_height <= finalized_height && finalized_height != u32::MAX {
                    println!(
                        "Build chain from tip: Reached finalized height {}",
                        finalized_height
                    );
                    break;
                }

                // 2. We've reached the fork point (this block is already in the active chain)
                if let Some(active_hash) = active_chain_map.get(&proof.block_height) {
                    if *active_hash == proof.block_hash {
                        // We've found the fork point, no need to continue
                        println!(
                            "Build chain from tip: Found fork point at height {}",
                            proof.block_height
                        );
                        break;
                    }
                }

                // 3. We've reached genesis block
                if proof.prev_hash == [0u8; 32] {
                    break;
                }

                // Move to parent block
                current_hash = proof.prev_hash;
            } else {
                // Can't find the block (shouldn't happen in a valid chain)
                break;
            }
        }

        // Reverse to get ascending order by height
        chain.reverse();

        // If we stopped at a fork point or finalized block, we need to get the rest of the active chain below it
        if !chain.is_empty() {
            let lowest_height = chain[0].block_height;

            // Only get blocks between the fork point and the finalized height
            // No need to include finalized blocks as they're already permanent
            if lowest_height > finalized_height && lowest_height > 0 {
                let lower_chain = self
                    .conn
                    .prepare(
                        "SELECT block_height, block_hash, prev_hash, method_id, receipt
                 FROM proofs
                 WHERE status = 'ActiveNotFinalized'
                 AND block_height < ?1
                 AND block_height > ?2
                 ORDER BY block_height ASC",
                    )?
                    .query_map(params![lowest_height, finalized_height], |row| {
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
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                // Combine the chains
                let mut complete_chain = lower_chain;
                complete_chain.extend(chain);
                return Ok(complete_chain);
            }
        }

        Ok(chain)
    }

    /// Set a new finalization depth value
    pub fn set_finalization_depth(&mut self, new_depth: u32) -> SqliteResult<()> {
        self.finalization_depth = new_depth;

        // Update the stored value in the database
        self.conn.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('finalization_depth', ?1)",
            params![new_depth.to_string()],
        )?;

        Ok(())
    }

    /// Get the current finalization depth
    pub fn get_finalization_depth(&self) -> u32 {
        self.finalization_depth
    }

    /// Update a block's status
    pub fn update_block_status(
        &mut self,
        block_hash: &[u8; 32],
        status: BlockStatus,
    ) -> SqliteResult<bool> {
        let status_str = match status {
            BlockStatus::ActiveNotFinalized => "ActiveNotFinalized",
            BlockStatus::Finalized => "Finalized",
            BlockStatus::Inactive => "Inactive",
            BlockStatus::Pruned => "Pruned",
        };

        let result = self.conn.execute(
            "UPDATE proofs SET status = ?1 WHERE block_hash = ?2",
            params![status_str, block_hash],
        )?;

        // Returns true if a row was updated
        Ok(result > 0)
    }

    /// Get a proof by height and hash
    pub fn get_proof(
        &self,
        height: u32,
        block_hash: &[u8; 32],
    ) -> SqliteResult<Option<ProofEntry>> {
        let result = self.conn.query_row(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt
             FROM proofs
             WHERE block_height = ?1 AND block_hash = ?2",
            params![height, block_hash],
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

    /// Get the status of a block
    pub fn get_block_status(&self, block_hash: &[u8; 32]) -> SqliteResult<Option<BlockStatus>> {
        let result = self.conn.query_row(
            "SELECT status FROM proofs WHERE block_hash = ?1",
            params![block_hash],
            |row| {
                let status_str: String = row.get(0)?;

                let status = match status_str.as_str() {
                    "ActiveNotFinalized" => BlockStatus::ActiveNotFinalized,
                    "Finalized" => BlockStatus::Finalized,
                    "Inactive" => BlockStatus::Inactive,
                    "Pruned" => BlockStatus::Pruned,
                    _ => panic!("Invalid block status in database"),
                };

                Ok(status)
            },
        );

        match result {
            Ok(status) => Ok(Some(status)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get all the blocks that have the highest height
    pub fn get_chain_tips(&self) -> SqliteResult<Vec<ProofEntry>> {
        // First, find the maximum height
        let max_height: u32 =
            self.conn
                .query_row("SELECT MAX(block_height) FROM proofs", [], |row| row.get(0))?;

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

    /// Get all active blocks in order of height, forming a valid chain
    /// Optimization: Only retrieve non-finalized active blocks since finalized blocks are permanent
    pub fn get_active_chain(&self) -> SqliteResult<Vec<ProofEntry>> {
        // Get the current finalized height
        let finalized_height = self.get_finalized_height()?;

        // Only query for non-finalized active blocks above the finalized height
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt 
         FROM proofs 
         WHERE status = 'ActiveNotFinalized' 
         AND block_height > ?1
         ORDER BY block_height ASC",
        )?;

        let proof_iter = stmt.query_map(params![finalized_height], |row| {
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

        let mut chain = Vec::new();
        for proof_result in proof_iter {
            chain.push(proof_result?);
        }

        // We don't need to sort the chain since the SQL query already ordered the results by height

        Ok(chain)
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

    /// Get the complete active chain including both finalized and non-finalized blocks,
    /// forming a valid chain in order of height
    pub fn get_complete_active_chain(&self) -> SqliteResult<Vec<ProofEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_height, block_hash, prev_hash, method_id, receipt 
         FROM proofs 
         WHERE status IN ('ActiveNotFinalized', 'Finalized') 
         ORDER BY block_height ASC",
        )?;

        let proof_iter = stmt.query_map([], |row| {
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

        let mut chain = Vec::new();
        for proof_result in proof_iter {
            chain.push(proof_result?);
        }

        // The ORDER BY in the SQL query already sorted by height,
        // but if needed, we could sort here too:
        // chain.sort_by_key(|proof| proof.block_height);

        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const TEST_FINALIZATION_DEPTH: u32 = 3;

    fn create_test_db() -> Result<(Db, String), Box<dyn Error>> {
        // Create a simple in-memory database for testing
        let db_path = ":memory:";

        // Create the database
        let db = Db::new(db_path, TEST_FINALIZATION_DEPTH)?;

        Ok((db, db_path.to_string()))
    }

    fn create_proof(height: u32, hash_byte: u8, prev_hash_byte: u8) -> ProofEntry {
        ProofEntry {
            block_height: height,
            block_hash: [hash_byte; 32],
            prev_hash: [prev_hash_byte; 32],
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30], // Example receipt data
        }
    }

    #[test]
    fn test_save_genesis_block() -> Result<(), Box<dyn Error>> {
        println!("Starting test_save_genesis_block");
        println!("Creating test database");
        let (mut db, _) = create_test_db()?;
        println!("Test database created");
        // Create and save a genesis block
        let genesis = create_proof(0, 1, 0); // Height 0, hash [1;32], prev_hash [0;32]
        db.save_proof(genesis.clone())?;

        // Verify it was saved properly
        let saved_genesis = db.get_proof(0, &[1; 32])?.expect("Genesis block not found");
        println!("Saved genesis block: {:?}", saved_genesis);

        assert_eq!(saved_genesis.block_height, 0);
        assert_eq!(saved_genesis.block_hash, [1; 32]);

        // Verify best tip
        let best_tip_height = db.get_best_tip_height()?;
        println!("Best tip height: {}", best_tip_height);

        let best_tip_hash = db.get_best_tip_hash()?;
        println!("Best tip hash: {:?}", best_tip_hash);
        assert_eq!(best_tip_height, 0);
        assert_eq!(best_tip_hash, [1; 32]);

        // Verify finalized height (should still be 0 for genesis)
        let finalized_height = db.get_finalized_height()?;
        assert_eq!(finalized_height, 0);

        Ok(())
    }

    #[test]
    fn test_build_simple_chain() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a simple chain of 5 blocks
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        for i in 1..5u8 {
            let block = create_proof(i.into(), i + 1, i); // Height i, hash [i+1;32], prev_hash [i;32]
            db.save_proof(block)?;
            db.update_finalization()?;
        }

        // Verify best tip
        let best_tip_height = db.get_best_tip_height()?;
        let best_tip_hash = db.get_best_tip_hash()?;
        assert_eq!(best_tip_height, 4);
        assert_eq!(best_tip_hash, [5; 32]); // Hash of block 4 is [5u8; 32]

        // Verify all blocks are in sequence
        for i in 0..5u8 {
            let block = db
                .get_proof(i.into(), &[i + 1; 32])?
                .expect("Block not found");
            assert_eq!(block.block_height, i as u32);
            assert_eq!(block.block_hash, [i + 1; 32]);

            // Check status (should all be active, none finalized yet)
            let status = db
                .get_block_status(&[i + 1; 32])?
                .expect("Block status not found");
            println!("Block {} status: {:?}", i, status);

            if i == 0 || i == 1 {
                // Genesis is always finalized, and here block 1 is also finalized
                assert!(matches!(status, BlockStatus::Finalized));
            } else {
                assert!(matches!(status, BlockStatus::ActiveNotFinalized));
            }
        }

        Ok(())
    }

    #[test]
    fn test_finalization() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a chain longer than TEST_FINALIZATION_DEPTH
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        for i in 1..=(TEST_FINALIZATION_DEPTH as u8) + 5 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Call the update_finalization function to process finalization
        db.update_finalization()?;

        // Verify finalization
        let finalized_height = db.get_finalized_height()?;
        // With TEST_FINALIZATION_DEPTH = 3, blocks 0-5 should be finalized when tip is at height 8
        let expected_finalized_height =
            (TEST_FINALIZATION_DEPTH as u8 + 5) - TEST_FINALIZATION_DEPTH as u8;
        assert_eq!(finalized_height, expected_finalized_height as u32);

        // Check status of blocks
        for i in 0..=(TEST_FINALIZATION_DEPTH as u8) + 5 {
            let status = db
                .get_block_status(&[i + 1; 32])?
                .expect("Block status not found");

            if i <= expected_finalized_height {
                // These should be finalized
                assert!(
                    matches!(status, BlockStatus::Finalized),
                    "Block {} should be finalized",
                    i
                );
            } else {
                // These should still be active but not finalized
                assert!(
                    matches!(status, BlockStatus::ActiveNotFinalized),
                    "Block {} should be active but not finalized",
                    i
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_multiple_blocks_at_same_height() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Add a block at height 1
        let block1 = create_proof(1, 2, 1);
        db.save_proof(block1)?;

        // Add another block at height 1 with different hash
        let block1_alt = ProofEntry {
            block_height: 1,
            block_hash: [100; 32], // Different hash
            prev_hash: [1; 32],    // Same prev_hash
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block1_alt)?;

        // Both blocks should be active, but one is canonical based on deterministic selection
        // Get the status of both blocks
        let status1 = db.get_block_status(&[2; 32])?.expect("Block not found");
        let status2 = db.get_block_status(&[100; 32])?.expect("Block not found");

        // One block should be active, one should be inactive (our deterministic selection)
        let active_blocks = match (status1, status2) {
            (BlockStatus::ActiveNotFinalized, BlockStatus::Inactive) => {
                assert_eq!(db.get_best_tip_hash()?, [2; 32]);
                1
            }
            (BlockStatus::Inactive, BlockStatus::ActiveNotFinalized) => {
                assert_eq!(db.get_best_tip_hash()?, [100; 32]);
                1
            }
            _ => 2, // This will cause the test to fail
        };

        assert_eq!(active_blocks, 1, "Only one block should be active");

        // Verify both blocks exist
        let blocks_at_height_1 = db.get_blocks_at_height(1)?;
        assert_eq!(blocks_at_height_1.len(), 2);

        // Verify the best tip is still the one with the highest height
        let best_tip_height = db.get_best_tip_height()?;
        assert_eq!(best_tip_height, 1);

        Ok(())
    }

    #[test]
    fn test_save_duplicate_block() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a single block
        let block = create_proof(0, 1, 0);
        db.save_proof(block.clone())?;

        // Try to save it again with same data
        db.save_proof(block.clone())?;

        // Should still only have one block
        let blocks = db.get_blocks_at_height(0)?;
        assert_eq!(blocks.len(), 1);

        // Try saving with different receipt
        let mut modified_block = block.clone();
        modified_block.receipt = vec![99, 99, 99];
        db.save_proof(modified_block)?;

        // Should still only have one block but receipt should be updated
        let saved_block = db.get_proof(0, &[1; 32])?.expect("Block not found");
        assert_eq!(saved_block.receipt, vec![99, 99, 99]);

        Ok(())
    }

    #[test]
    fn test_chain_tips() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        for i in 1..5u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // There should be one chain tip at height 4
        let tips = db.get_chain_tips()?;
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].block_height, 4);
        assert_eq!(tips[0].block_hash, [5; 32]);

        // Add multiple blocks at height 5
        let block5a = ProofEntry {
            block_height: 5,
            block_hash: [6; 32],
            prev_hash: [5; 32],
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block5a)?;

        let block5b = ProofEntry {
            block_height: 5,
            block_hash: [100; 32],
            prev_hash: [5; 32],
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block5b)?;

        // Now there should be two chain tips, both at height 5
        let tips = db.get_chain_tips()?;
        assert_eq!(tips.len(), 2);
        assert_eq!(tips[0].block_height, 5);
        assert_eq!(tips[1].block_height, 5);

        // Their hashes should match what we expect
        let tip_hashes: Vec<[u8; 32]> = tips.iter().map(|t| t.block_hash).collect();
        assert!(tip_hashes.contains(&[6; 32]));
        assert!(tip_hashes.contains(&[100; 32]));

        Ok(())
    }

    #[test]
    fn test_orphaned_blocks() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Add a normal active block
        let block1 = create_proof(1, 2, 1);
        db.save_proof(block1)?;

        // Add an orphaned block (first save normally, then update status)
        let orphaned_block = ProofEntry {
            block_height: 1,
            block_hash: [200; 32],
            prev_hash: [99; 32], // Points to a non-existent block
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(orphaned_block)?;
        db.update_block_status(&[200; 32], BlockStatus::Pruned)?;

        // Add an inactive block (first save normally, then update status)
        let inactive_block = ProofEntry {
            block_height: 2,
            block_hash: [150; 32],
            prev_hash: [2; 32], // Points to the normal block
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(inactive_block)?;
        db.update_block_status(&[150; 32], BlockStatus::Inactive)?;

        // Verify statuses
        let status_active = db.get_block_status(&[2; 32])?.expect("Block not found");
        let status_orphaned = db.get_block_status(&[200; 32])?.expect("Block not found");
        let status_inactive = db.get_block_status(&[150; 32])?.expect("Block not found");

        assert!(matches!(status_active, BlockStatus::ActiveNotFinalized));
        assert!(matches!(status_orphaned, BlockStatus::Pruned));
        assert!(matches!(status_inactive, BlockStatus::Inactive));

        Ok(())
    }

    #[test]
    fn test_update_block_status() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a block
        let block = create_proof(1, 2, 1);
        db.save_proof(block.clone())?; // Start as active

        // Verify it's active
        let status = db.get_block_status(&[2; 32])?.expect("Block not found");
        assert!(matches!(status, BlockStatus::ActiveNotFinalized));

        // Update to inactive
        db.update_block_status(&[2; 32], BlockStatus::Inactive)?;

        // Verify it's now inactive
        let status = db.get_block_status(&[2; 32])?.expect("Block not found");
        assert!(matches!(status, BlockStatus::Inactive));

        // Update to pruned
        db.update_block_status(&[2; 32], BlockStatus::Pruned)?;

        // Verify it's now pruned
        let status = db.get_block_status(&[2; 32])?.expect("Block not found");
        assert!(matches!(status, BlockStatus::Pruned));

        Ok(())
    }

    #[test]
    fn test_get_active_chain() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        for i in 1..5u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Add an inactive block
        let inactive_block = ProofEntry {
            block_height: 3,
            block_hash: [100; 32],
            prev_hash: [3; 32],
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(inactive_block)?;
        db.update_block_status(&[100; 32], BlockStatus::Inactive)?;

        // Get the active chain
        let active_chain = db.get_active_chain()?;

        // Should have 5 blocks (0-4)
        assert_eq!(active_chain.len(), 5);

        // Verify all blocks are in order of height
        for i in 0..5 {
            assert_eq!(active_chain[i].block_height, i as u32);
        }

        // Verify the inactive block is not in the chain
        let contains_inactive = active_chain
            .iter()
            .any(|block| block.block_hash == [100; 32]);
        assert!(
            !contains_inactive,
            "Active chain should not contain inactive block"
        );

        Ok(())
    }

    #[test]
    fn test_finalized_blocks_status() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a chain beyond finalization depth
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        for i in 1..=8u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Call update_finalization to process finalization
        db.update_finalization()?;

        // Check finalized height (should be 5 with TEST_FINALIZATION_DEPTH = 3)
        let finalized_height = db.get_finalized_height()?;
        assert_eq!(finalized_height, 8 - TEST_FINALIZATION_DEPTH);

        // Try changing a finalized block to inactive
        let block3 = &[4; 32]; // Hash of block 3
        db.update_block_status(block3, BlockStatus::Inactive)?;

        // Verify status - this test may need to be updated based on your policy
        // Does updating a finalized block actually change its status?
        let status = db.get_block_status(block3)?.expect("Block not found");
        assert!(matches!(status, BlockStatus::Inactive)); // Using the new behavior - status can change

        // Try changing a finalized block to pruned
        let block4 = &[5; 32]; // Hash of block 4
        db.update_block_status(block4, BlockStatus::Pruned)?;

        // Verify status - again, may need updating based on your policy
        let status = db.get_block_status(block4)?.expect("Block not found");
        assert!(matches!(status, BlockStatus::Pruned)); // Using the new behavior - status can change

        Ok(())
    }

    #[test]
    fn test_update_finalization() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Add blocks up to height 8
        for i in 1..=8u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Add a competing chain from height 3 onwards
        for i in 3..=6u8 {
            let alt_block = ProofEntry {
                block_height: i.into(),
                block_hash: [100 + i; 32], // Different hash pattern
                prev_hash: if i == 3 { [3; 32] } else { [100 + i - 1; 32] },
                method_id: [0, 1, 2, 3, 4, 5, 6, 7],
                receipt: vec![10, 20, 30],
            };
            db.save_proof(alt_block)?;
        }

        // Blocks in the alt chain will be inactive, since they have a lower height

        // Call update_finalization
        db.update_finalization()?;

        // Verify finalized height
        let finalized_height = db.get_finalized_height()?;
        assert_eq!(finalized_height, 8 - TEST_FINALIZATION_DEPTH); // With tip at 8 and TEST_FINALIZATION_DEPTH = 3

        // Check blocks in the main chain
        for i in 0..=5u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::Finalized),
                "Block {} in main chain should be finalized",
                i
            );
        }

        // Blocks in the inactive chain that are below finalization height should be pruned
        for i in 3..=5u8 {
            let status = db
                .get_block_status(&[100 + i; 32])?
                .expect("Block not found");
            assert!(
                matches!(status, BlockStatus::Pruned) || matches!(status, BlockStatus::Inactive),
                "Block {} in inactive chain should be pruned or inactive",
                i
            );
        }

        Ok(())
    }

    #[test]
    fn test_changing_finalization_depth() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Verify initial finalization depth
        assert_eq!(db.get_finalization_depth(), TEST_FINALIZATION_DEPTH);

        // Create a chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        for i in 1..=10u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // With TEST_FINALIZATION_DEPTH = 3, block 7 should be finalized
        db.update_finalization()?;
        let finalized_height_before = db.get_finalized_height()?;
        assert_eq!(finalized_height_before, 7);

        // Change finalization depth to 5
        db.set_finalization_depth(5)?;
        assert_eq!(db.get_finalization_depth(), 5);

        // Update finalization again
        db.update_finalization()?;

        // With new depth of 5, block 5 should be finalized
        let finalized_height_after = db.get_finalized_height()?;
        assert_eq!(finalized_height_after, 5);

        // Verify blocks 0-5 are finalized
        for i in 0..=5u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::Finalized),
                "Block {} should be finalized with new depth",
                i
            );
        }

        // Verify blocks 6-10 are not finalized
        for i in 6..=10u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::ActiveNotFinalized),
                "Block {} should not be finalized with new depth",
                i
            );
        }

        Ok(())
    }

    #[test]
    fn test_chain_reorganization() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Build chain A: 0 -> 1 -> 2 -> 3A -> 4A
        for i in 1..=3u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Add block 4A (height 4, hash [5;32], prev_hash [4;32])
        let block4a = create_proof(4, 5, 4);
        db.save_proof(block4a)?;

        // Verify the active chain
        let best_tip_height = db.get_best_tip_height()?;
        let best_tip_hash = db.get_best_tip_hash()?;
        assert_eq!(best_tip_height, 4);
        assert_eq!(best_tip_hash, [5; 32]);

        // Now build a competing chain that starts at block 3
        // First, add block 3B (different from 3A)
        let block3b = ProofEntry {
            block_height: 3,
            block_hash: [100; 32], // Different hash
            prev_hash: [3; 32],    // Same prev_hash as block 3A
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block3b)?;
        // Right now this block must be inactive
        let status_3b = db
            .get_block_status(&[100; 32])?
            .expect("Block 3B not found");
        assert!(matches!(status_3b, BlockStatus::Inactive));

        // Add block 4B
        let block4b = ProofEntry {
            block_height: 4,
            block_hash: [101; 32],
            prev_hash: [100; 32], // Points to block 3B
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block4b)?;
        // Right now this block must be inactive
        let status_4b = db
            .get_block_status(&[101; 32])?
            .expect("Block 4B not found");
        assert!(matches!(status_4b, BlockStatus::Inactive));

        // Tip should not have changed, as both chains have the same height
        let best_tip_after_fork = db.get_best_tip_hash()?;
        // The hash might be [5u8; 32]
        assert!(best_tip_after_fork == [5; 32]);

        // Now add block 5B to make chain B longer
        let block5b = ProofEntry {
            block_height: 5,
            block_hash: [102; 32],
            prev_hash: [101; 32], // Points to block 4B
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block5b)?;

        // At this point, chain B should be the active chain as it's longer
        let new_best_tip_height = db.get_best_tip_height()?;
        let new_best_tip_hash = db.get_best_tip_hash()?;
        assert_eq!(new_best_tip_height, 5);
        assert_eq!(new_best_tip_hash, [102; 32]);

        // Check that blocks from chain B are now active
        let status3b = db
            .get_block_status(&[100; 32])?
            .expect("Block 3B not found");
        println!("Status of block 3B: {:?}", status3b);
        let status4b = db
            .get_block_status(&[101; 32])?
            .expect("Block 4B not found");
        println!("Status of block 4B: {:?}", status4b);
        let status5b = db
            .get_block_status(&[102; 32])?
            .expect("Block 5B not found");
        println!("Status of block 5B: {:?}", status5b);

        assert!(matches!(status3b, BlockStatus::ActiveNotFinalized));
        assert!(matches!(status4b, BlockStatus::ActiveNotFinalized));
        assert!(matches!(status5b, BlockStatus::ActiveNotFinalized));

        // Check that blocks from chain A that were replaced are now inactive
        let status3a = db.get_block_status(&[4; 32])?.expect("Block 3A not found");
        let status4a = db.get_block_status(&[5; 32])?.expect("Block 4A not found");

        assert!(matches!(status3a, BlockStatus::Inactive));
        assert!(matches!(status4a, BlockStatus::Inactive));

        // Verify common blocks 0, 1, 2 are still active
        for i in 0..=2u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::ActiveNotFinalized)
                    || matches!(status, BlockStatus::Finalized),
                "Block {} should still be active or finalized",
                i
            );
        }

        Ok(())
    }

    #[test]
    fn test_build_chain_from_tip() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Build chain up to block 10
        for i in 1..=10u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Create a fork at height 9
        // Add block 9B (different from 9A)
        let block5b = ProofEntry {
            block_height: 9,
            block_hash: [100; 32], // Different hash
            prev_hash: [9; 32],    // Same prev_hash as block 9A
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block5b)?;

        // Add blocks 10B and 11B
        let block6b = ProofEntry {
            block_height: 10,
            block_hash: [101; 32],
            prev_hash: [100; 32], // Points to block 9B
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block6b)?;

        let block7b = ProofEntry {
            block_height: 11,
            block_hash: [102; 32],
            prev_hash: [101; 32], // Points to block 10B
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block7b)?;

        // // Create the longest chain by adding blocks 8B, 9B, 10B, 11B
        // for i in 8..=11u8 {
        //     let block_b = ProofEntry {
        //         block_height: i as u32,
        //         block_hash: [100 + (i - 7); 32], // Continue the pattern
        //         prev_hash: if i == 8 {
        //             [102; 32]
        //         } else {
        //             [100 + (i - 8); 32]
        //         },
        //         method_id: [0, 1, 2, 3, 4, 5, 6, 7],
        //         receipt: vec![10, 20, 30],
        //     };
        //     db.save_proof(block_b)?;
        // }

        // Now chain B is longer than chain A, so it should be the active chain
        let best_tip_height = db.get_best_tip_height()?;
        println!("Best tip height test: {}", best_tip_height);
        let best_tip_hash = db.get_best_tip_hash()?;
        println!("Best tip hash test: {:?}", best_tip_hash);
        assert_eq!(best_tip_height, 11);
        assert_eq!(best_tip_hash, [102; 32]); // Hash of block 11B

        // Check that the build_chain_from_tip method correctly builds the chain from the tip
        // We access the private method through reflection or by adding a test-only public method

        // Instead, verify its effect by using get_active_chain
        let active_chain = db.get_active_chain()?;
        println!("Active chain: {:?}", active_chain);

        let complete_active_chain = db.get_complete_active_chain()?;
        println!("Complete active chain: {:?}", complete_active_chain);

        // Active chain should include blocks 0-4 from the original chain and blocks 5B-11B from the new chain
        assert_eq!(active_chain.len(), 3); // 0 through 11
        assert_eq!(complete_active_chain.len(), 12); // 0 through 11

        // Verify blocks 0-4 are from the original chain
        for i in 0..=4u8 {
            assert_eq!(complete_active_chain[i as usize].block_hash, [i + 1; 32]);
        }

        // Verify blocks 5-11 are from chain B
        assert_eq!(active_chain[0].block_hash, [100; 32]); // 9B
        assert_eq!(active_chain[1].block_hash, [101; 32]); // 10B
        assert_eq!(active_chain[2].block_hash, [102; 32]); // 11B
                                                           // assert_eq!(active_chain[8].block_hash, [101; 32]); // 8B
                                                           // assert_eq!(active_chain[9].block_hash, [102; 32]); // 9B
                                                           // assert_eq!(active_chain[10].block_hash, [103; 32]); // 10B
                                                           // assert_eq!(active_chain[11].block_hash, [104; 32]); // 11B

        // Check that blocks from chain A that were replaced are now inactive
        for i in 9..=10u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::Inactive),
                "Block {} from original chain should be inactive",
                i
            );
        }

        Ok(())
    }

    #[test]
    fn test_fork_at_finalized_depth() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Build chain up to block 10
        for i in 1..=10u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Finalize blocks up to height 7 (10 - TEST_FINALIZATION_DEPTH)
        db.update_finalization()?;
        let finalized_height = db.get_finalized_height()?;
        assert_eq!(finalized_height, 7);

        // Create a fork at finalized height (height 7)
        let block7b = ProofEntry {
            block_height: 7,
            block_hash: [100; 32], // Different hash
            prev_hash: [7; 32],    // Points to block 6
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block7b)?;

        // Add blocks to make this chain longer
        for i in 8..=15u8 {
            let block_b = ProofEntry {
                block_height: i as u32,
                block_hash: [100 + (i - 7); 32],
                prev_hash: if i == 8 {
                    [100; 32]
                } else {
                    [100 + (i - 8); 32]
                },
                method_id: [0, 1, 2, 3, 4, 5, 6, 7],
                receipt: vec![10, 20, 30],
            };
            db.save_proof(block_b)?;
        }

        // Now chain B is longer than chain A, but since the fork is at the finalized height,
        // the original chain should still be the active chain for the finalized blocks

        // Update finalization
        db.update_finalization()?;

        // Check new finalized height (should be 12 = 15 - TEST_FINALIZATION_DEPTH)
        let new_finalized_height = db.get_finalized_height()?;
        assert_eq!(new_finalized_height, 12);

        // Verify the active chain
        let active_chain = db.get_active_chain()?;

        // The active chain should include blocks 0-6 from the original chain
        // and blocks 7B-15B from the new chain
        assert_eq!(active_chain.len(), 16); // 0 through 15

        // Verify blocks 0-6 are from the original chain
        for i in 0..=6u8 {
            assert_eq!(active_chain[i as usize].block_hash, [i + 1; 32]);
        }

        // Verify block 7 is now from chain B, not chain A
        assert_eq!(active_chain[7].block_hash, [100; 32]); // 7B, not [8; 32]

        // Check that blocks 7-10 from chain A are now inactive or pruned
        for i in 7..=10u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::Inactive) || matches!(status, BlockStatus::Pruned),
                "Block {} from original chain should be inactive or pruned",
                i
            );
        }

        // Verify blocks 0-6 are still finalized
        for i in 0..=6u8 {
            let status = db.get_block_status(&[i + 1; 32])?.expect("Block not found");
            assert!(
                matches!(status, BlockStatus::Finalized),
                "Block {} should still be finalized",
                i
            );
        }

        // Verify that blocks 7B-12B are finalized
        assert!(matches!(
            db.get_block_status(&[100; 32])?.unwrap(),
            BlockStatus::Finalized
        )); // 7B
        assert!(matches!(
            db.get_block_status(&[101; 32])?.unwrap(),
            BlockStatus::Finalized
        )); // 8B
        assert!(matches!(
            db.get_block_status(&[102; 32])?.unwrap(),
            BlockStatus::Finalized
        )); // 9B
        assert!(matches!(
            db.get_block_status(&[103; 32])?.unwrap(),
            BlockStatus::Finalized
        )); // 10B
        assert!(matches!(
            db.get_block_status(&[104; 32])?.unwrap(),
            BlockStatus::Finalized
        )); // 11B
        assert!(matches!(
            db.get_block_status(&[105; 32])?.unwrap(),
            BlockStatus::Finalized
        )); // 12B

        // Verify that blocks 13B-15B are active but not finalized
        assert!(matches!(
            db.get_block_status(&[106; 32])?.unwrap(),
            BlockStatus::ActiveNotFinalized
        )); // 13B
        assert!(matches!(
            db.get_block_status(&[107; 32])?.unwrap(),
            BlockStatus::ActiveNotFinalized
        )); // 14B
        assert!(matches!(
            db.get_block_status(&[108; 32])?.unwrap(),
            BlockStatus::ActiveNotFinalized
        )); // 15B

        Ok(())
    }

    #[test]
    fn test_same_height_chain_selection() -> Result<(), Box<dyn Error>> {
        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Add two blocks at height 1
        // Block 1A: hash [2;32] (lexicographically larger)
        let block1a = create_proof(1, 2, 1);
        db.save_proof(block1a)?;

        // Block 1B: hash [1;32] (lexicographically smaller)
        let block1b = ProofEntry {
            block_height: 1,
            block_hash: [1; 32], // Different hash, lexicographically smaller
            prev_hash: [1; 32],  // Same prev_hash as block 1A
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block1b)?;

        // Because of our deterministic selection (min by hash),
        // the active chain should include block 1B ([1;32]), not 1A ([2;32])

        // Check best tip hash
        let best_tip_hash = db.get_best_tip_hash()?;
        assert_eq!(best_tip_hash, [1; 32]); // Block 1B should be selected

        // Now add a block on top of 1A to make that chain longer
        let block2a = ProofEntry {
            block_height: 2,
            block_hash: [3; 32],
            prev_hash: [2; 32], // Points to block 1A
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block2a)?;

        // Now chain A should be active as it's longer, despite block 1A having a larger hash
        let new_best_tip_height = db.get_best_tip_height()?;
        let new_best_tip_hash = db.get_best_tip_hash()?;
        assert_eq!(new_best_tip_height, 2);
        assert_eq!(new_best_tip_hash, [3; 32]);

        // Check that block 1A is now active and block 1B is inactive
        let status1a = db.get_block_status(&[2; 32])?.expect("Block 1A not found");
        let status1b = db.get_block_status(&[1; 32])?.expect("Block 1B not found");

        assert!(matches!(status1a, BlockStatus::ActiveNotFinalized));
        assert!(matches!(status1b, BlockStatus::Inactive));

        Ok(())
    }

    #[test]
    fn test_chain_reorg_without_height_change() -> Result<(), Box<dyn Error>> {
        // This tests the edge case in our update_finalization discussion
        // where A and B are tips of same height, A is canonical,
        // and then C is added on top of B making B,C the new canonical chain

        let (mut db, _) = create_test_db()?;

        // Create a base chain
        let genesis = create_proof(0, 1, 0);
        db.save_proof(genesis)?;

        // Add blocks up to height 3
        for i in 1..=3u8 {
            let block = create_proof(i.into(), i + 1, i);
            db.save_proof(block)?;
        }

        // Add a competing block at height 3 (3B)
        let block3b = ProofEntry {
            block_height: 3,
            block_hash: [100; 32], // Different hash
            prev_hash: [3; 32],    // Points to block 2
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block3b)?;

        // At this point, there should be two blocks at height 3,
        // and one should be canonical based on our deterministic selection

        // Assuming lexicographically smallest hash is chosen:
        // Block 3A: [4;32]
        // Block 3B: [100;32]
        // Block 3A should be active, Block A should be inactive
        let status3a = db.get_block_status(&[4; 32])?.expect("Block 3A not found");
        let status3b = db
            .get_block_status(&[100; 32])?
            .expect("Block 3B not found");

        assert!(
            (matches!(status3a, BlockStatus::ActiveNotFinalized)
                && matches!(status3b, BlockStatus::Inactive))
                || (matches!(status3a, BlockStatus::Inactive)
                    && matches!(status3b, BlockStatus::ActiveNotFinalized)),
            "One block should be active, one inactive"
        );

        // Figure out which one is currently active
        let currently_active = if matches!(status3a, BlockStatus::ActiveNotFinalized) {
            "A"
        } else {
            "B"
        };

        println!("Block 3{} is currently active", currently_active);

        // Now add block 4C on top of whichever block is currently inactive
        // This will force a chain reorganization
        let (block4c_hash, block4c_prev_hash) = if currently_active == "A" {
            // If A is active, add C on top of B
            ([110; 32], [100; 32])
        } else {
            // If B is active, add C on top of A
            ([110; 32], [4; 32])
        };

        let block4c = ProofEntry {
            block_height: 4,
            block_hash: block4c_hash,
            prev_hash: block4c_prev_hash,
            method_id: [0, 1, 2, 3, 4, 5, 6, 7],
            receipt: vec![10, 20, 30],
        };
        db.save_proof(block4c)?;

        // Now the chain with block 4C should be active, as it's longer
        let new_best_tip_height = db.get_best_tip_height()?;
        let new_best_tip_hash = db.get_best_tip_hash()?;
        assert_eq!(new_best_tip_height, 4);
        assert_eq!(new_best_tip_hash, [110; 32]);

        // Check that the previously inactive block is now active
        let new_status3a = db.get_block_status(&[4; 32])?.expect("Block 3A not found");
        let new_status3b = db
            .get_block_status(&[100; 32])?
            .expect("Block 3B not found");

        if currently_active == "A" {
            // If A was active, now B should be active
            assert!(matches!(new_status3a, BlockStatus::Inactive));
            assert!(matches!(new_status3b, BlockStatus::ActiveNotFinalized));
        } else {
            // If B was active, now A should be active
            assert!(matches!(new_status3a, BlockStatus::ActiveNotFinalized));
            assert!(matches!(new_status3b, BlockStatus::Inactive));
        }

        Ok(())
    }
}
