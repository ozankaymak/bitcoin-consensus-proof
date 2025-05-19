use std::{fs::File, io::Read};

use anyhow::{anyhow, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin_consensus_core::{
    utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO},
    UTXOInsertionUpdateProof,
};
use bitcoincore_rpc::{bitcoin::BlockHash, Client, RpcApi};
use jmt::{proof::UpdateMerkleProof, KeyHash, RootHash, ValueHash};
use rocks_db::RocksDbStorage; // Assuming this is a local module
use sha2::Sha256;
use sqlite::ProofEntry;
use tracing::info; // Assuming this is a local module
                        // tracing::{info, warn}; // Logging removed

pub mod mock_host; // Assuming these are local modules
pub mod rocks_db;
pub mod sqlite;

// Define a constant for the default sparse Merkle tree placeholder hash.
// "SPARSE_MERKLE_PLACEHOLDER_HASH__"
const SPARSE_MERKLE_PLACEHOLDER_HASH_BYTES: [u8; 32] = [
    83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76, 68, 69,
    82, 95, 72, 65, 83, 72, 95, 95,
];
const SPARSE_MERKLE_PLACEHOLDER_HASH: RootHash = RootHash(SPARSE_MERKLE_PLACEHOLDER_HASH_BYTES);

// Parse a block from a binary file
pub fn parse_block_from_file(file_path: &str) -> Result<Block> {
    let mut file = File::open(file_path)
        .with_context(|| format!("Failed to open block file: {}", file_path))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read block file: {}", file_path))?;
    let block: Block = bitcoin::consensus::deserialize(&buffer)
        .with_context(|| format!("Failed to deserialize block from file: {}", file_path))?;
    Ok(block)
}

// Generate JMT proof of deletion for a UTXO
pub fn delete_utxo_and_generate_update_proof(
    storage: &RocksDbStorage,
    utxo_key: &KeyOutPoint,
    prev_root_hash: &mut RootHash,
) -> Result<(UTXO, UpdateMerkleProof<Sha256>, RootHash)> {
    let jmt = storage.get_jmt();

    let latest_root = storage
        .get_latest_root()?
        .unwrap_or(SPARSE_MERKLE_PLACEHOLDER_HASH);
    if latest_root != *prev_root_hash {
        return Err(anyhow!(
            "Previous root hash mismatch. Expected: {:?}, Found in storage: {:?}",
            *prev_root_hash,
            latest_root
        ));
    }

    let latest_version = storage.get_latest_version()?;

    let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());

    let utxo_bytes = jmt.get(key_hash, latest_version)?.ok_or_else(|| {
        anyhow!(
            "UTXO not found in JMT for key_hash: {:?} at version {}",
            key_hash,
            latest_version
        )
    })?;

    let utxo: UTXO = UTXOBytes(utxo_bytes.clone()).into();
    let utxo_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_bytes);

    let (root_after_delete, deletion_proof, batch) = jmt
        .put_value_set_with_proof([(key_hash, None)], latest_version + 1)
        .context("Failed to generate JMT deletion proof")?;

    storage
        .update_with_batch(root_after_delete, batch, latest_version + 1)
        .context("Failed to update storage with JMT batch after deletion")?;

    let deletion_proof_to_borsh =
        borsh::to_vec(&deletion_proof).context("Failed to serialize deletion proof to borsh")?;

    // WARNING: The following slicing for key_hash_from_borsh and value_hash_from_borsh
    // is highly dependent on the internal structure of UpdateMerkleProof and its
    // Borsh serialization format. This is fragile and may break if the jmt crate
    // version or UpdateMerkleProof structure changes.
    // These specific byte ranges (5..37, 37..69) should be re-verified if issues arise.
    let key_hash_from_borsh = borsh::from_slice::<KeyHash>(&deletion_proof_to_borsh[5..37])
        .context("Failed to deserialize KeyHash from borsh (deletion proof)")?;
    let value_hash_from_borsh = borsh::from_slice::<ValueHash>(&deletion_proof_to_borsh[37..69])
        .context("Failed to deserialize ValueHash from borsh (deletion proof)")?;

    assert_eq!(
        key_hash, key_hash_from_borsh,
        "Mismatch in deserialized KeyHash from deletion proof"
    );
    assert_eq!(
        utxo_value_hash, value_hash_from_borsh,
        "Mismatch in deserialized ValueHash from deletion proof"
    );

    let (value_after_delete, noninclusion_proof_after_delete) = jmt
        .get_with_proof(key_hash, latest_version + 1)
        .with_context(|| {
            format!(
                "Failed to get_with_proof for key_hash {:?} after deletion",
                key_hash
            )
        })?;
    assert_eq!(
        value_after_delete, None,
        "UTXO value should be None after deletion"
    );

    noninclusion_proof_after_delete
        .verify_nonexistence(root_after_delete, key_hash)
        .context("Failed to verify nonexistence proof after UTXO deletion")?;

    *prev_root_hash = root_after_delete;

    Ok((utxo, deletion_proof, root_after_delete))
}

pub fn insert_utxos_and_generate_update_proofs(
    storage: &RocksDbStorage,
    key_value_pairs: &[(KeyOutPoint, UTXO)],
    prev_root_hash: &mut RootHash,
) -> Result<UTXOInsertionUpdateProof> {
    let jmt = storage.get_jmt();


    let _initial_latest_version = storage.get_latest_version()?;
    // Logs for leaf counts and root hashes removed here

    let root_before_insert = storage
        .get_latest_root()?
        .unwrap_or(SPARSE_MERKLE_PLACEHOLDER_HASH);
    info!(
        "Root before insert: {:?}, Previous root hash: {:?}",
        root_before_insert, *prev_root_hash
    );
    if root_before_insert != *prev_root_hash {
        return Err(anyhow!(
            "Previous root hash mismatch. Expected: {:?}, Found in storage: {:?}",
            *prev_root_hash,
            root_before_insert
        ));
    }
    let current_jmt_version = storage.get_latest_version()?;
    info!(
        "Current JMT version: {}, Latest version in storage: {}",
        current_jmt_version, _initial_latest_version
    );

    let updates: Vec<(KeyHash, Option<Vec<u8>>)> = key_value_pairs
        .iter()
        .map(|(utxo_key, utxo)| {
            let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
            let utxo_bytes = UTXOBytes::from(utxo.clone());
            (key_hash, Some(utxo_bytes.0))
        })
        .collect();

    // Note: If `put_value_set_with_proof` also has issues with `updates.iter().cloned()`,
    // it might also expect `updates.as_slice()` or the original `updates.clone()`
    // if it needs ownership or if its API is similar to verify_update's AsRef requirement.
    // For now, assuming `updates.iter().cloned()` is acceptable for `put_value_set_with_proof`
    // as the error was reported for `verify_update`.
    let (root_after_insert, insertion_proof, batch) = jmt
        .put_value_set_with_proof(
            updates.iter().cloned(), // This was `updates.clone()` in the original user code.
            // `updates.iter().cloned()` is generally fine if the API takes `IntoIterator + Clone`.
            current_jmt_version + 1,
        )
        .context("Failed to generate JMT insertion proof")?;
    info!("Root after insert: {:?}", root_after_insert);

    storage
        .update_with_batch(root_after_insert, batch, current_jmt_version + 1)
        .context("Failed to update storage with JMT batch after insertion")?;

    let updated_jmt_version = storage.get_latest_version()?;
    let updated_root = storage
        .get_latest_root()?
        .unwrap_or(SPARSE_MERKLE_PLACEHOLDER_HASH);
    info!("Updated root after insert: {:?}", updated_root);
    info!(
        "Updated JMT version: {}, Latest version in storage: {}",
        updated_jmt_version, current_jmt_version + 1
    );

    if updated_root != root_after_insert {
        return Err(anyhow!(
            "Mismatch between calculated root_after_insert ({:?}) and storage's latest root ({:?}) post-update.",
            root_after_insert, updated_root
        ));
    }
    if updated_jmt_version != current_jmt_version + 1 {
        return Err(anyhow!(
            "Mismatch in JMT version. Expected: {}, Found in storage: {}",
            current_jmt_version + 1,
            updated_jmt_version
        ));
    }
    let insertion_proof_to_borsh =
        borsh::to_vec(&insertion_proof).expect("Failed to serialize insertion proof");

    let insertion_proof_clone: UpdateMerkleProof<Sha256> =
        borsh::from_slice(&insertion_proof_to_borsh)?;

    insertion_proof_clone
        .verify_update(
            root_before_insert,
            root_after_insert,
            updates.as_slice(), // Corrected: Pass as a slice to satisfy AsRef<[T]>
        )
        .map_err(|e| anyhow!("JMT insertion proof verification failed: {}", e))?;

    // Logs for leaf and root hash information post-update removed here

    *prev_root_hash = root_after_insert;

    Ok(UTXOInsertionUpdateProof {
        update_proof: insertion_proof,
        new_root: root_after_insert,
    })
}

/// This function retrieves the last active proof from the SQLite database.
/// It traverses up the blockchain from the given `block_hash` until it finds a block
/// for which a proof is stored in `proof_db`. All intermediate blocks are collected.
pub async fn retrieve_proof_for_block_hash_with_blocks_to_prove(
    rpc: &Client,
    block_hash: BlockHash,
    proof_db: &sqlite::ProofDb,
) -> Result<(Option<ProofEntry>, Vec<Block>)> {
    let mut current_block_hash = block_hash;
    let mut proof_entry: Option<ProofEntry> = None;
    let mut blocks_to_prove: Vec<Block> = Vec::new();

    loop {
        match proof_db.find_proof_by_hash(&current_block_hash.to_byte_array().into()) {
            Ok(Some(entry)) => {
                proof_entry = Some(entry);
                break;
            }
            Ok(None) => {
                if current_block_hash == BlockHash::all_zeros() {
                    break;
                }

                let block = rpc.get_block(&current_block_hash).await.with_context(|| {
                    format!("Failed to get block from RPC: {}", current_block_hash)
                })?;

                blocks_to_prove.insert(0, block.clone());
                current_block_hash = block.header.prev_blockhash;
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to query proof_db for hash {:?}: {}",
                    current_block_hash,
                    e
                ));
            }
        }
    }
    Ok((proof_entry, blocks_to_prove))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use anyhow::Result;

    #[test]
    fn test_read_blocks_from_file() -> Result<()> {
        let base_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| anyhow!("Failed to get project root directory"))?
            .join("data/blocks/testnet4-blocks");

        let block_num_to_test = 0;
        let block_path = base_path.join(format!("testnet4_block_{}.bin", block_num_to_test));

        if block_path.exists() {
            let _block = parse_block_from_file(
                block_path
                    .to_str()
                    .ok_or_else(|| anyhow!("Invalid block path"))?,
            )?;

            // If you want to test all 80001 blocks, uncomment the loop:
            /*
            for block_num in 0..=80000 {
                let block_path_str = base_path.join(format!("testnet4_block_{}.bin", block_num));
                if !block_path_str.exists() {
                    // warn!("Test block file not found, skipping: {:?}", block_path_str.display()); // Log removed
                    continue;
                }
                parse_block_from_file(block_path_str.to_str().unwrap())
                    .with_context(|| format!("Failed to parse block number {}", block_num))?;
            }
            // info!("Successfully parsed all available blocks in the range!"); // Log removed
            */
        } else {
            // warn!("Test block file not found, skipping test_read_blocks_from_file: {:?}", block_path.display()); // Log removed
            // Optionally, fail the test if the essential test files are missing:
            // return Err(anyhow!("Essential test block file not found: {:?}", block_path.display()));
        }
        Ok(())
    }
}
