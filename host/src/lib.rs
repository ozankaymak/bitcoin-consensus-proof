use std::{fs::File, io::Read};

use anyhow::Result;
use bitcoin::Block;
use bitcoin_consensus_core::{
    utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO},
    UTXOInsertionUpdateProof,
};
use jmt::{proof::UpdateMerkleProof, KeyHash, RootHash, ValueHash};
use rocks_db::RocksDbStorage;
use sha2::Sha256;
use tracing::{info, warn};

pub mod mock_host;
pub mod rocks_db;

// Parse a block from a binary file
pub fn parse_block_from_file(file_path: &str) -> Result<Block, anyhow::Error> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let block: Block = bitcoin::consensus::deserialize(&buffer)?;
    Ok(block)
}

// Generate JMT proof of inclusion for a UTXO
pub fn delete_utxo_and_generate_update_proof(
    storage: &RocksDbStorage,
    utxo_key: &KeyOutPoint,
    prev_root_hash: &mut RootHash,
) -> Result<(UTXO, UpdateMerkleProof<Sha256>, RootHash)> {
    info!(
        "Generating UTXO deletion update proof for key: {:?}",
        utxo_key
    );

    let jmt = storage.get_jmt();

    // Get the latest version of the tree
    let latest_root = storage.get_latest_root()?.unwrap_or(RootHash::from([
        83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76, 68,
        69, 82, 95, 72, 65, 83, 72, 95, 95,
    ]));
    assert_eq!(latest_root, *prev_root_hash);
    let latest_version = storage.get_latest_version()?;
    warn!("Delete UTXO:  JMT State:");
    warn!("Delete UTXO:    Latest root: {:?}", latest_root);
    warn!("Delete UTXO:    Latest version: {}", latest_version);

    // Generate key hash from UTXO key using OutPointBytes
    let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
    warn!("  Key details:");
    warn!("    Transaction ID: {:?}", utxo_key.txid);
    warn!("    Output index: {}", utxo_key.vout);
    warn!("    Key hash: {:?}", key_hash);
    warn!("    Key hash bytes: {:?}", key_hash.0);

    // Get the UTXO value
    info!("  Fetching UTXO from JMT...");
    let utxo_bytes = jmt.get(key_hash, latest_version)?.expect("UTXO not found");
    let utxo: UTXO = UTXOBytes(utxo_bytes.clone()).into(); // Remove clone if you can
    let utxo_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_bytes);
    warn!("  UTXO details:");
    warn!("    Value: {} sats", utxo.value);
    warn!("    Block height: {}", utxo.block_height);
    warn!("    Is coinbase: {}", utxo.is_coinbase);
    warn!("    Block time: {}", utxo.block_time);
    warn!(
        "    Script pubkey length: {} bytes",
        utxo.script_pubkey.len()
    );

    let (root_after_delete, deletion_proof, batch) = jmt.put_value_set_with_proof(
        [(key_hash, None)],
        latest_version + 1, // next version
    )?;
    warn!("Key: {:?}", utxo_key);
    warn!("Key hash: {:?}", key_hash);
    warn!("UTXO value hash: {:?}", utxo_value_hash);
    warn!("UTXO bytes: {:?}", utxo_bytes);
    warn!("UTXO: {:?}", utxo);
    warn!("Root after delete: {:?}", root_after_delete);
    warn!("Deletion proof: {:?}", deletion_proof);
    warn!("Batch: {:?}", batch);

    warn!("HOST: root after delete: {:?}", root_after_delete);
    storage.update_with_batch(root_after_delete, batch, latest_version + 1)?;

    let deletion_proof_to_borsh =
        borsh::to_vec(&deletion_proof).expect("Failed to serialize deletion proof");
    warn!("Deletion proof to borsh: {:?}", deletion_proof_to_borsh);

    let key_hash_from_borsh = borsh::from_slice::<KeyHash>(&deletion_proof_to_borsh[5..37])?;
    warn!("Key hash from borsh: {:?}", key_hash_from_borsh);
    let value_hash_from_borsh = borsh::from_slice::<ValueHash>(&deletion_proof_to_borsh[37..69])?;
    warn!("Value hash from borsh: {:?}", value_hash_from_borsh);

    assert_eq!(key_hash, key_hash_from_borsh);
    assert_eq!(utxo_value_hash, value_hash_from_borsh);

    // Verify UTXO is gone
    let (value_after_delete, noninclusion_proof_after_delete) =
        jmt.get_with_proof(key_hash, latest_version + 1)?;
    assert_eq!(value_after_delete, None);

    // We should use verify_nonexistence instead of verify_existence for a deleted UTXO
    assert!(noninclusion_proof_after_delete
        .verify_nonexistence(root_after_delete, key_hash)
        .is_ok());

    *prev_root_hash = root_after_delete;

    Ok((utxo, deletion_proof, root_after_delete))
}

pub fn insert_utxos_and_generate_update_proofs(
    storage: &RocksDbStorage,
    key_value_pairs: &[(KeyOutPoint, UTXO)],
    prev_root_hash: &mut RootHash,
) -> Result<UTXOInsertionUpdateProof> {
    let jmt = storage.get_jmt();
    info!("HOST: Called JMT");
    let latest_version = storage.get_latest_version()?;
    // let key_should_return_some = jmt.get(
    //     KeyHash([
    //         0x1d, 0xd1, 0x00, 0xb5, 0x71, 0xb2, 0xd7, 0xdc, 0xa6, 0xd9, 0x47, 0xbf, 0x94, 0x75,
    //         0x7a, 0xdf, 0x5d, 0x5e, 0xca, 0xe9, 0x29, 0x16, 0xf3, 0x20, 0x05, 0xcb, 0x9c, 0xdf,
    //         0xed, 0x28, 0x3d, 0xca,
    //     ]),
    //     latest_version,
    // )?;
    // info!("returned value: {:?}", key_should_return_some);

    let something = jmt.get_leaf_count(0);
    info!("leaf count at latest version - 1: {:?}", something);
    let something = jmt.get_leaf_count(latest_version);
    info!(
        "leaf count at latest version {:?}: {:?}",
        latest_version, something
    );
    let something = jmt.get_leaf_count(latest_version + 1);
    info!("leaf count at latest version + 1: {:?}", something);

    let something = jmt.get_root_hash(0);
    info!("root hash at version 0 {:?}", something);
    let something = jmt.get_root_hash(latest_version);
    warn!(
        "root hash at latest version {:?}: {:?}",
        latest_version, something
    );
    let something = jmt.get_root_hash(latest_version + 1);
    warn!("root hash at latest version + 1: {:?}", something);

    // Get the latest version of the tree
    let root_before_insert = storage.get_latest_root()?.unwrap_or(RootHash::from([
        83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76, 68,
        69, 82, 95, 72, 65, 83, 72, 95, 95,
    ]));
    assert_eq!(root_before_insert, *prev_root_hash);
    let latest_version = storage.get_latest_version()?;
    info!("  JMT State:");
    info!("    Latest root: {:?}", root_before_insert);
    info!("    Latest version: {}", latest_version);

    // Generate key hash from UTXO key using OutPointBytes
    let updates = key_value_pairs
        .iter()
        .map(|(utxo_key, utxo)| {
            let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
            let utxo_bytes = UTXOBytes::from(utxo.clone());
            (key_hash, Some(utxo_bytes.0.clone()))
        })
        .collect::<Vec<_>>();

    let (root_after_insert, insertion_proof, batch) = jmt.put_value_set_with_proof(
        updates.clone(),
        latest_version + 1, // next version
    )?;
    warn!("HOST: Values inserted, proof generated");
    warn!("HOST: root after insert: {:?}", root_after_insert);
    // warn!("HOST: Updates: {:?}", updates);
    // warn!("HOST: insertion_proof: {:?}", insertion_proof);
    storage.update_with_batch(root_after_insert, batch, latest_version + 1)?;

    let latest_version = storage.get_latest_version()?;
    let latest_root = storage.get_latest_root()?.unwrap_or(RootHash::from([
        83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76, 68,
        69, 82, 95, 72, 65, 83, 72, 95, 95,
    ]));
    assert_eq!(latest_root, root_after_insert);
    info!("  JMT State:");
    info!("    Latest root: {:?}", latest_root);
    info!("    Latest version: {}", latest_version);

    let insertion_proof_to_borsh =
        borsh::to_vec(&insertion_proof).expect("Failed to serialize insertion proof");

    let insertion_proof_copy: UpdateMerkleProof<Sha256> =
        borsh::from_slice(&insertion_proof_to_borsh)?;

    info!("HOST: previous root hash: {:?}", prev_root_hash);
    info!("HOST: root after insert: {:?}", root_after_insert);
    info!("HOST: Updates: {:?}", updates);
    info!("HOST: insertion_proof: {:?}", insertion_proof_copy);

    let something = jmt.get_leaf_count(0);
    info!("leaf count at latest version - 1: {:?}", something);
    let something = jmt.get_leaf_count(latest_version);
    info!(
        "leaf count at latest version {:?}: {:?}",
        latest_version, something
    );
    let something = jmt.get_leaf_count(latest_version + 1);
    info!("leaf count at latest version + 1: {:?}", something);

    let something = jmt.get_root_hash(0);
    info!("root hash at version 0 {:?}", something);
    let something = jmt.get_root_hash(latest_version);
    info!(
        "root hash at latest version {:?}: {:?}",
        latest_version, something
    );
    let something = jmt.get_root_hash(latest_version + 1);
    info!("root hash at latest version + 1: {:?}", something);

    // let default_root = RootHash::from([
    //     83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76,
    //     68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
    // ]);

    insertion_proof_copy
        .verify_update(root_before_insert, root_after_insert, updates.clone())
        .unwrap();

    info!("HOST: insertion_proof verified");

    *prev_root_hash = root_after_insert;

    Ok(UTXOInsertionUpdateProof {
        update_proof: insertion_proof,
        new_root: root_after_insert,
    })
}

#[cfg(test)]
mod tests {
    use crate::parse_block_from_file;

    #[test]
    fn test_read_blocks_from_file() -> Result<(), anyhow::Error> {
        // Loop from 0 to 80000 (inclusive), testing 80001 blocks in total
        for block_num in 0..=80000 {
            let block_path = format!(
                "../data/blocks/testnet4-blocks/testnet4_block_{}.bin",
                block_num
            );
            let _block = parse_block_from_file(&block_path)?;
        }
        println!("Successfully parsed all the blocks!");
        Ok(())
    }
}
