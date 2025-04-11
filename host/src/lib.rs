use std::{fs::File, io::Read, path::Path};

use anyhow::Result;
use bitcoin::Block;
use bitcoin_consensus_core::utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO};
use jmt::{proof::UpdateMerkleProof, KeyHash, RootHash, ValueHash};
use jmt_host::rocks_db::RocksDbStorage;
use sha2::Sha256;
use tracing::info;

pub mod jmt_host;

// Parse a block from a binary file
pub fn parse_block_from_file(file_path: &str) -> Result<Block, anyhow::Error> {
    info!("Parsing block from file: {}", file_path);
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    info!("  Read {} bytes from file", buffer.len());
    info!("  Buffer :{:?}", buffer);
    let block: Block = bitcoin::consensus::deserialize(&buffer)?;
    info!("  Block parsed successfully:");
    info!("    Hash: {:?}", block.block_hash());
    info!("    Version: {:?}", block.header.version);
    info!("    Previous block: {:?}", block.header.prev_blockhash);
    info!("    Merkle root: {:?}", block.header.merkle_root);
    info!("    Timestamp: {}", block.header.time);
    info!("    Bits: {:?}", block.header.bits);
    info!("    Nonce: {}", block.header.nonce);
    info!("    Transaction count: {}", block.txdata.len());
    Ok(block)
}

// Generate JMT proof of inclusion for a UTXO
pub fn delete_utxo_and_generate_update_proof(
    storage: &RocksDbStorage,
    utxo_key: &KeyOutPoint,
    prev_root_hash: &RootHash,
) -> Result<(UTXO, UpdateMerkleProof<Sha256>, RootHash)> {
    info!(
        "Generating UTXO deletion update proof for key: {:?}",
        utxo_key
    );
    // info!("  Database path: {}", db_path.as_ref().display());

    // Create RocksDB storage
    // let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();

    // Get the latest version of the tree
    let latest_root = storage
        .get_latest_root()?
        .unwrap_or(RootHash::from([0u8; 32]));
    assert_eq!(latest_root, *prev_root_hash);
    let latest_version = storage.get_latest_version()?;
    info!("  JMT State:");
    info!("    Latest root: {:?}", latest_root);
    info!("    Latest version: {}", latest_version);

    // Generate key hash from UTXO key using OutPointBytes
    let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
    info!("  Key details:");
    info!("    Transaction ID: {:?}", utxo_key.txid);
    info!("    Output index: {}", utxo_key.vout);
    info!("    Key hash: {:?}", key_hash);
    info!("    Key hash bytes: {:?}", key_hash.0);

    // Get the UTXO value
    info!("  Fetching UTXO from JMT...");
    let utxo_bytes = jmt.get(key_hash, latest_version)?.expect("UTXO not found");
    let utxo: UTXO = UTXOBytes(utxo_bytes.clone()).into(); // Remove clone if you can
    let utxo_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_bytes);
    info!("  UTXO details:");
    info!("    Value: {} sats", utxo.value);
    info!("    Block height: {}", utxo.block_height);
    info!("    Is coinbase: {}", utxo.is_coinbase);
    info!("    Block time: {}", utxo.block_time);
    info!(
        "    Script pubkey length: {} bytes",
        utxo.script_pubkey.len()
    );

    let (root_after_delete, deletion_proof, batch) = jmt.put_value_set_with_proof(
        [(key_hash, None)],
        latest_version + 1, // next version
    )?;

    let deletion_proof_to_borsh =
        borsh::to_vec(&deletion_proof).expect("Failed to serialize deletion proof");

    let key_hash_from_borsh = borsh::from_slice::<KeyHash>(&deletion_proof_to_borsh[5..37])?;
    info!("Key hash from borsh: {:?}", key_hash_from_borsh);
    let value_hash_from_borsh = borsh::from_slice::<ValueHash>(&deletion_proof_to_borsh[37..69])?;
    info!("Value hash from borsh: {:?}", value_hash_from_borsh);

    assert_eq!(key_hash, key_hash_from_borsh);
    assert_eq!(utxo_value_hash, value_hash_from_borsh);

    storage.update_with_batch(root_after_delete, batch)?;

    // Verify UTXO is gone
    let (value_after_delete, noninclusion_proof_after_delete) =
        jmt.get_with_proof(key_hash, latest_version + 1)?;
    assert_eq!(value_after_delete, None);

    // We should use verify_nonexistence instead of verify_existence for a deleted UTXO
    assert!(noninclusion_proof_after_delete
        .verify_nonexistence(root_after_delete, key_hash)
        .is_ok());

    Ok((utxo, deletion_proof, root_after_delete))
}

pub fn insert_utxo_and_generate_update_proof(
    storage: &RocksDbStorage,
    utxo_key: &KeyOutPoint,
    utxo: &UTXO,
    prev_root_hash: &RootHash,
) -> Result<(UpdateMerkleProof<Sha256>, RootHash)> {
    info!(
        "Generating UTXO insertion update proof for key: {:?}",
        utxo_key
    );
    // info!("  Database path: {}", db_path.as_ref().display());

    // Create RocksDB storage
    // let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();

    // Get the latest version of the tree
    let latest_root = storage
        .get_latest_root()?
        .unwrap_or(RootHash::from([0u8; 32]));
    assert_eq!(latest_root, *prev_root_hash);
    let latest_version = storage.get_latest_version()?;
    info!("  JMT State:");
    info!("    Latest root: {:?}", latest_root);
    info!("    Latest version: {}", latest_version);

    // Generate key hash from UTXO key using OutPointBytes
    let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*utxo_key).as_ref());
    info!("  Key details:");
    info!("    Transaction ID: {:?}", utxo_key.txid);
    info!("    Output index: {}", utxo_key.vout);
    info!("    Key hash: {:?}", key_hash);
    info!("    Key hash bytes: {:?}", key_hash.0);

    let utxo_bytes = UTXOBytes::from(utxo.clone());
    let utxo_value_hash = ValueHash::with::<sha2::Sha256>(&utxo_bytes);
    info!("  UTXO details:");
    info!("    Value: {} sats", utxo.value);
    info!("    Block height: {}", utxo.block_height);
    info!("    Is coinbase: {}", utxo.is_coinbase);
    info!("    Block time: {}", utxo.block_time);
    info!(
        "    Script pubkey length: {} bytes",
        utxo.script_pubkey.len()
    );
    info!("  UTXO serialization:");
    info!("    UTXOBytes: {:?}", utxo_bytes);
    info!("    Value hash: {:?}", utxo_value_hash);
    info!("    Value hash bytes: {:?}", utxo_value_hash.0);

    let (root_after_insert, insertion_proof, batch) = jmt.put_value_set_with_proof(
        [(key_hash, Some(utxo_bytes.0.clone()))],
        latest_version + 1, // next version
    )?;

    storage.update_with_batch(root_after_insert, batch)?;

    // Verify UTXO is inserted
    let (value_after_delete, inclusion_proof_after_insert) =
        jmt.get_with_proof(key_hash, latest_version + 1)?;
    assert_eq!(value_after_delete.unwrap(), utxo_bytes.0);

    assert!(inclusion_proof_after_insert
        .verify_existence(root_after_insert, key_hash, utxo_bytes.0)
        .is_ok());

    Ok((insertion_proof, root_after_insert))
}
