use std::{fs::File, io::Read, path::Path};

use anyhow::Result;
use bitcoin::Block;
use bitcoin_consensus_core::utxo_set::{KeyOutPoint, UTXO};
use jmt::{proof::UpdateMerkleProof, KeyHash, RootHash};
use jmt_host::rocks_db::RocksDbStorage;
use sha2::Sha256;

pub mod jmt_host;

// Parse a block from a binary file
pub fn parse_block_from_file(file_path: &str) -> Block {
    println!("Parsing block from file: {}", file_path);
    let mut file = File::open(file_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let block = bitcoin::consensus::deserialize(&buffer).unwrap();
    block
}

// Generate JMT proof of inclusion for a UTXO
pub fn generate_utxo_inclusion_proof(
    db_path: impl AsRef<Path>,
    utxo_key: &KeyOutPoint
) -> Result<(UTXO, UpdateMerkleProof<Sha256>)> {
    // Create RocksDB storage
    let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();
    
    // Get the latest version of the tree
    let latest_root = storage.get_latest_root()?.unwrap_or(RootHash::from([0u8; 32]));
    let latest_version = storage.get_latest_version()?;
    
    // Generate key hash from UTXO key
    let key_hash = KeyHash::with::<sha2::Sha256>(&[&utxo_key.txid[..], &utxo_key.vout.to_be_bytes()[..]].concat());
    
    // Get the UTXO value
    let utxo_bytes = jmt.get(key_hash, latest_version)?.expect("UTXO not found");
    let utxo = UTXO::from_bytes(&utxo_bytes);
    
    // Generate inclusion proof
    let proof = jmt.get_with_proof(key_hash, latest_version)?.1;
    
    // Create update proof for latest root
    let (_, update_proof, _) = jmt.put_value_set_with_proof(vec![], latest_version)?;
    
    // Generate range proof (useful for proving absence of double spends)
    let range_proof = jmt.get_range_proof(key_hash, key_hash, latest_version)?;
    
    // Create inclusion proof
    let inclusion_proof = UTXOInclusionProof {
        update_proof,
        proof,
        range_proof,
    };
    
    Ok((utxo, inclusion_proof))
}

// Update the UTXO set with a batch of changes and return the new root and update proof
pub fn update_utxo_set(
    db_path: impl AsRef<Path>,
    updates: Vec<(UTXOKey, Option<UTXO>)>
) -> Result<(RootHash, UTXOInclusionProof)> {
    // Create RocksDB storage
    let storage = jmt_host::storage::RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();
    
    // Get the latest version
    let latest_version = storage.get_latest_version()?;
    
    // Convert updates to JMT format
    let jmt_updates: Vec<(KeyHash, Option<Vec<u8>>)> = updates
        .iter()
        .map(|(key, utxo_opt)| {
            let key_hash = KeyHash::with::<sha2::Sha256>(&[&key.txid[..], &key.vout.to_be_bytes()[..]].concat());
            let value_opt = utxo_opt.as_ref().map(|utxo| utxo.to_bytes());
            (key_hash, value_opt)
        })
        .collect();
    
    // Apply updates with proof
    let (new_root, update_proof, batch) = jmt.put_value_set_with_proof(jmt_updates, latest_version + 1)?;
    
    // Get a range proof over the entire set (or over a specific range of keys)
    let range_proof = jmt.get_range_proof(
        KeyHash::with::<sha2::Sha256>(&[0u8; 32]),
        KeyHash::with::<sha2::Sha256>(&[0xFF; 32]),
        latest_version + 1
    )?;
    
    // Get an inclusion proof for the first key (if available)
    let (proof, key_hash) = if let Some((key, _)) = updates.first() {
        let key_hash = KeyHash::with::<sha2::Sha256>(&[&key.txid[..], &key.vout.to_be_bytes()[..]].concat());
        let (_, proof) = jmt.get_with_proof(key_hash, latest_version + 1)?;
        (proof, key_hash)
    } else {
        // If no updates, use a default proof
        (jmt.get_with_proof(KeyHash::with::<sha2::Sha256>(&[0u8; 32]), latest_version + 1)?.1, KeyHash::with::<sha2::Sha256>(&[0u8; 32]))
    };
    
    // Store the updates
    storage.update_with_batch(new_root, batch)?;
    storage.store_latest_version(latest_version + 1)?;
    
    // Create inclusion proof bundle
    let inclusion_proof = UTXOInclusionProof {
        update_proof,
        proof,
        range_proof,
    };
    
    Ok((new_root, inclusion_proof))
}
