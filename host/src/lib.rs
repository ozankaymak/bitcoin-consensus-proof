use std::{fs::File, io::Read, path::Path};

use anyhow::Result;
use bitcoin::Block;
use bitcoin_consensus_core::{
    utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO},
    TransactionUTXOProofs, TransactionUpdateProof, UTXOInsertionProof,
};
use jmt::{
    proof::{SparseMerkleProof, SparseMerkleRangeProof, UpdateMerkleProof},
    KeyHash, RootHash,
};
use jmt_host::rocks_db::RocksDbStorage;
use sha2::Sha256;
use tracing::{debug, error, info, warn};

pub mod jmt_host;

// Parse a block from a binary file
pub fn parse_block_from_file(file_path: &str) -> Result<Block, anyhow::Error> {
    info!("Parsing block from file: {}", file_path);
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    info!("  Read {} bytes from file", buffer.len());
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
pub fn generate_utxo_inclusion_proof(
    db_path: impl AsRef<Path>,
    utxo_key: &KeyOutPoint,
) -> Result<(UTXO, SparseMerkleProof<Sha256>)> {
    info!("Generating UTXO inclusion proof for key: {:?}", utxo_key);
    info!("  Database path: {}", db_path.as_ref().display());

    // Create RocksDB storage
    let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();

    // Get the latest version of the tree
    let latest_root = storage
        .get_latest_root()?
        .unwrap_or(RootHash::from([0u8; 32]));
    let latest_version = storage.get_latest_version()?;
    info!("  JMT State:");
    info!("    Latest root: {:?}", latest_root);
    info!("    Latest version: {}", latest_version);
    info!("    Root hash bytes: {:?}", latest_root.0);

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
    let utxo: UTXO = UTXOBytes(utxo_bytes).into();
    info!("  UTXO details:");
    info!("    Value: {} sats", utxo.value);
    info!("    Block height: {}", utxo.block_height);
    info!("    Is coinbase: {}", utxo.is_coinbase);
    info!("    Block time: {}", utxo.block_time);
    info!(
        "    Script pubkey length: {} bytes",
        utxo.script_pubkey.len()
    );

    // Generate inclusion proof
    info!("  Generating inclusion proof...");
    let (_, proof) = jmt.get_with_proof(key_hash, latest_version)?;
    info!("  Proof generated successfully");

    Ok((utxo, proof))
}

// Update the UTXO set with a batch of changes and return the new root and update proof
pub fn update_utxo_set(
    db_path: impl AsRef<Path>,
    updates: Vec<(KeyOutPoint, Option<UTXO>)>,
) -> Result<(RootHash, UTXOInclusioWithDeletionProof)> {
    info!("Updating UTXO set with {} changes", updates.len());
    info!("  Database path: {}", db_path.as_ref().display());

    // Create RocksDB storage
    let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();

    // Get the latest version
    let latest_version = storage.get_latest_version()?;
    let latest_root = storage
        .get_latest_root()?
        .unwrap_or(RootHash::from([0u8; 32]));
    info!("  Current JMT State:");
    info!("    Root: {:?}", latest_root);
    info!("    Version: {}", latest_version);
    info!("    Root hash bytes: {:?}", latest_root.0);

    // Convert updates to JMT format using helper structs
    info!("  Converting updates to JMT format...");
    let jmt_updates: Vec<(KeyHash, Option<Vec<u8>>)> = updates
        .iter()
        .map(|(key, utxo_opt)| {
            let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*key).as_ref());
            let value = utxo_opt
                .as_ref()
                .map(|utxo| UTXOBytes::from(utxo.clone()).as_ref().to_vec());
            (key_hash, value)
        })
        .collect();
    info!("  Update details:");
    info!("    Total updates: {}", jmt_updates.len());
    info!(
        "    Deletions: {}",
        jmt_updates.iter().filter(|(_, v)| v.is_none()).count()
    );
    info!(
        "    Insertions: {}",
        jmt_updates.iter().filter(|(_, v)| v.is_some()).count()
    );

    // Apply updates with proof
    info!("  Applying updates to JMT...");
    let (new_root, _, batch) =
        jmt.put_value_set_with_proof(jmt_updates.clone(), latest_version + 1)?;
    info!("  JMT Update Results:");
    info!("    New root: {:?}", new_root);
    info!("    New root hash bytes: {:?}", new_root.0);
    info!("    New version: {}", latest_version + 1);

    // Store the updates
    info!("  Storing updates in database...");
    info!("    Batch: {:?}", batch);
    storage.update_with_batch(new_root, batch)?;
    storage.store_latest_version(latest_version + 1)?;
    info!("  Database update completed");

    // Get inclusion proof for the first key (if any)
    let proof = if let Some((key_hash, _)) = jmt_updates.first() {
        info!("  Generating inclusion proof for first key:");
        info!("    Key hash: {:?}", key_hash);
        info!("    Key hash bytes: {:?}", key_hash.0);
        let (_, proof) = jmt.get_with_proof(*key_hash, latest_version + 1)?;
        info!("    Proof generated successfully");
        proof
    } else {
        info!("  No updates, generating empty proof");
        let dummy_key = KeyHash::with::<sha2::Sha256>(&[0u8; 32]);
        let (_, proof) = jmt.get_with_proof(dummy_key, latest_version + 1)?;
        proof
    };

    // Create inclusion proof bundle
    let inclusion_proof = UTXOInclusioWithDeletionProof { proof };
    info!("  Created inclusion proof bundle");

    Ok((new_root, inclusion_proof))
}

/// Generate UTXO deletion proofs for transaction inputs
pub fn generate_utxo_deletion_proofs(
    db_path: impl AsRef<Path>,
    inputs: &[(KeyOutPoint, UTXO)],
) -> Result<Vec<(SparseMerkleProof<Sha256>, UTXO, RootHash)>> {
    info!(
        "Generating UTXO deletion proofs for {} inputs",
        inputs.len()
    );
    info!("  Database path: {}", db_path.as_ref().display());

    // Create RocksDB storage
    let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();

    // Get the latest version
    let latest_version = storage.get_latest_version()?;
    let mut curr_root = storage
        .get_latest_root()?
        .unwrap_or(RootHash::from([0u8; 32]));
    info!("  Initial JMT State:");
    info!("    Root: {:?}", curr_root);
    info!("    Version: {}", latest_version);
    info!("    Root hash bytes: {:?}", curr_root.0);

    let mut proofs = Vec::new();

    // Generate proof for each input
    for (i, (key, utxo)) in inputs.iter().enumerate() {
        info!("  Processing input {}/{}:", i + 1, inputs.len());
        info!("    Key: {:?}", key);
        info!("    Transaction ID: {:?}", key.txid);
        info!("    Output index: {}", key.vout);
        info!("    UTXO details:");
        info!("      Value: {} sats", utxo.value);
        info!("      Block height: {}", utxo.block_height);
        info!("      Is coinbase: {}", utxo.is_coinbase);
        info!("      Block time: {}", utxo.block_time);
        info!(
            "      Script pubkey length: {} bytes",
            utxo.script_pubkey.len()
        );

        // Generate key hash
        let key_hash =
            KeyHash::with::<sha2::Sha256>(&[&key.txid[..], &key.vout.to_be_bytes()[..]].concat());
        info!("    Generated key hash: {:?}", key_hash);
        info!("    Key hash bytes: {:?}", key_hash.0);

        // Get inclusion proof
        info!("    Fetching current inclusion proof...");
        let (_, proof) = jmt.get_with_proof(key_hash, latest_version)?;
        info!("    Current inclusion proof retrieved");

        // Create update proof for deletion
        info!("    Creating deletion proof...");
        let (new_root, _, _) =
            jmt.put_value_set_with_proof(vec![(key_hash, None)], latest_version + 1)?;
        info!("    Deletion proof created:");
        info!("      New root: {:?}", new_root);
        info!("      New root hash bytes: {:?}", new_root.0);
        info!("      New version: {}", latest_version + 1);

        proofs.push((proof, utxo.clone(), new_root));
        curr_root = new_root;
    }

    info!("  Deletion proof generation completed:");
    info!("    Total proofs generated: {}", proofs.len());
    info!("    Final JMT root: {:?}", curr_root);
    info!("    Final root hash bytes: {:?}", curr_root.0);
    Ok(proofs)
}

/// Generate UTXO insertion proofs for transaction outputs
pub fn generate_utxo_insertion_proofs(
    db_path: impl AsRef<Path>,
    outputs: &[(KeyOutPoint, UTXO)],
) -> Result<Vec<UTXOInsertionProof>> {
    info!(
        "Generating UTXO insertion proofs for {} outputs",
        outputs.len()
    );
    info!("  Database path: {}", db_path.as_ref().display());

    // Create RocksDB storage
    let storage = RocksDbStorage::new(db_path)?;
    let jmt = storage.get_jmt();

    // Get the latest version
    let latest_version = storage.get_latest_version()?;
    let mut curr_root = storage
        .get_latest_root()?
        .unwrap_or(RootHash::from([0u8; 32]));
    info!("  Initial JMT State:");
    info!("    Root: {:?}", curr_root);
    info!("    Version: {}", latest_version);
    info!("    Root hash bytes: {:?}", curr_root.0);

    let mut proofs = Vec::new();

    // Generate proof for each output
    for (i, (key, utxo)) in outputs.iter().enumerate() {
        info!("  Processing output {}/{}:", i + 1, outputs.len());
        info!("    Key: {:?}", key);
        info!("    Transaction ID: {:?}", key.txid);
        info!("    Output index: {}", key.vout);
        info!("    UTXO details:");
        info!("      Value: {} sats", utxo.value);
        info!("      Block height: {}", utxo.block_height);
        info!("      Is coinbase: {}", utxo.is_coinbase);
        info!("      Block time: {}", utxo.block_time);
        info!(
            "      Script pubkey length: {} bytes",
            utxo.script_pubkey.len()
        );

        // Generate key hash
        let key_hash =
            KeyHash::with::<sha2::Sha256>(&[&key.txid[..], &key.vout.to_be_bytes()[..]].concat());
        info!("    Generated key hash: {:?}", key_hash);
        info!("    Key hash bytes: {:?}", key_hash.0);

        let utxo_bytes = utxo.to_bytes();
        info!("    UTXO serialization:");
        info!("      Raw bytes length: {} bytes", utxo_bytes.len());

        // Create update proof for insertion
        info!("    Creating insertion proof...");
        let (new_root, update_proof, _) = jmt.put_value_set_with_proof(
            vec![(key_hash, Some(utxo_bytes.clone()))],
            latest_version + 1,
        )?;
        info!("    Insertion proof created:");
        info!("      New root: {:?}", new_root);
        info!("      New root hash bytes: {:?}", new_root.0);
        info!("      New version: {}", latest_version + 1);

        proofs.push(UTXOInsertionProof {
            key: *key,
            update_proof,
            new_root,
        });
        curr_root = new_root;
    }

    info!("  Insertion proof generation completed:");
    info!("    Total proofs generated: {}", proofs.len());
    info!("    Final JMT root: {:?}", curr_root);
    info!("    Final root hash bytes: {:?}", curr_root.0);
    Ok(proofs)
}
