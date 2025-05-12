use std::{collections::VecDeque, env, fs, path::Path, thread, time::Duration};

use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin_consensus_core::{
    block::CircuitBlock,
    softfork_manager::BIPFlags,
    utxo_set::{KeyOutPoint, UTXO},
    BitcoinConsensusCircuitData, BitcoinConsensusCircuitInput, BitcoinConsensusCircuitOutput,
    BitcoinConsensusPrevProofType, UTXODeletionUpdateProof, UTXOInsertionUpdateProof,
};
use borsh::BorshDeserialize;
use host::{
    delete_utxo_and_generate_update_proof, insert_utxos_and_generate_update_proofs,
    parse_block_from_file, rocks_db::RocksDbStorage,
};
use jmt::RootHash;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

const BITCOIN_GUEST_ELF: &[u8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            include_bytes!("../../elfs/mainnet-bitcoin-guest.bin")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            include_bytes!("../../elfs/testnet4-bitcoin-guest.bin")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            include_bytes!("../../elfs/signet-bitcoin-guest.bin")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            include_bytes!("../../elfs/regtest-bitcoin-guest.bin")
        }
        None => include_bytes!("../../elfs/mainnet-bitcoin-guest.bin"),
        _ => panic!("Invalid path or ELF file"),
    }
};

const NETWORK: &str = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) => network,
        None => "mainnet",
    }
};

const DB_PATH: &str = "data/utxo_db";

fn main() -> Result<(), anyhow::Error> {
    // Initialize tracing with DEBUG level as default if RUST_LOG is not set
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(Level::DEBUG.to_string())),
        )
        .init();

    info!("Starting Bitcoin consensus proof generation");

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: <program> <input_proof> <output_file_prefix> <batch_size> <num_batches>");
        eprintln!("  input_proof: Path to previous proof file or 'None' to start from genesis");
        eprintln!("  output_file_prefix: Prefix for proof output files");
        eprintln!("  batch_size: Number of blocks to process in each batch");
        eprintln!("  num_batches: Number of batches to process sequentially");
        return Ok(());
    }

    let input_proof = &args[1];
    let output_file_prefix = &args[2];
    let batch_size: usize = args[3].parse().expect("Batch size should be a number");
    let num_batches: usize = args[4]
        .parse()
        .expect("Number of batches should be a number");

    info!("Starting multi-batch proof generation with parameters:");
    info!("  Initial input proof: {}", input_proof);
    info!("  Output file prefix: {}", output_file_prefix);
    info!("  Batch size: {}", batch_size);
    info!("  Number of batches: {}", num_batches);
    info!("  Network: {}", NETWORK);

    // Set up the database path
    let db_path = Path::new(DB_PATH);
    if !db_path.exists() {
        fs::create_dir_all(db_path)?;
    }
    info!("Using database at: {}", db_path.display());

    let bitcoin_guest_id: [u32; 8] = compute_image_id(BITCOIN_GUEST_ELF)
        .unwrap()
        .as_words()
        .try_into()
        .unwrap();
    info!("Computed guest program ID: {:?}", bitcoin_guest_id);

    // Initialize previous proof path
    let mut current_proof_path = String::from(input_proof);

    // Initialize the array to track previous 11 block times for median time past calculation
    let mut prev_11_blocks_time: [u32; 11] = [0; 11];

    // Main batch loop
    for batch_num in 1..=num_batches {
        info!("==================================================");
        info!("Processing batch {}/{}", batch_num, num_batches);
        info!("==================================================");

        // Generate output file path for this batch
        let current_start_block = if current_proof_path.to_lowercase() == "none" {
            0
        } else {
            // Try to extract previous block height to calculate current start
            if let Ok(prev_proof_bytes) = fs::read(&current_proof_path) {
                if let Ok(receipt) = Receipt::try_from_slice(&prev_proof_bytes) {
                    if let Ok(prev_output) =
                        BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes)
                    {
                        prev_output.bitcoin_state.header_chain_state.block_height + 1
                    } else {
                        // Fallback if we can't parse the output
                        (batch_num as u32 - 1) * batch_size as u32
                    }
                } else {
                    // Fallback if we can't parse the receipt
                    (batch_num as u32 - 1) * batch_size as u32
                }
            } else {
                // Fallback if we can't read the file
                (batch_num as u32 - 1) * batch_size as u32
            }
        };

        let end_block = current_start_block + batch_size as u32 - 1;
        let output_file_path = format!(
            "{}_{}_to_{}.bin",
            output_file_prefix, current_start_block, end_block
        );

        info!("Batch {} details:", batch_num);
        info!("  Input proof: {}", current_proof_path);
        info!("  Output file: {}", output_file_path);
        info!(
            "  Processing blocks: {} to {}",
            current_start_block, end_block
        );

        // Process this batch
        let result = process_batch(
            &current_proof_path,
            &output_file_path,
            batch_size,
            bitcoin_guest_id,
            &mut prev_11_blocks_time,
        )?;

        // Update for next iteration
        current_proof_path = output_file_path;

        info!("Batch {} completed successfully", batch_num);
        info!("  Final block height: {}", result.block_height);
        info!("  Final JMT root: {:?}", result.jmt_root);

        // Sleep for 2 seconds before starting the next batch
        if batch_num < num_batches {
            info!("Sleeping for 2 seconds before starting next batch...");
            thread::sleep(Duration::from_secs(2));
        }
    }

    info!("All batches completed successfully!");
    info!("Final proof file: {}", current_proof_path);

    Ok(())
}

// Result structure for returning process_batch information
struct BatchResult {
    block_height: u32,
    jmt_root: RootHash,
}

// Extracted batch processing logic
fn process_batch(
    input_proof: &str,
    output_file_path: &str,
    batch_size: usize,
    bitcoin_guest_id: [u32; 8],
    prev_11_blocks_time: &mut [u32; 11],
) -> Result<BatchResult, anyhow::Error> {
    // Set the previous proof type based on input_proof argument
    let prev_receipt = if input_proof.to_lowercase() == "none" {
        info!("Starting from genesis block");
        None
    } else {
        info!("Loading previous proof from: {}", input_proof);
        let proof_bytes = fs::read(input_proof)?;
        let receipt: Receipt = Receipt::try_from_slice(&proof_bytes)?;
        info!("Previous Receipt Journal: {:?}", receipt.journal);
        Some(receipt)
    };

    // Store previous block height for later verification
    let prev_block_height = if let Some(receipt) = &prev_receipt {
        let prev_output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes)?;
        Some(prev_output.bitcoin_state.header_chain_state.block_height)
    } else {
        None
    };

    let mut blocks = Vec::new();
    let storage = RocksDbStorage::new(DB_PATH)?;
    // Inspect database
    // storage.inspect_all()?;

    // JMT root hash for the UTXO set on the host side
    let mut current_root = storage.get_latest_root()?.unwrap_or_else(|| {
        RootHash::from([
            83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76,
            68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
        ])
    });
    info!("Current JMT root at the beginning: {:?}", current_root);
    let mut start = 0;
    let prev_proof = match prev_receipt.clone() {
        Some(receipt) => {
            let output =
                BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes.clone())?;
            start = output.bitcoin_state.header_chain_state.block_height as usize + 1;
            info!("Syncing local UTXO set with proof state...");
            info!(
                "  Previous block height: {}",
                output.bitcoin_state.header_chain_state.block_height
            );
            info!("  Starting from block: {}", start);
            let jmt_root = output.bitcoin_state.utxo_set_commitment.jmt_root;
            assert_eq!(
                jmt_root, current_root,
                "JMT root mismatch between guest and host - critical error"
            );
            info!("  UTXO JMT Root: {:?}", jmt_root);
            BitcoinConsensusPrevProofType::PrevProof(output)
        }
        None => {
            info!("Using genesis block as previous proof");
            BitcoinConsensusPrevProofType::GenesisBlock
        }
    };

    // Track UTXOs created in this batch (our cache)
    let mut batch_created_utxos: std::collections::BTreeMap<KeyOutPoint, UTXO> =
        std::collections::BTreeMap::new();
    let mut tx_proofs: VecDeque<UTXODeletionUpdateProof> = VecDeque::new();

    // prev_11_blocks_time is now passed as a parameter

    // Process blocks and track UTXO changes
    for i in start..start + batch_size {
        // We use the block height for the version of jmt to isolate the version
        warn!(
            "Processing block {} ({} of {})",
            i,
            i - start + 1,
            batch_size
        );
        let block_path = format!("data/blocks/{NETWORK}-blocks/{NETWORK}_block_{i}.bin");
        info!("  Reading block from: {}", block_path);
        let block = parse_block_from_file(&block_path)?;

        // Get BIP flags to determine if BIP113 is active
        let bip_flags = BIPFlags::at_height(i as u32);

        // Sort previous block times to calculate median time past
        let mut prev_block_mtp_vec = prev_11_blocks_time.clone();
        prev_block_mtp_vec.sort_by(|a, b| a.cmp(b));

        // Determine block time to use based on BIP113 activation
        let prev_block_mtp = if bip_flags.is_bip113_active() {
            info!("  BIP113 active - using median time past for block {}", i);
            prev_block_mtp_vec[5] // Median of the 11 previous blocks
        } else {
            info!(
                "  BIP113 inactive - using current block time for block {}",
                i
            );
            block.header.time
        };

        // Update our sliding window of previous block times
        prev_11_blocks_time[i % 11] = block.header.time;

        let circuit_block = CircuitBlock::from(block.clone());
        blocks.push(circuit_block.clone());

        // Process transactions
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            warn!(
                "  Processing transaction {}/{}: {}",
                tx_index,
                block.txdata.len(),
                tx.compute_txid()
            );

            for (input_index, input) in tx.input.iter().enumerate() {
                if input.previous_output.txid.to_byte_array() == [0; 32] {
                    warn!("    Skipping coinbase input {}", input_index);
                    continue;
                }

                let utxo_key = KeyOutPoint {
                    txid: input.previous_output.txid.to_byte_array(),
                    vout: input.previous_output.vout,
                };

                warn!(
                    "    Processing input {}/{}: {:?}:{}",
                    input_index,
                    tx.input.len(),
                    input.previous_output.txid,
                    input.previous_output.vout
                );

                // Check if this UTXO was created in our batch
                if batch_created_utxos.contains_key(&utxo_key) {
                    info!(
                        "    UTXO {:?}:{} was created and spent within this batch",
                        utxo_key.txid, utxo_key.vout
                    );
                    batch_created_utxos.remove(&utxo_key);
                } else {
                    // Generate inclusion proof for pre-existing UTXO
                    info!(
                        "    Deleting UTXO from the tree and generating deletion update proof for UTXO: {:?}:{}",
                        utxo_key.txid, utxo_key.vout
                    );
                    match delete_utxo_and_generate_update_proof(
                        &storage,
                        &utxo_key,
                        &mut current_root,
                    ) {
                        Ok((utxo, proof, next_root)) => {
                            let utxo_deletion_update_proof = UTXODeletionUpdateProof {
                                update_proof: proof,
                                utxo,
                                new_root: next_root,
                            };
                            current_root = next_root;
                            tx_proofs.push_back(utxo_deletion_update_proof)
                        }
                        Err(_) => {
                            error!(
                                "Failed to generate deletion proof for UTXO: {:?}:{}",
                                utxo_key.txid, utxo_key.vout
                            );
                        }
                    }
                }
            }

            // Process outputs (create new UTXOs)
            for (vout, output) in tx.output.iter().enumerate() {
                let utxo_key = KeyOutPoint {
                    txid: tx.compute_txid().to_byte_array(),
                    vout: vout as u32,
                };

                let is_coinbase = tx.input.len() == 1
                    && tx.input[0].previous_output.txid.to_byte_array() == [0; 32];

                let current_height = match prev_receipt.as_ref() {
                    Some(receipt) => {
                        let output = BitcoinConsensusCircuitOutput::try_from_slice(
                            &receipt.journal.bytes.clone(),
                        )?;
                        output.bitcoin_state.header_chain_state.block_height
                            + 1
                            + (i - start) as u32
                    }
                    None => i as u32,
                };

                let utxo = UTXO {
                    value: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                    block_height: current_height,
                    is_coinbase,
                    block_time: prev_block_mtp, // Use the MTP or current block time based on BIP113
                };

                // Add to our batch cache
                batch_created_utxos.insert(utxo_key, utxo.clone());
            }
        }
    }

    // Update UTXO set after processing all blocks
    info!(
        "Batch created UTXOs length: {:?}",
        batch_created_utxos.len()
    );
    info!("Batch created UTXOs: {:?}", batch_created_utxos);

    let key_value_pairs = batch_created_utxos
        .iter()
        .map(|(key, utxo)| (key.clone(), utxo.clone()))
        .collect::<Vec<(KeyOutPoint, UTXO)>>();

    let insertion_update_proofs: UTXOInsertionUpdateProof =
        insert_utxos_and_generate_update_proofs(
            &storage,
            key_value_pairs.as_ref(),
            &mut current_root,
        )?;

    // Prepare the input for the circuit
    let input_data = BitcoinConsensusCircuitData {
        blocks,
        utxo_deletion_update_proofs: tx_proofs,
        utxo_insertion_update_proofs: insertion_update_proofs,
    };

    info!("Input data prepared for circuit execution");
    info!("  Number of blocks: {}", input_data.blocks.len());
    info!(
        "  Number of UTXO deletion proofs: {}",
        input_data.utxo_deletion_update_proofs.len()
    );
    info!("  Current JMT root: {:?}", current_root);

    let input = BitcoinConsensusCircuitInput {
        method_id: bitcoin_guest_id,
        prev_proof,
        input_data,
    };

    // storage.inspect_all()?;

    // Build ENV
    info!("Building executor environment");
    let mut binding = ExecutorEnv::builder();
    let mut env = binding.write_slice(&borsh::to_vec(&input)?);
    if let Some(receipt) = prev_receipt {
        info!("Adding previous receipt to environment");
        env = env.add_assumption(receipt);
    }
    let env = env.build()?;

    // Obtain the default prover.
    info!("Creating prover");
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    info!("Starting proof generation");
    let receipt = prover.prove_with_opts(env, BITCOIN_GUEST_ELF, &ProverOpts::succinct())?;

    info!("Proof generation completed:");
    info!("  Total cycles: {}", receipt.stats.total_cycles);
    info!("  User cycles: {}", receipt.stats.user_cycles);
    info!("  Paging cycles: {}", receipt.stats.paging_cycles);
    info!("  Reserved cycles: {}", receipt.stats.reserved_cycles);
    info!("  Number of segments: {}", receipt.stats.segments);
    let receipt = receipt.receipt;
    info!("New Receipt Journal: {:?}", receipt.journal);

    // Extract journal of receipt
    let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes)?;

    info!("Circuit output details:");
    info!("  Method ID: {:?}", output.method_id);
    info!(
        "  Block height: {}",
        output.bitcoin_state.header_chain_state.block_height
    );
    info!(
        "  JMT Root: {:?}",
        output.bitcoin_state.utxo_set_commitment.jmt_root
    );

    // Verify root hash matches receipt
    info!("Verifying JMT root hash matches receipt");
    info!(
        "  Receipt JMT root: {:?}",
        output.bitcoin_state.utxo_set_commitment.jmt_root
    );
    info!(
        "  Receipt root hash bytes: {:?}",
        output.bitcoin_state.utxo_set_commitment.jmt_root.0
    );
    info!("  Local JMT root: {:?}", current_root);
    info!("  Local root hash bytes: {:?}", current_root.0);

    // If roots don't match, it means the guest program modified the UTXO set differently
    // than our local execution. In that case, we need to update our local set to match.
    if output.bitcoin_state.utxo_set_commitment.jmt_root != current_root {
        info!("JMT root mismatch between guest and host - updating local UTXO set to match");

        // In a production system, we would sync the local UTXO set with the verified one
        // For now, let's just assert that they should match
        assert_eq!(
            output.bitcoin_state.utxo_set_commitment.jmt_root, current_root,
            "JMT root mismatch between guest and host - critical error"
        );
    } else {
        info!("JMT root verification successful - roots match");
    }

    // Verify block height matches
    info!("Verifying block height matches receipt");
    info!(
        "  Receipt block height: {}",
        output.bitcoin_state.header_chain_state.block_height
    );
    let local_block_height = match prev_block_height {
        Some(height) => height + batch_size as u32,
        None => (batch_size - 1) as u32, // If genesis, height should be batch_size - 1
    };
    info!("  Local block height: {}", local_block_height);
    assert_eq!(
        output.bitcoin_state.header_chain_state.block_height, local_block_height,
        "Block height mismatch between guest and host"
    );
    info!("Block height verification successful - heights match");

    info!("Proof verification successful");

    // Save the receipt to the specified output file path
    info!("Saving receipt to: {}", output_file_path);
    let receipt_bytes = borsh::to_vec(&receipt)?;
    fs::write(output_file_path, &receipt_bytes)?;
    info!("Receipt saved successfully");

    // Return the batch result
    Ok(BatchResult {
        block_height: output.bitcoin_state.header_chain_state.block_height,
        jmt_root: output.bitcoin_state.utxo_set_commitment.jmt_root,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, env, fs, path::Path, thread, time::Duration};

    use bitcoin::hashes::Hash;
    use bitcoin_consensus_core::{
        bitcoin_consensus_circuit,
        block::CircuitBlock,
        softfork_manager::BIPFlags,
        utxo_set::{KeyOutPoint, UTXO},
        zkvm::ZKProof,
        BitcoinConsensusCircuitData, BitcoinConsensusCircuitInput, BitcoinConsensusCircuitOutput,
        BitcoinConsensusPrevProofType, UTXODeletionUpdateProof,
    };
    use borsh::BorshDeserialize;
    use host::{
        delete_utxo_and_generate_update_proof, insert_utxos_and_generate_update_proofs,
        mock_host::{MockZkvmHost, ZkvmHost},
        parse_block_from_file,
        rocks_db::RocksDbStorage,
    };
    use jmt::RootHash;
    use risc0_zkvm::{compute_image_id, Receipt};
    use std::time::Instant;
    use tempfile::{tempdir, TempDir};
    use tracing::{info, warn, Level};
    use tracing_subscriber::EnvFilter;

    use crate::{process_batch, BITCOIN_GUEST_ELF, DB_PATH, NETWORK};

    #[ignore = "This tests e2e and takes a long time to run"]
    #[test]
    fn test_bitcoin_consensus_guest() -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let value = env!("BITCOIN_NETWORK");
        // println!("Compile-time variable: {}", value);
        // Initialize tracing
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(Level::ERROR.to_string())),
            )
            .init();

        info!("Starting Bitcoin consensus proof testing with MockZkvmHost");

        // Create a temporary directory for the database
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("db");
        fs::create_dir_all(&db_path)?;
        info!("Using temporary database at: {}", db_path.display());

        // Define test parameters
        let mock_method_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let batch_size = 100; // Process 100 blocks per batch
        let num_batches = 800; // Run 800 batches
        let network = "testnet4"; // Using testnet for more predictable block sizes

        // Initialize RocksDB storage
        let storage = RocksDbStorage::new(db_path.to_str().unwrap())?;
        let mut current_root = storage.get_latest_root()?.unwrap_or_else(|| {
            RootHash::from([
                83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79,
                76, 68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
            ])
        });

        info!("Initial JMT root: {:?}", current_root);

        let mut current_prev_proof = BitcoinConsensusPrevProofType::GenesisBlock;
        let mut current_height = 0;

        let mut receipt: bitcoin_consensus_core::zkvm::ZKProof = ZKProof {
            method_id: mock_method_id,
            journal: vec![],
        };

        let mut prev_11_blocks_time: [u32; 11] = [0; 11];

        // Process batches
        for batch_num in 1..=num_batches {
            info!("==================================================");
            info!("Processing batch {}/{}", batch_num, num_batches);
            info!("==================================================");

            println!("Starting block height: {}", current_height);

            let mut blocks = Vec::new();
            let mut batch_created_utxos = std::collections::BTreeMap::new();
            let mut tx_proofs: VecDeque<UTXODeletionUpdateProof> = VecDeque::new();

            // Process blocks in this batch
            for i in current_height..current_height + batch_size as u32 {
                let bip_flags = BIPFlags::at_height(i);
                let block_path = format!("../data/blocks/{network}-blocks/{network}_block_{i}.bin");
                info!("Reading block from: {}", block_path);
                let mut prev_block_mtp_vec = prev_11_blocks_time.clone();
                prev_block_mtp_vec.sort_by(|a, b| a.cmp(b));

                // Parse the block from file (must exist for real test)
                let block = parse_block_from_file(&block_path)?;
                let circuit_block = CircuitBlock::from(block.clone());
                blocks.push(circuit_block.clone());

                let prev_block_mtp = if bip_flags.is_bip113_active() {
                    // println!("BIP113 active - using median time past");
                    // println!(
                    //     "Previous 11 blocks time: {:?}",
                    //     prev_block_mtp_vec
                    // );
                    prev_block_mtp_vec[5]
                } else {
                    // println!("BIP113 inactive - using block time");
                    block.header.time
                };

                prev_11_blocks_time[i as usize % 11] = block.header.time;

                // Process transactions for this block - follow the same logic as in the main code
                for (tx_index, tx) in block.txdata.iter().enumerate() {
                    warn!(
                        "Processing transaction {}/{}: {}",
                        tx_index,
                        block.txdata.len(),
                        tx.compute_txid()
                    );

                    // Process inputs (spend UTXOs)
                    for (input_index, input) in tx.input.iter().enumerate() {
                        if input.previous_output.txid.to_byte_array() == [0; 32] {
                            warn!("Skipping coinbase input {}", input_index);
                            continue;
                        }

                        let utxo_key = KeyOutPoint {
                            txid: input.previous_output.txid.to_byte_array(),
                            vout: input.previous_output.vout,
                        };

                        warn!(
                            "Processing input {}/{}: {:?}:{}",
                            input_index,
                            tx.input.len(),
                            input.previous_output.txid,
                            input.previous_output.vout
                        );

                        // Check if this UTXO was created in our batch
                        if batch_created_utxos.contains_key(&utxo_key) {
                            info!(
                                "UTXO {:?}:{} was created and spent within this batch",
                                utxo_key.txid, utxo_key.vout
                            );
                            batch_created_utxos.remove(&utxo_key);
                        } else {
                            // Generate deletion proof for pre-existing UTXO
                            match delete_utxo_and_generate_update_proof(
                                &storage,
                                &utxo_key,
                                &mut current_root,
                            ) {
                                Ok((utxo, proof, next_root)) => {
                                    let utxo_deletion_update_proof = UTXODeletionUpdateProof {
                                        update_proof: proof,
                                        utxo,
                                        new_root: next_root,
                                    };
                                    current_root = next_root;
                                    tx_proofs.push_back(utxo_deletion_update_proof);
                                }
                                Err(e) => {
                                    warn!(
                                    "Failed to generate deletion proof for UTXO: {:?}:{} - Error: {}",
                                    utxo_key.txid, utxo_key.vout, e
                                );
                                    // Continue processing - in a real test we might want to handle this case
                                }
                            }
                        }
                    }

                    // Process outputs (create new UTXOs)
                    for (vout, output) in tx.output.iter().enumerate() {
                        let utxo_key = KeyOutPoint {
                            txid: tx.compute_txid().to_byte_array(),
                            vout: vout as u32,
                        };

                        let is_coinbase = tx.input.len() == 1
                            && tx.input[0].previous_output.txid.to_byte_array() == [0; 32];

                        let current_height = i;

                        let utxo = UTXO {
                            value: output.value.to_sat(),
                            script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                            block_height: current_height,
                            is_coinbase,
                            block_time: prev_block_mtp,
                        };

                        // Add to our batch cache
                        batch_created_utxos.insert(utxo_key, utxo);
                    }
                }
            }

            // Insert new UTXOs and generate proofs
            info!(
                "Inserting {} new UTXOs into database",
                batch_created_utxos.len()
            );
            let key_value_pairs = batch_created_utxos
                .iter()
                .map(|(key, utxo)| (key.clone(), utxo.clone()))
                .collect::<Vec<(KeyOutPoint, UTXO)>>();

            let insertion_update_proofs = insert_utxos_and_generate_update_proofs(
                &storage,
                key_value_pairs.as_ref(),
                &mut current_root,
            )?;

            // Prepare the input data for the circuit
            let input_data = BitcoinConsensusCircuitData {
                blocks,
                utxo_deletion_update_proofs: tx_proofs,
                utxo_insertion_update_proofs: insertion_update_proofs,
            };

            info!("Input data prepared for circuit execution");
            info!("  Number of blocks: {}", input_data.blocks.len());
            info!(
                "  Number of UTXO deletion proofs: {}",
                input_data.utxo_deletion_update_proofs.len()
            );
            info!("  Current JMT root: {:?}", current_root);

            let input = BitcoinConsensusCircuitInput {
                method_id: mock_method_id,
                prev_proof: current_prev_proof.clone(),
                input_data,
            };

            // Create a new host instance for this batch
            let batch_host = MockZkvmHost::new();

            // Write the input to the host
            batch_host.write(&input);
            // println!("Input written to host");

            if batch_num > 1 {
                batch_host.add_assumption(receipt);
            }

            // Execute the consensus circuit
            info!("Executing Bitcoin consensus circuit");
            bitcoin_consensus_circuit(&batch_host);
            info!("Circuit execution completed");

            // Get the proof
            receipt = batch_host.prove(&mock_method_id);

            // Extract and verify the output
            let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal)?;

            info!("Circuit output details:");
            info!("  Method ID: {:?}", output.method_id);
            info!(
                "  Block height: {}",
                output.bitcoin_state.header_chain_state.block_height
            );
            info!(
                "  JMT Root: {:?}",
                output.bitcoin_state.utxo_set_commitment.jmt_root
            );

            // Verify JMT root matches
            info!("Verifying JMT root consistency:");
            info!(
                "  Receipt JMT root: {:?}",
                output.bitcoin_state.utxo_set_commitment.jmt_root
            );
            info!("  Local JMT root: {:?}", current_root);

            // Ensure roots match
            assert_eq!(
                output.bitcoin_state.utxo_set_commitment.jmt_root, current_root,
                "JMT root mismatch between guest and host"
            );

            // Verify block height is as expected
            let expected_height = match &current_prev_proof.clone() {
                BitcoinConsensusPrevProofType::GenesisBlock => batch_size as u32 - 1,
                BitcoinConsensusPrevProofType::PrevProof(prev) => {
                    prev.bitcoin_state.header_chain_state.block_height + batch_size as u32
                }
            };

            assert_eq!(
                output.bitcoin_state.header_chain_state.block_height, expected_height,
                "Block height mismatch"
            );

            // Update state for next batch
            current_prev_proof = BitcoinConsensusPrevProofType::PrevProof(output.clone());
            current_height = output.bitcoin_state.header_chain_state.block_height + 1; // Next block to process
            current_root = output.bitcoin_state.utxo_set_commitment.jmt_root;

            info!("Batch {} completed successfully", batch_num);
            info!(
                "  Final block height: {}",
                output.bitcoin_state.header_chain_state.block_height
            );
            info!("  Final JMT root: {:?}", current_root);
        }

        info!("All batches completed successfully!");
        info!("Final block height: {}", current_height - 1); // Adjust for the +1 above
        info!("Final JMT root: {:?}", current_root);

        let end = Instant::now();
        let duration = end.duration_since(start);

        println!("Test started at: {:?}", start);
        println!("Test ended at: {:?}", end);
        println!("Total duration: {:?}", duration);

        Ok(())
    }
}
