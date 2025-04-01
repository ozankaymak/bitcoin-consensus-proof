use std::{env, fs, path::Path};

use anyhow::Result;
use bitcoin::{hashes::Hash, Block};
use bitcoin_consensus_core::{
    block::CircuitBlock,
    utxo_set::{KeyOutPoint, UTXO},
    BitcoinConsensusCircuitInput, BitcoinConsensusCircuitOutput, BitcoinConsensusPrevProofType,
    TransactionUTXOProofs, UTXOInsertionProof,
};
use borsh::BorshDeserialize;
use host::jmt_host::rocks_db::RocksDbStorage;
use host::{
    generate_utxo_inclusion_proof, generate_utxo_insertion_proofs, parse_block_from_file,
    update_utxo_set,
};
use jmt::{proof::SparseMerkleProof, RootHash};
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

const BITCOIN_GUEST_ELF: &[u8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            include_bytes!("../../elfs/mainnet-bitcoin-guest")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            include_bytes!("../../elfs/testnet4-bitcoin-guest")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            include_bytes!("../../elfs/signet-bitcoin-guest")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            include_bytes!("../../elfs/regtest-bitcoin-guest")
        }
        None => include_bytes!("../../elfs/mainnet-bitcoin-guest"),
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
    // Initialize tracing with info level
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();
    info!("Starting Bitcoin consensus proof generation");

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: <program> <input_proof> <output_file_path> <batch_size>");
        return Ok(());
    }

    let input_proof = &args[1];
    let output_file_path = &args[2];
    let batch_size: usize = args[3].parse().expect("Batch size should be a number");
    info!("Starting proof generation with parameters:");
    info!("  Input proof: {}", input_proof);
    info!("  Output file: {}", output_file_path);
    info!("  Batch size: {}", batch_size);
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
    let mut block_utxo_inclusion_proofs = Vec::new();
    let mut utxos_for_insertion_proofs = Vec::new();
    let storage = RocksDbStorage::new(&db_path)?;
    let mut current_root = storage
        .get_latest_root()?
        .unwrap_or_else(|| RootHash::from([0; 32]));

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
    let mut batch_created_utxos: std::collections::HashMap<KeyOutPoint, UTXO> =
        std::collections::HashMap::new();
    // Track which UTXOs from our cache get spent
    let mut batch_spent_utxos: std::collections::HashSet<KeyOutPoint> =
        std::collections::HashSet::new();

    // Process blocks and track UTXO changes
    for i in start..start + batch_size {
        info!(
            "Processing block {} ({} of {})",
            i,
            i - start + 1,
            batch_size
        );
        let block_path = format!("data/blocks/{NETWORK}-blocks/{NETWORK}_block_{i}.bin");
        info!("  Reading block from: {}", block_path);
        let block = parse_block_from_file(&block_path)?;
        let circuit_block = CircuitBlock::from(block.clone());
        blocks.push(circuit_block.clone());

        let mut block_proofs = Vec::new();

        // Process transactions
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            info!(
                "  Processing transaction {}/{}: {}",
                tx_index + 1,
                block.txdata.len(),
                tx.compute_txid()
            );

            let mut tx_proofs = Vec::new();
            for (input_index, input) in tx.input.iter().enumerate() {
                if input.previous_output.txid.to_byte_array() == [0; 32] {
                    info!("    Skipping coinbase input {}", input_index);
                    tx_proofs.push(None);
                    continue;
                }

                let utxo_key = KeyOutPoint {
                    txid: input.previous_output.txid.to_byte_array(),
                    vout: input.previous_output.vout,
                };

                // Check if this UTXO was created in our batch
                if batch_created_utxos.contains_key(&utxo_key) {
                    info!(
                        "    UTXO {:?}:{} was created and spent within this batch",
                        utxo_key.txid, utxo_key.vout
                    );
                    batch_spent_utxos.insert(utxo_key);
                    tx_proofs.push(None);
                } else {
                    // Generate inclusion proof for pre-existing UTXO
                    info!(
                        "    Generating inclusion proof for UTXO: {:?}:{}",
                        utxo_key.txid, utxo_key.vout
                    );
                    match generate_utxo_inclusion_proof(&db_path, &utxo_key) {
                        Ok((utxo, proof)) => tx_proofs.push(Some((proof, utxo, current_root))),
                        Err(_) => tx_proofs.push(None),
                    }
                }
            }

            // Process outputs (create new UTXOs)
            for (vout, output) in tx.output.iter().enumerate() {
                let utxo_key = KeyOutPoint {
                    txid: tx.compute_txid().to_byte_array(),
                    vout: vout as u32,
                };

                let is_coinbase = tx.input.is_empty()
                    || (tx.input.len() == 1
                        && tx.input[0].previous_output.txid.to_byte_array() == [0; 32]);

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
                    block_time: block.header.time,
                };

                // Add to our batch cache
                batch_created_utxos.insert(utxo_key, utxo.clone());

                // Track for insertion proof
                utxos_for_insertion_proofs.push((utxo_key, utxo));
            }

            block_proofs.push(TransactionUTXOProofs {
                update_proof: tx_proofs,
                new_root: current_root,
            });
        }

        block_utxo_inclusion_proofs.push(block_proofs);
    }

    // Update UTXO set after processing all blocks
    let updates: Vec<(KeyOutPoint, Option<UTXO>)> = batch_created_utxos
        .iter()
        .filter(|(k, _)| !batch_spent_utxos.contains(k))
        .map(|(k, v)| (*k, Some(v.clone())))
        .collect();

    let (new_root, _) = update_utxo_set(&db_path, updates)?;
    current_root = new_root;
    info!("  Updated UTXO set - New root: {:?}", current_root);

    // Generate insertion proofs for surviving UTXOs
    info!("Generating insertion proofs for surviving UTXOs");
    let utxo_insertion_proofs = {
        let surviving_utxos: Vec<(KeyOutPoint, UTXO)> = utxos_for_insertion_proofs
            .iter()
            .filter(|(key, _)| !batch_spent_utxos.contains(key))
            .map(|(key, utxo)| (*key, utxo.clone()))
            .collect();

        if surviving_utxos.is_empty() {
            info!("  No insertion proofs needed - all UTXOs were spent");
            Vec::new()
        } else {
            info!(
                "  Generating insertion proofs for {} UTXOs",
                surviving_utxos.len()
            );
            generate_utxo_insertion_proofs(&db_path, &surviving_utxos)?
        }
    };

    info!("Proof generation completed:");
    info!(
        "  Inclusion proofs for {} blocks",
        block_utxo_inclusion_proofs.len()
    );
    info!("  Insertion proofs: {}", utxo_insertion_proofs.len());

    info!("Preparing circuit input:");
    info!("  Number of blocks: {}", blocks.len());
    info!(
        "  Number of UTXO updates: {}",
        utxos_for_insertion_proofs.len()
    );
    info!(
        "  Number of UTXO inclusion proofs: {}",
        block_utxo_inclusion_proofs.len()
    );
    info!(
        "  Number of UTXO insertion proofs: {}",
        utxo_insertion_proofs.len()
    );
    info!("  Previous proof type: {:?}", prev_proof);

    // Prepare the input for the circuit
    let input = BitcoinConsensusCircuitInput {
        method_id: bitcoin_guest_id,
        prev_proof,
        blocks,
        utxo_inclusion_proofs: block_utxo_inclusion_proofs,
        utxo_insertion_proofs,
    };

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

    Ok(())
}
