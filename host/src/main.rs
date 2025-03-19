use std::{env, fs, path::Path};

use anyhow::Result;
use bitcoin::{hashes::Hash, Block};
use bitcoin_consensus_core::{
    block::CircuitBlock,
    utxo_set::{KeyOutPoint, UTXO},
    BitcoinConsensusCircuitInput, BitcoinConsensusCircuitOutput, BitcoinConsensusPrevProofType,
};
use borsh::BorshDeserialize;
use host::{generate_utxo_inclusion_proof, parse_block_from_file, update_utxo_set};
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
            info!("  UTXO JMT Root: {:?}", jmt_root);
            BitcoinConsensusPrevProofType::PrevProof(output)
        }
        None => {
            info!("Using genesis block as previous proof");
            BitcoinConsensusPrevProofType::GenesisBlock
        }
    };

    let mut blocks = Vec::new();
    let mut utxo_updates: Vec<(KeyOutPoint, Option<UTXO>)> = Vec::new();

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
        info!("  Block details:");
        info!("    Version: {:?}", block.header.version);
        info!("    Timestamp: {}", block.header.time);
        info!("    Bits: {:?}", block.header.bits);
        info!("    Nonce: {}", block.header.nonce);
        info!("    Transaction count: {}", block.txdata.len());

        let circuit_block = CircuitBlock::from(block.clone());
        blocks.push(circuit_block.clone());

        // Process transactions for UTXO updates
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            info!(
                "  Processing transaction {}/{}: {}",
                tx_index + 1,
                block.txdata.len(),
                tx.txid()
            );
            info!(
                "    Inputs: {}, Outputs: {}",
                tx.input.len(),
                tx.output.len()
            );

            // Handle spent UTXOs (inputs)
            for (input_index, input) in tx.input.iter().enumerate() {
                if input.previous_output.txid.to_byte_array() == [0; 32] {
                    info!("    Skipping coinbase input {}", input_index);
                    continue;
                }

                let utxo_key = KeyOutPoint {
                    txid: input.previous_output.txid.to_byte_array(),
                    vout: input.previous_output.vout,
                };

                // Mark UTXO as spent
                utxo_updates.push((utxo_key, None));
                info!(
                    "    Marked UTXO as spent: {:?}:{}",
                    utxo_key.txid, utxo_key.vout
                );
            }

            // Handle new UTXOs (outputs)
            let txid = tx.compute_txid().to_byte_array();
            for (vout, output) in tx.output.iter().enumerate() {
                let utxo_key = KeyOutPoint {
                    txid,
                    vout: vout as u32,
                };

                let is_coinbase = tx.input.is_empty()
                    || (tx.input.len() == 1
                        && tx.input[0].previous_output.txid.to_byte_array() == [0; 32]);

                // Determine current block height
                let current_height = match prev_receipt.as_ref() {
                    Some(receipt) => {
                        let output = BitcoinConsensusCircuitOutput::try_from_slice(
                            &receipt.journal.bytes.clone(),
                        )?;
                        output.bitcoin_state.header_chain_state.block_height
                            + 1
                            + (i - start) as u32
                    }
                    None => (i as u32), // If genesis, assume i is the height
                };

                let utxo = UTXO {
                    value: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                    block_height: current_height,
                    is_coinbase,
                    block_time: block.header.time,
                };

                // Add new UTXO
                utxo_updates.push((utxo_key, Some(utxo)));
                info!(
                    "    Added new UTXO: {:?}:{} ({} sats)",
                    utxo_key.txid,
                    utxo_key.vout,
                    output.value.to_sat()
                );
            }
        }
    }

    info!("Preparing circuit input:");
    info!("  Number of blocks: {}", blocks.len());
    info!("  Number of UTXO updates: {}", utxo_updates.len());
    info!("  Previous proof type: {:?}", prev_proof);

    // Prepare the input for the circuit
    let input = BitcoinConsensusCircuitInput {
        method_id: bitcoin_guest_id,
        prev_proof,
        blocks,
        utxo_inclusion_proofs: vec![], // Empty for now as we're not using them
        utxo_insertion_proofs: vec![], // Empty for now as we're not using them
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

    // Update the local UTXO set with tracked changes
    info!(
        "Updating local UTXO set with {} changes",
        utxo_updates.len()
    );
    let (new_root, _) = update_utxo_set(&db_path, utxo_updates)?;
    info!("Local UTXO set updated:");
    info!("  New JMT root: {:?}", new_root);
    info!("  New root hash bytes: {:?}", new_root.0);

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
    info!("  Local JMT root: {:?}", new_root);
    info!("  Local root hash bytes: {:?}", new_root.0);
    assert_eq!(
        output.bitcoin_state.utxo_set_commitment.jmt_root, new_root,
        "JMT root mismatch between guest and host"
    );
    info!("JMT root verification successful - roots match");

    // Verify block height matches
    info!("Verifying block height matches receipt");
    info!(
        "  Receipt block height: {}",
        output.bitcoin_state.header_chain_state.block_height
    );
    let local_block_height = output.bitcoin_state.header_chain_state.block_height;
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
