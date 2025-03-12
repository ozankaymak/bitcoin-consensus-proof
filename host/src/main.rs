use bitcoin_consensus_core::{
    block::CircuitBlock, header_chain::CircuitBlockHeader, BitcoinConsensusCircuitInput,
    BitcoinConsensusCircuitOutput, BitcoinConsensusPrevProofType, utxo_set::{UTXOKey, UTXO},
};
use std::{env, fs, path::Path};

use borsh::BorshDeserialize;
use host::{parse_block_from_file, update_utxo_set, generate_utxo_inclusion_proof};
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};

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

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: <program> <input_proof> <output_file_path> <batch_size> [--db-path=<path>]");
        return;
    }

    let input_proof = &args[1];
    let output_file_path = &args[2];
    let batch_size: usize = args[3].parse().expect("Batch size should be a number");
    
    // Get the database path if provided, otherwise use a default
    let db_path = args.iter().find(|arg| arg.starts_with("--db-path="))
        .map(|arg| arg.trim_start_matches("--db-path="))
        .unwrap_or("./bitcoin_utxo_db");

    // Set up the database path
    let db_path = Path::new(db_path);
    if !db_path.exists() {
        fs::create_dir_all(db_path).expect("Failed to create database directory");
    }

    let bitcoin_guest_id: [u32; 8] = compute_image_id(BITCOIN_GUEST_ELF)
        .unwrap()
        .as_words()
        .try_into()
        .unwrap();

    // Set the previous proof type based on input_proof argument
    let prev_receipt = if input_proof.to_lowercase() == "none" {
        None
    } else {
        let proof_bytes = fs::read(input_proof).expect("Failed to read input proof file");
        let receipt: Receipt = Receipt::try_from_slice(&proof_bytes).unwrap();
        println!("Previous Receipt Journal: {:?}", receipt.journal);
        Some(receipt)
    };

    let mut start = 0;
    let prev_proof = match prev_receipt.clone() {
        Some(receipt) => {
            let output =
                BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes.clone())
                    .unwrap();
            start = output.bitcoin_state.header_chain_state.block_height as usize + 1;
            
            // Update our local UTXO database to match the state from the proof
            println!("Syncing local UTXO set with proof state...");
            let jmt_root = output.bitcoin_state.utxo_set_commitment.jmt_root;
            println!("UTXO JMT Root: {:?}", jmt_root);
            
            BitcoinConsensusPrevProofType::PrevProof(output)
        }
        None => BitcoinConsensusPrevProofType::GenesisBlock,
    };

    let mut blocks = Vec::new();
    
    // Process blocks and track UTXO changes
    let mut utxo_updates: Vec<(UTXOKey, Option<UTXO>)> = Vec::new();

    for i in start..start + batch_size {
        println!("Processing block {}", i);
        let block_path = format!("data/{NETWORK}-blocks/{NETWORK}_block_{i}.bin");
        let block = parse_block_from_file(&block_path);
        let circuit_block = CircuitBlock::from(block.clone());
        blocks.push(circuit_block.clone());
        
        // Process transactions for UTXO updates
        for tx in &block.txdata {
            // Handle spent UTXOs (inputs)
            for input in &tx.input {
                if input.previous_output.txid.to_byte_array() == [0; 32] {
                    // Skip coinbase inputs
                    continue;
                }
                
                let utxo_key = UTXOKey {
                    txid: input.previous_output.txid.to_byte_array(),
                    vout: input.previous_output.vout,
                };
                
                // Mark UTXO as spent
                utxo_updates.push((utxo_key, None));
            }
            
            // Handle new UTXOs (outputs)
            let txid = tx.compute_txid().to_byte_array();
            for (vout, output) in tx.output.iter().enumerate() {
                let utxo_key = UTXOKey {
                    txid,
                    vout: vout as u32,
                };
                
                let is_coinbase = tx.input.is_empty() || 
                    (tx.input.len() == 1 && tx.input[0].previous_output.txid.to_byte_array() == [0; 32]);
                
                // Determine current block height
                let current_height = match prev_receipt.as_ref() {
                    Some(receipt) => {
                        let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes.clone()).unwrap();
                        output.bitcoin_state.header_chain_state.block_height + 1 + (i - start) as u32
                    },
                    None => (i as u32) // If genesis, assume i is the height
                };
                
                let utxo = UTXO {
                    value: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                    block_height: current_height,
                    is_coinbase,
                };
                
                // Add new UTXO
                utxo_updates.push((utxo_key, Some(utxo)));
            }
        }
    }

    // Prepare the input for the circuit
    let input = BitcoinConsensusCircuitInput {
        method_id: bitcoin_guest_id,
        prev_proof,
        blocks,
    };

    // Build ENV
    let mut binding = ExecutorEnv::builder();
    let mut env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    if let Some(receipt) = prev_receipt {
        env = env.add_assumption(receipt);
    }
    let env = env.build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover
        .prove_with_opts(env, BITCOIN_GUEST_ELF, &ProverOpts::succinct())
        .unwrap();

    println!("New Receipt: {:?}", receipt.stats);
    let receipt = receipt.receipt;
    println!("New Receipt Journal: {:?}", receipt.journal);

    // Extract journal of receipt
    let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes).unwrap();

    println!("Output Method ID: {:?}", output.method_id);
    println!("Output JMT Root: {:?}", output.bitcoin_state.utxo_set_commitment.jmt_root);
    
    // Update the local UTXO set with tracked changes
    println!("Updating local UTXO set with {} changes...", utxo_updates.len());
    match update_utxo_set(db_path, utxo_updates) {
        Ok((new_root, proof)) => {
            println!("Updated UTXO set, new root: {:?}", new_root);
            println!("UTXO update proof generated");
            
            // Check if this matches the proof from zkVM
            if new_root == output.bitcoin_state.utxo_set_commitment.jmt_root {
                println!("UTXO root hash in receipt matches local computation! ✓");
            } else {
                println!("WARNING: UTXO root hash mismatch between receipt and local computation!");
                println!("  Receipt root: {:?}", output.bitcoin_state.utxo_set_commitment.jmt_root);
                println!("  Local root:   {:?}", new_root);
            }
        },
        Err(e) => {
            println!("Failed to update UTXO set: {}", e);
        }
    }

    // Save the receipt to the specified output file path
    let receipt_bytes = borsh::to_vec(&receipt).unwrap();
    fs::write(output_file_path, &receipt_bytes).expect("Failed to write receipt to output file");
    println!("Receipt saved to {}", output_file_path);
    
    // Example: Generate a proof for a specific UTXO if one was requested
    if let Some(arg) = args.iter().find(|arg| arg.starts_with("--prove-utxo=")) {
        let utxo_info = arg.trim_start_matches("--prove-utxo=");
        let parts: Vec<&str> = utxo_info.split(':').collect();
        
        if parts.len() == 2 {
            let txid_hex = parts[0];
            let vout: u32 = parts[1].parse().expect("Invalid vout");
            
            let mut txid = [0u8; 32];
            hex::decode_to_slice(txid_hex, &mut txid).expect("Invalid txid hex");
            
            let utxo_key = UTXOKey { txid, vout };
            
            match generate_utxo_inclusion_proof(db_path, &utxo_key) {
                Ok((utxo, proof)) => {
                    println!("UTXO Proof generated for {}:{}", txid_hex, vout);
                    println!("UTXO value: {} satoshis", utxo.value);
                    println!("Script length: {} bytes", utxo.script_pubkey.len());
                    
                    // Save the proof
                    let proof_path = format!("proofs/utxo_proof_{}_{}.bin", txid_hex, vout);
                    let proof_bytes = borsh::to_vec(&proof).unwrap();
                    fs::write(&proof_path, &proof_bytes).expect("Failed to write UTXO proof to file");
                    println!("UTXO proof saved to {}", proof_path);
                },
                Err(e) => {
                    println!("Failed to generate UTXO proof: {}", e);
                }
            }
        } else {
            println!("Invalid UTXO format. Expected --prove-utxo=<txid_hex>:<vout>");
        }
    }
}
