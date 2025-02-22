use core::{
    block::CircuitBlock, header_chain::CircuitBlockHeader, BitcoinConsensusCircuitInput,
    BitcoinConsensusCircuitOutput, BitcoinConsensusPrevProofType,
};
use std::{env, fs};

use borsh::BorshDeserialize;
use host::parse_block_from_file;
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
        eprintln!("Usage: <program> <input_proof> <output_file_path> <batch_size>");
        return;
    }

    let input_proof = &args[1];
    let output_file_path = &args[2];
    let batch_size: usize = args[3].parse().expect("Batch size should be a number");

    // let headers = HEADERS
    //     .chunks(80)
    //     .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
    //     .collect::<Vec<CircuitBlockHeader>>();

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
            BitcoinConsensusPrevProofType::PrevProof(output)
        }
        None => BitcoinConsensusPrevProofType::GenesisBlock,
    };

    let mut blocks = Vec::new();

    for i in start..start + batch_size {
        let block =
            parse_block_from_file(&format!("data/{NETWORK}-blocks/{NETWORK}_block_{i}.bin"));
        blocks.push(CircuitBlock::from(block));
    }

    // Prepare the input for the circuit
    let input = BitcoinConsensusCircuitInput {
        method_id: bitcoin_guest_id,
        prev_proof,
        // block_headers: headers[start..start + batch_size].to_vec(),
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

    println!("Output: {:#?}", output.method_id);

    // Save the receipt to the specified output file path
    let receipt_bytes = borsh::to_vec(&receipt).unwrap();
    fs::write(output_file_path, &receipt_bytes).expect("Failed to write receipt to output file");
    println!("Receipt saved to {}", output_file_path);
}
