use block::CircuitBlock;
use borsh::{BorshDeserialize, BorshSerialize};
use header_chain::NETWORK_CONSTANTS;
use serde::{Deserialize, Serialize};
use zkvm::ZkvmGuest;

pub mod block;
pub mod hashes;
pub mod header_chain;
pub mod merkle_tree;
pub mod transaction;
pub mod zkvm;

/// The input proof of the Bitcoin Consensus circuit.
/// The proof can be either None (implying the beginning) or a Succinct Risc0 proof.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum BitcoinConsensusPrevProofType {
    GenesisBlock,
    PrevProof(BitcoinConsensusCircuitOutput),
}
/// The input of the Bitcoin Consensus circuit.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitInput {
    pub method_id: [u32; 8],
    pub prev_proof: BitcoinConsensusPrevProofType,
    pub blocks: Vec<CircuitBlock>,
}

/// The output of the Bitcoin Consensus circuit.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitOutput {
    pub method_id: [u32; 8],
    pub bitcoin_state: BitcoinState,
}
// TODO: Add the BitcoinState struct definition here.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinState {
    pub block_height: u32,
    pub total_work: [u8; 32],
    pub best_block_hash: [u8; 32],
    pub current_target_bits: u32,
    pub epoch_start_time: u32,
    pub prev_11_timestamps: [u32; 11],
    pub utxo_set_commitment: [u8; 32], // TODO: Change this in the future.
}

impl BitcoinState {
    pub fn new() -> Self {
        BitcoinState {
            block_height: u32::MAX,
            total_work: [0u8; 32],
            best_block_hash: [0u8; 32],
            current_target_bits: NETWORK_CONSTANTS.max_bits,
            epoch_start_time: 0,
            prev_11_timestamps: [0u32; 11],
            utxo_set_commitment: [0u8; 32],
        }
    }
    pub fn verify_and_apply_blocks(&mut self, blocks: Vec<CircuitBlock>) {
        for block in blocks {
            todo!();
        }
    }
}

pub fn bitcoin_consensus_circuit(guest: &impl ZkvmGuest) {
    let start = risc0_zkvm::guest::env::cycle_count();

    let input: BitcoinConsensusCircuitInput = guest.read_from_host();
    let mut bitcoin_state = match input.prev_proof {
        BitcoinConsensusPrevProofType::GenesisBlock => BitcoinState::new(),
        BitcoinConsensusPrevProofType::PrevProof(prev_proof) => {
            assert_eq!(prev_proof.method_id, input.method_id);
            guest.verify(input.method_id, &prev_proof);
            prev_proof.bitcoin_state
        }
    };

    bitcoin_state.verify_and_apply_blocks(input.blocks);

    guest.commit(&BitcoinConsensusCircuitOutput {
        method_id: input.method_id,
        bitcoin_state,
    });
    let end = risc0_zkvm::guest::env::cycle_count();
    println!("Header chain circuit took {:?} cycles", end - start);
}
