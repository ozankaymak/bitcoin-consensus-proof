use block::CircuitBlock;
use borsh::{BorshDeserialize, BorshSerialize};
use header_chain::HeaderChainState;
use serde::{Deserialize, Serialize};
use zkvm::ZkvmGuest;

pub mod bitcoin_merkle;
pub mod block;
pub mod hashes;
pub mod header_chain;
pub mod transaction;
pub mod utxo_set;
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
    pub header_chain_state: header_chain::HeaderChainState,
    pub utxo_set_commitment: utxo_set::UTXOSetState, // TODO: Change this in the future.
}

impl BitcoinState {
    pub fn new() -> Self {
        BitcoinState {
            header_chain_state: HeaderChainState::new(),
            utxo_set_commitment: utxo_set::UTXOSetState::new(),
        }
    }

    pub fn verify_and_apply_blocks(&mut self, blocks: Vec<CircuitBlock>) {
        for block in blocks {
            // Validate all transactions in the block.
            for transaction in &block.transactions {
                self.utxo_set_commitment
                    .verify_and_apply_transaction(transaction);
            }
            // Merkle root check.
            let mt = bitcoin_merkle::BitcoinMerkleTree::new(
                block.transactions.iter().map(|t| t.txid()).collect(),
            );
            assert_eq!(mt.root(), block.block_header.merkle_root);
            // Validate the block header.
            self.header_chain_state
                .verify_and_apply_header(block.block_header);

            // TODO: Coinbase transaction check. BIP-34: Height in coinbase.
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
