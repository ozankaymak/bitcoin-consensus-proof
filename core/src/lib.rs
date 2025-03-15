use std::collections::{BTreeMap, BTreeSet};

use bitcoin::key;
use bitcoin::{consensus::verify_transaction, hashes::Hash, Amount, Transaction};
use block::CircuitBlock;
use borsh::{BorshDeserialize, BorshSerialize};
use header_chain::HeaderChainState;
use jmt::{proof, ValueHash};
use jmt::{
    proof::{SparseMerkleLeafNode, SparseMerkleProof, UpdateMerkleProof},
    KeyHash, RootHash,
};
use params::NETWORK_PARAMS;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use transaction::CircuitTransaction;
use utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXO};
use zkvm::ZkvmGuest;

pub mod bitcoin_merkle;
pub mod block;
pub mod constants;
pub mod hashes;
pub mod header_chain;
pub mod params;
pub mod transaction;
pub mod utxo_set;
pub mod zkvm;

pub type NewRootAfterUTXODeletion = RootHash;
pub type NewRootAfterUTXOInsertion = RootHash;
pub type TransactionUpdateProof =
    Vec<Option<(SparseMerkleProof<Sha256>, UTXO, NewRootAfterUTXODeletion)>>;
pub type NewRootAfterTransaction = RootHash;

/// The input proof of the Bitcoin Consensus circuit.
/// The proof can be either None (implying the beginning) or a Succinct Risc0 proof.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum BitcoinConsensusPrevProofType {
    GenesisBlock,
    PrevProof(BitcoinConsensusCircuitOutput),
}
/// The input of the Bitcoin Consensus circuit.
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitInput {
    pub method_id: [u32; 8],
    pub prev_proof: BitcoinConsensusPrevProofType,
    pub blocks: Vec<CircuitBlock>,
    pub utxo_inclusion_proofs: Vec<Vec<TransactionUTXOProofs>>,
    pub utxo_insertion_proofs: Vec<UTXOInsertionProof>, // TODO: Maybe these two proofs can be combined into a Witness.
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct TransactionUTXOProofs {
    pub update_proof: TransactionUpdateProof,
    pub new_root: NewRootAfterTransaction,
    // pub spent_with_proof: BTreeMap<KeyOutPoint, UTXO>,
    // pub spent_from_cache: BTreeMap<KeyOutPoint, UTXO>, // No need, since we can check if a utxo is cached.
    // pub created: Vec<(KeyOutPoint, UTXO)>,
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOInsertionProof {
    pub key: KeyOutPoint,
    pub update_proof: UpdateMerkleProof<Sha256>,
    pub new_root: NewRootAfterUTXOInsertion,
    // pub spent_with_proof: BTreeMap<KeyOutPoint, UTXO>,
    // pub spent_from_cache: BTreeMap<KeyOutPoint, UTXO>, // No need, since we can check if a utxo is cached.
    // pub created: Vec<(KeyOutPoint, UTXO)>,
}

/// The output of the Bitcoin Consensus circuit.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitOutput {
    pub method_id: [u32; 8],
    pub bitcoin_state: BitcoinState,
}
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinState {
    pub header_chain_state: header_chain::HeaderChainState,
    pub utxo_set_commitment: utxo_set::UTXOSetGuest,
}

impl BitcoinState {
    pub fn new() -> Self {
        BitcoinState {
            header_chain_state: HeaderChainState::new(),
            utxo_set_commitment: utxo_set::UTXOSetGuest::new(),
        }
    }

    pub fn verify_and_apply_blocks(
        &mut self,
        blocks: Vec<CircuitBlock>,
        utxo_inclusion_proofs: Vec<Vec<TransactionUTXOProofs>>,
        utxo_insertion_proofs: Vec<UTXOInsertionProof>,
    ) {
        for (block, block_utxo_proofs) in blocks.iter().zip(utxo_inclusion_proofs) {
            // Check if the block is a segwit block
            let is_block_segwit = block.is_segwit();
            // Get the current block height
            // let validating_block_height = self.header_chain_state.block_height + 1;

            // Validate and apply the changes of the block header.
            self.header_chain_state
                .verify_and_apply_header(&block.block_header);

            // Merkle root check (txid).
            let txid_merkle_root = bitcoin_merkle::BitcoinMerkleTree::generate_root(
                block.transactions.iter().map(|t| t.txid()).collect(),
            );
            assert_eq!(txid_merkle_root, block.block_header.merkle_root);

            // Check size limits
            // First transaction must be coinbase, the rest must not be
            assert!(
                !block.is_empty(),
                "Block must contain at least one transaction"
            );
            assert!(
                block.transactions[0].is_coinbase(),
                "First transaction must be coinbase"
            );
            assert!(
                !block.transactions[1..].iter().any(|tx| tx.is_coinbase()),
                "Multiple coinbase transactions in block"
            );

            assert!(block.is_valid_size(), "Block size exceeds limits");

            // HERE TODO: Check sigops limits: https://github.com/bitcoin/bitcoin/blob/4637cb1eec48d1af8d23eeae1bb4c6f8de55eed9/src/validation.cpp#L4097
            // let mut sigops = 0;
            // for tx in &block.transactions {
            //     sigops += tx.total_sigop_cost(spent_utxos);
            //     assert!(sigops <= NETWORK_PARAMS.max_block_sigops, "Block exceeds sigops limit");
            // }

            // Validate all transactions in the block.
            for (transaction, tx_utxo_proof) in block.transactions.iter().zip(block_utxo_proofs) {
                self.verify_and_apply_transaction(transaction, tx_utxo_proof);
            }

            // BIP-34: Check height in coinbase
            if self.header_chain_state.block_height >= NETWORK_PARAMS.bip34_height {
                let coinbase_tx = &block.transactions[0];
                // Ensure the first transaction is a coinbase
                assert!(
                    coinbase_tx.input.is_empty()
                        || (coinbase_tx.input.len() == 1
                            && coinbase_tx.input[0].previous_output.txid.to_byte_array()
                                == [0; 32]),
                    "First transaction must be coinbase"
                );

                // // Extract and verify block height from coinbase script
                // let coinbase_script = &coinbase_tx.input[0].script_sig.as_bytes();
                // assert!(!coinbase_script.is_empty(), "Coinbase script cannot be empty");

                // // First byte must be length of height serialization
                // let height_len = coinbase_script[0] as usize;
                // assert!(height_len >= 1 && height_len <= 5, "Invalid height length in coinbase");
                // assert!(coinbase_script.len() > height_len, "Coinbase script too short");

                // // Extract the height bytes
                // let height_bytes = &coinbase_script[1..=height_len];
                // let mut height_value = 0u32;

                // // Parse little-endian encoded height
                // for (i, &byte) in height_bytes.iter().enumerate() {
                //     height_value |= (byte as u32) << (8 * i);
                // }

                // assert_eq!(height_value, block_height, "Block height mismatch in coinbase script");
            }
        }
        let mut curr_root_hash = self.utxo_set_commitment.jmt_root;
        for proof in utxo_insertion_proofs {
            let utxo = self.utxo_set_commitment.pop_utxo_from_cache(&proof.key); // Should not error since we should have this utxo in the cache.
            if utxo.is_none() {
                panic!("UTXO cannot be found in cache.");
            }
            let utxo = utxo.unwrap();
            let keyhash_outpoint =
                KeyHash::with::<sha2::Sha256>(OutPointBytes::from(proof.key).as_ref());
            let value_utxo_bytes: UTXOBytes = UTXOBytes::from(utxo.clone());
            // let valuehash_utxo = ValueHash::with::<sha2::Sha256>(&value_utxo_bytes);
            proof
                .update_proof
                .verify_update(
                    curr_root_hash,
                    proof.new_root,
                    &[(keyhash_outpoint, Some(value_utxo_bytes))],
                )
                .unwrap(); // Updates must be (KeyOutPoint, Some<Value>)
            curr_root_hash = proof.new_root;
        }
        // Make sure cache is empty
        assert!(self.utxo_set_commitment.utxo_cache.is_empty());
    }

    /// For now, handle UTXO set changes transaction by transaction. Maybe batch them later.
    pub fn verify_and_apply_transaction(
        &mut self,
        transaction: &CircuitTransaction,
        tx_utxo_proof: TransactionUTXOProofs,
    ) {
        let txid = transaction.txid(); // TODO: We already calculate this for merkle root check, find a way to reuse it.
                                       // 1. Check transaction: https://github.com/bitcoin/bitcoin/blob/4637cb1eec48d1af8d23eeae1bb4c6f8de55eed9/src/consensus/tx_check.cpp#L11
                                       // 1a. Basic checks
        if transaction.input.is_empty() {
            panic!("Transaction has no inputs");
        }
        if transaction.output.is_empty() {
            panic!("Transaction has no outputs");
        }
        // 1b. Size limits
        if transaction.base_size() * 4 > 4_000_000 {
            // 4_000_000 is the maximum block weight.
            panic!("Transaction size exceeds limits");
        }

        // 1c. Check for negative or overflow output values
        let mut total_output_value: Amount = Amount::ZERO;
        for output in &transaction.output {
            // This check is unnecessary because the value is a u64
            // if output.value < 0 {
            //     panic!("Negative output value");
            // }
            if output.value > Amount::MAX_MONEY {
                panic!("Output value exceeds maximum money");
            }
            total_output_value += output.value;
        }
        // This check is taken outside the for loop for efficiency
        if total_output_value > Amount::MAX_MONEY {
            panic!("Total output value exceeds maximum money");
        }

        // 1d. Check for duplicate inputs
        let mut tx_inputs_set = BTreeSet::new();
        for input in &transaction.input {
            if !tx_inputs_set.insert(input.previous_output) {
                panic!("Duplicate inputs");
            }
        }

        // 1e. Some more checks
        if transaction.is_coinbase() {
            if transaction.input[0].script_sig.len() < 2
                || transaction.input[0].script_sig.len() > 100
            {
                panic!("Coinbase script length out of range");
            }
        } else {
            for input in &transaction.input {
                if input.previous_output.is_null() {
                    panic!("Null previous output");
                }
            }
        }

        // 2. Verify transaction inputs
        // TODO: First verify inclusion of the PrevOuts, then verify the transaction, then create the new UTXOs
        let mut curr_root_hash = self.utxo_set_commitment.jmt_root;
        let mut spent_utxo_for_jmt: Vec<(KeyHash, Option<UTXO>)> = Vec::new();
        let mut prevouts: Vec<UTXO> = Vec::new();
        for (input, optional_utxo_proof_with_utxo) in
            transaction.input.iter().zip(tx_utxo_proof.update_proof)
        {
            let value_utxo;
            if let Some(utxo_proof_with_utxo) = optional_utxo_proof_with_utxo {
                // If this UTXO is not in the cache, meaning it is created before this block.
                // let utxo_leaf = utxo_proof_with_utxo.0.leaf().unwrap(); // Should not error since we should have this utxo in the jmt.
                let keyhash_outpoint = KeyHash::with::<sha2::Sha256>(
                    OutPointBytes::from(KeyOutPoint::from_outpoint(&input.previous_output))
                        .as_ref(),
                );
                value_utxo = utxo_proof_with_utxo.1.clone(); // TODO: Remove clone
                let value_utxo_bytes = UTXOBytes::from(utxo_proof_with_utxo.1);
                let valuehash_utxo = ValueHash::with::<sha2::Sha256>(&value_utxo_bytes); // TODO: This might be just value, not value hash. Check.
                let proof_leaf = utxo_proof_with_utxo.0.leaf().unwrap(); // Should not error since we should have this utxo in the jmt.
                let mut proof_leaf_serialized: Vec<u8> = Vec::with_capacity(64);
                BorshSerialize::serialize(&proof_leaf, &mut proof_leaf_serialized).unwrap();
                assert_eq!(proof_leaf_serialized[0..32], keyhash_outpoint.0);
                assert_eq!(proof_leaf_serialized[32..64], valuehash_utxo.0);
                let update_proof = UpdateMerkleProof::new(vec![utxo_proof_with_utxo.0]);
                update_proof
                    .verify_update(
                        curr_root_hash,
                        utxo_proof_with_utxo.2,
                        &[(keyhash_outpoint, None::<Vec<u8>>)],
                    )
                    .unwrap();
                spent_utxo_for_jmt.push((keyhash_outpoint, None));
                curr_root_hash = utxo_proof_with_utxo.2;
            } else {
                // If this UTXO is in the cache, meaning it is created in this block.
                let utxo = self
                    .utxo_set_commitment
                    .pop_utxo_from_cache(&KeyOutPoint::from_outpoint(&input.previous_output)); // Should not error since we should have this utxo in the cache.
                if utxo.is_none() {
                    panic!("UTXO not found in cache, and in the JMT.");
                }
                value_utxo = utxo.unwrap();
            }
            prevouts.push(value_utxo);
        }
        // tx_utxo_proof.update_proof.verify_update(curr_root_hash, tx_utxo_proof.new_root, spent_utxo_for_jmt).unwrap(); // Updates must be (KeyOutPoint, None) since we are only verifying the spent UTXOs.
        // verify_transaction(transaction, spent); // TODO: Implement this function, using prevouts.
        self.utxo_set_commitment.add_transaction_outputs(
            transaction,
            self.header_chain_state.block_height,
            false,
        );
    }

    pub fn check_coinbase_tx(&self, block: &CircuitBlock) -> bool {
        let coinbase_tx = &block.transactions[0];
        let tx_checks = coinbase_tx.input.len() == 1
            && coinbase_tx.inner().input[0].previous_output.txid
                == bitcoin::Txid::from_byte_array([0; 32])
            && coinbase_tx.inner().input[0].previous_output.vout == 0xFFFFFFFF;
        // TODO: Make sure BIP34 (height in coinbase) is enforced
        let bip34_check =
            block.get_bip34_block_height() == self.header_chain_state.block_height + 1;
        // TODO: Make sure BIP141 (if there exists a segwit tx in the block, then wtxid commitment is in one of the outputs as OP_RETURN) is enforced
        let bip141_check = match coinbase_tx.is_segwit() {
            true => coinbase_tx
                .output
                .iter()
                .any(|output| output.script_pubkey.is_op_return()),
            false => true,
        };
        // TODO: Make sure block reward is correct (block subsidy + fees >= sum of outputs)
        true
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

    bitcoin_state.verify_and_apply_blocks(
        input.blocks,
        input.utxo_inclusion_proofs,
        input.utxo_insertion_proofs,
    );

    guest.commit(&BitcoinConsensusCircuitOutput {
        method_id: input.method_id,
        bitcoin_state,
    });
    let end = risc0_zkvm::guest::env::cycle_count();
    println!("Header chain circuit took {:?} cycles", end - start);
}
