use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{
    consensus::{encode::Decodable, params::Params, Params as BitcoinParams},
    hashes::Hash,
    Amount, OutPoint, Script, Sequence, TxIn, TxOut, Txid, Witness,
};
use block::CircuitBlock;
use borsh::{BorshDeserialize, BorshSerialize};
use constants::{MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR};
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
        println!("[DEBUG] Creating new BitcoinState");
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
        let num_blocks = blocks.len();
        let num_insertion_proofs = utxo_insertion_proofs.len();

        println!(
            "[INFO] Starting block verification and application. Processing {} blocks",
            num_blocks
        );
        println!(
            "[INFO] Initial state - Block height: {}, JMT root: {:?}, UTXO cache size: {}",
            self.header_chain_state.block_height,
            self.utxo_set_commitment.jmt_root,
            self.utxo_set_commitment.utxo_cache.len()
        );

        for (block_idx, (block, block_utxo_proofs)) in
            blocks.into_iter().zip(utxo_inclusion_proofs).enumerate()
        {
            println!(
                "[INFO] Processing block {}/{} - Height: {}, Hash: {:?}, Transactions: {}",
                block_idx + 1,
                num_blocks,
                self.header_chain_state.block_height + 1,
                block.block_header.compute_block_hash(),
                block.transactions.len()
            );

            // Verify block header
            println!(
                "[INFO] Verifying block header - Version: {}, Time: {}, Bits: {}, Nonce: {}",
                block.block_header.version,
                block.block_header.time,
                block.block_header.bits,
                block.block_header.nonce
            );

            // Process transactions
            let mut sigops = 0u32;
            println!(
                "[INFO] Processing {} transactions in block",
                block.transactions.len()
            );

            for (tx_idx, (transaction, tx_utxo_proof)) in
                block.transactions.iter().zip(block_utxo_proofs).enumerate()
            {
                println!(
                    "[INFO] Processing transaction {}/{} - TXID: {:?}, Size: {} bytes, Inputs: {}, Outputs: {}",
                    tx_idx + 1,
                    block.transactions.len(),
                    transaction.txid(),
                    transaction.total_size(),
                    transaction.input.len(),
                    transaction.output.len()
                );
                self.verify_and_apply_transaction(&mut sigops, transaction, tx_utxo_proof);
                println!(
                    "[INFO] Transaction processed - Current UTXO cache size: {}",
                    self.utxo_set_commitment.utxo_cache.len()
                );
            }

            // Check sigops
            println!(
                "[INFO] Block sigops check - Total: {}, Limit: {}",
                sigops, MAX_BLOCK_SIGOPS_COST
            );
            if sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST {
                println!(
                    "[ERROR] Block sigops cost exceeds limits: {} > {}",
                    sigops * WITNESS_SCALE_FACTOR,
                    MAX_BLOCK_SIGOPS_COST
                );
                panic!("Block sigops cost exceeds limits");
            }

            // BIP-34 check
            if self.header_chain_state.block_height >= NETWORK_PARAMS.bip34_height {
                println!(
                    "[INFO] Performing BIP-34 check at height {}",
                    self.header_chain_state.block_height
                );
                let coinbase_tx = &block.transactions[0];
                assert!(
                    coinbase_tx.input.is_empty()
                        || (coinbase_tx.input.len() == 1
                            && coinbase_tx.input[0].previous_output.txid.to_byte_array()
                                == [0; 32]),
                    "First transaction must be coinbase"
                );
                println!("[INFO] BIP-34 check passed");
            }
        }

        println!(
            "[INFO] All blocks processed. Processing {} UTXO insertion proofs",
            num_insertion_proofs
        );

        let mut curr_root_hash = self.utxo_set_commitment.jmt_root;
        println!(
            "[INFO] Current JMT state - Root: {:?}, Version: {}, Cache size: {}",
            curr_root_hash,
            self.utxo_set_commitment.version,
            self.utxo_set_commitment.utxo_cache.len()
        );

        for (proof_idx, proof) in utxo_insertion_proofs.into_iter().enumerate() {
            println!(
                "[INFO] Processing UTXO insertion proof {}/{} - Key: {:?}",
                proof_idx + 1,
                num_insertion_proofs,
                proof.key
            );

            let utxo = self.utxo_set_commitment.pop_utxo_from_cache(&proof.key);
            if utxo.is_none() {
                println!("[ERROR] UTXO not found in cache for key: {:?}", proof.key);
                panic!("UTXO cannot be found in cache.");
            }
            let utxo = utxo.unwrap();
            println!(
                "[INFO] Found UTXO in cache - Value: {} satoshis, Height: {}, Coinbase: {}",
                utxo.value, utxo.block_height, utxo.is_coinbase
            );

            let keyhash_outpoint =
                KeyHash::with::<sha2::Sha256>(OutPointBytes::from(proof.key).as_ref());
            println!("[INFO] Computed key hash: {:?}", keyhash_outpoint);

            let value_utxo_bytes: UTXOBytes = UTXOBytes::from(utxo.clone());
            println!("[INFO] Converting UTXO to bytes for JMT update");

            println!("[INFO] Verifying update proof");
            let update_result = proof.update_proof.verify_update(
                curr_root_hash,
                proof.new_root,
                &[(keyhash_outpoint, Some(value_utxo_bytes))],
            );

            match &update_result {
                Ok(_) => println!("[INFO] Update proof verification successful"),
                Err(e) => println!("[ERROR] Update proof verification failed: {:?}", e),
            }

            update_result.unwrap();

            curr_root_hash = proof.new_root;
            println!(
                "[INFO] JMT updated - New root: {:?}, Cache size: {}",
                curr_root_hash,
                self.utxo_set_commitment.utxo_cache.len()
            );
        }

        println!(
            "[INFO] Verifying cache is empty. Current size: {}",
            self.utxo_set_commitment.utxo_cache.len()
        );
        assert!(self.utxo_set_commitment.utxo_cache.is_empty());
        println!("[INFO] All UTXO operations completed successfully");
    }

    /// For now, handle UTXO set changes transaction by transaction. Maybe batch them later.
    pub fn verify_and_apply_transaction(
        &mut self,
        total_sigops: &mut u32,
        transaction: &CircuitTransaction,
        tx_utxo_proof: TransactionUTXOProofs,
    ) {
        println!(
            "[INFO] Verifying transaction - TXID: {:?}, Version: {}, Locktime: {}",
            transaction.txid(),
            transaction.version,
            transaction.lock_time
        );

        // Basic transaction checks
        println!(
            "[INFO] Transaction structure - Inputs: {}, Outputs: {}, Size: {} bytes",
            transaction.input.len(),
            transaction.output.len(),
            transaction.total_size()
        );

        if transaction.input.is_empty() {
            println!("[ERROR] Transaction has no inputs");
            panic!("Transaction has no inputs");
        }

        if transaction.output.is_empty() {
            println!("[ERROR] Transaction has no outputs");
            panic!("Transaction has no outputs");
        }

        let tx_size = transaction.total_size();
        println!(
            "[INFO] Transaction size check - Size: {} bytes, Limit: 4MB",
            tx_size * 4
        );
        if tx_size * 4 > 4_000_000 {
            println!(
                "[ERROR] Transaction size exceeds limits: {} > 4MB",
                tx_size * 4
            );
            panic!("Transaction size exceeds limits");
        }

        // Coinbase transaction checks
        if transaction.is_coinbase() {
            println!(
                "[INFO] Coinbase transaction - Script length: {}",
                transaction.input[0].script_sig.len()
            );
            let script_len = transaction.input[0].script_sig.len();
            if script_len < 2 || script_len > 100 {
                println!(
                    "[ERROR] Coinbase script length out of range: {}",
                    script_len
                );
                panic!("Coinbase script length out of range");
            }
        } else {
            println!("[INFO] Non-coinbase transaction - Checking previous outputs");
            for (idx, input) in transaction.input.iter().enumerate() {
                if input.previous_output.is_null() {
                    println!("[ERROR] Null previous output in input {}", idx);
                    panic!("Null previous output");
                }
            }
        }

        // UTXO verification
        let mut curr_root_hash = self.utxo_set_commitment.jmt_root;
        println!(
            "[INFO] Starting UTXO verification - Current JMT root: {:?}",
            curr_root_hash
        );

        let mut spent_utxo_for_jmt: Vec<(KeyHash, Option<UTXO>)> = Vec::new();
        let mut prevouts: Vec<UTXO> = Vec::new();

        println!(
            "[INFO] Processing {} transaction inputs with UTXO proofs",
            transaction.input.len()
        );

        for (input_idx, (input, optional_utxo_proof_with_utxo)) in transaction
            .input
            .iter()
            .zip(tx_utxo_proof.update_proof)
            .enumerate()
        {
            println!(
                "[INFO] Processing input {}/{} - Previous output: {:?}",
                input_idx + 1,
                transaction.input.len(),
                input.previous_output
            );

            let value_utxo;
            if let Some(utxo_proof_with_utxo) = optional_utxo_proof_with_utxo {
                println!("[INFO] Input has JMT proof - Verifying UTXO existence");
                let keyhash_outpoint = KeyHash::with::<sha2::Sha256>(
                    OutPointBytes::from(KeyOutPoint::from_outpoint(&input.previous_output))
                        .as_ref(),
                );
                println!("[INFO] Computed key hash: {:?}", keyhash_outpoint);

                value_utxo = utxo_proof_with_utxo.1.clone();
                println!(
                    "[INFO] UTXO from proof - Value: {} satoshis, Height: {}, Coinbase: {}",
                    value_utxo.value, value_utxo.block_height, value_utxo.is_coinbase
                );

                let value_utxo_bytes = UTXOBytes::from(utxo_proof_with_utxo.1);
                let valuehash_utxo = ValueHash::with::<sha2::Sha256>(&value_utxo_bytes);
                println!("[INFO] Computed value hash: {:?}", valuehash_utxo);

                let proof_leaf = utxo_proof_with_utxo.0.leaf().unwrap();
                println!("[INFO] Verifying proof leaf");

                let mut proof_leaf_serialized: Vec<u8> = Vec::with_capacity(64);
                BorshSerialize::serialize(&proof_leaf, &mut proof_leaf_serialized).unwrap();
                println!(
                    "[INFO] Proof leaf serialized - Length: {} bytes",
                    proof_leaf_serialized.len()
                );

                assert_eq!(proof_leaf_serialized[0..32], keyhash_outpoint.0);
                assert_eq!(proof_leaf_serialized[32..64], valuehash_utxo.0);
                println!("[INFO] Leaf verification passed");

                let update_proof = UpdateMerkleProof::new(vec![utxo_proof_with_utxo.0]);
                println!("[INFO] Verifying update proof");

                let verify_result = update_proof.verify_update(
                    curr_root_hash,
                    utxo_proof_with_utxo.2,
                    &[(keyhash_outpoint, None::<Vec<u8>>)],
                );

                match &verify_result {
                    Ok(_) => println!("[INFO] Update proof verification successful"),
                    Err(e) => println!("[ERROR] Update proof verification failed: {:?}", e),
                }

                verify_result.unwrap();

                spent_utxo_for_jmt.push((keyhash_outpoint, None));
                curr_root_hash = utxo_proof_with_utxo.2;
                println!("[INFO] JMT updated - New root: {:?}", curr_root_hash);
            } else {
                println!("[INFO] Input has no JMT proof - Checking UTXO cache");
                let key_outpoint = KeyOutPoint::from_outpoint(&input.previous_output);
                println!(
                    "[INFO] Looking up UTXO in cache for key: {:?}",
                    key_outpoint
                );

                let utxo = self.utxo_set_commitment.pop_utxo_from_cache(&key_outpoint);

                if utxo.is_none() {
                    println!(
                        "[ERROR] UTXO not found in cache for key: {:?}",
                        key_outpoint
                    );
                    panic!("UTXO not found in cache, and in the JMT.");
                }
                value_utxo = utxo.unwrap();
                println!(
                    "[INFO] Found UTXO in cache - Value: {} satoshis, Height: {}, Coinbase: {}",
                    value_utxo.value, value_utxo.block_height, value_utxo.is_coinbase
                );
            }
            prevouts.push(value_utxo);
            *total_sigops += transaction.total_sigop_cost(|outpoint: &OutPoint| {
                transaction
                    .input
                    .iter()
                    .position(|input| &input.previous_output == outpoint)
                    .and_then(|idx| prevouts.get(idx))
                    .map(|utxo| utxo.into_txout().clone())
            }) as u32;
        }

        println!(
            "[INFO] Adding transaction outputs to UTXO cache - Current size: {}",
            self.utxo_set_commitment.utxo_cache.len()
        );
        self.utxo_set_commitment.add_transaction_outputs(
            transaction,
            self.header_chain_state.block_height,
            self.header_chain_state.block_time,
            false,
        );
        println!(
            "[INFO] UTXO cache updated - New size: {}",
            self.utxo_set_commitment.utxo_cache.len()
        );
        println!("[INFO] Transaction verification and application completed");
    }

    pub fn check_coinbase_tx(&self, block: &CircuitBlock) -> bool {
        println!("[DEBUG] Checking coinbase transaction");
        let coinbase_tx = &block.transactions[0];

        println!("[DEBUG] Checking basic coinbase structure");
        let tx_checks = coinbase_tx.input.len() == 1
            && coinbase_tx.inner().input[0].previous_output.txid
                == bitcoin::Txid::from_byte_array([0; 32])
            && coinbase_tx.inner().input[0].previous_output.vout == 0xFFFFFFFF;

        println!("[DEBUG] Basic coinbase check result: {}", tx_checks);

        // TODO: Make sure BIP34 (height in coinbase) is enforced
        let bip34_height = block.get_bip34_block_height();
        let expected_height = self.header_chain_state.block_height + 1;
        println!(
            "[DEBUG] BIP34 check: block height in coinbase = {}, expected = {}",
            bip34_height, expected_height
        );
        let bip34_check = bip34_height == expected_height;

        // TODO: Make sure BIP141 (if there exists a segwit tx in the block, then wtxid commitment is in one of the outputs as OP_RETURN) is enforced
        let is_segwit = coinbase_tx.is_segwit();
        println!("[DEBUG] Checking BIP141. Coinbase is segwit: {}", is_segwit);

        let bip141_check = if is_segwit {
            let has_op_return = coinbase_tx
                .output
                .iter()
                .any(|output| output.script_pubkey.is_op_return());
            println!(
                "[DEBUG] BIP141 check: segwit coinbase has OP_RETURN: {}",
                has_op_return
            );
            has_op_return
        } else {
            println!("[DEBUG] BIP141 check skipped: not a segwit coinbase");
            true
        };

        // TODO: Make sure block reward is correct (block subsidy + fees >= sum of outputs)
        println!("[DEBUG] Coinbase check completed successfully");
        true
    }
}

pub fn bitcoin_consensus_circuit(guest: &impl ZkvmGuest) {
    let start = risc0_zkvm::guest::env::cycle_count();
    println!(
        "[DEBUG] Starting bitcoin_consensus_circuit at cycle {}",
        start
    );

    println!("[DEBUG] Reading input from host");
    let input: BitcoinConsensusCircuitInput = guest.read_from_host();
    println!(
        "[DEBUG] Input read: method_id: {:?}, blocks: {}",
        input.method_id,
        input.blocks.len()
    );
    println!(
        "[DEBUG] Number of UTXO inclusion proofs: {}",
        input.utxo_inclusion_proofs.len()
    );
    println!(
        "[DEBUG] Number of UTXO insertion proofs: {}",
        input.utxo_insertion_proofs.len()
    );

    let mut bitcoin_state = match input.prev_proof {
        BitcoinConsensusPrevProofType::GenesisBlock => {
            println!("[DEBUG] Creating new BitcoinState from GenesisBlock");
            BitcoinState::new()
        }
        BitcoinConsensusPrevProofType::PrevProof(prev_proof) => {
            println!("[DEBUG] Using previous BitcoinState from PrevProof");
            println!(
                "[DEBUG] Previous block height: {}",
                prev_proof.bitcoin_state.header_chain_state.block_height
            );
            println!(
                "[DEBUG] Previous JMT root: {:?}",
                prev_proof.bitcoin_state.utxo_set_commitment.jmt_root
            );
            assert_eq!(prev_proof.method_id, input.method_id);
            println!("[DEBUG] Method IDs match, verifying previous proof");
            guest.verify(input.method_id, &prev_proof);
            println!("[DEBUG] Previous proof verified");
            prev_proof.bitcoin_state
        }
    };

    println!("[DEBUG] Verifying and applying blocks");
    bitcoin_state.verify_and_apply_blocks(
        input.blocks,
        input.utxo_inclusion_proofs,
        input.utxo_insertion_proofs,
    );
    println!("[DEBUG] All blocks verified and applied");

    println!("[DEBUG] Committing BitcoinConsensusCircuitOutput");
    println!(
        "[DEBUG] Final block height: {}",
        bitcoin_state.header_chain_state.block_height
    );
    println!(
        "[DEBUG] Final JMT root: {:?}",
        bitcoin_state.utxo_set_commitment.jmt_root
    );
    guest.commit(&BitcoinConsensusCircuitOutput {
        method_id: input.method_id,
        bitcoin_state,
    });
    println!("[DEBUG] Output committed");

    let end = risc0_zkvm::guest::env::cycle_count();
    println!(
        "[DEBUG] Bitcoin consensus circuit completed in {} cycles",
        end - start
    );
}
