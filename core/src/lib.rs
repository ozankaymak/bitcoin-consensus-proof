use core::panic;
use std::collections::{BTreeMap, VecDeque};
use std::vec;

use bitcoin::hashes::hash160;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder;
use bitcoin::taproot::{ControlBlock, LeafVersion};
/// # Bitcoin Consensus Proof Core Library
///
/// This library implements Bitcoin's consensus rules in a manner compatible with
/// zero-knowledge proof circuits. It allows for the cryptographic verification of
/// Bitcoin blocks and transactions without revealing the full blockchain data.
///
/// ## Key Components
///
/// The library provides:
///
/// - A circuit-compatible implementation of Bitcoin's consensus rules
/// - UTXO set management using Jellyfish Merkle Trees
/// - Block and transaction validation
/// - Proof structures for efficiently verifying blockchain state
/// - Support for SegWit, timelocks, and other Bitcoin features
///
/// ## Architecture
///
/// The implementation follows a modular design with components for:
///
/// 1. **Block Validation**: Verifying block structure, proof-of-work, and timestamps
/// 2. **Transaction Validation**: Checking signatures, scripts, and transaction rules
/// 3. **UTXO Management**: Tracking unspent transaction outputs efficiently
/// 4. **State Transitions**: Applying validated blocks to the blockchain state
/// 5. **Proof Generation/Verification**: Creating and checking cryptographic proofs
///
/// This library is designed to run within a zero-knowledge virtual machine (ZKVM)
/// to produce succinct proofs of Bitcoin consensus rule adherence.
use bitcoin::{hashes::Hash, OutPoint};
use bitcoin::{PubkeyHash, ScriptBuf, TapLeafHash, Witness, XOnlyPublicKey};
use block::CircuitBlock;
use borsh::{BorshDeserialize, BorshSerialize};
use constants::{MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR};
use header_chain::HeaderChainState;
use jmt::{proof::UpdateMerkleProof, KeyHash, RootHash};
use jmt::{SimpleHasher, ValueHash};
use script::txout::get_txout_type;
use script::{Exec, ExecCtx, Options, TxTemplate};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use transaction::CircuitTransaction;
use utxo_set::{KeyOutPoint, OutPointBytes, UTXOBytes, UTXOSetGuest, UTXO};
use witness::{
    get_non_standard_witness, get_p2pk_witness, get_p2pkh_witness,
    get_wrapped_p2sh_witness_and_redeem_script, split_p2sh_witness_and_redeem_script,
};
use zkvm::ZkvmGuest;

/// Bitcoin Merkle tree implementation (transaction hashing, block commitments)
pub mod bitcoin_merkle;
/// Block structure and validation
pub mod block;
/// Bitcoin protocol constants
pub mod constants;
/// Cryptographic hash function implementations
pub mod hashes;
/// Block header chain verification
pub mod header_chain;
/// Network parameters for different Bitcoin networks
pub mod params;
/// Transaction structure and validation
pub mod transaction;
/// UTXO set management
pub mod utxo_set;
/// Zero-knowledge virtual machine interface
pub mod zkvm;

pub mod script;

pub mod softfork_manager;

pub mod witness;

pub const OPTIONS: Options = Options {
    require_minimal: false,
    verify_cltv: true,
    verify_csv: true,
    verify_minimal_if: false,
    enforce_stack_limit: true,
};

/// Previous proof type for the Bitcoin consensus circuit
///
/// This enum represents the previous state for a Bitcoin consensus verification:
/// - GenesisBlock: Starting from the beginning of the blockchain
/// - PrevProof: Building on a previous verification's output
///
/// This enables incremental verification of the Bitcoin blockchain, where each
/// proof can build on previous proofs rather than starting from the genesis block.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum BitcoinConsensusPrevProofType {
    /// Start verification from the genesis block (no previous state)
    GenesisBlock,
    /// Continue verification from a previous proof's output state
    PrevProof(BitcoinConsensusCircuitOutput),
}

/// Input data for the Bitcoin consensus verification circuit
///
/// This structure contains all data needed to verify a sequence of Bitcoin blocks:
/// - method_id: Unique identifier for the verification method
/// - prev_proof: Previous state to build upon (or genesis)
/// - blocks: The sequence of blocks to verify
/// - utxo_inclusion_proofs: Proofs for transaction input UTXOs
/// - utxo_insertion_proofs: Proofs for transaction output UTXOs
///
/// Together with the verification code, this input allows generating a zero-knowledge
/// proof that the blocks follow Bitcoin's consensus rules.
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitInput {
    /// Unique identifier for the verification method
    pub method_id: [u32; 8],
    /// Previous state to build upon
    pub prev_proof: BitcoinConsensusPrevProofType,
    /// The blocks to verify
    pub input_data: BitcoinConsensusCircuitData,
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitData {
    /// The blocks to verify
    pub blocks: Vec<CircuitBlock>,
    /// Proofs for transaction input UTXOs. We already have the Key OutPoint in the input.
    pub utxo_deletion_update_proofs: VecDeque<UTXODeletionUpdateProof>,
    /// Proofs for transaction output UTXOs.
    pub utxo_insertion_update_proofs: UTXOInsertionUpdateProof, // TODO: Maybe these two proofs can be combined into a Witness.
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXODeletionUpdateProof {
    /// The JMT update proof for this UTXO deletion
    pub update_proof: UpdateMerkleProof<Sha256>,
    /// UTXO that was spent by the transaction input
    pub utxo: UTXO,
    /// The new JMT root hash after deletion
    pub new_root: RootHash,
}

impl UTXODeletionUpdateProof {
    pub fn verify_update(self, prev_root: &mut RootHash, key: KeyOutPoint) {
        let utxo_bytes = UTXOBytes::from(self.utxo);
        let value_hash = ValueHash::with::<sha2::Sha256>(&utxo_bytes);
        let proof_to_borsh = borsh::to_vec(&self.update_proof).unwrap();
        let key_hash_from_borsh = borsh::from_slice::<KeyHash>(&proof_to_borsh[5..37]).unwrap();
        // println!("Key hash from borsh: {:?}", key_hash_from_borsh);
        let value_hash_from_borsh =
            borsh::from_slice::<ValueHash>(&proof_to_borsh[37..69]).unwrap();
        // println!("Value hash from borsh: {:?}", value_hash_from_borsh);
        let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(key).as_ref());
        assert_eq!(key_hash, key_hash_from_borsh);
        assert_eq!(value_hash, value_hash_from_borsh);
        let updates = vec![(key_hash, None::<Vec<u8>>)];
        self.update_proof
            .verify_update(*prev_root, self.new_root, &updates)
            .unwrap();
        *prev_root = self.new_root;
    }
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOInsertionUpdateProof {
    /// The JMT update proof for this insertion
    pub update_proof: UpdateMerkleProof<Sha256>,
    /// The new JMT root hash after insertion
    pub new_root: RootHash,
}

impl UTXOInsertionUpdateProof {
    pub fn empty() -> Self {
        UTXOInsertionUpdateProof {
            update_proof: UpdateMerkleProof::new(vec![]),
            new_root: RootHash([0u8; 32]),
        }
    }

    pub fn verify_update(self, prev_root: &mut RootHash, updates: &Vec<(KeyOutPoint, UTXO)>) {
        let proof_updates = updates
            .iter()
            .map(|(key, value)| {
                let key_hash = KeyHash::with::<sha2::Sha256>(OutPointBytes::from(*key).as_ref());
                let utxo_bytes = UTXOBytes::from(value.clone());
                (key_hash, Some(utxo_bytes.0))
            })
            .collect::<Vec<_>>();
        self.update_proof
            .verify_update(*prev_root, self.new_root, &proof_updates)
            .unwrap();
        *prev_root = self.new_root;
    }
}

/// Output data from the Bitcoin consensus verification circuit
///
/// This structure represents the result of Bitcoin consensus verification:
/// - method_id: The verification method used
/// - bitcoin_state: The resulting state after verification
///
/// This output serves as a cryptographic commitment to the blockchain state
/// after processing the verified blocks.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinConsensusCircuitOutput {
    /// The verification method used
    pub method_id: [u32; 8],
    /// The resulting Bitcoin state after verification
    pub bitcoin_state: BitcoinState,
}

/// Bitcoin blockchain state representation
///
/// This structure encapsulates the essential state of the Bitcoin blockchain:
/// - header_chain_state: The state of the block header chain
/// - utxo_set_commitment: The state of the UTXO set
///
/// Together, these components form a complete representation of the blockchain
/// state needed for consensus verification.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BitcoinState {
    /// The state of the block header chain
    pub header_chain_state: header_chain::HeaderChainState,
    /// The state of the UTXO set (Unspent Transaction Outputs)
    pub utxo_set_commitment: utxo_set::UTXOSetGuest,
}

impl BitcoinState {
    /// Creates a new, empty Bitcoin blockchain state
    ///
    /// This method initializes a fresh Bitcoin state with:
    /// - A new header chain state (starting before the genesis block)
    /// - A new UTXO set commitment (empty UTXO set)
    ///
    /// This is typically used when starting verification from the genesis block.
    ///
    /// # Returns
    ///
    /// A new BitcoinState instance with default values
    pub fn new() -> Self {
        // println!("[DEBUG] Creating new BitcoinState");
        BitcoinState {
            header_chain_state: HeaderChainState::new(),
            utxo_set_commitment: utxo_set::UTXOSetGuest::new(),
        }
    }

    pub fn verify_and_apply_blocks(&mut self, input: &mut BitcoinConsensusCircuitData) {
        let mut utxo_cache: BTreeMap<KeyOutPoint, UTXO> = BTreeMap::new();

        for block in input.blocks.iter() {
            // Before validating header, know which BIP flags are active in the next block
            let expected_next_height = self.header_chain_state.block_height.wrapping_add(1);

            let bip_flags = softfork_manager::BIPFlags::at_height(expected_next_height);

            let time_to_compare_against = if bip_flags.is_bip113_active() {
                self.header_chain_state.get_median_time_past()
            } else {
                block.block_header.time
            };

            self.header_chain_state
                .verify_and_apply_header(&block.block_header);

            let expected_block_subsidy = self.header_chain_state.calculate_block_subsidy();

            let claimed_block_reward = block.get_claimed_block_reward().to_sat();

            block.check_block_simple();

            block.verify_merkle_root();
            block.verify_bip34_block_height(bip_flags.is_bip34_active(), expected_next_height);
            block.verify_witness_commitment(bip_flags.is_bip141_active());

            // Check if all txs are finalized
            for transaction in block.transactions.iter() {
                transaction.check_tx_simple();
                transaction.verify_final_tx(
                    time_to_compare_against,
                    self.header_chain_state.block_height,
                );
            }

            // Process transactions
            let mut sigops = 0u32;
            // println!(
            //     "[INFO] Processing {} transactions in block",
            //     block.transactions.len()
            // );
            let mut total_fee = 0u64;

            for transaction in block.transactions.iter() {
                let fee = self.verify_and_apply_transaction(
                    &mut utxo_cache,
                    &mut sigops,
                    &transaction,
                    &mut input.utxo_deletion_update_proofs,
                    bip_flags.is_assume_valid(),
                    bip_flags.is_bip68_active(),
                    time_to_compare_against,
                );
                total_fee += fee;
            }

            // Check if the claimed block reward is correct
            if claimed_block_reward > expected_block_subsidy + total_fee {
                panic!("Block reward mismatch");
            }

            if sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST {
                println!(
                    "[ERROR] Block sigops cost exceeds limits: {} > {}",
                    sigops * WITNESS_SCALE_FACTOR,
                    MAX_BLOCK_SIGOPS_COST
                );
                panic!("Block sigops cost exceeds limits");
            }
        }

        // Vectorize the UTXO cache
        let updates = utxo_cache
            .into_iter()
            .map(|(key_outpoint, value_utxo)| (key_outpoint, value_utxo))
            .collect::<Vec<_>>();

        let proof = std::mem::replace(
            &mut input.utxo_insertion_update_proofs,
            UTXOInsertionUpdateProof::empty(),
        );
        proof.verify_update(&mut self.utxo_set_commitment.jmt_root, &updates);
    }

    /// For now, handle UTXO set changes transaction by transaction. Maybe batch them later.
    pub fn verify_and_apply_transaction(
        &mut self,
        utxo_cache: &mut BTreeMap<KeyOutPoint, UTXO>,
        total_sigops: &mut u32,
        transaction: &CircuitTransaction,
        deletion_update_proof_vec: &mut VecDeque<UTXODeletionUpdateProof>,
        is_assume_valid: bool,
        is_bip68_active: bool,
        time_to_compare: u32,
    ) -> u64 {
        // UTXO verification
        let mut curr_root_hash = self.utxo_set_commitment.jmt_root;
        // println!(
        //     "[INFO] Starting UTXO verification - Current JMT root: {:?}",
        //     curr_root_hash
        // );

        let mut prevouts: Vec<UTXO> = Vec::new();
        let mut amount_in = 0u64;
        let mut amount_out = 0u64;

        // println!(
        //     "[INFO] Processing {} transaction inputs with UTXO proofs",
        //     transaction.input.len()
        // );
        let is_coinbase = transaction.is_coinbase();
        // Coinbase transaction checks
        if is_coinbase {
        } else {
            // println!("[INFO] Non-coinbase transaction - Checking previous outputs");
            for tx_input in transaction.input.iter() {
                // println!(
                //     "[INFO] Processing input {}/{} - Previous output: {:?}",
                //     idx + 1,
                //     transaction.input.len(),
                //     tx_input.previous_output
                // );
                let key_outpoint = KeyOutPoint::from_outpoint(&tx_input.previous_output);

                if let Some(utxo) = utxo_cache.remove(&key_outpoint) {
                    // println!("[INFO] UTXO Cache has the UTXO - No need for the JMT proof");
                    // println!(
                    //     "[INFO] Found UTXO in cache - Value: {} satoshis, Height: {}, Coinbase: {}",
                    //     utxo.value, utxo.block_height, utxo.is_coinbase
                    // );
                    prevouts.push(utxo);
                } else {
                    // println!("[INFO] UTXO not found in cache - Verifying JMT proof");
                    let proof = deletion_update_proof_vec.pop_front().unwrap();
                    // .expect("UTXO proof not found").clone();
                    prevouts.push(proof.utxo.clone());
                    proof.verify_update(&mut curr_root_hash, key_outpoint);

                    // println!("[INFO] JMT updated - New root: {:?}", curr_root_hash);
                }
            }
            let tx_sigops_count = transaction.total_sigop_cost(|outpoint: &OutPoint| {
                transaction
                    .input
                    .iter()
                    .position(|input| &input.previous_output == outpoint)
                    .and_then(|idx| prevouts.get(idx))
                    .map(|utxo| utxo.into_txout().clone())
            }) as u32;
            *total_sigops += tx_sigops_count;
        }

        self.utxo_set_commitment.jmt_root = curr_root_hash;

        let prev_txouts = prevouts
            .iter()
            .map(|utxo| utxo.into_txout())
            .collect::<Vec<_>>();

        if !is_coinbase {
            if is_bip68_active {
                transaction.sequence_locks(
                    is_bip68_active,
                    &prevouts,
                    time_to_compare,
                    self.header_chain_state.block_height,
                );
            }
            // Verify transaction inputs
            for (input_idx, input) in transaction.input.iter().enumerate() {
                let prev_height = prevouts[input_idx].block_height;
                let is_coinbase = prevouts[input_idx].is_coinbase;
                amount_in += prevouts[input_idx].value;
                if is_coinbase {
                    // 100 blocks maturity for coinbase outputs
                    if self.header_chain_state.block_height - prev_height < 100 {
                        panic!("Coinbase output not matured");
                    }
                }
                if !is_assume_valid {
                    let taproot_script_leafhash = if prev_txouts[input_idx].script_pubkey.is_p2tr()
                        && transaction.inner().input[input_idx].witness.len() > 1
                    {
                        // The last witness element is the merkle inclusion proof, the penultimate is the unlock script
                        let unlock_script = input.witness.tapscript().unwrap();
                        Some(TapLeafHash::from_script(
                            unlock_script,
                            LeafVersion::TapScript,
                        ))
                    } else {
                        None
                    };
                    let tx_template = TxTemplate {
                        tx: transaction.inner().clone(),
                        prevouts: prev_txouts.clone(), // TODO: Remove these clones
                        input_idx,
                        taproot_script_leafhash,
                    };
                    let (prev_txout_type, script, witness) =
                        get_prev_txout_type_with_script_and_witness(
                            transaction,
                            &prev_txouts,
                            input_idx,
                        );

                    let mut exec =
                        Exec::new(prev_txout_type, OPTIONS, tx_template, script, witness).unwrap();

                    loop {
                        if exec.exec_next().is_err() {
                            break;
                        }
                    }
                    if !exec.result().unwrap().success {
                        panic!("Script execution failed, details: {:?}", exec.result());
                    }
                }
            }
            for output in transaction.output.iter() {
                amount_out += output.value.to_sat();
            }
        }

        UTXOSetGuest::add_transaction_outputs(
            transaction,
            self.header_chain_state.block_height,
            time_to_compare,
            is_coinbase,
            utxo_cache,
        );

        if amount_in < amount_out {
            panic!("Transaction output exceeds input value");
        }
        let fee = amount_in - amount_out;
        if fee > 2_100_000_000_000_000 {
            panic!("Transaction fee exceeds maximum limit");
        }
        return fee;
    }
}

/// Main entry point for the Bitcoin consensus verification circuit
///
/// This function implements the core Bitcoin consensus verification circuit that:
/// 1. Reads the input data (blocks and proofs)
/// 2. Validates the previous proof (if applicable)
/// 3. Verifies all blocks against Bitcoin's consensus rules
/// 4. Commits the final state as a cryptographic proof
///
/// The circuit produces a zero-knowledge proof that the blocks follow
/// Bitcoin's consensus rules without revealing the full blockchain data.
///
/// # Arguments
///
/// * `guest` - Interface to the ZKVM guest environment
pub fn bitcoin_consensus_circuit(guest: &impl ZkvmGuest) {
    let start = risc0_zkvm::guest::env::cycle_count();

    let mut input: BitcoinConsensusCircuitInput = guest.read_from_host();

    // Initialize the Bitcoin state based on the previous proof
    let mut bitcoin_state = match input.prev_proof {
        // For genesis block verification, create a fresh state
        BitcoinConsensusPrevProofType::GenesisBlock => {
            // println!("[DEBUG] Creating new BitcoinState from GenesisBlock");
            BitcoinState::new()
        }
        // For incremental verification, verify the previous proof and use its state
        BitcoinConsensusPrevProofType::PrevProof(prev_proof) => {
            // Ensure the method ID matches
            assert_eq!(prev_proof.method_id, input.method_id);
            // Cryptographically verify the previous proof
            guest.verify(input.method_id, &prev_proof);
            // Use the state from the previous proof
            prev_proof.bitcoin_state
        }
    };

    // Verify all blocks and apply them to the state
    bitcoin_state.verify_and_apply_blocks(&mut input.input_data);

    // Commit the final state as the circuit output
    guest.commit(&BitcoinConsensusCircuitOutput {
        method_id: input.method_id,
        bitcoin_state,
    });

    let end = risc0_zkvm::guest::env::cycle_count();
    println!("{} cycles", end - start);
}

fn get_prev_txout_type_with_script_and_witness(
    transaction: &CircuitTransaction,
    prev_txouts: &Vec<bitcoin::TxOut>,
    input_idx: usize,
) -> (ExecCtx, ScriptBuf, Vec<Vec<u8>>) {
    // Get the previous transaction output type
    let prev_txout_type = get_txout_type(&prev_txouts[input_idx]);

    // Extract witness data
    let witness_vec = transaction.inner().input[input_idx]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect::<Vec<_>>();

    match prev_txout_type {
        script::txout::TxoutType::NonStandard => (
            ExecCtx::Legacy,
            prev_txouts[input_idx].script_pubkey.clone(),
            get_non_standard_witness(transaction.input[input_idx].script_sig.clone()),
        ),
        script::txout::TxoutType::P2A => (
            ExecCtx::Legacy,
            prev_txouts[input_idx].script_pubkey.clone(),
            get_non_standard_witness(transaction.input[input_idx].script_sig.clone()),
        ),
        script::txout::TxoutType::P2PK => {
            // P2PK: <pubkey> OP_CHECKSIG
            // The witness is the signature
            (
                ExecCtx::Legacy,
                prev_txouts[input_idx].script_pubkey.clone(),
                get_p2pk_witness(transaction.input[input_idx].script_sig.clone()),
            )
        }
        script::txout::TxoutType::P2PKH => {
            // P2PKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
            // The witness is [signature, pubkey]
            (
                ExecCtx::Legacy,
                prev_txouts[input_idx].script_pubkey.clone(),
                get_p2pkh_witness(transaction.input[input_idx].script_sig.clone()),
            )
        }
        script::txout::TxoutType::P2SH => {
            // P2SH: OP_HASH160 <scripthash> OP_EQUAL
            if !witness_vec.is_empty() {
                // This might be P2SH-wrapped segwit
                let script_sig = transaction.input[input_idx].script_sig.clone();

                // Check if it's a wrapped P2WSH or P2WPKH
                if script_sig[1..].is_p2wsh() {
                    let (witness_script, redeem_script) =
                        get_wrapped_p2sh_witness_and_redeem_script(
                            transaction.input[input_idx].witness.clone(),
                            script_sig.clone(),
                        );

                    // Verify script hash match
                    let redeem_script_hash =
                        hash160::Hash::hash(script_sig[1..].as_bytes()).to_byte_array();
                    let expected_script_hash =
                        prev_txouts[input_idx].script_pubkey[2..22].as_bytes();
                    assert_eq!(
                        redeem_script_hash, expected_script_hash,
                        "P2WSH wrapped in P2SH script hash mismatch"
                    );

                    (ExecCtx::P2WSHWrappedP2SH, redeem_script, witness_script)
                } else if script_sig[1..].is_p2wpkh() {
                    let (witness_script, redeem_script) =
                        get_wrapped_p2sh_witness_and_redeem_script(
                            transaction.input[input_idx].witness.clone(),
                            script_sig.clone(),
                        );

                    // Verify script hash match
                    let redeem_script_hash =
                        hash160::Hash::hash(script_sig[1..].as_bytes()).to_byte_array();
                    let expected_script_hash =
                        prev_txouts[input_idx].script_pubkey[2..22].as_bytes();
                    assert_eq!(
                        redeem_script_hash, expected_script_hash,
                        "P2WPKH wrapped in P2SH script hash mismatch"
                    );

                    (ExecCtx::P2WPKHWrappedP2SH, redeem_script, witness_script)
                } else {
                    // Regular P2SH with witness data
                    let (witness_script, redeem_script) = split_p2sh_witness_and_redeem_script(
                        transaction.input[input_idx].script_sig.clone(),
                    );

                    // Verify script hash match
                    let redeem_script_hash =
                        hash160::Hash::hash(&redeem_script.as_bytes()).to_byte_array();
                    let expected_script_hash =
                        prev_txouts[input_idx].script_pubkey[2..22].as_bytes();
                    assert_eq!(
                        redeem_script_hash, expected_script_hash,
                        "P2SH script hash mismatch"
                    );

                    (ExecCtx::Legacy, redeem_script, witness_script)
                }
            } else {
                // Standard P2SH
                let (witness_script, redeem_script) = split_p2sh_witness_and_redeem_script(
                    transaction.input[input_idx].script_sig.clone(),
                );

                // Verify script hash match
                let redeem_script_hash =
                    hash160::Hash::hash(&redeem_script.as_bytes()).to_byte_array();
                let expected_script_hash = prev_txouts[input_idx].script_pubkey[2..22].as_bytes();
                assert_eq!(
                    redeem_script_hash, expected_script_hash,
                    "P2SH script hash mismatch"
                );

                (ExecCtx::Legacy, redeem_script, witness_script)
            }
        }
        script::txout::TxoutType::MultiSig => {
            // MultiSig: m <pubkey1> <pubkey2> ... <pubkeyn> n OP_CHECKMULTISIG
            // The script_sig contains: OP_0 <sig1> <sig2> ... <sigm>
            let script_sig = transaction.input[input_idx].script_sig.clone();

            // For MultiSig, we use the script_pubkey directly from prevout
            let multisig_script = prev_txouts[input_idx].script_pubkey.clone();

            // Extract signatures from the script_sig
            // Using the same helper function as seen in the test examples
            let witness_sigs = get_non_standard_witness(script_sig);

            // Return the execution context for Legacy scripts, multisig script, and witness signatures
            (ExecCtx::Legacy, multisig_script, witness_sigs)
        }

        script::txout::TxoutType::NullData => {
            // OP_RETURN data, not spendable
            unimplemented!()
        }
        script::txout::TxoutType::P2WSH => {
            // P2WSH: 0 <32-byte-hash>
            // The witness is [sig1, sig2, ..., script]
            let mut witness_items = witness_vec.clone();
            if !witness_items.is_empty() {
                let script_bytes = witness_items.pop().unwrap();
                let script = ScriptBuf::from_bytes(script_bytes.clone());

                // Verify script hash match
                let script_hash = sha2::Sha256::hash(&script_bytes);
                let expected_script_hash = &prev_txouts[input_idx].script_pubkey.as_bytes()[2..34];
                assert_eq!(
                    script_hash, expected_script_hash,
                    "P2WSH script hash mismatch"
                );

                (ExecCtx::SegwitV0P2WSH, script, witness_items)
            } else {
                panic!("P2WSH witness is empty")
            }
        }
        script::txout::TxoutType::P2WPKH => {
            // P2WPKH: 0 <20-byte-key-hash>
            // The witness is [signature, pubkey]
            // For P2WPKH, we need to construct the P2PKH script from the key hash
            if witness_vec.len() >= 2 {
                let pubkey = &witness_vec[1];

                // Verify key hash match
                let pubkey_hash = hash160::Hash::hash(pubkey).to_byte_array();
                let expected_pubkey_hash = &prev_txouts[input_idx].script_pubkey.as_bytes()[2..22];
                assert_eq!(
                    pubkey_hash, expected_pubkey_hash,
                    "P2WPKH key hash mismatch"
                );

                let p2pkh_script =
                    ScriptBuf::new_p2pkh(&PubkeyHash::from_slice(expected_pubkey_hash).unwrap());
                (ExecCtx::SegwitV0P2WPKH, p2pkh_script, witness_vec)
            } else {
                panic!("P2WPKH witness does not contain pubkey");
            }
        }
        script::txout::TxoutType::P2TR => {
            // P2TR: Taproot output (SegWit v1)
            // 1-byte: 0x51 (OP_1)
            // 32-bytes: x-only public key

            // Get the x-only pubkey from the script
            let x_only_pubkey_bytes: [u8; 32] = prev_txouts[input_idx].script_pubkey.as_bytes()
                [2..34]
                .try_into()
                .unwrap();

            // Check if it's a key path spend or script path spend
            if witness_vec.len() == 1 {
                // Key path spend: The witness contains only the signature
                // For key path spending, we construct a simple script: <x_only_pubkey> OP_CHECKSIG
                let key_script = ScriptBuf::builder()
                    .push_slice(x_only_pubkey_bytes)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();

                (ExecCtx::TaprootKeySpend, key_script, witness_vec)
            } else {
                // Script path spend: The witness contains [signature(s), unlock_script, control_block]
                // Extract the control block and unlock script from the witness
                let mut script_witness = witness_vec.clone();

                // The last item is the control block
                let control_block_bytes = script_witness.pop().unwrap();

                // Parse the control block
                let control_block = ControlBlock::decode(&control_block_bytes)
                    .expect("Invalid control block in P2TR witness");

                // The second-to-last item is the unlock script (tapscript)
                let unlock_script_bytes = script_witness.pop().unwrap();
                let unlock_script = ScriptBuf::from_bytes(unlock_script_bytes);

                // Get the x-only pubkey from the script
                let output_xonly_pubkey = XOnlyPublicKey::from_slice(&x_only_pubkey_bytes)
                    .expect("Invalid x-only public key in P2TR output");

                // Verify the taproot commitment
                let secp = secp256k1::Secp256k1::new();
                let commitment_result = control_block.verify_taproot_commitment(
                    &secp,
                    output_xonly_pubkey,
                    &unlock_script,
                );

                assert!(
                    commitment_result,
                    "P2TR control block verification failed: {:?}",
                    commitment_result
                );

                // Return the execution context with script path spending
                (ExecCtx::TaprootScriptSpend, unlock_script, script_witness)
            }
        }
        script::txout::TxoutType::WitnessUnknown => {
            unimplemented!()
        }
    }
}
