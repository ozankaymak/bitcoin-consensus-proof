// Bitcoin Block Implementation
// =========================
//
// This module provides a custom implementation of Bitcoin blocks for circuit-based processing.
// It encapsulates the block structure and related functionality needed for consensus validation.

use bitcoin::{blockdata::weight::WITNESS_SCALE_FACTOR, script, Amount, Block, VarInt};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    bitcoin_merkle::BitcoinMerkleTree,
    constants::{MAGIC_BYTES, MAX_BLOCK_WEIGHT},
    hashes::calculate_double_sha256,
    header_chain::CircuitBlockHeader,
    transaction::CircuitTransaction,
};

/// Represents a Bitcoin block optimized for circuit processing
///
/// A Bitcoin block consists of a block header and a list of transactions.
/// This implementation is designed to be used in zero-knowledge circuits,
/// with appropriate data structures and methods for consensus validation.
///
/// The block structure mirrors Bitcoin's format:
/// - A block header containing metadata and proof-of-work
/// - A list of transactions, with the first transaction always being the coinbase
///   transaction (which creates new bitcoins and collects transaction fees)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct CircuitBlock {
    /// The block header containing metadata and proof-of-work
    pub block_header: CircuitBlockHeader,

    /// The list of transactions in the block
    /// The first transaction (index 0) is always the coinbase transaction
    pub transactions: Vec<CircuitTransaction>,
}

impl CircuitBlock {
    /// Creates a new CircuitBlock from a bitcoin-rs Block
    ///
    /// This conversion method takes a Block from the bitcoin-rs library and
    /// transforms it into our circuit-compatible representation.
    ///
    /// # Arguments
    ///
    /// * `block` - A Block from the bitcoin-rs library
    ///
    /// # Returns
    ///
    /// A new CircuitBlock instance
    pub fn from(block: Block) -> Self {
        // Convert the block header
        let block_header = CircuitBlockHeader::from(block.header);

        // Convert each transaction in the block
        let transactions = block
            .txdata
            .into_iter()
            .map(CircuitTransaction::from)
            .collect();

        // Create the final CircuitBlock
        let result = CircuitBlock {
            block_header,
            transactions,
        };

        result
    }

    /// Converts this CircuitBlock back into a bitcoin-rs Block
    ///
    /// This method is the inverse of `from()` and converts our circuit-compatible
    /// representation back into the standard bitcoin-rs Block type.
    ///
    /// # Returns
    ///
    /// A standard bitcoin-rs Block
    pub fn into(self) -> Block {
        // Create a standard bitcoin-rs Block
        let result = Block {
            // Convert the header
            header: self.block_header.into(),

            // Convert each transaction
            txdata: self
                .transactions
                .into_iter()
                .map(&CircuitTransaction::into)
                .collect(),
        };

        result
    }

    // Some simple checks
    pub fn check_block_simple(&self) {
        if self.is_empty() {
            println!("Blockhash: {:?}", self.block_header.compute_block_hash());
            panic!("Block is empty");
        }
        if self.base_size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT {
            println!("Blockhash: {:?}", self.block_header.compute_block_hash());
            panic!("Block base size is too large");
        }
        if self.total_size() > MAX_BLOCK_WEIGHT {
            println!("Blockhash: {:?}", self.block_header.compute_block_hash());
            panic!("Block total size is too large");
        }
        if self.weight() > MAX_BLOCK_WEIGHT {
            println!("Blockhash: {:?}", self.block_header.compute_block_hash());
            panic!("Block weight is too large");
        }

        // Only the first transaction can be a coinbase
        if !self.transactions[0].is_coinbase() {
            println!("Txid: {:?}", self.transactions[0].txid());
            panic!("First transaction is not a coinbase");
        }
        // All other transactions must not be coinbase
        for tx in self.transactions.iter().skip(1) {
            if tx.is_coinbase() {
                println!("Txid: {:?}", tx.txid());
                panic!("Non-coinbase transaction is a coinbase");
            }
        }
    }

    pub fn verify_merkle_root(&self) {
        // Calculate the Merkle root of the transactions
        let merkle_tree =
            BitcoinMerkleTree::new(self.transactions.iter().map(|tx| tx.txid()).collect());
        let calculated_root = merkle_tree.root();

        assert_eq!(
            self.block_header.merkle_root, calculated_root,
            "Merkle root does not match"
        );
    }

    pub fn verify_bip34_block_height(&self, is_bip34_active: bool, expected_next_height: u32) {
        if !is_bip34_active {
            return;
        }

        // BIP-34 is only in effect for blocks with version 2 and above
        if self.block_header.version < 2 {
            panic!("BIP-34 is only in effect for blocks with version 2 and above");
        }

        // Get the coinbase transaction
        let coinbase_tx = &self.transactions[0]; // Should not err

        // Get the first input
        let input = coinbase_tx.input.first().unwrap_or_else(|| {
            panic!("BIP-34 violation: Coinbase input not present");
        });

        // Get the first instruction in the scriptSig
        let push = input
            .script_sig
            .instructions_minimal()
            .next()
            .unwrap_or_else(|| panic!("BIP-34 violation: scriptSig is empty"));

        let height = match push {
            Ok(script::Instruction::PushBytes(b)) => {
                let h = script::read_scriptint(b.as_bytes()).unwrap_or_else(|_e| {
                    panic!(
                        "BIP-34 violation: Unexpected push bytes: {:?}",
                        b.as_bytes()
                    );
                });

                if h < 0 {
                    panic!("BIP-34 violation: Block height is negative");
                }

                h as u64
            }
            Ok(script::Instruction::Op(op_code)) => {
                if op_code.to_u8() == 0x00 {
                    0u64
                } else if op_code.to_u8() >= 0x51 && op_code.to_u8() <= 0x60 {
                    (op_code.to_u8() - 0x50) as u64
                } else {
                    panic!("Unexpected non-push opcode: {:?}", op_code);
                }
            }
            _ => {
                panic!("BIP-34 violation: scriptSig does not start with PushBytes");
            }
        };
        if height != expected_next_height as u64 {
            panic!(
                "BIP-34 violation: Block height does not match expected value: {}",
                expected_next_height
            );
        }
    }

    pub fn verify_witness_commitment(&self, is_bip141_active: bool) {
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if !self.is_segwit() {
            return;
        } else {
            // Check if BIP-141 is active
            if !is_bip141_active {
                panic!("BIP-141 is not active, but SegWit transactions are present");
            }
        }

        // Block must have at least one transaction (the coinbase), this check is already done

        let witness_merkle_tree =
            BitcoinMerkleTree::new(self.transactions.iter().map(|tx| tx.wtxid()).collect());

        let witness_merkle_root = witness_merkle_tree.root();

        // Get the coinbase transaction
        let coinbase = &self.transactions[0];
        // println!("Coinbase tx: {:?}", coinbase);

        let witness_commitment: [u8; 32];
        // println!("Coinbase output 0 length: {:?}", coinbase.output[0].script_pubkey.len());
        // println!(
        //     "Coinbase output 0 script: {:?}",
        //     coinbase.output[0].script_pubkey
        // );
        // println!("Coinbase output 1 length: {:?}", coinbase.output[1].script_pubkey.len());
        // println!(
        //     "Coinbase output 1 script: {:?}",
        //     coinbase.output[1].script_pubkey
        // );
        // Find the commitment output - it's the last output that starts with the magic bytes, and it should be at least 38 bytes long.
        // Extract the 32-byte commitment hash from the output script
        if let Some(pos) = coinbase.output.iter().rposition(|o| {
            o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC_BYTES
        }) {
            // Extract the 32-byte commitment hash from the output script
            witness_commitment = coinbase.output[pos].script_pubkey.as_bytes()[6..38]
                .try_into()
                .expect(
                    "Witness commitment is at least 38 bytes, 32 bytes of which are the commitment",
                );
        } else {
            panic!("Witness commitment not found in coinbase transaction");
        }

        // Extract the witness reserved value from the coinbase transaction input witness
        let witness_reserved_value: [u8; 32] = coinbase.input[0].witness[0]
            .to_vec()
            .try_into()
            .expect("witness reserved value is 32 bytes");
        let mut hash_preimage: [u8; 64] = [0u8; 64];
        hash_preimage[0..32].copy_from_slice(&witness_merkle_root);
        hash_preimage[32..64].copy_from_slice(&witness_reserved_value);

        // Double-SHA256(witness root hash|witness reserved value)
        let expected_witness_commitment = calculate_double_sha256(&hash_preimage);

        assert_eq!(
            witness_commitment, expected_witness_commitment,
            "Witness commitment does not match expected value"
        );
    }

    /// Checks if this block contains any SegWit transactions
    ///
    /// A block is considered SegWit if any of its transactions (except the coinbase)
    /// use segregated witness.
    ///
    /// # Returns
    ///
    /// `true` if any transaction (except the coinbase) is SegWit, `false` otherwise
    pub fn is_segwit(&self) -> bool {
        // A block is SegWit if any non-coinbase transaction uses SegWit
        // We start from index 1 to skip the coinbase transaction
        let result = self.transactions[1..].iter().any(|tx| tx.is_segwit()); // Should not err

        result
    }

    pub fn is_empty(&self) -> bool {
        let result = self.transactions.is_empty();

        result
    }

    fn base_size(&self) -> usize {
        // Start with the fixed block header size
        let mut size = 80; // Block header size is always 80 bytes

        // Add the size of the transaction count VarInt
        size += VarInt::from(self.transactions.len()).size();

        // Add the base size of each transaction
        size += self
            .transactions
            .iter()
            .map(|tx| tx.base_size())
            .sum::<usize>();

        let result = size;
        result
    }

    pub fn total_size(&self) -> usize {
        // Start with the fixed block header size
        let mut size = 80; // Block header size

        // Add the size of the transaction count VarInt
        size += VarInt::from(self.transactions.len()).size();

        // Add the total size of each transaction (including witness data)
        size += self
            .transactions
            .iter()
            .map(|tx| tx.total_size())
            .sum::<usize>();

        let result = size;
        result
    }

    pub fn weight(&self) -> usize {
        // Calculate weight according to BIP-141 formula:
        // weight = (base size * 3) + total size
        let result = self.base_size() * 3 + self.total_size();

        result
    }

    pub fn get_claimed_block_reward(&self) -> Amount {
        // Get the coinbase transaction (first transaction)
        let coinbase_tx = &self.transactions[0]; // Should not err

        // Start with zero
        let mut reward = Amount::from_sat(0);

        // Sum all outputs in the coinbase transaction
        for output in coinbase_tx.output.iter() {
            reward += output.value;
        }

        let result = reward;
        result
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Block;

    use super::CircuitBlock;

    #[test]
    fn test_coinbase_tx_simple() {
        let block: Block = bitcoin::consensus::deserialize(&hex::decode("000000207663d3bb84157a1cbee9ad4d01c70230684325785ff32a26f6fde51e000000009db28139792c252ac89807ba837cb9056edb3f9af877d547e8925274e2b3984327e53866ffff001d64a2ce0c01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0a028c00062f4077697a2fffffffff0200f2052a01000000160014a54e2a1ec06389203887661535ed118b7d0538890000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        let circuit_block = CircuitBlock::from(block);
        circuit_block.check_block_simple();
        circuit_block.verify_merkle_root();
        circuit_block.verify_bip34_block_height(true, 140);
    }

    #[test]
    fn test_coinbase_tx_large() {
        let block_bytes: &[u8] =
            include_bytes!("../../data/blocks/testnet4-blocks/testnet4_block_81672.bin");
        let block: Block = bitcoin::consensus::deserialize(block_bytes).unwrap();
        let circuit_block = CircuitBlock::from(block);
        circuit_block.check_block_simple();
        circuit_block.verify_merkle_root();
        circuit_block.verify_bip34_block_height(true, 81672);
    }
}
