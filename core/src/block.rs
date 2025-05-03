// Bitcoin Block Implementation
// =========================
//
// This module provides a custom implementation of Bitcoin blocks for circuit-based processing.
// It encapsulates the block structure and related functionality needed for consensus validation.

use std::vec;

use bitcoin::{block::Bip34Error, script, Amount, Block, VarInt};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    bitcoin_merkle::BitcoinMerkleTree, constants::MAGIC_BYTES, header_chain::CircuitBlockHeader,
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
        // println!("[DEBUG] Creating CircuitBlock from Block");

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

        // println!("[DEBUG] Resulting CircuitBlock: {:?}", result);
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
        // println!("[DEBUG] Converting CircuitBlock into Block");

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

        // println!("[DEBUG] Resulting Block: {:?}", result);
        result
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
        // println!("[DEBUG] Checking if block is SegWit");

        // A block is SegWit if any non-coinbase transaction uses SegWit
        // We start from index 1 to skip the coinbase transaction
        let result = self.transactions[1..].iter().any(|tx| tx.is_segwit());

        // println!("[DEBUG] Is SegWit: {}", result);
        result
    }

    /// Calculates the Merkle root of the witness transaction IDs (wtxids)
    ///
    /// In SegWit blocks, a second Merkle root is calculated using the witness
    /// transaction IDs, which include the witness data in the hash. This is used
    /// for the witness commitment in the coinbase transaction.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the witness Merkle root
    pub fn calculate_wtxid_merkle_root(&self) -> [u8; 32] {
        // println!("[DEBUG] Calculating WTXID Merkle Root");

        // TODO: Make this optional
        // The wtxid of the coinbase transaction is defined to be all zeros
        let mut wtxids = vec![[0u8; 32]];

        // Add wtxids for all non-coinbase transactions
        wtxids.extend(self.transactions[1..].iter().map(|tx| tx.wtxid()));

        // Calculate the Merkle root of these wtxids
        let result = BitcoinMerkleTree::generate_root(wtxids);

        // println!("[DEBUG] WTXID Merkle Root: {:?}", result);
        result
    }

    /// Checks if the block has no transactions
    ///
    /// A valid Bitcoin block must have at least one transaction (the coinbase),
    /// so an empty block is invalid.
    ///
    /// # Returns
    ///
    /// `true` if the block has no transactions, `false` otherwise
    pub fn is_empty(&self) -> bool {
        // println!("[DEBUG] Checking if block is empty");

        let result = self.transactions.is_empty();

        // println!("[DEBUG] Is Empty: {}", result);
        result
    }

    /// Calculates the base size of the block
    ///
    /// The base size is the size of the block excluding witness data.
    /// This was the only measure of block size before SegWit.
    ///
    /// # Returns
    ///
    /// The base size in bytes
    fn base_size(&self) -> usize {
        // println!("[DEBUG] Calculating base size of block");

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
        // println!("[DEBUG] Base Size: {}", result);
        result
    }

    /// Calculates the total size of the block including witness data
    ///
    /// The total size includes all witness data in SegWit transactions.
    ///
    /// # Returns
    ///
    /// The total size in bytes
    pub fn total_size(&self) -> usize {
        // println!("[DEBUG] Calculating total size of block");

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
        // println!("[DEBUG] Total Size: {}", result);
        result
    }

    /// Calculates the weight of the block as defined in BIP-141
    ///
    /// Block weight is a measure introduced with SegWit (BIP-141) that
    /// gives witness data a discount. The formula is:
    /// weight = (base size * 3) + total size
    ///
    /// # Returns
    ///
    /// The block weight in weight units
    pub fn weight(&self) -> u64 {
        // println!("[DEBUG] Calculating weight of block");

        // Calculate weight according to BIP-141 formula:
        // weight = (base size * 3) + total size
        let result = (self.base_size() * 3 + self.total_size()) as u64;

        // println!("[DEBUG] Weight: {}", result);
        result
    }

    /// Verifies the witness commitment in a SegWit block
    ///
    /// In SegWit blocks, the coinbase transaction must contain a witness commitment
    /// output. This commitment is a hash derived from the wtxid Merkle root and
    /// a witness reserved value.
    ///
    /// # Returns
    ///
    /// `true` if the witness commitment is valid or if the block has no SegWit transactions,
    /// `false` otherwise
    pub fn check_witness_commitment(&self) -> bool {
        // println!("[DEBUG] Checking witness commitment");

        // Magic bytes prefix that identifies a witness commitment output
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if !self.is_segwit() {
            return true;
        }

        // Block must have at least one transaction (the coinbase)
        if self.is_empty() {
            return false;
        }

        // Get the coinbase transaction
        let coinbase = &self.transactions[0];

        // First transaction must be a coinbase
        if !coinbase.is_coinbase() {
            return false;
        }

        // Find the commitment output - it's the last output that starts with the magic bytes
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            // Extract the 32-byte commitment hash from the output script
            let commitment: [u8; 32] = coinbase.output[pos].script_pubkey.as_bytes()[6..38]
                .try_into()
                .unwrap();

            // The witness reserved value is in the coinbase input's witness data
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();

            // Verify the witness has exactly one 32-byte value
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                let witness = witness_vec[0];

                // The witness commitment must match the reserved value
                if witness == commitment {
                    return true;
                }
            }
        }

        // If we get here, the commitment is invalid
        let result = false;
        // println!("[DEBUG] Witness Commitment Check: {}", result);
        result
    }

    /// Checks if the block's size is valid according to consensus rules
    ///
    /// This validates that:
    /// 1. The block has at least one transaction (the coinbase)
    /// 2. The block's weight is below the maximum allowed (4,000,000 weight units)
    /// 3. The block's base size (when weighted) is below the maximum allowed
    ///
    /// # Returns
    ///
    /// `true` if the block size is valid, `false` otherwise
    pub fn is_valid_size(&self) -> bool {
        // println!("[DEBUG] Checking if block size is valid");

        // Blocks must contain at least the coinbase transaction
        if self.transactions.is_empty() {
            return false;
        }

        // Calculate the block weight
        let weight = self.weight();

        // Calculate the weighted base size (using the witness scale factor of 4)
        let base_size_weight = (self.base_size() as u64) * 4;

        // Check against the maximum allowed block weight (4,000,000 weight units)
        // We check both the weight and the weighted base size to ensure compatibility
        // with both SegWit and non-SegWit validation rules
        if weight > 4_000_000 || base_size_weight > 4_000_000 {
            return false;
        }

        // Block size is valid
        let result = true;
        // println!("[DEBUG] Is Valid Size: {}", result);
        result
    }

    /// Returns a reference to the coinbase transaction of the block
    ///
    /// The coinbase transaction is the first transaction in a block and is special
    /// because it's allowed to create new bitcoins as a block reward. It has no real
    /// inputs and must follow specific rules.
    ///
    /// # Returns
    ///
    /// `Some(&CircuitTransaction)` pointing to the coinbase transaction if the block has any transactions,
    /// or `None` if the block is empty
    pub fn coinbase(&self) -> Option<&CircuitTransaction> {
        // println!("[DEBUG] Retrieving coinbase transaction");

        // The coinbase is the first transaction in the block
        let result = self.transactions.first();

        // println!("[DEBUG] Coinbase Transaction: {:?}", result);
        result
    }

    /// Extracts the block height encoded in the coinbase according to BIP-34
    ///
    /// BIP-34 requires that blocks with version 2 and above include the block height
    /// in the coinbase transaction's scriptSig. This method extracts that height.
    ///
    /// As per the spec:
    /// "Add height as the first item in the coinbase transaction's scriptSig,
    /// and increase block version to 2. The format of the height is
    /// 'minimally encoded serialized CScript' -- first byte is number of bytes in the number
    /// (will be 0x03 on main net for the next 150 or so years with 2^23-1 blocks),
    /// following bytes are little-endian representation of the number (including a sign bit).
    /// Height is the height of the mined block in the block chain, where the genesis block
    /// is height zero (0)."
    ///
    /// # Returns
    ///
    /// The block height as a u64 if successfully extracted, or a Bip34Error otherwise
    // TODO: Maybe we don't need this
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // println!("[DEBUG] Retrieving BIP34 block height");

        // BIP-34 is only in effect for blocks with version 2 and above
        if self.block_header.version < 2 {
            return Err(Bip34Error::Unsupported);
        }

        // Get the coinbase transaction
        let coinbase_tx = self.coinbase().ok_or(Bip34Error::NotPresent)?;

        // Get the first input
        let input = coinbase_tx.input.first().ok_or(Bip34Error::NotPresent)?;

        // Get the first instruction in the scriptSig
        let push = input
            .script_sig
            .instructions_minimal()
            .next()
            .ok_or(Bip34Error::NotPresent)?;

        // Match on the instruction type
        match push.map_err(|_| Bip34Error::NotPresent)? {
            // We're looking for a simple push of bytes
            script::Instruction::PushBytes(b) => {
                // Read the scriptint (numeric value) from the push
                // This validates that the number is properly encoded
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;

                // Height must be non-negative
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    let result = Ok(h as u64);
                    // println!("[DEBUG] BIP34 Block Height: {:?}", result);
                    result
                }
            }
            // Any other instruction type is invalid
            _ => Err(Bip34Error::NotPresent),
        }
    }

    /// Calculates the total block reward claimed by the coinbase transaction
    ///
    /// The coinbase transaction creates new bitcoins and collects transaction fees.
    /// This method sums all the outputs of the coinbase transaction to find the
    /// total reward claimed by the miner.
    ///
    /// # Returns
    ///
    /// The total value of all coinbase outputs as a Bitcoin Amount
    pub fn get_claimed_block_reward(&self) -> Amount {
        // println!("[DEBUG] Calculating claimed block reward");

        // Get the coinbase transaction (first transaction)
        let coinbase_tx = &self.transactions[0];

        // Start with zero
        let mut reward = Amount::from_sat(0);

        // Sum all outputs in the coinbase transaction
        for output in coinbase_tx.output.iter() {
            reward += output.value;
        }

        let result = reward;
        // println!("[DEBUG] Claimed Block Reward: {}", result);
        result
    }

    /// Extracts the block height from the coinbase transaction using BIP-34 rules
    ///
    /// BIP-34 mandates including the block height in the coinbase script to prevent
    /// duplicate transaction IDs. This method directly parses the height value from
    /// the coinbase script.
    ///
    /// NOTE: This implementation assumes the block adheres to BIP-34 and will panic
    /// if the coinbase script is malformed.
    ///
    /// # Returns
    ///
    /// The encoded block height as a u32
    ///
    /// # Panics
    ///
    /// Panics if the coinbase script doesn't conform to the expected format
    pub fn get_bip34_block_height(&self) -> u32 {
        // println!("[DEBUG] Getting BIP34 block height");

        // Get the coinbase transaction
        let coinbase_tx = &self.transactions[0];

        // Get the coinbase script
        let coinbase_script = coinbase_tx.input[0].script_sig.as_bytes();

        // Ensure the script is not empty
        assert!(
            !coinbase_script.is_empty(),
            "Coinbase script cannot be empty"
        );

        // The first byte indicates the length of the height encoding
        let height_len = coinbase_script[0] as usize;

        // Validate the height length (up to 5 bytes for a u32)
        assert!(
            height_len >= 1 && height_len <= 5,
            "Invalid height length in coinbase"
        );

        // Ensure the script is long enough to contain the height
        assert!(
            coinbase_script.len() > height_len,
            "Coinbase script too short"
        );

        // Extract the height bytes
        let height_bytes = &coinbase_script[1..=height_len];
        let mut height_value = 0u32;

        // Parse the height value from little-endian bytes
        for (i, &byte) in height_bytes.iter().enumerate() {
            height_value |= (byte as u32) << (8 * i);
        }

        let result = height_value;
        // println!("[DEBUG] BIP34 Block Height: {}", result);
        result
    }

    /// Extracts the witness commitment hash from the coinbase transaction
    ///
    /// In SegWit blocks, the coinbase must contain an output with an OP_RETURN
    /// followed by the witness commitment hash. This method extracts that hash.
    ///
    /// # Returns
    ///
    /// The 32-byte witness commitment hash
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The first transaction is not a coinbase
    /// - No witness commitment is found
    /// - The witness commitment format is invalid
    pub fn get_witness_commitment_hash(&self) -> [u8; 32] {
        // println!("[DEBUG] Getting witness commitment hash");

        // Get the coinbase transaction
        let coinbase_tx = &self.transactions[0];

        // Verify this is really a coinbase transaction
        if !coinbase_tx.is_coinbase() {
            panic!("Only coinbase transactions can have a witness commitment hash");
        }

        // Look for an OP_RETURN output containing the witness commitment
        for output in coinbase_tx.output.iter() {
            if output.script_pubkey.is_op_return() {
                // The output script must be at least 38 bytes:
                // - 2 bytes for OP_RETURN and push
                // - 4 bytes for magic bytes
                // - 32 bytes for the commitment hash
                if output.script_pubkey.len() < 38 {
                    panic!("Witness commitment hash is too short");
                }

                // Verify the magic bytes prefix
                assert_eq!(
                    MAGIC_BYTES,
                    output.script_pubkey.as_bytes()[2..6],
                    "Invalid magic bytes (witness commitment prefix)"
                );

                // Extract the 32-byte commitment hash
                let result = output.script_pubkey.as_bytes()[6..38].try_into().unwrap();
                // println!("[DEBUG] Witness Commitment Hash: {:?}", result);
                return result;
            }
        }

        // TODO: Some blocks do not have a witness commitment hash, so this should be handled more gracefully
        panic!("No witness commitment hash found in coinbase transaction");
    }
}
