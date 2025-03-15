use std::vec;

use bitcoin::{block::Bip34Error, script, Amount, Block, VarInt};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    bitcoin_merkle::BitcoinMerkleTree, constants::MAGIC_BYTES, header_chain::CircuitBlockHeader,
    transaction::CircuitTransaction,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct CircuitBlock {
    pub block_header: CircuitBlockHeader,
    pub transactions: Vec<CircuitTransaction>,
}

impl CircuitBlock {
    pub fn from(block: Block) -> Self {
        let block_header = CircuitBlockHeader::from(block.header);
        let transactions = block
            .txdata
            .into_iter()
            .map(CircuitTransaction::from)
            .collect();
        CircuitBlock {
            block_header,
            transactions,
        }
    }

    pub fn into(self) -> Block {
        Block {
            header: self.block_header.into(),
            txdata: self
                .transactions
                .into_iter()
                .map(&CircuitTransaction::into)
                .collect(),
        }
    }

    pub fn is_segwit(&self) -> bool {
        self.transactions[1..].iter().any(|tx| tx.is_segwit())
    }

    pub fn calculate_wtxid_merkle_root(&self) -> [u8; 32] {
        // TODO: Make this optional
        // Wtxid of the coinbase transaction is always 0x000...000
        let mut wtxids = vec![[0u8; 32]];
        wtxids.extend(self.transactions[1..].iter().map(|tx| tx.wtxid()));
        BitcoinMerkleTree::generate_root(wtxids)
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    fn base_size(&self) -> usize {
        let mut size = 80; // Block header size

        size += VarInt::from(self.transactions.len()).size();
        size += self
            .transactions
            .iter()
            .map(|tx| tx.base_size())
            .sum::<usize>();

        size
    }

    pub fn total_size(&self) -> usize {
        let mut size = 80; // Block header size

        size += VarInt::from(self.transactions.len()).size();
        size += self
            .transactions
            .iter()
            .map(|tx| tx.total_size())
            .sum::<usize>();

        size
    }

    pub fn weight(&self) -> u64 {
        // TODO: Maybe u32
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        (self.base_size() * 3 + self.total_size()) as u64
    }

    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.is_segwit() {
            return true;
        }

        if self.is_empty() {
            return false;
        }

        let coinbase = &self.transactions[0];
        if !coinbase.is_coinbase() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            let commitment: [u8; 32] = coinbase.output[pos].script_pubkey.as_bytes()[6..38]
                .try_into()
                .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                let witness = witness_vec[0];
                if witness == commitment {
                    return true;
                }
            }
        }

        false
    }

    pub fn is_valid_size(&self) -> bool {
        if self.transactions.is_empty() {
            return false; // Blocks must contain at least the coinbase transaction.
        }

        let weight = self.weight();
        let base_size_weight = (self.base_size() as u64) * 4; // Witness scale factor is 4.

        if weight > 4_000_000 || base_size_weight > 4_000_000 {
            // 4_000_000 is the maximum block weight.
            return false;
        }

        true
    }

    pub fn coinbase(&self) -> Option<&CircuitTransaction> {
        self.transactions.first()
    }

    // TODO: Maybe we don't need this
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).
        if self.block_header.version < 2 {
            // VERSION::TWO
            return Err(Bip34Error::Unsupported);
        }

        let coinbase_tx = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = coinbase_tx.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input
            .script_sig
            .instructions_minimal()
            .next()
            .ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }

    /// This is for the coinbase transaction only
    pub fn get_claimed_block_reward(&self) -> Amount {
        let coinbase_tx = &self.transactions[0];
        let mut reward = Amount::from_sat(0);
        for output in coinbase_tx.output.iter() {
            reward += output.value;
        }
        reward
    }

    /// This is for the coinbase transaction only
    pub fn get_bip34_block_height(&self) -> u32 {
        // Extract and verify block height from coinbase script
        let coinbase_tx = &self.transactions[0];
        let coinbase_script = coinbase_tx.input[0].script_sig.as_bytes();
        assert!(
            !coinbase_script.is_empty(),
            "Coinbase script cannot be empty"
        );

        // First byte must be length of height serialization
        let height_len = coinbase_script[0] as usize;
        assert!(
            height_len >= 1 && height_len <= 5,
            "Invalid height length in coinbase"
        );
        assert!(
            coinbase_script.len() > height_len,
            "Coinbase script too short"
        );

        // Extract the height bytes
        let height_bytes = &coinbase_script[1..=height_len];
        let mut height_value = 0u32;

        // Parse little-endian encoded height
        for (i, &byte) in height_bytes.iter().enumerate() {
            height_value |= (byte as u32) << (8 * i);
        }

        // assert_eq!(height_value, block_height, "Block height mismatch in coinbase script");
        height_value
    }

    /// This is for the coinbase transaction only
    pub fn get_witness_commitment_hash(&self) -> [u8; 32] {
        let coinbase_tx = &self.transactions[0];
        if !coinbase_tx.is_coinbase() {
            panic!("Only coinbase transactions can have a witness commitment hash");
        }
        for output in coinbase_tx.output.iter() {
            if output.script_pubkey.is_op_return() {
                if output.script_pubkey.len() < 38 {
                    panic!("Witness commitment hash is too short");
                }
                assert_eq!(
                    MAGIC_BYTES,
                    output.script_pubkey.as_bytes()[2..6],
                    "Invalid magic bytes (witness commitment prefix)"
                );
                return output.script_pubkey.as_bytes()[6..38].try_into().unwrap();
            }
        }
        panic!("No witness commitment hash found in coinbase transaction"); // TODO: Some blocks do not have a witness commitment hash, so this should be handled more gracefully
    }
}
