// Bitcoin Transaction Implementation
// ==============================
//
// This module provides a custom implementation of Bitcoin transactions for circuit-based processing.
// It handles transaction serialization, hash calculation, and consensus rule validation.
// The implementation is designed to be compatible with the Bitcoin protocol while being
// optimized for use in zero-knowledge circuits.
//
// Based on code from Citrea:
// https://github.com/chainwayxyz/citrea/blob/0acb887b1a766fac1a482a68c6d51ecf9661f538/crates/bitcoin-da/src/spec/transaction.rs

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

use crate::constants::{LOCKTIME_THRESHOLD, SEGWIT_FLAG, SEGWIT_MARKER};
use crate::hashes::calculate_double_sha256;
use crate::header_chain::CircuitBlockHeader;

// Constants for BIP-68 (Relative timelock)
// These constants are used to decode and interpret the sequence field in transaction inputs

/// Flag to indicate that sequence numbers should be validated as relative timelocks
const LOCKTIME_VERIFY_SEQUENCE: u32 = 0x00000080;

/// Granularity for time-based relative timelocks (2^9 = 512 seconds, approx. 9 minutes)
const SEQUENCE_LOCKTIME_GRANULARITY: u8 = 9;

/// Flag that indicates a sequence number should not be interpreted as a relative timelock
const SEQUENCE_LOCKTIME_DISABLED: u32 = 0x80000000;

/// Flag to indicate whether the sequence number encodes a block height (0) or time (1)
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 0x00400000;

/// Mask to extract the actual locktime value from a sequence number
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;

/// A wrapper around the bitcoin-rs Transaction type optimized for circuit processing
///
/// This struct provides a circuit-compatible Bitcoin transaction implementation with
/// additional methods for transaction validation and hash calculation. It uses a newtype
/// pattern to wrap the bitcoin-rs Transaction type, adding circuit-specific functionality
/// while maintaining compatibility with the standard Bitcoin transaction format.
///
/// Importantly, this implementation handles both legacy and SegWit transactions, providing
/// proper serialization and hash calculation methods for both formats, which is essential
/// for consensus verification.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct CircuitTransaction(pub Transaction);

impl CircuitTransaction {
    /// Creates a new CircuitTransaction from a bitcoin-rs Transaction
    ///
    /// This conversion method takes a Transaction from the bitcoin-rs library and
    /// wraps it in the CircuitTransaction type.
    ///
    /// # Arguments
    ///
    /// * `transaction` - A Transaction from the bitcoin-rs library
    ///
    /// # Returns
    ///
    /// A new CircuitTransaction instance
    pub fn from(transaction: Transaction) -> Self {
        println!("[DEBUG] Creating CircuitTransaction from Transaction");
        let result = Self(transaction);
        println!("[DEBUG] Resulting CircuitTransaction: {:?}", result);
        result
    }

    /// Returns a reference to the underlying bitcoin-rs Transaction
    ///
    /// This method provides access to the wrapped Transaction, allowing
    /// direct use of the bitcoin-rs transaction methods when needed.
    ///
    /// # Returns
    ///
    /// A reference to the inner Transaction
    pub fn inner(&self) -> &Transaction {
        println!("[DEBUG] Accessing inner Transaction");
        let result = &self.0;
        println!("[DEBUG] Inner Transaction: {:?}", result);
        result
    }

    /// Calculates the transaction ID (txid) in big-endian byte order
    ///
    /// The transaction ID is a double-SHA256 hash of the serialized transaction,
    /// excluding any witness data. For legacy transactions, this is the hash of the
    /// entire transaction. For SegWit transactions, this excludes the witness data,
    /// providing transaction malleability protection.
    ///
    /// Note: Bitcoin protocol uses little-endian byte order for displaying transaction IDs,
    /// but this method returns big-endian for consistency with other hash functions.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the transaction ID
    pub fn txid(&self) -> [u8; 32] {
        println!("[DEBUG] Calculating transaction ID");

        // Create a buffer for the serialized transaction
        let mut tx_bytes_vec = vec![];

        // Serialize the transaction version
        self.inner()
            .version
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // Serialize the transaction inputs
        self.inner()
            .input
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // Serialize the transaction outputs
        self.inner()
            .output
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // Serialize the transaction locktime
        self.inner()
            .lock_time
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // Calculate double SHA-256 of the serialized transaction
        let result = calculate_double_sha256(&tx_bytes_vec);

        println!("[DEBUG] Transaction ID: {:?}", result);
        result
    }

    /// Calculates the witness transaction ID (wtxid) in big-endian byte order
    ///
    /// The witness transaction ID is a double-SHA256 hash of the serialized transaction
    /// including any witness data. For legacy transactions, this is identical to the txid.
    /// For SegWit transactions, this includes the witness data.
    ///
    /// Per BIP-141, the wtxid of a coinbase transaction is defined as all zeros.
    ///
    /// Note: Bitcoin protocol uses little-endian byte order for displaying transaction IDs,
    /// but this method returns big-endian for consistency with other hash functions.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the witness transaction ID
    pub fn wtxid(&self) -> [u8; 32] {
        println!("[DEBUG] Calculating witness transaction ID");

        // Special case: coinbase transaction's wtxid is defined as all zeros
        if self.is_coinbase() {
            return [0; 32];
        }

        // Create a buffer for the serialized transaction
        let mut tx_bytes_vec = vec![];

        // Serialize the transaction version
        self.inner()
            .version
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // For SegWit transactions, add the SegWit marker and flag
        if self.is_segwit() {
            tx_bytes_vec.push(SEGWIT_MARKER);
            tx_bytes_vec.push(SEGWIT_FLAG);
        }

        // Serialize the transaction inputs
        self.inner()
            .input
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // Serialize the transaction outputs
        self.inner()
            .output
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        // For SegWit transactions, serialize the witness data
        if self.is_segwit() {
            for input in &self.inner().input {
                input.witness.consensus_encode(&mut tx_bytes_vec).unwrap();
            }
        }

        // Serialize the transaction locktime
        self.inner()
            .lock_time
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();

        println!("{:?}", tx_bytes_vec);

        // Calculate double SHA-256 of the serialized transaction
        let result = calculate_double_sha256(&tx_bytes_vec);

        println!("[DEBUG] Witness Transaction ID: {:?}", result);
        result
    }

    /// Checks if this transaction uses Segregated Witness (SegWit)
    ///
    /// A transaction is considered SegWit if any of its inputs has witness data.
    /// SegWit transactions have a different serialization format and hash calculation
    /// method, which is important for consensus verification.
    ///
    /// # Returns
    ///
    /// `true` if any input has witness data, `false` otherwise
    pub fn is_segwit(&self) -> bool {
        println!("[DEBUG] Checking if transaction is SegWit");

        // A transaction is SegWit if any input has a non-empty witness
        let result = self
            .inner()
            .input
            .iter()
            .any(|input| !input.witness.is_empty());

        println!("[DEBUG] Is SegWit: {}", result);
        result
    }

    /// Determines if the transaction is final according to Bitcoin consensus rules
    ///
    /// A transaction is considered final if:
    /// 1. Its locktime is 0, OR
    /// 2. The locktime is less than the block height/time and is satisfied, OR
    /// 3. All inputs have SEQUENCE_FINAL values (0xFFFFFFFF)
    ///
    /// This implements Bitcoin Core's IsFinalTx logic, which is used to determine
    /// if a transaction can be included in a block.
    ///
    /// # Arguments
    ///
    /// * `block_height` - The height of the block containing this transaction
    /// * `block_time` - The timestamp of the block containing this transaction
    ///
    /// # Returns
    ///
    /// `true` if the transaction is final, `false` otherwise
    pub fn is_final_tx(&self, block_height: i32, block_time: i64) -> bool {
        println!("[DEBUG] Checking if transaction is final");

        // Case 1: If nLockTime is 0, transaction is always final
        if self.0.lock_time.to_consensus_u32() == 0 {
            return true;
        }

        // Get lock time as both u32 and i64 for comparison
        let lock_time_u32 = self.0.lock_time.to_consensus_u32();
        let lock_time_i64 = lock_time_u32 as i64;

        // Case 2: Check if locktime is satisfied by the current block height/time
        // If locktime < LOCKTIME_THRESHOLD (500,000,000), it's a block height locktime
        // Otherwise, it's a timestamp locktime
        if (lock_time_u32 < LOCKTIME_THRESHOLD && lock_time_i64 < block_height as i64)
            || (lock_time_u32 >= LOCKTIME_THRESHOLD && lock_time_i64 < block_time)
        {
            return true;
        }

        // Case 3: Transaction is still considered final if all inputs have SEQUENCE_FINAL
        // This allows spending inputs even if the locktime isn't satisfied yet
        for txin in &self.0.input {
            // If any input doesn't have SEQUENCE_FINAL, the transaction isn't final
            if txin.sequence != Sequence::MAX {
                return false;
            }
        }

        // If we get here, all inputs have SEQUENCE_FINAL
        let result = true;
        println!("[DEBUG] Is Final Transaction: {}", result);
        result
    }

    /// Calculates relative timelock requirements based on BIP-68
    ///
    /// BIP-68 introduced relative timelocks, allowing transaction inputs to specify
    /// a minimum age (in blocks or time) since the referenced output was created.
    /// This method calculates the minimum block height and time at which the
    /// transaction would be valid based on these relative timelocks.
    ///
    /// # Arguments
    ///
    /// * `flags` - Verification flags that control which consensus rules to enforce
    /// * `prev_heights` - Vector of block heights where the spent outputs were created
    /// * `block` - The block header for context (used for time calculations)
    ///
    /// # Returns
    ///
    /// A tuple of (min_height, min_time) representing the minimum block height and
    /// timestamp at which this transaction would be valid.
    ///
    /// # Panics
    ///
    /// Panics if `prev_heights` doesn't have the same length as the transaction inputs.
    pub fn calculate_sequence_locks(
        &self,
        flags: u32,
        prev_heights: &mut Vec<i32>,
        block: &CircuitBlockHeader,
    ) -> (i32, i64) {
        println!("[DEBUG] Calculating sequence locks");

        // Ensure we have height information for each input
        assert_eq!(prev_heights.len(), self.0.input.len());

        // Will be set to the equivalent height- and time-based nLockTime values
        // that would be necessary to satisfy all relative lock-time constraints.
        // The semantics of nLockTime are the last invalid height/time, so
        // use -1 to have the effect of any height or time being valid.
        let mut min_height = -1;
        let mut min_time = -1;

        // BIP-68 only applies to transactions version 2 or higher
        // and only when LOCKTIME_VERIFY_SEQUENCE flag is set
        let enforce_bip68 = self.0.version.0 >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE != 0;

        // Skip processing if BIP-68 is not being enforced
        if !enforce_bip68 {
            return (min_height, min_time);
        }

        // Process each input to find the most restrictive timelock
        for (txin_index, txin) in self.0.input.iter().enumerate() {
            // Sequence numbers with the most significant bit set are not
            // treated as relative lock-times
            if (txin.sequence.0 & SEQUENCE_LOCKTIME_DISABLED) != 0 {
                // The height of this input is not relevant for sequence locks
                prev_heights[txin_index] = 0;
                continue;
            }

            // Get the height of the block containing the spent output
            let coin_height = prev_heights[txin_index];

            // Check if this is a time-based relative lock time (bit 22 set)
            if (txin.sequence.0 & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0 {
                // Time-based relative lock-times are measured from the smallest allowed
                // timestamp of the block containing the output being spent,
                // which is the median time past of the block prior.
                let coin_time =
                    get_median_time_past_for_height(block, std::cmp::max(coin_height - 1, 0));

                // Calculate the lock time in seconds
                // The 16-bit mask is shifted by the granularity (9 bits = 512 seconds)
                let sequence_locked_seconds =
                    (txin.sequence.0 & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY;

                // Calculate when this input can be spent
                // NOTE: Subtract 1 to maintain nLockTime semantics (last invalid time)
                let new_min_time = coin_time + (sequence_locked_seconds as i64) - 1;

                // Keep track of the most restrictive timelock
                min_time = std::cmp::max(min_time, new_min_time);
            } else {
                // Height-based relative lock time (bit 22 not set)
                // The 16-bit mask gives the number of blocks directly
                let sequence_locked_height = (txin.sequence.0 & SEQUENCE_LOCKTIME_MASK) as i32;

                // Calculate when this input can be spent
                // NOTE: Subtract 1 to maintain nLockTime semantics (last invalid height)
                let new_min_height = coin_height + sequence_locked_height - 1;

                // Keep track of the most restrictive timelock
                min_height = std::cmp::max(min_height, new_min_height);
            }
        }

        let result = (min_height, min_time);
        println!("[DEBUG] Sequence Locks: {:?}", result);
        result
    }

    /// Evaluates whether the calculated sequence locks are satisfied
    ///
    /// This method checks if the transaction's sequence locks (calculated by
    /// `calculate_sequence_locks`) are satisfied by the given block height and time.
    ///
    /// # Arguments
    ///
    /// * `block` - The block header for context (used for time calculations)
    /// * `block_height` - The height of the block where this transaction would be included
    /// * `lock_pair` - The (min_height, min_time) tuple calculated by `calculate_sequence_locks`
    ///
    /// # Returns
    ///
    /// `true` if all sequence locks are satisfied, `false` otherwise
    pub fn evaluate_sequence_locks(
        block: &CircuitBlockHeader,
        block_height: i32,
        lock_pair: (i32, i64),
    ) -> bool {
        println!("[DEBUG] Evaluating sequence locks");

        // Get current block time (median time past)
        let block_time = get_median_time_past(block);

        // Check if either the height or time lock requirement hasn't been met
        // The locks specify the last invalid block/time, so the current block/time
        // must be strictly greater to be valid
        if lock_pair.0 >= block_height || lock_pair.1 >= block_time {
            return false;
        }

        // All sequence locks are satisfied
        let result = true;
        println!("[DEBUG] Sequence Locks Satisfied: {}", result);
        result
    }

    /// Checks if all sequence locks for this transaction are satisfied
    ///
    /// This is a convenience method that combines `calculate_sequence_locks` and
    /// `evaluate_sequence_locks` to determine if a transaction can be included
    /// in a block based on its relative timelock requirements (BIP-68).
    ///
    /// # Arguments
    ///
    /// * `flags` - Verification flags that control which consensus rules to enforce
    /// * `prev_heights` - Vector of block heights where the spent outputs were created
    /// * `block` - The block header for context
    /// * `block_height` - The height of the block where this transaction would be included
    ///
    /// # Returns
    ///
    /// `true` if all sequence locks are satisfied, `false` otherwise
    pub fn sequence_locks(
        &self,
        flags: u32,
        prev_heights: &mut Vec<i32>,
        block: &CircuitBlockHeader,
        block_height: i32,
    ) -> bool {
        println!("[DEBUG] Checking sequence locks");

        // First, calculate the sequence locks
        let lock_pair = self.calculate_sequence_locks(flags, prev_heights, block);

        // Then, evaluate if they're satisfied
        let result = Self::evaluate_sequence_locks(block, block_height, lock_pair);

        println!("[DEBUG] Sequence Locks Check: {}", result);
        result
    }
}

// Helper functions for timelock operations

/// Gets the median time past for a block at the given height
///
/// The median time past (MTP) is used for time-based lock validation and is
/// defined as the median timestamp of the previous 11 blocks. This provides
/// a more stable notion of "block time" that miners cannot manipulate easily.
///
/// In Bitcoin, MTP was introduced by BIP-113 to address timestamp manipulation
/// issues. Using the median of the last 11 blocks creates a more predictable and
/// manipulation-resistant time reference for consensus rules.
///
/// Note: This is a simplified implementation that would need to be expanded
/// in a full Bitcoin implementation to actually compute the median of the
/// last 11 blocks' timestamps. The full implementation would require access
/// to the blockchain history to retrieve the timestamps of the previous blocks.
///
/// # Arguments
///
/// * `header` - The current block header for context
/// * `height` - The block height to get the median time past for
///
/// # Returns
///
/// The median time past as a Unix timestamp (seconds since epoch)
fn get_median_time_past_for_height(header: &CircuitBlockHeader, height: i32) -> i64 {
    // In a real implementation, this would:
    // 1. Look up the block at the given height
    // 2. Retrieve the timestamps of that block and its 10 ancestors
    // 3. Sort those timestamps
    // 4. Return the middle value (median) of those sorted timestamps
    //
    // For circuit simplicity in this implementation, we'll just return the block's timestamp
    // as a simplification. This is not consensus-compatible with Bitcoin but serves as
    // a placeholder for the actual implementation.
    header.time as i64
}

/// Gets the median time past for the current block
///
/// The median time past (MTP) is a critical concept in Bitcoin's consensus rules,
/// especially for time-based locks like OP_CHECKLOCKTIMEVERIFY and BIP-68 sequence
/// locks. By using the median of the previous 11 blocks' timestamps rather than
/// the current block's timestamp, Bitcoin prevents miners from manipulating
/// timelocks by setting extreme timestamp values.
///
/// This is a convenience function that provides the MTP for the current block.
///
/// # Arguments
///
/// * `header` - The block header to get the median time past for
///
/// # Returns
///
/// The median time past as a Unix timestamp (seconds since epoch)
fn get_median_time_past(header: &CircuitBlockHeader) -> i64 {
    // In a real implementation, this would compute the median of the
    // last 11 blocks' timestamps (including this block's ancestors)
    // For now, we'll just return the block's timestamp as a simplification
    header.time as i64
}

/// Implementation of Borsh serialization for CircuitTransaction
///
/// This allows CircuitTransaction instances to be efficiently serialized using
/// the Borsh binary format, which is optimized for use in zero-knowledge circuits.
/// Unlike Bitcoin's native serialization, this format is designed for efficiency
/// in circuit processing.
impl BorshSerialize for CircuitTransaction {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        // Serialize the transaction version
        BorshSerialize::serialize(&self.0.version.0, writer)?;

        // Serialize the lock time
        BorshSerialize::serialize(&self.0.lock_time.to_consensus_u32(), writer)?;

        // Serialize the number of inputs
        BorshSerialize::serialize(&self.0.input.len(), writer)?;

        // Serialize each input
        for input in &self.0.input {
            serialize_txin(input, writer)?;
        }

        // Serialize the number of outputs
        BorshSerialize::serialize(&self.0.output.len(), writer)?;

        // Serialize each output
        for output in &self.0.output {
            serialize_txout(output, writer)?;
        }

        Ok(())
    }
}

/// Implementation of Borsh deserialization for CircuitTransaction
///
/// This allows CircuitTransaction instances to be efficiently deserialized from
/// the Borsh binary format, reconstructing the full transaction structure.
impl BorshDeserialize for CircuitTransaction {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        // Deserialize the transaction version
        let version = Version(i32::deserialize_reader(reader)?);

        // Deserialize the lock time
        let lock_time = LockTime::from_consensus(u32::deserialize_reader(reader)?);

        // Deserialize the inputs
        let input_len = usize::deserialize_reader(reader)?;
        let mut input = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            input.push(deserialize_txin(reader)?);
        }

        // Deserialize the outputs
        let output_len = usize::deserialize_reader(reader)?;
        let mut output = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            output.push(deserialize_txout(reader)?);
        }

        // Construct the transaction
        let tx = Transaction {
            version,
            lock_time,
            input,
            output,
        };

        Ok(Self(tx))
    }
}

/// Serialize a transaction input (TxIn) using Borsh
///
/// This function handles the serialization of a Bitcoin transaction input (TxIn)
/// to the Borsh binary format. It breaks down the complex TxIn structure into its
/// component parts and serializes each part individually.
///
/// The serialization includes:
/// 1. The previous transaction ID (txid) that the input is spending from
/// 2. The output index (vout) from the previous transaction
/// 3. The unlocking script (script_sig) which proves ownership
/// 4. The sequence number, which can be used for relative timelocks (BIP-68)
/// 5. The witness data for SegWit transactions
///
/// # Arguments
///
/// * `txin` - The transaction input to serialize
/// * `writer` - The output writer to serialize to
///
/// # Returns
///
/// A Result indicating success or an error
fn serialize_txin<W: borsh::io::Write>(txin: &TxIn, writer: &mut W) -> borsh::io::Result<()> {
    // Serialize the previous output txid
    BorshSerialize::serialize(&txin.previous_output.txid.to_byte_array(), writer)?;

    // Serialize the previous output vout index
    BorshSerialize::serialize(&txin.previous_output.vout, writer)?;

    // Serialize the script signature
    BorshSerialize::serialize(&txin.script_sig.as_bytes(), writer)?;

    // Serialize the sequence number
    BorshSerialize::serialize(&txin.sequence.0, writer)?;

    // Serialize the witness data
    BorshSerialize::serialize(&txin.witness.to_vec(), writer)
}

/// Deserialize a transaction input (TxIn) using Borsh
///
/// This function reconstructs a Bitcoin transaction input (TxIn) from its
/// Borsh binary representation. It reads and deserializes each component
/// of a TxIn in the same order they were serialized.
///
/// The deserialization process:
/// 1. Reads the previous transaction ID (txid)
/// 2. Reads the output index (vout)
/// 3. Reads and reconstructs the unlocking script (script_sig)
/// 4. Reads the sequence number
/// 5. Reads and reconstructs the witness data
/// 6. Assembles these components into a complete TxIn structure
///
/// # Arguments
///
/// * `reader` - The input reader to deserialize from
///
/// # Returns
///
/// A Result containing the deserialized TxIn or an error
fn deserialize_txin<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxIn> {
    // Deserialize the previous output txid
    let txid = bitcoin::Txid::from_byte_array(<[u8; 32]>::deserialize_reader(reader)?);

    // Deserialize the previous output vout index
    let vout = u32::deserialize_reader(reader)?;

    // Deserialize the script signature
    let script_sig = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);

    // Deserialize the sequence number
    let sequence = Sequence(u32::deserialize_reader(reader)?);

    // Deserialize the witness data
    let witness = Witness::from(Vec::<Vec<u8>>::deserialize_reader(reader)?);

    // Construct and return the TxIn
    Ok(TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig,
        sequence,
        witness,
    })
}

/// Serialize a transaction output (TxOut) using Borsh
///
/// This function handles the serialization of a Bitcoin transaction output (TxOut)
/// to the Borsh binary format. Transaction outputs define where the bitcoin value
/// is being sent and under what conditions it can be spent in the future.
///
/// The serialization includes:
/// 1. The output value in satoshis (Bitcoin's smallest unit, 10^-8 BTC)
/// 2. The locking script (script_pubkey) which defines spending conditions
///
/// # Arguments
///
/// * `txout` - The transaction output to serialize
/// * `writer` - The output writer to serialize to
///
/// # Returns
///
/// A Result indicating success or an error
fn serialize_txout<W: borsh::io::Write>(txout: &TxOut, writer: &mut W) -> borsh::io::Result<()> {
    // Serialize the output value in satoshis
    BorshSerialize::serialize(&txout.value.to_sat(), writer)?;

    // Serialize the output script
    BorshSerialize::serialize(&txout.script_pubkey.as_bytes(), writer)
}

/// Deserialize a transaction output (TxOut) using Borsh
///
/// This function reconstructs a Bitcoin transaction output (TxOut) from its
/// Borsh binary representation. Transaction outputs consist of an amount
/// and a locking script that defines the conditions under which the amount
/// can be spent.
///
/// The deserialization process:
/// 1. Reads the value amount in satoshis
/// 2. Reads and reconstructs the locking script (script_pubkey)
/// 3. Assembles these components into a complete TxOut structure
///
/// # Arguments
///
/// * `reader` - The input reader to deserialize from
///
/// # Returns
///
/// A Result containing the deserialized TxOut or an error
fn deserialize_txout<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxOut> {
    // Deserialize the output value
    let value = Amount::from_sat(u64::deserialize_reader(reader)?);

    // Deserialize the output script
    let script_pubkey = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);

    // Construct and return the TxOut
    Ok(TxOut {
        value,
        script_pubkey,
    })
}

/// Implementation of Deref for CircuitTransaction
///
/// This allows CircuitTransaction to be used as if it were a reference to
/// a Transaction object, providing transparent access to all methods and
/// fields of the inner Transaction.
///
/// For example, one can call `tx.version` directly on a CircuitTransaction
/// instead of having to use `tx.0.version` or `tx.inner().version`.
impl Deref for CircuitTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        // Return a reference to the inner Transaction
        &self.0
    }
}

/// Implementation of DerefMut for CircuitTransaction
///
/// This extends the Deref implementation to allow mutable access to the
/// inner Transaction object, enabling fields to be modified directly.
///
/// For example, one can write `tx.version = Version(2)` directly on a
/// CircuitTransaction instead of accessing the inner transaction.
impl DerefMut for CircuitTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Return a mutable reference to the inner Transaction
        &mut self.0
    }
}

/// Implementation of From<Transaction> for CircuitTransaction
///
/// This allows a Transaction to be converted into a CircuitTransaction
/// using the From trait, which enables idiomatic Rust conversions:
/// ```
/// let circuit_tx = CircuitTransaction::from(tx);
/// // or
/// let circuit_tx: CircuitTransaction = tx.into();
/// ```
impl From<Transaction> for CircuitTransaction {
    fn from(tx: Transaction) -> Self {
        // Wrap the Transaction in a CircuitTransaction
        Self(tx)
    }
}

/// Implementation of Into<Transaction> for CircuitTransaction
///
/// This allows a CircuitTransaction to be converted back into a Transaction
/// using the Into trait, which enables idiomatic Rust conversions:
/// ```
/// let tx: Transaction = circuit_tx.into();
/// ```
impl Into<Transaction> for CircuitTransaction {
    fn into(self) -> Transaction {
        // Extract and return the inner Transaction
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the transaction ID calculation for a legacy transaction
    ///
    /// This test verifies that our implementation correctly calculates the txid
    /// for a real, non-SegWit transaction from the Bitcoin blockchain.
    /// The test compares our result with the known expected transaction ID.
    /// Note: Bitcoin transaction IDs are typically displayed in little-endian format,
    /// so we reverse our big-endian result for the comparison.
    #[test]
    fn test_txid_legacy() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000").unwrap()).unwrap());
        let mut txid = tx.txid();
        txid.reverse();
        assert_eq!(
            hex::encode(txid),
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
        );
    }

    /// Tests the transaction ID calculation for a SegWit transaction
    ///
    /// This test verifies that our implementation correctly calculates the txid
    /// for a SegWit transaction. For SegWit transactions, the txid excludes
    /// the witness data, which is a key feature of SegWit's transaction
    /// malleability protection.
    #[test]
    fn test_txid_segwit() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000000010142ec43062180882d239799f134f7d8e9d104f37d87643e35fda84c47e4fc67a00000000000ffffffff026734000000000000225120e86c9c8c6777f28af40ef0c4cbd8308d27b60c7adf4f668d2433113616ddaa33cf660000000000001976a9149893ea81967d770f07f9bf0f659e3bce155be99a88ac01418a3d2a2182154dfd083cf48bfcd9f7dfb9d09eb46515e0043cdf39b688e9e711a2ce47f0f535191368be52fd706d77eb82eacd293a6a881491cdadf99b1df4400100000000").unwrap()).unwrap());
        let mut txid = tx.txid();
        txid.reverse();
        assert_eq!(
            hex::encode(txid),
            "a6a150fcdbabaf26040f4dea78ff53d794da2807d8600ead4758b065c5339324"
        );
    }

    /// Tests the witness transaction ID calculation for a legacy transaction
    ///
    /// For non-SegWit transactions, the witness transaction ID (wtxid) should be
    /// identical to the transaction ID (txid). This test verifies that our
    /// implementation correctly calculates the wtxid for a legacy transaction
    /// and matches the result from bitcoin-rs library's computation.
    #[test]
    fn test_wtxid_legacy() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
    }

    /// Tests the witness transaction ID calculation for a SegWit transaction
    ///
    /// For SegWit transactions, the witness transaction ID (wtxid) includes the
    /// witness data, making it different from the transaction ID (txid).
    /// This test verifies that our implementation correctly calculates the
    /// wtxid for a SegWit transaction and matches the result from bitcoin-rs.
    #[test]
    fn test_wtxid_segwit() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0200000000010113e176edfce2e0c7b5971d77dce40a7dc00def275bff7bacdb376f5cd47ba6670200000000ffffffff023d7f0000000000002251202781c84ebc5bce862463b8cd6145d68491c5fa83756562f0b9efc9ec81f7f7080000000000000000076a5d0414011400014016d434ce9d12620cc97e7e443444820c5cdf89b393f8a98cc8c79f0a91e6ba1f58f5e6a98f6a2357406bad50e0fb18abebfc94fb04c7976f2b9d43c8f2f4ef9f00000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
    }

    /// Tests the witness transaction ID calculation for a mixed transaction
    ///
    /// This test verifies the wtxid calculation for a transaction that has
    /// both SegWit and non-SegWit inputs. This is important to validate
    /// that our implementation correctly handles mixed transaction types,
    /// which are common in the Bitcoin blockchain.
    #[test]
    fn test_wtxid_mixed() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000000010259687388210557217699dfd43e04b41511e33aae70e1380d1083bbfb993f12a70100000000ffffffff17ef8a209e53c3b70b8b4944b5418c0c64ae5e515d66cc54675cc8d9348dc4cd000000006b483045022100b3a922bf43654c40377c2a426a081b112304dc3165e0b1428db21c83a8bdb7f502203a143acfb2f869816cf041899f446463ad0cc24c79cf66c51969edcb6e00487d0121026982c4421a2445efdd0162accb013d1feba9b9f84ea2c6057c3a535cf6c2dadbffffffff02f8fe9e0500000000160014eb00eec2dd3a416988f23418003268bdd4ffd400205913000000000017a91479deefa2344faeb4706858b65d9aa5ac00760f2987024830450221008016450ad0999300ad84d24f7ecb275a18b71f8aa70f85a8c64a1c7d5545dd34022033a904f78946d73294151937fb90686864bdb766eccd2c5e764f2be3136097580121032f2b2402a2c4aa07121355378d02f84eb6d17d61b834e51e4a62cab8667440ee0000000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
    }

    /// Tests the From<Transaction> implementation for CircuitTransaction
    ///
    /// This test verifies that a standard Bitcoin transaction can be correctly
    /// converted to a CircuitTransaction using both the From trait and the
    /// from() method. It ensures that the wrapped transaction maintains
    /// the same properties and produces the same transaction ID.
    #[test]
    fn test_from_transaction() {
        let original_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        };

        let bridge_tx = CircuitTransaction::from(original_tx.clone());
        assert_eq!(bridge_tx.inner(), &original_tx);

        let bridge_tx2: CircuitTransaction = original_tx.clone().into();
        assert_eq!(bridge_tx2.inner(), &original_tx);
        assert_eq!(bridge_tx.txid(), bridge_tx2.txid());
        assert_eq!(bridge_tx.txid(), bridge_tx2.txid());
    }

    /// Tests the Into<Transaction> implementation for CircuitTransaction
    ///
    /// This test verifies that a CircuitTransaction can be correctly converted
    /// back to a standard Bitcoin transaction using the Into trait. It ensures
    /// that the conversion preserves the transaction's properties and
    /// produces the same transaction ID.
    #[test]
    fn test_into_transaction() {
        let bridge_tx = CircuitTransaction(Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        });

        let original_tx: Transaction = bridge_tx.clone().into();
        assert_eq!(&original_tx, bridge_tx.inner());
        assert_eq!(original_tx.compute_txid().to_byte_array(), bridge_tx.txid());
    }

    /// Tests the Borsh serialization and deserialization for CircuitTransaction
    ///
    /// This test verifies that a CircuitTransaction can be correctly serialized
    /// to bytes using Borsh, and then deserialized back to a CircuitTransaction
    /// that is equivalent to the original. This is important for ensuring that
    /// transactions can be correctly stored and transmitted in zero-knowledge circuits.
    #[test]
    fn test_borsh_serialization() {
        let original_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        };
        let bridge_tx = CircuitTransaction(original_tx);

        // Serialize
        let serialized = borsh::to_vec(&bridge_tx).unwrap();

        // Deserialize
        let deserialized: CircuitTransaction = borsh::from_slice(&serialized).unwrap();

        assert_eq!(bridge_tx, deserialized);
        assert_eq!(bridge_tx.txid(), deserialized.txid());
    }

    /// Tests the Deref and DerefMut trait implementations for CircuitTransaction
    ///
    /// This test verifies that we can access and modify the inner Transaction
    /// directly through the CircuitTransaction wrapper using the Deref and
    /// DerefMut traits. This provides an ergonomic API that lets users
    /// interact with CircuitTransaction as if it were a regular Transaction.
    #[test]
    fn test_deref_traits() {
        let mut bridge_tx = CircuitTransaction(Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        });

        assert_eq!(bridge_tx.version, Version(1));

        bridge_tx.version = Version(2);
        assert_eq!(bridge_tx.version, Version(2));
    }

    /// Tests handling of a more complex transaction structure
    ///
    /// This test creates a transaction with inputs and outputs, then wraps it
    /// in a CircuitTransaction and verifies that all properties are correctly
    /// maintained, including script signatures, public keys, values, and
    /// transaction IDs.
    #[test]
    fn test_complex_transaction() {
        let script_sig = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);

        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0; 32]),
                    vout: 0,
                },
                script_sig: script_sig.clone(),
                sequence: Sequence(0xffffffff),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: script_pubkey.clone(),
            }],
        };

        let bridge_tx = CircuitTransaction(tx.clone());

        assert_eq!(bridge_tx.version, tx.version);
        assert_eq!(bridge_tx.lock_time, tx.lock_time);
        assert_eq!(bridge_tx.input.len(), 1);
        assert_eq!(bridge_tx.output.len(), 1);
        assert_eq!(bridge_tx.input[0].script_sig, script_sig);
        assert_eq!(bridge_tx.output[0].script_pubkey, script_pubkey);
        assert_eq!(bridge_tx.output[0].value, Amount::from_sat(50000));
        assert_eq!(bridge_tx.txid(), tx.compute_txid().to_byte_array());
    }
}
