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
use bitcoin::blockdata::weight::WITNESS_SCALE_FACTOR;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

use crate::constants::{LOCKTIME_THRESHOLD, SEGWIT_FLAG, SEGWIT_MARKER};
use crate::hashes::calculate_double_sha256;
use crate::utxo_set::UTXO;

// Constants for BIP-68 (Relative timelock)
// These constants are used to decode and interpret the sequence field in transaction inputs

/// Granularity for time-based relative timelocks (2^9 = 512 seconds, approx. 9 minutes)
const SEQUENCE_LOCKTIME_GRANULARITY: u8 = 9;

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
        // println!("[DEBUG] Creating CircuitTransaction from Transaction");
        let result = Self(transaction);
        // println!("[DEBUG] Resulting CircuitTransaction: {:?}", result);
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
        // println!("[DEBUG] Accessing inner Transaction");
        let result = &self.0;
        // println!("[DEBUG] Inner Transaction: {:?}", result);
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
        // println!("[DEBUG] Calculating transaction ID");

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

        // println!("[DEBUG] Transaction ID: {:?}", result);
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
        // println!("[DEBUG] Calculating witness transaction ID");

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

        // println!("{:?}", tx_bytes_vec);

        // Calculate double SHA-256 of the serialized transaction
        let result = calculate_double_sha256(&tx_bytes_vec);

        // println!("[DEBUG] Witness Transaction ID: {:?}", result);
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
        // println!("[DEBUG] Checking if transaction is SegWit");

        // A transaction is SegWit if any input has a non-empty witness
        let result = self
            .inner()
            .input
            .iter()
            .any(|input| !input.witness.is_empty());

        // println!("[DEBUG] Is SegWit: {}", result);
        result
    }

    pub fn check_tx_simple(&self) {
        // Check if inputs are empty
        if self.inner().input.is_empty() {
            panic!("[ERROR] Transaction has no inputs");
        }
        // Check if outputs are empty
        if self.inner().output.is_empty() {
            panic!("[ERROR] Transaction has no outputs");
        }
        // Tx with no witness size check
        if self.base_size() * WITNESS_SCALE_FACTOR > 4_000_000 {
            panic!("[ERROR] Size of transaction without witness is too large");
        }

        // Output amount check
        let mut total_amount: u64 = 0;
        for output in self.output.iter() {
            if output.value.to_sat() > 2_100_000_000_000_000 {
                panic!("[ERROR] Output amount exceeds maximum");
            }
            total_amount += output.value.to_sat();
        }

        // Total amount check
        if total_amount > 2_100_000_000_000_000 {
            panic!("[ERROR] Total amount exceeds maximum");
        }

        // Inputs duplicate check
        let mut seen_inputs = std::collections::HashSet::new();
        for input in self.inner().input.iter() {
            if seen_inputs.contains(&input.previous_output) {
                panic!("[ERROR] Duplicate input found");
            }
            seen_inputs.insert(input.previous_output);
        }

        if self.is_coinbase() {
            let script_len = self.input[0].script_sig.len();
            if script_len < 2 || script_len > 100 {
                panic!("Coinbase script length out of range");
            }
        } else {
            for input in self.input.iter() {
                if input.previous_output.is_null() {
                    panic!("Null previous output");
                }
            }
        }
    }

    /// Does not include both block_time and median_time_past as which one will be used is already checked
    pub fn verify_final_tx(&self, time_to_compare: u32, block_height: u32) {
        // println!("[DEBUG] Checking if transaction is final");

        let lock_time = self.0.lock_time.to_consensus_u32();

        if lock_time == 0 {
            return;
        }

        if (lock_time < LOCKTIME_THRESHOLD && lock_time <= block_height)
            || (lock_time >= LOCKTIME_THRESHOLD && lock_time < time_to_compare)
        {
            return;
        }

        for txin in &self.0.input {
            if txin.sequence != Sequence::MAX {
                panic!("[ERROR] Transaction is not final");
            }
        }
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
        is_bip68_active: bool,
        prevouts: &Vec<UTXO>,
    ) -> (u32, u32) {
        // println!("[DEBUG] Calculating sequence locks");

        // Ensure we have height information for each input
        assert_eq!(prevouts.len(), self.0.input.len());

        // Will be set to the equivalent height- and time-based nLockTime values
        // that would be necessary to satisfy all relative lock-time constraints.
        // The semantics of nLockTime are the last invalid height/time, so
        // use -1 to have the effect of any height or time being valid.
        let mut min_height = 0;
        let mut min_time = 0;

        // BIP-68 only applies to transactions version 2 or higher
        // and only when LOCKTIME_VERIFY_SEQUENCE flag is set
        let enforce_bip68 = self.0.version.0 >= 2 && is_bip68_active;

        // Skip processing if BIP-68 is not being enforced
        if !enforce_bip68 {
            return (min_height, min_time);
        }

        // Process each input to find the most restrictive timelock
        for (txin_index, txin) in self.0.input.iter().enumerate() {
            // Sequence numbers with the most significant bit set are not
            // treated as relative lock-times
            if !txin.sequence.is_relative_lock_time() {
                // The height of this input is not relevant for sequence locks
                continue;
            }

            // Get the height of the block containing the spent output
            let coin_height = prevouts[txin_index].block_height;
            let coin_time = prevouts[txin_index].block_time;

            // let time_lock = txin.sequence.to_relative_lock_time();

            // Check if this is a time-based relative lock time (bit 22 set)
            if txin.sequence.is_time_locked() {
                // Calculate the lock time in seconds
                // The 16-bit mask is shifted by the granularity (9 bits = 512 seconds)
                let sequence_locked_seconds =
                    (txin.sequence.0 & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY;
                println!(
                    "[DEBUG] Sequence locked seconds: {}",
                    sequence_locked_seconds
                );

                // Relative timelock must exist and it should be in seconds
                // let time_lock_seconds = time_lock.expect("Time lock should be in seconds");

                // Calculate when this input can be spent
                // NOTE: Subtract 1 to maintain nLockTime semantics (last invalid time)
                let new_min_time = coin_time + (sequence_locked_seconds) - 1;

                // Keep track of the most restrictive timelock
                min_time = std::cmp::max(min_time, new_min_time);
            } else {
                // Height-based relative lock time (bit 22 not set)
                // The 16-bit mask gives the number of blocks directly
                let sequence_locked_height = txin.sequence.0 & SEQUENCE_LOCKTIME_MASK;

                // Calculate when this input can be spent
                // NOTE: Subtract 1 to maintain nLockTime semantics (last invalid height)
                let new_min_height = coin_height + sequence_locked_height - 1;

                // Keep track of the most restrictive timelock
                min_height = std::cmp::max(min_height, new_min_height);
            }
        }

        let result = (min_height, min_time);
        // println!("[DEBUG] Sequence Locks: {:?}", result);
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
        block_height: u32,
        median_time_past: u32,
        lock_pair: (u32, u32),
    ) -> bool {
        // println!("[DEBUG] Evaluating sequence locks");

        // Get current block time (median time past)
        // let block_time = get_median_time_past(block);

        // Check if either the height or time lock requirement hasn't been met
        // The locks specify the last invalid block/time, so the current block/time
        // must be strictly greater to be valid
        if lock_pair.0 >= block_height || lock_pair.1 >= median_time_past {
            return false;
        }

        // All sequence locks are satisfied
        let result = true;
        // println!("[DEBUG] Sequence Locks Satisfied: {}", result);
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
        is_bip68_active: bool,
        prevouts: &Vec<UTXO>,
        median_time_past: u32,
        block_height: u32,
    ) {
        // println!("[DEBUG] Checking sequence locks");

        // First, calculate the sequence locks
        let lock_pair = self.calculate_sequence_locks(is_bip68_active, prevouts);

        // Then, evaluate if they're satisfied
        let result = Self::evaluate_sequence_locks(block_height, median_time_past, lock_pair);

        if !result {
            println!("Txid: {:?}", self.txid());
            panic!("[ERROR] Sequence locks not satisfied");
        }
    }
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
    use bitcoin::block::Header;

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

    #[test]
    fn test_wtxid_legacy() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
    }

    #[test]
    fn test_wtxid_segwit() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0200000000010113e176edfce2e0c7b5971d77dce40a7dc00def275bff7bacdb376f5cd47ba6670200000000ffffffff023d7f0000000000002251202781c84ebc5bce862463b8cd6145d68491c5fa83756562f0b9efc9ec81f7f7080000000000000000076a5d0414011400014016d434ce9d12620cc97e7e443444820c5cdf89b393f8a98cc8c79f0a91e6ba1f58f5e6a98f6a2357406bad50e0fb18abebfc94fb04c7976f2b9d43c8f2f4ef9f00000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
    }

    #[test]
    fn test_wtxid_mixed() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000000010259687388210557217699dfd43e04b41511e33aae70e1380d1083bbfb993f12a70100000000ffffffff17ef8a209e53c3b70b8b4944b5418c0c64ae5e515d66cc54675cc8d9348dc4cd000000006b483045022100b3a922bf43654c40377c2a426a081b112304dc3165e0b1428db21c83a8bdb7f502203a143acfb2f869816cf041899f446463ad0cc24c79cf66c51969edcb6e00487d0121026982c4421a2445efdd0162accb013d1feba9b9f84ea2c6057c3a535cf6c2dadbffffffff02f8fe9e0500000000160014eb00eec2dd3a416988f23418003268bdd4ffd400205913000000000017a91479deefa2344faeb4706858b65d9aa5ac00760f2987024830450221008016450ad0999300ad84d24f7ecb275a18b71f8aa70f85a8c64a1c7d5545dd34022033a904f78946d73294151937fb90686864bdb766eccd2c5e764f2be3136097580121032f2b2402a2c4aa07121355378d02f84eb6d17d61b834e51e4a62cab8667440ee0000000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
    }

    #[test]
    fn test_wtxid_txid_wrapped_segwit_p2wsh() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("02000000000101274d91a28c19b438dca594861904754fc3f6fd20596dae920fc84f1dd604467d00000000232200209e10c2e5f987892dc244c68c0976d7372560c7a2eb66a1eca50b72fe91273356fdffffff01d32601000000000017a914e7d5b5e0e78e62a2b5ec1992fcdff29b3592f19287054730440220313bbf45eb48c441e03c71c2ce4a521d6333505f05606c493cd5af6c9184669702200d4ef55a5119d9c99600ece27dd23a2e3100e955dd6d760113eee2ea03d51821012103e883d861ed309b2cf4ac1c55e718d7e74ac29588b4cf67806ae141a1b89147ed2103d456243e3f0514c72c12955685d5e5a9ea11e6411f14c9ed55fc52df832476050101c67651876375146c6c16edcbe7affb09db27ccce423fcbdd5eee3414ff71d1b07938f5d851cfef7048d4c302bf1254da677652876375146c6c16edcbe7affb09db27ccce423fcbdd5eee34146e1b083c68550638432760aaf567c81fe8ad1e1167765387637514eb632ddb345d69dff5c949947eca73d17984909b14a6f90bf7f475e8db549aa309cdfd70bb7e1d1c2067548814eb632ddb345d69dff5c949947eca73d17984909b14f2fe3a09eb39336280602725a14aa9cb9a9912e16868687ba98878a988ac00000000").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
        let txid = tx.txid();
        let bitcoin_txid: [u8; 32] = tx.0.compute_txid().to_byte_array();
        assert_eq!(txid, bitcoin_txid);
    }

    #[test]
    fn test_wtxid_txid_wrapped_segwit_p2wpkh() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0200000000010137a30260883b90a1181a364df7695f527d951b726942cc889db3cbefedd81f840000000017160014488f02106cac5c542291e1a94853556b7ac8c630fdffffff0244a90100000000001976a914b90702429b6c012f101fbda7306b44014f196d9788acccee8506000000001976a914c3c419a17435cd45f1ecd7d77f72bebd9eb3795388ac02473044022035359460f33455858dfe534dbb4bd85ba28d22a27ebdbe194b3e1a5aed08520e022043e9dfeddda7c3838bf8b83ba5f6dc4833bdef7c26c5109a2b2a3426617383b0012102cf7b0a6b9d72e4e193fabe6c4adc9660f238d764afac947933fde2ddc1d6fea250a80d00").unwrap()).unwrap());
        let wtxid = tx.wtxid();
        let bitcoin_wtxid: [u8; 32] = tx.0.compute_wtxid().to_byte_array();
        assert_eq!(wtxid, bitcoin_wtxid);
        let txid = tx.txid();
        let bitcoin_txid: [u8; 32] = tx.0.compute_txid().to_byte_array();
        assert_eq!(txid, bitcoin_txid);
    }

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

    #[test]
    fn test_sequence_locks() {
        let header_15: Header = bitcoin::consensus::deserialize(&hex::decode("00000020646781e6eab68bc63f8f44646990cd9fe7739286c7802a425c7fd76e00000000dce4ea98c6e9e7cda7d223a4a3958adc05469b0a01a7352ecfb6022b6f3e5bad9cc1ad67ffff001d6a1bdaa0").unwrap()).unwrap(); // Tx block
        let header_14: Header = bitcoin::consensus::deserialize(&hex::decode("000000204c4879a4f1957c363a5298c80083fdfe35e390a99668a5ade4c951a900000000490359eed7e3d0f8912d7da2a9e6deacf926ef7782ed40687b2a32c2a9b78539ebbcad67ffff001d4ed447d1").unwrap()).unwrap();
        let header_13: Header = bitcoin::consensus::deserialize(&hex::decode("000000202642f6d2ffcba6ccf647de97d0b1f5c709b435870e419663f32800e600000000d253595bb5ffae226cf30ca576a5f418da81ec5d6214c5630f65f8114e3de4643ab8ad67ffff001d0c983cc0").unwrap()).unwrap();
        let header_12: Header = bitcoin::consensus::deserialize(&hex::decode("0000002025d07e712f9c2ff76e9c7a45822a10a3b054d5667d16d7f3e0ca53e600000000b4277cee26e44fbc5983762efc0f31bed2624c03938838b3f0495829862c8eba89b3ad67ffff001d0e9209a2").unwrap()).unwrap();
        let header_11: Header = bitcoin::consensus::deserialize(&hex::decode("0000002025b2a397efe878cf99e4816049e2e901ebdf47114eb6364ad85a870b00000000e7728ec4373a169117a947e33aaee06ee8c553507b202cdaea2a3b831a7e56c4d8aead67ffff001d8e67cfd6").unwrap()).unwrap(); // Prevouts[1..4] block
        let header_10: Header = bitcoin::consensus::deserialize(&hex::decode("00000020600fe8487479569e5aa939e3c93bce822445eb7ab65865b3b16c49cc000000000cb3e1e20f23ea4bc25c1b3badc8b311102e24659135cea989f842ad76ec940027aaad67ffff001d3d0613b7").unwrap()).unwrap();
        let header_9: Header = bitcoin::consensus::deserialize(&hex::decode("0000002093ea53c6bb156b1a54af21af98891810da3ea197cb7e27690dcc247f000000004ec077d63731a638dc75bdd1590eea8b464f681842e69a637c81bdecf8738cba76a5ad67ffff001d40162c9a").unwrap()).unwrap();
        let header_8: Header = bitcoin::consensus::deserialize(&hex::decode("0000002069fc3a5b02012015a74085ebd6566297c1977d88236d792b9bab94d6000000004027cf2741daac5482e9b5169086c43f417a351e8f639d2a565b6865d91edf79c5a0ad67ffff001d44d0fba6").unwrap()).unwrap();
        let header_7: Header = bitcoin::consensus::deserialize(&hex::decode("0000002068e33b5a84f0cee8d956de3b8b49e632665c8299fb100c0a7e8ea2b2000000007157e0ec7b053a91bfcf943176a9925b8af9ba59dc69cb59f676d9ad5def5dfb149cad67ffff001d50580746").unwrap()).unwrap();
        let header_6: Header = bitcoin::consensus::deserialize(&hex::decode("000000204224edd0e6859817d153c5f3f2889ce5419d742511d0779772e93cdf00000000b7aa52b76d90f397a326a26b4fb0463f38cff763aaf896673ebf2d1ee2c51bb36397ad67ffff001d1f35c057").unwrap()).unwrap();
        let header_5: Header = bitcoin::consensus::deserialize(&hex::decode("00000020118f5f386fe3604f38e0e4d6414bc1dd8ac0aa3c5097a7ed4f4ab878000000008c81410f53117093d747dd67014b9eb507cd556c81ffb35a19bc8482541a5fe2b292ad67ffff001daccdb197").unwrap()).unwrap();
        let header_4: Header = bitcoin::consensus::deserialize(&hex::decode("00000020fb98eac85822a26124bca95cf51170367ea33f6ddd6e813ade2bf2b100000000b21438c0a682cdcccbdb0247db2da55d29af02d06726b59b786601a6ff0ce7eb018ead67ffff001d322eab99").unwrap()).unwrap();
        let header_3: Header = bitcoin::consensus::deserialize(&hex::decode("000000206dfad61b027824a71c461eb4b52c7b5394560a3df1745747923c1b07000000008a9085eda6256dc0f93f8c1c2383831c62f55de780ab866b313d6ce080e285fb5089ad67ffff001d10b9bafb").unwrap()).unwrap();
        let header_2: Header = bitcoin::consensus::deserialize(&hex::decode("0000002061377b362de02aacaf00bb78c38cc71e119ffea8ac6e42b29418774b00000000639a8b1e3eece1a67775dcc515a26161e210a314c782071dbff37856653da5549f84ad67ffff001d29a22858").unwrap()).unwrap();
        let header_1: Header = bitcoin::consensus::deserialize(&hex::decode("00000020c0d91a803d4172159f428971634f16ffdb8bbf9187760bfdbf0a5dd700000000cfc4046ef47f6324ec0ef4f38658f1e93d0ac8835c1885873092b7128b178681ee7fad67ffff001d247dcb7a").unwrap()).unwrap();
        let header_0: Header = bitcoin::consensus::deserialize(&hex::decode("00000020a1400b04d2c4919f1cadff2a9d4153030be8cd46c17eca69f36fb0850000000090797454023d3c03bcb917fe8d5e2a8aad6538d4408bf90c75a5ab98d1c6aa053d7bad67ffff001d2a7a10b1").unwrap()).unwrap();
        println!("block header: {:?}", header_11);
        let timestamps = vec![
            header_15.time,
            header_14.time,
            header_13.time,
            header_12.time,
            header_11.time,
            header_10.time,
            header_9.time,
            header_8.time,
            header_7.time,
            header_6.time,
            header_5.time,
            header_4.time,
            header_3.time,
            header_2.time,
            header_1.time,
            header_0.time,
        ];
        let mut mine_timestamps = timestamps[5..16].to_vec();
        let mut spend_timestamps = timestamps[1..12].to_vec();
        mine_timestamps.sort_by(|a, b| a.cmp(b));
        spend_timestamps.sort_by(|a, b| a.cmp(b));
        let mine_median_time_past = mine_timestamps[5];
        let spend_median_time_past = spend_timestamps[5];
        println!("mine median time past: {:?}", mine_median_time_past);
        println!("spend median time past: {:?}", spend_median_time_past);
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("020000000001040eccb5b2036e90b63a8cb94bebb26f0013b57b8d59fcfe422719ca86073a7a430000000000ffffffffdc9a1e2bbe43cbf132716bc72b9958456b71f58a025c220cb39b4815e74cfc94000000000004004000dc9a1e2bbe43cbf132716bc72b9958456b71f58a025c220cb39b4815e74cfc940100000000ffffffffdc9a1e2bbe43cbf132716bc72b9958456b71f58a025c220cb39b4815e74cfc940200000000ffffffff024c1d0000000000002251200e9f8622c811a7c0c082bd0e2b8db205db4c1877a22a02165a148f9ec785eaee4c5400000000000022512055adedbbc065b351050eb29627ba5ca3bb7134268a396a69e2b6d5d6f9ff650404004730440220051de5717227b3bd3ca4ba46b788082c4fab9e54b7e42f0b66f2c953a3e22fd102203922cf5cddb17e64f8d518c21365e859ca2150799a8469c533a561c971f7339e01473044022029a3e859b3519d30f9265f4396b916f67346a8a832d43f9b1341f63895f4fc660220156b73976aa440aeeef1247eabad347e4ef76b2835670e57d262c193d50a272b83475221038d165da47910f53d3e75aff5e7b0e2b9ee6f13474b885fea8adb8a07e9d5b267210381071665ea05c9099246e1aa66a6bd8c613e974ce64bac7bb3705f8d214dcc9c52ae03483045022100b46d3051c53db81162c861aac98b8c299c2ec4dffa9e6672639a6f85f9f2742d02201e402777b1e07c69bacd436785165c1f8de2c1cc031d3e38ae4e6e977dec6570812102764658d172abdc24bfbda77205657ee389cb8946def560ed2c40722f3ed9910b1f03040040b27576a914724e8781e249014c488a8d286823f17d02e4035e88ac030047304402202a516794326e250af20c333267283e6736dcd375c72f7bae1577137181b3ab86022006b40cb8e939c80b153fba36f392ac81d26e02b1d52cc1fb0704bdcb0c8a6ea201255121038d165da47910f53d3e75aff5e7b0e2b9ee6f13474b885fea8adb8a07e9d5b26751ae0300483045022100cf31f924bd507ba0a49ef87635d8641730dfa333702a7437f41b71633f0c2fa2022060bf3ff9f517f12c30dc5c8f7728ed2da4095c013f77819ffa055ec4eba80bf301255121038d165da47910f53d3e75aff5e7b0e2b9ee6f13474b885fea8adb8a07e9d5b26751ae00000000").unwrap()).unwrap());
        println!("sequence: {:?}", tx.0.input[1].sequence);
        println!(
            "is relative time lock enabled: {:?}",
            tx.0.input[1].sequence.is_relative_lock_time()
        );
        println!(
            "relative time lock is time related: {:?}",
            tx.0.input[1].sequence.is_time_locked()
        );
        println!(
            "relative time lock is height related: {:?}",
            tx.0.input[1].sequence.is_height_locked()
        );
        println!(
            "Until when: {:?}",
            tx.0.input[1].sequence.to_relative_lock_time()
        );
        let prev_txout_0: TxOut = bitcoin::consensus::deserialize(&hex::decode("4c1d000000000000220020f810c8d49dc97cfeb79898d977836e52ccadafcfd3cb40032fc4ea3a5853c4aa").unwrap()).unwrap();
        let prev_txout_1: TxOut = bitcoin::consensus::deserialize(&hex::decode("e8030000000000002200201914b2d53b2c29defe55c7d94d2ea6aedd7c99106c7c6a94c330f444c57b4691").unwrap()).unwrap();
        let prev_txout_2: TxOut = bitcoin::consensus::deserialize(&hex::decode("e80300000000000022002058e7198cb5dd8c6302a2976a20595317c4767e3da595f8e7e512b3aa121b11fe").unwrap()).unwrap();
        let prev_txout_3: TxOut = bitcoin::consensus::deserialize(&hex::decode("204e00000000000022002058e7198cb5dd8c6302a2976a20595317c4767e3da595f8e7e512b3aa121b11fe").unwrap()).unwrap();
        let prevouts = vec![
            UTXO {
                value: prev_txout_0.value.to_sat(),
                block_height: 69803,
                block_time: 0, // Irrelevant for this test
                is_coinbase: false,
                script_pubkey: prev_txout_0.script_pubkey.to_bytes(),
            },
            UTXO {
                value: prev_txout_1.value.to_sat(),
                block_height: 69909,
                block_time: mine_median_time_past,
                is_coinbase: false,
                script_pubkey: prev_txout_1.script_pubkey.to_bytes(),
            },
            UTXO {
                value: prev_txout_2.value.to_sat(),
                block_height: 69909,
                block_time: mine_median_time_past,
                is_coinbase: false,
                script_pubkey: prev_txout_2.script_pubkey.to_bytes(),
            },
            UTXO {
                value: prev_txout_3.value.to_sat(),
                block_height: 69909,
                block_time: mine_median_time_past,
                is_coinbase: false,
                script_pubkey: prev_txout_3.script_pubkey.to_bytes(),
            },
        ];

        let (min_height, min_time) = tx.calculate_sequence_locks(true, &prevouts);
        println!("Minimum height: {}", min_height);
        println!("Minimum time: {}", min_time);

        tx.sequence_locks(true, &prevouts, spend_median_time_past, 69913);
    }
}
