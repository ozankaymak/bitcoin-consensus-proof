use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
/// Code is taken from Citrea
/// https://github.com/chainwayxyz/citrea/blob/0acb887b1a766fac1a482a68c6d51ecf9661f538/crates/bitcoin-da/src/spec/transaction.rs
///
///
use std::ops::{Deref, DerefMut};

use crate::constants::{LOCKTIME_THRESHOLD, SEGWIT_FLAG, SEGWIT_MARKER};
use crate::hashes::calculate_double_sha256;
use crate::header_chain::CircuitBlockHeader;

// Constants for sequence locktime (BIP68)
const LOCKTIME_VERIFY_SEQUENCE: u32 = 0x00000080;
const SEQUENCE_LOCKTIME_GRANULARITY: u8 = 9;
const SEQUENCE_LOCKTIME_DISABLED: u32 = 0x80000000;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 0x00400000;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct CircuitTransaction(pub Transaction);

impl CircuitTransaction {
    pub fn from(transaction: Transaction) -> Self {
        Self(transaction)
    }

    pub fn inner(&self) -> &Transaction {
        &self.0
    }

    /// Returns the transaction id, in big-endian byte order. One must be careful when dealing with
    /// Bitcoin transaction ids, as they are little-endian in the Bitcoin protocol.
    pub fn txid(&self) -> [u8; 32] {
        let mut tx_bytes_vec = vec![];
        self.inner()
            .version
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .input
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .output
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .lock_time
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        calculate_double_sha256(&tx_bytes_vec)
    }

    /// Returns the witness-transaction id, in big-endian byte order. One must be careful when dealing with
    /// Bitcoin transaction ids, as they are little-endian in the Bitcoin protocol.
    /// the witness-transaction id of the coinbase transaction is assumed to be "0x0000000000000000000000000000000000000000000000000000000000000000"
    pub fn wtxid(&self) -> [u8; 32] {
        if self.is_coinbase() {
            return [0; 32];
        }
        let mut tx_bytes_vec = vec![];
        self.inner()
            .version
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        // If at least one witness is nonempty, then it is a segwit tx
        // Otherwise, it is a legacy tx
        if self.is_segwit() {
            tx_bytes_vec.push(SEGWIT_MARKER);
            tx_bytes_vec.push(SEGWIT_FLAG);
        }
        self.inner()
            .input
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .output
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        if self.is_segwit() {
            for input in &self.inner().input {
                input.witness.consensus_encode(&mut tx_bytes_vec).unwrap();
            }
        }
        self.inner()
            .lock_time
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        println!("{:?}", tx_bytes_vec);
        calculate_double_sha256(&tx_bytes_vec)
    }

    pub fn is_segwit(&self) -> bool {
        self.inner()
            .input
            .iter()
            .any(|input| !input.witness.is_empty())
    }

    /// Determines if transaction is final using Bitcoin Core's IsFinalTx logic
    pub fn is_final_tx(&self, block_height: i32, block_time: i64) -> bool {
        // If nLockTime is 0, transaction is final
        if self.0.lock_time.to_consensus_u32() == 0 {
            return true;
        }

        // Otherwise check if lock time is satisfied by height/time
        let lock_time_u32 = self.0.lock_time.to_consensus_u32();
        let lock_time_i64 = lock_time_u32 as i64;

        // Check if locktime is satisfied
        if (lock_time_u32 < LOCKTIME_THRESHOLD && lock_time_i64 < block_height as i64)
            || (lock_time_u32 >= LOCKTIME_THRESHOLD && lock_time_i64 < block_time)
        {
            return true;
        }

        // Transaction is still considered final if all inputs have SEQUENCE_FINAL
        for txin in &self.0.input {
            if txin.sequence != Sequence::MAX {
                return false;
            }
        }

        true
    }

    /// Calculate sequence locks based on BIP68
    pub fn calculate_sequence_locks(
        &self,
        flags: u32,
        prev_heights: &mut Vec<i32>,
        block: &CircuitBlockHeader,
    ) -> (i32, i64) {
        assert_eq!(prev_heights.len(), self.0.input.len());

        // Will be set to the equivalent height- and time-based nLockTime
        // values that would be necessary to satisfy all relative lock-
        // time constraints given our view of block chain history.
        // The semantics of nLockTime are the last invalid height/time, so
        // use -1 to have the effect of any height or time being valid.
        let mut min_height = -1;
        let mut min_time = -1;

        // BIP68 only applies to transactions version 2 or higher
        let enforce_bip68 = self.0.version.0 >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE != 0;

        // Do not enforce sequence numbers as a relative lock time
        // unless we have been instructed to
        if !enforce_bip68 {
            return (min_height, min_time);
        }

        for (txin_index, txin) in self.0.input.iter().enumerate() {
            // Sequence numbers with the most significant bit set are not
            // treated as relative lock-times, nor are they given any
            // consensus-enforced meaning at this point.
            if (txin.sequence.0 & SEQUENCE_LOCKTIME_DISABLED) != 0 {
                // The height of this input is not relevant for sequence locks
                prev_heights[txin_index] = 0;
                continue;
            }

            let coin_height = prev_heights[txin_index];

            // Check if this is a time-based relative lock time
            if (txin.sequence.0 & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0 {
                // Time-based relative lock-times are measured from the
                // smallest allowed timestamp of the block containing the
                // txout being spent, which is the median time past of the
                // block prior.
                let coin_time =
                    get_median_time_past_for_height(block, std::cmp::max(coin_height - 1, 0));

                // NOTE: Subtract 1 to maintain nLockTime semantics
                // BIP 68 relative lock times have the semantics of calculating
                // the first block or time at which the transaction would be
                // valid. When calculating the effective block time or height
                // for the entire transaction, we switch to using the
                // semantics of nLockTime which is the last invalid block
                // time or height. Thus we subtract 1 from the calculated
                // time or height.
                let sequence_locked_seconds =
                    (txin.sequence.0 & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY;
                let new_min_time = coin_time + (sequence_locked_seconds as i64) - 1;
                min_time = std::cmp::max(min_time, new_min_time);
            } else {
                // Height-based relative lock time
                // NOTE: Subtract 1 to maintain nLockTime semantics
                let sequence_locked_height = (txin.sequence.0 & SEQUENCE_LOCKTIME_MASK) as i32;
                let new_min_height = coin_height + sequence_locked_height - 1;
                min_height = std::cmp::max(min_height, new_min_height);
            }
        }

        (min_height, min_time)
    }

    /// Evaluate whether the sequence locks are satisfied
    pub fn evaluate_sequence_locks(
        block: &CircuitBlockHeader,
        block_height: i32,
        lock_pair: (i32, i64),
    ) -> bool {
        // Get current block time
        let block_time = get_median_time_past(block);

        // Check if the lock requirements exceed current height/time
        if lock_pair.0 >= block_height || lock_pair.1 >= block_time {
            return false;
        }

        true
    }

    /// Check sequence locks
    pub fn sequence_locks(
        &self,
        flags: u32,
        prev_heights: &mut Vec<i32>,
        block: &CircuitBlockHeader,
        block_height: i32,
    ) -> bool {
        let lock_pair = self.calculate_sequence_locks(flags, prev_heights, block);
        Self::evaluate_sequence_locks(block, block_height, lock_pair)
    }
}

// Helper functions for timelock operations

/// Get median time past for a block at the given height
/// This is a placeholder and would need to be implemented based on your blockchain access
fn get_median_time_past_for_height(header: &CircuitBlockHeader, height: i32) -> i64 {
    // In a real implementation, this would look up the block at the given height
    // and return its median time past (the median of the last 11 blocks' timestamps)
    // For now, we'll just return the block's timestamp
    header.time as i64
}

/// Get median time past for a block
fn get_median_time_past(header: &CircuitBlockHeader) -> i64 {
    // In a real implementation, this would return the median time past of the block
    // which is the median of the last 11 blocks' timestamps
    // For now, we'll just return the block's timestamp
    header.time as i64
}

impl BorshSerialize for CircuitTransaction {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0.version.0, writer)?;
        BorshSerialize::serialize(&self.0.lock_time.to_consensus_u32(), writer)?;
        BorshSerialize::serialize(&self.0.input.len(), writer)?;
        for input in &self.0.input {
            serialize_txin(input, writer)?;
        }
        BorshSerialize::serialize(&self.0.output.len(), writer)?;
        for output in &self.0.output {
            serialize_txout(output, writer)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for CircuitTransaction {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let version = Version(i32::deserialize_reader(reader)?);
        let lock_time = LockTime::from_consensus(u32::deserialize_reader(reader)?);
        let input_len = usize::deserialize_reader(reader)?;
        let mut input = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            input.push(deserialize_txin(reader)?);
        }
        let output_len = usize::deserialize_reader(reader)?;
        let mut output = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            output.push(deserialize_txout(reader)?);
        }

        let tx = Transaction {
            version,
            lock_time,
            input,
            output,
        };

        Ok(Self(tx))
    }
}

fn serialize_txin<W: borsh::io::Write>(txin: &TxIn, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txin.previous_output.txid.to_byte_array(), writer)?;
    BorshSerialize::serialize(&txin.previous_output.vout, writer)?;
    BorshSerialize::serialize(&txin.script_sig.as_bytes(), writer)?;
    BorshSerialize::serialize(&txin.sequence.0, writer)?;
    BorshSerialize::serialize(&txin.witness.to_vec(), writer)
}

fn deserialize_txin<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxIn> {
    let txid = bitcoin::Txid::from_byte_array(<[u8; 32]>::deserialize_reader(reader)?);
    let vout = u32::deserialize_reader(reader)?;
    let script_sig = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);
    let sequence = Sequence(u32::deserialize_reader(reader)?);
    let witness = Witness::from(Vec::<Vec<u8>>::deserialize_reader(reader)?);

    Ok(TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig,
        sequence,
        witness,
    })
}

fn serialize_txout<W: borsh::io::Write>(txout: &TxOut, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txout.value.to_sat(), writer)?;
    BorshSerialize::serialize(&txout.script_pubkey.as_bytes(), writer)
}

fn deserialize_txout<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxOut> {
    let value = Amount::from_sat(u64::deserialize_reader(reader)?);
    let script_pubkey = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);

    Ok(TxOut {
        value,
        script_pubkey,
    })
}

impl Deref for CircuitTransaction {
    type Target = Transaction;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CircuitTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Transaction> for CircuitTransaction {
    fn from(tx: Transaction) -> Self {
        Self(tx)
    }
}

impl Into<Transaction> for CircuitTransaction {
    fn into(self) -> Transaction {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
