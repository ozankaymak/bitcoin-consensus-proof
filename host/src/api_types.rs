use serde::{Serialize, Deserialize};
// Consider adding other necessary imports, e.g., for hex encoding/decoding if not handled by a wrapper.

/// Represents the ZK proof and its associated metadata.
/// This is what the server provides when a client asks for the latest proof.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofResponse {
    /// A unique identifier for this proof instance (e.g., a hash of the proof,
    /// the block hash it corresponds to, or a sequence number).
    pub proof_id: String,
    /// The hex-encoded RISC Zero Verifier Receipt.
    /// The client will use this to verify the ZK proof.
    pub risc0_receipt_hex: String,
    /// The hex-encoded journal output from the RISC Zero guest program.
    /// This journal is expected to contain the JMT root of the UTXO set.
    pub journal_hex: String,
    /// The JMT root of the UTXO set as claimed by this proof's journal.
    /// Extracted for client convenience and cross-checking.
    pub jmt_root_hex: String,
    /// The Bitcoin block height to which this proof and UTXO set correspond.
    pub block_height: u64,
    /// The Bitcoin block hash (hex-encoded) to which this proof and UTXO set correspond.
    pub block_hash_hex: String,
    // Potentially other metadata like timestamp of proof generation, etc.
}

/// Represents a single UTXO entry for constructing or updating the JMT.
/// The key is typically a serialized Bitcoin OutPoint (txid:vout).
/// The value is typically a serialized Bitcoin TxOut (value, scriptPubKey) or other relevant UTXO data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct JmtUtxoEntry {
    /// Hex-encoded key of the UTXO (e.g., serialized OutPoint).
    pub key_hex: String,
    /// Hex-encoded value of the UTXO (e.g., serialized TxOut data).
    /// This could also be a hash of the value if only existence is proven for some leaves.
    pub value_hex: String,
}

/// Request from the client for UTXO/JMT data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JmtSyncRequest {
    /// The JMT root the client wants to synchronize its UTXO set to.
    /// This should match a `jmt_root_hex` from a successfully verified `ProofResponse`.
    pub target_jmt_root_hex: String,
    /// The client's last known JMT root (hex-encoded, if any).
    /// If `None`, the client is requesting a full JMT dump.
    /// If `Some(...)`, the client is requesting a delta from this known root.
    pub last_known_jmt_root_hex: Option<String>,
}

/// Response from the server containing JMT data.
/// The `serde(tag = "sync_type")` attribute creates a "sync_type" field in the JSON
/// output, which helps the client distinguish between the variants.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sync_type")]
pub enum JmtSyncResponse {
    /// Contains all JMT elements needed to reconstruct the JMT for the `target_jmt_root_hex`.
    Full {
        target_jmt_root_hex: String,
        /// A list of all UTXO entries (key-value pairs). The client uses these to build its JMT
        /// from scratch and verify it matches `target_jmt_root_hex`.
        elements: Vec<JmtUtxoEntry>,
    },
    /// Contains the changes (updates/additions and deletions) to transition
    /// from the client's `last_known_jmt_root_hex` to the `target_jmt_root_hex`.
    Delta {
        from_jmt_root_hex: String,
        to_jmt_root_hex: String,
        /// UTXO entries that were added or whose values changed since `from_jmt_root_hex`.
        updates: Vec<JmtUtxoEntry>,
        /// Hex-encoded keys of UTXO entries that were removed since `from_jmt_root_hex`.
        deletions: Vec<String>, // Keys are sufficient for deletion
    },
    /// Indicates that the client's `last_known_jmt_root_hex` is already the current target.
    NoChange {
        jmt_root_hex: String,
    },
    /// Used if there's an error processing the request (e.g., unknown JMT root, internal error).
    Error {
        message: String,
    },
}