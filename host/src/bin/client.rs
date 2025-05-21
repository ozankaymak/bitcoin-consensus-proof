// host/src/bin/client.rs

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hex;
use risc0_zkvm::{sha::DigestWords, Digest, Journal, Receipt}; // For Receipt verification, Journal parsing, and Digest types
use rs_merkle::{Hasher, MerkleTree}; // Assuming server uses this for JMT. MerkleProof might be needed for other client features.
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2DigestTrait, Sha256}; // Renamed Digest to avoid conflict with risc0_zkvm::Digest
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tokio;

// --- API Data Structures (copied from Canvas design for self-containment) ---
// Ideally, these would be in a shared module like `host::api_types`

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofResponse {
    pub proof_id: String,
    pub risc0_receipt_hex: String,
    pub journal_hex: String,
    pub jmt_root_hex: String,
    pub block_height: u64,
    pub block_hash_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct JmtUtxoEntry {
    pub key_hex: String,
    pub value_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JmtSyncRequest {
    pub target_jmt_root_hex: String,
    pub last_known_jmt_root_hex: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sync_type")]
pub enum JmtSyncResponse {
    Full {
        target_jmt_root_hex: String,
        elements: Vec<JmtUtxoEntry>,
    },
    Delta {
        from_jmt_root_hex: String,
        to_jmt_root_hex: String,
        updates: Vec<JmtUtxoEntry>,
        deletions: Vec<String>,
    },
    NoChange {
        jmt_root_hex: String,
    },
    Error {
        message: String,
    },
}

// --- Client State ---

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct ClientState {
    last_known_jmt_root_hex: Option<String>,
    last_known_block_height: Option<u64>,
    last_known_block_hash_hex: Option<String>,
    // For simplicity, storing UTXOs directly. A real client would use a proper JMT data structure.
    // Key: UTXO key (hex), Value: UTXO value (hex)
    local_utxos: HashMap<String, String>,
    // Optionally, store the trusted ImageID if it's configured at runtime
    // trusted_image_id_hex: Option<String>,
}

const CLIENT_STATE_FILE: &str = "client_state.json";

// --- Merkle Tree Hasher (Example) ---
// This needs to be compatible with the server's Hasher for rs_merkle.
#[derive(Clone)]
struct Sha256Algorithm;

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

// --- CLI Definition ---

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// Server base URL (e.g., http://localhost:8080)
    #[clap(long, global = true, default_value = "http://127.0.0.1:8080")]
    server_url: String,

    /// (Optional) Hex-encoded ImageID of the trusted guest program.
    /// If not provided, the client will only verify the receipt's internal consistency
    /// against the ImageID claimed within the receipt itself.
    #[clap(long, global = true)]
    trusted_image_id: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Fetches the latest proof, syncs UTXO data, verifies, and updates local state.
    Sync,
    /// Shows the current synchronized status of the client.
    Status,
    /// Retrieves a specific UTXO from the local synchronized state.
    GetUtxo {
        /// Hex-encoded UTXO key
        key_hex: String,
    },
    /// Resets the client state (clears local UTXO data and sync status).
    ResetState,
}

// --- Main Application Logic ---

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync => sync_command(&cli.server_url, cli.trusted_image_id.as_deref()).await?,
        Commands::Status => status_command().await?,
        Commands::GetUtxo { key_hex } => get_utxo_command(&key_hex).await?,
        Commands::ResetState => reset_state_command().await?,
    }

    Ok(())
}

async fn sync_command(server_url: &str, trusted_image_id_hex_opt: Option<&str>) -> Result<()> {
    println!("Starting synchronization with server: {}", server_url);

    // 1. Load local state
    let mut client_state = load_client_state().unwrap_or_default();
    println!(
        "Current local state: {:?}",
        client_state.last_known_jmt_root_hex
    );

    // 2. Fetch latest proof
    println!("Fetching latest proof...");
    let proof_url = format!("{}/proof/latest", server_url);
    let http_client = reqwest::Client::new();
    let proof_response: ProofResponse = http_client
        .get(&proof_url)
        .send()
        .await
        .context("Failed to send request to server for latest proof")?
        .error_for_status() // Ensure we have a success status
        .context("Server returned an error for latest proof request")?
        .json()
        .await
        .context("Failed to parse ProofResponse JSON")?;

    println!(
        "Received Proof ID: {}, Block Height: {}, JMT Root: {}",
        proof_response.proof_id, proof_response.block_height, proof_response.jmt_root_hex
    );

    // 3. Verify Proof
    println!("Deserializing RISC Zero receipt...");
    let receipt_bytes =
        hex::decode(&proof_response.risc0_receipt_hex).context("Failed to decode receipt_hex")?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .context("Failed to deserialize RISC Zero Receipt from bytes")?;

    // The `receipt.image_id` is the ImageID claimed by the receipt itself.
    let claimed_image_id: Digest = receipt.image_id;
    println!("Receipt claims ImageID: {:?}", claimed_image_id);

    // SECURITY NOTE:
    // Verifying the receipt against `receipt.image_id` (as done below by default if no
    // `trusted_image_id` is provided) confirms the receipt's internal consistency for the
    // ImageID it claims. However, this step ALONE does not guarantee that `receipt.image_id`
    // corresponds to the *expected* or *trusted* guest program.
    //
    // For enhanced security, a `trusted_image_id` should be provided via CLI (or other
    // configuration). If provided, the client will first check if the receipt's claimed
    // ImageID matches this trusted one.

    let image_id_to_verify_against: Digest;

    if let Some(trusted_hex) = trusted_image_id_hex_opt {
        let trusted_image_id_bytes = hex::decode(trusted_hex).context(format!(
            "Failed to decode provided trusted_image_id_hex: {}",
            trusted_hex
        ))?;
        if trusted_image_id_bytes.len() != DigestWords::LEN * 4 {
            // 32 bytes
            return Err(anyhow!(
                "Provided trusted_image_id_hex does not decode to 32 bytes. Length: {}",
                trusted_image_id_bytes.len()
            ));
        }
        let trusted_image_id_array: [u8; 32] = trusted_image_id_bytes.try_into().unwrap(); // Should not panic due to length check
        let trusted_image_id = Digest::from(trusted_image_id_array);

        if claimed_image_id != trusted_image_id {
            return Err(anyhow!(
                "ImageID mismatch! Receipt claims ImageID: {:?}, but client trusts ImageID: {:?}. Proof rejected.",
                claimed_image_id,
                trusted_image_id
            ));
        }
        println!("Receipt's claimed ImageID matches the trusted ImageID provided.");
        image_id_to_verify_against = trusted_image_id;
    } else {
        println!("No trusted ImageID provided via CLI. Verifying receipt against its own claimed ImageID: {:?}", claimed_image_id);
        println!("WARNING: For production use, providing a specific trusted ImageID is recommended for enhanced security.");
        image_id_to_verify_against = claimed_image_id;
    }

    // This verifies the cryptographic integrity of the receipt against the determined ImageID.
    // If `image_id_to_verify_against` came from `trusted_image_id_hex_opt`, this ensures the receipt
    // is valid AND for the trusted program.
    // If it came from `receipt.image_id` (because no trusted ID was given), it only ensures internal consistency.
    receipt.verify(image_id_to_verify_against).context(format!(
        "RISC Zero receipt verification failed. ImageID used for verification: {:?}.",
        image_id_to_verify_against
    ))?;
    println!(
        "Receipt integrity verified successfully against ImageID: {:?}.",
        image_id_to_verify_against
    );

    // Verify journal integrity: JMT root in journal matches `jmt_root_hex` in `ProofResponse`
    let journal_bytes =
        hex::decode(&proof_response.journal_hex).context("Failed to decode journal_hex")?;
    let journal =
        Journal::from_bytes(&journal_bytes).context("Failed to parse Journal from bytes")?;

    // Assuming the JMT root is the first `[u8; 32]` element in the public journal outputs.
    // Adjust this based on your actual guest program's journal structure.
    let jmt_root_from_journal_bytes: &[u8] =
        journal.bytes.get(0..DigestWords::LEN * 4).ok_or_else(|| {
            anyhow!("Journal too short to extract JMT root (expected at least 32 bytes)")
        })?;
    let jmt_root_from_journal: [u8; 32] = jmt_root_from_journal_bytes.try_into().unwrap(); // Safe due to slice length check
    let jmt_root_from_journal_hex = hex::encode(jmt_root_from_journal);

    if jmt_root_from_journal_hex != proof_response.jmt_root_hex {
        return Err(anyhow!(
            "JMT root mismatch! From Journal: {}, From ProofResponse: {}. Proof is compromised or data inconsistency.",
            jmt_root_from_journal_hex,
            proof_response.jmt_root_hex
        ));
    }
    println!("Journal JMT root matches ProofResponse JMT root.");
    println!("Proof verified successfully!");

    // 4. Request JMT Sync
    println!(
        "Requesting JMT synchronization for root: {}",
        proof_response.jmt_root_hex
    );
    let sync_request = JmtSyncRequest {
        target_jmt_root_hex: proof_response.jmt_root_hex.clone(),
        last_known_jmt_root_hex: client_state.last_known_jmt_root_hex.clone(),
    };

    let sync_url = format!("{}/jmt/sync", server_url);
    let sync_response: JmtSyncResponse = http_client
        .post(&sync_url)
        .json(&sync_request)
        .send()
        .await
        .context("Failed to send JMT sync request to server")?
        .error_for_status()
        .context("Server returned an error for JMT sync request")?
        .json()
        .await
        .context("Failed to parse JmtSyncResponse JSON")?;

    // 5. Process JMT Sync Response and update local JMT (simplified)
    println!("Processing JMT sync response...");
    match sync_response {
        JmtSyncResponse::Full {
            target_jmt_root_hex,
            elements,
        } => {
            println!(
                "Received full JMT data with {} elements for root: {}",
                elements.len(),
                target_jmt_root_hex
            );
            client_state.local_utxos.clear();
            for entry in elements {
                client_state
                    .local_utxos
                    .insert(entry.key_hex, entry.value_hex);
            }
        }
        JmtSyncResponse::Delta {
            from_jmt_root_hex,
            to_jmt_root_hex,
            updates,
            deletions,
        } => {
            println!(
                "Received JMT delta from {} to {} ({} updates, {} deletions)",
                from_jmt_root_hex,
                to_jmt_root_hex,
                updates.len(),
                deletions.len()
            );
            for entry in updates {
                client_state
                    .local_utxos
                    .insert(entry.key_hex, entry.value_hex);
            }
            for key_hex in deletions {
                client_state.local_utxos.remove(&key_hex);
            }
        }
        JmtSyncResponse::NoChange { jmt_root_hex } => {
            println!("No change to JMT. Already synced to root: {}", jmt_root_hex);
        }
        JmtSyncResponse::Error { message } => {
            return Err(anyhow!("Server JMT sync error: {}", message));
        }
    }

    // 6. Verify Local JMT Root (Simplified - using collected UTXOs)
    let mut sorted_utxo_keys: Vec<String> = client_state.local_utxos.keys().cloned().collect();
    sorted_utxo_keys.sort();

    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for key_hex in sorted_utxo_keys {
        if let Some(value_hex) = client_state.local_utxos.get(&key_hex) {
            let key_bytes =
                hex::decode(key_hex).context("Failed to decode UTXO key_hex for JMT")?;
            let value_bytes =
                hex::decode(value_hex).context("Failed to decode UTXO value_hex for JMT")?;

            let mut combined = Vec::new();
            combined.extend_from_slice(&key_bytes);
            combined.extend_from_slice(&value_bytes);
            leaf_hashes.push(Sha256Algorithm::hash(&combined));
        }
    }

    let local_calculated_jmt_root_hex = if leaf_hashes.is_empty() {
        let empty_tree_hash = Sha256Algorithm::hash(&[]); // Example: H("") for an empty set of leaves.
                                                          // This needs to align with server's empty tree root definition.
        hex::encode(empty_tree_hash)
    } else {
        let local_merkle_tree = MerkleTree::<Sha256Algorithm>::from_leaves(&leaf_hashes);
        local_merkle_tree
            .root()
            .map(hex::encode)
            .ok_or_else(|| anyhow!("Failed to get root from non-empty local Merkle tree"))?
    };

    println!(
        "Local calculated JMT root: {}",
        local_calculated_jmt_root_hex
    );
    if local_calculated_jmt_root_hex != proof_response.jmt_root_hex {
        if client_state.local_utxos.is_empty() {
            println!(
                "Local UTXO set is empty. Calculated root (for empty): {}. Expected server root: {}.",
                local_calculated_jmt_root_hex,
                proof_response.jmt_root_hex
            );
            println!("Ensure the client's empty tree root calculation matches the server's definition for an empty JMT.");
        }
        return Err(anyhow!(
            "Local JMT root verification failed! Calculated: {}, Expected: {}",
            local_calculated_jmt_root_hex,
            proof_response.jmt_root_hex
        ));
    }
    println!("Local JMT root verified successfully.");

    // 7. Save Local State
    client_state.last_known_jmt_root_hex = Some(proof_response.jmt_root_hex.clone());
    client_state.last_known_block_height = Some(proof_response.block_height);
    client_state.last_known_block_hash_hex = Some(proof_response.block_hash_hex.clone());
    save_client_state(&client_state)?;

    println!(
        "Synchronization complete. Client state updated to block height {}.",
        proof_response.block_height
    );
    Ok(())
}

async fn status_command() -> Result<()> {
    let client_state = load_client_state().unwrap_or_default();
    println!("Client Status:");
    println!("  Server URL: (Configured via --server-url option)");
    // Consider also printing the trusted_image_id if it was configured for the last sync
    match &client_state.last_known_jmt_root_hex {
        Some(root) => {
            println!("  Last Synced JMT Root: {}", root);
            println!(
                "  Last Synced Block Height: {}",
                client_state.last_known_block_height.unwrap_or(0)
            );
            println!(
                "  Last Synced Block Hash: {}",
                client_state
                    .last_known_block_hash_hex
                    .as_deref()
                    .unwrap_or("N/A")
            );
            println!(
                "  Number of local UTXOs: {}",
                client_state.local_utxos.len()
            );
        }
        None => {
            println!("  Not yet synchronized with any server state.");
        }
    }
    Ok(())
}

async fn get_utxo_command(key_hex: &str) -> Result<()> {
    let client_state = load_client_state().unwrap_or_default();
    if client_state.last_known_jmt_root_hex.is_none() {
        println!("Client has not been synchronized yet. Please run `sync` first.");
        return Ok(());
    }

    match client_state.local_utxos.get(key_hex) {
        Some(value_hex) => {
            println!("UTXO Found:");
            println!("  Key: {}", key_hex);
            println!("  Value (Hex): {}", value_hex);
        }
        None => {
            println!(
                "UTXO with key {} not found in local synchronized state.",
                key_hex
            );
        }
    }
    Ok(())
}

async fn reset_state_command() -> Result<()> {
    let path = PathBuf::from(CLIENT_STATE_FILE);
    if path.exists() {
        fs::remove_file(&path).context("Failed to remove client state file")?;
        println!("Client state has been reset.");
    } else {
        println!("No client state file found to reset.");
    }
    Ok(())
}

// --- Helper Functions for State Management ---

fn load_client_state() -> Result<ClientState> {
    let path = PathBuf::from(CLIENT_STATE_FILE);
    if !path.exists() {
        return Ok(ClientState::default());
    }
    let data = fs::read_to_string(path).context("Failed to read client state file")?;
    let state: ClientState =
        serde_json::from_str(&data).context("Failed to parse client state JSON")?;
    Ok(state)
}

fn save_client_state(state: &ClientState) -> Result<()> {
    let data =
        serde_json::to_string_pretty(state).context("Failed to serialize client state to JSON")?;
    fs::write(CLIENT_STATE_FILE, data).context("Failed to write client state file")?;
    Ok(())
}
