use anyhow::{anyhow, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{consensus::Encodable, Block as RpcBlock, BlockHash};
use bitcoin_consensus_core::{
    block::CircuitBlock,
    softfork_manager::BIPFlags,
    utxo_set::{KeyOutPoint, UTXO}, // From utxo_set.rs
    BitcoinConsensusCircuitData,
    BitcoinConsensusCircuitInput,
    BitcoinConsensusCircuitOutput,
    BitcoinConsensusPrevProofType,
    UTXODeletionUpdateProof,
    UTXOInsertionUpdateProof,
};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use borsh::{BorshDeserialize, BorshSerialize};
use dotenv::dotenv;
use host::{delete_utxo_and_generate_update_proof, insert_utxos_and_generate_update_proofs};
use host::{
    rocks_db::RocksDbStorage,
    sqlite::{ProofDb, ProofEntry}, // Assumes ProofEntry has jmt_operations_bytes
};
use jmt::{proof::UpdateMerkleProof, RootHash};
use risc0_zkvm::{
    compute_image_id, default_prover, sha::Block, ExecutorEnv, ProveInfo, ProverOpts, Receipt,
};
use std::{
    collections::{BTreeMap, VecDeque},
    env,
    fs,
    net::SocketAddr, // For RPC server
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::EnvFilter;

// For RPC
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

const MAX_PROOF_SEARCH_DEPTH: u32 = 2016;
const MAX_PROOFS_IN_RPC_CHAIN: usize = 100; // Limit for RPC response

#[derive(Clone, Debug)]
struct Config {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    rocks_db_path: PathBuf,
    proof_db_path: String,
    guest_elf_path: PathBuf,
    network: String,
    tip_check_interval_secs: u64,
    target_catchup_height: u32,
    max_batch_size_bytes: usize,
    min_proof_search_height: u32,
    rpc_listen_addr: String, // Added for RPC server
}

impl Config {
    fn load() -> Result<Self> {
        dotenv().ok();

        Ok(Config {
            rpc_url: env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8332".to_string()),
            rpc_user: env::var("RPC_USER").unwrap_or_else(|_| "admin".to_string()),
            rpc_pass: env::var("RPC_PASS").unwrap_or_else(|_| "admin".to_string()),
            rocks_db_path: PathBuf::from(
                env::var("ROCKS_DB_PATH").unwrap_or_else(|_| "data/utxo_db_server".to_string()),
            ),
            proof_db_path: env::var("PROOF_DB_PATH")
                .unwrap_or_else(|_| "data/proofs_db_server.sqlite".to_string()),
            guest_elf_path: PathBuf::from(
                env::var("GUEST_ELF_PATH").context("GUEST_ELF_PATH must be set from .env")?,
            ),
            network: env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "testnet4".to_string()),
            tip_check_interval_secs: env::var("TIP_CHECK_INTERVAL_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()?,
            target_catchup_height: env::var("TARGET_CATCHUP_HEIGHT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()?,
            max_batch_size_bytes: env::var("MAX_BATCH_SIZE_BYTES")
                .unwrap_or_else(|_| "10000000".to_string())
                .parse()?,
            min_proof_search_height: env::var("MIN_PROOF_SEARCH_HEIGHT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()?,
            rpc_listen_addr: env::var("RPC_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9944".to_string()),
        })
    }
}

struct AppState {
    config: Config,
    rpc_client: RpcClient,
    utxo_db: RocksDbStorage,
    proof_db: Arc<Mutex<ProofDb>>,
    bitcoin_guest_elf: Vec<u8>,
    bitcoin_guest_id: [u32; 8],
    prev_11_blocks_time: Arc<Mutex<[u32; 11]>>,
    current_jmt_root: Arc<Mutex<RootHash>>,
    last_proven_block_height: Arc<Mutex<Option<u32>>>,
    last_proven_block_hash: Arc<Mutex<Option<BlockHash>>>,
}

/// Holds the key-value changes for a batch, to be stored as the "delta".
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct JmtKeyValueChanges {
    pub creations: Vec<(KeyOutPoint, UTXO)>,
    pub deletions: Vec<KeyOutPoint>,
}

// --- RPC Related Definitions ---
mod rpc_helpers {
    use serde::{de::Error, Deserializer, Serializer};
    pub mod hex_array_32 {
        use super::*;
        use bitcoin::hashes::hex::FromHex;
        use hex::ToHex;
        use serde::Deserialize;
        pub fn serialize<S>(array: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&hex::encode(&array))
        }
        pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Vec::<u8>::from_hex(&s)
                .map_err(Error::custom)?
                .try_into()
                .map_err(|_| Error::custom("Invalid hex length for [u8; 32]"))
        }
    }

    pub mod base64_vec_u8 {
        use super::*;
        use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
        use serde::Deserialize;
        pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
        }
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            BASE64_STANDARD.decode(s.as_bytes()).map_err(Error::custom)
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct RpcProofEntry {
    pub block_height: u32,
    #[serde(with = "rpc_helpers::hex_array_32")]
    pub block_hash: [u8; 32],
    #[serde(with = "rpc_helpers::hex_array_32")]
    pub prev_hash: [u8; 32],
    pub method_id: [u32; 8],
    #[serde(with = "rpc_helpers::base64_vec_u8")]
    pub receipt: Vec<u8>,
    pub last_version: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct RpcProofChainElement {
    pub proof_entry: RpcProofEntry,
    #[serde(with = "rpc_helpers::base64_vec_u8")]
    pub jmt_operations_bytes: Vec<u8>,
}

impl From<host::sqlite::ProofEntry> for RpcProofChainElement {
    fn from(db_entry: host::sqlite::ProofEntry) -> Self {
        RpcProofChainElement {
            proof_entry: RpcProofEntry {
                block_height: db_entry.block_height,
                block_hash: db_entry.block_hash,
                prev_hash: db_entry.prev_hash,
                method_id: db_entry.method_id,
                receipt: db_entry.receipt,
                last_version: db_entry.last_version,
            },
            jmt_operations_bytes: db_entry.jmt_operations_bytes,
        }
    }
}

#[derive(Debug, SerdeDeserialize, SerdeSerialize)]
pub struct GetProofChainParams {
    #[serde(with = "rpc_helpers::hex_array_32")]
    pub client_block_hash: [u8; 32],
}

#[rpc(server, client)]
pub trait BitcoinConsensusRpc {
    #[method(name = "getProofChain")]
    async fn get_proof_chain(
        &self,
        params: GetProofChainParams,
    ) -> jsonrpsee::core::RpcResult<Vec<RpcProofChainElement>>;
}

pub struct BitcoinConsensusRpcServerImpl {
    app_state: Arc<AppState>,
}

impl BitcoinConsensusRpcServerImpl {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl BitcoinConsensusRpcServer for BitcoinConsensusRpcServerImpl {
    async fn get_proof_chain(
        &self,
        params: GetProofChainParams,
    ) -> jsonrpsee::core::RpcResult<Vec<RpcProofChainElement>> {
        let client_block_hash_bytes = params.client_block_hash;
        info!(
            "RPC: get_proof_chain called with client_block_hash: {:?}",
            BlockHash::from_slice(&client_block_hash_bytes).unwrap_or(BlockHash::all_zeros())
        );

        let proof_db_locked = self.app_state.proof_db.lock().await;
        let mut proof_chain_to_send: VecDeque<RpcProofChainElement> = VecDeque::new();
        let last_proven_hash_on_server_opt = *self.app_state.last_proven_block_hash.lock().await;
        let mut current_hash_to_fetch_opt = last_proven_hash_on_server_opt;

        if current_hash_to_fetch_opt.is_none() {
            info!("RPC: No proofs available in the system.");
            return Ok(Vec::new());
        }

        let mut proofs_collected_count = 0;
        while let Some(current_hash_to_fetch) = current_hash_to_fetch_opt {
            if proofs_collected_count >= MAX_PROOFS_IN_RPC_CHAIN {
                warn!(
                    "RPC: Reached MAX_PROOFS_IN_RPC_CHAIN ({}) for client_block_hash: {:?}",
                    MAX_PROOFS_IN_RPC_CHAIN,
                    BlockHash::from_slice(&client_block_hash_bytes)
                        .unwrap_or(BlockHash::all_zeros())
                );
                break;
            }

            match proof_db_locked.find_proof_by_hash(&current_hash_to_fetch.to_byte_array()) {
                Ok(Some(db_proof_entry)) => {
                    let rpc_element = RpcProofChainElement::from(db_proof_entry.clone());
                    proof_chain_to_send.push_front(rpc_element);
                    proofs_collected_count += 1;

                    if db_proof_entry.prev_hash == client_block_hash_bytes {
                        debug!(
                            "RPC: Found link to client_block_hash ({:?}). Chain complete.",
                            BlockHash::from_slice(&client_block_hash_bytes)
                                .unwrap_or(BlockHash::all_zeros())
                        );
                        current_hash_to_fetch_opt = None;
                        break;
                    } else if client_block_hash_bytes == BlockHash::all_zeros().to_byte_array()
                        && db_proof_entry.prev_hash == BlockHash::all_zeros().to_byte_array()
                    {
                        debug!("RPC: Client requested from genesis, and current proof's prev_hash is genesis. Chain complete.");
                        current_hash_to_fetch_opt = None;
                        break;
                    } else if db_proof_entry.prev_hash == BlockHash::all_zeros().to_byte_array() {
                        debug!(
                            "RPC: Reached earliest known proof in DB. Stopping chain construction."
                        );
                        current_hash_to_fetch_opt = None;
                        break;
                    } else {
                        current_hash_to_fetch_opt = Some(
                            BlockHash::from_slice(&db_proof_entry.prev_hash).map_err(|e| {
                                jsonrpsee::types::ErrorObject::owned(
                                    -32000,
                                    format!("Failed to parse prev_hash: {}", e),
                                    None::<()>,
                                )
                            })?,
                        );
                    }
                }
                Ok(None) => {
                    error!(
                        "RPC: Proof chain broken. No proof found for hash {:?}",
                        current_hash_to_fetch
                    );
                    current_hash_to_fetch_opt = None;
                    break;
                }
                Err(e) => {
                    error!(
                        "RPC: DB error while fetching proof for hash {:?}: {}",
                        current_hash_to_fetch, e
                    );
                    return Err(jsonrpsee::types::ErrorObject::owned(
                        -32001,
                        format!("DB error: {}", e),
                        None::<()>,
                    ));
                }
            }
        }

        if client_block_hash_bytes != BlockHash::all_zeros().to_byte_array()
            && !proof_chain_to_send.is_empty()
            && proof_chain_to_send.front().unwrap().proof_entry.prev_hash != client_block_hash_bytes
        {
            warn!("RPC: Client block_hash {:?} not found as a direct ancestor or is too old. Returning available chain segment from current tip.", BlockHash::from_slice(&client_block_hash_bytes).unwrap_or(BlockHash::all_zeros()));
        } else if proof_chain_to_send.is_empty()
            && last_proven_hash_on_server_opt.is_some()
            && client_block_hash_bytes
                != last_proven_hash_on_server_opt
                    .unwrap_or(BlockHash::all_zeros())
                    .to_byte_array()
        {
            warn!("RPC: Client block_hash {:?} not found or is current tip. Returning empty proof chain.", BlockHash::from_slice(&client_block_hash_bytes).unwrap_or(BlockHash::all_zeros()));
        }

        info!(
            "RPC: Sending {} proof elements to client.",
            proof_chain_to_send.len()
        );
        Ok(proof_chain_to_send.into_iter().collect())
    }
}
// --- End RPC Related Definitions ---

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(Level::DEBUG.to_string())),
        )
        .init();

    info!("Starting Bitcoin Consensus Proving Server (server.rs)...");

    let config = Config::load().context("Failed to load configuration")?;
    info!("Config loaded: {:?}", config);

    fs::create_dir_all(&config.rocks_db_path).with_context(|| {
        format!(
            "Failed to create UTXO DB directory: {:?}",
            config.rocks_db_path
        )
    })?;
    if let Some(parent) = PathBuf::from(&config.proof_db_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create Proof DB directory: {:?}", parent))?;
        }
    }

    let rpc_client = RpcClient::new(
        &config.rpc_url,
        Auth::UserPass(config.rpc_user.clone(), config.rpc_pass.clone()),
    )
    .await
    .context("Failed to create RPC client")?;

    let utxo_db = RocksDbStorage::new(config.rocks_db_path.to_str().unwrap())
        .context("Failed to initialize RocksDB UTXO storage")?;
    let proof_db_conn =
        ProofDb::new(&config.proof_db_path).context("Failed to initialize SQLite ProofDB")?;
    let proof_db = Arc::new(Mutex::new(proof_db_conn));

    let bitcoin_guest_elf = fs::read(&config.guest_elf_path).with_context(|| {
        format!(
            "Failed to read Bitcoin guest ELF from {:?}",
            config.guest_elf_path
        )
    })?;
    let bitcoin_guest_id: [u32; 8] = compute_image_id(&bitcoin_guest_elf)?
        .as_words()
        .try_into()
        .expect("Failed to convert image ID");
    info!("Computed guest program ID: {:?}", bitcoin_guest_id);

    let (
        initial_last_proven_height,
        initial_last_proven_block_hash,
        initial_prev_11_times,
        initial_jmt_root,
    ) = load_initial_server_state(&proof_db, &utxo_db, &rpc_client, &config).await?;

    info!(
        "Initial server state loaded. Last proven height: {:?}, Last proven hash: {:?}, JMT root: {:?}",
        initial_last_proven_height, initial_last_proven_block_hash, initial_jmt_root
    );

    let app_state = Arc::new(AppState {
        config: config.clone(), // Clone config for AppState
        rpc_client,
        utxo_db,
        proof_db,
        bitcoin_guest_elf,
        bitcoin_guest_id,
        prev_11_blocks_time: Arc::new(Mutex::new(initial_prev_11_times)),
        current_jmt_root: Arc::new(Mutex::new(initial_jmt_root)),
        last_proven_block_height: Arc::new(Mutex::new(initial_last_proven_height)),
        last_proven_block_hash: Arc::new(Mutex::new(initial_last_proven_block_hash)),
    });

    let (block_batch_sender, block_batch_receiver) = mpsc::channel::<Vec<CircuitBlock>>(10);

    let proof_worker_handle =
        tokio::spawn(proof_worker_task(app_state.clone(), block_batch_receiver));

    let orchestrator_handle =
        tokio::spawn(orchestrator_task(app_state.clone(), block_batch_sender));

    // Start RPC server
    let rpc_server_impl = BitcoinConsensusRpcServerImpl::new(app_state.clone());
    let rpc_addr: SocketAddr = app_state
        .config
        .rpc_listen_addr
        .parse() // Use from config
        .with_context(|| {
            format!(
                "Invalid RPC listen address: {}",
                app_state.config.rpc_listen_addr
            )
        })?;

    let rpc_server_builder = ServerBuilder::default();
    let rpc_server = rpc_server_builder
        .build(rpc_addr)
        .await
        .with_context(|| format!("Failed to build RPC server on {}", rpc_addr))?;

    let rpc_handle: ServerHandle = rpc_server.start(rpc_server_impl.into_rpc());

    info!("Server initialized. Orchestrator, proof worker, and RPC server are running.");
    info!("RPC server listening on {}", rpc_addr);
    info!("Target Network: {}", app_state.config.network);

    tokio::select! {
        res = orchestrator_handle => { error!("Orchestrator task exited: {:?}", res); }
        res = proof_worker_handle => { error!("Proof worker task exited: {:?}", res); }
        _ = rpc_handle.stopped() => { info!("RPC server task stopped."); }
    }

    Ok(())
}

async fn load_initial_server_state(
    proof_db: &Arc<Mutex<ProofDb>>,
    utxo_db: &RocksDbStorage,
    rpc: &RpcClient,
    config: &Config,
) -> Result<(Option<u32>, Option<BlockHash>, [u32; 11], RootHash)> {
    info!("Attempting to load initial server state by finding latest proven block on current chain tip...");

    let chain_tip_hash = rpc
        .get_best_block_hash()
        .await
        .context("RPC: Failed to get best block hash for initial state load")?;
    let chain_tip_header_info =
        rpc.get_block_header_info(&chain_tip_hash)
            .await
            .context(format!(
                "RPC: Failed to get block header info for tip {}",
                chain_tip_hash
            ))?;
    let mut current_search_hash = chain_tip_hash;
    let mut current_search_height = chain_tip_header_info.height as u32;

    info!(
        "Current chain tip is {} at height {}. Searching backwards for a known proof.",
        current_search_hash, current_search_height
    );

    let mut found_proof_entry: Option<ProofEntry> = None;

    for i in 0..MAX_PROOF_SEARCH_DEPTH {
        if current_search_height < config.min_proof_search_height
            && config.min_proof_search_height > 0
        // Only apply if min_proof_search_height is set
        {
            info!(
                "Search reached min_proof_search_height ({}), stopping backward search.",
                config.min_proof_search_height
            );
            break;
        }
        // Check if we are at height 0. If so, we only process this iteration if it's the first one (i.e., chain tip is 0).
        if current_search_height == 0 && i > 0 {
            info!("Search reached height 0 after initial check, stopping backward search.");
            break;
        }

        debug!(
            "Searching for proof for block hash {} at height {}",
            current_search_hash, current_search_height
        );
        let proof_db_locked = proof_db.lock().await;
        match proof_db_locked.find_proof_by_hash(&current_search_hash.to_byte_array()) {
            Ok(Some(entry)) => {
                info!("Found proof in DB for block {} at height {}. JMT version: {}. This will be our resumption point.",
                    current_search_hash, entry.block_height, entry.last_version);
                found_proof_entry = Some(entry);
                drop(proof_db_locked);
                break;
            }
            Ok(None) => {
                drop(proof_db_locked);
                // If current_search_hash is all zeros, or if we are at height 0 and it's not the chain tip we started with
                if current_search_hash == BlockHash::all_zeros()
                    || (current_search_height == 0 && current_search_hash != chain_tip_hash)
                {
                    info!("Reached genesis or zero hash (height {}) while searching for proof. Stopping search.", current_search_height);
                    break;
                }

                match rpc.get_block(&current_search_hash).await {
                    Ok(block) => {
                        current_search_hash = block.header.prev_blockhash;
                        if current_search_hash != BlockHash::all_zeros() {
                            match rpc.get_block_header_info(&current_search_hash).await {
                                Ok(hdr) => current_search_height = hdr.height as u32,
                                Err(e) => {
                                    warn!("RPC: Failed to get header info for parent {} during proof search: {}. Stopping search.", current_search_hash, e);
                                    break;
                                }
                            }
                        } else {
                            // prev_blockhash is zero, this means current_search_hash was genesis.
                            // current_search_height should reflect the height of the block whose prev is zero.
                            // If we were at height 1, its prev is height 0. If we were at height 0, its prev is all_zeros hash.
                            // We effectively stop here if current_search_hash is all_zeros
                            if current_search_height > 0 {
                                // If current_search_height was >0, its parent (all_zeros) is conceptual height -1
                                current_search_height = current_search_height.saturating_sub(1);
                                // Should bring it to 0 if it was 1
                            }
                            if current_search_hash == BlockHash::all_zeros() {
                                // explicit check to break
                                info!("Reached genesis block (parent is all zeros) while searching for proof. Stopping search.");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("RPC: Failed to get block {} to find its parent during proof search: {}. Stopping search.", current_search_hash, e);
                        break;
                    }
                }
            }
            Err(e) => {
                drop(proof_db_locked);
                error!("DB error while searching for proof for hash {}: {}. Halting initial state load.", current_search_hash, e);
                return Err(anyhow!(
                    "DB error during proof search for {}: {}",
                    current_search_hash,
                    e
                ));
            }
        }
        if i == MAX_PROOF_SEARCH_DEPTH - 1 {
            warn!(
                "Reached max proof search depth ({}) without finding a proof.",
                MAX_PROOF_SEARCH_DEPTH
            );
        }
    }

    if let Some(resumption_proof_entry) = found_proof_entry {
        let resumption_block_hash_bytes = resumption_proof_entry.block_hash;
        let resumption_block_hash = BlockHash::from_slice(&resumption_block_hash_bytes)
            .with_context(|| {
                format!(
                    "Failed to convert byte array {:?} to BlockHash",
                    resumption_block_hash_bytes
                )
            })?;

        info!(
            "Resuming from proof for block {} at height {}. Associated JMT version: {}.",
            resumption_block_hash,
            resumption_proof_entry.block_height,
            resumption_proof_entry.last_version
        );

        let receipt =
            Receipt::try_from_slice(&resumption_proof_entry.receipt).with_context(|| {
                format!(
                    "Failed to deserialize receipt from found ProofEntry for height {}",
                    resumption_proof_entry.block_height
                )
            })?;
        let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes)
            .with_context(|| {
                format!(
                    "Failed to deserialize CircuitOutput from receipt for height {}",
                    resumption_proof_entry.block_height
                )
            })?;

        let jmt_root_from_proof = output.bitcoin_state.utxo_set_commitment.jmt_root;
        let prev_11_times_from_proof = output.bitcoin_state.header_chain_state.prev_11_timestamps;
        let jmt_version_for_pruning = resumption_proof_entry.last_version;

        info!(
            "Pruning UTXO DB to JMT version: {}",
            jmt_version_for_pruning
        );
        utxo_db.prune(jmt_version_for_pruning).with_context(|| {
            format!(
                "Failed to prune UTXO DB to JMT version {} from found proof",
                jmt_version_for_pruning
            )
        })?;
        info!(
            "UTXO DB pruned successfully to version {}.",
            jmt_version_for_pruning
        );

        let root_in_db_after_prune = utxo_db
            .get_root_at_version(jmt_version_for_pruning)?
            .ok_or_else(|| {
                anyhow!(
                    "JMT root not found in RocksDB for version {} after prune (from found proof).",
                    jmt_version_for_pruning
                )
            })?;

        if root_in_db_after_prune != jmt_root_from_proof {
            error!(
                "CRITICAL: JMT root mismatch after pruning (from found proof)! Version {}. From Proof: {:?}, From DB: {:?}.",
                jmt_version_for_pruning, jmt_root_from_proof, root_in_db_after_prune
            );
            return Err(anyhow!(
                "JMT root mismatch for version {} (from found proof). Expected: {:?}, Got: {:?}. Halting.",
                jmt_version_for_pruning, jmt_root_from_proof, root_in_db_after_prune
            ));
        }
        info!("JMT root in DB successfully verified against found proof's JMT root after pruning.");

        return Ok((
            Some(resumption_proof_entry.block_height),
            Some(resumption_block_hash),
            prev_11_times_from_proof,
            jmt_root_from_proof,
        ));
    }

    warn!(
        "No proof found on the current chain (up to search depth {} from tip {}). Starting fresh.",
        MAX_PROOF_SEARCH_DEPTH, chain_tip_hash
    );
    info!("Pruning UTXO DB to version 0 for a fresh start.");
    utxo_db.prune(0).context(
        "Failed to prune JMT to version 0 for fresh start after no proof found on chain",
    )?;
    info!("UTXO DB pruned to version 0.");

    Ok((None, None, [0; 11], default_jmt_root()))
}

fn default_jmt_root() -> RootHash {
    RootHash::from([
        83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69, 72, 79, 76, 68,
        69, 82, 95, 72, 65, 83, 72, 95, 95,
    ])
}

async fn orchestrator_task(
    app_state: Arc<AppState>,
    block_batch_sender: mpsc::Sender<Vec<CircuitBlock>>,
) -> Result<()> {
    info!("Orchestrator task started.");

    let mut current_height_to_process = {
        let lock = app_state.last_proven_block_height.lock().await;
        lock.map_or(0, |h| h + 1)
    };

    let mut initial_target_catchup_height = app_state.config.target_catchup_height;
    if current_height_to_process == 0 && initial_target_catchup_height == 0 {
        let tip_hash = app_state
            .rpc_client
            .get_best_block_hash()
            .await
            .context("Orchestrator: Failed to get initial chain tip for fresh sync")?;
        initial_target_catchup_height = app_state
            .rpc_client
            .get_block_header_info(&tip_hash)
            .await
            .context("Orchestrator: Failed to get initial chain tip header for fresh sync")?
            .height as u32;
        info!(
            "Orchestrator: Fresh start, setting initial target catch-up height to current tip: {}",
            initial_target_catchup_height
        );
    }

    info!(
        "Orchestrator: Starting processing from height {}. Initial target height: {}.",
        current_height_to_process, initial_target_catchup_height
    );

    if current_height_to_process <= initial_target_catchup_height {
        info!(
            "Orchestrator: Entering catch-up phase from {} to {}.",
            current_height_to_process, initial_target_catchup_height
        );
        while current_height_to_process <= initial_target_catchup_height {
            let mut batch_to_prove: Vec<CircuitBlock> = Vec::new();
            let mut current_batch_size_bytes: usize = 0;
            let batch_start_height = current_height_to_process;

            debug!(
                "(Catch-up) Forming batch starting from height {}.",
                batch_start_height
            );

            // Inner loop to build a batch
            while current_height_to_process <= initial_target_catchup_height {
                let block_hash = match app_state
                    .rpc_client
                    .get_block_hash(current_height_to_process as u64)
                    .await
                {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!(
                            "(Catch-up) RPC error getting block hash for height {}: {}. Pausing and will retry this height.",
                            current_height_to_process, e
                        );
                        // Break inner loop to retry current_height_to_process after a delay
                        // This means batch_to_prove might be empty or partial, which is handled below
                        break;
                    }
                };
                let rpc_block = match app_state.rpc_client.get_block(&block_hash).await {
                    Ok(block) => block,
                    Err(e) => {
                        error!(
                            "(Catch-up) RPC error getting block for height {}: {}. Pausing and will retry this height.",
                            current_height_to_process, e
                        );
                        // Break inner loop to retry current_height_to_process after a delay
                        break;
                    }
                };

                let mut block_bytes_for_size_check = Vec::new();
                rpc_block.consensus_encode(&mut block_bytes_for_size_check)?;
                let block_size = block_bytes_for_size_check.len();

                if !batch_to_prove.is_empty()
                    && (current_batch_size_bytes + block_size
                        > app_state.config.max_batch_size_bytes)
                {
                    debug!(
                        "(Catch-up) Max batch size reached before adding block {}. Batch size: {}",
                        current_height_to_process, current_batch_size_bytes
                    );
                    break; // break inner while to send current batch
                }

                batch_to_prove.push(CircuitBlock::from(rpc_block));
                current_batch_size_bytes += block_size;
                debug!(
                    "(Catch-up) Added block height {} (size: {}B) to batch. Batch size: {}/{}B.",
                    current_height_to_process,
                    block_size,
                    current_batch_size_bytes,
                    app_state.config.max_batch_size_bytes
                );

                if current_height_to_process == initial_target_catchup_height {
                    current_height_to_process += 1;
                    break;
                }
                current_height_to_process += 1;
            } // End of inner batch building loop

            if !batch_to_prove.is_empty() {
                let batch_actual_end_height = batch_start_height + batch_to_prove.len() as u32 - 1;
                info!(
                    "(Catch-up) Sending batch ({} blocks, heights {}-{}) to proof worker.",
                    batch_to_prove.len(),
                    batch_start_height,
                    batch_actual_end_height
                );
                if block_batch_sender.send(batch_to_prove).await.is_err() {
                    error!("(Catch-up) Failed to send block batch. Worker might have exited.");
                    return Err(anyhow!("(Catch-up) Block batch queue receiver dropped."));
                }

                // Wait for this batch to be processed
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let last_proven = *app_state.last_proven_block_height.lock().await;
                    if last_proven.map_or(false, |h| h >= batch_actual_end_height) {
                        info!(
                            "(Catch-up) Batch ending at height {} processed.",
                            batch_actual_end_height
                        );
                        break;
                    }
                    debug!(
                        "(Catch-up) Waiting for batch {}-{} to process. Last proven: {:?}...",
                        batch_start_height, batch_actual_end_height, last_proven
                    );
                }
            } else if current_height_to_process <= initial_target_catchup_height {
                // This case is hit if the inner loop broke due to RPC error before adding any block
                // or if a single block is too large (which should be an error exit now)
                warn!(
                    "(Catch-up) Empty batch formed, likely due to RPC error at height {}. Retrying after delay.",
                    current_height_to_process
                );
                let single_block_hash_res = app_state
                    .rpc_client
                    .get_block_hash(current_height_to_process as u64)
                    .await;
                if let Ok(single_block_hash) = single_block_hash_res {
                    if let Ok(single_rpc_block) =
                        app_state.rpc_client.get_block(&single_block_hash).await
                    {
                        let mut temp_bytes = Vec::new();
                        if single_rpc_block.consensus_encode(&mut temp_bytes).is_ok() {
                            if temp_bytes.len() > app_state.config.max_batch_size_bytes {
                                error!("(Catch-up) Single block at height {} (size: {}) exceeds max_batch_size ({}). Halting.",
                                    current_height_to_process, temp_bytes.len(), app_state.config.max_batch_size_bytes);
                                return Err(anyhow!(
                                    "Block at height {} too large for batch size.",
                                    current_height_to_process
                                ));
                            }
                        }
                    }
                } // End single block check
                tokio::time::sleep(Duration::from_secs(
                    app_state.config.tip_check_interval_secs,
                ))
                .await;
            }
            // If current_height_to_process > initial_target_catchup_height, outer loop will terminate
        } // End of outer catch-up loop
        info!(
            "(Catch-up) Phase completed. Target height {} reached or passed.",
            initial_target_catchup_height
        );
    } else {
        info!("Orchestrator: No catch-up phase needed. Last proven height {} is at or beyond initial target {}.",
            current_height_to_process.saturating_sub(1), initial_target_catchup_height);
    }

    info!("Switching to continuous syncing mode.");
    let mut tip_check_interval = tokio::time::interval(Duration::from_secs(
        app_state.config.tip_check_interval_secs,
    ));

    loop {
        tip_check_interval.tick().await;

        current_height_to_process = {
            let lock = app_state.last_proven_block_height.lock().await;
            lock.map_or(0, |h| h + 1)
        };
        debug!(
            "(Continuous) Checking for new blocks from height {}.",
            current_height_to_process
        );

        let chain_tip_hash = match app_state.rpc_client.get_best_block_hash().await {
            Ok(hash) => hash,
            Err(e) => {
                error!("(Continuous) RPC: Failed to get best block hash: {}", e);
                continue;
            }
        };
        let chain_tip_header = match app_state
            .rpc_client
            .get_block_header_info(&chain_tip_hash)
            .await
        {
            Ok(header) => header,
            Err(e) => {
                error!(
                    "(Continuous) RPC: Failed to get block header for tip {}: {}",
                    chain_tip_hash, e
                );
                continue;
            }
        };
        let chain_tip_height = chain_tip_header.height as u32;

        if chain_tip_height >= current_height_to_process {
            info!(
                "(Continuous) New block(s) detected. Chain tip: {}, Next to prove: {}.",
                chain_tip_height, current_height_to_process
            );

            let mut height_being_processed = current_height_to_process;
            while chain_tip_height >= height_being_processed {
                let block_hash_to_prove = match app_state
                    .rpc_client
                    .get_block_hash(height_being_processed as u64)
                    .await
                {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!(
                            "(Continuous) RPC: Failed to get block hash for height {}: {}",
                            height_being_processed, e
                        );
                        break;
                    }
                };
                let rpc_block_to_prove =
                    match app_state.rpc_client.get_block(&block_hash_to_prove).await {
                        Ok(block) => block,
                        Err(e) => {
                            error!(
                                "(Continuous) RPC: Failed to get block for height {}: {}",
                                height_being_processed, e
                            );
                            break;
                        }
                    };

                let mut block_bytes_check = Vec::new();
                rpc_block_to_prove.consensus_encode(&mut block_bytes_check)?;
                if block_bytes_check.len() > app_state.config.max_batch_size_bytes {
                    error!("(Continuous) Single block at height {} (size: {}) exceeds max_batch_size_bytes ({}). Halting.",
                        height_being_processed, block_bytes_check.len(), app_state.config.max_batch_size_bytes);
                    return Err(anyhow!(
                        "(Continuous) Block at height {} too large.",
                        height_being_processed
                    ));
                }

                let circuit_block = CircuitBlock::from(rpc_block_to_prove);
                info!(
                    "(Continuous) Queuing block height {} for proving.",
                    height_being_processed
                );
                if block_batch_sender.send(vec![circuit_block]).await.is_err() {
                    error!("(Continuous) Failed to send block to proving queue (height {}). Worker might have exited.", height_being_processed);
                    return Err(anyhow!(
                        "(Continuous) Block batch queue receiver dropped for height {}.",
                        height_being_processed
                    ));
                }

                let expected_proven_height = height_being_processed;
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let last_proven_after_send = *app_state.last_proven_block_height.lock().await;
                    if last_proven_after_send.map_or(false, |h| h >= expected_proven_height) {
                        info!(
                            "(Continuous) Block height {} processed.",
                            expected_proven_height
                        );
                        break;
                    }
                    debug!(
                        "(Continuous) Waiting for block height {} to process... Last proven: {:?}",
                        expected_proven_height, last_proven_after_send
                    );
                }
                height_being_processed += 1;
            }
        } else {
            debug!(
                "(Continuous) No new blocks. Synced up to height {}. Chain tip at {}.",
                current_height_to_process.saturating_sub(1),
                chain_tip_height
            );
        }
    }
}

async fn proof_worker_task(
    app_state: Arc<AppState>,
    mut block_batch_receiver: mpsc::Receiver<Vec<CircuitBlock>>,
) -> Result<()> {
    info!("Proof worker task started. Waiting for block batches...");

    while let Some(block_batch) = block_batch_receiver.recv().await {
        if block_batch.is_empty() {
            warn!("Proof worker received an empty block batch. Skipping.");
            continue;
        }

        let first_block_in_batch = block_batch.first().unwrap();
        let first_block_height_in_batch = first_block_in_batch
            .get_height_from_rpc(&app_state.rpc_client)
            .await
            .context("Worker: Failed to get height for first block in batch")?;

        let last_block_in_batch = block_batch.last().unwrap();
        let last_block_height_in_batch = last_block_in_batch
            .get_height_from_rpc(&app_state.rpc_client)
            .await
            .context("Worker: Failed to get height for last block in batch")?;

        info!(
            "Proof worker received batch of {} blocks (heights {}-{}) for proving.",
            block_batch.len(),
            first_block_height_in_batch,
            last_block_height_in_batch
        );

        let mut temp_jmt_root: RootHash;
        let mut temp_prev_11_times: [u32; 11];
        let prev_proof_type_for_batch: BitcoinConsensusPrevProofType;
        let mut last_proven_hash_for_linking: Option<BlockHash>;

        // --- State Preparation ---
        {
            let shared_jmt_root_guard = app_state.current_jmt_root.lock().await;
            let shared_prev_11_times_guard = app_state.prev_11_blocks_time.lock().await;
            let shared_last_proven_height_guard = app_state.last_proven_block_height.lock().await;
            let shared_last_proven_hash_guard = app_state.last_proven_block_hash.lock().await;

            temp_jmt_root = *shared_jmt_root_guard;
            temp_prev_11_times = *shared_prev_11_times_guard;
            last_proven_hash_for_linking = *shared_last_proven_hash_guard;

            let jmt_version_consistent_with_loaded_state =
                app_state.utxo_db.get_latest_version().context(
                    "Worker: Failed to get JMT latest version for batch start consistency check",
                )?;

            prev_proof_type_for_batch = match *shared_last_proven_height_guard {
                Some(prev_h) if prev_h == first_block_height_in_batch - 1 => {
                    match last_proven_hash_for_linking {
                        Some(ref prev_hash_val) => {
                            let proof_db_locked = app_state.proof_db.lock().await;
                            match proof_db_locked.find_proof_by_hash(&prev_hash_val.to_byte_array())
                            {
                                Ok(Some(prev_proof_entry)) => {
                                    if prev_proof_entry.last_version
                                        != jmt_version_consistent_with_loaded_state
                                    {
                                        error!(
                                            "WORKER: JMT version mismatch! Prev proof (hash {}) JMT version ({}) != current UTXO DB JMT version ({}). Critical. Skipping.",
                                            prev_hash_val, prev_proof_entry.last_version, jmt_version_consistent_with_loaded_state
                                        );
                                        drop(proof_db_locked);
                                        continue;
                                    }
                                    let prev_receipt =
                                        Receipt::try_from_slice(&prev_proof_entry.receipt)?;
                                    let prev_output =
                                        BitcoinConsensusCircuitOutput::try_from_slice(
                                            &prev_receipt.journal.bytes,
                                        )?;
                                    info!(
                                        "Batch starts after proven block {} (height {}). Using its proof. JMT version for prev proof: {}",
                                        prev_hash_val, prev_h, prev_proof_entry.last_version
                                    );
                                    BitcoinConsensusPrevProofType::PrevProof(prev_output)
                                }
                                Err(e) => {
                                    error!("WORKER: DB error finding prev proof by hash {} for height {}: {}. Skipping.", prev_hash_val, prev_h, e);
                                    drop(proof_db_locked);
                                    continue;
                                }
                                Ok(None) => {
                                    error!("WORKER: Could not find prev proof by hash {} for height {}. Inconsistent. Skipping.", prev_hash_val, prev_h);
                                    drop(proof_db_locked);
                                    continue;
                                }
                            }
                        }
                        None => {
                            error!("WORKER: Last proven height is Some({}), but last proven hash is None. Inconsistent state. Skipping.", prev_h);
                            continue;
                        }
                    }
                }
                None if first_block_height_in_batch == 0 => {
                    if jmt_version_consistent_with_loaded_state != 0 {
                        warn!(
                           "WORKER: Genesis batch (height 0), but current JMT version is {}. Expected 0.",
                           jmt_version_consistent_with_loaded_state
                       );
                    }
                    info!(
                       "WORKER: Processing genesis batch (starts height {}). JMT version before batch: {}",
                       first_block_height_in_batch, jmt_version_consistent_with_loaded_state
                   );
                    BitcoinConsensusPrevProofType::GenesisBlock
                }
                _ => {
                    error!(
                        "WORKER: Batch start height {} is not sequential to last proven height {:?} / hash {:?}. State mismatch. Skipping batch.",
                        first_block_height_in_batch, *shared_last_proven_height_guard, last_proven_hash_for_linking
                    );
                    continue;
                }
            };
        }

        // --- Data collection for JMT Update Proofs (for circuit) AND K-V changes (for delta) ---
        let mut batch_utxo_deletion_proofs_for_circuit: VecDeque<UTXODeletionUpdateProof> =
            VecDeque::new();
        let mut batch_utxo_creations_for_circuit_and_delta: BTreeMap<KeyOutPoint, UTXO> =
            BTreeMap::new();
        let mut actual_deletions_for_delta: Vec<KeyOutPoint> = Vec::new();

        let mut current_processing_block_height_in_worker = first_block_height_in_batch;

        'batch_processing_loop: for (idx, circuit_block) in block_batch.iter().enumerate() {
            let actual_block_height = circuit_block
                .get_height_from_rpc(&app_state.rpc_client)
                .await?;
            if actual_block_height != current_processing_block_height_in_worker {
                error!(
                    "WORKER: Height mismatch! Expected {}, got {}. Aborting.",
                    current_processing_block_height_in_worker, actual_block_height
                );
                break 'batch_processing_loop;
            }
            info!(
                "WORKER: Processing block {} ({} of {} in batch).",
                actual_block_height,
                idx + 1,
                block_batch.len()
            );

            let bip_flags = BIPFlags::at_height(actual_block_height);
            let mut sorted_prev_times = temp_prev_11_times;
            sorted_prev_times.sort_unstable();
            let median_time_past_for_utxo = if bip_flags.is_bip113_active() {
                sorted_prev_times[5]
            } else {
                circuit_block.block_header.time
            };
            temp_prev_11_times[actual_block_height as usize % 11] = circuit_block.block_header.time;

            for tx in circuit_block.transactions.iter() {
                for input in tx.input.iter() {
                    if input.previous_output.txid.to_byte_array() == [0; 32] {
                        continue;
                    }
                    let utxo_key = KeyOutPoint {
                        txid: input.previous_output.txid.to_byte_array(),
                        vout: input.previous_output.vout,
                    };

                    if batch_utxo_creations_for_circuit_and_delta.contains_key(&utxo_key) {
                        batch_utxo_creations_for_circuit_and_delta.remove(&utxo_key);
                    } else {
                        match delete_utxo_and_generate_update_proof(
                            &app_state.utxo_db,
                            &utxo_key,
                            &mut temp_jmt_root,
                        ) {
                            Ok((utxo, proof, next_root)) => {
                                batch_utxo_deletion_proofs_for_circuit.push_back(
                                    UTXODeletionUpdateProof {
                                        update_proof: proof,
                                        utxo,
                                        new_root: next_root,
                                    },
                                );
                                actual_deletions_for_delta.push(utxo_key);
                            }
                            Err(e) => {
                                error!("WORKER: UTXO deletion failed for {:?} at height {}: {}. Aborting batch.", utxo_key, actual_block_height, e);
                                break 'batch_processing_loop;
                            }
                        }
                    }
                }
                for (vout, output) in tx.output.iter().enumerate() {
                    let utxo_key = KeyOutPoint {
                        txid: tx.compute_txid().to_byte_array(),
                        vout: vout as u32,
                    };
                    let utxo_to_create = UTXO {
                        value: output.value.to_sat(),
                        script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                        block_height: actual_block_height,
                        is_coinbase: tx.is_coinbase(),
                        block_time: median_time_past_for_utxo,
                    };
                    batch_utxo_creations_for_circuit_and_delta.insert(utxo_key, utxo_to_create);
                }
            }
            current_processing_block_height_in_worker += 1;
        }

        if current_processing_block_height_in_worker <= last_block_height_in_batch {
            error!("WORKER: Batch processing aborted. Skipping proof. JMT state may be partially advanced.");
            continue;
        }

        let key_value_pairs_for_batch_insertion: Vec<(KeyOutPoint, UTXO)> =
            batch_utxo_creations_for_circuit_and_delta
                .clone()
                .into_iter()
                .collect();

        let batch_insertion_proofs_vec_for_circuit =
            if !key_value_pairs_for_batch_insertion.is_empty() {
                match insert_utxos_and_generate_update_proofs(
                    &app_state.utxo_db,
                    &key_value_pairs_for_batch_insertion,
                    &mut temp_jmt_root,
                ) {
                    Ok(proofs_struct) => proofs_struct.update_proof,
                    Err(e) => {
                        error!("WORKER: UTXO batch insertion failed: {}. Aborting.", e);
                        continue;
                    }
                }
            } else {
                UpdateMerkleProof::new(vec![])
            };

        let utxo_batch_insertion_proof_for_circuit = UTXOInsertionUpdateProof {
            update_proof: batch_insertion_proofs_vec_for_circuit,
            new_root: temp_jmt_root,
        };

        let final_jmt_version_for_this_batch_proof = app_state
            .utxo_db
            .get_latest_version()
            .context("Worker: Failed to get final JMT version from utxo_db for batch proof")?;

        let circuit_data = BitcoinConsensusCircuitData {
            blocks: block_batch.clone(),
            utxo_deletion_update_proofs: batch_utxo_deletion_proofs_for_circuit,
            utxo_insertion_update_proofs: utxo_batch_insertion_proof_for_circuit,
        };
        let circuit_input = BitcoinConsensusCircuitInput {
            method_id: app_state.bitcoin_guest_id,
            prev_proof: prev_proof_type_for_batch,
            input_data: circuit_data,
        };

        let jmt_kv_changes_for_delta = JmtKeyValueChanges {
            creations: batch_utxo_creations_for_circuit_and_delta
                .into_iter()
                .collect(),
            deletions: actual_deletions_for_delta,
        };

        let jmt_operations_bytes_for_db = match borsh::to_vec(&jmt_kv_changes_for_delta) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    "WORKER: Failed to serialize JmtKeyValueChanges for DB: {}. Skipping proof.",
                    e
                );
                continue;
            }
        };

        let circuit_input_bytes = borsh::to_vec(&circuit_input)
            .context("Failed to serialize circuit input for ExecutorEnv")?;

        let mut receipts_for_assumptions: Vec<Receipt> = Vec::new();
        if let BitcoinConsensusPrevProofType::PrevProof(prev_output) = &circuit_input.prev_proof {
            let proof_db_locked = app_state.proof_db.lock().await;
            let prev_proof_block_hash_bytes =
                prev_output.bitcoin_state.header_chain_state.best_block_hash;
            if let Ok(Some(prev_entry_for_assumption)) =
                proof_db_locked.find_proof_by_hash(&prev_proof_block_hash_bytes)
            {
                match Receipt::try_from_slice(&prev_entry_for_assumption.receipt) {
                    Ok(receipt) => receipts_for_assumptions.push(receipt),
                    Err(e) => {
                        warn!("WORKER: Failed to deserialize previous receipt for assumption: {}. This assumption will be skipped.", e);
                    }
                }
            } else {
                warn!("WORKER: Could not find previous RISC Zero receipt (via ProofEntry hash {:?}) for ZKVM assumption. Guest must handle.",
                    BlockHash::from_slice(&prev_proof_block_hash_bytes).unwrap_or(BlockHash::all_zeros()));
            }
        }

        info!(
            "Starting proof generation for batch ({} blocks, heights {}-{}). Final JMT version for proof: {}",
            block_batch.len(), first_block_height_in_batch, last_block_height_in_batch, final_jmt_version_for_this_batch_proof
        );
        let elf_bytes = app_state.bitcoin_guest_elf.clone();

        match tokio::task::spawn_blocking(move || {
            let mut env_builder = ExecutorEnv::builder();
            env_builder.write_slice(&circuit_input_bytes);
            for receipt in receipts_for_assumptions {
                env_builder.add_assumption(receipt);
            }
            let built_env = env_builder
                .build()
                .context("Failed to build ExecutorEnv inside spawn_blocking")?;

            let prover = default_prover();
            let prove_info =
                prover.prove_with_opts(built_env, &elf_bytes, &ProverOpts::succinct())?;
            Ok::<ProveInfo, anyhow::Error>(prove_info)
        })
        .await
        {
            Ok(Ok(prove_info)) => {
                let receipt = prove_info.receipt;
                info!(
                    "Proof successful for batch ending height {}. Cycles: {}",
                    last_block_height_in_batch, prove_info.stats.total_cycles
                );

                let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes)?;

                if output.bitcoin_state.utxo_set_commitment.jmt_root != temp_jmt_root {
                    error!("CRITICAL JMT ROOT MISMATCH! Host pre-proof JMT root: {:?}, Guest output JMT root: {:?}. Batch {}-{}",
                        temp_jmt_root, output.bitcoin_state.utxo_set_commitment.jmt_root, first_block_height_in_batch, last_block_height_in_batch);
                    continue;
                }
                if output.bitcoin_state.header_chain_state.block_height
                    != last_block_height_in_batch
                {
                    error!("CRITICAL BLOCK HEIGHT MISMATCH! Expected last block height: {}, Guest output height: {}. Batch {}-{}",
                        last_block_height_in_batch, output.bitcoin_state.header_chain_state.block_height, first_block_height_in_batch, last_block_height_in_batch);
                    continue;
                }

                let proof_bytes_for_db = borsh::to_vec(&receipt)?;

                let parent_block_hash_for_entry_bytes = match last_proven_hash_for_linking {
                    Some(hash) => hash.to_byte_array(),
                    None => BlockHash::all_zeros().to_byte_array(),
                };

                let current_batch_last_block_hash_bytes =
                    output.bitcoin_state.header_chain_state.best_block_hash;

                let entry_to_store = ProofEntry {
                    block_height: last_block_height_in_batch,
                    block_hash: current_batch_last_block_hash_bytes,
                    prev_hash: parent_block_hash_for_entry_bytes,
                    method_id: app_state.bitcoin_guest_id,
                    receipt: proof_bytes_for_db,
                    last_version: final_jmt_version_for_this_batch_proof,
                    jmt_operations_bytes: jmt_operations_bytes_for_db,
                };

                let mut proof_db_locked = app_state.proof_db.lock().await;
                match proof_db_locked.save_proof(entry_to_store) {
                    Ok(_) => {
                        let current_batch_last_block_hash_for_appstate = BlockHash::from_slice(
                            &current_batch_last_block_hash_bytes,
                        )
                        .context(
                            "Failed to convert current batch last block hash for AppState update",
                        )?;
                        drop(proof_db_locked);
                        info!(
                            "Proof for batch ending height {} (block hash {}, JMT version {}) stored successfully.",
                            last_block_height_in_batch,
                            current_batch_last_block_hash_for_appstate,
                            final_jmt_version_for_this_batch_proof
                        );

                        let mut shared_jmt_root_guard = app_state.current_jmt_root.lock().await;
                        let mut shared_prev_11_times_guard =
                            app_state.prev_11_blocks_time.lock().await;
                        let mut shared_last_proven_height_guard =
                            app_state.last_proven_block_height.lock().await;
                        let mut shared_last_proven_hash_guard =
                            app_state.last_proven_block_hash.lock().await;

                        *shared_jmt_root_guard = temp_jmt_root;
                        *shared_prev_11_times_guard = temp_prev_11_times;
                        *shared_last_proven_height_guard = Some(last_block_height_in_batch);
                        *shared_last_proven_hash_guard =
                            Some(current_batch_last_block_hash_for_appstate);

                        info!(
                            "Shared state updated. Last proven height: {}, Last proven hash: {:?}, JMT root {:?}, JMT version in DB {}.",
                            last_block_height_in_batch,
                            *shared_last_proven_hash_guard,
                            temp_jmt_root,
                            final_jmt_version_for_this_batch_proof
                        );
                    }
                    Err(e) => {
                        drop(proof_db_locked);
                        error!("WORKER: Failed to store proof for batch {}-{}: {}. JMT state in RocksDB was advanced to version {} but proof not saved.",
                            first_block_height_in_batch, last_block_height_in_batch, e, final_jmt_version_for_this_batch_proof);
                    }
                }
            }
            Ok(Err(anyhow_err)) => {
                error!(
                    "WORKER: Proof generation failed for batch {}-{}: {}",
                    first_block_height_in_batch, last_block_height_in_batch, anyhow_err
                );
            }
            Err(join_err) => {
                error!(
                    "WORKER: Proving task panicked or was cancelled for batch {}-{}: {}",
                    first_block_height_in_batch, last_block_height_in_batch, join_err
                );
            }
        }
    }

    info!("Proof worker task finished.");
    Ok(())
}

pub trait CircuitBlockExt {
    fn get_height_from_rpc(
        &self,
        rpc: &RpcClient,
    ) -> impl std::future::Future<Output = Result<u32>> + Send;
}

impl CircuitBlockExt for CircuitBlock {
    async fn get_height_from_rpc(&self, rpc: &RpcClient) -> Result<u32> {
        let block_hash_arr = self.block_header.compute_block_hash();
        let block_hash = BlockHash::from_slice(&block_hash_arr).with_context(|| {
            format!(
                "Failed to create BlockHash from computed hash: {:?}",
                block_hash_arr
            )
        })?;
        Ok(rpc
            .get_block_header_info(&block_hash)
            .await
            .with_context(|| format!("RPC failed to get header info for {}", block_hash))?
            .height as u32)
    }
}

pub trait PrevProofExt {
    fn get_prev_block_hash_bytes(&self) -> Option<[u8; 32]>;
}
impl PrevProofExt for BitcoinConsensusPrevProofType {
    fn get_prev_block_hash_bytes(&self) -> Option<[u8; 32]> {
        match self {
            BitcoinConsensusPrevProofType::PrevProof(output_boxed) => Some(
                output_boxed
                    .bitcoin_state
                    .header_chain_state
                    .best_block_hash,
            ),
            BitcoinConsensusPrevProofType::GenesisBlock => None,
        }
    }
}
