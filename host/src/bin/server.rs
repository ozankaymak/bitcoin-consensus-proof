// host/src/server_main.rs

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    consensus::Encodable, // For getting block size
    Block as RpcBlock,    // Renamed to avoid clash with CircuitBlock
    BlockHash,
};
use bitcoin_consensus_core::{
    block::CircuitBlock,
    softfork_manager::BIPFlags,
    utxo_set::{KeyOutPoint, UTXO},
    BitcoinConsensusCircuitData, BitcoinConsensusCircuitInput, BitcoinConsensusCircuitOutput,
    BitcoinConsensusPrevProofType, UTXODeletionUpdateProof, UTXOInsertionUpdateProof,
};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use borsh::{BorshDeserialize, BorshSerialize};
use dotenv::dotenv; // For .env file
use host::{
    // Assuming these are accessible from host crate
    delete_utxo_and_generate_update_proof,
    insert_utxos_and_generate_update_proofs,
    rocks_db::RocksDbStorage,
    sqlite::{ProofDb, ProofEntry},
};
use jmt::RootHash;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::{
    collections::{BTreeMap, VecDeque},
    env, fs,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::EnvFilter;
use bitcoin::hashes::Hash;

// --- Configuration ---
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
    max_batch_size_bytes: usize, // Max cumulative block size for a batch
}

impl Config {
    fn load() -> Result<Self> {
        dotenv().ok(); // Load .env file if present

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
                .context("TARGET_CATCHUP_HEIGHT must be set from .env")?
                .parse()?,
            max_batch_size_bytes: env::var("MAX_BATCH_SIZE_BYTES")
                .unwrap_or_else(|_| "10000000".to_string()) // 10MB
                .parse()?,
        })
    }
}

// --- Main Application State (Shared) ---
// These Arc<Mutex<T>> are for state that is read by the orchestrator
// and updated by the proof_worker upon successful proof of a batch.
struct AppState {
    config: Config,
    rpc_client: RpcClient, // RPC client can be Arc if shared by multiple tasks directly, but here primarily orchestrator uses it.
    utxo_db: RocksDbStorage, // RocksDbStorage might need its own internal synchronization or be used by one writer (worker) at a time.
    proof_db: ProofDb,       // Same for ProofDb
    bitcoin_guest_elf: Vec<u8>,
    bitcoin_guest_id: [u32; 8],
    // Critical shared states reflecting the blockchain after the last *successful* proof.
    prev_11_blocks_time: Arc<Mutex<[u32; 11]>>,
    current_jmt_root: Arc<Mutex<RootHash>>,
    last_proven_block_height: Arc<Mutex<Option<u32>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(Level::INFO.to_string())),
        )
        .init();

    info!("Starting Bitcoin Consensus Proving Server (server_main.rs)...");

    let config = Config::load().context("Failed to load configuration")?;
    info!("Config loaded: {:?}", config);

    // Create directories if they don't exist
    fs::create_dir_all(&config.rocks_db_path).with_context(|| {
        format!(
            "Failed to create UTXO DB directory: {:?}",
            config.rocks_db_path
        )
    })?;
    // if let Some(parent) = config.proof_db_path.parent() {
    //     fs::create_dir_all(parent)
    //         .with_context(|| format!("Failed to create Proof DB directory: {:?}", parent))?;
    // }

    let rpc_client = RpcClient::new(
        &config.rpc_url,
        Auth::UserPass(config.rpc_user.clone(), config.rpc_pass.clone()),
    )
    .await
    .context("Failed to create RPC client")?;

    let utxo_db = RocksDbStorage::new(config.rocks_db_path.to_str().unwrap())
        .context("Failed to initialize RocksDB UTXO storage")?;
    let proof_db =
        ProofDb::new(&config.proof_db_path).context("Failed to initialize SQLite ProofDB")?;

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

    let (initial_last_proven_height, initial_prev_11_times, initial_jmt_root) =
        load_initial_server_state(&proof_db, &utxo_db).await?;

    info!(
        "Initial server state loaded. Last proven height: {:?}, JMT root: {:?}",
        initial_last_proven_height, initial_jmt_root
    );

    let app_state = Arc::new(AppState {
        config: config.clone(),
        rpc_client,
        utxo_db,
        proof_db,
        bitcoin_guest_elf,
        bitcoin_guest_id,
        prev_11_blocks_time: Arc::new(Mutex::new(initial_prev_11_times)),
        current_jmt_root: Arc::new(Mutex::new(initial_jmt_root)),
        last_proven_block_height: Arc::new(Mutex::new(initial_last_proven_height)),
    });

    // Proving queue will send batches (Vec<CircuitBlock>)
    let (block_batch_sender, block_batch_receiver) = mpsc::channel::<Vec<CircuitBlock>>(10); // Buffer size 10 batches

    let proof_worker_handle =
        tokio::spawn(proof_worker_task(app_state.clone(), block_batch_receiver));

    // Orchestrator task for catch-up and continuous syncing
    let orchestrator_handle =
        tokio::spawn(orchestrator_task(app_state.clone(), block_batch_sender));

    info!("Server initialized. Orchestrator and proof worker are running.");
    info!("Target Network: {}", config.network);

    // Placeholder for HTTP server initialization later
    // let http_server_handle = tokio::spawn(async { /* ... http server ... */ });

    tokio::select! {
        res = orchestrator_handle => { error!("Orchestrator task exited: {:?}", res); }
        res = proof_worker_handle => { error!("Proof worker task exited: {:?}", res); }
        // res = http_server_handle => { error!("HTTP server task exited: {:?}", res); }
    }

    Ok(())
}

async fn load_initial_server_state(
    proof_db: &ProofDb,
    utxo_db: &RocksDbStorage,
) -> Result<(Option<u32>, [u32; 11], RootHash)> {
    // This function needs to correctly load the state *after* the last successfully proven block.
    // The ProofEntryData in your sqlite.rs should store `prev_11_blocks_time_after_proof`
    // and `jmt_root_after_proof`.
    match proof_db.get_latest_proof_entry_data() {
        Ok(Some(latest_proof_data)) => {
            info!(
                "Resuming from last known state from proof at height {}.",
                latest_proof_data.block_height
            );
            let times = latest_proof_data
                .prev_11_blocks_time_after_proof
                .unwrap_or_else(|| {
                    warn!("MTP window not found in last proof entry, defaulting to zeros. This might be incorrect for next proof.");
                    [0; 11]
                });
            let root = latest_proof_data
                .jmt_root_after_proof
                .unwrap_or_else(|| {
                    warn!("JMT root not found in last proof entry, defaulting to placeholder. This might be incorrect for next proof.");
                    default_jmt_root()
                });
            Ok((Some(latest_proof_data.block_height), times, root))
        }
        Ok(None) => {
            info!("No previous proof state found in DB. Starting as fresh (before genesis).");
            // This state represents the state *before* proving the genesis block (height 0).
            Ok((None, [0; 11], default_jmt_root()))
        }
        Err(e) => {
            error!(
                "Error loading initial state from ProofDB: {}. Starting fresh.",
                e
            );
            Ok((None, [0; 11], default_jmt_root()))
        }
    }
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

    // --- Phase 1: Initial Catch-up ---
    let mut current_height_to_process = app_state
        .last_proven_block_height
        .lock()
        .await
        .map_or(0, |h| h + 1);
    let target_catchup_height = app_state.config.target_catchup_height;

    info!(
        "Starting catch-up phase. From height {} to {}.",
        current_height_to_process, target_catchup_height
    );

    while current_height_to_process <= target_catchup_height {
        let mut batch_to_prove: Vec<CircuitBlock> = Vec::new();
        let mut current_batch_size_bytes: usize = 0;
        let batch_start_height = current_height_to_process;

        debug!("Forming batch starting from height {}.", batch_start_height);

        // Loop to form a batch
        while current_height_to_process <= target_catchup_height {
            let block_hash = match app_state
                .rpc_client
                .get_block_hash(current_height_to_process as u64).await
            {
                Ok(hash) => hash,
                Err(e) => {
                    error!(
                        "RPC error getting block hash for height {}: {}. Pausing catch-up.",
                        current_height_to_process, e
                    );
                    tokio::time::sleep(Duration::from_secs(
                        app_state.config.tip_check_interval_secs,
                    ))
                    .await; // Wait before retrying
                    continue; // Retry getting this block hash
                }
            };
            let rpc_block = match app_state.rpc_client.get_block(&block_hash).await {
                Ok(block) => block,
                Err(e) => {
                    error!(
                        "RPC error getting block for height {}: {}. Pausing catch-up.",
                        current_height_to_process, e
                    );
                    tokio::time::sleep(Duration::from_secs(
                        app_state.config.tip_check_interval_secs,
                    ))
                    .await;
                    continue; // Retry getting this block
                }
            };

            let mut block_bytes_for_size_check = Vec::new();
            rpc_block.consensus_encode(&mut block_bytes_for_size_check)?;
            let block_size = block_bytes_for_size_check.len();

            if !batch_to_prove.is_empty()
                && (current_batch_size_bytes + block_size > app_state.config.max_batch_size_bytes)
            {
                debug!(
                    "Max batch size reached before adding block {}. Current batch size: {}",
                    current_height_to_process, current_batch_size_bytes
                );
                break; // Finalize current batch without this block
            }

            batch_to_prove.push(CircuitBlock::from(rpc_block));
            current_batch_size_bytes += block_size;
            debug!(
                "Added block height {} (size: {} bytes) to batch. Batch size: {}/{} bytes.",
                current_height_to_process,
                block_size,
                current_batch_size_bytes,
                app_state.config.max_batch_size_bytes
            );

            if current_height_to_process == target_catchup_height {
                current_height_to_process += 1;
                break;
            }
            current_height_to_process += 1;
        }

        if !batch_to_prove.is_empty() {
            let batch_actual_end_height = batch_start_height + batch_to_prove.len() as u32 - 1;
            info!(
                "Sending batch ({} blocks, heights {}-{}) to proof worker.",
                batch_to_prove.len(),
                batch_start_height,
                batch_actual_end_height
            );
            if block_batch_sender.send(batch_to_prove).await.is_err() {
                error!("Failed to send block batch to proving queue. Worker might have exited.");
                return Err(anyhow!("Block batch queue receiver dropped."));
            }

            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let last_proven = *app_state.last_proven_block_height.lock().await;
                if last_proven.map_or(false, |h| h >= batch_actual_end_height) {
                    info!(
                        "Batch ending at height {} processed.",
                        batch_actual_end_height
                    );
                    break;
                }
                debug!(
                    "Waiting for batch ending at height {} to be processed. Last proven: {:?}...",
                    batch_actual_end_height, last_proven
                );
            }
        } else if current_height_to_process <= target_catchup_height {
            warn!(
                "Empty batch formed but still below target catchup height {}. Current height: {}",
                target_catchup_height, current_height_to_process
            );
            let single_block_hash = app_state
                .rpc_client
                .get_block_hash(current_height_to_process as u64).await?;
            let single_rpc_block = app_state.rpc_client.get_block(&single_block_hash).await?;
            let mut temp_bytes = Vec::new();
            single_rpc_block.consensus_encode(&mut temp_bytes)?;

            if temp_bytes.len() > app_state.config.max_batch_size_bytes {
                error!("Single block at height {} (size: {}) exceeds max_batch_size_bytes ({}). Cannot process. Halting catch-up.", 
                    current_height_to_process, temp_bytes.len(), app_state.config.max_batch_size_bytes);
                return Err(anyhow!(
                    "Block too large for configured max_batch_size_bytes."
                ));
            } else {
                // This case implies some logic error if an empty batch was formed when blocks are available and within size.
                // For safety, just wait and retry iteration.
                warn!("Logic error: Empty batch formed unexpectedly. Retrying iteration for height {}.", current_height_to_process);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
    info!(
        "Catch-up phase completed. Target height {} reached or passed.",
        target_catchup_height
    );

    // --- Phase 2: Continuous Syncing ---
    info!("Switching to continuous syncing mode.");
    let mut tip_check_interval = tokio::time::interval(Duration::from_secs(
        app_state.config.tip_check_interval_secs,
    ));

    loop {
        tip_check_interval.tick().await;
        debug!("(Continuous) Checking for new blocks...");

        let chain_tip_hash = match app_state.rpc_client.get_best_block_hash().await {
            Ok(hash) => hash,
            Err(e) => {
                error!("RPC: Failed to get best block hash: {}", e);
                continue;
            }
        };
        let chain_tip_header = match app_state.rpc_client.get_block_header_info(&chain_tip_hash).await {
            Ok(header) => header,
            Err(e) => {
                error!(
                    "RPC: Failed to get block header for tip {}: {}",
                    chain_tip_hash, e
                );
                continue;
            }
        };
        let chain_tip_height = chain_tip_header.height as u32;

        let last_proven_h_guard = app_state.last_proven_block_height.lock().await;
        let next_height_to_prove = last_proven_h_guard.map_or(0, |h| h + 1);

        if chain_tip_height >= next_height_to_prove {
            info!(
                "(Continuous) New block(s) detected. Chain tip: {}, Next to prove: {}.",
                chain_tip_height, next_height_to_prove
            );
            drop(last_proven_h_guard); // Release lock before RPC calls and await

            let block_hash_to_prove = match app_state
                .rpc_client
                .get_block_hash(next_height_to_prove as u64).await
            {
                Ok(hash) => hash,
                Err(e) => {
                    error!(
                        "RPC: Failed to get block hash for height {}: {}",
                        next_height_to_prove, e
                    );
                    continue;
                }
            };
            let rpc_block_to_prove = match app_state.rpc_client.get_block(&block_hash_to_prove).await {
                Ok(block) => block,
                Err(e) => {
                    error!(
                        "RPC: Failed to get block for height {}: {}",
                        next_height_to_prove, e
                    );
                    continue;
                }
            };

            let circuit_block = CircuitBlock::from(rpc_block_to_prove);
            info!(
                "(Continuous) Queuing block height {} for proving.",
                next_height_to_prove
            );
            if block_batch_sender.send(vec![circuit_block]).await.is_err() {
                error!(
                    "(Continuous) Failed to send block to proving queue. Worker might have exited."
                );
                return Err(anyhow!("Block batch queue receiver dropped."));
            }

            let expected_proven_height = next_height_to_prove;
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
                    "(Continuous) Waiting for block height {} to be processed...",
                    expected_proven_height
                );
            }
        } else {
            drop(last_proven_h_guard);
            debug!(
                "(Continuous) No new blocks to prove. Synced up to height {}.",
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

        let first_block_height_in_batch = block_batch
            .first()
            .unwrap()
            .get_height_from_rpc(&app_state.rpc_client)
            .await?;
        let last_block_height_in_batch = block_batch
            .last()
            .unwrap()
            .get_height_from_rpc(&app_state.rpc_client)
            .await?;

        info!(
            "Proof worker received batch of {} blocks (heights {}-{}) for proving.",
            block_batch.len(),
            first_block_height_in_batch,
            last_block_height_in_batch
        );

        // --- Critical State Initialization for the Batch ---
        let mut temp_jmt_root: RootHash;
        let mut temp_prev_11_times: [u32; 11];
        let prev_proof_type_for_batch: BitcoinConsensusPrevProofType;

        // Lock shared state to get the starting point for this batch
        {
            let shared_jmt_root_guard = app_state.current_jmt_root.lock().await;
            let shared_prev_11_times_guard = app_state.prev_11_blocks_time.lock().await;
            let shared_last_proven_height_guard = app_state.last_proven_block_height.lock().await;

            temp_jmt_root = *shared_jmt_root_guard;
            temp_prev_11_times = *shared_prev_11_times_guard;

            prev_proof_type_for_batch = match *shared_last_proven_height_guard {
                Some(prev_h) if prev_h == first_block_height_in_batch - 1 => {
                    match app_state.proof_db.get_proof_by_height(prev_h) {
                        // Ensure get_proof_by_height fetches ProofEntryData
                        Ok(Some(prev_proof_entry_data)) => {
                            let receipt: Receipt =
                                Receipt::try_from_slice(&prev_proof_entry_data.proof_data)?;
                            let output = BitcoinConsensusCircuitOutput::try_from_slice(
                                &receipt.journal.bytes,
                            )?;
                            info!(
                                "Batch starts after proven height {}. Using its proof.",
                                prev_h
                            );
                            BitcoinConsensusPrevProofType::PrevProof(output)
                        }
                        _ => {
                            error!("WORKER: Could not find/load prev proof for height {}. This is unexpected if not genesis.", prev_h);
                            // This logic needs to be robust. If the orchestrator guarantees sequentiality, this shouldn't happen
                            // unless it's the very first block (height 0 or configured genesis).
                            if first_block_height_in_batch == 0 {
                                // Or configured genesis height
                                info!("WORKER: Assuming genesis for batch starting at height 0 as no prior proof found.");
                                BitcoinConsensusPrevProofType::GenesisBlock
                            } else {
                                error!("WORKER: Critical error - missing previous proof for non-genesis batch start height {}. Skipping batch.", 
                                    first_block_height_in_batch);
                                continue;
                            }
                        }
                    }
                }
                None if first_block_height_in_batch == 0 => {
                    info!(
                        "WORKER: Processing genesis batch (starts height {}).",
                        first_block_height_in_batch
                    );
                    BitcoinConsensusPrevProofType::GenesisBlock
                }
                _ => {
                    error!(
                        "WORKER: Batch start height {} is not sequential to last proven height {:?}. State mismatch. Skipping batch.",
                        first_block_height_in_batch, *shared_last_proven_height_guard
                    );
                    continue;
                }
            };
        } // Release locks

        // --- Process Blocks Within the Batch Sequentially (for UTXO state and MTP) ---
        let mut batch_utxo_deletion_proofs: VecDeque<UTXODeletionUpdateProof> = VecDeque::new();
        let mut batch_utxo_creations: BTreeMap<KeyOutPoint, UTXO> = BTreeMap::new();
        let mut current_processing_block_height = first_block_height_in_batch; // Track height within batch

        for (idx, circuit_block) in block_batch.iter().enumerate() {
            let actual_block_height = circuit_block
                .get_height_from_rpc(&app_state.rpc_client)
                .await?;
            // Ensure the block from RPC matches the expected sequential height
            if actual_block_height != current_processing_block_height {
                error!(
                    "WORKER: Height mismatch within batch! Expected {}, got {}. Aborting batch.",
                    current_processing_block_height, actual_block_height
                );
                // This indicates a serious issue, possibly with how blocks were fetched or ordered.
                break; // Abort this batch
            }

            info!(
                "WORKER: Processing block at height {} ({} of {} in batch)",
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

                    if batch_utxo_creations.contains_key(&utxo_key) {
                        batch_utxo_creations.remove(&utxo_key);
                    } else {
                        match delete_utxo_and_generate_update_proof(
                            &app_state.utxo_db,
                            &utxo_key,
                            &mut temp_jmt_root, // This JMT root evolves through the batch
                        ) {
                            Ok((utxo, proof, next_root)) => {
                                batch_utxo_deletion_proofs.push_back(UTXODeletionUpdateProof {
                                    update_proof: proof,
                                    utxo,
                                    new_root: next_root, // This new_root is specific to this deletion
                                });
                                // temp_jmt_root is updated by the function
                            }
                            Err(e) => {
                                error!(
                                    "WORKER: UTXO deletion failed for {:?}: {}. Aborting batch processing.",
                                    utxo_key, e
                                );
                                // This error should cause the entire batch to fail.
                                // A more graceful recovery might try to re-process or flag.
                                // For now, break from inner loops, then the outer.
                                return Err(anyhow!("UTXO deletion failed during batch processing for block height {}", actual_block_height).context(e));
                            }
                        }
                    }
                }
                for (vout, output) in tx.output.iter().enumerate() {
                    let utxo_key = KeyOutPoint {
                        txid: tx.compute_txid().to_byte_array(),
                        vout: vout as u32,
                    };
                    let is_coinbase = tx.is_coinbase();
                    batch_utxo_creations.insert(
                        utxo_key,
                        UTXO {
                            value: output.value.to_sat(),
                            script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                            block_height: actual_block_height,
                            is_coinbase,
                            block_time: median_time_past_for_utxo,
                        },
                    );
                }
            }
            current_processing_block_height += 1; // Move to next expected height for the batch
        } // End of for loop processing blocks in batch for UTXO changes

        let key_value_pairs_for_batch_insertion: Vec<(KeyOutPoint, UTXO)> =
            batch_utxo_creations.into_iter().collect();
        let batch_insertion_update_proofs = match insert_utxos_and_generate_update_proofs(
            &app_state.utxo_db,
            &key_value_pairs_for_batch_insertion,
            &mut temp_jmt_root, // Final update to temp_jmt_root for the batch
        ) {
            Ok(proofs) => proofs,
            Err(e) => {
                error!(
                    "WORKER: UTXO batch insertion failed: {}. Aborting batch.",
                    e
                );
                continue; // Skip to next batch from receiver
            }
        };

        // --- Prepare Circuit Input for the Whole Batch ---
        let circuit_data = BitcoinConsensusCircuitData {
            blocks: block_batch.clone(),
            utxo_deletion_update_proofs: batch_utxo_deletion_proofs,
            utxo_insertion_update_proofs: batch_insertion_update_proofs,
        };
        let circuit_input = BitcoinConsensusCircuitInput {
            method_id: app_state.bitcoin_guest_id,
            prev_proof: prev_proof_type_for_batch,
            input_data: circuit_data,
        };

        // --- Execute Prover for the Batch ---
        info!(
            "Starting proof generation for batch ({} blocks, ending height {})...",
            block_batch.len(),
            last_block_height_in_batch
        );
        let env_builder = ExecutorEnv::builder();
        let mut env_for_prover = env_builder
            .write_slice(&borsh::to_vec(&circuit_input)?)
            .build()?;

        if let BitcoinConsensusPrevProofType::PrevProof(prev_output) = &circuit_input.prev_proof {
            // The hash here is of the block *before* this batch starts
            if let Ok(Some(prev_entry_data)) = app_state
                .proof_db
                .get_proof_by_hash(&prev_output.bitcoin_state.header_chain_state.best_block_hash)
            {
                let prev_receipt_for_env = Receipt::try_from_slice(&prev_entry_data.proof_data)?;
                env_for_prover.add_assumption(prev_receipt_for_env.into());
            } else {
                warn!("WORKER: Could not find previous receipt for assumption for batch starting after {:?}. Guest must handle this.", prev_output.bitcoin_state.header_chain_state.best_block_hash);
            }
        }

        let prover = default_prover();
        match prover.prove_with_opts(
            env_for_prover,
            &app_state.bitcoin_guest_elf,
            &ProverOpts::succinct(), // Consider ProverOpts based on performance needs
        ) {
            Ok(prove_info) => {
                let receipt = prove_info.receipt;
                info!(
                    "Proof successful for batch ending height {}. Cycles: {}",
                    last_block_height_in_batch, prove_info.stats.total_cycles
                );

                let output = BitcoinConsensusCircuitOutput::try_from_slice(&receipt.journal.bytes)?;

                // Crucial checks:
                // 1. JMT root from guest matches host's calculated JMT root after batch processing
                assert_eq!(
                    output.bitcoin_state.utxo_set_commitment.jmt_root, temp_jmt_root,
                    "JMT root mismatch for batch!"
                );
                // 2. Block height in guest output matches the height of the *last* block in the batch
                assert_eq!(
                    output.bitcoin_state.header_chain_state.block_height,
                    last_block_height_in_batch,
                    "Batch end height mismatch in guest output!"
                );

                let proof_bytes = borsh::to_vec(&receipt)?;
                app_state
                    .proof_db
                    .store_proof_entry_data(&ProofEntry {
                        block_height: last_block_height_in_batch,
                        block_hash: output.bitcoin_state.header_chain_state.best_block_hash,
                        proof_data: proof_bytes,
                        prev_11_blocks_time_after_proof: Some(temp_prev_11_times),
                        jmt_root_after_proof: Some(temp_jmt_root),
                        parent_block_hash: circuit_input
                            .prev_proof
                            .get_prev_block_hash_bytes()
                            .unwrap_or([0u8; 32]),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    })
                    .context("Failed to store batch proof in DB")?;

                info!(
                    "Proof for batch ending height {} stored successfully.",
                    last_block_height_in_batch
                );

                // --- Update Shared Global State AFTER Successful Batch Proof ---
                let mut shared_jmt_root_guard = app_state.current_jmt_root.lock().await;
                let mut shared_prev_11_times_guard = app_state.prev_11_blocks_time.lock().await;
                let mut shared_last_proven_height_guard =
                    app_state.last_proven_block_height.lock().await;

                *shared_jmt_root_guard = temp_jmt_root; // Update with the JMT root *after* this batch
                *shared_prev_11_times_guard = temp_prev_11_times; // Update with MTP window *after* this batch
                *shared_last_proven_height_guard = Some(last_block_height_in_batch);

                info!(
                    "Shared state updated. Last proven height: {}",
                    last_block_height_in_batch
                );
            }
            Err(e) => {
                error!(
                    "WORKER: Proof generation failed for batch ending height {}: {}",
                    last_block_height_in_batch, e
                );
                // If proof fails, the shared global state is NOT updated.
                // The orchestrator will likely retry or eventually halt if errors persist.
            }
        }
    }

    info!("Proof worker task finished.");
    Ok(())
}

// --- Helper traits/structs ---
pub trait CircuitBlockExt {
    fn get_height_from_rpc(
        &self,
        rpc: &RpcClient,
    ) -> impl std::future::Future<Output = Result<u32>> + Send;
}

impl CircuitBlockExt for CircuitBlock {
    async fn get_height_from_rpc(&self, rpc: &RpcClient) -> Result<u32> {
        let block_hash_arr = self.block_header.compute_block_hash();
        let block_hash = BlockHash::from_slice(&block_hash_arr).context(format!(
            "Failed to create BlockHash from computed hash: {:?}",
            block_hash_arr
        ))?;
        Ok(rpc
            .get_block_header_info(&block_hash).await
            .context(format!("RPC failed to get header info for {}", block_hash))?
            .height as u32)
    }
}

pub trait PrevProofExt {
    fn get_prev_block_hash_bytes(&self) -> Option<[u8; 32]>;
}
impl PrevProofExt for BitcoinConsensusPrevProofType {
    fn get_prev_block_hash_bytes(&self) -> Option<[u8; 32]> {
        match self {
            BitcoinConsensusPrevProofType::PrevProof(output) => {
                Some(output.bitcoin_state.header_chain_state.best_block_hash)
            }
            BitcoinConsensusPrevProofType::GenesisBlock => None,
        }
    }
}

// Ensure your host/src/sqlite.rs defines ProofEntryData and methods like:
// pub struct ProofEntryData {
//     pub block_height: u32,
//     pub block_hash: [u8; 32], // Hash of the block this proof is for (last in batch)
//     pub parent_block_hash: [u8; 32], // Hash of the block *before* this proof/batch started
//     pub proof_data: Vec<u8>,
//     pub timestamp: u64, // Proof generation time
//     // State *after* this proof/batch was successfully applied
//     pub prev_11_blocks_time_after_proof: Option<[u32; 11]>,
//     pub jmt_root_after_proof: Option<RootHash>,
// }
//
// impl ProofDb {
//     pub fn get_latest_proof_entry_data(&self) -> Result<Option<ProofEntryData>>;
//     pub fn get_proof_by_height(&self, height: u32) -> Result<Option<ProofEntryData>>;
//     pub fn get_proof_by_hash(&self, block_hash: &[u8; 32]) -> Result<Option<ProofEntryData>>;
//     pub fn store_proof_entry_data(&self, entry: &ProofEntryData) -> Result<()>;
// }
