// Bitcoin Network Parameters
// =======================
//
// This module defines parameters specific to different Bitcoin networks (mainnet, testnet, etc.)
// These parameters are crucial for consensus and determine how blocks are validated on each network.

use crypto_bigint::U256;

/// Stores the parameters for a specific Bitcoin network
///
/// Bitcoin has several networks with different parameters, such as mainnet (the primary network),
/// testnet (for testing), signet (for testing with a controlled difficulty), and regtest (for
/// local regression testing). Each network has different consensus rules and activation heights
/// for various protocol upgrades.
///
/// This struct stores the parameters that differ between networks, allowing the consensus code
/// to behave appropriately for the selected network.
// TODO: Implement checkpoints
#[derive(Clone, Debug)]
pub struct NetworkParams {
    /// Maximum difficulty bits value
    ///
    /// This is used to calculate the maximum target (minimum difficulty) allowed for a block.
    /// It represents the encoded form of the target threshold.
    pub max_bits: u32,

    /// Maximum target value as a 256-bit integer
    ///
    /// This is the decoded form of max_bits and represents the highest possible target value
    /// (lowest possible difficulty) for a block on this network.
    pub max_target: U256,

    /// Maximum target value as a byte array
    ///
    /// This is the same as max_target but represented as a 32-byte array for convenience.
    pub max_target_bytes: [u8; 32],

    /// The number of blocks between Bitcoin reward halvings
    ///
    /// Bitcoin's block reward is designed to decrease by half every subsidy_halving_interval blocks.
    /// For mainnet, this is set to 210,000 blocks (approximately 4 years).
    pub subsidy_halving_interval: u32,

    /// The block height at which BIP-16 (Pay to Script Hash) activated
    ///
    /// BIP-16 introduced P2SH (Pay to Script Hash) addresses, which allow complex redemption conditions
    /// to be hidden behind a hash, simplifying addresses and improving security.
    pub bip16_height: u32,
    // pub bip16_exception: Option<[u8; 32]>,

    // /// BIP30: Duplicate transactions
    // pub bip30_height: u32,
    pub bip34_height: u32,

    pub bip65_height: u32,

    /// BIP68: Relative lock-time using consensus-enforced sequence numbers
    pub bip68_height: u32,

    // /// BIP66: Strict DER signatures
    // pub bip66_height: u32,
    /// BIP112: CHECKSEQUENCEVERIFY
    pub bip112_height: u32,

    /// BIP113: Median time-past as endpoint for lock-time calculations
    pub bip113_height: u32,

    /// The block height at which Segregated Witness (segwit) activated
    ///
    /// Segwit (BIP-141, BIP-143, BIP-144, BIP-145) separated transaction signatures
    /// from transaction data, fixing transaction malleability and enabling various improvements.
    pub bip141_height: u32,

    /// The block height at which Taproot (BIP-341, BIP-342) activated
    ///
    /// Taproot introduced Schnorr signatures, Merklelized Alternative Script Trees (MAST),
    /// and improved privacy and efficiency for Bitcoin transactions.
    pub bip341_height: u32,
    // The following fields are commented out but could be added in the future:
    // pub genesis_block_hash: [u8; 32], // Genesis block hash
    // pub genesis_block_header: BlockHeader, // Genesis block header
    // pub genesis_block: Block, // Genesis block
    pub assume_valid_height: u32,
}

/// The currently configured Bitcoin network type
///
/// This is determined at compile time from the `BITCOIN_NETWORK` environment variable.
/// If the environment variable is not set, it defaults to "mainnet".
/// Valid values are "mainnet", "testnet4", "signet", and "regtest".
///
/// This constant is used to select the appropriate network parameters for consensus rules.
pub const NETWORK_TYPE: &str = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => "mainnet",
        Some(network) if matches!(network.as_bytes(), b"testnet4") => "testnet4",
        Some(network) if matches!(network.as_bytes(), b"signet") => "signet",
        Some(network) if matches!(network.as_bytes(), b"regtest") => "regtest",
        None => "mainnet",
        _ => panic!("Invalid network type"),
    }
};

// Convenience boolean constants for checking the current network type
/// True if the current network is Bitcoin mainnet
pub const IS_MAINNET: bool = matches!(NETWORK_TYPE.as_bytes(), b"mainnet");

/// True if the current network is Bitcoin signet
pub const IS_SIGNET: bool = matches!(NETWORK_TYPE.as_bytes(), b"signet");

/// True if the current network is Bitcoin regtest
pub const IS_REGTEST: bool = matches!(NETWORK_TYPE.as_bytes(), b"regtest");

/// True if the current network is Bitcoin testnet4
pub const IS_TESTNET4: bool = matches!(NETWORK_TYPE.as_bytes(), b"testnet4");

/// The minimum required chainwork for testnet4
///
/// Chainwork is a cumulative measure of the total work done in the blockchain.
/// It's calculated as the sum of the work in each block, which is derived from
/// the difficulty of mining that block.
///
/// This constant represents the minimum chainwork required for a testnet4 chain
/// to be considered valid. It prevents validating chains with too little work.
pub const MINIMUM_WORK_TESTNET4: U256 =
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000100010001");

/// Network parameters for the currently configured Bitcoin network
///
/// This constant holds the specific consensus parameters for the currently selected
/// network (mainnet, testnet4, signet, or regtest). The selection is determined at
/// compile time based on the BITCOIN_NETWORK environment variable.
///
/// Each network has different parameters for:
/// - Difficulty calculation (max_bits, max_target)
/// - Block reward schedule (subsidy_halving_interval)
/// - Soft fork activation heights (bip16_height, bip34_height, etc.)
///
/// These parameters are essential for implementing consistent consensus rules
/// across all nodes on the network.
pub const NETWORK_PARAMS: NetworkParams = {
    match option_env!("BITCOIN_NETWORK") {
        // Mainnet parameters
        Some(n) if matches!(n.as_bytes(), b"mainnet") => NetworkParams {
            // Maximum difficulty bits (minimum difficulty)
            max_bits: 0x1D00FFFF, // The original max target from Bitcoin's genesis block

            // Maximum target value as a 256-bit integer (minimum difficulty)
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),

            // Same max target as above, but as a 32-byte array for convenience
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],

            // Block reward halving occurs every 210,000 blocks (about 4 years)
            subsidy_halving_interval: 210000,

            // BIP-16 (Pay to Script Hash) activation height
            bip16_height: 173805,

            // BIP-34 (Block height in coinbase) activation height
            bip34_height: 227931,

            // BIP-65 (CHECKLOCKTIMEVERIFY) activation height
            bip65_height: 388381,

            // // BIP-66 (Strict DER signatures) activation height
            // bip66_height: 363725,
            bip68_height: 419328,
            bip112_height: 419328,
            bip113_height: 419328,

            // Segregated Witness (BIP-141, BIP-143, BIP-144, BIP-145) activation height
            bip141_height: 481824,

            // Taproot (BIP-341, BIP-342) activation height
            bip341_height: 709632,
            // Genesis block hash (commented out for now)
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
            assume_valid_height: 886157,
        },
        Some(n) if matches!(n.as_bytes(), b"testnet4") => NetworkParams {
            max_bits: 0x1D00FFFF,
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],

            // Block reward halving occurs every 210,000 blocks (about 4 years)
            subsidy_halving_interval: 210000,

            // BIP-16 (Pay to Script Hash) activation height
            bip16_height: 1,

            // BIP-34 (Block height in coinbase) activation height
            bip34_height: 1,

            // BIP-65 (CHECKLOCKTIMEVERIFY) activation height
            bip65_height: 1,

            // // BIP-66 (Strict DER signatures) activation height
            // bip66_height: 363725,
            bip68_height: 1,
            bip112_height: 1,
            bip113_height: 1,

            // Segregated Witness (BIP-141, BIP-143, BIP-144, BIP-145) activation height
            bip141_height: 1,

            // Taproot (BIP-341, BIP-342) activation height
            bip341_height: 1,
            // Genesis block hash (commented out for now)
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
            assume_valid_height: 72600,
        },
        Some(n) if matches!(n.as_bytes(), b"signet") => NetworkParams {
            max_bits: 0x1E0377AE,
            max_target: U256::from_be_hex(
                "00000377AE000000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 3, 119, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],

            // Block reward halving occurs every 210,000 blocks (about 4 years)
            subsidy_halving_interval: 210000,

            // BIP-16 (Pay to Script Hash) activation height
            bip16_height: 1,

            // BIP-34 (Block height in coinbase) activation height
            bip34_height: 1,

            // BIP-65 (CHECKLOCKTIMEVERIFY) activation height
            bip65_height: 1,

            // // BIP-66 (Strict DER signatures) activation height
            // bip66_height: 363725,
            bip68_height: 1,
            bip112_height: 1,
            bip113_height: 1,

            // Segregated Witness (BIP-141, BIP-143, BIP-144, BIP-145) activation height
            bip141_height: 1,

            // Taproot (BIP-341, BIP-342) activation height
            bip341_height: 1,
            // Genesis block hash (commented out for now)
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
            assume_valid_height: 237722,
        },
        Some(n) if matches!(n.as_bytes(), b"regtest") => NetworkParams {
            max_bits: 0x207FFFFF,
            max_target: U256::from_be_hex(
                "7FFFFF0000000000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                127, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],

            // Block reward halving occurs every 210,000 blocks (about 4 years)
            subsidy_halving_interval: 150,

            // BIP-16 (Pay to Script Hash) activation height
            bip16_height: 1,

            // BIP-34 (Block height in coinbase) activation height
            bip34_height: 1,

            // BIP-65 (CHECKLOCKTIMEVERIFY) activation height
            bip65_height: 1,

            // // BIP-66 (Strict DER signatures) activation height
            // bip66_height: 363725,
            bip68_height: 419328,
            bip112_height: 1,
            bip113_height: 1,

            // Segregated Witness (BIP-141, BIP-143, BIP-144, BIP-145) activation height
            bip141_height: 1,

            // Taproot (BIP-341, BIP-342) activation height
            bip341_height: 1,
            // Genesis block hash (commented out for now)
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
            assume_valid_height: 0,
        },
        None => NetworkParams {
            // Maximum difficulty bits (minimum difficulty)
            max_bits: 0x1D00FFFF, // The original max target from Bitcoin's genesis block

            // Maximum target value as a 256-bit integer (minimum difficulty)
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),

            // Same max target as above, but as a 32-byte array for convenience
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],

            // Block reward halving occurs every 210,000 blocks (about 4 years)
            subsidy_halving_interval: 210000,

            // BIP-16 (Pay to Script Hash) activation height
            bip16_height: 173805,

            // BIP-34 (Block height in coinbase) activation height
            bip34_height: 227931,

            // BIP-65 (CHECKLOCKTIMEVERIFY) activation height
            bip65_height: 388381,

            // // BIP-66 (Strict DER signatures) activation height
            // bip66_height: 363725,
            bip68_height: 419328,
            bip112_height: 0,
            bip113_height: 0,

            // Segregated Witness (BIP-141, BIP-143, BIP-144, BIP-145) activation height
            bip141_height: 481824,

            // Taproot (BIP-341, BIP-342) activation height
            bip341_height: 709632,
            // Genesis block hash (commented out for now)
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
            assume_valid_height: 886157,
        },
        _ => panic!("Unsupported network"),
    }
};
