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
    /// The block height at which BIP-34 activated
    ///
    /// BIP-34 required the block height to be included in the coinbase transaction,
    /// preventing duplicate coinbase transaction IDs and associated security issues.
    pub bip34_height: u32,
    // pub bip34_hash: [u8; 32],
    /// The block height at which BIP-65 (CHECKLOCKTIMEVERIFY) activated
    ///
    /// BIP-65 introduced the OP_CHECKLOCKTIMEVERIFY opcode, allowing scripts to check
    /// if a certain block height or time has been reached.
    pub bip65_height: u32,

    /// The block height at which BIP-66 (strict DER signatures) activated
    ///
    /// BIP-66 enforced strict DER encoding of signatures to prevent malleability and
    /// potential security issues.
    pub bip66_height: u32,

    /// The block height at which BIP-68, BIP-112, and BIP-113 (CSV) activated
    ///
    /// These BIPs introduced relative timelocks (CheckSequenceVerify) and improved
    /// timestamp handling for consensus.
    pub csv_height: u32,

    /// The block height at which Segregated Witness (segwit) activated
    ///
    /// Segwit (BIP-141, BIP-143, BIP-144, BIP-145) separated transaction signatures
    /// from transaction data, fixing transaction malleability and enabling various improvements.
    pub segwit_height: u32,

    /// The block height at which Taproot (BIP-341, BIP-342) activated
    ///
    /// Taproot introduced Schnorr signatures, Merklelized Alternative Script Trees (MAST),
    /// and improved privacy and efficiency for Bitcoin transactions.
    pub taproot_activation_height: u32,
    // The following fields are commented out but could be added in the future:
    // pub genesis_block_hash: [u8; 32], // Genesis block hash
    // pub genesis_block_header: BlockHeader, // Genesis block header
    // pub genesis_block: Block, // Genesis block
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

            // BIP-66 (Strict DER signatures) activation height
            bip66_height: 363725,

            // BIP-68, BIP-112, BIP-113 (CSV) activation height
            csv_height: 419328,

            // Segregated Witness (BIP-141, BIP-143, BIP-144, BIP-145) activation height
            segwit_height: 481824,

            // Taproot (BIP-341, BIP-342) activation height
            taproot_activation_height: 709632,
            // Genesis block hash (commented out for now)
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
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
            subsidy_halving_interval: 210000,
            bip16_height: 1,
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_activation_height: 0,
            // genesis_block_hash: [0x00; 32], // 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
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
            subsidy_halving_interval: 210000,
            bip16_height: 1,
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_activation_height: 0,
            // genesis_block_hash: [0x00; 32], // 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
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
            subsidy_halving_interval: 150,
            bip16_height: 0,
            bip34_height: 100000000,
            bip65_height: 1351,
            bip66_height: 1251,
            csv_height: 1,
            segwit_height: 1,
            taproot_activation_height: 0,
            // genesis_block_hash: [0x00; 32], // 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
        },
        None => NetworkParams {
            // Default to mainnet
            max_bits: 0x1D00FFFF,
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
            subsidy_halving_interval: 210000,
            bip16_height: 173805,
            bip34_height: 227931,
            bip65_height: 388381,
            bip66_height: 363725,
            csv_height: 419328,
            segwit_height: 481824,
            taproot_activation_height: 709632,
            // genesis_block_hash: [0x00; 32], // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        },
        _ => panic!("Unsupported network"),
    }
};
