use crypto_bigint::U256;

// TODO: Implement checkpoints
#[derive(Clone, Debug)]
pub struct NetworkParams {
    pub max_bits: u32,
    pub max_target: U256,
    pub max_target_bytes: [u8; 32],
    pub subsidy_halving_interval: u32,
    pub bip16_height: u32,
    // pub bip16_exception: Option<[u8; 32]>,
    pub bip34_height: u32,
    // pub bip34_hash: [u8; 32],
    pub bip65_height: u32,
    pub bip66_height: u32,
    pub csv_height: u32,
    pub segwit_height: u32,
    pub taproot_activation_height: u32,
    // pub genesis_block_hash: [u8; 32], // Genesis block hash (commented out)
    // pub genesis_block_header: BlockHeader, // Genesis block header (commented out)
    // pub genesis_block: Block, // Genesis block (commented out)
}

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

// Const evaluation of network type from environment
pub const IS_MAINNET: bool = matches!(NETWORK_TYPE.as_bytes(), b"mainnet");
pub const IS_SIGNET: bool = matches!(NETWORK_TYPE.as_bytes(), b"signet");
pub const IS_REGTEST: bool = matches!(NETWORK_TYPE.as_bytes(), b"regtest");
pub const IS_TESTNET4: bool = matches!(NETWORK_TYPE.as_bytes(), b"testnet4");
pub const MINIMUM_WORK_TESTNET4: U256 =
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000100010001");

pub const NETWORK_PARAMS: NetworkParams = {
    match option_env!("BITCOIN_NETWORK") {
        Some(n) if matches!(n.as_bytes(), b"mainnet") => NetworkParams {
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
