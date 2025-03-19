pub const SEGWIT_MARKER: u8 = 0x00;
pub const SEGWIT_FLAG: u8 = 0x01;
pub const MAGIC_BYTES: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80000;
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
pub const WITNESS_SCALE_FACTOR: u32 = 4;
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;
