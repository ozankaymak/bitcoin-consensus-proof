// Bitcoin Constants
// ================
//
// This module defines various constant values used in the Bitcoin protocol.
// These constants are core to Bitcoin's consensus rules and define the limits and
// behavior of the network.

/// Marker byte used in segregated witness (segwit) transactions
///
/// In a serialized segwit transaction, this byte (0x00) appears where the transaction
/// input count would normally be, signaling that the transaction uses the segwit format.
/// It is followed by the segwit flag.
pub const SEGWIT_MARKER: u8 = 0x00;

/// Flag byte used in segregated witness (segwit) transactions
///
/// This byte (0x01) follows the segwit marker in a serialized segwit transaction,
/// indicating that the transaction contains witness data. After this byte, the actual
/// input count follows.
pub const SEGWIT_FLAG: u8 = 0x01;

/// Magic bytes used for the TapTweak key prefixing in Taproot
///
/// In BIP-341 (Taproot), these bytes are used as a prefix when calculating
/// the TapTweak value to tweak the internal public key with the Merkle root.
/// They provide domain separation for this specific operation.
pub const MAGIC_BYTES: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Maximum allowed signature operation cost per block
///
/// This constant limits the number of signature operations in a Bitcoin block to
/// prevent denial-of-service attacks with computationally expensive signature
/// verification operations. Each signature operation has a "cost" associated with it,
/// and the total cost for all transactions in a block must not exceed this value.
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80000;

/// Maximum allowed weight of a block
///
/// Introduced in BIP-141 (Segregated Witness), block weight is a measure that
/// replaces the previous concept of block size. A block's weight is calculated
/// as (base size * 3) + total size, where base size is the size of the block
/// with witness data removed, and total size includes witness data.
///
/// This 4MB weight limit translates to roughly 1MB of base data plus 3MB of
/// witness data in the worst case.
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;

/// The scale factor used to calculate weight for witness data
///
/// Witness data is counted at 1/4 the weight of non-witness data. This constant
/// defines that relationship: non-witness (base) data is multiplied by 4 when
/// calculating block weight, while witness data is counted directly.
pub const WITNESS_SCALE_FACTOR: u32 = 4;

/// Threshold to determine if a locktime value represents a block height or timestamp
///
/// In Bitcoin transactions, the nLockTime field can be interpreted in two ways:
/// - If the value is less than this threshold (500,000,000), it's interpreted as a block height
/// - If the value is equal to or greater than this threshold, it's interpreted as a UNIX timestamp
///
/// This threshold was chosen because block heights will not reach this value for many decades,
/// while UNIX timestamps start from January 1, 1970, and already exceed this value.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;
