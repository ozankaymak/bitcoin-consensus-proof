// Bitcoin Hash Functions
// ===================
//
// This module provides implementations of the cryptographic hash functions used in Bitcoin.
// These hash functions are core to Bitcoin's security and used in various parts of the protocol,
// including transaction hashing, address generation, block validation, and Merkle trees.

use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};

use sha2::{Digest, Sha256};

/// Calculates the double SHA-256 hash of the provided input
///
/// Double SHA-256 (SHA-256(SHA-256(input))) is the most commonly used hash function in Bitcoin.
/// It's used for:
/// - Transaction IDs (txid)
/// - Block hashes
/// - Merkle tree nodes
/// - Data integrity verification
///
/// # Arguments
///
/// * `input` - The data to hash
///
/// # Returns
///
/// A 32-byte array containing the double SHA-256 hash
pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    // Create a new SHA-256 hasher
    let mut hasher = Sha256::default();

    // Add the input data to the hasher
    hasher.update(input);

    // First round of SHA-256
    let result = hasher.finalize_reset();

    // Second round of SHA-256, using the result of the first round as input
    hasher.update(result);

    // Return the final 32-byte hash
    hasher.finalize().into()
}

/// Calculates the SHA-256 hash of the provided input
///
/// SHA-256 is used in Bitcoin for:
/// - First step in double SHA-256
/// - Part of Hash160 calculation
/// - BIP-340 (Taproot) tagged hashes
/// - Public key derivation in BIP-32 (HD wallets)
///
/// # Arguments
///
/// * `input` - The data to hash
///
/// # Returns
///
/// A 32-byte array containing the SHA-256 hash
pub fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    // Create a new SHA-256 hasher
    let mut hasher = Sha256::default();

    // Add the input data to the hasher
    hasher.update(input);

    // Return the 32-byte hash
    hasher.finalize().into()
}

/// Utility function to hash two 32-byte values together
///
/// This is commonly used when computing values for Merkle trees or other
/// cryptographic data structures where two hashes need to be combined.
///
/// # Arguments
///
/// * `left` - The first 32-byte hash value
/// * `right` - The second 32-byte hash value
///
/// # Returns
///
/// A 32-byte array containing the SHA-256 hash of the concatenation of left and right
pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    // Create a new SHA-256 hasher
    let mut hasher = Sha256::default();

    // Add the left hash to the hasher
    hasher.update(left);

    // Add the right hash to the hasher
    hasher.update(right);

    // Return the 32-byte hash
    hasher.finalize().into()
}

/// Calculates the RIPEMD-160 hash of the provided input
///
/// RIPEMD-160 is used in Bitcoin primarily as part of the Hash160 function
/// for creating shorter hashes used in address generation.
///
/// # Arguments
///
/// * `input` - The data to hash
///
/// # Returns
///
/// A 20-byte array containing the RIPEMD-160 hash
pub fn calculate_ripemd160(input: &[u8]) -> [u8; 20] {
    // Calculate the RIPEMD-160 hash using the bitcoin crate's implementation
    let result = ripemd160::Hash::hash(input);

    // Convert to a 20-byte array and return
    result.to_byte_array()
}

/// Calculates the Hash160 (SHA-256 then RIPEMD-160) of the provided input
///
/// Hash160 is used in Bitcoin for:
/// - P2PKH addresses (Pay to Public Key Hash)
/// - P2SH addresses (Pay to Script Hash)
/// - P2WPKH addresses (Pay to Witness Public Key Hash, nested in P2SH)
///
/// The two-step process (SHA-256 followed by RIPEMD-160) provides both
/// security and a shorter hash for efficiency.
///
/// # Arguments
///
/// * `input` - The data to hash
///
/// # Returns
///
/// A 20-byte array containing the Hash160 result
pub fn calculate_hash160(input: &[u8]) -> [u8; 20] {
    // Calculate the Hash160 using the bitcoin crate's implementation
    // This performs SHA-256 followed by RIPEMD-160
    let result = hash160::Hash::hash(input);

    // Convert to a 20-byte array and return
    result.to_byte_array()
}

/// Creates a tagged hash as specified in BIP-340 (Taproot)
///
/// Tagged hashes provide domain separation for different hash operations in
/// Bitcoin, preventing hash collisions between different contexts. The tagged
/// hash is calculated as:
///
/// SHA-256(SHA-256(tag) || SHA-256(tag) || msg)
///
/// Where || represents concatenation. This method is used extensively in BIP-340 (Schnorr
/// signatures), BIP-341 (Taproot), and BIP-342 (Tapscript).
///
/// Common tags include:
/// - "TapLeaf": For hashing tapscript leaves in a Taproot tree
/// - "TapBranch": For hashing branches in a Taproot tree
/// - "TapSighash": For the signature hash in Taproot
/// - "TapTweak": For tweaking the internal public key in Taproot
///
/// # Arguments
///
/// * `tag` - A string representing the domain/context of the hash
/// * `msg` - The message to hash
///
/// # Returns
///
/// A 32-byte array containing the tagged hash
pub fn calculate_tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    // Calculate the tag hash
    // TODO: Make these constant, hashing tags every time is inefficient
    let tag_hash = sha256::Hash::hash(tag.as_bytes());

    // Create the preimage with tag hash repeated twice followed by message
    // The preimage format is: SHA-256(tag) || SHA-256(tag) || msg
    let mut preimage = Vec::with_capacity(tag_hash.as_byte_array().len() * 2 + msg.len());

    // Add the tag hash twice
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(tag_hash.as_byte_array());

    // Add the message
    preimage.extend_from_slice(msg);

    // Hash the preimage and return the 32-byte hash
    sha256::Hash::hash(&preimage).to_byte_array()
}
