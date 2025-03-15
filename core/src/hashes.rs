// Bitcoin hash implementations

use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};

use sha2::{Digest, Sha256};

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

pub fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}

/// Utility function to hash two nodes together
pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// RIPEMD160 hash function
pub fn calculate_ripemd160(input: &[u8]) -> [u8; 20] {
    let result = ripemd160::Hash::hash(input);
    result.to_byte_array()
}

/// Hash160 (SHA256 then RIPEMD160)
pub fn calculate_hash160(input: &[u8]) -> [u8; 20] {
    let result = hash160::Hash::hash(input);
    result.to_byte_array()
}

/// Create a tagged hash as specified in BIP-340 (Taproot)
pub fn calculate_tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    // Calculate the tag hash
    let tag_hash = sha256::Hash::hash(tag.as_bytes()); // TODO: Make these constant, hashing tags every time is inefficient

    // Create the preimage with tag hash repeated twice followed by message
    let mut preimage = Vec::with_capacity(tag_hash.as_byte_array().len() * 2 + msg.len());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(msg);

    // Hash the preimage
    sha256::Hash::hash(&preimage).to_byte_array()
}
