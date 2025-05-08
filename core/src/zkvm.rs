use std::io::Write;

use borsh::BorshDeserialize;
use risc0_zkvm::guest::env;

/// Interface for zero-knowledge virtual machine guests
///
/// This trait defines the necessary functionality for interacting with
/// a zkVM from the guest side.
pub trait ZkvmGuest {
    /// Reads and deserializes data sent from the host
    fn read_from_host<T: borsh::BorshDeserialize>(&self) -> T;

    /// Commits data to the zkVM journal that will be included in the proof
    fn commit<T: borsh::BorshSerialize>(&self, item: &T);

    /// Verifies another proof within this guest execution
    fn verify<T: borsh::BorshSerialize>(&self, method_id: [u32; 8], journal: &T);
}

/// Represents a zkVM proof with its method ID and journal data
#[derive(Debug, Clone)]
pub struct ZKProof {
    /// Method ID identifying which zkVM program created this proof
    pub method_id: [u32; 8],

    /// Serialized journal data from the proof
    pub journal: Vec<u8>,
}

/// Implementation of ZkvmGuest for Risc0 zkVM
#[derive(Debug, Clone)]
pub struct Risc0Guest;

impl Risc0Guest {
    /// Creates a new Risc0Guest instance
    pub fn new() -> Self {
        Self {}
    }
}

impl ZkvmGuest for Risc0Guest {
    fn read_from_host<T: borsh::BorshDeserialize>(&self) -> T {
        let mut reader = env::stdin();
        BorshDeserialize::deserialize_reader(&mut reader)
            .expect("Failed to deserialize input from host")
    }

    fn commit<T: borsh::BorshSerialize>(&self, item: &T) {
        let buf = borsh::to_vec(item).expect("Serialization to vec is infallible");
        let mut journal = env::journal();
        journal.write_all(&buf).unwrap();
    }

    fn verify<T: borsh::BorshSerialize>(&self, method_id: [u32; 8], output: &T) {
        env::verify(method_id, &borsh::to_vec(output).unwrap()).unwrap();
    }
}
