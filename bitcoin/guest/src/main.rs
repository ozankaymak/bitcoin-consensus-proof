
/// Entrypoint for the Bitcoin consensus zkVM guest program
/// This initializes a zkVM guest and runs the Bitcoin consensus circuit
fn main() {
    // Initialize the Risc0 guest implementation
    let zkvm_guest = bitcoin_consensus_core::zkvm::Risc0Guest::new();
    
    // Execute the Bitcoin consensus circuit with the guest implementation
    bitcoin_consensus_core::bitcoin_consensus_circuit(&zkvm_guest);
}
