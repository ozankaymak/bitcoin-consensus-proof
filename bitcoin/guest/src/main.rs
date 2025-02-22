
fn main() {
    let zkvm_guest = core::zkvm::Risc0Guest::new();
    core::bitcoin_consensus_circuit(&zkvm_guest);
}
