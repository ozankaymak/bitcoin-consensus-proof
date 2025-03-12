use bitcoin_consensus_core::bitcoin_merkle::BitcoinMerkleTree;

fn main() {
    // Generate 1024 sample txids
    let mut txids = Vec::with_capacity(1024);
    for i in 0..1024 {
        let mut txid = [0u8; 32];
        for j in 0..32 {
            txid[j] = ((i + j) % 256) as u8;
        }
        txids.push(txid);
    }
    
    // Generate root using the full tree method
    let start_full = std::time::Instant::now();
    let tree = BitcoinMerkleTree::new(txids.clone());
    let root_full = tree.root();
    let duration_full = start_full.elapsed();
    
    // Generate root using the memory-efficient method
    let start_efficient = std::time::Instant::now();
    let root_efficient = BitcoinMerkleTree::generate_root(txids.clone());
    let duration_efficient = start_efficient.elapsed();
    
    // Verify both methods produce the same root
    assert_eq\!(root_full, root_efficient);
    
    println\!("Memory complexity analysis of Merkle tree computation:");
    println\!("Level 0 (leaves): {} hashes", txids.len());
    
    let mut level_size = txids.len();
    let mut level = 1;
    
    while level_size > 1 {
        level_size = (level_size + 1) / 2; // Ceiling division to handle odd numbers
        println\!("Level {}: {} hashes", level, level_size);
        level += 1;
    }
    
    println\!("\nPerformance comparison:");
    println\!("Full tree method: {:?}", duration_full);
    println\!("Efficient method: {:?}", duration_efficient);
}
