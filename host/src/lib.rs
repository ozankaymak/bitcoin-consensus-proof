use std::{fs::File, io::Read};

use bitcoin::Block;

pub fn parse_block_from_file(file_path: &str) -> Block {
    println!("Parsing block from file: {}", file_path);
    let mut file = File::open(file_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let block = bitcoin::consensus::deserialize(&buffer).unwrap();
    block
}
