use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::transaction::CircuitTransaction;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct UTXOSetState {
    pub utxo_set_commitment: [u8; 32], // TODO: Change this in the future.
}

impl UTXOSetState {
    pub fn new() -> Self {
        UTXOSetState {
            utxo_set_commitment: [0u8; 32],
        }
    }
    pub fn verify_and_apply_transaction(&mut self, transaction: &CircuitTransaction) {
        todo!()
    }
}
