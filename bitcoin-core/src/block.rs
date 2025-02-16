use bitcoin::Block;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{header_chain::CircuitBlockHeader, transaction::CircuitTransaction};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct CircuitBlock {
    pub block_header: CircuitBlockHeader,
    pub transactions: Vec<CircuitTransaction>,
}

impl CircuitBlock {
    pub fn from(block: Block) -> Self {
        let block_header = CircuitBlockHeader::from(block.header);
        let transactions = block
            .txdata
            .into_iter()
            .map(CircuitTransaction::from)
            .collect();
        CircuitBlock {
            block_header,
            transactions,
        }
    }

    pub fn into(self) -> Block {
        Block {
            header: self.block_header.into(),
            txdata: self
                .transactions
                .into_iter()
                .map(&CircuitTransaction::into)
                .collect(),
        }
    }
}

impl BorshSerialize for CircuitBlock {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, _writer: &mut W) -> borsh::io::Result<()> {
        unimplemented!()
    }
}

impl BorshDeserialize for CircuitBlock {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(_reader: &mut R) -> borsh::io::Result<Self> {
        unimplemented!()
    }
}
