use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::params::NETWORK_PARAMS;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BIPFlags {
    pub bip16: bool,
    // pub bip30: bool,
    pub bip34: bool,
    pub bip65: bool,
    // pub bip66: bool,
    pub bip68: bool,
    pub bip112: bool,
    pub bip113: bool,
    pub bip141: bool,
    pub bip341: bool,
    pub assume_valid: bool,
}

impl Default for BIPFlags {
    fn default() -> Self {
        Self {
            bip16: false,
            // bip30: false,
            bip34: false,
            bip65: false,
            // bip66: false,
            bip68: false,
            bip112: false,
            bip113: false,
            bip141: false,
            bip341: false,
            assume_valid: true,
        }
    }
}

impl BIPFlags {
    pub fn at_height(height: u32) -> Self {
        Self {
            bip16: NETWORK_PARAMS.bip16_height <= height,
            // bip30: NETWORK_PARAMS.bip30_height <= height, TODO: Not in scope right now
            bip34: NETWORK_PARAMS.bip34_height <= height,
            bip65: NETWORK_PARAMS.bip65_height <= height,
            // bip66: NETWORK_PARAMS.bip66_height <= height, TODO: Not in scope right now
            bip68: NETWORK_PARAMS.bip68_height <= height,
            bip112: NETWORK_PARAMS.bip112_height <= height,
            bip113: NETWORK_PARAMS.bip113_height <= height,
            bip141: NETWORK_PARAMS.bip141_height <= height,
            bip341: NETWORK_PARAMS.bip341_height <= height,
            assume_valid: NETWORK_PARAMS.assume_valid_height >= height,
        }
    }

    pub fn is_bip16_active(&self) -> bool {
        self.bip16
    }

    // pub fn is_bip30_active(&self) -> bool {
    //     self.bip30
    // }

    pub fn is_bip34_active(&self) -> bool {
        self.bip34
    }

    pub fn is_bip65_active(&self) -> bool {
        self.bip65
    }

    // pub fn is_bip66_active(&self) -> bool {
    //     self.bip66
    // }

    pub fn is_bip68_active(&self) -> bool {
        self.bip68
    }

    pub fn is_bip112_active(&self) -> bool {
        self.bip112
    }

    pub fn is_bip113_active(&self) -> bool {
        self.bip113
    }

    pub fn is_bip141_active(&self) -> bool {
        self.bip141
    }

    pub fn is_bip341_active(&self) -> bool {
        self.bip341
    }

    pub fn is_assume_valid(&self) -> bool {
        self.assume_valid
    }
}
