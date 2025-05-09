use bitcoin::{ScriptBuf, TxOut};

pub enum TxoutType {
    NonStandard,
    P2A,            // Pay-to-Anchor
    P2PK,           // Pay-to-Pubkey
    P2PKH,          // Pay-to-PubkeyHash
    P2SH,           // Pay-to-ScriptHash
    MultiSig,       // Bare MultiSig
    NullData,       // Unspendable OP_RETURN script that carries data
    P2WSH,          // Pay-to-Witness-ScriptHash
    P2WPKH,         // Pay-to-Witness-PubkeyHash
    P2TR,           // Pay-to-Taproot
    WitnessUnknown, // Only for Witness versions not already defined above
}

pub fn get_txout_type(txout: &TxOut) -> TxoutType {
    let script_pubkey = &txout.script_pubkey;

    if script_pubkey.is_p2pk() {
        return TxoutType::P2PK;
    }

    if script_pubkey.is_p2pkh() {
        return TxoutType::P2PKH;
    }

    if script_pubkey.is_p2sh() {
        return TxoutType::P2SH;
    }

    if script_pubkey.is_multisig() {
        return TxoutType::MultiSig;
    }

    if script_pubkey.is_op_return() {
        return TxoutType::NullData;
    }

    if script_pubkey.is_p2wsh() {
        return TxoutType::P2WSH;
    }

    if script_pubkey.is_p2wpkh() {
        return TxoutType::P2WPKH;
    }

    if script_pubkey.is_p2tr() {
        return TxoutType::P2TR;
    }

    if is_p2a(script_pubkey) {
        return TxoutType::P2A;
    }

    if script_pubkey.is_witness_program() {
        return TxoutType::WitnessUnknown;
    }

    return TxoutType::NonStandard;
}

fn is_p2a(script_pubkey: &ScriptBuf) -> bool {
    let script_bytes = script_pubkey.as_bytes();
    script_bytes.len() == 4
        && script_bytes[0] == 0x51
        && script_bytes[1] == 0x02
        && script_bytes[2] == 0x4e
        && script_bytes[3] == 0x73
}
