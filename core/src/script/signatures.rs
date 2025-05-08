use bitcoin::opcodes::OP_0;
use bitcoin::secp256k1::{self};
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, TapSighashType};
use bitcoin::{PubkeyHash, Script};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use secp256k1::PublicKey;

use crate::script::ExecError;
use crate::*;

use super::Exec;

lazy_static::lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

impl Exec {
    pub fn check_sig_ecdsa(&mut self, sig: &[u8], pk: &[u8], script_code: &[u8]) -> bool {
        // println!("Checksig ECDSA pk bytes: {:?}", pk);
        // println!("Current script_code: {:?}", script_code);

        // let pk = match PublicKey::from_slice(pk) {
        //     Ok(pk) => pk,
        //     Err(_) => return false,
        // };

        let pk = match k256::ecdsa::VerifyingKey::from_sec1_bytes(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // println!("Checksig ECDSA pk for k256: {:?}", pk);

        if sig.is_empty() {
            return false;
        }

        let hashtype = *sig.last().unwrap();
        // let sig = match secp256k1::ecdsa::Signature::from_der(&sig[0..sig.len() - 1]) {
        //     Ok(s) => s,
        //     Err(_) => return false,
        // };
        let sig = match k256::ecdsa::Signature::from_der(&sig[0..sig.len() - 1]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sighash: [u8; 32] = if self.ctx == ExecCtx::P2WSHWrappedP2SH {
            self.sighashcache
                .p2wsh_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(script_code),
                    self.tx.prevouts[self.tx.input_idx].value,
                    //TODO(stevenroose) this might not actually emulate consensus behavior
                    EcdsaSighashType::from_consensus(hashtype as u32),
                )
                .expect("only happens on prevout index out of bounds")
                .to_byte_array()
        } else if self.ctx == ExecCtx::P2WPKHWrappedP2SH {
            // println!("Checksig script_code: {:?}", script_code);
            let key_hash160 = hash160::Hash::hash(&script_code.to_vec()[1..script_code.len() - 1]);
            let p2wpkh_script = Builder::new()
                .push_opcode(OP_0)
                .push_slice(&key_hash160.to_byte_array())
                .into_script();
            // println!("Checksig p2wpkh_script: {:?}", p2wpkh_script);
            self.sighashcache
                .p2wpkh_signature_hash(
                    self.tx.input_idx,
                    &p2wpkh_script,
                    self.tx.prevouts[self.tx.input_idx].value,
                    //TODO(stevenroose) this might not actually emulate consensus behavior
                    EcdsaSighashType::from_consensus(hashtype as u32),
                )
                .expect("only happens on prevout index out of bounds")
                .to_byte_array()
        } else if self.ctx == ExecCtx::SegwitV0P2WPKH {
            // println!("Checksig script_code: {:?}", script_code);
            let p2pkh_script = Script::from_bytes(script_code);
            let mut p2wsh_script = vec![0x00, 0x14];
            let public_key_hash = p2pkh_script[3..p2pkh_script.len() - 2].as_bytes().to_vec();
            p2wsh_script.extend(public_key_hash);
            // println!(
            //     "Checksig p2wsh_script: {:?}",
            //     ScriptBuf::from_bytes(p2wsh_script.clone())
            // );
            self.sighashcache
                .p2wpkh_signature_hash(
                    self.tx.input_idx,
                    &ScriptBuf::from_bytes(p2wsh_script),
                    // self.tx.prevouts[self.tx.input_idx].script_pubkey.clone(),
                    self.tx.prevouts[self.tx.input_idx].value,
                    //TODO(stevenroose) this might not actually emulate consensus behavior
                    EcdsaSighashType::from_consensus(hashtype as u32),
                )
                .expect("only happens on prevout index out of bounds")
                .to_byte_array()
        } else if self.ctx == ExecCtx::SegwitV0P2WSH {
            self.sighashcache
                .p2wsh_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(script_code),
                    self.tx.prevouts[self.tx.input_idx].value,
                    //TODO(stevenroose) this might not actually emulate consensus behavior
                    EcdsaSighashType::from_consensus(hashtype as u32),
                )
                .expect("only happens on prevout index out of bounds")
                .to_byte_array()
        } else if self.ctx == ExecCtx::Legacy {
            // println!("sig verify for legacy");
            // println!("Checksig script_code: {:?}", script_code);
            self.sighashcache
                .legacy_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(script_code),
                    hashtype as u32,
                )
                .expect("TODO(stevenroose) seems to only happen if prevout index out of bound")
                .to_byte_array()
        } else {
            unreachable!();
        };

        // let sighash = if self.ctx == ExecCtx::P2WSHWrappedP2SH {
        //     self.sighashcache
        //         .p2wsh_signature_hash(
        //             self.tx.input_idx,
        //             Script::from_bytes(script_code),
        //             self.tx.prevouts[self.tx.input_idx].value,
        //             //TODO(stevenroose) this might not actually emulate consensus behavior
        //             EcdsaSighashType::from_consensus(hashtype as u32),
        //         )
        //         .expect("only happens on prevout index out of bounds")
        //         .into()
        // } else if self.ctx == ExecCtx::P2WPKHWrappedP2SH {
        //     println!("Checksig script_code: {:?}", script_code);
        //     let key_hash160 = hash160::Hash::hash(&script_code.to_vec()[1..script_code.len() - 1]);
        //     let p2wpkh_script = Builder::new()
        //         .push_opcode(OP_0)
        //         .push_slice(&key_hash160.to_byte_array())
        //         .into_script();
        //     println!("Checksig p2wpkh_script: {:?}", p2wpkh_script);
        //     self.sighashcache
        //         .p2wpkh_signature_hash(
        //             self.tx.input_idx,
        //             &p2wpkh_script,
        //             self.tx.prevouts[self.tx.input_idx].value,
        //             //TODO(stevenroose) this might not actually emulate consensus behavior
        //             EcdsaSighashType::from_consensus(hashtype as u32),
        //         )
        //         .expect("only happens on prevout index out of bounds")
        //         .into()
        // } else if self.ctx == ExecCtx::SegwitV0P2WPKH {
        //     println!("Checksig script_code: {:?}", script_code);
        //     let p2pkh_script = Script::from_bytes(script_code);
        //     let mut p2wsh_script = vec![0x00, 0x14];
        //     let public_key_hash = p2pkh_script[3..p2pkh_script.len() - 2].as_bytes().to_vec();
        //     p2wsh_script.extend(public_key_hash);
        //     println!(
        //         "Checksig p2wsh_script: {:?}",
        //         ScriptBuf::from_bytes(p2wsh_script.clone())
        //     );
        //     self.sighashcache
        //         .p2wpkh_signature_hash(
        //             self.tx.input_idx,
        //             &ScriptBuf::from_bytes(p2wsh_script),
        //             // self.tx.prevouts[self.tx.input_idx].script_pubkey.clone(),
        //             self.tx.prevouts[self.tx.input_idx].value,
        //             //TODO(stevenroose) this might not actually emulate consensus behavior
        //             EcdsaSighashType::from_consensus(hashtype as u32),
        //         )
        //         .expect("only happens on prevout index out of bounds")
        //         .into()
        // } else if self.ctx == ExecCtx::SegwitV0P2WSH {
        //     self.sighashcache
        //         .p2wsh_signature_hash(
        //             self.tx.input_idx,
        //             Script::from_bytes(script_code),
        //             self.tx.prevouts[self.tx.input_idx].value,
        //             //TODO(stevenroose) this might not actually emulate consensus behavior
        //             EcdsaSighashType::from_consensus(hashtype as u32),
        //         )
        //         .expect("only happens on prevout index out of bounds")
        //         .into()
        // } else if self.ctx == ExecCtx::Legacy {
        //     println!("sig verify for legacy");
        //     println!("Checksig script_code: {:?}", script_code);
        //     self.sighashcache
        //         .legacy_signature_hash(
        //             self.tx.input_idx,
        //             Script::from_bytes(script_code),
        //             hashtype as u32,
        //         )
        //         .expect("TODO(stevenroose) seems to only happen if prevout index out of bound")
        //         .into()
        // } else {
        //     unreachable!();
        // };

        match pk.verify_prehash(&sighash, &sig) {
            Ok(()) => return true,
            Err(_) => return false,
        }

        // SECP.verify_ecdsa(&sighash, &sig, &pk).is_ok()
    }

    /// [pk] should be passed as 32-bytes.
    pub fn check_sig_schnorr(&mut self, sig: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        assert_eq!(pk.len(), 32);

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ExecError::SchnorrSigSize);
        }

        // let pk = XOnlyPublicKey::from_slice(pk).expect("TODO(stevenroose) what to do here?");

        let pk = match k256::schnorr::VerifyingKey::from_bytes(pk) {
            Ok(pk) => pk,
            Err(_) => return Err(ExecError::SchnorrSig),
        };

        let (sig, hashtype) = if sig.len() == 65 {
            let b = *sig.last().unwrap();

            // let sig = secp256k1::schnorr::Signature::from_slice(&sig[0..sig.len() - 1])
            //     .map_err(|_| ExecError::SchnorrSig)?;

            let sig = match k256::schnorr::Signature::try_from(&sig[0..sig.len() - 1]) {
                Ok(s) => s,
                Err(_) => return Err(ExecError::SchnorrSig),
            };

            if b == TapSighashType::Default as u8 {
                return Err(ExecError::SchnorrSigHashtype);
            }
            //TODO(stevenroose) core does not error here
            let sht =
                TapSighashType::from_consensus_u8(b).map_err(|_| ExecError::SchnorrSigHashtype)?;
            (sig, sht)
        } else {
            // let sig = secp256k1::schnorr::Signature::from_slice(sig)
            //     .map_err(|_| ExecError::SchnorrSig)?;
            let sig = match k256::schnorr::Signature::try_from(sig) {
                Ok(s) => s,
                Err(_) => return Err(ExecError::SchnorrSig),
            };
            (sig, TapSighashType::Default)
        };

        let sighash: [u8; 32] = if self.ctx == ExecCtx::TaprootKeySpend {
            self.sighashcache
                .taproot_key_spend_signature_hash(
                    self.tx.input_idx,
                    &Prevouts::All(&self.tx.prevouts), // TODO: this is not correct, we need to check the prevout type
                    hashtype,
                )
                .expect("TODO(stevenroose) seems to only happen if prevout index out of bound")
                .to_byte_array()
        } else if self.ctx == ExecCtx::TaprootScriptSpend {
            let leaf_hash = self.tx.taproot_script_leafhash.as_ref().unwrap();
            self.sighashcache
                .taproot_script_spend_signature_hash(
                    self.tx.input_idx,
                    &Prevouts::All(&self.tx.prevouts), // TODO: this is not correct, we need to check the prevout type
                    *leaf_hash,
                    hashtype,
                )
                .expect("TODO(stevenroose) seems to only happen if prevout index out of bound")
                .to_byte_array()
        } else {
            unreachable!();
        };

        // println!("sighash: {:?}", sighash);
        // println!("sig: {:?}", sig);
        // println!("pk: {:?}", pk);

        if pk.verify_prehash(&sighash, &sig).is_err() {
            return Err(ExecError::SchnorrSig);
        }

        Ok(())
    }
}
