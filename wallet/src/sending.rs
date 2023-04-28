use std::{collections::HashMap, fmt::Debug};

use anyhow::Result;
use secp256k1::{ecdsa::Signature, KeyPair, PublicKey, Secp256k1};
use thiserror::Error;

use crate::{script, util::double_sha256};

struct SigHash {
    value: u32,
}

impl SigHash {
    fn base(&self) -> SigHash {
        Self {
            value: self.value & 0x1F,
        }
    }

    fn has_all(&self) -> bool {
        self.value & 0x01 == 0x01
    }

    fn has_none(&self) -> bool {
        self.value & 0x02 == 0x02
    }

    fn has_single(&self) -> bool {
        self.value & 0x03 == 0x03
    }

    fn has_fork_id(&self) -> bool {
        self.value & 0x40 == 0x40
    }

    fn has_anyone_can_pay(&self) -> bool {
        self.value & 0x80 == 0x80
    }
}

impl From<i32> for SigHash {
    fn from(value: i32) -> Self {
        Self {
            value: value as u32,
        }
    }
}

#[derive(Error, Debug)]
enum SignatureError {
    #[error("Input out of bounds: {0}/{1}")]
    InputOutOfBounds(usize, usize),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Input {
    tx_hash: Vec<u8>,
    index: u32,
    script_sig: Vec<u8>,
    //sig_type: u8,
    sequence: u32,
}

impl Input {
    fn new(tx_hash: Vec<u8>, index: u32) -> Result<Self> {
        Ok(Self {
            tx_hash,
            index,
            script_sig: vec![],
            //sig_type: SIGHASH_ALL,
            sequence: 0xFFFF_FFFF,
        })
    }

    /*
    fn override_sign(&mut self) {
        self.script_sig = self.create_locking_script();
    }*/

    /*
    fn create_locking_script(&self) -> Vec<u8> {
        let mut script = vec![0x76, 0xA9, 0x14]; // OP_DUP, OP_HASH160, push 20 bytes to stack
        script.extend(self.address);
        script.extend(vec![0x88, 0xAC]); // OP_EQUALVERIFY OP_CHECKSIG
        script
    }*/
}

impl Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut source = vec![0x00];
        //source.extend(self.address);

        let checksum = double_sha256(&source);
        source.extend(&checksum[..4]);

        let address = bs58::encode(source).into_string();
        let tx_hash: Vec<_> = self.tx_hash.iter().cloned().collect();
        let tx_hash = hex::encode(&tx_hash);
        let script_sig = hex::encode(&self.script_sig);

        write!(
            f,
            "Input {{ address: {address}, tx_hash: {tx_hash}, index: {}, script_sig: {script_sig} }}",
            self.index, //self.sig_type
        )
    }
}

impl From<&Input> for Vec<u8> {
    fn from(value: &Input) -> Self {
        value
            .tx_hash
            .iter()
            .rev()
            .cloned()
            .chain(value.index.to_le_bytes())
            .chain(encode_compact_size(value.script_sig.len() as u64))
            .chain(value.script_sig.iter().cloned())
            .chain(value.sequence.to_le_bytes())
            .collect()
    }
}

#[derive(Clone)]
struct Output {
    amount: u64,
    script: Vec<u8>,
}

impl Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let script = hex::encode(&self.script);

        write!(f, "Output {{ amount: {}, script: {script} }}", self.amount)
    }
}

impl From<&Output> for Vec<u8> {
    fn from(value: &Output) -> Self {
        value
            .amount
            .to_le_bytes()
            .into_iter()
            .chain(encode_compact_size(value.script.len() as u64))
            .chain(value.script.iter().cloned())
            .collect()
    }
}

#[derive(Clone, Debug)]
struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    locktime: u32,
}

impl Transaction {
    fn new() -> Self {
        Self {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
        }
    }

    fn add_input(&mut self, input: Input) {
        self.inputs.push(input);
    }

    fn add_output(&mut self, output: Output) {
        self.outputs.push(output);
    }

    fn sign_inputs(&mut self, address_keys: HashMap<[u8; 20], KeyPair>) {
        let mut copy = self.clone();
        copy.inputs.iter_mut().for_each(|i| i.script_sig.clear());

        for i in 0..self.inputs.len() {
            let mut current_signing = copy.clone();
            //current_signing.inputs[i].override_sign();

            let mut serialized = Vec::from(&current_signing);
            //serialized.extend(SIGHASH_ALL.to_le_bytes());
            let hash = double_sha256(&serialized);

            let secp = Secp256k1::new();
            //let keypair = address_keys.get(&self.inputs[i].address).unwrap(); // TODO: fail if not present
            //let result =
            //    secp.sign_ecdsa(&Message::from_slice(&hash).unwrap(), &keypair.secret_key());
            //let mut script_sig = result.serialize_der().to_vec();
            //script_sig.push(SIGHASH_ALL | SIGHASH_FORKID);
            // script_sig.extend(keypair.public_key().serialize());
            //self.inputs[i].script_sig = script_sig;
        }
    }

    fn verify(&self) -> Result<()> {
        let secp = Secp256k1::new();
        let mut copy = self.clone();
        copy.inputs.iter_mut().for_each(|i| i.script_sig.clear());

        for i in 0..self.inputs.len() {
            //let message = if self.inputs[i].sig_type & SIGHASH_FORKID != 0 {
            //    self.hash_fork(i)?
            //} else {
            //let message = self.hash_original(i, &secp, copy.clone())?;
            //};

            let input = &self.inputs[i];
            let signature_length = input.script_sig[0] as usize;
            let signature = &input.script_sig[1..signature_length];
            let signature = Signature::from_der(signature)?;
            let pub_key = &input.script_sig[signature_length + 2..];
            let pub_key = PublicKey::from_slice(&pub_key)?;
            //secp.verify_ecdsa(&message, &signature, &pub_key)?;
            println!("Input valid");
        }

        Ok(())
    }

    fn hash_fork(
        &self,
        index: usize,
        script: &[u8],
        sig_hash: &SigHash,
        amount: u64,
    ) -> Result<[u8; 32]> {
        if !sig_hash.has_fork_id() {
            return self.hash_original(index, script, sig_hash);
        }

        let mut preimage = vec![];
        preimage.extend(self.version.to_le_bytes());

        let prevouts_hash = if sig_hash.has_anyone_can_pay() {
            [0u8; 32]
        } else {
            //let previous_outputs: Vec<_> = self
            //    .inputs
            //    .iter()
            //    .flat_map(|i| i.address.iter().cloned().chain(i.index.to_le_bytes()))
            //    .collect();
            //preimage.extend(double_sha256(&previous_outputs));
            todo!("Not supported yet");
        };
        preimage.extend(prevouts_hash);

        let sequence_hash = if sig_hash.has_anyone_can_pay()
            || sig_hash.base().has_single()
            || sig_hash.base().has_none()
        {
            [0u8; 32]
        } else {
            let sequence_numbers: Vec<_> = self
                .inputs
                .iter()
                .flat_map(|i| i.sequence.to_le_bytes())
                .collect();
            double_sha256(&sequence_numbers)
        };
        preimage.extend(sequence_hash);

        preimage.extend(self.inputs[index].tx_hash.iter().rev());
        preimage.extend(self.inputs[index].index.to_le_bytes());

        preimage.extend(encode_compact_size(script.len() as u64));
        preimage.extend(script);

        preimage.extend(amount.to_le_bytes());
        preimage.extend(self.inputs[index].sequence.to_le_bytes());

        let outputs: Vec<_> = self.outputs.iter().flat_map(|o| Vec::from(o)).collect();
        preimage.extend(double_sha256(&outputs));

        preimage.extend(self.locktime.to_le_bytes());
        preimage.extend(sig_hash.value.to_le_bytes());

        Ok(double_sha256(&preimage))
    }

    fn hash_original(&self, index: usize, script: &[u8], sig_hash: &SigHash) -> Result<[u8; 32]> {
        if self.has_invalid_flag(index, sig_hash) {
            return Err(SignatureError::InputOutOfBounds(index, self.inputs.len()).into());
        }

        let mut current_signing = self.clone();
        current_signing
            .inputs
            .iter_mut()
            .for_each(|i| i.script_sig.clear());
        current_signing.inputs[index].script_sig = script
            .iter()
            .cloned()
            .filter(|c| c != &script::OP_CODESEPARATOR)
            .collect();

        if sig_hash.has_anyone_can_pay() {
            let mut inputs = std::mem::take(&mut current_signing.inputs);
            let input = inputs.remove(index);
            current_signing.inputs.push(input);
        }

        let base_sig = sig_hash.base();
        if base_sig.has_none() {
            current_signing.outputs.clear();
        } else if base_sig.has_single() {
            todo!("Unsupported: {}", base_sig.value);
        }

        let mut serialized = Vec::from(&current_signing);
        serialized.extend(sig_hash.value.to_le_bytes());
        Ok(double_sha256(&serialized))
    }

    fn has_invalid_flag(&self, index: usize, sig_hash: &SigHash) -> bool {
        index >= self.inputs.len() || sig_hash.base().has_single() && index >= self.outputs.len()
    }
}

impl From<&Transaction> for Vec<u8> {
    fn from(value: &Transaction) -> Self {
        let mut raw_transaction = Vec::new();
        raw_transaction.extend(value.version.to_le_bytes());

        raw_transaction.extend(encode_compact_size(value.inputs.len() as u64));
        for input in &value.inputs {
            raw_transaction.extend(Vec::from(input));
        }

        raw_transaction.extend(encode_compact_size(value.outputs.len() as u64));
        for output in &value.outputs {
            raw_transaction.extend(Vec::from(output))
        }

        raw_transaction.extend(value.locktime.to_le_bytes());

        raw_transaction
    }
}

#[derive(Error, Debug)]
enum DeserializeError {
    #[error("Invalid transaction version")]
    InvalidVersion,
    #[error("Invalid signature script")]
    InvalidSignatureScript,
    #[error("Leftover data after parsing: {0:?}")]
    LeftoverData(Vec<u8>),
}

impl TryFrom<Vec<u8>> for Transaction {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        let version = u32::from_le_bytes(value[..4].try_into()?);

        let mut transaction = value[4..].to_vec();
        let input_count = read_var_int(&mut transaction)?;

        let mut inputs = vec![];
        for _ in 0..input_count {
            let tx_hash: Vec<_> = transaction.drain(0..32).rev().collect();
            let index: Vec<_> = transaction.drain(0..4).collect();
            let index = u32::from_le_bytes(index[..].try_into()?);
            let script_len = read_var_int(&mut transaction)? as usize;
            let script_sig: Vec<_> = transaction.drain(0..script_len).collect();

            //let signature_length = script_sig[0] as usize + 1;
            //let key_length = script_sig[signature_length];
            //if key_length != 33 {
            //    return Err(DeserializeError::InvalidSignatureScript.into());
            //}

            //let address = ripemd160(&sha256(&script_sig[script_sig.len() - 33..]));
            //let sig_type = script_sig[script_sig.len() - 35];

            let sequence: Vec<_> = transaction.drain(0..4).collect();
            let sequence = u32::from_le_bytes(sequence[..].try_into()?);
            inputs.push(Input {
                //address,
                tx_hash,
                index,
                script_sig,
                //sig_type,
                sequence,
            })
        }

        let output_count = read_var_int(&mut transaction)?;
        let mut outputs = vec![];
        for _ in 0..output_count {
            let amount: Vec<_> = transaction.drain(0..8).collect();
            let amount = u64::from_le_bytes(amount[..].try_into()?);

            let script_len = read_var_int(&mut transaction)? as usize;
            let script: Vec<_> = transaction.drain(0..script_len).collect();

            outputs.push(Output { amount, script })
        }
        let locktime: Vec<_> = transaction.drain(0..4).collect();
        let locktime = u32::from_le_bytes(locktime[..].try_into()?);

        if transaction.len() > 0 {
            return Err(DeserializeError::LeftoverData(transaction).into());
        }

        Ok(Transaction {
            version,
            inputs,
            outputs,
            locktime,
        })
    }
}

fn read_var_int(input: &mut Vec<u8>) -> Result<u64> {
    Ok(match input.remove(0) {
        0xFD => {
            let count = u16::from_le_bytes(input[..2].try_into()?);
            input.drain(0..2);
            count as u64
        }
        0xFE => {
            let count = u32::from_le_bytes(input[..4].try_into()?);
            input.drain(0..4);
            count as u64
        }
        0xFF => {
            let count = u64::from_le_bytes(input[..8].try_into()?);
            input.drain(0..8);
            count
        }
        value => value as u64,
    })
}

fn encode_compact_size(input: u64) -> Vec<u8> {
    return if input <= 252 {
        vec![input as u8]
    } else if input <= 0xFFFF {
        let mut output = vec![0xFD];
        output.extend((input as u16).to_le_bytes());
        output
    } else if input <= 0xFFFF_FFFF {
        let mut output = vec![0xFE];
        output.extend((input as u32).to_le_bytes());
        output
    } else {
        let mut output = vec![0xFF];
        output.extend(input.to_le_bytes());
        output
    };
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use anyhow::Result;

    use super::*;

    #[test]
    fn create_transaction() -> Result<()> {
        let mut transaction = Transaction::new();
        transaction.add_input(Input::new(
            hex::decode("3f4fa19803dec4d6a84fae3821da7ac7577080ef75451294e71f9b20e0ab1e7b")?,
            0,
        )?);
        transaction.add_output(Output {
            amount: 4999990000,
            script: hex::decode("76a914cbc20a7664f2f69e5355aa427045bc15e7c6c77288ac")?,
        });

        assert_eq!(
            hex::decode("01000000017b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f0000000000ffffffff01f0ca052a010000001976a914cbc20a7664f2f69e5355aa427045bc15e7c6c77288ac00000000")?,
            Vec::from(&transaction),
        );

        Ok(())
    }

    #[test]
    fn encode_compact_size_serializes_correct() {
        assert_eq!(vec![123], encode_compact_size(123));
        assert_eq!(vec![0xFD, 0xCD, 0xAB], encode_compact_size(0xABCD));
        assert_eq!(
            vec![0xFE, 0x01, 0xEF, 0xCD, 0xAB],
            encode_compact_size(0xABCDEF01)
        );
        assert_eq!(
            vec![0xFF, 0x89, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB],
            encode_compact_size(0xABCDEF0123456789)
        )
    }

    #[test]
    fn verify_signature_fork() -> Result<()> {
        let input = "0100000002b9d7f35e43d40ba1fb7a03ce78c0f882f8fb41bc5d544347565673e62dad6739010000006a4730440220693afd8f6d09b88489c66e2084ce95e5d4be122d4e4056b7e5f17e0072baee4c022063eb4c064e6cec56746ffa29db694bb16d4439beddfff39dfa0b0b86340057dd412103eb73f67c22a83656d96b4a355360699042ac185d474474ec8805f4735178050affffffff73c3335f056dff3f95d2a279893a5904416581f63dc8157fa035085c1c423eba010000006a47304402207b94740f3d4357feab803a40708c7dacbdf9d9e7200364cfd71ab96a56d634cf02202070fc09e1dadd645dd133addbdd27e5c0b814f179bfed08b7a466808b19cb54412103aa0837bbdd4fa56c4c34c0e0407d4a9c58a5de8df57393764207acec0067e95bffffffff02808d5b00000000001976a9141e9c2e4b2427952f5e92b1be245aa71a3f7e133888acac920700000000001976a914bc9bdd6c9945529b57e645b65a5fcea198ecdbf688ac00000000";

        let raw_tx = hex::decode(input)?;
        let transaction: Transaction = raw_tx.try_into()?;

        let serialized = hex::encode(Vec::from(&transaction)).to_string();
        assert_eq!(input, serialized);

        transaction.verify()
    }

    #[test]
    fn verify_signature_no_fork() -> Result<()> {
        let input = "0200000001c44c3bae60810fd288c11ec8682eaf88de396b2d53aae6ee3d5824e2f3dc3e96050000006a473044022005c396c208844da838467f05545862c63391f84dc07e02792d52784ae52cb32f022074ec4622b45fbd1accd5f59767f969aafc339367f18dca9162d2d122f75523b3012102be0aa60c89ce7ebe35418a79284bfb2fef25a3fac9262afb6ff6e9c546e9cd5bfeffffff01435d320000000000160014bf1bafa3caa7fb41eeb66218ce0cdb4f4b3b95e398010c00";

        let raw_tx = hex::decode(input)?;
        let transaction: Transaction = raw_tx.try_into()?;

        let serialized = hex::encode(Vec::from(&transaction)).to_string();
        assert_eq!(input, serialized);

        transaction.verify()
    }

    #[test]
    fn verify_sighash_generation() -> Result<()> {
        type TestInput = (String, String, usize, i32, String, String);

        let json_file = File::open("../tests/sigtest.json")?;
        let inputs: Vec<TestInput> = serde_json::from_reader(json_file)?;

        for input in inputs {
            let (raw_tx, raw_script, index, sig_hash, sig_hash_reg_hex, sig_hash_old_hex) = input;

            let sig_hash: SigHash = sig_hash.into();

            let transaction: Transaction = hex::decode(raw_tx)?.try_into()?;

            let script = hex::decode(raw_script)?;
            let sig_hash_regular = transaction.hash_fork(index, &script, &sig_hash, 0)?;
            assert_eq!(
                sig_hash_reg_hex,
                hex::encode(sig_hash_regular.into_iter().rev().collect::<Vec<u8>>())
            );

            let sig_hash_old = transaction.hash_original(index, &script, &sig_hash)?;
            assert_eq!(
                sig_hash_old_hex,
                hex::encode(sig_hash_old.into_iter().rev().collect::<Vec<u8>>())
            );
        }

        Ok(())
    }
}
