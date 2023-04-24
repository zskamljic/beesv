use std::{collections::HashMap, fmt::Debug};

use anyhow::Result;
use secp256k1::{ecdsa::Signature, KeyPair, Message, PublicKey, Secp256k1};
use thiserror::Error;

use crate::util::{double_sha256, ripemd160, sha256};

const SIGHASH_ALL: u8 = 0x41;

#[derive(Error, Debug)]
enum SendingError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Address checksum error")]
    ChecksumError,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Input {
    address: [u8; 20],
    tx_hash: Vec<u8>,
    index: u32,
    script_sig: Vec<u8>,
    sig_type: u8,
    sequence: u32,
}

impl Input {
    fn new(address: &str, tx_hash: Vec<u8>, index: u32) -> Result<Self> {
        let decoded_address = bs58::decode(address).into_vec()?;
        if decoded_address.len() != 25 || decoded_address[0] != 0 {
            return Err(SendingError::InvalidAddress(address.to_owned()).into());
        }

        let address = decoded_address[1..21]
            .try_into()
            .expect("Manual bounds set");
        let checksum = double_sha256(&decoded_address[..21]);
        if checksum[0..4] != decoded_address[21..] {
            return Err(SendingError::ChecksumError.into());
        }

        Ok(Self {
            address,
            tx_hash,
            index,
            script_sig: vec![],
            sig_type: SIGHASH_ALL,
            sequence: 0xFFFF_FFFF,
        })
    }

    fn override_sign(&mut self) {
        self.script_sig = vec![0x76, 0xA9, 0x14]; // OP_DUP, OP_HASH160, push 20 bytes to stack
        self.script_sig.extend(self.address);
        self.script_sig.extend(vec![0x88, 0xAC]); // OP_EQUALVERIFY OP_CHECKSIG
    }
}

impl Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut source = vec![0x00];
        source.extend(self.address);

        let checksum = double_sha256(&source);
        source.extend(&checksum[..4]);

        let address = bs58::encode(source).into_string();
        let tx_hash: Vec<_> = self.tx_hash.iter().cloned().rev().collect();
        let tx_hash = hex::encode(&tx_hash);
        let script_sig = hex::encode(&self.script_sig);

        write!(
            f,
            "Input {{ address: {address}, tx_hash: {tx_hash}, index: {}, script_sig: {script_sig}, sig_type: {} }}",
            self.index, self.sig_type
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
            current_signing.inputs[i].override_sign();

            let mut serialized = Vec::from(&current_signing);
            serialized.extend(SIGHASH_ALL.to_le_bytes());
            let hash = double_sha256(&serialized);

            let secp = Secp256k1::new();
            let keypair = address_keys.get(&self.inputs[i].address).unwrap(); // TODO: fail if not present
            let result =
                secp.sign_ecdsa(&Message::from_slice(&hash).unwrap(), &keypair.secret_key());
            let mut script_sig = result.serialize_der().to_vec();
            script_sig.push(SIGHASH_ALL);
            script_sig.extend(keypair.public_key().serialize());
            self.inputs[i].script_sig = script_sig;
        }
    }

    fn verify(&self) -> Result<()> {
        let secp = Secp256k1::new();
        let mut copy = self.clone();
        copy.inputs.iter_mut().for_each(|i| i.script_sig.clear());

        for i in 0..self.inputs.len() {
            let mut current_signing = copy.clone();
            current_signing.inputs[i].override_sign();

            println!(
                "Validating: {current_signing:?}\n{}",
                hex::encode(Vec::from(&current_signing))
            );

            let input = &self.inputs[i];
            let mut serialized = Vec::from(&current_signing);
            serialized.push(input.sig_type);
            serialized.extend([0u8; 3]);
            let hash = double_sha256(&serialized);
            println!("Hash: {}", hex::encode(serialized).to_string());

            let signature_length = input.script_sig[0] as usize;
            let signature = &input.script_sig[1..signature_length];

            let signature = Signature::from_der(signature)?;
            let pub_key = &input.script_sig[signature_length + 2..];
            let pub_key = PublicKey::from_slice(&pub_key)?;
            let message = Message::from_slice(&hash)?;
            secp.verify_ecdsa(&message, &signature, &pub_key)?;
        }

        Ok(())
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
        if version > 0x02 {
            return Err(DeserializeError::InvalidVersion.into());
        }
        let mut transaction = value[4..].to_vec();
        let input_count = read_var_int(&mut transaction)?;

        let mut inputs = vec![];
        for _ in 0..input_count {
            let tx_hash: Vec<_> = transaction.drain(0..32).rev().collect();
            let index: Vec<_> = transaction.drain(0..4).collect();
            let index = u32::from_le_bytes(index[..].try_into()?);
            let script_len = read_var_int(&mut transaction)? as usize;
            let script_sig: Vec<_> = transaction.drain(0..script_len).collect();

            let signature_length = script_sig[0] as usize + 1;
            let key_length = script_sig[signature_length];
            if key_length != 33 {
                return Err(DeserializeError::InvalidSignatureScript.into());
            }

            let address = ripemd160(&sha256(&script_sig[script_sig.len() - 33..]));
            let sig_type = script_sig[script_sig.len() - 35];

            let sequence: Vec<_> = transaction.drain(0..4).collect();
            let sequence = u32::from_le_bytes(sequence[..].try_into()?);
            inputs.push(Input {
                address,
                tx_hash,
                index,
                script_sig,
                sig_type,
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
    use anyhow::Result;

    use super::*;

    #[test]
    fn create_transaction() -> Result<()> {
        let mut transaction = Transaction::new();
        transaction.add_input(Input::new(
            "1GfPuSBZHon3x6UtupKHFSDwjfUEnaRRLD",
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
    fn verify_signature() -> Result<()> {
        let input = "0100000002b9d7f35e43d40ba1fb7a03ce78c0f882f8fb41bc5d544347565673e62dad6739010000006a4730440220693afd8f6d09b88489c66e2084ce95e5d4be122d4e4056b7e5f17e0072baee4c022063eb4c064e6cec56746ffa29db694bb16d4439beddfff39dfa0b0b86340057dd412103eb73f67c22a83656d96b4a355360699042ac185d474474ec8805f4735178050affffffff73c3335f056dff3f95d2a279893a5904416581f63dc8157fa035085c1c423eba010000006a47304402207b94740f3d4357feab803a40708c7dacbdf9d9e7200364cfd71ab96a56d634cf02202070fc09e1dadd645dd133addbdd27e5c0b814f179bfed08b7a466808b19cb54412103aa0837bbdd4fa56c4c34c0e0407d4a9c58a5de8df57393764207acec0067e95bffffffff02808d5b00000000001976a9141e9c2e4b2427952f5e92b1be245aa71a3f7e133888acac920700000000001976a914bc9bdd6c9945529b57e645b65a5fcea198ecdbf688ac00000000";

        let raw_tx = hex::decode(input)?;
        let transaction: Transaction = raw_tx.try_into()?;

        let serialized = hex::encode(Vec::from(&transaction)).to_string();
        assert_eq!(input, serialized);

        transaction.verify()
    }

    #[test]
    fn verify_signature2() -> Result<()> {
        let input = "0200000001c44c3bae60810fd288c11ec8682eaf88de396b2d53aae6ee3d5824e2f3dc3e96050000006a473044022005c396c208844da838467f05545862c63391f84dc07e02792d52784ae52cb32f022074ec4622b45fbd1accd5f59767f969aafc339367f18dca9162d2d122f75523b3012102be0aa60c89ce7ebe35418a79284bfb2fef25a3fac9262afb6ff6e9c546e9cd5bfeffffff01435d320000000000160014bf1bafa3caa7fb41eeb66218ce0cdb4f4b3b95e398010c00";

        let raw_tx = hex::decode(input)?;
        let transaction: Transaction = raw_tx.try_into()?;

        let serialized = hex::encode(Vec::from(&transaction)).to_string();
        assert_eq!(input, serialized);

        transaction.verify()
    }
}
