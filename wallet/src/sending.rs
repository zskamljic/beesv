use std::{collections::HashMap, fmt::Debug, hash::Hash};

use anyhow::Result;
use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey};
use thiserror::Error;

use crate::{script, util::double_sha256};

struct SigHash {
    value: u32,
}

impl SigHash {
    fn base(&self) -> BaseSigHash {
        BaseSigHash {
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

impl Default for SigHash {
    fn default() -> Self {
        Self { value: 0x41 }
    }
}

struct BaseSigHash {
    value: u32,
}

impl BaseSigHash {
    fn has_all(&self) -> bool {
        self.value == 0x01
    }

    fn has_none(&self) -> bool {
        self.value == 0x02
    }

    fn has_single(&self) -> bool {
        self.value == 0x03
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
pub enum SignatureError {
    #[error("Input out of bounds: {0}/{1}")]
    InputOutOfBounds(usize, usize),
    #[error("Missing previous input for {0}:{1}")]
    MissingInput(String, u32),
    #[error("Missing signing key")]
    MissingKey,
    #[error("Invalid script")]
    InvalidScript,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Input {
    tx_hash: Vec<u8>,
    index: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

impl Input {
    pub fn new_decoded(tx_hash: Vec<u8>, index: u32) -> Self {
        Self {
            tx_hash,
            index,
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
        }
    }

    pub fn new(tx_hash: String, index: u32) -> Result<Self> {
        Ok(Input::new_decoded(hex::decode(tx_hash)?, index))
    }
}

impl Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tx_hash: Vec<_> = self.tx_hash.to_vec();
        let tx_hash = hex::encode(tx_hash);
        let script_sig = hex::encode(&self.script_sig);

        write!(
            f,
            "Input {{ tx_hash: {tx_hash}, index: {}, script_sig: {script_sig} }}",
            self.index,
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
pub struct Output {
    amount: u64,
    script: Vec<u8>,
}

#[derive(Error, Debug)]
enum SendingError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Address checksum error")]
    ChecksumError,
}

impl Output {
    pub fn new(amount: u64, address: &str) -> Result<Self> {
        let decoded_address = bs58::decode(address).into_vec()?;
        if decoded_address.len() != 25 || decoded_address[0] != 0 {
            return Err(SendingError::InvalidAddress(address.to_owned()).into());
        }

        let address: [u8; 20] = decoded_address[1..21]
            .try_into()
            .expect("Manual bounds set");
        let checksum = double_sha256(&decoded_address[..21]);
        if checksum[0..4] != decoded_address[21..] {
            return Err(SendingError::ChecksumError.into());
        }

        let mut script = vec![0x76, 0xA9, 0x14];
        script.extend(address);
        script.extend([0x88, 0xAC]);

        Ok(Self { amount, script })
    }

    pub fn new_from_decoded(amount: u64, address: [u8; 20]) -> Self {
        let mut script = vec![0x76, 0xA9, 0x14];
        script.extend(address);
        script.extend([0x88, 0xAC]);

        Self { amount, script }
    }

    fn address(&self) -> Result<[u8; 20]> {
        if self.script.len() != 25
            || self.script[0] != 0x76
            || self.script[1] != 0xA9
            || self.script[2] != 0x14
            || self.script[23] != 0x88
            || self.script[24] != 0xAC
        {
            return Err(SignatureError::InvalidScript.into());
        }
        let address = self.script[3..23].try_into()?;
        Ok(address)
    }
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
pub struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    locktime: u32,
}

impl Transaction {
    pub fn add_input(&mut self, input: Input) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: Output) {
        self.outputs.push(output);
    }

    pub fn sign_inputs(
        &mut self,
        previous_outputs: &HashMap<(Vec<u8>, u32), Output>,
        address_keys: &HashMap<[u8; 20], (SecretKey, PublicKey)>,
    ) -> Result<()> {
        for i in 0..self.inputs.len() {
            let input = &self.inputs[i];
            let prev_out = previous_outputs
                .get(&(input.tx_hash.clone(), input.index))
                .ok_or(SignatureError::MissingInput(
                    hex::encode(&input.tx_hash),
                    input.index,
                ))?;

            let hash = self.hash_fork(i, &prev_out.script, &SigHash::default(), prev_out.amount)?;

            let (sk, pk) = address_keys
                .get(&prev_out.address()?)
                .ok_or(SignatureError::MissingKey)?;

            let signature = sk.sign_ecdsa(Message::from_slice(&hash)?);
            let der = signature.serialize_der().to_vec();
            let mut sig_script = vec![];
            sig_script.extend(encode_compact_size(der.len() as u64 + 1));
            sig_script.extend(&der);
            sig_script.push(0x41);
            sig_script.push(0x21);
            sig_script.extend(&pk.serialize());

            self.inputs[i].script_sig = sig_script;
        }
        Ok(())
    }

    pub fn suggested_fee(&self) -> u64 {
        let sig_len = self.inputs.len() * 107;

        Vec::from(self).len() as u64 + 34 + sig_len as u64
    }

    pub fn verify(&self, previous_outputs: &HashMap<(Vec<u8>, u32), Output>) -> Result<()> {
        for i in 0..self.inputs.len() {
            let input = &self.inputs[i];
            let signature_length = input.script_sig[0] as usize;
            let signature = &input.script_sig[1..signature_length];
            let signature = Signature::from_der(signature)?;
            let pub_key = &input.script_sig[signature_length + 2..];
            let pub_key = PublicKey::from_slice(pub_key)?;

            let sig_hash = SigHash {
                value: input.script_sig[signature_length] as u32,
            };
            let output = previous_outputs
                .get(&(input.tx_hash.clone(), input.index))
                .ok_or(SignatureError::MissingInput(
                    hex::encode(&input.tx_hash),
                    input.index,
                ))?;
            let script = &output.script;
            let message = if sig_hash.has_fork_id() {
                self.hash_fork(i, script, &sig_hash, output.amount)?
            } else {
                self.hash_original(i, script, &sig_hash)?
            };
            let message = Message::from_slice(&message)?;

            signature.verify(&message, &pub_key)?;
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
            let previous_outputs: Vec<_> = self
                .inputs
                .iter()
                .flat_map(|i| i.tx_hash.iter().rev().cloned().chain(i.index.to_le_bytes()))
                .collect();
            double_sha256(&previous_outputs)
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

        let outputs_hash = if sig_hash.base().has_single() && index < self.outputs.len() {
            double_sha256(&Vec::from(&self.outputs[index]))
        } else if !sig_hash.base().has_single() && !sig_hash.base().has_none() {
            let outputs: Vec<_> = self.outputs.iter().flat_map(Vec::from).collect();
            double_sha256(&outputs)
        } else {
            [0u8; 32]
        };

        preimage.extend(outputs_hash);

        preimage.extend(self.locktime.to_le_bytes());
        preimage.extend(sig_hash.value.to_le_bytes());

        Ok(double_sha256(&preimage))
    }

    fn hash_original(&self, index: usize, script: &[u8], sig_hash: &SigHash) -> Result<[u8; 32]> {
        if self.has_invalid_flag(index, sig_hash) {
            return Err(SignatureError::InputOutOfBounds(index, self.inputs.len()).into());
        }

        let mut current_signing = self.clone();
        for i in 0..current_signing.inputs.len() {
            if i == index {
                continue;
            }
            current_signing.inputs[i].script_sig.clear();
            if sig_hash.base().has_single() || sig_hash.base().has_none() {
                current_signing.inputs[i].sequence = 0;
            }
        }
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
            current_signing.outputs = current_signing.outputs[..index + 1].to_vec();
            for i in 0..current_signing.outputs.len() {
                if i != index {
                    current_signing.outputs[i] = Output {
                        amount: u64::MAX,
                        script: vec![],
                    }
                }
            }
        }

        let mut serialized = Vec::from(&current_signing);
        serialized.extend(sig_hash.value.to_le_bytes());
        Ok(double_sha256(&serialized))
    }

    fn has_invalid_flag(&self, index: usize, sig_hash: &SigHash) -> bool {
        index >= self.inputs.len() || sig_hash.base().has_single() && index >= self.outputs.len()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
        }
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

        if !transaction.is_empty() {
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
    if input <= 252 {
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
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, str::FromStr};

    use anyhow::Result;

    use super::*;

    #[test]
    fn create_transaction() -> Result<()> {
        let mut transaction = Transaction::default();
        transaction.add_input(Input::new_decoded(
            hex::decode("3f4fa19803dec4d6a84fae3821da7ac7577080ef75451294e71f9b20e0ab1e7b")?,
            0,
        ));
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

        let mut inputs = HashMap::new();
        inputs.insert(
            (
                hex::decode("3967ad2de67356564743545dbc41fbf882f8c078ce037afba10bd4435ef3d7b9")?,
                1,
            ),
            Output {
                amount: 1222064,
                script: hex::decode("76a9140b16eb01af7a0f6fa56ee8183ca84a27cf4151e988ac")?,
            },
        );
        inputs.insert(
            (
                hex::decode("ba3e421c5c0835a07f15c83df681654104593a8979a2d2953fff6d055f33c373")?,
                1,
            ),
            Output {
                amount: 5274723,
                script: hex::decode("76a9140c6a3b21b00ddc232da8a62bb24aa031e0a93be188ac")?,
            },
        );

        transaction.verify(&inputs)
    }

    #[test]
    fn verify_signature_no_fork() -> Result<()> {
        let input = "0200000001c44c3bae60810fd288c11ec8682eaf88de396b2d53aae6ee3d5824e2f3dc3e96050000006a473044022005c396c208844da838467f05545862c63391f84dc07e02792d52784ae52cb32f022074ec4622b45fbd1accd5f59767f969aafc339367f18dca9162d2d122f75523b3012102be0aa60c89ce7ebe35418a79284bfb2fef25a3fac9262afb6ff6e9c546e9cd5bfeffffff01435d320000000000160014bf1bafa3caa7fb41eeb66218ce0cdb4f4b3b95e398010c00";

        let raw_tx = hex::decode(input)?;
        let transaction: Transaction = raw_tx.try_into()?;

        let serialized = hex::encode(Vec::from(&transaction)).to_string();
        assert_eq!(input, serialized);

        let mut inputs = HashMap::new();
        inputs.insert(
            (
                hex::decode("963edcf3e224583deee6aa532d6b39de88af2e68c81ec188d20f8160ae3b4cc4")?,
                5,
            ),
            Output {
                amount: 3303000,
                script: hex::decode("76a914152fc05ea22a712eb8227e57dbd8d79451ea0e3e88ac")?,
            },
        );

        transaction.verify(&inputs)
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
            let sig_hash_regular =
                signature_hash(&transaction, index, &script, &sig_hash, 0, true)?;
            assert_eq!(
                sig_hash_reg_hex,
                hex::encode(sig_hash_regular.into_iter().rev().collect::<Vec<u8>>())
            );

            let sig_hash_old = signature_hash(&transaction, index, &script, &sig_hash, 0, false)?;
            assert_eq!(
                sig_hash_old_hex,
                hex::encode(sig_hash_old.into_iter().rev().collect::<Vec<u8>>())
            );
        }

        Ok(())
    }

    fn signature_hash(
        transaction: &Transaction,
        index: usize,
        script: &[u8],
        sig_hash: &SigHash,
        amount: u64,
        enable_fork: bool,
    ) -> Result<[u8; 32]> {
        if enable_fork {
            transaction.hash_fork(index, script, sig_hash, amount)
        } else {
            transaction.hash_original(index, script, sig_hash)
        }
    }

    #[test]
    fn sign_generates_correct() -> Result<()> {
        let mut transaction = Transaction::default();
        transaction.add_input(Input::new_decoded(
            hex::decode("ba3e421c5c0835a07f15c83df681654104593a8979a2d2953fff6d055f33c373")?,
            1,
        ));
        transaction.add_output(Output {
            amount: 5274723,
            script: hex::decode("76a9140c6a3b21b00ddc232da8a62bb24aa031e0a93be188ac")?,
        });

        let sk = SecretKey::from_str(
            "2e7d8617942ef7cb24aae1ab35dfa39e5e3d7f4fc3060ca5247acf375a8ec456",
        )?;
        let pk = PublicKey::from_str(
            "03209b1875a86a7dbc7a8b65965b5df44a97d5010725c920a28869ed740ff5852e",
        )?;

        let mut address_keys = HashMap::new();
        address_keys.insert(
            [
                0x0c, 0x6a, 0x3b, 0x21, 0xb0, 0x0d, 0xdc, 0x23, 0x2d, 0xa8, 0xa6, 0x2b, 0xb2, 0x4a,
                0xa0, 0x31, 0xe0, 0xa9, 0x3b, 0xe1,
            ],
            (sk, pk),
        );

        let mut prev_outs = HashMap::new();
        prev_outs.insert(
            (
                hex::decode("ba3e421c5c0835a07f15c83df681654104593a8979a2d2953fff6d055f33c373")?,
                1,
            ),
            Output {
                amount: 5274723,
                script: hex::decode("76a9140c6a3b21b00ddc232da8a62bb24aa031e0a93be188ac")?,
            },
        );

        transaction.sign_inputs(&prev_outs, &address_keys)?;

        transaction.verify(&prev_outs)
    }
}
