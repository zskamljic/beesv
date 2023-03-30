use std::str::FromStr;

use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::JsValue;

use crate::util::{map_any_err, JsResult};

const HARDENED_INDEX: u32 = 0x80000000;

#[derive(Debug)]
pub struct XPrv {
    depth: u8,
    child_number: u32,
    parent_fingerprint: [u8; 4],
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl XPrv {
    pub fn new(key: [u8; 32], chain_code: [u8; 32]) -> Self {
        Self {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0u8; 4],
            key,
            chain_code,
        }
    }

    #[allow(unused)]
    pub fn derive_private(&self, index: u32) -> JsResult<XPrv> {
        let private_key = SecretKey::from_slice(&self.key).map_err(map_any_err)?;
        let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code).map_err(map_any_err)?;

        // >= 2³¹ indicates hardned keys
        if index >= HARDENED_INDEX {
            let mut key = vec![0];
            key.extend(self.key);
            key.extend(index.to_be_bytes());

            hmac.update(&key);
        } else {
            let point = private_key.public_key(&Secp256k1::new());
            let serialized_point = point.serialize();
            hmac.update(&serialized_point);
            hmac.update(&index.to_be_bytes());
        }
        let i = hmac.finalize().into_bytes();

        let secret = SecretKey::from_slice(&i[..32]).map_err(map_any_err)?;
        let secret = secret.add_tweak(&private_key.into()).map_err(map_any_err)?;

        let chain_code = i[32..].try_into().map_err(map_any_err)?;
        Ok(XPrv {
            depth: self.depth + 1,
            child_number: index,
            parent_fingerprint: self.fingerprint(),
            key: secret.secret_bytes(),
            chain_code,
        })
    }

    pub fn serialize(&self) -> JsResult<String> {
        let mut xprv = vec![0x04, 0x88, 0xAD, 0xE4];
        xprv.push(self.depth);
        xprv.extend(self.parent_fingerprint);
        xprv.extend(self.child_number.to_be_bytes());
        xprv.extend(&self.chain_code);
        xprv.push(0x0);
        xprv.extend(&self.key);

        let hashed_xprv = sha256(&xprv);
        let hashed_xprv = sha256(&hashed_xprv);

        xprv.extend(&hashed_xprv[..4]);

        Ok(bs58::encode(xprv).into_string())
    }

    fn fingerprint(&self) -> [u8; 4] {
        let private_key = SecretKey::from_slice(&self.key).unwrap();
        let public_key = private_key.public_key(&Secp256k1::new());

        let sha = sha256(&public_key.serialize());
        let mut ripemd = Ripemd160::new();
        ripemd.update(sha);
        let ripemd = ripemd.finalize();
        ripemd[..4].try_into().expect("Should always succeed")
    }
}

impl FromStr for XPrv {
    type Err = JsValue;

    fn from_str(s: &str) -> JsResult<Self> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

        let checksum = sha256(&sha256(&decoded[..78]));

        if decoded[78..] != checksum[..4] {
            return Err(JsValue::from_str("Checksum mismatch"));
        }

        Ok(XPrv {
            depth: decoded[4],
            child_number: u32::from_be_bytes(decoded[9..13].try_into().map_err(map_any_err)?),
            parent_fingerprint: decoded[5..9].try_into().map_err(map_any_err)?,
            key: decoded[46..78].try_into().map_err(map_any_err)?,
            chain_code: decoded[13..45].try_into().map_err(map_any_err)?,
        })
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use crate::util::JsResult;

    use super::{XPrv, HARDENED_INDEX};

    #[test]
    fn derive_hardened_returns_correct() -> JsResult<()> {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let key: XPrv = xprv.parse()?;

        let derived = key.derive_private(HARDENED_INDEX + 0)?;

        let serialized: String = derived.serialize()?;
        assert_eq!(
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            serialized
        );

        Ok(())
    }

    #[test]
    fn derive_private_returns_correct() -> JsResult<()> {
        let xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        let key: XPrv = xprv.parse()?;

        let derived = key.derive_private(1)?;

        let serialized: String = derived.serialize()?;
        assert_eq!(
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            serialized
        );

        Ok(())
    }

    #[test]
    fn derive_0h_1_2h() -> JsResult<()> {
        let xprv ="xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        let key: XPrv = xprv.parse()?;

        let derived = key.derive_private(HARDENED_INDEX + 2)?;

        let serialized: String = derived.serialize()?;
        assert_eq!(
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
            serialized
        );

        Ok(())
    }
}
