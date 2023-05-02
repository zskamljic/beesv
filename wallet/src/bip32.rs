use std::str::FromStr;

use anyhow::Result;
use hmac::{Hmac, Mac};
use regex::Regex;
use secp256k1::{PublicKey, SecretKey};
use sha2::Sha512;
use thiserror::Error;

use crate::util::double_sha256;
use crate::util::ripemd160;
use crate::util::sha256;

const HARDENED_INDEX: u32 = 0x80000000;

#[derive(Debug, Error)]
enum Bip32Error {
    #[error("Invalid derivation path")]
    InvalidDerivationPath,
    #[error("Cannot derive hardened key from public")]
    PublicHardenedDerivation,
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

pub trait DerivePath<T> {
    fn parse_path(path: &str) -> Result<Vec<u32>> {
        let path_regex = Regex::new(r"^m(/\d+'?)+$")?;
        if !path_regex.is_match(path) {
            return Err(Bip32Error::InvalidDerivationPath.into());
        }
        Ok(path
            .split('/')
            .skip(1)
            .filter_map(|p| match p.strip_suffix('\'') {
                Some(value) => value.parse::<u32>().map(|v| HARDENED_INDEX + v).ok(),
                None => p.parse().ok(),
            })
            .collect())
    }

    fn derive_path(&self, path: &str) -> Result<T>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct XPrv {
    depth: u8,
    child_number: u32,
    parent_fingerprint: [u8; 4],
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl XPrv {
    pub fn empty() -> Self {
        Self {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0u8; 4],
            key: SecretKey::from_slice(&[0xCD; 32]).unwrap().secret_bytes(),
            chain_code: [0u8; 32],
        }
    }

    pub fn new(key: [u8; 32], chain_code: [u8; 32]) -> Self {
        Self {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0u8; 4],
            key,
            chain_code,
        }
    }

    pub fn derive(&self, index: u32) -> Result<XPrv> {
        let private_key = SecretKey::from_slice(&self.key)?;
        let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code)?;

        // >= 2³¹ indicates hardned keys
        if index >= HARDENED_INDEX {
            let mut key = vec![0];
            key.extend(self.key);
            key.extend(index.to_be_bytes());

            hmac.update(&key);
        } else {
            let point = PublicKey::from_secret_key_global(&private_key);
            let serialized_point = point.serialize();
            hmac.update(&serialized_point);
            hmac.update(&index.to_be_bytes());
        }
        let i = hmac.finalize().into_bytes();

        let secret = SecretKey::from_slice(&i[..32])?;
        let secret = secret.add_tweak(&private_key.into())?;

        let chain_code = i[32..].try_into()?;
        Ok(XPrv {
            depth: self.depth + 1,
            child_number: index,
            parent_fingerprint: self.fingerprint(),
            key: secret.secret_bytes(),
            chain_code,
        })
    }

    pub fn derive_public(&self) -> Result<XPub> {
        let public_key = PublicKey::from_secret_key_global(&SecretKey::from_slice(&self.key)?);

        Ok(XPub {
            depth: self.depth,
            child_number: self.child_number,
            parent_fingerprint: self.parent_fingerprint,
            public_key,
            chain_code: self.chain_code,
        })
    }

    fn fingerprint(&self) -> [u8; 4] {
        let private_key = SecretKey::from_slice(&self.key).unwrap();
        let public_key = PublicKey::from_secret_key_global(&private_key);

        let sha = sha256(&public_key.serialize());
        let ripemd = ripemd160(&sha);
        ripemd[..4].try_into().expect("Should always succeed")
    }
}

impl DerivePath<XPrv> for XPrv {
    fn derive_path(&self, path: &str) -> Result<XPrv> {
        let path = Self::parse_path(path)?;

        let mut key = self.derive(path[0])?;
        for item in path.iter().skip(1) {
            key = key.derive(*item)?;
        }
        Ok(key)
    }
}

impl From<&XPrv> for String {
    fn from(value: &XPrv) -> Self {
        let mut xprv = vec![0x04, 0x88, 0xAD, 0xE4];
        xprv.push(value.depth);
        xprv.extend(value.parent_fingerprint);
        xprv.extend(value.child_number.to_be_bytes());
        xprv.extend(&value.chain_code);
        xprv.push(0x0);
        xprv.extend(&value.key);

        let hashed_xprv = double_sha256(&xprv);

        xprv.extend(&hashed_xprv[..4]);

        bs58::encode(xprv).into_string()
    }
}

impl FromStr for XPrv {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let decoded = bs58::decode(s).into_vec()?;

        let checksum = sha256(&sha256(&decoded[..78]));

        if decoded[78..] != checksum[..4] {
            return Err(Bip32Error::ChecksumMismatch.into());
        }

        Ok(XPrv {
            depth: decoded[4],
            child_number: u32::from_be_bytes(decoded[9..13].try_into()?),
            parent_fingerprint: decoded[5..9].try_into()?,
            key: decoded[46..78].try_into()?,
            chain_code: decoded[13..45].try_into()?,
        })
    }
}

#[derive(Clone)]
pub struct XPub {
    depth: u8,
    child_number: u32,
    parent_fingerprint: [u8; 4],
    public_key: PublicKey,
    chain_code: [u8; 32],
}

impl XPub {
    fn fingerprint(&self) -> [u8; 4] {
        let sha = sha256(&self.public_key.serialize());
        let ripemd = ripemd160(&sha);
        ripemd[..4].try_into().expect("Should always succeed")
    }

    pub fn derive(&self, index: u32) -> Result<XPub> {
        if index >= HARDENED_INDEX {
            return Err(Bip32Error::PublicHardenedDerivation.into());
        }
        let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code)?;
        let serialized_point = self.public_key.serialize();
        hmac.update(&serialized_point);
        hmac.update(&index.to_be_bytes());
        let i = hmac.finalize().into_bytes();

        let public_key = PublicKey::from_secret_key_global(&SecretKey::from_slice(&i[..32])?)
            .combine(&self.public_key)?;

        let chain_code = i[32..].try_into()?;

        Ok(XPub {
            depth: self.depth + 1,
            child_number: index,
            parent_fingerprint: self.fingerprint(),
            public_key,
            chain_code,
        })
    }

    pub fn to_address(&self) -> String {
        let serialized_key = self.public_key.serialize();
        let hashed = ripemd160(&sha256(&serialized_key));
        let mut prefixed = Vec::with_capacity(21);
        prefixed.push(0x00);
        prefixed.extend(&hashed);

        let checksum = sha256(&sha256(&prefixed));
        prefixed.extend(&checksum[..4]);

        bs58::encode(prefixed).into_string()
    }
}

impl DerivePath<XPub> for XPub {
    fn derive_path(&self, path: &str) -> Result<XPub> {
        let path = Self::parse_path(path)?;

        if path.iter().any(|i| *i >= HARDENED_INDEX) {
            return Err(Bip32Error::PublicHardenedDerivation.into());
        }

        let mut key = self.derive(path[0])?;
        for item in path.iter().skip(1) {
            key = key.derive(*item)?;
        }
        Ok(key)
    }
}

impl FromStr for XPub {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let decoded = bs58::decode(s).into_vec()?;

        let checksum = sha256(&sha256(&decoded[..78]));

        if decoded[78..] != checksum[..4] {
            return Err(Bip32Error::ChecksumMismatch.into());
        }

        Ok(XPub {
            depth: decoded[4],
            child_number: u32::from_be_bytes(decoded[9..13].try_into()?),
            parent_fingerprint: decoded[5..9].try_into()?,
            public_key: PublicKey::from_slice(&decoded[45..78])?,
            chain_code: decoded[13..45].try_into()?,
        })
    }
}

impl From<&XPub> for String {
    fn from(value: &XPub) -> Self {
        let mut xprv = vec![0x04, 0x88, 0xB2, 0x1E];
        xprv.push(value.depth);
        xprv.extend(value.parent_fingerprint);
        xprv.extend(value.child_number.to_be_bytes());
        xprv.extend(&value.chain_code);
        xprv.extend(&value.public_key.serialize());

        let hashed_xprv = sha256(&xprv);
        let hashed_xprv = sha256(&hashed_xprv);

        xprv.extend(&hashed_xprv[..4]);

        bs58::encode(xprv).into_string()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::bip32::DerivePath;

    use super::{XPrv, XPub, HARDENED_INDEX};

    #[test]
    fn derive_hardened_returns_correct() -> Result<()> {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let key: XPrv = xprv.parse()?;

        let derived = key.derive(HARDENED_INDEX + 0)?;

        let serialized = String::try_from(&derived)?;
        assert_eq!(
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            serialized
        );

        Ok(())
    }

    #[test]
    fn derive_private_returns_correct() -> Result<()> {
        let xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        let key: XPrv = xprv.parse()?;

        let derived = key.derive(1)?;

        let serialized = String::try_from(&derived)?;
        assert_eq!(
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            serialized
        );

        Ok(())
    }

    #[test]
    fn derive_0h_1_2h() -> Result<()> {
        let xprv ="xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        let key: XPrv = xprv.parse()?;

        let derived = key.derive(HARDENED_INDEX + 2)?;

        let serialized = String::try_from(&derived)?;
        assert_eq!(
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
            serialized
        );

        Ok(())
    }

    #[test]
    fn generate_public() -> Result<()> {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let key: XPrv = xprv.parse()?;

        let public = key.derive_public()?;

        let serialized = String::try_from(&public)?;
        assert_eq!(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            serialized
        );

        Ok(())
    }

    #[test]
    fn parse_path_works_direct() -> Result<()> {
        struct Dummy;

        impl DerivePath<Dummy> for Dummy {
            fn derive_path(&self, _: &str) -> Result<Dummy> {
                Ok(Dummy)
            }
        }

        let result = Dummy::parse_path("m/0/1/2/3")?;

        assert_eq!(vec![0, 1, 2, 3], result);

        Ok(())
    }

    #[test]
    fn parse_path_works_hardened() -> Result<()> {
        struct Dummy;

        impl DerivePath<Dummy> for Dummy {
            fn derive_path(&self, _: &str) -> Result<Dummy> {
                Ok(Dummy)
            }
        }

        let result = Dummy::parse_path("m/0'/1'/2'/3'")?;

        assert_eq!(
            vec![
                HARDENED_INDEX + 0,
                HARDENED_INDEX + 1,
                HARDENED_INDEX + 2,
                HARDENED_INDEX + 3
            ],
            result
        );

        Ok(())
    }

    #[test]
    fn derive_by_path() -> Result<()> {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let key: XPrv = xprv.parse()?;

        let path = "m/0'/1/2'/2/1000000000";
        let result = key.derive_path(path)?;

        let serialized = String::try_from(&result)?;
        assert_eq!(
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
            serialized
        );

        let public = String::from(&result.derive_public()?);
        assert_eq!(
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            public
        );
        Ok(())
    }

    #[test]
    fn derive_address() -> Result<()> {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let key: XPrv = xprv.parse()?;

        let path = "m/0'/0/0";
        let result = key.derive_path(path)?.derive_public()?;

        let serialized_public = result.public_key.serialize();
        assert_eq!(
            "027b6a7dd645507d775215a9035be06700e1ed8c541da9351b4bd14bd50ab61428",
            hex::encode(serialized_public)
        );

        let address = result.to_address();
        assert_eq!("1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr", address);

        Ok(())
    }

    #[test]
    fn public_key_derives_expected() -> Result<()> {
        let xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
        let xpub: XPub = xpub.parse()?;

        let derived = xpub.derive_path("m/2/1000000000")?;
        let serialized = String::from(&derived);

        assert_eq!(
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            serialized,
        );

        Ok(())
    }
}
