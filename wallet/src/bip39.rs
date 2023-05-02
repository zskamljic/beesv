use std::str::FromStr;

use anyhow::Result;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use thiserror::Error;

use crate::bip32::XPrv;

#[derive(Debug, Error)]
enum Bip39Error {
    #[error("Invalid size")]
    InvalidSize,
}

pub struct Seed {
    seed: [u8; 64],
}

impl Seed {
    pub fn generate(mnemonic: &str, password: &str) -> Self {
        let salt = format!("mnemonic{password}");

        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        Self { seed }
    }

    pub fn to_xprv(&self) -> Result<XPrv> {
        type HmacSha256 = Hmac<Sha512>;
        let mut hmac = HmacSha256::new_from_slice(b"Bitcoin seed")?;
        hmac.update(&self.seed);

        let seed = hmac.finalize().into_bytes();

        XPrv::new(seed[..32].try_into()?, seed[32..].try_into()?)
    }
}

impl FromStr for Seed {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let seed = hex::decode(value)?;
        let seed = match seed.try_into() {
            Ok(seed) => seed,
            Err(_) => return Err(Bip39Error::InvalidSize.into()),
        };

        Ok(Self { seed })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::bip39::Seed;

    #[test]
    fn generate_seed_generates_correct() {
        let mnemonic = "initial devote cake drill toy hidden foam gasp film palace flip clump";
        let seed = Seed::generate(mnemonic, "");

        assert_eq!(
            "88a6b54bf042d0ba673e497dd283feeca6a1d0fd31cf26d8b7e115f2b3cc92294541855a9c0e74a3c3b87a5aee5adc89faf0702721b6b8af31c0d2b403aba531",
            hex::encode(seed.seed)
        );
    }

    #[test]
    fn generate_xprv_returns_correct() -> Result<()> {
        let seed = "88a6b54bf042d0ba673e497dd283feeca6a1d0fd31cf26d8b7e115f2b3cc92294541855a9c0e74a3c3b87a5aee5adc89faf0702721b6b8af31c0d2b403aba531";
        let seed: Seed = seed.parse()?;
        let xprv = seed.to_xprv()?;
        let serialized = String::try_from(&xprv)?;

        assert_eq!(
            "xprv9s21ZrQH143K43iibmycYZ1GRBnkoqG14kHwrGAAkjQTbT3DG5xgizWtvzz49AeozJjUSKf36iWNkRsuFN7PLWo7Kz4AzJqCB1kSHqRhwGE",
            &serialized
        );
        Ok(())
    }
}
