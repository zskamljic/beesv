use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::JsValue;

use crate::util::JsResult;

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

    pub fn to_xprv(&self) -> JsResult<XPrv> {
        type HmacSha256 = Hmac<Sha512>;
        let mut hmac = match HmacSha256::new_from_slice(b"Bitcoin seed") {
            Ok(hmac) => hmac,
            Err(error) => return Err(JsValue::from_str(&format!("{error:?}"))),
        };
        hmac.update(&self.seed);

        let seed = hmac.finalize().into_bytes();

        Ok(XPrv {
            key: seed[..32]
                .try_into()
                .map_err(|e| JsValue::from_str(&format!("{e:?}")))?,
            chain_code: seed[32..]
                .try_into()
                .map_err(|e| JsValue::from_str(&format!("{e:?}")))?,
        })
    }
}

#[derive(Debug)]
pub struct XPrv {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl TryFrom<XPrv> for String {
    type Error = JsValue;

    fn try_from(value: XPrv) -> JsResult<Self> {
        let mut xprv = vec![0x04, 0x88, 0xAD, 0xE4];
        xprv.extend([0u8; 9]);
        xprv.extend(&value.chain_code);
        xprv.push(0x0);
        xprv.extend(&value.key);

        let hashed_xprv = {
            let mut hash = Sha256::new();
            hash.update(&xprv);
            hash.finalize()
        };
        let hashed_xprv = {
            let mut hash = Sha256::new();
            hash.update(hashed_xprv);
            hash.finalize()
        };

        xprv.extend(&hashed_xprv[..4]);

        Ok(bs58::encode(xprv).into_string())
    }
}

impl TryFrom<&str> for Seed {
    type Error = JsValue;

    fn try_from(value: &str) -> JsResult<Self> {
        let seed = hex::decode(value)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

        Ok(Self { seed })
    }
}

#[cfg(test)]
mod tests {
    use crate::{bip39::Seed, util::JsResult};

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
    fn generate_xprv_returns_correct() -> JsResult<()> {
        let seed = "88a6b54bf042d0ba673e497dd283feeca6a1d0fd31cf26d8b7e115f2b3cc92294541855a9c0e74a3c3b87a5aee5adc89faf0702721b6b8af31c0d2b403aba531";
        let seed: Seed = seed.try_into()?;
        let xprv = seed.to_xprv()?;
        let serialized: String = xprv.try_into()?;

        assert_eq!(
            "xprv9s21ZrQH143K43iibmycYZ1GRBnkoqG14kHwrGAAkjQTbT3DG5xgizWtvzz49AeozJjUSKf36iWNkRsuFN7PLWo7Kz4AzJqCB1kSHqRhwGE",
            &serialized
        );
        Ok(())
    }
}
