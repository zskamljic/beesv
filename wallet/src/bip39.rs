use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::JsValue;

use crate::util::JsResult;

pub fn generate_seed(mnemonic: &str, password: &str) -> [u8; 64] {
    let salt = format!("mnemonic{password}");

    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

    return seed;
}

pub fn to_xprv(seed: [u8; 64]) -> JsResult<String> {
    type HmacSha256 = Hmac<Sha512>;
    let mut hmac = match HmacSha256::new_from_slice(b"Bitcoin seed") {
        Ok(hmac) => hmac,
        Err(error) => return Err(JsValue::from_str(&format!("{error:?}"))),
    };
    hmac.update(&seed);

    let seed = hmac.finalize().into_bytes();

    let mut xprv = vec![0x04, 0x88, 0xAD, 0xE4];
    xprv.extend([0u8; 9]);
    xprv.extend(&seed[32..]);
    xprv.push(0x0);
    xprv.extend(&seed[..32]);

    let hashed_xprv = {
        let mut hash = Sha256::new();
        hash.update(&xprv);
        hash.finalize()
    };
    let hashed_xprv = {
        let mut hash = Sha256::new();
        hash.update(&hashed_xprv);
        hash.finalize()
    };

    xprv.extend(&hashed_xprv[..4]);

    Ok(bs58::encode(xprv).into_string())
}

#[cfg(test)]
mod tests {
    use crate::bip39::generate_seed;

    use super::to_xprv;

    #[test]
    fn generate_seed_generates_correct() {
        let mnemonic = "initial devote cake drill toy hidden foam gasp film palace flip clump";
        let seed = generate_seed(mnemonic, "");

        assert_eq!(
            "88a6b54bf042d0ba673e497dd283feeca6a1d0fd31cf26d8b7e115f2b3cc92294541855a9c0e74a3c3b87a5aee5adc89faf0702721b6b8af31c0d2b403aba531",
            hex::encode(seed)
        );
    }

    #[test]
    fn generate_xprv_returns_correct() {
        let seed = "88a6b54bf042d0ba673e497dd283feeca6a1d0fd31cf26d8b7e115f2b3cc92294541855a9c0e74a3c3b87a5aee5adc89faf0702721b6b8af31c0d2b403aba531";
        let seed = hex::decode(seed)
            .expect("Should decode")
            .try_into()
            .expect("Should be sized correctly");

        assert_eq!(
            "xprv9s21ZrQH143K43iibmycYZ1GRBnkoqG14kHwrGAAkjQTbT3DG5xgizWtvzz49AeozJjUSKf36iWNkRsuFN7PLWo7Kz4AzJqCB1kSHqRhwGE",
            to_xprv(seed).expect("Should succeed")
        );
    }
}
